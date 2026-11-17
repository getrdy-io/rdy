//! What the answers of the cluster mean for `k8s.dns`: the findings, with fix text, and what could not be
//! read. The rules are in the module comment of `dns` and in 03.

use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::K8sDns;
use serde_json::{Value, json};

use super::corefile::Corefile;
use super::fix;
use super::objects::{Crash, PodFacts, Role, Workload};
use super::{KUBE_SYSTEM, OPENSHIFT_DNS};
use crate::namespace::Read;

/// A crash is "recent" when the last run of the container ended within this many seconds.
pub(super) const RECENT: i64 = 3600;

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 64;

/// The most crash lines kept in `observed`.
const MAX_CRASHES: usize = 16;

/// One list of workloads, first page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Workloads {
    pub(super) items: Vec<Workload>,
    /// True when the list has a next page that was not read.
    pub(super) cut: bool,
}

/// One list of pods, first page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pods {
    pub(super) pods: Vec<PodFacts>,
    pub(super) cut: bool,
}

/// What was read in one namespace.
#[derive(Debug)]
pub(super) struct Place {
    pub(super) namespace: &'static str,
    pub(super) deployments: Read<Workloads>,
    pub(super) daemon_sets: Read<Workloads>,
    pub(super) pods: Read<Pods>,
}

impl Place {
    /// The workloads that carry the cluster DNS label, of both kinds.
    pub(super) fn cluster_workloads(&self) -> impl Iterator<Item = &Workload> {
        self.of_role(Role::Cluster)
    }

    fn of_role(&self, role: Role) -> impl Iterator<Item = &Workload> {
        [&self.deployments, &self.daemon_sets]
            .into_iter()
            .filter_map(|read| match read {
                Read::Ok(list) => Some(list.items.iter()),
                _ => None,
            })
            .flatten()
            .filter(move |workload| workload.role == role)
    }

    /// True when a DNS workload was found here.
    pub(super) fn has_cluster_workload(&self) -> bool {
        self.cluster_workloads().next().is_some()
    }

    /// True when both lists were read, so "none found" means none exist.
    pub(super) fn readable(&self) -> bool {
        matches!(self.deployments, Read::Ok(_)) && matches!(self.daemon_sets, Read::Ok(_))
    }
}

/// The DNS Service, as far as the check reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServiceFacts {
    pub(super) name: String,
    pub(super) namespace: String,
    /// The ClusterIP, when the Service has a real one.
    pub(super) cluster_ip: Option<String>,
    /// True when `clusterIP` is `None` (headless).
    pub(super) headless: bool,
    /// True when a port 53 is listed.
    pub(super) dns_port: bool,
}

/// What was read, before any judgement.
#[derive(Debug)]
pub(super) struct Gathered {
    /// The namespaces looked at, `kube-system` first.
    pub(super) places: Vec<Place>,
    /// The index of the place that holds the DNS (the first, when none does).
    pub(super) chosen: usize,
    pub(super) service: Read<ServiceFacts>,
    /// The Corefile: `None` when it is not asked for (not CoreDNS in `kube-system`), `Some(Ok(None))` for a
    /// ConfigMap with no `Corefile` key.
    pub(super) corefile: Option<Read<Option<Corefile>>>,
}

/// Text from the server, safe for a terminal and for a sentence, and cut short.
fn shown(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(SHOWN).collect();
    // A backtick would let the text open a command span in the sentence around it.
    let mut out = escape_untrusted(&head).replace('`', "'");
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// One thing that stops the install.
struct Issue {
    message: String,
    fix: String,
}

#[derive(Default)]
struct Sink {
    issues: Vec<Issue>,
    notes: Vec<String>,
    unverified: Vec<String>,
    fixes_unverified: Vec<String>,
    quiet: Vec<String>,
    /// `(what to ask for, the command that checks it)`.
    grants: Vec<(String, String)>,
    openshift_grant: bool,
}

impl Sink {
    fn grant(&mut self, wanted: String, can_i: String) {
        if !self.grants.iter().any(|(have, _)| *have == wanted) {
            self.grants.push((wanted, can_i));
        }
    }

    fn fix_once(&mut self, line: String) {
        if !self.fixes_unverified.contains(&line) {
            self.fixes_unverified.push(line);
        }
    }
}

/// The name of what runs the DNS, for a sentence.
fn engine(namespace: &str, workload: &Workload) -> &'static str {
    if workload.is_kube_dns() {
        "kube-dns"
    } else if namespace == OPENSHIFT_DNS {
        "OpenShift DNS"
    } else {
        "CoreDNS"
    }
}

pub(super) fn judge(params: &K8sDns, found: &Gathered) -> Finding {
    let mut sink = Sink::default();
    let want_domain = params
        .cluster_domain
        .as_ref()
        .map_or("cluster.local", |name| name.as_str())
        .to_ascii_lowercase();
    let domain_asked = params.cluster_domain.is_some();

    let Some(place) = found.places.get(found.chosen) else {
        return Finding::new(Level::Warn, "No answer from the cluster".to_owned());
    };
    judge_extra_places(found, &mut sink);
    judge_workloads(place, found, &mut sink);
    let crashes = judge_pods(place, &mut sink);
    judge_service(place, found, &mut sink);
    let loop_evidence = judge_corefile(
        place,
        found,
        &crashes,
        &want_domain,
        domain_asked,
        &mut sink,
    );
    finish(found, place, &want_domain, loop_evidence, sink)
}

// ---- the workloads ------------------------------------------------------------------------------------------

/// A forbidden or failed read of the namespace that was asked second (OpenShift) when the first had none.
fn judge_extra_places(found: &Gathered, sink: &mut Sink) {
    for place in found.places.iter().skip(1) {
        if place.has_cluster_workload() {
            continue;
        }
        let ns = place.namespace;
        match &place.daemon_sets {
            Read::Forbidden => {
                sink.unverified.push(format!(
                    "no DNS workload was found in kube-system, and the identity may not list daemonsets in {ns}, where OpenShift runs it"
                ));
                sink.grant(
                    format!("list daemonsets in {ns}"),
                    format!("`kubectl auth can-i list daemonsets -n {ns}`"),
                );
                sink.openshift_grant = true;
            }
            // The namespace is not there: not an OpenShift cluster, and nothing is missing.
            Read::Ok(_) | Read::Missing => {}
            other => sink.unverified.push(format!(
                "the daemonsets of {ns} were not read: {}",
                other.why()
            )),
        }
    }
}

fn judge_workloads(place: &Place, found: &Gathered, sink: &mut Sink) {
    let ns = place.namespace;
    for (what, read) in [
        ("deployments", &place.deployments),
        ("daemonsets", &place.daemon_sets),
    ] {
        match read {
            Read::Ok(list) => {
                if list.cut {
                    sink.unverified.push(format!(
                        "the {what} of {ns} after the first page were not read"
                    ));
                }
            }
            Read::Forbidden => {
                sink.unverified.push(format!(
                    "the {what} of {ns} were not read: the identity may not list them"
                ));
                sink.grant(
                    format!("list {what} in {ns}"),
                    format!("`kubectl auth can-i list {what} -n {ns}`"),
                );
                sink.openshift_grant |= ns == OPENSHIFT_DNS;
            }
            other => sink
                .unverified
                .push(format!("the {what} of {ns} were not read: {}", other.why())),
        }
    }

    let workloads: Vec<&Workload> = place.cluster_workloads().collect();
    if workloads.is_empty() {
        let service_there = matches!(
            &found.service,
            Read::Ok(service) if service.cluster_ip.is_some()
        );
        let all_read = found.places.iter().all(Place::readable);
        if all_read && !service_there {
            sink.issues.push(Issue {
                message: "No cluster DNS was found: no workload with the label k8s-app=kube-dns in kube-system or openshift-dns, and no DNS Service".to_owned(),
                fix: fix::none_found(),
            });
        } else if all_read {
            sink.unverified.push(
                "no workload carries a cluster DNS label, so whether its pods are ready was not read; the DNS Service exists"
                    .to_owned(),
            );
            sink.fix_once(fix::look_by_hand(ns));
        }
    }
    for workload in &workloads {
        let name = shown(&workload.name);
        let what = engine(ns, workload);
        let kind = workload.kind.word();
        if workload.desired == 0 {
            sink.issues.push(Issue {
                message: format!(
                    "{what} {kind} {name} in {ns} wants no pods, so nothing answers DNS"
                ),
                fix: fix::not_ready(ns, workload),
            });
        } else if workload.ready < workload.desired {
            sink.issues.push(Issue {
                message: format!(
                    "{what} {kind} {name} in {ns} has {} of {} pods ready",
                    workload.ready, workload.desired
                ),
                fix: fix::not_ready(ns, workload),
            });
        } else {
            sink.quiet.push(format!(
                "{what} {kind} {name} has {} of {} pods ready",
                workload.ready, workload.desired
            ));
        }
    }
    // NodeLocal DNSCache: a note, with the count. A node whose cache pod is down loses DNS for its pods, but
    // 03 gives no threshold for it, so it is not a verdict.
    for local in place.of_role(Role::NodeLocal) {
        sink.notes.push(format!(
            "NodeLocal DNSCache {} runs on {} of {} nodes.",
            shown(&local.name),
            local.ready,
            local.desired
        ));
    }
}

// ---- the pods -----------------------------------------------------------------------------------------------

/// The crash loops of the DNS pods. Evidence for the loop verdict is decided later, with the Corefile.
fn judge_pods(place: &Place, sink: &mut Sink) -> Vec<Crash> {
    let ns = place.namespace;
    match &place.pods {
        Read::Ok(list) => {
            if list.cut {
                sink.unverified.push(format!(
                    "the pods of {ns} after the first page were not read"
                ));
            }
            list.pods
                .iter()
                .flat_map(|pod| pod.crashes.iter().cloned())
                .collect()
        }
        Read::Forbidden => {
            sink.unverified.push(
                "whether the DNS pods crash-loop was not read: the identity may not list pods"
                    .to_owned(),
            );
            // The guard allows a pod list only cluster wide, so the grant is the cluster role's.
            sink.grant(
                "list pods".to_owned(),
                "`kubectl auth can-i list pods`".to_owned(),
            );
            Vec::new()
        }
        other => {
            sink.unverified.push(format!(
                "whether the DNS pods crash-loop was not read: {}",
                other.why()
            ));
            Vec::new()
        }
    }
}

// ---- the Service --------------------------------------------------------------------------------------------

fn judge_service(place: &Place, found: &Gathered, sink: &mut Sink) {
    let ns = place.namespace;
    let name = if ns == OPENSHIFT_DNS {
        "dns-default"
    } else {
        "kube-dns"
    };
    match &found.service {
        Read::Ok(service) => {
            if service.headless || service.cluster_ip.is_none() {
                sink.issues.push(Issue {
                    message: format!(
                        "Service {} in {} has no ClusterIP, so pods have no DNS address",
                        shown(&service.name),
                        shown(&service.namespace)
                    ),
                    fix: fix::headless(ns, name),
                });
                return;
            }
            sink.quiet.push(format!(
                "Service {} has ClusterIP {}",
                shown(&service.name),
                shown(service.cluster_ip.as_deref().unwrap_or_default())
            ));
            if !service.dns_port {
                sink.notes.push(format!(
                    "Service {} lists no port 53.",
                    shown(&service.name)
                ));
            }
        }
        Read::Missing => {
            // With no workload either, the "none found" issue already says it.
            if place.has_cluster_workload() {
                sink.issues.push(Issue {
                    message: format!(
                        "Service {name} does not exist in {ns}, so pods have no DNS address"
                    ),
                    fix: fix::no_service(ns, name),
                });
            }
        }
        Read::Forbidden => {
            sink.unverified.push(format!(
                "whether the DNS Service has a ClusterIP was not read: the identity may not get service {name} in {ns}"
            ));
            sink.grant(
                format!("get service {name} in {ns}"),
                format!("`kubectl auth can-i get services/{name} -n {ns}`"),
            );
            sink.openshift_grant |= ns == OPENSHIFT_DNS;
        }
        other => sink.unverified.push(format!(
            "whether the DNS Service has a ClusterIP was not read: {}",
            other.why()
        )),
    }
}

// ---- the Corefile and the loop ------------------------------------------------------------------------------

/// Reads the Corefile against the crash evidence and the cluster domain. Returns the crashes that are loop
/// evidence when the Corefile forwards to `/etc/resolv.conf`.
fn judge_corefile(
    place: &Place,
    found: &Gathered,
    crashes: &[Crash],
    want_domain: &str,
    domain_asked: bool,
    sink: &mut Sink,
) -> Vec<Crash> {
    let recent: Vec<&Crash> = crashes
        .iter()
        .filter(|crash| crash.ended_ago.is_some_and(|age| age <= RECENT))
        .collect();
    // An OOM kill is a memory limit problem, not a loop.
    let (oom, looping): (Vec<&Crash>, Vec<&Crash>) = recent
        .iter()
        .copied()
        .partition(|crash| crash.reason.as_deref() == Some("OOMKilled"));
    let workload = place.cluster_workloads().next();

    for crash in crashes.iter().filter(|crash| !recent.contains(crash)) {
        sink.notes.push(format!(
            "Container {} of pod {} waits in CrashLoopBackOff, but its last run ended {}, so it is not counted as recent evidence.",
            shown(&crash.container),
            shown(&crash.pod),
            crash
                .ended_ago
                .map_or_else(|| "at a time the pod does not say".to_owned(), age_text)
        ));
    }
    for crash in &oom {
        sink.notes.push(format!(
            "Container {} of pod {} was OOMKilled {} ago: raise its memory limit. That is not a forward loop.",
            shown(&crash.container),
            shown(&crash.pod),
            crash.ended_ago.map_or_else(String::new, age_text)
        ));
    }

    let Some(corefile) = &found.corefile else {
        // Not CoreDNS in kube-system (kube-dns, OpenShift): there is no Corefile this check reads.
        if !looping.is_empty() {
            sink.notes.push(
                "A DNS container is crash-looping. This cluster's DNS has no Corefile that rdy reads, so a forward loop cannot be told from another cause."
                    .to_owned(),
            );
            if let Some(workload) = workload {
                sink.fix_once(fix::crash_logs(workload));
            }
        }
        if domain_asked {
            sink.unverified.push(format!(
                "whether the cluster domain is {} was not read: this cluster's DNS has no CoreDNS Corefile that rdy reads (kube-dns, or OpenShift)",
                shown(want_domain)
            ));
        } else {
            sink.notes.push(
                "The cluster domain was not checked: this cluster's DNS has no CoreDNS Corefile that rdy reads."
                    .to_owned(),
            );
        }
        return Vec::new();
    };

    match corefile {
        Read::Ok(Some(file)) => {
            if !looping.is_empty() && !file.forwards_to_resolv_conf {
                sink.notes.push(
                    "A DNS container is crash-looping, but the Corefile does not forward the root zone to /etc/resolv.conf, so this is not the forward loop that rdy can see. Read the logs."
                        .to_owned(),
                );
                if let Some(workload) = workload {
                    sink.fix_once(fix::crash_logs(workload));
                }
            }
            judge_domain(file, want_domain, domain_asked, sink);
            if file.forwards_to_resolv_conf {
                if !looping.is_empty() && !file.loop_plugin {
                    // CoreDNS stops itself on a loop only through the `loop` plugin. Without it the crash has
                    // another cause too, so the verdict stays (03) and the note says so.
                    sink.notes.push(
                        "The Corefile has no loop plugin, so CoreDNS would not stop itself on a forward loop: the crash may have another cause."
                            .to_owned(),
                    );
                }
                return looping.into_iter().cloned().collect();
            }
            Vec::new()
        }
        Read::Ok(None) => {
            sink.notes.push(
                "The coredns ConfigMap has no Corefile key, so the forward and the cluster domain were not read."
                    .to_owned(),
            );
            unread_corefile(&looping, domain_asked, want_domain, sink);
            Vec::new()
        }
        Read::Missing => {
            sink.notes.push(
                "ConfigMap coredns was not found in kube-system, so the Corefile was not read. Some distributions name it differently, and rdy reads only this one."
                    .to_owned(),
            );
            unread_corefile(&looping, domain_asked, want_domain, sink);
            Vec::new()
        }
        Read::Forbidden => {
            let needed = !looping.is_empty() || domain_asked;
            let text = "the Corefile was not read: the identity may not get ConfigMap coredns in kube-system";
            if needed {
                sink.unverified.push(if looping.is_empty() {
                    format!(
                        "whether the cluster domain is {} was not read: {text}",
                        shown(want_domain)
                    )
                } else {
                    format!("whether the crash loop is a forward loop was not read: {text}")
                });
            } else {
                sink.notes.push(format!(
                    "The cluster domain and the forward were not checked: {text}."
                ));
            }
            sink.grant(
                format!("get configmap {KUBE_SYSTEM}/coredns"),
                format!("`kubectl auth can-i get configmaps/coredns -n {KUBE_SYSTEM}`"),
            );
            sink.fix_once(fix::read_corefile_by_hand().to_owned());
            Vec::new()
        }
        other => {
            sink.unverified
                .push(format!("the Corefile was not read: {}", other.why()));
            Vec::new()
        }
    }
}

/// The partial lines for a Corefile that could not give its content.
fn unread_corefile(looping: &[&Crash], domain_asked: bool, want_domain: &str, sink: &mut Sink) {
    if !looping.is_empty() {
        sink.unverified.push(
            "whether the crash loop is a forward loop was not read: the Corefile was not read"
                .to_owned(),
        );
        sink.fix_once(fix::read_corefile_by_hand().to_owned());
    } else if domain_asked {
        sink.unverified.push(format!(
            "whether the cluster domain is {} was not read: the Corefile was not read",
            shown(want_domain)
        ));
    }
}

fn judge_domain(file: &Corefile, want: &str, asked: bool, sink: &mut Sink) {
    if file.cluster_zones.is_empty() {
        let line = "The Corefile has no kubernetes plugin zone that rdy could read, so the cluster domain was not checked.";
        if asked {
            sink.unverified.push(format!(
                "whether the cluster domain is {} was not read: the Corefile has no kubernetes zone",
                shown(want)
            ));
        } else {
            sink.notes.push(line.to_owned());
        }
        return;
    }
    if file.cluster_zones.iter().any(|zone| zone == want) {
        sink.quiet
            .push(format!("cluster domain is {}", shown(want)));
    } else {
        let have = file.cluster_zones.first().map_or("", String::as_str);
        sink.issues.push(Issue {
            message: format!(
                "The cluster domain is {}, and the product expects {}",
                shown(have),
                shown(want)
            ),
            fix: fix::domain(&shown(have), &shown(want)),
        });
    }
}

fn age_text(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 120 {
        format!("{seconds} seconds ago")
    } else if seconds < 7200 {
        format!("{} minutes ago", seconds / 60)
    } else {
        format!("{} hours ago", seconds / 3600)
    }
}

// ---- the finding ---------------------------------------------------------------------------------------------

fn finish(
    found: &Gathered,
    place: &Place,
    want_domain: &str,
    loop_evidence: Vec<Crash>,
    mut sink: Sink,
) -> Finding {
    // The loop is the headline: it explains the not-ready pods next to it.
    if let Some(crash) = loop_evidence.first() {
        let workload = place.cluster_workloads().next();
        let ago = crash.ended_ago.map_or_else(String::new, age_text);
        let message = format!(
            "The cluster DNS is crash-looping and its Corefile forwards to /etc/resolv.conf: a forward loop (container {} of pod {}, last run ended {ago})",
            shown(&crash.container),
            shown(&crash.pod)
        );
        let fix = workload.map_or_else(String::new, fix::forward_loop);
        sink.issues.insert(0, Issue { message, fix });
    }
    let Sink {
        issues,
        mut notes,
        unverified,
        fixes_unverified,
        quiet,
        grants,
        openshift_grant,
    } = sink;
    let level = if issues.is_empty() {
        Level::Pass
    } else {
        Level::Fail
    };
    let message = match issues.first() {
        Some(first) if issues.len() > 1 => format!(
            "{} (and {} more, see the notes)",
            first.message,
            issues.len() - 1
        ),
        Some(first) => first.message.clone(),
        None => pass_message(&quiet),
    };
    let mut fixes: Vec<String> = issues.iter().map(|issue| issue.fix.clone()).collect();
    fixes.extend(fixes_unverified);
    if !grants.is_empty() {
        let can_i: Vec<String> = grants.iter().map(|(_, c)| c.clone()).collect();
        let wanted: Vec<String> = grants.iter().map(|(w, _)| w.clone()).collect();
        fixes.push(fix::grants(&can_i, &wanted, openshift_grant));
    }
    let mut finding = Finding::new(level, message);
    if !fixes.is_empty() {
        finding = finding.with_fix(fixes.join(" "));
    }
    for issue in issues.iter().skip(1) {
        finding = finding.with_note(issue.message.clone());
    }
    notes.push(
        "The forward loop is read from restarts and the Corefile only: rdy never reads pod logs. In-cluster name resolution is not tried."
            .to_owned(),
    );
    for note in notes {
        finding = finding.with_note(note);
    }
    if !unverified.is_empty() {
        finding = finding.with_partial(
            Partial::new(Vec::new(), unverified.join("; "))
                .with_missing_grants(grants.iter().map(|(w, _)| w.clone()).collect()),
        );
    }
    finding
        .with_observed(observed(found, place))
        .with_expected(json!({ "cluster_domain": want_domain }))
}

/// The sentences of a pass, as one.
fn pass_message(quiet: &[String]) -> String {
    let text = quiet.join("; ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Nothing found that stops the install".to_owned(),
    }
}

fn observed(found: &Gathered, place: &Place) -> Value {
    let ns = place.namespace;
    let workloads: Vec<Value> = place
        .cluster_workloads()
        .map(|w| {
            json!({
                "kind": w.kind.word(),
                "name": shown(&w.name),
                "engine": engine(ns, w),
                "desired": w.desired,
                "ready": w.ready,
            })
        })
        .collect();
    let node_local: Vec<Value> = place
        .of_role(Role::NodeLocal)
        .map(|w| json!({ "name": shown(&w.name), "desired": w.desired, "ready": w.ready }))
        .collect();
    let service = match &found.service {
        Read::Ok(s) => json!({
            "name": shown(&s.name),
            "namespace": shown(&s.namespace),
            "cluster_ip": s.cluster_ip.as_deref().map(shown),
            "headless": s.headless,
        }),
        _ => Value::Null,
    };
    let corefile = match &found.corefile {
        Some(Read::Ok(Some(file))) => json!({
            "forwards_to": file.upstreams.iter().take(8).map(|u| shown(u)).collect::<Vec<_>>(),
            "forwards_to_resolv_conf": file.forwards_to_resolv_conf,
            "loop_plugin": file.loop_plugin,
            "cluster_zones": file.cluster_zones.iter().take(8).map(|z| shown(z)).collect::<Vec<_>>(),
        }),
        _ => Value::Null,
    };
    let crashes: Vec<Value> = match &place.pods {
        Read::Ok(list) => list
            .pods
            .iter()
            .flat_map(|pod| pod.crashes.iter())
            .take(MAX_CRASHES)
            .map(|c| {
                json!({
                    "pod": shown(&c.pod),
                    "container": shown(&c.container),
                    "restarts": c.restarts,
                    "last_reason": c.reason.as_deref().map(shown),
                    "last_exit_code": c.exit_code,
                    "last_ended_seconds_ago": c.ended_ago,
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    let restarts = match &place.pods {
        Read::Ok(list) => list.pods.iter().map(|pod| pod.restarts).max().unwrap_or(0),
        _ => 0,
    };
    json!({
        "namespace": ns,
        "workloads": workloads,
        "node_local_dns": node_local,
        "service": service,
        "corefile": corefile,
        "crash_loops": crashes,
        "most_lifetime_restarts": restarts,
    })
}
