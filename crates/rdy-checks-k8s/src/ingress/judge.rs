//! What the answers of the cluster mean for `k8s.ingress`: the findings, with fix text, and what could not be
//! read.
//!
//! The levels are the ones 03 names:
//!
//! - A required controller (`controller`) that no `IngressClass` names, a required Gateway API
//!   (`gateway_api: required`) that is not installed at `v1`, and an OpenShift `Route` the product needs
//!   (`route: true`) on a cluster that does not serve the API: block. On GKE (a built-in ingress that needs
//!   no class) and on OpenShift (the router) a missing class or Gateway API is "not verified", not a block. A
//!   missing class on a list that has a second page is also "not verified": rdy read the first page only.
//! - No default class while the spec names a controller, a Gateway API with no accepted `GatewayClass`
//!   while it is required, and a `LoadBalancer` Service that has had no address for 10 minutes: warn.
//! - A class whose controller is the community `k8s.io/ingress-nginx`: warn with the retirement text. The F5
//!   controller is another project and does not warn.
//! - What could not be read is never a block: the result is partial and `missing_grants` says what to ask for.

use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::{GatewayApi, K8sIngress};
use serde_json::{Value, json};

use super::fix;
use super::objects::{Balancer, Class, GatewayClass};
use crate::namespace::Read;

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 64;

/// The most names listed in one sentence.
const LISTED: usize = 5;

/// A `LoadBalancer` Service with no address is a warning when it is older than this (03: "older than 10
/// minutes", so exactly 600 seconds does not warn).
pub(super) const PENDING_AFTER_SECS: i64 = 10 * 60;

/// The controller of the community ingress-nginx project, retired upstream in March 2026.
const RETIRED_CONTROLLER: &str = "k8s.io/ingress-nginx";

/// The Gateway API kinds the product needs at `v1` (03): the resource names the discovery document lists.
pub(super) const GATEWAY_KINDS: [&str; 3] = ["gatewayclasses", "gateways", "httproutes"];

/// The API group of the Gateway API.
pub(super) const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";
/// The API group that only OpenShift serves for routes.
pub(super) const ROUTE_GROUP: &str = "route.openshift.io";
/// The API group of MetalLB's custom resources.
pub(super) const METALLB_GROUP: &str = "metallb.io";

/// What kind of cluster this is, from facts the run already has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Platform {
    /// The server version says GKE (`-gke.` in it).
    pub(super) gke: bool,
    /// The facts say OpenShift, or the cluster serves `route.openshift.io`.
    pub(super) openshift: bool,
}

/// One page of a list, and whether the server said there was more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Page<T> {
    pub(super) items: Vec<T>,
    /// True when the list has a next page that was not read.
    pub(super) cut: bool,
}

impl<T> Page<T> {
    pub(super) fn empty() -> Self {
        Self {
            items: Vec::new(),
            cut: false,
        }
    }
}

/// What `GET /apis` says about the groups this check looks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Groups {
    /// The versions the Gateway API group serves, `None` when the group is not served.
    pub(super) gateway: Option<Vec<String>>,
    /// True when `route.openshift.io` is served.
    pub(super) route: bool,
    /// True when `metallb.io` is served.
    pub(super) metallb: bool,
}

impl Groups {
    fn gateway_v1(&self) -> bool {
        self.gateway
            .as_ref()
            .is_some_and(|versions| versions.iter().any(|v| v == "v1"))
    }
}

/// What was read, before any judgement.
#[derive(Debug)]
pub(super) struct Gathered {
    /// The namespace of the Service list: the family's. `None` when the spec names none.
    pub(super) namespace: Option<String>,
    pub(super) platform: Platform,
    pub(super) classes: Read<Page<Class>>,
    pub(super) groups: Read<Groups>,
    /// The resource names `GET /apis/gateway.networking.k8s.io/v1` lists. `None` when it was not asked.
    pub(super) gateway_kinds: Option<Read<Vec<String>>>,
    /// `None` when the Gateway API is not served at `v1`.
    pub(super) gateway_classes: Option<Read<Page<GatewayClass>>>,
    /// `None` when the Services were not asked for: the spec does not need a load balancer, or names no
    /// namespace.
    pub(super) services: Option<Read<Page<Balancer>>>,
}

/// Text from the server, safe for a terminal and for a sentence, and cut short.
pub(super) fn shown(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(SHOWN).collect();
    // A backtick would let the text open a command span in the sentence around it.
    let mut out = escape_untrusted(&head).replace('`', "'");
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// A few names, joined for a sentence.
fn list<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let names: Vec<&str> = names.into_iter().collect();
    let mut out: Vec<String> = names.iter().take(LISTED).map(|n| shown(n)).collect();
    if names.len() > LISTED {
        out.push(format!("{} more", names.len() - LISTED));
    }
    out.join(", ")
}

/// A permission the identity lacked: the wire text, and the command that checks it.
struct Grant {
    text: &'static str,
    can_i: &'static str,
}

const LIST_CLASSES: Grant = Grant {
    text: "list ingressclasses (networking.k8s.io)",
    can_i: "`kubectl auth can-i list ingressclasses.networking.k8s.io`",
};

const LIST_GATEWAY_CLASSES: Grant = Grant {
    text: "list gatewayclasses (gateway.networking.k8s.io)",
    can_i: "`kubectl auth can-i list gatewayclasses.gateway.networking.k8s.io`",
};

const LIST_SERVICES: Grant = Grant {
    text: "list services",
    can_i: "`kubectl auth can-i list services -n <namespace>`",
};

/// One thing that stops the install or may stop it.
struct Issue {
    level: Level,
    message: String,
    fix: String,
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Fail => 2,
        Level::Warn => 1,
        _ => 0,
    }
}

/// What the judgement collects on the way to a finding.
#[derive(Default)]
struct Sink {
    issues: Vec<Issue>,
    notes: Vec<String>,
    unverified: Vec<String>,
    fixes_unverified: Vec<String>,
    quiet: Vec<String>,
    grants: Vec<&'static Grant>,
}

impl Sink {
    fn issue(&mut self, level: Level, message: String, fix: String) {
        self.issues.push(Issue {
            level,
            message,
            fix,
        });
    }

    /// Adds a by-hand line to the fix once, however many causes lead to it.
    fn fix_once(&mut self, line: String) {
        if !self.fixes_unverified.contains(&line) {
            self.fixes_unverified.push(line);
        }
    }

    fn grant(&mut self, grant: &'static Grant) {
        if !self.grants.iter().any(|have| have.text == grant.text) {
            self.grants.push(grant);
        }
    }
}

pub(super) fn judge(params: &K8sIngress, found: &Gathered) -> Finding {
    let mut sink = Sink::default();
    judge_classes(params, found, &mut sink);
    judge_gateway(params, found, &mut sink);
    judge_route(params, found, &mut sink);
    judge_balancers(params, found, &mut sink);

    let Sink {
        mut issues,
        mut notes,
        unverified,
        fixes_unverified,
        quiet,
        grants,
    } = sink;
    notes.push(
        "A read-only check cannot prove a load balancer or an ingress controller works: load balancer not verified (no canary Service is created)."
            .to_owned(),
    );
    issues.sort_by_key(|issue| std::cmp::Reverse(rank(issue.level)));
    let level = issues.first().map_or(Level::Pass, |issue| issue.level);
    let message = match issues.first() {
        Some(first) if issues.len() > 1 => format!(
            "{} (and {} more, see the notes)",
            first.message,
            issues.len() - 1
        ),
        Some(first) => first.message.clone(),
        None => pass_message(&quiet),
    };
    let mut finding = Finding::new(level, message);
    let mut fixes: Vec<String> = issues.iter().map(|issue| issue.fix.clone()).collect();
    fixes.extend(fixes_unverified);
    if !grants.is_empty() {
        let can_i: Vec<String> = grants.iter().map(|g| g.can_i.to_owned()).collect();
        let wanted: Vec<String> = grants.iter().map(|g| g.text.to_owned()).collect();
        fixes.push(fix::grants(&can_i, &wanted));
    }
    if !fixes.is_empty() {
        finding = finding.with_fix(fixes.join(" "));
    }
    for issue in issues.iter().skip(1) {
        finding = finding.with_note(issue.message.clone());
    }
    for note in notes {
        finding = finding.with_note(note);
    }
    if !unverified.is_empty() {
        finding = finding.with_partial(
            Partial::new(Vec::new(), unverified.join("; "))
                .with_missing_grants(grants.iter().map(|g| g.text.to_owned()).collect()),
        );
    }
    finding
        .with_observed(observed(found))
        .with_expected(expected(params, found.namespace.as_deref()))
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

// ---- ingress classes ------------------------------------------------------------------------------------------

fn judge_classes(params: &K8sIngress, found: &Gathered, sink: &mut Sink) {
    let page = match &found.classes {
        Read::Ok(page) => page,
        Read::Forbidden => {
            sink.unverified.push(
                "the ingress classes were not read: the identity may not list them".to_owned(),
            );
            sink.grant(&LIST_CLASSES);
            return;
        }
        other => {
            sink.unverified.push(format!(
                "the ingress classes were not read: {}",
                other.why()
            ));
            return;
        }
    };
    let want = params.controller.as_ref().map(|c| c.as_str());

    let retired: Vec<&Class> = page
        .items
        .iter()
        .filter(|class| class.controller == RETIRED_CONTROLLER)
        .collect();
    if !retired.is_empty() {
        sink.issue(
            Level::Warn,
            format!(
                "Ingress class {} uses the community Ingress NGINX controller (k8s.io/ingress-nginx), which was retired upstream in March 2026, whoever ships it",
                list(retired.iter().map(|class| class.name.as_str()))
            ),
            fix::retired().to_owned(),
        );
    }

    if page.items.is_empty() {
        quiet_or_unverified_empty(want, found, page.cut, sink);
        return;
    }

    let satisfied = match want {
        None => true,
        Some("any") => true,
        Some(controller) => page
            .items
            .iter()
            .any(|class| class.controller == controller),
    };
    if !satisfied {
        if let Some(controller) = want {
            missing_class(controller, found, page.cut, sink);
            sink.notes.push(format!(
                "The cluster has ingress classes for these controllers: {}.",
                list(page.items.iter().map(|class| class.controller.as_str()))
            ));
        }
    } else {
        sink.quiet.push(format!(
            "{} found: {}",
            plural(page.items.len(), "ingress class", "ingress classes"),
            list(page.items.iter().map(|class| class.name.as_str()))
        ));
    }

    let defaults: Vec<&Class> = page.items.iter().filter(|class| class.default).collect();
    // OpenShift's router and GKE's built-in ingress take an Ingress with no class, so no default is no
    // problem there.
    let own_ingress = found.platform.gke || found.platform.openshift;
    if want.is_some() && satisfied && defaults.is_empty() && !own_ingress {
        sink.issue(
            Level::Warn,
            "No ingress class is the default, so an Ingress with no class is ignored".to_owned(),
            fix::no_default(page.items.first().map_or("", |class| class.name.as_str())),
        );
    }
    if defaults.len() > 1 {
        sink.notes.push(format!(
            "{} ingress classes are marked as the default ({}). The API server refuses an Ingress with no class when more than one is.",
            defaults.len(),
            list(defaults.iter().map(|class| class.name.as_str()))
        ));
    }
    if page.cut {
        sink.notes.push(format!(
            "The cluster has more ingress classes than rdy read. {}",
            fix::cut_list("classes", "kubectl get ingressclass")
        ));
    }
}

/// A cluster with no ingress class at all.
fn quiet_or_unverified_empty(want: Option<&str>, found: &Gathered, cut: bool, sink: &mut Sink) {
    match want {
        Some(controller) => missing_class(controller, found, cut, sink),
        None => {
            sink.quiet.push("no ingress class exists".to_owned());
            if found.platform.gke {
                sink.notes.push(fix::built_in(true).to_owned());
            }
        }
    }
}

/// The spec names a controller and no class has it.
fn missing_class(controller: &str, found: &Gathered, cut: bool, sink: &mut Sink) {
    if found.platform.gke || found.platform.openshift {
        sink.unverified.push(format!(
            "no ingress class has controller {controller}, and this platform has a built-in ingress that needs no class"
        ));
        sink.fix_once(fix::built_in(found.platform.gke).to_owned());
    } else if cut {
        sink.unverified.push(format!(
            "no ingress class in the first page has controller {controller}, and the list has more"
        ));
        sink.fix_once(fix::cut_list("classes", "kubectl get ingressclass"));
    } else {
        let what = if controller == "any" {
            "No ingress class exists".to_owned()
        } else {
            format!("No ingress class has controller {}", shown(controller))
        };
        sink.issue(Level::Fail, what, fix::no_class(controller));
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

// ---- Gateway API ----------------------------------------------------------------------------------------------

fn judge_gateway(params: &K8sIngress, found: &Gathered, sink: &mut Sink) {
    let required = params.gateway_api == Some(GatewayApi::Required);
    let groups = match &found.groups {
        Read::Ok(groups) => groups,
        other => {
            if required {
                sink.unverified.push(format!(
                    "whether the Gateway API is installed was not read: {}",
                    other.why()
                ));
            }
            return;
        }
    };
    if !groups.gateway_v1() {
        let seen = groups
            .gateway
            .as_ref()
            .map(|versions| {
                format!(
                    " (the cluster serves {} only)",
                    list(versions.iter().map(String::as_str))
                )
            })
            .unwrap_or_default();
        if required {
            gateway_missing(
                found,
                format!("The Gateway API (gateway.networking.k8s.io/v1) is not installed{seen}"),
                sink,
            );
        } else {
            sink.notes
                .push(format!("The Gateway API v1 is not installed{seen}."));
        }
        return;
    }

    // Served at v1. Which kinds?
    let missing: Vec<&str> = match &found.gateway_kinds {
        Some(Read::Ok(kinds)) => GATEWAY_KINDS
            .iter()
            .copied()
            .filter(|want| !kinds.iter().any(|k| k == want))
            .collect(),
        Some(other) => {
            if required {
                sink.unverified.push(format!(
                    "the kinds the Gateway API serves were not read: {}",
                    other.why()
                ));
            }
            Vec::new()
        }
        None => Vec::new(),
    };
    if !missing.is_empty() {
        let message = format!(
            "The Gateway API v1 is installed but does not serve {}",
            missing.join(", ")
        );
        if required {
            gateway_missing(found, message, sink);
            return;
        }
        sink.notes.push(format!("{message}."));
    }

    match &found.gateway_classes {
        Some(Read::Ok(page)) => {
            let accepted: Vec<&GatewayClass> = page
                .items
                .iter()
                .filter(|class| class.accepted == Some(true))
                .collect();
            if accepted.is_empty() {
                let text = if page.items.is_empty() {
                    "no GatewayClass exists".to_owned()
                } else {
                    format!(
                        "no GatewayClass is accepted by a controller (found {})",
                        list(page.items.iter().map(|class| class.name.as_str()))
                    )
                };
                if required && !page.cut {
                    sink.issue(
                        Level::Warn,
                        format!("The Gateway API is installed, but {text}"),
                        fix::no_accepted_class().to_owned(),
                    );
                } else if required {
                    sink.unverified.push(format!(
                        "{text} in the first page of the list, and the list has more"
                    ));
                    sink.fix_once(fix::cut_list("gateway classes", "kubectl get gatewayclass"));
                } else {
                    sink.notes
                        .push(format!("The Gateway API v1 is installed, but {text}."));
                }
            } else {
                sink.quiet.push(format!(
                    "the Gateway API v1 is installed with {}: {}",
                    plural(accepted.len(), "accepted class", "accepted classes"),
                    list(accepted.iter().map(|class| class.name.as_str()))
                ));
            }
        }
        Some(Read::Forbidden) => {
            if required {
                sink.unverified.push(
                    "the gateway classes were not read: the identity may not list them".to_owned(),
                );
                sink.grant(&LIST_GATEWAY_CLASSES);
            } else {
                sink.notes
                    .push("The Gateway API v1 is installed. Its classes were not read: the identity may not list them.".to_owned());
            }
        }
        Some(other) if required => sink.unverified.push(format!(
            "the gateway classes were not read: {}",
            other.why()
        )),
        Some(_) | None => {}
    }
}

/// A required Gateway API that is missing: a block, or "not verified" where the platform has its own ingress.
fn gateway_missing(found: &Gathered, message: String, sink: &mut Sink) {
    let platform = found.platform;
    if platform.gke || platform.openshift {
        sink.unverified.push(format!(
            "{}; this platform manages its own ingress, so rdy does not block on it",
            lower_first(&message)
        ));
        sink.fix_once(fix::no_gateway_api(platform.gke, platform.openshift).to_owned());
    } else {
        sink.issue(
            Level::Fail,
            message,
            fix::no_gateway_api(false, false).to_owned(),
        );
    }
}

/// The sentence with its first letter in lower case, to join it to another.
fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

// ---- OpenShift Route ------------------------------------------------------------------------------------------

fn judge_route(params: &K8sIngress, found: &Gathered, sink: &mut Sink) {
    if !params.route {
        return;
    }
    match &found.groups {
        Read::Ok(groups) if groups.route => sink
            .quiet
            .push("the OpenShift Route API is served".to_owned()),
        Read::Ok(_) => sink.issue(
            Level::Fail,
            "The product needs an OpenShift Route and this cluster does not serve route.openshift.io"
                .to_owned(),
            fix::no_route_api().to_owned(),
        ),
        other => sink.unverified.push(format!(
            "whether the cluster serves the OpenShift Route API was not read: {}",
            other.why()
        )),
    }
}

// ---- LoadBalancer Services ------------------------------------------------------------------------------------

fn judge_balancers(params: &K8sIngress, found: &Gathered, sink: &mut Sink) {
    if !params.loadbalancer {
        return;
    }
    let Some(namespace) = found.namespace.as_deref() else {
        sink.unverified.push(
            "the spec names no namespace, so the LoadBalancer services were not read".to_owned(),
        );
        sink.fix_once(
            "Name the install namespace in the `k8s` block of the spec (`namespace: <name>`), so its LoadBalancer services can be read."
                .to_owned(),
        );
        return;
    };
    let metallb = matches!(&found.groups, Read::Ok(groups) if groups.metallb);
    match &found.services {
        Some(Read::Ok(page)) => {
            let mut old: Vec<&Balancer> = page
                .items
                .iter()
                .filter(|b| !b.assigned && b.age_secs.is_some_and(|age| age > PENDING_AFTER_SECS))
                .collect();
            // The oldest is named first, ties by name (the page is sorted by name already).
            old.sort_by_key(|b| std::cmp::Reverse(b.age_secs));
            let young: Vec<&Balancer> = page
                .items
                .iter()
                .filter(|b| !b.assigned && b.age_secs.is_some_and(|age| age <= PENDING_AFTER_SECS))
                .collect();
            let unknown_age: Vec<&Balancer> = page
                .items
                .iter()
                .filter(|b| !b.assigned && b.age_secs.is_none())
                .collect();
            if let Some(first) = old.first() {
                let minutes = first.age_secs.unwrap_or(0) / 60;
                sink.issue(
                    Level::Warn,
                    format!(
                        "LoadBalancer service {} in {namespace} has had no address for {minutes} minutes{}",
                        shown(&first.name),
                        if old.len() > 1 {
                            format!(" (and {} more)", old.len() - 1)
                        } else {
                            String::new()
                        }
                    ),
                    fix::pending_balancer(&first.name, namespace, minutes, metallb),
                );
                sink.notes.push(
                    "A Service's age counts from its creation. If its type was changed to LoadBalancer later, it has waited less than that."
                        .to_owned(),
                );
            }
            if !young.is_empty() {
                sink.notes.push(format!(
                    "LoadBalancer service {} has no address yet. It is under 10 minutes old, so it may still be provisioning.",
                    list(young.iter().map(|b| b.name.as_str()))
                ));
            }
            if !unknown_age.is_empty() {
                sink.notes.push(format!(
                    "LoadBalancer service {} has no address, and the server sent no creation time, so rdy cannot say how long.",
                    list(unknown_age.iter().map(|b| b.name.as_str()))
                ));
            }
            if page.cut {
                sink.notes.push(format!(
                    "The namespace has more services than rdy read. {}",
                    fix::cut_list("services", &format!("kubectl get services -n {namespace}"))
                ));
            }
            if old.is_empty() {
                let assigned = page.items.iter().filter(|b| b.assigned).count();
                sink.quiet.push(if page.items.is_empty() {
                    format!("no LoadBalancer service in {namespace} yet")
                } else {
                    format!(
                        "{} of {} LoadBalancer services in {namespace} have an address",
                        assigned,
                        page.items.len()
                    )
                });
            }
        }
        Some(Read::Forbidden) => {
            sink.unverified.push(format!(
                "the services of {namespace} were not read: the identity may not list them"
            ));
            sink.grant(&LIST_SERVICES);
        }
        Some(other) => sink.unverified.push(format!(
            "the services of {namespace} were not read: {}",
            other.why()
        )),
        None => sink
            .unverified
            .push(format!("the services of {namespace} were not read")),
    }
}

// ---- observed and expected --------------------------------------------------------------------------------------

fn read_word<T>(read: &Read<T>) -> &'static str {
    match read {
        Read::Ok(_) => "read",
        Read::Missing => "missing",
        Read::Forbidden => "forbidden",
        Read::Unreadable(_) => "unreadable",
        Read::Refused => "refused",
        Read::OutOfTime => "out_of_time",
    }
}

fn observed(found: &Gathered) -> Value {
    let classes = match &found.classes {
        Read::Ok(page) => json!({
            "read": "read",
            "cut": page.cut,
            "items": page.items.iter().take(32).map(|class| json!({
                "name": shown(&class.name),
                "controller": shown(&class.controller),
                "default": class.default,
            })).collect::<Vec<_>>(),
        }),
        other => json!({"read": read_word(other)}),
    };
    let gateway = match &found.groups {
        Read::Ok(groups) => json!({
            "served_versions": groups.gateway.as_ref().map(|v| v.iter().map(|x| shown(x)).collect::<Vec<_>>()),
            "kinds": match &found.gateway_kinds {
                Some(Read::Ok(kinds)) => json!(kinds.iter().take(16).map(|k| shown(k)).collect::<Vec<_>>()),
                Some(other) => json!(read_word(other)),
                None => Value::Null,
            },
            "classes": match &found.gateway_classes {
                Some(Read::Ok(page)) => json!(page.items.iter().take(32).map(|class| json!({
                    "name": shown(&class.name),
                    "controller": shown(&class.controller),
                    "accepted": class.accepted,
                })).collect::<Vec<_>>()),
                Some(other) => json!(read_word(other)),
                None => Value::Null,
            },
        }),
        other => json!({"read": read_word(other)}),
    };
    let services = found.services.as_ref().map(|read| match read {
        Read::Ok(page) => json!({
            "read": "read",
            "cut": page.cut,
            "load_balancers": page.items.iter().take(32).map(|b| json!({
                "name": shown(&b.name),
                "assigned": b.assigned,
                "age_seconds": b.age_secs,
            })).collect::<Vec<_>>(),
        }),
        other => json!({"read": read_word(other)}),
    });
    let groups = match &found.groups {
        Read::Ok(groups) => json!({"route": groups.route, "metallb": groups.metallb}),
        other => json!({"read": read_word(other)}),
    };
    json!({
        "platform": {"gke": found.platform.gke, "openshift": found.platform.openshift},
        "ingress_classes": classes,
        "gateway_api": gateway,
        "api_groups": groups,
        "services": services,
    })
}

fn expected(params: &K8sIngress, namespace: Option<&str>) -> Value {
    json!({
        "controller": params.controller.as_ref().map(|c| c.as_str()),
        "gateway_api": params.gateway_api.map(|g| match g {
            GatewayApi::Required => "required",
            GatewayApi::Optional => "optional",
            _ => "other",
        }),
        "route": params.route,
        "loadbalancer": params.loadbalancer,
        "namespace": namespace,
    })
}
