//! What the answers of the cluster mean for `k8s.cni`: the findings, with fix text, and what could not be
//! read.
//!
//! The rules (03, "k8s.cni"):
//!
//! - `network_policy: enforced` and a plugin that is known not to enforce: block. A plugin that cannot be
//!   named, or whose setting cannot be read, is partial and never a block.
//! - A pod or service range that overlaps an `avoid_cidrs` range: block.
//! - A default-deny egress policy in the namespace while the spec lists `needs_egress`: warn.
//! - What could not be read is never a block: the result is partial and `missing_grants` says what to ask
//!   for.

use std::collections::BTreeSet;

use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::{K8sCni, NetworkPolicyMode};
use serde_json::{Value, json};

use super::cidr::Net;
use super::fix;
use super::objects::{DaemonSetFacts, NodeFacts, OcpFacts, PolicyFacts};
use super::table::{Enforces, Entry, PodCidr, Role, Table};
use crate::namespace::Read;

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 64;

/// The API group of Multus, a secondary plugin that is not a primary one.
const MULTUS_GROUP: &str = "k8s.cni.cncf.io";

/// The API group only OpenShift serves for its cluster configuration.
pub(super) const OPENSHIFT_CONFIG: &str = "config.openshift.io";

/// The most items of one kind listed in a sentence.
const LISTED: usize = 3;

/// A page of objects, and whether the list had a second page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Page<T> {
    pub(super) items: Vec<T>,
    pub(super) cut: bool,
}

/// How the service range was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServiceSource {
    OpenShiftNetwork,
    ServiceCidr,
    KubeadmConfig,
}

impl ServiceSource {
    fn words(self) -> &'static str {
        match self {
            Self::OpenShiftNetwork => "the OpenShift Network object",
            Self::ServiceCidr => "a ServiceCIDR object",
            Self::KubeadmConfig => "the kubeadm-config ConfigMap",
        }
    }
}

/// One read of a service range source that gave nothing, with the grant that would help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Unread {
    pub(super) what: &'static str,
    pub(super) why: String,
    /// The grant to name, when the identity may not read it.
    pub(super) grant: Option<&'static Grant>,
}

/// The service ranges found, and what could not be read on the way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ServiceCidrs {
    pub(super) found: Option<(ServiceSource, Vec<String>)>,
    pub(super) unread: Vec<Unread>,
}

/// One DaemonSet asked for by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Probe {
    pub(super) namespace: String,
    pub(super) name: String,
    pub(super) entry: String,
    pub(super) read: Read<DaemonSetFacts>,
}

/// What was read, before any judgement.
#[derive(Debug)]
pub(super) struct Gathered {
    /// The namespace whose policies are read.
    pub(super) namespace: Option<String>,
    pub(super) nodes: Read<Page<NodeFacts>>,
    pub(super) groups: Read<Vec<String>>,
    /// `Network` of OpenShift, read when the cluster serves `config.openshift.io`.
    pub(super) ocp: Option<Read<OcpFacts>>,
    pub(super) service: ServiceCidrs,
    /// The DaemonSets asked for, in order. `None` when the cheaper signals named the plugin.
    pub(super) probes: Option<Vec<Probe>>,
    /// True when the DaemonSet reads stopped for lack of time.
    pub(super) probes_cut: bool,
    /// The policies of the namespace. `None` when no namespace is named.
    pub(super) policies: Option<Read<Page<PolicyFacts>>>,
}

/// A permission the identity lacked: the wire text, and the command that checks it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Grant {
    pub(super) text: &'static str,
    pub(super) can_i: &'static str,
}

pub(super) const LIST_NODES: Grant = Grant {
    text: "list nodes",
    can_i: "`kubectl auth can-i list nodes`",
};
pub(super) const LIST_POLICIES: Grant = Grant {
    text: "list networkpolicies",
    can_i: "`kubectl auth can-i list networkpolicies -n <namespace>`",
};
pub(super) const GET_DAEMONSETS: Grant = Grant {
    text: "get daemonsets (by name)",
    can_i: "`kubectl auth can-i get daemonsets.apps/aws-node -n kube-system`",
};
pub(super) const LIST_SERVICECIDRS: Grant = Grant {
    text: "list servicecidrs",
    can_i: "`kubectl auth can-i list servicecidrs.networking.k8s.io`",
};
pub(super) const GET_KUBEADM: Grant = Grant {
    text: "get configmaps/kubeadm-config in kube-system",
    can_i: "`kubectl auth can-i get configmaps/kubeadm-config -n kube-system`",
};
pub(super) const GET_OCP_NETWORK: Grant = Grant {
    text: "get networks.config.openshift.io/cluster",
    can_i: "`oc auth can-i get networks.config.openshift.io/cluster`",
};

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

// ---- naming the plugin ------------------------------------------------------------------------------------

/// How a plugin was recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Signal {
    NodeReason(String),
    CrdGroup(String),
    NetworkType(String),
    DaemonSet(String),
}

impl Signal {
    fn words(&self) -> String {
        match self {
            Self::NodeReason(reason) => format!("the node condition {}", shown(reason)),
            Self::CrdGroup(group) => format!("the API group {}", shown(group)),
            Self::NetworkType(kind) => format!("the OpenShift network type {}", shown(kind)),
            Self::DaemonSet(pair) => format!("the DaemonSet {}", shown(pair)),
        }
    }

    fn json(&self) -> Value {
        match self {
            Self::NodeReason(r) => json!({"node_condition": shown(r)}),
            Self::CrdGroup(g) => json!({"api_group": shown(g)}),
            Self::NetworkType(t) => json!({"network_type": shown(t)}),
            Self::DaemonSet(p) => json!({"daemonset": shown(p)}),
        }
    }
}

/// What the signals say about the plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Named<'t> {
    /// No signal named a plugin.
    Nothing,
    /// One plugin, with the signals that named it.
    One(&'t Entry, Vec<Signal>),
    /// More than one plugin: the names.
    Several(Vec<&'t str>),
}

/// The signals that need no DaemonSet: node conditions, API groups and the OpenShift network type.
pub(super) fn cheap_signals<'t>(
    table: &'t Table,
    nodes: &[NodeFacts],
    groups: &[String],
    network_type: Option<&str>,
) -> Vec<(&'t Entry, Signal)> {
    let mut out = Vec::new();
    for entry in table.entries() {
        for reason in &entry.node_reasons {
            if nodes.iter().any(|n| n.reason.as_deref() == Some(reason)) {
                out.push((entry, Signal::NodeReason(reason.clone())));
            }
        }
        for group in &entry.crd_groups {
            if groups.iter().any(|g| g == group) {
                out.push((entry, Signal::CrdGroup(group.clone())));
            }
        }
        for kind in &entry.network_types {
            if network_type == Some(kind) {
                out.push((entry, Signal::NetworkType(kind.clone())));
            }
        }
    }
    out
}

/// Settles the signals into one plugin, or says there is none or more than one.
///
/// Plugins of one family are one plugin (GKE Dataplane V2 is Cilium). Flannel with Calico is Canal.
pub(super) fn name_plugin<'t>(table: &'t Table, signals: Vec<(&'t Entry, Signal)>) -> Named<'t> {
    if signals.is_empty() {
        return Named::Nothing;
    }
    let mut families: BTreeSet<&str> = signals.iter().map(|(e, _)| e.family.as_str()).collect();
    // Canal is Flannel (the network) and Calico (the policy). Either part, or both, with the Canal
    // DaemonSet, is Canal.
    let canal =
        families.contains("canal") || (families.contains("flannel") && families.contains("calico"));
    if canal {
        families.remove("flannel");
        families.remove("calico");
        families.insert("canal");
    }
    // One policy plugin on top of base plugins is the policy plugin, like Canal: Calico over the AWS VPC
    // CNI or Azure CNI, Cilium in chaining mode. The base plugin stays in the signals.
    let role_of = |family: &str| {
        signals
            .iter()
            .find(|(e, _)| e.family == family)
            .map(|(e, _)| e.role)
    };
    let policy: Vec<&str> = families
        .iter()
        .copied()
        .filter(|f| role_of(f) == Some(Role::Policy))
        .collect();
    let others_are_base = families
        .iter()
        .all(|f| policy.contains(f) || role_of(f) == Some(Role::Base));
    if families.len() > 1 && policy.len() == 1 && others_are_base {
        families = policy.into_iter().collect();
    }
    if families.len() > 1 {
        return Named::Several(
            families
                .iter()
                .map(|family| {
                    table
                        .entries()
                        .iter()
                        .find(|e| e.family == *family)
                        .map_or(*family, |e| e.name.as_str())
                })
                .collect(),
        );
    }
    let Some(family) = families.iter().next() else {
        return Named::Nothing;
    };
    // The entry of the family that a DaemonSet named is the most exact one. Else the first entry of the
    // table with a signal, or for Canal made from its parts the Canal entry.
    let entry = signals
        .iter()
        .find(|(e, s)| e.family == *family && matches!(s, Signal::DaemonSet(_)))
        .map(|(e, _)| *e)
        .or_else(|| {
            if *family == "canal" {
                table.by_id("canal")
            } else {
                signals
                    .iter()
                    .find(|(e, _)| e.family == *family)
                    .map(|(e, _)| *e)
            }
        });
    match entry {
        Some(entry) => Named::One(entry, signals.into_iter().map(|(_, s)| s).collect()),
        None => Named::Nothing,
    }
}

/// True when the signals leave nothing for a DaemonSet to add: they named one plugin whose enforcement
/// needs no setting from its DaemonSet, or they named more than one (a DaemonSet would not settle that).
pub(super) fn settled(table: &Table, signals: &[(&Entry, Signal)]) -> bool {
    match name_plugin(table, signals.to_vec()) {
        Named::One(entry, _) => entry.enforces != Enforces::Env,
        Named::Several(_) => true,
        Named::Nothing => false,
    }
}

/// The family that the DaemonSet reads ask for first.
pub(super) fn first_family<'t>(
    table: &'t Table,
    signals: &[(&'t Entry, Signal)],
) -> Option<&'t str> {
    match name_plugin(table, signals.to_vec()) {
        Named::One(entry, _) => Some(entry.family.as_str()),
        _ => None,
    }
}

// ---- enforcement ------------------------------------------------------------------------------------------

/// Whether the plugin enforces `NetworkPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Enforcement {
    Yes,
    No,
    /// rdy cannot tell, and why, in words.
    Unknown(String),
}

/// True when a node reports a k3s kubelet.
fn is_k3s(nodes: &[NodeFacts]) -> bool {
    nodes.iter().any(|n| {
        n.kubelet_version
            .as_deref()
            .is_some_and(|v| v.contains("+k3s"))
    })
}

fn enforcement(
    named: &Named<'_>,
    nodes: &[NodeFacts],
    probes: Option<&[Probe]>,
) -> (Enforcement, bool) {
    match named {
        Named::Nothing => (
            Enforcement::Unknown("no network plugin was recognised".to_owned()),
            false,
        ),
        Named::Several(names) => (
            Enforcement::Unknown(format!(
                "the signals name more than one plugin ({})",
                names.join(", ")
            )),
            false,
        ),
        Named::One(entry, _) => match entry.enforces {
            Enforces::Yes => (Enforcement::Yes, false),
            Enforces::No if entry.id == "flannel" && is_k3s(nodes) => (
                Enforcement::Unknown(
                    "k3s runs Flannel and enforces NetworkPolicy with its own controller unless the server was started with --disable-network-policy, which rdy cannot read"
                        .to_owned(),
                ),
                true,
            ),
            Enforces::No => (Enforcement::No, false),
            Enforces::Env => {
                let facts = probes.and_then(|probes| {
                    probes.iter().find_map(|p| match (&p.read, p.entry == entry.id) {
                        (Read::Ok(facts), true) => Some(facts),
                        _ => None,
                    })
                });
                match facts.and_then(|f| f.network_policy_env.as_deref()) {
                    Some(value) if value.eq_ignore_ascii_case("true") => (Enforcement::Yes, false),
                    Some(value) if value.eq_ignore_ascii_case("false") => (Enforcement::No, false),
                    Some(_) => (
                        Enforcement::Unknown(
                            "ENABLE_NETWORK_POLICY on the aws-node DaemonSet is not true or false"
                                .to_owned(),
                        ),
                        false,
                    ),
                    None => (
                        Enforcement::Unknown(
                            "the setting ENABLE_NETWORK_POLICY of the aws-node DaemonSet was not read or is not set"
                                .to_owned(),
                        ),
                        false,
                    ),
                }
            }
        },
    }
}

// ---- the judgement ----------------------------------------------------------------------------------------

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
    fn grant(&mut self, grant: &'static Grant) {
        if !self.grants.iter().any(|have| have.text == grant.text) {
            self.grants.push(grant);
        }
    }

    fn fix_once(&mut self, line: &str) {
        if !self.fixes_unverified.iter().any(|have| have == line) {
            self.fixes_unverified.push(line.to_owned());
        }
    }
}

/// The ranges of the spec's `avoid_cidrs`, with their text.
fn avoid_ranges(params: &K8sCni) -> Vec<(String, Net)> {
    params
        .avoid_cidrs
        .iter()
        .flat_map(|list| list.iter())
        .filter_map(|cidr| Net::new(cidr.addr(), cidr.prefix()).map(|net| (net.to_string(), net)))
        .collect()
}

/// `host:port` of each `needs_egress` entry.
fn egress_needs(params: &K8sCni) -> Vec<String> {
    params
        .needs_egress
        .iter()
        .flat_map(|list| list.iter())
        .map(|item| format!("{}:{}", item.target().host(), item.target().port()))
        .collect()
}

pub(super) fn judge(table: &Table, params: &K8sCni, found: &Gathered) -> Finding {
    let mut sink = Sink::default();
    let avoid = avoid_ranges(params);
    let needs = egress_needs(params);
    let enforced = params.network_policy == Some(NetworkPolicyMode::Enforced);

    let page = match &found.nodes {
        Read::Ok(page) => Some(page),
        Read::Forbidden => {
            sink.unverified
                .push("the nodes were not read: the identity may not list them".to_owned());
            sink.grant(&LIST_NODES);
            None
        }
        other => {
            sink.unverified
                .push(format!("the nodes were not read: {}", other.why()));
            None
        }
    };
    let nodes: &[NodeFacts] = page.map_or(&[], |p| p.items.as_slice());
    if page.is_some_and(|p| p.cut) {
        sink.notes
            .push("Only the first 500 nodes were read.".to_owned());
    }
    let groups: &[String] = match &found.groups {
        Read::Ok(groups) => groups,
        other => {
            sink.unverified
                .push(format!("the API group list was not read: {}", other.why()));
            &[]
        }
    };
    let ocp = match &found.ocp {
        Some(Read::Ok(facts)) => Some(facts),
        Some(Read::Forbidden) => {
            sink.grant(&GET_OCP_NETWORK);
            sink.unverified.push(
                "the OpenShift Network object was not read: the identity may not read it"
                    .to_owned(),
            );
            None
        }
        Some(other) => {
            sink.unverified.push(format!(
                "the OpenShift Network object was not read: {}",
                other.why()
            ));
            None
        }
        None => None,
    };

    // The plugin: the cheap signals, then the DaemonSet found by name.
    let mut signals = cheap_signals(
        table,
        nodes,
        groups,
        ocp.and_then(|o| o.network_type.as_deref()),
    );
    if let Some(probes) = &found.probes {
        for probe in probes {
            if let (Read::Ok(_), Some(entry)) = (&probe.read, table.by_id(&probe.entry)) {
                signals.push((
                    entry,
                    Signal::DaemonSet(format!("{}/{}", probe.namespace, probe.name)),
                ));
            }
        }
    }
    let named = name_plugin(table, signals);
    let (enforcement, k3s) = enforcement(&named, nodes, found.probes.as_deref());
    let multus = groups.iter().any(|g| g == MULTUS_GROUP);

    describe_plugin(&named, multus, found, &mut sink);
    judge_enforcement(&named, &enforcement, k3s, enforced, &mut sink);
    judge_nodes(nodes, &mut sink);
    let pods = judge_ranges(&named, nodes, ocp, &found.service, &avoid, &mut sink);
    judge_policies(
        found,
        &needs,
        matches!(enforcement, Enforcement::No),
        &mut sink,
    );
    // One note on every result: these objects are not read, so "no default-deny" never means "no policy".
    sink.notes.push(
        "Only namespace NetworkPolicy objects are read. CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, Calico GlobalNetworkPolicy and AdminNetworkPolicy are not, so other policy may apply."
            .to_owned(),
    );

    finish(params, found, &named, &enforcement, nodes, ocp, pods, sink)
}

fn describe_plugin(named: &Named<'_>, multus: bool, found: &Gathered, sink: &mut Sink) {
    match named {
        Named::One(entry, signals) => {
            let via: Vec<String> = signals.iter().take(LISTED).map(Signal::words).collect();
            sink.quiet
                .push(format!("network plugin {} ({})", entry.name, via.join(", ")));
            if entry.id == "openshift-sdn" {
                sink.notes.push(
                    "OpenShift SDN has reached end of life. Plan the move to OVN-Kubernetes.".to_owned(),
                );
            }
        }
        Named::Several(names) => sink.notes.push(format!(
            "More than one network plugin shows signals: {}. A cluster that is moving from one to the other looks like this.",
            names.join(", ")
        )),
        Named::Nothing => {
            if let Some(probes) = &found.probes {
                let forbidden = probes.iter().any(|p| matches!(p.read, Read::Forbidden));
                if forbidden {
                    sink.unverified.push(
                        "no network plugin was recognised, and the DaemonSets of the known plugins could not all be read"
                            .to_owned(),
                    );
                    sink.grant(&GET_DAEMONSETS);
                } else if probes.iter().any(|p| {
                    matches!(
                        p.read,
                        Read::Unreadable(_) | Read::Refused | Read::OutOfTime
                    )
                }) {
                    sink.unverified.push(
                        "no network plugin was recognised, and some DaemonSets of the known plugins could not be read"
                            .to_owned(),
                    );
                } else if found.probes_cut {
                    sink.unverified.push(
                        "no network plugin was recognised before rdy ran out of time".to_owned(),
                    );
                } else {
                    sink.notes.push(
                        "No network plugin of the known list was recognised (node conditions, API groups and the DaemonSets of the list)."
                            .to_owned(),
                    );
                }
            }
        }
    }
    if multus {
        sink.notes.push(
            "Multus is installed (the API group k8s.cni.cncf.io). It adds networks next to the main plugin."
                .to_owned(),
        );
    }
}

fn judge_enforcement(
    named: &Named<'_>,
    enforcement: &Enforcement,
    k3s: bool,
    enforced: bool,
    sink: &mut Sink,
) {
    let name = match named {
        Named::One(entry, _) => entry.name.clone(),
        _ => "The network plugin".to_owned(),
    };
    match enforcement {
        Enforcement::Yes => sink.quiet.push("NetworkPolicy is enforced".to_owned()),
        Enforcement::No if enforced => {
            let aws = matches!(named, Named::One(entry, _) if entry.enforces == Enforces::Env);
            sink.issues.push(Issue {
                level: Level::Fail,
                message: if aws {
                    format!("{name} has its network policy agent off, and the spec needs NetworkPolicy enforced")
                } else {
                    format!("{name} does not enforce NetworkPolicy, and the spec needs it enforced")
                },
                fix: if aws {
                    fix::vpc_cni_policy_off().to_owned()
                } else {
                    fix::not_enforced(&name)
                },
            });
        }
        Enforcement::No => sink.notes.push(format!(
            "{name} does not enforce NetworkPolicy. The spec does not ask for it."
        )),
        Enforcement::Unknown(why) if enforced => {
            sink.unverified.push(format!(
                "whether NetworkPolicy is enforced is not known: {why}"
            ));
            if k3s {
                sink.fix_once(fix::check_k3s());
            } else if matches!(named, Named::One(entry, _) if entry.enforces == Enforces::Env) {
                sink.fix_once(fix::check_vpc_cni());
            }
        }
        Enforcement::Unknown(_) => {}
    }
}

fn judge_nodes(nodes: &[NodeFacts], sink: &mut Sink) {
    let down: Vec<String> = nodes
        .iter()
        .filter(|n| n.unavailable)
        .take(LISTED)
        .map(|n| shown(&n.name))
        .collect();
    if !down.is_empty() {
        let total = nodes.iter().filter(|n| n.unavailable).count();
        sink.notes.push(format!(
            "{total} node(s) report NetworkUnavailable as true, so their network plugin is not up: {}.",
            down.join(", ")
        ));
    }
}

/// What the pod ranges are known from, for the result.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PodRanges {
    from: &'static str,
    ranges: Vec<String>,
}

/// Judges the ranges against `avoid_cidrs`. Returns the pod ranges that were used.
fn judge_ranges(
    named: &Named<'_>,
    nodes: &[NodeFacts],
    ocp: Option<&OcpFacts>,
    service: &ServiceCidrs,
    avoid: &[(String, Net)],
    sink: &mut Sink,
) -> Option<PodRanges> {
    // Pod ranges: the OpenShift Network object is exact. Else the node field, only where the plugin uses
    // node IPAM.
    let node_ranges = || -> Vec<String> {
        let mut seen = BTreeSet::new();
        nodes
            .iter()
            .flat_map(|n| n.pod_cidrs.iter().cloned())
            .filter(|c| seen.insert(c.clone()))
            .collect()
    };
    let pods = match (ocp, named) {
        (Some(o), _) if !o.pod_cidrs.is_empty() => Some(PodRanges {
            from: "the OpenShift Network object",
            ranges: o.pod_cidrs.clone(),
        }),
        (_, Named::One(entry, _)) if entry.pod_cidr == PodCidr::Node => {
            let ranges = node_ranges();
            (!ranges.is_empty()).then_some(PodRanges {
                from: "the nodes (spec.podCIDRs)",
                ranges,
            })
        }
        _ => None,
    };
    let service_ranges: Vec<String> = service
        .found
        .as_ref()
        .map(|(_, ranges)| ranges.clone())
        .unwrap_or_default();

    if let Some(pods) = &pods {
        sink.quiet.push(format!(
            "pod ranges from {}: {}",
            pods.from,
            list_ranges(&pods.ranges)
        ));
    } else if !avoid.is_empty() {
        let why = match named {
            Named::One(entry, _) if entry.pod_cidr == PodCidr::Own => format!(
                "{} allocates pod addresses from its own pool, which rdy does not read",
                entry.name
            ),
            _ => "the plugin is not known, so rdy cannot say where pod addresses come from"
                .to_owned(),
        };
        sink.unverified
            .push(format!("the pod ranges were not compared: {why}"));
    } else if let Named::One(entry, _) = named
        && entry.pod_cidr == PodCidr::Own
    {
        sink.notes.push(format!(
            "{} allocates pod addresses from its own pool, which rdy does not read.",
            entry.name
        ));
    }
    match &service.found {
        Some((source, ranges)) => sink.quiet.push(format!(
            "service ranges from {}: {}",
            source.words(),
            list_ranges(ranges)
        )),
        None if !avoid.is_empty() => {
            sink.unverified
                .push("the service range was not read".to_owned());
            for unread in &service.unread {
                if let Some(grant) = unread.grant {
                    sink.grant(grant);
                }
            }
        }
        None => {}
    }
    if service.found.is_none()
        && !avoid.is_empty()
        && service.unread.iter().all(|u| u.grant.is_none())
    {
        // Every source answered "not there": a cluster that has none of them (a managed one).
        sink.notes
            .push("No service range source answered (ServiceCIDR, the OpenShift Network object, kubeadm-config).".to_owned());
    }

    for (kind, ranges) in [
        ("pod", pods.as_ref().map(|p| p.ranges.as_slice())),
        ("service", Some(service_ranges.as_slice())),
    ] {
        let Some(ranges) = ranges else { continue };
        for (avoid_text, avoid_net) in avoid {
            let hits: Vec<String> = ranges
                .iter()
                .filter_map(|text| Net::parse(text).map(|net| (text, net)))
                .filter(|(_, net)| net.overlaps(*avoid_net))
                .map(|(text, _)| shown(text))
                .collect();
            if hits.is_empty() {
                continue;
            }
            let listed: Vec<String> = hits.iter().take(LISTED).cloned().collect();
            let more = if hits.len() > LISTED {
                format!(" and {} more", hits.len() - LISTED)
            } else {
                String::new()
            };
            sink.issues.push(Issue {
                level: Level::Fail,
                message: format!(
                    "The {kind} range {}{more} overlaps {avoid_text}, which the spec says to avoid",
                    listed.join(", ")
                ),
                fix: if kind == "pod" {
                    fix::overlap_pod(avoid_text)
                } else {
                    fix::overlap_service(avoid_text)
                },
            });
        }
    }
    // A range from the server that is not a range is a note, not a block.
    let bad: Vec<String> = pods
        .iter()
        .flat_map(|p| p.ranges.iter())
        .chain(service_ranges.iter())
        .filter(|text| Net::parse(text).is_none())
        .map(|text| shown(text))
        .take(LISTED)
        .collect();
    if !bad.is_empty() {
        sink.notes.push(format!(
            "These values from the cluster are not address ranges and were not compared: {}.",
            bad.join(", ")
        ));
    }
    pods
}

fn list_ranges(ranges: &[String]) -> String {
    let shown_ranges: Vec<String> = ranges.iter().take(LISTED).map(|r| shown(r)).collect();
    if ranges.len() > LISTED {
        format!(
            "{} and {} more",
            shown_ranges.join(", "),
            ranges.len() - LISTED
        )
    } else {
        shown_ranges.join(", ")
    }
}

fn judge_policies(found: &Gathered, needs: &[String], enforcement_none: bool, sink: &mut Sink) {
    let wants = !needs.is_empty();
    let Some(namespace) = found.namespace.as_deref() else {
        if wants {
            sink.unverified.push(
                "the spec lists egress needs, and no install namespace is named, so no policy was read"
                    .to_owned(),
            );
            sink.fix_once(fix::name_the_namespace());
        }
        return;
    };
    let Some(read) = &found.policies else { return };
    let page = match read {
        Read::Ok(page) => page,
        Read::Forbidden => {
            if wants {
                sink.unverified.push(format!(
                    "the network policies of {namespace} were not read: the identity may not list them"
                ));
                sink.grant(&LIST_POLICIES);
            } else {
                sink.notes.push(format!(
                    "The network policies of {namespace} were not read: the identity may not list them."
                ));
            }
            return;
        }
        other => {
            let text = format!(
                "the network policies of {namespace} were not read: {}",
                other.why()
            );
            if wants {
                sink.unverified.push(text);
            } else {
                sink.notes.push(capitalise(&text));
            }
            return;
        }
    };
    if page.cut {
        sink.notes.push(format!(
            "Only the first 500 policies of {namespace} were read. {}",
            fix::cut_policies(namespace)
        ));
    }
    // 03: a default-deny policy is one that selects all pods and has no egress rules. A policy that selects
    // every pod and lists destinations is a restriction, not a default-deny, and is not judged.
    let selecting: Vec<&PolicyFacts> = page
        .items
        .iter()
        .filter(|p| p.selects_all && p.egress)
        .collect();
    let deny: Vec<&PolicyFacts> = selecting
        .iter()
        .copied()
        .filter(|p| p.egress_rules.is_empty())
        .collect();
    if deny.is_empty() {
        sink.quiet.push(format!(
            "no default-deny egress policy in {namespace} (namespace NetworkPolicy only)"
        ));
        return;
    }
    let names: Vec<String> = deny.iter().take(LISTED).map(|p| shown(&p.name)).collect();
    // Policies add up: a rule with no destination and no port in another policy that selects every pod
    // allows all egress again.
    if selecting
        .iter()
        .flat_map(|p| p.egress_rules.iter())
        .any(|r| !r.has_to && !r.has_ports)
    {
        sink.notes.push(format!(
            "Namespace {namespace} has a default-deny egress policy ({}), and another policy that selects every pod allows all destinations.",
            names.join(", ")
        ));
        return;
    }
    if enforcement_none {
        sink.notes.push(format!(
            "Namespace {namespace} has a default-deny egress policy ({}), and the network plugin does not enforce NetworkPolicy, so it blocks nothing today.",
            names.join(", ")
        ));
    } else if wants {
        sink.issues.push(Issue {
            level: Level::Warn,
            message: format!(
                "Namespace {namespace} has a default-deny egress policy ({}) that blocks all egress. The product needs egress to {}",
                names.join(", "),
                list_ranges(needs)
            ),
            fix: fix::default_deny(namespace, needs),
        });
    } else {
        sink.notes.push(format!(
            "Namespace {namespace} has a default-deny egress policy ({}) that blocks all egress. The spec lists no egress need.",
            names.join(", ")
        ));
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect::<String>() + ".",
        None => String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    params: &K8sCni,
    found: &Gathered,
    named: &Named<'_>,
    enforcement: &Enforcement,
    nodes: &[NodeFacts],
    ocp: Option<&OcpFacts>,
    pods: Option<PodRanges>,
    sink: Sink,
) -> Finding {
    let Sink {
        mut issues,
        notes,
        unverified,
        fixes_unverified,
        quiet,
        grants,
    } = sink;
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
        .with_observed(observed(
            found,
            named,
            enforcement,
            nodes,
            ocp,
            pods.as_ref(),
        ))
        .with_expected(expected(params))
}

fn pass_message(quiet: &[String]) -> String {
    let text = quiet.join("; ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Nothing found that stops the install".to_owned(),
    }
}

fn observed(
    found: &Gathered,
    named: &Named<'_>,
    enforcement: &Enforcement,
    nodes: &[NodeFacts],
    ocp: Option<&OcpFacts>,
    pods: Option<&PodRanges>,
) -> Value {
    let plugin = match named {
        Named::One(entry, signals) => json!({
            "id": entry.id,
            "name": entry.name,
            "signals": signals.iter().take(8).map(Signal::json).collect::<Vec<_>>(),
        }),
        Named::Several(names) => json!({"several": names}),
        Named::Nothing => Value::Null,
    };
    let enforces = match enforcement {
        Enforcement::Yes => json!("yes"),
        Enforcement::No => json!("no"),
        Enforcement::Unknown(why) => json!({"unknown": why}),
    };
    let service = found.service.found.as_ref().map(|(source, ranges)| {
        json!({
            "source": source.words(),
            "ranges": ranges.iter().take(8).map(|r| shown(r)).collect::<Vec<_>>(),
        })
    });
    let policies = match &found.policies {
        Some(Read::Ok(page)) => json!({
            "namespace": found.namespace,
            "read": page.items.len(),
            "default_deny_egress": page
                .items
                .iter()
                .filter(|p| p.selects_all && p.egress && p.egress_rules.is_empty())
                .take(8)
                .map(|p| shown(&p.name))
                .collect::<Vec<_>>(),
        }),
        _ => Value::Null,
    };
    json!({
        "plugin": plugin,
        "enforces_network_policy": enforces,
        "nodes_read": nodes.len(),
        "k3s": is_k3s(nodes),
        "network_type": ocp.and_then(|o| o.network_type.as_deref()).map(shown),
        "pod_ranges": pods.map(|p| json!({
            "from": p.from,
            "ranges": p.ranges.iter().take(8).map(|r| shown(r)).collect::<Vec<_>>(),
        })),
        "service_ranges": service,
        "policies": policies,
    })
}

fn expected(params: &K8sCni) -> Value {
    json!({
        "network_policy": params.network_policy.map(|_| "enforced"),
        "needs_egress": egress_needs(params),
        "avoid_cidrs": avoid_ranges(params).into_iter().map(|(text, _)| text).collect::<Vec<_>>(),
    })
}
