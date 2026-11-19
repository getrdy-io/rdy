//! The judgement of `k8s.nodes`: pure functions from the nodes read to a [`Finding`].
//!
//! The rules, from 03:
//!
//! - A node counts when it is `Ready`, not cordoned, Linux, not Fargate or virtual, matches the `selector`
//!   and the `arch` list, and has no `NoSchedule` or `NoExecute` taint that `tolerations` do not tolerate
//!   (`facts::NodeFacts::excluded`).
//! - `per_node` is judged on allocatable, never on capacity. With `min_ready`, that many counted nodes must
//!   meet it. Without `min_ready`, every counted node must, and at least one must count.
//! - A shortfall of nodes blocks. It warns instead, "capacity may scale, not verified", when every counted
//!   node is big enough and a node autoscaler is found: the shortfall is then only a count. A node that is
//!   too small never takes that exit.
//! - Pods per node (`allocatable.pods`) is its own problem with its own fix.
//! - Pressure conditions on a counted node warn.
//! - `min_zones` blocks. Without a zone label on any counted node it is "not evaluated" (partial).
//! - `free` is judged by [`super::free`]: the counted nodes' allocatable minus the pods' requests. Short is a
//!   block, below the 120% margin a warn, and a Pod list that could not be read is partial, never a pass.
//!
//! The 120% margin of 03 belongs to `free`. It is not applied to `per_node`: `cpu: 7` must pass on a node
//! that shows 7910m.

use std::collections::BTreeMap;

use rdy_engine::check::{Finding, Level, Partial};
use rdy_spec::check::K8sNodes;
use serde_json::{Value, json};

use super::facts::{Excluded, NodeFacts, Platform, RESOURCES, Resource, command_arg, shown};
use super::fix;
use super::free::{self, FreeRead};
use crate::namespace::amount::{Amount, show};

/// The most nodes listed in the result.
const MAX_LISTED: usize = 20;

/// The most zones, versions and runtimes listed in the result.
const MAX_KINDS: usize = 16;

/// The most node names a sentence names.
const MAX_NAMED: usize = 3;

/// What was found about a node autoscaler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Scaler {
    /// One was found. The text names it.
    Found(String),
    /// Every place that was looked at says there is none.
    NotFound,
    /// A place could not be read, so "none" is not known. The text says why.
    Unknown(String),
}

/// The amount the spec's `per_node` or `free` asks for, as one number per resource.
#[derive(Debug, Clone, Copy, Default)]
struct Needs {
    cpu: Option<Amount>,
    memory: Option<Amount>,
    ephemeral: Option<Amount>,
    pods: Option<Amount>,
}

impl Needs {
    fn of(params: &K8sNodes) -> Self {
        let Some(per_node) = &params.per_node else {
            return Self::default();
        };
        Self {
            cpu: per_node.cpu.map(|cpu| {
                Amount::parse(&format!("{}m", cpu.millicores())).unwrap_or(Amount::from_bytes(0))
            }),
            memory: per_node
                .memory
                .map(|memory| Amount::from_bytes(memory.bytes())),
            ephemeral: per_node
                .ephemeral
                .map(|size| Amount::from_bytes(size.bytes())),
            pods: per_node
                .pods
                .map(|pods| Amount::from_bytes(u64::from(pods.get()))),
        }
    }

    fn get(&self, resource: Resource) -> Option<Amount> {
        match resource {
            Resource::Cpu => self.cpu,
            Resource::Memory => self.memory,
            Resource::Ephemeral => self.ephemeral,
            Resource::Pods => self.pods,
        }
    }

    /// The resources below `node`'s allocatable: those the spec asks for and the node does not have, or
    /// does not report.
    fn short(&self, node: &NodeFacts) -> Vec<Resource> {
        RESOURCES
            .into_iter()
            .filter(|resource| {
                self.get(*resource).is_some_and(|need| {
                    node.allocatable
                        .get(*resource)
                        .is_none_or(|have| have < need)
                })
            })
            .collect()
    }

    /// `7 CPU, 28Gi memory` for the given resources.
    fn text(&self, resources: &[Resource]) -> String {
        let parts: Vec<String> = resources
            .iter()
            .filter_map(|resource| {
                self.get(*resource)
                    .map(|need| format!("{} {}", show(need, resource.bytes()), resource.name()))
            })
            .collect();
        join(&parts)
    }
}

/// An amount for a sentence: sizes in bytes are rounded to a tenth of a Gi (or whole Mi), so `29567452Ki`
/// reads `28.2Gi`. The result keeps the exact text ([`show`]).
pub(super) fn human(amount: Amount, bytes: bool) -> String {
    const GI: i128 = 1 << 30;
    const MI: i128 = 1 << 20;
    if !bytes {
        return show(amount, false);
    }
    let total = amount.nano() / 1_000_000_000;
    if total >= GI {
        let tenths = (total * 10 + GI / 2) / GI;
        let (whole, tenth) = (tenths / 10, tenths % 10);
        if tenth == 0 {
            format!("{whole}Gi")
        } else {
            format!("{whole}.{tenth}Gi")
        }
    } else if total >= MI {
        format!("{}Mi", (total + MI / 2) / MI)
    } else {
        show(amount, true)
    }
}

/// `a`, `a and b`, `a, b and c`.
fn join(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [only] => only.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The nodes read, sorted into counted and not, with what is short.
pub(super) struct Assessment<'a> {
    pub(super) total: usize,
    pub(super) counted: Vec<&'a NodeFacts>,
    /// Why each node that does not count does not count, with its name.
    excluded: BTreeMap<Excluded, Vec<&'a str>>,
    needs: Needs,
    /// The counted nodes below `per_node`, and the resources they lack.
    short: Vec<(&'a NodeFacts, Vec<Resource>)>,
    min_ready: Option<usize>,
    /// A capacity service that sizes new nodes to pending pods (Karpenter, Auto Mode, Autopilot, node
    /// auto-provisioning), from the labels of any node.
    managed: Option<&'static str>,
    /// A node runs on GKE or AKS, whose own autoscaler leaves no object that rdy may read.
    hosted: bool,
}

impl<'a> Assessment<'a> {
    pub(super) fn new(params: &K8sNodes, nodes: &'a [NodeFacts]) -> Self {
        let needs = Needs::of(params);
        let mut counted = Vec::new();
        let mut excluded: BTreeMap<Excluded, Vec<&str>> = BTreeMap::new();
        for node in nodes {
            match node.excluded(params) {
                Some(reason) => excluded.entry(reason).or_default().push(&node.name),
                None => counted.push(node),
            }
        }
        let short = counted
            .iter()
            .filter_map(|node| {
                let lacking = needs.short(node);
                (!lacking.is_empty()).then_some((*node, lacking))
            })
            .collect();
        Self {
            total: nodes.len(),
            counted,
            excluded,
            needs,
            short,
            min_ready: params
                .min_ready
                .map(|n| usize::try_from(n.get()).unwrap_or(usize::MAX)),
            managed: nodes.iter().find_map(NodeFacts::scaler_hint),
            hosted: nodes
                .iter()
                .any(|node| matches!(node.platform(), Platform::Gke | Platform::Aks)),
        }
    }

    /// Counted nodes that meet `per_node`.
    fn fits(&self) -> usize {
        self.counted.len() - self.short.len()
    }

    /// The spec's node requirement is not met. With no node counted it never is: a spec that asks for
    /// nothing about nodes still needs one.
    fn blocked(&self) -> bool {
        if self.counted.is_empty() {
            return true;
        }
        match self.min_ready {
            Some(min) => self.fits() < min,
            None => !self.short.is_empty(),
        }
    }

    /// The only thing wrong is that there are too few nodes (or none), which an autoscaler can fix. The
    /// caller asks whether one exists only when this is true.
    pub(super) fn only_a_count_is_short(&self) -> bool {
        self.blocked() && self.short.is_empty()
    }

    /// `3 not Ready, 1 cordoned`.
    fn why_excluded(&self) -> String {
        let parts: Vec<String> = self
            .excluded
            .iter()
            .map(|(reason, names)| format!("{} {}", names.len(), reason.phrase()))
            .collect();
        parts.join(", ")
    }
}

/// One thing wrong, with its fix.
struct Problem {
    level: Level,
    text: String,
    fix: String,
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Fail => 2,
        Level::Warn => 1,
        _ => 0,
    }
}

/// The first few names of `names`, escaped, and how many are left.
fn some(names: &[&str]) -> String {
    let shown_names: Vec<String> = names
        .iter()
        .take(MAX_NAMED)
        .map(|name| shown(name))
        .collect();
    let more = names.len().saturating_sub(MAX_NAMED);
    if more == 0 {
        shown_names.join(", ")
    } else {
        format!("{} and {more} more", shown_names.join(", "))
    }
}

/// The finding for a node list that was read.
pub(super) fn finish(
    params: &K8sNodes,
    found: &Assessment<'_>,
    scaler: Option<&Scaler>,
    cut: bool,
    pods: &FreeRead,
) -> Finding {
    let mut problems: Vec<Problem> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();

    count_and_size(found, scaler, cut, &mut problems);
    if let Some(Scaler::Unknown(why)) = scaler
        && found.only_a_count_is_short()
    {
        notes.push(format!(
            "rdy could not check for a node autoscaler ({why}), so the shortfall stands."
        ));
    }
    if found.only_a_count_is_short() && found.hosted && !matches!(scaler, Some(Scaler::Found(_))) {
        notes.push(
            "managed autoscalers are invisible without a ConfigMap read, so check by hand: `kubectl get nodes` after a scale-up, or the node pool settings in the cloud console."
                .to_owned(),
        );
    }
    if params.per_node.is_some()
        && let Some(managed) = found.managed
    {
        notes.push(format!(
            "per_node is only a hint here: {managed} sizes new nodes to the pods waiting for them, so the nodes that exist now may not be the nodes the product gets."
        ));
    }
    pressure(found, &mut problems);
    zones(params, found, cut, &mut problems, &mut unverified);

    let mut grants: Vec<String> = Vec::new();
    let mut free_observed = Value::Null;
    let mut free_fix: Option<String> = None;
    if let Some(free_need) = &params.free {
        let verdict = free::judge(free_need, &found.counted, pods);
        for short in verdict.short {
            problems.push(Problem {
                level: if short.warn_only {
                    Level::Warn
                } else {
                    Level::Fail
                },
                text: short.text,
                fix: free::fix_short(),
            });
        }
        unverified.extend(verdict.unverified);
        grants = verdict.grants;
        free_fix = verdict.fix;
        free_observed = verdict.observed;
    }
    if cut {
        unverified.push(format!(
            "the node list was cut after {} nodes, the rest are not evaluated",
            found.total
        ));
    }

    problems.sort_by_key(|problem| std::cmp::Reverse(rank(problem.level)));
    let level = problems.first().map_or(Level::Pass, |p| p.level);
    let mut finding = match problems.first() {
        Some(first) => {
            let more = problems.len() - 1;
            let message = if more == 0 {
                first.text.clone()
            } else {
                format!("{} (and {more} more, see the notes)", first.text)
            };
            let mut finding = Finding::new(level, message);
            for problem in problems.iter().skip(1) {
                finding = finding.with_note(problem.text.clone());
            }
            let mut fixes: Vec<&str> = Vec::new();
            for problem in &problems {
                if !fixes.contains(&problem.fix.as_str()) {
                    fixes.push(&problem.fix);
                }
            }
            finding.with_fix(fixes.join(" "))
        }
        None => Finding::new(Level::Pass, pass_message(params, found)),
    };
    for note in notes {
        finding = finding.with_note(note);
    }
    if !unverified.is_empty() {
        finding = finding.with_partial(
            Partial::new(Vec::new(), unverified.join("; ")).with_missing_grants(grants),
        );
    }
    if problems.is_empty()
        && let Some(fix) = free_fix
    {
        finding = finding.with_fix(fix);
    }
    finding
        .with_observed(observed(found, scaler, cut, free_observed))
        .with_expected(expected(params))
}

/// The finding for a node list that could not be read. It is never a block (03).
pub(super) fn unreadable(params: &K8sNodes, why: &str, forbidden: bool) -> Finding {
    let message = format!("Not verified: the node list could not be read ({why})");
    let grants = if forbidden {
        vec!["list nodes".to_owned()]
    } else {
        Vec::new()
    };
    let mut finding = Finding::new(Level::Pass, message)
        .with_partial(
            Partial::new(Vec::new(), "the node list was not read").with_missing_grants(grants),
        )
        .with_observed(json!({"nodes_read": false}))
        .with_expected(expected(params));
    finding = finding.with_fix(if forbidden {
        fix::grant_list()
    } else {
        fix::by_hand()
    });
    finding
}

/// The problems of how many nodes there are and how big they are.
fn count_and_size(
    found: &Assessment<'_>,
    scaler: Option<&Scaler>,
    cut: bool,
    problems: &mut Vec<Problem>,
) {
    if !found.blocked() {
        return;
    }
    let counted = found.counted.len();
    let pure_count = found.short.is_empty();
    let scales = matches!(scaler, Some(Scaler::Found(_))) && pure_count;
    let missing_nodes = match found.min_ready {
        Some(min) => counted < min,
        None => counted == 0,
    };
    // Nodes past the cut were not read, so a count that is short may not be.
    let unread = ". The node list was cut, so more nodes may exist";

    if missing_nodes {
        let fits = found.fits();
        let mut text = if found.total == 0 {
            "The cluster has no node that the product can use".to_owned()
        } else if let Some(min) = found.min_ready {
            format!(
                "Only {fits} of {} nodes can run the product, and the spec needs {min}",
                found.total
            )
        } else {
            "No node can run the product".to_owned()
        };
        let mut parts = Vec::new();
        let why = found.why_excluded();
        if !why.is_empty() {
            parts.push(why);
        }
        if !found.short.is_empty() {
            parts.push(format!("{} below per_node", found.short.len()));
        }
        if !parts.is_empty() {
            text.push_str(&format!(" ({})", parts.join(", ")));
        }
        let (level, fix_text) = match scaler {
            Some(Scaler::Found(name)) if scales => {
                text.push_str(&format!(
                    ". Capacity may scale ({name} is installed), not verified"
                ));
                (Level::Warn, fix::scale_up())
            }
            _ if cut => {
                text.push_str(unread);
                (Level::Warn, fix::add_nodes(&first_names(found)))
            }
            _ => (Level::Fail, fix::add_nodes(&first_names(found))),
        };
        problems.push(Problem {
            level,
            text,
            fix: fix_text,
        });
    }

    // The size of the counted nodes: the dimensions other than pods, then pods, each with its own fix.
    let others: Vec<Resource> = RESOURCES
        .into_iter()
        .filter(|r| *r != Resource::Pods)
        .filter(|r| found.short.iter().any(|(_, lacking)| lacking.contains(r)))
        .collect();
    if !others.is_empty() {
        let k = found
            .counted
            .iter()
            .filter(|node| others.iter().all(|r| !found.needs.short(node).contains(r)))
            .count();
        problems.push(Problem {
            level: size_level(found, cut),
            text: format!(
                "Only {k} of {counted} counted nodes have {} allocatable (the smallest has {})",
                found.needs.text(&others),
                smallest(found, &others)
            ),
            fix: fix::bigger_nodes(),
        });
    }
    if let Some(worst) = pods_short(found) {
        let (node, k) = worst;
        let need = found
            .needs
            .get(Resource::Pods)
            .map_or_else(String::new, |need| show(need, false));
        let have = node
            .allocatable
            .get(Resource::Pods)
            .map_or_else(|| "not reported".to_owned(), |have| show(have, false));
        let instance = node
            .instance_type
            .as_deref()
            .map_or_else(String::new, |kind| format!(" ({})", shown(kind)));
        problems.push(Problem {
            level: size_level(found, cut),
            text: format!(
                "Only {k} of {counted} counted nodes allow {need} pods. {}{instance} allows {have}",
                shown(&node.name)
            ),
            fix: fix::pod_limit(node.platform(), &command_arg(&node.name, "<node>")),
        });
    }
}

/// A size problem is certain unless it only decides whether enough nodes fit and the list was cut.
fn size_level(found: &Assessment<'_>, cut: bool) -> Level {
    if cut && found.min_ready.is_some() {
        Level::Warn
    } else {
        Level::Fail
    }
}

/// The counted node with the fewest pods, when any counted node is below the pod need, and how many counted
/// nodes meet it.
fn pods_short<'a>(found: &Assessment<'a>) -> Option<(&'a NodeFacts, usize)> {
    let low: Vec<&NodeFacts> = found
        .short
        .iter()
        .filter(|(_, lacking)| lacking.contains(&Resource::Pods))
        .map(|(node, _)| *node)
        .collect();
    let worst = low
        .iter()
        .copied()
        .min_by_key(|node| node.allocatable.get(Resource::Pods).map(Amount::nano))?;
    Some((worst, found.counted.len() - low.len()))
}

/// The smallest allocatable of each resource over the counted nodes, `3920m CPU, 14Gi memory`.
fn smallest(found: &Assessment<'_>, resources: &[Resource]) -> String {
    let parts: Vec<String> = resources
        .iter()
        .map(|resource| {
            let least = found
                .counted
                .iter()
                .map(|node| node.allocatable.get(*resource))
                .try_fold(None::<Amount>, |least, have| {
                    have.map(|have| Some(least.map_or(have, |l| l.min(have))))
                });
            match least.flatten() {
                Some(have) => format!("{} {}", human(have, resource.bytes()), resource.name()),
                None => format!("{} not reported", resource.name()),
            }
        })
        .collect();
    join(&parts)
}

/// The first node of each reason it does not count, for the commands of the fix.
fn first_names<'a>(found: &Assessment<'a>) -> Vec<(Excluded, &'a str)> {
    found
        .excluded
        .iter()
        .filter_map(|(reason, names)| names.first().map(|name| (*reason, *name)))
        .collect()
}

fn pressure(found: &Assessment<'_>, problems: &mut Vec<Problem>) {
    let under: Vec<&&NodeFacts> = found
        .counted
        .iter()
        .filter(|node| !node.pressure.is_empty())
        .collect();
    let Some(first) = under.first() else {
        return;
    };
    let names: Vec<&str> = under.iter().map(|node| node.name.as_str()).collect();
    problems.push(Problem {
        level: Level::Warn,
        text: format!(
            "{} counted node{} report{} {}: {}",
            under.len(),
            if under.len() == 1 { "" } else { "s" },
            if under.len() == 1 { "s" } else { "" },
            if under.iter().all(|node| node.pressure == first.pressure) {
                first.pressure.join(" and ")
            } else {
                "pressure".to_owned()
            },
            some(&names)
        ),
        fix: fix::pressure(&command_arg(&first.name, "<node>")),
    });
}

fn zones(
    params: &K8sNodes,
    found: &Assessment<'_>,
    cut: bool,
    problems: &mut Vec<Problem>,
    unverified: &mut Vec<String>,
) {
    let Some(min) = params.min_zones else {
        return;
    };
    if found.counted.is_empty() {
        return;
    }
    let labeled: Vec<&NodeFacts> = found
        .counted
        .iter()
        .copied()
        .filter(|node| node.zone.is_some())
        .collect();
    if labeled.is_empty() {
        unverified.push("min_zones was not evaluated: no counted node has a zone label".to_owned());
        return;
    }
    let distinct = zone_names(found).len();
    let need = usize::try_from(min.get()).unwrap_or(usize::MAX);
    if distinct < need {
        let unlabeled = found.counted.len() - labeled.len();
        let extra = if unlabeled == 0 {
            String::new()
        } else {
            format!(" ({unlabeled} counted nodes have no zone label)")
        };
        problems.push(Problem {
            level: if cut { Level::Warn } else { Level::Fail },
            text: format!(
                "The counted nodes span {distinct} zone{}, and the spec needs {need}{extra}",
                if distinct == 1 { "" } else { "s" }
            ),
            fix: fix::more_zones(),
        });
    }
}

/// The distinct zones of the counted nodes, sorted.
fn zone_names<'a>(found: &Assessment<'a>) -> Vec<&'a str> {
    let mut zones: Vec<&str> = found
        .counted
        .iter()
        .filter_map(|node| node.zone.as_deref())
        .collect();
    zones.sort_unstable();
    zones.dedup();
    zones
}

fn pass_message(params: &K8sNodes, found: &Assessment<'_>) -> String {
    let mut text = format!("{} of {} nodes count", found.counted.len(), found.total);
    let why = found.why_excluded();
    if !why.is_empty() {
        text.push_str(&format!(" ({why})"));
    }
    let wanted: Vec<Resource> = RESOURCES
        .into_iter()
        .filter(|r| found.needs.get(*r).is_some())
        .collect();
    if !wanted.is_empty() && !found.counted.is_empty() {
        text.push_str(&format!(
            ", the smallest has {} allocatable",
            smallest(found, &wanted)
        ));
    }
    if let Some(min) = params.min_zones {
        text.push_str(&format!(
            ", {} zones of the {min} needed",
            zone_names(found).len()
        ));
    }
    text
}

fn amount_pair(node: &NodeFacts, resource: Resource) -> Value {
    let one = |amount: Option<Amount>| amount.map(|a| show(a, resource.bytes()));
    json!({
        "allocatable": one(node.allocatable.get(resource)),
        "capacity": one(node.capacity.get(resource)),
    })
}

fn observed(found: &Assessment<'_>, scaler: Option<&Scaler>, cut: bool, free: Value) -> Value {
    let mut excluded = serde_json::Map::new();
    for (reason, names) in &found.excluded {
        excluded.insert(reason.field().to_owned(), json!(names.len()));
    }
    let mut arches: BTreeMap<String, usize> = BTreeMap::new();
    let mut kubelets: BTreeMap<String, usize> = BTreeMap::new();
    let mut runtimes: BTreeMap<String, usize> = BTreeMap::new();
    for node in &found.counted {
        let arch = node
            .arch_text
            .as_deref()
            .map_or_else(|| "unknown".to_owned(), shown);
        *arches.entry(arch).or_default() += 1;
        if let Some(kubelet) = &node.kubelet {
            *kubelets.entry(shown(kubelet)).or_default() += 1;
        }
        if let Some(runtime) = &node.runtime {
            *runtimes.entry(shown(runtime)).or_default() += 1;
        }
    }
    let listed: Vec<Value> = found
        .counted
        .iter()
        .take(MAX_LISTED)
        .map(|node| {
            json!({
                "name": shown(&node.name),
                "cpu": amount_pair(node, Resource::Cpu),
                "memory": amount_pair(node, Resource::Memory),
                "ephemeral": amount_pair(node, Resource::Ephemeral),
                "pods": amount_pair(node, Resource::Pods),
                "zone": node.zone.as_deref().map(shown),
                "instance_type": node.instance_type.as_deref().map(shown),
                "pressure": node.pressure,
            })
        })
        .collect();
    let cap = |counts: BTreeMap<String, usize>| -> Value {
        Value::Object(
            counts
                .into_iter()
                .take(MAX_KINDS)
                .map(|(name, n)| (name, json!(n)))
                .collect(),
        )
    };
    json!({
        "nodes_read": found.total,
        "list_cut": cut,
        "counted": found.counted.len(),
        "meeting_per_node": found.fits(),
        "excluded": Value::Object(excluded),
        "zones": zone_names(found).into_iter().take(MAX_KINDS).map(shown).collect::<Vec<_>>(),
        "arch": cap(arches),
        "kubelet_versions": cap(kubelets),
        "runtimes": cap(runtimes),
        "nodes": listed,
        "nodes_omitted": found.counted.len().saturating_sub(MAX_LISTED),
        "autoscaler": match scaler {
            Some(Scaler::Found(name)) => json!(name),
            Some(Scaler::NotFound) => json!("none found"),
            Some(Scaler::Unknown(_)) => json!("not known"),
            None => Value::Null,
        },
        "free": free,
    })
}

fn expected(params: &K8sNodes) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(min) = params.min_ready {
        out.insert("min_ready".to_owned(), json!(min.get()));
    }
    if let Some(min) = params.min_zones {
        out.insert("min_zones".to_owned(), json!(min.get()));
    }
    let needs = Needs::of(params);
    let mut per_node = serde_json::Map::new();
    for resource in RESOURCES {
        if let Some(need) = needs.get(resource) {
            per_node.insert(
                resource.field().to_owned(),
                json!(show(need, resource.bytes())),
            );
        }
    }
    if !per_node.is_empty() {
        out.insert("per_node".to_owned(), Value::Object(per_node));
    }
    if let Some(free) = &params.free {
        out.insert("free".to_owned(), free::expected(free));
    }
    Value::Object(out)
}
