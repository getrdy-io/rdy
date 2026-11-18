//! Free capacity of `k8s.nodes` (03 section 4, M1-159): what the counted nodes have left after the pods'
//! requests.
//!
//! The Pod list is read with `status.phase!=Succeeded,status.phase!=Failed`, because the read-only guard
//! refuses a Pod list without a `status.phase` term. Of each pod only the node name, the phase and the
//! requests are kept: a pod spec can hold literal environment values, and none of it is read.
//!
//! The effective request of a pod is the larger of the init phase and the run phase, plus `spec.overhead`.
//! The run phase is the sum of the app containers and the restartable init containers (sidecars). A
//! regular init container runs with the sidecars that started before it, and a sidecar keeps its request
//! for the rest of the init phase. This is the rule the scheduler uses.
//!
//! Free is allocatable minus the effective requests of the pods on a node, floored at zero for each node,
//! and summed over the counted nodes. A pod with no node (Pending) takes nothing from any node. A node
//! that reports no allocatable for a resource gives none of it.
//!
//! A list that is forbidden, cut at the paging cap or not readable gives "not evaluated", never a pass.
//! When the cluster-wide list is cut, each counted node is listed by `spec.nodeName` (the same phase
//! terms), up to [`MAX_NODE_LISTS`] nodes. A request that is not a quantity is counted and makes the
//! result partial: free may be overstated, so it cannot pass.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Container, Pod, PodSpec};
use rdy_spec::check::K8sResources;
use serde_json::{Value, json};

use super::facts::{NodeFacts, RESOURCES, Resource};
use super::judge::human;
use crate::namespace::amount::{Amount, show};

/// The field selector every Pod list carries (the guard requires a `status.phase` term).
pub(super) const PHASE_SELECTOR: &str = "status.phase!=Succeeded,status.phase!=Failed";

/// The most counted nodes listed one by one when the cluster-wide Pod list was cut.
pub(super) const MAX_NODE_LISTS: usize = 25;

/// The requests of the pods on one node.
#[derive(Debug, Clone, Copy)]
pub(super) struct Usage {
    pods: u64,
    cpu: Amount,
    memory: Amount,
    ephemeral: Amount,
}

impl Usage {
    fn new() -> Self {
        Self {
            pods: 0,
            cpu: Amount::zero(),
            memory: Amount::zero(),
            ephemeral: Amount::zero(),
        }
    }

    fn get(&self, resource: Resource) -> Amount {
        match resource {
            Resource::Cpu => self.cpu,
            Resource::Memory => self.memory,
            Resource::Ephemeral => self.ephemeral,
            Resource::Pods => Amount::from_bytes(self.pods),
        }
    }
}

/// The Pod requests read, by node.
#[derive(Debug, Default)]
pub(super) struct PodsRead {
    by_node: BTreeMap<String, Usage>,
    /// How many pods were counted.
    seen: usize,
    /// How many requests were not quantities.
    unreadable: usize,
    /// The counted nodes were listed one by one.
    per_node: bool,
}

impl PodsRead {
    /// Adds the pods of one list.
    pub(super) fn add(&mut self, pods: &[Pod]) {
        for pod in pods {
            let Some(spec) = pod.spec.as_ref() else {
                continue;
            };
            let node = spec.node_name.as_deref().unwrap_or_default();
            let phase = pod
                .status
                .as_ref()
                .and_then(|status| status.phase.as_deref());
            // The server already left these out. A fixture or a server that did not is judged the same.
            if node.is_empty() || matches!(phase, Some("Succeeded" | "Failed")) {
                continue;
            }
            let mut bad = false;
            let usage = self
                .by_node
                .entry(node.to_owned())
                .or_insert_with(Usage::new);
            usage.pods += 1;
            usage.cpu = usage.cpu.plus(effective(spec, "cpu", &mut bad));
            usage.memory = usage.memory.plus(effective(spec, "memory", &mut bad));
            usage.ephemeral = usage
                .ephemeral
                .plus(effective(spec, "ephemeral-storage", &mut bad));
            self.seen += 1;
            self.unreadable += usize::from(bad);
        }
    }

    /// Marks that the counted nodes were listed one by one.
    pub(super) fn by_node_lists(&mut self) {
        self.per_node = true;
    }
}

/// What the check got when it asked for the pods.
#[derive(Debug)]
pub(super) enum FreeRead {
    /// The spec has no `free`.
    NotAsked,
    /// No node counts, so there is nothing to add up.
    NoNodes,
    /// The pods were read.
    Read(PodsRead),
    /// The pods could not be read. `grants` holds `list pods` when the server said forbidden.
    NotEvaluated { why: String, grants: Vec<String> },
}

/// One request of a container. Text that is not a quantity counts as zero and sets `bad`.
fn request(container: &Container, key: &str, bad: &mut bool) -> Amount {
    let Some(quantity) = container
        .resources
        .as_ref()
        .and_then(|resources| resources.requests.as_ref())
        .and_then(|requests| requests.get(key))
    else {
        return Amount::zero();
    };
    Amount::parse(&quantity.0).unwrap_or_else(|| {
        *bad = true;
        Amount::zero()
    })
}

/// The effective request of a pod for one resource.
fn effective(spec: &PodSpec, key: &str, bad: &mut bool) -> Amount {
    let apps = spec
        .containers
        .iter()
        .fold(Amount::zero(), |sum, c| sum.plus(request(c, key, bad)));
    let mut sidecars = Amount::zero();
    let mut peak = Amount::zero();
    for init in spec.init_containers.iter().flatten() {
        let asked = request(init, key, bad);
        if init.restart_policy.as_deref() == Some("Always") {
            sidecars = sidecars.plus(asked);
            peak = peak.max(sidecars);
        } else {
            peak = peak.max(sidecars.plus(asked));
        }
    }
    let overhead = match spec.overhead.as_ref().and_then(|map| map.get(key)) {
        Some(quantity) => Amount::parse(&quantity.0).unwrap_or_else(|| {
            *bad = true;
            Amount::zero()
        }),
        None => Amount::zero(),
    };
    peak.max(apps.plus(sidecars)).plus(overhead)
}

/// One resource that is short.
#[derive(Debug)]
pub(super) struct Shortfall {
    pub(super) warn_only: bool,
    pub(super) text: String,
}

/// The judgement of free capacity.
#[derive(Debug, Default)]
pub(super) struct FreeVerdict {
    /// The resources that are short, a block, or a warn inside the 120% margin.
    pub(super) short: Vec<Shortfall>,
    /// Why part of it was not evaluated.
    pub(super) unverified: Vec<String>,
    /// The grants the identity lacks.
    pub(super) grants: Vec<String>,
    /// The `free` field of the result.
    pub(super) observed: Value,
    /// What to do when the pods could not be read.
    pub(super) fix: Option<String>,
}

/// The amount of `resource` the spec's `free` asks for.
fn need_of(free: &K8sResources, resource: Resource) -> Option<Amount> {
    match resource {
        Resource::Cpu => free.cpu.map(|cpu| {
            Amount::parse(&format!("{}m", cpu.millicores())).unwrap_or_else(Amount::zero)
        }),
        Resource::Memory => free.memory.map(|size| Amount::from_bytes(size.bytes())),
        Resource::Ephemeral => free.ephemeral.map(|size| Amount::from_bytes(size.bytes())),
        Resource::Pods => free
            .pods
            .map(|pods| Amount::from_bytes(u64::from(pods.get()))),
    }
}

/// What `free` asks for, as a result field.
pub(super) fn expected(free: &K8sResources) -> Value {
    let mut out = serde_json::Map::new();
    for resource in RESOURCES {
        if let Some(need) = need_of(free, resource) {
            out.insert(
                resource.field().to_owned(),
                json!(show(need, resource.bytes())),
            );
        }
    }
    Value::Object(out)
}

/// Judges `free` against what the counted nodes have left.
pub(super) fn judge(free: &K8sResources, counted: &[&NodeFacts], read: &FreeRead) -> FreeVerdict {
    let mut verdict = FreeVerdict::default();
    let pods = match read {
        FreeRead::NotAsked => return verdict,
        FreeRead::NoNodes => {
            verdict
                .unverified
                .push("free capacity was not evaluated: no node counts".to_owned());
            verdict.observed = json!("not evaluated");
            return verdict;
        }
        FreeRead::NotEvaluated { why, grants } => {
            verdict.unverified.push(format!(
                "free capacity was not evaluated: the pod requests could not be read ({why})"
            ));
            verdict.grants.clone_from(grants);
            verdict.fix = Some(if grants.is_empty() {
                fix_by_hand()
            } else {
                fix_grant()
            });
            verdict.observed = json!("not evaluated");
            return verdict;
        }
        FreeRead::Read(pods) => pods,
    };
    let mut fields = serde_json::Map::new();
    for resource in RESOURCES {
        let Some(need) = need_of(free, resource) else {
            continue;
        };
        let mut left = Amount::zero();
        let mut requested = Amount::zero();
        for node in counted {
            let used = pods
                .by_node
                .get(&node.name)
                .map_or_else(|| Usage::new().get(resource), |usage| usage.get(resource));
            requested = requested.plus(used);
            if let Some(have) = node.allocatable.get(resource) {
                left = left.plus(have.minus(used).at_least_zero());
            }
        }
        let bytes = resource.bytes();
        fields.insert(
            resource.field().to_owned(),
            json!({
                "free": show(left, bytes),
                "need": show(need, bytes),
                "requested": show(requested, bytes),
            }),
        );
        let (short, warn_only) = if left < need {
            (true, false)
        } else {
            (left < need.with_margin(), true)
        };
        if short {
            let margin = if warn_only {
                " (below the 120% margin)"
            } else {
                ""
            };
            verdict.short.push(Shortfall {
                warn_only,
                text: format!(
                    "Free {} on the {} counted nodes is {}, and the spec needs {}{margin}. Pods already request {}",
                    resource.name(),
                    counted.len(),
                    human(left, bytes),
                    human(need, bytes),
                    human(requested, bytes),
                ),
            });
        }
    }
    fields.insert("pods_read".to_owned(), json!(pods.seen));
    fields.insert("unreadable_requests".to_owned(), json!(pods.unreadable));
    fields.insert("listed_per_node".to_owned(), json!(pods.per_node));
    verdict.observed = Value::Object(fields);
    if pods.unreadable > 0 {
        verdict.unverified.push(format!(
            "{} pods had a request that is not a quantity, so free capacity may be overstated",
            pods.unreadable
        ));
    }
    verdict
}

/// The fix for a short free capacity.
pub(super) fn fix_short() -> String {
    "Add nodes, or a node group with larger nodes (EKS: `eksctl create nodegroup --cluster <cluster> --nodes 3 --node-type m6i.2xlarge`), or move load off the counted nodes. `kubectl describe node <node>` lists the requests already placed on it under Allocated resources.".to_owned()
}

/// The fix for a Pod list the identity may not read.
pub(super) fn fix_grant() -> String {
    "Ask the cluster admin to grant this identity `list` on `pods`, or check free capacity by hand with `kubectl describe node <node>`. Check with `kubectl auth can-i list pods`.".to_owned()
}

/// The fix for a Pod list that could not be read for another reason.
pub(super) fn fix_by_hand() -> String {
    "Check free capacity by hand: `kubectl describe node <node>` lists the requests placed on each node under Allocated resources.".to_owned()
}
