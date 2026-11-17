//! What `k8s.nodes` keeps of a `Node`, and which nodes count (03, "k8s.nodes").
//!
//! Nothing else of a node is kept. Every text here came from the server: it is escaped before it is shown
//! ([`shown`]) and never reaches a command except through [`command_arg`].

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Node;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::{Arch, K8sNodes, TaintEffect, Toleration, TolerationOperator};

use crate::namespace::amount::Amount;

/// The longest node name or label text shown whole, in characters.
const SHOWN: usize = 64;

/// The most taints kept per node. A node with more is not a real one; the rest are ignored.
const MAX_TAINTS: usize = 64;

/// A text from the cluster, escaped and cut to [`SHOWN`] characters.
pub(super) fn shown(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(SHOWN).collect();
    let mut out = escape_untrusted(&head);
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// `text` if it is a DNS-1123 subdomain that [`shown`] keeps whole, else `placeholder`. A name from the
/// server that does not follow the naming rules never becomes a flag, or a command that names an object
/// that does not exist.
pub(super) fn command_arg(text: &str, placeholder: &str) -> String {
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let whole = !text.is_empty()
        && text.len() <= SHOWN
        && text.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.first().is_some_and(edge)
                && bytes.last().is_some_and(edge)
                && bytes.iter().all(|b| edge(b) || *b == b'-')
        });
    if whole {
        text.to_owned()
    } else {
        placeholder.to_owned()
    }
}

/// A resource the spec's `per_node` can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Resource {
    Cpu,
    Memory,
    Ephemeral,
    Pods,
}

impl Resource {
    /// The key of `status.allocatable` and `status.capacity`.
    fn key(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Ephemeral => "ephemeral-storage",
            Self::Pods => "pods",
        }
    }

    /// True when the amount is a size in bytes.
    pub(super) fn bytes(self) -> bool {
        matches!(self, Self::Memory | Self::Ephemeral)
    }

    /// The name in a sentence.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Memory => "memory",
            Self::Ephemeral => "ephemeral storage",
            Self::Pods => "pods",
        }
    }

    /// The key in the result.
    pub(super) fn field(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Ephemeral => "ephemeral",
            Self::Pods => "pods",
        }
    }
}

/// Every resource, in the order a message names them.
pub(super) const RESOURCES: [Resource; 4] = [
    Resource::Cpu,
    Resource::Memory,
    Resource::Ephemeral,
    Resource::Pods,
];

/// The four sizes of one side (allocatable or capacity). A size the node does not report, or reports in
/// text that is not a quantity, is `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Sizes {
    cpu: Option<Amount>,
    memory: Option<Amount>,
    ephemeral: Option<Amount>,
    pods: Option<Amount>,
}

impl Sizes {
    fn from_map(map: Option<&BTreeMap<String, Quantity>>) -> Self {
        let read = |resource: Resource| {
            map.and_then(|map| map.get(resource.key()))
                .and_then(|quantity| Amount::parse(&quantity.0))
        };
        Self {
            cpu: read(Resource::Cpu),
            memory: read(Resource::Memory),
            ephemeral: read(Resource::Ephemeral),
            pods: read(Resource::Pods),
        }
    }

    pub(super) fn get(&self, resource: Resource) -> Option<Amount> {
        match resource {
            Resource::Cpu => self.cpu,
            Resource::Memory => self.memory,
            Resource::Ephemeral => self.ephemeral,
            Resource::Pods => self.pods,
        }
    }
}

/// One taint, as the node holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Taint {
    pub(super) key: String,
    pub(super) value: String,
    pub(super) effect: String,
}

/// What rdy keeps of one node.
#[derive(Debug, Clone, Default)]
pub(super) struct NodeFacts {
    pub(super) name: String,
    /// The `Ready` condition is `True`. A node with no `Ready` condition is not ready.
    pub(super) ready: bool,
    /// `spec.unschedulable`: cordoned.
    pub(super) cordoned: bool,
    /// `kubernetes.io/os`, or `status.nodeInfo.operatingSystem` when the label is missing.
    pub(super) os: Option<String>,
    /// The architecture as the node says it (`kubernetes.io/arch`, else `status.nodeInfo.architecture`).
    pub(super) arch_text: Option<String>,
    /// The architecture when it is one the spec can name.
    pub(super) arch: Option<Arch>,
    /// A Fargate node (`eks.amazonaws.com/compute-type: fargate`).
    pub(super) fargate: bool,
    /// A virtual kubelet: its capacity is the connector's, not a machine's.
    pub(super) virtual_node: bool,
    pub(super) labels: BTreeMap<String, String>,
    pub(super) taints: Vec<Taint>,
    /// The node holds more taints than [`MAX_TAINTS`]: the rest were not kept, so it counts as tainted.
    pub(super) taints_cut: bool,
    /// The conditions that are `True` and mean trouble: the three pressures and `NetworkUnavailable`.
    pub(super) pressure: Vec<&'static str>,
    pub(super) zone: Option<String>,
    pub(super) instance_type: Option<String>,
    pub(super) kubelet: Option<String>,
    pub(super) runtime: Option<String>,
    pub(super) allocatable: Sizes,
    pub(super) capacity: Sizes,
}

/// The conditions that mean the node is short of something, in the order a message names them.
const PRESSURE: [&str; 4] = [
    "MemoryPressure",
    "DiskPressure",
    "PIDPressure",
    "NetworkUnavailable",
];

/// The architecture a node or a spec names, if it is one rdy knows.
pub(super) fn arch_of(text: &str) -> Option<Arch> {
    match text {
        "amd64" | "x86_64" => Some(Arch::X86_64),
        "arm64" | "aarch64" => Some(Arch::Aarch64),
        _ => None,
    }
}

/// `amd64` and `x86_64` are one architecture, and so are `arm64` and `aarch64`.
fn same_arch(a: Arch, b: Arch) -> bool {
    let intel = |arch: Arch| matches!(arch, Arch::X86_64 | Arch::Amd64);
    intel(a) == intel(b)
}

impl NodeFacts {
    pub(super) fn from_node(node: &Node) -> Self {
        let labels = node.metadata.labels.clone().unwrap_or_default();
        let status = node.status.as_ref();
        let info = status.and_then(|status| status.node_info.as_ref());
        let label = |key: &str| labels.get(key).cloned();
        let condition = |kind: &str| {
            status
                .and_then(|status| status.conditions.as_ref())
                .and_then(|conditions| conditions.iter().find(|c| c.type_ == kind))
                .map(|condition| condition.status.as_str())
        };
        let kubelet = info.map(|info| info.kubelet_version.clone());
        let arch_text = label("kubernetes.io/arch")
            .or_else(|| info.map(|info| info.architecture.clone()))
            .filter(|text| !text.is_empty());
        let os = label("kubernetes.io/os")
            .or_else(|| info.map(|info| info.operating_system.clone()))
            .filter(|text| !text.is_empty());
        Self {
            name: node.metadata.name.clone().unwrap_or_default(),
            ready: condition("Ready") == Some("True"),
            cordoned: node
                .spec
                .as_ref()
                .and_then(|spec| spec.unschedulable)
                .unwrap_or(false),
            os,
            arch: arch_text.as_deref().and_then(arch_of),
            arch_text,
            fargate: label("eks.amazonaws.com/compute-type").as_deref() == Some("fargate"),
            virtual_node: label("type").as_deref() == Some("virtual-kubelet")
                || kubelet.as_deref().is_some_and(|text| text.contains("-vk-")),
            taints_cut: node
                .spec
                .as_ref()
                .and_then(|spec| spec.taints.as_ref())
                .is_some_and(|taints| taints.len() > MAX_TAINTS),
            taints: node
                .spec
                .as_ref()
                .and_then(|spec| spec.taints.as_ref())
                .map(|taints| {
                    taints
                        .iter()
                        .take(MAX_TAINTS)
                        .map(|taint| Taint {
                            key: taint.key.clone(),
                            value: taint.value.clone().unwrap_or_default(),
                            effect: taint.effect.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            pressure: PRESSURE
                .into_iter()
                .filter(|kind| condition(kind) == Some("True"))
                .collect(),
            // AKS writes `0` for a node that is not in a zone: that is no zone.
            zone: label("topology.kubernetes.io/zone")
                .or_else(|| label("failure-domain.beta.kubernetes.io/zone"))
                .filter(|zone| !zone.is_empty() && zone != "0"),
            instance_type: label("node.kubernetes.io/instance-type")
                .or_else(|| label("beta.kubernetes.io/instance-type"))
                .filter(|text| !text.is_empty()),
            kubelet,
            runtime: info.map(|info| info.container_runtime_version.clone()),
            allocatable: Sizes::from_map(status.and_then(|status| status.allocatable.as_ref())),
            capacity: Sizes::from_map(status.and_then(|status| status.capacity.as_ref())),
            labels,
        }
    }

    /// The node autoscaler or managed capacity service that this node's labels or name show, if any.
    pub(super) fn scaler_hint(&self) -> Option<&'static str> {
        let has = |key: &str| self.labels.contains_key(key);
        if has("karpenter.sh/nodepool") || has("karpenter.sh/provisioner-name") {
            Some("Karpenter")
        } else if self
            .labels
            .get("eks.amazonaws.com/compute-type")
            .is_some_and(|value| value == "auto")
        {
            Some("EKS Auto Mode")
        } else if self
            .labels
            .get("cloud.google.com/gke-nodepool")
            .is_some_and(|pool| pool.starts_with("nap-"))
        {
            Some("GKE node auto-provisioning")
        } else if self.name.starts_with("gk3-") {
            // Google documents the `gk3-` prefix of node names as the mark of Autopilot-managed nodes. No
            // node label says it, so this is the one weak hint of the list.
            Some("GKE Autopilot")
        } else {
            None
        }
    }
}

/// Why a node does not count, in the order the tests are made: the first that applies is the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Excluded {
    Fargate,
    Virtual,
    NotLinux,
    Arch,
    Selector,
    Cordoned,
    NotReady,
    Tainted,
}

impl Excluded {
    /// The reason in a sentence, with a count in front.
    pub(super) fn phrase(self) -> &'static str {
        match self {
            Self::Fargate => "on Fargate",
            Self::Virtual => "virtual",
            Self::NotLinux => "not Linux",
            Self::Arch => "of another architecture",
            Self::Selector => "not matching the selector",
            Self::Cordoned => "cordoned",
            Self::NotReady => "not Ready",
            Self::Tainted => "tainted",
        }
    }

    /// The key in the result.
    pub(super) fn field(self) -> &'static str {
        match self {
            Self::Fargate => "fargate",
            Self::Virtual => "virtual",
            Self::NotLinux => "not_linux",
            Self::Arch => "arch",
            Self::Selector => "selector",
            Self::Cordoned => "cordoned",
            Self::NotReady => "not_ready",
            Self::Tainted => "tainted",
        }
    }
}

fn effect_name(effect: TaintEffect) -> &'static str {
    match effect {
        TaintEffect::NoSchedule => "NoSchedule",
        TaintEffect::PreferNoSchedule => "PreferNoSchedule",
        TaintEffect::NoExecute => "NoExecute",
        _ => "",
    }
}

/// Kubernetes' own rules for a toleration against one taint.
pub(super) fn tolerates(toleration: &Toleration, taint: &Taint) -> bool {
    if let Some(effect) = toleration.effect
        && effect_name(effect) != taint.effect
    {
        return false;
    }
    match &toleration.key {
        // No key, and the spec allows nothing but `Exists` then: every taint.
        None => true,
        Some(key) if key.as_str() != taint.key => false,
        Some(_) if toleration.operator == Some(TolerationOperator::Exists) => true,
        Some(_) => toleration.value.as_ref().map_or("", |value| value.as_str()) == taint.value,
    }
}

/// The taints the node lifecycle controller adds for a condition of the node. They are not the operator's
/// taints: the node stays counted, and the condition is judged on its own (pressure warns, a node that
/// is not Ready is `not Ready`, a cordon is `spec.unschedulable`).
const LIFECYCLE_TAINTS: [&str; 7] = [
    "node.kubernetes.io/memory-pressure",
    "node.kubernetes.io/disk-pressure",
    "node.kubernetes.io/pid-pressure",
    "node.kubernetes.io/network-unavailable",
    "node.kubernetes.io/not-ready",
    "node.kubernetes.io/unreachable",
    "node.kubernetes.io/unschedulable",
];

/// Where a node runs, for the words of a fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Platform {
    Eks,
    EksAuto,
    Gke,
    Aks,
    OpenShift,
    Other,
}

impl NodeFacts {
    /// The managed platform the node's labels or version name.
    pub(super) fn platform(&self) -> Platform {
        let has = |key: &str| self.labels.contains_key(key);
        let kubelet = self.kubelet.as_deref().unwrap_or_default();
        if has("node.openshift.io/os_id") {
            Platform::OpenShift
        } else if self
            .labels
            .get("eks.amazonaws.com/compute-type")
            .is_some_and(|v| v == "auto")
        {
            Platform::EksAuto
        } else if has("eks.amazonaws.com/nodegroup")
            || has("eks.amazonaws.com/compute-type")
            || kubelet.contains("-eks-")
        {
            Platform::Eks
        } else if has("cloud.google.com/gke-nodepool") || kubelet.contains("-gke.") {
            Platform::Gke
        } else if has("kubernetes.azure.com/cluster") {
            Platform::Aks
        } else {
            Platform::Other
        }
    }

    /// True when a `NoSchedule` or `NoExecute` taint of the node is tolerated by none of `tolerations`.
    /// `PreferNoSchedule` never keeps a pod off.
    fn tainted(&self, tolerations: &[Toleration]) -> bool {
        if self.taints_cut {
            return true;
        }
        self.taints
            .iter()
            .filter(|taint| matches!(taint.effect.as_str(), "NoSchedule" | "NoExecute"))
            .filter(|taint| !LIFECYCLE_TAINTS.contains(&taint.key.as_str()))
            .any(|taint| !tolerations.iter().any(|t| tolerates(t, taint)))
    }

    /// The reason the node does not count for `params`, or `None` when it does.
    pub(super) fn excluded(&self, params: &K8sNodes) -> Option<Excluded> {
        if self.fargate {
            return Some(Excluded::Fargate);
        }
        if self.virtual_node {
            return Some(Excluded::Virtual);
        }
        // A node that says nothing about its OS counts: the kubelet always sets the label, so a gap is the
        // server's, and 03 counts Linux by default.
        if self.os.as_deref().is_some_and(|os| os != "linux") {
            return Some(Excluded::NotLinux);
        }
        if let Some(wanted) = &params.arch
            && !self
                .arch
                .is_some_and(|arch| wanted.iter().any(|want| same_arch(*want, arch)))
        {
            return Some(Excluded::Arch);
        }
        if let Some(selector) = &params.selector
            && !selector
                .labels()
                .iter()
                .all(|(key, value)| self.labels.get(key) == Some(value))
        {
            return Some(Excluded::Selector);
        }
        if self.cordoned {
            return Some(Excluded::Cordoned);
        }
        if !self.ready {
            return Some(Excluded::NotReady);
        }
        let tolerations: &[Toleration] = params.tolerations.as_deref().unwrap_or_default();
        if self.tainted(tolerations) {
            return Some(Excluded::Tainted);
        }
        None
    }
}
