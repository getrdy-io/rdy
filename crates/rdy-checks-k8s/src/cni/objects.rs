//! The objects `k8s.cni` reads, cut down to the fields it uses.
//!
//! 02 Appendix B rule 6: a DaemonSet holds environment values and arguments that often carry credentials,
//! a node holds annotations, and any object can carry `kubectl.kubernetes.io/last-applied-configuration`,
//! which is the whole applied object. So no object is read into its full k8s-openapi type. Each type here
//! names the few fields the check needs, and serde drops the rest while parsing. Metadata goes through a
//! private `{name, namespace}` struct: annotations and labels never become strings in rdy.
//!
//! The one environment value that is kept is `ENABLE_NETWORK_POLICY` of the AWS VPC CNI. It is read by an
//! element reader that allocates a string only for a short value of a variable with that name, so no other
//! variable's value, long or short, is held after its element is read.

use std::borrow::Cow;
use std::fmt;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::core::{ClusterResourceScope, NamespaceResourceScope};
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// The most conditions, containers, rules, CIDRs and policy types kept of one object.
const MAX_ITEMS: usize = 64;

/// The longest `ENABLE_NETWORK_POLICY` value kept. The real values are `true` and `false`.
const MAX_ENV_VALUE: usize = 8;

/// The longest `ClusterConfiguration` document that is read, in bytes. A real one is under 4 KiB.
pub(super) const MAX_KUBEADM: usize = 256 * 1024;

/// The env variable of the AWS VPC CNI that turns the network policy agent on.
pub(super) const ENV_NETWORK_POLICY: &str = "ENABLE_NETWORK_POLICY";

macro_rules! resource {
    ($ty:ty, $scope:ty, $kind:literal, $group:literal, $version:literal, $plural:literal) => {
        impl kube::Resource for $ty {
            type DynamicType = ();
            type Scope = $scope;

            fn kind(_: &()) -> Cow<'_, str> {
                Cow::Borrowed($kind)
            }

            fn group(_: &()) -> Cow<'_, str> {
                Cow::Borrowed($group)
            }

            fn version(_: &()) -> Cow<'_, str> {
                Cow::Borrowed($version)
            }

            fn plural(_: &()) -> Cow<'_, str> {
                Cow::Borrowed($plural)
            }

            fn meta(&self) -> &ObjectMeta {
                &self.metadata
            }

            fn meta_mut(&mut self) -> &mut ObjectMeta {
                &mut self.metadata
            }
        }
    };
}

/// The two metadata fields the check uses. Annotations and labels are never read.
#[derive(Debug, Default, Deserialize)]
struct Meta {
    name: Option<String>,
    namespace: Option<String>,
}

/// Reads `metadata` into an `ObjectMeta` that holds only name and namespace, so `kube::Resource` still
/// works and nothing else of the metadata becomes a string.
fn meta<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ObjectMeta, D::Error> {
    let meta = Option::<Meta>::deserialize(deserializer)?.unwrap_or_default();
    Ok(ObjectMeta {
        name: meta.name,
        namespace: meta.namespace,
        ..ObjectMeta::default()
    })
}

/// A list of at most [`MAX_ITEMS`] items. The rest is read and dropped.
fn bounded<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a list")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut out = Vec::new();
            while let Some(item) = seq.next_element::<T>()? {
                if out.len() < MAX_ITEMS {
                    out.push(item);
                }
            }
            Ok(out)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Vec<T>, E> {
            Ok(Vec::new())
        }
    }
    deserializer.deserialize_any(Bounded(std::marker::PhantomData))
}

/// The count of the items of a list, with the items dropped as they are read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Count(pub(super) usize);

impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Counter;
        impl<'de> Visitor<'de> for Counter {
            type Value = Count;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Count, A::Error> {
                let mut n = 0_usize;
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    n = n.saturating_add(1);
                }
                Ok(Count(n))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Count, E> {
                Ok(Count(0))
            }
        }
        deserializer.deserialize_any(Counter)
    }
}

// ---- Node -------------------------------------------------------------------------------------------------

/// A node: the `NetworkUnavailable` condition, the pod ranges and the kubelet version.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct CniNode {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    spec: Option<NodeSpec>,
    #[serde(default)]
    status: Option<NodeStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NodeSpec {
    #[serde(default, rename = "podCIDR")]
    pod_cidr: Option<String>,
    #[serde(default, rename = "podCIDRs", deserialize_with = "bounded")]
    pod_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NodeStatus {
    #[serde(default, deserialize_with = "bounded")]
    conditions: Vec<NodeCondition>,
    #[serde(default, rename = "nodeInfo")]
    node_info: Option<NodeInfo>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NodeCondition {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NodeInfo {
    #[serde(default, rename = "kubeletVersion")]
    kubelet_version: Option<String>,
}

resource!(CniNode, ClusterResourceScope, "Node", "", "v1", "nodes");

/// What the check keeps of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NodeFacts {
    pub(super) name: String,
    /// The reason of the `NetworkUnavailable` condition, when there is one.
    pub(super) reason: Option<String>,
    /// True when the condition says the network is NOT available (`status: "True"`).
    pub(super) unavailable: bool,
    pub(super) pod_cidrs: Vec<String>,
    pub(super) kubelet_version: Option<String>,
}

impl CniNode {
    pub(super) fn facts(self) -> NodeFacts {
        let status = self.status.unwrap_or_default();
        let condition = status
            .conditions
            .into_iter()
            .find(|c| c.kind == "NetworkUnavailable");
        let spec = self.spec.unwrap_or_default();
        // `podCIDRs` is the whole list, and `podCIDR` is its first entry. Older servers set only the latter.
        let mut pod_cidrs = spec.pod_cidrs;
        if pod_cidrs.is_empty() {
            pod_cidrs.extend(spec.pod_cidr);
        }
        NodeFacts {
            name: self.metadata.name.unwrap_or_default(),
            unavailable: condition.as_ref().is_some_and(|c| c.status == "True"),
            reason: condition.and_then(|c| c.reason),
            pod_cidrs,
            kubelet_version: status.node_info.and_then(|info| info.kubelet_version),
        }
    }
}

// ---- DaemonSet --------------------------------------------------------------------------------------------

/// A DaemonSet: nodes wanted and ready, and the one environment value of the VPC CNI.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct CniDaemonSet {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    spec: Option<DaemonSetSpec>,
    #[serde(default)]
    status: Option<DaemonSetStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DaemonSetSpec {
    #[serde(default)]
    template: Option<Template>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Template {
    #[serde(default)]
    spec: Option<PodSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct PodSpec {
    #[serde(default, deserialize_with = "bounded")]
    containers: Vec<Container>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Container {
    #[serde(default)]
    env: PolicyEnv,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DaemonSetStatus {
    #[serde(default, rename = "desiredNumberScheduled")]
    desired: Option<i64>,
    #[serde(default, rename = "numberReady")]
    ready: Option<i64>,
}

resource!(
    CniDaemonSet,
    NamespaceResourceScope,
    "DaemonSet",
    "apps",
    "v1",
    "daemonsets"
);

/// What the check keeps of a DaemonSet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DaemonSetFacts {
    pub(super) desired: i64,
    pub(super) ready: i64,
    /// The value of `ENABLE_NETWORK_POLICY`, when a container sets it to a short plain value.
    pub(super) network_policy_env: Option<String>,
}

impl CniDaemonSet {
    pub(super) fn facts(self) -> DaemonSetFacts {
        let status = self.status.unwrap_or_default();
        let env = self
            .spec
            .and_then(|spec| spec.template)
            .and_then(|template| template.spec)
            .into_iter()
            .flat_map(|spec| spec.containers)
            .find_map(|container| container.env.0);
        DaemonSetFacts {
            desired: status.desired.unwrap_or(0),
            ready: status.ready.unwrap_or(0),
            network_policy_env: env,
        }
    }
}

/// The `env` list of a container, reduced to the value of `ENABLE_NETWORK_POLICY`.
#[derive(Debug, Clone, Default)]
struct PolicyEnv(Option<String>);

impl<'de> Deserialize<'de> for PolicyEnv {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;
        impl<'de> Visitor<'de> for Reader {
            type Value = PolicyEnv;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of environment variables")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<PolicyEnv, A::Error> {
                let mut found = None;
                while let Some(item) = seq.next_element::<EnvItem>()? {
                    if found.is_none() {
                        found = item.0;
                    }
                }
                Ok(PolicyEnv(found))
            }

            fn visit_unit<E: de::Error>(self) -> Result<PolicyEnv, E> {
                Ok(PolicyEnv(None))
            }
        }
        deserializer.deserialize_any(Reader)
    }
}

/// One environment variable: `Some(value)` only for `ENABLE_NETWORK_POLICY` with a short value.
struct EnvItem(Option<String>);

impl<'de> Deserialize<'de> for EnvItem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;
        impl<'de> Visitor<'de> for Reader {
            type Value = EnvItem;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an environment variable")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<EnvItem, A::Error> {
                let mut wanted = false;
                let mut value = None;
                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    match key.as_ref() {
                        "name" => {
                            let name: Cow<'de, str> = map.next_value()?;
                            wanted = name == ENV_NETWORK_POLICY;
                        }
                        // A value is allocated only when it is short, so a long value (a token, a
                        // connection string) never becomes a string. A short value of another variable is
                        // dropped when the element ends.
                        "value" => value = map.next_value::<Short>()?.0,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(EnvItem(if wanted { value } else { None }))
            }
        }
        deserializer.deserialize_map(Reader)
    }
}

/// A string of at most [`MAX_ENV_VALUE`] bytes. A longer one is skipped without being copied.
struct Short(Option<String>);

impl<'de> Deserialize<'de> for Short {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;
        impl Visitor<'_> for Reader {
            type Value = Short;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Short, E> {
                Ok(Short(
                    (text.len() <= MAX_ENV_VALUE).then(|| text.to_owned()),
                ))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Short, E> {
                Ok(Short(None))
            }
        }
        deserializer.deserialize_any(Reader)
    }
}

// ---- NetworkPolicy ----------------------------------------------------------------------------------------

/// A NetworkPolicy: which pods it selects, which directions it governs and the shape of its rules.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct CniPolicy {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    spec: Option<PolicySpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct PolicySpec {
    #[serde(default, rename = "podSelector")]
    pod_selector: Selector,
    #[serde(default, rename = "policyTypes", deserialize_with = "bounded")]
    policy_types: Vec<String>,
    #[serde(default, deserialize_with = "bounded")]
    egress: Vec<RuleShape>,
}

/// A label selector, reduced to whether it selects every pod.
#[derive(Debug, Clone, Default, Deserialize)]
struct Selector {
    #[serde(default, rename = "matchLabels")]
    match_labels: Option<MapCount>,
    #[serde(default, rename = "matchExpressions")]
    match_expressions: Option<Count>,
}

impl Selector {
    fn selects_all(&self) -> bool {
        self.match_labels.is_none_or(|m| m.0 == 0)
            && self.match_expressions.is_none_or(|c| c.0 == 0)
    }
}

/// The count of the entries of a map, with keys and values dropped as they are read.
#[derive(Debug, Clone, Copy, Default)]
struct MapCount(usize);

impl<'de> Deserialize<'de> for MapCount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Counter;
        impl<'de> Visitor<'de> for Counter {
            type Value = MapCount;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<MapCount, A::Error> {
                let mut n = 0_usize;
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    n = n.saturating_add(1);
                }
                Ok(MapCount(n))
            }

            fn visit_unit<E: de::Error>(self) -> Result<MapCount, E> {
                Ok(MapCount(0))
            }
        }
        deserializer.deserialize_any(Counter)
    }
}

/// An egress rule, reduced to whether it names destinations and ports.
#[derive(Debug, Clone, Default, Deserialize)]
struct RuleShape {
    #[serde(default)]
    to: Option<Count>,
    #[serde(default)]
    ports: Option<Count>,
}

resource!(
    CniPolicy,
    NamespaceResourceScope,
    "NetworkPolicy",
    "networking.k8s.io",
    "v1",
    "networkpolicies"
);

/// One egress rule of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EgressRule {
    /// The rule names destinations (`to` is not empty). Without it the rule allows every destination.
    pub(super) has_to: bool,
    /// The rule names ports. Without it the rule allows every port.
    pub(super) has_ports: bool,
}

/// What the check keeps of a NetworkPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyFacts {
    pub(super) name: String,
    /// The pod selector is empty, so the policy selects every pod of the namespace.
    pub(super) selects_all: bool,
    /// The policy governs egress.
    pub(super) egress: bool,
    pub(super) egress_rules: Vec<EgressRule>,
}

impl CniPolicy {
    pub(super) fn facts(self) -> PolicyFacts {
        let spec = self.spec.unwrap_or_default();
        // `policyTypes` defaults to Ingress, plus Egress when the policy has egress rules (an empty list is
        // not serialized, so a policy that only names Egress carries the type).
        let egress = spec.policy_types.iter().any(|t| t == "Egress")
            || (spec.policy_types.is_empty() && !spec.egress.is_empty());
        PolicyFacts {
            name: self.metadata.name.unwrap_or_default(),
            selects_all: spec.pod_selector.selects_all(),
            egress,
            egress_rules: spec
                .egress
                .iter()
                .map(|rule| EgressRule {
                    has_to: rule.to.is_some_and(|c| c.0 > 0),
                    has_ports: rule.ports.is_some_and(|c| c.0 > 0),
                })
                .collect(),
        }
    }
}

// ---- ServiceCIDR ------------------------------------------------------------------------------------------

macro_rules! service_cidr {
    ($ty:ident, $version:literal) => {
        /// A `ServiceCIDR`: the ranges of the cluster's Services.
        #[derive(Debug, Clone, Default, Deserialize)]
        pub(super) struct $ty {
            #[serde(default, deserialize_with = "meta")]
            metadata: ObjectMeta,
            #[serde(default)]
            spec: Option<ServiceCidrSpec>,
        }

        resource!(
            $ty,
            ClusterResourceScope,
            "ServiceCIDR",
            "networking.k8s.io",
            $version,
            "servicecidrs"
        );

        impl $ty {
            pub(super) fn cidrs(self) -> Vec<String> {
                self.spec.map(|spec| spec.cidrs).unwrap_or_default()
            }
        }
    };
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ServiceCidrSpec {
    #[serde(default, deserialize_with = "bounded")]
    cidrs: Vec<String>,
}

service_cidr!(ServiceCidrV1, "v1");
service_cidr!(ServiceCidrV1Beta1, "v1beta1");

// ---- kubeadm-config ---------------------------------------------------------------------------------------

/// The `kubeadm-config` ConfigMap, reduced to its `ClusterConfiguration` key.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct Kubeadm {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    data: ClusterConfiguration,
}

/// The `data` of the ConfigMap: every key but `ClusterConfiguration` is skipped without being copied.
#[derive(Debug, Clone, Default)]
struct ClusterConfiguration(Option<String>);

impl<'de> Deserialize<'de> for ClusterConfiguration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;
        impl<'de> Visitor<'de> for Reader {
            type Value = ClusterConfiguration;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the data of a ConfigMap")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<ClusterConfiguration, A::Error> {
                let mut found = None;
                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    if key == "ClusterConfiguration" {
                        let text: Cow<'de, str> = map.next_value()?;
                        found = (text.len() <= MAX_KUBEADM).then(|| text.into_owned());
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(ClusterConfiguration(found))
            }

            fn visit_unit<E: de::Error>(self) -> Result<ClusterConfiguration, E> {
                Ok(ClusterConfiguration(None))
            }
        }
        deserializer.deserialize_any(Reader)
    }
}

resource!(
    Kubeadm,
    NamespaceResourceScope,
    "ConfigMap",
    "",
    "v1",
    "configmaps"
);

impl Kubeadm {
    /// The text of `ClusterConfiguration`, when the key is there and not too long.
    pub(super) fn cluster_configuration(self) -> Option<String> {
        let _ = &self.metadata;
        self.data.0
    }
}

// ---- OpenShift Network ------------------------------------------------------------------------------------

/// `config.openshift.io/v1` `Network` `cluster`: the network type and the ranges.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct OcpNetwork {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    status: Option<OcpStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OcpStatus {
    #[serde(default, rename = "networkType")]
    network_type: Option<String>,
    #[serde(default, rename = "clusterNetwork", deserialize_with = "bounded")]
    cluster_network: Vec<OcpCluster>,
    #[serde(default, rename = "serviceNetwork", deserialize_with = "bounded")]
    service_network: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OcpCluster {
    #[serde(default)]
    cidr: Option<String>,
}

resource!(
    OcpNetwork,
    ClusterResourceScope,
    "Network",
    "config.openshift.io",
    "v1",
    "networks"
);

/// What the check keeps of the OpenShift `Network`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OcpFacts {
    pub(super) network_type: Option<String>,
    pub(super) pod_cidrs: Vec<String>,
    pub(super) service_cidrs: Vec<String>,
}

impl OcpNetwork {
    pub(super) fn facts(self) -> OcpFacts {
        let _ = &self.metadata;
        let status = self.status.unwrap_or_default();
        OcpFacts {
            network_type: status.network_type,
            pod_cidrs: status
                .cluster_network
                .into_iter()
                .filter_map(|c| c.cidr)
                .collect(),
            service_cidrs: status.service_network,
        }
    }
}
