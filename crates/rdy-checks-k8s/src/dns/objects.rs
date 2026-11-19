//! The objects `k8s.dns` reads, cut down to the fields it uses.
//!
//! 02 Appendix B rule 6: a pod, a deployment or a daemon set holds environment values and arguments that
//! often carry credentials, and a ConfigMap holds whatever its owner put in it. So none of them is read
//! into its full k8s-openapi type. Each type here names the few fields the check needs, and serde drops the
//! rest while parsing: the spec of a pod, the env and args of a container, and every ConfigMap key but
//! `Corefile` never become strings in rdy. The `Resource` impls name the one path of each kind that the
//! guard allows.

use std::borrow::Cow;
use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
use kube::core::NamespaceResourceScope;
use serde::{Deserialize, Deserializer};

/// The most containers kept of one workload or pod.
pub(super) const MAX_CONTAINERS: usize = 8;

/// The longest Corefile that is parsed, in bytes. A real one is under 2 KiB.
pub(super) const MAX_COREFILE: usize = 64 * 1024;

macro_rules! namespaced_resource {
    ($ty:ty, $kind:literal, $group:literal, $version:literal, $plural:literal) => {
        impl kube::Resource for $ty {
            type DynamicType = ();
            type Scope = NamespaceResourceScope;

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

/// The three metadata fields the check uses. Annotations are never read: `last-applied-configuration` holds
/// the whole applied object, env values and every ConfigMap key included.
#[derive(Debug, Default, Deserialize)]
struct Meta {
    name: Option<String>,
    namespace: Option<String>,
    labels: Option<BTreeMap<String, String>>,
}

/// Reads `metadata` into an `ObjectMeta` that holds only name, namespace and labels, so `kube::Resource`
/// still works and nothing else of the metadata becomes a string.
fn meta<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ObjectMeta, D::Error> {
    let meta = Option::<Meta>::deserialize(deserializer)?.unwrap_or_default();
    Ok(ObjectMeta {
        name: meta.name,
        namespace: meta.namespace,
        labels: meta.labels,
        ..ObjectMeta::default()
    })
}

/// A container of a pod template: its name only.
#[derive(Debug, Clone, Default, Deserialize)]
struct Named {
    #[serde(default)]
    name: String,
}

/// `spec.template.spec` of a Deployment or a DaemonSet: the container names.
#[derive(Debug, Clone, Default, Deserialize)]
struct PodSpecNames {
    #[serde(default)]
    containers: Vec<Named>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct TemplateNames {
    #[serde(default)]
    spec: Option<PodSpecNames>,
}

fn names(template: Option<TemplateNames>) -> Vec<String> {
    template
        .and_then(|template| template.spec)
        .map(|spec| {
            spec.containers
                .into_iter()
                .take(MAX_CONTAINERS)
                .map(|container| container.name)
                .collect()
        })
        .unwrap_or_default()
}

// ---- Deployment -------------------------------------------------------------------------------------------

/// A Deployment: replicas wanted and ready, and the container names.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct DnsDeployment {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    spec: Option<DeploymentSpec>,
    #[serde(default)]
    status: Option<DeploymentStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DeploymentSpec {
    replicas: Option<i32>,
    #[serde(default)]
    template: Option<TemplateNames>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DeploymentStatus {
    #[serde(rename = "readyReplicas")]
    ready_replicas: Option<i32>,
}

namespaced_resource!(DnsDeployment, "Deployment", "apps", "v1", "deployments");

// ---- DaemonSet --------------------------------------------------------------------------------------------

/// A DaemonSet: nodes wanted and ready, and the container names.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct DnsDaemonSet {
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
    template: Option<TemplateNames>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DaemonSetStatus {
    #[serde(rename = "desiredNumberScheduled")]
    desired: Option<i32>,
    #[serde(rename = "numberReady")]
    ready: Option<i32>,
}

namespaced_resource!(DnsDaemonSet, "DaemonSet", "apps", "v1", "daemonsets");

/// What the check keeps of a Deployment or a DaemonSet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Workload {
    pub(super) kind: Kind,
    pub(super) name: String,
    /// What the workload is for, from its labels.
    pub(super) role: Role,
    /// Pods wanted: the replicas of a Deployment (the server's default is 1), or the nodes a DaemonSet
    /// schedules on.
    pub(super) desired: i64,
    /// Pods ready.
    pub(super) ready: i64,
    /// The names of the containers of its pod template.
    pub(super) containers: Vec<String>,
}

impl Workload {
    /// True for kube-dns (the `kubedns` container), which has no Corefile and no `loop` plugin.
    pub(super) fn is_kube_dns(&self) -> bool {
        self.containers.iter().any(|name| name == "kubedns")
    }
}

/// Deployment or DaemonSet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Deployment,
    DaemonSet,
}

impl Kind {
    /// The word for a sentence.
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Deployment => "Deployment",
            Self::DaemonSet => "DaemonSet",
        }
    }

    /// The `kubectl` short name, for `kubectl logs <short>/<name>`.
    pub(super) fn short(self) -> &'static str {
        match self {
            Self::Deployment => "deploy",
            Self::DaemonSet => "ds",
        }
    }
}

/// What a workload is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    /// The cluster DNS: label `k8s-app=kube-dns`, or the OpenShift DNS label.
    Cluster,
    /// NodeLocal DNSCache: label `k8s-app=node-local-dns`.
    NodeLocal,
    /// Something else the label selector returned.
    Other,
}

fn role_of(meta: &ObjectMeta) -> Role {
    let labels = meta.labels.as_ref();
    let k8s_app = labels
        .and_then(|labels| labels.get("k8s-app"))
        .map(String::as_str);
    let openshift = labels
        .and_then(|labels| labels.get("dns.operator.openshift.io/owning-dns"))
        .map(String::as_str);
    match (k8s_app, openshift) {
        (Some("kube-dns"), _) | (_, Some("default")) => Role::Cluster,
        (Some("node-local-dns"), _) => Role::NodeLocal,
        _ => Role::Other,
    }
}

/// A Deployment, as the check keeps it.
pub(super) fn deployment_of(object: DnsDeployment) -> Workload {
    let role = role_of(&object.metadata);
    let (replicas, template) = object
        .spec
        .map_or((None, None), |spec| (spec.replicas, spec.template));
    Workload {
        kind: Kind::Deployment,
        name: object.metadata.name.unwrap_or_default(),
        role,
        // The API server defaults `spec.replicas` to 1.
        desired: i64::from(replicas.unwrap_or(1)),
        ready: i64::from(
            object
                .status
                .and_then(|status| status.ready_replicas)
                .unwrap_or(0),
        ),
        containers: names(template),
    }
}

/// A DaemonSet, as the check keeps it.
pub(super) fn daemon_set_of(object: DnsDaemonSet) -> Workload {
    let role = role_of(&object.metadata);
    let template = object.spec.and_then(|spec| spec.template);
    let (desired, ready) = object.status.map_or((0, 0), |status| {
        (status.desired.unwrap_or(0), status.ready.unwrap_or(0))
    });
    Workload {
        kind: Kind::DaemonSet,
        name: object.metadata.name.unwrap_or_default(),
        role,
        desired: i64::from(desired),
        ready: i64::from(ready),
        containers: names(template),
    }
}

// ---- Pod --------------------------------------------------------------------------------------------------

/// A pod: its name and the states of its containers. The spec is never read.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct DnsPod {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    status: Option<PodStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct PodStatus {
    #[serde(rename = "containerStatuses", default)]
    containers: Vec<ContainerStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ContainerStatus {
    #[serde(default)]
    name: String,
    #[serde(rename = "restartCount", default)]
    restarts: i64,
    #[serde(default)]
    state: Option<ContainerState>,
    #[serde(rename = "lastState", default)]
    last: Option<ContainerState>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ContainerState {
    #[serde(default)]
    waiting: Option<Waiting>,
    #[serde(default)]
    terminated: Option<Terminated>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Waiting {
    reason: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Terminated {
    reason: Option<String>,
    #[serde(rename = "exitCode")]
    exit_code: Option<i64>,
    #[serde(rename = "finishedAt")]
    finished_at: Option<Time>,
}

namespaced_resource!(DnsPod, "Pod", "", "v1", "pods");

impl DnsPod {
    /// True when the pod is in `namespace`.
    pub(super) fn is_in(&self, namespace: &str) -> bool {
        self.metadata.namespace.as_deref() == Some(namespace)
    }
}

/// A container that waits in `CrashLoopBackOff`, with what its last run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Crash {
    pub(super) pod: String,
    pub(super) container: String,
    /// Restarts over the life of the container. Shown, never a verdict.
    pub(super) restarts: i64,
    /// Why the last run ended (`Error`, `OOMKilled`), when it says.
    pub(super) reason: Option<String>,
    pub(super) exit_code: Option<i64>,
    /// Seconds from the end of the last run to now. `None` when the pod does not say.
    pub(super) ended_ago: Option<i64>,
}

/// One pod, as the check keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PodFacts {
    pub(super) name: String,
    /// The containers in `CrashLoopBackOff`.
    pub(super) crashes: Vec<Crash>,
    /// The most restarts of any container over the pod's life. Shown only.
    pub(super) restarts: i64,
}

/// A pod as the check keeps it: the containers that wait in `CrashLoopBackOff`, with the end of their last run
/// counted back from `now` (seconds since the epoch).
pub(super) fn pod_of(object: DnsPod, now: i64) -> PodFacts {
    let name = object.metadata.name.unwrap_or_default();
    let mut crashes = Vec::new();
    let mut restarts = 0;
    for status in object
        .status
        .map(|status| status.containers)
        .unwrap_or_default()
        .into_iter()
        .take(MAX_CONTAINERS)
    {
        restarts = restarts.max(status.restarts);
        let looping = status
            .state
            .as_ref()
            .and_then(|state| state.waiting.as_ref())
            .and_then(|waiting| waiting.reason.as_deref())
            == Some("CrashLoopBackOff");
        if !looping {
            continue;
        }
        let last = status.last.and_then(|last| last.terminated);
        crashes.push(Crash {
            pod: name.clone(),
            container: status.name,
            restarts: status.restarts,
            reason: last.as_ref().and_then(|last| last.reason.clone()),
            exit_code: last.as_ref().and_then(|last| last.exit_code),
            ended_ago: last
                .and_then(|last| last.finished_at)
                .map(|time| now.saturating_sub(time.0.as_second())),
        });
    }
    PodFacts {
        name,
        crashes,
        restarts,
    }
}

// ---- ConfigMap --------------------------------------------------------------------------------------------

/// The ConfigMap of the Corefile: the one key `Corefile`, and nothing else of the map.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct DnsConfigMap {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    data: Option<CorefileData>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CorefileData {
    #[serde(rename = "Corefile")]
    corefile: Option<String>,
}

namespaced_resource!(DnsConfigMap, "ConfigMap", "", "v1", "configmaps");

/// The text of the Corefile, cut at [`MAX_COREFILE`] bytes (on a character boundary).
pub(super) fn corefile_of(object: DnsConfigMap) -> Option<String> {
    let mut text = object.data?.corefile?;
    if text.len() > MAX_COREFILE {
        let mut end = MAX_COREFILE;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    Some(text)
}

// ---- Service ----------------------------------------------------------------------------------------------

/// The DNS Service: the cluster IP and the ports, and nothing else (no selector, no annotations).
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct DnsService {
    #[serde(default, deserialize_with = "meta")]
    metadata: ObjectMeta,
    #[serde(default)]
    spec: Option<ServiceSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ServiceSpec {
    #[serde(rename = "clusterIP")]
    cluster_ip: Option<String>,
    #[serde(default)]
    ports: Vec<ServicePort>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ServicePort {
    #[serde(default)]
    port: i64,
    protocol: Option<String>,
}

namespaced_resource!(DnsService, "Service", "", "v1", "services");

/// What the check keeps of the Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServiceParts {
    pub(super) cluster_ip: String,
    /// True when port 53 is listed for UDP.
    pub(super) udp_53: bool,
    /// True when port 53 is listed for TCP.
    pub(super) tcp_53: bool,
}

/// The Service as the check keeps it. A port with no protocol is TCP, as the server defaults it.
pub(super) fn service_of(object: DnsService) -> ServiceParts {
    let spec = object.spec.unwrap_or_default();
    let has = |wanted: &str| {
        spec.ports.iter().any(|port| {
            port.port == 53
                && port
                    .protocol
                    .as_deref()
                    .unwrap_or("TCP")
                    .eq_ignore_ascii_case(wanted)
        })
    };
    ServiceParts {
        udp_53: has("UDP"),
        tcp_53: has("TCP"),
        cluster_ip: spec.cluster_ip.unwrap_or_default(),
    }
}
