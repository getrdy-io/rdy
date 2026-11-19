//! The pod list of `k8s.nodes` free capacity, read into a type that holds requests and nothing else.
//!
//! A full `Pod` carries `env[].value`, which often holds credentials, and a list can hold 5000 pods
//! (05 I4). So this is a resource type of its own: serde skips every field that is not named here, and
//! the pod is never held whole, not even for the length of a parse. What is kept: the name and namespace,
//! `spec.nodeName`, the phase, the `requests` of each container and init container (with `restartPolicy`,
//! which marks a sidecar), `spec.overhead` and the pod-level `spec.resources.requests`.

use std::borrow::Cow;
use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::core::NamespaceResourceScope;
use serde::Deserialize;

/// A map of resource name to quantity, as `requests` and `overhead` hold it.
pub(super) type Quantities = BTreeMap<String, Quantity>;

/// What one container asks for.
#[derive(Debug, Clone, Default)]
pub(super) struct ContainerRequests {
    pub(super) requests: Quantities,
    /// An init container with `restartPolicy: Always`: it keeps running next to the app containers.
    pub(super) sidecar: bool,
}

/// One pod, as far as free capacity reads it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(from = "Raw")]
pub(super) struct PodRequests {
    metadata: ObjectMeta,
    pub(super) node_name: String,
    pub(super) phase: Option<String>,
    pub(super) containers: Vec<ContainerRequests>,
    pub(super) init_containers: Vec<ContainerRequests>,
    pub(super) overhead: Quantities,
    /// `spec.resources.requests` (pod-level resources).
    pub(super) pod_level: Quantities,
}

#[derive(Deserialize)]
struct Raw {
    metadata: Option<RawName>,
    spec: Option<RawSpec>,
    status: Option<RawStatus>,
}

#[derive(Deserialize)]
struct RawName {
    name: Option<String>,
    namespace: Option<String>,
}

#[derive(Deserialize)]
struct RawSpec {
    #[serde(rename = "nodeName")]
    node_name: Option<String>,
    #[serde(default)]
    containers: Vec<RawContainer>,
    #[serde(default, rename = "initContainers")]
    init_containers: Vec<RawContainer>,
    overhead: Option<Quantities>,
    resources: Option<RawResources>,
}

#[derive(Deserialize)]
struct RawContainer {
    resources: Option<RawResources>,
    #[serde(rename = "restartPolicy")]
    restart_policy: Option<String>,
}

#[derive(Deserialize)]
struct RawResources {
    requests: Option<Quantities>,
}

#[derive(Deserialize)]
struct RawStatus {
    phase: Option<String>,
}

fn container(raw: RawContainer) -> ContainerRequests {
    ContainerRequests {
        requests: raw
            .resources
            .and_then(|resources| resources.requests)
            .unwrap_or_default(),
        sidecar: raw.restart_policy.as_deref() == Some("Always"),
    }
}

impl From<Raw> for PodRequests {
    fn from(raw: Raw) -> Self {
        let (name, namespace) = raw.metadata.map_or((None, None), |m| (m.name, m.namespace));
        let metadata = ObjectMeta {
            name,
            namespace,
            ..ObjectMeta::default()
        };
        let phase = raw.status.and_then(|status| status.phase);
        let Some(spec) = raw.spec else {
            return Self {
                metadata,
                phase,
                ..Self::default()
            };
        };
        Self {
            metadata,
            node_name: spec.node_name.unwrap_or_default(),
            phase,
            containers: spec.containers.into_iter().map(container).collect(),
            init_containers: spec.init_containers.into_iter().map(container).collect(),
            overhead: spec.overhead.unwrap_or_default(),
            pod_level: spec
                .resources
                .and_then(|resources| resources.requests)
                .unwrap_or_default(),
        }
    }
}

impl kube::Resource for PodRequests {
    type DynamicType = ();
    type Scope = NamespaceResourceScope;

    fn kind(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("Pod")
    }

    fn group(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn version(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("v1")
    }

    fn api_version(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("v1")
    }

    fn plural(_: &()) -> Cow<'_, str> {
        Cow::Borrowed("pods")
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}
