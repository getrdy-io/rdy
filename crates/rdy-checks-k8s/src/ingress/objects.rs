//! The objects `k8s.ingress` reads, cut down to the fields it uses.
//!
//! 02 Appendix B rule 6: none of these is read into its full k8s-openapi type. Each type names the few fields
//! the check needs and serde drops the rest while parsing, so a Service spec, the load balancer addresses and
//! every annotation but one never become strings in rdy. The metadata of each object goes through a private
//! struct that names the fields it keeps, so `kubectl.kubernetes.io/last-applied-configuration` (a copy of
//! the whole applied object) is never held. The one annotation kept is the default-class marker of an
//! `IngressClass`, read by its exact key into a flag.

use std::borrow::Cow;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
use kube::core::{ClusterResourceScope, NamespaceResourceScope};
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer};

/// The most conditions kept of a `GatewayClass`.
const MAX_CONDITIONS: usize = 16;

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
                &self.metadata.meta
            }

            fn meta_mut(&mut self) -> &mut ObjectMeta {
                &mut self.metadata.meta
            }
        }
    };
}

/// The metadata fields of an object as the server sends them. Only these are named, so serde skips the rest
/// (annotations, labels, owner references, managed fields) without building a string for them.
#[derive(Debug, Default, Deserialize)]
struct RawMeta {
    name: Option<String>,
    #[serde(rename = "creationTimestamp")]
    creation_timestamp: Option<Time>,
    annotations: Option<Annotations>,
}

/// The one annotation `k8s.ingress` looks at. Every other annotation is skipped while parsing.
#[derive(Debug, Default, Deserialize)]
struct Annotations {
    #[serde(rename = "ingressclass.kubernetes.io/is-default-class")]
    default_class: Option<String>,
}

/// What is kept of the metadata: an `ObjectMeta` with the name and the creation time (so `kube::Resource`
/// works), and the default-class flag.
#[derive(Debug, Clone, Default)]
pub(super) struct Held {
    meta: ObjectMeta,
    default_class: bool,
}

impl<'de> Deserialize<'de> for Held {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawMeta::deserialize(deserializer)?;
        Ok(Self {
            meta: ObjectMeta {
                name: raw.name,
                creation_timestamp: raw.creation_timestamp,
                ..ObjectMeta::default()
            },
            // Kubernetes compares the value with the text `true` and nothing else.
            default_class: raw
                .annotations
                .and_then(|annotations| annotations.default_class)
                .as_deref()
                == Some("true"),
        })
    }
}

// ---- IngressClass -----------------------------------------------------------------------------------------

/// An `IngressClass`: its name, its controller and whether it is the default.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct IngressClassObject {
    #[serde(default)]
    metadata: Held,
    #[serde(default)]
    spec: Option<IngressClassSpec>,
}

/// `spec.controller` only. The parameters reference is dropped.
#[derive(Debug, Clone, Default, Deserialize)]
struct IngressClassSpec {
    controller: Option<String>,
}

resource!(
    IngressClassObject,
    ClusterResourceScope,
    "IngressClass",
    "networking.k8s.io",
    "v1",
    "ingressclasses"
);

/// What the check keeps of an `IngressClass`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Class {
    pub(super) name: String,
    /// `spec.controller`, empty when the class has none.
    pub(super) controller: String,
    pub(super) default: bool,
}

/// An `IngressClass`, as the check keeps it.
pub(super) fn class_of(object: IngressClassObject) -> Class {
    Class {
        name: object
            .metadata
            .meta
            .name
            .unwrap_or_else(|| "<unnamed>".to_owned()),
        controller: object
            .spec
            .and_then(|spec| spec.controller)
            .unwrap_or_default(),
        default: object.metadata.default_class,
    }
}

// ---- GatewayClass -----------------------------------------------------------------------------------------

/// A `GatewayClass`: its name, its controller and the conditions' type and status.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct GatewayClassObject {
    #[serde(default)]
    metadata: Held,
    #[serde(default)]
    spec: Option<GatewayClassSpec>,
    #[serde(default)]
    status: Option<GatewayClassStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GatewayClassSpec {
    #[serde(rename = "controllerName")]
    controller_name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GatewayClassStatus {
    #[serde(default)]
    conditions: Vec<GatewayCondition>,
}

/// A condition's type and status. Its message, reason and times are dropped.
#[derive(Debug, Clone, Default, Deserialize)]
struct GatewayCondition {
    #[serde(rename = "type", default)]
    type_: String,
    #[serde(default)]
    status: String,
}

resource!(
    GatewayClassObject,
    ClusterResourceScope,
    "GatewayClass",
    "gateway.networking.k8s.io",
    "v1",
    "gatewayclasses"
);

/// What the check keeps of a `GatewayClass`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GatewayClass {
    pub(super) name: String,
    pub(super) controller: String,
    /// The `Accepted` condition: `Some(true)` for `True`, `Some(false)` for any other status, `None` when
    /// the controller has not set one.
    pub(super) accepted: Option<bool>,
}

/// A `GatewayClass`, as the check keeps it.
pub(super) fn gateway_class_of(object: GatewayClassObject) -> GatewayClass {
    let accepted = object
        .status
        .map(|status| status.conditions)
        .unwrap_or_default()
        .into_iter()
        .take(MAX_CONDITIONS)
        .find(|condition| condition.type_ == "Accepted")
        .map(|condition| condition.status == "True");
    GatewayClass {
        name: object
            .metadata
            .meta
            .name
            .unwrap_or_else(|| "<unnamed>".to_owned()),
        controller: object
            .spec
            .and_then(|spec| spec.controller_name)
            .unwrap_or_default(),
        accepted,
    }
}

// ---- Service ----------------------------------------------------------------------------------------------

/// A Service: its name, creation time, type and how many load balancer addresses it has.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct ServiceObject {
    #[serde(default)]
    metadata: Held,
    #[serde(default)]
    spec: Option<ServiceSpec>,
    #[serde(default)]
    status: Option<ServiceStatus>,
}

/// `spec.type` only. The ports, selector, cluster IPs and the rest are dropped.
#[derive(Debug, Clone, Default, Deserialize)]
struct ServiceSpec {
    #[serde(rename = "type")]
    type_: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ServiceStatus {
    #[serde(rename = "loadBalancer", default)]
    load_balancer: Option<LoadBalancerStatus>,
}

/// The addresses are counted and never held: `IgnoredAny` builds no string.
#[derive(Debug, Clone, Default, Deserialize)]
struct LoadBalancerStatus {
    #[serde(default)]
    ingress: Vec<IgnoredAny>,
}

resource!(
    ServiceObject,
    NamespaceResourceScope,
    "Service",
    "",
    "v1",
    "services"
);

/// What the check keeps of a `LoadBalancer` Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Balancer {
    pub(super) name: String,
    /// Seconds since the Service was created, `None` when the server sent no creation time.
    pub(super) age_secs: Option<i64>,
    /// True when `status.loadBalancer.ingress` holds at least one address.
    pub(super) assigned: bool,
}

/// A Service, as the check keeps it: `Some` for a `LoadBalancer` and `None` for any other type.
pub(super) fn balancer_of(object: ServiceObject, now: i64) -> Option<Balancer> {
    let is_balancer =
        object.spec.as_ref().and_then(|spec| spec.type_.as_deref()) == Some("LoadBalancer");
    if !is_balancer {
        return None;
    }
    let assigned = object
        .status
        .and_then(|status| status.load_balancer)
        .is_some_and(|balancer| !balancer.ingress.is_empty());
    let age_secs = object
        .metadata
        .meta
        .creation_timestamp
        .as_ref()
        .map(|time| now.saturating_sub(time.0.as_second()));
    Some(Balancer {
        name: object
            .metadata
            .meta
            .name
            .unwrap_or_else(|| "<unnamed>".to_owned()),
        age_secs,
        assigned,
    })
}
