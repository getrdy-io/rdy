//! What `k8s.rbac` asks the server: one `SelfSubjectAccessReview` per permission.
//!
//! An [`Ask`] is a verb on a [`Target`]: a resource (group, resource, subresource, namespace, name) or a
//! URL that is not a resource. The spec's items become asks, in order and without repeats. For an item
//! that creates or changes roles or bindings, the check adds the asks the API server makes of the
//! caller: `escalate` for a role, `bind` for a binding (03, "k8s.rbac"). Those are implied asks.
//! The spec has 100 items at most, and so does a run: implied asks past the cap are dropped and counted.

use k8s_openapi::api::authorization::v1::{
    NonResourceAttributes, ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use kube::api::ObjectMeta;
use rdy_spec::check::{K8sRbac, NonResourceRule, RbacItem, RbacRule};

/// The most reviews one run sends (03: "up to 100 per run").
pub(super) const MAX_REVIEWS: usize = 100;

/// The RBAC API group, where roles and bindings live.
const RBAC_GROUP: &str = "rbac.authorization.k8s.io";

/// What a verb is asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Target {
    /// A resource, maybe in a namespace, maybe one object.
    Resource {
        group: String,
        resource: String,
        subresource: Option<String>,
        namespace: Option<String>,
        name: Option<String>,
    },
    /// A URL that is not a resource, such as `/healthz`.
    NonResource { path: String },
}

/// One permission to ask about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ask {
    pub(super) verb: String,
    pub(super) target: Target,
    /// True for an ask the check added (`escalate`, `bind`), false for an item of the spec.
    pub(super) implied: bool,
}

impl Ask {
    /// True when both ask the same thing, whether or not the check added them.
    fn same(&self, other: &Self) -> bool {
        self.verb == other.verb && self.target == other.target
    }

    /// The ask as a person writes it: `create clusterroles.rbac.authorization.k8s.io`,
    /// `get pods/log web-0 in acme`, `get /healthz`. The words come from the spec or are fixed, so
    /// nothing here is text from the server.
    pub(super) fn describe(&self) -> String {
        match &self.target {
            Target::NonResource { path } => format!("{} {path}", self.verb),
            Target::Resource {
                group,
                resource,
                subresource,
                namespace,
                name,
            } => {
                let mut text = format!("{} {resource}", self.verb);
                if !group.is_empty() {
                    text.push('.');
                    text.push_str(group);
                }
                if let Some(subresource) = subresource {
                    text.push('/');
                    text.push_str(subresource);
                }
                if let Some(name) = name {
                    text.push(' ');
                    text.push_str(name);
                }
                if let Some(namespace) = namespace {
                    text.push_str(" in ");
                    text.push_str(namespace);
                }
                text
            }
        }
    }

    /// The namespace the ask is made in, if it names one.
    pub(super) fn namespace(&self) -> Option<&str> {
        match &self.target {
            Target::Resource { namespace, .. } => namespace.as_deref(),
            Target::NonResource { .. } => None,
        }
    }

    /// The review to post. Empty fields are left out, so the server sees the core group as no group.
    pub(super) fn review(&self) -> SelfSubjectAccessReview {
        let mut spec = SelfSubjectAccessReviewSpec::default();
        match &self.target {
            Target::Resource {
                group,
                resource,
                subresource,
                namespace,
                name,
            } => {
                spec.resource_attributes = Some(ResourceAttributes {
                    verb: Some(self.verb.clone()),
                    group: Some(group.clone()).filter(|group| !group.is_empty()),
                    resource: Some(resource.clone()),
                    subresource: subresource.clone(),
                    namespace: namespace.clone(),
                    name: name.clone(),
                    ..ResourceAttributes::default()
                });
            }
            Target::NonResource { path } => {
                spec.non_resource_attributes = Some(NonResourceAttributes {
                    verb: Some(self.verb.clone()),
                    path: Some(path.clone()),
                });
            }
        }
        SelfSubjectAccessReview {
            metadata: ObjectMeta::default(),
            spec,
            status: None,
        }
    }
}

/// The asks of a run.
#[derive(Debug, Default)]
pub(super) struct Asks {
    /// The spec's items, in order, without repeats.
    pub(super) spec: Vec<Ask>,
    /// The asks the check added, without repeats and not already in `spec`.
    pub(super) implied: Vec<Ask>,
    /// Implied asks left out because the run is at [`MAX_REVIEWS`].
    pub(super) dropped: usize,
}

impl Asks {
    /// Builds the asks for `params`. The entry's `namespace` applies to every item that names none.
    pub(super) fn from_params(params: &K8sRbac) -> Self {
        let entry_namespace = params.namespace.as_ref().map(|ns| ns.as_str().to_owned());
        let mut asks = Self::default();
        for item in params.can.iter() {
            let ask = match item {
                RbacItem::Resource(rule) => resource_ask(rule, entry_namespace.as_deref()),
                RbacItem::NonResource(rule) => non_resource_ask(rule),
                _ => continue,
            };
            if !asks.spec.iter().any(|seen| seen.same(&ask)) {
                asks.spec.push(ask);
            }
        }
        let wanted: Vec<Ask> = asks.spec.iter().flat_map(implied_by).collect();
        for ask in wanted {
            if asks.all().any(|seen| seen.same(&ask)) {
                continue;
            }
            if asks.spec.len() + asks.implied.len() >= MAX_REVIEWS {
                asks.dropped += 1;
            } else {
                asks.implied.push(ask);
            }
        }
        asks
    }

    /// Every ask: the spec's, then the implied ones.
    pub(super) fn all(&self) -> impl Iterator<Item = &Ask> {
        self.spec.iter().chain(&self.implied)
    }
}

fn resource_ask(rule: &RbacRule, entry_namespace: Option<&str>) -> Ask {
    Ask {
        verb: rule.verb.as_str().to_owned(),
        target: Target::Resource {
            group: rule.group.as_str().to_owned(),
            resource: rule.resource.as_str().to_owned(),
            subresource: rule.subresource.as_ref().map(|sub| sub.as_str().to_owned()),
            namespace: rule
                .namespace
                .as_ref()
                .map(|ns| ns.as_str().to_owned())
                .or_else(|| entry_namespace.map(str::to_owned)),
            name: rule.name.as_ref().map(|name| name.as_str().to_owned()),
        },
        implied: false,
    }
}

fn non_resource_ask(rule: &NonResourceRule) -> Ask {
    Ask {
        verb: rule.verb.as_str().to_owned(),
        target: Target::NonResource {
            path: rule.path.as_str().to_owned(),
        },
        implied: false,
    }
}

/// The asks the API server makes of a caller that writes `ask`.
///
/// Creating or changing a role needs `escalate` on it, unless the caller already holds every rule the role
/// grants. Creating or changing a binding needs `bind` on the role it names, with the same exception.
/// The binding's role is not known, so the ask is for any role of the kind (`clusterroles`, and `roles`
/// in the binding's namespace).
fn implied_by(ask: &Ask) -> Vec<Ask> {
    let Target::Resource {
        group,
        resource,
        subresource: None,
        namespace,
        ..
    } = &ask.target
    else {
        return Vec::new();
    };
    if group != RBAC_GROUP || !matches!(ask.verb.as_str(), "create" | "update" | "patch" | "*") {
        return Vec::new();
    }
    let on = |verb: &str, resource: &str, namespace: Option<&String>| Ask {
        verb: verb.to_owned(),
        target: Target::Resource {
            group: RBAC_GROUP.to_owned(),
            resource: resource.to_owned(),
            subresource: None,
            namespace: namespace.cloned(),
            name: None,
        },
        implied: true,
    };
    match resource.as_str() {
        "clusterroles" => vec![on("escalate", "clusterroles", None)],
        "roles" => vec![on("escalate", "roles", namespace.as_ref())],
        "clusterrolebindings" => vec![on("bind", "clusterroles", None)],
        "rolebindings" => vec![
            on("bind", "clusterroles", None),
            on("bind", "roles", namespace.as_ref()),
        ],
        _ => Vec::new(),
    }
}

/// The ask that tells whether the identity may act as `user`: `impersonate` on the service account, or on
/// the user. It is asked of the kubeconfig identity itself, never impersonated.
pub(super) fn impersonation_ask(user: &str) -> Ask {
    let target = match user
        .strip_prefix("system:serviceaccount:")
        .and_then(|rest| rest.split_once(':'))
    {
        Some((namespace, name)) => Target::Resource {
            group: String::new(),
            resource: "serviceaccounts".to_owned(),
            subresource: None,
            namespace: Some(namespace.to_owned()),
            name: Some(name.to_owned()),
        },
        None => Target::Resource {
            group: String::new(),
            resource: "users".to_owned(),
            subresource: None,
            namespace: None,
            name: Some(user.to_owned()),
        },
    };
    Ask {
        verb: "impersonate".to_owned(),
        target,
        implied: false,
    }
}
