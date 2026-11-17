//! Admission webhooks that can reject the product's pods (03, "k8s.admission", M1-160).
//!
//! What is read: both webhook configuration lists (first page of 500), then, for each webhook that fails
//! closed (`failurePolicy: Fail`, which is also the default of `admissionregistration.k8s.io/v1`), applies to
//! a pod create in the namespace and is backed by a `Service`, that Service (one list with a
//! `metadata.name` field selector) and its `EndpointSlice` objects (one list with the
//! `kubernetes.io/service-name` label). At most [`MAX_SERVICES`] distinct Services are read.
//!
//! What is judged:
//!
//! - A `Fail` webhook that certainly applies and whose Service has no ready endpoint, or does not exist,
//!   blocks: the API server cannot get an answer, so it rejects every pod create. `ready` unset on an
//!   endpoint means ready.
//! - The same webhook, when something the check cannot read may exempt a pod (`matchConditions`, a CEL
//!   expression, or an `objectSelector`, which matches the pod's own labels), warns and says it was not
//!   evaluated.
//! - A `Fail` webhook that applies and whose backend is a URL, or a Service of type `ExternalName`, is an
//!   external backend, not verified: it is listed as not evaluated and the result is partial.
//! - A webhook whose Service could not be read (403, a status, no time) is not evaluated and names the grant.
//! - `Ignore` webhooks are listed in the observed data and never judged: the API server lets the request
//!   through when they fail.

use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhook, MutatingWebhookConfiguration, ValidatingWebhook,
    ValidatingWebhookConfiguration, WebhookClientConfig,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use rdy_engine::check::Level;
use serde_json::{Value, json};

use super::judge::{Grant, Issue, Part, shown};
use super::matching::{self, Applies, NsLabels, Rule};
use super::{Listed, Read, fix};

/// The most distinct Services whose endpoints are read. A longer list is not evaluated.
pub(super) const MAX_SERVICES: usize = 8;

/// Which kind of configuration holds the webhook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConfigKind {
    Validating,
    Mutating,
}

impl ConfigKind {
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Validating => "validating",
            Self::Mutating => "mutating",
        }
    }

    /// The resource, as a command writes it.
    pub(super) fn resource(self) -> &'static str {
        match self {
            Self::Validating => "validatingwebhookconfigurations",
            Self::Mutating => "mutatingwebhookconfigurations",
        }
    }
}

/// Where a webhook sends the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Backend {
    /// A Service in the cluster. The URL host of an external one is never kept.
    Service { namespace: String, name: String },
    /// `clientConfig.url`.
    Url,
    /// Neither: the API server refuses such a configuration, so this is a hostile or broken object.
    Neither,
}

/// One webhook, as far as the check reads it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Webhook {
    pub(super) kind: ConfigKind,
    /// The name of the configuration object.
    pub(super) config: String,
    pub(super) name: String,
    /// `failurePolicy` is `Fail`, or unset (the v1 default).
    pub(super) fail: bool,
    pub(super) backend: Backend,
    pub(super) rules: Vec<Rule>,
    pub(super) namespace_selector: Option<LabelSelector>,
    /// True when an `objectSelector` is set and not empty: it matches the labels of the pod.
    pub(super) object_selector: bool,
    /// True when `matchConditions` is not empty: a CEL expression may exempt the request.
    pub(super) conditions: bool,
}

impl Webhook {
    /// Does the webhook apply to the creation of a pod in the namespace? `Maybe` when the namespace labels
    /// were not read, or an `objectSelector` or `matchConditions` may exempt the pod.
    pub(super) fn applies(&self, labels: &NsLabels) -> Applies {
        if !matching::any_matches(&self.rules) {
            return Applies::No;
        }
        matching::selects(self.namespace_selector.as_ref(), labels)
            .capped(self.object_selector || self.conditions)
    }

    /// The Service a `Fail` webhook that applies depends on, to read its endpoints.
    pub(super) fn service_to_read(&self, labels: &NsLabels) -> Option<(&str, &str)> {
        match &self.backend {
            Backend::Service { namespace, name }
                if self.fail && self.applies(labels) != Applies::No =>
            {
                Some((namespace, name))
            }
            _ => None,
        }
    }
}

fn backend_of(config: &WebhookClientConfig) -> Backend {
    if let Some(service) = &config.service {
        return Backend::Service {
            namespace: service.namespace.clone(),
            name: service.name.clone(),
        };
    }
    if config.url.is_some() {
        return Backend::Url;
    }
    Backend::Neither
}

fn is_fail(policy: Option<&str>) -> bool {
    policy.is_none_or(|policy| policy == "Fail")
}

fn rules_of<'a>(
    rules: impl IntoIterator<Item = &'a k8s_openapi::api::admissionregistration::v1::RuleWithOperations>,
) -> Vec<Rule> {
    rules.into_iter().map(Rule::from).collect()
}

fn validating(config: &str, hook: &ValidatingWebhook) -> Webhook {
    Webhook {
        kind: ConfigKind::Validating,
        config: config.to_owned(),
        name: hook.name.clone(),
        fail: is_fail(hook.failure_policy.as_deref()),
        backend: backend_of(&hook.client_config),
        rules: rules_of(hook.rules.iter().flatten()),
        namespace_selector: hook.namespace_selector.clone(),
        object_selector: !matching::is_empty(hook.object_selector.as_ref()),
        conditions: hook
            .match_conditions
            .as_ref()
            .is_some_and(|c| !c.is_empty()),
    }
}

fn mutating(config: &str, hook: &MutatingWebhook) -> Webhook {
    Webhook {
        kind: ConfigKind::Mutating,
        config: config.to_owned(),
        name: hook.name.clone(),
        fail: is_fail(hook.failure_policy.as_deref()),
        backend: backend_of(&hook.client_config),
        rules: rules_of(hook.rules.iter().flatten()),
        namespace_selector: hook.namespace_selector.clone(),
        object_selector: !matching::is_empty(hook.object_selector.as_ref()),
        conditions: hook
            .match_conditions
            .as_ref()
            .is_some_and(|c| !c.is_empty()),
    }
}

/// The webhooks of a list of validating configurations.
pub(super) fn from_validating(list: Vec<ValidatingWebhookConfiguration>) -> Vec<Webhook> {
    list.iter()
        .flat_map(|config| {
            let name = config.metadata.name.clone().unwrap_or_default();
            config
                .webhooks
                .iter()
                .flatten()
                .map(move |hook| validating(&name, hook))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The webhooks of a list of mutating configurations.
pub(super) fn from_mutating(list: Vec<MutatingWebhookConfiguration>) -> Vec<Webhook> {
    list.iter()
        .flat_map(|config| {
            let name = config.metadata.name.clone().unwrap_or_default();
            config
                .webhooks
                .iter()
                .flatten()
                .map(move |hook| mutating(&name, hook))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// What the endpoints behind a Service showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BackendState {
    /// This many endpoints are ready.
    Ready(usize),
    /// No endpoint is ready; `total` endpoints exist (0 when there is no slice at all).
    NoReady { total: usize },
    /// The Service does not exist in its namespace.
    ServiceMissing,
    /// A Service of type `ExternalName`: the request goes outside the cluster.
    External,
    /// The Service or its slices could not be read, and why. `grant` is what to ask for.
    Unread {
        why: String,
        grant: Option<ReadGrant>,
    },
    /// The name is not a Kubernetes name, so no path was built for it.
    BadName,
    /// The cap on Services was reached, or the check ran out of time.
    NotAsked,
}

/// Which list the identity may not make, for the grant text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadGrant {
    Services,
    EndpointSlices,
}

/// One Service read: its namespace, name and what was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServiceRead {
    pub(super) namespace: String,
    pub(super) name: String,
    pub(super) state: BackendState,
}

/// Everything read about webhooks.
#[derive(Debug)]
pub(super) struct Webhooks {
    pub(super) validating: Read<Listed<Webhook>>,
    pub(super) mutating: Read<Listed<Webhook>>,
    pub(super) services: Vec<ServiceRead>,
}

impl Webhooks {
    fn all(&self) -> impl Iterator<Item = &Webhook> {
        fn items(read: &Read<Listed<Webhook>>) -> &[Webhook] {
            match read {
                Read::Ok(listed) => &listed.items,
                _ => &[],
            }
        }
        items(&self.validating)
            .iter()
            .chain(items(&self.mutating).iter())
    }

    fn state_of(&self, namespace: &str, name: &str) -> Option<&BackendState> {
        self.services
            .iter()
            .find(|read| read.namespace == namespace && read.name == name)
            .map(|read| &read.state)
    }
}

/// True when `text` can stand in a command or a path as a Kubernetes name: a DNS-1123 subdomain.
pub(super) fn safe_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            let bytes = label.as_bytes();
            let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first().is_some_and(edge)
                && bytes.last().is_some_and(edge)
                && bytes.iter().all(|b| edge(b) || *b == b'-')
        })
}

/// The name of an object for a command: itself if it has the shape of a name, else a placeholder.
fn arg<'a>(name: &'a str, placeholder: &'a str) -> &'a str {
    if safe_name(name) { name } else { placeholder }
}

/// The finding part for the webhooks. `ns` is the namespace judged, if the spec names one.
pub(super) fn judge(webhooks: &Webhooks, labels: &NsLabels, ns: Option<&str>) -> Part {
    let mut part = Part::default();
    let ns_text = ns.unwrap_or("<namespace>");
    for (kind, read) in [
        (ConfigKind::Validating, &webhooks.validating),
        (ConfigKind::Mutating, &webhooks.mutating),
    ] {
        match read {
            Read::Ok(listed) if listed.cut => part.unverified.push(format!(
                "only the first {} {} webhook configurations were read, so a webhook on a later page is not evaluated",
                super::PAGE,
                kind.word()
            )),
            Read::Ok(_) => {}
            Read::Missing => part.notes.push(format!(
                "The server does not serve {} webhook configurations.",
                kind.word()
            )),
            other => {
                part.unverified.push(format!(
                    "{} webhooks were not evaluated: the list could not be read ({})",
                    kind.word(),
                    other.why()
                ));
                if matches!(other, Read::Forbidden) {
                    part.grants.push(Grant::list(kind.resource(), "admissionregistration.k8s.io"));
                }
            }
        }
    }

    let mut applying = 0_usize;
    let mut unevaluated: Vec<String> = Vec::new();
    for hook in webhooks.all() {
        let applies = hook.applies(labels);
        if applies == Applies::No {
            continue;
        }
        applying += 1;
        if !hook.fail {
            continue;
        }
        let label = format!(
            "{} webhook {} of {}",
            hook.kind.word(),
            shown(&hook.name),
            shown(&hook.config)
        );
        match &hook.backend {
            Backend::Url => unevaluated.push(format!(
                "{label} sends requests to a URL outside the cluster and fails closed: external backend, not verified"
            )),
            Backend::Neither => unevaluated.push(format!(
                "{label} names neither a Service nor a URL: not evaluated"
            )),
            Backend::Service { namespace, name } => {
                let state = webhooks.state_of(namespace, name);
                judge_service(&mut part, hook, &label, applies, namespace, name, state, ns_text);
            }
        }
    }
    part.unverified.extend(unevaluated);
    if let (Read::Ok(v), Read::Ok(m)) = (&webhooks.validating, &webhooks.mutating)
        && v.items.len() + m.items.len() > 0
    {
        part.notes.push(format!(
            "rdy read {} validating and {} mutating webhooks. {applying} can apply to a pod create in namespace {ns_text}.",
            v.items.len(),
            m.items.len()
        ));
    }
    part
}

/// One `Fail` webhook that applies, with the state of its Service.
#[allow(clippy::too_many_arguments)]
fn judge_service(
    part: &mut Part,
    hook: &Webhook,
    label: &str,
    applies: Applies,
    namespace: &str,
    name: &str,
    state: Option<&BackendState>,
    ns_text: &str,
) {
    let service = format!("Service {} in namespace {}", shown(name), shown(namespace));
    let problem = match state {
        Some(BackendState::Ready(_)) => return,
        Some(BackendState::NoReady { total: 0 }) => {
            format!("{service} has no endpoint")
        }
        Some(BackendState::NoReady { total }) => {
            format!("{service} has {total} endpoints and none is ready")
        }
        Some(BackendState::ServiceMissing) => format!("{service} does not exist"),
        Some(BackendState::External) => {
            part.unverified.push(format!(
                "{label} fails closed and its {service} is of type ExternalName: external backend, not verified"
            ));
            return;
        }
        Some(BackendState::Unread { why, grant }) => {
            part.unverified.push(format!(
                "{label} fails closed, and its endpoints were not read ({why}): not evaluated"
            ));
            if let Some(grant) = grant {
                part.grants.push(match grant {
                    ReadGrant::Services => Grant::list("services", ""),
                    ReadGrant::EndpointSlices => Grant::list("endpointslices", "discovery.k8s.io"),
                });
            }
            return;
        }
        Some(BackendState::BadName) | None | Some(BackendState::NotAsked) => {
            part.unverified.push(format!(
                "{label} fails closed, and its endpoints were not read: not evaluated"
            ));
            return;
        }
    };
    let fix = fix::webhook(
        hook.kind,
        arg(&hook.config, "<configuration>"),
        arg(namespace, "<namespace>"),
        arg(name, "<service>"),
    );
    if applies == Applies::Yes {
        part.issues.push(Issue {
            level: Level::Fail,
            message: format!(
                "{label} fails closed and {problem}, so the API server rejects every pod create in namespace {ns_text}"
            ),
            fix,
        });
    } else {
        let why = if hook.conditions && hook.object_selector {
            "its matchConditions and objectSelector"
        } else if hook.conditions {
            "its matchConditions"
        } else if hook.object_selector {
            "its objectSelector"
        } else {
            "the namespace labels, which were not read,"
        };
        // Warn and partial: the doubt is the unread part, and the result says it was not evaluated.
        part.unverified.push(format!(
            "{label} fails closed and {problem}, and {why} may exempt the pod: not evaluated"
        ));
        part.issues.push(Issue {
            level: Level::Warn,
            message: format!(
                "{label} fails closed and {problem}; it rejects the product's pods unless {why} exempt them, and rdy did not evaluate that"
            ),
            fix,
        });
    }
}

/// What the result records about webhooks, for the `observed` object.
pub(super) fn observed(webhooks: &Webhooks, labels: &NsLabels) -> Value {
    let count = |read: &Read<Listed<Webhook>>| match read {
        Read::Ok(listed) => json!(listed.items.len()),
        _ => Value::Null,
    };
    let applying: Vec<Value> = webhooks
        .all()
        .filter_map(|hook| {
            let applies = hook.applies(labels);
            (applies != Applies::No).then(|| {
                let backend = match &hook.backend {
                    Backend::Service { .. } => "service",
                    Backend::Url => "url",
                    Backend::Neither => "none",
                };
                let ready = match &hook.backend {
                    Backend::Service { namespace, name } => {
                        match webhooks.state_of(namespace, name) {
                            Some(BackendState::Ready(n)) => json!(n),
                            Some(BackendState::NoReady { .. } | BackendState::ServiceMissing) => {
                                json!(0)
                            }
                            _ => Value::Null,
                        }
                    }
                    _ => Value::Null,
                };
                json!({
                    "kind": hook.kind.word(),
                    "configuration": shown(&hook.config),
                    "name": shown(&hook.name),
                    "failure_policy": if hook.fail { "Fail" } else { "Ignore" },
                    "applies": if applies == Applies::Yes { "yes" } else { "maybe" },
                    "backend": backend,
                    "ready_endpoints": ready,
                })
            })
        })
        .collect();
    json!({
        "validating": count(&webhooks.validating),
        "mutating": count(&webhooks.mutating),
        "applying": applying,
    })
}
