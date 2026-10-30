//! `k8s.access`: can rdy reach the cluster, and as whom (03 section 4).
//!
//! It reports what the run's connection attempt found ([`Dial`], made once per run by the family probe)
//! and adds what only a request can show:
//!
//! - **The kubeconfig and the route.** Which source was used, the context, the server (a Rancher path
//!   prefix is kept), the kind of each credential and, for a static JWT or a client certificate, when it
//!   ends. An exec plugin and the pod's service account have no expiry to warn about. The proxy that
//!   applies and the rule that chose it (`proxy-url`, `HTTPS_PROXY`, or `NO_PROXY` exempting the host).
//! - **Who rdy is.** `/version`, `/api` and `/readyz` answer anonymous callers, so they prove nothing about
//!   the credentials. The check sends a `SelfSubjectReview` (`authentication.k8s.io/v1`, GA in 1.28)
//!   through the raw route of `ReadOnlyClient`, never a typed k8s-openapi review (the guard refuses the
//!   `metadata` member a typed value carries). It prints the user and groups and warns on
//!   `system:anonymous`. When the route answers 404 one `SelfSubjectAccessReview` shows that the
//!   credentials are accepted, and the identity is "not verified". The server version says why: 1.27
//!   serves only `v1beta1`, older servers have no review, and a 1.28 or later server that answers 404 has
//!   the route switched off or filtered.
//! - **Discovery.** `GET /api` and `GET /apis`, named exactly. A refusal is a note, never a failure.
//!
//! When the attempt failed, the check says why, with the fix for that cause: no kubeconfig, a login that
//! needs a person, a certificate rdy does not trust, a private endpoint, a proxy that refuses the tunnel.
//! It never fails on data it could not read: the only blocks are an unreachable cluster, credentials the
//! server refuses (a credential whose end date has passed is a block only when the server also says 401;
//! otherwise it is a clock warning), and a context or server that is not the one the spec expects.
//!
//! **Privilege.** None. It reads the kubeconfig the operator chose, through the client module, and sends
//! three read-only requests. Without a cluster it still reports, because the attempt's outcome is its
//! input. With `--no-network` there is no attempt and the check is skipped as `missing_need` `network`.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use kube::api::PostParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Need,
    OsSupport, PeerClass, Support,
};
use rdy_spec::check::K8sAccess;
use serde_json::json;

use crate::client::{ConnectionFacts, KubeError, ReadOnlyClient, ServerVersion, from_kube_error};

mod dial;
mod fix;
mod judge;

#[cfg(test)]
mod tests;

pub use dial::{Dial, DialOutcome, Dialed};
use judge::{CORE_VERSIONS_KEPT, DEFAULT_MAX_LATENCY, Discovery, NotVerified, Rules, Seen, Who};

/// The time `k8s.access` keeps back for its own requests: below it, discovery is skipped.
const DISCOVERY_MIN_TIME: Duration = Duration::from_secs(1);

/// The static facts about `k8s.access` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.access",
    family: "k8s",
    summary: "Kubeconfig, API reachable, who am I",
    meta: CheckMeta {
        title: "Cluster access",
        remediation: "Point rdy at the right cluster with `--kubeconfig <file>` and `--kube-context <name>`, and sign in again if the credentials ended. EKS: `aws eks update-kubeconfig`. GKE: `gcloud container clusters get-credentials`. AKS: `az aks get-credentials`, then `kubelogin convert-kubeconfig -l azurecli`. OpenShift: `oc login`. A private API endpoint needs a host inside the network or the VPN. Behind a proxy, set `proxy-url` in the kubeconfig or HTTPS_PROXY, and make sure the proxy allows CONNECT to the API server.",
    },
    // Not `KubeContext`: this check reports the outcome of the attempt that meets it (02). It needs the
    // network, because it returns `MissingNeed(Network)` when the run forbids it.
    needs: &[Need::Network],
    wants: &[],
    default_timeout: Some(Duration::from_secs(10)),
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    },
    reads: &[],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[PeerClass::KubeApi, PeerClass::Proxy],
};

/// Why a `k8s.access` entry cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("k8s.access {field} is not a pattern rdy can use: {reason}")]
pub struct PatternError {
    field: &'static str,
    reason: String,
}

impl PatternError {
    /// The spec key that holds the pattern.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }
}

/// `k8s.access`, built from its spec entry.
pub struct AccessCheck {
    rules: Rules,
    dial: Arc<dyn Dial>,
}

impl std::fmt::Debug for AccessCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessCheck")
            .field("rules", &self.rules)
            .finish_non_exhaustive()
    }
}

impl AccessCheck {
    /// The check for `params`, reading the run's attempt `dial`.
    ///
    /// # Errors
    ///
    /// [`PatternError`] when `context_pattern` or `server_pattern` does not compile under the spec's
    /// limits. Lint finds the same, so this happens only for a spec that skipped lint. The family refuses
    /// to build the entry (`unsupported_spec`).
    pub fn new(params: &K8sAccess, dial: Arc<dyn Dial>) -> Result<Self, PatternError> {
        let pattern = |field: &'static str, text: Option<&rdy_spec::check::RegexText>| {
            text.map(|text| {
                rdy_spec::pattern::compile(text.as_str())
                    .map(|_| text.as_str().to_owned())
                    .map_err(|reason| PatternError { field, reason })
            })
            .transpose()
        };
        Ok(Self {
            rules: Rules {
                context_pattern: pattern("context_pattern", params.context_pattern.as_ref())?,
                server_pattern: pattern("server_pattern", params.server_pattern.as_ref())?,
                max_latency: params
                    .max_latency
                    .as_ref()
                    .map_or(DEFAULT_MAX_LATENCY, rdy_spec::Duration::to_std),
            },
            dial,
        })
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for AccessCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            match self.dial.outcome() {
                DialOutcome::NoNetwork => Err(CheckError::MissingNeed(Need::Network)),
                DialOutcome::Failed(error) => Ok(self.failed(error)),
                DialOutcome::TimedOut => Ok(self.timed_out()),
                DialOutcome::Reached { version, latency } => {
                    self.reached(ctx, version, *latency).await
                }
            }
        })
    }
}

impl AccessCheck {
    /// The finding for an attempt that failed, with the fix for its cause.
    fn failed(&self, error: &KubeError) -> Finding {
        let facts = self.dial.facts();
        let route = facts.and_then(|facts| facts.proxy().describe());
        let mut message = error.to_string();
        let mut fix = fix::for_error(error, facts, route.as_deref());
        // A credential that has ended explains a 401 better than "not accepted".
        if matches!(error, KubeError::Unauthorized { .. })
            && let Some(facts) = facts
            && let Some((text, credential)) = judge::first_ended(facts)
        {
            message = text;
            fix = fix::renew(&fix::guess(Some(facts)), credential);
        }
        self.not_connected(message, fix, state_of(error), facts)
    }

    /// The finding for an attempt that did not finish in time.
    fn timed_out(&self) -> Finding {
        let facts = self.dial.facts();
        let guess = fix::guess(facts);
        let plugin = facts.and_then(|facts| {
            facts
                .credentials()
                .iter()
                .find_map(|credential| match credential {
                    crate::client::Credential::Plugin { binary } => Some(binary.clone()),
                    _ => None,
                })
        });
        let (message, fix) = match (&plugin, facts) {
            (Some(binary), _) => (
                format!(
                    "The credential plugin `{binary}` did not answer in time. It may need an interactive login."
                ),
                fix::plugin_timed_out(binary, &guess),
            ),
            (None, Some(facts)) => (
                format!("No answer from {} in time.", facts.line().server()),
                fix::no_reply(&guess),
            ),
            (None, None) => (
                "Reading the kubeconfig took too long.".to_owned(),
                "Check that the kubeconfig and the files it names are on a local disk, not a slow network mount.".to_owned(),
            ),
        };
        self.not_connected(message, fix, "timed_out", facts)
    }

    fn not_connected(
        &self,
        message: String,
        fix: String,
        state: &str,
        facts: Option<&ConnectionFacts>,
    ) -> Finding {
        let mut observed = json!({"state": state, "reason": message});
        if let Some(facts) = facts {
            observed["context"] = json!(facts.line().context());
            observed["server"] = json!(facts.line().server());
            observed["source"] = json!(facts.source().label());
            observed["proxy"] = judge::proxy_json(facts);
        }
        let mut finding = Finding::fail(message)
            .with_observed(observed)
            .with_expected(judge::expected_for(&self.rules))
            .with_fix(fix);
        if let Some(facts) = facts {
            finding = finding.with_note(format!(
                "Kubeconfig from {}; context {}.",
                facts.source().label(),
                facts.line().context()
            ));
            for note in judge::facts_notes(facts) {
                finding = finding.with_note(note);
            }
        }
        finding
    }

    /// The finding for an attempt that reached the cluster: ask who rdy is, read discovery, judge.
    async fn reached(
        &self,
        ctx: &CheckContext,
        version: &ServerVersion,
        latency: Duration,
    ) -> CheckOutcome {
        let (Some(facts), Some(client)) = (self.dial.facts(), self.dial.read_only(ctx.probe()))
        else {
            return Err(CheckError::Failed {
                message: "the run reached the cluster but holds no client for this check"
                    .to_owned(),
                hint: "Tell the vendor, with the JSON report.".to_owned(),
            });
        };
        let who = ask_who(&client, facts, version).await?;
        let discovery = match who {
            Who::Unauthorized | Who::Forbidden | Who::Broken(_) => Discovery::default(),
            _ => discover(&client, ctx, facts).await?,
        };
        let seen = Seen {
            facts,
            version,
            latency,
            who,
            discovery,
        };
        Ok(judge::judge(&self.rules, &seen))
    }
}

/// The `state` word of `observed` for a failed attempt.
fn state_of(error: &KubeError) -> &'static str {
    match error {
        KubeError::NoKubeconfig => "no_kubeconfig",
        KubeError::Unauthorized { .. } => "unauthorized",
        KubeError::Forbidden { .. } => "forbidden",
        KubeError::Timeout { .. } => "timed_out",
        KubeError::Unreachable { .. } => "unreachable",
        KubeError::PluginFailed { .. }
        | KubeError::PluginNotStarted { .. }
        | KubeError::PluginOutputInvalid { .. } => "plugin_failed",
        KubeError::ProxyUnsupported { .. } | KubeError::ProxyPlainServer { .. } => {
            "proxy_unsupported"
        }
        _ => "not_connected",
    }
}

/// An error from the cluster in the vocabulary of [`KubeError`].
fn classify(error: &kube::Error, facts: &ConnectionFacts) -> KubeError {
    let plugin = facts
        .credentials()
        .iter()
        .find_map(|credential| match credential {
            crate::client::Credential::Plugin { binary } => Some(binary.as_str()),
            _ => None,
        });
    from_kube_error(
        error,
        facts.line().server(),
        plugin,
        facts.proxy().is_proxied(),
        facts.ca_set(),
    )
}

/// A guard refusal is a bug in rdy, not an answer of the cluster: it ends the check as an error.
fn refusal(error: &KubeError) -> CheckError {
    CheckError::Failed {
        message: error.to_string(),
        hint: error.hint(),
    }
}

/// Asks the server who rdy is.
async fn ask_who(
    client: &ReadOnlyClient,
    facts: &ConnectionFacts,
    version: &ServerVersion,
) -> Result<Who, CheckError> {
    let error = match client.self_subject_review().await {
        Ok(review) => return Ok(who_from(&review)),
        Err(error) => classify(&error, facts),
    };
    match error {
        KubeError::Api { code: 404, .. } => {
            ask_access_review(client, facts, NotVerified::of(version)).await
        }
        other => settle(other),
    }
}

/// A server with no `SelfSubjectReview` route (404). One access review shows that the credentials are
/// accepted. It asks about a single read of namespaces and keeps no part of the answer.
async fn ask_access_review(
    client: &ReadOnlyClient,
    facts: &ConnectionFacts,
    why: NotVerified,
) -> Result<Who, CheckError> {
    let review = SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some("get".to_owned()),
                resource: Some("namespaces".to_owned()),
                ..ResourceAttributes::default()
            }),
            non_resource_attributes: None,
        },
        ..SelfSubjectAccessReview::default()
    };
    match client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &review)
        .await
    {
        Ok(_) => Ok(Who::NotVerified(why)),
        Err(error) => settle(classify(&error, facts)),
    }
}

/// Sorts the error of an identity request into an answer, or ends the check.
fn settle(error: KubeError) -> Result<Who, CheckError> {
    match error {
        KubeError::Unauthorized { .. } => Ok(Who::Unauthorized),
        KubeError::Forbidden { .. } => Ok(Who::Forbidden),
        KubeError::Api { code, .. } => Ok(Who::Other { code }),
        KubeError::BadAnswer { .. } => Ok(Who::Silent),
        refused @ KubeError::Refused { .. } => Err(refusal(&refused)),
        other => Ok(Who::Broken(other)),
    }
}

fn who_from(review: &SelfSubjectReview) -> Who {
    let user = review
        .status
        .as_ref()
        .and_then(|status| status.user_info.as_ref());
    match user {
        Some(user) if user.username.is_some() || user.groups.is_some() => judge::who_from_user(
            user.username.as_deref().unwrap_or(""),
            user.groups.as_deref().unwrap_or(&[]),
        ),
        _ => Who::Silent,
    }
}

/// Reads `/api` and `/apis`. A refusal or an error is a note.
async fn discover(
    client: &ReadOnlyClient,
    ctx: &CheckContext,
    facts: &ConnectionFacts,
) -> Result<Discovery, CheckError> {
    let mut found = Discovery::default();
    if ctx.remaining() < DISCOVERY_MIN_TIME {
        found
            .notes
            .push("Discovery was skipped: little time was left.".to_owned());
        return Ok(found);
    }
    match client.core_versions().await {
        Ok(list) => {
            // The versions come from the server: escape each and keep a few (INV-17).
            found.core_total = list.versions.len();
            found.core_versions = Some(
                list.versions
                    .iter()
                    .take(CORE_VERSIONS_KEPT)
                    .map(|version| judge::shown(version))
                    .collect(),
            );
        }
        Err(error) => found.notes.push(discovery_note("/api", &error, facts)?),
    }
    match client.api_groups().await {
        Ok(list) => found.group_count = Some(list.groups.len()),
        Err(error) => found.notes.push(discovery_note("/apis", &error, facts)?),
    }
    Ok(found)
}

fn discovery_note(
    path: &str,
    error: &kube::Error,
    facts: &ConnectionFacts,
) -> Result<String, CheckError> {
    let why = match classify(error, facts) {
        KubeError::Unauthorized { .. } => "was not accepted (401)".to_owned(),
        KubeError::Forbidden { .. } => "was refused (403)".to_owned(),
        KubeError::Api { code, .. } => format!("answered with status {code}"),
        refused @ KubeError::Refused { .. } => return Err(refusal(&refused)),
        other => format!("failed: {other}"),
    };
    Ok(format!(
        "Discovery: GET {path} {why}. Nothing else depends on it, so this is a note."
    ))
}
