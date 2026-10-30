//! `k8s.rbac`: can the install identity do what the installer does (03 section 4, M1-111).
//!
//! What it sends, all through the read-only guard and all logged under this check's id:
//!
//! - `SelfSubjectReview`, once: who the API server says rdy is (user and groups). On a server older than
//!   1.28 the identity is "not verified".
//! - `SelfSubjectAccessReview`, one per permission in `can`, 8 at a time, 100 at most per run. A review
//!   creates nothing: the server answers and stores nothing. It is still one entry in the cluster's audit
//!   log, so the note of the result says how many were sent. For an item that creates or changes roles or
//!   bindings, `escalate` and `bind` asks are added (they count toward the 100).
//! - With a spec `as:`, the reviews are sent as that user (`Impersonate-User`, [`ImpersonateAs`]). First one
//!   un-impersonated review asks whether the kubeconfig identity may `impersonate` it. If it may not, nothing
//!   is evaluated and the result is partial with the grant to ask for. The kubeconfig must not impersonate
//!   already (kube would add a second header below the guard): the check then fails before any request.
//! - `SelfSubjectRulesReview`, once, only when something is denied: what the tested user may do in the
//!   namespace, printed so the admin sees what is already granted.
//! - `GET` of the `Namespace` for each namespace a denied item names (3 at most): a missing namespace is
//!   the usual reason a namespaced item is denied.
//!
//! How the answers are judged:
//!
//! - `allowed: true` passes. `allowed: false` with `denied: true` is an explicit deny (an authorizer other
//!   than RBAC said no, and a role cannot fix it). Plain `allowed: false` is not allowed (no rule grants it).
//!   Both block. `allowed: false` with an `evaluationError` is unclear and warns.
//! - A denied `escalate` or `bind` warns: the identity may still create the role if it already holds every
//!   rule it grants, which a review cannot prove.
//! - A review the identity may not run, an API the server does not have, or time that ran out is "not
//!   evaluated": the result is partial and never blocks on it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use k8s_openapi::api::authorization::v1::{
    SelfSubjectAccessReview, SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
    SubjectAccessReviewStatus,
};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::PostParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::K8sRbac;

use crate::client::{ImpersonateAs, KubeError, ReadOnlyClient};
use crate::cluster::Cluster;

mod ask;
mod fix;
mod judge;
mod rules;
mod window;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use ask::{Ask, Asks, impersonation_ask};
use judge::{Answer, Gathered, Identity, Impersonation, NamespaceState, Why};
use rules::RulesView;

/// The reviews in flight at once (03).
const IN_FLIGHT: usize = 8;

/// The namespaces whose existence is read, at most.
const MAX_NAMESPACES: usize = 3;

/// The static facts about `k8s.rbac` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.rbac",
    family: "k8s",
    summary: "Can the install identity do what the installer does",
    meta: CheckMeta {
        title: "Install permissions",
        remediation: "Ask the cluster admin to bind a role that grants the listed permissions to the install identity: `kubectl create clusterrole` and `kubectl create clusterrolebinding` (or `role` and `rolebinding -n <namespace>`). A denial that says it was explicit comes from another authorizer, such as a webhook, and a role cannot override it. On a throwaway test cluster only, `cluster-admin` works.",
    },
    needs: &[Need::KubeContext],
    wants: &[],
    default_timeout: Some(Duration::from_secs(30)),
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    },
    reads: &[],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// `k8s.rbac`, built from its spec entry.
pub struct RbacCheck {
    params: K8sRbac,
    cluster: Arc<dyn Cluster>,
}

impl std::fmt::Debug for RbacCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbacCheck")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl RbacCheck {
    /// The check for `params`, reading `cluster`.
    #[must_use]
    pub fn new(params: K8sRbac, cluster: Arc<dyn Cluster>) -> Self {
        Self { params, cluster }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for RbacCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let gathered = self.gather(ctx).await?;
            Ok(judge::judge(&self.params, &gathered))
        })
    }
}

/// How a failed request becomes a [`KubeError`]: `Cluster::map_error`, which knows the connection.
type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> KubeError + Sync);

/// A failure of the check itself: the network, the credentials, or a refusal by the guard.
fn failed(error: &KubeError) -> CheckError {
    CheckError::Failed {
        message: error.to_string(),
        hint: error.hint(),
    }
}

/// What a request the server answered with an error means for the check.
///
/// A refusal for this identity (403), a missing API (404) and any other status of the server are answers
/// the check can report. Everything else fails the check.
fn why_not(error: &KubeError) -> Result<Why, CheckError> {
    match error {
        KubeError::Forbidden { .. } => Ok(Why::Forbidden),
        KubeError::Api { code: 404, .. } => Ok(Why::Missing),
        KubeError::Api { code, .. } => Ok(Why::Status(*code)),
        other => Err(failed(other)),
    }
}

/// True when too little of the check's time is left to send another review.
fn out_of_time(ctx: &CheckContext) -> bool {
    ctx.remaining() < Duration::from_millis(500)
}

impl RbacCheck {
    async fn gather(&self, ctx: &CheckContext) -> Result<Gathered, CheckError> {
        let mapper = |error: &kube::Error| self.cluster.map_error(error);

        // The `as:` value is checked before any request. The kubeconfig must not impersonate too.
        let as_user = match &self.params.as_user {
            Some(user) => Some(ImpersonateAs::new(user.as_str()).map_err(|error| {
                CheckError::Failed {
                    message:
                        "the `as` value of the k8s.rbac entry cannot be sent as Impersonate-User"
                            .to_owned(),
                    hint: error.to_string(),
                }
            })?),
            None => None,
        };
        let plain = self.cluster.read_only(ctx.probe());
        let reviewer = match &as_user {
            Some(user) => self
                .cluster
                .read_only_as(ctx.probe(), user.clone())
                .map_err(|conflict| CheckError::Failed {
                    message: conflict.to_string(),
                    hint: conflict.hint().to_owned(),
                })?,
            None => plain.clone(),
        };

        let asks = Asks::from_params(&self.params);
        let sent = AtomicUsize::new(0);
        let identity = identity(&mapper, &plain).await?;

        // With `as:`, first ask whether the kubeconfig identity may act as that user.
        let impersonation = match &as_user {
            None => Impersonation::NotUsed,
            Some(user) => {
                let ask = impersonation_ask(user.as_str());
                match review_one(&mapper, &plain, &ask, &sent).await? {
                    Answer::Allowed => Impersonation::Allowed,
                    Answer::NotEvaluated(why) => Impersonation::Unknown(why),
                    Answer::NotAllowed { .. } | Answer::Denied { .. } | Answer::Unclear { .. } => {
                        Impersonation::Refused(ask.describe())
                    }
                }
            }
        };

        let (spec, implied) = if impersonation.blocks_reviews() {
            // Nothing can be evaluated as that user, and sending the reviews would only fail.
            let none = |asks: &[Ask]| -> Vec<(Ask, Answer)> {
                asks.iter()
                    .map(|ask| (ask.clone(), Answer::NotEvaluated(impersonation.why())))
                    .collect()
            };
            (none(&asks.spec), none(&asks.implied))
        } else {
            self.review_all(ctx, &mapper, &reviewer, &asks, &sent)
                .await?
        };

        let mut gathered = Gathered {
            identity,
            as_user: as_user.map(|user| user.as_str().to_owned()),
            impersonation,
            spec,
            implied,
            dropped: asks.dropped,
            rules: None,
            namespaces: Vec::new(),
            sent: 0,
        };

        // What is already granted, and whether the namespaces exist, only when it helps the fix.
        if gathered.has_denial() && !gathered.impersonation.blocks_reviews() {
            if let Some(namespace) = gathered.rules_namespace(self.params.namespace.as_ref())
                && !out_of_time(ctx)
            {
                gathered.rules = rules_review(&mapper, &reviewer, &namespace).await?;
            }
            for namespace in gathered
                .denied_namespaces()
                .into_iter()
                .take(MAX_NAMESPACES)
            {
                if out_of_time(ctx) {
                    break;
                }
                let state = namespace_state(&mapper, &plain, &namespace).await?;
                gathered.namespaces.push((namespace, state));
            }
        }
        gathered.sent = sent.load(Ordering::SeqCst);
        Ok(gathered)
    }

    /// Sends the reviews: the first one alone, then the rest 8 at a time.
    ///
    /// If the first one shows that the server has no review API or that the identity may not create
    /// reviews, the rest are not sent: every one would fail the same way.
    async fn review_all(
        &self,
        ctx: &CheckContext,
        mapper: Mapper<'_>,
        reviewer: &ReadOnlyClient,
        asks: &Asks,
        sent: &AtomicUsize,
    ) -> Result<(Vec<(Ask, Answer)>, Vec<(Ask, Answer)>), CheckError> {
        let all: Vec<&Ask> = asks.all().collect();
        let mut answers: Vec<Answer> = Vec::with_capacity(all.len());
        if let Some(first) = all.first() {
            answers.push(review_one(mapper, reviewer, first, sent).await?);
        }
        let stop = match answers.first() {
            Some(Answer::NotEvaluated(why @ (Why::Forbidden | Why::Missing))) => Some(why.clone()),
            _ => None,
        };
        // Boxed with a named lifetime: a closure that returns an `async fn` future makes the compiler
        // ask for a bound it cannot name once the check future is boxed as `dyn Future + Send`.
        let mut rest: Vec<BoxFuture<'_, Result<Answer, CheckError>>> = Vec::new();
        for ask in all.iter().skip(1).copied() {
            rest.push(Box::pin(review_unless_stopped(
                ctx,
                mapper,
                reviewer,
                ask,
                stop.as_ref(),
                sent,
            )));
        }
        for answer in window::windowed(IN_FLIGHT, rest).await {
            answers.push(answer?);
        }
        let mut paired = all
            .into_iter()
            .cloned()
            .zip(answers)
            .collect::<Vec<(Ask, Answer)>>();
        let implied = paired.split_off(asks.spec.len());
        Ok((paired, implied))
    }
}

/// One review, unless the first one showed that every one would fail (`stop`) or time has run out.
async fn review_unless_stopped(
    ctx: &CheckContext,
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    ask: &Ask,
    stop: Option<&Why>,
    sent: &AtomicUsize,
) -> Result<Answer, CheckError> {
    if let Some(why) = stop {
        return Ok(Answer::NotEvaluated(why.clone()));
    }
    if out_of_time(ctx) {
        return Ok(Answer::NotEvaluated(Why::OutOfTime));
    }
    review_one(mapper, client, ask, sent).await
}

/// `SelfSubjectReview`: who the server says rdy is. A server without the API, or an identity that may not
/// call it, leaves the identity unverified.
async fn identity(mapper: Mapper<'_>, client: &ReadOnlyClient) -> Result<Identity, CheckError> {
    match client.self_subject_review().await {
        Ok(review) => {
            let info = review.status.and_then(|status| status.user_info);
            Ok(
                match info.and_then(|info| info.username.map(|user| (user, info.groups))) {
                    Some((user, groups)) => Identity::Verified {
                        user,
                        groups: groups.unwrap_or_default(),
                    },
                    None => Identity::Unverified(Why::NoStatus),
                },
            )
        }
        Err(error) => Ok(Identity::Unverified(why_not(&mapper(&error))?)),
    }
}

/// One `SelfSubjectAccessReview`.
async fn review_one(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    ask: &Ask,
    sent: &AtomicUsize,
) -> Result<Answer, CheckError> {
    sent.fetch_add(1, Ordering::SeqCst);
    let api = client.all::<SelfSubjectAccessReview>();
    match api.create(&PostParams::default(), &ask.review()).await {
        Ok(review) => Ok(match review.status {
            Some(status) => answer_of(&status),
            None => Answer::NotEvaluated(Why::NoStatus),
        }),
        Err(error) => Ok(Answer::NotEvaluated(why_not(&mapper(&error))?)),
    }
}

/// Reads the status of a review. An explicit deny wins over an evaluation error.
fn answer_of(status: &SubjectAccessReviewStatus) -> Answer {
    let reason = status.reason.clone().unwrap_or_default();
    let error = status.evaluation_error.clone().unwrap_or_default();
    if status.allowed {
        Answer::Allowed
    } else if status.denied == Some(true) {
        Answer::Denied { reason }
    } else if !error.is_empty() {
        Answer::Unclear { reason: error }
    } else {
        Answer::NotAllowed { reason }
    }
}

/// `SelfSubjectRulesReview` for `namespace`: what the tested user may do there. Any error leaves it out:
/// it only adds detail.
async fn rules_review(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    namespace: &str,
) -> Result<Option<RulesView>, CheckError> {
    let review = SelfSubjectRulesReview {
        metadata: kube::api::ObjectMeta::default(),
        spec: SelfSubjectRulesReviewSpec {
            namespace: Some(namespace.to_owned()),
        },
        status: None,
    };
    match client
        .all::<SelfSubjectRulesReview>()
        .create(&PostParams::default(), &review)
        .await
    {
        Ok(done) => Ok(done
            .status
            .map(|status| RulesView::from_status(namespace, &status))),
        Err(error) => match why_not(&mapper(&error)) {
            Ok(_) => Ok(None),
            Err(error) => Err(error),
        },
    }
}

/// `GET` of the namespace a denied item names: does it exist?
async fn namespace_state(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    namespace: &str,
) -> Result<NamespaceState, CheckError> {
    match client.all::<Namespace>().get(namespace).await {
        Ok(_) => Ok(NamespaceState::Exists),
        Err(error) => Ok(match why_not(&mapper(&error))? {
            Why::Missing => NamespaceState::Missing,
            _ => NamespaceState::Unknown,
        }),
    }
}
