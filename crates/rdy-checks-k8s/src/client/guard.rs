//! The read-only guard: a tower layer in front of the kube client's service (INV-14, ADR 0010).
//!
//! [`guarded_service`] is the one constructor. Production and the mock tests both call it, so the real
//! layer order is under test. The guard sits outside kube's own layers. It sees the request as the
//! caller built it (a path with no host, no `Authorization` header yet) and decides before anything is
//! sent. A refused request never reaches the inner service: no socket, no plugin, no token refresh.
//!
//! Every request writes exactly one `kube` entry to the action log through [`Probe::kube_call`]. The
//! entry has the method and the path (no query string, no body), `via_proxy` (the proxy origin the
//! request goes through, with no user info, or `null`), and it is closed with the status, a refusal rule
//! or a fixed failure phrase. A request that is dropped in flight is recorded as `timeout`.
//! The entry names the check whose probe built the guard, so a check derives its client from its own
//! probe ([`Connected::read_only`](super::Connected::read_only)).
//!
//! A request header outside `accept`, `content-type` and `content-length` is refused, and the entry
//! names the header and never its value. The one exception is `Impersonate-User` with the spec's `as:`
//! value on the two access review POSTs ([`guarded_service_as`]). A redirect (3xx) is logged as `failed`: redirects are not
//! followed. A `failed` entry always has a fixed `error` field.
//!
//! The refusal is a [`GuardError`] with a fixed text: the rule sentence and a fix hint. It holds no
//! path, no query and no body, and the guard logs none of them to `tracing` either.

use std::fmt;
use std::future::{Future, ready};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use http::header::CONTENT_TYPE;
use http::{Request, Response};
use http_body::Body as _;
use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{APIGroupList, APIResourceList, APIVersions};
use kube::client::Body;
use rdy_engine::probe::{Probe, ProbeError, RULE_CHECK_FINISHED, RULE_NO_PROBE};
use tower_layer::Layer;
use tower_service::Service;

mod rules;
#[cfg(test)]
mod tests;

use rules::SELF_SUBJECT_REVIEW_PATH;
#[cfg(not(test))]
use rules::log_path;
pub use rules::{
    ALLOWED, Access, Allowed, FieldSelector, ImpersonateAs, ImpersonateError, Only, RULE_BODY,
    RULE_GET_BODY, RULE_HEADER, RULE_IMPERSONATE, RULE_METHOD, RULE_NOT_ALLOWED, RULE_PATH_SHAPE,
    RULE_POST_QUERY, RULE_POST_TARGET, RULE_QUERY, RULE_REVIEW_BODY, RULE_SECRETS, RULE_SELECTOR,
    RULE_SUBRESOURCE, RULE_UPGRADE, SELF_SUBJECT_REVIEW_BODY,
};
pub(super) use rules::{BodyView, judge};
use rules::{bad_header, impersonation_allowed, is_group, is_version};
// What the mock harness (`client::mock`) needs to judge the requests it recorded the way the guard does.
#[cfg(test)]
pub(super) use rules::{Target, decode_query_value, log_path, target_of};

use super::text::escape_capped;

/// The error type tower services share.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The guard refused a request. The request was not sent.
///
/// It reaches a caller inside `kube::Error::Service`. The text is fixed: the rule sentence and a hint,
/// never the path, the query or the body. The path is in the action log, redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the read-only guard refused this request ({rule}). Fix: {}", fix_text(.rule))]
pub struct GuardError {
    rule: &'static str,
}

impl GuardError {
    /// The fixed sentence of the rule that refused the request.
    #[must_use]
    pub fn rule(&self) -> &'static str {
        self.rule
    }

    /// True when the request came after its check ended. That is a check that ran past its timeout,
    /// not a request the rules refuse. A request from a closed probe ([`RULE_NO_PROBE`]) is a bug in
    /// how the client was built, so it is not late.
    #[must_use]
    pub fn is_late(&self) -> bool {
        self.rule == RULE_CHECK_FINISHED
    }
}

/// The fixed fix hint of a refusal. A late call gets its own text.
fn fix_text(rule: &str) -> &'static str {
    if rule == RULE_CHECK_FINISHED {
        "this request came after its check ended. The check ran past its time limit. The request was not sent; report it with the action log of the run"
    } else {
        "rdy only reads, and never reads Secrets. This is a bug in rdy or in a check; report it with the action log of the run"
    }
}

/// Wraps `inner` in the read-only guard, logging through `probe`.
///
/// `inner` is the service that sends requests (kube's stack, or a mock in a test). The result is a
/// `tower::Service` of the same request and response types, with `BoxError` as its error.
pub fn guarded_service<S>(inner: S, probe: &Probe) -> Guarded<S> {
    guarded_service_via(inner, probe, None)
}

/// Like [`guarded_service`], and every `kube` entry records `via_proxy`: the proxy origin
/// (`scheme://host:port`, no user info) that the connection's requests go through, or `None` for none.
pub fn guarded_service_via<S>(inner: S, probe: &Probe, via_proxy: Option<&str>) -> Guarded<S> {
    GuardLayer {
        probe: probe.clone(),
        impersonate: None,
        via_proxy: via_proxy.map(Arc::from),
    }
    .layer(inner)
}

/// Like [`guarded_service_via`], and the two access review POSTs may carry `Impersonate-User: <user>`.
///
/// `user` is the spec's `as:` value, already checked by [`ImpersonateAs::new`]. The header passes only on
/// `selfsubjectaccessreviews` and `selfsubjectrulesreviews`, only once and only with exactly this value.
/// On any other request it is refused, as is every other `Impersonate-*` header (02 Appendix B rule 8).
pub fn guarded_service_as<S>(
    inner: S,
    probe: &Probe,
    user: ImpersonateAs,
    via_proxy: Option<&str>,
) -> Guarded<S> {
    GuardLayer {
        probe: probe.clone(),
        impersonate: Some(Arc::new(user)),
        via_proxy: via_proxy.map(Arc::from),
    }
    .layer(inner)
}

/// The tower layer behind [`guarded_service`].
#[derive(Clone)]
pub struct GuardLayer {
    probe: Probe,
    impersonate: Option<Arc<ImpersonateAs>>,
    via_proxy: Option<Arc<str>>,
}

impl fmt::Debug for GuardLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardLayer").finish_non_exhaustive()
    }
}

impl<S> Layer<S> for GuardLayer {
    type Service = Guarded<S>;

    fn layer(&self, inner: S) -> Guarded<S> {
        Guarded {
            inner,
            probe: self.probe.clone(),
            impersonate: self.impersonate.clone(),
            via_proxy: self.via_proxy.clone(),
        }
    }
}

/// A service behind the read-only guard. Build it with [`guarded_service`].
#[derive(Clone)]
pub struct Guarded<S> {
    inner: S,
    probe: Probe,
    impersonate: Option<Arc<ImpersonateAs>>,
    via_proxy: Option<Arc<str>>,
}

impl<S> fmt::Debug for Guarded<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guarded").finish_non_exhaustive()
    }
}

/// The future of a guarded request.
type GuardFuture<B> = Pin<Box<dyn Future<Output = Result<Response<B>, BoxError>> + Send>>;

impl<S, B> Service<Request<Body>> for Guarded<S>
where
    S: Service<Request<Body>, Response = Response<B>>,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: Send + 'static,
{
    type Response = Response<B>;
    type Error = BoxError;
    type Future = GuardFuture<B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let method = escape_capped(request.method().as_str(), 16);
        let call =
            match self
                .probe
                .kube_call(&method, &log_path(request.uri()), self.via_proxy.as_deref())
            {
                Ok(call) => call,
                // The probe is closed or its check ended. The refusal is logged by the probe.
                Err(error) => {
                    let rule = match error {
                        ProbeError::Denied { rule, .. } => rule,
                        _ => RULE_NO_PROBE,
                    };
                    return Box::pin(ready(Err(GuardError { rule }.into())));
                }
            };

        let body = read_body(request.body());
        let view = match &body {
            Some(bytes) if bytes.is_empty() => BodyView::Empty,
            Some(bytes) => BodyView::Bytes(bytes),
            None => BodyView::Opaque,
        };
        let configured = self.impersonate.as_deref();
        if let Err(rule) = judge(
            request.method(),
            request.uri(),
            request.headers(),
            view,
            configured,
        ) {
            // A refused header is named in the log, never its value.
            let allowed = impersonation_allowed(request.method(), request.uri(), configured);
            match bad_header(request.headers(), allowed) {
                Some((header_rule, name)) if header_rule == rule => {
                    call.refused_header(rule, &escape_capped(name, 64));
                }
                _ => call.refused(rule),
            }
            return Box::pin(ready(Err(GuardError { rule }.into())));
        }

        let future = self.inner.call(request);
        Box::pin(async move {
            match future.await {
                Ok(response) => {
                    call.answered(response.status().as_u16());
                    Ok(response)
                }
                Err(error) => {
                    call.failed("the request failed");
                    Err(error.into())
                }
            }
        })
    }
}

/// The bytes of a body that can be replayed, or `None` for one that is streamed.
///
/// A body that kube builds from a `Vec` is a single chunk, so one poll with a waker that does nothing
/// returns it. The body is cloned first, so the request keeps its own copy.
fn read_body(body: &Body) -> Option<Vec<u8>> {
    if body.size_hint().exact() == Some(0) {
        return Some(Vec::new());
    }
    let copy = pin!(body.try_clone()?);
    let mut cx = Context::from_waker(Waker::noop());
    match copy.poll_frame(&mut cx) {
        Poll::Ready(Some(Ok(frame))) => frame.into_data().ok().map(|data| data.to_vec()),
        _ => None,
    }
}

/// The unguarded kube client, as a service for [`guarded_service`] to wrap.
///
/// It is private to this module's parent. Nothing outside the client module can name it, and the only
/// client it ends up in is built by [`ReadOnlyClient`].
#[derive(Clone)]
pub(super) struct RawService(pub(super) kube::Client);

impl Service<Request<Body>> for RawService {
    type Response = Response<Body>;
    type Error = kube::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, kube::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let client = self.0.clone();
        Box::pin(async move { client.send(request).await })
    }
}

/// The only client type checks get. Every request it sends passed the guard and wrote one `kube` entry
/// to the action log of the probe it was made with (INV-14).
///
/// It hands out `kube::Api` values and never a `kube::Client`, so check code never names the type.
/// Get one from [`Connected::read_only`](super::Connected::read_only).
#[derive(Clone)]
pub struct ReadOnlyClient {
    client: kube::Client,
}

impl fmt::Debug for ReadOnlyClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadOnlyClient").finish_non_exhaustive()
    }
}

impl ReadOnlyClient {
    /// Puts the guard in front of `raw`. Needs a running tokio runtime, because kube's client starts a
    /// worker task.
    pub(super) fn new(raw: &kube::Client, probe: &Probe, via_proxy: Option<&str>) -> Self {
        Self::over(RawService(raw.clone()), probe, via_proxy)
    }

    /// Puts the guard in front of `inner`: the one place a client is built. Production passes the raw
    /// kube client, and the mock harness (`client::mock`) passes its replaying service, so a fixture run
    /// goes through the same layers a real run does.
    pub(super) fn over<S>(inner: S, probe: &Probe, via_proxy: Option<&str>) -> Self
    where
        S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
    {
        // The namespace of a kubeconfig is not used (ADR 0031 decision 12).
        let client = kube::Client::new(guarded_service_via(inner, probe, via_proxy), "");
        Self { client }
    }

    /// An API handle for a resource in the whole cluster, or a cluster-scoped one.
    #[must_use]
    pub fn all<K>(&self) -> kube::Api<K>
    where
        K: kube::Resource,
        K::DynamicType: Default,
    {
        kube::Api::all(self.client.clone())
    }

    /// An API handle for a namespaced resource in `namespace`.
    #[must_use]
    pub fn namespaced<K>(&self, namespace: &str) -> kube::Api<K>
    where
        K: kube::Resource<Scope = kube::core::NamespaceResourceScope>,
        K::DynamicType: Default,
    {
        kube::Api::namespaced(self.client.clone(), namespace)
    }

    /// The legacy discovery document of the core group, `GET /api`: the versions it serves.
    ///
    /// The plain document, not the aggregated one: no `Accept` is sent that selects it, so an old and a
    /// new server answer in the same shape (03, "Fixtures for all of them").
    ///
    /// # Errors
    ///
    /// The `kube::Error` of the request, which can be a [`GuardError`] inside `Service`.
    pub async fn core_versions(&self) -> Result<APIVersions, kube::Error> {
        self.client.list_core_api_versions().await
    }

    /// The resources the core group serves at `version`, `GET /api/<version>`. The core group has one
    /// version, `v1`, and the guard allows that one discovery path, so any other value is refused as
    /// [`RULE_PATH_SHAPE`] before anything is sent (it writes no log entry). A check reads that refusal as
    /// "not served".
    ///
    /// # Errors
    ///
    /// The `kube::Error` of the request, which can be a [`GuardError`] inside `Service`.
    pub async fn core_resources(&self, version: &str) -> Result<APIResourceList, kube::Error> {
        if version != "v1" {
            return Err(kube::Error::Service(
                GuardError {
                    rule: RULE_PATH_SHAPE,
                }
                .into(),
            ));
        }
        self.client.list_core_api_resources(version).await
    }

    /// The legacy discovery document of the named groups, `GET /apis`.
    ///
    /// # Errors
    ///
    /// The `kube::Error` of the request, which can be a [`GuardError`] inside `Service`.
    pub async fn api_groups(&self) -> Result<APIGroupList, kube::Error> {
        self.client.list_api_groups().await
    }

    /// The resources a group version serves, `GET /apis/<group>/<version>`. A 404 means the server does
    /// not serve it, and is the answer a check reads as "not installed".
    ///
    /// `group` and `version` are put in the path only if they have the shape of a group and a version
    /// (a DNS-1123 subdomain, and `v1`, `v2`, `v1beta1`, `v1alpha2`). Anything else, a `/` or a `?` in
    /// either, is refused as [`RULE_PATH_SHAPE`] before anything is sent: such a value could build a
    /// different path than a discovery path. This refusal is not a request, so it writes no log entry.
    /// The guard then judges the path itself, as for every request.
    ///
    /// # Errors
    ///
    /// The `kube::Error` of the request, which can be a [`GuardError`] inside `Service`.
    pub async fn group_resources(
        &self,
        group: &str,
        version: &str,
    ) -> Result<APIResourceList, kube::Error> {
        if !(is_group(group) && is_version(version)) {
            return Err(kube::Error::Service(
                GuardError {
                    rule: RULE_PATH_SHAPE,
                }
                .into(),
            ));
        }
        self.client
            .list_api_group_resources(&format!("{group}/{version}"))
            .await
    }

    /// Who the server says rdy is, `POST /apis/authentication.k8s.io/v1/selfsubjectreviews`.
    ///
    /// The body is [`SELF_SUBJECT_REVIEW_BODY`], sent as raw bytes. A typed k8s-openapi
    /// `SelfSubjectReview` serializes with a `metadata` member, which the guard refuses, so this is the
    /// only way a check sends one (ADR 0010 decision 2). The request goes through the guard like any other.
    ///
    /// # Errors
    ///
    /// The `kube::Error` of the request: `Api` for a 401 or 403 (or a 404 on a server older than 1.28),
    /// or a [`GuardError`] inside `Service`.
    pub async fn self_subject_review(&self) -> Result<SelfSubjectReview, kube::Error> {
        let request = Request::post(SELF_SUBJECT_REVIEW_PATH)
            .header(CONTENT_TYPE, "application/json")
            .body(SELF_SUBJECT_REVIEW_BODY.to_vec())
            .map_err(kube::Error::HttpError)?;
        self.client.request(request).await
    }

    /// The server's `GET /version` through the guard.
    ///
    /// # Errors
    ///
    /// The `kube::Error` of the request, which can be a [`GuardError`] inside `Service`.
    pub(super) async fn version(
        &self,
    ) -> Result<k8s_openapi::apimachinery::pkg::version::Info, kube::Error> {
        self.client.apiserver_version().await
    }
}
