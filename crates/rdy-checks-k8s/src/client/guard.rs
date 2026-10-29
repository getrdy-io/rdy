//! The read-only guard: a tower layer in front of the kube client's service (INV-14, ADR 0010).
//!
//! [`guarded_service`] is the one constructor. Production and the mock tests both call it, so the real
//! layer order is under test. The guard sits outside kube's own layers. It sees the request as the
//! caller built it (a path with no host, no `Authorization` header yet) and decides before anything is
//! sent. A refused request never reaches the inner service: no socket, no plugin, no token refresh.
//!
//! Every request writes exactly one `kube` entry to the action log through [`Probe::kube_call`]. The
//! entry has the method and the path (no query string, no body), and it is closed with the status, a
//! refusal rule or a fixed failure phrase. A request that is dropped in flight is recorded as `timeout`.
//! The entry names the check whose probe built the guard, so a check derives its client from its own
//! probe ([`Connected::read_only`](super::Connected::read_only)).
//!
//! The refusal is a [`GuardError`] with a fixed text: the rule sentence and a fix hint. It holds no
//! path, no query and no body, and the guard logs none of them to `tracing` either.

use std::fmt;
use std::future::{Future, ready};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use http::{Request, Response};
use http_body::Body as _;
use kube::client::Body;
use rdy_engine::probe::{Probe, ProbeError, RULE_NO_PROBE};
use tower_layer::Layer;
use tower_service::Service;

mod rules;
#[cfg(test)]
mod tests;

pub use rules::{
    ALLOWED, Access, Allowed, Only, RULE_BODY, RULE_GET_BODY, RULE_IMPERSONATE, RULE_METHOD,
    RULE_NOT_ALLOWED, RULE_PATH_SHAPE, RULE_POST_QUERY, RULE_POST_TARGET, RULE_QUERY,
    RULE_REVIEW_BODY, RULE_SECRETS, RULE_UPGRADE, SELF_SUBJECT_REVIEW_BODY,
};
use rules::{BodyView, judge, log_path};

use super::text::escape_capped;

/// The error type tower services share.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The guard refused a request. The request was not sent.
///
/// It reaches a caller inside `kube::Error::Service`. The text is fixed: the rule sentence and a hint,
/// never the path, the query or the body. The path is in the action log, redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the read-only guard refused this request ({rule}). Fix: rdy only reads, and never reads Secrets. This is a bug in rdy or in a check; report it with the action log of the run"
)]
pub struct GuardError {
    rule: &'static str,
}

impl GuardError {
    /// The fixed sentence of the rule that refused the request.
    #[must_use]
    pub fn rule(&self) -> &'static str {
        self.rule
    }
}

/// Wraps `inner` in the read-only guard, logging through `probe`.
///
/// `inner` is the service that sends requests (kube's stack, or a mock in a test). The result is a
/// `tower::Service` of the same request and response types, with `BoxError` as its error.
pub fn guarded_service<S>(inner: S, probe: &Probe) -> Guarded<S> {
    GuardLayer {
        probe: probe.clone(),
    }
    .layer(inner)
}

/// The tower layer behind [`guarded_service`].
#[derive(Clone)]
pub struct GuardLayer {
    probe: Probe,
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
        }
    }
}

/// A service behind the read-only guard. Build it with [`guarded_service`].
#[derive(Clone)]
pub struct Guarded<S> {
    inner: S,
    probe: Probe,
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
        let call = match self.probe.kube_call(&method, &log_path(request.uri())) {
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
        if let Err(rule) = judge(request.method(), request.uri(), request.headers(), view) {
            call.refused(rule);
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
    pub(super) fn new(raw: &kube::Client, probe: &Probe) -> Self {
        // The namespace of a kubeconfig is not used (ADR 0031 decision 12).
        let client = kube::Client::new(guarded_service(RawService(raw.clone()), probe), "");
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
