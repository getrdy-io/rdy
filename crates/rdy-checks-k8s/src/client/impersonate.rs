//! Impersonation for the access reviews of `k8s.rbac` (M1-111, 02 Appendix B rule 8).
//!
//! `k8s.rbac` can test as another user: the spec's `as:`. The server evaluates a `SelfSubjectAccessReview`
//! as the user in an `Impersonate-User` header, and the caller needs the `impersonate` verb for it.
//!
//! kube's `Api` cannot set a header, and the guard must see the header to judge it. So a thin service
//! sits *above* the guard: [`AddImpersonation`] puts `Impersonate-User: <user>` on the two review POSTs and
//! nothing else, and the guard (built by [`guarded_service_as`](super::guard::guarded_service_as)) lets
//! exactly that header through. It marks the action-log entry `impersonated: true`. The order is
//! `kube::Client` over `AddImpersonation` over `Guarded` over kube's stack.
//!
//! kube's own stack sits below the guard and adds `Impersonate-User` and `Impersonate-Group` when the
//! kubeconfig user sets `as` or `as-groups`. If both sources wrote the header, the server would see two
//! values, so rdy refuses before it builds the client: [`ImpersonationConflict`].

use std::task::{Context, Poll};

use http::Request;
use http::header::{HeaderName, HeaderValue};
use kube::client::Body;
use tower_service::Service;

use super::guard::{ImpersonateAs, impersonation_allowed};

#[cfg(test)]
mod tests;

/// The header kube and the API server use for the user to act as.
const IMPERSONATE_USER: HeaderName = HeaderName::from_static("impersonate-user");

/// The kubeconfig user already impersonates, so a spec `as:` cannot be used.
///
/// The text holds no user name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the kubeconfig user already sets an impersonation field (as, as-uid, as-groups or as-user-extra)"
)]
pub struct ImpersonationConflict;

impl ImpersonationConflict {
    /// What to do about it.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        "Use a kubeconfig whose user does not set `as`, `as-uid`, `as-groups` or `as-user-extra` (see `kubectl config view --minify`), or remove `as:` from the k8s.rbac entry of the spec. rdy does not stack two impersonations: the server would see two Impersonate-User headers."
    }
}

/// A service that adds `Impersonate-User: <user>` to the review POSTs that may carry it.
///
/// It is the outer layer: the guard below it sees the header and judges it.
#[derive(Clone)]
pub(super) struct AddImpersonation<S> {
    inner: S,
    user: ImpersonateAs,
    value: HeaderValue,
}

impl<S> AddImpersonation<S> {
    /// Wraps `inner`. A value the guard accepted is printable ASCII, so it is a valid header value. The
    /// value is marked sensitive so it is not printed by a debug format of the request.
    pub(super) fn new(inner: S, user: ImpersonateAs) -> Self {
        let mut value = HeaderValue::from_str(user.as_str())
            .unwrap_or_else(|_| HeaderValue::from_static("invalid"));
        value.set_sensitive(true);
        Self { inner, user, value }
    }
}

impl<S, R> Service<Request<Body>> for AddImpersonation<S>
where
    S: Service<Request<Body>, Response = R>,
{
    type Response = R;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        if impersonation_allowed(request.method(), request.uri(), Some(&self.user)).is_some() {
            // `insert` replaces any value a caller set, so the guard never sees two.
            request
                .headers_mut()
                .insert(IMPERSONATE_USER, self.value.clone());
        }
        self.inner.call(request)
    }
}
