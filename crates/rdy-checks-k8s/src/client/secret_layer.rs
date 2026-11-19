//! A layer that makes the `Authorization` value of every request a known secret before the request is sent
//! (M1-107, S1 and C1 of the reviews).
//!
//! A credential plugin hands its token to kube, and kube 4.2.0 does not show it to anyone. The only place
//! rdy can see it is on the request. The stack is built here: the auth layer of kube (the plugin, the
//! token file, a static token) sits OUTSIDE this layer, so by the time a request reaches it the header is
//! set, and this layer registers the token with the run's known-secret set and only then lets it go to the
//! rest of the stack (and the socket). A token that is refreshed later is a new value, registered the same
//! way. When the set refuses a value, nothing is sent, the refusal is remembered in a flag the family reads,
//! and the run ends with exit 70.

use std::collections::HashSet;
use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use http::header::AUTHORIZATION;
use http::{Request, Response};
use kube::client::Body;
use kube::client::middleware::AuthLayer;
use rdy_engine::probe::SecretSink;
use tower_layer::Layer;
use tower_service::Service;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Where the bearer tokens go, and the flag that says the set refused one.
#[derive(Clone)]
pub struct SecretHook {
    sink: SecretSink,
    refused: Arc<AtomicBool>,
    seen: Arc<Mutex<HashSet<String>>>,
}

impl SecretHook {
    /// A hook that adds to `sink` and sets `refused` when the set says no.
    #[must_use]
    pub fn new(sink: SecretSink, refused: Arc<AtomicBool>) -> Self {
        Self {
            sink,
            refused,
            seen: Arc::default(),
        }
    }

    /// Registers the credential of an `Authorization` value. `false` when the set refused it.
    fn register(&self, header: &str) -> bool {
        // `Bearer <token>` and `Basic <base64>`: the secret is the part after the scheme.
        let value = header
            .split_once(' ')
            .map_or(header, |(_, rest)| rest)
            .trim();
        if value.is_empty() {
            return true;
        }
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.contains(value) {
            return true;
        }
        if self.sink.add(value) {
            seen.insert(value.to_owned());
            true
        } else {
            self.refused.store(true, Ordering::SeqCst);
            false
        }
    }
}

/// The auth layer of kube with the registering layer under it.
pub(super) struct Stack {
    pub(super) auth: AuthLayer,
    pub(super) hook: SecretHook,
}

impl<S> Layer<S> for Stack
where
    AuthLayer: Layer<Register<S>>,
{
    type Service = <AuthLayer as Layer<Register<S>>>::Service;

    fn layer(&self, inner: S) -> Self::Service {
        self.auth.layer(Register {
            inner,
            hook: self.hook.clone(),
        })
    }
}

/// The service that registers, then forwards.
#[derive(Clone)]
pub(super) struct Register<S> {
    inner: S,
    hook: SecretHook,
}

impl<S> Service<Request<Body>> for Register<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        if let Some(value) = request.headers().get(AUTHORIZATION)
            && let Ok(text) = value.to_str()
            && !self.hook.register(text)
        {
            // Nothing is sent. The error holds no value.
            return Box::pin(ready(Err(
                "a credential could not be registered for redaction".into(),
            )));
        }
        let future = self.inner.call(request);
        Box::pin(async move { future.await.map_err(Into::into) })
    }
}
