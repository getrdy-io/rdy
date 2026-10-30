use std::convert::Infallible;
use std::future::{Future, Ready, ready};
use std::sync::{Arc, Mutex};

use super::*;

const USER: &str = "system:serviceaccount:acme:installer";

/// Records the `Impersonate-User` values of every request and answers nothing else.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Vec<String>>>>);

impl Service<Request<Body>> for Recorder {
    type Response = ();
    type Error = Infallible;
    type Future = Ready<Result<(), Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let values = request
            .headers()
            .get_all("impersonate-user")
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        self.0.lock().expect("records").push(values);
        ready(Ok(()))
    }
}

/// The `Impersonate-User` values the inner service saw for one request.
fn send(method: &str, path: &str, caller_header: Option<&str>) -> Vec<String> {
    let recorder = Recorder::default();
    let mut service =
        AddImpersonation::new(recorder.clone(), ImpersonateAs::new(USER).expect("valid"));
    let mut request = Request::builder().method(method).uri(path);
    if let Some(value) = caller_header {
        request = request.header("impersonate-user", value);
    }
    let request = request.body(Body::empty()).expect("a request");
    let mut future = service.call(request);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(std::pin::Pin::new(&mut future).poll(&mut cx).is_ready());
    let records = recorder.0.lock().expect("records");
    records[0].clone()
}

#[test]
fn the_two_review_posts_get_the_header_once() {
    for path in [
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
    ] {
        assert_eq!(send("POST", path, None), [USER], "{path}");
    }
}

#[test]
fn a_value_the_caller_set_is_replaced_not_added_to() {
    assert_eq!(
        send(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            Some("someone-else")
        ),
        [USER]
    );
}

#[test]
fn nothing_else_gets_the_header() {
    for (method, path) in [
        ("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews"),
        (
            "GET",
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        ),
        ("GET", "/version"),
        ("GET", "/api/v1/namespaces/acme"),
        ("POST", "/api/v1/namespaces/acme/pods"),
    ] {
        assert!(send(method, path, None).is_empty(), "{method} {path}");
    }
    // A value a caller set on another request is left for the guard to refuse.
    assert_eq!(send("GET", "/version", Some("x")), ["x"]);
}

#[test]
fn the_value_is_marked_sensitive() {
    let service = AddImpersonation::new(
        Recorder::default(),
        ImpersonateAs::new(USER).expect("valid"),
    );
    assert!(service.value.is_sensitive());
}

#[test]
fn the_conflict_text_names_the_fields_and_no_user() {
    let text = ImpersonationConflict.to_string();
    assert!(text.contains("as-groups") && !text.contains("system:"));
    assert!(
        ImpersonationConflict
            .hint()
            .contains("remove `as:` from the k8s.rbac entry")
    );
}
