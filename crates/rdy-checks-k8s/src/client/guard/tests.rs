//! Tests of the read-only guard (M1-103): the rules as a table, then the real layer in front of a mock
//! API server that records what reaches it.
//!
//! The mock is a tower service, and the client is built with `guarded_service` and kube's own request
//! builders, so the layer order and the request shapes are the ones a check gets. The probe is a
//! `TestRun` probe, so the action log is the real one.

use std::convert::Infallible;
use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::{Method, Request, Response, StatusCode};
use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use k8s_openapi::api::core::v1::{Namespace, Node, Pod, Secret};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::client::Body;
use rdy_engine::check::Os;
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::json;
use tower_service::Service;

use super::*;

// ---- the mock API server ------------------------------------------------------------------------------

/// Records `METHOD path-and-query` of every request that reaches it and answers 200 with `body`.
#[derive(Clone, Default)]
struct Mock {
    seen: Arc<Mutex<Vec<String>>>,
    body: Arc<Mutex<String>>,
    /// The status of every answer.
    status: StatusCode,
    /// When set, a request is never answered (a hung server).
    hang: bool,
}

impl Mock {
    fn reply(&self, body: serde_json::Value) {
        *self.body.lock().expect("body") = body.to_string();
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("seen").clone()
    }
}

impl Service<Request<Body>> for Mock {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let line = format!(
            "{} {}",
            request.method(),
            request
                .uri()
                .path_and_query()
                .map_or("", http::uri::PathAndQuery::as_str)
        );
        self.seen.lock().expect("seen").push(line);
        if self.hang {
            return Box::pin(std::future::pending());
        }
        let body = self.body.lock().expect("body").clone();
        let body = if body.is_empty() {
            "{}".to_owned()
        } else {
            body
        };
        let response = Response::builder()
            .status(self.status)
            .body(Body::from(body.into_bytes()))
            .expect("response");
        Box::pin(ready(Ok(response)))
    }
}

/// One check's client over the shared mock.
struct Rig {
    mock: Mock,
    run: TestRun,
    client: kube::Client,
}

impl Rig {
    fn new() -> Self {
        Self::for_check(
            &TestRun::new(Replay::new()),
            &Mock::default(),
            Some("k8s.nodes"),
        )
    }

    /// A client for `check` (or the run itself) over `mock`, logging into `run`.
    fn for_check(run: &TestRun, mock: &Mock, check: Option<&str>) -> Self {
        let probe = match check {
            Some(key) => run.context(key, Os::Linux, []).probe().clone(),
            None => run.run_probe(Os::Linux),
        };
        let client = kube::Client::new(guarded_service(mock.clone(), &probe), "");
        Self {
            mock: mock.clone(),
            run: run.clone(),
            client,
        }
    }

    /// Sends one request. `Err` holds the rule if the guard refused it.
    async fn send(&self, request: Request<Body>) -> Result<StatusCode, &'static str> {
        match self.client.send(request).await {
            Ok(response) => Ok(response.status()),
            Err(error) => Err(refusal(&error).expect("only the guard fails in these tests")),
        }
    }

    async fn get(&self, uri: &str) -> Result<StatusCode, &'static str> {
        self.send(request(Method::GET, uri, &[], Vec::new())).await
    }

    fn log(&self) -> Vec<Action> {
        self.run.action_log().actions
    }
}

fn request(method: Method, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body)).expect("request")
}

/// The rule of a guard refusal inside a kube error, or `None` for any other error.
fn refusal(error: &kube::Error) -> Option<&'static str> {
    match error {
        kube::Error::Service(inner) => inner.downcast_ref::<GuardError>().map(GuardError::rule),
        _ => None,
    }
}

fn field<'a>(action: &'a Action, name: &str) -> Option<&'a str> {
    action.fields.get(name).and_then(|value| value.as_str())
}

// ---- the rules, as a table ------------------------------------------------------------------------------

fn judge_get(uri: &str) -> Result<(), &'static str> {
    let uri: http::Uri = uri.parse().expect("uri");
    judge(&Method::GET, &uri, &http::HeaderMap::new(), BodyView::Empty)
}

#[test]
fn the_table_has_no_secrets_and_every_entry_names_its_checks() {
    assert!(!ALLOWED.is_empty());
    for entry in ALLOWED {
        let text = format!(
            "{} {} {} {:?}",
            entry.group, entry.version, entry.resource, entry.reads
        );
        assert!(!text.to_lowercase().contains("secret"), "{text}");
        assert!(!entry.checks.is_empty(), "{}", entry.resource);
        assert!(entry.checks.iter().all(|c| c.starts_with("k8s.")));
        assert!(!entry.reads.is_empty() && !entry.access.is_empty());
        let same = ALLOWED
            .iter()
            .filter(|e| {
                (e.group, e.version, e.resource) == (entry.group, entry.version, entry.resource)
            })
            .count();
        assert_eq!(same, 1, "{} is listed twice", entry.resource);
    }
}

/// The path an `Access` shape gives for an entry.
fn path_for(entry: &Allowed, access: &Access) -> String {
    let prefix = if entry.group.is_empty() {
        format!("/api/{}", entry.version)
    } else {
        format!("/apis/{}/{}", entry.group, entry.version)
    };
    let name = |only: &Only| match only {
        Only::Any => "x".to_owned(),
        Only::Name(name) => (*name).to_owned(),
    };
    match access {
        Access::List => format!("{prefix}/{}", entry.resource),
        Access::ListInNamespace(only) => {
            format!("{prefix}/namespaces/{}/{}", name(only), entry.resource)
        }
        Access::Get(only) => format!("{prefix}/{}/{}", entry.resource, name(only)),
    }
}

#[test]
fn every_allowed_shape_passes_and_a_neighbour_does_not() {
    for entry in ALLOWED {
        for access in entry.access {
            let path = path_for(entry, access);
            if matches!(access, Access::Get(_))
                || entry.field_selector == FieldSelector::NotRequired
            {
                assert_eq!(judge_get(&path), Ok(()), "{path}");
                assert_eq!(judge_get(&format!("{path}?limit=500")), Ok(()), "{path}");
                assert_eq!(judge_get(&format!("{path}?")), Ok(()), "{path}");
            } else {
                // A list whose entry names a field selector is refused without it.
                assert_eq!(judge_get(&path), Err(RULE_SELECTOR), "{path}");
                assert_eq!(judge_get(&format!("{path}?")), Err(RULE_SELECTOR), "{path}");
                let selector = match entry.field_selector {
                    FieldSelector::Key(key) => format!("{key}%21%3Dx"),
                    FieldSelector::Equals(key, value) => format!("{key}%3D{value}"),
                    FieldSelector::NotRequired => unreachable!("handled above"),
                };
                let ok = format!("{path}?&fieldSelector={selector}&limit=500");
                assert_eq!(judge_get(&ok), Ok(()), "{ok}");
            }
        }
        // A shape the entry does not list is refused: a list where only a get is allowed, and the
        // other way round.
        let all = [
            Access::List,
            Access::ListInNamespace(Only::Any),
            Access::Get(Only::Any),
        ];
        for access in all {
            let listed = entry
                .access
                .iter()
                .any(|a| std::mem::discriminant(a) == std::mem::discriminant(&access));
            if !listed {
                let path = path_for(entry, &access);
                assert_eq!(judge_get(&path), Err(RULE_NOT_ALLOWED), "{path}");
            }
        }
    }
}

#[test]
fn a_pod_list_needs_the_phase_field_selector() {
    let pods = "/api/v1/pods";
    for query in [
        "&fieldSelector=status.phase%21%3DSucceeded%2Cstatus.phase%21%3DFailed&limit=500",
        "fieldSelector=status.phase%3DRunning",
        "fieldSelector=status.phase%3D%3DRunning",
        "fieldSelector=spec.nodeName%3Dn1%2Cstatus.phase%21%3DFailed",
        "fieldSelector=status.phase%21%3DFailed%2Cspec.nodeName%3Dn1&limit=100",
    ] {
        assert_eq!(judge_get(&format!("{pods}?{query}")), Ok(()), "{query}");
    }
    // Missing, or a selector on another key.
    for query in [
        "",
        "?",
        "?&limit=500",
        "?labelSelector=status.phase%3DRunning",
        "?fieldSelector=spec.nodeName%3Dn1",
        "?fieldSelector=",
        "?fieldSelector=metadata.name%3Dstatus.phase",
        "?fieldSelector=xstatus.phase%3DRunning",
        "?fieldSelector=status.phasex%3DRunning",
        "?fieldSelector=status.phase",
        "?fieldSelector=status.phase%2Cspec.nodeName%3Dn1",
    ] {
        assert_eq!(
            judge_get(&format!("{pods}{query}")),
            Err(RULE_SELECTOR),
            "{query}"
        );
    }
    // A selector the guard cannot read is a query error, not a pass.
    for query in [
        "fieldSelector=status.phase%21%3DFailed&fieldSelector=status.phase%21%3DRunning",
        "fieldSelector=spec.nodeName%3Da%5C%2Cstatus.phase%3Dx",
        "fieldSelector=status.phase%3D%ff",
    ] {
        assert_eq!(
            judge_get(&format!("{pods}?{query}")),
            Err(RULE_QUERY),
            "{query}"
        );
    }
}

#[test]
fn an_event_list_needs_the_pvc_field_selector() {
    let events = "/api/v1/namespaces/app/events";
    for query in [
        "&fieldSelector=involvedObject.kind%3DPersistentVolumeClaim&limit=500",
        "fieldSelector=involvedObject.kind%3D%3DPersistentVolumeClaim",
        "fieldSelector=involvedObject.name%3Dc%2CinvolvedObject.kind%3DPersistentVolumeClaim",
    ] {
        assert_eq!(judge_get(&format!("{events}?{query}")), Ok(()), "{query}");
    }
    for query in [
        "",
        "?",
        "?&limit=500",
        "?fieldSelector=involvedObject.kind%3DPod",
        "?fieldSelector=involvedObject.kind%3DPersistentVolumeClaims",
        "?fieldSelector=involvedObject.kind%21%3DPersistentVolumeClaim",
        "?fieldSelector=involvedObject.name%3DPersistentVolumeClaim",
        "?fieldSelector=reason%3DProvisioningFailed",
        "?labelSelector=involvedObject.kind%3DPersistentVolumeClaim",
    ] {
        assert_eq!(
            judge_get(&format!("{events}{query}")),
            Err(RULE_SELECTOR),
            "{query}"
        );
    }
}

#[test]
fn a_raw_semicolon_in_the_query_is_refused() {
    // Go's `URL.Query()` drops a pair that holds a raw `;`, so the server would list without the
    // selector that the guard saw.
    for uri in [
        "/api/v1/pods?&fieldSelector=status.phase%21%3DFailed;&limit=500",
        "/api/v1/pods?fieldSelector=status.phase%21%3DFailed;",
        "/api/v1/pods?fieldSelector=status.phase%21%3DFailed&limit=5;00",
        "/api/v1/namespaces/app/events?&fieldSelector=involvedObject.kind%3DPersistentVolumeClaim;&limit=500",
        "/api/v1/namespaces/app/events?fieldSelector=involvedObject.kind%3DPersistentVolumeClaim;x",
        "/api/v1/nodes?labelSelector=a;",
        "/api/v1/nodes?labelSelector=a%3Db;limit=5",
        "/api/v1/nodes?;",
    ] {
        assert_eq!(judge_get(uri), Err(RULE_QUERY), "{uri}");
    }
    // An encoded `;` is a byte in the value, decoded once after the split.
    assert_eq!(judge_get("/api/v1/nodes?labelSelector=a%3Bb"), Ok(()));
}

#[test]
fn lists_without_a_required_selector_and_gets_are_not_affected() {
    for path in [
        "/api/v1/nodes",
        "/api/v1/namespaces/app/persistentvolumeclaims",
        "/apis/storage.k8s.io/v1/storageclasses",
        "/apis/storage.k8s.io/v1/storageclasses/gp2",
        "/apis/apps/v1/namespaces/kube-system/deployments",
        "/api/v1/namespaces/app",
    ] {
        assert_eq!(judge_get(path), Ok(()), "{path}");
    }
}

#[test]
fn name_and_namespace_limits_are_kept() {
    // Deployments only in kube-system, and only the ClusterVersion called `version`.
    assert_eq!(
        judge_get("/apis/apps/v1/namespaces/kube-system/deployments"),
        Ok(())
    );
    assert_eq!(
        judge_get("/apis/apps/v1/namespaces/default/deployments"),
        Err(RULE_NOT_ALLOWED)
    );
    assert_eq!(
        judge_get("/apis/apps/v1/deployments"),
        Err(RULE_NOT_ALLOWED)
    );
    assert_eq!(
        judge_get("/apis/config.openshift.io/v1/clusterversions/version"),
        Ok(())
    );
    assert_eq!(
        judge_get("/apis/config.openshift.io/v1/clusterversions/other"),
        Err(RULE_NOT_ALLOWED)
    );
    assert_eq!(
        judge_get("/apis/config.openshift.io/v1/clusterversions"),
        Err(RULE_NOT_ALLOWED)
    );
    // A wrong version of a listed group is a different API.
    assert_eq!(
        judge_get("/apis/storage.k8s.io/v1beta1/storageclasses"),
        Err(RULE_NOT_ALLOWED)
    );
    assert_eq!(judge_get("/api/v2/nodes"), Err(RULE_NOT_ALLOWED));
}

#[test]
fn discovery_paths_pass_and_look_alikes_do_not() {
    for path in [
        "/version",
        "/api",
        "/apis",
        "/api/v1",
        "/apis/kyverno.io",
        "/apis/policies.kyverno.io/v1alpha1",
        "/apis/templates.gatekeeper.sh/v1beta1",
        "/apis/autoscaling/v2",
        "/apis/security.openshift.io",
    ] {
        assert_eq!(judge_get(path), Ok(()), "{path}");
    }
    for path in [
        "/healthz",
        "/readyz",
        "/metrics",
        "/openapi/v2",
        "/apis/Bad_Group/v1",
        "/apis/-bad.example/v1",
        "/apis/kyverno.io/1",
        "/apis/kyverno.io/v",
        "/apis/kyverno.io/v1gamma1",
        "/apis/kyverno.io/v1alpha",
        "/api/v1/",
        "/version/x",
    ] {
        assert!(judge_get(path).is_err(), "{path}");
    }
}

#[test]
fn the_path_pre_filter_refuses_anything_not_plain() {
    for path in [
        "/api/v1/nodes/",
        "/api//v1/nodes",
        "/api/v1/../v1/nodes",
        "/api/v1/./nodes",
        "/api/v1/nodes;x=1",
        "/api/v1/%6eodes",
        "/api/v1/nodes%2f",
        "/api/v1/n\u{e9}des",
        "/api/v1/nodes\\x",
        "/api/v1/no des",
    ] {
        // Not every one parses as a URI. Those that do must be refused.
        if let Ok(uri) = path.parse::<http::Uri>() {
            let verdict = judge(&Method::GET, &uri, &http::HeaderMap::new(), BodyView::Empty);
            assert_eq!(verdict, Err(RULE_PATH_SHAPE), "{path}");
        }
    }
    let long = format!("/api/v1/{}", "n".repeat(600));
    assert_eq!(judge_get(&long), Err(RULE_PATH_SHAPE));
    assert_eq!(
        judge_get("http://api.example/version"),
        Err(RULE_PATH_SHAPE)
    );
}

#[test]
fn only_four_query_keys_pass_with_plain_values() {
    let nodes = "/api/v1/nodes";
    for query in [
        "limit=500",
        "limit=500&continue=eyJhIjoxfQ",
        "labelSelector=kubernetes.io%2Fos%3Dlinux",
        "fieldSelector=status.phase%21%3DSucceeded%2Cstatus.phase%21%3DFailed",
        "fieldSelector=spec.nodeName%3Dnode-1&limit=100",
        // kube writes a `&` before the first parameter.
        "&limit=500&fieldSelector=status.phase%21%3DFailed",
    ] {
        assert_eq!(judge_get(&format!("{nodes}?{query}")), Ok(()), "{query}");
    }
    for query in [
        "watch=true",
        "watch=1&limit=5",
        "follow=true",
        "dryRun=All",
        "resourceVersion=0",
        "timeoutSeconds=5",
        "limit=",
        "limit=abc",
        "limit=1234567",
        "limit=5&&limit=6",
        "&&limit=5",
        "fieldSelector=a%zz",
        "fieldSelector=a%2",
        "LIMIT=5",
    ] {
        assert_eq!(
            judge_get(&format!("{nodes}?{query}")),
            Err(RULE_QUERY),
            "{query}"
        );
    }
}

#[test]
fn upgrade_and_impersonate_headers_are_refused() {
    let uri: http::Uri = "/api/v1/nodes".parse().expect("uri");
    for (name, value, rule) in [
        ("upgrade", "websocket", RULE_UPGRADE),
        ("connection", "Upgrade", RULE_UPGRADE),
        ("connection", "keep-alive, upgrade", RULE_UPGRADE),
        ("impersonate-user", "admin", RULE_IMPERSONATE),
        ("Impersonate-Group", "system:masters", RULE_IMPERSONATE),
        ("impersonate-extra-x", "y", RULE_IMPERSONATE),
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
            value.parse().expect("value"),
        );
        let verdict = judge(&Method::GET, &uri, &headers, BodyView::Empty);
        assert_eq!(verdict, Err(rule), "{name}");
    }
    // The three headers kube sets (and the length) pass.
    let mut headers = http::HeaderMap::new();
    headers.insert("accept", "application/json".parse().expect("value"));
    headers.insert("content-type", "application/json".parse().expect("value"));
    headers.insert("content-length", "0".parse().expect("value"));
    assert_eq!(judge(&Method::GET, &uri, &headers, BodyView::Empty), Ok(()));
}

/// One test per refused header, through the real layer: the request is refused with `rule`, never
/// reaches the server, and the log names the header and holds no value.
macro_rules! refused_header {
    ($test:ident, $name:expr, $rule:expr) => {
        #[tokio::test]
        async fn $test() {
            let rig = Rig::new();
            let sent = request(
                Method::GET,
                "/api/v1/nodes",
                &[($name, "canary-header-value")],
                Vec::new(),
            );
            assert_eq!(rig.send(sent).await, Err($rule));
            assert_eq!(rig.mock.seen(), Vec::<String>::new());
            let log = rig.log();
            assert_eq!(log.len(), 1);
            assert_eq!(log[0].outcome, ActionOutcome::Denied);
            assert_eq!(field(&log[0], "rule"), Some($rule));
            assert_eq!(
                field(&log[0], "header"),
                Some($name.to_ascii_lowercase().as_str())
            );
            let all = serde_json::to_string(&log).expect("json");
            assert!(!all.contains("canary-header-value"), "{all}");
        }
    };
}

refused_header!(authorization_is_refused, "Authorization", RULE_HEADER);
refused_header!(x_remote_user_is_refused, "X-Remote-User", RULE_HEADER);
refused_header!(x_remote_group_is_refused, "X-Remote-Group", RULE_HEADER);
refused_header!(
    x_http_method_override_is_refused,
    "X-HTTP-Method-Override",
    RULE_HEADER
);
refused_header!(host_is_refused, "Host", RULE_HEADER);
refused_header!(a_made_up_header_is_refused, "X-Anything", RULE_HEADER);
refused_header!(connection_keep_alive_is_refused, "Connection", RULE_HEADER);
refused_header!(
    impersonate_user_is_refused,
    "Impersonate-User",
    RULE_IMPERSONATE
);
refused_header!(
    impersonate_group_is_refused,
    "Impersonate-Group",
    RULE_IMPERSONATE
);
refused_header!(
    impersonate_uid_is_refused,
    "Impersonate-Uid",
    RULE_IMPERSONATE
);
refused_header!(
    impersonate_extra_is_refused,
    "Impersonate-Extra-Scopes",
    RULE_IMPERSONATE
);
refused_header!(upgrade_header_is_refused, "Upgrade", RULE_UPGRADE);

#[tokio::test]
async fn the_headers_kube_sets_pass_the_guard() {
    // kube sets `accept` (a metadata or discovery list) and `content-type` (every POST). Ask kube to
    // build requests with both and send them through the layer.
    let rig = Rig::new();
    let api = kube::Api::<k8s_openapi::api::core::v1::Node>::all(rig.client.clone());
    rig.mock
        .reply(json!({"apiVersion":"v1","kind":"NodeList","metadata":{},"items":[]}));
    api.list(&ListParams::default()).await.expect("list");
    rig.mock.reply(json!({"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","metadata":{},"spec":{},"status":{"allowed":true}}));
    let review = SelfSubjectAccessReview::default();
    let sent = kube::Api::<SelfSubjectAccessReview>::all(rig.client.clone())
        .create(&PostParams::default(), &review)
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    let discovery = request(
        Method::GET,
        "/apis/autoscaling/v2",
        &[(
            "accept",
            "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList",
        )],
        Vec::new(),
    );
    assert_eq!(rig.send(discovery).await, Ok(StatusCode::OK));
}

#[test]
fn a_get_with_a_body_is_refused() {
    let uri: http::Uri = "/api/v1/nodes".parse().expect("uri");
    for body in [BodyView::Bytes(b"{}"), BodyView::Opaque] {
        let verdict = judge(&Method::GET, &uri, &http::HeaderMap::new(), body);
        assert_eq!(verdict, Err(RULE_GET_BODY));
    }
}

#[test]
fn version_and_group_grammars() {
    for good in ["v1", "v2", "v10", "v1alpha1", "v2beta3", "v1beta12"] {
        assert!(rules_is_version(good), "{good}");
    }
    for bad in [
        "",
        "v",
        "1",
        "v1alpha",
        "v1gamma1",
        "V1",
        "v1beta",
        "v1alpha1x",
        "va1",
    ] {
        assert!(!rules_is_version(bad), "{bad}");
    }
}

fn rules_is_version(text: &str) -> bool {
    judge_get(&format!("/apis/kyverno.io/{text}")).is_ok()
}

// ---- the layer in front of the mock ---------------------------------------------------------------------

#[tokio::test]
async fn kube_builds_its_requests_in_a_shape_the_guard_allows() {
    let rig = Rig::new();
    let nodes = rig.client.clone();

    rig.mock
        .reply(json!({"apiVersion":"v1","kind":"NodeList","metadata":{},"items":[]}));
    let api = kube::Api::<Node>::all(nodes.clone());
    let params = ListParams::default()
        .limit(500)
        .fields("status.phase!=Succeeded,status.phase!=Failed")
        .labels("kubernetes.io/os=linux");
    api.list(&params).await.expect("node list");
    api.list(&ListParams::default().continue_token("abc"))
        .await
        .expect("next page");

    rig.mock
        .reply(json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}));
    kube::Api::<Namespace>::all(nodes.clone())
        .get("app")
        .await
        .expect("namespace get");

    rig.mock.reply(json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"name":"gp2"},"provisioner":"p"}));
    kube::Api::<StorageClass>::all(nodes.clone())
        .get("gp2")
        .await
        .expect("storageclass get");

    rig.mock.reply(json!({"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","metadata":{},"spec":{},"status":{"allowed":true}}));
    let review = SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some("create".to_owned()),
                resource: Some("namespaces".to_owned()),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        ..SelfSubjectAccessReview::default()
    };
    kube::Api::<SelfSubjectAccessReview>::all(nodes)
        .create(&PostParams::default(), &review)
        .await
        .expect("access review");

    let seen = rig.mock.seen();
    assert_eq!(seen.len(), 5, "{seen:?}");
    assert!(seen[0].starts_with("GET /api/v1/nodes?"), "{seen:?}");
    assert!(
        seen[2].starts_with("GET /api/v1/namespaces/app"),
        "{seen:?}"
    );
    assert!(
        seen[4].starts_with("POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews"),
        "{seen:?}"
    );
}

#[tokio::test]
async fn every_write_is_refused_and_never_reaches_the_server() {
    let rig = Rig::new();
    let pods = kube::Api::<Pod>::namespaced(rig.client.clone(), "app");
    let nodes = kube::Api::<Node>::all(rig.client.clone());

    let outcomes = [
        refusal_of(pods.delete("p", &DeleteParams::default()).await),
        refusal_of(
            pods.delete_collection(&DeleteParams::default(), &ListParams::default())
                .await,
        ),
        refusal_of(
            pods.patch("p", &PatchParams::default(), &Patch::Merge(json!({"a": 1})))
                .await,
        ),
        refusal_of(
            pods.replace("p", &PostParams::default(), &Pod::default())
                .await,
        ),
        refusal_of(pods.create(&PostParams::default(), &Pod::default()).await),
        refusal_of(
            pods.create(
                &PostParams {
                    dry_run: true,
                    ..PostParams::default()
                },
                &Pod::default(),
            )
            .await,
        ),
        refusal_of(nodes.delete("n1", &DeleteParams::default()).await),
        refusal_of(
            nodes
                .patch_status("n1", &PatchParams::default(), &Patch::Merge(json!({})))
                .await,
        ),
    ];
    assert_eq!(
        outcomes,
        [
            RULE_METHOD,
            RULE_METHOD,
            RULE_METHOD,
            RULE_METHOD,
            RULE_POST_TARGET,
            RULE_POST_TARGET,
            RULE_METHOD,
            RULE_METHOD,
        ]
    );
    for method in [
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::HEAD,
        Method::OPTIONS,
        Method::CONNECT,
        Method::TRACE,
    ] {
        let verdict = rig
            .send(request(method.clone(), "/api/v1/nodes", &[], Vec::new()))
            .await;
        assert_eq!(verdict, Err(RULE_METHOD), "{method}");
    }
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
}

fn refusal_of<T>(result: Result<T, kube::Error>) -> &'static str {
    match result {
        Ok(_) => "was allowed",
        Err(error) => refusal(&error).unwrap_or("failed for another reason"),
    }
}

#[tokio::test]
async fn a_post_goes_only_to_the_three_reviews_with_no_query_and_the_fixed_body() {
    let rig = Rig::new();
    let post = |uri: &str, body: &[u8]| {
        request(
            Method::POST,
            uri,
            &[("content-type", "application/json")],
            body.to_vec(),
        )
    };
    let ssr = "/apis/authentication.k8s.io/v1/selfsubjectreviews";

    // The three reviews pass.
    assert_eq!(
        rig.send(post(ssr, SELF_SUBJECT_REVIEW_BODY)).await,
        Ok(StatusCode::OK)
    );
    assert_eq!(
        rig.send(post(&format!("{ssr}?"), SELF_SUBJECT_REVIEW_BODY))
            .await,
        Ok(StatusCode::OK)
    );
    let ssar =
        br#"{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{}}"#;
    for resource in ["selfsubjectaccessreviews", "selfsubjectrulesreviews"] {
        let uri = format!("/apis/authorization.k8s.io/v1/{resource}");
        assert_eq!(
            rig.send(post(&uri, ssar)).await,
            Ok(StatusCode::OK),
            "{resource}"
        );
    }
    assert_eq!(rig.mock.seen().len(), 4);

    // A SelfSubjectReview with another body, a query string, or another version is refused.
    let other: &[&[u8]] = &[
        br#"{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","metadata":{}}"#,
        br#"{"apiVersion":"authentication.k8s.io/v1", "kind":"SelfSubjectReview"}"#,
        br#"{"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1"}"#,
        br#"{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"} "#,
        b"{}",
        b"",
    ];
    for body in other {
        assert_eq!(
            rig.send(post(ssr, body)).await,
            Err(RULE_REVIEW_BODY),
            "{body:?}"
        );
    }
    assert_eq!(
        rig.send(post(&format!("{ssr}?dryRun=All"), SELF_SUBJECT_REVIEW_BODY))
            .await,
        Err(RULE_POST_QUERY)
    );
    assert_eq!(
        rig.send(post(
            "/apis/authentication.k8s.io/v1beta1/selfsubjectreviews",
            SELF_SUBJECT_REVIEW_BODY
        ))
        .await,
        Err(RULE_POST_TARGET)
    );
    assert_eq!(
        rig.send(post(
            "/apis/authentication.k8s.io/v1alpha1/selfsubjectreviews",
            SELF_SUBJECT_REVIEW_BODY
        ))
        .await,
        Err(RULE_POST_TARGET)
    );

    // An access review with a query string or no usable body is refused.
    let ssar_uri = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";
    assert_eq!(
        rig.send(post(&format!("{ssar_uri}?dryRun=All"), ssar))
            .await,
        Err(RULE_POST_QUERY)
    );
    assert_eq!(rig.send(post(ssar_uri, b"")).await, Err(RULE_BODY));
    assert_eq!(
        rig.send(post(ssar_uri, &vec![b' '; 64 * 1024 + 1])).await,
        Err(RULE_BODY)
    );

    // Every other POST is refused: pods, the reviews' neighbours, subresources, other groups.
    for uri in [
        "/api/v1/namespaces/app/pods",
        "/api/v1/namespaces/app/pods?dryRun=All",
        "/api/v1/namespaces/app/pods/p/exec",
        "/api/v1/namespaces/app/pods/p/eviction",
        "/api/v1/namespaces/app/pods/p/binding",
        "/api/v1/namespaces/app/serviceaccounts/sa/token",
        "/api/v1/namespaces",
        "/apis/authorization.k8s.io/v1/localsubjectaccessreviews",
        "/apis/authorization.k8s.io/v1/subjectaccessreviews",
        "/apis/authorization.k8s.io/v1/namespaces/app/localsubjectaccessreviews",
        "/apis/authentication.k8s.io/v1/tokenreviews",
        "/apis/authentication.k8s.io/v1/tokenrequests",
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews/x",
        "/version",
    ] {
        assert_eq!(
            rig.send(post(uri, b"{}")).await,
            Err(RULE_POST_TARGET),
            "{uri}"
        );
    }
    assert_eq!(rig.mock.seen().len(), 4, "{:?}", rig.mock.seen());
}

#[tokio::test]
async fn a_typed_self_subject_review_does_not_match_the_fixed_body() {
    // k8s-openapi writes `metadata` into a default review, so it is not the fixed body. The identity
    // call (M1-105) must send SELF_SUBJECT_REVIEW_BODY, not a typed value.
    let rig = Rig::new();
    let api = kube::Api::<SelfSubjectReview>::all(rig.client.clone());
    let result = api
        .create(&PostParams::default(), &SelfSubjectReview::default())
        .await;
    let sent = serde_json::to_vec(&SelfSubjectReview::default()).expect("json");
    assert_ne!(sent, SELF_SUBJECT_REVIEW_BODY);
    assert_eq!(refusal_of(result), RULE_REVIEW_BODY);
    assert!(rig.mock.seen().is_empty());
}

#[test]
fn a_body_the_guard_cannot_read_is_refused() {
    // kube builds every body from a `Vec`, so this is a request that did not come from kube's builders.
    let post = |path: &str, body| {
        let uri: http::Uri = path.parse().expect("uri");
        judge(&Method::POST, &uri, &http::HeaderMap::new(), body)
    };
    assert_eq!(
        post(
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            BodyView::Opaque
        ),
        Err(RULE_REVIEW_BODY)
    );
    assert_eq!(
        post(
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            BodyView::Opaque
        ),
        Err(RULE_BODY)
    );
}

#[test]
fn a_body_is_read_without_being_consumed() {
    let body = Body::from(b"{\"a\":1}".to_vec());
    assert_eq!(read_body(&body).as_deref(), Some(b"{\"a\":1}".as_slice()));
    // The request still has its bytes.
    assert_eq!(read_body(&body).as_deref(), Some(b"{\"a\":1}".as_slice()));
    assert_eq!(read_body(&Body::empty()).as_deref(), Some(b"".as_slice()));
}

#[tokio::test]
async fn secrets_are_refused_in_every_position() {
    let rig = Rig::new();
    let secrets = kube::Api::<Secret>::namespaced(rig.client.clone(), "app");
    let all = kube::Api::<Secret>::all(rig.client.clone());
    assert_eq!(
        refusal_of(secrets.list(&ListParams::default()).await),
        RULE_SECRETS
    );
    assert_eq!(refusal_of(secrets.get("token").await), RULE_SECRETS);
    assert_eq!(
        refusal_of(all.list(&ListParams::default()).await),
        RULE_SECRETS
    );
    assert_eq!(
        refusal_of(secrets.delete("token", &DeleteParams::default()).await),
        RULE_METHOD
    );

    for path in [
        "/api/v1/secrets",
        "/api/v1/namespaces/app/secrets",
        "/api/v1/namespaces/app/secrets/token",
        "/api/v1/namespaces/secrets/pods",
        "/api/v1/nodes/secrets",
        "/apis/secrets/v1",
        "/apis/storage.k8s.io/v1/secrets",
        "/apis/storage.k8s.io/v1/storageclasses/secrets",
        "/apis/secrets",
        "/secrets",
    ] {
        assert_eq!(rig.get(path).await, Err(RULE_SECRETS), "{path}");
    }
    let post = request(
        Method::POST,
        "/api/v1/namespaces/app/secrets",
        &[],
        b"{}".to_vec(),
    );
    assert_eq!(rig.send(post).await, Err(RULE_SECRETS));
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
}

#[tokio::test]
async fn unlisted_resources_subresources_and_hostile_requests_are_refused() {
    let rig = Rig::new();
    for (uri, rule) in [
        ("/api/v1/configmaps", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/configmaps", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/serviceaccounts", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/pods", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/pods/p", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/pods/p/log", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/pods/p/exec", RULE_NOT_ALLOWED),
        ("/api/v1/nodes/n1", RULE_NOT_ALLOWED),
        ("/api/v1/nodes/n1/proxy", RULE_NOT_ALLOWED),
        ("/api/v1/nodes/n1/status", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/finalize", RULE_NOT_ALLOWED),
        ("/api/v1/namespaces/app/status", RULE_NOT_ALLOWED),
        (
            "/api/v1/namespaces/app/persistentvolumeclaims/c",
            RULE_NOT_ALLOWED,
        ),
        ("/api/v1/namespaces/app/nodes", RULE_NOT_ALLOWED),
        (
            "/apis/rbac.authorization.k8s.io/v1/clusterroles",
            RULE_NOT_ALLOWED,
        ),
        (
            "/apis/apps/v1/namespaces/kube-system/deployments/x",
            RULE_NOT_ALLOWED,
        ),
        (
            "/apis/apps/v1/namespaces/kube-system/deployments/x/scale",
            RULE_NOT_ALLOWED,
        ),
        ("/api/v1/nodes?watch=true", RULE_QUERY),
        ("/api/v1/nodes?dryRun=All", RULE_QUERY),
        ("/api/v1/%73ecrets", RULE_PATH_SHAPE),
        ("/api/v1/namespaces/app/%73ecrets", RULE_PATH_SHAPE),
        ("/api/v1/nodes/../secrets", RULE_PATH_SHAPE),
        ("/api/v1/nodes/", RULE_PATH_SHAPE),
    ] {
        assert_eq!(rig.get(uri).await, Err(rule), "{uri}");
    }
    let upgrade = request(
        Method::GET,
        "/api/v1/namespaces/app/pods/p/exec",
        &[("connection", "Upgrade"), ("upgrade", "SPDY/3.1")],
        Vec::new(),
    );
    assert_eq!(rig.send(upgrade).await, Err(RULE_UPGRADE));
    let impersonate = request(
        Method::GET,
        "/api/v1/nodes",
        &[("impersonate-user", "admin")],
        Vec::new(),
    );
    assert_eq!(rig.send(impersonate).await, Err(RULE_IMPERSONATE));
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
}

#[tokio::test]
async fn a_refusal_is_a_fixed_error_that_holds_no_request_text() {
    let rig = Rig::new();
    let uri = "/api/v1/namespaces/canary-ns/secrets/canary-name?fieldSelector=canary-value";
    let error = rig
        .client
        .send(request(Method::GET, uri, &[], Vec::new()))
        .await
        .expect_err("refused");
    let shown = format!("{error} {error:?}");
    assert!(shown.contains(RULE_SECRETS), "{shown}");
    assert!(shown.contains("Fix:"), "{shown}");
    for canary in ["canary-ns", "canary-name", "canary-value"] {
        assert!(!shown.contains(canary), "{shown}");
    }
    // The error maps to a refusal whose hint says to report it. A refusal repeats, so "run again" is wrong.
    let mapped = crate::client::error::from_kube_error(&error, "https://s", None, false, true);
    assert!(
        matches!(
            mapped,
            crate::client::KubeError::Refused { late: false, .. }
        ),
        "{mapped:?}"
    );
    let hint = mapped.hint();
    assert!(
        hint.contains("bug") && hint.contains("action log"),
        "{hint}"
    );
    assert!(
        !hint.contains("again") || hint.contains("will not help"),
        "{hint}"
    );
}

#[test]
fn a_call_after_its_check_ended_has_its_own_text_and_hint() {
    for rule in [RULE_CHECK_FINISHED] {
        let late = GuardError { rule };
        assert!(late.is_late(), "{rule}");
        let text = late.to_string();
        assert!(
            text.contains(rule) && text.contains("after its check ended"),
            "{text}"
        );
        assert!(!text.contains("Secrets"), "{text}");
        let error = kube::Error::Service(Box::new(late));
        let mapped = crate::client::error::from_kube_error(&error, "https://s", None, false, true);
        assert!(
            matches!(mapped, crate::client::KubeError::Refused { late: true, .. }),
            "{mapped:?}"
        );
        let hint = mapped.hint();
        assert!(
            hint.contains("after it ended") && hint.contains("action log"),
            "{hint}"
        );
    }
    assert!(!GuardError { rule: RULE_SECRETS }.is_late());
    // A closed probe is not a late call: it is a client built without a probe.
    let closed = GuardError {
        rule: RULE_NO_PROBE,
    };
    assert!(!closed.is_late());
    assert!(!closed.to_string().contains("after its check ended"));
}

// ---- the fixture run (INV-14) -----------------------------------------------------------------------------

/// A request a check makes, as `(method, uri, body)`.
type Call = (&'static str, &'static str, &'static [u8]);

const SSAR_BODY: &[u8] = br#"{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"namespaces"}}}"#;
const SSR: &str = "/apis/authentication.k8s.io/v1/selfsubjectreviews";
const SSAR: &str = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";
const SSRR: &str = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews";
const PHASE: &str = "fieldSelector=status.phase%21%3DSucceeded%2Cstatus.phase%21%3DFailed";

/// Every API call the M1 checks make, from 03 and 02 Appendix B, one list per check. The checks are not
/// built yet (M1-104 onward), so these are the calls the design says each one sends, written as the
/// requests kube builds. M1-105 replaces them with the real checks over the mock harness.
fn calls_of(check: &str) -> Vec<Call> {
    let get = |uri| ("GET", uri, &b""[..]);
    match check {
        "k8s.access" => vec![
            get("/version"),
            get("/api"),
            get("/apis"),
            ("POST", SSR, SELF_SUBJECT_REVIEW_BODY),
            ("POST", SSAR, SSAR_BODY),
        ],
        "k8s.version" => vec![
            get("/version"),
            get("/apis/autoscaling/v2"),
            get("/apis/networking.k8s.io/v1"),
            get("/api/v1/nodes?&limit=500"),
            get("/apis/config.openshift.io/v1/clusterversions/version"),
        ],
        "k8s.storageclass" => vec![
            get("/api/v1/namespaces/app"),
            get("/apis/storage.k8s.io/v1/storageclasses?&limit=500"),
            get("/apis/storage.k8s.io/v1/storageclasses/gp2"),
            get("/apis/storage.k8s.io/v1/csinodes?&limit=500"),
            get("/apis/storage.k8s.io/v1/csidrivers?&limit=500"),
            get("/api/v1/namespaces/app/persistentvolumeclaims?&limit=500"),
            get(
                "/api/v1/namespaces/app/events?&fieldSelector=involvedObject.kind%3DPersistentVolumeClaim&limit=500",
            ),
        ],
        "k8s.rbac" => vec![
            ("POST", SSR, SELF_SUBJECT_REVIEW_BODY),
            ("POST", SSAR, SSAR_BODY),
            ("POST", SSAR, SSAR_BODY),
            ("POST", SSRR, SSAR_BODY),
            get("/api/v1/namespaces/app"),
        ],
        "k8s.admission" => vec![
            get("/api/v1/namespaces/app"),
            get("/apis/kyverno.io"),
            get("/apis/policies.kyverno.io"),
            get("/apis/templates.gatekeeper.sh"),
            get("/apis/constraints.gatekeeper.sh"),
            get("/apis/security.openshift.io"),
            get("/apis/security.openshift.io/v1/securitycontextconstraints"),
        ],
        "k8s.nodes" => vec![
            get("/api/v1/nodes?&limit=500"),
            get(pods_uri()),
            get("/api/v1/pods?&fieldSelector=spec.nodeName%3Dn1%2Cstatus.phase%21%3DFailed"),
            get("/apis/karpenter.sh"),
            get("/apis/karpenter.k8s.aws"),
            get("/apis/apps/v1/namespaces/kube-system/deployments?&limit=500"),
        ],
        other => panic!("no calls for {other}"),
    }
}

fn pods_uri() -> &'static str {
    // `PHASE` is the selector 03 gives for the pod list. Built once so the test table stays readable.
    static URI: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URI.get_or_init(|| format!("/api/v1/pods?&{PHASE}&limit=500"))
}

/// What a faulty or hostile check could try. Each is refused, from any check.
fn hostile_calls() -> Vec<(Call, &'static str)> {
    vec![
        (
            ("DELETE", "/api/v1/namespaces/app/pods/p", b""),
            RULE_METHOD,
        ),
        (("PATCH", "/api/v1/nodes/n1", b"{}"), RULE_METHOD),
        (
            ("PUT", "/apis/storage.k8s.io/v1/storageclasses/gp2", b"{}"),
            RULE_METHOD,
        ),
        (
            ("POST", "/api/v1/namespaces/app/pods", b"{}"),
            RULE_POST_TARGET,
        ),
        (
            ("POST", "/api/v1/namespaces/app/pods?dryRun=All", b"{}"),
            RULE_POST_TARGET,
        ),
        (
            (
                "POST",
                "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                b"{}",
            ),
            RULE_REVIEW_BODY,
        ),
        (
            (
                "POST",
                "/apis/authentication.k8s.io/v1/selfsubjectreviews?dryRun=All",
                SELF_SUBJECT_REVIEW_BODY,
            ),
            RULE_POST_QUERY,
        ),
        (("GET", "/api/v1/namespaces/app/secrets", b""), RULE_SECRETS),
        (("GET", "/api/v1/secrets?limit=1", b""), RULE_SECRETS),
        (
            ("GET", "/api/v1/namespaces/app/configmaps", b""),
            RULE_NOT_ALLOWED,
        ),
        (
            ("GET", "/api/v1/namespaces/app/pods/p/log", b""),
            RULE_NOT_ALLOWED,
        ),
        (("GET", "/api/v1/nodes?watch=true", b""), RULE_QUERY),
    ]
}

#[tokio::test]
async fn a_full_fixture_run_reaches_the_server_with_only_allowlisted_requests() {
    // INV-14 and the M1-103 exit test. Six checks, each with its own client and probe over one mock
    // server. Each check also makes the hostile calls. The server must see exactly the allowed calls,
    // in order, and the log must hold one entry per call.
    let checks = [
        "k8s.access",
        "k8s.version",
        "k8s.storageclass",
        "k8s.rbac",
        "k8s.admission",
        "k8s.nodes",
    ];
    let run = TestRun::new(Replay::new());
    let mock = Mock::default();
    let mut expected_seen = Vec::new();
    let mut expected_log = Vec::new();

    // The run itself asks for the version first, with no check id.
    let boot = Rig::for_check(&run, &mock, None);
    assert_eq!(boot.get("/version").await, Ok(StatusCode::OK));
    expected_seen.push("GET /version".to_owned());
    expected_log.push((
        None,
        ActionOutcome::Ok,
        "GET".to_owned(),
        "/version".to_owned(),
    ));

    for check in checks {
        let rig = Rig::for_check(&run, &mock, Some(check));
        for (method, uri, body) in calls_of(check) {
            let method = Method::from_bytes(method.as_bytes()).expect("method");
            let sent = rig
                .send(request(method.clone(), uri, &[], body.to_vec()))
                .await;
            assert_eq!(sent, Ok(StatusCode::OK), "{check}: {method} {uri}");
            expected_seen.push(format!("{method} {uri}"));
            let path = uri.split('?').next().unwrap_or(uri).to_owned();
            expected_log.push((
                Some(check.to_owned()),
                ActionOutcome::Ok,
                method.to_string(),
                path,
            ));
        }
        for ((method, uri, body), rule) in hostile_calls() {
            let method = Method::from_bytes(method.as_bytes()).expect("method");
            let sent = rig
                .send(request(method.clone(), uri, &[], body.to_vec()))
                .await;
            assert_eq!(sent, Err(rule), "{check}: {method} {uri}");
            let path = uri.split('?').next().unwrap_or(uri).to_owned();
            expected_log.push((
                Some(check.to_owned()),
                ActionOutcome::Denied,
                method.to_string(),
                path,
            ));
        }
        let upgrade = request(
            Method::GET,
            "/api/v1/namespaces/app/pods/p/exec",
            &[("connection", "Upgrade"), ("upgrade", "SPDY/3.1")],
            Vec::new(),
        );
        assert_eq!(rig.send(upgrade).await, Err(RULE_UPGRADE));
        expected_log.push((
            Some(check.to_owned()),
            ActionOutcome::Denied,
            "GET".to_owned(),
            "/api/v1/namespaces/app/pods/p/exec".to_owned(),
        ));
    }

    // The server saw the allowed calls and nothing else, in order. Every allowed call was sent and
    // answered above, and every hostile call was refused with its own rule, so this equality is the
    // proof that only allowlisted requests reached the socket.
    assert_eq!(mock.seen(), expected_seen);

    // One log entry per call, in order, under the right check, with no query string in any path.
    let log = run.action_log().actions;
    let got: Vec<_> = log
        .iter()
        .map(|a| {
            (
                a.check.clone(),
                a.outcome.clone(),
                field(a, "method").unwrap_or_default().to_owned(),
                field(a, "path").unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(got, expected_log);
    assert!(log.iter().all(|a| a.kind == ActionKind::Kube));
    assert!(
        log.iter()
            .all(|a| !field(a, "path").unwrap_or_default().contains('?'))
    );
}

// ---- the action log -------------------------------------------------------------------------------------

#[tokio::test]
async fn every_request_writes_one_entry_under_its_check() {
    let rig = Rig::new();
    let post = request(
        Method::POST,
        "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        &[],
        SELF_SUBJECT_REVIEW_BODY.to_vec(),
    );
    assert_eq!(rig.send(post).await, Ok(StatusCode::OK));
    assert_eq!(
        rig.get("/api/v1/nodes?fieldSelector=canary-selector&limit=5")
            .await,
        Ok(StatusCode::OK)
    );
    assert_eq!(
        rig.get("/api/v1/namespaces/app/secrets").await,
        Err(RULE_SECRETS)
    );
    let delete = request(Method::DELETE, "/api/v1/nodes", &[], Vec::new());
    assert_eq!(rig.send(delete).await, Err(RULE_METHOD));

    let log = rig.log();
    assert_eq!(log.len(), 4, "one entry per request");
    let seen: Vec<_> = log
        .iter()
        .map(|a| (a.kind.clone(), a.outcome.clone(), a.check.as_deref()))
        .collect();
    assert_eq!(
        seen,
        [
            (ActionKind::Kube, ActionOutcome::Ok, Some("k8s.nodes")),
            (ActionKind::Kube, ActionOutcome::Ok, Some("k8s.nodes")),
            (ActionKind::Kube, ActionOutcome::Denied, Some("k8s.nodes")),
            (ActionKind::Kube, ActionOutcome::Denied, Some("k8s.nodes")),
        ]
    );
    assert_eq!(field(&log[0], "method"), Some("POST"));
    assert_eq!(
        field(&log[0], "path"),
        Some("/apis/authentication.k8s.io/v1/selfsubjectreviews")
    );
    assert_eq!(log[0].fields["status"], 200);
    // The path has no query string, and the log holds no selector and no body.
    assert_eq!(field(&log[1], "path"), Some("/api/v1/nodes"));
    assert_eq!(field(&log[2], "rule"), Some(RULE_SECRETS));
    assert_eq!(field(&log[3], "rule"), Some(RULE_METHOD));
    let all = serde_json::to_string(&log).expect("json");
    assert!(
        !all.contains("canary-selector") && !all.contains("SelfSubjectReview\""),
        "{all}"
    );
}

#[tokio::test]
async fn a_server_error_is_logged_as_failed_with_its_status() {
    let run = TestRun::new(Replay::new());
    let mock = Mock {
        status: StatusCode::FORBIDDEN,
        ..Mock::default()
    };
    let rig = Rig::for_check(&run, &mock, Some("k8s.version"));
    assert_eq!(rig.get("/version").await, Ok(StatusCode::FORBIDDEN));
    let log = run.action_log().actions;
    assert_eq!(log[0].outcome, ActionOutcome::Failed);
    assert_eq!(log[0].fields["status"], 403);
    assert_eq!(log[0].check.as_deref(), Some("k8s.version"));
    // A failed entry always has a fixed `error` (01 section 5.4).
    assert_eq!(
        field(&log[0], "error"),
        Some("the server answered with an error status")
    );
}

#[tokio::test]
async fn a_redirect_is_logged_as_failed_because_it_is_not_followed() {
    let run = TestRun::new(Replay::new());
    let mock = Mock {
        status: StatusCode::FOUND,
        ..Mock::default()
    };
    let rig = Rig::for_check(&run, &mock, Some("k8s.version"));
    assert_eq!(rig.get("/version").await, Ok(StatusCode::FOUND));
    let log = run.action_log().actions;
    assert_eq!(log[0].outcome, ActionOutcome::Failed);
    assert_eq!(log[0].fields["status"], 302);
    assert!(
        field(&log[0], "error").is_some_and(|error| error.contains("redirect")),
        "{:?}",
        log[0].fields
    );
}

#[tokio::test]
async fn a_request_dropped_in_flight_leaves_a_timeout_entry_with_its_check() {
    let run = TestRun::new(Replay::new());
    let mock = Mock {
        hang: true,
        ..Mock::default()
    };
    let rig = Rig::for_check(&run, &mock, Some("k8s.access"));
    let sent = tokio::time::timeout(Duration::from_millis(100), rig.get("/api/v1/nodes")).await;
    assert!(sent.is_err(), "the mock never answers");

    let log = run.action_log().actions;
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].kind, ActionKind::Kube);
    assert_eq!(log[0].outcome, ActionOutcome::Timeout);
    assert_eq!(log[0].check.as_deref(), Some("k8s.access"));
    assert_eq!(field(&log[0], "path"), Some("/api/v1/nodes"));
}

#[tokio::test]
async fn a_run_level_request_logs_no_check() {
    let run = TestRun::new(Replay::new());
    let rig = Rig::for_check(&run, &Mock::default(), None);
    assert_eq!(rig.get("/version").await, Ok(StatusCode::OK));
    assert_eq!(run.action_log().actions[0].check, None);
}
