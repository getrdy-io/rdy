//! Tests of the parts of the mock harness that `k8s.rbac` (M1-111) added: the rules table, the recorded
//! POST fallback, the impersonating client and the audit of `Impersonate-User`.

use http::Method;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
    SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
};
use kube::api::{ObjectMeta, PostParams};
use rdy_engine::testing::{Fixture, TestRun};
use serde_json::json;

use super::*;

const AS_USER: &str = "system:serviceaccount:app:other";
const TWO_DENIED: &str = "checks/k8s.rbac/two-denied";
const AS_CASE: &str = "checks/k8s.rbac/as-allowed";
const REVIEWS_FORBIDDEN: &str = "checks/k8s.rbac/reviews-forbidden";

fn access(verb: &str, resource: &str) -> SelfSubjectAccessReview {
    SelfSubjectAccessReview {
        metadata: ObjectMeta::default(),
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some(verb.to_owned()),
                resource: Some(resource.to_owned()),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        status: None,
    }
}

fn rules(namespace: &str) -> SelfSubjectRulesReview {
    SelfSubjectRulesReview {
        metadata: ObjectMeta::default(),
        spec: SelfSubjectRulesReviewSpec {
            namespace: Some(namespace.to_owned()),
        },
        status: None,
    }
}

/// Sends a request straight to the mock, with no guard in front.
async fn raw(mock: &Mock, method: Method, uri: &str, headers: &[(&str, &str)], body: &[u8]) -> u16 {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Body::from(body.to_vec())).expect("request");
    let mut mock = mock.clone();
    mock.call(request)
        .await
        .expect("the mock cannot fail")
        .status()
        .as_u16()
}

fn user() -> ImpersonateAs {
    ImpersonateAs::new("system:serviceaccount:acme-system:installer").expect("a valid user")
}

#[tokio::test]
async fn a_rules_review_is_answered_from_the_rules_table() {
    let harness = Harness::load(TWO_DENIED).expect("loads");
    let client = harness.client_for("k8s.rbac");
    let answered = client
        .all::<SelfSubjectRulesReview>()
        .create(&PostParams::default(), &rules("acme-system"))
        .await
        .expect("a row for the namespace");
    let status = answered.status.expect("a status");
    assert!(!status.incomplete);
    assert_eq!(status.resource_rules.len(), 2);
    // A namespace with no row is a request the fixture cannot answer.
    let error = client
        .all::<SelfSubjectRulesReview>()
        .create(&PostParams::default(), &rules("elsewhere"))
        .await
        .expect_err("no row");
    assert!(matches!(error, kube::Error::Api(status) if status.code == 501));
    assert_eq!(
        harness.mock().unrecorded(),
        ["POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews?"]
    );
    // The audit reports the unanswered request, which is the point of a table.
    let violations = harness.audit().expect_err("unanswered");
    assert!(
        violations.iter().any(|v| v.contains("no answer")),
        "{violations:?}"
    );
}

#[tokio::test]
async fn a_review_with_no_row_falls_back_to_a_recorded_post() {
    let harness = Harness::load(REVIEWS_FORBIDDEN).expect("loads");
    let client = harness.client_for("k8s.rbac");
    let error = client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("create", "namespaces"))
        .await
        .expect_err("the fixture refuses every review");
    assert!(matches!(error, kube::Error::Api(status) if status.code == 403));
    harness.audit().expect("a recorded answer is an answer");
}

#[test]
fn a_rules_row_needs_a_boolean_incomplete_and_unknown_keys_are_refused() {
    let cases = [
        (
            r#"{"access":[],"rules":[{"spec":{"namespace":"a"},"status":{}}]}"#,
            "boolean `incomplete`",
        ),
        (
            r#"{"access":[],"rules":[{"spec":{"namespace":"a"},"status":{"incomplete":"no"}}]}"#,
            "boolean `incomplete`",
        ),
        (r#"{"access":[],"rules":{"a":1}}"#, "`rules` must be a list"),
        (
            r#"{"access":[],"rules":[],"extra":[]}"#,
            "unknown key `extra`",
        ),
        (
            r#"{"access":[],"rules":[{"spec":{"namespace":"a"},"status":{"incomplete":false}},{"spec":{"namespace":"a"},"status":{"incomplete":true}}]}"#,
            "two rows have the spec",
        ),
    ];
    for (table, reason) in cases {
        let value: serde_json::Value = serde_json::from_str(table).expect("JSON");
        let error = parse_rules(&value).expect_err("refused");
        assert!(
            matches!(&error, MockError::BadReviews(text) if text.contains(reason)),
            "{table}: {error}"
        );
    }
    // A table with no `rules` list has no rules rows, and still parses.
    let value = json!({"access": []});
    assert!(parse_rules(&value).expect("parses").is_empty());
}

#[tokio::test]
async fn an_impersonating_client_passes_the_audit_and_its_entries_are_marked() {
    let harness = Harness::load(AS_CASE).expect("loads");
    let ctx = harness
        .run()
        .context("k8s.rbac", Os::Linux, [Need::KubeContext]);
    let client = harness.client_as(ctx.probe(), user()).expect("a client");
    client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("create", "namespaces"))
        .await
        .expect("the row");
    // The request reached the mock with the header, once, and the log entry says so.
    let seen = harness.mock().seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].headers.get_all("impersonate-user").iter().count(),
        1
    );
    assert_eq!(
        seen[0].headers["impersonate-user"],
        "system:serviceaccount:acme-system:installer"
    );
    let log = harness.run().action_log().actions;
    assert_eq!(log[0].fields["impersonated"], true);
    harness.audit().expect("clean");
}

#[tokio::test]
async fn an_impersonating_client_records_the_proxy_it_goes_through() {
    let harness = Harness::load(AS_CASE)
        .expect("loads")
        .via_proxy("http://proxy.test:3128");
    let ctx = harness
        .run()
        .context("k8s.rbac", Os::Linux, [Need::KubeContext]);
    let client = harness.client_as(ctx.probe(), user()).expect("a client");
    client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("create", "namespaces"))
        .await
        .expect("the row");
    let log = harness.run().action_log().actions;
    assert_eq!(log[0].fields["via_proxy"], "http://proxy.test:3128");
    assert_eq!(log[0].fields["impersonated"], true);
    harness.audit().expect("clean");
}

#[tokio::test]
async fn a_request_whose_header_and_log_entry_disagree_fails_the_run() {
    let harness = Harness::load(AS_CASE).expect("loads");
    let ctx = harness
        .run()
        .context("k8s.rbac", Os::Linux, [Need::KubeContext]);
    // A request reaches the mock with no header, as if something sent it without the layer, before the
    // guarded one that is impersonated and logged so. The only sent entry for the path says "impersonated",
    // so the first request has no entry that agrees with it.
    let client = harness.client_as(ctx.probe(), user()).expect("a client");
    let body = serde_json::to_vec(&access("create", "namespaces")).expect("JSON");
    let status = raw(
        harness.mock(),
        Method::POST,
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        &[("content-type", "application/json")],
        &body,
    )
    .await;
    assert_eq!(status, 201);
    client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("create", "namespaces"))
        .await
        .expect("the row");
    let violations = harness.audit().expect_err("the first request is unguarded");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("disagrees about Impersonate-User")),
        "{violations:?}"
    );
}

#[tokio::test]
async fn a_header_on_a_run_with_no_as_user_is_refused_by_the_audit() {
    let harness = Harness::load(AS_CASE).expect("loads");
    let body = serde_json::to_vec(&access("create", "namespaces")).expect("JSON");
    raw(
        harness.mock(),
        Method::POST,
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        &[
            ("content-type", "application/json"),
            ("impersonate-user", "acme-installer"),
        ],
        &body,
    )
    .await;
    let violations = harness.audit().expect_err("no as user, so no header");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("which the guard refuses") && v.contains("Impersonate headers")),
        "{violations:?}"
    );
}

#[tokio::test]
#[should_panic(expected = "a harness serves one `as:` user")]
async fn a_harness_serves_one_as_user() {
    let harness = Harness::load(AS_CASE).expect("loads");
    let ctx = harness
        .run()
        .context("k8s.rbac", Os::Linux, [Need::KubeContext]);
    let _first = harness.client_as(ctx.probe(), user()).expect("a client");
    let _second = harness.client_as(
        ctx.probe(),
        ImpersonateAs::new(AS_USER).expect("another valid user"),
    );
}

/// A fixture `case` under `root` with `files`: a minimal manifest and the `api/` files.
fn fixture_with(root: &std::path::Path, files: &[(&str, &str)]) -> Fixture {
    let case = root.join("case");
    std::fs::create_dir_all(case.join("api")).expect("dirs");
    std::fs::write(
        case.join("fixture.toml"),
        "schema = 1\nname = \"case\"\nsummary = \"x\"\norigin = \"hand\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = []\n\n[caps]\nroot = false\nnetwork = true\nkube = true\n",
    )
    .expect("manifest");
    for (name, text) in files {
        std::fs::write(case.join(name), text).expect("file");
    }
    Fixture::load(root, "case").expect("loads")
}

const FORBIDDEN_POST: &str = r#"{"request":{"method":"POST","path":"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},"status":403,"body":{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"no","reason":"Forbidden","code":403}}"#;

#[tokio::test]
async fn a_review_that_matches_no_row_of_a_table_with_rows_is_not_hidden_by_a_recorded_post() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture_with(
        dir.path(),
        &[
            (
                "api/reviews.json",
                r#"{"access":[{"spec":{"resourceAttributes":{"verb":"create","resource":"namespaces"}},"status":{"allowed":true}}]}"#,
            ),
            ("api/forbidden.json", FORBIDDEN_POST),
        ],
    );
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let client = harness.client_for("k8s.rbac");
    client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("create", "namespaces"))
        .await
        .expect("the row answers");
    // A typo in the verb matches no row. It is a 501 that the audit reports, not the recorded 403.
    let error = client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("craete", "namespaces"))
        .await
        .expect_err("no row");
    assert!(matches!(error, kube::Error::Api(status) if status.code == 501));
    let violations = harness.audit().expect_err("unanswered");
    assert!(
        violations.iter().any(|v| v.contains("no answer")),
        "{violations:?}"
    );
}

#[tokio::test]
async fn a_row_can_refuse_its_review() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture_with(
        dir.path(),
        &[(
            "api/reviews.json",
            r#"{"access":[{"spec":{"resourceAttributes":{"verb":"create","resource":"namespaces"}},"refuse":403},{"spec":{"resourceAttributes":{"verb":"get","resource":"pods"}},"status":{"allowed":true}}]}"#,
        )],
    );
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let client = harness.client_for("k8s.rbac");
    let error = client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("create", "namespaces"))
        .await
        .expect_err("refused");
    assert!(matches!(error, kube::Error::Api(status) if status.code == 403));
    client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &access("get", "pods"))
        .await
        .expect("the other row answers");
    harness.audit().expect("a refusal is an answer");
}

#[test]
fn a_refuse_value_must_be_an_error_status_and_exclude_status() {
    for row in [
        r#"{"spec":{"a":"b"},"refuse":200}"#,
        r#"{"spec":{"a":"b"},"refuse":"no"}"#,
        r#"{"spec":{"a":"b"},"refuse":403,"status":{"allowed":true}}"#,
    ] {
        let table: serde_json::Value =
            serde_json::from_str(&format!(r#"{{"access":[{row}]}}"#)).expect("JSON");
        let error = parse_reviews(&table).expect_err("refused");
        assert!(
            matches!(&error, MockError::BadReviews(text) if text.contains("`refuse` is an HTTP status")),
            "{row}: {error}"
        );
    }
}

#[tokio::test]
async fn the_run_level_connection_of_an_impersonating_kubeconfig_says_so_once() {
    let harness = Harness::load("checks/_kube/cluster")
        .expect("loads")
        .kubeconfig_impersonates();
    let client = harness.client_for("k8s.access");
    client.version().await.expect("version");
    let log = harness.run().action_log().actions;
    assert_eq!(log[0].fields["kubeconfig_impersonates"], true);
    // The entry names no user.
    assert!(
        !log[0]
            .fields
            .values()
            .any(|v| v.to_string().contains("system:"))
    );
    harness.audit().expect("clean");

    let plain = Harness::load("checks/_kube/cluster").expect("loads");
    let client = plain.client_for("k8s.access");
    client.version().await.expect("version");
    let log = plain.run().action_log().actions;
    assert!(log[0].fields.get("kubeconfig_impersonates").is_none());
}
