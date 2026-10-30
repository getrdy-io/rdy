//! Tests of the parts of the mock harness that `k8s.rbac` (M1-111) added: the rules table, the recorded
//! POST fallback, the impersonating client and the audit of `Impersonate-User`.

use http::Method;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
    SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
};
use kube::api::{ObjectMeta, PostParams};
use serde_json::json;

use super::*;

const AS_USER: &str = "case-no-such-fixture";
const TWO_DENIED: &str = "checks/k8s.rbac/two-denied";
const AS_CASE: &str = "checks/k8s.rbac/as-user";
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
    ImpersonateAs::new("acme-installer").expect("a valid user")
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
    let client = harness.client_as(ctx.probe(), user());
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
    assert_eq!(seen[0].headers["impersonate-user"], "acme-installer");
    let log = harness.run().action_log().actions;
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
    let client = harness.client_as(ctx.probe(), user());
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
    let _first = harness.client_as(ctx.probe(), user());
    let _second = harness.client_as(
        ctx.probe(),
        ImpersonateAs::new(AS_USER).expect("another valid user"),
    );
}
