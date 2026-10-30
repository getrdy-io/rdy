//! Tests of the kube mock harness (M1-105): the exit test, then the mock's rules, the audit and the new
//! `ReadOnlyClient` routes.

use std::time::Duration;

use http::{Method, Request};
use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::api::authorization::v1::{
    NonResourceAttributes, ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use k8s_openapi::api::core::v1::{Node, Pod};
use k8s_openapi::api::storage::v1::CSINode;
use kube::api::{ListParams, PostParams};
use rdy_spec::result::ActionOutcome;
use serde_json::json;

use super::*;
use crate::client::guard::{
    GuardError, RULE_PATH_SHAPE, RULE_REVIEW_BODY, RULE_SECRETS, SELF_SUBJECT_REVIEW_BODY,
};

const CLUSTER: &str = "checks/_kube/cluster";
const DENIED: &str = "checks/_kube/denied";

fn cluster() -> Harness {
    Harness::load(CLUSTER).expect("the cluster fixture loads")
}

fn names(nodes: &[Node]) -> Vec<&str> {
    nodes
        .iter()
        .map(|node| node.metadata.name.as_deref().unwrap_or_default())
        .collect()
}

/// The rule of a guard refusal inside a kube error.
fn refusal(error: &kube::Error) -> Option<&'static str> {
    match error {
        kube::Error::Service(inner) => inner.downcast_ref::<GuardError>().map(GuardError::rule),
        _ => None,
    }
}

/// The HTTP code of a server answer inside a kube error.
fn api_code(error: &kube::Error) -> Option<u16> {
    match error {
        kube::Error::Api(status) => Some(status.code),
        _ => None,
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

fn access_review(attributes: ResourceAttributes) -> SelfSubjectAccessReview {
    SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(attributes),
            non_resource_attributes: None,
        },
        ..SelfSubjectAccessReview::default()
    }
}

fn attributes(
    verb: &str,
    group: &str,
    resource: &str,
    namespace: Option<&str>,
) -> ResourceAttributes {
    ResourceAttributes {
        verb: Some(verb.to_owned()),
        group: (!group.is_empty()).then(|| group.to_owned()),
        resource: Some(resource.to_owned()),
        namespace: namespace.map(str::to_owned),
        ..ResourceAttributes::default()
    }
}

// ---- the exit test -----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_client_on_the_mock_pages_restarts_once_on_410_and_answers_a_review_from_a_table() {
    // The ticket's exit test in one run: the guard in front of the mock, a recorded `nodes.json` paged
    // through, one restart on `410 Gone`, and a SelfSubjectAccessReview answered from the table. The
    // harness audits the run when it drops.
    let harness = cluster();
    let client = harness.client_for("k8s.version");
    let nodes = client.all::<Node>();
    let params = ListParams::default().limit(500);

    let plain = list_all(&nodes, &params).await.expect("three pages");
    assert_eq!(
        names(&plain.items),
        ["node-a", "node-b", "node-c", "node-d"]
    );
    assert_eq!(plain.restarts, 0);

    // The server forgets the third token: the walk starts over once and then succeeds.
    harness.mock().expire_once("tok-page-3");
    let restarted = list_all(&nodes, &params)
        .await
        .expect("the restart succeeds");
    assert_eq!(
        names(&restarted.items),
        ["node-a", "node-b", "node-c", "node-d"]
    );
    assert_eq!(restarted.restarts, 1);

    let rbac = harness.client_for("k8s.rbac");
    let review = rbac
        .all::<SelfSubjectAccessReview>()
        .create(
            &PostParams::default(),
            &access_review(attributes("create", "", "namespaces", None)),
        )
        .await
        .expect("answered from the table");
    let status = review.status.expect("a status");
    assert!(status.allowed);
    assert!(status.reason.unwrap_or_default().contains("acme-installer"));

    harness.audit().expect("the run is clean");
}

// ---- paging and 410 --------------------------------------------------------------------------------------

#[tokio::test]
async fn paging_sends_one_request_per_recorded_page_through_the_guard() {
    let harness = cluster();
    let client = harness.client_for("k8s.version");
    let listed = list_all(&client.all::<Node>(), &ListParams::default().limit(500))
        .await
        .expect("pages");
    assert_eq!(listed.items.len(), 4);

    let seen = harness.mock().seen();
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|request| request.uri.path() == "/api/v1/nodes")
    );
    // kube's own query text reached the mock; the third request carries the second token.
    let last = seen.last().expect("a request").line();
    assert!(
        last.contains("continue=tok-page-3") && last.contains("limit=500"),
        "{last}"
    );

    let log = harness.run().action_log().actions;
    assert_eq!(log.len(), 3, "one entry per page");
    assert!(log.iter().all(|entry| {
        entry.outcome == ActionOutcome::Ok
            && entry.check.as_deref() == Some("k8s.version")
            && entry.fields.get("path").and_then(|p| p.as_str()) == Some("/api/v1/nodes")
    }));
    harness.audit().expect("clean");
}

#[tokio::test]
async fn a_410_is_logged_as_failed_and_the_walk_starts_over_from_the_first_page() {
    let harness = cluster();
    harness.mock().expire_once("tok-page-2");
    let client = harness.client_for("k8s.nodes");
    let listed = list_all(&client.all::<Node>(), &ListParams::default().limit(500))
        .await
        .expect("the restart succeeds");
    assert_eq!(listed.restarts, 1);
    assert_eq!(listed.items.len(), 4);

    // Page 1, the 410, then page 1, 2 and 3 again.
    let lines: Vec<String> = harness.mock().seen().iter().map(Seen::line).collect();
    assert_eq!(lines.len(), 5, "{lines:?}");
    let log = harness.run().action_log().actions;
    let outcomes: Vec<_> = log.iter().map(|entry| entry.outcome.clone()).collect();
    assert_eq!(
        outcomes,
        [
            ActionOutcome::Ok,
            ActionOutcome::Failed,
            ActionOutcome::Ok,
            ActionOutcome::Ok,
            ActionOutcome::Ok
        ]
    );
    assert_eq!(log[1].fields["status"], 410);
    harness.audit().expect("clean");
}

#[tokio::test]
async fn a_recorded_410_fails_the_walk_after_exactly_one_restart() {
    // `csinodes-stale.json` records a 410 for its token, so the restart meets it again.
    let harness = cluster();
    let client = harness.client_for("k8s.storageclass");
    let error = list_all(&client.all::<CSINode>(), &ListParams::default().limit(500))
        .await
        .expect_err("the second 410 is returned");
    assert_eq!(api_code(&error), Some(410));
    assert_eq!(harness.mock().seen().len(), 4, "two walks of two pages");
    harness.audit().expect("clean");
}

#[tokio::test]
async fn an_expired_token_answers_410_once_and_then_finds_its_record() {
    let harness = cluster();
    harness.mock().expire_once("tok-page-2");
    let client = harness.client_for("k8s.nodes");
    let nodes = client.all::<Node>();
    let page = ListParams::default()
        .limit(500)
        .continue_token("tok-page-2");
    let first = nodes.list(&page).await.expect_err("expired");
    assert_eq!(api_code(&first), Some(410));
    let second = nodes.list(&page).await.expect("the record");
    assert_eq!(names(&second.items), ["node-c"]);
    harness.audit().expect("clean");
}

// ---- selectors -------------------------------------------------------------------------------------------

#[test]
fn a_query_is_found_by_its_decoded_sorted_pairs() {
    let kube = canonical_query(
        "&limit=500&fieldSelector=status.phase%21%3DSucceeded%2Cstatus.phase%21%3DFailed",
    );
    let plain =
        canonical_query("fieldSelector=status.phase!=Succeeded,status.phase!=Failed&limit=500");
    assert_eq!(kube.expect("decodes"), plain.expect("decodes"));
    assert_eq!(canonical_query("").expect("empty"), "");
    assert!(canonical_query("limit=%zz").is_err());
}

#[tokio::test]
async fn a_selector_written_in_plain_text_matches_the_query_kube_encodes() {
    let harness = cluster();
    let client = harness.client_for("k8s.nodes");
    let params = ListParams::default()
        .fields("status.phase!=Succeeded,status.phase!=Failed")
        .limit(500);
    let pods = list_all(&client.all::<Pod>(), &params)
        .await
        .expect("recorded");
    let pod_names: Vec<_> = pods
        .items
        .iter()
        .map(|pod| pod.metadata.name.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(pod_names, ["web-0", "web-1"]);
    // kube sends the encoded form, and the fixture holds the plain one.
    let line = harness.mock().seen()[0].line();
    assert!(line.contains("%21%3D"), "{line}");
    harness.audit().expect("clean");
}

#[tokio::test]
async fn another_selector_is_another_request_and_the_fixture_has_no_answer_for_it() {
    let harness = cluster();
    let client = harness.client_for("k8s.nodes");
    // The guard admits this selector (it names `status.phase`), the fixture does not hold it.
    let params = ListParams::default()
        .fields("status.phase=Running")
        .limit(500);
    let error = client
        .all::<Pod>()
        .list(&params)
        .await
        .expect_err("not recorded");
    assert_eq!(api_code(&error), Some(501));
    assert_eq!(harness.mock().unrecorded().len(), 1);
    let violations = harness
        .audit()
        .expect_err("an unanswered request fails the run");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("no answer") && v.contains("status.phase%3DRunning")),
        "{violations:?}"
    );
}

// ---- discovery -------------------------------------------------------------------------------------------

#[tokio::test]
async fn legacy_discovery_is_read_through_the_guard() {
    let harness = cluster();
    let client = harness.client_for("k8s.version");

    let core = client.core_versions().await.expect("/api");
    assert_eq!(core.versions, ["v1"]);
    let groups = client.api_groups().await.expect("/apis");
    let group_names: Vec<_> = groups.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(group_names, ["autoscaling", "storage.k8s.io"]);
    let autoscaling = client
        .group_resources("autoscaling", "v2")
        .await
        .expect("/apis/autoscaling/v2");
    assert_eq!(autoscaling.resources[0].name, "horizontalpodautoscalers");
    // A group the server does not serve answers 404, which a check reads as "not installed".
    let absent = client
        .group_resources("karpenter.sh", "v1")
        .await
        .expect_err("not served");
    assert_eq!(api_code(&absent), Some(404));

    let paths: Vec<String> = harness
        .mock()
        .seen()
        .iter()
        .map(|request| request.uri.path().to_owned())
        .collect();
    assert_eq!(
        paths,
        [
            "/api",
            "/apis",
            "/apis/autoscaling/v2",
            "/apis/karpenter.sh/v1"
        ]
    );
    // No Accept header selects the aggregated document.
    assert!(
        harness
            .mock()
            .seen()
            .iter()
            .all(|request| !format!("{:?}", request.headers).contains("apidiscovery"))
    );
    let log = harness.run().action_log().actions;
    assert_eq!(log.len(), 4);
    assert_eq!(log[3].outcome, ActionOutcome::Failed);
    assert_eq!(log[3].fields["status"], 404);
    harness.audit().expect("discovery paths need no entry");
}

#[tokio::test]
async fn the_aggregated_discovery_document_is_not_recorded_so_the_mock_refuses_it() {
    let harness = cluster();
    let accept = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList";
    let status = raw(
        harness.mock(),
        Method::GET,
        "/apis",
        &[("accept", accept)],
        b"",
    )
    .await;
    assert_eq!(status, 406);
    // The same path without the header is the legacy document.
    assert_eq!(
        raw(harness.mock(), Method::GET, "/apis", &[], b"").await,
        200
    );
    harness
        .audit()
        .expect_err("the raw requests have no log entries");
}

#[tokio::test]
async fn a_discovery_route_with_a_hostile_group_is_refused_before_anything_is_sent() {
    let harness = cluster();
    let client = harness.client_for("k8s.version");
    // A well-formed group named `secrets` reaches the guard, which refuses it and logs the refusal.
    let secrets = client
        .group_resources("secrets", "v1")
        .await
        .expect_err("refused");
    assert_eq!(refusal(&secrets), Some(RULE_SECRETS));
    // These are not a group and a version, so the route refuses them before the guard: nothing is sent
    // and no entry is written. Each one would have built a path other than a discovery path.
    for (group, version) in [
        ("evil?x=1", "v1"),
        ("a%2fb", "v1"),
        ("apps", "v1/deployments"),
        ("apps/v1", "x"),
        ("storage.k8s.io", "v1/csinodes"),
        ("apps", "v"),
        ("", "v1"),
        ("apps", ""),
    ] {
        let error = client
            .group_resources(group, version)
            .await
            .expect_err("refused");
        assert_eq!(
            refusal(&error),
            Some(RULE_PATH_SHAPE),
            "({group:?}, {version:?})"
        );
    }
    assert!(harness.mock().seen().is_empty());
    let log = harness.run().action_log().actions;
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, ActionOutcome::Denied);
    harness
        .audit()
        .expect("denied requests are not sent, so nothing is recorded");
}

// ---- the raw SelfSubjectReview ---------------------------------------------------------------------------

#[tokio::test]
async fn the_raw_review_route_sends_the_fixed_bytes_and_reads_the_user() {
    let harness = cluster();
    let client = harness.client_for("k8s.access");
    let review = client.self_subject_review().await.expect("answered");
    let user = review.status.expect("status").user_info.expect("user info");
    assert_eq!(
        user.username.as_deref(),
        Some("system:serviceaccount:acme-system:installer")
    );

    let seen = harness.mock().seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, Method::POST);
    assert_eq!(
        seen[0].uri.path(),
        "/apis/authentication.k8s.io/v1/selfsubjectreviews"
    );
    assert_eq!(
        seen[0].body, SELF_SUBJECT_REVIEW_BODY,
        "exactly the fixed bytes"
    );
    assert_eq!(seen[0].headers["content-type"], "application/json");
    let log = harness.run().action_log().actions;
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
    assert_eq!(log[0].check.as_deref(), Some("k8s.access"));
    harness.audit().expect("clean");
}

#[tokio::test]
async fn a_typed_review_is_still_refused_because_it_serializes_with_metadata() {
    let harness = cluster();
    let client = harness.client_for("k8s.access");
    let error = client
        .all::<SelfSubjectReview>()
        .create(&PostParams::default(), &SelfSubjectReview::default())
        .await
        .expect_err("refused");
    assert_eq!(refusal(&error), Some(RULE_REVIEW_BODY));
    assert!(harness.mock().seen().is_empty());
    harness.audit().expect("clean");
}

#[tokio::test]
async fn a_refused_identity_review_and_an_unauthorized_version_are_server_answers() {
    let harness = Harness::load(DENIED).expect("loads");
    let client = harness.client_for("k8s.access");
    let review = client.self_subject_review().await.expect_err("403");
    assert_eq!(api_code(&review), Some(403));
    let version = client.version().await.expect_err("401");
    assert_eq!(api_code(&version), Some(401));
    let log = harness.run().action_log().actions;
    assert!(
        log.iter()
            .all(|entry| entry.outcome == ActionOutcome::Failed)
    );
    assert_eq!(log[0].fields["status"], 403);
    assert_eq!(log[1].fields["status"], 401);
    harness.audit().expect("clean");
}

// ---- the review table ------------------------------------------------------------------------------------

#[tokio::test]
async fn the_review_table_answers_allowed_denied_and_non_resource_rows() {
    let harness = cluster();
    let client = harness.client_for("k8s.rbac");
    let reviews = client.all::<SelfSubjectAccessReview>();
    let post = PostParams::default();

    let allowed = reviews
        .create(
            &post,
            &access_review(attributes("create", "", "namespaces", None)),
        )
        .await
        .expect("row");
    assert!(allowed.status.expect("status").allowed);

    // A row with `evaluationError` and no reason.
    let blocked = reviews
        .create(
            &post,
            &access_review(attributes(
                "create",
                "rbac.authorization.k8s.io",
                "clusterroles",
                None,
            )),
        )
        .await
        .expect("row")
        .status
        .expect("status");
    assert!(!blocked.allowed);
    assert_eq!(
        blocked.evaluation_error.as_deref(),
        Some("no RBAC policy matched")
    );

    // `denied` with a reason, in a namespace.
    let denied = reviews
        .create(
            &post,
            &access_review(attributes("list", "", "pods", Some("app"))),
        )
        .await
        .expect("row")
        .status
        .expect("status");
    assert_eq!((denied.allowed, denied.denied), (false, Some(true)));
    assert!(denied.reason.unwrap_or_default().contains("acme-guard"));

    let non_resource = SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: None,
            non_resource_attributes: Some(NonResourceAttributes {
                path: Some("/healthz".to_owned()),
                verb: Some("get".to_owned()),
            }),
        },
        ..SelfSubjectAccessReview::default()
    };
    let health = reviews.create(&post, &non_resource).await.expect("row");
    assert!(health.status.expect("status").allowed);

    // The posted spec comes back in the answer, as the server echoes it.
    assert_eq!(
        allowed
            .spec
            .resource_attributes
            .and_then(|a| a.resource)
            .as_deref(),
        Some("namespaces")
    );
    harness.audit().expect("reviews need no entry");
}

#[tokio::test]
async fn attributes_the_table_does_not_hold_fail_the_run() {
    let harness = cluster();
    let client = harness.client_for("k8s.rbac");
    let error = client
        .all::<SelfSubjectAccessReview>()
        .create(
            &PostParams::default(),
            &access_review(attributes("delete", "", "nodes", None)),
        )
        .await
        .expect_err("no row");
    assert_eq!(api_code(&error), Some(501));
    assert_eq!(harness.mock().unrecorded().len(), 1);
    harness
        .audit()
        .expect_err("an unrecorded review fails the run");
}

// ---- the audit (INV-14) ----------------------------------------------------------------------------------

#[tokio::test]
async fn an_unlisted_recorded_request_fails_the_run() {
    // The guard refuses these before the mock sees them, so the test sends them to the mock directly:
    // what the mock recorded is what the audit judges.
    let harness = cluster();
    let hostile = [
        (
            "/api/v1/namespaces/app/configmaps",
            "this resource is not on the list rdy reads",
        ),
        ("/api/v1/secrets", "Secrets are never read"),
        (
            "/api/v1/nodes?watch=true",
            "this query string is not allowed",
        ),
    ];
    for (uri, _) in hostile {
        raw(harness.mock(), Method::GET, uri, &[], b"").await;
    }
    let delete = raw(
        harness.mock(),
        Method::DELETE,
        "/api/v1/nodes/node-a",
        &[],
        b"",
    )
    .await;
    assert_eq!(delete, 501);

    let violations = harness.audit().expect_err("unlisted requests fail the run");
    for (uri, rule) in hostile {
        assert!(
            violations
                .iter()
                .any(|v| v.contains(&format!("`GET {uri}`")) && v.contains(rule)),
            "{uri}: {violations:?}"
        );
    }
    assert!(
        violations
            .iter()
            .any(|v| v.contains("`DELETE /api/v1/nodes/node-a`") && v.contains("only GET")),
        "{violations:?}"
    );
}

#[tokio::test]
#[should_panic(expected = "INV-14")]
async fn a_harness_dropped_after_an_unlisted_request_panics() {
    let harness = cluster();
    raw(
        harness.mock(),
        Method::GET,
        "/api/v1/namespaces/app/configmaps",
        &[],
        b"",
    )
    .await;
    // No explicit audit: dropping the harness runs it.
}

#[tokio::test]
async fn a_request_logged_under_a_check_that_does_not_cite_its_entry_fails_the_run() {
    let harness = cluster();
    // `csinodes` is cited by `k8s.storageclass` only.
    let wrong = harness.client_for("k8s.version");
    wrong
        .all::<CSINode>()
        .list(&ListParams::default().limit(500))
        .await
        .expect("the guard allows it and the fixture holds it");
    let violations = harness.audit().expect_err("the citation is wrong");
    assert_eq!(violations.len(), 1, "{violations:?}");
    let message = &violations[0];
    assert!(
        message.contains("/apis/storage.k8s.io/v1/csinodes"),
        "{message}"
    );
    assert!(
        message.contains("`k8s.version`") && message.contains("k8s.storageclass"),
        "{message}"
    );
}

#[tokio::test]
async fn a_request_logged_under_no_check_id_fails_because_the_run_cites_no_entry() {
    let harness = cluster();
    // The run-level client (check: null) reads discovery and the version freely, but not a node list.
    let run = harness.run_client();
    run.core_versions().await.expect("discovery");
    run.all::<Node>()
        .list(&ListParams::default().limit(500))
        .await
        .expect("allowed by the guard");
    let violations = harness.audit().expect_err("no check id cites nodes");
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].contains("no check id"), "{}", violations[0]);
}

#[tokio::test]
async fn the_right_check_passes_the_citation() {
    let harness = cluster();
    for check in ["k8s.version", "k8s.nodes"] {
        let client = harness.client_for(check);
        client
            .all::<Node>()
            .list(&ListParams::default().limit(500))
            .await
            .expect("first page");
    }
    harness
        .client_for("k8s.storageclass")
        .all::<CSINode>()
        .list(&ListParams::default().limit(500))
        .await
        .expect("first page");
    harness.audit().expect("each check cites its entry");
}

#[tokio::test]
async fn a_request_that_reached_the_mock_without_the_guard_fails_the_count() {
    let harness = cluster();
    // `/version` is a path the audit exempts, so only the count can catch the bypass.
    assert_eq!(
        raw(harness.mock(), Method::GET, "/version", &[], b"").await,
        200
    );
    let violations = harness.audit().expect_err("the log has no entry for it");
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0].contains("without the guard"),
        "{}",
        violations[0]
    );
}

#[tokio::test]
async fn an_unguarded_request_is_not_hidden_by_a_guarded_one_that_never_reached_the_mock() {
    let harness = cluster();
    // A guarded request for `/api` that is dropped before it is sent: the probe logs it as a timeout.
    let probe = harness.run().run_probe(Os::Linux);
    drop(probe.kube_call("GET", "/api").expect("an open probe"));
    // An unguarded request for `/version`. One request and one sent entry: a count would call it clean.
    assert_eq!(
        raw(harness.mock(), Method::GET, "/version", &[], b"").await,
        200
    );
    let log = harness.run().action_log().actions;
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, ActionOutcome::Timeout);

    let violations = harness.audit().expect_err("the two do not pair");
    assert_eq!(violations.len(), 2, "{violations:?}");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("`GET /version`") && v.contains("without the guard")),
        "{violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.contains("`GET /api`") && v.contains("never recorded")),
        "{violations:?}"
    );
}

#[tokio::test]
#[should_panic(expected = "INV-14")]
async fn a_clean_audit_does_not_switch_off_the_audit_at_drop() {
    let harness = cluster();
    harness.audit().expect("nothing yet");
    raw(
        harness.mock(),
        Method::GET,
        "/api/v1/namespaces/app/configmaps",
        &[],
        b"",
    )
    .await;
    // Dropped: the later request is audited.
}

#[tokio::test]
async fn a_header_the_guard_refuses_is_found_in_the_recorded_request() {
    let harness = cluster();
    raw(
        harness.mock(),
        Method::GET,
        "/api/v1/nodes?&limit=500",
        &[("impersonate-user", "someone")],
        b"",
    )
    .await;
    let violations = harness.audit().expect_err("impersonation reached the mock");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("Impersonate headers are not allowed")),
        "{violations:?}"
    );
}

#[tokio::test]
async fn a_clean_run_drops_quietly_and_an_audited_dirty_run_does_not_panic() {
    {
        let harness = cluster();
        let client = harness.client_for("k8s.version");
        client.version().await.expect("version");
        // Dropped without an explicit audit: the drop audit runs and passes.
    }
    let harness = cluster();
    raw(harness.mock(), Method::GET, "/api/v1/secrets", &[], b"").await;
    harness.audit().expect_err("dirty");
    // Dropped after an explicit audit: no second panic.
}

// ---- the mock's rules ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_recorded_delay_is_a_timer_on_the_tokio_clock() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_fixture(
        dir.path(),
        &[(
            "api/version.json",
            r#"{"request":{"method":"GET","path":"/version"},"status":200,"body":{},"delay_ms":60000}"#,
        )],
    );
    let fixture = Fixture::load(dir.path(), "case").expect("loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("mock");
    let client = harness.client_for("k8s.access");
    let waited = tokio::time::timeout(Duration::from_millis(100), client.version()).await;
    assert!(
        waited.is_err(),
        "the recorded delay outlasts the caller's timer"
    );
    drop(client);
    let log = harness.run().action_log().actions;
    assert_eq!(log[0].outcome, ActionOutcome::Timeout);
    harness.audit().expect("clean");
}

/// Writes a minimal fixture `case` under `root` with `files`.
fn write_fixture(root: &std::path::Path, files: &[(&str, &str)]) {
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
}

fn mock_error(files: &[(&str, &str)]) -> MockError {
    let dir = tempfile::tempdir().expect("tempdir");
    write_fixture(dir.path(), files);
    let fixture = Fixture::load(dir.path(), "case").expect("loads");
    Mock::new(fixture.replay()).expect_err("not a mock")
}

fn record(slug: &str, query: &str) -> (String, String) {
    (
        format!("api/{slug}.json"),
        format!(
            r#"{{"request":{{"method":"GET","path":"/api/v1/nodes","query":"{query}"}},"status":200,"body":{{}}}}"#
        ),
    )
}

#[test]
fn two_records_that_are_one_request_once_decoded_are_refused() {
    let (a_name, a) = record("a", "limit=500&continue=tok");
    let (b_name, b) = record("b", "continue=tok&limit=500");
    let error = mock_error(&[(a_name.as_str(), a.as_str()), (b_name.as_str(), b.as_str())]);
    assert!(matches!(error, MockError::Duplicate(_)), "{error}");
    let (c_name, c) = record("c", "limit=%zz");
    let error = mock_error(&[(c_name.as_str(), c.as_str())]);
    assert!(matches!(error, MockError::BadQuery(_)), "{error}");
}

#[test]
fn a_malformed_review_table_is_refused_with_the_reason() {
    let cases = [
        (r"[]", "must be an object"),
        (r#"{"rows":[]}"#, "unknown key `rows`"),
        (r#"{"access":{}}"#, "`access` must be a list"),
        (
            r#"{"access":[{"spec":{},"status":{"allowed":true},"x":1}]}"#,
            "unknown row key `x`",
        ),
        (
            r#"{"access":[{"status":{"allowed":true}}]}"#,
            "needs a `spec`",
        ),
        (
            r#"{"access":[{"spec":{}, "status":{}}]}"#,
            "boolean `allowed`",
        ),
        (
            r#"{"access":[{"spec":{"a":"b"},"status":{"allowed":true}},{"spec":{"a":"b","c":""},"status":{"allowed":false}}]}"#,
            "two rows have the spec",
        ),
    ];
    for (table, reason) in cases {
        let error = mock_error(&[("api/reviews.json", table)]);
        assert!(
            matches!(&error, MockError::BadReviews(text) if text.contains(reason)),
            "{table}: {error}"
        );
    }
}

#[test]
fn the_cluster_fixture_answers_every_review_row_it_holds() {
    // The fixture keeps its table in the shape the mock reads, and keeps it small.
    let fixture = Fixture::load(&fixtures_dir(), CLUSTER).expect("loads");
    let rows = parse_reviews(fixture.replay().reviews().expect("a table")).expect("parses");
    assert_eq!(rows.len(), 4);
    assert_eq!(
        without_empty(&json!({"verb": "get", "name": "", "group": null})),
        json!({"verb": "get"})
    );
}
