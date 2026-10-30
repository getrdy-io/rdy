//! Fixture tests of `k8s.rbac`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.rbac/` (written by
//! `scripts/gen-k8s-rbac-fixtures.py`). Every `Rig` audits its run when it drops (INV-14): each request the
//! mock recorded passes the guard's rules and is logged under a check that `ALLOWED` cites, and a request
//! that carried `Impersonate-User` is logged `impersonated: true`.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckContext, CheckError, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::Probe;
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};
use rdy_spec::check::K8sRbac;
use rdy_spec::result::{ActionOutcome, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;
use crate::client::mock::Harness;
use crate::client::{ImpersonateAs, ImpersonationError, ServerVersion};

/// A cluster over the mock. `impersonating` stands for a kubeconfig user that sets `as`.
struct Fixtured {
    harness: Harness,
    version: ServerVersion,
    impersonating: bool,
    openshift: bool,
}

impl Cluster for Fixtured {
    fn server_version(&self) -> &ServerVersion {
        &self.version
    }

    fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        self.harness.client(probe)
    }

    fn read_only_as(
        &self,
        probe: &Probe,
        user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        if self.impersonating {
            return Err(ImpersonationError::Conflict);
        }
        self.harness.client_as(probe, user)
    }

    fn is_openshift(&self) -> bool {
        self.openshift
    }
}

struct Rig {
    cluster: Arc<Fixtured>,
    ctx: CheckContext,
}

fn rig_with(case: &str, impersonating: bool) -> Rig {
    build_rig(case, impersonating, false)
}

fn build_rig(case: &str, impersonating: bool, openshift: bool) -> Rig {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.rbac/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.rbac", Os::Linux, [Need::KubeContext]);
    let version = ServerVersion {
        git_version: "v1.29.4".to_owned(),
        major: "1".to_owned(),
        minor: "29".to_owned(),
        platform: "linux/amd64".to_owned(),
    };
    Rig {
        cluster: Arc::new(Fixtured {
            harness,
            version,
            impersonating,
            openshift,
        }),
        ctx,
    }
}

fn rig(case: &str) -> Rig {
    rig_with(case, false)
}

fn params(spec: Value) -> K8sRbac {
    serde_json::from_value(spec).expect("the parameters parse")
}

/// One request the check made: method, path, outcome, and whether the entry says it was impersonated.
type Sent = (String, String, ActionOutcome, bool);

impl Rig {
    async fn outcome(&self, spec: Value) -> CheckOutcome {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        RbacCheck::new(params(spec), cluster).run(&self.ctx).await
    }

    async fn finding(&self, spec: Value) -> Finding {
        self.outcome(spec).await.expect("the check ran")
    }

    fn requests(&self) -> Vec<Sent> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.rbac")),
            "every request carries the check id"
        );
        log.iter()
            .map(|entry| {
                (
                    entry.fields["method"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    entry.fields["path"].as_str().unwrap_or_default().to_owned(),
                    entry.outcome.clone(),
                    entry.fields.get("impersonated") == Some(&Value::Bool(true)),
                )
            })
            .collect()
    }

    /// The count of requests to `path`.
    fn count(&self, path: &str) -> usize {
        self.requests().iter().filter(|r| r.1 == path).count()
    }

    fn audit(&self) {
        self.cluster.harness.audit().expect("INV-14 audit is clean");
    }
}

const SELF_REVIEW: &str = "/apis/authentication.k8s.io/v1/selfsubjectreviews";
const ACCESS: &str = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";
const RULES: &str = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews";

fn result(rig: &Rig, finding: Finding) -> rdy_spec::result::CheckResult {
    map_outcome(
        &INFO,
        &CheckSpec::new("k8s.rbac"),
        &rig.ctx,
        Ok(finding),
        0,
        0,
    )
}

// ---- the exit test --------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_table_with_two_denied_items_blocks_and_lists_both_with_reasons_and_the_kind_of_no() {
    let rig = rig("two-denied");
    let finding = rig
        .finding(json!({"can": [
            "create namespaces",
            {"verb": "create", "group": "apps", "resource": "deployments", "namespace": "acme-system"},
            {"verb": "list", "resource": "pods", "namespace": "acme-system"},
            "get /healthz"
        ]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "2 of 4 permissions are missing for `system:serviceaccount:acme-system:installer`: `create namespaces` (not allowed); `list pods in acme-system` (denied by an authorizer)"
    );
    // Both are listed with their reason, and the notes tell plain "not allowed" from "denied: true".
    assert_eq!(
        finding.notes[0],
        "`create namespaces`: not allowed, no rule grants it. The server said: no RBAC policy matched"
    );
    assert_eq!(
        finding.notes[1],
        "`list pods in acme-system`: explicitly denied (denied: true) by an authorizer, so adding a role cannot fix it. The server said: denied by the admission webhook acme-guard"
    );
    // Both reasons are in the notes, not just one.
    assert!(
        finding.notes[..2]
            .iter()
            .all(|note| note.contains("The server said:")),
        "{:?}",
        finding.notes
    );
    assert_eq!(
        finding.observed["missing"][0]["reason"],
        "no RBAC policy matched"
    );
    // What the identity may already do, and nothing about the namespace (it exists).
    assert!(
        finding.notes.iter().any(|note| note
            == "`system:serviceaccount:acme-system:installer` may already do this in `acme-system`: get,list configmaps; create deployments in group apps; get /healthz,/version"),
        "{:?}",
        finding.notes
    );
    assert!(
        !finding
            .notes
            .iter()
            .any(|note| note.contains("does not exist"))
    );
    // The fix grants the first and says the second is not a role problem.
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains(
            "`kubectl create clusterrole rdy-installer --verb=create --resource=namespaces`"
        ),
        "{fix}"
    );
    assert!(
        fix.contains("--serviceaccount=acme-system:installer"),
        "{fix}"
    );
    assert!(
        fix.contains("`list pods in acme-system` was refused by an authorizer other than RBAC"),
        "{fix}"
    );
    assert!(fix.contains("`cluster-admin` works"), "{fix}");
    assert_eq!(finding.observed["missing"][0]["answer"], "not_allowed");
    assert_eq!(finding.observed["missing"][1]["answer"], "denied");
    assert_eq!(
        finding.observed["missing"][1]["reason"],
        "denied by the admission webhook acme-guard"
    );
    assert_eq!(finding.observed["allowed"], 2);
    assert_eq!(finding.observed["reviews"], 4);
    assert!(finding.partial.is_none());
    // The requests: who, four reviews, the rules in the target namespace, and the namespace.
    assert_eq!(rig.count(SELF_REVIEW), 1);
    assert_eq!(rig.count(ACCESS), 4);
    assert_eq!(rig.count(RULES), 1);
    assert_eq!(rig.count("/api/v1/namespaces/acme-system"), 1);
    assert!(
        rig.requests().iter().all(|r| !r.3),
        "nothing was impersonated"
    );
    // A required check with a missing permission blocks.
    assert_eq!(result(&rig, finding).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn a_denied_escalate_warns_and_says_it_passes_if_the_rules_are_held() {
    let rig = rig("escalate-denied");
    let finding = rig
        .finding(json!({"can": [
            "create clusterroles.rbac.authorization.k8s.io",
            "create clusterrolebindings.rbac.authorization.k8s.io"
        ]}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Cannot prove `system:serviceaccount:acme-system:installer` may grant roles (`escalate clusterroles.rbac.authorization.k8s.io` (not allowed); `bind clusterroles.rbac.authorization.k8s.io` (not allowed)). It passes if the identity already holds every rule it grants"
    );
    assert_eq!(
        finding.observed["implied"].as_array().map(Vec::len),
        Some(2)
    );
    assert!(finding.partial.is_none());
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("`kubectl create clusterrole rdy-installer --verb=escalate --resource=clusterroles.rbac.authorization.k8s.io`"),
        "{fix}"
    );
    // 2 items and 2 implied asks, and no namespace in play, so no rules review.
    assert_eq!(rig.count(ACCESS), 4);
    assert_eq!(rig.count(RULES), 0);
    // The result is a warning, never a block.
    assert_eq!(result(&rig, finding).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn holding_escalate_and_bind_passes() {
    let rig = rig("escalate-allowed");
    let finding = rig
        .finding(json!({"can": [
            "create clusterroles.rbac.authorization.k8s.io",
            "create clusterrolebindings.rbac.authorization.k8s.io"
        ]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "`system:serviceaccount:acme-system:installer` can do all 2 permissions, and may escalate and bind (2 more reviews)"
    );
    assert_eq!(
        rig.count(RULES),
        0,
        "no rules review when nothing is denied"
    );
    rig.audit();
}

#[tokio::test]
async fn everything_allowed_passes_and_the_entry_namespace_applies_to_every_item() {
    let rig = rig("all-allowed");
    let finding = rig
        .finding(json!({"can": [
            "create deployments.apps",
            "get pods/log",
            "get /healthz"
        ], "namespace": "acme-system"}))
        .await;
    // The entry's namespace went onto the two resource items (the fixture holds rows for them in
    // `acme-system` only), and not onto the URL.
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.expected["can"],
        json!([
            "create deployments.apps in acme-system",
            "get pods/log in acme-system",
            "get /healthz"
        ])
    );
    rig.audit();
}

#[tokio::test]
async fn a_spec_of_all_allowed_items_passes_with_every_shape() {
    let rig = rig("all-allowed");
    let finding = rig
        .finding(json!({"can": [
            "create namespaces",
            {"verb": "create", "group": "apps", "resource": "deployments", "namespace": "acme-system"},
            {"verb": "get", "resource": "pods", "subresource": "log", "namespace": "acme-system"},
            {"verb": "get", "path": "/healthz"}
        ]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "`system:serviceaccount:acme-system:installer` can do all 4 permissions"
    );
    assert_eq!(finding.observed["identity"]["verified"], true);
    assert_eq!(
        finding.observed["identity"]["groups"],
        json!([
            "system:serviceaccounts",
            "system:serviceaccounts:acme-system",
            "system:authenticated"
        ])
    );
    assert_eq!(finding.observed["allowed"], 4);
    assert_eq!(
        finding.expected,
        json!({"can": [
            "create namespaces",
            "create deployments.apps in acme-system",
            "get pods/log in acme-system",
            "get /healthz"
        ], "permissions": 4})
    );
    assert!(finding.fix.is_none());
    assert!(
        finding.notes.iter().any(|note| note
            .starts_with("rdy sent 4 access reviews (one entry each in the cluster's audit log")),
        "{:?}",
        finding.notes
    );
    assert_eq!(result(&rig, finding).status, Status::Pass);
    // Every request is logged under the check and answered.
    assert!(
        rig.requests()
            .iter()
            .all(|(method, _, outcome, _)| !method.is_empty() && *outcome == ActionOutcome::Ok)
    );
    rig.audit();
}

#[tokio::test]
async fn a_repeated_item_is_asked_once() {
    let rig = rig("all-allowed");
    let finding = rig
        .finding(json!({"can": ["create namespaces", {"verb": "create", "resource": "namespaces"}, "get /healthz"]}))
        .await;
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(rig.count(ACCESS), 2);
    rig.audit();
}

#[tokio::test]
async fn a_non_resource_item_is_asked_with_nonresourceattributes() {
    let rig = rig("non-resource");
    let finding = rig
        .finding(json!({"can": ["get /healthz", {"verb": "get", "path": "/metrics"}]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "`system:serviceaccount:acme-system:installer` cannot `get /metrics`: not allowed"
    );
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains(
            "`kubectl create clusterrole rdy-installer --verb=get --non-resource-url=/metrics`"
        ),
        "{fix}"
    );
    // No namespace in play: no rules review, no namespace read.
    assert_eq!(rig.count(RULES), 0);
    let seen = rig.cluster.harness.mock().seen();
    let bodies: Vec<Value> = seen
        .iter()
        .filter(|request| request.uri.path() == ACCESS)
        .map(|request| serde_json::from_slice(&request.body).expect("JSON"))
        .collect();
    assert_eq!(
        bodies[0]["spec"],
        json!({"nonResourceAttributes": {"verb": "get", "path": "/healthz"}})
    );
    rig.audit();
}

#[tokio::test]
async fn an_evaluation_error_with_allowed_false_warns() {
    let rig = rig("evaluation-error");
    let finding = rig
        .finding(json!({"can": ["create namespaces", {"verb": "create", "group": "apps", "resource": "deployments", "namespace": "acme-system"}]}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "1 permission for `system:serviceaccount:acme-system:installer` could not be fully evaluated: `create deployments.apps in acme-system` (could not be fully evaluated)"
    );
    assert!(
        finding.notes[0].contains("an authorizer reported an error (evaluationError)")
            && finding.notes[0].contains("context deadline exceeded"),
        "{:?}",
        finding.notes
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.contains("The list may be short")),
        "an incomplete rules review says so: {:?}",
        finding.notes
    );
    assert_eq!(result(&rig, finding).status, Status::Warn);
    rig.audit();
}

// ---- degrade: what could not be read is never a block --------------------------------------------------------

#[tokio::test]
async fn an_identity_that_may_not_create_reviews_gets_one_request_and_a_partial_result() {
    let rig = rig("reviews-forbidden");
    let finding = rig
        .finding(json!({"can": ["create namespaces", "create nodes", "get /healthz", "list pods"]}))
        .await;
    // Not a block: nothing was read.
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "No permission could be evaluated for `system:serviceaccount:acme-system:installer`"
    );
    let partial = finding.partial.clone().expect("partial");
    assert_eq!(
        partial.note,
        "4 permissions were not evaluated: the identity may not create access reviews"
    );
    assert_eq!(
        partial.missing_grants,
        [
            "create selfsubjectaccessreviews.authorization.k8s.io (for system:serviceaccount:acme-system:installer)"
        ]
    );
    // The first review found out; the other three were never sent.
    assert_eq!(rig.count(ACCESS), 1);
    assert_eq!(finding.observed["reviews"], 1);
    assert_eq!(
        finding.observed["not_evaluated"].as_array().map(Vec::len),
        Some(4)
    );
    let mapped = result(&rig, finding);
    assert_eq!(
        mapped.status,
        Status::Warn,
        "a pass with a partial is a warning"
    );
    assert!(
        mapped.message.starts_with("not verified:"),
        "{}",
        mapped.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_server_without_selfsubjectreview_leaves_the_identity_unverified() {
    let rig = rig("old-server");
    let finding = rig
        .finding(json!({"can": ["create namespaces", "create nodes"]}))
        .await;
    assert_eq!(
        finding.message,
        "The kubeconfig identity cannot `create nodes`: not allowed"
    );
    assert!(
        finding.notes.iter().any(|note| note
            == "The identity is not verified by the API server: SelfSubjectReview needs Kubernetes 1.28"),
        "{:?}",
        finding.notes
    );
    assert_eq!(finding.observed["identity"], json!({"verified": false}));
    // The fix has no user to name, so it keeps a placeholder.
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("--user=<user>"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn a_selfsubjectreview_that_is_forbidden_is_not_fatal() {
    let rig = rig("identity-forbidden");
    let finding = rig.finding(json!({"can": ["create namespaces"]})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note == "The identity is not verified by the API server: the identity may not create access reviews"),
        "{:?}",
        finding.notes
    );
    rig.audit();
}

#[tokio::test]
async fn a_namespace_that_does_not_exist_is_said_in_the_notes_and_the_fix() {
    let rig = rig("namespace-missing");
    let finding = rig
        .finding(json!({"can": [{"verb": "create", "group": "apps", "resource": "deployments", "namespace": "ghost"}]}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.notes.iter().any(|note| note
            == "Namespace `ghost` does not exist, so a namespaced permission there fails until it is created"),
        "{:?}",
        finding.notes
    );
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.starts_with(
            "Namespace `ghost` does not exist. Create it with `kubectl create namespace ghost`"
        ),
        "{fix}"
    );
    assert!(
        fix.contains(
            "`kubectl create role rdy-installer -n ghost --verb=create --resource=deployments.apps`"
        ),
        "{fix}"
    );
    assert_eq!(
        finding.observed["namespaces"],
        json!([{"namespace": "ghost", "exists": false}])
    );
    rig.audit();
}

#[tokio::test]
async fn a_namespace_the_identity_cannot_read_is_unknown_and_not_blamed() {
    let rig = rig("namespace-forbidden");
    let finding = rig
        .finding(json!({"can": [{"verb": "create", "group": "apps", "resource": "deployments", "namespace": "ghost"}]}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    assert!(
        !finding
            .notes
            .iter()
            .any(|note| note.contains("does not exist"))
    );
    assert_eq!(
        finding.observed["namespaces"],
        json!([{"namespace": "ghost", "exists": null}])
    );
    assert!(
        finding.partial.is_none(),
        "the namespace only refines the fix"
    );
    rig.audit();
}

#[tokio::test]
async fn a_forbidden_rules_review_only_leaves_out_its_note() {
    let rig = rig("rules-forbidden");
    let finding = rig
        .finding(json!({"can": [{"verb": "create", "group": "apps", "resource": "deployments", "namespace": "acme-system"}]}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.observed.get("rules").is_none());
    assert!(
        !finding
            .notes
            .iter()
            .any(|note| note.contains("may already do"))
    );
    assert_eq!(rig.count(RULES), 1);
    rig.audit();
}

// ---- the cap -------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_run_sends_at_most_100_reviews_and_says_what_it_left_out() {
    let rig = rig("at-the-cap");
    let mut can: Vec<Value> = (0..99)
        .map(|i| json!({"verb": "get", "resource": "configmaps", "namespace": "acme-system", "name": format!("cfg-{i:03}")}))
        .collect();
    can.push(json!("create clusterroles.rbac.authorization.k8s.io"));
    let finding = rig.finding(json!({"can": can})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(rig.count(ACCESS), 100, "100 reviews, not 101");
    assert_eq!(finding.observed["reviews"], 100);
    assert!(
        finding.notes.iter().any(|note| note
            == "1 implied escalate or bind review was left out: a run sends 100 reviews at most"),
        "{:?}",
        finding.notes
    );
    rig.audit();
}

// ---- impersonation -------------------------------------------------------------------------------------------------

const AS: &str = "system:serviceaccount:acme-system:installer";

#[tokio::test]
async fn a_spec_as_sends_exactly_one_impersonate_user_on_the_reviews_and_marks_the_log() {
    let rig = rig("as-allowed");
    let finding = rig
        .finding(json!({"can": [
            "create namespaces",
            "create nodes",
            {"verb": "list", "resource": "pods", "namespace": "acme-system"}
        ], "as": AS}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        format!(
            "2 of 3 permissions are missing for `{AS}`: `create nodes` (not allowed); `list pods in acme-system` (not allowed)"
        )
    );
    assert!(
        finding.notes.iter().any(|note| note
            == &format!("The reviews ran as `{AS}` (spec as). rdy itself is `acme-admin`.")),
        "{:?}",
        finding.notes
    );
    assert_eq!(finding.observed["tested_as"], AS);
    assert_eq!(finding.observed["identity"]["user"], "acme-admin");
    assert_eq!(finding.expected["as"], AS);
    // The fix names the tested user, and no groups of the kubeconfig identity.
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains("--serviceaccount=acme-system:installer"),
        "{fix}"
    );
    assert!(!fix.contains("--group"), "{fix}");

    // On the wire: one Impersonate-User with the spec's value on each impersonated review, no group, no
    // uid, no extra; and none on the question whether the identity may impersonate, or on who-am-I.
    let seen = rig.cluster.harness.mock().seen();
    let mut impersonated = 0;
    let mut plain_reviews = 0;
    for request in &seen {
        let values: Vec<_> = request.headers.get_all("impersonate-user").iter().collect();
        assert!(
            values.len() <= 1,
            "{} sent {} values",
            request.line(),
            values.len()
        );
        assert!(
            request.headers.keys().all(
                |name| !name.as_str().starts_with("impersonate-") || name == "impersonate-user"
            ),
            "{}",
            request.line()
        );
        match request.uri.path() {
            SELF_REVIEW => assert!(values.is_empty(), "who-am-I is never impersonated"),
            ACCESS | RULES if !values.is_empty() => {
                assert_eq!(values[0].as_bytes(), AS.as_bytes());
                impersonated += 1;
            }
            ACCESS => plain_reviews += 1,
            _ => assert!(values.is_empty(), "{}", request.line()),
        }
    }
    assert_eq!(
        plain_reviews, 1,
        "only the impersonate question is not impersonated"
    );
    assert_eq!(impersonated, 4, "three items and the rules review");
    // The log says so, and never says who.
    let marked: Vec<Sent> = rig.requests().into_iter().filter(|r| r.3).collect();
    assert_eq!(marked.len(), 4);
    let log = rig.cluster.harness.run().action_log().actions;
    assert!(
        log.iter().all(|entry| !entry
            .fields
            .values()
            .any(|value| value.to_string().contains("installer"))),
        "the log holds no user name"
    );
    // The question asked for `impersonate serviceaccounts` of this service account.
    let question: Value = serde_json::from_slice(
        &seen
            .iter()
            .find(|request| request.uri.path() == ACCESS)
            .expect("a review")
            .body,
    )
    .expect("JSON");
    assert_eq!(
        question["spec"]["resourceAttributes"],
        json!({"verb": "impersonate", "resource": "serviceaccounts", "namespace": "acme-system", "name": "installer"})
    );
    rig.audit();
}

#[test]
fn a_plain_user_as_does_not_parse_and_the_error_says_what_to_write() {
    // M1 tests as a service account only (ADR 0038): the server derives a service account's groups, and
    // rdy sends no Impersonate-Group, so a plain user would lose the grants it holds through groups.
    for bad in [
        "acme-installer",
        "jane@example.com",
        "system:serviceaccount:acme",
        "",
    ] {
        let error =
            serde_json::from_value::<K8sRbac>(json!({"can": ["create namespaces"], "as": bad}))
                .expect_err("refused")
                .to_string();
        assert!(
            error.contains("system:serviceaccount:<namespace>:<name>"),
            "{bad}: {error}"
        );
    }
}

#[tokio::test]
async fn a_403_on_the_first_impersonated_review_reads_as_a_refused_impersonation() {
    let rig = rig("as-forbidden");
    let finding = rig
        .finding(json!({"can": ["create namespaces", "create nodes"], "as": AS}))
        .await;
    assert_eq!(finding.level, Level::Pass, "not a block: {finding:?}");
    let partial = finding.partial.clone().expect("partial");
    assert_eq!(
        partial.note,
        "2 permissions were not evaluated: the identity may not `impersonate serviceaccounts installer in acme-system`"
    );
    assert_eq!(
        partial.missing_grants,
        ["impersonate serviceaccounts installer in acme-system"]
    );
    // The question and the one refused review. The second item was not sent.
    assert_eq!(rig.count(ACCESS), 2);
    assert_eq!(result(&rig, finding).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn the_impersonation_question_counts_toward_the_cap_of_100() {
    let rig = rig("as-at-the-cap");
    let mut can: Vec<Value> = (0..99)
        .map(|i| json!({"verb": "get", "resource": "configmaps", "namespace": "acme-system", "name": format!("cfg-{i:03}")}))
        .collect();
    can.push(json!("create clusterroles.rbac.authorization.k8s.io"));
    let finding = rig.finding(json!({"can": can, "as": AS})).await;
    assert_eq!(rig.count(ACCESS), 100, "the question and 99 items, not 101");
    assert_eq!(finding.observed["reviews"], 100);
    // The 100th item was not asked, and its escalate was dropped.
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial
            .note
            .contains("the run is at its cap of 100 reviews"),
        "{}",
        partial.note
    );
    assert!(
        finding.notes.iter().any(|note| note
            == "1 implied escalate or bind review was left out: a run sends 100 reviews at most"),
        "{:?}",
        finding.notes
    );
    rig.audit();
}

#[tokio::test]
async fn a_cluster_that_is_openshift_gets_the_oc_binding_in_the_fix() {
    let rig = build_rig("two-denied", false, true);
    let finding = rig.finding(json!({"can": ["create namespaces"]})).await;
    assert_eq!(finding.level, Level::Fail);
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains(
            "`oc adm policy add-cluster-role-to-user rdy-installer -z installer -n acme-system`"
        ),
        "{fix}"
    );
    let plain = rig_with("two-denied", false);
    let fix = plain
        .finding(json!({"can": ["create namespaces"]}))
        .await
        .fix
        .expect("a fix");
    assert!(!fix.contains("oc adm policy"), "{fix}");
}

#[tokio::test]
async fn an_identity_that_may_not_impersonate_leaves_every_item_not_evaluated() {
    let rig = rig("as-refused");
    let finding = rig
        .finding(json!({"can": ["create namespaces", "create nodes"], "as": AS}))
        .await;
    assert_eq!(finding.level, Level::Pass, "not a block: {finding:?}");
    assert_eq!(
        finding.message,
        format!("No permission could be evaluated for `{AS}`")
    );
    let partial = finding.partial.clone().expect("partial");
    assert_eq!(
        partial.note,
        "2 permissions were not evaluated: the identity may not `impersonate serviceaccounts installer in acme-system`"
    );
    assert_eq!(
        partial.missing_grants,
        ["impersonate serviceaccounts installer in acme-system"]
    );
    // Who-am-I and the one question. No item was sent as the user.
    assert_eq!(rig.count(ACCESS), 1);
    assert_eq!(rig.count(RULES), 0);
    assert!(rig.requests().iter().all(|r| !r.3));
    assert_eq!(result(&rig, finding).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_spec_as_is_refused_with_a_fix_when_the_kubeconfig_already_impersonates() {
    let rig = rig_with("as-allowed", true);
    let error = rig
        .outcome(json!({"can": ["create namespaces"], "as": AS}))
        .await
        .expect_err("refused");
    let CheckError::Failed { message, hint } = &error else {
        panic!("not a failure: {error:?}");
    };
    assert_eq!(
        message,
        "the kubeconfig user already sets an impersonation field (as, as-uid, as-groups or as-user-extra)"
    );
    assert!(
        hint.contains("remove `as:` from the k8s.rbac entry"),
        "{hint}"
    );
    assert!(
        hint.contains("`as`, `as-uid`, `as-groups` or `as-user-extra`"),
        "{hint}"
    );
    assert!(!message.contains("installer") && !hint.contains("installer"));
    // Nothing was sent: not even who-am-I.
    assert!(rig.requests().is_empty());
    // The result is an error that carries the hint, not a pass or a block.
    let mapped = map_outcome(
        &INFO,
        &CheckSpec::new("k8s.rbac"),
        &rig.ctx,
        Err(error),
        0,
        0,
    );
    assert_eq!(mapped.status, Status::Error);
    assert!(mapped.fix.is_some_and(|fix| fix.contains("remove `as:`")));
    rig.audit();
}

#[tokio::test]
async fn a_kubeconfig_that_impersonates_does_not_matter_without_a_spec_as() {
    let rig = rig_with("all-allowed", true);
    let finding = rig.finding(json!({"can": ["create namespaces"]})).await;
    assert_eq!(finding.level, Level::Pass);
    rig.audit();
}

#[tokio::test]
async fn an_as_value_the_header_cannot_carry_is_refused_before_any_request() {
    for bad in [
        // The spec accepts these shapes, and the guard's exact DNS-1123 rules refuse them.
        "system:serviceaccount:-acme:installer",
        "system:serviceaccount:acme-:installer",
        "system:serviceaccount:acme:.installer",
        "system:serviceaccount:acme:installer.",
    ] {
        let rig = rig("as-allowed");
        let error = rig
            .outcome(json!({"can": ["create namespaces"], "as": bad}))
            .await
            .expect_err("refused");
        let CheckError::Failed { message, hint } = &error else {
            panic!("not a failure: {error:?}");
        };
        assert_eq!(
            message,
            "the `as` value of the k8s.rbac entry cannot be sent as Impersonate-User"
        );
        assert!(!hint.is_empty() && !hint.contains("Fix:"), "{hint}");
        assert!(rig.requests().is_empty(), "{bad}");
    }
}

// ---- hostile text --------------------------------------------------------------------------------------------------

#[tokio::test]
async fn text_from_the_server_is_escaped_cut_and_kept_out_of_commands() {
    let rig = rig("hostile-reasons");
    let finding = rig
        .finding(json!({"can": [{"verb": "create", "resource": "namespaces", "namespace": "acme-system"}]}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    let mut texts: Vec<String> = vec![
        finding.message.clone(),
        finding.fix.clone().unwrap_or_default(),
    ];
    texts.extend(finding.notes.clone());
    texts.push(finding.observed.to_string());
    for text in &texts {
        assert!(
            !text.contains('\u{1b}'),
            "an escape character got through: {text:?}"
        );
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }
    // Backticks from the server do not open a command span in a sentence.
    for text in finding
        .notes
        .iter()
        .chain(std::iter::once(&finding.message))
    {
        let ticks = text.matches('`').count();
        assert_eq!(ticks % 2, 0, "unbalanced backticks: {text}");
    }
    // The reason is cut.
    assert!(finding.notes[0].ends_with("..."), "{}", finding.notes[0]);
    assert!(finding.notes[0].len() < 400);
    // A user name with odd characters never reaches a command.
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("--user=<user>"), "{fix}");
    assert!(!fix.contains("rm -rf"), "{fix}");
    rig.audit();
}

#[test]
fn the_window_is_eight_and_the_cap_is_a_hundred() {
    assert_eq!(IN_FLIGHT, 8);
    assert_eq!(ask::MAX_REVIEWS, 100);
}
