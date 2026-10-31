//! Fixture tests of `k8s.namespace`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.namespace/`, written by
//! `scripts/gen-k8s-namespace-fixtures.py`. Every `Rig` audits its run when it drops (INV-14): each request
//! the mock recorded passes the guard's rules and is logged under a check that `ALLOWED` cites.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckContext, Finding, Level, Need, Os};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::Probe;
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};
use rdy_spec::result::Status;
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;
use crate::client::mock::Harness;
use crate::client::{ImpersonateAs, ImpersonationError, ServerVersion};

const NAMESPACE: &str = "/api/v1/namespaces/acme-system";
const QUOTAS: &str = "/api/v1/namespaces/acme-system/resourcequotas";
const LIMITS: &str = "/api/v1/namespaces/acme-system/limitranges";
const APIS: &str = "/apis";
const REVIEW: &str = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";

/// A cluster over the mock.
struct Fixtured {
    harness: Harness,
    version: ServerVersion,
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
        _probe: &Probe,
        _user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        // This check never impersonates.
        Err(ImpersonationError::Conflict)
    }
}

/// One fixture cluster, the check's context and the run that logs into it.
struct Rig {
    cluster: Arc<Fixtured>,
    ctx: CheckContext,
}

fn rig(case: &str) -> Rig {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.namespace/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.namespace", Os::Linux, [Need::KubeContext]);
    Rig {
        cluster: Arc::new(Fixtured {
            harness,
            version: ServerVersion {
                git_version: "v1.30.2".to_owned(),
                major: "1".to_owned(),
                minor: "30".to_owned(),
                platform: "linux/amd64".to_owned(),
            },
        }),
        ctx,
    }
}

fn params(spec: Value) -> K8sNamespace {
    serde_json::from_value(spec).expect("the parameters parse")
}

impl Rig {
    fn check(&self, spec: Value, family_namespace: Option<&str>) -> NamespaceCheck {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let namespace =
            family_namespace.map(|name| serde_json::from_value(json!(name)).expect("a name"));
        NamespaceCheck::new(params(spec), namespace, cluster)
    }

    /// The finding for a spec that names the namespace `acme-system`.
    async fn finding(&self, mut spec: Value) -> Finding {
        spec["namespace"] = json!("acme-system");
        self.finding_in(spec, None).await
    }

    async fn finding_in(&self, spec: Value, family_namespace: Option<&str>) -> Finding {
        let finding = self
            .check(spec, family_namespace)
            .run(&self.ctx)
            .await
            .expect("the check ran");
        assert_fix_text_is_clean(&finding);
        finding
    }

    /// The `(method, path)` of every request, in order, all logged under `k8s.namespace`.
    fn requests(&self) -> Vec<(String, String)> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.namespace")),
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
                )
            })
            .collect()
    }

    /// The paths of every request. Every one is a GET: this check only reads.
    fn paths(&self) -> Vec<String> {
        let requests = self.requests();
        assert!(
            requests.iter().all(|(method, _)| method == "GET"),
            "the check only reads: {requests:?}"
        );
        requests.into_iter().map(|(_, path)| path).collect()
    }

    fn audit(&self) {
        self.cluster.harness.audit().expect("INV-14 audit is clean");
    }
}

/// Every fix text and note of a finding passes the fix-text allow-list (commands only from `commands.txt`).
fn assert_fix_text_is_clean(finding: &Finding) {
    for text in finding.fix.iter().chain(&finding.notes) {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("fix text breaks the allow-list: {error}\n{text}");
        }
        assert!(!text.contains('\u{2014}'), "no em dash: {text}");
    }
    assert!(!finding.message.contains('\u{2014}'), "{}", finding.message);
}

fn grants(finding: &Finding) -> Vec<String> {
    finding
        .partial
        .as_ref()
        .map(|partial| partial.missing_grants.clone())
        .unwrap_or_default()
}

fn notes(finding: &Finding) -> String {
    finding.notes.join("\n")
}

fn fix_of(finding: &Finding) -> String {
    finding.fix.clone().expect("a fix")
}

fn partial_note(finding: &Finding) -> String {
    finding.partial.clone().expect("partial").note
}

/// What the engine makes of a finding for an entry with this severity.
fn engine(rig: &Rig, finding: Finding, severity: Option<&str>) -> rdy_spec::result::CheckResult {
    let mut entry = json!({"id": "k8s.namespace"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

/// The needs of the 03 example, small enough for the roomy quota.
fn needs_03() -> Value {
    json!({
        "requests.cpu": 16,
        "requests.memory": "64Gi",
        "pods": 100,
        "persistentvolumeclaims": 10,
        "requests.storage": "500Gi",
    })
}

// ---- the exit test ----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_quota_with_2_cpu_left_blocks_a_16_cpu_need() {
    let rig = rig("quota-short");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 16, "pods": 10}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Quota compute in acme-system leaves 2 of requests.cpu (8 allowed, 6 used), and the product needs 16"
    );
    assert_eq!(
        fix_of(&finding),
        "Quota `compute` in `acme-system` allows 8 of `requests.cpu` and 6 are used, so 2 is left and the product needs 16. Ask an admin to raise it: `kubectl edit resourcequota compute -n acme-system`."
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    // The pods need fits (38 left of 50), and its row says so.
    let rows = finding.observed["quotas"]["checks"]
        .as_array()
        .expect("rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["resource"], "pods");
    assert_eq!(rows[0]["enough"], true);
    assert_eq!(rows[1]["resource"], "requests.cpu");
    assert_eq!(rows[1]["left"], "2");
    assert_eq!(rows[1]["enough"], false);
    // Namespace, quotas, limit ranges, and nothing else.
    assert_eq!(rig.paths(), [NAMESPACE, QUOTAS, LIMITS]);
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_scoped_quota_is_not_evaluated() {
    let rig = rig("quota-scoped");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 16, "requests.memory": "64Gi"}}))
        .await;
    // Nothing measured as failing, so the level is a pass that the engine shows as "not verified".
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let notes = notes(&finding);
    assert!(
        notes.contains("Quota high-priority has PriorityClass, so it applies only to the pods it selects. Not evaluated."),
        "{notes}"
    );
    assert!(
        notes.contains("Quota long-running has NotTerminating, so it applies only to the pods it selects. Not evaluated."),
        "{notes}"
    );
    let note = partial_note(&finding);
    assert!(
        note.contains(
            "quota high-priority is scoped and limits requests.cpu, so it was not evaluated"
        ),
        "{note}"
    );
    assert!(
        note.contains(
            "quota long-running is scoped and limits requests.memory, so it was not evaluated"
        ),
        "{note}"
    );
    assert!(grants(&finding).is_empty());
    assert_eq!(
        finding.observed["quotas"]["scoped"],
        json!(["high-priority", "long-running"])
    );
    assert_eq!(finding.observed["quotas"]["checks"], json!([]));
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_scoped_quota_does_not_hide_a_short_unscoped_one() {
    let rig = rig("quota-scoped-and-short");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 16}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("Quota compute in acme-system leaves 2 of requests.cpu"),
        "{}",
        finding.message
    );
    assert!(partial_note(&finding).contains("quota high-priority is scoped"));
    rig.audit();
}

#[tokio::test]
async fn openshift_uses_the_project_request_review() {
    let rig = rig("missing-openshift");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system does not exist yet, and this identity may create it"
    );
    assert!(
        notes(&finding).contains(
            "This identity may request a project, which creates it: `oc new-project acme-system`."
        ),
        "{}",
        notes(&finding)
    );
    assert_eq!(finding.observed["create"]["via"], "projectrequests");
    assert_eq!(finding.observed["create"]["answer"], "allowed");
    assert!(finding.partial.is_none(), "{finding:?}");
    // The table holds only the project request row, so a `create namespaces` review would have been a 501.
    let requests = rig.requests();
    assert_eq!(
        requests,
        [
            ("GET".to_owned(), NAMESPACE.to_owned()),
            ("GET".to_owned(), APIS.to_owned()),
            ("POST".to_owned(), REVIEW.to_owned()),
        ]
    );
    rig.audit();
}

// ---- the namespace --------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_terminating_namespace_blocks_and_nothing_inside_it_is_listed() {
    let rig = rig("terminating");
    let finding = rig
        .finding(
            json!({"quota_needs": {"pods": 10}, "limit_needs": {"container_max_memory": "1Gi"}}),
        )
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system is Terminating: it is being deleted and takes no new objects"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.contains("`kubectl get namespace acme-system -o yaml`"),
        "{fix}"
    );
    assert!(fix.contains("before anyone removes a finalizer"), "{fix}");
    // Only the conditions that are True are named.
    assert!(
        notes(&finding).contains(
            "Namespace acme-system reports these conditions: NamespaceDeletionContentFailure, NamespaceContentRemaining."
        ),
        "{}",
        notes(&finding)
    );
    assert_eq!(finding.observed["namespace_state"], "terminating");
    assert_eq!(finding.observed["quotas"], Value::Null);
    // The fixture holds no quota or limit range file, so asking for one would have failed the run.
    assert_eq!(rig.paths(), [NAMESPACE]);
    assert!(finding.partial.is_none());
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn an_active_namespace_with_nothing_in_it_passes() {
    let rig = rig("active-plain");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 16}, "limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system exists and is active; no quota in the namespace limits what the product needs; no limit range in the namespace"
    );
    assert!(finding.partial.is_none());
    assert_eq!(finding.observed["namespace_state"], "active");
    assert_eq!(finding.observed["quotas"]["count"], 0);
    assert_eq!(finding.observed["create"], Value::Null);
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn a_missing_namespace_the_identity_may_create_passes_with_a_note() {
    let rig = rig("missing-creatable");
    let finding = rig.finding(json!({"quota_needs": {"pods": 10}})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding)
            .contains("This identity may create it: `kubectl create namespace acme-system`"),
        "{}",
        notes(&finding)
    );
    assert!(
        notes(&finding).contains("A new namespace has no quota or limit range of its own yet."),
        "{}",
        notes(&finding)
    );
    assert_eq!(finding.observed["create"]["via"], "namespaces");
    assert_eq!(finding.observed["namespace_state"], "missing");
    assert_eq!(
        rig.requests(),
        [
            ("GET".to_owned(), NAMESPACE.to_owned()),
            ("GET".to_owned(), APIS.to_owned()),
            ("POST".to_owned(), REVIEW.to_owned()),
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn a_missing_namespace_the_identity_may_not_create_blocks() {
    let rig = rig("missing-denied");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system does not exist, and this identity may not create it"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.contains(
            "Ask the platform team to create `acme-system` and grant your identity admin in it"
        ),
        "{fix}"
    );
    assert!(
        fix.contains("`kubectl create namespace acme-system`"),
        "{fix}"
    );
    assert!(
        notes(&finding).contains("The cluster said: RBAC: no rule allows 'create' on 'namespaces'")
            || notes(&finding)
                .contains("The cluster said: RBAC: no rule allows \"create\" on \"namespaces\""),
        "{}",
        notes(&finding)
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn openshift_without_the_right_to_request_a_project_blocks_with_oc() {
    let rig = rig("missing-openshift-denied");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system does not exist, and this identity may not request it as a project"
    );
    let fix = fix_of(&finding);
    assert!(fix.contains("`oc new-project acme-system`"), "{fix}");
    assert!(
        fix.contains("`oc adm policy add-role-to-user admin <identity> -n acme-system`"),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn when_openshift_is_not_known_a_denied_create_is_not_a_block() {
    let rig = rig("missing-apis-forbidden");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains(
            "the API group list could not be read, so rdy cannot tell whether this is OpenShift"
        ),
        "{}",
        partial_note(&finding)
    );
    assert!(
        fix_of(&finding).contains("on OpenShift `oc new-project acme-system`"),
        "{}",
        fix_of(&finding)
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_refused_review_is_partial_not_a_block() {
    let rig = rig("missing-review-refused");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("could not check whether this identity may create it"),
        "{}",
        partial_note(&finding)
    );
    assert_eq!(finding.observed["create"]["answer"], "unknown");
    rig.audit();
}

#[tokio::test]
async fn a_namespace_the_identity_may_not_read_is_partial_and_its_quotas_are_still_judged() {
    let rig = rig("namespace-forbidden");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 16}}))
        .await;
    // The quota list was readable and is short: that is measured, so it blocks.
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(grants(&finding), ["get namespaces"]);
    assert!(
        partial_note(&finding).contains(
            "whether namespace acme-system exists and is active was not read: the identity may not read it"
        ),
        "{}",
        partial_note(&finding)
    );
    assert!(
        fix_of(&finding).contains(
            "Ask the cluster admin to grant this identity: get namespaces. Check each with `kubectl auth can-i get namespaces`."
        ),
        "{}",
        fix_of(&finding)
    );
    assert_eq!(finding.observed["namespace_state"], "forbidden");
    assert_eq!(rig.paths(), [NAMESPACE, QUOTAS, LIMITS]);
    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn a_spec_with_no_namespace_reads_nothing_and_says_so() {
    let rig = rig("no-namespace");
    let finding = rig
        .finding_in(json!({"quota_needs": {"pods": 10}}), None)
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("the spec names no namespace"),
        "{}",
        partial_note(&finding)
    );
    assert!(fix_of(&finding).contains("`namespace: <name>`"));
    assert_eq!(finding.observed["namespace_state"], "not_named");
    assert!(rig.requests().is_empty());
    rig.audit();
}

#[tokio::test]
async fn the_namespace_of_the_entry_wins_over_the_family_one() {
    let rig = rig("active-plain");
    let finding = rig
        .finding_in(json!({"namespace": "acme-system"}), Some("other"))
        .await;
    assert_eq!(finding.observed["namespace"], "acme-system");
    // And the family namespace is used when the entry has none.
    let rig = self::rig("active-plain");
    let finding = rig.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.observed["namespace"], "acme-system");
    assert_eq!(rig.paths(), [NAMESPACE, QUOTAS, LIMITS]);
}

#[tokio::test]
async fn a_namespace_called_secrets_is_read_and_its_lists_are_refused_by_the_guard() {
    let rig = rig("namespace-named-secrets");
    let mut spec = json!({"namespace": "secrets", "quota_needs": {"pods": 10}});
    spec["limit_needs"] = json!({"container_max_memory": "1Gi"});
    let finding = rig.finding_in(spec, None).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding)
            .contains("rdy never reads a path through a namespace called secrets"),
        "{}",
        partial_note(&finding)
    );
    assert_eq!(finding.observed["quotas"]["read"], "refused");
    rig.audit();
}

// ---- quotas ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_roomy_quota_passes_every_need_of_the_catalog_example() {
    let rig = rig("quota-roomy");
    let finding = rig.finding(json!({"quota_needs": needs_03()})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system exists and is active; the quotas leave room for what the product needs"
    );
    assert_eq!(
        finding.observed["quotas"]["checks"]
            .as_array()
            .expect("rows")
            .len(),
        5
    );
    assert!(finding.partial.is_none());
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn the_tightest_quota_decides_when_there_are_two() {
    let rig = rig("quota-two");
    let finding = rig.finding(json!({"quota_needs": needs_03()})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Quota object-counts in acme-system leaves 5 of pods (110 allowed, 105 used), and the product needs 100"
    );
    assert!(fix_of(&finding).contains("`kubectl edit resourcequota object-counts -n acme-system`"));
    rig.audit();
}

#[tokio::test]
async fn cpu_and_requests_cpu_are_the_same_quota_resource() {
    let rig = rig("quota-aliases");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 16, "requests.memory": "64Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Quota legacy in acme-system leaves 3 of requests.cpu (4 allowed, 1 used), and the product needs 16 (and 1 more, see the notes)"
    );
    assert!(
        notes(&finding).contains(
            "Quota legacy in acme-system leaves 7Gi of requests.memory (8Gi allowed, 1Gi used), and the product needs 64Gi"
        ),
        "{}",
        notes(&finding)
    );
    // A need written with the short name meets the long name too.
    let rig = self::rig("quota-short");
    let finding = rig.finding(json!({"quota_needs": {"cpu": 16}})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .contains("leaves 2 of cpu (8 allowed, 6 used)"),
        "{}",
        finding.message
    );
}

#[tokio::test]
async fn a_quota_nobody_filled_in_yet_is_partial() {
    let rig = rig("quota-unused");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 1}}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains(
            "quota compute limits requests.cpu, but its amounts were not readable (limit 8, used not reported)"
        ),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn quotas_the_identity_may_not_list_are_partial_with_the_grant_when_the_spec_needs_them() {
    let rig = rig("quota-forbidden");
    let finding = rig.finding(json!({"quota_needs": {"pods": 10}})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list resourcequotas"]);
    assert!(
        fix_of(&finding).contains(
            "Ask the cluster admin to grant this identity: list resourcequotas. Check each with `kubectl auth can-i list resourcequotas -n <namespace>`."
        ),
        "{}",
        fix_of(&finding)
    );
    assert_eq!(finding.observed["quotas"]["read"], "forbidden");
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    // With no quota need the same refusal is only a note.
    let rig = self::rig("quota-forbidden");
    let finding = rig.finding(json!({})).await;
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(
        notes(&finding).contains("The quotas of namespace acme-system were not listed"),
        "{}",
        notes(&finding)
    );
}

#[tokio::test]
async fn a_cut_quota_list_is_partial() {
    let rig = rig("quota-cut");
    let finding = rig.finding(json!({"quota_needs": {"pods": 10}})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("more than 500 quotas and only the first 500 were read"),
        "{}",
        partial_note(&finding)
    );
    assert_eq!(finding.observed["quotas"]["cut"], true);
    rig.audit();
}

#[tokio::test]
async fn a_quota_without_a_need_in_the_spec_is_listed_and_not_judged() {
    let rig = rig("quota-short");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("Namespace acme-system has 1 unscoped quota(s): compute. The spec states no quota need, so none was judged."),
        "{}",
        notes(&finding)
    );
    assert!(finding.partial.is_none());
    rig.audit();
}

#[tokio::test]
async fn hostile_names_and_amounts_never_reach_a_sentence_or_a_command_raw() {
    let rig = rig("quota-hostile");
    let finding = rig
        .finding(json!({"quota_needs": {"requests.cpu": 16, "requests.memory": "1Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    let everything = format!(
        "{}\n{}\n{}\n{}\n{}",
        finding.message,
        notes(&finding),
        fix_of(&finding),
        finding.observed,
        partial_note(&finding)
    );
    assert!(!everything.contains('\u{1b}'), "{everything:?}");
    assert!(!everything.contains('\u{202e}'), "{everything:?}");
    assert!(!everything.contains("`rm -rf /`"), "{everything:?}");
    assert!(!everything.contains(&"x".repeat(65)), "{everything:?}");
    // The command takes a placeholder for a name that is not a name.
    assert!(
        fix_of(&finding).contains("`kubectl edit resourcequota <name> -n acme-system`"),
        "{}",
        fix_of(&finding)
    );
    // The amount that is not one is unreadable, and said so with its text made safe.
    assert!(
        partial_note(&finding).contains("quota garbled limits requests.memory, but its amounts were not readable (limit lots, used \\x1b[2J1Gi)"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

// ---- limit ranges ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_container_max_below_the_largest_container_blocks() {
    let rig = rig("limit-low");
    let finding = rig
        .finding(json!({"limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "LimitRange container-caps in acme-system caps a container at 8Gi of memory, and the product's largest container needs 16Gi"
    );
    assert_eq!(
        fix_of(&finding),
        "LimitRange `container-caps` in `acme-system` caps a container at 8Gi of memory, and the product's largest container needs 16Gi. Ask an admin to raise its max: `kubectl edit limitrange container-caps -n acme-system`."
    );
    // The default limit is a note: the spec does not say the product sets requests and no limits.
    assert!(
        notes(&finding).contains("gives a container with no memory limit a default limit of 512Mi"),
        "{}",
        notes(&finding)
    );
    assert_eq!(rig.paths(), [NAMESPACE, QUOTAS, LIMITS]);
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn a_pod_max_below_the_largest_container_blocks_too() {
    let rig = rig("limit-pod-low");
    let finding = rig
        .finding(json!({"limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding.message.contains("caps a pod at 8Gi of memory"),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_default_limit_below_the_need_is_a_note_not_a_finding() {
    let rig = rig("limit-default-low");
    let finding = rig
        .finding(json!({"limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let notes = notes(&finding);
    assert!(
        notes.contains("A container that sets a memory request of 16Gi and no limit gets that default as its limit, and the pod is rejected."),
        "{notes}"
    );
    assert!(
        notes.contains("`kubectl edit limitrange defaults -n acme-system`"),
        "{notes}"
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn limit_ranges_that_allow_the_container_pass() {
    let rig = rig("limit-ok");
    let finding = rig
        .finding(json!({"limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .message
            .ends_with("the limit ranges allow a container of 16Gi"),
        "{}",
        finding.message
    );
    assert!(
        !notes(&finding).contains("default limit"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn limit_ranges_the_identity_may_not_list_are_partial_with_the_grant() {
    let rig = rig("limit-forbidden");
    let finding = rig
        .finding(json!({"limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list limitranges"]);
    assert_eq!(finding.observed["limit_ranges"]["read"], "forbidden");
    // With no limit need it is a note.
    let rig = self::rig("limit-forbidden");
    let finding = rig.finding(json!({})).await;
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(
        notes(&finding).contains("The limit ranges of namespace acme-system were not listed"),
        "{}",
        notes(&finding)
    );
}

#[tokio::test]
async fn a_cut_limit_range_list_is_partial() {
    let rig = rig("limit-cut");
    let finding = rig
        .finding(json!({"limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert!(
        partial_note(&finding).contains("more than 500 limit ranges"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_hostile_limit_range_is_made_safe() {
    let rig = rig("limit-hostile");
    let finding = rig
        .finding(json!({"limit_needs": {"container_max_memory": "16Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    let everything = format!(
        "{}\n{}\n{}\n{}",
        finding.message,
        notes(&finding),
        fix_of(&finding),
        partial_note(&finding)
    );
    assert!(!everything.contains('\u{1b}'), "{everything:?}");
    assert!(!everything.contains("`rm -rf /`"), "{everything:?}");
    assert!(
        fix_of(&finding).contains("`kubectl edit limitrange <name> -n acme-system`"),
        "{}",
        fix_of(&finding)
    );
    assert!(
        partial_note(&finding)
            .contains("a limit range holds a memory amount that rdy could not read"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

// ---- the whole run ------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_request_is_bounded_and_every_cluster_is_audited() {
    // The cases are the directories of the fixture folder, so a new case cannot skip the audit.
    let cases = rdy_engine::testing::fixture_cases("k8s.namespace");
    assert!(cases.len() >= 28, "the cases were found: {cases:?}");
    for case in cases.iter().map(String::as_str) {
        let rig = rig(case);
        let mut spec = json!({
            "quota_needs": needs_03(),
            "limit_needs": {"container_max_memory": "16Gi"},
        });
        let finding = match case {
            "no-namespace" => rig.finding_in(spec, None).await,
            "namespace-named-secrets" => {
                spec["namespace"] = json!("secrets");
                rig.finding_in(spec, None).await
            }
            _ => rig.finding(spec).await,
        };
        assert!(
            !finding.message.is_empty() && finding.message.len() < 500,
            "{case}: {}",
            finding.message
        );
        let requests = rig.requests();
        assert!(
            requests.len() <= 5,
            "{case}: at most five requests: {requests:?}"
        );
        // GET, except the one access review, which carries no query and goes to the review path.
        for (method, path) in &requests {
            assert!(
                method == "GET" || (method == "POST" && path == REVIEW),
                "{case}: {method} {path}"
            );
        }
        assert!(
            requests
                .iter()
                .filter(|(method, _)| method == "POST")
                .count()
                <= 1,
            "{case}: {requests:?}"
        );
        if case != "namespace-named-secrets" {
            assert!(
                !requests.iter().any(|(_, path)| path.contains("secrets")),
                "{case}: {requests:?}"
            );
        }
        rig.audit();
    }
}

#[test]
fn the_info_is_the_one_the_registry_holds() {
    assert_eq!(NamespaceCheck::info().id, "k8s.namespace");
    assert!(
        crate::registry::infos()
            .iter()
            .any(|info| std::ptr::eq(*info, NamespaceCheck::info()))
    );
    assert_eq!(INFO.needs, &[Need::KubeContext]);
    assert!(INFO.wants.is_empty());
    assert_eq!(INFO.default_timeout, Some(Duration::from_secs(15)));
    assert!(INFO.peers.is_empty());
    assert!(INFO.commands.is_empty());
}
