//! Fixture tests of `k8s.admission`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.admission/`, written by
//! `scripts/gen-k8s-admission-fixtures.py`. Every `Rig` audits its run when it drops (INV-14): each request
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
const APIS: &str = "/apis";
const SCC: &str = "/apis/security.openshift.io/v1/securitycontextconstraints";

/// A cluster over the mock: the version the test says, and the harness for the rest.
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

fn version(git: &str) -> ServerVersion {
    let minor = git
        .trim_start_matches('v')
        .split('.')
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    ServerVersion {
        git_version: git.to_owned(),
        major: "1".to_owned(),
        minor,
        platform: "linux/amd64".to_owned(),
    }
}

fn rig_at(case: &str, git: &str) -> Rig {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.admission/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.admission", Os::Linux, [Need::KubeContext]);
    Rig {
        cluster: Arc::new(Fixtured {
            harness,
            version: version(git),
        }),
        ctx,
    }
}

fn rig(case: &str) -> Rig {
    rig_at(case, "v1.30.2")
}

fn params(spec: Value) -> K8sAdmission {
    serde_json::from_value(spec).expect("the parameters parse")
}

impl Rig {
    fn check(&self, spec: Value, family_namespace: Option<&str>) -> AdmissionCheck {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let namespace =
            family_namespace.map(|name| serde_json::from_value(json!(name)).expect("a name"));
        AdmissionCheck::new(params(spec), namespace, cluster)
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

    /// The `(method, path)` of every request, in order, all logged under `k8s.admission`.
    fn requests(&self) -> Vec<(String, String)> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.admission")),
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

/// What the engine makes of a finding for an entry with this severity.
fn engine(rig: &Rig, finding: Finding, severity: Option<&str>) -> rdy_spec::result::CheckResult {
    let mut entry = json!({"id": "k8s.admission"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

// ---- the exit test ----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_restricted_namespace_blocks_a_privileged_need_and_the_fix_says_privileged() {
    let rig = rig("restricted");
    let finding = rig
        .finding(json!({"uses": ["hostPath", "privileged"]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system enforces restricted, and the product needs privileged"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains(
            "`kubectl label ns acme-system pod-security.kubernetes.io/enforce=privileged --overwrite`"
        ),
        "{fix}"
    );
    assert!(
        fix.contains("it uses hostPath volumes and privileged containers"),
        "{fix}"
    );
    assert!(
        fix.contains("ask the vendor for chart values that fit `restricted`"),
        "{fix}"
    );
    // The warn and audit labels are in the notes, with their own commands, behind the one fix that matters.
    assert!(
        notes(&finding).contains(
            "`kubectl label ns acme-system pod-security.kubernetes.io/warn=privileged --overwrite`"
        ),
        "{finding:?}"
    );
    assert!(
        notes(&finding).contains(
            "`kubectl label ns acme-system pod-security.kubernetes.io/audit=privileged --overwrite`"
        ),
        "{finding:?}"
    );
    assert_eq!(finding.observed["pod_security"]["enforce"], "restricted");
    assert_eq!(
        finding.observed["pod_security"]["enforce_version"],
        "latest"
    );
    assert_eq!(finding.observed["need"]["level"], "privileged");
    assert_eq!(
        finding.observed["need"]["uses"],
        json!(["hostPath", "privileged"])
    );
    assert_eq!(finding.observed["openshift"], false);
    assert!(finding.partial.is_none());
    // Namespace first, then the group list, and nothing else on a plain cluster.
    assert_eq!(rig.paths(), [NAMESPACE, APIS]);
    // The engine blocks on a block-severity entry and warns on a warn-severity one.
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn openshift_discovery_gives_the_scc_text() {
    let rig = rig("openshift");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "This is OpenShift: security context constraints decide whether the product's pods are admitted, and the spec names none"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(fix.contains("`restricted-v2` is the default"), "{fix}");
    assert!(
        fix.contains("requires a UID in the namespace range"),
        "{fix}"
    );
    assert!(fix.contains("drops all capabilities"), "{fix}");
    assert!(fix.contains("pins `runAsUser`"), "{fix}");
    assert!(fix.contains("First remove `runAsUser`"), "{fix}");
    assert!(
        fix.contains("`oc adm policy add-scc-to-user <scc> -z <service-account> -n acme-system`"),
        "{fix}"
    );
    assert_eq!(finding.observed["openshift"], true);
    assert_eq!(finding.observed["uid_range"], "1000680000/10000");
    // The synced warn and audit labels are notes: the SCC is the gate.
    assert!(
        notes(&finding).contains("Namespace acme-system sets warn to restricted. On OpenShift that label is synced from the SCCs, so pods are not rejected for it, if it was not edited by hand."),
        "{finding:?}"
    );
    assert!(
        notes(&finding).contains("allocates the UID range 1000680000/10000"),
        "{finding:?}"
    );
    // No SCC is named, so the SCC list is not read.
    assert_eq!(rig.paths(), [NAMESPACE, APIS]);
    assert!(finding.partial.is_none());
    rig.audit();
}

#[tokio::test]
async fn gatekeeper_and_kyverno_discovery_warn_with_names() {
    let rig = rig("both-engines");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Policy engine found: Kyverno (kyverno.io, policies.kyverno.io); Gatekeeper (templates.gatekeeper.sh, constraints.gatekeeper.sh). Their policies can reject the product's pods"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("which Kyverno and Gatekeeper policies apply to namespace `acme-system`"),
        "{fix}"
    );
    assert!(
        fix.contains("`kubectl get clusterpolicies.kyverno.io,policies.kyverno.io -A`"),
        "{fix}"
    );
    assert!(
        fix.contains("`kubectl get validatingpolicies.policies.kyverno.io`"),
        "{fix}"
    );
    assert!(fix.contains("`kubectl get constraints`"), "{fix}");
    assert!(
        fix.contains("`kubectl apply --dry-run=server -n acme-system -f <manifest>`"),
        "{fix}"
    );
    let notes = notes(&finding);
    assert!(
        notes.contains(
            "Kyverno serves these kinds in kyverno.io: CleanupPolicy, ClusterCleanupPolicy, PolicyException, UpdateRequest."
        ),
        "{notes}"
    );
    assert!(
        notes.contains(
            "Kyverno serves these kinds in policies.kyverno.io: MutatingPolicy, ValidatingPolicy."
        ),
        "{notes}"
    );
    assert!(
        notes.contains(
            "Gatekeeper serves these kinds in constraints.gatekeeper.sh: K8sAllowedRepos, K8sRequiredLabels."
        ),
        "{notes}"
    );
    let engines = &finding.observed["policy_engines"];
    assert_eq!(engines[0]["name"], "Kyverno");
    assert_eq!(engines[1]["name"], "Gatekeeper");
    // The namespace, the group list, one read per engine group (kyverno.io twice: its preferred version
    // v2 and then v1, where ClusterPolicy lives), never a policy.
    assert_eq!(
        rig.paths(),
        [
            NAMESPACE,
            APIS,
            "/apis/kyverno.io/v2",
            "/apis/kyverno.io/v1",
            "/apis/policies.kyverno.io/v1",
            "/apis/templates.gatekeeper.sh/v1",
            "/apis/constraints.gatekeeper.sh/v1beta1",
        ]
    );
    rig.audit();
}

// ---- Pod Security labels ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_namespace_that_fits_the_need_passes() {
    for (case, need, enforce) in [
        ("baseline", json!({"pod_security": "baseline"}), "baseline"),
        ("privileged", json!({"uses": ["hostPath"]}), "privileged"),
        (
            "restricted",
            json!({"pod_security": "restricted"}),
            "restricted",
        ),
        ("baseline", json!({"uses": ["runAsRoot"]}), "baseline"),
        ("restricted", json!({}), "restricted"),
    ] {
        let rig = rig(case);
        let finding = rig.finding(need.clone()).await;
        assert_eq!(finding.level, Level::Pass, "{case} {need}: {finding:?}");
        assert_eq!(finding.observed["pod_security"]["enforce"], enforce);
        assert!(finding.partial.is_none(), "{case} {need}");
        assert_eq!(rig.paths(), [NAMESPACE, APIS]);
        rig.audit();
    }
}

#[tokio::test]
async fn the_pass_message_says_what_was_found() {
    let rig = rig("baseline");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(
        finding.message,
        "Namespace acme-system enforces baseline, and the product needs baseline; no policy engine or OpenShift found"
    );
    assert_eq!(finding.observed["pod_security"]["warn"], "none");
    assert_eq!(finding.observed["pod_security"]["enforce_version"], "v1.29");
    // The webhooks of M1-160 are said not to be evaluated.
    assert!(
        notes(&finding).contains(
            "Admission webhooks and ValidatingAdmissionPolicy are not evaluated by this version."
        ),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn an_enforce_level_stricter_than_baseline_blocks_a_run_as_root_need() {
    let rig = rig("restricted");
    let finding = rig.finding(json!({"uses": ["runAsRoot"]})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system enforces restricted, and the product needs baseline"
    );
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("enforce=baseline --overwrite"), "{fix}");
    assert!(fix.contains("containers that run as root"), "{fix}");
    assert!(
        fix.contains("`restricted` requires `runAsNonRoot`"),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_stated_level_blocks_without_uses() {
    let rig = rig("restricted");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains("The spec says the product needs `baseline`."),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_stricter_warn_or_audit_label_warns() {
    let rig = rig("warn-audit");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system sets warn to restricted, and the product needs baseline: pods still start, and the person who installs sees a warning (and 1 more, see the notes)"
    );
    assert!(
        notes(&finding).contains("Namespace acme-system sets audit to restricted, and the product needs baseline: pods still start, and each one adds an audit log entry"),
        "{finding:?}"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains(
            "`kubectl label ns acme-system pod-security.kubernetes.io/warn=baseline --overwrite`"
        ),
        "{fix}"
    );
    assert!(
        fix.contains(
            "`kubectl label ns acme-system pod-security.kubernetes.io/audit=baseline --overwrite`"
        ),
        "{fix}"
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_warn_label_the_product_fits_is_not_a_finding() {
    // warn and audit at restricted, and the product needs restricted: nothing to say.
    let rig = rig("restricted");
    let finding = rig.finding(json!({"pod_security": "restricted"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn no_labels_is_the_cluster_default_and_a_note() {
    let rig = rig("no-labels");
    let finding = rig.finding(json!({"uses": ["hostNetwork"]})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system sets no Pod Security enforce label, and the product needs privileged; no policy engine or OpenShift found"
    );
    assert!(
        notes(&finding).contains("cluster default not readable"),
        "{finding:?}"
    );
    assert!(finding.partial.is_none());
    assert_eq!(finding.observed["pod_security"]["enforce"], "none");
    assert_eq!(
        finding.observed["pod_security"]["enforce_version"],
        Value::Null
    );
    rig.audit();
}

#[tokio::test]
async fn a_namespace_with_no_labels_member_reads_the_same() {
    let rig = rig("no-metadata-labels");
    let finding = rig.finding(json!({"uses": ["hostNetwork"]})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["pod_security"]["enforce"], "none");
    rig.audit();
}

#[tokio::test]
async fn no_labels_need_no_note_when_the_product_fits_restricted() {
    let rig = rig("no-labels");
    let finding = rig.finding(json!({"pod_security": "restricted"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(!notes(&finding).contains("cluster default"), "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn on_rke2_a_namespace_with_no_label_is_not_verified() {
    let rig = rig_at("no-labels", "v1.30.2+rke2r1");
    let finding = rig.finding(json!({"uses": ["hostPath"]})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial
            .note
            .contains("RKE2 enforces `restricted` by default only with the CIS profile"),
        "{partial:?}"
    );
    assert!(partial.missing_grants.is_empty());
    assert!(
        notes(&finding)
            .contains("It also holds exemptions (namespaces, usernames and runtime classes)"),
        "{finding:?}"
    );
    // A pass that is not verified is a warning in the report.
    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Warn);
    assert!(
        result.message.starts_with("not verified:"),
        "{}",
        result.message
    );
    rig.audit();
}

#[tokio::test]
async fn an_invalid_enforce_label_is_read_as_restricted() {
    let rig = rig("invalid-labels");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system has an invalid Pod Security enforce label, which the API server reads as restricted, and the product needs baseline"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(fix.contains("enforce=baseline --overwrite"), "{fix}");
    assert!(
        notes(&finding)
            .contains("is not a Pod Security level. The API server reads it as `restricted`"),
        "{finding:?}"
    );
    assert_eq!(finding.observed["pod_security"]["enforce"], "invalid");
    assert_eq!(
        finding.observed["pod_security"]["enforce_version"],
        "invalid"
    );
    // Invalid audit and warn values are read as privileged and never shown.
    assert_eq!(finding.observed["pod_security"]["audit"], "invalid");
    let everything = format!("{finding:?}");
    assert!(!everything.contains("rm -rf"), "{everything}");
    assert!(!everything.contains("2Jstrict"), "{everything}");
    rig.audit();
}

#[tokio::test]
async fn an_invalid_enforce_label_passes_a_product_that_fits_restricted() {
    let rig = rig("invalid-labels");
    let finding = rig.finding(json!({"pod_security": "restricted"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .message
            .contains("has an invalid enforce label, read as restricted, which the product fits"),
        "{}",
        finding.message
    );
    // It is still a thing to fix.
    assert!(
        notes(&finding).contains("is not a Pod Security level"),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn an_invalid_warn_label_is_read_as_privileged_and_never_warns() {
    let rig = rig("invalid-warn");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["pod_security"]["warn"], "invalid");
    assert!(
        notes(&finding).contains(
            "The warn label of namespace acme-system is not a Pod Security level. The API server reads it as `privileged`, so it never warns."
        ),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_missing_namespace_is_a_note_and_not_a_block() {
    let rig = rig("namespace-missing");
    let finding = rig.finding(json!({"uses": ["privileged"]})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system does not exist yet; no policy engine or OpenShift found"
    );
    assert!(
        notes(&finding).contains("A new namespace takes the cluster default"),
        "{finding:?}"
    );
    assert!(finding.partial.is_none());
    assert_eq!(finding.observed["namespace_read"], "missing");
    assert_eq!(rig.paths(), [NAMESPACE, APIS]);
    rig.audit();
}

#[tokio::test]
async fn a_namespace_the_identity_may_not_read_is_partial_with_the_grant() {
    let rig = rig("namespace-forbidden");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    // Nothing was measured as failing, so the level is a pass that the engine turns into "not verified".
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get namespaces"]);
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial.note.contains("the Pod Security labels of namespace acme-system were not read: the identity may not read it"),
        "{partial:?}"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("Ask the cluster admin to grant this identity: get namespaces. Check each with `kubectl auth can-i get namespaces`."),
        "{fix}"
    );
    assert_eq!(finding.observed["namespace_read"], "forbidden");
    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Warn);
    assert_eq!(
        result.partial.expect("partial").missing_grants,
        ["get namespaces"]
    );
    rig.audit();
}

#[tokio::test]
async fn an_identity_that_can_only_get_namespaces_never_blocks_on_what_it_could_not_read() {
    // The group list is refused. The namespace is read and judged, and what is not read is said.
    let rig = rig("apis-forbidden");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get /apis"]);
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial
            .note
            .contains("policy engines and OpenShift were not checked"),
        "{partial:?}"
    );
    assert_eq!(finding.observed["openshift"], Value::Null);
    assert_eq!(finding.observed["policy_engines"], Value::Null);
    assert_eq!(rig.paths(), [NAMESPACE, APIS]);
    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_block_stays_a_block_when_something_else_could_not_be_read() {
    let rig = rig("apis-forbidden");
    let finding = rig.finding(json!({"uses": ["hostPath"]})).await;
    // enforce=baseline against a product that needs privileged: measured, so it blocks.
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(grants(&finding), ["get /apis"]);
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn no_namespace_means_no_namespace_request() {
    let rig = rig("no-namespace");
    // A level to judge and nowhere to read it: not verified, with the fix that names the key.
    let finding = rig
        .finding_in(json!({"pod_security": "baseline"}), None)
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial.note.contains("the spec names no namespace"),
        "{partial:?}"
    );
    assert!(partial.missing_grants.is_empty());
    assert!(
        finding
            .fix
            .clone()
            .expect("a fix")
            .contains("`namespace: <name>`"),
    );
    assert_eq!(finding.observed["namespace_read"], "not_named");
    assert_eq!(rig.paths(), [APIS]);
    rig.audit();
}

#[tokio::test]
async fn a_spec_with_no_level_judges_no_label_and_reports_what_it_found() {
    let rig = rig("no-namespace");
    let finding = rig.finding_in(json!({}), None).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "The spec states no Pod Security level to judge; no policy engine or OpenShift found"
    );
    assert!(finding.partial.is_none());
    rig.audit();

    let labelled = self::rig("baseline");
    let finding = labelled.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system has Pod Security enforce baseline, warn none, audit none; no policy engine or OpenShift found"
    );
    labelled.audit();
}

#[tokio::test]
async fn a_forbidden_namespace_is_only_a_note_when_there_is_no_level_to_judge() {
    let rig = rig("namespace-forbidden");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert!(
        notes(&finding).contains("The Pod Security labels of namespace acme-system were not read"),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn the_family_namespace_is_used_when_the_entry_names_none() {
    let rig = rig("restricted");
    let finding = rig
        .finding_in(json!({"uses": ["hostPath"]}), Some("acme-system"))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(rig.paths(), [NAMESPACE, APIS]);
    rig.audit();
}

#[tokio::test]
async fn the_entry_namespace_wins_over_the_family_namespace() {
    // The fixture has only acme-system. A read of the family namespace would be unrecorded and fail the audit.
    let rig = rig("restricted");
    let finding = rig
        .finding_in(
            json!({"uses": ["hostPath"], "namespace": "acme-system"}),
            Some("other"),
        )
        .await;
    assert_eq!(finding.observed["namespace"], "acme-system");
    assert_eq!(rig.paths(), [NAMESPACE, APIS]);
    rig.audit();
}

// ---- OpenShift and its SCCs ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_named_scc_on_the_cluster_passes_and_says_how_to_bind_it() {
    let rig = rig("openshift");
    let finding = rig
        .finding(json!({"pod_security": "baseline", "scc": "anyuid"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system sets no Pod Security enforce label, and the product needs baseline; OpenShift, and the product documents the SCC anyuid"
    );
    let notes = notes(&finding);
    assert!(
        notes
            .contains("`oc adm policy add-scc-to-user anyuid -z <service-account> -n acme-system`"),
        "{notes}"
    );
    assert!(
        notes.contains("The SCC `anyuid` exists on this cluster."),
        "{notes}"
    );
    assert!(
        notes.contains("On OpenShift the global default enforces `privileged`"),
        "{notes}"
    );
    assert_eq!(finding.observed["scc_on_cluster"], true);
    assert_eq!(rig.paths(), [NAMESPACE, APIS, SCC]);
    rig.audit();
}

#[tokio::test]
async fn a_named_scc_that_is_not_on_the_cluster_is_a_note() {
    let rig = rig("openshift");
    let finding = rig
        .finding(json!({"pod_security": "baseline", "scc": "acme-scc"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("The SCC `acme-scc` is not on this cluster. That is expected if the product's installer creates it."),
        "{finding:?}"
    );
    assert_eq!(finding.observed["scc_on_cluster"], false);
    rig.audit();
}

#[tokio::test]
async fn an_scc_list_the_identity_may_not_read_is_a_note_and_not_partial() {
    let rig = rig("openshift-scc-forbidden");
    let finding = rig
        .finding(json!({"pod_security": "baseline", "scc": "anyuid"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert!(
        notes(&finding).contains("rdy could not list the SCCs (the identity may not read it), so it did not check that `anyuid` exists."),
        "{finding:?}"
    );
    assert_eq!(finding.observed["scc_on_cluster"], Value::Null);
    rig.audit();
}

#[tokio::test]
async fn an_scc_that_is_not_on_the_first_page_is_not_called_missing() {
    let rig = rig("openshift-scc-cut");
    let finding = rig
        .finding(json!({"pod_security": "baseline", "scc": "acme-scc"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("the list is longer than the first page"),
        "{finding:?}"
    );
    assert_eq!(finding.observed["scc_on_cluster"], Value::Null);
    // Found on the first page is found, whatever follows.
    let found = rig
        .finding(json!({"pod_security": "baseline", "scc": "anyuid"}))
        .await;
    assert_eq!(found.observed["scc_on_cluster"], true);
    rig.audit();
}

#[tokio::test]
async fn an_scc_in_the_spec_is_ignored_off_openshift() {
    let rig = rig("baseline");
    let finding = rig
        .finding(json!({"pod_security": "baseline", "scc": "anyuid"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains(
            "The spec names the SCC `anyuid`. It is ignored: this cluster is not OpenShift."
        ),
        "{finding:?}"
    );
    // The SCC list is never read there.
    assert_eq!(rig.paths(), [NAMESPACE, APIS]);
    rig.audit();
}

#[tokio::test]
async fn pod_security_labels_still_block_on_openshift() {
    let rig = rig("openshift-enforce");
    let finding = rig
        .finding(json!({"uses": ["hostPath"], "scc": "anyuid"}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system enforces restricted, and the product needs privileged"
    );
    rig.audit();
}

#[tokio::test]
async fn openshift_with_label_sync_off_judges_the_warn_and_audit_labels() {
    let rig = rig("openshift-sync-off");
    let finding = rig
        .finding(json!({"pod_security": "baseline", "scc": "anyuid"}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system sets warn to restricted, and the product needs baseline: pods still start, and the person who installs sees a warning (and 1 more, see the notes)"
    );
    assert!(
        !notes(&finding).contains("synced from the SCCs"),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_synced_label_note_says_it_holds_if_nobody_edited_the_label() {
    let rig = rig("openshift");
    let finding = rig
        .finding(json!({"pod_security": "baseline", "scc": "anyuid"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("so pods are not rejected for it, if it was not edited by hand."),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_range_annotation_that_is_not_a_range_is_dropped() {
    let rig = rig("openshift-hostile-range");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.observed["uid_range"], Value::Null);
    assert!(!notes(&finding).contains("oc delete"), "{finding:?}");
    assert!(!format!("{finding:?}").contains("oc delete"), "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn openshift_with_an_engine_lists_both_and_the_openshift_text_is_in_the_fix() {
    let rig = rig("openshift-and-engine");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.ends_with("(and 1 more, see the notes)"),
        "{}",
        finding.message
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(fix.contains("`restricted-v2` is the default"), "{fix}");
    assert!(fix.contains("Gatekeeper policies apply"), "{fix}");
    rig.audit();
}

// ---- policy engines -----------------------------------------------------------------------------------------

#[tokio::test]
async fn kyverno_alone_is_named_with_its_groups() {
    let rig = rig("kyverno");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(
        finding.message,
        "Policy engine found: Kyverno (kyverno.io, policies.kyverno.io). Its policies can reject the product's pods"
    );
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("which Kyverno policies apply"), "{fix}");
    assert!(
        fix.contains("`kubectl get clusterpolicies.kyverno.io,policies.kyverno.io -A`"),
        "{fix}"
    );
    assert!(!fix.contains("kubectl get constraints"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn kyverno_that_prefers_v2_and_keeps_clusterpolicy_in_v1_gets_the_legacy_command() {
    // Kyverno 1.12 to 1.19: the server prefers kyverno.io/v2, which has no ClusterPolicy. The check reads
    // v1 as well.
    let rig = rig("kyverno");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("clusterpolicies.kyverno.io"), "{fix}");
    assert!(
        fix.contains("`kubectl get validatingpolicies.policies.kyverno.io`"),
        "{fix}"
    );
    assert_eq!(
        rig.paths(),
        [
            NAMESPACE,
            APIS,
            "/apis/kyverno.io/v2",
            "/apis/kyverno.io/v1",
            "/apis/policies.kyverno.io/v1",
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn kyverno_whose_v1_cannot_be_read_is_unknown_and_keeps_the_command() {
    let rig = rig("kyverno-v1-forbidden");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("clusterpolicies.kyverno.io"), "{fix}");
    assert!(finding.partial.is_none());
    assert_eq!(
        rig.paths(),
        [
            NAMESPACE,
            APIS,
            "/apis/kyverno.io/v2",
            "/apis/kyverno.io/v1"
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn kyverno_without_the_legacy_kinds_gets_no_command_for_them() {
    let rig = rig("kyverno-no-legacy");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Policy engine found: Kyverno (kyverno.io, policies.kyverno.io). Its policies can reject the product's pods"
    );
    let fix = finding.fix.expect("a fix");
    assert!(!fix.contains("clusterpolicies"), "{fix}");
    assert!(
        fix.contains("`kubectl get validatingpolicies.policies.kyverno.io`"),
        "{fix}"
    );
    // v1 is not served, so it is not asked.
    assert_eq!(
        rig.paths(),
        [
            NAMESPACE,
            APIS,
            "/apis/kyverno.io/v2",
            "/apis/policies.kyverno.io/v1",
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn kyverno_with_only_the_legacy_group_reads_one_group() {
    let rig = rig("kyverno-legacy-only");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Policy engine found: Kyverno (kyverno.io). Its policies can reject the product's pods"
    );
    let fix = finding.fix.expect("a fix");
    assert!(!fix.contains("validatingpolicies"), "{fix}");
    assert!(fix.contains("clusterpolicies.kyverno.io"), "{fix}");
    assert_eq!(rig.paths(), [NAMESPACE, APIS, "/apis/kyverno.io/v1"]);
    rig.audit();
}

#[tokio::test]
async fn gatekeeper_alone_is_named_with_its_constraint_kinds() {
    let rig = rig("gatekeeper");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(
        finding.message,
        "Policy engine found: Gatekeeper (templates.gatekeeper.sh, constraints.gatekeeper.sh). Its policies can reject the product's pods"
    );
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("`kubectl get constraints`"), "{fix}");
    assert!(!fix.contains("kyverno"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn an_engine_whose_groups_cannot_be_read_is_still_found() {
    let rig = rig("engine-forbidden");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.starts_with("Policy engine found: Kyverno"),
        "{}",
        finding.message
    );
    // Not being able to name the kinds is not a gap in what the check measures.
    assert!(finding.partial.is_none());
    // Whether the legacy kinds exist is unknown, so the command stays.
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("`kubectl get clusterpolicies.kyverno.io,policies.kyverno.io -A`"),
        "{fix}"
    );
    assert!(
        !notes(&finding).contains("serves these kinds"),
        "{finding:?}"
    );
    assert_eq!(finding.observed["policy_engines"][0]["kinds"], json!([]));
    rig.audit();
}

#[tokio::test]
async fn kinds_are_sorted_cut_at_eight_and_counted() {
    let rig = rig("many-kinds");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    // 16 kinds: a name shaped like a kind (a letter, then letters and digits, at most 63 characters) comes
    // first. The four hostile names (escape bytes, backticks, a bidi mark, 100 characters) are not shaped
    // like one, so they sort after the twelve real ones whatever their bytes, and are counted in "more".
    assert!(
        notes(&finding).contains(
            "Gatekeeper serves these kinds in constraints.gatekeeper.sh: K8sCheck00, K8sCheck01, K8sCheck02, K8sCheck03, K8sCheck04, K8sCheck05, K8sCheck06, K8sCheck07 and 8 more."
        ),
        "{}",
        notes(&finding)
    );
    let kinds = finding.observed["policy_engines"][0]["kinds"]
        .as_array()
        .expect("a list")
        .len();
    assert_eq!(kinds, 9, "the template kind, and eight constraint kinds");
    rig.audit();
}

#[tokio::test]
async fn a_hostile_kind_name_never_reaches_a_sentence_raw() {
    let rig = rig("hostile-kinds");
    let finding = rig.finding(json!({"pod_security": "baseline"})).await;
    let everything = format!(
        "{}\n{}\n{}\n{}",
        finding.message,
        notes(&finding),
        finding.fix.clone().unwrap_or_default(),
        finding.observed
    );
    assert!(!everything.contains('\u{1b}'), "{everything:?}");
    assert!(!everything.contains('\u{202e}'), "{everything:?}");
    // The backticks of a kind name are turned into quotes, so the name cannot open a command span.
    assert!(!everything.contains("`rm -rf /`"), "{everything:?}");
    assert!(
        notes(&finding).contains("'rm -rf /'"),
        "{}",
        notes(&finding)
    );
    assert!(
        notes(&finding).contains("Evil\\x1b[2JKind"),
        "{}",
        notes(&finding)
    );
    assert!(
        notes(&finding).contains("A\\u{202e}B"),
        "{}",
        notes(&finding)
    );
    // The 100-character name is cut at 64 and says so.
    assert!(
        notes(&finding).contains(&format!("{}...", "L".repeat(64))),
        "{}",
        notes(&finding)
    );
    assert!(!everything.contains(&"L".repeat(65)), "{everything:?}");
    rig.audit();
}

// ---- the whole run ------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_request_is_a_get_and_every_cluster_is_audited() {
    // The cases are the directories of the fixture folder, so a new case cannot skip the audit.
    let cases = rdy_engine::testing::fixture_cases("k8s.admission");
    assert!(cases.len() >= 28, "the cases were found: {cases:?}");
    for case in cases.iter().map(String::as_str) {
        let rig = rig(case);
        let spec = if case == "no-namespace" {
            json!({"pod_security": "baseline"})
        } else {
            json!({"pod_security": "baseline", "scc": "anyuid"})
        };
        let finding = if case == "no-namespace" {
            rig.finding_in(spec, None).await
        } else {
            rig.finding(spec).await
        };
        assert!(
            !finding.message.is_empty() && finding.message.len() < 400,
            "{case}: {}",
            finding.message
        );
        let paths = rig.paths();
        assert!(
            paths.len() <= 8,
            "{case}: at most eight requests: {paths:?}"
        );
        assert!(
            !paths.iter().any(|path| path.contains("secrets")),
            "{case}: {paths:?}"
        );
        rig.audit();
    }
}

#[test]
fn the_info_is_the_one_the_registry_holds() {
    assert_eq!(AdmissionCheck::info().id, "k8s.admission");
    assert!(
        crate::registry::infos()
            .iter()
            .any(|info| std::ptr::eq(*info, AdmissionCheck::info()))
    );
    assert_eq!(INFO.needs, &[Need::KubeContext]);
    assert!(INFO.wants.is_empty());
    assert_eq!(INFO.default_timeout, Some(Duration::from_secs(30)));
    assert!(INFO.peers.is_empty());
}
