//! Fixture tests of `k8s.crds`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.crds/`, written by
//! `scripts/gen-k8s-crds-fixtures.py`. Every `Rig` audits its run when it drops (INV-14): each request the
//! mock recorded passes the guard's rules and is logged under a check that `ALLOWED` cites.

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

const APIS: &str = "/apis";
const V1: &str = "/apis/pki.acme.example/v1";
const V1BETA1: &str = "/apis/pki.acme.example/v1beta1";
const OPERATOR: &str = "/apis/apps/v1/namespaces/acme-system/deployments/acme-operator";
const CERTS: &str = "certificates.pki.acme.example";
const ISSUERS: &str = "issuers.pki.acme.example";

/// The strings the fixtures put in annotations, arguments and environment values. None may reach a result.
const MARKERS: [&str; 2] = ["MARKER-ANNOTATION-7731", "MARKER-ENV-5520"];

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
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.crds/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.crds", Os::Linux, [Need::KubeContext]);
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

fn params(spec: Value) -> K8sCrds {
    serde_json::from_value(spec).expect("the parameters parse")
}

fn operator(min: Option<&str>) -> Value {
    let mut rule = json!({"namespace": "acme-system", "deployment": "acme-operator"});
    if let Some(min) = min {
        rule["min_version"] = json!(min);
    }
    rule
}

impl Rig {
    async fn finding(&self, spec: Value) -> Finding {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let finding = CrdsCheck::new(params(spec), cluster)
            .run(&self.ctx)
            .await
            .expect("the check ran");
        assert_fix_text_is_clean(&finding);
        // Nothing a Deployment carries beyond what the check reads may reach a result.
        let everything = format!("{finding:?}");
        for marker in MARKERS {
            assert!(
                !everything.contains(marker),
                "{marker} reached {everything}"
            );
        }
        finding
    }

    /// The `(method, path)` of every request, in order, all logged under `k8s.crds`.
    fn requests(&self) -> Vec<(String, String)> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.crds")),
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

fn assert_fix_text_is_clean(finding: &Finding) {
    for text in finding.fix.iter().chain(&finding.notes) {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("fix text breaks the allow-list: {error}\n{text}");
        }
        assert!(!text.contains('\u{2014}'), "no em dash: {text}");
    }
    assert!(!finding.message.contains('\u{2014}'), "{}", finding.message);
    // No terminal escape and no backtick from the server in a sentence: every backtick is a span the
    // check wrote, so the count is even and no span holds an escape.
    for text in finding
        .fix
        .iter()
        .chain(&finding.notes)
        .chain([&finding.message])
    {
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(!text.contains("rm -rf"), "{text:?}");
    }
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
    let mut entry = json!({"id": "k8s.crds"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

fn crds(names: &[&str], versions: Option<&[&str]>) -> Value {
    let rules: Vec<Value> = names
        .iter()
        .map(|name| match versions {
            Some(versions) => json!({"name": name, "versions": versions}),
            None => json!({"name": name}),
        })
        .collect();
    Value::Array(rules)
}

// ---- the exit test ----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_crd_blocks_with_the_mirror_aware_helm_fix() {
    let rig = rig("crd-group-missing");
    let finding = rig
        .finding(json!({"crds": crds(&[CERTS, ISSUERS], Some(&["v1"]))}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "2 CRDs of API group pki.acme.example are not installed: `certificates.pki.acme.example`, `issuers.pki.acme.example`"
    );
    assert_eq!(
        fix_of(&finding),
        "The CRDs of API group `pki.acme.example` are missing. Install the chart that ships them, from your registry or mirror: `helm install <release> <chart> -n <namespace> --create-namespace`. Use the chart reference your vendor gave you. On an air-gapped cluster that is your own mirror, not a public repository. See what the cluster serves: `kubectl api-resources --api-group=pki.acme.example`."
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    // A group that is not served has no document to read: the group list only.
    assert_eq!(rig.paths(), [APIS]);
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn an_operator_below_min_version_blocks() {
    let rig = rig("operator-old");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14"))]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Operator acme-operator in namespace acme-system runs 1.12.3 and the product needs 1.14 or later"
    );
    assert_eq!(
        fix_of(&finding),
        "Upgrade the operator from your registry or mirror: `helm upgrade <release> <chart> -n acme-system`. Apply the CRDs of the new version first when the chart's notes say so. See what runs now: `kubectl get deployment acme-operator -n acme-system -o wide`."
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    assert_eq!(rig.paths(), [OPERATOR]);
    assert_eq!(finding.observed["operators"][0]["version"], "1.12.3");
    assert_eq!(
        finding.observed["operators"][0]["version_source"],
        "image tag"
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

// ---- definitions ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn definitions_and_an_operator_that_are_fine_pass() {
    let rig = rig("crds-present");
    let finding = rig
        .finding(json!({
            "crds": crds(&[CERTS, ISSUERS], Some(&["v1"])),
            "operators": [operator(Some("1.13"))],
        }))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "2 definitions are installed at the versions the product needs; operator acme-operator in namespace acme-system has 1 of 1 replicas ready at 1.14.5"
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(finding.fix.is_none());
    // The group list, one document for both definitions (it is read once), and the Deployment.
    assert_eq!(rig.paths(), [APIS, V1, OPERATOR]);
    assert_eq!(finding.observed["crds"][0]["state"], "served");
    assert_eq!(finding.observed["crds"][0]["served"], json!(["v1"]));
    assert_eq!(finding.observed["operators"][0]["ready"], 1);
    assert_eq!(
        finding.expected["operators"][0]["min_version"],
        json!("1.13")
    );
    assert!(
        notes(&finding).contains("The CustomResourceDefinition objects are not read."),
        "{}",
        notes(&finding)
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn a_definition_that_serves_only_an_old_version_blocks_with_the_upgrade_fix() {
    let rig = rig("crd-version-old");
    let finding = rig
        .finding(json!({"crds": crds(&[CERTS], Some(&["v1"]))}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CRD certificates.pki.acme.example is installed but does not serve v1; it serves v1beta1"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.contains("Helm does not upgrade CRDs that a chart ships in its crds directory"),
        "{fix}"
    );
    assert!(
        fix.contains("`kubectl apply --server-side -f <crds.yaml>`"),
        "{fix}"
    );
    // v1 is not served, so its document is not read; v1beta1 is, to say what is served.
    assert_eq!(rig.paths(), [APIS, V1BETA1]);
    assert_eq!(finding.observed["crds"][0]["state"], "version_missing");
    assert_eq!(finding.observed["crds"][0]["served"], json!(["v1beta1"]));
    rig.audit();
}

#[tokio::test]
async fn a_group_that_is_served_without_the_definition_blocks() {
    let rig = rig("crd-not-in-group");
    let finding = rig
        .finding(json!({"crds": crds(&[CERTS], Some(&["v1"]))}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CRD certificates.pki.acme.example is not installed: the cluster has no definition of it in API group pki.acme.example"
    );
    assert!(fix_of(&finding).starts_with("The CRDs of API group `pki.acme.example` are missing."));
    assert_eq!(rig.paths(), [APIS, V1]);
    rig.audit();
}

#[tokio::test]
async fn a_definition_without_versions_is_found_at_any_version() {
    let rig = rig("crd-any-version");
    let finding = rig.finding(json!({"crds": crds(&[CERTS], None)})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    // The preferred version has no such resource, so the next one is read, and the search stops there.
    assert_eq!(rig.paths(), [APIS, V1, V1BETA1]);
    assert_eq!(finding.observed["crds"][0]["served"], json!(["v1beta1"]));
    rig.audit();
}

#[tokio::test]
async fn a_group_list_the_identity_may_not_read_is_partial_never_a_block() {
    let rig = rig("crd-discovery-forbidden");
    let finding = rig
        .finding(json!({"crds": crds(&[CERTS], Some(&["v1"]))}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get /apis"]);
    assert!(
        partial_note(&finding)
            .contains("whether CRD certificates.pki.acme.example is installed was not read"),
        "{}",
        partial_note(&finding)
    );
    assert!(
        fix_of(&finding).contains("`kubectl auth can-i get /apis`"),
        "{}",
        fix_of(&finding)
    );
    assert_eq!(rig.paths(), [APIS]);
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_document_the_identity_may_not_read_is_partial() {
    let rig = rig("crd-document-forbidden");
    let finding = rig
        .finding(json!({"crds": crds(&[CERTS], Some(&["v1"]))}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get /apis"]);
    assert_eq!(rig.paths(), [APIS, V1]);
    rig.audit();
}

#[tokio::test]
async fn a_version_document_that_answers_404_says_the_definition_is_not_served() {
    let rig = rig("crd-document-gone");
    let finding = rig
        .finding(json!({"crds": crds(&[CERTS], Some(&["v1"]))}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(rig.paths(), [APIS, V1]);
    rig.audit();
}

#[tokio::test]
async fn a_crd_name_without_a_group_is_not_looked_up() {
    let rig = rig("crd-group-missing");
    let finding = rig
        .finding(json!({"crds": [{"name": "certificates"}]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("has no API group in its name"),
        "{}",
        partial_note(&finding)
    );
    assert!(fix_of(&finding).contains("`<plural>.<group>`"));
    rig.audit();
}

// ---- operators ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_operator_with_all_replicas_ready_passes_without_a_minimum() {
    let rig = rig("operator-ready");
    let finding = rig.finding(json!({"operators": [operator(None)]})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Operator acme-operator in namespace acme-system has 2 of 2 replicas ready"
    );
    // No minimum, so no version is asked for and none is missing.
    assert!(finding.partial.is_none(), "{finding:?}");
    assert_eq!(rig.paths(), [OPERATOR]);
    rig.audit();
}

#[tokio::test]
async fn an_operator_with_no_replica_ready_warns() {
    let rig = rig("operator-not-ready");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.13"))]}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Operator Deployment acme-operator in namespace acme-system has 0 of 1 replicas ready"
    );
    assert_eq!(
        fix_of(&finding),
        "Find out why the pods of `acme-operator` in `acme-system` are not ready: `kubectl describe deployment acme-operator -n acme-system`, then `kubectl get pods -n acme-system`, then `kubectl logs deployment/acme-operator -n acme-system`."
    );
    // 1.14.5 is above 1.13, so only the readiness is a finding.
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn an_operator_with_some_replicas_ready_warns() {
    let rig = rig("operator-partly-ready");
    let finding = rig.finding(json!({"operators": [operator(None)]})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.ends_with("has 1 of 3 replicas ready"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["operators"][0]["state"], "not_ready");
    rig.audit();
}

#[tokio::test]
async fn an_operator_scaled_to_zero_warns() {
    let rig = rig("operator-scaled-to-zero");
    let finding = rig.finding(json!({"operators": [operator(None)]})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Operator Deployment acme-operator in namespace acme-system is scaled to 0"
    );
    assert!(
        fix_of(&finding)
            .contains("`kubectl scale deployment acme-operator -n acme-system --replicas=1`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_missing_operator_deployment_warns_and_never_blocks() {
    let rig = rig("operator-missing");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.13"))]}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Operator Deployment acme-operator was not found in namespace acme-system"
    );
    assert!(
        fix_of(&finding).contains("`kubectl get deployments -n acme-system`"),
        "{}",
        fix_of(&finding)
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_deployment_the_identity_may_not_get_is_partial_with_the_grant() {
    let rig = rig("operator-forbidden");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.13"))]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get deployments.apps in acme-system"]);
    assert_eq!(
        fix_of(&finding),
        "Ask the cluster admin to grant this identity: get deployments.apps in acme-system. Check each with `kubectl auth can-i get deployments.apps -n acme-system`."
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_pre_release_of_the_minimum_is_below_it() {
    let rig = rig("operator-prerelease");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14.0"))]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Operator acme-operator in namespace acme-system runs 1.14.0 (a pre-release) and the product needs 1.14.0 or later"
    );
    rig.audit();
}

#[tokio::test]
async fn a_tag_with_a_distro_suffix_at_the_minimum_passes() {
    let rig = rig("operator-equal");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14"))]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding.message.ends_with("at 1.14.0"),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn an_image_pinned_by_digest_takes_its_version_from_the_label() {
    let rig = rig("operator-digest-label");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14"))]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["operators"][0]["version"], "1.14.5");
    assert_eq!(finding.observed["operators"][0]["version_source"], "label");
    rig.audit();
}

#[tokio::test]
async fn the_image_tag_wins_over_a_label_that_differs_and_a_note_says_so() {
    let rig = rig("operator-label-differs");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14"))]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding.message.contains("runs 1.12.3"),
        "{}",
        finding.message
    );
    assert!(
        notes(&finding).contains(
            "has an image tag of 1.12.3 and a version label of 1.14.5. rdy judges the image tag."
        ),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_version_that_cannot_be_read_is_partial_never_a_block() {
    for case in [
        "operator-latest",
        "operator-registry-port",
        "operator-ambiguous",
    ] {
        let rig = rig(case);
        let finding = rig
            .finding(json!({"operators": [operator(Some("1.14"))]}))
            .await;
        assert_eq!(finding.level, Level::Pass, "{case}: {finding:?}");
        assert!(
            partial_note(&finding).contains(
                "the version of operator acme-operator in namespace acme-system was not read"
            ),
            "{case}: {}",
            partial_note(&finding)
        );
        assert_eq!(
            fix_of(&finding),
            "Check the version of `acme-operator` by hand: `kubectl get deployment acme-operator -n acme-system -o wide`, and read the image tag."
        );
        assert!(grants(&finding).is_empty());
        assert_eq!(engine(&rig, finding, None).status, Status::Warn, "{case}");
        rig.audit();
    }
}

#[tokio::test]
async fn the_ambiguous_case_says_why() {
    let rig = rig("operator-ambiguous");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14"))]}))
        .await;
    assert!(
        partial_note(&finding).contains(
            "its containers have different versions and none is named like the Deployment"
        ),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_sidecar_with_its_own_version_does_not_hide_the_operator_container() {
    let rig = rig("operator-sidecar");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14"))]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["operators"][0]["version"], "1.14.5");
    rig.audit();
}

#[tokio::test]
async fn a_hostile_tag_and_label_never_reach_a_sentence_or_a_command() {
    let rig = rig("operator-hostile");
    let finding = rig
        .finding(json!({"operators": [operator(Some("1.14"))]}))
        .await;
    // Neither the tag nor the label reads as a version, so the result is partial, and `finding` already
    // asserted that no escape and no command from the server is in any text.
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_some());
    assert_eq!(finding.observed["operators"][0]["version"], Value::Null);
    rig.audit();
}

// ---- several results at once ------------------------------------------------------------------------------------

#[tokio::test]
async fn the_headline_is_the_first_block_and_the_rest_are_notes() {
    let rig = rig("everything-wrong");
    let finding = rig
        .finding(json!({
            "crds": crds(&[CERTS, ISSUERS], Some(&["v1"])),
            "operators": [
                operator(None),
                {"namespace": "acme-data", "deployment": "acme-store", "min_version": "2.4"},
            ],
        }))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("2 CRDs of API group pki.acme.example are not installed")
            && finding.message.ends_with("(and 2 more, see the notes)"),
        "{}",
        finding.message
    );
    let notes = notes(&finding);
    assert!(
        notes.contains(
            "Operator Deployment acme-operator in namespace acme-system has 0 of 1 replicas ready"
        ),
        "{notes}"
    );
    assert!(
        notes.contains("Operator acme-store in namespace acme-data runs 2.3.1 and the product needs 2.4 or later"),
        "{notes}"
    );
    let fix = fix_of(&finding);
    for part in [
        "The CRDs of API group `pki.acme.example` are missing.",
        "Find out why the pods of `acme-operator`",
        "Upgrade the operator from your registry or mirror: `helm upgrade <release> <chart> -n acme-data`.",
    ] {
        assert!(fix.contains(part), "{part}\n{fix}");
    }
    assert_eq!(
        rig.paths(),
        [
            APIS,
            OPERATOR,
            "/apis/apps/v1/namespaces/acme-data/deployments/acme-store"
        ]
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn a_warning_alone_stays_a_warning() {
    let rig = rig("warn-only");
    let finding = rig
        .finding(json!({
            "crds": crds(&[CERTS], Some(&["v1"])),
            "operators": [operator(Some("1.14"))],
        }))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn the_definitions_of_one_missing_group_are_one_block_and_other_groups_are_their_own() {
    let rig = rig("two-groups");
    let finding = rig
        .finding(json!({"crds": [
            {"name": CERTS, "versions": ["v1"]},
            {"name": "widgets.other.acme.example"},
            {"name": "gadgets.other.acme.example"},
        ]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CRD certificates.pki.acme.example is installed but does not serve v1; it serves v1beta1 (and 1 more, see the notes)"
    );
    assert_eq!(
        notes(&finding).lines().next().expect("a note"),
        "2 CRDs of API group other.acme.example are not installed: `widgets.other.acme.example`, `gadgets.other.acme.example`"
    );
    // One install fix for the two, and the upgrade fix for the third.
    let fix = fix_of(&finding);
    assert_eq!(
        fix.matches("The CRDs of API group `other.acme.example`")
            .count(),
        1
    );
    assert_eq!(rig.paths(), [APIS, V1BETA1]);
    rig.audit();
}

#[tokio::test]
async fn a_namespace_called_secrets_is_refused_by_the_guard_and_not_a_block() {
    let rig = rig("namespace-secrets");
    let finding = rig
        .finding(json!({"operators": [{"namespace": "secrets", "deployment": "acme-operator"}]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("rdy never reads a path through a name that is secrets"),
        "{}",
        partial_note(&finding)
    );
    // The guard logs the refusal and sends nothing: the audit proves the mock saw no request.
    assert_eq!(
        rig.paths(),
        ["/apis/apps/v1/namespaces/secrets/deployments/acme-operator"]
    );
    rig.audit();
}

// ---- bounds ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_run_reads_at_most_32_discovery_documents_and_then_says_so() {
    let rig = rig("crds-present");
    let client = rig.cluster.harness.client(rig.ctx.probe());
    let mapper = |error: &kube::Error| rig.cluster.map_error(error);
    let mut docs = Docs {
        client: &client,
        mapper: &mapper,
        cache: std::collections::BTreeMap::new(),
        asked: MAX_DOCS,
    };
    let got = docs
        .plurals(&rig.ctx, "pki.acme.example", "v1")
        .await
        .expect("no error");
    assert_eq!(got, Err(Unread::Budget));
    // Nothing was asked of the server.
    assert!(rig.paths().is_empty());
    rig.audit();
}
