//! Fixture tests of `k8s.storageclass`: the real check code over the kube mock harness, with the guard in
//! front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.storageclass/`, written by
//! `scripts/gen-k8s-storageclass-fixtures.py`. Every `Rig` audits its run when it drops (INV-14): each
//! request the mock recorded passes the guard's rules and is logged under a check that `ALLOWED` cites.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckContext, Finding, Level, Need, Os};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::Probe;
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};
use rdy_spec::check::K8sStorageClass;
use rdy_spec::result::Status;
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;
use crate::client::mock::Harness;

/// The time the claims are aged at: two hours after the fixtures' oldest claim was made.
const NOW: &str = "2026-06-01T12:00:00Z";

const CLASSES: &str = "/apis/storage.k8s.io/v1/storageclasses";
const CSINODES: &str = "/apis/storage.k8s.io/v1/csinodes";
const CSIDRIVERS: &str = "/apis/storage.k8s.io/v1/csidrivers";
const NAMESPACE: &str = "/api/v1/namespaces/acme-system";
const CLAIMS: &str = "/api/v1/namespaces/acme-system/persistentvolumeclaims";
const EVENTS: &str = "/api/v1/namespaces/acme-system/events";

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
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.storageclass/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.storageclass", Os::Linux, [Need::KubeContext]);
    Rig {
        cluster: Arc::new(Fixtured {
            harness,
            version: version(git),
        }),
        ctx,
    }
}

fn rig(case: &str) -> Rig {
    rig_at(case, "v1.29.4")
}

fn params(spec: Value) -> K8sStorageClass {
    serde_json::from_value(spec).expect("the parameters parse")
}

impl Rig {
    fn check(&self, spec: Value, namespace: Option<&str>) -> StorageClassCheck {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let namespace = namespace.map(|name| serde_json::from_value(json!(name)).expect("a name"));
        StorageClassCheck::new(params(spec), namespace, cluster).at(NOW.parse().expect("a time"))
    }

    async fn finding(&self, spec: Value) -> Finding {
        self.finding_in(spec, None).await
    }

    async fn finding_in(&self, spec: Value, namespace: Option<&str>) -> Finding {
        let finding = self
            .check(spec, namespace)
            .run(&self.ctx)
            .await
            .expect("the check ran");
        assert_fix_text_is_clean(&finding);
        finding
    }

    /// The `(method, path)` of every request, in order, all logged under `k8s.storageclass`.
    fn requests(&self) -> Vec<(String, String)> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.storageclass")),
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

/// What the engine makes of a finding for an entry with this severity.
fn engine(rig: &Rig, finding: Finding, severity: Option<&str>) -> rdy_spec::result::CheckResult {
    let mut entry = json!({"id": "k8s.storageclass"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

// ---- the exit test ----------------------------------------------------------------------------------------

#[tokio::test]
async fn eks_gp2_with_no_csi_addon_blocks() {
    let rig = rig("eks-gp2-no-csi");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "No ebs.csi.aws.com CSI driver is registered, so PVCs on gp2 stay Pending"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains(
            "`eksctl create addon --cluster <cluster> --name aws-ebs-csi-driver --service-account-role-arn <role-arn>`"
        ),
        "{fix}"
    );
    assert!(fix.contains("--pod-identity-associations"), "{fix}");
    assert!(fix.contains("`AmazonEBSCSIDriverPolicyV2`"), "{fix}");
    assert_eq!(finding.observed["provisioner"], "kubernetes.io/aws-ebs");
    assert_eq!(finding.observed["serving_driver"], "ebs.csi.aws.com");
    assert_eq!(finding.observed["driver_evidence"], "none");
    assert_eq!(finding.observed["csinodes_read"], 2);
    assert_eq!(finding.observed["csinodes_with_driver"], 0);
    assert!(finding.partial.is_none());
    // The class list, the strongest evidence, then the weaker one.
    assert_eq!(rig.paths(), [CLASSES, CSINODES, CSIDRIVERS]);
    // The engine blocks on a block-severity entry and warns on a warn-severity one.
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn k3s_local_path_passes_with_driver_not_verified() {
    let rig = rig("k3s-local-path");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Default class local-path (rancher.io/local-path): not CSI or unknown, driver not verified"
    );
    assert!(finding.partial.is_none());
    assert_eq!(finding.observed["driver_kind"], "not_csi");
    assert_eq!(finding.observed["driver_evidence"], "not_needed");
    // Nothing but the class list: a driver that is not CSI has nothing to look up.
    assert_eq!(rig.paths(), [CLASSES]);
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn eks_auto_mode_passes_with_the_driver_not_verified_and_is_never_looked_up() {
    let rig = rig("eks-auto-mode");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Default class auto-ebs-sc (ebs.csi.eks.amazonaws.com): not CSI or unknown, driver not verified"
    );
    assert!(finding.partial.is_none());
    assert_eq!(finding.observed["driver_kind"], "not_csi");
    // No CSINode or CSIDriver is asked for: nothing says Auto Mode registers there.
    assert_eq!(rig.paths(), [CLASSES]);
    // RWO is served, the modes the table does not list are not verified and never refused.
    let rwo = rig
        .finding(json!({"access_modes": ["ReadWriteOnce"]}))
        .await;
    assert_eq!(rwo.level, Level::Pass, "{rwo:?}");
    let more = rig
        .finding(json!({"access_modes": ["ReadWriteOncePod", "ReadWriteMany"]}))
        .await;
    assert_eq!(more.level, Level::Warn, "{more:?}");
    assert_eq!(
        more.observed["access_modes"],
        json!({"ReadWriteOncePod": "not verified", "ReadWriteMany": "not verified"})
    );
    assert_eq!(engine(&rig, more, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn two_defaults_block_on_1_25_and_warn_on_1_28() {
    let old = rig_at("two-defaults", "v1.25.9");
    let finding = old.finding(json!({})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "2 storage classes are marked as the default (acme-new, acme-old). Kubernetes 1.25 rejects a claim with no class when there are several"
    );
    old.audit();

    let new = rig_at("two-defaults", "v1.28.3");
    let finding = new.finding(json!({})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "2 storage classes are marked as the default (acme-new, acme-old). The newest, acme-new, is used"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("kubectl patch storageclass acme-old -p")
            && fix.contains("\"storageclass.kubernetes.io/is-default-class\":\"false\""),
        "{fix}"
    );
    // The newest default is the one judged further, and the legacy annotation counts as a default.
    assert_eq!(finding.observed["class"], "acme-new");
    assert_eq!(
        finding.observed["default_classes"],
        json!(["acme-new", "acme-old"])
    );
    assert_eq!(engine(&new, finding, None).status, Status::Warn);
    new.audit();
}

#[tokio::test]
async fn the_server_version_decides_at_1_26_and_unknown_never_blocks() {
    let edge = rig_at("two-defaults", "v1.26.0");
    assert_eq!(edge.finding(json!({})).await.level, Level::Warn);
    let last = rig_at("two-defaults", "v1.25.99-eks-1");
    assert_eq!(last.finding(json!({})).await.level, Level::Fail);
    let unknown = rig_at("two-defaults", "not-a-version");
    let finding = unknown.finding(json!({})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding
            .message
            .contains("could not read the server version"),
        "{}",
        finding.message
    );
    assert!(finding.observed.get("server_minor").is_none());
}

#[tokio::test]
async fn csinode_forbidden_gives_partial_with_the_grant_and_never_a_block() {
    let rig = rig("csinode-forbidden");
    let finding = rig.finding(json!({})).await;
    // A CSIDriver object is the weaker evidence: a pass with a partial, which the engine shows as a warning.
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list csinodes (storage.k8s.io)"]);
    let partial = finding.partial.clone().expect("partial");
    assert_eq!(partial.note, "could not read the CSINode list");
    assert_eq!(finding.observed["driver_evidence"], "csidriver");
    assert_eq!(rig.paths(), [CLASSES, CSINODES, CSIDRIVERS]);
    let fix = finding.fix.clone().expect("a fix naming the grant");
    assert!(
        fix.contains("`kubectl auth can-i list csinodes.storage.k8s.io`"),
        "{fix}"
    );

    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Warn);
    assert!(
        result.message.starts_with("not verified:"),
        "{}",
        result.message
    );
    // The grant is on the wire, in the field and no longer in the notes.
    let wire = result.partial.expect("wire partial");
    assert_eq!(wire.missing_grants, ["list csinodes (storage.k8s.io)"]);
    assert!(
        result
            .notes
            .iter()
            .all(|note| !note.contains("Missing grants"))
    );
    rig.audit();
}

#[tokio::test]
async fn unreadable_driver_evidence_is_a_warning_with_grants_never_a_block() {
    for (case, grant_list) in [
        (
            "csinode-forbidden-no-object",
            vec!["list csinodes (storage.k8s.io)"],
        ),
        (
            "both-forbidden",
            vec![
                "list csinodes (storage.k8s.io)",
                "list csidrivers (storage.k8s.io)",
            ],
        ),
        (
            "csidriver-forbidden",
            vec!["list csidrivers (storage.k8s.io)"],
        ),
        ("csinode-capped", vec![]),
    ] {
        let rig = rig(case);
        let finding = rig.finding(json!({})).await;
        assert_eq!(finding.level, Level::Warn, "{case}: {finding:?}");
        assert!(
            finding.message.starts_with("Not verified:"),
            "{case}: {}",
            finding.message
        );
        assert_eq!(grants(&finding), grant_list, "{case}");
        assert_eq!(finding.observed["driver_evidence"], "unread", "{case}");
        // Even a block-severity entry only warns.
        assert_eq!(engine(&rig, finding, None).status, Status::Warn, "{case}");
        rig.audit();
    }
}

#[tokio::test]
async fn the_words_follow_why_the_list_was_not_read() {
    let forbidden = rig("both-forbidden").finding(json!({})).await;
    assert!(
        forbidden
            .message
            .contains("the CSINode list may not be listed by this identity"),
        "{}",
        forbidden.message
    );
    let capped = rig("csinode-capped").finding(json!({})).await;
    assert!(
        capped
            .message
            .contains("the CSINode list is longer than the page rdy read"),
        "{}",
        capped.message
    );
    let fix = capped.fix.expect("a fix");
    assert!(fix.contains("kubectl get csinodes"), "{fix}");
}

#[tokio::test]
async fn a_driver_object_without_a_registration_warns_the_node_plugin_may_be_down() {
    let rig = rig("driver-object-only");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding
            .message
            .contains("has a CSIDriver object, but no node has registered it"),
        "{}",
        finding.message
    );
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("node plugin may be down"), "{fix}");
    assert!(fix.contains("kubectl get csinodes"), "{fix}");
    rig.audit();
}

// ---- the classes -------------------------------------------------------------------------------------------

#[tokio::test]
async fn with_the_ebs_addon_the_default_passes_on_the_csinode_list_alone() {
    let rig = rig("eks-ebs-csi");
    let finding = rig
        .finding(json!({"access_modes": ["ReadWriteOnce"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Default class gp3 (ebs.csi.aws.com) supports ReadWriteOnce, driver registered on 3 nodes"
    );
    assert_eq!(
        finding.observed["access_modes"],
        json!({"ReadWriteOnce": "served"})
    );
    assert_eq!(finding.observed["driver_evidence"], "csinode");
    assert_eq!(finding.expected, json!({"access_modes": ["ReadWriteOnce"]}));
    // A hit on a node means the weaker list is not asked for.
    assert_eq!(rig.paths(), [CLASSES, CSINODES]);
    rig.audit();
}

#[tokio::test]
async fn gp2_on_the_in_tree_name_passes_once_the_addon_registered_the_csi_name() {
    let rig = rig("eks-gp2-with-addon");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Default class gp2 (kubernetes.io/aws-ebs via ebs.csi.aws.com): driver registered on 2 nodes"
    );
    rig.audit();
}

#[tokio::test]
async fn a_named_class_is_judged_even_when_it_is_not_the_default() {
    let rig = rig("eks-ebs-csi");
    let finding = rig.finding(json!({"class": "gp2"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("Class gp2 (kubernetes.io/aws-ebs via ebs.csi.aws.com)"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["selected"], "named");
    assert_eq!(finding.expected, json!({"class": "gp2"}));
    rig.audit();
}

#[tokio::test]
async fn a_named_class_that_does_not_exist_blocks_and_lists_what_does() {
    let rig = rig("eks-ebs-csi");
    let finding = rig.finding(json!({"class": "fast"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Storage class fast does not exist. It has: gp2, gp3."
    );
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("kubectl get storageclass"), "{fix}");
    // Nothing else is read for a class that is not there.
    assert_eq!(rig.paths(), [CLASSES]);
    rig.audit();
}

#[tokio::test]
async fn no_storage_class_at_all_blocks() {
    let rig = rig("none");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "No default storage class. The cluster has no storage class"
    );
    assert!(finding.fix.expect("a fix").contains("Install a CSI driver"));
    assert_eq!(finding.observed["classes_read"], 0);
    rig.audit();
}

#[tokio::test]
async fn no_default_blocks_and_the_fix_names_a_class_to_mark() {
    let rig = rig("no-default");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "No default storage class. The cluster has: standard, managed-csi"
    );
    let fix = finding.fix.expect("a fix");
    // The managed-service class is preferred over the first by name.
    assert!(
        fix.contains(
            "`kubectl patch storageclass managed-csi -p '{\"metadata\":{\"annotations\":{\"storageclass.kubernetes.io/is-default-class\":\"true\"}}}'`"
        ),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_class_list_longer_than_a_page_is_not_a_block() {
    let capped = rig("capped");
    let finding = capped.finding(json!({})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(finding.message.starts_with("Not verified:"));
    assert_eq!(finding.observed["classes_complete"], false);
    assert!(
        finding
            .fix
            .expect("a fix")
            .contains("kubectl get storageclass")
    );
    capped.audit();

    let named = rig("capped");
    let finding = named.finding(json!({"class": "elsewhere"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(finding.message.contains("is not in the first page"));
}

// ---- a list the identity may not read -----------------------------------------------------------------------

#[tokio::test]
async fn a_forbidden_class_list_is_partial_and_never_a_block() {
    let rig = rig("list-forbidden");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Not verified: the identity may not list storage classes"
    );
    assert_eq!(grants(&finding), ["list storageclasses (storage.k8s.io)"]);
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("`kubectl auth can-i list storageclasses.storage.k8s.io`"),
        "{fix}"
    );
    assert_eq!(rig.paths(), [CLASSES]);
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_forbidden_list_falls_back_to_the_named_class() {
    let rig = rig("list-forbidden-named");
    let finding = rig
        .finding(json!({"class": "gp3", "expansion": true}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.message.starts_with("Class gp3 (ebs.csi.aws.com)"));
    assert!(finding.partial.is_none());
    assert_eq!(finding.observed["classes_complete"], false);
    assert_eq!(rig.paths(), [CLASSES, &format!("{CLASSES}/gp3"), CSINODES]);
    rig.audit();
}

#[tokio::test]
async fn a_forbidden_get_by_name_is_partial_with_the_get_grant() {
    let rig = rig("list-and-get-forbidden");
    let finding = rig.finding(json!({"class": "gp3"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(grants(&finding), ["get storageclasses (storage.k8s.io)"]);
    assert!(finding.message.starts_with("Not verified:"));
    rig.audit();
}

// ---- driver kinds -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn no_provisioner_passes_without_a_lookup_and_says_volumes_are_made_by_hand() {
    let rig = rig("no-provisioner");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.message.contains("driver not verified"));
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.contains("creates no volumes")),
        "{:?}",
        finding.notes
    );
    assert_eq!(finding.observed["driver_kind"], "static");
    assert_eq!(rig.paths(), [CLASSES]);
    // A class that makes no volumes cannot be checked for an access mode.
    let modes = rig
        .finding(json!({"access_modes": ["ReadWriteMany"]}))
        .await;
    assert_eq!(modes.level, Level::Warn);
    assert!(modes.message.contains("made by hand"), "{}", modes.message);
}

#[tokio::test]
async fn an_unknown_provisioner_never_blocks_on_driver_grounds() {
    let rig = rig("unknown-provisioner");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Default class acme-fast (csi.acme.example): not CSI or unknown, driver not verified"
    );
    assert_eq!(rig.paths(), [CLASSES]);
    let modes = rig
        .finding(json!({"access_modes": ["ReadWriteOnce"]}))
        .await;
    assert_eq!(modes.level, Level::Warn);
    assert!(
        modes
            .message
            .contains("rdy has no access mode data for csi.acme.example"),
        "{}",
        modes.message
    );
}

#[tokio::test]
async fn the_openshift_data_foundation_prefix_matches_the_ceph_entries() {
    let rig = rig("odf");
    let rwo = rig
        .finding(json!({"access_modes": ["ReadWriteOnce"]}))
        .await;
    assert_eq!(rwo.level, Level::Pass, "{rwo:?}");
    assert_eq!(
        rwo.message,
        "Default class ocs-storagecluster-ceph-rbd (openshift-storage.rbd.csi.ceph.com) supports ReadWriteOnce, driver registered on 2 nodes"
    );
    // RWX on rbd works only for raw block volumes, which a class cannot say: not verified, not refused.
    let rwx = rig
        .finding(json!({"access_modes": ["ReadWriteMany"]}))
        .await;
    assert_eq!(rwx.level, Level::Warn, "{rwx:?}");
    assert!(
        rwx.message
            .contains("serves ReadWriteMany only for raw block volumes"),
        "{}",
        rwx.message
    );
    // CephFS serves it.
    let fs = rig
        .finding(json!({"class": "ocs-storagecluster-cephfs", "access_modes": ["ReadWriteMany"]}))
        .await;
    assert_eq!(fs.level, Level::Pass, "{fs:?}");
    assert!(
        fs.message.starts_with(
            "Class ocs-storagecluster-cephfs (openshift-storage.cephfs.csi.ceph.com) supports ReadWriteMany"
        ),
        "{}",
        fs.message
    );
    rig.audit();
}

// ---- access modes ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn local_path_serves_read_write_once_and_nothing_wider() {
    let rig = rig("k3s-local-path");
    let rwo = rig
        .finding(json!({"access_modes": ["ReadWriteOnce"]}))
        .await;
    assert_eq!(rwo.level, Level::Pass, "{rwo:?}");
    assert_eq!(
        rwo.message,
        "Default class local-path (rancher.io/local-path) supports ReadWriteOnce, driver not verified"
    );

    let rwx = rig
        .finding(json!({"access_modes": ["ReadWriteMany"]}))
        .await;
    assert_eq!(rwx.level, Level::Fail, "{rwx:?}");
    assert_eq!(
        rwx.message,
        "Class local-path cannot serve ReadWriteMany: rancher.io/local-path serves ReadWriteOnce"
    );
    let fix = rwx.fix.clone().expect("a fix");
    assert!(
        fix.contains("NFS, EFS, Azure Files, Filestore or CephFS"),
        "{fix}"
    );

    let once_pod = rig
        .finding(json!({"access_modes": ["ReadWriteOnce", "ReadWriteOncePod"]}))
        .await;
    assert_eq!(once_pod.level, Level::Fail, "{once_pod:?}");
    assert!(
        once_pod
            .message
            .contains("Kubernetes serves ReadWriteOncePod for CSI volumes only"),
        "{}",
        once_pod.message
    );
    assert_eq!(
        once_pod.observed["access_modes"],
        json!({"ReadWriteOnce": "served", "ReadWriteOncePod": "not served"})
    );
    // The access mode is the spec's own threshold: a block-severity entry blocks, a warn one warns.
    assert_eq!(engine(&rig, rwx.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, rwx, Some("warn")).status, Status::Warn);
    rig.audit();
}

// ---- binding, expansion and reclaim ----------------------------------------------------------------------------

#[tokio::test]
async fn immediate_binding_on_a_zonal_driver_warns() {
    let rig = rig("gke-immediate");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Class standard-rwo binds with Immediate, and its volumes live in one zone. If the nodes span more than one zone, a pod can land where its volume cannot attach"
    );
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains("volumeBindingMode: WaitForFirstConsumer"),
        "{fix}"
    );

    // The spec that asks for Immediate accepts it.
    let wanted = rig.finding(json!({"binding": "Immediate"})).await;
    assert_eq!(wanted.level, Level::Pass, "{wanted:?}");
    // The spec that asks for WaitForFirstConsumer blocks on it.
    let strict = rig
        .finding(json!({"binding": "WaitForFirstConsumer"}))
        .await;
    assert_eq!(strict.level, Level::Fail, "{strict:?}");
    assert_eq!(
        strict.message,
        "Class standard-rwo binds with Immediate, and WaitForFirstConsumer is needed"
    );
    assert_eq!(strict.expected, json!({"binding": "WaitForFirstConsumer"}));
    rig.audit();
}

#[tokio::test]
async fn expansion_and_reclaim_policy_warn_on_a_mismatch() {
    let rig = rig("eks-gp2-with-addon");
    // gp2 here does not allow expansion and reclaims with the default, Delete.
    let finding = rig
        .finding(json!({"expansion": true, "reclaim_policy": "Retain"}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(finding.message, "Class gp2 does not allow volume expansion");
    assert_eq!(
        finding.notes,
        ["Class gp2 reclaims with Delete, and Retain is wanted. Deleting a claim deletes its data"]
    );
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains("kubectl patch storageclass gp2 -p '{\"allowVolumeExpansion\":true}'"),
        "{fix}"
    );
    assert!(fix.contains("`reclaimPolicy: Retain`"), "{fix}");

    // Expansion that is off and not wanted, and a matching policy, are fine.
    let fine = rig
        .finding(json!({"expansion": false, "reclaim_policy": "Delete"}))
        .await;
    assert_eq!(fine.level, Level::Pass, "{fine:?}");
    rig.audit();
}

// ---- claims that wait --------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_claim_pending_with_provisioning_failed_warns_and_names_the_describe_command() {
    let rig = rig("pending-failed");
    let finding = rig.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "1 claim in acme-system on class gp3 has been Pending for 5 minutes or more with a ProvisioningFailed event: data-db-0"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("`kubectl describe pvc data-db-0 -n acme-system`"),
        "{fix}"
    );
    // The claim made two minutes ago, the bound one and the one on another class are not counted.
    assert_eq!(
        finding.observed["pending_claims"],
        json!([{"claim": "data-db-0", "minutes": 20, "provisioning_failed": true}])
    );
    assert_eq!(rig.paths(), [CLASSES, CSINODES, NAMESPACE, CLAIMS, EVENTS]);
    rig.audit();
}

#[tokio::test]
async fn waiting_for_a_first_consumer_is_normal_and_passes() {
    let rig = rig("pending-waiting");
    let finding = rig.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.observed["pending_claims"],
        json!([{"claim": "data-db-0", "minutes": 20, "provisioning_failed": false}])
    );
    rig.audit();
}

#[tokio::test]
async fn no_waiting_claim_means_the_events_are_not_read() {
    let rig = rig("no-waiting");
    let finding = rig.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["pending_claims"], json!([]));
    assert_eq!(rig.paths(), [CLASSES, CSINODES, NAMESPACE, CLAIMS]);
    rig.audit();
}

#[tokio::test]
async fn without_a_target_namespace_no_claim_is_read() {
    let rig = rig("no-waiting");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.observed.get("pending_claims").is_none());
    assert_eq!(rig.paths(), [CLASSES, CSINODES]);
}

#[tokio::test]
async fn forbidden_claims_or_events_are_partial_with_the_grant() {
    let claims = rig("claims-forbidden");
    let finding = claims.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        grants(&finding),
        ["list persistentvolumeclaims in acme-system"]
    );
    assert_eq!(finding.observed["pending_claims"], "not read");
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("`kubectl auth can-i list persistentvolumeclaims -n acme-system`"),
        "{fix}"
    );
    assert_eq!(engine(&claims, finding, None).status, Status::Warn);
    claims.audit();

    let events = rig("events-forbidden");
    let finding = events.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list events in acme-system"]);
    // The claim was seen, and the events that would say why it waits were not.
    assert_eq!(
        finding.observed["pending_claims"],
        json!([{"claim": "data-db-0", "minutes": 20, "provisioning_failed": false}])
    );
    events.audit();
}

#[tokio::test]
async fn a_target_namespace_that_does_not_exist_reads_no_claim() {
    let rig = rig("namespace-missing");
    let finding = rig.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.observed["pending_claims"],
        "namespace does not exist"
    );
    assert_eq!(
        finding.notes,
        ["The namespace acme-system does not exist, so no claim in it was read"]
    );
    assert!(finding.partial.is_none());
    assert_eq!(rig.paths(), [CLASSES, CSINODES, NAMESPACE]);
    rig.audit();
}

#[tokio::test]
async fn a_namespace_the_identity_may_not_get_does_not_stop_the_claim_list() {
    let rig = rig("namespace-forbidden");
    let finding = rig.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none(), "{:?}", finding.partial);
    assert_eq!(finding.observed["pending_claims"], json!([]));
    assert_eq!(rig.paths(), [CLASSES, CSINODES, NAMESPACE, CLAIMS]);
    rig.audit();
}

// ---- what never leaves the cluster -------------------------------------------------------------------------------

/// The marker the `secret-params` fixture puts in every value that must stay in the cluster, and the
/// account number inside the key ARN.
const SENTINELS: [&str; 2] = ["sentinel-7f3a", "111122223333"];

#[tokio::test]
async fn class_parameters_annotations_and_event_text_never_reach_the_result() {
    // The fixture must really serve the values, or the test below proves nothing.
    let seeded = rig("secret-params");
    let client = seeded.cluster.harness.client(seeded.ctx.probe());
    let classes = client
        .all::<StorageClass>()
        .list(&first_page())
        .await
        .expect("the class list");
    let held = serde_json::to_string(&classes.items).expect("serializes");
    assert!(held.matches(SENTINELS[0]).count() >= 6, "{held}");
    assert!(held.contains(SENTINELS[1]), "{held}");
    let events = client
        .namespaced::<Event>("acme-system")
        .list(&first_page().fields("involvedObject.kind=PersistentVolumeClaim"))
        .await
        .expect("the event list");
    let held = serde_json::to_string(&events.items).expect("serializes");
    assert!(held.matches(SENTINELS[0]).count() >= 3, "{held}");

    let rig = rig("secret-params");
    // Waiting claims make the check read the events too, so every server text is in play.
    let finding = rig.finding_in(json!({}), Some("acme-system")).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.observed["pending_claims"],
        json!([{"claim": "data-db-0", "minutes": 20, "provisioning_failed": true}])
    );
    assert_eq!(rig.paths(), [CLASSES, CSINODES, NAMESPACE, CLAIMS, EVENTS]);
    for severity in [None, Some("warn")] {
        let result = engine(&rig, finding.clone(), severity);
        let wire = serde_json::to_string(&result).expect("the result serializes");
        for sentinel in SENTINELS {
            assert!(
                !wire.contains(sentinel),
                "{sentinel} reached the result: {wire}"
            );
        }
        assert!(
            !wire.contains("kmsKeyId") && !wire.contains("provisioner-secret"),
            "{wire}"
        );
    }
    rig.audit();
}

// ---- every case ------------------------------------------------------------------------------------------------

/// Every fixture the sweep runs, with whether it has claims in the target namespace.
const CASES: &[(&str, bool)] = &[
    ("eks-gp2-no-csi", false),
    ("eks-ebs-csi", false),
    ("eks-gp2-with-addon", false),
    ("eks-auto-mode", false),
    ("k3s-local-path", false),
    ("gke-immediate", false),
    ("no-provisioner", false),
    ("unknown-provisioner", false),
    ("odf", false),
    ("none", false),
    ("no-default", false),
    ("two-defaults", false),
    ("capped", false),
    ("driver-object-only", false),
    ("csinode-forbidden", false),
    ("csinode-forbidden-no-object", false),
    ("both-forbidden", false),
    ("csidriver-forbidden", false),
    ("csinode-capped", false),
    ("list-forbidden", false),
    ("pending-failed", true),
    ("pending-waiting", true),
    ("claims-forbidden", true),
    ("events-forbidden", true),
    ("no-waiting", true),
    ("namespace-missing", true),
    ("namespace-forbidden", true),
    ("secret-params", true),
];

#[tokio::test]
async fn every_case_only_reads_stays_in_the_manifest_and_bounds_its_output() {
    let mut seen = std::collections::BTreeSet::new();
    for (case, claims) in CASES {
        let rig = rig(case);
        let finding = rig
            .finding_in(json!({}), claims.then_some("acme-system"))
            .await;
        // Only GETs, only the paths the guard lets this check read (the audit also proves it).
        let paths = rig.paths();
        seen.extend(paths.iter().cloned());
        assert!(
            paths
                .iter()
                .all(|path| path.starts_with("/apis/storage.k8s.io/v1/")
                    || path.starts_with(NAMESPACE)),
            "{case}: {paths:?}"
        );
        // A block always comes with a fix, and no result is a block on data it could not read.
        if finding.level == Level::Fail {
            assert!(finding.fix.is_some(), "{case}");
            assert!(finding.partial.is_none(), "{case}: {finding:?}");
        }
        // The output is bounded: few keys, short text.
        assert!(
            finding.observed.as_object().is_some_and(|o| o.len() <= 24),
            "{case}"
        );
        assert!(finding.message.len() <= 400, "{case}: {}", finding.message);
        assert!(
            finding.fix.as_ref().is_none_or(|fix| fix.len() <= 2000),
            "{case}"
        );
        rig.audit();
    }
    // Every resource the guard lets this check read (the `ALLOWED` entries that cite it, 02 Appendix B) is
    // read by some case: the namespace, the claims and events, and the three storage lists.
    for path in [CLASSES, CSINODES, CSIDRIVERS, NAMESPACE, CLAIMS, EVENTS] {
        assert!(seen.contains(path), "no case reads {path}");
    }
}

#[test]
fn the_info_is_registered_and_declares_what_the_check_needs() {
    assert_eq!(INFO.id, "k8s.storageclass");
    assert_eq!(INFO.family, "k8s");
    assert_eq!(INFO.needs, &[Need::KubeContext]);
    assert_eq!(INFO.default_timeout, Some(Duration::from_secs(30)));
    assert!(
        crate::registry::infos()
            .iter()
            .any(|info| info.id == "k8s.storageclass")
    );
    assert!(std::ptr::eq(StorageClassCheck::info(), &INFO));
    // The generic remediation text passes the allow-list too.
    rdy_engine::fixtext::check(INFO.meta.remediation).expect("remediation text is clean");
}
