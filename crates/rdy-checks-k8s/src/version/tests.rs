//! Fixture tests of `k8s.version`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.version/`. Every `Rig` audits its run when
//! it drops (INV-14): each request the mock recorded passes the guard's rules and is logged under a check
//! that `ALLOWED` cites.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckContext, CheckOutcome, Finding, Level, Need, Os, PeerClass};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::Probe;
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};
use rdy_spec::check::K8sVersion;
use rdy_spec::result::{ActionOutcome, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;
use crate::client::ServerVersion;
use crate::client::mock::Harness;

/// A cluster over the mock: the `/version` answer the fixture records, and the harness for the rest.
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

fn rig(case: &str) -> Rig {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.version/{case}"))
        .expect("the fixture loads");
    let body = fixture
        .replay()
        .api_records()
        .find(|(method, path, _, _)| *method == "GET" && *path == "/version")
        .map(|(_, _, _, record)| record.body.clone())
        .expect("the fixture records /version");
    let text = |key: &str| body[key].as_str().expect("a text field").to_owned();
    let version = ServerVersion {
        git_version: text("gitVersion"),
        major: text("major"),
        minor: text("minor"),
        platform: text("platform"),
    };
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.version", Os::Linux, [Need::KubeContext]);
    Rig {
        cluster: Arc::new(Fixtured { harness, version }),
        ctx,
    }
}

fn params(spec: Value) -> K8sVersion {
    serde_json::from_value(spec).expect("the parameters parse")
}

impl Rig {
    async fn outcome(&self, spec: Value) -> CheckOutcome {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        VersionCheck::new(params(spec), cluster)
            .run(&self.ctx)
            .await
    }

    async fn finding(&self, spec: Value) -> Finding {
        self.outcome(spec).await.expect("the check ran")
    }

    /// The `(method, path, outcome)` of every request, in order, all logged under `k8s.version`.
    fn requests(&self) -> Vec<(String, String, ActionOutcome)> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.version")),
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
                )
            })
            .collect()
    }

    fn paths(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .map(|(_, path, _)| path)
            .collect()
    }

    fn audit(&self) {
        self.cluster.harness.audit().expect("INV-14 audit is clean");
    }
}

// ---- the exit test --------------------------------------------------------------------------------------------

#[tokio::test]
async fn eks_v1_29_4_parses_to_1_29_and_passes_when_the_apis_are_served() {
    let rig = rig("eks");
    let finding = rig
        .finding(json!({
            "min": "1.27", "max": "1.31",
            "apis": ["autoscaling/v2 HorizontalPodAutoscaler", "networking.k8s.io/v1 Ingress", "batch/v1 CronJob", "v1 Pod"]
        }))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Server v1.29.4-eks-abc123, 1.27 to 1.31 needed, 4 APIs served"
    );
    assert_eq!(finding.observed["kubernetes"], "1.29.4");
    assert_eq!(finding.observed["distribution"], "eks");
    assert_eq!(finding.observed["cloud"], "aws");
    assert_eq!(finding.observed["nodes_read"], 2);
    assert_eq!(finding.observed["kubelet_minors"], json!(["1.28", "1.29"]));
    assert_eq!(
        finding.observed["apis"][3],
        json!({"api": "v1 Pod", "served": true})
    );
    assert_eq!(
        finding.expected,
        json!({"min": "1.27", "max": "1.31", "over_max": "warn", "apis": [
            "autoscaling/v2 HorizontalPodAutoscaler", "networking.k8s.io/v1 Ingress",
            "batch/v1 CronJob", "v1 Pod"]})
    );
    assert!(finding.partial.is_none());
    // The requests: the group list, the nodes, and one document per group version (the core one is /api/v1).
    assert_eq!(
        rig.paths(),
        [
            "/apis",
            "/api/v1/nodes",
            "/apis/autoscaling/v2",
            "/apis/networking.k8s.io/v1",
            "/apis/batch/v1",
            "/api/v1",
        ]
    );
    assert!(
        rig.requests()
            .iter()
            .all(|(method, _, outcome)| method == "GET" && *outcome == ActionOutcome::Ok)
    );
    rig.audit();
}

#[tokio::test]
async fn plain_v1_29_4_with_azure_labels_is_aks() {
    let rig = rig("aks");
    let finding = rig.finding(json!({"min": "1.28"})).await;
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.message, "Server v1.29.4, 1.28 or newer needed");
    assert_eq!(finding.observed["distribution"], "aks");
    assert_eq!(finding.observed["cloud"], "azure");
    // The AKS command is in the fix when the server is too old.
    let old = rig.finding(json!({"min": "1.31"})).await;
    assert_eq!(old.level, Level::Fail);
    let fix = old.fix.expect("a fix");
    assert!(
        fix.contains("az aks upgrade -g <resource-group> -n <cluster> --kubernetes-version 1.30"),
        "{fix}"
    );
    assert!(fix.contains("then repeat for 1.31"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn openshift_reads_the_cluster_version() {
    let rig = rig("openshift");
    let finding = rig.finding(json!({"openshift_min": "4.14"})).await;
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(
        finding.message,
        "OpenShift 4.14.9 (Kubernetes v1.27.8+3f8e0c1), 4.14 or newer needed"
    );
    assert_eq!(finding.observed["distribution"], "openshift");
    assert_eq!(finding.observed["openshift_version"], "4.14.9");
    assert!(
        rig.paths()
            .contains(&"/apis/config.openshift.io/v1/clusterversions/version".to_owned())
    );

    let old = rig.finding(json!({"openshift_min": "4.15"})).await;
    assert_eq!(old.level, Level::Fail);
    assert_eq!(
        old.message,
        "OpenShift 4.14.9 is older than the 4.15 minimum (Kubernetes v1.27.8+3f8e0c1)"
    );
    let fix = old.fix.expect("a fix");
    assert!(fix.contains("oc adm upgrade channel stable-4.15"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn on_openshift_openshift_min_replaces_min_and_min_alone_still_applies() {
    let rig = rig("openshift");
    // Kubernetes 1.27 is below min 1.28, but OpenShift 4.14 meets openshift_min: pass, and the note says why.
    let both = rig
        .finding(json!({"min": "1.28", "openshift_min": "4.14"}))
        .await;
    assert_eq!(both.level, Level::Pass);
    assert!(
        both.notes.iter().any(|note| note.contains("not applied")),
        "{:?}",
        both.notes
    );
    // With no openshift_min, min is a Kubernetes bound and blocks. The ClusterVersion is not asked for.
    let alone = self::rig("openshift");
    let only_min = alone.finding(json!({"min": "1.28"})).await;
    assert_eq!(only_min.level, Level::Fail);
    assert!(only_min.fix.expect("fix").contains("oc adm upgrade"));
    assert!(
        !alone
            .paths()
            .iter()
            .any(|path| path.contains("clusterversions")),
        "{:?}",
        alone.paths()
    );
    alone.audit();
    // max still applies to the Kubernetes version.
    let max = rig
        .finding(json!({"openshift_min": "4.14", "max": "1.26"}))
        .await;
    assert_eq!(max.level, Level::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_forbidden_cluster_version_is_partial_and_never_blocks() {
    let rig = rig("openshift-forbidden");
    let finding = rig.finding(json!({"openshift_min": "4.15"})).await;
    assert_eq!(
        finding.level,
        Level::Pass,
        "nothing was measured as failing"
    );
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial.note.contains("openshift_min was not checked"),
        "{}",
        partial.note
    );
    assert_eq!(
        partial.missing_grants,
        ["get clusterversions.config.openshift.io/version"]
    );
    // The engine turns a pass with a partial on a required check into a warning.
    let result = map_outcome(
        &INFO,
        &CheckSpec::new("k8s.version"),
        &rig.ctx,
        Ok(finding),
        0,
        0,
    );
    assert_eq!(result.status, Status::Warn);
    assert!(
        result.message.starts_with("not verified:"),
        "{}",
        result.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_missing_autoscaling_v2_blocks() {
    let rig = rig("missing-apis");
    let finding = rig
        .finding(json!({"apis": ["autoscaling/v2 HorizontalPodAutoscaler"]}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "autoscaling/v2 HorizontalPodAutoscaler is not served"
    );
    assert_eq!(
        finding.observed["apis"],
        json!([{"api": "autoscaling/v2 HorizontalPodAutoscaler", "served": false}])
    );
    let result = map_outcome(
        &INFO,
        &CheckSpec::new("k8s.version"),
        &rig.ctx,
        Ok(finding),
        0,
        0,
    );
    assert_eq!(result.status, Status::Block);
    // `/apis` already says the group version is not served, so no document is asked for.
    assert_eq!(rig.paths(), ["/apis", "/api/v1/nodes"]);
    rig.audit();
}

#[tokio::test]
async fn missing_apis_say_why() {
    let rig = rig("missing-apis");
    let finding = rig
        .finding(json!({"apis": [
            "autoscaling/v2 HorizontalPodAutoscaler",
            "autoscaling/v2beta2 HorizontalPodAutoscaler",
            "batch/v1 CronJob",
            "v1 Pod",
            "v2 Pod"
        ]}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "4 required APIs are not served: autoscaling/v2 HorizontalPodAutoscaler, autoscaling/v2beta2 HorizontalPodAutoscaler, batch/v1 CronJob, and 1 more"
    );
    let fix = finding.fix.expect("fix");
    // The first three are explained: v2 (general), v2beta2 (removed in 1.26) and the CronJob kind.
    assert!(
        fix.contains(
            "\"autoscaling/v2beta2 HorizontalPodAutoscaler\" was removed in Kubernetes 1.26"
        ),
        "{fix}"
    );
    assert!(fix.contains("uses \"autoscaling/v2\""), "{fix}");
    assert!(fix.contains("\"batch/v1 CronJob\" is not served"), "{fix}");
    // The core document lists Pod; version v2 of the core group is not a thing and needs no request.
    assert_eq!(
        rig.paths(),
        ["/apis", "/api/v1/nodes", "/apis/batch/v1", "/api/v1"]
    );
    rig.audit();
}

#[tokio::test]
async fn an_openshift_update_in_progress_is_judged_on_the_last_completed_version() {
    let rig = rig("openshift-updating");
    // The cluster runs 4.14.9 and is moving to 4.15.2: a 4.15 minimum is not met yet.
    let finding = rig.finding(json!({"openshift_min": "4.15"})).await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "OpenShift 4.14.9 is older than the 4.15 minimum (Kubernetes v1.28.5+3f8e0c1)"
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.contains("An OpenShift update is running, from 4.14.9 to 4.15.2")),
        "{:?}",
        finding.notes
    );
    let pass = rig.finding(json!({"openshift_min": "4.14"})).await;
    assert_eq!(pass.level, Level::Pass);
    assert_eq!(pass.observed["openshift_version"], "4.14.9");
    rig.audit();
}

// ---- a group list the identity may not read -------------------------------------------------------------------

#[tokio::test]
async fn an_unreadable_group_list_still_finds_openshift_through_the_cluster_version() {
    let rig = rig("apis-unreadable-openshift");
    // Kubernetes 1.27 is below min 1.28, but this is OpenShift 4.14, so only openshift_min applies.
    let finding = rig
        .finding(json!({"min": "1.28", "openshift_min": "4.14"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["distribution"], "openshift");
    assert_eq!(finding.observed["openshift_version"], "4.14.9");
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.contains("not applied")),
        "{:?}",
        finding.notes
    );
    let old = rig.finding(json!({"openshift_min": "4.15"})).await;
    assert_eq!(old.level, Level::Fail);
    rig.audit();
}

#[tokio::test]
async fn an_unreadable_group_list_and_cluster_version_leave_min_unapplied_and_partial() {
    let rig = rig("apis-unreadable-forbidden");
    // 1.27 is below min 1.28. rdy cannot tell whether this is OpenShift, so it does not block on min.
    let finding = rig
        .finding(json!({"min": "1.28", "openshift_min": "4.14"}))
        .await;
    assert_eq!(
        finding.level,
        Level::Pass,
        "nothing was measured as failing"
    );
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial.note.contains("openshift_min was not checked")
            && partial
                .note
                .contains("cannot tell whether this is OpenShift"),
        "{}",
        partial.note
    );
    assert_eq!(
        partial.missing_grants,
        ["get clusterversions.config.openshift.io/version"]
    );
    let result = map_outcome(
        &INFO,
        &CheckSpec::new("k8s.version"),
        &rig.ctx,
        Ok(finding),
        0,
        0,
    );
    assert_eq!(result.status, Status::Warn);
    // The requests: the group list, the ClusterVersion, the nodes.
    assert_eq!(
        rig.paths(),
        [
            "/apis",
            "/apis/config.openshift.io/v1/clusterversions/version",
            "/api/v1/nodes"
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn an_unreadable_group_list_and_no_cluster_version_is_not_openshift_and_min_applies() {
    let rig = rig("apis-unreadable-vanilla");
    let finding = rig
        .finding(json!({"min": "1.28", "openshift_min": "4.14"}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "Server v1.27.4 is older than the 1.28 minimum"
    );
    assert_eq!(finding.observed["distribution"], "vanilla");
    assert!(finding.partial.is_none(), "{:?}", finding.partial);
    // Without openshift_min the ClusterVersion is not asked for at all.
    let plain = self::rig("apis-unreadable-vanilla");
    let finding = plain.finding(json!({"min": "1.28"})).await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(plain.paths(), ["/apis", "/api/v1/nodes"]);
    plain.audit();
    rig.audit();
}

// ---- the nodes ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_forbidden_node_list_is_partial_with_the_grant_and_never_blocks() {
    let rig = rig("nodes-forbidden");
    let finding = rig.finding(json!({"min": "1.28"})).await;
    assert_eq!(
        finding.level,
        Level::Pass,
        "nothing was measured as failing"
    );
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial.note.contains("kubelet skew was not checked")
            && partial.note.contains("the identity may not read it"),
        "{}",
        partial.note
    );
    assert_eq!(partial.missing_grants, ["list nodes"]);
    // The suffix still says EKS.
    assert_eq!(finding.observed["distribution"], "eks");
    assert!(finding.observed.get("nodes_read").is_none());
    let requests = rig.requests();
    assert_eq!(requests[1].2, ActionOutcome::Failed);
    // A required check with a partial pass is a warning, never a block.
    let result = map_outcome(
        &INFO,
        &CheckSpec::new("k8s.version"),
        &rig.ctx,
        Ok(finding),
        0,
        0,
    );
    assert_eq!(result.status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_kubelet_far_behind_or_ahead_warns_and_a_virtual_kubelet_is_left_out() {
    let rig = rig("skew");
    let finding = rig.finding(json!({"min": "1.28"})).await;
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(
        finding.message,
        "1 kubelet is too far behind the API server: acme-old-1 (1.24.3); 1 kubelet is newer than the API server: acme-new-1 (1.30.0)"
    );
    let fix = finding.fix.expect("fix");
    assert!(fix.contains("never newer"), "{fix}");
    assert!(fix.contains("several API servers"), "{fix}");
    // 1.26 is three minors behind 1.29: allowed. The virtual kubelet does not count.
    assert!(!finding.message.contains("acme-edge-1"));
    assert!(!finding.message.contains("acme-virtual-1"));
    assert_eq!(
        finding.observed["kubelet_minors"],
        json!(["1.24", "1.26", "1.28", "1.30"])
    );
    rig.audit();
}

#[tokio::test]
async fn a_node_list_with_a_second_page_is_partial_and_says_the_rest_is_not_evaluated() {
    let rig = rig("paged");
    let finding = rig.finding(json!({"min": "1.28"})).await;
    assert_eq!(finding.level, Level::Pass);
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial.note.contains("first 500 nodes only")
            && partial.note.contains("the rest are not evaluated"),
        "{}",
        partial.note
    );
    assert!(partial.missing_grants.is_empty());
    // One page only: no continue request.
    assert_eq!(rig.paths(), ["/apis", "/api/v1/nodes"]);
    rig.audit();
}

// ---- the distributions ----------------------------------------------------------------------------------------

#[tokio::test]
async fn every_distribution_fixture_is_named_by_its_evidence() {
    for (case, distro, cloud) in [
        ("eks", "eks", Some("aws")),
        ("gke", "gke", Some("gcp")),
        ("aks", "aks", Some("azure")),
        ("openshift", "openshift", Some("aws")),
        ("k3s", "k3s", None),
        ("rke2", "rke2", None),
        ("kind", "kind", Some("kind")),
        ("vanilla", "vanilla", Some("aws")),
    ] {
        let rig = rig(case);
        let finding = rig.finding(json!({"min": "1.20"})).await;
        assert_eq!(finding.level, Level::Pass, "{case}: {finding:?}");
        assert_eq!(finding.observed["distribution"], distro, "{case}");
        assert_eq!(
            finding.observed.get("cloud").and_then(Value::as_str),
            cloud,
            "{case}"
        );
        rig.audit();
    }
}

#[tokio::test]
async fn gke_below_min_gets_the_gke_command() {
    let rig = rig("gke");
    let finding = rig.finding(json!({"min": "1.28"})).await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "Server v1.26.9-gke.1000 is older than the 1.28 minimum"
    );
    assert_eq!(
        finding.fix.as_deref(),
        Some(
            "Cluster is 1.26.9, product needs 1.28 or newer. GKE moves the control plane one minor at a time. Find the 1.27 version with `gcloud container get-server-config --location=<location>`, then run `gcloud container clusters upgrade <cluster> --master --location=<location> --cluster-version <the 1.27 version>`, wait for it to finish, then repeat for 1.28. Then upgrade the node pools."
        )
    );
    rig.audit();
}

#[tokio::test]
async fn eks_below_min_lists_the_minors_one_at_a_time() {
    let rig = rig("eks");
    let finding = rig.finding(json!({"min": "1.31"})).await;
    assert_eq!(finding.level, Level::Fail);
    let fix = finding.fix.expect("fix");
    assert!(
        fix.contains(
            "`aws eks update-cluster-version --region <region> --name <cluster> --kubernetes-version 1.30`"
        ),
        "{fix}"
    );
    assert!(fix.contains("then repeat for 1.31"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn a_cluster_that_is_not_openshift_ignores_openshift_min_and_never_asks_for_the_cluster_version()
 {
    let rig = rig("eks");
    let finding = rig.finding(json!({"openshift_min": "4.14"})).await;
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(
        finding.message,
        "Server v1.29.4-eks-abc123 is not OpenShift, so openshift_min does not apply"
    );
    assert!(
        !rig.paths()
            .iter()
            .any(|path| path.contains("clusterversions"))
    );
    rig.audit();
}

// ---- max and over_max -----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_newer_server_warns_or_blocks_by_over_max() {
    let rig = rig("eks");
    let warn = rig.finding(json!({"max": "1.28"})).await;
    assert_eq!(warn.level, Level::Warn);
    assert_eq!(
        warn.message,
        "Server v1.29.4-eks-abc123 is newer than 1.28, the newest this product is tested on"
    );
    assert_eq!(warn.expected, json!({"max": "1.28", "over_max": "warn"}));
    let block = rig
        .finding(json!({"max": "1.28", "over_max": "block"}))
        .await;
    assert_eq!(block.level, Level::Fail);
    assert_eq!(block.expected, json!({"max": "1.28", "over_max": "block"}));
    // The same minor is not over: max is compared over the parts it names.
    let same = rig.finding(json!({"max": "1.29"})).await;
    assert_eq!(same.level, Level::Pass);
    assert_eq!(
        same.message,
        "Server v1.29.4-eks-abc123, 1.29 or older needed"
    );
    // A min and a max problem together: the block comes first, the warning is in the notes.
    let both = rig.finding(json!({"min": "1.31", "max": "1.27"})).await;
    assert_eq!(both.level, Level::Fail);
    assert!(
        both.message.ends_with("(and 1 more, see the notes)"),
        "{}",
        both.message
    );
    assert_eq!(both.notes.len(), 1);
    rig.audit();
}

// ---- hostile and odd servers ----------------------------------------------------------------------------------

#[tokio::test]
async fn a_version_text_that_is_not_kubernetes_warns_and_is_partial() {
    let rig = rig("unreadable-version");
    let finding = rig.finding(json!({"min": "1.28"})).await;
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.contains("`acme-build-7`"),
        "{}",
        finding.message
    );
    assert!(finding.partial.is_some());
    assert_eq!(finding.observed, json!({"git_version": "acme-build-7"}));
    // Nothing can be compared, so the cluster is not asked for anything more.
    assert!(rig.paths().is_empty());
    rig.audit();
}

#[tokio::test]
async fn an_unreadable_version_still_blocks_on_an_api_the_server_does_not_serve() {
    let rig = rig("unreadable-version");
    // `/apis` lists autoscaling v2 and v1, so v2beta2 is not served: a block that needs no version.
    let finding = rig
        .finding(json!({"min": "1.28", "apis": [
            "autoscaling/v2beta2 HorizontalPodAutoscaler"
        ]}))
        .await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "autoscaling/v2beta2 HorizontalPodAutoscaler is not served"
    );
    assert!(finding.partial.is_some(), "the version was not compared");
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.contains("acme-build-7")),
        "{:?}",
        finding.notes
    );
    let fix = finding.fix.clone().expect("fix");
    assert!(
        fix.contains("\"autoscaling/v2beta2 HorizontalPodAutoscaler\" is not served"),
        "the server minor is unknown, so no removal is claimed: {fix}"
    );
    assert!(fix.contains("kubectl version"), "{fix}");
    // The group list is read, the nodes are not, and `/apis` already says the group version is absent.
    assert_eq!(rig.paths(), ["/apis"]);
    let result = map_outcome(
        &INFO,
        &CheckSpec::new("k8s.version"),
        &rig.ctx,
        Ok(finding),
        0,
        0,
    );
    assert_eq!(result.status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn the_check_declares_what_the_registry_and_the_planner_read() {
    let check = VersionCheck::new(params(json!({"min": "1.28"})), rig("eks").cluster);
    let info = check.info();
    assert_eq!(info.id, "k8s.version");
    assert_eq!(info.needs, [Need::KubeContext]);
    assert_eq!(info.default_timeout, Some(Duration::from_secs(10)));
    assert!(info.reads.is_empty() && info.commands.is_empty());
    // It talks to the API server, and the connection may go through a proxy (ADR 0037).
    assert_eq!(info.peers, [PeerClass::KubeApi, PeerClass::Proxy]);
    assert!(
        crate::registry::infos()
            .iter()
            .any(|registered| registered.id == "k8s.version")
    );
}
