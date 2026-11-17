//! Fixture tests of `k8s.nodes`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.nodes/`, written by
//! `scripts/gen-k8s-nodes-fixtures.py`. Every `Rig` audits its run when it drops (INV-14): each request the
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

const NODES: &str = "/api/v1/nodes";
const GROUPS: &str = "/apis";
const DEPLOYMENTS: &str = "/apis/apps/v1/namespaces/kube-system/deployments";

/// A cluster over the mock.
struct Fixtured {
    harness: Harness,
}

impl Cluster for Fixtured {
    fn server_version(&self) -> &ServerVersion {
        static VERSION: std::sync::OnceLock<ServerVersion> = std::sync::OnceLock::new();
        VERSION.get_or_init(|| ServerVersion {
            git_version: "v1.29.4".to_owned(),
            major: "1".to_owned(),
            minor: "29".to_owned(),
            platform: "linux/amd64".to_owned(),
        })
    }

    fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        self.harness.client(probe)
    }

    fn read_only_as(
        &self,
        _probe: &Probe,
        _user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        Err(ImpersonationError::Conflict)
    }
}

/// One fixture cluster, the check's context and the run that logs into it.
struct Rig {
    cluster: Arc<Fixtured>,
    ctx: CheckContext,
}

fn rig(case: &str) -> Rig {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.nodes/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.nodes", Os::Linux, [Need::KubeContext]);
    Rig {
        cluster: Arc::new(Fixtured { harness }),
        ctx,
    }
}

fn params(spec: Value) -> K8sNodes {
    serde_json::from_value(spec).expect("the parameters parse")
}

impl Rig {
    async fn finding(&self, spec: Value) -> Finding {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let finding = NodesCheck::new(params(spec), cluster)
            .run(&self.ctx)
            .await
            .expect("the check ran");
        assert_fix_text_is_clean(&finding);
        finding
    }

    /// The path of every request, in order, all GET and all logged under `k8s.nodes`.
    fn paths(&self) -> Vec<String> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.nodes")),
            "every request carries the check id"
        );
        assert!(
            log.iter().all(|entry| entry.fields["method"] == "GET"),
            "the check only reads"
        );
        log.iter()
            .map(|entry| entry.fields["path"].as_str().unwrap_or_default().to_owned())
            .collect()
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

fn partial_note(finding: &Finding) -> String {
    finding
        .partial
        .as_ref()
        .map(|partial| partial.note.clone())
        .unwrap_or_default()
}

/// What the engine makes of a finding for an entry with this severity.
fn engine(rig: &Rig, finding: Finding, severity: Option<&str>) -> rdy_spec::result::CheckResult {
    let mut entry = json!({"id": "k8s.nodes"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

// ---- the exit test ----------------------------------------------------------------------------------------

#[tokio::test]
async fn cpu_7_passes_on_an_8_vcpu_node_that_shows_7910m() {
    let rig = rig("healthy");
    let finding = rig
        .finding(json!({"min_ready": 3, "per_node": {"cpu": 7, "memory": "28Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "3 of 3 nodes count, the smallest has 7910m CPU and 28.2Gi memory allocatable"
    );
    assert!(finding.partial.is_none());
    // Capacity is printed next to allocatable.
    assert_eq!(finding.observed["nodes"][0]["cpu"]["allocatable"], "7910m");
    assert_eq!(finding.observed["nodes"][0]["cpu"]["capacity"], "8");
    assert_eq!(rig.paths(), [NODES]);
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn cpu_8_does_not_pass_because_allocatable_is_below_the_machine_size() {
    let rig = rig("healthy");
    let finding = rig
        .finding(json!({"min_ready": 3, "per_node": {"cpu": 8}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Only 0 of 3 counted nodes have 8 CPU allocatable (the smallest has 7910m CPU)"
    );
    assert!(
        finding
            .fix
            .expect("a fix")
            .contains("allocatable is less than the machine size")
    );
    rig.audit();
}

#[tokio::test]
async fn cordoned_windows_fargate_virtual_not_ready_and_tainted_nodes_do_not_count() {
    let rig = rig("excluded");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "3 of 10 nodes count (1 on Fargate, 1 virtual, 1 not Linux, 1 cordoned, 1 not Ready, 2 tainted)"
    );
    assert_eq!(finding.observed["counted"], 3);
    assert_eq!(
        finding.observed["excluded"],
        json!({"fargate": 1, "virtual": 1, "not_linux": 1, "cordoned": 1, "not_ready": 1, "tainted": 2})
    );
    rig.audit();

    // One more than there are: the shortfall names every reason, and the fix has the node commands.
    let short = rig.finding_again(json!({"min_ready": 4})).await;
    assert_eq!(short.level, Level::Fail, "{short:?}");
    assert_eq!(
        short.message,
        "Only 3 of 10 nodes can run the product, and the spec needs 4 (1 on Fargate, 1 virtual, 1 not Linux, 1 cordoned, 1 not Ready, 2 tainted)"
    );
    let fix = short.fix.expect("a fix");
    assert!(fix.contains("`kubectl uncordon acme-cordoned`"), "{fix}");
    assert!(
        fix.contains("`kubectl describe node acme-notready`"),
        "{fix}"
    );
    assert!(fix.contains("eksctl create nodegroup"), "{fix}");
}

impl Rig {
    /// A second run on the same cluster (the log keeps both).
    async fn finding_again(&self, spec: Value) -> Finding {
        self.finding(spec).await
    }
}

#[tokio::test]
async fn a_toleration_makes_a_tainted_pool_count() {
    let rig = rig("excluded");
    let gpu = rig
        .finding(json!({
            "min_ready": 4,
            "tolerations": [{"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}]
        }))
        .await;
    assert_eq!(gpu.level, Level::Pass, "{gpu:?}");
    assert_eq!(gpu.observed["counted"], 4);
    // A toleration with no key tolerates every taint, the control plane's too.
    let all = rig
        .finding(json!({"min_ready": 5, "tolerations": [{"operator": "Exists"}]}))
        .await;
    assert_eq!(all.level, Level::Pass, "{all:?}");
    assert_eq!(all.observed["counted"], 5);
    // `Equal` needs the value.
    let wrong = rig
        .finding(json!({
            "min_ready": 4,
            "tolerations": [{"key": "nvidia.com/gpu", "value": "absent", "effect": "NoSchedule"}]
        }))
        .await;
    assert_eq!(wrong.level, Level::Fail, "{wrong:?}");
    let right = rig
        .finding(json!({
            "min_ready": 4,
            "tolerations": [{"key": "nvidia.com/gpu", "value": "present"}]
        }))
        .await;
    assert_eq!(right.level, Level::Pass, "{right:?}");
    rig.audit();
}

#[tokio::test]
async fn a_prefer_no_schedule_taint_does_not_exclude() {
    let rig = rig("prefer-no-schedule");
    let finding = rig.finding(json!({"min_ready": 2})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn arch_and_selector_narrow_the_count() {
    let rig = rig("arch");
    let amd = rig
        .finding(json!({"min_ready": 2, "arch": ["amd64"]}))
        .await;
    assert_eq!(amd.level, Level::Pass, "{amd:?}");
    assert_eq!(amd.observed["counted"], 2);
    assert_eq!(amd.observed["excluded"], json!({"arch": 3}));
    // `x86_64` is `amd64`, and `aarch64` is `arm64`.
    let both = rig
        .finding(json!({"min_ready": 4, "arch": ["x86_64", "aarch64"]}))
        .await;
    assert_eq!(both.level, Level::Pass, "{both:?}");
    assert_eq!(both.observed["arch"], json!({"amd64": 2, "arm64": 2}));
    let three = rig
        .finding(json!({"min_ready": 3, "arch": ["arm64"]}))
        .await;
    assert_eq!(three.level, Level::Fail, "{three:?}");
    rig.audit();

    let rig = self::rig("selector");
    let pool = rig
        .finding(json!({"min_ready": 2, "selector": {"acme.example/pool": "product"}}))
        .await;
    assert_eq!(pool.level, Level::Pass, "{pool:?}");
    let more = rig
        .finding(json!({"min_ready": 3, "selector": {"acme.example/pool": "product"}}))
        .await;
    assert_eq!(more.level, Level::Fail, "{more:?}");
    assert!(
        more.message.contains("1 not matching the selector"),
        "{}",
        more.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_forbidden_node_list_is_partial_and_never_a_block() {
    let rig = rig("forbidden");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "Not verified: the node list could not be read (the identity may not list nodes)"
    );
    let partial = finding.partial.clone().expect("a partial");
    assert_eq!(partial.missing_grants, ["list nodes"]);
    assert!(
        finding
            .fix
            .clone()
            .expect("a fix")
            .contains("kubectl auth can-i list nodes")
    );
    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Warn, "{result:?}");
    assert!(
        result.message.starts_with("not verified"),
        "{}",
        result.message
    );
    assert_eq!(rig.paths(), [NODES]);
    rig.audit();
}

// ---- autoscalers ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_autoscaled_single_node_warns_instead_of_blocking() {
    let rig = rig("scaler-karpenter");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Only 1 of 1 nodes can run the product, and the spec needs 3. Capacity may scale (Karpenter is installed), not verified"
    );
    assert_eq!(finding.observed["autoscaler"], "Karpenter");
    assert_eq!(rig.paths(), [NODES, GROUPS]);
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();

    let rig = self::rig("scaler-deployment");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(finding.message.contains("cluster-autoscaler is installed"));
    assert_eq!(rig.paths(), [NODES, GROUPS, DEPLOYMENTS]);
    rig.audit();
}

#[tokio::test]
async fn node_labels_and_names_show_a_managed_autoscaler_with_no_request() {
    for (case, name) in [
        ("scaler-auto-mode", "EKS Auto Mode"),
        ("scaler-karpenter-node", "Karpenter"),
        ("scaler-autopilot", "GKE Autopilot"),
    ] {
        let rig = rig(case);
        let finding = rig.finding(json!({"min_ready": 3})).await;
        assert_eq!(finding.level, Level::Warn, "{case}: {finding:?}");
        assert_eq!(finding.observed["autoscaler"], name, "{case}");
        assert_eq!(rig.paths(), [NODES], "{case}");
        rig.audit();
    }
}

#[tokio::test]
async fn no_autoscaler_means_the_shortfall_blocks() {
    let rig = rig("scaler-none");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(finding.observed["autoscaler"], "none found");
    assert_eq!(rig.paths(), [NODES, GROUPS, DEPLOYMENTS]);
    rig.audit();
}

#[tokio::test]
async fn an_autoscaler_that_cannot_be_looked_for_leaves_the_block_and_says_so() {
    let rig = rig("scaler-unreadable");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(finding.observed["autoscaler"], "not known");
    assert!(
        finding.notes.iter().any(|note| note
            .contains("rdy could not check for a node autoscaler (the group list: the identity may not read it; the identity may not list deployments in kube-system)")),
        "{:?}",
        finding.notes
    );
    rig.audit();
}

#[tokio::test]
async fn an_autoscaler_does_not_excuse_a_node_that_is_too_small() {
    let rig = rig("scaler-small");
    let finding = rig.finding(json!({"per_node": {"cpu": 7}})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    // The size is wrong, so no autoscaler is asked about.
    assert_eq!(rig.paths(), [NODES]);
    rig.audit();

    let with_count = self::rig("scaler-small");
    let finding = with_count
        .finding(json!({"min_ready": 1, "per_node": {"cpu": 7}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(with_count.paths(), [NODES]);
}

// ---- sizes -----------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_form_of_a_quantity_is_read() {
    let rig = rig("quantities");
    let finding = rig
        .finding(json!({
            "per_node": {"cpu": 7, "memory": "28Gi", "ephemeral": "90Gi", "pods": 100}
        }))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["meeting_per_node"], 3);
    rig.audit();
}

#[tokio::test]
async fn small_nodes_block_with_the_smallest_size_and_the_node_group_fix() {
    let rig = rig("small");
    let finding = rig
        .finding(json!({"min_ready": 3, "per_node": {"cpu": 7, "memory": "28Gi"}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Only 0 of 3 counted nodes have 7 CPU and 28Gi memory allocatable (the smallest has 3920m CPU and 14Gi memory)"
    );
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains(
            "`eksctl create nodegroup --cluster <cluster> --nodes 3 --node-type m6i.2xlarge`"
        ),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn with_min_ready_only_that_many_nodes_need_the_size_and_without_it_every_node_does() {
    let rig = rig("one-small");
    let two = rig
        .finding(json!({"min_ready": 2, "per_node": {"cpu": 7}}))
        .await;
    assert_eq!(two.level, Level::Pass, "{two:?}");
    assert_eq!(two.observed["meeting_per_node"], 2);
    let three = rig
        .finding(json!({"min_ready": 3, "per_node": {"cpu": 7}}))
        .await;
    assert_eq!(three.level, Level::Fail, "{three:?}");
    assert!(
        three
            .message
            .starts_with("Only 2 of 3 counted nodes have 7 CPU allocatable")
    );
    let each = rig.finding(json!({"per_node": {"cpu": 7}})).await;
    assert_eq!(each.level, Level::Fail, "{each:?}");
    rig.audit();
}

#[tokio::test]
async fn the_pod_count_limit_is_its_own_problem_with_the_eks_fix() {
    let rig = rig("pods-limit");
    let finding = rig
        .finding(json!({"min_ready": 3, "per_node": {"pods": 30}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Only 0 of 3 counted nodes allow 30 pods. acme-node-1 (t3.medium) allows 17"
    );
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("ENABLE_PREFIX_DELEGATION=true"), "{fix}");
    assert!(fix.contains("`kubectl describe node acme-node-1`"), "{fix}");
    rig.audit();

    let other = self::rig("pods-limit-other");
    let finding = other
        .finding(json!({"min_ready": 3, "per_node": {"pods": 100}}))
        .await;
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("maxPods"), "{fix}");
    assert!(!fix.contains("ENABLE_PREFIX_DELEGATION"), "{fix}");
}

#[tokio::test]
async fn a_node_that_reports_no_allocatable_is_below_every_need() {
    let rig = rig("no-allocatable");
    let finding = rig.finding(json!({"per_node": {"cpu": 1}})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .contains("the smallest has CPU not reported"),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn pressure_on_a_counted_node_warns() {
    let rig = rig("pressure");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "1 counted node reports MemoryPressure and DiskPressure: acme-node-3"
    );
    assert!(
        finding
            .fix
            .expect("a fix")
            .contains("`kubectl describe node acme-node-3`")
    );
    rig.audit();
}

// ---- zones -----------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn min_zones_blocks_on_one_zone_and_has_no_default() {
    let rig = rig("single-zone");
    let finding = rig.finding(json!({"min_ready": 3, "min_zones": 2})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "The counted nodes span 1 zone, and the spec needs 2"
    );
    let plain = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(plain.level, Level::Pass, "{plain:?}");
    assert_eq!(plain.observed["zones"], json!(["us-east-1a"]));
    rig.audit();

    let healthy = self::rig("healthy");
    let finding = healthy.finding(json!({"min_zones": 3})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
}

#[tokio::test]
async fn absent_zone_labels_are_not_evaluated_never_a_pass() {
    let rig = rig("no-zones");
    let finding = rig.finding(json!({"min_zones": 2})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(partial_note(&finding).contains("min_zones was not evaluated"));
    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Warn, "{result:?}");
    rig.audit();
}

// ---- free capacity ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn free_is_not_evaluated_and_so_never_a_pass() {
    let rig = rig("healthy");
    let finding = rig
        .finding(json!({"min_ready": 3, "free": {"cpu": 16}}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(partial_note(&finding).contains("free capacity was not evaluated"));
    assert_eq!(finding.observed["free"], "not evaluated");
    // No pod is listed: the pod list is M1-159's.
    assert_eq!(rig.paths(), [NODES]);
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

// ---- lists --------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_node_list_is_read_page_by_page() {
    let rig = rig("paged");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["nodes_read"], 3);
    assert_eq!(finding.observed["list_cut"], false);
    assert_eq!(rig.paths(), [NODES, NODES]);
    let seen = rig.cluster.harness.mock().seen();
    assert!(
        seen[1].line().contains("continue=tok-more"),
        "{}",
        seen[1].line()
    );
    rig.audit();
}

#[tokio::test]
async fn a_list_cut_by_a_failing_server_is_partial() {
    let rig = rig("capped");
    let finding = rig.finding(json!({"min_ready": 2})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["list_cut"], true);
    assert!(
        partial_note(&finding)
            .contains("the node list was cut after 2 nodes, the rest are not evaluated")
    );
    rig.audit();
}

#[tokio::test]
async fn an_empty_list_has_no_node_that_the_product_can_use() {
    let rig = rig("empty");
    let finding = rig.finding(json!({"min_ready": 1})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "The cluster has no node that the product can use"
    );
    rig.audit();
}

// ---- text from the cluster --------------------------------------------------------------------------------------

#[tokio::test]
async fn hostile_names_are_escaped_and_never_reach_a_command() {
    let rig = rig("hostile");
    let finding = rig
        .finding(json!({"min_ready": 5, "per_node": {"cpu": 1}}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    let wire = serde_json::to_string(&engine(&rig, finding.clone(), None)).expect("serializes");
    assert!(!wire.contains('\u{1b}'), "{wire}");
    assert!(!wire.contains('\u{202e}'), "{wire}");
    let fix = finding.fix.expect("a fix");
    // `--all` is not a name: the command holds the placeholder.
    assert!(fix.contains("`kubectl uncordon <node>`"), "{fix}");
    assert!(!fix.contains("--all"), "{fix}");
    // Text that is not a quantity is "not reported", never a pass: the node's allocatable is empty.
    let garbage = finding.observed["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["name"] == "acme-garbage")
        .expect("the garbage node is counted");
    for resource in ["cpu", "memory", "ephemeral", "pods"] {
        assert!(garbage[resource]["allocatable"].is_null(), "{garbage}");
    }
    let texts: Vec<&str> = std::iter::once(finding.message.as_str())
        .chain(finding.notes.iter().map(String::as_str))
        .collect();
    assert!(
        texts.iter().any(|text| text.contains("CPU not reported")),
        "{texts:?}"
    );
    rig.audit();
}

// ---- review fixes (M1-113 fix round) ---------------------------------------------------------------------------

#[tokio::test]
async fn a_cut_list_makes_a_count_or_zone_shortfall_a_warning_with_a_partial() {
    let rig = rig("capped");
    let count = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(count.level, Level::Warn, "{count:?}");
    assert!(
        count
            .message
            .ends_with("The node list was cut, so more nodes may exist"),
        "{}",
        count.message
    );
    assert!(partial_note(&count).contains("cut after 2 nodes"));
    let zones = rig.finding(json!({"min_ready": 2, "min_zones": 3})).await;
    assert_eq!(zones.level, Level::Warn, "{zones:?}");
    rig.audit();
}

#[tokio::test]
async fn lifecycle_taints_do_not_exclude_a_node_and_the_condition_is_judged_on_its_own() {
    // `pressure` carries the real memory-pressure and disk-pressure taints: the node counts and warns.
    let rig = rig("pressure");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(finding.observed["counted"], 3);
    rig.audit();
    // `excluded` has the unreachable taints on a node whose Ready is Unknown: it is `not Ready`, not tainted.
    let rig = self::rig("excluded");
    let finding = rig.finding(json!({"min_ready": 3})).await;
    assert_eq!(finding.observed["excluded"]["not_ready"], 1);
    assert_eq!(finding.observed["excluded"]["tainted"], 2);
}

#[tokio::test]
async fn with_no_node_counted_it_fails_unless_an_autoscaler_is_evident() {
    let managed = rig("zero-auto-mode");
    let finding = managed.finding(json!({"per_node": {"cpu": 7}})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.contains("EKS Auto Mode is installed"),
        "{}",
        finding.message
    );
    // A spec that asks nothing about size or count still needs a node.
    let zones = managed.finding(json!({"min_zones": 1})).await;
    assert_eq!(zones.level, Level::Warn, "{zones:?}");
    managed.audit();

    let plain = rig("zero-plain");
    let finding = plain.finding(json!({"min_zones": 1})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(finding.message, "No node can run the product (1 cordoned)");
    plain.audit();
}

#[tokio::test]
async fn a_zone_label_of_zero_is_no_zone() {
    let rig = rig("aks-no-zone");
    let finding = rig.finding(json!({"min_ready": 3, "min_zones": 2})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(partial_note(&finding).contains("min_zones was not evaluated"));
    rig.audit();
}

#[tokio::test]
async fn more_autoscalers_are_found_by_node_pool_group_and_helm_label() {
    for (case, what, paths) in [
        ("scaler-nap", "GKE node auto-provisioning", vec![NODES]),
        (
            "scaler-openshift",
            "the OpenShift machine autoscaler",
            vec![NODES, GROUPS],
        ),
        (
            "scaler-helm",
            "cluster-autoscaler",
            vec![NODES, GROUPS, DEPLOYMENTS],
        ),
    ] {
        let rig = rig(case);
        let finding = rig.finding(json!({"min_ready": 3})).await;
        assert_eq!(finding.level, Level::Warn, "{case}: {finding:?}");
        assert_eq!(finding.observed["autoscaler"], what, "{case}");
        assert_eq!(rig.paths(), paths, "{case}");
        rig.audit();
    }
}

#[tokio::test]
async fn per_node_is_only_a_hint_where_new_nodes_are_sized_to_pending_pods() {
    let rig = rig("scaler-auto-mode");
    let finding = rig
        .finding(json!({"min_ready": 1, "per_node": {"cpu": 7}}))
        .await;
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.starts_with("per_node is only a hint here: EKS Auto Mode")),
        "{:?}",
        finding.notes
    );
    // No hint, no note.
    let plain = self::rig("healthy");
    let finding = plain
        .finding(json!({"min_ready": 3, "per_node": {"cpu": 7}}))
        .await;
    assert!(finding.notes.is_empty(), "{:?}", finding.notes);
}

// ---- the engine ----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_block_becomes_a_warning_when_the_spec_says_severity_warn() {
    let rig = rig("small");
    let finding = rig.finding(json!({"per_node": {"cpu": 7}})).await;
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[test]
fn the_remediation_text_is_on_the_allow_list() {
    rdy_engine::fixtext::check(INFO.meta.remediation).expect("remediation text is clean");
}

// ---- every ALLOWED entry of this check is hit (M1-115) --------------------------------------------------------

/// The `ALLOWED` entries that cite this check and that no fixture run reads yet.
const NOT_READ_YET: &[&str] = &["/v1/pods"];

#[test]
fn every_allowed_entry_that_cites_this_check_is_read_by_a_fixture_run() {
    // Not read yet: the pod list belongs to the free capacity half, which M1-159 builds. When it lands,
    // this list must be empty, and the assert below fails until it is.
    // The fixture tests below run their own runtime on this thread and audit when their rig drops, which
    // records each (entry, check) pair a recorded request hit.
    crate::client::mock::hits::clear();
    a_block_becomes_a_warning_when_the_spec_says_severity_warn();
    a_cut_list_makes_a_count_or_zone_shortfall_a_warning_with_a_partial();
    assert_eq!(
        crate::client::mock::hits::unhit("k8s.nodes"),
        NOT_READ_YET,
        "an ALLOWED entry citing k8s.nodes is read by no fixture of the tests listed here"
    );
}
