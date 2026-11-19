//! Fixture tests of `k8s.dns`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.dns/`, written by
//! `scripts/gen-k8s-dns-fixtures.py`. Every `Rig` audits its run when it drops (INV-14): each request the
//! mock recorded passes the guard's rules and is logged under a check that `ALLOWED` cites. The clock is
//! pinned at 2026-11-17T12:00:00Z, which the generator counts its times from.

use std::sync::Arc;

use k8s_openapi::jiff::Timestamp;
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

const DEPLOYMENTS: &str = "/apis/apps/v1/namespaces/kube-system/deployments";
const DAEMONSETS: &str = "/apis/apps/v1/namespaces/kube-system/daemonsets";
const PODS: &str = "/api/v1/pods";
const SERVICE: &str = "/api/v1/namespaces/kube-system/services/kube-dns";
const RKE2_SERVICE: &str = "/api/v1/namespaces/kube-system/services/rke2-coredns-rke2-coredns";
const CONFIGMAP: &str = "/api/v1/namespaces/kube-system/configmaps/coredns";
const OS_DAEMONSETS: &str = "/apis/apps/v1/namespaces/openshift-dns/daemonsets";
const OS_PODS: &str = "/api/v1/pods";
const OS_SERVICE: &str = "/api/v1/namespaces/openshift-dns/services/dns-default";

/// The five reads of a CoreDNS cluster in kube-system.
const KUBEADM: [&str; 5] = [DEPLOYMENTS, DAEMONSETS, PODS, SERVICE, CONFIGMAP];

/// A cluster over the mock.
struct Fixtured {
    harness: Harness,
    version: ServerVersion,
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
        _probe: &Probe,
        _user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        // This check never impersonates.
        Err(ImpersonationError::Conflict)
    }

    fn is_openshift(&self) -> bool {
        self.openshift
    }
}

/// One fixture cluster, the check's context and the run that logs into it.
struct Rig {
    cluster: Arc<Fixtured>,
    ctx: CheckContext,
}

fn rig_with(case: &str, openshift: bool) -> Rig {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.dns/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.dns", Os::Linux, [Need::KubeContext]);
    Rig {
        cluster: Arc::new(Fixtured {
            harness,
            version: ServerVersion {
                git_version: "v1.30.2".to_owned(),
                major: "1".to_owned(),
                minor: "30".to_owned(),
                platform: "linux/amd64".to_owned(),
            },
            openshift,
        }),
        ctx,
    }
}

fn rig(case: &str) -> Rig {
    rig_with(case, false)
}

fn now() -> Timestamp {
    "2026-11-17T12:00:00Z".parse().expect("a time")
}

impl Rig {
    fn check(&self, spec: Value) -> DnsCheck {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let params: K8sDns = serde_json::from_value(spec).expect("the parameters parse");
        DnsCheck::new(params, cluster).at(now())
    }

    async fn finding(&self) -> Finding {
        self.finding_with(json!({})).await
    }

    async fn finding_with(&self, spec: Value) -> Finding {
        let finding = self
            .check(spec)
            .run(&self.ctx)
            .await
            .expect("the check ran");
        assert_text_is_clean(&finding);
        finding
    }

    /// The paths of every request, in order, all logged under `k8s.dns`. Every one is a GET: this check only
    /// reads.
    fn paths(&self) -> Vec<String> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.dns")),
            "every request carries the check id"
        );
        log.iter()
            .map(|entry| {
                assert_eq!(
                    entry.fields["method"].as_str(),
                    Some("GET"),
                    "the check only reads"
                );
                entry.fields["path"].as_str().unwrap_or_default().to_owned()
            })
            .collect()
    }

    fn audit(&self) {
        self.cluster.harness.audit().expect("INV-14 audit is clean");
    }
}

/// Every fix text and note of a finding passes the fix-text allow-list (commands only from `commands.txt`),
/// and nothing a hostile server sent reaches a terminal as a control character or a command span.
fn assert_text_is_clean(finding: &Finding) {
    for text in finding.fix.iter().chain(&finding.notes) {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("fix text breaks the allow-list: {error}\n{text}");
        }
        assert!(!text.contains('\u{2014}'), "no em dash: {text}");
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        assert!(!text.contains('\u{202e}'), "{text:?}");
    }
    let message = &finding.message;
    assert!(!message.contains('\u{2014}'), "{message}");
    assert!(!message.chars().any(char::is_control), "{message:?}");
    assert!(!message.contains('\u{202e}'), "{message:?}");
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
    let mut entry = json!({"id": "k8s.dns"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

// ---- the exit test: a crash-looping CoreDNS that forwards to /etc/resolv.conf ----------------------------------

#[tokio::test]
async fn a_crash_looping_coredns_that_forwards_to_resolv_conf_with_a_recent_termination_blocks() {
    let rig = rig("loop-crashloop");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("The cluster DNS is crash-looping and its Corefile forwards to /etc/resolv.conf: a forward loop"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .message
            .contains("container coredns of pod coredns-aaa"),
        "{}",
        finding.message
    );
    // The not-ready Deployment is the second issue, as a note.
    assert!(
        notes(&finding).contains("CoreDNS Deployment coredns in kube-system has 1 of 2 pods ready"),
        "{}",
        notes(&finding)
    );
    let fix = fix_of(&finding);
    assert!(
        fix.contains("CoreDNS forwards to `/etc/resolv.conf`"),
        "{fix}"
    );
    assert!(fix.contains("`forward . {upstream}`"), "{fix}");
    assert!(fix.contains("--resolv-conf"), "{fix}");
    assert!(fix.contains("`plugin/loop: Loop ... detected`"), "{fix}");
    assert!(
        fix.contains("`kubectl -n kube-system logs deploy/coredns`"),
        "{fix}"
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    assert_eq!(finding.observed["crash_loops"][0]["last_reason"], "Error");
    assert_eq!(
        finding.observed["crash_loops"][0]["last_ended_seconds_ago"],
        120
    );
    assert_eq!(rig.paths(), KUBEADM);
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn the_loop_verdict_stands_without_the_loop_plugin_and_says_the_cause_may_differ() {
    let rig = rig("loop-without-loop-plugin");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding.message.contains("a forward loop"),
        "{}",
        finding.message
    );
    assert!(
        finding.message.contains(": likely a forward loop"),
        "{}",
        finding.message
    );
    assert!(
        notes(&finding).contains("The Corefile has no loop plugin"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn lifetime_restarts_alone_do_not_block() {
    let rig = rig("kubeadm-ok");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns has 2 of 2 pods ready; Service kube-dns has ClusterIP 10.96.0.10; cluster domain is cluster.local"
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(finding.fix.is_none(), "{finding:?}");
    // The 14 restarts are shown, and are no verdict.
    assert_eq!(finding.observed["most_lifetime_restarts"], 14);
    assert_eq!(finding.observed["crash_loops"], json!([]));
    assert_eq!(
        finding.observed["corefile"]["forwards_to_resolv_conf"],
        true
    );
    assert_eq!(finding.observed["service"]["cluster_ip"], "10.96.0.10");
    assert_eq!(finding.expected["cluster_domain"], "cluster.local");
    assert_eq!(rig.paths(), KUBEADM);
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn a_recent_last_run_of_a_pod_that_is_running_again_is_not_a_crash_loop() {
    let rig = rig("kubeadm-restarts-recent-but-running");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["crash_loops"], json!([]));
    rig.audit();
}

#[tokio::test]
async fn a_crash_loop_whose_last_run_ended_hours_ago_is_not_loop_evidence() {
    let rig = rig("crashloop-old");
    let finding = rig.finding().await;
    // The Deployment is short of ready pods, so that blocks. The loop does not.
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system has 1 of 2 pods ready"
    );
    assert!(
        notes(&finding)
            .contains("its last run ended 5 hours ago, so it is not counted as recent evidence"),
        "{}",
        notes(&finding)
    );
    assert!(
        !fix_of(&finding).contains("plugin/loop"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_crash_loop_with_no_termination_time_is_not_loop_evidence() {
    let rig = rig("crashloop-no-finish-time");
    let finding = rig.finding().await;
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system has 1 of 2 pods ready"
    );
    assert!(
        notes(&finding).contains("at a time the pod does not say"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_crash_loop_with_explicit_upstreams_is_not_called_a_loop() {
    let rig = rig("crashloop-explicit-upstream");
    let finding = rig.finding().await;
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system has 1 of 2 pods ready"
    );
    assert!(
        notes(&finding).contains("does not forward the root zone to /etc/resolv.conf, so this is not the forward loop that rdy can see"),
        "{}",
        notes(&finding)
    );
    assert!(
        fix_of(&finding).contains("`kubectl -n kube-system logs deploy/coredns --previous`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn an_oom_kill_is_not_a_forward_loop() {
    let rig = rig("crashloop-oom");
    let finding = rig.finding().await;
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system has 1 of 2 pods ready"
    );
    assert!(
        notes(&finding).contains("was OOMKilled 2 minutes ago"),
        "{}",
        notes(&finding)
    );
    assert!(!fix_of(&finding).contains("plugin/loop"));
    rig.audit();
}

#[tokio::test]
async fn a_crash_loop_without_the_corefile_is_partial_with_the_grant() {
    let rig = rig("loop-corefile-forbidden");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system has 1 of 2 pods ready"
    );
    assert_eq!(grants(&finding), ["get configmap kube-system/coredns"]);
    assert!(
        partial_note(&finding).contains("whether the crash loop is a forward loop was not read"),
        "{}",
        partial_note(&finding)
    );
    assert!(
        fix_of(&finding).contains("`kubectl auth can-i get configmaps/coredns -n kube-system`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_forbidden_corefile_is_only_a_note_when_nothing_needs_it() {
    let rig = rig("healthy-corefile-forbidden");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(
        notes(&finding).contains("may not get ConfigMap coredns in kube-system"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_forbidden_corefile_is_partial_when_the_spec_names_a_cluster_domain() {
    let rig = rig("healthy-corefile-forbidden");
    let finding = rig
        .finding_with(json!({"cluster_domain": "corp.internal"}))
        .await;
    assert!(finding.partial.is_some(), "{finding:?}");
    assert!(
        partial_note(&finding).contains("whether the cluster domain is corp.internal was not read"),
        "{}",
        partial_note(&finding)
    );
    assert_eq!(grants(&finding), ["get configmap kube-system/coredns"]);
    rig.audit();
}

// ---- readiness ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_deployment_with_no_ready_pod_blocks() {
    let rig = rig("not-ready");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system has 0 of 2 pods ready"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.contains("`kubectl -n kube-system get pods -l k8s-app=kube-dns`"),
        "{fix}"
    );
    assert!(
        fix.contains("`kubectl -n kube-system describe deploy/coredns`"),
        "{fix}"
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn a_deployment_scaled_to_zero_blocks() {
    let rig = rig("scaled-to-zero");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system wants no pods, so nothing answers DNS"
    );
    rig.audit();
}

#[tokio::test]
async fn a_deployment_with_no_replicas_field_wants_one_pod() {
    let rig = rig("default-replicas");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("CoreDNS Deployment coredns has 1 of 1 pods ready")
    );
    rig.audit();
}

// ---- the cluster domain ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_cluster_domain_that_is_not_the_default_is_a_note_when_the_spec_names_none() {
    let rig = rig("domain-other");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding)
            .contains("The cluster domain is corp.internal, not the default cluster.local"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_cluster_domain_that_is_not_the_one_the_spec_names_blocks() {
    let rig = rig("domain-other");
    let finding = rig
        .finding_with(json!({"cluster_domain": "cluster.local"}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "The cluster domain is corp.internal, and the spec expects cluster.local"
    );
    assert!(
        fix_of(&finding).contains("kubelet `--cluster-domain`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_corefile_zone_that_is_a_shell_command_never_reaches_a_command_span() {
    let rig = rig("hostile-zone");
    let finding = rig
        .finding_with(json!({"cluster_domain": "cluster.local"}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    let fix = fix_of(&finding);
    assert!(
        fix.contains("The cluster domain is `<cluster domain>`"),
        "{fix}"
    );
    assert!(!fix.contains("curl"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn the_spec_names_the_cluster_domain() {
    let rig = rig("domain-other");
    let finding = rig
        .finding_with(json!({"cluster_domain": "corp.internal"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding.message.ends_with("cluster domain is corp.internal"),
        "{}",
        finding.message
    );
    assert_eq!(finding.expected["cluster_domain"], "corp.internal");
    rig.audit();
}

#[tokio::test]
async fn a_corefile_with_no_kubernetes_zone_is_a_note_or_partial() {
    let rig = rig("corefile-no-zone");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert!(
        notes(&finding).contains("no kubernetes plugin zone"),
        "{}",
        notes(&finding)
    );
    let rig = self::rig("corefile-no-zone");
    let finding = rig
        .finding_with(json!({"cluster_domain": "cluster.local"}))
        .await;
    assert!(partial_note(&finding).contains("the Corefile has no kubernetes zone"));
}

#[tokio::test]
async fn a_configmap_with_no_corefile_key_is_a_note() {
    let rig = rig("corefile-no-key");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("has no Corefile key"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

// ---- NodeLocal DNSCache -------------------------------------------------------------------------------------

#[tokio::test]
async fn node_local_dns_is_a_note_with_its_count() {
    let rig = rig("nodelocal");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("NodeLocal DNSCache node-local-dns runs on 2 of 3 nodes."),
        "{}",
        notes(&finding)
    );
    // It is not counted as the cluster DNS.
    assert_eq!(
        finding.observed["workloads"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(finding.observed["node_local_dns"][0]["ready"], 2);
    rig.audit();
}

#[tokio::test]
async fn a_workload_the_label_selector_returned_by_mistake_is_not_cluster_dns() {
    let rig = rig("label-noise");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.observed["workloads"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(finding.observed["workloads"][0]["name"], "coredns");
    rig.audit();
}

// ---- the Service -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_headless_service_warns() {
    let rig = rig("service-headless");
    let finding = rig.finding().await;
    // 03 names no level for the Service, so it is a warn, not a block.
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Warn);
    assert_eq!(
        finding.message,
        "Service kube-dns in kube-system has no ClusterIP, so pods have no DNS address"
    );
    assert!(fix_of(&finding).contains("`kubectl -n kube-system get service kube-dns -o yaml`"));
    rig.audit();
}

#[tokio::test]
async fn a_service_that_is_not_there_is_unverified_not_a_block() {
    let rig = rig("service-missing");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("no Service named kube-dns exists in kube-system"),
        "{}",
        partial_note(&finding)
    );
    assert!(fix_of(&finding).contains("`kubectl -n kube-system get services`"));
    rig.audit();
}

#[tokio::test]
async fn a_service_the_identity_may_not_get_is_partial_with_the_grant() {
    let rig = rig("service-forbidden");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get service kube-dns in kube-system"]);
    assert!(
        fix_of(&finding).contains("`kubectl auth can-i get services/kube-dns -n kube-system`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_service_with_no_port_53_is_a_note() {
    let rig = rig("service-no-port");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("lists no UDP port 53"),
        "{}",
        notes(&finding)
    );
    assert!(
        notes(&finding).contains("lists no TCP port 53"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_service_with_no_tcp_port_53_is_a_note_that_says_rdy_tests_neither() {
    let rig = rig("service-no-tcp");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        !notes(&finding).contains("no UDP port 53"),
        "{}",
        notes(&finding)
    );
    assert!(
        notes(&finding).contains("lists no TCP port 53. Answers too big for UDP fall back to TCP. rdy does not test either."),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

// ---- nothing, or nothing readable --------------------------------------------------------------------------

#[tokio::test]
async fn no_dns_and_no_service_warns_after_looking_in_openshift_dns_too() {
    let rig = rig("no-dns");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.starts_with("No cluster DNS was found"),
        "{}",
        finding.message
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    // No pod list: with no DNS workload there is nothing to explain.
    assert_eq!(
        rig.paths(),
        [
            DEPLOYMENTS,
            DAEMONSETS,
            OS_DAEMONSETS,
            OS_DAEMONSETS,
            SERVICE
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn a_service_with_no_workload_under_the_label_is_partial_not_a_block() {
    let rig = rig("workload-gone-service-there");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("no workload carries a cluster DNS label"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn nothing_readable_is_partial_with_every_grant_and_never_a_block() {
    let rig = rig("all-forbidden");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        grants(&finding),
        [
            "list deployments in kube-system",
            "list daemonsets in kube-system",
            "list pods",
            "get service kube-dns in kube-system",
        ]
    );
    let fix = fix_of(&finding);
    assert!(fix.contains("examples/rbac/rdy-readonly.yaml"), "{fix}");
    assert!(
        fix.contains("`kubectl auth can-i list deployments -n kube-system`"),
        "{fix}"
    );
    // A kube-system that could not be read is no reason to look in openshift-dns.
    assert_eq!(rig.paths(), [DEPLOYMENTS, DAEMONSETS, PODS, SERVICE]);
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_cluster_known_to_be_openshift_looks_in_openshift_dns_even_when_kube_system_is_closed() {
    let rig = rig_with("all-forbidden", true);
    // The fixture holds no openshift-dns file, so the request fails the run: that is the proof it is asked.
    rig.check(json!({}))
        .run(&rig.ctx)
        .await
        .expect("the check ran");
    assert!(
        rig.paths().iter().any(|path| path == OS_DAEMONSETS),
        "{:?}",
        rig.paths()
    );
    // The mock answered 501 for what it does not hold, which this audit reports.
    assert!(rig.cluster.harness.audit().is_err());
}

#[tokio::test]
async fn openshift_dns_that_may_not_be_listed_is_partial_with_the_openshift_role() {
    let rig = rig("openshift-namespace-forbidden");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list daemonsets in openshift-dns"]);
    assert!(
        fix_of(&finding).contains("examples/rbac/rdy-readonly-openshift-dns.yaml"),
        "{}",
        fix_of(&finding)
    );
    // No "no cluster DNS" block: an OpenShift cluster was not ruled out.
    assert!(
        !finding.message.starts_with("No cluster DNS"),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_list_with_a_second_page_is_partial() {
    let rig = rig("cut");
    let finding = rig.finding().await;
    assert!(
        partial_note(&finding)
            .contains("the deployments of kube-system after the first page were not read"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

// ---- RKE2, OpenShift and GKE -------------------------------------------------------------------------------

#[tokio::test]
async fn rke2_is_found_by_label_not_by_the_name_coredns() {
    let rig = rig("rke2");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.observed["workloads"][0]["name"],
        "rke2-coredns-rke2-coredns"
    );
    assert_eq!(finding.observed["workloads"][0]["engine"], "CoreDNS");
    // RKE2 names its Service after its Deployment, so `kube-dns` is asked first and then that name.
    assert_eq!(
        finding.observed["service"]["name"],
        "rke2-coredns-rke2-coredns"
    );
    assert_eq!(finding.observed["service"]["cluster_ip"], "10.43.0.10");
    // The ConfigMap `coredns` does not exist on RKE2: a note, never a block.
    assert!(
        notes(&finding).contains("ConfigMap coredns was not found in kube-system"),
        "{}",
        notes(&finding)
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    assert_eq!(
        rig.paths(),
        [
            DEPLOYMENTS,
            DAEMONSETS,
            PODS,
            SERVICE,
            RKE2_SERVICE,
            CONFIGMAP
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn rke2_with_neither_service_is_unverified_not_a_block() {
    let rig = rig("rke2-no-service");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding)
            .contains("no Service named kube-dns or rke2-coredns-rke2-coredns exists"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn rke2_with_a_crash_loop_cannot_tell_a_loop_without_the_corefile() {
    let rig = rig("rke2-loop");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "CoreDNS Deployment rke2-coredns-rke2-coredns in kube-system has 0 of 1 pods ready"
    );
    assert!(
        partial_note(&finding).contains("whether the crash loop is a forward loop was not read"),
        "{}",
        partial_note(&finding)
    );
    assert!(
        grants(&finding).is_empty(),
        "the file is not forbidden, only not there"
    );
    rig.audit();
}

#[tokio::test]
async fn openshift_is_found_in_openshift_dns_by_its_label() {
    let rig = rig("openshift");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "OpenShift DNS DaemonSet dns-default has 6 of 6 pods ready; Service dns-default has ClusterIP 172.30.0.10"
    );
    assert_eq!(finding.observed["namespace"], "openshift-dns");
    assert_eq!(finding.observed["workloads"][0]["engine"], "OpenShift DNS");
    assert!(
        notes(&finding).contains("The cluster domain was not checked"),
        "{}",
        notes(&finding)
    );
    assert!(finding.partial.is_none(), "{finding:?}");
    // No kube-dns Service and no ConfigMap coredns is asked for on OpenShift: the fixture holds neither.
    assert_eq!(
        rig.paths(),
        [DEPLOYMENTS, DAEMONSETS, OS_DAEMONSETS, OS_PODS, OS_SERVICE]
    );
    rig.audit();
}

#[tokio::test]
async fn openshift_with_a_missing_pod_blocks_and_names_its_commands() {
    let rig = rig("openshift-partial");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "OpenShift DNS DaemonSet dns-default in openshift-dns has 5 of 6 pods ready"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.contains(
            "`kubectl -n openshift-dns get pods -l dns.operator.openshift.io/daemonset-dns=default`"
        ),
        "{fix}"
    );
    assert!(
        fix.contains("`kubectl -n openshift-dns logs ds/dns-default`"),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn openshift_with_no_dns_service_is_unverified_not_a_block() {
    let rig = rig("openshift-service-missing");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("no Service named dns-default exists in openshift-dns"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn openshift_is_found_by_name_when_its_labels_drift() {
    let rig = rig("openshift-labels-drift");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["workloads"][0]["name"], "dns-default");
    assert_eq!(finding.observed["namespace"], "openshift-dns");
    rig.audit();
}

#[tokio::test]
async fn an_openshift_crash_loop_has_no_corefile_to_call_a_loop() {
    let rig = rig("openshift-crashloop");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        !finding.message.contains("forward loop"),
        "{}",
        finding.message
    );
    assert!(
        notes(&finding)
            .contains("has no Corefile that rdy reads, so a forward loop cannot be told"),
        "{}",
        notes(&finding)
    );
    // The logs command names the DNS namespace, not kube-system.
    assert!(
        fix_of(&finding).contains("`kubectl -n openshift-dns logs ds/dns-default --previous`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn gke_is_kube_dns_with_no_corefile_and_no_configmap_request() {
    let rig = rig("gke");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.observed["workloads"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(finding.observed["workloads"][0]["engine"], "kube-dns");
    assert_eq!(finding.observed["workloads"][0]["name"], "kube-dns");
    assert_eq!(finding.observed["corefile"], Value::Null);
    assert!(
        notes(&finding).contains("The cluster domain was not checked"),
        "{}",
        notes(&finding)
    );
    // The fixture holds no ConfigMap: asking for one would fail the run.
    assert_eq!(rig.paths(), [DEPLOYMENTS, DAEMONSETS, PODS, SERVICE]);
    rig.audit();
}

#[tokio::test]
async fn gke_with_a_named_cluster_domain_is_partial_because_there_is_no_corefile() {
    let rig = rig("gke");
    let finding = rig
        .finding_with(json!({"cluster_domain": "corp.internal"}))
        .await;
    assert!(
        partial_note(&finding).contains("whether the cluster domain is corp.internal was not read"),
        "{}",
        partial_note(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_gke_crash_loop_is_never_called_a_forward_loop() {
    let rig = rig("gke-crashloop");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "kube-dns Deployment kube-dns in kube-system has 1 of 2 pods ready"
    );
    assert!(!fix_of(&finding).contains("plugin/loop"));
    rig.audit();
}

// ---- hostile answers ---------------------------------------------------------------------------------------

#[tokio::test]
async fn text_from_the_server_stays_inert() {
    let rig = rig("hostile");
    let finding = rig.finding().await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    // The name has the shape of nothing, so a command carries `<name>`.
    let fix = fix_of(&finding);
    assert!(fix.contains("describe deploy/<name>"), "{fix}");
    assert!(!fix.contains("rm -rf"), "{fix}");
    assert!(
        !finding.message.contains("rm -rf /`"),
        "{}",
        finding.message
    );
    let observed = finding.observed.to_string();
    assert!(!observed.contains('\u{1b}'), "{observed}");
    assert!(!observed.contains('\u{202e}'), "{observed}");
    rig.audit();
}

#[tokio::test]
async fn env_values_and_other_configmap_keys_never_reach_the_finding() {
    for case in ["kubeadm-ok", "loop-crashloop"] {
        let rig = rig(case);
        let finding = rig.finding().await;
        let all = format!("{finding:?}");
        assert!(!all.contains("ENV-VALUE-MUST-NOT-APPEAR"), "{case}: {all}");
        assert!(!all.contains("KEY-MUST-NOT-APPEAR"), "{case}: {all}");
        rig.audit();
    }
}

#[tokio::test]
async fn a_last_run_dated_after_the_clock_is_skew_and_no_evidence() {
    let rig = rig("crashloop-skew");
    let finding = rig.finding().await;
    assert_eq!(
        finding.message,
        "CoreDNS Deployment coredns in kube-system has 1 of 2 pods ready"
    );
    assert!(
        notes(&finding).contains("(clock skew)"),
        "{}",
        notes(&finding)
    );
    assert!(!fix_of(&finding).contains("plugin/loop"));
    rig.audit();
}

#[tokio::test]
async fn grants_in_both_namespaces_name_both_role_files() {
    let rig = rig_with("both-forbidden", true);
    let finding = rig.finding().await;
    let fix = fix_of(&finding);
    assert!(
        fix.contains(
            "The roles in examples/rbac/rdy-readonly.yaml and examples/rbac/rdy-readonly-openshift-dns.yaml have them."
        ),
        "{fix}"
    );
    assert!(grants(&finding).contains(&"list daemonsets in openshift-dns".to_owned()));
    rig.audit();
}

#[tokio::test]
async fn the_refused_rke2_service_is_the_one_the_grant_names() {
    let rig = rig("rke2-service-forbidden");
    let finding = rig.finding().await;
    assert_eq!(
        grants(&finding),
        ["get service rke2-coredns-rke2-coredns in kube-system"]
    );
    assert!(
        fix_of(&finding)
            .contains("`kubectl auth can-i get services/rke2-coredns-rke2-coredns -n kube-system`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

// ---- every ALLOWED entry of this check is hit (M1-115) --------------------------------------------------------

/// The `ALLOWED` entries that cite this check and that no fixture run reads yet.
const NOT_READ_YET: &[&str] = &[];

#[tokio::test]
async fn every_allowed_entry_that_cites_this_check_is_read_by_a_fixture_run() {
    crate::client::mock::hits::clear();
    for case in ["kubeadm-ok", "openshift", "rke2", "crashloop-old"] {
        let rig = rig_with(case, case == "openshift");
        let _ = rig.finding().await;
    }
    assert_eq!(
        crate::client::mock::hits::unhit("k8s.dns"),
        NOT_READ_YET,
        "an ALLOWED entry citing k8s.dns is read by no fixture of the tests listed here"
    );
}
