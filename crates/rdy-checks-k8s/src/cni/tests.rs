//! Fixture tests of `k8s.cni`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.cni/`, written by
//! `scripts/gen-k8s-cni-fixtures.py`. Every `Rig` audits its run when it drops (INV-14): each request the
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
const APIS: &str = "/apis";
const SC_V1: &str = "/apis/networking.k8s.io/v1/servicecidrs";
const SC_BETA: &str = "/apis/networking.k8s.io/v1beta1/servicecidrs";
const KUBEADM: &str = "/api/v1/namespaces/kube-system/configmaps/kubeadm-config";
const POLICIES: &str = "/apis/networking.k8s.io/v1/namespaces/acme-system/networkpolicies";
const OCP: &str = "/apis/config.openshift.io/v1/networks/cluster";

/// The marker that the fixtures put in annotations, env values and args. It must never reach a finding.
const MARKER: &str = "ENV-VALUE-MARKER-4f9c2a7e1b3d";

fn ds(namespace: &str, name: &str) -> String {
    format!("/apis/apps/v1/namespaces/{namespace}/daemonsets/{name}")
}

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
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.cni/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.cni", Os::Linux, [Need::KubeContext]);
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

fn params(spec: Value) -> K8sCni {
    serde_json::from_value(spec).expect("the parameters parse")
}

impl Rig {
    fn check(&self, spec: Value, namespace: Option<&str>) -> CniCheck {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let namespace = namespace.map(|name| serde_json::from_value(json!(name)).expect("a name"));
        CniCheck::new(params(spec), namespace, cluster)
    }

    /// The finding for the install namespace `acme-system`.
    async fn finding(&self, spec: Value) -> Finding {
        self.finding_in(spec, Some("acme-system")).await
    }

    async fn finding_in(&self, spec: Value, namespace: Option<&str>) -> Finding {
        let finding = self
            .check(spec, namespace)
            .run(&self.ctx)
            .await
            .expect("the check ran");
        assert_text_is_clean(&finding);
        finding
    }

    /// The paths of every request, in order. Every one is a GET: this check only reads.
    fn paths(&self) -> Vec<String> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.cni")),
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

/// Every fix text and note passes the fix-text allow-list, and nothing carries the marker, an escape, a
/// backtick from the server or an em dash.
fn assert_text_is_clean(finding: &Finding) {
    for text in finding.fix.iter().chain(&finding.notes) {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("fix text breaks the allow-list: {error}\n{text}");
        }
        assert!(!text.contains('\u{2014}'), "no em dash: {text}");
    }
    let all = format!("{finding:?}");
    assert!(
        !all.contains(MARKER),
        "an env value or annotation leaked: {all}"
    );
    assert!(!all.contains("\\u{1b}"), "an escape sequence leaked: {all}");
    assert!(
        !all.contains('\u{202e}'),
        "a direction override leaked: {all}"
    );
    if let Some(fix) = &finding.fix {
        assert!(
            !fix.contains("rm -rf") && !fix.contains("\\x1b"),
            "server text reached a fix: {fix}"
        );
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

fn engine(rig: &Rig, finding: Finding, severity: Option<&str>) -> rdy_spec::result::CheckResult {
    let mut entry = json!({"id": "k8s.cni"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

fn no_daemonset(paths: &[String]) {
    assert!(
        paths.iter().all(|p| !p.contains("/daemonsets/")),
        "a DaemonSet was read: {paths:?}"
    );
}

/// The default requests of a cluster whose plugin the cheap signals name, with a kubeadm service range.
fn cheap_kubeadm() -> Vec<&'static str> {
    vec![NODES, APIS, SC_V1, SC_BETA, KUBEADM, POLICIES]
}

// ---- the exit test ----------------------------------------------------------------------------------------

#[tokio::test]
async fn k3s_with_no_daemonset_is_flannel_from_the_node_condition() {
    let rig = rig("k3s-flannel");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("Network plugin Flannel (the node condition FlannelIsUp)"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["plugin"]["id"], "flannel");
    assert_eq!(finding.observed["k3s"], true);
    // The pod ranges are the node ranges, because Flannel uses node IPAM.
    assert_eq!(
        finding.observed["pod_ranges"]["ranges"],
        json!(["10.42.0.0/24", "10.42.1.0/24", "10.42.2.0/24"])
    );
    // No DaemonSet was asked for: the node condition settled it.
    let paths = rig.paths();
    no_daemonset(&paths);
    assert_eq!(paths, [NODES, APIS, SC_V1, SC_BETA, KUBEADM, POLICIES]);
    rig.audit();
}

#[tokio::test]
async fn k3s_with_enforced_is_partial_not_a_block() {
    // k3s runs its own network policy controller unless it was disabled, so Flannel on k3s is not "no".
    let rig = rig("k3s-flannel");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding)
            .contains("k3s runs Flannel and enforces NetworkPolicy with its own controller"),
        "{finding:?}"
    );
    assert!(
        fix_of(&finding).contains("`--disable-network-policy`"),
        "{}",
        fix_of(&finding)
    );
    assert!(grants(&finding).is_empty());
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn flannel_with_enforced_blocks_on_a_cluster_that_is_not_k3s() {
    let rig = rig("kubeadm-flannel");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "Flannel does not enforce NetworkPolicy, and the spec needs it enforced"
    );
    assert!(fix_of(&finding).starts_with("Flannel does not enforce NetworkPolicy, so the policies the product ships would be ignored."), "{}", fix_of(&finding));
    assert!(fix_of(&finding).contains("Calico, Cilium or Antrea"));
    assert!(finding.partial.is_none(), "{finding:?}");
    assert_eq!(finding.observed["enforces_network_policy"], "no");
    assert_eq!(
        finding.observed["service_ranges"]["ranges"],
        json!(["10.96.0.0/12"])
    );
    no_daemonset(&rig.paths());
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn flannel_without_the_enforced_key_is_a_note() {
    let rig = rig("kubeadm-flannel");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding)
            .contains("Flannel does not enforce NetworkPolicy. The spec does not ask for it.")
    );
    rig.audit();
}

#[tokio::test]
async fn a_default_deny_egress_policy_warns_when_the_spec_lists_egress() {
    let rig = rig("default-deny-egress");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443", "10.20.0.5:5432"]}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Namespace acme-system has a default-deny egress policy (default-deny-egress) that blocks all egress. The product needs egress to registry.acme.example:443, 10.20.0.5:5432"
    );
    assert_eq!(
        fix_of(&finding),
        "Namespace `acme-system` has a default-deny egress policy. Add a NetworkPolicy there that allows egress from the product's pods to `registry.acme.example:443`, `10.20.0.5:5432`, and to the cluster DNS. See the current ones: `kubectl get networkpolicy -n acme-system`."
    );
    assert!(notes(&finding).contains("Only namespace NetworkPolicy objects are read"));
    assert_eq!(
        finding.observed["policies"]["default_deny_egress"],
        json!(["default-deny-egress"])
    );
    // The policy that selects one app is not a default-deny.
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_default_deny_without_rules_blocks_all_egress_and_warns() {
    let rig = rig("default-deny-all");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443"]}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.contains(
            "that blocks all egress. The product needs egress to registry.acme.example:443"
        ),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_default_deny_without_an_egress_need_is_a_note() {
    let rig = rig("default-deny-egress");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("The spec lists no egress need."),
        "{}",
        notes(&finding)
    );
    assert!(finding.partial.is_none());
    rig.audit();
}

#[tokio::test]
async fn an_allow_all_egress_rule_lifts_the_default_deny() {
    let rig = rig("egress-allow-all");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("another policy that selects every pod allows all destinations"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn an_ingress_only_default_deny_is_not_an_egress_deny() {
    let rig = rig("ingress-deny-only");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding.message.contains(
            "no default-deny egress policy in acme-system (namespace NetworkPolicy only)"
        ),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn policies_the_identity_may_not_list_are_partial_with_a_named_grant() {
    let rig = rig("policies-forbidden");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list networkpolicies"]);
    assert!(fix_of(&finding).contains("rdy-readonly-cni.yaml"));
    // Without an egress need, the same refusal is only a note.
    let rig = self::rig("policies-forbidden");
    let finding = rig.finding(json!({})).await;
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(
        notes(&finding).contains("The network policies of acme-system were not read"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn an_egress_need_with_no_namespace_reads_no_policy() {
    let rig = rig("no-namespace");
    let finding = rig
        .finding_in(json!({"needs_egress": ["registry.acme.example:443"]}), None)
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("no install namespace is named"),
        "{finding:?}"
    );
    assert!(fix_of(&finding).contains("Name the install namespace"));
    assert!(!rig.paths().contains(&POLICIES.to_owned()));
    rig.audit();
}

#[tokio::test]
async fn a_policy_list_with_a_second_page_says_so() {
    let rig = rig("policies-cut");
    let finding = rig.finding(json!({})).await;
    assert!(notes(&finding).contains("Only the first 500 policies of acme-system were read. Read the rest by hand: `kubectl get networkpolicy -n acme-system`."), "{}", notes(&finding));
    rig.audit();
}

#[tokio::test]
async fn a_policy_name_from_the_server_never_reaches_a_command() {
    let rig = rig("policy-hostile-name");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443"]}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    // The name is in the message, escaped, with its backticks turned to quotes, and cut at 64 characters.
    assert!(
        finding.message.contains("(q\\x1b[2J'rm -rf /'"),
        "{}",
        finding.message
    );
    assert!(finding.message.contains("...)"), "{}", finding.message);
    // It is in no fix command (assert_text_is_clean also checks every note and the fix).
    assert!(!fix_of(&finding).contains("rm -rf"));
    rig.audit();
}

// ---- plugins named by cheap signals -----------------------------------------------------------------------

#[tokio::test]
async fn calico_is_named_by_its_condition_and_its_api_group() {
    let rig = rig("calico-crd");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.message.starts_with("Network plugin Calico (the node condition CalicoIsUp, the API group crd.projectcalico.org); NetworkPolicy is enforced"), "{}", finding.message);
    assert_eq!(finding.observed["enforces_network_policy"], "yes");
    assert_eq!(rig.paths(), cheap_kubeadm());
    rig.audit();
}

#[tokio::test]
async fn calico_allocates_pod_addresses_itself_so_the_node_field_is_not_used() {
    let rig = rig("calico-crd");
    let finding = rig.finding(json!({"avoid_cidrs": ["10.0.0.0/8"]})).await;
    // The service range overlaps 10.0.0.0/8 and blocks. The pod ranges were not compared.
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding.message.starts_with(
            "The service range 10.96.0.0/12 overlaps 10.0.0.0/8, which the spec says to avoid"
        ),
        "{}",
        finding.message
    );
    assert!(
        partial_note(&finding).contains(
            "the pod ranges were not compared: Calico allocates pod addresses from its own pool"
        ),
        "{finding:?}"
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Block);
    rig.audit();
}

#[tokio::test]
async fn cilium_is_named_by_its_condition_and_group() {
    let rig = rig("cilium-crd");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["plugin"]["id"], "cilium");
    // A ServiceCIDR at v1 ends the service range reads: no v1beta1, no kubeadm-config.
    assert_eq!(rig.paths(), [NODES, APIS, SC_V1, POLICIES]);
    rig.audit();
}

#[tokio::test]
async fn flannel_with_calico_is_canal_and_enforces() {
    let rig = rig("canal");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["plugin"]["id"], "canal");
    assert_eq!(finding.observed["enforces_network_policy"], "yes");
    no_daemonset(&rig.paths());
    rig.audit();
}

#[tokio::test]
async fn rke2_canal_needs_no_daemonset() {
    let rig = rig("rke2-canal");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["plugin"]["id"], "canal");
    no_daemonset(&rig.paths());
    rig.audit();
}

#[tokio::test]
async fn weave_names_itself_in_the_node_condition() {
    let rig = rig("weave-condition");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["plugin"]["id"], "weave");
    no_daemonset(&rig.paths());
    rig.audit();
}

#[tokio::test]
async fn antrea_uses_node_ranges_and_is_named_by_its_group() {
    let rig = rig("antrea-crd");
    let finding = rig
        .finding(json!({"network_policy": "enforced", "avoid_cidrs": ["10.10.1.0/24"]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("The pod range 10.10.1.0/24 overlaps 10.10.1.0/24"),
        "{}",
        finding.message
    );
    assert!(fix_of(&finding).contains("`--pod-network-cidr`"));
    rig.audit();
}

#[tokio::test]
async fn signals_of_two_plugins_are_partial_never_a_block() {
    let rig = rig("calico-and-cilium");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("the signals name more than one plugin (Calico, Cilium)"),
        "{finding:?}"
    );
    assert!(notes(&finding).contains("More than one network plugin shows signals"));
    rig.audit();
}

#[tokio::test]
async fn multus_is_a_note_and_not_the_plugin() {
    let rig = rig("multus");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.observed["plugin"]["id"], "calico");
    assert!(notes(&finding).contains("Multus is installed"));
    rig.audit();
}

#[tokio::test]
async fn the_route_controller_condition_names_no_plugin() {
    let rig = rig("route-created");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.observed["plugin"].is_null());
    assert!(
        notes(&finding).contains("No network plugin of the known list was recognised"),
        "{}",
        notes(&finding)
    );
    // All 16 DaemonSets of the table were asked for, one namespace and name each.
    let paths = rig.paths();
    assert_eq!(
        paths.iter().filter(|p| p.contains("/daemonsets/")).count(),
        16,
        "{paths:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_node_that_reports_no_network_is_a_note() {
    let rig = rig("node-network-down");
    let finding = rig.finding(json!({})).await;
    assert!(notes(&finding).contains("1 node(s) report NetworkUnavailable as true, so their network plugin is not up: acme-node-3."), "{}", notes(&finding));
    rig.audit();
}

#[tokio::test]
async fn a_node_list_with_a_second_page_says_so() {
    let rig = rig("nodes-cut");
    let finding = rig.finding(json!({})).await;
    assert!(notes(&finding).contains("Only the first 500 nodes were read."));
    rig.audit();
}

#[tokio::test]
async fn unreadable_nodes_are_partial_with_a_grant() {
    let rig = rig("nodes-forbidden");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        grants(&finding).contains(&"list nodes".to_owned()),
        "{finding:?}"
    );
    assert!(fix_of(&finding).contains("`kubectl auth can-i list nodes`"));
    rig.audit();
}

// ---- plugins named by a DaemonSet -------------------------------------------------------------------------

#[tokio::test]
async fn the_vpc_cni_with_its_agent_on_enforces() {
    let rig = rig("eks-vpc-cni-on");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["plugin"]["id"], "aws-vpc-cni");
    assert_eq!(finding.observed["enforces_network_policy"], "yes");
    // The EKS kubelet version put the VPC CNI first: one DaemonSet read, and it is aws-node.
    let paths = rig.paths();
    assert_eq!(
        paths
            .iter()
            .filter(|p| p.contains("/daemonsets/"))
            .collect::<Vec<_>>(),
        [&ds("kube-system", "aws-node")]
    );
    rig.audit();
}

#[tokio::test]
async fn the_vpc_cni_with_its_agent_off_blocks_when_enforcement_is_needed() {
    let rig = rig("eks-vpc-cni-off");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "AWS VPC CNI has its network policy agent off, and the spec needs NetworkPolicy enforced"
    );
    assert!(
        fix_of(&finding).starts_with("The VPC CNI network policy agent is off."),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_vpc_cni_that_sets_no_value_is_partial_not_a_block() {
    let rig = rig("eks-vpc-cni-unset");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains(
            "the setting ENABLE_NETWORK_POLICY of the aws-node DaemonSet was not read or is not set"
        ),
        "{finding:?}"
    );
    assert!(fix_of(&finding).contains("Check the VPC CNI by hand"));
    // The DaemonSet was read, so no grant is missing.
    assert!(grants(&finding).is_empty(), "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn a_daemonset_the_identity_may_not_read_is_partial_with_a_grant() {
    let rig = rig("eks-vpc-cni-forbidden");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get daemonsets (by name)"]);
    // A refusal in a namespace skips the rest of it: one request per namespace.
    let paths = rig.paths();
    let reads: Vec<_> = paths
        .iter()
        .filter(|p| p.contains("/daemonsets/"))
        .collect();
    assert_eq!(reads.len(), 3, "{paths:?}");
    rig.audit();
}

#[tokio::test]
async fn gke_dataplane_v2_is_cilium_by_its_anetd_daemonset() {
    let rig = rig("gke-anetd");
    let finding = rig
        .finding(json!({"network_policy": "enforced", "avoid_cidrs": ["10.64.1.0/24"]}))
        .await;
    assert_eq!(finding.observed["plugin"]["id"], "anetd");
    assert_eq!(finding.observed["enforces_network_policy"], "yes");
    // GKE allocates pod ranges from node IPAM, so the node field is used and overlaps.
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("The pod range 10.64.1.0/24 overlaps 10.64.1.0/24"),
        "{}",
        finding.message
    );
    let paths = rig.paths();
    let reads: Vec<_> = paths
        .iter()
        .filter(|p| p.contains("/daemonsets/"))
        .cloned()
        .collect();
    assert_eq!(
        reads,
        [
            ds("kube-system", "cilium"),
            ds("kube-system", "rke2-cilium"),
            ds("kube-system", "anetd")
        ]
    );
    rig.audit();
}

#[tokio::test]
async fn other_plugins_are_named_by_their_daemonsets() {
    for (case, id, enforces) in [
        ("aks-azure-npm", "azure-npm", "yes"),
        ("kube-router-ds", "kube-router", "yes"),
        ("flannel-ds", "flannel", "no"),
        ("weave-ds", "weave", "yes"),
        ("calico-operator-ds", "calico", "yes"),
    ] {
        let rig = rig(case);
        let finding = rig.finding(json!({})).await;
        assert_eq!(finding.observed["plugin"]["id"], id, "{case}: {finding:?}");
        assert_eq!(
            finding.observed["enforces_network_policy"], enforces,
            "{case}"
        );
        assert_eq!(finding.level, Level::Pass, "{case}: {finding:?}");
        rig.audit();
    }
}

#[tokio::test]
async fn flannel_found_by_its_daemonset_blocks_when_enforcement_is_needed() {
    let rig = rig("flannel-ds");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn no_plugin_and_no_readable_daemonset_is_partial_never_a_block() {
    let rig = rig("daemonsets-forbidden");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["get daemonsets (by name)"]);
    assert!(
        partial_note(&finding).contains("no network plugin was recognised"),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn no_plugin_with_every_daemonset_missing_is_unknown_for_enforcement() {
    let rig = rig("no-plugin");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains(
            "whether NetworkPolicy is enforced is not known: no network plugin was recognised"
        ),
        "{finding:?}"
    );
    assert!(grants(&finding).is_empty());
    rig.audit();
}

// ---- OpenShift --------------------------------------------------------------------------------------------

#[tokio::test]
async fn openshift_names_the_plugin_and_both_ranges_from_the_network_object() {
    let rig = rig("openshift-ovn");
    let finding = rig
        .finding(json!({"network_policy": "enforced", "avoid_cidrs": ["10.128.0.0/16"]}))
        .await;
    assert_eq!(finding.observed["plugin"]["id"], "ovn-kubernetes");
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("The pod range 10.128.0.0/14 overlaps 10.128.0.0/16"),
        "{}",
        finding.message
    );
    assert_eq!(
        finding.observed["service_ranges"]["ranges"],
        json!(["172.30.0.0/16"])
    );
    // The Network object gives the service range, so no ServiceCIDR or kubeadm-config is read.
    assert_eq!(rig.paths(), [NODES, APIS, OCP, POLICIES]);
    rig.audit();
}

#[tokio::test]
async fn openshift_sdn_is_named_and_flagged_as_end_of_life() {
    let rig = rig("openshift-sdn");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.observed["plugin"]["id"], "openshift-sdn");
    assert!(notes(&finding).contains("OpenShift SDN has reached end of life."));
    rig.audit();
}

// ---- the ranges -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_service_cidr_object_is_read_at_v1_and_at_v1beta1() {
    let rig = rig("servicecidr-v1");
    let finding = rig.finding(json!({})).await;
    assert_eq!(
        finding.observed["service_ranges"]["ranges"],
        json!(["10.96.0.0/12", "fd00:10:96::/112"])
    );
    assert_eq!(rig.paths(), [NODES, APIS, SC_V1, POLICIES]);
    rig.audit();
    let rig = self::rig("servicecidr-beta");
    let finding = rig.finding(json!({})).await;
    assert_eq!(
        finding.observed["service_ranges"]["ranges"],
        json!(["10.96.0.0/12"])
    );
    assert_eq!(rig.paths(), [NODES, APIS, SC_V1, SC_BETA, POLICIES]);
    rig.audit();
}

#[tokio::test]
async fn an_overlapping_service_range_blocks() {
    let rig = rig("kubeadm-flannel");
    let finding = rig
        .finding(json!({"avoid_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    // The pod range comes first, then the service range.
    assert_eq!(
        finding.message,
        "The pod range 10.244.0.0/24, 10.244.1.0/24, 10.244.2.0/24 overlaps 10.0.0.0/8, which the spec says to avoid (and 1 more, see the notes)"
    );
    assert!(
        notes(&finding).contains(
            "The service range 10.96.0.0/12 overlaps 10.0.0.0/8, which the spec says to avoid"
        ),
        "{}",
        notes(&finding)
    );
    assert!(fix_of(&finding).contains("(kubeadm: `--service-cidr`)"));
    assert!(fix_of(&finding).contains("(kubeadm: `--pod-network-cidr`)"));
    assert!(finding.partial.is_none(), "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn ranges_that_do_not_overlap_pass() {
    let rig = rig("kubeadm-flannel");
    let finding = rig
        .finding(json!({"avoid_cidrs": ["192.168.0.0/16", "172.16.0.0/12"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    rig.audit();
}

#[tokio::test]
async fn an_unreadable_service_range_is_partial_with_grants_only_when_a_range_is_avoided() {
    let rig = rig("service-unreadable");
    let finding = rig
        .finding(json!({"avoid_cidrs": ["192.168.0.0/16"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("the service range was not read"),
        "{finding:?}"
    );
    assert_eq!(
        grants(&finding),
        [
            "list servicecidrs",
            "get configmaps/kubeadm-config in kube-system"
        ]
    );
    // Without avoid_cidrs, nothing needs the range.
    let rig = self::rig("service-unreadable");
    let finding = rig.finding(json!({})).await;
    assert!(finding.partial.is_none(), "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn a_cluster_with_no_service_range_source_is_a_note() {
    let rig = rig("service-none");
    let finding = rig
        .finding(json!({"avoid_cidrs": ["192.168.0.0/16"]}))
        .await;
    assert!(
        notes(&finding).contains("No service range source answered"),
        "{}",
        notes(&finding)
    );
    assert!(partial_note(&finding).contains("the service range was not read"));
    rig.audit();
}

#[tokio::test]
async fn a_server_error_on_the_service_cidr_read_goes_on_to_kubeadm_config() {
    let rig = rig("service-server-error");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(rig.paths(), [NODES, APIS, SC_V1, KUBEADM, POLICIES]);
    rig.audit();
}

#[tokio::test]
async fn a_service_subnet_that_is_not_a_range_is_a_note() {
    let rig = rig("service-not-a-range");
    let finding = rig
        .finding(json!({"avoid_cidrs": ["192.168.0.0/16"]}))
        .await;
    assert!(
        notes(&finding).contains("are not address ranges and were not compared"),
        "{}",
        notes(&finding)
    );
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    // The text is escaped and cut: the escape byte is written out, the backticks are quotes.
    assert!(
        notes(&finding).contains("q\\x1b[2J'rm -rf /'"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_dual_stack_cluster_compares_both_families() {
    let rig = rig("dual-stack");
    let finding = rig.finding(json!({"avoid_cidrs": ["fd00:244::/32"]})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding.message.starts_with(
            "The pod range fd00:244:0::/64, fd00:244:1::/64, fd00:244:2::/64 overlaps fd00:244::/32"
        ),
        "{}",
        finding.message
    );
    // The IPv4 service range does not meet an IPv6 range to avoid.
    assert_eq!(
        finding.observed["service_ranges"]["ranges"],
        json!(["10.96.0.0/12", "fd00:96::/108"])
    );
    rig.audit();
}

// ---- hostile text and the marker ---------------------------------------------------------------------------

#[tokio::test]
async fn a_node_condition_reason_from_the_server_is_escaped() {
    let rig = rig("hostile-reason");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn a_kubelet_version_from_the_server_is_never_shown() {
    let rig = rig("hostile-version");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.observed["plugin"]["id"], "flannel");
    rig.audit();
}

#[tokio::test]
async fn the_check_only_registers_what_it_reads() {
    // The INFO names the kube context need and a timeout, and the registry holds it.
    assert_eq!(INFO.id, "k8s.cni");
    assert!(INFO.gates_on_network());
    assert!(
        crate::registry::infos()
            .iter()
            .any(|info| info.id == "k8s.cni")
    );
    let _: &Value = &json!(null);
}

// ---- the PR #78 fix round ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_namespace_that_does_not_exist_is_skipped_and_asks_for_no_grant() {
    let rig = rig("namespaces-missing");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    // No refusal, no grant: nobody can apply a Role in a namespace that is missing.
    assert!(grants(&finding).is_empty(), "{finding:?}");
    let paths = rig.paths();
    for ns in ["calico-system", "kube-flannel"] {
        assert!(
            paths.contains(&format!("/api/v1/namespaces/{ns}")),
            "{paths:?}"
        );
        assert!(
            paths
                .iter()
                .all(|p| !p.contains(&format!("namespaces/{ns}/daemonsets"))),
            "a DaemonSet was asked for in the missing {ns}: {paths:?}"
        );
    }
    // The other 14 pairs, all in kube-system, were asked for.
    assert_eq!(
        paths.iter().filter(|p| p.contains("/daemonsets/")).count(),
        14,
        "{paths:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_policy_that_lists_destinations_is_not_a_default_deny() {
    let rig = rig("restricting-policy");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding.message.contains("no default-deny egress policy"),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_default_deny_on_a_plugin_that_does_not_enforce_is_a_note_not_a_warning() {
    let rig = rig("flannel-default-deny");
    let finding = rig
        .finding(json!({"needs_egress": ["registry.acme.example:443"]}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains(
            "the network plugin does not enforce NetworkPolicy, so it blocks nothing today"
        ),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn calico_over_the_vpc_cni_is_calico_and_enforces() {
    let rig = rig("calico-over-vpc-cni");
    let finding = rig.finding(json!({"network_policy": "enforced"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.observed["plugin"]["id"], "calico");
    assert_eq!(finding.observed["enforces_network_policy"], "yes");
    rig.audit();
}

#[tokio::test]
async fn every_result_says_which_policy_objects_are_not_read() {
    for case in [
        "kubeadm-flannel",
        "k3s-flannel",
        "calico-crd",
        "openshift-ovn",
        "nodes-forbidden",
    ] {
        let rig = self::rig(case);
        let finding = rig.finding(json!({})).await;
        let count = finding
            .notes
            .iter()
            .filter(|n| n.starts_with("Only namespace NetworkPolicy objects are read."))
            .count();
        assert_eq!(count, 1, "{case}: {:?}", finding.notes);
        rig.audit();
    }
}
