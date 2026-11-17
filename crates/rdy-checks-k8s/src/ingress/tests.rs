//! Fixture tests of `k8s.ingress`: the real check code over the kube mock harness, with the guard in front.
//!
//! The clusters are the cases under `tests/fixtures/checks/k8s.ingress/`, written by
//! `scripts/gen-k8s-ingress-fixtures.py`. Each test ends with `Rig::audit` (INV-14): each request the mock
//! recorded passes the guard's rules and is logged under a check that `ALLOWED` cites.

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

const CLASSES: &str = "/apis/networking.k8s.io/v1/ingressclasses";
const APIS: &str = "/apis";
const GATEWAY_V1: &str = "/apis/gateway.networking.k8s.io/v1";
const GATEWAY_CLASSES: &str = "/apis/gateway.networking.k8s.io/v1/gatewayclasses";
const SERVICES: &str = "/api/v1/namespaces/acme-system/services";

/// The moment the fixtures' creation times are counted from.
const NOW: &str = "2026-11-17T12:00:00Z";

const PLAIN: &str = "v1.30.2";
const GKE: &str = "v1.30.5-gke.1014001";

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
    rig_on(case, PLAIN)
}

fn rig_on(case: &str, git_version: &str) -> Rig {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/k8s.ingress/{case}"))
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let ctx = harness
        .run()
        .context_for(&INFO, "k8s.ingress", Os::Linux, [Need::KubeContext]);
    Rig {
        cluster: Arc::new(Fixtured {
            harness,
            version: ServerVersion {
                git_version: git_version.to_owned(),
                major: "1".to_owned(),
                minor: "30".to_owned(),
                platform: "linux/amd64".to_owned(),
            },
        }),
        ctx,
    }
}

fn params(spec: Value) -> K8sIngress {
    serde_json::from_value(spec).expect("the parameters parse")
}

impl Rig {
    fn check(&self, spec: Value, namespace: Option<&str>) -> IngressCheck {
        let cluster: Arc<dyn Cluster> = self.cluster.clone();
        let namespace = namespace.map(|name| serde_json::from_value(json!(name)).expect("a name"));
        let now: Timestamp = NOW.parse().expect("a time");
        IngressCheck::new(params(spec), namespace, cluster).at(now)
    }

    /// The finding for a spec, with the family namespace `acme-system`.
    async fn finding(&self, spec: Value) -> Finding {
        self.finding_in(spec, Some("acme-system")).await
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

    /// The `(method, path)` of every request, in order, all logged under `k8s.ingress`.
    fn requests(&self) -> Vec<(String, String)> {
        let log = self.cluster.harness.run().action_log().actions;
        assert!(
            log.iter()
                .all(|entry| entry.check.as_deref() == Some("k8s.ingress")),
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

/// Every string of a finding as written, plus its observed and expected values as JSON (which writes a
/// control character as `\u001b`), so a leak of server text shows in either form.
fn all_text(finding: &Finding) -> String {
    let mut out = vec![finding.message.clone()];
    out.extend(finding.fix.clone());
    out.extend(finding.notes.clone());
    out.extend(finding.partial.as_ref().map(|partial| partial.note.clone()));
    out.push(finding.observed.to_string());
    out.push(finding.expected.to_string());
    out.join("\n")
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
    let mut entry = json!({"id": "k8s.ingress"});
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a spec entry");
    map_outcome(&INFO, &entry, &rig.ctx, Ok(finding), 0, 0)
}

// ---- the exit test ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_community_ingress_nginx_class_warns_with_the_retirement_text() {
    let rig = rig("nginx-community");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Ingress class nginx uses the community Ingress NGINX controller (k8s.io/ingress-nginx), which was retired upstream in March 2026, whoever ships it"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.starts_with("Ingress NGINX (`k8s.io/ingress-nginx`) was retired upstream in March 2026. It still runs but gets no releases or security fixes."),
        "{fix}"
    );
    assert!(fix.contains("a Gateway API implementation, Traefik, or a cloud controller"));
    assert!(fix.contains("`ingress2gateway` tool helps convert them"));
    assert!(fix.contains("`nginx.org/ingress-controller`) is a different project"));
    assert!(finding.partial.is_none(), "{finding:?}");
    // The class list and the group list, and nothing else.
    assert_eq!(rig.paths(), [CLASSES, APIS]);
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn an_f5_class_does_not_warn() {
    let rig = rig("nginx-f5");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.message, "1 ingress class found: nginx");
    assert!(finding.fix.is_none(), "{finding:?}");
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(!notes(&finding).contains("retired"));
    assert_eq!(engine(&rig, finding, None).status, Status::Pass);
    rig.audit();
}

#[tokio::test]
async fn gke_with_no_class_is_not_verified() {
    let rig = rig_on("gke-no-class", GKE);
    let finding = rig.finding(json!({"controller": "any"})).await;
    // Nothing measured as failing: a pass that the engine shows as "not verified".
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let note = partial_note(&finding);
    assert!(
        note.contains("this platform has a built-in ingress that needs no class"),
        "{note}"
    );
    assert!(
        fix_of(&finding)
            .contains("GKE has a built-in ingress controller that needs no `IngressClass`")
    );
    assert!(grants(&finding).is_empty());
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    assert_eq!(rig.paths(), [CLASSES, APIS]);
    rig.audit();
}

#[tokio::test]
async fn a_20_minute_old_pending_load_balancer_warns() {
    let rig = rig("lb-pending-old");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "LoadBalancer service acme-gateway in acme-system has had no address for 20 minutes"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.contains("On bare metal install MetalLB and an `IPAddressPool`. In a cloud, check the cloud controller manager logs"),
        "{fix}"
    );
    assert!(
        fix.contains("`kubectl describe service acme-gateway -n acme-system`"),
        "{fix}"
    );
    assert!(notes(&finding).contains("load balancer not verified (no canary Service is created)"));
    assert_eq!(rig.paths(), [CLASSES, APIS, SERVICES]);
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

// ---- classes by controller -----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_class_is_matched_by_its_controller_and_not_by_its_name() {
    // The Traefik class is called `traefik`, but a spec asks for the controller string.
    let rig = rig("traefik-k3s");
    let finding = rig
        .finding(json!({"controller": "traefik.io/ingress-controller"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    rig.audit();
}

#[tokio::test]
async fn a_required_controller_that_no_class_names_blocks() {
    let rig = rig("nginx-f5");
    let finding = rig
        .finding(json!({"controller": "traefik.io/ingress-controller"}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "No ingress class has controller traefik.io/ingress-controller"
    );
    let fix = fix_of(&finding);
    assert!(
        fix.starts_with(
            "No `IngressClass` with controller `traefik.io/ingress-controller`. Install an ingress controller your platform team supports, or tell the vendor which classes exist."
        ),
        "{fix}"
    );
    assert!(
        notes(&finding)
            .contains("ingress classes for these controllers: nginx.org/ingress-controller")
    );
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn the_controller_match_is_exact_and_case_sensitive() {
    // The class says `Acme.example/Ingress`. The spec type lower-cases what it is given, so it can never
    // equal it: a controller string is compared as written.
    let rig = rig("classes-mixed-case");
    let finding = rig
        .finding(json!({"controller": "acme.example/ingress"}))
        .await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    rig.audit();

    let rig = self::rig("classes-mixed-case");
    let finding = rig.finding(json!({"controller": "any"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn managed_and_bundled_copies_of_the_community_controller_warn_too() {
    for case in ["aks-app-routing", "rke2-nginx"] {
        let rig = rig(case);
        let finding = rig.finding(json!({})).await;
        assert_eq!(finding.level, Level::Warn, "{case}: {finding:?}");
        assert!(
            finding.message.contains(
                "(k8s.io/ingress-nginx), which was retired upstream in March 2026, whoever ships it"
            ),
            "{}",
            finding.message
        );
        let fix = fix_of(&finding);
        assert!(
            fix.contains(
                "the AKS application routing add-on (class `webapprouting.kubernetes.azure.com`)"
            ),
            "{fix}"
        );
        assert!(fix.contains("RKE2's `rke2-ingress-nginx`"), "{fix}");
        rig.audit();
    }
}

#[tokio::test]
async fn any_needs_one_class_and_a_bare_cluster_blocks() {
    let rig = rig("none-bare");
    let finding = rig.finding(json!({"controller": "any"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(finding.message, "No ingress class exists");
    assert!(fix_of(&finding).starts_with("No `IngressClass` exists."));
    rig.audit();

    // With no key at all, a cluster with no class is only reported.
    let rig = self::rig("none-bare");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.message, "No ingress class exists");
    assert!(finding.partial.is_none());
    rig.audit();
}

#[tokio::test]
async fn openshift_with_no_class_for_the_controller_is_not_verified() {
    let rig = rig("openshift");
    let finding = rig
        .finding(json!({"controller": "k8s.io/ingress-nginx"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(partial_note(&finding).contains("built-in ingress"));
    assert!(fix_of(&finding).contains("OpenShift serves ingress through its router"));
    rig.audit();
}

#[tokio::test]
async fn gke_with_no_class_and_a_named_controller_is_not_verified_and_never_blocks() {
    let rig = rig_on("gke-no-class", GKE);
    let finding = rig
        .finding(json!({"controller": "traefik.io/ingress-controller"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_some());
    rig.audit();
}

#[tokio::test]
async fn a_gke_cluster_with_no_class_and_no_key_gets_a_note() {
    let rig = rig_on("gke-no-class", GKE);
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert!(notes(&finding).contains("built-in ingress controller"));
    rig.audit();
}

#[tokio::test]
async fn no_default_class_warns_only_when_the_spec_needs_a_class() {
    let rig = rig("eks-alb");
    let finding = rig
        .finding(json!({"controller": "ingress.k8s.aws/alb"}))
        .await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "No ingress class is the default, so an Ingress with no class is ignored"
    );
    assert!(
        fix_of(&finding).contains(
            "`kubectl annotate ingressclass alb ingressclass.kubernetes.io/is-default-class=true`"
        ),
        "{}",
        fix_of(&finding)
    );
    rig.audit();

    // The same cluster with a default class passes.
    let rig = self::rig("eks-alb-default");
    let finding = rig.finding(json!({"controller": "any"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    rig.audit();

    // And with no key the cluster is only reported.
    let rig = self::rig("eks-alb");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn two_default_classes_are_a_note() {
    let rig = rig("two-defaults");
    let finding = rig.finding(json!({"controller": "any"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        notes(&finding).contains("2 ingress classes are marked as the default (nginx, traefik)"),
        "{}",
        notes(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn two_classes_with_a_retired_one_and_no_default() {
    let rig = rig("two-classes");
    let finding = rig.finding(json!({"controller": "any"})).await;
    // Two warnings: the retirement and the missing default. Retirement is listed first, then the other as a note.
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(finding.message.contains("(and 1 more, see the notes)"));
    assert!(notes(&finding).contains("No ingress class is the default"));
    rig.audit();
}

#[tokio::test]
async fn the_k3s_traefik_class_passes() {
    let rig = rig("traefik-k3s");
    let finding = rig.finding(json!({"controller": "any"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.message, "1 ingress class found: traefik");
    assert_eq!(
        finding.observed["ingress_classes"]["items"][0]["default"],
        true
    );
    assert_eq!(
        finding.observed["ingress_classes"]["items"][0]["controller"],
        "traefik.io/ingress-controller"
    );
    rig.audit();
}

// ---- what the identity may not read ---------------------------------------------------------------------------------

#[tokio::test]
async fn classes_the_identity_may_not_list_are_partial_never_a_block() {
    let rig = rig("classes-forbidden");
    let finding = rig.finding(json!({"controller": "any"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        grants(&finding),
        ["list ingressclasses (networking.k8s.io)"]
    );
    assert!(
        fix_of(&finding).contains(
            "Ask the cluster admin to grant this identity: list ingressclasses (networking.k8s.io). Check each with `kubectl auth can-i list ingressclasses.networking.k8s.io`."
        ),
        "{}",
        fix_of(&finding)
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_server_that_does_not_serve_classes_has_none() {
    let rig = rig("classes-not-served");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.message, "No ingress class exists");
    rig.audit();
}

#[tokio::test]
async fn a_cut_class_list_is_not_a_block() {
    let rig = rig("classes-cut-no-match");
    let finding = rig
        .finding(json!({"controller": "nginx.org/ingress-controller"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding).contains("the list has more"),
        "{}",
        partial_note(&finding)
    );
    assert!(fix_of(&finding).contains("`kubectl get ingressclass`"));
    rig.audit();

    // A cut list that does hold the controller is satisfied, with a note.
    let rig = self::rig("classes-cut");
    let finding = rig
        .finding(json!({"controller": "nginx.org/ingress-controller"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(notes(&finding).contains("more ingress classes than rdy read"));
    rig.audit();
}

#[tokio::test]
async fn text_from_the_server_is_cleaned_before_it_reaches_a_sentence() {
    let rig = rig("classes-hostile");
    let finding = rig.finding(json!({"controller": "any"})).await;
    let text = all_text(&finding);
    assert!(
        !text.contains('\u{1b}') && !text.contains("\\u001b"),
        "no escape byte: {text}"
    );
    // The backtick is swapped for a quote, so the name cannot open a command span, and the control
    // characters are shown as text.
    assert!(!text.contains("`rm"), "{text}");
    assert!(text.contains("c\\x1b[2J"), "{text}");
    assert!(
        !text.contains('\u{202e}') && !text.contains("\\u202e"),
        "no bidi override: {text}"
    );
    // The hostile class name never reaches a command span.
    let fix = finding.fix.clone().unwrap_or_default();
    assert!(!fix.contains("rm -rf"), "{fix}");
    rig.audit();
}

#[tokio::test]
async fn annotations_of_the_objects_are_never_held() {
    let rig = rig("last-applied");
    let finding = rig.finding(json!({})).await;
    let text = all_text(&finding);
    assert!(!text.contains("ACME-MARKER-LAST-APPLIED"), "{text}");
    // The marker is on a class that is the default: the default flag was still read.
    assert_eq!(finding.level, Level::Warn);
    rig.audit();

    let rig = self::rig("lb-annotated");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    let text = all_text(&finding);
    assert!(!text.contains("ACME-MARKER-LAST-APPLIED"), "{text}");
    assert_eq!(finding.level, Level::Warn);
    rig.audit();
}

// ---- the Gateway API -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_required_gateway_api_with_an_accepted_class_passes() {
    let rig = rig("gateway-istio");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "No ingress class exists; the Gateway API v1 is installed with 1 accepted class: istio"
    );
    assert_eq!(rig.paths(), [CLASSES, APIS, GATEWAY_V1, GATEWAY_CLASSES]);
    assert_eq!(
        finding.observed["gateway_api"]["classes"][0]["controller"],
        "istio.io/gateway-controller"
    );
    assert_eq!(
        finding.observed["gateway_api"]["classes"][0]["accepted"],
        true
    );
    rig.audit();
}

#[tokio::test]
async fn the_google_and_aws_gateway_classes_pass() {
    for (case, version) in [("gateway-gke", GKE), ("gateway-eks", PLAIN)] {
        let rig = rig_on(case, version);
        let finding = rig.finding(json!({"gateway_api": "required"})).await;
        assert_eq!(finding.level, Level::Pass, "{case}: {finding:?}");
        assert!(finding.partial.is_none(), "{case}: {finding:?}");
        rig.audit();
    }
}

#[tokio::test]
async fn a_required_gateway_api_that_is_not_installed_blocks() {
    let rig = rig("none-bare");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "The Gateway API (gateway.networking.k8s.io/v1) is not installed"
    );
    assert!(fix_of(&finding).contains("Install the Gateway API standard channel CRDs"));
    // No Gateway request is sent for a group that is not served.
    assert_eq!(rig.paths(), [CLASSES, APIS]);
    rig.audit();
}

#[tokio::test]
async fn an_old_bundle_that_serves_no_v1_blocks_and_says_which_versions() {
    let rig = rig("gateway-v1beta1-only");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "The Gateway API (gateway.networking.k8s.io/v1) is not installed (the cluster serves v1beta1, v1alpha2 only)"
    );
    assert_eq!(rig.paths(), [CLASSES, APIS]);
    rig.audit();
}

#[tokio::test]
async fn a_gateway_api_without_httproute_blocks_when_required() {
    let rig = rig("gateway-missing-kinds");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "The Gateway API v1 is installed but does not serve httproutes"
    );
    rig.audit();

    // Optional: a note.
    let rig = self::rig("gateway-missing-kinds");
    let finding = rig.finding(json!({"gateway_api": "optional"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(notes(&finding).contains("does not serve httproutes"));
    rig.audit();
}

#[tokio::test]
async fn a_gateway_class_no_controller_accepted_warns() {
    for case in ["gateway-pending", "gateway-no-condition"] {
        let rig = rig(case);
        let finding = rig.finding(json!({"gateway_api": "required"})).await;
        assert_eq!(finding.level, Level::Warn, "{case}: {finding:?}");
        assert!(
            finding
                .message
                .starts_with("The Gateway API is installed, but no GatewayClass is accepted by a controller (found eg)"),
            "{}",
            finding.message
        );
        assert!(fix_of(&finding).contains("`kubectl describe gatewayclass`"));
        rig.audit();
    }
    let rig = rig("gateway-no-class");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(finding.message.contains("no GatewayClass exists"));
    rig.audit();
}

#[tokio::test]
async fn a_cut_gateway_class_list_is_not_a_warning() {
    let rig = rig("gateway-cut");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(partial_note(&finding).contains("the list has more"));
    rig.audit();
}

#[tokio::test]
async fn gateway_classes_the_identity_may_not_list_are_partial() {
    let rig = rig("gateway-classes-forbidden");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        grants(&finding),
        ["list gatewayclasses (gateway.networking.k8s.io)"]
    );
    rig.audit();

    // Not required: a note, and no partial.
    let rig = self::rig("gateway-classes-forbidden");
    let finding = rig.finding(json!({"gateway_api": "optional"})).await;
    assert!(finding.partial.is_none(), "{finding:?}");
    assert!(notes(&finding).contains("Its classes were not read"));
    rig.audit();
}

#[tokio::test]
async fn a_missing_gateway_api_is_not_verified_on_gke_and_openshift() {
    let rig = rig_on("gateway-gke-absent", GKE);
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(partial_note(&finding).contains("this platform manages its own ingress"));
    assert!(fix_of(&finding).contains("On GKE, enable it on the cluster"));
    rig.audit();

    let rig = self::rig("gateway-openshift-absent");
    let finding = rig.finding(json!({"gateway_api": "required"})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(fix_of(&finding).contains("OpenShift installs it"));
    rig.audit();
}

#[tokio::test]
async fn an_unreadable_group_list_is_partial() {
    let rig = rig("apis-forbidden");
    let finding = rig
        .finding(json!({"gateway_api": "required", "route": true}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let note = partial_note(&finding);
    assert!(
        note.contains("whether the Gateway API is installed was not read"),
        "{note}"
    );
    assert!(
        note.contains("whether the cluster serves the OpenShift Route API was not read"),
        "{note}"
    );
    rig.audit();

    // Not required: nothing to say.
    let rig = self::rig("apis-forbidden");
    let finding = rig.finding(json!({})).await;
    assert!(finding.partial.is_none(), "{finding:?}");
    rig.audit();
}

// ---- the OpenShift Route API --------------------------------------------------------------------------------------

#[tokio::test]
async fn a_route_the_product_needs_blocks_off_openshift_and_passes_on_it() {
    let rig = rig("route-missing");
    let finding = rig.finding(json!({"route": true})).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "The product needs an OpenShift Route and this cluster does not serve route.openshift.io"
    );
    rig.audit();

    let rig = self::rig("openshift");
    let finding = rig
        .finding(json!({"route": true, "controller": "any"}))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "1 ingress class found: openshift-default; the OpenShift Route API is served"
    );
    assert_eq!(finding.observed["platform"]["openshift"], true);
    rig.audit();
}

// ---- LoadBalancer services ----------------------------------------------------------------------------------------

#[tokio::test]
async fn load_balancers_are_read_only_when_the_spec_asks() {
    let rig = rig("no-lb-ask");
    let finding = rig.finding(json!({})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(rig.paths(), [CLASSES, APIS]);
    rig.audit();
}

#[tokio::test]
async fn a_pending_load_balancer_warns_when_older_than_ten_minutes() {
    // 03 says "older than 10 minutes": 599 and 600 seconds do not warn, 601 does.
    for (case, warns) in [
        ("lb-pending-under", false),
        ("lb-pending-boundary", false),
        ("lb-pending-over", true),
    ] {
        let rig = rig(case);
        let finding = rig.finding(json!({"loadbalancer": true})).await;
        if warns {
            assert_eq!(finding.level, Level::Warn, "{case}: {finding:?}");
            assert!(
                finding
                    .message
                    .contains("has had no address for 10 minutes")
            );
        } else {
            assert_eq!(finding.level, Level::Pass, "{case}: {finding:?}");
            assert!(
                notes(&finding)
                    .contains("acme-gateway has no address yet. It is under 10 minutes old"),
                "{}",
                notes(&finding)
            );
        }
        rig.audit();
    }
}

#[tokio::test]
async fn a_young_pending_load_balancer_is_a_note() {
    let rig = rig("lb-pending-young");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    rig.audit();
}

#[tokio::test]
async fn several_pending_load_balancers_are_counted_and_the_oldest_is_named() {
    let rig = rig("lb-pending-old-two");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "LoadBalancer service acme-metrics in acme-system has had no address for 45 minutes (and 1 more)"
    );
    assert!(
        notes(&finding).contains(
            "If its type was changed to LoadBalancer later, it has waited less than that."
        )
    );
    rig.audit();
}

#[tokio::test]
async fn assigned_load_balancers_and_other_service_types_pass() {
    let rig = rig("lb-assigned");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        finding.message,
        "1 ingress class found: nginx; 2 of 2 LoadBalancer services in acme-system have an address"
    );
    // The addresses are counted and never kept.
    let text = all_text(&finding);
    assert!(!text.contains("203.0.113.20"), "{text}");
    assert!(!text.contains("elb.acme.example"), "{text}");
    rig.audit();

    let rig = self::rig("lb-none");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .message
            .contains("no LoadBalancer service in acme-system yet")
    );
    rig.audit();
}

#[tokio::test]
async fn services_the_identity_may_not_list_are_partial() {
    let rig = rig("lb-forbidden");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list services"]);
    assert!(fix_of(&finding).contains("`kubectl auth can-i list services -n <namespace>`"));
    rig.audit();
}

#[tokio::test]
async fn with_no_namespace_the_services_are_not_asked() {
    let rig = rig("lb-pending-old");
    let finding = rig.finding_in(json!({"loadbalancer": true}), None).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(partial_note(&finding).contains("the spec names no namespace"));
    assert!(fix_of(&finding).contains("Name the install namespace in the `k8s` block of the spec"));
    assert_eq!(rig.paths(), [CLASSES, APIS]);
    rig.audit();
}

#[tokio::test]
async fn metallb_changes_the_hint() {
    let rig = rig("lb-metallb");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        fix_of(&finding)
            .contains("MetalLB is installed: create an `IPAddressPool` and an `L2Advertisement`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_hostile_service_name_stays_out_of_the_command() {
    let rig = rig("lb-hostile");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    let text = all_text(&finding);
    assert!(
        !text.contains('\u{1b}') && !text.contains("\\u001b"),
        "{text}"
    );
    assert!(!text.contains("`rm"), "{text}");
    assert!(
        fix_of(&finding).contains("`kubectl describe service <name> -n acme-system`"),
        "{}",
        fix_of(&finding)
    );
    rig.audit();
}

#[tokio::test]
async fn a_cut_service_list_and_a_missing_creation_time_are_notes() {
    let rig = rig("lb-cut");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(notes(&finding).contains("more services than rdy read"));
    rig.audit();

    let rig = self::rig("lb-no-timestamp");
    let finding = rig.finding(json!({"loadbalancer": true})).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(notes(&finding).contains("the server sent no creation time"));
    rig.audit();
}

// ---- the wire -------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_request_is_a_get_and_no_listing_is_cluster_wide() {
    let rig = rig("lb-pending-old");
    let _ = rig
        .finding(json!({"controller": "any", "gateway_api": "optional", "route": true, "loadbalancer": true}))
        .await;
    let paths = rig.paths();
    assert_eq!(paths, [CLASSES, APIS, SERVICES]);
    assert!(paths.iter().all(|p| !p.starts_with("/api/v1/services")));
    rig.audit();
}

#[tokio::test]
async fn a_gateway_cluster_asks_four_questions_without_services() {
    let rig = rig("gateway-istio");
    let _ = rig
        .finding(json!({"controller": "any", "gateway_api": "required"}))
        .await;
    assert_eq!(rig.paths(), [CLASSES, APIS, GATEWAY_V1, GATEWAY_CLASSES]);
    rig.audit();
}

#[tokio::test]
async fn a_namespace_called_secrets_is_refused_by_the_guard_and_is_not_a_failure() {
    // The guard refuses every path through a namespace called `secrets`. The check reads that as an answer.
    let rig = rig("nginx-f5");
    let finding = rig
        .finding_in(json!({"loadbalancer": true}), Some("secrets"))
        .await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        partial_note(&finding)
            .contains("rdy never reads a path through a namespace called secrets"),
        "{}",
        partial_note(&finding)
    );
}

#[tokio::test]
async fn the_findings_carry_what_was_observed_and_expected() {
    let rig = rig("nginx-community");
    let finding = rig
        .finding(json!({"controller": "k8s.io/ingress-nginx", "gateway_api": "optional", "route": false}))
        .await;
    assert_eq!(finding.expected["controller"], "k8s.io/ingress-nginx");
    assert_eq!(finding.expected["gateway_api"], "optional");
    assert_eq!(finding.expected["namespace"], "acme-system");
    assert_eq!(finding.observed["ingress_classes"]["read"], "read");
    assert_eq!(finding.observed["platform"]["gke"], false);
    rig.audit();
}
