//! Runs the client and `k8s.version` against a real cluster, for the kind job (M1-108). Ignored by default.
//!
//! The kind workflow (`.github/workflows/kind.yml`) runs every test here on the oldest and newest
//! supported minors (ADR 0039) through `scripts/kind-live-test.sh`, which sets up the cluster side:
//!
//! - the namespace `rdy-live`, labelled `restricted` for enforce, audit and warn (and shown to refuse a
//!   privileged pod before the tests start);
//! - `examples/rbac/rdy-readonly.yaml`, and a kubeconfig of its service account in
//!   `RDY_READONLY_KUBECONFIG`;
//! - `RDY_LIVE_NAMESPACE` (`rdy-live`) and `RDY_LIVE_EXPECT_MINOR` (`1.35`), so a green run proves it
//!   tested the cluster it says it did.
//!
//! To run them by hand against a cluster you own, run the script with `KUBECONFIG` pointing at it. It
//! needs `kubectl`, `cargo-nextest` and `RDY_LIVE_EXPECT_MINOR`; it creates and deletes the namespaces
//! `rdy-live` and `rdy-system`. The tests themselves are plain ignored tests:
//! `cargo test -p rdy-checks-k8s --test live_cluster -- --ignored --nocapture` uses the kubeconfig the
//! environment points at (`KUBECONFIG` or `~/.kube/config`), as `rdy run` does.
//!
//! - `the_default_kubeconfig_reaches_the_cluster` sends one request, `GET /version`.
//! - `k8s_version_passes_on_the_cluster` runs the `k8s.version` check (the real check code, built
//!   directly here until M1-107 builds it from the spec) and expects a pass on the minor the job started.
//! - `the_server_names_the_caller_and_answers_access_reviews` sends the raw `SelfSubjectReview` and two
//!   access reviews as the admin of the kind cluster.
//! - `the_test_namespace_enforces_restricted` reads the namespace labels through the read-only client.
//! - `k8s_dns_passes_on_the_cluster` runs the `k8s.dns` check (M1-162) as the `rdy-readonly` service account, and
//!   expects a pass with nothing partial: kind runs CoreDNS under the label `k8s-app=kube-dns`, with a Service
//!   `kube-dns` and a ConfigMap `coredns`, which the optional `kube-system` Role lets the check read.
//! - `the_readonly_role_serves_discovery_and_names_itself` runs the discovery routes, the raw
//!   `SelfSubjectReview` and `k8s.version` as the `rdy-readonly` service account.
//! - `the_readonly_role_serves_every_allowed_read_and_nothing_else` is the guard test of M1-103
//!   (SEC-24). It reads `RDY_READONLY_KUBECONFIG`, the path of a kubeconfig whose only user is the
//!   `rdy-readonly` service account. When the variable is not set, the test panics with a message that
//!   says so, so an explicit `--ignored` run can never pass without proving SEC-24. It does not use
//!   `KUBECONFIG`, because under an admin kubeconfig the server would allow the writes it checks for.
//!
//!   It proves three things on a real API server. Every read the guard allows is served to the role
//!   (each must return `Ok`; a 404 is tolerated only for the get of a storage class that does not
//!   exist, where the point is that the answer is not a 403). The same role, asked through the
//!   server's own access review, may not write, read Secrets, mint tokens, exec, impersonate or bind.
//!   And the server's rules review of the role, for `default` and `kube-system`, lists only the grants
//!   of the role file (and `system:basic-user`'s reviews), so nothing else is granted by any binding. The
//!   same review's `nonResourceRules` hold only the `get` of the URLs of the default ClusterRoles
//!   `system:discovery`, `system:public-info-viewer` and `system:service-account-issuer-discovery`
//!   (`NON_RESOURCE_DEFAULTS`).
//!   The guard's refusals need no cluster and are tested without one.
//!
//! Not covered here, and carried:
//! - The OpenShift reads (`securitycontextconstraints` list, `clusterversions/version` get). A kind
//!   cluster does not serve them, so the test asks the server's access review whether the role allows
//!   them. That catches a typo in the rule, not a missing API.
//! - The policy lists of Kyverno and Gatekeeper (M1-160: `clusterpolicies`, `validatingpolicies`,
//!   `imagevalidatingpolicies` and any constraint kind). Their groups are not on a kind cluster either, so
//!   the test asks the access review, with a constraint kind that only the `*` rule of the role can admit.
//!   The webhook, admission policy, Service and EndpointSlice lists are served by kind and run for real.
//! - The in-cluster path (a pod's service account). The job runs rdy outside the cluster.
//! - The optional `kube-system` Role: the deployments and daemon sets lists, the Service `kube-dns` get and the
//!   ConfigMap `coredns` get run, and a 403 there means the optional
//!   Role was not applied.

#![allow(clippy::expect_used)]
// These are tests of the client module. They start mock servers, write kubeconfigs and run plugin
// scripts, which the lint wall bans in the rest of this crate (INV-07). This file is on the allowlist of
// tests/lint-wall/tests/allow_grep.rs. A test of a check does not belong here: use the probe.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
    ValidatingWebhookConfiguration,
};
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
    SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
};
use k8s_openapi::api::core::v1::{
    ConfigMap, Event, LimitRange, Namespace, Node, PersistentVolumeClaim, Pod, ResourceQuota,
    Secret, Service,
};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::IngressClass;
use k8s_openapi::api::storage::v1::{CSIDriver, CSINode, StorageClass};
use kube::api::{DeleteParams, ListParams, PostParams};
use rdy_checks_k8s::client::{Connected, Env, GuardError, KubeOptions, load};
use rdy_checks_k8s::{Cluster, DnsCheck, VersionCheck};
use rdy_engine::check::{Check, Finding, Level, Need, Os};
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::check::{K8sDns, K8sVersion};
use serde_json::json;

async fn connect_with(run: &TestRun, options: KubeOptions) -> Connected {
    let loaded = load(&options, &Env::from_process())
        .await
        .expect("a kubeconfig that kubectl accepts");
    loaded
        .connect(&run.run_probe(Os::Linux), |line| {
            eprintln!("cluster {line}")
        })
        .await
        .expect("GET /version answers")
}

#[tokio::test]
#[ignore = "runs in job: kind"]
async fn the_default_kubeconfig_reaches_the_cluster() {
    let run = TestRun::new(Replay::new());
    let connected = connect_with(&run, KubeOptions::new(Duration::from_secs(10))).await;

    let version = connected.server_version();
    eprintln!("server {} {}", version.git_version, version.platform);
    assert!(
        version.git_version.starts_with('v'),
        "{}",
        version.git_version
    );
}

/// The minor the job started (`1.35`). A run that tested another one is not a proof of the one it names.
fn expected_minor() -> String {
    std::env::var("RDY_LIVE_EXPECT_MINOR").expect(
        "RDY_LIVE_EXPECT_MINOR is not set. Set it to the Kubernetes minor of the cluster, for example \
         1.35; scripts/kind-live-test.sh does",
    )
}

fn assert_expected_minor(connected: &Connected) {
    let git_version = &connected.server_version().git_version;
    let prefix = format!("v{}.", expected_minor());
    assert!(
        git_version.starts_with(&prefix),
        "the cluster says {git_version}, the job meant to test {prefix}x"
    );
}

/// Runs `k8s.version` against the cluster `connected` reached, as the check runs in a real run: its own
/// probe, bound to its id, and the real client behind the guard. The spec entry asks for the floor the
/// docs use and four APIs every supported minor serves.
async fn version_finding(connected: Connected, run: &TestRun) -> Finding {
    let params: K8sVersion = serde_json::from_value(json!({
        "min": "1.28",
        "apis": [
            "autoscaling/v2 HorizontalPodAutoscaler",
            "networking.k8s.io/v1 Ingress",
            "batch/v1 CronJob",
            "v1 Pod",
        ],
    }))
    .expect("the parameters parse");
    let cluster: Arc<dyn Cluster> = Arc::new(connected);
    let ctx = run.context_for(
        VersionCheck::info(),
        "k8s.version",
        Os::Linux,
        [Need::KubeContext],
    );
    VersionCheck::new(params, cluster)
        .run(&ctx)
        .await
        .expect("the check ran")
}

fn assert_version_passes(finding: &Finding, connected_minor: &str) {
    assert_eq!(finding.level, Level::Pass, "{finding:#?}");
    assert!(finding.partial.is_none(), "{finding:#?}");
    let kubernetes = finding.observed["kubernetes"].as_str().unwrap_or_default();
    assert!(
        kubernetes.starts_with(&format!("{connected_minor}.")),
        "{finding:#?}"
    );
    assert!(
        finding.observed["nodes_read"].as_u64().unwrap_or(0) >= 1,
        "{finding:#?}"
    );
    eprintln!("k8s.version: {}", finding.message);
}

#[tokio::test]
#[ignore = "runs in job: kind"]
async fn k8s_version_passes_on_the_cluster() {
    let run = TestRun::new(Replay::new());
    let connected = connect_with(&run, KubeOptions::new(Duration::from_secs(10))).await;
    assert_expected_minor(&connected);
    let finding = version_finding(connected, &run).await;
    assert_version_passes(&finding, &expected_minor());
    // A real server answered every request, and the log holds one entry per request under the check.
    let log = run.action_log().actions;
    let own: Vec<_> = log
        .iter()
        .filter(|entry| entry.check.as_deref() == Some("k8s.version"))
        .collect();
    assert!(!own.is_empty(), "{log:#?}");
    assert!(
        own.iter()
            .all(|entry| entry.outcome == rdy_spec::result::ActionOutcome::Ok),
        "{own:#?}"
    );
}

#[tokio::test]
#[ignore = "runs in job: kind"]
async fn the_server_names_the_caller_and_answers_access_reviews() {
    let run = TestRun::new(Replay::new());
    let connected = connect_with(&run, KubeOptions::new(Duration::from_secs(10))).await;
    let check = run.context("k8s.access", Os::Linux, []);
    let client = connected.read_only(check.probe());

    // The raw route and its fixed body: a typed `SelfSubjectReview` carries `metadata` and is refused.
    let who = client
        .self_subject_review()
        .await
        .expect("the server answers the review");
    let username = who
        .status
        .and_then(|status| status.user_info)
        .and_then(|info| info.username)
        .expect("the review names the caller");
    assert!(!username.is_empty());
    eprintln!("the server says the caller is {username}");

    // Access reviews round trip: the admin of a kind cluster may create a pod in the test namespace and
    // read nodes, and the server says so in `status.allowed`.
    let namespace = std::env::var("RDY_LIVE_NAMESPACE")
        .expect("RDY_LIVE_NAMESPACE is not set; scripts/kind-live-test.sh sets it");
    let reviews = client.all::<SelfSubjectAccessReview>();
    for (verb, resource, scoped) in [("create", "pods", true), ("list", "nodes", false)] {
        let spec = review(
            verb,
            "",
            resource,
            scoped.then_some(namespace.as_str()),
            None,
        );
        let answer = reviews
            .create(&PostParams::default(), &spec)
            .await
            .expect("access review")
            .status
            .expect("the server fills the status");
        assert!(answer.allowed, "{verb} {resource}: {answer:?}");
    }
}

#[tokio::test]
#[ignore = "runs in job: kind"]
async fn the_test_namespace_enforces_restricted() {
    let namespace = std::env::var("RDY_LIVE_NAMESPACE")
        .expect("RDY_LIVE_NAMESPACE is not set; scripts/kind-live-test.sh sets it");
    let run = TestRun::new(Replay::new());
    let connected = connect_with(&run, KubeOptions::new(Duration::from_secs(10))).await;
    let check = run.context("k8s.admission", Os::Linux, []);
    let client = connected.read_only(check.probe());
    let object = client
        .all::<Namespace>()
        .get(&namespace)
        .await
        .expect("the namespace is readable");
    let labels = object.metadata.labels.unwrap_or_default();
    for level in ["enforce", "audit", "warn"] {
        assert_eq!(
            labels
                .get(&format!("pod-security.kubernetes.io/{level}"))
                .map(String::as_str),
            Some("restricted"),
            "{level}: {labels:?}"
        );
    }
}

/// The read-only client of the `rdy-readonly` kubeconfig, or the panic that says how to set it.
async fn readonly_connection(run: &TestRun) -> Connected {
    let kubeconfig = std::env::var_os("RDY_READONLY_KUBECONFIG").expect(
        "RDY_READONLY_KUBECONFIG is not set. Point it at a kubeconfig of the rdy-readonly service \
         account (see the header of this file); scripts/kind-live-test.sh sets it. The tests never fall \
         back to KUBECONFIG, and the readonly test must not pass without proving SEC-24",
    );
    connect_with(
        run,
        KubeOptions::new(Duration::from_secs(10)).kubeconfig(kubeconfig),
    )
    .await
}

#[tokio::test]
#[ignore = "runs in job: kind"]
async fn the_readonly_role_serves_discovery_and_names_itself() {
    let run = TestRun::new(Replay::new());
    let connected = readonly_connection(&run).await;
    assert_expected_minor(&connected);
    let check = run.context("k8s.access", Os::Linux, []);
    let client = connected.read_only(check.probe());

    // The three discovery routes, and the core one k8s.version reads. system:discovery serves them.
    let core = client.core_versions().await.expect("GET /api");
    assert!(core.versions.iter().any(|v| v == "v1"), "{core:?}");
    let groups = client.api_groups().await.expect("GET /apis");
    assert!(
        groups.groups.iter().any(|g| g.name == "storage.k8s.io"),
        "{groups:?}"
    );
    let served = client
        .group_resources("storage.k8s.io", "v1")
        .await
        .expect("GET /apis/storage.k8s.io/v1");
    assert!(
        served.resources.iter().any(|r| r.name == "storageclasses"),
        "{served:?}"
    );
    let core_v1 = client.core_resources("v1").await.expect("GET /api/v1");
    assert!(core_v1.resources.iter().any(|r| r.name == "pods"));

    // The raw SelfSubjectReview names the service account the kubeconfig holds.
    let username = client
        .self_subject_review()
        .await
        .expect("the server answers the review")
        .status
        .and_then(|status| status.user_info)
        .and_then(|info| info.username);
    assert_eq!(
        username.as_deref(),
        Some("system:serviceaccount:rdy-system:rdy-readonly")
    );

    // k8s.version with only the role: discovery, and the node list the role grants, so nothing is partial.
    let finding = version_finding(connected, &run).await;
    assert_version_passes(&finding, &expected_minor());
}

#[tokio::test]
#[ignore = "runs in job: kind"]
async fn k8s_dns_passes_on_the_cluster() {
    let run = TestRun::new(Replay::new());
    let connected = readonly_connection(&run).await;
    assert_expected_minor(&connected);
    let cluster: Arc<dyn Cluster> = Arc::new(connected);
    let ctx = run.context_for(DnsCheck::info(), "k8s.dns", Os::Linux, [Need::KubeContext]);
    let params: K8sDns = serde_json::from_value(json!({})).expect("the parameters parse");
    // CoreDNS may still be coming up when the job starts. Ask again for up to a minute.
    let mut finding = None;
    for _ in 0..30 {
        let answer = DnsCheck::new(params.clone(), cluster.clone())
            .run(&ctx)
            .await
            .expect("the check ran");
        let done = answer.level == Level::Pass;
        finding = Some(answer);
        if done {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let finding = finding.expect("the check ran at least once");
    eprintln!("k8s.dns: {}", finding.message);
    assert_eq!(finding.level, Level::Pass, "{finding:#?}");
    // Every read the check makes is in the role file, so nothing is partial.
    assert!(finding.partial.is_none(), "{finding:#?}");
    assert_eq!(finding.observed["namespace"], "kube-system");
    assert!(
        finding.observed["workloads"]
            .as_array()
            .is_some_and(|list| !list.is_empty()),
        "{finding:#?}"
    );
    assert!(
        finding.observed["service"]["cluster_ip"].is_string(),
        "{finding:#?}"
    );
    assert!(finding.observed["corefile"].is_object(), "{finding:#?}");
}

/// A `GatewayClass`, named only so the live test can list it: the Gateway API has no type in k8s-openapi.
#[derive(Debug, Clone, serde::Deserialize)]
struct GatewayClass {
    metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
}

impl kube::Resource for GatewayClass {
    type DynamicType = ();
    type Scope = kube::core::ClusterResourceScope;

    fn kind(_: &()) -> std::borrow::Cow<'_, str> {
        "GatewayClass".into()
    }

    fn group(_: &()) -> std::borrow::Cow<'_, str> {
        "gateway.networking.k8s.io".into()
    }

    fn version(_: &()) -> std::borrow::Cow<'_, str> {
        "v1".into()
    }

    fn plural(_: &()) -> std::borrow::Cow<'_, str> {
        "gatewayclasses".into()
    }

    fn meta(&self) -> &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
        &mut self.metadata
    }
}

/// What a read must do on a real cluster: succeed. A 404 is tolerated only where `optional` is set,
/// for the get of a storage class that does not exist. Anything else, including a guard refusal, a 403
/// or a 500, fails the test.
fn assert_served<T>(name: &str, optional: bool, result: &Result<T, kube::Error>) {
    match result {
        Ok(_) => {}
        Err(kube::Error::Api(status)) if status.code == 404 && optional => {
            eprintln!("{name}: 404, as expected for a name that does not exist");
        }
        Err(error) => panic!("{name}: an allowed read did not succeed: {error:?}"),
    }
}

fn review(
    verb: &str,
    group: &str,
    resource: &str,
    namespace: Option<&str>,
    name: Option<&str>,
) -> SelfSubjectAccessReview {
    // `pods/exec` is the resource `pods` and the subresource `exec`.
    let (resource, subresource) = match resource.split_once('/') {
        Some((resource, subresource)) => (resource, Some(subresource.to_owned())),
        None => (resource, None),
    };
    SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some(verb.to_owned()),
                group: Some(group.to_owned()),
                resource: Some(resource.to_owned()),
                subresource,
                namespace: namespace.map(str::to_owned),
                name: name.map(str::to_owned),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        ..SelfSubjectAccessReview::default()
    }
}

/// What one access review asks: `(verb, group, resource, namespace, name)`.
type Ask = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
);

/// Asks the server whether the identity may do `ask`. The answer counts only when the server filled
/// the status and reported no evaluation error, so a denial can never be a missing answer.
async fn is_allowed(reviews: &kube::Api<SelfSubjectAccessReview>, ask: Ask) -> bool {
    let (verb, group, resource, namespace, name) = ask;
    let status = reviews
        .create(
            &PostParams::default(),
            &review(verb, group, resource, namespace, name),
        )
        .await
        .expect("access review")
        .status
        .expect("the server fills the status");
    assert!(
        status
            .evaluation_error
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "{ask:?}: the server could not evaluate the review: {status:?}"
    );
    status.allowed
}

/// One grant of a rules review: `(verb, api group, resource, resource name)`. The name is empty for
/// every name. A resource with a subresource reads `pods/exec`, as in a role.
type Grant = (String, String, String, String);

/// What the `rdy-readonly` role grants as resources, from `examples/rbac/rdy-readonly.yaml`. A test keeps
/// that file and the guard's `ALLOWED` in step; this list keeps the live server in step with the file.
const GRANTED: &[(&str, &str, &str, &str)] = &[
    ("get", "", "namespaces", ""),
    ("list", "", "nodes", ""),
    ("list", "", "pods", ""),
    ("list", "", "persistentvolumeclaims", ""),
    ("list", "", "events", ""),
    ("list", "", "resourcequotas", ""),
    ("list", "", "limitranges", ""),
    ("list", "networking.k8s.io", "ingressclasses", ""),
    ("list", "gateway.networking.k8s.io", "gatewayclasses", ""),
    ("list", "", "services", ""),
    (
        "list",
        "admissionregistration.k8s.io",
        "validatingwebhookconfigurations",
        "",
    ),
    (
        "list",
        "admissionregistration.k8s.io",
        "mutatingwebhookconfigurations",
        "",
    ),
    (
        "list",
        "admissionregistration.k8s.io",
        "validatingadmissionpolicies",
        "",
    ),
    (
        "list",
        "admissionregistration.k8s.io",
        "validatingadmissionpolicybindings",
        "",
    ),
    ("list", "discovery.k8s.io", "endpointslices", ""),
    ("list", "kyverno.io", "clusterpolicies", ""),
    ("list", "policies.kyverno.io", "validatingpolicies", ""),
    ("list", "policies.kyverno.io", "imagevalidatingpolicies", ""),
    ("list", "constraints.gatekeeper.sh", "*", ""),
    ("get", "storage.k8s.io", "storageclasses", ""),
    ("list", "storage.k8s.io", "storageclasses", ""),
    ("list", "storage.k8s.io", "csinodes", ""),
    ("list", "storage.k8s.io", "csidrivers", ""),
    (
        "list",
        "security.openshift.io",
        "securitycontextconstraints",
        "",
    ),
    ("get", "config.openshift.io", "clusterversions", "version"),
    ("create", "authentication.k8s.io", "selfsubjectreviews", ""),
    (
        "create",
        "authorization.k8s.io",
        "selfsubjectaccessreviews",
        "",
    ),
    (
        "create",
        "authorization.k8s.io",
        "selfsubjectrulesreviews",
        "",
    ),
];

/// What the optional `kube-system` Role of the role file grants (`rdy-readonly-kube-system`): the deployments
/// of `k8s.nodes`, and the daemon sets, the Service `kube-dns` and the ConfigMap `coredns` of `k8s.dns`.
const KUBE_SYSTEM_ROLE: &[(&str, &str, &str, &str)] = &[
    ("list", "apps", "deployments", ""),
    ("list", "apps", "daemonsets", ""),
    ("get", "", "services", "kube-dns"),
    ("get", "", "services", "rke2-coredns-rke2-coredns"),
    ("get", "", "configmaps", "coredns"),
];

/// Reads the Kubernetes project gives every signed-in user on newer minors, outside the role file. Each
/// is read-only and holds no secret. An entry stays only with a reason.
const SERVER_DEFAULTS: &[(&str, &str, &str, &str)] = &[
    // ClusterTrustBundles are cluster-wide CA bundles, public by design. The 1.37.0 server grants get, list
    // and watch on them through the ClusterRole `system:cluster-trust-bundle-discovery`, bound to the group
    // `system:serviceaccounts` (so to every service account, ours included, and not to the role file). It
    // comes with the `ClusterTrustBundle` feature gate: on in 1.37.0, off in 1.35.8, whose rules review
    // lists none of them.
    ("get", "certificates.k8s.io", "clustertrustbundles", ""),
    ("list", "certificates.k8s.io", "clustertrustbundles", ""),
    ("watch", "certificates.k8s.io", "clustertrustbundles", ""),
];

/// The URLs the Kubernetes project lets every signed-in user `get` outside the role file: the rules of the
/// ClusterRoles `system:discovery` and `system:public-info-viewer`, bound to the group
/// `system:authenticated`. `/healthz/*`, `/livez/*`, `/readyz/*` and `/metrics` belong to
/// `system:monitoring` only, so they are surprises here. They are discovery, health and version documents, and hold no secret. The role
/// file has no `nonResourceURLs` rule of its own, so any other URL, any other verb and any wildcard verb
/// is a grant the role file did not make. The identity is a service account, so it also gets the
/// ClusterRole `system:service-account-issuer-discovery`, which Kubernetes binds to the group
/// `system:serviceaccounts` by default: the public OIDC discovery document and its key set, which hold no
/// secret either.
const NON_RESOURCE_DEFAULTS: &[&str] = &[
    "/api",
    "/api/*",
    "/apis",
    "/apis/*",
    "/healthz",
    "/livez",
    "/readyz",
    "/version",
    "/version/",
    "/openapi",
    "/openapi/*",
    "/.well-known/openid-configuration",
    "/.well-known/openid-configuration/",
    "/openid/v1/jwks",
    "/openid/v1/jwks/",
];

/// What the server grants the identity on non-resource URLs in `namespace`, one entry per verb and URL.
fn non_resource_grants(namespace: &str, answer: &SelfSubjectRulesReview) -> Vec<(String, String)> {
    let status = answer
        .status
        .as_ref()
        .expect("the server fills the status of a rules review");
    let mut out = Vec::new();
    for rule in &status.non_resource_rules {
        let urls = rule.non_resource_urls.clone().unwrap_or_default();
        assert!(
            !urls.is_empty(),
            "{namespace}: a non-resource rule with no URL: {rule:?}"
        );
        for verb in &rule.verbs {
            for url in &urls {
                out.push((verb.clone(), url.clone()));
            }
        }
    }
    out
}

/// The grants of `grants` that are not a `get` of a URL of [`NON_RESOURCE_DEFAULTS`].
fn unexpected_non_resource(namespace: &str, grants: &[(String, String)]) -> Vec<String> {
    grants
        .iter()
        .filter(|(verb, url)| verb != "get" || !NON_RESOURCE_DEFAULTS.contains(&url.as_str()))
        .map(|(verb, url)| format!("{namespace}: {verb} {url}"))
        .collect()
}

#[test]
fn only_a_get_of_a_default_url_is_an_expected_non_resource_grant() {
    let grant = |verb: &str, url: &str| (verb.to_owned(), url.to_owned());
    // What a stock server reports for a signed-in service account.
    let stock: Vec<_> = NON_RESOURCE_DEFAULTS
        .iter()
        .map(|url| grant("get", url))
        .collect();
    assert!(unexpected_non_resource("default", &stock).is_empty());
    // Another verb, another URL, a wildcard URL or a wildcard verb are each a surprise.
    let surprises = [
        grant("post", "/healthz"),
        grant("get", "/metrics"),
        grant("get", "*"),
        grant("get", "/logs/*"),
        grant("*", "/version"),
        grant("get", "/apis/*/extra"),
        grant("get", "/healthz/*"),
        grant("get", "/livez/*"),
        grant("get", "/readyz/*"),
        grant("get", "/metrics"),
    ];
    for surprise in surprises {
        assert_eq!(
            unexpected_non_resource("kube-system", std::slice::from_ref(&surprise)),
            [format!("kube-system: {} {}", surprise.0, surprise.1)],
            "{surprise:?}"
        );
    }
}

/// What the server grants the identity in `namespace`, one entry per verb, group, resource and name.
/// The server may merge rules, so the answer is expanded before it is compared.
fn grants(namespace: &str, answer: &SelfSubjectRulesReview) -> Vec<Grant> {
    let status = answer
        .status
        .as_ref()
        .expect("the server fills the status of a rules review");
    assert!(
        !status.incomplete,
        "{namespace}: the rules review is incomplete, so it cannot prove the role is read-only: {status:?}"
    );
    assert!(
        status
            .evaluation_error
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "{namespace}: the server could not evaluate the rules review: {status:?}"
    );
    let mut out = Vec::new();
    for rule in &status.resource_rules {
        let groups = rule.api_groups.clone().unwrap_or_default();
        let resources = rule.resources.clone().unwrap_or_default();
        let names = rule.resource_names.clone().unwrap_or_default();
        let names = if names.is_empty() {
            vec![String::new()]
        } else {
            names
        };
        for verb in &rule.verbs {
            for group in &groups {
                for resource in &resources {
                    for name in &names {
                        out.push((verb.clone(), group.clone(), resource.clone(), name.clone()));
                    }
                }
            }
        }
    }
    out
}

#[tokio::test]
#[ignore = "runs in job: kind"]
async fn the_readonly_role_serves_every_allowed_read_and_nothing_else() {
    let run = TestRun::new(Replay::new());
    let connected = readonly_connection(&run).await;
    let check = run.context("k8s.nodes", Os::Linux, []);
    let client = connected.read_only(check.probe());
    let all = ListParams::default().limit(50);
    // The selectors the guard requires on these two lists (02 Appendix B, section 4).
    let pods = all
        .clone()
        .fields("status.phase!=Succeeded,status.phase!=Failed");
    let events = all
        .clone()
        .fields("involvedObject.kind=PersistentVolumeClaim");

    // 1. Every read the guard allows is served to the role. Each must return Ok. CSINode, CSIDriver and
    //    the rules review are GA on every supported minor, so a 404 there fails too. The one tolerated
    //    404 is the get of a storage class that does not exist (the point is that it is not a 403).
    assert_served("nodes", false, &client.all::<Node>().list(&all).await);
    assert_served("pods", false, &client.all::<Pod>().list(&pods).await);
    assert_served(
        "pvc",
        false,
        &client
            .namespaced::<PersistentVolumeClaim>("default")
            .list(&all)
            .await,
    );
    assert_served(
        "events",
        false,
        &client.namespaced::<Event>("default").list(&events).await,
    );
    assert_served(
        "resourcequotas",
        false,
        &client
            .namespaced::<ResourceQuota>("default")
            .list(&all)
            .await,
    );
    assert_served(
        "limitranges",
        false,
        &client.namespaced::<LimitRange>("default").list(&all).await,
    );
    assert_served(
        "storageclasses",
        false,
        &client.all::<StorageClass>().list(&all).await,
    );
    assert_served(
        "storageclass by name",
        true,
        &client.all::<StorageClass>().get("no-such-class").await,
    );
    assert_served("csinodes", false, &client.all::<CSINode>().list(&all).await);
    assert_served(
        "csidrivers",
        false,
        &client.all::<CSIDriver>().list(&all).await,
    );
    assert_served(
        "namespace",
        false,
        &client.all::<Namespace>().get("kube-system").await,
    );
    // k8s.admission (M1-160). The Service is asked for by name, as the check asks, and the slices by label.
    assert_served(
        "validatingwebhookconfigurations",
        false,
        &client
            .all::<ValidatingWebhookConfiguration>()
            .list(&all)
            .await,
    );
    assert_served(
        "mutatingwebhookconfigurations",
        false,
        &client
            .all::<MutatingWebhookConfiguration>()
            .list(&all)
            .await,
    );
    assert_served(
        "validatingadmissionpolicies",
        false,
        &client.all::<ValidatingAdmissionPolicy>().list(&all).await,
    );
    assert_served(
        "validatingadmissionpolicybindings",
        false,
        &client
            .all::<ValidatingAdmissionPolicyBinding>()
            .list(&all)
            .await,
    );
    assert_served(
        "services",
        false,
        &client
            .namespaced::<Service>("default")
            .list(&all.clone().fields("metadata.name=kubernetes"))
            .await,
    );
    assert_served(
        "endpointslices",
        false,
        &client
            .namespaced::<EndpointSlice>("default")
            .list(&all.clone().labels("kubernetes.io/service-name=kubernetes"))
            .await,
    );
    assert_served(
        "deployments (needs the optional kube-system Role)",
        false,
        &client
            .namespaced::<k8s_openapi::api::apps::v1::Deployment>("kube-system")
            .list(&all)
            .await,
    );
    assert_served(
        "daemonsets (needs the optional kube-system Role)",
        false,
        &client
            .namespaced::<k8s_openapi::api::apps::v1::DaemonSet>("kube-system")
            .list(&all)
            .await,
    );
    assert_served(
        "service kube-dns (needs the optional kube-system Role)",
        false,
        &client
            .namespaced::<Service>("kube-system")
            .get("kube-dns")
            .await,
    );
    assert_served(
        "configmap coredns (needs the optional kube-system Role)",
        false,
        &client
            .namespaced::<ConfigMap>("kube-system")
            .get("coredns")
            .await,
    );
    assert_served(
        "ingressclasses",
        false,
        &client.all::<IngressClass>().list(&all).await,
    );
    // The whole-namespace list of k8s.ingress, with no field selector (the admission list carries one).
    assert_served(
        "services (the whole namespace, no selector)",
        false,
        &client.namespaced::<Service>("default").list(&all).await,
    );
    // kind has no Gateway API CRDs, so the server answers 404 ("not installed"), which is the answer the
    // check reads. A 403 would fail here: that is what proves the role grants the list.
    assert_served(
        "gatewayclasses (404 when the Gateway API is not installed)",
        true,
        &client.all::<GatewayClass>().list(&all).await,
    );
    // The rules review is a POST the guard allows. The server answers 201. It is asked for `default`
    // (where only the cluster role applies) and for `kube-system` (where the optional Role adds the
    // deployments list), and the answers are read in step 2.
    let mut rules_answers = Vec::new();
    for namespace in ["default", "kube-system"] {
        let rules = SelfSubjectRulesReview {
            spec: SelfSubjectRulesReviewSpec {
                namespace: Some(namespace.to_owned()),
            },
            ..SelfSubjectRulesReview::default()
        };
        let answer = client
            .all::<SelfSubjectRulesReview>()
            .create(&PostParams::default(), &rules)
            .await;
        assert_served("selfsubjectrulesreviews", false, &answer);
        rules_answers.push((namespace, answer.expect("served, checked above")));
    }

    // 2. The server itself says what the role can and cannot do. These are the allowed
    //    SelfSubjectAccessReview POSTs, so they pass the guard.
    let reviews = client.all::<SelfSubjectAccessReview>();
    let must_allow = [
        ("list", "", "nodes", None, None),
        // k8s.dns: the Service and the ConfigMap, by name, in kube-system only (the optional Role).
        ("get", "", "services", Some("kube-system"), Some("kube-dns")),
        (
            "get",
            "",
            "services",
            Some("kube-system"),
            Some("rke2-coredns-rke2-coredns"),
        ),
        (
            "get",
            "",
            "configmaps",
            Some("kube-system"),
            Some("coredns"),
        ),
        ("list", "apps", "daemonsets", Some("kube-system"), None),
        // The OpenShift rules cannot be exercised on kind (404), so the server's review stands in. A
        // typo in either rule fails here.
        (
            "list",
            "security.openshift.io",
            "securitycontextconstraints",
            None,
            None,
        ),
        (
            "get",
            "config.openshift.io",
            "clusterversions",
            None,
            Some("version"),
        ),
        // The engines' groups are not on a kind cluster either. The Gatekeeper kind is one the rule's
        // wildcard has to admit.
        ("list", "kyverno.io", "clusterpolicies", None, None),
        (
            "list",
            "policies.kyverno.io",
            "validatingpolicies",
            None,
            None,
        ),
        (
            "list",
            "policies.kyverno.io",
            "imagevalidatingpolicies",
            None,
            None,
        ),
        (
            "list",
            "constraints.gatekeeper.sh",
            "k8srequiredlabels",
            None,
            None,
        ),
    ];
    let allowed_count = must_allow.len();
    for ask in must_allow {
        assert!(
            is_allowed(&reviews, ask).await,
            "the role must allow {ask:?}"
        );
    }
    let must_not_allow = [
        ("get", "", "secrets", Some("kube-system"), None),
        // The ConfigMap and Service reads are by name: no other name, no list, no other namespace.
        (
            "get",
            "",
            "configmaps",
            Some("kube-system"),
            Some("kubeadm-config"),
        ),
        ("list", "", "configmaps", Some("kube-system"), None),
        ("get", "", "configmaps", Some("default"), Some("coredns")),
        (
            "get",
            "",
            "services",
            Some("kube-system"),
            Some("metrics-server"),
        ),
        ("watch", "", "services", Some("kube-system"), None),
        ("list", "", "secrets", None, None),
        ("create", "", "pods", Some("default"), None),
        ("delete", "", "pods", Some("default"), None),
        ("patch", "", "nodes", None, None),
        ("update", "storage.k8s.io", "storageclasses", None, None),
        ("delete", "storage.k8s.io", "storageclasses", None, None),
        ("create", "", "namespaces", None, None),
        // The ClusterVersion rule is by name only.
        (
            "get",
            "config.openshift.io",
            "clusterversions",
            None,
            Some("other"),
        ),
        // The M1-160 lists are lists only: no get by name, no write, and the wildcard group is not writable.
        (
            "delete",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            None,
            None,
        ),
        (
            "get",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            None,
            Some("x"),
        ),
        (
            "create",
            "constraints.gatekeeper.sh",
            "k8srequiredlabels",
            None,
            None,
        ),
        (
            "get",
            "constraints.gatekeeper.sh",
            "k8srequiredlabels",
            None,
            Some("x"),
        ),
        // Escalation paths: minting tokens, running commands in pods, acting as someone else and
        // granting roles.
        ("create", "", "serviceaccounts/token", Some("default"), None),
        ("create", "", "pods/exec", Some("default"), None),
        ("impersonate", "", "users", None, None),
        (
            "bind",
            "rbac.authorization.k8s.io",
            "clusterroles",
            None,
            None,
        ),
    ];
    let denied_count = must_not_allow.len();
    for ask in must_not_allow {
        assert!(
            !is_allowed(&reviews, ask).await,
            "the role must not allow {ask:?}"
        );
    }

    //    "Nothing else" is read from the server, not sampled. Every grant the server reports for the
    //    identity must be one the role file lists, a default the Kubernetes project gives every signed-in
    //    user (`SERVER_DEFAULTS`), or one of the reads the optional Role adds in `kube-system` (`KUBE_SYSTEM_ROLE`).
    //    Another binding, an aggregated role or a broad grant to `system:authenticated` shows up here.
    //    All of them are collected, so one run names every surprise.
    let mut unexpected = Vec::new();
    for (namespace, answer) in &rules_answers {
        for grant in grants(namespace, answer) {
            let listed = |table: &[(&str, &str, &str, &str)]| {
                table.iter().any(|&(verb, group, resource, name)| {
                    grant
                        == (
                            verb.to_owned(),
                            group.to_owned(),
                            resource.to_owned(),
                            name.to_owned(),
                        )
                })
            };
            let optional = *namespace == "kube-system"
                && KUBE_SYSTEM_ROLE
                    .iter()
                    .any(|&(verb, group, resource, name)| listed(&[(verb, group, resource, name)]));
            if !(listed(GRANTED) || listed(SERVER_DEFAULTS) || optional) {
                unexpected.push(format!("{namespace}: {grant:?}"));
            }
        }
    }
    assert!(
        unexpected.is_empty(),
        "the server grants the rdy-readonly identity more than the role file lists: {unexpected:#?}"
    );
    //    The same for URLs. The role file grants none, so every non-resource rule the server reports is a
    //    default the project gives every signed-in user (`NON_RESOURCE_DEFAULTS`), and a `get` only.
    let mut unexpected_urls = Vec::new();
    for (namespace, answer) in &rules_answers {
        let urls = non_resource_grants(namespace, answer);
        unexpected_urls.extend(unexpected_non_resource(namespace, &urls));
    }
    assert!(
        unexpected_urls.is_empty(),
        "the server grants the rdy-readonly identity non-resource URLs beyond the discovery, public-info-viewer and issuer-discovery defaults: {unexpected_urls:#?}"
    );

    // 3. The guard refuses a write and a Secrets read before they reach the server.
    let error = client
        .all::<Node>()
        .delete("no-such-node", &DeleteParams::default())
        .await
        .expect_err("refused by the guard");
    assert!(
        matches!(&error, kube::Error::Service(inner) if inner.is::<GuardError>()),
        "{error:?}"
    );
    let error = client
        .namespaced::<Secret>("kube-system")
        .list(&all)
        .await
        .expect_err("refused by the guard");
    assert!(
        matches!(&error, kube::Error::Service(inner) if inner.is::<GuardError>()),
        "{error:?}"
    );

    // 4. One log entry per call: /version, the 24 `assert_served` reads of step 1 (add one here when a
    //    read is added), one rules review per namespace asked, the access reviews of step 2 (counted from
    //    their tables), and two refusals.
    let log = run.action_log().actions;
    let expected = 1 + 24 + rules_answers.len() + allowed_count + denied_count + 2;
    assert_eq!(log.len(), expected, "{log:#?}");
}
