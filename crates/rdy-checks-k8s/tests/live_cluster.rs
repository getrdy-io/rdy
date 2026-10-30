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
//! - `the_readonly_role_serves_discovery_and_names_itself` runs the discovery routes, the raw
//!   `SelfSubjectReview` and `k8s.version` as the `rdy-readonly` service account.
//! - `the_readonly_role_serves_every_allowed_read_and_nothing_else` is the guard test of M1-103
//!   (SEC-24). It reads `RDY_READONLY_KUBECONFIG`, the path of a kubeconfig whose only user is the
//!   `rdy-readonly` service account. When the variable is not set, the test panics with a message that
//!   says so, so an explicit `--ignored` run can never pass without proving SEC-24. It does not use
//!   `KUBECONFIG`, because under an admin kubeconfig the server would allow the writes it checks for.
//!
//!   It proves two things on a real API server. Every read the guard allows is served to the role
//!   (each must return `Ok`; a 404 is tolerated only for the get of a storage class that does not
//!   exist, where the point is that the answer is not a 403), and the
//!   same role, asked through the server's own access review, may not write or read Secrets. The
//!   guard's refusals need no cluster and are tested without one.
//!
//! Not covered here, and carried:
//! - The OpenShift reads (`securitycontextconstraints` list, `clusterversions/version` get). A kind
//!   cluster does not serve them, so the test asks the server's access review whether the role allows
//!   them. That catches a typo in the rule, not a missing API.
//! - The in-cluster path (a pod's service account). The job runs rdy outside the cluster.
//! - The optional `kube-system` Role: the deployments list runs, and a 403 there means the optional
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

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
    SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
};
use k8s_openapi::api::core::v1::{Event, Namespace, Node, PersistentVolumeClaim, Pod, Secret};
use k8s_openapi::api::storage::v1::{CSIDriver, CSINode, StorageClass};
use kube::api::{DeleteParams, ListParams, PostParams};
use rdy_checks_k8s::client::{Connected, Env, GuardError, KubeOptions, load};
use rdy_checks_k8s::{Cluster, VersionCheck};
use rdy_engine::check::{Check, Finding, Level, Need, Os};
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::check::K8sVersion;
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
    SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some(verb.to_owned()),
                group: Some(group.to_owned()),
                resource: Some(resource.to_owned()),
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

/// Asks the server whether the identity may do `ask`.
async fn is_allowed(reviews: &kube::Api<SelfSubjectAccessReview>, ask: Ask) -> bool {
    let (verb, group, resource, namespace, name) = ask;
    reviews
        .create(
            &PostParams::default(),
            &review(verb, group, resource, namespace, name),
        )
        .await
        .expect("access review")
        .status
        .is_some_and(|status| status.allowed)
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
    assert_served(
        "deployments (needs the optional kube-system Role)",
        false,
        &client
            .namespaced::<k8s_openapi::api::apps::v1::Deployment>("kube-system")
            .list(&all)
            .await,
    );
    // The rules review is a POST the guard allows. The server answers 201.
    let rules = SelfSubjectRulesReview {
        spec: SelfSubjectRulesReviewSpec {
            namespace: Some("default".to_owned()),
        },
        ..SelfSubjectRulesReview::default()
    };
    assert_served(
        "selfsubjectrulesreviews",
        false,
        &client
            .all::<SelfSubjectRulesReview>()
            .create(&PostParams::default(), &rules)
            .await,
    );

    // 2. The server itself says what the role can and cannot do. These are the allowed
    //    SelfSubjectAccessReview POSTs, so they pass the guard.
    let reviews = client.all::<SelfSubjectAccessReview>();
    for ask in [
        ("list", "", "nodes", None, None),
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
    ] {
        assert!(
            is_allowed(&reviews, ask).await,
            "the role must allow {ask:?}"
        );
    }
    for ask in [
        ("get", "", "secrets", Some("kube-system"), None),
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
    ] {
        assert!(
            !is_allowed(&reviews, ask).await,
            "the role must not allow {ask:?}"
        );
    }

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

    // 4. One log entry per call: /version, 11 reads and posts, 12 reviews, two refusals.
    let log = run.action_log().actions;
    assert_eq!(log.len(), 1 + 11 + 12 + 2, "{log:#?}");
}
