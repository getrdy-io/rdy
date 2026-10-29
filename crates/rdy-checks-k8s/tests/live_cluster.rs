//! Runs the client against a real cluster, for the kind job (M1-108). Ignored by default.
//!
//! `cargo test -p rdy-checks-k8s --test live_cluster -- --ignored --nocapture` uses the kubeconfig the
//! environment points at (`KUBECONFIG` or `~/.kube/config`), as `rdy run` does.
//!
//! - `the_default_kubeconfig_reaches_the_cluster` sends one request, `GET /version`.
//! - `the_readonly_role_serves_every_allowed_read_and_nothing_else` is the guard test of M1-103
//!   (SEC-24). It reads `RDY_READONLY_KUBECONFIG`, the path of a kubeconfig whose only user is the
//!   `rdy-readonly` service account. When the variable is not set, the test panics with a message that
//!   says so, so an explicit `--ignored` run can never pass without proving SEC-24. It does not use
//!   `KUBECONFIG`, because under an admin kubeconfig the server would allow the writes it checks for.
//!   M1-108 sets the variable and runs it.
//!
//!   ```text
//!   kubectl apply -f examples/rbac/rdy-readonly.yaml
//!   TOKEN=$(kubectl -n rdy-system create token rdy-readonly --duration 1h)
//!   SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
//!   kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
//!       | base64 -d > ca.crt
//!   kubectl config --kubeconfig=ro.kubeconfig set-cluster c --server="$SERVER" \
//!       --certificate-authority=ca.crt --embed-certs
//!   kubectl config --kubeconfig=ro.kubeconfig set-credentials rdy --token="$TOKEN"
//!   kubectl config --kubeconfig=ro.kubeconfig set-context c --cluster=c --user=rdy
//!   kubectl config --kubeconfig=ro.kubeconfig use-context c
//!   RDY_READONLY_KUBECONFIG=$PWD/ro.kubeconfig cargo test -p rdy-checks-k8s --test live_cluster \
//!       -- --ignored --nocapture
//!   ```
//!
//!   It proves two things on a real API server. Every read the guard allows is served to the role
//!   (each must return `Ok`; a 404 is tolerated only for the get of a storage class that does not
//!   exist, where the point is that the answer is not a 403), and the
//!   same role, asked through the server's own access review, may not write or read Secrets. The
//!   guard's refusals need no cluster and are tested without one.
//!
//! Not covered here, and carried (12-progress, M1-105 and M1-108):
//! - The discovery routes (`/api`, `/apis`, `/apis/<group>/<version>`) and the raw
//!   `SelfSubjectReview` POST. `ReadOnlyClient` has no route for either yet. M1-105 adds both, and
//!   M1-108 runs them.
//! - The OpenShift reads (`securitycontextconstraints` list, `clusterversions/version` get). A kind
//!   cluster does not serve them, so the test asks the server's access review whether the role allows
//!   them. That catches a typo in the rule, not a missing API.
//! - The optional `kube-system` Role: the deployments list runs, and a 403 there means the optional
//!   Role was not applied.
//!
//! They have not run in CI yet: the kind job is M1-108, which runs this file.

#![allow(clippy::expect_used)]
// These are tests of the client module. They start mock servers, write kubeconfigs and run plugin
// scripts, which the lint wall bans in the rest of this crate (INV-07). This file is on the allowlist of
// tests/lint-wall/tests/allow_grep.rs. A test of a check does not belong here: use the probe.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::time::Duration;

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
    SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
};
use k8s_openapi::api::core::v1::{Event, Namespace, Node, PersistentVolumeClaim, Pod, Secret};
use k8s_openapi::api::storage::v1::{CSIDriver, CSINode, StorageClass};
use kube::api::{DeleteParams, ListParams, PostParams};
use rdy_checks_k8s::client::{Connected, Env, GuardError, KubeOptions, load};
use rdy_engine::check::Os;
use rdy_engine::testing::{Replay, TestRun};

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
#[ignore = "needs a cluster; the kind job runs it (M1-108)"]
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
#[ignore = "needs a cluster and the rdy-readonly kubeconfig; the kind job runs it (M1-108)"]
async fn the_readonly_role_serves_every_allowed_read_and_nothing_else() {
    let kubeconfig = std::env::var_os("RDY_READONLY_KUBECONFIG").expect(
        "RDY_READONLY_KUBECONFIG is not set. Point it at a kubeconfig of the rdy-readonly service \
         account (see the header of this file); M1-108 sets it. The test never falls back to KUBECONFIG, \
         and it must not pass without proving SEC-24",
    );
    let run = TestRun::new(Replay::new());
    let options = KubeOptions::new(Duration::from_secs(10)).kubeconfig(kubeconfig);
    let connected = connect_with(&run, options).await;
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
