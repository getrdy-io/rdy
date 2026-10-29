//! Runs the client against a real cluster, for the kind job (M1-108). Ignored by default.
//!
//! `cargo test -p rdy-checks-k8s --test live_cluster -- --ignored --nocapture` uses the kubeconfig the
//! environment points at (`KUBECONFIG` or `~/.kube/config`), as `rdy run` does.
//!
//! - `the_default_kubeconfig_reaches_the_cluster` sends one request, `GET /version`.
//! - `the_readonly_role_serves_every_allowed_read_and_nothing_else` is the guard test of M1-103 (SEC-24).
//!   Point `KUBECONFIG` at a kubeconfig whose user is the `rdy-readonly` service account, and nothing
//!   else:
//!
//!   ```text
//!   kubectl apply -f examples/rbac/rdy-readonly.yaml
//!   TOKEN=$(kubectl -n rdy-system create token rdy-readonly --duration 1h)
//!   # write a kubeconfig with the cluster of your kind context and `token: $TOKEN` as the only user
//!   KUBECONFIG=/path/to/readonly.kubeconfig cargo test -p rdy-checks-k8s --test live_cluster \
//!       -- --ignored --nocapture
//!   ```
//!
//!   It proves two things on a real API server. The role covers every read the guard allows (no 403),
//!   and the same role, asked through the server's own access review, may not write or read Secrets. The
//!   guard's refusals need no cluster and are tested without one.
//!
//! They have not run in CI yet: the kind job is M1-108, which runs this file.

#![allow(clippy::expect_used)]

use std::time::Duration;

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use k8s_openapi::api::core::v1::{Event, Namespace, Node, PersistentVolumeClaim, Pod, Secret};
use k8s_openapi::api::storage::v1::{CSIDriver, CSINode, StorageClass};
use kube::api::{DeleteParams, ListParams, PostParams};
use rdy_checks_k8s::client::{Connected, Env, GuardError, KubeOptions, load};
use rdy_engine::check::Os;
use rdy_engine::testing::{Replay, TestRun};

async fn connect(run: &TestRun) -> Connected {
    let loaded = load(
        &KubeOptions::new(Duration::from_secs(10)),
        &Env::from_process(),
    )
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
    let connected = connect(&run).await;

    let version = connected.server_version();
    eprintln!("server {} {}", version.git_version, version.platform);
    assert!(
        version.git_version.starts_with('v'),
        "{}",
        version.git_version
    );
}

/// True when the error is the server saying 403.
fn forbidden(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(status) if status.code == 403)
}

fn review(
    verb: &str,
    group: &str,
    resource: &str,
    namespace: Option<&str>,
) -> SelfSubjectAccessReview {
    SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some(verb.to_owned()),
                group: Some(group.to_owned()),
                resource: Some(resource.to_owned()),
                namespace: namespace.map(str::to_owned),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        ..SelfSubjectAccessReview::default()
    }
}

#[tokio::test]
#[ignore = "needs a cluster and the rdy-readonly kubeconfig; the kind job runs it (M1-108)"]
async fn the_readonly_role_serves_every_allowed_read_and_nothing_else() {
    let run = TestRun::new(Replay::new());
    let connected = connect(&run).await;
    let check = run.context("k8s.nodes", Os::Linux, []);
    let client = connected.read_only(check.probe());
    let all = ListParams::default().limit(50);

    // 1. Every read the guard allows works with the role. A 404 (the resource is not served, as on
    //    a cluster that is not OpenShift) is fine. A 403 is not.
    let reads = [
        ("nodes", client.all::<Node>().list(&all).await.err()),
        ("pods", client.all::<Pod>().list(&all).await.err()),
        (
            "pvc",
            client
                .namespaced::<PersistentVolumeClaim>("default")
                .list(&all)
                .await
                .err(),
        ),
        (
            "events",
            client.namespaced::<Event>("default").list(&all).await.err(),
        ),
        (
            "storageclasses",
            client.all::<StorageClass>().list(&all).await.err(),
        ),
        ("csinodes", client.all::<CSINode>().list(&all).await.err()),
        (
            "csidrivers",
            client.all::<CSIDriver>().list(&all).await.err(),
        ),
        (
            "namespace",
            client.all::<Namespace>().get("kube-system").await.err(),
        ),
        (
            "deployments",
            client
                .namespaced::<k8s_openapi::api::apps::v1::Deployment>("kube-system")
                .list(&all)
                .await
                .err(),
        ),
    ];
    for (name, error) in reads {
        assert!(
            error.as_ref().is_none_or(|e| !forbidden(e)),
            "{name}: the role does not cover a read the guard allows: {error:?}"
        );
    }

    // 2. The server itself says the role cannot write or read Secrets. These are the allowed
    //    SelfSubjectAccessReview POSTs, so they pass the guard.
    let reviews = client.all::<SelfSubjectAccessReview>();
    let allowed = |verb: &'static str,
                   group: &'static str,
                   resource: &'static str,
                   ns: Option<&'static str>| {
        let reviews = reviews.clone();
        async move {
            reviews
                .create(&PostParams::default(), &review(verb, group, resource, ns))
                .await
                .expect("access review")
                .status
                .is_some_and(|status| status.allowed)
        }
    };
    assert!(allowed("list", "", "nodes", None).await, "list nodes");
    for (verb, group, resource, ns) in [
        ("get", "", "secrets", Some("kube-system")),
        ("list", "", "secrets", None),
        ("create", "", "pods", Some("default")),
        ("delete", "", "pods", Some("default")),
        ("patch", "", "nodes", None),
        ("update", "storage.k8s.io", "storageclasses", None),
        ("delete", "storage.k8s.io", "storageclasses", None),
        ("create", "", "namespaces", None),
    ] {
        assert!(
            !allowed(verb, group, resource, ns).await,
            "the role must not allow {verb} {resource}"
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

    // 4. One log entry per call: /version, the nine reads, nine reviews, two refusals.
    let log = run.action_log().actions;
    assert_eq!(log.len(), 1 + 9 + 9 + 2, "{log:#?}");
}
