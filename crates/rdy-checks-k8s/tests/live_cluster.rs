//! Runs the client against a real cluster, for the kind job (M1-108). Ignored by default.
//!
//! `cargo test -p rdy-checks-k8s --test live_cluster -- --ignored --nocapture` uses the kubeconfig the
//! environment points at (`KUBECONFIG` or `~/.kube/config`), as `rdy run` does. It sends one request,
//! `GET /version`.
//!
//! It has not run in CI yet: the kind job is M1-108.

#![allow(clippy::expect_used)]

use std::time::Duration;

use rdy_checks_k8s::client::{Env, KubeOptions, load};

#[tokio::test]
#[ignore = "needs a cluster; the kind job runs it (M1-108)"]
async fn the_default_kubeconfig_reaches_the_cluster() {
    let loaded = load(
        &KubeOptions::new(Duration::from_secs(10)),
        &Env::from_process(),
    )
    .expect("a kubeconfig that kubectl accepts");

    let connected = loaded
        .connect(|line| eprintln!("cluster {line}"))
        .await
        .expect("GET /version answers");

    let version = connected.server_version();
    eprintln!("server {} {}", version.git_version, version.platform);
    assert!(
        version.git_version.starts_with('v'),
        "{}",
        version.git_version
    );
}
