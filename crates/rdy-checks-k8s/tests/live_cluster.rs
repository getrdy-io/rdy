//! Runs the client against a real cluster, for the kind job (M1-108). Ignored by default.
//!
//! `cargo test -p rdy-checks-k8s --test live_cluster -- --ignored --nocapture` uses the kubeconfig the
//! environment points at (`KUBECONFIG` or `~/.kube/config`), as `rdy run` does. It sends one request,
//! `GET /version`.
//!
//! It has not run in CI yet: the kind job is M1-108.

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

use rdy_checks_k8s::client::{Env, KubeOptions, load};

#[tokio::test]
#[ignore = "needs a cluster; the kind job runs it (M1-108)"]
async fn the_default_kubeconfig_reaches_the_cluster() {
    let loaded = load(
        &KubeOptions::new(Duration::from_secs(10)),
        &Env::from_process(),
    )
    .await
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
