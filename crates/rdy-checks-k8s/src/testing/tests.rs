//! Tests of the scripted cluster (M1-185): the family reaches it, the guard stays in front of it, the audit
//! passes, and a `/version` that does not answer ends at the family limit with no worker blocked.

use std::time::Duration;

use k8s_openapi::api::core::v1::Secret;
use kube::api::ListParams;
use rdy_engine::check::{Need, Os};
use rdy_engine::family::{FAMILY_PROBE_LIMIT, Family};
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};

use super::ScriptedCluster;
use crate::access::{Dial, DialOutcome};
use crate::VersionCheck;

fn load(case: &str) -> (Fixture, TestRun) {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/_kube/{case}"))
        .expect("the fixture loads");
    let run = TestRun::for_fixture(&fixture);
    (fixture, run)
}

#[tokio::test]
async fn the_family_reaches_a_scripted_cluster_through_the_guard_and_the_audit_passes() {
    let (fixture, run) = load("cluster");
    let cluster = ScriptedCluster::new(fixture.replay()).expect("a cluster");
    let family = cluster.family();
    let said = std::sync::Mutex::new(Vec::new());
    let announce = |line: &str| said.lock().expect("lines").push(line.to_owned());
    let caps = family
        .probe(run.family_probe(&[VersionCheck::info()], &announce))
        .await
        .expect("no fatal error");
    assert_eq!(caps.len(), 1);
    assert!(caps[0].available, "{caps:?}");
    // The cluster line comes before the first request, and names nothing real.
    let lines = said.lock().expect("lines").clone();
    assert_eq!(lines, ["acme-fixture, https://k8s.acme.test:6443, user acme-reader"]);
    assert_eq!(cluster.requests(), ["GET /version"]);
    assert!(matches!(
        family.cluster().server_version().git_version.as_str(),
        "v1.29.4-eks-abc123"
    ));

    // The guard is in front of the mock: a read of Secrets is refused before it reaches the cluster.
    let context = run.context("k8s.version", Os::Linux, [Need::KubeContext]);
    let client = family.cluster().read_only(context.probe());
    let refused = client
        .all::<Secret>()
        .list(&ListParams::default())
        .await
        .expect_err("the guard refuses a Secret list");
    assert!(
        refused.to_string().contains("read-only guard"),
        "{refused}"
    );
    assert_eq!(cluster.requests(), ["GET /version"], "nothing was sent");
    assert_eq!(
        cluster.audit(&run.action_log().actions),
        Vec::<String>::new()
    );
}

#[tokio::test(start_paused = true)]
async fn a_version_that_does_not_answer_ends_at_the_family_limit_with_no_worker_blocked() {
    let (fixture, run) = load("slow-version");
    let cluster = ScriptedCluster::new(fixture.replay()).expect("a cluster");
    let family = cluster.family();
    let announce = |_: &str| {};
    let started = tokio::time::Instant::now();
    // The engine bounds the probe like this (`engine.rs`). The test runtime has one thread, so a blocked
    // worker would hang the test, not end it.
    let ended = tokio::time::timeout(
        FAMILY_PROBE_LIMIT,
        family.probe(run.family_probe(&[VersionCheck::info()], &announce)),
    )
    .await;
    assert!(ended.is_err(), "the probe was cut at its limit");
    let waited = started.elapsed();
    assert!(
        waited >= FAMILY_PROBE_LIMIT && waited < FAMILY_PROBE_LIMIT + Duration::from_secs(1),
        "{waited:?}"
    );

    let caps = family.probe_timed_out();
    assert!(!caps[0].available);
    assert!(
        matches!(family.cluster().server_version().git_version.as_str(), ""),
        "no version without an answer"
    );
    // The request was sent and never answered in time; the audit pairs it with its log entry.
    assert_eq!(cluster.requests(), ["GET /version"]);
    assert!(cluster.audit(&run.action_log().actions).is_empty());
    assert!(matches!(family.dial().outcome(), DialOutcome::TimedOut));
}
