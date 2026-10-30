//! Tests of the cgroup helper against the synthetic machines under `tests/fixtures/checks/_cgroup/`
//! (the 08 format, read by the Replay fixture loader).
//!
//! Each test asks through a probe that applies the real read policy and `CheckInfo::reads`, so a path
//! the helper reads outside [`READS`] would fail here as it would in a run.

use std::future::Future;

use rdy_engine::check::{CheckContext, CheckInfo, CheckMeta, Need, Os};
use rdy_engine::probe::ProbeError;
use rdy_engine::testing::{Fixture, Replay, TestRun, fixtures_dir};
use rdy_spec::result::ActionOutcome;

use super::*;
use crate::family::OS;

const GIB: u64 = 1 << 30;

/// A check that declares what the helper needs and nothing else.
pub(super) static INFO: CheckInfo = CheckInfo {
    id: "host.memory",
    family: "host",
    summary: "test",
    meta: CheckMeta {
        title: "Test",
        remediation: "Test.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: OS,
    reads: &READS,
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// A check that declares no reads.
static BLIND: CheckInfo = CheckInfo { reads: &[], ..INFO };

pub(super) fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
        .block_on(future)
}

fn fixture(case: &str) -> Fixture {
    Fixture::load(&fixtures_dir(), &format!("checks/_cgroup/{case}")).expect("the fixture loads")
}

pub(super) fn context(run: &TestRun, info: &'static CheckInfo, os: Os) -> CheckContext {
    run.context_for(info, "host.memory", os, Vec::<Need>::new())
}

/// Discovers the cgroups of the fixture machine `case`.
fn discover(case: &str) -> (Cgroups, CheckContext) {
    let fixture = fixture(case);
    let run = TestRun::for_fixture(&fixture);
    let ctx = context(&run, &INFO, Os::Linux);
    let cgroups = block_on(Cgroups::discover(ctx.probe()))
        .expect("discovery succeeds")
        .expect("the machine has cgroups");
    (cgroups, ctx)
}

fn bound<T>(value: T, at: &str) -> Option<Bound<T>> {
    Some(Bound {
        value,
        at: at.to_owned(),
    })
}

fn set(words: &[&str]) -> Option<BTreeSet<String>> {
    Some(words.iter().map(|w| (*w).to_owned()).collect())
}

#[test]
fn v2_nested_slice_reports_the_minimum_along_the_parent_chain() {
    let (cgroups, ctx) = discover("v2-nested");
    assert_eq!(cgroups.layout(), Layout::V2);

    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.hierarchy, Some(Hierarchy::V2));
    // The service allows 8 GiB, its parent slice 4 GiB, the slice above it nothing. The parent binds.
    assert_eq!(memory.limit.min, bound(4 * GIB, "/system.slice/acme.slice"));
    // The top of the mount has no `memory.max`, so three levels answered, not four.
    assert_eq!(memory.limit.levels_read, 3);
    assert!(memory.limit.is_complete());
    assert!(!memory.limit.hidden_above);
    // `memory.swap.max`.
    assert_eq!(memory.swap.min, bound(GIB, "/system.slice/acme.slice"));
    assert_eq!(memory.swap.levels_read, 3);

    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    assert_eq!(cpu.hierarchy, Some(Hierarchy::V2));
    let quota = cpu.quota.min.expect("a quota");
    assert_eq!(quota.at, "/system.slice/acme.slice");
    assert_eq!(
        quota.value,
        CpuQuota {
            quota_us: 200_000,
            period_us: 100_000
        }
    );
    assert!((quota.value.cores() - 2.0).abs() < f64::EPSILON);
}

#[test]
fn v2_controllers_show_what_the_kernel_offers_and_what_is_delegated() {
    let (cgroups, ctx) = discover("v2-nested");
    let found = block_on(cgroups.controllers(ctx.probe())).expect("controllers");
    assert_eq!(found.layout, Layout::V2);
    assert!(found.v1.is_empty());
    let v2 = found.v2.expect("a v2 hierarchy");
    assert_eq!(
        v2.top_available,
        set(&[
            "cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc"
        ])
    );
    assert_eq!(v2.top_enabled, set(&["cpu", "io", "memory", "pids"]));
    assert_eq!(v2.own_available, set(&["cpu", "memory"]));
    assert_eq!(v2.own_enabled, set(&[]));
}

#[test]
fn v1_tree_reads_limit_in_bytes_and_cfs_quota_along_the_chain() {
    let (cgroups, ctx) = discover("v1-tree");
    assert_eq!(cgroups.layout(), Layout::V1);

    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.hierarchy, Some(Hierarchy::V1));
    assert_eq!(memory.limit.min, bound(2 * GIB, "/system.slice/acme.slice"));
    // v1 has the file at the top too, so all four levels answered.
    assert_eq!(memory.limit.levels_read, 4);
    // The v1 mem+swap limit is not read: the swap chain is empty, not "unlimited".
    assert!(!memory.swap.is_present());

    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    assert_eq!(cpu.hierarchy, Some(Hierarchy::V1));
    let quota = cpu.quota.min.expect("a quota");
    assert_eq!(quota.at, "/system.slice/acme.slice");
    assert!((quota.value.cores() - 1.5).abs() < f64::EPSILON);
    assert_eq!(cpu.quota.levels_read, 4);

    let found = block_on(cgroups.controllers(ctx.probe())).expect("controllers");
    assert_eq!(found.v2, None);
    // `name=systemd` is a named hierarchy, not a controller.
    assert_eq!(
        found.v1,
        ["cpu", "cpuacct", "memory", "pids"]
            .map(str::to_owned)
            .into_iter()
            .collect()
    );
}

#[test]
fn v2_with_every_limit_at_max_is_unlimited_and_complete() {
    let (cgroups, ctx) = discover("v2-unlimited");
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.hierarchy, Some(Hierarchy::V2));
    assert_eq!(memory.limit.min, None);
    assert_eq!(memory.limit.levels_read, 2);
    assert!(memory.limit.is_present() && memory.limit.is_complete());
    assert_eq!(memory.swap.min, None);
    assert!(memory.swap.is_present());
    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    assert_eq!(cpu.quota.min, None);
    assert!(cpu.quota.is_present());
}

#[test]
fn v1_sentinel_and_minus_one_are_unlimited() {
    let (cgroups, ctx) = discover("v1-unlimited");
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.hierarchy, Some(Hierarchy::V1));
    assert_eq!(memory.limit.min, None);
    assert_eq!(memory.limit.levels_read, 3);
    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    assert_eq!(cpu.quota.min, None);
    assert_eq!(cpu.quota.levels_read, 3);
}

#[test]
fn hybrid_uses_v1_where_v2_has_no_controller_files() {
    let (cgroups, ctx) = discover("hybrid");
    assert_eq!(cgroups.layout(), Layout::Hybrid);
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.hierarchy, Some(Hierarchy::V1));
    assert_eq!(memory.limit.min, bound(GIB, "/user.slice"));
    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    assert_eq!(cpu.hierarchy, Some(Hierarchy::V1));
    assert_eq!(cpu.quota.min, None);

    let found = block_on(cgroups.controllers(ctx.probe())).expect("controllers");
    let v2 = found.v2.expect("the unified hierarchy");
    assert_eq!(v2.top_available, set(&[]));
    assert_eq!(
        found.v1,
        ["cpu", "cpuacct", "memory"]
            .map(str::to_owned)
            .into_iter()
            .collect()
    );
}

#[test]
fn memory_controller_off_has_no_memory_answer_and_a_cpu_answer() {
    let (cgroups, ctx) = discover("v2-memory-off");
    let memory = block_on(cgroups.memory(ctx.probe())).expect("memory");
    assert_eq!(memory.hierarchy, None);
    assert!(!memory.limit.is_present());
    assert!(!memory.swap.is_present());
    assert!(memory.limit.is_complete());
    let cpu = block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    let quota = cpu.quota.min.expect("a quota");
    assert!((quota.value.cores() - 1.0).abs() < f64::EPSILON);
    assert_eq!(quota.at, "/system.slice/acme-api.service");

    let found = block_on(cgroups.controllers(ctx.probe())).expect("controllers");
    let v2 = found.v2.expect("v2");
    assert!(!v2.top_available.expect("a list").contains("memory"));
}

#[test]
fn a_check_that_does_not_declare_the_reads_is_refused_by_the_probe() {
    let fixture = fixture("v2-nested");
    let run = TestRun::for_fixture(&fixture);
    let ctx = context(&run, &BLIND, Os::Linux);
    let error = block_on(Cgroups::discover(ctx.probe())).expect_err("refused");
    assert!(
        matches!(error, CgroupError::Probe(ProbeError::Denied { .. })),
        "{error:?}"
    );
}

#[test]
fn another_os_has_no_cgroups_and_reads_nothing() {
    let run = TestRun::new(Replay::for_os(Os::Macos));
    let ctx = context(&run, &INFO, Os::Macos);
    assert_eq!(block_on(Cgroups::discover(ctx.probe())), Ok(None));
    assert!(run.action_log().actions.is_empty());
}

#[test]
fn a_kernel_without_proc_cgroup_has_no_cgroups() {
    let run = TestRun::new(Replay::new());
    let ctx = context(&run, &INFO, Os::Linux);
    assert_eq!(block_on(Cgroups::discover(ctx.probe())), Ok(None));
}

#[test]
fn every_read_stays_inside_the_declared_prefixes() {
    let fixture = fixture("v1-tree");
    let run = TestRun::for_fixture(&fixture);
    let ctx = context(&run, &INFO, Os::Linux);
    let cgroups = block_on(Cgroups::discover(ctx.probe()))
        .expect("discovery")
        .expect("cgroups");
    block_on(cgroups.memory(ctx.probe())).expect("memory");
    block_on(cgroups.cpu(ctx.probe())).expect("cpu");
    block_on(cgroups.controllers(ctx.probe())).expect("controllers");
    let log = run.action_log();
    assert!(!log.actions.is_empty());
    for action in &log.actions {
        assert_ne!(action.outcome, ActionOutcome::Denied, "{action:?}");
    }
}
