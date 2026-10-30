//! Tests of `host.memory` against the synthetic machines under `tests/fixtures/checks/host.memory/`
//! (the 08 format, read by the Replay fixture loader).
//!
//! Each run goes through a probe that applies the real read policy and `CheckInfo::reads` and writes
//! the real action log, so a read outside the manifest would fail here as it does in a run.

use rdy_engine::check::{Check, CheckError, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

const GIB: u64 = 1 << 30;

fn memory(params: &Value) -> Memory {
    let mut entry = json!({"id": "host.memory"});
    for (key, value) in params.as_object().expect("an object") {
        entry[key] = value.clone();
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a check entry");
    match entry.decode_params() {
        CheckParams::HostMemory(params) => Memory::from_params(&params),
        other => panic!("not host.memory: {other:?}"),
    }
}

/// What one run produced and what it did to the machine.
struct Ran {
    outcome: CheckOutcome,
    run: TestRun,
}

impl Ran {
    fn finding(&self) -> &Finding {
        self.outcome.as_ref().expect("a finding")
    }

    fn observed(&self, key: &str) -> &Value {
        &self.finding().observed[key]
    }
}

fn run_on(case: &str, os: Os, params: &Value) -> Ran {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.memory/{case}"))
        .expect("the fixture loads");
    fixture
        .ensure_answers("host.memory")
        .expect("the fixture answers host.memory");
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(&INFO, "host.memory", os, fixture.available_needs());
    let check = memory(params);
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
        .block_on(check.run(&ctx));
    Ran { outcome, run }
}

fn run(case: &str, params: &Value) -> Ran {
    run_on(case, Os::Linux, params)
}

fn has_note(finding: &Finding, part: &str) -> bool {
    finding.notes.iter().any(|n| n.contains(part))
}

// ---- the total ---------------------------------------------------------------------------------

#[test]
fn a_31_3_gib_meminfo_against_min_32gi_passes_with_a_note() {
    let ran = run("pass", &json!({"min": "32Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(
        f.message,
        "31.3 GiB found, 32 GiB needed, inside the 5% tolerance"
    );
    assert!(has_note(f, "nominal size"), "{:?}", f.notes);
    assert_eq!(f.fix, None);
    assert_eq!(ran.observed("total_bytes"), &json!(32_820_428_u64 * 1024));
    assert_eq!(ran.observed("cgroup_limit_bytes"), &Value::Null);
    assert_eq!(f.expected["min_bytes"], json!(32 * GIB));
    assert_eq!(f.expected["band_bytes"], json!(32 * GIB / 20));
    assert_eq!(f.expected["min_available_bytes"], json!(16 * GIB));
    assert_eq!(f.partial, None);
}

#[test]
fn a_machine_that_has_the_memory_passes_with_no_note() {
    let ran = run("pass", &json!({"min": "8Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(f.message, "31.3 GiB found, 8 GiB needed");
    assert!(f.notes.is_empty(), "{:?}", f.notes);
}

#[test]
fn a_24_gib_meminfo_against_min_32gi_blocks_with_the_fix() {
    let ran = run("below-min", &json!({"min": "32Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(f.message, "24 GiB found, 32 GiB needed");
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.starts_with("24 GiB RAM, 32 GiB needed. Add RAM or pick a larger node class."),
        "{fix}"
    );
}

#[test]
fn a_4gb_vm_showing_3_8_gib_passes_against_4gi_on_the_256_mib_floor() {
    let ran = run("vm-4gb", &json!({"min": "4Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(
        f.message,
        "3.8 GiB found, 4 GiB needed, inside the 256 MiB tolerance"
    );
    assert_eq!(f.expected["band_bytes"], json!(256 * 1024 * 1024));
}

#[test]
fn tolerance_percent_zero_turns_the_band_off() {
    let ran = run("vm-4gb", &json!({"min": "4Gi", "tolerance_percent": 0}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(f.message, "3.8 GiB found, 4 GiB needed");
    assert_eq!(f.expected["band_bytes"], json!(0));
}

#[test]
fn tolerance_result_warn_makes_the_band_a_warning_with_the_fix() {
    let ran = run("pass", &json!({"min": "32Gi", "tolerance_result": "warn"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert!(f.message.contains("inside the 5% tolerance"));
    assert!(f.fix.as_deref().expect("a fix").contains("Add RAM"));
}

#[test]
fn a_bigger_tolerance_widens_the_band() {
    // 24 GiB against 32Gi is 25% short. A 20% band does not reach it.
    let ran = run(
        "below-min",
        &json!({"min": "32Gi", "tolerance_percent": 20}),
    );
    assert_eq!(ran.finding().level, Level::Fail);
    // 24 GiB against 28Gi is 14% short. 15% reaches it.
    let ran = run(
        "below-min",
        &json!({"min": "28Gi", "tolerance_percent": 15}),
    );
    assert_eq!(ran.finding().level, Level::Pass);
}

// ---- swap --------------------------------------------------------------------------------------

#[test]
fn swap_forbid_with_swap_on_blocks() {
    let ran = run("swap-on", &json!({"min": "32Gi", "swap": "forbid"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message
            .ends_with("swap is on (4 GiB), the spec says it must be off"),
        "{}",
        f.message
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("`swapoff -a`") && fix.contains("/etc/fstab"),
        "{fix}"
    );
    assert_eq!(
        ran.observed("swap_total_bytes"),
        &json!(4_194_300_u64 * 1024)
    );
    assert_eq!(ran.observed("swap_used_bytes"), &json!(98_300_u64 * 1024));
    assert_eq!(f.expected["swap"], json!("forbid"));
}

#[test]
fn swap_forbid_with_swap_off_passes() {
    let ran = run("pass", &json!({"min": "32Gi", "swap": "forbid"}));
    assert_eq!(ran.finding().level, Level::Pass);
    assert_eq!(ran.observed("swap_total_bytes"), &json!(0));
}

#[test]
fn swap_any_is_the_default_and_only_reports() {
    let ran = run("swap-on", &json!({"min": "32Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert!(!f.message.contains("swap"));
    assert_eq!(f.expected["swap"], json!("any"));
    assert_eq!(
        ran.observed("swap_total_bytes"),
        &json!(4_194_300_u64 * 1024)
    );
}

// ---- available memory --------------------------------------------------------------------------

#[test]
fn low_available_memory_warns_that_the_box_is_busy() {
    let ran = run("low-available", &json!({"min": "8Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert_eq!(
        f.message,
        "15.6 GiB found, 8 GiB needed; only 2.3 GiB available, 4 GiB wanted, the box is busy"
    );
    assert!(
        f.fix
            .as_deref()
            .expect("a fix")
            .contains("Stop other workloads")
    );
    // The total was fine, so its fix is not in the advice.
    assert!(!f.fix.as_deref().expect("a fix").contains("Add RAM"));
}

#[test]
fn min_available_in_the_spec_replaces_the_default() {
    let ran = run(
        "low-available",
        &json!({"min": "8Gi", "min_available": "2Gi"}),
    );
    assert_eq!(ran.finding().level, Level::Pass);
    let ran = run(
        "low-available",
        &json!({"min": "8Gi", "min_available": "3Gi"}),
    );
    assert_eq!(ran.finding().level, Level::Warn);
}

#[test]
fn a_kernel_with_no_memavailable_line_gets_an_estimate_and_says_so() {
    let ran = run("no-memavailable", &json!({"min": "8Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(ran.observed("available_estimated"), &json!(true));
    assert_eq!(
        ran.observed("available_bytes"),
        &json!((9_000_000_u64 + 100_000 + 4_000_000) * 1024)
    );
    assert!(has_note(f, "estimated"), "{:?}", f.notes);
    // The estimate is judged like the real value.
    let ran = run(
        "no-memavailable",
        &json!({"min": "8Gi", "min_available": "12800Mi"}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert!(
        f.message.contains("only about 12.5 GiB available"),
        "{}",
        f.message
    );
}

#[test]
fn a_total_failure_and_a_busy_box_report_both_and_fix_both() {
    let ran = run(
        "below-min",
        &json!({"min": "32Gi", "min_available": "30Gi"}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(f.message.contains("24 GiB found, 32 GiB needed; only"));
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("Add RAM") && fix.contains("Stop other workloads"),
        "{fix}"
    );
}

// ---- cgroups -----------------------------------------------------------------------------------

#[test]
fn a_nested_v2_limit_is_reported_and_binds() {
    let ran = run("cgroup-v2-nested", &json!({"min": "2Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(
        f.message,
        "4 GiB found, 2 GiB needed, limited by cgroup /system.slice/acme.slice, host has 62.8 GiB"
    );
    assert_eq!(ran.observed("total_bytes"), &json!(65_839_996_u64 * 1024));
    assert_eq!(ran.observed("cgroup_limit_bytes"), &json!(4 * GIB));
    assert_eq!(
        ran.observed("cgroup_limit_at"),
        &json!("/system.slice/acme.slice")
    );
    assert_eq!(ran.observed("cgroup_swap_limit_bytes"), &json!(GIB));
    assert_eq!(ran.observed("cgroup_hierarchy"), &json!("v2"));
    assert_eq!(ran.observed("effective_bytes"), &json!(4 * GIB));
    // Available is capped at the limit and the note says use inside the cgroup is not measured.
    assert_eq!(ran.observed("available_effective_bytes"), &json!(4 * GIB));
    assert!(has_note(f, "not measured"), "{:?}", f.notes);
}

#[test]
fn a_nested_v2_limit_below_min_blocks_and_the_fix_names_the_cgroup() {
    let ran = run("cgroup-v2-nested", &json!({"min": "8Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message
            .starts_with("4 GiB found, 8 GiB needed, limited by cgroup")
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.starts_with(
            "The memory limit of cgroup /system.slice/acme.slice is 4 GiB, 8 GiB needed (the host has 62.8 GiB)."
        ),
        "{fix}"
    );
    assert!(
        fix.contains("`systemctl set-property acme.slice MemoryMax=8G`"),
        "{fix}"
    );
    assert!(!fix.contains("Add RAM"), "{fix}");
}

#[test]
fn a_swap_limit_in_the_cgroup_is_evidence_and_not_a_pass_for_swap_forbid() {
    // The host has swap; the slice limit of 1 GiB does not make the machine swapless.
    let ran = run("cgroup-v2-nested", &json!({"min": "2Gi", "swap": "forbid"}));
    assert_eq!(ran.finding().level, Level::Pass, "no swap on this host");
    let ran = run("swap-on", &json!({"min": "32Gi", "swap": "forbid"}));
    assert_eq!(ran.observed("cgroup_swap_limit_bytes"), &Value::Null);
}

#[test]
fn a_v1_limit_is_found_and_swap_stays_empty() {
    let ran = run("cgroup-v1-limit", &json!({"min": "4Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "2 GiB found, 4 GiB needed, limited by cgroup /system.slice/acme.slice, host has 15.6 GiB"
    );
    assert_eq!(ran.observed("cgroup_hierarchy"), &json!("v1"));
    assert_eq!(ran.observed("cgroup_swap_limit_bytes"), &Value::Null);
}

#[test]
fn a_limit_above_the_host_does_not_bind() {
    let ran = run("cgroup-above-host", &json!({"min": "32Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert!(!f.message.contains("limited by cgroup"), "{}", f.message);
    assert_eq!(ran.observed("cgroup_limit_bytes"), &json!(128 * GIB));
    assert_eq!(
        ran.observed("effective_bytes"),
        &json!(32_820_428_u64 * 1024)
    );
}

#[test]
fn an_unreadable_cgroup_file_is_a_note_and_the_readable_limit_still_binds() {
    let ran = run("cgroup-unreadable", &json!({"min": "2Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert!(
        f.message.contains("limited by cgroup /system.slice"),
        "{}",
        f.message
    );
    assert!(has_note(f, "could not be read"), "{:?}", f.notes);
}

#[test]
fn a_container_that_sees_a_subtree_says_a_limit_above_it_is_not_visible() {
    let ran = run("cgroup-container-view", &json!({"min": "8Gi"}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert!(has_note(f, "only part of the cgroup tree"), "{:?}", f.notes);
}

#[test]
fn a_machine_with_no_cgroup_files_has_no_cgroup_evidence_or_notes() {
    let ran = run("pass", &json!({"min": "8Gi"}));
    assert_eq!(ran.observed("cgroup_hierarchy"), &Value::Null);
    assert!(ran.finding().notes.is_empty());
}

// ---- errors, OS, manifest ----------------------------------------------------------------------

#[test]
fn a_meminfo_that_is_not_a_meminfo_is_a_check_failure_with_a_hint() {
    let ran = run("garbage", &json!({"min": "8Gi"}));
    let Err(CheckError::Failed { message, hint }) = &ran.outcome else {
        panic!("{:?}", ran.outcome);
    };
    assert!(
        message.starts_with("/proc/meminfo is not in the form rdy reads"),
        "{message}"
    );
    assert!(hint.contains("/proc is mounted"), "{hint}");
}

#[test]
fn a_machine_with_no_meminfo_is_a_check_failure_with_a_hint() {
    let ran = run("no-proc", &json!({"min": "8Gi"}));
    let Err(CheckError::Failed { message, .. }) = &ran.outcome else {
        panic!("{:?}", ran.outcome);
    };
    assert_eq!(message, "/proc/meminfo does not exist on this machine");
}

#[test]
fn macos_and_windows_are_skipped_without_a_read() {
    for os in [Os::Macos, Os::Windows] {
        let ran = run_on("pass", os, &json!({"min": "8Gi"}));
        assert!(
            matches!(ran.outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {:?}",
            ran.outcome
        );
        assert!(ran.run.action_log().actions.is_empty(), "{os:?}");
    }
}

#[test]
fn the_check_needs_nothing_and_runs_without_root() {
    assert!(INFO.needs.is_empty());
    assert!(INFO.wants.is_empty());
    assert_eq!(INFO.default_timeout, Some(Duration::from_secs(2)));
    let fixture = Fixture::load(&fixtures_dir(), "checks/host.memory/pass").expect("loads");
    assert!(!fixture.available_needs().contains(&Need::Root));
    assert_eq!(
        run("pass", &json!({"min": "8Gi"})).finding().level,
        Level::Pass
    );
}

/// The paths the check read are all inside its manifest, nothing was denied and no command ran. The
/// probe enforces the manifest, so a violation would also have failed the run.
#[test]
fn every_run_stays_inside_the_manifest() {
    for case in [
        "pass",
        "swap-on",
        "cgroup-v2-nested",
        "cgroup-v1-limit",
        "cgroup-unreadable",
        "cgroup-container-view",
        "no-proc",
    ] {
        let ran = run(case, &json!({"min": "8Gi"}));
        let log = ran.run.action_log();
        assert!(!log.actions.is_empty(), "{case}");
        for action in &log.actions {
            assert_eq!(action.kind, ActionKind::Read, "{case}: {action:?}");
            assert_ne!(action.outcome, ActionOutcome::Denied, "{case}: {action:?}");
            let path = action.fields["path"].as_str().expect("a path");
            let inside = INFO.reads.iter().any(|prefix| {
                path == *prefix
                    || path
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/'))
            });
            assert!(inside, "{case}: {path} is outside the declared reads");
        }
    }
}

/// Every fix the check can give passes the fix-text audit (ADR 0028).
#[test]
fn every_fix_passes_the_fix_text_audit() {
    let mut seen = 0;
    for (case, params) in [
        ("below-min", json!({"min": "32Gi", "min_available": "30Gi"})),
        ("swap-on", json!({"min": "64Gi", "swap": "forbid"})),
        ("low-available", json!({"min": "8Gi"})),
        ("cgroup-v2-nested", json!({"min": "8Gi"})),
        ("cgroup-v1-limit", json!({"min": "4Gi"})),
    ] {
        let ran = run(case, &params);
        let fix = ran.finding().fix.clone().expect("a fix");
        if let Err(error) = rdy_engine::fixtext::check(&fix) {
            panic!("{case}: {error}");
        }
        seen += 1;
    }
    assert_eq!(seen, 5);
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("{error}");
    }
}
