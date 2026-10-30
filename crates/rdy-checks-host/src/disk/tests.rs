//! Tests of `host.disk` against the synthetic machines under `tests/fixtures/checks/host.disk/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest (`statfs` and `reads`) and the action log are the ones a run has. Each case
//! has an `expect.json` with the spec entry and the reviewed result. The test crate may not read files,
//! so the goldens are compiled in with `include_str!`. A mismatch panics with the new result in full:
//! when it is right, paste it into the case's `expect.json` and review the diff.

use std::sync::Arc;
use std::time::Duration;

use rdy_engine::check::{Check, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::{Fixture, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

macro_rules! expect {
    ($case:literal) => {
        (
            $case,
            include_str!(concat!(
                "../../../../tests/fixtures/checks/host.disk/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case, with its golden.
const CASES: &[(&str, &str)] = &[
    expect!("plenty"),
    expect!("tight"),
    expect!("below-recommended"),
    expect!("few-inodes"),
    expect!("no-inode-accounting"),
    expect!("missing-parent"),
    expect!("noexec-tmp"),
    expect!("nfs-home"),
    expect!("space-in-mount-point"),
    expect!("hung-nfs"),
    expect!("root-run"),
    expect!("permission-denied"),
    expect!("no-mountinfo"),
    expect!("btrfs-link-nodev"),
    expect!("btrfs-flag-mismatch"),
];

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.disk/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture.ensure_answers("host.disk").expect("it answers");
    fixture
}

fn disk(entry: &Value) -> Disk {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::HostDisk(params) => Disk::new(&params),
        other => panic!("not host.disk: {other:?}"),
    }
}

/// What a run produced.
struct Run {
    end: End,
    log: ActionLogOutput,
}

impl Run {
    fn finding(&self) -> &Finding {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        done.as_ref().as_ref().expect("a finding")
    }

    fn outcome(&self) -> &CheckOutcome {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        done
    }
}

/// Runs `disk` on the machine of `fixture` through the scheduler, on a paused clock.
fn run(fixture: &Fixture, disk: Disk) -> Run {
    let test_run = TestRun::for_fixture(fixture);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let planned = Planned::new(Arc::new(disk), "host.disk");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let mut ran = runtime.block_on(scheduler.run(vec![planned]));
    Run {
        end: ran.remove(0).end,
        log: test_run.action_log(),
    }
}

fn level_word(level: Level) -> &'static str {
    match level {
        Level::Pass => "pass",
        Level::Warn => "warn",
        Level::Fail => "fail",
    }
}

/// The result as the goldens hold it.
fn render(end: &End) -> Value {
    match end {
        End::TimedOut { after } => json!({ "timed_out_ms": after.as_millis() }),
        End::Done(done) => match done.as_ref() {
            Ok(finding) => json!({
                "level": level_word(finding.level),
                "message": finding.message,
                "observed": finding.observed,
                "expected": finding.expected,
                "fix": finding.fix,
                "notes": finding.notes,
                "partial": finding.partial.as_ref().map(|p| json!({
                    "missing": p.missing.iter().map(|n| format!("{n:?}")).collect::<Vec<_>>(),
                    "note": p.note,
                })),
            }),
            Err(error) => json!({ "error": error.to_string() }),
        },
        other => panic!("unexpected end: {other:?}"),
    }
}

#[test]
fn every_case_matches_its_golden() {
    let mut changed = Vec::new();
    for (case, text) in CASES {
        let golden: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{case}: {e}"));
        let entry = &golden["entry"];
        let result = run(&load(case), disk(entry));
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        if actual != golden {
            changed.push(format!(
                "=== tests/fixtures/checks/host.disk/{case}/expect.json ===\n{}\n",
                serde_json::to_string_pretty(&actual).expect("json")
            ));
        }
    }
    assert!(
        changed.is_empty(),
        "{} case(s) changed. If the new results are right, replace each expect.json with the text below it and review the diff:\n{}",
        changed.len(),
        changed.join("\n")
    );
}

#[test]
fn the_case_list_names_the_cases_the_catalog_needs_and_lists_none_twice() {
    // This does not look at the directory: a new case directory without a row is not caught here.
    // It checks that the cases named in the ticket are in the list and that no row repeats.
    let names: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    for expected in [
        "plenty",
        "tight",
        "no-inode-accounting",
        "noexec-tmp",
        "nfs-home",
        "space-in-mount-point",
        "hung-nfs",
    ] {
        assert!(names.contains(&expected), "{expected}");
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "a case is listed twice");
}

fn level_of(case: &str) -> Level {
    let golden: Value = serde_json::from_str(
        CASES
            .iter()
            .find(|(name, _)| *name == case)
            .expect("a case")
            .1,
    )
    .expect("json");
    let entry = &golden["entry"];
    run(&load(case), disk(entry)).finding().level
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    assert_eq!(level_of("plenty"), Level::Pass);
    assert_eq!(level_of("tight"), Level::Fail);
    assert_eq!(level_of("below-recommended"), Level::Warn);
    assert_eq!(level_of("few-inodes"), Level::Fail);
    assert_eq!(level_of("no-inode-accounting"), Level::Pass);
    assert_eq!(level_of("missing-parent"), Level::Pass);
    assert_eq!(level_of("noexec-tmp"), Level::Fail);
    assert_eq!(level_of("nfs-home"), Level::Fail);
    assert_eq!(level_of("space-in-mount-point"), Level::Pass);
    assert_eq!(level_of("root-run"), Level::Pass);
    assert_eq!(level_of("permission-denied"), Level::Warn);
    assert_eq!(level_of("no-mountinfo"), Level::Warn);
}

#[test]
fn a_hung_mount_ends_in_a_timeout_at_the_check_default() {
    let fixture = load("hung-nfs");
    let result = run(
        &fixture,
        disk(&json!({"id": "host.disk", "path": "/mnt/nfs/data", "min": "20Gi"})),
    );
    assert_eq!(
        result.end,
        End::TimedOut {
            after: Duration::from_secs(5)
        }
    );
    // One call went out and never came back.
    let natives: Vec<&Action> = result
        .log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Native)
        .collect();
    assert_eq!(natives.len(), 1);
}

#[test]
fn a_run_stays_inside_the_manifest() {
    for (case, text) in CASES {
        if *case == "hung-nfs" {
            continue;
        }
        let golden: Value = serde_json::from_str(text).expect("json");
        let result = run(&load(case), disk(&golden["entry"]));
        assert!(result.outcome().is_ok(), "{case}: {:?}", result.outcome());
        for action in &result.log.actions {
            assert!(
                matches!(action.kind, ActionKind::Native | ActionKind::Read),
                "{case}: {:?}",
                action.kind
            );
            if action.kind == ActionKind::Read {
                assert_eq!(
                    action.fields.get("path").and_then(Value::as_str),
                    Some(MOUNTINFO),
                    "{case}"
                );
            } else {
                assert_eq!(
                    action.fields.get("api").and_then(Value::as_str),
                    Some("statvfs"),
                    "{case}"
                );
            }
            assert_ne!(action.outcome, ActionOutcome::Denied, "{case}");
        }
        assert_within_manifest(case, &INFO, &result.log);
    }
    assert_eq!(INFO.reads, [MOUNTINFO]);
    assert_eq!(INFO.statfs, ["/"]);
    assert!(INFO.commands.is_empty() && INFO.env.is_empty() && INFO.peers.is_empty());
}

#[test]
fn the_walk_up_retries_statvfs_and_stops_at_the_first_parent_that_exists() {
    let fixture = load("missing-parent");
    let result = run(
        &fixture,
        disk(&json!({"id": "host.disk", "path": "/opt/acme/data", "min": "20Gi"})),
    );
    let paths: Vec<&str> = result
        .log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Native)
        .filter_map(|a| a.fields.get("path").and_then(Value::as_str))
        .collect();
    assert_eq!(paths, ["/opt/acme/data", "/opt/acme", "/opt"]);
    let finding = result.finding();
    assert_eq!(finding.observed["measured_path"], "/opt");
    assert_eq!(finding.observed["path"], "/opt/acme/data");
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("does not exist yet") && n.contains("`/opt`")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_walk_that_runs_out_of_attempts_is_not_verified() {
    let fixture = load("missing-parent");
    let check = disk(&json!({"id": "host.disk", "path": "/opt/acme/data", "min": "20Gi"}));
    let test_run = TestRun::for_fixture(&fixture);
    let ctx = test_run.context_for(&INFO, "host.disk", Os::Linux, Vec::<Need>::new());
    let parts = ["opt", "acme", "data"];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let stopped = runtime
        .block_on(check.reach_with(&ctx, &parts, 2))
        .expect("no error");
    let Reach::Stop(finding) = stopped else {
        panic!("it should have stopped");
    };
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("too many missing levels"));
    let found = runtime
        .block_on(check.reach_with(&ctx, &parts, 3))
        .expect("no error");
    assert!(matches!(found, Reach::Got(_)));
}

#[test]
fn a_whole_component_prefix_picks_the_right_mount_of_a_shared_volume() {
    // `/mnt/acme` is a bind mount of the same volume (same device) with `nodev`. The path is under
    // `/mnt/acme data`, and `/mnt/acme` is not a component-wise prefix of it.
    let fixture = load("space-in-mount-point");
    let result = run(
        &fixture,
        disk(
            &json!({"id": "host.disk", "path": "/mnt/acme data/releases", "min": "20Gi", "forbid_options": ["nodev"]}),
        ),
    );
    let finding = result.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    assert_eq!(finding.observed["mount"], "/mnt/acme data");
    assert_eq!(finding.observed["nodev"], false);
}

#[test]
fn a_forbidden_type_that_is_unknown_never_passes() {
    let fixture = load("no-mountinfo");
    let result = run(
        &fixture,
        disk(
            &json!({"id": "host.disk", "path": "/var/lib/acme", "min": "20Gi", "forbid_fstypes": ["nfs"]}),
        ),
    );
    let finding = result.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.partial.is_some());
    // With nothing forbidden by type, the same machine passes and says the type is unknown.
    let result = run(
        &fixture,
        disk(&json!({"id": "host.disk", "path": "/var/lib/acme", "min": "20Gi"})),
    );
    let finding = result.finding();
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.notes.iter().any(|n| n.contains("type is unknown")));
}

#[test]
fn an_nfs_home_is_a_pass_with_a_note_when_the_spec_does_not_forbid_it() {
    let fixture = load("nfs-home");
    let result = run(
        &fixture,
        disk(&json!({"id": "host.disk", "path": "/home/acme", "min": "20Gi"})),
    );
    let finding = result.finding();
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.observed["network"], true);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("network file system"))
    );
}

#[test]
fn the_root_note_appears_only_for_a_root_run() {
    let notes = |case: &str| -> Vec<String> {
        let fixture = load(case);
        run(
            &fixture,
            disk(&json!({"id": "host.disk", "path": "/var/lib/acme", "min": "20Gi"})),
        )
        .finding()
        .notes
        .clone()
    };
    assert!(notes("root-run").iter().any(|n| n.contains("runs as root")));
    assert!(!notes("plenty").iter().any(|n| n.contains("runs as root")));
}

#[test]
fn a_path_the_denylist_covers_is_not_verified_and_not_a_crash() {
    let fixture = load("plenty");
    let result = run(
        &fixture,
        disk(&json!({"id": "host.disk", "path": "/etc/shadow", "min": "1Gi"})),
    );
    let finding = result.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("rdy does not read this path"));
    assert!(finding.fix.as_deref().is_some_and(|f| !f.is_empty()));
}

#[test]
fn a_windows_path_or_a_dotdot_path_is_not_verified_before_any_call() {
    let fixture = load("plenty");
    for path in ["C:\\acme", "/var/../etc"] {
        let result = run(
            &fixture,
            disk(&json!({"id": "host.disk", "path": path, "min": "1Gi"})),
        );
        assert_eq!(result.finding().level, Level::Warn, "{path}");
        assert!(
            result.log.actions.is_empty(),
            "{path}: {:?}",
            result.log.actions
        );
    }
}

#[test]
fn on_another_os_the_check_is_unsupported_and_makes_no_call() {
    let fixture = load("plenty");
    let test_run = TestRun::for_fixture(&fixture);
    for os in [Os::Macos, Os::Windows] {
        let ctx = test_run.context_for(&INFO, "host.disk", os, Vec::<Need>::new());
        let check = disk(&json!({"id": "host.disk", "path": "/var", "min": "1Gi"}));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let outcome = runtime.block_on(check.run(&ctx));
        assert!(matches!(outcome, Err(CheckError::Unsupported(_))), "{os:?}");
    }
    assert!(test_run.action_log().actions.is_empty());
}

fn golden_entry(case: &str) -> Value {
    let text = CASES
        .iter()
        .find(|(name, _)| *name == case)
        .expect("a case")
        .1;
    let golden: Value = serde_json::from_str(text).expect("json");
    golden["entry"].clone()
}

#[test]
fn a_btrfs_subvolume_is_matched_by_mount_point_and_says_so() {
    // `st_dev` is 0:45, the subvolume's own device. Mountinfo shows 0:26 for the superblock.
    let fixture = load("no-inode-accounting");
    let result = run(
        &fixture,
        disk(
            &json!({"id": "host.disk", "path": "/opt/acme", "min": "20Gi", "forbid_fstypes": ["btrfs"]}),
        ),
    );
    let finding = result.finding();
    assert_eq!(finding.level, Level::Fail, "{}", finding.message);
    assert_eq!(finding.observed["device"], "0:45");
    assert_eq!(finding.observed["fstype"], "btrfs");
    assert!(finding.partial.is_none());
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("0:45")
                && n.contains("matched the btrfs mount `/` by its mount point")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_denied_directory_lists_no_missing_need_because_the_check_wants_none() {
    let fixture = load("permission-denied");
    let result = run(&fixture, disk(&golden_entry("permission-denied")));
    let finding = result.finding();
    let partial = finding.partial.as_ref().expect("a partial");
    assert!(partial.missing.is_empty(), "{:?}", partial.missing);
    assert!(INFO.wants.is_empty());
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("as root"))
    );
}
