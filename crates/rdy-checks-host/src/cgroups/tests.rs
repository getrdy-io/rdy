//! Tests of `host.cgroups` against the synthetic machines under `tests/fixtures/checks/host.cgroups/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest (`reads`) and the action log are the ones a run has. Each case has an
//! `expect.json` with the spec entry and the reviewed result. The test crate may not read files, so the
//! goldens are compiled in with `include_str!` to read the spec entry. `assert_golden` compares the
//! bytes: a mismatch fails with a diff, and `UPDATE_GOLDENS=1` rewrites the file for review.
//!
//! The level in a golden is the check's. What the customer sees is the status `map_outcome` gives it, so
//! `mapped_status` asserts that too, for a required check and for a `severity: warn` check.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckOutcome, Finding, Level, Os};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

macro_rules! expect {
    ($case:literal) => {
        (
            $case,
            include_str!(concat!(
                "../../../../tests/fixtures/checks/host.cgroups/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case, with its golden.
const CASES: &[(&str, &str)] = &[
    expect!("v2-ok"),
    expect!("v2-idle-top"),
    expect!("v2-no-demand"),
    expect!("v2-named-v1"),
    expect!("v1-wanted-v2-rhel"),
    expect!("v1-hinted-command-line"),
    expect!("hybrid-wanted-v2-ubuntu"),
    expect!("hybrid-wanted-v1"),
    expect!("v2-wanted-v1"),
    expect!("v2-memory-off"),
    expect!("v2-memory-off-pi"),
    expect!("v1-hierarchy-not-mounted"),
    expect!("unmounted"),
];

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.cgroups/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture.ensure_answers("host.cgroups").expect("it answers");
    fixture
}

fn entry_of(case: &str) -> Value {
    let text = CASES
        .iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("{case} is not in CASES"))
        .1;
    let golden: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{case}: {e}"));
    golden["entry"].clone()
}

fn spec_entry(entry: &Value) -> CheckSpec {
    serde_json::from_value(entry.clone()).expect("a check entry")
}

fn check_for(entry: &Value) -> CgroupsCheck {
    match spec_entry(entry).decode_params() {
        CheckParams::HostCgroups(params) => CgroupsCheck::from_params(&params),
        other => panic!("not host.cgroups: {other:?}"),
    }
}

/// What a run produced.
struct Run {
    end: End,
    log: ActionLogOutput,
}

impl Run {
    fn outcome(&self) -> &CheckOutcome {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        done
    }

    fn finding(&self) -> &Finding {
        self.outcome().as_ref().expect("a finding")
    }
}

/// Runs `check` on the machine of `fixture` through the scheduler, on a paused clock.
fn run(fixture: &Fixture, check: CgroupsCheck) -> Run {
    let test_run = TestRun::for_fixture(fixture);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let planned = Planned::new(Arc::new(check), "host.cgroups");
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

fn run_case(case: &str) -> Run {
    run(&load(case), check_for(&entry_of(case)))
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

/// The value with every object's keys in order. The goldens have sorted keys, and a build where another
/// crate turns on serde_json's `preserve_order` would otherwise write them in insertion order.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// The status of the report entry for `case`, with `extra` keys (such as `severity`) added to the entry.
fn mapped_status(case: &str, extra: &Value) -> Status {
    let mut entry = entry_of(case);
    for (key, value) in extra.as_object().expect("an object") {
        entry[key] = value.clone();
    }
    let fixture = load(case);
    let outcome = run(&fixture, check_for(&entry)).outcome().clone();
    let test_run = TestRun::for_fixture(&fixture);
    let ctx = test_run.context_for(&INFO, "host.cgroups", Os::Linux, Vec::new());
    map_outcome(&INFO, &spec_entry(&entry), &ctx, outcome, 0, 0).status
}

#[test]
fn every_case_matches_its_golden() {
    for (case, _) in CASES {
        let entry = entry_of(case);
        let result = run_case(case);
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        let mut bytes = serde_json::to_string_pretty(&sorted(actual)).expect("json");
        bytes.push('\n');
        assert_golden(
            fixtures_dir().join(format!("checks/host.cgroups/{case}/expect.json")),
            bytes,
        );
    }
}

#[test]
fn the_case_list_names_the_cases_the_ticket_needs_and_lists_none_twice() {
    // This does not look at the directory: a new case directory without a row is not caught here.
    let names: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    for expected in [
        "v2-ok",
        "hybrid-wanted-v2-ubuntu",
        "hybrid-wanted-v1",
        "v1-wanted-v2-rhel",
        "v2-memory-off",
    ] {
        assert!(names.contains(&expected), "{expected}");
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "a case is listed twice");
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    for (case, level) in [
        ("v2-ok", Level::Pass),
        ("v2-idle-top", Level::Pass),
        ("v2-no-demand", Level::Pass),
        ("v2-named-v1", Level::Pass),
        ("v1-wanted-v2-rhel", Level::Fail),
        ("v1-hinted-command-line", Level::Fail),
        ("hybrid-wanted-v2-ubuntu", Level::Fail),
        ("hybrid-wanted-v1", Level::Pass),
        ("v2-wanted-v1", Level::Fail),
        ("v2-memory-off", Level::Fail),
        ("v2-memory-off-pi", Level::Fail),
        ("v1-hierarchy-not-mounted", Level::Warn),
        ("unmounted", Level::Warn),
    ] {
        assert_eq!(run_case(case).finding().level, level, "{case}");
    }
}

#[test]
fn the_mapped_status_of_a_required_check_blocks_on_a_fail_and_passes_on_a_pass() {
    // This is what the customer sees. A required check that fails is `block`, a pass stays `pass`
    // with no privilege, and a case that cannot be confirmed is only a `warn`.
    let none = json!({});
    for (case, status) in [
        ("v2-ok", Status::Pass),
        ("v2-idle-top", Status::Pass),
        ("v2-no-demand", Status::Pass),
        ("v2-named-v1", Status::Pass),
        ("hybrid-wanted-v1", Status::Pass),
        ("v1-wanted-v2-rhel", Status::Block),
        ("v1-hinted-command-line", Status::Block),
        ("hybrid-wanted-v2-ubuntu", Status::Block),
        ("v2-wanted-v1", Status::Block),
        ("v2-memory-off", Status::Block),
        ("v2-memory-off-pi", Status::Block),
        ("v1-hierarchy-not-mounted", Status::Warn),
        ("unmounted", Status::Warn),
    ] {
        assert_eq!(mapped_status(case, &none), status, "{case}");
    }
}

#[test]
fn a_severity_warn_entry_turns_a_fail_into_a_warn_and_leaves_a_pass() {
    // The example spec sets `severity: warn` on host.cgroups. A pass must not become a warning
    // (the check wants nothing, so the partial rule has nothing to downgrade).
    let warn = json!({"severity": "warn"});
    assert_eq!(mapped_status("v1-wanted-v2-rhel", &warn), Status::Warn);
    assert_eq!(mapped_status("v2-memory-off", &warn), Status::Warn);
    assert_eq!(mapped_status("v2-ok", &warn), Status::Pass);
}

#[test]
fn the_version_cases_say_what_they_found_and_what_is_needed() {
    let v1 = run_case("v1-wanted-v2-rhel");
    let f = v1.finding();
    assert_eq!(f.message, "cgroup v1 in use, v2 needed");
    assert_eq!(f.observed["layout"], "v1");
    assert_eq!(
        f.fix.as_deref(),
        Some(
            "Run `grubby --update-kernel=ALL --args=\"systemd.unified_cgroup_hierarchy=1\"` and reboot."
        )
    );

    let hybrid = run_case("hybrid-wanted-v2-ubuntu");
    let f = hybrid.finding();
    assert_eq!(f.message, "cgroup hybrid layout in use, v2 needed");
    assert_eq!(
        f.fix.as_deref(),
        Some(
            "Add `systemd.unified_cgroup_hierarchy=1` to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, run `update-grub` and reboot."
        )
    );
    assert!(f.notes.iter().any(|n| n.starts_with("Hybrid layout:")));

    // A hybrid host keeps its controllers in v1, so `version: v1` is met, with the note.
    let ok = run_case("hybrid-wanted-v1");
    let f = ok.finding();
    assert_eq!(
        f.message,
        "cgroup hybrid layout in use, controllers `cpu` and `memory` available"
    );
    assert_eq!(f.fix, None);

    let suse = run_case("v2-wanted-v1");
    let f = suse.finding();
    assert_eq!(f.message, "cgroup v2 in use, v1 needed");
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.starts_with("Add `systemd.unified_cgroup_hierarchy=0` to the kernel command line"),
        "{fix}"
    );
    assert!(
        fix.contains("SYSTEMD_CGROUP_ENABLE_LEGACY_FORCE=1"),
        "{fix}"
    );
}

#[test]
fn a_named_v1_hierarchy_beside_a_unified_tree_is_v2_not_hybrid() {
    let ran = run_case("v2-named-v1");
    let f = ran.finding();
    assert_eq!(
        f.message,
        "cgroup v2 in use, controllers `cpu` and `memory` available"
    );
    assert_eq!(f.observed["layout"], "v2");
    assert!(f.notes.is_empty(), "{:?}", f.notes);
}

#[test]
fn a_command_line_that_says_the_opposite_is_named_in_a_note() {
    let ran = run_case("v1-hinted-command-line");
    let f = ran.finding();
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("systemd.unified_cgroup_hierarchy=0")
                && n.contains("Change that word")),
        "{:?}",
        f.notes
    );
    assert_eq!(
        f.observed["cmdline"],
        json!(["systemd.unified_cgroup_hierarchy=0"])
    );
}

#[test]
fn a_memory_controller_that_is_off_follows_the_boot_option_and_the_os() {
    let rhel = run_case("v2-memory-off");
    let f = rhel.finding();
    assert_eq!(
        f.message,
        "cgroup v2 in use, controller `memory` is missing"
    );
    assert_eq!(
        f.fix.as_deref(),
        Some(
            "Run `grubby --update-kernel=ALL --remove-args=\"cgroup_disable=memory\"` and reboot."
        )
    );
    assert_eq!(f.observed["controllers"]["memory"], "missing");
    assert_eq!(f.observed["controllers"]["cpu"], "ok");
    assert_eq!(
        f.observed["proc_cgroups"]["memory"],
        json!({"enabled": false, "hierarchy": 0})
    );
    // Only the cgroup words of the command line are kept.
    assert_eq!(f.observed["cmdline"], json!(["cgroup_disable=memory"]));

    let pi = run_case("v2-memory-off-pi");
    let f = pi.finding();
    assert_eq!(
        f.fix.as_deref(),
        Some(
            "Add `cgroup_memory=1 cgroup_enable=memory` to the single line in `/boot/firmware/cmdline.txt` (`/boot/cmdline.txt` before Debian 12) and reboot."
        )
    );
    assert_eq!(f.observed["cmdline"], json!([]));
}

#[test]
fn a_controller_offered_but_not_enabled_at_the_top_passes_with_a_note() {
    let ran = run_case("v2-idle-top");
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert!(
        f.notes.iter().any(|n| n.contains("`memory` and `pids`")),
        "{:?}",
        f.notes
    );
    assert_eq!(f.fix, None);
}

#[test]
fn a_v1_hierarchy_that_is_not_mounted_is_not_confirmed_never_called_missing() {
    let ran = run_case("v1-hierarchy-not-mounted");
    let f = ran.finding();
    assert_eq!(f.message, "cgroup v1 in use, could not confirm `io`");
    assert_eq!(f.observed["controllers"]["io"], "not_confirmed");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("enabled in the kernel but its hierarchy is not mounted")),
        "{:?}",
        f.notes
    );
}

#[test]
fn a_masked_cgroup_tree_says_so_and_does_not_guess() {
    let ran = run_case("unmounted");
    let f = ran.finding();
    assert_eq!(
        f.message,
        "rdy could not see a cgroup file system, so the cgroup version is not known"
    );
    assert_eq!(f.observed["layout"], Value::Null);
    assert!(
        f.fix
            .as_deref()
            .expect("a fix")
            .contains("not in a container")
    );
}

#[test]
fn a_spec_with_no_keys_only_reports() {
    let ran = run_case("v2-no-demand");
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(f.message, "cgroup v2 in use");
    assert_eq!(f.expected, json!({"version": "any", "controllers": []}));
}

#[test]
fn another_os_is_not_yet_and_reads_nothing() {
    let fixture = load("v2-ok");
    for os in [Os::Macos, Os::Windows] {
        let test_run = TestRun::for_fixture(&fixture);
        let ctx = test_run.context_for(&INFO, "host.cgroups", os, Vec::new());
        let check = check_for(&json!({"id": "host.cgroups", "version": "v2"}));
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
            .block_on(check.run(&ctx));
        assert!(
            matches!(outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {outcome:?}"
        );
        assert!(test_run.action_log().actions.is_empty(), "{os:?}");
    }
}

#[test]
fn a_run_stays_inside_the_manifest_and_only_reads() {
    for (case, _) in CASES {
        let result = run_case(case);
        assert!(result.outcome().is_ok(), "{case}: {:?}", result.outcome());
        for action in &result.log.actions {
            assert_eq!(action.kind, ActionKind::Read, "{case}");
            assert_ne!(action.outcome, ActionOutcome::Denied, "{case}");
        }
        assert_within_manifest(case, &INFO, &result.log);
    }
    // No privilege, no command, no socket, no `statfs`: the layout comes from the mount table.
    assert!(INFO.needs.is_empty() && INFO.wants.is_empty());
    assert!(INFO.commands.is_empty() && INFO.env.is_empty() && INFO.peers.is_empty());
    assert!(INFO.statfs.is_empty());
    for path in crate::cgroup::READS {
        assert!(INFO.reads.contains(&path), "{path}");
    }
}

#[test]
fn every_fix_and_the_remediation_pass_the_fix_text_audit() {
    let mut seen = 0;
    for (case, _) in CASES {
        if let Some(fix) = run_case(case).finding().fix.clone() {
            if let Err(error) = rdy_engine::fixtext::check(&fix) {
                panic!("{case}: {error}");
            }
            seen += 1;
        }
    }
    assert_eq!(seen, 8);
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("{error}");
    }
}
