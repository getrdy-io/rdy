//! Tests of `host.kernel` against the synthetic machines under `tests/fixtures/checks/host.kernel/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest (`reads`) and the action log are the ones a run has. Each case has an
//! `expect.json` with the spec entry and the reviewed result. The test crate may not read files, so the
//! goldens are compiled in with `include_str!` to read the spec entry. `assert_golden` compares the
//! bytes: a mismatch fails with a diff, and `UPDATE_GOLDENS=1` rewrites the file for review.
//!
//! The check wants no privilege, so the engine never downgrades a pass for a missing need. The tests
//! still map each finding through `map_outcome` and assert the status that lands in the report.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckError, CheckOutcome, Finding, Level, Need, Os};
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
                "../../../../tests/fixtures/checks/host.kernel/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case, with its golden.
const CASES: &[(&str, &str)] = &[
    expect!("pass"),
    expect!("module-xz-only"),
    expect!("module-absent"),
    expect!("dependency-only"),
    expect!("name-case-and-dash"),
    expect!("distro-min-overrides"),
    expect!("distro-min-below"),
    expect!("upstream-below"),
    expect!("distro-unknown"),
    expect!("distro-like"),
    expect!("distro-not-listed"),
    expect!("btf-missing"),
    expect!("modules-dir-missing"),
    expect!("proc-modules-unreadable"),
    expect!("usr-lib-modules-zst"),
    expect!("uname-fallback"),
    expect!("hostile-release"),
];

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.kernel/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture.ensure_answers("host.kernel").expect("it answers");
    fixture
}

fn entry_of(case: &str) -> Value {
    let (_, text) = CASES
        .iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("no case {case}"));
    let golden: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{case}: {e}"));
    golden["entry"].clone()
}

fn kernel(entry: &Value) -> Kernel {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::HostKernel(params) => Kernel::from_params(&params),
        other => panic!("not host.kernel: {other:?}"),
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
fn run(fixture: &Fixture, check: Kernel) -> Run {
    let test_run = TestRun::for_fixture(fixture);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let planned = Planned::new(Arc::new(check), "host.kernel");
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
    run(&load(case), kernel(&entry_of(case)))
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

/// The value with every object's keys in order. The goldens have sorted keys, and a build where
/// another crate turns on serde_json's `preserve_order` would otherwise write them in insertion order.
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

#[test]
fn every_case_matches_its_golden() {
    for (case, _) in CASES {
        let entry = entry_of(case);
        let result = run(&load(case), kernel(&entry));
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        let mut bytes = serde_json::to_string_pretty(&sorted(actual)).expect("json");
        bytes.push('\n');
        assert_golden(
            fixtures_dir().join(format!("checks/host.kernel/{case}/expect.json")),
            bytes,
        );
    }
}

#[test]
fn the_case_list_lists_no_case_twice_and_names_the_exit_test_cases() {
    let names: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    for expected in [
        "pass",
        "module-xz-only",
        "module-absent",
        "distro-min-overrides",
    ] {
        assert!(names.contains(&expected), "{expected}");
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "a case is listed twice");
}

/// The status the report gets for the finding of `case`, with the entry's own severity.
fn status_of(case: &str, severity: Option<&str>) -> Status {
    let fixture = load(case);
    let finding = run(&fixture, kernel(&entry_of(case))).finding().clone();
    let mut entry = entry_of(case);
    if let Some(severity) = severity {
        entry["severity"] = json!(severity);
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a check entry");
    let test_run = TestRun::for_fixture(&fixture);
    let ctx = test_run.context_for(&INFO, "host.kernel", Os::Linux, Vec::<Need>::new());
    let result = map_outcome(&INFO, &entry, &ctx, Ok(finding), 0, 0);
    // Nothing here is a want, so a result is never partial and never lists a need.
    assert!(result.partial.is_none(), "{case}: {:?}", result.partial);
    assert!(result.needs.is_empty(), "{case}: {:?}", result.needs);
    result.status
}

#[test]
fn the_exit_test_a_module_only_in_modules_dep_as_xz_warns() {
    let run = run_case("module-xz-only");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "Module `br_netfilter` is installed but not loaded."
    );
    assert_eq!(finding.observed["modules"]["br_netfilter"], "available");
    assert_eq!(finding.observed["modules"]["overlay"], "loaded");
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("sudo modprobe -a br_netfilter"), "{fix}");
    assert!(fix.contains("/etc/modules-load.d/vendor.conf"), "{fix}");
    assert_eq!(status_of("module-xz-only", None), Status::Warn);
}

#[test]
fn the_exit_test_an_absent_module_blocks() {
    let run = run_case("module-absent");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("Module `ip_vs` is not available for kernel `5.14.0-362.el9.x86_64`"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["modules"]["ip_vs"], "absent");
    assert_eq!(status_of("module-absent", None), Status::Block);
    // A severity: warn entry caps the block at a warning.
    assert_eq!(status_of("module-absent", Some("warn")), Status::Warn);
}

#[test]
fn the_exit_test_distro_min_overrides_the_upstream_compare() {
    // 4.18.0-348 is below min 5.4 and above the RHEL minimum 4.18.0-305: the RHEL entry decides.
    let overrides = run_case("distro-min-overrides");
    let finding = overrides.finding();
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(finding.expected["applied"]["source"], "distro_min");
    assert_eq!(finding.expected["applied"]["distro"], "rhel");
    assert_eq!(status_of("distro-min-overrides", None), Status::Pass);

    // Below the RHEL build number it blocks, and the message names the build that was compared.
    let below = run_case("distro-min-below");
    assert_eq!(below.finding().level, Level::Fail);
    assert!(
        below.finding().message.contains("4.18.0-305 on `rhel`"),
        "{}",
        below.finding().message
    );
    assert_eq!(status_of("distro-min-below", None), Status::Block);

    // Without distro_min the same kernel is compared with min.
    let plain = run(
        &load("distro-min-overrides"),
        kernel(&json!({"id": "host.kernel", "min": "5.4"})),
    );
    assert_eq!(plain.finding().level, Level::Fail);
}

#[test]
fn a_name_only_in_a_dependency_list_is_not_an_installed_module() {
    let run = run_case("dependency-only");
    assert_eq!(run.finding().level, Level::Fail);
    assert_eq!(run.finding().observed["modules"]["llc_extra"], "absent");
}

#[test]
fn module_names_keep_their_case_and_treat_dash_as_underscore() {
    let run = run_case("name-case-and-dash");
    let finding = run.finding();
    assert_eq!(finding.observed["modules"]["xt_tcpmss"], "absent");
    assert_eq!(finding.observed["modules"]["xt-TCPMSS"], "loaded");
    assert_eq!(finding.observed["modules"]["nf-defrag-ipv6"], "loaded");
    assert_eq!(finding.level, Level::Fail);
}

#[test]
fn a_module_in_modules_builtin_counts_without_being_loaded() {
    let run = run_case("pass");
    let finding = run.finding();
    assert_eq!(finding.observed["modules"]["br_netfilter"], "built_in");
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(status_of("pass", None), Status::Pass);
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    for (case, level) in [
        ("pass", Level::Pass),
        ("module-xz-only", Level::Warn),
        ("module-absent", Level::Fail),
        ("dependency-only", Level::Fail),
        ("name-case-and-dash", Level::Fail),
        ("distro-min-overrides", Level::Pass),
        ("distro-min-below", Level::Fail),
        ("upstream-below", Level::Fail),
        // The distribution is unknown, so a kernel below min is a warning.
        ("distro-unknown", Level::Warn),
        ("distro-like", Level::Warn),
        ("distro-not-listed", Level::Pass),
        ("btf-missing", Level::Fail),
        // Cannot tell never blocks.
        ("modules-dir-missing", Level::Warn),
        ("proc-modules-unreadable", Level::Warn),
        ("usr-lib-modules-zst", Level::Warn),
        ("uname-fallback", Level::Pass),
        ("hostile-release", Level::Warn),
    ] {
        assert_eq!(run_case(case).finding().level, level, "{case}");
    }
}

#[test]
fn what_cannot_be_read_says_so_and_never_blocks() {
    let missing = run_case("modules-dir-missing");
    let message = &missing.finding().message;
    assert!(
        message.contains("/lib/modules/5.14.0-362.el9.x86_64/modules.dep does not exist"),
        "{message}"
    );
    assert_eq!(
        missing.finding().observed["modules"]["br_netfilter"],
        "unknown"
    );

    let unreadable = run_case("proc-modules-unreadable");
    let message = &unreadable.finding().message;
    assert!(
        message.contains("/proc/modules could not be read (permission denied)"),
        "{message}"
    );
    assert_eq!(status_of("proc-modules-unreadable", None), Status::Warn);
}

#[test]
fn an_unknown_distribution_applies_min_and_only_warns() {
    let run = run_case("distro-unknown");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("could not be identified")),
        "{:?}",
        finding.notes
    );
    // A warning even for a required check: the engine adds nothing.
    assert_eq!(status_of("distro-unknown", None), Status::Warn);
}

#[test]
fn an_id_like_match_is_a_hint_and_never_applies_the_entry() {
    let run = run_case("distro-like");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.contains("no distro_min entry for `rocky`")
            && finding.message.contains("ID_LIKE"),
        "{}",
        finding.message
    );
    assert!(finding.expected.get("applied").is_none());
}

#[test]
fn a_distribution_the_spec_does_not_list_has_no_minimum() {
    let run = run_case("distro-not-listed");
    assert_eq!(run.finding().level, Level::Pass);
    assert_eq!(
        run.finding().message,
        "Kernel `5.15.0-91-generic` has no minimum in the spec for this OS."
    );
}

#[test]
fn modules_are_found_under_usr_lib_modules_and_zstd_names() {
    let run = run_case("usr-lib-modules-zst");
    assert_eq!(
        run.finding().observed["modules"]["br_netfilter"],
        "available"
    );
    let reads: Vec<&str> = run
        .log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Read)
        .filter_map(|a| a.fields.get("path").and_then(Value::as_str))
        .collect();
    assert!(
        reads.contains(&"/lib/modules/6.8.0-1021-aws/modules.dep"),
        "{reads:?}"
    );
    assert!(
        reads.contains(&"/usr/lib/modules/6.8.0-1021-aws/modules.dep"),
        "{reads:?}"
    );
    assert!(
        reads.contains(&"/usr/lib/modules/6.8.0-1021-aws/modules.builtin"),
        "{reads:?}"
    );
}

#[test]
fn the_release_falls_back_to_proc_when_uname_fails() {
    let run = run_case("uname-fallback");
    assert_eq!(run.finding().level, Level::Pass);
    assert_eq!(run.finding().observed["release"], "5.14.0-362.el9.x86_64");
}

#[test]
fn a_hostile_release_reads_no_module_file_and_leaves_no_directory() {
    let run = run_case("hostile-release");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.observed["modules"]["br_netfilter"], "unknown");
    for action in &run.log.actions {
        let path = action
            .fields
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(!path.contains(".."), "{path}");
        assert!(!path.starts_with("/lib/modules/"), "{path}");
        assert_ne!(action.outcome, ActionOutcome::Denied, "{path}");
    }
}

#[test]
fn only_the_sources_the_spec_needs_are_read() {
    // min and distro_min only: no module file and no BTF stat.
    let run = run_case("distro-min-overrides");
    for action in &run.log.actions {
        let path = action
            .fields
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(!path.contains("modules") && !path.contains("btf"), "{path}");
    }
    // Modules alone read no BTF file, and BTF alone reads no module file.
    let run = run_case("btf-missing");
    for action in &run.log.actions {
        let path = action
            .fields
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(!path.contains("modules"), "{path}");
    }
    let run = run_case("module-absent");
    for action in &run.log.actions {
        let path = action
            .fields
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(!path.contains("btf"), "{path}");
    }
}

#[test]
fn the_fix_follows_the_distribution_read_from_os_release() {
    // The spec has no distro_min, but the machine is RHEL, so the fix names dnf.
    let absent = run_case("module-absent");
    let fix = absent.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("dnf install kernel-modules-extra"), "{fix}");
    // Debian 11 gets apt.
    let below = run_case("upstream-below");
    let fix = below.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("apt full-upgrade"), "{fix}");
}

#[test]
fn a_run_stays_inside_the_manifest_and_makes_no_command_or_connection() {
    for (case, _) in CASES {
        let run = run_case(case);
        assert!(run.outcome().is_ok(), "{case}: {:?}", run.outcome());
        for action in &run.log.actions {
            assert!(
                matches!(
                    action.kind,
                    ActionKind::Native | ActionKind::Read | ActionKind::Stat
                ),
                "{case}: {:?}",
                action.kind
            );
            if action.kind == ActionKind::Native {
                assert_eq!(
                    action.fields.get("api").and_then(Value::as_str),
                    Some("uname"),
                    "{case}"
                );
            }
        }
        assert_within_manifest(case, &INFO, &run.log);
    }
    assert!(INFO.needs.is_empty() && INFO.wants.is_empty());
    assert!(INFO.statfs.is_empty() && INFO.commands.is_empty());
    assert!(INFO.env.is_empty() && INFO.peers.is_empty());
}

#[test]
fn every_fix_in_every_case_passes_the_fix_text_audit() {
    for (case, _) in CASES {
        let run = run_case(case);
        let finding = run.finding();
        for text in finding.fix.iter().chain(&finding.notes) {
            if let Err(error) = rdy_engine::fixtext::check(text) {
                panic!("{case}: fix text breaks the allow-list: {error}\n{text}");
            }
            assert!(!text.contains('\u{2014}'), "{case}: no em dash: {text}");
        }
        assert!(!finding.message.contains('\u{2014}'), "{case}");
    }
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("the remediation breaks the allow-list: {error}");
    }
}

#[test]
fn on_macos_and_windows_the_check_says_it_has_no_source() {
    let fixture = load("pass");
    for os in [Os::Macos, Os::Windows] {
        let test_run = TestRun::for_fixture(&fixture);
        let ctx = test_run.context_for(&INFO, "host.kernel", os, Vec::<Need>::new());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime");
        let check = kernel(&entry_of("pass"));
        let outcome = runtime.block_on(check.run(&ctx));
        assert!(
            matches!(outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {outcome:?}"
        );
        assert!(test_run.action_log().actions.is_empty());
    }
}
