//! Tests for `rdy run` that need the insides of the crate: a registry of the test's own, the order of the
//! start-up steps, and the mapping of the report writer's errors.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, Need, OsSupport,
    Support, current_os,
};
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_engine::output::ReportError;
use rdy_engine::redact::{Redactor, TagKey};
use rdy_engine::report::{JsonError, json_bytes, write_json};
use rdy_engine::testing::Replay;
use rdy_spec::check::CheckParams;
use rdy_spec::result::{
    CheckResult, Host, HostOs, HostOsFamily, Identity, Producer, Report, Run, RunOptions, Severity,
    Signature, SpecRef, Status,
};
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::Value;

use crate::error::ReportStep;
use crate::error::{CliError, ErrorCode};
use crate::hooks::RunHooks;
use crate::output::report_error;

const CANARY: &str = "canary-run-cmd-token-9917";

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

const fn info(needs: &'static [Need], env: &'static [&'static str]) -> CheckInfo {
    CheckInfo {
        id: "host.cpu",
        family: "host",
        summary: "A test check.",
        meta: CheckMeta {
            title: "Test",
            remediation: "Fix it.",
        },
        needs,
        wants: &[],
        default_timeout: None,
        os: FULL,
        reads: &[],
        statfs: &[],
        env,
        commands: &[],
        peers: &[],
    }
}

/// Declares a secret-named variable and puts the secret in its message without ever reading it.
static LEAKY: CheckInfo = info(&[], &["API_TOKEN"]);
/// Needs root.
static NEEDS_ROOT: CheckInfo = info(&[Need::Root], &[]);

struct Said(&'static CheckInfo);

impl Check for Said {
    fn info(&self) -> &'static CheckInfo {
        self.0
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async { Ok(Finding::pass(format!("the check saw {CANARY}"))) })
    }
}

struct Only(&'static CheckInfo, &'static [&'static CheckInfo]);

impl Family for Only {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        self.1
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Ok(Built::new(Box::new(Said(self.0))))
    }
}

static LEAKY_LIST: [&CheckInfo; 1] = [&LEAKY];
static ROOT_LIST: [&CheckInfo; 1] = [&NEEDS_ROOT];

fn leaky_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Only(&LEAKY, &LEAKY_LIST))?;
    Ok(registry)
}

fn root_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Only(&NEEDS_ROOT, &ROOT_LIST))?;
    Ok(registry)
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n";

/// A machine that shows an ordinary user (uid 1000, no capability).
fn unprivileged() -> Replay {
    let user = [1000; 4];
    match current_os() {
        rdy_engine::check::Os::Windows => Replay::for_os(rdy_engine::check::Os::Windows),
        rdy_engine::check::Os::Macos => {
            Replay::for_os(rdy_engine::check::Os::Macos).ids(user, user)
        }
        _ => Replay::new()
            .file(
                "/proc/self/status",
                "Name:\trdy\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\n",
            )
            .file("/proc/self/auxv", {
                let mut bytes = Vec::new();
                for (key, value) in [(3_usize, 0x5555_0000_usize), (23, 0), (0, 0)] {
                    bytes.extend(key.to_ne_bytes());
                    bytes.extend(value.to_ne_bytes());
                }
                bytes
            }),
    }
}

fn call(
    machine: Replay,
    args: &[&str],
    make: fn() -> Result<Registry, RegistryError>,
) -> (u8, String, String) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = runtime.block_on(crate::run_code(
        argv,
        Arc::new(machine),
        RunHooks::default(),
        make,
        &mut out,
        &mut err,
    ));
    (
        code,
        String::from_utf8(out).expect("utf-8 stdout"),
        String::from_utf8(err).expect("utf-8 stderr"),
    )
}

// The proof that the secret is in the set before the first log event is in
// tests/run_secret_order.rs: it needs a global subscriber, which sees the threads of `spawn_blocking`.

#[test]
fn a_declared_secret_is_in_the_known_set_before_the_first_check() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let spec = dir.path().join("spec.yaml");
    std::fs::write(&spec, SPEC).expect("write the spec");
    let spec = spec.to_string_lossy().into_owned();

    let (code, stdout, stderr) = call(
        unprivileged().env("API_TOKEN", CANARY),
        &["run", &spec, "--allow-unsigned", "--json", "--no-report"],
        leaky_registry,
    );

    // The check never read the variable and put the value in its message. The value is not in the
    // report, so it was in the set before the check ran.
    assert_eq!(code, 0, "{stdout}");
    assert!(!stdout.contains(CANARY), "{stdout}");
    assert!(!stderr.contains(CANARY), "{stderr}");
    let report: Value = serde_json::from_str(&stdout).expect("the report is JSON");
    let message = report["checks"][0]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("the check saw [REDACTED:known_secret:"),
        "{message}"
    );
}

#[test]
fn a_declared_secret_the_set_refuses_ends_the_run_with_exit_70_and_never_prints_the_value() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let spec = dir.path().join("spec.yaml");
    std::fs::write(&spec, SPEC).expect("write the spec");
    let spec = spec.to_string_lossy().into_owned();
    // Five bytes: under the minimum the set takes.
    let (code, stdout, stderr) = call(
        unprivileged().env("API_TOKEN", "abcde"),
        &["run", &spec, "--allow-unsigned", "--json", "--no-report"],
        leaky_registry,
    );
    assert_eq!(code, 70, "{stderr}");
    assert!(
        stderr.starts_with("error: rdy cannot promise to keep the value of API_TOKEN"),
        "{stderr}"
    );
    assert!(!stderr.contains("abcde") && !stdout.contains("abcde"));
    let doc: Value = serde_json::from_str(&stdout).expect("an error object");
    assert_eq!(doc["error"]["code"], "internal");
}

#[test]
fn the_root_fix_names_the_spec_file_as_the_user_typed_it_quoted_for_a_shell() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let spec = dir.path().join("my spec.yaml");
    std::fs::write(&spec, SPEC).expect("write the spec");
    let typed = spec.to_string_lossy().into_owned();
    let (code, stdout, stderr) = call(
        unprivileged(),
        &["run", &typed, "--allow-unsigned", "--json", "--no-report"],
        root_registry,
    );
    assert_eq!(code, 2, "{stderr}");
    let report: Value = serde_json::from_str(&stdout).expect("the report is JSON");
    let check = &report["checks"][0];
    assert_eq!(check["skip_kind"], "missing_need");
    let fix = check["fix"].as_str().unwrap_or_default();
    if cfg!(windows) {
        // Windows has no `sudo`: the fix names no spec file at all.
        assert!(fix.starts_with("Run rdy from an elevated prompt"), "{fix}");
    } else {
        assert_eq!(fix, format!("Rerun as root: sudo rdy run '{typed}'"));
    }
    assert!(!fix.contains("<spec>"));
}

/// Counts how many times it ran.
static RAN: AtomicUsize = AtomicUsize::new(0);
static COUNTED: CheckInfo = info(&[], &[]);
static COUNTED_LIST: [&CheckInfo; 1] = [&COUNTED];

struct Counted;

impl Check for Counted {
    fn info(&self) -> &'static CheckInfo {
        &COUNTED
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async {
            RAN.fetch_add(1, Ordering::SeqCst);
            Ok(Finding::pass("ran"))
        })
    }
}

struct CountedFamily;

impl Family for CountedFamily {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &COUNTED_LIST
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Ok(Built::new(Box::new(Counted)))
    }
}

fn counted_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(CountedFamily)?;
    Ok(registry)
}

#[test]
fn a_report_folder_that_cannot_be_made_runs_no_check() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let spec = dir.path().join("spec.yaml");
    std::fs::write(&spec, SPEC).expect("write the spec");
    let spec = spec.to_string_lossy().into_owned();
    let missing = dir.path().join("no-such-folder");
    let before = RAN.load(Ordering::SeqCst);
    let (code, _, stderr) = call(
        unprivileged(),
        &[
            "run",
            &spec,
            "--allow-unsigned",
            "--out-dir",
            &missing.to_string_lossy(),
        ],
        counted_registry,
    );
    assert_eq!(code, 70, "{stderr}");
    assert_eq!(RAN.load(Ordering::SeqCst), before, "a check ran");

    // Control: with a folder that exists the same check does run.
    let (code, _, stderr) = call(
        unprivileged(),
        &["run", &spec, "--allow-unsigned", "--no-report"],
        counted_registry,
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(RAN.load(Ordering::SeqCst), before + 1);
}

// --- what the run leaves behind ---

#[test]
fn an_empty_report_folder_is_removed_and_one_with_a_file_stays() {
    let parent = tempfile::tempdir().expect("a temp dir");
    let made = |ts: &str| {
        rdy_engine::output::OutputDir::create_new(parent.path(), "acme", ts).expect("a folder")
    };

    let empty = made("20270309T101502Z");
    let empty_path = empty.path().to_owned();
    super::discard_if_empty(Some(empty));
    assert!(!empty_path.exists(), "the empty folder stayed");

    let full = made("20270309T101503Z");
    let full_path = full.path().to_owned();
    let redacted = redactor().redact_report(small_report()).expect("redacts");
    full.write_json(&redacted).expect("a file");
    super::discard_if_empty(Some(full));
    assert!(full_path.exists(), "the folder with a file went");
    assert!(std::fs::read_dir(&full_path).expect("a folder").count() > 0);

    // No folder (`--no-report`) is fine.
    super::discard_if_empty(None);
}

#[test]
fn the_access_rule_residual_note_is_for_windows_with_out_dir_and_for_every_macos_report() {
    use rdy_engine::check::Os;
    assert!(super::residual_note(Os::Windows, true).is_some());
    assert!(super::residual_note(Os::Windows, false).is_none());
    assert!(super::residual_note(Os::Macos, false).is_some());
    assert!(super::residual_note(Os::Macos, true).is_some());
    assert!(super::residual_note(Os::Linux, true).is_none());
    for note in [
        super::residual_note(Os::Windows, true),
        super::residual_note(Os::Macos, false),
    ]
    .into_iter()
    .flatten()
    {
        assert!(note.starts_with("note: "), "{note}");
        assert!(!note.contains('\u{2014}'), "{note}");
    }
}

#[test]
fn the_unsigned_warning_names_no_flag_and_one_line() {
    assert!(super::UNSIGNED_WARNING.starts_with("warning: this spec is not signed."));
    assert!(!super::UNSIGNED_WARNING.contains("--"));
    assert!(!super::UNSIGNED_WARNING.contains('\n'));
}

// --- the report writer's errors ---

/// A writer that refuses every byte.
struct Closed;

impl Write for Closed {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("the pipe is closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([3; 32]))
}

fn small_report() -> Report {
    Report::new(
        Producer::new("0.1.0", "0.1.0", "x86_64-unknown-linux-musl"),
        Run::new(
            "id",
            "2026-11-02T09:00:00.000Z",
            "2026-11-02T09:00:01.000Z",
            1000,
            RunOptions::new(8, 300_000),
        ),
        SpecRef::new("acme", "0".repeat(64), "spec.yaml", 1),
        Signature::unsigned(),
        Host::new("host-a.example", HostOs::new(HostOsFamily::Linux), "x86_64"),
        Identity::new(Some(1000), None, false),
        vec![CheckResult::new(
            "host.cpu",
            "host",
            Severity::Block,
            Status::Pass,
        )],
    )
}

fn assert_report_write(error: &CliError, message_starts: &str) {
    assert_eq!(error.code(), ErrorCode::ReportWrite, "{error:?}");
    assert_eq!(error.exit_code().code(), 70);
    let rendered = error.render();
    assert!(
        rendered.message.starts_with(message_starts),
        "{}",
        rendered.message
    );
    assert!(
        !rendered.message.contains("internal error"),
        "{}",
        rendered.message
    );
    assert!(!rendered.fix.contains("this is a bug"), "{}", rendered.fix);
    assert!(!rendered.fix.is_empty());
}

#[test]
fn a_broken_output_maps_to_report_write_with_the_writers_message() {
    let redacted = redactor().redact_report(small_report()).expect("redacts");
    let Err(json) = write_json(&redacted, &mut Closed) else {
        panic!("a closed stream took the report");
    };
    assert!(matches!(json, JsonError::Io(_)));
    let error = super::writer_error(json);
    assert_report_write(&error, "cannot write the report: the pipe is closed");
    assert_eq!(error.hint(), "check that the output is open and has room");
}

#[test]
fn a_report_over_the_cap_maps_to_report_write_with_the_writers_message_and_fix() {
    let mut report = small_report();
    let note = "a note with some words ".repeat(44);
    report.checks = (0..256)
        .map(|i| {
            let mut check = CheckResult::new("host.cpu", "host", Severity::Block, Status::Pass);
            check.key = format!("host.cpu/c{i}");
            check.notes = (0..20).map(|_| note.clone()).collect();
            check
        })
        .collect();
    let redacted = redactor().redact_report(report).expect("redacts");
    let Err(json) = json_bytes(&redacted) else {
        panic!("a 5 MiB report was written");
    };
    assert!(matches!(json, JsonError::TooLarge { .. }));

    // Through the output folder's error, as `write_json` on the folder returns it.
    let error = report_error(
        ReportStep::WriteFiles,
        std::path::Path::new("rdy-report-acme-20261030T000000Z"),
        ReportError::from(json),
    );
    assert_report_write(&error, "the report is ");
    let rendered = error.render();
    assert!(
        rendered.message.contains("over the limit of 2097152 bytes"),
        "{}",
        rendered.message
    );
    assert!(
        rendered.message.contains("host.cpu/c"),
        "{}",
        rendered.message
    );
    assert!(
        rendered.fix.starts_with("send this message to the vendor"),
        "{}",
        rendered.fix
    );
    // One error object, with the fix in its own field and not repeated in the message.
    assert!(!rendered.message.contains("Fix:"));
}

#[test]
fn the_other_writer_errors_stay_bugs() {
    let bug = report_error(
        ReportStep::WriteFiles,
        std::path::Path::new("x"),
        ReportError::from(JsonError::Serialize),
    );
    assert_eq!(bug.code(), ErrorCode::Internal);
    assert!(CliError::report_writer(&JsonError::Serialize).is_none());
}

#[test]
fn a_run_id_is_a_uuid_v4() {
    let id = super::uuid_v4().expect("random bytes");
    let parts: Vec<&str> = id.split('-').collect();
    assert_eq!(
        parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
        [8, 4, 4, 4, 12],
        "{id}"
    );
    assert!(parts[2].starts_with('4'), "{id}");
    assert!(
        matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'),
        "{id}"
    );
    assert_ne!(id, super::uuid_v4().expect("random bytes"));
}

// --- files that cannot be written after the verdict exists ---

fn write_failed() -> CliError {
    CliError::ReportWrite {
        step: ReportStep::WriteFiles,
        path: "rdy-report-acme-20261030T000000Z".to_owned(),
        reason: crate::error::IoReason::DiskFull.into(),
    }
}

fn fail(json: bool, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    super::fail_after_verdict(
        &write_failed(),
        small_report(),
        rdy_engine::redact::RuleCounts::default(),
        &redactor(),
        json,
        out,
        err,
    )
}

#[test]
fn files_that_cannot_be_written_still_print_the_report_as_incomplete_and_exit_70() {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(fail(true, &mut out, &mut err), 70);
    let stdout = String::from_utf8(out).expect("utf-8");
    let doc: Value = serde_json::from_str(&stdout).expect("stdout is the report");
    assert_eq!(doc["kind"], "Report");
    assert_eq!(doc["complete"], false);
    let stderr = String::from_utf8(err).expect("utf-8");
    assert!(
        stderr.starts_with(
            "0 blocks, 0 warnings, 1 passed\nerror: cannot write the report files to "
        ),
        "{stderr}"
    );
    assert!(stderr.contains("\nfix: make room"), "{stderr}");
}

#[test]
fn without_json_the_failure_prints_only_on_stderr() {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(fail(false, &mut out, &mut err), 70);
    assert!(out.is_empty());
    let stderr = String::from_utf8(err).expect("utf-8");
    assert!(stderr.contains("error: cannot write the report files"));
}

#[test]
fn a_report_that_cannot_be_printed_either_still_ends_with_the_error_on_stderr() {
    let mut err = Vec::new();
    assert_eq!(fail(true, &mut Closed, &mut err), 70);
    let stderr = String::from_utf8(err).expect("utf-8");
    assert!(stderr.contains("error: cannot write the report files"));
}
