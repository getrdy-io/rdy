//! The two banners of 01 section 4.7 on a real `rdy run` (M1-130): the exact text, the place (before
//! the header and the first check, and again directly above the verdict) and the page.
//!
//! `rdy run` writes no HTML until M1-181. Until then the page is proved by rendering the report of the
//! run, as the report writer will; M1-181 proves the run-to-file path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use rdy_cli::RunHooks;
use rdy_cli::style::{StyleEnv, write_styled};
use rdy_engine::redact::{Redactor, TagKey};
use rdy_spec::result::Report;

mod common;

/// The short fingerprint of `tests/fixtures/signed/acme-platform.pub`: first eight, last four.
const FIXTURE_SHORT: &str = "5214b48f...7e4a";

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn hooks() -> RunHooks {
    let mut hooks = RunHooks::default();
    hooks.clock = Some(UNIX_EPOCH + Duration::from_millis(1_804_587_302_123));
    hooks.run_id = Some("00000000-0000-4000-8000-000000000001".to_owned());
    hooks.stderr_terminal = Some(false);
    hooks.stderr_columns = Some(100);
    hooks.style_env = Some(StyleEnv::default());
    hooks
}

fn call_with(hooks: RunHooks, args: &[&str]) -> Ran {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = runtime
        .block_on(rdy_cli::run(
            argv,
            Arc::new(common::unprivileged()),
            hooks,
            &mut out,
            &mut err,
        ))
        .code();
    Ran {
        code,
        stdout: String::from_utf8(out).unwrap_or_else(|e| panic!("stdout: {e}")),
        stderr: String::from_utf8(err).unwrap_or_else(|e| panic!("stderr: {e}")),
    }
}

fn call(args: &[&str]) -> Ran {
    call_with(hooks(), args)
}

fn signed() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signed")
}

fn spec_text(dir: &Path) -> String {
    dir.join("acme-platform.yaml")
        .to_string_lossy()
        .into_owned()
}

fn key_text(dir: &Path) -> String {
    dir.join("acme-platform.pub").to_string_lossy().into_owned()
}

/// Removes colour codes.
fn plain(text: &str) -> String {
    let mut out = Vec::new();
    write_styled(&mut out, false, text).unwrap_or_else(|e| panic!("{e}"));
    String::from_utf8(out).unwrap_or_else(|e| panic!("{e}"))
}

/// Checks the place of the banner in `stderr` (colour codes removed): it opens the output, a blank
/// line and the header follow, the header comes before the first check, and the title comes again
/// directly above the verdict line, which is the last.
fn assert_placed(stderr: &str, banner: &str, title: &str) {
    let stderr = plain(stderr);
    let stderr = stderr.as_str();
    assert!(stderr.starts_with(&format!("{banner}\nrdy ")), "{stderr}");
    let header = stderr
        .find("\nrdy 0.")
        .unwrap_or_else(|| panic!("{stderr}"));
    let first_check = stderr
        .find("host.cpu")
        .unwrap_or_else(|| panic!("no check line: {stderr}"));
    assert!(banner.len() <= header && header < first_check, "{stderr}");
    assert_eq!(stderr.matches(title).count(), 2, "{stderr}");
    let lines: Vec<&str> = stderr.lines().collect();
    let last = lines.len() - 1;
    assert_eq!(lines[last - 1], title, "{stderr}");
    assert!(lines[last].contains("READY"), "{stderr}");
}

/// One way to run: the extra arguments and how the hooks differ.
struct Variant {
    name: &'static str,
    extra: &'static [&'static str],
    set: fn(&mut RunHooks),
}

const NO_COLOR_WITH_ALWAYS: fn(&mut RunHooks) = |hooks| {
    hooks.style_env = Some(StyleEnv::from_lookup(|name| {
        (name == "NO_COLOR").then(|| OsString::from("1"))
    }));
};

fn variants() -> Vec<Variant> {
    vec![
        Variant {
            name: "json",
            extra: &["--json"],
            set: |_| {},
        },
        Variant {
            name: "human",
            extra: &[],
            set: |_| {},
        },
        Variant {
            name: "quiet",
            extra: &["--quiet"],
            set: |_| {},
        },
        Variant {
            name: "colour always",
            extra: &["--color", "always"],
            set: |_| {},
        },
        Variant {
            name: "NO_COLOR with colour always",
            extra: &["--color", "always"],
            set: NO_COLOR_WITH_ALWAYS,
        },
        Variant {
            name: "20 columns",
            extra: &[],
            set: |hooks| hooks.stderr_columns = Some(20),
        },
    ]
}

/// Runs `args` once per variant and checks the banner in each. Returns the output of the `json` one.
fn run_each(args: &[&str], banner: &str, title: &str) -> Ran {
    let mut json = None;
    for variant in variants() {
        let mut hooks = hooks();
        (variant.set)(&mut hooks);
        let all: Vec<&str> = args.iter().chain(variant.extra).copied().collect();
        let ran = call_with(hooks, &all);
        assert!(ran.code <= 2, "{}: {}", variant.name, ran.stderr);
        // Colour on or off, the banner and its place are the same.
        assert_placed(&ran.stderr, banner, title);
        if variant.name == "json" {
            json = Some(ran);
        }
    }
    json.unwrap_or_else(|| panic!("no json variant"))
}

fn report_of(stdout: &str) -> Report {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("stdout is not a Report ({e})"))
}

fn page_of(report: Report) -> String {
    let redactor = Redactor::new(TagKey::fixed([5; 32]));
    let redacted = redactor
        .redact_report(report)
        .unwrap_or_else(|e| panic!("redact: {e}"));
    rdy_engine::report::render_html(&redacted).unwrap_or_else(|e| panic!("render: {e}"))
}

#[test]
fn an_unsigned_run_prints_its_banner_before_the_first_check_and_again_above_the_verdict() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("acme-platform.yaml");
    std::fs::copy(signed().join("acme-platform.yaml"), &spec)
        .unwrap_or_else(|e| panic!("copy: {e}"));
    let spec = spec.to_string_lossy().into_owned();
    let banner = format!(
        "WARNING: UNSIGNED SPEC\n\
         {spec} has no signature. rdy cannot tell who wrote it or whether it was changed.\n\
         The spec decides which files rdy reads and which hosts it contacts.\n\
         Run it only if you wrote it yourself or got it from the vendor in a way you trust.\n\
         Every report from this run is marked UNSIGNED SPEC.\n"
    );
    let ran = run_each(
        &[
            "run",
            &spec,
            "--allow-unsigned",
            "--no-report",
            "--no-network",
        ],
        &banner,
        "WARNING: UNSIGNED SPEC",
    );
    // The page of the same report carries it too (the file path is M1-181's).
    let page = page_of(report_of(&ran.stdout));
    assert!(page.contains("WARNING: UNSIGNED SPEC"), "{page}");
    assert!(page.contains("This report is marked UNSIGNED SPEC."));
}

#[test]
fn a_key_run_prints_key_not_pinned_exactly_before_the_first_check_and_again_above_the_verdict() {
    let dir = signed();
    let (spec, key) = (spec_text(&dir), key_text(&dir));
    let banner = format!(
        "WARNING: KEY NOT PINNED\n\
         This spec was checked with a key given on the command line (fingerprint {FIXTURE_SHORT}).\n\
         rdy cannot tell whose key that is.\n\
         Every report from this run is marked KEY NOT PINNED.\n"
    );
    let ran = run_each(
        &["run", &spec, "--key", &key, "--no-report", "--no-network"],
        &banner,
        "WARNING: KEY NOT PINNED",
    );
    // Every page of the run carries it.
    let page = page_of(report_of(&ran.stdout));
    assert!(page.contains("WARNING: KEY NOT PINNED"), "{page}");
    assert!(page.contains("This report is marked KEY NOT PINNED."));
    assert!(!page.contains("UNSIGNED SPEC"));
}

/// 01 4.7: no hint, fix line or error message names the flags. The one place `--key` may appear is the
/// `rdy trust add` command line.
fn assert_no_flag_hint(text: &str) {
    assert!(!text.contains("--allow-unsigned"), "{text}");
    for line in text.lines().filter(|line| line.contains("--key")) {
        assert!(line.contains("trust add"), "{line}");
    }
}

#[test]
fn a_run_with_no_override_and_no_signature_prints_no_banner_and_no_flag_name() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("acme-platform.yaml");
    std::fs::copy(signed().join("acme-platform.yaml"), &spec)
        .unwrap_or_else(|e| panic!("copy: {e}"));
    let spec = spec.to_string_lossy().into_owned();
    let ran = call(&["run", &spec, "--no-report"]);
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    assert!(!ran.stderr.contains("WARNING"), "{}", ran.stderr);
    assert_no_flag_hint(&ran.stderr);
    // The same with `--json`: the hint is on stdout, in the error object.
    let ran = call(&["run", &spec, "--no-report", "--json"]);
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    let doc: serde_json::Value = serde_json::from_str(&ran.stdout)
        .unwrap_or_else(|e| panic!("stdout is not an error object ({e}): {}", ran.stdout));
    assert_eq!(doc["error"]["code"], "spec_unsigned");
    let fix = doc["error"]["fix"].as_str().unwrap_or_default();
    assert!(fix.contains(".minisig"), "{fix}");
    assert_no_flag_hint(fix);
    assert_no_flag_hint(doc["error"]["message"].as_str().unwrap_or_default());
    assert_no_flag_hint(&ran.stderr);
}

/// 07 section 4.1: files that cannot be written after the verdict. The call site tells
/// `fail_after_verdict` that the document is already on stdout, so a `--json` run leaves one document
/// on stdout and the plain note on stderr.
#[test]
fn a_json_run_whose_files_cannot_be_written_has_one_document_and_a_note() {
    let dir = signed();
    let (spec, key) = (spec_text(&dir), key_text(&dir));
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let mut hooks = hooks();
    hooks.fail_files = true;
    let ran = call_with(
        hooks,
        &[
            "run",
            &spec,
            "--key",
            &key,
            "--no-network",
            "--json",
            "--out-dir",
            &out.path().to_string_lossy(),
        ],
    );
    assert_eq!(ran.code, 70, "{}", ran.stderr);
    // One document, the Report as printed before the files.
    let report = report_of(&ran.stdout);
    assert!(report.complete);
    // The note is a `note:` line, and the only `error:` is the real one, with its fix.
    let note =
        "note: report files not written. The JSON on stdout is complete but the exit code is 70.\n";
    assert_eq!(ran.stderr.matches(note).count(), 1, "{}", ran.stderr);
    assert_eq!(ran.stderr.matches("error:").count(), 1, "{}", ran.stderr);
    let at_note = ran.stderr.find(note).expect("the note is printed");
    let at_error = ran
        .stderr
        .find("error: cannot write")
        .expect("the error is printed");
    assert!(at_note < at_error, "{}", ran.stderr);
    assert!(ran.stderr.contains("\nfix: "), "{}", ran.stderr);
    // No leftover folder.
    assert_eq!(std::fs::read_dir(out.path()).map_or(0, Iterator::count), 0);
}

#[test]
fn without_json_a_failed_file_write_leaves_stdout_empty_and_prints_no_note() {
    let dir = signed();
    let (spec, key) = (spec_text(&dir), key_text(&dir));
    let out = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let mut hooks = hooks();
    hooks.fail_files = true;
    let ran = call_with(
        hooks,
        &[
            "run",
            &spec,
            "--key",
            &key,
            "--no-network",
            "--out-dir",
            &out.path().to_string_lossy(),
        ],
    );
    assert_eq!(ran.code, 70, "{}", ran.stderr);
    assert!(ran.stdout.is_empty(), "{}", ran.stdout);
    assert!(!ran.stderr.contains("note:"), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("error: cannot write the report files"),
        "{}",
        ran.stderr
    );
}
