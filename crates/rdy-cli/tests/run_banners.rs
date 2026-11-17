//! The two banners of 01 section 4.7 on a real `rdy run` (M1-130): the exact text, the place (before
//! the header and the first check, and again directly above the verdict) and the page.
//!
//! `rdy run` writes no HTML until M1-181. Until then the page is proved by rendering the report of the
//! run, as the report writer will; M1-181 proves the run-to-file path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use rdy_cli::RunHooks;
use rdy_engine::redact::{Redactor, TagKey};
use rdy_spec::result::Report;

mod common;

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
    hooks.style_env = Some(rdy_cli::style::StyleEnv::default());
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

/// Checks the place of the banner in `stderr`: it opens the output, a blank line and the header
/// follow, the header comes before the first check, and the title comes again directly above the
/// verdict line, which is the last.
fn assert_placed(stderr: &str, banner: &str, title: &str) {
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
    let ran = call(&[
        "run",
        &spec,
        "--allow-unsigned",
        "--no-report",
        "--no-network",
        "--json",
    ]);
    assert!(ran.code <= 2, "{}", ran.stderr);
    let banner = format!(
        "WARNING: UNSIGNED SPEC\n\
         {spec} has no signature. rdy cannot tell who wrote it or whether it was changed.\n\
         The spec decides which files rdy reads and which hosts it contacts.\n\
         Run it only if you wrote it yourself or got it from the vendor in a way you trust.\n\
         Every report from this run is marked UNSIGNED SPEC.\n"
    );
    assert_placed(&ran.stderr, &banner, "WARNING: UNSIGNED SPEC");
    // The page of the same report carries it too (the file path is M1-181's).
    let page = page_of(report_of(&ran.stdout));
    assert!(page.contains("WARNING: UNSIGNED SPEC"), "{page}");
    assert!(page.contains("This report is marked UNSIGNED SPEC."));
}

#[test]
fn a_key_run_prints_key_not_pinned_exactly_before_the_first_check_and_again_above_the_verdict() {
    let dir = signed();
    let (spec, key) = (spec_text(&dir), key_text(&dir));
    let ran = call(&[
        "run",
        &spec,
        "--key",
        &key,
        "--no-report",
        "--no-network",
        "--json",
    ]);
    assert!(ran.code <= 2, "{}", ran.stderr);
    // The fingerprint is the first eight and the last four characters, as the report holds it.
    let report = report_of(&ran.stdout);
    let full = report.signature.key_fingerprint.clone().unwrap_or_default();
    assert!(full.len() > 12, "{full}");
    let short = format!("{}...{}", &full[..8], &full[full.len() - 4..]);
    let banner = format!(
        "WARNING: KEY NOT PINNED\n\
         This spec was checked with a key given on the command line (fingerprint {short}).\n\
         rdy cannot tell whose key that is.\n\
         Every report from this run is marked KEY NOT PINNED.\n"
    );
    assert_placed(&ran.stderr, &banner, "WARNING: KEY NOT PINNED");
    // Every page of the run carries it.
    let page = page_of(report);
    assert!(page.contains("WARNING: KEY NOT PINNED"), "{page}");
    assert!(page.contains("This report is marked KEY NOT PINNED."));
    assert!(!page.contains("UNSIGNED SPEC"));
}

#[test]
fn a_run_with_no_override_and_no_signature_prints_no_banner_and_no_flag_name() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("acme-platform.yaml");
    std::fs::copy(signed().join("acme-platform.yaml"), &spec)
        .unwrap_or_else(|e| panic!("copy: {e}"));
    let ran = call(&["run", &spec.to_string_lossy(), "--no-report"]);
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    assert!(!ran.stderr.contains("WARNING"), "{}", ran.stderr);
    // 01 4.7: no fix line names the flag that would allow the run.
    assert!(!ran.stderr.contains("--allow-unsigned"), "{}", ran.stderr);
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
    assert!(
        ran.stderr.find(note) < ran.stderr.find("error: cannot write"),
        "{}",
        ran.stderr
    );
    assert!(ran.stderr.contains("\nfix: "), "{}", ran.stderr);
    // No leftover folder.
    assert_eq!(std::fs::read_dir(out.path()).map_or(0, Iterator::count), 0);
}
