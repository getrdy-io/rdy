//! `--out-dir` and `--no-report` through the real command tree.

use std::fs;
use std::io;
use std::time::{Duration, UNIX_EPOCH};

use clap::FromArgMatches;

use super::*;
use crate::cli::{Cli, Commands};
use crate::error::ErrorCode;

/// 2027-03-09T14:30:05Z
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_804_602_605)
}

fn args(extra: &[&str]) -> RunArgs {
    let mut argv = vec!["rdy", "run", "acme.yaml"];
    argv.extend_from_slice(extra);
    let matches = crate::command().try_get_matches_from(argv).expect("parse");
    match Cli::from_arg_matches(&matches).expect("cli").command {
        Commands::Run(run) => run,
        other => panic!("not run: {other:?}"),
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn out_dir_names_the_parent_of_the_report_folder() {
    let parent = tempfile::tempdir().expect("temp dir");
    let given = parent.path().to_str().expect("utf8");
    let out = open_report_dir(&args(&["--out-dir", given]), "acme-platform", now())
        .expect("open")
        .expect("a folder");
    assert_eq!(out.name(), "rdy-report-acme-platform-20270309T143005Z");
    assert_eq!(entries(parent.path()), [out.name()]);
}

#[test]
fn no_report_creates_nothing_and_ignores_out_dir() {
    let parent = tempfile::tempdir().expect("temp dir");
    let given = parent.path().to_str().expect("utf8");
    let out = open_report_dir(&args(&["--no-report", "--out-dir", given]), "acme", now());
    assert!(matches!(out, Ok(None)));
    assert!(entries(parent.path()).is_empty());
    // A folder that does not exist is not an error when nothing is written.
    let missing = parent.path().join("missing");
    let given = missing.to_str().expect("utf8");
    let out = open_report_dir(&args(&["--no-report", "--out-dir", given]), "acme", now());
    assert!(matches!(out, Ok(None)));
    assert!(!missing.exists());
}

#[test]
fn a_missing_out_dir_is_reported_as_the_folder_that_could_not_be_made() {
    let parent = tempfile::tempdir().expect("temp dir");
    let missing = parent.path().join("missing");
    let given = missing.to_str().expect("utf8");
    // The folder is joined with the OS separator, so the expectation is built the same way.
    let folder = missing.join("rdy-report-acme-20270309T143005Z");
    let err = open_report_dir(&args(&["--out-dir", given]), "acme", now()).expect_err("fails");
    assert_eq!(err.code(), ErrorCode::ReportWrite);
    assert_eq!(err.exit_code().code(), 70);
    assert_eq!(
        err.to_string(),
        format!(
            "cannot create the report folder {} (no such file)",
            folder.display()
        )
    );
    assert_eq!(
        err.hint(),
        "use --out-dir <a folder you can write to>, or --no-report to skip the files"
    );
}

#[cfg(unix)]
#[test]
fn a_read_only_out_dir_gives_the_exact_row_6_message_and_fix() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().expect("temp dir");
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o500)).expect("chmod");
    if fs::create_dir(parent.path().join("probe")).is_ok() {
        // root ignores the mode. The root job covers the other rows.
        eprintln!("skipped: this user can write to a 0500 folder");
        return;
    }
    let given = parent.path().to_str().expect("utf8");
    let err = open_report_dir(&args(&["--out-dir", given]), "acme", now()).expect_err("fails");
    assert_eq!(err.code(), ErrorCode::ReportWrite);
    assert_eq!(
        err.to_string(),
        format!(
            "cannot create the report folder {given}/rdy-report-acme-20270309T143005Z (permission denied)"
        )
    );
    assert_eq!(
        err.hint(),
        "use --out-dir <a folder you can write to>, or --no-report to skip the files"
    );
    assert!(entries(parent.path()).is_empty());
}

#[test]
fn every_engine_error_maps_to_its_own_reason_and_fix() {
    let shown = Path::new("/out/rdy-report-acme-20270309T143005Z");
    let map = |err| report_error(ReportStep::CreateFolder, shown, err);
    let check = |err: CliError, message: &str, fix_has: &str| {
        assert_eq!(err.code(), ErrorCode::ReportWrite);
        assert_eq!(err.to_string(), message);
        assert!(err.hint().contains(fix_has), "{}", err.hint());
    };
    check(
        map(ReportError::NotOwner {
            path: "/out/x".into(),
            owner: 0,
            euid: 1000,
        }),
        "cannot create the report folder /out/x (the folder is owned by another user)",
        "root_squash",
    );
    check(
        map(ReportError::NotPrivate {
            path: "/out/x".into(),
            mode: 0o755,
        }),
        "cannot create the report folder /out/x (the folder cannot be made private)",
        "keeps Unix permissions",
    );
    check(
        map(ReportError::NameTaken {
            parent: "/out".into(),
        }),
        "cannot create the report folder in /out (all the folder names are taken)",
        "wait a second",
    );
    check(
        map(ReportError::FileExists {
            path: "/out/x/report.json".into(),
        }),
        "cannot create the report folder /out/x/report.json (the file already exists)",
        "bug in rdy",
    );
    // An error with no path of its own shows the folder rdy meant to make.
    check(
        map(ReportError::Io {
            action: OPEN_PARENT,
            path: "/out".into(),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        }),
        "cannot create the report folder /out/rdy-report-acme-20270309T143005Z (permission denied)",
        "--out-dir",
    );
}

#[test]
fn a_product_that_would_escape_is_a_bug_message_with_no_echo() {
    let parent = tempfile::tempdir().expect("temp dir");
    let given = parent.path().to_str().expect("utf8");
    let err = open_report_dir(&args(&["--out-dir", given]), "../x", now()).expect_err("fails");
    assert_eq!(err.code(), ErrorCode::Internal);
    assert!(!err.to_string().contains("../x"));
    assert!(entries(parent.path()).is_empty());
}

#[cfg(not(windows))]
#[test]
fn the_default_parent_is_the_current_folder() {
    assert!(args(&[]).out_dir.is_none());
    assert_eq!(default_parent().expect("default"), Path::new("."));
}

/// The exit test of M1-037 through the real entry point: with no `--out-dir`, the report folder is
/// made under `%USERPROFILE%\rdy-reports`.
#[cfg(windows)]
#[test]
fn the_default_lands_under_userprofile_rdy_reports() {
    assert!(args(&[]).out_dir.is_none());
    let profile = std::path::PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE"));
    let out = open_report_dir(&args(&[]), "acme-m1-037-test", now())
        .expect("open")
        .expect("a folder");
    let expected_parent = profile.join("rdy-reports");
    assert_eq!(out.path().parent(), Some(expected_parent.as_path()));
    assert!(out.path().is_dir());
    let path = out.path().to_path_buf();
    drop(out);
    // Take away only the folder this test made.
    fs::remove_dir(&path).expect("remove the test folder");
}

#[test]
fn a_redirect_error_maps_to_a_report_write_error_with_a_fix() {
    let shown = Path::new("/out/rdy-report-acme-20270309T143005Z");
    let err = report_error(
        ReportStep::CreateFolder,
        shown,
        ReportError::NotPlainFolder {
            path: shown.to_path_buf(),
        },
    );
    assert_eq!(err.code(), ErrorCode::ReportWrite);
    assert_eq!(err.exit_code().code(), 70);
    assert!(
        err.to_string()
            .contains("a link, junction or other redirect")
    );
    assert!(err.hint().contains("Remove the link or junction"));
    let err = report_error(
        ReportStep::CreateFolder,
        Path::new(DEFAULT_LABEL),
        ReportError::NoDefaultFolder,
    );
    assert_eq!(err.code(), ErrorCode::ReportWrite);
    assert_eq!(
        err.to_string(),
        r"cannot create the report folder %USERPROFILE%\rdy-reports (USERPROFILE is not set to a full path)"
    );
}
