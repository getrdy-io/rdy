//! `--out-dir` and `--no-report` through the real command tree.

use std::fs;
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
fn an_out_dir_that_cannot_be_used_is_an_exit_70_error_with_the_documented_fix() {
    let parent = tempfile::tempdir().expect("temp dir");
    let missing = parent.path().join("missing");
    let given = missing.to_str().expect("utf8");
    let err = open_report_dir(&args(&["--out-dir", given]), "acme", now()).expect_err("fails");
    assert_eq!(err.code(), ErrorCode::ReportWrite);
    assert_eq!(err.exit_code().code(), 70);
    assert!(
        err.to_string()
            .starts_with(&format!("cannot create the report folder {given}")),
        "{err}"
    );
    assert!(err.to_string().ends_with("(no such file)"), "{err}");
    assert_eq!(
        err.hint(),
        "use --out-dir <a folder you can write to>, or --no-report to skip the files"
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

#[test]
fn the_default_parent_is_the_current_folder() {
    assert!(args(&[]).out_dir.is_none());
    assert_eq!(default_parent(), Path::new("."));
}
