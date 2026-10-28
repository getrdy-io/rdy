//! Runs the built `rdy` binary and checks the version line (ADR 0011, 07 section 4.3).

use std::process::{Command, Output};

fn rdy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"))
}

/// True when this checkout is a git work tree, so the build had a commit to embed.
fn built_from_git() -> bool {
    Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

/// The line is `rdy <version>` and, when built from git, `rdy <version> (<commit7> <date>)`.
fn assert_version_line(line: &str) {
    let version = env!("CARGO_PKG_VERSION");
    let rest = line
        .strip_prefix("rdy ")
        .unwrap_or_else(|| panic!("line does not start with `rdy `: {line:?}"));
    let rest = rest
        .strip_prefix(version)
        .unwrap_or_else(|| panic!("line does not carry {version}: {line:?}"));
    if rest.is_empty() {
        assert!(
            !built_from_git(),
            "a git build must embed commit and date: {line:?}"
        );
        return;
    }
    let inner = rest
        .strip_prefix(" (")
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("bad suffix after the version: {line:?}"));
    let (commit, date) = inner
        .split_once(' ')
        .unwrap_or_else(|| panic!("want `<commit> <date>`: {line:?}"));
    assert!(
        commit.len() == 7 && commit.bytes().all(|c| c.is_ascii_hexdigit()),
        "commit is not 7 hex digits: {line:?}"
    );
    assert!(is_date(date), "date is not YYYY-MM-DD: {line:?}");
}

fn assert_prints_version_line(args: &[&str]) {
    let out = rdy(args);
    assert!(out.status.success(), "rdy {args:?} failed: {out:?}");
    assert!(
        out.stderr.is_empty(),
        "rdy {args:?} wrote to stderr: {out:?}"
    );
    let stdout =
        String::from_utf8(out.stdout).unwrap_or_else(|e| panic!("stdout is not UTF-8: {e}"));
    let line = stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("stdout does not end in a newline: {stdout:?}"));
    assert!(!line.contains('\n'), "want exactly one line: {stdout:?}");
    assert_version_line(line);
}

#[test]
fn version_command_prints_the_line() {
    assert_prints_version_line(&["version"]);
}

#[test]
fn long_version_flag_prints_the_line() {
    assert_prints_version_line(&["--version"]);
}

#[test]
fn short_version_flag_prints_the_line() {
    assert_prints_version_line(&["-V"]);
}

#[test]
fn flag_and_command_print_the_same_bytes() {
    assert_eq!(rdy(&["version"]).stdout, rdy(&["--version"]).stdout);
}
