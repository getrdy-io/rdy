//! Runs the built `rdy` binary and checks the version line (ADR 0011, 07 section 4.3).

use std::path::Path;
use std::process::{Command, Output};

fn rdy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"))
}

/// The 7-character commit of `HEAD` when this is a git checkout of the workspace, so the build had
/// a commit to embed. `None` for a packaged tree or a checkout that is not this workspace.
fn expected_commit() -> Option<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if dir.join(".cargo_vcs_info.json").exists() {
        return None;
    }
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        out.status.success().then(|| text.trim().to_string())
    };
    let top = Path::new(&git(&["rev-parse", "--show-toplevel"])?)
        .canonicalize()
        .ok()?;
    if top != dir.join("../..").canonicalize().ok()? {
        return None;
    }
    let full = git(&["rev-parse", "HEAD"])?;
    (full.len() >= 7).then(|| full[..7].to_string())
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
    let want = expected_commit();
    if rest.is_empty() {
        assert!(
            want.is_none(),
            "a git build must embed commit and date: {line:?}"
        );
        return;
    }
    let inner = rest
        .strip_prefix(" (")
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("bad suffix after the version: {line:?}"));
    let (commit, date) = match inner.split_once(' ') {
        Some((commit, date)) => (commit, Some(date)),
        None => (inner, None),
    };
    assert!(
        commit.len() == 7 && commit.bytes().all(|c| c.is_ascii_hexdigit()),
        "commit is not 7 hex digits: {line:?}"
    );
    if let Some(want) = want {
        assert_eq!(commit, want, "commit is not HEAD: {line:?}");
        assert!(date.is_some(), "a git build must embed the date: {line:?}");
    }
    if let Some(date) = date {
        assert!(is_date(date), "date is not YYYY-MM-DD: {line:?}");
    }
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
