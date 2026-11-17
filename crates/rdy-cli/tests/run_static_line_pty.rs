//! The static "Running N checks..." line on a pty (M1-088, 07 section 3, Unix only).
//!
//! The built `rdy` runs the quickstart spec offline in a pseudo terminal. The line shows before the
//! first check and is cleared before the check list, so the final screen holds no trace of it. A pipe,
//! `--quiet`, `--progress never` and `TERM=dumb` print nothing. No example binary is built: the test
//! runs `rdy` itself, so it needs no entry in the `pty-probe` nextest group.
#![cfg(unix)]
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

use rexpect::session::spawn_command;

mod common;

const TIMEOUT_MS: u64 = 60_000;

/// One pty test at a time within this binary: rexpect forks.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn quickstart() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs/acme-quickstart.yaml")
}

fn command(extra: &[&str], term: &str) -> (Command, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.arg("run")
        .arg(quickstart())
        .args(["--allow-unsigned", "--no-network", "--color", "never"])
        .args(["--out-dir"])
        .arg(dir.path())
        .args(extra)
        .current_dir(dir.path())
        .env("TERM", term)
        .env_remove("RUST_LOG")
        .env_remove("RDY_PROGRESS");
    (cmd, dir)
}

/// What the terminal shows after `rdy` ends, as raw bytes in order.
fn on_pty(extra: &[&str], term: &str) -> String {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let (cmd, _dir) = command(extra, term);
    let mut session = spawn_command(cmd, Some(TIMEOUT_MS)).expect("spawn rdy on a pty");
    session.exp_eof().expect("eof")
}

/// Plays carriage returns on `text` the way a terminal does and returns the lines left on screen.
fn screen(text: &str) -> Vec<String> {
    text.split('\n')
        .map(|line| {
            let mut cells: Vec<char> = Vec::new();
            let mut col = 0;
            for c in line.chars() {
                if c == '\r' {
                    col = 0;
                } else {
                    if col < cells.len() {
                        cells[col] = c;
                    } else {
                        cells.push(c);
                    }
                    col += 1;
                }
            }
            cells.into_iter().collect::<String>().trim_end().to_owned()
        })
        .collect()
}

/// The index of `Running N check(s)...` in `text`, with its length.
fn static_line(text: &str) -> Option<(usize, usize)> {
    let at = text.find("Running ")?;
    let rest = &text[at..];
    let end = rest.find("...")? + 3;
    let line = &rest[..end];
    let words: Vec<&str> = line.trim_end_matches("...").split(' ').collect();
    let ok = words.len() == 3
        && words[1].chars().all(|c| c.is_ascii_digit())
        && matches!(words[2], "check" | "checks");
    ok.then_some((at, end))
}

#[test]
fn the_line_shows_before_the_first_check_and_leaves_no_trace() {
    let seen = on_pty(&[], "xterm");
    let (at, len) = static_line(&seen).unwrap_or_else(|| panic!("no static line in {seen:?}"));
    let after = &seen[at + len..];
    // Cleared at once: a carriage return, as many spaces as the line, and a carriage return.
    let clear = format!("\r{}\r", " ".repeat(len));
    assert!(after.starts_with(&clear), "{after:?}");
    // The check list comes after the clear, and the line appears once.
    let list = after.find("checks").or_else(|| after.find("READY"));
    assert!(list.is_some_and(|i| i >= clear.len()), "{after:?}");
    assert_eq!(seen.matches("Running ").count(), 1, "{seen:?}");
    // The final screen has no trace of it, and it has no escape sequence for the clear.
    for line in screen(&seen) {
        assert!(!line.contains("Running"), "{line:?}");
    }
    assert!(!seen[at..at + len + clear.len()].contains('\u{1b}'));
}

#[test]
fn quiet_progress_never_and_a_dumb_terminal_print_nothing() {
    for (extra, term) in [
        (&["--quiet"][..], "xterm"),
        (&["--progress", "never"][..], "xterm"),
        (&[][..], "dumb"),
    ] {
        let seen = on_pty(extra, term);
        assert!(!seen.contains("Running"), "{extra:?} TERM={term}: {seen:?}");
    }
}

#[test]
fn a_pipe_prints_nothing() {
    let (mut cmd, _dir) = command(&[], "xterm");
    let out = common::quiet(
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run rdy"),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("Running"), "{stderr}");
    assert!(!stderr.contains('\r'), "{stderr:?}");
    assert!(out.stdout.is_empty());
}
