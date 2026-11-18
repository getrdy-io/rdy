//! SIGINT and SIGTERM at a password prompt (M1-058, Unix only).
//!
//! The prompt switches echo and the signal keys off, so a signal sent from outside (`kill`) would leave
//! the user's shell with echo off if nothing put the terminal back. This runs `rdy spec keygen` on a
//! pty, waits for the password prompt, sends the signal once and expects the two-line error, exit 70
//! and a terminal with echo, canonical mode and the signal keys on again. Windows has no pty test.
#![cfg(unix)]
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, PoisonError};

use rexpect::process::WaitStatus;
use rexpect::session::PtySession;
use rustix::process::{Pid, Signal};

const TIMEOUT_MS: u64 = 30_000;

/// One test at a time within this binary: rexpect forks.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Runs `rdy spec keygen k` on a pty with echo switched on. An inner shell writes its
/// own pid to `pid_file` and then execs rdy, so the pid is rdy's. Stdout goes to `out_file`. After rdy
/// ends, the outer shell prints the terminal settings and exits with rdy's code.
fn on_pty(dir: &Path, pid_file: &Path, out_file: &Path) -> PtySession {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(
            "stty echo; \
             sh -c 'echo $$ > \"$0\"; out=$1; rdy=$2; shift 2; exec \"$rdy\" \"$@\" > \"$out\"' \"$PIDF\" \"$OUTF\" \"$RDY\" spec keygen k; \
             code=$?; echo STTY-BEGIN; stty -a; echo STTY-END; exit $code",
        )
        .current_dir(dir)
        .env("PIDF", pid_file)
        .env("OUTF", out_file)
        .env("RDY", env!("CARGO_BIN_EXE_rdy"))
        .env_remove("RDY_KEY_PASSWORD")
        .env_remove("RDY_PROGRESS");
    rexpect::session::spawn_command(cmd, Some(TIMEOUT_MS)).expect("spawn rdy on a pty")
}

fn exit_code(session: &PtySession) -> i32 {
    match session.process().wait().expect("wait") {
        WaitStatus::Exited(_, code) => code,
        other => panic!("child did not exit normally: {other:?}"),
    }
}

/// The terminal flags from the `stty -a` block in `output`.
fn stty_flags(output: &str) -> HashSet<String> {
    let block = output
        .split("STTY-BEGIN")
        .nth(1)
        .and_then(|rest| rest.split("STTY-END").next())
        .unwrap_or_else(|| panic!("no stty output in {output:?}"));
    block
        .split(|c: char| c.is_whitespace() || c == ';')
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

fn assert_terminal_restored(output: &str) {
    let flags = stty_flags(output);
    for on in ["echo", "icanon", "isig"] {
        assert!(flags.contains(on), "{on} is not on: {output:?}");
        assert!(
            !flags.contains(&format!("-{on}")),
            "-{on} is set: {output:?}"
        );
    }
}

/// Interrupts the prompt with `signal` and returns what the terminal showed and the stdout file.
fn interrupt_prompt(signal: Signal) -> (String, i32, String, tempfile::TempDir) {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("pid");
    let out_file = dir.path().join("stdout.txt");
    let mut session = on_pty(dir.path(), &pid_file, &out_file);
    session
        .exp_string("Password for the new secret key (input hidden): ")
        .expect("the password prompt");
    // Something typed first: the signal must not leave it in any output.
    session.send("half-typed-CANARY").expect("send");
    std::thread::sleep(std::time::Duration::from_millis(200));
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    rustix::process::kill_process(Pid::from_raw(pid).expect("pid"), signal).expect("signal");
    let seen = session.exp_eof().expect("eof");
    let code = exit_code(&session);
    let stdout = std::fs::read_to_string(&out_file).unwrap_or_default();
    (seen, code, stdout, dir)
}

fn check_text_run(signal: Signal) {
    let (seen, code, stdout, dir) = interrupt_prompt(signal);
    assert_eq!(code, 70, "{seen}");
    assert!(
        seen.contains("\r\nerror: interrupted\r\nfix: run the command again\r\n"),
        "{seen:?}"
    );
    assert!(!seen.contains("CANARY"), "typed text was shown: {seen:?}");
    assert_eq!(stdout, "");
    assert_terminal_restored(&seen);
    assert!(!dir.path().join("k.key").exists());
}

#[test]
fn sigint_at_a_password_prompt_restores_the_terminal_and_exits_70() {
    check_text_run(Signal::INT);
}

#[test]
fn sigterm_at_a_password_prompt_restores_the_terminal_and_exits_70() {
    check_text_run(Signal::TERM);
}

/// Core dumps are off while rdy waits at a prompt (security review S3): the exit can end in SIGABRT
/// (the 1 s fallback), and a core file would hold secrets. Linux only: it reads `/proc/<pid>/limits`.
#[cfg(target_os = "linux")]
#[test]
fn the_core_file_limit_is_zero_while_rdy_waits() {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("pid");
    let out_file = dir.path().join("stdout.txt");
    let mut session = on_pty(dir.path(), &pid_file, &out_file);
    session
        .exp_string("Password for the new secret key (input hidden): ")
        .expect("the password prompt");
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).expect("limits");
    let line = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .expect("a core file size line");
    let numbers: Vec<&str> = line.split_whitespace().skip(4).take(2).collect();
    assert_eq!(numbers, ["0", "0"], "{line}");
    rustix::process::kill_process(Pid::from_raw(pid).expect("pid"), Signal::TERM).expect("signal");
    let _ = session.exp_eof();
}
