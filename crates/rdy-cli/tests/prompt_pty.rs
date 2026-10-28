//! Drive the prompt helper through a real pseudo-terminal (M1-123, Unix only).
//!
//! The helper under test is `examples/prompt_probe.rs`, which uses the real `StdTerminal`.
//! Windows is covered by the scripted-terminal unit tests in `src/prompt.rs`.
#![cfg(unix)]
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, Once, PoisonError};

use rexpect::process::WaitStatus;
use rexpect::session::PtySession;

const TIMEOUT_MS: u64 = 20_000;
const SECRET: &str = "s3cret-pass-phrase-7f3a";

/// One test at a time. rexpect forks, and a fork in a busy multi-threaded process is not safe.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The probe binary. `cargo test -p rdy` builds examples next to the test binaries. A run of just
/// this test file does not, and a stale one would test old code. So build it once per run, for the
/// same profile and target. When it is fresh this takes a moment and changes nothing.
fn probe_path() -> PathBuf {
    static BUILD: Once = Once::new();
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // deps
    dir.pop(); // the profile folder: debug, release or a custom profile
    BUILD.call_once(|| build_probe(&dir));
    dir.join("examples").join("prompt_probe")
}

/// Run `cargo build --example prompt_probe` for the profile folder `dir`.
fn build_probe(dir: &Path) {
    let mut cargo = Command::new(env!("CARGO"));
    cargo.args(["build", "--quiet", "-p", "rdy", "--example", "prompt_probe"]);
    match dir.file_name().and_then(|n| n.to_str()) {
        Some("debug") | None => {}
        Some("release") => {
            cargo.arg("--release");
        }
        Some(profile) => {
            cargo.args(["--profile", profile]);
        }
    }
    // With `--target T` the folders are target/T/<profile>. A target triple has at least two
    // dashes. `CARGO_BUILD_TARGET` wins when it is set.
    let target = std::env::var("CARGO_BUILD_TARGET").ok().or_else(|| {
        let name = dir.parent()?.file_name()?.to_str()?;
        (name.matches('-').count() >= 2).then(|| name.to_string())
    });
    if let Some(target) = target {
        cargo.args(["--target", &target]);
    }
    assert!(cargo.status().expect("run cargo").success());
}

/// The probe with no terminal wiring, for the no-terminal cases.
fn probe(mode: &str) -> Command {
    let mut cmd = Command::new(probe_path());
    cmd.arg(mode).env("RDY_PROBE_EXPECT", SECRET);
    cmd
}

/// Run the probe on a pty with the terminal's echo switched ON, as a login shell has it.
///
/// rexpect starts its terminals with echo off, which would hide a helper that forgot to turn echo
/// off. `stty echo` puts it back first.
fn on_pty(mode: &str) -> PtySession {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg("stty echo && exec \"$0\" \"$@\"")
        .arg(probe_path())
        .arg(mode)
        .env("RDY_PROBE_EXPECT", SECRET);
    rexpect::session::spawn_command(cmd, Some(TIMEOUT_MS)).expect("spawn probe on a pty")
}

/// Run the probe on a pty like `on_pty`, then print the terminal settings with `stty -a` and exit
/// with the probe's exit code. This shows what state the probe left the terminal in.
fn on_pty_then_stty(mode: &str) -> PtySession {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(
            "stty echo; \"$0\" \"$@\"; code=$?; \
             echo STTY-BEGIN; stty -a; echo STTY-END; exit $code",
        )
        .arg(probe_path())
        .arg(mode)
        .env("RDY_PROBE_EXPECT", SECRET);
    rexpect::session::spawn_command(cmd, Some(TIMEOUT_MS)).expect("spawn probe on a pty")
}

/// Wait for the child and return its exit code.
fn exit_code(session: &PtySession) -> i32 {
    match session.process().wait().expect("wait") {
        WaitStatus::Exited(_, code) => code,
        other => panic!("child did not exit normally: {other:?}"),
    }
}

/// The terminal flags from the `stty -a` block in `output`, such as `echo` or `-icanon`.
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

/// The terminal is back to a normal shell state: echo, canonical mode and signal keys all on.
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

/// Answer the y/N question with `typed` and return (output after the prompt, exit code).
fn answer(typed: &str) -> (String, i32) {
    let mut session = on_pty("confirm");
    session
        .exp_string("Trust this key for acme-platform? [y/N] ")
        .expect("prompt");
    session.send_line(typed).expect("send");
    let rest = session.exp_eof().expect("eof");
    let code = exit_code(&session);
    (rest, code)
}

#[test]
fn y_and_yes_are_yes() {
    let _guard = lock();
    for typed in ["y", "yes", "Y", "YES"] {
        let (rest, code) = answer(typed);
        assert!(rest.contains("answer=true"), "{typed}: {rest:?}");
        assert_eq!(code, 0);
    }
}

#[test]
fn n_and_an_empty_line_are_no() {
    let _guard = lock();
    for typed in ["n", "no", "", "maybe"] {
        let (rest, code) = answer(typed);
        assert!(rest.contains("answer=false"), "{typed:?}: {rest:?}");
        assert_eq!(code, 0);
    }
}

#[test]
fn typed_answers_are_echoed_on_this_pty() {
    // Control for the password test: with echo on, typed text does come back.
    let _guard = lock();
    let (rest, _) = answer("yes");
    assert!(rest.starts_with("yes"), "{rest:?}");
}

#[test]
fn end_of_input_is_no() {
    let _guard = lock();
    let mut session = on_pty("confirm");
    session.exp_string("[y/N] ").expect("prompt");
    session.send_control('d').expect("ctrl-d");
    let rest = session.exp_eof().expect("eof");
    assert!(rest.contains("answer=false"), "{rest:?}");
    assert_eq!(exit_code(&session), 0);
}

#[test]
fn password_is_read_with_echo_off_and_never_appears_in_the_output() {
    let _guard = lock();
    let mut session = on_pty("password");
    let before = session
        .exp_string("Password (input hidden): ")
        .expect("prompt");
    session.send_line(SECRET).expect("send");
    let rest = session.exp_eof().expect("eof");
    let everything = format!("{before}{rest}");

    assert!(
        rest.contains(&format!("len={} match=true", SECRET.len())),
        "{rest:?}"
    );
    assert!(
        !everything.contains(SECRET),
        "the password was echoed: {everything:?}"
    );
    // Not even the start of it.
    assert!(!everything.contains(&SECRET[..4]), "{everything:?}");
    assert_eq!(exit_code(&session), 0);
}

#[test]
fn no_terminal_exits_64_with_the_fix_line() {
    let _guard = lock();
    let out = probe("confirm")
        .stdin(Stdio::null())
        .output()
        .expect("run probe");
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "error: cannot ask for confirmation because there is no terminal\n\
         fix: check the key's fingerprint with the vendor, then run again with --yes\n"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn no_terminal_with_yes_flag_is_yes() {
    let _guard = lock();
    let out = probe("confirm-yes")
        .stdin(Stdio::null())
        .output()
        .expect("run probe");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "answer=true\n");
}

#[test]
fn password_without_a_terminal_exits_64() {
    let _guard = lock();
    let out = probe("password")
        .stdin(Stdio::null())
        .output()
        .expect("run probe");
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "error: cannot ask for a password because there is no terminal\n\
         fix: use --password-file or the RDY_KEY_PASSWORD variable\n"
    );
}

#[test]
fn ctrl_c_at_the_password_prompt_restores_the_terminal_and_exits_70() {
    let _guard = lock();
    let mut session = on_pty_then_stty("password");
    session
        .exp_string("Password (input hidden): ")
        .expect("prompt");
    session.send("half-typed").expect("send");
    session.send_control('c').expect("ctrl-c");
    let rest = session.exp_eof().expect("eof");

    assert!(
        rest.contains("error: interrupted\r\nfix: run the command again"),
        "{rest:?}"
    );
    assert!(!rest.contains("half-typed"), "{rest:?}");
    assert_terminal_restored(&rest);
    assert_eq!(exit_code(&session), 70);
}

#[test]
fn ctrl_d_at_the_password_prompt_restores_the_terminal_and_exits_64() {
    let _guard = lock();
    let mut session = on_pty_then_stty("password");
    session
        .exp_string("Password (input hidden): ")
        .expect("prompt");
    session.send_control('d').expect("ctrl-d");
    let rest = session.exp_eof().expect("eof");

    assert!(rest.contains("error: no password was entered"), "{rest:?}");
    assert_terminal_restored(&rest);
    assert_eq!(exit_code(&session), 64);
}

#[test]
fn after_a_good_password_the_terminal_is_restored() {
    let _guard = lock();
    let mut session = on_pty_then_stty("password");
    session
        .exp_string("Password (input hidden): ")
        .expect("prompt");
    session.send_line(SECRET).expect("send");
    let rest = session.exp_eof().expect("eof");
    assert!(rest.contains("match=true"), "{rest:?}");
    assert!(!rest.contains(SECRET), "{rest:?}");
    assert_terminal_restored(&rest);
    assert_eq!(exit_code(&session), 0);
}

#[test]
fn backspace_edits_the_hidden_password() {
    let _guard = lock();
    let mut session = on_pty("password");
    session
        .exp_string("Password (input hidden): ")
        .expect("prompt");
    session
        .send(&format!("wrong\x7f\x7f\x7f\x7f\x7f{SECRET}\n"))
        .expect("send");
    let rest = session.exp_eof().expect("eof");
    assert!(rest.contains("match=true"), "{rest:?}");
}

#[test]
fn a_password_over_the_cap_is_refused_with_exit_64() {
    let _guard = lock();
    let mut session = on_pty_then_stty("password");
    session
        .exp_string("Password (input hidden): ")
        .expect("prompt");
    session.send_line(&"p".repeat(2000)).expect("send");
    let rest = session.exp_eof().expect("eof");
    assert!(
        rest.contains("error: the password is longer than 1024 bytes"),
        "{rest:?}"
    );
    assert_terminal_restored(&rest);
    assert_eq!(exit_code(&session), 64);
}
