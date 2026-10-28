//! `rdy spec keygen` and `rdy spec sign` at a real terminal (M1-125, Unix only).
//!
//! The password prompts of M1-123 are used, so the typed password is read with echo off and never
//! appears in the output. Windows has no pty test; the scripted-terminal unit tests cover the logic.
#![cfg(unix)]
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used)]

use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, PoisonError};

use rexpect::process::WaitStatus;
use rexpect::session::PtySession;

const TIMEOUT_MS: u64 = 60_000;
const PASSWORD: &str = "pty-pass-phrase-7f3a-CANARY";
const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n    fix: Use a bigger node.\n";

/// One test at a time. rexpect forks, and the key derivation needs 1 GiB.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Runs `rdy args` in `dir` on a pty with echo switched on, as a login shell has it. Without this
/// rexpect's terminal has echo off, which would hide a prompt that forgot to turn it off.
fn on_pty(dir: &Path, args: &[&str]) -> PtySession {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg("stty echo && exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .current_dir(dir)
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

#[test]
fn keygen_and_sign_ask_with_echo_off_and_the_password_never_shows() {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("acme-platform.yaml"), SPEC).expect("write spec");

    // keygen: two prompts, the second must match.
    let mut session = on_pty(dir.path(), &["spec", "keygen", "acme-signing"]);
    let mut seen = session
        .exp_string("Password for the new secret key (input hidden): ")
        .expect("first prompt");
    session.send_line(PASSWORD).expect("send");
    seen.push_str(
        &session
            .exp_string("Repeat the password: ")
            .expect("second prompt"),
    );
    session.send_line(PASSWORD).expect("send");
    seen.push_str(&session.exp_eof().expect("eof"));
    assert_eq!(exit_code(&session), 0, "{seen}");
    assert!(seen.contains("Wrote acme-signing.key"), "{seen}");
    assert!(seen.contains("fingerprint  "), "{seen}");
    assert!(
        !seen.contains(PASSWORD),
        "the password was echoed: {seen:?}"
    );

    // sign: one prompt that names the key.
    let mut session = on_pty(
        dir.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "acme-signing.key",
        ],
    );
    let mut seen = session
        .exp_string("Password for acme-signing.key (input hidden): ")
        .expect("prompt");
    session.send_line(PASSWORD).expect("send");
    seen.push_str(&session.exp_eof().expect("eof"));
    assert_eq!(exit_code(&session), 0, "{seen}");
    assert!(
        seen.contains("Checked the new signature: it verifies."),
        "{seen}"
    );
    assert!(
        !seen.contains(PASSWORD),
        "the password was echoed: {seen:?}"
    );
    assert!(dir.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn keygen_with_passwords_that_differ_exits_64_and_writes_nothing() {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut session = on_pty(dir.path(), &["spec", "keygen", "k"]);
    session.exp_string("(input hidden): ").expect("prompt");
    session.send_line("one-CANARY").expect("send");
    session.exp_string("Repeat the password: ").expect("prompt");
    session.send_line("two-CANARY").expect("send");
    let seen = session.exp_eof().expect("eof");
    assert_eq!(exit_code(&session), 64, "{seen}");
    assert!(seen.contains("the passwords did not match"), "{seen}");
    assert!(!seen.contains("CANARY"), "{seen:?}");
    assert!(!dir.path().join("k.key").exists());
    assert!(!dir.path().join("k.pub").exists());
}
