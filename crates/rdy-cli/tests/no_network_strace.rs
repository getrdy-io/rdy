//! `rdy run --no-network` makes no `socket(2)` call (M1-059, threat model network rules).
//!
//! The test runs the built `rdy` under `strace -f` and reads the system call log. Any `socket(` line
//! fails it. Two controls keep an empty log from passing for the wrong reason: the log must hold the
//! `execve` of `rdy` itself, and a child that opens a UDP socket must show a `socket(` line in the
//! same kind of log.
//!
//! The test is skipped, with the reason on stderr, where `strace` is missing or cannot trace (a
//! container without `ptrace`). Set `RDY_REQUIRE_STRACE=1` in a job that installs `strace` to make a
//! skip a failure. No job sets it yet (a deferral of M1-059).

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The name of the child test that opens a socket. The control runs it by this exact name.
const PROBE: &str = "strace_probe_open_socket";

const PROBE_VAR: &str = "RDY_PROBE_OPEN_SOCKET";

fn acme() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs/acme-platform.yaml")
}

/// The child side of the control. It is `#[ignore]`, so no normal run executes it.
#[test]
#[ignore = "run by the control test under strace"]
fn strace_probe_open_socket() {
    if std::env::var_os(PROBE_VAR).is_none() {
        return;
    }
    drop(std::net::UdpSocket::bind("127.0.0.1:0"));
}

/// Runs `argv` under `strace -f -e trace=socket,execve` and returns the log text, or `None` (with the
/// reason on stderr) when `strace` is not usable here.
fn traced(argv: &[&std::ffi::OsStr], envs: &[(&str, &str)], log: &Path) -> Option<String> {
    let mut command = Command::new("strace");
    command
        .args(["-f", "-qq", "-e", "trace=socket,execve", "-o"])
        .arg(log)
        .arg("--")
        .args(argv);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.env_remove("RDY_PROGRESS").env_remove("RUST_LOG");
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            return skip_or_fail(&format!("strace did not start: {error}"));
        }
    };
    // `strace` exits with the traced program's code. Its own failure to trace leaves no log.
    let text = std::fs::read_to_string(log).unwrap_or_default();
    if text.is_empty() {
        return skip_or_fail(&format!(
            "strace wrote no log (ptrace may be blocked): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Some(text)
}

fn skip_or_fail(reason: &str) -> Option<String> {
    assert!(
        std::env::var_os("RDY_REQUIRE_STRACE").is_none(),
        "RDY_REQUIRE_STRACE is set but strace is not usable: {reason}"
    );
    eprintln!("skipped: {reason} (RDY_REQUIRE_STRACE=1 turns this skip into a failure)");
    None
}

fn socket_lines(log: &str) -> Vec<&str> {
    log.lines().filter(|l| l.contains("socket(")).collect()
}

#[test]
fn the_control_sees_a_socket_call() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let log = dir.path().join("control.log");
    let me = std::env::current_exe().expect("the test binary");
    let argv = [
        me.as_os_str(),
        "--ignored".as_ref(),
        "--exact".as_ref(),
        PROBE.as_ref(),
        "--nocapture".as_ref(),
    ];
    let Some(text) = traced(&argv, &[(PROBE_VAR, "1")], &log) else {
        return;
    };
    assert!(
        !socket_lines(&text).is_empty(),
        "the control opened a socket and strace did not show it:\n{text}"
    );
}

#[test]
fn no_network_makes_no_socket_call() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let log = dir.path().join("rdy.log");
    let out = dir.path().join("reports");
    std::fs::create_dir(&out).expect("a report folder");
    let rdy = Path::new(env!("CARGO_BIN_EXE_rdy"));
    let spec = acme();
    let argv = [
        rdy.as_os_str(),
        "run".as_ref(),
        spec.as_os_str(),
        "--allow-unsigned".as_ref(),
        "--no-network".as_ref(),
        "--json".as_ref(),
        "--out-dir".as_ref(),
        out.as_os_str(),
    ];
    let Some(text) = traced(&argv, &[], &log) else {
        return;
    };
    // Control: the log is of this run, so it holds the start of `rdy`.
    assert!(text.contains("execve("), "no execve in the log:\n{text}");
    let sockets = socket_lines(&text);
    assert!(sockets.is_empty(), "rdy opened a socket: {sockets:#?}");
}
