//! `rdy run --no-network` opens no network socket (M1-059, SEC-01, correction-39).
//!
//! The test runs the built `rdy` under `strace -f` and reads the system call log. `--no-network`
//! is an allow-list: the only sockets from rdy or its children are AF_UNIX (local IPC). Any other
//! socket domain, and any call that names an AF_INET, AF_INET6 or AF_PACKET address, fails the test.
//!
//! Controls keep an empty log from passing for the wrong reason. The first test runs a child that
//! opens a UDP socket and requires the log to show it. The second requires the `execve` of `rdy`
//! itself, and that the run really ran: exit 1 or 2 (the example spec has blockers and warnings on
//! any machine, never a clean 0), a Report on stdout with `run.options.network == false`, and at
//! least one check that ran.
//!
//! The names start with `root_`, so the nextest default and `ci` profiles skip them and the `root`
//! job (which installs `strace`) runs them (08-testing.md, section 6). Plain `cargo test` runs them
//! too. Where `strace` is missing or cannot trace, they skip with the reason on stderr, unless
//! `RDY_REQUIRE_ROOT` (set by the root job) or `RDY_REQUIRE_STRACE` is set, which makes a skip a
//! failure.
//!
//! The real binary registers only the host family, which opens no socket today, so this is a
//! regression guard. The net and k8s skips are proved at engine level. M1-095 and M1-107 rerun this
//! test once those families are registered.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

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

struct Traced {
    log: String,
    code: Option<i32>,
    stdout: String,
}

/// Runs `argv` under `strace -f` and returns the log, the exit code and stdout, or `None` (with the
/// reason on stderr) when `strace` is not usable here.
fn traced(argv: &[&OsStr], envs: &[(&str, &str)], log: &Path) -> Option<Traced> {
    let mut command = Command::new("strace");
    command
        .args(["-f", "-qq", "-e", "trace=%network,execve", "-o"])
        .arg(log)
        .arg("--")
        .args(argv);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.env_remove("RDY_PROGRESS").env_remove("RUST_LOG");
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => return skip_or_fail(&format!("strace did not start: {error}")),
    };
    // `strace` exits with the traced program's code. Its own failure to trace leaves no log.
    let text = std::fs::read_to_string(log).unwrap_or_default();
    if text.is_empty() {
        return skip_or_fail(&format!(
            "strace wrote no log (ptrace may be blocked): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Some(Traced {
        log: text,
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

fn skip_or_fail(reason: &str) -> Option<Traced> {
    assert!(
        std::env::var_os("RDY_REQUIRE_ROOT").is_none()
            && std::env::var_os("RDY_REQUIRE_STRACE").is_none(),
        "RDY_REQUIRE_ROOT or RDY_REQUIRE_STRACE is set but strace is not usable: {reason}"
    );
    eprintln!("skipped: {reason} (RDY_REQUIRE_STRACE=1 turns this skip into a failure)");
    None
}

/// The domain of a `socket(` line, such as `AF_UNIX`.
fn domain(line: &str) -> Option<&str> {
    let rest = line.split("socket(").nth(1)?;
    Some(rest.split([',', ')']).next()?.trim())
}

/// Every line that is not local IPC: a socket of any domain but AF_UNIX, or any call that names an
/// internet or packet address.
fn network_lines(log: &str) -> Vec<&str> {
    log.lines()
        .filter(|line| {
            let socket = line.contains("socket(") && !line.contains("socketpair(");
            let bad_domain = socket && !matches!(domain(line), Some("AF_UNIX" | "AF_LOCAL"));
            let bad_address = line.contains("AF_INET") || line.contains("AF_PACKET");
            bad_domain || bad_address
        })
        .collect()
}

#[test]
fn root_strace_control_sees_a_socket_call() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let log = dir.path().join("control.log");
    let me = std::env::current_exe().expect("the test binary");
    let argv = [
        me.as_os_str(),
        OsStr::new("--ignored"),
        OsStr::new("--exact"),
        OsStr::new(PROBE),
        OsStr::new("--nocapture"),
    ];
    let Some(done) = traced(&argv, &[(PROBE_VAR, "1")], &log) else {
        return;
    };
    assert!(
        !network_lines(&done.log).is_empty(),
        "the control opened a UDP socket and strace did not show it:\n{}",
        done.log
    );
}

#[test]
fn root_no_network_run_opens_no_network_socket() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let control = dir.path().join("control.log");
    let log = dir.path().join("rdy.log");
    let out = dir.path().join("reports");
    std::fs::create_dir(&out).expect("a report folder");

    // The control first: if strace cannot see a socket here, the run below proves nothing.
    let me = std::env::current_exe().expect("the test binary");
    let probe = [
        me.as_os_str(),
        OsStr::new("--ignored"),
        OsStr::new("--exact"),
        OsStr::new(PROBE),
        OsStr::new("--nocapture"),
    ];
    let Some(seen) = traced(&probe, &[(PROBE_VAR, "1")], &control) else {
        return;
    };
    assert!(
        !network_lines(&seen.log).is_empty(),
        "the control opened a UDP socket and strace did not show it:\n{}",
        seen.log
    );

    let rdy = Path::new(env!("CARGO_BIN_EXE_rdy"));
    let spec = acme();
    let argv = [
        rdy.as_os_str(),
        OsStr::new("run"),
        spec.as_os_str(),
        OsStr::new("--allow-unsigned"),
        OsStr::new("--no-network"),
        OsStr::new("--json"),
        OsStr::new("--out-dir"),
        out.as_os_str(),
    ];
    let Some(done) = traced(&argv, &[], &log) else {
        return;
    };
    assert!(
        done.log.contains("execve("),
        "no execve in the log:\n{}",
        done.log
    );

    // The run really ran.
    assert!(
        matches!(done.code, Some(1 | 2)),
        "exit {:?}, stdout:\n{}",
        done.code,
        done.stdout
    );
    let report: Value = serde_json::from_str(&done.stdout)
        .unwrap_or_else(|e| panic!("stdout is not the Report ({e}):\n{}", done.stdout));
    assert_eq!(report["run"]["options"]["network"], false, "{report}");
    let ran = report["checks"].as_array().map_or(0, |checks| {
        checks
            .iter()
            .filter(|c| !matches!(c["status"].as_str(), Some("skipped" | "error") | None))
            .count()
    });
    assert!(ran >= 1, "no check ran:\n{}", done.stdout);

    let lines = network_lines(&done.log);
    assert!(
        lines.is_empty(),
        "rdy opened a socket other than AF_UNIX: {lines:#?}"
    );
}
