//! The live progress line on a real pseudo-terminal (M1-142, Unix only).
//!
//! The helper is `examples/progress_probe.rs`: `rdy_cli::run` in process with one check that takes 900 ms.
//! Its stderr is the slave side of a pty and its stdout is a pipe. The test reads the pty master.
//!
//! - On a terminal: the spinner draws, the last clear (`\r\x1b[2K`) comes before the first check line, and
//!   nothing of it is on stdout.
//! - A pipe, `--quiet`, `--progress never`, `RDY_PROGRESS=never`, `TERM=dumb` and `RUST_LOG` draw no
//!   progress byte at all.
#![cfg(unix)]
#![allow(clippy::expect_used)]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, Once, PoisonError};

use rustix::fs::{Mode, OFlags, open};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n";
/// The clear that indicatif writes: carriage return, then erase the line.
const CLEAR: &str = "\r\x1b[2K";

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The probe binary, built once for the same profile and target as this test.
fn probe_path() -> PathBuf {
    static BUILD: Once = Once::new();
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    dir.pop();
    BUILD.call_once(|| build_probe(&dir));
    dir.join("examples").join("progress_probe")
}

fn build_probe(dir: &Path) {
    let mut cargo = Command::new(env!("CARGO"));
    cargo.args([
        "build",
        "--quiet",
        "-p",
        "rdy",
        "--example",
        "progress_probe",
    ]);
    match dir.file_name().and_then(|n| n.to_str()) {
        Some("debug") | None => {}
        Some("release") => {
            cargo.arg("--release");
        }
        Some(profile) => {
            cargo.args(["--profile", profile]);
        }
    }
    if let Ok(target) = std::env::var("CARGO_BUILD_TARGET") {
        cargo.args(["--target", &target]);
    }
    assert!(cargo.status().expect("run cargo").success());
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    /// What the pty carried: everything the probe wrote to stderr.
    terminal: String,
}

/// Runs the probe with stderr on a pty (or a pipe) and stdout on a pipe.
fn run(on_pty: bool, term: Option<&str>, env: &[(&str, &str)], args: &[&str]) -> Ran {
    let dir = tempfile::tempdir().expect("temp dir");
    let spec = dir.path().join("acme.yaml");
    std::fs::write(&spec, SPEC).expect("spec");

    let mut cmd = Command::new(probe_path());
    cmd.arg("run")
        .arg(&spec)
        .args(["--allow-unsigned", "--no-report", "--color", "never"])
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.path())
        .env("RDY_PROBE_NAP_MS", "900")
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    if let Some(term) = term {
        cmd.env("TERM", term);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }

    let master = if on_pty {
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).expect("openpt");
        grantpt(&master).expect("grantpt");
        unlockpt(&master).expect("unlockpt");
        let name = ptsname(&master, Vec::new()).expect("ptsname");
        let slave = open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open the pty slave");
        cmd.stderr(Stdio::from(slave));
        Some(master)
    } else {
        cmd.stderr(Stdio::piped());
        None
    };

    let child = cmd.spawn().expect("spawn the probe");
    // The slave end held by `cmd` must be closed here, or the master never sees the hang-up.
    drop(cmd);
    let output = match master {
        Some(master) => {
            let mut file = File::from(master);
            let mut bytes = Vec::new();
            // Linux gives EIO when the last slave closes: that is the end of the stream.
            let _ = file.read_to_end(&mut bytes);
            let output = child.wait_with_output().expect("wait");
            (output, String::from_utf8_lossy(&bytes).into_owned())
        }
        None => {
            let output = child.wait_with_output().expect("wait");
            let terminal = String::from_utf8_lossy(&output.stderr).into_owned();
            (output, terminal)
        }
    };
    Ran {
        code: output.0.status.code(),
        stdout: String::from_utf8_lossy(&output.0.stdout).into_owned(),
        terminal: output.1,
    }
}

/// The text with the spinner's frames: any `Running 1 check` line, which only the live line writes.
fn has_spinner(text: &str) -> bool {
    text.contains("Running 1 check") || text.contains(CLEAR)
}

#[test]
fn on_a_terminal_the_line_is_cleared_before_the_check_list() {
    let _guard = lock();
    let ran = run(true, Some("xterm-256color"), &[], &[]);
    assert_eq!(ran.code, Some(0), "{:?}", ran.terminal);
    let text = &ran.terminal;
    assert!(text.contains("Running 1 check"), "{text:?}");
    let last_clear = text.rfind(CLEAR).expect("the line is cleared");
    let first_check = text.find("PASS").expect("a check line");
    assert!(
        last_clear < first_check,
        "the last clear must come before the first check line: {text:?}"
    );
    // indicatif writes the clear before every redraw, so the position of the last clear proves nothing
    // alone. What follows it, up to the first check line, must hold no frame text: the line really ended.
    let between = &text[last_clear + CLEAR.len()..first_check];
    assert!(
        !between.contains("Running"),
        "a frame is left between the last clear and the check list: {between:?}"
    );
    assert!(
        !between.replace("\r\n", "").contains('\r'),
        "a redraw is left between the last clear and the check list: {between:?}"
    );
    // Nothing of the spinner after the check list starts.
    assert!(!text[first_check..].contains("Running 1 check"), "{text:?}");
    assert!(ran.stdout.is_empty(), "{:?}", ran.stdout);
}

#[test]
fn with_json_the_line_is_on_the_terminal_and_never_on_stdout() {
    let _guard = lock();
    let ran = run(true, Some("xterm-256color"), &[], &["--json"]);
    assert_eq!(ran.code, Some(0), "{:?}", ran.terminal);
    assert!(
        ran.terminal.contains("Running 1 check"),
        "{:?}",
        ran.terminal
    );
    assert!(ran.stdout.starts_with('{'), "{}", ran.stdout);
    assert!(!ran.stdout.contains("Running"), "{}", ran.stdout);
    assert!(!ran.stdout.contains('\x1b'), "{}", ran.stdout);
}

/// A case of the off-switch table: name, stderr is a pty, TERM, variables, arguments.
type OffRow<'a> = (
    &'a str,
    bool,
    Option<&'a str>,
    &'a [(&'a str, &'a str)],
    &'a [&'a str],
);

#[test]
fn every_off_switch_writes_no_progress_byte() {
    let _guard = lock();
    let rows: [OffRow; 7] = [
        ("a pipe", false, Some("xterm"), &[], &[]),
        ("--quiet", true, Some("xterm"), &[], &["--quiet"]),
        ("--verbose", true, Some("xterm"), &[], &["--verbose"]),
        (
            "--progress never",
            true,
            Some("xterm"),
            &[],
            &["--progress", "never"],
        ),
        (
            "RDY_PROGRESS=never",
            true,
            Some("xterm"),
            &[("RDY_PROGRESS", "never")],
            &[],
        ),
        ("TERM=dumb", true, Some("dumb"), &[], &[]),
        ("RUST_LOG", true, Some("xterm"), &[("RUST_LOG", "off")], &[]),
    ];
    for (name, pty, term, env, args) in rows {
        let ran = run(pty, term, env, args);
        assert_eq!(ran.code, Some(0), "{name}: {:?}", ran.terminal);
        assert!(
            !has_spinner(&ran.terminal),
            "{name}: progress bytes on stderr: {:?}",
            ran.terminal
        );
        assert!(ran.stdout.is_empty(), "{name}: {:?}", ran.stdout);
    }
}
