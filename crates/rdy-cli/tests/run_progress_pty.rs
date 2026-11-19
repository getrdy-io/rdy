//! The live progress line on a real pseudo-terminal (M1-142, Unix only).
//!
//! The helper is `examples/progress_probe.rs`: `rdy_cli::run` in process with one check that takes 700 ms.
//! Its stderr is a pty (through rexpect, with a read timeout) and its stdout is a file.
//!
//! - On a terminal: the spinner draws, the last clear (`\r\x1b[2K`) comes before the first check line, and
//!   nothing of it is on stdout.
//! - A pipe, `--quiet`, `--progress never`, `RDY_PROGRESS=never`, `TERM=dumb` and `RUST_LOG` draw no
//!   progress byte at all.
#![cfg(unix)]
#![allow(clippy::expect_used)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, Once, PoisonError};

use rexpect::session::spawn_command;

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n";
/// The clear that indicatif writes: carriage return, then erase the line.
const CLEAR: &str = "\r\x1b[2K";

/// Under nextest's 120 s kill, so a hung read fails with a message and does not pass as a kill.
const TIMEOUT_MS: u64 = 30_000;
/// The probe's nap: well past the 250 ms first frame, so a slow runner still sees one frame.
const NAP_MS: &str = "700";

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
    let probe = dir.join("examples").join("progress_probe");
    // `cargo test` builds the examples of the package before it runs a test, so the probe is normally
    // here already. A second `cargo build` from inside the test costs a minute on a cold cache.
    BUILD.call_once(|| {
        if !probe.exists() {
            build_probe(&dir);
        }
    });
    probe
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

/// Runs the probe with stderr on a pty (or a pipe) and stdout on a pipe or a file.
///
/// The pty case uses rexpect, as the other pty tests do: it forks, puts the slave on the child's
/// descriptors 0 to 2 and reads the master with a timeout. The probe's stdout goes to a file, and a
/// small `sh` wrapper writes the exit code to a second file, because rexpect does not return it.
fn run(on_pty: bool, term: Option<&str>, env: &[(&str, &str)], args: &[&str]) -> Ran {
    let dir = tempfile::tempdir().expect("temp dir");
    let spec = dir.path().join("acme.yaml");
    std::fs::write(&spec, SPEC).expect("spec");
    let stdout_file = dir.path().join("stdout.txt");
    let code_file = dir.path().join("code.txt");

    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg("\"$@\"; echo $? > \"$RDY_TEST_CODE_FILE\"")
        .arg("sh")
        .arg(probe_path())
        .arg("run")
        .arg(&spec)
        .args(["--allow-unsigned", "--no-report", "--color", "never"])
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.path())
        .env("RDY_TEST_CODE_FILE", &code_file)
        .env("RDY_PROBE_NAP_MS", NAP_MS)
        .stdout(Stdio::from(
            File::create(&stdout_file).expect("stdout file"),
        ));
    if let Some(term) = term {
        cmd.env("TERM", term);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }

    let terminal = if on_pty {
        let mut session = spawn_command(cmd, Some(TIMEOUT_MS)).expect("spawn the probe on a pty");
        session
            .exp_eof()
            .expect("the probe ends before the timeout")
    } else {
        let output = cmd
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the probe")
            .wait_with_output()
            .expect("wait");
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let code = std::fs::read_to_string(&code_file)
        .ok()
        .and_then(|text| text.trim().parse().ok());
    Ran {
        code,
        stdout: std::fs::read_to_string(&stdout_file).expect("stdout file text"),
        terminal,
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
