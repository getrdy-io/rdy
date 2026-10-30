//! A privilege-carrying `rdy` never opens the spec (M1-074, INV-10, threat E2).
//!
//! The real binary is copied, and the copy is made setuid root, or given a file capability. The CI
//! user runs it with a spec path that is a FIFO with no writer. Opening that path blocks for ever, so
//! an exit 70 within 5 seconds shows the spec was never opened. The refusal text shows the gate is what
//! ended the run.
//!
//! The setup needs `sudo` for `chown` and `setcap`. The tests run only when `RDY_REQUIRE_SETUID=1`,
//! which the linux-x64 leg of CI sets after it installs `libcap2-bin`. Without the variable they skip
//! and say so, so `cargo test --workspace` stays green for a normal user. With it set, a missing
//! `sudo` or `setcap` is a failure, not a skip.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::fs::{CWD, FileType, Mode, mknodat};

mod common;

/// The user the tests drop to when they run as root (a local run under `sudo`). CI runs as its own user.
const UNPRIVILEGED_ID: u32 = 65534;

fn required() -> bool {
    std::env::var_os("RDY_REQUIRE_SETUID").is_some_and(|v| v == "1")
}

/// Runs `sudo -n <args>`; any failure fails the test.
fn sudo(args: &[&str]) {
    let status = Command::new("sudo")
        .arg("-n")
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("sudo did not start ({e}); this test needs passwordless sudo"));
    assert!(status.success(), "sudo {args:?} failed: {status}");
}

struct Setup {
    // Held so the folder stays until the test ends.
    _dir: tempfile::TempDir,
    binary: PathBuf,
    fifo: PathBuf,
}

/// A folder that anyone can enter, with a copy of `rdy` and a FIFO with no writer.
fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
    let mode = |path: &Path, bits: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    };
    mode(dir.path(), 0o755);
    let binary = dir.path().join("rdy");
    std::fs::copy(env!("CARGO_BIN_EXE_rdy"), &binary)
        .unwrap_or_else(|e| panic!("copy of the rdy binary: {e}"));
    mode(&binary, 0o755);
    let fifo = dir.path().join("spec.yaml");
    mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o666), 0)
        .unwrap_or_else(|e| panic!("mkfifo: {e}"));
    mode(&fifo, 0o666);
    Setup {
        _dir: dir,
        binary,
        fifo,
    }
}

struct Ended {
    code: Option<i32>,
    stderr: String,
    took: Duration,
    /// The process was still running at the limit and was killed.
    timed_out: bool,
}

/// Runs `binary args...` as the unprivileged user and waits up to `limit`.
fn run_for(binary: &Path, args: &[&str], limit: Duration) -> Ended {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env_remove("RDY_PROGRESS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if rustix::process::geteuid().is_root() {
        // A local run under sudo. A setuid-root file would not look privileged to root itself.
        command.uid(UNPRIVILEGED_ID).gid(UNPRIVILEGED_ID);
    }
    let started = Instant::now();
    let mut child = command
        .spawn()
        .unwrap_or_else(|e| panic!("rdy did not start: {e}"));
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() >= limit => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("wait: {e}"),
        }
    }
    let took = started.elapsed();
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait: {e}"));
    Ended {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&common::without_fd_warning(&out.stderr)).into_owned(),
        took,
        timed_out,
    }
}

/// Every command that reads a spec, with `FIFO` standing for the spec path. `run` is not built yet and
/// exits 70 on its own, so the refusal text is what tells the gate from that. `spec lint` and
/// `trust add` look at the path first and refuse a FIFO as "not a regular file" (exit 64), which is
/// also how the gate is told apart from them. `spec sign` opens its spec, so it is the command that
/// blocks.
const COMMANDS: &[&[&str]] = &[
    &["run", "FIFO"],
    &["verify", "FIFO"],
    &["spec", "lint", "FIFO"],
    &["spec", "sign", "FIFO", "--secret-key", "FIFO"],
    &["trust", "add", "acme", "--key", "FIFO"],
];

fn with_fifo(command: &[&str], set: &Setup) -> Vec<String> {
    let fifo = set.fifo.to_string_lossy();
    command
        .iter()
        .map(|word| {
            if *word == "FIFO" {
                fifo.to_string()
            } else {
                (*word).to_owned()
            }
        })
        .collect()
}

/// The control: the same copy with no privilege bit opens the FIFO in `spec sign` and blocks, and
/// reaches the path check of `spec lint`. Without this, a FIFO that did not block would make every
/// other assertion here empty.
fn assert_the_fifo_blocks(set: &Setup) {
    let sign = with_fifo(&["spec", "sign", "FIFO", "--secret-key", "FIFO"], set);
    let words: Vec<&str> = sign.iter().map(String::as_str).collect();
    let ended = run_for(&set.binary, &words, Duration::from_secs(2));
    assert!(
        ended.timed_out,
        "an unprivileged rdy did not block on the FIFO (exit {:?}): {}",
        ended.code, ended.stderr
    );
    let lint = with_fifo(&["spec", "lint", "FIFO"], set);
    let words: Vec<&str> = lint.iter().map(String::as_str).collect();
    let ended = run_for(&set.binary, &words, Duration::from_secs(5));
    assert_eq!(ended.code, Some(64), "{}", ended.stderr);
    assert!(
        ended.stderr.contains("not a regular file"),
        "{}",
        ended.stderr
    );
}

/// The refusal text of INV-10.
const REFUSED: &str = "error: rdy will not run with more privilege";
/// A process that the kernel started with file capabilities is not dumpable, so `/proc/self/auxv`
/// (mode 0400, owned by root for such a process) is not readable by the user. The snapshot then ends in
/// its fail-closed branch: still exit 70, with the unreadable-source text. See the carry in
/// docs/plan/12-progress.md (M1-074).
const AUXV_UNREADABLE: &str = "error: rdy could not read /proc/self/auxv";

fn assert_refused_without_opening_the_spec(set: &Setup, what: &str, texts: &[&str]) {
    for command in COMMANDS {
        let args = with_fifo(command, set);
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        let ended = run_for(&set.binary, &words, Duration::from_secs(5));
        assert!(
            !ended.timed_out,
            "{what}: rdy {words:?} was still running after 5 s, so it opened the spec. If the folder is on a nosuid mount the bit has no effect: set TMPDIR to another folder"
        );
        assert!(
            ended.took < Duration::from_secs(5),
            "{what}: {:?}",
            ended.took
        );
        assert_eq!(
            ended.code,
            Some(70),
            "{what}: rdy {words:?}: {}",
            ended.stderr
        );
        assert!(
            texts.iter().any(|text| ended.stderr.starts_with(text)),
            "{what}: rdy {words:?}: {}",
            ended.stderr
        );
    }
}

#[test]
fn a_setuid_root_rdy_exits_70_and_never_opens_the_spec() {
    if !required() {
        eprintln!("skipped: needs sudo (the linux-x64 leg sets RDY_REQUIRE_SETUID=1)");
        return;
    }
    let set = setup();
    assert_the_fifo_blocks(&set);
    let binary = set.binary.to_string_lossy().into_owned();
    sudo(&["chown", "root", &binary]);
    sudo(&["chmod", "u+s", &binary]);
    assert_refused_without_opening_the_spec(&set, "setuid root", &[REFUSED]);
}

#[test]
fn an_rdy_with_a_file_capability_exits_70_and_never_opens_the_spec() {
    if !required() {
        eprintln!("skipped: needs sudo and setcap (the linux-x64 leg sets RDY_REQUIRE_SETUID=1)");
        return;
    }
    let set = setup();
    assert_the_fifo_blocks(&set);
    let binary = set.binary.to_string_lossy().into_owned();
    sudo(&["setcap", "cap_net_raw+ep", &binary]);
    assert_refused_without_opening_the_spec(&set, "file capability", &[REFUSED, AUXV_UNREADABLE]);
}
