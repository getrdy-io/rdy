//! A root run touches no path under a user's home (threat model INV-04, SEC-60, M1-122).
//!
//! The `root` CI job runs this under `sudo` with `strace` installed. The test runs the trust store load
//! of this very crate in a child process under `strace -f`, with `HOME`, `XDG_CONFIG_HOME` and
//! `SUDO_USER` all pointing at a fixture user whose home holds a trust file. It then reads the system
//! call log. Any call that mentions the fixture home fails the test, whatever the call is (open, stat,
//! readlink, access).
//!
//! The child is this test binary itself, run with `--ignored --exact` on the probe below. The CLI does
//! not call the trust store yet (M1-126), so the library call is what a root `rdy run` will make.
//!
//! A second test is the control: the same probe, with a layout for a normal user, must show the home in
//! the log. Without it, an empty log would pass for the wrong reason (a broken `strace` command line).
//!
//! The names start with `root_`, so the nextest default and `ci` profiles skip them (08-testing.md,
//! section 6). Plain `cargo test` runs them and they return early when not root and
//! `RDY_REQUIRE_ROOT` is unset.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rdy_cli::trust::{self, Layout, Vars};

/// The name of the probe test. The tests below run it by this exact name.
const PROBE: &str = "strace_probe_load_trust";

/// Which layout the probe builds.
const MODE_VAR: &str = "RDY_PROBE_LAYOUT";

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The gate for every `root_*` test: see `root_smoke.rs`.
fn root_or_skip() -> bool {
    if is_root() {
        return true;
    }
    assert!(
        std::env::var_os("RDY_REQUIRE_ROOT").is_none(),
        "euid is not 0; the root job must run under sudo"
    );
    eprintln!("skipped: needs uid 0 (the root job sets RDY_REQUIRE_ROOT=1)");
    false
}

/// The child side. It is `#[ignore]`, so no normal run executes it. The tests below run it under
/// `strace`. The result of the load is not the point, the system calls are, so it is not asserted.
#[test]
#[ignore = "run by the root_* tests under strace"]
fn strace_probe_load_trust() {
    let Some(mode) = std::env::var_os(MODE_VAR) else {
        return;
    };
    let layout = if mode == "real" {
        // What a root `rdy run` will do.
        Layout::detect()
    } else {
        // The control: the environment of a normal user (uid 1000), read by the same code.
        Layout::from_env(&Vars::from_process(), 1000)
    };
    drop(trust::load(&layout));
}

/// A user's home with a trust file in it, and the log file for `strace`.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("rdy-sudo-user-")
            .tempdir()
            .expect("tempdir");
        let store_dir = dir.path().join("home/alice/.config/rdy");
        fs::create_dir_all(&store_dir).expect("mkdir");
        fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        let file = store_dir.join("trust.yaml");
        fs::write(&file, "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home/alice")
    }

    fn log(&self) -> PathBuf {
        self.dir.path().join("strace.log")
    }
}

/// Runs the probe under `strace -f` and returns the log. `strace` is a hard requirement of the `root`
/// job, so a missing one fails there and skips nowhere.
fn run_probe_under_strace(fixture: &Fixture, layout: &str) -> String {
    let exe = std::env::current_exe().expect("current_exe");
    let home = fixture.home();
    let status = Command::new("strace")
        .arg("-f")
        .args(["-s", "512"])
        .arg("-o")
        .arg(fixture.log())
        .arg("--")
        .arg(&exe)
        .args([
            "--ignored",
            "--exact",
            PROBE,
            "--nocapture",
            "--test-threads=1",
            "--color=never",
        ])
        // sudo resets HOME and XDG_CONFIG_HOME, so this test sets them itself, as a login shell would.
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        // The test harness (libtest) looks for a terminfo file under HOME when TERM is set. That is the
        // harness, not rdy, so the child gets no TERM.
        .env_remove("TERM")
        .env("SUDO_USER", "alice")
        .env("SUDO_UID", "1000")
        .env(MODE_VAR, layout)
        .status()
        .expect("strace could not be started; the root job installs it (apt-get install strace)");
    assert!(status.success(), "the probe failed under strace: {status}");
    fs::read_to_string(fixture.log()).expect("strace log")
}

fn mentions(log: &str, path: &Path) -> Vec<String> {
    let needle = path.to_string_lossy();
    log.lines()
        .filter(|line| line.contains(needle.as_ref()))
        .map(str::to_owned)
        .collect()
}

#[test]
fn root_run_opens_no_path_under_sudo_users_home() {
    if !root_or_skip() {
        return;
    }
    let fixture = Fixture::new();
    let log = run_probe_under_strace(&fixture, "real");
    // The probe really ran and really looked for the system store. If this fails, the log is not
    // evidence of anything.
    assert!(
        log.contains("/etc/rdy"),
        "the log does not show the system store lookup:\n{log}"
    );
    let hits = mentions(&log, &fixture.home());
    assert!(
        hits.is_empty(),
        "a root run touched a path under the user's home:\n{}",
        hits.join("\n")
    );
    // Nothing under a `.config/rdy` folder either, wherever it is.
    let config: Vec<&str> = log.lines().filter(|l| l.contains(".config/rdy")).collect();
    assert!(
        config.is_empty(),
        "a root run looked for a user config folder:\n{}",
        config.join("\n")
    );
}

#[test]
fn root_control_a_user_layout_does_show_the_home_in_the_log() {
    if !root_or_skip() {
        return;
    }
    let fixture = Fixture::new();
    let log = run_probe_under_strace(&fixture, "user");
    let hits = mentions(&log, &fixture.home());
    assert!(
        !hits.is_empty(),
        "the control run never touched the user's store, so the strace check above proves nothing:\n{log}"
    );
}
