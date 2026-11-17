//! Every spec read refuses a named pipe or a device, and `rdy spec sign` refuses an expired spec (M1-183).
//!
//! `rdy run`, `rdy verify`, `rdy spec lint` and `rdy spec sign` each get a named pipe at the spec path,
//! a link to one, and `/dev/zero`. Each must exit 64 with `spec_unreadable` in under a second, and never
//! wait on the pipe. A child that is still alive after ten seconds is killed and fails the test, so a
//! hang cannot stall CI. The swap between the `stat` and the open is covered by unit tests with a hook
//! (no real race).
//!
//! Unix only: Windows has no named pipe at a file path and no `/dev/zero`. Its twin is
//! `spec_read_special_windows.rs`, which uses `NUL` and a pipe from `\\.\pipe\`, and relies on the
//! `GetFileType` test of `signing::files` (the standard library's `is_file` passes both).
#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

mod common;

const PASSWORD_VAR: &str = "RDY_KEY_PASSWORD";

/// One start of the binary, so its pages are in the cache before a run is timed (a slow runner).
fn warm_up() {
    let _ = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .arg("version")
        .stdin(Stdio::null())
        .output();
}

fn run(dir: &Path, args: &[&str]) -> (Output, Duration) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .current_dir(dir)
        .env_remove(PASSWORD_VAR)
        .env_remove("RDY_PROGRESS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the rdy binary starts");
    // Timed from the spawn, after the warm-up, so a cold binary does not count.
    let start = Instant::now();
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rdy hung on {args:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let took = start.elapsed();
    (
        common::quiet(child.wait_with_output().expect("output")),
        took,
    )
}

fn fifo(path: &Path) {
    let made = Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo failed");
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn commands(spec: &str) -> Vec<(&'static str, Vec<String>)> {
    let s = spec.to_owned();
    vec![
        ("run", vec!["run".into(), s.clone(), "--no-report".into()]),
        ("verify", vec!["verify".into(), s.clone()]),
        (
            "sign",
            vec![
                "spec".into(),
                "sign".into(),
                s.clone(),
                "--secret-key".into(),
                "none.key".into(),
            ],
        ),
        ("lint", vec!["spec".into(), "lint".into(), s]),
    ]
}

fn assert_refused(dir: &Path, spec: &str, what: &str) {
    for (name, args) in commands(spec) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (out, took) = run(dir, &args);
        let err = text(&out);
        assert_eq!(out.status.code(), Some(64), "{what} {name}: {err}");
        assert!(took < Duration::from_secs(1), "{what} {name}: {took:?}");
        assert!(err.contains("not a regular file"), "{what} {name}: {err}");
        assert!(err.contains("fix:"), "{what} {name}: {err}");
        assert!(!dir.join(format!("{spec}.minisig")).exists());
    }
}

#[test]
fn a_named_pipe_at_the_spec_path_exits_64_at_once() {
    warm_up();
    let d = tempfile::tempdir().expect("tempdir");
    fifo(&d.path().join("spec.yaml"));
    assert_refused(d.path(), "spec.yaml", "a named pipe");
}

#[test]
fn a_device_at_the_spec_path_exits_64_at_once() {
    warm_up();
    let d = tempfile::tempdir().expect("tempdir");
    assert_refused(d.path(), "/dev/zero", "/dev/zero");
}

#[test]
fn a_link_to_a_named_pipe_exits_64_at_once() {
    warm_up();
    let d = tempfile::tempdir().expect("tempdir");
    fifo(&d.path().join("real.fifo"));
    std::os::unix::fs::symlink("real.fifo", d.path().join("spec.yaml")).expect("symlink");
    assert_refused(d.path(), "spec.yaml", "a link to a pipe");
}

const EXPIRED: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\n  expires: 2020-01-01T00:00:00Z\nchecks:\n  - id: host.cpu\n    min: 8\n";

#[test]
fn sign_refuses_an_expired_spec_before_the_key_and_writes_nothing() {
    let d = tempfile::tempdir().expect("tempdir");
    std::fs::write(d.path().join("spec.yaml"), EXPIRED).expect("write");
    // The key file does not exist and no password is given. Refusing the spec comes first, so neither is
    // asked for.
    let (out, _) = run(
        d.path(),
        &["spec", "sign", "spec.yaml", "--secret-key", "missing.key"],
    );
    let err = text(&out);
    assert_eq!(out.status.code(), Some(64), "{err}");
    assert!(err.contains("expired on 2020-01-01"), "{err}");
    assert!(err.contains("fix:"), "{err}");
    assert!(!err.contains("input hidden"), "{err}");
    assert!(!err.contains("not signed:"), "{err}");
    assert!(!err.contains("missing.key"), "{err}");
    assert!(!d.path().join("spec.yaml.minisig").exists());
}
