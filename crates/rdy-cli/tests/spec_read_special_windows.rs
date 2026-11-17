//! A device name or a named pipe as the spec exits 64 at once on Windows (M1-183, 05 INV-02).
//!
//! `NUL` is a character device and `\\.\pipe\...` is a pipe served by this test. Both pass the standard
//! library's `is_file` check, so the proof is the `GetFileType` test on the open handle. Each of `rdy run`,
//! `rdy verify`, `rdy spec lint` and `rdy spec sign` must exit 64 in under a second. The Unix twin is
//! `spec_read_special.rs`.
#![cfg(windows)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::ServerOptions;

fn assert_exits_64(spec: &str) {
    let commands: [&[&str]; 4] = [
        &["run", spec, "--no-report"],
        &["verify", spec],
        &["spec", "lint", spec],
        &["spec", "sign", spec, "--secret-key", "none.key"],
    ];
    // One start of the binary first, so a cold start does not count against the second.
    let _ = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .arg("version")
        .stdin(Stdio::null())
        .output();
    for args in commands {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut child = Command::new(env!("CARGO_BIN_EXE_rdy"))
            .args(args)
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the rdy binary starts");
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                panic!("rdy hung on {args:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(64), "{spec} {args:?}");
        assert!(start.elapsed() < Duration::from_secs(1), "{spec} {args:?}");
    }
}

#[test]
fn a_device_name_as_the_spec_exits_64_at_once() {
    assert_exits_64("NUL");
}

#[test]
fn a_named_pipe_as_the_spec_exits_64_at_once() {
    let name = format!(r"\\.\pipe\rdy-m1-183-{}", std::process::id());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();
    // Several instances, so an open finds a free one: with a single instance the open fails as busy and
    // the disk check is never reached.
    let _servers: Vec<_> = (0..16)
        .map(|n| {
            let mut options = ServerOptions::new();
            options.first_pipe_instance(n == 0);
            options.create(&name).expect("create the pipe")
        })
        .collect();
    assert_exits_64(&name);
}
