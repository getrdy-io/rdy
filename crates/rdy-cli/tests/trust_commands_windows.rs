//! `rdy trust` on Windows (M1-131, ADR 0027): `add` and `remove` are not supported and exit 64 before they
//! read the key or ask anything, and `list` with no store is empty and does not offer `trust add`.
//!
//! The Unix behaviour is in `trust_commands.rs`.
#![cfg(windows)]
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Output, Stdio};

mod common;

/// Runs `rdy` with a `ProgramData` folder that does not exist, from a temporary folder.
fn rdy(dir: &std::path::Path, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .current_dir(dir)
        .env("ProgramData", dir.join("ProgramData"))
        .env_remove("RDY_PROGRESS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("rdy runs");
    common::quiet(out)
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("rdy was not killed by a signal")
}

#[test]
fn add_and_remove_are_not_supported_and_list_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The key file does not exist. A supported command would complain about it. This one refuses first.
    let out = rdy(
        dir.path(),
        &[
            "trust",
            "add",
            "acme-platform",
            "--key",
            "no-such-file.pub",
            "--yes",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(code(&out), 64, "{err}");
    assert!(err.contains("cannot write a trust store"), "{err}");
    assert!(!dir.path().join("ProgramData").exists());

    let out = rdy(dir.path(), &["trust", "remove", "acme-platform"]);
    assert_eq!(code(&out), 64);

    let out = rdy(dir.path(), &["trust", "list"]);
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(shown.starts_with("No keys are trusted yet."), "{shown}");
    assert!(!shown.contains("rdy trust add"), "{shown}");
}
