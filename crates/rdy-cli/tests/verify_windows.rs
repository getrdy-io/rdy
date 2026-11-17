//! `rdy verify` on Windows with a trust store present (M1-126, ADR 0027 decision 4).
//!
//! A Windows store cannot be checked in M1, so one that exists is refused. A `--key` run never reads a
//! store, so with the same store in place `rdy verify --key <pub>` still exits 0 and `rdy verify`
//! without `--key` exits 64 with `trust_store_insecure`.
//!
//! The Unix behaviour is in `verify_command.rs`.
#![cfg(windows)]
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

mod common;

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/signed")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn rdy(dir: &Path, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .args(["--color", "never"])
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

#[test]
fn a_key_run_ignores_the_store_and_a_run_without_one_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in [
        "acme-platform.yaml",
        "acme-platform.yaml.minisig",
        "acme-platform.pub",
    ] {
        std::fs::write(dir.path().join(name), fixture(name)).expect("write");
    }
    let store = dir.path().join("ProgramData").join("rdy");
    std::fs::create_dir_all(&store).expect("mkdir");
    std::fs::write(
        store.join("trust.yaml"),
        "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n",
    )
    .expect("write");

    let out = rdy(
        dir.path(),
        &["verify", "acme-platform.yaml", "--key", "acme-platform.pub"],
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("VERIFIED, KEY NOT PINNED"), "{err}");

    let out = rdy(dir.path(), &["verify", "acme-platform.yaml", "--json"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(64), "{err}");
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON on stdout");
    assert_eq!(doc["error"]["code"], "trust_store_insecure", "{doc}");
    assert!(
        !doc["error"].to_string().contains("--allow-unsigned"),
        "{doc}"
    );
}
