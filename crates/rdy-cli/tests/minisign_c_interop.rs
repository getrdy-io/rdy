//! Interop with the C `minisign` tool (M1-125; the exit test names `minisign -V`).
//!
//! Two directions, each with real files:
//!
//! - rdy opens a key and reads a signature that C minisign 0.11 made. They are committed in
//!   `tests/fixtures/minisign-c/` (see its README). This test always runs.
//! - C minisign opens a key rdy made and verifies a signature rdy made, and rdy reads a signature
//!   made with that key. This test needs a `minisign` program on the PATH. Without one it says so
//!   and passes, unless `RDY_REQUIRE_C_MINISIGN` is set and not empty, which makes a missing program a
//!   failure. The linux-x64 CI leg installs minisign and sets it.
//!
//! Both derive a key at the real cost (1 GiB), so the `real-kdf` test group in
//! .config/nextest.toml lists this binary, and a lock keeps the two apart under `cargo test`.
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};

use rdy_spec::sig::{Policy, PublicKey, SignatureState, TrustSource, TrustStore};
use rdy_spec::spec::ProductSlug;

mod common;

/// The password of the committed fixture key. It protects nothing.
const FIXTURE_PASSWORD: &str = "rdy-test-password-not-a-secret";
/// The key id C minisign gave the fixture key.
const FIXTURE_KEY_ID: &str = "62DF9736939C03E8";
const FIXTURE_SIGNED_AT: &str = "2026-11-30T16:02:11Z";

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/minisign-c")
}

fn rdy(dir: &Path, args: &[&str], password: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .current_dir(dir)
        .env("RDY_KEY_PASSWORD", password)
        .env_remove("RDY_PROGRESS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the rdy binary starts");
    drop(child.stdin.take());
    common::quiet(child.wait_with_output().expect("rdy finishes"))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn pinned(pub_text: &str) -> TrustStore {
    let mut trust = TrustStore::new();
    trust.pin(
        ProductSlug::new("acme-platform").expect("slug"),
        PublicKey::from_base64(pub_text.lines().nth(1).expect("key line")).expect("public key"),
        TrustSource::User,
    );
    trust
}

fn verified(spec: &Path, sidecar: &Path, pub_text: &str) -> SignatureState {
    let spec = std::fs::read(spec).expect("spec");
    let sidecar = std::fs::read(sidecar).expect("sidecar");
    rdy_spec::load(
        &spec,
        Some(&sidecar),
        &pinned(pub_text),
        Policy::RequireSigned,
    )
    .expect("rdy verifies")
    .signature()
    .clone()
}

/// Copies the fixture to a new folder. Git does not keep the 0600 mode, so it is set here.
fn copy_fixture() -> tempfile::TempDir {
    let d = tempfile::tempdir().expect("tempdir");
    for name in [
        "acme-platform.yaml",
        "acme-platform.pub",
        "acme-platform.key",
        "acme-platform.yaml.minisig",
    ] {
        std::fs::copy(fixture_dir().join(name), d.path().join(name)).expect("copy");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            d.path().join("acme-platform.key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
    }
    d
}

#[test]
fn rdy_reads_what_c_minisign_wrote_and_signs_with_the_key_it_made() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let d = copy_fixture();
    let pub_text = std::fs::read_to_string(d.path().join("acme-platform.pub")).expect("pub");

    // The signature C minisign made, with the trusted comment of 01 section 4.2, verifies in rdy.
    let state = verified(
        &d.path().join("acme-platform.yaml"),
        &d.path().join("acme-platform.yaml.minisig"),
        &pub_text,
    );
    match &state {
        SignatureState::Verified {
            key_id, signed_at, ..
        } => {
            assert_eq!(key_id.to_string(), FIXTURE_KEY_ID);
            assert_eq!(signed_at, FIXTURE_SIGNED_AT);
        }
        other => panic!("not verified: {other:?}"),
    }

    // rdy opens the key (scrypt N = 2^20, 1 GiB, made by C minisign) and signs with it.
    std::fs::remove_file(d.path().join("acme-platform.yaml.minisig")).expect("rm");
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "acme-platform.key",
        ],
        FIXTURE_PASSWORD,
    );
    let shown = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{shown}");
    assert!(shown.contains(FIXTURE_KEY_ID), "{shown}");
    assert!(!shown.contains(FIXTURE_PASSWORD), "{shown}");
    let state = verified(
        &d.path().join("acme-platform.yaml"),
        &d.path().join("acme-platform.yaml.minisig"),
        &pub_text,
    );
    assert!(
        matches!(state, SignatureState::Verified { .. }),
        "{state:?}"
    );

    // A wrong password is told apart, and nothing is written.
    std::fs::remove_file(d.path().join("acme-platform.yaml.minisig")).expect("rm");
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "acme-platform.key",
        ],
        "not the password",
    );
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(stderr(&out).contains("password"));
    assert!(!d.path().join("acme-platform.yaml.minisig").exists());
}

/// True when a C `minisign` is on the PATH.
fn c_minisign_available() -> bool {
    Command::new("minisign")
        .arg("-v")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn c_minisign(dir: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new("minisign")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("minisign starts");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("minisign finishes")
}

#[test]
fn c_minisign_opens_a_key_rdy_made_and_verifies_what_rdy_signed() {
    if !c_minisign_available() {
        assert!(
            std::env::var_os("RDY_REQUIRE_C_MINISIGN").is_none_or(|v| v.is_empty()),
            "RDY_REQUIRE_C_MINISIGN is set and there is no minisign on the PATH"
        );
        eprintln!("skipped: no C minisign on the PATH (set RDY_REQUIRE_C_MINISIGN to require it)");
        return;
    }
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let d = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        fixture_dir().join("acme-platform.yaml"),
        d.path().join("acme-platform.yaml"),
    )
    .expect("copy spec");

    let out = rdy(d.path(), &["spec", "keygen", "k"], FIXTURE_PASSWORD);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "k.key",
        ],
        FIXTURE_PASSWORD,
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    // `minisign -V`: the file signature and the trusted comment signature of rdy's output.
    let out = c_minisign(
        d.path(),
        &[
            "-V",
            "-p",
            "k.pub",
            "-m",
            "acme-platform.yaml",
            "-x",
            "acme-platform.yaml.minisig",
        ],
        "",
    );
    let shown = String::from_utf8_lossy(&out.stdout).into_owned() + &stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{shown}");
    assert!(
        shown.contains("Signature and comment signature verified"),
        "{shown}"
    );
    assert!(shown.contains("Trusted comment: rdy-spec-v1 product=acme-platform signed_at="));

    // `minisign -S` opens rdy's key (the password is read from standard input) and rdy accepts
    // what it signs.
    let comment = "rdy-spec-v1 product=acme-platform signed_at=2026-12-01T09:00:00Z";
    let out = c_minisign(
        d.path(),
        &[
            "-S",
            "-s",
            "k.key",
            "-m",
            "acme-platform.yaml",
            "-x",
            "from-c.minisig",
            "-t",
            comment,
        ],
        &format!("{FIXTURE_PASSWORD}\n"),
    );
    let shown = String::from_utf8_lossy(&out.stdout).into_owned() + &stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{shown}");
    let pub_text = std::fs::read_to_string(d.path().join("k.pub")).expect("pub");
    let state = verified(
        &d.path().join("acme-platform.yaml"),
        &d.path().join("from-c.minisig"),
        &pub_text,
    );
    assert!(
        matches!(&state, SignatureState::Verified { signed_at, .. } if signed_at == "2026-12-01T09:00:00Z"),
        "{state:?}"
    );
}
