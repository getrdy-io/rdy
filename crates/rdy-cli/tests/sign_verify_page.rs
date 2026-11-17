//! The sign and verify page, `docs/src/content/docs/specs/signing.md` (M1-134).
//!
//! Every `rdy` line the page shows runs here, through `run_page`, exactly as the page writes it. The
//! docs test `sign_and_verify_page_runs_every_command_it_shows` in `docs_pages.rs` checks that each of
//! those lines is a literal in this file, so the page and the tests cannot drift apart.
//!
//! The exit test: a copy of the example spec is signed with a key made during the test. The page's
//! `verify` commands then accept it, print the full fingerprint that `keygen` and `sign` printed, and
//! show only the short form in the KEY NOT PINNED banner. A changed copy is refused.
//!
//! The trust test: `rdy trust add` pins the key, and `rdy verify` accepts the spec with no banner. It
//! runs only as a normal user. A root run writes `/etc/rdy/trust.yaml`, which a test must not touch
//! (INV-04), so a root run skips it, as `trust_commands.rs` does.
//!
//! Keys are made at run time, so no key file is committed. The password is a test value. Each key
//! derivation takes 1 GiB, so the tests take one at a time, as `spec_keygen_sign.rs` does.
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};

mod common;

/// The password of the test keys. It must never appear in any output.
const PASSWORD: &str = "CANARY-sign-verify-page test password";

/// One key derivation at a time within this binary.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The example spec the page signs. A copy of it goes into each test folder.
fn example_spec() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs/acme-platform.yaml")
}

/// True when the tests run as root. A root run reads and writes `/etc/rdy`, not `HOME`.
fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Runs one line of the page in `dir`. `HOME` is `home`, so a normal user's trust store lands there.
/// Stdin is not a terminal, so no command can prompt. `password` goes in `RDY_KEY_PASSWORD`.
fn run_page(dir: &Path, home: &Path, line: &str, password: Option<&str>) -> Output {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let mut words = line.split_whitespace();
    assert_eq!(
        words.next(),
        Some("rdy"),
        "a page line starts with rdy: {line}"
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.args(words)
        .current_dir(dir)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("RDY_KEY_PASSWORD")
        .env_remove("RDY_PROGRESS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(password) = password {
        cmd.env("RDY_KEY_PASSWORD", password);
    }
    common::quiet(cmd.output().expect("the rdy binary starts"))
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("rdy was not killed by a signal")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The full fingerprint in a block that starts with a `fingerprint` line, as 64 hex digits. The block
/// has two lines of four groups each. Spaces are dropped, so the result compares with another one.
fn full_fingerprint(text: &str) -> String {
    let mut lines = text.lines();
    let first = lines
        .by_ref()
        .find(|line| line.trim_start().starts_with("fingerprint "))
        .expect("a fingerprint line");
    let head = first.trim_start().trim_start_matches("fingerprint");
    let tail = lines.next().expect("the second fingerprint line");
    let fingerprint: String = format!("{head}{tail}")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert_eq!(fingerprint.len(), 64, "a full fingerprint: {fingerprint}");
    assert!(
        fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
        "hex digits only"
    );
    fingerprint
}

/// A folder with the example spec copied in, and an empty `HOME` for the run.
fn workspace() -> (tempfile::TempDir, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("tempdir");
    std::fs::copy(example_spec(), dir.path().join("acme-platform.yaml")).expect("copy the spec");
    (dir, home)
}

/// Makes the key pair `acme-signing` and signs the copy of the example spec. Returns the fingerprint
/// that `sign` printed.
fn keygen_and_sign(dir: &Path, home: &Path) -> String {
    let out = run_page(dir, home, "rdy spec keygen acme-signing", Some(PASSWORD));
    assert_eq!(code(&out), 0, "keygen: {}", stderr(&out));
    assert!(dir.join("acme-signing.key").is_file());
    assert!(dir.join("acme-signing.pub").is_file());
    let made = full_fingerprint(&stderr(&out));

    let out = run_page(
        dir,
        home,
        "rdy spec sign acme-platform.yaml --secret-key acme-signing.key",
        Some(PASSWORD),
    );
    assert_eq!(code(&out), 0, "sign: {}", stderr(&out));
    assert!(stderr(&out).contains("Checked the new signature: it verifies."));
    assert!(dir.join("acme-platform.yaml.minisig").is_file());
    let signed = full_fingerprint(&stderr(&out));
    assert_eq!(signed, made, "sign prints the fingerprint keygen printed");
    for text in [
        stderr(&out),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ] {
        assert!(!text.contains("CANARY"), "the password is not printed");
    }
    signed
}

#[test]
fn the_page_flow_signs_the_example_and_its_verify_commands_check_it() {
    let (dir, home) = workspace();
    let fingerprint = keygen_and_sign(dir.path(), home.path());

    // The page's verify command with a key. The banner shows the short form only, and the full
    // fingerprint is the one that matches the vendor's.
    let out = run_page(
        dir.path(),
        home.path(),
        "rdy verify --key acme-signing.pub acme-platform.yaml",
        None,
    );
    assert_eq!(code(&out), 0, "verify --key: {}", stderr(&out));
    let shown = stderr(&out);
    assert!(shown.starts_with("WARNING: KEY NOT PINNED\n"), "{shown}");
    assert!(shown.contains("VERIFIED, KEY NOT PINNED"), "{shown}");
    assert_eq!(full_fingerprint(&shown), fingerprint);
    let short = format!("fingerprint {}...{}", &fingerprint[..8], &fingerprint[60..]);
    assert!(shown.contains(&short), "the banner shows {short}: {shown}");
    assert!(
        !shown.contains(&fingerprint),
        "the banner never shows the full fingerprint"
    );

    // Without a key, a key nobody trusted yet exits 64 and says how to trust it.
    let out = run_page(
        dir.path(),
        home.path(),
        "rdy verify acme-platform.yaml",
        None,
    );
    assert_eq!(
        code(&out),
        64,
        "verify without a trusted key: {}",
        stderr(&out)
    );
    let refused = stderr(&out);
    assert!(refused.contains("which you have not trusted"), "{refused}");
    assert!(
        refused.contains("rdy trust add acme-platform --key <file>"),
        "{refused}"
    );

    // A changed copy of the spec is refused, even with the key.
    let spec = dir.path().join("acme-platform.yaml");
    let mut body = std::fs::read(&spec).expect("read the spec");
    body.extend_from_slice(b"# changed after signing\n");
    std::fs::write(dir.path().join("changed.yaml"), &body).expect("write the copy");
    std::fs::copy(
        dir.path().join("acme-platform.yaml.minisig"),
        dir.path().join("changed.yaml.minisig"),
    )
    .expect("copy the signature");
    let out = run_page(
        dir.path(),
        home.path(),
        "rdy verify --key acme-signing.pub changed.yaml",
        None,
    );
    assert_eq!(code(&out), 64, "a changed spec: {}", stderr(&out));
    let tampered = stderr(&out);
    assert!(tampered.contains("does not match the file"), "{tampered}");
    assert!(tampered.contains("Do not run this file."), "{tampered}");
}

#[test]
fn trust_add_pins_the_vendor_key_for_a_normal_user() {
    if is_root() {
        eprintln!("skipped: a root run writes /etc/rdy/trust.yaml, which this test never touches");
        return;
    }
    let (dir, home) = workspace();
    let fingerprint = keygen_and_sign(dir.path(), home.path());

    // Without a terminal, trust add will not ask, so it exits 64 and names --yes.
    let out = run_page(
        dir.path(),
        home.path(),
        "rdy trust add acme-platform --key acme-signing.pub",
        None,
    );
    assert_eq!(code(&out), 64, "trust add without --yes: {}", stderr(&out));
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert!(!home.path().join(".config/rdy/trust.yaml").exists());

    // The page asks you to check the fingerprint first. A script answers with --yes after that.
    let out = run_page(
        dir.path(),
        home.path(),
        "rdy trust add acme-platform --key acme-signing.pub --yes",
        None,
    );
    assert_eq!(code(&out), 0, "trust add --yes: {}", stderr(&out));
    let saved = stderr(&out);
    assert!(saved.contains("Trusted key"), "{saved}");
    assert_eq!(full_fingerprint(&saved), fingerprint);
    assert!(home.path().join(".config/rdy/trust.yaml").is_file());

    // With the key pinned, verify needs no --key and shows no banner.
    let out = run_page(
        dir.path(),
        home.path(),
        "rdy verify acme-platform.yaml",
        None,
    );
    assert_eq!(code(&out), 0, "verify with a pinned key: {}", stderr(&out));
    let shown = stderr(&out);
    assert!(!shown.contains("KEY NOT PINNED"), "{shown}");
    assert!(shown.contains("VERIFIED"), "{shown}");
    assert!(shown.contains("trusted on this machine"), "{shown}");
}
