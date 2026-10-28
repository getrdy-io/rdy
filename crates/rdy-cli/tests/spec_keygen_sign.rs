//! `rdy spec keygen` and `rdy spec sign` through the built binary (M1-125).
//!
//! The exit test of the ticket: a signature made by rdy verifies with `rdy_spec::load` (what a customer
//! runs) and with the stock `minisign` crate (what `minisign -V` runs); keys are 0600 and encrypted
//! unless `--unencrypted`; a spec with a lint error, a key that others can read and a signature file
//! that exists are all refused; and CI can use `RDY_KEY_PASSWORD` and `--password-file -` with no
//! prompt (these runs have no terminal, so a prompt would exit 64).
//!
//! These tests run the real key derivation (1 GiB), so each keygen or sign takes a second or two.
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};

use rdy_spec::sig::{Policy, PublicKey, SignatureState, TrustSource, TrustStore};
use rdy_spec::spec::ProductSlug;

const PASSWORD: &str = "CANARY-ci password with spaces";
const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 8\n    severity: block\n    fix: Use a node with at least 8 vCPUs.\n";

/// One run at a time. Each key derivation needs 1 GiB, and a CI runner has a few GiB.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Runs `rdy` in `dir` with stdin from `stdin` (never a terminal) and the given extra variable.
fn rdy(dir: &Path, args: &[&str], env_password: Option<&str>, stdin: &str) -> Output {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.args(args)
        .current_dir(dir)
        .env_remove("RDY_KEY_PASSWORD")
        .env_remove("RDY_PROGRESS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(password) = env_password {
        cmd.env("RDY_KEY_PASSWORD", password);
    }
    let mut child = cmd.spawn().expect("the rdy binary starts");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("rdy finishes")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("rdy was not killed by a signal")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn write_spec(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("acme-platform.yaml");
    std::fs::write(&path, body).expect("write spec");
    path
}

/// Checks the signature next to the spec the way a customer's rdy does, and the way stock minisign does.
fn assert_verifies(dir: &Path, key_name: &str) {
    let spec = std::fs::read(dir.join("acme-platform.yaml")).expect("spec");
    let sidecar = std::fs::read(dir.join("acme-platform.yaml.minisig")).expect("sidecar");
    let pub_text = std::fs::read_to_string(dir.join(format!("{key_name}.pub"))).expect("pub");
    let line = pub_text.lines().nth(1).expect("key line");

    let mut trust = TrustStore::new();
    trust.pin(
        ProductSlug::new("acme-platform").expect("slug"),
        PublicKey::from_base64(line).expect("public key"),
        TrustSource::User,
    );
    let loaded =
        rdy_spec::load(&spec, Some(&sidecar), &trust, Policy::RequireSigned).expect("rdy verifies");
    assert!(matches!(
        loaded.signature(),
        SignatureState::Verified { .. }
    ));

    let public = minisign::PublicKeyBox::from_string(&pub_text)
        .expect("pub box")
        .into_public_key()
        .expect("stock crate reads the public key");
    let sig = minisign::SignatureBox::from_string(&String::from_utf8_lossy(&sidecar))
        .expect("stock crate reads the signature");
    minisign::verify(&public, &sig, Cursor::new(spec), true, false, false)
        .expect("stock minisign verifies");
}

#[test]
fn ci_can_make_a_key_and_sign_with_the_variable_and_with_stdin_and_no_prompt() {
    let d = tempfile::tempdir().expect("tempdir");
    write_spec(d.path(), SPEC);

    // Key one: password from the variable. Signed with the password on standard input.
    let out = rdy(d.path(), &["spec", "keygen", "one"], Some(PASSWORD), "");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(out.stdout.is_empty(), "keygen prints nothing on stdout");
    assert!(!stderr(&out).contains("input hidden"), "no prompt");
    assert!(!stderr(&out).contains("CANARY"));
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "one.key",
            "--password-file",
            "-",
        ],
        None,
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("Checked the new signature: it verifies."));
    assert!(!stderr(&out).contains("input hidden"), "no prompt");
    assert!(!stderr(&out).contains("CANARY"));
    assert_verifies(d.path(), "one");

    // Key two: password on standard input. Signed with the password from the variable.
    std::fs::remove_file(d.path().join("acme-platform.yaml.minisig")).expect("rm");
    let out = rdy(
        d.path(),
        &["spec", "keygen", "two", "--password-file", "-"],
        None,
        &format!("{PASSWORD}\r\n"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "two.key",
        ],
        Some(PASSWORD),
        "",
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!stderr(&out).contains("input hidden"), "no prompt");
    assert_verifies(d.path(), "two");
}

#[test]
fn the_key_is_encrypted_and_private_and_the_public_key_is_not_a_secret() {
    let d = tempfile::tempdir().expect("tempdir");
    let out = rdy(d.path(), &["spec", "keygen", "k"], Some(PASSWORD), "");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let key = std::fs::read_to_string(d.path().join("k.key")).expect("key");
    let record = {
        use ct_codecs::Decoder;
        ct_codecs::Base64::decode_to_vec(key.lines().nth(1).expect("line"), None).expect("base64")
    };
    assert_eq!(&record[..6], b"EdScB2", "scrypt-encrypted");
    assert!(!key.contains("CANARY"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |name: &str| {
            std::fs::metadata(d.path().join(name))
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("k.key"), 0o600);
        assert_eq!(mode("k.pub"), 0o644);
    }
    let shown = stderr(&out);
    assert!(shown.contains("Wrote k.key"), "{shown}");
    assert!(shown.contains("fingerprint  "), "{shown}");
}

#[test]
fn unencrypted_keygen_is_explicit_and_signs_without_any_password() {
    let d = tempfile::tempdir().expect("tempdir");
    write_spec(d.path(), SPEC);
    // The variable is ignored with --unencrypted: it is not used to protect the key.
    let out = rdy(
        d.path(),
        &["spec", "keygen", "ci", "--unencrypted"],
        Some(PASSWORD),
        "",
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("is not protected by a password"));
    let key = std::fs::read_to_string(d.path().join("ci.key")).expect("key");
    let record = {
        use ct_codecs::Decoder;
        ct_codecs::Base64::decode_to_vec(key.lines().nth(1).expect("line"), None).expect("base64")
    };
    assert_eq!(&record[..6], b"Ed\0\0B2", "not encrypted");
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "ci.key",
        ],
        None,
        "",
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_verifies(d.path(), "ci");
}

#[test]
fn unencrypted_and_a_password_file_cannot_be_combined() {
    let d = tempfile::tempdir().expect("tempdir");
    let out = rdy(
        d.path(),
        &[
            "spec",
            "keygen",
            "k",
            "--unencrypted",
            "--password-file",
            "-",
        ],
        None,
        "x\n",
    );
    assert_eq!(code(&out), 64);
    assert!(!d.path().join("k.key").exists());
}

#[test]
fn without_a_terminal_or_a_password_keygen_and_sign_exit_64_with_a_fix() {
    let d = tempfile::tempdir().expect("tempdir");
    let out = rdy(d.path(), &["spec", "keygen", "k"], None, "");
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("\nfix: "), "{}", stderr(&out));
    assert!(!d.path().join("k.key").exists());

    // Sign with an encrypted key and no password source.
    write_spec(d.path(), SPEC);
    let out = rdy(d.path(), &["spec", "keygen", "k"], Some(PASSWORD), "");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "k.key",
        ],
        None,
        "",
    );
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("RDY_KEY_PASSWORD"));
    assert!(!d.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn a_wrong_password_exits_64_and_signs_nothing() {
    let d = tempfile::tempdir().expect("tempdir");
    write_spec(d.path(), SPEC);
    let out = rdy(d.path(), &["spec", "keygen", "k"], Some(PASSWORD), "");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "k.key",
        ],
        Some("CANARY-not-the-password"),
        "",
    );
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("password"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("CANARY"));
    assert!(!d.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn sign_refuses_the_typos_and_exits_64_with_findings_and_no_signature() {
    for (what, check) in [
        ("mn: 32Gi", "  - id: host.memory\n    mn: 32Gi\n"),
        ("min: 32G", "  - id: host.memory\n    min: 32G\n"),
        ("host.memroy", "  - id: host.memroy\n    min: 32Gi\n"),
    ] {
        let d = tempfile::tempdir().expect("tempdir");
        let spec = format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n{check}"
        );
        write_spec(d.path(), &spec);
        // A key that does not exist: the spec is refused first.
        let out = rdy(
            d.path(),
            &[
                "spec",
                "sign",
                "acme-platform.yaml",
                "--secret-key",
                "k.key",
            ],
            Some(PASSWORD),
            "",
        );
        let err = stderr(&out);
        assert_eq!(code(&out), 64, "{what}: {err}");
        assert!(out.stdout.is_empty(), "{what}");
        assert!(err.contains("acme-platform.yaml: error: "), "{what}: {err}");
        assert!(
            err.contains("error: not signed: acme-platform.yaml has 1 error"),
            "{what}: {err}"
        );
        assert!(
            err.ends_with("fix: correct the errors above and run rdy spec sign again\n"),
            "{what}: {err}"
        );
        assert!(
            !d.path().join("acme-platform.yaml.minisig").exists(),
            "{what}"
        );
    }
}

#[test]
fn a_refusal_with_json_is_an_error_object_on_stdout() {
    let d = tempfile::tempdir().expect("tempdir");
    write_spec(
        d.path(),
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.memroy\n    min: 1Gi\n",
    );
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "k.key",
            "--json",
        ],
        None,
        "",
    );
    assert_eq!(code(&out), 64);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON on stdout");
    assert_eq!(doc["kind"], "Error");
    assert_eq!(doc["error"]["code"], "usage");
}

#[cfg(unix)]
#[test]
fn a_key_that_others_can_read_is_refused_with_the_chmod_fix() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().expect("tempdir");
    write_spec(d.path(), SPEC);
    let out = rdy(d.path(), &["spec", "keygen", "k"], Some(PASSWORD), "");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    std::fs::set_permissions(
        d.path().join("k.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod");
    let out = rdy(
        d.path(),
        &[
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "k.key",
        ],
        Some(PASSWORD),
        "",
    );
    let err = stderr(&out);
    assert_eq!(code(&out), 64, "{err}");
    assert!(
        err.contains("can be read or written by other users"),
        "{err}"
    );
    assert!(
        err.contains("fix: make it private with: chmod 600 k.key"),
        "{err}"
    );
    assert!(!d.path().join("acme-platform.yaml.minisig").exists());
}

#[test]
fn keys_and_signatures_are_never_overwritten_without_force() {
    let d = tempfile::tempdir().expect("tempdir");
    write_spec(d.path(), SPEC);
    let out = rdy(d.path(), &["spec", "keygen", "k"], Some(PASSWORD), "");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let before = std::fs::read(d.path().join("k.key")).expect("key");

    // keygen has no --force, and the key is untouched.
    let out = rdy(d.path(), &["spec", "keygen", "k"], Some(PASSWORD), "");
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("already exists"));
    assert_eq!(std::fs::read(d.path().join("k.key")).expect("key"), before);
    let out = rdy(
        d.path(),
        &["spec", "keygen", "k", "--force"],
        Some(PASSWORD),
        "",
    );
    assert_eq!(code(&out), 64, "there is no --force for keygen");

    let sign = |extra: &[&str]| {
        let mut args = vec![
            "spec",
            "sign",
            "acme-platform.yaml",
            "--secret-key",
            "k.key",
        ];
        args.extend_from_slice(extra);
        rdy(d.path(), &args, Some(PASSWORD), "")
    };
    assert_eq!(code(&sign(&[])), 0);
    let first = std::fs::read(d.path().join("acme-platform.yaml.minisig")).expect("sig");
    let out = sign(&[]);
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("--force"));
    assert_eq!(
        std::fs::read(d.path().join("acme-platform.yaml.minisig")).expect("sig"),
        first
    );
    assert_eq!(code(&sign(&["--force"])), 0);
    assert_verifies(d.path(), "k");
}

#[test]
fn the_password_flag_is_still_refused() {
    let d = tempfile::tempdir().expect("tempdir");
    let out = rdy(
        d.path(),
        &["spec", "keygen", "k", "--password", "CANARY-7f3a"],
        None,
        "",
    );
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("shell history"));
    assert!(!stderr(&out).contains("CANARY"));
    assert!(!d.path().join("k.key").exists());
}
