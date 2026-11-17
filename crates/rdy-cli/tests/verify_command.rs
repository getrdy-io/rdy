//! `rdy verify`, `rdy run --key` and the refusals of spec loading, through the built binary (M1-126).
//!
//! The exit test of the ticket, in pieces:
//!
//! - every code of 01 section 4.8 comes out of a fixture, with the first line of the table and a fix that
//!   does not name the flag that allows an unsigned spec, in text and in JSON;
//! - `--allow-unsigned` still exits 64 for an unpinned key, a signature that does not verify, an
//!   unreadable sidecar, a sidecar that is not a file and an empty one, and no folder is made;
//! - `verify --key` prints the KEY NOT PINNED banner and `VERIFIED, KEY NOT PINNED` (golden for 07 C.4),
//!   and its JSON validates against the `Verification` definition;
//! - a `--key` run reads no trust store, so a store that is refused cannot stop it (ADR 0027).
//!
//! Signatures that the fixtures do not hold (another product, an expiry) are made here with the stock
//! `minisign` crate and a key that is thrown away.
// Helper functions in tests/ are not covered by clippy.toml, and a failed spawn must fail the test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use rdy_engine::testing::golden::assert_golden;
use serde_json::Value;

mod common;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = repo().join("tests/fixtures").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// A folder to run in, with its own empty home, so no trust store of the machine is read.
struct Dir {
    dir: tempfile::TempDir,
}

impl Dir {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn put(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path().join(name), bytes).expect("write");
    }

    /// The signed fixture: the spec, its signature and its key.
    fn with_signed_fixture(&self) {
        self.put("acme-platform.yaml", &fixture("signed/acme-platform.yaml"));
        self.put(
            "acme-platform.yaml.minisig",
            &fixture("signed/acme-platform.yaml.minisig"),
        );
        self.put("acme-platform.pub", &fixture("signed/acme-platform.pub"));
        self.put("other.pub", &fixture("minisign-c/acme-platform.pub"));
    }

    fn rdy(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
        cmd.args(args)
            .args(["--color", "never"])
            .current_dir(self.path())
            .env("HOME", self.path().join("home"))
            .env("ProgramData", self.path().join("ProgramData"))
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RDY_PROGRESS")
            .env_remove("RUST_LOG")
            .env_remove("COLUMNS")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        common::quiet(cmd.output().expect("the rdy binary starts"))
    }

    /// True when a report folder was made here.
    fn has_report_folder(&self) -> bool {
        std::fs::read_dir(self.path())
            .expect("read_dir")
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().starts_with("rdy-report-"))
    }
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("rdy was not killed by a signal")
}

fn stderr(out: &Output) -> String {
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    if cfg!(windows) {
        text.replace("\r\n", "\n")
    } else {
        text
    }
}

fn json(out: &Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {text}"))
}

fn validator(def: &str) -> jsonschema::Validator {
    let path = repo().join("crates/rdy-spec/schema/result.v1.schema.json");
    let source = std::fs::read_to_string(&path).expect("schema");
    let mut schema: Value = serde_json::from_str(&source).expect("schema is JSON");
    schema["$ref"] = Value::String(format!("#/$defs/{def}"));
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("schema builds")
}

fn assert_valid(validator: &jsonschema::Validator, doc: &Value) {
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}\n{doc}");
}

/// A key pair that is thrown away, and a signature file over `bytes` with `comment`.
fn sign(bytes: &[u8], comment: &str) -> (String, String) {
    let pair = minisign::KeyPair::generate_unencrypted_keypair().expect("keypair");
    let sig = minisign::sign(
        Some(&pair.pk),
        &pair.sk,
        Cursor::new(bytes),
        Some(comment),
        None,
    )
    .expect("sign")
    .into_string();
    (pair.pk.to_base64(), sig)
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\nchecks:\n  - id: host.cpu\n    min: 1\n    severity: block\n";

// ---------------------------------------------------------------------------------------------
// verify: the output
// ---------------------------------------------------------------------------------------------

#[test]
fn verify_with_a_one_run_key_prints_the_banner_and_ends_verified_key_not_pinned() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    let out = dir.rdy(&["verify", "acme-platform.yaml", "--key", "acme-platform.pub"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert_golden(
        repo().join("tests/fixtures/verify/key-not-pinned.stderr.txt"),
        stderr(&out),
    );
}

#[test]
fn verify_json_is_a_verification_that_validates_and_says_the_key_was_not_pinned() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    let out = dir.rdy(&[
        "verify",
        "acme-platform.yaml",
        "--key",
        "acme-platform.pub",
        "--json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let doc = json(&out);
    assert_valid(&validator("Verification"), &doc);
    assert_eq!(doc["kind"], "Verification");
    assert_eq!(doc["signature"]["state"], "verified");
    assert_eq!(doc["signature"]["trust_source"], "flag");
    assert_eq!(doc["signature"]["product"], "acme-platform");
    assert_eq!(doc["spec"]["file_name"], "acme-platform.yaml");
    // The text is still on stderr, and the banner is not on stdout.
    assert!(stderr(&out).contains("WARNING: KEY NOT PINNED"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("WARNING"));
}

#[test]
fn verify_takes_no_allow_unsigned_flag() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    let out = dir.rdy(&["verify", "acme-platform.yaml", "--allow-unsigned"]);
    assert_eq!(code(&out), 64);
    assert!(
        stderr(&out).starts_with("error: unknown option or argument"),
        "{}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------------------------
// Every code of 01 section 4.8
// ---------------------------------------------------------------------------------------------

struct Refusal {
    name: &'static str,
    code: &'static str,
    first_line: String,
}

/// Runs `args` in `dir` as `verify` and as `verify --json`, and checks both against the row.
fn assert_refused(dir: &Dir, args: &[&str], row: &Refusal) {
    let out = dir.rdy(args);
    assert_eq!(code(&out), 64, "{}: {}", row.name, stderr(&out));
    assert!(out.stdout.is_empty(), "{}", row.name);
    let text = stderr(&out);
    assert!(
        text.starts_with(&format!("error: {}", row.first_line)),
        "{}: {text}",
        row.name
    );
    assert_eq!(text.lines().count(), 2, "{}: {text}", row.name);
    assert!(text.lines().nth(1).is_some_and(|l| l.starts_with("fix: ")));
    assert!(!text.contains("--allow-unsigned"), "{}: {text}", row.name);

    let mut with_json = args.to_vec();
    with_json.push("--json");
    let out = dir.rdy(&with_json);
    assert_eq!(code(&out), 64, "{}", row.name);
    let doc = json(&out);
    assert_valid(&validator("ErrorOutput"), &doc);
    assert_eq!(doc["error"]["code"], row.code, "{}: {doc}", row.name);
    let message = doc["error"]["message"].as_str().unwrap_or_default();
    assert!(message.starts_with(&row.first_line), "{}: {doc}", row.name);
    let fix = doc["error"]["fix"].as_str().unwrap_or_default();
    assert!(
        !fix.is_empty() && !fix.contains("--allow-unsigned"),
        "{doc}"
    );
    assert_eq!(stderr(&out), text, "{}: JSON and text differ", row.name);
}

#[test]
fn every_code_of_the_spec_loading_table_comes_out_of_a_fixture() {
    // spec_unreadable
    let dir = Dir::new();
    assert_refused(
        &dir,
        &["verify", "no-such.yaml"],
        &Refusal {
            name: "spec_unreadable",
            code: "spec_unreadable",
            first_line: "cannot read no-such.yaml: no such file".to_owned(),
        },
    );

    // spec_unsigned: no sidecar.
    let dir = Dir::new();
    dir.with_signed_fixture();
    std::fs::remove_file(dir.path().join("acme-platform.yaml.minisig")).expect("rm");
    assert_refused(
        &dir,
        &["verify", "acme-platform.yaml"],
        &Refusal {
            name: "spec_unsigned",
            code: "spec_unsigned",
            first_line: "no signature found at acme-platform.yaml.minisig".to_owned(),
        },
    );

    // spec_key_unknown: the signature is by a key that is not the one given. With `--key` only that key
    // is considered, so this does not depend on a trust store.
    let dir = Dir::new();
    dir.with_signed_fixture();
    let id = String::from_utf8_lossy(&fixture("signed/acme-platform.yaml.minisig")).into_owned();
    assert!(id.contains("trusted comment: rdy-spec-v1"));
    assert_refused(
        &dir,
        &["verify", "acme-platform.yaml", "--key", "other.pub"],
        &Refusal {
            name: "spec_key_unknown",
            code: "spec_key_unknown",
            first_line: "acme-platform.yaml is signed with key ".to_owned(),
        },
    );

    // spec_signature_invalid: tampered.
    let dir = Dir::new();
    dir.with_signed_fixture();
    let mut bytes = fixture("signed/acme-platform.yaml");
    bytes.extend(b"# edited\n");
    dir.put("acme-platform.yaml", &bytes);
    let tampered = Refusal {
        name: "tampered",
        code: "spec_signature_invalid",
        first_line: "the signature on acme-platform.yaml does not match the file. It may have been changed after signing.".to_owned(),
    };
    assert_refused(
        &dir,
        &["verify", "acme-platform.yaml", "--key", "acme-platform.pub"],
        &tampered,
    );

    // The same file with Windows line endings: the note comes after the first sentence.
    let crlf = String::from_utf8_lossy(&fixture("signed/acme-platform.yaml")).replace('\n', "\r\n");
    dir.put("acme-platform.yaml", crlf.as_bytes());
    assert_refused(
        &dir,
        &["verify", "acme-platform.yaml", "--key", "acme-platform.pub"],
        &Refusal {
            name: "crlf",
            code: "spec_signature_invalid",
            first_line: format!(
                "{} The file has Windows line endings. If it went through Git or email, ask for the original.",
                tampered.first_line
            ),
        },
    );

    // spec_signature_invalid: form.
    dir.put("acme-platform.yaml", &fixture("signed/acme-platform.yaml"));
    dir.put("acme-platform.yaml.minisig", b"not a signature\n");
    assert_refused(
        &dir,
        &["verify", "acme-platform.yaml", "--key", "acme-platform.pub"],
        &Refusal {
            name: "form",
            code: "spec_signature_invalid",
            first_line: "the signature on acme-platform.yaml is not in the form rdy accepts."
                .to_owned(),
        },
    );

    // spec_signature_invalid: product. Signed for acme-edge, says acme-platform.
    let dir = Dir::new();
    let (key, sig) = sign(
        SPEC.as_bytes(),
        "rdy-spec-v1 product=acme-edge signed_at=2026-11-30T16:02:11Z",
    );
    dir.put("s.yaml", SPEC.as_bytes());
    dir.put("s.yaml.minisig", sig.as_bytes());
    assert_refused(
        &dir,
        &["verify", "s.yaml", "--key", &key],
        &Refusal {
            name: "product",
            code: "spec_signature_invalid",
            first_line:
                "s.yaml is signed for product 'acme-edge', but the spec says 'acme-platform'."
                    .to_owned(),
        },
    );

    // spec_expired.
    let expired = SPEC.replace(
        "  product: acme-platform\n",
        "  product: acme-platform\n  expires: 2020-01-31T00:00:00Z\n",
    );
    let (key, sig) = sign(
        expired.as_bytes(),
        "rdy-spec-v1 product=acme-platform signed_at=2019-11-30T16:02:11Z",
    );
    dir.put("e.yaml", expired.as_bytes());
    dir.put("e.yaml.minisig", sig.as_bytes());
    let out = dir.rdy(&["verify", "e.yaml", "--key", &key]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        text.starts_with("error: e.yaml expired on 2020-01-31. This machine's clock says 20"),
        "{text}"
    );
    assert!(
        text.contains("\nfix: ask the vendor for a current spec."),
        "{text}"
    );
    let out = dir.rdy(&["verify", "e.yaml", "--key", &key, "--json"]);
    assert_eq!(json(&out)["error"]["code"], "spec_expired");
}

#[cfg(unix)]
#[test]
fn a_trust_store_that_others_can_write_is_trust_store_insecure() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        eprintln!("skipped: a root run reads only /etc/rdy/trust.yaml");
        return;
    }
    let dir = Dir::new();
    dir.with_signed_fixture();
    let store_dir = dir.path().join("home/.config/rdy");
    std::fs::create_dir_all(&store_dir).expect("mkdir");
    std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let store = store_dir.join("trust.yaml");
    std::fs::write(&store, "apiVersion: rdy/v1\nkind: TrustStore\nkeys: []\n").expect("write");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    let out = dir.rdy(&["verify", "acme-platform.yaml", "--json"]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert_eq!(json(&out)["error"]["code"], "trust_store_insecure");
    // `--key` never reads the store, so the same refused store does not stop it (ADR 0027).
    let out = dir.rdy(&["verify", "acme-platform.yaml", "--key", "acme-platform.pub"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

// ---------------------------------------------------------------------------------------------
// --allow-unsigned never waves a present signature through
// ---------------------------------------------------------------------------------------------

/// A run with the flag on, in a folder with no report folder yet. It must exit 64, say nothing on stdout
/// and make no folder, and no line of the refusal may name the flag.
fn assert_refused_even_with_the_flag(dir: &Dir, extra: &[&str], what: &str) {
    let mut args = vec![
        "run",
        "acme-platform.yaml",
        "--allow-unsigned",
        "--no-network",
    ];
    args.extend(extra);
    let out = dir.rdy(&args);
    let text = stderr(&out);
    assert_eq!(code(&out), 64, "{what}: {text}");
    assert!(out.stdout.is_empty(), "{what}");
    assert!(!dir.has_report_folder(), "{what}: a folder was made");
    assert!(text.starts_with("error: "), "{what}: {text}");
    assert!(!text.contains("--allow-unsigned"), "{what}: {text}");
    assert!(!text.contains("WARNING: UNSIGNED"), "{what}: {text}");

    args.push("--json");
    let out = dir.rdy(&args);
    assert_eq!(code(&out), 64, "{what}");
    let doc = json(&out);
    assert_valid(&validator("ErrorOutput"), &doc);
    let body = doc["error"].to_string();
    assert!(!body.contains("--allow-unsigned"), "{what}: {body}");
}

#[test]
fn allow_unsigned_still_exits_64_for_an_unpinned_key() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    // No store holds the key (a fresh home), and a different key is not it either.
    assert_refused_even_with_the_flag(
        &dir,
        &["--key", "other.pub"],
        "a key that is not the signer",
    );
}

#[test]
fn allow_unsigned_still_exits_64_for_a_signature_that_does_not_verify() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    let mut bytes = fixture("signed/acme-platform.yaml");
    bytes.extend(b"# edited\n");
    dir.put("acme-platform.yaml", &bytes);
    assert_refused_even_with_the_flag(&dir, &["--key", "acme-platform.pub"], "tampered");
    // Without a key the signer is unknown, which is also a refusal.
    assert_refused_even_with_the_flag(&dir, &[], "tampered, no key");
}

#[test]
fn allow_unsigned_still_exits_64_for_a_key_with_no_signature() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    std::fs::remove_file(dir.path().join("acme-platform.yaml.minisig")).expect("rm");
    // A key means the person wants a signature checked. A spec with none is refused.
    assert_refused_even_with_the_flag(&dir, &["--key", "acme-platform.pub"], "key, no signature");
}

#[test]
fn allow_unsigned_still_exits_64_for_a_sidecar_that_is_there_but_is_not_a_signature() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    // Empty.
    dir.put("acme-platform.yaml.minisig", b"");
    assert_refused_even_with_the_flag(&dir, &[], "an empty sidecar");
    // A folder.
    std::fs::remove_file(dir.path().join("acme-platform.yaml.minisig")).expect("rm");
    std::fs::create_dir(dir.path().join("acme-platform.yaml.minisig")).expect("mkdir");
    assert_refused_even_with_the_flag(&dir, &[], "a folder");
    let out = dir.rdy(&["verify", "acme-platform.yaml"]);
    assert!(
        stderr(&out).starts_with(
            "error: the signature on acme-platform.yaml is not in the form rdy accepts."
        ),
        "{}",
        stderr(&out)
    );
}

#[cfg(unix)]
#[test]
fn allow_unsigned_still_exits_64_for_a_dangling_link_and_a_sidecar_nobody_may_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new();
    dir.with_signed_fixture();
    let sidecar = dir.path().join("acme-platform.yaml.minisig");
    std::fs::remove_file(&sidecar).expect("rm");
    std::os::unix::fs::symlink("nowhere.minisig", &sidecar).expect("symlink");
    assert_refused_even_with_the_flag(&dir, &[], "a link to nothing");

    std::fs::remove_file(&sidecar).expect("rm");
    dir.put(
        "acme-platform.yaml.minisig",
        &fixture("signed/acme-platform.yaml.minisig"),
    );
    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::File::open(&sidecar).is_ok() {
        eprintln!("skipped the permission-denied row: this user can read a 0000 file (root)");
        return;
    }
    assert_refused_even_with_the_flag(&dir, &[], "permission denied");
}

#[test]
fn a_sig_file_that_does_not_exist_is_a_usage_error_even_with_the_flag() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    let out = dir.rdy(&[
        "run",
        "acme-platform.yaml",
        "--allow-unsigned",
        "--sig",
        "missing.minisig",
        "--json",
    ]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    let doc = json(&out);
    assert_eq!(doc["error"]["code"], "usage");
    assert!(
        doc["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("cannot read the signature file missing.minisig"),
        "{doc}"
    );
    assert!(!doc["error"].to_string().contains("--allow-unsigned"));
    assert!(!dir.has_report_folder());
}

#[test]
fn an_env_variable_cannot_allow_an_unsigned_spec() {
    // INV-05: the flag is read from argv only.
    let dir = Dir::new();
    dir.with_signed_fixture();
    std::fs::remove_file(dir.path().join("acme-platform.yaml.minisig")).expect("rm");
    let out = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(["run", "acme-platform.yaml", "--color", "never"])
        .current_dir(dir.path())
        .env("RDY_ALLOW_UNSIGNED", "1")
        .env("HOME", dir.path().join("home"))
        .output()
        .expect("rdy starts");
    assert_eq!(out.status.code(), Some(64));
    assert!(!dir.has_report_folder());
}

// ---------------------------------------------------------------------------------------------
// `--key` runs
// ---------------------------------------------------------------------------------------------

#[test]
fn run_with_a_one_run_key_prints_the_banner_and_marks_the_report() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    let out = dir.rdy(&[
        "run",
        "acme-platform.yaml",
        "--key",
        "acme-platform.pub",
        "--no-network",
        "--no-report",
        "--json",
    ]);
    let text = stderr(&out);
    assert!(matches!(code(&out), 1 | 2), "{}: {text}", code(&out));
    let doc = json(&out);
    assert_eq!(doc["signature"]["state"], "verified");
    assert_eq!(doc["signature"]["trust_source"], "flag");
    assert_eq!(doc["run"]["options"]["allow_unsigned"], false);
    // The banner comes first and again above the verdict (01 section 4.7).
    assert_eq!(
        text.lines().next(),
        Some("WARNING: KEY NOT PINNED"),
        "{text}"
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[lines.len() - 2], "WARNING: KEY NOT PINNED", "{text}");
    assert!(!text.contains("--allow-unsigned"), "{text}");
}

#[test]
fn a_secret_key_given_to_verify_is_refused_and_never_echoed() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    dir.put(
        "acme-platform.key",
        &fixture("minisign-c/acme-platform.key"),
    );
    let out = dir.rdy(&["verify", "acme-platform.yaml", "--key", "acme-platform.key"]);
    assert_eq!(code(&out), 64);
    assert!(stderr(&out).contains("is a secret key, not a public key"));
}

// ---------------------------------------------------------------------------------------------
// 07 section C.8: `rdy spec lint`
// ---------------------------------------------------------------------------------------------

#[test]
fn lint_output_matches_the_c8_goldens() {
    let dir = Dir::new();
    dir.put(
        "acme-platform.yaml",
        &std::fs::read(repo().join("examples/specs/acme-platform.yaml")).expect("example"),
    );
    let out = dir.rdy(&["spec", "lint", "acme-platform.yaml"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert_golden(
        repo().join("tests/fixtures/verify/lint-acme-platform.stderr.txt"),
        stderr(&out),
    );

    // Two errors, at the lines and columns of the sample: an unknown field and a check with no threshold.
    let mut lines = vec!["apiVersion: rdy/v1", "kind: Readiness", "metadata:"];
    lines.extend(["  product: acme-platform", "checks:"]);
    lines.extend(std::iter::repeat_n("#", 17));
    lines.extend(["  - id: host.memory", "    mn: 32Gi"]);
    lines.extend(std::iter::repeat_n("#", 5));
    lines.push("  - id: host.cpu");
    dir.put(
        "acme-typo.yaml",
        format!("{}\n", lines.join("\n")).as_bytes(),
    );
    let out = dir.rdy(&["spec", "lint", "acme-typo.yaml"]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert_golden(
        repo().join("tests/fixtures/verify/lint-acme-typo.stderr.txt"),
        stderr(&out),
    );
}

#[cfg(unix)]
#[test]
fn a_root_run_with_no_matching_key_says_it_reads_only_the_system_store() {
    let dir = Dir::new();
    dir.with_signed_fixture();
    let out = dir.rdy(&["verify", "acme-platform.yaml"]);
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    let text = stderr(&out);
    let root = rustix::process::geteuid().is_root();
    assert_eq!(
        text.contains("As root, rdy reads only /etc/rdy/trust.yaml."),
        root,
        "{text}"
    );
    // `--key` runs name no store at all.
    let out = dir.rdy(&["verify", "acme-platform.yaml", "--key", "other.pub"]);
    assert!(!stderr(&out).contains("As root"), "{}", stderr(&out));
}
