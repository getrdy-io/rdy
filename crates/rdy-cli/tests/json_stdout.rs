//! `--json` stdout hygiene on the exit paths of the built binary (M1-088, 07 section 4.1).
//!
//! Each row runs `rdy` with `--json --color always`, the setting most likely to leak a colour code into
//! the data stream. Stdout must be one JSON document and a final newline: UTF-8, no BOM, no escape byte.
//! A Report must validate and equal the `.json` file byte for byte. An error object must validate and
//! carry the row's stable code.
//!
//! Proven here, with the real binary: exit 0, 1 and 2 on Linux legs only (synthetic one-check specs on `host.cpu`, so the
//! verdict does not depend on the machine), `--no-report`, and exit 64 for a bad flag, a missing file,
//! malformed YAML, a schema-invalid spec, an expired spec, an unsigned spec, a tampered signature, an
//! unknown key and (Unix) an insecure trust store, and exit 70 `report_write` before any check.
//!
//! Proven elsewhere. The watchdog path (blocked stdout, exit 70, a `complete: false` report in the
//! folder) is `run_watchdog.rs` and `run_watchdog_binary.rs` (M1-176, PC-51). The interrupt path is
//! `run_interrupt.rs` (M1-058). "Files not written after the verdict" is the `run_cmd` unit tests, which
//! hold that stdout already has the document (PC-50); neither of those is run with `--color always` here.
//! The static line is `run_static_line_pty.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jsonschema::Validator;
use serde_json::Value;

mod common;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// Used by the Linux verdict tests and the Unix signed tests only.
#[cfg_attr(not(unix), allow(dead_code))]
fn report_validator() -> Validator {
    let path = repo().join("crates/rdy-spec/schema/result.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let schema: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema does not build: {e}"))
}

/// A one-check spec on `host.cpu`. Every machine has at least one CPU and none has 100000. The verdicts
/// are stable on Linux only: `host.cpu` reports "not yet on this OS" on macOS and Windows.
fn cpu_spec(min: u32, severity: &str) -> String {
    format!(
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-json\nchecks:\n  - id: host.cpu\n    min: {min}\n    severity: {severity}\n    fix: \"Use a machine with more cores.\"\n"
    )
}

/// Runs `rdy <args> --json --color always` in `dir`, with `home` as the user's home.
fn run(dir: &Path, home: &Path, args: &[&str]) -> Output {
    common::quiet(
        Command::new(env!("CARGO_BIN_EXE_rdy"))
            .args(args)
            .args(["--json", "--color", "always"])
            .current_dir(dir)
            .env("HOME", home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RDY_PROGRESS")
            .env_remove("RUST_LOG")
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR")
            .env_remove("COLUMNS")
            .output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}")),
    )
}

/// The one document on stdout, after the byte rules.
fn document(out: &Output, row: &str) -> (String, Value) {
    let stdout = String::from_utf8(out.stdout.clone())
        .unwrap_or_else(|e| panic!("{row}: stdout is not UTF-8: {e}"));
    assert!(!stdout.starts_with('\u{feff}'), "{row}: a BOM");
    assert!(
        !stdout.contains('\u{1b}'),
        "{row}: an escape byte: {stdout}"
    );
    assert!(!stdout.contains('\r'), "{row}: a CR");
    assert!(stdout.ends_with("}\n"), "{row}: {stdout:?}");
    assert!(!stdout.ends_with("\n\n"), "{row}: more than one newline");
    // `from_str` refuses a second document or any trailing text.
    let doc = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{row}: stdout is not one JSON document ({e}): {stdout}"));
    (stdout, doc)
}

fn assert_valid(validator: &Validator, doc: &Value, row: &str) {
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .take(10)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{row}: {errors:#?}");
}

/// The `.json` files in the folders under `parent`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn json_files(parent: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in std::fs::read_dir(parent).into_iter().flatten().flatten() {
        let path = dir.path();
        if !path.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(&path).into_iter().flatten().flatten() {
            if file.path().extension().is_some_and(|x| x == "json") {
                found.push(file.path());
            }
        }
    }
    found
}

fn temp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"))
}

fn write(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap_or_else(|e| panic!("cannot write {name}: {e}"));
}

fn copy(from: &Path, dir: &Path, name: &str) {
    std::fs::copy(from, dir.join(name))
        .unwrap_or_else(|e| panic!("cannot copy {}: {e}", from.display()));
}

// Linux only, because `host.cpu` is not built for macOS and Windows yet (see `cpu_spec`). No check gives
// a stable pass, warn and block on all five legs, so exit 0, 1 and 2 are proved on the Linux legs; the
// error rows below run everywhere.
#[cfg(target_os = "linux")]
#[test]
fn exit_0_1_and_2_print_the_report_that_the_json_file_holds() {
    // (row, spec, exit code)
    let rows = [
        ("ready", cpu_spec(1, "block"), 0),
        ("warnings", cpu_spec(100_000, "warn"), 1),
        ("blocked", cpu_spec(100_000, "block"), 2),
    ];
    let validator = report_validator();
    for (row, spec, exit) in rows {
        let (dir, home) = (temp(), temp());
        write(dir.path(), "spec.yaml", &spec);
        std::fs::create_dir(dir.path().join("reports")).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let out = run(
            dir.path(),
            home.path(),
            &[
                "run",
                "spec.yaml",
                "--allow-unsigned",
                "--no-network",
                "--out-dir",
                "reports",
            ],
        );
        assert_eq!(out.status.code(), Some(exit), "{row}: {out:?}");
        let (stdout, doc) = document(&out, row);
        assert_valid(&validator, &doc, row);
        assert_eq!(doc["kind"], "Report", "{row}");
        assert_eq!(doc["complete"], true, "{row}");
        assert_eq!(doc["exit_code"], exit, "{row}");
        let files = json_files(&dir.path().join("reports"));
        assert_eq!(files.len(), 1, "{row}: {files:?}");
        assert_eq!(
            std::fs::read_to_string(&files[0]).unwrap_or_default(),
            stdout,
            "{row}: stdout and the .json file differ"
        );
        // The colour went where colour belongs: the human result on stderr.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains('\u{1b}'), "{row}: no colour on stderr");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn no_report_still_prints_the_whole_report_and_makes_no_folder() {
    for (spec, exit) in [(cpu_spec(1, "block"), 0), (cpu_spec(100_000, "block"), 2)] {
        let (dir, home) = (temp(), temp());
        write(dir.path(), "spec.yaml", &spec);
        let out = run(
            dir.path(),
            home.path(),
            &[
                "run",
                "spec.yaml",
                "--allow-unsigned",
                "--no-network",
                "--no-report",
            ],
        );
        assert_eq!(out.status.code(), Some(exit), "{out:?}");
        let (_, doc) = document(&out, "no-report");
        assert_valid(&report_validator(), &doc, "no-report");
        assert_eq!(doc["kind"], "Report");
        assert_eq!(doc["complete"], true);
        assert_eq!(doc["exit_code"], exit);
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap_or_else(|e| panic!("cannot list: {e}"))
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["spec.yaml"], "a folder or file was made");
    }
}

/// What a row puts in its folder before the run.
enum Setup {
    /// Nothing but a valid spec as `spec.yaml`.
    Valid,
    /// Nothing at all.
    Nothing,
    /// A fixture from `tests/fixtures/specs` as `spec.yaml`.
    Fixture(&'static str),
}

#[test]
fn the_error_paths_print_one_error_object_with_no_colour_code() {
    let validator = common::error_output_validator();
    // (row, setup, args, exit code, stable code)
    let rows: [(&str, Setup, &[&str], i32, &str); 8] = [
        ("bad-flag", Setup::Nothing, &["--bogus"], 64, "usage"),
        (
            "missing-file",
            Setup::Nothing,
            &["run", "no-such-spec.yaml", "--allow-unsigned"],
            64,
            "spec_unreadable",
        ),
        (
            "malformed-yaml",
            Setup::Fixture("malformed/anchor.yaml"),
            &["run", "spec.yaml", "--allow-unsigned"],
            64,
            "spec_parse",
        ),
        (
            "schema-invalid",
            Setup::Fixture("invalid/bad-product.yaml"),
            &["run", "spec.yaml", "--allow-unsigned"],
            64,
            "spec_invalid",
        ),
        (
            "expired",
            Setup::Fixture("invalid/expired.yaml"),
            &["run", "spec.yaml", "--allow-unsigned"],
            64,
            "spec_expired",
        ),
        (
            "unsigned",
            Setup::Valid,
            &["run", "spec.yaml"],
            64,
            "spec_unsigned",
        ),
        (
            "too-many-hosts",
            Setup::Fixture("invalid/too-many-hosts-across-checks.yaml"),
            &["run", "spec.yaml", "--allow-unsigned"],
            64,
            "spec_invalid",
        ),
        (
            "unwritable-out-dir",
            Setup::Valid,
            &[
                "run",
                "spec.yaml",
                "--allow-unsigned",
                "--no-network",
                "--out-dir",
                "no-such-dir/reports",
            ],
            70,
            "report_write",
        ),
    ];
    for (row, setup, args, exit, code) in rows {
        let (dir, home) = (temp(), temp());
        match setup {
            Setup::Nothing => {}
            Setup::Valid => write(dir.path(), "spec.yaml", &cpu_spec(1, "block")),
            Setup::Fixture(name) => copy(
                &repo().join("tests/fixtures/specs").join(name),
                dir.path(),
                "spec.yaml",
            ),
        }
        let out = run(dir.path(), home.path(), args);
        assert_eq!(out.status.code(), Some(exit), "{row}: {out:?}");
        let (_, doc) = document(&out, row);
        assert_valid(&validator, &doc, row);
        assert_eq!(doc["kind"], "Error", "{row}");
        assert_eq!(doc["error"]["code"], code, "{row}: {doc}");
        assert_eq!(doc["complete"], false, "{row}");
    }
}

/// The signed-spec rows read the user trust store, so they skip for root (a root run reads only
/// `/etc/rdy/trust.yaml`) and do not exist on Windows (no user store).
#[cfg(unix)]
mod signed {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn fixtures() -> PathBuf {
        repo().join("tests/fixtures/signed")
    }

    fn root() -> bool {
        let root = rustix::process::geteuid().is_root();
        if root {
            eprintln!("skipped: a root run reads only /etc/rdy/trust.yaml");
        }
        root
    }

    /// A folder with the signed spec and its sidecar, and a home that has pinned the vendor key when
    /// `pinned`.
    fn setup(pinned: bool) -> (tempfile::TempDir, tempfile::TempDir) {
        let (dir, home) = (temp(), temp());
        let signed = fixtures();
        copy(&signed.join("acme-platform.yaml"), dir.path(), "spec.yaml");
        copy(
            &signed.join("acme-platform.yaml.minisig"),
            dir.path(),
            "spec.yaml.minisig",
        );
        if pinned {
            let pin = Command::new(env!("CARGO_BIN_EXE_rdy"))
                .args(["trust", "add", "acme-platform", "--key"])
                .arg(signed.join("acme-platform.pub"))
                .arg("--yes")
                .env("HOME", home.path())
                .env_remove("XDG_CONFIG_HOME")
                .output()
                .unwrap_or_else(|e| panic!("rdy did not start: {e}"));
            assert_eq!(pin.status.code(), Some(0), "{pin:?}");
        }
        (dir, home)
    }

    fn error_row(row: &str, dir: &Path, home: &Path, code: &str) {
        let out = run(
            dir,
            home,
            &["run", "spec.yaml", "--no-network", "--no-report"],
        );
        assert_eq!(out.status.code(), Some(64), "{row}: {out:?}");
        let (_, doc) = document(&out, row);
        assert_valid(&common::error_output_validator(), &doc, row);
        assert_eq!(doc["kind"], "Error", "{row}");
        assert_eq!(doc["error"]["code"], code, "{row}: {doc}");
        assert_eq!(doc["complete"], false, "{row}");
    }

    #[test]
    fn a_tampered_signature_is_spec_signature_invalid() {
        if root() {
            return;
        }
        let (dir, home) = setup(true);
        let mut bytes = std::fs::read(dir.path().join("spec.yaml")).unwrap_or_default();
        bytes.extend(b"# edited\n");
        std::fs::write(dir.path().join("spec.yaml"), bytes)
            .unwrap_or_else(|e| panic!("cannot write: {e}"));
        error_row(
            "tampered",
            dir.path(),
            home.path(),
            "spec_signature_invalid",
        );
    }

    #[test]
    fn a_key_that_is_not_pinned_is_spec_key_unknown() {
        if root() {
            return;
        }
        let (dir, home) = setup(false);
        error_row("unknown-key", dir.path(), home.path(), "spec_key_unknown");
    }

    #[test]
    fn a_store_others_can_write_is_trust_store_insecure() {
        if root() {
            return;
        }
        let (dir, home) = setup(true);
        let store = home.path().join(".config/rdy/trust.yaml");
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o666))
            .unwrap_or_else(|e| panic!("cannot chmod {}: {e}", store.display()));
        error_row(
            "insecure-store",
            dir.path(),
            home.path(),
            "trust_store_insecure",
        );
    }

    #[test]
    fn a_pinned_signed_spec_prints_a_report() {
        if root() {
            return;
        }
        let (dir, home) = setup(true);
        let out = run(
            dir.path(),
            home.path(),
            &["run", "spec.yaml", "--no-network", "--no-report"],
        );
        let (_, doc) = document(&out, "signed");
        assert_valid(&report_validator(), &doc, "signed");
        assert_eq!(doc["signature"]["state"], "verified", "{doc}");
    }
}
