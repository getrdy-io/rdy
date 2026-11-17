//! `--json` stdout hygiene on every exit path of the built binary (M1-088, 07 section 4.1).
//!
//! Each row runs `rdy` with `--json --color always`, the setting most likely to leak a colour code into
//! the data stream. Stdout must be one JSON document and a final newline: UTF-8, no BOM, no escape byte.
//! A Report must validate and equal the `.json` file byte for byte (and must exist with `--no-report`
//! too). An error object must validate and carry the row's stable code.
//!
//! Not here. The watchdog path (blocked stdout, exit 70, a `complete: false` report in the folder) is
//! proved by `run_watchdog.rs` and `run_watchdog_binary.rs` (M1-176, PC-51). The interrupt path is
//! `run_interrupt.rs` (M1-058), and the unit tests of `run_cmd` hold "files not written after the
//! verdict" with a stdout that already has the document (PC-50). The static line is
//! `run_static_line_pty.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jsonschema::Validator;
use serde_json::Value;

mod common;

fn quickstart() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs/acme-quickstart.yaml")
}

fn report_validator() -> Validator {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let schema: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema does not build: {e}"))
}

/// Runs `rdy <args> --json --color always` in a fresh folder that holds `spec.yaml`.
fn run(dir: &Path, args: &[&str]) -> Output {
    std::fs::copy(quickstart(), dir.join("spec.yaml"))
        .unwrap_or_else(|e| panic!("cannot copy the spec: {e}"));
    common::quiet(
        Command::new(env!("CARGO_BIN_EXE_rdy"))
            .args(args)
            .args(["--json", "--color", "always"])
            .current_dir(dir)
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

#[test]
fn a_run_prints_the_report_that_the_json_file_holds_with_no_colour_code() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    // The report folder is made inside `reports`, which `rdy` does not create.
    std::fs::create_dir(dir.path().join("reports")).unwrap_or_else(|e| panic!("mkdir: {e}"));
    let out = run(
        dir.path(),
        &[
            "run",
            "spec.yaml",
            "--allow-unsigned",
            "--no-network",
            "--out-dir",
            "reports",
        ],
    );
    let (stdout, doc) = document(&out, "run");
    assert_valid(&report_validator(), &doc, "run");
    assert_eq!(doc["kind"], "Report");
    assert_eq!(doc["complete"], true);
    let code = out.status.code().unwrap_or(-1);
    assert!(matches!(code, 0..=2), "{code}");
    assert_eq!(i64::from(code), doc["exit_code"].as_i64().unwrap_or(99));
    // The same bytes as the file.
    let files = json_files(&dir.path().join("reports"));
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(
        std::fs::read_to_string(&files[0]).unwrap_or_default(),
        stdout
    );
    // The colour went where colour belongs: the human result on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains('\u{1b}'),
        "colour is off on stderr: {stderr}"
    );
}

#[test]
fn no_report_still_prints_the_whole_report_and_makes_no_folder() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let out = run(
        dir.path(),
        &[
            "run",
            "spec.yaml",
            "--allow-unsigned",
            "--no-network",
            "--no-report",
        ],
    );
    let (_, doc) = document(&out, "no-report");
    assert_valid(&report_validator(), &doc, "no-report");
    assert_eq!(doc["kind"], "Report");
    assert_eq!(doc["complete"], true);
    assert_eq!(
        i64::from(out.status.code().unwrap_or(-1)),
        doc["exit_code"].as_i64().unwrap_or(99)
    );
    let left: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap_or_else(|e| panic!("cannot list: {e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["spec.yaml"], "a folder or file was made");
}

#[test]
fn the_error_paths_print_one_error_object_with_no_colour_code() {
    let validator = common::error_output_validator();
    // (row, args, exit code, stable code)
    let rows: [(&str, &[&str], i32, &str); 4] = [
        ("bad-flag", &["--bogus"], 64, "usage"),
        (
            "missing-file",
            &["run", "no-such-spec.yaml", "--allow-unsigned"],
            64,
            "spec_unreadable",
        ),
        ("unsigned", &["run", "spec.yaml"], 64, "spec_unsigned"),
        (
            "unwritable-out-dir",
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
    for (row, args, exit, code) in rows {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
        let out = run(dir.path(), args);
        assert_eq!(out.status.code(), Some(exit), "{row}: {out:?}");
        let (_, doc) = document(&out, row);
        assert_valid(&validator, &doc, row);
        assert_eq!(doc["kind"], "Error", "{row}");
        assert_eq!(doc["error"]["code"], code, "{row}");
        assert_eq!(doc["complete"], false, "{row}");
    }
}
