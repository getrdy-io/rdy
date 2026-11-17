//! Exit-code goldens (M1-087, 07 section 5, 08 section 3).
//!
//! The rows that need no fixture backend run the built binary: a bad flag (64), a missing spec (64), a
//! spec that names 65 hosts (64) and a report folder that cannot be made (70). Each row is run twice.
//! Plain, it must exit with the row's code, print nothing on stdout and match the stderr golden. With
//! `--json`, it must exit the same, print the same stderr, and print one ErrorOutput on stdout that
//! validates against the result schema and carries the row's stable code.
//!
//! Exits 0, 1 and 2 are the fixture env goldens (`env_harness`, M1-075). The unsigned row joins with
//! `rdy verify` (M1-126). `rdy spec lint` exits 2 for a spec with 65 hosts by design (07 C.8); `rdy run`
//! exits 64 (M1-094 proves the same at the `CliError` level).
//!
//! The unwritable report folder is a folder whose parent does not exist. A read-only folder is not
//! portable: the CI containers run as root, and Windows ACLs differ. A missing parent fails the same way
//! on all five legs, and `rdy` does not create parents (`report_write`, exit 70).
//!
//! Determinism: each run starts in its own folder and names its files relative to it, so no machine path
//! reaches the output. The report folder name carries the run time, and the golden holds `<stamp>` in its
//! place. `\` becomes `/` and CRLF becomes LF before the comparison, for the Windows leg.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jsonschema::Validator;
use rdy_engine::testing::golden::assert_golden;
use serde_json::Value;

mod common;

struct Row {
    /// The golden's name under `tests/fixtures/exit-codes`.
    name: &'static str,
    args: &'static [&'static str],
    /// The folder the run starts in, relative to the repo root, or `None` for the example spec's copy.
    cwd: Cwd,
    exit: i32,
    code: &'static str,
}

enum Cwd {
    /// A fresh empty folder.
    Empty,
    /// A fresh folder that holds `spec.yaml`, a copy of the quickstart example.
    WithSpec,
    /// The folder of the invalid spec fixtures.
    InvalidSpecs,
}

const ROWS: &[Row] = &[
    Row {
        name: "bad-flag",
        args: &["--bogus"],
        cwd: Cwd::Empty,
        exit: 64,
        code: "usage",
    },
    Row {
        name: "missing-file",
        args: &["run", "no-such-spec.yaml", "--allow-unsigned"],
        cwd: Cwd::Empty,
        exit: 64,
        code: "spec_unreadable",
    },
    Row {
        name: "too-many-hosts",
        args: &[
            "run",
            "too-many-hosts-across-checks.yaml",
            "--allow-unsigned",
        ],
        cwd: Cwd::InvalidSpecs,
        exit: 64,
        code: "spec_invalid",
    },
    Row {
        name: "unwritable-out-dir",
        args: &[
            "run",
            "spec.yaml",
            "--allow-unsigned",
            "--out-dir",
            "no-such-dir/reports",
        ],
        cwd: Cwd::WithSpec,
        exit: 70,
        code: "report_write",
    },
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn golden(name: &str) -> PathBuf {
    repo().join("tests/fixtures/exit-codes").join(name)
}

fn validator() -> Validator {
    let path = repo().join("crates/rdy-spec/schema/result.v1.schema.json");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut schema: Value =
        serde_json::from_str(&source).unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    schema["$ref"] = Value::String("#/$defs/ErrorOutput".into());
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema does not build: {e}"))
}

/// Runs the row in its folder. `_keep` holds the temp folder until the run ends.
fn run(row: &Row, json: bool) -> Output {
    let temp = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let cwd = match row.cwd {
        Cwd::Empty => temp.path().to_path_buf(),
        Cwd::WithSpec => {
            let from = repo().join("examples/specs/acme-quickstart.yaml");
            std::fs::copy(&from, temp.path().join("spec.yaml"))
                .unwrap_or_else(|e| panic!("cannot copy {}: {e}", from.display()));
            temp.path().to_path_buf()
        }
        Cwd::InvalidSpecs => repo().join("tests/fixtures/specs/invalid"),
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_rdy"));
    command
        .args(row.args)
        .args(["--color", "never"])
        .current_dir(cwd)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1");
    if json {
        command.arg("--json");
    }
    common::quiet(
        command
            .output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}")),
    )
}

/// The report folder is `rdy-report-<product>-<YYYYMMDDTHHMMSSZ>`. The stamp is the run time.
fn scrub_stamp(text: &str) -> String {
    const STAMP: usize = "20261117T020947Z".len();
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("rdy-report-") {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let name_end = tail.find([' ', ')', '\n']).unwrap_or(tail.len());
        let name = &tail[..name_end];
        match name.len().checked_sub(STAMP) {
            Some(cut) if name.is_char_boundary(cut) => {
                out.push_str(&name[..cut]);
                out.push_str("<stamp>");
            }
            _ => out.push_str(name),
        }
        rest = &tail[name_end..];
    }
    out.push_str(rest);
    out
}

fn stderr_text(out: &Output) -> String {
    let text = std::str::from_utf8(&out.stderr)
        .unwrap_or_else(|e| panic!("stderr is not UTF-8: {e}"))
        .replace("\r\n", "\n")
        .replace('\\', "/");
    scrub_stamp(&text)
}

#[test]
fn every_row_exits_with_its_code_and_matches_its_stderr_golden() {
    for row in ROWS {
        let out = run(row, false);
        assert_eq!(out.status.code(), Some(row.exit), "{}: {out:?}", row.name);
        assert!(out.stdout.is_empty(), "{} wrote to stdout", row.name);
        assert_golden(
            golden(&format!("{}.stderr.txt", row.name)),
            stderr_text(&out),
        );
    }
}

#[test]
fn every_row_with_json_prints_one_valid_error_object_and_the_same_stderr() {
    let validator = validator();
    for row in ROWS {
        let out = run(row, true);
        assert_eq!(out.status.code(), Some(row.exit), "{}: {out:?}", row.name);
        assert_golden(
            golden(&format!("{}.stderr.txt", row.name)),
            stderr_text(&out),
        );
        let stdout = std::str::from_utf8(&out.stdout)
            .unwrap_or_else(|e| panic!("{}: stdout is not UTF-8: {e}", row.name));
        let doc: Value = serde_json::from_str(stdout)
            .unwrap_or_else(|e| panic!("{}: stdout is not one JSON document: {e}", row.name));
        let errors: Vec<String> = validator
            .iter_errors(&doc)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{}: {errors:#?}\n{doc}", row.name);
        assert_eq!(doc["error"]["code"], row.code, "{}", row.name);
        assert_eq!(doc["kind"], "Error", "{}", row.name);
    }
}

#[test]
fn no_machine_path_reaches_a_golden() {
    for row in ROWS {
        let text = stderr_text(&run(row, false));
        let repo = repo().to_string_lossy().replace('\\', "/");
        assert!(!text.contains(&repo), "{}: {text}", row.name);
        assert!(
            !text.contains("/tmp") && !text.contains(".tmp"),
            "{}: {text}",
            row.name
        );
    }
}
