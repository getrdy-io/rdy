//! The first run page (M1-129). Each command on `docs/src/content/docs/first-run.md` is a case here.
//!
//! Three checks, in both directions:
//! - every line of a `sh` block on the page is a case, and every case is a line of a `sh` block, so a
//!   command cannot be added to the page without a test, or the other way round;
//! - every shape line a case checks also appears on the page, so the page shows the output the test sees;
//! - the built `rdy` runs each command in a fresh folder that holds a copy of
//!   `examples/specs/acme-quickstart.yaml`, as a reader does, and the exit code and output shape match.
//!
//! The checks read the shape of the output, never host numbers. The run may or may not reach the example
//! host names, and both outcomes end NOT READY with exit 2.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// The page under test, relative to the repo root.
const PAGE: &str = "docs/src/content/docs/first-run.md";
/// The example spec the page tells the reader to save.
const SPEC: &str = "acme-quickstart.yaml";

/// One command on the page, with its exit code and the text its output must show.
struct Case {
    /// The command as the page shows it, starting with `rdy`.
    command: &'static str,
    /// The exit code the run must give.
    exit: i32,
    /// Text the output must contain, on stdout or stderr.
    shape: &'static [&'static str],
    /// Text the page must show for this command. A version number is shown as `<version>`, so the
    /// page does not need a change on every release.
    shown: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        command: "rdy version",
        exit: 0,
        shape: &["rdy 0."],
        shown: &["rdy <version>"],
    },
    Case {
        command: "rdy spec lint acme-quickstart.yaml",
        exit: 0,
        shape: &["acme-quickstart.yaml: 0 errors, 0 warnings"],
        shown: &["acme-quickstart.yaml: 0 errors, 0 warnings"],
    },
    Case {
        command: "rdy run acme-quickstart.yaml --allow-unsigned",
        exit: 2,
        shape: &[
            "WARNING: UNSIGNED SPEC",
            "net.egress",
            "NOT READY",
            "Report written to",
        ],
        shown: &[
            "WARNING: UNSIGNED SPEC",
            "net.egress",
            "NOT READY",
            "Report written to",
        ],
    },
    Case {
        command: "rdy run acme-quickstart.yaml --allow-unsigned --json",
        exit: 2,
        shape: &["\"verdict\": \"not_ready\"", "\"exit_code\": 2"],
        shown: &["\"verdict\": \"not_ready\"", "\"exit_code\": 2"],
    },
];

/// The repo root: two levels above this crate's manifest (`crates/rdy-cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn page() -> String {
    let path = repo_root().join(PAGE);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The lines of every `sh` block on the page, in order. A block starts with a line that is exactly
/// `` ```sh `` and ends at the next line that is exactly `` ``` ``.
fn sh_lines(page: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_sh = false;
    for line in page.lines() {
        if in_sh {
            if line == "```" {
                in_sh = false;
            } else if !line.trim().is_empty() {
                lines.push(line.to_owned());
            }
        } else if line == "```sh" {
            in_sh = true;
        }
    }
    lines
}

/// A folder with a copy of the example spec, as a reader has after the page's second step.
fn reader_folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp folder: {e}"));
    let spec = repo_root().join("examples/specs").join(SPEC);
    fs::copy(&spec, dir.path().join(SPEC))
        .unwrap_or_else(|e| panic!("cannot copy {}: {e}", spec.display()));
    dir
}

/// Runs the command from a case in `dir`, with the arguments split at spaces. The page has no quoted
/// arguments, so a plain split is exact.
fn run(case: &Case, dir: &std::path::Path) -> (i32, String, String) {
    let args: Vec<&str> = case.command.split_whitespace().skip(1).collect();
    let output = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(&args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("cannot run `{}`: {e}", case.command));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.code().unwrap_or(-1), stdout, stderr)
}

#[test]
fn every_command_on_the_page_is_a_case_and_every_case_is_on_the_page() {
    let lines = sh_lines(&page());
    assert!(!lines.is_empty(), "the page has no sh block");
    for line in &lines {
        assert!(
            CASES.iter().any(|case| case.command == line),
            "`{line}` is on the page but is not a case in first_run_page.rs. Add a case, or remove the line."
        );
        assert!(line.starts_with("rdy "), "`{line}` is not an rdy command");
    }
    for case in CASES {
        assert!(
            lines.iter().any(|line| line == case.command),
            "`{}` is a case but is not on the page in a sh block",
            case.command
        );
    }
}

#[test]
fn the_page_shows_the_output_shape_each_case_checks() {
    let page = page();
    for case in CASES {
        for shown in case.shown {
            assert!(
                page.contains(shown),
                "the page does not show `{shown}` for the case `{}`",
                case.command
            );
        }
    }
    // The JSON fields the page names are the ones the JSON case reads.
    for field in ["`verdict`", "`exit_code`", "`signature`"] {
        assert!(page.contains(field), "the page does not name {field}");
    }
}

#[test]
fn every_command_on_the_page_runs_with_the_exit_code_and_shape_it_shows() {
    let dir = reader_folder();
    for case in CASES {
        let (code, stdout, stderr) = run(case, dir.path());
        assert_eq!(
            code, case.exit,
            "`{}` exit code. stdout:\n{stdout}\nstderr:\n{stderr}",
            case.command
        );
        let seen = format!("{stdout}\n{stderr}");
        for shape in case.shape {
            assert!(
                seen.contains(shape),
                "`{}` output lacks `{shape}`. stdout:\n{stdout}\nstderr:\n{stderr}",
                case.command
            );
        }
    }
}

#[test]
fn the_json_case_reports_an_unsigned_not_ready_result() {
    let dir = reader_folder();
    let case = CASES
        .iter()
        .find(|case| case.command.ends_with("--json"))
        .expect("the page has a --json command");
    let (code, stdout, _) = run(case, dir.path());
    assert_eq!(code, 2);
    let report: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not JSON: {e}"));
    assert_eq!(report["verdict"], "not_ready");
    assert_eq!(report["exit_code"], 2);
    assert_eq!(report["signature"]["state"], "unsigned");
}
