//! The first run page (M1-129). Each command on `docs/src/content/docs/first-run.md` is a case here.
//!
//! Four checks:
//! - every line of a `sh` block on the page is a case, and every case is a line of a `sh` block, so a
//!   command cannot be added to the page without a test, or the other way round. A block opens with
//!   `` ```sh `` and an optional info string, such as `` ```sh tested ``;
//! - the shape lines a case checks appear on the page in the same order, so the page shows the output
//!   the test sees;
//! - the top-level keys of the JSON report appear on the page in the order the binary prints them;
//! - the built `rdy` runs each command in a fresh folder that holds a copy of
//!   `examples/specs/acme-quickstart.yaml`, as a reader does. The `run` cases add `--no-network`, so the
//!   test never makes a lookup or a connection. The page command is the one the reader types, without it.
//!
//! The checks read the shape of the output, never host numbers.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The page under test, relative to the repo root.
const PAGE: &str = "docs/src/content/docs/first-run.md";
/// The example spec the page tells the reader to save.
const SPEC: &str = "acme-quickstart.yaml";
/// Proxy variables a child process must not inherit, so no case uses a proxy.
const PROXY_VARS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

/// One command on the page, with its exit code and the lines its output must show, in order.
struct Case {
    /// The command as the page shows it, starting with `rdy`.
    command: &'static str,
    /// The exit code the run must give.
    exit: i32,
    /// Lines the output must contain, in this order. Stdout is read before stderr.
    shape: &'static [&'static str],
    /// Lines the page must show for this command, in this order. A version number is shown as
    /// `<version>`, so the page does not need a change on every release.
    shown: &'static [&'static str],
}

/// The offline text output of the example run. The page shows the same lines.
const RUN_SHAPE: &[&str] = &[
    "WARNING: UNSIGNED SPEC",
    "sig     UNSIGNED (allowed by --allow-unsigned)",
    "  SKIP     net.egress",
    "Report written to ",
    "  rdy-report-acme-quickstart-",
    "  spec.yaml",
    "WARNING: UNSIGNED SPEC",
    "NOT READY",
];

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
        shape: RUN_SHAPE,
        shown: RUN_SHAPE,
    },
    Case {
        command: "rdy run acme-quickstart.yaml --allow-unsigned --json",
        exit: 2,
        shape: &["\"verdict\": \"not_ready\"", "\"exit_code\": 2"],
        shown: &["\"verdict\": \"not_ready\"", "\"exit_code\": 2"],
    },
];

/// The top-level keys of the JSON report, in the order the binary prints them.
const REPORT_KEYS: &[&str] = &[
    "api_version",
    "kind",
    "producer",
    "run",
    "spec",
    "signature",
    "host",
    "identity",
    "proxy",
    "capabilities",
    "verdict",
    "verdict_reason",
    "exit_code",
    "summary",
    "checks",
    "actions",
    "actions_truncated",
    "actions_dropped",
    "redaction",
    "complete",
    "interrupted",
];

/// The repo root: two levels above this crate's manifest (`crates/rdy-cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn page() -> String {
    let path = repo_root().join(PAGE);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The lines of every `sh` block on the page, in order. A block opens with a line that is `` ```sh ``
/// or `` ```sh `` and a space and an info string. It ends at the next line that is exactly `` ``` ``.
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
        } else if line == "```sh" || line.starts_with("```sh ") {
            in_sh = true;
        }
    }
    lines
}

/// The part of the page from the heading `start` up to the heading `end`.
fn section<'a>(page: &'a str, start: &str, end: &str) -> &'a str {
    let from = page
        .find(start)
        .unwrap_or_else(|| panic!("the page has no `{start}` heading"));
    let rest = &page[from..];
    let to = rest
        .find(end)
        .unwrap_or_else(|| panic!("the page has no `{end}` heading after `{start}`"));
    &rest[..to]
}

/// The first needle that is missing when the needles are searched for in `text`, in order. `None`
/// when each one appears after the one before it.
fn missing_in_order<'a>(text: &str, needles: &[&'a str]) -> Option<&'a str> {
    let mut rest = text;
    for needle in needles {
        match rest.find(needle) {
            Some(at) => rest = &rest[at + needle.len()..],
            None => return Some(needle),
        }
    }
    None
}

/// The keys of the top level of a pretty-printed JSON object. A top-level key starts a line with
/// exactly two spaces, a quote and a colon after the key.
fn top_keys(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("  \"")?;
            let (key, after) = rest.split_once('"')?;
            after.starts_with(':').then(|| key.to_owned())
        })
        .collect()
}

/// A folder with a copy of the example spec, as a reader has after the page's second step.
fn reader_folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp folder: {e}"));
    let spec = repo_root().join("examples/specs").join(SPEC);
    fs::copy(&spec, dir.path().join(SPEC))
        .unwrap_or_else(|e| panic!("cannot copy {}: {e}", spec.display()));
    dir
}

/// Runs the command from a case in `dir`. The arguments are the words after `rdy`, which the page
/// does not quote. `run` gets `--no-network`, so the example's host names are never looked up. The
/// child has its own home folder and no proxy, and no variable that changes the output.
fn run(case: &Case, dir: &Path) -> (i32, String, String) {
    let mut args: Vec<&str> = case.command.split_whitespace().skip(1).collect();
    if args.first() == Some(&"run") {
        args.push("--no-network");
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_rdy"));
    command
        .args(&args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG")
        .env_remove("CLICOLOR_FORCE");
    for var in PROXY_VARS {
        command.env_remove(var);
    }
    let output = common::quiet(
        command
            .output()
            .unwrap_or_else(|e| panic!("cannot run `{}`: {e}", case.command)),
    );
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
fn the_page_shows_each_shape_in_the_order_the_case_checks_it() {
    let page = page();
    for case in CASES {
        assert_eq!(
            missing_in_order(&page, case.shown),
            None,
            "the page does not show these lines in order for `{}`",
            case.command
        );
    }
}

#[test]
fn the_page_lists_the_json_report_keys_in_the_order_the_binary_prints_them() {
    let page = page();
    let shown = top_keys(section(&page, "## Read the JSON report", "## Next steps"));
    let expected: Vec<String> = REPORT_KEYS.iter().map(|key| (*key).to_owned()).collect();
    assert_eq!(shown, expected, "the JSON keys on the page");

    let dir = reader_folder();
    let json = CASES
        .iter()
        .find(|case| case.command.ends_with("--json"))
        .expect("the page has a --json command");
    let (_, stdout, _) = run(json, dir.path());
    assert_eq!(
        top_keys(&stdout),
        expected,
        "the JSON keys the binary prints"
    );
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
        assert_eq!(
            missing_in_order(&seen, case.shape),
            None,
            "`{}` output lacks these lines in order. stdout:\n{stdout}\nstderr:\n{stderr}",
            case.command
        );
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
    // The reason depends on the host: a required check that did not run, or no reason when a check
    // blocks instead. Either is the same verdict.
    let reason = &report["verdict_reason"];
    assert!(
        reason.is_null() || reason == "required_check_not_run",
        "verdict_reason is {reason}"
    );
    assert_eq!(report["exit_code"], 2);
    assert_eq!(report["signature"]["state"], "unsigned");
}
