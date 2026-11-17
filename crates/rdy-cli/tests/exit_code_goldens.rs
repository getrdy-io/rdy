//! Exit-code goldens (M1-087, 07 section 5, 08 section 3).
//!
//! The rows that need no fixture backend run the built binary: a bad flag (64), a missing spec (64), an
//! unsigned spec (64), a spec that names 65 hosts (64) and a report folder that cannot be made (70). Each row is run twice.
//! Plain, it must exit with the row's code, print nothing on stdout and match the stderr golden. With
//! `--json`, it must exit the same, print the same stderr, and print one ErrorOutput on stdout that
//! validates against the result schema, carries the row's stable code and says what stderr says.
//!
//! The unsigned row is `rdy run` on a spec with no `.minisig` and no flag (M1-126). `rdy verify` and the
//! other signature refusals are in `verify_command.rs`.
//!
//! Exits 0, 1 and 2 are the fixture env goldens (`env_harness`, M1-075). `rdy spec lint` exits 2 for a
//! spec with 65 hosts by design (07 C.8); `rdy run`
//! exits 64 (M1-094 proves the same at the `CliError` level).
//!
//! The `unwritable-out-dir` row gives a folder whose parent does not exist. It fails the same way on all
//! five legs, and `rdy` does not create parents (`report_write`, exit 70). The Unix-only
//! `read-only-out-dir` row gives a 0500 folder (07 C.7, "permission denied"). It skips itself when this
//! user can write to such a folder anyway (root), as `output/tests.rs` does, and on Windows, where ACLs
//! differ.
//!
//! Determinism: each run starts in its own folder and names its files relative to it, so no machine path
//! reaches the output. The report folder name carries the run time, and the golden holds `<stamp>` in its
//! place. On Windows only, `\` becomes `/` and CRLF becomes LF before the comparison.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rdy_engine::testing::golden::assert_golden;
use serde_json::Value;

mod common;

struct Row {
    /// The golden's name under `tests/fixtures/exit-codes`.
    name: &'static str,
    args: &'static [&'static str],
    /// What the fresh folder the run starts in holds.
    cwd: Cwd,
    exit: i32,
    code: &'static str,
}

enum Cwd {
    /// Nothing.
    Empty,
    /// `spec.yaml`, a copy of the quickstart example.
    WithSpec,
    /// A copy of the 65-host spec fixture.
    TooManyHosts,
    /// Like `WithSpec`, plus an empty `ro` folder with mode 0500. Unix only.
    ReadOnly,
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
        name: "unsigned",
        args: &["run", "spec.yaml"],
        cwd: Cwd::WithSpec,
        exit: 64,
        code: "spec_unsigned",
    },
    Row {
        name: "too-many-hosts",
        args: &[
            "run",
            "too-many-hosts-across-checks.yaml",
            "--allow-unsigned",
        ],
        cwd: Cwd::TooManyHosts,
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
    Row {
        name: "read-only-out-dir",
        args: &["run", "spec.yaml", "--allow-unsigned", "--out-dir", "ro"],
        cwd: Cwd::ReadOnly,
        exit: 70,
        code: "report_write",
    },
];

fn repo() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    path.canonicalize()
        .unwrap_or_else(|e| panic!("cannot resolve {}: {e}", path.display()))
}

fn golden(name: &str) -> PathBuf {
    repo().join("tests/fixtures/exit-codes").join(name)
}

fn copy_into(from: &Path, dir: &Path, name: &str) {
    std::fs::copy(from, dir.join(name))
        .unwrap_or_else(|e| panic!("cannot copy {}: {e}", from.display()));
}

/// Runs the row in a fresh folder. `None` means the row does not apply on this machine.
fn run(row: &Row, json: bool) -> Option<Output> {
    let temp = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let dir = temp.path();
    let quickstart = repo().join("examples/specs/acme-quickstart.yaml");
    match row.cwd {
        Cwd::Empty => {}
        Cwd::WithSpec => copy_into(&quickstart, dir, "spec.yaml"),
        Cwd::TooManyHosts => copy_into(
            &repo().join("tests/fixtures/specs/invalid/too-many-hosts-across-checks.yaml"),
            dir,
            "too-many-hosts-across-checks.yaml",
        ),
        Cwd::ReadOnly => {
            copy_into(&quickstart, dir, "spec.yaml");
            if !make_read_only(&dir.join("ro")) {
                return None;
            }
        }
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_rdy"));
    command
        .args(row.args)
        .args(["--color", "never"])
        .current_dir(dir)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("COLUMNS")
        .env("NO_COLOR", "1");
    if json {
        command.arg("--json");
    }
    Some(common::quiet(command.output().unwrap_or_else(|e| {
        panic!("the rdy binary did not start: {e}")
    })))
}

/// Makes `path` a 0500 folder. False when this user can write to it anyway (root ignores the mode).
#[cfg(unix)]
fn make_read_only(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(path).unwrap_or_else(|e| panic!("cannot make {}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500))
        .unwrap_or_else(|e| panic!("cannot chmod {}: {e}", path.display()));
    if std::fs::create_dir(path.join("probe")).is_ok() {
        eprintln!("skipped: this user can write to a 0500 folder");
        return false;
    }
    true
}

#[cfg(not(unix))]
fn make_read_only(_path: &Path) -> bool {
    eprintln!("skipped: a read-only folder is a Unix test");
    false
}

fn is_stamp(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 16
        && b[8] == b'T'
        && b[15] == b'Z'
        && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit)
}

/// The report folder is `rdy-report-<product>-<YYYYMMDDTHHMMSSZ>`. The stamp is the run time.
fn scrub_stamp(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("rdy-report-") {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let name_end = tail.find([' ', ')', '\n']).unwrap_or(tail.len());
        let name = &tail[..name_end];
        let cut = name
            .len()
            .checked_sub(16)
            .filter(|cut| name.is_char_boundary(*cut) && is_stamp(&name[*cut..]))
            .unwrap_or_else(|| panic!("a report folder name has no time stamp: {name:?}"));
        out.push_str(&name[..cut]);
        out.push_str("<stamp>");
        rest = &tail[name_end..];
    }
    out.push_str(rest);
    out
}

fn stderr_text(out: &Output) -> String {
    let text =
        std::str::from_utf8(&out.stderr).unwrap_or_else(|e| panic!("stderr is not UTF-8: {e}"));
    let text = if cfg!(windows) {
        text.replace("\r\n", "\n").replace('\\', "/")
    } else {
        text.to_string()
    };
    scrub_stamp(&text)
}

#[test]
fn every_row_exits_with_its_code_and_matches_its_stderr_golden() {
    for row in ROWS {
        let Some(out) = run(row, false) else { continue };
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
    let validator = common::error_output_validator();
    for row in ROWS {
        let Some(out) = run(row, true) else { continue };
        assert_eq!(out.status.code(), Some(row.exit), "{}: {out:?}", row.name);
        let stderr = stderr_text(&out);
        assert_golden(golden(&format!("{}.stderr.txt", row.name)), &stderr);
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

        // The two lines on stderr say what the JSON says (07 section 4.1). A spec error names its file.
        let field = |name: &str| doc["error"][name].as_str().unwrap_or_default().to_string();
        // A refusal that names the file inside its sentence has no `file:` prefix on the terminal.
        let message = match doc["error"]["file"].as_str() {
            Some(file) if !field("message").contains(file) => {
                format!("{file}: {}", field("message"))
            }
            _ => field("message"),
        };
        let message = scrub_stamp(&message);
        let message = if cfg!(windows) {
            message.replace('\\', "/")
        } else {
            message
        };
        assert!(
            stderr.contains(&format!("error: {message}\n")),
            "{}: {message:?} not in {stderr:?}",
            row.name
        );
        let fix = field("fix");
        assert!(
            stderr.contains(&format!("fix: {fix}\n")),
            "{}: {fix:?} not in {stderr:?}",
            row.name
        );
    }
}

#[test]
fn no_machine_path_reaches_a_golden() {
    let repo = repo().to_string_lossy().replace('\\', "/");
    for row in ROWS {
        let Some(out) = run(row, false) else { continue };
        let text = stderr_text(&out).replace('\\', "/");
        assert!(!text.contains(&repo), "{}: {text}", row.name);
        assert!(
            !text.contains("/tmp") && !text.contains(".tmp"),
            "{}: {text}",
            row.name
        );
    }
}
