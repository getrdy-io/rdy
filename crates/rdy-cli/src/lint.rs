//! `rdy spec lint` (07 section C.8, 01 section 2.5).
//!
//! The command reads the spec file, hands the bytes to [`rdy_spec::lint::lint_bytes`] and prints the
//! [`LintReport`]. It never runs a check and never needs a signature.
//!
//! - The text goes to stderr, one finding per two lines, then a summary (07 section 1, rule 1).
//! - With `--json`, the report goes to stdout as one document (07 section 4.1).
//! - Exit 0 for no findings, 1 for warnings only and 2 for any error. A spec that does not parse is a
//!   finding (exit 2), because the person running lint wants to know what is wrong with the file. A file
//!   that cannot be read is exit 64.

use std::io::Write;
use std::path::Path;

use rdy_spec::MAX_SPEC_BYTES;
use rdy_spec::lint::{LintReport, lint_bytes};

use crate::error::{CliError, IoReason, emit, escape_untrusted};
use crate::signing::files::{self, FileError};

/// Runs `rdy spec lint` on the file at `path` and returns the exit code.
pub(crate) fn run(path: &Path, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let name = path.to_string_lossy();
    let bytes = match read_spec(path, &name) {
        Ok(bytes) => bytes,
        Err(err) => return emit(&err, json, stdout, stderr),
    };
    // Control characters in the file name are shown as text, so a name cannot act on the terminal.
    let report = lint_bytes(&escape_untrusted(&name), &bytes);
    if json {
        // A closed stdout is the caller's choice. The exit code still says what lint found.
        let _ = stdout.write_all(json_text(&report).as_bytes());
    }
    let _ = stderr.write_all(text(&report).as_bytes());
    report.exit_code().code()
}

/// Reads the spec file for every command that reads one (`rdy run`, `rdy verify`, `rdy spec lint` and
/// `rdy spec sign`): a regular file, at most one byte over the limit so that an oversized file is told
/// as a finding without reading all of it.
///
/// The file goes through the opened-file checks of `signing::files` (M1-183): a `stat` that follows a
/// link, a non-blocking open that never becomes the terminal, then a type and a device and inode compare
/// on the open handle. A named pipe or a device is refused with exit 64 and never waited on, whether it
/// is at the path or is swapped in after the `stat`.
pub(crate) fn read_spec(path: &Path, name: &str) -> Result<Vec<u8>, CliError> {
    files::read_public_prefix(path, MAX_SPEC_BYTES + 1)
        .map(|(bytes, _)| bytes)
        .map_err(|err| spec_file_error(name, &err))
}

/// [`read_spec`] with a hook between the `stat` and the open, for the tests of the swap.
#[cfg(all(test, unix))]
pub(crate) fn read_spec_between(
    path: &Path,
    name: &str,
    between: &dyn Fn(),
) -> Result<Vec<u8>, CliError> {
    files::read_public_prefix_between(path, MAX_SPEC_BYTES + 1, between)
        .map(|(bytes, _)| bytes)
        .map_err(|err| spec_file_error(name, &err))
}

/// A spec file that cannot be read is `spec_unreadable`, exit 64.
fn spec_file_error(name: &str, err: &FileError) -> CliError {
    let reason = match err {
        FileError::Unreadable { reason } => *reason,
        // A link is followed, so these are a pipe, a device, a folder, or one swapped in after the stat.
        _ => IoReason::NotAFile,
    };
    CliError::SpecUnreadable {
        path: name.to_owned(),
        reason,
    }
}

/// The text report of 07 section C.8. Every line ends in a newline.
///
/// ```text
/// acme-platform.yaml:45:9: warning: gpu.cuda: this version of rdy has no gpu checks yet
///   fix: customers will see this check as not run, and NOT READY while it is required.
///
/// acme-platform.yaml: 0 errors, 1 warning
/// ```
#[must_use]
pub fn text(report: &LintReport) -> String {
    let file = escape_untrusted(&report.file);
    let mut out = findings_text(report);
    if !report.findings.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "{file}: {}, {}\n",
        count(report.errors, "error"),
        count(report.warnings, "warning")
    ));
    out
}

/// The finding lines of [`text`] only, two lines each, with no blank line and no summary. `rdy spec sign`
/// prints these for a spec that has warnings (07 C.9).
#[must_use]
pub fn findings_text(report: &LintReport) -> String {
    let file = escape_untrusted(&report.file);
    let mut out = String::new();
    for finding in &report.findings {
        let level = finding.level.as_str();
        let place = match (finding.line, finding.column) {
            (Some(line), Some(column)) => format!("{file}:{line}:{column}"),
            _ => file.clone(),
        };
        out.push_str(&format!(
            "{place}: {level}: {}\n  fix: {}\n",
            escape_untrusted(&finding.message),
            escape_untrusted(&finding.fix)
        ));
    }
    out
}

/// "0 errors", "1 error", "2 errors".
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// The JSON document and a final newline. `<`, `>` and `&` are written as the escapes `<`,
/// `>` and `&`, like every document rdy prints (01 section 5.5).
#[must_use]
pub fn json_text(report: &LintReport) -> String {
    // The report holds strings, numbers and nulls, so serializing cannot fail.
    let text = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_owned());
    let mut out = text
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

    fn report(entries: &str) -> LintReport {
        lint_bytes("t.yaml", format!("{HEAD}{entries}").as_bytes())
    }

    #[test]
    fn a_clean_spec_prints_only_the_summary() {
        let r = report("  - id: host.cpu\n    min: 4\n");
        assert_eq!(text(&r), "t.yaml: 0 errors, 0 warnings\n");
    }

    #[test]
    fn findings_print_as_in_the_cli_design() {
        let r = report(
            "  - id: host.memory\n    mn: 32Gi\n  - id: gpu.cuda\n    min: \"12.4\"\n  - id: host.cpu\n",
        );
        let want = "\
t.yaml:7:5: error: unknown field 'mn' in host.memory
  fix: check the spelling (did you mean 'min'?)
t.yaml:8:9: warning: gpu.cuda: this version of rdy has no gpu checks yet
  fix: customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want.
t.yaml:10:5: error: host.cpu has no threshold, so it can only pass
  fix: add 'min: 4'.

t.yaml: 2 errors, 1 warning
";
        assert_eq!(text(&r), want);
    }

    #[test]
    fn a_finding_with_a_position_and_one_without() {
        let r = lint_bytes("t.yaml", b"apiVersion: [");
        assert!(text(&r).starts_with("t.yaml:1:"), "{}", text(&r));
        let r = lint_bytes("t.yaml", &vec![b'a'; MAX_SPEC_BYTES + 1]);
        let out = text(&r);
        assert!(
            out.starts_with("t.yaml: error: the spec is more than 1 MiB. The limit is 1 MiB\n"),
            "{out}"
        );
        assert!(out.ends_with("t.yaml: 1 error, 0 warnings\n"), "{out}");
    }

    #[test]
    fn json_escapes_angle_brackets_and_ampersands() {
        let r = LintReport::new("a<b>&.yaml", Vec::new());
        let out = json_text(&r);
        assert!(out.contains("a\\u003cb\\u003e\\u0026.yaml"), "{out}");
        assert!(out.ends_with("}\n"));
    }
}

#[cfg(all(test, unix))]
mod swap_tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn a_pipe_swapped_in_after_the_stat_is_spec_unreadable() {
        let d = tempfile::tempdir().expect("tempdir");
        let path = d.path().join("s.yaml");
        std::fs::write(&path, "a: 1").expect("write");
        let p = path.clone();
        let hook = move || {
            std::fs::remove_file(&p).expect("rm");
            let made = std::process::Command::new("mkfifo")
                .arg(&p)
                .status()
                .expect("mkfifo");
            assert!(made.success());
        };
        let start = std::time::Instant::now();
        let err = read_spec_between(&path, "s.yaml", &hook).unwrap_err();
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(err.code(), ErrorCode::SpecUnreadable);
        assert!(!err.hint().is_empty());
    }
}
