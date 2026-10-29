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

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use rdy_spec::MAX_SPEC_BYTES;
use rdy_spec::lint::{LintReport, lint_bytes};

use crate::error::{CliError, IoReason, emit, escape_untrusted};

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

/// Reads the spec file: a regular file, at most one byte over the limit so that an oversized file is
/// told as a finding without reading all of it.
fn read_spec(path: &Path, name: &str) -> Result<Vec<u8>, CliError> {
    let unreadable = |err: &std::io::Error| CliError::spec_unreadable(name, err);
    let meta = std::fs::metadata(path).map_err(|e| unreadable(&e))?;
    if !meta.is_file() {
        return Err(CliError::SpecUnreadable {
            path: name.to_owned(),
            reason: IoReason::NotAFile,
        });
    }
    let file = File::open(path).map_err(|e| unreadable(&e))?;
    let mut bytes = Vec::new();
    file.take(MAX_SPEC_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unreadable(&e))?;
    Ok(bytes)
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
