//! The lint report: what `rdy spec lint` prints, and what `rdy spec sign` checks before it signs.
//!
//! [`lint_bytes`] reads a spec file's bytes and returns every finding with its line and column. It joins
//! three sources:
//!
//! - an error from the parser ([`crate::parse_unverified`]), which stops at the first problem. It is one
//!   finding, with the code `unknown_key` for a key the format does not have and `structure` for the
//!   rest;
//! - a spec whose `expires` has passed, a `structure` finding with no position;
//! - the findings about check entries ([`crate::spec::Spec::lint_checks`]), in file order.
//!
//! The report is the `LintReport` of the result schema (`$defs/LintReport`, 07 section C.11).

use std::time::SystemTime;

use serde::Serialize;

#[cfg(doc)]
use crate::result::Report;

use super::locate::locate;
use super::{CheckLint, Level, Spot};
use crate::error::echo_safe;
use crate::expiry::check_not_expired;
use crate::parse::parse_unverified;
use crate::result::ExitCode;
use crate::spec::{CheckSpec, Lenient};
use crate::{API_VERSION, SpecError};

/// The most characters of a file name that a report keeps (the schema's `maxLength`).
const MAX_FILE_CHARS: usize = 4096;

/// Not a [`Report`]. What `rdy spec lint` prints with `--json`.
///
/// The counts equal the number of findings of each level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct LintReport {
    /// Always `rdy/v1`.
    #[cfg_attr(feature = "schema", schemars(extend("const" = "rdy/v1")))]
    pub api_version: &'static str,
    /// Always `Lint`.
    #[cfg_attr(feature = "schema", schemars(extend("const" = "Lint")))]
    pub kind: &'static str,
    /// The file as the caller named it.
    #[cfg_attr(feature = "schema", schemars(length(max = 4096)))]
    pub file: String,
    /// Every finding, in file order. Empty when the spec is clean.
    pub findings: Vec<Finding>,
    /// How many findings are errors.
    pub errors: usize,
    /// How many findings are warnings.
    pub warnings: usize,
}

/// One finding of a [`LintReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Finding {
    /// Warning or error.
    pub level: Level,
    /// The code: `unknown_key`, `unknown_check`, `unsupported_field`, `bad_value`, `not_in_build`,
    /// `no_threshold` or `structure`. The set only grows.
    #[cfg_attr(feature = "schema", schemars(schema_with = "code_schema"))]
    pub code: &'static str,
    /// The line in the file, from 1, when it is known.
    #[cfg_attr(feature = "schema", schemars(range(min = 1)))]
    pub line: Option<u32>,
    /// The column in the file, from 1, when it is known.
    #[cfg_attr(feature = "schema", schemars(range(min = 1)))]
    pub column: Option<u32>,
    /// The key of the check the finding is about (`host.disk` or `host.disk/data`). Null for a finding
    /// about the file as a whole.
    pub key: Option<String>,
    /// What is wrong. Safe to print: text from the file is cut and escaped.
    pub message: String,
    /// What to do about it. Never empty.
    pub fix: String,
}

/// The schema of [`Finding::code`]: the known codes, and any snake_case code a later version adds.
#[cfg(feature = "schema")]
fn code_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let open = generator.subschema_for::<crate::result::open::OpenCode>();
    schemars::json_schema!({
        "anyOf": [
            {
                "enum": [
                    "unknown_key",
                    "unknown_check",
                    "unsupported_field",
                    "bad_value",
                    "not_in_build",
                    "no_threshold",
                    "structure"
                ]
            },
            open
        ]
    })
}

impl LintReport {
    /// A report for `file` with these findings. The counts are worked out from the findings.
    #[must_use]
    pub fn new(file: &str, findings: Vec<Finding>) -> Self {
        let count = |level| findings.iter().filter(|f| f.level == level).count();
        Self {
            api_version: API_VERSION,
            kind: "Lint",
            file: file.chars().take(MAX_FILE_CHARS).collect(),
            errors: count(Level::Error),
            warnings: count(Level::Warning),
            findings,
        }
    }

    /// Whether any finding is an error. `rdy spec sign` refuses a spec for which this is true.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.errors > 0
    }

    /// The exit code of `rdy spec lint`: [`ExitCode::Ready`] when there is nothing to say,
    /// [`ExitCode::Warnings`] for warnings only and [`ExitCode::Blockers`] for any error.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        if self.errors > 0 {
            ExitCode::Blockers
        } else if self.warnings > 0 {
            ExitCode::Warnings
        } else {
            ExitCode::Ready
        }
    }
}

/// Lints the bytes of a spec file, as `rdy spec lint` does, using this machine's clock for `expires`.
///
/// `file` is the name to put in the report. The caller is responsible for escaping it for a terminal.
/// The bytes are not trusted and no signature is looked at: lint says what is wrong with the text, not
/// who wrote it. This never panics and never fails. A file that cannot be read as a spec is a finding.
#[must_use]
pub fn lint_bytes(file: &str, bytes: &[u8]) -> LintReport {
    lint_bytes_at(file, bytes, SystemTime::now())
}

/// [`lint_bytes`] with the clock given, so a test decides what "now" is.
pub(crate) fn lint_bytes_at(file: &str, bytes: &[u8], now: SystemTime) -> LintReport {
    let mut findings = Vec::new();
    match parse_unverified(bytes) {
        Err(error) => findings.push(structure_finding(&error)),
        Ok(spec) => {
            if let Err(error) = check_not_expired(spec.metadata.expires.as_deref(), now) {
                findings.push(structure_finding(&error));
            }
            let lints = spec.lint_checks();
            let places = if lints.is_empty() {
                None
            } else {
                // The bytes parsed, so they are UTF-8. The fallback cannot happen.
                std::str::from_utf8(bytes).ok().map(|text| {
                    let wanted: Vec<(usize, &Spot)> =
                        lints.iter().map(|l| (l.index, &l.spot)).collect();
                    locate(text, &wanted)
                })
            };
            for lint in lints {
                let at = places.as_ref().and_then(|p| p.of(lint.index, &lint.spot));
                findings.push(check_finding(
                    &lint,
                    spec.checks.get(lint.index),
                    at.map(|a| (a.line, a.column)),
                ));
            }
        }
    }
    LintReport::new(file, findings)
}

/// The finding for an error of the parser or of the expiry rule.
fn structure_finding(error: &SpecError) -> Finding {
    let at = error.location();
    let code = match error.kind() {
        SpecError::UnknownKey { .. } | SpecError::UnknownKeyIn { .. } => "unknown_key",
        _ => "structure",
    };
    Finding {
        level: Level::Error,
        code,
        line: at.map(|a| a.line),
        column: at.map(|a| a.column),
        key: None,
        message: match error.kind() {
            // `rdy spec lint` reads one byte past the limit and stops, so the size is not known.
            SpecError::TooLarge { .. } => {
                "the spec is more than 1 MiB. The limit is 1 MiB".to_owned()
            }
            _ => error.to_string(),
        },
        fix: error.fix(),
    }
}

/// The finding for a check entry.
fn check_finding(lint: &CheckLint, entry: Option<&CheckSpec>, at: Option<(u32, u32)>) -> Finding {
    Finding {
        level: lint.level,
        code: lint.report_code,
        line: at.map(|(line, _)| line),
        column: at.map(|(_, column)| column),
        key: entry.map(check_key),
        message: lint.message.clone(),
        fix: lint.fix.clone(),
    }
}

/// `host.disk`, or `host.disk/data` when the entry has a name. Text from the file is escaped and cut.
fn check_key(entry: &CheckSpec) -> String {
    match &entry.name {
        Some(Lenient::Valid(name)) => format!("{}/{}", echo_safe(&entry.id), name.as_str()),
        _ => echo_safe(&entry.id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\n";

    fn lint(entries: &str) -> LintReport {
        lint_bytes("t.yaml", format!("{HEAD}checks:\n{entries}").as_bytes())
    }

    fn only(report: &LintReport) -> &Finding {
        assert_eq!(report.findings.len(), 1, "{report:?}");
        &report.findings[0]
    }

    #[test]
    fn an_oversized_file_is_told_without_a_size() {
        // The message says 1 MiB, so the limit must be 1 MiB.
        assert_eq!(crate::MAX_SPEC_BYTES, 1024 * 1024);
        let report = lint_bytes("t.yaml", &vec![b'a'; crate::MAX_SPEC_BYTES + 1]);
        let f = only(&report);
        assert_eq!(f.message, "the spec is more than 1 MiB. The limit is 1 MiB");
        assert!(f.fix.contains("1 MiB"), "{}", f.fix);
    }

    #[test]
    fn a_clean_spec_has_no_findings_and_exits_ready() {
        let report = lint("  - id: host.cpu\n    min: 4\n");
        assert!(report.findings.is_empty());
        assert_eq!((report.errors, report.warnings), (0, 0));
        assert_eq!(report.exit_code(), ExitCode::Ready);
        assert_eq!((report.api_version, report.kind), ("rdy/v1", "Lint"));
    }

    #[test]
    fn a_reserved_id_warns_at_the_id_value() {
        let report = lint("  - id: host.cpu\n    min: 4\n  - id: gpu.cuda\n    min: \"12.4\"\n");
        let f = only(&report);
        assert_eq!((f.level, f.code), (Level::Warning, "not_in_build"));
        // Line 8 is `  - id: gpu.cuda`. The id value starts at column 9.
        assert_eq!((f.line, f.column), (Some(8), Some(9)));
        assert_eq!(f.key.as_deref(), Some("gpu.cuda"));
        assert_eq!(report.exit_code(), ExitCode::Warnings);
    }

    #[test]
    fn a_misspelled_field_is_an_error_with_a_did_you_mean_and_its_line() {
        let report = lint("  - id: host.memory\n    mn: 32Gi\n");
        let f = only(&report);
        assert_eq!((f.level, f.code), (Level::Error, "unsupported_field"));
        assert_eq!((f.line, f.column), (Some(7), Some(5)));
        assert_eq!(f.message, "unknown field 'mn' in host.memory");
        assert_eq!(f.fix, "check the spelling (did you mean 'min'?)");
        assert_eq!(report.exit_code(), ExitCode::Blockers);
    }

    #[test]
    fn a_bad_value_points_at_the_value() {
        let report = lint("  - id: host.memory\n    min: 32G\n");
        let f = only(&report);
        assert_eq!(f.code, "bad_value");
        assert_eq!((f.line, f.column), (Some(7), Some(10)));
    }

    #[test]
    fn a_bare_threshold_points_at_the_entry() {
        let report = lint("  - id: host.cpu\n    min: 4\n  - id: host.memory\n");
        let f = only(&report);
        assert_eq!(f.code, "no_threshold");
        assert_eq!((f.line, f.column), (Some(8), Some(5)));
        assert_eq!(f.fix, "add 'min: 8Gi'.");
    }

    #[test]
    fn a_nested_unknown_key_has_its_path_and_a_did_you_mean() {
        let report =
            lint("  - id: host.ports\n    free:\n      - port: 80\n        bnid: loopback\n");
        let f = only(&report);
        assert_eq!(f.code, "unsupported_field");
        assert_eq!(f.message, "unknown field 'free[0].bnid' in host.ports");
        assert!(f.fix.contains("did you mean 'bind'"), "{}", f.fix);
        assert_eq!((f.line, f.column), (Some(9), Some(9)));
    }

    #[test]
    fn a_misspelled_id_gets_a_did_you_mean() {
        let report = lint("  - id: host.memroy\n    min: 32Gi\n");
        let f = only(&report);
        assert_eq!(f.code, "unknown_check");
        assert!(f.fix.contains("did you mean 'host.memory'"), "{}", f.fix);
        assert_eq!((f.line, f.column), (Some(6), Some(9)));
    }

    #[test]
    fn a_regex_that_does_not_compile_is_an_error_at_its_value() {
        let report = lint("  - id: net.tls_intercept\n    expected_issuer: \"(abc\"\n");
        let f = only(&report);
        assert_eq!((f.level, f.code), (Level::Error, "bad_value"));
        assert!(f.message.contains("unclosed group"), "{}", f.message);
        assert_eq!((f.line, f.column), (Some(7), Some(22)));
    }

    #[test]
    fn an_unknown_top_level_key_is_one_finding_with_a_did_you_mean() {
        let report = lint_bytes(
            "t.yaml",
            b"apiVersion: rdy/v1\nkind: Readiness\nmetdata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 4\n",
        );
        let f = only(&report);
        assert_eq!((f.level, f.code), (Level::Error, "unknown_key"));
        assert_eq!((f.line, f.column), (Some(3), Some(1)));
        assert_eq!(f.message, "unknown key 'metdata'");
        assert!(f.fix.contains("did you mean 'metadata'"), "{}", f.fix);
        assert_eq!(f.key, None);
    }

    #[test]
    fn a_bad_redact_regex_is_an_error_at_its_line() {
        let report = lint_bytes(
            "t.yaml",
            format!(
                "{HEAD}checks:\n  - id: host.cpu\n    min: 4\nbundle:\n  redact_patterns:\n    - name: a\n      regex: \"(abc\"\n"
            )
            .as_bytes(),
        );
        let f = only(&report);
        assert_eq!(f.code, "structure");
        assert!(f.message.contains("unclosed group"), "{}", f.message);
        assert_eq!((f.line, f.column), (Some(11), Some(14)));
    }

    #[test]
    fn a_spec_past_its_expiry_is_an_error_without_a_position() {
        let bytes = format!(
            "{HEAD}  expires: \"2027-01-31T00:00:00Z\"\nchecks:\n  - id: host.cpu\n    min: 4\n"
        );
        let at = |secs: u64| {
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(secs))
                .expect("time in range")
        };
        // 2027-02-03T00:00:00Z
        let late = lint_bytes_at("t.yaml", bytes.as_bytes(), at(1_801_872_000));
        let f = only(&late);
        assert_eq!((f.code, f.line), ("structure", None));
        assert!(
            f.message.starts_with("expired on 2027-01-31"),
            "{}",
            f.message
        );
        // 2027-01-01T00:00:00Z
        let early = lint_bytes_at("t.yaml", bytes.as_bytes(), at(1_798_761_600));
        assert!(early.findings.is_empty(), "{early:?}");
    }

    #[test]
    fn nothing_the_file_says_reaches_the_report_unescaped() {
        let report = lint("  - id: host.memory\n    \"m\\u001b[2Jn\": 32Gi\n");
        let f = only(&report);
        assert!(!f.message.chars().any(char::is_control), "{:?}", f.message);
        assert!(!f.fix.chars().any(char::is_control), "{:?}", f.fix);
    }

    #[test]
    fn the_file_name_is_cut_to_the_schema_limit() {
        let report = LintReport::new(&"a".repeat(5000), Vec::new());
        assert_eq!(report.file.chars().count(), 4096);
    }

    #[test]
    fn the_report_serializes_like_the_schema_sample() {
        let report = lint("  - id: gpu.cuda\n    min: \"12.4\"\n");
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["kind"], "Lint");
        assert_eq!(json["findings"][0]["level"], "warning");
        assert_eq!(json["findings"][0]["code"], "not_in_build");
        assert_eq!(json["findings"][0]["key"], "gpu.cuda");
        assert_eq!(json["errors"], 0);
        assert_eq!(json["warnings"], 1);
    }
}
