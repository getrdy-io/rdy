//! The lint rule for check entries.
//!
//! `docs/plan/01-spec-format.md` section 2.5 sets how `rdy spec lint` and `rdy spec sign` treat an entry
//! that a run would skip. A run skips it and goes on. Lint and sign are stricter, because the person
//! running them is the vendor:
//!
//! | Decoding | Code | Level | `spec sign` |
//! | --- | --- | --- | --- |
//! | [`CheckParams::Unknown`], id is reserved (`host.kernel`, `gpu.cuda`) | [`LintCode::NotInBuild`] | [`Level::Warning`] | signs, with the warning |
//! | [`CheckParams::Unknown`], id is not reserved (`host.memroy`) | [`LintCode::UnknownCheck`] | [`Level::Error`] | refuses |
//! | [`CheckParams::Unsupported`] (`mn: 32Gi`, `min: 32G`) | [`LintCode::UnsupportedSpec`] | [`Level::Error`] | refuses |
//! | a typed variant | none | none | signs |
//!
//! This module judges one entry at a time and gives every finding a `fix` line. Lines and columns,
//! did-you-mean suggestions and the `LintReport` object belong to the `rdy spec lint` command.

use crate::check::{CheckParams, UnsupportedReason};
use crate::error::echo_safe;
use crate::reserved::UnknownKind;
use crate::spec::{CheckSpec, Spec};

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Level {
    /// Lint exits 1 and sign goes on.
    Warning,
    /// Lint exits 2 and sign refuses.
    Error,
}

/// Which rule a finding comes from. [`LintCode::as_str`] is the stable name used in reports, and it
/// equals the `skip_kind` a run reports for the same entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LintCode {
    /// A reserved id that this build does not implement.
    NotInBuild,
    /// An id that is not reserved, so no version of rdy has it.
    UnknownCheck,
    /// A known check with a field or value rdy cannot read.
    UnsupportedSpec,
}

impl LintCode {
    /// The name in reports: `not_in_build`, `unknown_check` or `unsupported_spec`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInBuild => "not_in_build",
            Self::UnknownCheck => "unknown_check",
            Self::UnsupportedSpec => "unsupported_spec",
        }
    }
}

/// One finding about one check entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckLint {
    /// The index of the entry in [`Spec::checks`].
    pub index: usize,
    /// The rule.
    pub code: LintCode,
    /// Warning or error.
    pub level: Level,
    /// What is wrong, as one sentence. Safe to print: text from the file is cut and escaped.
    pub message: String,
    /// What to do about it, as one sentence. Safe to print.
    pub fix: String,
}

impl CheckLint {
    /// Whether `rdy spec sign` must refuse a spec with this finding.
    #[must_use]
    pub fn blocks_signing(&self) -> bool {
        self.level == Level::Error
    }
}

impl CheckSpec {
    /// Judges this entry for lint and sign, or `None` when a run would read it without trouble.
    ///
    /// `index` is the position of the entry in the spec and is copied into the finding.
    #[must_use]
    pub fn lint(&self, index: usize) -> Option<CheckLint> {
        lint_params(index, &self.decode_params())
    }
}

impl Spec {
    /// Judges every check entry, in order. Entries that are fine give no finding.
    ///
    /// Structure errors such as a duplicate key are not here. [`crate::parse_unverified`] rejects them
    /// with a line and column.
    #[must_use]
    pub fn lint_checks(&self) -> Vec<CheckLint> {
        self.checks
            .iter()
            .enumerate()
            .filter_map(|(index, check)| check.lint(index))
            .collect()
    }
}

/// The finding for decoded parameters, if any.
fn lint_params(index: usize, params: &CheckParams) -> Option<CheckLint> {
    let finding = |code, level, message, fix| CheckLint {
        index,
        code,
        level,
        message,
        fix,
    };
    match params {
        CheckParams::Unknown { id, .. } => {
            let id = echo_safe(id);
            match params.unknown_kind()? {
                UnknownKind::NotInBuild => Some(finding(
                    LintCode::NotInBuild,
                    Level::Warning,
                    format!("'{id}' is a reserved check id that this version of rdy does not have yet."),
                    "Keep it if the vendor wants it. An older rdy skips it and says so. A newer rdy runs it."
                        .to_owned(),
                )),
                UnknownKind::UnknownCheck => Some(finding(
                    LintCode::UnknownCheck,
                    Level::Error,
                    format!("'{id}' is not a check id that any version of rdy has."),
                    format!(
                        "Fix the spelling of '{id}' against the check catalog, or remove the entry."
                    ),
                )),
            }
        }
        CheckParams::Unsupported { id, reason, .. } => {
            let id = echo_safe(id);
            let fix = match reason {
                UnsupportedReason::UnknownField { field } => format!(
                    "Fix the spelling of '{field}' against the parameters of {id}, or remove it."
                ),
                UnsupportedReason::MissingField { field } => {
                    format!("Add '{field}' to the {id} entry.")
                }
                UnsupportedReason::BadValue {
                    field: Some(field), ..
                } => format!("Change the value of '{field}' in the {id} entry to one that fits."),
                UnsupportedReason::BadValue { field: None, .. } => {
                    format!("Change the value that does not fit in the {id} entry.")
                }
                UnsupportedReason::BadCommonField { field } => {
                    format!("Change the value of '{field}' in the {id} entry to one that fits.")
                }
            };
            Some(finding(
                LintCode::UnsupportedSpec,
                Level::Error,
                format!("'{id}' cannot be read: {reason}."),
                fix,
            ))
        }
        _ => None,
    }
}
