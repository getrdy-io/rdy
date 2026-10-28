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
//! | [`CheckParams::Unsupported`], any other reason (`mn: 32Gi`, `min: 32G`) | [`LintCode::UnsupportedSpec`] | [`Level::Error`] | refuses |
//! | [`CheckParams::Unsupported`] with no threshold (a bare `- id: host.memory`) | [`LintCode::NoThreshold`] | [`Level::Error`] | refuses |
//! | a typed variant | none | none | signs |
//!
//! This module judges one entry at a time and gives every finding a `fix` line. Lines and columns,
//! did-you-mean suggestions and the `LintReport` object belong to the `rdy spec lint` command.

use crate::check::{CheckParams, KNOWN_IDS, UnsupportedReason};
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

/// Which rule a finding comes from. [`LintCode::as_str`] is the stable name used in reports. It equals
/// the `skip_kind` a run reports for the same entry, except [`LintCode::NoThreshold`], which a run
/// reports as `unsupported_spec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LintCode {
    /// A reserved id that this build does not implement.
    NotInBuild,
    /// An id that is not reserved, so no version of rdy has it.
    UnknownCheck,
    /// A known check with a field or value rdy cannot read.
    UnsupportedSpec,
    /// A known check that needs a threshold and has none, such as a bare `- id: host.memory`. A run
    /// reports it as `unsupported_spec`.
    NoThreshold,
}

impl LintCode {
    /// The name in reports: `not_in_build`, `unknown_check`, `unsupported_spec` or `no_threshold`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInBuild => "not_in_build",
            Self::UnknownCheck => "unknown_check",
            Self::UnsupportedSpec => "unsupported_spec",
            Self::NoThreshold => "no_threshold",
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
                    not_in_build_message(&id),
                    "customers will see this check as not run, and NOT READY while it is required. \
                     Keep it if that is what you want."
                        .to_owned(),
                )),
                UnknownKind::UnknownCheck => Some(finding(
                    LintCode::UnknownCheck,
                    Level::Error,
                    format!("'{id}' is not a check id that any version of rdy has"),
                    format!(
                        "check the spelling of '{id}' against the check catalog, or remove the entry."
                    ),
                )),
            }
        }
        CheckParams::Unsupported { id, reason, .. } => {
            let id = echo_safe(id);
            let (code, message, fix) = match reason {
                UnsupportedReason::UnknownField { field } => (
                    LintCode::UnsupportedSpec,
                    format!("unknown field '{field}' in {id}"),
                    format!(
                        "check the spelling of '{field}' against the parameters of {id}, or remove it."
                    ),
                ),
                UnsupportedReason::MissingField { field } => (
                    LintCode::UnsupportedSpec,
                    format!("{id} is missing the required field '{field}'"),
                    format!("add '{field}' to the {id} entry."),
                ),
                UnsupportedReason::BadValue {
                    field: Some(field),
                    message,
                } => (
                    LintCode::UnsupportedSpec,
                    format!("bad value for '{field}' in {id}: {message}"),
                    format!("change the value of '{field}' to one that fits."),
                ),
                UnsupportedReason::BadValue {
                    field: None,
                    message,
                } => (
                    LintCode::UnsupportedSpec,
                    format!("bad value in {id}: {message}"),
                    "change the value that does not fit.".to_owned(),
                ),
                UnsupportedReason::NoThreshold { one_of, and } => (
                    LintCode::NoThreshold,
                    format!("{id} has no threshold, so it can only pass"),
                    no_threshold_fix(one_of, and),
                ),
                UnsupportedReason::BadCommonField { field } => (
                    LintCode::UnsupportedSpec,
                    format!("bad value for '{field}' in {id}"),
                    format!("change the value of '{field}' to one that fits."),
                ),
            };
            Some(finding(code, Level::Error, message, fix))
        }
        _ => None,
    }
}

/// The message for a reserved id this build lacks. A family with no check in this build reads "no gpu
/// checks yet". A family with some reads "does not have the check host.kernel yet".
fn not_in_build_message(id: &str) -> String {
    let family = id.split_once('.').map_or(id, |(family, _)| family);
    let family_dot = format!("{family}.");
    if KNOWN_IDS.iter().any(|known| known.starts_with(&family_dot)) {
        format!("{id}: this version of rdy does not have the check {id} yet")
    } else {
        format!("{id}: this version of rdy has no {family} checks yet")
    }
}

/// The fix for a check with no threshold: one of the threshold keys, then the other required keys.
fn no_threshold_fix(one_of: &[&str], and: &[&str]) -> String {
    let quoted: Vec<String> = one_of.iter().map(|k| format!("'{k}'")).collect();
    let mut fix = match quoted.as_slice() {
        [] => "add a threshold".to_owned(),
        [only] => format!("add {only}"),
        [init @ .., last] => format!("add at least one of {}, or {last}", init.join(", ")),
    };
    if !and.is_empty() {
        let also: Vec<String> = and.iter().map(|k| format!("'{k}'")).collect();
        fix.push_str(&format!("; also add {}", also.join(" and ")));
    }
    fix.push('.');
    fix
}
