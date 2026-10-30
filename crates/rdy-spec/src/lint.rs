//! The lint rule for check entries, and the report `rdy spec lint` prints.
//!
//! `docs/plan/01-spec-format.md` section 2.5 sets how `rdy spec lint` and `rdy spec sign` treat an entry
//! that a run would skip. A run skips it and goes on. Lint and sign are stricter, because the person
//! running them is the vendor:
//!
//! | Decoding | Code | Level | `spec sign` |
//! | --- | --- | --- | --- |
//! | [`CheckParams::Unknown`], id is reserved (`host.virtualization`, `gpu.cuda`) | [`LintCode::NotInBuild`] | [`Level::Warning`] | signs, with the warning |
//! | [`CheckParams::Unknown`], id is not reserved (`host.memroy`) | [`LintCode::UnknownCheck`] | [`Level::Error`] | refuses |
//! | [`CheckParams::Unsupported`], any other reason (`mn: 32Gi`, `min: 32G`) | [`LintCode::UnsupportedSpec`] | [`Level::Error`] | refuses |
//! | [`CheckParams::Unsupported`] with no threshold (a bare `- id: host.memory`) | [`LintCode::NoThreshold`] | [`Level::Error`] | refuses |
//! | a typed variant with a regex that does not compile (`expected_issuer: "(abc"`) | [`LintCode::UnsupportedSpec`] | [`Level::Error`] | refuses |
//! | a typed variant | none | none | signs |
//!
//! [`CheckSpec::lint`] and [`Spec::lint_checks`] judge entries and give every finding a `fix` line. A
//! typo in a key or an id comes with a did-you-mean when a known name is within two edits. The file-level
//! entry point is [`lint_bytes`]: it reads the bytes, judges the spec as a whole and returns a
//! [`LintReport`] with the line and column of every finding. `rdy spec lint` prints that report and
//! `rdy spec sign` refuses to sign while [`LintReport::has_errors`].

use serde::Serialize;

use crate::check::{
    CheckParams, K8sAccess, KNOWN_IDS, NetTlsIntercept, ParamSet, RegexText, UnsupportedReason,
    fields_of, threshold_example_of,
};
use crate::error::echo_safe;
use crate::pattern;
use crate::reserved::{RESERVED_IDS, UnknownKind};
use crate::spec::{CheckSpec, Spec};
use crate::suggest::did_you_mean;

mod locate;
mod report;

pub use report::{Finding, LintReport, lint_bytes};

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Level {
    /// Lint exits 1 and sign goes on.
    Warning,
    /// Lint exits 2 and sign refuses.
    Error,
}

impl Level {
    /// The word in reports: `warning` or `error`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
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

/// Where in a check entry a finding points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Spot {
    /// The start of the entry.
    Entry,
    /// The value of the entry's `id`.
    Id,
    /// The key at this path from the top of the entry, such as `mn` or `free[0].prot`. The path is
    /// escaped and cut as it is in the message, so it is compared with an escaped path.
    Key(String),
    /// The value at this path.
    Value(String),
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
    /// The `code` this finding has in a [`LintReport`]. It is one of the codes the result schema names
    /// (`not_in_build`, `unknown_check`, `unsupported_field`, `bad_value`, `no_threshold`).
    pub report_code: &'static str,
    /// What is wrong, as one sentence. Safe to print: text from the file is cut and escaped.
    pub message: String,
    /// What to do about it, as one sentence. Safe to print.
    pub fix: String,
    /// Where in the entry the finding points.
    pub(crate) spot: Spot,
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
    /// with a line and column. [`lint_bytes`] runs both.
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
    let finding = |code, level, report_code, spot, message, fix| CheckLint {
        index,
        code,
        level,
        report_code,
        message,
        fix,
        spot,
    };
    match params {
        CheckParams::Unknown { id, .. } => {
            let id = echo_safe(id);
            match params.unknown_kind()? {
                UnknownKind::NotInBuild => Some(finding(
                    LintCode::NotInBuild,
                    Level::Warning,
                    "not_in_build",
                    Spot::Id,
                    not_in_build_message(&id),
                    "customers will see this check as not run, and NOT READY while it is required. \
                     Keep it if that is what you want."
                        .to_owned(),
                )),
                UnknownKind::UnknownCheck => Some(finding(
                    LintCode::UnknownCheck,
                    Level::Error,
                    "unknown_check",
                    Spot::Id,
                    format!("'{id}' is not a check id that any version of rdy has"),
                    match did_you_mean(&id, RESERVED_IDS) {
                        Some(near) => {
                            format!("check the spelling (did you mean '{near}'?), or remove the entry.")
                        }
                        None => format!(
                            "check the spelling of '{id}' against the check catalog, or remove the entry."
                        ),
                    },
                )),
            }
        }
        CheckParams::Unsupported { id, reason, .. } => {
            let known_fields = fields_of(id).unwrap_or(&[]);
            let id = echo_safe(id);
            let error = |report_code, spot, message, fix| {
                finding(
                    LintCode::UnsupportedSpec,
                    Level::Error,
                    report_code,
                    spot,
                    message,
                    fix,
                )
            };
            Some(match reason {
                UnsupportedReason::UnknownField { field } => error(
                    "unsupported_field",
                    Spot::Key(field.clone()),
                    format!("unknown field '{field}' in {id}"),
                    unknown_field_fix(field, did_you_mean(field, known_fields)),
                ),
                UnsupportedReason::UnknownNestedField { path, near } => error(
                    "unsupported_field",
                    Spot::Key(path.clone()),
                    format!("unknown field '{path}' in {id}"),
                    unknown_field_fix(path, near.as_deref()),
                ),
                UnsupportedReason::MissingField { field } => error(
                    "bad_value",
                    Spot::Entry,
                    format!("{id} is missing the required field '{field}'"),
                    format!("add '{field}' to the {id} entry."),
                ),
                UnsupportedReason::BadValue {
                    field: Some(field),
                    message,
                } => error(
                    "bad_value",
                    Spot::Value(field.clone()),
                    format!("bad value for '{field}' in {id}: {message}"),
                    format!("change the value of '{field}' to one that fits."),
                ),
                UnsupportedReason::BadValue {
                    field: None,
                    message,
                } => error(
                    "bad_value",
                    Spot::Entry,
                    format!("bad value in {id}: {message}"),
                    "change the value that does not fit.".to_owned(),
                ),
                UnsupportedReason::NoThreshold { one_of, and } => finding(
                    LintCode::NoThreshold,
                    Level::Error,
                    "no_threshold",
                    Spot::Entry,
                    format!("{id} has no threshold, so it can only pass"),
                    no_threshold_fix(threshold_example_of(&id), one_of, and),
                ),
                UnsupportedReason::BadCommonField { field } => error(
                    "bad_value",
                    Spot::Value((*field).to_owned()),
                    format!("bad value for '{field}' in {id}"),
                    format!("change the value of '{field}' to one that fits."),
                ),
            })
        }
        // A new check struct with a regex key needs its own arm here, and `REGEX_FIELDS` set.
        CheckParams::NetTlsIntercept(p) => regex_finding(
            index,
            params.id(),
            <NetTlsIntercept as ParamSet>::REGEX_FIELDS,
            &[p.expected_issuer.as_ref()],
        ),
        CheckParams::K8sAccess(p) => regex_finding(
            index,
            params.id(),
            <K8sAccess as ParamSet>::REGEX_FIELDS,
            &[p.context_pattern.as_ref(), p.server_pattern.as_ref()],
        ),
        _ => None,
    }
}

/// The fix for an unknown field: a did-you-mean when there is a near match.
fn unknown_field_fix(field: &str, near: Option<&str>) -> String {
    match near {
        Some(near) => format!("check the spelling (did you mean '{near}'?)"),
        None => format!(
            "check the spelling of '{field}' against the parameters of the check, or remove it."
        ),
    }
}

/// The finding for the first regex field of a typed check that does not compile.
///
/// `names` is `ParamSet::REGEX_FIELDS` of the check. `texts` holds the value of each name, in the same
/// order. A test keeps `names` complete.
fn regex_finding(
    index: usize,
    id: &str,
    names: &'static [&'static str],
    texts: &[Option<&RegexText>],
) -> Option<CheckLint> {
    debug_assert_eq!(names.len(), texts.len());
    names.iter().zip(texts).find_map(|(field, text)| {
        let why = pattern::compile((*text)?.as_str()).err()?;
        Some(CheckLint {
            index,
            code: LintCode::UnsupportedSpec,
            level: Level::Error,
            report_code: "bad_value",
            message: format!("bad value for '{field}' in {id}: {why}"),
            fix: format!(
                "change '{field}' to a pattern in Rust regex syntax. It has no look-around and no back-references."
            ),
            spot: Spot::Value((*field).to_owned()),
        })
    })
}

/// The message for a reserved id this build lacks. A family with no check in this build reads "no gpu
/// checks yet". A family with some reads "does not have the check host.virtualization yet".
fn not_in_build_message(id: &str) -> String {
    let family = id.split_once('.').map_or(id, |(family, _)| family);
    let family_dot = format!("{family}.");
    if KNOWN_IDS.iter().any(|known| known.starts_with(&family_dot)) {
        format!("{id}: this version of rdy does not have the check {id} yet")
    } else {
        format!("{id}: this version of rdy has no {family} checks yet")
    }
}

/// The fix for a check with no threshold: an example when the check has one, else one of the threshold
/// keys, then the other required keys.
fn no_threshold_fix(example: &str, one_of: &[&str], and: &[&str]) -> String {
    let quoted: Vec<String> = one_of.iter().map(|k| format!("'{k}'")).collect();
    let mut fix = match quoted.as_slice() {
        _ if !example.is_empty() => format!("add '{example}'"),
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
