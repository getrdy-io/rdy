//! The verdict rule (01 section 5.3, ADR 0008 decision 3, ADR 0013).
//!
//! This module is the one implementation. The terminal, the HTML report, the JSON writer and the portal
//! all take their verdict, bucket and counts from here. Everything is a pure function of severity,
//! status and skip kind, so the rule can be tested over a table.
//!
//! ```text
//! not_run(c)  = (c.status == skipped and c.skip_kind != not_applicable)
//!               or c.status in {timeout, error, <unknown>}
//! required(c) = c.severity != warn          # unreadable or unknown severity counts as block
//!
//! not_ready            if any c.status == block, or any c is required and not_run
//! ready_with_warnings  else if any c.status == warn, or any c is not required and not_run,
//!                      or no check reached pass, warn or block (nothing_verified)
//! ready                otherwise
//! ```
//!
//! A `timeout` or `error` that carries `skip_kind: not_applicable` by mistake still counts as not run,
//! because only the spec's `os` list may relax a requirement (ADR 0013 decisions 1 and 2).

use super::codes::{Bucket, Need, Severity, SkipKind, Status, Verdict, VerdictReason};
use super::model::{CheckResult, Partial};

/// `true` when a check with this severity is required. Only `warn` is optional. A severity this version
/// does not know is required.
#[must_use]
pub fn is_required(severity: &Severity) -> bool {
    !matches!(severity, Severity::Warn)
}

/// `true` when the check did not run: skipped (for any reason except `not_applicable`), timed out,
/// errored, or has a status this version does not know.
#[must_use]
pub fn is_not_run(status: &Status, skip_kind: Option<&SkipKind>) -> bool {
    match status {
        Status::Skipped => !matches!(skip_kind, Some(SkipKind::NotApplicable)),
        Status::Timeout | Status::Error | Status::Unknown(_) => true,
        Status::Pass | Status::Warn | Status::Block => false,
    }
}

/// The display group of a check. The result is never [`Bucket::Unknown`].
///
/// | Bucket | Contains |
/// | --- | --- |
/// | `blocker` | `status: block` |
/// | `required_not_run` | a required check that did not run |
/// | `warning` | `status: warn`, and an optional check that did not run |
/// | `passed` | `status: pass` |
/// | `not_applicable` | `status: skipped` with `skip_kind: not_applicable` |
#[must_use]
pub fn classify(severity: &Severity, status: &Status, skip_kind: Option<&SkipKind>) -> Bucket {
    match status {
        Status::Block => Bucket::Blocker,
        Status::Warn => Bucket::Warning,
        Status::Pass => Bucket::Passed,
        Status::Skipped | Status::Timeout | Status::Error | Status::Unknown(_) => {
            if !is_not_run(status, skip_kind) {
                Bucket::NotApplicable
            } else if is_required(severity) {
                Bucket::RequiredNotRun
            } else {
                Bucket::Warning
            }
        }
    }
}

/// The verdict of a run and why, when the checks alone do not explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Judgement {
    /// The verdict.
    pub verdict: Verdict,
    /// `required_check_not_run`, `nothing_verified` or `None`.
    pub reason: Option<VerdictReason>,
}

impl Judgement {
    /// The process exit code for this verdict: 0, 1 or 2.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.verdict.exit_code().code()
    }
}

/// Decides the verdict of a run from its results.
///
/// It reads severity, status and skip kind. It never trusts the stored `bucket`. An empty slice gives
/// `ready_with_warnings` with `nothing_verified`.
///
/// `verdict_reason` is `required_check_not_run` when the verdict is `not_ready` with no block, and
/// `nothing_verified` when the verdict is `ready_with_warnings` because no check reached pass, warn or
/// block. Otherwise it is `None`.
#[must_use]
pub fn verdict(checks: &[CheckResult]) -> Judgement {
    let mut any_block = false;
    let mut any_required_not_run = false;
    let mut any_warning = false;
    let mut any_verified = false;
    for c in checks {
        any_verified |= matches!(c.status, Status::Pass | Status::Warn | Status::Block);
        match classify(&c.severity, &c.status, c.skip_kind.as_ref()) {
            Bucket::Blocker => any_block = true,
            Bucket::RequiredNotRun => any_required_not_run = true,
            Bucket::Warning => any_warning = true,
            _ => {}
        }
    }
    if any_block {
        Judgement {
            verdict: Verdict::NotReady,
            reason: None,
        }
    } else if any_required_not_run {
        Judgement {
            verdict: Verdict::NotReady,
            reason: Some(VerdictReason::RequiredCheckNotRun),
        }
    } else if !any_verified {
        Judgement {
            verdict: Verdict::ReadyWithWarnings,
            reason: Some(VerdictReason::NothingVerified),
        }
    } else if any_warning {
        Judgement {
            verdict: Verdict::ReadyWithWarnings,
            reason: None,
        }
    } else {
        Judgement {
            verdict: Verdict::Ready,
            reason: None,
        }
    }
}

/// The status to record for a check after the partial rule (ADR 0013 decision 4).
///
/// A `pass` with `partial` set on a required check becomes `warn`, because the check could not read
/// everything it wanted. The one exception: every missing need is in `evidence_only`, the needs the
/// check's `CheckInfo` marks as only adding detail. A partial with no missing needs, which is what a
/// `Partial` OS gives (the OS note is the reason), never has that exception. Any other status, an
/// optional check and a result with no `partial` come back as they are.
///
/// The caller words the message ("not verified: ...") and sets the fix.
#[must_use]
pub fn apply_partial_rule(
    status: Status,
    severity: &Severity,
    partial: Option<&Partial>,
    evidence_only: &[Need],
) -> Status {
    let Some(partial) = partial else {
        return status;
    };
    if !matches!(status, Status::Pass) || !is_required(severity) {
        return status;
    }
    let only_evidence =
        !partial.missing.is_empty() && partial.missing.iter().all(|n| evidence_only.contains(n));
    if only_evidence { status } else { Status::Warn }
}
