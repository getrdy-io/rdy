//! From what a check returned to the [`CheckResult`] of the report (ADR 0008 decision 2, ADR 0013).
//!
//! [`map_outcome`] is the one place that turns a [`CheckOutcome`] into a result. A check never sets a
//! status, a severity, a skip kind or a fix source. This module does, from four inputs: the check's
//! [`CheckInfo`], the spec entry, the [`CheckContext`] of the run and the outcome itself.
//!
//! The rules, in order:
//!
//! 1. **Level and severity give the status.** `Pass` is `pass`. `Warn` is `warn`. `Fail` is `block` for
//!    a required check and `warn` for a `severity: warn` check.
//! 2. **The partial rule.** Missing soft needs (wants), the missing needs a finding names and an OS that
//!    [`Support::Partial`] all make the result `partial`. A `pass` with `partial` on a required check
//!    becomes `warn` with "not verified: ...", unless every missing need is `evidence_only` in the
//!    check's wants. The rule itself is [`apply_partial_rule`], the same code the verdict tests cover.
//! 3. **The fix.** On `warn` and `block` the spec's `fix` replaces rdy's text verbatim
//!    (`fix_source: spec`) and rdy's text moves to `builtin_fix`. On `pass` there is no fix. When the
//!    check did not run, the spec's fix is hidden and rdy's own text is shown (`fix_source: rdy`),
//!    because the vendor's advice would tell the customer to fix something nobody measured. A `pass`
//!    that became `warn` through the partial rule is in the same position: nothing was measured as
//!    failing, so it also gets rdy's text.
//! 4. **Needs.** Every hard need and want in the `CheckInfo` is listed with whether the run met it.
//!
//! Redaction and the size caps are not applied here. They come with M1-062.

use std::collections::HashSet;

use rdy_spec::result::{
    CheckResult, ErrorKind, FixSource, NeedState, Partial as WirePartial, Severity, Status,
    apply_partial_rule,
};
use rdy_spec::spec::{CheckSpec, Lenient};
use serde_json::{Map, Value};

use crate::check::{
    CheckContext, CheckError, CheckInfo, CheckOutcome, Finding, Need, Os, Partial, Support,
};
use crate::units::cap_level;

#[cfg(test)]
mod tests;

/// Stands for the spec file name in the root fix. The text is 01 section 5.2 word for word, but the
/// engine does not know the file name as typed. The CLI replaces this with its own shell-quoted
/// spec argument, as `SkipWhy::MissingRoot` does. M1-057 reconciles the two sources of skip text.
pub const SPEC_PLACEHOLDER: &str = "<spec>";

/// Text for a result whose check gave no advice of its own and the spec gave none either.
const NO_ADVICE_FIX: &str =
    "rdy has no advice for this result. Tell the vendor which check it was.";

/// Text for a check that failed and gave an empty hint.
const FAILED_FIX: &str = "Run again. If it fails again, tell the vendor which check it was.";

/// Turns what a check returned into the result entry for the report.
///
/// `entry` is the spec entry the check was built from, `ctx` is the context it ran with, and
/// `started_ms` and `duration_ms` are the timing the scheduler measured. The key comes from `ctx`.
/// A `fix` in `entry` that did not parse is ignored here: the planner has already skipped such an entry.
#[must_use]
pub fn map_outcome(
    info: &CheckInfo,
    entry: &CheckSpec,
    ctx: &CheckContext,
    outcome: CheckOutcome,
    started_ms: u64,
    duration_ms: u64,
) -> CheckResult {
    let severity = Severity::from(entry.effective_severity());
    let mut result = match outcome {
        Ok(finding) => from_finding(info, entry, ctx, &severity, finding),
        Err(error) => from_error(info, ctx, &severity, error),
    };
    result.key = ctx.key().to_owned();
    result.name = entry
        .name
        .as_ref()
        .and_then(Lenient::valid)
        .map(|name| name.as_str().to_owned());
    result.needs = need_states(info, ctx);
    result.started_ms = started_ms;
    result.duration_ms = duration_ms;
    result.refresh_bucket();
    result
}

/// Every hard need and want of `info`, with whether `ctx` met it. Hard needs come first.
#[must_use]
pub fn need_states(info: &CheckInfo, ctx: &CheckContext) -> Vec<NeedState> {
    let hard = info.needs.iter().map(|need| (need, true));
    let soft = info.wants.iter().map(|want| (&want.need, false));
    hard.chain(soft)
        .map(|(need, is_hard)| {
            let mut state = NeedState::new(need.wire(), is_hard, ctx.has(need));
            state.name = need.name().map(str::to_owned);
            state
        })
        .collect()
}

fn from_finding(
    info: &CheckInfo,
    entry: &CheckSpec,
    ctx: &CheckContext,
    severity: &Severity,
    finding: Finding,
) -> CheckResult {
    let Finding {
        level,
        message,
        observed,
        expected,
        fix,
        partial,
        mut notes,
    } = finding;

    let partial = merge_partial(info, ctx, partial);
    if let Some(partial) = &partial
        && !partial.missing_grants.is_empty()
    {
        // The wire `partial` has no field for grants yet, so they go to the notes.
        notes.push(format!(
            "Missing grants: {}",
            partial.missing_grants.join(", ")
        ));
    }

    let level_status = cap_level(level, severity);
    let wire_partial = partial.as_ref().map(wire_partial);
    let os_partial = matches!(info.os.on(ctx.os()), Support::Partial(_));
    let evidence_only = evidence_only_missing(info, partial.as_ref(), os_partial);
    let status = apply_partial_rule(
        level_status.clone(),
        severity,
        wire_partial.as_ref(),
        &evidence_only,
    );
    let downgraded = matches!(level_status, Status::Pass) && matches!(status, Status::Warn);

    let mut result = CheckResult::new(info.id, info.family, severity.clone(), status.clone());
    result.observed = to_map(observed);
    result.expected = to_map(expected);
    result.partial = wire_partial;

    let builtin = fix.filter(|text| !text.is_empty());
    if downgraded {
        result.message = format!("not verified: {}", unverified_reason(partial.as_ref()));
        notes.insert(0, format!("What the check could read passed: {message}"));
        result.fix = Some(builtin.unwrap_or_else(|| partial_fix(partial.as_ref())));
        result.fix_source = Some(FixSource::Rdy);
    } else {
        result.message = message;
        match status {
            Status::Warn | Status::Block => {
                let spec_fix = entry
                    .fix
                    .as_ref()
                    .and_then(Lenient::valid)
                    .map(|text| text.as_str().to_owned());
                if let Some(spec_fix) = spec_fix {
                    result.fix = Some(spec_fix);
                    result.fix_source = Some(FixSource::FromSpec);
                    result.builtin_fix = builtin;
                } else {
                    result.fix = Some(builtin.unwrap_or_else(|| NO_ADVICE_FIX.to_owned()));
                    result.fix_source = Some(FixSource::Rdy);
                }
            }
            _ => {}
        }
    }
    result.notes = notes;
    result
}

fn from_error(
    info: &CheckInfo,
    ctx: &CheckContext,
    severity: &Severity,
    error: CheckError,
) -> CheckResult {
    let Some(skip_kind) = error.skip_kind() else {
        return failed(info, severity, error);
    };
    let mut result = CheckResult::skipped(info.id, info.family, severity.clone(), skip_kind);
    match error {
        CheckError::MissingNeed(need) => {
            let (message, fix) = missing_need_text(&need, ctx.os());
            result.message = message;
            result.fix = Some(fix);
        }
        CheckError::Unsupported(what) => {
            result.message = format!(
                "Not run. This check does not work on {} yet.",
                os_name(ctx.os())
            );
            result.fix = Some("Run rdy on the machine you will install on.".to_owned());
            result.notes.push(what.to_owned());
        }
        _ => {
            result.message = "Not run. The check could not start.".to_owned();
            result.fix = Some(FAILED_FIX.to_owned());
        }
    }
    result.fix_source = Some(FixSource::Rdy);
    result
}

fn failed(info: &CheckInfo, severity: &Severity, error: CheckError) -> CheckResult {
    let mut result = CheckResult::new(info.id, info.family, severity.clone(), Status::Error);
    result.error_kind = Some(ErrorKind::CheckFailed);
    let hint = match &error {
        CheckError::Failed { hint, .. } if !hint.is_empty() => hint.clone(),
        _ => FAILED_FIX.to_owned(),
    };
    result.message = error.to_string();
    result.fix = Some(hint);
    result.fix_source = Some(FixSource::Rdy);
    result
}

/// The message and fix for a hard need that was not met (01 section 5.2, skip kinds and their words).
fn missing_need_text(need: &Need, os: Os) -> (String, String) {
    match need {
        Need::Root => (
            "Not run. This check needs root.".to_owned(),
            if os == Os::Windows {
                "Run rdy from an elevated prompt: open Terminal or PowerShell with Run as administrator, then run it again.".to_owned()
            } else {
                format!("Rerun as root: sudo rdy run {SPEC_PLACEHOLDER}")
            },
        ),
        Need::KubeContext => (
            "Not run. No Kubernetes cluster was reachable.".to_owned(),
            "Set a kubeconfig, or pass --kube-context <name>, then run again.".to_owned(),
        ),
        Need::Network => (
            "Not run. The network is turned off for this run.".to_owned(),
            "Run again without --no-network.".to_owned(),
        ),
        Need::Command(program) => (
            format!("Not run. The program {program} was not found."),
            format!("Install {program} on this machine, then run again."),
        ),
    }
}

pub(crate) fn os_name(os: Os) -> &'static str {
    match os {
        Os::Linux => "Linux",
        Os::Macos => "macOS",
        Os::Windows => "Windows",
        _ => "this OS",
    }
}

/// The partial of a finding, plus every want that was not met, plus the note of a [`Support::Partial`]
/// OS. `None` when none of the three applies.
fn merge_partial(info: &CheckInfo, ctx: &CheckContext, found: Option<Partial>) -> Option<Partial> {
    let os_note = match info.os.on(ctx.os()) {
        Support::Partial(note) => Some(note),
        _ => None,
    };
    let mut missing: Vec<Need> = found.as_ref().map_or_else(Vec::new, |p| p.missing.clone());
    for want in info.wants {
        if !ctx.has(&want.need) && !missing.contains(&want.need) {
            missing.push(want.need.clone());
        }
    }
    if found.is_none() && missing.is_empty() && os_note.is_none() {
        return None;
    }
    let (missing_grants, found_note) =
        found.map_or((Vec::new(), None), |p| (p.missing_grants, Some(p.note)));
    let note = match (os_note, found_note) {
        (Some(os), Some(found)) if !found.is_empty() => format!("{os}. {found}"),
        (Some(os), _) => os.to_owned(),
        (None, Some(found)) if !found.is_empty() => found,
        _ => missing_note(&missing),
    };
    Some(Partial {
        missing,
        missing_grants,
        note,
    })
}

fn missing_note(missing: &[Need]) -> String {
    if missing.is_empty() {
        "Some sources could not be read.".to_owned()
    } else {
        format!("Could not use: {}.", need_list(missing))
    }
}

fn need_list(needs: &[Need]) -> String {
    needs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn wire_partial(partial: &Partial) -> WirePartial {
    let mut wire: Vec<rdy_spec::result::Need> = Vec::new();
    for need in &partial.missing {
        let need = need.wire();
        if !wire.contains(&need) {
            wire.push(need);
        }
    }
    WirePartial::new(wire, partial.note.clone())
}

/// What [`apply_partial_rule`] should treat as evidence only.
///
/// The wire form of a need has no program name, so `command ss` and `command ip` look the same to
/// the rule. This decides in engine terms, where they differ: when every missing need is a want marked
/// `evidence_only`, the result is the wire form of the missing needs, and otherwise nothing. A
/// [`Support::Partial`] OS (`os_partial`) never has the exception: its note is a reason of its own.
fn evidence_only_missing(
    info: &CheckInfo,
    partial: Option<&Partial>,
    os_partial: bool,
) -> Vec<rdy_spec::result::Need> {
    let Some(partial) = partial.filter(|_| !os_partial) else {
        return Vec::new();
    };
    let evidence: HashSet<&Need> = info
        .wants
        .iter()
        .filter(|want| want.evidence_only)
        .map(|want| &want.need)
        .collect();
    let all_evidence =
        !partial.missing.is_empty() && partial.missing.iter().all(|need| evidence.contains(need));
    if all_evidence {
        partial.missing.iter().map(Need::wire).collect()
    } else {
        Vec::new()
    }
}

fn unverified_reason(partial: Option<&Partial>) -> String {
    match partial {
        Some(p) if !p.missing.is_empty() => need_list(&p.missing),
        Some(p) => p.note.clone(),
        None => "some sources could not be read".to_owned(),
    }
}

fn partial_fix(partial: Option<&Partial>) -> String {
    match partial {
        Some(p) if !p.missing.is_empty() => {
            format!(
                "Make {} available and run rdy again.",
                need_list(&p.missing)
            )
        }
        _ => "Run rdy again on an OS where this check has full support.".to_owned(),
    }
}

/// The result format wants objects. `Null` is no value, and anything else is kept under `value`.
fn to_map(value: Value) -> Option<Map<String, Value>> {
    match value {
        Value::Null => None,
        Value::Object(map) => Some(map),
        other => {
            let mut map = Map::new();
            map.insert("value".to_owned(), other);
            Some(map)
        }
    }
}
