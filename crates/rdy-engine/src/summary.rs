//! The summary line and the last line of a run (01 section 5.3, 07 section 2.4).
//!
//! Both lines are pure functions of the check results, so the terminal and any other reader print the
//! same words. They read severity, status and skip kind through the verdict rule in `rdy_spec::result`
//! and never trust a stored `bucket` or `verdict`.
//!
//! **Summary line.** `<n> block(s), <n> warning(s), <n> passed` always. Then, only when above zero and
//! in this order: `<n> required check(s) not run`, `<n> optional check(s) not run`,
//! `<n> not applicable`. A timeout or error inside a not-run count adds `(1 timed out)`, `(1 failed)`
//! or `(1 timed out, 1 failed)` after it. Parts are joined with `, `. Singular for one.
//!
//! **Last line.**
//!
//! | Verdict and reason | Last line |
//! | --- | --- |
//! | `not_ready`, a block was seen | `NOT READY` |
//! | `not_ready`, `required_check_not_run` | `NOT READY: 1 required check was not run`, `NOT READY: 2 required checks were not run` |
//! | `ready_with_warnings`, no reason | `READY with warnings` |
//! | `ready_with_warnings`, `nothing_verified` | `READY with warnings: nothing was checked` |
//! | `ready` | `READY` |
//!
//! ```
//! # use rdy_engine::summary::{last_line, summary_line};
//! # use rdy_spec::result::{CheckResult, Severity, Status};
//! let checks = [CheckResult::new("host.cpu", "host", Severity::Block, Status::Pass)];
//! assert_eq!(summary_line(&checks), "0 blocks, 0 warnings, 1 passed");
//! assert_eq!(last_line(&checks), "READY");
//! ```

use rdy_spec::result::{
    Bucket, CheckResult, Status, Summary, Verdict, VerdictReason, classify, verdict,
};

#[cfg(test)]
mod tests;

/// The summary line for `checks`, such as `1 block, 1 warning, 3 passed, 2 required checks not run`.
#[must_use]
pub fn summary_line(checks: &[CheckResult]) -> String {
    let summary = Summary::from_checks(checks);
    let (required, optional) = failures(checks);
    let mut parts = vec![
        format!("{} {}", summary.block, plural(summary.block, "block")),
        format!("{} {}", summary.warn, plural(summary.warn, "warning")),
        format!("{} passed", summary.pass),
    ];
    if summary.required_not_run > 0 {
        parts.push(format!(
            "{} required {} not run{}",
            summary.required_not_run,
            plural(summary.required_not_run, "check"),
            required.suffix()
        ));
    }
    if summary.optional_not_run > 0 {
        parts.push(format!(
            "{} optional {} not run{}",
            summary.optional_not_run,
            plural(summary.optional_not_run, "check"),
            optional.suffix()
        ));
    }
    if summary.not_applicable > 0 {
        parts.push(format!("{} not applicable", summary.not_applicable));
    }
    parts.join(", ")
}

/// The last line of a run for `checks`: the verdict word and, for two cases, the reason.
#[must_use]
pub fn last_line(checks: &[CheckResult]) -> String {
    let required_not_run = Summary::from_checks(checks).required_not_run;
    let judgement = verdict(checks);
    verdict_line(
        judgement.verdict,
        judgement.reason.as_ref(),
        required_not_run,
    )
}

/// The last line for a verdict already worked out, such as a `Report`'s `verdict` and
/// `verdict_reason`. `required_not_run` is [`Summary::required_not_run`]; it is used only for
/// `required_check_not_run`.
///
/// A reason this version does not know, or `required_check_not_run` with a count of zero (which the
/// verdict rule never gives), prints the plain verdict word.
#[must_use]
pub fn verdict_line(
    verdict: Verdict,
    reason: Option<&VerdictReason>,
    required_not_run: u32,
) -> String {
    match (verdict, reason) {
        (Verdict::NotReady, Some(VerdictReason::RequiredCheckNotRun)) if required_not_run > 0 => {
            let verb = if required_not_run == 1 { "was" } else { "were" };
            format!(
                "NOT READY: {required_not_run} required {} {verb} not run",
                plural(required_not_run, "check")
            )
        }
        (Verdict::ReadyWithWarnings, Some(VerdictReason::NothingVerified)) => {
            "READY with warnings: nothing was checked".to_owned()
        }
        (Verdict::ReadyWithWarnings, _) => "READY with warnings".to_owned(),
        (Verdict::Ready, _) => "READY".to_owned(),
        // `Verdict` is non_exhaustive. A value this version does not know is the worst case, so it
        // prints the strictest word.
        _ => "NOT READY".to_owned(),
    }
}

/// `block` or `blocks`: the plural takes an `s` unless `n` is one.
fn plural(n: u32, word: &str) -> String {
    if n == 1 {
        word.to_owned()
    } else {
        format!("{word}s")
    }
}

/// How many not-run checks of one kind timed out and how many failed.
#[derive(Debug, Default, Clone, Copy)]
struct Failures {
    timed_out: u32,
    failed: u32,
}

impl Failures {
    /// ` (1 timed out)`, ` (1 failed)`, ` (1 timed out, 1 failed)` or nothing.
    fn suffix(self) -> String {
        let mut parts = Vec::new();
        if self.timed_out > 0 {
            parts.push(format!("{} timed out", self.timed_out));
        }
        if self.failed > 0 {
            parts.push(format!("{} failed", self.failed));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join(", "))
        }
    }
}

/// The timeouts and errors inside the required and the optional not-run counts. A status this version
/// does not know is not run but adds to neither.
fn failures(checks: &[CheckResult]) -> (Failures, Failures) {
    let mut required = Failures::default();
    let mut optional = Failures::default();
    for c in checks {
        let slot = match classify(&c.severity, &c.status, c.skip_kind.as_ref()) {
            Bucket::RequiredNotRun => &mut required,
            Bucket::Warning if !matches!(c.status, Status::Warn) => &mut optional,
            _ => continue,
        };
        match c.status {
            Status::Timeout => slot.timed_out = slot.timed_out.saturating_add(1),
            Status::Error => slot.failed = slot.failed.saturating_add(1),
            _ => {}
        }
    }
    (required, optional)
}
