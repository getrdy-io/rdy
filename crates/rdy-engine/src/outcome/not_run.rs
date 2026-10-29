//! Results for a check that did not finish: a timeout, a run that hit its deadline first, and a
//! report that had to be written without a snapshot (M1-043).
//!
//! The scheduler and the watchdog both need them, and the outcome mapping of M1-057 uses the same
//! functions for `End::TimedOut` and `End::RunDeadline`. Each takes a template: any result of the same
//! entry, from which only the identity (key, id, name, family, severity and needs) is kept. The text
//! is fixed, so it holds nothing that needs redaction. The spec's `fix` is never shown, because the
//! check did not produce the failure the vendor's advice is about (01 section 2.6).

use std::time::Duration;

use rdy_spec::result::{CheckResult, ErrorKind, FixSource, SkipKind, Status};

/// The result for a check that was still running at its time limit. `after` is the limit it had.
#[must_use]
pub fn timeout_result(template: &CheckResult, after: Duration, started: Duration) -> CheckResult {
    let mut result = base(template, Status::Timeout);
    result.timeout_after_ms = Some(millis(after));
    result.message = format!("Timed out after {}.", limit_text(after));
    result.fix =
        Some("Run again. If it times out again, tell the vendor which check it was.".into());
    result.started_ms = millis(started);
    result.duration_ms = millis(after);
    result.refresh_bucket();
    result
}

/// The result for a check that had not started when the run reached its deadline. `limit` is the
/// run's deadline.
#[must_use]
pub fn run_deadline_result(template: &CheckResult, limit: Duration) -> CheckResult {
    let mut result = base(template, Status::Skipped);
    result.skip_kind = Some(SkipKind::RunDeadline);
    result.message = format!(
        "Not run. The run reached its {} limit first.",
        limit_text(limit)
    );
    result.fix = Some("Run again. If it happens again, tell the vendor.".into());
    result.refresh_bucket();
    result
}

/// The result for a check when the watchdog could not read the run's results at all.
///
/// It is an `error`, so a required check still counts as not run and the verdict can never be
/// better than the truth.
#[must_use]
pub fn unfinished_result(template: &CheckResult) -> CheckResult {
    let mut result = base(template, Status::Error);
    result.error_kind = Some(ErrorKind::CheckFailed);
    result.message =
        "Not finished. rdy stopped before the results of this run could be read.".into();
    result.fix = Some("Run again. If it happens again, tell the vendor.".into());
    result.refresh_bucket();
    result
}

/// The identity of `template` with `status`, rdy's own fix text and nothing else.
fn base(template: &CheckResult, status: Status) -> CheckResult {
    let mut result = CheckResult::new(
        template.id.clone(),
        template.family.clone(),
        template.severity.clone(),
        status,
    );
    result.key.clone_from(&template.key);
    result.name.clone_from(&template.name);
    result.needs.clone_from(&template.needs);
    result.fix_source = Some(FixSource::Rdy);
    result
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// `10 s`, `5 minute`, `1 minute` or `1500 ms`. The word after the number is built for both uses:
/// "Timed out after 10 s." and "its 5 minute limit".
fn limit_text(duration: Duration) -> String {
    let ms = millis(duration);
    if ms >= 60_000 && ms.is_multiple_of(60_000) {
        format!("{} minute", ms / 60_000)
    } else if ms.is_multiple_of(1000) {
        format!("{} s", ms / 1000)
    } else {
        format!("{ms} ms")
    }
}

#[cfg(test)]
mod tests {
    use rdy_spec::result::{Bucket, Need, NeedState, Severity};

    use super::*;

    fn template() -> CheckResult {
        let mut template = CheckResult::new("net.dns", "net", Severity::Block, Status::Pass);
        template.key = "net.dns/primary".into();
        template.name = Some("primary".into());
        template.fix = Some("The vendor's own words".into());
        template.fix_source = Some(FixSource::FromSpec);
        template.needs = vec![NeedState::new(Need::Network, true, true)];
        template.message = "ok".into();
        template
    }

    #[test]
    fn a_timeout_keeps_the_identity_and_uses_rdys_text() {
        let result = timeout_result(
            &template(),
            Duration::from_secs(10),
            Duration::from_millis(40),
        );
        assert_eq!(result.status, Status::Timeout);
        assert_eq!(result.key, "net.dns/primary");
        assert_eq!(result.name.as_deref(), Some("primary"));
        assert_eq!(result.needs.len(), 1);
        assert_eq!(result.timeout_after_ms, Some(10_000));
        assert_eq!(result.message, "Timed out after 10 s.");
        assert_eq!(result.fix_source, Some(FixSource::Rdy));
        assert!(
            !result
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("vendor's own")
        );
        assert_eq!(result.bucket, Bucket::RequiredNotRun);
        assert_eq!(result.started_ms, 40);
    }

    #[test]
    fn a_run_deadline_skip_says_the_limit() {
        let result = run_deadline_result(&template(), Duration::from_secs(300));
        assert_eq!(result.status, Status::Skipped);
        assert_eq!(result.skip_kind, Some(SkipKind::RunDeadline));
        assert_eq!(
            result.message,
            "Not run. The run reached its 5 minute limit first."
        );
        assert_eq!(result.bucket, Bucket::RequiredNotRun);
    }

    #[test]
    fn an_unfinished_check_is_an_error_that_counts_as_not_run() {
        let result = unfinished_result(&template());
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.error_kind, Some(ErrorKind::CheckFailed));
        assert_eq!(result.bucket, Bucket::RequiredNotRun);
    }

    #[test]
    fn limits_read_naturally() {
        assert_eq!(limit_text(Duration::from_secs(60)), "1 minute");
        assert_eq!(limit_text(Duration::from_secs(90)), "90 s");
        assert_eq!(limit_text(Duration::from_millis(1500)), "1500 ms");
    }
}
