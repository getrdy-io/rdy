//! Tests of the summary line and the last line (M1-054).
//!
//! The golden cases are the samples of 01 section 5.3 and 07 (C.12, C.13, C.17, C.18 and 2.7), one file
//! each under `tests/fixtures/summary/`: the summary line, then the last line. The other tests pin the
//! singular and plural forms and the timeout and error suffixes.

use rdy_spec::result::{CheckResult, Severity, SkipKind, Status, Verdict, VerdictReason};

use super::{last_line, summary_line, verdict_line};
use crate::testing::fixtures_dir;
use crate::testing::golden::assert_golden;

fn result(severity: Severity, status: Status) -> CheckResult {
    CheckResult::new("host.cpu", "host", severity, status)
}

fn skipped(severity: Severity, kind: SkipKind) -> CheckResult {
    CheckResult::skipped("host.cpu", "host", severity, kind)
}

fn many(n: usize, make: impl Fn() -> CheckResult) -> Vec<CheckResult> {
    (0..n).map(|_| make()).collect()
}

/// Compares both lines with the golden `tests/fixtures/summary/<case>.txt`.
#[track_caller]
fn golden(case: &str, checks: &[CheckResult]) {
    let text = format!("{}\n{}\n", summary_line(checks), last_line(checks));
    assert_golden(fixtures_dir().join(format!("summary/{case}.txt")), text);
}

fn cat(parts: Vec<Vec<CheckResult>>) -> Vec<CheckResult> {
    parts.into_iter().flatten().collect()
}

#[test]
fn golden_a_block_with_required_checks_not_run_is_plain_not_ready() {
    // 01 section 5.3, first sample.
    let checks = cat(vec![
        many(2, || result(Severity::Block, Status::Block)),
        many(1, || result(Severity::Warn, Status::Warn)),
        many(3, || result(Severity::Block, Status::Pass)),
        many(2, || skipped(Severity::Block, SkipKind::MissingNeed)),
    ]);
    golden("block-and-required-not-run", &checks);
}

#[test]
fn golden_an_optional_check_not_run_and_not_applicable_checks() {
    // 01 section 5.3, second sample.
    let checks = cat(vec![
        many(5, || result(Severity::Block, Status::Pass)),
        many(1, || skipped(Severity::Warn, SkipKind::MissingNeed)),
        many(2, || skipped(Severity::Block, SkipKind::NotApplicable)),
    ]);
    golden("optional-not-run-and-not-applicable", &checks);
}

#[test]
fn golden_nothing_verified() {
    // 01 section 5.3, third sample, and 07 C.13.
    let checks = many(3, || skipped(Severity::Block, SkipKind::NotApplicable));
    golden("nothing-verified", &checks);
}

#[test]
fn golden_only_required_checks_not_run() {
    // 07 C.12.
    let checks = many(3, || skipped(Severity::Block, SkipKind::NotInBuild));
    golden("required-not-run-only", &checks);
}

#[test]
fn golden_one_required_check_not_run_uses_the_singular() {
    let checks = cat(vec![
        many(2, || result(Severity::Block, Status::Pass)),
        many(1, || skipped(Severity::Block, SkipKind::MissingNeed)),
    ]);
    golden("one-required-not-run", &checks);
}

#[test]
fn golden_all_passed_with_one_not_applicable() {
    // 07 C.17 shape.
    let checks = cat(vec![
        many(4, || result(Severity::Block, Status::Pass)),
        many(1, || skipped(Severity::Block, SkipKind::NotApplicable)),
    ]);
    golden("all-passed", &checks);
}

#[test]
fn golden_a_warning_gives_ready_with_warnings() {
    // 07 C.18 shape.
    let checks = cat(vec![
        many(1, || result(Severity::Warn, Status::Warn)),
        many(3, || result(Severity::Block, Status::Pass)),
        many(1, || skipped(Severity::Block, SkipKind::NotApplicable)),
    ]);
    golden("one-warning", &checks);
}

#[test]
fn golden_the_unsigned_run_of_07_section_2_7() {
    let checks = cat(vec![
        many(1, || result(Severity::Block, Status::Block)),
        many(1, || result(Severity::Warn, Status::Warn)),
        many(1, || result(Severity::Block, Status::Pass)),
        many(1, || result(Severity::Block, Status::Timeout)),
        many(3, || skipped(Severity::Block, SkipKind::MissingNeed)),
        many(1, || skipped(Severity::Warn, SkipKind::MissingNeed)),
    ]);
    golden("unsigned-run-with-a-timeout", &checks);
}

#[test]
fn golden_timed_out_and_failed_checks_in_both_not_run_counts() {
    let checks = cat(vec![
        many(2, || result(Severity::Block, Status::Timeout)),
        many(1, || result(Severity::Block, Status::Error)),
        many(1, || skipped(Severity::Block, SkipKind::Cancelled)),
        many(1, || result(Severity::Warn, Status::Error)),
        many(2, || result(Severity::Warn, Status::Timeout)),
        many(1, || result(Severity::Block, Status::Pass)),
    ]);
    golden("timeouts-and-errors", &checks);
}

#[test]
fn an_empty_run_verified_nothing() {
    assert_eq!(summary_line(&[]), "0 blocks, 0 warnings, 0 passed");
    assert_eq!(last_line(&[]), "READY with warnings: nothing was checked");
}

#[test]
fn singular_and_plural_forms_of_every_part() {
    let one = cat(vec![
        many(1, || result(Severity::Block, Status::Block)),
        many(1, || result(Severity::Warn, Status::Warn)),
        many(1, || skipped(Severity::Block, SkipKind::MissingNeed)),
        many(1, || skipped(Severity::Warn, SkipKind::MissingNeed)),
        many(1, || skipped(Severity::Block, SkipKind::NotApplicable)),
    ]);
    assert_eq!(
        summary_line(&one),
        "1 block, 1 warning, 0 passed, 1 required check not run, 1 optional check not run, 1 not applicable"
    );
    let two = cat(vec![
        many(2, || result(Severity::Block, Status::Block)),
        many(2, || result(Severity::Warn, Status::Warn)),
        many(2, || skipped(Severity::Block, SkipKind::MissingNeed)),
        many(2, || skipped(Severity::Warn, SkipKind::MissingNeed)),
        many(2, || skipped(Severity::Block, SkipKind::NotApplicable)),
    ]);
    assert_eq!(
        summary_line(&two),
        "2 blocks, 2 warnings, 0 passed, 2 required checks not run, 2 optional checks not run, 2 not applicable"
    );
}

#[test]
fn zero_parts_after_the_three_fixed_ones_are_left_out() {
    let checks = many(2, || result(Severity::Block, Status::Pass));
    assert_eq!(summary_line(&checks), "0 blocks, 0 warnings, 2 passed");
}

#[test]
fn the_suffix_names_a_timeout_a_failure_or_both() {
    let timed_out = cat(vec![
        many(1, || result(Severity::Block, Status::Timeout)),
        many(3, || skipped(Severity::Block, SkipKind::MissingNeed)),
    ]);
    assert!(summary_line(&timed_out).ends_with("4 required checks not run (1 timed out)"));

    let failed = many(1, || result(Severity::Block, Status::Error));
    assert!(summary_line(&failed).ends_with("1 required check not run (1 failed)"));

    let both = cat(vec![
        many(1, || result(Severity::Block, Status::Timeout)),
        many(1, || result(Severity::Block, Status::Error)),
    ]);
    assert!(summary_line(&both).ends_with("2 required checks not run (1 timed out, 1 failed)"));
}

#[test]
fn an_optional_timeout_is_counted_in_the_optional_part_only() {
    let checks = cat(vec![
        many(1, || result(Severity::Warn, Status::Timeout)),
        many(1, || result(Severity::Block, Status::Pass)),
    ]);
    assert_eq!(
        summary_line(&checks),
        "0 blocks, 0 warnings, 1 passed, 1 optional check not run (1 timed out)"
    );
    assert_eq!(last_line(&checks), "READY with warnings");
}

#[test]
fn an_unknown_status_is_not_run_without_a_suffix() {
    let checks = cat(vec![
        many(1, || {
            result(Severity::Block, Status::Unknown("paused".into()))
        }),
        many(1, || result(Severity::Block, Status::Pass)),
    ]);
    assert_eq!(
        summary_line(&checks),
        "0 blocks, 0 warnings, 1 passed, 1 required check not run"
    );
    assert_eq!(
        last_line(&checks),
        "NOT READY: 1 required check was not run"
    );
}

#[test]
fn an_unknown_severity_counts_as_required() {
    let checks = many(1, || {
        result(Severity::Unknown("urgent".into()), Status::Error)
    });
    assert_eq!(
        summary_line(&checks),
        "0 blocks, 0 warnings, 0 passed, 1 required check not run (1 failed)"
    );
}

#[test]
fn a_timeout_marked_not_applicable_by_mistake_still_counts_as_not_run() {
    let mut c = result(Severity::Block, Status::Timeout);
    c.skip_kind = Some(SkipKind::NotApplicable);
    c.refresh_bucket();
    let checks = [c];
    assert_eq!(
        summary_line(&checks),
        "0 blocks, 0 warnings, 0 passed, 1 required check not run (1 timed out)"
    );
}

#[test]
fn the_stored_bucket_is_never_trusted() {
    let mut c = result(Severity::Block, Status::Block);
    c.bucket = rdy_spec::result::Bucket::Passed;
    let checks = [c];
    assert_eq!(summary_line(&checks), "1 block, 0 warnings, 0 passed");
    assert_eq!(last_line(&checks), "NOT READY");
}

#[test]
fn every_row_of_the_last_line_table() {
    let line =
        |verdict, reason: Option<VerdictReason>, n| verdict_line(verdict, reason.as_ref(), n);
    assert_eq!(line(Verdict::Ready, None, 0), "READY");
    assert_eq!(
        line(Verdict::ReadyWithWarnings, None, 0),
        "READY with warnings"
    );
    assert_eq!(
        line(
            Verdict::ReadyWithWarnings,
            Some(VerdictReason::NothingVerified),
            0
        ),
        "READY with warnings: nothing was checked"
    );
    assert_eq!(line(Verdict::NotReady, None, 0), "NOT READY");
    assert_eq!(line(Verdict::NotReady, None, 4), "NOT READY");
    assert_eq!(
        line(
            Verdict::NotReady,
            Some(VerdictReason::RequiredCheckNotRun),
            1
        ),
        "NOT READY: 1 required check was not run"
    );
    assert_eq!(
        line(
            Verdict::NotReady,
            Some(VerdictReason::RequiredCheckNotRun),
            2
        ),
        "NOT READY: 2 required checks were not run"
    );
}

#[test]
fn a_reason_this_version_does_not_know_prints_the_plain_verdict() {
    let unknown = || Some(VerdictReason::Unknown("future".into()));
    let line = |verdict, n| verdict_line(verdict, unknown().as_ref(), n);
    assert_eq!(line(Verdict::NotReady, 3), "NOT READY");
    assert_eq!(line(Verdict::ReadyWithWarnings, 0), "READY with warnings");
    assert_eq!(line(Verdict::Ready, 0), "READY");
}

#[test]
fn required_check_not_run_with_a_zero_count_prints_the_plain_verdict() {
    let reason = VerdictReason::RequiredCheckNotRun;
    assert_eq!(
        verdict_line(Verdict::NotReady, Some(&reason), 0),
        "NOT READY"
    );
}

#[test]
fn the_last_line_follows_the_verdict_of_the_checks() {
    let blocked = cat(vec![
        many(1, || result(Severity::Block, Status::Block)),
        many(2, || skipped(Severity::Block, SkipKind::MissingNeed)),
    ]);
    // A block was seen, so the reason is gone and the count stays in the summary line.
    assert_eq!(last_line(&blocked), "NOT READY");
}
