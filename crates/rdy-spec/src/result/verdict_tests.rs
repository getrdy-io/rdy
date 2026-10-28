//! Table tests for the verdict rule, taken from 01 section 5.3 and ADR 0013.

use super::{
    Bucket, CheckResult, ExitCode, Need, Partial, Severity, SkipKind, Status, Summary, Verdict,
    VerdictReason, apply_partial_rule, is_not_run, is_required, verdict,
};

const NOT_RUN_KINDS: [&str; 8] = [
    "missing_need",
    "not_in_build",
    "unknown_check",
    "unsupported_spec",
    "not_yet_on_os",
    "run_deadline",
    "cancelled",
    "from_a_later_release",
];

fn sev(text: &str) -> Severity {
    Severity::from(text)
}

fn check(severity: &str, status: &str, skip_kind: Option<&str>) -> CheckResult {
    let mut c = CheckResult::new("host.x", "host", sev(severity), Status::from(status));
    c.skip_kind = skip_kind.map(SkipKind::from);
    c.refresh_bucket();
    c
}

/// One row: a run of a single check, and what the rule says about it.
struct Row {
    severity: &'static str,
    status: &'static str,
    skip_kind: Option<&'static str>,
    bucket: Bucket,
    verdict: Verdict,
    reason: Option<VerdictReason>,
    exit: u8,
}

fn row(
    severity: &'static str,
    status: &'static str,
    skip_kind: Option<&'static str>,
    bucket: Bucket,
    verdict: Verdict,
    reason: Option<VerdictReason>,
    exit: u8,
) -> Row {
    Row {
        severity,
        status,
        skip_kind,
        bucket,
        verdict,
        reason,
        exit,
    }
}

/// Every severity and status pair, as a run of one check. Written out, not derived from the rule.
fn single_check_table() -> Vec<Row> {
    use Bucket as B;
    use Verdict as V;
    use VerdictReason as R;
    let mut t = Vec::new();
    // block and an unknown severity are the same: required.
    for s in ["block", "critical"] {
        t.push(row(s, "pass", None, B::Passed, V::Ready, None, 0));
        t.push(row(
            s,
            "warn",
            None,
            B::Warning,
            V::ReadyWithWarnings,
            None,
            1,
        ));
        t.push(row(s, "block", None, B::Blocker, V::NotReady, None, 2));
        for kind in NOT_RUN_KINDS {
            t.push(row(
                s,
                "skipped",
                Some(kind),
                B::RequiredNotRun,
                V::NotReady,
                Some(R::RequiredCheckNotRun),
                2,
            ));
        }
        // A skipped result with no skip_kind is malformed. It counts as not run.
        t.push(row(
            s,
            "skipped",
            None,
            B::RequiredNotRun,
            V::NotReady,
            Some(R::RequiredCheckNotRun),
            2,
        ));
        t.push(row(
            s,
            "skipped",
            Some("not_applicable"),
            B::NotApplicable,
            V::ReadyWithWarnings,
            Some(R::NothingVerified),
            1,
        ));
        for status in ["timeout", "error", "quarantined"] {
            t.push(row(
                s,
                status,
                None,
                B::RequiredNotRun,
                V::NotReady,
                Some(R::RequiredCheckNotRun),
                2,
            ));
        }
    }
    // warn severity: not required.
    t.push(row("warn", "pass", None, B::Passed, V::Ready, None, 0));
    t.push(row(
        "warn",
        "warn",
        None,
        B::Warning,
        V::ReadyWithWarnings,
        None,
        1,
    ));
    t.push(row("warn", "block", None, B::Blocker, V::NotReady, None, 2));
    for kind in NOT_RUN_KINDS {
        t.push(row(
            "warn",
            "skipped",
            Some(kind),
            B::Warning,
            V::ReadyWithWarnings,
            Some(R::NothingVerified),
            1,
        ));
    }
    t.push(row(
        "warn",
        "skipped",
        Some("not_applicable"),
        B::NotApplicable,
        V::ReadyWithWarnings,
        Some(R::NothingVerified),
        1,
    ));
    for status in ["timeout", "error", "quarantined"] {
        t.push(row(
            "warn",
            status,
            None,
            B::Warning,
            V::ReadyWithWarnings,
            Some(R::NothingVerified),
            1,
        ));
    }
    t
}

#[test]
fn every_severity_and_status_pair() {
    for r in single_check_table() {
        let c = check(r.severity, r.status, r.skip_kind);
        let what = format!("{} {} {:?}", r.severity, r.status, r.skip_kind);
        assert_eq!(c.bucket, r.bucket, "bucket of {what}");
        let j = verdict(std::slice::from_ref(&c));
        assert_eq!(j.verdict, r.verdict, "verdict of {what}");
        assert_eq!(j.reason, r.reason, "reason of {what}");
        assert_eq!(j.exit_code(), r.exit, "exit code of {what}");
        assert_eq!(j.verdict.exit_code().code(), r.exit);
    }
}

#[test]
fn a_skipped_block_check_is_not_ready_with_exit_2() {
    let c = check("block", "skipped", Some("missing_need"));
    let j = verdict(&[c]);
    assert_eq!(j.verdict, Verdict::NotReady);
    assert_eq!(j.reason, Some(VerdictReason::RequiredCheckNotRun));
    assert_eq!(j.exit_code(), 2);
}

#[test]
fn timeout_and_error_block_like_a_skip() {
    for status in ["timeout", "error"] {
        let j = verdict(&[check("block", status, None), check("block", "pass", None)]);
        assert_eq!(j.verdict, Verdict::NotReady, "{status}");
        assert_eq!(j.exit_code(), 2, "{status}");
    }
}

#[test]
fn not_applicable_has_no_effect() {
    let na = || check("block", "skipped", Some("not_applicable"));
    // Next to a pass it leaves the run READY.
    let j = verdict(&[check("block", "pass", None), na()]);
    assert_eq!((j.verdict, j.reason), (Verdict::Ready, None));
    // Next to a warning it changes nothing.
    let j = verdict(&[check("block", "warn", None), na()]);
    assert_eq!((j.verdict, j.reason), (Verdict::ReadyWithWarnings, None));
    // Next to a required skip it does not hide it.
    let j = verdict(&[na(), check("block", "skipped", Some("not_in_build"))]);
    assert_eq!(j.verdict, Verdict::NotReady);
    // The summary does not count it as required, optional or a block.
    let s = Summary::from_checks(&[na()]);
    assert_eq!(
        (
            s.not_applicable,
            s.required_not_run,
            s.optional_not_run,
            s.skipped
        ),
        (1, 0, 0, 1)
    );
}

/// Only the spec's `os` list may relax a requirement. A stray skip kind on a result that is not
/// skipped does not.
#[test]
fn not_applicable_on_another_status_is_ignored() {
    for status in ["timeout", "error", "quarantined"] {
        let c = check("block", status, Some("not_applicable"));
        assert_eq!(c.bucket, Bucket::RequiredNotRun, "{status}");
        assert_eq!(verdict(&[c]).verdict, Verdict::NotReady, "{status}");
    }
}

#[test]
fn unknown_severity_counts_as_block() {
    assert!(is_required(&sev("critical")));
    assert!(is_required(&sev("block")));
    assert!(!is_required(&sev("warn")));
    let j = verdict(&[
        check("catastrophic", "skipped", Some("missing_need")),
        check("block", "pass", None),
    ]);
    assert_eq!(j.verdict, Verdict::NotReady);
    let s = Summary::from_checks(&[check("catastrophic", "timeout", None)]);
    assert_eq!((s.required_not_run, s.optional_not_run), (1, 0));
}

#[test]
fn unknown_status_counts_as_not_run() {
    assert!(is_not_run(&Status::from("quarantined"), None));
    assert!(!is_not_run(&Status::Pass, None));
    let s = Summary::from_checks(&[
        check("block", "quarantined", None),
        check("warn", "quarantined", None),
    ]);
    // Counted in total and in the not-run views, in no status field.
    assert_eq!(s.total, 2);
    assert_eq!(
        s.pass + s.warn + s.block + s.skipped + s.timeout + s.error,
        0
    );
    assert_eq!((s.required_not_run, s.optional_not_run), (1, 1));
}

#[test]
fn a_run_that_verified_nothing_is_at_least_ready_with_warnings() {
    let nothing = Some(VerdictReason::NothingVerified);
    // The empty run.
    let j = verdict(&[]);
    assert_eq!(
        (j.verdict, j.reason.clone(), j.exit_code()),
        (Verdict::ReadyWithWarnings, nothing.clone(), 1)
    );
    // All not applicable.
    let na = check("block", "skipped", Some("not_applicable"));
    let j = verdict(&[na.clone(), na.clone(), na.clone()]);
    assert_eq!(
        (j.verdict, j.reason),
        (Verdict::ReadyWithWarnings, nothing.clone())
    );
    // Only optional checks that did not run.
    let j = verdict(&[na, check("warn", "timeout", None)]);
    assert_eq!((j.verdict, j.reason), (Verdict::ReadyWithWarnings, nothing));
    // A required check that did not run is NOT READY, not "nothing verified".
    let j = verdict(&[check("block", "error", None)]);
    assert_eq!(
        (j.verdict, j.reason),
        (Verdict::NotReady, Some(VerdictReason::RequiredCheckNotRun))
    );
}

#[test]
fn an_observed_block_leaves_the_reason_empty() {
    let j = verdict(&[
        check("block", "block", None),
        check("block", "skipped", Some("not_in_build")),
    ]);
    assert_eq!((j.verdict, j.reason), (Verdict::NotReady, None));
}

#[test]
fn mixed_runs() {
    use Verdict as V;
    let p = || check("block", "pass", None);
    let w = || check("warn", "warn", None);
    let opt_skip = || check("warn", "skipped", Some("missing_need"));
    // Passes and a warning.
    assert_eq!(verdict(&[p(), w()]).verdict, V::ReadyWithWarnings);
    // Passes and an optional check that did not run: warnings, with a real pass, so no reason.
    let j = verdict(&[p(), opt_skip()]);
    assert_eq!((j.verdict, j.reason), (V::ReadyWithWarnings, None));
    // The 01 section 7.2 shape: 2 blocks, 1 warning, 3 passed, 2 required not run.
    let run = [
        p(),
        p(),
        p(),
        check("block", "block", None),
        check("block", "block", None),
        check("warn", "warn", None),
        check("block", "skipped", Some("not_in_build")),
        check("block", "skipped", Some("not_in_build")),
    ];
    let j = verdict(&run);
    let exit = j.exit_code();
    assert_eq!((j.verdict, j.reason, exit), (V::NotReady, None, 2));
    let s = Summary::from_checks(&run);
    assert_eq!(
        (
            s.total,
            s.pass,
            s.warn,
            s.block,
            s.skipped,
            s.required_not_run
        ),
        (8, 3, 1, 2, 2, 2)
    );
}

#[test]
fn the_stored_bucket_is_not_trusted() {
    let mut c = check("block", "skipped", Some("missing_need"));
    c.bucket = Bucket::Passed;
    assert_eq!(verdict(std::slice::from_ref(&c)).verdict, Verdict::NotReady);
    assert_eq!(Summary::from_checks(&[c]).required_not_run, 1);
}

#[test]
fn summary_identities_hold_for_known_statuses() {
    let mut run = Vec::new();
    for status in ["pass", "warn", "block", "timeout", "error"] {
        for severity in ["block", "warn"] {
            run.push(check(severity, status, None));
        }
    }
    for kind in NOT_RUN_KINDS.iter().chain(&["not_applicable"]) {
        run.push(check("block", "skipped", Some(kind)));
        run.push(check("warn", "skipped", Some(kind)));
    }
    let s = Summary::from_checks(&run);
    assert_eq!(
        s.pass + s.warn + s.block + s.skipped + s.timeout + s.error,
        s.total
    );
    assert_eq!(usize::try_from(s.total).ok(), Some(run.len()));
    let count =
        |b: Bucket| u32::try_from(run.iter().filter(|c| c.bucket == b).count()).unwrap_or(u32::MAX);
    assert_eq!(count(Bucket::Blocker), s.block);
    assert_eq!(count(Bucket::RequiredNotRun), s.required_not_run);
    assert_eq!(count(Bucket::NotApplicable), s.not_applicable);
    assert_eq!(count(Bucket::Passed), s.pass);
    // The warning bucket holds the warn status and the optional checks that did not run.
    assert_eq!(count(Bucket::Warning), s.warn + s.optional_not_run);
    // The three views sit inside skipped + timeout + error.
    assert_eq!(
        s.required_not_run + s.optional_not_run + s.not_applicable,
        s.skipped + s.timeout + s.error
    );
}

#[test]
fn bucket_order_key() {
    let order = [
        Bucket::Blocker,
        Bucket::RequiredNotRun,
        Bucket::Unknown("frozen".into()),
        Bucket::Warning,
        Bucket::Passed,
        Bucket::NotApplicable,
    ];
    for pair in order.windows(2) {
        assert!(pair[0].order_key() < pair[1].order_key(), "{pair:?}");
    }
}

#[test]
fn exit_codes() {
    assert_eq!(Verdict::Ready.exit_code(), ExitCode::Ready);
    assert_eq!(Verdict::ReadyWithWarnings.exit_code(), ExitCode::Warnings);
    assert_eq!(Verdict::NotReady.exit_code(), ExitCode::Blockers);
    let codes = [
        (ExitCode::Ready, 0),
        (ExitCode::Warnings, 1),
        (ExitCode::Blockers, 2),
        (ExitCode::Usage, 64),
        (ExitCode::Internal, 70),
    ];
    for (code, n) in codes {
        assert_eq!(code.code(), n);
        assert_eq!(u8::from(code), n);
    }
}

// The partial rule (ADR 0013 decision 4).

fn partial(missing: &[Need], note: &str) -> Partial {
    Partial::new(missing.to_vec(), note)
}

#[test]
fn partial_pass_on_a_required_check_becomes_warn() {
    let p = partial(&[Need::Root], "not verified: root");
    for severity in ["block", "critical"] {
        let s = apply_partial_rule(Status::Pass, &sev(severity), Some(&p), &[]);
        assert_eq!(s, Status::Warn, "{severity}");
    }
    // And the run is READY with warnings, exit 1, not READY.
    let mut c = check("block", "pass", None);
    c.status = apply_partial_rule(Status::Pass, &c.severity, Some(&p), &[]);
    c.refresh_bucket();
    let j = verdict(&[c]);
    assert_eq!((j.verdict, j.exit_code()), (Verdict::ReadyWithWarnings, 1));
}

#[test]
fn partial_pass_on_an_optional_check_stays_pass() {
    let p = partial(&[Need::Root], "x");
    assert_eq!(
        apply_partial_rule(Status::Pass, &Severity::Warn, Some(&p), &[]),
        Status::Pass
    );
}

#[test]
fn evidence_only_wants_cannot_change_the_level() {
    let p = partial(&[Need::Command], "no ip command");
    assert_eq!(
        apply_partial_rule(Status::Pass, &Severity::Block, Some(&p), &[Need::Command]),
        Status::Pass
    );
    // One missing want that is not evidence only is enough.
    let p = partial(&[Need::Command, Need::Root], "x");
    assert_eq!(
        apply_partial_rule(Status::Pass, &Severity::Block, Some(&p), &[Need::Command]),
        Status::Warn
    );
}

#[test]
fn a_partial_os_note_always_applies() {
    // A Partial OS sets partial with the OS note and no missing need. Nothing is evidence only.
    let p = partial(&[], "env only on macOS");
    assert_eq!(
        apply_partial_rule(Status::Pass, &Severity::Block, Some(&p), &[]),
        Status::Warn
    );
    assert_eq!(
        apply_partial_rule(Status::Pass, &Severity::Block, Some(&p), &[Need::Root]),
        Status::Warn
    );
}

#[test]
fn the_partial_rule_changes_nothing_else() {
    let p = partial(&[Need::Root], "x");
    for status in [
        "warn",
        "block",
        "skipped",
        "timeout",
        "error",
        "quarantined",
    ] {
        let s = Status::from(status);
        assert_eq!(
            apply_partial_rule(s.clone(), &Severity::Block, Some(&p), &[]),
            s,
            "{status}"
        );
    }
    assert_eq!(
        apply_partial_rule(Status::Pass, &Severity::Block, None, &[]),
        Status::Pass
    );
}
