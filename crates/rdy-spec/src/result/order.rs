//! Display order of the checks of a report (01 section 5.2).
//!
//! The terminal, the HTML report and the portal list checks by `bucket`: blocker, required_not_run,
//! warning, passed, not_applicable, then spec order inside a bucket. A bucket this version does not know
//! sorts with required_not_run (01 section 3.2). They all call the functions here, so
//! the order lives in one place. The functions read the stored `bucket` and never recompute it.

use super::codes::Bucket;
use super::model::CheckResult;

/// Checks in display order: by bucket, then the order they were given (spec order).
///
/// The sort is stable, so spec order holds inside a bucket. An unknown bucket sorts with
/// `required_not_run`, in spec order among those checks ([`Bucket::order_key`]). The result borrows from
/// `checks`.
#[must_use]
pub fn sort_by_bucket(checks: &[CheckResult]) -> Vec<&CheckResult> {
    let mut sorted: Vec<&CheckResult> = checks.iter().collect();
    sorted.sort_by_key(|c| c.bucket.order_key());
    sorted
}

/// The checks of one display section.
#[derive(Debug, Clone, PartialEq)]
pub struct BucketGroup<'a> {
    /// The bucket of the section. Checks with a bucket this version does not know sit in the
    /// `required_not_run` section, so a group holding any of them is labelled [`Bucket::RequiredNotRun`].
    pub bucket: Bucket,
    /// The checks of the section, in spec order. Never empty.
    pub checks: Vec<&'a CheckResult>,
}

/// Checks split into display sections, in display order. A bucket with no checks has no section.
///
/// Concatenating the sections gives [`sort_by_bucket`].
#[must_use]
pub fn group_by_bucket(checks: &[CheckResult]) -> Vec<BucketGroup<'_>> {
    let mut groups: Vec<BucketGroup<'_>> = Vec::new();
    for check in sort_by_bucket(checks) {
        match groups.last_mut() {
            Some(group) if group.bucket.order_key() == check.bucket.order_key() => {
                group.checks.push(check);
            }
            _ => groups.push(BucketGroup {
                bucket: section_bucket(&check.bucket),
                checks: vec![check],
            }),
        }
    }
    groups
}

/// The bucket a section is labelled with: an unknown bucket is shown as `required_not_run`.
fn section_bucket(bucket: &Bucket) -> Bucket {
    if bucket.is_unknown() {
        Bucket::RequiredNotRun
    } else {
        bucket.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{Severity, SkipKind, Status, Summary};

    /// One check per outcome the engine can produce, listed in an order that is not the display order.
    fn every_outcome() -> Vec<CheckResult> {
        let mut checks = Vec::new();
        let mut add = |id: &str, severity: &str, status: &str, skip: Option<&str>| {
            let mut c =
                CheckResult::new(id, "host", Severity::from(severity), Status::from(status));
            c.skip_kind = skip.map(SkipKind::from);
            c.refresh_bucket();
            checks.push(c);
        };
        add(
            "n1.not_applicable",
            "block",
            "skipped",
            Some("not_applicable"),
        );
        add("p1.pass", "block", "pass", None);
        add("w1.optional_skip", "warn", "skipped", Some("missing_need"));
        add("b1.block", "block", "block", None);
        add("r1.required_skip", "block", "skipped", Some("missing_need"));
        add("w2.warn", "warn", "warn", None);
        add("r2.timeout", "block", "timeout", None);
        add("p2.pass", "warn", "pass", None);
        add("b2.block", "warn", "block", None);
        add("r3.error", "block", "error", None);
        add("w3.optional_timeout", "warn", "timeout", None);
        add(
            "n2.not_applicable",
            "warn",
            "skipped",
            Some("not_applicable"),
        );
        // The other skip kinds the engine writes: all of them are not run.
        add("r4.not_in_build", "block", "skipped", Some("not_in_build"));
        add(
            "w4.unsupported_spec",
            "warn",
            "skipped",
            Some("unsupported_spec"),
        );
        add(
            "r5.unknown_check",
            "block",
            "skipped",
            Some("unknown_check"),
        );
        add(
            "r6.not_yet_on_os",
            "block",
            "skipped",
            Some("not_yet_on_os"),
        );
        add("w5.run_deadline", "warn", "skipped", Some("run_deadline"));
        add("r7.cancelled", "block", "skipped", Some("cancelled"));
        // An optional check that errored.
        add("w6.optional_error", "warn", "error", None);
        // A status and a severity this version does not know: unknown status is not run, unknown
        // severity is required.
        add("r8.unknown_status", "block", "paused", None);
        add("p3.unknown_severity_pass", "fatal", "pass", None);
        add(
            "r9.unknown_severity_skip",
            "fatal",
            "skipped",
            Some("missing_need"),
        );
        checks
    }

    fn ids<'a>(checks: impl IntoIterator<Item = &'a CheckResult>) -> Vec<&'a str> {
        checks.into_iter().map(|c| c.id.as_str()).collect()
    }

    #[test]
    fn every_outcome_sorts_blocker_required_warning_passed_not_applicable() {
        let checks = every_outcome();
        let sorted = sort_by_bucket(&checks);
        let buckets: Vec<Bucket> = sorted.iter().map(|c| c.bucket.clone()).collect();
        let mut expected = Vec::new();
        for (bucket, n) in [
            (Bucket::Blocker, 2),
            (Bucket::RequiredNotRun, 9),
            (Bucket::Warning, 6),
            (Bucket::Passed, 3),
            (Bucket::NotApplicable, 2),
        ] {
            expected.extend(std::iter::repeat_n(bucket, n));
        }
        assert_eq!(buckets, expected);
        // Spec order holds inside each bucket.
        assert_eq!(
            ids(sorted),
            [
                "b1.block",
                "b2.block",
                "r1.required_skip",
                "r2.timeout",
                "r3.error",
                "r4.not_in_build",
                "r5.unknown_check",
                "r6.not_yet_on_os",
                "r7.cancelled",
                "r8.unknown_status",
                "r9.unknown_severity_skip",
                "w1.optional_skip",
                "w2.warn",
                "w3.optional_timeout",
                "w4.unsupported_spec",
                "w5.run_deadline",
                "w6.optional_error",
                "p1.pass",
                "p2.pass",
                "p3.unknown_severity_pass",
                "n1.not_applicable",
                "n2.not_applicable",
            ]
        );
    }

    #[test]
    fn bucket_counts_equal_the_summary() {
        let checks = every_outcome();
        let s = Summary::from_checks(&checks);
        let groups = group_by_bucket(&checks);
        let count = |b: Bucket| {
            let n = groups
                .iter()
                .find(|g| g.bucket == b)
                .map_or(0, |g| g.checks.len());
            u32::try_from(n).unwrap_or(u32::MAX)
        };
        assert_eq!(count(Bucket::Blocker), s.block);
        assert_eq!(count(Bucket::RequiredNotRun), s.required_not_run);
        assert_eq!(count(Bucket::Warning), s.warn + s.optional_not_run);
        assert_eq!(count(Bucket::Passed), s.pass);
        assert_eq!(count(Bucket::NotApplicable), s.not_applicable);
        let total: usize = groups.iter().map(|g| g.checks.len()).sum();
        assert_eq!(u32::try_from(total).ok(), Some(s.total));
    }

    #[test]
    fn groups_follow_the_sort_and_skip_empty_buckets() {
        let checks = every_outcome();
        let flat: Vec<&CheckResult> = group_by_bucket(&checks)
            .into_iter()
            .flat_map(|g| g.checks)
            .collect();
        assert_eq!(flat, sort_by_bucket(&checks));

        let only_pass: Vec<CheckResult> = checks
            .iter()
            .filter(|c| c.bucket == Bucket::Passed)
            .cloned()
            .collect();
        let groups = group_by_bucket(&only_pass);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].bucket, Bucket::Passed);
        assert!(group_by_bucket(&[]).is_empty());
        assert!(sort_by_bucket(&[]).is_empty());
    }

    #[test]
    fn the_stored_bucket_decides_the_order() {
        // A reader never recomputes: a stored bucket is taken as written.
        let mut checks = every_outcome();
        let mut moved = checks[1].clone();
        moved.id = "moved".into();
        moved.bucket = Bucket::Blocker;
        checks.push(moved);
        let sorted = sort_by_bucket(&checks);
        assert_eq!(ids(sorted)[..3], ["b1.block", "b2.block", "moved"]);
    }

    #[test]
    fn an_unknown_bucket_sorts_with_required_not_run_in_spec_order() {
        let mut checks = every_outcome();
        let unknown = |id: &str, text: &str| {
            let mut c = CheckResult::new(id, "host", Severity::from("block"), Status::from("pass"));
            c.bucket = Bucket::from(text);
            c
        };
        // One in the middle of the list (after r1.required_skip), two at the end.
        checks.insert(5, unknown("u1", "frozen"));
        checks.push(unknown("u2", "chilled"));
        checks.push(unknown("u3", "frozen"));
        let groups = group_by_bucket(&checks);
        // Still five sections: the unknown ones sit inside the required section.
        let order: Vec<Bucket> = groups.iter().map(|g| g.bucket.clone()).collect();
        assert_eq!(
            order,
            [
                Bucket::Blocker,
                Bucket::RequiredNotRun,
                Bucket::Warning,
                Bucket::Passed,
                Bucket::NotApplicable,
            ]
        );
        assert!(groups.iter().all(|g| !g.bucket.is_unknown()));
        assert_eq!(
            ids(groups[1].checks.iter().copied()),
            [
                "r1.required_skip",
                "u1",
                "r2.timeout",
                "r3.error",
                "r4.not_in_build",
                "r5.unknown_check",
                "r6.not_yet_on_os",
                "r7.cancelled",
                "r8.unknown_status",
                "r9.unknown_severity_skip",
                "u2",
                "u3",
            ]
        );
        // The stored bucket of each check is untouched.
        assert_eq!(groups[1].checks[1].bucket, Bucket::Unknown("frozen".into()));
    }
}
