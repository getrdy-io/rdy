//! `normalize`: makes two reports of the same environment comparable (08 Appendix C).
//!
//! Determinism comes first: the harness pins the clock, the run id, the host and the environment, and
//! those fields are not touched here. `normalize` scrubs only what a run cannot pin: how long things
//! took, which build wrote the file, and the order that concurrent checks wrote their action log in.

use rdy_spec::result::Report;

/// Stands for `producer.version`.
pub const VERSION: &str = "<version>";
/// Stands for `producer.commit`.
pub const COMMIT: &str = "<commit>";
/// Stands for `producer.target`.
pub const TARGET: &str = "<target>";
/// Stands for `producer.rdy_spec`.
pub const RDY_SPEC: &str = "<rdy_spec>";

/// Scrubs `report` as 08 Appendix C says:
///
/// - `run.duration_ms`, each check's `duration_ms` and `started_ms`, and each action's `at_ms` and
///   `duration_ms` become 0. `timeout_after_ms` stays, because it is the configured limit.
/// - `producer.version`, `commit` and `target` become `<version>`, `<commit>` and `<target>`, so a
///   release or a CI leg never changes a golden. `producer.rdy_spec` becomes `<rdy_spec>` for the same
///   reason: it moves with every release of the crate.
/// - The action log is sorted by the position of its check in the report (run-level entries first),
///   then by the order that check wrote them in, and `seq` is numbered again from 1.
///
/// Everything else is left alone, so a golden still fails when a message, a verdict or a count changes.
///
/// ```
/// # use rdy_engine::testing::normalize;
/// # use rdy_spec::result::{Host, HostOs, HostOsFamily, Identity, Producer, Report, Run, RunOptions, Signature, SpecRef};
/// let mut report = Report::new(
///     Producer::new("1.2.3", "1.2.3", "x86_64-unknown-linux-musl"),
///     Run::new("id", "2026-11-02T09:00:00.000Z", "2026-11-02T09:00:01.250Z", 1250, RunOptions::new(8, 300_000)),
///     SpecRef::new("acme", "00", "spec.yaml", 1),
///     Signature::unsigned(),
///     Host::new("host-a.example", HostOs::new(HostOsFamily::Linux), "x86_64"),
///     Identity::new(Some(1000), None, false),
///     Vec::new(),
/// );
/// normalize(&mut report);
/// assert_eq!(report.producer.version, "<version>");
/// assert_eq!(report.run.duration_ms, 0);
/// ```
pub fn normalize(report: &mut Report) {
    report.run.duration_ms = 0;
    VERSION.clone_into(&mut report.producer.version);
    TARGET.clone_into(&mut report.producer.target);
    RDY_SPEC.clone_into(&mut report.producer.rdy_spec);
    report.producer.commit = Some(COMMIT.to_owned());

    for check in &mut report.checks {
        check.started_ms = 0;
        check.duration_ms = 0;
    }

    let position = |key: &Option<String>| match key {
        None => 0,
        Some(key) => report
            .checks
            .iter()
            .position(|check| &check.key == key)
            .map_or(usize::MAX, |at| at + 1),
    };
    let mut order: Vec<(usize, u64, usize)> = report
        .actions
        .iter()
        .enumerate()
        .map(|(at, action)| (position(&action.check), action.seq, at))
        .collect();
    // `at` breaks a tie between equal `seq`, so the sort is the same on every run.
    order.sort_unstable();
    let mut taken: Vec<Option<rdy_spec::result::Action>> = std::mem::take(&mut report.actions)
        .into_iter()
        .map(Some)
        .collect();
    report.actions = order
        .into_iter()
        .filter_map(|(_, _, at)| taken.get_mut(at).and_then(Option::take))
        .zip(1_u64..)
        .map(|(mut action, seq)| {
            action.seq = seq;
            action.at_ms = 0;
            action.duration_ms = 0;
            action
        })
        .collect();
}

/// [`normalize`], and sets `run.options.jobs` to 1.
///
/// The jobs value is the one input the "same report at `jobs = 1` and `jobs = 8`" test varies on
/// purpose, and the report records it. Use [`normalize`] for a golden and this for that comparison.
pub fn normalize_across_jobs(report: &mut Report) {
    normalize(report);
    report.run.options.jobs = 1;
}
