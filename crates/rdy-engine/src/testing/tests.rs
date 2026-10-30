//! Tests of the test helpers: `run_fixture`, `assert_within_manifest` and `normalize` (M1-051).
//! `FakeCheck` is proved by the scheduler tests, which use it.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rdy_spec::result::{
    Action, ActionKind, ActionOutcome, CheckResult, Host, HostOs, HostOsFamily, Identity, Producer,
    Report, Run, RunOptions, Severity, Signature, SpecRef, Status,
};

use super::*;
use crate::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Need,
    OsSupport, Support,
};

const META: CheckMeta = CheckMeta {
    title: "Test check",
    remediation: "Nothing to fix. This check is a test double.",
};

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

const fn info(id: &'static str, needs: &'static [Need]) -> CheckInfo {
    CheckInfo {
        id,
        family: "host",
        summary: "A test check.",
        meta: META,
        needs,
        wants: &[],
        default_timeout: None,
        os: FULL,
        reads: &["/proc/meminfo"],
        statfs: &[],
        env: &[],
        commands: &[],
        peers: &[],
    }
}

static MEMORY: CheckInfo = info("host.memory", &[]);
static MEMORY_NEEDS_ROOT: CheckInfo = info("host.memory", &[Need::Root]);
static CPU: CheckInfo = info("host.cpu", &[]);

/// Reads the paths it is told to, ignores every error and passes. A check that does this is the case
/// `assert_within_manifest` exists for.
struct Reader {
    info: &'static CheckInfo,
    paths: &'static [&'static str],
    ran: Arc<AtomicBool>,
}

impl Reader {
    fn new(info: &'static CheckInfo, paths: &'static [&'static str]) -> Self {
        Self {
            info,
            paths,
            ran: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Check for Reader {
    fn info(&self) -> &'static CheckInfo {
        self.info
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            self.ran.store(true, Ordering::SeqCst);
            let mut total = 0;
            for path in self.paths {
                if let Ok(file) = ctx.probe().read(Path::new(path)).await {
                    total += file.bytes.len();
                }
            }
            Ok(Finding::pass(format!("read {total} bytes")))
        })
    }
}

const CASE: &str = "checks/host.memory/pass";

#[tokio::test]
async fn a_check_runs_against_the_fixture_and_stays_inside_its_manifest() {
    let check = Reader::new(&MEMORY, &["/proc/meminfo"]);
    let run = run_fixture(&check, CASE).await.expect("the fixture loads");

    assert!(run.finding().message.starts_with("read "), "{run:?}");
    assert_eq!(run.fixture().name(), CASE);
    assert_eq!(run.info().id, "host.memory");
    let reads: Vec<_> = run
        .log()
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Read)
        .collect();
    assert_eq!(reads.len(), 1, "{:?}", run.log());
    assert_eq!(reads[0].outcome, ActionOutcome::Ok);
    assert_eq!(reads[0].check.as_deref(), Some("host.memory"));
    assert!(manifest_violations(run.info(), run.log()).is_empty());
    run.assert_within_manifest();
}

#[tokio::test]
async fn a_fixture_that_does_not_answer_the_check_fails_naming_the_check_before_it_runs() {
    let check = Reader::new(&CPU, &["/proc/meminfo"]);
    let error = run_fixture(&check, CASE).await.expect_err("not answered");

    assert!(
        matches!(&error, FixtureError::DoesNotAnswer { check, fixture }
            if check == "host.cpu" && fixture == CASE),
        "{error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("host.cpu"), "{text}");
    assert!(text.contains(CASE), "{text}");
    assert!(
        !check.ran.load(Ordering::SeqCst),
        "the check must not run against a fixture that does not answer it"
    );
}

#[tokio::test]
async fn a_missing_fixture_is_a_read_error_naming_it() {
    let check = Reader::new(&MEMORY, &[]);
    let error = run_fixture(&check, "checks/host.memory/nope")
        .await
        .expect_err("no such fixture");
    assert!(
        error.to_string().contains("checks/host.memory/nope"),
        "{error}"
    );
}

#[tokio::test]
async fn a_hard_need_the_fixture_lacks_gives_missing_need_and_the_check_does_not_run() {
    // The fixture is not root (`[caps] root = false`).
    let check = Reader::new(&MEMORY_NEEDS_ROOT, &["/proc/meminfo"]);
    let run = run_fixture(&check, CASE).await.expect("the fixture loads");
    assert_eq!(run.error(), &CheckError::MissingNeed(Need::Root));
    assert!(!check.ran.load(Ordering::SeqCst));
    assert!(run.log().actions.is_empty());
}

#[tokio::test]
#[should_panic(expected = "went beyond its declared manifest")]
async fn assert_within_manifest_fails_on_a_check_that_reads_an_undeclared_path() {
    // The check swallows the refusal and passes, so only the log shows what it tried.
    let check = Reader::new(&MEMORY, &["/proc/meminfo", "/etc/hostname"]);
    let run = run_fixture(&check, CASE).await.expect("the fixture loads");
    assert!(run.outcome().is_ok(), "the check hid the refusal");
    run.assert_within_manifest();
}

#[tokio::test]
async fn the_violation_names_the_entry_the_path_and_the_rule() {
    let check = Reader::new(&MEMORY, &["/proc/meminfo", "/etc/hostname"]);
    let run = run_fixture(&check, CASE).await.expect("the fixture loads");
    let violations = manifest_violations(run.info(), run.log());
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0].contains("read /etc/hostname"),
        "{violations:?}"
    );
    assert!(violations[0].contains("declared reads"), "{violations:?}");
}

#[tokio::test]
async fn a_refusal_by_the_deny_list_is_not_a_manifest_violation() {
    // `/etc/shadow` is refused by the read policy, not by the manifest. The check declared a prefix
    // that covers it, which is its own bug and not this assertion's business.
    static WIDE: CheckInfo = CheckInfo {
        reads: &["/etc", "/proc/meminfo"],
        ..info("host.memory", &[])
    };
    let check = Reader::new(&WIDE, &["/etc/shadow"]);
    let run = run_fixture(&check, CASE).await.expect("the fixture loads");
    assert!(
        run.log()
            .actions
            .iter()
            .any(|a| a.outcome == ActionOutcome::Denied),
        "{:?}",
        run.log()
    );
    run.assert_within_manifest();
}

#[tokio::test]
#[should_panic(expected = "etc/shadow")]
async fn assert_within_manifest_fails_on_a_deny_listed_path_the_check_did_not_declare() {
    // The deny list refuses `/etc/shadow` before the manifest is looked at, so the log holds the
    // deny-list rule. The check declares only `/proc/meminfo`, so this is still a violation.
    let check = Reader::new(&MEMORY, &["/proc/meminfo", "/etc/shadow"]);
    let run = run_fixture(&check, CASE).await.expect("the fixture loads");
    assert!(run.outcome().is_ok(), "the check hid the refusal");
    run.assert_within_manifest();
}

#[tokio::test]
async fn paths_that_the_earlier_read_rules_refuse_are_violations_when_not_declared() {
    let check = Reader::new(
        &MEMORY,
        &[
            "/proc/meminfo",
            "/etc/shadow",
            "/dev/null",
            "proc/meminfo",
            "/proc/../etc/hostname",
        ],
    );
    let run = run_fixture(&check, CASE).await.expect("the fixture loads");
    let violations = manifest_violations(run.info(), run.log());
    assert_eq!(violations.len(), 4, "{violations:?}");
    for path in [
        "/etc/shadow",
        "/dev/null",
        "proc/meminfo",
        "/proc/../etc/hostname",
    ] {
        assert!(
            violations
                .iter()
                .any(|v| v.contains(&format!("read {path})"))),
            "{path} in {violations:?}"
        );
    }
}

#[test]
fn the_fd_walk_declaration_covers_a_listing_and_link_reads_of_an_fd_directory_only() {
    use super::fixture_run::undeclared_file;
    use crate::check::FD_WALK;
    static WALKER: CheckInfo = CheckInfo {
        reads: &["/proc/self/ns/net", FD_WALK],
        ..info("host.ports", &[])
    };
    static PROC_ONLY: CheckInfo = CheckInfo {
        reads: &["/proc"],
        ..info("host.ports", &[])
    };
    let action = |kind: ActionKind, path: &str| {
        let mut action = Action::new(
            1,
            Some("host.ports".to_owned()),
            0,
            0,
            kind,
            ActionOutcome::Denied,
        );
        action.fields.insert("path".to_owned(), path.into());
        action
    };
    let link = action(ActionKind::ReadLink, "/proc/1234/fd/7");
    let dir = action(ActionKind::ReadDir, "/proc/1234/fd");
    assert!(!undeclared_file(&WALKER, &link));
    assert!(!undeclared_file(&WALKER, &dir));
    assert!(!undeclared_file(
        &WALKER,
        &action(ActionKind::ReadLink, "/proc/self/fd/0")
    ));
    // The declaration is no prefix of `/proc`, and no read or `stat` of an fd is declared by it.
    assert!(undeclared_file(
        &WALKER,
        &action(ActionKind::Read, "/proc/1234/fd/7")
    ));
    assert!(undeclared_file(
        &WALKER,
        &action(ActionKind::Stat, "/proc/1234/fd")
    ));
    assert!(undeclared_file(
        &WALKER,
        &action(ActionKind::ReadLink, "/proc/1234/comm")
    ));
    assert!(undeclared_file(
        &WALKER,
        &action(ActionKind::ReadLink, "/proc/1234/fd/7/x")
    ));
    assert!(undeclared_file(
        &WALKER,
        &action(ActionKind::ReadLink, "/host/proc/1234/fd/7")
    ));
    assert!(!undeclared_file(
        &WALKER,
        &action(ActionKind::ReadLink, "/proc/self/ns/net")
    ));
    // Without the declaration a link read is covered by a prefix like any other call.
    assert!(!undeclared_file(&PROC_ONLY, &link));
    assert!(undeclared_file(&MEMORY, &link));

    // The path shape goes with the call: a listing is of the directory, a link read is of a link in it.
    for path in ["/proc/1234/fd/7", "/proc/self/fd/0"] {
        assert!(
            undeclared_file(&WALKER, &action(ActionKind::ReadDir, path)),
            "read_dir {path}"
        );
    }
    for path in ["/proc/1234/fd", "/proc/self/fd"] {
        assert!(
            undeclared_file(&WALKER, &action(ActionKind::ReadLink, path)),
            "read_link {path}"
        );
    }
    // The declaration text is no prefix: it covers no read of a literal `/proc/<pid>/fd/x`.
    for kind in [ActionKind::Read, ActionKind::Stat, ActionKind::ReadLink] {
        assert!(
            undeclared_file(&WALKER, &action(kind.clone(), "/proc/<pid>/fd/x")),
            "{kind:?}"
        );
    }
    assert!(undeclared_file(
        &WALKER,
        &action(ActionKind::ReadDir, "/proc/<pid>/fd")
    ));
}

#[test]
fn the_prefix_matcher_reads_linux_paths_as_text_on_every_host() {
    use super::fixture_run::covers;
    // Covered: the prefix itself, a child, repeated and dotted separators, a trailing slash.
    for (prefix, path) in [
        ("/etc", "/etc/hostname"),
        ("/proc/meminfo", "/proc/meminfo"),
        ("/proc", "/proc//meminfo"),
        ("/proc", "/proc/./meminfo"),
        ("/proc/net", "/proc/net/"),
        ("/", "/etc/shadow"),
    ] {
        assert!(covers(prefix, path), "{prefix} should cover {path}");
    }
    // Not covered: another name, a partial component, `..`, a relative path, a home shorthand, a
    // Windows-style path, a path shorter than the prefix.
    for (prefix, path) in [
        ("/etc", "/etcetera"),
        ("/etc", "/proc/meminfo"),
        ("/etc", "/etc/../etc/shadow"),
        ("/etc", "etc/hostname"),
        ("/etc", "~/etc"),
        ("/etc", "C:\\etc\\hostname"),
        ("/etc", "\\etc\\hostname"),
        ("/proc/meminfo", "/proc"),
        ("etc", "/etc/hostname"),
        ("/etc/..", "/etc/hostname"),
    ] {
        assert!(!covers(prefix, path), "{prefix} should not cover {path}");
    }
}

// ---- normalize -----------------------------------------------------------------------------------

fn base_report(jobs: u32, version: &str, checks: Vec<CheckResult>) -> Report {
    let mut producer = Producer::new(version, version, "x86_64-unknown-linux-musl");
    producer.commit = Some("abc1234".to_owned());
    Report::new(
        producer,
        Run::new(
            "00000000-0000-4000-8000-000000000001",
            "2026-11-02T09:00:00.000Z",
            "2026-11-02T09:00:01.000Z",
            u64::from(jobs) * 111,
            RunOptions::new(jobs, 300_000),
        ),
        SpecRef::new("acme", "00", "spec.yaml", 1),
        Signature::unsigned(),
        Host::new("host-a.example", HostOs::new(HostOsFamily::Linux), "x86_64"),
        Identity::new(Some(1000), None, false),
        checks,
    )
}

fn result(key: &str, started_ms: u64, duration_ms: u64) -> CheckResult {
    let mut result = CheckResult::new(key, "host", Severity::Block, Status::Pass);
    result.started_ms = started_ms;
    result.duration_ms = duration_ms;
    result
}

fn read(seq: u64, check: Option<&str>, at_ms: u64, path: &str) -> Action {
    let mut action = Action::new(
        seq,
        check.map(str::to_owned),
        at_ms,
        at_ms / 2,
        ActionKind::Read,
        ActionOutcome::Ok,
    );
    action.fields.insert("path".to_owned(), path.into());
    action
}

#[test]
fn normalize_scrubs_timing_and_build_fields_and_nothing_else() {
    let mut report = base_report(8, "1.2.3", vec![result("host.memory", 40, 9)]);
    let mut timeout = result("host.cpu", 5, 10_000);
    timeout.status = Status::Timeout;
    timeout.timeout_after_ms = Some(10_000);
    report.checks.push(timeout);
    report.actions = vec![read(1, Some("host.memory"), 41, "/proc/meminfo")];
    let before = report.clone();

    normalize(&mut report);

    assert_eq!(report.producer.version, "<version>");
    assert_eq!(report.producer.commit.as_deref(), Some("<commit>"));
    assert_eq!(report.producer.target, "<target>");
    assert_eq!(report.producer.rdy_spec, "<rdy_spec>");
    assert_eq!(report.run.duration_ms, 0);
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.started_ms == 0 && c.duration_ms == 0)
    );
    assert_eq!(
        report.checks[1].timeout_after_ms,
        Some(10_000),
        "the configured limit stays"
    );
    assert_eq!(
        (report.actions[0].at_ms, report.actions[0].duration_ms),
        (0, 0)
    );
    // The pinned fields are untouched.
    assert_eq!(report.run.id, before.run.id);
    assert_eq!(report.run.started_at, before.run.started_at);
    assert_eq!(report.run.finished_at, before.run.finished_at);
    assert_eq!(report.run.options, before.run.options);
    assert_eq!(report.host, before.host);
    assert_eq!(report.verdict, before.verdict);
    assert_eq!(report.summary, before.summary);
    assert_eq!(report.checks[1].message, before.checks[1].message);
    assert_eq!(report.actions[0].fields, before.actions[0].fields);
}

#[test]
fn normalize_is_idempotent() {
    let mut report = base_report(3, "9.9.9", vec![result("host.memory", 40, 9)]);
    report.actions = vec![
        read(2, Some("host.memory"), 41, "/proc/meminfo"),
        read(5, None, 3, "/proc/self/auxv"),
    ];
    normalize(&mut report);
    let once = report.clone();
    normalize(&mut report);
    assert_eq!(report, once);
}

#[test]
fn normalize_orders_the_action_log_by_check_position_then_write_order_and_renumbers() {
    let checks = vec![result("a", 0, 0), result("b", 0, 0)];
    let mut report = base_report(8, "1", checks);
    // As eight workers wrote them: run level first, then b and a interleaved by time.
    report.actions = vec![
        read(1, None, 1, "/run"),
        read(2, Some("b"), 5, "/b1"),
        read(3, Some("a"), 6, "/a1"),
        read(4, Some("b"), 7, "/b2"),
        read(5, Some("a"), 8, "/a2"),
        read(6, Some("gone"), 9, "/gone"),
    ];
    normalize(&mut report);
    let seen: Vec<(u64, &str)> = report
        .actions
        .iter()
        .map(|a| (a.seq, a.fields["path"].as_str().expect("path")))
        .collect();
    assert_eq!(
        seen,
        [
            (1, "/run"),
            (2, "/a1"),
            (3, "/a2"),
            (4, "/b1"),
            (5, "/b2"),
            (6, "/gone")
        ]
    );
}

#[cfg(feature = "runtime")]
mod fakes {
    use super::*;
    use crate::check::Os;

    #[tokio::test]
    #[should_panic(expected = "has already run once")]
    async fn a_block_fake_runs_once_and_a_second_run_panics_instead_of_returning() {
        let run = TestRun::new(Replay::new());
        let ctx = run.context("fake.plain", Os::Linux, []);
        let (check, release) = FakeCheck::block();
        release.release();
        check.run(&ctx).await.expect("the first run passes");
        drop(check.run(&ctx).await);
    }

    #[tokio::test]
    #[should_panic(expected = "needs a multi-thread runtime")]
    async fn a_spin_fake_on_the_current_thread_runtime_panics_instead_of_hanging() {
        let run = TestRun::new(Replay::new());
        let ctx = run.context("fake.plain", Os::Linux, []);
        let (check, release) = FakeCheck::spin();
        drop(check.run(&ctx).await);
        release.release();
    }
}

#[cfg(feature = "runtime")]
mod across_jobs {
    use std::time::Duration;

    use super::*;
    use rdy_spec::spec::CheckSpec;

    use crate::outcome::{map_outcome, timeout_result};
    use crate::sched::{End, Planned, Ran, Scheduler};

    /// Runs the same four fakes at `jobs` on paused time and builds the report a run would write.
    /// Each check wrote two log entries, and the log is in the order the workers got there.
    async fn run_at(jobs: usize) -> Report {
        let keys = ["host.a", "host.b", "host.c", "host.d"];
        let planned = vec![
            Planned::new(Arc::new(FakeCheck::sleep(Duration::from_secs(3))), keys[0]),
            Planned::new(Arc::new(FakeCheck::sleep(Duration::from_secs(1))), keys[1]),
            Planned::new(
                Arc::new(FakeCheck::outcome(Ok(Finding::warn("close")))),
                keys[2],
            ),
            Planned::new(Arc::new(FakeCheck::forever()), keys[3])
                .with_timeout(Duration::from_secs(5)),
        ];
        let ran = Scheduler::new(jobs, crate::check::Os::Linux, [])
            .run(planned)
            .await;
        let checks: Vec<CheckResult> = ran.iter().map(to_result).collect();

        // A worker writes its two entries when it starts and when it ends, so the interleaving
        // follows the clock. Sorting by the time they happened gives the order a run would log.
        let mut entries: Vec<(Duration, usize, u64)> = Vec::new();
        for (index, one) in ran.iter().enumerate() {
            entries.push((one.started, index, 1));
            entries.push((one.started + one.elapsed, index, 2));
        }
        entries.sort();
        let mut report = base_report(u32::try_from(jobs).expect("small"), "1.0.0", checks);
        report.actions = entries
            .iter()
            .zip(1_u64..)
            .map(|((at, index, step), seq)| {
                read(
                    seq,
                    Some(keys[*index]),
                    u64::try_from(at.as_millis()).expect("small"),
                    &format!("/{}/{step}", keys[*index]),
                )
            })
            .collect();
        report
    }

    /// The result the report writer would make: `map_outcome` gives each check its own status and
    /// message, so the reports at one job and eight differ by check and not only by timing.
    fn to_result(one: &Ran) -> CheckResult {
        let started_ms = u64::try_from(one.started.as_millis()).expect("small");
        let duration_ms = u64::try_from(one.elapsed.as_millis()).expect("small");
        match &one.end {
            End::Done(outcome) => {
                let ctx = CheckContext::new(&one.key, crate::check::Os::Linux, []);
                map_outcome(
                    &FAKE_INFO,
                    &CheckSpec::new("fake.plain"),
                    &ctx,
                    (**outcome).clone(),
                    started_ms,
                    duration_ms,
                )
            }
            End::TimedOut { after } => {
                let template = result(&one.key, 0, 0);
                timeout_result(&template, *after, one.started)
            }
            other => panic!("unexpected end {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn normalized_reports_are_equal_at_one_job_and_eight() {
        let mut one = run_at(1).await;
        let mut eight = run_at(8).await;

        // The checks differ from each other: a pass, a pass, a warn and a timeout.
        let statuses: Vec<Status> = one.checks.iter().map(|c| c.status.clone()).collect();
        assert_eq!(
            statuses,
            [Status::Pass, Status::Pass, Status::Warn, Status::Timeout]
        );
        assert_ne!(one.checks[0].message, one.checks[1].message);

        // The reports differ for real: timing, job count and the order of the log.
        assert_ne!(one, eight);
        assert_ne!(one.checks[1].started_ms, eight.checks[1].started_ms);
        assert_ne!(
            one.actions
                .iter()
                .map(|a| a.check.clone())
                .collect::<Vec<_>>(),
            eight
                .actions
                .iter()
                .map(|a| a.check.clone())
                .collect::<Vec<_>>()
        );

        normalize_across_jobs(&mut one);
        normalize_across_jobs(&mut eight);
        assert_eq!(one, eight);
        assert_eq!(
            serde_json::to_string(&one).expect("serializes"),
            serde_json::to_string(&eight).expect("serializes")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn plain_normalize_keeps_the_job_count_for_a_golden() {
        let mut one = run_at(1).await;
        let mut eight = run_at(8).await;
        normalize(&mut one);
        normalize(&mut eight);
        assert_eq!(one.run.options.jobs, 1);
        assert_eq!(eight.run.options.jobs, 8);
        assert_ne!(one, eight);
    }

    #[tokio::test(start_paused = true)]
    async fn a_real_difference_survives_normalize() {
        let mut one = run_at(8).await;
        let mut other = run_at(8).await;
        other.checks[0].message = "different".to_owned();
        normalize_across_jobs(&mut one);
        normalize_across_jobs(&mut other);
        assert_ne!(one, other);
    }
}
