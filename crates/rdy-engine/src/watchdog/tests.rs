//! Tests for the watchdog with a clock that moves by hand and effects that record, so nothing waits
//! for real time and no test ends the test process. The real thing, with a real hang, is
//! `tests/watchdog_hang.rs`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rdy_spec::result::{
    Bucket, CheckResult, Host, HostOs, HostOsFamily, Identity, Producer, Report, Run, RunOptions,
    Severity, Signature, SkipKind, SpecRef, Status, Verdict,
};

use super::*;
use crate::redact::TagKey;
use crate::sched::{End, Observer, Ran};

const DEADLINE: Duration = Duration::from_secs(300);
/// In the message of a result the board redacted as it completed.
const CANARY: &str = "canary-hunter2-value";
/// In the base report and the templates, which nothing redacted before the watchdog did.
const HOST_CANARY: &str = "canary-host-pw-1";
const USER_CANARY: &str = "canary-user-tok-2";
const NAME_CANARY: &str = "canary-name-pw-3";

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([5; 32]))
}

fn base_report() -> Report {
    Report::new(
        Producer::new("0.1.0", "0.1.0", "x86_64-unknown-linux-musl"),
        Run::new(
            "00000000-0000-4000-8000-000000000000",
            "2027-02-08T10:00:00.000Z",
            "2027-02-08T10:05:00.000Z",
            300_000,
            RunOptions::new(4, 300_000),
        ),
        SpecRef::new("acme", "0".repeat(64), "spec.yaml", 10),
        Signature::unsigned(),
        Host::new(
            format!("build-01 password={HOST_CANARY}"),
            HostOs::new(HostOsFamily::Linux),
            "x86_64",
        ),
        Identity::new(Some(1000), Some(format!("ada token={USER_CANARY}")), false),
        Vec::new(),
    )
}

fn template(id: &str) -> CheckResult {
    let mut result = CheckResult::new(id, "host", Severity::Block, Status::Pass);
    result.name = Some(format!("primary password={NAME_CANARY}"));
    result
}

/// Passing results that the map hands out by index. The first carries a secret in its message.
fn passing(index: usize) -> CheckResult {
    let mut result = template(&format!("host.check{index}"));
    result.message = format!("token: {CANARY}");
    result
}

fn ran(index: usize) -> Ran {
    Ran {
        key: format!("host.check{index}"),
        id: "host.check",
        end: End::Cancelled,
        started: Duration::ZERO,
        elapsed: Duration::ZERO,
    }
}

/// Three checks: 0 finished, 1 running, 2 not started.
fn board_with_three() -> Arc<Board> {
    let templates = (0..3)
        .map(|n| template(&format!("host.check{n}")))
        .collect();
    let board = Arc::new(Board::new(
        base_report(),
        templates,
        redactor(),
        DEADLINE,
        Box::new(|index, _| passing(index)),
    ));
    board.started(0, Duration::ZERO, Duration::from_secs(10));
    board.finished(0, &ran(0));
    board.started(1, Duration::from_secs(1), Duration::from_secs(10));
    board
}

#[derive(Default)]
struct ManualClock {
    now: Mutex<Duration>,
}

impl ManualClock {
    fn set(&self, at: Duration) {
        *self.now.lock().unwrap() = at;
    }
}

impl Clock for ManualClock {
    fn wait_until(&self, at: Duration, stop: &Stop) -> bool {
        loop {
            if *self.now.lock().unwrap() >= at {
                return true;
            }
            if stop.wait(Duration::from_millis(1)) {
                return false;
            }
        }
    }
}

#[derive(Default)]
struct Recorder {
    kills: AtomicUsize,
    notices: AtomicUsize,
    exits: Mutex<Vec<i32>>,
}

impl Effects for Recorder {
    fn kill_groups(&self) {
        self.kills.fetch_add(1, Ordering::SeqCst);
    }

    fn notice(&self) {
        self.notices.fetch_add(1, Ordering::SeqCst);
    }

    fn exit(&self, code: i32) {
        self.exits.lock().unwrap().push(code);
    }
}

impl Recorder {
    fn exits(&self) -> Vec<i32> {
        self.exits.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct Collect {
    reports: Mutex<Vec<Report>>,
}

impl ReportSink for Collect {
    fn write(&self, report: &RedactedReport) -> Result<(), ReportError> {
        self.reports.lock().unwrap().push((**report).clone());
        Ok(())
    }
}

struct Rig {
    clock: Arc<ManualClock>,
    effects: Arc<Recorder>,
    state: Arc<WriteState>,
    watchdog: Watchdog,
}

fn fast() -> Timing {
    Timing {
        grace: Duration::from_secs(10),
        snapshot_bound: Duration::from_millis(30),
        loser_wait: Duration::from_millis(100),
        write_bound: Duration::from_millis(100),
    }
}

fn rig(timing: Timing) -> Rig {
    rig_at(Instant::now(), DEADLINE, timing)
}

fn rig_at(origin: Instant, deadline: Duration, timing: Timing) -> Rig {
    let clock = Arc::new(ManualClock::default());
    let effects = Arc::new(Recorder::default());
    let state = Arc::new(WriteState::new());
    let config = WatchdogConfig::new(origin, deadline, Arc::clone(&state), redactor())
        .with_timing(timing)
        .with_clock(clock.clone())
        .with_effects(effects.clone());
    Rig {
        clock,
        effects,
        state,
        watchdog: Watchdog::start(config).unwrap(),
    }
}

fn status_of(report: &Report, index: usize) -> &Status {
    &report.checks[index].status
}

#[test]
fn at_the_fire_time_it_writes_an_incomplete_report_and_exits_70() {
    let rig = rig(fast());
    let sink = Arc::new(Collect::default());
    assert!(rig.watchdog.arm(board_with_three(), sink.clone()));

    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();

    let reports = sink.reports.lock().unwrap();
    assert_eq!(reports.len(), 1);
    let report = &reports[0];
    assert!(!report.complete);
    assert_eq!(*status_of(report, 0), Status::Pass);
    assert_eq!(*status_of(report, 1), Status::Timeout);
    assert_eq!(*status_of(report, 2), Status::Skipped);
    assert_eq!(report.checks[2].skip_kind, Some(SkipKind::RunDeadline));
    assert_eq!(report.checks[1].bucket, Bucket::RequiredNotRun);
    assert_eq!(report.verdict, Verdict::NotReady);
    assert_eq!(rig.effects.exits(), [70]);
    assert_eq!(rig.effects.kills.load(Ordering::SeqCst), 1);
    assert_eq!(rig.effects.notices.load(Ordering::SeqCst), 1);
}

#[test]
fn the_watchdog_redacts_the_whole_report_itself_and_keeps_the_counts_of_earlier_results() {
    let rig = rig(fast());
    let sink = Arc::new(Collect::default());
    let board = board_with_three();
    // The control: before the watchdog's pass the canaries are there, so a no-op redaction would fail.
    let (plain, _) = board.partial_report(Duration::from_millis(30));
    let plain = serde_json::to_string(&plain).unwrap();
    for canary in [HOST_CANARY, USER_CANARY, NAME_CANARY] {
        assert!(
            plain.contains(canary),
            "{canary} must be in the raw snapshot"
        );
    }
    rig.watchdog.arm(board, sink.clone());

    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();

    let reports = sink.reports.lock().unwrap();
    let text = serde_json::to_string(&reports[0]).unwrap();
    for canary in [CANARY, HOST_CANARY, USER_CANARY, NAME_CANARY] {
        assert!(!text.contains(canary), "{canary} survived: {text}");
    }
    // Host, user, three names (one in each kind of result) and the message of result 0.
    assert!(
        reports[0].redaction.total >= 5,
        "{:?}",
        reports[0].redaction
    );
}

#[test]
fn a_finish_at_nine_point_nine_seconds_after_the_deadline_keeps_the_complete_report() {
    let rig = rig(fast());
    let sink = Arc::new(Collect::default());
    rig.watchdog.arm(board_with_three(), sink.clone());

    // 9.9 s after the deadline: the watchdog has not fired. The normal path takes the write state.
    rig.clock.set(DEADLINE + Duration::from_millis(9_900));
    thread::sleep(Duration::from_millis(30));
    assert!(rig.state.claim(), "the CLI must win the race");
    rig.state.finish(1);

    // Then the fire time passes. The watchdog does not write. The process is leaving on its own in
    // the real thing, so only the backstop remains: after `loser_wait` it exits with the stored code.
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();

    assert!(sink.reports.lock().unwrap().is_empty());
    assert_eq!(rig.effects.exits(), [1]);
    assert_eq!(rig.effects.notices.load(Ordering::SeqCst), 0);
}

#[test]
fn a_stuck_exit_after_done_is_ended_with_the_stored_code_after_loser_wait() {
    let rig = rig(fast());
    let sink = Arc::new(Collect::default());
    rig.watchdog.arm(board_with_three(), sink.clone());
    assert!(rig.state.claim());
    rig.state.finish(2);

    let started = Instant::now();
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();

    assert!(started.elapsed() >= fast().loser_wait);
    assert_eq!(rig.effects.exits(), [2]);
    assert_eq!(rig.effects.kills.load(Ordering::SeqCst), 1);
    assert!(sink.reports.lock().unwrap().is_empty());
}

#[test]
fn a_process_that_leaves_by_itself_after_done_is_not_exited_by_the_watchdog() {
    // In a real run `process::exit` ends the thread. Here `stop` stands in for that.
    let rig = rig(Timing {
        loser_wait: Duration::from_secs(30),
        ..fast()
    });
    assert!(rig.state.claim());
    rig.state.finish(0);
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    thread::sleep(Duration::from_millis(30));
    rig.watchdog.stop();
    assert!(rig.effects.exits().is_empty());
}

#[test]
fn the_real_clock_counts_from_the_origin_it_is_given() {
    // An origin 12 s in the past: 12 s have already gone, so waiting for 12 s plus 50 ms takes about 50 ms.
    let origin = Instant::now()
        .checked_sub(Duration::from_secs(12))
        .expect("an instant 12 s back");
    let clock = SystemClock::new(origin);
    let stop = Stop::default();

    let started = Instant::now();
    assert!(clock.wait_until(Duration::from_secs(12) + Duration::from_millis(50), &stop));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(30) && took < Duration::from_secs(2),
        "{took:?}"
    );

    // A time already past returns at once.
    let started = Instant::now();
    assert!(clock.wait_until(Duration::from_secs(5), &stop));
    assert!(started.elapsed() < Duration::from_millis(500));

    // A time far ahead returns false when stopped.
    let stop = Arc::new(Stop::default());
    let stopper = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        stopper.stop();
    });
    assert!(!clock.wait_until(Duration::from_secs(20), &stop));
    handle.join().unwrap();
}

#[test]
fn the_scheduler_and_the_watchdog_share_one_origin() {
    use crate::check::{BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Os};
    use crate::check::{OsSupport, Support};
    use crate::sched::{Planned, Scheduler};

    static INFO: CheckInfo = CheckInfo {
        id: "fake.forever",
        family: "fake",
        summary: "A fake check that never ends.",
        meta: CheckMeta {
            title: "Fake check",
            remediation: "Nothing to fix. This check is a test double.",
        },
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: OsSupport {
            linux: Support::Full,
            macos: Support::Full,
            windows: Support::Full,
        },
        reads: &[],
        statfs: &[],
        env: &[],
        commands: &[],
        peers: &[],
    };
    struct Forever;
    impl Check for Forever {
        fn info(&self) -> &'static CheckInfo {
            &INFO
        }
        fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
            Box::pin(std::future::pending())
        }
    }

    // The runtime is built paused by hand, so the scheduler's clock is virtual while the origin is a
    // real instant that is already 12 s old, as when set-up (a cluster probe) took 12 s.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let deadline = Duration::from_secs(30);
    let origin = Instant::now()
        .checked_sub(Duration::from_secs(12))
        .expect("an instant 12 s back");
    let ran = runtime.block_on(async {
        Scheduler::new(1, Os::Linux, [])
            .with_deadline(deadline)
            .with_origin(origin)
            .run(vec![
                Planned::new(Arc::new(Forever), "fake.forever")
                    .with_timeout(Duration::from_secs(60)),
            ])
            .await
    });
    // The check was cut at origin plus 30 s, which is 18 s into the run, not 30 s.
    let End::TimedOut { after } = ran[0].end else {
        panic!("want a timeout, got {:?}", ran[0].end);
    };
    // The paused clock and the real origin differ by the real time the test took, so allow a little.
    let slack = Duration::from_millis(500);
    assert!(after.abs_diff(Duration::from_secs(18)) < slack, "{after:?}");

    // The watchdog counts from the same origin: it fires 10 s after the same deadline, not before.
    let rig = rig_at(origin, deadline, fast());
    rig.clock
        .set(deadline + Timing::DEFAULT.grace - Duration::from_millis(1));
    thread::sleep(Duration::from_millis(30));
    assert!(rig.effects.exits().is_empty());
    rig.clock.set(deadline + Timing::DEFAULT.grace);
    rig.watchdog.join();
    assert_eq!(rig.effects.exits(), [70]);
}

#[test]
fn nothing_happens_before_the_fire_time() {
    let rig = rig(fast());
    let sink = Arc::new(Collect::default());
    rig.watchdog.arm(board_with_three(), sink.clone());

    rig.clock.set(DEADLINE + Duration::from_millis(9_999));
    thread::sleep(Duration::from_millis(50));
    assert!(sink.reports.lock().unwrap().is_empty());
    assert!(rig.effects.exits().is_empty());
    assert_eq!(rig.state.phase(), Phase::Running);

    rig.watchdog.stop();
    assert!(rig.effects.exits().is_empty());
}

#[test]
fn a_normal_path_that_is_writing_and_never_finishes_ends_in_exit_70_with_no_report() {
    let rig = rig(fast());
    let sink = Arc::new(Collect::default());
    rig.watchdog.arm(board_with_three(), sink.clone());
    assert!(rig.state.claim());

    let started = Instant::now();
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();

    assert!(started.elapsed() >= fast().loser_wait);
    assert!(
        sink.reports.lock().unwrap().is_empty(),
        "the loser never writes"
    );
    assert_eq!(rig.effects.exits(), [70]);
    assert_eq!(rig.effects.kills.load(Ordering::SeqCst), 1);
}

#[test]
fn a_normal_path_that_finishes_while_the_watchdog_waits_is_not_overwritten() {
    let rig = rig(Timing {
        loser_wait: Duration::from_millis(300),
        ..fast()
    });
    let sink = Arc::new(Collect::default());
    rig.watchdog.arm(board_with_three(), sink.clone());
    assert!(rig.state.claim());
    let state = Arc::clone(&rig.state);
    let finisher = thread::spawn(move || {
        thread::sleep(Duration::from_millis(40));
        state.finish(0);
    });

    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();
    finisher.join().unwrap();

    assert!(sink.reports.lock().unwrap().is_empty());
    // Only the backstop acts, with the stored code. No report is written over the CLI's.
    assert_eq!(rig.effects.exits(), [0]);
}

#[test]
fn before_the_watchdog_is_armed_it_kills_and_exits_70_with_no_report() {
    let rig = rig(fast());
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();
    assert_eq!(rig.effects.exits(), [70]);
    assert_eq!(rig.effects.kills.load(Ordering::SeqCst), 1);
}

#[test]
fn a_held_snapshot_lock_still_gives_a_report_with_every_check_unfinished() {
    let rig = rig(fast());
    let sink = Arc::new(Collect::default());
    let board = board_with_three();
    rig.watchdog.arm(Arc::clone(&board), sink.clone());

    let hold = board.hold_lock_for_test();
    let started = Instant::now();
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();
    drop(hold);

    assert!(started.elapsed() >= fast().snapshot_bound);
    let reports = sink.reports.lock().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(!reports[0].complete);
    assert!(
        reports[0]
            .checks
            .iter()
            .all(|check| check.status == Status::Error)
    );
    assert_eq!(reports[0].verdict, Verdict::NotReady);
    assert_eq!(rig.effects.exits(), [70]);
}

#[test]
fn a_poisoned_lock_is_still_read() {
    let board = board_with_three();
    let poisoner = Arc::clone(&board);
    let _ = thread::spawn(move || {
        let _hold = poisoner.hold_lock_for_test();
        panic!("poison the board");
    })
    .join();
    let snapshot = board.snapshot(Duration::from_millis(50));
    assert!(snapshot.locked);
    assert_eq!(snapshot.results[0].status, Status::Pass);
}

#[test]
fn a_panic_in_the_sink_still_exits_70() {
    struct Panics;
    impl ReportSink for Panics {
        fn write(&self, _report: &RedactedReport) -> Result<(), ReportError> {
            panic!("sink bug");
        }
    }
    let rig = rig(fast());
    rig.watchdog.arm(board_with_three(), Arc::new(Panics));
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();
    assert_eq!(rig.effects.exits(), [70]);
    assert_eq!(rig.effects.kills.load(Ordering::SeqCst), 1);
}

#[test]
fn a_sink_that_never_returns_cannot_stop_the_exit() {
    struct Blocks(Mutex<mpsc::Receiver<()>>);
    impl ReportSink for Blocks {
        fn write(&self, _report: &RedactedReport) -> Result<(), ReportError> {
            let _ = self.0.lock().unwrap().recv();
            Ok(())
        }
    }
    let (release, wait) = mpsc::channel();
    let rig = rig(fast());
    rig.watchdog
        .arm(board_with_three(), Arc::new(Blocks(Mutex::new(wait))));

    let started = Instant::now();
    rig.clock.set(DEADLINE + Duration::from_secs(10));
    rig.watchdog.join();

    assert!(started.elapsed() >= fast().write_bound);
    assert_eq!(rig.effects.exits(), [70]);
    drop(release);
}

#[test]
fn only_one_side_can_claim_the_write() {
    let state = Arc::new(WriteState::new());
    let wins = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let state = Arc::clone(&state);
            let wins = Arc::clone(&wins);
            thread::spawn(move || {
                if state.claim() {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(wins.load(Ordering::SeqCst), 1);
    assert_eq!(state.phase(), Phase::Writing);
    state.finish(0);
    assert_eq!(state.phase(), Phase::Done);
    assert!(!state.claim());
}

#[test]
fn a_losing_claim_or_park_never_returns() {
    let state = Arc::new(WriteState::new());
    assert!(state.claim());
    let returned = Arc::new(AtomicBool::new(false));
    let (s, r) = (Arc::clone(&state), Arc::clone(&returned));
    // The thread parks for good, so it is left behind on purpose.
    let _parked = thread::spawn(move || {
        s.claim_or_park();
        r.store(true, Ordering::SeqCst);
    });
    thread::sleep(Duration::from_millis(50));
    assert!(!returned.load(Ordering::SeqCst));
}
