//! Scheduler tests, with fake checks.
//!
//! Most tests run under paused time, so a 10 s timeout costs no wall-clock time. The Spin test needs a
//! real two-worker runtime because a spinning check holds a worker.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rdy_spec::result::SkipKind;
use serde_json::json;

use super::*;
use crate::check::{BoxFuture, CheckInfo, CheckMeta, Finding, Level, OsSupport, Support};

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

static PLAIN: CheckInfo = CheckInfo {
    id: "fake.plain",
    family: "fake",
    summary: "A fake check with no needs.",
    meta: CheckMeta {
        title: "Fake check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: FULL,
    reads: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

static QUICK: CheckInfo = CheckInfo {
    id: "fake.quick",
    family: "fake",
    summary: "A fake check with a 2 s default timeout.",
    meta: CheckMeta {
        title: "Fake check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(2)),
    os: FULL,
    reads: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

static NEEDS_ROOT: CheckInfo = CheckInfo {
    id: "fake.needs_root",
    family: "fake",
    summary: "A fake check that needs root.",
    meta: CheckMeta {
        title: "Fake check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[Need::Root],
    wants: &[],
    default_timeout: None,
    os: FULL,
    reads: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// What a fake check does when it runs.
enum Mode {
    /// Passes at once.
    Pass,
    /// Waits for this long, then passes.
    Sleep(Duration),
    /// Waits forever.
    Forever,
    /// Panics with this text.
    Panic(&'static str),
    /// Holds its thread until the flag is set, without ever yielding.
    Spin(Arc<AtomicBool>),
    /// Counts how many are in flight, waits 10 ms, then passes.
    Track(Arc<Gauge>),
    /// Passes and counts the run.
    Count(Arc<AtomicUsize>),
    /// Saves `remaining()` at the start and after a 3 s wait, then passes.
    Remaining(Arc<Mutex<Vec<Duration>>>),
    /// Sets the flag when the future is dropped.
    DropFlag(Arc<AtomicBool>),
    /// Saves its probe where the test can reach it after the run, then waits forever.
    KeepProbe(Arc<Mutex<Option<crate::probe::Probe>>>),
}

#[derive(Default)]
struct Gauge {
    now: AtomicUsize,
    max: AtomicUsize,
}

struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct Fake {
    info: &'static CheckInfo,
    mode: Mode,
}

impl Check for Fake {
    fn info(&self) -> &'static CheckInfo {
        self.info
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            match &self.mode {
                Mode::Pass => {}
                Mode::Sleep(wait) => tokio::time::sleep(*wait).await,
                Mode::Forever => std::future::pending::<()>().await,
                Mode::Panic(text) => panic!("{text}"),
                Mode::Spin(release) => {
                    while !release.load(Ordering::SeqCst) {
                        std::hint::spin_loop();
                    }
                }
                Mode::Track(gauge) => {
                    let now = gauge.now.fetch_add(1, Ordering::SeqCst) + 1;
                    gauge.max.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    gauge.now.fetch_sub(1, Ordering::SeqCst);
                }
                Mode::Count(runs) => {
                    runs.fetch_add(1, Ordering::SeqCst);
                }
                Mode::Remaining(seen) => {
                    seen.lock().expect("lock").push(ctx.remaining());
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    seen.lock().expect("lock").push(ctx.remaining());
                }
                Mode::DropFlag(dropped) => {
                    let _flag = SetOnDrop(Arc::clone(dropped));
                    std::future::pending::<()>().await;
                }
                Mode::KeepProbe(slot) => {
                    *slot.lock().expect("lock") = Some(ctx.probe().clone());
                    std::future::pending::<()>().await;
                }
            }
            Ok(Finding::pass(format!("{} ran", ctx.key())).with_observed(json!({ "ok": true })))
        })
    }
}

fn fake(info: &'static CheckInfo, mode: Mode) -> Arc<dyn Check> {
    Arc::new(Fake { info, mode })
}

fn planned(key: &str, mode: Mode) -> Planned {
    Planned::new(fake(&PLAIN, mode), key)
}

fn scheduler(jobs: usize) -> Scheduler {
    Scheduler::new(jobs, Os::Linux, [])
}

fn passed(ran: &Ran) -> bool {
    matches!(&ran.end, End::Done(done) if matches!(&**done, Ok(finding) if finding.level == Level::Pass))
}

#[test]
fn jobs_are_capped_at_32_and_never_zero() {
    assert_eq!(cap_jobs(500), 32);
    assert_eq!(cap_jobs(32), 32);
    assert_eq!(cap_jobs(8), 8);
    assert_eq!(cap_jobs(1), 1);
    assert_eq!(cap_jobs(0), 1);
    assert_eq!(scheduler(500).jobs(), MAX_JOBS);
    assert_eq!(DEFAULT_JOBS, 8);
}

#[test]
fn the_timeout_is_spec_then_check_default_then_ten_seconds_capped_at_sixty() {
    let secs = Duration::from_secs;
    assert_eq!(effective_timeout(None, None), secs(10));
    assert_eq!(effective_timeout(None, Some(secs(5))), secs(5));
    assert_eq!(effective_timeout(Some(secs(3)), Some(secs(5))), secs(3));
    // A spec value replaces the default, so it can also be higher than the default.
    assert_eq!(effective_timeout(Some(secs(30)), Some(secs(5))), secs(30));
    assert_eq!(effective_timeout(Some(secs(300)), None), secs(60));
    assert_eq!(effective_timeout(None, Some(secs(120))), secs(60));
}

#[tokio::test(start_paused = true)]
async fn a_check_that_sleeps_forever_reports_timeout_and_the_others_still_pass() {
    let ran = scheduler(8)
        .run(vec![
            planned("fake.plain/a", Mode::Pass),
            planned("fake.plain/stuck", Mode::Forever),
            planned("fake.plain/b", Mode::Pass),
        ])
        .await;
    assert!(passed(&ran[0]));
    assert_eq!(
        ran[1].end,
        End::TimedOut {
            after: Duration::from_secs(10)
        }
    );
    assert_eq!(ran[1].elapsed, Duration::from_secs(10));
    assert!(passed(&ran[2]));
}

#[tokio::test(start_paused = true)]
async fn the_check_default_timeout_applies_and_the_spec_timeout_replaces_it() {
    let default = Planned::new(fake(&QUICK, Mode::Forever), "fake.quick");
    let spec = Planned::new(fake(&QUICK, Mode::Forever), "fake.quick/spec")
        .with_timeout(Duration::from_secs(7));
    let ran = scheduler(8).run(vec![default, spec]).await;
    assert_eq!(
        ran[0].end,
        End::TimedOut {
            after: Duration::from_secs(2)
        }
    );
    assert_eq!(
        ran[1].end,
        End::TimedOut {
            after: Duration::from_secs(7)
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_spec_timeout_above_sixty_seconds_is_held_to_sixty() {
    let item = planned("fake.plain/long", Mode::Forever).with_timeout(Duration::from_secs(600));
    let ran = scheduler(8).run(vec![item]).await;
    assert_eq!(
        ran[0].end,
        End::TimedOut {
            after: Duration::from_secs(60)
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_check_that_finishes_before_its_timeout_is_not_a_timeout() {
    let item = planned("fake.plain/slow", Mode::Sleep(Duration::from_secs(9)));
    let ran = scheduler(8).run(vec![item]).await;
    assert!(passed(&ran[0]));
    assert_eq!(ran[0].elapsed, Duration::from_secs(9));
}

#[tokio::test]
async fn a_panicking_check_reports_the_panic_and_the_others_still_pass() {
    let ran = scheduler(8)
        .run(vec![
            planned("fake.plain/a", Mode::Pass),
            planned("fake.plain/bad", Mode::Panic("index out of range")),
            planned("fake.plain/b", Mode::Pass),
        ])
        .await;
    assert!(passed(&ran[0]));
    let End::Panicked { message } = &ran[1].end else {
        panic!("want a panic, got {:?}", ran[1].end);
    };
    assert_eq!(&**message.redacted(&redactor()), "index out of range");
    assert!(passed(&ran[2]));
}

fn redactor() -> Redactor {
    Redactor::new(crate::redact::TagKey::fixed([7; 32]))
}

#[tokio::test]
async fn panic_text_is_redacted_and_its_debug_output_is_hidden() {
    // The default panic hook still prints the raw text. The CLI replaces it (M1-056).
    let ran = scheduler(1)
        .run(vec![planned(
            "fake.plain/bad",
            Mode::Panic("bad config: password=canary-hunter2 end"),
        )])
        .await;
    let End::Panicked { message } = &ran[0].end else {
        panic!("want a panic, got {:?}", ran[0].end);
    };
    let shown = message.redacted(&redactor());
    assert!(!shown.contains("canary-hunter2"), "{}", *shown);
    assert!(shown.contains("[REDACTED:secret_by_key:"), "{}", *shown);
    assert!(!format!("{ran:?}").contains("canary-hunter2"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spinning_check_on_a_two_worker_runtime_does_not_stop_the_others() {
    let release = Arc::new(AtomicBool::new(false));
    let _release_on_exit = SetOnDrop(Arc::clone(&release));

    let spin = planned("fake.plain/spin", Mode::Spin(Arc::clone(&release)))
        .with_timeout(Duration::from_millis(300));
    let mut items = vec![spin];
    for n in 0..5 {
        items.push(planned(&format!("fake.plain/{n}"), Mode::Pass));
    }
    items.push(planned(
        "fake.plain/sleeper",
        Mode::Sleep(Duration::from_millis(50)),
    ));

    let ran = scheduler(8).run(items).await;
    assert_eq!(
        ran[0].end,
        End::TimedOut {
            after: Duration::from_millis(300)
        }
    );
    assert!(ran[1..].iter().all(passed), "{ran:?}");
}

#[tokio::test(start_paused = true)]
async fn at_most_jobs_checks_run_at_once() {
    let gauge = Arc::new(Gauge::default());
    let items: Vec<Planned> = (0..12)
        .map(|n| planned(&format!("fake.plain/{n}"), Mode::Track(Arc::clone(&gauge))))
        .collect();
    let ran = scheduler(3).run(items).await;
    assert!(ran.iter().all(passed));
    assert_eq!(gauge.max.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn one_job_runs_checks_one_after_another_in_input_order() {
    let items: Vec<Planned> = (0..4)
        .map(|n| {
            planned(
                &format!("fake.plain/{n}"),
                Mode::Sleep(Duration::from_secs(1)),
            )
        })
        .collect();
    let ran = scheduler(1).run(items).await;
    let started: Vec<u64> = ran.iter().map(|r| r.started.as_secs()).collect();
    assert_eq!(started, [0, 1, 2, 3]);
    let keys: Vec<&str> = ran.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "fake.plain/0",
            "fake.plain/1",
            "fake.plain/2",
            "fake.plain/3"
        ]
    );
}

#[tokio::test]
async fn a_fake_family_comes_back_as_pass_and_missing_need() {
    let runs = Arc::new(AtomicUsize::new(0));
    let items = vec![
        planned("fake.plain", Mode::Pass),
        Planned::new(
            fake(&NEEDS_ROOT, Mode::Count(Arc::clone(&runs))),
            "fake.needs_root",
        ),
    ];

    let ran = scheduler(8).run(items.clone()).await;
    assert!(passed(&ran[0]));
    let End::Done(done) = &ran[1].end else {
        panic!("expected a skip, got {:?}", ran[1].end);
    };
    let Err(error) = &**done else {
        panic!("expected a skip, got {:?}", ran[1].end);
    };
    assert_eq!(error, &CheckError::MissingNeed(Need::Root));
    assert_eq!(error.skip_kind(), Some(SkipKind::MissingNeed));
    assert_eq!(ran[1].id, "fake.needs_root");
    assert_eq!(ran[1].elapsed, Duration::ZERO);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "a check with a missing hard need must not start"
    );

    // The same plan passes when the need is met.
    let with_root = Scheduler::new(8, Os::Linux, [Need::Root]);
    let ran = with_root.run(items).await;
    assert!(ran.iter().all(passed));
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_check_sees_its_key_and_the_os_it_was_given() {
    let ran = Scheduler::new(2, Os::Macos, [Need::Network])
        .run(vec![planned("fake.plain/named", Mode::Pass)])
        .await;
    let End::Done(done) = &ran[0].end else {
        panic!("expected a finding");
    };
    let Ok(finding) = &**done else {
        panic!("expected a finding");
    };
    assert_eq!(finding.message, "fake.plain/named ran");
    assert_eq!(finding.observed, json!({ "ok": true }));
}

#[tokio::test(start_paused = true)]
async fn remaining_counts_down_to_the_timeout() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let item = planned("fake.plain/r", Mode::Remaining(Arc::clone(&seen)))
        .with_timeout(Duration::from_secs(10));
    let ran = scheduler(8).run(vec![item]).await;
    assert!(passed(&ran[0]));
    let seen = seen.lock().expect("lock").clone();
    assert_eq!(seen, [Duration::from_secs(10), Duration::from_secs(7)]);
}

#[tokio::test(start_paused = true)]
async fn remaining_is_the_cap_outside_the_scheduler_and_zero_after_the_deadline() {
    let bare = CheckContext::new("fake.plain", Os::Linux, []);
    assert_eq!(bare.remaining(), MAX_TIMEOUT);

    let timed = CheckContext::new("fake.plain", Os::Linux, [])
        .at_deadline(Instant::now() + Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(timed.remaining(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_run_aborts_the_checks_still_running() {
    let dropped = Arc::new(AtomicBool::new(false));
    let item = planned("fake.plain/held", Mode::DropFlag(Arc::clone(&dropped)));
    let outcome = tokio::time::timeout(Duration::from_secs(1), scheduler(8).run(vec![item])).await;
    assert!(outcome.is_err(), "the run should still be waiting");
    // Let the aborted task unwind.
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn an_empty_plan_returns_an_empty_result() {
    assert!(scheduler(8).run(Vec::new()).await.is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_permit_comes_back_after_a_timeout() {
    let ran = scheduler(1)
        .run(vec![
            planned("fake.plain/stuck", Mode::Forever),
            planned("fake.plain/after", Mode::Pass),
        ])
        .await;
    assert!(matches!(ran[0].end, End::TimedOut { .. }));
    assert!(passed(&ran[1]));
}

#[tokio::test]
async fn the_permit_comes_back_after_a_panic() {
    let ran = scheduler(1)
        .run(vec![
            planned("fake.plain/bad", Mode::Panic("boom")),
            planned("fake.plain/after", Mode::Pass),
        ])
        .await;
    assert!(matches!(ran[0].end, End::Panicked { .. }));
    assert!(passed(&ran[1]));
}

// Run deadline (M1-043). All under paused time, so a 5 minute deadline costs nothing.

/// Records what the scheduler tells an observer.
#[derive(Default)]
struct Log {
    events: Mutex<Vec<String>>,
}

impl Observer for Log {
    fn started(&self, index: usize, at: Duration, timeout: Duration) {
        self.events.lock().expect("lock").push(format!(
            "start {index} at {}s for {}s",
            at.as_secs(),
            timeout.as_secs()
        ));
    }

    fn finished(&self, index: usize, ran: &Ran) {
        let how = match &ran.end {
            End::Done(_) => "done",
            End::TimedOut { .. } => "timeout",
            End::RunDeadline => "run_deadline",
            End::Panicked { .. } => "panic",
            End::Cancelled => "cancelled",
        };
        self.events
            .lock()
            .expect("lock")
            .push(format!("end {index} {how}"));
    }
}

#[tokio::test(start_paused = true)]
async fn running_checks_time_out_at_the_deadline_and_unstarted_ones_are_run_deadline() {
    let started = Instant::now();
    let ran = scheduler(2)
        .with_deadline(Duration::from_secs(30))
        .run(vec![
            planned("fake.plain/a", Mode::Forever).with_timeout(Duration::from_secs(60)),
            planned("fake.plain/b", Mode::Forever).with_timeout(Duration::from_secs(60)),
            planned("fake.plain/c", Mode::Pass),
            planned("fake.plain/d", Mode::Pass),
        ])
        .await;
    let at_deadline = End::TimedOut {
        after: Duration::from_secs(30),
    };
    assert_eq!(ran[0].end, at_deadline);
    assert_eq!(ran[1].end, at_deadline);
    assert_eq!(ran[2].end, End::RunDeadline);
    assert_eq!(ran[3].end, End::RunDeadline);
    assert_eq!(started.elapsed(), Duration::from_secs(30));
    assert_eq!(ran[2].elapsed, Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn a_timeout_is_held_to_the_time_left_in_the_run() {
    // `late` starts at 20 s with 10 s of its own timeout and 5 s of run left.
    let ran = scheduler(1)
        .with_deadline(Duration::from_secs(25))
        .run(vec![
            planned("fake.plain/early", Mode::Sleep(Duration::from_secs(20)))
                .with_timeout(Duration::from_secs(30)),
            planned("fake.plain/late", Mode::Forever).with_timeout(Duration::from_secs(10)),
        ])
        .await;
    assert!(passed(&ran[0]));
    assert_eq!(
        ran[1].end,
        End::TimedOut {
            after: Duration::from_secs(5)
        }
    );
}

#[tokio::test(start_paused = true)]
async fn the_check_sees_the_capped_time_as_what_remains() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ran = scheduler(1)
        .with_deadline(Duration::from_secs(2))
        .run(vec![planned(
            "fake.plain/r",
            Mode::Remaining(Arc::clone(&seen)),
        )])
        .await;
    // The check waits 3 s, the run has 2 s: it times out after having seen 2 s remaining.
    assert!(matches!(ran[0].end, End::TimedOut { .. }));
    assert_eq!(seen.lock().expect("lock")[0], Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn a_run_that_finishes_before_the_deadline_has_no_run_deadline_results() {
    let ran = scheduler(2)
        .with_deadline(Duration::from_secs(30))
        .run(vec![
            planned("fake.plain/a", Mode::Sleep(Duration::from_secs(5))),
            planned("fake.plain/b", Mode::Pass),
            planned("fake.plain/c", Mode::Pass),
        ])
        .await;
    assert!(ran.iter().all(passed), "{ran:?}");
}

#[tokio::test(start_paused = true)]
async fn the_observer_sees_every_start_and_every_end_including_checks_never_started() {
    let log = Arc::new(Log::default());
    let ran = scheduler(1)
        .with_deadline(Duration::from_secs(5))
        .run_observed(
            vec![
                planned("fake.plain/a", Mode::Forever).with_timeout(Duration::from_secs(60)),
                planned("fake.plain/b", Mode::Pass),
            ],
            log.clone(),
        )
        .await;
    assert_eq!(ran.len(), 2);
    // The timeout of check 0 and the wait of check 1 end at the same instant, so their order is not fixed.
    let mut events = log.events.lock().expect("lock").clone();
    assert_eq!(events.remove(0), "start 0 at 0s for 5s");
    events.sort();
    assert_eq!(events, ["end 0 timeout", "end 1 run_deadline"]);
}

#[tokio::test(start_paused = true)]
async fn a_missing_need_is_reported_as_such_even_after_the_deadline() {
    let ran = scheduler(1)
        .with_deadline(Duration::from_secs(1))
        .run(vec![
            planned("fake.plain/a", Mode::Forever),
            Planned::new(fake(&NEEDS_ROOT, Mode::Pass), "fake.needs_root"),
        ])
        .await;
    assert!(matches!(
        &ran[1].end,
        End::Done(done) if matches!(&**done, Err(CheckError::MissingNeed(_)))
    ));
}

#[tokio::test(start_paused = true)]
async fn a_check_cut_by_the_run_deadline_has_its_probe_ended() {
    use crate::probe::{ProbeError, ProbeHub, RULE_CHECK_FINISHED, replay::Replay};

    let hub = ProbeHub::new(
        Arc::new(Replay::new().file("/etc/hostname", "host-a")),
        redactor(),
    );
    let slot = Arc::new(Mutex::new(None));
    let ran = scheduler(1)
        .with_probes(hub)
        .with_deadline(Duration::from_secs(5))
        .run(vec![
            planned("fake.plain/held", Mode::KeepProbe(Arc::clone(&slot)))
                .with_timeout(Duration::from_secs(60)),
        ])
        .await;
    // The deadline, not the check's own 60 s, ended it.
    assert_eq!(
        ran[0].end,
        End::TimedOut {
            after: Duration::from_secs(5)
        }
    );
    let probe = slot.lock().expect("lock").take().expect("the check ran");
    // A late call, on the handle the check kept, is refused.
    let error = probe
        .read(std::path::Path::new("/etc/hostname"))
        .await
        .expect_err("the probe has ended");
    assert_eq!(
        error,
        ProbeError::Denied {
            rule: RULE_CHECK_FINISHED,
            what: "/etc/hostname".to_owned()
        }
    );
}

#[test]
fn the_default_deadline_is_five_minutes() {
    assert_eq!(DEFAULT_DEADLINE, Duration::from_secs(300));
    assert_eq!(scheduler(1).deadline(), DEFAULT_DEADLINE);
}
