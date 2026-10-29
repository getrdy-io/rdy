//! The run watchdog (MF-02, 02 "Watchdog", ADR 0016 decision 6).
//!
//! A check that never yields cannot be aborted, and a blocked stdout pipe or a stuck lock can stop
//! the run from ever finishing. The watchdog is the backstop: a plain OS thread, started before the
//! async runtime, that guarantees a report and an exit.
//!
//! It fires at the run deadline plus [`Timing::grace`] (10 s). Then:
//!
//! 1. **One writer.** [`WriteState`] holds `Running`, `Writing` or `Done`. Whoever moves it from
//!    `Running` to `Writing` writes the report. If the run finished first (state `Done`), the watchdog
//!    does nothing. If the normal path is `Writing` and does not reach `Done` within
//!    [`Timing::loser_wait`] (5 s), the watchdog kills the process groups and exits 70 without writing.
//! 2. **Snapshot.** [`Board::snapshot`] reads the results so far with a `try_lock` loop bounded by
//!    [`Timing::snapshot_bound`] (1 s). Checks still running become `timeout`, checks not started
//!    become `run_deadline`, and with no lock every check is an `error`.
//! 3. **Its own pass.** It redacts the whole report with `redact_report_counted`, whatever the
//!    snapshot held, and keeps the counts of the results redacted earlier.
//! 4. **Bounded write.** The sink runs on a helper thread. The watchdog waits at most
//!    [`Timing::write_bound`] (10 s).
//! 5. **Kill, then exit.** It kills every live process group, writes one fixed line to stderr and
//!    exits 70, whatever happened above, even a panic in the redactor.
//!
//! It never takes std's stdout or stderr lock, because the thread that holds one may be the stuck one.
//! The worst case from the start of the run is the deadline plus about 22 s.
//!
//! Before [`Watchdog::arm`] has been called (no output folder yet) there is nothing to write, so the
//! watchdog only kills and exits. On the normal path the CLI calls [`WriteState::claim_or_park`],
//! writes, calls [`WriteState::finish`], kills leftover groups and exits.
//!
//! Time and effects are traits ([`Clock`], [`Effects`]) so the tests can move time by hand and see
//! the exit without ending the test process. The real ones are [`SystemClock`] and [`ProcessEffects`].

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::exec;
use crate::output::ReportError;
use crate::redact::{RedactedReport, Redactor};

mod board;
#[cfg(test)]
mod tests;

pub use board::{Board, MapRan, Snapshot};

/// The exit code of a run that hung.
pub const EXIT_HUNG: i32 = 70;

/// The one line written to stderr when the watchdog ends a run. Fixed text: it holds no input.
const NOTICE: &str = "error: the run did not finish and rdy stopped it. Fix: run it again. \
If it happens again, tell the vendor which check hung. A report may be in the report folder.\n";

/// The watchdog's time limits (02, "Watchdog").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Time after the run deadline at which the watchdog fires.
    pub grace: Duration,
    /// The longest it waits for the snapshot lock.
    pub snapshot_bound: Duration,
    /// The longest it waits for the normal path to reach `Done` after losing the race.
    pub loser_wait: Duration,
    /// The longest it waits for the helper thread that writes the report.
    pub write_bound: Duration,
}

impl Timing {
    /// 10 s, 1 s, 5 s and 10 s. With the kill and the notice, the exit is within the deadline plus 22 s.
    pub const DEFAULT: Self = Self {
        grace: Duration::from_secs(10),
        snapshot_bound: Duration::from_secs(1),
        loser_wait: Duration::from_secs(5),
        write_bound: Duration::from_secs(10),
    };
}

impl Default for Timing {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Who may write the report: the CLI at the end of the run or the watchdog (ADR 0016 decision 6).
#[derive(Debug, Default)]
pub struct WriteState(AtomicU8);

/// The phases of [`WriteState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nobody has started writing.
    Running,
    /// One side is writing.
    Writing,
    /// The report is written.
    Done,
}

const RUNNING: u8 = 0;
const WRITING: u8 = 1;
const DONE: u8 = 2;

impl WriteState {
    /// A state in `Running`.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU8::new(RUNNING))
    }

    /// Moves `Running` to `Writing`. True means the caller writes. False means the other side does
    /// and the caller must not write.
    pub fn claim(&self) -> bool {
        self.0
            .compare_exchange(RUNNING, WRITING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Like [`WriteState::claim`], and parks the thread for good when it loses. The watchdog is
    /// writing and will exit the process.
    pub fn claim_or_park(&self) {
        if !self.claim() {
            loop {
                thread::park();
            }
        }
    }

    /// Marks the report as written.
    pub fn finish(&self) {
        self.0.store(DONE, Ordering::Release);
    }

    /// Where the state is now.
    #[must_use]
    pub fn phase(&self) -> Phase {
        match self.0.load(Ordering::Acquire) {
            RUNNING => Phase::Running,
            WRITING => Phase::Writing,
            _ => Phase::Done,
        }
    }
}

/// Writes the report when the watchdog has to. The CLI gives it the held output folder and the
/// renderers (JSON and HTML). It runs on a helper thread and gets only a redacted report.
pub trait ReportSink: Send + Sync {
    /// Writes the report. The watchdog ignores the error: it exits 70 either way.
    ///
    /// # Errors
    ///
    /// Whatever the output folder refuses.
    fn write(&self, report: &RedactedReport) -> Result<(), ReportError>;
}

/// A stop signal that a [`Clock`] can wait on.
#[derive(Debug, Default)]
pub struct Stop {
    stopped: Mutex<bool>,
    wake: Condvar,
}

impl Stop {
    /// Asks the watchdog to end without acting.
    pub fn stop(&self) {
        *self
            .stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }

    /// Whether [`Stop::stop`] was called.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        *self
            .stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Waits up to `limit` for a stop. True if it was stopped.
    #[must_use]
    pub fn wait(&self, limit: Duration) -> bool {
        let guard = self
            .stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (guard, _timed_out) = self
            .wake
            .wait_timeout_while(guard, limit, |stopped| !*stopped)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard
    }
}

/// Time for the watchdog's single long wait. Tests move it by hand.
pub trait Clock: Send + Sync {
    /// Blocks until `at` has passed since the watchdog started (true) or `stop` is stopped (false).
    fn wait_until(&self, at: Duration, stop: &Stop) -> bool;
}

/// The real clock, counted from when it was made.
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// A clock that starts now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn wait_until(&self, at: Duration, stop: &Stop) -> bool {
        loop {
            let left = at.saturating_sub(self.start.elapsed());
            if left.is_zero() {
                return true;
            }
            if stop.wait(left) {
                return false;
            }
        }
    }
}

/// What the watchdog does to the outside world. The real one is [`ProcessEffects`].
pub trait Effects: Send + Sync {
    /// Sends SIGKILL to every live process group of the run.
    fn kill_groups(&self);
    /// Writes the fixed line to stderr. Must not block for long and must not take std's locks.
    fn notice(&self);
    /// Ends the process.
    fn exit(&self, code: i32);
}

/// Kills the real process groups, writes to the real stderr and ends the real process.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEffects;

impl Effects for ProcessEffects {
    fn kill_groups(&self) {
        exec::kill_all_groups();
    }

    fn notice(&self) {
        write_notice();
    }

    fn exit(&self, code: i32) {
        std::process::exit(code);
    }
}

/// How long the watchdog waits for the stderr line before it exits anyway.
#[cfg(unix)]
const NOTICE_WAIT: Duration = Duration::from_millis(200);

/// Writes [`NOTICE`] on a helper thread with a raw write, so neither a full pipe nor a held std lock
/// can stop the exit.
#[cfg(unix)]
fn write_notice() {
    use std::os::fd::AsFd as _;

    let (done, wait) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("rdy-watchdog-notice".into())
        .spawn(move || {
            // `as_fd` on the handle does not take the lock. `write` may block on a full pipe.
            let _ = rustix::io::write(io::stderr().as_fd(), NOTICE.as_bytes());
            let _ = done.send(());
        });
    if spawned.is_ok() {
        let _ = wait.recv_timeout(NOTICE_WAIT);
    }
}

/// No stderr line outside Unix: every safe way to write takes std's lock.
#[cfg(not(unix))]
fn write_notice() {}

/// Everything [`Watchdog::start`] needs.
pub struct WatchdogConfig {
    deadline: Duration,
    timing: Timing,
    state: Arc<WriteState>,
    redactor: Redactor,
    clock: Arc<dyn Clock>,
    effects: Arc<dyn Effects>,
}

impl WatchdogConfig {
    /// A config for a run with this `deadline` (give it the one the scheduler has), the shared write
    /// `state` and the process redactor, with the real clock, the real effects and [`Timing::DEFAULT`].
    #[must_use]
    pub fn new(deadline: Duration, state: Arc<WriteState>, redactor: Redactor) -> Self {
        Self {
            deadline,
            timing: Timing::DEFAULT,
            state,
            redactor,
            clock: Arc::new(SystemClock::new()),
            effects: Arc::new(ProcessEffects),
        }
    }

    /// Replaces the time limits.
    #[must_use]
    pub fn with_timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    /// Replaces the clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Replaces the effects.
    #[must_use]
    pub fn with_effects(mut self, effects: Arc<dyn Effects>) -> Self {
        self.effects = effects;
        self
    }
}

struct Armed {
    board: Arc<Board>,
    sink: Arc<dyn ReportSink>,
}

struct Shared {
    timing: Timing,
    state: Arc<WriteState>,
    redactor: Redactor,
    clock: Arc<dyn Clock>,
    effects: Arc<dyn Effects>,
    armed: OnceLock<Armed>,
    stop: Stop,
}

/// The watchdog thread. Start it first thing in `main`, before the runtime.
///
/// Its clock counts from the start of the run, so start it when the scheduler's deadline starts. The
/// 10 s of grace covers the little that happens in between.
pub struct Watchdog {
    shared: Arc<Shared>,
    thread: JoinHandle<()>,
}

impl std::fmt::Debug for Watchdog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watchdog").finish_non_exhaustive()
    }
}

impl Watchdog {
    /// Starts the thread. It waits for the deadline plus the grace.
    ///
    /// # Errors
    ///
    /// The OS could not start a thread. rdy exits 70 then: a run with no watchdog is not allowed.
    pub fn start(config: WatchdogConfig) -> io::Result<Self> {
        let WatchdogConfig {
            deadline,
            timing,
            state,
            redactor,
            clock,
            effects,
        } = config;
        let shared = Arc::new(Shared {
            timing,
            state,
            redactor,
            clock,
            effects,
            armed: OnceLock::new(),
            stop: Stop::default(),
        });
        let fire_at = deadline.saturating_add(timing.grace);
        let for_thread = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("rdy-watchdog".into())
            .spawn(move || {
                if for_thread.clock.wait_until(fire_at, &for_thread.stop) {
                    for_thread.fire();
                }
            })?;
        Ok(Self { shared, thread })
    }

    /// Gives the watchdog what it needs to write a report: the board and the sink. Call it right
    /// after the output folder is made. True the first time, false after that.
    pub fn arm(&self, board: Arc<Board>, sink: Arc<dyn ReportSink>) -> bool {
        self.shared.armed.set(Armed { board, sink }).is_ok()
    }

    /// Ends the watchdog without it acting, and waits for the thread.
    pub fn stop(self) {
        self.shared.stop.stop();
        let _ = self.thread.join();
    }

    /// Waits for the thread to end on its own. For tests: in a real run the thread ends the process.
    pub fn join(self) {
        let _ = self.thread.join();
    }
}

impl Shared {
    /// The deadline plus the grace has passed.
    fn fire(&self) {
        if self.state.phase() == Phase::Done {
            // The run finished and the process is on its way out.
            return;
        }
        if self.state.claim() {
            // A panic anywhere in the write (the redactor, the sink) must not stop the exit.
            let _ = catch_unwind(AssertUnwindSafe(|| self.write_partial_report()));
        } else if self.wait_for_done() {
            return;
        }
        self.effects.kill_groups();
        self.effects.notice();
        self.effects.exit(EXIT_HUNG);
    }

    /// The normal path is writing. Waits for it, at most `loser_wait`. True if it finished.
    fn wait_for_done(&self) -> bool {
        let give_up = Instant::now() + self.timing.loser_wait;
        while self.state.phase() != Phase::Done {
            if Instant::now() >= give_up {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// Snapshot, redact, write on a helper thread and wait for it, each step bounded. Writes nothing
    /// when the watchdog was never armed.
    fn write_partial_report(&self) {
        let Some(armed) = self.armed.get() else {
            return;
        };
        let (report, counts) = armed.board.partial_report(self.timing.snapshot_bound);
        let Ok(redacted) = self.redactor.redact_report_counted(report, counts) else {
            return;
        };
        let sink = Arc::clone(&armed.sink);
        let (done, wait) = mpsc::channel();
        let spawned = thread::Builder::new()
            .name("rdy-watchdog-write".into())
            .spawn(move || {
                let _ = sink.write(&redacted);
                let _ = done.send(());
            });
        if spawned.is_ok() {
            let _ = wait.recv_timeout(self.timing.write_bound);
        }
    }
}
