//! The scheduler: runs checks with a concurrency limit, a timeout each and panic isolation.
//!
//! The scheduler is the only place that starts a [`Check`]. It follows 02 (engine design), "Scheduling,
//! timeouts and hangs":
//!
//! - **Concurrency.** One semaphore. The default is [`DEFAULT_JOBS`] and [`cap_jobs`] holds the top at
//!   [`MAX_JOBS`]. Checks take a permit in the order they were given.
//! - **Timeout.** Each check runs as its own tokio task. The scheduler awaits the task's `JoinHandle`
//!   under `tokio::time::timeout`, so the timer lives outside the check. On expiry the task is aborted
//!   and the result is [`End::TimedOut`]. A check that never yields cannot be aborted. It holds its
//!   worker until it returns. The timer and the other checks keep running only while the runtime has a
//!   free worker: it fails once as many checks spin as there are workers, or on a `current_thread`
//!   runtime. Threads abandoned on `spawn_blocking` also outlive the timeout, but a command does not:
//!   [`crate::exec`] kills its process group when the aborted task drops it. The backstop for the rest
//!   is the run watchdog ([`crate::watchdog`]).
//! - **Run deadline.** The whole run has a deadline ([`DEFAULT_DEADLINE`], 5 minutes, 02 "Scheduling,
//!   timeouts and hangs"). A check's timeout is held to the time left in the run, so a check that is
//!   still running at the deadline ends as [`End::TimedOut`]. A check that has not started by then
//!   ends as [`End::RunDeadline`] and is never started. The deadline is read from the tokio clock, so
//!   tests under paused time cover it.
//! - **Panics.** A panic stays inside the check's task. The join handle returns it and the result is
//!   [`End::Panicked`].
//! - **Hard needs.** A check whose hard need is missing is not started. Its result is
//!   `Err(CheckError::MissingNeed)`, the same value a check would return itself.
//!
//! The scheduler returns the raw [`CheckOutcome`] and the timing. Mapping them to a `CheckResult`
//! (status, severity, fix, redaction) is the outcome mapping (M1-033). An [`Observer`] sees each check
//! start and finish while the run is going, which is how the watchdog's snapshot stays current.

use std::any::Any;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

use crate::check::{Check, CheckContext, CheckError, CheckOutcome, Need, Os};
use crate::redact::{Redacted, Redactor};

#[cfg(test)]
mod tests;

/// How many checks run at once when the operator does not say.
pub const DEFAULT_JOBS: usize = 8;

/// The most checks that may run at once. `--jobs` above this is capped.
pub const MAX_JOBS: usize = 32;

/// How long a whole run may take when the operator does not say (02, "Run deadline").
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(300);

/// The timeout of a check with neither a spec value nor a check default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

pub use crate::check::MAX_TIMEOUT;

/// Holds a requested `--jobs` value to `1..=`[`MAX_JOBS`].
///
/// The CLI refuses `--jobs 0` before it gets here (M1-059). Zero maps to one so the scheduler can
/// never be built with no permits.
#[must_use]
pub fn cap_jobs(requested: usize) -> usize {
    requested.clamp(1, MAX_JOBS)
}

/// The timeout a check gets: the spec value, else the check default, else [`DEFAULT_TIMEOUT`], held to
/// [`MAX_TIMEOUT`].
#[must_use]
pub fn effective_timeout(spec: Option<Duration>, check_default: Option<Duration>) -> Duration {
    spec.or(check_default)
        .unwrap_or(DEFAULT_TIMEOUT)
        .min(MAX_TIMEOUT)
}

/// One check to run.
#[derive(Clone)]
pub struct Planned {
    check: Arc<dyn Check>,
    key: String,
    timeout: Option<Duration>,
}

impl Planned {
    /// A check with its result `key` (the id, or `id/name`). It gets the check's own default timeout.
    #[must_use]
    pub fn new(check: Arc<dyn Check>, key: impl Into<String>) -> Self {
        Self {
            check,
            key: key.into(),
            timeout: None,
        }
    }

    /// Sets the spec's `timeout` for this check. It replaces the check default.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl std::fmt::Debug for Planned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Planned")
            .field("key", &self.key)
            .field("id", &self.check.info().id)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// How one check ended.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum End {
    /// The check returned, or was never started because a hard need was missing.
    ///
    /// The outcome is boxed. A finding carries two JSON values, and in a `--workspace` build
    /// `serde_json`'s `preserve_order` feature is on (ADR 0019), which makes them large enough that an
    /// unboxed outcome would make every `End`, even a timeout, as big as a finding.
    Done(Box<CheckOutcome>),
    /// The check was still running at its timeout and was aborted.
    TimedOut {
        /// The timeout it had.
        after: Duration,
    },
    /// The check panicked.
    ///
    /// The text is raw and can only be read through [`PanicText::redacted`]. The default panic hook
    /// writes the raw text to stderr before the scheduler catches the panic. The CLI replaces that hook.
    Panicked {
        /// The panic message when it was text, else a fixed note.
        message: PanicText,
    },
    /// The run reached its deadline before this check started, so it never started.
    RunDeadline,
    /// The task was cancelled from outside, which means the runtime was shutting down.
    Cancelled,
}

/// The raw text of a panic.
///
/// A panic message can hold anything the check had in hand, such as a value from an environment
/// variable. There is no `Display`, no `Deref` and no accessor for the raw text, and `Debug` hides it,
/// so the only way to read it is [`PanicText::redacted`] (ADR 0015 decision 6).
#[derive(Clone, PartialEq, Eq)]
pub struct PanicText(String);

impl PanicText {
    /// The panic text with secrets removed.
    #[must_use]
    pub fn redacted(&self, redactor: &Redactor) -> Redacted<String> {
        redactor.redact_str(&self.0)
    }
}

impl fmt::Debug for PanicText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The text is raw. A log line with `{:?}` of a `Ran` must not print it.
        f.write_str("PanicText(..)")
    }
}

/// One check's result from the scheduler, with timing.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Ran {
    /// The result key, as given in [`Planned::new`].
    pub key: String,
    /// The check id.
    pub id: &'static str,
    /// How it ended.
    pub end: End,
    /// When it started, counted from the start of the run.
    pub started: Duration,
    /// How long it ran. Zero for a check that was never started.
    pub elapsed: Duration,
}

/// Sees checks start and finish while a run is going.
///
/// The scheduler calls it from its own tasks, so an implementation must not block for long. The
/// watchdog's snapshot ([`crate::watchdog::Board`]) is the one in this crate. `index` is the check's
/// place in the list given to [`Scheduler::run_observed`].
pub trait Observer: Send + Sync {
    /// The check started. `at` is counted from the start of the run and `timeout` is the limit it was
    /// given, already held to the time left in the run.
    fn started(&self, index: usize, at: Duration, timeout: Duration);

    /// The check ended in any way, or was never started.
    fn finished(&self, index: usize, ran: &Ran);
}

/// An [`Observer`] that does nothing.
struct NoObserver;

impl Observer for NoObserver {
    fn started(&self, _index: usize, _at: Duration, _timeout: Duration) {}

    fn finished(&self, _index: usize, _ran: &Ran) {}
}

/// Runs checks. Build one per run.
#[derive(Debug, Clone)]
pub struct Scheduler {
    jobs: usize,
    os: Os,
    available: Arc<HashSet<Need>>,
    deadline: Duration,
}

impl Scheduler {
    /// A scheduler for a run on `os` where the `available` needs are met.
    ///
    /// `jobs` is held to `1..=`[`MAX_JOBS`] by [`cap_jobs`].
    #[must_use]
    pub fn new(jobs: usize, os: Os, available: impl IntoIterator<Item = Need>) -> Self {
        Self {
            jobs: cap_jobs(jobs),
            os,
            available: Arc::new(available.into_iter().collect()),
            deadline: DEFAULT_DEADLINE,
        }
    }

    /// Sets the run deadline, counted from the start of [`Scheduler::run`]. The default is
    /// [`DEFAULT_DEADLINE`].
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// The run deadline.
    #[must_use]
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The number of checks that may run at once, after the cap.
    #[must_use]
    pub fn jobs(&self) -> usize {
        self.jobs
    }

    /// Runs every check and returns one [`Ran`] per input, in input order.
    ///
    /// Checks start in input order as permits free up. A check that times out, panics or misses a hard
    /// need does not stop the others. When the run deadline passes, checks still running end as
    /// timeouts and checks not yet started end as [`End::RunDeadline`]. Dropping the returned future
    /// aborts every check still running.
    pub async fn run(&self, planned: Vec<Planned>) -> Vec<Ran> {
        self.run_observed(planned, Arc::new(NoObserver)).await
    }

    /// Like [`Scheduler::run`], and tells `observer` about every start and every end.
    pub async fn run_observed(
        &self,
        planned: Vec<Planned>,
        observer: Arc<dyn Observer>,
    ) -> Vec<Ran> {
        let origin = Instant::now();
        let deadline_at = origin + self.deadline;
        let semaphore = Arc::new(Semaphore::new(self.jobs));
        let mut slots: Vec<Option<Ran>> = vec![None; planned.len()];
        let mut drivers: JoinSet<(usize, Ran)> = JoinSet::new();
        let meta: Vec<(String, &'static str)> = planned
            .iter()
            .map(|p| (p.key.clone(), p.check.info().id))
            .collect();

        for (index, item) in planned.into_iter().enumerate() {
            let info = item.check.info();
            if let Some(missing) = info
                .needs
                .iter()
                .find(|need| !self.available.contains(need))
            {
                let end = End::Done(Box::new(Err(CheckError::MissingNeed(missing.clone()))));
                let now = Instant::now();
                let result = ran(item.key, info.id, end, origin, now, now);
                observer.finished(index, &result);
                slots[index] = Some(result);
                continue;
            }
            // Past the deadline nothing new starts. A permit that frees up at the deadline does not
            // count: the wait for one ends at the deadline too.
            let permit = if Instant::now() >= deadline_at {
                None
            } else {
                match tokio::time::timeout_at(deadline_at, Arc::clone(&semaphore).acquire_owned())
                    .await
                {
                    Ok(Ok(permit)) => Some(permit),
                    Ok(Err(_closed)) => continue,
                    Err(_elapsed) => None,
                }
            };
            let Some(permit) = permit else {
                let now = Instant::now();
                let result = ran(item.key, info.id, End::RunDeadline, origin, now, now);
                observer.finished(index, &result);
                slots[index] = Some(result);
                continue;
            };
            let run = Run {
                os: self.os,
                available: Arc::clone(&self.available),
                origin,
                deadline_at,
                index,
                observer: Arc::clone(&observer),
            };
            drivers.spawn(async move {
                let result = drive(item, &run).await;
                run.observer.finished(index, &result);
                drop(permit);
                (index, result)
            });
        }

        while let Some(joined) = drivers.join_next().await {
            if let Ok((index, result)) = joined
                && let Some(slot) = slots.get_mut(index)
            {
                *slot = Some(result);
            }
        }

        // A driver only fails if the runtime is shutting down. Report those checks as cancelled.
        slots
            .into_iter()
            .zip(meta)
            .map(|(slot, (key, id))| {
                slot.unwrap_or_else(|| {
                    let now = Instant::now();
                    ran(key, id, End::Cancelled, origin, now, now)
                })
            })
            .collect()
    }
}

/// Builds a [`Ran`] that started at `started` and ended at `finished`.
fn ran(
    key: String,
    id: &'static str,
    end: End,
    origin: Instant,
    started: Instant,
    finished: Instant,
) -> Ran {
    Ran {
        key,
        id,
        end,
        started: started.saturating_duration_since(origin),
        elapsed: finished.saturating_duration_since(started),
    }
}

/// Aborts the task on drop, so a dropped `run` future does not leave checks running.
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What a driver needs to know about the run.
struct Run {
    os: Os,
    available: Arc<HashSet<Need>>,
    origin: Instant,
    deadline_at: Instant,
    index: usize,
    observer: Arc<dyn Observer>,
}

/// Starts one check as a task and waits for it under its timeout, held to the time left in the run.
async fn drive(item: Planned, run: &Run) -> Ran {
    let Planned {
        check,
        key,
        timeout,
    } = item;
    let id = check.info().id;
    let started = Instant::now();
    let left = run.deadline_at.saturating_duration_since(started);
    if left.is_zero() {
        // The permit came at the deadline. Nothing starts now.
        return ran(key, id, End::RunDeadline, run.origin, started, started);
    }
    let after = effective_timeout(timeout, check.info().default_timeout).min(left);
    let ctx = CheckContext::new(key.clone(), run.os, run.available.iter().cloned())
        .at_deadline(started + after);
    run.observer.started(
        run.index,
        started.saturating_duration_since(run.origin),
        after,
    );

    let mut handle = tokio::spawn(async move { check.run(&ctx).await });
    let _guard = AbortOnDrop(handle.abort_handle());

    let end = match tokio::time::timeout(after, &mut handle).await {
        Ok(Ok(outcome)) => End::Done(Box::new(outcome)),
        Ok(Err(error)) if error.is_panic() => End::Panicked {
            message: PanicText(panic_message(error.into_panic())),
        },
        Ok(Err(_)) => End::Cancelled,
        Err(_elapsed) => {
            handle.abort();
            End::TimedOut { after }
        }
    };
    ran(key, id, end, run.origin, started, Instant::now())
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(text) => *text,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(text) => (*text).to_owned(),
            Err(_) => "the check panicked with a non-text payload".to_owned(),
        },
    }
}
