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
//!   runtime. Threads abandoned on `spawn_blocking` also outlive the timeout. The backstops are the
//!   blocking helper (M1-038) and the run watchdog (M1-043).
//! - **Panics.** A panic stays inside the check's task. The join handle returns it and the result is
//!   [`End::Panicked`].
//! - **Hard needs.** A check whose hard need is missing is not started. Its result is
//!   `Err(CheckError::MissingNeed)`, the same value a check would return itself.
//!
//! The scheduler returns the raw [`CheckOutcome`] and the timing. Mapping them to a `CheckResult`
//! (status, severity, fix, redaction) is the outcome mapping (M1-033). The run deadline, the watchdog
//! and the "time left in the run" cap on a timeout come with M1-043.

use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

use crate::check::{Check, CheckContext, CheckError, CheckOutcome, Need, Os};

#[cfg(test)]
mod tests;

/// How many checks run at once when the operator does not say.
pub const DEFAULT_JOBS: usize = 8;

/// The most checks that may run at once. `--jobs` above this is capped.
pub const MAX_JOBS: usize = 32;

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
    Done(CheckOutcome),
    /// The check was still running at its timeout and was aborted.
    TimedOut {
        /// The timeout it had.
        after: Duration,
    },
    /// The check panicked.
    ///
    /// The text is raw. Redact it before it is shown or written: this type's `Debug` output prints it
    /// as is, and so does the default panic hook, which writes it to stderr before the scheduler
    /// catches the panic. The CLI replaces that hook.
    Panicked {
        /// The panic message when it was text, else a fixed note. It is not redacted yet.
        message: String,
    },
    /// The task was cancelled from outside, which means the runtime was shutting down.
    Cancelled,
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

/// Runs checks. Build one per run.
#[derive(Debug, Clone)]
pub struct Scheduler {
    jobs: usize,
    os: Os,
    available: Arc<HashSet<Need>>,
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
        }
    }

    /// The number of checks that may run at once, after the cap.
    #[must_use]
    pub fn jobs(&self) -> usize {
        self.jobs
    }

    /// Runs every check and returns one [`Ran`] per input, in input order.
    ///
    /// Checks start in input order as permits free up. A check that times out, panics or misses a hard
    /// need does not stop the others. Dropping the returned future aborts every check still running.
    pub async fn run(&self, planned: Vec<Planned>) -> Vec<Ran> {
        let origin = Instant::now();
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
                let end = End::Done(Err(CheckError::MissingNeed(missing.clone())));
                let now = Instant::now();
                slots[index] = Some(ran(item.key, info.id, end, origin, now, now));
                continue;
            }
            let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                continue;
            };
            let os = self.os;
            let available = Arc::clone(&self.available);
            drivers.spawn(async move {
                let result = drive(item, os, &available, origin).await;
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

/// Starts one check as a task and waits for it under its timeout.
async fn drive(item: Planned, os: Os, available: &HashSet<Need>, origin: Instant) -> Ran {
    let Planned {
        check,
        key,
        timeout,
    } = item;
    let id = check.info().id;
    let after = effective_timeout(timeout, check.info().default_timeout);
    let started = Instant::now();
    let ctx =
        CheckContext::new(key.clone(), os, available.iter().cloned()).at_deadline(started + after);

    let mut handle = tokio::spawn(async move { check.run(&ctx).await });
    let _guard = AbortOnDrop(handle.abort_handle());

    let end = match tokio::time::timeout(after, &mut handle).await {
        Ok(Ok(outcome)) => End::Done(outcome),
        Ok(Err(error)) if error.is_panic() => End::Panicked {
            message: panic_message(error.into_panic()),
        },
        Ok(Err(_)) => End::Cancelled,
        Err(_elapsed) => {
            handle.abort();
            End::TimedOut { after }
        }
    };
    ran(key, id, end, origin, started, Instant::now())
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
