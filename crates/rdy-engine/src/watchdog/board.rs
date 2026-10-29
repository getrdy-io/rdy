//! The run board: the snapshot of finished results that the watchdog reads (02, "Watchdog").
//!
//! The scheduler tells the board about every start and every end ([`Observer`]). The board turns an
//! end into a `CheckResult` with the function it was given, redacts it with
//! [`Redactor::redact_check`] and keeps it. So the results here are already redacted as they
//! complete (ADR 0015), and the watchdog still runs its own pass over them as a second line.
//!
//! The lock is a plain `std` mutex, and the watchdog never waits on it for long: [`Board::snapshot`]
//! uses `try_lock` in a loop bounded by the caller. A lock held by a stuck thread gives a snapshot
//! with no results, and every check is then reported as unfinished. A poisoned lock is read through
//! `into_inner`: results are only ever replaced whole, so a poisoned board is still consistent.

use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use rdy_spec::result::{CheckResult, Report};

use crate::outcome::{run_deadline_result, timeout_result, unfinished_result};
use crate::redact::{Redactor, RuleCounts};
use crate::sched::{Observer, Ran};

/// How the board turns an end into a result. It gets the check's index and what the scheduler saw.
/// M1-057 gives it `map_outcome` for a finished check and `timeout_result` for a timeout.
pub type MapRan = Box<dyn Fn(usize, &Ran) -> CheckResult + Send + Sync>;

/// How long `snapshot` sleeps between two `try_lock` calls.
const POLL: Duration = Duration::from_millis(1);

enum Slot {
    /// Not started.
    Pending,
    /// Started and not ended. The offset from the run start and the limit it was given.
    Running { at: Duration, timeout: Duration },
    /// Ended. The result is already redacted.
    Done(Box<CheckResult>),
}

struct Inner {
    slots: Vec<Slot>,
    counts: RuleCounts,
}

/// The results so far, read by the watchdog.
#[non_exhaustive]
pub struct Snapshot {
    /// One result per check, in spec order. A check still running is a timeout, a check not started
    /// is `run_deadline`, and with no lock every check is unfinished.
    pub results: Vec<CheckResult>,
    /// What the redactor did to the results kept so far. Empty when the lock was not taken.
    pub counts: RuleCounts,
    /// Whether the lock was taken.
    pub locked: bool,
}

/// The shared record of a run: what each check is doing and the results of the ones that ended.
pub struct Board {
    base: Report,
    templates: Vec<CheckResult>,
    redactor: Redactor,
    map: MapRan,
    deadline: Duration,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Board {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Board")
            .field("checks", &self.templates.len())
            .finish_non_exhaustive()
    }
}

impl Board {
    /// A board for a run.
    ///
    /// - `base` is the report without its results: producer, run, spec, host, identity and so on.
    ///   Its `checks` are ignored.
    /// - `templates` holds one result per check, in spec order, from which only the identity is
    ///   used (see [`crate::outcome::timeout_result`]). The scheduler's indexes are positions in this
    ///   list.
    /// - `deadline` is the run's deadline, for the text of a `run_deadline` skip.
    /// - `map` makes the result of an end.
    #[must_use]
    pub fn new(
        base: Report,
        templates: Vec<CheckResult>,
        redactor: Redactor,
        deadline: Duration,
        map: MapRan,
    ) -> Self {
        let slots = templates.iter().map(|_| Slot::Pending).collect();
        Self {
            base,
            templates,
            redactor,
            map,
            deadline,
            inner: Mutex::new(Inner {
                slots,
                counts: RuleCounts::default(),
            }),
        }
    }

    /// Reads the results so far, waiting at most `bound` for the lock.
    ///
    /// Never blocks past `bound`, whoever holds the lock. This is the watchdog's read.
    #[must_use]
    pub fn snapshot(&self, bound: Duration) -> Snapshot {
        let give_up = Instant::now() + bound;
        loop {
            match self.inner.try_lock() {
                Ok(inner) => return self.read(&inner),
                Err(TryLockError::Poisoned(poisoned)) => return self.read(&poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {}
            }
            if Instant::now() >= give_up {
                return Snapshot {
                    results: self.templates.iter().map(unfinished_result).collect(),
                    counts: RuleCounts::default(),
                    locked: false,
                };
            }
            std::thread::sleep(POLL);
        }
    }

    /// The report as far as the run got: the base report with the snapshot's results, `complete`
    /// false, and the verdict worked out again from them. The counts go with it so the caller can
    /// call `redact_report_counted`. Not yet redacted.
    #[must_use]
    pub fn partial_report(&self, bound: Duration) -> (Report, RuleCounts) {
        let snapshot = self.snapshot(bound);
        let mut report = self.base.clone();
        report.checks = snapshot.results;
        report.complete = false;
        report.refresh_verdict();
        (report, snapshot.counts)
    }

    /// What the redactor did to every result kept so far. Pass it to `redact_report_counted` when
    /// the final report is built.
    #[must_use]
    pub fn counts(&self) -> RuleCounts {
        self.lock().counts.clone()
    }

    fn read(&self, inner: &Inner) -> Snapshot {
        let results = inner
            .slots
            .iter()
            .zip(&self.templates)
            .map(|(slot, template)| match slot {
                Slot::Pending => run_deadline_result(template, self.deadline),
                Slot::Running { at, timeout } => timeout_result(template, *timeout, *at),
                Slot::Done(result) => (**result).clone(),
            })
            .collect();
        Snapshot {
            results,
            counts: inner.counts.clone(),
            locked: true,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Holds the lock until the guard drops, as a stuck thread would.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn hold_lock_for_test(&self) -> impl Drop + '_ {
        self.lock()
    }
}

impl Observer for Board {
    fn started(&self, index: usize, at: Duration, timeout: Duration) {
        if let Some(slot) = self.lock().slots.get_mut(index) {
            *slot = Slot::Running { at, timeout };
        }
    }

    fn finished(&self, index: usize, ran: &Ran) {
        let Some(template) = self.templates.get(index) else {
            return;
        };
        let result = (self.map)(index, ran);
        // Redacted before the lock is taken: a slow redaction must not make the watchdog's `try_lock`
        // fail. Only the counts and the result go in under the lock.
        let mut counts = RuleCounts::default();
        let kept = match self.redactor.redact_check(result, &mut counts) {
            Ok(redacted) => (*redacted).clone(),
            // The result no longer read as a result. Keep none of its text.
            Err(_) => unfinished_result(template),
        };
        let mut inner = self.lock();
        inner.counts.merge(&counts);
        if let Some(slot) = inner.slots.get_mut(index) {
            *slot = Slot::Done(Box::new(kept));
        }
    }
}
