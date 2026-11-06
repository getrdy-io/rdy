//! The watchdog of one process and its write state (M1-176, 02 "Watchdog").
//!
//! The binary starts a [`Rig`] in [`crate::entry`], before the runtime, and hands it to
//! [`crate::run_watched`]. [`crate::run`], the entry point for tests, starts its own and disarms it when
//! the run returns, so a test process never carries a watchdog that fires later and ends it.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdy_engine::watchdog::{Watchdog, WatchdogConfig, WriteState};

use crate::interrupt::{self, Interrupt};
use crate::redaction;

/// A started watchdog and the state that decides who writes the report.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Rig {
    pub(crate) origin: Instant,
    pub(crate) deadline: Duration,
    pub(crate) state: Arc<WriteState>,
    pub(crate) watchdog: Arc<Watchdog>,
    pub(crate) interrupt: Arc<Interrupt>,
}

impl Rig {
    /// Starts the watchdog thread. It fires `deadline` plus the grace after `origin`, the same origin
    /// the scheduler counts from.
    ///
    /// # Errors
    ///
    /// The OS could not start a thread, or could not supply the redaction key. A run with no watchdog
    /// is not allowed, so the caller ends the run with exit 70.
    pub fn start(origin: Instant, deadline: Duration) -> io::Result<Self> {
        let redactor = redaction::init()
            .map_err(|_| io::Error::other("no redaction key"))?
            .clone();
        let state = Arc::new(WriteState::new());
        let watchdog = Watchdog::start(WatchdogConfig::new(
            origin,
            deadline,
            Arc::clone(&state),
            redactor,
        ))?;
        Ok(Self {
            origin,
            deadline,
            state,
            watchdog: Arc::new(watchdog),
            interrupt: Arc::new(Interrupt::default()),
        })
    }

    /// Starts the thread that catches SIGINT and SIGTERM (Ctrl-C and Ctrl-Break on Windows). The first
    /// one aborts the process with exit 70 and no report (M1-058, [`crate::interrupt`]). The binary calls
    /// it once, before the runtime; `json` says whether the error also goes to stdout as an
    /// `ErrorOutput`. A test process does not call it, so it keeps its own signal handling.
    ///
    /// # Errors
    ///
    /// The thread or the handlers could not be set up. The caller ends the run with exit 70.
    pub fn watch_signals(&self, json: bool) -> io::Result<()> {
        interrupt::watch(Arc::clone(&self.interrupt), Arc::clone(&self.state), json)
    }

    /// For the main thread, once it has the code to exit with: takes the exit. After this a signal is
    /// ignored. If a signal got there first, waits for it to end the process with 70, so that is the
    /// only code the shell sees. False if that wait ran out.
    pub fn claim_exit(&self) -> bool {
        self.interrupt.claim_exit()
    }

    /// Ends the watchdog without it acting. The binary never calls this on a run: the backstop after
    /// the report is written must stay. Commands that wait for a person (a prompt) call it, and so does
    /// [`crate::run`] when it returns.
    pub fn disarm(&self) {
        self.watchdog.disarm();
    }
}
