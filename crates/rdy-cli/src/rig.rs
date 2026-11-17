//! The watchdog of one process and its write state (M1-176, 02 "Watchdog").
//!
//! The binary starts a [`Rig`] in [`crate::entry`], before the runtime, and hands it to
//! [`crate::run_watched`]. [`crate::run`], the entry point for tests, starts its own and disarms it when
//! the run returns, so a test process never carries a watchdog that fires later and ends it.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdy_engine::watchdog::{Watchdog, WatchdogConfig, WriteState};

use crate::redaction;

/// A started watchdog and the state that decides who writes the report.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Rig {
    pub(crate) origin: Instant,
    pub(crate) deadline: Duration,
    pub(crate) state: Arc<WriteState>,
    pub(crate) watchdog: Arc<Watchdog>,
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
        })
    }

    /// Ends the watchdog without it acting. The binary never calls this on a run: the backstop after
    /// the report is written must stay. Commands that wait for a person (a prompt) call it, and so does
    /// [`crate::run`] when it returns.
    pub fn disarm(&self) {
        self.watchdog.disarm();
    }
}
