//! Test hooks for the in-process entry point (ADR 0011 decision 4).
//!
//! A test steers a run through the fields of [`RunHooks`], never through an argv flag or an environment
//! variable, so the shipped binary cannot be steered the same way. The binary passes
//! [`RunHooks::default`] and nothing else.
//!
//! The fields so far are the ones `rdy run` reads (M1-057): the wall clock of the run record and of
//! the report folder name, the run id, the run deadline and the check families. None of them reaches
//! the spec loader, so a pinned clock cannot defeat `metadata.expires`, and none touches the privilege
//! gate, the redactor or the output folder rules. The watchdog action arrives with the watchdog wiring. The privilege ids
//! need no field: the privilege snapshot reads them through the backend, so a replay backend that
//! records `/proc/self/status` supplies them (02, "Privilege and needs").

use std::time::{Duration, SystemTime};

use rdy_engine::family::{Registry, RegistryError};

/// Builds the check families of a run. See [`RunHooks::families`].
pub type FamiliesFn = fn() -> Result<Registry, RegistryError>;

/// What a test may pin for one in-process run. See the module text.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RunHooks {
    /// The wall clock of the run: `run.started_at`, `run.finished_at` and the time in the report
    /// folder name. With it set the clock does not move, so a golden report holds one time. `None`
    /// reads the real clock.
    pub clock: Option<SystemTime>,
    /// The run id (`run.id`). `None` makes a random UUID v4.
    pub run_id: Option<String>,
    /// The run deadline. `None` is five minutes.
    pub deadline: Option<Duration>,
    /// The check families of the run. `None` is the families of this build ([`crate::registry`]). A
    /// test gives its own, to run a check that declares a secret variable or counts that it ran. It
    /// changes nothing about the privilege gate, which runs on the machine's snapshot.
    pub families: Option<FamiliesFn>,
}
