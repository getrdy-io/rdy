//! Test hooks for the in-process entry point (ADR 0011 decision 4).
//!
//! A test steers a run through the fields of [`RunHooks`], never through an argv flag or an environment
//! variable, so the shipped binary cannot be steered the same way. The binary passes
//! [`RunHooks::default`] and nothing else.
//!
//! The struct has no field yet. Each field arrives with the ticket that reads it: the run clock, the
//! run id and the deadline with `rdy run` (M1-057), the watchdog action with the watchdog wiring
//! (M1-043). The privilege ids need no field: the privilege snapshot reads them through the backend,
//! so a replay backend that records `/proc/self/status` supplies them (02, "Privilege and needs").

/// What a test may pin for one in-process run. See the module text.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RunHooks {}
