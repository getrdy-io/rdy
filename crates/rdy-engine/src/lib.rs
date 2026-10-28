//! The rdy check engine.
//!
//! It runs checks, applies timeouts and renders reports. So far it has the check contract, the
//! scheduler and the mapping from what a check returns to a report entry.
//!
//! - [`check`]: the `Check` trait, `CheckInfo`, needs, `Finding` and `CheckError`.
//! - [`outcome`]: [`outcome::map_outcome`] turns a check's outcome into a `CheckResult`.
//! - [`units`]: version compare, byte sizes, the nominal band and the severity cap that checks share.
//! - [`family`]: the `Family` trait and the `Registry` of the checks in this build.
//! - [`plan`]: [`family::Registry::plan`] decides, with no I/O, which spec entries run and which are
//!   skipped, and why.
//! - `sched` (feature `runtime`, on by default): runs checks with a concurrency limit, a timeout each
//!   and panic isolation.
//! - `blocking` (feature `runtime`): runs blocking work off the async workers.
//! - `exec` (feature `runtime`): runs a command in its own process group and kills the group on
//!   timeout, on drop and at exit.
//!
//! The probe facade and the renderers arrive in later M1 tickets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "runtime")]
pub mod blocking;
pub mod check;
#[cfg(feature = "runtime")]
pub mod exec;
pub mod family;
pub mod outcome;
pub mod plan;
pub mod redact;
#[cfg(feature = "runtime")]
pub mod sched;
pub mod units;
