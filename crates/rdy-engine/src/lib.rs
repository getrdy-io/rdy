//! The rdy check engine.
//!
//! It runs checks, applies timeouts and renders reports. So far it has the check contract, the
//! scheduler and the mapping from what a check returns to a report entry.
//!
//! - [`check`]: the `Check` trait, `CheckInfo`, needs, `Finding` and `CheckError`.
//! - [`outcome`]: [`outcome::map_outcome`] turns a check's outcome into a `CheckResult`.
//! - `sched` (feature `runtime`, on by default): runs checks with a concurrency limit, a timeout each
//!   and panic isolation.
//!
//! The probe facade and the renderers arrive in later M1 tickets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod check;
pub mod outcome;
#[cfg(feature = "runtime")]
pub mod sched;
