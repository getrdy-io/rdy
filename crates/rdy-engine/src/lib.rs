//! The rdy check engine.
//!
//! It runs checks, applies timeouts and renders reports. So far it has the check contract and the
//! mapping from what a check returns to a report entry.
//!
//! - [`check`]: the `Check` trait, `CheckInfo`, needs, `Finding` and `CheckError`.
//! - [`outcome`]: [`outcome::map_outcome`] turns a check's outcome into a `CheckResult`.
//! - [`family`]: the `Family` trait and the `Registry` of the checks in this build.
//! - [`plan`]: [`family::Registry::plan`] decides, with no I/O, which spec entries run and which are
//!   skipped, and why.
//!
//! The scheduler, the probe facade and the renderers arrive in later M1 tickets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod check;
pub mod family;
pub mod outcome;
pub mod plan;
