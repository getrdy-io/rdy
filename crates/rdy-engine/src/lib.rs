//! The rdy check engine.
//!
//! It runs checks, applies timeouts and renders reports. So far it has the check contract, the
//! scheduler and the mapping from what a check returns to a report entry.
//!
//! - [`check`]: the `Check` trait, `CheckInfo` with its `CheckMeta`, needs, `Finding` and `CheckError`.
//! - [`outcome`]: [`outcome::map_outcome`] turns a check's outcome into a `CheckResult`.
//! - [`units`]: version compare, byte sizes, the nominal band and the severity cap that checks share.
//! - [`text`]: [`text::escape_untrusted`], the one escaper for text from a spec, a file or a server.
//! - [`fixtext`]: the audit that keeps commands and sysctl names in fix text on two reviewed lists.
//! - [`family`]: the `Family` trait and the `Registry` of the checks in this build.
//! - [`plan`]: [`family::Registry::plan`] decides, with no I/O, which spec entries run and which are
//!   skipped, and why.
//! - `sched` (feature `runtime`, on by default): runs checks with a concurrency limit, a timeout each
//!   and panic isolation.
//! - `blocking` (feature `runtime`): runs blocking work off the async workers.
//! - `output` (feature `runtime`): `output::OutputDir`, the one new folder that reports are written
//!   to, with safe names, no symlinks and private modes (ADR 0016).
//! - `exec`: the command table and the command policy, which need no runtime, and (feature `runtime`)
//!   the runner that starts a command in its own process group and kills the group on timeout, on
//!   drop and at exit. `exec::table::run` is the only public way to run a command.
//!
//! - [`redact`]: the redactor. [`redact::Redactor::redact_report`] redacts and then caps every string of a
//!   report and returns a [`redact::RedactedReport`], the only type the writers and renderers accept.
//!
//! The probe facade and the renderers arrive in later M1 tickets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "runtime")]
pub mod blocking;
pub mod check;
pub mod exec;
pub mod family;
pub mod fixtext;
pub mod outcome;
#[cfg(feature = "runtime")]
pub mod output;
pub mod plan;
pub mod redact;
#[cfg(feature = "runtime")]
pub mod sched;
pub mod text;
pub mod units;
