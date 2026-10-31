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
//! - [`probe`]: the facade a check reads the machine through, with the action log and the read
//!   policy. `live_backend` (feature `runtime`) reads real files; the replay backend is in `testing`
//!   behind the `testing` feature.
//! - `engine` (feature `runtime`): `engine::Engine` plans a verified spec, probes the needs, runs the checks
//!   and returns their redacted results (M1-057).
//! - `sched` (feature `runtime`, on by default): runs checks with a concurrency limit, a timeout each
//!   and panic isolation.
//! - `blocking` (feature `runtime`): runs blocking work off the async workers.
//! - `output` (feature `runtime`): `output::OutputDir`, the one new folder that reports are written
//!   to, with safe names, no symlinks and private modes (ADR 0016).
//! - `exec`: the command table and the command policy, which need no runtime, and (feature `runtime`)
//!   the runner that starts a command in its own process group and kills the group on timeout, on
//!   drop and at exit. `exec::table::run` is the only public way to run a command.
//! - [`privilege`]: the privilege snapshot, the refusal of a setuid or capability-carrying binary
//!   (INV-10) and the capability probes.
//! - [`redact`]: the redactor. [`redact::Redactor::redact_report`] redacts and then caps every string of a
//!   report and returns a [`redact::RedactedReport`], the only type the writers and renderers accept.
//! - [`summary`]: the summary line and the last line of a run (01 section 5.3, 07 section 2.4).
//!
//! - `watchdog` (feature `runtime`): the run watchdog, a plain thread that writes an incomplete report
//!   and exits 70 when a run hangs, and the run board that holds its snapshot.
//! - [`report`]: [`report::write_json`] writes the one JSON text of a report (HTML safe, in schema order,
//!   cut to the schema's caps and to 2 MiB), and [`report::read_report_from`] refuses a document over the cap
//!   before it parses. With the `html` feature (on by default), `report::render_html` turns a
//!   [`redact::RedactedReport`] into one self-contained HTML page with askama templates.
//!
//! The terminal renderer arrives in a later M1 ticket.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "runtime")]
pub mod blocking;
pub mod check;
#[cfg(feature = "runtime")]
pub mod engine;
pub mod exec;
pub mod family;
pub mod fixtext;
pub mod outcome;
#[cfg(feature = "runtime")]
pub mod output;
pub mod plan;
pub mod privilege;
pub mod probe;
pub mod redact;
pub mod report;
#[cfg(feature = "runtime")]
pub mod sched;
pub mod summary;
#[cfg(feature = "testing")]
pub mod testing;
pub mod text;
pub mod units;
#[cfg(feature = "runtime")]
pub mod watchdog;

/// The backend that reads real files. Only the engine and the CLI may call it; check crates reach the
/// machine through their `Probe` (ADR 0014, SEC-17).
#[cfg(feature = "runtime")]
pub use probe::live_backend;
