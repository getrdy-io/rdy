//! The `rdy/v1` result format as Rust types, and the verdict rule.
//!
//! These are the wire types of docs/plan/01-spec-format.md section 5. They serialize to the JSON
//! described by `schema/result.v1.schema.json`. ADR 0012 puts them here so Rdy Cloud reads exactly what
//! `rdy` writes.
//!
//! - The enums: the status, severity, skip kind and other values. All are open except
//!   [`Verdict`].
//! - [`verdict()`], [`classify`], [`Summary::from_checks`] and [`apply_partial_rule`]: the one
//!   implementation of the verdict rule (ADR 0013).
//! - [`Verdict::exit_code`] and [`ExitCode`]: the process exit codes.
//! - [`VersionInfo`]: the object `rdy version --json` prints.
//!
//! The error object (`ErrorOutput`), the `rdy verify` object and the lint report are not here yet. The
//! error types, `verify` and `spec lint` tickets add them. Until then the schema for those three comes
//! from a fragment (see [`crate::schema`]).

mod codes;
mod model;
pub(crate) mod open;
mod verdict;
#[cfg(test)]
mod verdict_tests;
mod version_info;

pub use codes::{
    ActionKind, ActionOutcome, Bucket, ErrorKind, ExitCode, FixSource, HostOsFamily, Need,
    RedactionRuleset, Severity, SignatureState, SkipKind, Status, TrustSource, Verdict,
    VerdictReason, Virtualization,
};
pub use model::{
    Action, Capability, CheckResult, Host, HostOs, Identity, KubeIdentity, NeedState, Partial,
    Producer, Proxy, REPORT_KIND, Redaction, Report, Run, RunOptions, Signature, SpecRef, Summary,
};
pub use verdict::{Judgement, apply_partial_rule, classify, is_not_run, is_required, verdict};
pub use version_info::VersionInfo;
