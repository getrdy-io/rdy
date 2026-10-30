//! The enumerated values of the result format (01 section 5).
//!
//! Almost every one is open: the schema lists the values it knows and accepts any snake_case code
//! besides. A reader keeps an unknown value as `Unknown(text)` and applies the rule in the doc comment of
//! that type. Only [`Verdict`] is closed, because a new verdict needs `rdy/v2`.

use serde::{Deserialize, Serialize};

use super::open::open_enum;

open_enum! {
    /// How much a check matters, as the spec wrote it.
    ///
    /// An unknown severity counts as `block` everywhere.
    Severity {
        /// Required. A failure makes the run NOT READY.
        Block => "block",
        /// Optional. A failure gives READY with warnings.
        Warn => "warn",
    }
}

impl From<crate::spec::Severity> for Severity {
    fn from(value: crate::spec::Severity) -> Self {
        match value {
            crate::spec::Severity::Warn => Self::Warn,
            _ => Self::Block,
        }
    }
}

open_enum! {
    /// What happened to a check, after its severity was applied.
    ///
    /// An unknown status counts as not run.
    Status {
        /// The requirement is met.
        Pass => "pass",
        /// The requirement is not met and the check is optional.
        Warn => "warn",
        /// The requirement is not met and the check is required.
        Block => "block",
        /// The check did not run. [`SkipKind`] says why.
        Skipped => "skipped",
        /// The check ran out of time.
        Timeout => "timeout",
        /// The check failed to run, or panicked.
        Error => "error",
    }
}

open_enum! {
    /// Why a check did not run. Present when the status is `skipped`.
    ///
    /// Every kind except `not_applicable` counts as not run, and so does an unknown kind.
    SkipKind {
        /// A need the check cannot do without was not met, such as root or a cluster.
        MissingNeed => "missing_need",
        /// This build of rdy has no checks of that family.
        NotInBuild => "not_in_build",
        /// This rdy does not know the check id.
        UnknownCheck => "unknown_check",
        /// This rdy cannot read a field or value of the entry.
        UnsupportedSpec => "unsupported_spec",
        /// The check has no data source on this OS yet.
        NotYetOnOs => "not_yet_on_os",
        /// The spec's `os` list leaves this OS out. Only the spec can cause this (ADR 0013).
        NotApplicable => "not_applicable",
        /// The run reached its deadline before the check started.
        RunDeadline => "run_deadline",
        /// The run was interrupted.
        Cancelled => "cancelled",
    }
}

open_enum! {
    /// Why a check ended in `error`. Present when the status is `error`.
    ErrorKind {
        /// The check returned an error.
        CheckFailed => "check_failed",
        /// The check panicked.
        Panic => "panic",
    }
}

open_enum! {
    /// Whose fix text a result carries.
    FixSource {
        /// The vendor's text from the spec (wire text `spec`).
        // Not named `Spec`: a variant with that name makes rustc print full paths for
        // `rdy_spec::spec::Spec`, which breaks the compile-fail goldens of the `LoadedSpec` test.
        FromSpec => "spec",
        /// rdy's own text.
        Rdy => "rdy",
    }
}

open_enum! {
    /// The display group of a check, from the same rule as the verdict.
    ///
    /// Sort by it in this order: blocker, required_not_run, warning, passed, not_applicable. Do not
    /// recompute it.
    Bucket {
        /// `status: block`.
        Blocker => "blocker",
        /// A required check that did not run.
        RequiredNotRun => "required_not_run",
        /// `status: warn`, or an optional check that did not run.
        Warning => "warning",
        /// `status: pass`.
        Passed => "passed",
        /// `skip_kind: not_applicable`.
        NotApplicable => "not_applicable",
    }
}

impl Bucket {
    /// The sort key for display: blocker, required_not_run, warning, passed, not_applicable (01 section
    /// 5.2), then spec order. Sort with a stable sort so spec order is kept inside a bucket.
    ///
    /// An unknown bucket sorts with `required_not_run` (01 section 3.2): a reader cannot tell what it is,
    /// so it counts as not run and must not sink below the passed checks.
    #[must_use]
    pub fn order_key(&self) -> u8 {
        match self {
            Self::Blocker => 0,
            Self::RequiredNotRun | Self::Unknown(_) => 1,
            Self::Warning => 2,
            Self::Passed => 3,
            Self::NotApplicable => 4,
        }
    }
}

open_enum! {
    /// Something rdy needs for a check, such as root or a cluster.
    Need {
        /// Effective uid 0, or an elevated token on Windows.
        Root => "root",
        /// A reachable Kubernetes cluster.
        KubeContext => "kube_context",
        /// Sockets are allowed (not `--no-network`).
        Network => "network",
        /// A program on the search path. The program is the `name`.
        Command => "command",
        /// Cloud credentials. The provider is the `name`.
        CloudCredentials => "cloud_credentials",
    }
}

open_enum! {
    /// The state of the spec signature in a report.
    ///
    /// An unknown state counts as not verified. `invalid` appears in the `rdy verify` object, never in a
    /// written report.
    SignatureState {
        /// Signed by a trusted key.
        Verified => "verified",
        /// No signature. The run needed `--allow-unsigned`.
        Unsigned => "unsigned",
        /// The signature did not check out.
        Invalid => "invalid",
    }
}

open_enum! {
    /// Where the trusted key came from.
    ///
    /// An unknown source is treated like `flag`.
    TrustSource {
        /// The system trust store.
        System => "system",
        /// The user trust store.
        User => "user",
        /// A key given with `--key` for one run.
        Flag => "flag",
    }
}

open_enum! {
    /// The OS family of the host.
    HostOsFamily {
        /// Linux.
        Linux => "linux",
        /// macOS.
        Macos => "macos",
        /// Windows.
        Windows => "windows",
    }
}

open_enum! {
    /// Whether the host is a virtual machine.
    Virtualization {
        /// Bare metal (wire text `none`).
        NotVirtualized => "none",
        /// A virtual machine.
        Vm => "vm",
        /// rdy could not tell (wire text `unknown`).
        Undetected => "unknown",
    }
}

open_enum! {
    /// What a recorded side effect was.
    ActionKind {
        /// A command was run.
        Exec => "exec",
        /// A file was read.
        Read => "read",
        /// A directory was listed.
        ReadDir => "read_dir",
        /// A path was inspected.
        Stat => "stat",
        /// An environment variable name was read.
        Env => "env",
        /// A host name was resolved.
        Lookup => "lookup",
        /// A TCP connection was made.
        Connect => "connect",
        /// A TLS handshake was made.
        Tls => "tls",
        /// An HTTP request was sent.
        Http => "http",
        /// A DNS query was sent.
        Dns => "dns",
        /// A Kubernetes API request was sent.
        Kube => "kube",
        /// A native OS call was made.
        Native => "native",
        /// Many reads were folded into one entry.
        Coalesced => "coalesced",
    }
}

open_enum! {
    /// How a recorded side effect ended.
    ActionOutcome {
        /// It worked.
        Ok => "ok",
        /// rdy's own policy refused it.
        Denied => "denied",
        /// The OS or the peer said no.
        Failed => "failed",
        /// It ran out of time.
        Timeout => "timeout",
    }
}

open_enum! {
    /// Which compiled redaction rule set ran.
    RedactionRuleset {
        /// The report rule set.
        Report => "report",
        /// The bundle rule set.
        Bundle => "bundle",
    }
}

open_enum! {
    /// Why the verdict is not explained by an observed block or warning.
    VerdictReason {
        /// NOT READY with no block: a required check did not run.
        RequiredCheckNotRun => "required_check_not_run",
        /// READY with warnings because no check reached pass, warn or block.
        NothingVerified => "nothing_verified",
    }
}

/// The overall answer of a run. Closed in v1: a new value needs `rdy/v2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Verdict {
    /// Everything the spec asks for passed. Exit 0.
    Ready,
    /// Warnings only, or optional checks did not run, or nothing was verified. Exit 1.
    ReadyWithWarnings,
    /// A block, or a required check did not run. Exit 2.
    NotReady,
}

impl Verdict {
    /// The wire text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ReadyWithWarnings => "ready_with_warnings",
            Self::NotReady => "not_ready",
        }
    }

    /// The process exit code of this verdict. A pure mapping: 0, 1 or 2.
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        match self {
            Self::Ready => ExitCode::Ready,
            Self::ReadyWithWarnings => ExitCode::Warnings,
            Self::NotReady => ExitCode::Blockers,
        }
    }
}

/// The exit codes of the `rdy` process (01 section 5.3, 07 section 5).
///
/// 0, 1 and 2 come from the verdict. 64 and 70 mean there is no verdict: the input must change, or rdy
/// could not deliver its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExitCode {
    /// 0: ready, or the command did its job.
    Ready,
    /// 1: ready with warnings.
    Warnings,
    /// 2: blockers, or a required check was not run.
    Blockers,
    /// 64: usage error. The input must change.
    Usage,
    /// 70: internal error. rdy could not deliver its result.
    Internal,
}

impl ExitCode {
    /// The number the process exits with.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::Warnings => 1,
            Self::Blockers => 2,
            Self::Usage => 64,
            Self::Internal => 70,
        }
    }
}

impl From<ExitCode> for u8 {
    fn from(value: ExitCode) -> Self {
        value.code()
    }
}
