//! The check contract: what a check is, what it needs, and what it hands back.
//!
//! A check is a struct built from its typed spec parameters, with one `static` [`CheckInfo`]. The
//! scheduler (M1-034) calls [`Check::run`] with a [`CheckContext`] and gets a [`CheckOutcome`]. The
//! check never sets a status, a severity or a skip kind. The engine maps the outcome to those
//! (ADR 0008 decision 2, and M1-033).
//!
//! Two rules from ADR 0013 live in the types here:
//!
//! - Nothing in this module can produce `not_applicable`. [`CheckError::skip_kind`] and
//!   [`Support::skip_kind`] never return it. Only the spec's `os` list can cause it.
//! - A requirement met by absence is a pass built through [`Finding::pass_by_absence`], so the call
//!   sites can be listed and reviewed.
//!
//! The probe facade (ADR 0014) and the run deadline are not here yet. [`CheckContext`] gains
//! `probe()` and `remaining()` with the tickets that build them.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use rdy_spec::result::SkipKind;

pub use rdy_spec::spec::OsFamily as Os;

#[cfg(test)]
mod tests;

/// A boxed, sendable future. It is what [`Check::run`] returns, so `dyn Check` stays object safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a check returns: a [`Finding`] when it ran, or a [`CheckError`] when it could not.
pub type CheckOutcome = Result<Finding, CheckError>;

/// The OS rdy was built for.
///
/// Unix targets other than macOS count as Linux. CI covers Linux, macOS and Windows only.
#[must_use]
pub fn current_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::Macos
    } else if cfg!(windows) {
        Os::Windows
    } else {
        Os::Linux
    }
}

/// Something a check needs, such as root or a reachable cluster.
///
/// A need is declared in [`CheckInfo::needs`] (hard: the check does not run without it) or in
/// [`CheckInfo::wants`] (soft: the check runs partial). `rdy_spec::result::Need` is the wire form.
/// This type carries the name that the wire form keeps in a separate field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Need {
    /// Effective uid 0, or an elevated token on Windows.
    Root,
    /// A reachable Kubernetes cluster.
    KubeContext,
    /// Sockets are allowed (not `--no-network`).
    Network,
    /// A program on the fixed search path. The program name is the payload.
    Command(&'static str),
}

impl Need {
    /// The wire value of this need.
    #[must_use]
    pub fn wire(&self) -> rdy_spec::result::Need {
        match self {
            Self::Root => rdy_spec::result::Need::Root,
            Self::KubeContext => rdy_spec::result::Need::KubeContext,
            Self::Network => rdy_spec::result::Need::Network,
            Self::Command(_) => rdy_spec::result::Need::Command,
        }
    }

    /// The wire `name`: the program for `command`, nothing for the others.
    #[must_use]
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Self::Command(program) => Some(program),
            Self::Root | Self::KubeContext | Self::Network => None,
        }
    }
}

impl std::fmt::Display for Need {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{} {name}", self.wire()),
            None => f.write_str(self.wire().as_str()),
        }
    }
}

/// A soft need. When it is missing the check runs and reports a partial result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    /// What would complete the result.
    pub need: Need,
    /// `true` when the want can only add detail and never change the level (ADR 0013 decision 4).
    pub evidence_only: bool,
}

/// One program a check may run, and the limits on it. The facade enforces these (M1-038).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// The program name, resolved on the fixed search path.
    pub program: &'static str,
    /// Extra absolute directories to search after the fixed path.
    pub extra_dirs: &'static [&'static str],
    /// The most stdout kept, in bytes.
    pub max_stdout: usize,
    /// Extra environment variable names the child may see.
    pub env: &'static [&'static str],
}

/// A class of network peer a check may talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerClass {
    /// The hosts the check's own spec entry names.
    SpecHosts,
    /// The operator's configured proxy.
    Proxy,
    /// The system resolver.
    SystemResolver,
    /// The Kubernetes API server of the chosen context.
    KubeApi,
}

/// How well a check works on one OS.
///
/// There is no "not applicable" here (ADR 0013). A check with no data source on an OS is
/// [`Support::NotYet`], and it counts as not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Works fully.
    Full,
    /// Works with less evidence. The text says what is missing. Every result gets `partial` set.
    Partial(&'static str),
    /// No data source on this OS yet.
    NotYet,
}

impl Support {
    /// The skip kind when the check cannot run: [`SkipKind::NotYetOnOs`] for [`Support::NotYet`].
    ///
    /// It never returns [`SkipKind::NotApplicable`].
    #[must_use]
    pub fn skip_kind(&self) -> Option<SkipKind> {
        match self {
            Self::NotYet => Some(SkipKind::NotYetOnOs),
            Self::Full | Self::Partial(_) => None,
        }
    }

    /// What is missing on a [`Support::Partial`] OS.
    #[must_use]
    pub fn partial_note(&self) -> Option<&'static str> {
        match self {
            Self::Partial(note) => Some(note),
            Self::Full | Self::NotYet => None,
        }
    }
}

/// [`Support`] for each OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsSupport {
    /// Linux.
    pub linux: Support,
    /// macOS.
    pub macos: Support,
    /// Windows.
    pub windows: Support,
}

impl OsSupport {
    /// The support level on `os`.
    ///
    /// An OS this version does not know counts as [`Support::NotYet`], which counts as not run.
    #[must_use]
    pub fn on(&self, os: Os) -> Support {
        match os {
            Os::Linux => self.linux,
            Os::Macos => self.macos,
            Os::Windows => self.windows,
            _ => Support::NotYet,
        }
    }
}

/// The static facts about a check.
///
/// Every check has exactly one, as a `static`. The planner reads it without running anything, the
/// facade will enforce the manifest fields (`reads`, `env`, `commands`, `peers`), and the action log
/// proves them.
#[derive(Debug)]
pub struct CheckInfo {
    /// The check id, such as `host.memory`.
    pub id: &'static str,
    /// The family prefix, such as `host`.
    pub family: &'static str,
    /// One line for humans.
    pub summary: &'static str,
    /// Hard needs. A missing one means `skipped` with `skip_kind: missing_need`.
    pub needs: &'static [Need],
    /// Soft needs. A missing one means a partial result.
    pub wants: &'static [Want],
    /// The default timeout. The engine falls back to 10 s and caps at 60 s.
    pub default_timeout: Option<Duration>,
    /// Support per OS.
    pub os: OsSupport,
    /// Absolute path prefixes the check may read.
    pub reads: &'static [&'static str],
    /// Environment variable names the check may read.
    pub env: &'static [&'static str],
    /// Programs the check may run.
    pub commands: &'static [CommandSpec],
    /// Network peer classes the check may reach.
    pub peers: &'static [PeerClass],
}

/// How a finding sits against the requirement, before severity.
///
/// The engine turns `Warn` and `Fail` into `warn` or `block` using the spec's severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The requirement is met.
    Pass,
    /// Not met, but only just or only in a minor way. The engine caps it at a warning.
    Warn,
    /// Not met.
    Fail,
}

/// A result that rests on less evidence than the check wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Partial {
    /// The needs that were missing.
    pub missing: Vec<Need>,
    /// Grants the check lacked, such as an RBAC verb.
    pub missing_grants: Vec<String>,
    /// What was not verified, in a sentence.
    pub note: String,
}

impl Partial {
    /// A partial result with no missing grants.
    #[must_use]
    pub fn new(missing: Vec<Need>, note: impl Into<String>) -> Self {
        Self {
            missing,
            missing_grants: Vec::new(),
            note: note.into(),
        }
    }

    /// Adds the grants the check lacked.
    #[must_use]
    pub fn with_missing_grants(mut self, grants: Vec<String>) -> Self {
        self.missing_grants = grants;
        self
    }
}

/// What a check found when it ran.
///
/// Build one with [`Finding::pass`], [`Finding::warn`] or [`Finding::fail`] and add detail with the
/// `with_*` methods. The fields are public to read, and the type is `#[non_exhaustive]` so a new field
/// does not break a check.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Finding {
    /// How the result sits against the requirement.
    pub level: Level,
    /// One sentence. The engine redacts and caps it.
    pub message: String,
    /// What the check measured, as JSON.
    pub observed: serde_json::Value,
    /// The effective threshold the check used, as JSON.
    pub expected: serde_json::Value,
    /// rdy's own advice. A spec `fix` replaces it on `warn` and `block`.
    pub fix: Option<String>,
    /// Set when the result rests on less evidence than wanted.
    pub partial: Option<Partial>,
    /// Extra lines for the report.
    pub notes: Vec<String>,
}

impl Finding {
    /// A finding at `level` with no detail.
    #[must_use]
    pub fn new(level: Level, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            observed: serde_json::Value::Null,
            expected: serde_json::Value::Null,
            fix: None,
            partial: None,
            notes: Vec::new(),
        }
    }

    /// The requirement is met.
    #[must_use]
    pub fn pass(message: impl Into<String>) -> Self {
        Self::new(Level::Pass, message)
    }

    /// The requirement is not met, in a minor way.
    #[must_use]
    pub fn warn(message: impl Into<String>) -> Self {
        Self::new(Level::Warn, message)
    }

    /// The requirement is not met.
    #[must_use]
    pub fn fail(message: impl Into<String>) -> Self {
        Self::new(Level::Fail, message)
    }

    /// A requirement met because the thing it limits does not exist here.
    ///
    /// An example is a spec that allows SELinux to be `disabled`, run on a host with no SELinux. This is
    /// the only way to report such a case. It is a pass, never `not_applicable` (ADR 0013 decision 2),
    /// and the call sites are listed in review. `note` says why absence is enough.
    #[must_use]
    pub fn pass_by_absence(note: impl Into<String>) -> Self {
        let note = note.into();
        let mut finding = Self::pass(note.clone());
        finding.notes.push(note);
        finding
    }

    /// Sets what the check measured.
    #[must_use]
    pub fn with_observed(mut self, observed: serde_json::Value) -> Self {
        self.observed = observed;
        self
    }

    /// Sets the effective threshold.
    #[must_use]
    pub fn with_expected(mut self, expected: serde_json::Value) -> Self {
        self.expected = expected;
        self
    }

    /// Sets rdy's own advice.
    #[must_use]
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    /// Marks the result as resting on less evidence than wanted.
    #[must_use]
    pub fn with_partial(mut self, partial: Partial) -> Self {
        self.partial = Some(partial);
        self
    }

    /// Adds a line to the notes.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

/// Why a check could not produce a [`Finding`].
///
/// Probe errors from the facade join this enum with the facade ticket (M1-040).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CheckError {
    /// A hard need was not met. The result is `skipped` with `skip_kind: missing_need`.
    #[error("missing need: {0}")]
    MissingNeed(Need),
    /// The check has no data source on this OS. The result is `skipped` with `skip_kind:
    /// not_yet_on_os`. The text names what is missing.
    #[error("not supported here: {0}")]
    Unsupported(&'static str),
    /// The check itself failed. The result is `error` with `error_kind: check_failed`.
    #[error("{message}")]
    Failed {
        /// What went wrong. The engine redacts and caps it.
        message: String,
        /// What the operator can do about it.
        hint: String,
    },
}

impl CheckError {
    /// The skip kind this error maps to, or `None` when the check has status `error`.
    ///
    /// It never returns [`SkipKind::NotApplicable`] (ADR 0013 decision 2).
    #[must_use]
    pub fn skip_kind(&self) -> Option<SkipKind> {
        match self {
            Self::MissingNeed(_) => Some(SkipKind::MissingNeed),
            Self::Unsupported(_) => Some(SkipKind::NotYetOnOs),
            Self::Failed { .. } => None,
        }
    }
}

/// A check.
///
/// The scheduler spawns `async move { check.run(&ctx).await }`, so the task owns its `Arc`s and a
/// panic stays inside it. A check does no blocking work itself.
pub trait Check: Send + Sync + 'static {
    /// The static facts about this check.
    fn info(&self) -> &'static CheckInfo;

    /// Runs the check.
    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome>;
}

/// What the engine hands a check for one run.
///
/// The fields are private. The engine builds one per check.
#[derive(Debug, Clone)]
pub struct CheckContext {
    key: String,
    os: Os,
    available: HashSet<Need>,
}

impl CheckContext {
    /// A context for the check with `key`, on `os`, where the `available` needs are met.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the scheduler (M1-034) is the first caller")
    )]
    pub(crate) fn new(
        key: impl Into<String>,
        os: Os,
        available: impl IntoIterator<Item = Need>,
    ) -> Self {
        Self {
            key: key.into(),
            os,
            available: available.into_iter().collect(),
        }
    }

    /// The result key: the check id, or `id/name` when the entry has a name.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The OS this run is on.
    #[must_use]
    pub fn os(&self) -> Os {
        self.os
    }

    /// Whether `need` is met on this host.
    #[must_use]
    pub fn has(&self, need: &Need) -> bool {
        self.available.contains(need)
    }
}
