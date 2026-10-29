//! The probe facade: the handles a check uses to touch the machine (ADR 0014, SEC-17).
//!
//! A check gets one [`Probe`] in its [`CheckContext`](crate::check::CheckContext). Everything it
//! reads, lists, stats or runs goes through that handle, and every call writes one entry to the action
//! log. The handle is bound to its check:
//!
//! - **The log names the check.** Each entry carries the check's result key.
//! - **It dies with the check.** The scheduler ends the handle when the check ends, however it ends.
//!   A call made later, for example from a task the check left running, is refused with rule
//!   [`RULE_CHECK_FINISHED`] and logged as `denied`.
//! - **A context built without a hub is closed.** Every call is refused with [`RULE_NO_PROBE`]. There
//!   is nothing to log it in.
//!
//! Policy and the log sit above [`Backend`], which does the raw I/O and nothing else. A call goes in
//! this order: the handle is checked, the policy (`policy` module) is applied, the backend runs, the
//! entry is closed. A refused call never reaches the backend.
//!
//! **What is here, and what is not.** This ticket (M1-040) builds the handle, the log and the read
//! denylist, with `read`, `read_dir`, `stat` and `exec`. Still to come, each in its own ticket:
//!
//! - the real path check, the `reads` prefixes, the size caps, `read_tail` and `env`: M1-045;
//! - the command policy (fixed search path, refused programs, environment): M1-039. [`Probe::exec`]
//!   hands a [`Cmd`] to [`Backend::spawn`]. The live backend will implement `spawn` by calling
//!   `exec::policy::run` and mapping its error to [`ProbeError`];
//! - names, TCP, TLS, HTTP and native calls: the network and native tickets. They open their entries
//!   with the crate-private `Probe::begin`, the same way the methods here do;
//! - the live backend itself, which only these tickets can make safe to ship. Only the replay backend
//!   (feature `testing`) exists today, so nothing in a release build reaches the machine yet.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rdy_spec::result::{ActionKind, ActionOutcome};
use serde_json::{Map, Value};

use crate::check::BoxFuture;
use crate::redact::Redactor;

pub use log::{ActionLogOutput, MAX_ENTRIES};

use log::{ActionLog, Pending};

mod log;
mod policy;
#[cfg(any(test, feature = "testing"))]
pub(crate) mod replay;
#[cfg(test)]
mod tests;

/// The rule of a call made after its check ended.
pub const RULE_CHECK_FINISHED: &str = "check finished";

/// The rule of a call on a context that has no probe hub.
pub const RULE_NO_PROBE: &str = "no probe in this context";

/// Why a probe call did not give a value.
///
/// It is `Clone`, `PartialEq` and `Eq` because [`CheckError`](crate::check::CheckError) is. The
/// variants the network ticket adds (`Net`) must keep that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// rdy's own policy refused the call. `rule` is a fixed sentence, `what` names the target.
    #[error("refused by rdy policy ({rule}): {what}")]
    Denied {
        /// The rule that refused it.
        rule: &'static str,
        /// What was refused, such as a path. Redact it before it is shown.
        what: String,
    },
    /// The file, directory or program does not exist.
    #[error("not found")]
    NotFound,
    /// The OS refused: this user may not do that.
    #[error("permission denied")]
    PermissionDenied,
    /// The call ran out of time.
    #[error("timed out")]
    Timeout,
    /// A killed command was not reaped. It may be stuck in the kernel.
    #[error("the command did not exit after it was killed (pid {pid})")]
    Hung {
        /// The child's process id.
        pid: u32,
    },
    /// Any other I/O failure. The text is the OS message.
    #[error("{0}")]
    Io(String),
}

impl ProbeError {
    /// The error for an I/O failure, using the kinds checks care about.
    pub(crate) fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(error.to_string()),
        }
    }

    /// How the action log records this error.
    fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Denied { .. } => ActionOutcome::Denied,
            Self::Timeout | Self::Hung { .. } => ActionOutcome::Timeout,
            Self::NotFound | Self::PermissionDenied | Self::Io(_) => ActionOutcome::Failed,
        }
    }

    fn denied(rule: &'static str, what: impl Into<String>) -> Self {
        Self::Denied {
            rule,
            what: what.into(),
        }
    }
}

/// The bytes of a file, and whether the backend cut them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct FileBytes {
    /// The bytes. Raw: redact before they are shown.
    pub bytes: Vec<u8>,
    /// `true` when the start of the file was left out (`read_tail`, M1-045).
    pub truncated_head: bool,
    /// `true` when the end of the file was left out (the size cap, M1-045).
    pub truncated_tail: bool,
}

impl FileBytes {
    /// A whole file.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            truncated_head: false,
            truncated_tail: false,
        }
    }

    /// `true` when either end was cut.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated_head || self.truncated_tail
    }
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DirEntry {
    /// The file name, with invalid UTF-8 replaced.
    pub name: String,
    /// `true` for a directory.
    pub is_dir: bool,
}

impl DirEntry {
    /// An entry.
    #[must_use]
    pub fn new(name: impl Into<String>, is_dir: bool) -> Self {
        Self {
            name: name.into(),
            is_dir,
        }
    }
}

/// What `stat` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileMeta {
    /// `true` for a regular file.
    pub is_file: bool,
    /// `true` for a directory.
    pub is_dir: bool,
    /// Size in bytes.
    pub len: u64,
}

impl FileMeta {
    /// Metadata for a regular file of `len` bytes.
    #[must_use]
    pub fn file(len: u64) -> Self {
        Self {
            is_file: true,
            is_dir: false,
            len,
        }
    }

    /// Metadata for a directory.
    #[must_use]
    pub fn dir() -> Self {
        Self {
            is_file: false,
            is_dir: true,
            len: 0,
        }
    }
}

/// A command to run. The program is a constant, so spec text cannot name one (02 "Exec").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    /// The program name. The backend resolves it (M1-039).
    pub program: &'static str,
    /// The arguments after the program, passed as argv. No shell sees them.
    pub args: Vec<String>,
    /// The timeout. `None` lets the backend choose.
    pub timeout: Option<Duration>,
}

impl Cmd {
    /// A command with no arguments and the backend's timeout.
    #[must_use]
    pub fn new(program: &'static str) -> Self {
        Self {
            program,
            args: Vec::new(),
            timeout: None,
        }
    }

    /// Sets the arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }
}

/// What a command that ran left behind.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Output {
    /// The exit code, or `None` when a signal ended the process.
    pub exit: Option<i32>,
    /// The first bytes of stdout. Raw: redact before they are shown.
    pub stdout: Vec<u8>,
    /// `true` when stdout had more bytes than the cap.
    pub stdout_truncated: bool,
    /// The first bytes of stderr. Raw: redact before they are shown.
    pub stderr: Vec<u8>,
    /// `true` when stderr had more bytes than the cap.
    pub stderr_truncated: bool,
}

impl Output {
    /// A command that exited with `exit` and wrote `stdout`.
    #[must_use]
    pub fn new(exit: Option<i32>, stdout: Vec<u8>) -> Self {
        Self {
            exit,
            stdout,
            ..Self::default()
        }
    }
}

/// A finished command and the absolute path it ran from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Executed {
    /// The resolved program path. The action log records it.
    pub path: PathBuf,
    /// What the command left behind.
    pub output: Output,
}

impl Executed {
    /// A command that ran from `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, output: Output) -> Self {
        Self {
            path: path.into(),
            output,
        }
    }
}

mod sealed {
    /// Keeps [`super::Backend`] closed: only this crate can implement it (ADR 0014 decision 1).
    pub trait Sealed {}
}

/// The raw I/O under the facade. It enforces no policy and writes no log.
///
/// Sealed: the live backend and the replay backend are the only implementations. A check cannot
/// supply its own, so it cannot route around the facade's policy.
pub trait Backend: sealed::Sealed + Send + Sync + 'static {
    /// Reads a file.
    fn open_read<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<FileBytes>>;
    /// Lists a directory.
    fn read_dir<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Vec<DirEntry>>>;
    /// Inspects a path. `Ok(None)` means it does not exist.
    fn stat<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Option<FileMeta>>>;
    /// Runs a command. Unlike the file calls this returns a [`ProbeError`], because the command
    /// policy (M1-039) refuses and times out in ways an `io::Error` cannot carry.
    fn spawn<'a>(&'a self, cmd: &'a Cmd) -> BoxFuture<'a, Result<Executed, ProbeError>>;
}

/// The run-wide side of the facade: the backend and the action log.
///
/// The engine builds one per run, hands a [`Probe`] to each check and reads the log at the end.
#[derive(Clone)]
pub struct ProbeHub {
    backend: Arc<dyn Backend>,
    log: ActionLog,
}

impl fmt::Debug for ProbeHub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeHub").finish_non_exhaustive()
    }
}

impl ProbeHub {
    /// A hub over `backend`. Every string in the log passes `redactor`.
    #[must_use]
    pub fn new(backend: Arc<dyn Backend>, redactor: Redactor) -> Self {
        Self {
            backend,
            log: ActionLog::new(redactor, None, MAX_ENTRIES),
        }
    }

    /// Shows paths under `home` as `~/...` in the log. Call it before the first probe is made: it
    /// starts a new, empty log.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        let redactor = self.log.redactor().clone();
        self.log = ActionLog::new(redactor, Some(home.into()), MAX_ENTRIES);
        self
    }

    /// Caps the log at `max` entries. For tests of retention.
    #[cfg(test)]
    fn with_max_entries(mut self, max: usize) -> Self {
        let redactor = self.log.redactor().clone();
        self.log = ActionLog::new(redactor, None, max);
        self
    }

    /// The probe for one check. `key` is the check's result key.
    #[cfg_attr(
        not(any(test, feature = "runtime", feature = "testing")),
        expect(
            dead_code,
            reason = "only the scheduler and the test helpers open probes"
        )
    )]
    pub(crate) fn check_probe(&self, key: &str) -> Probe {
        self.probe(Some(key.to_owned()))
    }

    /// The probe for run-level work, which the log records with `check: null`.
    #[cfg_attr(
        not(all(test, feature = "runtime")),
        expect(dead_code, reason = "the engine run (M1-057) opens run-level probes")
    )]
    pub(crate) fn run_probe(&self) -> Probe {
        self.probe(None)
    }

    fn probe(&self, check: Option<String>) -> Probe {
        Probe {
            hub: Some(self.clone()),
            scope: Arc::new(Scope {
                check,
                ended: AtomicBool::new(false),
            }),
        }
    }

    /// The log as it is now, ready for [`ActionLogOutput::apply`].
    #[must_use]
    pub fn action_log(&self) -> ActionLogOutput {
        self.log.snapshot()
    }
}

struct Scope {
    check: Option<String>,
    ended: AtomicBool,
}

/// What a check uses to read the machine. See the [module docs](self).
#[derive(Clone)]
pub struct Probe {
    hub: Option<ProbeHub>,
    scope: Arc<Scope>,
}

impl fmt::Debug for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Probe")
            .field("check", &self.scope.check)
            .field("closed", &self.hub.is_none())
            .field("ended", &self.scope.ended.load(Ordering::Acquire))
            .finish()
    }
}

impl Probe {
    /// A probe that refuses every call. It is what a context has until the scheduler or a test hub
    /// gives it a real one.
    pub(crate) fn closed() -> Self {
        Self {
            hub: None,
            scope: Arc::new(Scope {
                check: None,
                ended: AtomicBool::new(false),
            }),
        }
    }

    /// Ends the probe. Every later call, on this handle or a clone, is refused and logged.
    #[cfg_attr(
        not(any(test, feature = "runtime")),
        expect(dead_code, reason = "only the scheduler ends probes")
    )]
    pub(crate) fn end(&self) {
        self.scope.ended.store(true, Ordering::Release);
    }

    /// Opens the log entry for a call, after the handle checks. This is the one door every method
    /// goes through. A call on a closed or ended probe is refused here.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] with [`RULE_NO_PROBE`] or [`RULE_CHECK_FINISHED`]. The second is logged.
    pub(crate) fn begin(
        &self,
        kind: ActionKind,
        fields: Map<String, Value>,
        what: &str,
    ) -> Result<(&ProbeHub, Pending), ProbeError> {
        let Some(hub) = &self.hub else {
            return Err(ProbeError::denied(RULE_NO_PROBE, what));
        };
        let entry = hub.log.begin(self.scope.check.as_deref(), kind, fields);
        if self.scope.ended.load(Ordering::Acquire) {
            return Err(refuse(entry, RULE_CHECK_FINISHED, what));
        }
        Ok((hub, entry))
    }

    /// Reads a whole file.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for a path on the denylist, a relative path, a `..` path, or a call after
    /// the check ended; the other variants when the backend fails.
    pub async fn read(&self, path: &Path) -> Result<FileBytes, ProbeError> {
        let (hub, entry) = self.gate_file(ActionKind::Read, path)?;
        let result = hub
            .backend
            .open_read(path)
            .await
            .map_err(|e| ProbeError::from_io(&e));
        settle(entry, result, |file, entry| {
            entry.set("bytes", file.bytes.len());
            entry.set("truncated", file.truncated());
        })
    }

    /// Lists a directory.
    ///
    /// # Errors
    ///
    /// The same as [`Probe::read`].
    pub async fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, ProbeError> {
        let (hub, entry) = self.gate_file(ActionKind::ReadDir, path)?;
        let result = hub
            .backend
            .read_dir(path)
            .await
            .map_err(|e| ProbeError::from_io(&e));
        settle(entry, result, |entries, entry| {
            entry.set("entries", entries.len());
        })
    }

    /// Inspects a path. `Ok(None)` means it does not exist.
    ///
    /// # Errors
    ///
    /// The same as [`Probe::read`].
    pub async fn stat(&self, path: &Path) -> Result<Option<FileMeta>, ProbeError> {
        let (hub, entry) = self.gate_file(ActionKind::Stat, path)?;
        let result = hub
            .backend
            .stat(path)
            .await
            .map_err(|e| ProbeError::from_io(&e));
        settle(entry, result, |meta, entry| {
            if let Some(meta) = meta {
                entry.set("bytes", meta.len);
            }
        })
    }

    /// Runs a command.
    ///
    /// The entry records the resolved program path, the arguments, the exit code and how many bytes of
    /// stdout were kept. M1-039 routes this through `exec::policy::run`.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] after the check ended, or when the command policy refuses; the other
    /// variants when the command fails or times out.
    pub async fn exec(&self, cmd: Cmd) -> Result<Output, ProbeError> {
        let mut fields = Map::new();
        fields.insert("program".to_owned(), cmd.program.into());
        fields.insert(
            "argv".to_owned(),
            Value::Array(cmd.args.iter().cloned().map(Value::String).collect()),
        );
        let (hub, entry) = self.begin(ActionKind::Exec, fields, cmd.program)?;
        let result = hub.backend.spawn(&cmd).await;
        settle(entry, result, |done, entry| {
            entry.set("program", done.path.to_string_lossy().into_owned());
            entry.set("exit", done.output.exit);
            entry.set("stdout_bytes", done.output.stdout.len());
            entry.set("truncated", done.output.stdout_truncated);
        })
        .map(|done| done.output)
    }

    /// The common start of a file call: the handle checks, then the read denylist.
    fn gate_file(&self, kind: ActionKind, path: &Path) -> Result<(&ProbeHub, Pending), ProbeError> {
        let mut fields = Map::new();
        if let Some(hub) = &self.hub {
            fields.insert("path".to_owned(), hub.log.display_path(path).into());
        }
        let what = path.to_string_lossy();
        let (hub, entry) = self.begin(kind, fields, &what)?;
        match policy::check_read(path) {
            Ok(()) => Ok((hub, entry)),
            Err(rule) => Err(refuse(entry, rule, &what)),
        }
    }
}

/// Closes `entry` as `denied` and returns the error to give the check.
fn refuse(mut entry: Pending, rule: &'static str, what: &str) -> ProbeError {
    entry.set("rule", rule);
    entry.finish(ActionOutcome::Denied);
    ProbeError::denied(rule, what)
}

/// Closes `entry` with the result of the backend call and passes the result on.
///
/// `note` adds the kind-specific fields of a success.
fn settle<T>(
    mut entry: Pending,
    result: Result<T, ProbeError>,
    note: impl FnOnce(&T, &mut Pending),
) -> Result<T, ProbeError> {
    match &result {
        Ok(value) => {
            note(value, &mut entry);
            entry.finish(ActionOutcome::Ok);
        }
        Err(error) => {
            match error {
                ProbeError::Denied { rule, .. } => entry.set("rule", *rule),
                other => entry.set("error", other.to_string()),
            }
            entry.finish(error.outcome());
        }
    }
    result
}
