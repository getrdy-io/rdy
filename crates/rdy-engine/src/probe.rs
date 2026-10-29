//! The probe facade: the handles a check uses to touch the machine (ADR 0014, SEC-17).
//!
//! A check gets one [`Probe`] in its [`CheckContext`](crate::check::CheckContext). Everything it
//! reads, lists, stats or runs goes through that handle, and every call writes one entry to the action
//! log. The handle is bound to its check:
//!
//! - **The log names the check.** Each entry carries the check's result key.
//! - **It dies with the check.** The scheduler ends the handle when the check ends, however it ends.
//!   A call made later, for example from a task the check left running, is refused with rule
//!   [`RULE_CHECK_FINISHED`] and logged as `denied`. A call that is still running when the check ends
//!   is cut off the same way (feature `runtime`; without it the call finishes first).
//! - **A context built without a hub is closed.** Every call is refused with [`RULE_NO_PROBE`]. There
//!   is nothing to log it in.
//!
//! Policy and the log sit above [`Backend`], which does the raw I/O and nothing else. A call goes in
//! this order: the handle is checked, the policy is applied, the backend runs, the entry is closed. A
//! refused call never reaches the backend.
//!
//! **Commands.** `Probe::exec` takes the one `Cmd` type of `exec::policy`, built with
//! `CommandEntry::cmd` from the command table (ADR 0028). The probe applies what the check declared for
//! that program in `CheckInfo::commands` (extra search directories, stdout cap, environment names),
//! then checks the command with `table::validate_for` for the check's OS, and only then hands it to
//! `Backend::spawn`. A command that is not in the table is refused here, whichever backend is under
//! it, so a replayed run refuses `sh`, `sudo` and anything unlisted exactly as a live run does. The
//! provided `Backend::spawn` runs the command with `exec::table::run`, the only public command runner
//! (it validates again, then applies the command policy). The replay backend overrides it with
//! recorded output. A probe built with no `CheckInfo` (run-level work, or a test context from
//! `TestRun::context`) skips the declaration step and still gets the table.
//!
//! **What is here, and what is not.** This ticket (M1-040) builds the handle, the log and the read
//! denylist, with `read`, `read_dir`, `stat` and `exec`. Still to come, each in its own ticket:
//!
//! - the real path check, the `reads` prefixes, the size caps, `read_tail` and `env`: M1-045;
//! - names, TCP, TLS, HTTP and native calls: the network and native tickets. They open their entries
//!   with the crate-private `Probe::begin`, the same way the methods here do. Each tcp, http and kube
//!   call writes exactly one entry (M1-091, M1-103);
//! - the live backend for files, which only these tickets can make safe to ship. Only the replay
//!   backend (feature `testing`) exists today, so nothing in a release build reaches the machine yet.

use std::fmt;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rdy_spec::result::{ActionKind, ActionOutcome};
use serde_json::{Map, Value};

use crate::check::{BoxFuture, CheckInfo, Os, current_os};
use crate::exec::policy::{Cmd, PolicyError};
use crate::exec::table::{self, TableError};
#[cfg(feature = "runtime")]
use crate::exec::{ExecError, ExecOutput, policy::CommandError};
use crate::redact::Redactor;

pub use log::{
    ActionLogOutput, CHECK_QUOTA, COALESCE_AFTER, COALESCE_OK_AFTER, DENIED_TARGETS, MAX_ENTRIES,
};

use log::{ActionLog, Limits, Pending};

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

/// The rule of a command the check did not declare in `CheckInfo::commands`.
pub const RULE_COMMAND_UNDECLARED: &str = "command not declared by the check";

/// The rule of an environment name the check did not declare for that command.
pub const RULE_ENV_UNDECLARED: &str = "environment name not declared by the check";

/// Why a probe call did not give a value.
///
/// It is `Clone`, `PartialEq` and `Eq` because [`CheckError`](crate::check::CheckError) is. The
/// variants the network ticket adds (`Net`) must keep that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// rdy's own policy refused the call. `rule` is a fixed sentence, `what` names the target. For a
    /// path, `what` is the path as the log shows it (`~/...` under the home directory).
    #[error(
        "refused by rdy policy ({rule}): {what}. Fix: rdy blocks this on purpose. Ask the spec author to drop the requirement, or file a bug if the check should not need it"
    )]
    Denied {
        /// The rule that refused it.
        rule: &'static str,
        /// What was refused, such as a path. Redact it before it is shown.
        what: String,
    },
    /// The command policy refused the command. The text ends with what to do.
    #[error("refused by rdy policy: {0}")]
    Policy(#[from] PolicyError),
    /// The command is not in the command table, or does not fit its entry. The text ends with what
    /// to do, and never holds an argument value.
    #[error("refused by rdy policy: {0}")]
    Table(#[from] TableError),
    /// The file, directory or program does not exist.
    #[error("not found. Fix: check that the file, directory or program exists on this machine")]
    NotFound,
    /// The OS refused: this user may not do that.
    #[error(
        "permission denied. Fix: run rdy as a user who may read it, or accept the limited result"
    )]
    PermissionDenied,
    /// The call ran out of time.
    #[error(
        "timed out. Fix: run again, and if it repeats check that the machine is not overloaded"
    )]
    Timeout,
    /// A killed command was not reaped. It may be stuck in the kernel.
    #[error(
        "the command did not exit after it was killed (pid {pid}). Fix: look at that process; it may be stuck in the kernel, for example on a hung network mount"
    )]
    Hung {
        /// The child's process id.
        pid: u32,
    },
    /// Any other I/O failure. The text is the OS message.
    #[error("{0}. Fix: check the message above and the state of the machine, then run again")]
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

    /// Maps what `table::run` returns.
    #[cfg(feature = "runtime")]
    fn from_command(error: CommandError) -> Self {
        match error {
            CommandError::Policy(policy) => Self::Policy(policy),
            CommandError::Table(table) => Self::Table(table),
            CommandError::Exec(ExecError::Spawn(io)) => Self::from_io(&io),
            CommandError::Exec(ExecError::Timeout) => Self::Timeout,
            CommandError::Exec(ExecError::Hung { pid }) => Self::Hung { pid },
            CommandError::Exec(ExecError::Io(text)) => Self::Io(text),
            other => Self::Io(other.to_string()),
        }
    }

    /// How the action log records this error.
    fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Denied { .. } => ActionOutcome::Denied,
            Self::Policy(_) | Self::Table(_) => ActionOutcome::Denied,
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

#[cfg(feature = "runtime")]
impl From<ExecOutput> for Output {
    fn from(done: ExecOutput) -> Self {
        Self {
            exit: done.status.code(),
            stdout: done.stdout,
            stdout_truncated: done.stdout_truncated,
            stderr: done.stderr,
            stderr_truncated: done.stderr_truncated,
        }
    }
}

mod sealed {
    /// Keeps [`super::Backend`] closed: only this crate can implement it (ADR 0014 decision 1).
    pub trait Sealed {}
}

/// The raw I/O under the facade. The file calls enforce no policy and write no log: the probe has
/// already done both. The provided `spawn` is the exception: it runs `exec::table::run`, which applies
/// the command table and the command policy again before anything starts.
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
    /// Runs a command that the probe already checked against the command table. Unlike the file
    /// calls this returns a [`ProbeError`], because a start failure, a timeout and a command that would
    /// not die are not `io::Error` kinds.
    ///
    /// The provided body is the live path: it hands the command to `exec::table::run`, the only public
    /// command runner, which validates the command again and applies the command policy before
    /// anything starts. A fixture backend overrides it and starts nothing. Without feature `runtime`
    /// there is no runner and the call fails.
    fn spawn<'a>(&'a self, cmd: Cmd) -> BoxFuture<'a, Result<Output, ProbeError>> {
        #[cfg(feature = "runtime")]
        {
            // The one sanctioned call of the table runner outside `exec` (root clippy.toml).
            #[expect(
                clippy::disallowed_methods,
                reason = "the probe is the only caller of table::run; it has logged the entry and applied the declaration"
            )]
            let running = table::run(cmd);
            Box::pin(async move {
                running
                    .await
                    .map(Output::from)
                    .map_err(ProbeError::from_command)
            })
        }
        #[cfg(not(feature = "runtime"))]
        {
            let _ = cmd;
            Box::pin(async {
                Err(ProbeError::Io(
                    "this build of rdy-engine cannot run commands (feature `runtime` is off)"
                        .to_owned(),
                ))
            })
        }
    }
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
            log: ActionLog::new(redactor, None, Limits::default()),
        }
    }

    /// Shows paths under `home` as `~/...` in the log. Call it before the first probe is made: it
    /// starts a new, empty log.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        let redactor = self.log.redactor().clone();
        self.log = ActionLog::new(redactor, Some(home.into()), Limits::default());
        self
    }

    /// Sets the log limits. For tests of retention.
    #[cfg(test)]
    fn with_limits(mut self, max_entries: usize, check_quota: usize) -> Self {
        let redactor = self.log.redactor().clone();
        self.log = ActionLog::new(
            redactor,
            None,
            Limits {
                max_entries,
                check_quota,
            },
        );
        self
    }

    /// The probe for one check. `key` is the check's result key and `os` the operating system the
    /// check runs on, which the command table is read for. `info` is the check's manifest: with it, a
    /// command must be one the check declared, and its directories, environment names and stdout cap
    /// come from the declaration.
    #[cfg_attr(
        not(any(test, feature = "runtime", feature = "testing")),
        expect(
            dead_code,
            reason = "only the scheduler and the test helpers open probes"
        )
    )]
    pub(crate) fn check_probe(&self, key: &str, os: Os, info: Option<&'static CheckInfo>) -> Probe {
        self.probe(Some(key.to_owned()), os, info)
    }

    /// The probe for run-level work, which the log records with `check: null`.
    #[cfg_attr(
        not(all(test, feature = "runtime", unix)),
        expect(dead_code, reason = "the engine run (M1-057) opens run-level probes")
    )]
    pub(crate) fn run_probe(&self) -> Probe {
        self.probe(None, current_os(), None)
    }

    fn probe(&self, check: Option<String>, os: Os, info: Option<&'static CheckInfo>) -> Probe {
        Probe {
            hub: Some(self.clone()),
            scope: Arc::new(Scope::new(check, os, info)),
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
    /// The OS the command table is read for.
    os: Os,
    /// The check's manifest. Only commands read it so far (M1-045 adds files and env).
    info: Option<&'static CheckInfo>,
    ended: AtomicBool,
    /// Tells calls in flight that the check ended.
    #[cfg(feature = "runtime")]
    ended_signal: tokio::sync::watch::Sender<bool>,
}

impl Scope {
    fn new(check: Option<String>, os: Os, info: Option<&'static CheckInfo>) -> Self {
        Self {
            check,
            os,
            info,
            ended: AtomicBool::new(false),
            #[cfg(feature = "runtime")]
            ended_signal: tokio::sync::watch::channel(false).0,
        }
    }
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

/// A call that passed the handle checks and the read denylist.
struct Gate<'a> {
    hub: &'a ProbeHub,
    entry: Pending,
    /// The path as the log shows it. This, never the raw path, goes into an error.
    what: String,
}

impl Probe {
    /// A probe that refuses every call. It is what a context has until the scheduler or a test hub
    /// gives it a real one.
    pub(crate) fn closed() -> Self {
        Self {
            hub: None,
            scope: Arc::new(Scope::new(None, current_os(), None)),
        }
    }

    /// Ends the probe. Every later call, on this handle or a clone, is refused and logged. A call in
    /// flight is cut off.
    #[cfg_attr(
        not(any(test, feature = "runtime")),
        expect(dead_code, reason = "only the scheduler ends probes")
    )]
    pub(crate) fn end(&self) {
        self.scope.ended.store(true, Ordering::Release);
        #[cfg(feature = "runtime")]
        self.scope.ended_signal.send_replace(true);
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

    /// Runs `work`, unless the check ends first. Then the call is refused as a late call.
    async fn unless_ended<T>(
        &self,
        what: &str,
        work: impl Future<Output = Result<T, ProbeError>>,
    ) -> Result<T, ProbeError> {
        #[cfg(feature = "runtime")]
        {
            let mut ended = self.scope.ended_signal.subscribe();
            tokio::select! {
                biased;
                _ = ended.wait_for(|ended| *ended) => {
                    Err(ProbeError::denied(RULE_CHECK_FINISHED, what))
                }
                result = work => result,
            }
        }
        #[cfg(not(feature = "runtime"))]
        {
            let _ = what;
            work.await
        }
    }

    /// Reads a whole file.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for a path on the denylist, a relative path, a `..` path, or a call after
    /// the check ended; the other variants when the backend fails.
    pub async fn read(&self, path: &Path) -> Result<FileBytes, ProbeError> {
        let Gate { hub, entry, what } = self.gate_file(ActionKind::Read, path)?;
        let result = self
            .unless_ended(&what, async {
                hub.backend
                    .open_read(path)
                    .await
                    .map_err(|e| ProbeError::from_io(&e))
            })
            .await;
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
        let Gate { hub, entry, what } = self.gate_file(ActionKind::ReadDir, path)?;
        let result = self
            .unless_ended(&what, async {
                hub.backend
                    .read_dir(path)
                    .await
                    .map_err(|e| ProbeError::from_io(&e))
            })
            .await;
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
        let Gate { hub, entry, what } = self.gate_file(ActionKind::Stat, path)?;
        let result = self
            .unless_ended(&what, async {
                hub.backend
                    .stat(path)
                    .await
                    .map_err(|e| ProbeError::from_io(&e))
            })
            .await;
        settle(entry, result, |meta, entry| {
            if let Some(meta) = meta {
                entry.set("bytes", meta.len);
            }
        })
    }

    /// Runs a command.
    ///
    /// Build the command with `CommandEntry::cmd` from the command table. The probe applies what the
    /// check declared for this program, checks the command against the table for the check's OS, and
    /// hands it to the backend. The entry records the program name, the form id, the arguments
    /// (redacted, including the value after a secret flag), the exit code and how many bytes of stdout
    /// were kept.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] after the check ended, for a program or environment name the check did
    /// not declare; [`ProbeError::Table`] when the command is not in the table or does not fit its
    /// entry; [`ProbeError::Policy`] when the command policy refuses; the other variants when the
    /// command fails or times out.
    pub async fn exec(&self, cmd: Cmd) -> Result<Output, ProbeError> {
        let mut fields = Map::new();
        fields.insert("program".to_owned(), cmd.program().into());
        fields.insert(
            "argv".to_owned(),
            Value::Array(
                cmd.arguments()
                    .iter()
                    .map(|arg| Value::String(arg.to_string_lossy().into_owned()))
                    .collect(),
            ),
        );
        let (hub, mut entry) = self.begin(ActionKind::Exec, fields, cmd.program())?;
        let (cmd, form) = match self.admit(cmd) {
            Ok(admitted) => admitted,
            Err(error) => return settle(entry, Err(error), |_: &Output, _| {}),
        };
        entry.set("form", form);
        let program = cmd.program();
        let result = self.unless_ended(program, hub.backend.spawn(cmd)).await;
        settle(entry, result, |done, entry| {
            entry.set("exit", done.exit);
            entry.set("stdout_bytes", done.stdout.len());
            entry.set("truncated", done.stdout_truncated);
        })
    }

    /// Applies the check's declaration to `cmd`, then the command table. Returns the command and the
    /// id of the table form it matched.
    fn admit(&self, cmd: Cmd) -> Result<(Cmd, &'static str), ProbeError> {
        let cmd = match self.scope.info {
            Some(info) => {
                let program = cmd.program();
                let spec = info
                    .commands
                    .iter()
                    .find(|spec| same_program(spec.program, program))
                    .ok_or_else(|| ProbeError::denied(RULE_COMMAND_UNDECLARED, program))?;
                if let Some(name) = cmd
                    .declared_env_names()
                    .find(|name| !spec.env.contains(name))
                {
                    return Err(ProbeError::denied(RULE_ENV_UNDECLARED, name));
                }
                // The declaration can narrow the command and never widen it: the declared
                // directories replace the entry's, and the cap is the lower of the two.
                let cap = cmd.output_cap().min(spec.max_stdout);
                cmd.extra_dirs(spec.extra_dirs).stdout_cap(cap)
            }
            None => cmd,
        };
        let listed = table::validate_for(self.scope.os, &cmd)?;
        Ok((cmd, listed.form.id))
    }

    /// The common start of a file call: the handle checks, then the read denylist.
    fn gate_file(&self, kind: ActionKind, path: &Path) -> Result<Gate<'_>, ProbeError> {
        // The path as the log shows it. The error carries this text, and an error becomes a result
        // message, so a home directory name must not be in it.
        let what = self.hub.as_ref().map_or_else(
            || path.to_string_lossy().into_owned(),
            |hub| hub.log.display_path(path),
        );
        let mut fields = Map::new();
        fields.insert("path".to_owned(), what.clone().into());
        let (hub, entry) = self.begin(kind, fields, &what)?;
        match policy::check_read(path) {
            Ok(()) => Ok(Gate { hub, entry, what }),
            Err(rule) => Err(refuse(entry, rule, &what)),
        }
    }
}

/// Whether two program names are the same program. It follows the command table, where a Windows
/// entry matches without regard to case (`NETSTAT.EXE` and `netstat.exe`) and any other must match
/// exactly.
fn same_program(declared: &str, asked: &str) -> bool {
    match (table::entry(declared), table::entry(asked)) {
        (Some(a), Some(b)) => std::ptr::eq(a, b),
        _ => declared == asked,
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
                ProbeError::Policy(_) | ProbeError::Table(_) => {
                    entry.set("rule", error.to_string());
                }
                other => entry.set("error", other.to_string()),
            }
            entry.finish(error.outcome());
        }
    }
    result
}
