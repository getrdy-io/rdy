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
//! **Files and environment.** `read`, `read_tail`, `read_dir` and `stat` pass the read policy
//! ([`ReadGuard`], see the `policy` module): the path as written, then the real path after links, which the
//! live backend checks while it opens the file (M1-045). A read returns at most [`MAX_READ`] bytes and
//! says when it cut. `env` reads a variable the check declared in `CheckInfo::env`, and the log records
//! the name and never the value.
//!
//! **Native calls.** `Probe::native` takes a [`NativeCall`], a closed enum, never a closure. Each
//! variant has one policy row and writes one `native` entry that holds the call and never the answer.
//! A `Statvfs` path passes the read denylist and the check's `statfs` prefixes. The machine id is
//! opaque and run-level only (see the `native` module, ADR 0014).
//!
//! **What is here, and what is not.** The handle, the log, the read policy, `read`, `read_tail`,
//! `read_dir`, `read_link` (M1-169), `stat`, `env`, `exec`, `native`, `udp_exchange` and `unix_get`
//! (M1-144, policy in `sock`), `tcp` with the proxy `CONNECT` (M1-091), `tls_chain` (M1-092), `http`
//! and `trust_store` (M1-093), all three in `net` and needing feature `runtime` or `loopback`, and the
//! live backend (`live_backend`, feature `runtime`). Each tcp, tls and http call writes exactly one
//! entry through the crate-private `Probe::begin`. Still to come, each in its own ticket:
//!
//! - Kube requests (M1-103): a request writes its entry through [`Probe::kube_call`], which the
//!   read-only guard of `rdy-checks-k8s` calls.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rdy_spec::result::{ActionKind, ActionOutcome};
use serde_json::{Map, Value};

use crate::check::{BoxFuture, CheckInfo, Os, current_os};
use crate::exec::policy::{Cmd, PolicyError};
use crate::exec::table::{self, TableError};
#[cfg(feature = "runtime")]
use crate::exec::{ExecError, ExecOutput, policy::CommandError};
use crate::privilege::ProcessIds;
use crate::redact::{
    Cut, KNOWN_SECRET_REFUSED, Redacted, Redactor, is_secret_name, worth_registering,
};
use sock::{UdpReply, UnixResponse};

#[cfg(feature = "runtime")]
pub use live::live_backend;
pub use log::{
    ActionLogOutput, CHECK_QUOTA, COALESCE_AFTER, COALESCE_OK_AFTER, DENIED_TARGETS, MAX_ENTRIES,
};
pub use native::{
    MAX_ROOT_BYTES, MAX_SYSTEM_ROOTS, MachineId, NativeCall, NativeValue, RULE_MACHINE_ID,
    Resource, RlimitInfo, StatvfsInfo, StoreKind, StoreOrigin, StoreSource, SystemRoots, UnameInfo,
};
#[cfg(feature = "testing")]
pub(crate) use policy::{RULE_OUTSIDE_READS, RULE_OUTSIDE_STATFS, is_fd_dir, is_fd_link};
pub use policy::{ReadGuard, Refused};
pub use proxy::{
    DEFAULT_PROXY_PORT, MAX_CONNECT_HEAD, NetFailure, ProxyChallenge, ProxyError, ProxyUrl,
    ProxyUrlError,
};

pub use attempt::AttemptOutcome;
pub use trust::{NoRoots, TrustFailure};

use log::{ActionLog, Limits, Pending};
pub(crate) use log::{Tier, dropped_calls, tier};

mod addr;
mod attempt;
#[cfg(feature = "runtime")]
mod live;
mod log;
mod native;
#[cfg(any(feature = "runtime", feature = "loopback"))]
pub mod net;
mod policy;
mod proxy;
#[cfg(any(test, feature = "testing"))]
pub(crate) mod replay;
pub mod sock;
#[cfg(test)]
mod tests;
mod trust;

/// The rule of a call made after its check ended.
pub const RULE_CHECK_FINISHED: &str = "check finished";

/// The rule of a call on a context that has no probe hub.
pub const RULE_NO_PROBE: &str = "no probe in this context";

/// The most bytes one file read returns. A longer file is cut and the result says so.
pub const MAX_READ: usize = 1 << 20;

/// The most entries one directory listing returns. A longer directory is an error, not a short list.
pub const MAX_DIR_ENTRIES: usize = 65_536;

/// The rule of a command the check did not declare in `CheckInfo::commands`.
pub const RULE_COMMAND_UNDECLARED: &str = "command not declared by the check";

/// The rule of an environment name the check did not declare for that command.
pub const RULE_ENV_UNDECLARED: &str = "environment name not declared by the check";

/// The rule of an environment variable name the check did not declare in `CheckInfo::env`.
pub const RULE_ENV_NOT_DECLARED: &str = "environment variable not declared by the check";

/// The rule of a string that cannot be an environment variable name.
pub const RULE_ENV_BAD_NAME: &str = "not a valid environment variable name";

/// Why a probe call did not give a value.
///
/// It is `Clone`, `PartialEq` and `Eq` because [`CheckError`](crate::check::CheckError) is, and
/// [`NetFailure`] keeps that.
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
    /// Nothing listens at the address: the socket file is there and the service behind it is not.
    #[error(
        "connection refused. Fix: check that the service is running, and that the socket is not left over from an earlier run"
    )]
    ConnectionRefused,
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
    /// The OS has no source for this call yet. A check maps it to `CheckError::Unsupported`, so the
    /// result is `skipped`, not yet on this OS.
    #[error(
        "{0} is not available on this OS in this version of rdy. Fix: none needed, the result is skipped here; a later version adds it"
    )]
    Unsupported(String),
    /// The OS trust store is replaced by `SSL_CERT_FILE` or `SSL_CERT_DIR`, and rdy may not read what they
    /// name on this OS (Windows, in this version). Only the trust roots call gives it.
    #[error(
        "SSL_CERT_FILE or SSL_CERT_DIR is set, and rdy reads no files on this OS in this version. Fix: unset SSL_CERT_FILE and SSL_CERT_DIR and run again"
    )]
    StoreOverridden,
    /// The replay fixture holds no answer for this call. Only the replay backend gives it: a fixture
    /// never falls through to the real machine (08 section 2). The text names the call.
    #[error(
        "the replay fixture has no recorded answer for {0}. Fix: record the answer in the fixture (commands/, native/ or the file tree), or correct the test"
    )]
    NotRecorded(String),
    /// A network step failed in a way the facade names: a name that did not resolve, or a proxy that
    /// refused, wanted credentials or sent something that is not HTTP. The text ends with what to do.
    #[error("{0}")]
    Net(#[from] NetFailure),
    /// Any other I/O failure. The text is the OS message.
    #[error("{0}. Fix: check the message above and the state of the machine, then run again")]
    Io(String),
}

impl ProbeError {
    /// The error for an I/O failure, using the kinds checks care about.
    pub(crate) fn from_io(error: &io::Error) -> Self {
        #[cfg(any(test, feature = "testing"))]
        if let Some(unrecorded) = replay::Unrecorded::from_io(error) {
            return Self::NotRecorded(unrecorded.to_string());
        }
        match error.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(error.to_string()),
        }
    }

    /// The error for a failed file call. A refusal from the live backend (a link to a denied file, a
    /// FIFO) becomes `Denied`, with `what` as the log shows the path.
    fn from_file_io(error: &io::Error, what: &str) -> Self {
        match Refused::from_io(error) {
            Some(refused) => Self::denied(refused.rule, what),
            None => Self::from_io(error),
        }
    }

    /// The error for a failed native call. A refusal from the live backend (a `Statvfs` path that is a
    /// link to a denied place) becomes `Denied`, and `Unsupported` becomes [`ProbeError::Unsupported`].
    /// `what` is the path as the log shows it and `api` the call's name.
    fn from_native_io(error: &io::Error, what: &str, api: &str) -> Self {
        if error.kind() == io::ErrorKind::Unsupported {
            return Self::Unsupported(format!("the native call {api}"));
        }
        if native::RootsOverridden::is_in(error) {
            return Self::StoreOverridden;
        }
        Self::from_file_io(error, what)
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
            Self::NotFound
            | Self::PermissionDenied
            | Self::ConnectionRefused
            | Self::StoreOverridden
            | Self::Unsupported(_)
            | Self::NotRecorded(_)
            | Self::Net(_)
            | Self::Io(_) => ActionOutcome::Failed,
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
    /// `true` when the start of the file was left out (`read_tail`).
    pub truncated_head: bool,
    /// `true` when the end of the file was left out (the size cap).
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

    /// Which ends were cut, in the form the redactor takes (see [`Probe::file_text`]).
    #[must_use]
    pub fn cut(&self) -> Cut {
        Cut::new(self.truncated_head, self.truncated_tail)
    }
}

/// Which part of a file a read wants. The backend never returns more than the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadRange {
    /// The first `n` bytes. A longer file sets `truncated_tail`.
    Head(usize),
    /// The last `n` bytes. A longer file sets `truncated_head`.
    Tail(usize),
}

impl ReadRange {
    /// Cuts `bytes`, a whole file, to this range. Used by the replay backend.
    #[must_use]
    #[cfg_attr(
        not(any(test, feature = "testing")),
        expect(dead_code, reason = "only the replay backend cuts a whole file")
    )]
    pub(crate) fn cut(self, mut bytes: Vec<u8>) -> FileBytes {
        match self {
            Self::Head(max) => {
                let truncated_tail = bytes.len() > max;
                bytes.truncate(max);
                FileBytes {
                    bytes,
                    truncated_head: false,
                    truncated_tail,
                }
            }
            Self::Tail(max) => {
                let truncated_head = bytes.len() > max;
                let start = bytes.len().saturating_sub(max);
                FileBytes {
                    bytes: bytes.split_off(start),
                    truncated_head,
                    truncated_tail: false,
                }
            }
        }
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

    /// Which ends of stdout were cut. A command's output is cut at the end only.
    #[must_use]
    pub fn stdout_cut(&self) -> Cut {
        Cut::new(false, self.stdout_truncated)
    }

    /// Which ends of stderr were cut. A command's output is cut at the end only.
    #[must_use]
    pub fn stderr_cut(&self) -> Cut {
        Cut::new(false, self.stderr_truncated)
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

/// Why the provided socket methods of [`Backend`] fail.
const NO_SOCKETS: &str = "this backend cannot open sockets";

fn no_sockets_io() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, NO_SOCKETS)
}

mod sealed {
    /// Keeps [`super::Backend`] closed: only this crate can implement it (ADR 0014 decision 1).
    pub trait Sealed {}
}

/// The raw I/O under the facade. The file calls write no log, and the policy they enforce is the
/// [`ReadGuard`] the probe passes in. The probe has already applied it to the path as written. A backend
/// that resolves links applies [`ReadGuard::admit_real`] to the real path before it opens anything and
/// reports a refusal as [`Refused`] inside an `io::Error` of kind `PermissionDenied`. The replay backend
/// follows the symlinks of its fixture the same way, on its virtual tree. The provided `spawn` is the
/// exception: it runs `exec::table::run`, which applies the command table and the command policy again
/// before anything starts.
///
/// Sealed: the live backend and the replay backend are the only implementations. A check cannot
/// supply its own, so it cannot route around the facade's policy.
pub trait Backend: sealed::Sealed + Send + Sync + 'static {
    /// Reads the part of a regular file that `range` names, at most `MAX_READ` bytes.
    fn open_read<'a>(
        &'a self,
        path: &'a Path,
        range: ReadRange,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<FileBytes>>;
    /// Lists a directory, at most `MAX_DIR_ENTRIES` entries.
    fn read_dir<'a>(
        &'a self,
        path: &'a Path,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>>;
    /// Inspects a path. `Ok(None)` means it does not exist.
    fn stat<'a>(
        &'a self,
        path: &'a Path,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Option<FileMeta>>>;
    /// Reads where the symbolic link at `path` points, without following it (M1-169). The raw target
    /// bytes come back: a path, or a name such as `socket:[8841]`. A backend resolves the links in the
    /// parent directory, applies [`ReadGuard::admit_real`] to the link's real path (the real parent
    /// plus the link's own name) before it reads anything, and then [`ReadGuard::admit_link`] to what
    /// it read. A refusal is [`Refused`] inside an `io::Error` of kind `PermissionDenied`. A path that
    /// is not a link is an `io::Error` of kind `InvalidInput`. The provided body is for a backend with
    /// no links: it reports `Unsupported`.
    fn read_link<'a>(
        &'a self,
        path: &'a Path,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        let _ = (path, guard);
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this backend cannot read links",
            ))
        })
    }
    /// The value of one environment variable of this process, or `None` when it is not set. The probe
    /// has already checked the name: a check's probe reads only names it declared (`Probe::env`), and
    /// the run-level probe reads the few the engine needs (`Probe::run_env`). The live backend reads the
    /// process environment and a fixture backend answers from its record.
    fn env(&self, name: &str) -> Option<String>;
    /// Runs one OS call from the closed list. The probe has applied the policy row of the variant. A
    /// `Statvfs` call also gets the check's [`ReadGuard`], and a backend that resolves links applies
    /// [`ReadGuard::admit_real`] to the real path before it asks the file system. An OS with no source
    /// for the call returns an `io::Error` of kind `Unsupported`, which the probe reports as
    /// [`ProbeError::Unsupported`]. The answer must be the value kind of the call: the probe checks.
    fn native<'a>(
        &'a self,
        call: &'a NativeCall,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<NativeValue>>;
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

    /// Resolves a spec host name to addresses through the system resolver, for `udp_exchange` only.
    /// The probe has already checked that the name is one of the check's spec hosts. It judges the
    /// answers itself. The live backend uses the system resolver and a fixture backend answers from its
    /// record. The provided body refuses: no backend reaches a socket by default.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        let _ = (host, port, timeout);
        Box::pin(async { Err(no_sockets_io()) })
    }

    /// Sends one datagram to `to` from a socket connected to it and reads one reply of at most
    /// `max_reply` bytes within `timeout`. The probe has already applied the peer and address policy.
    /// The provided body refuses.
    fn udp_exchange<'a>(
        &'a self,
        to: SocketAddr,
        payload: &'a [u8],
        max_reply: usize,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<UdpReply, ProbeError>> {
        let _ = (to, payload, max_reply, timeout);
        Box::pin(async { Err(ProbeError::Io(NO_SOCKETS.to_owned())) })
    }

    /// Sends `GET path` over the unix socket at `socket` and reads the reply within `timeout`. The
    /// probe has already checked the socket, the method and the path against the policy. The provided
    /// body refuses.
    fn unix_get<'a>(
        &'a self,
        socket: &'a Path,
        path: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<UnixResponse, ProbeError>> {
        let _ = (socket, path, timeout);
        Box::pin(async { Err(ProbeError::Io(NO_SOCKETS.to_owned())) })
    }

    /// Opens a TCP stream to `addr`. The probe has already applied the peer and address policy, and it
    /// bounds the wait with its own timeout. The live backend connects a socket. The replay backend
    /// follows `net.json`: `refused`, `reset`, `blackhole`, or `serve`, which connects the in-process
    /// server the test registered under that name. The provided body refuses.
    #[cfg(any(feature = "runtime", feature = "loopback"))]
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<net::BoxedStream>> {
        let _ = addr;
        Box::pin(async { Err(no_sockets_io()) })
    }

    /// The process's real and effective user and group ids, for the privilege snapshot on macOS.
    ///
    /// Linux reads all four of each from `/proc/self/status` through `read`, and Windows has none. The
    /// provided body is the live path: the real and effective ids from the OS (`rustix`, safe). macOS
    /// has no call for the saved id and no filesystem id, so both are reported as the effective one.
    /// A fixture backend overrides it.
    fn process_ids(&self) -> BoxFuture<'_, Result<ProcessIds, ProbeError>> {
        #[cfg(all(feature = "runtime", unix))]
        {
            Box::pin(async {
                let uid = rustix::process::getuid().as_raw();
                let euid = rustix::process::geteuid().as_raw();
                let gid = rustix::process::getgid().as_raw();
                let egid = rustix::process::getegid().as_raw();
                Ok(ProcessIds::new(
                    [uid, euid, euid, euid],
                    [gid, egid, egid, egid],
                ))
            })
        }
        #[cfg(not(all(feature = "runtime", unix)))]
        {
            Box::pin(async {
                Err(ProbeError::Io(
                    "this build of rdy-engine cannot read the process ids".to_owned(),
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
    /// The run's proxy, set once before the checks start. Clones of the hub share it.
    proxy: Arc<OnceLock<ProxyUrl>>,
    /// Set when a check's probe is opened. After that the proxy can no longer be set.
    checks_started: Arc<AtomicBool>,
    /// The trust stores of the TLS calls, built once per run.
    #[cfg(any(feature = "runtime", feature = "loopback"))]
    tls: Arc<net::TlsState>,
    /// The time every TLS verdict sees instead of the real clock, since the Unix epoch. Set by tests
    /// only (feature `testing`), through `ProbeHub::pin_clock`.
    #[cfg(all(feature = "testing", any(feature = "runtime", feature = "loopback")))]
    clock: Arc<std::sync::Mutex<Option<Duration>>>,
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
            proxy: Arc::new(OnceLock::new()),
            checks_started: Arc::new(AtomicBool::new(false)),
            #[cfg(any(feature = "runtime", feature = "loopback"))]
            tls: Arc::default(),
            #[cfg(all(feature = "testing", any(feature = "runtime", feature = "loopback")))]
            clock: Arc::default(),
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

    /// Adds a secret to the run-scoped known-secret set (ADR 0015 decision 3). Every string the log, the
    /// report and the CLI redact from now on has the exact value removed. The kubeconfig token and
    /// client key data and the proxy password come in through here. Returns `false` if the value was
    /// refused (see [`Redactor::add_known_secret`]).
    ///
    /// A refusal is not silent. It logs a warning with no value and counts `known_secret_refused` in
    /// the report's `redaction.by_rule`. The caller decides whether it can go on (a refused kubeconfig
    /// or proxy secret is the caller's to treat as fatal). Never log the value.
    pub fn add_known_secret(&self, secret: &str) -> bool {
        let accepted = self.log.redactor().add_known_secret(secret);
        if !accepted {
            tracing::warn!(
                "a secret could not be added to the redaction set (too short, too long or no room), so it may not be removed from output"
            );
            self.log.count(KNOWN_SECRET_REFUSED);
        }
        accepted
    }

    /// Sets the proxy the run's checks reach through `Probe::tcp` with `Route::ViaProxy`, once.
    ///
    /// The password is added to the run-scoped known-secret set first, as written, percent-decoded and
    /// as the base64 `Proxy-Authorization` pair, so no later string can carry it into the log or the
    /// report. If the set refuses any of them, the proxy is not set and the call fails: the run cannot
    /// promise to hide the password, and the caller ends it with exit code 70 (PR #96 reviews). Call it
    /// after [`ProbeHub::new`] and before `Privilege::snapshot` (the first probe read), and before
    /// anything is printed or written. A URL with a user and no password registers the user name and
    /// the base64 of `user:` when the user name is 6 bytes or more, and a shorter user name registers
    /// nothing and is not refused. The log redacts an entry
    /// when it is written, so an entry that exists before the password is known could hold it: the call
    /// fails with [`ProxyError::TooLate`] once the action log has an entry or a check's probe was opened.
    ///
    /// # Errors
    ///
    /// [`ProxyError::SecretRefused`] when the set refused the password, [`ProxyError::AlreadySet`]
    /// when a proxy was already set, and [`ProxyError::TooLate`] when the run has started.
    pub fn set_proxy(&self, proxy: ProxyUrl) -> Result<(), ProxyError> {
        if self.proxy.get().is_some() {
            return Err(ProxyError::AlreadySet);
        }
        if self.checks_started.load(Ordering::SeqCst) || self.log.has_entries() {
            return Err(ProxyError::TooLate);
        }
        // Every form is tried even after a refusal, so what fits is in the set when the run stops.
        let mut accepted = true;
        for secret in proxy.secrets() {
            accepted &= self.add_known_secret(&secret);
        }
        if !accepted {
            return Err(ProxyError::SecretRefused);
        }
        self.proxy.set(proxy).map_err(|_| ProxyError::AlreadySet)
    }

    /// Reads a proxy URL and sets it as [`ProbeHub::set_proxy`] does.
    ///
    /// # Errors
    ///
    /// [`ProxyError::Url`] for text that is not a usable proxy URL, then the errors of
    /// [`ProbeHub::set_proxy`]. No error holds any part of the text.
    pub fn set_proxy_text(&self, text: &str) -> Result<(), ProxyError> {
        self.set_proxy(ProxyUrl::parse(text)?)
    }

    /// The probe for run-level work on this OS, which the log records with `check: null`. The
    /// privilege snapshot, the machine id and the capability probes use it.
    #[must_use]
    pub fn run_probe(&self) -> Probe {
        self.run_probe_for(current_os())
    }

    /// Like [`ProbeHub::run_probe`], for an explicit OS. The command table and the privilege snapshot
    /// read it, so a test can run the Windows path on any machine. It is crate-private: a caller
    /// outside the crate must not be able to pick an OS whose snapshot skips the INV-10 sources
    /// (`TestRun::run_probe` is the test door).
    pub(crate) fn run_probe_for(&self, os: Os) -> Probe {
        self.probe(None, os, None)
    }

    fn probe(&self, check: Option<String>, os: Os, info: Option<&'static CheckInfo>) -> Probe {
        if check.is_some() {
            self.checks_started.store(true, Ordering::SeqCst);
        }
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
    /// The check's manifest: commands, `reads`, `statfs`, `env` and `peers`.
    info: Option<&'static CheckInfo>,
    ended: AtomicBool,
    /// The spec hosts and timeouts of the socket calls (M1-144).
    peers: sock::Peers,
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
            peers: sock::Peers::default(),
            #[cfg(feature = "runtime")]
            ended_signal: tokio::sync::watch::channel(false).0,
        }
    }
}

/// One open `kube` entry of the action log. See [`Probe::kube_call`].
///
/// Close it with [`KubeCall::refused`], [`KubeCall::answered`] or [`KubeCall::failed`]. If it is dropped
/// first, the log records the call as `timeout`.
#[must_use = "an entry that is dropped is logged as a timeout"]
pub struct KubeCall {
    entry: Pending,
}

impl fmt::Debug for KubeCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KubeCall").finish_non_exhaustive()
    }
}

impl KubeCall {
    /// Marks the entry: the request carries `Impersonate-User` with the spec's `as:` user. The entry gets
    /// `impersonated: true`, and never the user name (02 Appendix B, rule 8).
    #[must_use = "the entry is closed by refused, answered or failed"]
    pub fn impersonated(mut self) -> Self {
        self.entry.set("impersonated", true);
        self
    }

    /// Marks the entry: the kubeconfig user sets an `as*` field, so kube adds `Impersonate-*` headers below
    /// the guard, to every request. The entry gets `kubeconfig_impersonates: true`, and never the user
    /// name. Absent otherwise, so a reader can tell "not impersonated" from "not said".
    #[must_use = "the entry is closed by refused, answered or failed"]
    pub fn kubeconfig_impersonates(mut self) -> Self {
        self.entry.set("kubeconfig_impersonates", true);
        self
    }

    /// The guard refused the request. It never left the process. `rule` is a fixed sentence.
    pub fn refused(mut self, rule: &'static str) {
        self.entry.set("rule", rule);
        self.entry.finish(ActionOutcome::Denied);
    }

    /// The guard refused the request because of one request header. As [`KubeCall::refused`], and the
    /// entry also names the header. Pass the name, never the value (02 Appendix B, rule 8).
    pub fn refused_header(mut self, rule: &'static str, header: &str) {
        self.entry.set("header", header);
        self.refused(rule);
    }

    /// The server answered with `status`. A status below 300 is `ok`. Any other is `failed` with a fixed
    /// `error` (01 section 5.4): a redirect is not followed, so a 3xx is a failure too.
    pub fn answered(mut self, status: u16) {
        self.entry.set("status", status);
        if status < 300 {
            self.entry.finish(ActionOutcome::Ok);
            return;
        }
        let error = if status < 400 {
            "the server answered with a redirect, which rdy does not follow"
        } else {
            "the server answered with an error status"
        };
        self.entry.set("error", error);
        self.entry.finish(ActionOutcome::Failed);
    }

    /// The request got no answer. `error` is a fixed phrase, never text from the client or the server.
    pub fn failed(mut self, error: &'static str) {
        self.entry.set("error", error);
        self.entry.finish(ActionOutcome::Failed);
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
    /// What the backend enforces on the real path.
    guard: ReadGuard,
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

    /// Opens the action-log entry for one Kubernetes API request (`kind` `kube`, with `method` and
    /// `path`). The read-only guard in `rdy-checks-k8s` calls this once per request, before it decides.
    /// Pass the path without the query string: a query can hold selector text, and 01 keeps it out of
    /// the log. `via_proxy` is the proxy the request goes through, as `scheme://host:port` with no user
    /// info ([`ProxyUrl::origin`] has that form), or `None` for a direct request (the entry then has
    /// `via_proxy: null`, as a `connect` entry does). A caller that sends its own `CONNECT` records it here.
    ///
    /// The entry carries this probe's check id, so a check that derives its client from its own probe
    /// gets its requests logged under its own key. A probe with no check (run-level work) logs
    /// `check: null`. Close the entry with one of the [`KubeCall`] methods. An entry that is dropped
    /// first is recorded as `timeout`, so a request that is cancelled in flight still leaves one entry.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] after the check ended (the refusal is logged, rule
    /// [`RULE_CHECK_FINISHED`]) or on a probe with no hub (rule [`RULE_NO_PROBE`]). The request must not
    /// be sent.
    pub fn kube_call(
        &self,
        method: &str,
        path: &str,
        via_proxy: Option<&str>,
    ) -> Result<KubeCall, ProbeError> {
        let mut fields = Map::new();
        fields.insert("method".to_owned(), method.into());
        fields.insert("path".to_owned(), path.into());
        fields.insert(
            "via_proxy".to_owned(),
            via_proxy.map_or(Value::Null, Into::into),
        );
        let (_, entry) = self.begin(ActionKind::Kube, fields, path)?;
        Ok(KubeCall { entry })
    }

    /// The OS this probe's command table and privilege snapshot are read for.
    #[must_use]
    pub fn os(&self) -> Os {
        self.scope.os
    }

    /// The process's user and group ids from the OS, for the privilege snapshot on macOS. Linux reads
    /// `/proc/self/status` instead. The entry is a `native` call with `api` `process_ids`.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] after the check ended, or the backend's error.
    pub(crate) async fn process_ids(&self) -> Result<ProcessIds, ProbeError> {
        let mut fields = Map::new();
        fields.insert("api".to_owned(), "process_ids".into());
        let (hub, entry) = self.begin(ActionKind::Native, fields, "process ids")?;
        let result = self
            .unless_ended("process ids", hub.backend.process_ids())
            .await;
        settle(entry, result, |_, _| {})
    }

    /// One environment variable, for run-level work (the Windows snapshot reads `SystemRoot`). The
    /// entry names the variable and never holds the value. A check's probe is refused: a check reads
    /// the names it declares, through `Probe::env`.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for a check's probe, or after the probe ended.
    pub(crate) fn run_env(&self, name: &'static str) -> Result<Option<String>, ProbeError> {
        let mut fields = Map::new();
        fields.insert("name".to_owned(), name.into());
        let (hub, entry) = self.begin(ActionKind::Env, fields, name)?;
        if self.scope.check.is_some() {
            return Err(refuse(entry, RULE_ENV_UNDECLARED, name));
        }
        let value = hub.backend.env(name);
        entry.finish(ActionOutcome::Ok);
        Ok(value)
    }

    /// Reads a regular file, up to [`MAX_READ`] bytes.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for a path on the denylist, outside the check's `reads`, a relative path,
    /// a `..` path, a link that leads to any of those, a file that is not a regular file (a FIFO, a
    /// device), or a call after the check ended; the other variants when the backend fails.
    pub async fn read(&self, path: &Path) -> Result<FileBytes, ProbeError> {
        self.read_range(path, ReadRange::Head(MAX_READ)).await
    }

    /// Reads the last `max` bytes of a regular file (at most [`MAX_READ`]). `truncated_head` says the
    /// start was left out.
    ///
    /// # Errors
    ///
    /// The same as [`Probe::read`].
    pub async fn read_tail(&self, path: &Path, max: usize) -> Result<FileBytes, ProbeError> {
        self.read_range(path, ReadRange::Tail(max.min(MAX_READ)))
            .await
    }

    async fn read_range(&self, path: &Path, range: ReadRange) -> Result<FileBytes, ProbeError> {
        let Gate {
            hub,
            entry,
            what,
            guard,
        } = self.gate_file(ActionKind::Read, path)?;
        let result = self
            .unless_ended(&what, async {
                hub.backend
                    .open_read(path, range, &guard)
                    .await
                    .map_err(|e| ProbeError::from_file_io(&e, &what))
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
    /// The same as [`Probe::read`], and `Io` for a directory with more than [`MAX_DIR_ENTRIES`]
    /// entries.
    pub async fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, ProbeError> {
        let Gate {
            hub,
            entry,
            what,
            guard,
        } = self.gate_file(ActionKind::ReadDir, path)?;
        let result = self
            .unless_ended(&what, async {
                hub.backend
                    .read_dir(path, &guard)
                    .await
                    .map_err(|e| ProbeError::from_file_io(&e, &what))
            })
            .await;
        settle(entry, result, |entries, entry| {
            entry.set("entries", entries.len());
        })
    }

    /// Reads where a symbolic link points, without following it. The answer is the raw target, as
    /// [`FileBytes`]: parse numbers from `.bytes` and put text in a finding only through
    /// [`Probe::file_text`], because a target is a path and may name a home directory.
    ///
    /// The link is judged where it sits: the path as written and its real path (the parent resolved)
    /// must be off the denylist and under one of the check's `reads` prefixes. Where it points is not
    /// judged and not logged. The log gets one `read_link` entry with the link's path.
    ///
    /// Two links are special. `/proc/self/ns/net` is readable when the check's `reads` cover it, and is
    /// not found where there is no `/proc`. A link in `/proc/<pid>/fd` is readable only by a check that
    /// declared [`FD_WALK`](crate::check::FD_WALK), and only a target that is a socket
    /// (`socket:[8841]`) is returned: any other target is refused and logged without it. List the
    /// directory with [`Probe::read_dir`], which the same declaration allows.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for a link on the denylist or outside the check's `reads`, a relative or
    /// `..` path, a non-socket target in an fd directory, or a call after the check ended;
    /// [`ProbeError::NotFound`] for a link that is not there; `Io` for a path that is not a link; the
    /// other variants when the backend fails.
    pub async fn read_link(&self, path: &Path) -> Result<FileBytes, ProbeError> {
        let Gate {
            hub,
            entry,
            what,
            guard,
        } = self.gate_file(ActionKind::ReadLink, path)?;
        let result = self
            .unless_ended(&what, async {
                hub.backend
                    .read_link(path, &guard)
                    .await
                    .map(FileBytes::new)
                    .map_err(|e| ProbeError::from_file_io(&e, &what))
            })
            .await;
        settle(entry, result, |_, _| {})
    }

    /// Inspects a path. `Ok(None)` means it does not exist.
    ///
    /// # Errors
    ///
    /// The same as [`Probe::read`].
    pub async fn stat(&self, path: &Path) -> Result<Option<FileMeta>, ProbeError> {
        let Gate {
            hub,
            entry,
            what,
            guard,
        } = self.gate_file(ActionKind::Stat, path)?;
        let result = self
            .unless_ended(&what, async {
                hub.backend
                    .stat(path, &guard)
                    .await
                    .map_err(|e| ProbeError::from_file_io(&e, &what))
            })
            .await;
        settle(entry, result, |meta, entry| {
            if let Some(meta) = meta {
                entry.set("bytes", meta.len);
            }
        })
    }

    /// Reads an environment variable the check declared in `CheckInfo::env`. `Ok(None)` means it is
    /// not set. The log records the name and never the value.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for a name the check did not declare, a string that cannot be a variable
    /// name, or a call after the check ended.
    pub fn env(&self, name: &str) -> Result<Option<String>, ProbeError> {
        let mut fields = Map::new();
        fields.insert("name".to_owned(), name.into());
        let (hub, entry) = self.begin(ActionKind::Env, fields, name)?;
        if name.is_empty() || name.contains(['=', '\0']) {
            return Err(refuse(entry, RULE_ENV_BAD_NAME, name));
        }
        if self
            .scope
            .info
            .is_some_and(|info| !info.env.contains(&name))
        {
            return Err(refuse(entry, RULE_ENV_NOT_DECLARED, name));
        }
        let value = hub.backend.env(name);
        // The value of a name that looks like a secret joins the run-scoped set before the check sees
        // it, so it is removed wherever it later shows up (ADR 0015 decision 3). A plain word, a
        // `${NAME}` reference or a path under /run/secrets/ does not: the key rule leaves those alone
        // too, and in the set they would be removed from every string. A refusal is counted.
        if let Some(value) = &value
            && is_secret_name(name)
            && worth_registering(value)
        {
            let _accepted = hub.add_known_secret(value);
        }
        settle(entry, Ok(value), |_, _| {})
    }

    /// The text of a file the facade returned, redacted. The partial edge line of a cut file is dropped
    /// first, an unterminated private key is removed through the end, and the known secrets are removed
    /// (see [`Redactor::redact_buffer`]). Use it, never `String::from_utf8`, for any part of the file
    /// that goes into a finding: `observed`, a note or a message.
    ///
    /// Parse numbers from `file.bytes`; take evidence from here.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] on a probe that has no hub, which is one the scheduler did not make.
    pub fn file_text(&self, file: &FileBytes) -> Result<Redacted<String>, ProbeError> {
        self.buffer_text(&file.bytes, file.cut())
    }

    /// The text of a command's stdout, redacted. Stdout is cut at its end when it passed the cap.
    ///
    /// # Errors
    ///
    /// The same as [`Probe::file_text`].
    pub fn stdout_text(&self, output: &Output) -> Result<Redacted<String>, ProbeError> {
        self.buffer_text(&output.stdout, output.stdout_cut())
    }

    /// The text of a command's stderr, redacted. Stderr is cut at its end when it passed its cap.
    ///
    /// # Errors
    ///
    /// The same as [`Probe::file_text`].
    pub fn stderr_text(&self, output: &Output) -> Result<Redacted<String>, ProbeError> {
        self.buffer_text(&output.stderr, output.stderr_cut())
    }

    /// The text of a unix socket reply body, redacted. The body is cut at its end when the server sent
    /// more than [`sock::BODY_LIMIT`]. `/info` can carry proxy settings with credentials, so use this
    /// for any part of the body that goes into a finding.
    ///
    /// # Errors
    ///
    /// The same as [`Probe::file_text`].
    pub fn unix_text(&self, reply: &UnixResponse) -> Result<Redacted<String>, ProbeError> {
        self.buffer_text(&reply.body, Cut::new(false, reply.truncated))
    }

    fn buffer_text(&self, bytes: &[u8], cut: Cut) -> Result<Redacted<String>, ProbeError> {
        let hub = self
            .hub
            .as_ref()
            .ok_or_else(|| ProbeError::denied(RULE_NO_PROBE, "buffer text"))?;
        Ok(hub.log.redact_buffer(bytes, cut))
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

    /// The common start of a file call: the handle checks, then the read policy on the path as written.
    fn gate_file(&self, kind: ActionKind, path: &Path) -> Result<Gate<'_>, ProbeError> {
        // The path as the log shows it. The error carries this text, and an error becomes a result
        // message, so a home directory name must not be in it.
        let what = self.hub.as_ref().map_or_else(
            || path.to_string_lossy().into_owned(),
            |hub| hub.log.display_path(path),
        );
        let mut fields = Map::new();
        fields.insert("path".to_owned(), what.clone().into());
        let reads = self.scope.info.map(|info| info.reads);
        let guard = match kind {
            ActionKind::ReadDir => ReadGuard::listing(self.scope.os, reads),
            ActionKind::ReadLink => ReadGuard::link(self.scope.os, reads),
            _ => ReadGuard::new(self.scope.os, reads),
        };
        let (hub, entry) = self.begin(kind, fields, &what)?;
        match guard.admit(path) {
            Ok(()) => Ok(Gate {
                hub,
                entry,
                what,
                guard,
            }),
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
