//! The replay backend: answers from a recorded fixture and touches nothing.
//!
//! Policy and the log sit above the backend, so a fixture run exercises the same denylist and the same
//! action log as a live run (02 "The probe facade"). A command arrives here after the probe checked it
//! against the command table for the check's OS, so the fixture can never be asked to "run" a shell, a
//! privilege tool or any program the table does not list: the table refused it first. Nothing is
//! started and no program is looked up on the machine.
//!
//! **What "not recorded" means.** The file tree is the machine: a path it does not hold does not exist,
//! so a read is `NotFound`, and a check that expects a missing file can be tested. A command, a native
//! call or a connection the fixture does not hold is different. Nothing says the machine lacks it, so
//! the call fails with [`ProbeError::NotRecorded`] and the test fails loudly. A fixture never falls
//! through to the real machine.
//!
//! **Links and the read policy.** The fixture can hold symlinks (`root.manifest.json`). A file call
//! follows them on the virtual tree and gives the real path to [`ReadGuard::admit_real`], as the live
//! backend does, so a link to `/etc/shadow` is refused. A link whose target is not a path
//! (`socket:[8841]`, what `/proc/<pid>/fd` shows) is a special file: it is not a regular file and not a
//! directory.
//!
//! **Time.** A `delay_ms` is a tokio timer and a `blackhole` is a future that never completes. Neither
//! uses a thread, so under paused time a wait costs nothing. A command whose delay reaches its time
//! limit gives `Timeout` after the limit.
//!
//! **Paths.** Keys are POSIX text whatever the runner is (see `paths`). Call [`Replay::with_os`] before
//! adding files: the fixture's `os` decides how a key is written.
//!
//! The loader that builds a [`Replay`] from the 08 directory format is [`Fixture`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use super::policy::{RULE_NOT_DIR, RULE_NOT_FILE_OR_DIR, RULE_NOT_REGULAR};
use super::sealed::Sealed;
use super::{
    Backend, DirEntry, FileBytes, FileMeta, NativeCall, NativeValue, Output, ProbeError, ReadGuard,
    ReadRange, Refused,
};
use crate::check::{BoxFuture, Os};
use crate::exec::DEFAULT_STDERR_CAP;
use crate::exec::policy::Cmd;
use crate::privilege::ProcessIds;

mod b64;
mod fixture;
mod net;
mod paths;
#[cfg(test)]
mod tests;

pub use fixture::{Caps, Expect, Fixture, FixtureError, Manifest, Origin, RunPins};
pub use net::{DnsAnswer, NetScript, TcpScript};

/// The most links followed while resolving one path. The same bound as the kernel's.
const MAX_LINK_HOPS: u32 = 40;

/// The fixture holds no answer for a call. It rides inside an `io::Error` of kind `NotFound`, and the
/// probe turns it back into [`ProbeError::NotRecorded`].
#[derive(Debug)]
pub(crate) struct Unrecorded(String);

impl fmt::Display for Unrecorded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unrecorded {}

impl Unrecorded {
    fn error(what: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::NotFound, Self(what.into()))
    }

    /// The marker inside `error`, if it carries one.
    pub(crate) fn from_io(error: &io::Error) -> Option<&Self> {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Self>())
    }
}

/// Why a recorded native call fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NativeFailure {
    Unsupported,
    PermissionDenied,
    NotFound,
    Io(String),
}

impl NativeFailure {
    fn into_io(self) -> io::Error {
        match self {
            Self::Unsupported => io::Error::from(io::ErrorKind::Unsupported),
            Self::PermissionDenied => io::Error::from(io::ErrorKind::PermissionDenied),
            Self::NotFound => io::Error::from(io::ErrorKind::NotFound),
            Self::Io(text) => io::Error::other(text),
        }
    }
}

/// What a recorded command did.
#[derive(Debug, Clone)]
struct CommandAnswer {
    output: Output,
    delay: Duration,
}

/// What a recorded native call did.
#[derive(Debug, Clone)]
struct NativeAnswer {
    result: Result<NativeValue, NativeFailure>,
    delay: Duration,
}

/// A recorded Kubernetes or cloud API response (`api/*.json`).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ApiRecord {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body.
    pub body: Value,
    /// How long the mock waits before it answers, on the tokio clock.
    pub delay: Duration,
}

/// A recorded machine: files, directories, links, command output, native answers and a network script.
#[derive(Debug, Clone)]
pub struct Replay {
    os: Os,
    files: HashMap<String, Vec<u8>>,
    dirs: HashMap<String, Vec<DirEntry>>,
    /// Link key to the target text as recorded.
    links: HashMap<String, String>,
    unreadable: HashSet<String>,
    modes: HashMap<String, u32>,
    env: HashMap<String, String>,
    commands: HashMap<(String, Vec<String>), CommandAnswer>,
    ids: Option<ProcessIds>,
    native: HashMap<NativeCall, NativeAnswer>,
    net: NetScript,
    api: HashMap<(String, String, String), ApiRecord>,
    reviews: Option<Value>,
}

impl Default for Replay {
    fn default() -> Self {
        Self::new()
    }
}

impl Replay {
    /// An empty Linux machine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            os: Os::Linux,
            files: HashMap::new(),
            dirs: HashMap::new(),
            links: HashMap::new(),
            unreadable: HashSet::new(),
            modes: HashMap::new(),
            env: HashMap::new(),
            commands: HashMap::new(),
            ids: None,
            native: HashMap::new(),
            net: NetScript::default(),
            api: HashMap::new(),
            reviews: None,
        }
    }

    /// Sets the OS the machine reports. It decides how keys are written (a Windows machine has drive
    /// paths in lower case) and how a program name is compared. Call it before adding anything.
    #[must_use]
    pub fn with_os(mut self, os: Os) -> Self {
        self.os = os;
        self
    }

    /// The OS the machine reports.
    #[must_use]
    pub fn os(&self) -> Os {
        self.os
    }

    fn key(&self, path: &Path) -> String {
        paths::key(self.os, &path.to_string_lossy())
    }

    /// The name a command is stored under: the program name, lower case on Windows.
    fn program_key(&self, program: &str) -> String {
        if self.os == Os::Windows {
            program.to_lowercase()
        } else {
            program.to_owned()
        }
    }

    /// Adds a file.
    #[must_use]
    pub fn file(mut self, path: impl AsRef<Path>, bytes: impl Into<Vec<u8>>) -> Self {
        let key = self.key(path.as_ref());
        self.files.insert(key, bytes.into());
        self
    }

    /// Adds a symlink at `path` that leads to `target`. The target is text: a path (absolute, or
    /// relative to the directory of the link) or a name such as `socket:[8841]`.
    #[must_use]
    pub fn symlink(mut self, path: impl AsRef<Path>, target: &str) -> Self {
        let key = self.key(path.as_ref());
        self.links.insert(key, target.to_owned());
        self
    }

    /// Makes a file or directory unreadable: a read of it fails with permission denied, as it does for
    /// a user without the right. `stat` still works.
    #[must_use]
    pub fn unreadable(mut self, path: impl AsRef<Path>) -> Self {
        let key = self.key(path.as_ref());
        self.unreadable.insert(key);
        self
    }

    /// Sets an environment variable. A check's probe still has to declare the name; the run-level probe
    /// reads the few names the engine needs.
    #[must_use]
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_owned(), value.to_owned());
        self
    }

    /// Adds a directory with these entries.
    #[must_use]
    pub fn dir(mut self, path: impl AsRef<Path>, entries: Vec<DirEntry>) -> Self {
        let key = self.key(path.as_ref());
        self.dirs.insert(key, entries);
        self
    }

    /// Adds the output of `program args...`. The command must still be one the table lists for the
    /// check's OS, or the probe refuses it before the fixture is asked.
    #[must_use]
    pub fn command(mut self, program: &str, args: &[&str], exit: i32, stdout: &str) -> Self {
        let output = Output::new(Some(exit), stdout.as_bytes().to_vec());
        let key = (
            self.program_key(program),
            args.iter().map(|a| (*a).to_owned()).collect(),
        );
        self.commands.insert(
            key,
            CommandAnswer {
                output,
                delay: Duration::ZERO,
            },
        );
        self
    }

    /// Records the answer to a native call. A call with no answer recorded is "not recorded", so a test
    /// that forgets one fails loudly. A later answer to the same call replaces the earlier one.
    #[must_use]
    pub fn native(mut self, call: NativeCall, value: NativeValue) -> Self {
        let call = self.normal_call(&call);
        self.native.insert(
            call,
            NativeAnswer {
                result: Ok(value),
                delay: Duration::ZERO,
            },
        );
        self
    }

    /// Sets the real, effective, saved and filesystem ids that `process_ids` answers with (the macOS
    /// snapshot). A backend with none set answers "not found".
    #[must_use]
    pub fn ids(mut self, uid: [u32; 4], gid: [u32; 4]) -> Self {
        self.ids = Some(ProcessIds::new(uid, gid));
        self
    }

    /// The scripted names and connections of `net.json`.
    #[must_use]
    pub fn net(&self) -> &NetScript {
        &self.net
    }

    /// The recorded API response for a request, or `None`. The method is compared in upper case.
    #[must_use]
    pub fn api(&self, method: &str, path: &str, query: &str) -> Option<&ApiRecord> {
        self.api.get(&(
            method.to_ascii_uppercase(),
            path.to_owned(),
            query.to_owned(),
        ))
    }

    /// The access review table (`api/reviews.json`): attributes to `allowed` and `reason`. The k8s mock
    /// reads it.
    #[must_use]
    pub fn reviews(&self) -> Option<&Value> {
        self.reviews.as_ref()
    }

    /// The mode the manifest records for a path (`modes` in `root.manifest.json`), such as `0o640`. No
    /// facade call reports a mode yet.
    #[must_use]
    pub fn mode(&self, path: impl AsRef<Path>) -> Option<u32> {
        self.modes.get(&self.key(path.as_ref())).copied()
    }

    /// What connecting to `addr` does under the fixture's `net.json`.
    ///
    /// A `blackhole` entry never completes: the future holds no timer and no thread, so the caller's
    /// timeout ends it, and under paused time the wait costs nothing. A `serve` entry returns the name
    /// of the server factory the test registered. A `refused` or `reset` entry fails with that kind. An
    /// address the script does not hold is "not recorded".
    ///
    /// # Errors
    ///
    /// An `io::Error` of kind `ConnectionRefused` or `ConnectionReset`, or the not-recorded marker.
    pub fn dial(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<String>> {
        Box::pin(async move {
            match self.net.tcp(addr) {
                Some(TcpScript::Serve(name)) => Ok(name.clone()),
                Some(TcpScript::Refused) => Err(io::ErrorKind::ConnectionRefused.into()),
                Some(TcpScript::Reset) => Err(io::ErrorKind::ConnectionReset.into()),
                Some(TcpScript::Blackhole) => std::future::pending().await,
                None => Err(Unrecorded::error(format!("a connection to {addr}"))),
            }
        })
    }

    /// Puts the path of a `Statvfs` call in key form, so a call compares equal however it was written.
    fn normal_call(&self, call: &NativeCall) -> NativeCall {
        match call {
            NativeCall::Statvfs { path } => NativeCall::Statvfs {
                path: self.key(path).into(),
            },
            other => other.clone(),
        }
    }

    /// Follows links on the virtual tree, one component at a time, like `realpath`.
    fn resolve(&self, key: &str) -> io::Result<Resolved> {
        use std::collections::VecDeque;
        let mut pending: VecDeque<String> = paths::components(self.os, key).into();
        let mut done: Vec<String> = Vec::new();
        let mut hops = 0u32;
        while let Some(part) = pending.pop_front() {
            if part == ".." {
                // Never above the root, and never off the drive of a Windows path.
                let drive_only = self.os == Os::Windows
                    && done.len() == 1
                    && done.iter().all(|p| paths::is_drive(p));
                if !drive_only {
                    done.pop();
                }
                continue;
            }
            done.push(part);
            let here = paths::join(self.os, &done);
            let Some(target) = self.links.get(&here) else {
                continue;
            };
            if paths::is_special_target(target) {
                return if pending.is_empty() {
                    Ok(Resolved::Special)
                } else {
                    Err(io::ErrorKind::NotFound.into())
                };
            }
            hops += 1;
            if hops > MAX_LINK_HOPS {
                return Err(io::Error::other(
                    "too many levels of symbolic links in the fixture",
                ));
            }
            done.pop();
            if paths::is_absolute(self.os, target) {
                done.clear();
            }
            for part in paths::components(self.os, target).into_iter().rev() {
                pending.push_front(part);
            }
        }
        Ok(Resolved::Real {
            key: paths::join(self.os, &done),
            followed: hops > 0,
        })
    }

    /// The first half of every file call: resolve the path, and when a link was followed, give the
    /// real path to the check's guard, as the live backend does before it opens anything.
    fn judge(&self, path: &Path, guard: &ReadGuard) -> io::Result<Judged> {
        match self.resolve(&self.key(path))? {
            Resolved::Special => Ok(Judged::Special),
            Resolved::Real { key, followed } => {
                if followed {
                    guard
                        .admit_real(Path::new(&key))
                        .map_err(Refused::into_io)?;
                }
                Ok(Judged::Real(key))
            }
        }
    }
}

/// Where a path ends once links are followed.
enum Resolved {
    Real {
        key: String,
        followed: bool,
    },
    /// A link whose target is not a path.
    Special,
}

/// A path that passed the guard.
enum Judged {
    Real(String),
    Special,
}

fn refusal(rule: &'static str) -> io::Error {
    Refused { rule }.into_io()
}

/// Waits `delay` on the tokio clock. Without feature `runtime` there is no clock, and a fixture that
/// asks for a delay cannot be replayed.
#[cfg(feature = "runtime")]
async fn pause(delay: Duration) -> io::Result<()> {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    Ok(())
}

#[cfg(not(feature = "runtime"))]
async fn pause(delay: Duration) -> io::Result<()> {
    if delay.is_zero() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a fixture delay needs feature `runtime` of rdy-engine",
        ))
    }
}

impl Sealed for Replay {}

impl Backend for Replay {
    fn open_read<'a>(
        &'a self,
        path: &'a Path,
        range: ReadRange,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<FileBytes>> {
        Box::pin(async move {
            let real = match self.judge(path, guard)? {
                Judged::Special => return Err(refusal(RULE_NOT_REGULAR)),
                Judged::Real(real) => real,
            };
            if self.unreadable.contains(&real) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if let Some(bytes) = self.files.get(&real) {
                Ok(range.cut(bytes.clone()))
            } else if self.dirs.contains_key(&real) {
                Err(refusal(RULE_NOT_REGULAR))
            } else {
                Err(io::ErrorKind::NotFound.into())
            }
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a Path,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
        Box::pin(async move {
            let real = match self.judge(path, guard)? {
                Judged::Special => return Err(refusal(RULE_NOT_DIR)),
                Judged::Real(real) => real,
            };
            if self.unreadable.contains(&real) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if let Some(entries) = self.dirs.get(&real) {
                Ok(entries.clone())
            } else if self.files.contains_key(&real) {
                Err(refusal(RULE_NOT_DIR))
            } else {
                Err(io::ErrorKind::NotFound.into())
            }
        })
    }

    fn stat<'a>(
        &'a self,
        path: &'a Path,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
        Box::pin(async move {
            let real = match self.judge(path, guard)? {
                Judged::Special => {
                    return Ok(Some(FileMeta {
                        is_file: false,
                        is_dir: false,
                        len: 0,
                    }));
                }
                Judged::Real(real) => real,
            };
            let meta = if let Some(bytes) = self.files.get(&real) {
                Some(FileMeta::file(
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                ))
            } else {
                self.dirs.contains_key(&real).then(FileMeta::dir)
            };
            Ok(meta)
        })
    }

    fn env(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }

    fn native<'a>(
        &'a self,
        call: &'a NativeCall,
        guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<NativeValue>> {
        Box::pin(async move {
            let call = self.normal_call(call);
            if let NativeCall::Statvfs { path } = &call
                && matches!(self.judge(path, guard)?, Judged::Special)
            {
                return Err(refusal(RULE_NOT_FILE_OR_DIR));
            }
            let Some(answer) = self.native.get(&call) else {
                // The call's name only. A path would carry a home directory name into a result message;
                // the action log holds the path as `~/...`.
                let what = format!("the native call {}", call.policy().api);
                return Err(Unrecorded::error(what));
            };
            pause(answer.delay).await?;
            answer.result.clone().map_err(NativeFailure::into_io)
        })
    }

    fn spawn<'a>(&'a self, cmd: Cmd) -> BoxFuture<'a, Result<Output, ProbeError>> {
        Box::pin(async move {
            let args: Vec<String> = cmd
                .arguments()
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            let key = (self.program_key(cmd.program()), args);
            let Some(answer) = self.commands.get(&key) else {
                let (_, args) = key;
                return Err(ProbeError::NotRecorded(format!(
                    "the command `{} {}`",
                    cmd.program(),
                    args.join(" ")
                )));
            };
            // The live runner kills a command at its time limit. A delay that reaches it is a timeout,
            // after the limit and no longer.
            let limit = cmd.time_limit();
            if !answer.delay.is_zero() && answer.delay >= limit {
                pause(limit).await.map_err(|e| ProbeError::from_io(&e))?;
                return Err(ProbeError::Timeout);
            }
            pause(answer.delay)
                .await
                .map_err(|e| ProbeError::from_io(&e))?;
            let mut output = answer.output.clone();
            let cap = cmd.output_cap();
            if output.stdout.len() > cap {
                output.stdout.truncate(cap);
                output.stdout_truncated = true;
            }
            if output.stderr.len() > DEFAULT_STDERR_CAP {
                output.stderr.truncate(DEFAULT_STDERR_CAP);
                output.stderr_truncated = true;
            }
            Ok(output)
        })
    }

    fn process_ids(&self) -> BoxFuture<'_, Result<ProcessIds, ProbeError>> {
        Box::pin(async move { self.ids.ok_or(ProbeError::NotFound) })
    }
}
