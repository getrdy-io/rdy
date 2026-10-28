//! The process runner: starts one command, bounds it, and makes sure it dies with its check.
//!
//! This is the mechanism under the facade's `exec` (02, "Exec"). The command policy (search path,
//! refused programs, environment names, output caps) is M1-039 and sits on top. This module only
//! answers: how does a child start, how does it end, and what is left when it does not end by itself.
//!
//! - **Own process group.** On Unix each child leads a new process group, so `sh -c 'sleep 600 &'`
//!   and everything it forks share one group id. Killing the group kills them all.
//! - **Kill on every way out.** The group gets SIGKILL when the command times out, when the future
//!   is dropped (the scheduler aborts a check at its timeout, which drops it) and when the run
//!   ends through [`kill_all_groups`] (the watchdog and the Ctrl-C path).
//! - **Hung.** A child that is still not reaped one second after SIGKILL returns
//!   [`ExecError::Hung`] without waiting for it. A detached task reaps it later.
//! - **Registry.** Live groups sit in a fixed array of atomics until the child is reaped.
//!   [`kill_all_groups`] reads it with no lock, so it is safe from a watchdog that must not block.
//!
//! The environment is cleared, stdin is null, and stdout and stderr are read up to a byte cap each.
//! The rest is drained and dropped, so a chatty child never blocks on a full pipe.
//!
//! **Windows.** Job objects are M2-006. Until then a timeout or a drop kills the child process only
//! ([`KILLS_PROCESS_TREE`] is `false`), which is enough for the one program M1 runs there
//! (`whoami.exe`, which starts no children). [`kill_all_groups`] is a no-op there. Other targets
//! behave like Unix. A leader that calls `setsid` or `setpgid` for a grandchild lets that grandchild
//! escape the group. That residual is documented in the threat model.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

#[cfg(test)]
mod tests;

/// Whether a timeout or a drop kills the child's whole process tree on this target.
///
/// `true` on Unix. `false` on Windows until job objects land (M2-006).
pub const KILLS_PROCESS_TREE: bool = cfg!(unix);

/// How long a killed child gets to be reaped before the call returns [`ExecError::Hung`].
pub const REAP_GRACE: Duration = Duration::from_secs(1);

/// Default cap on captured stdout, in bytes (02, "Exec").
pub const DEFAULT_STDOUT_CAP: usize = 1024 * 1024;

/// Default cap on captured stderr, in bytes (02, "Exec").
pub const DEFAULT_STDERR_CAP: usize = 64 * 1024;

/// How many live process groups the registry holds. The facade allows at most 4 at once.
const REGISTRY_SLOTS: usize = 64;

/// Why a command did not give an [`ExecOutput`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExecError {
    /// The program could not be started. The operator can check that it exists and may be run.
    #[error("could not start the command: {0}")]
    Spawn(#[source] io::Error),
    /// The command ran past its timeout. Its process group was killed and reaped.
    #[error("the command timed out")]
    Timeout,
    /// The command was killed on timeout but the child was not reaped within [`REAP_GRACE`].
    ///
    /// This is the signature of a process stuck in the kernel, such as a hung network mount. A
    /// detached task reaps it if it ever leaves that state.
    #[error("the command did not exit after SIGKILL (pid {pid})")]
    Hung {
        /// The child's process id.
        pid: u32,
    },
    /// Reading the command's output or waiting for it failed.
    #[error("reading the command failed: {0}")]
    Io(String),
    /// The registry of live process groups is full. Retry when other commands have ended.
    #[error("too many commands are running at once")]
    TooMany,
}

/// One command to run. The program must already be an absolute path (the policy layer resolves it).
#[derive(Debug, Clone)]
pub struct ExecSpec {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    timeout: Duration,
    stdout_cap: usize,
    stderr_cap: usize,
}

impl ExecSpec {
    /// A command with no arguments, an empty environment and the default output caps.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            timeout,
            stdout_cap: DEFAULT_STDOUT_CAP,
            stderr_cap: DEFAULT_STDERR_CAP,
        }
    }

    /// Sets the arguments. They go to the program as is. No shell sees them.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the environment. The parent's environment is never inherited.
    #[must_use]
    pub fn env<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        self.env = vars
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        self
    }

    /// Sets how many bytes of stdout and stderr to keep.
    #[must_use]
    pub fn caps(mut self, stdout: usize, stderr: usize) -> Self {
        self.stdout_cap = stdout;
        self.stderr_cap = stderr;
        self
    }
}

/// What a command that ran to the end left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecOutput {
    /// How the process ended.
    pub status: ExitStatus,
    /// The first bytes of stdout, up to the cap. Raw: redact before it is shown.
    pub stdout: Vec<u8>,
    /// Whether stdout had more bytes than the cap.
    pub stdout_truncated: bool,
    /// The first bytes of stderr, up to the cap. Raw: redact before it is shown.
    pub stderr: Vec<u8>,
    /// Whether stderr had more bytes than the cap.
    pub stderr_truncated: bool,
}

/// Runs one command to the end, its timeout, or the drop of this future.
///
/// Dropping the future kills the child's process group. That is how a scheduler abort stops a
/// command: the check's task is dropped at its next await, and this future goes with it.
///
/// # Errors
///
/// [`ExecError::Timeout`] after the group was killed and reaped, [`ExecError::Hung`] when the child
/// would not be reaped, and the other variants for start and read failures.
pub async fn run(spec: ExecSpec) -> Result<ExecOutput, ExecError> {
    run_with(spec, &REGISTRY, kill_group, REAP_GRACE).await
}

/// Sends SIGKILL to every live process group in the registry.
///
/// Lock-free and non-blocking. The watchdog calls it before it exits, and so does the normal exit
/// path for any group still left. It does nothing on Windows (see [`KILLS_PROCESS_TREE`]).
pub fn kill_all_groups() {
    REGISTRY.kill_all(kill_group);
}

/// The number of process groups that are live now, meaning started and not yet reaped.
#[must_use]
pub fn live_groups() -> usize {
    REGISTRY.live()
}

/// Sends SIGKILL to the process group led by `pid`. Errors are ignored: the usual one is "no such
/// process", which means the group is already gone.
#[cfg(unix)]
fn kill_group(pid: u32) {
    use rustix::process::{Pid, Signal, kill_process_group};
    if let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(pid, Signal::KILL);
    }
}

/// Windows has no process group to signal. The child itself is killed through its handle.
#[cfg(not(unix))]
fn kill_group(_pid: u32) {}

/// The registry that [`run`] and [`kill_all_groups`] share.
static REGISTRY: Registry<REGISTRY_SLOTS> = Registry::new();

/// A slot value for "claimed, pid not known yet". No process id equals it, so `kill_all` skips it.
const RESERVED: u32 = u32::MAX;

/// A fixed set of atomic slots holding the pids of live process groups. Zero means free.
struct Registry<const N: usize> {
    slots: [AtomicU32; N],
}

impl<const N: usize> Registry<N> {
    const fn new() -> Self {
        Self {
            slots: [const { AtomicU32::new(0) }; N],
        }
    }

    /// Claims a free slot, or returns `None` when all are taken.
    fn reserve(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.compare_exchange(0, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
    }

    fn set(&self, index: usize, pid: u32) {
        if let Some(slot) = self.slots.get(index) {
            slot.store(pid, Ordering::Release);
        }
    }

    fn release(&self, index: usize) {
        if let Some(slot) = self.slots.get(index) {
            slot.store(0, Ordering::Release);
        }
    }

    fn kill_all(&self, kill: fn(u32)) {
        for slot in &self.slots {
            let pid = slot.load(Ordering::Acquire);
            if pid != 0 && pid != RESERVED {
                kill(pid);
            }
        }
    }

    fn live(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.load(Ordering::Acquire) != 0)
            .count()
    }
}

/// Owns one registry slot and the right to kill that group. Dropping it kills the group and frees
/// the slot, so every way out of [`run_with`], including a dropped future, leaves nothing behind.
struct Tracked {
    registry: &'static Registry<REGISTRY_SLOTS>,
    index: usize,
    pid: u32,
    kill: fn(u32),
}

impl Tracked {
    fn kill(&self) {
        (self.kill)(self.pid);
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.kill();
        self.registry.release(self.index);
    }
}

/// The body of [`run`], with the registry, the kill function and the reap grace passed in so tests
/// can stand in for a child that survives SIGKILL.
async fn run_with(
    spec: ExecSpec,
    registry: &'static Registry<REGISTRY_SLOTS>,
    kill: fn(u32),
    grace: Duration,
) -> Result<ExecOutput, ExecError> {
    let index = registry.reserve().ok_or(ExecError::TooMany)?;
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            registry.release(index);
            return Err(ExecError::Spawn(error));
        }
    };
    let Some(pid) = child.id() else {
        registry.release(index);
        return Err(ExecError::Io(
            "the child ended before it was tracked".into(),
        ));
    };
    registry.set(index, pid);
    let tracked = Tracked {
        registry,
        index,
        pid,
        kill,
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let work = async {
        tokio::join!(
            child.wait(),
            read_capped(stdout, spec.stdout_cap),
            read_capped(stderr, spec.stderr_cap)
        )
    };

    match tokio::time::timeout(spec.timeout, work).await {
        Ok((status, stdout, stderr)) => {
            // The leader is done. Anything it left in the group goes too.
            drop(tracked);
            let status = status.map_err(|error| ExecError::Io(error.to_string()))?;
            let (stdout, stdout_truncated) = stdout?;
            let (stderr, stderr_truncated) = stderr?;
            Ok(ExecOutput {
                status,
                stdout,
                stdout_truncated,
                stderr,
                stderr_truncated,
            })
        }
        Err(_elapsed) => {
            tracked.kill();
            #[cfg(not(unix))]
            let _ = child.start_kill();
            if let Ok(Ok(_)) = tokio::time::timeout(grace, child.wait()).await {
                drop(tracked);
                Err(ExecError::Timeout)
            } else {
                // Not reaped in time. Hand the child and its slot to a task that waits for it, so
                // the slot stays in the registry until the process is really gone.
                tokio::spawn(async move {
                    let _ = child.wait().await;
                    drop(tracked);
                });
                Err(ExecError::Hung { pid })
            }
        }
    }
}

/// Reads `reader` to the end, keeping the first `cap` bytes. Returns them and whether any were cut.
async fn read_capped<R>(reader: Option<R>, cap: usize) -> Result<(Vec<u8>, bool), ExecError>
where
    R: AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return Ok((Vec::new(), false));
    };
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut chunk)
            .await
            .map_err(|error| ExecError::Io(error.to_string()))?;
        if read == 0 {
            return Ok((kept, truncated));
        }
        let room = cap.saturating_sub(kept.len());
        let take = read.min(room);
        if let Some(head) = chunk.get(..take) {
            kept.extend_from_slice(head);
        }
        if take < read {
            truncated = true;
        }
    }
}
