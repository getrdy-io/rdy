//! The process runner: starts one command, bounds it, and makes sure it dies with its check.
//!
//! This is the mechanism under the facade's `exec` (02, "Exec"). The command policy (search path,
//! refused programs, environment names, output caps) is M1-039 and sits on top. This module only
//! answers: how does a child start, how does it end, and what is left when it does not end by itself.
//!
//! - **Own process group.** On Unix each child leads a new process group, so `sh -c 'sleep 600 &'`
//!   and everything it forks share one group id. Killing the group kills them all.
//! - **Kill before reap.** A process group id stays reserved while its leader is a zombie. So the
//!   runner never reaps the leader before it has signalled the group: it waits for the exit without
//!   reaping (it polls `waitid` with `WNOWAIT`), sends SIGKILL to the group, frees the registry slot,
//!   and only then reaps. A kill after the reap could hit a new, unrelated group that reused the
//!   number. Two guards back this up. Every run first registers a `SIGCHLD` handler, because a process
//!   started with `SIGCHLD` ignored has its children reaped by the kernel at exit. And the group kill
//!   itself is skipped when the leader is already reaped (`ECHILD`).
//! - **Kill on every way out.** The group gets SIGKILL when the leader exits (so a background child
//!   never outlives its command), when the command times out, when the future is dropped (the
//!   scheduler aborts a check at its timeout, which drops it) and when the run ends through
//!   [`kill_all_groups`] (the watchdog and the Ctrl-C path).
//! - **Hung.** A child that is still not reaped one second after SIGKILL returns
//!   [`ExecError::Hung`] without waiting for it. A detached task reaps it later.
//! - **Registry.** Live groups sit in a fixed array of atomics until the leader's group is killed.
//!   [`kill_all_groups`] reads it with no lock, so it is safe from a watchdog that must not block.
//!   It also sets a shutdown flag first, so a command that is being started at that moment is killed
//!   as soon as it is registered, and none start afterwards.
//!
//! The program must be an absolute path, so no `PATH` or working-directory lookup happens. The
//! environment is cleared, stdin is null, the working directory is the root of the file system
//! ([`child_cwd`]), and stdout and stderr are read up to a byte cap each. The rest is drained and
//! dropped, so a chatty child never blocks on a full pipe.
//!
//! **Inherited descriptors.** The standard library opens its own descriptors with close-on-exec, but a
//! descriptor above 2 that `rdy` inherited from its parent (a shell that left a file open) passes to
//! every child. Setting close-on-exec on those needs a raw descriptor, which safe `rustix` does not
//! give. M1-039 (command policy) and the CLI start-up own this; until then the runner does not close
//! them.
//!
//! **Windows.** Job objects are M2-006. Until then a timeout or a drop kills the child process only
//! ([`KILLS_PROCESS_TREE`] is `false`), which is enough for the one program M1 runs there
//! (`whoami.exe`, which starts no children). [`kill_all_groups`] sets the shutdown flag there and
//! kills nothing. Other targets behave like Unix. A leader that calls `setsid` or `setpgid` for a
//! grandchild lets that grandchild escape the group. That residual is in the threat model (05,
//! Surface 1, "Residual risks") with the M2 fixes.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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

/// The working directory every child gets, so it never runs inside the operator's directory.
///
/// Unix: `/`. Windows: `%SystemRoot%\System32`, or the root of the current drive when `SystemRoot`
/// is not set.
#[must_use]
pub fn child_cwd() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/")
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("SystemRoot").map_or_else(
            || PathBuf::from("\\"),
            |root| PathBuf::from(root).join("System32"),
        )
    }
}

/// How many live process groups the registry holds. The facade allows at most 4 at once.
const REGISTRY_SLOTS: usize = 64;

/// Why a command did not give an [`ExecOutput`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExecError {
    /// The program could not be started. The operator can check that it exists and may be run. A
    /// program path that is not absolute is refused here too.
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
    /// The run is ending ([`kill_all_groups`] was called), so no new command starts.
    #[error("the run is ending, so the command was not started")]
    ShuttingDown,
}

/// One command to run. The program must be an absolute path (the policy layer resolves it).
#[derive(Clone)]
pub struct ExecSpec {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    timeout: Duration,
    stdout_cap: usize,
    stderr_cap: usize,
}

impl fmt::Debug for ExecSpec {
    /// Prints environment variable names only. Values can be secrets and never reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&OsString> = self.env.iter().map(|(name, _)| name).collect();
        f.debug_struct("ExecSpec")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env_names", &names)
            .field("timeout", &self.timeout)
            .field("stdout_cap", &self.stdout_cap)
            .field("stderr_cap", &self.stderr_cap)
            .finish()
    }
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
/// When the leader exits, the rest of its process group is killed, then the output is drained. The
/// status is the leader's real status. Dropping the future kills the child's process group. That is
/// how a scheduler abort stops a command: the check's task is dropped at its next await, and this
/// future goes with it.
///
/// # Errors
///
/// [`ExecError::Timeout`] after the group was killed and reaped, [`ExecError::Hung`] when the child
/// would not be reaped, and the other variants for start and read failures. The `Timeout` also covers
/// a descendant that left the group (see the module docs) and still holds the output pipe.
pub async fn run(spec: ExecSpec) -> Result<ExecOutput, ExecError> {
    run_with(spec, &REGISTRY, LIVE, REAP_GRACE).await
}

/// Ends the run's commands: sets the shutdown flag, then sends SIGKILL to every live process group in
/// the registry.
///
/// The flag comes first, so a command being started at this moment is killed as soon as it is
/// registered, and later calls to [`run`] return [`ExecError::ShuttingDown`]. The flag is never
/// cleared. Lock-free and non-blocking: the watchdog calls it before it exits, and so does the
/// normal exit path. It kills nothing on Windows (see [`KILLS_PROCESS_TREE`]).
pub fn kill_all_groups() {
    REGISTRY.kill_all(kill_group);
}

/// The number of registry slots in use now. A slot is in use from just before the child starts until
/// its process group has been killed, which is before the leader is reaped.
#[must_use]
pub fn live_groups() -> usize {
    REGISTRY.live()
}

/// Sends SIGKILL to the process group led by `pid`. Errors are ignored: the usual one is "no such
/// process", which means the group is already gone.
///
/// Callers must hold the leader unreaped, so the group id cannot have been reused.
#[cfg(unix)]
fn kill_group(pid: u32) {
    use rustix::process::{Signal, kill_process_group};
    if let Some(pid) = to_pid(pid)
        && leader_unreaped(pid)
    {
        let _ = kill_process_group(pid, Signal::KILL);
    }
}

/// Whether the child `pid` still exists as our child, running or as a zombie.
///
/// `false` means it was reaped already, by us or by the kernel (when `SIGCHLD` is ignored the kernel
/// reaps a child at its exit). Its group id is then free to be reused, so the group must not be
/// signalled. This is a second line behind [`ensure_sigchld_handled`], which stops the kernel
/// reaping; it also covers a reap by another part of the process.
#[cfg(unix)]
fn leader_unreaped(pid: rustix::process::Pid) -> bool {
    use rustix::io::Errno;
    use rustix::process::{WaitId, WaitIdOptions, waitid};
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
    !matches!(waitid(WaitId::Pid(pid), options), Err(Errno::CHILD))
}

/// Makes sure `SIGCHLD` has a handler before any child starts.
///
/// If `rdy` is started with `SIGCHLD` set to ignore (a shell can do that with `trap '' CHLD`), the
/// kernel reaps each child the moment it exits, and the zombie that protects the group id is never
/// there. Registering tokio's child-exit signal replaces the ignore with a handler. It is idempotent.
/// The returned guard only needs to live while the command is started.
#[cfg(unix)]
fn ensure_sigchld_handled() -> Result<tokio::signal::unix::Signal, ExecError> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        .map_err(|error| ExecError::Io(format!("cannot watch for child exits: {error}")))
}

/// Windows has no process group to signal. The child itself is killed through its handle.
#[cfg(not(unix))]
fn kill_group(_pid: u32) {}

#[cfg(unix)]
fn to_pid(pid: u32) -> Option<rustix::process::Pid> {
    i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
}

/// Waits until the process `pid` has exited, without reaping it. The exited process stays a zombie,
/// which keeps its process group id reserved until the caller has signalled the group.
///
/// This polls on every Unix, Linux included. `pidfd_open` would let the kernel wake us, but tokio
/// 1.54 deprecates every safe `AsyncFd` constructor (they cannot prove the descriptor stays open),
/// and the only supported one is `unsafe`. This crate forbids unsafe code, so polling it is.
#[cfg(unix)]
async fn wait_exited(pid: u32) -> io::Result<()> {
    match to_pid(pid) {
        Some(pid) => poll_exited(pid).await,
        None => Ok(()),
    }
}

/// Polls `waitid(P_PID, WEXITED | WNOWAIT | WNOHANG)` until the process has exited. `WNOWAIT` leaves
/// the zombie in place.
#[cfg(unix)]
async fn poll_exited(pid: rustix::process::Pid) -> io::Result<()> {
    use rustix::io::Errno;
    use rustix::process::{WaitId, WaitIdOptions, waitid};
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
    let mut delay = Duration::from_millis(2);
    loop {
        match waitid(WaitId::Pid(pid), options) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            // Not our child any more: nothing is left to protect.
            Err(Errno::CHILD) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(25));
    }
}

/// Windows has no process group to protect, so there is nothing to wait for before the kill.
#[cfg(not(unix))]
async fn wait_exited(_pid: u32) -> io::Result<()> {
    Ok(())
}

/// The registry that [`run`] and [`kill_all_groups`] share.
static REGISTRY: Registry<REGISTRY_SLOTS> = Registry::new();

/// A slot value for "claimed, pid not known yet". No process id equals it, so `kill_all` skips it.
const RESERVED: u32 = u32::MAX;

/// A fixed set of atomic slots holding the pids of live process groups, plus the shutdown flag. Zero
/// means free. Every access is `SeqCst`: a slot store then a flag load, against a flag store then
/// slot loads, must not both miss each other.
struct Registry<const N: usize> {
    slots: [AtomicU32; N],
    shutdown: AtomicBool,
}

impl<const N: usize> Registry<N> {
    const fn new() -> Self {
        Self {
            slots: [const { AtomicU32::new(0) }; N],
            shutdown: AtomicBool::new(false),
        }
    }

    /// Claims a free slot, or returns `None` when all are taken.
    fn reserve(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.compare_exchange(0, RESERVED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        })
    }

    fn set(&self, index: usize, pid: u32) {
        if let Some(slot) = self.slots.get(index) {
            slot.store(pid, Ordering::SeqCst);
        }
    }

    fn release(&self, index: usize) {
        if let Some(slot) = self.slots.get(index) {
            slot.store(0, Ordering::SeqCst);
        }
    }

    fn shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Sets the shutdown flag, then kills every registered group.
    fn kill_all(&self, kill: fn(u32)) {
        self.shutdown.store(true, Ordering::SeqCst);
        for slot in &self.slots {
            let pid = slot.load(Ordering::SeqCst);
            if pid != 0 && pid != RESERVED {
                kill(pid);
            }
        }
    }

    /// Slots in use, reserved ones included.
    fn live(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.load(Ordering::SeqCst) != 0)
            .count()
    }
}

/// The two side effects of ending a group, as functions so tests can watch or replace them.
#[derive(Clone, Copy)]
struct Hooks {
    /// Sends SIGKILL to the group of this pid.
    kill: fn(u32),
    /// Called right after the slot is released, before the leader is reaped.
    released: fn(u32),
}

fn nothing(_pid: u32) {}

/// What [`run`] uses.
const LIVE: Hooks = Hooks {
    kill: kill_group,
    released: nothing,
};

/// Owns one registry slot and the right to kill that group while the leader is unreaped.
///
/// [`Tracked::end_group`] kills the group, frees the slot and disarms, in that order, and only once.
/// The caller reaps the leader after it. Dropping an armed value does the same, so a dropped future
/// leaves nothing behind. A disarmed value never signals again: the leader may be reaped by then and
/// its group id reused.
struct Tracked {
    registry: &'static Registry<REGISTRY_SLOTS>,
    index: usize,
    pid: u32,
    hooks: Hooks,
    armed: AtomicBool,
}

impl Tracked {
    fn end_group(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            (self.hooks.kill)(self.pid);
            self.registry.release(self.index);
            (self.hooks.released)(self.pid);
        }
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.end_group();
    }
}

/// The body of [`run`], with the registry, the side effects and the reap grace passed in so tests can
/// stand in for a child that survives SIGKILL and can watch the order of events.
async fn run_with(
    spec: ExecSpec,
    registry: &'static Registry<REGISTRY_SLOTS>,
    hooks: Hooks,
    grace: Duration,
) -> Result<ExecOutput, ExecError> {
    if !spec.program.is_absolute() {
        return Err(ExecError::Spawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the program path must be absolute",
        )));
    }
    if registry.shutting_down() {
        return Err(ExecError::ShuttingDown);
    }
    #[cfg(unix)]
    let _sigchld = ensure_sigchld_handled()?;
    let index = registry.reserve().ok_or(ExecError::TooMany)?;
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(key, value)| (key, value)))
        .current_dir(child_cwd())
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
        hooks,
        armed: AtomicBool::new(true),
    };
    // The run may have ended between the check above and the registration. Dropping `tracked` kills
    // the group.
    if registry.shutting_down() {
        return Err(ExecError::ShuttingDown);
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let finished = {
        // The leader's life: wait for the exit without reaping, kill the group, free the slot, then
        // reap. The pipes drain alongside and reach EOF once the group is dead.
        let leader = async {
            wait_exited(pid)
                .await
                .map_err(|error| ExecError::Io(error.to_string()))?;
            tracked.end_group();
            child
                .wait()
                .await
                .map_err(|error| ExecError::Io(error.to_string()))
        };
        let work = async {
            tokio::join!(
                leader,
                read_capped(stdout, spec.stdout_cap),
                read_capped(stderr, spec.stderr_cap)
            )
        };
        tokio::time::timeout(spec.timeout, work).await
    };

    match finished {
        Ok((status, stdout, stderr)) => {
            let status = status?;
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
            // A no-op when the leader had already exited and its group was killed.
            tracked.end_group();
            #[cfg(not(unix))]
            let _ = child.start_kill();
            if let Ok(Ok(_)) = tokio::time::timeout(grace, child.wait()).await {
                Err(ExecError::Timeout)
            } else {
                // Not reaped in time. A detached task reaps it if it ever can.
                tokio::spawn(async move {
                    let _ = child.wait().await;
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
