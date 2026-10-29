//! The process runner: starts one command, bounds it, and makes sure it dies with its check.
//!
//! This is the mechanism under the facade's `exec` (02, "Exec"). The command policy (search path,
//! refused programs, environment names, output caps) is [`policy`] and sits on top: facade code runs a
//! [`policy::Cmd`] and never builds an [`ExecSpec`] itself. `ExecSpec::new` and the raw `run` are
//! `pub` only under `cfg(any(test, feature = "testing"))`, so a check crate cannot reach the runner
//! without the policy (SEC-18). This module answers: how does a child start, how does it end, and what
//! is left when it does not end by itself.
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
//! The program must be an absolute path, so no `PATH` or working-directory lookup happens here ([`policy`]
//! resolves names from the fixed search path). The environment is cleared, stdin is null, the working directory is the root of the file system
//! ([`child_cwd`]), and stdout and stderr are read up to a byte cap each. The rest is drained and
//! dropped, so a chatty child never blocks on a full pipe.
//!
//! **Umask.** Before each start the runner sets the process umask to `0o077` ([`harden_umask`]), and the
//! child inherits it. Safe code cannot set a umask in the child alone (that needs `pre_exec`, which is
//! `unsafe`), so the change is process-wide. It only makes files that `rdy` itself creates tighter, and
//! the report writer sets its modes explicitly (ADR 0016). The value is constant, so repeated calls are
//! harmless.
//!
//! **Inherited descriptors.** The standard library opens its own descriptors with close-on-exec, but a
//! descriptor above 2 that `rdy` inherited from its parent (a shell that left a file open) passes to
//! every child. Setting close-on-exec or closing it needs a raw descriptor number, which no safe API
//! accepts. M1 does not close them. [`inherited_fds`] lists them so the CLI can warn at start-up
//! (M1-168, before the first public release), and the M2 fix is an FFI close (M2-104). ADR 0023 records
//! why. The children are fixed system tools with fixed argv, so a leaked descriptor is a detected
//! residual in M1, not an open door.
//!
//! **Windows.** Job objects are M2-006. Until then a timeout or a drop kills the child process only
//! ([`KILLS_PROCESS_TREE`] is `false`), which is enough for the one program M1 runs there
//! (`whoami.exe`, which starts no children). [`kill_all_groups`] sets the shutdown flag there and
//! kills nothing. Other targets behave like Unix. A leader that calls `setsid` or `setpgid` for a
//! grandchild lets that grandchild escape the group. That residual is in the threat model (05,
//! Surface 1, "Residual risks") with the M2 fixes.

pub mod policy;
pub mod table;

#[cfg(feature = "runtime")]
mod runner;

#[cfg(all(feature = "runtime", any(test, feature = "testing")))]
pub use runner::run;
#[cfg(feature = "runtime")]
pub use runner::{
    CHILD_UMASK, ExecError, ExecOutput, ExecSpec, KILLS_PROCESS_TREE, REAP_GRACE, child_cwd,
    harden_umask, inherited_fds, kill_all_groups, live_groups,
};

/// Default cap on captured stdout, in bytes (02, "Exec").
pub const DEFAULT_STDOUT_CAP: usize = 1024 * 1024;

/// Default cap on captured stderr, in bytes (02, "Exec").
pub const DEFAULT_STDERR_CAP: usize = 64 * 1024;
