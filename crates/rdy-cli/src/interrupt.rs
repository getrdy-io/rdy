//! Ctrl-C, SIGINT and SIGTERM in M1 (M1-058, 07 section 5.1, 02 "Ctrl-C in M1").
//!
//! The first signal aborts the process. It does not write a report. The sequence, on one thread of its
//! own that the binary starts before the runtime ([`crate::Rig::watch_signals`]):
//!
//! 1. **Claim the write state** (`WriteState::claim`, the same bit the watchdog uses). If the watchdog
//!    or the end of the run already holds it, the report is being written or is written, and the signal
//!    is ignored: that path ends the process within its own bounds. Winning the claim means no report
//!    file is written afterwards by either side, so a folder that is empty now stays empty.
//! 2. **Put the terminal back.** A password prompt has echo and the signal keys off ([`crate::prompt`]),
//!    so a signal that arrives from outside would leave the user's shell with echo off.
//! 3. **Kill the child process groups** (`Effects::kill_groups`, the watchdog's own kill).
//! 4. **Remove the report folder** if nothing was written into it (`discard_if_empty` of `run_cmd`,
//!    which uses `remove_dir`, so a folder that holds a file stays). The folder is held weakly, as the
//!    watchdog holds it.
//! 5. **Print the two lines**, and with `--json` the `ErrorOutput` with code `interrupted`, then exit 70
//!    (`Effects::exit`, which aborts after 1 s if the exit blocks).
//!
//! The text is written with one raw write per stream on helper threads, like the watchdog's notice,
//! so a full pipe or a held std lock cannot stop the exit. The streams are never locked here.
//!
//! The thread, not the async runtime, handles the signal, so a check that never yields cannot delay it.
//! The main thread must not leave the process first with another exit code: `Interrupt::taken` tells
//! it to wait (see `Interrupt::wait_for_exit`).
//!
//! **Windows.** Ctrl-C and Ctrl-Break are caught through `tokio::signal::windows` and take the same
//! path. Windows has no process-group kill until M2-006 and `rdy` holds the report folder open, so
//! `remove_dir` can fail there and leave the empty folder. None of this is tested on Windows yet
//! (M1-058 deferral).
//!
//! **Not here.** The graceful first Ctrl-C with a partial report and the second Ctrl-C message are M2.

use std::fs::File;
use std::io::{self, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use rdy_engine::output::OutputDir;
use rdy_engine::watchdog::{Effects, ProcessEffects, WriteState};

use crate::error::{CliError, emit};
use crate::prompt::{Cancel, PromptError};

/// How long one stream may take to accept the text before the exit goes on without it.
const WRITE_WAIT: Duration = Duration::from_millis(200);

/// The longest the main thread waits for the signal thread to end the process.
const EXIT_WAIT: Duration = Duration::from_secs(5);

/// What the signal thread needs to know about the run, shared with the main thread.
#[derive(Debug, Default)]
pub(crate) struct Interrupt {
    /// `rdy run` has started: the text says "No report was written".
    run: AtomicBool,
    /// A signal won the claim and the process is on its way out with exit 70.
    taken: AtomicBool,
    /// The report folder, once it exists. Weak, so a folder the run removed is not held open.
    folder: Mutex<Weak<OutputDir>>,
}

impl Interrupt {
    /// `rdy run` has started.
    pub(crate) fn set_run(&self) {
        self.run.store(true, Ordering::SeqCst);
    }

    /// Records the report folder, held weakly.
    pub(crate) fn set_folder(&self, dir: Weak<OutputDir>) {
        *self.folder.lock().unwrap_or_else(PoisonError::into_inner) = dir;
    }

    /// True when a signal has taken over and the process is about to exit with 70.
    pub(crate) fn taken(&self) -> bool {
        self.taken.load(Ordering::SeqCst)
    }

    /// For the main thread, when it has a code to exit with: if a signal took over, waits for the signal
    /// thread to end the process, so that its exit code (70) is the one the shell sees. Bounded.
    pub(crate) fn wait_for_exit(&self) {
        let start = Instant::now();
        while self.taken() && start.elapsed() < EXIT_WAIT {
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Handles one signal. False means it was ignored because the report is being written or is
    /// written. True means the whole sequence ran (in the binary the process is gone by then).
    ///
    /// `put` writes the two buffers (stderr first, then stdout) and `restore` puts the terminal back and
    /// says whether it had to. Both are arguments so a test can see them.
    pub(crate) fn handle(
        &self,
        state: &WriteState,
        json: bool,
        effects: &dyn Effects,
        restore: &dyn Fn() -> bool,
        put: &dyn Fn(&[u8], &[u8]),
    ) -> bool {
        // `taken` is set first so the main thread cannot slip out with another code between the claim
        // and the flag. A lost claim clears it again.
        let already = self.taken.swap(true, Ordering::SeqCst);
        if !state.claim() {
            // A second signal, while the first is ending the process, must not clear the flag.
            if !already {
                self.taken.store(false, Ordering::SeqCst);
            }
            return false;
        }
        let restored = restore();
        effects.kill_groups();
        let folder = self
            .folder
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade();
        crate::run_cmd::discard_if_empty(folder);

        let error = if self.run.load(Ordering::SeqCst) {
            CliError::Interrupted
        } else {
            CliError::Prompt(PromptError::Cancelled(Cancel::Interrupted))
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        if restored {
            // The cursor is after the prompt the user was answering.
            err.push(b'\n');
        }
        emit(&error, json, &mut out, &mut err);
        put(&err, &out);
        effects.exit(i32::from(crate::EXIT_INTERNAL));
        true
    }
}

/// Writes `bytes` to a duplicate of the stream, on a helper thread, and waits at most [`WRITE_WAIT`].
fn write_bounded(stream: Option<File>, bytes: &[u8]) {
    let Some(mut file) = stream else {
        return;
    };
    if bytes.is_empty() {
        return;
    }
    let bytes = bytes.to_vec();
    let (done, wait) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("rdy-interrupt-write".into())
        .spawn(move || {
            let _ = file.write_all(&bytes);
            let _ = done.send(());
        });
    if spawned.is_ok() {
        let _ = wait.recv_timeout(WRITE_WAIT);
    }
}

/// The real output: a duplicate of descriptor 2, then of descriptor 1. No std lock is taken.
fn put_raw(err: &[u8], out: &[u8]) {
    write_bounded(clone_stderr(), err);
    write_bounded(clone_stdout(), out);
}

#[cfg(unix)]
fn clone_stderr() -> Option<File> {
    use std::os::fd::AsFd as _;
    io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(File::from)
}

#[cfg(unix)]
fn clone_stdout() -> Option<File> {
    use std::os::fd::AsFd as _;
    io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(File::from)
}

#[cfg(windows)]
fn clone_stderr() -> Option<File> {
    use std::os::windows::io::AsHandle as _;
    io::stderr()
        .as_handle()
        .try_clone_to_owned()
        .ok()
        .map(File::from)
}

#[cfg(windows)]
fn clone_stdout() -> Option<File> {
    use std::os::windows::io::AsHandle as _;
    io::stdout()
        .as_handle()
        .try_clone_to_owned()
        .ok()
        .map(File::from)
}

#[cfg(not(any(unix, windows)))]
fn clone_stderr() -> Option<File> {
    None
}

#[cfg(not(any(unix, windows)))]
fn clone_stdout() -> Option<File> {
    None
}

/// Starts the signal thread. It returns once the handlers are installed, so a signal after this
/// call is never lost.
///
/// # Errors
///
/// The thread or the handlers could not be set up. The binary ends the run with exit 70 then: a run
/// that cannot be interrupted cleanly is not allowed.
pub(crate) fn watch(
    interrupt: Arc<Interrupt>,
    state: Arc<WriteState>,
    json: bool,
) -> io::Result<()> {
    let (ready, installed) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("rdy-interrupt".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                let mut signals = match Signals::install() {
                    Ok(signals) => signals,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                loop {
                    signals.next().await;
                    interrupt.handle(
                        &state,
                        json,
                        &ProcessEffects,
                        &crate::prompt::restore_terminal,
                        &put_raw,
                    );
                }
            });
        })?;
    installed
        .recv()
        .map_err(|_| io::Error::other("the signal thread ended"))?
}

/// The signals that stop a run: SIGINT and SIGTERM.
#[cfg(unix)]
struct Signals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    fn install() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn next(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

/// The events that stop a run: Ctrl-C and Ctrl-Break.
#[cfg(windows)]
struct Signals {
    ctrl_c: tokio::signal::windows::CtrlC,
    ctrl_break: tokio::signal::windows::CtrlBreak,
}

#[cfg(windows)]
impl Signals {
    fn install() -> io::Result<Self> {
        Ok(Self {
            ctrl_c: tokio::signal::windows::ctrl_c()?,
            ctrl_break: tokio::signal::windows::ctrl_break()?,
        })
    }

    async fn next(&mut self) {
        tokio::select! {
            _ = self.ctrl_c.recv() => {}
            _ = self.ctrl_break.recv() => {}
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct Signals;

#[cfg(not(any(unix, windows)))]
impl Signals {
    fn install() -> io::Result<Self> {
        Ok(Self)
    }

    async fn next(&mut self) {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests;
