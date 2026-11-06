//! Ctrl-C, SIGINT and SIGTERM in M1 (M1-058, 07 section 5.1, 02 "Ctrl-C in M1").
//!
//! The first signal aborts the process. It does not write a report. The sequence, on one thread of its
//! own that the binary starts before the runtime ([`crate::Rig::watch_signals`]):
//!
//! 1. **Take the exit.** Who ends the process is decided once, by a compare-and-swap on
//!    `Interrupt::exit`. The main thread takes it with `Interrupt::claim_exit` when it has its code, and
//!    a signal that comes later is ignored. A signal that gets it first wins, and the main thread waits
//!    for the exit 70. So "interrupted" is never printed and then followed by another exit code.
//! 2. **Claim the write state** (`WriteState::claim`, the same bit the watchdog uses). If the watchdog
//!    or the end of the run already holds it, the report is being written, and the first such signal is
//!    ignored: that path ends the process within its own bounds. Winning the claim means no report file
//!    is written afterwards by either side, so a folder that is empty now stays empty. A **second**
//!    signal after a lost claim (a hung report write) kills the groups and exits 70 at once, without
//!    touching the folder (07 section 5.1, "Second Ctrl-C").
//! 3. **Put the terminal back.** A password prompt has echo and the signal keys off ([`crate::prompt`]),
//!    so a signal that arrives from outside would leave the user's shell with echo off.
//! 4. **Kill the child process groups** (`Effects::kill_groups`, the watchdog's own kill).
//! 5. **Remove the report folder** if nothing was written into it (`OutputDir::remove_if_empty`, through
//!    the held parent handle, on a helper thread with a bound; a folder that holds a file stays). The
//!    folder is held weakly, as the watchdog holds it.
//! 6. **Put the terminal back again and flush the typed-ahead keys**, right before the text, then
//!    **print the two lines**, and with `--json` the `ErrorOutput` with code `interrupted`, then exit 70
//!    (`Effects::exit`, which aborts after 1 s if the exit blocks; core dumps are off, see
//!    `startup::harden_process`). Once the JSON document has started on stdout
//!    (`Interrupt::set_stdout_used`), the error goes to stderr only, so stdout holds one document.
//!
//! The text is written with `write_raw_bounded`, the watchdog's own helper, so a full pipe or a held
//! std lock cannot stop the exit. The streams are never locked here. The thread, not the async runtime,
//! handles the signal, so a check that never yields cannot delay it.
//!
//! **Windows.** Ctrl-C and Ctrl-Break are caught through `tokio::signal::windows` and take the same
//! path. Windows has no process-group kill until M2-006 and `rdy` holds the report folder open, so
//! the removal can fail there and leave the empty folder. None of this is tested on Windows yet
//! (M1-058 deferral).
//!
//! **Not here.** The graceful first Ctrl-C with a partial report and the second Ctrl-C message are M2.

use std::io::{self, IsTerminal as _};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use rdy_engine::output::OutputDir;
use rdy_engine::watchdog::{
    Effects, Phase, ProcessEffects, RawStream, WriteState, write_raw_bounded,
};

use crate::error::{CliError, emit};
use crate::prompt::{Cancel, PromptError};

/// How long the folder removal may take before the exit goes on without it.
const REMOVE_WAIT: Duration = Duration::from_millis(500);

/// The longest the main thread waits for the signal thread to end the process.
const EXIT_WAIT: Duration = Duration::from_secs(5);

/// Nobody owns the exit yet.
const FREE: u8 = 0;
/// A signal owns the exit: the process ends with 70.
const SIGNAL: u8 = 1;
/// The main thread owns the exit: it ends with its own code and a signal is ignored.
const MAIN: u8 = 2;

/// What the signal thread needs to know about the run, shared with the main thread.
#[derive(Debug, Default)]
pub(crate) struct Interrupt {
    /// `rdy run` has started: the text says "No report was written".
    run: AtomicBool,
    /// Who owns the exit: `FREE`, `SIGNAL` or `MAIN`.
    exit: AtomicU8,
    /// A signal lost the claim on the write state once (the report is being written). The next one
    /// ends the process at once.
    lost_claim: AtomicBool,
    /// `--json` has started to write the document to stdout. From then on a signal writes to stderr only.
    stdout_used: AtomicBool,
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

    /// The run is about to write the JSON document to stdout. Call it before the first byte.
    pub(crate) fn set_stdout_used(&self) {
        self.stdout_used.store(true, Ordering::SeqCst);
    }

    /// For the main thread, once it has the code to exit with: takes the exit. True when the main
    /// thread owns it, and a signal that comes later is ignored. If a signal owns it, waits (bounded)
    /// for the signal thread to end the process with 70, so that is the code the shell sees. A signal
    /// that gave the exit back (the report is being written) lets the retry succeed. False if the wait
    /// ran out.
    pub(crate) fn claim_exit(&self) -> bool {
        let start = Instant::now();
        loop {
            match self
                .exit
                .compare_exchange(FREE, MAIN, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) | Err(MAIN) => return true,
                Err(_) => {}
            }
            if start.elapsed() >= EXIT_WAIT {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Handles one signal. False means it was ignored: the main thread owns the exit, a signal is
    /// already ending the process, or the report is being written (the first time). True means the
    /// whole sequence ran (in the binary the process is gone by then).
    ///
    /// `at_terminal` says stderr is a terminal, where the cursor sits after the echoed `^C`, so the
    /// text starts on a new line. `put` writes the two buffers (stderr first, then stdout) and `restore`
    /// puts a password prompt's terminal settings back. Both are arguments so a test can see them.
    pub(crate) fn handle(
        &self,
        state: &WriteState,
        json: bool,
        at_terminal: bool,
        effects: &dyn Effects,
        restore: &dyn Fn() -> bool,
        put: &dyn Fn(&[u8], &[u8]),
    ) -> bool {
        if self
            .exit
            .compare_exchange(FREE, SIGNAL, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        let forced = if state.claim() {
            false
        } else if state.phase() == Phase::Writing && self.lost_claim.swap(true, Ordering::SeqCst) {
            // The second signal, and the report write has not finished: stop now, and leave the folder
            // to whoever is writing into it. A report that is `Done` is never turned into exit 70: the
            // main thread is about to exit with its code.
            true
        } else {
            // The report is being written. It ends the process within its own bounds.
            self.exit.store(FREE, Ordering::SeqCst);
            return false;
        };
        let restored = restore();
        effects.kill_groups();
        if !forced {
            let folder = self
                .folder
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .upgrade();
            crate::run_cmd::discard_bounded(folder, REMOVE_WAIT);
        }
        let error = if self.run.load(Ordering::SeqCst) {
            CliError::Interrupted
        } else {
            CliError::Prompt(PromptError::Cancelled(Cancel::Interrupted))
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        if restored || at_terminal {
            // The cursor is after the prompt, or after the `^C` the terminal echoed.
            err.push(b'\n');
        }
        // The last thing before the text: put the terminal back again and drop what was typed during the
        // kill and the folder removal, so those keys neither echo nor reach the shell (security review).
        let restored_again = restore();
        let _ = restored_again;
        // Once the document has started on stdout, nothing more goes there.
        let to_stdout = json && !self.stdout_used.load(Ordering::SeqCst);
        emit(&error, to_stdout, &mut out, &mut err);
        put(&err, &out);
        effects.exit(i32::from(crate::EXIT_INTERNAL));
        true
    }
}

/// The real output: a bounded raw write to descriptor 2, then to descriptor 1. No std lock is taken.
fn put_raw(err: &[u8], out: &[u8]) {
    write_raw_bounded(RawStream::Stderr, err);
    write_raw_bounded(RawStream::Stdout, out);
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
                        io::stderr().is_terminal(),
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
