//! The process entry point, in the order 02 ("Startup order") gives.
//!
//! 0. `harden_umask()` and the list of inherited descriptors, before anything is created or opened
//!    (M1-168, ADR 0023).
//! 1. The redactor, so nothing printed after this can leak. The descriptor warning, if any, follows
//!    it ([`crate::startup`]).
//! 2. The redacting log writer.
//! 3. The panic hook, which prints nothing ([`crate::panic_hook`]).
//! 4. The live backend and the async runtime, then [`crate::run`] inside [`guarded`], so that a panic
//!    outside a check exits 70, not 101 (07 section 5), with the same error text as every other
//!    internal error.
//!
//! **The one call site of `live_backend` (INV-07, ADR 0011 decision 4).** [`main_code`] is the body of
//! `main`, and it calls [`rdy_engine::live_backend`] once, here, with [`RunHooks::default`] and no
//! other hooks. The call sits after step 0 because building the live backend stats the password and
//! sudo files, and the descriptor list must be taken before rdy opens anything of its own. A test
//! builds its own backend and calls [`crate::run`] (see `tests/entry_point.rs`).

use std::ffi::OsString;
use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};

use rdy_engine::exec;

use crate::error::{CliError, emit, wants_json};
use crate::{EXIT_INTERNAL, RunHooks, logging, panic_hook, redaction, run, startup};

/// Runs rdy as the binary does and returns the exit code.
#[must_use]
pub fn main_code() -> u8 {
    // First, before any file is created or descriptor opened: a private umask, and the descriptors
    // the parent left open (they would reach every child command).
    exec::harden_umask();
    let inherited = exec::inherited_fds();
    let redactor = match redaction::init() {
        Ok(redactor) => redactor.clone(),
        Err(_) => {
            // Fixed text in the standard pair. It holds no input, so it needs no redaction.
            let mut err = io::stderr();
            let _ = writeln!(
                err,
                "error: the operating system could not supply random bytes for the redaction key"
            );
            let _ = writeln!(
                err,
                "fix: check that the OS random source works (on Linux, the getrandom call or /dev/urandom), then run rdy again"
            );
            return EXIT_INTERNAL;
        }
    };
    // Outside `guarded` and before the panic hook: this call has no panic path (a write error is
    // ignored), so there is nothing for either to catch.
    startup::warn_inherited(&inherited, &mut io::stderr());
    logging::init_stderr(redactor);
    panic_hook::install();
    let args: Vec<OsString> = std::env::args_os().collect();
    let json = wants_json(&args);
    guarded(
        json,
        &mut io::stdout(),
        &mut io::stderr(),
        |stdout, stderr| run_live(args, json, stdout, stderr),
    )
}

/// Builds the live backend and the runtime, runs the command and returns its exit code.
///
/// A runtime that cannot start is an internal error. The runtime is shut down without waiting: a
/// file read on a hung mount can leave a blocking thread, and the process is about to exit.
fn run_live(args: Vec<OsString>, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    #[expect(
        clippy::disallowed_methods,
        reason = "INV-07: this is the one call of live_backend outside the engine. The binary reads the real machine, and a check only ever gets the Probe it is handed (ADR 0014)"
    )]
    let backend = rdy_engine::live_backend();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return emit(&CliError::bug(), json, stdout, stderr),
    };
    // A panic in `block_on` would drop the runtime on the way out, and dropping waits for its blocking
    // pool with no limit. Catch it, shut down without waiting, then let `guarded` handle the panic.
    let ran = panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(run(args, backend, RunHooks::default(), stdout, stderr))
    }));
    runtime.shutdown_background();
    match ran {
        Ok(code) => code.code(),
        Err(payload) => panic::resume_unwind(payload),
    }
}

/// Runs `f` with the two streams. If `f` panics, prints the standard internal error and returns 70.
///
/// The error is the two lines on stderr, and with `json` the `ErrorOutput` on stdout too (07 section 5).
/// The panic text is not printed. With `RUST_LOG` set it goes to the log, escaped and redacted.
pub fn guarded<F>(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write, f: F) -> u8
where
    F: FnOnce(&mut dyn Write, &mut dyn Write) -> u8,
{
    let caught = panic::catch_unwind(AssertUnwindSafe(|| f(&mut *stdout, &mut *stderr)));
    match caught {
        Ok(code) => code,
        Err(payload) => {
            let location = panic_hook::take_location();
            // A formatter or writer panic while logging must not turn exit 70 into an abort or 101.
            let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                tracing::error!(
                    location = location.as_deref().unwrap_or("unknown"),
                    panic_message = %panic_hook::payload_text(&*payload),
                    "panic outside a check"
                );
            }));
            emit(&CliError::bug(), json, stdout, stderr)
        }
    }
}
