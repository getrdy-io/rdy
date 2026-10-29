//! The process entry point, in the order 02 ("Startup order") gives.
//!
//! 0. `harden_umask()` and the list of inherited descriptors, before anything is created or opened
//!    (M1-168, ADR 0023).
//! 1. The redactor, so nothing printed after this can leak. The descriptor warning, if any, follows
//!    it ([`crate::startup`]).
//! 2. The redacting log writer.
//! 3. The panic hook, which prints nothing ([`crate::panic_hook`]).
//! 4. [`crate::run`] inside [`guarded`], so that a panic outside a check exits 70, not 101 (07
//!    section 5), with the same error text as every other internal error.

use std::ffi::OsString;
use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};

use rdy_engine::exec;

use crate::error::{CliError, emit, wants_json};
use crate::{EXIT_INTERNAL, logging, panic_hook, redaction, run, startup};

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
    startup::warn_inherited(&inherited, &mut io::stderr());
    logging::init_stderr(redactor);
    panic_hook::install();
    let args: Vec<OsString> = std::env::args_os().collect();
    let json = wants_json(&args);
    guarded(
        json,
        &mut io::stdout(),
        &mut io::stderr(),
        |stdout, stderr| run(args, stdout, stderr),
    )
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
