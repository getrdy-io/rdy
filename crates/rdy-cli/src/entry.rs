//! The process entry point, in the order 02 ("Startup order") gives.
//!
//! 1. The redactor, so nothing printed after this can leak.
//! 2. The redacting log writer.
//! 3. The panic hook.
//! 4. [`crate::run`], with a catch so that a panic outside a check exits 70, not 101 (07 section 5).

use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};

use crate::{EXIT_INTERNAL, logging, panic_hook, redaction, run};

/// Runs rdy as the binary does and returns the exit code.
#[must_use]
pub fn main_code() -> u8 {
    let redactor = match redaction::init() {
        Ok(redactor) => redactor.clone(),
        Err(err) => {
            // A fixed message with a fix line. It holds no input, so it needs no redaction.
            let _ = writeln!(io::stderr(), "error: {err}");
            return EXIT_INTERNAL;
        }
    };
    logging::init_stderr(redactor.clone());
    panic_hook::install(redactor, Box::new(|| Box::new(io::stderr())));
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
        run(std::env::args_os(), &mut io::stdout(), &mut io::stderr())
    }));
    // The hook has already printed the redacted text.
    caught.unwrap_or(EXIT_INTERNAL)
}
