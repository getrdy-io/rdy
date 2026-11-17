//! The static "Running N checks..." line (07 section 3, M1-088).
//!
//! The core build prints one line on stderr before the first check and clears it before the check
//! list, so a terminal that is busy for a few seconds does not look hung. It is never needed to read a
//! result and it never touches stdout.
//!
//! It prints only when stderr is a terminal, `TERM` is not `dumb`, and none of `--quiet`, `--verbose`,
//! `--progress never` (or `RDY_PROGRESS=never`) and `RUST_LOG` is set. `--verbose` prints its own event
//! lines on stderr while the checks run, and `RUST_LOG` makes the log write there, so either would
//! tear the line.
//!
//! The clear is a carriage return, spaces and a carriage return. It uses no escape sequence on
//! purpose: stderr goes through anstream, which strips escape sequences when colour is off, and a
//! stripped clear would leave the line on the screen.
//!
//! The live line of M1-142 replaces this one. Whichever of the two lands second removes the call in
//! `run_cmd`, so the two never draw together.

use std::io::Write;

use crate::cli::ProgressChoice;

/// Everything the decision reads. Built by the caller so a test can pin each field.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Gate {
    /// stderr is a terminal.
    pub(crate) terminal: bool,
    /// `TERM` is `dumb`.
    pub(crate) term_dumb: bool,
    /// `--quiet`.
    pub(crate) quiet: bool,
    /// `--verbose`.
    pub(crate) verbose: bool,
    /// `--progress never` or `RDY_PROGRESS=never`.
    pub(crate) progress_never: bool,
    /// `RUST_LOG` is set to a non-empty value.
    pub(crate) rust_log: bool,
}

impl Gate {
    /// Reads the flags, the stream and `TERM` as given, and `RUST_LOG` from the process.
    pub(crate) fn new(
        choice: ProgressChoice,
        quiet: bool,
        verbose: bool,
        terminal: bool,
        term_dumb: bool,
    ) -> Self {
        Self {
            terminal,
            term_dumb,
            quiet,
            verbose,
            progress_never: choice == ProgressChoice::Never,
            rust_log: std::env::var_os("RUST_LOG").is_some_and(|v| !v.is_empty()),
        }
    }

    /// Whether the line may print.
    pub(crate) fn allows(self) -> bool {
        self.terminal
            && !self.term_dumb
            && !self.quiet
            && !self.verbose
            && !self.progress_never
            && !self.rust_log
    }
}

/// The line, printed or not.
#[derive(Debug)]
pub(crate) struct StaticLine {
    /// The number of cells the line took, `None` when nothing was printed or it is cleared.
    shown: Option<usize>,
}

impl StaticLine {
    /// Prints `Running N checks...` when the gate allows, and returns the handle that clears it.
    pub(crate) fn show(gate: Gate, total: usize, stderr: &mut dyn Write) -> Self {
        if !gate.allows() {
            return Self { shown: None };
        }
        let text = text(total);
        let wrote = stderr
            .write_all(text.as_bytes())
            .and_then(|()| stderr.flush())
            .is_ok();
        Self {
            shown: wrote.then_some(text.len()),
        }
    }

    /// Clears the line, so the next write starts at column 0 of an empty line. Does nothing twice.
    pub(crate) fn clear(&mut self, stderr: &mut dyn Write) {
        if let Some(len) = self.shown.take() {
            let blank = format!("\r{}\r", " ".repeat(len));
            let _ = stderr
                .write_all(blank.as_bytes())
                .and_then(|()| stderr.flush());
        }
    }
}

/// `Running 8 checks...`, and `Running 1 check...`.
fn text(total: usize) -> String {
    let noun = if total == 1 { "check" } else { "checks" };
    format!("Running {total} {noun}...")
}

#[cfg(test)]
mod tests;
