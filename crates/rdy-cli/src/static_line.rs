//! The static "Running N checks..." line (07 section 3, M1-088).
//!
//! The core build prints one line on stderr before the first check and clears it before the check
//! list, so a terminal that is busy for a few seconds does not look hung. It is never needed to read a
//! result and it never touches stdout.
//!
//! It prints only when stderr is a terminal, `TERM` is not `dumb`, and none of `--quiet`, `--verbose`,
//! `--progress never` (or `RDY_PROGRESS=never`) and `RUST_LOG` is set. The `--verbose` rule comes from
//! M1-143 (PR #68), which prints event lines on stderr while the checks run. `RUST_LOG` makes the log
//! write there too, and either would tear the line.
//!
//! The clear is a carriage return, spaces and a carriage return. It uses no escape sequence on
//! purpose: stderr goes through anstream, which strips escape sequences when colour is off, and a
//! stripped clear would leave the line on the screen.
//!
//! **Retired by the live line.** The live line of M1-142 (PR #60) also prints "Running N checks", so
//! whichever of PR #60 and PR #82 merges second deletes this file, `static_line/tests.rs`,
//! `tests/run_static_line_pty.rs` and the gate call in `run_cmd` (PC-54 in 13). M1-088's static-line
//! clause is then retired, and `tests/run_progress_pty.rs` of PR #60 holds the proof for a pipe,
//! `--quiet` and `TERM=dumb`. The `--verbose` part of the gate moves with M1-143 (PR #68).

use std::io::Write;

use crate::cli::ProgressChoice;

/// How much the run prints (`--quiet`, `--verbose`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detail {
    /// Neither flag.
    Normal,
    /// `--quiet`.
    Quiet,
    /// `--verbose`.
    Verbose,
}

impl Detail {
    /// The two flags clap keeps apart (`conflicts_with`).
    pub(crate) fn from_flags(quiet: bool, verbose: bool) -> Self {
        if quiet {
            Self::Quiet
        } else if verbose {
            Self::Verbose
        } else {
            Self::Normal
        }
    }
}

/// Everything the decision reads. Built by the caller so a test can pin each field.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gate {
    /// stderr is a terminal.
    pub(crate) terminal: bool,
    /// `TERM` is `dumb`.
    pub(crate) term_dumb: bool,
    /// `RUST_LOG` is set to a non-empty value.
    pub(crate) rust_log: bool,
    /// `--quiet` or `--verbose`.
    pub(crate) detail: Detail,
    /// `--progress` (and `RDY_PROGRESS`).
    pub(crate) progress: ProgressChoice,
}

impl Gate {
    /// Reads the flags, the stream and `TERM` as given, and `RUST_LOG` from the process.
    pub(crate) fn new(
        progress: ProgressChoice,
        detail: Detail,
        terminal: bool,
        term_dumb: bool,
    ) -> Self {
        Self {
            terminal,
            term_dumb,
            rust_log: std::env::var_os("RUST_LOG").is_some_and(|v| !v.is_empty()),
            detail,
            progress,
        }
    }

    /// Whether the line may print.
    pub(crate) fn allows(self) -> bool {
        self.terminal
            && !self.term_dumb
            && !self.rust_log
            && self.detail == Detail::Normal
            && self.progress != ProgressChoice::Never
    }
}

/// The line, printed or not. A guard: when it is dropped with the line still on screen (a panic, an
/// early return), the drop clears it on the process stderr, so the next text starts at column 0.
#[derive(Debug)]
pub(crate) struct StaticLine {
    /// The number of cells the line took, `None` when nothing was printed or it is cleared.
    shown: Option<usize>,
}

impl StaticLine {
    /// Prints `Running N checks...` when the gate allows, and returns the guard that clears it.
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

impl Drop for StaticLine {
    fn drop(&mut self) {
        self.clear(&mut std::io::stderr());
    }
}

/// `Running 8 checks...`, and `Running 1 check...`.
fn text(total: usize) -> String {
    let noun = if total == 1 { "check" } else { "checks" };
    format!("Running {total} {noun}...")
}

#[cfg(test)]
mod tests;
