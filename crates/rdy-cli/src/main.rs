//! The `rdy` binary. It is a thin wrapper: all behaviour is in the `rdy_cli` library (ADR 0011).

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(rdy_cli::entry::main_code())
}
