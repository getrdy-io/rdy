//! The `rdy` binary. It is a thin wrapper: all behaviour is in the `rdy_cli` library (ADR 0011).

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = rdy_cli::run(
        std::env::args_os(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    ExitCode::from(code)
}
