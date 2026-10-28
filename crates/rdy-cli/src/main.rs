//! The `rdy` binary.
//!
//! This is the skeleton from M1-003. It has the `version` command and `--version`. The command tree
//! grows in later tickets and moves into the `rdy_cli` library target (ADR 0011).

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// `<version> (<commit> <date>)`, built by `build.rs`.
const VERSION: &str = env!("RDY_VERSION");

/// Exit code for an internal error (CLAUDE.md, Output).
const EXIT_INTERNAL: u8 = 70;

#[derive(Parser)]
#[command(name = "rdy", version = VERSION, about = "Check an environment against a vendor's requirements before install day")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the version
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => match writeln!(std::io::stdout(), "rdy {VERSION}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(EXIT_INTERNAL),
        },
    }
}
