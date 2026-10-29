//! Repo tasks for rdy, run as `cargo xtask <command>` (alias in `.cargo/config.toml`).
//!
//! The commands write and check the generated files (the JSON schemas under `crates/rdy-spec/schema/`
//! and the pages under `docs/`), lint the tracked text files for dashes and banned tokens, and list
//! the registered checks with their title and remediation. `dist` and `publish` are off until their
//! tickets land.
//! This crate is never published (docs/plan/09-docs-site.md, section 2).

#![forbid(unsafe_code)]

mod checks;
mod docs;
mod generate;
mod lint;
mod schema;
mod spec_reference;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// A check or the lint found a problem.
const EXIT_FOUND: u8 = 1;
/// Bad command line, or a command that is off in this build (CLAUDE.md, Output).
const EXIT_USAGE: u8 = 64;
/// Internal error (CLAUDE.md, Output).
const EXIT_INTERNAL: u8 = 70;

const DIST_OFF: &str = "xtask dist is off in this build. Nothing was packaged. Release packaging comes with ticket M1-007 (docs/plan/06-release-and-distribution.md).";
const PUBLISH_OFF: &str = "xtask publish is off in this build. Nothing was published. Crate publishing follows docs/adr/0007-crate-publishing-and-versioning.md. Ticket M2-015 wires it up.";

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Repo tasks for rdy. Run as `cargo xtask <command>`."
)]
struct Cli {
    /// Repo root to read and write. Defaults to this checkout. Tests point it at a temporary repo.
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write the JSON schema files generated from the rdy-spec types.
    Schema {
        /// Render in memory and fail on any difference from the files on disk. Writes nothing.
        #[arg(long)]
        check: bool,
    },
    /// Write the generated Markdown pages under docs/.
    Docs {
        /// Render in memory and fail on any difference from the pages on disk. Writes nothing.
        #[arg(long)]
        check: bool,
    },
    /// Fail on em dashes, en dashes and banned tokens in tracked text files, and on an empty check
    /// title or remediation.
    DocsLint,
    /// List each registered check with its id, family, title and remediation. Fail on an empty one.
    Checks,
    /// Off in this build. Refuses and exits 64.
    Dist,
    /// Off in this build. Refuses and exits 64.
    Publish,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // Help and version print to stdout and exit 0. Usage errors exit 64.
            // xtask is a repo tool, not the `rdy` binary: it takes no secrets, so clap's own text is fine.
            #[allow(clippy::disallowed_methods)]
            let _ = err.print();
            return ExitCode::from(if err.use_stderr() { EXIT_USAGE } else { 0 });
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("xtask: {err:#}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Runs the command and returns its exit code.
fn run(cli: Cli) -> Result<u8> {
    let root = match cli.root {
        Some(root) => root,
        None => default_root(),
    };
    let passed = match cli.command {
        Command::Schema { check } => schema::run(&root, check)?,
        Command::Docs { check } => docs::run(&root, check)?,
        Command::DocsLint => {
            // Run both, so one run reports every problem.
            let text = lint::run(&root)?;
            let registry = checks::registry()?;
            text & checks::report(&checks::ordered(&registry))
        }
        Command::Checks => checks::run()?,
        Command::Dist => return Ok(refuse(DIST_OFF)),
        Command::Publish => return Ok(refuse(PUBLISH_OFF)),
    };
    Ok(if passed { 0 } else { EXIT_FOUND })
}

/// Prints why a command is off and returns the usage exit code.
fn refuse(message: &str) -> u8 {
    eprintln!("{message}");
    EXIT_USAGE
}

/// The repo root: two levels above this crate's manifest (`crates/xtask`).
fn default_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}
