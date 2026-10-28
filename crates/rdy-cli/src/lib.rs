//! The `rdy` command line, as a library.
//!
//! The binary in `src/main.rs` is a thin wrapper around [`run`]. Tests and the docs CLI reference
//! use the same code (ADR 0011).
//!
//! This is the M1 command tree (M1-029). Only `rdy version` does its job. Every other command
//! prints "not yet implemented in this build" and exits 70 until its own ticket lands.
//!
//! Exit codes (CLAUDE.md, Output): clap's own exit code is 2, but in rdy 2 means NOT READY. So rdy
//! parses with [`clap::Parser::try_parse_from`] and maps the outcome itself. Help and version go to
//! stdout with exit 0. Every other parse failure prints two lines on stderr and exits 64.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Write;

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction, CommandFactory, FromArgMatches};

pub mod cli;

use cli::{Cli, Commands, SpecCommand, TrustCommand, VERSION};

/// Exit code for success.
pub const EXIT_OK: u8 = 0;

/// Exit code for a usage error (ADR 0008).
pub const EXIT_USAGE: u8 = 64;

/// Exit code for an internal error (ADR 0008).
pub const EXIT_INTERNAL: u8 = 70;

/// The clap command tree, for the docs CLI reference and for tests.
#[must_use]
pub fn command() -> clap::Command {
    // clap's own `-V` text is "Print version". 07 Appendix A says "Print the version", so the flag
    // is declared here. It sorts last, after `-h`.
    Cli::command().arg(
        Arg::new("version")
            .short('V')
            .long("version")
            .action(ArgAction::Version)
            .help("Print the version")
            .display_order(1000),
    )
}

/// Parse `args` (the first item is the program name), run the command and return the exit code.
///
/// This does what `Parser::try_parse_from` does, so that [`command`] can add the `-V` flag.
///
/// Output goes to `stdout` and `stderr`, never to the process streams directly. If a stream cannot
/// be written, the exit code is 70.
pub fn run<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let parsed = command()
        .try_get_matches_from(args)
        .and_then(|matches| Cli::from_arg_matches(&matches));
    match parsed {
        Ok(cli) => dispatch(&cli.command, stdout, stderr),
        Err(err) => report_parse_error(&err, stdout, stderr),
    }
}

/// Run a parsed command.
fn dispatch(command: &Commands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    match command {
        Commands::Version(args) if !args.json => finish(writeln!(stdout, "rdy {VERSION}"), stderr),
        // `version --json` waits for the Version schema (07 section 4.3).
        Commands::Version(_) => not_implemented("version --json", stderr),
        Commands::Help { command } => show_help(command, stdout, stderr),
        Commands::Run(_) => not_implemented("run", stderr),
        Commands::Verify(_) => not_implemented("verify", stderr),
        Commands::Spec { command } => match command {
            SpecCommand::Lint(_) => not_implemented("spec lint", stderr),
            SpecCommand::Sign(_) => not_implemented("spec sign", stderr),
            SpecCommand::Keygen(_) => not_implemented("spec keygen", stderr),
        },
        Commands::Trust { command } => match command {
            TrustCommand::Add(_) => not_implemented("trust add", stderr),
            TrustCommand::List => not_implemented("trust list", stderr),
            TrustCommand::Remove(_) => not_implemented("trust remove", stderr),
        },
    }
}

/// `rdy help [COMMAND]...`: print the full help of a command, as `COMMAND --help` does.
fn show_help(path: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut root = command();
    root.build();
    let mut current = &mut root;
    for name in path {
        match current.find_subcommand_mut(name) {
            Some(next) => current = next,
            None => {
                // The name is not echoed: it is what the user typed.
                let _ = writeln!(stderr, "error: unknown command\nfix: see 'rdy --help'");
                return EXIT_USAGE;
            }
        }
    }
    let text = current.render_long_help().to_string();
    finish(write!(stdout, "{text}"), stderr)
}

/// Map a write result to an exit code. A failed write on stdout is an internal error.
fn finish(written: std::io::Result<()>, stderr: &mut dyn Write) -> u8 {
    match written {
        Ok(()) => EXIT_OK,
        Err(_) => {
            // Best effort: stderr may be the broken stream too.
            let _ = writeln!(
                stderr,
                "error: rdy could not write its output\nfix: check that the output is not closed or full"
            );
            EXIT_INTERNAL
        }
    }
}

/// The error for a command a later ticket implements. Exit 70, with a fix line.
fn not_implemented(name: &str, stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stderr,
        "error: rdy {name} is not yet implemented in this build\n\
         fix: use a later release of rdy, listed at https://github.com/getrdy-io/rdy/releases"
    );
    EXIT_INTERNAL
}

/// Print a clap error the rdy way and return the exit code.
///
/// Help, version and "no subcommand given" print on stdout and exit 0. Everything else is a usage
/// error: two lines on stderr and exit 64.
fn report_parse_error(err: &clap::Error, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    match err.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            let text = err.render().to_string();
            finish(write!(stdout, "{text}"), stderr)
        }
        kind => {
            let (message, fix) = usage_lines(kind, err);
            let _ = writeln!(stderr, "error: {message}\nfix: {fix}");
            EXIT_USAGE
        }
    }
}

/// The two lines of a usage error.
///
/// Nothing the user typed is echoed. The only text taken from clap is the name of an argument as
/// the command tree defines it (such as `--color <WHEN>`) and the command path in the usage line.
/// M1-030 adds the flag name and the did-you-mean under the no-echo rule of 07 section 1.
fn usage_lines(kind: ErrorKind, err: &clap::Error) -> (String, String) {
    let fix = format!("see '{} --help'", command_path(err));
    let message = match kind {
        ErrorKind::MissingRequiredArgument => match defined_arg(err) {
            Some(arg) => format!("missing required argument {arg}"),
            None => "missing a required argument".to_string(),
        },
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => match defined_arg(err) {
            Some(arg) => format!("invalid value for {arg}"),
            None => "invalid value for an option".to_string(),
        },
        ErrorKind::UnknownArgument => "unknown option or argument".to_string(),
        ErrorKind::InvalidSubcommand => "unknown command".to_string(),
        ErrorKind::ArgumentConflict => "two options cannot be used together".to_string(),
        ErrorKind::MissingSubcommand => "missing a command".to_string(),
        _ => "the command line is not valid".to_string(),
    };
    (message, fix)
}

/// The name of the argument the error is about, when clap defines it (not when the user typed it).
fn defined_arg(err: &clap::Error) -> Option<String> {
    match err.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(name)) => Some(name.clone()),
        Some(ContextValue::Strings(names)) => Some(names.join(", ")),
        _ => None,
    }
}

/// The command path, such as `rdy spec sign`, read from the usage line clap builds from the tree.
///
/// The words of a usage line run from the program name up to the first `[`, `<` or `-` token.
fn command_path(err: &clap::Error) -> String {
    let usage = match err.get(ContextKind::Usage) {
        Some(ContextValue::StyledStr(text)) => text.to_string(),
        _ => return "rdy".to_string(),
    };
    let words: Vec<&str> = usage
        .trim()
        .strip_prefix("Usage:")
        .unwrap_or("")
        .split_whitespace()
        .take_while(|w| !w.starts_with(['[', '<', '-']))
        .collect();
    if words.first() == Some(&"rdy") {
        words.join(" ")
    } else {
        "rdy".to_string()
    }
}
