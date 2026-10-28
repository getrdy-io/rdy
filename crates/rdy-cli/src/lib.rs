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

#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod password;

#[doc(hidden)]
pub mod prompt;

use cli::{Cli, Commands, SpecCommand, TrustCommand, VERSION};
use error::{CliError, InternalKind, emit};
use rdy_spec::result::{ExitCode, VersionInfo};

/// Exit code for success.
pub const EXIT_OK: u8 = ExitCode::Ready.code();

/// Exit code for a usage error (ADR 0008).
pub const EXIT_USAGE: u8 = ExitCode::Usage.code();

/// Exit code for an internal error (ADR 0008).
pub const EXIT_INTERNAL: u8 = ExitCode::Internal.code();

/// The clap command tree, for the docs CLI reference and for tests.
///
/// The binary name is fixed to `rdy`, so help reads the same when argv[0] is `rdy.exe`.
#[doc(hidden)]
#[must_use]
pub fn command() -> clap::Command {
    // clap's own `-V` text is "Print version". 07 Appendix A says "Print the version", so the flag
    // is declared here. It sorts last, after `-h`.
    Cli::command().bin_name("rdy").arg(
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
///
/// This is the one entry point (ADR 0011 decision 4). It returns the exit code as a `u8` for now.
/// M1-074 gives it the `Backend` and `RunHooks` parameters and an `ExitCode` result.
#[doc(hidden)]
pub fn run<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    // Read from the raw arguments, so that even a command line that does not parse can answer in JSON.
    let json = error::wants_json(&args);
    // A password on argv is refused before clap sees it, so that the refusal wins over every other
    // usage error and the value is never parsed (07 section 10).
    if password::argv_has_password_flag(&args) && takes_key_password(&command_path(&args)) {
        return emit(&password::argv_refusal(), json, stdout, stderr);
    }
    let parsed = command()
        .try_get_matches_from(&args)
        .and_then(|matches| Cli::from_arg_matches(&matches));
    match parsed {
        Ok(cli) => dispatch(&cli.command, json, stdout, stderr),
        Err(err) => report_parse_error(&err, &args, json, stdout, stderr),
    }
}

/// True for the commands that read a key password: `spec sign` and `spec keygen`.
fn takes_key_password(path: &str) -> bool {
    matches!(path, "rdy spec sign" | "rdy spec keygen")
}

/// Run a parsed command.
fn dispatch(command: &Commands, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    match command {
        Commands::Version(args) if !args.json => finish(writeln!(stdout, "rdy {VERSION}"), stderr),
        Commands::Help { command } => show_help(command, json, stdout, stderr),
        Commands::Version(_) => finish(write!(stdout, "{}", version_json()), stderr),
        Commands::Run(_) => not_implemented("run", json, stdout, stderr),
        Commands::Verify(_) => not_implemented("verify", json, stdout, stderr),
        Commands::Spec { command } => match command {
            SpecCommand::Lint(_) => not_implemented("spec lint", json, stdout, stderr),
            SpecCommand::Sign(_) => not_implemented("spec sign", json, stdout, stderr),
            SpecCommand::Keygen(_) => not_implemented("spec keygen", json, stdout, stderr),
        },
        Commands::Trust { command } => match command {
            TrustCommand::Add(_) => not_implemented("trust add", json, stdout, stderr),
            TrustCommand::List => not_implemented("trust list", json, stdout, stderr),
            TrustCommand::Remove(_) => not_implemented("trust remove", json, stdout, stderr),
        },
    }
}

/// The text of `rdy version --json`: one object with a final newline (07 sections 4.3 and C.11).
///
/// `commit` and `date` are `null` when the build had no trustworthy git information. The characters
/// `<`, `>` and `&` are escaped, as in every other JSON object rdy prints, so the text is safe inside
/// HTML.
fn version_json() -> String {
    let known = |text: &str| (!text.is_empty()).then(|| text.to_owned());
    let mut info = VersionInfo::new(env!("CARGO_PKG_VERSION"), cli::TARGET, rdy_spec::VERSION);
    info.commit = known(cli::COMMIT);
    info.date = known(cli::COMMIT_DATE);
    // The object holds short strings only, so serializing cannot fail. If it ever did, an empty
    // object is still valid JSON for a reader that checks the exit code first.
    let text = serde_json::to_string_pretty(&info).unwrap_or_else(|_| "{}".to_owned());
    let mut out = text
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    out.push('\n');
    out
}

/// `rdy help [COMMAND]...`: print the full help of a command, as `COMMAND --help` does.
fn show_help(path: &[String], json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut root = command();
    root.build();
    let mut current = &mut root;
    for name in path {
        match current.find_subcommand_mut(name) {
            Some(next) => current = next,
            None => {
                // The name is not echoed: it is what the user typed.
                let err = CliError::usage("unknown command", "see 'rdy --help'");
                return emit(&err, json, stdout, stderr);
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
            // Best effort: stderr may be the broken stream too. Stdout is the broken one, so the
            // error object has nowhere to go.
            let err = CliError::Internal(InternalKind::OutputClosed);
            emit(&err, false, &mut std::io::sink(), stderr)
        }
    }
}

/// The error for a command a later ticket implements. Exit 70, with a fix line.
fn not_implemented(
    command: &'static str,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let err = CliError::Internal(InternalKind::NotImplemented { command });
    emit(&err, json, stdout, stderr)
}

/// Print a clap error the rdy way and return the exit code.
///
/// Help, version and "no subcommand given" print on stdout and exit 0. Everything else is a usage
/// error: two lines on stderr and exit 64.
fn report_parse_error(
    err: &clap::Error,
    args: &[OsString],
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match err.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            let text = err.render().to_string();
            finish(write!(stdout, "{text}"), stderr)
        }
        kind => {
            let (message, fix) = usage_lines(kind, err, args);
            emit(&CliError::usage(message, fix), json, stdout, stderr)
        }
    }
}

/// The two lines of a usage error.
///
/// Nothing the user typed is echoed. The only text taken from clap is the name of an argument as
/// the command tree defines it (such as `--color <WHEN>`). The command path in the fix line comes
/// from walking the arguments through the command tree, so it holds only names from the tree.
/// M1-030 adds the flag name and the did-you-mean under the no-echo rule of 07 section 1.
fn usage_lines(kind: ErrorKind, err: &clap::Error, args: &[OsString]) -> (String, String) {
    let mut fix = format!("see '{} --help'", command_path(args));
    let arg = defined_arg(err);
    let message = match kind {
        ErrorKind::MissingRequiredArgument => match arg {
            Some(arg) => format!("missing required argument {arg}"),
            None => "missing a required argument".to_string(),
        },
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let named = |a: &str| arg.as_deref().is_some_and(|x| x.starts_with(a));
            if named("--progress") && !on_argv(args, "--progress") {
                // The bad value came from the environment, not from a flag.
                fix = "set RDY_PROGRESS to auto or never, or unset it".to_string();
                "RDY_PROGRESS has an invalid value".to_string()
            } else if value_is_missing(err) {
                match arg {
                    Some(arg) => format!("missing a value for {arg}"),
                    None => "missing a value for an option".to_string(),
                }
            } else {
                match arg {
                    Some(arg) => format!("invalid value for {arg}"),
                    None => "invalid value for an option".to_string(),
                }
            }
        }
        ErrorKind::UnknownArgument => "unknown option or argument".to_string(),
        ErrorKind::InvalidSubcommand => "unknown command".to_string(),
        ErrorKind::ArgumentConflict => match (&arg, prior_arg(err)) {
            (Some(arg), Some(prior)) if *arg == prior => {
                format!("{arg} can be used only once")
            }
            _ => "two options cannot be used together".to_string(),
        },
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

/// The earlier argument a conflict names, as the command tree defines it.
fn prior_arg(err: &clap::Error) -> Option<String> {
    match err.get(ContextKind::PriorArg) {
        Some(ContextValue::String(name)) => Some(name.clone()),
        _ => None,
    }
}

/// True when clap found the flag but no value after it.
fn value_is_missing(err: &clap::Error) -> bool {
    matches!(err.get(ContextKind::InvalidValue), Some(ContextValue::String(v)) if v.is_empty())
}

/// True when the long flag `name` (such as `--progress`) is on the command line before any `--`.
fn on_argv(args: &[OsString], name: &str) -> bool {
    args.iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .filter_map(|a| a.to_str())
        .any(|a| a == name || a.strip_prefix(name).is_some_and(|r| r.starts_with('=')))
}

/// The command path, such as `rdy spec sign`, found by walking `args` through the command tree.
///
/// A word that names a subcommand of the current command moves down one level. A long flag that
/// takes a value skips the word after it. Only names from the tree reach the result, never what
/// the user typed. The binary name is always `rdy`, whatever argv[0] was.
fn command_path(args: &[OsString]) -> String {
    let mut root = command();
    root.build();
    let mut current = &root;
    let mut path = vec!["rdy".to_string()];
    let mut words = args.iter().skip(1).filter_map(|a| a.to_str());
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let takes_value = !long.contains('=')
                && current
                    .get_arguments()
                    .find(|a| a.get_long() == Some(long))
                    .is_some_and(|a| a.get_action().takes_values());
            if takes_value {
                words.next();
            }
        } else if !word.starts_with('-')
            && let Some(sub) = current.find_subcommand(word)
        {
            path.push(sub.get_name().to_string());
            current = sub;
        }
    }
    path.join(" ")
}
