//! Test helper for `tests/prompt_pty.rs`. It is not a rdy command and is not shipped.
//!
//! Usage: `prompt_probe confirm|confirm-yes|password`. It asks through the real
//! `StdTerminal` and prints the result on stdout. For `password` it prints only the length and
//! whether the text equals `RDY_PROBE_EXPECT`, never the text itself. On a prompt error it prints
//! the `error:` and `fix:` lines on stderr and exits with the error's exit code.

use std::process::ExitCode;

use rdy_cli::prompt::Prompter;

const CONFIRM_FIX: &str = "check the key's fingerprint with the vendor, then run again with --yes";
const PASSWORD_FIX: &str = "use --password-file or the RDY_KEY_PASSWORD variable";

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let mut prompter = Prompter::stdio();
    let outcome = match mode.as_str() {
        "confirm" | "confirm-yes" => prompter
            .confirm(
                "Trust this key for acme-platform?",
                mode == "confirm-yes",
                CONFIRM_FIX,
            )
            .map(|yes| println!("answer={yes}")),
        "password" => prompter
            .password("Password (input hidden): ", PASSWORD_FIX)
            .map(|secret| {
                let expected = std::env::var("RDY_PROBE_EXPECT").unwrap_or_default();
                println!(
                    "len={} match={}",
                    secret.expose().len(),
                    secret.expose() == expected
                );
            }),
        _ => return ExitCode::from(rdy_cli::EXIT_USAGE),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => ExitCode::from(err.report(&mut std::io::stderr())),
    }
}
