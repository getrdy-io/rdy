//! Prompts: a y/N question and a hidden password read (07 section 7 rule 7, Appendix C.9 and C.10).
//!
//! Rules this module keeps:
//!
//! - A question ends in ` [y/N] ` and the default is No. Only `y` or `yes` (any case) is a yes.
//!   An empty line, any other text and end of input are all a No.
//! - Prompts go to stderr, never stdout, so `--json` output stays clean.
//! - With no terminal, a question is refused with an `error:` line and a `fix:` line, and exit 64.
//!   The one way past that is the caller's `--yes`, which skips the question.
//! - A password is read with echo off. Nothing the user types is written back, logged or put in an
//!   error. [`Secret`] has no `Display` and its `Debug` shows no text.
//! - A line of input is capped at 4096 bytes. The rest of an over-long line is read and dropped, so
//!   it cannot become the answer to the next prompt.
//!
//! The logic sits behind the [`Terminal`] trait. [`StdTerminal`] is the real keyboard and stderr.
//! Unit tests use a scripted terminal, so they need no TTY. On Unix, `tests/prompt_pty.rs` also
//! drives [`StdTerminal`] through a real pseudo-terminal (Linux and macOS CI legs): `y`, `yes`, `n`,
//! an empty line, end of input, no terminal, and a password that is never echoed. Windows has no pty
//! test. The scripted-terminal unit tests cover the logic there, and `rpassword` does the console
//! work.
//!
//! A declined question is not an error here: [`Prompter::confirm`] returns `Ok(false)`. The caller
//! decides what that means. `trust add` prints `Not trusted. Nothing was changed.` and exits 64
//! (ADR 0002 decision 5).
//!
//! Text passed in as a question or a fix line is printed as given. A caller that includes text from
//! argv or from a file must escape it first (07 section 9).

use std::io::{self, BufRead, IsTerminal, Write};

use zeroize::Zeroizing;

/// The most bytes read from one line of an answer. Longer lines are cut, and the rest is dropped.
const MAX_LINE: usize = 4096;

/// A secret read from the user, such as a key password.
///
/// It has no `Display` and no `Clone`. `Debug` prints no text, so it cannot reach a log by accident.
/// The text is wiped from memory when the value is dropped.
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap secret text. The text is wiped when the [`Secret`] is dropped.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// The secret text. Use it, then drop the [`Secret`]. Never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// True when nothing was typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Why a prompt could not be shown or read.
#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    /// A question was needed, but there is no terminal and the caller did not pass `--yes`.
    #[error("cannot ask for confirmation because there is no terminal")]
    NoTerminalConfirm {
        /// The fix line, such as "check the key's fingerprint with the vendor, then run again with --yes".
        fix: String,
    },
    /// A password prompt was needed, but there is no terminal.
    #[error("cannot ask for a password because there is no terminal")]
    NoTerminalPassword {
        /// The fix line, such as "use --password-file or the RDY_KEY_PASSWORD variable".
        fix: String,
    },
    /// The terminal could not be read or written. The OS error is kept as the source, not printed.
    #[error("could not read your answer from the terminal")]
    Io(#[source] io::Error),
}

impl PromptError {
    /// The fix line for this error.
    #[must_use]
    pub fn fix(&self) -> &str {
        match self {
            Self::NoTerminalConfirm { fix } | Self::NoTerminalPassword { fix } => fix,
            Self::Io(_) => "check that the terminal is still open, then run the command again",
        }
    }

    /// The exit code for this error: 64 when there is no terminal (ADR 0008), 70 for an I/O failure.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NoTerminalConfirm { .. } | Self::NoTerminalPassword { .. } => crate::EXIT_USAGE,
            Self::Io(_) => crate::EXIT_INTERNAL,
        }
    }

    /// Write the two-line `error:` and `fix:` message to `stderr` and return the exit code.
    ///
    /// A write failure is ignored: stderr may be the broken stream, and the exit code still says
    /// what happened.
    pub fn report(&self, stderr: &mut dyn Write) -> u8 {
        let _ = writeln!(stderr, "error: {self}\nfix: {}", self.fix());
        self.exit_code()
    }
}

/// The keyboard and the prompt stream, as the prompts see them.
pub trait Terminal {
    /// True when a person can answer: input and the prompt stream are both terminals.
    fn is_interactive(&self) -> bool;

    /// Write prompt text (to stderr) and flush it.
    ///
    /// # Errors
    /// Returns the I/O error if the stream cannot be written.
    fn write_prompt(&mut self, text: &str) -> io::Result<()>;

    /// Read one line of visible input, without its line ending. `None` means end of input.
    ///
    /// # Errors
    /// Returns the I/O error if the input cannot be read.
    fn read_line(&mut self) -> io::Result<Option<String>>;

    /// Read one line with echo off, without its line ending.
    ///
    /// The typed text is never shown. When the line is done the cursor is at the start of a new
    /// line, so the implementation ends the line itself (the Enter key is not echoed either).
    ///
    /// # Errors
    /// Returns the I/O error if the terminal cannot be read or its mode cannot be changed.
    fn read_hidden(&mut self) -> io::Result<Secret>;
}

/// The real terminal: stdin for answers, the controlling terminal for hidden input, stderr for prompts.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdTerminal;

impl Terminal for StdTerminal {
    fn is_interactive(&self) -> bool {
        io::stdin().is_terminal() && io::stderr().is_terminal()
    }

    fn write_prompt(&mut self, text: &str) -> io::Result<()> {
        let mut err = io::stderr().lock();
        err.write_all(text.as_bytes())?;
        err.flush()
    }

    fn read_line(&mut self) -> io::Result<Option<String>> {
        read_bounded_line(&mut io::stdin().lock())
    }

    fn read_hidden(&mut self) -> io::Result<Secret> {
        // rpassword turns echo off on the controlling terminal and restores it when it is done,
        // including on an error.
        rpassword::read_password().map(Secret::new)
    }
}

/// Asks questions and reads passwords through a [`Terminal`].
#[derive(Debug)]
pub struct Prompter<T: Terminal> {
    term: T,
}

impl Prompter<StdTerminal> {
    /// A prompter on the real terminal.
    #[must_use]
    pub fn stdio() -> Self {
        Self::new(StdTerminal)
    }
}

impl<T: Terminal> Prompter<T> {
    /// A prompter on `term`.
    #[must_use]
    pub fn new(term: T) -> Self {
        Self { term }
    }

    /// Ask `question` and return true only for `y` or `yes`.
    ///
    /// `question` is a plain question without the `[y/N]` suffix, such as
    /// `Trust this key for acme-platform?`. This adds ` [y/N] `.
    ///
    /// - With `assume_yes` (the caller's `--yes`) nothing is asked and the result is true.
    /// - With no terminal, the result is [`PromptError::NoTerminalConfirm`] carrying `fix`.
    /// - An empty line, other text, or end of input is `Ok(false)`.
    ///
    /// # Errors
    /// [`PromptError::NoTerminalConfirm`] when there is no terminal and `assume_yes` is false.
    /// [`PromptError::Io`] when the prompt cannot be written or the answer cannot be read.
    pub fn confirm(
        &mut self,
        question: &str,
        assume_yes: bool,
        fix: &str,
    ) -> Result<bool, PromptError> {
        if assume_yes {
            return Ok(true);
        }
        if !self.term.is_interactive() {
            return Err(PromptError::NoTerminalConfirm {
                fix: fix.to_string(),
            });
        }
        self.term
            .write_prompt(&format!("{question} [y/N] "))
            .map_err(PromptError::Io)?;
        match self.term.read_line().map_err(PromptError::Io)? {
            Some(line) => Ok(is_yes(&line)),
            None => {
                // End of input (Ctrl-D). End the prompt line so the shell prompt starts clean.
                self.term.write_prompt("\n").map_err(PromptError::Io)?;
                Ok(false)
            }
        }
    }

    /// Show `prompt` (such as `Password for acme-signing.key (input hidden): `) and read a password
    /// with echo off.
    ///
    /// # Errors
    /// [`PromptError::NoTerminalPassword`] carrying `fix` when there is no terminal.
    /// [`PromptError::Io`] when the prompt cannot be written or the password cannot be read.
    pub fn password(&mut self, prompt: &str, fix: &str) -> Result<Secret, PromptError> {
        if !self.term.is_interactive() {
            return Err(PromptError::NoTerminalPassword {
                fix: fix.to_string(),
            });
        }
        self.term.write_prompt(prompt).map_err(PromptError::Io)?;
        self.term.read_hidden().map_err(PromptError::Io)
    }
}

/// True for `y` or `yes` in any case, ignoring spaces and a trailing `\r`.
fn is_yes(line: &str) -> bool {
    let answer = line.trim();
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

/// Read one line, keep at most [`MAX_LINE`] bytes of it, and drop the rest of the line.
///
/// Returns `None` at end of input with nothing read. A last line without a line ending still counts.
/// Bytes that are not UTF-8 become U+FFFD, which is never a yes.
fn read_bounded_line(reader: &mut dyn BufRead) -> io::Result<Option<String>> {
    let mut line: Vec<u8> = Vec::new();
    let mut read_any = false;
    loop {
        let buf = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if buf.is_empty() {
            break;
        }
        read_any = true;
        let newline = buf.iter().position(|&b| b == b'\n');
        let chunk = &buf[..newline.unwrap_or(buf.len())];
        let room = MAX_LINE.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        let used = newline.map_or(buf.len(), |i| i + 1);
        reader.consume(used);
        if newline.is_some() {
            break;
        }
    }
    Ok(read_any.then(|| String::from_utf8_lossy(&line).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const FIX: &str = "check the key's fingerprint with the vendor, then run again with --yes";

    /// A terminal that needs no TTY. It records everything written to the prompt stream.
    struct Scripted {
        interactive: bool,
        input: Cursor<Vec<u8>>,
        hidden: Option<io::Result<&'static str>>,
        out: Vec<u8>,
        hidden_reads: usize,
    }

    impl Scripted {
        fn new(interactive: bool, input: &str) -> Self {
            Self {
                interactive,
                input: Cursor::new(input.as_bytes().to_vec()),
                hidden: None,
                out: Vec::new(),
                hidden_reads: 0,
            }
        }

        fn typing(input: &str) -> Prompter<Self> {
            Prompter::new(Self::new(true, input))
        }

        fn out(p: &Prompter<Self>) -> String {
            String::from_utf8_lossy(&p.term.out).into_owned()
        }
    }

    impl Terminal for Scripted {
        fn is_interactive(&self) -> bool {
            self.interactive
        }

        fn write_prompt(&mut self, text: &str) -> io::Result<()> {
            self.out.extend_from_slice(text.as_bytes());
            Ok(())
        }

        fn read_line(&mut self) -> io::Result<Option<String>> {
            read_bounded_line(&mut self.input)
        }

        fn read_hidden(&mut self) -> io::Result<Secret> {
            self.hidden_reads += 1;
            // Like the real terminal with echo off: the typed text is NOT written to `out`, but
            // the line is ended (rpassword writes the line break itself).
            self.out.extend_from_slice(b"\n");
            match self.hidden.take() {
                Some(Ok(text)) => Ok(Secret::new(text.to_string())),
                Some(Err(err)) => Err(err),
                None => Ok(Secret::new(String::new())),
            }
        }
    }

    #[test]
    fn y_and_yes_in_any_case_are_yes() {
        for answer in [
            "y\n", "Y\n", "yes\n", "YES\n", "Yes\n", " yes \n", "y\r\n", "y",
        ] {
            let mut p = Scripted::typing(answer);
            assert!(
                p.confirm("Trust this key?", false, FIX).unwrap(),
                "{answer:?}"
            );
        }
    }

    #[test]
    fn everything_else_is_no() {
        for answer in [
            "n\n",
            "N\n",
            "no\n",
            "\n",
            "\r\n",
            "   \n",
            "maybe\n",
            "yy\n",
            "yes please\n",
            "ye\n",
        ] {
            let mut p = Scripted::typing(answer);
            assert!(
                !p.confirm("Trust this key?", false, FIX).unwrap(),
                "{answer:?}"
            );
        }
    }

    #[test]
    fn question_gets_the_default_no_suffix() {
        let mut p = Scripted::typing("n\n");
        p.confirm("Trust this key for acme-platform?", false, FIX)
            .unwrap();
        assert_eq!(
            Scripted::out(&p),
            "Trust this key for acme-platform? [y/N] "
        );
    }

    #[test]
    fn end_of_input_is_no_and_ends_the_prompt_line() {
        let mut p = Scripted::typing("");
        assert!(!p.confirm("Trust this key?", false, FIX).unwrap());
        assert_eq!(Scripted::out(&p), "Trust this key? [y/N] \n");
    }

    #[test]
    fn invalid_utf8_is_no() {
        let mut term = Scripted::new(true, "");
        term.input = Cursor::new(vec![0xff, 0xfe, b'\n']);
        let mut p = Prompter::new(term);
        assert!(!p.confirm("Trust this key?", false, FIX).unwrap());
    }

    #[test]
    fn no_terminal_refuses_with_exit_64_and_the_fix_line() {
        let mut p = Prompter::new(Scripted::new(false, "y\n"));
        let err = p.confirm("Trust this key?", false, FIX).unwrap_err();
        assert!(matches!(err, PromptError::NoTerminalConfirm { .. }));
        assert_eq!(err.exit_code(), 64);

        let mut stderr = Vec::new();
        assert_eq!(err.report(&mut stderr), 64);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "error: cannot ask for confirmation because there is no terminal\n\
             fix: check the key's fingerprint with the vendor, then run again with --yes\n"
        );
        // Nothing was asked and the input was not read, even though it held a "y".
        assert_eq!(Scripted::out(&p), "");
        assert_eq!(p.term.input.position(), 0);
    }

    #[test]
    fn yes_flag_skips_the_question_without_a_terminal() {
        let mut p = Prompter::new(Scripted::new(false, ""));
        assert!(p.confirm("Trust this key?", true, FIX).unwrap());
        assert_eq!(Scripted::out(&p), "");
    }

    #[test]
    fn yes_flag_does_not_read_input_on_a_terminal() {
        let mut p = Scripted::typing("n\n");
        assert!(p.confirm("Trust this key?", true, FIX).unwrap());
        assert_eq!(Scripted::out(&p), "");
        assert_eq!(p.term.input.position(), 0);
    }

    #[test]
    fn a_long_line_is_no_and_does_not_leak_into_the_next_answer() {
        let long = "y".repeat(100_000);
        let mut p = Scripted::typing(&format!("{long}\ny\n"));
        // 4096 'y' bytes are not "y" or "yes".
        assert!(!p.confirm("First?", false, FIX).unwrap());
        assert!(p.confirm("Second?", false, FIX).unwrap());
    }

    #[test]
    fn bounded_line_keeps_the_cap_and_consumes_the_line() {
        let mut reader = Cursor::new(format!("{}\nnext\n", "a".repeat(MAX_LINE + 50)).into_bytes());
        let first = read_bounded_line(&mut reader).unwrap().unwrap();
        assert_eq!(first.len(), MAX_LINE);
        assert_eq!(
            read_bounded_line(&mut reader).unwrap().as_deref(),
            Some("next")
        );
        assert_eq!(read_bounded_line(&mut reader).unwrap(), None);
    }

    #[test]
    fn a_read_error_is_exit_70_with_a_fix() {
        struct Broken;
        impl Terminal for Broken {
            fn is_interactive(&self) -> bool {
                true
            }
            fn write_prompt(&mut self, _: &str) -> io::Result<()> {
                Ok(())
            }
            fn read_line(&mut self) -> io::Result<Option<String>> {
                Err(io::Error::other("boom"))
            }
            fn read_hidden(&mut self) -> io::Result<Secret> {
                Err(io::Error::other("boom"))
            }
        }
        let mut p = Prompter::new(Broken);
        let err = p.confirm("Trust this key?", false, FIX).unwrap_err();
        assert_eq!(err.exit_code(), 70);
        let mut stderr = Vec::new();
        err.report(&mut stderr);
        let text = String::from_utf8(stderr).unwrap();
        assert!(
            text.starts_with("error: could not read your answer from the terminal\nfix: "),
            "{text}"
        );
        assert!(!text.contains("boom"));
        assert!(matches!(
            p.password("Password: ", FIX),
            Err(PromptError::Io(_))
        ));
    }

    #[test]
    fn password_is_read_hidden_and_never_echoed() {
        let mut term = Scripted::new(true, "visible-line\n");
        term.hidden = Some(Ok("correct horse battery staple"));
        let mut p = Prompter::new(term);

        let secret = p
            .password("Password for acme-signing.key (input hidden): ", "unused")
            .unwrap();

        assert_eq!(secret.expose(), "correct horse battery staple");
        assert_eq!(p.term.hidden_reads, 1);
        // The prompt and the line break are the only output. The secret is not in it.
        let out = Scripted::out(&p);
        assert_eq!(out, "Password for acme-signing.key (input hidden): \n");
        assert!(!out.contains("correct horse"));
        // The visible line reader was not used.
        assert_eq!(p.term.input.position(), 0);
    }

    #[test]
    fn secret_debug_shows_no_text() {
        let secret = Secret::new("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "Secret(..)");
        assert!(!secret.is_empty());
        assert!(Secret::new(String::new()).is_empty());
    }

    #[test]
    fn password_without_a_terminal_is_refused_and_reads_nothing() {
        let mut term = Scripted::new(false, "");
        term.hidden = Some(Ok("never read"));
        let mut p = Prompter::new(term);
        let err = p
            .password(
                "Password: ",
                "use --password-file or the RDY_KEY_PASSWORD variable",
            )
            .unwrap_err();
        assert_eq!(err.exit_code(), 64);
        assert_eq!(p.term.hidden_reads, 0);
        let mut stderr = Vec::new();
        err.report(&mut stderr);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "error: cannot ask for a password because there is no terminal\n\
             fix: use --password-file or the RDY_KEY_PASSWORD variable\n"
        );
        assert_eq!(Scripted::out(&p), "");
    }

    #[test]
    fn a_failed_hidden_read_is_an_io_error_with_no_secret_text() {
        let mut term = Scripted::new(true, "");
        term.hidden = Some(Err(io::Error::other("no tty")));
        let mut p = Prompter::new(term);
        let err = p.password("Password: ", "unused").unwrap_err();
        assert_eq!(err.exit_code(), 70);
        assert!(!err.to_string().contains("no tty"));
    }
}
