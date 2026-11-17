//! The live progress line of `rdy run` (07 section 3, M1-142).
//!
//! One spinner line on stderr, redrawn at most 10 times a second, with no bar and nothing else on the
//! screen. It exists because a run can take ten seconds and a silent terminal looks hung. It is never
//! needed to read a result, and it never writes to stdout.
//!
//! - **When it draws.** [`live_line_allowed`] says yes only when stderr is a terminal, `TERM` is not
//!   `dumb`, `RUST_LOG` is not set, and none of `--quiet`, `--progress never` and `RDY_PROGRESS=never`
//!   (clap reads that variable into `--progress`) is given. indicatif checks only the terminal, so these
//!   rules are ours. The bar is made hidden and gets a real draw target only when the first frame is due.
//! - **First frame.** It waits [`FIRST_FRAME`] (250 ms), so a fast run draws no byte at all.
//! - **Text.** `Running N checks`, and after 2 seconds `Running N checks, 4 s`. The engine does not tell
//!   the CLI which checks are running yet, so the line does not name them.
//! - **Glyphs.** Braille when Unicode is allowed ([`unicode_allowed`], 07 D.1), else `- \ | /`.
//! - **Clearing.** [`Progress::clear`] and `Drop` finish the line with `finish_and_clear`, so it leaves
//!   no trace, and `error:` or the check list starts at column 0. The task that ticks is aborted first.
//!
//! The ticker is a tokio task on the run's own runtime, so it uses tokio time, and a test can pause the
//! clock. indicatif's own steady-tick thread is not used.

use std::ffi::OsString;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle, TermLike};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep};

use crate::cli::ProgressChoice;

/// How long the run is quiet before the first frame, so a fast run never flashes a spinner.
pub const FIRST_FRAME: Duration = Duration::from_millis(250);
/// The time between two frames: 10 a second.
pub const FRAME_EVERY: Duration = Duration::from_millis(100);
/// The elapsed time shows from this point.
pub const SHOW_ELAPSED_AFTER: Duration = Duration::from_secs(2);

/// The line template. It has no style spec (`{spinner:.green}` and the like): a styled template makes the
/// `console` crate read `NO_COLOR` and `CLICOLOR` and, on Windows, change the console mode without
/// restoring it (SEC-60-1). A test holds this.
pub const TEMPLATE: &str = "{spinner} {wide_msg}";

/// The Braille spinner of 07 D.1.
pub const BRAILLE: [&str; 10] = [
    "\u{280b}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283c}", "\u{2834}", "\u{2826}", "\u{2827}",
    "\u{2807}", "\u{280f}",
];
/// The ASCII spinner.
pub const ASCII: [&str; 4] = ["-", "\\", "|", "/"];

/// The variables that decide whether and how the line draws (07 D.6), read once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgressEnv {
    /// `TERM` is `dumb`.
    term_dumb: bool,
    /// `TERM` is `dumb` or `linux`, which the Unicode rule of D.1 refuses.
    term_no_unicode: bool,
    /// `RUST_LOG` is set to a non-empty value.
    rust_log: bool,
    /// The first of `LC_ALL`, `LC_CTYPE`, `LANG` that is set and non-empty names UTF-8.
    utf8_locale: bool,
    /// `WT_SESSION` is set.
    wt_session: bool,
    /// `TERM_PROGRAM` is `vscode`.
    vscode: bool,
}

impl ProgressEnv {
    /// Reads the variables through `get`, which returns the value of a variable or `None`.
    pub fn from_lookup(get: impl Fn(&str) -> Option<OsString>) -> Self {
        let non_empty = |name: &str| get(name).filter(|v| !v.is_empty());
        let term = get("TERM");
        let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .find_map(|name| non_empty(name));
        Self {
            term_dumb: term.as_ref().is_some_and(|v| v == "dumb"),
            term_no_unicode: term.as_ref().is_some_and(|v| v == "dumb" || v == "linux"),
            rust_log: non_empty("RUST_LOG").is_some(),
            utf8_locale: locale.is_some_and(|v| {
                let v = v.to_string_lossy().to_ascii_lowercase();
                v.contains("utf-8") || v.contains("utf8")
            }),
            wt_session: get("WT_SESSION").is_some(),
            vscode: get("TERM_PROGRAM").is_some_and(|v| v == "vscode"),
        }
    }

    /// Reads the variables of this process.
    #[must_use]
    pub fn from_process() -> Self {
        Self::from_lookup(|name| std::env::var_os(name))
    }
}

/// Whether the live line may draw (07 section 3). `stderr_is_terminal` is the stream, not stdout.
#[must_use]
pub fn live_line_allowed(
    choice: ProgressChoice,
    quiet: bool,
    env: &ProgressEnv,
    stderr_is_terminal: bool,
) -> bool {
    stderr_is_terminal
        && choice == ProgressChoice::Auto
        && !quiet
        && !env.term_dumb
        && !env.rust_log
}

/// Whether the spinner may be Braille (07 D.1). `windows` picks the Windows rule over the Unix one.
#[must_use]
pub fn unicode_allowed(env: &ProgressEnv, windows: bool) -> bool {
    if windows {
        env.wt_session || env.vscode
    } else {
        env.utf8_locale && !env.term_no_unicode
    }
}

/// The spinner frames for this process.
#[must_use]
pub fn frames(env: &ProgressEnv) -> &'static [&'static str] {
    if unicode_allowed(env, cfg!(windows)) {
        &BRAILLE
    } else {
        &ASCII
    }
}

/// The text after the spinner.
#[must_use]
pub fn message(total: usize, elapsed: Duration) -> String {
    let noun = if total == 1 { "check" } else { "checks" };
    if elapsed >= SHOW_ELAPSED_AFTER {
        format!("Running {total} {noun}, {} s", elapsed.as_secs())
    } else {
        format!("Running {total} {noun}")
    }
}

/// A test's stand-in for the terminal: every draw lands in a shared buffer, as text. A clear shows as
/// `<clear>` and a cursor move as `<up>`, so a test can read what the user would have seen.
#[derive(Debug, Clone, Default)]
pub struct ProgressCapture(Arc<Mutex<String>>);

impl ProgressCapture {
    /// What was drawn so far.
    #[must_use]
    pub fn text(&self) -> String {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the last frame was cleared: after the last `Running` text only blanks, cursor moves and
    /// at least one clear follow, so nothing of the line is left on the screen.
    #[must_use]
    pub fn cleared(&self) -> bool {
        let text = self.text();
        let Some(at) = text.rfind("Running") else {
            return false;
        };
        let tail = &text[at..];
        let mut rest = tail.trim_start_matches(|c: char| c != '<' && c != '\n');
        let mut clears = 0;
        while let Some(after) = rest.trim_start().strip_prefix('<') {
            let Some(end) = after.find('>') else {
                return false;
            };
            clears += usize::from(&after[..end] == "clear");
            rest = &after[end + 1..];
        }
        clears > 0 && rest.trim().is_empty()
    }

    fn push(&self, text: &str) -> io::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_str(text);
        Ok(())
    }
}

impl TermLike for ProgressCapture {
    fn width(&self) -> u16 {
        80
    }
    fn move_cursor_up(&self, _: usize) -> io::Result<()> {
        self.push("<up>")
    }
    fn move_cursor_down(&self, _: usize) -> io::Result<()> {
        self.push("<down>")
    }
    fn move_cursor_right(&self, _: usize) -> io::Result<()> {
        self.push("<right>")
    }
    fn move_cursor_left(&self, _: usize) -> io::Result<()> {
        self.push("<left>")
    }
    fn write_line(&self, s: &str) -> io::Result<()> {
        self.push(s)?;
        self.push("\n")
    }
    fn write_str(&self, s: &str) -> io::Result<()> {
        self.push(s)
    }
    fn clear_line(&self) -> io::Result<()> {
        self.push("<clear>")
    }
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Where the line draws.
#[derive(Debug, Clone)]
pub enum Target {
    /// The real stderr, at most 10 frames a second.
    Stderr,
    /// A test's buffer, with the same 10 frames a second limit as the real stderr (counted in real time).
    Capture(ProgressCapture),
    /// A test's buffer with no rate limit, for a test on a paused clock: indicatif's limiter counts real
    /// time, and a paused test passes seconds in no time. The ticker paces the frames.
    CaptureUnlimited(ProgressCapture),
}

impl Target {
    fn draw_target(&self) -> ProgressDrawTarget {
        match self {
            Self::Stderr => ProgressDrawTarget::stderr_with_hz(10),
            Self::Capture(capture) => {
                ProgressDrawTarget::term_like_with_hz(Box::new(capture.clone()), 10)
            }
            Self::CaptureUnlimited(capture) => {
                ProgressDrawTarget::term_like(Box::new(capture.clone()))
            }
        }
    }
}

/// A live line, or nothing. Clears itself when dropped.
#[derive(Debug)]
pub struct Progress {
    bar: ProgressBar,
    ticker: Option<JoinHandle<()>>,
}

impl Progress {
    /// No line: nothing is ever drawn.
    #[must_use]
    pub fn off() -> Self {
        Self {
            bar: ProgressBar::hidden(),
            ticker: None,
        }
    }

    /// Starts the line for `total` checks. It draws nothing for [`FIRST_FRAME`]. Needs a tokio runtime
    /// with time enabled.
    #[must_use]
    pub fn start(total: usize, frames: &'static [&'static str], target: Target) -> Self {
        Self::start_after(FIRST_FRAME, total, frames, target)
    }

    /// Like [`Progress::start`], with the quiet time before the first frame given. The binary always uses
    /// [`FIRST_FRAME`]; a test that needs a run to end first gives a long one.
    #[must_use]
    pub fn start_after(
        first_frame: Duration,
        total: usize,
        frames: &'static [&'static str],
        target: Target,
    ) -> Self {
        let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::hidden());
        let mut strings: Vec<&str> = frames.to_vec();
        // indicatif takes the last string as the one for a finished bar. It is never drawn.
        strings.push(" ");
        // The template is a constant that a test parses. The default styles are coloured, so a failure
        // here keeps indicatif's plain default rather than falling back to one of them.
        if let Ok(style) = ProgressStyle::with_template(TEMPLATE) {
            bar.set_style(style.tick_strings(&strings));
        }
        let mut shown = message(total, Duration::ZERO);
        bar.set_message(shown.clone());
        let handle = bar.clone();
        let started = Instant::now();
        let ticker = tokio::spawn(async move {
            // Strictly over the delay: a run that ends at exactly 250 ms draws nothing.
            sleep(first_frame + Duration::from_millis(1)).await;
            handle.set_draw_target(target.draw_target());
            let mut every = interval(FRAME_EVERY);
            every.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                every.tick().await;
                // Only our own text goes here (a count and seconds). Any text from the spec or the
                // machine, such as a check name, must pass `style::untrusted` and the width cap first
                // (SEC-60-4).
                let text = message(total, started.elapsed());
                if text != shown {
                    handle.set_message(text.clone());
                    shown = text;
                }
                handle.tick();
            }
        });
        Self {
            bar,
            ticker: Some(ticker),
        }
    }

    /// Takes the line off the screen. Call it before anything else is written to stderr.
    pub fn clear(&mut self) {
        if let Some(ticker) = self.ticker.take() {
            ticker.abort();
        }
        self.bar.finish_and_clear();
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests;
