//! The terminal styling layer: colour choice, width, escaping and ASCII text (07 section 6, M1-070).
//!
//! The renderers of `rdy run` (M1-086), `rdy verify` and the progress line (M1-142) call this module for
//! every decision about how text looks. It writes nothing itself. It has four parts.
//!
//! - **Colour choice.** [`use_color`] applies the five rules of 07 section 6, first match wins, to one
//!   stream. [`StyleEnv`] holds the variables it reads, so a test never touches the process
//!   environment. Stdout is data and is never coloured: only stderr callers ask.
//! - **Palette.** [`Styler::paint`] wraps a word in ANSI 16 colour codes (07 D.1), or returns it as it
//!   is when colour is off. It takes `&'static str` on purpose: text from the machine or the spec is not
//!   `'static`, so it cannot be styled by mistake. Use [`untrusted`] for that text.
//! - **Width.** [`wrap_width`] gives the line width (the terminal, else `COLUMNS`, else 100, clamped to
//!   60 to 100). [`display_width`] and [`pad_end`] count cells with `unicode-width`, so a name in
//!   another script pads the same as ASCII.
//! - **Text.** [`untrusted`] escapes control characters as `\x1b` and bidirectional controls as
//!   `\u{202e}` with [`rdy_engine::text::escape_untrusted`]. [`cut`] shortens escaped text with `...`
//!   and never splits an escape. rdy's own static text is ASCII, and the cut marker is `...`, never an
//!   ellipsis character.
//!
//! Writing the coloured text to the stream is the renderer's job. On Windows it must go through
//! `anstream`, which turns the codes into console calls where it can and strips them elsewhere (07
//! section 6). This module only builds the strings.

use std::ffi::OsString;
use std::io::IsTerminal;

use rdy_engine::text::escape_untrusted;
use unicode_width::UnicodeWidthStr;

use crate::cli::ColorChoice;

/// The line width when neither the terminal nor `COLUMNS` says (07 section 2.2).
pub const DEFAULT_WIDTH: usize = 100;
/// The narrowest line rdy wraps to.
pub const MIN_WIDTH: usize = 60;
/// The widest line rdy wraps to.
pub const MAX_WIDTH: usize = 100;
/// What [`cut`] puts where it removed text.
pub const CUT_MARKER: &str = "...";

/// The environment variables that decide colour and width (07 D.6), read once.
///
/// A variable that is set but empty counts as not set for `CLICOLOR_FORCE` as well as `NO_COLOR`:
/// when the text is unclear the safe error is too little colour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StyleEnv {
    /// `NO_COLOR` is set to a non-empty value.
    no_color: bool,
    /// `CLICOLOR_FORCE` is set to a non-empty value other than `0`.
    clicolor_force: bool,
    /// `CLICOLOR` is `0`.
    clicolor_off: bool,
    /// `TERM` is `dumb`.
    term_dumb: bool,
    /// `COLUMNS` as a positive whole number.
    columns: Option<usize>,
}

impl StyleEnv {
    /// Reads the variables through `get`, which returns the value of a variable or `None`.
    pub fn from_lookup(get: impl Fn(&str) -> Option<OsString>) -> Self {
        let non_empty = |name: &str| get(name).filter(|v| !v.is_empty());
        Self {
            no_color: non_empty("NO_COLOR").is_some(),
            clicolor_force: non_empty("CLICOLOR_FORCE").is_some_and(|v| v != "0"),
            clicolor_off: get("CLICOLOR").is_some_and(|v| v == "0"),
            term_dumb: get("TERM").is_some_and(|v| v == "dumb"),
            columns: get("COLUMNS")
                .and_then(|v| v.to_str().and_then(|s| s.trim().parse::<usize>().ok()))
                .filter(|n| *n > 0),
        }
    }

    /// Reads the variables of this process.
    #[must_use]
    pub fn from_process() -> Self {
        Self::from_lookup(|name| std::env::var_os(name))
    }
}

/// Decides whether one stream gets colour. The first rule that matches wins (07 section 6).
///
/// 1. `--color always` or `never` is taken as asked.
/// 2. `NO_COLOR` set to a non-empty value: never.
/// 3. `CLICOLOR_FORCE` set to anything but `0`: always.
/// 4. `CLICOLOR=0`, or `TERM=dumb`: never.
/// 5. Otherwise colour exactly when the stream is a terminal.
///
/// `NO_COLOR` beats `CLICOLOR_FORCE`, because the safe error is too little colour. There is no
/// `RDY_NO_COLOR` or `RDY_COLOR`.
#[must_use]
pub fn use_color(choice: ColorChoice, env: &StyleEnv, stream_is_terminal: bool) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            if env.no_color {
                false
            } else if env.clicolor_force {
                true
            } else if env.clicolor_off || env.term_dumb {
                false
            } else {
                stream_is_terminal
            }
        }
    }
}

/// The line width for wrapped text (07 section 2.2): the terminal width when `terminal_columns` has
/// one, else `COLUMNS`, else 100, clamped to 60 to 100. A terminal that reports 0 columns has none.
#[must_use]
pub fn wrap_width(terminal_columns: Option<usize>, env: &StyleEnv) -> usize {
    terminal_columns
        .filter(|n| *n > 0)
        .or(env.columns)
        .unwrap_or(DEFAULT_WIDTH)
        .clamp(MIN_WIDTH, MAX_WIDTH)
}

/// The width of the terminal on stderr, or `None` when stderr is not a terminal or the size is not
/// known. Unix asks the terminal; the other platforms return `None` until M2 (Windows then uses
/// `COLUMNS` or 100).
#[must_use]
pub fn stderr_columns() -> Option<usize> {
    stderr_columns_impl()
}

#[cfg(unix)]
fn stderr_columns_impl() -> Option<usize> {
    let stderr = std::io::stderr();
    if !stderr.is_terminal() {
        return None;
    }
    let size = rustix::termios::tcgetwinsize(&stderr).ok()?;
    Some(usize::from(size.ws_col))
}

#[cfg(not(unix))]
fn stderr_columns_impl() -> Option<usize> {
    None
}

/// How the human output looks on stderr, decided once per run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Styler {
    enabled: bool,
}

/// The roles of the palette (07 D.1). ANSI 16 only: no 256-colour, no truecolour, no background, no
/// blink, no links. A role never carries meaning alone: every status is also a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `PASS`: green.
    Pass,
    /// `WARN` and `SKIP`: yellow.
    Warn,
    /// `BLOCK`: red, bold.
    Block,
    /// `TIMEOUT` and `ERROR`: red.
    Failure,
    /// `(required)`, `Tip:` and `fix from ...:`: bold.
    Label,
    /// The first line of a banner: red, bold.
    BannerTitle,
    /// The other lines of a banner: red.
    Banner,
    /// The `error:` prefix: red, bold.
    ErrorPrefix,
    /// `READY`: green, bold.
    VerdictReady,
    /// `READY with warnings`: yellow, bold.
    VerdictWarnings,
    /// `NOT READY`: red, bold.
    VerdictNotReady,
    /// Elapsed time and verbose event lines: dim. Nothing the user must read is dim.
    Dim,
}

impl Role {
    /// Every role, in the order of the palette table.
    pub const ALL: [Role; 12] = [
        Role::Pass,
        Role::Warn,
        Role::Block,
        Role::Failure,
        Role::Label,
        Role::BannerTitle,
        Role::Banner,
        Role::ErrorPrefix,
        Role::VerdictReady,
        Role::VerdictWarnings,
        Role::VerdictNotReady,
        Role::Dim,
    ];

    /// The SGR parameters of the role.
    const fn sgr(self) -> &'static str {
        match self {
            Role::Pass => "32",
            Role::Warn => "33",
            Role::Block | Role::BannerTitle | Role::ErrorPrefix | Role::VerdictNotReady => "1;31",
            Role::Failure | Role::Banner => "31",
            Role::Label => "1",
            Role::VerdictReady => "1;32",
            Role::VerdictWarnings => "1;33",
            Role::Dim => "2",
        }
    }
}

/// Ends every styled run.
const RESET: &str = "\x1b[0m";

impl Styler {
    /// A styler that colours when `enabled`.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// The styler for stderr: colour by [`use_color`] with the stream state of this process.
    #[must_use]
    pub fn for_stderr(choice: ColorChoice, env: &StyleEnv) -> Self {
        Self::new(use_color(choice, env, std::io::stderr().is_terminal()))
    }

    /// True when [`paint`](Self::paint) adds codes.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Wraps `word` in the codes of `role`, or returns it unchanged when colour is off.
    ///
    /// `word` is `&'static str` so that only text written in rdy's source can be styled. Text from the
    /// machine or the spec goes through [`untrusted`] and is never styled (07 section 6). Style the
    /// parts of a line separately, and put the untrusted part between them.
    #[must_use]
    pub fn paint(self, role: Role, word: &'static str) -> String {
        if self.enabled && !word.is_empty() {
            format!("\x1b[{}m{word}{RESET}", role.sgr())
        } else {
            word.to_owned()
        }
    }
}

/// Text from the machine or the spec, made safe to print: control characters become `\x1b`
/// (lowercase hex, two digits) and bidirectional and invisible characters become `\u{202e}`. The
/// result holds no control character, so it cannot move the cursor or hide a line (threat model T4).
///
/// This is [`rdy_engine::text::escape_untrusted`]. It is the only escaping rdy has.
#[must_use]
pub fn untrusted(text: &str) -> String {
    escape_untrusted(text)
}

/// The number of terminal cells `text` takes. Pass escaped text: a raw control character counts as
/// zero cells here and would still move the cursor.
#[must_use]
pub fn display_width(text: &str) -> usize {
    text.width()
}

/// `text` followed by spaces up to `width` cells. Text that is already wider is not cut.
#[must_use]
pub fn pad_end(text: &str, width: usize) -> String {
    let have = display_width(text);
    let mut out = String::with_capacity(text.len() + width.saturating_sub(have));
    out.push_str(text);
    out.extend(std::iter::repeat_n(' ', width.saturating_sub(have)));
    out
}

/// Escapes `text` with [`untrusted`] and, when it is wider than `max` cells, cuts it so that the
/// result including [`CUT_MARKER`] is at most `max` cells. An escape such as `\x1b` is never split,
/// and a combining mark stays with its letter. With `max` under three cells the result is as many dots
/// as fit.
#[must_use]
pub fn cut(text: &str, max: usize) -> String {
    let escaped = untrusted(text);
    if display_width(&escaped) <= max {
        return escaped;
    }
    let marker = CUT_MARKER.len();
    if max < marker {
        return CUT_MARKER[..max].to_owned();
    }
    let budget = max - marker;
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let unit = untrusted(c.encode_utf8(&mut [0; 4]));
        let cells = display_width(&unit);
        // Zero-width characters always fit, so a combining mark stays on its letter.
        if used + cells > budget {
            break;
        }
        used += cells;
        out.push_str(&unit);
    }
    out.push_str(CUT_MARKER);
    out
}

#[cfg(test)]
mod tests;
