//! Text from the report, made safe to show: the one way to build a [`Shown`] (M1-141, SEC-149-11).
//!
//! The field of [`Shown`] is private to this module, and [`shown`] is the only function that builds one. A
//! view field of type `Shown` therefore cannot hold text that skipped the escaping, and a new `String`
//! field is easy to tell from it in review.

use std::fmt;

/// Text that has been through [`shown`]: no control character, and no format or zero-width character,
/// is left in it raw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::report::html) struct Shown(String);

impl Shown {
    /// The escaped text.
    pub(in crate::report::html) fn as_str(&self) -> &str {
        &self.0
    }

    /// True when there is no text.
    pub(in crate::report::html) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for Shown {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Shown {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// The Unicode format (Cf) characters that `rdy_engine::text::is_invisible` does not list. Together they
/// are every Cf character and the zero-width characters outside Cf.
///
/// Checked against Unicode 15.1. Check this list again when the Unicode version of the toolchain moves:
/// a Cf character added later is not escaped until it is listed here.
fn is_extra_format(c: char) -> bool {
    matches!(
        u32::from(c),
        0x0600..=0x0605
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
    )
}

/// `text` as the page shows it. Every format (Cf) and zero-width character, among them the bidi controls
/// U+202A to U+202E and U+2066 to U+2069, is written as an escape such as `\u{202e}`, so it cannot reorder
/// or hide anything and a reader sees that it is there (M1-141, SEC-149-11). Every control character
/// (C0, DEL and C1) except line feed and tab is written as `\x1b` and so on, like the terminal does
/// (07 section 9 item 9). Line feed and tab stay, because the page collapses them to a space. Everything
/// else is kept.
///
/// Every string from the report goes through this before it reaches the template, which then wraps it in
/// `<bdi>` and HTML-escapes it. A backslash is left as it is, like `crate::text::escape_untrusted`. The
/// function is idempotent: its output holds nothing it would change.
pub(in crate::report::html) fn shown(text: &str) -> Shown {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // Writing to a String cannot fail.
        if c.is_control() && c != '\n' && c != '\t' {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        } else if crate::text::is_invisible(c) || is_extra_format(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Shown(out)
}
