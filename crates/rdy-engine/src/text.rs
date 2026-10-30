//! Safe text for the terminal, shared by every crate that shows text it did not write.

use std::fmt::Write as _;

/// Escapes the characters of `text` that could act on a terminal.
///
/// Control characters (the C0 and C1 ranges and DEL) become `\xNN`. Bidirectional controls, line and
/// paragraph separators, zero-width characters and the byte order mark become `\u{202e}`. Nothing else
/// changes. Backslashes are left alone, because text from `rdy-spec` is already escaped and a second pass
/// would double every backslash.
///
/// Every string that reaches stderr or an `ErrorOutput` goes through this function, so an ANSI sequence
/// in a spec cannot move the cursor, clear the screen or hide a line (threat model T4).
#[must_use]
pub fn escape_untrusted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // Writing to a String cannot fail.
        if c.is_control() {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        } else if is_invisible(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// True for the code points that print as nothing or reorder text without being control characters.
///
/// This is the Unicode Default_Ignorable_Code_Point set, plus the line and paragraph separators, the
/// interlinear annotation marks and the bidirectional controls. `escape_untrusted` shows them as
/// `\u{..}` so a reader sees that they are there. A check that builds text a customer copies refuses
/// them.
#[must_use]
pub fn is_invisible(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD // soft hyphen
            | 0x034F // combining grapheme joiner
            | 0x061C // arabic letter mark
            | 0x115F..=0x1160 // hangul fillers
            | 0x17B4..=0x17B5 // khmer inherent vowels
            | 0x180B..=0x180F // mongolian free variation selectors and vowel separator
            | 0x200B..=0x200F // zero-width characters and direction marks
            | 0x2028..=0x202E // line and paragraph separators, embeddings and overrides
            | 0x2060..=0x206F // word joiner, invisible operators, isolates and deprecated controls
            | 0x3164 // hangul filler
            | 0xFE00..=0xFE0F // variation selectors
            | 0xFEFF // byte order mark
            | 0xFFA0 // halfwidth hangul filler
            | 0xFFF0..=0xFFFB // reserved specials and annotation marks
            | 0x1BCA0..=0x1BCA3 // shorthand format controls
            | 0x1D173..=0x1D17A // musical symbol format controls
            | 0xE0000..=0xE0FFF // tags and variation selectors supplement
    )
}

#[cfg(test)]
mod tests {
    use super::escape_untrusted;

    #[test]
    fn control_characters_become_visible_text() {
        assert_eq!(escape_untrusted("a\u{1b}[2Jb"), "a\\x1b[2Jb");
        assert_eq!(
            escape_untrusted("x\u{7}\u{0}\n\r\t"),
            "x\\x07\\x00\\x0a\\x0d\\x09"
        );
        assert_eq!(escape_untrusted("\u{7f}\u{85}\u{9b}"), "\\x7f\\x85\\x9b");
    }

    #[test]
    fn bidirectional_and_invisible_characters_become_visible_text() {
        assert_eq!(escape_untrusted("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(escape_untrusted("\u{2066}\u{2069}"), "\\u{2066}\\u{2069}");
        assert_eq!(
            escape_untrusted("\u{200b}\u{feff}\u{2028}"),
            "\\u{200b}\\u{feff}\\u{2028}"
        );
        // Default-ignorable code points: soft hyphen, joiner, variation selector, a tag character.
        assert_eq!(
            escape_untrusted("a\u{ad}\u{34f}\u{fe0f}\u{e0041}\u{e007f}\u{3164}b"),
            "a\\u{ad}\\u{34f}\\u{fe0f}\\u{e0041}\\u{e007f}\\u{3164}b"
        );
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        let text = "min is 32Gi \\ 'quoted' \"double\" \u{e9}\u{4e2d}\u{1f600}";
        assert_eq!(escape_untrusted(text), text);
    }
}
