//! Safe text for the terminal: escaping, shell quoting and did-you-mean (07 section 9, rule 9).

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
/// `\u{..}` so a reader sees that they are there.
fn is_invisible(c: char) -> bool {
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

/// The most characters of a spec value that a skip message keeps.
const MAX_ECHO_CHARS: usize = 64;

/// Escapes `text` and cuts it to 64 characters, ending in `...` when it was cut.
#[must_use]
pub fn echo(text: &str) -> String {
    let mut clipped: String = text.chars().take(MAX_ECHO_CHARS).collect();
    if text.chars().nth(MAX_ECHO_CHARS).is_some() {
        clipped.push_str("...");
    }
    escape_untrusted(&clipped)
}

/// Quotes `word` for a POSIX shell when it holds anything but letters, digits and `._/-:@+,=`.
///
/// A file name is typed by the user, so a fix line that repeats it must not turn into a second command
/// when pasted. The result is also escaped for the terminal.
#[must_use]
pub fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-:@+,=".contains(c));
    if plain {
        word.to_owned()
    } else {
        escape_untrusted(&format!("'{}'", word.replace('\'', "'\\''")))
    }
}

/// The candidate closest to `input`, when it is close enough to be a typo (distance 2 or less, one
/// third of the length of `input` at most). The implementation lives in `rdy-spec`, so the spec lint
/// and the command line give the same advice. See [`rdy_spec::did_you_mean`].
pub use rdy_spec::did_you_mean;

#[cfg(test)]
mod tests {
    use super::{did_you_mean, echo, escape_untrusted, shell_word};

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

    #[test]
    fn echo_cuts_long_values() {
        assert_eq!(echo(&"a".repeat(64)), "a".repeat(64));
        assert_eq!(echo(&"a".repeat(65)), format!("{}...", "a".repeat(64)));
        assert_eq!(echo("\u{1b}[0m"), "\\x1b[0m");
    }

    #[test]
    fn shell_word_quotes_only_when_needed() {
        assert_eq!(shell_word("acme-platform.yaml"), "acme-platform.yaml");
        assert_eq!(shell_word("specs/a b.yaml"), "'specs/a b.yaml'");
        assert_eq!(shell_word("a;rm -rf x"), "'a;rm -rf x'");
        assert_eq!(shell_word("it's.yaml"), "'it'\\''s.yaml'");
        assert_eq!(shell_word(""), "''");
        assert_eq!(shell_word("a\u{1b}b"), "'a\\x1bb'");
    }

    #[test]
    fn did_you_mean_finds_typos_and_ignores_the_rest() {
        let fields = ["min", "max", "path"];
        assert_eq!(did_you_mean("mn", &fields), Some("min"));
        let ids = ["host.memory", "host.disk", "net.dns"];
        assert_eq!(did_you_mean("host.memroy", &ids), Some("host.memory"));
        assert_eq!(did_you_mean("upload.now", &ids), None);
        assert_eq!(did_you_mean("host.memory", &ids), None);
        assert_eq!(did_you_mean("", &ids), None);
    }
}
