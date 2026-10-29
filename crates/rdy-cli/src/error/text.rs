//! Safe text for the terminal: escaping, shell quoting and did-you-mean (07 section 9, rule 9).

/// Escapes the characters of `text` that could act on a terminal. The one escaper lives in
/// [`rdy_engine::text`], so the check crates and the command line show the same text.
pub use rdy_engine::text::escape_untrusted;

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
    use super::{did_you_mean, echo, shell_word};

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
