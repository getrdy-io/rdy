//! Escaping of text that comes from a kubeconfig or a server, before it can reach a terminal.
//!
//! A kubeconfig can come from someone else, and a server answers with whatever it likes. A context
//! name with `\x1b[2J` in it must not clear the screen, and a right-to-left override must not hide the
//! end of a server address (07 section 9 rule 9). The escaper is the shared one in
//! [`rdy_engine::text`], so this crate and the command line show the same text.

pub(crate) use rdy_engine::text::escape_untrusted as escape;

/// [`escape`], cut to `max` characters of the input with `...` at the end when something was cut.
pub(crate) fn escape_capped(value: &str, max: usize) -> String {
    let mut chars = value.chars();
    let head: String = chars.by_ref().take(max).collect();
    let mut out = escape(&head);
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(
            escape("prod-eu.example:6443/k8s"),
            "prod-eu.example:6443/k8s"
        );
    }

    #[test]
    fn the_shared_escaper_covers_what_the_cli_covers() {
        assert_eq!(escape("a\u{1b}[2Jb"), "a\\x1b[2Jb");
        assert_eq!(escape("x\u{202e}y"), "x\\u{202e}y");
        assert_eq!(escape("t\u{0}"), "t\\x00");
        // Line and paragraph separators, variation selectors, tag characters and hangul fillers.
        assert_eq!(
            escape("a\u{2028}\u{2029}\u{fe0f}\u{e0041}\u{3164}\u{115f}b"),
            "a\\u{2028}\\u{2029}\\u{fe0f}\\u{e0041}\\u{3164}\\u{115f}b"
        );
    }

    #[test]
    fn capping_counts_characters_and_marks_the_cut() {
        assert_eq!(escape_capped("abcdef", 3), "abc...");
        assert_eq!(escape_capped("abc", 3), "abc");
        assert_eq!(
            escape_capped("\u{e9}\u{e9}\u{e9}\u{e9}", 2),
            "\u{e9}\u{e9}..."
        );
    }
}
