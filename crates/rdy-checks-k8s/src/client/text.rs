//! Escaping of text that comes from a kubeconfig or a server, before it can reach a terminal.
//!
//! A kubeconfig can come from someone else, and a server answers with whatever it likes. A context
//! name with `\x1b[2J` in it must not clear the screen, and a right-to-left override must not hide the
//! end of a server address (07 section 9 rule 9). Control characters and invisible format characters
//! become `\u{..}`.

/// True for characters that must not reach a terminal as they are.
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
        )
}

/// Replaces control and invisible characters with `\u{..}` escapes.
pub(crate) fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if is_unsafe(c) {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

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
    fn escape_sequences_and_bidi_marks_are_made_visible() {
        assert_eq!(escape("a\u{1b}[2Jb"), "a\\u{001b}[2Jb");
        assert_eq!(escape("x\u{202e}y"), "x\\u{202e}y");
        assert_eq!(escape("t\u{0}"), "t\\u{0000}");
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
