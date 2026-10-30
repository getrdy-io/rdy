//! Small text helpers the host checks share.

use rdy_engine::check::CheckError;
use rdy_engine::probe::ProbeError;
use rdy_engine::text::{escape_untrusted, is_invisible};

/// A probe error the check can work around. A refusal by rdy's own policy is a bug in the check's
/// manifest or command, and ends the check.
pub(crate) fn soft(error: ProbeError) -> Result<ProbeError, CheckError> {
    match error {
        ProbeError::Denied { .. } | ProbeError::Policy(_) | ProbeError::Table(_) => {
            Err(CheckError::Probe(error))
        }
        other => Ok(other),
    }
}

/// A short reason for a probe failure, for a note.
pub(crate) fn short(error: &ProbeError) -> String {
    match error {
        ProbeError::NotFound => "not found".to_owned(),
        ProbeError::PermissionDenied => "permission denied".to_owned(),
        ProbeError::Timeout => "timed out".to_owned(),
        other => other
            .to_string()
            .split(". Fix:")
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}

/// Whether `c` could make a copied command differ from what the reader sees: a control character, an
/// invisible or bidirectional code point, or the replacement character a lossy decode leaves.
pub(crate) fn is_odd(c: char) -> bool {
    c.is_control() || is_invisible(c) || c == '\u{FFFD}'
}

/// Text from the machine or the spec, ready to sit in a sentence. Plain text is wrapped in backticks.
/// Text with a backtick would break the code span, so it is shown without the wrapping. Control and
/// invisible characters are always shown escaped (`\x0a`, `\u{202e}`).
pub(crate) fn code(text: &str) -> String {
    let shown = escape_untrusted(text).replace('\u{FFFD}', "\\u{fffd}");
    if text.contains('`') {
        shown
    } else {
        format!("`{shown}`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_wrapped() {
        assert_eq!(code("/var/lib/acme"), "`/var/lib/acme`");
    }

    #[test]
    fn a_backtick_is_shown_bare_so_it_cannot_close_a_span() {
        assert_eq!(code("/mnt/a`b"), "/mnt/a`b");
    }

    #[test]
    fn controls_and_bidi_are_escaped() {
        assert_eq!(code("/mnt/a\nb"), "`/mnt/a\\x0ab`");
        assert_eq!(code("/mnt/a\u{202e}b"), "`/mnt/a\\u{202e}b`");
        assert_eq!(code("/mnt/\u{fffd}"), "`/mnt/\\u{fffd}`");
        assert_eq!(code("/mnt/a\u{1b}[2Jb"), "`/mnt/a\\x1b[2Jb`");
    }

    #[test]
    fn odd_characters_are_named() {
        for c in ['\n', '\0', '\u{200b}', '\u{202e}', '\u{fffd}'] {
            assert!(is_odd(c), "{c:?}");
        }
        assert!(!is_odd('a'));
        assert!(!is_odd('é'));
    }
}
