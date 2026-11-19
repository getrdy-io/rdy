//! Small text helpers the net checks share.

use rdy_engine::check::CheckError;
use rdy_engine::probe::ProbeError;
use rdy_engine::text::escape_untrusted;

/// A probe error the check can work around. A refusal by rdy's own policy is a bug in the check's
/// manifest, and ends the check.
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

/// Text from the machine, ready to sit in a sentence. Plain text is wrapped in backticks. Text with a
/// backtick would break the code span, so it is shown without the wrapping. Control and invisible
/// characters are always shown escaped (`\x0a`, `\u{202e}`).
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
        assert_eq!(code("eth0"), "`eth0`");
    }

    #[test]
    fn a_backtick_is_shown_bare_so_it_cannot_close_a_span() {
        assert_eq!(code("a`b"), "a`b");
    }

    #[test]
    fn controls_and_bidi_are_escaped() {
        assert_eq!(code("eth\n0"), "`eth\\x0a0`");
        assert_eq!(code("eth\u{202e}0"), "`eth\\u{202e}0`");
        assert_eq!(code("eth\u{fffd}"), "`eth\\u{fffd}`");
    }
}
