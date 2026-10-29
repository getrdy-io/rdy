//! Start-up hardening (M1-168, ADR 0023).
//!
//! [`crate::entry::main_code`] calls [`rdy_engine::exec::harden_umask`] first, so every file `rdy`
//! creates is private, and lists the inherited descriptors before it opens anything of its own. When
//! the list is not empty, [`warn_inherited`] prints one `warning:` line on stderr. It never goes to
//! stdout, so `--json` output stays clean. Closing the descriptors is M2-104.

use std::io::Write;

use crate::error::escape_untrusted;
use crate::redaction;

/// The most descriptor numbers the warning names. The rest are counted.
const MAX_LISTED: usize = 8;

/// The `warning:` text for `fds`, or `None` when there are none. It has no line break.
///
/// It names at most 8 descriptors and counts the rest, with a hint to close those too.
#[must_use]
pub fn inherited_fd_warning(fds: &[u32]) -> Option<String> {
    if fds.is_empty() {
        return None;
    }
    let listed: Vec<String> = fds.iter().take(MAX_LISTED).map(u32::to_string).collect();
    let more = fds.len().saturating_sub(MAX_LISTED);
    let mut numbers = listed.join(", ");
    if more > 0 {
        numbers.push_str(&format!(" and {more} more"));
    }
    let closers: Vec<String> = fds
        .iter()
        .take(MAX_LISTED)
        .map(|fd| format!("{fd}>&-"))
        .collect();
    let noun = if fds.len() == 1 {
        "descriptor"
    } else {
        "descriptors"
    };
    let rest = if more > 0 {
        " and close the rest the same way"
    } else {
        ""
    };
    Some(format!(
        "warning: rdy inherited open file {noun} {numbers}, and the commands it runs inherit them. To start without, close them in the shell: rdy ... {}{rest}",
        closers.join(" ")
    ))
}

/// Prints the inherited-descriptor warning to `stderr`, redacted and escaped like every other CLI
/// line. Prints nothing when `fds` is empty. A write error is ignored.
pub fn warn_inherited(fds: &[u32], stderr: &mut dyn Write) {
    if let Some(text) = inherited_fd_warning(fds) {
        let line = redaction::redact_text_then(&text, escape_untrusted);
        let _ = writeln!(stderr, "{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_descriptors_no_warning() {
        assert_eq!(inherited_fd_warning(&[]), None);
        let mut out = Vec::new();
        warn_inherited(&[], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn one_descriptor_is_named_on_one_line() {
        let text = inherited_fd_warning(&[3]).unwrap_or_default();
        assert!(text.starts_with("warning: "), "{text}");
        assert!(text.contains("descriptor 3,"), "{text}");
        assert!(text.ends_with("rdy ... 3>&-"), "{text}");
        assert!(!text.contains('\n'));
    }

    #[test]
    fn many_descriptors_are_capped() {
        let fds: Vec<u32> = (3..23).collect();
        let text = inherited_fd_warning(&fds).unwrap_or_default();
        assert!(
            text.contains("3, 4, 5, 6, 7, 8, 9, 10 and 12 more"),
            "{text}"
        );
        assert!(!text.contains("11,"), "{text}");
        assert!(
            text.ends_with(
                "rdy ... 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 10>&- and close the rest the same way"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_printed_line_ends_with_one_newline() {
        let mut out = Vec::new();
        warn_inherited(&[3, 7], &mut out);
        let shown = String::from_utf8(out).unwrap_or_default();
        assert_eq!(shown.lines().count(), 1, "{shown}");
        assert!(shown.starts_with("warning: rdy inherited open file descriptors 3, 7,"));
        assert!(shown.ends_with('\n'));
    }
}
