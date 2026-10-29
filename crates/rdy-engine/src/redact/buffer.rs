//! Buffers the facade cut (ADR 0015 decision 2, 02 "From finding to result").
//!
//! A file read, a tail read, stdout and stderr stop at a cap. A secret that straddles the cap leaves a
//! fragment that no rule matches: half a key id, a URL without its host, the body of a PEM key without
//! its header. So a buffer that carries a cut flag is handled before any rule runs:
//!
//! 1. **The partial edge line goes.** At a cut head the first line is dropped, at a cut tail the part
//!    after the last newline. With no newline at all, the first or last [`WINDOW`] bytes go. The cap
//!    marker takes its place.
//! 2. **A private key with no end goes to the end.** A `-----BEGIN ... PRIVATE KEY-----` with no
//!    `-----END` is removed through the end of the buffer, and an `-----END ... PRIVATE KEY-----` with
//!    no `BEGIN` before it from the start of the buffer. The full PEM rule is M1-060; this is the part
//!    that only a cut buffer needs.
//! 3. **Known secrets cut by the edge.** An 8-byte or longer prefix of a known secret at the end, or
//!    suffix at the start, is removed.
//! 4. The rules and the exact known-secret match run on what is left, as for any string.

use super::span::Span;
use super::{Redacted, Redactor, RuleCounts};

/// The marker put where a partial edge line was dropped.
const MARKER: &str = "[truncated]";

/// How many bytes go from a cut edge that has no newline in the whole buffer.
const WINDOW: usize = 4096;

/// The rule name of the unterminated key guard. It is the name of the PEM rule of 04 Appendix B.
const PEM_RULE: &str = "pem_private_key";

/// Priority of the guard: above every other rule, below known secrets.
const PEM_PRIORITY: u8 = 90;

/// Which ends of a buffer the facade cut off.
///
/// `FileBytes::cut` and `Output::stdout_cut` build one from the facade's flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Cut {
    /// The start was left out (`read_tail`).
    pub head: bool,
    /// The end was left out (a size cap).
    pub tail: bool,
}

impl Cut {
    /// A buffer cut at neither end.
    pub const NONE: Self = Self {
        head: false,
        tail: false,
    };

    /// A buffer cut at the given ends.
    #[must_use]
    pub const fn new(head: bool, tail: bool) -> Self {
        Self { head, tail }
    }
}

impl Redactor {
    /// Redacts a buffer from the facade. Invalid UTF-8 becomes U+FFFD. See the module notes for what a
    /// cut end loses. Never fails and never returns raw text.
    #[must_use]
    pub fn redact_buffer(&self, bytes: &[u8], cut: Cut) -> Redacted<String> {
        self.redact_buffer_counted(bytes, cut, &mut RuleCounts::default())
    }

    /// Like [`Redactor::redact_buffer`], and adds what it did to `counts`.
    #[must_use]
    pub fn redact_buffer_counted(
        &self,
        bytes: &[u8],
        cut: Cut,
        counts: &mut RuleCounts,
    ) -> Redacted<String> {
        let text = String::from_utf8_lossy(bytes);
        let (start, end) = kept(&text, cut);
        let kept_text = text.get(start..end).unwrap_or_default();
        let mut extra = Vec::new();
        if cut.tail {
            unterminated_begin(kept_text, &mut extra);
        }
        if cut.head {
            unmatched_end(kept_text, &mut extra);
        }
        self.known
            .edge_spans(kept_text, cut.head, cut.tail, &mut extra);
        let body = self.run_with(super::rules::BUILT_IN, kept_text, &extra, counts);
        let mut out = String::with_capacity(body.len() + MARKER.len() + 2);
        if cut.head {
            out.push_str(MARKER);
            out.push('\n');
        }
        out.push_str(&body);
        if cut.tail {
            // The marker joins the last line, which is whole or empty, so no value runs into it.
            if !out.is_empty() && !out.ends_with('\n') {
                out.push(' ');
            }
            out.push_str(MARKER);
        }
        Redacted::new(out)
    }
}

/// The byte range of `text` that survives the edge drop.
fn kept(text: &str, cut: Cut) -> (usize, usize) {
    let mut start = 0;
    if cut.head {
        start = match text.find('\n') {
            Some(i) => i + 1,
            None => text.ceil_char_boundary(WINDOW.min(text.len())),
        };
    }
    let mut end = text.len();
    if cut.tail {
        let rest = text.get(start..).unwrap_or_default();
        end = match rest.rfind('\n') {
            Some(i) => start + i + 1,
            None => text.floor_char_boundary(text.len().saturating_sub(WINDOW)),
        }
        .max(start);
    }
    (start, end)
}

/// A private key that starts and never ends: removed through the end of the text.
fn unterminated_begin(text: &str, out: &mut Vec<Span>) {
    for (at, _) in text.match_indices("-----BEGIN ") {
        let header_end = text.get(at..).and_then(|t| t.find('\n')).map(|i| at + i);
        let header = text
            .get(at..header_end.unwrap_or(text.len()))
            .unwrap_or_default();
        if !header.contains("PRIVATE KEY") {
            continue;
        }
        let after = header_end.unwrap_or(text.len());
        if !text.get(after..).unwrap_or_default().contains("-----END ") {
            out.push(Span {
                start: at,
                end: text.len(),
                rule: PEM_RULE,
                priority: PEM_PRIORITY,
            });
            return;
        }
    }
}

/// A private key whose start was cut off: removed from the start of the text through its END line.
fn unmatched_end(text: &str, out: &mut Vec<Span>) {
    let begin = text.find("-----BEGIN ");
    for (at, _) in text.match_indices("-----END ") {
        if begin.is_some_and(|b| b < at) {
            return;
        }
        let line_end = text
            .get(at..)
            .and_then(|t| t.find('\n'))
            .map_or(text.len(), |i| at + i);
        if text
            .get(at..line_end)
            .unwrap_or_default()
            .contains("PRIVATE KEY")
        {
            out.push(Span {
                start: 0,
                end: line_end,
                rule: PEM_RULE,
                priority: PEM_PRIORITY,
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests;
