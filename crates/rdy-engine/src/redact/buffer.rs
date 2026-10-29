//! Buffers the facade cut (ADR 0015 decision 2, 02 "From finding to result").
//!
//! A file read, a tail read, stdout and stderr stop at a cap. A secret that straddles the cap leaves a
//! fragment that no rule matches: half a key id, a URL without its host, the body of a PEM key without
//! its header. So a buffer that carries a cut flag is handled before any rule runs:
//!
//! 1. **The partial edge line goes.** At a cut head the first line is dropped, at a cut tail the part
//!    after the last newline. With no newline at all, the first or last [`WINDOW`] bytes go, and then
//!    the boundary moves to the nearest separator (NUL, white space, `,` `;` `&` `"` `'`) so that it
//!    does not split a value. If there is none within another [`WINDOW`] bytes, the whole buffer goes.
//!    A known secret that crosses the boundary on the full text moves the boundary to its start (tail)
//!    or its end (head). The cap marker takes the place of what went.
//! 2. **A private key with no end goes to the end.** A `-----BEGIN ... PRIVATE KEY-----` with no
//!    `-----END` of the same label is removed through the end of the buffer, and an
//!    `-----END ... PRIVATE KEY-----` with no `BEGIN` of the same label before it from the start of the
//!    buffer. With both ends cut (a tail read of a file past the scan budget), a run of long base64
//!    lines that has neither armor line is removed as well. The full PEM rule is M1-060; this is the
//!    part that only a cut buffer needs.
//! 3. **Known secrets cut by the edge.** An 8-byte or longer prefix of a known secret at the end, or
//!    suffix at the start, is removed.
//! 4. The rules and the exact known-secret match run on what is left, as for any string.

use super::span::Span;
use super::{Redacted, Redactor, RuleCounts};

/// The marker put where a partial edge line was dropped.
const MARKER: &str = "[truncated]";

/// How many bytes go from a cut edge that has no newline in the whole buffer, and how far the boundary
/// then looks for a separator.
const WINDOW: usize = 4096;

/// The shortest line, in bytes, that counts as a line of key body when both ends are cut. PEM bodies
/// are 64 characters a line (70 for OpenSSH keys).
const BODY_LINE_MIN: usize = 40;

/// How many such lines in a row count as a key body.
const BODY_LINES_MIN: usize = 2;

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
        let (start, end) = self.kept(&text, cut);
        let kept_text = text.get(start..end).unwrap_or_default();
        let mut extra = Vec::new();
        if cut.tail {
            unterminated_begin(kept_text, &mut extra);
        }
        if cut.head {
            unmatched_end(kept_text, &mut extra);
        }
        if cut.head && cut.tail {
            bare_body(kept_text, &mut extra);
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

    /// The byte range of `text` that survives the edge drop.
    ///
    /// The known secrets are matched on the full text first. One that crosses a boundary moves it to
    /// the secret's own start (tail) or end (head), so a value the rules cannot see is never half kept.
    fn kept(&self, text: &str, cut: Cut) -> (usize, usize) {
        let (mut start, mut end) = edge_drop(text, cut);
        if !cut.head && !cut.tail {
            return (start, end);
        }
        let mut known = Vec::new();
        self.known.exact_spans(text, &mut known);
        loop {
            let before = (start, end);
            for span in &known {
                if cut.tail && span.start < end && span.end > end {
                    end = span.start;
                }
                if cut.head && span.start < start && span.end > start {
                    start = span.end;
                }
            }
            end = end.max(start);
            if (start, end) == before {
                return before;
            }
        }
    }
}

/// The edge drop without the known secrets.
fn edge_drop(text: &str, cut: Cut) -> (usize, usize) {
    let mut start = 0;
    if cut.head {
        start = match text.find('\n') {
            Some(i) => i + 1,
            None => head_boundary(text),
        };
    }
    let mut end = text.len();
    if cut.tail {
        let rest = text.get(start..).unwrap_or_default();
        end = match rest.rfind('\n') {
            Some(i) => start + i + 1,
            None => tail_boundary(text, start),
        }
        .max(start);
    }
    (start, end)
}

/// True for a character that ends a value: NUL, white space, `,` `;` `&` `"` and `'`.
fn is_separator(c: char) -> bool {
    c == '\0' || c.is_whitespace() || matches!(c, ',' | ';' | '&' | '"' | '\'')
}

/// Where the kept text of a head-cut buffer with no newline starts: [`WINDOW`] bytes in, then after the
/// first separator at or past that point. No separator within another [`WINDOW`] bytes: the end, so the
/// whole buffer goes.
fn head_boundary(text: &str) -> usize {
    if text.len() <= WINDOW {
        return text.len();
    }
    let at = text.ceil_char_boundary(WINDOW);
    let stop = text.ceil_char_boundary(at.saturating_add(WINDOW).min(text.len()));
    text.get(at..stop)
        .unwrap_or_default()
        .char_indices()
        .find(|&(_, c)| is_separator(c))
        .map_or(text.len(), |(i, c)| at + i + c.len_utf8())
}

/// Where the kept text of a tail-cut buffer with no newline ends: [`WINDOW`] bytes before the end, then
/// back to just after the last separator before that point (and not before `floor`). No separator
/// within another [`WINDOW`] bytes: `floor`, so the whole buffer goes.
fn tail_boundary(text: &str, floor: usize) -> usize {
    if text.len() <= WINDOW {
        return floor;
    }
    let at = text.floor_char_boundary(text.len() - WINDOW);
    let from = text.ceil_char_boundary(at.saturating_sub(WINDOW).max(floor));
    text.get(from..at)
        .unwrap_or_default()
        .char_indices()
        .rev()
        .find(|&(_, c)| is_separator(c))
        .map_or(floor, |(i, c)| from + i + c.len_utf8())
}

/// The label of an armor line such as `-----BEGIN RSA PRIVATE KEY-----`, given the prefix up to the
/// label. A line with no closing dashes gives the whole line, which never matches a real label, so the
/// guards treat it as unmatched and remove more, not less.
fn armor_label<'a>(line: &'a str, prefix: &str) -> &'a str {
    let rest = line.strip_prefix(prefix).unwrap_or(line);
    rest.find("-----")
        .and_then(|end| rest.get(..end))
        .unwrap_or(rest)
}

/// A private key that starts and never ends: removed through the end of the text. The END line must
/// carry the label of the BEGIN line, so one key's END does not close another's BEGIN.
fn unterminated_begin(text: &str, out: &mut Vec<Span>) {
    for (at, _) in text.match_indices("-----BEGIN ") {
        let line = text
            .get(at..)
            .and_then(|t| t.split(['\n', '\r']).next())
            .unwrap_or_default();
        let label = armor_label(line, "-----BEGIN ");
        if !label.contains("PRIVATE KEY") {
            continue;
        }
        let after = at + line.len();
        let end_line = format!("-----END {label}-----");
        if !text.get(after..).unwrap_or_default().contains(&end_line) {
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

/// A private key whose start was cut off: removed from the start of the text through its END line. A
/// BEGIN line of another label before it does not count.
fn unmatched_end(text: &str, out: &mut Vec<Span>) {
    for (at, _) in text.match_indices("-----END ") {
        let line_end = text
            .get(at..)
            .and_then(|t| t.find(['\n', '\r']))
            .map_or(text.len(), |i| at + i);
        let line = text.get(at..line_end).unwrap_or_default();
        let label = armor_label(line, "-----END ");
        if !label.contains("PRIVATE KEY") {
            continue;
        }
        let begin_line = format!("-----BEGIN {label}-----");
        if text.get(..at).unwrap_or_default().contains(&begin_line) {
            continue;
        }
        out.push(Span {
            start: 0,
            end: line_end,
            rule: PEM_RULE,
            priority: PEM_PRIORITY,
        });
        return;
    }
}

/// With both ends cut, the body of a key can be the whole kept text, with neither armor line in it. A
/// run of long base64 lines is removed. It also removes a base64 blob, which is the safe side.
fn bare_body(text: &str, out: &mut Vec<Span>) {
    // start, end and line count of the run so far.
    let mut run: Option<(usize, usize, usize)> = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        let body = trimmed.len() >= BODY_LINE_MIN
            && trimmed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        if body {
            let end = offset + trimmed.len();
            run = Some(match run {
                Some((start, _, lines)) => (start, end, lines + 1),
                None => (offset, end, 1),
            });
        } else {
            push_run(run.take(), out);
        }
        offset += line.len();
    }
    push_run(run, out);
}

fn push_run(run: Option<(usize, usize, usize)>, out: &mut Vec<Span>) {
    if let Some((start, end, lines)) = run
        && lines >= BODY_LINES_MIN
    {
        out.push(Span {
            start,
            end,
            rule: PEM_RULE,
            priority: PEM_PRIORITY,
        });
    }
}

#[cfg(test)]
mod edges;
#[cfg(test)]
mod tests;
