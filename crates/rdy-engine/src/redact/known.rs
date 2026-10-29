//! The run-scoped known-secret set (ADR 0015 decision 3, 02 "From finding to result").
//!
//! The facade registers the secrets it handles: the kubeconfig token and client key data, the proxy
//! password and the values of declared environment variables whose name looks like a secret. The
//! redactor then removes them wherever they appear, in any string, with no rule needed to recognise
//! their shape. The set is shared by every clone of a [`super::Redactor`], so the report, the action
//! log, the log writer and the CLI error text all see the same secrets.
//!
//! A secret is stored in the forms it takes in output: as given, percent-encoded (a URL) and
//! JSON-escaped (a log line that holds JSON). A multi-line value is also stored line by line.
//!
//! Nothing here prints a secret. `Debug` shows a count.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use super::span::Span;

/// The shortest secret that is matched exactly. A shorter value would redact common words and numbers
/// across the whole report.
pub const MIN_LEN: usize = 6;

/// The shortest prefix or suffix of a secret that is removed at a truncated edge.
pub(crate) const EDGE_MIN: usize = 8;

/// The most bytes the set holds, all forms together. Past it [`KnownSecrets::add`] refuses what does
/// not fit and returns `false`. The budget is bytes, not entries, so a long key file cannot use up a
/// count of slots that a later, short secret needed.
const MAX_TOTAL_BYTES: usize = 512 * 1024;

/// A backstop on the number of entries, because each one is a scan of every string. At the minimum
/// length it is far past what a real run registers.
const MAX_ENTRIES: usize = 4096;

/// Longest value accepted, in bytes.
const MAX_LEN: usize = 64 * 1024;

/// Priority of a known secret. Above every rule: a value the facade handled is a secret whatever shape
/// it has (see [`super::rules::priority`]).
pub(crate) const PRIORITY: u8 = 100;

/// The rule name in placeholders and counts.
pub(crate) const RULE: &str = "known_secret";

/// The count of a secret the set refused (too short, too long or no room). It is a count of refusals in
/// the report's `redaction.by_rule`, not a placeholder.
pub(crate) const REFUSED_RULE: &str = "known_secret_refused";

#[derive(Default)]
struct Inner {
    /// Replaced whole on every change, so a scan holds its own `Arc` and never the lock.
    list: Arc<[String]>,
    bytes: usize,
}

/// The secrets of one run. Clones share one list.
#[derive(Clone, Default)]
pub(crate) struct KnownSecrets {
    inner: Arc<Mutex<Inner>>,
}

impl fmt::Debug for KnownSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KnownSecrets({})", self.len())
    }
}

impl KnownSecrets {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock still holds a valid list. Redaction must keep working.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The list as it is now. A scan uses this and holds no lock.
    fn snapshot(&self) -> Arc<[String]> {
        Arc::clone(&self.lock().list)
    }

    /// Adds a secret and the forms it takes in output. Returns `false` if anything was refused: the
    /// value is too short or too long, or the set has no room for all of its forms. What fits is added.
    ///
    /// A value of several lines is added whole and line by line, because a line of a key file shows up
    /// alone in a truncated buffer. Lines that are PEM armor (`-----BEGIN ...`) are not added: they are
    /// public and the PEM rule owns them.
    pub(crate) fn add(&self, secret: &str) -> bool {
        let secret = secret.trim();
        if secret.len() < MIN_LEN || secret.len() > MAX_LEN {
            return false;
        }
        let mut bases = vec![secret];
        if secret.contains(['\n', '\r']) {
            bases.extend(
                secret
                    .lines()
                    .map(str::trim)
                    .filter(|line| line.len() >= MIN_LEN && !line.starts_with("-----")),
            );
        }
        let mut forms = Vec::with_capacity(bases.len() * 3);
        for base in bases {
            forms.push(base.to_owned());
            forms.extend(Some(percent_encoded(base)).filter(|form| form != base));
            forms.extend(json_escaped(base).filter(|form| form != base));
        }
        let mut inner = self.lock();
        let mut list = inner.list.to_vec();
        let mut bytes = inner.bytes;
        let mut ok = true;
        for form in forms {
            if list.contains(&form) {
                continue;
            }
            if list.len() >= MAX_ENTRIES || bytes + form.len() > MAX_TOTAL_BYTES {
                ok = false;
                continue;
            }
            bytes += form.len();
            list.push(form);
        }
        if bytes != inner.bytes {
            inner.list = list.into();
            inner.bytes = bytes;
        }
        ok
    }

    /// The number of entries in the set.
    pub(crate) fn len(&self) -> usize {
        self.lock().list.len()
    }

    /// Spans of every exact occurrence of every secret in `text`, except those inside a placeholder this
    /// redactor wrote earlier, so that a second pass changes nothing.
    pub(crate) fn exact_spans(&self, text: &str, out: &mut Vec<Span>) {
        let list = self.snapshot();
        if list.is_empty() {
            return;
        }
        let placeholders = placeholders(text);
        for secret in list.iter() {
            out.extend(
                text.match_indices(secret.as_str())
                    .map(|(start, found)| (start, start + found.len()))
                    .filter(|&(start, end)| !inside(&placeholders, start, end))
                    .map(|(start, end)| Span {
                        start,
                        end,
                        rule: RULE,
                        priority: PRIORITY,
                    }),
            );
        }
    }

    /// Spans for a secret cut by a truncated edge: a prefix of a secret (at least [`EDGE_MIN`] bytes)
    /// at the very end of `text` when the tail was cut, and a suffix at the very start when the head
    /// was cut. The longest one wins; shorter ones lie inside it.
    pub(crate) fn edge_spans(&self, text: &str, head: bool, tail: bool, out: &mut Vec<Span>) {
        if !head && !tail {
            return;
        }
        let list = self.snapshot();
        let placeholders = placeholders(text);
        for secret in list.iter() {
            if tail
                && let Some(k) = longest_prefix_at_end(secret, text)
                && !inside(&placeholders, text.len() - k, text.len())
            {
                out.push(Span {
                    start: text.len() - k,
                    end: text.len(),
                    rule: RULE,
                    priority: PRIORITY,
                });
            }
            if head
                && let Some(k) = longest_suffix_at_start(secret, text)
                && !inside(&placeholders, 0, k)
            {
                out.push(Span {
                    start: 0,
                    end: k,
                    rule: RULE,
                    priority: PRIORITY,
                });
            }
        }
    }
}

/// The form a URL carries: every byte but an unreserved one as `%XX`.
fn percent_encoded(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len() + 8);
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// The form inside a JSON string: quotes, backslashes and control characters escaped.
fn json_escaped(value: &str) -> Option<String> {
    let quoted = serde_json::to_string(value).ok()?;
    quoted
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
}

/// The byte ranges of well-formed placeholders (`[REDACTED:<rule>:<8 hex>]`) in `text`, in order. A
/// bracket that only looks like one is not a placeholder, so text cannot hide a secret inside it.
fn placeholders(text: &str) -> Vec<(usize, usize)> {
    const OPEN: &str = "[REDACTED:";
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for (at, _) in text.match_indices(OPEN) {
        let rule_start = at + OPEN.len();
        let mut i = rule_start;
        while bytes
            .get(i)
            .is_some_and(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'))
        {
            i += 1;
        }
        if i == rule_start || bytes.get(i) != Some(&b':') {
            continue;
        }
        let tag = bytes.get(i + 1..i + 9).unwrap_or_default();
        let hex = tag.len() == 8 && tag.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if hex && bytes.get(i + 9) == Some(&b']') {
            out.push((at, i + 10));
        }
    }
    out
}

/// True if `start..end` lies inside one of the sorted `ranges`.
fn inside(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    let i = ranges.partition_point(|&(range_start, _)| range_start <= start);
    i.checked_sub(1)
        .and_then(|j| ranges.get(j))
        .is_some_and(|&(_, range_end)| end <= range_end)
}

/// The length of the longest proper prefix of `secret` (at least [`EDGE_MIN`]) that `text` ends with.
fn longest_prefix_at_end(secret: &str, text: &str) -> Option<usize> {
    let most = secret.len().saturating_sub(1).min(text.len());
    (EDGE_MIN..=most)
        .rev()
        .find(|&k| secret.get(..k).is_some_and(|prefix| text.ends_with(prefix)))
}

/// The length of the longest proper suffix of `secret` (at least [`EDGE_MIN`]) that `text` starts with.
fn longest_suffix_at_start(secret: &str, text: &str) -> Option<usize> {
    let most = secret.len().saturating_sub(1).min(text.len());
    (EDGE_MIN..=most).rev().find(|&k| {
        secret
            .get(secret.len() - k..)
            .is_some_and(|suffix| text.starts_with(suffix))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(set: &KnownSecrets, text: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        set.exact_spans(text, &mut out);
        let mut found: Vec<_> = out.iter().map(|s| (s.start, s.end)).collect();
        found.sort_unstable();
        found
    }

    #[test]
    fn short_values_are_refused_and_long_ones_found_everywhere() {
        let set = KnownSecrets::default();
        assert!(!set.add("abc12"));
        // Exactly the minimum is accepted.
        assert!(set.add("abc123"));
        assert!(set.add("  tok-123456  "));
        assert_eq!(set.len(), 2);
        assert_eq!(
            spans(&set, "a tok-123456 b tok-123456"),
            [(2, 12), (15, 25)]
        );
        assert!(spans(&set, "tok-12345").is_empty());
        assert_eq!(spans(&set, "x abc123"), [(2, 8)]);
    }

    #[test]
    fn a_multi_line_value_is_added_whole_and_by_line_but_not_its_armor() {
        let set = KnownSecrets::default();
        assert!(set.add(
            "-----BEGIN PRIVATE KEY-----\nLINE-ONE-AAAA\nLINE-TWO-BBBB\n-----END PRIVATE KEY-----"
        ));
        assert!(!spans(&set, "x LINE-TWO-BBBB y").is_empty());
        assert!(spans(&set, "-----BEGIN PRIVATE KEY-----").is_empty());
    }

    #[test]
    fn adding_twice_keeps_one_entry() {
        let set = KnownSecrets::default();
        assert!(set.add("same-secret-1"));
        assert!(set.add("same-secret-1"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn the_set_is_bounded_by_total_bytes_and_a_refusal_is_reported() {
        let set = KnownSecrets::default();
        // Eight 64 KiB values fill the budget exactly. A count of entries would not have noticed.
        for i in 0..8 {
            let value = format!("{i:04}{}", "x".repeat(MAX_LEN - 4));
            assert!(set.add(&value), "value {i}");
        }
        assert_eq!(set.len(), 8);
        assert!(!set.add("one-more-secret"));
        assert!(!set.add(&"x".repeat(MAX_LEN + 1)));
        assert_eq!(set.len(), 8);
        // Many tiny values are bounded by the entry backstop.
        let tiny = KnownSecrets::default();
        let mut refused = false;
        for i in 0..MAX_ENTRIES + 10 {
            refused |= !tiny.add(&format!("tiny-{i:06}"));
        }
        assert!(refused);
        assert_eq!(tiny.len(), MAX_ENTRIES);
    }

    #[test]
    fn a_long_key_file_does_not_crowd_out_a_later_short_secret() {
        let set = KnownSecrets::default();
        let key: String = (0..1000).map(|i| format!("LINE{i:05}ABCDEFGH\n")).collect();
        assert!(set.add(&key));
        assert!(set.add("later-token-1"));
        assert!(!spans(&set, "x later-token-1").is_empty());
    }

    #[test]
    fn the_percent_encoded_and_json_escaped_forms_are_found_too() {
        let set = KnownSecrets::default();
        assert!(set.add("p@ss \"w0rd\"/9"));
        assert!(!spans(&set, "https://u:p%40ss%20%22w0rd%22%2F9@h/").is_empty());
        assert!(!spans(&set, r#"{"pw":"p@ss \"w0rd\"/9"}"#).is_empty());
        assert!(!spans(&set, "raw p@ss \"w0rd\"/9 raw").is_empty());
    }

    #[test]
    fn a_match_inside_a_placeholder_is_skipped_but_a_lookalike_is_not_a_placeholder() {
        let set = KnownSecrets::default();
        assert!(set.add("REDACTED"));
        assert!(set.add("deadbeef"));
        assert!(set.add("known_secret"));
        // Well formed: nothing inside it matches, so a second pass changes nothing.
        let text = "a [REDACTED:known_secret:deadbeef] b [REDACTED:rule.x:0123abcd]";
        assert!(spans(&set, text).is_empty(), "{:?}", spans(&set, text));
        // A bracket that is not a placeholder does not hide a secret.
        assert_eq!(spans(&set, "[REDACTED:A:deadbeef"), [(1, 9), (12, 20)]);
    }

    #[test]
    fn clones_share_one_list_and_debug_shows_a_count_only() {
        let a = KnownSecrets::default();
        let b = a.clone();
        assert!(b.add("shared-secret-value"));
        assert_eq!(a.len(), 1);
        assert_eq!(format!("{a:?}"), "KnownSecrets(1)");
    }

    #[test]
    fn edge_spans_find_the_longest_cut_prefix_or_suffix() {
        let set = KnownSecrets::default();
        assert!(set.add("0123456789abcdef"));
        let mut out = Vec::new();
        set.edge_spans("log line 0123456789ab", false, true, &mut out);
        assert_eq!((out[0].start, out[0].end), (9, 21));
        out.clear();
        set.edge_spans("6789abcdef rest", true, false, &mut out);
        assert_eq!((out[0].start, out[0].end), (0, 10));
        out.clear();
        // Too short, the wrong edge, or no edge cut: nothing.
        set.edge_spans("x 0123456", false, true, &mut out);
        set.edge_spans("x 0123456789ab", true, false, &mut out);
        set.edge_spans("x 0123456789ab", false, false, &mut out);
        assert!(out.is_empty());
    }
}
