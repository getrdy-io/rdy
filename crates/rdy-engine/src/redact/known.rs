//! The run-scoped known-secret set (ADR 0015 decision 3, 02 "From finding to result").
//!
//! The facade registers the secrets it handles: the kubeconfig token and client key data, the proxy
//! password and the values of declared environment variables whose name looks like a secret. The
//! redactor then removes them wherever they appear, in any string, with no rule needed to recognise
//! their shape. The set is shared by every clone of a [`super::Redactor`], so the report, the action
//! log, the log writer and the CLI error text all see the same secrets.
//!
//! Nothing here prints a secret. `Debug` shows a count.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use super::span::Span;

/// The shortest secret that is matched exactly. A shorter value would redact common words and numbers
/// across the whole report.
const MIN_LEN: usize = 6;

/// The shortest prefix or suffix of a secret that is removed at a truncated edge.
pub(crate) const EDGE_MIN: usize = 8;

/// Most entries kept. Past it [`KnownSecrets::add`] refuses and returns `false`.
const MAX_ENTRIES: usize = 1024;

/// Longest value kept, in bytes.
const MAX_LEN: usize = 64 * 1024;

/// Priority of a known secret. Above every rule: a value the facade handled is a secret whatever shape
/// it has (see [`super::rules::priority`]).
pub(crate) const PRIORITY: u8 = 100;

/// The rule name in placeholders and counts.
pub(crate) const RULE: &str = "known_secret";

/// The secrets of one run. Clones share one list.
#[derive(Clone, Default)]
pub(crate) struct KnownSecrets {
    list: Arc<Mutex<Vec<String>>>,
}

impl fmt::Debug for KnownSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KnownSecrets({})", self.len())
    }
}

impl KnownSecrets {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        // A poisoned lock still holds a valid list. Redaction must keep working.
        self.list.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds a secret. Returns `false` if it was refused: too short, too long or the set is full.
    ///
    /// A value of several lines is added whole and line by line, because a line of a key file shows up
    /// alone in a truncated buffer. Lines that are PEM armor (`-----BEGIN ...`) are not added: they are
    /// public and the PEM rule owns them.
    pub(crate) fn add(&self, secret: &str) -> bool {
        let secret = secret.trim();
        if secret.len() < MIN_LEN || secret.len() > MAX_LEN {
            return false;
        }
        let mut list = self.lock();
        let mut ok = push(&mut list, secret);
        if secret.contains(['\n', '\r']) {
            for line in secret.lines().map(str::trim) {
                if line.len() >= MIN_LEN && !line.starts_with("-----") {
                    ok &= push(&mut list, line);
                }
            }
        }
        ok
    }

    /// The number of secrets in the set.
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    /// Spans of every exact occurrence of every secret in `text`.
    pub(crate) fn exact_spans(&self, text: &str, out: &mut Vec<Span>) {
        for secret in self.lock().iter() {
            out.extend(
                text.match_indices(secret.as_str())
                    .map(|(start, found)| Span {
                        start,
                        end: start + found.len(),
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
        for secret in self.lock().iter() {
            if tail && let Some(k) = longest_prefix_at_end(secret, text) {
                out.push(Span {
                    start: text.len() - k,
                    end: text.len(),
                    rule: RULE,
                    priority: PRIORITY,
                });
            }
            if head && let Some(k) = longest_suffix_at_start(secret, text) {
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

fn push(list: &mut Vec<String>, secret: &str) -> bool {
    if list.iter().any(|known| known == secret) {
        return true;
    }
    if list.len() >= MAX_ENTRIES {
        return false;
    }
    list.push(secret.to_owned());
    true
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
        out.iter().map(|s| (s.start, s.end)).collect()
    }

    #[test]
    fn short_values_are_refused_and_long_ones_found_everywhere() {
        let set = KnownSecrets::default();
        assert!(!set.add("abc12"));
        assert!(set.add("  tok-123456  "));
        assert_eq!(set.len(), 1);
        assert_eq!(
            spans(&set, "a tok-123456 b tok-123456"),
            [(2, 12), (15, 25)]
        );
        assert!(spans(&set, "tok-12345").is_empty());
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
    fn adding_twice_keeps_one_entry_and_the_set_is_bounded() {
        let set = KnownSecrets::default();
        assert!(set.add("same-secret-1"));
        assert!(set.add("same-secret-1"));
        assert_eq!(set.len(), 1);
        for i in 0..MAX_ENTRIES {
            let _ = set.add(&format!("secret-number-{i}"));
        }
        assert_eq!(set.len(), MAX_ENTRIES);
        assert!(!set.add("one-more-secret"));
        assert!(!set.add(&"x".repeat(MAX_LEN + 1)));
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
