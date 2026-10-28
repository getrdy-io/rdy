//! The redactor (ADR 0015, 04 section 3).
//!
//! Every string that reaches a report, a log line or an error message goes through a [`Redactor`] first.
//! The contract, in short:
//!
//! - **Compiled in, add only.** The rules ship in the binary. A spec can add rules later. It cannot remove
//!   or weaken one.
//! - **Spans merge by union.** Every rule looks at the original text and reports byte ranges. Overlapping
//!   or touching ranges merge into one range, named after the highest priority rule in it. The output is
//!   written once, so no rule sees a placeholder and no partly overlapped secret leaves bytes behind.
//! - **Keyed tags.** A placeholder is `[REDACTED:<rule>:<tag>]`. The tag is the first 4 bytes of
//!   HMAC-SHA256 over the secret bytes, under a random per-run [`TagKey`] that is never written. Equal
//!   secrets get equal tags inside one run. Nothing hashes raw content without the key.
//! - **A typed gate.** [`Redacted<T>`] has no public constructor, `From`, `Default` or `Deserialize`, and
//!   no `DerefMut`. A writer that takes only `&Redacted<_>` cannot be handed raw text.
//! - **Fail closed.** If redaction cannot be trusted for a string, the whole string is replaced. Raw text
//!   is never the fallback. If the OS cannot make a key, [`TagKey::generate`] fails and rdy exits 70.
//!
//! This is the M1-048 core: the engine, the key, the gate and the first rule (`secret_by_key`). M1-060
//! adds the other M1 rules. M1-056 wires the tracing writer, panic hook and CLI errors. M1-062 adds the
//! report walk and `RedactedReport`.

// `TagKey::fixed` makes tags predictable. It is for tests only, so a release build with the `testing`
// feature is refused. A debug build is allowed so `cargo test` and `cargo clippy --features testing` work.
// Cargo unifies features across a workspace build, so build the shipped binary with
// `cargo build --release -p rdy`, and let CI also check `cargo tree -e features -p rdy` for `testing`.
#[cfg(all(feature = "testing", not(test), not(debug_assertions)))]
compile_error!("the `testing` feature of rdy-engine must not be enabled in a release build");

mod key;
mod rules;
mod span;

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;

pub use key::TagKey;

use rules::{BUILT_IN, Rule};
use span::{Span, merge};

/// The rule name used when a string had to be replaced whole because redaction failed.
const FAIL_CLOSED_RULE: &str = "redactor_error";

/// Why redaction could not run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RedactError {
    /// The operating system could not supply random bytes for the tag key.
    #[error(
        "the operating system could not supply random bytes for the redaction key. \
         Fix: check that the OS random source works (on Linux, the getrandom call or /dev/urandom), \
         then run rdy again"
    )]
    NoRandomness,
}

/// Text that has been through a [`Redactor`].
///
/// Only the redactor builds one. There is no public constructor, no `From`, no `Default` and no
/// `Deserialize`, and no `DerefMut`, so a function that takes `&Redacted<_>` cannot be given raw text.
/// Read the value through `Deref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// The only way in. Private to this module and its children, which are the redactor.
    fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: fmt::Display> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How many placeholders each rule wrote in one call or one walk.
///
/// Counts only, never matched text (ADR 0015 decision 7). A [`Redactor`] does not keep counts. The caller
/// owns a `RuleCounts` for the unit of work it reports on, so log lines never change a report's numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleCounts {
    by_rule: BTreeMap<&'static str, u64>,
}

impl RuleCounts {
    /// The number of placeholders written for this rule.
    #[must_use]
    pub fn get(&self, rule: &str) -> u64 {
        self.by_rule.get(rule).copied().unwrap_or(0)
    }

    /// The number of placeholders written by all rules.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.by_rule.values().sum()
    }

    /// Rule names and counts, in rule name order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.by_rule.iter().map(|(rule, n)| (*rule, *n))
    }

    fn add(&mut self, rule: &'static str) {
        *self.by_rule.entry(rule).or_insert(0) += 1;
    }
}

/// Removes secrets from text.
///
/// It holds the per-run [`TagKey`] and nothing else, so it is cheap to clone and safe to share. Build it
/// first in `main`, before the spec is read.
#[derive(Debug, Clone)]
pub struct Redactor {
    key: TagKey,
}

impl Redactor {
    /// A redactor with the built-in rules.
    #[must_use]
    pub fn new(key: TagKey) -> Self {
        Self { key }
    }

    /// Redacts one string. Never fails and never returns raw text for a string it could not handle.
    #[must_use]
    pub fn redact_str(&self, text: &str) -> Redacted<String> {
        self.redact_str_counted(text, &mut RuleCounts::default())
    }

    /// Redacts one string and adds what it did to `counts`.
    #[must_use]
    pub fn redact_str_counted(&self, text: &str, counts: &mut RuleCounts) -> Redacted<String> {
        self.run(BUILT_IN, text, counts)
    }

    /// The engine. Runs every rule on the original text, merges the spans, writes the output once.
    fn run(&self, rules: &[Rule], text: &str, counts: &mut RuleCounts) -> Redacted<String> {
        let mut spans = Vec::new();
        let mut found = Vec::new();
        // An inverted range (start after end) is a rule bug. It must fail closed, not vanish.
        let mut ranges_ok = true;
        for rule in rules {
            found.clear();
            (rule.find)(text, &mut found);
            ranges_ok &= found.iter().all(|r| r.start <= r.end);
            spans.extend(found.drain(..).map(|r| Span {
                start: r.start,
                end: r.end,
                rule: rule.name,
                priority: rule.priority,
            }));
        }
        let spans = merge(spans);
        match ranges_ok.then(|| self.write(text, &spans)).flatten() {
            Some(out) => {
                for span in &spans {
                    counts.add(span.rule);
                }
                Redacted::new(out)
            }
            None => {
                // A rule reported a range outside the text or inside a character. Do not guess:
                // drop the whole string.
                counts.add(FAIL_CLOSED_RULE);
                Redacted::new(self.placeholder(FAIL_CLOSED_RULE, text.as_bytes()))
            }
        }
    }

    /// Writes the text with each span replaced. `None` if any span is not a valid char range.
    fn write(&self, text: &str, spans: &[Span]) -> Option<String> {
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for span in spans {
            out.push_str(text.get(cursor..span.start)?);
            let secret = text.get(span.start..span.end)?;
            out.push_str(&self.placeholder(span.rule, secret.as_bytes()));
            cursor = span.end;
        }
        out.push_str(text.get(cursor..)?);
        Some(out)
    }

    fn placeholder(&self, rule: &str, secret: &[u8]) -> String {
        format!("[REDACTED:{rule}:{}]", self.key.tag(secret))
    }
}

#[cfg(test)]
mod tests;
