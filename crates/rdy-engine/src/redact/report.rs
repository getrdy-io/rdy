//! The report walk: redact every string, then cap it (ADR 0015 decision 4, 02 "From finding to result",
//! 04 section 3.2).
//!
//! A [`Report`] (or one [`CheckResult`] or [`Action`] as it completes) is turned into a JSON value and walked.
//! Typed fields keep their names and their non-string values. Every string goes through the redactor
//! first and is capped second, so a secret that straddles a cap is gone before the cap can cut it. The
//! result comes back as a [`Redacted`] value, which is the only thing the writers and renderers accept.
//!
//! The caps, in bytes, cut on a character boundary and never inside a placeholder or a reference the key
//! rule leaves alone (`${NAME}`, a `/run/secrets/` path, `null`), and never between a key and the opening
//! quote of either. A cut inside such a token backs up to where the token starts. A cut string ends with ` [truncated]`, and the check's `truncated`
//! flag is set. A trailing marker is set aside while a string is redacted and put back after, so a second
//! pass over a cut string changes nothing and counts nothing.
//!
//! | Where | Cap |
//! | --- | --- |
//! | `message`, each of `notes` | 1 KiB, and 20 notes |
//! | `fix`, `builtin_fix`, every other string | 4 KiB |
//! | `observed` and `expected` | 64 KiB each, measured as compact JSON, and lists cut to 200 items |
//!
//! `observed`, `expected`, an action's `argv` and the env pairs inside them are free-form, so they also
//! get the whole-member rule: the strings and numbers under a member whose key names a secret
//! (`password`, `api_token`) and the `value` of a `{name, value}` (or `{key, value}`) pair whose name
//! does are replaced whole. Numbers stay only when the key's last word is a unit or a count
//! (`token_ttl_ms`, `password_len`), and only for a number directly under the key: a list or object under
//! it is replaced whole, so key material written as a byte array does not stay. Booleans and `null` stay.
//! Every list in free-form data is read as a command line, so `["--password", "hunter2", 5432]` loses its
//! second item. The rule never touches a schema-defined field, so `summary.pass` and a key such as
//! `passed` survive.
//!
//! `redaction.total` and `by_rule` count every replacement the walk made, including in text that a later
//! cap or cut dropped (a list past 200 items, notes past 20, keys dropped to fit 64 KiB). They are never
//! lower than what was hidden.
//!
//! The 2 MiB cap on the whole document is measured on the written bytes, so it belongs to the writer.

use std::collections::HashSet;

use rdy_spec::result::{Action, CheckResult, Redaction, RedactionRuleset, Report};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::rules::{
    SECRET_BY_KEY, is_exempt_value, is_secret_key, last_word_is_unit, placeholder_spans,
};
use super::{RedactError, Redacted, RedactedReport, Redactor, RuleCounts};

const KIB: usize = 1024;
/// `message` and each note.
const MESSAGE_CAP: usize = KIB;
/// `fix`, `builtin_fix` and every other string.
const STRING_CAP: usize = 4 * KIB;
/// `observed` and `expected`, as compact JSON.
const FREE_FORM_CAP: usize = 64 * KIB;
/// Items in a list inside `observed` or `expected`.
const MAX_LIST_ITEMS: usize = 200;
/// Notes on one result.
const MAX_NOTES: usize = 20;
/// What a cut string ends with.
const CUT_MARKER: &str = " [truncated]";

impl Redactor {
    /// Redacts, then caps, every string of a report and returns the only value the writers accept.
    ///
    /// The `redaction` block of the result counts what this call did. If some results were redacted
    /// earlier with [`Redactor::redact_check`], use [`Redactor::redact_report_counted`] so their counts are
    /// kept. Run it on the final report and on the watchdog's snapshot alike: it does not need a runtime
    /// and never assumes its input was redacted.
    ///
    /// # Errors
    ///
    /// [`RedactError::ReportShape`] if the walked report no longer reads as a report. No report is then
    /// written and rdy exits 70.
    pub fn redact_report(&self, report: Report) -> Result<RedactedReport, RedactError> {
        self.redact_report_counted(report, RuleCounts::default())
    }

    /// Like [`Redactor::redact_report`], with the counts of the results redacted earlier added in.
    ///
    /// Counts come from the caller only. A [`Redactor`] keeps none, so log lines never change them.
    ///
    /// # Errors
    ///
    /// As [`Redactor::redact_report`].
    pub fn redact_report_counted(
        &self,
        report: Report,
        earlier: RuleCounts,
    ) -> Result<RedactedReport, RedactError> {
        let mut report = report;
        // Whatever the caller put there is not trusted: the block is rebuilt from this walk's counts.
        report.redaction = Redaction::new(RedactionRuleset::Report);
        let mut value = to_value(&report)?;
        drop(report);
        let mut counts = earlier;
        Walk::new(self, &mut counts).report(&mut value);
        let mut out: Report = from_value(value)?;
        out.redaction.total = counts.total();
        out.redaction.by_rule = counts
            .iter()
            .map(|(rule, n)| (rule.to_owned(), n))
            .collect();
        Ok(Redacted::new(out))
    }

    /// Redacts, then caps, one result as it completes, and adds what it did to `counts`.
    ///
    /// The scheduler's snapshot, the progress events and the terminal see only this text. Pass the same
    /// `counts` to [`Redactor::redact_report_counted`] at the end.
    ///
    /// # Errors
    ///
    /// [`RedactError::ReportShape`] if the result no longer reads as a result.
    pub fn redact_check(
        &self,
        check: CheckResult,
        counts: &mut RuleCounts,
    ) -> Result<Redacted<CheckResult>, RedactError> {
        let mut value = to_value(&check)?;
        drop(check);
        Walk::new(self, counts).check(&mut value);
        Ok(Redacted::new(from_value(value)?))
    }

    /// Redacts, then caps, one action log entry as it is written, and adds what it did to `counts`.
    ///
    /// # Errors
    ///
    /// [`RedactError::ReportShape`] if the entry no longer reads as an action.
    pub fn redact_action(
        &self,
        action: Action,
        counts: &mut RuleCounts,
    ) -> Result<Redacted<Action>, RedactError> {
        let mut value = to_value(&action)?;
        drop(action);
        Walk::new(self, counts).action(&mut value);
        Ok(Redacted::new(from_value(value)?))
    }
}

fn to_value<T: Serialize>(item: &T) -> Result<Value, RedactError> {
    // The serde error text can quote a value, so it is dropped here.
    serde_json::to_value(item).map_err(|_| RedactError::ReportShape)
}

fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, RedactError> {
    serde_json::from_value(value).map_err(|_| RedactError::ReportShape)
}

/// Room kept in a key for the suffix of a collision: `~` and a `u32` counter, at most 11 bytes, so 12.
const SUFFIX_ROOM: usize = 12;

/// One walk: the redactor, the tally it adds to, and whether any cap cut something since the flag was
/// last taken.
struct Walk<'a> {
    redactor: &'a Redactor,
    counts: &'a mut RuleCounts,
    cut: bool,
}

impl<'a> Walk<'a> {
    fn new(redactor: &'a Redactor, counts: &'a mut RuleCounts) -> Self {
        Self {
            redactor,
            counts,
            cut: false,
        }
    }

    /// Redacts one string. A trailing [`CUT_MARKER`] is set aside first and put back after, so the key
    /// rule never reads it as part of a value and a second pass over a cut string finds nothing new.
    fn text(&mut self, text: &str) -> String {
        let (head, marker) = split_marker(text);
        let mut out = self.redactor.redact_str_counted(head, self.counts).0;
        out.push_str(marker);
        out
    }

    /// Caps a redacted string and remembers whether it was cut.
    fn capped_text(&mut self, redacted: String, max: usize) -> String {
        let (text, was_cut) = cap(redacted, max);
        self.cut |= was_cut;
        text
    }

    /// The report: results and actions get their own caps, and everything else is a plain string field.
    /// The `redaction` block was reset before the walk, so walking it changes nothing.
    fn report(&mut self, report: &mut Value) {
        let Value::Object(fields) = report else {
            return self.generic(report);
        };
        for (name, value) in fields.iter_mut() {
            match (name.as_str(), value) {
                ("checks", Value::Array(checks)) => {
                    for check in checks {
                        self.check(check);
                    }
                }
                ("actions", Value::Array(actions)) => {
                    for action in actions {
                        self.action(action);
                    }
                }
                (_, value) => self.generic(value),
            }
        }
    }

    /// One result. Sets `truncated` when a cap cut any string, list or map in it.
    fn check(&mut self, check: &mut Value) {
        let outer = std::mem::replace(&mut self.cut, false);
        self.check_fields(check);
        let cut = std::mem::replace(&mut self.cut, outer);
        if cut && let Value::Object(fields) = check {
            fields.insert("truncated".to_owned(), Value::Bool(true));
        }
    }

    fn check_fields(&mut self, check: &mut Value) {
        let Value::Object(fields) = check else {
            return self.generic(check);
        };
        for (name, value) in fields.iter_mut() {
            match name.as_str() {
                "message" => self.capped(value, MESSAGE_CAP),
                "fix" | "builtin_fix" => self.capped(value, STRING_CAP),
                "notes" => self.notes(value),
                "observed" | "expected" => self.free_form(value),
                "truncated" => {}
                _ => self.generic(value),
            }
        }
    }

    /// One action entry. `argv` is free-form: a flag that names a secret takes the next argument whole.
    /// The entry's other fields are flattened into the same object, so its keys are redacted too.
    fn action(&mut self, action: &mut Value) {
        let Value::Object(fields) = action else {
            return self.generic(action);
        };
        for (name, value) in fields.iter_mut() {
            match (name.as_str(), value) {
                ("argv", Value::Array(args)) => self.argv(args, true),
                (_, value) => self.generic(value),
            }
        }
        self.rekey(fields);
    }

    /// Redacts every string, capped at [`STRING_CAP`], and the keys of every object.
    fn generic(&mut self, value: &mut Value) {
        match value {
            Value::String(s) => {
                let redacted = self.text(s);
                *s = self.capped_text(redacted, STRING_CAP);
            }
            Value::Array(items) => {
                for item in items {
                    self.generic(item);
                }
            }
            Value::Object(map) => {
                for (_, item) in map.iter_mut() {
                    self.generic(item);
                }
                self.rekey(map);
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// A string field with its own cap. Other value types are walked as plain fields.
    fn capped(&mut self, value: &mut Value, max: usize) {
        let Value::String(s) = value else {
            return self.generic(value);
        };
        let redacted = self.text(s);
        *s = self.capped_text(redacted, max);
    }

    fn notes(&mut self, value: &mut Value) {
        let Value::Array(notes) = value else {
            return self.generic(value);
        };
        for note in notes.iter_mut() {
            self.capped(note, MESSAGE_CAP);
        }
        if notes.len() > MAX_NOTES {
            notes.truncate(MAX_NOTES);
            self.cut = true;
        }
    }

    /// `observed` or `expected`: the whole-member rule, the list cut, then the size cap.
    fn free_form(&mut self, value: &mut Value) {
        self.free(value);
        if let Value::Object(map) = value {
            self.cut |= cap_map(map);
        }
    }

    fn free(&mut self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => {
                // Any list may hold a command line, with or without a number in it:
                // `["--password", "hunter2", 5432]`. Redact first and cut second, so what is dropped
                // has been counted like the rest.
                self.argv(items, false);
                if items.len() > MAX_LIST_ITEMS {
                    items.truncate(MAX_LIST_ITEMS);
                    self.cut = true;
                }
            }
            Value::Object(map) => {
                // `{"name": "DB_PASSWORD", "value": "..."}`: the name says what the value is.
                let pair = pair_name_is_secret(map);
                for (key, item) in map.iter_mut() {
                    if is_secret_key(key) {
                        self.blank(item, last_word_is_unit(key));
                    } else if let Some(keep_numbers) = pair
                        && key.eq_ignore_ascii_case("value")
                    {
                        self.blank(item, keep_numbers);
                    } else {
                        self.free(item);
                    }
                }
                self.rekey(map);
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Replaces every string and number under a secret-named member with a placeholder of its text.
    ///
    /// `keep_numbers` is true when the key's last word is a unit or a count (`token_ttl_ms`). It keeps a
    /// number that sits directly under the key. A list or object under the key is replaced whole, because
    /// key material is often a number array (`private_key_bytes: [48, 130]`). Empty strings and the forms
    /// the key rule leaves alone (`${NAME}`, `null`, a `/run/secrets/` path, a placeholder) stay, so the
    /// two rules agree. A trailing cut marker is set aside and put back, so a cut placeholder stays one.
    /// Booleans and `null` stay.
    fn blank(&mut self, value: &mut Value, keep_numbers: bool) {
        match value {
            Value::String(s) => {
                let (head, marker) = split_marker(s);
                if !head.is_empty() && !is_exempt_value(head) {
                    let mut out = self.redactor.placeholder(SECRET_BY_KEY, head.as_bytes());
                    out.push_str(marker);
                    *s = out;
                    self.counts.add(SECRET_BY_KEY);
                }
            }
            Value::Number(n) if !keep_numbers => {
                let text = n.to_string();
                *value = Value::String(self.redactor.placeholder(SECRET_BY_KEY, text.as_bytes()));
                self.counts.add(SECRET_BY_KEY);
            }
            Value::Array(items) => {
                for item in items {
                    self.blank(item, false);
                }
            }
            Value::Object(map) => {
                for (_, item) in map.iter_mut() {
                    self.blank(item, false);
                }
                self.rekey(map);
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Arguments of a command, or any list. Each string is redacted as a string. An argument that is a
    /// flag naming a secret (`--password`, with no `=`) takes the next item whole, whatever its type. The
    /// other items that are not strings are walked as plain fields (`capped`) or as free-form data, and
    /// they do not end the state: `["--password", "hunter2", 5432]` is still read as a command line.
    /// `capped` cuts each string at [`STRING_CAP`]; inside `observed` the 64 KiB cap does that job.
    fn argv(&mut self, args: &mut [Value], capped: bool) {
        let mut next_is_secret = false;
        for arg in args {
            if next_is_secret {
                self.blank(arg, false);
                next_is_secret = false;
                continue;
            }
            let Value::String(s) = arg else {
                if capped {
                    self.generic(arg);
                } else {
                    self.free(arg);
                }
                continue;
            };
            next_is_secret =
                s.starts_with('-') && !s.contains('=') && is_secret_key(s.trim_start_matches('-'));
            if capped {
                self.generic(arg);
            } else {
                let redacted = self.text(s);
                *s = redacted;
            }
        }
    }

    /// Redacts the keys of an object. A key that changes keeps its value and its place. If a changed key
    /// equals another key, the changed one gets `~2`, `~3` and so on, so no value is lost. The map is
    /// rebuilt in order, so the result does not depend on whether `serde_json` keeps insertion order.
    fn rekey(&mut self, map: &mut Map<String, Value>) {
        let new_keys: Vec<String> = map
            .keys()
            .map(|key| {
                let redacted = self.text(key);
                self.capped_text(redacted, STRING_CAP)
            })
            .collect();
        if map.keys().zip(&new_keys).all(|(old, new)| old == new) {
            return;
        }
        let old_map = std::mem::take(map);
        // Keys that did not change keep their names, so a renamed key never takes one.
        let mut taken: HashSet<String> = old_map
            .keys()
            .zip(&new_keys)
            .filter(|(old, new)| old == new)
            .map(|(old, _)| old.clone())
            .collect();
        for ((old, value), new) in old_map.into_iter().zip(new_keys) {
            if old == new {
                map.insert(old, value);
                continue;
            }
            let base = cut_str(&new, STRING_CAP - SUFFIX_ROOM).unwrap_or_else(|| new.clone());
            let mut key = new;
            let mut n = 2_u32;
            while taken.contains(&key) {
                key = format!("{base}~{n}");
                n = n.saturating_add(1);
            }
            taken.insert(key.clone());
            map.insert(key, value);
        }
    }
}

/// For a `{name, value}` pair (any of `name`/`Name`/`key`/`Key` next to `value`/`Value`): `Some` if the
/// name is a secret key, holding whether numbers under it stay (the name's last word is a unit).
fn pair_name_is_secret(map: &Map<String, Value>) -> Option<bool> {
    ["name", "Name", "key", "Key"]
        .iter()
        .filter_map(|k| map.get(*k).and_then(Value::as_str))
        .find(|name| is_secret_key(name))
        .map(last_word_is_unit)
}

/// Cuts `text` to at most `max` bytes, with the marker at the end, if it is longer. The flag says whether
/// it was cut. The cut falls on a character boundary and never inside a placeholder or a reference.
/// The JSON writer cuts the texts of `observed` and `expected` to the schema's 4 KiB with it.
pub(crate) fn cap(text: String, max: usize) -> (String, bool) {
    match cut_str(&text, max) {
        Some(cut) => (cut, true),
        None => (text, false),
    }
}

/// Splits a trailing [`CUT_MARKER`] off a string. The second part is empty if there is none.
fn split_marker(text: &str) -> (&str, &str) {
    text.strip_suffix(CUT_MARKER)
        .map_or((text, ""), |head| (head, CUT_MARKER))
}

/// How far [`exempt_token_start`] looks to each side of the cut. A longer token is not one the key rule
/// leaves alone in practice, and the cut then stays where it fell, which fails closed.
const TOKEN_WINDOW: usize = 512;

/// If `at` falls inside a token that the key rule leaves alone, where that token starts. A token runs
/// between blanks, quotes, `=`, `:`, `,` and `;`.
fn exempt_token_start(text: &str, at: usize) -> Option<usize> {
    const DELIMS: [char; 11] = [' ', '\t', '\n', '\r', '=', ':', '"', '\'', ',', ';', '\\'];
    let from = text.floor_char_boundary(at.saturating_sub(TOKEN_WINDOW));
    let to = text.ceil_char_boundary((at + TOKEN_WINDOW).min(text.len()));
    let start = match text.get(from..at)?.rfind(DELIMS) {
        Some(i) => from + i + 1,
        None if from == 0 => 0,
        None => return None,
    };
    let end = match text.get(at..to)?.find(DELIMS) {
        Some(i) => at + i,
        None if to == text.len() => to,
        None => return None,
    };
    let token = text.get(start..end)?;
    (start < at && at < end && is_exempt_value(token)).then_some(start)
}

fn cut_str(text: &str, max: usize) -> Option<String> {
    if text.len() <= max {
        return None;
    }
    let room = max.saturating_sub(CUT_MARKER.len());
    let mut at = text.floor_char_boundary(room);
    // A placeholder is never cut, and a cut never ends right behind one or in front of one's quote. Back
    // up to where it starts, and over the quote (and escapes) that open it, so `password="` or
    // `password="[REDACTED:..]` is not left as an open quote for a later pass to read as a value.
    // The same goes for a value the key rule leaves alone (`${NAME}`, a `/run/secrets/` path, `null`):
    // a cut inside it would leave a stub that a later pass reads as a secret.
    let back_to = placeholder_spans(text)
        .into_iter()
        .find(|span| span.start <= at && at <= span.end)
        .map(|span| span.start)
        .or_else(|| exempt_token_start(text, at));
    if let Some(start) = back_to {
        at = text
            .get(..start)
            .unwrap_or_default()
            .trim_end_matches(['"', '\\', '\''])
            .len();
    }
    let mut out = String::with_capacity(at + CUT_MARKER.len());
    out.push_str(text.get(..at).unwrap_or_default());
    out.push_str(CUT_MARKER);
    Some(out)
}

/// The size of a map as compact JSON. A map that cannot be measured counts as too big.
fn json_len(map: &Map<String, Value>) -> usize {
    serde_json::to_string(map).map_or(usize::MAX, |s| s.len())
}

/// Cuts every string in `value` that is longer than `max` bytes.
fn shorten(value: &mut Value, max: usize) {
    match value {
        Value::String(s) => {
            if let Some(cut) = cut_str(s, max) {
                *s = cut;
            }
        }
        Value::Array(items) => {
            for item in items {
                shorten(item, max);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                shorten(item, max);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The length of the longest string in `value`.
fn longest_string(value: &Value) -> usize {
    match value {
        Value::String(s) => s.len(),
        Value::Array(items) => items.iter().map(longest_string).max().unwrap_or(0),
        Value::Object(map) => map.values().map(longest_string).max().unwrap_or(0),
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

/// Brings a free-form map under [`FREE_FORM_CAP`]. Returns true if it cut anything.
///
/// First every string is cut to one common length, the longest one that fits. If that is not enough
/// (too many keys), keys are dropped from the end, as many as it takes. The map was redacted before this
/// runs, so a cut cannot leave part of a secret.
fn cap_map(map: &mut Map<String, Value>) -> bool {
    if json_len(map) <= FREE_FORM_CAP {
        return false;
    }
    let floor = CUT_MARKER.len();
    let fits = |max: usize| {
        let mut probe = map.clone();
        probe.values_mut().for_each(|v| shorten(v, max));
        json_len(&probe) <= FREE_FORM_CAP
    };
    if fits(floor) {
        let longest = map.values().map(longest_string).max().unwrap_or(floor);
        let (mut lo, mut hi) = (floor, longest.max(floor));
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if fits(mid) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        map.values_mut().for_each(|v| shorten(v, lo));
    } else {
        map.values_mut().for_each(|v| shorten(v, floor));
        let keys: Vec<String> = map.keys().cloned().collect();
        let keeps = |n: usize| {
            let probe: Map<String, Value> = keys
                .iter()
                .take(n)
                .filter_map(|k| map.get(k).map(|v| (k.clone(), v.clone())))
                .collect();
            json_len(&probe) <= FREE_FORM_CAP
        };
        let (mut lo, mut hi) = (0, keys.len());
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if keeps(mid) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        for key in keys.iter().skip(lo) {
            map.remove(key);
        }
    }
    true
}

#[cfg(test)]
mod tests;
