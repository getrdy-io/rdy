//! The report walk: redact every string, then cap it (ADR 0015 decision 4, 02 "From finding to result",
//! 04 section 3.2).
//!
//! A [`Report`] (or one [`CheckResult`] or [`Action`] as it completes) is turned into a JSON value and walked.
//! Typed fields keep their names and their non-string values. Every string goes through the redactor
//! first and is capped second, so a secret that straddles a cap is gone before the cap can cut it. The
//! result comes back as a [`Redacted`] value, which is the only thing the writers and renderers accept.
//!
//! The caps, in bytes, cut on a character boundary and never inside a placeholder. A cut string ends with
//! ` [truncated]`, and the check's `truncated` flag is set.
//!
//! | Where | Cap |
//! | --- | --- |
//! | `message`, each of `notes` | 1 KiB, and 20 notes |
//! | `fix`, `builtin_fix`, every other string | 4 KiB |
//! | `observed` and `expected` | 64 KiB each, measured as compact JSON, and lists cut to 200 items |
//!
//! `observed`, `expected`, an action's `argv` and the env pairs inside them are free-form, so they also
//! get the whole-member rule: the string values under a member whose key names a secret (`password`,
//! `api_token`) and the `value` of a `{name, value}` pair whose `name` does are replaced whole. Numbers,
//! booleans and `null` are kept: a count such as `token_ttl_ms` is not a secret. The rule never touches
//! a schema-defined field, so `summary.pass` and a key such as `passed` survive.
//!
//! The 2 MiB cap on the whole document is measured on the written bytes, so it belongs to the writer.

use rdy_spec::result::{Action, CheckResult, RedactionRuleset, Report};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::rules::{SECRET_BY_KEY, is_exempt_value, is_secret_key, placeholder_spans};
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
        let mut value = to_value(&report)?;
        drop(report);
        let mut counts = earlier;
        Walk::new(self, &mut counts).report(&mut value);
        let mut out: Report = from_value(value)?;
        out.redaction.ruleset = RedactionRuleset::Report;
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

/// One walk: the redactor and the tally it adds to.
struct Walk<'a> {
    redactor: &'a Redactor,
    counts: &'a mut RuleCounts,
}

impl<'a> Walk<'a> {
    fn new(redactor: &'a Redactor, counts: &'a mut RuleCounts) -> Self {
        Self { redactor, counts }
    }

    /// Redacts one string.
    fn text(&mut self, text: &str) -> String {
        self.redactor.redact_str_counted(text, self.counts).0
    }

    /// The report: results and actions get their own caps, `redaction` is rewritten by the caller, and
    /// everything else is a plain string field.
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
                // Rewritten after the walk. Walking it would count the rule names as text.
                ("redaction", _) => {}
                (_, value) => self.generic(value),
            }
        }
    }

    /// One result. Sets `truncated` when a cap cut `message`, `fix`, `builtin_fix`, `notes`, `observed`
    /// or `expected`.
    fn check(&mut self, check: &mut Value) {
        let Value::Object(fields) = check else {
            return self.generic(check);
        };
        let mut cut = false;
        for (name, value) in fields.iter_mut() {
            match name.as_str() {
                "message" => self.capped(value, MESSAGE_CAP, &mut cut),
                "fix" | "builtin_fix" => self.capped(value, STRING_CAP, &mut cut),
                "notes" => self.notes(value, &mut cut),
                "observed" | "expected" => self.free_form(value, &mut cut),
                "truncated" => {}
                _ => self.generic(value),
            }
        }
        if cut {
            fields.insert("truncated".to_owned(), Value::Bool(true));
        }
    }

    /// One action entry. `argv` is free-form: a flag that names a secret takes the next argument whole.
    fn action(&mut self, action: &mut Value) {
        let Value::Object(fields) = action else {
            return self.generic(action);
        };
        for (name, value) in fields.iter_mut() {
            match (name.as_str(), value) {
                ("argv", Value::Array(args)) => self.argv(args),
                (_, value) => self.generic(value),
            }
        }
    }

    /// Redacts every string, capped at [`STRING_CAP`], and the keys of every object.
    fn generic(&mut self, value: &mut Value) {
        match value {
            Value::String(s) => {
                let redacted = self.text(s);
                *s = cap(redacted, STRING_CAP).0;
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
    fn capped(&mut self, value: &mut Value, max: usize, cut: &mut bool) {
        let Value::String(s) = value else {
            return self.generic(value);
        };
        let redacted = self.text(s);
        let (text, was_cut) = cap(redacted, max);
        *s = text;
        *cut |= was_cut;
    }

    fn notes(&mut self, value: &mut Value, cut: &mut bool) {
        let Value::Array(notes) = value else {
            return self.generic(value);
        };
        for note in notes.iter_mut() {
            self.capped(note, MESSAGE_CAP, cut);
        }
        if notes.len() > MAX_NOTES {
            notes.truncate(MAX_NOTES);
            *cut = true;
        }
    }

    /// `observed` or `expected`: the whole-member rule, the list cut, then the size cap.
    fn free_form(&mut self, value: &mut Value, cut: &mut bool) {
        self.free(value, cut);
        if let Value::Object(map) = value {
            *cut |= cap_map(map);
        }
    }

    fn free(&mut self, value: &mut Value, cut: &mut bool) {
        match value {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => {
                // Redact first and cut second, so what is dropped has been counted like the rest.
                for item in items.iter_mut() {
                    self.free(item, cut);
                }
                if items.len() > MAX_LIST_ITEMS {
                    items.truncate(MAX_LIST_ITEMS);
                    *cut = true;
                }
            }
            Value::Object(map) => {
                // `{"name": "DB_PASSWORD", "value": "..."}`: the name says what the value is.
                let pair_is_secret = map
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(is_secret_key);
                for (key, item) in map.iter_mut() {
                    if is_secret_key(key) || (pair_is_secret && key == "value") {
                        self.blank(item);
                    } else {
                        self.free(item, cut);
                    }
                }
                self.rekey(map);
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Replaces every string under a secret-named member with a placeholder of that string.
    ///
    /// Empty strings and the forms the key rule leaves alone (`${NAME}`, `null`, a `/run/secrets/` path,
    /// a placeholder) stay, so the two rules agree.
    fn blank(&mut self, value: &mut Value) {
        match value {
            Value::String(s) => {
                if !s.is_empty() && !is_exempt_value(s) {
                    *s = self.redactor.placeholder(SECRET_BY_KEY, s.as_bytes());
                    self.counts.add(SECRET_BY_KEY);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.blank(item);
                }
            }
            Value::Object(map) => {
                for (_, item) in map.iter_mut() {
                    self.blank(item);
                }
                self.rekey(map);
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Arguments of a command. Each is redacted as a string. An argument that is a flag naming a secret
    /// (`--password`, with no `=`) takes the next argument whole.
    fn argv(&mut self, args: &mut [Value]) {
        let mut next_is_secret = false;
        for arg in args {
            let Value::String(s) = arg else {
                next_is_secret = false;
                self.generic(arg);
                continue;
            };
            if next_is_secret {
                self.blank(arg);
                next_is_secret = false;
                continue;
            }
            next_is_secret =
                s.starts_with('-') && !s.contains('=') && is_secret_key(s.trim_start_matches('-'));
            self.generic(arg);
        }
    }

    /// Redacts the keys of an object. A key that changes keeps its value. If two keys end up equal the
    /// later one gets `~2`, `~3` and so on, so no value is lost.
    fn rekey(&mut self, map: &mut Map<String, Value>) {
        let renamed: Vec<(String, String)> = map
            .keys()
            .filter_map(|key| {
                let new = cap(self.text(key), STRING_CAP).0;
                (new != *key).then(|| (key.clone(), new))
            })
            .collect();
        for (old, new) in renamed {
            let Some(value) = map.remove(&old) else {
                continue;
            };
            let mut key = new.clone();
            let mut n = 2_u32;
            while map.contains_key(&key) {
                key = format!("{new}~{n}");
                n = n.saturating_add(1);
            }
            map.insert(key, value);
        }
    }
}

/// Cuts `text` to at most `max` bytes, with the marker at the end, if it is longer. The flag says whether
/// it was cut. The cut falls on a character boundary and never inside a placeholder.
fn cap(text: String, max: usize) -> (String, bool) {
    match cut_str(&text, max) {
        Some(cut) => (cut, true),
        None => (text, false),
    }
}

fn cut_str(text: &str, max: usize) -> Option<String> {
    if text.len() <= max {
        return None;
    }
    let room = max.saturating_sub(CUT_MARKER.len());
    let mut at = text.floor_char_boundary(room);
    // A placeholder is never cut. Back up to where it starts.
    if let Some(inside) = placeholder_spans(text)
        .into_iter()
        .find(|span| span.start < at && at < span.end)
    {
        at = inside.start;
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
