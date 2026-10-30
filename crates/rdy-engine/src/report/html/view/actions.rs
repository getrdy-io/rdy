//! The action log as the page shows it: one plain table, the first 1000 rows and every refusal after
//! them (01 section 6, item 7).
//!
//! Every word of the table that is not one of ours came from the report, so it goes in a [`Span`] marked
//! untrusted, one span per value, and our own words ("through", "via", "under") sit between the spans,
//! outside the `<bdi>`. The report was redacted before it got here, `argv` included (`--password` takes
//! the next argument whole), so this file only formats what it is given.

use rdy_spec::result::{Action, ActionKind, ActionOutcome, Report};
use serde_json::{Map, Value};

use super::Span;

/// Rows past this many are left out of the page and counted, except the ones rdy refused. The JSON file
/// has them all.
pub(super) const MAX_ROWS: usize = 1000;

/// The table, and what it leaves out.
pub(in crate::report::html) struct ActionLog {
    pub rows: Vec<ActionRow>,
    /// Entries that are not in the table.
    pub more: usize,
    /// A sentence about entries the log itself dropped to stay within its limits, or empty.
    pub dropped: Vec<Span>,
}

/// One row.
pub(in crate::report::html) struct ActionRow {
    pub number: u64,
    /// The check's key, or `None` for a probe made by the run itself.
    pub check: Option<String>,
    /// What kind of thing it was, in our words.
    pub what: Vec<Span>,
    /// The program and arguments, the path, the host: what it was done to.
    pub detail: Vec<Span>,
    /// How it ended.
    pub result: Vec<Span>,
}

impl ActionLog {
    /// The first [`MAX_ROWS`] entries, then every later entry that rdy's policy refused: a refusal is the
    /// one thing a reader must not have to look for in the JSON.
    pub(in crate::report::html) fn new(report: &Report) -> Self {
        let actions = &report.actions;
        let rows: Vec<ActionRow> = actions
            .iter()
            .enumerate()
            .filter(|(index, action)| {
                *index < MAX_ROWS || matches!(action.outcome, ActionOutcome::Denied)
            })
            .map(|(_, action)| row(action))
            .collect();
        Self {
            more: actions.len().saturating_sub(rows.len()),
            rows,
            dropped: dropped_note(report),
        }
    }
}

/// "rdy left entries out of its own log ...", with the count per kind, when the log was cut.
fn dropped_note(report: &Report) -> Vec<Span> {
    if !report.actions_truncated && report.actions_dropped.is_empty() {
        return Vec::new();
    }
    let mut spans = vec![Span::own(
        "rdy left some entries out of its own log to stay within its size limits",
    )];
    for (index, (kind, count)) in report.actions_dropped.iter().enumerate() {
        spans.push(Span::own(if index == 0 { ": " } else { ", " }));
        spans.push(Span::own(&format!("{count} ")));
        match kind_words(&ActionKind::from(kind.as_str())) {
            Some((_, noun)) => spans.push(Span::own(noun)),
            None => spans.push(Span::untrusted(kind)),
        }
    }
    spans.push(Span::own("."));
    spans
}

fn row(action: &Action) -> ActionRow {
    ActionRow {
        number: action.seq,
        check: action.check.clone(),
        what: what(&action.kind),
        detail: detail(&action.kind, &action.fields),
        result: result(action),
    }
}

/// A known kind as the phrase for one entry ("Read a file") and the plural for a count ("file reads").
fn kind_words(kind: &ActionKind) -> Option<(&'static str, &'static str)> {
    Some(match kind {
        ActionKind::Exec => ("Ran a command", "commands"),
        ActionKind::Read => ("Read a file", "file reads"),
        ActionKind::ReadDir => ("Listed a folder", "folder listings"),
        ActionKind::Stat => ("Looked at a path", "path checks"),
        ActionKind::Env => (
            "Checked an environment variable name",
            "environment variable name checks",
        ),
        ActionKind::Lookup => ("Looked up a host name", "host name lookups"),
        ActionKind::Connect => ("Opened a connection", "connections"),
        ActionKind::Tls => ("Started a TLS handshake", "TLS handshakes"),
        ActionKind::Http => ("Sent an HTTP request", "HTTP requests"),
        ActionKind::Dns => ("Sent a DNS query", "DNS queries"),
        ActionKind::Kube => ("Sent a Kubernetes API request", "Kubernetes API requests"),
        ActionKind::Native => ("Made a system call", "system calls"),
        ActionKind::Coalesced => ("Many calls shown as one row", "folded rows"),
        _ => return None,
    })
}

/// The kind in plain words. A kind this version does not know is shown as written.
fn what(kind: &ActionKind) -> Vec<Span> {
    match kind_words(kind) {
        Some((words, _)) => vec![Span::own(words)],
        None => vec![Span::untrusted(kind.as_str())],
    }
}

/// A field as text. Numbers and booleans read as written; anything else is not there.
fn field(fields: &Map<String, Value>, key: &str) -> Option<String> {
    match fields.get(key)? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Spans joined by single spaces: our words and the values from the report, each its own span.
#[derive(Default)]
struct Words(Vec<Span>);

impl Words {
    fn gap(&mut self) {
        if !self.0.is_empty() {
            self.0.push(Span::own(" "));
        }
    }

    /// Our own word.
    fn own(&mut self, text: &str) -> &mut Self {
        self.gap();
        self.0.push(Span::own(text));
        self
    }

    /// A value from the report.
    fn value(&mut self, text: &str) -> &mut Self {
        self.gap();
        self.0.push(Span::untrusted(text));
        self
    }

    /// The value of `key`, if it has one.
    fn field(&mut self, fields: &Map<String, Value>, key: &str) -> &mut Self {
        if let Some(text) = field(fields, key) {
            self.value(&text);
        }
        self
    }

    /// `lead` and then the value of `key`, if it has one.
    fn led(&mut self, lead: &str, fields: &Map<String, Value>, key: &str) -> &mut Self {
        if let Some(text) = field(fields, key) {
            self.own(lead);
            self.value(&text);
        }
        self
    }
}

fn detail(kind: &ActionKind, fields: &Map<String, Value>) -> Vec<Span> {
    let mut words = Words::default();
    match kind {
        ActionKind::Exec => {
            words.field(fields, "program");
            if let Some(Value::Array(argv)) = fields.get("argv") {
                for arg in argv {
                    match arg {
                        Value::String(text) => words.value(text),
                        other => words.value(&other.to_string()),
                    };
                }
            }
        }
        ActionKind::Read | ActionKind::ReadDir | ActionKind::Stat => {
            words.field(fields, "path");
        }
        ActionKind::Env => {
            words.field(fields, "name");
        }
        ActionKind::Lookup | ActionKind::Tls => {
            words.field(fields, "host");
        }
        ActionKind::Dns => {
            words.field(fields, "name").field(fields, "rtype");
            words.led("via", fields, "server");
        }
        ActionKind::Connect => {
            match (field(fields, "host"), field(fields, "port")) {
                (Some(host), Some(port)) => words.value(&format!("{host}:{port}")),
                (Some(only), None) | (None, Some(only)) => words.value(&only),
                (None, None) => &mut words,
            };
            if field(fields, "proto").as_deref() == Some("udp") {
                words.own("(UDP)");
            }
            words.led("through", fields, "via_proxy");
        }
        ActionKind::Http => {
            words.field(fields, "method").field(fields, "url");
            // A request over a unix socket names the socket in `path` and the API path in `url`.
            if fields.contains_key("url") {
                words.led("on", fields, "path");
            } else {
                words.field(fields, "path");
            }
        }
        ActionKind::Kube => {
            words.field(fields, "method").field(fields, "path");
        }
        ActionKind::Native => {
            words.field(fields, "api").field(fields, "path");
        }
        ActionKind::Coalesced => coalesced(&mut words, fields),
        _ => {}
    }
    words.0
}

/// "12 folder listings under /var/lib": the count, the kind it folded, and where.
fn coalesced(words: &mut Words, fields: &Map<String, Value>) {
    if let Some(count) = fields.get("count").and_then(Value::as_u64) {
        words.own(&count.to_string());
    }
    match field(fields, "of").map(|of| ActionKind::from(of.as_str())) {
        Some(of) => match kind_words(&of) {
            Some((_, noun)) => {
                words.own(noun);
            }
            None => {
                words.own("calls of").value(of.as_str());
            }
        },
        None => {
            words.own("calls");
        }
    }
    // `*` stands for the calls past the 100 targets that are kept apart.
    match field(fields, "under") {
        Some(under) if under == "*" => {
            words.own("under more than 100 other targets");
        }
        Some(under) => {
            words.own("under").value(&under);
        }
        None => {}
    }
}

/// How it ended, then the numbers that go with it (exit code, status, bytes, entries).
fn result(action: &Action) -> Vec<Span> {
    let fields = &action.fields;
    let mut spans = match &action.outcome {
        ActionOutcome::Ok => vec![Span::own("Done")],
        ActionOutcome::Denied => with_reason("Refused by rdy", fields.get("rule")),
        ActionOutcome::Failed => with_reason("Failed", fields.get("error")),
        ActionOutcome::Timeout => vec![Span::own("Timed out")],
        other => vec![Span::untrusted(other.as_str())],
    };
    for (key, before, after) in [
        ("exit", "exit code ", ""),
        ("status", "status ", ""),
        ("bytes", "", " bytes"),
        ("entries", "", " entries"),
    ] {
        if let Some(number) = fields.get(key).and_then(Value::as_i64) {
            spans.push(Span::own(&format!(", {before}{number}{after}")));
        }
    }
    spans
}

fn with_reason(lead: &str, reason: Option<&Value>) -> Vec<Span> {
    let mut spans = vec![Span::own(lead)];
    if let Some(Value::String(reason)) = reason {
        spans.push(Span::own(": "));
        spans.push(Span::untrusted(reason));
    }
    spans
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::plain;
    use super::*;

    fn action(kind: ActionKind, outcome: ActionOutcome, fields: &Value) -> Action {
        let mut action = Action::new(1, Some("host.cpu".to_owned()), 0, 0, kind, outcome);
        if let Value::Object(map) = fields {
            action.fields = map.clone();
        }
        action
    }

    fn row_text(action: &Action) -> (String, String, String) {
        let row = row(action);
        (plain(&row.what), plain(&row.detail), plain(&row.result))
    }

    #[test]
    fn a_command_shows_its_program_and_arguments() {
        let entry = action(
            ActionKind::Exec,
            ActionOutcome::Ok,
            &json!({"program": "/usr/bin/df", "argv": ["-P", "/var/lib"], "exit": 0}),
        );
        assert_eq!(
            row_text(&entry),
            (
                "Ran a command".to_owned(),
                "/usr/bin/df -P /var/lib".to_owned(),
                "Done, exit code 0".to_owned()
            )
        );
        // One untrusted span per value, and nothing else is untrusted.
        let detail = row(&entry).detail;
        assert_eq!(detail.iter().filter(|span| span.untrusted).count(), 3);
        assert!(detail.iter().all(|span| span.untrusted || span.text == " "));
    }

    #[test]
    fn a_refusal_and_a_failure_say_why() {
        let denied = action(
            ActionKind::Read,
            ActionOutcome::Denied,
            &json!({"path": "/proc/1/environ", "rule": "read_denylist"}),
        );
        assert_eq!(row_text(&denied).2, "Refused by rdy: read_denylist");
        let failed = action(
            ActionKind::Connect,
            ActionOutcome::Failed,
            &json!({"host": "h.example", "port": 443, "via_proxy": null, "error": "timed out"}),
        );
        let (_, detail, result) = row_text(&failed);
        assert_eq!(detail, "h.example:443");
        assert_eq!(result, "Failed: timed out");
    }

    #[test]
    fn our_words_between_values_are_outside_the_isolates() {
        let entry = action(
            ActionKind::Connect,
            ActionOutcome::Ok,
            &json!({"host": "h.example", "port": 443, "proto": "udp", "via_proxy": "http://p.example:3128"}),
        );
        let detail = row(&entry).detail;
        assert_eq!(
            plain(&detail),
            "h.example:443 (UDP) through http://p.example:3128"
        );
        let own: Vec<&str> = detail
            .iter()
            .filter(|span| !span.untrusted)
            .map(|span| span.text.as_str())
            .collect();
        assert_eq!(own, [" ", "(UDP)", " ", "through", " "]);
    }

    #[test]
    fn a_folded_row_names_its_kind_in_plain_words() {
        let listing = action(
            ActionKind::Coalesced,
            ActionOutcome::Failed,
            &json!({"of": "read_dir", "under": "/var/lib", "count": 12, "error": "permission denied"}),
        );
        let (what, detail, result) = row_text(&listing);
        assert_eq!(what, "Many calls shown as one row");
        assert_eq!(detail, "12 folder listings under /var/lib");
        assert_eq!(result, "Failed: permission denied");
        let stat = action(
            ActionKind::Coalesced,
            ActionOutcome::Ok,
            &json!({"of": "stat", "under": "*", "count": 3}),
        );
        assert_eq!(
            row_text(&stat).1,
            "3 path checks under more than 100 other targets"
        );
        // A kind this version does not know is shown as written, as an untrusted value.
        let future = action(
            ActionKind::Coalesced,
            ActionOutcome::Ok,
            &json!({"of": "future_kind", "count": 2}),
        );
        assert_eq!(row_text(&future).1, "2 calls of future_kind");
        for entry in [&listing, &stat, &future] {
            let text = row_text(entry).1;
            assert!(!text.contains("read_dir") && !text.contains(" stat"));
        }
    }

    #[test]
    fn only_the_words_from_the_report_are_untrusted() {
        let entry = action(
            ActionKind::from("future_kind"),
            ActionOutcome::Failed,
            &json!({"error": "bad"}),
        );
        let row = row(&entry);
        assert!(row.what.iter().all(|span| span.untrusted));
        assert!(row.result.iter().any(|span| !span.untrusted));
        assert!(row.result.iter().any(|span| span.untrusted));
    }
}
