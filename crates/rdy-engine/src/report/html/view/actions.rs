//! The action log as the page shows it: one plain table, the first 1000 rows (01 section 6, item 7).
//!
//! Every word of the table that is not one of ours came from the report, so it goes in a [`Span`] marked
//! untrusted. The report was redacted before it got here, `argv` included (`--password` takes the next
//! argument whole), so this file only formats what it is given.

use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::{Map, Value};

use super::Span;

/// Rows past this many are left out of the page and counted. The JSON file has them all.
pub(super) const MAX_ROWS: usize = 1000;

/// The table, and how many entries it leaves out.
pub(in crate::report::html) struct ActionLog {
    pub rows: Vec<ActionRow>,
    /// Entries past [`MAX_ROWS`].
    pub more: usize,
}

/// One row.
pub(in crate::report::html) struct ActionRow {
    pub number: u64,
    /// The check's key, or `None` for a probe made by the run itself.
    pub check: Option<String>,
    /// What kind of thing it was, in our words.
    pub what: Vec<Span>,
    /// The program and arguments, the path, the host: what it was done to.
    pub detail: String,
    /// How it ended.
    pub result: Vec<Span>,
}

impl ActionLog {
    pub(in crate::report::html) fn new(actions: &[Action]) -> Self {
        Self {
            rows: actions.iter().take(MAX_ROWS).map(row).collect(),
            more: actions.len().saturating_sub(MAX_ROWS),
        }
    }
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

/// The kind in plain words. A kind this version does not know is shown as written.
fn what(kind: &ActionKind) -> Vec<Span> {
    let words = match kind {
        ActionKind::Exec => "Ran a command",
        ActionKind::Read => "Read a file",
        ActionKind::ReadDir => "Listed a folder",
        ActionKind::Stat => "Looked at a path",
        ActionKind::Env => "Checked an environment variable name",
        ActionKind::Lookup => "Looked up a host name",
        ActionKind::Connect => "Opened a connection",
        ActionKind::Tls => "Started a TLS handshake",
        ActionKind::Http => "Sent an HTTP request",
        ActionKind::Dns => "Sent a DNS query",
        ActionKind::Kube => "Sent a Kubernetes API request",
        ActionKind::Native => "Made a system call",
        ActionKind::Coalesced => "Many calls shown as one row",
        other => return vec![Span::untrusted(other.as_str())],
    };
    vec![Span::own(words)]
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

/// `parts` that exist, joined by single spaces.
fn words(parts: &[Option<String>]) -> String {
    parts
        .iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

fn detail(kind: &ActionKind, fields: &Map<String, Value>) -> String {
    let get = |key: &str| field(fields, key);
    match kind {
        ActionKind::Exec => {
            let mut parts = vec![get("program")];
            if let Some(Value::Array(argv)) = fields.get("argv") {
                parts.extend(argv.iter().map(|arg| match arg {
                    Value::String(text) => Some(text.clone()),
                    other => Some(other.to_string()),
                }));
            }
            words(&parts)
        }
        ActionKind::Read | ActionKind::ReadDir | ActionKind::Stat => {
            get("path").unwrap_or_default()
        }
        ActionKind::Env => get("name").unwrap_or_default(),
        ActionKind::Lookup | ActionKind::Tls => get("host").unwrap_or_default(),
        ActionKind::Dns => words(&[
            get("name"),
            get("rtype"),
            get("server").map(|server| format!("via {server}")),
        ]),
        ActionKind::Connect => {
            let target = match (get("host"), get("port")) {
                (Some(host), Some(port)) => Some(format!("{host}:{port}")),
                (host, port) => host.or(port),
            };
            words(&[
                target,
                get("proto").filter(|proto| proto == "udp"),
                get("via_proxy").map(|proxy| format!("through {proxy}")),
            ])
        }
        ActionKind::Http => words(&[
            get("method"),
            get("url"),
            // A request over a unix socket names the socket in `path` and the API path in `url`.
            get("path").map(|path| match get("url") {
                Some(_) => format!("on {path}"),
                None => path,
            }),
        ]),
        ActionKind::Kube => words(&[get("method"), get("path")]),
        ActionKind::Native => words(&[get("api"), get("path")]),
        ActionKind::Coalesced => words(&[
            get("count"),
            get("of"),
            Some("calls".to_owned()),
            get("under").map(|under| format!("under {under}")),
        ]),
        _ => String::new(),
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
        (plain(&row.what), row.detail, plain(&row.result))
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

    #[test]
    fn rows_past_the_limit_are_counted() {
        let entries: Vec<Action> = (1..=1005)
            .map(|seq| {
                let mut entry = action(ActionKind::Stat, ActionOutcome::Ok, &json!({"path": "/x"}));
                entry.seq = seq;
                entry
            })
            .collect();
        let log = ActionLog::new(&entries);
        assert_eq!((log.rows.len(), log.more), (1000, 5));
        assert_eq!(log.rows[999].number, 1000);
    }
}
