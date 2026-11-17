//! Found and Needed: what a check saw and what it wanted, as labels and plain values (01 section 6,
//! 07 D.7).
//!
//! `observed` and `expected` are free-form JSON written by the check families. The page has no code per
//! check, so one rule reads them all: keys become words (`free_bytes` is "Free"), a number under a
//! `_bytes` key is a size, under `_ms` it is milliseconds, under `_percent` it has a percent sign, and a
//! list is one line per item. Every label and every value is text from the machine or the spec, so the
//! template puts each in `<bdi>`. The values were redacted before they got here (`crate::redact`).

use serde_json::{Map, Number, Value};

use crate::units::format_bytes;

/// One label and the lines under it.
pub(in crate::report::html) struct Fact {
    /// The humanised key.
    pub label: String,
    /// One line per list item or member. Never empty.
    pub lines: Vec<String>,
}

/// The members of `map` sorted by key. A JSON map keeps insertion order or sorts, by a feature some other
/// crate in the build turns on, so the page sorts itself and the same report gives the same bytes.
fn sorted(map: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut members: Vec<_> = map.iter().collect();
    members.sort_by(|a, b| a.0.cmp(b.0));
    members
}

/// The facts of an `observed` or `expected` map, in key order. Empty when the map is absent or empty.
pub(in crate::report::html) fn facts(map: Option<&Map<String, Value>>) -> Vec<Fact> {
    map.map(sorted)
        .into_iter()
        .flatten()
        .map(|(key, value)| Fact {
            label: label(key),
            lines: lines(key, value),
        })
        .collect()
}

/// The unit a key ends in, if any: `free_bytes` is `bytes`.
fn unit(key: &str) -> Option<&'static str> {
    let word = key.rsplit('_').next()?;
    ["bytes", "ms", "percent"]
        .into_iter()
        .find(|unit| word.eq_ignore_ascii_case(unit))
}

/// `free_bytes` as "Free", `logical_cores` as "Logical cores". A key that is only a unit word keeps it.
fn label(key: &str) -> String {
    let stem = match (unit(key), key.rsplit_once('_')) {
        (Some(_), Some((stem, _))) => stem,
        _ => key,
    };
    let spaced = stem.replace('_', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => spaced,
    }
}

fn number(key: &str, n: &Number) -> String {
    match (unit(key), n.as_u64()) {
        (Some("bytes"), Some(bytes)) => format_bytes(bytes),
        (Some("bytes"), None) => format!("{n} bytes"),
        (Some("ms"), _) => format!("{n} ms"),
        (Some("percent"), _) => format!("{n}%"),
        _ => n.to_string(),
    }
}

/// A value on one line: used inside a list item or a nested map.
fn inline(key: &str, value: &Value) -> String {
    match value {
        Value::Null => "none".to_owned(),
        Value::Bool(true) => "yes".to_owned(),
        Value::Bool(false) => "no".to_owned(),
        Value::Number(n) => number(key, n),
        Value::String(s) if s.is_empty() => "(empty)".to_owned(),
        Value::String(s) => s.clone(),
        Value::Array(items) if items.is_empty() => "none".to_owned(),
        Value::Array(items) => items
            .iter()
            .map(|item| inline(key, item))
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(map) if map.is_empty() => "none".to_owned(),
        Value::Object(map) => member_lines(map).join("; "),
    }
}

fn member_lines(map: &Map<String, Value>) -> Vec<String> {
    sorted(map)
        .into_iter()
        .map(|(k, v)| format!("{}: {}", label(k), inline(k, v)))
        .collect()
}

/// The lines under a label: one per list item, one per member of a map, else one.
fn lines(key: &str, value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) if !items.is_empty() => {
            items.iter().map(|item| inline(key, item)).collect()
        }
        Value::Object(map) if !map.is_empty() => member_lines(map),
        _ => vec![inline(key, value)],
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn units_become_sizes_milliseconds_and_percents() {
        assert_eq!(
            lines("total_bytes", &json!(16_496_934_912_u64)),
            ["15.4 GiB"]
        );
        assert_eq!(lines("connect_ms", &json!(38)), ["38 ms"]);
        assert_eq!(lines("used_percent", &json!(42.5)), ["42.5%"]);
        assert_eq!(lines("logical_cores", &json!(8)), ["8"]);
        assert_eq!(lines("odd_bytes", &json!(-1)), ["-1 bytes"]);
    }

    #[test]
    fn labels_are_words() {
        assert_eq!(label("free_bytes"), "Free");
        assert_eq!(label("logical_cores"), "Logical cores");
        assert_eq!(label("bytes"), "Bytes");
        assert_eq!(label(""), "");
    }

    #[test]
    fn lists_are_one_line_per_item_and_scalars_are_words() {
        assert_eq!(
            lines("options", &json!(["rw", "relatime"])),
            ["rw", "relatime"]
        );
        assert_eq!(lines("x", &json!(null)), ["none"]);
        assert_eq!(lines("x", &json!([])), ["none"]);
        assert_eq!(lines("x", &json!(true)), ["yes"]);
        assert_eq!(lines("x", &json!("")), ["(empty)"]);
        assert_eq!(
            lines("endpoints", &json!([{"target": "a:443", "connect_ms": 38}])),
            ["Connect: 38 ms; Target: a:443"]
        );
    }
}
