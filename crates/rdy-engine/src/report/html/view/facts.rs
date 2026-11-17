//! Found and Needed: what a check saw and what it wanted, as labels and plain values (01 section 6,
//! 07 D.7).
//!
//! `observed` and `expected` are free-form JSON written by the check families. The page has no code per
//! check, so one rule reads them all: keys become words (`free_bytes` is "Free"), a number under a
//! `_bytes` key is a size, under `_ms` it is milliseconds, under `_percent` it has a percent sign, and a
//! list is one line per item. A line is a list of [`Span`]s, like a banner line: our separators are our
//! own text, and every label and every value is untrusted, so the template puts each in its own `<bdi>`.
//! The values were redacted before they got here (`crate::redact`), and the page builds these from the
//! report the JSON holds, so it never shows what the JSON writer cut.

use serde_json::{Map, Number, Value};

use super::Span;
use crate::units::format_bytes;

/// Words that stay capitals in a label.
const ACRONYMS: [&str; 22] = [
    "api", "ca", "cidr", "cpu", "csi", "cuda", "dns", "gpu", "http", "https", "id", "ip", "iam",
    "mtu", "ntp", "os", "pid", "rbac", "tls", "uid", "url", "vram",
];

/// One label and the lines under it.
#[derive(Clone)]
pub(in crate::report::html) struct Fact {
    /// The humanised key. Untrusted: the template wraps it in `<bdi>`.
    pub label: String,
    /// One line per list item or member. Never empty.
    pub lines: Vec<Vec<Span>>,
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

/// `free_bytes` as "Free", `logical_cores` as "Logical cores", `tls_ms` as "TLS". A key that is only a
/// unit word keeps it. A key the redactor replaced (`[REDACTED:...]`) is left as it is.
fn label(key: &str) -> String {
    if key.contains("[REDACTED:") {
        return key.to_owned();
    }
    let stem = match (unit(key), key.rsplit_once('_')) {
        (Some(_), Some((stem, _))) if !stem.trim_matches('_').is_empty() => stem,
        _ => key,
    };
    let words: Vec<String> = stem
        .split('_')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let lower = word.to_ascii_lowercase();
            if ACRONYMS.contains(&lower.as_str()) {
                lower.to_ascii_uppercase()
            } else if lower == "fstype" {
                "filesystem type".to_owned()
            } else {
                word.to_owned()
            }
        })
        .collect();
    let text = words.join(" ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "(unnamed)".to_owned(),
    }
}

/// One decimal place, without a trailing `.0`: `42.5`, `42`.
fn one_decimal(f: f64) -> String {
    let text = format!("{f:.1}");
    let text = text.strip_suffix(".0").map_or(text.clone(), str::to_owned);
    // A small negative rounds to -0, which reads as a number nobody wrote.
    if text == "-0" { "0".to_owned() } else { text }
}

fn number(key: &str, n: &Number) -> String {
    let whole_float = n
        .as_f64()
        .filter(|f| f.is_finite() && *f >= 0.0 && f.fract() == 0.0 && *f < 1.8e19);
    match unit(key) {
        Some("bytes") => match (n.as_u64(), whole_float) {
            (Some(bytes), _) => format_bytes(bytes),
            // A whole, non-negative float is below 2^64 here, so the cast is exact.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            (None, Some(f)) => format_bytes(f as u64),
            _ => format!("{n} bytes"),
        },
        Some("ms") => match n.as_f64() {
            Some(f) if n.as_i64().is_none() && n.as_u64().is_none() => {
                format!("{} ms", one_decimal(f))
            }
            _ => format!("{n} ms"),
        },
        Some("percent") => match n.as_f64() {
            Some(f) if n.as_i64().is_none() && n.as_u64().is_none() => {
                format!("{}%", one_decimal(f))
            }
            _ => format!("{n}%"),
        },
        _ => n.to_string(),
    }
}

/// A scalar as text, or `None` for a list or a map.
fn scalar(key: &str, value: &Value) -> Option<String> {
    Some(match value {
        Value::Null => "none".to_owned(),
        Value::Bool(true) => "yes".to_owned(),
        Value::Bool(false) => "no".to_owned(),
        Value::Number(n) => number(key, n),
        Value::String(s) if s.is_empty() => "(empty)".to_owned(),
        Value::String(s) => s.clone(),
        Value::Array(_) | Value::Object(_) => return None,
    })
}

/// A value on one line, as spans: used inside a list item or a nested map. A map reads
/// `Label: value; Label: value` and a list `a, b`, with our separators outside the untrusted values.
fn inline(key: &str, value: &Value) -> Vec<Span> {
    if let Some(text) = scalar(key, value) {
        return vec![Span::untrusted(&text)];
    }
    match value {
        Value::Array(items) if !items.is_empty() => {
            let mut out = Vec::new();
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(Span::own(", "));
                }
                out.extend(inline(key, item));
            }
            out
        }
        Value::Object(map) if !map.is_empty() => {
            let mut out = Vec::new();
            for (at, (k, v)) in sorted(map).into_iter().enumerate() {
                if at > 0 {
                    out.push(Span::own("; "));
                }
                out.push(Span::untrusted(&label(k)));
                out.push(Span::own(": "));
                out.extend(inline(k, v));
            }
            out
        }
        _ => vec![Span::untrusted("none")],
    }
}

/// The lines under a label: one per list item, one per member of a map, else one.
fn lines(key: &str, value: &Value) -> Vec<Vec<Span>> {
    match value {
        Value::Array(items) if !items.is_empty() => {
            items.iter().map(|item| inline(key, item)).collect()
        }
        Value::Object(map) if !map.is_empty() => sorted(map)
            .into_iter()
            .map(|(k, v)| {
                let mut line = vec![Span::untrusted(&label(k)), Span::own(": ")];
                line.extend(inline(k, v));
                line
            })
            .collect(),
        _ => vec![inline(key, value)],
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::report::html::view::plain;

    use super::*;

    /// The lines as plain text, and for each span whether it is untrusted.
    fn text(key: &str, value: &Value) -> Vec<String> {
        lines(key, value).iter().map(|line| plain(line)).collect()
    }

    #[test]
    fn units_become_sizes_milliseconds_and_percents() {
        assert_eq!(
            text("total_bytes", &json!(16_496_934_912_u64)),
            ["15.4 GiB"]
        );
        assert_eq!(text("connect_ms", &json!(38)), ["38 ms"]);
        assert_eq!(text("used_percent", &json!(42)), ["42%"]);
        assert_eq!(text("logical_cores", &json!(8)), ["8"]);
    }

    #[test]
    fn edge_numbers_are_plain_and_never_panic() {
        assert_eq!(text("free_bytes", &json!(0)), ["0 bytes"]);
        assert_eq!(
            text("free_bytes", &json!(u64::MAX)),
            [format_bytes(u64::MAX)]
        );
        // A whole float is a size. A fraction and a negative number stay numbers with the unit word.
        assert_eq!(text("free_bytes", &json!(2048.0)), ["2 KiB"]);
        assert_eq!(text("free_bytes", &json!(1.5)), ["1.5 bytes"]);
        assert_eq!(text("free_bytes", &json!(-1)), ["-1 bytes"]);
        // A float under milliseconds or percent rounds to one decimal, and never reads -0.
        assert_eq!(text("took_ms", &json!(12.26)), ["12.3 ms"]);
        assert_eq!(text("took_ms", &json!(-0.0)), ["0 ms"]);
        assert_eq!(text("used_percent", &json!(-0.04)), ["0%"]);
        assert_eq!(text("used_percent", &json!(42.54)), ["42.5%"]);
        assert_eq!(text("used_percent", &json!(42.0)), ["42%"]);
        assert_eq!(text("used_percent", &json!(0.04)), ["0%"]);
        // A string under a unit key is shown as it is, such as a quantity the spec wrote.
        assert_eq!(text("min_bytes", &json!("32Gi")), ["32Gi"]);
    }

    #[test]
    fn labels_are_words() {
        assert_eq!(label("free_bytes"), "Free");
        assert_eq!(label("logical_cores"), "Logical cores");
        assert_eq!(label("tls_ms"), "TLS");
        assert_eq!(label("csi_driver_present"), "CSI driver present");
        assert_eq!(label("fstype"), "Filesystem type");
        assert_eq!(label("bytes"), "Bytes");
        assert_eq!(label(""), "(unnamed)");
        // A key that is only a unit word is not an empty label.
        assert_eq!(label("_bytes"), "Bytes");
        assert_eq!(label("_"), "(unnamed)");
        // A placeholder the redactor wrote for a key stays as it is.
        let placeholder = "[REDACTED:secret_by_key:0123abcd]";
        assert_eq!(label(placeholder), placeholder);
    }

    #[test]
    fn lists_are_one_line_per_item_and_scalars_are_words() {
        assert_eq!(
            text("options", &json!(["rw", "relatime"])),
            ["rw", "relatime"]
        );
        assert_eq!(text("x", &json!(null)), ["none"]);
        assert_eq!(text("x", &json!([])), ["none"]);
        assert_eq!(text("x", &json!(true)), ["yes"]);
        assert_eq!(text("x", &json!("")), ["(empty)"]);
        assert_eq!(
            text("endpoints", &json!([{"target": "a:443", "connect_ms": 38}])),
            ["Connect: 38 ms; Target: a:443"]
        );
        assert_eq!(
            text("m", &json!({"b": [1, 2], "a": "x"})),
            ["A: x", "B: 1, 2"]
        );
    }

    /// The control of the canary test in `tests/html_found_needed.rs`: with no redaction these lists show
    /// every canary on its line, so the absence there is the redactor's doing and not the page leaving
    /// the fields out.
    #[test]
    fn without_redaction_every_canary_shows_on_its_line() {
        let planted: Value = serde_json::from_str(include_str!("found-canaries.json"))
            .expect("the shared canary input is JSON");
        let all: Vec<String> = facts(planted["observed"].as_object())
            .iter()
            .flat_map(|fact| {
                fact.lines
                    .iter()
                    .map(|line| format!("{}: {}", fact.label, plain(line)))
            })
            .collect();
        for line in [
            "API password: canary-found-key-1",
            "Env: Name: DB_PASSWORD; Value: canary-found-env-2",
            "Cmdline: --password",
            "Cmdline: canary-found-argv-3",
            "Log: Authorization: Bearer canary-found-hdr-4\nok",
            "Kubeconfig: Token: canary-found-kube-6",
            "Note: token=canary-found-text-5",
        ] {
            assert!(all.iter().any(|l| l == line), "{line:?} is not in {all:?}");
        }
        // And the expected side.
        let needed: Vec<String> = facts(planted["expected"].as_object())
            .iter()
            .flat_map(|fact| {
                fact.lines
                    .iter()
                    .map(|line| format!("{}: {}", fact.label, plain(line)))
            })
            .collect();
        for line in [
            "Client secret: canary-found-exp-7",
            "Args: canary-found-exp-8",
        ] {
            assert!(
                needed.iter().any(|l| l == line),
                "{line:?} is not in {needed:?}"
            );
        }
    }

    /// Our separators are our own text, and each label and value is its own untrusted span.
    #[test]
    fn every_label_and_value_is_its_own_untrusted_span() {
        let line = &lines("endpoints", &json!([{"target": "a", "port": 1}]))[0];
        let shape: Vec<(bool, &str)> = line
            .iter()
            .map(|span| (span.untrusted, span.text.as_str()))
            .collect();
        assert_eq!(
            shape,
            [
                (true, "Port"),
                (false, ": "),
                (true, "1"),
                (false, "; "),
                (true, "Target"),
                (false, ": "),
                (true, "a"),
            ]
        );
    }
}
