//! The compiled-in rules (04 Appendix B).
//!
//! M1-048 ships the engine and one rule, `secret_by_key`. M1-060 adds the rest and tunes this one against
//! the corpus. A spec can add rules but never remove or weaken one, so this table is a `static`.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

/// Rule priorities. Higher wins when spans merge (04 section 3.2).
///
/// The full order, highest first: PEM and Secret blocks, token shapes, headers, URL userinfo, key names,
/// custom patterns, emails, IPs, entropy. M1-060 adds the other constants.
pub(crate) mod priority {
    /// `secret_by_key`.
    pub const KEY_NAMES: u8 = 60;
}

/// One redaction rule. It looks at the original text and reports byte ranges.
pub(crate) struct Rule {
    /// The name that appears in placeholders and counts. Only `[a-z0-9_.]`.
    pub name: &'static str,
    /// See [`priority`].
    pub priority: u8,
    /// Pushes the byte ranges to remove. Ranges must sit on char boundaries and inside the text.
    pub find: fn(&str, &mut Vec<Range<usize>>),
}

/// The built-in rule set for the Report ruleset.
pub(crate) static BUILT_IN: &[Rule] = &[Rule {
    name: "secret_by_key",
    priority: priority::KEY_NAMES,
    find: find_secret_by_key,
}];

/// `key = value`, `key: value`, `"key": "value"`, `--flag=value`, `\"key\":\"value\"`.
///
/// The regex finds the key and the separator. Code reads the value, because the value may be quoted,
/// escaped-quoted or bare. `Err` means the pattern failed to compile, which is a bug a unit test catches;
/// the rule then fails closed and removes the whole text.
/// A well-formed placeholder. Keys inside one are not assignments: `secret_by_key:1a2b3c4d]` looks like
/// `key: value` and must not be redacted again.
static PLACEHOLDER: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"\[REDACTED:[a-z0-9_.]+:[0-9a-f]{8}\]"));

static ASSIGNMENT: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"([A-Za-z0-9_\-][A-Za-z0-9_.\-]*)(?:\\?["'])?[ \t]*[=:][ \t]*"#));

/// Key stems (04 Appendix B). Matched on the key with `-`, `_` and `.` removed and lowercased, so
/// `api_key`, `api-key` and `apiKey` are all `apikey`.
const STEMS: &[&str] = &[
    "pass",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "credential",
    "auth",
    "bearer",
    "dsn",
];

/// Words that contain a stem but are not secrets, such as `passed: 12` and `author: Ada`.
/// A stem hit that starts one of these words is ignored. M1-060 tunes this list against the corpus.
const NOT_SECRET_WORDS: &[&str] = &[
    "passed",
    "passing",
    "passage",
    "passport",
    "passive",
    "passable",
    "passthrough",
    "passthru",
    "author",
    "authority",
    "authorities",
];

/// A key that ends in one of these names a thing, not a secret: `secretName`, `tokenFile`, `keyRef`.
const NAME_SUFFIXES: &[&str] = &["name", "ref", "file", "path", "namespace"];

/// Values that are not secrets, compared case-insensitively.
const PLAIN_VALUES: &[&str] = &["null", "true", "false", "none", "required"];

/// Variable and template references: the value names a secret, it is not one.
const REFERENCES: [(&str, &str); 3] = [("${", "}"), ("$(", ")"), ("{{", "}}")];

/// Where a mounted secret lives. The path is not the secret.
const SECRET_MOUNT: &str = "/run/secrets/";

fn find_secret_by_key(text: &str, out: &mut Vec<Range<usize>>) {
    let Ok(assignment) = ASSIGNMENT.as_ref() else {
        out.push(0..text.len());
        return;
    };
    let Ok(placeholder) = PLACEHOLDER.as_ref() else {
        out.push(0..text.len());
        return;
    };
    let placeholders: Vec<Range<usize>> = placeholder.find_iter(text).map(|m| m.range()).collect();
    for caps in assignment.captures_iter(text) {
        let (Some(whole), Some(key)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        if placeholders.iter().any(|p| p.contains(&key.start())) {
            continue;
        }
        if !is_secret_key(key.as_str()) {
            continue;
        }
        let value = value_range(text, whole.end());
        if value.is_empty() || is_exempt_value(&text[value.clone()]) {
            continue;
        }
        out.push(value);
    }
}

/// True if the key looks like it names a secret.
fn is_secret_key(key: &str) -> bool {
    let norm: String = key
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if NAME_SUFFIXES.iter().any(|s| norm.ends_with(s)) {
        return false;
    }
    STEMS.iter().any(|stem| {
        norm.match_indices(stem).any(|(at, _)| {
            let rest = &norm[at..];
            !NOT_SECRET_WORDS.iter().any(|w| rest.starts_with(w))
        })
    })
}

/// The byte range of the value that starts at `start`, without its quotes.
///
/// A quoted value runs to the closing quote, or to the end of the line if there is none (fail closed).
/// A bare value runs to the next whitespace. It may swallow a closing quote or comma that belongs to the
/// text around it. Over-redacting is the safe side.
fn value_range(text: &str, start: usize) -> Range<usize> {
    let rest = &text[start..];
    let line_end = rest.find(['\n', '\r']).unwrap_or(rest.len());
    let line = &rest[..line_end];

    for escaped in ["\\\"", "\\'"] {
        if line.starts_with(escaped) {
            let from = escaped.len();
            let to = line[from..].find(escaped).map_or(line.len(), |i| from + i);
            return start + from..start + to;
        }
    }
    for &quote in b"\"'" {
        if line.as_bytes().first() == Some(&quote) {
            let mut i = 1;
            let bytes = line.as_bytes();
            while i < bytes.len() && bytes[i] != quote {
                // A backslash escapes the next byte. Only ASCII bytes are compared, so a multi-byte
                // character is never split by the comparison.
                i += if bytes[i] == b'\\' { 2 } else { 1 };
            }
            let to = i.min(line.len());
            return start + 1..start + to;
        }
    }
    // A reference such as `$(cat /x)` may hold spaces. It is one value only if it ends the word.
    for (open, close) in REFERENCES {
        if line.starts_with(open)
            && let Some(at) = line[open.len()..].find(close)
        {
            let end = open.len() + at + close.len();
            if line[end..].chars().next().is_none_or(char::is_whitespace) {
                return start..start + end;
            }
        }
    }
    let to = line.find(char::is_whitespace).unwrap_or(line.len());
    start..start + to
}

/// Values the key rule leaves alone (04 Appendix B, key-name exclusions).
fn is_exempt_value(value: &str) -> bool {
    PLAIN_VALUES.iter().any(|p| value.eq_ignore_ascii_case(p))
        || value.starts_with(SECRET_MOUNT)
        || REFERENCES
            .iter()
            .any(|(open, close)| is_single_reference(value, open, close))
        || is_single_placeholder(value)
}

/// True if the value is exactly one `open ... close` reference, such as `${DB_PASSWORD}`.
/// `${A}${B}` is not, because the first close is not at the end.
fn is_single_reference(value: &str, open: &str, close: &str) -> bool {
    value
        .strip_prefix(open)
        .and_then(|inner| inner.strip_suffix(close))
        .is_some_and(|inner| !inner.is_empty() && !inner.contains(close))
}

/// True if the value is exactly one well-formed placeholder, `[REDACTED:<rule>:<8 hex>]`.
///
/// Anything more, such as `[REDACTED:x:00000000]hunter2`, is not exempt, so a forged prefix cannot hide a
/// secret (04 section 3.2).
pub(crate) fn is_single_placeholder(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix("[REDACTED:")
        .and_then(|v| v.strip_suffix(']'))
    else {
        return false;
    };
    let Some((rule, tag)) = inner.rsplit_once(':') else {
        return false;
    };
    !rule.is_empty()
        && rule
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
        && tag.len() == 8
        && tag
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        find_secret_by_key(text, &mut out);
        out.into_iter().map(|r| &text[r]).collect()
    }

    #[test]
    fn the_assignment_pattern_compiles() {
        assert!(ASSIGNMENT.is_ok());
        assert!(PLACEHOLDER.is_ok());
    }

    #[test]
    fn finds_values_in_every_common_form() {
        assert_eq!(found("DB_PASSWORD=hunter2"), ["hunter2"]);
        assert_eq!(found("password: hunter2"), ["hunter2"]);
        assert_eq!(found(r#"{"password": "hunter2"}"#), ["hunter2"]);
        assert_eq!(found("password = 'hunter2'"), ["hunter2"]);
        assert_eq!(found("--db-password=hunter2 --other"), ["hunter2"]);
        assert_eq!(found(r#"{\"apiKey\":\"hunter2\"}"#), ["hunter2"]);
        assert_eq!(found("Environment=DB_TOKEN=hunter2"), ["hunter2"]);
        assert_eq!(found("api-key: hunter2\nnext: line"), ["hunter2"]);
    }

    #[test]
    fn an_unterminated_quote_runs_to_the_end_of_the_line() {
        assert_eq!(found("password=\"hunter2\nnext=1"), ["hunter2"]);
    }

    #[test]
    fn a_backslash_inside_quotes_does_not_end_the_value() {
        assert_eq!(found(r#"password="ab\"cd" x"#), [r#"ab\"cd"#]);
    }

    #[test]
    fn leaves_non_secrets_alone() {
        for text in [
            "passed: 12",
            "secretName: acme-tls",
            "password: ${DB_PASSWORD}",
            "password: $(cat /x)",
            "password: {{ .Values.pw }}",
            "token: null",
            "secret: Required",
            "password:",
            "password: ''",
            "passwordFile: /etc/pw",
            "tokenRef: x",
            "author: Ada",
            "password: /run/secrets/db",
            "host: example.test",
        ] {
            assert!(found(text).is_empty(), "should not match: {text}");
        }
    }

    #[test]
    fn only_an_exact_placeholder_is_skipped() {
        assert!(found("password=[REDACTED:secret_by_key:1a2b3c4d]").is_empty());
        assert_eq!(
            found("password=[REDACTED:x:00000000]hunter2"),
            ["[REDACTED:x:00000000]hunter2"]
        );
        assert_eq!(
            found("password=[REDACTED:x:0000000]"),
            ["[REDACTED:x:0000000]"]
        );
        assert_eq!(
            found("password=[REDACTED:X:00000000]"),
            ["[REDACTED:X:00000000]"]
        );
        assert_eq!(found("password=${A}${B}"), ["${A}${B}"]);
        assert_eq!(found("password=${A}secret123"), ["${A}secret123"]);
        assert_eq!(found("password=$(cat /x)tail"), ["$(cat"]);
    }

    #[test]
    fn multibyte_text_is_never_split() {
        assert_eq!(
            found("pässword=ünï password=pä\u{1F600}ss"),
            ["pä\u{1F600}ss"]
        );
        assert_eq!(found("password=\"é\\é\" x"), ["é\\é"]);
    }
}
