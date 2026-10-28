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

/// A well-formed placeholder. Keys inside one are not assignments: `secret_by_key:1a2b3c4d]` looks like
/// `key: value` and must not be redacted again.
static PLACEHOLDER: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"\[REDACTED:[a-z0-9_.]+:[0-9a-f]{8}\]"));

/// `key = value`, `key: value`, `"key": "value"`, `--flag=value`, `\"key\":\"value\"` and the same
/// with more backslashes (JSON inside JSON).
///
/// The regex finds the key and the separator. Code reads the value, because the value may be quoted,
/// escaped-quoted or bare. `Err` means the pattern failed to compile, which is a bug a unit test catches;
/// the rule then fails closed and removes the whole text.
static ASSIGNMENT: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"([A-Za-z0-9_\-][A-Za-z0-9_.\-]*)(?:\\*["'])?[ \t]*[=:][ \t]*"#));

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
    // Covered by `auth` already. Listed so the header name stays a stem if `auth` is ever narrowed.
    "authorization",
    "bearer",
    "dsn",
];

/// Whole words that contain a stem but are not secrets, such as `passed: 12` and `author: Ada`.
/// A stem hit is ignored only when it is exactly one of these words, split on `-`, `_`, `.` and
/// camelCase, so `authorization` and `authProfile` still match. M1-060 tunes this list on the corpus.
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
    "authors",
    "authority",
    "authorities",
];

/// A key whose last word is one of these names a thing, not a secret: `secretName`, `tokenFile`, `keyRef`.
const NAME_SUFFIXES: &[&str] = &["name", "ref", "file", "path", "namespace"];

/// Values that are not secrets, compared case-insensitively.
const PLAIN_VALUES: &[&str] = &["null", "true", "false", "none", "required"];

/// Where a mounted secret lives. The path is not the secret.
const SECRET_MOUNT: &str = "/run/secrets/";

fn find_secret_by_key(text: &str, out: &mut Vec<Range<usize>>) {
    let (Ok(assignment), Ok(placeholder)) = (ASSIGNMENT.as_ref(), PLACEHOLDER.as_ref()) else {
        out.push(0..text.len());
        return;
    };
    // Sorted and disjoint, so a binary search tells whether a position is inside one.
    let placeholders: Vec<Range<usize>> = placeholder.find_iter(text).map(|m| m.range()).collect();
    // Everything before this offset is part of a value already handled. A later key there is inside
    // that value, so it is skipped. This also keeps the scan linear on input such as `pass=pass=...`.
    let mut covered_until = 0;
    for caps in assignment.captures_iter(text) {
        let (Some(whole), Some(key)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        if key.start() < covered_until || inside(&placeholders, key.start()) {
            continue;
        }
        if !is_secret_key(key.as_str()) {
            continue;
        }
        let (value, bare) = value_range(text, whole.end());
        if value.is_empty() {
            if bare {
                // `password:` with nothing after it may be a YAML key whose value is on the next
                // lines. Redact the lines indented deeper than the key.
                if let Some(block) = block_lines(text, key.start(), value.end) {
                    covered_until = block.end;
                    out.push(block);
                }
            }
            continue;
        }
        covered_until = value.end;
        let value_text = &text[value.clone()];
        if bare && is_block_header(value_text) {
            // `token: |` is not the secret. The indented lines after it are.
            if let Some(block) = block_lines(text, key.start(), value.end) {
                covered_until = block.end;
                out.push(block);
            }
        } else if !is_exempt_value(value_text) {
            out.push(value);
        }
    }
}

/// True if `pos` is inside one of the sorted, disjoint ranges.
fn inside(ranges: &[Range<usize>], pos: usize) -> bool {
    let i = ranges.partition_point(|r| r.end <= pos);
    ranges.get(i).is_some_and(|r| r.start <= pos)
}

/// True if the key looks like it names a secret.
fn is_secret_key(key: &str) -> bool {
    let (norm, boundary) = normalize_key(key);
    // The suffix must be a whole last word: `secretName` is a name, `authProfile` is not a `file`.
    if NAME_SUFFIXES
        .iter()
        .any(|s| norm.ends_with(s) && boundary[norm.len() - s.len()])
    {
        return false;
    }
    STEMS.iter().any(|stem| {
        norm.match_indices(stem).any(|(at, _)| {
            let is_excluded_word = NOT_SECRET_WORDS.iter().any(|w| {
                norm[at..].starts_with(w)
                    && boundary[at]
                    && boundary.get(at + w.len()).copied().unwrap_or(true)
            });
            !is_excluded_word
        })
    })
}

/// The key lowercased with `-`, `_` and `.` removed, and for each byte of it whether a word starts
/// there. Words split at the removed separators and at camelCase: `apiKey` is `api|key`, `APIKey` is
/// `api|key`. The key comes from an ASCII-only pattern, so byte offsets and char offsets agree.
fn normalize_key(key: &str) -> (String, Vec<bool>) {
    let chars: Vec<char> = key.chars().collect();
    let mut norm = String::with_capacity(key.len());
    let mut boundary = Vec::with_capacity(key.len());
    let mut at_word_start = true;
    for (i, &c) in chars.iter().enumerate() {
        if matches!(c, '-' | '_' | '.') {
            at_word_start = true;
            continue;
        }
        let prev = i.checked_sub(1).map(|p| chars[p]);
        let next = chars.get(i + 1).copied();
        let camel = c.is_ascii_uppercase()
            && prev.is_some_and(|p| {
                p.is_ascii_lowercase()
                    || p.is_ascii_digit()
                    || (p.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase()))
            });
        boundary.push(at_word_start || camel);
        norm.push(c.to_ascii_lowercase());
        at_word_start = false;
    }
    (norm, boundary)
}

/// The byte range of the value that starts at `start`, without its quotes, and whether it is bare.
///
/// - A quoted value (`"x"`, `'x'`, `\"x\"`, `\\\"x\\\"`) runs to the closing quote, or to the end of the
///   line if there is none. The closing quote of an escaped value is the same run of backslashes and the
///   same quote. If the closing quote is followed by anything but whitespace or a delimiter (`,;)]}`), as
///   in `""hunter2`, the value runs to the end of the line instead.
/// - A bare value runs to the end of the line, trimmed. It may take in text that belongs to a command line
///   or a JSON object around it. Over-redacting is the safe side, and a bare password may hold spaces.
///
/// Scanning stops at the end of the value, never at the end of the text, so many assignments on one long
/// line stay linear (the caller skips keys inside a value).
fn value_range(text: &str, start: usize) -> (Range<usize>, bool) {
    /// More backslashes than this are not treated as an escaped quote. The value is then bare, which
    /// takes the rest of the line. The cap keeps the scan linear.
    const MAX_ESCAPES: usize = 16;

    let rest = &text[start..];
    let bytes = rest.as_bytes();
    let slashes = bytes.iter().take_while(|&&b| b == b'\\').count();
    let quote = bytes
        .get(slashes)
        .copied()
        .filter(|b| matches!(b, b'"' | b'\''));
    if let Some(quote) = quote
        && slashes <= MAX_ESCAPES
    {
        let escaped = slashes > 0;
        let open = slashes + 1;
        let closer = &bytes[..open];
        let mut i = open;
        let closed = loop {
            match bytes.get(i) {
                None | Some(b'\n' | b'\r') => break false,
                Some(_) if escaped && bytes[i..].starts_with(closer) => break true,
                Some(b'\\') if !escaped => {
                    // A backslash escapes the next byte, except a line break. Only ASCII bytes are
                    // compared, so a multi-byte character is never split.
                    i += if matches!(bytes.get(i + 1), None | Some(b'\n' | b'\r')) {
                        1
                    } else {
                        2
                    };
                }
                Some(&b) if !escaped && b == quote => break true,
                Some(_) => i += 1,
            }
        };
        if closed {
            let after = i + if escaped { open } else { 1 };
            let tail_is_clean = rest[after..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace() || matches!(c, ',' | ';' | ')' | ']' | '}'));
            if tail_is_clean {
                return (start + open..start + i, false);
            }
        }
        // Unterminated, or text glued to the closing quote: take the rest of the line.
        let line_end = rest.find(['\n', '\r']).unwrap_or(rest.len());
        let end = rest[..line_end].trim_end().len().max(open);
        return (start + open..start + end, false);
    }
    let line_end = rest.find(['\n', '\r']).unwrap_or(rest.len());
    let line = &rest[..line_end];
    let trimmed = line.trim_start();
    let lead = line.len() - trimmed.len();
    (start + lead..start + lead + trimmed.trim_end().len(), true)
}

/// True if a bare value is a YAML block scalar header, such as `|`, `>-`, `| # note`, `!!binary |` or
/// `&anchor |2`. A trailing comment, and leading tags and anchors, are ignored.
fn is_block_header(value: &str) -> bool {
    let without_comment = find_comment(value).map_or(value, |at| &value[..at]);
    let mut v = without_comment.trim();
    while v.starts_with(['!', '&']) {
        match v.split_once([' ', '\t']) {
            Some((_, after)) => v = after.trim_start(),
            None => return false,
        }
    }
    is_block_indicator(v)
}

/// The offset of a YAML comment: a `#` that follows whitespace.
fn find_comment(v: &str) -> Option<usize> {
    v.match_indices('#')
        .map(|(i, _)| i)
        .find(|&i| v[..i].ends_with([' ', '\t']))
}

/// True for a YAML block scalar header: `|`, `>`, `|-`, `>+`, `|2`, `|2-`.
fn is_block_indicator(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(['|', '>']) else {
        return false;
    };
    let digits = rest.chars().filter(|c| ('1'..='9').contains(c)).count();
    let chomps = rest.chars().filter(|c| matches!(c, '+' | '-')).count();
    digits <= 1 && chomps <= 1 && digits + chomps == rest.chars().count()
}

/// The body of a YAML block scalar, or of a key with an empty value: the lines after the key's line that
/// are indented deeper than the key, from the start of the first to the end of the last non-blank one.
/// `key_start` is the offset of the key and `line_end` the end of the key's value, on the same line.
/// Tabs count as indentation, so a tab-indented body is not cut short (over-redacting is safe).
fn block_lines(text: &str, key_start: usize, line_end: usize) -> Option<Range<usize>> {
    let line_start = text[..key_start].rfind('\n').map_or(0, |i| i + 1);
    // A quoted key starts at its quote, which the key match leaves out.
    let mut column_start = key_start;
    while column_start > line_start
        && matches!(text.as_bytes()[column_start - 1], b'"' | b'\'' | b'\\')
    {
        column_start -= 1;
    }
    let key_column = column_start - line_start;
    let mut pos = line_end + text[line_end..].find('\n')? + 1;
    let mut first = None;
    let mut last_end = 0;
    while pos < text.len() {
        let eol = text[pos..].find('\n').map_or(text.len(), |i| pos + i);
        let line = text[pos..eol].trim_end();
        if !line.is_empty() {
            let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
            if indent <= key_column {
                break;
            }
            first.get_or_insert(pos);
            last_end = pos + line.len();
        }
        pos = eol + 1;
    }
    first.map(|f| f..last_end)
}

/// Values the key rule leaves alone (04 Appendix B, key-name exclusions).
///
/// Each form is exact, because anything extra could carry a secret: `${PG_PW:-hunter2}`,
/// `$(echo hunter2)` and `{{ .pw | default "hunter2" }}` are not references.
fn is_exempt_value(value: &str) -> bool {
    PLAIN_VALUES.iter().any(|p| value.eq_ignore_ascii_case(p))
        || is_secret_mount_path(value)
        || is_env_reference(value)
        || is_cat_reference(value)
        || is_template_reference(value)
        || is_single_placeholder(value)
}

fn is_path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-')
}

/// `/run/secrets/<path characters>`. The path names a secret, it is not one.
fn is_secret_mount_path(value: &str) -> bool {
    value
        .strip_prefix(SECRET_MOUNT)
        .is_some_and(|p| !p.is_empty() && !p.contains("..") && p.bytes().all(is_path_char))
}

/// `${NAME}` with NAME `[A-Za-z_][A-Za-z0-9_]*`. No default (`:-`), no other expansion.
fn is_env_reference(value: &str) -> bool {
    value
        .strip_prefix("${")
        .and_then(|v| v.strip_suffix('}'))
        .is_some_and(|name| {
            let mut bytes = name.bytes();
            bytes
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// `$(cat <path>)` with path characters only.
fn is_cat_reference(value: &str) -> bool {
    value
        .strip_prefix("$(cat ")
        .and_then(|v| v.strip_suffix(')'))
        .is_some_and(|p| !p.is_empty() && p.bytes().all(is_path_char))
}

/// `{{ .Values.pw }}`: one dotted name that starts with `.` between the braces, with no quote, space or
/// pipe inside, so a literal default cannot ride along and `{{ hunter2 }}` is not a reference.
fn is_template_reference(value: &str) -> bool {
    value
        .strip_prefix("{{")
        .and_then(|v| v.strip_suffix("}}"))
        .map(str::trim)
        .is_some_and(|name| {
            name.len() > 1 && name.starts_with('.') && name.bytes().all(is_path_char)
        })
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
        assert_eq!(found(r#"{\"apiKey\":\"hunter2\"}"#), ["hunter2"]);
        assert_eq!(found("Environment=DB_TOKEN=hunter2"), ["hunter2"]);
        assert_eq!(found("api-key: hunter2\nnext: line"), ["hunter2"]);
        assert_eq!(
            found("Authorization: Basic dXNlcjpwYXNz"),
            ["Basic dXNlcjpwYXNz"]
        );
    }

    #[test]
    fn a_bare_value_runs_to_the_end_of_the_line() {
        for (text, want) in [
            (
                "password: correct horse battery staple",
                "correct horse battery staple",
            ),
            ("token: Bearer abc123xyz", "Bearer abc123xyz"),
            ("password=x\u{a0}y", "x\u{a0}y"),
            ("password=a\tb  \nnext: 1", "a\tb"),
            ("--db-password=hunter2 --other", "hunter2 --other"),
            ("password=a\u{3000}b", "a\u{3000}b"),
        ] {
            assert_eq!(found(text), [want], "{text:?}");
        }
    }

    #[test]
    fn an_unterminated_quote_runs_to_the_end_of_the_line() {
        assert_eq!(found("password=\"hunter2\nnext=1"), ["hunter2"]);
    }

    #[test]
    fn text_glued_to_a_closing_quote_is_part_of_the_value() {
        assert_eq!(found(r#"password=""hunter2"#), ["\"hunter2"]);
        assert_eq!(found(r#"password="a"hunter2 more"#), [r#"a"hunter2 more"#]);
        assert_eq!(found(r"password='a'b"), ["a'b"]);
        // A delimiter after the quote is a real end.
        assert_eq!(found(r#"{"password":"a","user":"b"}"#), ["a"]);
        assert_eq!(found(r#"password="a" next"#), ["a"]);
    }

    #[test]
    fn a_backslash_inside_quotes_does_not_end_the_value() {
        assert_eq!(found(r#"password="ab\"cd" x"#), [r#"ab\"cd"#]);
    }

    #[test]
    fn a_backslash_before_a_line_break_does_not_skip_it() {
        assert_eq!(found("password=\"abc\\\nnext=1"), ["abc\\"]);
    }

    #[test]
    fn leaves_non_secrets_alone() {
        for text in [
            "passed: 12",
            "secretName: acme-tls",
            "password: ${DB_PASSWORD}",
            "password: $(cat /x)",
            "password: $(cat /run/secrets/db-pass)",
            "password: {{ .Values.pw }}",
            "token: null",
            "secret: Required",
            "password:",
            "password: ''",
            "passwordFile: /etc/pw",
            "tokenRef: x",
            "author: Ada",
            "authors: Ada",
            "passedCount: 3",
            "password: /run/secrets/db",
            "host: example.test",
        ] {
            assert!(found(text).is_empty(), "should not match: {text}");
        }
    }

    #[test]
    fn references_that_carry_a_literal_are_redacted() {
        for (text, want) in [
            ("password=${PG_PW:-hunter2}", "${PG_PW:-hunter2}"),
            ("password=$(echo hunter2)", "$(echo hunter2)"),
            (
                r#"password={{ .pw | default "hunter2" }}"#,
                r#"{{ .pw | default "hunter2" }}"#,
            ),
            ("password={{ default hunter2 }}", "{{ default hunter2 }}"),
            (
                "password=$(cat /x; echo hunter2)",
                "$(cat /x; echo hunter2)",
            ),
            ("password=/run/secrets/x hunter2", "/run/secrets/x hunter2"),
            ("password=/run/secrets/", "/run/secrets/"),
            ("password=${A}${B}", "${A}${B}"),
            ("password=${A}secret123", "${A}secret123"),
            ("password=$(cat /x)tail", "$(cat /x)tail"),
            ("password=${1ABC}", "${1ABC}"),
        ] {
            assert_eq!(found(text), [want], "{text}");
        }
    }

    #[test]
    fn auth_words_are_matched_whole() {
        assert_eq!(found("authorization: Bearer x"), ["Bearer x"]);
        assert_eq!(found("authProfile: hunter2"), ["hunter2"]);
        assert_eq!(found("auth_profile: hunter2"), ["hunter2"]);
        assert_eq!(found("authorizationHeader: hunter2"), ["hunter2"]);
        assert_eq!(found("passedToken: hunter2"), ["hunter2"]);
        assert!(found("authorProfile: Ada").is_empty());
        assert!(found("AUTHOR: Ada").is_empty());
    }

    #[test]
    fn yaml_block_values_are_redacted_to_the_end_of_the_block() {
        let text = "a: 1\ntoken: |\n  line one hunter2\n\n  line two\nnext: ok\n";
        assert_eq!(found(text), ["  line one hunter2\n\n  line two"]);
        let text = "key:\n  - token: >-\n      folded secret\n      more\n    other: 1\n";
        assert_eq!(found(text), ["      folded secret\n      more"]);
        // CRLF, a block at the end of the text, and an empty block.
        assert_eq!(found("token: |\r\n  abc\r\nx: 1\r\n"), ["  abc"]);
        assert_eq!(found("token: |\n  abc"), ["  abc"]);
        assert!(found("token: |\nnext: 1").is_empty());
        assert!(found("token: |").is_empty());
        // Not a block header.
        assert_eq!(found("token: | foo\n  bar"), ["| foo"]);
        assert_eq!(found("token: |22\n  bar"), ["|22"]);
    }

    #[test]
    fn an_empty_value_takes_the_deeper_lines_that_follow() {
        assert_eq!(found("password:\n  hunter2\nnext: 1"), ["  hunter2"]);
        assert_eq!(
            found("password:   \r\n    a\r\n\r\n    b\r\nx: 1"),
            ["    a\r\n\r\n    b"]
        );
        assert_eq!(
            found("- secret:\n    key: hunter2\n  other: 1"),
            ["    key: hunter2"]
        );
        assert!(found("password:\nnext: 1").is_empty());
        assert!(found("password:").is_empty());
        // A quoted empty value is a value, not a pointer to the next lines.
        assert!(found("password: \"\"\n  hunter2").is_empty());
    }

    #[test]
    fn block_headers_may_carry_tags_anchors_and_comments() {
        for text in [
            "token: | # note\n  hunter2",
            "token: |- #note\n  hunter2",
            "token: !!binary |\n  hunter2",
            "token: &a |\n  hunter2",
            "token: !!str &a >-\n  hunter2",
            "token: |2+ # x\n  hunter2",
        ] {
            assert_eq!(found(text), ["  hunter2"], "{text:?}");
        }
        // A quoted pipe is a value, not a block.
        assert_eq!(found("token: \"|\"\n  body"), ["|"]);
        assert_eq!(found("token: !!binary\n  body"), ["!!binary"]);
    }

    #[test]
    fn block_indent_is_measured_from_a_quoted_key_and_counts_tabs() {
        assert_eq!(found("\"token\": |\n hunter2\n"), [" hunter2"]);
        assert_eq!(found("'token': |\n hunter2\n"), [" hunter2"]);
        assert_eq!(
            found("token: |\n\thunter2\n\tmore\nnext: 1"),
            ["\thunter2\n\tmore"]
        );
        assert_eq!(found("- token: |\n    hunter2\n  next: 1"), ["    hunter2"]);
    }

    #[test]
    fn escaped_quotes_may_carry_more_backslashes() {
        assert_eq!(found(r#"{\\\"password\\\":\\\"hunter2\\\"}"#), ["hunter2"]);
        assert_eq!(
            found(r#"{\\\\\\\"password\\\\\\\":\\\\\\\"hunter2\\\\\\\",\\\\\\\"x\\\\\\\":1}"#),
            ["hunter2"]
        );
        // Too many backslashes: the rest of the line, never a leak.
        let many = "\\".repeat(40);
        let text = format!("password={many}\"hunter2{many}\" x");
        assert_eq!(found(&text), [text.strip_prefix("password=").unwrap_or("")]);
    }

    #[test]
    fn names_that_look_like_references_but_are_not() {
        for (text, want) in [
            ("password={{hunter2}}", "{{hunter2}}"),
            ("password={{ hunter2 }}", "{{ hunter2 }}"),
            ("password={{ . }}", "{{ . }}"),
            (
                "password=/run/secrets/../../etc/shadow",
                "/run/secrets/../../etc/shadow",
            ),
        ] {
            assert_eq!(found(text), [want], "{text}");
        }
        assert!(found("password={{.Values.pw}}").is_empty());
        assert!(found("password: /run/secrets/db.pass").is_empty());
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
    }

    #[test]
    fn multibyte_text_is_never_split() {
        assert_eq!(
            found("pässword=ünï password=pä\u{1F600}ss"),
            ["pä\u{1F600}ss"]
        );
        assert_eq!(found("password=\"é\\é\" x"), ["é\\é"]);
    }

    #[test]
    fn many_assignments_on_one_line_stay_linear() {
        let started = std::time::Instant::now();
        let text = "pass=".repeat(100_000);
        assert_eq!(found(&text).len(), 1);
        let quoted = "password=\"a\" ".repeat(100_000);
        assert_eq!(found(&quoted).len(), 100_000);
        let placeholders = "[REDACTED:x:00000000] ".repeat(100_000) + "password=a";
        assert_eq!(found(&placeholders), ["a"]);
        let nulls = "password=null ".repeat(100_000);
        assert_eq!(found(&nulls).len(), 1);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
    }
}
