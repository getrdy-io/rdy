//! The compiled-in rules (04 Appendix B).
//!
//! M1-048 ships the engine and one rule, `secret_by_key`. M1-060 adds the rest and tunes this one against
//! the corpus. A spec can add rules but never remove or weaken one, so this table is a `static`.

use std::cell::OnceCell;
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

/// Characters that end a line: LF, CR, NEL, line separator and paragraph separator. CR LF is one end.
const LINE_ENDS: [char; 5] = ['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'];

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
    let lines = OnceCell::new();
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
        let value = value_range(text, whole.end());
        // A comment line has no continuation, so a key inside one takes only its own line. That also keeps
        // the scan below linear on a run of comment lines that all mention a key.
        let lines = lines.get_or_init(|| Lines::new(text));
        let body = if lines.is_comment(text, key.start()) {
            None
        } else {
            // A quoted key with nothing after it, as in `{"password":` then `"x"}`, takes the next line.
            let force_next = value.is_empty() && text[..key.start()].ends_with(['"', '\'']);
            body_lines(text, lines, key.start(), value.end, force_next)
        };
        if let Some(body) = body {
            covered_until = body.end;
            let from = if value.is_empty() {
                body.start
            } else {
                value.start
            };
            out.push(from..body.end);
        } else if !value.is_empty() {
            covered_until = value.end;
            // References, plain words and placeholders are exempt only when the value is one line
            // with nothing below it: `null` followed by a deeper line is not exempt.
            if !is_exempt_value(&text[value.clone()]) {
                out.push(value);
            }
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

/// The byte range of the value that starts at `start`, without its quotes.
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
fn value_range(text: &str, start: usize) -> Range<usize> {
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
        let mut i = open;
        let closed = loop {
            if i >= bytes.len() || at_line_end(bytes, i) {
                break false;
            }
            match bytes[i] {
                b'\\' if escaped => {
                    // Close only on exactly the opener's run of backslashes and the same quote. A longer
                    // run is a deeper level of escaping and belongs to the value.
                    let run = bytes[i..].iter().take_while(|&&b| b == b'\\').count();
                    if run == slashes && bytes.get(i + run) == Some(&quote) {
                        break true;
                    }
                    i += run;
                }
                b'\\' => {
                    // A backslash escapes the next byte, except a line break. Only ASCII bytes are
                    // compared, so a multi-byte character is never split.
                    i += if at_line_end(bytes, i + 1) { 1 } else { 2 };
                }
                b if b == quote && !escaped => break true,
                _ => i += 1,
            }
        };
        if closed {
            let after = i + if escaped { open } else { 1 };
            let tail_is_clean = rest[after..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace() || matches!(c, ',' | ';' | ')' | ']' | '}'));
            if tail_is_clean {
                return start + open..start + i;
            }
        }
        // Unterminated, or text glued to the closing quote: take the rest of the line.
        let line_end = rest.find(LINE_ENDS).unwrap_or(rest.len());
        let end = rest[..line_end].trim_end().len().max(open);
        return start + open..start + end;
    }
    let line_end = rest.find(LINE_ENDS).unwrap_or(rest.len());
    let line = &rest[..line_end];
    let trimmed = line.trim_start();
    let lead = line.len() - trimmed.len();
    start + lead..start + lead + trimmed.trim_end().len()
}

/// True if a line end (see [`LINE_ENDS`]) starts at byte `i`.
fn at_line_end(bytes: &[u8], i: usize) -> bool {
    match bytes.get(i) {
        Some(b'\n' | b'\r') => true,
        Some(0xC2) => bytes.get(i + 1) == Some(&0x85),
        Some(0xE2) => {
            bytes.get(i + 1) == Some(&0x80) && matches!(bytes.get(i + 2), Some(0xA8 | 0xA9))
        }
        _ => false,
    }
}

/// Where every line ends, so the lines around a position are found without rescanning the text. A line
/// end is one of [`LINE_ENDS`], and CR LF is a single end.
struct Lines {
    /// For each line end, the offset where it starts and the offset after it. Sorted.
    breaks: Vec<(usize, usize)>,
    len: usize,
}

impl Lines {
    fn new(text: &str) -> Self {
        let mut breaks: Vec<(usize, usize)> = Vec::new();
        for (i, m) in text.match_indices(LINE_ENDS) {
            if breaks.last().is_some_and(|&(_, after)| i < after) {
                continue; // the LF of a CR LF
            }
            let width = if m == "\r" && text[i + 1..].starts_with('\n') {
                2
            } else {
                m.len()
            };
            breaks.push((i, i + width));
        }
        Self {
            breaks,
            len: text.len(),
        }
    }

    /// The end of the line that holds `pos`, and where the next line starts (`None` after the last line).
    fn line_end(&self, pos: usize) -> (usize, Option<usize>) {
        let i = self.breaks.partition_point(|&(start, _)| start < pos);
        self.breaks
            .get(i)
            .map_or((self.len, None), |&(start, after)| (start, Some(after)))
    }

    /// The offset where the line that holds `pos` starts.
    fn line_start(&self, pos: usize) -> usize {
        let i = self.breaks.partition_point(|&(start, _)| start < pos);
        i.checked_sub(1).map_or(0, |j| self.breaks[j].1)
    }

    /// True if the first non-blank character of the line that holds `pos` is `#`.
    fn is_comment(&self, text: &str, pos: usize) -> bool {
        text[self.line_start(pos)..]
            .trim_start_matches([' ', '\t'])
            .starts_with('#')
    }
}

/// True if a line with indent `line_ws` and text `rest` still belongs to the value of a key whose line
/// has indent `key_ws`. Deeper lines do. A line at the same indent does if it starts a `- ` list item,
/// as in `passwords:` then `- hunter2`. If the two indents mix tabs and spaces they cannot be compared,
/// and the line counts as deeper, which fails closed.
fn continues_value(key_ws: &str, line_ws: &str, rest: &str) -> bool {
    let uniform = |ws: &str| ws.bytes().all(|b| Some(b) == ws.bytes().next());
    let comparable = key_ws.is_empty()
        || line_ws.is_empty()
        || (uniform(key_ws) && uniform(line_ws) && key_ws.as_bytes()[0] == line_ws.as_bytes()[0]);
    if !comparable {
        return true;
    }
    match line_ws.len().cmp(&key_ws.len()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => rest
            .strip_prefix('-')
            .is_some_and(|r| r.is_empty() || r.starts_with([' ', '\t'])),
        std::cmp::Ordering::Less => false,
    }
}

/// The lines below a key that belong to its value. This is the one rule for every YAML shape (block
/// scalars, multi-line plain and quoted scalars, flow collections, values on the next line, tags, anchors
/// and comments), and it fails closed:
///
/// after any key match, the value is the rest of the key's line **and** every following line up to the first
/// line that does not continue it. Blank lines never end the value. A comment line (first non-blank
/// character `#`) never ends it either, unless it is deeper than the key, in which case it is value text,
/// as in a block scalar. Any other line continues the value if its indent is deeper than the indent of the
/// key's line, or equal and starting with `- ` (kubectl-style lists). The indent is measured from the start
/// of the key's line, not from the key, so `db password:` and `- token:` count from their line's first
/// non-blank column. A tab and space mix in the two indents counts as deeper. If `force_next` is set, the
/// first line that is not blank or a shallower comment is taken whatever its indent.
///
/// This over-redacts on purpose. It takes sibling list items after a `- token:` line, closing brackets,
/// and the text of a value already on the key's line that was only a comment or tag. M1-060 narrows it
/// against the corpus.
///
/// Returns the span from the start of the first taken line to the end of the last, or `None` if no line
/// is taken. `value_end` is the end of the key's value, on the key's line.
fn body_lines(
    text: &str,
    lines: &Lines,
    key_start: usize,
    value_end: usize,
    mut force_next: bool,
) -> Option<Range<usize>> {
    let key_line = &text[lines.line_start(key_start)..];
    let key_ws = &key_line[..key_line.len() - key_line.trim_start_matches([' ', '\t']).len()];
    let mut pos = lines.line_end(value_end).1?;
    let mut first = None;
    let mut last_end = 0;
    loop {
        let (end, next) = lines.line_end(pos);
        let line = text[pos..end].trim_end();
        if !line.is_empty() {
            let rest = line.trim_start_matches([' ', '\t']);
            let line_ws = &line[..line.len() - rest.len()];
            let continues = continues_value(key_ws, line_ws, rest);
            let is_comment = rest.starts_with('#');
            if !(is_comment && !continues) {
                if !continues && !force_next {
                    break;
                }
                force_next = false;
                first.get_or_insert(pos);
                last_end = pos + line.len();
            }
        }
        match next {
            Some(n) => pos = n,
            None => break,
        }
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
        // The header is part of the value: one rule for every shape, and it fails closed.
        let text = "a: 1\ntoken: |\n  line one hunter2\n\n  line two\nnext: ok\n";
        assert_eq!(found(text), ["|\n  line one hunter2\n\n  line two"]);
        let text = "key:\n  - token: >-\n      folded secret\n      more\n    other: 1\n";
        // `other: 1` is deeper than the key's line (the `-` is at column 2), so it is part of the value.
        assert_eq!(
            found(text),
            [">-\n      folded secret\n      more\n    other: 1"]
        );
        // CRLF, a block at the end of the text, and an empty block.
        assert_eq!(found("token: |\r\n  abc\r\nx: 1\r\n"), ["|\r\n  abc"]);
        assert_eq!(found("token: |\n  abc"), ["|\n  abc"]);
        assert_eq!(found("token: |\nnext: 1"), ["|"]);
        assert_eq!(found("token: |"), ["|"]);
        assert_eq!(found("token: | foo\n  bar"), ["| foo\n  bar"]);
        assert_eq!(found("token: |22\n  bar"), ["|22\n  bar"]);
        // A deeper comment line is text in a block scalar. A shallower one is not.
        assert_eq!(found("token: |\n  # hunter2"), ["|\n  # hunter2"]);
        assert_eq!(found("password:\n# old\n  hunter2"), ["  hunter2"]);
        assert_eq!(found("password:\n  a\n# c\n  b"), ["  a\n# c\n  b"]);
        assert_eq!(found("password:\n  a\n# c\nnext: 1"), ["  a"]);
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
            ["    key: hunter2\n  other: 1"]
        );
        assert!(found("password:\nnext: 1").is_empty());
        assert!(found("password:").is_empty());
        // A quoted empty value does not end the value either.
        assert_eq!(found("password: \"\"\n  hunter2"), ["  hunter2"]);
    }

    #[test]
    fn a_value_may_continue_on_the_next_lines_in_every_yaml_shape() {
        for (text, want) in [
            (
                "password: correct horse\n  battery staple",
                "correct horse\n  battery staple",
            ),
            ("password: \"hunter\n  2\"", "hunter\n  2\""),
            ("password: 'hunter\n  2'", "hunter\n  2'"),
            ("password: {\n  a: hunter2\n}", "{\n  a: hunter2"),
            ("password: [\n  hunter2\n]", "[\n  hunter2"),
            ("password: null\n  hunter2", "null\n  hunter2"),
            ("password: ${DB}\n  hunter2", "${DB}\n  hunter2"),
            ("password: true\n  hunter2", "true\n  hunter2"),
            (
                "password: [REDACTED:x:00000000]\n  hunter2",
                "[REDACTED:x:00000000]\n  hunter2",
            ),
            ("{\"password\":\n\"hunter2\"}", "\"hunter2\"}"),
            ("{'password':\n  'hunter2'}", "  'hunter2'}"),
            ("{\"password\":\n\n# c\n\"hunter2\"}", "\"hunter2\"}"),
            ("k:\n  y: 1\u{85}password:\n hunter2", " hunter2"),
            ("k:\n  y: 1\u{2028}password:\n hunter2", " hunter2"),
            ("k:\n  y: 1\u{2029}password:\n hunter2", " hunter2"),
            ("password:\u{85}  hunter2", "  hunter2"),
            ("password:\u{2028}  hunter2\u{2029}next: 1", "  hunter2"),
            ("password=\"a\\\u{85}b", "a\\"),
        ] {
            assert_eq!(found(text), [want], "{text:?}");
        }
        // A key inside a comment takes only its own line.
        assert_eq!(found("# password: hunter2\n  x"), ["hunter2"]);
    }

    #[test]
    fn block_indent_is_measured_from_the_line_start_and_counts_tabs() {
        assert_eq!(found("\"token\": |\n hunter2\n"), ["|\n hunter2"]);
        assert_eq!(found("'token': |\n hunter2\n"), ["|\n hunter2"]);
        assert_eq!(
            found("token: |\n\thunter2\n\tmore\nnext: 1"),
            ["|\n\thunter2\n\tmore"]
        );
        assert_eq!(
            found("- token: |\n    hunter2\n  next: 1"),
            ["|\n    hunter2\n  next: 1"]
        );
    }

    #[test]
    fn a_value_on_the_following_lines_is_found_in_every_yaml_form() {
        for (text, want) in [
            ("password: # note\n  hunter2", "# note\n  hunter2"),
            ("token: !!binary\n  aGk=", "!!binary\n  aGk="),
            ("password: &a\n  hunter2", "&a\n  hunter2"),
            ("token: !!binary |\n  aGk=", "!!binary |\n  aGk="),
            ("passwords:\n- hunter2", "- hunter2"),
            ("passwords:\n- a\n- b\nnext: 1", "- a\n- b"),
            ("db password:\n  hunter2", "  hunter2"),
            ("x/token: |\n hunter2", "|\n hunter2"),
            ("password:\r  hunter2", "  hunter2"),
            ("password:\r\n  hunter2\r\nnext: 1", "  hunter2"),
            ("token: |\r  hunter2\rnext: 1", "|\r  hunter2"),
            ("    password:\n\thunter2", "\thunter2"),
            ("\tpassword:\n    hunter2", "    hunter2"),
            ("  password:\n \t hunter2\n  next: 1", " \t hunter2"),
            ("password:\n  a\n\n  b\nnext: 1", "  a\n\n  b"),
        ] {
            assert_eq!(found(text), [want], "{text:?}");
        }
    }

    #[test]
    fn a_value_below_ends_at_the_first_line_that_is_not_deeper() {
        assert_eq!(found("password:\n  a\nnext: 1\n  b"), ["  a"]);
        assert_eq!(found("  password:\n    a\n  next: 1\n    b"), ["    a"]);
        assert_eq!(found("  password:\n    a\n next: 1"), ["    a"]);
        // A same-column `- ` line continues the value, a same-column key does not.
        assert_eq!(found("  passwords:\n  - a\n  next: 1"), ["  - a"]);
        assert_eq!(found("  passwords:\n  -\n  next: 1"), ["  -"]);
        assert!(found("  password:\n  -x\n").is_empty());
    }

    #[test]
    fn an_escaped_value_closes_only_on_its_own_run_of_backslashes() {
        // `\"pa\\\",ss\"`: the three-backslash run is part of the value.
        let text = r#"password=\"pa\\\",ss\" x"#;
        assert_eq!(found(text), [r#"pa\\\",ss"#]);
        let text = r#"{\"password\":\"a\\\"b\\\\\"c\",\"x\":1}"#;
        assert_eq!(found(text), [r#"a\\\"b\\\\\"c"#]);
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
        for (unit, spans) in [
            ("password:\n", 0),
            ("- token: |\n", 1),
            ("password:\n\n", 0),
            ("password:\n# password:\n", 0),
            ("password:\n  a\n", 100_000),
            ("# password: x\n", 100_000),
            ("password: \"a\"\n", 100_000),
        ] {
            let text = unit.repeat(100_000);
            assert_eq!(found(&text).len(), spans, "{unit:?}");
        }
        let quoted = "password=\"a\" ".repeat(100_000);
        assert_eq!(found(&quoted).len(), 100_000);
        let placeholders = "[REDACTED:x:00000000] ".repeat(100_000) + "password=a";
        assert_eq!(found(&placeholders), ["a"]);
        let nulls = "password=null ".repeat(100_000);
        assert_eq!(found(&nulls).len(), 1);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "took {:?}",
            started.elapsed()
        );
    }
}
