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

/// The name of the key-name rule, also used by the report walk when it replaces a whole member.
pub(crate) const SECRET_BY_KEY: &str = "secret_by_key";

/// The built-in rule set for the Report ruleset.
pub(crate) static BUILT_IN: &[Rule] = &[Rule {
    name: SECRET_BY_KEY,
    priority: priority::KEY_NAMES,
    find: find_secret_by_key,
}];

/// A well-formed placeholder. Keys inside one are not assignments: `secret_by_key:1a2b3c4d]` looks like
/// `key: value` and must not be redacted again.
static PLACEHOLDER: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"\[REDACTED:[a-z0-9_.]+:[0-9a-f]{8}\]"));

/// Where the well-formed placeholders in `text` are, sorted and disjoint. The size caps use it so a cut
/// never lands inside one.
pub(crate) fn placeholder_spans(text: &str) -> Vec<Range<usize>> {
    PLACEHOLDER
        .as_ref()
        .map(|re| re.find_iter(text).map(|m| m.range()).collect())
        .unwrap_or_default()
}

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

// Counts the bytes the key rule looks at, so a test can check that the work is linear in the input
// without timing anything. Every scan in this rule calls `visit` with the bytes it covers.
#[cfg(test)]
thread_local! {
    static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn visit(bytes: usize) {
    VISITS.with(|v| v.set(v.get() + bytes));
}

#[cfg(not(test))]
#[inline(always)]
fn visit(_bytes: usize) {}

fn find_secret_by_key(text: &str, out: &mut Vec<Range<usize>>) {
    let (Ok(assignment), Ok(placeholder)) = (ASSIGNMENT.as_ref(), PLACEHOLDER.as_ref()) else {
        out.push(0..text.len());
        return;
    };
    // Sorted and disjoint, so a binary search tells whether a position is inside one.
    let placeholders: Vec<Range<usize>> = placeholder.find_iter(text).map(|m| m.range()).collect();
    // Everything before this offset is part of a value already handled. A later key there is inside
    // that value, so it is skipped. This keeps the work linear on input such as `pass=pass=...`.
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
        let lines = lines.get_or_init(|| Lines::new(text));
        let (span, covered) = value_span(text, lines, key.start(), whole.end());
        covered_until = covered_until.max(covered);
        out.extend(span);
    }
}

/// The one rule for what to redact after a secret key. It parses no quotes, brackets or escapes, because
/// every such parser leaked on some input (`'a\''`, `#` inside brackets, `"""`, tags, anchors). It fails
/// closed instead. `key_start` is where the key starts and `from` where its separator ends.
///
/// 1. The **value** is the rest of the key's line, trimmed.
/// 2. A value is **simple** when, after dropping one trailing `,` or `;`, it is not empty and is made
///    only of `A-Z a-z 0-9 . _ ~ + / = : @ % -`. That excludes quotes, brackets, braces, `\`, `#`, `!`,
///    `&`, `|`, `>`, `*` and spaces. A **reference or placeholder** (`${NAME}`, `$(cat path)`,
///    `{{ .Name }}`, `[REDACTED:..]`, `null`, a `/run/secrets/` path) counts as simple too, but it is left
///    alone when nothing is taken below it.
/// 3. A simple value is redacted in place. It also takes the lines **below it that are indented deeper**
///    than the key's line (blank lines inside are fine), so `password: a` then `  b` is covered.
/// 4. Any other value (empty, quoted, bracketed, tagged, anchored, a block indicator, escaped, or with
///    spaces) is redacted to the end of the line, and so is every following line up to, but not
///    including, the first line that **both** starts at or left of the key line's first non-blank column
///    **and** itself starts with a key (`name:`, `name=`, `"name":`). With no such line it runs to the
///    end of the text. If the value is one line wrapped in a matching pair of quotes, the two outer
///    quotes stay. A tab and space mix in the two indents counts as deeper.
/// 5. The terminator test in rule 4 is switched off, so the value goes on, while any of these plain counts
///    over the text taken so far says it is still open: more `[` and `{` than `]` and `}`; an odd number
///    of the value's opening quote character (`"` or `'`); or more `-----BEGIN ` than `-----END `
///    markers (a PEM key, whose `Proc-Type: 4,ENCRYPTED` header looks like a key). The counts ignore
///    quotes inside brackets, escapes and everything else, and they can only make a span longer. Without
///    them `password: {` then `v: hunter2}`, or `KEY="-----BEGIN` then a key-shaped line, would stop early.
/// 6. A line only counts as a key when `name=` is not directly followed by another `=`, a quote or the end
///    of the line, so the base64 tail `QUJD==` is not a key. This also keeps `NEXT="1"` inside the
///    value, while `NEXT= "1"` still counts as a key.
/// 7. A key inside a `#` comment line takes only its own value, never the lines below.
///
/// This over-redacts on purpose: a one-line JSON object after a secret key loses the rest of its line,
/// a `[INFO]` log line is not a key, so a quoted secret in a log can take every line below it, and a
/// sibling list item or a stray closing bracket is taken with the value. M1-060 narrows this with
/// corpus evidence. A line is visited a constant number of times, and keys inside what was taken are
/// skipped by the caller, so the work is linear.
///
/// Returns the range to redact, if any, and the offset up to which the caller can skip keys.
fn value_span(
    text: &str,
    lines: &Lines,
    key_start: usize,
    from: usize,
) -> (Option<Range<usize>>, usize) {
    let (line_end, next_line) = lines.line_end(from);
    let key_line = &text[lines.line_start(key_start)..line_end];
    let key_text = key_line.trim_start_matches([' ', '\t']);
    let key_ws = &key_line[..key_line.len() - key_text.len()];
    visit(key_line.len());

    let raw = &text[from..line_end];
    let value = raw.trim();
    let value_start = from + (raw.len() - raw.trim_start().len());
    let value_end = value_start + value.len();
    let stripped = value.strip_suffix([',', ';']).unwrap_or(value);
    let is_simple = !stripped.is_empty() && stripped.bytes().all(is_simple_byte);
    let is_exempt = !stripped.is_empty() && is_exempt_value(stripped);
    visit(raw.len());

    // What to redact if nothing below the value is taken.
    let own = if is_simple {
        value_start..value_start + stripped.len()
    } else if let [first, .., last] = stripped.as_bytes()
        && first == last
        && matches!(first, b'"' | b'\'')
    {
        value_start + 1..value_start + stripped.len() - 1
    } else {
        value_start..value_end
    };

    if key_text.starts_with('#') {
        let span = (!is_exempt && !own.is_empty()).then_some(own);
        return (span, line_end);
    }

    let simple = is_simple || is_exempt;
    let key_indent = Indent::of(key_ws);
    let quote = value.bytes().next().filter(|b| matches!(b, b'"' | b'\''));
    let mut open = Open::default();
    if !simple {
        open.add(value, quote);
    }
    let mut first = None;
    let mut last_end = None;
    let mut pos = next_line;
    while let Some(start) = pos {
        let (end, next) = lines.line_end(start);
        visit(end - start + 1);
        let line = text[start..end].trim_end();
        if !line.is_empty() {
            let rest = line.trim_start_matches([' ', '\t']);
            let at_or_left =
                key_indent.is_at_or_left_of(&Indent::of(&line[..line.len() - rest.len()]));
            if at_or_left && (simple || (!open.is_open() && starts_with_key_token(rest))) {
                break;
            }
            first.get_or_insert(start);
            last_end = Some(start + line.len());
            if !simple {
                open.add(line, quote);
            }
        }
        pos = next;
    }

    let span = match (simple, last_end) {
        (true, None) => (!is_exempt).then_some(own),
        (true, Some(end)) => Some(value_start..end),
        (false, None) => (!own.is_empty()).then_some(own),
        (false, Some(end)) => {
            let from = if value.is_empty() {
                first.unwrap_or(end)
            } else {
                value_start
            };
            Some(from..end)
        }
    };
    let covered = span.as_ref().map_or(line_end, |s| s.end.max(line_end));
    (span, covered)
}

/// The bytes a simple value may hold: letters, digits and `. _ ~ + / = : @ % -`.
fn is_simple_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b':' | b'@' | b'%' | b'-'
        )
}

/// The leading blanks of a line, classified so two of them can be compared.
#[derive(Clone, Copy)]
enum Indent {
    Empty,
    Spaces(usize),
    Tabs(usize),
    /// Tabs and spaces mixed. It cannot be compared with anything but an empty indent.
    Mixed(usize),
}

impl Indent {
    fn of(ws: &str) -> Self {
        let tabs = ws.bytes().filter(|&b| b == b'\t').count();
        match (ws.len(), tabs) {
            (0, _) => Self::Empty,
            (n, 0) => Self::Spaces(n),
            (n, t) if t == n => Self::Tabs(n),
            (n, _) => Self::Mixed(n),
        }
    }

    fn width(self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Spaces(n) | Self::Tabs(n) | Self::Mixed(n) => n,
        }
    }

    /// True if `line` starts at or left of `self`. An indent that cannot be compared (tabs against
    /// spaces, or a mix) counts as deeper, which fails closed.
    fn is_at_or_left_of(self, line: &Self) -> bool {
        let comparable = matches!(
            (self, *line),
            (Self::Empty, _)
                | (_, Self::Empty)
                | (Self::Spaces(_), Self::Spaces(_))
                | (Self::Tabs(_), Self::Tabs(_))
        );
        comparable && line.width() <= self.width()
    }
}

/// True if the line text starts with a key: `name:`, `name=`, `"name":` or `'name':`.
fn starts_with_key_token(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    let mut i = 0;
    if let Some(&quote) = bytes.first().filter(|b| matches!(b, b'"' | b'\'')) {
        let Some(close) = bytes[1..].iter().position(|&b| b == quote) else {
            visit(bytes.len());
            return false;
        };
        i = close + 2;
    } else {
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.' | b'-'))
        {
            i += 1;
        }
        if i == 0 {
            visit(1);
            return false;
        }
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    visit(i + 1);
    match bytes.get(i) {
        Some(b':') => true,
        // `AbCd==` and `KEY="v"` and `AbCd=` are not keys here.
        Some(b'=') => !matches!(bytes.get(i + 1), None | Some(b'=' | b'"' | b'\'')),
        _ => false,
    }
}

/// Plain counts over the text a value has taken so far. They decide whether the value is still open,
/// and they are deliberately naive: no quotes inside brackets, no escapes, no nesting by kind.
#[derive(Default)]
struct Open {
    /// `[` and `{` minus `]` and `}`.
    brackets: i64,
    /// How many times the value's opening quote character has appeared.
    quotes: usize,
    /// `-----BEGIN ` markers minus `-----END ` markers.
    pem: i64,
}

impl Open {
    fn add(&mut self, s: &str, quote: Option<u8>) {
        visit(s.len());
        for b in s.bytes() {
            match b {
                b'[' | b'{' => self.brackets += 1,
                b']' | b'}' => self.brackets -= 1,
                _ if Some(b) == quote => self.quotes += 1,
                _ => {}
            }
        }
        if s.contains("-----") {
            visit(2 * s.len());
            let begins = i64::try_from(s.matches("-----BEGIN ").count()).unwrap_or(i64::MAX);
            let ends = i64::try_from(s.matches("-----END ").count()).unwrap_or(i64::MAX);
            self.pem += begins - ends;
        }
    }

    /// True while a bracket, a quote or a PEM block that the value opened has not been closed.
    fn is_open(&self) -> bool {
        self.brackets > 0 || self.quotes % 2 == 1 || self.pem > 0
    }
}

/// True if `pos` is inside one of the sorted, disjoint ranges.
fn inside(ranges: &[Range<usize>], pos: usize) -> bool {
    let i = ranges.partition_point(|r| r.end <= pos);
    ranges.get(i).is_some_and(|r| r.start <= pos)
}

/// True if the key looks like it names a secret.
pub(crate) fn is_secret_key(key: &str) -> bool {
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

/// Where every line ends, so the lines around a position are found without rescanning the text. A line
/// end is one of [`LINE_ENDS`], and CR LF is a single end.
struct Lines {
    /// For each line end, the offset where it starts and the offset after it. Sorted.
    breaks: Vec<(usize, usize)>,
    len: usize,
}

impl Lines {
    fn new(text: &str) -> Self {
        visit(text.len());
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
}

/// Values the key rule leaves alone (04 Appendix B, key-name exclusions).
///
/// Each form is exact, because anything extra could carry a secret: `${PG_PW:-hunter2}`,
/// `$(echo hunter2)` and `{{ .pw | default "hunter2" }}` are not references.
pub(crate) fn is_exempt_value(value: &str) -> bool {
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

    fn spans(text: &str) -> Vec<Range<usize>> {
        let mut out = Vec::new();
        find_secret_by_key(text, &mut out);
        out
    }

    fn found(text: &str) -> Vec<&str> {
        spans(text).into_iter().map(|r| &text[r]).collect()
    }

    /// Asserts that every occurrence of `secret` in `text` sits inside a span.
    fn assert_covered(text: &str, secret: &str) {
        let spans = spans(text);
        assert!(text.contains(secret), "{text:?} does not hold {secret:?}");
        for (at, _) in text.match_indices(secret) {
            assert!(
                spans
                    .iter()
                    .any(|r| r.start <= at && at + secret.len() <= r.end),
                "{secret:?} leaks at {at} in {text:?}, spans {spans:?}"
            );
        }
    }

    #[test]
    fn the_patterns_compile() {
        assert!(ASSIGNMENT.is_ok());
        assert!(PLACEHOLDER.is_ok());
    }

    #[test]
    fn simple_values_are_redacted_in_place() {
        for (text, want) in [
            ("DB_PASSWORD=hunter2", "hunter2"),
            ("password: hunter2", "hunter2"),
            ("password = hunter2", "hunter2"),
            ("api-key: hunter2\nnext: line", "hunter2"),
            ("Environment=DB_TOKEN=hunter2", "hunter2"),
            ("password=hunter2,", "hunter2"),
            ("password=hunter2;", "hunter2"),
            ("password: a.b_c~d+e/f=g:h@i%j-k", "a.b_c~d+e/f=g:h@i%j-k"),
            ("password=aGk=\nnext=1", "aGk="),
        ] {
            assert_eq!(found(text), [want], "{text:?}");
        }
    }

    #[test]
    fn a_simple_value_takes_the_deeper_lines_below_it() {
        assert_eq!(found("password: a\n  b"), ["a\n  b"]);
        assert_eq!(found("password: a\n\n  b\n  c\nnext: 1"), ["a\n\n  b\n  c"]);
        assert_eq!(found("  password: a\n    b\n  next: 1"), ["a\n    b"]);
        assert_eq!(found("password: a\nnext: 1\n  b"), ["a"]);
        assert_eq!(found("password: a\r\n  b\r\nnext: 1"), ["a\r\n  b"]);
        assert_eq!(found("password: a\r  b\rnext: 1"), ["a\r  b"]);
        // Tabs against spaces cannot be compared, so the line counts as deeper.
        assert_eq!(found("    password: a\n\tb\nnext: 1"), ["a\n\tb"]);
        assert_eq!(found("\tpassword: a\n    b\nnext: 1"), ["a\n    b"]);
        assert_eq!(found("  password: a\n \t b\n  next: 1"), ["a\n \t b"]);
        // The same indent, or less, ends it.
        assert_eq!(found("  password: a\n  b"), ["a"]);
    }

    #[test]
    fn values_that_are_not_simple_run_to_the_next_key() {
        for (text, want) in [
            // The rest of the line, spaces and all.
            ("password: correct horse\nuser: bob", "correct horse"),
            ("token: Bearer abc123xyz\nuser: bob", "Bearer abc123xyz"),
            ("--db-password=hunter2 --other", "hunter2 --other"),
            ("password=x\u{a0}y", "x\u{a0}y"),
            ("password=a\u{3000}b", "a\u{3000}b"),
            ("password=a\tb  \nnext: 1", "a\tb"),
            // Quoted: outer quotes stay when the value is one quoted line.
            ("password = 'hunter2'\nuser: bob", "hunter2"),
            ("password=\"hunter2\"", "hunter2"),
            ("password=\"hunter2\",\nuser=bob", "hunter2"),
            ("password: \"x\"\nuser: bob", "x"),
            // Quoted with text after it: the whole rest of the line.
            ("{\"password\": \"hunter2\"}", "\"hunter2\"}"),
            (
                "{\"password\": \"hunter2\", \"user\": \"ada\"}",
                "\"hunter2\", \"user\": \"ada\"}",
            ),
            ("password=\"\"hunter2", "\"\"hunter2"),
            ("password=\"a\"hunter2 more", "\"a\"hunter2 more"),
            ("Authorization: Basic dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"),
            // Escaped.
            (r#"{\"apiKey\":\"hunter2\"}"#, r#"\"hunter2\"}"#),
        ] {
            assert_eq!(found(text), [want], "{text:?}");
        }
    }

    #[test]
    fn over_redaction_stops_at_a_sibling_key() {
        assert_eq!(found("password: \"x\"\nuser: bob"), ["x"]);
        assert_eq!(found("password: [a, b]\nuser: bob"), ["[a, b]"]);
        assert_eq!(found("password: {\nv: 1\n}\nuser: bob"), ["{\nv: 1\n}"]);
        assert_eq!(found("password: \"a b\"\n\"user\": bob"), ["a b"]);
        assert_eq!(found("password: \"a b\"\nuser = bob"), ["a b"]);
        assert_eq!(found("  password: \"a b\"\n  user: bob\n  x: 1"), ["a b"]);
        assert_eq!(found("password:\n  a\nnext: 1\n  b"), ["  a"]);
        assert_eq!(found("passwords:\n- a\n- b\nnext: 1"), ["- a\n- b"]);
        assert_eq!(
            found("{\n  \"password\": \"a b\",\n  \"user\": \"bob\"\n}"),
            ["a b"]
        );
        // A deeper key does not end it, a comment does not either.
        assert_eq!(
            found("password: \"a b\"\n  deeper: 1\nuser: bob"),
            ["\"a b\"\n  deeper: 1"]
        );
        assert_eq!(found("password: \"a b\"\n# c\nuser: bob"), ["\"a b\"\n# c"]);
        // A line that is not a key does not end it.
        assert_eq!(
            found("password: \"a b\"\nplain text\nuser: bob"),
            ["\"a b\"\nplain text"]
        );
    }

    #[test]
    fn a_value_with_nothing_after_the_key_takes_the_lines_below() {
        assert_eq!(found("password:\n  hunter2\nnext: 1"), ["  hunter2"]);
        assert_eq!(
            found("password:   \r\n    a\r\n\r\n    b\r\nx: 1"),
            ["    a\r\n\r\n    b"]
        );
        assert_eq!(
            found("- secret:\n    key: hunter2\n  other: 1"),
            ["    key: hunter2\n  other: 1"]
        );
        assert_eq!(found("password:\n# old\n  hunter2"), ["# old\n  hunter2"]);
        assert_eq!(found("password:\n  a\n# c\nnext: 1"), ["  a\n# c"]);
        assert!(found("password:\nnext: 1").is_empty());
        assert!(found("password:").is_empty());
        assert!(found("password: \"\"\nnext: 1").is_empty());
        assert_eq!(found("password: \"\"\n  hunter2"), ["\"\"\n  hunter2"]);
    }

    #[test]
    fn a_comment_line_takes_only_its_own_value() {
        assert_eq!(found("# password: hunter2\n  x"), ["hunter2"]);
        assert_eq!(found("# password: \"a b\"\n  x"), ["a b"]);
        assert_eq!(found("  # token = abc\n    next"), ["abc"]);
    }

    /// Every leak found in review, one per shape. Each must be covered by a span.
    #[test]
    fn no_leak_from_any_review_round() {
        for (text, secret) in [
            // Round 1 and 2: spaces, glued quotes, references with literals.
            ("password: correct horse hunter2", "hunter2"),
            ("token: Bearer hunter2", "hunter2"),
            ("password=x\u{a0}hunter2", "hunter2"),
            ("password=\"\"hunter2", "hunter2"),
            ("password=\"a\"hunter2 tail", "hunter2"),
            ("password=${PG_PW:-hunter2}", "hunter2"),
            ("password=$(echo hunter2)", "hunter2"),
            ("password={{ .pw | default \"hunter2\" }}", "hunter2"),
            ("password=${A}hunter2", "hunter2"),
            ("password={{hunter2}}", "hunter2"),
            ("password={{ hunter2 }}", "hunter2"),
            ("password=/run/secrets/../hunter2", "hunter2"),
            ("Authorization: Basic hunter2", "hunter2"),
            ("authProfile: hunter2", "hunter2"),
            (r#"{\\\"password\\\":\\\"hunter2\\\"}"#, "hunter2"),
            (r#"password=\"pa\\\",hunter2\" x"#, "hunter2"),
            // Round 2 and 3: block scalars, tags, anchors, comments, line ends, indents.
            ("token: |\n  hunter2\n  more hunter2\nnext: 1", "hunter2"),
            ("- token: >-\n    hunter2\n", "hunter2"),
            ("password:\n  hunter2\nnext: 1", "hunter2"),
            ("secret:   \r\n    hunter2\r\nnext: 1", "hunter2"),
            ("token: | # note\n  hunter2", "hunter2"),
            ("token: !!binary |\n  hunter2", "hunter2"),
            ("token: &anchor |-\n  hunter2", "hunter2"),
            ("\"token\": |\n hunter2\n", "hunter2"),
            ("token: |\n\thunter2\nnext: 1", "hunter2"),
            ("password: # note\n  hunter2", "hunter2"),
            ("token: !!binary\n  hunter2", "hunter2"),
            ("password: &a\n  hunter2", "hunter2"),
            ("passwords:\n- hunter2", "hunter2"),
            ("db password:\n  hunter2", "hunter2"),
            ("x/token: |\n hunter2", "hunter2"),
            ("password:\r  hunter2", "hunter2"),
            ("    password:\n\thunter2", "hunter2"),
            ("\tpassword:\n    hunter2", "hunter2"),
            ("password=!hunter2", "hunter2"),
            ("password=#hunter2", "hunter2"),
            // Round 4: values over several lines.
            ("password: correct horse\n  battery hunter2", "hunter2"),
            ("password: \"hunter\n  2\"", "hunter"),
            ("password: 'hunter\n  2'", "hunter"),
            ("password: {\n  a: hunter2\n}", "hunter2"),
            ("password: [\n  hunter2\n]", "hunter2"),
            ("password: null\n  hunter2", "hunter2"),
            ("password:\n# old\n  hunter2", "hunter2"),
            ("{\"password\":\n\"hunter2\"}", "hunter2"),
            ("k:\n  y: 1\u{85}password:\n hunter2", "hunter2"),
            ("k:\n  y: 1\u{2028}password:\n hunter2", "hunter2"),
            ("k:\n  y: 1\u{2029}password:\n hunter2", "hunter2"),
            ("token: |\n  # hunter2", "hunter2"),
            // Round 5: same-column continuation.
            ("password: [a,\nhunter2]", "hunter2"),
            ("password: {\nv: hunter2}", "hunter2"),
            ("password: \"a\nhunter2\"", "hunter2"),
            ("{\n\"password\": [\n\"hunter2\"\n]\n}", "hunter2"),
            ("TOKEN=\"a\nhunter2\"", "hunter2"),
            ("TOKEN='a\nhunter2'", "hunter2"),
            ("password: [[a], {b: [\nhunter2]}]\nnext: 1", "hunter2"),
            ("password: [\"]\",\nhunter2]\nnext: 1", "hunter2"),
            ("password: \"a\\\"\nhunter2\"\nnext: 1", "hunter2"),
            ("password: 'it''s\nhunter2'\nnext: 1", "hunter2"),
            ("password: [a,\nhunter2\nnext: 1", "hunter2"),
            ("password: \"a\nb\"hunter2 x\nnext: 1", "hunter2"),
            ("password: [a,\nb]\n  hunter2\nnext: 1", "hunter2"),
            // Round 6: parsing quotes, escapes and brackets.
            ("password: 'a\\''\nhunter2'", "hunter2"),
            ("password: ['a\\'' ]\nhunter2']", "hunter2"),
            ("password: [a, # ]\nhunter2]", "hunter2"),
            ("password: !!str \"a\nhunter2\"", "hunter2"),
            ("password: &p [a,\nhunter2]", "hunter2"),
            ("password = \"\"\"\nhunter2\n\"\"\"", "hunter2"),
            ("{\n\"password\":\n[\n\"hunter2\"\n]\n}", "hunter2"),
            ("password: [a}\nhunter2]", "hunter2"),
            ("TOKEN=\\\"a\nhunter2\\\"", "hunter2"),
            // Round 7: an open quote, a base64 tail and a PEM header that looks like a key.
            ("password: \"a\nb: hunter2\"", "hunter2"),
            ("password: 'a\nb: hunter2'", "hunter2"),
            ("password: \"a\nb=hunter2\"", "hunter2"),
            (
                "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\nQUJD==\n-----END PRIVATE KEY-----\"\nNEXT=1",
                "MIIBVQIBADANBgkq",
            ),
            (
                "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\nQUJD==\n-----END PRIVATE KEY-----\"\nNEXT=1",
                "QUJD==",
            ),
            (
                "PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF\n\nMIIBVQIBADANBgkq\n-----END RSA PRIVATE KEY-----\"",
                "MIIBVQIBADANBgkq",
            ),
            (
                "PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF\n\nMIIBVQIBADANBgkq\n-----END RSA PRIVATE KEY-----\"",
                "DEK-Info",
            ),
            (
                "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nMIIBVQIBADANBgkq\n-----END RSA PRIVATE KEY-----",
                "MIIBVQIBADANBgkq",
            ),
            (
                "password: |\n  -----BEGIN PRIVATE KEY-----\n  MIIBVQIBADANBgkq\n  -----END PRIVATE KEY-----",
                "MIIBVQIBADANBgkq",
            ),
            (
                "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIIBVQ=\nAbCd=\nQUJD==\n",
                "AbCd=",
            ),
        ] {
            assert_covered(text, secret);
        }
    }

    #[test]
    fn a_pem_key_in_a_dotenv_file_is_covered_and_the_next_key_is_not() {
        let text = "A=1\nPRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\nQUJD==\n-----END PRIVATE KEY-----\"\nNEXT=1\nB=\"2\"";
        let spans = spans(text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        let taken = &text[spans[0].clone()];
        assert!(taken.starts_with("\"-----BEGIN"), "{taken:?}");
        assert!(taken.ends_with("-----END PRIVATE KEY-----\""), "{taken:?}");
        // The key after it is a key again once the block is closed.
        let text = "PRIVATE_KEY=-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\n-----END X-----\nNEXT=1\npassword: \"q r\"";
        assert_eq!(
            found(text),
            [
                "-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\n-----END X-----",
                "q r"
            ]
        );
    }

    #[test]
    fn base64_tails_and_quoted_assignments_are_not_keys() {
        for line in ["QUJD==", "AbCd=", "x=\"v\"", "x='v'", "x=", "x ==y"] {
            assert!(!starts_with_key_token(line), "{line:?}");
        }
        for line in [
            "name: v",
            "name=v",
            "name = v",
            "\"name\": v",
            "'name': v",
            "a.b-c:",
            "x= v",
        ] {
            assert!(starts_with_key_token(line), "{line:?}");
        }
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
            "password={{.Values.pw}}",
            "token: null",
            "secret: Required",
            "password:",
            "password: ''\nnext: 1",
            "passwordFile: /etc/pw",
            "tokenRef: x",
            "author: Ada",
            "authors: Ada",
            "AUTHOR: Ada",
            "authorProfile: Ada",
            "passedCount: 3",
            "password: /run/secrets/db",
            "password: /run/secrets/db.pass",
            "host: example.test",
            "password: ${DB}\nnext: 1",
            "password=[REDACTED:secret_by_key:1a2b3c4d]\nnext: 1",
        ] {
            assert!(found(text).is_empty(), "should not match: {text}");
        }
    }

    #[test]
    fn exemptions_apply_only_when_nothing_is_taken_below() {
        for (text, want) in [
            ("password: ${DB}\n  hunter2", "${DB}\n  hunter2"),
            ("password: null\n  hunter2", "null\n  hunter2"),
            ("password: true\n  hunter2", "true\n  hunter2"),
            (
                "password: [REDACTED:x:00000000]\n  hunter2",
                "[REDACTED:x:00000000]\n  hunter2",
            ),
        ] {
            assert_eq!(found(text), [want], "{text:?}");
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
    fn auth_words_are_matched_whole() {
        assert_eq!(found("authorization: Bearer x"), ["Bearer x"]);
        assert_eq!(found("authProfile: hunter2"), ["hunter2"]);
        assert_eq!(found("auth_profile: hunter2"), ["hunter2"]);
        assert_eq!(found("authorizationHeader: hunter2"), ["hunter2"]);
        assert_eq!(found("passedToken: hunter2"), ["hunter2"]);
    }

    #[test]
    fn multibyte_text_is_never_split() {
        assert_eq!(
            found("pässword=ünï password=pä\u{1F600}ss"),
            ["pä\u{1F600}ss"]
        );
        assert_eq!(found("password=\"é\\é\" x"), ["\"é\\é\" x"]);
        assert_eq!(found("password=\"é\""), ["é"]);
    }

    #[test]
    fn line_ends_are_lf_crlf_cr_nel_ls_and_ps() {
        for end in ["\n", "\r\n", "\r", "\u{85}", "\u{2028}", "\u{2029}"] {
            let text = format!("password: a{end}  b{end}next: 1");
            assert_eq!(found(&text), [format!("a{end}  b")], "{end:?}");
            let text = format!("password:{end}  hunter2{end}next: 1");
            assert_eq!(found(&text), ["  hunter2"], "{end:?}");
        }
    }

    /// Runs the rule on `text` and returns how many bytes it visited.
    fn visits(text: &str) -> usize {
        VISITS.with(|v| v.set(0));
        let _ = spans(text);
        VISITS.with(std::cell::Cell::get)
    }

    /// Every input here made some earlier version of the rule quadratic. The rule must visit a bounded
    /// number of bytes per input byte, whatever the shape. `n` is large enough that a quadratic rule
    /// would visit thousands of times the input.
    ///
    /// The counter covers the rule's own scans only. The time spent inside the `regex` crate
    /// (`captures_iter`) and in `is_secret_key` is not counted. The smoke test below times adversarial
    /// inputs for those.
    #[test]
    fn the_work_is_linear_in_the_input() {
        let n = 20_000;
        let inputs: Vec<(&str, String)> = vec![
            ("pass=", "pass=".repeat(n)),
            ("quoted keys", "password=\"a\" ".repeat(n)),
            (
                "placeholders",
                "[REDACTED:x:00000000] ".repeat(n) + "password=a",
            ),
            ("null", "password=null ".repeat(n)),
            (
                "keys then blank lines",
                "password=\"a\" ".repeat(n) + &"\n".repeat(4 * n),
            ),
            (
                "keys then comment lines",
                "password=\"a\" ".repeat(n) + &"# c\n".repeat(4 * n),
            ),
            (
                "keys then CRLF lines",
                "password=\"a\" ".repeat(n) + &"\r\n".repeat(4 * n),
            ),
            (
                "escaped keys then blank lines",
                "\"\\\"password\\\":\\\"\\\",".repeat(n) + &"\n".repeat(4 * n),
            ),
            (
                "huge indent",
                " ".repeat(8 * n) + &"password=\"a\" ".repeat(n / 4),
            ),
            (
                "huge indent then lines",
                " ".repeat(8 * n) + &"password=\"a\" ".repeat(n / 4) + &"\n".repeat(n),
            ),
            (
                "huge indent on many lines",
                (" ".repeat(200) + "password: a\n").repeat(n / 10),
            ),
            ("password:", "password:\n".repeat(n)),
            ("- token: |", "- token: |\n".repeat(n)),
            ("password: blank", "password:\n\n".repeat(n)),
            ("password: comment", "password:\n# password:\n".repeat(n)),
            ("password: body", "password:\n  a\n".repeat(n)),
            ("comment keys", "# password: x\n".repeat(n)),
            ("quoted lines", "password: \"a b\"\n".repeat(n)),
            (
                "quoted then sibling",
                "password: \"a b\"\nuser: x\n".repeat(n),
            ),
            ("simple then deeper", "password: a\n  b\n".repeat(n)),
            ("open quotes", "password=\"a\n".repeat(n)),
            ("open brackets", "password=[a\n".repeat(n)),
            ("deep brackets", "password=".to_owned() + &"[".repeat(n)),
            ("open then closed", "password: [a,\nb]\n".repeat(n)),
            ("backslashes", "password=\"".to_owned() + &"\\".repeat(n)),
            ("brackets then keys", "password: {\nv: 1\n".repeat(n)),
            ("deep keys", "a: 1\n  password: \"x y\"\n".repeat(n)),
            (
                "blank gaps",
                "password: \"x y\"\n\n\n\n\nuser: 1\n".repeat(n),
            ),
            ("open quote then keys", "password: \"a\nb: 1\n".repeat(n)),
            (
                "pem blocks",
                "PRIVATE_KEY=\"-----BEGIN K-----\nAAAA\nBB==\n-----END K-----\"\n".repeat(n),
            ),
            (
                "open pem",
                "PRIVATE_KEY=-----BEGIN K-----\nProc-Type: 4\n".repeat(n),
            ),
            ("base64 tails", "password: \"a b\"\nQUJD==\n".repeat(n)),
        ];
        for (name, text) in &inputs {
            let counted = visits(text);
            let limit = 8 * text.len() + 1000;
            assert!(
                counted <= limit,
                "{name}: {counted} bytes visited for {} bytes of input",
                text.len()
            );
        }
    }

    /// One wall-clock check with a generous bound, as a smoke test for the parts the counter cannot see:
    /// the `regex` crate's `captures_iter` and `is_secret_key`.
    #[test]
    fn a_large_hostile_input_finishes_in_reasonable_time() {
        let n = 5_000;
        let inputs = [
            "password=\"a\" ".repeat(n) + &"\n".repeat(4 * n),
            // Regex worst cases: long runs that almost match, and matches that start far back.
            "a".repeat(40 * n) + "=b ",
            "a=".repeat(20 * n),
            "=".repeat(40 * n),
            "a".repeat(20 * n) + &"\\".repeat(20 * n) + "\"=",
            "a\"=".repeat(20 * n),
            "-a".repeat(20 * n) + ":x",
            // A key with a stem and an excluded word at every position.
            "password".repeat(8 * n) + "=x",
            "author".repeat(8 * n) + "=x",
            "authorization".repeat(4 * n) + "=x",
            "passed_".repeat(8 * n) + "token=x",
            " ".repeat(40 * n) + "password=x",
        ];
        let started = std::time::Instant::now();
        for text in &inputs {
            let _ = spans(text);
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "took {:?}",
            started.elapsed()
        );
    }
}
