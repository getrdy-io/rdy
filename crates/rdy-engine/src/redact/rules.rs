//! The compiled-in rules (04 Appendix B).
//!
//! M1-048 ships the engine and the key-name rule, `secret_by_key`. M1-060 adds the other M1 rules and tunes
//! this one. The shape rules (private keys, key ids, JWTs, share tokens) are in `shapes`, the header rules
//! in `headers` and the URL rule in `url`. The rules that read `key: value` text (the key-name rule, the
//! AWS secret and session token keys, the kubeconfig keys and the space-separated flag form) are here,
//! because they share one reader for the value. A spec can add rules but never remove or weaken one, so
//! this table is a `static`.

use std::cell::OnceCell;
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

/// Rule priorities. Higher wins when spans merge (04 section 3.2), so it decides the name in the
/// placeholder.
///
/// The full order, highest first: PEM and Secret blocks, token shapes, headers, URL userinfo, specific
/// key names, key names, custom patterns, emails, IPs, entropy. The cut-buffer guard of a private key
/// uses [`PEM`] too.
pub(crate) mod priority {
    /// `pem_private_key`.
    pub const PEM: u8 = 90;
    /// `aws_access_key_id`, `rdy_share_token` and `jwt`.
    pub const TOKEN_SHAPES: u8 = 80;
    /// `auth_header` and `api_key_header`.
    pub const HEADERS: u8 = 70;
    /// `url_userinfo`.
    pub const URL: u8 = 65;
    /// `aws_secret_access_key`, `aws_session_token` and `kubeconfig_credential`: a key name that says
    /// more than the generic stems do.
    pub const SPECIFIC_KEYS: u8 = 62;
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

/// The built-in rule set for the Report ruleset (04 Appendix B, milestone 1).
pub(crate) static BUILT_IN: &[Rule] = &[
    Rule {
        name: super::shapes::PEM_PRIVATE_KEY,
        priority: priority::PEM,
        find: super::shapes::find_pem_private_key,
    },
    Rule {
        name: "aws_access_key_id",
        priority: priority::TOKEN_SHAPES,
        find: super::shapes::find_aws_access_key_id,
    },
    Rule {
        name: "rdy_share_token",
        priority: priority::TOKEN_SHAPES,
        find: super::shapes::find_rdy_share_token,
    },
    Rule {
        name: "jwt",
        priority: priority::TOKEN_SHAPES,
        find: super::shapes::find_jwt,
    },
    Rule {
        name: "auth_header",
        priority: priority::HEADERS,
        find: super::headers::find_auth_header,
    },
    Rule {
        name: "api_key_header",
        priority: priority::HEADERS,
        find: super::headers::find_api_key_header,
    },
    Rule {
        name: "url_userinfo",
        priority: priority::URL,
        find: super::url::find_url_userinfo,
    },
    Rule {
        name: "aws_secret_access_key",
        priority: priority::SPECIFIC_KEYS,
        find: find_aws_secret_access_key,
    },
    Rule {
        name: "aws_session_token",
        priority: priority::SPECIFIC_KEYS,
        find: find_aws_session_token,
    },
    Rule {
        name: "kubeconfig_credential",
        priority: priority::SPECIFIC_KEYS,
        find: find_kubeconfig_credential,
    },
    Rule {
        name: SECRET_BY_KEY,
        priority: priority::KEY_NAMES,
        find: find_secret_by_key,
    },
];

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
///
/// Three things may sit between the key and the separator, and after it, without hiding the key:
/// colour codes (`\x1b[0m`), blanks, and a tab that was written as the two characters backslash and `t`
/// (a `&str` field is written with `Debug`, so a tab inside it arrives that way).
static ASSIGNMENT: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| {
    Regex::new(
        r#"([A-Za-z0-9_\-][A-Za-z0-9_.\-]*)(?:\x1b\[[0-9;]*[A-Za-z])*(?:\\*["'])?(?:[ \t]|\\+t|\x1b\[[0-9;]*[A-Za-z])*[=:](?:[ \t]|\x1b\[[0-9;]*[A-Za-z])*"#,
    )
});

/// A flag with its value in the next word: `--password hunter2`. The regex finds the flag and the blanks
/// after it, and code reads the word. Only a flag that starts the text or follows a blank, a quote, a
/// bracket or a comma counts.
static FLAG: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"(?:^|[\s"'\[(,])(--?[A-Za-z][A-Za-z0-9_.\-]*)[ \t]+"#));

/// A colour code at the end of a value.
static TRAILING_ANSI: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"(?:\x1b\[[0-9;]*[A-Za-z])+$"));

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
    // `client-key-data`, the private key of a kubeconfig user. `certificate-authority-data` and
    // `client-certificate-data` are public and have no stem.
    "keydata",
];

/// Whole words that contain a stem but are not secrets, such as `passed: 12` and `author: Ada`.
/// A stem hit is ignored only when it is exactly one of these words, split on `-`, `_`, `.` and
/// camelCase, so `authorization` and `authProfile` still match. A word is excluded only where the stem
/// starts it (or `un` before it), so `bypass` is not here and stays a secret key (it fails closed).
const NOT_SECRET_WORDS: &[&str] = &[
    "passes",
    "passenger",
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
    "authored",
    // `Unauthorized: invalid token` is an HTTP status line.
    "unauthorized",
    "unauthorised",
    "unauthenticated",
    // `WWW-Authenticate` is the challenge a server sends, not a credential.
    "authenticate",
    "tokenizer",
    "tokenizers",
];

/// A key whose last word is one of these names a thing, not a secret: `secretName`, `tokenFile`, `keyRef`,
/// or says how a secret is given or what kind it is: `auth_method`, `tokenType`, `password_stdin`,
/// `api_key_env`. The value of such a key is a word, and a real secret under it is not what the key says.
const NAME_SUFFIXES: &[&str] = &[
    "name",
    "ref",
    "file",
    "path",
    "namespace",
    "method",
    "mode",
    "type",
    "kind",
    "scheme",
    "provider",
    "stdin",
    "env",
];

/// A key whose last word is one of these holds a number about a secret, not the secret: `token_ttl_ms`,
/// `password_len`, `api_key_count`. The report walk keeps a number directly under such a key, never a list
/// or object. `bytes` is not here: `private_key_bytes` is key material, not a size.
const UNIT_WORDS: &[&str] = &[
    "ms", "sec", "secs", "seconds", "ttl", "count", "size", "len", "length",
];

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

/// The key-name rule: any key that [`is_secret_key`] says names a secret, and a flag that does.
fn find_secret_by_key(text: &str, out: &mut Vec<Range<usize>>) {
    scan_assignments(text, is_secret_key, out);
    find_secret_flags(text, out);
}

/// `aws_secret_access_key`, `SecretAccessKey`: the value of a key with this name (04 Appendix B).
fn find_aws_secret_access_key(text: &str, out: &mut Vec<Range<usize>>) {
    scan_assignments(
        text,
        |key| is_secret_key(key) && normalize_key(key).0.contains("secretaccesskey"),
        out,
    );
}

/// `aws_session_token`, `SessionToken`, `x-amz-security-token`.
fn find_aws_session_token(text: &str, out: &mut Vec<Range<usize>>) {
    scan_assignments(
        text,
        |key| {
            is_secret_key(key) && {
                let norm = normalize_key(key).0;
                norm.contains("sessiontoken") || norm.contains("securitytoken")
            }
        },
        out,
    );
}

/// Keys that only a kubeconfig, or the OIDC settings in one, spells with hyphens.
const KUBECONFIG_HYPHEN_KEYS: &[&str] = &[
    "client-key-data",
    "client-key",
    "client-secret",
    "access-token",
    "refresh-token",
    "id-token",
];

/// Words that a kubeconfig holds and little else does. `token` and `password` are kubeconfig credentials
/// only in a text that has one of them.
const KUBECONFIG_MARKERS: &[&str] = &[
    "current-context",
    "certificate-authority",
    "client-certificate",
    "clusters:",
    "contexts:",
    "users:",
    "\"clusters\"",
    "\"contexts\"",
    "\"users\"",
    "kind: Config",
    "\"kind\": \"Config\"",
    "\"kind\":\"Config\"",
];

/// `token`, `client-key-data`, `password` and the like in a kubeconfig. Public certificates have no stem.
fn find_kubeconfig_credential(text: &str, out: &mut Vec<Range<usize>>) {
    let is_kubeconfig = OnceCell::new();
    scan_assignments(
        text,
        |key| {
            KUBECONFIG_HYPHEN_KEYS
                .iter()
                .any(|k| key.eq_ignore_ascii_case(k))
                || (["token", "password"]
                    .iter()
                    .any(|k| key.eq_ignore_ascii_case(k))
                    && *is_kubeconfig
                        .get_or_init(|| KUBECONFIG_MARKERS.iter().any(|m| text.contains(m))))
        },
        out,
    );
}

/// Runs the assignment reader over `text` and pushes the value of every key `accept` says yes to.
fn scan_assignments(text: &str, accept: impl Fn(&str) -> bool, out: &mut Vec<Range<usize>>) {
    // Every assignment has a separator. A byte scan is much cheaper than the regex on a large buffer
    // that has none, and the rules that read assignments run one after the other.
    if !text.bytes().any(|b| b == b'=' || b == b':') {
        return;
    }
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
        if !accept(key.as_str()) {
            continue;
        }
        let lines = lines.get_or_init(|| Lines::new(text));
        let (span, covered) = value_span(text, lines, key.start(), whole.end());
        covered_until = covered_until.max(covered);
        out.extend(span);
    }
}

/// True if `arg` is a flag that names a secret and has no `=`: `--password`, `-token`. Its value is the
/// next word (`--password hunter2`) or the next argument of a command line.
pub(crate) fn is_secret_flag(arg: &str) -> bool {
    arg.starts_with('-') && !arg.contains('=') && is_secret_key(arg.trim_start_matches('-'))
}

/// `--password hunter2`: a flag that names a secret, with its value in the next word. The word is the
/// value, so `--user bob` after it stays. A quoted word runs to its closing quote when that is plain.
fn find_secret_flags(text: &str, out: &mut Vec<Range<usize>>) {
    if !text.contains('-') {
        return;
    }
    let Ok(flag) = FLAG.as_ref() else {
        out.push(0..text.len());
        return;
    };
    let lines = OnceCell::new();
    // A flag inside a value already taken is skipped, which keeps the work linear.
    let mut covered_until = 0;
    let mut at = 0;
    while let Some(caps) = flag.captures_at(text, at) {
        let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else {
            break;
        };
        // Resume right after the flag name, so the blank that follows can open the next flag.
        at = name.end();
        if name.start() < covered_until || !is_secret_flag(name.as_str()) {
            continue;
        }
        let lines = lines.get_or_init(|| Lines::new(text));
        if let Some(range) = flag_value(text, lines, whole.end()) {
            covered_until = range.end;
            out.push(range);
        }
    }
}

/// The value after a flag: the word at `from`, or the quoted string there. `None` when the next word is
/// another long flag, starts with `=` or `:` (the assignment reader has it), or is a reference.
fn flag_value(text: &str, lines: &Lines, from: usize) -> Option<Range<usize>> {
    let line = text.get(from..lines.line_end(from).0.max(from))?;
    let first = line.chars().next()?;
    let is_long_flag = line
        .strip_prefix("--")
        .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_alphabetic()));
    if is_long_flag || matches!(first, '=' | ':') {
        return None;
    }
    let range = match first {
        '"' | '\'' => {
            let inner = &line[1..];
            let plain = inner.find(first).filter(|&close| {
                !inner[..close].contains('\\')
                    && inner[close + 1..]
                        .chars()
                        .next()
                        .is_none_or(char::is_whitespace)
            });
            match plain {
                Some(close) => from + 1..from + 1 + close,
                None => from..from + line.trim_end().len(),
            }
        }
        _ => {
            let word = line.split(char::is_whitespace).next().unwrap_or_default();
            from..from + word.len()
        }
    };
    let word = text.get(range.clone())?;
    (!word.is_empty() && !is_exempt_value(word) && !is_shell_variable(word)).then_some(range)
}

/// `$NAME`: a reference to a variable, not a value.
fn is_shell_variable(word: &str) -> bool {
    word.strip_prefix('$').is_some_and(|name| {
        let mut bytes = name.bytes();
        bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
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
    let commented = key_text.starts_with('#');
    // The key's own indent. A commented key sits after its `#` and the blanks behind it, so the lines
    // of a commented block are compared from there.
    let key_indent = if commented {
        comment_indent(key_line).map_or(Indent::Empty, |(indent, _)| indent)
    } else {
        Indent::of(&key_line[..key_line.len() - key_text.len()])
    };
    visit(key_line.len());

    let raw = &text[from..line_end];
    // A colour code after the value is not part of it: `password=\x1b[31mhunter2\x1b[0m`.
    let trimmed = raw.trim();
    let value = TRAILING_ANSI
        .as_ref()
        .ok()
        .and_then(|re| re.find(trimmed))
        .map_or(trimmed, |m| trimmed[..m.start()].trim_end());
    let value_start = from + (raw.len() - raw.trim_start().len());
    let value_end = value_start + value.len();
    let stripped = value.strip_suffix([',', ';']).unwrap_or(value);
    let is_simple = !stripped.is_empty() && stripped.bytes().all(is_simple_byte);
    // `password="[REDACTED:..]"` is what a first pass leaves, so the quoted placeholder is exempt too and
    // a second pass changes nothing.
    let quoted = match stripped.as_bytes() {
        [first, .., last] if first == last && matches!(first, b'"' | b'\'') => {
            Some(&stripped[1..stripped.len() - 1])
        }
        _ => None,
    };
    let is_exempt = !stripped.is_empty()
        && (is_exempt_value(stripped) || quoted.is_some_and(is_single_placeholder));
    visit(raw.len());

    // What to redact if nothing below the value is taken.
    let own = if is_simple {
        value_start..value_start + stripped.len()
    } else if quoted.is_some() {
        value_start + 1..value_start + stripped.len() - 1
    } else {
        value_start..value_end
    };

    let quote = value.bytes().next().filter(|b| matches!(b, b'"' | b'\''));
    let mut open = Open::default();
    open.add(value, quote);
    // A plain value that starts like a simple one and has spaces in it (`hunter2 --host db`) and opens
    // nothing is read like a simple one: it takes the deeper lines below it and nothing else.
    let plain = value.bytes().next().is_some_and(is_simple_byte) && !open.is_open();
    let simple = is_simple || is_exempt || plain;
    let mut first = None;
    let mut last_end = None;
    let mut pos = next_line;
    while let Some(start) = pos {
        let (end, next) = lines.line_end(start);
        visit(end - start + 1);
        let line = text[start..end].trim_end();
        if !line.is_empty() {
            // A commented key takes the lines below it that are comments too, and stops at the first
            // line that is not.
            let (indent, rest) = if commented {
                match comment_indent(line) {
                    Some(found) => found,
                    None => break,
                }
            } else {
                let rest = line.trim_start_matches([' ', '\t']);
                (Indent::of(&line[..line.len() - rest.len()]), rest)
            };
            let at_or_left = key_indent.is_at_or_left_of(&indent);
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

/// For a comment line (`  #   text`): the indent of its text, counting the `#` as a blank, and the text.
/// `None` if the line is not a comment.
fn comment_indent(line: &str) -> Option<(Indent, &str)> {
    let lead = line.len() - line.trim_start_matches([' ', '\t']).len();
    let after_hash = line.get(lead..)?.strip_prefix('#')?;
    let text = after_hash.trim_start_matches([' ', '\t']);
    let blanks = &line[..line.len() - text.len()];
    let tabs = blanks.bytes().filter(|&b| b == b'\t').count();
    // The `#` is a space, so the indent is never all tabs.
    let indent = if tabs == 0 {
        Indent::Spaces(blanks.len())
    } else {
        Indent::Mixed(blanks.len())
    };
    Some((indent, text))
}

/// True if `rest` is one quoted word and nothing else: it starts and ends with the same quote and has no
/// other quote of that kind in it. `"v"` is, `"a" "b"` and `"a\"` are not.
fn is_closed_quoted(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    match bytes {
        [first, .., last] if first == last && matches!(first, b'"' | b'\'') => {
            bytes.iter().filter(|&&b| b == *first).count() == 2
        }
        _ => false,
    }
}

/// True if the line text starts with a key: `name:`, `name=`, `"name":` or `'name':`, after any list
/// markers (`- name: v`). `name="v"` counts when the line is that one quoted assignment and nothing else,
/// so an `.env` file with every value quoted ends a secret at its next line.
fn starts_with_key_token(rest: &str) -> bool {
    let mut rest = rest;
    while let Some(after) = rest.strip_prefix("- ").or_else(|| rest.strip_prefix("-\t")) {
        rest = after.trim_start_matches([' ', '\t']);
    }
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
        Some(b'=') => match bytes.get(i + 1) {
            None | Some(b'=') => false,
            Some(b'"' | b'\'') => is_closed_quoted(&rest[i + 1..]),
            Some(_) => true,
        },
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
            // The word may start up to two bytes before the stem (`un` + `authorized`).
            let is_excluded_word = (0..=2).any(|back| {
                let Some(from) = at.checked_sub(back) else {
                    return false;
                };
                NOT_SECRET_WORDS.iter().any(|w| {
                    norm.get(from..).is_some_and(|rest| rest.starts_with(w))
                        && boundary[from]
                        && boundary.get(from + w.len()).copied().unwrap_or(true)
                })
            });
            !is_excluded_word
        })
    })
}

/// True if the last word of the key is a unit or a count (`ms`, `seconds`, `ttl`, `count`, `size`, `len`). Words split as in [`is_secret_key`].
pub(crate) fn last_word_is_unit(key: &str) -> bool {
    let (norm, boundary) = normalize_key(key);
    let start = boundary.iter().rposition(|&b| b).unwrap_or(0);
    norm.get(start..)
        .is_some_and(|word| UNIT_WORDS.contains(&word))
}

/// The key lowercased with `-`, `_` and `.` removed, and for each byte of it whether a word starts
/// there. Words split at the removed separators and at camelCase: `apiKey` is `api|key`, `APIKey` is
/// `api|key`. Keys can come from any JSON, so a multibyte character gets one entry per byte, with only the
/// first one set, and `boundary` always has the same length as the returned string.
fn normalize_key(key: &str) -> (String, Vec<bool>) {
    // A character that is not ASCII counts as a lowercase letter, so `ñPassed` is judged like `xPassed`.
    let is_lower = |c: char| c.is_ascii_lowercase() || !c.is_ascii();
    let mut norm = String::with_capacity(key.len());
    let mut boundary = Vec::with_capacity(key.len());
    let mut at_word_start = true;
    let mut prev: Option<char> = None;
    let mut chars = key.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '-' | '_' | '.') {
            at_word_start = true;
            prev = Some(c);
            continue;
        }
        let next = chars.peek().copied();
        let camel = c.is_ascii_uppercase()
            && prev.is_some_and(|p| {
                is_lower(p)
                    || p.is_ascii_digit()
                    || (p.is_ascii_uppercase() && next.is_some_and(is_lower))
            });
        boundary.push(at_word_start || camel);
        boundary.extend(std::iter::repeat_n(false, c.len_utf8() - 1));
        norm.push(c.to_ascii_lowercase());
        at_word_start = false;
        prev = Some(c);
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

    /// Keys with multibyte characters used to index the word boundaries by character, so they panicked
    /// (`ññññname`, `日本path`) or were judged on shifted boundaries.
    #[test]
    fn multibyte_keys_do_not_panic_and_keep_their_boundaries() {
        for key in [
            "ññññname",
            "日本path",
            "日本日本passed",
            "é",
            "日本",
            "ñ_ñ-ñ.ñ",
        ] {
            let (norm, boundary) = normalize_key(key);
            assert_eq!(norm.len(), boundary.len(), "{key}");
            let _ = is_secret_key(key);
            let _ = last_word_is_unit(key);
        }
        // A multibyte character is judged like one lowercase ASCII letter, in the word boundaries too.
        for (key, ascii) in [
            ("ññññname", "xxxxname"),
            ("日本path", "xxpath"),
            ("日本日本passed", "xxxxpassed"),
            ("ñPassed", "xPassed"),
            ("token日Path", "tokenxPath"),
            ("日Passed", "xPassed"),
            ("Ñ日Passed", "xxPassed"),
        ] {
            assert_eq!(is_secret_key(key), is_secret_key(ascii), "{key}");
        }
        assert!(!is_secret_key("ññññname"));
        assert!(!is_secret_key("日本path"));
        // `ñPassed` is the word `passed`, not a stem hit, exactly like `xPassed`.
        assert!(!is_secret_key("ñPassed"));
        assert!(!is_secret_key("xPassed"));
        assert!(!is_secret_key("token日Path"));
        // The boundary is still right after multibyte text: `日本` then a camelCase word.
        assert!(is_secret_key("日本Password"));
        assert!(is_secret_key("ñññ_password"));
        assert!(!is_secret_key("ñññ_tokenName"));
        assert!(is_secret_key("ññtoken"));
    }

    proptest::proptest! {
        #[test]
        fn is_secret_key_never_panics(key in proptest::prelude::any::<String>()) {
            let (norm, boundary) = normalize_key(&key);
            proptest::prop_assert_eq!(norm.len(), boundary.len());
            let _ = last_word_is_unit(&key);
            // Only the safe direction: if the key with every non-ASCII character read as `x` is a
            // secret, the key is one too. The other direction is not claimed, so a change that makes a
            // key more secret never fails here and a change that hides one does.
            let ascii: String = key.chars().map(|c| if c.is_ascii() { c } else { 'x' }).collect();
            proptest::prop_assert!(!is_secret_key(&ascii) || is_secret_key(&key));
        }

        #[test]
        fn is_secret_key_never_panics_on_mixed_text(
            key in "[a-zA-Z_.ñ日é-]{0,24}(name|path|passed|word|token|Key)?"
        ) {
            let _ = is_secret_key(&key);
            let _ = last_word_is_unit(&key);
        }
    }

    #[test]
    fn a_last_word_that_is_a_unit_or_a_count_is_found() {
        for key in [
            "token_ttl_ms",
            "tokenTtlMs",
            "password_len",
            "api-key-count",
            "secretSize",
            "ttl",
            "token_length",
            "passwordLength",
            "token_secs",
        ] {
            assert!(last_word_is_unit(key), "{key}");
        }
        for key in [
            "password",
            "db.password.bytes",
            "private_key_bytes",
            "msToken",
            "api_key",
            "secret_names",
            "",
        ] {
            assert!(!last_word_is_unit(key), "{key}");
        }
    }

    #[test]
    fn the_cut_marker_is_not_an_exempt_value() {
        // The report walk strips a trailing marker before the key rule. The rule itself knows no marker,
        // so a bare `[truncated]` is a value like any other and a line after it is still taken.
        assert!(!is_exempt_value("[truncated]"));
        assert!(!is_exempt_value("[truncated] hunter2"));
        assert_eq!(found("password= [truncated]"), ["[truncated]"]);
        assert_eq!(found("password: [truncated]"), ["[truncated]"]);
        assert_covered("password: [truncated]\nhunter2\nnext: ok", "hunter2");
        assert_eq!(
            found("password= [truncated] hunter2"),
            ["[truncated] hunter2"]
        );
    }

    #[test]
    fn a_quoted_single_placeholder_is_left_alone_and_nothing_longer_is() {
        let ph = "[REDACTED:secret_by_key:1a2b3c4d]";
        for text in [
            format!("password=\"{ph}\""),
            format!("password='{ph}'"),
            format!("\"password\":\"{ph}\","),
            // What a first pass leaves of an escaped JSON string: the whole value is one placeholder.
            format!("\\\"password\\\":{ph}"),
        ] {
            assert!(found(&text).is_empty(), "{text}");
        }
        // The real escaped form, with escaped quotes around the value. It is not a quoted pair, so the
        // rule takes the whole value, quotes and all: a first pass leaves a bare placeholder, never this.
        assert_eq!(found(r#"\"password\":\"hunter2\""#), [r#"\"hunter2\""#]);
        assert_eq!(
            found(&format!("\\\"password\\\":\\\"{ph}\\\"")),
            [format!("\\\"{ph}\\\"")]
        );
        assert_eq!(found(&format!("password=\"{ph}x\"")), [format!("{ph}x")]);
        assert_eq!(found(&format!("password=\"{ph}")), [format!("\"{ph}")]);
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
        for line in [
            "QUJD==",
            "AbCd=",
            "x=",
            "x ==y",
            // More than one quoted word, or an open quote, is value text and not a key.
            "x=\"a\" \"b\"",
            "x=\"a",
            "x='a\"",
        ] {
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
            // A line that is one quoted assignment is a key, so an all-quoted .env file ends a secret.
            "x=\"v\"",
            "x='v'",
            "- name: v",
            "-\tname=v",
            "- - name: v",
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

    /// What a rule other than the key-name rule finds.
    fn found_by(rule: fn(&str, &mut Vec<Range<usize>>), text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        rule(text, &mut out);
        out.into_iter().map(|r| &text[r]).collect()
    }

    #[test]
    fn colour_codes_around_a_key_and_its_value_do_not_hide_it() {
        let esc = "\u{1b}";
        for (text, want) in [
            (
                format!("{esc}[1mpassword{esc}[0m=hunter2{esc}[0m"),
                "hunter2",
            ),
            (
                format!("{esc}[31mpassword=hunter2{esc}[0m\nnext: 1"),
                "hunter2",
            ),
            (
                format!("password{esc}[0m: {esc}[32mhunter2{esc}[0m"),
                "hunter2",
            ),
            (
                format!("\"password\"{esc}[0m: \"hunter2\"{esc}[0m"),
                "hunter2",
            ),
        ] {
            assert_eq!(found(&text), [want], "{text:?}");
        }
    }

    #[test]
    fn a_tab_written_as_backslash_t_is_a_blank_before_the_separator() {
        assert_eq!(found(r"password\t= hunter2"), ["hunter2"]);
        assert_eq!(found(r"password\t\t: hunter2"), ["hunter2"]);
        assert_eq!(found(r#""password"\t: "hunter2""#), ["hunter2"]);
        // After the separator it is part of the value, so none of the value is left behind.
        assert_eq!(found(r"password=\thunter2"), [r"\thunter2"]);
        // A word that merely starts with t is not a blank.
        assert!(found(r"password\u: x").is_empty());
    }

    #[test]
    fn a_flag_with_a_secret_name_takes_the_next_word() {
        for (text, want) in [
            ("--password hunter2", vec!["hunter2"]),
            ("mysql --password hunter2 --host db", vec!["hunter2"]),
            ("mysql -password hunter2", vec!["hunter2"]),
            ("--api-key abc --token def", vec!["abc", "def"]),
            ("cmd --password 'one two' --x", vec!["one two"]),
            ("cmd --password \"one two\" --x", vec!["one two"]),
            // An escape or a quote that does not close plainly takes the rest of the line.
            ("cmd --password 'a\\' b' --x", vec!["'a\\' b' --x"]),
            ("cmd --password 'open --x", vec!["'open --x"]),
            ("cmd --password 'a'b --x", vec!["'a'b --x"]),
            ("[\"cmd\", \"--password\" x", vec![]),
            ("(--token  spaced)", vec!["spaced)"]),
            ("cmd --token one\n--token two", vec!["one", "two"]),
        ] {
            assert_eq!(found(text), want, "{text:?}");
        }
    }

    #[test]
    fn a_flag_that_is_not_followed_by_a_value_is_left_alone() {
        for text in [
            "--password",
            "--password\nhunter2",
            "--password --verbose",
            "--password=",
            "--password = x",
            "--password: x",
            "--password $DB_PASSWORD",
            "--password ${DB_PASSWORD}",
            "--password null",
            "--password-file /etc/pw",
            "--password-stdin",
            "--token-name x",
            "--auth-method basic",
            "--auth-provider gcp",
            "--verbose hunter2",
            "x--password hunter2",
            "--password [REDACTED:secret_by_key:1a2b3c4d]",
        ] {
            let got = found(text);
            // `--password = x` and `--password: x` are assignments, and the assignment reader has them.
            let flag_only: Vec<_> = got.iter().filter(|s| **s != "x").collect();
            assert!(flag_only.is_empty(), "{text:?}: {got:?}");
        }
    }

    #[test]
    fn is_secret_flag_is_the_argv_rule() {
        for arg in ["--password", "-token", "--api-key", "--client-secret"] {
            assert!(is_secret_flag(arg), "{arg}");
        }
        for arg in [
            "--password=x",
            "--password-file",
            "--verbose",
            "password",
            "-v",
            "",
        ] {
            assert!(!is_secret_flag(arg), "{arg}");
        }
    }

    #[test]
    fn words_that_say_how_a_secret_is_given_are_not_secret_keys() {
        for key in [
            "auth_method",
            "authMode",
            "auth-type",
            "tokenKind",
            "auth_scheme",
            "auth_provider",
            "password_stdin",
            "api_key_env",
            "WWW-Authenticate",
            "Unauthorized",
            "unauthenticated_requests",
        ] {
            assert!(!is_secret_key(key), "{key}");
        }
        for key in ["auth", "authorization", "authenticationToken", "password"] {
            assert!(is_secret_key(key), "{key}");
        }
    }

    fn aws_secret(text: &str) -> Vec<&str> {
        found_by(find_aws_secret_access_key, text)
    }

    fn aws_session(text: &str) -> Vec<&str> {
        found_by(find_aws_session_token, text)
    }

    fn kubeconfig(text: &str) -> Vec<&str> {
        found_by(find_kubeconfig_credential, text)
    }

    #[test]
    fn aws_secret_and_session_keys_are_found_by_name_in_every_syntax() {
        for text in [
            "AWS_SECRET_ACCESS_KEY=abc/def",
            "aws_secret_access_key = abc/def",
            "{\"SecretAccessKey\": \"abc/def\"}",
            "secretAccessKey: abc/def",
            "export AWS_SECRET_ACCESS_KEY=abc/def",
        ] {
            assert!(
                aws_secret(text).iter().any(|s| s.contains("abc/def")),
                "{text}: {:?}",
                aws_secret(text)
            );
            assert!(aws_session(text).is_empty(), "{text}");
        }
        for text in [
            "AWS_SESSION_TOKEN=abc",
            "SessionToken: abc",
            "x-amz-security-token: abc",
            "\"SessionToken\": \"abc\"",
        ] {
            assert!(
                aws_session(text).iter().any(|s| s.contains("abc")),
                "{text}: {:?}",
                aws_session(text)
            );
        }
        // Names of things, not secrets.
        assert!(aws_secret("secret_access_key_name: x").is_empty());
        assert!(aws_session("session_token_file: /x").is_empty());
        assert!(aws_secret("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE").is_empty());
    }

    #[test]
    fn kubeconfig_credentials_need_a_kubeconfig_for_the_plain_names() {
        let config = "apiVersion: v1\nkind: Config\nusers:\n- name: a\n  user:\n    token: abc\n    password: def\n    client-key-data: ghi\n    client-certificate-data: public\n";
        assert_eq!(kubeconfig(config), ["abc", "def", "ghi"]);
        // The hyphenated names are kubeconfig names wherever they are.
        assert_eq!(kubeconfig("client-key-data: ghi"), ["ghi"]);
        assert_eq!(
            kubeconfig("access-token: x\nrefresh-token: y\nid-token: z"),
            ["x", "y", "z"]
        );
        assert_eq!(kubeconfig("client-secret: s"), ["s"]);
        // A plain `token` outside a kubeconfig is the key-name rule's.
        assert!(kubeconfig("token: abc").is_empty());
        assert!(kubeconfig("DB_PASSWORD=abc").is_empty());
        assert_eq!(
            kubeconfig("{\"users\":[{\"user\":{\"token\":\"abc\"}}]}"),
            ["\"abc\"}}]}"]
        );
    }

    #[test]
    fn the_client_key_stem_does_not_catch_public_data() {
        assert!(is_secret_key("client-key-data"));
        assert!(!is_secret_key("client-certificate-data"));
        assert!(!is_secret_key("certificate-authority-data"));
    }

    #[test]
    fn a_commented_block_goes_to_its_last_comment_line() {
        assert_eq!(
            found("# token: |\n#   hunter2\n#   more\nkeep: 1"),
            ["|\n#   hunter2\n#   more"]
        );
        assert_eq!(
            found("  # password: a\n  #   b\n  # c: 1\nnext"),
            ["a\n  #   b"]
        );
        // A comment alone, or a comment followed by code, takes its own value only.
        assert_eq!(found("# password: hunter2\nplain"), ["hunter2"]);
        assert_eq!(found("# password: hunter2\n#"), ["hunter2"]);
        // A commented block that ends at a comment at the key's own column.
        assert_eq!(found("# password: |\n#   a\n# other: 1\n"), ["|\n#   a"]);
    }

    #[test]
    fn a_list_item_ends_a_secret_like_a_sibling_key() {
        assert_eq!(
            found("- password: |\n    hunter2\n- name: b"),
            ["|\n    hunter2"]
        );
        assert_eq!(found("items:\n  - password: \"a b\"\n  - name: b"), ["a b"]);
        assert_eq!(
            found("- - password: {\n  v: 1\n  }\n- name: b"),
            ["{\n  v: 1\n  }"]
        );
    }

    #[test]
    fn a_quoted_assignment_line_is_a_key_so_an_env_file_ends_a_secret_per_line() {
        assert_eq!(found("A=\"1\"\nPASSWORD=\"x y\"\nB=\"2\"\nC=3"), ["x y"]);
        assert_eq!(found("A='1'\nTOKEN='x'\nB='2'"), ["x"]);
        // Two quoted words on the next line is not one assignment, so it stays in the value.
        assert_eq!(
            found("PASSWORD=\"a\"b\nB=\"1\" \"2\"\nC=3"),
            ["\"a\"b\nB=\"1\" \"2\""]
        );
    }

    #[test]
    fn a_plain_value_with_spaces_takes_only_the_deeper_lines_below() {
        assert_eq!(
            found("mysql --password=hunter2 --host db\nnext line"),
            ["hunter2 --host db"]
        );
        assert_eq!(found("password: a b\n  c d\ne f"), ["a b\n  c d"]);
        assert_eq!(found("password=hunter2 failed\n"), ["hunter2 failed"]);
        // A value that opens a bracket is still read to the next key.
        assert_eq!(
            found("password=a [b\nplain\nuser: x"),
            ["a [b\nplain\nuser: x"]
        );
    }

    #[test]
    fn units_include_length_and_seconds() {
        for key in ["password_length", "tokenSecs", "token_sec", "secret_ttl"] {
            assert!(last_word_is_unit(key), "{key}");
        }
    }

    #[test]
    fn the_new_readers_cost_linear_time() {
        let n = 20_000;
        let inputs: Vec<(&str, String)> = vec![
            ("flags", "--password --password ".repeat(n)),
            ("flags with values", "--password a ".repeat(n)),
            ("commented keys", "# password: |\n#   a\n".repeat(n)),
            ("list items", "- password: |\n    a\n".repeat(n)),
            ("env", "A=\"1\"\nPASSWORD=\"x\"\n".repeat(n)),
            ("ansi", "\u{1b}[1mpassword\u{1b}[0m=a\u{1b}[0m\n".repeat(n)),
            ("tabs", "password\\t=a\n".repeat(n)),
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
