//! `os-release(5)`: the fields `host.os` uses, parsed defensively.
//!
//! The file is shell syntax in a small subset: `KEY=value` lines, a value that may sit in single or
//! double quotes, `#` comments. The parser takes the lines it understands and ignores the rest. A later
//! line for a key wins, as it would when the shell sources the file. It reads at most [`MAX_LINES`]
//! lines and keeps at most [`MAX_VALUE`] characters of a value, so a hostile file cannot grow the
//! result.

/// The most lines read.
const MAX_LINES: usize = 256;
/// The most characters kept of one value.
const MAX_VALUE: usize = 128;
/// The most `ID_LIKE` words kept.
const MAX_LIKE: usize = 8;

/// The fields of `os-release` that the check reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Release {
    /// `ID`, lower case. `linux` when the file has none (the default in `os-release(5)`).
    pub(crate) id: String,
    /// The words of `ID_LIKE`, lower case.
    pub(crate) id_like: Vec<String>,
    /// `VERSION_ID`. `None` for a rolling release that has none.
    pub(crate) version_id: Option<String>,
    /// `NAME`.
    pub(crate) name: Option<String>,
    /// `PRETTY_NAME`.
    pub(crate) pretty_name: Option<String>,
}

impl Release {
    /// What to call this OS in a sentence: `PRETTY_NAME`, else `NAME` and `VERSION_ID`, else `ID`.
    pub(crate) fn display(&self) -> String {
        if let Some(pretty) = &self.pretty_name {
            return pretty.clone();
        }
        match (&self.name, &self.version_id) {
            (Some(name), Some(version)) => format!("{name} {version}"),
            (Some(name), None) => name.clone(),
            (None, Some(version)) => format!("{} {version}", self.id),
            (None, None) => self.id.clone(),
        }
    }
}

/// Parses `text`. `None` when it holds none of the keys the check reads, so it is not an
/// `os-release` file at all.
pub(crate) fn parse(text: &str) -> Option<Release> {
    let mut id = None;
    let mut id_like = None;
    let mut version_id = None;
    let mut name = None;
    let mut pretty_name = None;
    for line in text.lines().take(MAX_LINES) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let slot = match key.trim() {
            "ID" => &mut id,
            "ID_LIKE" => &mut id_like,
            "VERSION_ID" => &mut version_id,
            "NAME" => &mut name,
            "PRETTY_NAME" => &mut pretty_name,
            _ => continue,
        };
        *slot = Some(value(raw));
    }
    if [&id, &id_like, &version_id, &name, &pretty_name]
        .iter()
        .all(|slot| slot.is_none())
    {
        return None;
    }
    let present = |slot: Option<String>| slot.filter(|v| !v.is_empty());
    Some(Release {
        id: present(id).map_or_else(|| "linux".to_owned(), |v| v.to_ascii_lowercase()),
        id_like: id_like
            .iter()
            .flat_map(|v| v.split_whitespace())
            .take(MAX_LIKE)
            .map(str::to_ascii_lowercase)
            .collect(),
        version_id: present(version_id),
        name: present(name),
        pretty_name: present(pretty_name),
    })
}

/// The value after `=`: unquoted, with the four escapes the shell keeps inside double quotes undone.
fn value(raw: &str) -> String {
    let raw = raw.trim();
    let quote = raw.chars().next().filter(|c| matches!(c, '"' | '\''));
    let inner = match quote {
        Some(q) => {
            let body = raw.get(q.len_utf8()..).unwrap_or_default();
            // Up to the closing quote. In double quotes a backslash escapes the next character.
            let mut end = body.len();
            let mut escaped = false;
            for (at, c) in body.char_indices() {
                if q == '"' && escaped {
                    escaped = false;
                } else if q == '"' && c == '\\' {
                    escaped = true;
                } else if c == q {
                    end = at;
                    break;
                }
            }
            body.get(..end).unwrap_or_default()
        }
        None => raw.split_whitespace().next().unwrap_or_default(),
    };
    let text = if quote == Some('"') {
        unescape(inner)
    } else {
        inner.to_owned()
    };
    text.chars().take(MAX_VALUE).collect()
}

/// `\"`, `\\`, `\$` and a backslash before a backtick lose the backslash. Other backslashes stay.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(next) = chars.peek().copied()
            && matches!(next, '"' | '\\' | '$' | '`')
        {
            out.push(next);
            chars.next();
        } else {
            out.push(c);
        }
    }
    out
}
