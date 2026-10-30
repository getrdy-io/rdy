//! Reads the AVC denials out of the tail of `audit.log`. Pure functions of text.
//!
//! The audit log holds far more than denials: commands with their arguments, user names, file names.
//! None of that is kept. A denial line gives only the fields below, and each one must pass a strict
//! character test before it can reach the report.

use std::collections::BTreeMap;

/// The most distinct (source, target, class) groups kept. Denials past this are still counted.
const MAX_GROUPS: usize = 64;

/// The longest context, type or class name kept.
const MAX_NAME: usize = 128;

/// The longest program name kept. The kernel cuts `comm` at 15 bytes.
const MAX_COMM: usize = 32;

/// One kind of denial: who was denied, on what, and how many times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Group {
    /// The type of the source context, such as `container_t`.
    pub source: String,
    /// The type of the target context.
    pub target: String,
    /// The object class, such as `file`.
    pub class: String,
    pub count: usize,
}

/// What the tail of the log said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Scan {
    /// Denials at or after the window start.
    pub total: usize,
    /// How many of them were logged in permissive mode, which means they were not blocked.
    pub permissive: usize,
    /// Denial groups, most frequent first, at most [`MAX_GROUPS`].
    pub groups: Vec<Group>,
    /// For each `watch` entry that matched, the number of denials it matched.
    pub watched: BTreeMap<String, usize>,
    /// Denials with at least one watch match.
    pub watched_total: usize,
    /// The time stamp of the oldest record in the text, any type.
    pub oldest: Option<u64>,
}

/// Counts the denials with a time stamp at or after `cutoff` (Unix seconds).
///
/// A `watch` entry matches a denial when it equals the source type, the target type, the whole source
/// context, the whole target context or the program name.
pub(super) fn scan(text: &str, cutoff: u64, watch: &[String]) -> Scan {
    let mut out = Scan::default();
    let mut groups: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for line in text.lines() {
        let Some(stamp) = stamp(line) else {
            continue;
        };
        out.oldest = Some(out.oldest.map_or(stamp, |old| old.min(stamp)));
        if stamp < cutoff || !is_denial(line) {
            continue;
        }
        out.total += 1;
        let scontext = field(line, "scontext=").filter(|v| context_ok(v));
        let tcontext = field(line, "tcontext=").filter(|v| context_ok(v));
        let class = field(line, "tclass=").filter(|v| name_ok(v));
        let comm = quoted(line, "comm=").filter(|v| comm_ok(v));
        if field(line, "permissive=") == Some("1") {
            out.permissive += 1;
        }
        let source = scontext.and_then(context_type);
        let target = tcontext.and_then(context_type);

        let mut matched = false;
        for entry in watch {
            let hit = [source, target, scontext, tcontext, comm]
                .into_iter()
                .flatten()
                .any(|c| c == entry);
            if hit {
                *out.watched.entry(entry.clone()).or_insert(0) += 1;
                matched = true;
            }
        }
        if matched {
            out.watched_total += 1;
        }

        let key = (
            source.unwrap_or("unknown").to_owned(),
            target.unwrap_or("unknown").to_owned(),
            class.unwrap_or("unknown").to_owned(),
        );
        if let Some(count) = groups.get_mut(&key) {
            *count += 1;
        } else if groups.len() < MAX_GROUPS {
            groups.insert(key, 1);
        }
    }
    let mut groups: Vec<Group> = groups
        .into_iter()
        .map(|((source, target, class), count)| Group {
            source,
            target,
            class,
            count,
        })
        .collect();
    // A stable sort keeps the key order among equal counts, so the evidence does not depend on the file.
    groups.sort_by_key(|g| std::cmp::Reverse(g.count));
    out.groups = groups;
    out
}

/// The time stamp of a record: the seconds in `msg=audit(1730000000.123:456)`.
pub(super) fn stamp(line: &str) -> Option<u64> {
    let rest = line.split_once("msg=audit(")?.1;
    let seconds = rest.split(['.', ':', ')']).next()?;
    if seconds.is_empty() || seconds.len() > 12 || !seconds.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    seconds.parse().ok()
}

/// An SELinux denial record. The numeric record type 1400 is the same as `AVC`. A log kept with
/// `name_format` starts each line with `node=`, so the type is found as a word, not at the start.
fn is_denial(line: &str) -> bool {
    matches!(field(line, "type="), Some("AVC" | "1400"))
        && line.contains("avc:")
        && line.contains(" denied ")
}

/// What follows `key` where `key` starts a word.
fn after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(offset) = line.get(from..)?.find(key) {
        let at = from + offset;
        let starts_word = at == 0 || line.as_bytes().get(at - 1) == Some(&b' ');
        if starts_word {
            return line.get(at + key.len()..);
        }
        from = at + key.len();
    }
    None
}

/// The value of `key=` up to the next space.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    after(line, key)?.split(' ').next()
}

/// The value of `key="..."`, without the quotes. A value the audit system wrote in hex is not quoted
/// and gives `None`.
fn quoted<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = after(line, key)?.strip_prefix('"')?;
    rest.split_once('"').map(|(value, _)| value)
}

/// The type of a context `user:role:type:level`.
fn context_type(context: &str) -> Option<&str> {
    context.split(':').nth(2).filter(|t| !t.is_empty())
}

fn name_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn context_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b',' | b'*')
        })
}

fn comm_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_COMM
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+'))
}
