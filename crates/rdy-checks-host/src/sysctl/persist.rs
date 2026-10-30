//! Which kernel parameters a machine sets at boot, from `sysctl.d` and `/etc/sysctl.conf`.
//!
//! The files are read in the order `systemd-sysctl` and `sysctl --system` apply them (see `layers`),
//! then `/etc/sysctl.conf` last. Only the keys the spec asks about, and wildcard keys, are kept.
//!
//! A line is `key = value`. Blank lines and lines whose first character is `#` or `;` are ignored. A
//! leading `-` on a line is the "ignore errors" mark and does not change the value. A line `-key` with
//! no `=` takes that key out of wildcard matches. The key may use dots or slashes: the first separator
//! decides, and a leading dot swaps the two (`net.ipv4.conf.eth0/100.rp_filter` is
//! `net/ipv4/conf/eth0.100/rp_filter`). Every key is held in the slash form, as `SysctlName::canonical`
//! writes it.

use std::collections::{BTreeMap, BTreeSet};

use rdy_engine::check::{CheckContext, CheckError};

use super::layers::{Layers, read_layers};
use super::value::normalise;

/// The directories, highest priority first. `/lib/sysctl.d` is the same directory as
/// `/usr/lib/sysctl.d` on most systems, and the layers drop a file that shows up twice with one text.
pub(super) const DIRS: [&str; 5] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
];
/// The compatibility file, applied after every file in the directories.
pub(super) const SYSCTL_CONF: &str = "/etc/sysctl.conf";

/// The most wildcard lines kept.
const MAX_GLOBS: usize = 256;
/// The longest key or value kept, in bytes.
const MAX_FIELD: usize = 512;

/// One setting that a file makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Setting {
    /// The value, with white space runs made one space.
    pub value: String,
    /// The file that sets it.
    pub file: String,
}

/// One line of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Line {
    /// `key = value`.
    Set { key: String, value: String },
    /// `-key`: leave this key out of wildcard matches.
    Exclude { key: String },
}

/// `net.ipv4.conf.eth0/100.rp_filter` and `net/ipv4/conf/eth0.100/rp_filter` are one key. The first
/// separator decides: a slash keeps the text, a dot swaps dots and slashes.
pub(super) fn canonical_key(key: &str) -> String {
    match key.find(['.', '/']) {
        Some(at) if key.as_bytes().get(at) == Some(&b'/') => key.to_owned(),
        Some(_) => key
            .chars()
            .map(|c| match c {
                '.' => '/',
                '/' => '.',
                other => other,
            })
            .collect(),
        None => key.to_owned(),
    }
}

/// Reads one line, or `None` for a blank line, a comment or a line that means nothing.
pub(super) fn parse_line(raw: &str) -> Option<Line> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let (marked, line) = line
        .strip_prefix('-')
        .map_or((false, line), |rest| (true, rest.trim_start()));
    match line.split_once('=') {
        Some((key, value)) => {
            let key = key.trim();
            if key.is_empty() || key.len() > MAX_FIELD {
                return None;
            }
            let value = normalise(value);
            if value.len() > MAX_FIELD {
                return None;
            }
            Some(Line::Set {
                key: canonical_key(key),
                value,
            })
        }
        None if marked && !line.is_empty() && line.len() <= MAX_FIELD => Some(Line::Exclude {
            key: canonical_key(line.trim()),
        }),
        None => None,
    }
}

/// Whether `key` has a wildcard in it.
fn is_glob(key: &str) -> bool {
    key.contains(['*', '?', '['])
}

/// Whether one path part matches one pattern part. `*` is any run of characters and `?` one. A part
/// with `[` never matches: rdy does not read character classes, and the result says so.
fn part_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(&c) if c != b'[' && Some(&c) == text.get(t) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

/// Whether the slash-form `pattern` matches the slash-form `key`. A wildcard stays inside one part.
pub(super) fn glob_matches(pattern: &str, key: &str) -> bool {
    let (mut pat, mut path) = (pattern.split('/'), key.split('/'));
    loop {
        match (pat.next(), path.next()) {
            (None, None) => return true,
            (Some(p), Some(k)) if part_matches(p.as_bytes(), k.as_bytes()) => {}
            _ => return false,
        }
    }
}

/// The settings the files make for the keys that were asked about.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Settings {
    wanted: BTreeSet<String>,
    explicit: BTreeMap<String, Setting>,
    globs: Vec<(String, Setting)>,
    excluded: BTreeSet<String>,
    /// Wildcard lines that were left out because the list was full or the pattern has a `[`.
    pub skipped_globs: usize,
}

impl Settings {
    /// An empty set that keeps only `wanted` keys (slash form) and wildcard lines.
    pub(super) fn new(wanted: BTreeSet<String>) -> Self {
        Self {
            wanted,
            ..Self::default()
        }
    }

    /// Applies the text of one file. A later setting replaces an earlier one.
    pub(super) fn ingest(&mut self, file: &str, text: &str) {
        for raw in text.lines() {
            match parse_line(raw) {
                Some(Line::Set { key, value }) if is_glob(&key) => {
                    if key.contains('[') || self.globs.len() >= MAX_GLOBS {
                        self.skipped_globs += 1;
                    } else {
                        self.globs.push((
                            key,
                            Setting {
                                value,
                                file: file.to_owned(),
                            },
                        ));
                    }
                }
                Some(Line::Set { key, value }) if self.wanted.contains(&key) => {
                    self.explicit.insert(
                        key,
                        Setting {
                            value,
                            file: file.to_owned(),
                        },
                    );
                }
                Some(Line::Exclude { key }) if self.wanted.contains(&key) => {
                    self.excluded.insert(key);
                }
                _ => {}
            }
        }
    }

    /// What the files set for `key`: its own line, else the last wildcard line that matches it and
    /// does not leave it out.
    pub(super) fn get(&self, key: &str) -> Option<&Setting> {
        self.explicit.get(key).or_else(|| {
            if self.excluded.contains(key) {
                return None;
            }
            self.globs
                .iter()
                .rev()
                .find(|(pattern, _)| glob_matches(pattern, key))
                .map(|(_, setting)| setting)
        })
    }
}

/// A setting that a file makes and a same-named file in a higher directory takes away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Hidden {
    /// What the hidden file sets.
    pub setting: Setting,
    /// The file that hides it.
    pub by: String,
}

/// What the machine sets at boot for the asked-about keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Persisted {
    /// The settings that apply.
    pub settings: Settings,
    /// What a hidden file would have set, by key.
    pub hidden: BTreeMap<String, Hidden>,
    /// The paths that are links to `/dev/null`.
    pub null_masks: Vec<String>,
    /// How many files apply.
    pub applied: usize,
    /// Why the answer may be incomplete. Empty when everything was read.
    pub unknown: Vec<String>,
}

/// Builds the answer from files already read.
pub(super) fn from_layers(layers: &Layers, wanted: &BTreeSet<String>) -> Persisted {
    let mut settings = Settings::new(wanted.clone());
    for file in &layers.files {
        settings.ingest(&file.path, &file.text);
    }
    let mut hidden = BTreeMap::new();
    for file in &layers.hidden {
        let mut one = Settings::new(wanted.clone());
        one.ingest(&file.path, &file.text);
        for key in wanted {
            if let Some(setting) = one.get(key) {
                hidden.insert(
                    key.clone(),
                    Hidden {
                        setting: setting.clone(),
                        by: file.by.clone(),
                    },
                );
            }
        }
    }
    Persisted {
        settings,
        hidden,
        null_masks: layers.null_masks.clone(),
        applied: layers.files.len(),
        unknown: layers.unknown.clone(),
    }
}

/// Reads the boot-time settings for `wanted` keys (slash form).
///
/// # Errors
///
/// [`CheckError`] only for a refusal by rdy's own policy.
pub(super) async fn gather(
    ctx: &CheckContext,
    wanted: &BTreeSet<String>,
) -> Result<Persisted, CheckError> {
    let layers = read_layers(ctx, &DIRS, ".conf", &[SYSCTL_CONF], true).await?;
    Ok(from_layers(&layers, wanted))
}
