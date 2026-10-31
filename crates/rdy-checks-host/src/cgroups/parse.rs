//! Parsers for the two kernel files `host.cgroups` reads besides the cgroup helper: `/proc/cgroups`
//! and `/proc/cmdline`. Both are defensive: a line that does not fit is skipped, and the output is
//! bounded however large the input is.

/// The most lines of `/proc/cgroups` read.
const MAX_LINES: usize = 128;
/// The most words of `/proc/cmdline` read.
const MAX_WORDS: usize = 512;
/// The most cgroup-related words kept.
const MAX_KEPT: usize = 16;
/// The longest kept word, in characters.
const MAX_WORD: usize = 96;

/// The start of every kernel command line word that bears on cgroups. Nothing else is kept, so an
/// `ip=` or `root=` word with a secret in it never reaches the report.
const CGROUP_WORDS: &[&str] = &[
    "cgroup_disable=",
    "cgroup_enable=",
    "cgroup_memory=",
    "cgroup_no_v1=",
    "cgroup.memory=",
    "systemd.unified_cgroup_hierarchy=",
    "systemd.legacy_systemd_cgroup_controller=",
    "SYSTEMD_CGROUP_ENABLE_LEGACY_FORCE=",
];

/// One row of `/proc/cgroups`: a controller the kernel was built with (v1 names, so `blkio` for what v2
/// calls `io`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcController {
    pub name: String,
    /// The v1 hierarchy it is attached to. `0` means none: it is off, or it belongs to v2.
    pub hierarchy: u32,
    /// The `enabled` column. `false` after `cgroup_disable=` or when the OS turns it off by default.
    pub enabled: bool,
}

/// Parses `/proc/cgroups`. The header line starts with `#`.
pub(super) fn parse_proc_cgroups(text: &str) -> Vec<ProcController> {
    text.lines()
        .take(MAX_LINES)
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let name = words.next()?;
            let hierarchy = words.next()?.parse::<u32>().ok()?;
            let _num_cgroups = words.next()?.parse::<u64>().ok()?;
            let enabled = match words.next()? {
                "1" => true,
                "0" => false,
                _ => return None,
            };
            let plain = name.len() <= 32
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            plain.then(|| ProcController {
                name: name.to_owned(),
                hierarchy,
                enabled,
            })
        })
        .collect()
}

/// The cgroup-related words of `/proc/cmdline`, in order. A word with a character outside
/// `a-z A-Z 0-9 _ . , = : -`, or one longer than 96 characters, is dropped.
pub(super) fn parse_cmdline(text: &str) -> Vec<String> {
    text.split_whitespace()
        .take(MAX_WORDS)
        .filter(|word| CGROUP_WORDS.iter().any(|start| word.starts_with(start)))
        .filter(|word| {
            word.chars().count() <= MAX_WORD
                && word.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ',' | '=' | ':' | '-')
                })
        })
        .take(MAX_KEPT)
        .map(str::to_owned)
        .collect()
}

/// The `cgroup_disable=` word that turns off `controller` (its v1 or v2 name), as it stands on the
/// command line.
pub(super) fn disabling_word<'a>(words: &'a [String], names: [&str; 2]) -> Option<&'a str> {
    words
        .iter()
        .find(|word| {
            word.strip_prefix("cgroup_disable=")
                .is_some_and(|list| list.split(',').any(|name| names.contains(&name)))
        })
        .map(String::as_str)
}

/// The value of the word that starts with `start` (such as `systemd.unified_cgroup_hierarchy=`).
/// The last one wins, as it does for the kernel command line.
pub(super) fn word_value<'a>(words: &'a [String], start: &str) -> Option<&'a str> {
    words.iter().rev().find_map(|word| word.strip_prefix(start))
}
