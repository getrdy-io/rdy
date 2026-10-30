//! Parsers for the AppArmor files `host.lsm` reads. Pure functions of text.

use std::collections::BTreeSet;

/// `/sys/module/apparmor/parameters/enabled`: `Y` or `N`.
pub(super) fn parse_enabled(text: &str) -> Option<bool> {
    match text.trim() {
        "Y" | "y" => Some(true),
        "N" | "n" => Some(false),
        _ => None,
    }
}

/// The most profile names kept from the list.
const MAX_PROFILES: usize = 4096;

/// The loaded profiles, from `/sys/kernel/security/apparmor/profiles`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Profiles {
    /// Every profile name, whatever its mode.
    pub names: BTreeSet<String>,
    /// How many of them are in enforce mode.
    pub enforce: usize,
    /// How many are in complain mode.
    pub complain: usize,
    /// `true` when the list was longer than [`MAX_PROFILES`].
    pub cut: bool,
}

/// Reads lines such as `docker-default (enforce)`. The mode is the last word, in parentheses, so a
/// name that holds a space still reads. A line in another form is skipped.
pub(super) fn parse_profiles(text: &str) -> Profiles {
    let mut out = Profiles::default();
    for line in text.lines() {
        let Some((name, mode)) = line.trim_end().rsplit_once(" (") else {
            continue;
        };
        let Some(mode) = mode.strip_suffix(')') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        match mode {
            "enforce" => out.enforce += 1,
            "complain" => out.complain += 1,
            _ => {}
        }
        if out.names.len() >= MAX_PROFILES {
            out.cut = true;
            continue;
        }
        out.names.insert(name.to_owned());
    }
    out
}
