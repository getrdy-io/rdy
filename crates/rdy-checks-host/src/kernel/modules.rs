//! Finding module names in the three files that list them, without keeping more than the spec asked for.
//!
//! - `/proc/modules`: one loaded module per line, the name first.
//! - `modules.builtin`: one built-in module per line, as a path such as `kernel/fs/overlayfs/overlay.ko`.
//! - `modules.dep`: one installed module per line, as `path/name.ko.xz: dependency paths`. Only the part
//!   before the colon names a module. A name in the dependency list is not a line of its own.
//!
//! A module name matches with `-` and `_` equal (the kernel treats them the same) and with its case kept
//! (`xt_TCPMSS` and `xt_tcpmss` are two modules). A path matches with any of `.ko`, `.ko.xz`, `.ko.zst`
//! or `.ko.gz`, because distributions compress modules differently. Each scan takes the set of names the
//! spec wants and reports which of them it saw, so what the check keeps is bounded by the spec.

use std::collections::BTreeSet;

use rdy_engine::probe::{FileBytes, MAX_READ};

/// The most lines one scan reads. `modules.dep` has one line per installed module, a few thousand.
const MAX_LINES: usize = 200_000;

/// The endings of a module file, longest first.
const SUFFIXES: [&str; 4] = [".ko.zst", ".ko.xz", ".ko.gz", ".ko"];

/// A file that `head` and `tail` together may not cover. Lines can be long (a module with many
/// dependencies), so the covered size is kept this far below the two reads.
const SLACK: u64 = 64 * 1024;

/// A module name the way the kernel compares it: `-` is `_`.
pub(super) fn normalize(name: &str) -> String {
    name.replace('-', "_")
}

/// The module a file path names: its last component without the module ending, normalized. `None` when
/// the path does not end like a module file.
pub(super) fn name_of_path(path: &str) -> Option<String> {
    let file = path.rsplit('/').next()?;
    SUFFIXES
        .iter()
        .find_map(|suffix| file.strip_suffix(suffix))
        .filter(|stem| !stem.is_empty())
        .map(normalize)
}

/// Which of `wanted` the text of `/proc/modules` lists.
pub(super) fn scan_loaded(text: &str, wanted: &BTreeSet<String>) -> BTreeSet<String> {
    text.lines()
        .take(MAX_LINES)
        .filter_map(|line| line.split_whitespace().next())
        .map(normalize)
        .filter(|name| wanted.contains(name))
        .collect()
}

/// Which of `wanted` the text of `modules.builtin` or `modules.dep` names. Only the part of a line
/// before a colon counts.
pub(super) fn scan_paths(text: &str, wanted: &BTreeSet<String>) -> BTreeSet<String> {
    text.lines()
        .take(MAX_LINES)
        .filter_map(|line| line.split(':').next())
        .filter_map(|path| name_of_path(path.trim()))
        .filter(|name| wanted.contains(name))
        .collect()
}

/// What was found in `modules.dep`, and whether the scan covered the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Dep {
    /// The wanted names the file lists.
    pub(super) found: BTreeSet<String>,
    /// `false` when part of the file was not read, so a name that is not in `found` may still be in it.
    pub(super) complete: bool,
}

/// Reads `modules.dep` from its first read `head` and, when the file was longer than one read, from
/// `tail` (its last bytes) and `len` (its size).
///
/// A read is cut at [`MAX_READ`]. A cut can leave half a line at the end of `head` or at the start of
/// `tail`, and that half is dropped, so it can never name a module that is not in the file. The scan
/// is complete when the file fits in the two reads with room for a long line between them.
pub(super) fn scan_dep(
    head: &FileBytes,
    tail: Option<&FileBytes>,
    len: Option<u64>,
    wanted: &BTreeSet<String>,
) -> Dep {
    let mut found = scan_paths(&whole_lines(head), wanted);
    if !head.truncated_tail {
        return Dep {
            found,
            complete: true,
        };
    }
    let Some(tail) = tail else {
        return Dep {
            found,
            complete: false,
        };
    };
    found.extend(scan_paths(&whole_lines(tail), wanted));
    let reach = 2 * u64::try_from(MAX_READ).unwrap_or(u64::MAX);
    let complete = len.is_some_and(|len| len <= reach.saturating_sub(SLACK));
    Dep { found, complete }
}

/// The text of a read with a line cut by the read dropped: the last line when the end was cut, the first
/// when the start was cut.
fn whole_lines(file: &FileBytes) -> String {
    let text = String::from_utf8_lossy(&file.bytes);
    let mut text: &str = &text;
    if file.truncated_head {
        text = text.split_once('\n').map_or("", |(_, rest)| rest);
    }
    if file.truncated_tail {
        text = text.rsplit_once('\n').map_or("", |(rest, _)| rest);
    }
    text.to_owned()
}
