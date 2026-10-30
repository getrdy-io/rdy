//! Parsers for the SELinux files `host.lsm` reads. Pure functions of text.

use rdy_spec::check::SelinuxMode;

/// The runtime mode in `/sys/fs/selinux/enforce`: `1` enforcing, `0` permissive.
pub(super) fn parse_enforce(text: &str) -> Option<SelinuxMode> {
    match text.trim() {
        "1" => Some(SelinuxMode::Enforcing),
        "0" => Some(SelinuxMode::Permissive),
        _ => None,
    }
}

/// What `SELINUX=` says in `/etc/selinux/config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Configured {
    /// A mode rdy knows.
    Mode(SelinuxMode),
    /// The file has no `SELINUX=` line.
    Unset,
    /// A value rdy does not know. At most 32 characters of it.
    Other(String),
}

/// The mode `SELINUX=` sets, as libselinux's `selinux_getenforcemode` reads the file. The tag must start
/// the line, white space after the `=` is skipped, and the value is matched by its start, ignoring
/// case. The first line with a known value wins. A line with an unknown value is skipped, and the
/// first of those is kept only to say so when no line is known.
pub(super) fn parse_config(text: &str) -> Configured {
    let mut other = None;
    // `SELINUXTYPE=` does not start with `SELINUX=`, so it never gets here.
    for line in text.lines() {
        let Some(value) = line.strip_prefix("SELINUX=") else {
            continue;
        };
        let value = value.trim_start();
        let lower = value.to_ascii_lowercase();
        for (word, mode) in [
            ("enforcing", SelinuxMode::Enforcing),
            ("permissive", SelinuxMode::Permissive),
            ("disabled", SelinuxMode::Disabled),
        ] {
            if lower.starts_with(word) {
                return Configured::Mode(mode);
            }
        }
        if other.is_none() {
            let shown = value.split('#').next().unwrap_or_default().trim();
            other = Some(Configured::Other(shown.chars().take(32).collect()));
        }
    }
    other.unwrap_or(Configured::Unset)
}

/// What is mounted on `/sys/fs/selinux`, from `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Mount {
    /// The kernel's own file system. `enforce` should be under it.
    Selinuxfs,
    /// Something else covers the path: a container runtime's mask. The file system type.
    Masked(String),
}

const SELINUX_DIR: &str = "/sys/fs/selinux";

/// The topmost mount on `/sys/fs/selinux`, if any. Later lines of mountinfo are later mounts, so the
/// last match is the one a process sees. A line that does not parse is skipped.
pub(super) fn selinux_mount(mountinfo: &str) -> Option<Mount> {
    let mut found = None;
    for line in mountinfo.lines() {
        // `id parent major:minor root mount-point options [optional...] - fstype source super-options`
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let Some(point) = before.split(' ').nth(4) else {
            continue;
        };
        if unescape(point) != SELINUX_DIR {
            continue;
        }
        let Some(fstype) = after.split(' ').next().filter(|t| !t.is_empty()) else {
            continue;
        };
        found = Some(if fstype == "selinuxfs" {
            Mount::Selinuxfs
        } else {
            Mount::Masked(fstype.chars().take(32).collect())
        });
    }
    found
}

/// The root file system is an overlay, which is how a container runtime builds the root of a pod.
/// The last mount on `/` is the one a process sees. A line that does not parse is skipped.
pub(super) fn root_is_overlay(mountinfo: &str) -> bool {
    let mut found = false;
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        if before.split(' ').nth(4) != Some("/") {
            continue;
        }
        let Some(fstype) = after.split(' ').next().filter(|t| !t.is_empty()) else {
            continue;
        };
        found = fstype == "overlay";
    }
    found
}

/// The mount as it may appear in a message: `a tmpfs mount`. The type keeps lower case letters, digits,
/// `.`, `_` and `-` only. A FUSE subtype is chosen by whoever mounted it, so anything else is not
/// repeated.
pub(super) fn mount_words(fstype: &str) -> String {
    let plain = !fstype.is_empty()
        && fstype
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if plain {
        format!("a {fstype} mount")
    } else {
        "another file system".to_owned()
    }
}

/// Undoes the octal escapes mountinfo uses for a space, tab, newline and backslash.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let octal = (b == b'\\')
            .then(|| bytes.get(i + 1..i + 4))
            .flatten()
            .filter(|d| d.iter().all(|c| (b'0'..=b'7').contains(c)))
            .and_then(|d| {
                let value = d.iter().fold(0u32, |acc, c| acc * 8 + u32::from(c - b'0'));
                u8::try_from(value).ok()
            });
        if let Some(value) = octal {
            out.push(value);
            i += 4;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
