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

/// The value of the last `SELINUX=` line, as the library that reads the file takes it.
pub(super) fn parse_config(text: &str) -> Configured {
    let mut found = Configured::Unset;
    for line in text.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("SELINUX=") else {
            continue;
        };
        // `SELINUXTYPE=` does not start with `SELINUX=`, so it never gets here.
        let value = value.split('#').next().unwrap_or_default().trim();
        found = match value.to_ascii_lowercase().as_str() {
            "enforcing" => Configured::Mode(SelinuxMode::Enforcing),
            "permissive" => Configured::Mode(SelinuxMode::Permissive),
            "disabled" => Configured::Mode(SelinuxMode::Disabled),
            _ => Configured::Other(value.chars().take(32).collect()),
        };
    }
    found
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
