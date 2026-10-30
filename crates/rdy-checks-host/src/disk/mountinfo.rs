//! The lines of `/proc/self/mountinfo` that `host.disk` needs, and the rule that picks one.
//!
//! The device of the measured file system (`major:minor`, field 3) finds the lines. Several lines can
//! share a device (a bind mount, a stacked mount), so the longest mount point that is a whole-component
//! prefix of the measured path breaks the tie. Paths are `/`-separated text everywhere here, never
//! `std::path`, so the same code and the same fixtures run on every CI leg.

use crate::cgroup::unescape;

/// The most lines read. The probe already caps the file at 1 MiB. This keeps the work bounded if lines
/// are very short.
const MAX_LINES: usize = 20_000;

/// One mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mount {
    /// Field 3: `(major, minor)`.
    pub dev: (u32, u32),
    /// Field 5, with the octal escapes decoded.
    pub point: String,
    /// Field 6: the per-mount options (`rw`, `noexec`, `nosuid`, `nodev`, `relatime`).
    pub options: Vec<String>,
    /// The file system type after the `-` separator (`ext4`, `nfs4`, `fuse.sshfs`).
    pub fstype: String,
    /// The mount source after the type (`/dev/mapper/vg0-var`, `server.example:/export`), decoded.
    pub source: String,
}

impl Mount {
    /// Whether the per-mount options hold `option`.
    pub fn has_option(&self, option: &str) -> bool {
        self.options.iter().any(|o| o == option)
    }
}

/// What the parse saw.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Parsed {
    pub mounts: Vec<Mount>,
    /// Lines that were not in the form and were left out.
    pub skipped: usize,
}

/// Parses the file. A line that is not in the form is counted and left out, never an error.
pub(super) fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for line in text.lines().take(MAX_LINES) {
        if line.trim().is_empty() {
            continue;
        }
        match mount_line(line) {
            Some(mount) => parsed.mounts.push(mount),
            None => parsed.skipped += 1,
        }
    }
    parsed
}

fn mount_line(line: &str) -> Option<Mount> {
    // `id parent major:minor root point options [optional fields] - fstype source super-options`
    // A space inside a field is written `\040`, so a plain split on spaces is safe.
    let fields: Vec<&str> = line.split(' ').collect();
    let dash = fields.iter().position(|f| *f == "-")?;
    if dash < 6 {
        return None;
    }
    let dev = device(fields[2])?;
    let fstype = *fields.get(dash + 1)?;
    if fstype.is_empty() {
        return None;
    }
    Some(Mount {
        dev,
        point: unescape(fields[4]),
        options: fields[5]
            .split(',')
            .filter(|o| !o.is_empty())
            .map(str::to_owned)
            .collect(),
        fstype: fstype.to_owned(),
        source: unescape(fields.get(dash + 2).copied().unwrap_or_default()),
    })
}

/// `8:1` as `(8, 1)`. Decimal digits only.
pub(super) fn device(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.split_once(':')?;
    let number = |part: &str| {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse::<u32>().ok()
    };
    Some((number(major)?, number(minor)?))
}

/// The components of a `/`-separated absolute path. Empty parts and `.` are dropped. `None` when the
/// path has a `..`, which text alone cannot settle.
pub(super) fn components(path: &str) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            other => parts.push(other),
        }
    }
    Some(parts)
}

/// Whether the mount point `point` is `path` or a directory above it, comparing whole components, so
/// `/var` is above `/var/lib` and not above `/variable`.
fn is_above(point: &str, path: &[&str]) -> Option<usize> {
    let parts = components(point)?;
    (parts.len() <= path.len() && parts.iter().zip(path).all(|(a, b)| a == b))
        .then_some(parts.len())
}

/// How the mount of a file system was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Lookup<'a> {
    /// The line of the mount that holds the path.
    Found(&'a Mount),
    /// No line has this device.
    NoDevice,
    /// Several lines have this device and none is a prefix of the path, so the mount is not known.
    Ambiguous,
}

/// The mount that holds `path` (components of the measured path) on device `dev`.
///
/// Among the lines with that device it takes the one with the longest whole-component mount point that
/// is a prefix of the path; a later line wins a tie (it was mounted over the earlier one). When no
/// mount point is a prefix, which happens when the path goes through a link, a single line with that
/// device is still the answer, because the device names the file system. Several such lines are
/// [`Lookup::Ambiguous`].
pub(super) fn find<'a>(mounts: &'a [Mount], dev: (u32, u32), path: &[&str]) -> Lookup<'a> {
    let same: Vec<&Mount> = mounts.iter().filter(|m| m.dev == dev).collect();
    let mut best: Option<(usize, &Mount)> = None;
    for mount in &same {
        if let Some(depth) = is_above(&mount.point, path)
            && best.is_none_or(|(deepest, _)| depth >= deepest)
        {
            best = Some((depth, mount));
        }
    }
    match (best, same.as_slice()) {
        (Some((_, mount)), _) => Lookup::Found(mount),
        (None, [mount]) => Lookup::Found(mount),
        (None, []) => Lookup::NoDevice,
        (None, _) => Lookup::Ambiguous,
    }
}

/// File system types that live on another machine.
const NETWORK: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ceph",
    "glusterfs",
    "lustre",
    "gpfs",
    "beegfs",
    "afs",
    "9p",
    "fuse.sshfs",
    "fuse.glusterfs",
    "fuse.s3fs",
];

/// Whether `fstype` is a network file system.
pub(super) fn is_network(fstype: &str) -> bool {
    NETWORK.contains(&fstype)
}

/// Whether the spec's `listed` type names `fstype`. An exact name matches. `fuse` also covers
/// `fuse.sshfs` (a type with a dot after the listed name), and `nfs` also covers `nfs4`.
pub(super) fn type_matches(listed: &str, fstype: &str) -> bool {
    fstype == listed
        || fstype
            .strip_prefix(listed)
            .is_some_and(|rest| rest.starts_with('.'))
        || (listed == "nfs" && fstype == "nfs4")
}
