//! The match rules of `host.os` (03 section 2) and the fix text for a miss. Pure functions of text.

use super::release::Release;

/// Hosts whose `VERSION_ID` follows the major version of the distribution they rebuild, so a spec that
/// lists the parent covers them. Amazon Linux and Linux Mint are not here on purpose: their versions are
/// unrelated to the parent's.
const REBUILDS: &[&str] = &["rocky", "almalinux", "ol", "centos"];

/// The parent ids an `ID_LIKE` word may stand for on a rebuild. `fedora` is left out because Fedora's
/// version numbers do not track the rebuild's.
const PARENTS: &[&str] = &["rhel", "centos"];

/// The most distributions named in a sentence before the rest are counted.
const LIST_MAX: usize = 8;

/// One entry of the spec's `supported` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wanted {
    pub(crate) id: String,
    /// `None` accepts every version.
    pub(crate) versions: Option<Vec<String>>,
}

/// How the host sits against the `supported` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Match {
    /// Supported. `via` is the host `ID` when the match went through `ID_LIKE`.
    Yes { via: Option<String> },
    /// The id, or every version of it, is not on the list.
    No,
    /// The id is on the list with versions, and the host has no `VERSION_ID` to compare.
    VersionUnknown,
}

/// Matches `release` against `supported`.
///
/// `ID` is compared exactly. `ID_LIKE` counts only on a rebuild (`rocky`, `almalinux`, `ol`, `centos`)
/// and only for the parents `rhel` and `centos`. A version without a dot is a major match, a dotted one
/// is exact.
pub(crate) fn matches(release: &Release, supported: &[Wanted]) -> Match {
    let mut via = None;
    let mut unknown = false;
    for want in supported {
        let direct = want.id == release.id;
        let like = !direct
            && REBUILDS.contains(&release.id.as_str())
            && PARENTS.contains(&want.id.as_str())
            && release.id_like.contains(&want.id);
        if !direct && !like {
            continue;
        }
        let ok = match (&want.versions, &release.version_id) {
            (None, _) => true,
            (Some(_), None) => {
                unknown = true;
                false
            }
            (Some(wanted), Some(have)) => wanted.iter().any(|w| version_matches(w, have)),
        };
        if ok {
            if direct {
                return Match::Yes { via: None };
            }
            via.get_or_insert_with(|| release.id.clone());
        }
    }
    match via {
        Some(id) => Match::Yes { via: Some(id) },
        None if unknown => Match::VersionUnknown,
        None => Match::No,
    }
}

/// `"8"` matches `8` and `8.6`. `"22.04"` matches `22.04` only.
pub(crate) fn version_matches(wanted: &str, have: &str) -> bool {
    let (wanted, have) = (wanted.trim(), have.trim());
    if wanted.contains('.') {
        wanted == have
    } else {
        have.split('.').next() == Some(wanted)
    }
}

/// The spec's architecture names (`amd64`, `arm64`) and the kernel's (`x86_64`, `aarch64`) in one form.
pub(crate) fn canonical_arch(name: &str) -> &str {
    match name {
        "amd64" => "x86_64",
        "arm64" => "aarch64",
        other => other,
    }
}

/// `rhel 8 or 9, ubuntu 22.04`, at most [`LIST_MAX`] entries.
pub(crate) fn list_supported(supported: &[Wanted]) -> String {
    let mut parts: Vec<String> = supported
        .iter()
        .take(LIST_MAX)
        .map(|w| match &w.versions {
            None => format!("{} (any version)", w.id),
            Some(vs) => format!("{} {}", w.id, or_list(vs)),
        })
        .collect();
    if supported.len() > LIST_MAX {
        parts.push(format!("{} more", supported.len() - LIST_MAX));
    }
    parts.join(", ")
}

/// `8`, `8 or 9`, `8, 9 or 10`.
fn or_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} or {last}", init.join(", ")),
    }
}

/// Which FIPS procedure fits the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// RHEL and its rebuilds, Fedora, Amazon Linux.
    Rhel,
    /// Ubuntu and its derivatives.
    Ubuntu,
    /// Anything else.
    Other,
}

/// The family from `ID` and `ID_LIKE`.
pub(crate) fn family(release: &Release) -> Family {
    let any = |names: &[&str]| {
        std::iter::once(&release.id)
            .chain(&release.id_like)
            .any(|w| names.contains(&w.as_str()))
    };
    if any(&["rhel", "centos", "fedora", "amzn"]) {
        Family::Rhel
    } else if any(&["ubuntu"]) {
        Family::Ubuntu
    } else {
        Family::Other
    }
}

/// The fix for FIPS mode being on when the spec forbids it, or off when it requires it.
pub(crate) fn fips_fix(require: bool, family: Family) -> &'static str {
    match (require, family) {
        (true, Family::Rhel) => "Run `fips-mode-setup --enable`, then reboot.",
        (false, Family::Rhel) => "Run `fips-mode-setup --disable`, then reboot.",
        (true, Family::Ubuntu) => "Attach Ubuntu Pro, run `pro enable fips-updates`, then reboot.",
        (false, Family::Ubuntu) => {
            "Remove fips=1 from GRUB_CMDLINE_LINUX in /etc/default/grub, run `update-grub`, then reboot."
        }
        (true, Family::Other) => "Turn FIPS mode on with the OS vendor's procedure, then reboot.",
        (false, Family::Other) => "Turn FIPS mode off with the OS vendor's procedure, then reboot.",
    }
}
