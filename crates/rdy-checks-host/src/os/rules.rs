//! The match rules of `host.os` (03 section 2) and the fix text for a miss. Pure functions of text.

use super::release::Release;

/// Hosts whose `VERSION_ID` follows the major version of the distribution they rebuild, so a spec that
/// lists the parent covers them. Amazon Linux and Linux Mint are not here on purpose: their versions are
/// unrelated to the parent's.
const REBUILDS: &[&str] = &["rocky", "almalinux", "ol", "centos"];

/// The parent ids an `ID_LIKE` word may stand for on a rebuild. `fedora` is left out because Fedora's
/// version numbers do not track the rebuild's.
const PARENTS: &[&str] = &["rhel", "centos"];

/// Whether `release` is a rebuild that stands for the parent `want`. A rebuild names its parent in
/// `ID_LIKE`, except Oracle Linux: it says `ID_LIKE="fedora"`, so `ol` is mapped to `rhel` here.
fn stands_for(release: &Release, want: &str) -> bool {
    REBUILDS.contains(&release.id.as_str())
        && PARENTS.contains(&want)
        && (release.id_like.iter().any(|w| w == want) || (release.id == "ol" && want == "rhel"))
}

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
/// and only for the parents `rhel` and `centos`. Oracle Linux (`ol`) says `ID_LIKE="fedora"`, so it is
/// mapped to `rhel` by name. A version without a dot is a major match, a dotted one is exact.
///
/// Trap: a dotted version is exact, so a spec entry that is a shorter prefix of the host version does
/// not match. Alpine `3.19.1` is not matched by `3.19`. List `3.19.1`, or the major (`3`) to accept
/// every 3.x. [`prefix_trap`] finds this case so the check can say so.
pub(crate) fn matches(release: &Release, supported: &[Wanted]) -> Match {
    let mut via = None;
    let mut unknown = false;
    for want in supported {
        let direct = want.id == release.id;
        let like = !direct && stands_for(release, &want.id);
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

/// The spec entry versions that are a dotted prefix of `have` but do not match it, such as `3.19` for a
/// host on `3.19.1`. The check names them in a note, because the miss looks like a bug in the spec.
pub(crate) fn prefix_trap<'a>(wanted: &'a [String], have: &str) -> Vec<&'a str> {
    let have = have.trim();
    wanted
        .iter()
        .map(|w| w.trim())
        .filter(|w| {
            w.contains('.')
                && !version_matches(w, have)
                && have
                    .strip_prefix(w)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
        .collect()
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
pub(crate) enum Procedure {
    /// RHEL 8 and 9, their rebuilds, and Amazon Linux 2023: `fips-mode-setup`.
    ModeSetup,
    /// RHEL 10 and later and their rebuilds: no tool, FIPS mode is chosen when the host is installed.
    InstallOnly,
    /// Amazon Linux 2: `dracut-fips`, `dracut` and `grubby`.
    AmazonLinux2,
    /// Ubuntu and its derivatives: the Ubuntu Pro client.
    UbuntuPro,
    /// Anything else, including Fedora: the OS vendor's own procedure.
    Vendor,
}

/// The first number of a `VERSION_ID`, as in `9` for `9.2`.
fn major(release: &Release) -> Option<u32> {
    release
        .version_id
        .as_deref()?
        .trim()
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// The FIPS procedure from `ID`, `ID_LIKE` and the major version.
pub(crate) fn procedure(release: &Release) -> Procedure {
    let id = release.id.as_str();
    let like = |name: &str| release.id_like.iter().any(|w| w == name);
    if id == "amzn" {
        return match major(release) {
            Some(2) => Procedure::AmazonLinux2,
            Some(2023) => Procedure::ModeSetup,
            _ => Procedure::Vendor,
        };
    }
    if id == "ubuntu" || like("ubuntu") {
        return Procedure::UbuntuPro;
    }
    let el = matches!(id, "rhel" | "centos" | "rocky" | "almalinux" | "ol")
        || (id != "fedora" && (like("rhel") || like("centos")));
    if !el {
        return Procedure::Vendor;
    }
    match major(release) {
        Some(8 | 9) => Procedure::ModeSetup,
        Some(10..) => Procedure::InstallOnly,
        _ => Procedure::Vendor,
    }
}

/// The fix for FIPS mode being on when the spec forbids it, or off when it requires it.
pub(crate) fn fips_fix(require: bool, procedure: Procedure) -> &'static str {
    match (require, procedure) {
        (true, Procedure::ModeSetup) => "Run `fips-mode-setup --enable`, then reboot.",
        (false, Procedure::ModeSetup) => "Run `fips-mode-setup --disable`, then reboot.",
        (true, Procedure::InstallOnly) => {
            "This release sets FIPS mode at install time only. Reinstall the host with `fips=1` on the installer command line."
        }
        (false, Procedure::InstallOnly) => {
            "This release sets FIPS mode at install time only. Reinstall the host without `fips=1` on the installer command line."
        }
        (true, Procedure::AmazonLinux2) => {
            "Install the `dracut-fips` package, run `dracut -f`, run `grubby --update-kernel=ALL --args=fips=1`, then reboot."
        }
        (false, Procedure::AmazonLinux2) => {
            "Run `grubby --update-kernel=ALL --remove-args=fips`, then reboot."
        }
        (true, Procedure::UbuntuPro) => {
            "Attach Ubuntu Pro, run `pro enable fips-updates`, then reboot."
        }
        (false, Procedure::UbuntuPro) => {
            "Run `pro disable fips-updates` (or `pro disable fips`), purge the FIPS kernel with Canonical's procedure, then reboot."
        }
        (true, Procedure::Vendor) => {
            "Turn FIPS mode on with the OS vendor's procedure, then reboot."
        }
        (false, Procedure::Vendor) => {
            "Turn FIPS mode off with the OS vendor's procedure, then reboot."
        }
    }
}
