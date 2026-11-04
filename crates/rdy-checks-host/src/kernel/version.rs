//! A kernel release string such as `5.14.0-362.el9.x86_64`, read tolerantly, and its comparison with a
//! spec version.
//!
//! The spec writes a version as dotted numbers with an optional build part (`5.4`, `4.18.0-305`). The
//! machine reports more: a distribution suffix (`.el9`), an architecture (`.x86_64`), a flavour
//! (`-generic`, `-aws`). The reader takes the leading numbers before and after the first `-` and drops
//! the rest. Comparing is the shared dotted compare, part by part as numbers, never as semver.

use std::cmp::Ordering;

use rdy_engine::units::compare_versions;
use rdy_spec::Version;
use rdy_spec::check::KernelVersion;

/// The most numbers kept from each part. `Version` holds four.
const MAX_PARTS: usize = 4;

/// The longest release string read. A real one is under 64 characters.
const MAX_LEN: usize = 128;

/// A release read from the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Release {
    /// The numbers before the first `-`, such as `5.14.0`.
    pub(super) base: Version,
    /// The numbers right after the first `-`, such as the `362` of `5.14.0-362.el9`. `None` when the
    /// release has none (`5.10.102.1-microsoft-standard-WSL2`, `6.1.0`).
    pub(super) build: Option<Version>,
}

/// How a release stands against a wanted version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Standing {
    /// At or above the wanted version.
    AtLeast,
    /// Below it.
    Below,
    /// The wanted version has a build number and the release has none, so they cannot be compared.
    NoBuild,
}

/// Reads `text`. `None` when it does not start with a number or a number is too large.
pub(super) fn parse(text: &str) -> Option<Release> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_LEN {
        return None;
    }
    let base_text = numbers(text)?;
    let base = version(base_text)?;
    let rest = text.get(base_text.len()..).unwrap_or_default();
    let build = rest.strip_prefix('-').and_then(numbers).and_then(version);
    Some(Release { base, build })
}

/// The leading run of digits and dots, without a trailing dot. `None` when it does not start with a digit.
fn numbers(text: &str) -> Option<&str> {
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let run = text.get(..end)?.trim_end_matches('.');
    run.starts_with(|c: char| c.is_ascii_digit()).then_some(run)
}

/// The first four numbers of `run` as a [`Version`]. `None` for an empty part (`5..4`) or a part of more
/// than nine digits.
fn version(run: &str) -> Option<Version> {
    let parts: Vec<&str> = run.split('.').take(MAX_PARTS).collect();
    Version::parse(&parts.join(".")).ok()
}

/// How `have` stands against `want`.
///
/// The numbers before the `-` decide first. When they are equal and `want` has a build number, the build
/// numbers decide. A release with no build number cannot be compared to one that has.
pub(super) fn compare(have: &Release, want: &KernelVersion) -> Standing {
    match compare_versions(&have.base, want.base()) {
        Ordering::Less => Standing::Below,
        Ordering::Greater => Standing::AtLeast,
        Ordering::Equal => match (want.build(), &have.build) {
            (None, _) => Standing::AtLeast,
            (Some(wanted), Some(found)) => {
                if compare_versions(found, wanted).is_ge() {
                    Standing::AtLeast
                } else {
                    Standing::Below
                }
            }
            (Some(_), None) => Standing::NoBuild,
        },
    }
}

/// Whether `release` is safe to put in a path under `/lib/modules`: 1 to 64 letters, digits and
/// `. _ + ~ -`, and not starting with a dot. A kernel release has no slash, so this never refuses a
/// real one, and it keeps a hostile string from leaving the directory.
pub(super) fn is_path_safe(release: &str) -> bool {
    !release.is_empty()
        && release.len() <= 64
        && !release.starts_with('.')
        && release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'~' | b'-'))
}
