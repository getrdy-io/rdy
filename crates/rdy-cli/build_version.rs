//! Pure logic for the version line. `build.rs` and `tests/build_version.rs` both include this file,
//! so the rules are tested without running git.

/// Where the build got its commit information from.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    /// A git checkout of this workspace: full commit hash and commit time in Unix seconds.
    Git { commit: String, unix_secs: i64 },
    /// A `cargo package` tarball: the commit recorded by cargo, with no date.
    Packaged { commit: String },
    /// No trustworthy commit information.
    None,
}

/// Decide the source. The order matters.
///
/// 1. A `.cargo_vcs_info.json` means this is a packaged source tree. Git is never asked, because a
///    tarball unpacked inside another repository would stamp that repository's commit.
/// 2. Otherwise git is used only when its top-level directory is this workspace.
/// 3. Otherwise there is no commit information.
pub fn source(
    vcs_info: Option<&str>,
    git_toplevel_is_workspace: impl FnOnce() -> bool,
    git_head: impl FnOnce() -> Option<(String, i64)>,
) -> Source {
    if let Some(json) = vcs_info {
        return match commit_from_vcs_info(json) {
            Some(commit) => Source::Packaged { commit },
            None => Source::None,
        };
    }
    if !git_toplevel_is_workspace() {
        return Source::None;
    }
    match git_head() {
        Some((commit, unix_secs)) => Source::Git { commit, unix_secs },
        None => Source::None,
    }
}

/// Read `git.sha1` from the text of `.cargo_vcs_info.json`.
pub fn commit_from_vcs_info(json: &str) -> Option<String> {
    let rest = json.split("\"sha1\"").nth(1)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let hash = &rest[..rest.find('"')?];
    short_hash(hash).map(|_| hash.to_string())
}

/// The first 7 characters of a full hex commit hash, or `None` if it is not one.
pub fn short_hash(full: &str) -> Option<String> {
    let ok = full.len() >= 7 && full.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| full[..7].to_ascii_lowercase())
}

/// `<version>`, `<version> (<commit>)` or `<version> (<commit> <date>)`.
pub fn line(version: &str, source: &Source) -> String {
    match commit_and_date(source) {
        (Some(commit), Some(date)) => format!("{version} ({commit} {date})"),
        (Some(commit), None) => format!("{version} ({commit})"),
        (None, _) => version.to_string(),
    }
}

/// The short commit and the UTC commit date (`YYYY-MM-DD`) that `rdy version --json` prints. Either
/// is `None` when the build has no trustworthy value. A date never appears without a commit.
pub fn commit_and_date(source: &Source) -> (Option<String>, Option<String>) {
    match source {
        Source::Git { commit, unix_secs } => match short_hash(commit) {
            Some(short) => {
                let (year, month, day) = civil_from_days(unix_secs.div_euclid(86_400));
                (Some(short), Some(format!("{year:04}-{month:02}-{day:02}")))
            }
            None => (None, None),
        },
        Source::Packaged { commit } => (short_hash(commit), None),
        Source::None => (None, None),
    }
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
