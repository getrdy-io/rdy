//! Build script. It builds the version line `rdy --version` prints (ADR 0011).
//!
//! The line is `<version> (<commit> <date>)`. The commit is the short hash of `HEAD`. The date is the
//! commit date in UTC, not the build date, so two builds of one commit print the same line. Without
//! git (a crates.io source build) the line is just `<version>`. The script runs `git` and nothing
//! else. It reads no network and writes only the `RDY_VERSION` compile-time variable.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    watch_git_head();

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let line = match (git(&["rev-parse", "--short=7", "HEAD"]), commit_date()) {
        (Some(commit), Some(date)) => format!("{version} ({commit} {date})"),
        _ => version,
    };
    println!("cargo:rustc-env=RDY_VERSION={line}");
}

/// Run git in the package directory and return trimmed stdout, or `None` on any failure.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Rebuild when `HEAD` or the branch it points at moves.
fn watch_git_head() {
    if let Some(path) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
}

/// The commit date of `HEAD` as `YYYY-MM-DD` in UTC.
fn commit_date() -> Option<String> {
    let secs: i64 = git(&["show", "-s", "--format=%ct", "HEAD"])?.parse().ok()?;
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
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
