//! Tests the rules `build.rs` uses to stamp the version line. No git is run here.

#[path = "../build_version.rs"]
mod build_version;

use build_version::{Source, civil_from_days, commit_from_vcs_info, line, short_hash, source};

const FULL: &str = "0123456789abcdef0123456789abcdef01234567";
const VCS_INFO: &str =
    r#"{"git":{"sha1":"0123456789abcdef0123456789abcdef01234567"},"path_in_vcs":"crates/rdy-cli"}"#;

fn never<T>() -> T {
    panic!("git must not be asked");
}

#[test]
fn packaged_tree_never_asks_git() {
    // A tarball unpacked inside another repository must not stamp that repository's commit.
    let got = source(
        Some(VCS_INFO),
        never::<bool>,
        never::<Option<(String, i64)>>,
    );
    assert_eq!(
        got,
        Source::Packaged {
            commit: FULL.to_string()
        }
    );
    assert_eq!(line("1.2.3", &got), "1.2.3 (0123456)");
}

#[test]
fn packaged_tree_with_unreadable_info_prints_version_only() {
    let got = source(Some("{}"), never::<bool>, never::<Option<(String, i64)>>);
    assert_eq!(got, Source::None);
    assert_eq!(line("1.2.3", &got), "1.2.3");
}

#[test]
fn foreign_repository_prints_version_only() {
    let got = source(None, || false, never::<Option<(String, i64)>>);
    assert_eq!(got, Source::None);
    assert_eq!(line("1.2.3", &got), "1.2.3");
}

#[test]
fn own_checkout_prints_commit_and_utc_date() {
    let got = source(None, || true, || Some((FULL.to_string(), 1_798_675_200)));
    assert_eq!(line("1.2.3", &got), "1.2.3 (0123456 2026-12-31)");
}

#[test]
fn own_checkout_without_a_commit_prints_version_only() {
    let got = source(None, || true, || None);
    assert_eq!(line("1.2.3", &got), "1.2.3");
}

#[test]
fn vcs_info_parsing_rejects_junk() {
    assert_eq!(commit_from_vcs_info(VCS_INFO).as_deref(), Some(FULL));
    assert_eq!(commit_from_vcs_info(r#"{"git":{"sha1":"zzz"}}"#), None);
    assert_eq!(commit_from_vcs_info(r#"{"git":{"sha1":"abc"}}"#), None);
    assert_eq!(commit_from_vcs_info(""), None);
}

#[test]
fn short_hash_cuts_to_seven() {
    assert_eq!(short_hash(FULL).as_deref(), Some("0123456"));
    assert_eq!(short_hash("ABCDEF1234").as_deref(), Some("abcdef1"));
    assert_eq!(short_hash("abc123"), None);
    assert_eq!(short_hash("not a hash at all"), None);
}

#[test]
fn civil_dates_are_right() {
    let cases = [
        (0, "1970-01-01"),
        (-1, "1969-12-31"),
        (951_782_400, "2000-02-29"),
        (1_709_164_800, "2024-02-29"),
        (4_102_444_800, "2100-01-01"),
    ];
    for (secs, want) in cases {
        let (y, m, d) = civil_from_days(i64::div_euclid(secs, 86_400));
        assert_eq!(format!("{y:04}-{m:02}-{d:02}"), want, "for {secs}");
    }
}
