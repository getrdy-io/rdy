//! Unit tests for the words the page is made of. The page as a whole is tested in
//! `tests/html_report.rs`.

use rdy_spec::result::{CheckResult, Need, NeedState, Severity, SkipKind, Status};

use super::view::{need_label, not_run_reason, short_fingerprint, utc_text};

#[test]
fn a_timestamp_is_shown_as_utc_and_anything_else_as_written() {
    assert_eq!(
        utc_text("2027-03-09T14:30:05.000Z"),
        "2027-03-09 14:30:05 UTC"
    );
    assert_eq!(utc_text("2027-03-09T14:30:05Z"), "2027-03-09 14:30:05 UTC");
    // An offset, a short text and non-ASCII text are not touched, and never panic.
    assert_eq!(
        utc_text("2027-03-09T14:30:05+02:00"),
        "2027-03-09T14:30:05+02:00"
    );
    assert_eq!(utc_text("soon"), "soon");
    assert_eq!(
        utc_text("2027-03-09T14:30:05.\u{e9}\u{e9}Z"),
        "2027-03-09T14:30:05.\u{e9}\u{e9}Z"
    );
    assert_eq!(utc_text(""), "");
}

#[test]
fn a_fingerprint_is_cut_to_the_first_eight_and_last_four() {
    let full = "4d2a7c0e9b1f3a5c6e8d0b2f4a6c8e0d1b3f5a7c9e2d4b6f8a0c2e4d6b8f0a1c";
    assert_eq!(short_fingerprint(full), "4d2a7c0e...0a1c");
    assert_eq!(short_fingerprint("abc"), "abc");
}

#[test]
fn needs_have_plain_names() {
    assert_eq!(need_label(&Need::Root, None), "root");
    assert_eq!(
        need_label(&Need::Command, Some("kubectl")),
        "the command kubectl"
    );
    assert_eq!(
        need_label(&Need::CloudCredentials, Some("aws")),
        "cloud credentials for aws"
    );
    assert_eq!(need_label(&Need::from("future_need"), None), "future_need");
}

#[test]
fn a_skip_says_why_in_the_words_of_01_section_6() {
    let mut check = CheckResult::new("host.ports", "host", Severity::Block, Status::Skipped);
    let cases = [
        ("not_in_build", "Not in this version of rdy"),
        ("unknown_check", "Not in this version of rdy"),
        ("unsupported_spec", "rdy cannot read this check"),
        ("not_yet_on_os", "Not available on this OS yet"),
        ("not_applicable", "Does not apply here"),
        ("run_deadline", "Run time limit reached"),
        ("cancelled", "Run was interrupted"),
        ("something_new", "rdy did not run this check"),
    ];
    for (kind, text) in cases {
        check.skip_kind = Some(SkipKind::from(kind));
        assert_eq!(not_run_reason(&check).as_deref(), Some(text), "{kind}");
    }
    check.skip_kind = Some(SkipKind::MissingNeed);
    check.needs = vec![NeedState::new(Need::Root, true, false)];
    assert_eq!(not_run_reason(&check).as_deref(), Some("Missing: root"));
}

#[test]
fn a_check_that_ran_has_no_not_run_reason() {
    let check = CheckResult::new("host.cpu", "host", Severity::Block, Status::Pass);
    assert_eq!(not_run_reason(&check), None);
}
