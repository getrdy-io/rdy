//! Unit tests for the words the page is made of. The page as a whole is tested in
//! `tests/html_report.rs`.

use rdy_spec::result::{CheckResult, Need, NeedState, Severity, SkipKind, Status};

use super::view::{need_label, need_spans, not_run_reason, plain, short_fingerprint, utc_text};

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
        let spans = not_run_reason(&check).expect("a skip has a reason");
        assert_eq!(plain(&spans), text, "{kind}");
        assert!(spans.iter().all(|span| !span.untrusted), "{kind}");
    }
    check.skip_kind = Some(SkipKind::MissingNeed);
    check.needs = vec![NeedState::new(Need::Root, true, false)];
    let spans = not_run_reason(&check).expect("a skip has a reason");
    assert_eq!(plain(&spans), "Missing: root");
    assert!(spans.iter().all(|span| !span.untrusted));
}

#[test]
fn a_check_that_ran_has_no_not_run_reason() {
    let check = CheckResult::new("host.cpu", "host", Severity::Block, Status::Pass);
    assert!(not_run_reason(&check).is_none());
}

/// SEC-149-4, code 3: only the name that came from the report is untrusted. Our words around it are not.
#[test]
fn a_need_name_is_the_only_untrusted_piece_of_its_label() {
    let spans = need_spans(&Need::Command, Some("ss\u{202e}"));
    let untrusted: Vec<&str> = spans
        .iter()
        .filter(|span| span.untrusted)
        .map(|span| span.text.as_str())
        .collect();
    assert_eq!(untrusted, ["ss\u{202e}"]);
    assert_eq!(plain(&spans), "the command ss\u{202e}");
    assert!(need_spans(&Need::Root, None).iter().all(|s| !s.untrusted));
}

/// The report the size cap tests cut: the 01 section 7.2 sample with `count` copies of its first action.
fn report_with_actions(count: u64, denied: &[u64]) -> crate::redact::RedactedReport {
    use crate::redact::{Redactor, TagKey};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/reports/not-ready-7.2.json");
    let text = std::fs::read_to_string(path).expect("the sample report is in the repo");
    let mut doc: serde_json::Value = serde_json::from_str(&text).expect("the sample is JSON");
    let template = doc["actions"][0].clone();
    let actions = doc["actions"].as_array_mut().expect("actions is a list");
    actions.clear();
    for seq in 1..=count {
        let mut entry = template.clone();
        entry["seq"] = serde_json::json!(seq);
        if denied.contains(&seq) {
            entry["outcome"] = serde_json::json!("denied");
            entry["rule"] = serde_json::json!("read_denylist");
        }
        actions.push(entry);
    }
    let report = serde_json::from_value(doc).expect("the sample is a report");
    Redactor::new(TagKey::fixed([5; 32]))
        .redact_report(report)
        .expect("the sample redacts")
}

fn rows_in(page: &str) -> usize {
    let start = page.find("id=\"actions\"").expect("the action section");
    page[start..].matches("<tr><th scope=\"row\">").count()
}

/// Past the page cap the table is cut to the rows that fit, the line under it counts the rest, and the
/// embedded JSON is whole (07 D.4).
#[test]
fn a_page_over_its_cap_loses_table_rows_and_nothing_else() {
    let report = report_with_actions(400, &[]);
    let mut view = super::view::View::new(&report).expect("the report is fine");
    let whole = super::fit_page(&mut view, usize::MAX).expect("renders");
    assert_eq!(rows_in(&whole), 400);
    let max = whole.len() - 40_000;
    let mut view = super::view::View::new(&report).expect("the report is fine");
    let page = super::fit_page(&mut view, max).expect("renders");
    assert!(page.len() <= max, "{} bytes is over {max}", page.len());
    let shown = rows_in(&page);
    assert!(shown > 0 && shown < 400, "{shown} rows");
    // One more row would not have fit.
    assert!(page.len() + (whole.len() - page.len()) / (400 - shown) > max);
    assert!(page.contains(&format!(
        "<p>{} more entries are in the embedded JSON. Every refused call in the log is listed above.</p>",
        400 - shown
    )));
    // The JSON block is the same bytes.
    let json = |text: &str| text[text.find("id=\"rdy-result\"").expect("block")..].to_owned();
    assert_eq!(json(&page), json(&whole));
}

/// When the cap cuts a refusal, the page does not claim that every refusal is listed.
#[test]
fn a_refusal_cut_by_the_page_cap_is_not_called_listed() {
    let report = report_with_actions(300, &[300]);
    let mut view = super::view::View::new(&report).expect("the report is fine");
    let whole = super::fit_page(&mut view, usize::MAX).expect("renders");
    let mut view = super::view::View::new(&report).expect("the report is fine");
    let page = super::fit_page(&mut view, whole.len() - 20_000).expect("renders");
    assert!(!page.contains("Every refused call"));
    assert!(page.contains("are in the embedded JSON.</p>"));
}
