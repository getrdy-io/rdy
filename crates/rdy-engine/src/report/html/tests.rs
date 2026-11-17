//! Unit tests for the words the page is made of. The page as a whole is tested in
//! `tests/html_report.rs`.

use rdy_spec::result::{CheckResult, Need, NeedState, Severity, SkipKind, Status};

use super::view::{
    need_label, need_spans, not_run_reason, plain, short_fingerprint, shown, utc_text,
};

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
    assert_eq!(untrusted, ["ss\\u{202e}"]);
    assert_eq!(plain(&spans), "the command ss\\u{202e}");
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

/// A cap below the page with no rows cuts every row, and the page still says how many it left out.
#[test]
fn a_cap_that_cuts_every_row_still_counts_them() {
    let report = report_with_actions(50, &[]);
    let mut view = super::view::View::new(&report).expect("the report is fine");
    let page = super::fit_page(&mut view, 1).expect("renders");
    assert_eq!(rows_in(&page), 0);
    assert!(page.contains("<p>50 more entries are in the embedded JSON."));
    assert!(!page.contains("recorded nothing"));
    assert!(!page.contains("<caption>What rdy recorded"));
}

/// A log with no entries says so. That line is only for a log that really is empty.
#[test]
fn an_empty_log_says_nothing_was_recorded() {
    let report = report_with_actions(0, &[]);
    let page = super::render_html(&report).expect("renders");
    assert!(page.contains("rdy recorded nothing in this run."));
    assert!(!page.contains("more entries are in the embedded JSON"));
}

/// Nearly the biggest report the JSON writer accepts: 256 results with 7 notes of 1 KiB each (about 1.8 MiB
/// of JSON). The page, with the checks shown twice (as text and in the JSON), is under the real cap with
/// no row cut, and the `debug_assert` in `fit_page` runs.
#[test]
fn a_report_near_the_json_cap_is_under_the_page_cap() {
    use crate::redact::{Redactor, TagKey};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/reports/not-ready-7.2.json");
    let text = std::fs::read_to_string(path).expect("the sample report is in the repo");
    let mut doc: serde_json::Value = serde_json::from_str(&text).expect("the sample is JSON");
    let template = doc["checks"][0].clone();
    let note = "a note with some words ".repeat(44);
    let checks = doc["checks"].as_array_mut().expect("checks is a list");
    checks.clear();
    for number in 0..256 {
        let mut check = template.clone();
        check["key"] = serde_json::json!(format!("host.cpu{number}"));
        check["id"] = serde_json::json!("host.cpu");
        check["notes"] = serde_json::json!(vec![note.clone(); 7]);
        // Large Found and Needed lists: 200-item lists and a 4 KiB string on every check.
        check["observed"] = serde_json::json!({
            "items": (0..200).map(|n| format!("item number {n:04}")).collect::<Vec<_>>(),
            "text": "word ".repeat(820),
        });
        check["expected"] = serde_json::Value::Null;
        checks.push(check);
    }
    let report = serde_json::from_value(doc).expect("a report");
    let report = Redactor::new(TagKey::fixed([5; 32]))
        .redact_report(report)
        .expect("redacts");
    let page = super::render_html(&report).expect("renders");
    assert!(
        page.len() > 3_000_000,
        "{} bytes is not a big page",
        page.len()
    );
    assert!(page.len() <= super::MAX_PAGE_BYTES, "{} bytes", page.len());
}

/// A report whose first check has the given `observed`.
fn report_with_observed(
    observed: serde_json::Value,
    checks: usize,
) -> crate::redact::RedactedReport {
    use crate::redact::{Redactor, TagKey};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/reports/not-ready-7.2.json");
    let text = std::fs::read_to_string(path).expect("the sample report is in the repo");
    let mut doc: serde_json::Value = serde_json::from_str(&text).expect("the sample is JSON");
    let template = doc["checks"][0].clone();
    let list = doc["checks"].as_array_mut().expect("checks is a list");
    list.clear();
    for number in 0..checks {
        let mut check = template.clone();
        check["key"] = serde_json::json!(format!("host.cpu{number}"));
        check["observed"] = observed.clone();
        check["expected"] = serde_json::Value::Null;
        list.push(check);
    }
    let report = serde_json::from_value(doc).expect("a report");
    Redactor::new(TagKey::fixed([5; 32]))
        .redact_report(report)
        .expect("redacts")
}

/// Past the page cap, with no action rows left to cut, Found lines are cut, each check says how many
/// lines it lost, the page fits, and the embedded JSON is whole (07 D.4).
#[test]
fn a_page_still_over_its_cap_loses_found_lines_and_says_so() {
    let observed =
        serde_json::json!({"items": (0..40).map(|n| format!("item {n:03}")).collect::<Vec<_>>()});
    let report = report_with_observed(observed, 20);
    let mut view = super::view::View::new(&report).expect("fine");
    let whole = super::fit_page(&mut view, usize::MAX).expect("renders");
    // 800 fact lines, and the details list has `<dd>` too.
    let total = whole.matches("<dd>").count();
    assert!(total >= 800);
    assert!(!whole.contains("more lines are in the embedded JSON"));
    let max = whole.len() - 20_000;
    let mut view = super::view::View::new(&report).expect("fine");
    let page = super::fit_page(&mut view, max).expect("renders");
    assert!(page.len() <= max, "{} bytes is over {max}", page.len());
    let shown = page.matches("<dd>").count();
    assert!(shown > 0 && shown < total, "{shown} lines");
    assert!(
        page.contains("more lines are in the embedded JSON."),
        "no count"
    );
    // The counts add up: what is shown and what is left out are all 800 lines.
    let left_out: usize = page
        .split("<p class=\"muted\">")
        .skip(1)
        .filter_map(|rest| rest.split(" more line").next()?.parse::<usize>().ok())
        .sum();
    assert_eq!(shown + left_out, total);
    let json = |text: &str| text[text.find("id=\"rdy-result\"").expect("block")..].to_owned();
    assert_eq!(json(&page), json(&whole));
}

/// What the JSON writer cut is not on the page: a string over its 4 KiB cap shows the cut text, the same
/// text the embedded JSON holds (SEC-81).
#[test]
fn found_shows_what_the_json_holds_and_not_the_longer_text() {
    let observed = serde_json::json!({"text": format!("{}END", "a".repeat(10_000))});
    let report = report_with_observed(observed, 1);
    let page = super::render_html(&report).expect("renders");
    assert!(!page.contains("END"), "the page shows text the JSON cut");
    assert!(!page.contains(&"a".repeat(5_000)));
    assert!(page.contains(&"a".repeat(1_000)));
}

/// M1-141: every Unicode format (Cf) and zero-width character becomes an escape. Other text is kept.
#[test]
fn format_and_zero_width_characters_are_shown_as_escapes() {
    assert_eq!(shown("x\u{2069}\u{202e}"), "x\\u{2069}\\u{202e}");
    assert_eq!(shown("a\u{2066}b"), "a\\u{2066}b");
    for (c, text) in [
        ('\u{200b}', "\\u{200b}"),
        ('\u{200d}', "\\u{200d}"),
        ('\u{feff}', "\\u{feff}"),
        ('\u{2060}', "\\u{2060}"),
        ('\u{ad}', "\\u{ad}"),
        ('\u{61c}', "\\u{61c}"),
        ('\u{600}', "\\u{600}"),
        ('\u{6dd}', "\\u{6dd}"),
        ('\u{110bd}', "\\u{110bd}"),
        ('\u{e0041}', "\\u{e0041}"),
        ('\u{3164}', "\\u{3164}"),
    ] {
        assert_eq!(shown(&format!("a{c}b")), format!("a{text}b"), "{c:?}");
    }
    let kept = "caf\u{e9} \u{4e2d}\u{6587} \u{1f600} \\ \"q\" <b>\n\t";
    assert_eq!(shown(kept), kept);
    assert_eq!(shown(""), "");
}

/// A span from the report is escaped. Our own words are not touched.
#[test]
fn an_untrusted_span_is_escaped() {
    let spans = need_spans(&Need::Command, Some("a\u{202e}"));
    assert_eq!(plain(&spans), "the command a\\u{202e}");
    assert_eq!(
        need_spans(&Need::from("x\u{2066}"), None)[0].text,
        "x\\u{2066}"
    );
}
