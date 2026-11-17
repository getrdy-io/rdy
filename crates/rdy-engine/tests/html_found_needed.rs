//! The HTML report's Found and Needed lists, the footer link and the print padding (M1-081): sizes,
//! milliseconds and percents read as such, the one link out carries `ref=report` and the product and
//! nothing else, the fixed banner has room in print, and secrets planted in `observed` and `expected` show
//! as redaction markers and never as themselves (01 section 6, 07 D.4 and D.7; PR #149 security review).

use std::error::Error;
use std::path::Path;

use rdy_engine::redact::{Redactor, TagKey};
use rdy_engine::report::render_html;
use rdy_spec::result::Report;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn sample() -> TestResult<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/reports/not-ready-7.2.json");
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn html_of(doc: Value) -> TestResult<String> {
    let report: Report = serde_json::from_value(doc)?;
    let redacted = Redactor::new(TagKey::fixed([5; 32])).redact_report(report)?;
    Ok(render_html(&redacted)?)
}

/// The text from `from` up to and including the next `to`.
fn between<'a>(html: &'a str, from: &str, to: &str) -> TestResult<&'a str> {
    let start = html
        .find(from)
        .ok_or_else(|| format!("{from:?} is not in the page"))?;
    let len = html[start..]
        .find(to)
        .ok_or_else(|| format!("{to:?} does not follow {from:?}"))?;
    Ok(&html[start..start + len + to.len()])
}

/// The article of the check with `id`.
fn article<'a>(html: &'a str, id: &str) -> TestResult<&'a str> {
    let head = format!("<span class=\"id\"><bdi>{id}</bdi></span>");
    let at = html
        .find(&head)
        .ok_or_else(|| format!("{id} is not on the page"))?;
    let start = html[..at].rfind("<article").ok_or("no article")?;
    let len = html[at..].find("</article>").ok_or("no end of article")?;
    Ok(&html[start..at + len])
}

#[test]
fn bytes_ms_and_percent_print_as_sizes_milliseconds_and_percents() -> TestResult {
    let mut doc = sample()?;
    // `used_percent` is not in the sample: plant one beside the sizes and the milliseconds.
    doc["checks"][0]["observed"]["used_percent"] = json!(42.5);
    let html = html_of(doc)?;

    let memory = article(&html, "host.memory")?;
    // total_bytes 16496934912 and available_bytes 12884901888; min_bytes 34359738368.
    assert!(memory.contains("<dt><bdi>Total</bdi></dt>\n<dd><bdi>15.4 GiB</bdi></dd>"));
    assert!(memory.contains("<dd><bdi>12 GiB</bdi></dd>"));
    assert!(memory.contains("<dd><bdi>32 GiB</bdi></dd>"));
    assert!(!memory.contains("16496934912"));
    assert!(!memory.contains("total_bytes"));

    let egress = article(&html, "net.egress")?;
    assert!(
        egress.contains("<bdi>Connect</bdi>: <bdi>38 ms</bdi>"),
        "{egress}"
    );
    assert!(!egress.contains("connect_ms"));

    let cpu = article(&html, "host.cpu")?;
    assert!(cpu.contains("<dd><bdi>42.5%</bdi></dd>"));
    // A plain number stays a number, and a list is one line per item.
    assert!(cpu.contains("<dt><bdi>Logical cores</bdi></dt>\n<dd><bdi>8</bdi></dd>"));
    let disk = article(&html, "host.disk")?;
    assert!(disk.contains("<dd><bdi>rw</bdi></dd>\n<dd><bdi>relatime</bdi></dd>"));
    // The two lists are labelled.
    assert!(memory.contains("<p class=\"label\">Found</p>"));
    assert!(memory.contains("<p class=\"label\">Needed</p>"));
    Ok(())
}

#[test]
fn a_check_with_nothing_observed_has_no_lists() -> TestResult {
    let mut doc = sample()?;
    doc["checks"][0]["observed"] = Value::Null;
    doc["checks"][0]["expected"] = json!({});
    let html = html_of(doc)?;
    let cpu = article(&html, "host.cpu")?;
    assert!(!cpu.contains("Found") && !cpu.contains("Needed"), "{cpu}");
    Ok(())
}

/// Every `href` value on the page, in order.
fn hrefs(html: &str) -> Vec<String> {
    html.split(" href=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_footer_link_has_only_ref_report_and_the_product() -> TestResult {
    let html = html_of(sample()?)?;
    let footer = between(&html, "<footer>", "</footer>")?;
    // askama writes `&` in an attribute as `&#38;`.
    let link = "https://getrdy.io/?ref=report&#38;product=acme-platform";
    assert!(
        footer.contains(&format!(
            "<a href=\"{link}\" rel=\"noopener noreferrer\">{link}</a>"
        )),
        "{footer}"
    );
    assert!(footer.contains("This link carries the product name and nothing else."));
    assert!(footer.contains(
        "<a href=\"https://github.com/getrdy-io/rdy\" rel=\"noopener noreferrer\">\
         https://github.com/getrdy-io/rdy</a>"
    ));
    // Outside the page there are two links, and no other. No version, host, date or run id is in either.
    let outside: Vec<String> = hrefs(&html)
        .into_iter()
        .filter(|href| !href.starts_with('#'))
        .collect();
    assert_eq!(
        outside,
        [
            "https://getrdy.io/?ref=report&#38;product=acme-platform",
            "https://github.com/getrdy-io/rdy"
        ]
    );
    assert_eq!(html.matches("rel=\"noopener noreferrer\"").count(), 2);
    assert_eq!(html.matches("getrdy.io/").count(), 2);
    Ok(())
}

#[test]
fn a_hostile_product_cannot_add_a_parameter_or_markup_to_the_link() -> TestResult {
    let mut doc = sample()?;
    doc["spec"]["product"] = json!("a b&host=x\"><i>\u{202e}é");
    let html = html_of(doc)?;
    let footer = between(&html, "<footer>", "</footer>")?;
    let link =
        "https://getrdy.io/?ref=report&#38;product=a%20b%26host%3Dx%22%3E%3Ci%3E%E2%80%AE%C3%A9";
    assert!(footer.contains(&format!("href=\"{link}\"")), "{footer}");
    assert!(!footer.contains("host=x"));
    assert!(!footer.contains("<i>"));
    Ok(())
}

/// The banners stay in the flow in print: no fixed box can cover the first lines of a later page. A
/// fixed banner was tried and does not print right (see the CSS comment).
#[test]
fn the_banners_stay_in_the_flow_in_print() -> TestResult {
    let mut doc = sample()?;
    doc["signature"] = json!({"state": "unsigned"});
    doc["complete"] = json!(false);
    let html = html_of(doc)?;
    assert_eq!(html.matches("<div class=\"banner\">").count(), 2);
    let style = html.find("<style>").ok_or("no style")?;
    let css = &html[style..html.find("</style>").ok_or("no end of style")?];
    let print = &css[css.find("@media print {").ok_or("no print block")?..];
    assert!(!css.contains("position: fixed"), "{css}");
    assert!(!print.contains("padding-top"), "{print}");
    assert!(!html.contains("--banner-height"));
    // Every printed page carries the banner titles in its top margin, so page 2 still says the spec was
    // not verified. The words are ours: a hostile spec file name is not in the rule.
    assert!(css.contains(
        "@page { margin-top: 2cm; @top-center { content: \"WARNING: UNSIGNED SPEC / INCOMPLETE\";"
    ));
    let mut doc = sample()?;
    doc["signature"] = json!({"state": "unsigned"});
    doc["spec"]["file_name"] = json!("evil\"; } } x{y:z");
    let hostile = html_of(doc)?;
    let rule = between(&hostile, "@page {", "#000000; } }")?;
    assert!(
        rule.contains("WARNING: UNSIGNED SPEC") && !rule.contains("evil"),
        "{rule}"
    );
    // A key given for one run, alone: its own title. An incomplete run, alone: its own title.
    let mut doc = sample()?;
    doc["signature"]["trust_source"] = json!("flag");
    let page = html_of(doc)?;
    assert!(page.contains("content: \"WARNING: KEY NOT PINNED\";"));
    assert!(!page.contains("INCOMPLETE"));
    let mut doc = sample()?;
    doc["complete"] = json!(false);
    let page = html_of(doc)?;
    assert!(page.contains("content: \"INCOMPLETE\";"));
    assert!(!page.contains("WARNING: "));
    // No banner, no rule.
    assert!(!html_of(sample()?)?.contains("@page"));
    Ok(())
}

/// The secrets of the M1-081 exit test. Each is planted in `observed` or `expected` of `host.cpu`.
const CANARIES: [&str; 8] = [
    "canary-found-key-1",
    "canary-found-env-2",
    "canary-found-argv-3",
    "canary-found-hdr-4",
    "canary-found-text-5",
    "canary-found-kube-6",
    "canary-found-exp-7",
    "canary-found-exp-8",
];

/// Canaries planted in `observed` and `expected` render as redacted text (PR #149 security review).
///
/// The test is not vacuous in three ways. Each canary is in the input, as JSON text and as a field of the
/// parsed report. None is on the page. And the page shows the redaction marker where each one was, in the
/// Found and Needed lists, next to the values that were not secret.
#[test]
fn canaries_planted_in_observed_and_expected_render_as_redacted_text() -> TestResult {
    let mut doc = sample()?;
    // The input is shared with the raw-map control in `view/facts.rs`.
    let planted: Value =
        serde_json::from_str(include_str!("../src/report/html/view/found-canaries.json"))?;
    doc["checks"][0]["observed"] = planted["observed"].clone();
    doc["checks"][0]["expected"] = planted["expected"].clone();

    // The canaries are in the input, as text and as fields of the report the engine reads.
    let input = serde_json::to_string(&doc)?;
    let report: Report = serde_json::from_value(doc.clone())?;
    let read = serde_json::to_string(&(&report.checks[0].observed, &report.checks[0].expected))?;
    for canary in CANARIES {
        assert!(input.contains(canary), "{canary} is not in the input");
        assert!(read.contains(canary), "{canary} is not in the report");
    }

    let html = html_of(doc)?;
    for canary in CANARIES {
        assert!(!html.contains(canary), "{canary} reached the page");
    }

    // The lists are on the page, with a marker where each secret was and the other values intact.
    let cpu = article(&html, "host.cpu")?;
    let found = between(cpu, "<p class=\"label\">Found</p>", "</dl>")?;
    let needed = between(cpu, "<p class=\"label\">Needed</p>", "</dl>")?;
    assert!(found.contains("<dd><bdi>x86_64</bdi></dd>"), "{found}");
    assert!(found.contains("/home/synthetic"), "{found}");
    assert!(needed.contains("<dd><bdi>8</bdi></dd>"), "{needed}");
    // Each marker is where its canary was.
    for (list, line) in [
        (
            found,
            "<dt><bdi>API password</bdi></dt>\n<dd><bdi>[REDACTED:",
        ),
        (found, "<bdi>Value</bdi>: <bdi>[REDACTED:"),
        (found, "<dd><bdi>--password</bdi></dd>\n<dd><bdi>[REDACTED:"),
        (found, "<bdi>Token</bdi>: <bdi>[REDACTED:"),
        (
            found,
            "<dt><bdi>Log</bdi></dt>\n<dd><bdi>Authorization: Bearer [REDACTED:",
        ),
        (found, "<dt><bdi>Note</bdi></dt>\n<dd><bdi>token=[REDACTED:"),
        (
            needed,
            "<dt><bdi>Client secret</bdi></dt>\n<dd><bdi>[REDACTED:",
        ),
        (needed, "<dd><bdi>--token</bdi></dd>\n<dd><bdi>[REDACTED:"),
    ] {
        assert!(list.contains(line), "{line:?} is not in {list}");
    }
    // One marker at least for each canary.
    let all = found.matches("[REDACTED:").count() + needed.matches("[REDACTED:").count();
    assert!(all >= CANARIES.len(), "{all} markers in {found} {needed}");
    Ok(())
}

/// A bidi control in a key or a value stays inside its own `<bdi>` (07 D.7).
#[test]
fn a_bidi_control_in_a_key_or_a_value_stays_in_its_own_isolate() -> TestResult {
    let mut doc = sample()?;
    doc["checks"][0]["observed"] = json!({"x\u{2069}\u{202e}": "y\u{2069}\u{202e}"});
    let html = html_of(doc)?;
    let cpu = article(&html, "host.cpu")?;
    assert!(
        cpu.contains(
            "<dt><bdi>X\u{2069}\u{202e}</bdi></dt>\n<dd><bdi>y\u{2069}\u{202e}</bdi></dd>"
        )
    );
    Ok(())
}

/// The check ids that sit under "Required checks not run" in the sample are skipped with severity block.
fn required_not_run_article(html: &str) -> TestResult<&str> {
    let section = between(html, "<h2 id=\"required-not-run\">", "</section>")?;
    Ok(section)
}

/// A required check that did not run says who requires it: the product when the signature is verified and
/// the key pinned, else "the spec file" (01 section 6, 07 D.7). The product is untrusted.
#[test]
fn a_required_check_that_did_not_run_says_who_requires_it() -> TestResult {
    // Verified and pinned: the product, in its own isolate.
    let mut doc = sample()?;
    doc["spec"]["product"] = json!("acme\u{202e}-platform");
    let html = html_of(doc)?;
    let section = required_not_run_article(&html)?;
    assert!(
        section.contains("<p>required by <bdi>acme\u{202e}-platform</bdi></p>"),
        "{section}"
    );
    assert!(!section.contains("required by the spec file"));
    // Not pinned (a key given for one run) and unsigned: the spec file, and no product name.
    for signature in [json!("flag"), json!("unsigned")] {
        let mut doc = sample()?;
        if signature == json!("unsigned") {
            doc["signature"] = json!({"state": "unsigned"});
        } else {
            doc["signature"]["trust_source"] = signature;
        }
        let html = html_of(doc)?;
        let section = required_not_run_article(&html)?;
        assert!(
            section.contains("<p>required by the spec file</p>"),
            "{section}"
        );
        assert!(!section.contains("required by <bdi>"), "{section}");
    }
    // Only a required check that did not run has the line: not a block, a warning or a pass.
    let html = html_of(sample()?)?;
    assert_eq!(
        html.matches("required by ").count(),
        required_not_run_article(&html)?
            .matches("<p>required by ")
            .count()
    );
    Ok(())
}

/// In print a page break comes before the action log, as before Passed and the capabilities (07 D.3).
#[test]
fn print_breaks_the_page_before_the_action_log() -> TestResult {
    let html = html_of(sample()?)?;
    let print = &html[html.find("@media print {").ok_or("no print block")?..];
    assert!(print.contains("#passed, #capabilities, #actions { break-before: page; }"));
    assert!(html.contains("<h2 id=\"actions\">"));
    Ok(())
}
