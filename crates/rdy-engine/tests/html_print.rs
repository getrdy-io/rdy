//! The HTML report's print override, labels and legend (M1-079): the print stylesheet is black on white
//! and replaces the dark palette, no raw JSON key is visible text in the template, and the header says
//! the rule in plain words and "No blocks." when nothing blocks (01 section 6 item 2, 07 D.7).

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

use rdy_engine::redact::{Redactor, TagKey};
use rdy_engine::report::render_html;
use rdy_spec::result::Report;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sample() -> TestResult<Value> {
    let text =
        std::fs::read_to_string(repo_root().join("tests/fixtures/reports/not-ready-7.2.json"))?;
    Ok(serde_json::from_str(&text)?)
}

fn html_of(doc: Value) -> TestResult<String> {
    let report: Report = serde_json::from_value(doc)?;
    let redacted = Redactor::new(TagKey::fixed([5; 32])).redact_report(report)?;
    Ok(render_html(&redacted)?)
}

/// The sample with every check that has status `block` taken out.
fn no_blocks_doc() -> TestResult<Value> {
    let mut doc = sample()?;
    doc["checks"]
        .as_array_mut()
        .ok_or("checks is not a list")?
        .retain(|check| check["status"] != "block");
    Ok(doc)
}

/// The text between the braces of the block that starts with `head` (nested braces counted).
fn block<'a>(css: &'a str, head: &str) -> TestResult<&'a str> {
    let start = css
        .find(head)
        .ok_or_else(|| format!("{head:?} is not in the CSS"))?
        + head.len();
    let mut depth = 1_usize;
    for (at, c) in css[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&css[start..start + at]);
                }
            }
            _ => {}
        }
    }
    Err(format!("{head:?} is never closed").into())
}

/// The value of custom property `name` in `css`, such as `#000000` for `--text`.
fn property<'a>(css: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}:");
    let (at, _) = css.match_indices(&key).find(|(i, _)| {
        // A whole name: `--text:` must not match inside `--banner-text:`.
        css[..*i]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'))
    })?;
    let rest = css[at + key.len()..].trim_start();
    Some(rest[..rest.find(';')?].trim())
}

/// Every custom property name set in `css`.
fn property_names(css: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = css;
    while let Some(at) = rest.find("--") {
        let tail = &rest[at..];
        let len = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(tail.len());
        if tail[len..].starts_with(':') {
            names.insert(tail[..len].to_owned());
        }
        rest = &tail[len..];
    }
    names
}

#[test]
fn print_is_black_on_white_and_replaces_the_dark_palette() -> TestResult {
    let html = html_of(sample()?)?;
    let start = html.find("<style>").ok_or("no style element")?;
    let end = html.find("</style>").ok_or("no end of style")?;
    let css = &html[start..end];

    let dark_head = "@media (prefers-color-scheme: dark) {";
    let print_head = "@media print {";
    let dark = block(css, dark_head)?;
    let print = block(css, print_head)?;
    // The print block comes after the dark one, so at equal weight it wins.
    assert!(css.find(dark_head) < css.find(print_head));

    assert_eq!(property(print, "--text"), Some("#000000"));
    assert_eq!(property(print, "--bg"), Some("#ffffff"));
    assert!(print.contains("color-scheme: light;"), "{print}");
    assert!(!print.contains("color-scheme: dark"), "{print}");
    assert_eq!(
        property(print, "--panel"),
        Some("#ffffff"),
        "no backgrounds"
    );
    assert_eq!(property(print, "--banner-bg"), Some("#ffffff"));

    // Every variable the dark palette sets is set again for print, to a different value.
    let dark_names = property_names(dark);
    assert!(!dark_names.is_empty());
    let print_names = property_names(print);
    for name in &dark_names {
        assert!(print_names.contains(name), "print does not reset {name}");
    }
    assert_eq!(property(dark, "--bg"), Some("#0d1117"));
    assert_ne!(property(dark, "--text"), property(print, "--text"));
    assert_ne!(property(dark, "--bg"), property(print, "--bg"));
    Ok(())
}

/// The visible text of an askama template: the `<style>` block, `{{ }}` and `{% %}` tags and the HTML
/// tags are removed, so what is left is what a reader would see in the page around the data.
fn visible_text(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while !rest.is_empty() {
        let close = if rest.starts_with("{{") {
            "}}"
        } else if rest.starts_with("{%") {
            "%}"
        } else if rest.starts_with('<') {
            ">"
        } else {
            let next = rest[1..].find(['<', '{']).map_or(rest.len(), |at| at + 1);
            out.push_str(&rest[..next]);
            rest = &rest[next..];
            continue;
        };
        let end = if rest.starts_with("<style") {
            // The CSS is not text: skip to the end of the element.
            rest.find("</style>").map_or(rest.len(), |at| at + 8)
        } else {
            rest.find(close).map_or(rest.len(), |at| at + close.len())
        };
        rest = &rest[end..];
        out.push(' ');
    }
    out
}

/// Raw JSON keys and engine words that are single English words, so a snake_case scan cannot find them.
/// The match is on whole lowercase words, so a label such as "Needs" or "Partial" is not one.
const ENGINE_WORDS: [&str; 12] = [
    "bucket",
    "observed",
    "expected",
    "severity",
    "status",
    "needs",
    "met",
    "capabilities",
    "partial",
    "serial",
    "actions",
    "truncated",
];

/// The words of `text` that are a raw key: anything in snake_case, or a name in [`ENGINE_WORDS`].
fn raw_keys(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| word.contains('_') || ENGINE_WORDS.contains(word))
        .map(str::to_owned)
        .collect()
}

#[test]
fn no_raw_json_key_is_visible_text_in_the_template() -> TestResult {
    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/report.html"),
    )?;
    let text = visible_text(&template);
    // The scan sees real words: the labels of 01 section 6 are there.
    for label in [
        "Requires:",
        "Fix:",
        "More from rdy:",
        "Run and spec details",
    ] {
        assert!(text.contains(label), "{label:?} is not in {text}");
    }
    assert_eq!(raw_keys(&text), Vec::<String>::new());
    Ok(())
}

#[test]
fn the_scan_finds_a_raw_key_when_there_is_one() {
    let bad = "<p class=\"skip_kind\">Found {{ x_bytes }} skip_kind and <b>severity</b></p><style>a_b{}</style>";
    let text = visible_text(bad);
    assert_eq!(raw_keys(&text), ["skip_kind", "severity"]);
    // Attributes, askama tags and the style block are not text.
    assert!(!text.contains("x_bytes") && !text.contains("a_b"));
}

#[test]
fn the_header_carries_the_legend_and_the_rule_in_plain_words() -> TestResult {
    let html = html_of(sample()?)?;
    let legend = "<p class=\"legend\">BLOCK: fix before install. WARN: fix if you can. SKIP: rdy could not check it.</p>";
    let rule = "<p class=\"rule\">NOT READY if anything blocks or a required check could not run. READY with warnings if only optional things are wrong. READY if every check ran and passed.</p>";
    let header_end = html.find("</header>").ok_or("no end of header")?;
    let header = &html[..header_end];
    let legend_at = header.find(legend).ok_or("no legend in the header")?;
    let rule_at = header.find(rule).ok_or("no rule in the header")?;
    // Both sit after the summary and before the line about hostnames.
    let summary = header.find("class=\"summary\"").ok_or("no summary")?;
    let privacy = header.find("class=\"privacy\"").ok_or("no privacy line")?;
    assert!(summary < legend_at && legend_at < rule_at && rule_at < privacy);
    Ok(())
}

#[test]
fn nothing_blocking_says_no_blocks_and_a_block_does_not() -> TestResult {
    let with_blocks = html_of(sample()?)?;
    assert!(!with_blocks.contains("No blocks"));
    assert!(with_blocks.contains("<h2 id=\"blocks\">"));

    let html = html_of(no_blocks_doc()?)?;
    assert!(!html.contains("<h2 id=\"blocks\">"));
    let header_end = html.find("</header>").ok_or("no end of header")?;
    let note = html
        .find("<p class=\"no-blocks\">No blocks.</p>")
        .ok_or("no note")?;
    let summary = html.find("class=\"summary\"").ok_or("no summary")?;
    assert!(summary < note && note < header_end);
    // The note is about blocks only: required checks that did not run still make it NOT READY.
    assert!(html.contains("<title>rdy report: NOT READY"));
    Ok(())
}
