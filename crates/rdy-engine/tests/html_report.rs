//! The HTML report (M1-077): what is first on the page, one section per `group_by_bucket` group in that
//! order, the credential plugin in the run details, untrusted text shown as text, and two goldens.
//!
//! Every report goes through a real redactor first, because the renderer takes nothing else. The base is
//! the 01 section 7.2 sample at `tests/fixtures/reports/not-ready-7.2.json`.
//!
//! The exit test says the page passes an HTML validator. The CI job `html-validator` runs the Nu HTML
//! Checker over the two goldens (`scripts/validate-html.sh`). `well_formed` below is
//! the smoke test that runs on all five legs: the doctype, `lang`, `color-scheme`, balanced tags, void
//! elements and unique ids. The structure test (M1-082) goes further.
//!
//! The embedded result (M1-078, SEC-64) is tested at the end: the text of the `<script>` element is the
//! bytes of the `.json` file, the hash on it is their SHA-256, and a hostile hostname cannot close it.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

use rdy_engine::redact::{RedactedReport, Redactor, TagKey};
use rdy_engine::report::{HtmlError, JsonError, json_bytes, read_report, render_html};
use rdy_engine::testing::{fixtures_dir, golden::assert_golden};
use rdy_spec::result::{Bucket, Report, group_by_bucket};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sample() -> TestResult<Value> {
    let text =
        std::fs::read_to_string(repo_root().join("tests/fixtures/reports/not-ready-7.2.json"))?;
    Ok(serde_json::from_str(&text)?)
}

fn redact(doc: Value) -> TestResult<RedactedReport> {
    let report: Report = serde_json::from_value(doc)?;
    Ok(Redactor::new(TagKey::fixed([5; 32])).redact_report(report)?)
}

fn html_of(doc: Value) -> TestResult<String> {
    Ok(render_html(&redact(doc)?)?)
}

/// The sample, with a check the spec's `os` list leaves out, so every bucket has a check, and a kubeconfig
/// credential plugin.
fn five_buckets_doc() -> TestResult<Value> {
    let mut doc = sample()?;
    doc["identity"]["kube"]["exec_plugin"] = json!("aws");
    let mut check = doc["checks"][0].clone();
    check["key"] = json!("win.defender");
    check["id"] = json!("win.defender");
    check["family"] = json!("win");
    check["severity"] = json!("block");
    check["status"] = json!("skipped");
    check["bucket"] = json!("not_applicable");
    check["skip_kind"] = json!("not_applicable");
    check["message"] = json!("Does not apply on Linux.");
    check["observed"] = Value::Null;
    check["expected"] = Value::Null;
    doc["checks"]
        .as_array_mut()
        .ok_or("checks is not a list")?
        .push(check);
    Ok(doc)
}

/// Where `needle` first occurs, or a failure that names it.
fn at(html: &str, needle: &str) -> TestResult<usize> {
    html.find(needle)
        .ok_or_else(|| format!("{needle:?} is not in the page").into())
}

/// The ids of the section headings, in page order.
fn section_ids(html: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<h2 id=\"") {
        let after = &rest[start + "<h2 id=\"".len()..];
        let end = after.find('"').unwrap_or(after.len());
        ids.push(after[..end].to_owned());
        rest = &after[end..];
    }
    ids
}

/// A page-sized stand in for an HTML validator. Returns the problems it found.
fn well_formed(html: &str) -> Vec<String> {
    const VOID: [&str; 6] = ["meta", "link", "br", "hr", "img", "input"];
    let mut problems = Vec::new();
    if !html.starts_with("<!DOCTYPE html>\n") {
        problems.push("no doctype first".to_owned());
    }
    if !html.contains("<html lang=\"en\">") {
        problems.push("no lang=\"en\" on html".to_owned());
    }
    if !html.contains("<meta name=\"color-scheme\" content=\"light dark\">") {
        problems.push("no color-scheme meta".to_owned());
    }
    let mut stack: Vec<String> = Vec::new();
    let mut ids = BTreeSet::new();
    let mut i = 0;
    while let Some(open) = html[i..].find('<') {
        let start = i + open;
        let Some(len) = tag_end(&html[start..]) else {
            problems.push(format!("a tag at byte {start} never ends"));
            return problems;
        };
        let tag = &html[start + 1..start + len - 1];
        i = start + len;
        if tag.starts_with('!') {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            match stack.pop() {
                Some(top) if top == name.trim() => {}
                other => problems.push(format!("</{name}> closes {other:?}")),
            }
            continue;
        }
        let name: String = tag
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if let Some(id) = attribute(tag, "id")
            && !ids.insert(id.clone())
        {
            problems.push(format!("the id {id:?} is used twice"));
        }
        if name == "style" {
            // The CSS holds `>` and `<` text that is not markup.
            match html[i..].find("</style>") {
                Some(end) => i += end,
                None => problems.push("style never ends".to_owned()),
            }
        }
        if !VOID.contains(&name.as_str()) {
            stack.push(name);
        }
    }
    if !stack.is_empty() {
        problems.push(format!("never closed: {stack:?}"));
    }
    problems
}

/// The length of the tag that starts `text`, counting quoted `>` as text.
fn tag_end(text: &str) -> Option<usize> {
    let mut quote = None;
    for (at, c) in text.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => return Some(at + 1),
            _ => {}
        }
    }
    None
}

/// The value of the double-quoted attribute `name` in `tag`.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let key = format!(" {name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = tag[start..].find('"')?;
    Some(tag[start..start + end].to_owned())
}

#[test]
fn the_page_is_well_formed_for_the_sample_and_for_five_sections() -> TestResult {
    for doc in [sample()?, five_buckets_doc()?] {
        let html = html_of(doc)?;
        assert_eq!(well_formed(&html), Vec::<String>::new());
    }
    Ok(())
}

#[test]
fn the_page_sets_the_csp_lang_color_scheme_and_loads_nothing() -> TestResult {
    let html = html_of(sample()?)?;
    assert!(html.contains(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; \
         img-src data:; base-uri 'none'; form-action 'none'\">"
    ));
    // The head and the CSS hold no way to load anything. The body shows URLs from the machine as text.
    let (head, body) = html.split_at(at(&html, "<body>")?);
    for forbidden in [
        "<link", "<script", "@import", "url(", " src=", "http://", "https://",
    ] {
        assert!(!head.contains(forbidden), "{forbidden:?} is in the head");
    }
    for forbidden in ["<link", " src="] {
        assert!(!body.contains(forbidden), "{forbidden:?} is in the body");
    }
    // The only script element is the data block of the embedded result. Its type is not JavaScript, so a
    // browser never runs it, and the CSP above has no `script-src` anyway.
    assert_eq!(html.matches("<script").count(), 1);
    assert!(body.contains(OPEN));
    // Every link either stays inside the page or says `rel="noopener noreferrer"` (ADR 0003 decision 8).
    for part in html.split("<a ").skip(1) {
        let tag = format!(" {}", &part[..part.find('>').unwrap_or(part.len())]);
        let href = attribute(&tag, "href").ok_or("a link has no href")?;
        if !href.starts_with('#') {
            assert_eq!(
                attribute(&tag, "rel").as_deref(),
                Some("noopener noreferrer"),
                "an outside link has no rel: {tag}"
            );
        }
    }
    // The page has no event handler and no `javascript:` URL.
    for forbidden in [" onerror=", " onclick=", " onload=", "javascript:"] {
        assert!(!html.contains(forbidden), "{forbidden:?} is on the page");
    }
    Ok(())
}

#[test]
fn the_verdict_and_the_blocks_come_first() -> TestResult {
    let html = html_of(sample()?)?;
    assert!(html.contains("<title>rdy report: NOT READY, \u{2068}acme-platform\u{2069}</title>"));
    let h1 = at(&html, "<h1>")?;
    let blocks = at(&html, "<h2 id=\"blocks\">")?;
    let required = at(&html, "<h2 id=\"required-not-run\">")?;
    let warnings = at(&html, "<h2 id=\"warnings\">")?;
    let passed = at(&html, "<h2 id=\"passed\">")?;
    assert!(at(&html, "<header>")? < h1);
    assert!(h1 < blocks && blocks < required && required < warnings && warnings < passed);
    // The verdict word is in the h1, and a block check comes right after its section heading.
    assert!(html[h1..blocks].contains("NOT READY"));
    let first_check = at(&html[blocks..], "<h3>")? + blocks;
    assert!(html[first_check..].starts_with("<h3><span class=\"status\">BLOCK</span>"));
    // The sample is pinned and complete, so nothing sits above the header.
    assert!(!html[..at(&html, "<header>")?].contains("class=\"banner\""));
    Ok(())
}

#[test]
fn the_verdict_is_worked_out_from_the_checks_and_not_read_from_the_file() -> TestResult {
    let mut doc = sample()?;
    doc["verdict"] = json!("ready");
    doc["exit_code"] = json!(0);
    let html = html_of(doc)?;
    assert!(html.contains("<title>rdy report: NOT READY, \u{2068}acme-platform\u{2069}</title>"));
    assert!(html.contains("1 warning"));
    Ok(())
}

#[test]
fn there_is_one_section_per_group_in_group_by_bucket_order() -> TestResult {
    let report = redact(five_buckets_doc()?)?;
    let html = render_html(&report)?;
    let groups = group_by_bucket(&report.checks);
    let expected: Vec<&str> = groups
        .iter()
        .map(|group| match group.bucket {
            Bucket::Blocker => "blocks",
            Bucket::RequiredNotRun => "required-not-run",
            Bucket::Warning => "warnings",
            Bucket::Passed => "passed",
            Bucket::NotApplicable => "not-applicable",
            _ => "unexpected",
        })
        .collect();
    assert_eq!(
        expected,
        [
            "blocks",
            "required-not-run",
            "warnings",
            "passed",
            "not-applicable"
        ]
    );
    let ids: Vec<String> = section_ids(&html)
        .into_iter()
        .filter(|id| expected.contains(&id.as_str()))
        .collect();
    assert_eq!(ids, expected);
    // Inside a section the checks keep spec order, and each one is in the section of its group.
    let mut cursor = 0;
    for (group, id) in groups.iter().zip(&expected) {
        let start = at(&html, &format!("<h2 id=\"{id}\">"))?;
        assert!(start >= cursor);
        let end = html[start + 1..]
            .find("<h2 ")
            .map_or(html.len(), |next| start + 1 + next);
        let mut last = start;
        for check in &group.checks {
            let needle = format!("<bdi>{}</bdi>", check.id);
            let position = at(&html[start..end], &needle)? + start;
            assert!(position >= last, "{} is out of spec order", check.id);
            last = position;
        }
        cursor = end;
    }
    Ok(())
}

#[test]
fn a_group_with_no_checks_has_no_section() -> TestResult {
    let html = html_of(sample()?)?;
    assert_eq!(
        section_ids(&html)
            .iter()
            .filter(|id| id.as_str() == "not-applicable")
            .count(),
        0
    );
    assert!(!html.contains("Does not apply here"));
    Ok(())
}

#[test]
fn a_bucket_this_version_does_not_know_sits_with_the_required_checks_not_run() -> TestResult {
    let mut doc = sample()?;
    let mut check = doc["checks"][0].clone();
    check["id"] = json!("future.thing");
    check["key"] = json!("future.thing");
    check["bucket"] = json!("something_new");
    doc["checks"]
        .as_array_mut()
        .ok_or("checks is not a list")?
        .push(check);
    let html = html_of(doc)?;
    let required = at(&html, "<h2 id=\"required-not-run\">")?;
    let warnings = at(&html, "<h2 id=\"warnings\">")?;
    let future = at(&html, "<bdi>future.thing</bdi>")?;
    assert!(required < future && future < warnings);
    Ok(())
}

#[test]
fn the_run_details_show_the_credential_plugin_name() -> TestResult {
    let html = html_of(five_buckets_doc()?)?;
    assert!(html.contains("<dt>Credential plugin</dt>\n<dd><bdi>aws</bdi></dd>"));
    // With no plugin the row is left out, so a reader never sees an empty answer.
    assert!(!html_of(sample()?)?.contains("Credential plugin"));
    // `insecure_tls` is the other kubeconfig fact the details must carry (01 section 6 item 6).
    let mut doc = sample()?;
    doc["identity"]["kube"]["insecure_tls"] = json!(true);
    assert!(html_of(doc)?.contains("<dt>TLS certificate checks</dt>\n<dd><bdi>skipped</bdi></dd>"));
    Ok(())
}

#[test]
fn untrusted_text_is_shown_as_text() -> TestResult {
    let mut doc = sample()?;
    doc["host"]["hostname"] = json!("</script><img onerror=x>&amp;");
    doc["checks"][1]["message"] = json!("<b>bold</b> \"quoted\" 'single'");
    doc["checks"][1]["fix"] = json!("<a href=\"https://evil.example/\">click</a>");
    doc["spec"]["version"] = json!("<i>1</i>");
    let html = html_of(doc)?;
    assert!(html.contains("&#60;/script&#62;&#60;img onerror=x&#62;&#38;amp;"));
    assert!(html.contains("&#60;b&#62;bold&#60;/b&#62; &#34;quoted&#34; &#39;single&#39;"));
    assert!(html.contains("&#60;a href=&#34;https://evil.example/&#34;&#62;click&#60;/a&#62;"));
    for raw in ["<img onerror", "<b>bold", "<i>1", "evil.example/\">"] {
        assert!(!html.contains(raw), "{raw:?} reached the page as markup");
    }
    assert_eq!(well_formed(&html), Vec::<String>::new());
    Ok(())
}

/// The HTML half of the M1-056 exit test (PC-43, carried by M1-062): the canaries of the JSON test never
/// reach the page, and neither do canaries planted in the free text the page does show.
///
/// The page does not show `observed`, `expected` or the action log yet (M1-080 and M1-081 add them), so
/// the first group is a check on those two tickets as much as on this one: it must keep passing when they
/// land. A password inside a proxy URL is not planted: the URL rule is M1-060's and the known-secret
/// registration of the proxy password is M1-091's.
#[test]
fn canaries_never_reach_the_page() -> TestResult {
    const CANARIES: [&str; 11] = [
        "canary-env-token-2",
        "canary-kube-token-3",
        "canary-kube-text-3b",
        "canary-output-hdr-4",
        "canary-argv-5",
        "canary-action-argv-6",
        "canary-Zk3v9Qx7-host",
        "canary-Zk3v9Qx7-msg",
        "canary-Zk3v9Qx7-note",
        "canary-Zk3v9Qx7-fix",
        "canary-Zk3v9Qx7-part",
    ];
    let mut doc = five_buckets_doc()?;
    doc["checks"][0]["observed"] = json!({
        "env": [
            {"name": "API_TOKEN", "value": "canary-env-token-2"},
            {"name": "HOME", "value": "/home/synthetic"},
        ],
        "kubeconfig": {"users": [{"name": "synthetic", "user": {"token": "canary-kube-token-3"}}]},
        "kubeconfig_text":
            "users:\n- name: synthetic\n  user:\n    token: canary-kube-text-3b\n",
        "stdout": "Authorization: Bearer canary-output-hdr-4\nok",
        "cmdline": ["kubectl", "--token", "canary-argv-5"],
    });
    doc["actions"][0]["argv"] = json!(["/usr/bin/tool", "--password", "canary-action-argv-6"]);
    doc["host"]["hostname"] = json!("web-01 password=canary-Zk3v9Qx7-host");
    doc["checks"][1]["message"] = json!("failed, token=canary-Zk3v9Qx7-msg was sent");
    doc["checks"][1]["notes"] = json!(["secret=canary-Zk3v9Qx7-note"]);
    doc["checks"][1]["fix"] = json!("run it with password=canary-Zk3v9Qx7-fix");
    doc["checks"][2]["partial"] = json!({
        "missing": ["root"],
        "missing_grants": [],
        "note": "token=canary-Zk3v9Qx7-part",
    });
    let html = html_of(doc)?;
    for canary in CANARIES {
        assert!(!html.contains(canary), "{canary} reached the page");
    }
    // The planted fields are still shown, with the secret replaced, so the test is not passing because
    // the page left the fields out.
    assert!(html.contains("web-01 password="));
    assert!(html.contains("failed, token="));
    // The note, the fix and the partial note are shown too, with the secret replaced (SEC-149-5).
    assert!(html.contains("<bdi>secret="));
    assert!(html.contains("<bdi>run it with password="));
    assert!(html.contains("<bdi>token="));
    Ok(())
}

#[test]
fn the_unsigned_banner_comes_before_the_header() -> TestResult {
    let mut doc = sample()?;
    doc["signature"] = json!({ "state": "unsigned" });
    let html = html_of(doc)?;
    let banner = at(&html, "WARNING: UNSIGNED SPEC")?;
    assert!(banner < at(&html, "<header>")?);
    assert!(html.contains("This report is marked UNSIGNED SPEC."));
    assert!(!html.contains("KEY NOT PINNED"));
    Ok(())
}

/// SEC-149-4: a file name with a bidi control must not reorder the security warning around it.
#[test]
fn the_banner_shows_the_spec_file_name_in_its_own_isolate() -> TestResult {
    let mut doc = sample()?;
    doc["signature"] = json!({ "state": "unsigned" });
    doc["spec"]["file_name"] = json!("evil\u{202e}.yaml");
    let html = html_of(doc)?;
    assert!(html.contains(
        "<p><bdi>evil\u{202e}.yaml</bdi> has no signature. rdy cannot tell who wrote it or whether it was changed.</p>"
    ));
    Ok(())
}

/// The sentences of 01 section 4.7 for an unsigned spec, as the page prints them.
#[test]
fn the_unsigned_banner_uses_the_wording_of_section_4_7() -> TestResult {
    let mut doc = sample()?;
    doc["signature"] = json!({ "state": "unsigned" });
    let html = html_of(doc)?;
    assert!(
        html.contains(" has no signature. rdy cannot tell who wrote it or whether it was changed.")
    );
    assert!(!html.contains("no verified signature"));
    Ok(())
}

/// SEC-149-4: the other untrusted text that sits in a sentence is in `<bdi>` too.
#[test]
fn text_from_the_report_inside_a_sentence_is_isolated() -> TestResult {
    let mut doc = sample()?;
    doc["producer"]["version"] = json!("1.0\u{202e}x");
    let html = html_of(doc)?;
    assert!(html.contains("with rdy <bdi>1.0\u{202e}x</bdi>"));
    assert!(html.contains("<p>rdy <bdi>1.0\u{202e}x</bdi></p>"));
    assert!(html.contains("<p>Run <bdi>2026-12-01 14:30:05 UTC</bdi> with rdy"));
    Ok(())
}

#[test]
fn a_key_given_for_one_run_shows_the_not_pinned_banner_with_a_short_fingerprint() -> TestResult {
    let mut doc = sample()?;
    doc["signature"]["trust_source"] = json!("flag");
    let html = html_of(doc)?;
    assert!(at(&html, "WARNING: KEY NOT PINNED")? < at(&html, "<header>")?);
    assert!(html.contains("(fingerprint <bdi>4d2a7c0e...0a1c</bdi>)"));
    assert!(!html.contains("UNSIGNED SPEC"));
    Ok(())
}

#[test]
fn an_unfinished_run_shows_the_incomplete_banner() -> TestResult {
    let mut doc = sample()?;
    doc["complete"] = json!(false);
    let html = html_of(doc)?;
    assert!(at(&html, "INCOMPLETE")? < at(&html, "<header>")?);
    assert!(html.contains("rdy stopped before every check finished."));
    Ok(())
}

/// Code 3 of PR #149: the not-run reason, the partial summary and `Requires:` keep our own words outside
/// `<bdi>`, so a bidi control in a grant or a need name stays inside its own isolate.
#[test]
fn only_the_untrusted_words_of_a_reason_and_a_summary_are_isolated() -> TestResult {
    let mut doc = sample()?;
    doc["checks"][2]["partial"] = json!({
        "missing": ["root"],
        "missing_grants": ["list nodes\u{202e}"],
        "note": "",
    });
    doc["checks"][7]["skip_kind"] = json!("missing_need");
    doc["checks"][7]["needs"] = json!([
        { "need": "command", "name": "ss\u{202e}", "hard": true, "met": false }
    ]);
    let html = html_of(doc)?;
    assert!(html.contains(
        "<p>Checked in part. Could not read: root, <bdi>list nodes\u{202e}</bdi>. The result may be incomplete.</p>"
    ));
    assert!(html.contains("<p>Missing: the command <bdi>ss\u{202e}</bdi></p>"));
    assert!(html.contains("<p>Requires: the command <bdi>ss\u{202e}</bdi> (not available)</p>"));
    Ok(())
}

#[test]
fn the_same_report_gives_the_same_bytes() -> TestResult {
    let report = redact(five_buckets_doc()?)?;
    assert_eq!(render_html(&report)?, render_html(&report)?);
    Ok(())
}

#[test]
fn not_run_checks_say_why_and_what_they_needed() -> TestResult {
    let html = html_of(sample()?)?;
    assert!(html.contains("<p>Not in this version of rdy</p>"));
    assert!(html.contains("<p>Requires: network access (available)</p>"));
    Ok(())
}

/// The report as the sample has it: blocks, required checks not run, a warning and passes. Compared byte
/// for byte, so a change to the markup or the CSS shows in review.
#[test]
fn the_sample_matches_its_golden() -> TestResult {
    assert_golden(
        fixtures_dir().join("reports/golden/not-ready-7.2.html"),
        html_of(sample()?)?.as_bytes(),
    );
    Ok(())
}

/// All five sections in order, and a credential plugin in the run details.
#[test]
fn all_five_sections_match_their_golden() -> TestResult {
    assert_golden(
        fixtures_dir().join("reports/golden/five-sections-exec-plugin.html"),
        html_of(five_buckets_doc()?)?.as_bytes(),
    );
    Ok(())
}

// ---- The embedded result (M1-078) ----

const OPEN: &str = "<script type=\"application/json\" id=\"rdy-result\" data-sha256=\"";

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The `data-sha256` value and the text of the one result element: what an importer would read.
fn embedded(html: &str) -> TestResult<(String, String)> {
    let start = at(html, OPEN)? + OPEN.len();
    let quote = html[start..]
        .find("\">")
        .ok_or("the attribute never ends")?;
    let hash = html[start..start + quote].to_owned();
    let text_start = start + quote + 2;
    let end = html[text_start..]
        .find("</script>")
        .ok_or("the element never ends")?;
    Ok((hash, html[text_start..text_start + end].to_owned()))
}

/// A hostname that tries to close the element, open another and end the line in a script.
const HOSTILE: &str = "</script><img onerror=x>&amp;\u{2028}end</SCRIPT x><!--<ScRiPt>\u{2029}";

/// The ticket's exit test: the hostname comes back unchanged from the embedded JSON, and on the page it is
/// text.
#[test]
fn a_hostname_that_closes_the_script_round_trips_through_the_embedded_json() -> TestResult {
    let mut doc = sample()?;
    doc["host"]["hostname"] = json!(HOSTILE);
    let report = redact(doc)?;
    let html = render_html(&report)?;

    // One element, and nothing in the text can end it, in any case.
    let lower = html.to_ascii_lowercase();
    assert_eq!(lower.matches("<script").count(), 1);
    assert_eq!(lower.matches("</script").count(), 1);
    let (hash, text) = embedded(&html)?;
    assert!(!text.contains(['<', '>', '&', '\u{2028}', '\u{2029}']));
    assert!(
        text.contains("\\u003c/script\\u003e\\u003cimg onerror=x\\u003e\\u0026amp;\\u2028end\\u003c/SCRIPT x\\u003e\\u003c!--\\u003cScRiPt\\u003e\\u2029"),
        "{text}"
    );

    // Read back, the hostname is the one the report holds.
    let back: Value = serde_json::from_str(&text)?;
    assert_eq!(back["host"]["hostname"], HOSTILE);
    assert_eq!(report.host.hostname, HOSTILE);

    // The text is the bytes of the `.json` file, and the attribute is their hash.
    let json = json_bytes(&report)?;
    assert_eq!(text, json.as_str());
    assert_eq!(hash, sha256_hex(json.as_bytes()));
    assert_eq!(hash.len(), 64);
    assert!(
        hash.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );

    // Outside the element the same hostname is text: no tag came out of it.
    let before = &html[..at(&html, OPEN)?];
    let after = &html[at(&html, "</script>")?..];
    let outside = format!("{before}{after}");
    assert!(outside.contains("&#60;/script&#62;&#60;img onerror=x&#62;&#38;amp;"));
    for raw in ["<img", "onerror=x>", "<!--"] {
        assert!(!outside.contains(raw), "{raw:?} reached the page as markup");
    }
    let outside_lower = outside.to_ascii_lowercase();
    assert_eq!(outside_lower.matches("<script").count(), 0);
    assert_eq!(outside_lower.matches("</script").count(), 1);
    assert_eq!(well_formed(&html), Vec::<String>::new());
    Ok(())
}

/// The escapes reach every field, not only the hostname: text in the message, fix, notes, `observed`
/// (values and keys), the spec file name and the user cannot end the element or open a comment.
#[test]
fn hostile_text_in_any_field_cannot_end_the_element() -> TestResult {
    let mut doc = five_buckets_doc()?;
    let evil = "</script><!--<script>alert(1)</script>-->";
    doc["checks"][1]["message"] = json!(evil);
    doc["checks"][1]["fix"] = json!(evil);
    doc["checks"][1]["notes"] = json!([evil]);
    doc["checks"][0]["observed"] = json!({ "text": evil, "list": [evil], "<key>": 1 });
    doc["spec"]["file_name"] = json!(evil);
    doc["identity"]["user"] = json!(evil);
    let report = redact(doc)?;
    let html = render_html(&report)?;
    let (_, text) = embedded(&html)?;
    assert_eq!(html.matches("<script").count(), 1);
    assert_eq!(html.matches("</script>").count(), 1);
    assert!(!html.contains("<!--"));
    assert!(!text.contains(['<', '>', '&']));
    let back: Value = serde_json::from_str(&text)?;
    assert_eq!(back["checks"][1]["message"], evil);
    assert_eq!(back["checks"][0]["observed"]["<key>"], 1);
    Ok(())
}

/// The element holds the bytes of the file and nothing else: no leading newline, and the file's own
/// trailing newline is the last character before the end tag.
#[test]
fn the_element_text_is_the_file_bytes_with_nothing_added() -> TestResult {
    let report = redact(sample()?)?;
    let html = render_html(&report)?;
    let json = json_bytes(&report)?;
    let element = format!("{OPEN}{}\">{}</script>", sha256_hex(json.as_bytes()), json);
    assert!(html.contains(&element));
    assert!(json.as_str().ends_with("}\n"));
    Ok(())
}

/// The data block comes after the readable page, so a reader and a screen reader meet the report first.
#[test]
fn the_result_element_is_the_last_thing_in_the_body() -> TestResult {
    let html = html_of(sample()?)?;
    assert!(at(&html, "</footer>")? < at(&html, OPEN)?);
    let after = &html[at(&html, "</script>")? + "</script>".len()..];
    assert_eq!(after.trim(), "</body>\n</html>");
    Ok(())
}

/// A report the JSON writer refuses cannot be rendered either, and the error says why.
#[test]
fn a_report_the_json_writer_refuses_is_not_rendered() -> TestResult {
    let mut doc = sample()?;
    let check = doc["checks"][0].clone();
    let checks = doc["checks"].as_array_mut().ok_or("checks is not a list")?;
    while checks.len() < 257 {
        checks.push(check.clone());
    }
    let report = redact(doc)?;
    let err = render_html(&report).err().ok_or("rendered 257 results")?;
    assert!(matches!(
        err,
        HtmlError::Json(JsonError::TooManyChecks { .. })
    ));
    assert!(err.to_string().contains("Fix:"));
    Ok(())
}

/// The golden pair of SEC-64: the page of the report that `json_writer` writes as
/// `not-ready-hostile-host.json`. The hash on the page is the SHA-256 of that golden file, and the element
/// holds its bytes.
#[test]
fn the_golden_page_carries_the_golden_json() -> TestResult {
    let mut doc = sample()?;
    doc["host"]["hostname"] = json!(HOSTILE);
    doc["checks"][0]["observed"] =
        json!({ "zone": "b", "cores": 8, "labels": { "y": 1, "x": [3, 2, 1] } });
    doc["checks"][1]["observed"] = Value::Null;
    let html = html_of(doc)?;
    let golden_html = fixtures_dir().join("reports/golden/not-ready-hostile-host.html");
    assert_golden(&golden_html, html.as_bytes());

    // Read the golden pair back from disk, so the comparison is between the two files.
    let page = std::fs::read_to_string(&golden_html)?;
    let json = std::fs::read(fixtures_dir().join("reports/golden/not-ready-hostile-host.json"))?;
    let (hash, text) = embedded(&page)?;
    assert_eq!(hash, sha256_hex(&json));
    assert_eq!(text.as_bytes(), json.as_slice());
    Ok(())
}

/// Every golden page is consistent with itself: the hash is the hash of the element text, and the text
/// reads as a report.
#[test]
fn every_golden_page_hashes_its_own_element() -> TestResult {
    let mut seen = 0;
    for entry in std::fs::read_dir(fixtures_dir().join("reports/golden"))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let page = std::fs::read_to_string(&path)?;
        // One script element, in any case, and it is the data block.
        let lower = page.to_ascii_lowercase();
        assert_eq!(lower.matches("<script").count(), 1, "{}", path.display());
        assert_eq!(lower.matches("</script").count(), 1, "{}", path.display());
        assert!(page.contains(OPEN), "{}", path.display());
        let (hash, text) = embedded(&page)?;
        assert_eq!(hash, sha256_hex(text.as_bytes()), "{}", path.display());
        read_report(text.as_bytes())?;
        seen += 1;
    }
    assert!(seen >= 3, "only {seen} golden pages");
    Ok(())
}
