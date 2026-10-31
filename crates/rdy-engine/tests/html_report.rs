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

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

use rdy_engine::redact::{RedactedReport, Redactor, TagKey};
use rdy_engine::report::render_html;
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
    for forbidden in ["<link", "<script", " src="] {
        assert!(!body.contains(forbidden), "{forbidden:?} is in the body");
    }
    // Every `href` is a link inside the page.
    for part in html.split(" href=\"").skip(1) {
        assert!(part.starts_with('#'), "an href leaves the page: {part:.40}");
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
/// The page shows the action log (M1-080) but not `observed` or `expected` yet (M1-081 adds them), so the
/// `observed` canaries are vacuous until then: that test must keep passing when it lands. A password inside a proxy URL is not planted: the URL rule is M1-060's and the known-secret
/// registration of the proxy password is M1-091's.
#[test]
fn canaries_never_reach_the_page() -> TestResult {
    const CANARIES: [&str; 12] = [
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
        "canary-Zk3v9Qx7-act",
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
    // A command in the action log, whose argument after `--password` is a secret, and a failed call whose
    // error text holds one (M1-080).
    let mut command = doc["actions"][0].clone();
    command["kind"] = json!("exec");
    command["program"] = json!("/usr/bin/tool");
    command["argv"] = json!(["--password", "canary-action-argv-6", "--verbose"]);
    command["exit"] = json!(0);
    let mut failure = doc["actions"][0].clone();
    failure["outcome"] = json!("failed");
    failure["error"] = json!("refused, token=canary-Zk3v9Qx7-act");
    let actions = doc["actions"]
        .as_array_mut()
        .ok_or("actions is not a list")?;
    actions.push(command);
    actions.push(failure);
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
    // The action log shows the command with the secret replaced, not only without it (M1-080). The
    // placeholder keeps the flag and the argument after it.
    assert!(html.contains("<bdi>/usr/bin/tool</bdi> <bdi>--password</bdi> <bdi>[REDACTED:"));
    assert!(html.contains("]</bdi> <bdi>--verbose</bdi>"));
    assert!(html.contains("Failed: <bdi>refused, token=[REDACTED:"));
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

/// The vendor's fix is labelled with who wrote it. Only a verified signature with a pinned key puts the
/// product's name on it (01 section 2.6).
#[test]
fn a_spec_fix_is_labelled_with_the_product_when_pinned() -> TestResult {
    let html = html_of(sample()?)?;
    assert!(html.contains(
        "<span class=\"label\">From <bdi>acme-platform</bdi>:</span> <bdi>Add RAM or choose a larger node class.</bdi>"
    ));
    // rdy's own text for a check that did not run says so, and the extra text below a vendor fix too.
    assert!(html.contains("<span class=\"label\">From rdy:</span>"));
    assert!(html.contains("<span class=\"label\">More from rdy:</span>"));
    assert!(!html.contains("Fix:"));
    Ok(())
}

#[test]
fn a_spec_fix_that_was_not_verified_does_not_carry_the_product_name() -> TestResult {
    let mut unsigned = sample()?;
    unsigned["signature"] = json!({"state": "unsigned"});
    let mut one_run_key = sample()?;
    one_run_key["signature"]["trust_source"] = json!("flag");
    for doc in [unsigned, one_run_key] {
        let html = html_of(doc)?;
        assert!(html.contains(
            "<span class=\"label\">From the spec file (not verified):</span> <bdi>Add RAM or choose a larger node class.</bdi>"
        ));
        assert!(!html.contains("From <bdi>acme-platform</bdi>"));
        // rdy's own text keeps its label.
        assert!(html.contains("<span class=\"label\">From rdy:</span>"));
    }
    Ok(())
}

/// A `fix_source` this version does not know, and a fix with none, are not verified (SEC-22-3). The raw
/// value is never shown, and the product name is not put on it even when the key is pinned.
#[test]
fn an_unknown_or_missing_fix_source_is_labelled_not_verified() -> TestResult {
    let mut unknown = sample()?;
    unknown["checks"][1]["fix_source"] = json!("future_source");
    let mut missing = sample()?;
    missing["checks"][1]["fix_source"] = Value::Null;
    for doc in [unknown, missing] {
        let html = html_of(doc)?;
        assert!(html.contains(
            "<span class=\"label\">From the spec file (not verified):</span> <bdi>Add RAM or choose a larger node class.</bdi>"
        ));
        assert!(!html.contains("future_source"));
        assert!(!html.contains("unknown source"));
        // The other vendor fix on the page, whose source is known, keeps the product label.
        assert!(html.contains(
            "<span class=\"label\">From <bdi>acme-platform</bdi>:</span> <bdi>Ask your network team"
        ));
    }
    Ok(())
}

#[test]
fn a_product_name_in_a_fix_label_is_shown_as_text() -> TestResult {
    let mut doc = sample()?;
    doc["spec"]["product"] = json!("<b>x</b>");
    let html = html_of(doc)?;
    assert!(
        html.contains("<span class=\"label\">From <bdi>&#60;b&#62;x&#60;/b&#62;</bdi>:</span>")
    );
    Ok(())
}

/// The part of the page that is the action log: from its section to the end of the section.
fn action_section(html: &str) -> TestResult<&str> {
    let start = at(html, "<section aria-labelledby=\"actions\">")?;
    let end = at(&html[start..], "</section>")? + start;
    Ok(&html[start..end])
}

#[test]
fn the_action_log_is_one_table_with_no_details_element() -> TestResult {
    for doc in [sample()?, five_buckets_doc()?] {
        let html = html_of(doc)?;
        assert!(!html.contains("<details"));
        let section = action_section(&html)?;
        assert_eq!(section.matches("<table>").count(), 1);
        assert!(section.contains("<h2 id=\"actions\">What rdy read and contacted</h2>"));
        assert!(section.contains("<caption>"));
        assert!(section.contains("<th scope=\"col\">Detail</th>"));
        // The sample has 15 entries, and the header row is one more.
        assert_eq!(section.matches("<tr>").count(), 16);
        assert!(html.contains("<li><a href=\"#actions\">What rdy read and contacted</a></li>"));
        // It comes after the run and spec details.
        assert!(at(&html, "<h2 id=\"details\">")? < at(&html, "<h2 id=\"actions\">")?);
        assert_eq!(well_formed(&html), Vec::<String>::new());
    }
    Ok(())
}

#[test]
fn an_action_row_says_what_was_done_to_what_and_how_it_ended() -> TestResult {
    let html = html_of(sample()?)?;
    let section = action_section(&html)?;
    assert!(section.contains(
        "<tr><th scope=\"row\">1</th><td>the run itself</td><td>Read a file</td><td><bdi>~/.kube/config</bdi></td><td>Done, 5412 bytes</td></tr>"
    ));
    assert!(section.contains(
        "<td><bdi>host.cpu</bdi></td><td>Read a file</td><td><bdi>/proc/cpuinfo</bdi></td>"
    ));
    assert!(section.contains(
        "<td>Sent a Kubernetes API request</td><td><bdi>GET</bdi> <bdi>/version</bdi></td><td>Done, status 200</td>"
    ));
    assert!(section.contains(
        "<td>Opened a connection</td><td><bdi>license.acme.example:443</bdi> through <bdi>http://proxy.corp.example:3128</bdi></td><td>Failed: <bdi>proxy answered 403 to CONNECT</bdi></td>"
    ));
    // No raw JSON key or engine word is visible text.
    for raw in [
        "read_dir",
        "via_proxy",
        "duration_ms",
        "at_ms",
        "outcome",
        "denied",
    ] {
        assert!(
            !section.contains(raw),
            "{raw:?} is visible in the action log"
        );
    }
    Ok(())
}

#[test]
fn action_text_from_the_report_is_shown_as_text() -> TestResult {
    let mut doc = sample()?;
    doc["actions"][0]["path"] = json!("</td><script>x</script>");
    doc["actions"][1]["kind"] = json!("<i>kind</i>");
    let html = html_of(doc)?;
    assert!(html.contains("<bdi>&#60;/td&#62;&#60;script&#62;x&#60;/script&#62;</bdi>"));
    assert!(html.contains("<td><bdi>&#60;i&#62;kind&#60;/i&#62;</bdi></td>"));
    assert!(!html.contains("<script>x"));
    assert_eq!(well_formed(&html), Vec::<String>::new());
    Ok(())
}

/// A sample whose action log is `count` copies of its first entry, numbered from 1.
fn doc_with_actions(count: u64) -> TestResult<Value> {
    let mut doc = sample()?;
    let template = doc["actions"][0].clone();
    let actions = doc["actions"]
        .as_array_mut()
        .ok_or("actions is not a list")?;
    actions.clear();
    for seq in 1..=count {
        let mut entry = template.clone();
        entry["seq"] = json!(seq);
        actions.push(entry);
    }
    Ok(doc)
}

/// The page lists the first 1000 entries and counts the rest (01 section 6, item 7). The 5 MiB cap on the
/// whole page is not here: it is measured with the embedded JSON in it (M1-078).
#[test]
fn the_action_log_stops_at_1000_rows_and_counts_the_rest() -> TestResult {
    let html = html_of(doc_with_actions(1003)?)?;
    let section = action_section(&html)?;
    assert_eq!(section.matches("<tr><th scope=\"row\">").count(), 1000);
    assert!(section.contains("<th scope=\"row\">1000</th>"));
    assert!(!section.contains("<th scope=\"row\">1001</th>"));
    assert!(section.contains("<p>3 more entries are in the embedded JSON."));
    Ok(())
}

#[test]
fn one_entry_left_out_reads_as_one_entry() -> TestResult {
    let html = html_of(doc_with_actions(1001)?)?;
    assert!(action_section(&html)?.contains("<p>1 more entry is in the embedded JSON."));
    Ok(())
}

/// A refusal is never left to the JSON: every `denied` entry past the cut is a row too (SEC-22-1).
#[test]
fn a_refusal_past_the_row_limit_is_still_listed() -> TestResult {
    let mut doc = doc_with_actions(1010)?;
    for index in [1004, 1008] {
        doc["actions"][index]["outcome"] = json!("denied");
        doc["actions"][index]["rule"] = json!("read_denylist");
    }
    let html = html_of(doc)?;
    let section = action_section(&html)?;
    assert_eq!(section.matches("<tr><th scope=\"row\">").count(), 1002);
    assert!(section.contains("<th scope=\"row\">1005</th>"));
    assert!(section.contains("<th scope=\"row\">1009</th>"));
    assert!(!section.contains("<th scope=\"row\">1006</th>"));
    assert_eq!(
        section
            .matches("Refused by rdy: <bdi>read_denylist</bdi>")
            .count(),
        2
    );
    assert!(section.contains("<p>8 more entries are in the embedded JSON. Every refused call in the log is listed above.</p>"));
    Ok(())
}

/// A log the engine cut says so and counts what it dropped, and the caption never claims to be complete
/// (SEC-22-2).
#[test]
fn a_cut_log_says_what_was_dropped() -> TestResult {
    let plain_html = html_of(sample()?)?;
    let plain_section = action_section(&plain_html)?;
    assert!(plain_section.contains("<caption>What rdy recorded, in order</caption>"));
    assert!(!plain_section.contains("Every "));
    assert!(!plain_section.contains("left some entries out"));

    let mut doc = sample()?;
    doc["actions_truncated"] = json!(true);
    doc["actions_dropped"] = json!({"read": 120, "read_dir": 5, "future_kind": 2});
    let html = html_of(doc)?;
    let section = action_section(&html)?;
    assert!(section.contains("<caption>What rdy recorded, in order</caption>"));
    assert!(section.contains(
        "<p>rdy left some entries out of its own log to stay within its size limits: 2 <bdi>future_kind</bdi>, 120 file reads, 5 folder listings.</p>"
    ));
    assert!(!section.contains("read_dir"));
    Ok(())
}

#[test]
fn a_folded_row_uses_plain_words() -> TestResult {
    let mut doc = sample()?;
    let mut entry = doc["actions"][0].clone();
    entry["seq"] = json!(16);
    entry["kind"] = json!("coalesced");
    entry["outcome"] = json!("failed");
    entry["error"] = json!("permission denied");
    entry["of"] = json!("read_dir");
    entry["under"] = json!("/var/lib");
    entry["count"] = json!(12);
    for key in ["path", "bytes", "truncated"] {
        entry[key] = Value::Null;
    }
    doc["actions"]
        .as_array_mut()
        .ok_or("actions is not a list")?
        .push(entry);
    let html = html_of(doc)?;
    let section = action_section(&html)?;
    assert!(section.contains(
        "<td>Many calls shown as one row</td><td>12 folder listings under <bdi>/var/lib</bdi></td>"
    ));
    assert!(!section.contains("read_dir"));
    Ok(())
}

#[test]
fn an_empty_action_log_says_so() -> TestResult {
    let mut doc = sample()?;
    doc["actions"] = json!([]);
    let html = html_of(doc)?;
    let section = action_section(&html)?;
    assert!(section.contains("<p>rdy recorded nothing in this run.</p>"));
    assert!(!section.contains("<table>"));
    assert_eq!(well_formed(&html), Vec::<String>::new());
    Ok(())
}
