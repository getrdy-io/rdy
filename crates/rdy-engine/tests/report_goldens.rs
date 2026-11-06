//! Golden tests for the JSON and HTML reports (M1-083).
//!
//! The three result fixtures under `tests/fixtures/results/plan-07/` are 07 Appendix B.1 to B.3 (the 01
//! samples' sibling runs): a clean run, a run with a warning and a run that is not ready. Each goes through
//! a real redactor, then `write_json` and `render_html`, and the bytes are compared with a golden file.
//!
//! The goldens live in `tests/fixtures/reports/golden/`, one file per case, named `results-*`. The HTML
//! ones are separate from the JSON ones, so a change to the page regenerates only the `.html` files with
//! `UPDATE_GOLDENS=1 cargo test -p rdy-engine --test report_goldens`.
//!
//! Nothing here depends on a clock, a run id, a path separator or a line ending: the fixtures are fixed
//! text, the one live fixture run goes through `testing::normalize`, and every golden is compared as
//! bytes with `\n` line ends (`.gitattributes` keeps fixtures as they are on Windows).
//!
//! The static checks of ADR 0003 run on every golden page, not only on these: the exact CSP, `lang`, no
//! `<link>`, no `url(`, no `src` pointing off the file, no outside link without `rel="noopener
//! noreferrer"`, one script element, and a hostname that tries to close it comes back unchanged.
//!
//! The last test is the HTML half of M1-046 and M1-061: a fixture run holding a machine id, secrets cut by
//! the read cap and a known secret shows none of them on the page.

use std::error::Error;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use rdy_engine::check::Os;
use rdy_engine::probe::MAX_READ;
use rdy_engine::redact::{RedactedReport, Redactor, TagKey};
use rdy_engine::report::{json_bytes, read_report, render_html, write_json};
use rdy_engine::testing::{Replay, TestRun, fixtures_dir, golden::assert_golden, normalize};
use rdy_spec::result::Report;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The fixture file stem and the golden stem of each case.
const CASES: [(&str, &str); 3] = [
    ("b1-ready", "results-b1-ready"),
    ("b2-ready-with-warnings", "results-b2-ready-with-warnings"),
    ("b3-not-ready", "results-b3-not-ready"),
];

const OPEN: &str = "<script type=\"application/json\" id=\"rdy-result\" data-sha256=\"";

const CSP: &str = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
                   style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">";

/// A hostname that tries to close the element, open another and end the line in a script.
const HOSTILE: &str = "</script><img onerror=x>&amp;\u{2028}end</SCRIPT x><!--<ScRiPt>\u{2029}";

fn results_dir() -> PathBuf {
    fixtures_dir().join("results/plan-07")
}

fn golden_dir() -> PathBuf {
    fixtures_dir().join("reports/golden")
}

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([5; 32]))
}

fn fixture_text(stem: &str) -> TestResult<String> {
    Ok(std::fs::read_to_string(
        results_dir().join(format!("{stem}.json")),
    )?)
}

fn fixture_doc(stem: &str) -> TestResult<Value> {
    Ok(serde_json::from_str(&fixture_text(stem)?)?)
}

fn redact(doc: Value) -> TestResult<RedactedReport> {
    let report: Report = serde_json::from_value(doc)?;
    Ok(redactor().redact_report(report)?)
}

fn validator() -> TestResult<Validator> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    Ok(jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?)
}

fn assert_valid(what: &str, json: &str) -> TestResult {
    let instance: Value = serde_json::from_str(json)?;
    let errors: Vec<String> = validator()?
        .iter_errors(&instance)
        .take(10)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{what} fails the schema: {errors:#?}");
    Ok(())
}

fn written(report: &RedactedReport) -> TestResult<Vec<u8>> {
    let mut out = Vec::new();
    write_json(report, &mut out)?;
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The `data-sha256` value and the text of the one result element.
fn embedded(html: &str) -> TestResult<(String, String)> {
    let start = html.find(OPEN).ok_or("no result element")? + OPEN.len();
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

/// The value of attribute `name` in the start tag text `tag`, if it has one.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')?;
    Some(tag[start..start + end].to_owned())
}

/// The static checks of ADR 0003 on one page. `what` names the page in a failure.
fn assert_static(what: &str, html: &str) -> TestResult {
    assert!(html.starts_with("<!DOCTYPE html>"), "{what}: no doctype");
    assert!(html.contains("<html lang=\""), "{what}: no lang");
    assert_eq!(html.matches(CSP).count(), 1, "{what}: the CSP is not exact");
    assert_eq!(
        html.matches("Content-Security-Policy").count(),
        1,
        "{what}: a second CSP"
    );
    let body_at = html.find("<body>").ok_or("no body")?;
    let (head, body) = html.split_at(body_at);
    for forbidden in [
        "<link", "<script", "@import", "url(", " src=", "http://", "https://",
    ] {
        assert!(
            !head.contains(forbidden),
            "{what}: {forbidden:?} is in the head"
        );
    }
    for forbidden in ["<link", " src=", "url("] {
        assert!(
            !body.contains(forbidden),
            "{what}: {forbidden:?} is in the body"
        );
    }
    // Text from the machine is escaped, so none of it opens a tag that loads or runs anything.
    for forbidden in [
        "<img",
        "<iframe",
        "<object",
        "<embed",
        "<form",
        "<svg",
        "javascript:",
        "http-equiv=\"refresh",
    ] {
        assert!(
            !html.contains(forbidden),
            "{what}: {forbidden:?} is on the page"
        );
    }
    // Every link stays inside the page or is marked as an outside link.
    for part in html.split("<a ").skip(1) {
        let tag = format!(" {}", &part[..part.find('>').unwrap_or(part.len())]);
        let href = attribute(&tag, "href").ok_or("a link has no href")?;
        if !href.starts_with('#') {
            assert_eq!(
                attribute(&tag, "rel").as_deref(),
                Some("noopener noreferrer"),
                "{what}: an outside link has no rel: {tag}"
            );
        }
    }
    // One script element, case blind, and it is the data block.
    let lower = html.to_ascii_lowercase();
    assert_eq!(lower.matches("<script").count(), 1, "{what}: scripts");
    assert_eq!(lower.matches("</script").count(), 1, "{what}: script ends");
    assert!(body.contains(OPEN), "{what}: no data block");
    let (hash, text) = embedded(html)?;
    assert_eq!(hash, sha256_hex(text.as_bytes()), "{what}: hash");
    assert!(
        !text.contains(['<', '>', '&', '\u{2028}', '\u{2029}']),
        "{what}: the data block is not escaped"
    );
    read_report(text.as_bytes())?;
    Ok(())
}

// ---- JSON ----

/// `write_json` on each fixture: valid against the schema, equal to its golden, and the same bytes as
/// `json_bytes`. The fixtures are 07's documents in document order; the writer sorts maps and escapes `>`,
/// so the golden differs from the fixture in those ways and only there.
#[test]
fn write_json_on_each_result_fixture_matches_its_golden() -> TestResult {
    for (stem, golden) in CASES {
        let text = fixture_text(stem)?;
        assert_valid(stem, &text)?;
        let report = redact(serde_json::from_str(&text)?)?;
        let bytes = written(&report)?;
        assert_eq!(bytes, json_bytes(&report)?.as_bytes(), "{stem}");
        assert_valid(golden, std::str::from_utf8(&bytes)?)?;
        assert!(bytes.ends_with(b"}\n") && !bytes.contains(&b'\r'), "{stem}");
        assert_golden(golden_dir().join(format!("{golden}.json")), &bytes);
    }
    Ok(())
}

/// The three runs are the ones 07 describes: the verdicts, the exit codes and the run ids.
#[test]
fn the_fixtures_are_the_three_runs_of_07_appendix_b() -> TestResult {
    let expect = [
        (
            "b1-ready",
            "ready",
            0,
            "0c7e5a39-8d24-4f1b-b6e2-9a4f3d7c1e08",
        ),
        (
            "b2-ready-with-warnings",
            "ready_with_warnings",
            1,
            "3b9d1f70-52c6-4a8e-8c13-7e0a5d2b9f41",
        ),
        (
            "b3-not-ready",
            "not_ready",
            2,
            "6f8d2c4e-1b3a-4e5f-9a7b-2c1d0e9f8a6b",
        ),
    ];
    for (stem, verdict, exit, id) in expect {
        let doc = fixture_doc(stem)?;
        assert_eq!(doc["verdict"], verdict, "{stem}");
        assert_eq!(doc["exit_code"], exit, "{stem}");
        assert_eq!(doc["run"]["id"], id, "{stem}");
    }
    Ok(())
}

// ---- HTML ----

/// `render_html` on each fixture: equal to its golden, and the golden passes the static checks.
#[test]
fn render_html_on_each_result_fixture_matches_its_golden() -> TestResult {
    for (stem, golden) in CASES {
        let report = redact(fixture_doc(stem)?)?;
        let html = render_html(&report)?;
        assert_static(stem, &html)?;
        assert_golden(golden_dir().join(format!("{golden}.html")), html.as_bytes());
        // The page carries the bytes of the JSON golden, and the hash is theirs.
        let json = std::fs::read(golden_dir().join(format!("{golden}.json")))?;
        let page = std::fs::read_to_string(golden_dir().join(format!("{golden}.html")))?;
        let (hash, text) = embedded(&page)?;
        assert_eq!(text.as_bytes(), json.as_slice(), "{stem}");
        assert_eq!(hash, sha256_hex(&json), "{stem}");
    }
    Ok(())
}

/// The checks hold on every golden page in the folder, including the ones other tests own.
#[test]
fn every_golden_page_passes_the_static_checks() -> TestResult {
    let mut seen = 0;
    for entry in std::fs::read_dir(golden_dir())? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("html") {
            let html = std::fs::read_to_string(&path)?;
            assert_static(&path.display().to_string(), &html)?;
            seen += 1;
        }
    }
    assert!(seen >= 7, "only {seen} golden pages");
    Ok(())
}

/// The ticket's round trip on all three fixtures: a hostname that closes the script comes back from the
/// data block unchanged, and outside the block it is text.
#[test]
fn a_hostile_hostname_round_trips_on_each_result_fixture() -> TestResult {
    for (stem, _) in CASES {
        let mut doc = fixture_doc(stem)?;
        doc["host"]["hostname"] = json!(HOSTILE);
        let report = redact(doc)?;
        let html = render_html(&report)?;
        assert_static(stem, &html)?;
        let (_, text) = embedded(&html)?;
        let back: Value = serde_json::from_str(&text)?;
        assert_eq!(back["host"]["hostname"], HOSTILE, "{stem}");
        assert_eq!(report.host.hostname, HOSTILE, "{stem}");
        let before = &html[..html.find(OPEN).ok_or("no block")?];
        let after = &html[html.find("</script>").ok_or("no end")?..];
        for raw in ["<img", "onerror=x>", "<!--"] {
            assert!(!format!("{before}{after}").contains(raw), "{stem}: {raw:?}");
        }
    }
    Ok(())
}

// ---- A fixture run that holds things that must not leave ----

/// A made-up machine id, in the form systemd writes it.
const MACHINE_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// A secret the run knows, in text with no key name around it.
const TOKEN: &str = "kt-Zk3v9Qx7canaryTOKEN";
/// An AWS-style key id, cut by the read cap.
const AWS_ID: &str = "AKIAZ3Q7XK2MCANARY4B";
/// The userinfo of a URL, cut by the read cap.
const USERINFO: &str = "svcuser:Pw7canaryZq9";
const LOG: &str = "/var/log/synthetic.log";

/// Every 8 byte window of `secret`, so a fragment counts as a leak.
fn windows(secret: &str) -> Vec<String> {
    secret
        .as_bytes()
        .windows(8)
        .filter_map(|w| std::str::from_utf8(w).ok().map(str::to_owned))
        .collect()
}

/// A private key whose body lines are made of `i` and `j`, so no two runs agree by accident.
fn pem_body() -> Vec<String> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    (0..5)
        .map(|i| {
            let line: String = (0..64)
                .map(|j| char::from(table[(i * 17 + j * 7 + j / 3) % 64]))
                .collect();
            format!("{line}Zk{i}")
        })
        .collect()
}

/// A file of filler lines with `canary` ending `k` bytes after the point the cap cuts at.
fn file_cut_inside(canary: &str, k: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..MAX_READ - k)
        .map(|i| if i % 64 == 63 { b'\n' } else { b'x' })
        .collect();
    data.extend_from_slice(canary.as_bytes());
    data.extend(std::iter::repeat_n(b'q', 100));
    data
}

/// A run whose machine holds a machine id, three secrets cut by the read cap at different offsets and
/// a known secret. It returns the report document and the strings that must not appear in the page.
async fn leaky_doc(with_actions: bool) -> TestResult<(Value, Vec<String>)> {
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        pem_body().join("\n")
    );
    let aws = format!("id: {AWS_ID}");
    let url = format!("proxy: https://{USERINFO}@proxy.example.test:3128/");
    let files = [
        ("/etc/machine-id", format!("{MACHINE_ID}\n").into_bytes()),
        ("/var/log/pem.log", file_cut_inside(&pem, 20)),
        ("/var/log/aws.log", file_cut_inside(&aws, 9)),
        ("/var/log/url.log", file_cut_inside(&url, 17)),
        (
            LOG,
            format!("context: staging\nsee {TOKEN} for details\n").into_bytes(),
        ),
    ];
    let mut replay = Replay::new();
    for (path, data) in files {
        replay = replay.file(path, data);
    }
    let run = TestRun::new(replay);
    assert!(run.add_known_secret(TOKEN));
    let ctx = run.context("host.synthetic", Os::Linux, []);
    let probe = ctx.probe();

    let mut evidence = Vec::new();
    for path in [
        "/var/log/pem.log",
        "/var/log/aws.log",
        "/var/log/url.log",
        LOG,
    ] {
        let file = probe.read(Path::new(path)).await?;
        evidence.push(probe.file_text(&file)?.to_string());
    }
    // What a careless check would copy: the machine id file, read as a plain file.
    let denied = probe.read(Path::new("/etc/machine-id")).await;
    let denied_text = match denied {
        Ok(bytes) => String::from_utf8_lossy(&bytes.bytes).into_owned(),
        Err(error) => error.to_string(),
    };

    let mut doc = fixture_doc("b1-ready")?;
    doc["host"]["hostname"] = json!(format!("web-01 token={TOKEN}"));
    doc["checks"][0]["message"] = json!(format!("read it: {}", evidence[3]));
    doc["checks"][0]["observed"] = json!({
        "pem": evidence[0],
        "aws": evidence[1],
        "url": evidence[2],
        "machine_id_file": denied_text,
    });
    doc["checks"][0]["notes"] = json!([format!("the known secret is {TOKEN}")]);
    doc["actions"] = if with_actions {
        serde_json::to_value(run.action_log().actions)?
    } else {
        json!([])
    };

    let mut needles = vec![MACHINE_ID.to_owned()];
    needles.extend(windows(TOKEN));
    needles.extend(windows(AWS_ID));
    needles.extend(windows(USERINFO));
    needles.extend(pem_body().iter().flat_map(|line| windows(line)));
    Ok((doc, needles))
}

/// Normalizes `doc` as 08 Appendix C says, then redacts it with the known secret in the redactor's set.
fn redact_normalized(doc: Value) -> TestResult<RedactedReport> {
    let mut report: Report = serde_json::from_value(doc)?;
    normalize(&mut report);
    let redactor = redactor();
    assert!(redactor.add_known_secret(TOKEN));
    Ok(redactor.redact_report(report)?)
}

/// The HTML halves of M1-046 and M1-061: no machine id, no fragment of a secret the read cap cut and no
/// known secret on the page, in the JSON it carries or in the written file. The planted fields are still
/// shown, with the secret replaced, so the test does not pass because the page left them out.
#[tokio::test(flavor = "current_thread")]
async fn a_fixture_run_with_a_machine_id_cut_secrets_and_a_known_secret_leaves_none_on_the_page()
-> TestResult {
    let (doc, needles) = leaky_doc(true).await?;
    // The facade already holds the id back from a check, so it is not in the document yet.
    assert!(
        !doc.to_string().contains(MACHINE_ID),
        "the id reached the result before redaction"
    );
    let report = redact_normalized(doc)?;
    let html = render_html(&report)?;
    let json = written(&report)?;
    let json = String::from_utf8(json)?;
    for needle in &needles {
        assert!(!html.contains(needle.as_str()), "{needle} is on the page");
        assert!(!json.contains(needle.as_str()), "{needle} is in the file");
    }
    assert!(html.contains("[REDACTED:"), "nothing was replaced");
    assert!(html.contains("web-01 token="));
    assert!(html.contains("known_secret"));
    assert_static("leaky run", &html)?;
    assert_valid("leaky run", &json)?;
    Ok(())
}

/// The same run without its action log is a golden, so a reviewer sees what the page shows in place of the
/// secrets. The action log is left out because the leak test above already walks it.
#[tokio::test(flavor = "current_thread")]
async fn the_page_of_the_run_with_secrets_matches_its_golden() -> TestResult {
    let (doc, needles) = leaky_doc(false).await?;
    let report = redact_normalized(doc)?;
    let html = render_html(&report)?;
    for needle in &needles {
        assert!(!html.contains(needle.as_str()), "{needle} is on the page");
    }
    assert_static("leaky run", &html)?;
    assert_golden(
        golden_dir().join("results-secrets-redacted.html"),
        html.as_bytes(),
    );
    Ok(())
}
