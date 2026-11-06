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
use rdy_engine::probe::{MAX_READ, NativeCall, ProbeError};
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

/// The hrefs a page may hold besides `#id` links, written out in full. The footer links of 07 D.4 are
/// added here, exactly, when the page gets a footer. Until then the page links nowhere outside itself, and
/// a new off-file `href` fails every page check.
const OUTSIDE_HREFS: [&str; 0] = [];

/// The static checks of ADR 0003 on one page. `what` names the page in a failure.
///
/// The page is lower-cased first, so `<LINK` and `URL(` count. The `<svg` ban below is for text from the
/// machine; ADR 0003's inline logo is not on the page yet, and when it lands this check names it.
fn assert_static(what: &str, html: &str) -> TestResult {
    assert!(html.starts_with("<!DOCTYPE html>"), "{what}: no doctype");
    assert!(html.contains("<html lang=\"en\">"), "{what}: no lang=en");
    assert_eq!(html.matches(CSP).count(), 1, "{what}: the CSP is not exact");
    assert_eq!(
        html.matches("Content-Security-Policy").count(),
        1,
        "{what}: a second CSP"
    );
    let head_at = html.find("<head>").ok_or("no head")?;
    let csp_at = html.find(CSP).ok_or("no csp")?;
    let style_at = html.find("<style").ok_or("no style")?;
    let head_end = html.find("</head>").ok_or("no head end")?;
    assert!(
        head_at < csp_at && csp_at < style_at && style_at < head_end,
        "{what}: the CSP is not inside the head before the style"
    );
    let body_at = html.find("<body>").ok_or("no body")?;
    assert!(head_end < body_at, "{what}: the head ends after the body");

    let lower = html.to_ascii_lowercase();
    let (head, body) = lower.split_at(lower.find("<body>").ok_or("no body")?);
    for forbidden in [
        "<link",
        "<script",
        "@import",
        "url(",
        " src=",
        "srcset",
        "formaction",
        "<base",
        "<area",
        "xlink:href",
        "http://",
        "https://",
    ] {
        assert!(
            !head.contains(forbidden),
            "{what}: {forbidden:?} is in the head"
        );
    }
    for forbidden in [
        "<link",
        " src=",
        "srcset",
        "formaction",
        "<base",
        "<area",
        "xlink:href",
        "url(",
    ] {
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
            !lower.contains(forbidden),
            "{what}: {forbidden:?} is on the page"
        );
    }
    // Every anchor is `#id` or one of the exact outside links, which say `rel="noopener noreferrer"`.
    let mut rest = lower.as_str();
    while let Some(at) = rest.find("<a") {
        rest = &rest[at + 2..];
        match rest.chars().next() {
            Some(c) if c.is_ascii_whitespace() => {}
            Some(c) if c.is_ascii_alphanumeric() || c == '-' => continue,
            other => panic!("{what}: an anchor tag continues with {other:?}"),
        }
        let tag = format!(" {}", &rest[..rest.find('>').unwrap_or(rest.len())]);
        let tag = tag.replace(['\t', '\n', '\r', '\u{c}'], " ");
        let href = attribute(&tag, "href").ok_or("a link has no href")?;
        if !href.starts_with('#') {
            assert!(
                OUTSIDE_HREFS.contains(&href.as_str()),
                "{what}: an outside link that is not allowed: {href}"
            );
            assert_eq!(
                attribute(&tag, "rel").as_deref(),
                Some("noopener noreferrer"),
                "{what}: an outside link has no rel: {tag}"
            );
        }
    }
    // One script element, case blind, and it is the data block.
    assert_eq!(lower.matches("<script").count(), 1, "{what}: scripts");
    assert_eq!(lower.matches("</script").count(), 1, "{what}: script ends");
    assert!(html[body_at..].contains(OPEN), "{what}: no data block");
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
        // The golden is the fixture in value: only the order of keys and the escapes differ.
        let golden_text = std::fs::read_to_string(golden_dir().join(format!("{golden}.json")))?;
        assert_eq!(
            serde_json::from_str::<Value>(&golden_text)?,
            serde_json::from_str::<Value>(&text)?,
            "{stem}"
        );
    }
    Ok(())
}

/// The JSON block under the `###` heading that starts with `heading` in 07 Appendix B.
fn appendix_b(heading: &str) -> TestResult<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/plan/07-cli-ux.md");
    let doc = std::fs::read_to_string(path)?.replace("\r\n", "\n");
    let start = doc
        .find(&format!("\n### {heading}"))
        .ok_or("heading not found")?;
    let section = &doc[start + 1..];
    let open = section.find("```json\n").ok_or("no json block")? + "```json\n".len();
    let body = &section[open..];
    let close = body.find("\n```").ok_or("unterminated json block")?;
    Ok(serde_json::from_str(&body[..close])?)
}

/// Applies the `replace` and `add` operations of the B.2 patch (RFC 6902) to `doc`.
fn apply_patch(doc: &mut Value, patch: &Value) -> TestResult {
    for op in patch.as_array().ok_or("the patch is a list")? {
        let path = op["path"].as_str().ok_or("no path")?;
        let (parent, key) = path.rsplit_once('/').ok_or("bad path")?;
        let target = doc.pointer_mut(parent).ok_or("no such parent")?;
        let value = op["value"].clone();
        match op["op"].as_str() {
            Some("replace" | "add") => match target {
                Value::Array(items) => {
                    *items.get_mut(key.parse::<usize>()?).ok_or("index")? = value
                }
                Value::Object(map) => {
                    map.insert(key.to_owned(), value);
                }
                _ => return Err("the parent is a scalar".into()),
            },
            other => return Err(format!("unsupported op {other:?}").into()),
        }
    }
    Ok(())
}

/// The fixtures are 07 Appendix B.1 to B.3 as they stand in the plan (B.2 is B.1 with the patch), so a
/// change to the plan or to a fixture fails here. Verdicts and exit codes are 07's too.
#[test]
fn the_fixtures_are_the_three_runs_of_07_appendix_b() -> TestResult {
    let b1 = appendix_b("B.1 ")?;
    let mut b2 = b1.clone();
    apply_patch(&mut b2, &appendix_b("B.2 ")?)?;
    let b3 = appendix_b("B.3 ")?;
    let expect = [
        ("b1-ready", b1, "ready", 0),
        ("b2-ready-with-warnings", b2, "ready_with_warnings", 1),
        ("b3-not-ready", b3, "not_ready", 2),
    ];
    for (stem, plan, verdict, exit) in expect {
        let doc = fixture_doc(stem)?;
        assert_eq!(doc, plan, "{stem} is not 07's document");
        assert_eq!(doc["verdict"], verdict, "{stem}");
        assert_eq!(doc["exit_code"], exit, "{stem}");
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
    let mut seen = Vec::new();
    for entry in std::fs::read_dir(golden_dir())? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("html") {
            let html = std::fs::read_to_string(&path)?;
            assert_static(&path.display().to_string(), &html)?;
            seen.push(
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_owned(),
            );
        }
    }
    seen.sort();
    assert_eq!(
        seen,
        [
            "five-sections-exec-plugin.html",
            "not-ready-7.2.html",
            "not-ready-hostile-host.html",
            "not-ready-no-blocks.html",
            "results-b1-ready.html",
            "results-b2-ready-with-warnings.html",
            "results-b3-not-ready.html",
            "results-secrets-redacted.html",
        ],
        "a golden page was added or removed: list it here so it gets the checks on purpose"
    );
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
        let outside = format!("{before}{after}");
        for raw in ["<img", "onerror=x>", "<!--"] {
            assert!(!outside.contains(raw), "{stem}: {raw:?}");
        }
        // It is on the page as visible, escaped text.
        assert!(
            outside.contains("&#60;/script&#62;&#60;img onerror=x&#62;&#38;amp;"),
            "{stem}: the hostname is not shown as text"
        );
    }
    Ok(())
}

// ---- A fixture run that holds things that must not leave ----

/// A made-up machine id, in the form systemd writes it.
const MACHINE_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// A secret the run knows, in text with no key name around it.
const TOKEN: &str = "kt-Zk3v9Qx7canaryTOKEN";
const LOG: &str = "/var/log/synthetic.log";
/// The evidence a check keeps from a buffer: its last 4 KiB, where the cap cut it.
const EVIDENCE_TAIL: usize = 4096;

/// Every 8 byte window of `secret`, so a fragment counts as a leak.
fn windows(secret: &str) -> Vec<String> {
    secret
        .as_bytes()
        .windows(8)
        .filter_map(|w| std::str::from_utf8(w).ok().map(str::to_owned))
        .collect()
}

/// A secret of one kind, with the text around it in a file. Only `secret` must never be shown.
struct Secret {
    kind: &'static str,
    /// The redaction rule that removes it when it lies whole inside the buffer.
    rule: &'static str,
    prefix: String,
    secret: String,
    suffix: String,
    /// One needle per 8 byte window of the secret, or of each body line of a key.
    needles: Vec<String>,
}

impl Secret {
    fn text(&self) -> String {
        format!("{}{}{}", self.prefix, self.secret, self.suffix)
    }
}

/// A private key body whose lines are made of `i` and `j`, so no two lines agree by accident.
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

fn secrets() -> Vec<Secret> {
    let aws = "AKIAZ3Q7XK2MCANARY4B";
    let userinfo = "svcuser:Pw7canaryZq9";
    let body = pem_body();
    vec![
        Secret {
            kind: "aws key id",
            rule: "aws_access_key_id",
            prefix: "found ".to_owned(),
            secret: aws.to_owned(),
            suffix: "\n".to_owned(),
            needles: windows(aws),
        },
        Secret {
            kind: "url userinfo",
            rule: "url_userinfo",
            prefix: "proxy: https://".to_owned(),
            secret: userinfo.to_owned(),
            suffix: "@proxy.example.test:3128/\n".to_owned(),
            needles: windows(userinfo),
        },
        Secret {
            kind: "private key",
            rule: "pem_private_key",
            prefix: "-----BEGIN PRIVATE KEY-----\n".to_owned(),
            secret: body.join("\n"),
            suffix: "\n-----END PRIVATE KEY-----\n".to_owned(),
            needles: body.iter().flat_map(|line| windows(line)).collect(),
        },
    ]
}

/// Filler lines of 63 `x` and a newline, `n` bytes of them.
fn filler(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| if i % 64 == 63 { b'\n' } else { b'x' })
        .collect()
}

/// A file in which `secret` starts `back` bytes before the read cap, so the cap cuts it, followed by
/// 100 bytes the cap leaves out.
fn cut_by_the_cap(secret: &Secret, back: usize) -> Vec<u8> {
    let mut data = filler(MAX_READ - back);
    data.extend_from_slice(secret.text().as_bytes());
    data.truncate(MAX_READ);
    data.extend(std::iter::repeat_n(b'q', 100));
    data
}

/// A file in which the whole of `secret` stands on its own lines, 70 bytes before the cap.
fn whole_before_the_cap(secret: &Secret) -> Vec<u8> {
    let text = secret.text();
    let start = MAX_READ - text.len() - 70;
    let mut data = filler(MAX_READ + 100);
    data[start - 1] = b'\n';
    data[start..start + text.len()].copy_from_slice(text.as_bytes());
    data
}

/// The last `EVIDENCE_TAIL` bytes of `text`, on a character boundary.
fn evidence_of(text: &str) -> String {
    text[text.ceil_char_boundary(text.len().saturating_sub(EVIDENCE_TAIL))..].to_owned()
}

/// A run whose machine holds a machine id on both paths, each secret cut by the read cap at several
/// offsets and lying whole just inside it, and a known secret. It returns the report document and the
/// strings that must not appear on the page.
async fn leaky_doc(with_actions: bool) -> TestResult<(Value, Vec<String>)> {
    let secrets = secrets();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    // (file, case name, the secret's index, the number of secret bytes inside the cap, or 0 for whole)
    let mut cases: Vec<(String, String, usize, usize)> = Vec::new();
    for (index, secret) in secrets.iter().enumerate() {
        let length = secret.secret.len();
        let mut inside = vec![8, 16, length - 1];
        if secret.rule == "pem_private_key" {
            // Whole body lines lie inside the cap, and only the key guard can remove them.
            inside.extend([100, 200]);
        }
        for k in inside {
            let back = secret.prefix.len() + k;
            let name = format!("{}-cut-{k}", secret.rule);
            let path = format!("/var/log/{name}.log");
            files.push((path.clone(), cut_by_the_cap(secret, back)));
            cases.push((path, name, index, k));
        }
        let name = format!("{}-whole", secret.rule);
        let path = format!("/var/log/{name}.log");
        files.push((path.clone(), whole_before_the_cap(secret)));
        cases.push((path, name, index, 0));
    }
    files.push((
        "/etc/machine-id".to_owned(),
        format!("{MACHINE_ID}\n").into_bytes(),
    ));
    files.push((
        "/var/lib/dbus/machine-id".to_owned(),
        format!("{MACHINE_ID}\n").into_bytes(),
    ));
    files.push((
        LOG.to_owned(),
        format!("context: staging\nsee {TOKEN} for details\n").into_bytes(),
    ));
    let mut replay = Replay::new();
    for (path, data) in files {
        replay = replay.file(path, data);
    }
    let run = TestRun::new(replay);
    assert!(run.add_known_secret(TOKEN));
    let ctx = run.context("host.synthetic", Os::Linux, []);
    let probe = ctx.probe();

    let mut observed = serde_json::Map::new();
    for (number, (path, name, index, k)) in cases.iter().enumerate() {
        let secret = &secrets[*index];
        let file = probe.read(Path::new(path)).await?;
        assert!(file.truncated_tail, "{name}: the cap did not cut the file");
        // CONTROL: the bytes the facade read hold the secret, so a clean page is the redactor's doing.
        let raw = String::from_utf8_lossy(&file.bytes);
        let held = if *k == 0 { secret.secret.len() } else { *k };
        assert!(
            raw.contains(&secret.secret[..held]),
            "{name}: {held} bytes of the {} are not inside the cap",
            secret.kind
        );
        assert!(
            secret
                .needles
                .iter()
                .any(|needle| raw.contains(needle.as_str())),
            "{name}: no needle is inside the cap"
        );
        let shown = probe.file_text(&file)?;
        // The member name is plain on purpose: a name like `key` makes the report walk replace the whole
        // value, and the rule's own tag would never be seen.
        observed.insert(format!("case {number}"), json!(evidence_of(&shown)));
    }
    let known = probe.read(Path::new(LOG)).await?;
    let known_text = probe.file_text(&known)?.to_string();

    // What a careless check would copy: the machine id file, read as a file or from its tail, on both
    // paths. The policy refuses all four, and the refusal text is what a check would keep.
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        let whole = probe.read(Path::new(path)).await;
        assert!(
            matches!(whole, Err(ProbeError::Denied { .. })),
            "{path}: {whole:?}"
        );
        let tail = probe.read_tail(Path::new(path), 4096).await;
        assert!(
            matches!(tail, Err(ProbeError::Denied { .. })),
            "{path}: {tail:?}"
        );
        for (how, error) in [("read", whole.err()), ("tail", tail.err())] {
            if let Some(error) = error {
                observed.insert(format!("machine-id {path} {how}"), json!(error.to_string()));
            }
        }
    }
    // The native call is for the engine only, so a check's probe is refused.
    let call = probe.native(NativeCall::MachineId).await;
    assert!(matches!(call, Err(ProbeError::Denied { .. })), "{call:?}");
    observed.insert("machine_id_call".to_owned(), json!(format!("{call:?}")));

    let mut doc = fixture_doc("b1-ready")?;
    doc["host"]["hostname"] = json!(format!("web-01 token={TOKEN}"));
    doc["checks"][0]["message"] = json!(format!("read it: {known_text}"));
    doc["checks"][0]["observed"] = Value::Object(observed);
    doc["checks"][0]["notes"] = json!([format!("the known secret is {TOKEN}")]);
    doc["actions"] = if with_actions {
        serde_json::to_value(run.action_log().actions)?
    } else {
        json!([])
    };

    // CONTROL: the known secret is in the document before redaction, so the redactor has work to do.
    assert!(doc.to_string().contains(TOKEN), "the token is not planted");
    assert!(
        !doc.to_string().contains(MACHINE_ID),
        "the id reached the result before redaction"
    );

    let mut needles = windows(MACHINE_ID);
    needles.push(MACHINE_ID.to_owned());
    needles.extend(windows(TOKEN));
    for secret in &secrets {
        needles.extend(secret.needles.iter().cloned());
    }
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

/// The HTML halves of M1-046 and M1-061: no machine id, no fragment of a secret the read cap cut or left
/// whole just inside it, and no known secret on the page, in the JSON it carries or in the written file.
/// The test can fail: the controls inside `leaky_doc` show the secrets are in the bytes the facade read,
/// and the tags below show the page holds the replacements, so it does not pass because the page left
/// the fields out.
#[tokio::test(flavor = "current_thread")]
async fn a_fixture_run_with_a_machine_id_cut_secrets_and_a_known_secret_leaves_none_on_the_page()
-> TestResult {
    let (doc, needles) = leaky_doc(true).await?;
    let report = redact_normalized(doc)?;
    let html = render_html(&report)?;
    let json = String::from_utf8(written(&report)?)?;
    for needle in &needles {
        assert!(!html.contains(needle.as_str()), "{needle} is on the page");
        assert!(!json.contains(needle.as_str()), "{needle} is in the file");
    }
    // One replacement tag per kind of secret that lay whole inside the cap, and for the known secret.
    for secret in secrets() {
        let tag = format!("[REDACTED:{}", secret.rule);
        assert!(html.contains(&tag), "no {tag} for the {}", secret.kind);
    }
    assert!(html.contains("[REDACTED:known_secret"));
    assert!(html.contains("web-01 token="));
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
