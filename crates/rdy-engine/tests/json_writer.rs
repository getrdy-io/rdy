//! The JSON writer end to end (M1-055): the escapes, one byte string for the file and stdout, the layout,
//! the schema's caps, the 2 MiB cap with its two stages and the reader's check. The HTML copy of the same
//! bytes is proved by the HTML golden (M1-078, `data-sha256`).
//!
//! Every report here goes through a real redactor first, because the writer takes nothing else. The
//! base is the 01 section 7.2 sample at `tests/fixtures/reports/not-ready-7.2.json`.

use std::error::Error;
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use rdy_engine::output::OutputDir;
use rdy_engine::redact::{RedactedReport, Redactor, TagKey};
use rdy_engine::report::{
    JsonError, MAX_REPORT_BYTES, json_bytes, read_report, read_report_from, write_json,
};
use rdy_spec::result::Report;
use serde_json::{Map, Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([5; 32]))
}

/// The sample as a JSON document, for a test to change.
fn sample_value() -> TestResult<Value> {
    let text =
        std::fs::read_to_string(repo_root().join("tests/fixtures/reports/not-ready-7.2.json"))?;
    Ok(serde_json::from_str(&text)?)
}

fn redact(doc: Value) -> TestResult<RedactedReport> {
    let report: Report = serde_json::from_value(doc)?;
    Ok(redactor().redact_report(report)?)
}

fn validator() -> TestResult<Validator> {
    let text =
        std::fs::read_to_string(repo_root().join("crates/rdy-spec/schema/result.v1.schema.json"))?;
    let schema: Value = serde_json::from_str(&text)?;
    Ok(jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?)
}

fn assert_valid(json: &str) -> TestResult {
    let instance: Value = serde_json::from_str(json)?;
    let errors: Vec<String> = validator()?
        .iter_errors(&instance)
        .take(10)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the report fails the schema: {errors:#?}"
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn written(report: &RedactedReport) -> TestResult<String> {
    Ok(json_bytes(report)?.as_str().to_owned())
}

fn parsed(json: &str) -> TestResult<Value> {
    Ok(serde_json::from_str(json)?)
}

/// A hostname that tries to close the element, open another and end the line in a script.
const HOSTILE: &str = "</script><img onerror=x>&amp;\u{2028}end</SCRIPT x><!--<ScRiPt>\u{2029}";

fn hostile_doc() -> TestResult<Value> {
    let mut doc = sample_value()?;
    doc["host"]["hostname"] = json!(HOSTILE);
    Ok(doc)
}

#[test]
fn a_hostname_with_a_script_end_tag_is_written_escaped() -> TestResult {
    let report = redact(hostile_doc()?)?;
    let json = written(&report)?;
    assert!(json.contains("\\u003c/script\\u003e\\u003cimg onerror=x\\u003e\\u0026amp;\\u2028end\\u003c/SCRIPT x\\u003e\\u003c!--\\u003cScRiPt\\u003e\\u2029"));
    for raw in ['<', '>', '&', '\u{2028}', '\u{2029}'] {
        assert!(!json.contains(raw), "{raw:?} is in the output");
    }
    // The escapes mean the same text: the document reads back to the hostname the report holds.
    assert_eq!(
        parsed(&json)?["host"]["hostname"],
        report.host.hostname.as_str()
    );
    assert_eq!(report.host.hostname, HOSTILE);
    Ok(())
}

#[test]
fn the_file_and_stdout_are_the_same_bytes_as_the_returned_text() -> TestResult {
    // The HTML copy is not simulated here: the renderer does not exist yet, and a test that wraps the
    // string itself proves nothing about it. M1-078 hashes the `<script>` text of the real page.
    let report = redact(hostile_doc()?)?;
    let json = json_bytes(&report)?;

    // `--json` on stdout.
    let mut stdout = Vec::new();
    write_json(&report, &mut stdout)?;
    assert_eq!(stdout, json.as_bytes());

    // The `.json` file.
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let path = out.write_json(&report)?;
    assert!(path.ends_with("rdy-report-acme-platform-20270309T143005Z.json"));
    let file = std::fs::read(&path)?;
    assert_eq!(file, json.as_bytes());

    let hashes = [
        sha256_hex(json.as_bytes()),
        sha256_hex(&stdout),
        sha256_hex(&file),
    ];
    assert!(hashes.iter().all(|h| h == &hashes[0]), "{hashes:?}");
    // Nothing in the text can close or open an element, so a template can print it unescaped.
    assert!(!json.as_str().contains(['<', '>', '&']));
    Ok(())
}

#[test]
fn the_layout_is_two_space_lf_in_schema_order_with_a_trailing_newline() -> TestResult {
    let json = written(&redact(sample_value()?)?)?;
    assert!(json.starts_with("{\n  \"api_version\": \"rdy/v1\",\n  \"kind\": \"Report\",\n  \"producer\": {\n    \"name\": \"rdy\","));
    assert!(json.ends_with("\n}\n"));
    assert!(!json.contains('\r'));
    assert!(!json.starts_with('\u{feff}'));
    // Top-level fields in the order of 01 section 5.
    let doc = parsed(&json)?;
    let positions: Vec<usize> = [
        "api_version",
        "kind",
        "producer",
        "run",
        "spec",
        "signature",
        "host",
        "identity",
        "proxy",
        "capabilities",
        "verdict",
        "verdict_reason",
        "exit_code",
        "summary",
        "checks",
        "actions",
        "actions_truncated",
        "actions_dropped",
        "redaction",
        "complete",
        "interrupted",
    ]
    .iter()
    .map(|name| {
        json.find(&format!("\n  \"{name}\":"))
            .ok_or(format!("no {name}"))
    })
    .collect::<Result<_, _>>()?;
    assert!(positions.is_sorted(), "{positions:?}");
    assert!(doc.is_object());
    assert_valid(&json)
}

#[test]
fn a_report_inside_the_caps_is_written_without_a_change() -> TestResult {
    let report = redact(sample_value()?)?;
    assert_eq!(parsed(&written(&report)?)?, serde_json::to_value(&*report)?);
    Ok(())
}

#[test]
fn the_same_report_gives_the_same_bytes_whatever_order_the_maps_were_filled_in() -> TestResult {
    let mut forward = sample_value()?;
    let mut backward = sample_value()?;
    let keys: Vec<String> = (0..20).map(|i| format!("key_{i:02}")).collect();
    for (doc, order) in [
        (&mut forward, keys.clone()),
        (&mut backward, keys.into_iter().rev().collect()),
    ] {
        let mut observed = Map::new();
        let mut fields = Map::new();
        for key in &order {
            observed.insert(key.clone(), json!({ "z": 1, "a": [2, 3] }));
            fields.insert(key.clone(), json!(1));
        }
        doc["checks"][0]["observed"] = Value::Object(observed);
        if let Some(Value::Object(action)) = doc["actions"].get_mut(0) {
            action.extend(fields);
        }
    }
    let a = written(&redact(forward)?)?;
    let b = written(&redact(backward)?)?;
    assert_eq!(a, b);
    assert!(a.find("\"key_00\"") < a.find("\"key_19\""));
    // An action keeps its common fields first, then its own fields in key order.
    let action = a.find("\"seq\": 1,").ok_or("no first action")?;
    let tail = a.get(action..).ok_or("bad slice")?;
    assert!(tail.find("\"outcome\"") < tail.find("\"bytes\""));
    assert!(tail.find("\"bytes\"") < tail.find("\"key_00\""));
    Ok(())
}

/// A check with `n` keys of nested data, as a large cluster reports.
fn heavy_doc() -> TestResult<Value> {
    let mut doc = sample_value()?;
    let observed: Map<String, Value> = (0..100)
        .map(|i| {
            (
                format!("node_{i:03}"),
                json!({ "cpu": i, "labels": { "zone": "a" } }),
            )
        })
        .collect();
    let mut observed = observed;
    observed.insert(
        "a_deep".to_owned(),
        json!({ "a": { "b": { "c": { "d": 1 } } } }),
    );
    observed.insert(
        "a_nodes".to_owned(),
        json!((0..200).map(|i| json!({ "n": i })).collect::<Vec<_>>()),
    );
    observed.insert(
        "a_huge".to_owned(),
        json!("a long line of text ".repeat(600)),
    );
    observed.insert(
        "a_wide".to_owned(),
        Value::Object((0..100).map(|i| (format!("w{i:03}"), json!(i))).collect()),
    );
    doc["checks"][0]["observed"] = Value::Object(observed);
    doc["checks"][0]["expected"] = json!({ "huge": "word ".repeat(2000), "ok": 1 });
    doc["checks"][0]["needs"] = json!(
        (0..40)
            .map(|_| json!({ "need": "network", "name": null, "hard": true, "met": true }))
            .collect::<Vec<_>>()
    );
    doc["checks"][1]["unsupported_fields"] =
        json!((0..1500).map(|i| format!("field_{i}")).collect::<Vec<_>>());
    doc["checks"][1]["partial"] = json!({
        "missing": (0..1200).map(|_| "root").collect::<Vec<_>>(),
        "missing_grants": (0..1500).map(|i| format!("grant:{i}")).collect::<Vec<_>>(),
        "note": "could not read everything",
    });
    doc["capabilities"] = json!((0..1200)
        .map(|_| json!({ "need": "root", "name": null, "available": true, "detail": null, "hint": null }))
        .collect::<Vec<_>>());
    doc["proxy"] = json!({ "https": null, "http": null, "no_proxy": (0..1100).map(|i| format!("h{i}.example")).collect::<Vec<_>>() });
    doc["spec"]["annotations"] = Value::Object(
        (0..40)
            .map(|i| (format!("note{i:02}"), json!("x")))
            .collect(),
    );
    doc["actions_dropped"] =
        Value::Object((0..40).map(|i| (format!("kind{i:02}"), json!(1))).collect());
    Ok(doc)
}

fn len_at(doc: &Value, pointer: &str) -> Option<usize> {
    match doc.pointer(pointer)? {
        Value::Array(items) => Some(items.len()),
        Value::Object(map) => Some(map.len()),
        _ => None,
    }
}

#[test]
fn a_large_report_is_cut_to_the_schema_caps_and_validates() -> TestResult {
    let report = redact(heavy_doc()?)?;
    let json = written(&report)?;
    let doc = parsed(&json)?;

    assert_eq!(len_at(&doc, "/checks/0/needs"), Some(32));
    assert_eq!(len_at(&doc, "/checks/1/unsupported_fields"), Some(1000));
    assert_eq!(len_at(&doc, "/checks/1/partial/missing"), Some(1000));
    assert_eq!(len_at(&doc, "/checks/1/partial/missing_grants"), Some(1000));
    assert_eq!(len_at(&doc, "/capabilities"), Some(1000));
    assert_eq!(len_at(&doc, "/proxy/no_proxy"), Some(1000));
    assert_eq!(len_at(&doc, "/spec/annotations"), Some(32));
    assert_eq!(len_at(&doc, "/actions_dropped"), Some(32));

    // `observed`: 64 keys, the first in key order. The four `a_` keys and `node_000` to `node_059` stay.
    assert_eq!(len_at(&doc, "/checks/0/observed"), Some(64));
    assert!(doc.pointer("/checks/0/observed/node_000").is_some());
    assert!(doc.pointer("/checks/0/observed/node_059").is_some());
    assert!(doc.pointer("/checks/0/observed/node_060").is_none());
    // A list or object at the fourth level is text.
    assert_eq!(
        doc.pointer("/checks/0/observed/a_deep/a/b"),
        Some(&json!("[truncated]"))
    );
    // A nested object past 64 keys is cut.
    assert_eq!(len_at(&doc, "/checks/0/observed/a_wide"), Some(64));
    // A text over 4 KiB is cut with the marker.
    let huge = doc
        .pointer("/checks/0/observed/a_huge")
        .and_then(Value::as_str)
        .ok_or("no huge")?;
    assert!(
        huge.len() <= 4096 && huge.ends_with(" [truncated]"),
        "{}",
        huge.len()
    );
    let expected = doc
        .pointer("/checks/0/expected/huge")
        .and_then(Value::as_str)
        .ok_or("no huge")?;
    assert!(expected.len() <= 4096 && expected.ends_with(" [truncated]"));
    // The check says so, and the other check that lost a list says so too. A check that lost nothing does not.
    assert_eq!(doc.pointer("/checks/0/truncated"), Some(&json!(true)));
    assert_eq!(doc.pointer("/checks/1/truncated"), Some(&json!(true)));
    assert_eq!(doc.pointer("/checks/2/truncated"), Some(&json!(false)));

    assert_valid(&json)
}

#[test]
fn the_caps_do_not_change_what_the_redactor_already_kept() -> TestResult {
    // The redactor cuts a list to 200 items, under the writer's 256. The 200 stay.
    let mut small = sample_value()?;
    small["checks"][0]["observed"] =
        json!({ "nodes": (0..300).map(|i| json!({ "n": i })).collect::<Vec<_>>() });
    let doc = parsed(&written(&redact(small)?)?)?;
    assert_eq!(len_at(&doc, "/checks/0/observed/nodes"), Some(200));
    assert_eq!(doc.pointer("/checks/0/truncated"), Some(&json!(true)));
    Ok(())
}

/// An `ok` file read.
fn read(seq: u64, path: &str) -> Value {
    json!({ "seq": seq, "check": "host.cpu", "at_ms": seq, "duration_ms": 0, "kind": "read",
            "outcome": "ok", "path": path, "bytes": 10, "truncated": false })
}

fn denied(seq: u64) -> Value {
    json!({ "seq": seq, "check": "host.cpu", "at_ms": seq, "duration_ms": 0, "kind": "read",
            "outcome": "denied", "rule": "outside_reads", "path": "/etc/shadow" })
}

fn exec(seq: u64) -> Value {
    json!({ "seq": seq, "check": "host.cpu", "at_ms": seq, "duration_ms": 1, "kind": "exec",
            "outcome": "ok", "program": "lscpu", "argv": ["lscpu"], "exit": 0, "stdout_bytes": 100,
            "truncated": false })
}

fn kinds(doc: &Value) -> Vec<(u64, String, String)> {
    doc["actions"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|a| {
                    (
                        a["seq"].as_u64().unwrap_or(0),
                        a["kind"].as_str().unwrap_or("").to_owned(),
                        a["outcome"].as_str().unwrap_or("").to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn more_than_5000_actions_shed_the_newest_ok_reads_first() -> TestResult {
    let mut doc = sample_value()?;
    let mut actions: Vec<Value> = (1..=6000).map(|i| read(i, "/proc/cpuinfo")).collect();
    actions.push(denied(6001));
    actions.extend((6002..=6004).map(exec));
    doc["actions"] = Value::Array(actions);

    let json = written(&redact(doc)?)?;
    let out = parsed(&json)?;
    let kept = kinds(&out);
    assert_eq!(kept.len(), 5000);
    // 6004 entries, 1004 over: the 1004 newest `ok` reads go. The denied entry and the commands stay.
    assert_eq!(out["actions_dropped"]["read"], 1004);
    assert_eq!(out["actions_truncated"], true);
    assert!(
        kept.iter()
            .any(|(seq, _, outcome)| *seq == 6001 && outcome == "denied")
    );
    assert_eq!(kept.iter().filter(|(_, kind, _)| kind == "exec").count(), 3);
    let reads: Vec<u64> = kept
        .iter()
        .filter(|(_, kind, outcome)| kind == "read" && outcome == "ok")
        .map(|(seq, _, _)| *seq)
        .collect();
    assert_eq!(reads, (1..=4996).collect::<Vec<u64>>());
    assert_valid(&json)
}

#[test]
fn a_report_over_2_mib_sheds_actions_in_the_order_of_the_log() -> TestResult {
    let mut doc = sample_value()?;
    // 1500 reads of 1.5 KiB paths is about 2.3 MiB. Words, so no rule reads them as one secret.
    let path = format!("/srv/{}", "data dir ".repeat(170));
    let mut actions: Vec<Value> = (1..=1500).map(|i| read(i, &path)).collect();
    actions.push(denied(1501));
    actions.push(exec(1502));
    doc["actions"] = Value::Array(actions);

    let json = written(&redact(doc)?)?;
    assert!(json.len() <= MAX_REPORT_BYTES, "{}", json.len());
    assert!(
        json.len() > MAX_REPORT_BYTES - 4 * 1024,
        "{}: it shed more than it had to",
        json.len()
    );
    let out = parsed(&json)?;
    let kept = kinds(&out);
    assert!(
        kept.iter()
            .any(|(_, kind, outcome)| kind == "read" && outcome == "denied")
    );
    assert!(kept.iter().any(|(_, kind, _)| kind == "exec"));
    let oks: Vec<u64> = kept
        .iter()
        .filter(|(_, kind, outcome)| kind == "read" && outcome == "ok")
        .map(|(seq, _, _)| *seq)
        .collect();
    // The oldest stay: a prefix of 1, 2, 3 ...
    assert_eq!(oks, (1..=oks.len() as u64).collect::<Vec<u64>>());
    assert!(oks.len() < 1500);
    assert_eq!(out["actions_truncated"], true);
    assert_eq!(
        out["actions_dropped"]["read"].as_u64(),
        Some(1500 - oks.len() as u64)
    );
    assert_valid(&json)
}

#[test]
fn the_cap_is_measured_after_the_escapes() -> TestResult {
    let mut doc = sample_value()?;
    // 400 raw bytes become 2400 bytes of `\u003c`. 1000 entries are 0.4 MB raw and 2.4 MB written.
    let path = "<".repeat(400);
    doc["actions"] = Value::Array((1..=1000).map(|i| read(i, &path)).collect());
    let json = written(&redact(doc)?)?;
    assert!(json.len() <= MAX_REPORT_BYTES, "{}", json.len());
    let out = parsed(&json)?;
    assert!(kinds(&out).len() < 1000);
    assert_eq!(out["actions_truncated"], true);
    assert!(!json.contains('<'));
    Ok(())
}

/// `n` checks cloned from the sample's first, each with the map `observed(i)` as `observed`.
fn with_checks(doc: &mut Value, n: usize, observed: impl Fn(usize) -> Option<Map<String, Value>>) {
    let template = doc["checks"][0].clone();
    let checks: Vec<Value> = (0..n)
        .map(|i| {
            let mut check = template.clone();
            check["key"] = json!(format!("host.cpu.{i}"));
            check["observed"] = observed(i).map_or(Value::Null, Value::Object);
            check["expected"] = Value::Null;
            check
        })
        .collect();
    doc["checks"] = Value::Array(checks);
}

/// A map of 20 texts of `words` repeats each. Words, so no rule reads them as one secret.
fn text_map(words: usize) -> Map<String, Value> {
    (0..20)
        .map(|i| {
            (
                format!("k{i:02}"),
                json!(format!("some words {i} ").repeat(words)),
            )
        })
        .collect()
}

fn observed_len(check: &Value) -> usize {
    check["observed"].as_object().map_or(0, |map| {
        serde_json::to_string(map).map_or(0, |text| text.len())
    })
}

#[test]
fn a_report_over_2_mib_clears_observed_on_the_largest_checks_first() -> TestResult {
    let mut doc = sample_value()?;
    // 64 checks whose `observed` grows with the index. Together they are about 4 MiB.
    with_checks(&mut doc, 64, |i| Some(text_map(20 + 4 * i)));
    let report = redact(doc)?;
    let before: Vec<Value> = serde_json::to_value(&*report)?["checks"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let json = written(&report)?;
    assert!(json.len() <= MAX_REPORT_BYTES, "{}", json.len());
    let out = parsed(&json)?;
    let after = out["checks"].as_array().ok_or("no checks")?;
    assert_eq!(after.len(), 64);

    let cleared: Vec<usize> = (0..64)
        .filter(|&i| after[i]["observed"].is_null())
        .collect();
    assert!(!cleared.is_empty() && cleared.len() < 64, "{cleared:?}");
    // The largest first: every cleared one is at least as big as every one that kept its values.
    let smallest_cleared = cleared.iter().map(|&i| observed_len(&before[i])).min();
    let biggest_kept = (0..64)
        .filter(|i| !cleared.contains(i))
        .map(|i| observed_len(&before[i]))
        .max();
    assert!(
        smallest_cleared >= biggest_kept,
        "{smallest_cleared:?} {biggest_kept:?}"
    );
    // Only what was needed: one value fewer cleared would not fit, so the report is within the size of
    // the next largest value (70 KiB at most) of the cap.
    assert!(json.len() + 70 * 1024 > MAX_REPORT_BYTES, "{}", json.len());

    for i in 0..64 {
        let (was, now) = (&before[i], &after[i]);
        for field in ["key", "status", "message", "fix", "needs", "notes"] {
            assert_eq!(was.get(field), now.get(field), "check {i} field {field}");
        }
        assert_eq!(
            now["truncated"].as_bool(),
            Some(cleared.contains(&i) || was["truncated"] == true),
            "check {i}"
        );
    }
    assert_eq!(out["verdict"], serde_json::to_value(report.verdict)?);
    assert_valid(&json)
}

#[test]
fn a_report_too_big_with_nothing_left_to_clear_is_refused_and_nothing_is_written() -> TestResult {
    let mut doc = sample_value()?;
    // 256 checks with 20 notes of 1 KiB each and no measured values: about 5 MiB of results.
    with_checks(&mut doc, 256, |_| None);
    let note = "a note with some words ".repeat(44);
    for check in doc["checks"].as_array_mut().ok_or("no checks")? {
        check["notes"] = json!((0..20).map(|_| note.clone()).collect::<Vec<_>>());
    }
    let report = redact(doc)?;

    let Err(err) = json_bytes(&report) else {
        return Err("a 5 MiB report was written".into());
    };
    let JsonError::TooLarge {
        max,
        ref largest,
        bytes,
    } = err
    else {
        return Err(format!("wrong error: {err}").into());
    };
    assert_eq!(max, MAX_REPORT_BYTES);
    assert!(bytes > MAX_REPORT_BYTES);
    assert_eq!(largest.split(", ").count(), 3, "{largest}");
    let text = err.to_string();
    assert!(text.contains("Fix:") && text.contains("vendor") && text.contains(largest.as_str()));

    let mut sink = Vec::new();
    assert!(write_json(&report, &mut sink).is_err());
    assert!(sink.is_empty());

    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    assert!(out.write_json(&report).is_err());
    let listing: Vec<_> = std::fs::read_dir(out.path())?.collect();
    assert!(listing.is_empty(), "{listing:?}");
    Ok(())
}

/// A refused read whose path is about `len` bytes of words.
fn denied_long(seq: u64, len: usize) -> Value {
    let mut entry = denied(seq);
    entry["path"] = json!(format!("/srv/{}", "data dir ".repeat(len / 9)));
    entry
}

#[test]
fn denied_entries_are_never_shed_to_make_room() -> TestResult {
    let mut doc = sample_value()?;
    // 30 checks of 64 KiB each are just under the cap. 50 refused reads of 3 KiB push it over.
    with_checks(&mut doc, 30, |_| Some(text_map(400)));
    let alone = written(&redact(doc.clone())?)?.len();
    assert!(
        alone <= MAX_REPORT_BYTES && alone + 150 * 1024 > MAX_REPORT_BYTES,
        "the results alone are {alone} bytes"
    );
    doc["actions"] = Value::Array((1..=50).map(|i| denied_long(i, 3000)).collect());

    let json = written(&redact(doc)?)?;
    assert!(json.len() <= MAX_REPORT_BYTES, "{}", json.len());
    let out = parsed(&json)?;
    let kept = kinds(&out);
    assert_eq!(kept.len(), 50, "a refused call was shed");
    assert!(kept.iter().all(|(_, _, outcome)| outcome == "denied"));
    // Nothing was shed from the log, so it is not marked as cut.
    assert_eq!(out["actions_truncated"], false);
    // The room came from `observed` of the largest checks.
    let cleared = out["checks"].as_array().map_or(0, |checks| {
        checks.iter().filter(|c| c["observed"].is_null()).count()
    });
    assert!(cleared >= 1, "{cleared}");
    assert_valid(&json)
}

#[test]
fn last_resort_shedding_takes_other_entries_before_denied_and_counts_folded_calls() -> TestResult {
    let mut doc = sample_value()?;
    let words = "some words ".repeat(300);
    let heavy_exec = |seq: u64| {
        let mut entry = exec(seq);
        entry["argv"] = json!(["lscpu", words.clone()]);
        entry
    };
    let mut actions = vec![json!({
        "seq": 1, "check": "host.cpu", "at_ms": 1, "duration_ms": 0, "kind": "coalesced",
        "outcome": "ok", "of": "read", "under": "/proc", "count": 400
    })];
    actions.extend((2..=51).map(|i| denied_long(i, 200)));
    // 800 commands of 3.3 KiB are about 2.6 MiB: more than the cap, with no file call left but one fold.
    actions.extend((52..=851).map(heavy_exec));
    doc["actions"] = Value::Array(actions);

    let json = written(&redact(doc)?)?;
    assert!(json.len() <= MAX_REPORT_BYTES, "{}", json.len());
    assert!(
        json.len() + 8 * 1024 > MAX_REPORT_BYTES,
        "{}: it shed more than it had to",
        json.len()
    );
    let out = parsed(&json)?;
    let kept = kinds(&out);
    // All 50 refused calls stay, and the folded `ok` entry went first.
    assert_eq!(kept.iter().filter(|(_, _, o)| o == "denied").count(), 50);
    assert!(!kept.iter().any(|(_, kind, _)| kind == "coalesced"));
    // The newest commands go first, so the ones that stay are a prefix.
    let execs: Vec<u64> = kept
        .iter()
        .filter(|(_, kind, _)| kind == "exec")
        .map(|(seq, _, _)| *seq)
        .collect();
    assert!(!execs.is_empty() && execs.len() < 800);
    assert_eq!(execs, (52..52 + execs.len() as u64).collect::<Vec<u64>>());
    // A folded entry counts its calls, not one.
    assert_eq!(out["actions_dropped"]["read"], 400);
    assert_eq!(
        out["actions_dropped"]["exec"].as_u64(),
        Some(800 - execs.len() as u64)
    );
    assert_eq!(out["actions_truncated"], true);
    assert_valid(&json)
}

/// True if `rest` starts with a whole placeholder, `[REDACTED:<rule>:<8 hex digits>]`.
fn starts_with_placeholder(rest: &str) -> bool {
    let Some(body) = rest.strip_prefix("[REDACTED:") else {
        return false;
    };
    let Some((inside, _)) = body.split_once(']') else {
        return false;
    };
    inside.rsplit_once(':').is_some_and(|(rule, hex)| {
        !rule.is_empty() && hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

#[test]
fn a_cut_text_never_ends_in_part_of_a_placeholder() -> TestResult {
    let mut cut_cases = 0;
    for lead in 3990..4100 {
        let mut doc = sample_value()?;
        let pad = "ab ".repeat(lead / 3);
        doc["checks"][0]["observed"] = json!({
            "log": format!("{pad}password=hunter2canary\n{pad}")
        });
        let json = written(&redact(doc)?)?;
        let out = parsed(&json)?;
        let text = out["checks"][0]["observed"]["log"]
            .as_str()
            .ok_or("no log")?;
        assert!(!text.contains("hunter2canary"), "lead {lead}");
        for (at, _) in text.match_indices("[REDACTED") {
            let rest = text.get(at..).unwrap_or_default();
            assert!(
                starts_with_placeholder(rest),
                "lead {lead} left a stub: {rest}"
            );
        }
        cut_cases += usize::from(text.ends_with(" [truncated]") && text.contains("[REDACTED"));
        assert!(text.len() <= 4096, "lead {lead}: {}", text.len());
    }
    assert!(cut_cases > 0, "no case cut a text next to a placeholder");
    Ok(())
}

#[test]
fn more_than_256_results_are_refused_not_cut() -> TestResult {
    let mut doc = sample_value()?;
    let template = doc["checks"][0].clone();
    doc["checks"] = Value::Array((0..257).map(|_| template.clone()).collect());
    let report = redact(doc)?;
    assert!(matches!(
        json_bytes(&report),
        Err(JsonError::TooManyChecks {
            found: 257,
            max: 256
        })
    ));
    Ok(())
}

#[test]
fn a_reader_refuses_a_document_over_2_mib_before_it_parses() -> TestResult {
    // Not JSON at all: if the reader parsed first, the error would be `Parse`.
    let junk = vec![b'{'; MAX_REPORT_BYTES + 1];
    assert!(matches!(
        read_report(&junk),
        Err(JsonError::InputTooLarge { bytes, max }) if bytes == MAX_REPORT_BYTES + 1 && max == MAX_REPORT_BYTES
    ));
    // The cap is inclusive: a document of exactly the cap is read (and fails as JSON here, not on size).
    let at_cap = vec![b' '; MAX_REPORT_BYTES];
    assert!(matches!(read_report(&at_cap), Err(JsonError::Parse { .. })));
    // A report the writer made reads back.
    let report = redact(sample_value()?)?;
    let json = json_bytes(&report)?;
    let back = read_report(json.as_bytes())?;
    assert_eq!(back, *report);
    // The parse error does not quote the document.
    let Err(err) = read_report(b"{\"api_version\": \"hunter2-canary\"}") else {
        return Err("a bad document was read".into());
    };
    assert!(!err.to_string().contains("hunter2"));
    Ok(())
}

/// A reader that never ends and counts what it handed out.
struct Endless {
    served: usize,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(b' ');
        self.served += buf.len();
        Ok(buf.len())
    }
}

/// A reader that fails.
struct Broken;

impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("disk gone"))
    }
}

#[test]
fn a_stream_is_read_no_further_than_one_byte_past_the_cap() -> TestResult {
    let mut endless = Endless { served: 0 };
    let result = read_report_from(&mut endless);
    assert!(
        matches!(result, Err(JsonError::InputTooLarge { bytes, max })
            if bytes == MAX_REPORT_BYTES + 1 && max == MAX_REPORT_BYTES),
        "{result:?}"
    );
    assert_eq!(endless.served, MAX_REPORT_BYTES + 1);

    // A report the writer made reads back through a stream, and a failing stream is an `Io` error.
    let report = redact(sample_value()?)?;
    let json = json_bytes(&report)?;
    assert_eq!(read_report_from(json.as_bytes())?, *report);
    assert!(matches!(read_report_from(Broken), Err(JsonError::Io(_))));
    Ok(())
}

#[test]
fn the_file_is_private_and_named_after_the_folder() -> TestResult {
    let report = redact(sample_value()?)?;
    let parent = tempfile::tempdir()?;
    let out = OutputDir::create_new(parent.path(), "acme-platform", "20270309T143005Z")?;
    let path = out.write_json(&report)?;
    assert_eq!(
        path.file_name().and_then(|n| n.to_str()),
        Some("rdy-report-acme-platform-20270309T143005Z.json")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
    }
    // A second write does not replace the file.
    assert!(out.write_json(&report).is_err());
    Ok(())
}

/// The golden: the sample with a hostile hostname and maps that were filled out of order, written by
/// the writer. Every leg compares it, because the bytes must not depend on the OS.
#[test]
fn the_written_report_matches_its_golden() -> TestResult {
    use rdy_engine::testing::{fixtures_dir, golden::assert_golden};

    let mut doc = hostile_doc()?;
    doc["checks"][0]["observed"] =
        json!({ "zone": "b", "cores": 8, "labels": { "y": 1, "x": [3, 2, 1] } });
    doc["checks"][1]["observed"] = Value::Null;
    let report = redact(doc)?;
    assert_golden(
        fixtures_dir().join("reports/golden/not-ready-hostile-host.json"),
        json_bytes(&report)?.as_bytes(),
    );
    Ok(())
}
