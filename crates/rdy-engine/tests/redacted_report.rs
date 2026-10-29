//! The report walk against the samples of 01 section 7 (M1-062).
//!
//! The samples are read from `docs/plan/01-spec-format.md`, as the result tests in `rdy-spec` do. Redacting
//! one must change nothing. Planting a canary must change exactly the planted fields and the `redaction`
//! block, and no canary may survive anywhere in the output.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use rdy_engine::redact::{RedactedReport, Redactor, RuleCounts, TagKey};
use rdy_spec::result::{CheckResult, Report};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([9; 32]))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The first fenced `json` block under the `###` heading that starts with `heading` in 01.
fn sample(heading: &str) -> TestResult<Value> {
    let doc = std::fs::read_to_string(repo_root().join("docs/plan/01-spec-format.md"))?
        .replace("\r\n", "\n");
    let start = doc
        .find(&format!("\n### {heading}"))
        .ok_or("heading not found")?;
    let after_heading = start + "\n### ".len();
    let end = doc[after_heading..]
        .find("\n#")
        .map_or(doc.len(), |i| after_heading + i);
    let section = &doc[start..end];
    let open = section.find("```json\n").ok_or("no json block")? + "```json\n".len();
    let body = &section[open..];
    let close = body.find("\n```").ok_or("unterminated json block")?;
    Ok(serde_json::from_str(&body[..close])?)
}

/// The JSON pointers of every leaf that differs between two documents, or exists in only one.
fn changed_paths(a: &Value, b: &Value) -> BTreeSet<String> {
    fn walk(path: &str, a: &Value, b: &Value, out: &mut BTreeSet<String>) {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
                for key in keys {
                    let at = format!("{path}/{key}");
                    match (x.get(key), y.get(key)) {
                        (Some(p), Some(q)) => walk(&at, p, q, out),
                        _ => {
                            out.insert(at);
                        }
                    }
                }
            }
            (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
                for (i, (p, q)) in x.iter().zip(y).enumerate() {
                    walk(&format!("{path}/{i}"), p, q, out);
                }
            }
            _ if a == b => {}
            _ => {
                out.insert(path.to_owned());
            }
        }
    }
    let mut out = BTreeSet::new();
    walk("", a, b, &mut out);
    out
}

fn redact(doc: &Value) -> TestResult<RedactedReport> {
    let report: Report = serde_json::from_value(doc.clone())?;
    Ok(redactor().redact_report(report)?)
}

#[test]
fn the_01_samples_come_through_unchanged() -> TestResult {
    for heading in ["7.2 ", "7.3 "] {
        let original = sample(heading)?;
        let out = redact(&original)?;
        let written = serde_json::to_value(&*out)?;
        assert_eq!(written, original, "{heading} changed");
        assert_eq!(out.redaction.total, 0);
    }
    Ok(())
}

#[test]
fn the_01_check_results_come_through_unchanged() -> TestResult {
    let items = sample("7.4 ")?;
    for item in items.as_array().ok_or("7.4 is an array")? {
        let result: CheckResult = serde_json::from_value(item.clone())?;
        let mut counts = RuleCounts::default();
        let out = redactor().redact_check(result, &mut counts)?;
        assert_eq!(&serde_json::to_value(&*out)?, item);
        assert_eq!(counts.total(), 0);
    }
    Ok(())
}

/// A canary no rule can mistake for a placeholder or a plain word.
const CANARY: &str = "canary-Zk3v9Qx7";

#[test]
fn planted_canaries_change_only_the_planted_fields_and_the_redaction_block() -> TestResult {
    for heading in ["7.2 ", "7.3 "] {
        let original = sample(heading)?;
        let mut planted = original.clone();
        planted["host"]["hostname"] = json!(format!("web-01 password={CANARY}-1"));
        planted["checks"][0]["message"] = json!(format!("failed, token={CANARY}-2 was sent"));
        planted["checks"][0]["observed"] = json!({
            "db_password": format!("{CANARY}-3"),
            "cores": 4,
        });
        planted["actions"][0]["path"] = json!(format!("/etc/app.conf secret={CANARY}-4"));

        let out = redact(&planted)?;
        let written = serde_json::to_value(&*out)?;
        let text = serde_json::to_string(&written)?;
        assert!(!text.contains(CANARY), "{heading}: a canary survived");

        let changed = changed_paths(&planted, &written);
        let want: BTreeSet<String> = [
            "/host/hostname",
            "/checks/0/message",
            "/checks/0/observed/db_password",
            "/actions/0/path",
            "/redaction/total",
            "/redaction/by_rule/secret_by_key",
        ]
        .map(str::to_owned)
        .into();
        assert_eq!(changed, want, "{heading}");
        assert_eq!(out.redaction.total, 4);
        assert_eq!(out.redaction.by_rule.get("secret_by_key"), Some(&4));
    }
    Ok(())
}

#[test]
fn by_rule_does_not_depend_on_what_the_logs_redact_at_the_same_time() -> TestResult {
    // The log layer shares the process redactor and its key. At RUST_LOG=trace it redacts far more text
    // than with RUST_LOG unset. The report's counts are per call, so they must not move.
    let mut planted = sample("7.2 ")?;
    planted["checks"][0]["message"] = json!(format!("token={CANARY}-a and password={CANARY}-b"));
    planted["host"]["hostname"] = json!(format!("secret={CANARY}-c"));

    let shared = redactor();
    let quiet = {
        let report: Report = serde_json::from_value(planted.clone())?;
        shared.redact_report(report)?
    };

    let stop = AtomicBool::new(false);
    let loud = thread::scope(|scope| -> TestResult<RedactedReport> {
        let logger = scope.spawn(|| {
            let mut lines = 0_u32;
            while !stop.load(Ordering::Relaxed) {
                let line = shared.redact_str(&format!("TRACE rdy: password={CANARY}-log {lines}"));
                assert!(!line.contains(CANARY));
                lines += 1;
            }
        });
        let mut last = None;
        for _ in 0..50 {
            let report: Report = serde_json::from_value(planted.clone())?;
            last = Some(shared.redact_report(report)?);
        }
        stop.store(true, Ordering::Relaxed);
        logger.join().map_err(|_| "the logger thread panicked")?;
        Ok(last.ok_or("no report")?)
    })?;

    assert_eq!(quiet.redaction.by_rule, loud.redaction.by_rule);
    // The key rule runs to the end of the line, so `token=` and `password=` in one message are one span.
    assert_eq!(quiet.redaction.total, 2);
    assert_eq!(
        serde_json::to_value(&*quiet)?,
        serde_json::to_value(&*loud)?
    );
    Ok(())
}

#[test]
fn a_report_built_from_raw_results_is_redacted_on_a_plain_thread() -> TestResult {
    // The watchdog runs on a plain OS thread, before and outside the runtime, on a snapshot that may hold
    // results nobody redacted yet. It calls the same function and never assumes redaction happened.
    let mut planted = sample("7.2 ")?;
    planted["complete"] = json!(false);
    planted["interrupted"] = json!(true);
    planted["checks"][1]["message"] = json!(format!("timed out, password={CANARY}-w"));
    planted["checks"][1]["notes"] = json!([format!("token={CANARY}-n")]);
    let report: Report = serde_json::from_value(planted)?;

    let out = thread::spawn(move || redactor().redact_report(report))
        .join()
        .map_err(|_| "the watchdog thread panicked")??;
    let text = serde_json::to_string(&*out)?;
    assert!(!text.contains(CANARY), "the snapshot was not redacted");
    assert!(!out.complete);
    assert_eq!(out.redaction.total, 2);
    Ok(())
}

#[test]
fn results_are_redacted_as_they_complete_so_a_snapshot_never_holds_raw_text() -> TestResult {
    let items = sample("7.4 ")?;
    let mut counts = RuleCounts::default();
    let mut snapshot = Vec::new();
    for (i, item) in items.as_array().ok_or("array")?.iter().enumerate() {
        let mut result: CheckResult = serde_json::from_value(item.clone())?;
        result.message = format!("{} password={CANARY}-{i}", result.message);
        snapshot.push(redactor().redact_check(result, &mut counts)?);
        // After each completion, what a watchdog or a progress display could read has no canary.
        let seen = serde_json::to_string(&snapshot.iter().map(|c| &**c).collect::<Vec<_>>())?;
        assert!(!seen.contains(CANARY), "after result {i}");
    }
    assert_eq!(counts.get("secret_by_key"), snapshot.len() as u64);

    // The final pass keeps the earlier counts and finds nothing more.
    let template: Report = serde_json::from_value(sample("7.2 ")?)?;
    let mut report = template;
    report.checks = snapshot.iter().map(|c| (**c).clone()).collect();
    report.refresh_verdict();
    let total = counts.total();
    let out = redactor().redact_report_counted(report, counts)?;
    assert_eq!(out.redaction.total, total);
    Ok(())
}
