//! The report walk against the samples of 01 section 7 (M1-062).
//!
//! The samples are read from `docs/plan/01-spec-format.md`, as the result tests in `rdy-spec` do. Redacting
//! one must change nothing. Planting a canary must change exactly the planted fields and the `redaction`
//! block, and no canary may survive anywhere in the output.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use rdy_engine::check::{CheckInfo, CheckMeta, Need, Os, OsSupport, Support};
use rdy_engine::probe::{NativeCall, ProbeError};
use rdy_engine::redact::{RedactedReport, Redactor, RuleCounts, TagKey};
use rdy_engine::testing::{Replay, TestRun};
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
    // Both threads start together, so the logger is busy for the whole time the reports are walked.
    let start = Barrier::new(2);
    let loud = thread::scope(|scope| -> TestResult<RedactedReport> {
        let logger = scope.spawn(|| {
            start.wait();
            let mut lines = 0_u32;
            while !stop.load(Ordering::Relaxed) {
                let line = shared.redact_str(&format!("TRACE rdy: password={CANARY}-log {lines}"));
                assert!(!line.contains(CANARY));
                lines += 1;
            }
        });
        let mut last = None;
        start.wait();
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

/// The exit test of M1-056 that has no report before M1-062 (PC-43): canaries in an env pair, a kubeconfig,
/// command output and an argv never reach the serialized report. The tracing field part is proved on the
/// real binary by M1-057, and the HTML part by M1-077.
const PC43_CANARIES: [&str; 6] = [
    "canary-env-token-2",
    "canary-kube-token-3",
    "canary-kube-text-3b",
    "canary-output-hdr-4",
    "canary-argv-5",
    "canary-action-argv-6",
];

fn plant_pc43(doc: &mut Value) {
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
}

#[test]
fn canaries_in_env_kubeconfig_output_and_argv_never_reach_the_report() -> TestResult {
    for heading in ["7.2 ", "7.3 "] {
        let mut planted = sample(heading)?;
        plant_pc43(&mut planted);

        // The whole report in one call.
        let out = redact(&planted)?;
        let text = serde_json::to_string(&*out)?;
        for canary in PC43_CANARIES {
            assert!(!text.contains(canary), "{heading}: {canary} leaked");
        }
        assert!(
            out.redaction.total >= 6,
            "{heading}: {}",
            out.redaction.total
        );

        // Result by result as they complete, then the final pass, the way the engine will run it.
        let report: Report = serde_json::from_value(planted)?;
        let mut counts = RuleCounts::default();
        let mut done = report.clone();
        done.checks = report
            .checks
            .into_iter()
            .map(|c| {
                redactor()
                    .redact_check(c, &mut counts)
                    .map(|r| (*r).clone())
            })
            .collect::<Result<_, _>>()?;
        let out = redactor().redact_report_counted(done, counts)?;
        let text = serde_json::to_string(&*out)?;
        for canary in PC43_CANARIES {
            assert!(
                !text.contains(canary),
                "{heading}: {canary} leaked in pass two"
            );
        }
    }
    Ok(())
}

/// `client-key-data` is a kubeconfig key (04 Appendix B, `kubeconfig_credential`). It has the `keydata`
/// stem, so the report walk replaces the member and the key rule finds it in text.
#[test]
fn a_kubeconfig_client_key_never_reaches_the_report() -> TestResult {
    let mut planted = sample("7.2 ")?;
    planted["checks"][0]["observed"] = json!({
        "kubeconfig": {"users": [{"user": {"client-key-data": "canary-kube-key-7"}}]},
        "kubeconfig_text": "user:\n  client-key-data: canary-kube-key-7b\n",
    });
    let text = serde_json::to_string(&*redact(&planted)?)?;
    assert!(!text.contains("canary-kube-key-7"), "a client key leaked");
    Ok(())
}

/// A made-up machine id, in the form systemd writes it.
const MACHINE_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// A check that declared the whole tree for reading, as a disk check must to measure any spec path.
static BROAD_READS: CheckInfo = CheckInfo {
    id: "host.fixture",
    family: "host",
    summary: "Reads anywhere.",
    meta: CheckMeta {
        title: "Fixture check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::NotYet,
    },
    reads: &["/"],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// SEC-94-4: the raw machine id is in the replay fixture, and a check with broad reads tries every way
/// to put it in its result. It reaches neither `observed` nor the action log nor the redacted report.
/// The JSON half of the writers is checked here; `render_html` does not exist before M1-077, and its
/// golden test (M1-083) takes the same fixture.
#[tokio::test]
async fn the_machine_id_never_reaches_the_report_even_for_a_check_with_broad_reads() -> TestResult {
    let files = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
    let mut replay = Replay::new();
    for file in files {
        replay = replay.file(file, format!("{MACHINE_ID}\n"));
    }
    let run = TestRun::new(replay);
    let ctx = run.context_for(&BROAD_READS, "host.fixture", Os::Linux, [Need::Root]);
    let probe = ctx.probe();

    // What a careless check would copy into `observed`: file text, or the error text.
    let mut observed = serde_json::Map::new();
    for file in files {
        let text = match probe.read(Path::new(file)).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes.bytes).into_owned(),
            Err(error @ ProbeError::Denied { .. }) => error.to_string(),
            Err(other) => return Err(format!("{file}: {other:?}").into()),
        };
        observed.insert(file.to_owned(), json!(text));
    }
    // The native call is for the engine only, so a check's probe is refused.
    let call = probe.native(NativeCall::MachineId).await;
    assert!(matches!(call, Err(ProbeError::Denied { .. })), "{call:?}");
    observed.insert("machine_id_call".to_owned(), json!(format!("{call:?}")));

    let mut doc = sample("7.2 ")?;
    doc["checks"][0]["observed"] = Value::Object(observed);
    doc["actions"] = serde_json::to_value(run.action_log().actions)?;
    assert!(
        !doc.to_string().contains(MACHINE_ID),
        "the id reached the result before redaction"
    );

    let out = redact(&doc)?;
    let written = serde_json::to_string(&*out)?;
    assert!(!written.contains(MACHINE_ID), "the id is in the report");
    assert!(!format!("{out:?}").contains(MACHINE_ID));
    Ok(())
}
