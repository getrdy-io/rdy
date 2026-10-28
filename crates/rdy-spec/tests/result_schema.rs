//! The result types against `schema/result.v1.schema.json` and the samples of 01 section 7.
//!
//! The samples are read straight from docs/plan/01-spec-format.md, so the doc, the schema and the Rust
//! types cannot drift apart without this test failing.
//!
//! "Byte for byte" is checked on canonical JSON: both sides are written compactly with object keys in
//! sorted order, so the bytes are equal exactly when every key and value is equal. The sample files are
//! pretty-printed by hand with inline arrays, so comparing their raw text would test the editor, not the
//! types. Writing the report in schema order with two-space indent is the JSON writer's job (M1-055).

use std::error::Error;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use rdy_spec::result::{
    Bucket, CheckResult, Report, Severity, SignatureState, SkipKind, Status, Verdict,
    VerdictReason, classify, verdict,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn schema_value() -> TestResult<Value> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/result.v1.schema.json"),
    )?;
    Ok(serde_json::from_str(&text)?)
}

/// A validator for `$defs/<def>`, or for the whole report when `def` is `None`.
fn validator(def: Option<&str>) -> TestResult<Validator> {
    let mut schema = schema_value()?;
    if let Some(def) = def {
        schema["$ref"] = Value::String(format!("#/$defs/{def}"));
    }
    Ok(jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?)
}

fn assert_valid(v: &Validator, instance: &Value, what: &str) {
    let errors: Vec<String> = v
        .iter_errors(instance)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{what} fails the schema: {errors:#?}");
}

fn is_valid(v: &Validator, instance: &Value) -> bool {
    v.iter_errors(instance).next().is_none()
}

/// The first fenced `json` block after the heading that starts with `heading`.
fn sample(heading: &str) -> TestResult<Value> {
    let doc = std::fs::read_to_string(repo_root().join("docs/plan/01-spec-format.md"))?;
    let start = doc
        .find(&format!("\n### {heading}"))
        .ok_or("heading not found")?;
    let rest = &doc[start..];
    let open = rest.find("```json\n").ok_or("no json block")? + "```json\n".len();
    let body = &rest[open..];
    let close = body.find("\n```").ok_or("unterminated json block")?;
    Ok(serde_json::from_str(&body[..close])?)
}

fn canonical(v: &Value) -> TestResult<String> {
    Ok(serde_json::to_string(v)?)
}

#[test]
fn samples_7_2_and_7_3_validate_and_round_trip() -> TestResult {
    let v = validator(None)?;
    for heading in ["7.2 ", "7.3 "] {
        let original = sample(heading)?;
        assert_valid(&v, &original, heading);

        let report: Report = serde_json::from_value(original.clone())?;
        let written = serde_json::to_value(&report)?;
        assert_eq!(
            canonical(&written)?,
            canonical(&original)?,
            "{heading} did not round trip"
        );
        assert_valid(&v, &written, "the written report");

        // The text form reads back to the same report.
        let text = serde_json::to_string_pretty(&report)?;
        assert_eq!(serde_json::from_str::<Report>(&text)?, report);
    }
    Ok(())
}

#[test]
fn sample_7_4_validates_and_round_trips() -> TestResult {
    let v = validator(Some("CheckResult"))?;
    let original = sample("7.4 ")?;
    let items = original.as_array().ok_or("7.4 is an array")?;
    assert_eq!(items.len(), 5);
    for item in items {
        assert_valid(&v, item, "7.4 entry");
        let result: CheckResult = serde_json::from_value(item.clone())?;
        assert_eq!(
            canonical(&serde_json::to_value(&result)?)?,
            canonical(item)?
        );
        // The stored bucket is the one the rule computes.
        assert_eq!(
            result.bucket,
            classify(&result.severity, &result.status, result.skip_kind.as_ref())
        );
    }
    Ok(())
}

#[test]
fn samples_agree_with_the_verdict_rule() -> TestResult {
    for heading in ["7.2 ", "7.3 "] {
        let report: Report = serde_json::from_value(sample(heading)?)?;
        let judgement = verdict(&report.checks);
        assert_eq!(judgement.verdict, report.verdict, "{heading}");
        assert_eq!(judgement.reason, report.verdict_reason, "{heading}");
        assert_eq!(judgement.exit_code(), report.exit_code, "{heading}");
        assert_eq!(
            rdy_spec::result::Summary::from_checks(&report.checks),
            report.summary,
            "{heading}"
        );
        for c in &report.checks {
            assert_eq!(
                c.bucket,
                classify(&c.severity, &c.status, c.skip_kind.as_ref()),
                "{heading} {}",
                c.key
            );
        }
    }
    let not_ready: Report = serde_json::from_value(sample("7.2 ")?)?;
    assert_eq!(not_ready.verdict, Verdict::NotReady);
    assert_eq!(not_ready.verdict_reason, None);
    assert_eq!(not_ready.exit_code, 2);
    let ready: Report = serde_json::from_value(sample("7.3 ")?)?;
    assert_eq!(ready.verdict, Verdict::Ready);
    assert_eq!(ready.exit_code, 0);
    Ok(())
}

#[test]
fn summary_identities_hold_in_the_samples() -> TestResult {
    for heading in ["7.2 ", "7.3 "] {
        let r: Report = serde_json::from_value(sample(heading)?)?;
        let s = &r.summary;
        assert_eq!(
            s.pass + s.warn + s.block + s.skipped + s.timeout + s.error,
            s.total
        );
        let count = |b: Bucket| {
            u32::try_from(r.checks.iter().filter(|c| c.bucket == b).count()).unwrap_or(u32::MAX)
        };
        assert_eq!(count(Bucket::Blocker), s.block);
        assert_eq!(count(Bucket::RequiredNotRun), s.required_not_run);
        assert_eq!(count(Bucket::NotApplicable), s.not_applicable);
        assert_eq!(count(Bucket::Passed), s.pass);
    }
    Ok(())
}

#[test]
fn a_newer_producer_still_reads() -> TestResult {
    let mut doc = sample("7.2 ")?;
    // A field this version does not know, an unknown status and an unknown bucket.
    doc["added_in_a_later_release"] = serde_json::json!({"anything": [1, 2, 3]});
    doc["checks"][0]["status"] = Value::String("quarantined".into());
    doc["checks"][0]["bucket"] = Value::String("frozen".into());
    doc["checks"][0]["severity"] = Value::String("critical".into());

    let report: Report = serde_json::from_value(doc.clone())?;
    let first = &report.checks[0];
    assert_eq!(first.status, Status::Unknown("quarantined".into()));
    assert_eq!(first.bucket, Bucket::Unknown("frozen".into()));
    assert_eq!(first.severity, Severity::Unknown("critical".into()));
    assert!(first.status.is_unknown() && first.bucket.is_unknown());

    // The open values go back out as they came in, and the document stays valid.
    let written = serde_json::to_value(&report)?;
    assert_eq!(written["checks"][0]["status"], "quarantined");
    assert_eq!(written["checks"][0]["bucket"], "frozen");
    assert!(written.get("added_in_a_later_release").is_none());
    assert_valid(&validator(None)?, &written, "the re-written report");

    // Recomputing from an unknown status and an unknown severity: not run, and required.
    assert_eq!(
        classify(&first.severity, &first.status, first.skip_kind.as_ref()),
        Bucket::RequiredNotRun
    );
    assert_eq!(verdict(&report.checks).verdict, Verdict::NotReady);
    Ok(())
}

#[test]
fn closed_and_constant_fields_are_enforced() -> TestResult {
    let base = sample("7.3 ")?;

    let mut v2 = base.clone();
    v2["api_version"] = Value::String("rdy/v2".into());
    assert!(serde_json::from_value::<Report>(v2).is_err());

    let mut kind = base.clone();
    kind["kind"] = Value::String("Verification".into());
    assert!(serde_json::from_value::<Report>(kind).is_err());

    let mut closed = base.clone();
    closed["verdict"] = Value::String("mostly_ready".into());
    assert!(serde_json::from_value::<Report>(closed).is_err());

    let mut missing = base;
    missing.as_object_mut().ok_or("object")?.remove("checks");
    assert!(serde_json::from_value::<Report>(missing).is_err());
    Ok(())
}

fn blocked(id: &str) -> CheckResult {
    let mut c = CheckResult::new(id, "host", Severity::Block, Status::Block);
    c.message = "15.4 GiB found, 32 GiB needed".into();
    c.fix = Some("Add RAM.".into());
    c.fix_source = Some(rdy_spec::result::FixSource::FromSpec);
    c
}

fn passed(id: &str) -> CheckResult {
    CheckResult::new(id, "host", Severity::Block, Status::Pass)
}

fn skipped(id: &str, sev: Severity, kind: SkipKind) -> CheckResult {
    let mut c = CheckResult::skipped(id, "gpu", sev, kind);
    c.message = "Not run.".into();
    if !matches!(c.skip_kind, Some(SkipKind::NotApplicable)) {
        c.fix = Some("Install a newer rdy.".into());
        c.fix_source = Some(rdy_spec::result::FixSource::Rdy);
    }
    c
}

/// `Report::new` computes a consistent verdict, and the schema's own consistency rules accept it.
#[test]
fn built_reports_satisfy_the_schema_rules() -> TestResult {
    let template: Report = serde_json::from_value(sample("7.2 ")?)?;
    let v = validator(None)?;

    let runs: Vec<(Vec<CheckResult>, Verdict, Option<VerdictReason>, u8)> = vec![
        (
            vec![passed("host.cpu"), passed("host.memory")],
            Verdict::Ready,
            None,
            0,
        ),
        (
            vec![passed("host.cpu"), blocked("host.memory")],
            Verdict::NotReady,
            None,
            2,
        ),
        (
            vec![
                passed("host.cpu"),
                skipped("gpu.cuda", Severity::Block, SkipKind::NotInBuild),
            ],
            Verdict::NotReady,
            Some(VerdictReason::RequiredCheckNotRun),
            2,
        ),
        (
            vec![
                passed("host.cpu"),
                skipped("gpu.cuda", Severity::Warn, SkipKind::NotInBuild),
            ],
            Verdict::ReadyWithWarnings,
            None,
            1,
        ),
        (
            vec![skipped(
                "host.disk",
                Severity::Warn,
                SkipKind::NotApplicable,
            )],
            Verdict::ReadyWithWarnings,
            Some(VerdictReason::NothingVerified),
            1,
        ),
        (
            Vec::new(),
            Verdict::ReadyWithWarnings,
            Some(VerdictReason::NothingVerified),
            1,
        ),
    ];
    for (checks, want_verdict, want_reason, want_exit) in runs {
        let mut report = template.clone();
        report.checks = checks;
        report.refresh_verdict();
        assert_eq!(report.verdict, want_verdict);
        assert_eq!(report.verdict_reason, want_reason);
        assert_eq!(report.exit_code, want_exit);
        let written = serde_json::to_value(&report)?;
        assert_valid(&v, &written, "a built report");
    }
    Ok(())
}

/// The schema is the check on the types: a verdict that disagrees with the exit code is refused.
#[test]
fn the_schema_refuses_a_verdict_exit_code_mismatch() -> TestResult {
    let v = validator(None)?;
    let mut doc = sample("7.2 ")?;
    assert!(is_valid(&v, &doc));
    doc["exit_code"] = Value::from(1);
    assert!(!is_valid(&v, &doc));
    Ok(())
}

#[test]
fn unsigned_signature_state_round_trips() -> TestResult {
    let mut doc = sample("7.2 ")?;
    doc["signature"] = serde_json::json!({"state": "unsigned"});
    doc["run"]["options"]["allow_unsigned"] = Value::Bool(true);
    let report: Report = serde_json::from_value(doc)?;
    assert_eq!(report.signature.state, SignatureState::Unsigned);
    assert_valid(
        &validator(None)?,
        &serde_json::to_value(&report)?,
        "an unsigned report",
    );
    Ok(())
}
