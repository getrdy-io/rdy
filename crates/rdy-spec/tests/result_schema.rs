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

/// The first fenced `json` block inside the section whose `###` heading starts with `heading`, and not
/// beyond the next heading. Line endings are normalized first, so a Windows checkout with CRLF reads
/// the same as a Unix one.
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
    let open = section
        .find("```json\n")
        .ok_or("no json block in section")?
        + "```json\n".len();
    let body = &section[open..];
    let close = body.find("\n```").ok_or("unterminated json block")?;
    Ok(serde_json::from_str(&body[..close])?)
}

/// JSON with object keys kept in file order, which `serde_json::Value` does not do. Strings are kept
/// because `$ref` targets are strings. Other leaves are dropped.
#[derive(Debug)]
enum Ordered {
    Obj(Vec<(String, Ordered)>),
    Arr(Vec<Ordered>),
    Str(String),
    Other,
}

impl Ordered {
    fn get(&self, key: &str) -> Option<&Ordered> {
        match self {
            Self::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, _: bool) -> Result<Ordered, E> {
                Ok(Ordered::Other)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Ordered, E> {
                Ok(Ordered::Other)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Ordered, E> {
                Ok(Ordered::Other)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Ordered, E> {
                Ok(Ordered::Other)
            }
            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Other)
            }
            fn visit_str<E>(self, s: &str) -> Result<Ordered, E> {
                Ok(Ordered::Str(s.to_owned()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Ordered, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = a.next_element()? {
                    items.push(item);
                }
                Ok(Ordered::Arr(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Ordered, A::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = a.next_entry::<String, Ordered>()? {
                    fields.push(entry);
                }
                Ok(Ordered::Obj(fields))
            }
        }
        d.deserialize_any(V)
    }
}

/// Follows a `$ref` to `#/$defs/<Name>`. Returns the node and the definition name, if any.
fn resolve<'a>(node: &'a Ordered, defs: &'a Ordered) -> TestResult<(&'a Ordered, Option<&'a str>)> {
    match node.get("$ref") {
        Some(Ordered::Str(r)) => {
            let name = r.strip_prefix("#/$defs/").ok_or("unexpected $ref form")?;
            Ok((defs.get(name).ok_or("dangling $ref")?, Some(name)))
        }
        _ => Ok((node, None)),
    }
}

/// Checks a written value against the schema node for it: every object key is a schema property and
/// the keys come in the schema's `properties` order. Free-form objects (no `properties`) are skipped.
///
/// An `Action` is checked only up to its common fields. The fields that depend on `kind` are kept in a
/// map until the action log ticket types them, so they come out sorted by name, not in schema order.
fn check_order(out: &Ordered, node: &Ordered, defs: &Ordered, path: &str) -> TestResult {
    let (node, name) = resolve(node, defs)?;
    match out {
        Ordered::Arr(items) => {
            let item_node = node
                .get("items")
                .ok_or_else(|| format!("{path}: no items"))?;
            for item in items {
                check_order(item, item_node, defs, path)?;
            }
        }
        Ordered::Obj(fields) => {
            let Some(Ordered::Obj(props)) = node.get("properties") else {
                return Ok(());
            };
            let keep = if name == Some("Action") {
                6
            } else {
                usize::MAX
            };
            let mut last_rank = None;
            for (key, value) in fields.iter().take(keep) {
                let rank = props
                    .iter()
                    .position(|(k, _)| k == key)
                    .ok_or_else(|| format!("{path}/{key} is not a schema property"))?;
                if last_rank.is_some_and(|prev| rank <= prev) {
                    return Err(format!("{path}/{key} is out of schema order").into());
                }
                last_rank = Some(rank);
                let child = props.get(rank).map(|(_, v)| v).ok_or("rank in range")?;
                check_order(value, child, defs, &format!("{path}/{key}"))?;
            }
        }
        Ordered::Str(_) | Ordered::Other => {}
    }
    Ok(())
}

/// The value with every object's keys in sorted order. `serde_json` keeps keys in the order they were
/// inserted (the schema generator needs that), so the sorting is done here, not by the map.
fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .filter_map(|k| map.get(k).map(|inner| (k.clone(), sorted(inner))))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn canonical(v: &Value) -> TestResult<String> {
    Ok(serde_json::to_string(&sorted(v))?)
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

/// The typed model writes its keys in the schema's `properties` order, so a writer that serializes the
/// model gets schema order for free. This does not test the writer itself (indent, trailing newline,
/// `<` escapes, size caps). That layout is M1-055's job.
#[test]
fn typed_model_writes_keys_in_schema_order() -> TestResult {
    let schema_text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/result.v1.schema.json"),
    )?;
    let schema: Ordered = serde_json::from_str(&schema_text)?;
    let defs = schema.get("$defs").ok_or("no $defs")?;
    let root = defs.get("Report").ok_or("no Report")?;
    for heading in ["7.2 ", "7.3 "] {
        let report: Report = serde_json::from_value(sample(heading)?)?;
        let text = serde_json::to_string(&report)?;
        let written: Ordered = serde_json::from_str(&text)?;
        check_order(&written, root, defs, heading.trim())?;
    }
    // The checker is not vacuous: swapped keys are caught.
    let swapped: Ordered = serde_json::from_str(r#"{"kind":"Report","api_version":"rdy/v1"}"#)?;
    assert!(check_order(&swapped, root, defs, "swapped").is_err());
    let items = sample("7.4 ")?;
    for item in items.as_array().ok_or("array")? {
        let result: CheckResult = serde_json::from_value(item.clone())?;
        let written: Ordered = serde_json::from_str(&serde_json::to_string(&result)?)?;
        check_order(
            &written,
            defs.get("CheckResult").ok_or("no CheckResult")?,
            defs,
            "7.4",
        )?;
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

/// A datagram exchange as `Probe::udp_exchange` logs it (M1-144) satisfies the action schema, and a
/// `proto` other than `udp` does not.
#[test]
fn a_udp_connect_entry_validates_against_the_action_schema() -> TestResult {
    let action = validator(Some("Action"))?;
    let mut entry = serde_json::json!({
        "seq": 1,
        "check": "host.time_sync",
        "at_ms": 12,
        "duration_ms": 3,
        "kind": "connect",
        "outcome": "ok",
        "host": "pool.example",
        "port": 123,
        "proto": "udp",
        "addr": "192.0.2.10",
        "bytes": 48,
        "truncated": false
    });
    assert_valid(&action, &entry, "a udp connect entry");
    entry["proto"] = Value::String("tcp".into());
    assert!(!is_valid(&action, &entry), "only udp is a proto value");
    entry["proto"] = Value::String("x".repeat(16));
    assert!(!is_valid(&action, &entry), "no free text in proto");
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
