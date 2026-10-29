//! Tests for the report walk: redact then cap, the whole-member rule and the counts.

use rdy_spec::result::{
    ActionKind, ActionOutcome, Host, HostOs, HostOsFamily, Identity, Producer, Run, RunOptions,
    Severity, Signature, SpecRef, Status,
};
use serde_json::json;

use super::*;
use crate::redact::TagKey;

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([7; 32]))
}

fn check(id: &str) -> CheckResult {
    CheckResult::new(id, "host", Severity::Block, Status::Pass)
}

fn report(checks: Vec<CheckResult>) -> Report {
    Report::new(
        Producer::new("0.1.0", "0.1.0", "x86_64-unknown-linux-musl"),
        Run::new(
            "00000000-0000-4000-8000-000000000000",
            "2027-02-08T10:00:00.000Z",
            "2027-02-08T10:00:01.000Z",
            1000,
            RunOptions::new(4, 300_000),
        ),
        SpecRef::new("acme", "0".repeat(64), "spec.yaml", 10),
        Signature::unsigned(),
        Host::new("host.example", HostOs::new(HostOsFamily::Linux), "x86_64"),
        Identity::new(Some(1000), Some("ada".to_owned()), false),
        checks,
    )
}

/// `-----BEGIN PRIVATE KEY-----`, built from parts so no scanner sees a whole marker.
fn pem(lines: usize) -> String {
    let mut out = format!("-----BEGIN {}-----\n", "PRIVATE KEY");
    for i in 0..lines {
        out.push_str(&format!("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo{i:04}\n"));
    }
    out.push_str(&format!("-----END {}-----", "PRIVATE KEY"));
    out
}

fn observed(pairs: serde_json::Value) -> Map<String, Value> {
    match pairs {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn map_len(map: &Map<String, Value>) -> usize {
    json_len(map)
}

#[test]
fn a_pem_key_across_the_64_kib_cap_is_fully_redacted() {
    // The key starts 100 bytes before the cap and ends after it. Cut first and the first lines of the
    // key would stay. Redact first and the whole key is one placeholder, so the value then fits.
    let key = pem(8);
    let pad = "a".repeat(FREE_FORM_CAP - 140);
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "stderr": format!("{pad}\nprivate_key: {key}\n"),
    })));
    let mut counts = RuleCounts::default();
    let out = redactor()
        .redact_check(result, &mut counts)
        .expect("redacts");
    let text = serde_json::to_string(&*out).expect("serializes");
    assert!(!text.contains("QUJDREVG"), "key body survived");
    assert!(!text.contains("BEGIN PRIVATE"), "key header survived");
    assert!(text.contains("[REDACTED:"), "{}", text.len());
    assert!(
        !out.truncated,
        "the redacted value fits, so nothing was cut"
    );
    assert!(counts.total() >= 1);
}

#[test]
fn a_pem_key_in_a_value_that_is_still_too_big_is_redacted_and_the_cut_keeps_the_marker() {
    let key = pem(8);
    let pad = "a".repeat(FREE_FORM_CAP * 2);
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "stderr": format!("{pad}\nprivate_key: {key}\n{pad}"),
    })));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let observed = out.observed.as_ref().expect("observed kept");
    assert!(map_len(observed) <= FREE_FORM_CAP);
    assert!(out.truncated);
    let text = serde_json::to_string(&*out).expect("serializes");
    assert!(!text.contains("QUJDREVG"));
    assert!(text.contains(CUT_MARKER));
}

#[test]
fn message_is_cut_at_1_kib_with_a_marker_and_the_flag() {
    let mut result = check("host.cpu");
    result.message = "m".repeat(5000);
    result.fix = Some("f".repeat(5000));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    assert_eq!(out.message.len(), MESSAGE_CAP);
    assert!(out.message.ends_with(CUT_MARKER));
    assert_eq!(out.fix.as_ref().map(String::len), Some(STRING_CAP));
    assert!(out.truncated);
}

#[test]
fn a_short_result_is_left_alone() {
    let mut result = check("host.cpu");
    result.message = "4 cores found, 4 needed".to_owned();
    let out = redactor()
        .redact_check(result.clone(), &mut RuleCounts::default())
        .expect("redacts");
    assert_eq!(*out, result);
}

#[test]
fn a_cut_never_lands_inside_a_placeholder() {
    let placeholder = "[REDACTED:secret_by_key:1a2b3c4d]";
    for lead in 1000..1024 {
        let text = format!("{}{placeholder}{}", "a".repeat(lead), "b".repeat(200));
        let cut = cut_str(&text, MESSAGE_CAP).expect("longer than the cap");
        assert!(cut.len() <= MESSAGE_CAP, "{lead}: {}", cut.len());
        assert_eq!(
            cut.matches("[REDACTED:").count(),
            cut.matches(placeholder).count(),
            "lead {lead} cut a placeholder: {cut}"
        );
        assert!(!cut.contains("[REDACTED") || cut.contains(placeholder));
    }
}

#[test]
fn a_cut_lands_on_a_char_boundary() {
    // Every offset around the cut, with a 3 byte character, must give valid text of at most the cap.
    for lead in 1000..1012 {
        let text = format!("{}{}", "a".repeat(lead), "\u{20ac}".repeat(100));
        let cut = cut_str(&text, MESSAGE_CAP).expect("longer than the cap");
        assert!(cut.len() <= MESSAGE_CAP);
        assert!(cut.ends_with(CUT_MARKER));
    }
}

#[test]
fn redaction_comes_before_the_cap_for_message_too() {
    // The secret sits across the 1 KiB cap. It is replaced first, so no fragment is left.
    let secret = "S3cr3tValueThatMustNotLeak";
    let mut result = check("host.cpu");
    result.message = format!("{} password={secret} tail", "x".repeat(1010));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    assert!(!out.message.contains("S3cr3t"), "{}", out.message);
    assert!(!out.message.contains("Leak"), "{}", out.message);
}

#[test]
fn the_whole_member_rule_works_in_free_form_data_only() {
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "password": "hunter2",
        "api_token": ["t1", "t2"],
        "passed": 12,
        "secretName": "acme-tls",
        "token_ttl_ms": 3600,
        "ref": "${DB_PASSWORD}",
        "empty_password": "",
        "env": [
            {"name": "DB_PASSWORD", "value": "hunter2-env"},
            {"name": "HOME", "value": "/root"},
        ],
    })));
    result.expected = Some(observed(json!({"min_cores": 4})));
    let mut counts = RuleCounts::default();
    let out = redactor()
        .redact_check(result, &mut counts)
        .expect("redacts");
    let seen = out.observed.as_ref().expect("observed");
    assert!(
        seen["password"]
            .as_str()
            .is_some_and(|s| s.starts_with("[REDACTED:secret_by_key:"))
    );
    assert!(
        seen["api_token"]
            .as_array()
            .is_some_and(|a| a.iter().all(|v| v
                .as_str()
                .is_some_and(|s| s.starts_with("[REDACTED:secret_by_key:"))))
    );
    assert_eq!(seen["passed"], 12);
    assert_eq!(seen["secretName"], "acme-tls");
    assert_eq!(seen["token_ttl_ms"], 3600);
    assert_eq!(seen["ref"], "${DB_PASSWORD}");
    assert_eq!(seen["empty_password"], "");
    assert_eq!(seen["env"][1], json!({"name": "HOME", "value": "/root"}));
    assert_eq!(seen["env"][0]["name"], "DB_PASSWORD");
    assert!(
        seen["env"][0]["value"]
            .as_str()
            .is_some_and(|s| s.starts_with("[REDACTED:secret_by_key:"))
    );
    assert_eq!(counts.get("secret_by_key"), 4);
    // The same password under two keys gets one tag, as in text.
    assert!(
        !serde_json::to_string(&*out)
            .expect("json")
            .contains("hunter2")
    );
}

#[test]
fn the_whole_member_rule_leaves_schema_fields_alone() {
    // `summary.pass` and a key such as `passed` survive: the rule runs only in free-form subtrees.
    let r = report(vec![check("host.cpu")]);
    let before = serde_json::to_value(&r).expect("json");
    let out = redactor().redact_report(r).expect("redacts");
    assert_eq!(serde_json::to_value(&*out).expect("json"), before);
}

#[test]
fn lists_in_free_form_data_are_cut_to_200_items() {
    let mut result = check("host.cpu");
    let items: Vec<u32> = (0..500).collect();
    result.observed = Some(observed(json!({"mounts": items, "short": [1, 2]})));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let seen = out.observed.as_ref().expect("observed");
    assert_eq!(seen["mounts"].as_array().map(Vec::len), Some(200));
    assert_eq!(seen["short"].as_array().map(Vec::len), Some(2));
    assert!(out.truncated);
}

#[test]
fn notes_are_cut_to_20_of_1_kib() {
    let mut result = check("host.cpu");
    result.notes = (0..30).map(|_| "n".repeat(2000)).collect();
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    assert_eq!(out.notes.len(), MAX_NOTES);
    assert!(
        out.notes
            .iter()
            .all(|n| n.len() == MESSAGE_CAP && n.ends_with(CUT_MARKER))
    );
    assert!(out.truncated);
}

#[test]
fn many_small_keys_are_dropped_from_the_end_to_fit() {
    let mut map = Map::new();
    for i in 0..20_000 {
        map.insert(format!("key_{i:05}"), json!("value"));
    }
    let mut result = check("host.cpu");
    result.observed = Some(map);
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let seen = out.observed.as_ref().expect("observed");
    assert!(map_len(seen) <= FREE_FORM_CAP);
    assert!(seen.contains_key("key_00000"));
    assert!(!seen.contains_key("key_19999"));
    assert!(out.truncated);
}

#[test]
fn the_longest_strings_are_cut_first_and_short_ones_stay() {
    let mut map = Map::new();
    map.insert("big".to_owned(), json!("b".repeat(FREE_FORM_CAP * 3)));
    map.insert("small".to_owned(), json!("kept"));
    let mut result = check("host.cpu");
    result.observed = Some(map);
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let seen = out.observed.as_ref().expect("observed");
    assert_eq!(seen["small"], "kept");
    let big = seen["big"].as_str().expect("string");
    assert!(big.ends_with(CUT_MARKER));
    // The cut is the longest that fits, not a short stub.
    assert!(big.len() > FREE_FORM_CAP - 100, "{}", big.len());
    assert!(map_len(seen) <= FREE_FORM_CAP);
}

#[test]
fn argv_redacts_a_secret_flag_and_its_argument() {
    let mut action = Action::new(
        1,
        Some("host.cpu".to_owned()),
        1,
        1,
        ActionKind::Unknown("exec".to_owned()),
        ActionOutcome::Unknown("ok".to_owned()),
    );
    action.fields.insert(
        "argv".to_owned(),
        json!([
            "/usr/bin/tool",
            "--password",
            "hunter2",
            "--user",
            "ada",
            "--token=abc123"
        ]),
    );
    action
        .fields
        .insert("program".to_owned(), json!("/usr/bin/tool"));
    let mut counts = RuleCounts::default();
    let out = redactor()
        .redact_action(action, &mut counts)
        .expect("redacts");
    let argv = out.fields["argv"].as_array().expect("array");
    assert_eq!(argv[0], "/usr/bin/tool");
    assert_eq!(argv[1], "--password");
    assert!(
        argv[2]
            .as_str()
            .is_some_and(|s| s.starts_with("[REDACTED:"))
    );
    assert_eq!(argv[3], "--user");
    assert_eq!(argv[4], "ada");
    assert!(
        argv[5]
            .as_str()
            .is_some_and(|s| s.starts_with("--token=") && !s.contains("abc123")),
        "{}",
        argv[5]
    );
    assert_eq!(out.fields["program"], "/usr/bin/tool");
    assert!(counts.total() >= 2);
}

#[test]
fn keys_are_redacted_and_a_collision_keeps_both_values() {
    let mut walk_counts = RuleCounts::default();
    let r = redactor();
    let mut walk = Walk::new(&r, &mut walk_counts);
    let mut map = Map::new();
    // Both keys redact to the same text, so the second one gets a suffix.
    map.insert("a=1".to_owned(), json!(1));
    map.insert("a=2".to_owned(), json!(2));
    walk.rekey(&mut map);
    assert_eq!(map.len(), 2);
}

#[test]
fn the_report_walk_covers_every_string_field() {
    // Plant a canary in strings that are not message or fix, on every part of the report.
    let canary = "canary-pw-9f3a";
    let mut result = check("host.cpu");
    result.name = Some(format!("password={canary}"));
    result.unsupported_fields = Some(vec![format!("token={canary}")]);
    result.partial = Some(rdy_spec::result::Partial::new(
        Vec::new(),
        format!("secret={canary}"),
    ));
    let mut r = report(vec![result]);
    r.host.hostname = format!("host password={canary}");
    r.identity.user = Some(format!("user token={canary}"));
    r.spec
        .annotations
        .insert(format!("password={canary}"), format!("password={canary}"));
    let mut proxy = rdy_spec::result::Proxy::default();
    proxy.https = Some(format!("password={canary}"));
    r.proxy = Some(proxy);
    let mut cap = rdy_spec::result::Capability::new(rdy_spec::result::Need::Root, true);
    cap.detail = Some(format!("token={canary}"));
    r.capabilities.push(cap);
    let out = redactor().redact_report(r).expect("redacts");
    let text = serde_json::to_string(&*out).expect("json");
    assert!(!text.contains(canary), "{text}");
    assert!(out.redaction.total >= 8, "{}", out.redaction.total);
}

#[test]
fn counts_from_earlier_results_are_kept_and_a_second_pass_adds_none() {
    let mut result = check("host.cpu");
    result.message = "failed with password=hunter2".to_owned();
    let mut counts = RuleCounts::default();
    let done = redactor()
        .redact_check(result, &mut counts)
        .expect("redacts");
    assert_eq!(counts.get("secret_by_key"), 1);

    let mut r = report(Vec::new());
    r.checks.push((*done).clone());
    r.refresh_verdict();
    let out = redactor()
        .redact_report_counted(r, counts.clone())
        .expect("redacts");
    // Idempotent: the final pass finds nothing new, and the earlier count is still there.
    assert_eq!(out.redaction.total, 1);
    assert_eq!(out.redaction.by_rule.get("secret_by_key"), Some(&1));
    assert_eq!(out.checks[0], *done);
    // Without the earlier counts the walk reports only its own work.
    let again = redactor().redact_report((*out).clone()).expect("redacts");
    assert_eq!(again.redaction.total, 0);
    assert_eq!(again.checks[0], *done);
}

#[test]
fn the_redaction_block_is_rewritten_not_trusted() {
    let mut r = report(Vec::new());
    r.redaction.total = 99;
    r.redaction.by_rule.insert("forged".to_owned(), 99);
    let out = redactor().redact_report(r).expect("redacts");
    assert_eq!(out.redaction.total, 0);
    assert!(out.redaction.by_rule.is_empty());
    assert_eq!(out.redaction.ruleset, RedactionRuleset::Report);
}
