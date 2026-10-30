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

/// The same with a bare block, which no key name introduces: the PEM rule alone takes it (M1-060).
#[test]
fn a_bare_pem_key_across_the_64_kib_cap_is_fully_redacted() {
    let key = pem(8);
    for lead in [100, 10, 1] {
        let pad = "a".repeat(FREE_FORM_CAP - lead - 40);
        let mut result = check("host.cpu");
        result.observed = Some(observed(json!({
            "stderr": format!("{pad}\n{key}\ntail"),
            "log": format!("loaded: {}", key.replace('\n', "\\n")),
        })));
        let mut counts = RuleCounts::default();
        let out = redactor()
            .redact_check(result, &mut counts)
            .expect("redacts");
        let text = serde_json::to_string(&*out).expect("serializes");
        assert!(!text.contains("QUJDREVG"), "key body survived at {lead}");
        assert!(
            !text.contains("BEGIN PRIVATE"),
            "key header survived at {lead}"
        );
        assert!(text.contains("[REDACTED:pem_private_key:"), "{lead}");
        assert_eq!(counts.get("pem_private_key"), 2, "{lead}");
    }
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
    // The raw text is over the 1 KiB cap, but the redacted text is under it. Redact first and nothing is
    // cut: the message holds a placeholder and `truncated` stays false. Cap first and the secret would be
    // chopped (and the flag set), with no placeholder.
    let secret = "S3cr3tValueThatMustNotLeakS3cr3tValueThatMustNotLeakS3cr3tValue";
    let mut result = check("host.cpu");
    result.message = format!("{} password={secret}", "x".repeat(960));
    assert!(result.message.len() > MESSAGE_CAP);
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    assert!(!out.message.contains("S3cr3t"), "{}", out.message);
    assert!(
        out.message.contains("[REDACTED:secret_by_key:"),
        "{}",
        out.message
    );
    assert!(!out.truncated);
    assert!(!out.message.contains(CUT_MARKER));
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
        "password_len": 8,
        "db_password": 12345678,
        "pins": {"api_key": [1, 2]},
        "has_password": true,
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
    assert_eq!(seen["password_len"], 8);
    assert_eq!(seen["has_password"], true);
    // A number under a secret key is a secret too, unless the key's last word is a unit or a count.
    for number in [&seen["db_password"], &seen["pins"]["api_key"][0]] {
        assert!(
            number
                .as_str()
                .is_some_and(|s| s.starts_with("[REDACTED:secret_by_key:")),
            "{number}"
        );
    }
    assert_eq!(seen["ref"], "${DB_PASSWORD}");
    assert_eq!(seen["empty_password"], "");
    assert_eq!(seen["env"][1], json!({"name": "HOME", "value": "/root"}));
    assert_eq!(seen["env"][0]["name"], "DB_PASSWORD");
    assert!(
        seen["env"][0]["value"]
            .as_str()
            .is_some_and(|s| s.starts_with("[REDACTED:secret_by_key:"))
    );
    assert_eq!(counts.get("secret_by_key"), 7);
    // The same password under two keys gets one tag, as in text.
    assert!(
        !serde_json::to_string(&*out)
            .expect("json")
            .contains("hunter2")
    );
    assert!(
        !serde_json::to_string(&*out)
            .expect("json")
            .contains("12345678")
    );
}

#[test]
fn pairs_are_matched_by_name_and_value_in_any_of_the_usual_spellings() {
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "env": [
            {"Name": "DB_PASSWORD", "Value": "hunter2-a"},
            {"key": "api_token", "value": "hunter2-b"},
            {"Key": "API_TOKEN", "Value": "hunter2-c"},
            {"name": "DB_PASSWORD", "value": 987654321},
            {"name": "TOKEN_TTL_MS", "value": 3600},
            {"Name": "HOME", "Value": "/root"},
        ],
    })));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let text = serde_json::to_string(&*out).expect("json");
    for leaked in ["hunter2", "987654321"] {
        assert!(!text.contains(leaked), "{leaked} in {text}");
    }
    let seen = out.observed.as_ref().expect("observed");
    assert_eq!(seen["env"][4]["value"], 3600);
    assert_eq!(seen["env"][5], json!({"Name": "HOME", "Value": "/root"}));
}

#[test]
fn a_command_line_inside_observed_is_read_as_argv() {
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "cmdline": ["/usr/bin/tool", "--password", "hunter2-x", "--user", "ada"],
        "nested": {"args": ["--api-token", "hunter2-y"]},
        "mixed": ["--password", 5],
        "mixed_tail": ["--password", "hunter2-m", 5432],
        "mixed_head": [1, "--api-token", "hunter2-n", {"port": 5432}, "--user", "ada"],
        "mixed_object": ["--token", {"v": "hunter2-o"}, true],
    })));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let text = serde_json::to_string(&*out).expect("json");
    assert!(!text.contains("hunter2"), "{text}");
    let seen = out.observed.as_ref().expect("observed");
    assert_eq!(seen["cmdline"][0], "/usr/bin/tool");
    assert_eq!(seen["cmdline"][3], "--user");
    assert_eq!(seen["cmdline"][4], "ada");
    // A list with a number in it is still a command line: the flag takes the next item whole.
    let hidden = |v: &Value| v.as_str().is_some_and(|s| s.starts_with("[REDACTED:"));
    assert_eq!(seen["mixed"][0], "--password");
    assert!(hidden(&seen["mixed"][1]), "{}", seen["mixed"][1]);
    assert!(hidden(&seen["mixed_tail"][1]));
    assert_eq!(seen["mixed_tail"][2], 5432);
    assert_eq!(seen["mixed_head"][0], 1);
    assert!(hidden(&seen["mixed_head"][2]));
    assert_eq!(seen["mixed_head"][3], json!({"port": 5432}));
    assert_eq!(seen["mixed_head"][5], "ada");
    assert!(hidden(&seen["mixed_object"][1]["v"]));
    assert_eq!(seen["mixed_object"][2], true);
}

#[test]
fn a_list_or_object_under_a_secret_key_is_replaced_whole_even_with_a_unit_word() {
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "private_key_bytes": [48, 130, 1, 2],
        "secret_bytes": 48130,
        "token_ttl_ms": 3600,
        "token_ttl_seconds": [3600, 7200],
        "password_len": {"min": 8, "max": 12},
        "env": [
            {"name": "PRIVATE_KEY_BYTES", "value": [48, 130, 1, 3]},
            {"name": "TOKEN_TTL_MS", "value": [3600, 7200]},
            {"name": "TOKEN_TTL_MS", "value": 3600},
        ],
    })));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let text = serde_json::to_string(&*out).expect("json");
    for leaked in ["48130", "130", "7200", "\"min\":8"] {
        assert!(!text.contains(leaked), "{leaked} in {text}");
    }
    let seen = out.observed.as_ref().expect("observed");
    // A number directly under a unit key stays, and only that.
    assert_eq!(seen["token_ttl_ms"], 3600);
    assert_eq!(seen["env"][2]["value"], 3600);
    for list in [
        &seen["private_key_bytes"],
        &seen["token_ttl_seconds"],
        &seen["env"][0]["value"],
        &seen["env"][1]["value"],
    ] {
        assert!(
            list.as_array().is_some_and(|a| a
                .iter()
                .all(|v| v.as_str().is_some_and(|s| s.starts_with("[REDACTED:")))),
            "{list}"
        );
    }
    assert!(seen["secret_bytes"].is_string(), "{}", seen["secret_bytes"]);
    assert!(seen["password_len"]["min"].is_string());
    assert!(seen["password_len"]["max"].is_string());
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
fn an_action_argv_with_a_number_after_a_secret_flag_loses_it() {
    let mut action = Action::new(
        1,
        None,
        1,
        1,
        ActionKind::Unknown("exec".to_owned()),
        ActionOutcome::Unknown("ok".to_owned()),
    );
    action.fields.insert(
        "argv".to_owned(),
        json!(["tool", "--password", 987_654_321, "--port", 5432]),
    );
    let out = redactor()
        .redact_action(action, &mut RuleCounts::default())
        .expect("redacts");
    let text = serde_json::to_string(&*out).expect("json");
    assert!(!text.contains("987654321"), "{text}");
    assert_eq!(out.fields["argv"][4], 5432);
}

#[test]
fn a_real_key_collision_keeps_both_values_and_the_suffixed_key_fits() {
    // Two keys of 5001 bytes share their first 5000. Both are cut to the same 4 KiB text, so they collide.
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        format!("{}a", "k".repeat(5000)): 1,
        format!("{}b", "k".repeat(5000)): 2,
        "other": 3,
    })));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let seen = out.observed.as_ref().expect("observed");
    assert_eq!(seen.len(), 3);
    let cut_key = format!("{}{CUT_MARKER}", "k".repeat(STRING_CAP - CUT_MARKER.len()));
    assert_eq!(cut_key.len(), STRING_CAP);
    assert_eq!(seen.get(&cut_key), Some(&json!(1)));
    let suffixed: Vec<_> = seen.keys().filter(|k| k.ends_with("~2")).collect();
    assert_eq!(suffixed.len(), 1, "{:?}", seen.keys().map(String::len));
    assert_eq!(seen[suffixed[0]], 2);
    assert!(suffixed[0].len() <= STRING_CAP);
    assert_eq!(seen["other"], 3);
    assert!(out.truncated);
}

#[test]
fn a_redacted_key_never_takes_the_name_of_a_key_that_did_not_change() {
    let mut walk_counts = RuleCounts::default();
    let r = redactor();
    let mut walk = Walk::new(&r, &mut walk_counts);
    let mut map = Map::new();
    map.insert("password=hunter2".to_owned(), json!(1));
    let placeholder: String = (*r.redact_str("password=hunter2")).clone();
    map.insert(placeholder.clone(), json!(2));
    walk.rekey(&mut map);
    assert_eq!(map.len(), 2);
    assert_eq!(map[&placeholder], 2);
    assert_eq!(map[&format!("{placeholder}~2")], 1);
}

#[test]
fn rekey_keeps_the_other_keys_and_their_values() {
    let mut walk_counts = RuleCounts::default();
    let r = redactor();
    let mut walk = Walk::new(&r, &mut walk_counts);
    let mut map = Map::new();
    for (k, v) in [("a", 1), ("password=hunter2", 2), ("c", 3)] {
        map.insert(k.to_owned(), json!(v));
    }
    walk.rekey(&mut map);
    assert_eq!(map["a"], 1);
    assert_eq!(map["c"], 3);
    assert_eq!(map.len(), 3);
    assert!(!map.keys().any(|k| k.contains("hunter2")));
}

#[test]
fn the_keys_of_an_action_are_redacted() {
    let mut action = Action::new(
        1,
        None,
        1,
        1,
        ActionKind::Unknown("exec".to_owned()),
        ActionOutcome::Unknown("ok".to_owned()),
    );
    action
        .fields
        .insert("env password=hunter2".to_owned(), json!("x"));
    let out = redactor()
        .redact_action(action, &mut RuleCounts::default())
        .expect("redacts");
    let text = serde_json::to_string(&*out).expect("json");
    assert!(!text.contains("hunter2"), "{text}");
}

#[test]
fn a_cut_in_name_partial_or_unsupported_fields_sets_truncated() {
    let long = format!("a {}", "n".repeat(5000));
    let mut named = check("host.cpu");
    named.name = Some(long.clone());
    let mut partial = check("host.cpu");
    partial.partial = Some(rdy_spec::result::Partial::new(Vec::new(), long.clone()));
    let mut unsupported = check("host.cpu");
    unsupported.unsupported_fields = Some(vec![long]);
    for result in [named, partial, unsupported] {
        let out = redactor()
            .redact_check(result, &mut RuleCounts::default())
            .expect("redacts");
        assert!(out.truncated);
        let text = serde_json::to_string(&*out).expect("json");
        assert!(text.contains(CUT_MARKER));
    }
}

/// A secret that sits across a cap is redacted first and the cut then lands after `password=`, inside
/// the placeholder or just behind it. A second pass must change nothing and count nothing, in the bare
/// form and in every quoted form the key rule reads.
#[test]
fn a_second_pass_changes_nothing_when_a_cut_lands_after_the_key() {
    let secret = "S3cr3tValueThatMustNotLeak";
    // `{secret}` is where the value goes. Every form is followed by text, so the cap can cut inside it.
    let forms = [
        "password={secret} tail",
        "password=\"{secret}\" tail",
        "password='{secret}' tail",
        "\\\"password\\\":\\\"{secret}\\\" tail",
        "\"password\":\"{secret}\", \"user\":\"ada\"",
        "password: {secret}\nnext: ok",
        "password: \"{secret}\"\nnext: ok",
        // References are left alone by the key rule, so a cut inside one must not leave a stub.
        "password=${DB_PASSWORD}\nnext: ok",
        "password=/run/secrets/db\nnext: ok",
        "password=\"${DB_PASSWORD}\"\nnext: ok",
        "password: null\nnext: ok",
    ];
    let mut cut_after_key = false;
    for form in forms {
        let tail = form.replace("{secret}", secret);
        for offset in 1..=90 {
            // The text starts `offset` bytes before the cap, so the cut walks across the key, its quote
            // and the placeholder.
            let mut result = check("host.cpu");
            result.message = format!("{}{tail}", "x".repeat(MESSAGE_CAP - offset));
            let mut counts = RuleCounts::default();
            let first = redactor()
                .redact_check(result, &mut counts)
                .expect("redacts");
            assert!(!first.message.contains("S3cr3t"), "{form} {offset}");
            cut_after_key |= first.message.ends_with("password= [truncated]");

            let mut r = report(vec![(*first).clone()]);
            r.refresh_verdict();
            let before = counts.clone();
            let second = redactor()
                .redact_report_counted(r, counts)
                .expect("redacts");
            assert_eq!(second.checks[0], *first, "{form} offset {offset} changed");
            assert_eq!(
                second.redaction.total,
                before.total(),
                "{form} offset {offset}"
            );
            assert_eq!(
                second
                    .redaction
                    .by_rule
                    .get("secret_by_key")
                    .copied()
                    .unwrap_or(0),
                before.get("secret_by_key"),
                "{form} offset {offset}"
            );
        }
    }
    assert!(cut_after_key, "no offset cut right after the key");
}

/// The same with the cut made by the 64 KiB cap, where `shorten` does the cutting, in a text, under a
/// secret key and in a pair.
#[test]
fn a_second_pass_changes_nothing_after_the_free_form_cap() {
    let secret = "S3cr3tValueThatMustNotLeak";
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "log": format!("{}password=\"{secret}\" tail", "x".repeat(FREE_FORM_CAP - 20)),
        "password": format!("{secret} {}", "y".repeat(FREE_FORM_CAP)),
        "env": [{"name": "DB_PASSWORD", "value": format!("{secret}{}", "z".repeat(FREE_FORM_CAP))}],
    })));
    let mut counts = RuleCounts::default();
    let first = redactor()
        .redact_check(result, &mut counts)
        .expect("redacts");
    assert!(first.truncated);
    let text = serde_json::to_string(&*first).expect("json");
    assert!(!text.contains("S3cr3t"));
    let before = counts.clone();
    let again = redactor()
        .redact_check((*first).clone(), &mut counts)
        .expect("redacts");
    assert_eq!(*again, *first);
    assert_eq!(counts, before);
}

/// A value that is only the cut marker, or a placeholder and the marker, is not a secret. Anything else
/// before the marker is, and keeps the marker after its placeholder.
#[test]
fn a_cut_marker_under_a_secret_key_is_set_aside_and_never_exempts_text() {
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "password": CUT_MARKER,
        "token": format!("[REDACTED:secret_by_key:1a2b3c4d]{CUT_MARKER}"),
        "api_key": format!("hunter2{CUT_MARKER}"),
        "secret": "[truncated]",
    })));
    let mut counts = RuleCounts::default();
    let out = redactor()
        .redact_check(result, &mut counts)
        .expect("redacts");
    let seen = out.observed.as_ref().expect("observed");
    assert_eq!(seen["password"], CUT_MARKER);
    assert_eq!(
        seen["token"],
        format!("[REDACTED:secret_by_key:1a2b3c4d]{CUT_MARKER}")
    );
    let key = seen["api_key"].as_str().expect("string");
    assert!(
        key.starts_with("[REDACTED:secret_by_key:") && key.ends_with(&format!("]{CUT_MARKER}")),
        "{key}"
    );
    // The bare word without the leading space is just a value.
    assert!(
        seen["secret"]
            .as_str()
            .is_some_and(|s| s.starts_with("[REDACTED:"))
    );
    assert_eq!(counts.get("secret_by_key"), 2);
}

/// The marker is not an exemption for the next line: `password: [truncated]` is an open value like any
/// other, so the key rule still takes the lines below it.
#[test]
fn text_after_a_marker_like_value_is_still_redacted() {
    let mut result = check("host.cpu");
    result.observed = Some(observed(json!({
        "log": "password: [truncated]\nhunter2-log\nnext: ok",
    })));
    let out = redactor()
        .redact_check(result, &mut RuleCounts::default())
        .expect("redacts");
    let text = serde_json::to_string(&*out).expect("json");
    assert!(!text.contains("hunter2-log"), "{text}");
    assert!(text.contains("next: ok"), "{text}");
}

#[test]
fn an_escaped_json_value_becomes_one_bare_placeholder_and_stays_that_way() {
    let raw = r#"{\"password\":\"S3cr3t\"}"#;
    let first = redactor().redact_str(raw).0;
    assert!(!first.contains("S3cr3t"), "{first}");
    assert!(
        first.starts_with(r#"{\"password\":[REDACTED:secret_by_key:"#),
        "{first}"
    );
    assert_eq!(redactor().redact_str(&first).0, first);
}

#[test]
fn a_cut_inside_an_exempt_value_backs_up_to_where_the_value_starts() {
    for value in ["${DB_PASSWORD}", "/run/secrets/db", "null"] {
        for quote in ["", "\""] {
            let text = format!(
                "{}password={quote}{value}{quote}\nnext: ok and some more text",
                "x".repeat(40)
            );
            let start = 40 + "password=".len() + quote.len();
            for at in start + 1..start + value.len() {
                let cut = cut_str(&text, at + CUT_MARKER.len()).expect("cut");
                let want = format!("{}password={CUT_MARKER}", "x".repeat(40));
                assert_eq!(cut, want, "{value} {quote} at {at}");
            }
        }
    }
    // A value that is not exempt is cut where it falls.
    let text = format!(
        "{}password=hunter2-hunter2\nnext: ok and some more text",
        "x".repeat(40)
    );
    let cut = cut_str(&text, 40 + 9 + 4 + CUT_MARKER.len()).expect("cut");
    assert!(cut.ends_with("password=hunt [truncated]"), "{cut}");
}

#[test]
fn a_cut_backs_over_the_quote_that_opens_a_placeholder() {
    let ph = "[REDACTED:secret_by_key:1a2b3c4d]";
    let text = format!("{}password=\"{ph}\" tail", "x".repeat(40));
    // Cut at the quote, at the start of the placeholder and inside it.
    for max in [40 + 9 + 1, 40 + 10 + 1, 40 + 15] {
        let cut = cut_str(&text, max + CUT_MARKER.len()).expect("cut");
        assert!(cut.ends_with("password= [truncated]"), "{max}: {cut}");
    }
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
