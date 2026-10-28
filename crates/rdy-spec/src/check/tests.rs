use serde::Deserialize;
use serde_json::json;

use super::*;
use crate::Quantity;
use crate::spec::Metadata;

fn entry(value: &Value) -> CheckSpec {
    serde_json::from_value(value.clone()).expect("an entry with an id always reads")
}

fn reason(params: &CheckParams) -> &UnsupportedReason {
    match params {
        CheckParams::Unsupported { reason, .. } => reason,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

// ---- the three outcomes ----------------------------------------------------------------------

/// The ticket's exit test, first part: an id this build does not have is `Unknown`.
#[test]
fn an_id_this_build_does_not_have_is_unknown() {
    let c = entry(&json!({"id": "gpu.cuda", "min": "12.4", "severity": "warn"}));
    let CheckParams::Unknown { id, fields } = c.decode_params() else {
        panic!("gpu.cuda must be Unknown");
    };
    assert_eq!(id, "gpu.cuda");
    assert_eq!(fields["min"], "12.4");
    assert!(!fields.contains_key("severity"), "common fields stay out");
}

/// The ticket's exit test, second part: an unknown field in a known check is `Unsupported`, by name.
#[test]
fn an_unknown_field_in_a_known_check_is_unsupported_and_named() {
    let c = entry(&json!({"id": "host.memory", "mn": "32Gi"}));
    let params = c.decode_params();
    assert_eq!(
        reason(&params),
        &UnsupportedReason::UnknownField { field: "mn".into() }
    );
    assert_eq!(params.id(), "host.memory");
    assert_eq!(reason(&params).to_string(), "cannot read 'mn'");
    let CheckParams::Unsupported { fields, .. } = params else {
        panic!("not Unsupported");
    };
    assert_eq!(fields["mn"], "32Gi", "the fields are kept as written");
}

#[test]
fn a_known_id_with_its_parameters_decodes_to_its_typed_variant() {
    let c = entry(&json!({"id": "host.cpu", "min": 4}));
    let CheckParams::HostCpu(cpu) = c.decode_params() else {
        panic!("host.cpu must decode to HostCpu");
    };
    assert_eq!(cpu.min.map(Cores::get), Some(4));
}

/// The smallest parameters that make the entry of `id` read. A new parameter struct with a required key
/// adds its line here.
fn minimal(id: &str) -> Value {
    match id {
        "host.cpu" => json!({"id": id, "min": 1}),
        "host.memory" => json!({"id": id, "min": "1Gi"}),
        "host.disk" => json!({"id": id, "path": "/", "min": "1Gi"}),
        "host.ports" => json!({"id": id, "free": [80]}),
        _ => json!({"id": id}),
    }
}

#[test]
fn all_seventeen_m1_ids_are_known_and_decode_to_their_own_variant() {
    assert_eq!(KNOWN_IDS.len(), 17);
    let mut seen = HashSet::new();
    for id in KNOWN_IDS {
        assert!(seen.insert(*id), "{id} is listed twice");
        let params = entry(&minimal(id)).decode_params();
        assert!(
            !matches!(
                params,
                CheckParams::Unknown { .. } | CheckParams::Unsupported { .. }
            ),
            "{id}: {params:?}"
        );
        assert_eq!(params.id(), *id);
    }
    for id in [
        "host.cpu",
        "host.memory",
        "host.disk",
        "host.ports",
        "host.lsm",
        "host.security_agents",
        "host.os",
        "net.egress",
        "net.proxy",
        "net.tls_intercept",
        "net.dns",
        "k8s.access",
        "k8s.storageclass",
        "k8s.rbac",
        "k8s.admission",
        "k8s.nodes",
        "k8s.version",
    ] {
        assert!(KNOWN_IDS.contains(&id), "{id}");
    }
}

#[test]
fn ids_of_reserved_but_unbuilt_checks_and_typos_are_unknown() {
    for id in ["host.kernel", "aws.iam", "host.memroy", "upload.now"] {
        let params = entry(&json!({ "id": id })).decode_params();
        assert!(matches!(params, CheckParams::Unknown { .. }), "{id}");
        assert_eq!(params.id(), id);
    }
}

#[test]
fn an_id_that_is_not_family_dot_name_is_unknown_and_never_an_error() {
    for id in [
        "memroy",
        "Host.Memory",
        "host.",
        "",
        "host.memory ",
        "a.b.c",
    ] {
        let params = entry(&json!({ "id": id, "min": 1 })).decode_params();
        let CheckParams::Unknown { id: kept, fields } = params else {
            panic!("{id:?} must be Unknown");
        };
        assert_eq!(kept, id, "the id is kept as written");
        assert_eq!(fields["min"], 1);
    }
}

// ---- common fields ---------------------------------------------------------------------------

#[test]
fn a_bad_common_field_makes_a_known_check_unsupported() {
    let cases = [
        (json!({"id": "host.cpu", "name": "Data"}), "name"),
        (json!({"id": "host.cpu", "severity": "blok"}), "severity"),
        (json!({"id": "host.cpu", "severity": "info"}), "severity"),
        (json!({"id": "host.cpu", "fix": ""}), "fix"),
        (json!({"id": "host.cpu", "fix": 7}), "fix"),
        (json!({"id": "host.cpu", "timeout": "90s"}), "timeout"),
        (json!({"id": "host.cpu", "timeout": "500ms"}), "timeout"),
        (json!({"id": "host.cpu", "timeout": 10}), "timeout"),
        (json!({"id": "host.cpu", "os": ["rhel"]}), "os"),
        (json!({"id": "host.cpu", "os": "linux"}), "os"),
    ];
    for (value, field) in cases {
        let c = entry(&value);
        let params = c.decode_params();
        assert_eq!(
            reason(&params),
            &UnsupportedReason::BadCommonField { field },
            "{value}"
        );
        assert_eq!(params.id(), "host.cpu");
    }
}

/// An unreadable severity skips the check, and the verdict still counts it as required.
#[test]
fn an_unreadable_severity_still_counts_as_block() {
    let c = entry(&json!({"id": "host.cpu", "severity": "blok"}));
    assert!(matches!(c.decode_params(), CheckParams::Unsupported { .. }));
    assert_eq!(c.effective_severity(), crate::spec::Severity::Block);
}

#[test]
fn good_common_fields_do_not_disturb_the_parameters() {
    let c = entry(&json!({
        "id": "host.cpu", "name": "main", "severity": "warn", "fix": "Add cores.",
        "timeout": "20s", "os": ["linux"], "min": 2
    }));
    assert!(matches!(c.decode_params(), CheckParams::HostCpu(_)));
}

#[test]
fn an_unknown_id_hides_common_field_problems_because_it_is_not_read() {
    let c = entry(&json!({"id": "gpu.cuda", "severity": "blok", "timeout": "9h"}));
    assert!(matches!(c.decode_params(), CheckParams::Unknown { .. }));
}

#[test]
fn the_common_field_is_named_before_the_parameter_problem() {
    let c = entry(&json!({"id": "host.cpu", "severity": "blok", "mn": 1}));
    assert_eq!(
        reason(&c.decode_params()),
        &UnsupportedReason::BadCommonField { field: "severity" }
    );
}

// ---- values, required fields and unknown fields, with a struct that has fields ----------------

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Demo {
    min: Quantity,
    swap: Option<String>,
}

impl ParamSet for Demo {
    const FIELDS: &'static [&'static str] = &["min", "swap"];
}

fn fields(value: &Value) -> Map<String, Value> {
    value.as_object().expect("an object").clone()
}

#[test]
fn a_struct_with_fields_decodes_good_values() {
    let d = decode::<Demo>(&fields(&json!({"min": "32Gi", "swap": "forbid"}))).expect("decodes");
    assert_eq!(d.min, Quantity::parse("32Gi").expect("size"));
    assert_eq!(d.swap.as_deref(), Some("forbid"));
}

#[test]
fn a_value_that_does_not_fit_is_a_bad_value_that_names_the_field() {
    let r = decode::<Demo>(&fields(&json!({"min": "32G"}))).expect_err("32G is not a size");
    let UnsupportedReason::BadValue { field, message } = &r else {
        panic!("wrong reason {r:?}");
    };
    assert_eq!(field.as_deref(), Some("min"));
    assert!(message.contains("32G"), "{message}");
    assert!(message.contains("not a valid size"), "{message}");
    assert!(r.to_string().starts_with("the value of 'min' does not fit"));
}

#[test]
fn the_culprit_is_the_field_that_fails_and_not_a_good_one() {
    let r = decode::<Demo>(&fields(&json!({"min": "1Gi", "swap": 7}))).expect_err("swap is text");
    let UnsupportedReason::BadValue { field, .. } = &r else {
        panic!("wrong reason {r:?}");
    };
    assert_eq!(field.as_deref(), Some("swap"));
}

#[test]
fn a_missing_required_field_is_named() {
    let r = decode::<Demo>(&fields(&json!({"swap": "forbid"}))).expect_err("min is required");
    assert_eq!(
        r,
        UnsupportedReason::MissingField {
            field: "min".into()
        }
    );
    assert_eq!(r.to_string(), "'min' is required and missing");
    let r = decode::<Demo>(&Map::new()).expect_err("min is required");
    assert_eq!(
        r,
        UnsupportedReason::MissingField {
            field: "min".into()
        }
    );
}

#[test]
fn an_unknown_field_is_named_before_a_bad_value_is_looked_at() {
    let r = decode::<Demo>(&fields(&json!({"mn": "32Gi", "min": "32G"}))).expect_err("mn");
    assert_eq!(r, UnsupportedReason::UnknownField { field: "mn".into() });
}

#[test]
fn the_first_unknown_field_in_key_order_is_the_one_named() {
    let r = decode::<Demo>(&fields(&json!({"zeta": 1, "alpha": 2, "min": "1Gi"}))).expect_err("x");
    assert_eq!(
        r,
        UnsupportedReason::UnknownField {
            field: "alpha".into()
        }
    );
}

#[test]
fn a_field_name_in_the_list_but_not_in_the_struct_is_still_refused_by_serde() {
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Drift {
        #[allow(dead_code)]
        a: Option<u8>,
    }
    impl ParamSet for Drift {
        const FIELDS: &'static [&'static str] = &["a", "b"];
    }
    let r = decode::<Drift>(&fields(&json!({"b": 1}))).expect_err("serde refuses b");
    assert!(matches!(r, UnsupportedReason::BadValue { .. }), "{r:?}");
}

// ---- text safety -----------------------------------------------------------------------------

#[test]
fn names_and_messages_in_a_reason_are_escaped_and_capped() {
    let evil = "\u{1b}[2J\u{1b}]0;pwned\u{7}";
    let mut raw = Map::new();
    raw.insert(evil.to_owned(), json!(1));
    let c = CheckSpec {
        params: raw,
        ..CheckSpec::new("host.cpu")
    };
    let params = c.decode_params();
    let text = reason(&params).to_string();
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(text.contains("\\u{1b}[2J"), "{text}");

    let long = "k".repeat(10_000);
    let mut raw = Map::new();
    raw.insert(long, json!(1));
    let c = CheckSpec {
        params: raw,
        ..CheckSpec::new("host.cpu")
    };
    let params = c.decode_params();
    assert!(reason(&params).to_string().len() < 200);

    let r = decode::<Demo>(&fields(
        &json!({"min": format!("{evil}{}", "x".repeat(5000))}),
    ))
    .expect_err("bad size");
    let text = r.to_string();
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(text.chars().count() < 400, "{} chars", text.chars().count());
}

// ---- entry keys ------------------------------------------------------------------------------

fn spec_of(entries: &[Value]) -> Spec {
    let metadata = Metadata::new(crate::spec::ProductSlug::new("acme").expect("slug"));
    Spec::new(metadata, entries.iter().map(entry).collect())
}

#[test]
fn the_same_id_twice_is_a_duplicate() {
    let spec = spec_of(&[
        json!({"id": "host.cpu"}),
        json!({"id": "host.disk"}),
        json!({"id": "host.disk"}),
    ]);
    let (index, error) = find_duplicate(&spec.checks).expect("a duplicate");
    assert_eq!(index, 2);
    assert_eq!(error.to_string(), "two checks are named host.disk");
    assert_eq!(
        error.hint(),
        "give each one a name, for example 'name: data'. The name is only a label."
    );
    assert_eq!(spec.decode_checks().expect_err("duplicate"), error);
}

#[test]
fn the_same_id_and_name_twice_is_a_duplicate_and_the_name_is_shown() {
    let spec = spec_of(&[
        json!({"id": "host.disk", "name": "data"}),
        json!({"id": "host.disk", "name": "data"}),
    ]);
    let error = spec.decode_checks().expect_err("duplicate");
    assert_eq!(error.to_string(), "two checks are named host.disk (data)");
}

#[test]
fn a_name_tells_two_entries_with_one_id_apart() {
    let spec = spec_of(&[
        json!({"id": "host.disk", "name": "data"}),
        json!({"id": "host.disk", "name": "logs"}),
        json!({"id": "host.disk"}),
        json!({"id": "net.dns"}),
    ]);
    assert!(find_duplicate(&spec.checks).is_none());
    let decoded = spec.decode_checks().expect("no duplicate");
    assert_eq!(decoded.len(), spec.checks.len());
    assert_eq!(decoded[0].id(), "host.disk");
    assert_eq!(decoded[3].id(), "net.dns");
}

#[test]
fn an_entry_with_an_unreadable_name_has_no_key_and_is_not_a_duplicate() {
    let spec = spec_of(&[
        json!({"id": "host.disk", "name": "Data"}),
        json!({"id": "host.disk", "name": "Data"}),
        minimal("host.disk"),
    ]);
    assert!(find_duplicate(&spec.checks).is_none());
    let decoded = spec.decode_checks().expect("no duplicate");
    assert!(matches!(decoded[0], CheckParams::Unsupported { .. }));
    assert!(matches!(decoded[2], CheckParams::HostDisk(_)));
}

#[test]
fn unknown_ids_count_for_duplicates_too() {
    let spec = spec_of(&[json!({"id": "gpu.cuda"}), json!({"id": "gpu.cuda"})]);
    assert!(find_duplicate(&spec.checks).is_some());
}

#[test]
fn a_duplicate_id_is_escaped_in_the_error() {
    let evil = "\u{1b}[2Jx";
    let spec = spec_of(&[json!({"id": evil}), json!({"id": evil})]);
    let error = spec.decode_checks().expect_err("duplicate");
    assert!(!error.to_string().chars().any(char::is_control));
}

#[test]
fn decode_checks_keeps_entry_order_and_reports_each_outcome() {
    let spec = spec_of(&[
        minimal("host.cpu"),
        json!({"id": "gpu.cuda"}),
        json!({"id": "host.memory", "mn": "32Gi"}),
    ]);
    let decoded = spec.decode_checks().expect("decodes");
    assert!(matches!(decoded[0], CheckParams::HostCpu(_)));
    assert!(matches!(decoded[1], CheckParams::Unknown { .. }));
    assert!(matches!(decoded[2], CheckParams::Unsupported { .. }));
}
