use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;
use crate::check::common::serde_fields_of;
use crate::check::{CheckParams, UnsupportedReason};
use crate::spec::CheckSpec;

/// Decodes an entry written as JSON, the way a spec file reaches `decode_params`.
fn decode_entry(value: &Value) -> CheckParams {
    let spec: CheckSpec =
        serde_json::from_value(value.clone()).expect("an entry with an id always reads");
    spec.decode_params()
}

/// The entry for `id` with `params` merged in.
fn entry(id: &str, params: &Value) -> Value {
    let mut map = params.as_object().expect("params are an object").clone();
    map.insert("id".to_owned(), json!(id));
    Value::Object(map)
}

fn why(id: &str, params: &Value) -> UnsupportedReason {
    match decode_entry(&entry(id, params)) {
        CheckParams::Unsupported { reason, .. } => reason,
        other => panic!("{id} {params}: expected Unsupported, got {other:?}"),
    }
}

fn typed(id: &str, params: &Value) -> CheckParams {
    match decode_entry(&entry(id, params)) {
        CheckParams::Unknown { .. } => panic!("{id} is Unknown"),
        CheckParams::Unsupported { reason, .. } => panic!("{id} {params}: {reason}"),
        other => other,
    }
}

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect()
}

fn names(fields: &[&str]) -> BTreeSet<String> {
    fields.iter().map(|f| (*f).to_owned()).collect()
}

/// One check id with a fixture that sets every field, and one rejected value per field.
struct Case {
    id: &'static str,
    /// Sets every field of the struct.
    full: Value,
    /// A rejected value for each field, as `(field, value)`. A field may have several.
    bad: Vec<(&'static str, Value)>,
    fields: &'static [&'static str],
}

fn cases() -> Vec<Case> {
    let sixty_five_flags = Value::Array(vec![json!("avx2"); 65]);
    let thirty_three_fstypes = Value::Array((0..33).map(|i| json!(format!("fs{i}"))).collect());
    let long = "x".repeat(300);
    let ports_257 = Value::Array((1..=257).map(|p| json!(p)).collect());
    vec![
        Case {
            id: "host.cpu",
            full: json!({"min": 8, "recommended": 16, "arch": ["x86_64", "arm64"],
                "flags": ["avx2", "x86-64-v3"]}),
            bad: vec![
                ("min", json!(0)),
                ("min", json!(4097)),
                ("min", json!(-1)),
                ("min", json!("8")),
                ("min", json!(1.5)),
                ("recommended", json!(0)),
                ("recommended", json!("lots")),
                ("arch", json!(["sparc"])),
                ("arch", json!(["amd64", "amd64"])),
                ("arch", json!("x86_64")),
                ("flags", json!(["AVX2"])),
                ("flags", json!([""])),
                ("arch", json!([])),
                ("flags", json!([])),
                ("flags", sixty_five_flags),
            ],
            fields: HostCpu::FIELDS,
        },
        Case {
            id: "host.memory",
            full: json!({"min": "32Gi", "min_available": "8Gi", "swap": "forbid",
                "tolerance_percent": 2.5, "tolerance_result": "warn"}),
            bad: vec![
                ("min", json!("32G")),
                ("min", json!("32GB")),
                ("min", json!(-1)),
                ("min_available", json!("8 GiB")),
                ("swap", json!("off")),
                ("swap", json!(false)),
                ("tolerance_percent", json!(21)),
                ("tolerance_percent", json!(-0.5)),
                ("tolerance_percent", json!("5")),
                ("tolerance_result", json!("fail")),
            ],
            fields: HostMemory::FIELDS,
        },
        Case {
            id: "host.disk",
            full: json!({"path": "/var/lib", "min": "100Gi", "recommended": "150Gi",
                "min_inodes": 100_000, "forbid_options": ["noexec", "ro"],
                "forbid_fstypes": ["nfs", "cifs"]}),
            bad: vec![
                ("path", json!("var/lib")),
                ("path", json!("")),
                ("path", json!("C:/x")),
                ("path", json!("/a\u{0}b")),
                ("path", json!("/a\nb")),
                ("path", json!("/a\u{85}b")),
                ("path", json!(format!("/{}", "a".repeat(1024)))),
                ("path", json!(7)),
                ("min", json!("100G")),
                ("recommended", json!("lots")),
                ("min_inodes", json!(-1)),
                ("min_inodes", json!("many")),
                ("forbid_options", json!(["exec"])),
                ("forbid_options", json!(["ro", "ro"])),
                ("forbid_fstypes", json!(["NFS"])),
                ("forbid_fstypes", json!([""])),
                ("forbid_fstypes", thirty_three_fstypes),
            ],
            fields: HostDisk::FIELDS,
        },
        Case {
            id: "host.ports",
            full: json!({"free": [80, {"port": 443, "bind": "loopback"}], "udp_free": [53],
                "allow_owner": ["acme-agent"]}),
            bad: vec![
                ("free", json!([0])),
                ("free", json!([65536])),
                ("free", json!(["80"])),
                ("free", json!([{"port": 80, "bind": "all"}])),
                ("free", json!([{"bind": "public"}])),
                ("free", json!([{"port": 80, "extra": 1}])),
                ("free", json!(80)),
                ("free", ports_257),
                ("free", json!([])),
                ("udp_free", json!([])),
                ("udp_free", json!([0])),
                ("udp_free", json!([53, 53])),
                ("allow_owner", json!([""])),
                ("allow_owner", json!([long])),
                ("allow_owner", json!("acme")),
            ],
            fields: HostPorts::FIELDS,
        },
        Case {
            id: "host.lsm",
            full: json!({"selinux": {"allow": ["permissive", "disabled"], "denials_max": 0,
                "denials_window": "24h", "watch": ["container_t"]},
                "apparmor": {"allow": ["enabled"], "require_profiles": ["acme"]}}),
            bad: vec![
                ("selinux", json!({"allow": ["strict"]})),
                ("selinux", json!({"allow": ["enforcing", "enforcing"]})),
                ("selinux", json!({"denials_max": -1})),
                ("selinux", json!({"denials_window": "24"})),
                ("selinux", json!({"denials_window": "0s"})),
                ("selinux", json!({"watch": [""]})),
                ("selinux", json!({"denials_max": 4_294_967_296_u64})),
                ("selinux", json!({"mode": "enforcing"})),
                ("selinux", json!("enforcing")),
                ("apparmor", json!({"allow": ["on"]})),
                ("apparmor", json!({"require_profiles": "acme"})),
                ("apparmor", json!({"profiles": []})),
            ],
            fields: HostLsm::FIELDS,
        },
        Case {
            id: "host.security_agents",
            full: json!({"forbid": ["edr-one"], "allow": ["backup-one"]}),
            bad: vec![
                ("forbid", json!("edr-one")),
                ("forbid", json!([""])),
                ("allow", json!([1])),
            ],
            fields: HostSecurityAgents::FIELDS,
        },
        Case {
            id: "host.os",
            full: json!({"supported": [{"id": "rhel", "versions": ["8", "9"]}, {"id": "ubuntu"}],
                "arch": ["x86_64"], "fips": "require", "windows_min_build": 20348}),
            bad: vec![
                ("supported", json!([{"id": "RHEL"}])),
                ("supported", json!([{"versions": ["8"]}])),
                ("supported", json!([{"id": "rhel", "versions": [8]}])),
                (
                    "supported",
                    json!([{"id": "rhel", "versions": ["x".repeat(33)]}]),
                ),
                ("supported", json!([{"id": "rhel", "like": "fedora"}])),
                ("arch", json!(["z80"])),
                ("fips", json!("yes")),
                ("windows_min_build", json!(-1)),
                ("windows_min_build", json!("2022")),
                ("windows_min_build", json!(4_294_967_296_u64)),
            ],
            fields: HostOs::FIELDS,
        },
    ]
}

// ---- the fixture covers every field and every field has a rejecting case ----------------------

#[test]
fn each_fixture_sets_every_field_and_decodes() {
    for case in cases() {
        assert_eq!(keys(&case.full), names(case.fields), "{}", case.id);
        typed(case.id, &case.full);
    }
}

#[test]
fn each_field_has_a_rejecting_case_and_it_is_refused_with_the_field_named() {
    for case in cases() {
        let covered: BTreeSet<String> = case.bad.iter().map(|(f, _)| (*f).to_owned()).collect();
        assert_eq!(
            covered,
            names(case.fields),
            "{}: a field has no bad case",
            case.id
        );
        for (field, bad) in &case.bad {
            // Start from the full fixture so the other fields are good and a required one is there.
            let mut params = case.full.clone();
            params[*field] = bad.clone();
            let reason = why(case.id, &params);
            match &reason {
                UnsupportedReason::BadValue {
                    field: culprit,
                    message,
                } => {
                    assert_eq!(culprit.as_deref(), Some(*field), "{} {bad}", case.id);
                    assert!(!message.is_empty());
                }
                // A block with a key it does not have is told by the path of that key, which starts
                // with the field.
                UnsupportedReason::UnknownNestedField { path, .. } => {
                    assert!(path.starts_with(*field), "{} {bad}: {path}", case.id);
                }
                other => panic!(
                    "{} {field}={bad}: expected BadValue, got {other:?}",
                    case.id
                ),
            }
            let text = reason.to_string();
            assert!(!text.chars().any(char::is_control), "{text:?}");
            assert!(text.len() < 400, "{} chars", text.len());
        }
    }
}

#[test]
fn a_key_the_check_does_not_have_is_named_for_every_host_id() {
    for case in cases() {
        let mut params = case.full.clone();
        params["mn"] = json!("32Gi");
        assert_eq!(
            why(case.id, &params),
            UnsupportedReason::UnknownField { field: "mn".into() },
            "{}",
            case.id
        );
    }
}

#[test]
fn a_key_with_no_value_is_a_bad_value_and_not_an_absent_key() {
    for case in cases() {
        for field in case.fields {
            let mut params = case.full.clone();
            params[*field] = Value::Null;
            let reason = why(case.id, &params);
            assert!(
                matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == field),
                "{} {field}: {reason:?}",
                case.id
            );
        }
    }
}

// ---- FIELDS cannot drift from the struct ------------------------------------------------------

fn fields_match<P: ParamSet>() {
    let from_list: BTreeSet<String> = P::FIELDS.iter().map(|f| (*f).to_owned()).collect();
    assert_eq!(from_list.len(), P::FIELDS.len(), "FIELDS names a key twice");
    assert_eq!(serde_fields_of::<P>(), from_list);
    for key in P::THRESHOLD {
        assert!(
            P::FIELDS.contains(key),
            "THRESHOLD names '{key}', not a field"
        );
    }
}

#[test]
fn host_cpu_fields_match_the_struct() {
    fields_match::<HostCpu>();
}

#[test]
fn host_memory_fields_match_the_struct() {
    fields_match::<HostMemory>();
}

#[test]
fn host_disk_fields_match_the_struct() {
    fields_match::<HostDisk>();
}

#[test]
fn host_ports_fields_match_the_struct() {
    fields_match::<HostPorts>();
}

#[test]
fn host_lsm_fields_match_the_struct() {
    fields_match::<HostLsm>();
}

#[test]
fn host_security_agents_fields_match_the_struct() {
    fields_match::<HostSecurityAgents>();
}

#[test]
fn host_os_fields_match_the_struct() {
    fields_match::<HostOs>();
}

/// The check that stops the check above from passing for the wrong reason.
#[test]
fn the_drift_check_notices_a_field_missing_from_the_list() {
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Drift {
        #[allow(dead_code)]
        a: Option<u8>,
        #[allow(dead_code)]
        b: Option<u8>,
    }
    impl ParamSet for Drift {
        const FIELDS: &'static [&'static str] = &["a"];
    }
    let from_list: BTreeSet<String> = Drift::FIELDS.iter().map(|f| (*f).to_owned()).collect();
    assert_ne!(serde_fields_of::<Drift>(), from_list);
    assert_eq!(serde_fields_of::<Drift>(), names(&["a", "b"]));
}

// ---- no threshold -----------------------------------------------------------------------------

#[test]
fn a_bare_host_check_that_needs_a_threshold_is_no_threshold() {
    let cases = [
        ("host.cpu", &["min", "arch", "flags"][..]),
        ("host.memory", &["min"]),
        ("host.disk", &["min"]),
        ("host.ports", &["free", "udp_free"]),
    ];
    for (id, one_of) in cases {
        let reason = why(id, &json!({}));
        // Only host.disk has a second required key, and it is named too.
        let and = if id == "host.disk" {
            vec!["path"]
        } else {
            vec![]
        };
        assert_eq!(
            reason,
            UnsupportedReason::NoThreshold { one_of, and },
            "{id}"
        );
    }
}

#[test]
fn only_options_and_no_threshold_is_still_no_threshold() {
    let cases = [
        ("host.cpu", json!({"recommended": 8})),
        (
            "host.memory",
            json!({"min_available": "1Gi", "swap": "forbid"}),
        ),
        ("host.disk", json!({"path": "/", "recommended": "1Gi"})),
        ("host.ports", json!({"allow_owner": ["acme"]})),
    ];
    for (id, params) in cases {
        assert!(
            matches!(why(id, &params), UnsupportedReason::NoThreshold { .. }),
            "{id}"
        );
    }
}

/// Any one of the keys in `one_of` is a threshold on its own.
#[test]
fn any_one_threshold_is_enough_for_a_one_of_check() {
    for params in [
        json!({"min": 2}),
        json!({"arch": ["arm64"]}),
        json!({"flags": ["avx2"]}),
    ] {
        typed("host.cpu", &params);
    }
    for params in [json!({"free": [80]}), json!({"udp_free": [53]})] {
        typed("host.ports", &params);
    }
}

#[test]
fn no_threshold_reads_as_a_fix() {
    assert_eq!(
        why("host.memory", &json!({})).to_string(),
        "has no threshold: add 'min'"
    );
    assert_eq!(
        why("host.cpu", &json!({})).to_string(),
        "has no threshold: add at least one of 'min', 'arch', or 'flags'"
    );
    assert_eq!(
        why("host.disk", &json!({})).to_string(),
        "has no threshold: add 'min' and 'path'"
    );
    // With the path given, only the threshold is asked for.
    assert_eq!(
        why("host.disk", &json!({"path": "/"})).to_string(),
        "has no threshold: add 'min'"
    );
}

#[test]
fn a_bare_host_disk_asks_for_the_threshold_and_a_disk_without_a_path_names_the_path() {
    assert!(matches!(
        why("host.disk", &json!({})),
        UnsupportedReason::NoThreshold { .. }
    ));
    assert_eq!(
        why("host.disk", &json!({"min": "10Gi"})),
        UnsupportedReason::MissingField {
            field: "path".into()
        }
    );
}

#[test]
fn a_bad_value_is_reported_before_a_missing_second_key() {
    let reason = why("host.disk", &json!({"path": "/", "min": "10G"}));
    assert!(
        matches!(reason, UnsupportedReason::BadValue { .. }),
        "{reason:?}"
    );
}

#[test]
fn host_checks_that_need_no_threshold_decode_bare() {
    for id in ["host.lsm", "host.security_agents", "host.os"] {
        typed(id, &json!({}));
    }
}

#[test]
fn a_no_threshold_check_is_still_unsupported_for_the_run() {
    let value = entry("host.memory", &json!({"fix": "Add RAM."}));
    let CheckParams::Unsupported { id, fields, reason } = decode_entry(&value) else {
        panic!("expected Unsupported");
    };
    assert_eq!(id, "host.memory");
    assert!(fields.is_empty());
    assert!(matches!(reason, UnsupportedReason::NoThreshold { .. }));
}

// ---- what a good value reads as ---------------------------------------------------------------

#[test]
fn memory_defaults_are_applied() {
    let CheckParams::HostMemory(m) = typed("host.memory", &json!({"min": "32Gi"})) else {
        panic!("not HostMemory");
    };
    assert_eq!(m.swap, SwapPolicy::Any);
    assert_eq!(m.tolerance_result, ToleranceResult::Pass);
    assert!((m.tolerance_percent.get() - 5.0).abs() < f64::EPSILON);
    assert_eq!(m.min_available, None);
    assert_eq!(m.min, Quantity::parse("32Gi").expect("size"));
}

#[test]
fn a_whole_number_and_zero_are_good_tolerances() {
    for (written, want) in [(json!(0), 0.0), (json!(20), 20.0), (json!(7.5), 7.5)] {
        let CheckParams::HostMemory(m) = typed(
            "host.memory",
            &json!({"min": "1Gi", "tolerance_percent": written}),
        ) else {
            panic!("not HostMemory");
        };
        assert!((m.tolerance_percent.get() - want).abs() < f64::EPSILON);
    }
}

#[test]
fn a_bare_port_and_a_port_object_read_the_same_way() {
    let CheckParams::HostPorts(p) = typed(
        "host.ports",
        &json!({"free": [80, {"port": 81}, {"port": 82, "bind": "loopback"}]}),
    ) else {
        panic!("not HostPorts");
    };
    let free = p.free.expect("free");
    let rules: Vec<(u16, Bind)> = free.iter().map(|r| (r.port.get(), r.bind)).collect();
    assert_eq!(
        rules,
        [(80, Bind::Public), (81, Bind::Public), (82, Bind::Loopback)]
    );
}

#[test]
fn a_port_error_keeps_the_reason_of_the_inner_reader() {
    let reason = why("host.ports", &json!({"free": [70000]}));
    assert!(reason.to_string().contains("1 to 65535"), "{reason}");
}

#[test]
fn disk_reads_a_windows_path_and_keeps_it_as_written() {
    let CheckParams::HostDisk(d) = typed(
        "host.disk",
        &json!({"path": "C:\\Program Files", "min": "20Gi"}),
    ) else {
        panic!("not HostDisk");
    };
    assert_eq!(d.path.as_str(), "C:\\Program Files");
}

#[test]
fn os_fips_defaults_to_any_and_versions_stay_text() {
    let CheckParams::HostOs(o) = typed(
        "host.os",
        &json!({"supported": [{"id": "ubuntu", "versions": ["22.04", "24.04"]}]}),
    ) else {
        panic!("not HostOs");
    };
    assert_eq!(o.fips, FipsPolicy::Any);
    let supported = o.supported.expect("supported");
    assert_eq!(supported[0].id.as_str(), "ubuntu");
    let versions: Vec<&str> = supported[0]
        .versions
        .as_ref()
        .expect("versions")
        .iter()
        .map(OsVersion::as_str)
        .collect();
    assert_eq!(versions, ["22.04", "24.04"]);
}

#[test]
fn lsm_reads_the_window_as_a_duration() {
    let CheckParams::HostLsm(l) = typed(
        "host.lsm",
        &json!({"selinux": {"denials_window": "24h", "denials_max": 3}}),
    ) else {
        panic!("not HostLsm");
    };
    let selinux = l.selinux.expect("selinux");
    assert_eq!(selinux.denials_max, Some(3));
    assert_eq!(
        selinux.denials_window,
        Some("24h".parse::<Duration>().expect("duration"))
    );
    assert!(l.apparmor.is_none());
}

#[test]
fn hostile_text_in_a_host_value_is_escaped_in_the_reason() {
    let evil = "\u{1b}[2J\u{1b}]0;pwned\u{7}";
    let reason = why("host.disk", &json!({"path": evil, "min": "1Gi"}));
    let text = reason.to_string();
    assert!(!text.chars().any(char::is_control), "{text:?}");
    let reason = why("host.cpu", &json!({"flags": [evil]}));
    let text = reason.to_string();
    assert!(!text.chars().any(char::is_control), "{text:?}");
}

/// A key with no value is a bad value at any depth, because reading it as absent would widen a rule:
/// `selinux: {allow:}` would allow every mode.
#[test]
fn a_null_at_any_depth_is_a_bad_value_of_the_outer_key() {
    let cases = [
        ("host.lsm", json!({"selinux": {"allow": null}}), "selinux"),
        (
            "host.lsm",
            json!({"selinux": {"denials_max": null}}),
            "selinux",
        ),
        (
            "host.lsm",
            json!({"apparmor": {"require_profiles": null}}),
            "apparmor",
        ),
        (
            "host.os",
            json!({"supported": [{"id": "rhel", "versions": null}]}),
            "supported",
        ),
        ("host.os", json!({"supported": [null]}), "supported"),
        ("host.ports", json!({"free": [80, null]}), "free"),
        ("host.cpu", json!({"min": 2, "flags": [null]}), "flags"),
    ];
    for (id, params, field) in cases {
        let reason = why(id, &params);
        assert!(
            matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == field),
            "{id} {params}: {reason:?}"
        );
    }
}

#[test]
fn an_empty_list_is_refused_where_it_would_be_the_only_threshold() {
    for (id, params) in [
        ("host.cpu", json!({"flags": []})),
        ("host.cpu", json!({"arch": []})),
        ("host.ports", json!({"free": []})),
        ("host.ports", json!({"udp_free": []})),
    ] {
        let reason = why(id, &params);
        assert!(
            matches!(&reason, UnsupportedReason::BadValue { .. }),
            "{id} {params}: {reason:?}"
        );
        assert!(reason.to_string().contains("at least 1"), "{reason}");
    }
}
