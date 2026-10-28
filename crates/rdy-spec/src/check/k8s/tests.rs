use serde_json::{Value, json};

use super::*;
use crate::check::testkit::{Case, assert_printable, fields_match, run_case_checks, typed, why};
use crate::check::{CheckParams, UnsupportedReason};

fn cases() -> Vec<Case> {
    let long_name = "a".repeat(254);
    let items_101: Vec<Value> = (0..101).map(|i| json!(format!("get r{i}"))).collect();
    let apis_65: Vec<Value> = (0..65).map(|i| json!(format!("v1 K{i}"))).collect();
    let labels_17: Value = Value::Object((0..17).map(|i| (format!("k{i}"), json!("v"))).collect());
    let tolerations_17: Vec<Value> = (0..17).map(|i| json!({"key": format!("k{i}")})).collect();
    vec![
        Case {
            id: "k8s.access",
            full: json!({"context_pattern": "^prod-", "server_pattern": "^https://", "max_latency": "3s"}),
            bad: vec![
                ("context_pattern", json!("")),
                ("context_pattern", json!("x".repeat(257))),
                ("context_pattern", json!(5)),
                ("server_pattern", json!("")),
                ("server_pattern", json!(["a"])),
                ("max_latency", json!("0s")),
                ("max_latency", json!("slow")),
            ],
            fields: K8sAccess::FIELDS,
        },
        Case {
            id: "k8s.storageclass",
            full: json!({"class": "fast-ssd", "access_modes": ["ReadWriteOnce", "ReadWriteMany"],
                "binding": "WaitForFirstConsumer", "expansion": true, "reclaim_policy": "Retain"}),
            bad: vec![
                ("class", json!("")),
                ("class", json!("Fast")),
                ("class", json!("-fast")),
                ("class", json!("fast-")),
                ("class", json!("fast_ssd")),
                ("class", json!(long_name.clone())),
                ("class", json!(7)),
                ("access_modes", json!([])),
                ("access_modes", json!("ReadWriteOnce")),
                ("access_modes", json!(["RWO"])),
                ("access_modes", json!(["ReadWriteOnce", "ReadWriteOnce"])),
                ("binding", json!("wait")),
                ("binding", json!("immediate")),
                ("binding", json!(true)),
                ("expansion", json!("yes")),
                ("reclaim_policy", json!("retain")),
                ("reclaim_policy", json!("Recycle")),
            ],
            fields: K8sStorageClass::FIELDS,
        },
        Case {
            id: "k8s.rbac",
            full: json!({"can": ["create namespaces", "get pods/log",
                "create clusterroles.rbac.authorization.k8s.io",
                {"verb": "get", "group": "apps", "resource": "deployments",
                 "subresource": "status", "namespace": "acme", "name": "web"}],
                "namespace": "acme"}),
            bad: vec![
                ("can", json!([])),
                ("can", json!("create namespaces")),
                ("can", Value::Array(items_101)),
                ("can", json!(["create"])),
                ("can", json!(["create namespaces extra"])),
                ("can", json!(["Create namespaces"])),
                ("can", json!(["create Namespaces"])),
                ("can", json!(["create namespaces."])),
                ("can", json!(["get pods/"])),
                ("can", json!(["get pods/Log"])),
                ("can", json!([" create namespaces"])),
                ("can", json!([7])),
                ("can", json!([["create", "namespaces"]])),
                ("can", json!([{"verb": "get"}])),
                ("can", json!([{"resource": "pods"}])),
                (
                    "can",
                    json!([{"verb": "get", "resource": "pods", "as": "bob"}]),
                ),
                ("can", json!([{"verb": "GET", "resource": "pods"}])),
                ("can", json!([{"verb": "get", "resource": "Pods"}])),
                (
                    "can",
                    json!([{"verb": "get", "resource": "pods", "group": "Apps"}]),
                ),
                (
                    "can",
                    json!([{"verb": "get", "resource": "pods", "subresource": "a/b"}]),
                ),
                (
                    "can",
                    json!([{"verb": "get", "resource": "pods", "namespace": "Acme"}]),
                ),
                (
                    "can",
                    json!([{"verb": "get", "resource": "pods", "name": ""}]),
                ),
                ("namespace", json!("Acme")),
                ("namespace", json!("")),
            ],
            fields: K8sRbac::FIELDS,
        },
        Case {
            id: "k8s.admission",
            full: json!({"pod_security": "baseline",
                "uses": ["hostPath", "hostNetwork", "hostPID", "privileged", "runAsRoot"],
                "namespace": "acme", "scc": "restricted-v2"}),
            bad: vec![
                ("pod_security", json!("strict")),
                ("pod_security", json!("Baseline")),
                ("pod_security", json!(1)),
                ("uses", json!("hostPath")),
                ("uses", json!(["hostIPC"])),
                ("uses", json!(["hostpath"])),
                ("uses", json!(["hostPath", "hostPath"])),
                ("namespace", json!("Acme")),
                ("namespace", json!("")),
                ("scc", json!("Restricted V2")),
                ("scc", json!("")),
                ("scc", json!(long_name)),
            ],
            fields: K8sAdmission::FIELDS,
        },
        Case {
            id: "k8s.nodes",
            full: json!({
                "min_ready": 3, "min_zones": 2,
                "per_node": {"cpu": "7", "memory": "28Gi", "ephemeral": "100Gi", "pods": 30},
                "free": {"cpu": 16, "memory": "64Gi", "pods": 100},
                "arch": ["amd64", "aarch64"],
                "selector": {"node-role.kubernetes.io/worker": ""},
                "tolerations": [{"key": "gpu", "operator": "Exists", "effect": "NoSchedule"},
                    {"key": "dedicated", "operator": "Equal", "value": "acme"}]
            }),
            bad: vec![
                ("min_ready", json!(0)),
                ("min_ready", json!(-1)),
                ("min_ready", json!("3")),
                ("min_ready", json!(1.5)),
                ("min_ready", json!(4_294_967_296_u64)),
                ("min_zones", json!(0)),
                ("min_zones", json!("two")),
                ("per_node", json!({})),
                ("per_node", json!("big")),
                ("per_node", json!({"cpu": 0})),
                ("per_node", json!({"cpu": "0"})),
                ("per_node", json!({"cpu": "0m"})),
                ("per_node", json!({"cpu": "4 cores"})),
                ("per_node", json!({"cpu": -1})),
                ("per_node", json!({"cpu": 0.0001})),
                ("per_node", json!({"cpu": 0.0015})),
                ("per_node", json!({"cpu": 1_000_001})),
                ("per_node", json!({"cpu": "1000001"})),
                ("per_node", json!({"cpu": "1000000001m"})),
                ("per_node", json!({"cpu": "99999999999m"})),
                ("per_node", json!({"cpu": true})),
                ("per_node", json!({"memory": "28G"})),
                ("per_node", json!({"ephemeral": "lots"})),
                ("per_node", json!({"pods": 0})),
                ("per_node", json!({"disk": "1Gi"})),
                ("free", json!({})),
                ("free", json!({"memory": 1.5})),
                ("free", json!({"pods": "many"})),
                ("arch", json!([])),
                ("arch", json!(["sparc"])),
                ("arch", json!(["amd64", "amd64"])),
                ("arch", json!("amd64")),
                ("selector", labels_17),
                ("selector", json!({"a": 1})),
                ("selector", json!({"": "x"})),
                ("selector", json!({"-a": "x"})),
                ("selector", json!({"a b": "x"})),
                ("selector", json!({"a\u{202e}b": "x"})),
                ("selector", json!({"a\u{1b}": "x"})),
                ("selector", json!({"A.Example/b": "x"})),
                ("selector", json!({"a/b/c": "x"})),
                ("selector", json!({"k": "-x"})),
                ("selector", json!({"k": "x\u{202e}"})),
                ("selector", json!({"k": "x\n"})),
                ("selector", json!({"k": "x".repeat(64)})),
                ("selector", json!(["a"])),
                ("tolerations", Value::Array(tolerations_17)),
                ("tolerations", json!("gpu")),
                ("tolerations", json!([5])),
                ("tolerations", json!([{"operator": "Maybe"}])),
                ("tolerations", json!([{"effect": "Never"}])),
                ("tolerations", json!([{"key": ""}])),
                ("tolerations", json!([{"key": "a\u{202e}b"}])),
                ("tolerations", json!([{"key": "a b"}])),
                ("tolerations", json!([{"key": "gpu", "value": "\u{1b}[2J"}])),
                ("tolerations", json!([{"operator": "Exists", "value": "x"}])),
                ("tolerations", json!([{"operator": "Equal"}])),
                ("tolerations", json!([{"effect": "NoSchedule"}])),
                ("tolerations", json!([{"value": "x"}])),
                ("tolerations", json!([{}])),
                ("tolerations", json!([{"value": "x".repeat(64)}])),
                ("tolerations", json!([{"tolerationSeconds": 60}])),
            ],
            fields: K8sNodes::FIELDS,
        },
        Case {
            id: "k8s.version",
            full: json!({"min": "1.27", "max": "1.31", "openshift_min": "4.14",
                "apis": ["networking.k8s.io/v1 Ingress", "v1 Pod"], "over_max": "block"}),
            bad: vec![
                ("min", json!("latest")),
                ("min", json!("1.2.3.4.5")),
                ("min", json!(1.3)),
                ("min", json!(-1)),
                ("max", json!("")),
                ("max", json!(true)),
                ("openshift_min", json!("4.x")),
                ("apis", json!([])),
                ("apis", json!("v1 Pod")),
                ("apis", Value::Array(apis_65)),
                ("apis", json!(["Ingress"])),
                ("apis", json!(["networking.k8s.io/v1"])),
                ("apis", json!(["v1 pod"])),
                ("apis", json!(["v1  Pod"])),
                ("apis", json!(["1 Pod"])),
                ("apis", json!(["Networking/v1 Ingress"])),
                ("apis", json!(["/v1 Ingress"])),
                ("apis", json!([format!("{}/v1 Ingress", "a".repeat(320))])),
                ("apis", json!([5])),
                ("over_max", json!("error")),
                ("over_max", json!("Warn")),
                ("over_max", json!(false)),
            ],
            fields: K8sVersion::FIELDS,
        },
    ]
}

// ---- the fixture covers every field, every field has a rejecting case ---------------------------

#[test]
fn each_k8s_id_accepts_its_full_fixture_and_refuses_each_bad_value() {
    run_case_checks(&cases());
}

// ---- FIELDS cannot drift from the struct --------------------------------------------------------

#[test]
fn k8s_access_fields_match_the_struct() {
    fields_match::<K8sAccess>();
}

#[test]
fn k8s_storageclass_fields_match_the_struct() {
    fields_match::<K8sStorageClass>();
}

#[test]
fn k8s_rbac_fields_match_the_struct() {
    fields_match::<K8sRbac>();
}

#[test]
fn k8s_admission_fields_match_the_struct() {
    fields_match::<K8sAdmission>();
}

#[test]
fn k8s_nodes_fields_match_the_struct() {
    fields_match::<K8sNodes>();
}

#[test]
fn k8s_version_fields_match_the_struct() {
    fields_match::<K8sVersion>();
}

// ---- no threshold -------------------------------------------------------------------------------

#[test]
fn a_k8s_check_with_its_required_keys_missing_is_no_threshold() {
    let cases: [(&str, &[&str], Value); 5] = [
        ("k8s.rbac", &["can"], json!({})),
        ("k8s.rbac", &["can"], json!({"namespace": "acme"})),
        (
            "k8s.nodes",
            &["min_ready", "per_node", "free"],
            json!({"min_zones": 2, "arch": ["amd64"], "selector": {"a": "b"}}),
        ),
        (
            "k8s.version",
            &["min", "max", "openshift_min", "apis"],
            json!({}),
        ),
        (
            "k8s.version",
            &["min", "max", "openshift_min", "apis"],
            json!({"over_max": "block"}),
        ),
    ];
    for (id, one_of, params) in cases {
        assert_eq!(
            why(id, &params),
            UnsupportedReason::NoThreshold {
                one_of,
                and: vec![]
            },
            "{id} {params}"
        );
    }
    assert_eq!(
        why("k8s.rbac", &json!({})).to_string(),
        "has no threshold: add 'can'"
    );
    assert_eq!(
        why("k8s.nodes", &json!({})).to_string(),
        "has no threshold: add at least one of 'min_ready', 'per_node', or 'free'"
    );
}

#[test]
fn any_one_threshold_is_enough_for_a_one_of_check() {
    for params in [
        json!({"min_ready": 1}),
        json!({"per_node": {"memory": "1Gi"}}),
        json!({"free": {"pods": 10}}),
    ] {
        typed("k8s.nodes", &params);
    }
    for params in [
        json!({"min": "1.27"}),
        json!({"max": "1.31"}),
        json!({"openshift_min": "4.14"}),
        json!({"apis": ["v1 Pod"]}),
    ] {
        typed("k8s.version", &params);
    }
}

#[test]
fn k8s_checks_with_no_required_key_decode_bare() {
    for id in ["k8s.access", "k8s.storageclass", "k8s.admission"] {
        typed(id, &json!({}));
    }
}

// ---- keys that 01 removed or that are not in M1 -------------------------------------------------

/// 01 section 2.7: the `needs` alias of draft 1 is gone. It must not read as `access_modes`.
#[test]
fn needs_on_a_storage_class_is_an_unknown_field() {
    assert_eq!(
        why("k8s.storageclass", &json!({"needs": ["ReadWriteMany"]})),
        UnsupportedReason::UnknownField {
            field: "needs".into()
        }
    );
}

/// 01 section 2.7: `dry_run` and `probe_pod` come with the ADR 0010 amendment. Until then they are
/// refused by name, so the read-only guard is never asked to allow the call.
#[test]
fn dry_run_and_probe_pod_on_admission_are_unknown_fields() {
    for key in ["dry_run", "probe_pod", "needs_pod_security"] {
        let mut params = json!({"pod_security": "baseline"});
        params[key] = json!(true);
        assert_eq!(
            why("k8s.admission", &params),
            UnsupportedReason::UnknownField { field: key.into() },
            "{key}"
        );
    }
}

/// 01 section 2.7: the key is `over_max`, not `max_severity`.
#[test]
fn max_severity_on_version_is_an_unknown_field() {
    assert_eq!(
        why(
            "k8s.version",
            &json!({"max": "1.31", "max_severity": "block"})
        ),
        UnsupportedReason::UnknownField {
            field: "max_severity".into()
        }
    );
}

// ---- what a good value reads as -----------------------------------------------------------------

#[test]
fn storage_class_defaults_are_applied() {
    let CheckParams::K8sStorageClass(s) = typed("k8s.storageclass", &json!({})) else {
        panic!("not K8sStorageClass");
    };
    assert_eq!(s.binding, VolumeBinding::Any);
    assert!(s.class.is_none() && s.access_modes.is_none() && s.expansion.is_none());
    assert!(s.reclaim_policy.is_none());
}

#[test]
fn version_defaults_and_values_are_read() {
    let CheckParams::K8sVersion(v) = typed("k8s.version", &json!({"min": "1.27", "max": 1})) else {
        panic!("not K8sVersion");
    };
    assert_eq!(v.over_max, OverMax::Warn);
    assert_eq!(v.min.expect("min").components(), [1, 27]);
    assert_eq!(v.max.expect("max").components(), [1]);
}

#[test]
fn an_api_reference_is_split_into_group_version_and_kind() {
    let CheckParams::K8sVersion(v) = typed(
        "k8s.version",
        &json!({"apis": ["networking.k8s.io/v1 Ingress", "v1 Pod", "autoscaling/v2beta2 HorizontalPodAutoscaler"]}),
    ) else {
        panic!("not K8sVersion");
    };
    let apis = v.apis.expect("apis");
    assert_eq!(
        (apis[0].group(), apis[0].version(), apis[0].kind()),
        (Some("networking.k8s.io"), "v1", "Ingress")
    );
    assert_eq!(
        (apis[1].group(), apis[1].version(), apis[1].kind()),
        (None, "v1", "Pod")
    );
    assert_eq!(apis[2].version(), "v2beta2");
}

#[test]
fn a_permission_string_and_the_same_object_read_the_same_way() {
    let CheckParams::K8sRbac(r) = typed(
        "k8s.rbac",
        &json!({"can": [
            "create namespaces",
            {"verb": "create", "resource": "namespaces"},
            "get pods/log",
            {"verb": "get", "resource": "pods", "subresource": "log"},
            "create clusterroles.rbac.authorization.k8s.io",
            {"verb": "create", "group": "rbac.authorization.k8s.io", "resource": "clusterroles"},
            "get deployments.apps/status",
            {"verb": "get", "group": "apps", "resource": "deployments", "subresource": "status"}
        ]}),
    ) else {
        panic!("not K8sRbac");
    };
    for pair in r.can.chunks(2) {
        assert_eq!(pair[0], pair[1]);
    }
    assert_eq!(r.can[0].group.as_str(), "");
    assert_eq!(r.can[4].group.as_str(), "rbac.authorization.k8s.io");
    assert_eq!(
        r.can[2].subresource.as_ref().map(RbacSubresource::as_str),
        Some("log")
    );
}

#[test]
fn cpu_amounts_are_kept_in_millicores() {
    for (written, want) in [
        (json!(4), 4000),
        (json!("4"), 4000),
        (json!("500m"), 500),
        (json!("1m"), 1),
        (json!(0.5), 500),
        (json!(7.9), 7900),
        (json!(0.001), 1),
        (json!(1_000_000), 1_000_000_000),
        (json!("1000000"), 1_000_000_000),
        (json!("1000000000m"), 1_000_000_000),
        (json!("999999999m"), 999_999_999),
    ] {
        let CheckParams::K8sNodes(n) =
            typed("k8s.nodes", &json!({"per_node": {"cpu": written.clone()}}))
        else {
            panic!("not K8sNodes");
        };
        let cpu = n.per_node.and_then(|p| p.cpu).expect("cpu");
        assert_eq!(cpu.millicores(), want, "{written}");
    }
}

#[test]
fn resources_keep_every_field() {
    let CheckParams::K8sNodes(n) = typed(
        "k8s.nodes",
        &json!({"free": {"cpu": 2, "memory": "4Gi", "ephemeral": "10Gi", "pods": 5}}),
    ) else {
        panic!("not K8sNodes");
    };
    let free = n.free.expect("free");
    assert_eq!(free.pods.map(std::num::NonZeroU32::get), Some(5));
    assert_eq!(free.memory.map(|q| q.bytes()), Some(4 << 30));
    assert_eq!(free.ephemeral.map(|q| q.bytes()), Some(10 << 30));
}

#[test]
fn a_toleration_keeps_its_keys() {
    let CheckParams::K8sNodes(n) = typed(
        "k8s.nodes",
        &json!({"min_ready": 1, "tolerations": [
            {"key": "gpu", "operator": "Exists", "effect": "NoSchedule"},
            {"operator": "Exists"}, {"operator": "Exists", "value": ""}]}),
    ) else {
        panic!("not K8sNodes");
    };
    let tolerations = n.tolerations.expect("tolerations");
    assert_eq!(tolerations[0].operator, Some(TolerationOperator::Exists));
    assert_eq!(tolerations[0].effect, Some(TaintEffect::NoSchedule));
    assert_eq!(
        tolerations[0].key.as_ref().map(LabelKey::as_str),
        Some("gpu")
    );
    assert_eq!(tolerations[1].key, None);
    assert_eq!(tolerations[2].key, None);
}

// ---- nested values and hostile text -------------------------------------------------------------

#[test]
fn a_key_with_no_value_at_any_depth_is_a_bad_value() {
    for (id, params, field) in [
        ("k8s.nodes", json!({"per_node": {"cpu": null}}), "per_node"),
        (
            "k8s.nodes",
            json!({"min_ready": 1, "selector": {"a": null}}),
            "selector",
        ),
        (
            "k8s.nodes",
            json!({"min_ready": 1, "tolerations": [{"key": null}]}),
            "tolerations",
        ),
        (
            "k8s.rbac",
            json!({"can": [{"verb": "get", "resource": "pods", "namespace": null}]}),
            "can",
        ),
        ("k8s.rbac", json!({"can": [null]}), "can"),
        ("k8s.version", json!({"apis": [null]}), "apis"),
    ] {
        let reason = why(id, &params);
        assert!(
            matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == field),
            "{params}: {reason:?}"
        );
    }
}

#[test]
fn refused_text_is_escaped_in_the_reason() {
    for (id, params) in [
        ("k8s.storageclass", json!({"class": "a\u{1b}[2J"})),
        ("k8s.rbac", json!({"can": ["get \u{1b}[2J"]})),
        (
            "k8s.rbac",
            json!({"can": [{"verb": "\u{1b}[2J", "resource": "pods"}]}),
        ),
        ("k8s.nodes", json!({"selector": {"\u{1b}[2J": 1}})),
        (
            "k8s.nodes",
            json!({"min_ready": 1, "per_node": {"cpu": "\u{1b}[2J"}}),
        ),
        ("k8s.version", json!({"apis": ["\u{1b}[2J"]})),
        ("k8s.admission", json!({"scc": "\u{1b}[2J"})),
    ] {
        assert_printable(&why(id, &params));
    }
}
