//! Unit tests of the cut-down objects and the fix helpers of `k8s.ingress`.

use serde_json::json;

use super::fix::{is_name, no_default, pending_balancer};
use super::judge::shown;
use super::objects::{
    GatewayClassObject, IngressClassObject, ServiceObject, balancer_of, class_of, gateway_class_of,
};

const MARKER: &str = "ACME-MARKER-LAST-APPLIED";

fn annotated() -> serde_json::Value {
    json!({
        "kubectl.kubernetes.io/last-applied-configuration": format!("{{\"token\":\"{MARKER}\"}}"),
        "acme/other": MARKER,
    })
}

#[test]
fn an_ingress_class_holds_no_annotation_but_the_default_marker() {
    let mut annotations = annotated();
    annotations["ingressclass.kubernetes.io/is-default-class"] = json!("true");
    let object: IngressClassObject = serde_json::from_value(json!({
        "metadata": {
            "name": "nginx",
            "labels": {"acme/label": MARKER},
            "annotations": annotations,
            "managedFields": [{"manager": MARKER}],
        },
        "spec": {"controller": "k8s.io/ingress-nginx", "parameters": {"name": MARKER}},
    }))
    .expect("parses");
    assert!(!format!("{object:?}").contains(MARKER), "{object:?}");
    let class = class_of(object);
    assert_eq!(class.name, "nginx");
    assert_eq!(class.controller, "k8s.io/ingress-nginx");
    assert!(class.default);
}

#[test]
fn only_the_text_true_marks_a_default_class() {
    for (value, expected) in [
        ("true", true),
        ("false", false),
        ("True", false),
        ("", false),
    ] {
        let object: IngressClassObject = serde_json::from_value(json!({
            "metadata": {
                "name": "c",
                "annotations": {"ingressclass.kubernetes.io/is-default-class": value},
            },
            "spec": {"controller": "x.example/y"},
        }))
        .expect("parses");
        assert_eq!(class_of(object).default, expected, "{value}");
    }
}

#[test]
fn an_ingress_class_with_no_spec_or_metadata_parses() {
    let object: IngressClassObject = serde_json::from_value(json!({})).expect("parses");
    let class = class_of(object);
    assert_eq!(class.name, "<unnamed>");
    assert_eq!(class.controller, "");
    assert!(!class.default);
}

#[test]
fn a_gateway_class_holds_its_conditions_type_and_status_only() {
    let object: GatewayClassObject = serde_json::from_value(json!({
        "metadata": {"name": "istio", "annotations": annotated()},
        "spec": {"controllerName": "istio.io/gateway-controller", "description": MARKER},
        "status": {"conditions": [
            {"type": "SupportedVersion", "status": "True", "message": MARKER},
            {"type": "Accepted", "status": "True", "message": MARKER},
        ]},
    }))
    .expect("parses");
    assert!(!format!("{object:?}").contains(MARKER), "{object:?}");
    let class = gateway_class_of(object);
    assert_eq!(class.controller, "istio.io/gateway-controller");
    assert_eq!(class.accepted, Some(true));
}

#[test]
fn the_accepted_condition_is_true_false_or_absent() {
    let class = |conditions: serde_json::Value| {
        let object: GatewayClassObject = serde_json::from_value(json!({
            "metadata": {"name": "eg"},
            "status": {"conditions": conditions},
        }))
        .expect("parses");
        gateway_class_of(object).accepted
    };
    assert_eq!(
        class(json!([{"type": "Accepted", "status": "Unknown"}])),
        Some(false)
    );
    assert_eq!(
        class(json!([{"type": "Accepted", "status": "False"}])),
        Some(false)
    );
    assert_eq!(class(json!([{"type": "Ready", "status": "True"}])), None);
    assert_eq!(class(json!([])), None);
}

#[test]
fn a_service_keeps_its_type_age_and_whether_it_has_an_address() {
    let object: ServiceObject = serde_json::from_value(json!({
        "metadata": {
            "name": "acme-gateway",
            "creationTimestamp": "2026-11-17T11:40:00Z",
            "annotations": annotated(),
        },
        "spec": {
            "type": "LoadBalancer",
            "clusterIP": "10.96.0.9",
            "ports": [{"port": 443}],
            "loadBalancerSourceRanges": [MARKER],
        },
        "status": {"loadBalancer": {"ingress": [{"hostname": MARKER}, {"ip": "203.0.113.20"}]}},
    }))
    .expect("parses");
    let debug = format!("{object:?}");
    assert!(!debug.contains(MARKER), "{debug}");
    assert!(!debug.contains("203.0.113.20"), "{debug}");
    let now: i64 = "2026-11-17T12:00:00Z"
        .parse::<k8s_openapi::jiff::Timestamp>()
        .expect("time")
        .as_second();
    let balancer = balancer_of(object, now).expect("a load balancer");
    assert_eq!(balancer.name, "acme-gateway");
    assert_eq!(balancer.age_secs, Some(1200));
    assert!(balancer.assigned);
}

#[test]
fn only_a_load_balancer_service_is_kept() {
    for kind in ["ClusterIP", "NodePort", "ExternalName"] {
        let object: ServiceObject = serde_json::from_value(json!({
            "metadata": {"name": "s"},
            "spec": {"type": kind},
        }))
        .expect("parses");
        assert!(balancer_of(object, 0).is_none(), "{kind}");
    }
    // A Service with no type is a ClusterIP on the server, so it is no load balancer.
    let object: ServiceObject =
        serde_json::from_value(json!({"metadata": {"name": "s"}})).expect("parses");
    assert!(balancer_of(object, 0).is_none());
}

#[test]
fn an_empty_address_list_is_pending() {
    for status in [
        json!({}),
        json!({"loadBalancer": {}}),
        json!({"loadBalancer": {"ingress": []}}),
    ] {
        let object: ServiceObject = serde_json::from_value(json!({
            "metadata": {"name": "s", "creationTimestamp": "2026-11-17T11:00:00Z"},
            "spec": {"type": "LoadBalancer"},
            "status": status,
        }))
        .expect("parses");
        let balancer = balancer_of(object, 1_794_916_800).expect("a load balancer");
        assert!(!balancer.assigned);
    }
}

#[test]
fn a_creation_time_in_the_future_is_a_negative_age() {
    let object: ServiceObject = serde_json::from_value(json!({
        "metadata": {"name": "s", "creationTimestamp": "2030-01-01T00:00:00Z"},
        "spec": {"type": "LoadBalancer"},
    }))
    .expect("parses");
    let balancer = balancer_of(object, 1_794_916_800).expect("a load balancer");
    assert!(balancer.age_secs.is_some_and(|age| age < 0));
}

#[test]
fn a_name_has_the_shape_of_an_object_name_or_it_is_a_placeholder() {
    for good in ["nginx", "acme-gateway", "a.b-c", "a1"] {
        assert!(is_name(good), "{good}");
    }
    for bad in [
        "", "-a", "a-", "A", "a b", "a`b", "a;b", "a..b", "a\u{1b}b", "a/b", "$(x)",
    ] {
        assert!(!is_name(bad), "{bad:?}");
    }
    assert!(!is_name(&"a".repeat(254)));
    assert!(no_default("a`b").contains("ingressclass <name> ingressclass"));
    assert!(
        pending_balancer("$(x)", "acme-system", 20, false)
            .contains("service <name> -n acme-system")
    );
}

#[test]
fn shown_text_is_short_clean_and_has_no_backtick() {
    assert_eq!(shown("a`b"), "a'b");
    let long = shown(&"x".repeat(100));
    assert_eq!(long.chars().count(), 67);
    assert!(long.ends_with("..."));
    assert!(!shown("a\u{1b}[2Jb").contains('\u{1b}'));
}
