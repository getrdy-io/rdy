use serde_json::{Value, json};

use super::*;
use crate::check::testkit::{Case, assert_printable, fields_match, run_case_checks, typed, why};
use crate::check::{CheckParams, UnsupportedReason};

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn cases() -> Vec<Case> {
    let long = "x".repeat(300);
    let endpoints_65: Vec<Value> = (0..65)
        .map(|i| json!(format!("h{i}.example:443")))
        .collect();
    let hosts_65: Vec<Value> = (0..65).map(|i| json!(format!("h{i}.example"))).collect();
    let names_65: Vec<Value> = (0..65).map(|i| json!(format!("h{i}.example"))).collect();
    let pins_17: Vec<Value> = (0..17).map(|_| json!(PIN)).collect();
    let statuses_17: Vec<Value> = (200..217).map(|s| json!(s)).collect();
    let ranges_17: Vec<Value> = (0..17).map(|i| json!(format!("10.{i}.0.0/16"))).collect();
    vec![
        Case {
            id: "net.egress",
            full: json!({
                "endpoints": [
                    "registry.acme.example:443",
                    {"target": "https://api.acme.example/health", "optional": true,
                     "expect_status": [200, 401], "method": "GET", "via_proxy": "direct", "tls": true}
                ],
                "via_proxy": "proxy_only", "trust": "bundled", "max_latency": "3s"
            }),
            bad: vec![
                ("endpoints", json!([])),
                ("endpoints", json!("registry.acme.example:443")),
                ("endpoints", Value::Array(endpoints_65)),
                ("endpoints", json!(["registry.acme.example"])),
                ("endpoints", json!(["registry.acme.example:0"])),
                ("endpoints", json!(["registry.acme.example:65536"])),
                (
                    "endpoints",
                    json!(["https://user:pw@registry.acme.example/"]),
                ),
                ("endpoints", json!(["0xa9.0xfe.0xa9.0xfe:80"])),
                ("endpoints", json!([5])),
                ("endpoints", json!([{"optional": true}])),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "retries": 3}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "optional": "yes"}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "expect_status": []}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "expect_status": [99]}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "expect_status": [600]}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "expect_status": [200, 200]}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "expect_status": statuses_17}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "method": "POST"}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "method": "get"}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "via_proxy": "never"}]),
                ),
                (
                    "endpoints",
                    json!([{"target": "a.example:443", "tls": "yes"}]),
                ),
                ("via_proxy", json!("never")),
                ("via_proxy", json!("Auto")),
                ("via_proxy", json!(true)),
                ("trust", json!("os")),
                ("trust", json!(1)),
                ("max_latency", json!("2")),
                ("max_latency", json!("0s")),
                ("max_latency", json!(2)),
            ],
            fields: NetEgress::FIELDS,
        },
        Case {
            id: "net.proxy",
            full: json!({"required_no_proxy": [".svc", "10.0.0.0/8"], "daemons_need_proxy": true}),
            bad: vec![
                ("required_no_proxy", json!(".svc")),
                ("required_no_proxy", json!([""])),
                ("required_no_proxy", json!([long.clone()])),
                ("required_no_proxy", json!([1])),
                ("daemons_need_proxy", json!("yes")),
                ("daemons_need_proxy", json!(1)),
            ],
            fields: NetProxy::FIELDS,
        },
        Case {
            id: "net.tls_intercept",
            full: json!({
                "hosts": ["registry.acme.example", "api.acme.example:8443"],
                "expected_issuer": "^Acme Corp CA", "pin_sha256": [PIN],
                "forbid_interception": true
            }),
            bad: vec![
                ("hosts", json!([])),
                ("hosts", json!("registry.acme.example")),
                ("hosts", Value::Array(hosts_65)),
                ("hosts", json!([""])),
                ("hosts", json!([":443"])),
                ("hosts", json!(["a.example:0"])),
                ("hosts", json!(["a.example:99999"])),
                ("hosts", json!(["a.example:"])),
                ("hosts", json!(["a b"])),
                ("hosts", json!(["https://a.example"])),
                ("hosts", json!(["a.example."])),
                ("hosts", json!(["2852039166"])),
                ("hosts", json!([format!("{}.example", "a".repeat(300))])),
                ("hosts", json!([1])),
                ("expected_issuer", json!("")),
                ("expected_issuer", json!("x".repeat(257))),
                ("expected_issuer", json!(5)),
                ("pin_sha256", json!([])),
                ("pin_sha256", json!(PIN)),
                ("pin_sha256", json!(["abc"])),
                ("pin_sha256", json!([PIN.to_uppercase()])),
                ("pin_sha256", json!([format!("{}g", &PIN[1..])])),
                ("pin_sha256", json!([format!("{PIN}0")])),
                ("pin_sha256", Value::Array(pins_17)),
                ("forbid_interception", json!("yes")),
            ],
            fields: NetTlsIntercept::FIELDS,
        },
        Case {
            id: "net.dns",
            full: json!({
                "names": ["registry.acme.example",
                    {"name": "db.acme.example", "expect_in": ["10.0.0.0/8", "fd00::/8"],
                     "expect_public": false}],
                "max_latency": "250ms"
            }),
            bad: vec![
                ("names", json!([])),
                ("names", json!("registry.acme.example")),
                ("names", Value::Array(names_65)),
                ("names", json!([""])),
                ("names", json!(["a b"])),
                ("names", json!(["a_b.example"])),
                ("names", json!(["-s"])),
                ("names", json!(["--x"])),
                ("names", json!(["-a.example"])),
                ("names", json!(["a-.example"])),
                ("names", json!(["a..example"])),
                ("names", json!(["a.example."])),
                ("names", json!(["2852039166"])),
                ("names", json!(["0xa9.0xfe.0xa9.0xfe"])),
                ("names", json!(["10.0.0.1"])),
                ("names", json!(["a.example.1"])),
                ("names", json!([format!("{}.example", "a".repeat(64))])),
                ("names", json!([{"name": "-s"}])),
                ("names", json!(["a\u{202e}b.example"])),
                ("names", json!(["x".repeat(254)])),
                ("names", json!([7])),
                ("names", json!([{"expect_public": true}])),
                ("names", json!([{"name": "a.example", "retries": 1}])),
                ("names", json!([{"name": "a.example", "expect_in": []}])),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["10.0.0.0"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["10.0.0.0/33"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["10.0.0.0/08"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["10.0.0.0/8/8"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["10.0.0.300/8"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["::1/129"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["::ffff:10.0.0.1/104"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ["a.example/8"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": [":::/8"]}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_in": ranges_17}]),
                ),
                (
                    "names",
                    json!([{"name": "a.example", "expect_public": "yes"}]),
                ),
                ("max_latency", json!("fast")),
                ("max_latency", json!("0ms")),
            ],
            fields: NetDns::FIELDS,
        },
    ]
}

// ---- the fixture covers every field, every field has a rejecting case ---------------------------

#[test]
fn each_net_id_accepts_its_full_fixture_and_refuses_each_bad_value() {
    run_case_checks(&cases());
}

// ---- FIELDS cannot drift from the struct --------------------------------------------------------

#[test]
fn net_egress_fields_match_the_struct() {
    fields_match::<NetEgress>();
}

#[test]
fn net_proxy_fields_match_the_struct() {
    fields_match::<NetProxy>();
}

#[test]
fn net_tls_intercept_fields_match_the_struct() {
    fields_match::<NetTlsIntercept>();
}

#[test]
fn net_dns_fields_match_the_struct() {
    fields_match::<NetDns>();
}

// ---- no threshold -------------------------------------------------------------------------------

#[test]
fn a_net_check_with_a_required_key_missing_is_no_threshold() {
    let one_of: &[(&str, &[&str])] = &[("net.egress", &["endpoints"]), ("net.dns", &["names"])];
    for (id, keys) in one_of {
        for params in [json!({}), json!({"max_latency": "1s"})] {
            assert_eq!(
                why(id, &params),
                UnsupportedReason::NoThreshold {
                    one_of: keys,
                    and: vec![]
                },
                "{id} {params}"
            );
        }
    }
    assert_eq!(
        why(
            "net.egress",
            &json!({"via_proxy": "direct", "trust": "bundled"})
        )
        .to_string(),
        "has no threshold: add 'endpoints'"
    );
}

#[test]
fn net_checks_without_a_required_key_decode_bare() {
    typed("net.proxy", &json!({}));
    typed("net.tls_intercept", &json!({}));
}

// ---- what a good value reads as -----------------------------------------------------------------

#[test]
fn egress_defaults_are_applied() {
    let CheckParams::NetEgress(e) = typed(
        "net.egress",
        &json!({"endpoints": ["registry.acme.example:443"]}),
    ) else {
        panic!("not NetEgress");
    };
    assert_eq!(e.via_proxy, ViaProxy::Auto);
    assert_eq!(e.trust, Trust::System);
    assert_eq!(e.max_latency, None);
    let endpoint = &e.endpoints[0];
    assert!(!endpoint.optional);
    assert_eq!(endpoint.method, HttpMethod::Head);
    assert_eq!(endpoint.via_proxy, None);
    assert_eq!(endpoint.tls, None);
    assert_eq!(endpoint.expect_status, None);
    assert_eq!(endpoint.target.port(), 443);
}

#[test]
fn a_bare_target_and_a_target_object_read_the_same_way() {
    let CheckParams::NetEgress(e) = typed(
        "net.egress",
        &json!({"endpoints": ["a.example:443", {"target": "a.example:443"}]}),
    ) else {
        panic!("not NetEgress");
    };
    assert_eq!(e.endpoints[0], e.endpoints[1]);
}

#[test]
fn an_endpoint_keeps_its_options() {
    let CheckParams::NetEgress(e) = typed(
        "net.egress",
        &json!({"endpoints": [{"target": "https://a.example/x", "optional": true,
            "expect_status": [200, 401], "method": "GET", "via_proxy": "direct", "tls": false}]}),
    ) else {
        panic!("not NetEgress");
    };
    let endpoint = &e.endpoints[0];
    assert!(endpoint.target.is_url());
    assert!(endpoint.optional);
    assert_eq!(endpoint.method, HttpMethod::Get);
    assert_eq!(endpoint.via_proxy, Some(ViaProxy::Direct));
    assert_eq!(endpoint.tls, Some(false));
    let statuses: Vec<u16> = endpoint
        .expect_status
        .as_ref()
        .expect("statuses")
        .iter()
        .map(|s| s.get())
        .collect();
    assert_eq!(statuses, [200, 401]);
}

#[test]
fn a_tls_host_has_a_port_only_when_written() {
    let CheckParams::NetTlsIntercept(t) = typed(
        "net.tls_intercept",
        &json!({"hosts": ["a.example", "b.example:8443", "10.1.2.3"]}),
    ) else {
        panic!("not NetTlsIntercept");
    };
    let hosts = t.hosts.expect("hosts");
    assert_eq!(hosts[0].port(), None);
    assert_eq!(hosts[1].port(), Some(8443));
    assert_eq!(hosts[2].port(), None);
    assert_eq!(hosts[0].host().to_string(), "a.example");
    assert!(!t.forbid_interception);
}

#[test]
fn a_bare_name_and_a_name_object_read_the_same_way() {
    let CheckParams::NetDns(d) = typed(
        "net.dns",
        &json!({"names": ["a.example", {"name": "a.example"}]}),
    ) else {
        panic!("not NetDns");
    };
    assert_eq!(d.names[0], d.names[1]);
    assert_eq!(d.names[0].expect_in, None);
    assert_eq!(d.names[0].expect_public, None);
}

#[test]
fn address_ranges_keep_their_address_and_prefix() {
    let CheckParams::NetDns(d) = typed(
        "net.dns",
        &json!({"names": [{"name": "a.example", "expect_in": ["10.0.0.0/8", "fd00::/8", "0.0.0.0/0"]}]}),
    ) else {
        panic!("not NetDns");
    };
    let ranges = d.names[0].expect_in.as_ref().expect("ranges");
    assert_eq!(ranges[0].addr().to_string(), "10.0.0.0");
    assert_eq!(ranges[0].prefix(), 8);
    assert_eq!(ranges[1].addr().to_string(), "fd00::");
    assert_eq!(ranges[2].prefix(), 0);
}

// ---- hostile text and nested values -------------------------------------------------------------

#[test]
fn a_key_with_no_value_inside_an_endpoint_or_a_name_is_a_bad_value() {
    for (id, params, field) in [
        (
            "net.egress",
            json!({"endpoints": [{"target": "a.example:443", "optional": null}]}),
            "endpoints",
        ),
        (
            "net.egress",
            json!({"endpoints": [{"target": null}]}),
            "endpoints",
        ),
        (
            "net.dns",
            json!({"names": [{"name": "a.example", "expect_in": null}]}),
            "names",
        ),
        ("net.dns", json!({"names": [null]}), "names"),
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
        (
            "net.egress",
            json!({"endpoints": ["a\u{1b}[2J.example:443"]}),
        ),
        (
            "net.tls_intercept",
            json!({"hosts": ["a\u{1b}[2J.example"]}),
        ),
        ("net.tls_intercept", json!({"pin_sha256": ["\u{1b}[2J"]})),
        ("net.dns", json!({"names": ["a\u{1b}[2J.example"]})),
        (
            "net.dns",
            json!({"names": [{"name": "a.example", "expect_in": ["\u{1b}[2J/8"]}]}),
        ),
    ] {
        assert_printable(&why(id, &params));
    }
}

#[test]
fn a_refused_target_does_not_echo_a_query_string() {
    let reason = why(
        "net.egress",
        &json!({"endpoints": ["https://u:secret-token@a.example/x?token=hunter2"]}),
    );
    let text = reason.to_string();
    assert!(!text.contains("hunter2"), "{text}");
    assert!(!text.contains("secret-token"), "{text}");
}

/// A name of valid labels is still refused when the whole name is over 253 characters (PR #36 review).
#[test]
fn a_dns_name_of_valid_labels_is_refused_for_its_total_length() {
    let name_of = |len: usize| {
        // Labels of 63 characters joined by dots, the last one cut to fit.
        let mut parts: Vec<String> = Vec::new();
        let mut left = len;
        while left > 0 {
            let take = left.min(63);
            parts.push("a".repeat(take));
            left = left.saturating_sub(take + 1);
        }
        let name = parts.join(".");
        assert_eq!(name.len(), len);
        name
    };
    typed("net.dns", &json!({"names": [name_of(253)]}));
    let long = name_of(254);
    assert!(long.split('.').all(|label| (1..=63).contains(&label.len())));
    let reason = why("net.dns", &json!({"names": [long.clone()]}));
    assert!(
        matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == "names"),
        "{reason:?}"
    );
    let reason = why("net.tls_intercept", &json!({"hosts": [long]}));
    assert!(
        matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == "hosts"),
        "{reason:?}"
    );
}

/// ADR 0006 decision 5: the name reaches `getent ahosts` as an argument, so it must not read as an option.
#[test]
fn a_dns_name_cannot_start_with_a_dash_or_be_a_number() {
    for name in ["-s", "--x", "-", "2852039166", "0x7f000001", "127.1"] {
        let reason = why("net.dns", &json!({"names": [name]}));
        assert!(
            matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == "names"),
            "{name}: {reason:?}"
        );
    }
    for name in [
        "localhost",
        "a-b.example",
        "xn--bcher-kva.example",
        "A.Example",
        "a1.b2.example",
    ] {
        typed("net.dns", &json!({"names": [name]}));
    }
}

#[test]
fn a_host_with_credentials_does_not_echo_them() {
    let reason = why(
        "net.tls_intercept",
        &json!({"hosts": ["user:secret-pw@a.example"]}),
    );
    let text = reason.to_string();
    assert!(!text.contains("secret-pw"), "{text}");
}
