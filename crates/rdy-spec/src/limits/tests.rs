//! Unit tests for the host count and the collector grammar. The refusals with their places are tested on
//! fixtures in `tests/semantic_limits.rs`.

use serde_json::json;

use super::*;
use crate::spec::{CheckId, CheckSpec, Metadata, ProductSlug};

fn check(id: &str, params: serde_json::Value) -> CheckSpec {
    let mut check = CheckSpec::new(CheckId::new(id).unwrap());
    if let serde_json::Value::Object(map) = params {
        check.params = map;
    }
    check
}

fn spec_of(checks: Vec<CheckSpec>) -> Spec {
    Spec::new(Metadata::new(ProductSlug::new("acme").unwrap()), checks)
}

fn hosts(checks: Vec<CheckSpec>) -> usize {
    spec_hosts(&spec_of(checks)).len()
}

#[test]
fn a_host_counts_once_across_ports_case_checks_and_forms() {
    let egress = check(
        "net.egress",
        json!({"endpoints": [
            "registry.acme.example:443",
            "Registry.Acme.Example:8443",
            "https://registry.acme.example/v2/",
            {"target": "REGISTRY.acme.example:80", "optional": true},
            "10.0.0.1:443",
            "[2001:db8::1]:443",
        ]}),
    );
    let tls = check(
        "net.tls_intercept",
        json!({"hosts": ["registry.acme.example", "registry.acme.example:8443", "10.0.0.1", "[2001:db8::1]"]}),
    );
    let dns = check(
        "net.dns",
        json!({"names": ["registry.acme.example", {"name": "10.0.0.1"}]}),
    );
    assert_eq!(hosts(vec![egress.clone()]), 3);
    assert_eq!(hosts(vec![egress, tls, dns]), 3);
}

#[test]
fn other_checks_and_other_keys_add_no_hosts() {
    let proxy = check(
        "net.proxy",
        json!({"required_no_proxy": ["a.example", "b.example"]}),
    );
    let host = check("host.cpu", json!({"endpoints": ["a.example:1"]}));
    let wrong_key = check("net.egress", json!({"hosts": ["a.example:1"]}));
    let not_a_list = check("net.egress", json!({"endpoints": "a.example:443"}));
    let odd_items = check(
        "net.dns",
        json!({"names": [1, null, true, ["x"], {"other": "y"}]}),
    );
    assert_eq!(
        hosts(vec![proxy, host, wrong_key, not_a_list, odd_items]),
        0
    );
}

#[test]
fn text_that_is_not_a_target_still_counts_as_a_host() {
    // A check with a bad entry is skipped at run time, but it can never lower the spec-wide count.
    let dns = check(
        "net.dns",
        json!({"names": ["not a host", "NOT A HOST", "169.254.169.254.", "0xa9.0xfe.0xa9.0xfe"]}),
    );
    assert_eq!(hosts(vec![dns]), 3);
}

fn many(id: &str, key: &str, from: usize, to: usize, suffix: &str) -> CheckSpec {
    let list: Vec<String> = (from..to)
        .map(|i| format!("h{i}.acme.example{suffix}"))
        .collect();
    check(id, json!({ key: list }))
}

#[test]
fn sixty_four_hosts_pass_and_sixty_five_fail_however_they_are_spread() {
    let spread = |extra: usize| {
        spec_of(vec![
            many("net.egress", "endpoints", 0, 30, ":443"),
            many("net.tls_intercept", "hosts", 30, 60, ""),
            many("net.dns", "names", 60, 64 + extra, ""),
        ])
    };
    assert_eq!(validate(&spread(0), &Places::default()), Ok(()));
    assert_eq!(
        validate(&spread(1), &Places::default()),
        Err(SpecError::TooManyHosts {
            count: 65,
            limit: 64
        })
    );
}

#[test]
fn many_checks_naming_the_same_hosts_stay_under_the_limit() {
    // 256 checks times 64 entries is 16384 entries, but only 64 hosts.
    let checks: Vec<CheckSpec> = (0..256)
        .map(|n| {
            let mut c = many("net.egress", "endpoints", 0, 64, ":443");
            c.name = Some(crate::spec::Lenient::Valid(
                crate::spec::CheckName::new(format!("n{n}")).unwrap(),
            ));
            c
        })
        .collect();
    assert_eq!(hosts(checks.clone()), 64);
    assert_eq!(validate(&spec_of(checks), &Places::default()), Ok(()));
}

#[test]
fn many_checks_with_different_hosts_hit_the_limit_the_old_per_check_rule_missed() {
    // Each check is within its own 64 entries. Together they name 128 hosts.
    let checks = vec![
        many("net.egress", "endpoints", 0, 64, ":443"),
        many("net.tls_intercept", "hosts", 64, 128, ""),
    ];
    assert_eq!(
        validate(&spec_of(checks), &Places::default()),
        Err(SpecError::TooManyHosts {
            count: 128,
            limit: 64
        })
    );
}

#[test]
fn the_check_count_has_both_bounds() {
    assert_eq!(check_count(0), Err(SpecError::NoChecks));
    assert_eq!(check_count(1), Ok(()));
    assert_eq!(check_count(256), Ok(()));
    assert_eq!(
        check_count(257),
        Err(SpecError::TooManyChecks {
            count: 257,
            limit: 256
        })
    );
}

#[test]
fn collector_reasons_are_escaped() {
    let reason = check_collector("file:\u{1b}[2Jrelative").unwrap_err();
    assert!(!reason.chars().any(char::is_control), "{reason:?}");
    let reason = check_collector(&format!("x{}", "y".repeat(5000))).unwrap_err();
    assert!(reason.len() < 400, "{} bytes", reason.len());
}
