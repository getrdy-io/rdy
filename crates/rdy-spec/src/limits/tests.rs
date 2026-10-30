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
    named_endpoints(&spec_of(checks)).hosts.len()
}

fn pairs(checks: Vec<CheckSpec>) -> usize {
    named_endpoints(&spec_of(checks)).pairs.len()
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
            count: 65,
            limit: 64
        })
    );
}

/// `hosts` hosts with `ports` ports each, as `net.egress` endpoints, `per_check` endpoints to a check.
fn grid(hosts: usize, ports: usize, per_check: usize) -> Vec<CheckSpec> {
    let all: Vec<String> = (0..hosts)
        .flat_map(|h| (0..ports).map(move |p| format!("h{h}.acme.example:{}", 1000 + p)))
        .collect();
    all.chunks(per_check)
        .map(|chunk| check("net.egress", json!({"endpoints": chunk})))
        .collect()
}

#[test]
fn a_port_scan_shaped_spec_is_refused_by_the_pair_cap() {
    // 64 checks of 64 endpoints on 4 hosts: 4096 entries, 4 hosts, 4096 distinct pairs.
    let checks = grid(4, 1024, 64);
    assert_eq!(checks.len(), 64);
    assert_eq!(hosts(checks.clone()), 4);
    assert_eq!(
        validate(&spec_of(checks), &Places::default()),
        Err(SpecError::TooManyEndpoints {
            count: 257,
            limit: 256
        })
    );
}

#[test]
fn two_hundred_fifty_six_pairs_pass_and_two_hundred_fifty_seven_fail() {
    assert_eq!(
        validate(&spec_of(grid(4, 64, 64)), &Places::default()),
        Ok(())
    );
    let mut over = grid(4, 64, 64);
    over.push(check(
        "net.egress",
        json!({"endpoints": ["h0.acme.example:9999"]}),
    ));
    assert_eq!(pairs(over.clone()), 257);
    assert_eq!(
        validate(&spec_of(over), &Places::default()),
        Err(SpecError::TooManyEndpoints {
            count: 257,
            limit: 256
        })
    );
}

#[test]
fn a_pair_counts_once_however_it_is_written_and_dns_names_add_none() {
    let egress = check(
        "net.egress",
        json!({"endpoints": [
            "Registry.acme.example:443",
            "registry.acme.example:443",
            "https://registry.acme.example/v2/",
            {"target": "registry.acme.example:8443"},
        ]}),
    );
    let tls = check(
        "net.tls_intercept",
        json!({"hosts": ["registry.acme.example", "registry.acme.example:8443", "registry.acme.example:9443"]}),
    );
    let dns = check("net.dns", json!({"names": ["registry.acme.example"]}));
    assert_eq!(pairs(vec![egress, tls, dns.clone()]), 3);
    assert_eq!(pairs(vec![dns]), 0);
}

#[test]
fn pairs_in_a_check_that_does_not_decode_are_still_counted() {
    // 65 entries is over the 64 a check may have, so the check does not decode.
    let list: Vec<String> = (0..65)
        .map(|p| format!("a.acme.example:{}", 1000 + p))
        .collect();
    let skipped = check("net.egress", json!({"endpoints": list}));
    assert_eq!(pairs(vec![skipped]), 65);
}

#[test]
fn collection_stops_one_past_each_limit() {
    let named = named_endpoints(&spec_of(vec![
        many("net.egress", "endpoints", 0, 64, ":443"),
        many("net.tls_intercept", "hosts", 64, 128, ""),
        many("net.dns", "names", 128, 192, ""),
    ]));
    assert_eq!(named.hosts.len(), 65);
    let named = named_endpoints(&spec_of(grid(4, 64, 64)));
    assert_eq!(named.pairs.len(), 256);
    let named = named_endpoints(&spec_of(grid(4, 1024, 64)));
    assert_eq!(named.pairs.len(), 257);
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

/// Each of these fields names one host. Together with `others` egress endpoints they make `others + 1`
/// distinct hosts, typed (the check decodes) or raw (it carries a key it does not have, so it does not).
fn one_host_fields() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "host.time_sync",
            json!({"ntp_servers": ["ntp.field.example"]}),
        ),
        (
            "host.time_sync",
            json!({"ntp_servers": ["fd00:ec2::123", "ntp.field.example"]}),
        ),
        (
            "net.registry",
            json!({"registries": ["registry.field.example"]}),
        ),
        (
            "net.registry",
            json!({"registries": [{"host": "registry.field.example:5000"}]}),
        ),
        (
            "net.registry",
            json!({"registries": [{"host": "r0.field.example", "hosts": ["token.field.example"]}]}),
        ),
        (
            "net.bandwidth",
            json!({"url": "https://mirror.field.example/sample.bin"}),
        ),
    ]
}

#[test]
fn ntp_registry_and_bandwidth_hosts_count_toward_the_sixty_four_host_limit() {
    for (id, params) in one_host_fields() {
        let mut raw = params.clone();
        raw["unknown_key"] = json!(1);
        for (kind, params) in [("typed", params.clone()), ("raw", raw)] {
            let with = |others: usize| {
                spec_of(vec![
                    many("net.egress", "endpoints", 0, others, ":443"),
                    check(id, params.clone()),
                ])
            };
            // How many hosts the field names by itself, so the egress list can fill the rest.
            let room = 64 - named_endpoints(&with(0)).hosts.len();
            assert_eq!(
                validate(&with(room), &Places::default()),
                Ok(()),
                "{id} {kind}: 64 pass"
            );
            assert_eq!(
                validate(&with(room + 1), &Places::default()),
                Err(SpecError::TooManyHosts {
                    count: 65,
                    limit: 64
                }),
                "{id} {kind}: 65 fail"
            );
        }
    }
}

#[test]
fn registry_hosts_count_with_their_ports_as_pairs() {
    let registry = check(
        "net.registry",
        json!({"registries": [{"host": "r.example", "hosts": ["r.example:8443", "t.example"]}]}),
    );
    let named = named_endpoints(&spec_of(vec![registry]));
    assert_eq!(named.hosts.len(), 2);
    assert_eq!(named.pairs.len(), 3);
    let ntp = check(
        "host.time_sync",
        json!({"ntp_servers": ["ntp.acme.example", "ntp.acme.example:1123", "fd00::1"]}),
    );
    let named = named_endpoints(&spec_of(vec![ntp]));
    assert_eq!(named.hosts.len(), 2);
    assert_eq!(named.pairs.len(), 3);
    assert!(named.pairs.contains(&("ntp.acme.example".to_owned(), 123)));
}

#[test]
fn a_host_named_by_two_checks_counts_once() {
    let egress = check(
        "net.egress",
        json!({"endpoints": ["shared.acme.example:443"]}),
    );
    let registry = check(
        "net.registry",
        json!({"registries": ["Shared.Acme.Example"]}),
    );
    let ntp = check(
        "host.time_sync",
        json!({"ntp_servers": ["shared.acme.example"]}),
    );
    let bandwidth = check(
        "net.bandwidth",
        json!({"url": "https://shared.acme.example/sample.bin"}),
    );
    assert_eq!(hosts(vec![egress, registry, ntp, bandwidth]), 1);
}

#[test]
fn the_raw_registry_reading_survives_odd_items() {
    let odd = check(
        "net.registry",
        json!({"registries": [1, null, {"hosts": "x"}, {"host": 5}, ["a"]], "unknown_key": 1}),
    );
    assert_eq!(hosts(vec![odd]), 0);
}
