//! Table tests of the `NO_PROXY` matcher. The k8s client's own table (`client/proxy/tests.rs`) holds
//! the same cases, so the two cannot drift when M1-107 moves it onto this one.

use super::*;

fn entry(list: &str, host: &str, port: u16) -> Option<String> {
    match NoProxy::parse(list).exempts(host, port) {
        Some(Exemption::Entry(entry)) => Some(entry),
        Some(Exemption::All) => Some("*".to_owned()),
        Some(Exemption::Loopback) => Some("loopback".to_owned()),
        None => None,
    }
}

fn hit(list: &str, host: &str, port: u16) -> bool {
    entry(list, host, port).is_some()
}

#[test]
fn a_star_exempts_everything() {
    assert!(hit("*", "api.acme.example", 443));
    assert_eq!(
        NoProxy::parse(" * ").exempts("10.0.0.1", 1),
        Some(Exemption::All)
    );
}

#[test]
fn a_name_covers_itself_and_its_subdomains() {
    assert!(hit("acme.example", "acme.example", 443));
    assert!(hit("acme.example", "api.acme.example", 443));
    assert!(hit("acme.example", "a.b.acme.example", 443));
    assert!(!hit("acme.example", "notacme.example", 443));
    assert!(!hit("acme.example", "acme.example.evil.test", 443));
}

#[test]
fn a_leading_dot_or_star_dot_covers_subdomains_only() {
    for list in [".acme.example", "*.acme.example"] {
        assert!(hit(list, "api.acme.example", 443), "{list}");
        assert!(!hit(list, "acme.example", 443), "{list}");
        assert!(!hit(list, "notacme.example", 443), "{list}");
    }
}

#[test]
fn case_blanks_and_a_trailing_dot_are_ignored() {
    assert_eq!(
        entry("x.test,  .ACME.example ", "K8S.Acme.Example.", 443).as_deref(),
        Some(".acme.example")
    );
    assert!(!hit(",, ,", "acme.example", 80));
}

#[test]
fn a_port_limits_the_entry() {
    assert!(hit(
        "registry.acme.example:5000",
        "registry.acme.example",
        5000
    ));
    assert!(!hit(
        "registry.acme.example:5000",
        "registry.acme.example",
        443
    ));
    assert!(hit("registry.acme.example", "registry.acme.example", 5000));
    assert!(hit("10.0.0.7:8080", "10.0.0.7", 8080));
    assert!(!hit("10.0.0.7:8080", "10.0.0.7", 80));
}

#[test]
fn a_port_that_is_not_a_number_matches_nothing() {
    assert!(!hit("acme.example:abc", "acme.example", 443));
    assert!(!hit("acme.example:", "acme.example", 443));
    assert!(!hit("acme.example:99999", "acme.example", 443));
}

#[test]
fn an_ip_entry_matches_that_address_only() {
    assert!(hit("169.254.169.254", "169.254.169.254", 80));
    assert!(!hit("169.254.169.254", "169.254.169.253", 80));
    assert!(!hit("10.0.0.1", "a.10.0.0.1", 80));
}

#[test]
fn a_cidr_entry_covers_its_network() {
    assert!(hit("10.0.0.0/8", "10.255.1.1", 443));
    assert!(!hit("10.0.0.0/8", "11.0.0.1", 443));
    assert!(hit("192.168.4.0/22", "192.168.7.9", 1));
    assert!(!hit("192.168.4.0/22", "192.168.8.1", 1));
    assert!(hit("0.0.0.0/0", "8.8.8.8", 1));
    // A name is never resolved to test it against a network.
    assert!(!hit("10.0.0.0/8", "api.acme.example", 443));
    // A prefix that is too long or not a number matches nothing.
    assert!(!hit("10.0.0.0/33", "10.0.0.1", 1));
    assert!(!hit("10.0.0.0/x", "10.0.0.1", 1));
}

#[test]
fn ipv6_literals_and_networks_work_with_and_without_brackets() {
    assert!(hit("fd00::1", "fd00::1", 443));
    assert!(hit("[fd00::1]", "[fd00::1]", 443));
    assert!(hit("[fd00::1]:8443", "fd00::1", 8443));
    assert!(!hit("[fd00::1]:8443", "fd00::1", 443));
    assert!(hit("fd00::/8", "fd12::9", 443));
    assert!(!hit("fd00::/8", "fe80::9", 443));
    assert!(!hit("fd00::/8", "10.0.0.1", 443));
}

#[test]
fn loopback_never_uses_a_proxy() {
    for host in [
        "localhost",
        "LOCALHOST",
        "127.0.0.1",
        "127.9.9.9",
        "::1",
        "[::1]",
        "::ffff:127.0.0.1",
        "[::ffff:127.0.0.1]",
    ] {
        assert_eq!(
            NoProxy::parse("").exempts(host, 80),
            Some(Exemption::Loopback),
            "{host}"
        );
    }
    assert!(NoProxy::parse("").exempts("acme.example", 80).is_none());
}

#[test]
fn the_exemption_reads_in_a_sentence() {
    assert_eq!(
        Exemption::Entry(".svc".to_owned()).to_string(),
        "NO_PROXY entry \".svc\" covers the host"
    );
    assert_eq!(Exemption::All.to_string(), "NO_PROXY is *");
}

#[test]
fn the_list_is_bounded() {
    let many: String = (0..MAX_ENTRIES + 5)
        .map(|i| format!("h{i}.test,"))
        .collect();
    let list = NoProxy::parse(&many);
    assert_eq!(list.len(), MAX_ENTRIES);
    assert!(list.truncated());
    let long = format!("{},.tail.test", "a".repeat(MAX_LIST_BYTES));
    let list = NoProxy::parse(&long);
    assert!(list.truncated());
    assert!(!hit(&long, "x.tail.test", 1), "the tail was not read");
    let wide = "é".repeat(MAX_LIST_BYTES);
    assert!(
        NoProxy::parse(&wide).truncated(),
        "a cut inside a character"
    );
    let one = NoProxy::parse(&"b".repeat(1000));
    assert_eq!(
        one.entries().next().map(|e| e.chars().count()),
        Some(MAX_ENTRY_CHARS)
    );
}

fn covered(list: &str, required: &str) -> bool {
    NoProxy::parse(list).covers(required).is_some()
}

#[test]
fn coverage_of_a_required_entry() {
    // The same entry, a parent domain, a network that holds the network or the address, and a star.
    assert!(covered(".svc", ".svc"));
    assert!(covered("svc", ".svc"));
    assert!(covered(".cluster.local", ".svc.cluster.local"));
    assert!(covered("cluster.local", ".svc.cluster.local"));
    assert!(covered("*", ".svc"));
    assert!(covered("10.0.0.0/8", "10.0.0.0/8"));
    assert!(covered("10.0.0.0/8", "10.20.0.0/16"));
    assert!(covered("10.0.0.0/8", "10.1.2.3"));
    assert!(covered("169.254.169.254", "169.254.169.254"));
    assert!(covered("registry.acme.example", "registry.acme.example"));
    assert!(covered("acme.example", "registry.acme.example"));
    assert!(covered("acme.example", ".acme.example"));
}

#[test]
fn coverage_says_no_when_a_narrower_entry_is_listed() {
    assert!(!covered("10.0.0.0/16", "10.0.0.0/8"));
    assert!(!covered("10.1.0.0/16", "10.0.0.0/8"));
    assert!(!covered(".svc.cluster.local", ".cluster.local"));
    assert!(!covered("api.svc", ".svc"));
    // A dotted entry leaves out the bare domain.
    assert!(!covered(".acme.example", "acme.example"));
    // A name is not covered by a network, and a network is not covered by a name.
    assert!(!covered("10.0.0.0/8", "registry.acme.example"));
    assert!(!covered("acme.example", "10.0.0.0/8"));
    // A listed port covers that port only.
    assert!(!covered(
        "registry.acme.example:5000",
        "registry.acme.example"
    ));
    assert!(covered(
        "registry.acme.example:5000",
        "registry.acme.example:5000"
    ));
    assert!(covered(
        "registry.acme.example",
        "registry.acme.example:5000"
    ));
    // An entry that cannot match covers nothing, and nothing is covered by an empty list.
    assert!(!covered("x.test:abc", "x.test"));
    assert!(!covered("", ".svc"));
    assert!(!covered(".svc", "bad:port:x:"));
}

#[test]
fn coverage_names_the_entry() {
    let list = NoProxy::parse("x.test, 10.0.0.0/8 ,.svc");
    assert_eq!(list.covers("10.4.0.0/16"), Some("10.0.0.0/8"));
    assert_eq!(list.covers(".svc"), Some(".svc"));
}
