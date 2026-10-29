//! Boundary tests of the pure parsers and judges of `host.firewall`. No probe, no runtime.

use super::Verdict;
use super::firewalld::{self, Target};
use super::ports::PortRange;
use super::route;
use super::service::{self, Cover, Services, Svc};
use super::ufw::{self, Policy};

macro_rules! fx {
    ($case:literal, $file:literal) => {
        include_str!(concat!(
            "../../../../tests/fixtures/checks/host.firewall/",
            $case,
            "/",
            $file
        ))
    };
}

const ROUTE: &str = fx!("base-firewalld", "root/proc/net/route");
const RICH: &str = fx!("firewalld-rich-rule", "commands/list-all-public.json");
const USER_RULES: &str = fx!("ufw-allowed", "root/etc/ufw/user.rules");
const SERVICE: &str = fx!(
    "firewalld-service-open",
    "root/etc/firewalld/services/acme-kubelet.xml"
);

fn range(text: &str) -> PortRange {
    PortRange::parse(text, '-').expect("a range")
}

#[test]
fn port_ranges_have_inclusive_edges_and_refuse_nonsense() {
    let r = range("6000-6443");
    assert!(r.covers(6000) && r.covers(6443));
    assert!(!r.covers(5999) && !r.covers(6444));
    assert!(range("6443").covers(6443) && !range("6443").covers(6442));
    assert_eq!(
        PortRange::parse("6000:6010", ':'),
        PortRange::parse("6000-6010", '-')
    );
    for bad in [
        "", "0", "0-5", "65536", "7-6", "-5", "5-", "a", "1-2-3", "6443/tcp", " ",
    ] {
        assert_eq!(PortRange::parse(bad, '-'), None, "{bad:?}");
    }
    assert!(range("65535").covers(65535));
    assert!(PortRange::all().covers(1) && PortRange::all().covers(65535));
}

#[test]
fn the_default_route_is_the_lowest_metric_up_route_with_a_zero_destination() {
    assert_eq!(
        route::default_interface(Some(ROUTE), None).as_deref(),
        Some("eth0")
    );
    let two = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
               eth1\t00000000\t0100000A\t0003\t0\t0\t600\t00000000\n\
               eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\n";
    assert_eq!(
        route::default_interface(Some(two), None).as_deref(),
        Some("eth0")
    );
    // Flags without RTF_UP, a non-default mask and a header only.
    let down = "h\neth0\t00000000\t0100000A\t0002\t0\t0\t1\t00000000\n\
                eth1\t00000000\t0100000A\t0003\t0\t0\t1\t000000FF\n";
    assert_eq!(route::default_interface(Some(down), None), None);
    assert_eq!(route::default_interface(Some("h\n"), None), None);
    assert_eq!(route::default_interface(None, None), None);
}

#[test]
fn ipv6_is_used_only_without_an_ipv4_default_and_reject_routes_are_skipped() {
    let zeros = "00000000000000000000000000000000";
    let v6 = format!(
        "{zeros} 00 {zeros} 00 {zeros} 00000100 00000001 00000000 00000201 eth9\n\
         {zeros} 00 {zeros} 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth1\n"
    );
    // The first row is a reject route (UP and REJECT), with the lowest metric, and is skipped.
    assert_eq!(
        route::default_interface(None, Some(&v6)).as_deref(),
        Some("eth1")
    );
    assert_eq!(
        route::default_interface(Some(ROUTE), Some(&v6)).as_deref(),
        Some("eth0")
    );
    assert_eq!(
        route::default_interface(Some("h\n"), Some(&v6)).as_deref(),
        Some("eth1")
    );
}

#[test]
fn active_zones_are_read_with_their_interfaces() {
    let zones = firewalld::parse_active_zones(
        "public\n  interfaces: eth0 eth1\n  sources: 192.0.2.0/24\ndocker\n  interfaces: docker0\n\n",
    );
    assert_eq!(zones.len(), 2);
    assert_eq!(zones[0].name, "public");
    assert_eq!(zones[0].interfaces, ["eth0", "eth1"]);
    assert_eq!(zones[1].interfaces, ["docker0"]);
    assert!(firewalld::parse_active_zones("").is_empty());
    assert!(firewalld::parse_active_zones("  interfaces: eth0\n").is_empty());
}

fn zone(text: &str) -> firewalld::Zone {
    firewalld::parse_zone(text).expect("a zone")
}

#[test]
fn a_zone_listing_gives_ports_services_target_and_rich_rules() {
    let z = zone(
        "public (active)\n  target: DROP\n  interfaces: eth0\n  sources: ipset:acme\n  services: ssh http\n  ports: 6443/tcp 30000-32767/tcp 53/udp 9/sctp bogus\n  rich rules: \n\trule family=\"ipv6\" source address=\"fd00::/8\" accept\n",
    );
    assert_eq!(z.name, "public");
    assert_eq!(z.target, Target::Drop);
    assert_eq!(z.services, ["ssh", "http"]);
    assert_eq!(z.tcp.len(), 2);
    assert!(z.tcp[1].covers(32767) && !z.tcp[1].covers(32768));
    assert!(z.ipset_sources);
    // The IPv6 colons did not split the rule into a key and a value.
    assert_eq!(
        z.rich_rules,
        ["rule family=\"ipv6\" source address=\"fd00::/8\" accept"]
    );
    assert_eq!(zone("p\n  target: %%REJECT%%\n").target, Target::Reject);
    assert_eq!(zone("p\n  target: default\n").target, Target::Default);
    assert_eq!(zone("p\n").target, Target::Default);
    assert_eq!(firewalld::parse_zone(""), None);
    assert_eq!(firewalld::parse_zone("  indented\n"), None);
}

fn services_with_api(port: &str) -> Services {
    Services::default().with(
        "acme-api",
        Svc::Found(service::parse(&format!(
            "<service><port protocol=\"tcp\" port=\"{port}\"/></service>"
        ))),
    )
}

fn open(zone: &firewalld::Zone, services: &Services, port: u16) -> Verdict {
    firewalld::judge(zone, services, port)
}

#[test]
fn a_range_in_a_zone_opens_both_edges_and_not_the_next_port() {
    let z = zone("p\n  ports: 6000-6443/tcp\n");
    let none = Services::default();
    assert!(matches!(open(&z, &none, 6000), Verdict::Open(_)));
    assert!(matches!(open(&z, &none, 6443), Verdict::Open(_)));
    assert!(matches!(open(&z, &none, 6444), Verdict::Closed(_)));
    assert!(matches!(open(&z, &none, 5999), Verdict::Closed(_)));
}

#[test]
fn a_udp_only_port_does_not_open_the_tcp_port() {
    let z = zone("p\n  ports: 6443/udp\n");
    assert!(matches!(
        open(&z, &Services::default(), 6443),
        Verdict::Closed(_)
    ));
}

#[test]
fn a_service_that_is_missing_or_unreadable_makes_the_answer_unknown() {
    let z = zone("p\n  services: acme-api\n");
    let missing = Services::default().with("acme-api", Svc::Missing);
    assert!(matches!(open(&z, &missing, 6443), Verdict::Unknown(_)));
    let unreadable =
        Services::default().with("acme-api", Svc::Unreadable("permission denied".into()));
    let Verdict::Unknown(why) = open(&z, &unreadable, 6443) else {
        panic!("expected unknown");
    };
    assert!(why.contains("permission denied"), "{why}");
    // A service that was found and does not cover the port closes it.
    assert!(matches!(
        open(&z, &services_with_api("6442"), 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        open(&z, &services_with_api("6443"), 6443),
        Verdict::Open(_)
    ));
}

#[test]
fn a_service_with_a_destination_opens_the_port_only_for_some_addresses() {
    let limited = Services::default().with(
        "acme-api",
        Svc::Found(service::parse(
            "<service><port protocol=\"tcp\" port=\"6443\"/><destination ipv4=\"192.0.2.1\"/></service>",
        )),
    );
    let z = zone("p\n  services: acme-api\n");
    assert!(matches!(open(&z, &limited, 6443), Verdict::Unknown(_)));
}

fn applies(rule: &str, port: u16) -> bool {
    let z = zone(&format!(
        "p\n  ports: {port}/tcp\n  rich rules: \n\t{rule}\n"
    ));
    matches!(open(&z, &Services::default(), port), Verdict::Unknown(_))
}

#[test]
fn rich_rules_count_unless_they_are_about_something_else() {
    // About this port.
    assert!(applies(
        "rule family=\"ipv4\" source address=\"192.0.2.0/24\" port port=\"6443\" protocol=\"tcp\" drop",
        6443
    ));
    assert!(applies(
        "rule port port=\"6000-6500\" protocol=\"tcp\" accept",
        6443
    ));
    // Blanket rules from or to an address, and any IP protocol rule.
    assert!(applies(
        "rule family=\"ipv4\" source address=\"192.0.2.9\" reject",
        6443
    ));
    assert!(applies("rule protocol value=\"tcp\" reject", 6443));
    assert!(applies(
        "rule forward-port port=\"6443\" protocol=\"tcp\" to-port=\"8443\"",
        6443
    ));
    // About another port, another protocol, ICMP or masquerading.
    assert!(!applies(
        "rule port port=\"22\" protocol=\"tcp\" accept",
        6443
    ));
    assert!(!applies(
        "rule port port=\"6443\" protocol=\"udp\" accept",
        6443
    ));
    assert!(!applies(
        "rule family=\"ipv4\" icmp-block name=\"echo-request\"",
        6443
    ));
    assert!(!applies("rule family=\"ipv4\" masquerade", 6443));
    // A bad port value counts, because "cannot tell" must not read as "does not apply".
    assert!(applies(
        "rule port port=\"six\" protocol=\"tcp\" accept",
        6443
    ));
}

#[test]
fn a_rich_rule_service_is_resolved_before_it_counts() {
    let z = zone("p\n  ports: 6443/tcp\n  rich rules: \n\trule service name=\"acme-api\" accept\n");
    let covers = services_with_api("6443");
    assert!(matches!(open(&z, &covers, 6443), Verdict::Unknown(_)));
    let other = services_with_api("7000");
    assert!(matches!(open(&z, &other, 6443), Verdict::Open(_)));
    assert_eq!(firewalld::service_names(&z), ["acme-api"]);
}

#[test]
fn the_recorded_rich_rule_listing_is_unknown_for_6443_only() {
    let record: serde_json::Value = serde_json::from_str(RICH).expect("a record");
    let z = zone(record["stdout"].as_str().expect("stdout"));
    let none = Services::default();
    assert!(matches!(open(&z, &none, 6443), Verdict::Unknown(_)));
    assert!(matches!(open(&z, &none, 10250), Verdict::Open(_)));
}

#[test]
fn service_files_are_read_for_tcp_ports_includes_and_destinations() {
    let def = service::parse(SERVICE);
    let one = Services::default().with("s", Svc::Found(def));
    assert_eq!(one.covers("s", 10250), Cover::Yes);
    // The commented-out port 1 is not read.
    assert_eq!(one.covers("s", 1), Cover::No);

    let xml = "<?xml version='1.0'?><service><port port='80' protocol='TCP'/><port protocol=\"udp\" port=\"53\"/><port protocol=\"tcp\" port=\"1000-1010\"/><include service=\"base\"/></service>";
    let all = Services::default()
        .with("s", Svc::Found(service::parse(xml)))
        .with(
            "base",
            Svc::Found(service::parse(
                "<service><port protocol=\"tcp\" port=\"443\"/></service>",
            )),
        );
    assert_eq!(all.covers("s", 80), Cover::Yes);
    assert_eq!(all.covers("s", 53), Cover::No);
    assert_eq!(all.covers("s", 1010), Cover::Yes);
    assert_eq!(all.covers("s", 1011), Cover::No);
    assert_eq!(all.covers("s", 443), Cover::Yes);
}

#[test]
fn service_includes_that_loop_or_run_deep_end() {
    let looped = Services::default()
        .with(
            "a",
            Svc::Found(service::parse(
                "<service><include service=\"b\"/></service>",
            )),
        )
        .with(
            "b",
            Svc::Found(service::parse(
                "<service><include service=\"a\"/></service>",
            )),
        );
    assert_eq!(looped.covers("a", 80), Cover::No);
    let mut deep = Services::default();
    for n in 0..10 {
        deep = deep.with(
            &format!("s{n}"),
            Svc::Found(service::parse(&format!(
                "<service><include service=\"s{}\"/></service>",
                n + 1
            ))),
        );
    }
    deep = deep.with(
        "s10",
        Svc::Found(service::parse(
            "<service><port protocol=\"tcp\" port=\"80\"/></service>",
        )),
    );
    assert_eq!(deep.covers("s0", 80), Cover::No);
    assert_eq!(deep.covers("s9", 80), Cover::Yes);
    assert!(matches!(
        Services::default().covers("x", 80),
        Cover::Unknown(_)
    ));
}

#[test]
fn service_names_that_could_leave_the_directory_are_not_looked_up() {
    for ok in ["ssh", "kube-apiserver", "acme_api", "A1"] {
        assert!(service::valid_name(ok), "{ok}");
    }
    for bad in [
        "",
        "..",
        "a/b",
        "a.b",
        ".hidden",
        "a b",
        "a\0b",
        "../../etc/passwd",
    ] {
        assert!(!service::valid_name(bad), "{bad:?}");
    }
    assert!(!service::valid_name(&"a".repeat(65)));
}

#[test]
fn the_xml_scanner_stops_at_its_limits() {
    let many = "<port protocol=\"tcp\" port=\"80\"/>".repeat(10_000);
    let def = service::parse(&many);
    let one = Services::default().with("s", Svc::Found(def));
    assert_eq!(one.covers("s", 80), Cover::Yes);
    // Multi-byte text across the 64 KiB cut does not panic.
    let wide = format!("<service>{}</service>", "é".repeat(60_000));
    let _ = service::parse(&wide);
}

#[test]
fn ufw_conf_and_defaults_take_the_last_assignment_and_ignore_case() {
    assert_eq!(ufw::enabled("ENABLED=yes\n"), Some(true));
    assert_eq!(ufw::enabled("ENABLED=\"No\"\n"), Some(false));
    assert_eq!(ufw::enabled("ENABLED=yes\nENABLED=no\n"), Some(false));
    assert_eq!(ufw::enabled("ENABLED=maybe\n"), None);
    assert_eq!(ufw::enabled("# ENABLED=yes\n"), None);
    assert_eq!(ufw::enabled(""), None);
    assert_eq!(
        ufw::default_input("DEFAULT_INPUT_POLICY=\"DROP\"\n"),
        Policy::Drop
    );
    assert_eq!(
        ufw::default_input("DEFAULT_INPUT_POLICY=accept\n"),
        Policy::Accept
    );
    assert_eq!(
        ufw::default_input("DEFAULT_INPUT_POLICY=\"REJECT\"\n"),
        Policy::Reject
    );
    assert_eq!(
        ufw::default_input("DEFAULT_INPUT_POLICY=\"x\"\n"),
        Policy::Unknown
    );
    assert_eq!(ufw::default_input(""), Policy::Unknown);
}

fn ufw_verdict(tuples: &[&str], policy: Policy, iface: Option<&str>, port: u16) -> Verdict {
    let text: String = tuples
        .iter()
        .map(|t| format!("### tuple ### {t}\n"))
        .collect();
    ufw::judge(&ufw::parse_user_rules(&text), policy, iface, port)
}

const ALLOW: &str = "allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in";

#[test]
fn ufw_tuples_cover_lists_ranges_profiles_and_any_protocol() {
    let v = |t: &str, port| ufw_verdict(&[t], Policy::Drop, None, port);
    assert!(matches!(
        v("allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in", 443),
        Verdict::Open(_)
    ));
    assert!(matches!(
        v("allow tcp 6000:6010 0.0.0.0/0 any 0.0.0.0/0 in", 6010),
        Verdict::Open(_)
    ));
    assert!(matches!(
        v("allow tcp 6000:6010 0.0.0.0/0 any 0.0.0.0/0 in", 6011),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        v("allow any 6443 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in", 6443),
        Verdict::Open(_)
    ));
    assert!(matches!(
        v("limit tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in", 6443),
        Verdict::Open(_)
    ));
    assert!(matches!(
        v("allow tcp 6443 ::/0 any ::/0 in", 6443),
        Verdict::Open(_)
    ));
    // UDP, outbound and forwarded rules do not open inbound TCP.
    assert!(matches!(
        v("allow udp 6443 0.0.0.0/0 any 0.0.0.0/0 in", 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        v("allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 out", 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        v("allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 fwd", 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        v("allow tcp bogus 0.0.0.0/0 any 0.0.0.0/0 in", 6443),
        Verdict::Closed(_)
    ));
}

#[test]
fn ufw_first_unrestricted_rule_decides_in_file_order() {
    let deny = "deny tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in";
    assert!(matches!(
        ufw_verdict(&[deny, ALLOW], Policy::Accept, None, 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        ufw_verdict(&[ALLOW, deny], Policy::Drop, None, 6443),
        Verdict::Open(_)
    ));
    let reject = "reject tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in";
    assert!(matches!(
        ufw_verdict(&[reject], Policy::Accept, None, 6443),
        Verdict::Closed(_)
    ));
}

#[test]
fn ufw_rules_limited_by_address_or_interface_cannot_be_judged() {
    let from = "allow tcp 6443 0.0.0.0/0 any 192.0.2.0/24 in";
    assert!(matches!(
        ufw_verdict(&[from], Policy::Drop, None, 6443),
        Verdict::Unknown(_)
    ));
    // A limited rule followed by an unrestricted allow still opens the port.
    assert!(matches!(
        ufw_verdict(&[from, ALLOW], Policy::Drop, None, 6443),
        Verdict::Open(_)
    ));
    // A limited deny followed by an unrestricted allow opens it for everyone else.
    let deny_from = "deny tcp 6443 0.0.0.0/0 any 192.0.2.9/32 in";
    assert!(matches!(
        ufw_verdict(&[deny_from, ALLOW], Policy::Drop, None, 6443),
        Verdict::Open(_)
    ));
    // Interface rules: the default-route interface decides.
    let on_eth0 = "allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in_eth0";
    assert!(matches!(
        ufw_verdict(&[on_eth0], Policy::Drop, Some("eth0"), 6443),
        Verdict::Open(_)
    ));
    assert!(matches!(
        ufw_verdict(&[on_eth0], Policy::Drop, Some("eth1"), 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        ufw_verdict(&[on_eth0], Policy::Drop, None, 6443),
        Verdict::Unknown(_)
    ));
}

#[test]
fn ufw_default_policy_decides_when_no_rule_matches() {
    assert!(matches!(
        ufw_verdict(&[], Policy::Accept, None, 6443),
        Verdict::Open(_)
    ));
    assert!(matches!(
        ufw_verdict(&[], Policy::Drop, None, 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        ufw_verdict(&[], Policy::Reject, None, 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        ufw_verdict(&[], Policy::Unknown, None, 6443),
        Verdict::Unknown(_)
    ));
}

#[test]
fn the_recorded_user_rules_hold_three_tuples() {
    assert_eq!(ufw::parse_user_rules(USER_RULES).len(), 3);
}

/// Every prefix of the recorded texts, and some hostile ones, go through every parser.
#[test]
fn no_parser_panics_on_truncated_or_hostile_text() {
    let mut texts: Vec<String> = [
        ROUTE,
        RICH,
        USER_RULES,
        SERVICE,
        "public (active)\n  target: default\n  ports: 6443/tcp\n\trule family=\"ipv6\" source address=\"fd00::/8\" accept\n",
        "public\n  interfaces: eth0\ndocker\n  interfaces: docker0\n",
        "ENABLED=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n",
    ]
    .iter()
    .map(|t| (*t).to_owned())
    .collect();
    texts.extend([
        String::new(),
        "\0\0\0".to_owned(),
        "<".repeat(5000),
        "<a b=\"".repeat(2000),
        "rule \"".repeat(5000),
        "### tuple ### ".repeat(5000),
        "é".repeat(5000),
        "\r\n".repeat(5000),
        "a=".repeat(70_000),
    ]);
    for text in &texts {
        // Every cut of a short text; about a hundred cuts of a long one, so the run stays quick.
        let step = if text.len() < 2000 {
            1
        } else {
            text.len() / 100
        };
        for end in (0..=text.len())
            .filter(|e| text.is_char_boundary(*e))
            .step_by(step)
        {
            let part = &text[..end];
            let _ = firewalld::parse_active_zones(part);
            let _ = firewalld::parse_zone(part);
            let _ = service::parse(part);
            let _ = ufw::enabled(part);
            let _ = ufw::default_input(part);
            let _ = ufw::parse_user_rules(part);
            let _ = route::default_interface(Some(part), Some(part));
            if let Some(z) = firewalld::parse_zone(part) {
                let _ = firewalld::judge(&z, &Services::default(), 6443);
                let _ = firewalld::service_names(&z);
            }
        }
    }
}
