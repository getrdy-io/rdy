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
    let active = firewalld::parse_active_zones(
        "public\n  interfaces: eth0 eth1\n  sources: 192.0.2.0/24\ndocker\n  interfaces: docker0\n\n",
    );
    let zones = &active.zones;
    assert_eq!(zones.len(), 2);
    assert_eq!(zones[0].name, "public");
    assert_eq!(zones[0].interfaces, ["eth0", "eth1"]);
    assert_eq!(zones[0].sources, ["192.0.2.0/24"]);
    assert_eq!(zones[1].interfaces, ["docker0"]);
    assert!(zones[1].sources.is_empty());
    assert!(!active.truncated);
    assert_eq!(active.source_bound_besides("docker"), ["public"]);
    assert!(active.source_bound_besides("public").is_empty());
    assert!(firewalld::parse_active_zones("").zones.is_empty());
    assert!(
        firewalld::parse_active_zones("  interfaces: eth0\n")
            .zones
            .is_empty()
    );
}

#[test]
fn an_active_zone_listing_cut_by_a_limit_says_so() {
    let many: String = (0..70)
        .map(|n| format!("z{n}\n  interfaces: e{n}\n"))
        .collect();
    let cut = firewalld::parse_active_zones(&many);
    assert_eq!(cut.zones.len(), 64);
    assert!(cut.truncated);
    let long = format!("public\n  sources: {}\n", "10.0.0.1 ".repeat(3000));
    let words = firewalld::parse_active_zones(&long);
    assert!(words.truncated);
    assert_eq!(words.zones[0].sources.len(), 2048);
    let lines = format!("public\n{}", "  interfaces: eth0\n".repeat(700));
    assert!(firewalld::parse_active_zones(&lines).truncated);
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

fn verdict_with_rule(rule: &str, port: u16) -> Verdict {
    let z = zone(&format!(
        "p\n  ports: {port}/tcp\n  rich rules: \n\t{rule}\n"
    ));
    open(&z, &Services::default(), port)
}

#[test]
fn any_rich_rule_makes_every_port_unknown() {
    // About this port, about another port or protocol, ICMP, masquerading: the approved rule in 03 is
    // "any rich rule present: warn", so none of them leaves the port open.
    for rule in [
        "rule family=\"ipv4\" source address=\"192.0.2.0/24\" port port=\"6443\" protocol=\"tcp\" drop",
        "rule port port=\"6000-6500\" protocol=\"tcp\" accept",
        "rule family=\"ipv4\" source address=\"192.0.2.9\" reject",
        "rule protocol value=\"tcp\" reject",
        "rule forward-port port=\"6443\" protocol=\"tcp\" to-port=\"8443\"",
        "rule port port=\"22\" protocol=\"tcp\" accept",
        "rule port port=\"6443\" protocol=\"udp\" accept",
        "rule family=\"ipv4\" icmp-block name=\"echo-request\"",
        "rule family=\"ipv4\" masquerade",
        "rule port port=\"six\" protocol=\"tcp\" accept",
    ] {
        assert!(
            matches!(verdict_with_rule(rule, 6443), Verdict::Unknown(_)),
            "{rule}"
        );
    }
}

#[test]
fn a_rich_rule_is_described_from_its_parts_and_never_quoted() {
    let rule = "rule family=\"ipv4\" source address=\"198.51.100.7/32\" port port=\"6443\" protocol=\"tcp\" log prefix=\"SECRET-PREFIX\" level=\"info\" audit accept";
    let Verdict::Unknown(why) = verdict_with_rule(rule, 6443) else {
        panic!("expected unknown");
    };
    assert!(
        why.contains("ipv4, source address, port 6443/tcp, accept"),
        "{why}"
    );
    for leaked in ["198.51.100.7", "SECRET-PREFIX", "info", "prefix"] {
        assert!(!why.contains(leaked), "{leaked} in {why}");
    }
    let named = "rule service name=\"bad name; $(x)\" ipset source ipset=\"my-set\" reject";
    let Verdict::Unknown(why) = verdict_with_rule(named, 6443) else {
        panic!("expected unknown");
    };
    assert!(!why.contains("my-set") && !why.contains("$("), "{why}");
}

#[test]
fn a_rich_rule_service_is_looked_up_for_the_files_to_read() {
    let z = zone("p\n  ports: 6443/tcp\n  rich rules: \n\trule service name=\"acme-api\" accept\n");
    assert!(matches!(
        open(&z, &services_with_api("6443"), 6443),
        Verdict::Unknown(_)
    ));
    assert_eq!(firewalld::service_names(&z), ["acme-api"]);
}

#[test]
fn the_recorded_rich_rule_listing_is_unknown_for_every_port() {
    let record: serde_json::Value = serde_json::from_str(RICH).expect("a record");
    let z = zone(record["stdout"].as_str().expect("stdout"));
    let none = Services::default();
    assert!(matches!(open(&z, &none, 6443), Verdict::Unknown(_)));
    assert!(matches!(open(&z, &none, 10250), Verdict::Unknown(_)));
}

#[test]
fn protocols_tcp_opens_every_tcp_port_and_udp_does_not() {
    let all = zone("p\n  protocols: tcp\n");
    assert!(matches!(
        open(&all, &Services::default(), 6443),
        Verdict::Open(_)
    ));
    let number = zone("p\n  protocols: icmp 6\n");
    assert!(matches!(
        open(&number, &Services::default(), 6443),
        Verdict::Open(_)
    ));
    let udp = zone("p\n  protocols: udp icmp\n");
    assert!(matches!(
        open(&udp, &Services::default(), 6443),
        Verdict::Closed(_)
    ));
    assert!(matches!(
        open(&zone("p\n  protocols: \n"), &Services::default(), 6443),
        Verdict::Closed(_)
    ));
}

#[test]
fn a_zone_listing_cut_by_a_limit_is_unknown_not_closed() {
    let none = Services::default();
    let too_many_words = format!("p\n  ports: {}\n", "1/udp ".repeat(3000));
    let too_many_lines = format!("p\n{}", "  masquerade: no\n".repeat(700));
    let too_many_rules = format!(
        "p\n  rich rules: \n{}",
        "\trule family=\"ipv4\" masquerade\n".repeat(101)
    );
    let long_rule = format!("p\n  rich rules: \n\trule {}\n", "x ".repeat(600));
    for text in [too_many_words, too_many_lines, too_many_rules, long_rule] {
        let z = zone(&text);
        assert!(z.incomplete.is_some());
        assert!(matches!(open(&z, &none, 6443), Verdict::Unknown(_)));
    }
    // A listing inside every limit is not marked.
    assert!(zone("p\n  ports: 6443/tcp\n").incomplete.is_none());
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
    // Four levels of includes are followed. Deeper is "unknown", not "no".
    let Cover::Unknown(why) = deep.covers("s0", 80) else {
        panic!("expected unknown");
    };
    assert!(why.contains("deeper than rdy follows"), "{why}");
    assert!(matches!(deep.covers("s5", 80), Cover::Unknown(_)));
    assert_eq!(deep.covers("s6", 80), Cover::Yes);
    assert_eq!(deep.covers("s9", 80), Cover::Yes);
    assert!(matches!(
        Services::default().covers("x", 80),
        Cover::Unknown(_)
    ));
}

fn found(xml: &str) -> Svc {
    Svc::Found(service::parse(xml))
}

#[test]
fn a_chain_of_files_that_each_include_the_next_nearly_two_thousand_times_is_walked_once() {
    // Four files of 1990 identical includes each (44 KiB) once cost 1990^4 steps.
    let fan = "<include service=\"next\"/>".repeat(1990);
    let mut chain = Services::default();
    for (name, next) in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")] {
        chain = chain.with(
            name,
            found(&format!("<service>{}</service>", fan.replace("next", next))),
        );
    }
    chain = chain.with(
        "e",
        found("<service><port protocol=\"tcp\" port=\"80\"/></service>"),
    );
    assert_eq!(chain.covers("a", 80), Cover::Yes);
    assert_eq!(chain.covers("a", 81), Cover::No);
    assert_eq!(chain.visits("a"), 5);
}

#[test]
fn a_service_with_many_different_includes_is_unknown_and_the_walk_stays_bounded() {
    let many: String = (0..40)
        .map(|n| format!("<include service=\"i{n}\"/>"))
        .collect();
    let mut services =
        Services::default().with("root", found(&format!("<service>{many}</service>")));
    for n in 0..40 {
        services = services.with(&format!("i{n}"), found("<service/>"));
    }
    let Cover::Unknown(why) = services.covers("root", 80) else {
        panic!("expected unknown");
    };
    assert!(why.contains("more services than rdy follows"), "{why}");
    // The walk stops at the root, whose includes are in doubt.
    assert_eq!(services.visits("root"), 1);
}

#[test]
fn a_walk_over_a_full_set_of_services_never_exceeds_its_bound() {
    // 32 services (the most one run reads), each including 16 others, some of which loop back.
    let mut services = Services::default();
    for n in 0..32 {
        let includes: String = (1..=16)
            .map(|k| format!("<include service=\"s{}\"/>", (n + k) % 40))
            .collect();
        services = services.with(
            &format!("s{n}"),
            found(&format!("<service>{includes}</service>")),
        );
    }
    assert!(services.visits("s0") <= 1 + 32 * 16);
}

#[test]
fn a_service_limited_by_destination_still_walks_its_includes() {
    let services = Services::default()
        .with(
            "l",
            found(
                "<service><port protocol=\"tcp\" port=\"80\"/><destination ipv4=\"192.0.2.1\"/><include service=\"y\"/></service>",
            ),
        )
        .with(
            "y",
            found("<service><port protocol=\"tcp\" port=\"80\"/></service>"),
        );
    assert_eq!(services.covers("l", 80), Cover::Yes);
}

#[test]
fn the_depth_cap_is_not_hit_when_every_include_was_already_seen() {
    // s0 -> s1 -> s2 -> s3 -> s4, and s4 includes s0 again. No service is cut off.
    let mut ring = Services::default();
    for n in 0..5 {
        ring = ring.with(
            &format!("s{n}"),
            found(&format!(
                "<service><include service=\"s{}\"/></service>",
                (n + 1) % 5
            )),
        );
    }
    assert_eq!(ring.covers("s0", 80), Cover::No);
}

#[test]
fn merged_port_ranges_are_searched_by_halving() {
    let mut ranges = vec![
        range("100-200"),
        range("201-300"),
        range("50"),
        range("150-160"),
        range("1000"),
    ];
    PortRange::merge(&mut ranges);
    assert_eq!(ranges.len(), 3);
    for (port, want) in [
        (49, false),
        (50, true),
        (51, false),
        (99, false),
        (100, true),
        (300, true),
        (301, false),
        (1000, true),
        (1001, false),
    ] {
        assert_eq!(PortRange::any_covers(&ranges, port), want, "{port}");
    }
    assert!(!PortRange::any_covers(&[], 80));
    let mut all = vec![PortRange::all(), range("65535")];
    PortRange::merge(&mut all);
    assert!(PortRange::any_covers(&all, 65535));
}

#[test]
fn the_same_answer_comes_from_any_order_of_includes() {
    let yes = "<service><port protocol=\"tcp\" port=\"80\"/></service>";
    let limited =
        "<service><port protocol=\"tcp\" port=\"80\"/><destination ipv4=\"192.0.2.1\"/></service>";
    for (first, second) in [("y", "l"), ("l", "y")] {
        let services = Services::default()
            .with(
                "r",
                found(&format!(
                    "<service><include service=\"{first}\"/><include service=\"{second}\"/></service>"
                )),
            )
            .with("y", found(yes))
            .with("l", found(limited));
        assert_eq!(services.covers("r", 80), Cover::Yes, "{first} {second}");
    }
}

#[test]
fn a_service_file_that_a_limit_or_odd_text_cuts_is_unknown_even_when_it_names_the_port() {
    let tags = "<port protocol=\"tcp\" port=\"80\"/>".repeat(10_000);
    let cases = [
        ("too many tags", tags),
        (
            "an unreadable tag",
            "<service><port protocol=\"tcp\" port=\"80\"/><port protocol=tcp/></service>".to_owned(),
        ),
        (
            "a tag cut off",
            "<service><port protocol=\"tcp\" port=\"80\"/><desc".to_owned(),
        ),
        (
            "an unfinished comment",
            "<service><port protocol=\"tcp\" port=\"80\"/><!-- no end".to_owned(),
        ),
        (
            "a DOCTYPE",
            "<!DOCTYPE service [<!ENTITY x \"y\">]><service><port protocol=\"tcp\" port=\"80\"/></service>"
                .to_owned(),
        ),
        (
            "a file over 64 KiB",
            format!(
                "<service><port protocol=\"tcp\" port=\"80\"/><!--{}--></service>",
                "x".repeat(70_000)
            ),
        ),
    ];
    for (what, xml) in cases {
        let services = Services::default().with("s", found(&xml));
        assert!(
            matches!(services.covers("s", 80), Cover::Unknown(_)),
            "{what}"
        );
        assert!(
            matches!(services.covers("s", 81), Cover::Unknown(_)),
            "{what}"
        );
    }
}

#[test]
fn a_port_tag_inside_a_cdata_section_is_text_and_not_a_port() {
    let xml = "<service><description><![CDATA[ a > b <port protocol=\"tcp\" port=\"6443\"/> ]]></description></service>";
    let services = Services::default().with("s", found(xml));
    assert_eq!(services.covers("s", 6443), Cover::No);
    let open_after = "<service><![CDATA[ <port protocol=\"tcp\" port=\"1\"/> ]]><port protocol=\"tcp\" port=\"6443\"/></service>";
    let services = Services::default().with("s", found(open_after));
    assert_eq!(services.covers("s", 6443), Cover::Yes);
    assert_eq!(services.covers("s", 1), Cover::No);
    let unended = Services::default().with("s", found("<service><![CDATA[ no end"));
    assert!(matches!(unended.covers("s", 1), Cover::Unknown(_)));
}

#[test]
fn has_tag_finds_a_tag_and_says_when_it_could_not_look() {
    assert_eq!(
        service::has_tag("<direct><rule ipv=\"ipv4\"/></direct>", &["rule"]),
        Ok(true)
    );
    assert_eq!(
        service::has_tag("<?xml version='1.0'?><direct/>", &["rule"]),
        Ok(false)
    );
    assert_eq!(
        service::has_tag(
            "<direct><passthrough ipv=\"ipv4\">-A INPUT -j DROP</passthrough></direct>",
            &["rule", "passthrough"]
        ),
        Ok(true)
    );
    assert!(service::has_tag("<direct><rule", &["rule"]).is_err());
    assert!(service::has_tag("<direct><!-- ", &["rule"]).is_err());
}

#[test]
fn service_file_paths_use_forward_slashes_on_every_os() {
    // Built as text, so the Windows leg judges the same Linux path as the Linux leg does.
    assert_eq!(
        service::service_path("/etc/firewalld/services", "ssh"),
        "/etc/firewalld/services/ssh.xml"
    );
    assert!(!service::service_path("/usr/lib/firewalld/services", "a-b").contains('\\'));
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
    // The file was cut at 2000 tags, so what it says is not trusted either way.
    assert!(matches!(one.covers("s", 80), Cover::Unknown(_)));
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
    // A tuple that does not parse is unknown, not skipped.
    assert!(matches!(
        v("allow tcp bogus 0.0.0.0/0 any 0.0.0.0/0 in", 6443),
        Verdict::Unknown(_)
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
    // An allow for another interface may be where the traffic arrives: unknown, not closed.
    assert!(matches!(
        ufw_verdict(&[on_eth0], Policy::Drop, Some("eth1"), 6443),
        Verdict::Unknown(_)
    ));
    assert!(matches!(
        ufw_verdict(&[on_eth0], Policy::Drop, None, 6443),
        Verdict::Unknown(_)
    ));
    // A deny for another interface does not touch this one.
    let deny_eth1 = "deny tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in_eth1";
    assert!(matches!(
        ufw_verdict(&[deny_eth1], Policy::Accept, Some("eth0"), 6443),
        Verdict::Open(_)
    ));
    // An unrestricted allow after the other-interface allow still decides.
    assert!(matches!(
        ufw_verdict(&[on_eth0, ALLOW], Policy::Drop, Some("eth1"), 6443),
        Verdict::Open(_)
    ));
}

#[test]
fn ufw_tuples_with_a_comment_or_a_log_action_are_read() {
    let v = |t: &str| ufw_verdict(&[t], Policy::Drop, None, 6443);
    for open in [
        "allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in comment=6b3873",
        "allow_log tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in",
        "allow_log-all tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in",
        "allow_log-all tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in comment=6b3873",
        "limit_log tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in",
    ] {
        assert!(matches!(v(open), Verdict::Open(_)), "{open}");
    }
    for closed in [
        "deny_log tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in comment=6b3873",
        "reject_log-all tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in",
    ] {
        assert!(matches!(v(closed), Verdict::Closed(_)), "{closed}");
    }
    // Not about inbound TCP: left out, and the default policy decides.
    for elsewhere in [
        "route:allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1",
        "allow_log udp 6443 0.0.0.0/0 any 0.0.0.0/0 in comment=6b3873",
        "allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 out_eth0",
    ] {
        assert!(matches!(v(elsewhere), Verdict::Closed(_)), "{elsewhere}");
    }
}

#[test]
fn a_ufw_tuple_that_does_not_parse_makes_the_answer_unknown() {
    for bad in [
        "allow tcp bogus 0.0.0.0/0 any 0.0.0.0/0 in",
        "allow tcp 6443 0.0.0.0/0 any",
        "frobnicate tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in",
        "allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 sideways",
        "allow sctp 6443 0.0.0.0/0 any 0.0.0.0/0 in",
        "",
    ] {
        let v = ufw_verdict(&[bad], Policy::Drop, None, 6443);
        assert!(matches!(v, Verdict::Unknown(_)), "{bad:?}: {v:?}");
    }
    // A decisive rule before the bad line still decides. After it, the bad line wins.
    let bad = "allow tcp bogus 0.0.0.0/0 any 0.0.0.0/0 in";
    assert!(matches!(
        ufw_verdict(&[ALLOW, bad], Policy::Drop, None, 6443),
        Verdict::Open(_)
    ));
    assert!(matches!(
        ufw_verdict(&[bad, ALLOW], Policy::Drop, None, 6443),
        Verdict::Unknown(_)
    ));
}

#[test]
fn a_ufw_rules_file_cut_by_a_limit_is_unknown_not_closed() {
    let rule = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n";
    let many = rule.repeat(4097);
    let rules = ufw::parse_user_rules(&many);
    assert!(matches!(
        ufw::judge(&rules, Policy::Drop, None, 6443),
        Verdict::Unknown(_)
    ));
    let long = format!("{}{}", "# x\n".repeat(20_000), rule);
    let rules = ufw::parse_user_rules(&long);
    assert!(matches!(
        ufw::judge(&rules, Policy::Drop, None, 6443),
        Verdict::Unknown(_)
    ));
    // A file inside the limits is read in full.
    let ok = rule.repeat(4096);
    assert!(matches!(
        ufw::judge(&ufw::parse_user_rules(&ok), Policy::Drop, None, 6443),
        Verdict::Closed(_)
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
