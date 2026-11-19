//! Tests of `Probe::nameserver_exchange` (M1-155).
//!
//! The policy tests run on the replay backend with scripted DNS servers. The Azure door and the refused
//! ranges are tested with the server registered at the refused address too, so a call that reached the
//! backend would be seen (`reached`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rdy_spec::Target;
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::Value;

use super::*;
use crate::check::{CheckInfo, CheckMeta, OsSupport, Support};
use crate::family::HostSet;
use crate::probe::net::Route;
use crate::probe::replay::{DnsScript, Replay};
use crate::probe::{ProbeHub, RULE_NO_NETWORK};
use crate::redact::{Redactor, TagKey};

const META: CheckMeta = CheckMeta {
    title: "Fixture check",
    remediation: "Nothing to fix. This check is a test double.",
};

const ALL_OS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

macro_rules! info {
    ($peers:expr) => {{
        static INFO: CheckInfo = CheckInfo {
            id: "net.dns",
            family: "net",
            summary: "A fixture check.",
            meta: META,
            needs: &[],
            wants: &[],
            default_timeout: None,
            os: ALL_OS,
            reads: &[],
            statfs: &[],
            env: &[],
            commands: &[],
            peers: $peers,
        };
        &INFO
    }};
}

fn resolver() -> &'static CheckInfo {
    info!(&[PeerClass::SystemResolver, PeerClass::SpecHosts])
}

/// The same check with the proxy class too.
fn resolver_and_proxy() -> &'static CheckInfo {
    info!(&[
        PeerClass::SystemResolver,
        PeerClass::SpecHosts,
        PeerClass::Proxy
    ])
}

/// A check that may query nameservers and has no right to the spec host names.
fn resolver_only() -> &'static CheckInfo {
    info!(&[PeerClass::SystemResolver])
}

fn spec_hosts_only() -> &'static CheckInfo {
    info!(&[PeerClass::SpecHosts, PeerClass::NtpServers])
}

fn hub(replay: Replay, network: bool) -> ProbeHub {
    let hub = ProbeHub::new(Arc::new(replay), Redactor::new(TagKey::fixed([3; 32])));
    hub.set_network(network);
    hub
}

/// A probe with no spec hosts.
fn bare_probe(hub: &ProbeHub, info: &'static CheckInfo, os: Os) -> Probe {
    hub.check_probe(info.id, os, Some(info))
}

/// A probe whose check has the spec hosts the tests query for.
fn probe(hub: &ProbeHub, info: &'static CheckInfo, os: Os) -> Probe {
    let probe = bare_probe(hub, info, os);
    let hosts = ["a.example:53", "db.corp.example:443"].map(|t| Target::parse(t).expect("target"));
    assert!(probe.permit_hosts(HostSet::new(hosts)));
    probe
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

/// A query for `name`, type `rtype`.
fn query(name: &str, rtype: u16) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).expect("short label"));
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&rtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

fn resolv(lines: &str) -> Replay {
    Replay::new().file("/etc/resolv.conf", lines)
}

fn entries(hub: &ProbeHub, kind: ActionKind) -> Vec<Action> {
    hub.action_log()
        .actions
        .into_iter()
        .filter(|a| a.kind == kind)
        .collect()
}

fn denied_rule(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A server that counts the queries it sees and answers `reply`.
fn counting(replay: Replay, at: &str, reply: &'static [u8]) -> (Replay, Arc<AtomicUsize>) {
    let reached = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&reached);
    let replay = replay.dns_server(addr(at), move |_, _| {
        seen.fetch_add(1, Ordering::SeqCst);
        DnsScript::Answer(reply.to_vec())
    });
    (replay, reached)
}

#[test]
fn the_list_parser_reads_nameserver_lines_only() {
    let text = b"# comment\n; other\nsearch corp.example\nnameserver 10.0.0.2\n\
nameserver\nnameservers 1.1.1.1\n  nameserver\t2001:db8::53  # trailing\n\
nameserver fe80::1%eth0\nnameserver not-an-address\nnameserver 10.0.0.9\n";
    let list = parse_nameservers(text);
    let want: Vec<IpAddr> = ["10.0.0.2", "2001:db8::53", "fe80::1"]
        .iter()
        .map(|t| t.parse().expect("ip"))
        .collect();
    assert_eq!(list, want, "three at most, a zone id cut, junk skipped");
}

#[test]
fn the_query_parser_takes_one_plain_question() {
    let q = parse_query(&query("Db.Corp.Example", 28)).expect("a query");
    assert_eq!(q.name, "db.corp.example");
    assert_eq!(q.rtype, "AAAA");
    for (code, text) in [(1, "A"), (28, "AAAA"), (5, "CNAME"), (6, "SOA")] {
        let q = parse_query(&query("x_y-1.example", code)).expect("a query");
        assert_eq!(q.rtype, text);
        assert_eq!(q.name, "x_y-1.example");
    }
}

/// A query with `tail` after the question and ARCOUNT `arcount`.
fn with_tail(arcount: u8, tail: &[u8]) -> Vec<u8> {
    let mut q = query("a.example", 1);
    q[11] = arcount;
    q.extend_from_slice(tail);
    q
}

/// A bare OPT record: root name, type 41, class 1232, TTL 0, RDLEN 0.
const OPT: [u8; 11] = [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0];

#[test]
fn the_query_parser_takes_a_bare_opt_record_and_nothing_else_after_the_question() {
    assert!(parse_query(&with_tail(0, &[])).is_some());
    assert!(parse_query(&with_tail(1, &OPT)).is_some(), "a bare OPT");
    let mut named = OPT;
    named[0] = 1; // a label start instead of the root
    let mut other_type = OPT;
    other_type[2] = 42;
    let mut rdata = OPT.to_vec();
    rdata[10] = 4;
    rdata.extend_from_slice(b"data");
    let mut rdlen_no_data = OPT;
    rdlen_no_data[10] = 4;
    let mut do_bit = OPT;
    do_bit[7] = 0x80;
    assert!(parse_query(&with_tail(1, &do_bit)).is_some(), "the DO bit");
    for size in [512_u16, 4096] {
        let mut ok = OPT;
        ok[3..5].copy_from_slice(&size.to_be_bytes());
        assert!(parse_query(&with_tail(1, &ok)).is_some(), "size {size}");
    }
    let opt_with = |at: usize, value: u8| {
        let mut r = OPT;
        r[at] = value;
        with_tail(1, &r)
    };
    let size_of = |size: u16| {
        let mut r = OPT;
        r[3..5].copy_from_slice(&size.to_be_bytes());
        with_tail(1, &r)
    };
    for (name, payload) in [
        ("an extended RCODE", opt_with(5, 1)),
        ("an EDNS version", opt_with(6, 1)),
        ("a Z bit", opt_with(7, 0x01)),
        ("a Z bit in the high flag byte", opt_with(7, 0x40)),
        ("flag byte two", opt_with(8, 1)),
        ("a size of 511", size_of(511)),
        ("a size of 4097", size_of(4097)),
        ("a size of 0", size_of(0)),
        ("a size of 65535", size_of(65535)),
        ("one byte after the question", with_tail(0, &[0])),
        ("text after the question", with_tail(0, b"exfil")),
        ("an OPT record with ARCOUNT 0", with_tail(0, &OPT)),
        ("ARCOUNT 1 and no record", with_tail(1, &[])),
        ("a cut OPT record", with_tail(1, &OPT[..10])),
        (
            "a byte after the OPT record",
            with_tail(1, &[&OPT[..], &[0]].concat()),
        ),
        ("an OPT record with a name", with_tail(1, &named)),
        ("a record that is not OPT", with_tail(1, &other_type)),
        ("an OPT record with RDATA", with_tail(1, &rdata)),
        ("an RDLEN with no RDATA", with_tail(1, &rdlen_no_data)),
    ] {
        assert!(parse_query(&payload).is_none(), "{name} must be refused");
    }
}

#[test]
fn the_query_parser_takes_only_four_types_and_the_internet_class() {
    for code in [2_u16, 12, 15, 16, 33, 41, 251, 252, 255, 4242, 0] {
        assert!(
            parse_query(&query("a.example", code)).is_none(),
            "type {code} must be refused"
        );
    }
    for class in [0_u8, 2, 3, 4, 255] {
        let mut q = query("a.example", 1);
        let last = q.len() - 1;
        q[last] = class;
        assert!(parse_query(&q).is_none(), "class {class} must be refused");
    }
    let mut high = query("a.example", 1);
    let at = high.len() - 2;
    high[at] = 1; // class 0x0101
    assert!(parse_query(&high).is_none());
}

#[test]
fn the_query_parser_refuses_a_name_byte_that_is_not_a_letter_digit_hyphen_or_underscore() {
    for byte in [
        b' ', b'?', b'/', b'\\', b'+', b'=', b'%', 0, 0x7f, 0x80, 0xff, b'*',
    ] {
        let mut q = query("aaaa.example", 1);
        q[13 + 1] = byte;
        assert!(
            parse_query(&q).is_none(),
            "byte {byte:#04x} must be refused"
        );
    }
    // A dot inside a label cannot be written: the dot is the length byte. The root name is refused too.
    let mut root = query("a.example", 1);
    root.splice(12..22, [0]);
    assert!(
        parse_query(&root).is_none(),
        "the root name must be refused"
    );
}

#[test]
fn the_query_parser_refuses_everything_else() {
    let good = query("a.example", 1);
    let mut response = good.clone();
    response[2] |= 0x80;
    let mut opcode = good.clone();
    opcode[2] |= 0x28; // opcode 5, UPDATE
    let mut two = good.clone();
    two[5] = 2;
    let mut answers = good.clone();
    answers[7] = 1;
    let mut extra = good.clone();
    extra[11] = 2;
    let mut trailing = good.clone();
    trailing.push(0);
    let mut pointer = good.clone();
    pointer[12] = 0xc0;
    let mut cut = good.clone();
    cut.truncate(good.len() - 1);
    let long_label = {
        let mut q = good.clone();
        q[12] = 64;
        q
    };
    let long = {
        let mut q = good.clone();
        q.resize(513, 0);
        q
    };
    for (name, payload) in [
        ("empty", Vec::new()),
        ("header only", good[..11].to_vec()),
        ("a response", response),
        ("an update", opcode),
        ("two questions", two),
        ("answer records", answers),
        ("two additional records", extra),
        ("a byte after the question", trailing),
        ("a compression pointer", pointer),
        ("a cut question", cut),
        ("a label of 64", long_label),
        ("over 512 bytes", long),
        ("a TCP frame", [&[0, 20][..], &good[..]].concat()),
    ] {
        assert!(parse_query(&payload).is_none(), "{name} must be refused");
    }
}

#[tokio::test]
async fn a_query_goes_to_the_listed_nameserver_over_both_transports() {
    let replay = resolv("nameserver 10.0.0.2\nnameserver 10.0.0.3\n").dns_server(
        addr("10.0.0.2:53"),
        |q, transport| {
            let mut reply = q.to_vec();
            reply[2] |= 0x80;
            reply.push(match transport {
                DnsTransport::Udp => b'u',
                DnsTransport::Tcp => b't',
            });
            DnsScript::Answer(reply)
        },
    );
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    assert_eq!(probe.nameserver_count().await.expect("count"), 2);
    let q = query("db.corp.example", 1);
    let udp = probe
        .nameserver_exchange(0, &q, DnsTransport::Udp)
        .await
        .expect("udp");
    let tcp = probe
        .nameserver_exchange(0, &q, DnsTransport::Tcp)
        .await
        .expect("tcp");
    assert_eq!(udp.bytes.last(), Some(&b'u'));
    assert_eq!(tcp.bytes.last(), Some(&b't'));
    assert_eq!(udp.addr, "10.0.0.2".parse::<IpAddr>().expect("ip"));

    let dns = entries(&hub, ActionKind::Dns);
    assert_eq!(dns.len(), 2, "one entry per call: {dns:?}");
    assert_eq!(dns[0].outcome, ActionOutcome::Ok);
    assert_eq!(dns[0].fields["server"], Value::from("10.0.0.2"));
    assert_eq!(dns[0].fields["name"], Value::from("db.corp.example"));
    assert_eq!(dns[0].fields["rtype"], Value::from("A"));
    assert_eq!(dns[0].fields["proto"], Value::from("udp"));
    assert_eq!(dns[0].fields["bytes"], Value::from(q.len() + 1));
    assert!(dns[1].fields.get("proto").is_none(), "TCP has no proto");
    let reads = entries(&hub, ActionKind::Read);
    assert_eq!(reads.len(), 1, "the list is read once per check: {reads:?}");
    // The payload and the reply are in no entry.
    let all = serde_json::to_string(&hub.action_log().actions).expect("json");
    assert!(!all.contains("1234"), "no payload bytes in the log");
}

#[tokio::test]
async fn the_check_cannot_name_an_address_or_a_port() {
    // A server on 10.0.0.2 at a port other than 53 is never reached, and one at an address that is not
    // in the OS list is never reached. There is no parameter that could ask for either.
    let (replay, reached) = counting(resolv("nameserver 10.0.0.2\n"), "10.0.0.2:5353", b"x");
    let (replay, other) = counting(replay, "10.0.0.99:53", b"x");
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    let error = probe
        .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Udp)
        .await
        .expect_err("nothing at 10.0.0.2:53");
    assert!(matches!(error, ProbeError::ConnectionRefused), "{error:?}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    assert_eq!(other.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn only_a_check_that_declares_the_system_resolver_may_ask() {
    let (replay, reached) = counting(resolv("nameserver 10.0.0.2\n"), "10.0.0.2:53", b"x");
    let hub = hub(replay, true);
    let probe = probe(&hub, spec_hosts_only(), Os::Linux);
    let error = probe
        .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Udp)
        .await
        .expect_err("undeclared");
    assert_eq!(denied_rule(&error), RULE_NS_UNDECLARED);
    let error = probe.nameserver_count().await.expect_err("undeclared");
    assert_eq!(denied_rule(&error), RULE_NS_UNDECLARED);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    assert!(
        entries(&hub, ActionKind::Read)
            .iter()
            .all(|a| a.outcome == ActionOutcome::Denied),
        "the list was not read"
    );
    let first = &entries(&hub, ActionKind::Dns)[0];
    assert_eq!(first.outcome, ActionOutcome::Denied);
    assert_eq!(first.fields["rule"], Value::from(RULE_NS_UNDECLARED));
}

#[tokio::test]
async fn a_probe_with_no_manifest_may_not_ask() {
    let (replay, reached) = counting(resolv("nameserver 10.0.0.2\n"), "10.0.0.2:53", b"x");
    let hub = hub(replay, true);
    let probe = hub.check_probe("net.dns", Os::Linux, None);
    let error = probe
        .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Tcp)
        .await
        .expect_err("no manifest");
    assert_eq!(denied_rule(&error), RULE_NS_UNDECLARED);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn no_network_refuses_before_anything_is_read() {
    let (replay, reached) = counting(resolv("nameserver 10.0.0.2\n"), "10.0.0.2:53", b"x");
    let hub = hub(replay, false);
    let probe = probe(&hub, resolver(), Os::Linux);
    let error = probe
        .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Udp)
        .await
        .expect_err("offline");
    assert_eq!(denied_rule(&error), RULE_NO_NETWORK);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    assert!(entries(&hub, ActionKind::Read).is_empty());
}

#[tokio::test]
async fn a_payload_that_is_not_one_query_never_reaches_the_server() {
    let (replay, reached) = counting(resolv("nameserver 10.0.0.2\n"), "10.0.0.2:53", b"x");
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    for payload in [
        vec![],
        vec![0_u8; 513],
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        vec![0x1b; 48],
    ] {
        for transport in [DnsTransport::Udp, DnsTransport::Tcp] {
            let error = probe
                .nameserver_exchange(0, &payload, transport)
                .await
                .expect_err("not a query");
            assert_eq!(denied_rule(&error), RULE_NS_PAYLOAD);
        }
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_index_past_the_list_is_refused() {
    let hub = hub(resolv("nameserver 10.0.0.2\n"), true);
    let probe = probe(&hub, resolver(), Os::Linux);
    let error = probe
        .nameserver_exchange(1, &query("a.example", 1), DnsTransport::Udp)
        .await
        .expect_err("past the end");
    assert_eq!(denied_rule(&error), RULE_NS_INDEX);
}

#[tokio::test]
async fn every_refused_range_is_refused_and_the_server_is_never_reached() {
    // The first is the GCE metadata server, which some images list as the nameserver.
    for text in [
        "169.254.169.254",
        "169.254.169.123",
        "169.254.0.1",
        "fe80::1%eth0",
        "fe80::1",
        "fd00:ec2::254",
        "fd20:ce::254",
        "100.100.100.200",
        "0.0.0.0",
        "::",
        "224.0.0.251",
        "ff02::fb",
        "255.255.255.255",
        "::ffff:169.254.169.254",
        "::169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        // The Azure address in a form that is not the exact IPv4 address.
        "::ffff:168.63.129.16",
        "::168.63.129.16",
        "64:ff9b::a83f:8110",
    ] {
        let bare: IpAddr = text.split('%').next().expect("addr").parse().expect("ip");
        let reached = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&reached);
        let replay = resolv(&format!("nameserver {text}\n")).dns_server(
            SocketAddr::new(bare, 53),
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                DnsScript::Answer(vec![0; 12])
            },
        );
        let hub = hub(replay, true);
        let probe = probe(&hub, resolver(), Os::Linux);
        for transport in [DnsTransport::Udp, DnsTransport::Tcp] {
            let error = probe
                .nameserver_exchange(0, &query("a.example", 1), transport)
                .await
                .expect_err(text);
            assert_eq!(denied_rule(&error), RULE_NS_ADDRESS, "{text}");
            assert!(error.to_string().contains("nameserver 0"), "{error}");
        }
        assert_eq!(reached.load(Ordering::SeqCst), 0, "{text} was reached");
    }
    assert_eq!(RULE_NS_ADDRESS, "nameserver in a refused range");
}

#[tokio::test]
async fn the_azure_address_from_the_os_list_is_reached_on_port_53() {
    let (replay, reached) = counting(
        resolv("nameserver 168.63.129.16\n"),
        "168.63.129.16:53",
        b"azure",
    );
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    for transport in [DnsTransport::Udp, DnsTransport::Tcp] {
        let reply = probe
            .nameserver_exchange(0, &query("a.example", 1), transport)
            .await
            .expect("the Azure door is open");
        assert_eq!(reply.bytes, b"azure");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 2);
    let dns = entries(&hub, ActionKind::Dns);
    assert_eq!(dns[0].fields["server"], Value::from("168.63.129.16"));
}

#[tokio::test]
async fn the_azure_address_stays_refused_to_a_spec_host_on_every_port_and_form() {
    // A time server check and a TCP caller, both with the address as a spec host. Ports 53 (the door is
    // not theirs), 80 and 32526 (the WireServer), and the forms a translator could carry.
    let udp_info = spec_hosts_only();
    for host in [
        "168.63.129.16",
        "[::ffff:a83f:8110]",
        "[::a83f:8110]",
        "[64:ff9b::a83f:8110]",
    ] {
        for port in [53, 80, 32526, 123] {
            let text = format!("{host}:{port}");
            // A form that never parses as a target is refused one step earlier.
            let Ok(target) = Target::parse(&text) else {
                assert_ne!(host, "168.63.129.16", "the plain address must parse");
                continue;
            };
            let (replay, reached) = counting(Replay::new(), &format!("168.63.129.16:{port}"), b"x");
            let hub = hub(replay, true);
            let probe = bare_probe(&hub, udp_info, Os::Linux);
            assert!(probe.permit_hosts(HostSet::new([target.clone()])));
            let error = probe
                .udp_exchange(&target, &[0x1b; 48], 48)
                .await
                .expect_err(&text);
            assert!(
                matches!(error, ProbeError::Denied { .. }),
                "{text}: {error:?}"
            );
            let report = probe.tcp(&target, Route::Direct).await;
            assert!(
                matches!(report, Err(ProbeError::Denied { .. })),
                "{text}: {report:?}"
            );
            assert_eq!(reached.load(Ordering::SeqCst), 0, "{text} was reached");
        }
    }
}

#[tokio::test]
async fn a_spec_host_cannot_make_the_azure_address_a_nameserver() {
    // The list holds a public nameserver. A spec host at the Azure address does not change the list.
    let (replay, azure) = counting(resolv("nameserver 10.0.0.2\n"), "168.63.129.16:53", b"x");
    let hub = hub(replay, true);
    let probe = bare_probe(&hub, resolver(), Os::Linux);
    let azure_host = Target::parse("168.63.129.16:53").expect("target");
    let own = Target::parse("a.example:53").expect("target");
    assert!(probe.permit_hosts(HostSet::new([azure_host, own])));
    let error = probe
        .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Udp)
        .await
        .expect_err("10.0.0.2 has no server");
    assert!(matches!(error, ProbeError::ConnectionRefused), "{error:?}");
    assert_eq!(azure.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn replies_are_cut_at_the_cap_and_flagged() {
    let replay = resolv("nameserver 10.0.0.2\n").dns_server(addr("10.0.0.2:53"), |_, _| {
        DnsScript::Answer(vec![7; 20_000])
    });
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    let q = query("a.example", 1);
    let udp = probe
        .nameserver_exchange(0, &q, DnsTransport::Udp)
        .await
        .expect("udp");
    assert_eq!(udp.bytes.len(), MAX_NAMESERVER_UDP_REPLY);
    assert!(udp.truncated);
    let tcp = probe
        .nameserver_exchange(0, &q, DnsTransport::Tcp)
        .await
        .expect("tcp");
    assert_eq!(tcp.bytes.len(), MAX_NAMESERVER_TCP_REPLY);
    assert!(tcp.truncated);
}

#[tokio::test(start_paused = true)]
async fn a_silent_server_times_out_and_a_slow_one_is_measured() {
    let replay = resolv("nameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 10.0.0.4\n")
        .dns_silent(addr("10.0.0.2:53"))
        .dns_server(addr("10.0.0.3:53"), |_, _| DnsScript::Answer(vec![1; 12]))
        .dns_delay(addr("10.0.0.3:53"), Duration::from_secs(2))
        .dns_server(addr("10.0.0.4:53"), |_, _| DnsScript::Answer(vec![1; 12]))
        .dns_delay(addr("10.0.0.4:53"), Duration::from_secs(5));
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    let q = query("a.example", 1);
    let started = tokio::time::Instant::now();
    let error = probe
        .nameserver_exchange(0, &q, DnsTransport::Udp)
        .await
        .expect_err("silent");
    assert!(matches!(error, ProbeError::Timeout), "{error:?}");
    // The call takes the time it spent reading the nameserver list off the limit, and it measures that
    // with the real clock. Under the paused clock a slow runner can spend a few real milliseconds there,
    // so the silent server is cut a little before the full limit, never after it.
    let elapsed = started.elapsed();
    assert!(
        elapsed <= NAMESERVER_TIMEOUT && elapsed >= NAMESERVER_TIMEOUT - Duration::from_millis(100),
        "{elapsed:?}"
    );
    let started = tokio::time::Instant::now();
    probe
        .nameserver_exchange(1, &q, DnsTransport::Udp)
        .await
        .expect("slow but inside the limit");
    assert_eq!(started.elapsed(), Duration::from_secs(2));
    let error = probe
        .nameserver_exchange(2, &q, DnsTransport::Tcp)
        .await
        .expect_err("past the limit");
    assert!(matches!(error, ProbeError::Timeout), "{error:?}");
    let dns = entries(&hub, ActionKind::Dns);
    assert_eq!(dns[0].outcome, ActionOutcome::Timeout);
}

#[tokio::test]
async fn a_udp_only_server_refuses_tcp() {
    let replay = resolv("nameserver 10.0.0.2\n").dns_server(addr("10.0.0.2:53"), |_, t| match t {
        DnsTransport::Udp => DnsScript::Answer(vec![1; 12]),
        DnsTransport::Tcp => DnsScript::Refused,
    });
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    let q = query("a.example", 1);
    probe
        .nameserver_exchange(0, &q, DnsTransport::Udp)
        .await
        .expect("udp");
    let error = probe
        .nameserver_exchange(0, &q, DnsTransport::Tcp)
        .await
        .expect_err("tcp refused");
    assert!(matches!(error, ProbeError::ConnectionRefused), "{error:?}");
}

#[tokio::test]
async fn a_missing_list_and_an_os_without_a_source_are_reported_not_guessed() {
    let (replay, reached) = counting(Replay::new(), "10.0.0.2:53", b"x");
    let hub1 = hub(replay, true);
    let error = probe(&hub1, resolver(), Os::Linux)
        .nameserver_count()
        .await
        .expect_err("no resolv.conf");
    assert!(matches!(error, ProbeError::NotFound), "{error:?}");

    let (replay, reached2) = counting(resolv("nameserver 10.0.0.2\n"), "10.0.0.2:53", b"x");
    let hub2 = hub(replay, true);
    for os in [Os::Windows, Os::Macos] {
        let error = probe(&hub2, resolver(), os)
            .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Udp)
            .await
            .expect_err("no source");
        assert!(matches!(error, ProbeError::Unsupported(_)), "{error:?}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    assert_eq!(reached2.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_check_s_reads_do_not_widen_the_list_policy() {
    // The facade reads its own list. A check with no `reads` still gets it, and the guard it uses holds
    // only the three resolver files: a list in another place is not read.
    let hub = hub(
        Replay::new().file("/etc/other.conf", "nameserver 10.0.0.2\n"),
        true,
    );
    let error = probe(&hub, resolver(), Os::Linux)
        .nameserver_count()
        .await
        .expect_err("/etc/resolv.conf is missing");
    assert!(matches!(error, ProbeError::NotFound), "{error:?}");
    assert_eq!(NAMESERVER_FILES.len(), 6);
}

/// A server that answers `x` at 10.0.0.2:53, with the list that names it.
fn one_server() -> (Replay, Arc<AtomicUsize>) {
    counting(resolv("nameserver 10.0.0.2\n"), "10.0.0.2:53", b"x")
}

#[tokio::test]
async fn a_name_that_is_not_a_spec_host_is_refused_and_never_sent() {
    // The payload is a well formed query for a name the check does not own, as a data carrying name
    // would be: base32 text under a domain the signed spec never listed.
    let (replay, reached) = one_server();
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    for name in [
        "mzxw6ytboi.attacker.example",
        "example",
        "b.example",
        "a.example.evil.example",
        "sub.a.example",
    ] {
        for transport in [DnsTransport::Udp, DnsTransport::Tcp] {
            let error = probe
                .nameserver_exchange(0, &query(name, 1), transport)
                .await
                .expect_err(name);
            assert_eq!(denied_rule(&error), RULE_NS_NAME, "{name}");
        }
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    // The refusals are logged without the server: the list was not even read.
    assert!(entries(&hub, ActionKind::Read).is_empty());
    let dns = entries(&hub, ActionKind::Dns);
    assert!(dns.iter().all(|a| a.outcome == ActionOutcome::Denied));
}

#[tokio::test]
async fn a_name_is_matched_whatever_its_case_and_the_spec_host_is_sent() {
    let (replay, reached) = one_server();
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    probe
        .nameserver_exchange(0, &query("A.Example", 28), DnsTransport::Udp)
        .await
        .expect("a spec host in another case");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_check_without_the_spec_hosts_class_may_not_ask_for_a_spec_host_name() {
    let (replay, reached) = one_server();
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver_only(), Os::Linux);
    let error = probe
        .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Udp)
        .await
        .expect_err("SpecHosts not declared");
    assert_eq!(denied_rule(&error), RULE_NS_NAME);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_configured_proxy_name_may_be_asked_for_and_only_with_the_proxy_class() {
    for (info, proxy_set, ok) in [
        (resolver_and_proxy(), true, true),
        (resolver(), true, false),
        (resolver_and_proxy(), false, false),
    ] {
        let (replay, reached) = one_server();
        let hub = hub(replay, true);
        if proxy_set {
            hub.set_proxy_text("http://gate.corp.example:3128")
                .expect("a proxy");
        }
        let probe = probe(&hub, info, Os::Linux);
        let result = probe
            .nameserver_exchange(0, &query("gate.corp.example", 1), DnsTransport::Udp)
            .await;
        if ok {
            result.expect("the proxy's name");
            assert_eq!(reached.load(Ordering::SeqCst), 1);
        } else {
            let error = result.expect_err("not the check's proxy");
            assert_eq!(denied_rule(&error), RULE_NS_NAME);
            assert_eq!(reached.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn a_payload_with_a_foreign_byte_never_reaches_the_server() {
    let (replay, reached) = one_server();
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    let mut spaced = query("aaaaaaaa.example", 1);
    spaced[13] = b' ';
    for payload in [
        with_tail(0, b"smuggled"),
        with_tail(1, b"smuggled"),
        query("a.example", 16),
        query("a.example", 255),
        spaced,
    ] {
        let error = probe
            .nameserver_exchange(0, &payload, DnsTransport::Udp)
            .await
            .expect_err("not a plain query");
        assert_eq!(denied_rule(&error), RULE_NS_PAYLOAD);
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_resolv_conf_that_links_to_another_file_is_denied_by_the_read_guard() {
    // A link in /etc/resolv.conf to a file outside the list is judged on its real path. The replay
    // follows the link as the live backend does.
    for target in ["/etc/hostname", "/etc/shadow", "../shadow", "/etc/passwd"] {
        let (replay, reached) = counting(
            Replay::new()
                .symlink("/etc/resolv.conf", target)
                .file("/etc/hostname", "nameserver 10.0.0.2\n")
                .file("/etc/shadow", "nameserver 10.0.0.2\n")
                .file("/etc/passwd", "nameserver 10.0.0.2\n"),
            "10.0.0.2:53",
            b"x",
        );
        let hub = hub(replay, true);
        let probe = probe(&hub, resolver(), Os::Linux);
        let error = probe.nameserver_count().await.expect_err(target);
        assert!(
            matches!(error, ProbeError::Denied { .. }),
            "{target}: {error:?}"
        );
        let error = probe
            .nameserver_exchange(0, &query("a.example", 1), DnsTransport::Udp)
            .await
            .expect_err(target);
        assert!(
            matches!(error, ProbeError::Denied { .. }),
            "{target}: {error:?}"
        );
        assert_eq!(reached.load(Ordering::SeqCst), 0, "{target}");
        let reads = entries(&hub, ActionKind::Read);
        assert!(
            reads.iter().all(|a| a.outcome == ActionOutcome::Denied),
            "{target}: {reads:?}"
        );
    }
}

#[tokio::test]
async fn the_resolver_files_of_resolvconf_and_networkmanager_are_read_and_nothing_near_them() {
    for target in [
        "/run/systemd/resolve/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
        "/run/resolvconf/resolv.conf",
        "/run/NetworkManager/resolv.conf",
        "/run/NetworkManager/no-stub-resolv.conf",
    ] {
        let hub = hub(
            Replay::new()
                .symlink("/etc/resolv.conf", target)
                .file(target, "nameserver 10.0.0.2\n"),
            true,
        );
        let count = probe(&hub, resolver(), Os::Linux)
            .nameserver_count()
            .await
            .expect(target);
        assert_eq!(count, 1, "{target}");
    }
    // Other files of the same directories, and a file that merely starts the same, are not read.
    for target in [
        "/run/NetworkManager/conf.d/secret.conf",
        "/run/NetworkManager/system-connections/wifi.nmconnection",
        "/run/NetworkManager/resolv.conf.bak",
        "/run/resolvconf/interface/eth0.dhcp",
        "/run/resolvconf/resolv.conf/../../shadow",
        "/run/systemd/resolve/netif/1",
    ] {
        let hub = hub(
            Replay::new()
                .symlink("/etc/resolv.conf", target)
                .file(target, "nameserver 10.0.0.2\n"),
            true,
        );
        let error = probe(&hub, resolver(), Os::Linux)
            .nameserver_count()
            .await
            .expect_err(target);
        assert!(
            matches!(error, ProbeError::Denied { .. }),
            "{target}: {error:?}"
        );
    }
}

#[tokio::test]
async fn the_facade_picks_the_message_id_and_returns_it() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::<u16>::new()));
    let log = Arc::clone(&seen);
    let replay = resolv("nameserver 10.0.0.2\n").dns_server(addr("10.0.0.2:53"), move |q, _| {
        log.lock()
            .expect("lock")
            .push(u16::from_be_bytes([q[0], q[1]]));
        DnsScript::Answer(q.to_vec())
    });
    let hub = hub(replay, true);
    let probe = probe(&hub, resolver(), Os::Linux);
    let q = query("db.corp.example", 1);
    assert_eq!(&q[..2], &[0x12, 0x34]);
    let mut ids = Vec::new();
    for transport in [DnsTransport::Udp, DnsTransport::Tcp] {
        for _ in 0..8 {
            let reply = probe
                .nameserver_exchange(0, &q, transport)
                .await
                .expect("a reply");
            ids.push(reply.query_id.expect("the id the facade sent"));
        }
    }
    // What the server saw is what the facade reported, and it is not the caller's ID (a chance of 1 in
    // 65536 per call, so sixteen calls all matching 0x1234 cannot happen by luck).
    assert_eq!(*seen.lock().expect("lock"), ids);
    assert!(ids.iter().any(|id| *id != 0x1234), "{ids:?}");
    assert!(ids.windows(2).any(|w| w[0] != w[1]), "{ids:?}");
    // The rest of the payload is untouched.
    let echoed = probe
        .nameserver_exchange(0, &q, DnsTransport::Udp)
        .await
        .expect("a reply");
    assert_eq!(echoed.bytes[2..], q[2..]);
}
