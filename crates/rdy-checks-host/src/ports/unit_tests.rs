//! Unit tests of the parsers and the judgement of `host.ports`. Nothing here touches a probe.

use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;
use rdy_engine::check::Level;
use rdy_spec::check::Bind;
use serde_json::Value;

use super::net::{self, LISTEN, Scope, Socket};
use super::owner::{self, Gap, Owner};
use super::range;
use super::report::{self, Facts, Held, PortState, Proto};

const HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

fn row(local: &str, state: &str, uid: u32, inode: u64) -> String {
    format!(
        "   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 {uid:5}        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    )
}

fn one(local: &str, v6: bool) -> Socket {
    let table = net::parse(&format!("{HEAD}{}", row(local, "0A", 7, 55)), v6, false);
    assert_eq!(table.skipped, 0, "{local}");
    table.sockets.into_iter().next().expect("a socket")
}

// ---- net -----------------------------------------------------------------------------------------

#[test]
fn an_ipv4_address_is_little_endian_hex() {
    let socket = one("0100007F:1F90", false);
    assert_eq!(socket.addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(socket.port, 8080);
    assert_eq!((socket.state, socket.uid, socket.inode), (LISTEN, 7, 55));
    assert_eq!(socket.scope(), Scope::Loopback);
    assert_eq!(socket.shown(), "127.0.0.1");
    assert_eq!(one("0A0200C0:0016", false).addr.to_string(), "192.0.2.10");
}

#[test]
fn an_ipv6_address_is_four_little_endian_words() {
    let any = one("00000000000000000000000000000000:192B", true);
    assert_eq!(any.scope(), Scope::Unspecified);
    assert_eq!(any.shown(), "[::]");
    assert_eq!(any.port, 6443);
    let loopback = one("00000000000000000000000001000000:192B", true);
    assert_eq!(loopback.scope(), Scope::Loopback);
    assert_eq!(loopback.shown(), "[::1]");
    // 2001:db8::1
    let doc = one("B80D0120000000000000000001000000:0050", true);
    assert_eq!(doc.shown(), "[2001:db8::1]");
    assert_eq!(doc.scope(), Scope::Other);
}

#[test]
fn an_ipv4_mapped_address_counts_as_the_ipv4_address() {
    let mapped = one("0000000000000000FFFF00000100007F:1F90", true);
    assert_eq!(mapped.scope(), Scope::Loopback);
    let wild = one("0000000000000000FFFF000000000000:1F90", true);
    assert_eq!(wild.scope(), Scope::Unspecified);
}

#[test]
fn rows_that_do_not_parse_are_counted_and_left_out() {
    let text = format!(
        "{HEAD}{}garbage here\n{}   3: 0100007F:ZZZZ 00000000:0000 0A 0:0 0:0 0 0 0 5 1\n{}",
        row("0100007F:0050", "0A", 0, 1),
        row("0100007F:0051", "01", 0, 2),
        // A v6 address in a v4 table.
        row("00000000000000000000000000000000:0052", "0A", 0, 3),
    );
    let table = net::parse(&text, false, false);
    let ports: Vec<u16> = table.sockets.iter().map(|s| s.port).collect();
    assert_eq!(ports, [80, 81]);
    assert_eq!(table.skipped, 3);
    assert_eq!(table.last_state, Some(0x01));
}

#[test]
fn a_cut_table_drops_its_partial_last_line() {
    let whole = format!("{HEAD}{}", row("0100007F:0050", "0A", 0, 1));
    let cut_text = format!("{whole}   1: 0100007F:00");
    let table = net::parse(&cut_text, false, true);
    assert_eq!(table.sockets.len(), 1);
    assert_eq!(table.skipped, 0);
    // A table that was not cut keeps the line and counts it as unreadable.
    let table = net::parse(&cut_text, false, false);
    assert_eq!(table.skipped, 1);
}

#[test]
fn an_empty_table_and_a_header_only_table_have_no_sockets() {
    for text in ["", HEAD, "\n\n"] {
        let table = net::parse(text, false, false);
        assert!(table.sockets.is_empty());
        assert_eq!(table.last_state, None);
    }
}

proptest! {
    #[test]
    fn the_table_parser_never_panics(text in "\\PC{0,400}", v6 in any::<bool>(), cut in any::<bool>()) {
        let _ = net::parse(&text, v6, cut);
    }

    #[test]
    fn a_wellformed_row_round_trips(
        a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>(),
        port in 1u16.., uid in any::<u32>(), inode in 1u64..,
    ) {
        let hex = format!("{:02X}{:02X}{:02X}{:02X}:{port:04X}", d, c, b, a);
        let table = net::parse(&format!("{HEAD}{}", row(&hex, "0A", uid, inode)), false, false);
        prop_assert_eq!(table.sockets.len(), 1);
        let socket = &table.sockets[0];
        prop_assert_eq!(socket.addr, IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
        prop_assert_eq!((socket.port, socket.uid, socket.inode), (port, uid, inode));
    }

    #[test]
    fn the_range_parsers_never_panic(text in "\\PC{0,200}") {
        let _ = range::parse_range(&text);
        let _ = range::parse_reserved(&text);
        let _ = owner::socket_inode(text.as_bytes());
        let _ = owner::unit_of(&text);
        let _ = owner::effective_uid(&text);
        let _ = super::namespace(text.as_bytes());
    }
}

// ---- range ---------------------------------------------------------------------------------------

#[test]
fn the_ephemeral_range_is_two_numbers_in_order() {
    assert_eq!(range::parse_range("32768\t60999\n"), Some((32768, 60999)));
    assert_eq!(range::parse_range("1024 65535"), Some((1024, 65535)));
    for bad in ["", "32768", "60999 32768", "1 2 3", "a b", "0 70000"] {
        assert_eq!(range::parse_range(bad), None, "{bad:?}");
    }
}

#[test]
fn reserved_ports_are_items_and_ranges() {
    assert_eq!(
        range::parse_reserved("6443, 8000-8010,x,9-3\n"),
        (vec![(6443, 6443), (8000, 8010)], true)
    );
    assert_eq!(range::parse_reserved("\n"), (Vec::new(), true));
    // More than 1,024 items: the first are kept and the value is not complete.
    let long = (1..=1100u16)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let (spans, complete) = range::parse_reserved(&long);
    assert_eq!(spans.len(), 1024);
    assert!(!complete);
    assert!(range::contains(&[(8000, 8010)], 8005));
    assert!(!range::contains(&[(8000, 8010)], 8011));
}

#[test]
fn a_port_is_exposed_only_inside_the_range_and_when_not_reserved() {
    let span = (32768, 60999);
    assert!(range::exposed(span, &[], 32768));
    assert!(range::exposed(span, &[], 60999));
    assert!(!range::exposed(span, &[], 32767));
    assert!(!range::exposed(span, &[], 6443));
    assert!(!range::exposed(span, &[(40000, 40010)], 40005));
}

#[test]
fn the_merged_value_keeps_what_is_reserved_and_joins_touching_spans() {
    assert_eq!(range::merged_value(&[], &[32800]), "32800");
    assert_eq!(
        range::merged_value(&[(8000, 8010)], &[40000, 32800]),
        "8000-8010,32800,40000"
    );
    assert_eq!(
        range::merged_value(&[(8000, 8010)], &[8011, 8005]),
        "8000-8011"
    );
    assert_eq!(
        range::merged_value(&[(65530, 65535)], &[65535]),
        "65530-65535"
    );
    assert_eq!(range::merged_value(&[], &[]), "");
}

// ---- owner ---------------------------------------------------------------------------------------

#[test]
fn only_a_socket_target_has_an_inode() {
    assert_eq!(owner::socket_inode(b"socket:[8841]"), Some(8841));
    for bad in [
        &b"socket:[]"[..],
        b"socket:[12a]",
        b"socket:[8841",
        b"pipe:[8841]",
        b"/var/lib/socket:[8841]",
        b"socket:[99999999999999999999999]",
        b"",
    ] {
        assert_eq!(
            owner::socket_inode(bad),
            None,
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn the_effective_uid_is_the_second_number() {
    assert_eq!(
        owner::effective_uid("Name:\trdy\nUid:\t1000\t0\t0\t0\n"),
        Some(0)
    );
    assert_eq!(owner::effective_uid("Uid: 5 6 7 8"), Some(6));
    assert!(owner::owned_by("Uid:\t1000\t1000\t1000\t1000\n", 1000));
    // A process that changed any of the three ids is not listed by another user.
    assert!(!owner::owned_by("Uid:\t1000\t1000\t0\t1000\n", 1000));
    assert!(!owner::owned_by("Uid:\t0\t0\t0\t0\n", 1000));
    assert!(!owner::owned_by("Name:\tx\n", 1000));
    assert_eq!(owner::effective_uid("Gid:\t1\t2\t3\t4\n"), None);
    assert_eq!(owner::effective_uid("Uid:\t1000\n"), None);
}

#[test]
fn the_unit_is_the_deepest_plain_service() {
    let unit = |text: &str| owner::unit_of(text);
    assert_eq!(
        unit("0::/system.slice/kubelet.service\n").as_deref(),
        Some("kubelet.service")
    );
    assert_eq!(
        unit("0::/system.slice/kubelet.service/init.scope\n").as_deref(),
        Some("kubelet.service")
    );
    // The first component that is not a slice decides, and only a service counts.
    assert_eq!(
        unit("0::/machine.slice/machine-web.scope/system.slice/inner.service\n"),
        None
    );
    assert_eq!(
        unit(
            "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-abc.scope/system.slice/x.service\n"
        ),
        None
    );
    assert_eq!(unit("0::/system.slice/docker-abc.scope/x.service\n"), None);
    assert_eq!(unit("0::/init.scope/x.service\n"), None);
    // A name that starts with a dash would read as an option.
    assert_eq!(unit("0::/system.slice/-evil.service\n"), None);
    assert_eq!(unit("0::/system.slice/.hidden.service\n"), None);
    // Version 1: the systemd hierarchy.
    assert_eq!(
        unit("12:pids:/system.slice/x.service\n1:name=systemd:/system.slice/docker.service\n")
            .as_deref(),
        Some("docker.service")
    );
    // A user service needs `systemctl --user`, a pod or a login session has no service, and a name
    // that needs quoting is not shown.
    assert_eq!(
        unit("0::/user.slice/user-1000.slice/user@1000.service/app.slice/a.service\n"),
        None
    );
    assert_eq!(
        unit("0::/kubepods.slice/kubepods-burstable.slice/pod1/cri-containerd-abc.scope\n"),
        None
    );
    assert_eq!(unit("0::/system.slice/we ird.service\n"), None);
    assert_eq!(unit("0::/system.slice/a\\x2db.service\n"), None);
    assert_eq!(unit(""), None);
    assert_eq!(unit("0::/\n"), None);
}

#[test]
fn the_namespace_is_rebuilt_from_its_digits() {
    assert_eq!(
        super::namespace(b"net:[4026531992]").as_deref(),
        Some("net:[4026531992]")
    );
    for bad in [
        &b"net:[]"[..],
        b"net:[1a]",
        b"mnt:[1]",
        b"net:[1]x",
        b"/home/ada/net:[1]",
    ] {
        assert_eq!(super::namespace(bad), None);
    }
}

// ---- judgement -----------------------------------------------------------------------------------

fn socket(addr: &str, v6: bool) -> Socket {
    Socket {
        addr: addr.parse().expect("an address"),
        v6_table: v6,
        port: 6443,
        state: LISTEN,
        uid: 0,
        inode: 1,
    }
}

#[test]
fn a_public_bind_conflicts_with_every_listener_and_a_loopback_bind_with_two_kinds() {
    for (addr, v6, public, loopback) in [
        ("0.0.0.0", false, true, true),
        ("::", true, true, true),
        ("127.0.0.1", false, true, true),
        ("::1", true, true, true),
        ("10.0.0.5", false, true, false),
        ("2001:db8::1", true, true, false),
    ] {
        let s = socket(addr, v6);
        assert_eq!(report::conflicts(&s, Bind::Public), public, "{addr} public");
        assert_eq!(
            report::conflicts(&s, Bind::Loopback),
            loopback,
            "{addr} loopback"
        );
    }
}

fn held(owner: Option<Owner>, gap: Option<Gap>, addr: &str) -> Held {
    Held {
        socket: socket(addr, false),
        owner,
        gap,
    }
}

fn named(name: &str) -> Option<Owner> {
    Some(Owner {
        pid: 9,
        name: Some(name.to_owned()),
        unit: None,
    })
}

fn facts<'a>(ports: Vec<PortState>, allow: &'a [String], root: bool) -> Facts<'a> {
    Facts {
        ports,
        allow,
        root,
        range: Some((32768, 60999)),
        reserved: Vec::new(),
        reserved_known: true,
        netns: None,
        container: None,
        notes: Vec::new(),
        walked: 0,
    }
}

fn port(number: u16, held: Vec<Held>) -> PortState {
    PortState {
        proto: Proto::Tcp,
        port: number,
        bind: Bind::Public,
        held,
        unverified: None,
        ephemeral: false,
    }
}

#[test]
fn an_unknown_owner_blocks_unless_the_spec_allows_some_owner() {
    let unknown = || vec![port(6443, vec![held(None, Some(Gap::NotFound), "0.0.0.0")])];
    let none: Vec<String> = Vec::new();
    let f = report::assemble(&facts(unknown(), &none, true), Value::Null);
    assert_eq!(f.level, Level::Fail);
    let some = vec!["acme".to_owned()];
    let f = report::assemble(&facts(unknown(), &some, true), Value::Null);
    assert_eq!(f.level, Level::Warn);
}

#[test]
fn a_known_owner_outside_the_allow_list_blocks_and_one_inside_passes() {
    let allow = vec!["acme-agent".to_owned()];
    let other = vec![port(6443, vec![held(named("nginx"), None, "0.0.0.0")])];
    assert_eq!(
        report::assemble(&facts(other, &allow, true), Value::Null).level,
        Level::Fail
    );
    let mine = vec![port(6443, vec![held(named("acme-agent"), None, "0.0.0.0")])];
    assert_eq!(
        report::assemble(&facts(mine, &allow, true), Value::Null).level,
        Level::Pass
    );
}

#[test]
fn a_pid_without_a_readable_name_is_shown_by_pid_and_is_not_allowed() {
    let nameless = Owner {
        pid: 41,
        name: None,
        unit: None,
    };
    let ports = vec![port(6443, vec![held(Some(nameless), None, "0.0.0.0")])];
    let f = report::assemble(&facts(ports, &[], true), Value::Null);
    assert_eq!(f.level, Level::Fail);
    assert!(f.message.contains("held by pid 41."), "{}", f.message);
}

#[test]
fn a_name_in_the_message_cannot_break_the_sentence() {
    let ports = vec![port(
        6443,
        vec![held(named("a`b\u{1b}[2J"), None, "0.0.0.0")],
    )];
    let f = report::assemble(&facts(ports, &[], true), Value::Null);
    assert!(!f.message.contains('\u{1b}'), "{:?}", f.message);
    // Always in a code span, with the backtick escaped so it cannot close the span.
    assert!(
        f.message.contains("held by `a\\x60b\\x1b[2J` (pid 9)"),
        "{}",
        f.message
    );
    assert_eq!(f.message.matches('`').count(), 2, "{}", f.message);
}

#[test]
fn an_allowed_holder_is_shown_with_its_unit_and_the_note_says_the_name_is_not_proof() {
    let owner = Owner {
        pid: 9,
        name: Some("acme-agent".to_owned()),
        unit: Some("acme.service".to_owned()),
    };
    let allow = vec!["acme-agent".to_owned()];
    let ports = vec![port(6443, vec![held(Some(owner), None, "0.0.0.0")])];
    let f = report::assemble(&facts(ports, &allow, true), Value::Null);
    assert_eq!(f.level, Level::Pass);
    let note = f.notes.join(" ");
    assert!(note.contains("(pid 9, unit `acme.service`)"), "{note}");
    assert!(note.contains("any local process can set"), "{note}");
}

#[test]
fn the_ephemeral_fix_tells_the_user_to_append_when_the_reserved_ports_are_not_known() {
    let mut exposed = port(40000, Vec::new());
    exposed.ephemeral = true;
    let mut f = facts(vec![exposed], &[], true);
    f.reserved_known = false;
    let finding = report::assemble(&f, Value::Null);
    let fix = finding.fix.expect("a fix");
    assert!(
        !fix.contains("keeps the ports that are reserved now"),
        "{fix}"
    );
    assert!(
        fix.contains("`sysctl -n net.ipv4.ip_local_reserved_ports`"),
        "{fix}"
    );
    assert!(fix.contains("<that value>,40000"), "{fix}");
    assert!(fix.contains("99-zz-reserved-ports.conf"), "{fix}");
}

#[test]
fn many_holders_and_many_ports_are_cut() {
    let many: Vec<Held> = (0..20)
        .map(|i| {
            let mut h = held(named("web"), None, "0.0.0.0");
            h.socket.inode = 100 + i;
            h
        })
        .collect();
    let f = report::assemble(&facts(vec![port(6443, many)], &[], true), Value::Null);
    assert_eq!(
        f.observed["tcp"][0]["holders"].as_array().map(Vec::len),
        Some(8)
    );
    assert_eq!(f.observed["tcp"][0]["holders_not_shown"], 12);

    let ports: Vec<PortState> = (1000..1020).map(|n| port(n, Vec::new())).collect();
    let f = report::assemble(&facts(ports, &[], true), Value::Null);
    assert_eq!(f.level, Level::Pass);
    assert!(f.message.contains("and 12 more are free."), "{}", f.message);
}

#[test]
fn no_ports_is_a_pass_that_says_so() {
    let f = report::assemble(&facts(Vec::new(), &[], true), Value::Null);
    assert_eq!(f.level, Level::Pass);
    assert_eq!(f.message, "The spec names no ports to check.");
}

#[test]
fn the_ephemeral_fix_is_not_given_when_the_range_is_unknown() {
    let mut exposed = port(40000, Vec::new());
    exposed.ephemeral = true;
    let mut f = facts(vec![exposed], &[], true);
    f.range = None;
    let finding = report::assemble(&f, Value::Null);
    assert_eq!(finding.level, Level::Pass);
}
