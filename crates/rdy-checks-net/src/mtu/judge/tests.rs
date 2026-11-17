//! Tests of the overhead table and of the judgement, with no machine and no fixture.

use rdy_engine::check::Level;

use super::*;

fn iface(name: &str, mtu: u32) -> Iface {
    Iface {
        name: name.to_owned(),
        mtu: Some(mtu),
        state: "up".to_owned(),
        kind: Kind::Ethernet,
    }
}

fn facts(mtu: u32) -> Facts {
    Facts {
        default: Some(Chosen {
            iface: "eth0".to_owned(),
            family: Family::V4,
        }),
        ifaces: vec![iface("eth0", mtu)],
        ..Facts::default()
    }
}

fn rules(min_mtu: Option<u32>, overlay: Option<Overlay>) -> Rules {
    Rules {
        min_mtu,
        overlay,
        underlay: Underlay::Ipv4,
    }
}

#[test]
fn the_overhead_table_is_the_published_header_sizes() {
    let table = [
        (Overlay::Ipip, Underlay::Ipv4, 20),
        (Overlay::Ipip, Underlay::Ipv6, 48),
        (Overlay::Vxlan, Underlay::Ipv4, 50),
        (Overlay::Vxlan, Underlay::Ipv6, 70),
        (Overlay::Wireguard, Underlay::Ipv4, 60),
        (Overlay::Wireguard, Underlay::Ipv6, 80),
        (Overlay::Geneve, Underlay::Ipv4, 50),
        (Overlay::Geneve, Underlay::Ipv6, 70),
    ];
    for (overlay, underlay, bytes) in table {
        assert_eq!(
            overhead(overlay, underlay),
            Some(bytes),
            "{overlay:?} {underlay:?}"
        );
    }
}

#[test]
fn the_boundary_is_inclusive_for_every_overlay() {
    for (overlay, underlay) in [
        (Overlay::Ipip, Underlay::Ipv4),
        (Overlay::Ipip, Underlay::Ipv6),
        (Overlay::Vxlan, Underlay::Ipv4),
        (Overlay::Vxlan, Underlay::Ipv6),
        (Overlay::Wireguard, Underlay::Ipv4),
        (Overlay::Wireguard, Underlay::Ipv6),
        (Overlay::Geneve, Underlay::Ipv4),
        (Overlay::Geneve, Underlay::Ipv6),
    ] {
        let over = overhead(overlay, underlay).expect("known");
        let rules = Rules {
            min_mtu: Some(1400),
            overlay: Some(overlay),
            underlay,
        };
        assert_eq!(
            judge(facts(1400 + over), &rules).level,
            Level::Pass,
            "{overlay:?}"
        );
        assert_eq!(
            judge(facts(1400 + over - 1), &rules).level,
            Level::Fail,
            "{overlay:?}"
        );
    }
}

#[test]
fn a_tiny_interface_does_not_underflow() {
    let finding = judge(facts(68), &rules(Some(1400), Some(Overlay::Wireguard)));
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(finding.observed["pod_mtu"], 8);
    let finding = judge(facts(40), &rules(Some(68), Some(Overlay::Vxlan)));
    assert_eq!(finding.observed["pod_mtu"], 0);
}

#[test]
fn the_exact_1500_is_not_jumbo() {
    let finding = judge(facts(1500), &rules(Some(1400), None));
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.notes.is_empty(), "{:?}", finding.notes);
    assert_eq!(
        judge(facts(1501), &rules(Some(1400), None)).level,
        Level::Warn
    );
    assert_eq!(judge(facts(1501), &rules(None, None)).level, Level::Pass);
}

#[test]
fn the_small_mtu_line_is_1400() {
    assert_eq!(judge(facts(1399), &rules(None, None)).level, Level::Warn);
    assert_eq!(judge(facts(1400), &rules(None, None)).level, Level::Pass);
}

#[test]
fn a_minimum_above_the_mtu_asks_to_raise_it_even_when_the_mtu_is_above_1500() {
    // min_mtu 9000 with MTU 1600 and no overlay: never "set the MTU to 1500".
    let finding = judge(facts(1600), &rules(Some(9000), None));
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.message, "`eth0` has MTU 1600, and 9000 is needed.");
    let fix = finding.fix.expect("a fix");
    assert!(fix.contains("to 9000 or more"), "{fix}");
    assert!(!fix.contains("1500"), "{fix}");
    // Once the minimum is met the clamp warning applies again.
    assert!(
        judge(facts(9001), &rules(Some(9000), None))
            .message
            .contains("clamped")
    );
}

#[test]
fn the_overlay_block_beats_the_clamp_warning() {
    let finding = judge(facts(9001), &rules(Some(9000), Some(Overlay::Vxlan)));
    assert_eq!(finding.level, Level::Fail);
}

#[test]
fn an_interface_name_with_odd_characters_is_escaped_in_the_message_and_the_fix() {
    let mut f = facts(1450);
    f.default = Some(Chosen {
        iface: "e`th\n0".to_owned(),
        family: Family::V4,
    });
    f.ifaces = vec![iface("e`th\n0", 1450)];
    let finding = judge(f, &rules(Some(1450), Some(Overlay::Vxlan)));
    assert_eq!(finding.level, Level::Fail);
    assert!(!finding.message.contains('\n'));
    let fix = finding.fix.expect("a fix");
    assert!(!fix.contains('\n'));
    assert!(fix.contains("e`th\\x0a0"), "{fix}");
}

#[test]
fn the_kind_comes_from_the_type_then_the_name() {
    assert_eq!(kind_of(Some(1), "eth0"), Kind::Ethernet);
    assert_eq!(kind_of(Some(772), "lo"), Kind::Loopback);
    assert_eq!(kind_of(Some(65534), "wg0"), Kind::Tunnel);
    assert_eq!(kind_of(Some(65534), "weird0"), Kind::Tunnel);
    assert_eq!(kind_of(Some(768), "tunl0"), Kind::Tunnel);
    assert_eq!(kind_of(Some(1), "tap0"), Kind::Tunnel);
    assert_eq!(kind_of(Some(1), "tailscale0"), Kind::Tunnel);
    assert_eq!(kind_of(Some(32), "ib0"), Kind::Other);
    assert_eq!(kind_of(None, "eth0"), Kind::Other);
}

#[test]
fn the_evidence_lists_at_most_32_interfaces_and_counts_the_rest() {
    let mut f = facts(1500);
    f.ifaces = (0..40)
        .map(|n| iface(&format!("eth{n:02}"), 1500))
        .collect();
    f.default = Some(Chosen {
        iface: "eth00".to_owned(),
        family: Family::V4,
    });
    let finding = judge(f, &rules(None, None));
    assert_eq!(
        finding.observed["interfaces"].as_array().map(Vec::len),
        Some(32)
    );
    assert_eq!(finding.observed["interfaces_not_shown"], 8);
}
