//! The judgement of `net.mtu`: pure functions from the facts and the spec rules to a finding.
//!
//! Nothing here touches the machine. The overhead table is in [`overhead`] and the rules are in
//! [`judge`]. They follow 03 section 3:
//!
//! - An overlay with a `min_mtu`: the MTU of the default interface, less the overlay header, below
//!   `min_mtu` is `fail` (block). The header must fit; a result equal to `min_mtu` is enough.
//! - A default interface MTU below `min_mtu` with no overlay, or below 1400 with no `min_mtu`: `warn`.
//! - An MTU above 1500: informational, unless the spec sets `overlay` or `min_mtu`, then `warn`.

use rdy_engine::check::Finding;
use rdy_spec::check::{Overlay, Underlay};
use serde_json::{Value, json};

use crate::text::code;

/// An interface MTU below this, with no `min_mtu` in the spec, is a warning.
pub(super) const SMALL_MTU: u32 = 1400;

/// The MTU of ordinary Ethernet. Traffic that leaves the network is clamped to it (path MTU discovery
/// permitting).
pub(super) const ETHERNET_MTU: u32 = 1500;

/// The most interfaces listed in the evidence. The rest are counted.
const SHOWN_MAX: usize = 32;

/// What OVN-Kubernetes reserves for a Geneve header, options included (03 section 3).
const OVN_GENEVE_RESERVE: u32 = 100;

/// The bytes an overlay takes from the MTU of the interface under it, or `None` for an overlay this
/// rdy does not know (the enum is `non_exhaustive`).
///
/// The values are the header sizes of the published formats, counted from the outer IP header:
///
/// - IP in IP: one IPv4 header, 20 bytes (RFC 2003 section 3). Over an IPv6 underlay (`ip6tnl`) the
///   outer header is 40 bytes plus the 8-byte Tunnel Encapsulation Limit option that Linux adds by
///   default, 48 in all (RFC 2473 sections 3.3 and 4.1.1). 03 lists only the 20.
/// - VXLAN: outer IP (20, or 40 for IPv6) + UDP 8 + VXLAN 8 + inner Ethernet 14 = 50 or 70
///   (RFC 7348 section 4.3).
/// - WireGuard: outer IP (20 or 40) + UDP 8 + WireGuard data header and tag 32 = 60 or 80. The default
///   WireGuard MTU of 1420 is 1500 less the 80 of the IPv6 case.
/// - Geneve: outer IP (20 or 40) + UDP 8 + Geneve base header 8 + inner Ethernet 14 = 50 or 70
///   (RFC 8926 section 3.1), before options. [`ovn_geneve_pod_mtu`] covers the 100 that OVN-Kubernetes
///   reserves.
pub(super) fn overhead(overlay: Overlay, underlay: Underlay) -> Option<u32> {
    match (overlay, underlay) {
        (Overlay::Ipip, Underlay::Ipv4) => Some(20),
        (Overlay::Ipip, Underlay::Ipv6) => Some(48),
        (Overlay::Vxlan | Overlay::Geneve, Underlay::Ipv4) => Some(50),
        (Overlay::Vxlan | Overlay::Geneve, Underlay::Ipv6) => Some(70),
        (Overlay::Wireguard, Underlay::Ipv4) => Some(60),
        (Overlay::Wireguard, Underlay::Ipv6) => Some(80),
        _ => None,
    }
}

/// How the product names an overlay in a sentence.
fn overlay_name(overlay: Overlay) -> &'static str {
    match overlay {
        Overlay::Vxlan => "VXLAN",
        Overlay::Geneve => "Geneve",
        Overlay::Wireguard => "WireGuard",
        Overlay::Ipip => "IPIP",
        _ => "the overlay",
    }
}

/// The word the evidence uses for an overlay.
fn overlay_key(overlay: Overlay) -> &'static str {
    match overlay {
        Overlay::Vxlan => "vxlan",
        Overlay::Geneve => "geneve",
        Overlay::Wireguard => "wireguard",
        Overlay::Ipip => "ipip",
        _ => "unknown",
    }
}

/// What kind of interface a name and an ARP hardware type (`/sys/class/net/<if>/type`) make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Ethernet,
    Loopback,
    /// A VPN or tunnel: IPIP, SIT, GRE, WireGuard, `tun`, PPP and the like.
    Tunnel,
    Other,
}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Loopback => "loopback",
            Self::Tunnel => "tunnel",
            Self::Other => "other",
        }
    }
}

/// The kind from the `type` file (an `ARPHRD_*` number from `linux/if_arp.h`) and the name.
///
/// Type 65534 (`ARPHRD_NONE`) is what WireGuard and `tun` devices report. A `tap` device and some VPN
/// clients look like Ethernet, so the name decides for the usual VPN prefixes.
pub(super) fn kind_of(arphrd: Option<u32>, name: &str) -> Kind {
    let by_type = match arphrd {
        Some(772) => Some(Kind::Loopback),
        // IPIP, IP6 tunnel, SIT, GRE, IP6GRE, PPP, NONE.
        Some(768 | 769 | 776 | 778 | 823 | 512 | 65534) => Some(Kind::Tunnel),
        Some(1) => Some(Kind::Ethernet),
        _ => None,
    };
    let tunnel_name = ["wg", "tun", "tap", "ppp", "tailscale", "zt", "vpn", "utun"]
        .iter()
        .any(|prefix| name.starts_with(prefix));
    match by_type {
        Some(Kind::Loopback) => Kind::Loopback,
        _ if tunnel_name => Kind::Tunnel,
        Some(kind) => kind,
        None => Kind::Other,
    }
}

/// One network interface as sysfs showed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Iface {
    pub name: String,
    /// `None` when the file was missing, unreadable or not a number.
    pub mtu: Option<u32>,
    /// The `operstate` word, such as `up`, `down` or `unknown`.
    pub state: String,
    pub kind: Kind,
}

impl Iface {
    /// Whether the interface carries traffic: `up`, or `unknown`, which is what tunnels and many
    /// virtual devices report while they work.
    fn is_up(&self) -> bool {
        matches!(self.state.as_str(), "up" | "unknown")
    }
}

/// Which table the default route came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    V4,
    V6,
}

/// The default route that was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Chosen {
    pub iface: String,
    pub family: Family,
}

/// What the check found on the machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Facts {
    /// The default route, or `None` when there is none.
    pub default: Option<Chosen>,
    /// Every interface that was read, loopback excluded, sorted by name.
    pub ifaces: Vec<Iface>,
    /// Interfaces of container plumbing that were counted and not read (`veth*`, `cali*`, `lxc*`).
    pub container_ifaces: usize,
    /// Interfaces past the read limit.
    pub unread_ifaces: usize,
    /// Lines for the report.
    pub notes: Vec<String>,
}

/// The spec's rules for `net.mtu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Rules {
    pub min_mtu: Option<u32>,
    pub overlay: Option<Overlay>,
    pub underlay: Underlay,
}

/// The evidence for the report.
fn observed(facts: &Facts, rules: &Rules, default: Option<&Iface>, overhead: Option<u32>) -> Value {
    let shown: Vec<Value> = facts
        .ifaces
        .iter()
        .filter(|iface| iface.is_up() || default.is_some_and(|d| d.name == iface.name))
        .take(SHOWN_MAX)
        .map(|iface| {
            json!({
                "name": rdy_engine::text::escape_untrusted(&iface.name),
                "mtu": iface.mtu,
                "state": rdy_engine::text::escape_untrusted(&iface.state),
                "kind": iface.kind.word(),
            })
        })
        .collect();
    let listed = facts
        .ifaces
        .iter()
        .filter(|iface| iface.is_up() || default.is_some_and(|d| d.name == iface.name))
        .count();
    let down = facts.ifaces.len().saturating_sub(listed);
    let pod_mtu = default
        .and_then(|d| d.mtu)
        .zip(overhead)
        .map(|(mtu, over)| mtu.saturating_sub(over));
    json!({
        "default_interface": facts.default.as_ref().map(|d| rdy_engine::text::escape_untrusted(&d.iface)),
        "default_family": facts.default.as_ref().map(|d| match d.family {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }),
        "default_mtu": default.and_then(|d| d.mtu),
        "interfaces": shown,
        "interfaces_not_shown": listed.saturating_sub(SHOWN_MAX),
        "interfaces_down": down,
        "interfaces_not_read": facts.unread_ifaces,
        "container_interfaces": facts.container_ifaces,
        "overlay": rules.overlay.map(overlay_key),
        "overhead": overhead,
        "pod_mtu": pod_mtu,
    })
}

/// The effective thresholds for the report.
fn expected(rules: &Rules, overhead: Option<u32>) -> Value {
    json!({
        "min_mtu": rules.min_mtu,
        "overlay": rules.overlay.map(overlay_key),
        "underlay": match rules.underlay {
            Underlay::Ipv6 => "ipv6",
            _ => "ipv4",
        },
        "overhead": overhead,
        "warn_below": if rules.min_mtu.is_none() { Some(SMALL_MTU) } else { None },
        "clamp_above": ETHERNET_MTU,
    })
}

/// The finding for the facts and the rules.
pub(super) fn judge(facts: Facts, rules: &Rules) -> Finding {
    let overhead = rules
        .overlay
        .and_then(|overlay| overhead(overlay, rules.underlay));
    let default = facts
        .default
        .as_ref()
        .and_then(|chosen| facts.ifaces.iter().find(|iface| iface.name == chosen.iface));
    let mut notes = facts.notes.clone();
    if let Some(unknown) = rules.overlay.filter(|_| overhead.is_none()) {
        notes.push(format!(
            "This rdy does not know the header size of the {} overlay, so it did not check the room for it.",
            overlay_name(unknown)
        ));
    }
    let evidence = observed(&facts, rules, default, overhead);
    let thresholds = expected(rules, overhead);
    let (mut finding, mut more) = verdict(&facts, rules, default, overhead);
    notes.append(&mut more);
    finding.observed = evidence;
    finding.expected = thresholds;
    finding.notes = notes;
    finding
}

/// The level, message and fix, with the notes this verdict adds.
fn verdict(
    facts: &Facts,
    rules: &Rules,
    default: Option<&Iface>,
    overhead: Option<u32>,
) -> (Finding, Vec<String>) {
    let mut notes = Vec::new();
    let wants = rules.min_mtu.is_some() || rules.overlay.is_some();
    let Some(chosen) = facts.default.as_ref() else {
        let finding = if wants {
            Finding::warn(
                "No default route was found, so rdy cannot tell which interface carries the pod network.",
            )
            .with_fix(
                "Check the routing table for a default route. If there is none, add it, or tell the vendor which interface carries the traffic.",
            )
        } else {
            Finding::pass(
                "No default route was found. The MTU of each interface is in the evidence.",
            )
        };
        return (finding, notes);
    };
    let name = code(&chosen.iface);
    let Some((iface, mtu)) = default.and_then(|iface| iface.mtu.map(|mtu| (iface, mtu))) else {
        let finding = Finding::warn(format!(
            "The MTU of {name}, the default route interface, could not be read, so it was not checked."
        ))
        .with_fix(
            "Check that /sys is mounted and that the user who runs rdy may read /sys/class/net.",
        );
        return (finding, notes);
    };
    if iface.kind == Kind::Tunnel {
        notes.push(format!(
            "The default route goes through the tunnel interface {name}. Its MTU is usually lower than the MTU of the physical link under it."
        ));
    }
    let known = rules.overlay.zip(overhead);

    // 1. An overlay that does not fit: block.
    if let (Some(min), Some((overlay, over))) = (rules.min_mtu, known) {
        let pod = mtu.saturating_sub(over);
        if pod < min {
            let need = min.saturating_add(over);
            let label = overlay_name(overlay);
            let finding = Finding::fail(format!(
                "{name} has MTU {mtu} and {label} needs {over} bytes, so the pod network must use {pod} or less, and {min} is needed."
            ))
            .with_fix(format!(
                "Raise the MTU of {name} and of the switch ports it connects to, to {need} or more. Set it in your network configuration (netplan, NetworkManager or the ifcfg files) so it survives a reboot. If the network cannot carry that, set the CNI MTU to {pod} or less and ask the vendor if {pod} is enough."
            ));
            return (finding, notes);
        }
    }

    // 2. Below the minimum with no overlay: warn. This runs before the jumbo rule, so a minimum above
    // 1500 does not get advice to lower the MTU.
    if let Some(min) = rules.min_mtu.filter(|min| known.is_none() && mtu < *min) {
        let finding = Finding::warn(format!("{name} has MTU {mtu}, and {min} is needed."))
            .with_fix(format!(
                "Raise the MTU of {name} and of the switch ports it connects to, to {min} or more. Set it in your network configuration (netplan, NetworkManager or the ifcfg files) so it survives a reboot."
            ));
        return (finding, notes);
    }
    // 3. Above 1500: informational, unless the spec asks about the MTU.
    if mtu > ETHERNET_MTU && wants {
        let finding = Finding::warn(format!(
            "{name} has MTU {mtu}, and traffic that leaves the network is clamped to {ETHERNET_MTU}."
        ))
        .with_fix(format!(
            "Make sure ICMP \"fragmentation needed\" (type 3 code 4, and \"packet too big\", type 2, for IPv6) is not filtered between this host and its peers, or set the MTU of {name} to {ETHERNET_MTU} in your network configuration."
        ));
        add_headroom(&mut notes, rules, known, mtu);
        return (finding, notes);
    }

    if rules.min_mtu.is_none() && mtu < SMALL_MTU {
        let finding = Finding::warn(format!(
            "{name} has MTU {mtu}, which is below {SMALL_MTU}. Most networks use {ETHERNET_MTU} or more."
        ))
        .with_fix(format!(
            "Find out why {name} is small. A VPN or a tunnel on the default route is the usual cause. Ask the network team for the right MTU, then set it in your network configuration (netplan, NetworkManager or the ifcfg files)."
        ));
        add_headroom(&mut notes, rules, known, mtu);
        return (finding, notes);
    }

    // 4. Pass. Say what the MTU leaves for the pod network, and note a jumbo MTU.
    let message = match (known, rules.min_mtu) {
        (Some((overlay, over)), Some(min)) => format!(
            "{name} has MTU {mtu}, which leaves {} for the pod network after {over} bytes of {}, and {min} is needed.",
            mtu.saturating_sub(over),
            overlay_name(overlay)
        ),
        (Some((overlay, over)), None) => format!(
            "{name} has MTU {mtu}, which leaves {} for the pod network after {over} bytes of {}.",
            mtu.saturating_sub(over),
            overlay_name(overlay)
        ),
        (None, Some(min)) => format!("{name} has MTU {mtu}, and {min} is needed."),
        (None, None) => format!("{name} has MTU {mtu}."),
    };
    if mtu > ETHERNET_MTU {
        notes.push(format!(
            "MTU {mtu} is above {ETHERNET_MTU} (9001 is the default on EC2). Traffic that leaves the network is clamped to {ETHERNET_MTU}, so make sure ICMP \"fragmentation needed\" is not filtered."
        ));
    }
    add_headroom(&mut notes, rules, known, mtu);
    (Finding::pass(message), notes)
}

/// Tells the reader what MTU the pod network must use, and for Geneve what OVN-Kubernetes needs.
fn add_headroom(notes: &mut Vec<String>, rules: &Rules, known: Option<(Overlay, u32)>, mtu: u32) {
    let Some((overlay, over)) = known else {
        return;
    };
    let pod = mtu.saturating_sub(over);
    if rules.min_mtu.is_none() {
        notes.push(format!(
            "{} takes {over} bytes, so the pod network must use {pod} or less. Set the CNI MTU to {pod} or less.",
            overlay_name(overlay)
        ));
    }
    if let Some(ovn) = ovn_geneve_pod_mtu(overlay, mtu) {
        notes.push(format!(
            "OVN-Kubernetes reserves {OVN_GENEVE_RESERVE} bytes for Geneve, which would leave {ovn} for the pod network."
        ));
    }
}

/// The pod MTU when OVN-Kubernetes carries Geneve on an interface of `mtu`. `None` for any other overlay.
fn ovn_geneve_pod_mtu(overlay: Overlay, mtu: u32) -> Option<u32> {
    (overlay == Overlay::Geneve).then(|| mtu.saturating_sub(OVN_GENEVE_RESERVE))
}

#[cfg(test)]
mod tests;
