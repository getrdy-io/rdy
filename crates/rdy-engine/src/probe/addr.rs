//! The address rules for datagrams (INV-12, ADR 0014 decision 2).
//!
//! [`is_forbidden`] is the one table of addresses that no probe call may reach, literal or resolved.
//! [`is_unusable_peer`] adds what a datagram must also never go to: an unspecified, multicast or
//! broadcast address. A datagram to one of those is not a request to a named server.
//!
//! Loopback and private ranges are allowed. A spec may name a server on the customer's own network, and
//! the fixture suite runs on loopback.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `addr` is in a range that no call may reach: 169.254.0.0/16 (link-local and the cloud
/// metadata address), 100.100.100.200/32 (Alibaba Cloud metadata), 168.63.129.16/32 (the Azure
/// host-services address, M1-094), fe80::/10, fd00:ec2::/64 (AWS IPv6 metadata), fd20:ce::254/128 (GCP
/// IPv6 metadata, M1-094), and the IPv4-mapped, IPv4-compatible and `64:ff9b::/96` forms of each IPv4
/// range.
pub(crate) fn is_forbidden(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

/// Whether a datagram must never be sent to `addr`: [`is_forbidden`], or an unspecified, multicast or
/// broadcast address (including the same addresses in an embedded IPv4 form).
pub(crate) fn is_unusable_peer(addr: IpAddr) -> bool {
    if is_forbidden(addr) {
        return true;
    }
    match addr {
        IpAddr::V4(v4) => unusable_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.is_multicast() || embedded_v4(v6).is_some_and(unusable_v4)
        }
    }
}

fn forbidden_v4(addr: Ipv4Addr) -> bool {
    addr.is_link_local() || addr == ALIYUN_METADATA || addr == AZURE_HOST_SERVICES
}

/// The Alibaba Cloud metadata address.
const ALIYUN_METADATA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);

/// The Azure host-services address (WireServer and the virtual DNS address). Its HTTP side serves the
/// VM agent's extension settings and certificates, so it is refused like the metadata addresses. No
/// check has a reason to reach it: the system resolver may use it, but that is the OS, not a facade
/// connect. The decision and its residual are in 05 (M1-094).
const AZURE_HOST_SERVICES: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);

/// The GCP IPv6 metadata address `fd20:ce::254`.
const GCP_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254);

fn unusable_v4(addr: Ipv4Addr) -> bool {
    addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast()
}

fn forbidden_v6(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();
    // fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // fd00:ec2::/64
    if segments[..4] == [0xfd00, 0x0ec2, 0, 0] {
        return true;
    }
    // fd20:ce::254/128
    if addr == GCP_METADATA_V6 {
        return true;
    }
    embedded_v4(addr).is_some_and(forbidden_v4)
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`) or
/// `64:ff9b::/96` address.
fn embedded_v4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = addr.segments();
    let o = addr.octets();
    let low = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    let mapped = s[..5] == [0; 5] && s[5] == 0xffff;
    // `::` and `::1` are not IPv4-compatible addresses.
    let compatible = s[..6] == [0; 6] && (s[6] != 0 || s[7] > 1);
    let nat64 = s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0];
    (mapped || compatible || nat64).then_some(low)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    #[test]
    fn forbidden_table() {
        for text in [
            "169.254.169.254",
            "169.254.0.1",
            "100.100.100.200",
            "fe80::1",
            "febf::1",
            "fd00:ec2::254",
            "fd20:ce::254",
            "FD20:00CE:0:0:0:0:0:0254",
            "168.63.129.16",
            "::ffff:168.63.129.16",
            "::168.63.129.16",
            "64:ff9b::a83f:8110",
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "::ffff:100.100.100.200",
            "64:ff9b::6464:64c8",
        ] {
            assert!(is_forbidden(ip(text)), "{text} must be forbidden");
        }
    }

    #[test]
    fn ordinary_addresses_pass() {
        for text in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "8.8.8.8",
            "100.100.100.201",
            "169.253.0.1",
            "::1",
            "2001:db8::1",
            "fec0::1",
            "fd00:ec3::1",
            "fd20:ce::255",
            "fd20:cf::254",
            "fd20:ce::1:254",
            "168.63.129.15",
            "168.63.129.17",
            "168.63.128.16",
            "::ffff:10.0.0.1",
            "64:ff9b::808:808",
        ] {
            assert!(!is_forbidden(ip(text)), "{text} must pass");
            assert!(!is_unusable_peer(ip(text)), "{text} must pass for udp");
        }
    }

    #[test]
    fn datagrams_also_refuse_unspecified_multicast_and_broadcast() {
        for text in [
            "0.0.0.0",
            "224.0.0.251",
            "239.255.255.250",
            "255.255.255.255",
            "::",
            "ff02::1",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
        ] {
            assert!(is_unusable_peer(ip(text)), "{text} must be refused");
        }
    }
}
