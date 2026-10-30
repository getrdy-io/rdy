//! The interface that carries the default route, from `/proc/net/route` and `/proc/net/ipv6_route`.
//!
//! These are plain tables. Reading them needs no `ip` and no root. The firewalld zone that matters
//! for an install is the zone of this interface.

/// Route flag `RTF_UP`.
const RTF_UP: u32 = 0x1;
/// Route flag `RTF_REJECT` (an IPv6 blackhole entry, not a real gateway).
const RTF_REJECT: u32 = 0x200;
/// The most rows read from either table.
const MAX_ROWS: usize = 4096;

/// The interface of the best default route: IPv4 first, IPv6 when there is no IPv4 default.
pub(super) fn default_interface(v4: Option<&str>, v6: Option<&str>) -> Option<String> {
    v4.and_then(default_v4).or_else(|| v6.and_then(default_v6))
}

/// `Iface Destination Gateway Flags RefCnt Use Metric Mask ...`, numbers in hex except the metric.
fn default_v4(table: &str) -> Option<String> {
    let mut best: Option<(u32, &str)> = None;
    for line in table.lines().skip(1).take(MAX_ROWS) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(iface), Some(dest), Some(flags), Some(metric), Some(mask)) =
            (f.first(), f.get(1), f.get(3), f.get(6), f.get(7))
        else {
            continue;
        };
        let up = u32::from_str_radix(flags, 16).is_ok_and(|n| n & RTF_UP != 0);
        if *dest != "00000000" || *mask != "00000000" || !up {
            continue;
        }
        let metric = metric.parse::<u32>().unwrap_or(u32::MAX);
        if best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, iface));
        }
    }
    best.map(|(_, iface)| iface.to_owned())
}

/// `dest plen src plen nexthop metric refcnt use flags iface`, all hex.
fn default_v6(table: &str) -> Option<String> {
    let mut best: Option<(u32, &str)> = None;
    for line in table.lines().take(MAX_ROWS) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(dest), Some(plen), Some(metric), Some(flags), Some(iface)) =
            (f.first(), f.get(1), f.get(5), f.get(8), f.get(9))
        else {
            continue;
        };
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        let default = dest.bytes().all(|b| b == b'0') && *plen == "00";
        if !default || flags & RTF_UP == 0 || flags & RTF_REJECT != 0 || *iface == "lo" {
            continue;
        }
        let metric = u32::from_str_radix(metric, 16).unwrap_or(u32::MAX);
        if best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, iface));
        }
    }
    best.map(|(_, iface)| iface.to_owned())
}
