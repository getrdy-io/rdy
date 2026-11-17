//! The default route, read from `/proc/net/route` and `/proc/net/ipv6_route`.
//!
//! Both files are tables of hex fields. A line that does not have the expected shape is skipped, never
//! an error: a table that holds one odd line still has a default route. At most [`MAX_LINES`] lines are
//! read, so a router with a full table costs a bounded amount of work.
//!
//! Among the default routes, the lowest metric wins and the first line breaks a tie, which is the order
//! the kernel uses for the same destination.

/// The most lines of a route table that are looked at.
const MAX_LINES: usize = 4096;

/// `RTF_UP`: the route is usable.
const RTF_UP: u64 = 0x0001;

/// `RTF_REJECT`: the route answers "unreachable". IPv6 keeps one such default route on `lo`.
const RTF_REJECT: u64 = 0x0200;

/// The default route that traffic would use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DefaultRoute {
    /// The interface name, as the table wrote it.
    pub iface: String,
    /// The route metric. Lower wins.
    pub metric: u64,
}

/// Keeps the better of two candidates: the lower metric, and the earlier one on a tie.
fn better(best: Option<DefaultRoute>, candidate: DefaultRoute) -> Option<DefaultRoute> {
    match best {
        Some(current) if current.metric <= candidate.metric => Some(current),
        _ => Some(candidate),
    }
}

/// The IPv4 default route from `/proc/net/route`.
///
/// The columns are `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT`. A default
/// route has destination and mask `00000000` and the `RTF_UP` flag.
pub(super) fn default_v4(text: &str) -> Option<DefaultRoute> {
    let mut best = None;
    for line in text.lines().take(MAX_LINES) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [
            iface,
            destination,
            _gateway,
            flags,
            _refs,
            _use,
            metric,
            mask,
            ..,
        ] = fields[..]
        else {
            continue;
        };
        if destination != "00000000" || mask != "00000000" {
            continue;
        }
        let Ok(flags) = u64::from_str_radix(flags, 16) else {
            continue;
        };
        let Ok(metric) = metric.parse::<u64>() else {
            continue;
        };
        if flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
            continue;
        }
        best = better(
            best,
            DefaultRoute {
                iface: iface.to_owned(),
                metric,
            },
        );
    }
    best
}

/// The IPv6 default route from `/proc/net/ipv6_route`.
///
/// The columns are `dest plen src slen nexthop metric refcnt use flags iface`, all hex, with 32 digits
/// for an address. A default route has an all-zero destination, prefix length `00` and `RTF_UP`. A
/// reject route is not a default route.
pub(super) fn default_v6(text: &str) -> Option<DefaultRoute> {
    let mut best = None;
    for line in text.lines().take(MAX_LINES) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [
            destination,
            prefix,
            _src,
            _src_len,
            _next_hop,
            metric,
            _refs,
            _use,
            flags,
            iface,
            ..,
        ] = fields[..]
        else {
            continue;
        };
        if prefix != "00" || destination.len() != 32 || !destination.bytes().all(|b| b == b'0') {
            continue;
        }
        let Ok(flags) = u64::from_str_radix(flags, 16) else {
            continue;
        };
        let Ok(metric) = u64::from_str_radix(metric, 16) else {
            continue;
        };
        if flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
            continue;
        }
        best = better(
            best,
            DefaultRoute {
                iface: iface.to_owned(),
                metric,
            },
        );
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const V4_HEADER: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";

    fn v4(lines: &[&str]) -> Option<DefaultRoute> {
        default_v4(&format!("{V4_HEADER}{}\n", lines.join("\n")))
    }

    fn route(iface: &str, metric: u64) -> Option<DefaultRoute> {
        Some(DefaultRoute {
            iface: iface.to_owned(),
            metric,
        })
    }

    #[test]
    fn the_default_route_is_found() {
        let found = v4(&[
            "eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0",
            "eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0",
        ]);
        assert_eq!(found, route("eth0", 100));
    }

    #[test]
    fn the_lowest_metric_wins_and_the_first_line_breaks_a_tie() {
        let found = v4(&[
            "eth0\t00000000\t0100000A\t0003\t0\t0\t600\t00000000\t0\t0\t0",
            "eth1\t00000000\t0100000B\t0003\t0\t0\t100\t00000000\t0\t0\t0",
            "eth2\t00000000\t0100000C\t0003\t0\t0\t100\t00000000\t0\t0\t0",
        ]);
        assert_eq!(found, route("eth1", 100));
    }

    #[test]
    fn a_route_that_is_down_or_rejects_is_not_a_default_route() {
        assert_eq!(
            v4(&["eth0\t00000000\t0100000A\t0002\t0\t0\t100\t00000000\t0\t0\t0"]),
            None
        );
        assert_eq!(
            v4(&["eth0\t00000000\t0100000A\t0201\t0\t0\t100\t00000000\t0\t0\t0"]),
            None
        );
    }

    #[test]
    fn a_host_route_to_zero_is_not_a_default_route() {
        assert_eq!(
            v4(&["eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00FFFFFF\t0\t0\t0"]),
            None
        );
    }

    #[test]
    fn odd_lines_are_skipped() {
        let found = v4(&[
            "garbage",
            "eth0\t00000000\t0100000A\tzz\t0\t0\t100\t00000000",
            "eth0\t00000000\t0100000A\t0003\t0\t0\tx\t00000000",
            "eth3\t00000000\t0100000A\t0003\t0\t0\t7\t00000000\t0\t0\t0",
        ]);
        assert_eq!(found, route("eth3", 7));
    }

    const ZERO: &str = "00000000000000000000000000000000";

    fn v6(lines: &[String]) -> Option<DefaultRoute> {
        default_v6(&lines.join("\n"))
    }

    fn v6_line(iface: &str, metric: &str, flags: &str) -> String {
        format!(
            "{ZERO} 00 {ZERO} 00 fe800000000000000000000000000001 {metric} 00000001 00000000 {flags} {iface}"
        )
    }

    #[test]
    fn the_ipv6_default_route_is_found() {
        let found = v6(&[v6_line("eth0", "00000400", "00450003")]);
        assert_eq!(found, route("eth0", 0x400));
    }

    #[test]
    fn the_ipv6_reject_route_on_lo_is_not_a_default_route() {
        let found = v6(&[v6_line("lo", "ffffffff", "00200200")]);
        assert_eq!(found, None);
    }

    #[test]
    fn the_lowest_ipv6_metric_wins() {
        let found = v6(&[
            v6_line("eth0", "00000400", "00450003"),
            v6_line("eth1", "00000100", "00450003"),
        ]);
        assert_eq!(found, route("eth1", 0x100));
    }

    #[test]
    fn an_ipv6_route_with_a_prefix_is_not_a_default_route() {
        let line = format!("{ZERO} 40 {ZERO} 00 {ZERO} 00000100 00000001 00000000 00000001 eth0");
        assert_eq!(default_v6(&line), None);
    }

    proptest! {
        #[test]
        fn route_text_never_panics(text in ".{0,2000}") {
            let _ = default_v4(&text);
            let _ = default_v6(&text);
        }
    }
}
