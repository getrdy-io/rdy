//! The ephemeral port range and the reserved ports.
//!
//! `/proc/sys/net/ipv4/ip_local_port_range` holds two numbers, such as `32768 60999`. The kernel picks
//! the source port of an outgoing connection from that range, so a required port inside it can be taken
//! at any moment. `/proc/sys/net/ipv4/ip_local_reserved_ports` lists ports the kernel leaves out of the
//! pick, such as `6443,8000-8010`. The same two files serve TCP and UDP.

/// The most reserved-port items read.
const MAX_ITEMS: usize = 1024;

/// An inclusive range of ports.
pub(crate) type Span = (u16, u16);

/// The range in the text of `ip_local_port_range`. `None` when it does not hold two numbers in order.
pub(crate) fn parse_range(text: &str) -> Option<Span> {
    let mut numbers = text.split_whitespace();
    let low = numbers.next()?.parse::<u16>().ok()?;
    let high = numbers.next()?.parse::<u16>().ok()?;
    (numbers.next().is_none() && low <= high).then_some((low, high))
}

/// The ports in the text of `ip_local_reserved_ports`: items split by commas, each `6443` or
/// `8000-8010`. An item that is not one of those is left out. The flag says the whole value was read:
/// it is `false` when there are more than [`MAX_ITEMS`] items, and then a line built from the spans
/// would drop some of the reserved ports.
pub(crate) fn parse_reserved(text: &str) -> (Vec<Span>, bool) {
    let items: Vec<&str> = text.trim().split(',').collect();
    let complete = items.len() <= MAX_ITEMS;
    let spans = items
        .into_iter()
        .take(MAX_ITEMS)
        .filter_map(|item| {
            let item = item.trim();
            match item.split_once('-') {
                Some((low, high)) => {
                    let low = low.trim().parse::<u16>().ok()?;
                    let high = high.trim().parse::<u16>().ok()?;
                    (low <= high).then_some((low, high))
                }
                None => item.parse::<u16>().ok().map(|port| (port, port)),
            }
        })
        .collect();
    (spans, complete)
}

/// Whether `port` is in one of the spans.
pub(crate) fn contains(spans: &[Span], port: u16) -> bool {
    spans
        .iter()
        .any(|(low, high)| (*low..=*high).contains(&port))
}

/// Whether the kernel may hand `port` to an outgoing connection: it is in the range and not reserved.
pub(crate) fn exposed(range: Span, reserved: &[Span], port: u16) -> bool {
    (range.0..=range.1).contains(&port) && !contains(reserved, port)
}

/// The value for `ip_local_reserved_ports`: what is reserved now plus `add`, sorted, with overlapping
/// and touching spans joined (`6443,8000-8010`). A new file under `/etc/sysctl.d` replaces the value of
/// an older one, so the line must keep what is reserved already.
pub(crate) fn merged_value(existing: &[Span], add: &[u16]) -> String {
    let mut spans: Vec<Span> = existing.to_vec();
    spans.extend(add.iter().map(|port| (*port, *port)));
    spans.sort_unstable();
    let mut joined: Vec<Span> = Vec::new();
    for (low, high) in spans {
        match joined.last_mut() {
            Some(last) if u32::from(low) <= u32::from(last.1) + 1 => last.1 = last.1.max(high),
            _ => joined.push((low, high)),
        }
    }
    joined
        .iter()
        .map(|(low, high)| {
            if low == high {
                low.to_string()
            } else {
                format!("{low}-{high}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}
