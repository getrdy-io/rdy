//! The `NO_PROXY` matcher (M1-098, ADR 0014, 05 INV-11).
//!
//! One documented rule set, shared by `net.egress`, `net.proxy` and the Kubernetes client. It follows
//! Go's `httpproxy` package, which most products written in Go use, plus the CIDR forms curl reads:
//!
//! - Entries are separated by commas. Blanks and case are ignored. Each entry is cut at 253 characters.
//! - `*` exempts every host.
//! - `host` exempts that host and its subdomains. `.suffix` and `*.suffix` exempt subdomains only.
//! - `host:port` exempts that port only. `[::1]:8080` and a bare `::1` are IPv6 literals.
//! - `10.0.0.0/8` exempts every address in the network. An IPv6 network works the same way.
//! - `localhost` and loopback addresses never use a proxy, whatever the list says.
//! - An entry with a port that is not a number matches nothing, not even the bare name.
//!
//! A host name is matched as written. rdy never resolves a name to test it against a CIDR entry, because
//! the proxy, not this machine, resolves it. The list is bounded: at most [`MAX_ENTRIES`] entries and
//! [`MAX_LIST_BYTES`] bytes are read, and [`NoProxy::truncated`] says when more was written.
//!
//! The list can name internal hosts, so a caller shows an entry only where the customer needs it (a
//! coverage line, the entry that exempted a host) and never the whole list in a log.

use std::fmt;
use std::net::IpAddr;

/// The most entries read from one list.
pub const MAX_ENTRIES: usize = 256;

/// The most bytes read from one list.
pub const MAX_LIST_BYTES: usize = 8 * 1024;

/// The longest entry kept, in characters.
pub const MAX_ENTRY_CHARS: usize = 253;

/// Why a host does not use the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Exemption {
    /// `localhost` or a loopback address: never proxied.
    Loopback,
    /// The list is `*`.
    All,
    /// This entry of the list covers the host. It is lower case and cut to [`MAX_ENTRY_CHARS`].
    Entry(String),
}

impl fmt::Display for Exemption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loopback => f.write_str("loopback addresses never use a proxy"),
            Self::All => f.write_str("NO_PROXY is *"),
            Self::Entry(entry) => write!(f, "NO_PROXY entry \"{entry}\" covers the host"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    All,
    Cidr(IpAddr, u8),
    Ip(IpAddr),
    /// A name. `domain` has no leading dot. `dotted` is set for `.x` and `*.x`: subdomains only.
    Name {
        domain: String,
        dotted: bool,
    },
    /// An entry that can match nothing: a port that is not a number, an empty name, a bad prefix.
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    text: String,
    port: Option<u16>,
    kind: Kind,
}

/// A parsed `NO_PROXY` list.
///
/// ```
/// use rdy_engine::probe::{Exemption, NoProxy};
/// let list = NoProxy::parse("10.0.0.0/8, .svc, registry.acme.example:5000");
/// assert!(list.exempts("10.1.2.3", 443).is_some());
/// assert_eq!(list.exempts("api.svc", 443), Some(Exemption::Entry(".svc".to_owned())));
/// assert!(list.exempts("registry.acme.example", 443).is_none());
/// assert_eq!(list.exempts("localhost", 80), Some(Exemption::Loopback));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoProxy {
    entries: Vec<Entry>,
    truncated: bool,
}

impl NoProxy {
    /// Reads a list. It never fails: an entry that can match nothing is kept (so a report can show that
    /// it exists) and never matches.
    #[must_use]
    pub fn parse(list: &str) -> Self {
        let mut truncated = list.len() > MAX_LIST_BYTES;
        let end = if truncated {
            // Cut at a character boundary, and at a comma so a half entry is not read.
            let mut at = MAX_LIST_BYTES;
            while !list.is_char_boundary(at) {
                at -= 1;
            }
            list[..at].rfind(',').unwrap_or(at)
        } else {
            list.len()
        };
        let mut entries = Vec::new();
        for raw in list[..end].split(',') {
            let text = raw.trim().to_ascii_lowercase();
            if text.is_empty() {
                continue;
            }
            if entries.len() == MAX_ENTRIES {
                truncated = true;
                break;
            }
            entries.push(Entry::parse(&text));
        }
        Self { entries, truncated }
    }

    /// Whether the list has no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries were read.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list had more than [`MAX_ENTRIES`] entries or [`MAX_LIST_BYTES`] bytes, so the
    /// rest was not read.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// The entries, lower case, in the order written.
    pub fn entries(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.text.as_str())
    }

    /// Why `host` and `port` do not use the proxy, or `None` when they do. `host` may be a name, an
    /// IPv4 address, or an IPv6 address with or without brackets. Case and a trailing dot are ignored.
    #[must_use]
    pub fn exempts(&self, host: &str, port: u16) -> Option<Exemption> {
        let host = normal_host(host);
        if is_loopback(&host) {
            return Some(Exemption::Loopback);
        }
        let ip = host.parse::<IpAddr>().ok();
        for entry in &self.entries {
            if entry.matches(&host, ip, port) {
                return Some(match entry.kind {
                    Kind::All => Exemption::All,
                    _ => Exemption::Entry(entry.text.clone()),
                });
            }
        }
        None
    }

    /// The first entry of the list that covers everything `required` covers, or `None`. `required` is
    /// written as an entry is (`.svc`, `10.0.0.0/8`, `169.254.169.254`, `registry.acme.example:5000`).
    /// It is how `net.proxy` says whether `NO_PROXY` covers a name or a network the vendor needs
    /// direct. A name is never compared with a CIDR entry, because rdy does not resolve it.
    #[must_use]
    pub fn covers(&self, required: &str) -> Option<&str> {
        let wanted = Entry::parse(&required.trim().to_ascii_lowercase());
        if matches!(wanted.kind, Kind::Never) {
            return None;
        }
        self.entries
            .iter()
            .find(|listed| listed.subsumes(&wanted))
            .map(|listed| listed.text.as_str())
    }
}

impl Entry {
    fn parse(text: &str) -> Self {
        let text: String = text.chars().take(MAX_ENTRY_CHARS).collect();
        let never = |text: String| Self {
            text,
            port: None,
            kind: Kind::Never,
        };
        if text == "*" {
            return Self {
                text,
                port: None,
                kind: Kind::All,
            };
        }
        if let Some((net, bits)) = text.split_once('/') {
            // A port is not part of a network entry, as in Go.
            return match (
                net.trim_matches(['[', ']']).parse::<IpAddr>(),
                bits.parse::<u8>(),
            ) {
                (Ok(net), Ok(bits)) if bits <= max_bits(net) => {
                    let kind = Kind::Cidr(net, bits);
                    Self {
                        text,
                        port: None,
                        kind,
                    }
                }
                _ => never(text),
            };
        }
        let Some((name, port)) = split_port(&text) else {
            return never(text);
        };
        let (name, port) = (name.to_owned(), port);
        if name.is_empty() {
            return never(text);
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Self {
                text,
                port,
                kind: Kind::Ip(ip),
            };
        }
        let (domain, dotted) = match name.strip_prefix("*.").or_else(|| name.strip_prefix('.')) {
            Some(rest) => (rest.trim_end_matches('.').to_owned(), true),
            None => (name.trim_end_matches('.').to_owned(), false),
        };
        if domain.is_empty() {
            return never(text);
        }
        Self {
            text,
            port,
            kind: Kind::Name { domain, dotted },
        }
    }

    fn matches(&self, host: &str, ip: Option<IpAddr>, port: u16) -> bool {
        if self.port.is_some_and(|wanted| wanted != port) {
            return false;
        }
        match &self.kind {
            Kind::All => true,
            Kind::Cidr(net, bits) => ip.is_some_and(|ip| cidr_contains(*net, *bits, ip)),
            Kind::Ip(listed) => ip == Some(*listed),
            Kind::Name { domain, dotted } => {
                if ip.is_some() {
                    return false;
                }
                let tail_dot = format!(".{domain}");
                host.ends_with(&tail_dot) || (!dotted && host == domain)
            }
            Kind::Never => false,
        }
    }

    /// Whether everything `wanted` matches is also matched by this entry.
    fn subsumes(&self, wanted: &Self) -> bool {
        if let Kind::All = self.kind {
            return true;
        }
        // A listed port covers that port only. No listed port covers any.
        if self.port.is_some() && self.port != wanted.port {
            return false;
        }
        match (&self.kind, &wanted.kind) {
            (Kind::Cidr(net, bits), Kind::Cidr(inner, inner_bits)) => {
                bits <= inner_bits && cidr_contains(*net, *bits, *inner)
            }
            (Kind::Cidr(net, bits), Kind::Ip(ip)) => cidr_contains(*net, *bits, *ip),
            (Kind::Ip(a), Kind::Ip(b)) => a == b,
            (
                Kind::Name {
                    domain: have,
                    dotted: have_dotted,
                },
                Kind::Name {
                    domain: need,
                    dotted: need_dotted,
                },
            ) => {
                // `need` is every name below `need` (and `need` itself when it is not dotted). The listed
                // entry covers all of them when it is `need`'s own domain, or a parent of it. A dotted
                // entry leaves out the bare domain, which only a dotted `need` does too.
                need.ends_with(&format!(".{have}"))
                    || (have == need && (!have_dotted || *need_dotted))
            }
            _ => false,
        }
    }
}

fn max_bits(net: IpAddr) -> u8 {
    if net.is_ipv4() { 32 } else { 128 }
}

/// Lower case, no brackets, no trailing dot.
fn normal_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// `localhost` and loopback addresses. Go never proxies them.
fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

/// Splits `name:port`, `[v6]:port` and `[v6]`. An unbracketed IPv6 literal has no port. `None` for an
/// entry whose port is not a number (`host:abc`, `host:`), which matches nothing.
fn split_port(entry: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = entry.strip_prefix('[') {
        let Some((name, after)) = rest.split_once(']') else {
            return Some((entry, None));
        };
        if after.is_empty() {
            return Some((name, None));
        }
        let port = after.strip_prefix(':')?.parse().ok()?;
        return Some((name, Some(port)));
    }
    if entry.matches(':').count() == 1
        && let Some((name, port)) = entry.split_once(':')
    {
        return port.parse().ok().map(|port| (name, Some(port)));
    }
    Some((entry, None))
}

/// Whether `ip` is inside the network `net`/`bits`. A family mismatch or a prefix too long is no match.
fn cidr_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
