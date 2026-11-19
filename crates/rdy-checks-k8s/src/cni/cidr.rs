//! Address ranges: reading `10.96.0.0/12` text from the cluster and deciding whether two ranges overlap.
//!
//! A range from the server is text. It is read with the same grammar as the spec's `avoid_cidrs`: an IPv4
//! address in four plain decimal parts or an IPv6 address without a dotted tail, a slash, and a prefix with
//! no leading zero. Anything else is "not a range" and the caller says so; the text is never put in a
//! command.

use std::net::IpAddr;

/// An address range, with the bits past the prefix cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Net {
    v6: bool,
    bits: u128,
    prefix: u8,
}

impl Net {
    /// Reads `text`, or `None` when it is not a range.
    pub(super) fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = text.split_once('/')?;
        let digits = (1..=3).contains(&prefix.len())
            && prefix.bytes().all(|b| b.is_ascii_digit())
            && !(prefix.len() > 1 && prefix.starts_with('0'));
        if !digits {
            return None;
        }
        let ip = addr.parse::<IpAddr>().ok()?;
        // An IPv6 address with a dotted tail is another spelling of an IPv4 one: not read.
        if ip.is_ipv6() && addr.contains('.') {
            return None;
        }
        Self::new(ip, prefix.parse::<u8>().ok()?)
    }

    /// The range of an address and a prefix length, or `None` when the prefix is too long for the family.
    pub(super) fn new(ip: IpAddr, prefix: u8) -> Option<Self> {
        let (v6, bits, longest) = match ip {
            IpAddr::V4(a) => (false, u128::from(u32::from(a)), 32),
            IpAddr::V6(a) => (true, u128::from(a), 128),
        };
        (prefix <= longest).then(|| {
            let mut net = Self { v6, bits, prefix };
            net.bits &= net.mask();
            net
        })
    }

    /// The mask of the prefix, in the low 32 or 128 bits.
    fn mask(self) -> u128 {
        let width: u32 = if self.v6 { 128 } else { 32 };
        let host = width - u32::from(self.prefix);
        let all = if self.v6 {
            u128::MAX
        } else {
            u128::from(u32::MAX)
        };
        if host >= 128 {
            0
        } else {
            all & !((1_u128 << host) - 1)
        }
    }

    /// True when the two ranges share an address. Ranges of different families never do.
    pub(super) fn overlaps(self, other: Self) -> bool {
        if self.v6 != other.v6 {
            return false;
        }
        let shorter = Self {
            v6: self.v6,
            bits: 0,
            prefix: self.prefix.min(other.prefix),
        }
        .mask();
        (self.bits & shorter) == (other.bits & shorter)
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.v6 {
            write!(f, "{}/{}", std::net::Ipv6Addr::from(self.bits), self.prefix)
        } else {
            let v4 = u32::try_from(self.bits & u128::from(u32::MAX)).unwrap_or(0);
            write!(f, "{}/{}", std::net::Ipv4Addr::from(v4), self.prefix)
        }
    }
}
