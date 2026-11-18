//! The text rules of `net.dns`: which names may reach a command line, and what `getent ahosts` printed.
//!
//! Both are pure. Names come from the spec and the output comes from a program, so neither is trusted.

use std::net::{IpAddr, Ipv6Addr};

use rdy_spec::check::Cidr;

/// The most answers kept for one name. The facade's own lookup keeps 64.
pub(super) const MAX_ANSWERS: usize = 64;

/// The most lines of `getent` output read. Each address prints three lines (`STREAM`, `DGRAM`, `RAW`).
const MAX_LINES: usize = 4 * MAX_ANSWERS;

/// The longest a DNS name is, in bytes (RFC 1035).
const MAX_NAME: usize = 253;

/// Whether `name` may be put on the command line of `getent ahosts -- <name>`.
///
/// The rule is the one in 03 Appendix A: letters, digits, `.`, `_` and `-`, at most 253 bytes, and no
/// leading `-`. The spec parser already enforces a stricter grammar. This is the second check, made at
/// the door of the command, so a name that reached it any other way (a later spec field, a test) still
/// cannot read as an option or carry a space, a quote or a newline. The command table enforces the same
/// rule a third time.
///
/// # Errors
///
/// The reason, as a short phrase for a note.
pub(super) fn validate(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("the name is empty");
    }
    if name.len() > MAX_NAME {
        return Err("the name is longer than 253 bytes");
    }
    if name.starts_with('-') {
        return Err("the name starts with a hyphen, so a command would read it as an option");
    }
    let plain = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if plain {
        Ok(())
    } else {
        Err("the name has a character other than letters, digits, dot, underscore and hyphen")
    }
}

/// The addresses in the output of `getent ahosts <name>`, without repeats, in the order printed.
///
/// `ahosts` prints one line per address and socket type, so a dual-stack name shows each address three
/// times (`STREAM`, `DGRAM`, `RAW`). The first word of a line is the address. An IPv4-mapped IPv6 address
/// is the IPv4 address it carries. A line whose first word is not an address is ignored, and so is every
/// line after the first 256. At most [`MAX_ANSWERS`] are kept.
pub(super) fn addresses(stdout: &str) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for line in stdout.lines().take(MAX_LINES) {
        let Some(word) = line.split_whitespace().next() else {
            continue;
        };
        let Ok(ip) = word.parse::<IpAddr>() else {
            continue;
        };
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        if !out.contains(&ip) && out.len() < MAX_ANSWERS {
            out.push(ip);
        }
    }
    out
}

/// Whether `ip` is inside `range`. An IPv4 address is never inside an IPv6 range, and the reverse.
pub(super) fn in_range(ip: IpAddr, range: Cidr) -> bool {
    match (ip, range.addr()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => same_prefix(
            u128::from(u32::from(a)),
            u128::from(u32::from(b)),
            32,
            range.prefix(),
        ),
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            same_prefix(u128::from(a), u128::from(b), 128, range.prefix())
        }
        _ => false,
    }
}

/// Whether the first `prefix` bits of `a` and `b` (each `bits` wide) are equal.
fn same_prefix(a: u128, b: u128, bits: u32, prefix: u8) -> bool {
    let prefix = u32::from(prefix).min(bits);
    if prefix == 0 {
        return true;
    }
    let shift = bits - prefix;
    (a >> shift) == (b >> shift)
}

/// Whether `ip` is a private-use, loopback or link-local address: the kinds `expect_public: false` asks
/// for and `expect_public: true` refuses. Documentation ranges are not private, so a fixture can use
/// them as public addresses.
pub(super) fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                // 100.64.0.0/10, shared address space (carrier-grade NAT).
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    let first = v6.segments()[0];
    v6.is_loopback()
        || v6.is_unspecified()
        // fc00::/7, unique local.
        || (first & 0xfe00) == 0xfc00
        // fe80::/10, link-local.
        || (first & 0xffc0) == 0xfe80
}

/// What this machine's resolver is set to do, from `/etc/resolv.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Resolver {
    /// Seconds to wait for one nameserver on one attempt (`options timeout:`, default 5, at most 30).
    pub(super) timeout: u64,
    /// Attempts for each nameserver (`options attempts:`, default 2, at most 5).
    pub(super) attempts: u64,
    /// `nameserver` lines, counting at most 3: the glibc resolver ignores the rest.
    pub(super) nameservers: u64,
}

impl Resolver {
    /// The most seconds a lookup can wait before the resolver gives up.
    pub(super) fn worst_case(self) -> u64 {
        self.timeout * self.attempts * self.nameservers.max(1)
    }
}

/// Reads the `nameserver` count and the `options timeout:` and `attempts:` values of a `resolv.conf`.
///
/// Only those three facts are kept. The addresses are not read into the result. A later `options` line
/// overrides an earlier one, as in glibc. Defaults are 5 s and 2 attempts. Lines after the first 200
/// are ignored.
pub(super) fn resolver(text: &str) -> Resolver {
    let mut out = Resolver {
        timeout: 5,
        attempts: 2,
        nameservers: 0,
    };
    for line in text.lines().take(200) {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") if words.next().is_some() => {
                out.nameservers = (out.nameservers + 1).min(3);
            }
            Some("options") => {
                for word in words {
                    if let Some(n) = word.strip_prefix("timeout:") {
                        if let Ok(n) = n.parse::<u64>() {
                            out.timeout = n.min(30);
                        }
                    } else if let Some(n) = word.strip_prefix("attempts:")
                        && let Ok(n) = n.parse::<u64>()
                    {
                        out.attempts = n.clamp(1, 5);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn range(text: &str) -> Cidr {
        serde_json::from_value(serde_json::json!(text)).expect("a range")
    }

    #[test]
    fn plain_names_pass_and_option_shaped_or_odd_names_do_not() {
        for ok in ["a.acme.test", "A_b-c.example", "x", "a.b.c.d.e"] {
            assert_eq!(validate(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "-x",
            "--help",
            "-",
            "a b",
            "a\nb",
            "a;b",
            "a$(b)",
            "a`b",
            "a\"b",
            "a/b",
            "a:b",
            "a\u{e9}.test",
            "a\0b",
        ] {
            assert!(validate(bad).is_err(), "{bad:?}");
        }
        assert!(validate(&"a".repeat(254)).is_err());
        assert_eq!(validate(&"a".repeat(253)), Ok(()));
    }

    #[test]
    fn a_dual_stack_name_is_three_rows_per_address_and_dedupes() {
        let out = "\
2001:db8::10    STREAM web.acme.test\n\
2001:db8::10    DGRAM\n\
2001:db8::10    RAW\n\
192.0.2.10      STREAM\n\
192.0.2.10      DGRAM\n\
192.0.2.10      RAW\n";
        assert_eq!(addresses(out), [ip("2001:db8::10"), ip("192.0.2.10")]);
    }

    #[test]
    fn mapped_addresses_become_ipv4_and_junk_lines_are_ignored() {
        let out = "::ffff:192.0.2.7 STREAM a\nnot-an-address STREAM\n\n   \n192.0.2.7 DGRAM\n";
        assert_eq!(addresses(out), [ip("192.0.2.7")]);
    }

    #[test]
    fn answers_are_capped() {
        let mut out = String::new();
        for n in 0..200 {
            out.push_str(&format!("10.0.{}.{} STREAM\n", n / 250, n % 250));
        }
        assert_eq!(addresses(&out).len(), MAX_ANSWERS);
    }

    #[test]
    fn ranges_and_private_kinds() {
        assert!(in_range(ip("10.1.2.3"), range("10.0.0.0/8")));
        assert!(!in_range(ip("11.0.0.1"), range("10.0.0.0/8")));
        assert!(in_range(ip("192.0.2.9"), range("0.0.0.0/0")));
        assert!(!in_range(ip("2001:db8::1"), range("10.0.0.0/8")));
        assert!(in_range(ip("fd00::5"), range("fd00::/8")));
        assert!(!in_range(ip("fe80::1"), range("fd00::/8")));
        for private in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(is_private(ip(private)), "{private}");
        }
        for public in [
            "192.0.2.1",
            "198.51.100.1",
            "2001:db8::1",
            "100.128.0.1",
            "8.8.8.8",
        ] {
            assert!(!is_private(ip(public)), "{public}");
        }
    }

    #[test]
    fn resolv_conf_options_override_and_cap() {
        let r = resolver(
            "# c\nnameserver 192.0.2.1\nnameserver 192.0.2.2\noptions timeout:2 rotate\noptions attempts:3\n",
        );
        assert_eq!((r.timeout, r.attempts, r.nameservers), (2, 3, 2));
        assert_eq!(r.worst_case(), 12);
        let none = resolver("search acme.test\n");
        assert_eq!((none.timeout, none.attempts, none.nameservers), (5, 2, 0));
        assert_eq!(none.worst_case(), 10);
        let many = resolver(
            "nameserver a\nnameserver b\nnameserver c\nnameserver d\noptions timeout:99 attempts:0",
        );
        assert_eq!((many.timeout, many.attempts, many.nameservers), (30, 1, 3));
        let junk = resolver("options timeout:x attempts:\nnameserver\n");
        assert_eq!((junk.timeout, junk.attempts, junk.nameservers), (5, 2, 0));
    }

    proptest! {
        #[test]
        fn parsing_never_panics_and_stays_bounded(text in ".{0,4000}") {
            prop_assert!(addresses(&text).len() <= MAX_ANSWERS);
        }

        #[test]
        fn an_accepted_name_has_only_plain_bytes(name in ".{0,300}") {
            if validate(&name).is_ok() {
                prop_assert!(!name.starts_with('-'));
                prop_assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
            }
        }
    }
}
