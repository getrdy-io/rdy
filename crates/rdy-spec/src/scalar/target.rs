//! [`Target`]: a network endpoint a check talks to.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ScalarError;

/// The longest target, in bytes, as in the JSON schema.
const MAX_LEN: usize = 512;

/// The longest host name, in bytes (RFC 1035).
const MAX_HOST_LEN: usize = 253;

/// The longest label of a host name, in bytes (RFC 1035).
const MAX_LABEL_LEN: usize = 63;

/// What is wrong with a refused target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TargetProblem {
    /// There is nothing to read.
    #[error("it is empty")]
    Empty,
    /// It is longer than 512 bytes.
    #[error("it is longer than 512 bytes")]
    TooLong,
    /// It has a space, a control character, a backslash or a character outside ASCII.
    #[error("it has a space, a control character, a backslash or a non-ASCII character")]
    InvalidCharacter,
    /// A `host:port` has no port.
    #[error("it has no port")]
    MissingPort,
    /// The port is not a number from 1 to 65535.
    #[error("the port is not a number from 1 to 65535")]
    BadPort,
    /// The host is not a valid host name.
    #[error("the host is not a valid host name")]
    BadHost,
    /// The IPv6 address is malformed, or it is not in square brackets.
    #[error("the IPv6 address is malformed or has no square brackets")]
    BadIpv6,
    /// A URL carries a user name or password.
    #[error("the URL carries a user name or password")]
    Credentials,
    /// A URL has a `#fragment`.
    #[error("the URL has a fragment")]
    Fragment,
    /// The URL scheme is not lowercase `http` or `https`.
    #[error("the URL scheme is not http or https")]
    BadScheme,
}

impl TargetProblem {
    /// The fix line for this problem. Never empty.
    #[must_use]
    pub fn hint(self) -> &'static str {
        match self {
            Self::Empty => "write a target such as 'registry.acme.example:443'.",
            Self::TooLong => "use at most 512 characters.",
            Self::InvalidCharacter => {
                "use plain ASCII with no spaces. For a non-ASCII host name write its punycode form."
            }
            Self::MissingPort => "add the port, such as 'registry.acme.example:443'.",
            Self::BadPort => "use a port from 1 to 65535 with no leading zero, such as ':443'.",
            Self::BadHost => {
                "use letters, digits, hyphens and dots, such as 'registry.acme.example'."
            }
            Self::BadIpv6 => {
                "put an IPv6 address in square brackets with a port, such as '[::1]:443'."
            }
            Self::Credentials => {
                "remove the user name and password. A spec never carries credentials."
            }
            Self::Fragment => "remove the '#' and everything after it.",
            Self::BadScheme => {
                "use a lowercase 'http://' or 'https://' URL, or write 'host:port' without a scheme."
            }
        }
    }
}

/// The host part of a [`Target`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Host {
    /// A DNS name or an IPv4 address, in lowercase.
    Name(String),
    /// An IPv6 address.
    Ipv6(Ipv6Addr),
}

impl fmt::Display for Host {
    /// Writes the host as it appears in a target: an IPv6 address is in square brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Ipv6(addr) => write!(f, "[{addr}]"),
        }
    }
}

/// An endpoint a check talks to: `host:port`, `[v6]:port`, or an `http://` or `https://` URL.
///
/// - The port is 1 to 65535, with no leading zero. A `host:port` always has one.
/// - A URL may leave the port out. [`Target::port`] then gives 80 or 443.
/// - A host name has letters, digits, hyphens and dots, at most 253 bytes, and is kept in lowercase.
/// - An IPv6 address is in square brackets. It is parsed, and `Display` prints it in its short form.
/// - The text is ASCII only, with no spaces, and at most 512 bytes.
/// - A URL with a user name or password is refused, and so is a URL with a `#fragment`. The scheme must
///   be lowercase.
/// - The path and query of a URL are kept as written. Query strings never enter the action log, so a
///   caller that logs a target uses [`Target::host`] and [`Target::port`], not the whole text.
///
/// This type checks the shape only. Link-local and metadata addresses parse. The egress policy refuses
/// them at run time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Target {
    scheme: Option<Scheme>,
    host: Host,
    /// The port as written. `None` only for a URL without one.
    port: Option<u16>,
    /// For a URL, everything after the authority: empty, or starting with `/` or `?`.
    tail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Scheme {
    Http,
    Https,
}

impl Target {
    /// Reads a target such as `registry.acme.example:443`.
    ///
    /// # Errors
    ///
    /// Returns [`ScalarError::InvalidTarget`] when `text` does not fit the grammar.
    pub fn parse(text: &str) -> Result<Self, ScalarError> {
        Self::check(text).map_err(|p| ScalarError::target(text, p))
    }

    /// The host.
    #[must_use]
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The port, 1 to 65535. A URL without a port gives 80 for `http` and 443 for `https`.
    #[must_use]
    pub fn port(&self) -> u16 {
        match (self.port, self.scheme) {
            (Some(port), _) => port,
            (None, Some(Scheme::Http)) => 80,
            (None, _) => 443,
        }
    }

    /// True for an `http://` or `https://` URL.
    #[must_use]
    pub fn is_url(&self) -> bool {
        self.scheme.is_some()
    }

    /// `http` or `https` for a URL, and `None` for a `host:port`.
    #[must_use]
    pub fn scheme(&self) -> Option<&'static str> {
        self.scheme.map(|s| match s {
            Scheme::Http => "http",
            Scheme::Https => "https",
        })
    }

    /// For a URL, the path and query as written: empty, or starting with `/` or `?`. `None` for a
    /// `host:port`.
    #[must_use]
    pub fn path_and_query(&self) -> Option<&str> {
        self.scheme.map(|_| self.tail.as_str())
    }

    fn check(text: &str) -> Result<Self, TargetProblem> {
        if text.is_empty() {
            return Err(TargetProblem::Empty);
        }
        if text.len() > MAX_LEN {
            return Err(TargetProblem::TooLong);
        }
        if !text.bytes().all(|b| b.is_ascii_graphic()) || text.contains('\\') {
            return Err(TargetProblem::InvalidCharacter);
        }
        match text.split_once("://") {
            Some((scheme, rest)) => Self::check_url(scheme, rest),
            None => {
                let (host, port) = parse_authority(text, true)?;
                Ok(Self {
                    scheme: None,
                    host,
                    port,
                    tail: String::new(),
                })
            }
        }
    }

    fn check_url(scheme: &str, rest: &str) -> Result<Self, TargetProblem> {
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(TargetProblem::BadScheme),
        };
        if rest.contains('#') {
            return Err(TargetProblem::Fragment);
        }
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err(TargetProblem::Credentials);
        }
        let (host, port) = parse_authority(authority, false)?;
        Ok(Self {
            scheme: Some(scheme),
            host,
            port,
            tail: tail.to_owned(),
        })
    }
}

/// Reads `host[:port]` or `[v6][:port]`. `port_required` is true for a bare `host:port` target.
fn parse_authority(
    authority: &str,
    port_required: bool,
) -> Result<(Host, Option<u16>), TargetProblem> {
    let (host, port_text) = if let Some(inner) = authority.strip_prefix('[') {
        let (addr, after) = inner.split_once(']').ok_or(TargetProblem::BadIpv6)?;
        if addr.is_empty() || !addr.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
            return Err(TargetProblem::BadIpv6);
        }
        let addr: Ipv6Addr = addr.parse().map_err(|_| TargetProblem::BadIpv6)?;
        let port_text = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(TargetProblem::BadIpv6)?),
        };
        (Host::Ipv6(addr), port_text)
    } else {
        let (host, port_text) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if host.contains(':') {
            return Err(TargetProblem::BadIpv6);
        }
        (Host::Name(parse_host(host)?), port_text)
    };
    match port_text {
        Some(text) => Ok((host, Some(parse_port(text)?))),
        None if port_required => Err(TargetProblem::MissingPort),
        None => Ok((host, None)),
    }
}

/// A DNS name or IPv4 address: dot-separated labels of letters, digits and inner hyphens.
fn parse_host(host: &str) -> Result<String, TargetProblem> {
    let label_ok = |label: &str| {
        let b = label.as_bytes();
        !b.is_empty()
            && b.len() <= MAX_LABEL_LEN
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    };
    if host.len() > MAX_HOST_LEN || !host.split('.').all(label_ok) {
        return Err(TargetProblem::BadHost);
    }
    Ok(host.to_ascii_lowercase())
}

/// A port from 1 to 65535 as plain digits with no leading zero.
fn parse_port(text: &str) -> Result<u16, TargetProblem> {
    if text.is_empty() || text.len() > 5 || text.starts_with('0') {
        return Err(TargetProblem::BadPort);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TargetProblem::BadPort);
    }
    text.parse().map_err(|_| TargetProblem::BadPort)
}

impl FromStr for Target {
    type Err = ScalarError;

    fn from_str(s: &str) -> Result<Self, ScalarError> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Target {
    type Error = ScalarError;

    fn try_from(value: String) -> Result<Self, ScalarError> {
        Self::parse(&value)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = self.scheme() {
            write!(f, "{scheme}://")?;
        }
        write!(f, "{}", self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        f.write_str(&self.tail)
    }
}

impl From<Target> for String {
    fn from(target: Target) -> String {
        target.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Target {
        Target::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    fn problem(s: &str) -> TargetProblem {
        match Target::parse(s).unwrap_err() {
            ScalarError::InvalidTarget { problem, .. } => problem,
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn accepts_host_port() {
        let t = ok("registry.acme.example:443");
        assert_eq!(t.host(), &Host::Name("registry.acme.example".into()));
        assert_eq!(t.port(), 443);
        assert!(!t.is_url());
        assert_eq!(t.scheme(), None);
        assert_eq!(t.path_and_query(), None);
        assert_eq!(ok("localhost:1").port(), 1);
        assert_eq!(ok("10.0.0.1:65535").port(), 65535);
        assert_eq!(ok("a-b.c1:80").to_string(), "a-b.c1:80");
        assert_eq!(
            ok("Registry.ACME.example:443").to_string(),
            "registry.acme.example:443"
        );
    }

    #[test]
    fn accepts_bracketed_ipv6() {
        let t = ok("[::1]:443");
        assert_eq!(t.host(), &Host::Ipv6(Ipv6Addr::LOCALHOST));
        assert_eq!(t.port(), 443);
        assert_eq!(t.to_string(), "[::1]:443");
        assert_eq!(
            ok("[2001:DB8:0:0:0:0:0:1]:8443").to_string(),
            "[2001:db8::1]:8443"
        );
        assert_eq!(ok("[fe80::1]:53").port(), 53);
    }

    #[test]
    fn accepts_urls() {
        let t = ok("https://registry.acme.example/v2/?x=1");
        assert!(t.is_url());
        assert_eq!(t.scheme(), Some("https"));
        assert_eq!(t.port(), 443);
        assert_eq!(t.path_and_query(), Some("/v2/?x=1"));
        assert_eq!(t.to_string(), "https://registry.acme.example/v2/?x=1");
        assert_eq!(ok("http://proxy.corp.example").port(), 80);
        assert_eq!(ok("http://proxy.corp.example:3128").port(), 3128);
        assert_eq!(
            ok("http://proxy.corp.example:3128").path_and_query(),
            Some("")
        );
        assert_eq!(
            ok("https://[::1]:8443/x").host(),
            &Host::Ipv6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(ok("https://[::1]/x").port(), 443);
        assert_eq!(ok("https://h?a=b@c").path_and_query(), Some("?a=b@c"));
        assert_eq!(ok("https://h/a@b").to_string(), "https://h/a@b");
    }

    #[test]
    fn refuses_bad_ports() {
        for s in [
            "host:99999",
            "host:65536",
            "host:0",
            "host:00443",
            "host:0443",
            "host:-1",
            "host:+1",
            "host:",
            "host:4 3",
            "host:443a",
            "host:1e3",
            "host:123456",
            "[::1]:0",
            "[::1]:70000",
            "https://host:99999/",
            "https://host:/",
        ] {
            let p = problem(s);
            assert!(
                matches!(p, TargetProblem::BadPort | TargetProblem::InvalidCharacter),
                "{s:?}: {p:?}"
            );
        }
        assert_eq!(problem("host:99999"), TargetProblem::BadPort);
        assert_eq!(problem("host:"), TargetProblem::BadPort);
    }

    #[test]
    fn refuses_missing_port_and_bad_hosts() {
        assert_eq!(problem("registry.acme.example"), TargetProblem::MissingPort);
        assert_eq!(problem("[::1]"), TargetProblem::MissingPort);
        for s in [
            ":443",
            "-a:443",
            "a-:443",
            "a..b:443",
            ".a:443",
            "a.:443",
            "a_b:443",
            "a b:443x",
            "a*b:443",
            "a/b:443",
            "a%41:443",
            "a@b:443",
            "a#b:443",
            "https://:443/",
            "https:///x",
        ] {
            let p = problem(s);
            assert!(
                matches!(p, TargetProblem::BadHost | TargetProblem::InvalidCharacter),
                "{s:?}: {p:?}"
            );
        }
        let long = format!("{}:443", "a".repeat(64));
        assert_eq!(problem(&long), TargetProblem::BadHost);
        let long = format!("{}:443", vec!["a".repeat(63); 5].join("."));
        assert_eq!(problem(&long), TargetProblem::BadHost);
    }

    #[test]
    fn refuses_bad_ipv6() {
        for s in [
            "::1:443",
            "::1",
            "fe80::1:443",
            "[::1:443",
            "[::1]x:443",
            "[]:443",
            "[:::]:443",
            "[::g]:443",
            "[::ffff:1.2.3.4]:443",
            "[fe80::1%eth0]:443",
            "[::1]443",
            "[1:2:3:4:5:6:7:8:9]:1",
            "https://::1/",
            "https://[::1/x",
        ] {
            assert_eq!(problem(s), TargetProblem::BadIpv6, "{s:?}");
        }
    }

    #[test]
    fn refuses_credentials_and_fragments() {
        for s in [
            "https://u:p@host/",
            "https://user@host/",
            "http://u:p@host:80",
            "https://@host/",
            "https://u:p@[::1]:443/",
        ] {
            assert_eq!(problem(s), TargetProblem::Credentials, "{s:?}");
        }
        for s in [
            "https://host/#top",
            "https://host#top",
            "https://host/a?b#c",
            "https://u:p@host/#x",
        ] {
            assert_eq!(problem(s), TargetProblem::Fragment, "{s:?}");
        }
    }

    #[test]
    fn refuses_other_schemes_and_shapes() {
        for s in [
            "ftp://host/",
            "HTTPS://host/",
            "Http://host/",
            "tcp://host:443",
            "://host",
            "file:///etc/passwd",
            "ssh://host:22",
            "host:443://x",
        ] {
            assert_eq!(problem(s), TargetProblem::BadScheme, "{s:?}");
        }
        assert_eq!(problem(""), TargetProblem::Empty);
        for s in [
            " host:443",
            "host:443 ",
            "ho st:443",
            "host:443\n",
            "host:443\t",
            "h\u{f6}st:443",
            "https://host/\u{e9}",
            "https://host/a b",
            "https://host\\x",
            "host\u{0}:1",
            "https://host/\u{1b}[2J",
        ] {
            assert_eq!(problem(s), TargetProblem::InvalidCharacter, "{s:?}");
        }
        let long = format!("https://host/{}", "a".repeat(512));
        assert_eq!(problem(&long), TargetProblem::TooLong);
        let edge = format!("https://host/{}", "a".repeat(512 - "https://host/".len()));
        assert_eq!(ok(&edge).to_string().len(), 512);
    }

    #[test]
    fn serde_reads_and_writes_strings() {
        let t: Target = serde_json::from_str("\"[::1]:443\"").unwrap();
        assert_eq!(serde_json::to_string(&t).unwrap(), "\"[::1]:443\"");
        for bad in [
            "\"host:99999\"",
            "\"https://u:p@host/\"",
            "443",
            "null",
            "[]",
            "{}",
        ] {
            assert!(serde_json::from_str::<Target>(bad).is_err(), "{bad}");
        }
    }
}
