//! Parameters of the four M1 network check ids.
//!
//! The fields, ranges and defaults follow `$defs` in `crates/rdy-spec/schema/spec.v1.schema.json` and
//! the table in `docs/plan/01-spec-format.md` section 2.7. What each threshold means to the check is in
//! `docs/plan/03-check-catalog.md`.
//!
//! Every struct refuses a key it does not have. `net.egress` requires `endpoints` and `net.dns`
//! requires `names`. An entry without them decodes to
//! [`UnsupportedReason::NoThreshold`](super::UnsupportedReason::NoThreshold). `net.proxy` and
//! `net.tls_intercept` read bare.
//!
//! A [`Target`] is parsed with the strict grammar of 01 section 2.6. Parsing does not classify an
//! address: the egress policy of ADR 0009 does that at run time.

use std::net::IpAddr;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::ParamSet;
use super::common::{BoundedList, RegexText, StringList, from_value};
use crate::error::echo_safe;
use crate::scalar::{Duration, Host, Target, is_plain_host_name, redact_for_echo};

/// Builds a deserialize error from a message.
fn bad<E: serde::de::Error>(message: impl std::fmt::Display) -> E {
    E::custom(message)
}

/// Which path an endpoint is tried on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ViaProxy {
    /// Try what the product would do, and say if the other path works. This is the default.
    #[default]
    Auto,
    /// No proxy.
    Direct,
    /// Only through the proxy.
    ProxyOnly,
}

/// Which certificates `net.egress` trusts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Trust {
    /// The operating system's store, with the bundled public roots as a fallback. This is the default.
    #[default]
    System,
    /// The bundled public roots only.
    Bundled,
}

/// The request method for a URL endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum HttpMethod {
    /// Headers only. This is the default.
    #[default]
    #[serde(rename = "HEAD")]
    Head,
    /// A full request.
    #[serde(rename = "GET")]
    Get,
}

/// An HTTP status code, 100 to 599.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpStatus(u16);

impl HttpStatus {
    /// The status code.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for HttpStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = u64::deserialize(deserializer)?;
        match u16::try_from(n) {
            Ok(code) if (100..=599).contains(&code) => Ok(Self(code)),
            _ => Err(bad(format!("a status code is 100 to 599, not {n}"))),
        }
    }
}

/// One endpoint of `net.egress`.
///
/// In a spec it is a bare [`Target`], or an object with `target` and the options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Endpoint {
    /// Where to connect.
    pub target: Target,
    /// Unreachable gives a warning and not a block. The default is false.
    pub optional: bool,
    /// The statuses that count as reachable, for a URL target. At most 16.
    pub expect_status: Option<BoundedList<HttpStatus, 16, true, 1>>,
    /// The request method, for a URL target. The default is [`HttpMethod::Head`].
    pub method: HttpMethod,
    /// Overrides the `via_proxy` of the entry for this endpoint.
    pub via_proxy: Option<ViaProxy>,
    /// `false` probes plain TCP only. Without it TLS is tried for port 443 and `https` URLs.
    pub tls: Option<bool>,
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            target: Target,
            #[serde(default)]
            optional: bool,
            expect_status: Option<BoundedList<HttpStatus, 16, true, 1>>,
            #[serde(default)]
            method: HttpMethod,
            via_proxy: Option<ViaProxy>,
            tls: Option<bool>,
        }
        // Reading the value first keeps the messages of the inner readers.
        match Value::deserialize(deserializer)? {
            value @ Value::Object(_) => {
                let full: Full = from_value(value)?;
                Ok(Self {
                    target: full.target,
                    optional: full.optional,
                    expect_status: full.expect_status,
                    method: full.method,
                    via_proxy: full.via_proxy,
                    tls: full.tls,
                })
            }
            value => Ok(Self {
                target: from_value(value)?,
                optional: false,
                expect_status: None,
                method: HttpMethod::Head,
                via_proxy: None,
                tls: None,
            }),
        }
    }
}

/// Parameters of `net.egress`: can this machine reach the endpoints the product needs.
///
/// `endpoints` is required. At most 64 per spec; the spec-wide limit is checked with the whole spec.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetEgress {
    /// The endpoints, 1 to 64.
    pub endpoints: BoundedList<Endpoint, 64, false, 1>,
    /// Which path to try. The default is [`ViaProxy::Auto`].
    #[serde(default)]
    pub via_proxy: ViaProxy,
    /// Which certificates to trust. The default is [`Trust::System`].
    #[serde(default)]
    pub trust: Trust,
    /// A connect slower than this: the check warns. The default, 2s, is the check's.
    pub max_latency: Option<Duration>,
}

impl ParamSet for NetEgress {
    const FIELDS: &'static [&'static str] = &["endpoints", "via_proxy", "trust", "max_latency"];
    const THRESHOLD: &'static [&'static str] = &["endpoints"];
}

/// Parameters of `net.proxy`: the proxy settings the product would see.
///
/// Both keys are optional. With neither, the check only reports what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetProxy {
    /// Entries that `NO_PROXY` must cover, such as `.svc` or `10.0.0.0/8`.
    pub required_no_proxy: Option<StringList>,
    /// The container runtime and kubelet must have the proxy too. The default is false.
    #[serde(default)]
    pub daemons_need_proxy: bool,
}

impl ParamSet for NetProxy {
    const FIELDS: &'static [&'static str] = &["required_no_proxy", "daemons_need_proxy"];
}

/// A host for `net.tls_intercept`: a name or address, with a port when written.
///
/// It is read with the grammar of [`Target`], so the same forms are refused. The port is optional and
/// then 443 applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsHost {
    target: Target,
    port_written: bool,
}

impl TlsHost {
    /// The longest host in characters: a 253 character name, a colon and a 5 digit port.
    pub const MAX_CHARS: usize = 259;

    /// The host.
    #[must_use]
    pub fn host(&self) -> &Host {
        self.target.host()
    }

    /// The port as written, or `None` when the spec has none and 443 applies.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port_written.then(|| self.target.port())
    }
}

impl<'de> Deserialize<'de> for TlsHost {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let fits = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
        let (host, port) = match text.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (text.as_str(), None),
        };
        let shape_ok = text.chars().count() <= Self::MAX_CHARS
            && !host.is_empty()
            && host.chars().all(fits)
            && port.is_none_or(|p| {
                (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit())
            });
        if !shape_ok {
            return Err(bad(format!(
                "'{}' is not a host: write a name or address, with an optional :port",
                // A spec carries no credentials, but a mistake like user:secret@host must not be echoed.
                echo_safe(&redact_for_echo(&text))
            )));
        }
        let full = format!("{host}:{}", port.unwrap_or("443"));
        let target = Target::parse(&full).map_err(bad)?;
        Ok(Self {
            target,
            port_written: port.is_some(),
        })
    }
}

/// A SHA-256 digest as 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// The digest as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Hex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a SHA-256 digest: write 64 lowercase hex digits",
                echo_safe(&text)
            )))
        }
    }
}

/// Parameters of `net.tls_intercept`: is a middlebox re-signing TLS.
///
/// Every key is optional. With none, the check tests the hosts of `net.egress` and reports what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetTlsIntercept {
    /// The hosts to test, 1 to 64. The default is every `net.egress` host in the spec.
    pub hosts: Option<BoundedList<TlsHost, 64, false, 1>>,
    /// A pattern the issuer of the chain must match. A chain from another issuer blocks.
    pub expected_issuer: Option<RegexText>,
    /// SHA-256 digests of certificates the chain may be pinned to, 1 to 16.
    pub pin_sha256: Option<BoundedList<Sha256Hex, 16, false, 1>>,
    /// A chain that only this machine trusts blocks instead of warning. The default is false.
    #[serde(default)]
    pub forbid_interception: bool,
}

impl ParamSet for NetTlsIntercept {
    const FIELDS: &'static [&'static str] = &[
        "hosts",
        "expected_issuer",
        "pin_sha256",
        "forbid_interception",
    ];
    const REGEX_FIELDS: &'static [&'static str] = &["expected_issuer"];
}

/// A name to look up, by the host-name grammar of [`Target`] (01 section 2.6).
///
/// Labels are 1 to 63 letters, digits and hyphens, and do not start or end with a hyphen. The name is at
/// most 253 characters, has no trailing dot and its last label is not a number. So it cannot start with
/// `-`, and ADR 0006 decision 5 can pass it to `getent ahosts` without it reading as an option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(String);

impl DnsName {
    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DnsName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if is_plain_host_name(&text) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a name: use dot-separated labels of letters, digits and -, \
                 none starting or ending with -, and a last label that is not a number",
                echo_safe(&text)
            )))
        }
    }
}

/// An address range such as `10.0.0.0/8` or `fd00::/8`.
///
/// The address is IPv4 in four plain decimal parts, or IPv6 without a dotted tail. The prefix is 0 to
/// 32 for IPv4 and 0 to 128 for IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// The address as written. Bits beyond the prefix are not cleared.
    #[must_use]
    pub fn addr(self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    #[must_use]
    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let parsed = text.split_once('/').and_then(|(addr, prefix)| {
            // Plain digits with no leading zero, like the schema: `08` is not a prefix.
            let digits = (1..=3).contains(&prefix.len())
                && prefix.bytes().all(|b| b.is_ascii_digit())
                && !(prefix.len() > 1 && prefix.starts_with('0'));
            let addr = addr.parse::<IpAddr>().ok().filter(|a| match a {
                IpAddr::V4(_) => true,
                IpAddr::V6(_) => !addr.contains('.'),
            })?;
            let prefix = prefix.parse::<u8>().ok().filter(|_| digits)?;
            let longest = if addr.is_ipv4() { 32 } else { 128 };
            (prefix <= longest).then_some(Self { addr, prefix })
        });
        parsed.ok_or_else(|| {
            bad(format!(
                "'{}' is not an address range: write it like 10.0.0.0/8 or fd00::/8",
                echo_safe(&text)
            ))
        })
    }
}

/// A name for `net.dns` to look up, with what its answer must look like.
///
/// In a spec it is a bare name, or an object with `name` and the options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DnsRule {
    /// The name to look up.
    pub name: DnsName,
    /// Every answer must be inside one of these ranges, 1 to 16.
    pub expect_in: Option<BoundedList<Cidr, 16, false, 1>>,
    /// The answers must be public addresses (`true`) or private ones (`false`).
    pub expect_public: Option<bool>,
}

impl<'de> Deserialize<'de> for DnsRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            name: DnsName,
            expect_in: Option<BoundedList<Cidr, 16, false, 1>>,
            expect_public: Option<bool>,
        }
        match Value::deserialize(deserializer)? {
            value @ Value::Object(_) => {
                let Full {
                    name,
                    expect_in,
                    expect_public,
                } = from_value(value)?;
                Ok(Self {
                    name,
                    expect_in,
                    expect_public,
                })
            }
            value => Ok(Self {
                name: from_value(value)?,
                expect_in: None,
                expect_public: None,
            }),
        }
    }
}

/// Parameters of `net.dns`: do the names resolve, and to what.
///
/// `names` is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetDns {
    /// The names to look up, 1 to 64.
    pub names: BoundedList<DnsRule, 64, false, 1>,
    /// A lookup slower than this: the check warns. The default, 500ms, is the check's.
    pub max_latency: Option<Duration>,
}

impl ParamSet for NetDns {
    const FIELDS: &'static [&'static str] = &["names", "max_latency"];
    const THRESHOLD: &'static [&'static str] = &["names"];
}

#[cfg(test)]
mod tests;
