//! Parameters of the network check ids: the four M1 ids and the three M1-late ids.
//!
//! The fields, ranges and defaults follow `$defs` in `crates/rdy-spec/schema/spec.v1.schema.json` and
//! the table in `docs/plan/01-spec-format.md` section 2.7. What each threshold means to the check is in
//! `docs/plan/03-check-catalog.md`.
//!
//! Every struct refuses a key it does not have. `net.egress` requires `endpoints`, `net.dns` requires
//! `names`, `net.registry` requires `registries` and `net.bandwidth` requires `url`. An entry without
//! them decodes to
//! [`UnsupportedReason::NoThreshold`](super::UnsupportedReason::NoThreshold). `net.proxy`,
//! `net.tls_intercept` and `net.mtu` read bare.
//!
//! A [`Target`] is parsed with the strict grammar of 01 section 2.6. Parsing does not classify an
//! address: the egress policy of ADR 0009 does that at run time.

use std::net::IpAddr;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::ParamSet;
use super::common::{BoundedList, RegexText, StringList, from_value};
use crate::error::echo_safe;
use crate::scalar::{Duration, Host, Quantity, Target, is_plain_host_name, redact_for_echo};

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

// ---- the M1-late ids ----------------------------------------------------------------------------

/// An image in a registry, written `repository:tag`, such as `acme/agent:1.4`.
///
/// The repository is 1 or more `/`-separated parts, as in the OCI distribution rules: each part is
/// lowercase letters and digits, joined by a single `.`, `_`, `__` or any run of `-`. The tag is 1 to 128
/// letters, digits, `_`, `.` and `-`, and does not start with `.` or `-`. The tag is required, and a
/// digest is not accepted. The registry host is not part of it: it is the `host` of the registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageRef {
    repository: String,
    tag: String,
}

impl ImageRef {
    /// The longest repository in characters.
    pub const MAX_REPOSITORY_CHARS: usize = 255;

    /// The longest tag in characters.
    pub const MAX_TAG_CHARS: usize = 128;

    /// The repository, such as `acme/agent`.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The tag, such as `1.4`.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    fn parse(text: &str) -> Option<Self> {
        let (repository, tag) = text.rsplit_once(':')?;
        let tag_ok = (1..=Self::MAX_TAG_CHARS).contains(&tag.len())
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
            && tag
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
        let repository_ok = (1..=Self::MAX_REPOSITORY_CHARS).contains(&repository.len())
            && repository.split('/').all(is_repository_part);
        (tag_ok && repository_ok).then(|| Self {
            repository: repository.to_owned(),
            tag: tag.to_owned(),
        })
    }
}

/// One `/`-separated part of an image repository: runs of `a-z` and `0-9` joined by a single `.`, `_`,
/// `__` or a run of `-`.
fn is_repository_part(part: &str) -> bool {
    let word = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let mut chars = part.chars().peekable();
    let mut expect_word = true;
    while chars.peek().is_some() {
        let mut run = String::new();
        while let Some(c) = chars.next_if(|c| word(*c) == expect_word) {
            run.push(c);
        }
        if run.is_empty() {
            return false;
        }
        if !expect_word
            && !matches!(run.as_str(), "." | "_" | "__")
            && !run.bytes().all(|b| b == b'-')
        {
            return false;
        }
        expect_word = !expect_word;
    }
    // Ends with a word, which also means the part is not empty.
    !expect_word
}

impl<'de> Deserialize<'de> for ImageRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| {
            bad(format!(
                "'{}' is not an image: write it like 'acme/agent:1.4', a lowercase repository and a tag",
                echo_safe(&text)
            ))
        })
    }
}

/// A registry for `net.registry` to test, with the hosts it uses and the images to look up.
///
/// In a spec it is a bare host, or an object with `host` and the options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RegistryRule {
    /// The registry host, with a port when it is not 443.
    pub host: TlsHost,
    /// The other hosts the registry uses: the token service and the blob store. At most 8, none
    /// twice. A host the check finds that is not listed is not contacted, and the result names it.
    pub hosts: Option<BoundedList<TlsHost, 8, true, 1>>,
    /// Public images to resolve to a manifest, 1 to 16, none twice.
    pub images: Option<BoundedList<ImageRef, 16, true, 1>>,
    /// An unreachable registry warns and does not block. The default is false.
    pub optional: bool,
}

impl<'de> Deserialize<'de> for RegistryRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            host: TlsHost,
            hosts: Option<BoundedList<TlsHost, 8, true, 1>>,
            images: Option<BoundedList<ImageRef, 16, true, 1>>,
            #[serde(default)]
            optional: bool,
        }
        // Reading the value first keeps the messages of the inner readers.
        match Value::deserialize(deserializer)? {
            value @ Value::Object(_) => {
                let Full {
                    host,
                    hosts,
                    images,
                    optional,
                } = from_value(value)?;
                Ok(Self {
                    host,
                    hosts,
                    images,
                    optional,
                })
            }
            value => Ok(Self {
                host: from_value(value)?,
                hosts: None,
                images: None,
                optional: false,
            }),
        }
    }
}

/// Parameters of `net.registry`: does an OCI registry work from start to finish.
///
/// `registries` is required. At most 16.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetRegistry {
    /// The registries, 1 to 16.
    pub registries: BoundedList<RegistryRule, 16, false, 1>,
}

impl ParamSet for NetRegistry {
    const FIELDS: &'static [&'static str] = &["registries"];
    const THRESHOLD: &'static [&'static str] = &["registries"];
}

/// An MTU in bytes, 68 to 65535. 68 is the smallest an IPv4 link carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mtu(u16);

impl Mtu {
    /// The MTU in bytes.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Mtu {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = u64::deserialize(deserializer)?;
        match u16::try_from(n) {
            Ok(mtu) if mtu >= 68 => Ok(Self(mtu)),
            _ => Err(bad(format!("an MTU is 68 to 65535, not {n}"))),
        }
    }
}

/// The overlay network whose header the pod network must leave room for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Overlay {
    /// VXLAN.
    Vxlan,
    /// Geneve.
    Geneve,
    /// WireGuard.
    Wireguard,
    /// IP in IP.
    Ipip,
}

/// The IP version of the network under an overlay. It sets the size of the overlay header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Underlay {
    /// IPv4. This is the default.
    #[default]
    Ipv4,
    /// IPv6.
    Ipv6,
}

/// Parameters of `net.mtu`: interface MTU and room for an overlay.
///
/// Every key is optional. With none, the check reports the MTUs and warns about a small one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetMtu {
    /// The pod network needs this MTU. An interface MTU, less the overlay header, below it blocks.
    pub min_mtu: Option<Mtu>,
    /// The overlay the pod network will use.
    pub overlay: Option<Overlay>,
    /// The IP version under the overlay. The default is [`Underlay::Ipv4`].
    #[serde(default)]
    pub underlay: Underlay,
}

impl ParamSet for NetMtu {
    const FIELDS: &'static [&'static str] = &["min_mtu", "overlay", "underlay"];
}

/// The URL of a sample download: `http` or `https`, with no user name or password.
///
/// It is read with the grammar of [`Target`], and only a URL is accepted. The query is kept as written,
/// because a presigned URL has one, and no check logs more than the scheme, host, port and path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpUrl(Target);

impl HttpUrl {
    /// The URL.
    #[must_use]
    pub fn target(&self) -> &Target {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HttpUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let target = Target::parse(&text).map_err(bad)?;
        if target.is_url() {
            Ok(Self(target))
        } else {
            Err(bad(format!(
                "'{}' is not a URL: write it like https://mirror.acme.example/sample.bin",
                echo_safe(&redact_for_echo(&text))
            )))
        }
    }
}

/// The size of a bandwidth sample, 1 MiB to 100 MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SampleBytes(Quantity);

impl SampleBytes {
    /// The smallest sample: a shorter reply is "sample too small".
    pub const MIN: u64 = 1 << 20;

    /// The largest sample.
    pub const MAX: u64 = 100 << 20;

    /// The size in bytes.
    #[must_use]
    pub fn bytes(self) -> u64 {
        self.0.bytes()
    }
}

impl<'de> Deserialize<'de> for SampleBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let quantity = Quantity::deserialize(deserializer)?;
        if (Self::MIN..=Self::MAX).contains(&quantity.bytes()) {
            Ok(Self(quantity))
        } else {
            Err(bad(format!(
                "a sample is 1Mi to 100Mi, not {} bytes",
                quantity.bytes()
            )))
        }
    }
}

/// A rate in megabits per second, above 0 and at most 100000. It may have a decimal part.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Mbps(f64);

// A value read from a spec is finite and in range, so it never compares unequal to itself.
impl Eq for Mbps {}

impl Mbps {
    /// The largest rate.
    pub const MAX: f64 = 100_000.0;

    /// The rate in megabits per second.
    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Mbps {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = f64::deserialize(deserializer)?;
        if n > 0.0 && n <= Self::MAX {
            Ok(Self(n))
        } else {
            Err(bad(format!(
                "a rate is above 0 and at most 100000 Mbit/s, not {n}"
            )))
        }
    }
}

/// Parameters of `net.bandwidth`: a download sample from a URL the vendor chose.
///
/// `url` is required. There is no default URL. Without `min_mbps` and `recommended_mbps` the result is
/// informational.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetBandwidth {
    /// Where to download from.
    pub url: HttpUrl,
    /// How much to download. The default, 10 MiB, is the check's.
    pub bytes: Option<SampleBytes>,
    /// A slower single stream blocks.
    pub min_mbps: Option<Mbps>,
    /// A slower single stream warns.
    pub recommended_mbps: Option<Mbps>,
}

impl ParamSet for NetBandwidth {
    const FIELDS: &'static [&'static str] = &["url", "bytes", "min_mbps", "recommended_mbps"];
    const THRESHOLD: &'static [&'static str] = &["url"];
}

#[cfg(test)]
mod tests;
