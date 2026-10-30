//! The proxy URL and the typed network failures of the facade (M1-091, ADR 0014 decision 2).
//!
//! [`ProxyUrl`] is the one place the proxy address and its credentials are parsed. The facade writes the
//! `CONNECT` itself and builds the `Proxy-Authorization` header from this type, so a check never holds a
//! password. `Debug` and `Display` mask the userinfo. The URL is handed to the run through
//! [`ProbeHub::set_proxy`](crate::probe::ProbeHub::set_proxy), which puts the password into the
//! run-scoped known-secret set before the proxy can be used.
//!
//! **Scope.** Plain `http://` proxies with Basic authentication, as ADR 0014 says. A scheme-less
//! `host:port` is read as `http://`. `https://`, `socks5://` and PAC are refused with a hint. Negotiate
//! and NTLM challenges are reported by name and never attempted. Names resolve at the proxy.

use std::fmt;

use rdy_spec::Target;
use rdy_spec::scalar::Host;

#[cfg(test)]
mod tests;

/// The longest proxy URL accepted, in bytes.
const MAX_LEN: usize = 2048;

/// The port of a proxy URL that names none. It is the `http` default, as in a browser.
pub const DEFAULT_PROXY_PORT: u16 = 80;

/// The largest `CONNECT` reply head that is read, in bytes (ADR 0014 decision 2).
pub const MAX_CONNECT_HEAD: usize = 8 * 1024;

/// Why a proxy URL was refused. No variant holds any part of the text: it may carry a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyUrlError {
    /// The text is empty or longer than 2048 bytes.
    #[error(
        "the proxy URL is empty or longer than 2048 bytes. Fix: write it as http://host:port or http://user:password@host:port"
    )]
    Size,
    /// The scheme is not `http`.
    #[error(
        "only http:// proxies are supported (not https://, socks5:// or a PAC file). Fix: use the proxy's http://host:port address, or ask the network team for one"
    )]
    Scheme,
    /// The host or port is not valid.
    #[error(
        "the proxy host or port is not valid. Fix: write it as host:port, with the port from 1 to 65535 and an IPv6 address in square brackets"
    )]
    Address,
    /// The URL has a path, a query or a fragment.
    #[error(
        "the proxy URL has a path, query or fragment. Fix: use only http://[user:password@]host:port"
    )]
    Extra,
    /// The user name or password cannot be used.
    #[error(
        "the user name or password in the proxy URL cannot be used. Fix: write special characters as percent escapes (an at sign is %40, a colon in the user name is not allowed), and use UTF-8"
    )]
    Userinfo,
}

/// A proxy address and, if the URL had them, the credentials for Basic authentication.
///
/// `Debug` and `Display` print the userinfo as `***`. Use [`ProxyUrl::origin`] for the log.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    host: Host,
    port: u16,
    credentials: Option<Credentials>,
}

#[derive(Clone, PartialEq, Eq)]
struct Credentials {
    user: String,
    password: Option<String>,
    /// The password as written in the URL, percent escapes and all.
    raw_password: Option<String>,
}

impl ProxyUrl {
    /// Reads `http://[user[:password]@]host[:port]`, or `host[:port]` with no scheme.
    ///
    /// The user name and password are percent-decoded. A missing port is [`DEFAULT_PROXY_PORT`].
    ///
    /// # Errors
    ///
    /// [`ProxyUrlError`]. It never echoes the text.
    pub fn parse(text: &str) -> Result<Self, ProxyUrlError> {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_LEN {
            return Err(ProxyUrlError::Size);
        }
        let rest = match text.split_once("://") {
            Some(("http", rest)) => rest,
            Some(_) => return Err(ProxyUrlError::Scheme),
            None => text,
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#']) {
            return Err(ProxyUrlError::Extra);
        }
        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((userinfo, hostport)) => (Some(userinfo), hostport),
            None => (None, rest),
        };
        let has_port = if hostport.starts_with('[') {
            hostport.contains("]:")
        } else {
            hostport.contains(':')
        };
        let authority = if has_port {
            hostport.to_owned()
        } else {
            format!("{hostport}:{DEFAULT_PROXY_PORT}")
        };
        // A `Target` is `host:port` only here, so the grammar of 01 (no short IPv4 forms, lower case
        // names) applies to the proxy too.
        let target = Target::parse(&authority).map_err(|_| ProxyUrlError::Address)?;
        if target.is_url() {
            return Err(ProxyUrlError::Address);
        }
        let credentials = userinfo.map(parse_userinfo).transpose()?;
        Ok(Self {
            host: target.host().clone(),
            port: target.port(),
            credentials,
        })
    }

    /// The proxy host.
    #[must_use]
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The proxy port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The URL without its userinfo, such as `http://proxy.corp.example:3128`. It is what the action log
    /// records as `via_proxy`.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// Whether the URL carried a user name.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Every form of the password and the credential pair that can reach output: the password as
    /// written and percent-decoded, and the base64 of `user:password` that goes into
    /// `Proxy-Authorization`. A caller adds all of them to the known-secret set. Empty when the URL has
    /// no password.
    pub(crate) fn secrets(&self) -> Vec<String> {
        let Some(Credentials {
            user,
            password: Some(password),
            raw_password,
        }) = &self.credentials
        else {
            return Vec::new();
        };
        if password.is_empty() {
            return Vec::new();
        }
        let mut forms = vec![password.clone()];
        forms.extend(raw_password.clone().filter(|raw| raw != password));
        forms.push(base64(format!("{user}:{password}").as_bytes()));
        forms
    }

    /// The `Proxy-Authorization` header value, `Basic <base64>`, or `None` when the URL had no user.
    /// Never log it.
    #[cfg(any(feature = "runtime", feature = "loopback"))]
    pub(crate) fn authorization(&self) -> Option<String> {
        let credentials = self.credentials.as_ref()?;
        let pair = format!(
            "{}:{}",
            credentials.user,
            credentials.password.as_deref().unwrap_or("")
        );
        Some(format!("Basic {}", base64(pair.as_bytes())))
    }

    /// The bytes of the `CONNECT` request for `target` (`host:port`). It holds the credentials, so it
    /// goes to the proxy and nowhere else.
    #[cfg(any(feature = "runtime", feature = "loopback"))]
    pub(crate) fn connect_request(&self, target: &str) -> Vec<u8> {
        let mut text = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(value) = self.authorization() {
            text.push_str("Proxy-Authorization: ");
            text.push_str(&value);
            text.push_str("\r\n");
        }
        text.push_str("\r\n");
        text.into_bytes()
    }
}

impl fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.credentials.is_some() {
            write!(f, "http://***@{}:{}", self.host, self.port)
        } else {
            write!(f, "http://{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyUrl({self})")
    }
}

fn parse_userinfo(text: &str) -> Result<Credentials, ProxyUrlError> {
    let (user, raw_password) = match text.split_once(':') {
        Some((user, password)) => (user, Some(password)),
        None => (text, None),
    };
    let user = percent_decode(user).ok_or(ProxyUrlError::Userinfo)?;
    if user.is_empty() || user.contains(':') {
        return Err(ProxyUrlError::Userinfo);
    }
    let password = raw_password
        .map(|raw| percent_decode(raw).ok_or(ProxyUrlError::Userinfo))
        .transpose()?;
    Ok(Credentials {
        user,
        password,
        raw_password: raw_password.map(str::to_owned),
    })
}

/// Decodes `%XX`. `None` for a bad escape or a result that is not UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        if byte == b'%' {
            let hi = hex(*bytes.get(at + 1)?)?;
            let lo = hex(*bytes.get(at + 2)?)?;
            out.push(hi << 4 | lo);
            at += 3;
        } else {
            out.push(byte);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Standard base64 with padding (RFC 4648 section 4).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let sextet = |shift: u32| char::from(ALPHABET[(n >> shift & 0x3f) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

/// Why the proxy could not be set for the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// The URL did not parse.
    #[error("{0}")]
    Url(#[from] ProxyUrlError),
    /// The run-scoped known-secret set refused the proxy password, so rdy could not promise to keep it
    /// out of the output. The caller ends the run with exit code 70.
    #[error(
        "rdy could not add the proxy password to its redaction list, so it cannot promise to keep it out of the report. Fix: use a proxy password of 6 to 65536 characters, or take the password out of the proxy URL"
    )]
    SecretRefused,
    /// A proxy was already set for this run.
    #[error("a proxy is already set for this run. Fix: this is a bug in rdy; please report it")]
    AlreadySet,
}

/// What a proxy asked for in a `Proxy-Authenticate` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyChallenge {
    /// No `Proxy-Authenticate` header.
    None,
    /// `Basic`: a user name and password.
    Basic,
    /// `Negotiate`: Kerberos or integrated Windows sign-in. rdy never attempts it.
    Negotiate,
    /// `NTLM`. rdy never attempts it.
    Ntlm,
    /// Any other scheme.
    Other,
}

impl fmt::Display for ProxyChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "no scheme",
            Self::Basic => "Basic",
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
            Self::Other => "another scheme",
        })
    }
}

/// A network failure that the facade names. Each message ends with a `Fix:` hint and holds only the
/// spec's own host text, never a reply from the peer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NetFailure {
    /// The name did not resolve.
    #[error(
        "the name {host} did not resolve. Fix: check the spelling in the spec, and that this machine's DNS can answer for it"
    )]
    Dns {
        /// The spec host.
        host: String,
    },
    /// The proxy answered 403 to `CONNECT`.
    #[error(
        "the proxy refused CONNECT to {target} (403). Fix: ask the proxy team to add {target} to the allow list"
    )]
    ProxyForbidden {
        /// The `host:port` that was asked for.
        target: String,
    },
    /// The proxy answered 407 to `CONNECT`.
    #[error("the proxy answered 407 to CONNECT {target}. Fix: {}", fix_407(*.challenge, *.sent_credentials))]
    ProxyAuthRequired {
        /// The `host:port` that was asked for.
        target: String,
        /// What the proxy asked for.
        challenge: ProxyChallenge,
        /// Whether rdy sent Basic credentials from the proxy URL.
        sent_credentials: bool,
    },
    /// The proxy answered `CONNECT` with another status than 2xx, 403 or 407.
    #[error(
        "the proxy answered {status} to CONNECT {target}. Fix: ask the proxy team why it will not open a tunnel to {target}; 502 and 504 usually mean the proxy cannot reach it"
    )]
    ProxyRefused {
        /// The `host:port` that was asked for.
        target: String,
        /// The status code.
        status: u16,
    },
    /// The proxy's reply was not HTTP, was cut off, or was longer than 8 KiB.
    #[error(
        "the proxy sent a reply that is not a readable HTTP answer ({reason}). Fix: check that the proxy address is an HTTP proxy and not a TLS, SOCKS or other port"
    )]
    ProxyBadReply {
        /// A fixed phrase for what was wrong.
        reason: &'static str,
    },
    /// The call asked for the proxy and the run has none.
    #[error(
        "no proxy is set for this run. Fix: set HTTPS_PROXY or HTTP_PROXY before running rdy, or route the check direct"
    )]
    NoProxy,
}

fn fix_407(challenge: ProxyChallenge, sent: bool) -> &'static str {
    match (challenge, sent) {
        (ProxyChallenge::Negotiate | ProxyChallenge::Ntlm, _) => {
            "the proxy wants integrated sign-in, which rdy does not attempt; ask the proxy team to allow this endpoint without sign-in"
        }
        (_, true) => {
            "the proxy rejected the user name or password in the proxy URL; check them, and write special characters as percent escapes"
        }
        (_, false) => {
            "the proxy wants a user name and password; put them in the proxy URL as http://user:password@host:port"
        }
    }
}

/// What a `CONNECT` reply head said.
#[cfg(any(feature = "runtime", feature = "loopback"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectReply {
    pub(crate) status: u16,
    pub(crate) challenge: ProxyChallenge,
}

/// Reads the status line and the `Proxy-Authenticate` header of a reply head. Nothing else is kept, so
/// text from the proxy never reaches an error or the log.
#[cfg(any(feature = "runtime", feature = "loopback"))]
pub(crate) fn parse_connect_head(head: &[u8]) -> Result<ConnectReply, &'static str> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err("no HTTP status line");
    }
    let code = parts.next().unwrap_or_default();
    let status = (code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()))
        .then(|| code.parse::<u16>().ok())
        .flatten()
        .filter(|status| (100..=599).contains(status))
        .ok_or("no status code")?;
    let mut challenge = ProxyChallenge::None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("proxy-authenticate")
            && challenge == ProxyChallenge::None
        {
            let scheme = value.split_whitespace().next().unwrap_or_default();
            challenge = if scheme.eq_ignore_ascii_case("basic") {
                ProxyChallenge::Basic
            } else if scheme.eq_ignore_ascii_case("negotiate") {
                ProxyChallenge::Negotiate
            } else if scheme.eq_ignore_ascii_case("ntlm") {
                ProxyChallenge::Ntlm
            } else {
                ProxyChallenge::Other
            };
        }
    }
    Ok(ConnectReply { status, challenge })
}

#[cfg(any(feature = "runtime", feature = "loopback"))]
impl ConnectReply {
    /// `Ok` for a 2xx answer, else the typed failure for `target`.
    pub(crate) fn into_result(
        self,
        target: &str,
        sent_credentials: bool,
    ) -> Result<(), NetFailure> {
        match self.status {
            200..=299 => Ok(()),
            403 => Err(NetFailure::ProxyForbidden {
                target: target.to_owned(),
            }),
            407 => Err(NetFailure::ProxyAuthRequired {
                target: target.to_owned(),
                challenge: self.challenge,
                sent_credentials,
            }),
            status => Err(NetFailure::ProxyRefused {
                target: target.to_owned(),
                status,
            }),
        }
    }
}
