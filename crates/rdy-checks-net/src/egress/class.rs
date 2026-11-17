//! The failure classes of `net.egress` and the words for each (03 section 3, "net.egress").
//!
//! A class is a short stable id, safe to put in a report and to match in a vendor's tooling. The
//! `Fix:` text for a class names the command or the setting to change and holds only the spec's own
//! host text and port, never a reply from the peer.

use rdy_engine::check::{CheckError, Os};
use rdy_engine::probe::net::TrustFailure;
use rdy_engine::probe::{AttemptOutcome, NetFailure, ProbeError, ProxyChallenge};

/// Why one endpoint could not be reached, by stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// The name did not resolve, or the lookup ran out of time.
    Dns,
    /// The port is closed, or a firewall rejects.
    Refused,
    /// The SYN got no answer.
    Blackhole,
    /// No route to the network or the host.
    Unreachable,
    /// The connection was reset before it opened.
    ConnectionReset,
    /// Another failure to connect.
    ConnectFailed,
    /// The certificate has expired or is not valid yet.
    ClockOrExpiry,
    /// The issuer is not trusted by the roots in use.
    TlsUnknownIssuer,
    /// The certificate does not name the host.
    TlsNameMismatch,
    /// The certificate was refused for another reason.
    TlsUntrusted,
    /// The server answered the handshake with an alert.
    TlsAlert,
    /// The connection was reset during the handshake.
    ResetAfterHello,
    /// The handshake failed for another reason.
    TlsFailed,
    /// There is no CA store to judge the certificate against.
    NoTrustStore,
    /// rdy's own address policy refused the call.
    RefusedByPolicy,
    /// A stage ran out of time.
    Timeout,
    /// The server answered HTTP with a status the spec does not accept.
    HttpStatus,
    /// The server accepted the connection and did not answer HTTP.
    HttpFailed,
    /// The proxy answered 403: the endpoint is not on its allow list.
    ProxyForbidden,
    /// The proxy answered 407: it wants credentials rdy did not send, or rejected the ones it sent.
    ProxyAuthRequired,
    /// The proxy answered another status than 2xx, 403 or 407 to the tunnel.
    ProxyRefused,
    /// The proxy answered something that is not HTTP, or the reply was cut off.
    ProxyBadReply,
    /// rdy could not open a connection to the proxy itself.
    ProxyUnreachable,
}

impl Class {
    /// Every class, for the tests that audit all the words.
    #[cfg(test)]
    pub(crate) const ALL: [Class; 23] = [
        Self::Dns,
        Self::Refused,
        Self::Blackhole,
        Self::Unreachable,
        Self::ConnectionReset,
        Self::ConnectFailed,
        Self::ClockOrExpiry,
        Self::TlsUnknownIssuer,
        Self::TlsNameMismatch,
        Self::TlsUntrusted,
        Self::TlsAlert,
        Self::ResetAfterHello,
        Self::TlsFailed,
        Self::NoTrustStore,
        Self::RefusedByPolicy,
        Self::Timeout,
        Self::HttpStatus,
        Self::HttpFailed,
        Self::ProxyForbidden,
        Self::ProxyAuthRequired,
        Self::ProxyRefused,
        Self::ProxyBadReply,
        Self::ProxyUnreachable,
    ];

    /// The id written to the report.
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Refused => "refused",
            Self::Blackhole => "blackhole",
            Self::Unreachable => "unreachable",
            Self::ConnectionReset => "connection_reset",
            Self::ConnectFailed => "connect_failed",
            Self::ClockOrExpiry => "clock_or_expiry",
            Self::TlsUnknownIssuer => "tls_unknown_issuer",
            Self::TlsNameMismatch => "tls_name_mismatch",
            Self::TlsUntrusted => "tls_untrusted",
            Self::TlsAlert => "tls_alert",
            Self::ResetAfterHello => "reset_after_hello",
            Self::TlsFailed => "tls_failed",
            Self::NoTrustStore => "no_trust_store",
            Self::RefusedByPolicy => "refused_by_policy",
            Self::Timeout => "timeout",
            Self::HttpStatus => "http_status",
            Self::HttpFailed => "http_failed",
            Self::ProxyForbidden => "proxy_403",
            Self::ProxyAuthRequired => "proxy_407",
            Self::ProxyRefused => "proxy_refused",
            Self::ProxyBadReply => "proxy_bad_reply",
            Self::ProxyUnreachable => "proxy_unreachable",
        }
    }

    /// The class of a connection that did not open, from what the attempts came to.
    pub(crate) fn of_connect(outcome: AttemptOutcome) -> Self {
        match outcome {
            AttemptOutcome::Refused => Self::Refused,
            AttemptOutcome::TimedOut => Self::Blackhole,
            AttemptOutcome::Unreachable => Self::Unreachable,
            AttemptOutcome::Reset => Self::ConnectionReset,
            _ => Self::ConnectFailed,
        }
    }

    /// The class of a certificate the roots did not accept.
    pub(crate) fn of_trust(failure: TrustFailure) -> Self {
        if failure.is_clock_or_expiry() {
            return Self::ClockOrExpiry;
        }
        match failure {
            TrustFailure::UnknownIssuer => Self::TlsUnknownIssuer,
            TrustFailure::NameMismatch => Self::TlsNameMismatch,
            _ => Self::TlsUntrusted,
        }
    }

    /// The class of a probe error and its detail, or the check error to end the check with when the
    /// error says the test or the build is wrong and not the network (a fixture with no recorded
    /// answer, a proxied call when the run has no proxy).
    ///
    /// The detail is a fixed word or a status code that the fix text reads: for `proxy_407` it is
    /// `negotiate`, `rejected` or `needed`, and for `proxy_refused` the status.
    pub(crate) fn of_error(error: ProbeError) -> Result<(Self, Option<String>), CheckError> {
        let class = match error {
            ProbeError::Denied { .. } => Self::RefusedByPolicy,
            ProbeError::Timeout => Self::Timeout,
            ProbeError::Net(failure) => match failure {
                NetFailure::Dns { .. } => Self::Dns,
                NetFailure::NotConnected { outcome, .. } => Self::of_connect(outcome),
                NetFailure::TlsReset { .. } => Self::ResetAfterHello,
                NetFailure::TlsAlert { .. } => Self::TlsAlert,
                NetFailure::TlsUntrusted { failure, .. } => Self::of_trust(failure),
                NetFailure::HttpFailed { .. } => Self::HttpFailed,
                NetFailure::NoTrustRoots { .. } => Self::NoTrustStore,
                NetFailure::ProxyForbidden { .. } => Self::ProxyForbidden,
                NetFailure::ProxyAuthRequired {
                    challenge,
                    sent_credentials,
                    ..
                } => {
                    let word = match (challenge, sent_credentials) {
                        (ProxyChallenge::Negotiate | ProxyChallenge::Ntlm, _) => "negotiate",
                        (_, true) => "rejected",
                        (_, false) => "needed",
                    };
                    return Ok((Self::ProxyAuthRequired, Some(word.to_owned())));
                }
                NetFailure::ProxyRefused { status, .. } => {
                    return Ok((Self::ProxyRefused, Some(status.to_string())));
                }
                NetFailure::ProxyBadReply { .. } => Self::ProxyBadReply,
                // The check picks the proxy route only when the run has a proxy, so this is a bug in
                // the build or the test and not something the network did.
                other @ NetFailure::NoProxy => {
                    return Err(CheckError::Probe(ProbeError::Net(other)));
                }
                _ => Self::TlsFailed,
            },
            // The OS refused a socket call, or the resolver failed in its own way.
            ProbeError::PermissionDenied | ProbeError::NotFound | ProbeError::Io(_) => {
                Self::ConnectFailed
            }
            other => return Err(CheckError::Probe(other)),
        };
        Ok((class, None))
    }

    /// The `Fix:` text for `host` and `port` on `os`. `detail` is the address that did not answer for a blackhole, or the status for
    /// `http_status`, when one is known. Every command in it is on the fix-text allow-list (a test audits all of them).
    pub(crate) fn fix(self, os: Os, host: &str, port: u16, detail: Option<&str>) -> String {
        let at = format!("{host}:{port}");
        let hosts_file = match os {
            Os::Windows => "`%SystemRoot%\\System32\\drivers\\etc\\hosts`",
            _ => "`/etc/hosts`",
        };
        let sclient = match os {
            Os::Windows => format!(
                " Where openssl is installed, run `openssl s_client -connect {at} -servername {host}` to see the chain."
            ),
            _ => format!(
                " Run `openssl s_client -connect {at} -servername {host}` to see the chain."
            ),
        };
        match self {
            Self::Dns => format!(
                "{host} does not resolve from this machine. Check the spelling in the spec. Ask the DNS team for a record or a conditional forwarder for it, or add a temporary line to {hosts_file}."
            ),
            Self::Refused => format!(
                "{at} refused the connection: nothing listens there, or a firewall rejects it. Check the port in the spec, and ask the network team to allow tcp/{port} to {host} from this machine."
            ),
            // The catalog text names the source address. rdy does not know which address the OS picked
            // for the route, and guessing one would send the network team to the wrong rule, so the
            // text says "from this machine" (03 "Built in M1-095").
            Self::Blackhole => format!(
                "No reply to SYN from {} in 3s, a firewall is dropping it. Ask the network team to allow tcp/{port} to {host} from this machine.",
                detail.unwrap_or(&at)
            ),
            Self::Unreachable => {
                let routes = match os {
                    Os::Windows => "`route print`",
                    Os::Macos => "`netstat -rn`",
                    _ => "the output of ip route",
                };
                format!(
                    "There is no route to {at}. Check the default route with {routes} and ask the network team whether this subnet may reach {host}."
                )
            }
            Self::ConnectionReset => format!(
                "{at} reset the connection before it opened. A firewall or the server is closing it; ask the network team to allow tcp/{port} to {host}."
            ),
            Self::ConnectFailed => format!(
                "rdy could not open a connection to {at}. Check the host and port in the spec, and that this machine has a network interface that is up."
            ),
            Self::ClockOrExpiry => {
                let clock = match os {
                    Os::Windows => "`w32tm /query /status`",
                    Os::Macos => "`sntp time.apple.com`",
                    _ => "`timedatectl`",
                };
                format!(
                    "The certificate of {at} is expired or not valid yet. Check this machine's clock with {clock} first. If the clock is right, the server's owner must renew the certificate."
                )
            }
            Self::TlsUnknownIssuer => {
                let install = match os {
                    Os::Windows => "import that CA into the Trusted Root Certification Authorities store with `certlm.msc`".to_owned(),
                    Os::Macos => "install that CA with `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt`".to_owned(),
                    _ => "install that CA (Debian and Ubuntu: `update-ca-certificates`; RHEL: `update-ca-trust`)".to_owned(),
                };
                format!(
                    "The certificate of {at} comes from a CA this machine does not trust. A TLS-inspecting proxy is the usual cause. Add `net.tls_intercept` to the spec to see who issued it, then ask the network team to bypass inspection for {host}, or {install}."
                )
            }
            Self::TlsNameMismatch => format!(
                "The certificate of {at} is not valid for the name {host}. Check the name in the spec, or ask the server's owner for a certificate that names it."
            ),
            Self::TlsUntrusted => format!(
                "The certificate of {at} was refused by the CA store rdy checked against.{sclient} Ask the server's owner to fix the chain."
            ),
            Self::TlsAlert | Self::ResetAfterHello => format!(
                "{at} ended the TLS handshake. SNI filtering, or a server that speaks only TLS 1.0 and 1.1, does this.{sclient} Ask the network team whether {host} is allowed."
            ),
            Self::TlsFailed => format!(
                "{at} did not complete a TLS handshake. Check that it serves TLS 1.2 or 1.3 on that port and not plain HTTP. To test only the TCP connect, set `tls: false` on the endpoint."
            ),
            Self::NoTrustStore => match os {
                Os::Linux => "This machine has no CA store rdy can read. Install it with `apt-get install ca-certificates` or `dnf install ca-certificates`, or set `trust: bundled` on the check.".to_owned(),
                _ => "rdy could not read the OS certificate store. Check that the store is intact, or set `trust: bundled` on the check.".to_owned(),
            },
            Self::RefusedByPolicy => format!(
                "rdy will not contact {at}: the name or address is link-local, metadata, unspecified, multicast or broadcast. Put the real endpoint address in the spec."
            ),
            Self::HttpStatus => {
                let status = detail.unwrap_or("an unexpected status");
                let why = match detail.and_then(|d| d.parse::<u16>().ok()) {
                    Some(401) => "it wants credentials rdy does not send. If that is normal for this URL, add the status to `expect_status`.",
                    Some(407) => "a proxy that this route did not expect asked for credentials: an intercepting proxy sits on the direct path to the host. Ask the network team which proxy it is and whether to bypass it for this host, or set `HTTPS_PROXY` for the product service.",
                    Some(403) => "a firewall, a proxy allow list or the server refuses this machine. Ask the owner of the proxy or the server to allow it, or add 403 to `expect_status` if that is normal.",
                    Some(404 | 410) => "the path does not exist there. Check the URL in the spec.",
                    Some(429) => "the server is rate limiting. Run again later.",
                    Some(500..=599) => "the server, or a proxy in front of it, is failing. Run again; if it repeats, ask the owner of the server.",
                    _ => "that is not a status the spec accepts. Check the URL, or list the status in `expect_status`.",
                };
                format!("{at} answered {status}: {why}")
            }
            Self::HttpFailed => format!(
                "{at} accepted the connection and did not answer HTTP correctly. Check that the port serves HTTP and not another protocol, and that the scheme in the spec (http or https) matches it. A TLS port reached with `http://` gives this."
            ),
            Self::ProxyForbidden => {
                if detail == Some("request") {
                    format!(
                        "The proxy answered 403 to the request for {at}. Ask the proxy team to add {host} to the allow list. If the server itself answers 403 there, add 403 to `expect_status` on the endpoint."
                    )
                } else {
                    let ports = if port == 443 {
                        String::new()
                    } else {
                        format!(
                            " A proxy that allows tunnels only to port 443 refuses tcp/{port}: ask for that port too."
                        )
                    };
                    format!(
                        "The proxy refused CONNECT to {at}. Ask the proxy team to add it to the allow list.{ports}"
                    )
                }
            }
            Self::ProxyAuthRequired => match detail {
                Some("negotiate") => format!(
                    "The proxy wants integrated sign-in (Negotiate or NTLM) for {at}, which rdy does not attempt. Ask the proxy team to allow {host} without sign-in from this machine."
                ),
                Some("rejected") => "The proxy rejected the user name or password in the proxy URL (407). Check them, and write special characters as percent escapes (an at sign is %40). Then run rdy again with the corrected `HTTPS_PROXY`.".to_owned(),
                _ => "The proxy wants a user name and password (407). Put them in the proxy URL, as in `HTTPS_PROXY=http://user:password@proxy.example:3128`, then run rdy again.".to_owned(),
            },
            Self::ProxyRefused => {
                let status = detail.unwrap_or("an error status");
                format!(
                    "The proxy answered {status} to the tunnel for {at}. Ask the proxy team why it will not open it. 502 and 504 usually mean the proxy cannot reach {host}, so check DNS and the route on the proxy."
                )
            }
            Self::ProxyBadReply => "The proxy address did not answer like an HTTP proxy. Check that `HTTPS_PROXY` points at the proxy's HTTP port, not a TLS, SOCKS or other port.".to_owned(),
            Self::ProxyUnreachable => "rdy could not connect to the proxy. Check the host and port in `HTTPS_PROXY` or `HTTP_PROXY`, and that a firewall lets this machine reach the proxy. If the product does not use a proxy here, unset both variables.".to_owned(),
            Self::Timeout => format!(
                "A step for {at} ran out of time. Run again, and if it repeats check the nameservers this machine uses and the path to {host}."
            ),
        }
    }
}
