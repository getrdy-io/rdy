//! The failure classes of `net.egress` and the words for each (03 section 3, "net.egress").
//!
//! A class is a short stable id, safe to put in a report and to match in a vendor's tooling. The
//! `Fix:` text for a class names the command or the setting to change and holds only the spec's own
//! host text and port, never a reply from the peer.

use rdy_engine::check::CheckError;
use rdy_engine::probe::net::TrustFailure;
use rdy_engine::probe::{AttemptOutcome, NetFailure, ProbeError};

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
}

impl Class {
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

    /// The class of a probe error, or the check error to end the check with when the error says the
    /// test or the build is wrong and not the network (a fixture with no recorded answer).
    pub(crate) fn of_error(error: ProbeError) -> Result<Self, CheckError> {
        Ok(match error {
            ProbeError::Denied { .. } => Self::RefusedByPolicy,
            ProbeError::Timeout => Self::Timeout,
            ProbeError::Net(failure) => match failure {
                NetFailure::Dns { .. } => Self::Dns,
                NetFailure::NotConnected { outcome, .. } => Self::of_connect(outcome),
                NetFailure::TlsReset { .. } => Self::ResetAfterHello,
                NetFailure::TlsAlert { .. } => Self::TlsAlert,
                NetFailure::TlsUntrusted { failure, .. } => Self::of_trust(failure),
                NetFailure::NoTrustRoots { .. } => Self::NoTrustStore,
                _ => Self::TlsFailed,
            },
            // The OS refused a socket call, or the resolver failed in its own way.
            ProbeError::PermissionDenied | ProbeError::NotFound | ProbeError::Io(_) => {
                Self::ConnectFailed
            }
            other => return Err(CheckError::Probe(other)),
        })
    }

    /// The `Fix:` text for `host` and `port`. `ip` is the address that did not answer, when one is known.
    pub(crate) fn fix(self, host: &str, port: u16, ip: Option<&str>) -> String {
        let at = format!("{host}:{port}");
        match self {
            Self::Dns => format!(
                "{host} does not resolve from this machine. Check the spelling in the spec. Ask the DNS team for a record or a conditional forwarder for it, or add a temporary line to `/etc/hosts`."
            ),
            Self::Refused => format!(
                "{at} refused the connection: nothing listens there, or a firewall rejects it. Check the port in the spec, and ask the network team to allow tcp/{port} to {host} from this machine."
            ),
            Self::Blackhole => format!(
                "No reply to SYN from {} in 3s, a firewall is dropping it. Ask the network team to allow tcp/{port} to {host} from this machine.",
                ip.unwrap_or(&at)
            ),
            Self::Unreachable => format!(
                "There is no route to {at}. Check the default route with `ip route` and ask the network team whether this subnet may reach {host}."
            ),
            Self::ConnectionReset => format!(
                "{at} reset the connection before it opened. A firewall or the server is closing it; ask the network team to allow tcp/{port} to {host}."
            ),
            Self::ConnectFailed => format!(
                "rdy could not open a connection to {at}. Check the host and port in the spec, and that this machine has a network interface that is up."
            ),
            Self::ClockOrExpiry => format!(
                "The certificate of {at} is expired or not valid yet. Check this machine's clock with `timedatectl` first. If the clock is right, the server's owner must renew the certificate."
            ),
            Self::TlsUnknownIssuer => format!(
                "The certificate of {at} comes from a CA this machine does not trust. A TLS-inspecting proxy is the usual cause. Add `net.tls_intercept` to the spec to see who issued it, then ask the network team to bypass inspection for {host}, or install that CA (Debian and Ubuntu: `update-ca-certificates`; RHEL: `update-ca-trust`)."
            ),
            Self::TlsNameMismatch => format!(
                "The certificate of {at} is not valid for the name {host}. Check the name in the spec, or ask the server's owner for a certificate that names it."
            ),
            Self::TlsUntrusted => format!(
                "The certificate of {at} was refused by the CA store rdy checked against. Run `openssl s_client -connect {at} -servername {host}` to see the chain, and ask the server's owner to fix it."
            ),
            Self::TlsAlert | Self::ResetAfterHello => format!(
                "{at} ended the TLS handshake. SNI filtering, or a server that speaks only TLS 1.0 and 1.1, does this. Run `openssl s_client -connect {at} -servername {host}` to see which, and ask the network team whether {host} is allowed."
            ),
            Self::TlsFailed => format!(
                "{at} did not complete a TLS handshake. Check that it serves TLS 1.2 or 1.3 on that port and not plain HTTP. To test only the TCP connect, set `tls: false` on the endpoint."
            ),
            Self::NoTrustStore => "This machine has no CA store rdy can read. Install it with `apt-get install ca-certificates` or `dnf install ca-certificates`, or set `trust: bundled` on the check.".to_owned(),
            Self::RefusedByPolicy => format!(
                "rdy will not contact {at}: the name or address is link-local, metadata, unspecified, multicast or broadcast. Put the real endpoint address in the spec."
            ),
            Self::Timeout => format!(
                "A step for {at} ran out of time. Run again, and if it repeats check the nameservers in `/etc/resolv.conf` and the path to {host}."
            ),
        }
    }
}
