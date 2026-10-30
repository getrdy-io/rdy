//! TLS with the system roots, and the recording chain probe (M1-092, ADR 0014 decision 3, 02 "Network").
//!
//! [`Probe::tls_chain`] opens a connection to one of the check's own spec hosts (the same policy, the
//! same attempts and the same proxy `CONNECT` as [`Probe::tcp`]), runs one TLS handshake and returns the
//! chain the server presented, with two verdicts: does it validate against the OS roots, and does it
//! validate against the bundled Mozilla roots. A chain trusted by the machine only, an unknown issuer and
//! an expired leaf are all data in the [`TlsChain`], because they are what `net.tls_intercept` and
//! `net.egress` report. The call fails only when no chain could be had.
//!
//! **No application data.** The handshake ends and the facade sends `close_notify`. No HTTP request,
//! header or credential is written, so a server that is not trusted learns nothing it did not already
//! know from the `ClientHello`. The verifier that makes this possible accepts every chain, so it is
//! private to this module (`record`) and the stream never leaves it: the call returns the chain, not a
//! stream. The HTTP probe (M1-093) verifies strictly with its own configuration.
//!
//! **SNI.** The server name is built from the spec host of the call and from nothing else: not from
//! the proxy, not from an address a lookup returned. A name host sends that name. An address host sends
//! no SNI, as TLS says, and the log entry has no `sni` field.
//!
//! **Roots.** The OS roots come from `NativeCall::SystemRoots`, asked once per run by the run-level
//! probe (the log has one `native` entry with `check: null`, not one per check) and kept in the hub. They
//! are capped at [`MAX_SYSTEM_ROOTS`](crate::probe::MAX_SYSTEM_ROOTS) certificates of
//! [`MAX_ROOT_BYTES`](crate::probe::MAX_ROOT_BYTES) each. A store that is empty or that the OS could not
//! give leaves the system verdict [`TrustVerdict::Unavailable`], with [`NoRoots::Empty`] ("no OS trust
//! store found"), [`NoRoots::Unreadable`] ("the OS trust store could not be read") or
//! [`NoRoots::Overridden`] ("unset `SSL_CERT_FILE` and `SSL_CERT_DIR`"; Windows reads no files in M1).
//! The run keeps an empty store, a read error and an override; it asks again after a timeout or a
//! refusal. The bundled roots are the `webpki-roots` list. There is **no revocation check**:
//! [`REVOCATION_NOTE`] is the wording a report uses.
//!
//! **The log.** One `tls` entry per call: `host`, `port`, `via_proxy`, `addr` and, for a name, `sni`. The
//! entry holds no certificate, name from a certificate or alert text.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rdy_spec::Target;
use rdy_spec::result::ActionKind;
use rdy_spec::scalar::Host;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use serde_json::{Map, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;

use self::record::{Seen, Trust, recording_client};
use super::{Dialed, NetFailure, Probe, ProbeError, ProbeHub, Route, TcpReport};
use super::{fail_net, proxy_for, settle};
use crate::probe::log::Pending;
use crate::probe::proxy::ProxyUrl;
use crate::probe::sock::host_port;
use crate::probe::{NativeCall, NativeValue, refuse};

mod record;
#[cfg(test)]
mod tests;

/// The longest the handshake waits, from the first byte of the `ClientHello` to the last of the
/// server's `Finished`.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest the `close_notify` and the shutdown of the write side wait.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// What a report says about revocation, in these words: the facade never asks an OCSP responder or
/// reads a CRL.
pub const REVOCATION_NOTE: &str = "no revocation check";

/// The protocols the handshake offers, in order. The server's choice is [`TlsChain::alpn`].
pub const ALPN_PROTOCOLS: [&str; 2] = ["h2", "http/1.1"];

/// Which set of roots a verdict is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Roots {
    /// The roots of the OS store (`NativeCall::SystemRoots`).
    System,
    /// The Mozilla roots bundled with rdy.
    Bundled,
}

/// Why a chain did not validate against a set of roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustFailure {
    /// No root in the set signed the chain: the issuer's CA is not installed here.
    UnknownIssuer,
    /// A certificate in the chain has expired. Report it as clock or expiry, not as interception.
    Expired,
    /// A certificate in the chain is not valid yet. Report it as clock or expiry too.
    NotYetValid,
    /// The leaf is not valid for the name asked for.
    NameMismatch,
    /// A certificate's signature did not verify.
    BadSignature,
    /// rustls policy refused the chain for another reason: no subject alternative name, a SHA-1
    /// signature, a key usage that does not fit, a malformed certificate.
    Policy,
}

impl TrustFailure {
    /// `true` for the two failures that point at a wrong clock or an old certificate and not at the
    /// issuer: `Expired` and `NotYetValid`.
    #[must_use]
    pub fn is_clock_or_expiry(self) -> bool {
        matches!(self, Self::Expired | Self::NotYetValid)
    }
}

/// Whether a chain validates against one set of roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustVerdict {
    /// The chain validates.
    Valid,
    /// The chain does not validate, for this reason.
    Rejected(TrustFailure),
    /// The set has no roots to judge against, for this reason.
    Unavailable(NoRoots),
}

/// Why there are no OS roots to judge a chain against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoRoots {
    /// The OS has no trust store rdy can see, or the store holds no certificate. A check reports "no OS
    /// trust store found".
    Empty,
    /// The OS has a store but it could not be read: a file the operator named with `SSL_CERT_FILE` or
    /// `SSL_CERT_DIR` was missing or refused, or the OS gave an error. A check reports "the OS trust store
    /// could not be read" and not "no store found".
    Unreadable,
    /// `SSL_CERT_FILE` or `SSL_CERT_DIR` is set and rdy may not read what it names on this OS (Windows,
    /// in this version). A check reports that and says to unset the variable.
    Overridden,
}

/// What one TLS call found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsChain {
    /// The DER of each certificate the server sent, its own first. The root is not sent as a rule.
    pub certs: Vec<Vec<u8>>,
    /// The server name the handshake sent, which is the spec host. `None` for an address host.
    pub sni: Option<String>,
    /// Whether the chain validates against the OS roots.
    pub system: TrustVerdict,
    /// Whether the chain validates against the bundled Mozilla roots.
    pub bundled: TrustVerdict,
    /// How many OS roots the verdict used. 0 means no OS trust store was found.
    pub system_roots: usize,
    /// `"TLS 1.2"` or `"TLS 1.3"`.
    pub protocol: Option<&'static str>,
    /// The protocol the server chose from [`ALPN_PROTOCOLS`], if it chose one.
    pub alpn: Option<&'static str>,
    /// The connection that carried the handshake: its attempts and, through a proxy, the `CONNECT`.
    pub connect: TcpReport,
    /// How long the handshake took.
    pub handshake: Duration,
}

impl TlsChain {
    /// The verdict for one set of roots.
    #[must_use]
    pub fn verdict(&self, roots: Roots) -> TrustVerdict {
        match roots {
            Roots::System => self.system,
            Roots::Bundled => self.bundled,
        }
    }
}

/// The trust stores of a run, built the first time a TLS call needs them.
#[derive(Debug, Default)]
pub(crate) struct TlsState {
    system: OnceCell<Arc<Trust>>,
    bundled: OnceCell<Arc<Trust>>,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl Probe {
    /// Connects to `target`, one of the check's own spec hosts, runs one TLS handshake and returns the
    /// chain the server presented with its verdicts. It sends no application data. See the
    /// [module docs](crate::probe::net).
    ///
    /// The policy is that of [`Probe::tcp`]: the check must declare `PeerClass::SpecHosts` (and
    /// `PeerClass::Proxy` for `Route::ViaProxy`), the host and port must be one of its spec hosts, and a
    /// forbidden address, literal or resolved, is refused.
    ///
    /// # Errors
    ///
    /// - [`ProbeError::Denied`] as for `tcp`.
    /// - [`ProbeError::Net`] for a name that did not resolve, a proxy that refused (as for `tcp`),
    ///   [`NetFailure::NotConnected`], [`NetFailure::TlsReset`], [`NetFailure::TlsAlert`] and
    ///   [`NetFailure::TlsFailed`].
    /// - [`ProbeError::Timeout`] when the lookup, the `CONNECT` or the handshake ran out of time.
    /// - [`ProbeError::NotRecorded`] on a replay backend with no `system_roots` answer recorded.
    pub async fn tls_chain(&self, target: &Target, route: Route) -> Result<TlsChain, ProbeError> {
        let what = host_port(target);
        let sni = sni_of(target);
        let mut fields = Map::new();
        fields.insert("host".to_owned(), target.host().to_string().into());
        fields.insert("port".to_owned(), target.port().into());
        fields.insert("via_proxy".to_owned(), Value::Null);
        fields.insert("addr".to_owned(), Value::Null);
        if let Some(name) = &sni {
            fields.insert("sni".to_owned(), name.clone().into());
        }
        let (hub, mut entry) = self.begin(ActionKind::Tls, fields, &what)?;

        if let Err(rule) = self.admit_tcp(target, route) {
            return Err(refuse(entry, rule, &what));
        }
        let proxy = match proxy_for(hub, route, &mut entry) {
            Ok(proxy) => proxy,
            Err(failure) => return Err(fail_net(entry, failure)),
        };

        let result = self
            .unless_ended(&what, self.handshake(hub, target, proxy))
            .await;
        match result {
            Err(ProbeError::Net(failure)) => Err(fail_net(entry, failure)),
            other => settle(entry, other, set_addr),
        }
    }

    /// Roots, connection, handshake. Everything that can fail before the entry is closed.
    async fn handshake(
        &self,
        hub: &ProbeHub,
        target: &Target,
        proxy: Option<&ProxyUrl>,
    ) -> Result<TlsChain, ProbeError> {
        let what = host_port(target);
        let failed = |reason: &'static str| {
            ProbeError::Net(NetFailure::TlsFailed {
                target: what.clone(),
                reason,
            })
        };
        let name = server_name(target)
            .ok_or_else(|| failed("the host is not a name TLS can carry in a ClientHello"))?;
        let provider = provider();

        // Connect first: a host that cannot be reached does not cost a read of the OS store.
        let Dialed { report, stream } = self.dial(hub, target, proxy).await?;
        let Some(stream) = stream else {
            return Err(ProbeError::Net(NetFailure::NotConnected {
                target: what.clone(),
                reason: report.failure(),
            }));
        };
        let (system, bundled) = self.trust(hub, &provider).await?;

        let system_roots = system.roots();
        let (config, recorder) = recording_client(system, bundled, provider)
            .map_err(|_| failed("rustls could not build a client configuration"))?;
        let connector = TlsConnector::from(Arc::new(config));

        let started = Instant::now();
        let limit = self.scope.peers.timeout(HANDSHAKE_TIMEOUT);
        let mut tls = match timeout(limit, connector.connect(name, stream)).await {
            Err(_elapsed) => return Err(ProbeError::Timeout),
            Ok(Err(error)) => return Err(handshake_failure(&error, &what)),
            Ok(Ok(tls)) => tls,
        };
        let handshake = started.elapsed();
        let (protocol, alpn) = {
            let (_, connection) = tls.get_ref();
            (
                connection.protocol_version().and_then(protocol_name),
                connection.alpn_protocol().and_then(alpn_name),
            )
        };
        // `close_notify` and the end of the write side. Nothing else is ever written.
        let _ = timeout(CLOSE_TIMEOUT, tls.shutdown()).await;

        let Seen {
            chain,
            system,
            bundled,
        } = recorder
            .take()
            .ok_or_else(|| failed("the server presented no certificate"))?;
        Ok(TlsChain {
            certs: chain,
            sni: sni_of(target),
            system,
            bundled,
            system_roots,
            protocol,
            alpn,
            connect: report,
            handshake,
        })
    }

    /// The two trust stores, built on first use and kept for the run.
    ///
    /// The run keeps what is a fact about the machine: the roots, an empty store, an OS with no source
    /// and a store that did not read. A timeout, a refusal by policy or any other error is not a fact
    /// about the store: this call gets an `Unreadable` set and the next call asks again.
    async fn trust(
        &self,
        hub: &ProbeHub,
        provider: &Arc<CryptoProvider>,
    ) -> Result<(Arc<Trust>, Arc<Trust>), ProbeError> {
        let asked = hub
            .tls
            .system
            .get_or_try_init(|| async {
                // The run-level probe asks, so the one `native` entry has `check: null` and is not
                // charged to whichever check happened to make the first TLS call.
                let asked = hub
                    .run_probe_for(self.scope.os)
                    .native(NativeCall::SystemRoots)
                    .await;
                match asked {
                    Ok(NativeValue::SystemRoots(certs)) => {
                        Ok(Arc::new(Trust::from_der(&certs, provider)))
                    }
                    // No source on this OS.
                    Err(ProbeError::Unsupported(_)) => {
                        Ok(Arc::new(Trust::unavailable(NoRoots::Empty)))
                    }
                    // The operator replaced the store with a variable this OS may not read.
                    Err(ProbeError::StoreOverridden) => {
                        Ok(Arc::new(Trust::unavailable(NoRoots::Overridden)))
                    }
                    // The store is there and did not read.
                    Err(
                        ProbeError::Io(_) | ProbeError::NotFound | ProbeError::PermissionDenied,
                    ) => Ok(Arc::new(Trust::unavailable(NoRoots::Unreadable))),
                    // Anything else says nothing about the store and is not kept. A fixture with no
                    // answer is a test bug and says so.
                    Err(error) => Err(error),
                    Ok(_) => Err(ProbeError::Io(
                        "the trust roots came back as another kind of value".to_owned(),
                    )),
                }
            })
            .await;
        let system = match asked {
            Ok(system) => Arc::clone(system),
            Err(error @ ProbeError::NotRecorded(_)) => return Err(error),
            Err(_) => Arc::new(Trust::unavailable(NoRoots::Unreadable)),
        };
        let bundled = hub
            .tls
            .bundled
            .get_or_init(|| async { Arc::new(Trust::bundled(provider)) })
            .await;
        Ok((system, Arc::clone(bundled)))
    }
}

/// Sets `addr` to the address that connected, for a direct call. Through a proxy it stays `null`.
fn set_addr(chain: &TlsChain, entry: &mut Pending) {
    let addr = chain
        .connect
        .addr
        .filter(|_| !chain.connect.via_proxy)
        .map_or(Value::Null, |a| a.ip().to_string().into());
    entry.set("addr", addr);
}

/// The name the handshake sends as SNI, or `None` for an address host.
fn sni_of(target: &Target) -> Option<String> {
    match target.host() {
        Host::Name(name) => Some(name.clone()),
        _ => None,
    }
}

/// The server name of the handshake, from the spec host alone.
fn server_name(target: &Target) -> Option<ServerName<'static>> {
    match target.host() {
        Host::Name(name) => ServerName::try_from(name.clone()).ok(),
        Host::Ipv4(addr) => Some(ServerName::IpAddress(IpAddr::V4(*addr).into())),
        Host::Ipv6(addr) => Some(ServerName::IpAddress(IpAddr::V6(*addr).into())),
        // `Host` is non-exhaustive: a kind of host this version does not know has no server name.
        _ => None,
    }
}

fn protocol_name(version: rustls::ProtocolVersion) -> Option<&'static str> {
    match version {
        rustls::ProtocolVersion::TLSv1_2 => Some("TLS 1.2"),
        rustls::ProtocolVersion::TLSv1_3 => Some("TLS 1.3"),
        _ => None,
    }
}

fn alpn_name(chosen: &[u8]) -> Option<&'static str> {
    ALPN_PROTOCOLS
        .iter()
        .copied()
        .find(|protocol| protocol.as_bytes() == chosen)
}

/// Types a handshake failure. A reset before the server's first flight, an alert, and anything else
/// rustls objects to are different problems for the person fixing them.
fn handshake_failure(error: &io::Error, what: &str) -> ProbeError {
    let target = what.to_owned();
    if let Some(tls) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return ProbeError::Net(match tls {
            rustls::Error::AlertReceived(alert) => NetFailure::TlsAlert {
                target,
                alert: format!("{alert:?}"),
            },
            rustls::Error::InvalidCertificate(_) => NetFailure::TlsFailed {
                target,
                reason: "the server's certificate could not be used to check its signature",
            },
            rustls::Error::PeerIncompatible(_) => NetFailure::TlsFailed {
                target,
                reason: "no TLS version, cipher or signature is shared with the server",
            },
            _ => NetFailure::TlsFailed {
                target,
                reason: "the server did not speak TLS as expected",
            },
        });
    }
    match error.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => ProbeError::Net(NetFailure::TlsReset { target }),
        _ => ProbeError::from_io(error),
    }
}
