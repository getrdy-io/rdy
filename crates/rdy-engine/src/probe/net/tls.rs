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
use self::strict::{StrictError, strict_client};
use super::BoxedStream;
use super::{Dialed, NetFailure, Probe, ProbeError, ProbeHub, Route, TcpReport};
use super::{fail_net, proxy_for, settle};
use crate::probe::log::Pending;
use crate::probe::proxy::ProxyUrl;
use crate::probe::sock::host_port;
use crate::probe::{NativeCall, NativeValue, StoreSource, refuse};

pub use crate::probe::{NoRoots, TrustFailure};

mod record;
mod strict;
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
        let (mut config, recorder) = recording_client(system, bundled, provider)
            .map_err(|_| failed("rustls could not build a client configuration"))?;
        // A test pins the clock here, and the verdicts of both root sets see the pinned time.
        pin_clock(hub, &mut config);
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
    async fn trust(
        &self,
        hub: &ProbeHub,
        provider: &Arc<CryptoProvider>,
    ) -> Result<(Arc<Trust>, Arc<Trust>), ProbeError> {
        let system = self.system_trust(hub, provider).await?;
        let bundled = self.bundled_trust(hub, provider).await;
        Ok((system, bundled))
    }

    /// The OS roots, asked once for the run.
    ///
    /// The run keeps what is a fact about the machine: the roots, an empty store, an OS with no source
    /// and a store that did not read. A timeout, a refusal by policy or any other error is not a fact
    /// about the store: this call gets an `Unreadable` set and the next call asks again.
    async fn system_trust(
        &self,
        hub: &ProbeHub,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Arc<Trust>, ProbeError> {
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
                    Ok(NativeValue::SystemRoots(found)) => {
                        Ok(Arc::new(Trust::from_der(&found, provider)))
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
        match asked {
            Ok(system) => Ok(Arc::clone(system)),
            Err(error @ ProbeError::NotRecorded(_)) => Err(error),
            Err(_) => Ok(Arc::new(Trust::unavailable(NoRoots::Unreadable))),
        }
    }

    /// The bundled Mozilla roots, built once for the run. Nothing is read from the machine.
    async fn bundled_trust(&self, hub: &ProbeHub, provider: &Arc<CryptoProvider>) -> Arc<Trust> {
        let bundled = hub
            .tls
            .bundled
            .get_or_init(|| async { Arc::new(Trust::bundled(provider)) })
            .await;
        Arc::clone(bundled)
    }

    /// Wraps `stream` in a TLS session that verifies strictly (M1-093): the roots of `roots` accept
    /// the server's chain for the spec host, or the handshake fails and nothing is sent. The caller
    /// speaks HTTP/1.1 on the result; the ALPN offer is `http/1.1` only.
    ///
    /// `Roots::System` asks for the OS store, once for the run; `Roots::Bundled` never touches the
    /// machine.
    pub(super) async fn secure(
        &self,
        hub: &ProbeHub,
        target: &Target,
        stream: BoxedStream,
        roots: Roots,
    ) -> Result<Secured, ProbeError> {
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
        let trust = match roots {
            Roots::System => self.system_trust(hub, &provider).await?,
            Roots::Bundled => self.bundled_trust(hub, &provider).await,
        };
        let mut config = strict_client(&trust, provider).map_err(|error| match error {
            StrictError::NoRoots(reason) => ProbeError::Net(NetFailure::NoTrustRoots {
                target: what.clone(),
                reason,
            }),
            StrictError::Config => failed("rustls could not build a client configuration"),
        })?;
        pin_clock(hub, &mut config);
        let connector = TlsConnector::from(Arc::new(config));

        let started = Instant::now();
        let limit = self.scope.peers.timeout(HANDSHAKE_TIMEOUT);
        let tls = match timeout(limit, connector.connect(name, stream)).await {
            Err(_elapsed) => return Err(ProbeError::Timeout),
            Ok(Err(error)) => return Err(strict_failure(&error, &what)),
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
        Ok(Secured {
            stream: tls,
            protocol,
            alpn,
            handshake,
        })
    }

    /// The OS trust store as the run found it: where it was read from and the SHA-256 of each root.
    /// The store is asked once for the run, as for [`Probe::tls_chain`], and the answer is kept.
    ///
    /// This is a read of what the run already holds: it adds no entry of its own, and the one `native`
    /// entry with `check: null` records the question. An empty or unreadable store is not an error: it
    /// is [`TrustStore::missing`], so a check can say "no OS trust store found".
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] after the check ended or on a probe with no hub, and
    /// [`ProbeError::NotRecorded`] on a replay backend with no `system_roots` answer recorded.
    pub async fn trust_store(&self) -> Result<TrustStore, ProbeError> {
        let Some(hub) = &self.hub else {
            return Err(ProbeError::denied(
                crate::probe::RULE_NO_PROBE,
                "trust store",
            ));
        };
        if self.scope.ended.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ProbeError::denied(
                crate::probe::RULE_CHECK_FINISHED,
                "trust store",
            ));
        }
        let provider = provider();
        let trust = self
            .unless_ended("trust store", self.system_trust(hub, &provider))
            .await?;
        Ok(TrustStore {
            missing: trust.verifier.is_none().then(|| trust.missing()),
            sources: trust.sources().to_vec(),
            roots: trust.hashes().to_vec(),
        })
    }
}

/// A TLS session that passed strict verification, and what its handshake showed.
pub(super) struct Secured {
    pub(super) stream: tokio_rustls::client::TlsStream<BoxedStream>,
    pub(super) protocol: Option<&'static str>,
    pub(super) alpn: Option<&'static str>,
    pub(super) handshake: Duration,
}

/// The OS trust store as the run found it (M1-093, for the trust-store report of `net.tls_intercept`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustStore {
    /// Why there is no store to verify against, when there is none: [`NoRoots::Empty`] for "no OS trust
    /// store found", [`NoRoots::Unreadable`] and [`NoRoots::Overridden`].
    pub missing: Option<NoRoots>,
    /// The files, directories or OS store the roots were read from. Raw: redact before showing.
    pub sources: Vec<StoreSource>,
    /// The SHA-256 of the DER of each root the verifier uses, in store order.
    pub roots: Vec<[u8; 32]>,
}

impl TrustStore {
    /// Whether a root with this SHA-256 is in the store.
    #[must_use]
    pub fn contains(&self, sha256: &[u8; 32]) -> bool {
        self.roots.contains(sha256)
    }

    /// The SHA-256 of `der`, the form `roots` holds. A check hashes a certificate of a chain with this
    /// to look it up with [`TrustStore::contains`].
    #[must_use]
    pub fn hash(der: &[u8]) -> [u8; 32] {
        record::sha256(der)
    }

    /// `sha256` as 64 lowercase hex digits, the form a report shows.
    #[must_use]
    pub fn hex(sha256: &[u8; 32]) -> String {
        use std::fmt::Write as _;
        sha256
            .iter()
            .fold(String::with_capacity(64), |mut out, byte| {
                // Writing to a String does not fail.
                let _ = write!(out, "{byte:02x}");
                out
            })
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

/// Types a failure of the strict handshake. A certificate the roots refused is [`NetFailure::TlsUntrusted`],
/// with the class `net.egress` reports; every other failure is typed as for the recording handshake.
fn strict_failure(error: &io::Error, what: &str) -> ProbeError {
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    if let Some(tls @ rustls::Error::InvalidCertificate(_)) = tls {
        return ProbeError::Net(NetFailure::TlsUntrusted {
            target: what.to_owned(),
            failure: record::failure_of(tls),
        });
    }
    handshake_failure(error, what)
}

/// Gives `config` the hub's pinned clock, when a test pinned one. Both the recording and the strict
/// configuration pass through here, so the verdicts of `tls_chain` and the HTTP probe agree on the time.
/// A build without the `testing` feature has no clock to pin and keeps the real one.
#[cfg_attr(not(feature = "testing"), expect(unused_variables))]
fn pin_clock(hub: &ProbeHub, config: &mut rustls::ClientConfig) {
    #[cfg(feature = "testing")]
    if let Some(now) = hub.pinned_clock() {
        config.time_provider = Arc::new(Pinned(now));
    }
}

/// A time provider that always says the same time (feature `testing`).
#[cfg(feature = "testing")]
#[derive(Debug)]
struct Pinned(Duration);

#[cfg(feature = "testing")]
impl rustls::time_provider::TimeProvider for Pinned {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(self.0))
    }
}

#[cfg(feature = "testing")]
impl ProbeHub {
    /// Pins the clock that every TLS verdict of this hub sees, as time since the Unix epoch, for both
    /// `Probe::tls_chain` (the recording handshake) and `Probe::http` (the strict one). Without it
    /// they read the real clock. A test uses it to put "now" before or after a generated leaf's dates
    /// (`clock_or_expiry`), whatever the real date is. Call it before the calls it should affect: a
    /// handshake reads the pin once, when it starts.
    ///
    /// Only the feature `testing` builds it; a release build has no way to move the clock.
    pub fn pin_clock(&self, since_epoch: Duration) {
        *self
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(since_epoch);
    }

    /// Puts the real clock back.
    pub fn unpin_clock(&self) {
        *self
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn pinned_clock(&self) -> Option<Duration> {
        *self
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
