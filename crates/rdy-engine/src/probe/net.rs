//! TCP attempts and the proxy `CONNECT` (M1-091, ADR 0014 decision 2, 02 "Network").
//!
//! [`Probe::tcp`] connects to one of the check's own spec hosts and reports every attempt. A check never
//! names an address: the facade resolves the host, vets the answers, and tries them itself.
//!
//! **Policy, in order.** Every refusal is logged as `denied` and never reaches the backend.
//! - The check must declare [`PeerClass::SpecHosts`], and [`PeerClass::Proxy`] for a proxied call.
//! - The host and port must be one of the check's own spec hosts, set by `Probe::permit_hosts` from
//!   `Built::hosts`. A host that only another check lists is refused (INV-11).
//! - A literal address that the facade's address rule refuses (link-local, the
//!   metadata addresses, unspecified, multicast, broadcast, and their IPv4-mapped, IPv4-compatible and
//!   `64:ff9b::/96` forms) is refused before any connection, including a `CONNECT` target: no byte is
//!   sent to the proxy (INV-12).
//! - A name is resolved by the backend, and if any answer is refused by that rule the whole call is
//!   refused. Through a proxy only the proxy's own name is resolved here; the target name resolves at
//!   the proxy (05 residual).
//!
//! **Attempts.** The addresses are ordered with the two families interleaved, IPv6 first, and capped at
//! [`MAX_ADDRS`]. The first attempt starts at once. The next starts [`STAGGER`] later, or when the one
//! before it fails, and an attempt waits at most [`ATTEMPT_TIMEOUT`]. The first stream to connect wins
//! and the attempts still running are cut. The report lists every attempt in start order: its address,
//! when it started, how long it took and what happened, so a dead IPv6 address can be named.
//!
//! **Errors and reports.** A refused, reset, unreachable or silent address is data in the
//! [`TcpReport`], not an error: a check classifies it. An error means the call itself failed: the
//! policy refused it, the name did not resolve, the proxy said no, or a fixture was missing.
//!
//! **Proxy.** With [`Route::ViaProxy`] the facade connects to the proxy set with
//! [`ProbeHub::set_proxy`](super::ProbeHub::set_proxy) and writes the `CONNECT` itself: Basic
//! authentication from the [`ProxyUrl`], a reply head of at most [`MAX_CONNECT_HEAD`](super::MAX_CONNECT_HEAD) bytes, and
//! [`CONNECT_TIMEOUT`] for the exchange. A 2xx answer opens the tunnel; 403, 407 and every other
//! answer are typed [`NetFailure`]s. A 407 that asks for Negotiate or NTLM is named and never
//! attempted. `Proxy-Authorization` is never logged, and the password is in the known-secret set
//! before the proxy can be used.
//!
//! **TLS.** [`Probe::tls_chain`] takes the same policy and the same stream and runs one handshake that
//! sends no application data (the `tls` module, M1-092).
//!
//! **The log.** One `connect` entry per call, proxy `CONNECT` included: `host`, `port`, `via_proxy` (the
//! proxy without its userinfo, or `null`) and `addr` (the connected address, `null` through a proxy or
//! when nothing connected). There is no `proto`, which marks a datagram. A failure has a fixed `error`
//! phrase, and a refused `CONNECT` names its status in it. The entry never holds a header. `addr` is
//! `null` on every path that did not connect, a refusal included.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rdy_spec::Target;
use rdy_spec::result::{ActionKind, ActionOutcome};
use rdy_spec::scalar::Host;
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::{self, JoinSet};
use tokio::time::{Instant, sleep_until, timeout};

use super::addr::is_unusable_peer;
use super::log::Pending;
use super::proxy::{ProxyUrl, parse_connect_head};
use super::sock::host_port;
use super::{Backend, NetFailure, Probe, ProbeError, ProbeHub, refuse, settle};
use crate::check::PeerClass;

#[cfg(any(test, feature = "testing"))]
pub(super) mod replay;
#[cfg(test)]
mod tests;
mod tls;

pub(super) use tls::TlsState;
pub use tls::{
    ALPN_PROTOCOLS, HANDSHAKE_TIMEOUT, NoRoots, REVOCATION_NOTE, Roots, TlsChain, TrustFailure,
    TrustVerdict,
};

/// The longest one connection attempt waits.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long an attempt runs alone before the next address is tried.
pub const STAGGER: Duration = Duration::from_millis(250);

/// The most addresses of one host that are tried.
pub const MAX_ADDRS: usize = 4;

/// The longest a name lookup waits.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// The longest the `CONNECT` exchange waits, from the first byte sent to the end of the reply head.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The rule of a call from a check that did not declare `PeerClass::SpecHosts`.
pub const RULE_TCP_UNDECLARED: &str = "spec host peer class not declared by the check";

/// The rule of a proxied call from a check that did not declare `PeerClass::Proxy`.
pub const RULE_PROXY_UNDECLARED: &str = "proxy peer class not declared by the check";

/// The rule of a connection to a host that is not one of the check's spec hosts.
pub const RULE_TCP_HOST: &str = "host is not one of the check's spec hosts";

/// The rule of a connection to a link-local, metadata, unspecified, multicast or broadcast address,
/// whether the spec wrote it or a lookup returned it.
pub const RULE_TCP_ADDRESS: &str =
    "address is link-local, metadata, unspecified, multicast or broadcast";

/// The rule of a call whose proxy resolves to a link-local, metadata, unspecified, multicast or
/// broadcast address. The proxy is the problem here, not the target the check named.
pub const RULE_PROXY_ADDRESS: &str =
    "the proxy's address is link-local, metadata, unspecified, multicast or broadcast";

/// A byte stream the backend opened. `tokio-rustls` and `hyper` sit on it in the TLS and HTTP tickets.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// A stream behind a pointer, so the live backend and the replay backend return one type.
pub type BoxedStream = Box<dyn AsyncStream>;

/// How a call reaches its host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Route {
    /// Straight to the host's addresses.
    Direct,
    /// Through the run's proxy, with a `CONNECT` written by the facade.
    ViaProxy,
}

/// What one connection attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttemptOutcome {
    /// The connection opened.
    Connected,
    /// The host answered with a refusal (a closed port, or a firewall that rejects).
    Refused,
    /// The connection was reset.
    Reset,
    /// No answer within [`ATTEMPT_TIMEOUT`]: a firewall that drops packets looks like this.
    TimedOut,
    /// No route to the network or the host.
    Unreachable,
    /// Another failure.
    Failed,
    /// Another address connected first, so this attempt was cut while it was still running.
    Abandoned,
}

impl AttemptOutcome {
    fn of(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Self::Refused,
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe => Self::Reset,
            io::ErrorKind::TimedOut => Self::TimedOut,
            io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown => Self::Unreachable,
            _ => Self::Failed,
        }
    }

    /// A fixed phrase for the log.
    fn phrase(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Refused => "connection refused",
            Self::Reset => "connection reset",
            Self::TimedOut => "no answer in time",
            Self::Unreachable => "network or host unreachable",
            Self::Failed => "connection failed",
            Self::Abandoned => "cut because another address connected",
        }
    }
}

/// One connection attempt to one address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpAttempt {
    /// The address tried. Through a proxy it is the proxy's.
    pub addr: SocketAddr,
    /// When the attempt started, from the start of the call.
    pub started: Duration,
    /// How long it ran.
    pub elapsed: Duration,
    /// What happened.
    pub outcome: AttemptOutcome,
}

/// Every attempt of one [`Probe::tcp`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpReport {
    /// The attempts, in the order they started.
    pub attempts: Vec<TcpAttempt>,
    /// `true` when a connection opened, and through a proxy, when the tunnel opened too.
    pub connected: bool,
    /// The address that connected. Through a proxy it is the proxy's, and the target's address is
    /// not known.
    pub addr: Option<SocketAddr>,
    /// `true` when the call went through the proxy.
    pub via_proxy: bool,
    /// The proxy's answer to `CONNECT`, when it gave one.
    pub proxy_status: Option<u16>,
}

impl TcpReport {
    /// The fixed phrase for why nothing connected, from the attempts.
    fn failure(&self) -> &'static str {
        let all_silent = !self.attempts.is_empty()
            && self
                .attempts
                .iter()
                .all(|a| a.outcome == AttemptOutcome::TimedOut);
        if all_silent {
            return AttemptOutcome::TimedOut.phrase();
        }
        self.attempts
            .last()
            .map_or("no address to try", |a| a.outcome.phrase())
    }
}

/// A report and the stream behind it. The TLS and HTTP calls take the stream; `tcp` drops it.
struct Dialed {
    report: TcpReport,
    stream: Option<BoxedStream>,
}

impl Probe {
    /// Connects to `target`, one of the check's own spec hosts, and reports every attempt. The
    /// connection is closed when the call returns. See the [module docs](crate::probe::net).
    ///
    /// # Errors
    ///
    /// - [`ProbeError::Denied`] for an undeclared peer class, a host that is not one of the check's
    ///   spec hosts, a forbidden address (literal or from a lookup), or a call after the check ended.
    /// - [`ProbeError::Net`] for a name that did not resolve, a call through a proxy when the run has
    ///   none, and a proxy that answered 403, 407 or anything but 2xx to `CONNECT` or sent no HTTP.
    /// - [`ProbeError::Timeout`] when the lookup or the `CONNECT` ran out of time.
    ///
    /// A host that refuses, resets or stays silent is `Ok` with the outcome in the report.
    pub async fn tcp(&self, target: &Target, route: Route) -> Result<TcpReport, ProbeError> {
        let what = host_port(target);
        let mut fields = Map::new();
        fields.insert("host".to_owned(), target.host().to_string().into());
        fields.insert("port".to_owned(), target.port().into());
        fields.insert("via_proxy".to_owned(), Value::Null);
        // `null` on every path that does not connect; a connection replaces it.
        fields.insert("addr".to_owned(), Value::Null);
        let (hub, mut entry) = self.begin(ActionKind::Connect, fields, &what)?;

        if let Err(rule) = self.admit_tcp(target, route) {
            return Err(refuse(entry, rule, &what));
        }
        let proxy = match proxy_for(hub, route, &mut entry) {
            Ok(proxy) => proxy,
            Err(failure) => return Err(fail_net(entry, failure)),
        };

        let result = self
            .unless_ended(&what, self.dial(hub, target, proxy))
            .await
            .map(|dialed| dialed.report);
        match result {
            Ok(report) if !report.connected => {
                entry.set("error", report.failure());
                let silent = report.failure() == AttemptOutcome::TimedOut.phrase();
                entry.finish(if silent {
                    ActionOutcome::Timeout
                } else {
                    ActionOutcome::Failed
                });
                Ok(report)
            }
            Err(ProbeError::Net(failure)) => Err(fail_net(entry, failure)),
            other => settle(entry, other, |report, entry| {
                // Through a proxy the connected address is the proxy's, and the log shows the target.
                entry.set(
                    "addr",
                    report
                        .addr
                        .filter(|_| !report.via_proxy)
                        .map_or(Value::Null, |a| a.ip().to_string().into()),
                );
            }),
        }
    }

    /// The policy before any lookup or connection.
    fn admit_tcp(&self, target: &Target, route: Route) -> Result<(), &'static str> {
        let declared = |class: PeerClass| {
            self.scope
                .info
                .is_some_and(|info| info.peers.contains(&class))
        };
        if !declared(PeerClass::SpecHosts) {
            return Err(RULE_TCP_UNDECLARED);
        }
        if route == Route::ViaProxy && !declared(PeerClass::Proxy) {
            return Err(RULE_PROXY_UNDECLARED);
        }
        let listed = self.scope.peers.is_spec_host(target);
        if !listed {
            return Err(RULE_TCP_HOST);
        }
        // A literal is judged before anything is opened, whichever route it takes: a `CONNECT` to
        // 169.254.169.254 never sends a byte, and the proxy is not even called.
        if literal(target.host()).is_some_and(is_unusable_peer) {
            return Err(RULE_TCP_ADDRESS);
        }
        Ok(())
    }

    /// Resolves, vets and connects. Through a proxy the connection is to the proxy, and the `CONNECT`
    /// follows. The stream comes back open on success, for the TLS and HTTP calls.
    async fn dial(
        &self,
        hub: &ProbeHub,
        target: &Target,
        proxy: Option<&ProxyUrl>,
    ) -> Result<Dialed, ProbeError> {
        let what = host_port(target);
        let (host, port) = match proxy {
            Some(proxy) => (proxy.host().clone(), proxy.port()),
            None => (target.host().clone(), target.port()),
        };
        let rule = if proxy.is_some() {
            RULE_PROXY_ADDRESS
        } else {
            RULE_TCP_ADDRESS
        };
        let addrs = self.addresses(hub, &host, port, &what, rule).await?;
        let raced = race(
            &hub.backend,
            addrs
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
            self.scope.peers.timeout(ATTEMPT_TIMEOUT),
            STAGGER,
        )
        .await;
        let Raced {
            attempts,
            stream,
            unrecorded,
        } = raced;
        let addr = stream.as_ref().map(|(index, _)| attempts[*index].addr);
        let mut report = TcpReport {
            attempts,
            connected: stream.is_some(),
            addr,
            via_proxy: proxy.is_some(),
            proxy_status: None,
        };
        let Some((_, mut stream)) = stream else {
            return match unrecorded {
                Some(error) => Err(error),
                None => Ok(Dialed {
                    report,
                    stream: None,
                }),
            };
        };
        if let Some(proxy) = proxy {
            let status = tunnel(
                &mut stream,
                proxy,
                &what,
                self.scope.peers.timeout(CONNECT_TIMEOUT),
            )
            .await?;
            report.proxy_status = Some(status);
        }
        Ok(Dialed {
            report,
            stream: Some(stream),
        })
    }

    /// The addresses to try for `host`: a literal as it is, or the vetted answers of a lookup, ordered
    /// and capped. A refused address among the answers refuses the whole call with `rule`.
    async fn addresses(
        &self,
        hub: &ProbeHub,
        host: &Host,
        port: u16,
        what: &str,
        rule: &'static str,
    ) -> Result<Vec<IpAddr>, ProbeError> {
        let answers = match host {
            Host::Name(name) => {
                let timeout = self.scope.peers.timeout(RESOLVE_TIMEOUT);
                let found = hub
                    .backend
                    .resolve(name, port, timeout)
                    .await
                    .map_err(|error| match ProbeError::from_io(&error) {
                        failure @ (ProbeError::NotRecorded(_) | ProbeError::Timeout) => failure,
                        _ => ProbeError::Net(NetFailure::Dns { host: name.clone() }),
                    })?;
                if found.is_empty() {
                    return Err(ProbeError::Net(NetFailure::Dns { host: name.clone() }));
                }
                found
            }
            literal_host => literal(literal_host)
                .map(|ip| vec![ip])
                .ok_or_else(|| ProbeError::denied(RULE_TCP_HOST, what))?,
        };
        // Any answer in a refused range refuses the call: a name that also points at a metadata
        // address is not one to connect to.
        if answers.iter().any(|ip| is_unusable_peer(*ip)) {
            return Err(ProbeError::denied(rule, what));
        }
        Ok(order(&answers))
    }
}

/// The proxy a call takes, for `route`, and the `via_proxy` field of its entry. A call that wants the
/// proxy when the run has none is [`NetFailure::NoProxy`].
fn proxy_for<'h>(
    hub: &'h ProbeHub,
    route: Route,
    entry: &mut Pending,
) -> Result<Option<&'h ProxyUrl>, NetFailure> {
    match route {
        Route::Direct => Ok(None),
        Route::ViaProxy => {
            let proxy = hub.proxy.get().ok_or(NetFailure::NoProxy)?;
            entry.set("via_proxy", proxy.origin());
            Ok(Some(proxy))
        }
    }
}

/// Closes `entry` as `failed` with the fixed phrase of `failure` and returns the error for the check.
/// The log holds the phrase, not the user message, which names the spec host and a fix.
fn fail_net(mut entry: Pending, failure: NetFailure) -> ProbeError {
    entry.set("error", failure.log_phrase());
    entry.finish(ActionOutcome::Failed);
    ProbeError::Net(failure)
}

/// The address a literal host stands for, or `None` for a name.
fn literal(host: &Host) -> Option<IpAddr> {
    match host {
        Host::Ipv4(addr) => Some(IpAddr::V4(*addr)),
        Host::Ipv6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

/// Removes repeats, alternates the two families starting with IPv6, and keeps [`MAX_ADDRS`].
fn order(answers: &[IpAddr]) -> Vec<IpAddr> {
    let mut v6: Vec<IpAddr> = Vec::new();
    let mut v4: Vec<IpAddr> = Vec::new();
    for ip in answers {
        let family = if ip.is_ipv6() { &mut v6 } else { &mut v4 };
        if !family.contains(ip) {
            family.push(*ip);
        }
    }
    let mut v6 = v6.into_iter();
    let mut v4 = v4.into_iter();
    let mut out = Vec::new();
    while out.len() < MAX_ADDRS {
        let (six, four) = (v6.next(), v4.next());
        if six.is_none() && four.is_none() {
            break;
        }
        for ip in [six, four].into_iter().flatten() {
            if out.len() < MAX_ADDRS {
                out.push(ip);
            }
        }
    }
    out
}

/// What a race left: the attempts, the winning stream with its index, and a missing fixture, if one
/// ended an attempt.
struct Raced {
    attempts: Vec<TcpAttempt>,
    stream: Option<(usize, BoxedStream)>,
    unrecorded: Option<ProbeError>,
}

/// Tries `addrs` with a stagger and returns the first stream to connect. The attempts that are still
/// running are cut when it returns, because the join set aborts them as it drops.
async fn race(
    backend: &Arc<dyn Backend>,
    addrs: Vec<SocketAddr>,
    per_attempt: Duration,
    stagger: Duration,
) -> Raced {
    let origin = Instant::now();
    let mut attempts: Vec<TcpAttempt> = Vec::with_capacity(addrs.len());
    let mut done = Vec::with_capacity(addrs.len());
    let mut running: JoinSet<(usize, io::Result<BoxedStream>)> = JoinSet::new();
    let mut indexes: HashMap<task::Id, usize> = HashMap::new();
    let mut next_due = origin;
    let mut start_now = true;
    let mut stream = None;
    let mut unrecorded = None;

    loop {
        if attempts.len() < addrs.len()
            && (running.is_empty() || start_now || Instant::now() >= next_due)
        {
            start_now = false;
            let index = attempts.len();
            let addr = addrs[index];
            attempts.push(TcpAttempt {
                addr,
                started: origin.elapsed(),
                elapsed: Duration::ZERO,
                outcome: AttemptOutcome::Abandoned,
            });
            done.push(false);
            let backend = Arc::clone(backend);
            let handle = running.spawn(async move {
                let result = match timeout(per_attempt, backend.connect(addr)).await {
                    Ok(result) => result,
                    Err(_elapsed) => Err(io::ErrorKind::TimedOut.into()),
                };
                (index, result)
            });
            indexes.insert(handle.id(), index);
            next_due = Instant::now() + stagger;
            continue;
        }
        if running.is_empty() {
            break;
        }
        let more = attempts.len() < addrs.len();
        let wake = async {
            if more {
                sleep_until(next_due).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            joined = running.join_next_with_id() => {
                let (index, result) = match joined {
                    Some(Ok((_id, (index, result)))) => (index, result),
                    Some(Err(error)) => {
                        // A panic in the backend. The attempt failed; the facade goes on.
                        let Some(index) = indexes.get(&error.id()).copied() else { continue };
                        (index, Err(io::Error::other("the connection task failed")))
                    }
                    None => continue,
                };
                let ended = origin.elapsed();
                let slot = &mut attempts[index];
                slot.elapsed = ended.saturating_sub(slot.started);
                done[index] = true;
                match result {
                    Ok(opened) => {
                        slot.outcome = AttemptOutcome::Connected;
                        stream = Some((index, opened));
                        break;
                    }
                    Err(error) => {
                        slot.outcome = AttemptOutcome::of(&error);
                        if let ProbeError::NotRecorded(what) = ProbeError::from_io(&error) {
                            unrecorded.get_or_insert(ProbeError::NotRecorded(what));
                        }
                        start_now = true;
                    }
                }
            }
            () = wake => {}
        }
    }
    // Attempts still running are cut as `running` drops. They keep the time they had.
    let now = origin.elapsed();
    for (slot, finished) in attempts.iter_mut().zip(done) {
        if !finished {
            slot.elapsed = now.saturating_sub(slot.started);
        }
    }
    Raced {
        attempts,
        stream,
        unrecorded,
    }
}

/// Sends the `CONNECT` for `target` on `stream` and reads the reply head. Returns the status of a 2xx
/// answer. Nothing but the status line and `Proxy-Authenticate` is read out of the reply.
async fn tunnel(
    stream: &mut BoxedStream,
    proxy: &ProxyUrl,
    target: &str,
    limit: Duration,
) -> Result<u16, ProbeError> {
    let exchange = async {
        stream
            .write_all(&proxy.connect_request(target))
            .await
            .map_err(|e| ProbeError::from_io(&e))?;
        let head = read_head(stream).await?;
        let reply = parse_connect_head(&head)
            .map_err(|reason| ProbeError::Net(NetFailure::ProxyBadReply { reason }))?;
        reply.into_result(target, proxy.has_credentials())?;
        Ok(reply.status)
    };
    match timeout(limit, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProbeError::Timeout),
    }
}

/// Reads up to the blank line that ends a reply head, one byte at a time, so no byte of the tunnel
/// behind it is taken. The head is at most [`MAX_CONNECT_HEAD`](super::MAX_CONNECT_HEAD) bytes.
async fn read_head(stream: &mut BoxedStream) -> Result<Vec<u8>, ProbeError> {
    let bad = |reason| ProbeError::Net(NetFailure::ProxyBadReply { reason });
    let mut head = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| ProbeError::from_io(&e))?;
        if n == 0 {
            return Err(bad("the connection closed before the reply ended"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() >= super::MAX_CONNECT_HEAD {
            return Err(bad("the reply head is longer than 8 KiB"));
        }
    }
}
