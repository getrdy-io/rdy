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
//! **Lookup.** [`Probe::lookup`] resolves one of the check's spec hosts (any port) and returns its addresses.
//! The check must declare [`PeerClass::SpecHosts`]. If any answer is in a refused range, the whole call is
//! refused and the check gets no address. The log has one `lookup` entry with `host` and an `answers`
//! count, and no address (M1-094).
//!
//! **TLS.** [`Probe::tls_chain`] takes the same policy and the same stream and runs one handshake that
//! sends no application data (the `tls` module, M1-092).
//!
//! **HTTP.** [`Probe::http`] takes the same policy and the same stream, verifies an `https://` target
//! strictly, sends one `HEAD` or `GET`, reads at most 64 KiB of body and discards it, and follows no
//! redirect (the `http` module, M1-093).
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
use super::{
    Backend, EnvConflict, Exemption, NetFailure, NoProxy, Probe, ProbeError, ProbeHub,
    RULE_NO_NETWORK, refuse, settle,
};
use crate::check::PeerClass;

mod http;
mod lookup;
#[cfg(test)]
mod offline_tests;
#[cfg(any(test, feature = "testing"))]
pub(super) mod replay;
#[cfg(test)]
mod tests;
mod tls;

pub use super::AttemptOutcome;
pub use http::{
    BODY_TIMEOUT, HttpMethod, HttpOutcome, HttpProbe, HttpTiming, HttpTls, MAX_BODY,
    REPORTED_HEADERS, RESPONSE_TIMEOUT, RULE_HTTP_NOT_URL,
};
pub use lookup::{MAX_ANSWERS, RULE_LOOKUP_HOST};
pub(super) use tls::TlsState;
pub use tls::{
    ALPN_PROTOCOLS, HANDSHAKE_TIMEOUT, NoRoots, REVOCATION_NOTE, Roots, TlsChain, TrustFailure,
    TrustStore, TrustVerdict,
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

/// How `auto` reaches a host: the route, and why a host goes direct although the run has a proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AutoRoute {
    /// `Route::ViaProxy` when the run has a proxy and nothing exempts the host, else `Route::Direct`.
    pub route: Route,
    /// Why the host goes direct although the run has a proxy: `NO_PROXY`, or the loopback rule.
    pub exempt: Option<Exemption>,
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
    /// Why nothing connected, from the attempts: [`AttemptOutcome::TimedOut`] when every attempt was
    /// silent, else the last attempt's outcome, and [`AttemptOutcome::Failed`] when there was no address
    /// to try.
    fn failure_outcome(&self) -> AttemptOutcome {
        let all_silent = !self.attempts.is_empty()
            && self
                .attempts
                .iter()
                .all(|a| a.outcome == AttemptOutcome::TimedOut);
        if all_silent {
            return AttemptOutcome::TimedOut;
        }
        self.attempts
            .last()
            .map_or(AttemptOutcome::Failed, |a| a.outcome)
    }

    /// The fixed phrase for why nothing connected, from the attempts.
    fn failure(&self) -> &'static str {
        if self.attempts.is_empty() {
            return "no address to try";
        }
        self.failure_outcome().phrase()
    }

    /// The failure of a call that got no connection, typed.
    fn not_connected(&self, target: &str) -> NetFailure {
        NetFailure::NotConnected {
            target: target.to_owned(),
            outcome: self.failure_outcome(),
            reason: self.failure(),
        }
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
            .unless_ended(&what, self.dial(hub, target, proxy, true))
            .await
            .map(|dialed| dialed.report);
        match result {
            Ok(report) if !report.connected => {
                entry.set("error", report.failure());
                let silent = report.failure_outcome() == AttemptOutcome::TimedOut;
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

    /// The run's proxy as `http://host:port`, with no user name or password, or `None` when the run has
    /// none. A check reads this to choose its route (`auto` goes through a proxy when the run has one)
    /// and to name the proxy in a fix. It holds nothing secret and writes no log entry.
    #[must_use]
    pub fn proxy_origin(&self) -> Option<String> {
        self.hub.as_ref()?.proxy.get().map(ProxyUrl::origin)
    }

    /// The environment variable the run's proxy was read from (`HTTPS_PROXY`, `HTTP_PROXY`, either
    /// case), or `None` when the run has no proxy or it was set another way. A check names it in a fix
    /// and a note, because the proxy of one variable serves every endpoint of the run.
    #[must_use]
    pub fn proxy_source(&self) -> Option<&'static str> {
        self.hub.as_ref()?.proxy_source.get().copied()
    }

    /// How `auto` reaches `target`: through the run's proxy when it has one, unless `NO_PROXY` exempts
    /// the host (M1-098). The route a product started from this shell would take, which is what
    /// `net.egress` tests with `via_proxy: auto`. It writes no log entry and reads nothing: the list was
    /// read once by `ProbeHub::set_proxy_from_env`.
    ///
    /// It does not look at which variable the proxy came from or at the scheme of the target: one proxy
    /// serves the whole run. A caller that talks to an `https` server (the Kubernetes client, M1-107) must
    /// not use a proxy that was read from `HTTP_PROXY` for it (05 INV-11, ADR 0037); `Probe::proxy_source`
    /// says where it came from.
    ///
    /// A run with no proxy is [`Route::Direct`] with no exemption. A host that `NO_PROXY` or the
    /// loopback rule exempts is [`Route::Direct`] with the [`Exemption`] that did it.
    #[must_use]
    pub fn route_for(&self, target: &Target) -> AutoRoute {
        let direct = |exempt| AutoRoute {
            route: Route::Direct,
            exempt,
        };
        let Some(hub) = self.hub.as_ref().filter(|hub| hub.proxy.get().is_some()) else {
            return direct(None);
        };
        let exempt = match hub.no_proxy.get() {
            Some((list, _)) => list.exempts(&target.host().to_string(), target.port()),
            // With no list, only the loopback rule applies.
            None => NoProxy::default().exempts(&target.host().to_string(), target.port()),
        };
        match exempt {
            Some(why) => direct(Some(why)),
            None => AutoRoute {
                route: Route::ViaProxy,
                exempt: None,
            },
        }
    }

    /// The `NO_PROXY` list of the run and the variable it came from (`NO_PROXY` or `no_proxy`), or
    /// `None` when neither is set. It is read once, by `ProbeHub::set_proxy_from_env`. The list can name
    /// internal hosts: show an entry only where a customer needs it.
    #[must_use]
    pub fn no_proxy(&self) -> Option<(NoProxy, &'static str)> {
        self.hub.as_ref()?.no_proxy.get().cloned()
    }

    /// The proxy variables that were set in two spellings that differ when the run started, by name.
    /// Empty when `ProbeHub::set_proxy_from_env` did not run. It never holds a value.
    #[must_use]
    pub fn proxy_env_conflicts(&self) -> Vec<EnvConflict> {
        self.hub
            .as_ref()
            .and_then(|hub| hub.env_conflicts.get().cloned())
            .unwrap_or_default()
    }

    /// Opens one TCP connection to the run's proxy itself and closes it, with no `CONNECT` and no byte
    /// written (M1-098). It answers "can this machine reach the proxy", which is what `net.proxy` needs
    /// and no spec host is involved. The check must declare [`PeerClass::Proxy`]. The proxy's name is
    /// resolved here (it is the one name that is not resolved at the proxy) and every answer in a
    /// refused range refuses the call, as for a proxied call. The log has one `connect` entry for the
    /// proxy's host and port, with `via_proxy` null and the connected address.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for an undeclared peer class, `--no-network` and a call after the check
    /// ended; [`ProbeError::Net`] with [`NetFailure::NoProxy`] when the run has no proxy, or a name that
    /// did not resolve. A proxy that refuses, resets or stays silent is `Ok` with the outcome in the
    /// report.
    pub async fn proxy_reach(&self) -> Result<TcpReport, ProbeError> {
        let Some(proxy) = self.hub.as_ref().and_then(|hub| hub.proxy.get()) else {
            // The entry below needs a hub, so a probe without one is refused by `begin`.
            let (_, entry) = self.begin(ActionKind::Connect, Map::new(), "the proxy")?;
            return Err(fail_net(entry, NetFailure::NoProxy));
        };
        let what = format!("{}:{}", proxy.host(), proxy.port());
        let mut fields = Map::new();
        fields.insert("host".to_owned(), proxy.host().to_string().into());
        fields.insert("port".to_owned(), proxy.port().into());
        fields.insert("via_proxy".to_owned(), Value::Null);
        fields.insert("addr".to_owned(), Value::Null);
        let (hub, mut entry) = self.begin(ActionKind::Connect, fields, &what)?;
        if self.offline() {
            return Err(refuse(entry, RULE_NO_NETWORK, &what));
        }
        let declared = self
            .scope
            .info
            .is_some_and(|info| info.peers.contains(&PeerClass::Proxy));
        if !declared {
            return Err(refuse(entry, RULE_PROXY_UNDECLARED, &what));
        }
        // The proxy is dialled as a target of its own: the call has the proxy's address rule and no
        // spec-host rule, and no tunnel is opened.
        let Ok(target) = Target::parse(&what) else {
            return Err(fail_net(
                entry,
                NetFailure::Dns {
                    host: proxy.host().to_string(),
                },
            ));
        };
        let result = self
            .unless_ended(&what, self.dial(hub, &target, Some(proxy), false))
            .await
            .map(|dialed| dialed.report);
        match result {
            Ok(report) => {
                entry.set(
                    "addr",
                    report
                        .addr
                        .map_or(Value::Null, |a| a.ip().to_string().into()),
                );
                if report.connected {
                    entry.finish(ActionOutcome::Ok);
                } else {
                    entry.set("error", report.failure());
                    entry.finish(if report.failure_outcome() == AttemptOutcome::TimedOut {
                        ActionOutcome::Timeout
                    } else {
                        ActionOutcome::Failed
                    });
                }
                Ok(report)
            }
            Err(ProbeError::Net(failure)) => Err(fail_net(entry, failure)),
            Err(error) => settle::<TcpReport>(entry, Err(error), |_, _| {}),
        }
    }

    /// The policy before any lookup or connection.
    fn admit_tcp(&self, target: &Target, route: Route) -> Result<(), &'static str> {
        let declared = |class: PeerClass| {
            self.scope
                .info
                .is_some_and(|info| info.peers.contains(&class))
        };
        if self.offline() {
            return Err(RULE_NO_NETWORK);
        }
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
    ///
    /// With `open_tunnel` false the connection to the proxy is returned as it is, with no `CONNECT`: the
    /// caller writes an absolute-form request on it (a plain `http://` call, M1-097).
    async fn dial(
        &self,
        hub: &ProbeHub,
        target: &Target,
        proxy: Option<&ProxyUrl>,
        open_tunnel: bool,
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
        if let Some(proxy) = proxy.filter(|_| open_tunnel) {
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
            Host::Name(name) => self.answers_of(hub, name, port).await?,
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
