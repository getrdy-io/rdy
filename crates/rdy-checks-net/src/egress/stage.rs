//! One endpoint, stage by stage: lookup, connect (every address), TLS and ALPN.
//!
//! Every stage goes through the probe facade. The check names a spec host and never an address: the
//! facade resolves it, refuses the ranges its address rule forbids, and tries the addresses itself,
//! IPv6 first with a stagger. This module reads what the facade reports and turns it into an
//! [`Endpoint`] with a timing for each stage.
//!
//! **Lookup.** `Probe::lookup` runs first for a name, to time the stage and to count the IPv4 and IPv6
//! answers. A literal address skips it. The connect then resolves again inside the facade, which is the
//! same lookup the product would make, so a split-horizon or flapping answer shows up as two different
//! results and not as a stale one.
//!
//! **Connect and TLS.** For a TLS endpoint `Probe::tls_chain` does the connect and the handshake. When
//! it cannot connect it returns the last outcome and not the attempts, so the failed path then calls
//! `Probe::tcp` once to get the per-address attempts for the report. That second connect only happens
//! when the first one failed, and only when the check has time left.
//!
//! **Time.** The facade's own timeouts bound every stage: 3 s for a lookup, 3 s per address, 5 s for a
//! handshake. The lookup is timed on the check's remaining time, which a test without a scheduler does
//! not have, so it reads 0 ms there.

use std::net::IpAddr;
use std::time::Duration;

use rdy_engine::check::{CheckContext, CheckError};
use rdy_engine::probe::net::{
    Roots, Route, STAGGER, TcpAttempt, TcpReport, TlsChain, TrustVerdict,
};
use rdy_engine::probe::{AttemptOutcome, NetFailure, ProbeError};
use rdy_spec::check::{Endpoint, Trust};
use rdy_spec::scalar::Host;
use serde_json::{Value, json};

use super::class::Class;

/// Below this much time left the second connect that names the attempts is skipped.
const MIN_FOR_ATTEMPTS: Duration = Duration::from_secs(5);

/// Below this much time left an endpoint that has not started is not tried.
pub(super) const MIN_TO_START: Duration = Duration::from_secs(1);

/// The IP family of an address, for the report.
fn family(ip: IpAddr) -> &'static str {
    if ip.is_ipv6() { "ipv6" } else { "ipv4" }
}

/// Whole milliseconds, held to `u64`.
pub(super) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// How an attempt ended, as a report word.
fn outcome_word(outcome: AttemptOutcome) -> &'static str {
    match outcome {
        AttemptOutcome::Connected => "connected",
        AttemptOutcome::Refused => "refused",
        AttemptOutcome::Reset => "reset",
        AttemptOutcome::TimedOut => "timed_out",
        AttemptOutcome::Unreachable => "unreachable",
        AttemptOutcome::Abandoned => "abandoned",
        _ => "failed",
    }
}

/// How an endpoint ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Ending {
    /// Connected, and handshook when the endpoint is a TLS one.
    Reached,
    /// Failed in a stage, with the class. `ip` is the address that did not answer, when one is known.
    Failed(Class, Option<String>),
    /// Not tried. The text says why.
    NotTried(&'static str),
}

/// One attempt, as the report shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AttemptView {
    pub(super) addr: String,
    pub(super) family: &'static str,
    pub(super) outcome: &'static str,
    pub(super) started: Duration,
    pub(super) elapsed: Duration,
}

impl AttemptView {
    fn of(attempt: &TcpAttempt) -> Self {
        Self {
            addr: attempt.addr.ip().to_string(),
            family: family(attempt.addr.ip()),
            outcome: outcome_word(attempt.outcome),
            started: attempt.started,
            elapsed: attempt.elapsed,
        }
    }
}

/// What the TLS stage found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TlsView {
    pub(super) protocol: Option<&'static str>,
    pub(super) alpn: Option<&'static str>,
    pub(super) handshake: Duration,
    /// The certificates the server sent.
    pub(super) chain_len: usize,
    /// Which roots judged the chain: `system`, or `bundled` (by the spec or as the fallback).
    pub(super) roots: &'static str,
    /// Set when the bundled roots stood in for an OS store that was missing.
    pub(super) fallback: Option<&'static str>,
}

/// Everything one endpoint showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Probed {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) optional: bool,
    pub(super) tls_wanted: bool,
    /// The lookup stage: time, IPv4 answers, IPv6 answers.
    pub(super) lookup: Option<(Duration, usize, usize)>,
    pub(super) attempts: Vec<AttemptView>,
    /// From the start of the connect stage to the moment the winning address connected.
    pub(super) connect: Option<Duration>,
    pub(super) tls: Option<TlsView>,
    pub(super) ending: Ending,
}

impl Probed {
    fn new(spec: &Endpoint, tls_wanted: bool) -> Self {
        Self {
            host: spec.target.host().to_string(),
            port: spec.target.port(),
            optional: spec.optional,
            tls_wanted,
            lookup: None,
            attempts: Vec::new(),
            connect: None,
            tls: None,
            ending: Ending::NotTried("not started"),
        }
    }

    /// An endpoint that was not tried, for `why`.
    pub(super) fn not_tried(spec: &Endpoint, why: &'static str) -> Self {
        let mut out = Self::new(spec, wants_tls(spec));
        out.ending = Ending::NotTried(why);
        out
    }

    /// `host:port`, as the report names the endpoint.
    pub(super) fn label(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The addresses that did not carry the connection although a later one did, as `(family, why)`.
    /// A dead IPv6 address in front of a working IPv4 one is the case this names. An attempt the race
    /// cut counts only when it had been silent for the stagger or longer: a shorter one was cut
    /// because the other family was quicker, which says nothing about its address.
    pub(super) fn fell_through(&self) -> Vec<(&'static str, String)> {
        if self.ending != Ending::Reached {
            return Vec::new();
        }
        self.attempts
            .iter()
            .filter_map(|a| match a.outcome {
                "connected" => None,
                "abandoned" if a.elapsed >= STAGGER => {
                    Some((a.family, format!("no answer after {} ms", ms(a.elapsed))))
                }
                "abandoned" => None,
                other => Some((a.family, other.replace('_', " "))),
            })
            .collect()
    }

    /// The report entry. It holds the host and port and never the path or query of a URL.
    pub(super) fn json(&self) -> Value {
        let attempts: Vec<Value> = self
            .attempts
            .iter()
            .map(|a| {
                json!({
                    "addr": a.addr,
                    "family": a.family,
                    "outcome": a.outcome,
                    "started_ms": ms(a.started),
                    "elapsed_ms": ms(a.elapsed),
                })
            })
            .collect();
        let mut out = json!({
            "endpoint": self.label(),
            "optional": self.optional,
            "tls": self.tls_wanted,
            "attempts": attempts,
        });
        if let Some((took, v4, v6)) = self.lookup {
            out["lookup"] = json!({ "ms": ms(took), "ipv4": v4, "ipv6": v6 });
        }
        if let Some(connect) = self.connect {
            out["connect_ms"] = json!(ms(connect));
        }
        if let Some(tls) = &self.tls {
            out["tls_stage"] = json!({
                "protocol": tls.protocol,
                "alpn": tls.alpn,
                "handshake_ms": ms(tls.handshake),
                "chain_depth": tls.chain_len,
                "roots": tls.roots,
                "fallback": tls.fallback,
            });
        }
        match &self.ending {
            Ending::Reached => out["result"] = json!("reached"),
            Ending::Failed(class, _) => {
                out["result"] = json!("failed");
                out["class"] = json!(class.id());
            }
            Ending::NotTried(why) => {
                out["result"] = json!("not_tried");
                out["why"] = json!(why);
            }
        }
        out
    }
}

/// Whether the endpoint gets a TLS handshake: port 443, an `https` URL or `tls: true`, unless the spec
/// says `tls: false`.
pub(super) fn wants_tls(spec: &Endpoint) -> bool {
    match spec.tls {
        Some(choice) => choice,
        None => spec.target.port() == 443 || spec.target.scheme() == Some("https"),
    }
}

/// Probes one endpoint directly and returns what each stage showed.
///
/// # Errors
///
/// A [`CheckError`] only when a probe error says the test or the build is wrong and not the network,
/// such as a fixture with no recorded answer. Every network failure is data in the [`Probed`].
pub(super) async fn probe(
    ctx: &CheckContext,
    spec: &Endpoint,
    trust: Trust,
) -> Result<Probed, CheckError> {
    let tls_wanted = wants_tls(spec);
    let mut out = Probed::new(spec, tls_wanted);
    if ctx.remaining() < MIN_TO_START {
        out.ending = Ending::NotTried("the check ran out of time");
        return Ok(out);
    }
    let target = &spec.target;

    // Stage 1: lookup.
    if let Host::Name(name) = target.host() {
        let before = ctx.remaining();
        let answers = ctx.probe().lookup(name).await;
        let took = before.saturating_sub(ctx.remaining());
        match answers {
            Ok(ips) => {
                let v6 = ips.iter().filter(|ip| ip.is_ipv6()).count();
                out.lookup = Some((took, ips.len() - v6, v6));
            }
            Err(error) => {
                out.ending = Ending::Failed(Class::of_error(error)?, None);
                return Ok(out);
            }
        }
    }

    // Stages 2 and 3: connect, then TLS.
    if tls_wanted {
        match ctx.probe().tls_chain(target, Route::Direct).await {
            Ok(chain) => {
                finish_tls(&mut out, &chain, trust);
                return Ok(out);
            }
            Err(ProbeError::Net(NetFailure::NotConnected { outcome, .. })) => {
                out.ending = Ending::Failed(Class::of_connect(outcome), None);
                if ctx.remaining() >= MIN_FOR_ATTEMPTS {
                    // The attempts are what name the dead family. A connect that now works is a
                    // flapping path, and the first failure stands.
                    if let Ok(report) = ctx.probe().tcp(target, Route::Direct).await {
                        out.attempts = report.attempts.iter().map(AttemptView::of).collect();
                    }
                }
                out.ending = Ending::Failed(Class::of_connect(outcome), first_silent(&out));
                return Ok(out);
            }
            Err(error) => {
                out.ending = Ending::Failed(Class::of_error(error)?, None);
                return Ok(out);
            }
        }
    }

    match ctx.probe().tcp(target, Route::Direct).await {
        Ok(report) => finish_tcp(&mut out, &report),
        Err(error) => out.ending = Ending::Failed(Class::of_error(error)?, None),
    }
    Ok(out)
}

/// The address of the first attempt that got no answer, for the blackhole text.
fn first_silent(out: &Probed) -> Option<String> {
    let silent = out.attempts.iter().find(|a| a.outcome == "timed_out");
    silent.map(|a| match a.family {
        "ipv6" => format!("[{}]:{}", a.addr, out.port),
        _ => format!("{}:{}", a.addr, out.port),
    })
}

/// Records a plain TCP result.
fn finish_tcp(out: &mut Probed, report: &TcpReport) {
    out.attempts = report.attempts.iter().map(AttemptView::of).collect();
    out.connect = connect_time(report);
    if report.connected {
        out.ending = Ending::Reached;
        return;
    }
    let all_silent = !report.attempts.is_empty()
        && report
            .attempts
            .iter()
            .all(|a| a.outcome == AttemptOutcome::TimedOut);
    let outcome = if all_silent {
        AttemptOutcome::TimedOut
    } else {
        report
            .attempts
            .last()
            .map_or(AttemptOutcome::Failed, |a| a.outcome)
    };
    out.ending = Ending::Failed(Class::of_connect(outcome), first_silent(out));
}

/// When the winning address had connected, from the start of the connect stage.
fn connect_time(report: &TcpReport) -> Option<Duration> {
    report
        .attempts
        .iter()
        .find(|a| a.outcome == AttemptOutcome::Connected)
        .map(|a| a.started + a.elapsed)
}

/// Records a handshake that completed, and judges the chain against the roots the spec chose.
fn finish_tls(out: &mut Probed, chain: &TlsChain, trust: Trust) {
    out.attempts = chain.connect.attempts.iter().map(AttemptView::of).collect();
    out.connect = connect_time(&chain.connect);
    let (roots, verdict, fallback) = match trust {
        Trust::Bundled => ("bundled", chain.verdict(Roots::Bundled), None),
        // `system` is the default. When this machine has no store to judge against, the bundled public
        // roots stand in and the evidence says so.
        _ => match chain.verdict(Roots::System) {
            TrustVerdict::Unavailable(_) => (
                "bundled",
                chain.verdict(Roots::Bundled),
                Some("no usable OS trust store, so the bundled public roots judged the chain"),
            ),
            verdict => ("system", verdict, None),
        },
    };
    out.tls = Some(TlsView {
        protocol: chain.protocol,
        alpn: chain.alpn,
        handshake: chain.handshake,
        chain_len: chain.certs.len(),
        roots,
        fallback,
    });
    out.ending = match verdict {
        TrustVerdict::Valid => Ending::Reached,
        TrustVerdict::Rejected(failure) => Ending::Failed(Class::of_trust(failure), None),
        _ => Ending::Failed(Class::NoTrustStore, None),
    };
}
