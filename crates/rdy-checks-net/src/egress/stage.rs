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
//! `Probe::tcp` once to get the per-address attempts for the report. That second connect happens only
//! when the first one failed and the time left covers its worst case and the endpoints still queued
//! (a follow-up should carry the attempts in `NetFailure::NotConnected` and drop the second call).
//!
//! **Through the proxy (M1-097).** When the run has a proxy and the endpoint's route says so, the name is
//! not looked up here (names resolve at the proxy) and every connection goes through the facade's own
//! `CONNECT`. An `http://` URL is the exception: it is not tunnelled, because a proxy that allows
//! `CONNECT` only to port 443 would answer a tunnel to port 80 or 8080 with a false 403. Its HTTP stage
//! sends the absolute-form request to the proxy and is the whole test. The attempts of a proxied
//! endpoint are the proxy's own addresses, so the report names them `proxy_attempts`, and a failure to
//! connect is `proxy_unreachable`, never `refused` or `blackhole` for the endpoint.
//!
//! **Time.** Each endpoint has a budget of [`ENDPOINT_BUDGET`] (10 s, 03 "Needs"), cut short so that
//! [`RESERVE`] of the check's time is always left to write the result. The budget is enforced with
//! `CheckContext::within`: when it runs out, the endpoint is a `timeout` failure that keeps the stages it
//! had finished. The facade's own timeouts still bound each stage. The lookup is timed on the check's
//! remaining time, which a test without a scheduler does not have, so it reads 0 ms there.

use std::net::IpAddr;
use std::time::Duration;

use rdy_engine::check::{CheckContext, CheckError};
use rdy_engine::probe::net::{
    HttpMethod, HttpOutcome, HttpProbe, Roots, Route, STAGGER, TcpAttempt, TcpReport, TlsChain,
    TrustVerdict,
};
use rdy_engine::probe::{AttemptOutcome, NetFailure, NoRoots, ProbeError};
use rdy_spec::check::{Endpoint, HttpMethod as SpecMethod, Trust};
use rdy_spec::scalar::Host;
use serde_json::{Value, json};

use super::class::Class;

/// The most time one endpoint takes, from its lookup to the end of its handshake (03 "Needs").
pub(super) const ENDPOINT_BUDGET: Duration = Duration::from_secs(10);

/// Time of the check that is never spent on endpoints, so the result can be written.
pub(super) const RESERVE: Duration = Duration::from_secs(2);

/// The worst case of the second `tcp` call that names the attempts: four addresses, a stagger each and
/// the attempt limit of the last (3 s + 3 x 250 ms, rounded up).
const SECOND_CONNECT: Duration = Duration::from_secs(4);

/// The most time the HTTP request of one endpoint takes (03 "Needs": 15 s for HTTP). The facade's own
/// limits (10 s for the head, 5 s for the body) sit inside it.
pub(super) const HTTP_BUDGET: Duration = Duration::from_secs(15);

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
    /// Set when the bundled roots stood in for an OS store that was not usable: why.
    pub(super) fallback: Option<String>,
    /// `true` when the OS store was replaced by `SSL_CERT_FILE` or `SSL_CERT_DIR`, which rdy did not read.
    pub(super) overridden: bool,
}

/// What the HTTP stage found. It holds no URL, no header and no body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HttpView {
    pub(super) method: &'static str,
    pub(super) status: u16,
    /// From the request written to the end of the reply head.
    pub(super) first_byte: Duration,
    /// The whole call, to the end of the discard.
    pub(super) total: Duration,
    /// The statuses the spec accepts, or empty for the default (see [`HttpView::accepted`]).
    pub(super) expected: Vec<u16>,
    /// `true` when an `http://` request went to the proxy in the absolute form. A 403 to that request is
    /// the proxy's own answer (no tunnel exists to say otherwise). A 403 inside a `CONNECT` tunnel is the
    /// server's, and the direct rule applies.
    pub(super) absolute_form: bool,
    /// The host a redirect points at, from its `Location`: host only, never followed.
    pub(super) location_host: Option<String>,
    /// The default port of the redirect's scheme.
    pub(super) location_port: Option<u16>,
}

impl HttpView {
    /// Whether `status` counts as reachable: one of the listed statuses, or with none listed, 2xx, 3xx
    /// and 4xx except 407, and except 403 through the proxy. A 4xx proves the path works. A 407 is an intercepting proxy that answered on
    /// the direct route, and a 5xx says the server or a proxy in front is failing, so both fail.
    pub(super) fn accepted(&self) -> bool {
        if self.expected.is_empty() {
            // A 403 to an absolute-form request is most likely the proxy's own allow list: it fails, as
            // `proxy_403`, unless the spec lists 403 (the server really answers it).
            (200..500).contains(&self.status)
                && self.status != 407
                && !(self.absolute_form && self.status == 403)
        } else {
            self.expected.contains(&self.status)
        }
    }

    /// For a status that counts only because the spec lists none: the note, and whether it is a warning
    /// (a 403 may be the deny page of a transparent proxy, so it warns).
    pub(super) fn default_judgement(&self) -> Option<(&'static str, bool)> {
        if !self.expected.is_empty() || !self.accepted() {
            return None;
        }
        match self.status {
            300..=399 => Some((
                "the redirect was not followed, and with no expect_status a 3xx counts as reachable",
                false,
            )),
            403 => Some((
                "a deny page may come from a proxy or firewall on the path and not from the server; list 403 in expect_status if the server really answers it",
                true,
            )),
            400..=499 => Some((
                "the spec lists no expect_status, so it counts as reachable",
                false,
            )),
            _ => None,
        }
    }
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
    /// The HTTP stage, for a URL endpoint that got that far.
    pub(super) http: Option<HttpView>,
    /// The proxy the endpoint was tried through, as `http://host:port` with no user info. `None` for a
    /// direct endpoint.
    pub(super) via_proxy: Option<String>,
    /// The environment variable the proxy was read from, when known.
    pub(super) proxy_var: Option<&'static str>,
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
            http: None,
            via_proxy: None,
            proxy_var: None,
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

    /// The addresses that failed although a later one carried the connection, as `(family, why)`. A
    /// dead IPv6 address in front of a working IPv4 one is the case this names. Only a refusal, a reset,
    /// no route or a full attempt timeout counts: an attempt the race cut is slow and not known to be
    /// dead (see [`Probed::slow`]).
    pub(super) fn fell_through(&self) -> Vec<(&'static str, String)> {
        // The attempts of a proxied endpoint are the proxy's, not the endpoint's.
        if self.ending != Ending::Reached || self.via_proxy.is_some() {
            return Vec::new();
        }
        self.attempts
            .iter()
            .filter(|a| matches!(a.outcome, "refused" | "reset" | "unreachable" | "timed_out"))
            .map(|a| (a.family, a.outcome.replace('_', " ")))
            .collect()
    }

    /// The addresses the race cut after the stagger or longer, as `(family, ms)`. They did not answer
    /// before another family connected. That is a note and not a warning: a slow path that works is not
    /// a fault.
    pub(super) fn slow(&self) -> Vec<(&'static str, u64)> {
        if self.ending != Ending::Reached || self.via_proxy.is_some() {
            return Vec::new();
        }
        self.attempts
            .iter()
            .filter(|a| a.outcome == "abandoned" && a.elapsed >= STAGGER)
            .map(|a| (a.family, ms(a.elapsed)))
            .collect()
    }

    /// Extra advice for a trust failure that came after a fallback caused by an overridden OS store.
    pub(super) fn override_advice(&self) -> Option<&'static str> {
        let tls = self.tls.as_ref().filter(|t| t.overridden)?;
        matches!(self.ending, Ending::Failed(..)).then_some(
            "SSL_CERT_FILE or SSL_CERT_DIR is set, and rdy did not read what it names, so this verdict used the bundled public roots only. Unset both variables for the product and for rdy, then run again.",
        ).filter(|_| tls.fallback.is_some())
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
        });
        // Through the proxy the attempts are the proxy's own addresses, so they have their own name.
        match &self.via_proxy {
            Some(origin) => {
                out["route"] = json!("proxy");
                out["proxy"] = json!(origin);
                out["proxy_attempts"] = json!(attempts);
            }
            None => out["attempts"] = json!(attempts),
        }
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
        if let Some(http) = &self.http {
            out["http_stage"] = json!({
                "method": http.method,
                "status": http.status,
                "first_byte_ms": ms(http.first_byte),
                "total_ms": ms(http.total),
                "expect_status": http.expected,
            });
            if let Some(host) = &http.location_host {
                out["http_stage"]["location_host"] = json!(host);
            }
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

/// Probes one endpoint, direct or through `proxy` (its origin, from [`Probe::proxy_origin`]), and
/// returns what each stage showed. `queued` is how many rounds of endpoints are still waiting behind
/// this one.
///
/// # Errors
///
/// A [`CheckError`] only when a probe error says the test or the build is wrong and not the network,
/// such as a fixture with no recorded answer. Every network failure is data in the [`Probed`].
pub(super) async fn probe(
    ctx: &CheckContext,
    spec: &Endpoint,
    trust: Trust,
    queued: usize,
    proxy: Option<String>,
    proxy_var: Option<&'static str>,
) -> Result<Probed, CheckError> {
    let tls_wanted = wants_tls(spec);
    let mut out = Probed::new(spec, tls_wanted);
    out.via_proxy = proxy;
    out.proxy_var = proxy_var;
    let left = ctx.remaining();
    if left < RESERVE + MIN_TO_START {
        out.ending = Ending::NotTried(OUT_OF_TIME);
        return Ok(out);
    }
    let budget = ENDPOINT_BUDGET.min(left.saturating_sub(RESERVE));
    match ctx
        .within(budget, stages(ctx, spec, trust, queued, &mut out))
        .await
    {
        Some(done) => done?,
        // The stages it finished stay in `out`; the stage that was running is the one that ran out.
        None => out.ending = Ending::Failed(Class::Timeout, None),
    }
    // Stage 4, for a URL that connected and, for https, that the roots accepted. It has its own budget,
    // cut short in the same way so the result can still be written.
    if out.ending == Ending::Reached && spec.target.is_url() {
        let budget = HTTP_BUDGET.min(ctx.remaining().saturating_sub(RESERVE));
        if budget < MIN_TO_START {
            // The connect worked and the request could not start in the time left: not tried.
            out.ending = Ending::NotTried(OUT_OF_TIME);
        } else {
            match ctx.within(budget, http_stage(ctx, spec, &mut out)).await {
                Some(done) => done?,
                None => out.ending = Ending::Failed(Class::Timeout, None),
            }
        }
    }
    Ok(out)
}

/// Sends the request of a URL endpoint and judges the status against `expect_status`. A redirect is
/// not followed: its status is the answer.
async fn http_stage(
    ctx: &CheckContext,
    spec: &Endpoint,
    out: &mut Probed,
) -> Result<(), CheckError> {
    let method = match spec.method {
        SpecMethod::Head => HttpMethod::Head,
        SpecMethod::Get => HttpMethod::Get,
        // The spec enum may grow; a method this build does not know is not guessed.
        _ => {
            return Err(CheckError::Unsupported(
                "an HTTP method this rdy does not know",
            ));
        }
    };
    // The roots that judged the chain are the roots the request is verified against.
    let roots = match out.tls.as_ref().map(|t| t.roots) {
        Some("bundled") => Roots::Bundled,
        _ => Roots::System,
    };
    let route = route_of(out);
    let request = HttpProbe::new(spec.target.clone(), method)
        .roots(roots)
        .route(route);
    match ctx.probe().http(request).await {
        Ok(reply) => finish_http(out, spec, method, &reply),
        Err(error) => out.ending = failed(error, out)?,
    }
    Ok(())
}

/// Records the answer and sets the ending from the status.
fn finish_http(out: &mut Probed, spec: &Endpoint, method: HttpMethod, reply: &HttpOutcome) {
    let view = HttpView {
        method: method.as_str(),
        status: reply.status,
        first_byte: reply.timing.first_byte,
        total: reply.timing.total,
        expected: spec
            .expect_status
            .as_ref()
            .map(|list| list.iter().map(|s| s.get()).collect())
            .unwrap_or_default(),
        absolute_form: out.via_proxy.is_some() && spec.target.scheme() == Some("http"),
        location_host: reply.location_host.clone(),
        location_port: reply.location_port,
    };
    out.ending = if view.accepted() {
        Ending::Reached
    } else if view.absolute_form && view.status == 403 {
        // The proxy's allow list is the likely cause. The fix says what to do if it was the server.
        Ending::Failed(Class::ProxyForbidden, Some("request".to_owned()))
    } else {
        Ending::Failed(Class::HttpStatus, Some(view.status.to_string()))
    };
    out.http = Some(view);
}

/// The route of an endpoint's calls: through the proxy when the run chose it for this endpoint.
fn route_of(out: &Probed) -> Route {
    if out.via_proxy.is_some() {
        Route::ViaProxy
    } else {
        Route::Direct
    }
}

/// How an endpoint ends when a probe call fails. Through the proxy a failure to connect or to resolve
/// is the proxy's (the endpoint's name resolves at the proxy), never `refused`, `blackhole` or `dns` for
/// the endpoint. The proxy classes that name a variable carry the one the proxy was read from.
fn failed(error: ProbeError, out: &Probed) -> Result<Ending, CheckError> {
    if out.via_proxy.is_some()
        && matches!(
            error,
            ProbeError::Net(NetFailure::NotConnected { .. } | NetFailure::Dns { .. })
        )
    {
        return Ok(Ending::Failed(Class::ProxyUnreachable, None));
    }
    let (class, detail) = Class::of_error(error)?;
    let var = out.proxy_var.unwrap_or("HTTPS_PROXY");
    let detail = match (class, detail) {
        (Class::ProxyAuthRequired, Some(word)) => Some(format!("{word} {var}")),
        (Class::ProxyBadReply, _) => Some(var.to_owned()),
        (_, detail) => detail,
    };
    Ok(Ending::Failed(class, detail))
}

/// Why an endpoint that never started was not tried.
pub(super) const OUT_OF_TIME: &str = "the check ran out of time before it reached this endpoint";

/// The stages of one endpoint, writing each result into `out` as it comes.
async fn stages(
    ctx: &CheckContext,
    spec: &Endpoint,
    trust: Trust,
    queued: usize,
    out: &mut Probed,
) -> Result<(), CheckError> {
    let tls_wanted = out.tls_wanted;
    let target = &spec.target;
    let route = route_of(out);
    let via_proxy = route == Route::ViaProxy;

    // Stage 1: lookup. Through a proxy the name resolves at the proxy, so this machine does not look it
    // up: it may not be able to, and the answer would not be the proxy's.
    if !via_proxy && let Host::Name(name) = target.host() {
        let before = ctx.remaining();
        let answers = ctx.probe().lookup(name).await;
        let took = before.saturating_sub(ctx.remaining());
        match answers {
            Ok(ips) => {
                let v6 = ips.iter().filter(|ip| ip.is_ipv6()).count();
                out.lookup = Some((took, ips.len() - v6, v6));
            }
            Err(error) => {
                out.ending = failed(error, out)?;
                return Ok(());
            }
        }
    }

    // A plain `http://` URL through the proxy is not tunnelled: the HTTP stage sends the absolute form
    // to the proxy and is the whole test. A `CONNECT` to port 80 or 8080 is refused by a proxy that
    // allows tunnels only to port 443, which would be a false `proxy_403`.
    if via_proxy && target.scheme() == Some("http") && !tls_wanted {
        out.ending = Ending::Reached;
        return Ok(());
    }

    // Stages 2 and 3: connect, then TLS.
    if tls_wanted {
        match ctx.probe().tls_chain(target, route).await {
            Ok(chain) => finish_tls(out, &chain, trust),
            Err(ProbeError::Net(NetFailure::NotConnected { .. })) if via_proxy => {
                out.ending = Ending::Failed(Class::ProxyUnreachable, None);
            }
            Err(ProbeError::Net(NetFailure::NotConnected { outcome, .. })) => {
                out.ending = Ending::Failed(Class::of_connect(outcome), None);
                // The attempts name the dead family. Ask for them only when the worst case of the call
                // fits in what is left after this endpoint's own budget and the rounds behind it.
                let behind = SECOND_CONNECT * u32::try_from(queued).unwrap_or(u32::MAX);
                if ctx.remaining() >= RESERVE + SECOND_CONNECT + behind
                    && let Ok(report) = ctx.probe().tcp(target, Route::Direct).await
                {
                    out.attempts = report.attempts.iter().map(AttemptView::of).collect();
                }
                out.ending = Ending::Failed(Class::of_connect(outcome), first_silent(out));
            }
            Err(error) => out.ending = failed(error, out)?,
        }
        return Ok(());
    }

    match ctx.probe().tcp(target, route).await {
        Ok(report) => finish_tcp(out, &report),
        Err(error) => out.ending = failed(error, out)?,
    }
    Ok(())
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
    // Through the proxy the attempts were to the proxy, so the endpoint's own class cannot be told.
    if out.via_proxy.is_some() {
        out.ending = Ending::Failed(Class::ProxyUnreachable, None);
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
            TrustVerdict::Unavailable(why) => (
                "bundled",
                chain.verdict(Roots::Bundled),
                Some((
                    format!(
                        "{}, so the bundled public roots judged the chain",
                        why.phrase()
                    ),
                    why == NoRoots::Overridden,
                )),
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
        overridden: fallback.as_ref().is_some_and(|(_, overridden)| *overridden),
        fallback: fallback.map(|(text, _)| text),
    });
    out.ending = match verdict {
        TrustVerdict::Valid => Ending::Reached,
        TrustVerdict::Rejected(failure) => Ending::Failed(Class::of_trust(failure), None),
        _ => Ending::Failed(Class::NoTrustStore, None),
    };
}
