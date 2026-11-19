//! `net.egress`: can this machine reach the endpoints the product needs, stage by stage (03 section 3,
//! M1-095).
//!
//! For each endpoint, in this order, through the probe facade:
//!
//! 1. **lookup** of the name, timed, with the number of IPv4 and IPv6 answers;
//! 2. **connect** to every address the facade tries (IPv6 first, 250 ms stagger, 3 s each, at most 4),
//!    with one attempt per address in the report, so a dead IPv6 address is named when IPv4 carries the
//!    call;
//! 3. **TLS** for port 443, an `https` URL or `tls: true`: one handshake, the protocol, the ALPN the
//!    server chose, the handshake time, the chain depth, and a verdict against the roots the spec chose.
//!
//! 4. **HTTP** for a URL endpoint (`http://` or `https://`) that connected and, for https, that the
//!    roots accepted: one `HEAD` (or `GET`, by the spec) with no redirect followed. The status is judged
//!    against `expect_status`. With none listed, 2xx, 3xx and 4xx count as reachable except 407 (an
//!    intercepting proxy on the direct route), which fails, and a 5xx, which fails, both as `http_status`.
//!    A 3xx, 401, 404 and any other 4xx get a note, and a 403 warns, because a transparent proxy's deny
//!    page looks the same. A reply that is not HTTP is `http_failed`. A `host:port` endpoint gets no
//!    request, and an `expect_status` on it is noted as ignored. The URL's path and query go to the
//!    facade and never into the finding; the action log keeps the path and never the query.
//!
//! **Through the proxy (M1-097).** The run has at most one proxy, read from `HTTPS_PROXY` or
//! `HTTP_PROXY` (either case) by `rdy run`. `via_proxy: direct` never uses it. `proxy_only` uses it, and
//! with none set the endpoint is not tried and the result is partial. `auto`, the default, goes through
//! the proxy when the run has one and direct when it has none: that is what a product started from the
//! same shell does. A `host:port` or `https` endpoint is tunnelled with the facade's own `CONNECT` and
//! then verified end to end. An `http://` URL is sent to the proxy in the absolute form, with no tunnel,
//! because a proxy that allows `CONNECT` only to port 443 would answer a tunnel to another port with a
//! false 403. The name is not looked up here, because names resolve at the proxy. Classes: `proxy_403`
//! (the endpoint is not on the allow list), `proxy_407` (credentials wanted or rejected, or Negotiate or
//! NTLM, which rdy never attempts), `proxy_refused` (another status to the tunnel), `proxy_bad_reply`
//! and `proxy_unreachable` (no connection to the proxy itself). The proxy password never reaches a
//! finding: the evidence names the proxy as `http://host:port`.
//!
//! **Redirects.** A redirect is never followed. The host of an absolute `Location` is in the evidence
//! (`http_stage.location_host`), and when it is not an endpoint of this check a note says to add it.
//!
//! **`NO_PROXY` (M1-098).** `auto` honours the `NO_PROXY` list the run read (`Probe::route_for`, the
//! matcher of `rdy_engine::probe`): a host the list or the loopback rule exempts connects direct, and the
//! result says which entry did it. `proxy_only` takes the proxy whatever the list says. When an `auto`
//! endpoint fails through the proxy with a proxy class, the check makes one direct `tcp` call (when the
//! time left covers it). If that connects, the result says "direct works, proxy fails", names the proxy
//! variable and says to fix the proxy or add the host to `NO_PROXY`. When `HTTPS_PROXY` and `https_proxy`
//! (or the `HTTP` pair, or `NO_PROXY` and `no_proxy`) are set and differ, a note says which one rdy used.
//!
//! What this version does not do yet: `Date` evidence and issuer names (M1-099).
//!
//! **Levels.** An endpoint that cannot be reached fails the check, or warns when it is `optional`. A
//! connect slower than `max_latency` (2 s by default) warns. A dead address of one family in front of a
//! working address of the other warns, because a client without happy eyeballs hangs on it.
//!
//! **Needs.** `Need::Network`. Under `--no-network` the check is skipped as `missing_need(network)` and
//! no socket is opened. The probe only reaches the check's own endpoints (INV-11) and refuses
//! link-local, metadata, unspecified, multicast and broadcast addresses (INV-12), listed or not.
//!
//! **Privilege.** None. Root adds nothing here, so the check declares no `Want`.

use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Need,
    Os, OsSupport, PeerClass, Support,
};
use rdy_engine::probe::Exemption;
use rdy_engine::probe::net::REVOCATION_NOTE;
use rdy_engine::probe::net::Route;
use rdy_spec::check::{Endpoint, NetEgress, ViaProxy};
use serde_json::json;

use self::class::Class;
use self::stage::{Ending, Probed, Way, ms, probe};

mod class;
mod stage;
#[cfg(test)]
mod tests;

/// How many endpoints are probed at once.
const PARALLEL: usize = 8;

/// A connect slower than this warns, when the spec sets no `max_latency`.
const DEFAULT_MAX_LATENCY: Duration = Duration::from_secs(2);

/// The most endpoints the message names before it says "and N more".
const NAMED: usize = 5;

/// The most distinct fixes the finding carries.
const FIXES: usize = 3;

/// The static facts about `net.egress` (03 section 3).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "net.egress",
    family: "net",
    summary: "Each endpoint resolves, connects on every address family, completes TLS and answers HTTP",
    meta: CheckMeta {
        title: "Egress",
        remediation: "Ask the network team to allow the endpoint from this machine: the TCP port to the host named in the result. If the name does not resolve, fix DNS or add a temporary hosts file entry. If the certificate is not trusted, a TLS-inspecting proxy is the usual cause: bypass inspection for the host, or install the proxy's CA in the OS trust store. Where openssl is installed, run `openssl s_client -connect <host>:<port> -servername <host>` to see what the server sends.",
    },
    needs: &[Need::Network],
    wants: &[],
    default_timeout: Some(Duration::from_secs(60)),
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    },
    reads: &[],
    statfs: &[],
    // The proxy and `NO_PROXY` are read once for the run by `ProbeHub::set_proxy_from_env`, so the
    // check reads no variable itself.
    env: &[],
    commands: &[],
    peers: &[PeerClass::SpecHosts, PeerClass::Proxy],
};

/// `net.egress`, built from its spec entry.
#[derive(Debug)]
pub struct EgressCheck {
    params: NetEgress,
}

impl EgressCheck {
    /// The check for `params`.
    #[must_use]
    pub fn new(params: NetEgress) -> Self {
        Self { params }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }

    fn max_latency(&self) -> Duration {
        self.params
            .max_latency
            .as_ref()
            .map_or(DEFAULT_MAX_LATENCY, |d| d.to_std())
    }
}

impl Check for EgressCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            if !ctx.has(&Need::Network) {
                return Err(CheckError::MissingNeed(Need::Network));
            }
            // The futures are built first and boxed, so the stream does not borrow through a closure
            // (a closure that returns an async block over a reference is not `Send` for every lifetime).
            let entry_route = self.params.via_proxy;
            let trust = self.params.trust;
            let total = self.params.endpoints.len();
            let proxy = ctx.probe().proxy_origin();
            let proxy_var = ctx.probe().proxy_source();
            let pending: Vec<BoxFuture<'a, Result<Probed, CheckError>>> =
                self.params
                    .endpoints
                    .iter()
                    .enumerate()
                    .map(|(at, spec)| -> BoxFuture<'a, Result<Probed, CheckError>> {
                        // Rounds of endpoints that wait behind this one, for the budget of its extra call.
                        let queued = (total - at - 1) / PARALLEL;
                        match route_of(ctx, spec, entry_route, proxy.as_deref()) {
                            Routing::Direct(exempt) => {
                                Box::pin(probe(ctx, spec, trust, queued, Way::direct(exempt)))
                            }
                            Routing::Proxy { origin, auto } => Box::pin(probe(
                                ctx,
                                spec,
                                trust,
                                queued,
                                Way::proxy(origin.to_owned(), proxy_var, auto),
                            )),
                            Routing::NoProxy => Box::pin(std::future::ready(Ok(
                                Probed::not_tried(spec, NO_PROXY_SET),
                            ))),
                        }
                    })
                    .collect();
            let probed: Vec<Result<Probed, CheckError>> =
                stream::iter(pending).buffered(PARALLEL).collect().await;
            let probed: Vec<Probed> = probed.into_iter().collect::<Result<_, _>>()?;
            let mut finding = self.judge(ctx.os(), &probed);
            // Two spellings of one proxy variable that differ: the product may read the other one. Names
            // only, never a value.
            for conflict in ctx.probe().proxy_env_conflicts() {
                finding = finding.with_note(format!(
                    "{} and {} are both set and differ. rdy used {} for this run. Tools do not agree on which one wins (curl and Python read {} first), so the product may use the other value. Set one of them, or make them equal.",
                    conflict.upper, conflict.lower, conflict.upper, conflict.lower
                ));
            }
            Ok(finding)
        })
    }
}

/// Why a proxy-only endpoint is not tried when the run has no proxy.
const NO_PROXY_SET: &str = "the endpoint is proxy_only and no proxy is set for this run; set HTTPS_PROXY or HTTP_PROXY before running rdy";

/// How an endpoint is reached.
enum Routing<'p> {
    /// Straight to the host. The reason is set when the run has a proxy and `NO_PROXY` or the loopback
    /// rule sent the host direct.
    Direct(Option<Exemption>),
    /// Through the run's proxy, named by its origin. `auto` is set when the route is `auto` and not
    /// `proxy_only`.
    Proxy { origin: &'p str, auto: bool },
    /// The spec says proxy only and the run has no proxy.
    NoProxy,
}

/// The route of an endpoint: its own `via_proxy`, else the entry's. `auto` is the path the product takes
/// when it is started from the same shell: through the run's proxy, unless `NO_PROXY` exempts the host
/// (M1-098). `proxy_only` takes the proxy whatever `NO_PROXY` says, because the spec asked for it.
fn route_of<'p>(
    ctx: &CheckContext,
    spec: &Endpoint,
    entry: ViaProxy,
    proxy: Option<&'p str>,
) -> Routing<'p> {
    match (spec.via_proxy.unwrap_or(entry), proxy) {
        (ViaProxy::Direct, _) => Routing::Direct(None),
        (ViaProxy::ProxyOnly, None) => Routing::NoProxy,
        (ViaProxy::ProxyOnly, Some(origin)) => Routing::Proxy {
            origin,
            auto: false,
        },
        (_, Some(origin)) => {
            let choice = ctx.probe().route_for(&spec.target);
            match choice.route {
                Route::ViaProxy => Routing::Proxy { origin, auto: true },
                _ => Routing::Direct(choice.exempt),
            }
        }
        (_, None) => Routing::Direct(None),
    }
}

impl EgressCheck {
    /// The finding for the endpoints as probed.
    fn judge(&self, os: Os, probed: &[Probed]) -> Finding {
        let max_latency = self.max_latency();
        let mut failed: Vec<&Probed> = Vec::new();
        let mut optional_failed: Vec<&Probed> = Vec::new();
        let mut not_tried: Vec<&Probed> = Vec::new();
        let mut warns: Vec<String> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        for p in probed {
            // The reason is the same for every endpoint on this machine, so it is noted once.
            if let Some(why) = p.tls.as_ref().and_then(|t| t.fallback.as_ref()) {
                let note = format!("TLS trust: {why}");
                if !notes.contains(&note) {
                    notes.push(note);
                }
            }
            match &p.ending {
                Ending::Reached => {
                    if let Some(connect) = p.connect.filter(|c| *c > max_latency) {
                        warns.push(format!(
                            "{} took {} ms to connect, above {} ms",
                            p.label(),
                            ms(connect),
                            ms(max_latency)
                        ));
                    }
                    for (family, took) in p.slow() {
                        notes.push(format!(
                            "{}: the {family} address had no reply within {took} ms, so another family connected first",
                            p.label()
                        ));
                    }
                    if let Some(http) = &p.http
                        && let Some((why, warn)) = http.default_judgement()
                    {
                        let text = format!("{} answered {}: {why}", p.label(), http.status);
                        if warn {
                            warns.push(text);
                        } else {
                            notes.push(text);
                        }
                    }
                    if let Some(http) = &p.http
                        && let Some(host) = http.location_host.as_deref()
                        && !listed(&self.params, host)
                    {
                        let port = http.location_port.unwrap_or(443);
                        notes.push(format!(
                            "{} redirects to {host}, which rdy did not follow. Add {host}:{port} to the endpoints to test it.",
                            p.label()
                        ));
                    }
                    let fell = p.fell_through();
                    if let Some((family, why)) = fell.first() {
                        warns.push(format!(
                            "{}: the {family} address failed ({why}) and another family carried the connection",
                            p.label(),
                        ));
                    }
                }
                Ending::Failed(class, ip) => {
                    if matches!(class, Class::Blackhole) {
                        notes.push(format!(
                            "{}: no reply within 3 s from {}",
                            p.label(),
                            ip.as_deref().unwrap_or("any address")
                        ));
                    }
                    if p.optional {
                        optional_failed.push(p);
                    } else {
                        failed.push(p);
                    }
                }
                Ending::NotTried(_) => not_tried.push(p),
            }
        }

        let proxied =
            |p: &&Probed| p.via_proxy.is_some() && !matches!(p.ending, Ending::NotTried(_));
        if let Some(origin) = probed
            .iter()
            .filter(proxied)
            .find_map(|p| p.via_proxy.as_deref())
        {
            notes.push(format!(
                "{} endpoint(s) went through the proxy {origin}. A name resolves at the proxy, not on this machine.",
                probed.iter().filter(proxied).count()
            ));
        }
        // Hosts that `NO_PROXY` (or the loopback rule) sent direct although the run has a proxy.
        let bypassed: Vec<&Probed> = probed.iter().filter(|p| p.exempt.is_some()).collect();
        for p in bypassed.iter().take(NAMED) {
            if let Some(why) = &p.exempt {
                notes.push(format!(
                    "{} went direct, not through the proxy: {why}.",
                    p.label()
                ));
            }
        }
        if bypassed.len() > NAMED {
            notes.push(format!(
                "and {} more endpoints went direct for the same reason",
                bypassed.len() - NAMED
            ));
        }
        for p in probed.iter().filter(|p| p.direct_works) {
            notes.push(format!(
                "{}: direct works, proxy fails. A connection straight to the endpoint from this machine succeeded, so only the path through the proxy {} is broken.",
                p.label(),
                p.via_proxy.as_deref().unwrap_or("")
            ));
        }
        // One proxy serves the whole run. When it came from `HTTP_PROXY`, a tunnelled endpoint used it
        // although the usual tool would have taken `HTTPS_PROXY` for it.
        if let Some(var) = probed
            .iter()
            .filter(proxied)
            .filter(|p| p.tls_wanted)
            .find_map(|p| p.proxy_var.filter(|v| v.eq_ignore_ascii_case("http_proxy")))
        {
            notes.push(format!(
                "An https endpoint went through a proxy read from {var}, because rdy uses one proxy for the whole run and {var} was the only proxy variable set. Set HTTPS_PROXY if the product uses a different proxy for https."
            ));
        }
        let total = probed.len();
        let observed = json!({
            "endpoints": probed.iter().map(Probed::json).collect::<Vec<_>>(),
        });
        let expected = json!({
            "trust": match self.params.trust {
                rdy_spec::check::Trust::Bundled => "bundled",
                _ => "system",
            },
            "max_latency_ms": ms(max_latency),
        });

        let mut finding = if failed.is_empty() && optional_failed.is_empty() && warns.is_empty() {
            let tried = total - not_tried.len();
            if tried == 0 {
                Finding::pass("no endpoint was tried")
            } else {
                Finding::pass(format!("{tried} of {total} endpoints reachable"))
            }
        } else if failed.is_empty() {
            let optional_tag = format!("optional, {}", word(&optional_failed));
            let mut parts = names(&optional_failed, &optional_tag);
            parts.extend(warns.iter().cloned());
            Finding::warn(parts.join("; "))
        } else {
            let mut message = format!(
                "{} of {total} endpoints {}: {}",
                failed.len(),
                word(&failed),
                names(&failed, "").join(", ")
            );
            if !optional_failed.is_empty() {
                message.push_str(&format!(
                    "; {} optional also {}",
                    optional_failed.len(),
                    word(&optional_failed)
                ));
            }
            Finding::fail(message)
        }
        .with_observed(observed)
        .with_expected(expected);

        let unreachable: Vec<&Probed> = failed.iter().chain(&optional_failed).copied().collect();
        if let Some(fix) = fixes(os, &unreachable) {
            finding = finding.with_fix(fix);
        }
        // A handshake that finished says nothing about revocation. Said once per result (SF-01), first, because a report keeps only the first
        // notes and an endpoint list can fill the rest.
        if probed.iter().any(|p| p.tls.is_some()) {
            finding = finding.with_note(REVOCATION_NOTE);
        }
        for warn in &warns {
            finding = finding.with_note(warn.clone());
        }
        for note in notes {
            finding = finding.with_note(note);
        }
        if !not_tried.is_empty() {
            // One sentence per reason, in the order the reasons first appear.
            let mut reasons: Vec<(&str, usize)> = Vec::new();
            for p in &not_tried {
                if let Ending::NotTried(why) = p.ending {
                    match reasons.iter_mut().find(|(r, _)| *r == why) {
                        Some((_, n)) => *n += 1,
                        None => reasons.push((why, 1)),
                    }
                }
            }
            let note = reasons
                .iter()
                .map(|(why, n)| format!("{n} of {total} endpoints were not tried: {why}"))
                .collect::<Vec<_>>()
                .join("; ");
            finding = finding.with_partial(rdy_engine::check::Partial::new(Vec::new(), note));
        }
        let ignored = self
            .params
            .endpoints
            .iter()
            .filter(|e| e.expect_status.is_some() && !e.target.is_url())
            .count();
        if ignored > 0 {
            finding = finding.with_note(format!(
                "expect_status is ignored for {ignored} endpoint(s) written as host:port: rdy sends an HTTP request only to an http:// or https:// URL"
            ));
        }
        finding
    }
}

/// Whether `host` is the host of one of the check's endpoints.
fn listed(params: &NetEgress, host: &str) -> bool {
    params
        .endpoints
        .iter()
        .any(|e| e.target.host().to_string().eq_ignore_ascii_case(host))
}

/// "failed" when every endpoint in the list got an answer that was wrong (an HTTP status or a reply that is
/// not HTTP), else "unreachable": an endpoint that answered HTTP was reached.
fn word(list: &[&Probed]) -> &'static str {
    let answered = list.iter().all(|p| {
        matches!(
            p.ending,
            Ending::Failed(Class::HttpStatus | Class::HttpFailed, _)
        )
    });
    if answered { "failed" } else { "unreachable" }
}

/// `host:port (class)` for up to [`NAMED`] endpoints, then "and N more". `tag` is added to each when
/// it is not empty.
fn names(list: &[&Probed], tag: &str) -> Vec<String> {
    let mut out: Vec<String> = list
        .iter()
        .take(NAMED)
        .map(|p| {
            let class = match &p.ending {
                Ending::Failed(Class::HttpStatus, _) => match &p.http {
                    Some(http) => format!("http_status {}", http.status),
                    None => Class::HttpStatus.id().to_owned(),
                },
                Ending::Failed(class, _) => class.id().to_owned(),
                _ => "not tried".to_owned(),
            };
            if tag.is_empty() {
                format!("{} ({class})", p.label())
            } else {
                format!("{} ({tag}: {class})", p.label())
            }
        })
        .collect();
    if list.len() > NAMED {
        out.push(format!("and {} more", list.len() - NAMED));
    }
    out
}

/// The fix text for the first endpoints of each distinct class, at most [`FIXES`] of them.
fn fixes(os: Os, list: &[&Probed]) -> Option<String> {
    let mut seen: Vec<Class> = Vec::new();
    let mut parts: Vec<String> = Vec::new();
    for p in list {
        let Ending::Failed(class, ip) = &p.ending else {
            continue;
        };
        if seen.contains(class) || seen.len() >= FIXES {
            continue;
        }
        seen.push(*class);
        parts.push(class.fix(os, &p.host, p.port, ip.as_deref()));
        if p.direct_works {
            parts.push(format!(
                "A direct connection to {}:{} works, so a product started from this shell fails through the proxy. Fix the proxy as above, or add {} to NO_PROXY so the product connects direct.",
                p.host, p.port, p.host
            ));
        }
        if let Some(advice) = p.override_advice() {
            parts.push(advice.to_owned());
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}
