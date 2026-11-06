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
//! What this version does not do yet: the HTTP request and `expect_status` (M1-096), the proxy path
//! (M1-097), redirect and `Date` evidence. An endpoint whose `via_proxy` is `proxy_only` is not tried,
//! and the result says so and is partial.
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
    OsSupport, PeerClass, Support,
};
use rdy_spec::check::{Endpoint, NetEgress, ViaProxy};
use serde_json::json;

use self::class::Class;
use self::stage::{Ending, Probed, ms, probe};

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
    summary: "Each endpoint resolves, connects on every address family, and completes TLS",
    meta: CheckMeta {
        title: "Egress",
        remediation: "Ask the network team to allow the endpoint from this machine: the TCP port to the host named in the result. If the name does not resolve, fix DNS or add a temporary line to `/etc/hosts`. If the certificate is not trusted, a TLS-inspecting proxy is the usual cause: bypass inspection for the host, or install the proxy's CA with `update-ca-certificates` (Debian, Ubuntu) or `update-ca-trust` (RHEL). Run `openssl s_client -connect <host>:<port> -servername <host>` to see what the server sends.",
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
    env: &[],
    commands: &[],
    peers: &[PeerClass::SpecHosts],
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
            let pending: Vec<BoxFuture<'a, Result<Probed, CheckError>>> = self
                .params
                .endpoints
                .iter()
                .map(|spec| -> BoxFuture<'a, Result<Probed, CheckError>> {
                    if routes_direct(spec, entry_route) {
                        Box::pin(probe(ctx, spec, trust))
                    } else {
                        Box::pin(std::future::ready(Ok(Probed::not_tried(spec, PROXY_LATER))))
                    }
                })
                .collect();
            let probed: Vec<Result<Probed, CheckError>> =
                stream::iter(pending).buffered(PARALLEL).collect().await;
            let probed: Vec<Probed> = probed.into_iter().collect::<Result<_, _>>()?;
            Ok(self.judge(&probed))
        })
    }
}

/// Why a proxy-only endpoint is not tried.
const PROXY_LATER: &str = "this version of rdy does not send a check through a proxy yet";

/// Whether the endpoint is tried directly. `auto` and `direct` are; `proxy_only` is not tried yet.
fn routes_direct(spec: &Endpoint, entry: ViaProxy) -> bool {
    spec.via_proxy.unwrap_or(entry) != ViaProxy::ProxyOnly
}

impl EgressCheck {
    /// The finding for the endpoints as probed.
    fn judge(&self, probed: &[Probed]) -> Finding {
        let max_latency = self.max_latency();
        let mut failed: Vec<&Probed> = Vec::new();
        let mut optional_failed: Vec<&Probed> = Vec::new();
        let mut not_tried: Vec<&Probed> = Vec::new();
        let mut warns: Vec<String> = Vec::new();
        for p in probed {
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
                    let fell = p.fell_through();
                    if let Some((family, why)) = fell.first() {
                        warns.push(format!(
                            "{}: the {family} address failed ({why}) and another family carried the connection",
                            p.label(),
                        ));
                    }
                }
                Ending::Failed(..) if p.optional => optional_failed.push(p),
                Ending::Failed(..) => failed.push(p),
                Ending::NotTried(_) => not_tried.push(p),
            }
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
            let mut parts = names(&optional_failed, "optional, unreachable");
            parts.extend(warns.iter().cloned());
            Finding::warn(parts.join("; "))
        } else {
            let mut message = format!(
                "{} of {total} endpoints unreachable: {}",
                failed.len(),
                names(&failed, "").join(", ")
            );
            if !optional_failed.is_empty() {
                message.push_str(&format!(
                    "; {} optional also unreachable",
                    optional_failed.len()
                ));
            }
            Finding::fail(message)
        }
        .with_observed(observed)
        .with_expected(expected);

        let unreachable: Vec<&Probed> = failed.iter().chain(&optional_failed).copied().collect();
        if let Some(fix) = fixes(&unreachable) {
            finding = finding.with_fix(fix);
        }
        for warn in &warns {
            finding = finding.with_note(warn.clone());
        }
        if !not_tried.is_empty() {
            let note = format!(
                "{} of {total} endpoints were not tried: {PROXY_LATER}",
                not_tried.len()
            );
            finding = finding.with_partial(rdy_engine::check::Partial::new(Vec::new(), note));
        }
        if self
            .params
            .endpoints
            .iter()
            .any(|e| e.expect_status.is_some())
        {
            finding = finding.with_note(
                "expect_status is not checked yet: this version of rdy stops after the TLS handshake and sends no HTTP request",
            );
        }
        finding
    }
}

/// `host:port (class)` for up to [`NAMED`] endpoints, then "and N more". `tag` is added to each when
/// it is not empty.
fn names(list: &[&Probed], tag: &str) -> Vec<String> {
    let mut out: Vec<String> = list
        .iter()
        .take(NAMED)
        .map(|p| {
            let class = match &p.ending {
                Ending::Failed(class, _) => class.id(),
                _ => "not tried",
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
fn fixes(list: &[&Probed]) -> Option<String> {
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
        parts.push(class.fix(&p.host, p.port, ip.as_deref()));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}
