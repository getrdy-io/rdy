//! `net.tls_intercept`: is a middlebox re-signing TLS to the hosts the product needs, and does this
//! machine trust what it presents (03 section 3, M1-099).
//!
//! For each host the check makes one handshake through `Probe::tls_chain` and reads the two verdicts
//! the facade records for the chain it was shown: one against the bundled public roots, one against this
//! machine's OS store. The verdicts become one [`Class`]:
//!
//! - **public**: the public roots validate the chain. No interception. Pass.
//! - **machine_only**: only the OS store validates it. Warn, or block when the spec sets
//!   `forbid_interception`.
//! - **unknown_ca**: no root validates it. The issuer's CA is not installed, and product clients fail.
//!   Block.
//! - **clock_or_expiry**: a certificate is expired or not valid yet. Block, with a pointer to
//!   `host.time_sync`. Never reported as interception.
//! - **tls_name_mismatch**, **tls_untrusted**, **no_trust_store**: block, each with its own text.
//!
//! **The verifier.** The facade owns the recording verifier. It is private to the facade, it runs the
//! two real `WebPki` verifiers and records their verdicts, and it sends `close_notify` and zero
//! application bytes. This crate never sees a stream, a verifier or a rustls type. The check judges the
//! recorded verdicts and never the outcome of a connection that carried data, because none does.
//!
//! **Hosts.** The spec's `hosts`, or by default every `net.egress` endpoint of the spec that gets a TLS
//! handshake there (port 443, an `https` URL, or `tls: true`, unless `tls: false`), once per host and
//! port. At most [`MAX_HOSTS`]; the rest are named as not tested.
//!
//! **Not built yet (M1-100).** Issuer and subject names, the root's SHA-256, the trust-store location and
//! the per-distro install commands, and with them `expected_issuer` and `pin_sha256`, which need
//! `x509-parser`. When the spec sets either, the finding is partial and says so, so a pin is never read
//! as met. A host behind a proxy is not tried (M1-097).
//!
//! **Needs.** `Need::Network`, the same limits as `net.egress`: 10 s per host, 8 hosts at a time, 2 s of
//! the check's time left for the result. The probe reaches only the check's own hosts (INV-11) and
//! refuses link-local and metadata addresses (INV-12).
//!
//! **Privilege.** None.

use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Need, Os, OsSupport, Partial, PeerClass, Support,
};
use rdy_engine::probe::net::{Route, TlsChain, TrustFailure, TrustVerdict};
use rdy_engine::probe::{NetFailure, ProbeError};
use rdy_spec::Target;
use rdy_spec::check::{CheckParams, NetEgress, NetTlsIntercept};
use rdy_spec::scalar::Host;
use rdy_spec::spec::Spec;
use serde_json::{Value, json};

use self::class::Class;

mod class;
#[cfg(test)]
mod tests;

/// How many hosts are probed at once, as in `net.egress`.
const PARALLEL: usize = 8;

/// The most time one host takes, from its lookup to the end of its handshake.
const HOST_BUDGET: Duration = Duration::from_secs(10);

/// Time of the check that is never spent on hosts, so the result can be written.
const RESERVE: Duration = Duration::from_secs(2);

/// Below this much time left a host that has not started is not tried.
const MIN_TO_START: Duration = Duration::from_secs(1);

/// The most hosts one check tests, the spec's own limit for `hosts`.
pub(crate) const MAX_HOSTS: usize = 64;

/// The most hosts the message names before it says "and N more".
const NAMED: usize = 5;

/// The most distinct fixes the finding carries.
const FIXES: usize = 3;

/// The static facts about `net.tls_intercept` (03 section 3).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "net.tls_intercept",
    family: "net",
    summary: "TLS to each host is not re-signed by a middlebox this machine does not trust",
    meta: CheckMeta {
        title: "TLS interception",
        remediation: "Ask the network team to bypass TLS inspection for the host named in the result, or install the inspecting proxy's CA where the product reads its trust store. Where openssl is installed, run `openssl s_client -connect <host>:<port> -servername <host>` to see who issued the chain. If the result is a clock or expiry problem, fix the clock first.",
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

/// The hosts a `net.tls_intercept` entry tests, as targets, and how many were left out for the limit.
///
/// The spec's `hosts` when it has them, else every `net.egress` endpoint of the spec that gets a TLS
/// handshake, once per host and port, in spec order.
pub(crate) fn hosts_for(params: &NetTlsIntercept, spec: &Spec) -> (Vec<Target>, usize) {
    let mut found: Vec<Target> = Vec::new();
    let mut add = |target: Target| {
        let bare = bare(&target);
        if !found.contains(&bare) {
            found.push(bare);
        }
    };
    match &params.hosts {
        Some(hosts) => hosts.iter().for_each(|h| add(h.target().clone())),
        None => {
            for entry in spec.checks.iter().filter(|e| e.id == "net.egress") {
                if let CheckParams::NetEgress(NetEgress { endpoints, .. }) = entry.decode_params() {
                    for endpoint in endpoints.iter() {
                        let tls = endpoint.tls.unwrap_or_else(|| {
                            endpoint.target.port() == 443
                                || endpoint.target.scheme() == Some("https")
                        });
                        if tls {
                            add(endpoint.target.clone());
                        }
                    }
                }
            }
        }
    }
    let dropped = found.len().saturating_sub(MAX_HOSTS);
    found.truncate(MAX_HOSTS);
    (found, dropped)
}

/// `host:port` without a scheme or path, so two endpoints of one host and port are one host.
fn bare(target: &Target) -> Target {
    let text = match target.host() {
        Host::Ipv6(addr) => format!("[{addr}]:{}", target.port()),
        host => format!("{host}:{}", target.port()),
    };
    // The text was built from a parsed target, so it parses. If it somehow does not, the target is used
    // as it is: the probe judges it again.
    Target::parse(&text).unwrap_or_else(|_| target.clone())
}

/// `net.tls_intercept`, built from its spec entry.
#[derive(Debug)]
pub struct TlsInterceptCheck {
    hosts: Vec<Target>,
    dropped: usize,
    forbid_interception: bool,
    /// `expected_issuer` or `pin_sha256` is set. They are not checked in this version.
    unchecked: bool,
}

impl TlsInterceptCheck {
    /// The check for `params`, testing `hosts` (see [`hosts_for`]) and leaving `dropped` out.
    #[must_use]
    pub(crate) fn new(params: &NetTlsIntercept, hosts: Vec<Target>, dropped: usize) -> Self {
        Self {
            hosts,
            dropped,
            forbid_interception: params.forbid_interception,
            unchecked: params.expected_issuer.is_some() || params.pin_sha256.is_some(),
        }
    }
}

/// What one host came to.
#[derive(Debug)]
struct Tested {
    label: String,
    host: String,
    port: u16,
    what: What,
}

#[derive(Debug)]
enum What {
    /// The handshake gave a chain.
    Chain { class: Class, seen: Seen },
    /// No chain was had, for this reason. The probe's own words, never the peer's.
    Untested(&'static str),
}

/// What the evidence says about a chain.
#[derive(Debug)]
struct Seen {
    depth: usize,
    bundled: &'static str,
    system: &'static str,
    system_roots: usize,
    protocol: Option<&'static str>,
}

fn verdict_id(verdict: TrustVerdict) -> &'static str {
    match verdict {
        TrustVerdict::Valid => "valid",
        TrustVerdict::Rejected(failure) => match failure {
            TrustFailure::UnknownIssuer => "unknown_issuer",
            TrustFailure::Expired => "expired",
            TrustFailure::NotYetValid => "not_yet_valid",
            TrustFailure::NameMismatch => "name_mismatch",
            TrustFailure::BadSignature => "bad_signature",
            _ => "policy",
        },
        TrustVerdict::Unavailable(_) => "no_store",
        _ => "unknown",
    }
}

impl Seen {
    fn of(chain: &TlsChain) -> Self {
        Self {
            depth: chain.certs.len(),
            bundled: verdict_id(chain.bundled),
            system: verdict_id(chain.system),
            system_roots: chain.system_roots,
            protocol: chain.protocol,
        }
    }
}

impl Tested {
    fn json(&self) -> Value {
        let mut out = json!({"host": self.label});
        match &self.what {
            What::Chain { class, seen } => {
                out["class"] = class.id().into();
                out["chain_depth"] = seen.depth.into();
                out["public_roots"] = seen.bundled.into();
                out["os_store"] = seen.system.into();
                out["os_store_roots"] = seen.system_roots.into();
                out["protocol"] = seen.protocol.into();
            }
            What::Untested(why) => {
                out["class"] = "not_tested".into();
                out["reason"] = (*why).into();
            }
        }
        out
    }
}

/// Why a host that never started was not tried.
const OUT_OF_TIME: &str = "the check ran out of time before it reached this host";

/// The words for a failure to get a chain. Fixed phrases: nothing from the peer reaches the report.
fn untested(error: ProbeError) -> Result<&'static str, CheckError> {
    Ok(match error {
        ProbeError::Denied { .. } => "rdy's address rules refuse this host",
        ProbeError::Timeout => "a step ran out of time",
        ProbeError::Net(failure) => match failure {
            NetFailure::Dns { .. } => "the name did not resolve",
            NetFailure::NotConnected { .. } => "no connection opened",
            NetFailure::TlsReset { .. }
            | NetFailure::TlsAlert { .. }
            | NetFailure::TlsFailed { .. } => "the TLS handshake did not complete",
            _ => "the host could not be reached",
        },
        ProbeError::PermissionDenied | ProbeError::NotFound | ProbeError::Io(_) => {
            "the host could not be reached"
        }
        // A fixture with no recorded answer, or another sign that the test or the build is wrong.
        other => return Err(CheckError::Probe(other)),
    })
}

async fn test_host(ctx: &CheckContext, target: &Target) -> Result<Tested, CheckError> {
    let host = target.host().to_string();
    let port = target.port();
    // `Host` prints an IPv6 literal in brackets already.
    let label = format!("{host}:{port}");
    let make = |what| Tested {
        label: label.clone(),
        host: host.clone(),
        port,
        what,
    };
    let left = ctx.remaining();
    if left < RESERVE + MIN_TO_START {
        return Ok(make(What::Untested(OUT_OF_TIME)));
    }
    let budget = HOST_BUDGET.min(left.saturating_sub(RESERVE));
    let what = match ctx
        .within(budget, ctx.probe().tls_chain(target, Route::Direct))
        .await
    {
        Some(Ok(chain)) => What::Chain {
            class: Class::of_verdicts(chain.bundled, chain.system),
            seen: Seen::of(&chain),
        },
        Some(Err(error)) => What::Untested(untested(error)?),
        None => What::Untested("a step ran out of time"),
    };
    Ok(make(what))
}

impl Check for TlsInterceptCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            if !ctx.has(&Need::Network) {
                return Err(CheckError::MissingNeed(Need::Network));
            }
            // Built and boxed first, as `net.egress` does, so the stream does not borrow through a closure.
            let pending: Vec<BoxFuture<'a, Result<Tested, CheckError>>> = self
                .hosts
                .iter()
                .map(|target| -> BoxFuture<'a, Result<Tested, CheckError>> {
                    Box::pin(test_host(ctx, target))
                })
                .collect();
            let done: Vec<Result<Tested, CheckError>> =
                stream::iter(pending).buffered(PARALLEL).collect().await;
            let done: Vec<Tested> = done.into_iter().collect::<Result<_, _>>()?;
            Ok(self.judge(ctx.os(), &done))
        })
    }
}

impl TlsInterceptCheck {
    /// The finding for the hosts as tested.
    fn judge(&self, os: Os, done: &[Tested]) -> Finding {
        let forbid = self.forbid_interception;
        let chains: Vec<(&Tested, Class)> = done
            .iter()
            .filter_map(|t| match &t.what {
                What::Chain { class, .. } => Some((t, *class)),
                What::Untested(_) => None,
            })
            .collect();
        let untested: Vec<&Tested> = done
            .iter()
            .filter(|t| matches!(t.what, What::Untested(_)))
            .collect();
        let worst = chains
            .iter()
            .map(|(_, class)| class.level(forbid))
            .max_by_key(|level| match level {
                Level::Pass => 0,
                Level::Warn => 1,
                Level::Fail => 2,
            });
        let flagged: Vec<(&Tested, Class)> = chains
            .iter()
            .filter(|(_, class)| *class != Class::Public)
            .copied()
            .collect();

        let mut finding = match worst {
            None if done.is_empty() => Finding::pass("no host to test"),
            // Nothing was learned. That is not a pass: nobody can say there is no interception.
            None => Finding::warn(format!(
                "no host could be tested ({} not tested); net.egress shows why",
                untested.len()
            )),
            Some(Level::Pass) => Finding::pass(format!(
                "{} of {} hosts present a chain the public roots validate",
                chains.len(),
                done.len()
            )),
            Some(level) => {
                let mut parts: Vec<String> = flagged
                    .iter()
                    .take(NAMED)
                    .map(|(t, class)| format!("{} ({})", t.label, class.phrase()))
                    .collect();
                if flagged.len() > NAMED {
                    parts.push(format!("and {} more", flagged.len() - NAMED));
                }
                Finding::new(level, parts.join("; "))
            }
        }
        .with_observed(json!({"hosts": done.iter().map(Tested::json).collect::<Vec<_>>()}))
        .with_expected(json!({"forbid_interception": forbid}));

        let mut seen_classes: Vec<Class> = Vec::new();
        let mut fixes: Vec<String> = Vec::new();
        for (t, class) in &flagged {
            if seen_classes.contains(class) || seen_classes.len() >= FIXES {
                continue;
            }
            seen_classes.push(*class);
            fixes.extend(class.fix(os, &t.host, t.port, forbid));
        }
        if !fixes.is_empty() {
            finding = finding.with_fix(fixes.join(" "));
        }

        // A system store that held no roots is a fact about the machine, said once.
        if store_empty(done) {
            finding = finding
                .with_note("no OS trust store found: only the public roots could judge the chains");
        }

        let mut not_verified: Vec<String> = Vec::new();
        if !untested.is_empty() {
            let named: Vec<String> = untested
                .iter()
                .take(NAMED)
                .filter_map(|t| match &t.what {
                    What::Untested(why) => Some(format!("{} ({why})", t.label)),
                    What::Chain { .. } => None,
                })
                .collect();
            not_verified.push(format!(
                "{} of {} hosts were not tested: {}",
                untested.len(),
                done.len(),
                named.join(", ")
            ));
        }
        if self.dropped > 0 {
            not_verified.push(format!(
                "{} hosts over the limit of {MAX_HOSTS} were not tested",
                self.dropped
            ));
        }
        if self.unchecked {
            not_verified.push(
                "expected_issuer and pin_sha256 are not checked yet: this version of rdy reads no issuer name or certificate hash"
                    .to_owned(),
            );
        }
        if !not_verified.is_empty() {
            finding = finding.with_partial(Partial::new(Vec::new(), not_verified.join("; ")));
        }
        finding
    }
}

/// Whether the OS store gave no roots for the chains of this run.
fn store_empty(done: &[Tested]) -> bool {
    done.iter()
        .any(|t| matches!(&t.what, What::Chain { seen, .. } if seen.system == "no_store"))
}
