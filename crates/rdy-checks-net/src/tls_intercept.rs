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
//! **Evidence (M1-100).** For each chain: the leaf's issuer and subject (read with `x509-parser`, cleaned
//! and cut), the chain depth, the SHA-256 of the last certificate sent (`root_sha256`) and whether the OS
//! store holds it. For the run: where the OS roots came from (`trust_store`), and "no OS trust store
//! found" when there are none. A source named by `SSL_CERT_FILE` or `SSL_CERT_DIR` shows the variable and
//! the path with the home directory as `~`.
//!
//! **Rules (M1-100).** `expected_issuer` is a regex matched against the issuer of the leaf, written as
//! `CN=..., O=...`. `pin_sha256` lists SHA-256 digests of DER certificates: some certificate the server
//! sent must hash to one of them. A chain that breaks either rule blocks, whatever its class, and a chain
//! that meets it passes that rule. A host that was not tested is never read as meeting a rule. A host
//! behind a proxy is not tried (M1-097).
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
use rdy_engine::probe::{AttemptOutcome, NetFailure, NoRoots, ProbeError};
use rdy_spec::Target;
use rdy_spec::check::{CheckParams, NetEgress, NetTlsIntercept};
use rdy_spec::scalar::Host;
use rdy_spec::spec::Spec;
use serde_json::{Value, json};

use self::class::Class;
use self::evidence::{ChainEvidence, store_json};

mod class;
mod evidence;
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
    // Read only to show a trust store path from `SSL_CERT_FILE` or `SSL_CERT_DIR` with the home directory as
    // `~`. The values are never put in the report.
    env: &["HOME", "USERPROFILE"],
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
    rules: Rules,
}

/// The two rules a spec may set on a chain.
#[derive(Debug, Default)]
struct Rules {
    /// `expected_issuer`: the issuer of the leaf must match.
    issuer: Option<IssuerRule>,
    /// `pin_sha256`: some certificate of the chain must hash to one of these, as lowercase hex.
    pins: Vec<String>,
}

/// `expected_issuer`, compiled by the spec's own rules (size limits, linear time).
struct IssuerRule {
    pattern: String,
    matches: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl std::fmt::Debug for IssuerRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerRule")
            .field("pattern", &self.pattern)
            .finish_non_exhaustive()
    }
}

impl Rules {
    fn is_set(&self) -> bool {
        self.issuer.is_some() || !self.pins.is_empty()
    }
}

impl TlsInterceptCheck {
    /// The check for `params`, testing `hosts` (see [`hosts_for`]) and leaving `dropped` out.
    ///
    /// # Errors
    ///
    /// The reason, when `expected_issuer` does not compile under the spec's limits. Lint finds the same,
    /// so this happens only for a spec that skipped lint. The family refuses to build the entry.
    pub(crate) fn new(
        params: &NetTlsIntercept,
        hosts: Vec<Target>,
        dropped: usize,
    ) -> Result<Self, String> {
        let issuer = match &params.expected_issuer {
            Some(text) => {
                let compiled = rdy_spec::pattern::compile(text.as_str())?;
                Some(IssuerRule {
                    pattern: text.as_str().to_owned(),
                    matches: Box::new(move |issuer| compiled.is_match(issuer)),
                })
            }
            None => None,
        };
        let pins = params
            .pin_sha256
            .as_ref()
            .map(|pins| pins.iter().map(|p| p.as_str().to_owned()).collect())
            .unwrap_or_default();
        Ok(Self {
            hosts,
            dropped,
            forbid_interception: params.forbid_interception,
            rules: Rules { issuer, pins },
        })
    }
}

/// What one host came to.
#[derive(Debug)]
struct Tested {
    label: String,
    host: String,
    port: u16,
    what: What,
    /// Whether the last certificate of the chain is in the OS store. Known once the store was asked.
    in_store: Option<bool>,
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
    /// Why the OS store gave no roots, when it did not.
    no_roots: Option<NoRoots>,
    /// Who issued the chain and what it hashes to.
    evidence: ChainEvidence,
    /// Whether the issuer matches `expected_issuer`. `None` when the spec sets none.
    issuer_ok: Option<bool>,
    /// Whether a certificate of the chain matches `pin_sha256`. `None` when the spec sets none.
    pin_ok: Option<bool>,
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
            _ => "rejected_by_rustls_policy",
        },
        TrustVerdict::Unavailable(NoRoots::Empty) => "no_store",
        TrustVerdict::Unavailable(NoRoots::Unreadable) => "store_unreadable",
        TrustVerdict::Unavailable(NoRoots::Overridden) => "store_overridden",
        TrustVerdict::Unavailable(_) => "no_store",
        _ => "unknown",
    }
}

impl Seen {
    fn of(chain: &TlsChain, rules: &Rules) -> Self {
        let evidence = ChainEvidence::of(&chain.certs);
        let issuer_ok = rules
            .issuer
            .as_ref()
            .map(|rule| evidence.issuer_matches(&*rule.matches));
        let pin_ok = (!rules.pins.is_empty()).then(|| evidence.pinned(&rules.pins));
        Self {
            evidence,
            issuer_ok,
            pin_ok,
            depth: chain.certs.len(),
            bundled: verdict_id(chain.bundled),
            system: verdict_id(chain.system),
            system_roots: chain.system_roots,
            protocol: chain.protocol,
            no_roots: match chain.system {
                TrustVerdict::Unavailable(why) => Some(why),
                _ => None,
            },
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
                out["issuer"] = seen.evidence.shown_issuer().into();
                out["subject"] = seen.evidence.shown_subject().into();
                out["root_sha256"] = seen.evidence.root_sha256.clone().into();
                out["root_self_signed"] = seen.evidence.root_self_signed.into();
                out["root_in_os_store"] = self.in_store.into();
                if let Some(ok) = seen.issuer_ok {
                    out["expected_issuer_matches"] = ok.into();
                }
                if let Some(ok) = seen.pin_ok {
                    out["pin_sha256_matches"] = ok.into();
                }
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
        ProbeError::Timeout => TIMED_OUT,
        ProbeError::Net(failure) => match failure {
            NetFailure::Dns { .. } => "the name did not resolve",
            NetFailure::NotConnected {
                outcome: AttemptOutcome::TimedOut,
                ..
            } => CONNECT_TIMED_OUT,
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

async fn test_host(
    ctx: &CheckContext,
    target: &Target,
    rules: &Rules,
) -> Result<Tested, CheckError> {
    let host = target.host().to_string();
    let port = target.port();
    // `Host` prints an IPv6 literal in brackets already.
    let label = format!("{host}:{port}");
    let make = |what| Tested {
        label: label.clone(),
        host: host.clone(),
        port,
        what,
        in_store: None,
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
            seen: Seen::of(&chain, rules),
        },
        Some(Err(error)) => What::Untested(untested(error)?),
        None => What::Untested(TIMED_OUT),
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
                    Box::pin(test_host(ctx, target, &self.rules))
                })
                .collect();
            let done: Vec<Result<Tested, CheckError>> =
                stream::iter(pending).buffered(PARALLEL).collect().await;
            let mut done: Vec<Tested> = done.into_iter().collect::<Result<_, _>>()?;
            let store = trust_store_report(ctx, &mut done).await;
            Ok(self.judge(ctx.os(), &done, store))
        })
    }
}

impl TlsInterceptCheck {
    /// The finding for the hosts as tested.
    fn judge(&self, os: Os, done: &[Tested], store: Option<Value>) -> Finding {
        let forbid = self.forbid_interception;
        let verdicts: Vec<Verdict<'_>> = done.iter().filter_map(Verdict::of).collect();
        let untested: Vec<&Tested> = done
            .iter()
            .filter(|t| matches!(t.what, What::Untested(_)))
            .collect();
        let rank = |level: Level| match level {
            Level::Pass => 0,
            Level::Warn => 1,
            Level::Fail => 2,
        };
        let worst = verdicts
            .iter()
            .map(|v| v.level(forbid))
            .max_by_key(|level| rank(*level));
        let flagged: Vec<&Verdict<'_>> = verdicts.iter().filter(|v| v.flagged()).collect();

        let mut finding = match worst {
            // A check that tested nothing does not pass (03 gives no pass_by_absence for it).
            None if done.is_empty() => {
                Finding::warn("no host to test: set `hosts` or add a TLS `net.egress` endpoint")
            }
            // Nothing was learned. That is not a pass: nobody can say there is no interception.
            None => Finding::warn(format!(
                "no host could be tested ({} not tested); net.egress shows why",
                untested.len()
            )),
            Some(Level::Pass) => Finding::pass(format!(
                "{} of {} hosts present a chain the public roots validate{}",
                verdicts.len(),
                done.len(),
                self.rules.passed_words()
            )),
            Some(level) => {
                let mut parts: Vec<String> = flagged
                    .iter()
                    .take(NAMED)
                    .map(|v| format!("{} ({})", v.t.label, v.reasons().join(", ")))
                    .collect();
                if flagged.len() > NAMED {
                    parts.push(format!("and {} more", flagged.len() - NAMED));
                }
                Finding::new(level, parts.join("; "))
            }
        }
        .with_observed({
            let mut observed = json!({"hosts": done.iter().map(Tested::json).collect::<Vec<_>>()});
            if let Some(store) = store {
                observed["trust_store"] = store;
            }
            observed
        })
        .with_expected(self.rules.expected(forbid));

        // One fix per kind of problem, in host order, so the text stays short.
        let mut seen_fixes: Vec<&'static str> = Vec::new();
        let mut fixes: Vec<String> = Vec::new();
        for v in &flagged {
            let mut add = |key: &'static str, text: Option<String>| {
                if seen_fixes.contains(&key) || seen_fixes.len() >= FIXES {
                    return;
                }
                if let Some(text) = text {
                    seen_fixes.push(key);
                    fixes.push(text);
                }
            };
            if v.class != Class::Public {
                add(
                    v.class.id(),
                    v.class
                        .fix(os, &v.t.host, v.t.port, forbid, no_roots_of(v.t)),
                );
            }
            if v.issuer_ok == Some(false) {
                add("issuer_mismatch", Some(class::issuer_fix(&v.t.host)));
            }
            if v.pin_ok == Some(false) {
                add("pin_mismatch", Some(class::pin_fix(&v.t.host)));
            }
        }
        if !fixes.is_empty() {
            finding = finding.with_fix(fixes.join(" "));
        }

        // A system store that held no roots is a fact about the machine, said once.
        if let Some(why) = done.iter().find_map(no_roots_of) {
            finding = finding.with_note(format!(
                "{}: only the public roots could judge the chains",
                why.phrase()
            ));
        }
        // A step that ran out of time is named, so the report says plainly that a handshake hung.
        let hung: Vec<&Tested> = untested
            .iter()
            .copied()
            .filter(|t| matches!(t.what, What::Untested(why) if why == TIMED_OUT || why == CONNECT_TIMED_OUT))
            .collect();
        if !hung.is_empty() {
            let named: Vec<&str> = hung.iter().take(NAMED).map(|t| t.label.as_str()).collect();
            finding = finding.with_note(format!(
                "{} of {} hosts timed out: {}",
                hung.len(),
                done.len(),
                named.join(", ")
            ));
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
            let rules = if self.rules.is_set() {
                ", so expected_issuer and pin_sha256 were not checked for them"
            } else {
                ""
            };
            not_verified.push(format!(
                "{} of {} hosts were not tested{rules}: {}",
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
        if !not_verified.is_empty() {
            finding = finding.with_partial(Partial::new(Vec::new(), not_verified.join("; ")));
        }
        finding
    }
}

/// What one tested host came to, with its rules applied.
struct Verdict<'a> {
    t: &'a Tested,
    class: Class,
    issuer_ok: Option<bool>,
    pin_ok: Option<bool>,
}

impl<'a> Verdict<'a> {
    fn of(t: &'a Tested) -> Option<Self> {
        match &t.what {
            What::Chain { class, seen } => Some(Self {
                t,
                class: *class,
                issuer_ok: seen.issuer_ok,
                pin_ok: seen.pin_ok,
            }),
            What::Untested(_) => None,
        }
    }

    /// A rule the spec set that the chain does not meet. It blocks whatever the class says.
    fn broke_a_rule(&self) -> bool {
        self.issuer_ok == Some(false) || self.pin_ok == Some(false)
    }

    fn level(&self, forbid: bool) -> Level {
        if self.broke_a_rule() {
            Level::Fail
        } else {
            self.class.level(forbid)
        }
    }

    fn flagged(&self) -> bool {
        self.class != Class::Public || self.broke_a_rule()
    }

    /// The phrases for the message, after the host.
    fn reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.class != Class::Public {
            let phrase = self.class.phrase(no_roots_of(self.t));
            out.push(match (&self.t.what, self.class) {
                (What::Chain { seen, .. }, Class::MachineOnly | Class::UnknownCa) => {
                    match seen.evidence.shown_issuer() {
                        Some(issuer) => format!("{phrase}, issuer {issuer}"),
                        None => phrase.to_owned(),
                    }
                }
                _ => phrase.to_owned(),
            });
        }
        if self.issuer_ok == Some(false) {
            out.push("issuer does not match expected_issuer".to_owned());
        }
        if self.pin_ok == Some(false) {
            out.push("no certificate matches pin_sha256".to_owned());
        }
        out
    }
}

impl Rules {
    /// What the finding says it expected: the interception rule, and the two rules when set.
    fn expected(&self, forbid: bool) -> Value {
        let mut out = json!({"forbid_interception": forbid});
        if let Some(rule) = &self.issuer {
            out["expected_issuer"] = rule.pattern.clone().into();
        }
        if !self.pins.is_empty() {
            out["pin_sha256"] = self.pins.clone().into();
        }
        out
    }

    /// The end of a pass message when the spec set rules and every chain met them.
    fn passed_words(&self) -> &'static str {
        match (self.issuer.is_some(), !self.pins.is_empty()) {
            (true, true) => "; the issuer and the pin match",
            (true, false) => "; the issuer matches",
            (false, true) => "; the pin matches",
            (false, false) => "",
        }
    }
}

/// The words for a step that ran out of time.
const TIMED_OUT: &str = "a step ran out of time";

/// The words for a connection that nobody answered: no refusal, no reply, until the attempt was cut.
const CONNECT_TIMED_OUT: &str = "the connection timed out";

/// The trust store section of the report, once per run, and `in_store` for each chain.
///
/// The store is asked only when a chain was had: a run that reached no host has nothing to put beside
/// the store. A failure to read it is data (`not_read`), never an error of the check. `HOME` and
/// `USERPROFILE` are read so a path from `SSL_CERT_FILE` or `SSL_CERT_DIR` shows `~` and not a user name.
async fn trust_store_report(ctx: &CheckContext, done: &mut [Tested]) -> Option<Value> {
    if !done.iter().any(|t| matches!(t.what, What::Chain { .. })) {
        return None;
    }
    let answer = ctx.probe().trust_store().await;
    let homes: Vec<String> = ["HOME", "USERPROFILE"]
        .into_iter()
        .filter_map(|name| ctx.probe().env(name).ok().flatten())
        .collect();
    if let Ok(store) = &answer {
        for t in done.iter_mut() {
            if let What::Chain { seen, .. } = &t.what {
                t.in_store = seen
                    .evidence
                    .root_hash
                    .map(|hash| store.missing.is_none() && store.contains(&hash));
            }
        }
    }
    Some(store_json(&answer, &homes))
}

/// Why the OS store gave no roots for this host's chain, when it did not.
fn no_roots_of(t: &Tested) -> Option<NoRoots> {
    match &t.what {
        What::Chain { seen, .. } => seen.no_roots,
        What::Untested(_) => None,
    }
}
