//! The verdict of `net.dns`: from what each name gave to one finding. Pure, so the tests feed it facts.

use std::net::IpAddr;
use std::time::Duration;

use rdy_engine::check::{Finding, Os, Partial};
use rdy_spec::check::Cidr;
use serde_json::{Value, json};

use rdy_engine::probe::is_unusable_peer;

use super::direct::NsResult;
use super::parse::{self, Resolver};
use super::split::{self, Machine};
use super::{NOT_INSTALLED, PER_NAME};
use crate::text::code;

/// The most names the message spells out before it says "and N more".
const NAMED: usize = 5;

/// The per-name budget in seconds, for the text.
const PER_NAME_SECS: u64 = PER_NAME.as_secs();

/// The most distinct fixes the finding carries.
const FIXES: usize = 3;

/// The most addresses of one name shown in the evidence.
const SHOWN: usize = 16;

/// What the spec asked for one name.
#[derive(Debug, Clone)]
pub(super) struct Rule {
    pub(super) name: String,
    pub(super) expect_in: Vec<Cidr>,
    pub(super) expect_public: Option<bool>,
}

/// Where an answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
    /// `getent ahosts` (Linux).
    Getent,
    /// The facade's `getaddrinfo` lookup, which is the system answer on macOS and Windows.
    System,
    /// The facade's lookup, standing in for an unusable `getent` on Linux.
    Fallback,
}

impl Source {
    fn id(self) -> &'static str {
        match self {
            Self::Getent => "getent",
            Self::System => "getaddrinfo",
            Self::Fallback => "rdy_resolver",
        }
    }
}

/// What one lookup came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Answer {
    /// At least one address, without repeats.
    Found(Vec<IpAddr>),
    /// The resolver said no such name, or no nameserver answered before it gave up.
    NotFound,
    /// The lookup was stopped on its time limit.
    Timeout,
    /// The name points at an address rdy will not contact, so the facade gave no answer.
    Refused,
    /// The lookup failed in another way. The text says how.
    Failed(String),
    /// The name was not sent to the resolver. The text says why.
    Rejected(&'static str),
    /// The check ran out of time before this name.
    NotTried,
}

/// One name as it was looked up.
#[derive(Debug, Clone)]
pub(super) struct Looked {
    pub(super) name: String,
    pub(super) source: Source,
    pub(super) answer: Answer,
    pub(super) took: Duration,
    /// Why the fallback was used, on Linux.
    pub(super) fallback: Option<String>,
    /// What each nameserver of the OS list said, in list order. Empty when none was asked.
    pub(super) direct: Vec<NsResult>,
}

impl Looked {
    pub(super) fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            source: Source::Getent,
            answer: Answer::NotTried,
            took: Duration::ZERO,
            fallback: None,
            direct: Vec::new(),
        }
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Why a name is not fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Problem {
    NotFound,
    Timeout,
    Refused,
    Failed,
    Rejected,
}

impl Problem {
    fn words(self) -> &'static str {
        match self {
            Self::NotFound => "not found",
            Self::Timeout => "timed out",
            Self::Refused => "answer in a refused range",
            Self::Failed => "lookup failed",
            Self::Rejected => "not a valid name",
        }
    }
}

/// The zone to ask the DNS team about: the name without its first label, or the name itself.
fn zone_of(name: &str) -> &str {
    name.split_once('.')
        .map_or(name, |(_, rest)| rest)
        .trim_matches('.')
}

pub(super) fn fix_for(os: Os, problem: Problem, name: &str, resolver: Option<Resolver>) -> String {
    let zone = zone_of(name);
    let hosts = match os {
        Os::Windows => "`%SystemRoot%\\System32\\drivers\\etc\\hosts`",
        _ => "`/etc/hosts`",
    };
    match problem {
        Problem::NotFound => {
            let linux = if os == Os::Linux {
                " Check that the `hosts:` line of `/etc/nsswitch.conf` lists `dns`."
            } else {
                ""
            };
            format!(
                "{} does not resolve on this machine: the system resolver found no record, or no nameserver answered. Ask the DNS team for a record or a conditional forwarder for {}.{linux} As a stopgap add a line to {hosts}.",
                code(name),
                code(zone)
            )
        }
        Problem::Timeout => {
            let waits = resolver.map_or_else(String::new, |r| {
                format!(
                    " This machine waits up to about {} s ({} s, {} attempts, {} nameservers).",
                    r.worst_case(),
                    r.timeout,
                    r.attempts,
                    r.nameservers.max(1)
                )
            });
            let place = if os == Os::Linux {
                "the `nameserver` lines of `/etc/resolv.conf`"
            } else {
                "the DNS servers in this machine's network settings"
            };
            format!(
                "No nameserver answered for {} in time. Check {place}: a dead first nameserver adds its timeout to every lookup. Ask the network team to allow udp/53 and tcp/53 from this machine to them.{waits}",
                code(name)
            )
        }
        Problem::Refused => format!(
            "{} resolves to a link-local, metadata, unspecified, multicast or broadcast address, which rdy will not contact. Ask the DNS team to point it at the real address, or add a line to {hosts}.",
            code(name)
        ),
        Problem::Failed => format!(
            "rdy could not look up {}. Run again, and if it repeats check the DNS settings of this machine.",
            code(name)
        ),
        Problem::Rejected => format!(
            "{} is not a name rdy will look up. Use letters, digits, dots, underscores and hyphens, with no leading hyphen, in the spec.",
            code(name)
        ),
    }
}

/// The fix for a name that was not found: the generic one, with the nameservers that said NXDOMAIN named
/// by position when direct answers exist ("nameserver 2 answered NXDOMAIN").
fn not_found_fix(os: Os, l: &Looked, resolver: Option<Resolver>) -> String {
    let generic = fix_for(os, Problem::NotFound, &l.name, resolver);
    let nx = split::nxdomain_positions(l);
    if nx.is_empty() {
        return generic;
    }
    let who: Vec<String> = nx.iter().map(ToString::to_string).collect();
    let plural = if nx.len() == 1 {
        "nameserver"
    } else {
        "nameservers"
    };
    format!(
        "{} does not resolve: {plural} {} answered NXDOMAIN. Ask the DNS team for a conditional forwarder for {}, or add a temporary line to `/etc/hosts`.",
        code(&l.name),
        who.join(", "),
        code(zone_of(&l.name))
    )
}

/// The ranges an answer must be in, written for a message.
fn ranges(list: &[Cidr]) -> String {
    list.iter()
        .map(|c| format!("{}/{}", c.addr(), c.prefix()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Why `addrs` do not meet `rule`, or `None` when they do.
fn outside(rule: &Rule, addrs: &[IpAddr]) -> Option<String> {
    if !rule.expect_in.is_empty()
        && let Some(bad) = addrs
            .iter()
            .find(|ip| !rule.expect_in.iter().any(|r| parse::in_range(**ip, *r)))
    {
        return Some(format!("{} is outside {}", bad, ranges(&rule.expect_in)));
    }
    match rule.expect_public {
        Some(true) => addrs
            .iter()
            .find(|ip| parse::is_private(**ip))
            .map(|ip| format!("{ip} is a private address and the spec expects a public one")),
        Some(false) => addrs
            .iter()
            .find(|ip| !parse::is_private(**ip))
            .map(|ip| format!("{ip} is a public address and the spec expects a private one")),
        None => None,
    }
}

/// `a, b (and N more)` for up to [`NAMED`] items.
fn listed(items: &[String]) -> String {
    let mut shown: Vec<String> = items.iter().take(NAMED).cloned().collect();
    if items.len() > NAMED {
        shown.push(format!("and {} more", items.len() - NAMED));
    }
    shown.join(", ")
}

/// The finding for the names as looked up. `rules` and `looked` are in the same order.
pub(super) fn judge(
    os: Os,
    rules: &[Rule],
    looked: &[Looked],
    max_latency: Duration,
    resolver: Option<Resolver>,
    machine: &Machine,
) -> Finding {
    let mut broken: Vec<(&Looked, Problem)> = Vec::new();
    let mut misplaced: Vec<(&Looked, String)> = Vec::new();
    let mut slow: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut not_tried = 0_usize;

    for (rule, l) in rules.iter().zip(looked) {
        if let Some(why) = &l.fallback {
            let note = fallback_note(why);
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
        match &l.answer {
            Answer::Found(addrs) => {
                // Both paths give one verdict: an answer in a range rdy will not contact blocks, whether
                // getent or the facade resolver gave it. The addresses stay in the evidence.
                if refused(addrs) {
                    broken.push((l, Problem::Refused));
                } else if let Some(why) = outside(rule, addrs) {
                    misplaced.push((l, why));
                }
                if l.took > max_latency {
                    slow.push(format!(
                        "{} took {} ms to resolve, above {} ms",
                        code(&l.name),
                        ms(l.took),
                        ms(max_latency)
                    ));
                }
                if addrs.iter().all(IpAddr::is_ipv6) {
                    notes.push(format!(
                        "{} has only IPv6 (AAAA) answers. A client without IPv6 cannot reach it.",
                        code(&l.name)
                    ));
                }
            }
            Answer::NotFound => broken.push((l, Problem::NotFound)),
            Answer::Timeout => broken.push((l, Problem::Timeout)),
            Answer::Refused => broken.push((l, Problem::Refused)),
            Answer::Failed(why) => {
                notes.push(format!("{}: {why}", code(&l.name)));
                broken.push((l, Problem::Failed));
            }
            Answer::Rejected(why) => {
                notes.push(format!("{} was not looked up: {why}.", code(&l.name)));
                broken.push((l, Problem::Rejected));
            }
            Answer::NotTried => not_tried += 1,
        }
    }

    let found = split::assess(rules, looked, machine, max_latency);
    slow.extend(found.warns.iter().cloned());
    notes.extend(found.notes.iter().cloned());

    let total = looked.len();
    let tried = total - not_tried;
    let mut finding = if broken.is_empty() && misplaced.is_empty() && slow.is_empty() {
        if tried == 0 {
            Finding::pass("no name was looked up")
        } else {
            Finding::pass(format!("{tried} of {total} names resolve"))
        }
    } else if broken.is_empty() && misplaced.is_empty() {
        Finding::warn(slow.join("; "))
    } else {
        let mut parts: Vec<String> = Vec::new();
        if !broken.is_empty() {
            let named: Vec<String> = broken
                .iter()
                .map(|(l, p)| format!("{} ({})", code(&l.name), p.words()))
                .collect();
            parts.push(format!(
                "{} of {total} names do not resolve: {}",
                broken.len(),
                listed(&named)
            ));
        }
        if !misplaced.is_empty() {
            let named: Vec<String> = misplaced
                .iter()
                .map(|(l, why)| format!("{} ({why})", code(&l.name)))
                .collect();
            parts.push(format!(
                "{} of {total} names resolve to an address the spec does not expect: {}",
                misplaced.len(),
                listed(&named)
            ));
        }
        Finding::fail(parts.join("; "))
    };

    finding = finding
        .with_observed(observed(looked, resolver, machine))
        .with_expected(expected(rules, max_latency));

    let mut fixes: Vec<String> = Vec::new();
    let mut seen: Vec<Problem> = Vec::new();
    for (l, problem) in &broken {
        if seen.contains(problem) || seen.len() >= FIXES {
            continue;
        }
        seen.push(*problem);
        fixes.push(match problem {
            Problem::NotFound => not_found_fix(os, l, resolver),
            _ => fix_for(os, *problem, &l.name, resolver),
        });
    }
    if let Some((l, why)) = misplaced.first() {
        fixes.push(format!(
            "{} resolves to an address the spec does not expect ({why}). That is usually the wrong resolver or a split-horizon zone: check the nameservers this machine uses, and ask the DNS team which view should answer for {}.",
            code(&l.name),
            code(zone_of(&l.name))
        ));
    }
    for fix in &found.fixes {
        if !fixes.contains(fix) {
            fixes.push(fix.clone());
        }
    }
    if !fixes.is_empty() {
        finding = finding.with_fix(fixes.join(" "));
    }
    for (_, text) in timeout_notes(&broken, resolver) {
        notes.push(text);
    }
    for warn in slow {
        finding = finding.with_note(warn);
    }
    for note in notes {
        finding = finding.with_note(note);
    }
    let mut partial: Vec<String> = Vec::new();
    if not_tried > 0 {
        partial.push(format!(
            "{not_tried} of {total} names were not looked up: the check ran out of time before it reached them"
        ));
    }
    for pos in &found.skipped {
        partial.push(format!(
            "nameserver {pos} was not queried directly: nameserver in a refused range"
        ));
    }
    if !partial.is_empty() {
        finding = finding.with_partial(Partial::new(Vec::new(), partial.join("; ")));
    }
    finding
}

/// Whether any answer is in a range rdy will not contact (the facade's own address rule).
fn refused(addrs: &[IpAddr]) -> bool {
    addrs.iter().any(|ip| is_unusable_peer(*ip))
}

/// Per-source timeout notes. Each starts with the names that timed out, so a reader and the harness
/// both see which names. A `getent` timeout carries the resolver's own wait. Other sources say the
/// lookup used its time budget: [`PER_NAME_SECS`] for one name, or what the check had left.
fn timeout_notes(
    broken: &[(&Looked, Problem)],
    resolver: Option<Resolver>,
) -> Vec<(Source, String)> {
    let mut out = Vec::new();
    for source in [Source::Getent, Source::System, Source::Fallback] {
        let names: Vec<String> = broken
            .iter()
            .filter(|(l, p)| *p == Problem::Timeout && l.source == source)
            .map(|(l, _)| code(&l.name))
            .collect();
        if names.is_empty() {
            continue;
        }
        let lead = format!("{} timed out", listed(&names));
        let text = match (source, resolver) {
            (Source::Getent, Some(r)) => format!(
                "{lead}: getent is stopped after 5 s. This machine's resolver is set to wait {} s per nameserver, {} attempts, {} nameservers (options timeout and attempts in /etc/resolv.conf), so it can wait up to about {} s.",
                r.timeout,
                r.attempts,
                r.nameservers.max(1),
                r.worst_case()
            ),
            (Source::Getent, None) => format!("{lead}: getent is stopped after 5 s."),
            _ => format!(
                "{lead}: the lookup used its time budget ({PER_NAME_SECS} s for one name, or the time the check had left)."
            ),
        };
        out.push((source, text));
    }
    out
}

/// The one note for a Linux machine whose `getent` did not answer.
fn fallback_note(why: &str) -> String {
    let lead = if why == NOT_INSTALLED {
        "getent is not installed on this machine".to_owned()
    } else {
        why.to_owned()
    };
    format!(
        "{lead}, so rdy asked its own resolver. That resolver does not follow nsswitch.conf (mDNS, sssd), so a name served that way can differ from what the product sees."
    )
}

fn observed(looked: &[Looked], resolver: Option<Resolver>, machine: &Machine) -> Value {
    let names: Vec<Value> = looked.iter().map(name_json).collect();
    let mut out = json!({ "names": names });
    if let Some(direct) = split::machine_json(machine) {
        out["direct"] = direct;
    }
    if let Some(r) = resolver {
        out["resolver"] = json!({
            "timeout_s": r.timeout,
            "attempts": r.attempts,
            "nameservers": r.nameservers,
            "worst_case_s": r.worst_case(),
        });
    }
    out
}

fn name_json(l: &Looked) -> Value {
    let mut out = json!({ "name": l.name, "source": l.source.id(), "ms": ms(l.took) });
    match &l.answer {
        Answer::Found(addrs) => {
            let v6 = addrs.iter().filter(|a| a.is_ipv6()).count();
            out["result"] = json!(if refused(addrs) {
                "refused_by_policy"
            } else {
                "found"
            });
            out["ipv4"] = json!(addrs.len() - v6);
            out["ipv6"] = json!(v6);
            out["addresses"] = json!(
                addrs
                    .iter()
                    .take(SHOWN)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
            out["addresses_total"] = json!(addrs.len());
        }
        Answer::NotFound => out["result"] = json!("not_found"),
        Answer::Timeout => out["result"] = json!("timeout"),
        Answer::Refused => out["result"] = json!("refused_by_policy"),
        Answer::Failed(_) => out["result"] = json!("failed"),
        Answer::Rejected(_) => out["result"] = json!("rejected"),
        Answer::NotTried => out["result"] = json!("not_tried"),
    }
    if let Some(why) = &l.fallback {
        out["fallback"] = json!(why);
    }
    if !l.direct.is_empty() {
        out["nameservers"] = split::ns_json(&l.direct);
    }
    out
}

fn expected(rules: &[Rule], max_latency: Duration) -> Value {
    let wants: Vec<Value> = rules
        .iter()
        .filter(|r| !r.expect_in.is_empty() || r.expect_public.is_some())
        .map(|r| {
            json!({
                "name": r.name,
                "expect_in": r.expect_in.iter().map(|c| format!("{}/{}", c.addr(), c.prefix())).collect::<Vec<_>>(),
                "expect_public": r.expect_public,
            })
        })
        .collect();
    json!({ "max_latency_ms": ms(max_latency), "names": wants })
}
