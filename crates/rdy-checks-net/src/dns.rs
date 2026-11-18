//! `net.dns`: do the required names resolve the way this machine's own software would resolve them
//! (03 section 3, M1-153).
//!
//! The **system answer** is M1-153. The **direct lookups** are M1-155: on Linux each name is also asked of
//! each nameserver of the OS list (`direct`, `wire`), the answers are compared with the system answer
//! (`split`: split horizon, a slow or dead first nameserver, NXDOMAIN), and `/etc/nsswitch.conf` and
//! `/etc/resolv.conf` are read for the `sss`, mDNS, stub and missing-`dns` findings. A nameserver is named by
//! its position in the list and never by address (INV-11, ADR 0051). A nameserver in a refused range (the
//! GCE metadata address) is skipped with the facade's words, "nameserver in a refused range", and the
//! system answer is still reported. macOS and Windows have no nameserver source yet (M2-010).
//!
//! **Source.** On Linux the answer is `/usr/bin/getent ahosts -- <name>` through the probe facade's
//! `exec`, because glibc-linked products resolve through `nsswitch.conf` (mDNS, sssd, `/etc/hosts`
//! order) and rdy's own static binary does not. The command is on the exec allow-list by the command
//! table only (`exit 0` found, `2` not found, anything else a tool error). The name is validated before
//! it is put in the argument list, and the table validates it again.
//!
//! **Fallback.** When `getent` is not installed (scratch containers, Alpine) or fails in a way that is
//! not "not found", the facade's own `lookup` answers instead, and the evidence and a note say so: that
//! resolver does not follow `nsswitch.conf`, so an mDNS or sssd name can differ from what the product
//! sees. On macOS and Windows the facade `lookup` (`getaddrinfo`) is the system answer and is not a
//! fallback.
//!
//! **Timeout.** `getent` is stopped after 5 s. The resolver can legitimately wait longer
//! (`options timeout:` times `attempts:` times the nameservers), so a stopped lookup is a `timeout`
//! result with those values in the evidence, read from `/etc/resolv.conf`.
//!
//! **Levels.** A name that does not resolve, times out or fails: block. An answer outside the spec's
//! `expect_in` ranges, or public when `expect_public` is false and the reverse: block. A lookup slower
//! than `max_latency` (500 ms by default): warn.
//!
//! **Needs.** `Need::Network`. Under `--no-network` the check is skipped as `missing_need(network)` and
//! no command runs and no lookup is sent (the table marks `getent` as a network command, and the facade
//! refuses a lookup). The peer class is `SpecHosts`: the check may look up only the names its own spec
//! entry lists (INV-11). `getent` is a lookup, not a connection, so an answer in a refused range is
//! shown in the evidence and nothing connects to it. The facade fallback refuses such an answer and the
//! result says "refused".
//!
//! **Privilege.** None.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, CommandSpec,
    Need, Os, OsSupport, PeerClass, Support,
};
use rdy_engine::exec::policy::PolicyError;
use rdy_engine::exec::table::{self, ExitClass};
use rdy_engine::family::HostSet;
use rdy_engine::probe::net::RULE_TCP_ADDRESS;
use rdy_engine::probe::{NetFailure, ProbeError};
use rdy_spec::Target;
use rdy_spec::check::{Cidr, NetDns};

use self::judge::Rule;
use crate::text::{short, soft};

mod direct;
#[cfg(test)]
mod direct_tests;
mod judge;
mod parse;
mod split;
#[cfg(test)]
mod tests;
mod wire;

/// How many names are looked up at once.
const PARALLEL: usize = 8;

/// A lookup slower than this warns, when the spec sets no `max_latency`.
const DEFAULT_MAX_LATENCY: Duration = Duration::from_millis(500);

/// The most time one name takes: `getent` (5 s) and, if it is unusable, the facade lookup (3 s).
const PER_NAME: Duration = Duration::from_secs(9);

/// Time of the check that is never spent on names, so the result can be written.
const RESERVE: Duration = Duration::from_secs(2);

/// Below this much time left a name that has not started is not tried.
const MIN_TO_START: Duration = Duration::from_secs(1);

/// The port written into the host set. The facade's lookup admits a spec host at any port, and this
/// check never connects, so the number carries no meaning.
const HOST_SET_PORT: u16 = 443;

/// The most time the direct lookups of one name take (three nameservers at 3 s, and a second question).
const DIRECT_PER_NAME: Duration = Duration::from_secs(10);

const RESOLV_CONF: &str = "/etc/resolv.conf";
const NSSWITCH_CONF: &str = "/etc/nsswitch.conf";

/// The static facts about `net.dns` (03 section 3).
///
/// The `resolv.conf` read is for the evidence of a timeout and the stub and count notes; `nsswitch.conf` is for the `hosts:` findings. `/etc/resolv.conf` is often a link to
/// one of the two `systemd-resolved` files, and the read policy judges the real path too.
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "net.dns",
    family: "net",
    summary: "Each required name resolves through the system resolver, within the expected ranges",
    meta: CheckMeta {
        title: "DNS",
        remediation: "Ask the DNS team for a record, or a conditional forwarder for the zone, so the name resolves from this machine. Check the nameservers in `/etc/resolv.conf` (a dead first nameserver adds its timeout to every lookup) and that the `hosts:` line of `/etc/nsswitch.conf` lists `dns`. As a stopgap add a line to `/etc/hosts`. Containers and Java may use a different resolver from the host.",
    },
    needs: &[Need::Network],
    wants: &[],
    default_timeout: Some(Duration::from_secs(60)),
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::Full,
    },
    reads: &[
        RESOLV_CONF,
        "/run/systemd/resolve/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
        NSSWITCH_CONF,
    ],
    statfs: &[],
    env: &[],
    commands: &[CommandSpec {
        program: "getent",
        extra_dirs: &[],
        max_stdout: 64 * 1024,
        env: &[],
    }],
    // `SpecHosts`: the names the check looks up and asks of each nameserver are its own. `SystemResolver`:
    // the nameserver list is the facade's, read by index (M1-155, ADR 0051).
    peers: &[PeerClass::SpecHosts, PeerClass::SystemResolver],
};

/// `net.dns`, built from its spec entry.
#[derive(Debug, Clone)]
pub struct DnsCheck {
    rules: Vec<Rule>,
    max_latency: Duration,
}

impl DnsCheck {
    /// The check for these spec parameters.
    #[must_use]
    pub fn from_params(params: &NetDns) -> Self {
        let rules = params
            .names
            .iter()
            .map(|rule| Rule {
                name: rule.name.as_str().to_ascii_lowercase(),
                expect_in: rule
                    .expect_in
                    .iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<Cidr>>(),
                expect_public: rule.expect_public,
            })
            .collect();
        Self {
            rules,
            max_latency: params
                .max_latency
                .as_ref()
                .map_or(DEFAULT_MAX_LATENCY, |d| d.to_std()),
        }
    }

    /// The names this check may look up, as the host set the scheduler gives its probe (INV-11).
    #[must_use]
    pub fn hosts(&self) -> HostSet {
        HostSet::new(
            self.rules
                .iter()
                .filter_map(|rule| Target::parse(&format!("{}:{HOST_SET_PORT}", rule.name)).ok()),
        )
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for DnsCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            if !ctx.has(&Need::Network) {
                return Err(CheckError::MissingNeed(Need::Network));
            }
            let linux = ctx.os() == Os::Linux;
            let resolv = if linux {
                read_text(ctx, RESOLV_CONF).await?
            } else {
                None
            };
            let mut machine = split::Machine::default();
            if linux {
                machine.hosts = read_text(ctx, NSSWITCH_CONF)
                    .await?
                    .and_then(|t| parse::nsswitch_hosts(&t));
                machine.facts = resolv.as_deref().map(parse::resolv_facts);
                match nameserver_count(ctx).await? {
                    Ok(n) => machine.asked = n,
                    Err(why) => machine.list_problem = Some(why),
                }
                if machine.asked == 0 && machine.list_problem.is_none() && resolv.is_some() {
                    machine.list_problem =
                        Some("/etc/resolv.conf has no nameserver line".to_owned());
                }
            }
            let asked = machine.asked;
            // Built first and boxed, so the stream does not borrow through a closure (as in net.egress).
            let pending: Vec<BoxFuture<'a, Result<judge::Looked, CheckError>>> = self
                .rules
                .iter()
                .map(|rule| -> BoxFuture<'a, Result<judge::Looked, CheckError>> {
                    Box::pin(look_up(ctx, &rule.name, asked))
                })
                .collect();
            let looked: Vec<Result<judge::Looked, CheckError>> =
                stream::iter(pending).buffered(PARALLEL).collect().await;
            let looked: Vec<judge::Looked> = looked.into_iter().collect::<Result<_, _>>()?;
            let resolver = if linux && looked.iter().any(|l| l.answer == judge::Answer::Timeout) {
                resolv.as_deref().map(parse::resolver)
            } else {
                None
            };
            Ok(judge::judge(
                ctx.os(),
                &self.rules,
                &looked,
                self.max_latency,
                resolver,
                &machine,
            ))
        })
    }
}

/// A text file of the resolver setup, or `None` when it is missing or the read policy refuses it (a link to
/// somewhere not declared). The bytes are read lossily and only the first 64 KiB.
async fn read_text(ctx: &CheckContext, path: &str) -> Result<Option<String>, CheckError> {
    match ctx.probe().read(Path::new(path)).await {
        Ok(file) => Ok(Some(String::from_utf8_lossy(&file.bytes).into_owned())),
        Err(ProbeError::Denied { .. } | ProbeError::NotFound | ProbeError::PermissionDenied) => {
            Ok(None)
        }
        Err(error) => soft(error).map(|_| None),
    }
}

/// How many nameservers the facade lists. The inner `Err` is why there is no list, for a note.
async fn nameserver_count(ctx: &CheckContext) -> Result<Result<usize, String>, CheckError> {
    match ctx.probe().nameserver_count().await {
        Ok(n) => Ok(Ok(n)),
        Err(error) if error.is_no_network() => Err(CheckError::MissingNeed(Need::Network)),
        // The list file is missing, is a link to a place rdy may not read, or this OS has no source yet.
        // No `/etc/resolv.conf` at all: there is nothing to ask and nothing to report.
        Err(ProbeError::NotFound) => Ok(Ok(0)),
        Err(
            ProbeError::PermissionDenied | ProbeError::Denied { .. } | ProbeError::Unsupported(_),
        ) => Ok(Err(
            "rdy cannot read the nameserver list on this machine".to_owned()
        )),
        Err(error) => soft(error).map(|e| Err(short(&e))),
    }
}

/// One name, by the source this OS has, inside its own time budget.
async fn look_up(
    ctx: &CheckContext,
    name: &str,
    asked: usize,
) -> Result<judge::Looked, CheckError> {
    let mut out = judge::Looked::new(name);
    if let Err(why) = parse::validate(name) {
        out.answer = judge::Answer::Rejected(why);
        return Ok(out);
    }
    let left = ctx.remaining();
    if left < RESERVE + MIN_TO_START {
        out.answer = judge::Answer::NotTried;
        return Ok(out);
    }
    let budget = PER_NAME.min(left.saturating_sub(RESERVE));
    let before = ctx.remaining();
    match ctx.within(budget, resolve(ctx, name, &mut out)).await {
        Some(done) => done?,
        // The stage that was running is the one that ran out.
        None => out.answer = judge::Answer::Timeout,
    }
    out.took = before.saturating_sub(ctx.remaining());
    if asked > 0 {
        let left = ctx.remaining().saturating_sub(RESERVE);
        let want_v6 =
            matches!(&out.answer, judge::Answer::Found(a) if a.iter().any(IpAddr::is_ipv6));
        out.direct = direct::ask_all(ctx, name, asked, want_v6, DIRECT_PER_NAME.min(left)).await?;
    }
    Ok(out)
}

async fn resolve(
    ctx: &CheckContext,
    name: &str,
    out: &mut judge::Looked,
) -> Result<(), CheckError> {
    if ctx.os() == Os::Linux {
        match getent(ctx, name).await? {
            Ran::Answer(answer) => {
                out.source = judge::Source::Getent;
                out.answer = answer;
                return Ok(());
            }
            Ran::Unusable(why) => {
                out.source = judge::Source::Fallback;
                out.fallback = Some(why);
            }
        }
    } else {
        out.source = judge::Source::System;
    }
    out.answer = facade(ctx, name).await?;
    Ok(())
}

/// What running `getent` gave.
enum Ran {
    /// A usable answer: addresses, not found, or stopped on the time limit.
    Answer(judge::Answer),
    /// `getent` is not installed or did not give a usable answer. The text says why.
    Unusable(String),
}

async fn getent(ctx: &CheckContext, name: &str) -> Result<Ran, CheckError> {
    let failed = || CheckError::Failed {
        message: "getent is not in rdy's command table".to_owned(),
        hint: "Tell the vendor which rdy version this is.".to_owned(),
    };
    let entry = table::entry("getent").ok_or_else(failed)?;
    // The form has its own limit (5 s). `at_most` only lowers it, to the time the check has left.
    let cmd = entry
        .cmd_for(ctx.os(), "ahosts", &[name])
        .map_err(|e| CheckError::Probe(ProbeError::Table(e)))?
        .at_most(ctx.remaining().saturating_sub(RESERVE));
    let out = match ctx.probe().exec(cmd).await {
        Ok(out) => out,
        Err(error) => {
            // The live runner reports a program that is not on the search path as a policy `NotFound`.
            if matches!(error, ProbeError::Policy(PolicyError::NotFound { .. })) {
                return Ok(Ran::Unusable(NOT_INSTALLED.to_owned()));
            }
            if error.is_no_network() {
                return Err(CheckError::MissingNeed(Need::Network));
            }
            return match soft(error)? {
                ProbeError::NotFound => Ok(Ran::Unusable(NOT_INSTALLED.to_owned())),
                ProbeError::Timeout => Ok(Ran::Answer(judge::Answer::Timeout)),
                other => Ok(Ran::Unusable(format!("getent failed: {}", short(&other)))),
            };
        }
    };
    let Some(code) = out.exit else {
        return Ok(Ran::Unusable("getent was ended by a signal".to_owned()));
    };
    Ok(match entry.form("ahosts").and_then(|f| f.classify(code)) {
        Some(ExitClass::Ok) => {
            let found: Vec<IpAddr> = parse::addresses(&String::from_utf8_lossy(&out.stdout));
            if found.is_empty() {
                Ran::Unusable("getent printed no address".to_owned())
            } else {
                Ran::Answer(judge::Answer::Found(found))
            }
        }
        Some(ExitClass::NotFound) => Ran::Answer(judge::Answer::NotFound),
        _ => Ran::Unusable(format!("getent exited with code {code}")),
    })
}

/// Why the facade resolver stood in for `getent`.
pub(crate) const NOT_INSTALLED: &str = "getent is not installed";

/// The facade's own lookup of a spec name.
async fn facade(ctx: &CheckContext, name: &str) -> Result<judge::Answer, CheckError> {
    Ok(match ctx.probe().lookup(name).await {
        Ok(ips) => judge::Answer::Found(ips),
        Err(error) if error.is_no_network() => return Err(CheckError::MissingNeed(Need::Network)),
        Err(ProbeError::Net(NetFailure::Dns { .. })) => judge::Answer::NotFound,
        Err(ProbeError::Timeout) => judge::Answer::Timeout,
        // The facade refuses a name that points at a link-local, metadata or other refused address.
        Err(ProbeError::Denied { rule, .. }) if rule == RULE_TCP_ADDRESS => judge::Answer::Refused,
        // Any other refusal is a mistake in this check's manifest or in the host set, not the network.
        Err(other) => match soft(other)? {
            ProbeError::NotFound => judge::Answer::NotFound,
            other => judge::Answer::Failed(short(&other)),
        },
    })
}
