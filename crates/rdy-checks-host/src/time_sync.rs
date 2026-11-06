//! `host.time_sync`: is the clock synchronized, and how far is it from a reference.
//!
//! Linux only in M1. Three sources, all read-only, asked one after the other with SNTP first and each
//! cut to the time left in the check budget:
//!
//! - `timedatectl show` (systemd 239 and later), else `timedatectl status`, for the sync flag;
//! - `chronyc -n -c tracking`, for chrony's state and its own offset;
//! - an SNTP exchange with each server in the spec's `ntp_servers`, for an offset measured by rdy.
//!
//! There are no default servers: offline first means no surprise traffic. With no `ntp_servers` rdy sends
//! no datagram and the result says the offset was not measured. A server can only be reached through
//! `Probe::udp_exchange`, which allows the check's own spec hosts and refuses link-local, metadata,
//! unspecified, multicast and broadcast addresses. A server in such a range (the Amazon time address
//! `169.254.169.123`, `fd00:ec2::123`) is reported as "offset not measured, server in a refused range",
//! and the offset from `chronyc` is used instead when chrony runs.
//!
//! The kernel's own flags (`adjtimex`) are not read: the closed `NativeCall` list has no such variant
//! and the Linux sync flag comes from `timedatectl`. That source is M2-004.
//!
//! The judgement is a pure function of what the sources gave (`judge`). The SNTP packet work is pure
//! too (`sntp`). The check only runs the sources and collects the facts.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, CommandSpec,
    Os, PeerClass,
};
use rdy_engine::exec::policy::PolicyError;
use rdy_engine::exec::table;
use rdy_engine::probe::ProbeError;
use rdy_engine::probe::sock::RULE_UDP_ADDRESS;
use rdy_spec::Target;
use rdy_spec::check::HostTimeSync;

use crate::family::OS;
use crate::text::{short, soft};
use judge::{Attempt, Facts, Limits, Tool};
use sntp::{Fixed, Request};

mod judge;
mod parse;
mod sntp;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str =
    "this check reads Linux time sync state and has no data source on this OS yet";

/// Why a step was not run.
const NO_TIME: &str = "it was not run, because no time was left in the check budget";

/// The most bytes of a reply that are read. A time packet is 48.
const MAX_REPLY: usize = 128;

/// Kept back from the check's budget, so the check's own cut comes before the engine's timer.
const MARGIN: Duration = Duration::from_millis(250);

/// The least time a command step is given. Below it the step is not run.
const MIN_STEP: Duration = Duration::from_millis(100);

/// What the probe gives one SNTP exchange (`UDP_TIMEOUT`).
const SNTP_WINDOW: Duration = Duration::from_secs(3);

/// The port that applies when the spec names none.
const DEFAULT_PORT: u16 = 123;

/// The static facts about `host.time_sync` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.time_sync",
    family: "host",
    summary: "Clock sync state and offset",
    meta: CheckMeta {
        title: "Clock sync",
        remediation: "Turn on time sync with `timedatectl set-ntp true`, or install chrony with `dnf install chrony && systemctl enable --now chronyd`, then run `chronyc makestep`. On VMs also enable host time sync (VMware Tools, Hyper-V integration services).",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(5)),
    os: OS,
    reads: &[],
    statfs: &[],
    env: &[],
    commands: &[
        CommandSpec {
            program: "timedatectl",
            extra_dirs: &[],
            max_stdout: 64 * 1024,
            env: &[],
        },
        CommandSpec {
            program: "chronyc",
            extra_dirs: &[],
            max_stdout: 64 * 1024,
            env: &[],
        },
    ],
    peers: &[PeerClass::NtpServers],
};

/// `host.time_sync`.
///
/// Built from the spec's `max_skew`, `recommended_skew`, `require_sync` and `ntp_servers`. The servers
/// are the only hosts the check may reach (INV-11): the family hands them to the scheduler through
/// `Built::hosts`, and they count toward the 64 host limit of the spec.
#[derive(Debug, Clone)]
pub struct TimeSync {
    max_skew: Option<Duration>,
    recommended_skew: Option<Duration>,
    require_sync: bool,
    servers: Vec<Target>,
    clock: fn() -> SystemTime,
}

impl TimeSync {
    /// A check for these parameters.
    #[must_use]
    pub fn from_params(params: &HostTimeSync) -> Self {
        // `NtpServer::target` is the parsed host and port, so no server can be dropped here.
        let servers = params
            .ntp_servers
            .iter()
            .flatten()
            .map(|server| server.target().clone())
            .collect();
        Self {
            max_skew: params.max_skew.as_ref().map(rdy_spec::Duration::to_std),
            recommended_skew: params
                .recommended_skew
                .as_ref()
                .map(rdy_spec::Duration::to_std),
            require_sync: params.require_sync,
            servers,
            clock: SystemTime::now,
        }
    }

    /// The time servers, in spec order. These are the only hosts the check reaches.
    #[must_use]
    pub fn servers(&self) -> &[Target] {
        &self.servers
    }

    /// The same check reading `clock` for T1 and T4 instead of the system clock.
    #[cfg(test)]
    fn with_clock(mut self, clock: fn() -> SystemTime) -> Self {
        self.clock = clock;
        self
    }

    fn limits(&self) -> Limits {
        Limits::new(
            self.max_skew.map(|d| d.as_secs_f64()),
            self.recommended_skew.map(|d| d.as_secs_f64()),
            self.require_sync,
        )
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        // One after the other, each cut to the time left in the check's budget minus a margin, so the
        // check always answers before the engine's own timer. The SNTP exchange goes first, so a
        // `timedatectl` that hangs cannot throw away a good offset (03 host.time_sync, Needs).
        let servers = self.ask_all(ctx).await?;
        let timedatectl = timedatectl(ctx).await?;
        let chronyc = chronyc(ctx).await?;
        let facts = Facts {
            timedatectl,
            chronyc,
            servers,
        };
        Ok(judge::judge(&facts, self.limits()))
    }

    /// Asks the servers in spec order and stops at the first good reply. A server after that one, or
    /// one the budget does not reach, is "not measured".
    async fn ask_all(&self, ctx: &CheckContext) -> Result<Vec<(String, Attempt)>, CheckError> {
        let mut out = Vec::with_capacity(self.servers.len());
        let mut answered = false;
        for server in &self.servers {
            let text = server_text(server);
            if answered {
                out.push((
                    text,
                    Attempt::NotAsked("an earlier server already answered"),
                ));
                continue;
            }
            let attempt = self.ask(ctx, server).await?;
            answered = matches!(attempt, Attempt::Sample(_));
            out.push((text, attempt));
        }
        Ok(out)
    }

    /// One exchange with one server.
    async fn ask(&self, ctx: &CheckContext, server: &Target) -> Result<Attempt, CheckError> {
        // The probe gives one exchange up to 3 s. Do not start one the budget cannot hold.
        if slice(ctx).is_none_or(|left| left < SNTP_WINDOW) {
            return Ok(Attempt::NotAsked("no time left in the check budget"));
        }
        // T1 is read here, before the probe looks up a server name, so for a name the round trip
        // includes the lookup. The judge records half of it as the error bound of the offset.
        let Some(t1) = sntp::fixed_from((self.clock)()) else {
            return Ok(Attempt::Failed(
                "the local clock is set before 1970".to_owned(),
            ));
        };
        let request = Request::new(nonce(t1), t1);
        match ctx
            .probe()
            .udp_exchange(server, &request.bytes, MAX_REPLY)
            .await
        {
            Ok(reply) => {
                let Some(t4) = sntp::fixed_from((self.clock)()) else {
                    return Ok(Attempt::Failed(
                        "the local clock is set before 1970".to_owned(),
                    ));
                };
                Ok(match sntp::judge(&request, &reply.bytes, t4) {
                    Ok(sample) => Attempt::Sample(sample),
                    Err(why) => Attempt::Rejected(why),
                })
            }
            // The facade refused the address. This is the one policy refusal the check works around:
            // every other one is a bug in the check and ends it.
            Err(ProbeError::Denied { rule, .. }) if rule == RULE_UDP_ADDRESS => {
                Ok(Attempt::Refused)
            }
            Err(ProbeError::Timeout) => Ok(Attempt::Silent),
            Err(error) => Ok(match soft(error)? {
                ProbeError::NotFound => Attempt::Failed("the name did not resolve".to_owned()),
                other => Attempt::Failed(short(&other)),
            }),
        }
    }
}

impl Check for TimeSync {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// The time a step may use: what is left of the check's budget minus the margin. `None` when that is
/// under [`MIN_STEP`].
fn slice(ctx: &CheckContext) -> Option<Duration> {
    ctx.remaining()
        .checked_sub(MARGIN)
        .filter(|left| *left >= MIN_STEP)
}

/// The server as the text shows it: the host, and the port when it is not 123.
fn server_text(server: &Target) -> String {
    if server.port() == DEFAULT_PORT {
        server.host().to_string()
    } else {
        format!("{}:{}", server.host(), server.port())
    }
}

/// A random 64 bit transmit timestamp. The standard library seeds `RandomState` from the operating
/// system, so the value cannot be guessed by a host that cannot read this process. The counter and the
/// local time only keep two requests in one process apart.
///
/// `getrandom` is pinned in the workspace but `ci/check-crate-deps.toml` does not allow it for
/// `rdy-checks-host`, and a new dependency for eight random bytes is not worth the review. 64 bits of a
/// keyed hash are enough for the one job: an off-path sender must guess the value to be believed.
fn nonce(t1: Fixed) -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    RandomState::new().hash_one((count, t1))
}

/// What running a tool gave.
enum Ran {
    /// It ran and exited 0. The bytes are its stdout.
    Out(Vec<u8>),
    /// The program is not installed.
    Absent,
    /// It did not answer in time.
    Hung,
    /// There was no time left to start it.
    NoTime,
    /// It ran and the result is not usable. The text says why.
    Odd(String),
}

async fn run_tool(
    ctx: &CheckContext,
    program: &'static str,
    form: &str,
) -> Result<Ran, CheckError> {
    let failed = || CheckError::Failed {
        message: format!("{program} is not in rdy's command table"),
        hint: "Tell the vendor which rdy version this is.".to_owned(),
    };
    let entry = table::entry(program).ok_or_else(failed)?;
    let Some(left) = slice(ctx) else {
        return Ok(Ran::NoTime);
    };
    // The table form has its own limit (3 s). `at_most` only lowers it, to the time the budget has left.
    let cmd = entry
        .cmd_for(ctx.os(), form, &[])
        .map_err(|e| CheckError::Probe(ProbeError::Table(e)))?
        .at_most(left);
    let out = match ctx.probe().exec(cmd).await {
        Ok(out) => out,
        Err(error) => {
            // The live runner reports a program that is not on the search path as a policy
            // `NotFound`, not as a probe `NotFound`. Both mean the program is not installed.
            if matches!(error, ProbeError::Policy(PolicyError::NotFound { .. })) {
                return Ok(Ran::Absent);
            }
            return match soft(error)? {
                ProbeError::NotFound => Ok(Ran::Absent),
                ProbeError::Timeout => Ok(Ran::Hung),
                other => Ok(Ran::Odd(short(&other))),
            };
        }
    };
    let Some(code) = out.exit else {
        return Ok(Ran::Odd("it was ended by a signal".to_owned()));
    };
    match entry.form(form).and_then(|f| f.classify(code)) {
        Some(table::ExitClass::Ok) => Ok(Ran::Out(out.stdout)),
        _ => Ok(Ran::Odd(format!("it exited with code {code}"))),
    }
}

/// The sync flag from `timedatectl`: `show`, and `status` when `show` does not work (systemd 219).
async fn timedatectl(ctx: &CheckContext) -> Result<Tool<parse::Timedate>, CheckError> {
    match run_tool(ctx, "timedatectl", "show").await? {
        Ran::Out(bytes) => {
            if let Some(found) = parse::show(&String::from_utf8_lossy(&bytes)) {
                return Ok(Tool::Got(found));
            }
        }
        Ran::Absent => return Ok(Tool::Absent),
        // `status` waits on the same bus, so it is not tried after a `show` that timed out.
        Ran::Hung => return Ok(Tool::Unusable("it timed out".to_owned())),
        Ran::NoTime => return Ok(Tool::Unusable(NO_TIME.to_owned())),
        Ran::Odd(_) => {}
    }
    Ok(match run_tool(ctx, "timedatectl", "status").await? {
        Ran::Out(bytes) => match parse::status(&String::from_utf8_lossy(&bytes)) {
            Some(found) => Tool::Got(found),
            None => Tool::Unusable("its output has no synchronized line".to_owned()),
        },
        Ran::Absent => Tool::Absent,
        Ran::Hung => Tool::Unusable("it timed out".to_owned()),
        Ran::NoTime => Tool::Unusable(NO_TIME.to_owned()),
        Ran::Odd(why) => Tool::Unusable(why),
    })
}

/// The tracking line of `chronyc`.
async fn chronyc(ctx: &CheckContext) -> Result<Tool<parse::Tracking>, CheckError> {
    Ok(match run_tool(ctx, "chronyc", "tracking").await? {
        Ran::Out(bytes) => match parse::tracking(&String::from_utf8_lossy(&bytes)) {
            Some(found) => Tool::Got(found),
            None => Tool::Unusable("its output is not in the expected form".to_owned()),
        },
        Ran::Absent => Tool::Absent,
        Ran::Hung => Tool::Unusable("it timed out".to_owned()),
        Ran::NoTime => Tool::Unusable(NO_TIME.to_owned()),
        Ran::Odd(why) => Tool::Unusable(format!("chronyd may not be running ({why})")),
    })
}
