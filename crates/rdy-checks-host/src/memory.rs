//! `host.memory`: RAM, swap and the cgroup memory limit, against the spec's `min`.
//!
//! Linux only in M1. It reads `/proc/meminfo` through the probe and asks the cgroup helper
//! ([`crate::cgroup`]) for the effective limit and the swap limit. macOS and Windows are `NotYet` until
//! M2-005 adds the `sysinfo` source, so on those systems the check ends as "not yet on this OS".
//!
//! The effective total is the smaller of the host's `MemTotal` and the smallest memory limit on the
//! cgroup chain. The report says "limited by cgroup" when the limit binds. The judgement is a pure
//! function in `judge`. Parsing of `/proc/meminfo` is in `meminfo`. Neither touches the machine.
//!
//! **No privilege needed.** `/proc/meminfo` and the cgroup files are world readable. A cgroup file that
//! cannot be read becomes a note ("a limit may have been missed"), never a failure.

use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Level, Os,
};
use rdy_engine::probe::{Probe, ProbeError};
use rdy_engine::units::Band;
use rdy_spec::check::{HostMemory, ToleranceResult};

use crate::cgroup::{self, CgroupError, Cgroups, Hierarchy};
use crate::family::OS;

mod judge;
mod meminfo;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{Cgroup, Facts, Limit, Rules, judge};

const MEMINFO: &str = "/proc/meminfo";

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str = "this check reads /proc/meminfo and has no data source on this OS yet";

/// The static facts about `host.memory` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.memory",
    family: "host",
    summary: "RAM, swap, cgroup limit",
    meta: CheckMeta {
        title: "Memory",
        remediation: "Add RAM or pick a larger node class. A nominal 32 GiB machine shows about 31 GiB, so ask for a size class, not an exact number. On Linux, if the spec forbids swap, run `swapoff -a` and comment out the swap lines in `/etc/fstab`.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(2)),
    os: OS,
    reads: &[
        MEMINFO,
        cgroup::READS[0],
        cgroup::READS[1],
        cgroup::READS[2],
    ],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// `host.memory`.
///
/// Built from the spec entry's `min`, `min_available`, `swap`, `tolerance_percent` and
/// `tolerance_result` ([`Memory::from_params`]).
#[derive(Debug, Clone, Copy)]
pub struct Memory {
    rules: Rules,
}

impl Memory {
    /// The check for these spec parameters. `min_available` defaults to half of `min`, and the band is
    /// `tolerance_percent` of `min` with a floor of 256 MiB.
    #[must_use]
    pub fn from_params(params: &HostMemory) -> Self {
        Self {
            rules: Rules {
                min: params.min,
                min_available: params
                    .min_available
                    .map_or(params.min.bytes() / 2, |q| q.bytes()),
                swap: params.swap,
                band: Band::MEMORY.with_percent(params.tolerance_percent.get()),
                in_band: match params.tolerance_result {
                    ToleranceResult::Warn => Level::Warn,
                    _ => Level::Pass,
                },
            },
        }
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let probe = ctx.probe();
        let hint = "Check that /proc is mounted and readable by this user. If it is, tell the vendor which rdy version this is.";
        let file = match probe.read(Path::new(MEMINFO)).await {
            Ok(file) => file,
            Err(ProbeError::NotFound) => {
                return Err(CheckError::Failed {
                    message: format!("{MEMINFO} does not exist on this machine"),
                    hint: hint.to_owned(),
                });
            }
            Err(error) => return Err(CheckError::Probe(error)),
        };
        let text = String::from_utf8_lossy(&file.bytes);
        let info = meminfo::parse(&text).map_err(|why| CheckError::Failed {
            message: format!("{MEMINFO} is not in the form rdy reads: {why}"),
            hint: hint.to_owned(),
        })?;
        let mut notes = Vec::new();
        let cgroup = cgroup_facts(probe, &mut notes).await?;
        let facts = Facts {
            host_total: info.total,
            available: info.available,
            swap_total: info.swap_total,
            swap_free: info.swap_free,
            cgroup,
            notes,
        };
        Ok(judge(&self.rules, &facts))
    }
}

impl Check for Memory {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// The memory limits that apply to rdy. A cgroup that cannot be read or understood adds a note and
/// leaves the limits empty. Only a refusal by rdy's own policy (a bug in the manifest) ends the check.
async fn cgroup_facts(probe: &Probe, notes: &mut Vec<String>) -> Result<Cgroup, CheckError> {
    let found = match Cgroups::discover(probe).await {
        Ok(Some(cgroups)) => cgroups.memory(probe).await,
        Ok(None) => return Ok(Cgroup::default()),
        Err(error) => Err(error),
    };
    let memory = match found {
        Ok(memory) => memory,
        Err(CgroupError::Probe(
            error @ (ProbeError::Denied { .. }
            | ProbeError::Policy(_)
            | ProbeError::Table(_)
            | ProbeError::NotRecorded(_)),
        )) => return Err(CheckError::Probe(error)),
        Err(_) => {
            notes.push(
                "The cgroup files could not be read, so a cgroup memory limit may have been missed."
                    .to_owned(),
            );
            return Ok(Cgroup::default());
        }
    };
    let unreadable = memory.limit.unreadable + memory.swap.unreadable;
    if unreadable > 0 {
        notes.push(format!(
            "{unreadable} cgroup memory file(s) could not be read, so a limit may have been missed."
        ));
    }
    if memory.limit.min.is_none() && memory.limit.hidden_above {
        notes.push(
            "rdy sees only part of the cgroup tree (a container), so a memory limit set above it was not visible."
                .to_owned(),
        );
    }
    let limit = |bound: Option<cgroup::Bound<u64>>| {
        bound.map(|b| Limit {
            bytes: b.value,
            at: b.at,
        })
    };
    Ok(Cgroup {
        hierarchy: match memory.hierarchy {
            Some(Hierarchy::V2) => Some("v2"),
            Some(Hierarchy::V1) => Some("v1"),
            _ => None,
        },
        limit: limit(memory.limit.min),
        swap_limit: limit(memory.swap.min),
    })
}
