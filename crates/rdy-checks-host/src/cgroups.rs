//! `host.cgroups`: the cgroup version (v1, hybrid, v2) and the controllers, against the spec's
//! `version` and `controllers`.
//!
//! Linux only. macOS and Windows are `NotYet` in the support table, and the check ends as "not yet on
//! this OS" there. Cgroups do not exist on those systems, so the vendor scopes the check with
//! `os: [linux]` (ADR 0013).
//!
//! **Sources.** The layout and the controller lists come from the cgroup helper ([`crate::cgroup`],
//! M1-065), which joins `/proc/self/cgroup` with `/proc/self/mountinfo` and reads `cgroup.controllers`
//! and `cgroup.subtree_control`. A v2 mount is a `cgroup2` file system and a v1 mount a `cgroup` one, so
//! the layout needs no `statfs` call. `/proc/cgroups` says whether the kernel has a controller turned
//! off (the `enabled` column), and `/proc/cmdline` shows which boot option did it. `/etc/os-release`
//! (and the device tree model on a Raspberry Pi) choose the fix text.
//!
//! **No privilege needed.** Every file is world readable. A file that cannot be read weakens one
//! answer and becomes a note or a "not confirmed" warning, never a failure. The judgement is a pure
//! function in `judge`. Parsing is in `parse`, fix text in `fix`.

use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Os,
};
use rdy_engine::probe::ProbeError;
use rdy_spec::check::{CgroupVersion, HostCgroups};

use crate::cgroup::{self, CgroupError, Cgroups};
use crate::family::OS;
use crate::os::release;
use crate::reads::{Read, read_text};

mod fix;
mod judge;
mod parse;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{Facts, Rules, Wanted, judge};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str = "this check reads Linux cgroup files and has no data source on this OS yet";

const PROC_CGROUPS: &str = "/proc/cgroups";
const CMDLINE: &str = "/proc/cmdline";
const OS_RELEASE: &str = "/etc/os-release";
/// Where `/etc/os-release` usually points. The probe resolves links, so both are declared.
const OS_RELEASE_USR: &str = "/usr/lib/os-release";
const DEVICE_MODEL: &str = "/proc/device-tree/model";

/// The static facts about `host.cgroups` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.cgroups",
    family: "host",
    summary: "cgroup version and controllers",
    meta: CheckMeta {
        title: "cgroups",
        remediation: "Boot with the cgroup version the vendor needs. On the RHEL family, run `grubby --update-kernel=ALL --args=\"systemd.unified_cgroup_hierarchy=1\"` and reboot. On Debian and Ubuntu, add the argument to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, run `update-grub` and reboot.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(2)),
    os: OS,
    reads: &[
        cgroup::READS[0],
        cgroup::READS[1],
        cgroup::READS[2],
        PROC_CGROUPS,
        CMDLINE,
        OS_RELEASE,
        OS_RELEASE_USR,
        DEVICE_MODEL,
    ],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// `host.cgroups`.
///
/// Built from the spec entry's `version` and `controllers` ([`CgroupsCheck::from_params`]). With
/// neither, it reports what it finds and passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupsCheck {
    rules: Rules,
}

impl CgroupsCheck {
    /// The check for these spec parameters.
    #[must_use]
    pub fn from_params(params: &HostCgroups) -> Self {
        let version = match params.version {
            CgroupVersion::V2 => Wanted::V2,
            CgroupVersion::V1 => Wanted::V1,
            _ => Wanted::Any,
        };
        let mut controllers: Vec<String> = Vec::new();
        for name in params.controllers.iter().flat_map(|list| list.iter()) {
            let name = name.as_str().to_owned();
            if !controllers.contains(&name) {
                controllers.push(name);
            }
        }
        Self {
            rules: Rules {
                version,
                controllers,
            },
        }
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let mut notes = Vec::new();
        let controllers = controllers(ctx, &mut notes).await?;
        let mut facts = Facts {
            controllers,
            notes,
            ..Facts::default()
        };

        match read_text(ctx, PROC_CGROUPS).await? {
            Read::Text(text) => facts.proc_cgroups = Some(parse::parse_proc_cgroups(&text)),
            Read::Absent => {}
            Read::Unreadable(why) => facts
                .notes
                .push(format!("{PROC_CGROUPS} could not be read ({why}).")),
        }
        if let Read::Text(text) = read_text(ctx, CMDLINE).await? {
            facts.cmdline = parse::parse_cmdline(&text);
        }
        for path in [OS_RELEASE, OS_RELEASE_USR] {
            if let Read::Text(text) = read_text(ctx, path).await?
                && let Some(parsed) = release::parse(&text)
            {
                facts.release = Some(parsed);
                break;
            }
        }
        if let Read::Text(model) = read_text(ctx, DEVICE_MODEL).await? {
            facts.raspberry_pi = model.contains("Raspberry Pi");
        }
        Ok(judge(&self.rules, &facts))
    }
}

impl Check for CgroupsCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// The layout and controller lists. `None` when the cgroup files cannot be used, with a note why. Only
/// a refusal by rdy's own policy (a bug in the manifest) ends the check.
async fn controllers(
    ctx: &CheckContext,
    notes: &mut Vec<String>,
) -> Result<Option<cgroup::Controllers>, CheckError> {
    let probe = ctx.probe();
    let found = match Cgroups::discover(probe).await {
        Ok(Some(cgroups)) => cgroups.controllers(probe).await.map(Some),
        Ok(None) => {
            notes.push(
                "/proc/self/cgroup does not exist, so this kernel has no cgroup support rdy can read."
                    .to_owned(),
            );
            return Ok(None);
        }
        Err(error) => Err(error),
    };
    match found {
        Ok(found) => Ok(found),
        Err(CgroupError::Probe(
            error @ (ProbeError::Denied { .. }
            | ProbeError::Policy(_)
            | ProbeError::Table(_)
            | ProbeError::NotRecorded(_)),
        )) => Err(CheckError::Probe(error)),
        Err(_) => {
            notes.push("The cgroup files could not be read or understood.".to_owned());
            Ok(None)
        }
    }
}
