//! The host family: the OS support table, one static [`CheckInfo`] per check, and a stub check.

use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support, Want,
};
use rdy_engine::family::{BuildError, Built, Family};
use rdy_engine::plan::NEWER_RDY;
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

#[cfg(test)]
mod tests;

/// Where each host check works in M1 (02 section "Per-OS behaviour", 03 section 2).
///
/// Linux is `Full`. macOS and Windows are `NotYet`: the `sysinfo` subset is declined for M1 (MF-02)
/// and arrives with M2-005, which makes four of these `Partial`. A concept that does not exist on an
/// OS is not a state here either (ADR 0013): the vendor scopes such a check with `os: [linux]`.
const OS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::NotYet,
    windows: Support::NotYet,
};

/// What a stub says on Linux, where the check is planned but its code is not written yet.
const NOT_BUILT: &str = "is not built into this rdy yet";

/// What a stub says on an OS where the check is `NotYet`.
const NO_SOURCE: &str = "this check has no data source on this OS yet";

const ROOT: &[Want] = &[Want {
    need: Need::Root,
    evidence_only: false,
}];

/// A host check's static facts. The manifest fields stay empty until the real check declares them.
const fn info(
    id: &'static str,
    summary: &'static str,
    meta: CheckMeta,
    secs: u64,
    wants: &'static [Want],
) -> CheckInfo {
    CheckInfo {
        id,
        family: "host",
        summary,
        meta,
        needs: &[],
        wants,
        default_timeout: Some(Duration::from_secs(secs)),
        os: OS,
        reads: &[],
        env: &[],
        commands: &[],
        peers: &[],
    }
}

// Titles and remediation follow the Fix lines of 03 section 2, with the measured values taken out.
// The check that replaces each stub may sharpen its text. Its findings carry the specific fix.

static DISK: CheckInfo = info(
    "host.disk",
    "Free space, inodes, mount flags per path",
    CheckMeta {
        title: "Disk space and mount flags",
        remediation: "Free up space on the volume that holds the install path, grow the volume, or point the install at a larger disk. On Linux, run `df -h` on the install path to see what is free. If the path is on a `noexec` mount, remount it with `exec` and remove `noexec` from `/etc/fstab`, or move the install path.",
    },
    5,
    &[],
);
static MEMORY: CheckInfo = info(
    "host.memory",
    "RAM, swap, cgroup limit",
    CheckMeta {
        title: "Memory",
        remediation: "Add RAM or pick a larger node class. A nominal 32 GiB machine shows about 31 GiB, so ask for a size class, not an exact number. On Linux, if the spec forbids swap, run `swapoff -a` and comment out the swap lines in `/etc/fstab`.",
    },
    2,
    &[],
);
static PORTS: CheckInfo = info(
    "host.ports",
    "Required ports free",
    CheckMeta {
        title: "Free ports",
        remediation: "Stop the process that holds the port, or change the product's port setting. If the port is in the ephemeral range, reserve it with `net.ipv4.ip_local_reserved_ports` in a file under `/etc/sysctl.d/` as root, then run `sysctl --system`.",
    },
    5,
    ROOT,
);
static LSM: CheckInfo = info(
    "host.lsm",
    "SELinux and AppArmor state, recent denials",
    CheckMeta {
        title: "SELinux and AppArmor",
        remediation: "On SELinux, read recent denials with `ausearch -m avc -ts recent`. Install the vendor's policy module, or label the volume with `chcon -Rt container_file_t` or the `:Z` mount option. As a last resort, run `setenforce 0` and set `SELINUX=permissive` in `/etc/selinux/config`. This turns SELinux protection off, so ask the security team first. On AppArmor, read denials with `journalctl -k` and ask the vendor for a profile.",
    },
    3,
    ROOT,
);
static SECURITY_AGENTS: CheckInfo = info(
    "host.security_agents",
    "Security software processes that inspect file and process activity",
    CheckMeta {
        title: "Security software",
        remediation: "Security software often inspects file opens and process launches. If the install is slow or fails, ask the security team to review exclusions for the product's paths, then run rdy again.",
    },
    5,
    ROOT,
);
static CPU: CheckInfo = info(
    "host.cpu",
    "Cores, arch, CPU flags, virtualization",
    CheckMeta {
        title: "CPU",
        remediation: "Resize the instance to get more vCPUs or the right architecture. If a CPU flag is missing on a VM, set the VM CPU model to host passthrough or turn off CPU feature masking on the hypervisor.",
    },
    2,
    &[],
);
static HOST_OS: CheckInfo = info(
    "host.os",
    "Distro, version, arch, FIPS",
    CheckMeta {
        title: "Operating system",
        remediation: "Use an OS image the vendor supports, or ask the vendor about the one you have.",
    },
    2,
    &[],
);

/// Every host check this build lists, in catalog order.
static CHECKS: [&CheckInfo; 7] = [
    &DISK,
    &MEMORY,
    &PORTS,
    &LSM,
    &SECURITY_AGENTS,
    &CPU,
    &HOST_OS,
];

/// The `host` family: `host.disk`, `host.memory`, `host.ports`, `host.lsm`, `host.security_agents`,
/// `host.cpu` and `host.os`.
///
/// Each check is a stub for now ([`HostFamily::stub_ids`]).
///
/// Do not register this family in the CLI while any stub remains. On Linux a stub that runs reports
/// `error` with `check_failed`, which reads as a fault on the customer's machine. The ticket that
/// registers it (M1-057, `rdy run` end to end) must first drop the stubs, or have the engine add a
/// `not_in_build` skip for them. Tests may register it freely.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostFamily;

impl HostFamily {
    /// The ids of the checks that are still stubs, in catalog order.
    ///
    /// Each ticket that writes a real check removes its id here. The family may be registered in the
    /// CLI only when this is empty.
    #[must_use]
    pub fn stub_ids() -> &'static [&'static str] {
        &STUBS
    }
}

/// The checks that have no code yet. `build` returns a [`Stub`] for each.
static STUBS: [&str; 7] = [
    "host.disk",
    "host.memory",
    "host.ports",
    "host.lsm",
    "host.security_agents",
    "host.cpu",
    "host.os",
];

impl Family for HostFamily {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &CHECKS
    }

    fn build(&self, entry: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        let info = CHECKS
            .iter()
            .find(|info| info.id == entry.id)
            .ok_or_else(|| BuildError::Unsupported("not a host check".to_owned()))?;
        Ok(Built::new(Box::new(Stub(info))))
    }
}

/// A host check with no code yet.
///
/// The OS support lives in `CheckInfo::os`, so the planner never puts a stub into a run on an OS that
/// is `NotYet`. `run` still reads `ctx.os()`, so a stub that reaches the scheduler anyway says what the
/// planner would. It never returns a finding.
struct Stub(&'static CheckInfo);

impl Check for Stub {
    fn info(&self) -> &'static CheckInfo {
        self.0
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        let outcome = match self.0.os.on(ctx.os()) {
            Support::NotYet => Err(CheckError::Unsupported(NO_SOURCE)),
            Support::Full | Support::Partial(_) => Err(CheckError::Failed {
                message: format!("{} {NOT_BUILT}", self.0.id),
                hint: NEWER_RDY.to_owned(),
            }),
        };
        Box::pin(async move { outcome })
    }
}
