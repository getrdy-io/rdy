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

use crate::cpu::{self, CpuCheck};
use crate::disk::{self, Disk};
use crate::firewall::{self, Firewall};
use crate::lsm::{self, Lsm};
use crate::memory::{self, Memory};
use crate::os::{self, OsCheck};
use crate::security_agents::{self, SecurityAgents};

#[cfg(test)]
mod tests;

/// Where each host check works in M1 (02 section "Per-OS behaviour", 03 section 2).
///
/// Linux is `Full`. macOS and Windows are `NotYet`: the `sysinfo` subset is declined for M1 (MF-02)
/// and arrives with M2-005, which makes four of these `Partial`. A concept that does not exist on an
/// OS is not a state here either (ADR 0013): the vendor scopes such a check with `os: [linux]`.
pub(crate) const OS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::NotYet,
    windows: Support::NotYet,
};

/// What a stub says on Linux, where the check is planned but its code is not written yet.
const NOT_BUILT: &str = "is not built into this rdy yet";

/// What a stub says on an OS where the check is `NotYet`.
const NO_SOURCE: &str = "this check has no data source on this OS yet";

pub(crate) const ROOT: &[Want] = &[Want {
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
        statfs: &[],
        env: &[],
        commands: &[],
        peers: &[],
    }
}

// Titles and remediation follow the Fix lines of 03 section 2, with the measured values taken out.
// The check that replaces each stub may sharpen its text. Its findings carry the specific fix.

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
static TIME_SYNC: CheckInfo = info(
    "host.time_sync",
    "Clock sync state and offset",
    CheckMeta {
        title: "Clock sync",
        remediation: "Turn on time sync with `timedatectl set-ntp true`, or install chrony with `dnf install chrony && systemctl enable --now chronyd`, then run `chronyc makestep`. On VMs also enable host time sync (VMware Tools, Hyper-V integration services).",
    },
    5,
    &[],
);
static SYSCTL: CheckInfo = info(
    "host.sysctl",
    "Kernel parameters and limits",
    CheckMeta {
        title: "Kernel parameters and limits",
        remediation: "Set the value now with `sysctl -w vm.max_map_count=262144`, using the parameter and value from the result. Then persist it in a file under `/etc/sysctl.d/` and run `sysctl --system`. `sysctl -p` does not read `sysctl.d`. For file limits, set `LimitNOFILE=` in the service unit.",
    },
    2,
    &[],
);
static CONTAINER_RUNTIME: CheckInfo = info(
    "host.container_runtime",
    "Docker, containerd, Podman, CRI-O",
    CheckMeta {
        title: "Container runtime",
        remediation: "Install a container runtime the vendor supports, and make its socket readable by adding the user to the `docker` group or by running as root. The runtime and the kubelet must use the same cgroup driver. For containerd, set `SystemdCgroup = true` in `/etc/containerd/config.toml`, then run `systemctl restart containerd`.",
    },
    5,
    ROOT,
);
static CGROUPS: CheckInfo = info(
    "host.cgroups",
    "cgroup version and controllers",
    CheckMeta {
        title: "cgroups",
        remediation: "Boot with the cgroup version the vendor needs. On the RHEL family, run `grubby --update-kernel=ALL --args=\"systemd.unified_cgroup_hierarchy=1\"` and reboot. On Debian and Ubuntu, add the argument to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, run `update-grub` and reboot.",
    },
    2,
    &[],
);

static KERNEL: CheckInfo = info(
    "host.kernel",
    "Kernel version and modules",
    CheckMeta {
        title: "Kernel",
        remediation: "Use a kernel at or above the minimum. Load a missing module now and at boot with `modprobe br_netfilter && echo br_netfilter | sudo tee /etc/modules-load.d/vendor.conf`, using the module from the result.",
    },
    2,
    &[],
);

/// Every host check this build lists, in catalog order.
static CHECKS: [&CheckInfo; 13] = [
    &disk::INFO,
    &memory::INFO,
    &PORTS,
    &lsm::INFO,
    &security_agents::INFO,
    &firewall::INFO,
    &TIME_SYNC,
    &cpu::INFO,
    &SYSCTL,
    &CONTAINER_RUNTIME,
    &CGROUPS,
    &os::INFO,
    &KERNEL,
];

/// The `host` family: `host.disk`, `host.memory`, `host.ports`, `host.lsm`, `host.security_agents`,
/// `host.firewall`, `host.time_sync`, `host.cpu`, `host.sysctl`, `host.container_runtime`,
/// `host.cgroups`, `host.os` and `host.kernel`.
///
/// `host.cpu` ([`CpuCheck`]), `host.disk` ([`Disk`]), `host.firewall` ([`Firewall`]), `host.lsm` ([`Lsm`]),
/// `host.memory` ([`Memory`]), `host.os` ([`OsCheck`]) and `host.security_agents` ([`SecurityAgents`]) are
/// real. The others are stubs for now ([`HostFamily::stub_ids`]).
///
/// On Linux a stub that ran would report `error` with `check_failed`, which reads as a fault on the
/// customer's machine. So the family lists its stubs in [`Family::not_built`] and the planner skips each
/// as `not_in_build` before it builds anything (M1-057): `rdy run` registers the family, and a stub never
/// runs outside a test. Ids leave [`HostFamily::stub_ids`] as their real checks arrive.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostFamily;

impl HostFamily {
    /// The ids of the checks that are still stubs, in catalog order.
    ///
    /// Each ticket that writes a real check removes its id here. The planner skips these ids as
    /// `not_in_build` ([`Family::not_built`]).
    #[must_use]
    pub fn stub_ids() -> &'static [&'static str] {
        &STUBS
    }
}

/// The checks that have no code yet. `build` returns a [`Stub`] for each.
static STUBS: [&str; 6] = [
    "host.ports",
    "host.time_sync",
    "host.sysctl",
    "host.container_runtime",
    "host.cgroups",
    "host.kernel",
];

impl Family for HostFamily {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &CHECKS
    }

    fn not_built(&self) -> &'static [&'static str] {
        &STUBS
    }

    fn build(&self, entry: &CheckSpec, params: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        if let CheckParams::HostDisk(params) = &params {
            return Ok(Built::new(Box::new(Disk::new(params))));
        }
        if let CheckParams::HostFirewall(firewall) = params {
            let ports = firewall
                .open_inbound
                .iter()
                .flatten()
                .map(|port| port.get());
            return Ok(Built::new(Box::new(Firewall::new(ports))));
        }
        if let CheckParams::HostCpu(cpu) = &params {
            return Ok(Built::new(Box::new(CpuCheck::from_params(cpu))));
        }
        if let CheckParams::HostLsm(lsm) = &params {
            return Ok(Built::new(Box::new(Lsm::new(lsm))));
        }
        if let CheckParams::HostMemory(memory) = params {
            return Ok(Built::new(Box::new(Memory::from_params(&memory))));
        }
        if let CheckParams::HostOs(os) = &params {
            return Ok(Built::new(Box::new(OsCheck::from_params(os))));
        }
        if let CheckParams::HostSecurityAgents(agents) = params {
            let ids = |list: Option<&rdy_spec::check::StringList>| -> Vec<String> {
                list.into_iter()
                    .flatten()
                    .map(|id| id.as_str().to_owned())
                    .collect()
            };
            let check =
                SecurityAgents::new(ids(agents.forbid.as_ref()), ids(agents.allow.as_ref()));
            return Ok(Built::new(Box::new(check)));
        }
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
