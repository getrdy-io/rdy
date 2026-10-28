//! The host family: the OS support table, one static [`CheckInfo`] per check, and a stub check.

use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckOutcome, Need, OsSupport, Support,
    Want,
};
use rdy_engine::family::{BuildError, Built, Family};
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
    secs: u64,
    wants: &'static [Want],
) -> CheckInfo {
    CheckInfo {
        id,
        family: "host",
        summary,
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

static DISK: CheckInfo = info(
    "host.disk",
    "Free space, inodes, mount flags per path",
    5,
    &[],
);
static MEMORY: CheckInfo = info("host.memory", "RAM, swap, cgroup limit", 2, &[]);
static PORTS: CheckInfo = info("host.ports", "Required ports free", 5, ROOT);
static LSM: CheckInfo = info(
    "host.lsm",
    "SELinux and AppArmor state, recent denials",
    3,
    ROOT,
);
static SECURITY_AGENTS: CheckInfo = info(
    "host.security_agents",
    "Security software processes that inspect file and process activity",
    5,
    ROOT,
);
static CPU: CheckInfo = info("host.cpu", "Cores, arch, CPU flags, virtualization", 2, &[]);
static HOST_OS: CheckInfo = info("host.os", "Distro, version, arch, FIPS", 2, &[]);

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
/// Each check is a stub for now. Register it with
/// [`Registry::register`](rdy_engine::family::Registry::register) and the planner skips every host
/// check on macOS and Windows with `not_yet_on_os`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostFamily;

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
                hint: "Install a newer rdy. If there is none yet, ask the vendor how to go on."
                    .to_owned(),
            }),
        };
        Box::pin(async move { outcome })
    }
}
