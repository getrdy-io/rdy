//! `host.cpu`: how many CPUs rdy can use, on which architecture, and with which CPU features.
//!
//! Linux only in M1. macOS and Windows are `NotYet` until M2-005. Rosetta detection
//! (`sysctl.proc_translated`) arrives with the macOS sources in M2-007.
//!
//! **Cores.** The count is what the product can use, not what the hardware has. It starts from the
//! online CPUs (`/sys/devices/system/cpu/online`, else the processor blocks of `/proc/cpuinfo`), keeps
//! only the CPUs rdy may run on (`Cpus_allowed_list` in `/proc/self/status`, which a container cpuset or
//! `taskset` narrows), then takes the smaller of that and the cgroup CPU quota from the shared cgroup
//! helper. A quota of `200000/100000` is 2 CPUs. A quota that is not a whole number is kept exact, so a
//! quota of 1.5 CPUs does not pass `min: 2`. The report says which of the three limits the count.
//!
//! **Architecture** comes from `uname` (a native call), folded to `x86_64` or `aarch64`.
//!
//! **Features.** The `flags` line of `/proc/cpuinfo` on x86 and `Features` on Arm. A feature counts only
//! when every processor block shows it, so a hybrid CPU is judged by its weakest core. The levels
//! `x86-64-v2`, `x86-64-v3` and `x86-64-v4` are worked out from the feature names (see `parse::LEVELS`).
//! A few names are folded: `lzcnt` is `abm`, `sse3` is `pni`, `neon` is `asimd`.
//!
//! **Virtual machine.** On x86 the `hypervisor` flag. On Arm, which has no such flag, the DMI product
//! name and vendor, and `/sys/hypervisor/type`. It only picks the fix text.
//!
//! **Not built yet.** The catalog also asks for the flags through `std::is_x86_feature_detected!`
//! behind a native call. The closed `NativeCall` list has no such variant (it comes with M2-004), so
//! `/proc/cpuinfo` is the only feature source for now. The topology files under
//! `/sys/devices/system/cpu/cpu*/topology` are not read either: `physical_cores` comes from the
//! `physical id` and `core id` lines of `cpuinfo`, and is empty on Arm.
//!
//! **Not verified.** A cgroup CPU file or `/proc/self/status` that cannot be read could hide a limit
//! that lowers the count. With a `min` or `recommended` set, the check then never passes: it warns
//! "not verified" and sets `partial`.
//!
//! Nothing here needs a privilege. Every file is world-readable on a normal kernel.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Os, Partial,
};
use rdy_engine::probe::{NativeCall, NativeValue, ProbeError};
use rdy_spec::check::{Arch, HostCpu};
use serde_json::{Map, Value, json};

use crate::cgroup::{Bound, CgroupError, Cgroups, CpuQuota};
use crate::family::OS;
use crate::text::{short, soft};

mod parse;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use parse::{CpuInfo, CpuList};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str = "this check reads Linux CPU files and has no data source on this OS yet";

const CPUINFO: &str = "/proc/cpuinfo";
const STATUS: &str = "/proc/self/status";
const ONLINE: &str = "/sys/devices/system/cpu/online";
const DMI_PRODUCT: &str = "/sys/class/dmi/id/product_name";
const DMI_VENDOR: &str = "/sys/class/dmi/id/sys_vendor";
const HYPERVISOR_TYPE: &str = "/sys/hypervisor/type";

/// The most names listed in one sentence before the rest are counted.
const LIST_MAX: usize = 8;

/// The static facts about `host.cpu` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.cpu",
    family: "host",
    summary: "Cores, arch, CPU flags, virtualization",
    meta: CheckMeta {
        title: "CPU",
        remediation: "Resize the instance to get more vCPUs or the right architecture. If a cgroup CPU quota or a cpuset caps the count, raise it. If a CPU flag is missing on a VM, set the VM CPU model to host passthrough or turn off CPU feature masking on the hypervisor.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(2)),
    os: OS,
    // The first three are `cgroup::READS`; a test holds the two lists together.
    reads: &[
        "/proc/self/cgroup",
        "/proc/self/mountinfo",
        "/sys/fs/cgroup",
        CPUINFO,
        STATUS,
        ONLINE,
        DMI_PRODUCT,
        DMI_VENDOR,
        HYPERVISOR_TYPE,
    ],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// Whether the machine is a virtual machine, as far as rdy can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Virt {
    Vm,
    None,
    Unknown,
}

impl Virt {
    fn word(self) -> &'static str {
        match self {
            Self::Vm => "vm",
            Self::None => "none",
            Self::Unknown => "unknown",
        }
    }
}

/// What limits the CPU count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Limit {
    Hardware,
    Affinity,
    Quota,
}

/// Something that could lower the CPU count and could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gap {
    /// A cgroup CPU limit file.
    Cgroup,
    /// The affinity mask in `/proc/self/status`.
    Affinity,
}

impl Gap {
    fn said(self) -> &'static str {
        match self {
            Self::Cgroup => "a cgroup CPU limit could not be read",
            Self::Affinity => "the CPU affinity mask could not be read",
        }
    }

    fn fix(self, need: u16) -> String {
        match self {
            Self::Cgroup => format!(
                "Read /sys/fs/cgroup/cpu.max (cgroup v2) or cpu.cfs_quota_us (v1) by hand and confirm the limit allows {need} CPUs or more, or run rdy where the cgroup files are readable."
            ),
            Self::Affinity => format!(
                "Read Cpus_allowed_list in /proc/self/status by hand and confirm it lists {need} CPUs or more, or run rdy where /proc is readable."
            ),
        }
    }
}

/// Everything the check learned about the machine.
struct Facts {
    /// The CPUs online on the host.
    online: Option<u64>,
    /// The CPUs rdy may run on.
    usable: u64,
    quota: Option<Bound<CpuQuota>>,
    /// The CPUs the product can use, in thousandths.
    effective_milli: u64,
    limit: Limit,
    physical: Option<u32>,
    arch: Option<String>,
    virt: Virt,
    flags: Option<BTreeSet<String>>,
    /// What could have lowered the count and could not be read.
    gaps: Vec<Gap>,
}

/// `host.cpu`.
///
/// Built from the spec entry: `min` and `recommended` cores, the allowed architectures and the CPU
/// features that must be present. With none of them it reports what it found and passes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CpuCheck {
    min: Option<u16>,
    recommended: Option<u16>,
    arch: Vec<String>,
    flags: Vec<String>,
}

impl CpuCheck {
    /// A check from the parameters of a `host.cpu` spec entry.
    #[must_use]
    pub fn from_params(params: &HostCpu) -> Self {
        Self::new(
            params.min.map(|c| c.get()),
            params.recommended.map(|c| c.get()),
            params
                .arch
                .iter()
                .flat_map(|list| list.iter())
                .map(|arch| arch_name(*arch).to_owned()),
            params
                .flags
                .iter()
                .flat_map(|list| list.iter())
                .map(|flag| flag.as_str().to_owned()),
        )
    }

    /// A check for `min` and `recommended` CPUs, the allowed `arch` names (`amd64` and `arm64` are
    /// accepted) and the `flags` that must be present. Duplicates are dropped.
    #[must_use]
    pub fn new(
        min: Option<u16>,
        recommended: Option<u16>,
        arch: impl IntoIterator<Item = String>,
        flags: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut arch: Vec<String> = arch
            .into_iter()
            .map(|a| parse::normalize_arch(&a))
            .collect();
        arch.sort_unstable();
        arch.dedup();
        let mut seen = BTreeSet::new();
        let flags = flags
            .into_iter()
            .map(|f| f.trim().to_lowercase())
            .filter(|f| !f.is_empty() && seen.insert(parse::normalize(f)))
            .collect();
        Self {
            min,
            recommended,
            arch,
            flags,
        }
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let mut notes = Vec::new();
        let cpuinfo = read_cpuinfo(ctx, &mut notes).await?;
        let mut gaps = Vec::new();
        let online = match read_list(ctx, ONLINE).await? {
            Some(list) => Some(list),
            // A cut cpuinfo undercounts the processors, so it is not a source for the count.
            None => cpuinfo
                .as_ref()
                .filter(|info| !info.cut)
                .and_then(|info| CpuList::first(info.processors)),
        };
        let allowed = read_allowed(ctx, &mut notes, &mut gaps).await?;
        let usable = match (&online, &allowed) {
            (Some(online), Some(allowed)) => match allowed.common(online) {
                0 => allowed.count(),
                both => both,
            },
            (None, Some(list)) | (Some(list), None) => list.count(),
            (None, None) => {
                return Err(CheckError::Failed {
                    message: "rdy could not count the CPUs: it could not read /sys/devices/system/cpu/online, /proc/self/status or /proc/cpuinfo".to_owned(),
                    hint: "Mount /proc and /sys into the environment rdy runs in, or run rdy on the host.".to_owned(),
                });
            }
        };
        let (quota, quota_gap) = read_quota(ctx, &mut notes).await?;
        if quota_gap {
            gaps.push(Gap::Cgroup);
        }
        let quota_milli = quota.as_ref().map(|q| quota_milli(&q.value));
        let effective_milli = quota_milli.map_or(usable.saturating_mul(1000), |q| {
            q.min(usable.saturating_mul(1000))
        });
        let online_count = online.as_ref().map(CpuList::count);
        let limit = if quota_milli.is_some_and(|q| q < usable.saturating_mul(1000)) {
            Limit::Quota
        } else if online_count.is_some_and(|all| usable < all) {
            Limit::Affinity
        } else {
            Limit::Hardware
        };
        let arch = read_arch(ctx).await?;
        let flags = cpuinfo.as_ref().and_then(|info| info.flags.clone());
        let x86 = match (&arch, &flags) {
            (Some(arch), _) => arch == "x86_64",
            (None, Some(flags)) => flags.contains("sse2"),
            (None, None) => false,
        };
        let virt = read_virt(ctx, x86, flags.as_ref()).await?;
        let facts = Facts {
            online: online_count,
            usable,
            quota,
            effective_milli,
            limit,
            physical: cpuinfo.as_ref().and_then(|info| info.physical_cores),
            arch,
            virt,
            flags,
            gaps,
        };
        Ok(self.judge(&facts, x86, notes))
    }

    /// The finding for what was learned. Pure.
    fn judge(&self, facts: &Facts, x86: bool, mut notes: Vec<String>) -> Finding {
        let mut level = Level::Pass;
        let mut clauses: Vec<String> = Vec::new();
        let mut fixes: Vec<String> = Vec::new();
        let mut unseen: Vec<&str> = Vec::new();

        // Cores.
        let have = facts.effective_milli;
        let below_min = self.min.filter(|m| have < u64::from(*m) * 1000);
        let below_rec = self.recommended.filter(|r| have < u64::from(*r) * 1000);
        let mut cores = format!("{} found", vcpus(have));
        if let Some(min) = self.min {
            cores.push_str(&format!(", {min} needed"));
        }
        if let (Some(rec), None) = (below_rec, below_min) {
            cores.push_str(&format!(", {rec} recommended"));
        }
        if facts.limit != Limit::Hardware
            && let Some(all) = facts.online
        {
            cores.push_str(&format!(
                " (a {} limits the {all} CPUs of the host)",
                match facts.limit {
                    Limit::Quota => "cgroup CPU quota",
                    _ => "CPU affinity mask",
                }
            ));
        }
        clauses.push(cores);
        if let Some(need) = below_min.or(below_rec) {
            level = if below_min.is_some() {
                Level::Fail
            } else {
                raise(level, Level::Warn)
            };
            fixes.push(cores_fix(facts, need, have));
        }
        // The count is an upper bound when a limit file could not be read. If the minimum is met on
        // that count, it may not be met in fact, so the check cannot pass (03, degrade rule).
        if let Some(need) = self.min.or(self.recommended)
            && below_min.is_none()
            && !facts.gaps.is_empty()
        {
            level = raise(level, Level::Warn);
            let said: Vec<&str> = facts.gaps.iter().map(|g| g.said()).collect();
            clauses.push(format!("not verified: {}", said.join(" and ")));
            fixes.extend(facts.gaps.iter().map(|g| g.fix(need)));
            unseen.push("A CPU limit that could lower the count was not read.");
        }

        // Architecture.
        if !self.arch.is_empty() {
            let allowed = self.arch.join(" or ");
            match &facts.arch {
                Some(found) if self.arch.contains(found) => clauses.push(format!("arch {found}")),
                Some(found) => {
                    level = Level::Fail;
                    clauses.push(format!("arch is {found}, the spec allows {allowed}"));
                    fixes.push(format!(
                        "Use a host or instance type with {allowed}. This product does not run on {found}."
                    ));
                }
                None => {
                    level = raise(level, Level::Warn);
                    unseen.push("The architecture was not read.");
                    clauses.push(format!(
                        "could not read the architecture, the spec allows {allowed}"
                    ));
                    fixes.push(format!(
                        "Check the host architecture by hand and confirm it is {allowed}."
                    ));
                }
            }
        }

        // Features.
        let mut flag_map = Map::new();
        if !self.flags.is_empty() {
            let (missing, unknown) = self.check_flags(facts, x86, &mut flag_map, &mut notes);
            if !missing.is_empty() {
                level = Level::Fail;
                clauses.push(format!("missing CPU flags: {}", list(&missing)));
                fixes.push(flags_fix(facts, &missing));
            } else if unknown {
                level = raise(level, Level::Warn);
                unseen.push("The CPU flags were not read.");
                clauses.push("could not read the CPU flags".to_owned());
                fixes.push(
                    "Check the flags line of /proc/cpuinfo by hand, or run rdy where /proc/cpuinfo is readable."
                        .to_owned(),
                );
            } else {
                clauses.push(format!("flags present: {}", list(&self.flags)));
            }
        }

        if facts.limit == Limit::Quota
            && let Some(quota) = &facts.quota
        {
            notes.push(format!(
                "The CPU quota is {}/{} microseconds, set at cgroup {}.",
                quota.value.quota_us, quota.value.period_us, quota.at
            ));
        }

        let mut finding = Finding::new(level, clauses.join("; "))
            .with_observed(self.observed(facts, x86, flag_map))
            .with_expected(self.expected());
        if level != Level::Pass {
            finding = finding.with_fix(fixes.join(" "));
        }
        for note in notes {
            finding = finding.with_note(note);
        }
        if !unseen.is_empty() {
            finding = finding.with_partial(Partial::new(Vec::new(), unseen.join(" ")));
        }
        finding
    }

    /// Looks each wanted flag up. Returns the names that are missing, and whether any could not be
    /// judged. `map` gets `true` or `false` for each name that could.
    fn check_flags(
        &self,
        facts: &Facts,
        x86: bool,
        map: &mut Map<String, Value>,
        notes: &mut Vec<String>,
    ) -> (Vec<String>, bool) {
        let mut missing = Vec::new();
        let mut unknown = false;
        for name in &self.flags {
            if let Some(level) = parse::level_of(name) {
                if facts.arch.is_some() && !x86 {
                    notes.push(format!(
                        "{name} is an x86_64 level and this host is {}.",
                        facts.arch.as_deref().unwrap_or_default()
                    ));
                    map.insert(name.clone(), Value::Bool(false));
                    missing.push(name.clone());
                    continue;
                }
                let Some(flags) = &facts.flags else {
                    unknown = true;
                    continue;
                };
                let gaps = parse::level_gaps(flags, level);
                if gaps.is_empty() {
                    map.insert(name.clone(), Value::Bool(true));
                } else {
                    let gaps: Vec<String> = gaps.iter().map(|g| (*g).to_owned()).collect();
                    notes.push(format!("{name} is not met: the CPU lacks {}.", list(&gaps)));
                    map.insert(name.clone(), Value::Bool(false));
                    missing.push(name.clone());
                }
            } else if let Some(flags) = &facts.flags {
                let present = parse::has_feature(flags, name);
                map.insert(name.clone(), Value::Bool(present));
                if !present {
                    missing.push(name.clone());
                }
            } else {
                unknown = true;
            }
        }
        (missing, unknown)
    }

    fn observed(&self, facts: &Facts, x86: bool, flags: Map<String, Value>) -> Value {
        let level = if x86 {
            facts.flags.as_ref().map(parse::x86_level)
        } else {
            None
        };
        let hypervisor = match facts.virt {
            Virt::Vm => Some(true),
            Virt::None => Some(false),
            Virt::Unknown => None,
        };
        json!({
            "logical_cores": facts.online,
            "allowed_cores": facts.usable,
            "quota_cores": facts.quota.as_ref().map(|q| q.value.cores()),
            "effective_cores": milli_f64(facts.effective_milli),
            "physical_cores": facts.physical,
            "arch": facts.arch,
            "hypervisor": hypervisor,
            "virtualization": facts.virt.word(),
            "x86_64_level": level,
            "flags": flags,
        })
    }

    fn expected(&self) -> Value {
        let mut map = Map::new();
        if let Some(min) = self.min {
            map.insert("min".to_owned(), json!(min));
        }
        if let Some(rec) = self.recommended {
            map.insert("recommended".to_owned(), json!(rec));
        }
        if !self.arch.is_empty() {
            map.insert("arch".to_owned(), json!(self.arch));
        }
        if !self.flags.is_empty() {
            map.insert("flags".to_owned(), json!(self.flags));
        }
        Value::Object(map)
    }
}

impl Check for CpuCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// The name `uname` uses for an architecture in the spec.
fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 | Arch::Amd64 => "x86_64",
        Arch::Aarch64 | Arch::Arm64 => "aarch64",
        // `Arch` can grow. A name this build does not know matches no host, so the check blocks and
        // names it, rather than letting an unreadable spec entry pass.
        _ => "unknown",
    }
}

/// The higher of two levels, fail over warn over pass.
fn raise(have: Level, new: Level) -> Level {
    match (have, new) {
        (Level::Fail, _) | (_, Level::Fail) => Level::Fail,
        (Level::Warn, _) | (_, Level::Warn) => Level::Warn,
        _ => Level::Pass,
    }
}

/// The quota as thousandths of a CPU: `200000/100000` is 2000.
fn quota_milli(quota: &CpuQuota) -> u64 {
    let milli = u128::from(quota.quota_us) * 1000 / u128::from(quota.period_us.max(1));
    u64::try_from(milli).unwrap_or(u64::MAX)
}

fn milli_f64(milli: u64) -> f64 {
    // A CPU count in thousandths is far below 2^53, so the conversion is exact.
    milli as f64 / 1000.0
}

/// `8 vCPUs`, `1 vCPU`, `1.5 vCPUs`. A fraction is cut to one decimal, never rounded up.
fn vcpus(milli: u64) -> String {
    let whole = milli / 1000;
    let tenth = (milli % 1000) / 100;
    if tenth == 0 {
        if whole == 1 {
            "1 vCPU".to_owned()
        } else {
            format!("{whole} vCPUs")
        }
    } else {
        format!("{whole}.{tenth} vCPUs")
    }
}

/// `avx2`, `avx2 and bmi2`, or the first few and a count.
fn list(names: &[String]) -> String {
    if names.len() > LIST_MAX {
        let shown: Vec<&str> = names.iter().take(LIST_MAX).map(String::as_str).collect();
        return format!("{} and {} more", shown.join(", "), names.len() - LIST_MAX);
    }
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The fix for too few CPUs, by what limits the count.
fn cores_fix(facts: &Facts, need: u16, have_milli: u64) -> String {
    let have = vcpus(have_milli);
    match facts.limit {
        Limit::Quota => format!(
            "A cgroup CPU quota caps rdy at {have}. Raise it to {need} or more: `--cpus` for Docker, `resources.limits.cpu` for a pod, or `CPUQuota=` in the systemd unit. Or resize the instance."
        ),
        Limit::Affinity => format!(
            "A CPU affinity mask limits rdy to {have}. Allow {need} or more: `--cpuset-cpus` for Docker, `AllowedCPUs=` in the systemd unit, or the cpuset of the pod. Or resize the instance."
        ),
        Limit::Hardware => {
            format!("Resize the instance to at least {need} vCPUs. This host has {have}.")
        }
    }
}

/// The fix for missing CPU features, by whether the machine is a VM.
fn flags_fix(facts: &Facts, missing: &[String]) -> String {
    let names = list(missing);
    match facts.virt {
        Virt::None => format!("This CPU has no {names}. Use a CPU generation that has it."),
        Virt::Vm | Virt::Unknown => format!(
            "The CPU shows no {names}. In your own hypervisor, set the VM CPU model to host passthrough (libvirt `<cpu mode='host-passthrough'/>`), turn off VMware EVC masking, or on Hyper-V run `Set-VMProcessor -VMName <name> -CompatibilityForMigrationEnabled $false` on the hypervisor. In a public cloud the CPU model is fixed: pick an instance type whose CPU has it."
        ),
    }
}

/// What reading a file gave.
enum Got {
    Text { text: String, cut: bool },
    Absent,
    Unreadable(String),
}

async fn read(ctx: &CheckContext, path: &str) -> Result<Got, CheckError> {
    match ctx.probe().read(Path::new(path)).await {
        Ok(file) => Ok(Got::Text {
            text: String::from_utf8_lossy(&file.bytes).into_owned(),
            cut: file.truncated(),
        }),
        Err(error) => match soft(error)? {
            ProbeError::NotFound => Ok(Got::Absent),
            other => Ok(Got::Unreadable(short(&other))),
        },
    }
}

/// A CPU list file such as `/sys/devices/system/cpu/online`.
async fn read_list(ctx: &CheckContext, path: &str) -> Result<Option<CpuList>, CheckError> {
    Ok(match read(ctx, path).await? {
        Got::Text { text, .. } => CpuList::parse(&text),
        Got::Absent | Got::Unreadable(_) => None,
    })
}

async fn read_cpuinfo(
    ctx: &CheckContext,
    notes: &mut Vec<String>,
) -> Result<Option<CpuInfo>, CheckError> {
    Ok(match read(ctx, CPUINFO).await? {
        Got::Text { text, cut } => {
            if cut {
                notes.push(
                    "/proc/cpuinfo is longer than rdy reads. The CPU flags are judged on the part it read."
                        .to_owned(),
                );
            }
            Some(parse::parse_cpuinfo(&text, cut))
        }
        Got::Absent => {
            notes
                .push("/proc/cpuinfo does not exist here, so CPU flags cannot be read.".to_owned());
            None
        }
        Got::Unreadable(why) => {
            notes.push(format!("/proc/cpuinfo could not be read ({why})."));
            None
        }
    })
}

/// The CPUs `Cpus_allowed_list` in `/proc/self/status` allows. When the file is missing, unreadable
/// or has no such line, a note says so and the count cannot be called verified.
async fn read_allowed(
    ctx: &CheckContext,
    notes: &mut Vec<String>,
    gaps: &mut Vec<Gap>,
) -> Result<Option<CpuList>, CheckError> {
    let allowed = match read(ctx, STATUS).await? {
        Got::Text { text, .. } => {
            let list = parse::allowed_list(&text);
            if list.is_none() {
                notes.push(format!(
                    "{STATUS} has no usable Cpus_allowed_list line, so a CPU affinity mask is not counted."
                ));
            }
            list
        }
        Got::Absent => {
            notes.push(format!(
                "{STATUS} does not exist here, so a CPU affinity mask is not counted."
            ));
            None
        }
        Got::Unreadable(why) => {
            notes.push(format!(
                "{STATUS} could not be read ({why}), so a CPU affinity mask is not counted."
            ));
            None
        }
    };
    if allowed.is_none() {
        gaps.push(Gap::Affinity);
    }
    Ok(allowed)
}

/// The smallest CPU quota on the cgroup chain, and whether a limit file could not be read (then the
/// quota may be missing or too high). A problem reading it is a note and a flag, not a failure.
async fn read_quota(
    ctx: &CheckContext,
    notes: &mut Vec<String>,
) -> Result<(Option<Bound<CpuQuota>>, bool), CheckError> {
    let probe = ctx.probe();
    let found = match Cgroups::discover(probe).await {
        Ok(Some(cgroups)) => cgroups.cpu(probe).await,
        Ok(None) => return Ok((None, false)),
        Err(error) => Err(error),
    };
    match found {
        Ok(cpu) => {
            let mut unverified = false;
            if !cpu.quota.is_complete() {
                unverified = true;
                notes.push(
                    "Some cgroup CPU limit files could not be read, so a CPU limit may be missing."
                        .to_owned(),
                );
            } else if cpu.quota.min.is_none() && cpu.quota.hidden_above {
                notes.push(
                    "rdy sees only part of the cgroup tree, so a CPU limit set above it may be missing."
                        .to_owned(),
                );
            }
            Ok((cpu.quota.min, unverified))
        }
        Err(CgroupError::Malformed { file, reason }) => {
            notes.push(format!(
                "{file} is not in the expected form ({reason}), so cgroup CPU limits were not counted."
            ));
            Ok((None, true))
        }
        Err(CgroupError::Probe(error)) => {
            let other = soft(error)?;
            notes.push(format!(
                "The cgroup CPU limits could not be read ({}).",
                short(&other)
            ));
            Ok((None, true))
        }
    }
}

/// The machine type from `uname`, folded to `x86_64` or `aarch64`.
async fn read_arch(ctx: &CheckContext) -> Result<Option<String>, CheckError> {
    match ctx.probe().native(NativeCall::Uname).await {
        Ok(NativeValue::Uname(uname)) => Ok(Some(parse::normalize_arch(&uname.machine))),
        Ok(_) => Ok(None),
        Err(error) => {
            soft(error)?;
            Ok(None)
        }
    }
}

/// Whether this is a VM. On x86 the `hypervisor` flag settles it; on Arm the DMI text and the Xen type
/// are read, and only then.
async fn read_virt(
    ctx: &CheckContext,
    x86: bool,
    flags: Option<&BTreeSet<String>>,
) -> Result<Virt, CheckError> {
    if x86 {
        return Ok(match flags {
            Some(flags) if flags.contains("hypervisor") => Virt::Vm,
            Some(_) => Virt::None,
            None => Virt::Unknown,
        });
    }
    if matches!(read(ctx, HYPERVISOR_TYPE).await?, Got::Text { .. }) {
        return Ok(Virt::Vm);
    }
    let mut readable = false;
    for path in [DMI_PRODUCT, DMI_VENDOR] {
        if let Got::Text { text, .. } = read(ctx, path).await? {
            readable = true;
            if parse::looks_virtual(&text) {
                return Ok(Virt::Vm);
            }
        }
    }
    Ok(if readable { Virt::None } else { Virt::Unknown })
}
