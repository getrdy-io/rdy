//! Parameters of the seven M1 host check ids.
//!
//! The fields, ranges and defaults follow `$defs` in `crates/rdy-spec/schema/spec.v1.schema.json` and
//! the table in `docs/plan/01-spec-format.md` section 2.7. What each threshold means to the check is in
//! `docs/plan/03-check-catalog.md`.
//!
//! Every struct refuses a key it does not have. Where 01 requires a threshold, the struct names the key
//! or keys in [`ParamSet::THRESHOLD`], and an entry without one decodes to
//! [`UnsupportedReason::NoThreshold`](super::UnsupportedReason::NoThreshold).
//!
//! A default that the schema gives for an enum is applied while reading, so the field is not an
//! `Option`. A default that depends on another field, such as "half of `min`", is left to the check, and
//! the field is an `Option`.

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::ParamSet;
use super::common::{
    AbsPath, Arch, BoundedList, Cores, CpuFlag, DistroId, FsType, OsVersion, Port, StringList,
    TolerancePercent, from_value,
};
use crate::scalar::{Duration, Quantity};

/// Parameters of `host.cpu`: cores, architecture and CPU flags.
///
/// At least one of `min`, `arch` and `flags` is required. A list of `arch` or `flags` is not empty.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostCpu {
    /// Fewer cores than this: the check fails. Container limits count.
    pub min: Option<Cores>,
    /// Fewer cores than this: the check warns.
    pub recommended: Option<Cores>,
    /// The host must have one of these architectures. `amd64` is `x86_64` and `arm64` is `aarch64`.
    pub arch: Option<BoundedList<Arch, 4, true, 1>>,
    /// CPU flags the host must have, such as `avx2` or `x86-64-v3`. At most 64.
    pub flags: Option<BoundedList<CpuFlag, 64, false, 1>>,
}

impl ParamSet for HostCpu {
    const FIELDS: &'static [&'static str] = &["min", "recommended", "arch", "flags"];
    const THRESHOLD: &'static [&'static str] = &["min", "arch", "flags"];
    const THRESHOLD_EXAMPLE: &'static str = "min: 4";
}

/// What `host.memory` does about swap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SwapPolicy {
    /// Swap must be off.
    Forbid,
    /// Swap may be on. This is the default.
    #[default]
    Any,
}

/// What a total inside the tolerance of `host.memory` counts as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ToleranceResult {
    /// It passes, with a note. This is the default.
    #[default]
    Pass,
    /// It warns.
    Warn,
}

/// Parameters of `host.memory`: total and available RAM, and swap.
///
/// `min` is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostMemory {
    /// Less total RAM than this: the check fails, after the tolerance.
    pub min: Quantity,
    /// Less available RAM than this: the check warns. The default, half of `min`, is the check's.
    pub min_available: Option<Quantity>,
    /// What to do when swap is on. The default is [`SwapPolicy::Any`].
    #[serde(default)]
    pub swap: SwapPolicy,
    /// How far below `min` the total may be and still pass, in percent. A 32 GiB machine shows a
    /// little less. The default is 5. The check applies it with a floor of 256 MiB. 0 turns it off.
    #[serde(default)]
    pub tolerance_percent: TolerancePercent,
    /// What a total inside the tolerance counts as. The default is [`ToleranceResult::Pass`].
    #[serde(default)]
    pub tolerance_result: ToleranceResult,
}

impl ParamSet for HostMemory {
    const FIELDS: &'static [&'static str] = &[
        "min",
        "min_available",
        "swap",
        "tolerance_percent",
        "tolerance_result",
    ];
    const THRESHOLD: &'static [&'static str] = &["min"];
    const THRESHOLD_EXAMPLE: &'static str = "min: 8Gi";
}

/// A mount option that `host.disk` can forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum MountOption {
    /// Programs cannot run from the mount.
    Noexec,
    /// Set-user-id bits are ignored.
    Nosuid,
    /// Device files are ignored.
    Nodev,
    /// The mount is read only.
    Ro,
}

/// Parameters of `host.disk`: free space, inodes and mount rules for one path.
///
/// `path` and `min` are required. Repeat the id with a `name` to check more paths.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostDisk {
    /// The install path. When it does not exist yet, the nearest existing parent is measured.
    pub path: AbsPath,
    /// Less free space than this: the check fails.
    pub min: Quantity,
    /// Less free space than this: the check warns. The default, `min` plus 20%, is the check's.
    pub recommended: Option<Quantity>,
    /// Fewer free inodes than this: the check fails.
    pub min_inodes: Option<u64>,
    /// Mount options that make the check fail.
    pub forbid_options: Option<BoundedList<MountOption, 4, true>>,
    /// Filesystem types that make the check fail, such as `nfs`. At most 32.
    pub forbid_fstypes: Option<BoundedList<FsType, 32>>,
}

impl ParamSet for HostDisk {
    const FIELDS: &'static [&'static str] = &[
        "path",
        "min",
        "recommended",
        "min_inodes",
        "forbid_options",
        "forbid_fstypes",
    ];
    const THRESHOLD: &'static [&'static str] = &["min"];
    const THRESHOLD_EXAMPLE: &'static str = "min: 20Gi";
    const ALSO_REQUIRED: &'static [&'static str] = &["path"];
}

/// Which addresses a required port must be free on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Bind {
    /// The product listens on every address. This is the default.
    #[default]
    Public,
    /// The product listens on loopback only.
    Loopback,
}

/// A TCP port that must be free, and how the product binds it.
///
/// In a spec it is a bare port, which means [`Bind::Public`], or `{port, bind}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PortRule {
    /// The port.
    pub port: Port,
    /// How the product binds it.
    pub bind: Bind,
}

impl<'de> Deserialize<'de> for PortRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            port: Port,
            #[serde(default)]
            bind: Bind,
        }
        // Reading the value first keeps the messages of the inner readers. An untagged enum would
        // only say that no variant fit.
        match Value::deserialize(deserializer)? {
            value @ Value::Object(_) => {
                let Full { port, bind } = from_value(value)?;
                Ok(Self { port, bind })
            }
            value => Ok(Self {
                port: from_value(value)?,
                bind: Bind::Public,
            }),
        }
    }
}

/// Parameters of `host.ports`: ports that must be free.
///
/// At least one of `free` and `udp_free` is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostPorts {
    /// TCP ports that must be free. At most 256.
    pub free: Option<BoundedList<PortRule, 256, false, 1>>,
    /// UDP ports that must be free. At most 256, none twice.
    pub udp_free: Option<BoundedList<Port, 256, true, 1>>,
    /// Process names that may already hold a port, such as an earlier install of the product.
    pub allow_owner: Option<StringList>,
}

impl ParamSet for HostPorts {
    const FIELDS: &'static [&'static str] = &["free", "udp_free", "allow_owner"];
    const THRESHOLD: &'static [&'static str] = &["free", "udp_free"];
}

/// An SELinux mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SelinuxMode {
    /// Policy is enforced.
    Enforcing,
    /// Violations are logged only.
    Permissive,
    /// SELinux is off.
    Disabled,
}

/// What `host.lsm` expects of SELinux.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SelinuxPolicy {
    /// The modes that are fine. Any other mode makes the check fail. Without it every mode is fine.
    pub allow: Option<BoundedList<SelinuxMode, 3, true>>,
    /// More recent denials than this: the check warns. It fails when the context is in `watch`.
    pub denials_max: Option<u32>,
    /// How far back denials count, such as `24h`.
    pub denials_window: Option<Duration>,
    /// Security contexts or programs whose denials make the check fail.
    pub watch: Option<StringList>,
}

/// An AppArmor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ApparmorMode {
    /// AppArmor is on.
    Enabled,
    /// AppArmor is off.
    Disabled,
}

/// What `host.lsm` expects of AppArmor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ApparmorPolicy {
    /// The states that are fine. Any other state makes the check fail.
    pub allow: Option<BoundedList<ApparmorMode, 2, true>>,
    /// Profiles that must be loaded.
    pub require_profiles: Option<StringList>,
}

/// Parameters of `host.lsm`: SELinux and AppArmor state.
///
/// Both keys are optional. With neither, the check only reports what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostLsm {
    /// What to expect of SELinux.
    pub selinux: Option<SelinuxPolicy>,
    /// What to expect of AppArmor.
    pub apparmor: Option<ApparmorPolicy>,
}

impl ParamSet for HostLsm {
    const FIELDS: &'static [&'static str] = &["selinux", "apparmor"];
}

/// Parameters of `host.security_agents`: security software that may get in the way.
///
/// Both keys are optional. With neither, any detected agent is a warning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostSecurityAgents {
    /// Agent ids that make the check fail when detected. `rdy spec lint` lists the known ids.
    pub forbid: Option<StringList>,
    /// Agent ids that are fine when detected.
    pub allow: Option<StringList>,
}

impl ParamSet for HostSecurityAgents {
    const FIELDS: &'static [&'static str] = &["forbid", "allow"];
}

/// What `host.os` expects of FIPS mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum FipsPolicy {
    /// FIPS mode must be off.
    Forbid,
    /// FIPS mode must be on.
    Require,
    /// Either is fine. This is the default.
    #[default]
    Any,
}

/// A distribution the product supports, with the versions that count.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SupportedOs {
    /// The distribution id from `/etc/os-release`, such as `rhel`.
    pub id: DistroId,
    /// The versions that are supported. `"8"` matches a major version and `"22.04"` an exact one.
    /// Without it every version is.
    pub versions: Option<Vec<OsVersion>>,
}

/// Parameters of `host.os`: distribution, architecture and FIPS mode.
///
/// Every key is optional. With none, the check only reports what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostOs {
    /// The distributions the product supports. At most 64.
    pub supported: Option<BoundedList<SupportedOs, 64>>,
    /// The host must have one of these architectures.
    pub arch: Option<BoundedList<Arch, 4, true>>,
    /// What to expect of FIPS mode. The default is [`FipsPolicy::Any`].
    #[serde(default)]
    pub fips: FipsPolicy,
    /// The lowest Windows build number that is supported.
    pub windows_min_build: Option<u32>,
}

impl ParamSet for HostOs {
    const FIELDS: &'static [&'static str] = &["supported", "arch", "fips", "windows_min_build"];
}

#[cfg(test)]
mod tests;
