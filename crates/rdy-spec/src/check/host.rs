//! Parameters of the host check ids: the seven M1 ids and the six M1-late ids.
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
    AbsPath, Arch, BoundedList, BoundedMap, CgroupController, Cores, CpuFlag, DistroId, FsType,
    MAX_HOST_PORT_CHARS, ModuleName, OsVersion, Port, StorageDriver, StringList, TolerancePercent,
    from_value, host_with_default_port,
};
use crate::error::echo_safe;
use crate::scalar::{Duration, Host, Quantity, Target, Version, redact_for_echo};

/// Builds a deserialize error from a message.
fn bad<E: serde::de::Error>(message: impl std::fmt::Display) -> E {
    E::custom(message)
}

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

// ---- the M1-late ids ----------------------------------------------------------------------------

/// Parameters of `host.firewall`: is the host firewall in the way of the inbound ports.
///
/// The key is optional. With none, the check reports which firewall manager is active.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostFirewall {
    /// TCP ports that must be open for inbound traffic, 1 to 256, none twice.
    pub open_inbound: Option<BoundedList<Port, 256, true, 1>>,
}

impl ParamSet for HostFirewall {
    const FIELDS: &'static [&'static str] = &["open_inbound"];
}

/// A time server for the offset probe of `host.time_sync`: a name or address, with a port when written.
///
/// It is read with the grammar of [`Target`], like [`TlsHost`](super::TlsHost). A bare IPv6 address
/// (`fd00:ec2::123`) and a bracketed one (`[fd00:ec2::123]:123`) are both accepted. The port is optional
/// and then 123 applies. A URL is refused. Parsing does not classify an address: the probe applies the
/// egress policy of ADR 0009 before it sends a packet. Two servers are equal when they name the same
/// host and port, so `ntp.acme.example` and `ntp.acme.example:123` are the same server.
#[derive(Debug, Clone)]
pub struct NtpServer {
    target: Target,
    port_written: bool,
}

impl PartialEq for NtpServer {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
    }
}

impl Eq for NtpServer {}

impl std::hash::Hash for NtpServer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.target.hash(state);
    }
}

impl NtpServer {
    /// The longest server in characters: a 253 character name, a colon and a 5 digit port.
    pub const MAX_CHARS: usize = MAX_HOST_PORT_CHARS;

    /// The port that applies when the spec has none.
    pub const DEFAULT_PORT: u16 = 123;

    /// The host.
    #[must_use]
    pub fn host(&self) -> &Host {
        self.target.host()
    }

    /// The port as written, or `None` when the spec has none and [`NtpServer::DEFAULT_PORT`] applies.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port_written.then(|| self.target.port())
    }

    /// The port to use: the one written, or 123.
    #[must_use]
    pub fn port_or_default(&self) -> u16 {
        self.target.port()
    }
}

impl<'de> Deserialize<'de> for NtpServer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match host_with_default_port(&text, Self::DEFAULT_PORT)
            .map(|(full, port_written)| (Target::parse(&full), port_written))
        {
            Some((Ok(target), port_written)) => Ok(Self {
                target,
                port_written,
            }),
            _ => Err(bad(format!(
                "'{}' is not a time server: write a name or address, with an optional :port",
                echo_safe(&redact_for_echo(&text))
            ))),
        }
    }
}

/// Parameters of `host.time_sync`: is the clock synchronized, and how far off is it.
///
/// Every key is optional. With none, the check reports the sync state and does not measure an offset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostTimeSync {
    /// The offset from the time servers above which the check blocks. The default, 300s, is the check's,
    /// because AWS signing, Kerberos and TLS validity fail near five minutes. The warning level is
    /// `recommended_skew`.
    pub max_skew: Option<Duration>,
    /// The offset above which the check warns. The default, 5s, is the check's. Set `max_skew` as well to
    /// move the block level.
    pub recommended_skew: Option<Duration>,
    /// A clock that is not synchronized blocks. The default is false.
    #[serde(default)]
    pub require_sync: bool,
    /// Servers to measure the offset against, 1 to 8, none twice. There are no default servers: without
    /// this list the offset is not measured and rdy sends no time packet.
    pub ntp_servers: Option<BoundedList<NtpServer, 8, true, 1>>,
}

impl ParamSet for HostTimeSync {
    const FIELDS: &'static [&'static str] = &[
        "max_skew",
        "recommended_skew",
        "require_sync",
        "ntp_servers",
    ];
}

/// A comparison for a value of `host.sysctl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Compare {
    /// The value is this one.
    Equal,
    /// The value is a whole number and at least this.
    AtLeast,
    /// The value is a whole number and at most this.
    AtMost,
}

/// What a kernel value or a limit must be: `1`, `bbr`, `">=262144"` or `"<=1024"`.
///
/// A bare whole number in a spec means [`Compare::Equal`], as does any text that starts with neither
/// `>=` nor `<=`. After `>=` or `<=` come a whole number, with one optional space before it. The text
/// is 1 to 128 characters with no control character and no space at either end, and does not start with
/// an operator unless it is one of the two comparisons. The characters `<`, `>`, `=`, `!`, `~`, `≥`, `≤`
/// and `≠` are refused there, so `"!=0"` and `"≥5"` are errors and not an equality that always fails.
///
/// A value such as `4096 87380 6291456` (`net.ipv4.tcp_rmem`) is compared as text. The kernel prints
/// it with tabs and a vendor writes it with spaces, so `host.sysctl` (M1-149) must treat a tab and a
/// space as the same, and any run of them as one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ValueRule {
    /// How the value is compared.
    pub compare: Compare,
    /// The value, as written, without the comparison.
    pub value: String,
}

impl ValueRule {
    /// The most characters of a value.
    pub const MAX_CHARS: usize = 128;

    /// The value as a whole number, or `None` for text that is not one.
    #[must_use]
    pub fn integer(&self) -> Option<i64> {
        self.value.parse().ok()
    }

    fn parse(text: &str) -> Option<Self> {
        for (prefix, compare) in [(">=", Compare::AtLeast), ("<=", Compare::AtMost)] {
            if let Some(rest) = text.strip_prefix(prefix) {
                let number = rest.strip_prefix(' ').unwrap_or(rest);
                let digits = number.strip_prefix('-').unwrap_or(number);
                let shape =
                    (1..=18).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit());
                return shape.then(|| Self {
                    compare,
                    value: number.to_owned(),
                });
            }
        }
        let first = text.chars().next()?;
        let last = text.chars().next_back()?;
        let shape = text.chars().count() <= Self::MAX_CHARS
            && !matches!(first, '<' | '>' | '=' | '!' | '~' | '≥' | '≤' | '≠')
            && !first.is_whitespace()
            && !last.is_whitespace()
            && !text.chars().any(char::is_control);
        shape.then(|| Self {
            compare: Compare::Equal,
            value: text.to_owned(),
        })
    }
}

impl<'de> Deserialize<'de> for ValueRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let text = match &value {
            Value::String(text) => text.clone(),
            Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
            _ => String::new(),
        };
        Self::parse(&text).ok_or_else(|| {
            let shown = match &value {
                Value::String(text) => echo_safe(text),
                other => echo_safe(&other.to_string()),
            };
            bad(format!(
                "'{shown}' is not a value to expect: write a value such as 1 or bbr, \
                 or a comparison such as \">=262144\" or \"<=1024\""
            ))
        })
    }
}

/// A kernel parameter name for `host.sysctl`, such as `vm.max_map_count`.
///
/// With dots as separators, a name is dot-separated parts. With slashes, as in
/// `net/ipv4/conf/eth0.100/rp_filter`, a part may hold dots, for the name of an interface. A part
/// starts with a letter, a digit or `_`, so no part is empty, `.` or `..`. The name is at most 128
/// characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SysctlName(String);

impl SysctlName {
    /// The longest name in characters.
    pub const MAX_CHARS: usize = 128;

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name as a path under `/proc/sys`, with slashes: `vm/max_map_count` for both
    /// `vm.max_map_count` and `vm/max_map_count`. Two names with the same path are the same parameter.
    #[must_use]
    pub fn canonical(&self) -> String {
        if self.0.contains('/') {
            self.0.clone()
        } else {
            self.0.replace('.', "/")
        }
    }

    fn is_valid(text: &str) -> bool {
        let start = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let (separator, inner): (char, fn(char) -> bool) = if text.contains('/') {
            ('/', |c| {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
            })
        } else {
            ('.', |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        };
        text.chars().count() <= Self::MAX_CHARS
            && text
                .split(separator)
                .all(|part| part.chars().next().is_some_and(start) && part.chars().all(inner))
    }
}

impl<'de> Deserialize<'de> for SysctlName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if Self::is_valid(&text) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a kernel parameter name: write it like vm.max_map_count, or with \
                 slashes like net/ipv4/conf/eth0.100/rp_filter",
                echo_safe(&text)
            )))
        }
    }
}

/// The limits that `host.sysctl` can check. At least one is set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SysctlLimits {
    /// The open files limit that services get, `DefaultLimitNOFILE` of systemd.
    pub nofile: Option<ValueRule>,
}

impl<'de> Deserialize<'de> for SysctlLimits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            nofile: Option<ValueRule>,
        }
        let Raw { nofile } = Raw::deserialize(deserializer)?;
        if nofile.is_none() {
            return Err(bad("no limit is set: write nofile"));
        }
        Ok(Self { nofile })
    }
}

/// Reads `expect` and refuses a parameter written twice, once with dots and once with slashes.
fn expect_once<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BoundedMap<SysctlName, ValueRule, 64, 1>>, D::Error> {
    let expect = Option::<BoundedMap<SysctlName, ValueRule, 64, 1>>::deserialize(deserializer)?;
    let mut seen = std::collections::HashMap::new();
    for name in expect.iter().flat_map(|map| map.keys()) {
        if let Some(first) = seen.insert(name.canonical(), name) {
            return Err(bad(format!(
                "'{}' and '{}' are the same kernel parameter: write it once",
                echo_safe(first.as_str()),
                echo_safe(name.as_str())
            )));
        }
    }
    Ok(expect)
}

/// Parameters of `host.sysctl`: kernel parameters and limits.
///
/// At least one of `expect` and `limits` is required. There are no built-in values.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostSysctl {
    /// Kernel parameters and what each must be, 1 to 64. A live value that differs blocks. A right
    /// value that no file in a `sysctl.d` directory sets warns. `vm.max_map_count` and
    /// `vm/max_map_count` are the same parameter, so writing both is refused.
    #[serde(default, deserialize_with = "expect_once")]
    pub expect: Option<BoundedMap<SysctlName, ValueRule, 64, 1>>,
    /// File limits and what each must be.
    pub limits: Option<SysctlLimits>,
}

impl ParamSet for HostSysctl {
    const FIELDS: &'static [&'static str] = &["expect", "limits"];
    const THRESHOLD: &'static [&'static str] = &["expect", "limits"];
}

/// A container runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ContainerRuntime {
    /// Docker Engine.
    Docker,
    /// containerd.
    Containerd,
    /// Podman.
    Podman,
    /// CRI-O.
    Crio,
}

/// The cgroup driver of a container runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum CgroupDriver {
    /// systemd manages the cgroups.
    Systemd,
    /// The runtime manages the cgroups itself.
    Cgroupfs,
}

/// Parameters of `host.container_runtime`: which runtime is present and how it is set up.
///
/// Every key is optional. With none, the check blocks when no runtime is found and reports what it
/// finds.
///
/// `min_version` needs `runtime` with exactly one entry. One number means nothing across several
/// runtimes, and a per-runtime form can be added later without breaking this one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostContainerRuntime {
    /// Runtimes of which one must be present, 1 to 4.
    pub runtime: Option<BoundedList<ContainerRuntime, 4, true, 1>>,
    /// An older runtime blocks. It applies to the one runtime named in `runtime`.
    pub min_version: Option<Version>,
    /// The cgroup driver the runtime must use. A runtime that differs from the kubelet blocks too.
    pub cgroup_driver: Option<CgroupDriver>,
    /// The storage driver the runtime must use, such as `overlay2`.
    pub storage_driver: Option<StorageDriver>,
}

impl<'de> Deserialize<'de> for HostContainerRuntime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            runtime: Option<BoundedList<ContainerRuntime, 4, true, 1>>,
            min_version: Option<Version>,
            cgroup_driver: Option<CgroupDriver>,
            storage_driver: Option<StorageDriver>,
        }
        let Raw {
            runtime,
            min_version,
            cgroup_driver,
            storage_driver,
        } = Raw::deserialize(deserializer)?;
        if min_version.is_some() && runtime.as_ref().is_none_or(|list| list.len() != 1) {
            return Err(bad(
                "min_version needs runtime with exactly one entry, such as runtime: [containerd]: \
                 one version number means nothing across several runtimes",
            ));
        }
        Ok(Self {
            runtime,
            min_version,
            cgroup_driver,
            storage_driver,
        })
    }
}

impl ParamSet for HostContainerRuntime {
    const FIELDS: &'static [&'static str] =
        &["runtime", "min_version", "cgroup_driver", "storage_driver"];
}

/// The cgroup version that `host.cgroups` requires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum CgroupVersion {
    /// The unified hierarchy.
    #[serde(rename = "v2")]
    V2,
    /// The legacy hierarchy.
    #[serde(rename = "v1")]
    V1,
    /// Any version is fine. This is the default.
    #[default]
    #[serde(rename = "any")]
    Any,
}

/// Parameters of `host.cgroups`: the cgroup version and controllers.
///
/// Both keys are optional. With neither, the check only reports what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostCgroups {
    /// The cgroup version the host must have. The default is [`CgroupVersion::Any`].
    #[serde(default)]
    pub version: CgroupVersion,
    /// Controllers that must be available, such as `cpu`, `memory`, `io` and `pids`. 1 to 32.
    pub controllers: Option<BoundedList<CgroupController, 32, true, 1>>,
}

impl ParamSet for HostCgroups {
    const FIELDS: &'static [&'static str] = &["version", "controllers"];
}

/// A kernel version for `host.kernel`: dotted numbers with an optional build part, such as `5.4`,
/// `5.14.0` or `4.18.0-305`.
///
/// The part before the first `-` is one to four whole numbers joined by dots, as in [`Version`] but
/// without a leading `v`. The part after it is the same. A bare whole number (`5`) is accepted. An
/// unquoted decimal (`5.10`) is refused, because YAML reads it as the number 5.1: quote it. The text
/// is kept as written. Comparing versions is for the check, which tolerates the longer release strings
/// that vendor kernels report.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelVersion {
    text: String,
    base: Version,
    build: Option<Version>,
}

impl KernelVersion {
    /// The version as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The numbers before the `-`.
    #[must_use]
    pub fn base(&self) -> &Version {
        &self.base
    }

    /// The numbers after the `-`, such as the 305 of `4.18.0-305`.
    #[must_use]
    pub fn build(&self) -> Option<&Version> {
        self.build.as_ref()
    }

    fn parse_text(text: &str) -> Result<Self, String> {
        let (base_text, build_text) = match text.split_once('-') {
            Some((base, build)) => (base, Some(build)),
            None => (text, None),
        };
        let plain = |part: &str| !part.starts_with(['v', 'V']);
        if !plain(base_text) || build_text.is_some_and(|b| !plain(b)) {
            return Err(format!(
                "'{}' is not a kernel version: write numbers like 5.4 or 4.18.0-305, without a v",
                echo_safe(text)
            ));
        }
        let base = Version::parse(base_text).map_err(|e| e.to_string())?;
        let build = build_text
            .map(Version::parse)
            .transpose()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            text: text.to_owned(),
            base,
            build,
        })
    }
}

impl<'de> Deserialize<'de> for KernelVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::String(text) => Self::parse_text(&text).map_err(bad),
            // A whole number reads like a quoted one. A decimal is refused by `Version` with the
            // advice to quote it.
            other => {
                let version: Version = from_value(other)?;
                Ok(Self {
                    text: version.as_str().to_owned(),
                    base: version,
                    build: None,
                })
            }
        }
    }
}

/// Parameters of `host.kernel`: the kernel version and the modules it must have.
///
/// At least one of `min`, `distro_min`, `modules` and `btf: true` is required. `btf: false` alone
/// measures nothing, so it is [`UnsupportedReason::NoThreshold`](super::UnsupportedReason::NoThreshold).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HostKernel {
    /// An older kernel blocks.
    pub min: Option<KernelVersion>,
    /// A minimum for one distribution, by its `/etc/os-release` id, 1 to 16. It replaces `min` on that
    /// distribution, because a vendor kernel carries fixes under an older number.
    pub distro_min: Option<BoundedMap<DistroId, KernelVersion, 16, 1>>,
    /// Modules that must be available, 1 to 64. One that is absent blocks and one that is not loaded
    /// warns.
    pub modules: Option<BoundedList<ModuleName, 64, true, 1>>,
    /// The kernel must expose BTF type information. The default is false. Only `true` counts as a
    /// threshold.
    #[serde(default)]
    pub btf: bool,
}

impl ParamSet for HostKernel {
    const FIELDS: &'static [&'static str] = &["min", "distro_min", "modules", "btf"];
    const THRESHOLD: &'static [&'static str] = &["min", "distro_min", "modules", "btf"];
    const TRUE_ONLY: &'static [&'static str] = &["btf"];
    const THRESHOLD_EXAMPLE: &'static str = "min: \"5.4\"";
}

#[cfg(test)]
mod tests;
