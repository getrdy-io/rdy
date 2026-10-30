//! `host.os`: which Linux this is, on which architecture, and whether FIPS mode is on.
//!
//! Linux only for now. macOS and Windows report "not yet on this OS" until M2-005 adds the `sysinfo`
//! subset. The data sources are `/etc/os-release` (then `/usr/lib/os-release`), `uname` through the
//! facade, `/proc/sys/crypto/fips_enabled`, and a few files and one variable that show whether rdy runs
//! in a container or under WSL.
//!
//! The judgement is a pure function of what was read ([`rules`]). Every source is optional: a file that
//! is missing or unreadable weakens one answer and never ends the check. The spec's `supported`,
//! `arch` and `fips` keys decide what a weak answer costs: with the key set, "cannot tell" is a
//! warning, and without it nothing is asked.
//!
//! `windows_min_build` belongs to the Windows data source (M2-008) and is not read here.

use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Os,
};
use rdy_engine::probe::{NativeCall, NativeValue, ProbeError};
use rdy_spec::check::{Arch, FipsPolicy, HostOs};
use serde_json::{Value, json};

use crate::family::OS;

mod release;
mod rules;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use release::Release;
use rules::{Match, Wanted};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str = "this check reads Linux files and has no data source on this OS yet";

const OS_RELEASE: &str = "/etc/os-release";
/// Where `/etc/os-release` usually points. Also the fallback when the first is missing.
const OS_RELEASE_USR: &str = "/usr/lib/os-release";
const KERNEL_RELEASE: &str = "/proc/sys/kernel/osrelease";
const FIPS_ENABLED: &str = "/proc/sys/crypto/fips_enabled";
const SYSTEMD_DIR: &str = "/run/systemd/system";
const DOCKERENV: &str = "/.dockerenv";
const CONTAINERENV: &str = "/run/.containerenv";
const KUBE_HOST: &str = "KUBERNETES_SERVICE_HOST";

/// The static facts about `host.os` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.os",
    family: "host",
    summary: "Distro, version, arch, FIPS",
    meta: CheckMeta {
        title: "Operating system",
        remediation: "Use an OS image the vendor supports, or ask the vendor about the one you have. If FIPS mode is wrong, change it with the OS vendor's procedure. On RHEL 8 and 9, run `fips-mode-setup --enable` or `fips-mode-setup --disable`, then reboot.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(2)),
    os: OS,
    reads: &[
        OS_RELEASE,
        OS_RELEASE_USR,
        KERNEL_RELEASE,
        FIPS_ENABLED,
        SYSTEMD_DIR,
        DOCKERENV,
        CONTAINERENV,
    ],
    statfs: &[],
    env: &[KUBE_HOST],
    commands: &[],
    peers: &[],
};

/// What the spec wants of FIPS mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Fips {
    Forbid,
    Require,
    #[default]
    Any,
}

impl Fips {
    fn word(self) -> &'static str {
        match self {
            Self::Forbid => "forbid",
            Self::Require => "require",
            Self::Any => "any",
        }
    }
}

/// `host.os`.
///
/// Built from the spec's `supported`, `arch` and `fips` keys. With none of them set, it reports what it
/// found and passes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsCheck {
    supported: Vec<Wanted>,
    arch: Vec<String>,
    fips: Fips,
}

impl OsCheck {
    /// A check for the parameters of a `host.os` entry.
    #[must_use]
    pub fn from_params(params: &HostOs) -> Self {
        let supported = params
            .supported
            .iter()
            .flat_map(|list| list.iter())
            .map(|entry| Wanted {
                id: entry.id.as_str().to_ascii_lowercase(),
                versions: entry
                    .versions
                    .as_ref()
                    .map(|vs| vs.iter().map(|v| v.as_str().to_owned()).collect()),
            })
            .collect();
        let mut arch: Vec<String> = params
            .arch
            .iter()
            .flat_map(|list| list.iter())
            .filter_map(|a| match a {
                Arch::X86_64 | Arch::Amd64 => Some("x86_64".to_owned()),
                Arch::Aarch64 | Arch::Arm64 => Some("aarch64".to_owned()),
                _ => None,
            })
            .collect();
        arch.sort();
        arch.dedup();
        let fips = match params.fips {
            FipsPolicy::Forbid => Fips::Forbid,
            FipsPolicy::Require => Fips::Require,
            _ => Fips::Any,
        };
        Self {
            supported,
            arch,
            fips,
        }
    }
}

impl Check for OsCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            if ctx.os() != Os::Linux {
                return Err(CheckError::Unsupported(NO_SOURCE));
            }
            let machine = Machine::read(ctx).await?;
            Ok(self.judge(&machine))
        })
    }
}

/// What reading one source gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Got<T> {
    Value(T),
    /// The file does not exist.
    Absent,
    /// The source exists or may exist, and could not be read. The text says why.
    Failed(String),
}

impl<T> Got<T> {
    fn value(&self) -> Option<&T> {
        match self {
            Self::Value(v) => Some(v),
            Self::Absent | Self::Failed(_) => None,
        }
    }

    /// Why there is no value, for a sentence.
    fn why(&self, what: &str) -> String {
        match self {
            Self::Value(_) => String::new(),
            Self::Absent => format!("{what} does not exist"),
            Self::Failed(why) => format!("{what} could not be read ({why})"),
        }
    }
}

/// Everything read from the machine. The judgement needs nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Machine {
    release: Got<Release>,
    /// The path `release` came from.
    release_path: Option<&'static str>,
    /// The kernel's machine type, such as `x86_64`.
    arch: Got<String>,
    kernel: Option<String>,
    fips: Got<bool>,
    systemd: Option<bool>,
    containers: Vec<&'static str>,
    wsl: bool,
}

impl Machine {
    async fn read(ctx: &CheckContext) -> Result<Self, CheckError> {
        let (release, release_path) = read_release(ctx).await?;
        let (arch, uname_kernel) = read_uname(ctx).await?;
        let kernel_text = read_text(ctx, KERNEL_RELEASE).await?;
        let kernel_text = kernel_text.value().map(|t| first_word(t));
        let fips = match read_text(ctx, FIPS_ENABLED).await? {
            Got::Value(text) => match text.trim() {
                "1" => Got::Value(true),
                "0" => Got::Value(false),
                _ => Got::Failed("it holds something other than 0 or 1".to_owned()),
            },
            Got::Absent => Got::Absent,
            Got::Failed(why) => Got::Failed(why),
        };
        let systemd = match stat(ctx, SYSTEMD_DIR).await? {
            Got::Value(is_dir) => Some(is_dir),
            Got::Absent => Some(false),
            Got::Failed(_) => None,
        };
        let mut containers = Vec::new();
        if matches!(stat(ctx, DOCKERENV).await?, Got::Value(_)) {
            containers.push("docker");
        }
        if matches!(stat(ctx, CONTAINERENV).await?, Got::Value(_)) {
            containers.push("podman");
        }
        if matches!(ctx.probe().env(KUBE_HOST), Ok(Some(value)) if !value.is_empty()) {
            containers.push("kubernetes");
        }
        let wsl = uname_kernel
            .iter()
            .chain(kernel_text.iter())
            .any(|k| k.to_ascii_lowercase().contains("microsoft"));
        Ok(Self {
            release,
            release_path,
            arch,
            kernel: uname_kernel.or(kernel_text),
            fips,
            systemd,
            containers,
            wsl,
        })
    }
}

/// The first word of a file's text, cut to 64 characters.
fn first_word(text: &str) -> String {
    text.split_whitespace()
        .next()
        .unwrap_or_default()
        .chars()
        .take(64)
        .collect()
}

/// What a probe error means for one source. A replay fixture that lacks an answer ends the check,
/// because that is a bug in a test. Every other error (not found, denied, timed out) only weakens one
/// answer.
fn weak<T>(error: ProbeError) -> Result<Got<T>, CheckError> {
    match error {
        ProbeError::NotRecorded(_) => Err(CheckError::Probe(error)),
        ProbeError::NotFound => Ok(Got::Absent),
        other => Ok(Got::Failed(short(&other))),
    }
}

/// A short reason for a probe failure, for a sentence.
fn short(error: &ProbeError) -> String {
    match error {
        ProbeError::NotFound => "not found".to_owned(),
        ProbeError::PermissionDenied => "permission denied".to_owned(),
        ProbeError::Timeout => "timed out".to_owned(),
        ProbeError::Denied { .. } => "rdy does not read it".to_owned(),
        _ => "read failed".to_owned(),
    }
}

/// Reads a text file through the probe, redacted.
async fn read_text(ctx: &CheckContext, path: &str) -> Result<Got<String>, CheckError> {
    let probe = ctx.probe();
    let file = match probe.read(Path::new(path)).await {
        Ok(file) => file,
        Err(error) => return weak(error),
    };
    match probe.file_text(&file) {
        Ok(text) => Ok(Got::Value((*text).clone())),
        Err(error) => weak(error),
    }
}

/// Whether a path exists, and if so whether it is a directory.
async fn stat(ctx: &CheckContext, path: &str) -> Result<Got<bool>, CheckError> {
    match ctx.probe().stat(Path::new(path)).await {
        Ok(Some(meta)) => Ok(Got::Value(meta.is_dir)),
        Ok(None) => Ok(Got::Absent),
        Err(error) => weak(error),
    }
}

/// `/etc/os-release`, then `/usr/lib/os-release`. When neither gives a release, the failure names both
/// paths, so a denied second path is not hidden behind a missing first one.
async fn read_release(
    ctx: &CheckContext,
) -> Result<(Got<Release>, Option<&'static str>), CheckError> {
    let mut states = Vec::new();
    let mut all_absent = true;
    for path in [OS_RELEASE, OS_RELEASE_USR] {
        match read_text(ctx, path).await? {
            Got::Value(text) => match release::parse(&text) {
                Some(release) => return Ok((Got::Value(release), Some(path))),
                None => {
                    all_absent = false;
                    states.push(format!(
                        "{path} holds none of ID, NAME, PRETTY_NAME, VERSION_ID or ID_LIKE"
                    ));
                }
            },
            Got::Absent => states.push(format!("{path} does not exist")),
            Got::Failed(why) => {
                all_absent = false;
                states.push(format!("{path} could not be read ({why})"));
            }
        }
    }
    let got = if all_absent {
        Got::Absent
    } else {
        Got::Failed(states.join(" and "))
    };
    Ok((got, None))
}

/// The machine type and kernel release from `uname`.
async fn read_uname(ctx: &CheckContext) -> Result<(Got<String>, Option<String>), CheckError> {
    match ctx.probe().native(NativeCall::Uname).await {
        Ok(NativeValue::Uname(info)) => {
            let arch = info.machine.trim().to_owned();
            let kernel = first_word(&info.release);
            Ok((
                if arch.is_empty() {
                    Got::Failed("uname gave no machine type".to_owned())
                } else {
                    Got::Value(arch)
                },
                (!kernel.is_empty()).then_some(kernel),
            ))
        }
        Ok(_) => Ok((
            Got::Failed("uname gave an unexpected answer".to_owned()),
            None,
        )),
        Err(error) => Ok((weak(error)?, None)),
    }
}

/// One thing wrong with the machine.
struct Problem {
    level: Level,
    message: String,
    fix: String,
}

impl OsCheck {
    fn judge(&self, machine: &Machine) -> Finding {
        let mut problems = Vec::new();
        let mut notes = Vec::new();
        self.judge_release(machine, &mut problems, &mut notes);
        self.judge_arch(machine, &mut problems);
        self.judge_fips(machine, &mut problems, &mut notes);
        if !machine.containers.is_empty() {
            notes.push(format!(
                "rdy is running inside {}. The OS shown is the container image's and the kernel is the host's. To check the node, run rdy on the node.",
                machine.containers.join(" and ")
            ));
        }
        if machine.wsl {
            notes.push(
                "rdy is running under WSL. The kernel is Microsoft's and the distribution is the WSL one."
                    .to_owned(),
            );
        }

        let level = problems
            .iter()
            .map(|p| p.level)
            .fold(Level::Pass, |worst, l| match (worst, l) {
                (Level::Fail, _) | (_, Level::Fail) => Level::Fail,
                (Level::Warn, _) | (_, Level::Warn) => Level::Warn,
                _ => Level::Pass,
            });
        let message = if problems.is_empty() {
            self.pass_message(machine)
        } else {
            problems
                .iter()
                .map(|p| p.message.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let mut finding = Finding::new(level, message)
            .with_observed(observed(machine))
            .with_expected(self.expected());
        for note in notes {
            finding = finding.with_note(note);
        }
        if !problems.is_empty() {
            let fix: Vec<&str> = problems.iter().map(|p| p.fix.as_str()).collect();
            finding = finding.with_fix(fix.join(" "));
        }
        finding
    }

    fn pass_message(&self, machine: &Machine) -> String {
        let os = machine
            .release
            .value()
            .map_or_else(|| "an unidentified Linux".to_owned(), Release::display);
        let arch = machine
            .arch
            .value()
            .map_or("an unknown architecture", |a| a);
        let asked = !self.supported.is_empty() || !self.arch.is_empty() || self.fips != Fips::Any;
        if asked {
            format!("{os} on {arch} meets the spec.")
        } else {
            format!("Found {os} on {arch}. The spec sets no OS requirement.")
        }
    }

    fn judge_release(
        &self,
        machine: &Machine,
        problems: &mut Vec<Problem>,
        notes: &mut Vec<String>,
    ) {
        if self.supported.is_empty() {
            return;
        }
        let list = rules::list_supported(&self.supported);
        let Some(release) = machine.release.value() else {
            let why = match &machine.release {
                Got::Failed(why) => why.clone(),
                _ => format!("neither {OS_RELEASE} nor {OS_RELEASE_USR} exists"),
            };
            problems.push(Problem {
                level: Level::Warn,
                message: format!("Cannot tell which OS this is: {why}. The spec supports {list}."),
                fix: "Check that `/etc/os-release` exists and is readable, or ask the vendor whether this OS is supported.".to_owned(),
            });
            return;
        };
        let have = release.display();
        match rules::matches(release, &self.supported) {
            Match::Yes { via } => {
                if let Some(host) = via {
                    notes.push(format!(
                        "{host} is a rebuild, so the supported list was matched through ID_LIKE."
                    ));
                }
            }
            Match::VersionUnknown => problems.push(Problem {
                level: Level::Warn,
                message: format!(
                    "{have} has no VERSION_ID, so rdy cannot check its version against {list}."
                ),
                fix: "Ask the vendor whether this release is supported.".to_owned(),
            }),
            Match::No => {
                if let Some(host) = &release.version_id {
                    for want in &self.supported {
                        let Some(versions) = &want.versions else {
                            continue;
                        };
                        if want.id != release.id && !release.id_like.contains(&want.id) {
                            continue;
                        }
                        for listed in rules::prefix_trap(versions, host) {
                            notes.push(format!(
                                "The host is {host}; the spec lists {listed}, which matches only {listed} exactly. List {host}, or the major version to accept every release of it."
                            ));
                        }
                    }
                }
                let id = match &release.version_id {
                    Some(version) => format!("{} {version}", release.id),
                    None => release.id.clone(),
                };
                problems.push(Problem {
                    level: Level::Fail,
                    message: format!("{have} ({id}) is not supported. The spec supports {list}."),
                    fix: format!(
                        "Use a supported OS image, or ask the vendor whether {id} can be supported."
                    ),
                });
            }
        }
    }

    fn judge_arch(&self, machine: &Machine, problems: &mut Vec<Problem>) {
        if self.arch.is_empty() {
            return;
        }
        let wanted = self.arch.join(" or ");
        match &machine.arch {
            Got::Value(have) => {
                let have = rules::canonical_arch(have);
                if !self.arch.iter().any(|a| a == have) {
                    problems.push(Problem {
                        level: Level::Fail,
                        message: format!("The architecture is {have}. The spec needs {wanted}."),
                        fix: format!("Use a machine with the {wanted} architecture."),
                    });
                }
            }
            other => problems.push(Problem {
                level: Level::Warn,
                message: format!(
                    "Cannot tell the architecture: {}. The spec needs {wanted}.",
                    other.why("uname")
                ),
                fix: format!(
                    "Check by hand that this machine is {wanted}, for example with uname -m."
                ),
            }),
        }
    }

    fn judge_fips(&self, machine: &Machine, problems: &mut Vec<Problem>, notes: &mut Vec<String>) {
        if self.fips == Fips::Any {
            return;
        }
        let require = self.fips == Fips::Require;
        let procedure = machine
            .release
            .value()
            .map_or(rules::Procedure::Vendor, rules::procedure);
        let state = match &machine.fips {
            Got::Value(on) => Some(*on),
            Got::Absent => {
                notes.push(format!(
                    "{FIPS_ENABLED} does not exist, so the kernel is taken to have FIPS mode off."
                ));
                Some(false)
            }
            Got::Failed(_) => None,
        };
        match state {
            Some(on) if on != require => problems.push(Problem {
                level: Level::Fail,
                message: if on {
                    "FIPS mode is on, and the spec forbids it.".to_owned()
                } else {
                    "FIPS mode is off, and the spec requires it.".to_owned()
                },
                fix: rules::fips_fix(require, procedure).to_owned(),
            }),
            Some(_) => {}
            None => problems.push(Problem {
                level: Level::Warn,
                message: format!(
                    "Cannot read FIPS mode: {}. The spec {} it.",
                    machine.fips.why(FIPS_ENABLED),
                    if require { "requires" } else { "forbids" }
                ),
                fix: "Check by hand: the file /proc/sys/crypto/fips_enabled holds 1 when FIPS mode is on."
                    .to_owned(),
            }),
        }
    }

    fn expected(&self) -> Value {
        let mut expected = serde_json::Map::new();
        if !self.supported.is_empty() {
            let list: Vec<Value> = self
                .supported
                .iter()
                .map(|w| json!({ "id": w.id, "versions": w.versions }))
                .collect();
            expected.insert("supported".to_owned(), Value::Array(list));
        }
        if !self.arch.is_empty() {
            expected.insert("arch".to_owned(), json!(self.arch));
        }
        expected.insert("fips".to_owned(), json!(self.fips.word()));
        Value::Object(expected)
    }
}

/// The evidence object.
fn observed(machine: &Machine) -> Value {
    let os = machine.release.value().map(|r| {
        json!({
            "id": r.id,
            "id_like": r.id_like,
            "version_id": r.version_id,
            "name": r.name,
            "pretty_name": r.pretty_name,
            "source": machine.release_path,
        })
    });
    json!({
        "os": os,
        "arch": machine.arch.value(),
        "kernel": machine.kernel,
        "init": machine.systemd.map(|s| if s { "systemd" } else { "other" }),
        "container": machine.containers,
        "wsl": machine.wsl,
        "fips": machine.fips.value(),
    })
}
