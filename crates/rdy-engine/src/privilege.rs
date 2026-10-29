//! The privilege snapshot, the refusal of a privilege-carrying binary and the capability probes
//! (02 "Privilege and needs", threat model INV-10 and E2).
//!
//! [`Privilege::snapshot`] runs once, at start-up, before the spec is read. It reads through a
//! run-level [`Probe`] (`check: null` in the action log), so a fixture run replays it and the log shows
//! what it read. Nothing else in rdy asks the OS who it is.
//!
//! - **Linux.** The four values on the `Uid:` and `Gid:` lines of `/proc/self/status` (real,
//!   effective, saved, filesystem), `CapEff` and `CapAmb` from the same file, and `AT_SECURE` (type 23)
//!   from `/proc/self/auxv`. The auxv parser keeps that one flag. It copies no other value, so no
//!   load address or pointer can reach a report.
//! - **macOS.** The real and effective ids through the probe (a `native` call). The OS has no call for
//!   the saved id and no filesystem id, so those two are reported as the effective one, and the
//!   capability and `AT_SECURE` fields stay unset.
//! - **Windows.** `C:\Windows\System32\whoami.exe /groups /fo csv`, through the command table. The
//!   mandatory label SID decides: High (`S-1-16-12288`) and System (`S-1-16-16384`) are elevated. If
//!   `whoami` fails the answer is [`Elevation::Unknown`], never a guess. It feeds the `root` need and
//!   `identity.elevated` only, never trust (ADR 0027).
//!
//! [`Privilege::check`] is INV-10: rdy refuses to run when it carries more privilege than the user who
//! started it. A read that fails or a file that does not parse is also a refusal ([`PrivilegeError`]),
//! because a snapshot that cannot be taken cannot show that the binary is safe to run.
//!
//! [`capabilities`] probes only the needs the plan holds. A need that is not in the plan is never
//! probed, so a spec with no check that needs a program does not stat that program.

use rdy_spec::result::{Capability, Identity};

use crate::check::{Need, Os};
use crate::exec::policy::SEARCH_DIRS;
use crate::exec::table;
use crate::probe::{Probe, ProbeError};

#[cfg(test)]
mod tests;

/// `AT_SECURE` in the ELF auxiliary vector: nonzero when the kernel started the program as setuid,
/// setgid or with file capabilities.
const AT_SECURE: u64 = 23;
/// The end of the auxiliary vector.
const AT_NULL: u64 = 0;

/// The mandatory label RID of a High integrity token.
const INTEGRITY_HIGH: u32 = 12288;
/// The mandatory label RID of a System integrity token.
const INTEGRITY_SYSTEM: u32 = 16384;
/// Untrusted, Low, Medium and Medium Plus. Not elevated.
const INTEGRITY_NOT_ELEVATED: [u32; 4] = [0, 4096, 8192, 8448];

/// The user and group ids of a process: real, effective, saved and filesystem, in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIds {
    /// The user ids.
    pub uid: [u32; 4],
    /// The group ids.
    pub gid: [u32; 4],
}

impl ProcessIds {
    /// The four user ids and the four group ids, each as real, effective, saved, filesystem.
    #[must_use]
    pub fn new(uid: [u32; 4], gid: [u32; 4]) -> Self {
        Self { uid, gid }
    }

    /// All eight ids are the one the user started rdy as.
    #[must_use]
    fn uniform(&self) -> (bool, bool) {
        let same = |ids: &[u32; 4]| ids.iter().all(|id| *id == ids[0]);
        (same(&self.uid), same(&self.gid))
    }
}

/// How privileged this process is, as far as rdy could tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Elevation {
    /// Effective uid 0 on Linux or macOS.
    Root,
    /// A High integrity token on Windows (an administrator prompt).
    High,
    /// A System integrity token on Windows.
    System,
    /// Any other user.
    NotElevated,
    /// rdy could not tell. `whoami` failed or its output has no integrity level.
    Unknown,
}

impl Elevation {
    /// `true` for root, High and System.
    #[must_use]
    pub fn is_elevated(self) -> bool {
        matches!(self, Self::Root | Self::High | Self::System)
    }
}

/// What the OS says about this process, taken once at start-up.
///
/// The Debug output and every field hold no raw OS data beyond the ids, the two capability masks and
/// one flag.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Privilege {
    /// The four ids. `None` on Windows, which has none.
    pub ids: Option<ProcessIds>,
    /// `CapEff`. Zero where the OS has no such mask.
    pub cap_eff: u64,
    /// `CapAmb`. Zero where the OS has no such mask, and on a kernel before 4.3 that does not list it.
    pub cap_amb: u64,
    /// `AT_SECURE`. `false` where the OS has no such flag.
    pub at_secure: bool,
    /// Whether this process runs as root or elevated.
    pub elevation: Elevation,
}

/// Why rdy refuses to run (INV-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// A user id (real, effective, saved or filesystem) differs from the real one.
    UidMismatch,
    /// A group id differs from the real one.
    GidMismatch,
    /// `CapEff` or `CapAmb` is not zero for a non-root user.
    Capabilities,
    /// The kernel started rdy as setuid, setgid or with file capabilities (`AT_SECURE`).
    AtSecure,
}

impl Refusal {
    /// A fixed phrase for the error text. It holds no id and no path.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::UidMismatch => "a user id (real, effective, saved or filesystem) differs",
            Self::GidMismatch => "a group id (real, effective, saved or filesystem) differs",
            Self::Capabilities => "it holds Linux capabilities",
            Self::AtSecure => "the kernel started it as setuid, setgid or with file capabilities",
        }
    }
}

/// Why the privilege snapshot did not give a clean answer. Every variant means exit 70.
///
/// The text is `message. Fix: hint`, the shape of every other rdy error. [`PrivilegeError::message`]
/// and [`PrivilegeError::hint`] give the two parts for the CLI, which prints them on two lines.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivilegeError {
    /// rdy carries more privilege than the user who started it (INV-10).
    Refused(Vec<Refusal>),
    /// A source of the snapshot could not be read.
    Unreadable(Unreadable),
    /// A source was read and does not have the expected shape.
    Malformed(Source),
}

impl std::fmt::Display for PrivilegeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}. Fix: {}", self.message(), self.hint())
    }
}

impl std::error::Error for PrivilegeError {}

/// A source of the snapshot, named in an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// `/proc/self/status`.
    ProcStatus,
    /// `/proc/self/auxv`.
    ProcAuxv,
    /// The process ids on macOS.
    ProcessIds,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Self::ProcStatus => "/proc/self/status",
            Self::ProcAuxv => "/proc/self/auxv",
            Self::ProcessIds => "the process user and group ids",
        }
    }
}

/// A read of a snapshot source that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// What was being read.
    pub source: Source,
    /// Why, from the probe.
    pub cause: ProbeError,
}

impl Unreadable {
    fn message(&self) -> String {
        format!("rdy could not read {}", self.source.name())
    }
}

impl PrivilegeError {
    /// The fix for a refusal. It names the three ways a binary gets privilege.
    pub const HINT_REFUSED: &'static str = "run rdy without the setuid or setgid bit (`chmod u-s,g-s <path to rdy>`), without file capabilities (`setcap -r <path to rdy>`) and without ambient capabilities, as the user who should run it, then run rdy again";
    /// The fix for a source that could not be read.
    pub const HINT_UNREADABLE: &'static str = "check that /proc is mounted and readable by this user (rdy needs it to prove it is not running with extra privilege), then run rdy again";
    /// The fix for a source with an unexpected shape.
    pub const HINT_MALFORMED: &'static str = "this is a bug in rdy or in the kernel's /proc output. Please report it at https://github.com/getrdy-io/rdy/issues and include the output of rdy version";

    /// What went wrong, with no fix and no input text.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Refused(reasons) => {
                let why: Vec<&str> = reasons.iter().map(|r| r.reason()).collect();
                format!(
                    "rdy will not run with more privilege than the user who started it: {}",
                    why.join("; ")
                )
            }
            Self::Unreadable(u) => u.message(),
            Self::Malformed(source) => format!("rdy could not understand {}", source.name()),
        }
    }

    /// The fix, one action. Never empty.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Refused(_) => Self::HINT_REFUSED,
            Self::Unreadable(_) => Self::HINT_UNREADABLE,
            Self::Malformed(_) => Self::HINT_MALFORMED,
        }
    }
}

impl Privilege {
    /// Takes the snapshot through a run-level probe. The probe's OS decides which sources are read.
    ///
    /// A source that cannot be read or parsed is an error, not a default: the caller exits 70.
    /// A Windows `whoami` that fails is not an error, it gives [`Elevation::Unknown`].
    ///
    /// # Errors
    ///
    /// [`PrivilegeError::Unreadable`] or [`PrivilegeError::Malformed`].
    pub async fn snapshot(probe: &Probe) -> Result<Self, PrivilegeError> {
        match probe.os() {
            Os::Windows => Ok(Self::windows(probe).await),
            Os::Macos => Self::macos(probe).await,
            _ => Self::linux(probe).await,
        }
    }

    async fn linux(probe: &Probe) -> Result<Self, PrivilegeError> {
        let status = probe
            .read(std::path::Path::new("/proc/self/status"))
            .await
            .map_err(|cause| unreadable(Source::ProcStatus, cause))?;
        let parsed = parse_status(&String::from_utf8_lossy(&status.bytes))
            .ok_or(PrivilegeError::Malformed(Source::ProcStatus))?;
        let auxv = probe
            .read(std::path::Path::new("/proc/self/auxv"))
            .await
            .map_err(|cause| unreadable(Source::ProcAuxv, cause))?;
        let at_secure =
            parse_at_secure(&auxv.bytes).ok_or(PrivilegeError::Malformed(Source::ProcAuxv))?;
        Ok(Self {
            elevation: elevation_of(Some(parsed.ids)),
            ids: Some(parsed.ids),
            cap_eff: parsed.cap_eff,
            cap_amb: parsed.cap_amb,
            at_secure,
        })
    }

    async fn macos(probe: &Probe) -> Result<Self, PrivilegeError> {
        let ids = probe
            .process_ids()
            .await
            .map_err(|cause| unreadable(Source::ProcessIds, cause))?;
        Ok(Self {
            elevation: elevation_of(Some(ids)),
            ids: Some(ids),
            cap_eff: 0,
            cap_amb: 0,
            at_secure: false,
        })
    }

    async fn windows(probe: &Probe) -> Self {
        let elevation = match whoami_groups(probe).await {
            Some(text) => parse_integrity(&text),
            None => Elevation::Unknown,
        };
        Self {
            ids: None,
            cap_eff: 0,
            cap_amb: 0,
            at_secure: false,
            elevation,
        }
    }

    /// Every reason INV-10 gives to refuse, empty when the process is clean.
    ///
    /// Any of the four user ids or group ids that differs from the real one is a refusal. A nonzero
    /// `CapEff` or `CapAmb` is a refusal for a real uid other than 0. `AT_SECURE` is always one.
    #[must_use]
    pub fn refusals(&self) -> Vec<Refusal> {
        let mut found = Vec::new();
        if let Some(ids) = &self.ids {
            let (uid_same, gid_same) = ids.uniform();
            if !uid_same {
                found.push(Refusal::UidMismatch);
            }
            if !gid_same {
                found.push(Refusal::GidMismatch);
            }
            if ids.uid[0] != 0 && (self.cap_eff != 0 || self.cap_amb != 0) {
                found.push(Refusal::Capabilities);
            }
        }
        if self.at_secure {
            found.push(Refusal::AtSecure);
        }
        found
    }

    /// INV-10: `Ok` when this process carries no privilege the user did not bring.
    ///
    /// # Errors
    ///
    /// [`PrivilegeError::Refused`] with every reason found.
    pub fn check(&self) -> Result<(), PrivilegeError> {
        let reasons = self.refusals();
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(PrivilegeError::Refused(reasons))
        }
    }

    /// The effective uid, or `None` on Windows.
    #[must_use]
    pub fn euid(&self) -> Option<u32> {
        self.ids.map(|ids| ids.uid[1])
    }

    /// `true` when this process is root or elevated.
    #[must_use]
    pub fn is_elevated(&self) -> bool {
        self.elevation.is_elevated()
    }

    /// The `identity` object of the report, from the snapshot. The login name is not part of the
    /// snapshot, so `user` is `None`. `elevated` is `false` when the answer is unknown: the report
    /// field is a plain boolean, and the capability list says "unknown".
    #[must_use]
    pub fn identity(&self) -> Identity {
        Identity::new(self.euid().map(u64::from), None, self.is_elevated())
    }
}

fn unreadable(source: Source, cause: ProbeError) -> PrivilegeError {
    PrivilegeError::Unreadable(Unreadable { source, cause })
}

fn elevation_of(ids: Option<ProcessIds>) -> Elevation {
    match ids {
        Some(ids) if ids.uid[1] == 0 => Elevation::Root,
        Some(_) => Elevation::NotElevated,
        None => Elevation::Unknown,
    }
}

/// What the `status` file gives the snapshot.
struct Status {
    ids: ProcessIds,
    cap_eff: u64,
    cap_amb: u64,
}

/// Parses the `Uid:`, `Gid:`, `CapEff:` and `CapAmb:` lines of `/proc/self/status`.
///
/// `Uid`, `Gid` and `CapEff` must be there and well formed. `CapAmb` is missing on a kernel before
/// 4.3, which has no ambient capabilities, so a missing line is zero. A line that is there and does
/// not parse is `None`.
fn parse_status(text: &str) -> Option<Status> {
    let mut uid = None;
    let mut gid = None;
    let mut cap_eff = None;
    let mut cap_amb = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = uid.or(Some(four_ids(rest)?));
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = gid.or(Some(four_ids(rest)?));
        } else if let Some(rest) = line.strip_prefix("CapEff:") {
            cap_eff = cap_eff.or(Some(hex_mask(rest)?));
        } else if let Some(rest) = line.strip_prefix("CapAmb:") {
            cap_amb = cap_amb.or(Some(hex_mask(rest)?));
        }
    }
    Some(Status {
        ids: ProcessIds::new(uid?, gid?),
        cap_eff: cap_eff?,
        cap_amb: cap_amb.unwrap_or(0),
    })
}

/// Exactly four decimal ids.
fn four_ids(rest: &str) -> Option<[u32; 4]> {
    let mut parts = rest.split_whitespace();
    let ids = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(ids)
}

fn hex_mask(rest: &str) -> Option<u64> {
    let text = rest.trim();
    if text.is_empty() || text.len() > 16 {
        return None;
    }
    u64::from_str_radix(text, 16).ok()
}

/// Reads `AT_SECURE` from the bytes of `/proc/self/auxv` and nothing else.
///
/// The vector is pairs of native-endian machine words, ended by `AT_NULL`. Only the value of the
/// pair whose type is 23 is kept, as a flag. Every other value (load addresses, the random bytes
/// pointer, the program name pointer) is dropped here, so it cannot reach a report. `None` when the
/// vector has no `AT_SECURE` before its end or is cut in the middle of a pair: the Linux kernel
/// always writes it, so a vector without it is not one rdy can trust.
fn parse_at_secure(bytes: &[u8]) -> Option<bool> {
    const WORD: usize = std::mem::size_of::<usize>();
    let mut at_secure = None;
    for pair in bytes.chunks(2 * WORD) {
        let (key, value) = pair.split_at_checked(WORD)?;
        let key = word(key)?;
        if key == AT_NULL {
            return at_secure;
        }
        if key == AT_SECURE {
            at_secure = Some(word(value)? != 0);
        }
    }
    // No AT_NULL: cut short.
    None
}

/// One native-endian machine word.
fn word(bytes: &[u8]) -> Option<u64> {
    const WORD: usize = std::mem::size_of::<usize>();
    let array: [u8; WORD] = bytes.try_into().ok()?;
    u64::try_from(usize::from_ne_bytes(array)).ok()
}

/// The Windows command: `whoami.exe /groups /fo csv`, built from the command table.
fn whoami_cmd() -> Option<crate::exec::policy::Cmd> {
    table::entry("whoami.exe")?
        .cmd_for(Os::Windows, "groups", &[])
        .ok()
}

/// Runs `whoami`, and gives its stdout when it exited 0. Any failure is `None`.
async fn whoami_groups(probe: &Probe) -> Option<String> {
    let out = probe.exec(whoami_cmd()?).await.ok()?;
    (out.exit == Some(0)).then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Maps the mandatory label row of `whoami /groups /fo csv` to an [`Elevation`].
///
/// The SID column does not depend on the language of Windows, so the parser looks for a field of the
/// form `S-1-16-<rid>` and ignores every name. High and System are elevated, Untrusted to Medium Plus
/// are not. No label, two different labels or a level that is not listed are [`Elevation::Unknown`].
fn parse_integrity(csv: &str) -> Elevation {
    let mut found: Option<u32> = None;
    for line in csv.lines() {
        for field in csv_fields(line) {
            let Some(rid) = field.strip_prefix("S-1-16-") else {
                continue;
            };
            let Ok(rid) = rid.parse::<u32>() else {
                return Elevation::Unknown;
            };
            match found {
                Some(seen) if seen != rid => return Elevation::Unknown,
                _ => found = Some(rid),
            }
        }
    }
    match found {
        Some(INTEGRITY_HIGH) => Elevation::High,
        Some(INTEGRITY_SYSTEM) => Elevation::System,
        Some(rid) if INTEGRITY_NOT_ELEVATED.contains(&rid) => Elevation::NotElevated,
        _ => Elevation::Unknown,
    }
}

/// The fields of one CSV line, with quotes removed and `""` read as a quote.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.trim_end_matches(['\r', '\n']).chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

/// Probes the needs the plan holds and nothing else. The result goes into the report's `capabilities`.
///
/// `wanted` is every need of every runnable check in the plan; a repeated need is probed once. A need
/// that no check holds is not probed: a spec with no check that needs `getenforce` never stats it.
///
/// - `root` is answered from the snapshot, with no probe call.
/// - `network` is the run option, with no probe call.
/// - `command` stats the program in the fixed search path and the table's declared directories,
///   through the probe, never the caller's `PATH`. On Windows no command runs in M1, so it is not
///   available.
/// - `kube_context` is the Kubernetes family's probe (M1-107), not this function's, and is left out.
pub async fn capabilities(
    probe: &Probe,
    privilege: &Privilege,
    wanted: &[Need],
    network: bool,
) -> Vec<Capability> {
    let mut seen: Vec<&Need> = Vec::new();
    let mut found = Vec::new();
    for need in wanted {
        if seen.contains(&need) {
            continue;
        }
        seen.push(need);
        match need {
            Need::Root => found.push(root_capability(privilege)),
            Need::Network => found.push(network_capability(network)),
            Need::Command(program) => found.push(command_capability(probe, program).await),
            _ => {}
        }
    }
    found
}

fn root_capability(privilege: &Privilege) -> Capability {
    let mut cap = Capability::new(Need::Root.wire(), privilege.is_elevated());
    cap.detail = Some(match (privilege.euid(), privilege.elevation) {
        (Some(euid), _) => format!("uid {euid}"),
        (None, Elevation::High) => "elevated token (High integrity)".to_owned(),
        (None, Elevation::System) => "elevated token (System integrity)".to_owned(),
        (None, Elevation::NotElevated) => "not elevated".to_owned(),
        (None, _) => "could not tell whether rdy is elevated".to_owned(),
    });
    if !privilege.is_elevated() {
        cap.hint = Some(
            match privilege.elevation {
                Elevation::Unknown => {
                    "rdy could not read its integrity level, so checks that need elevation are skipped. Run rdy from an administrator prompt if they matter"
                }
                _ if privilege.ids.is_none() => {
                    "start rdy from an administrator prompt to run the checks that need elevation. rdy never asks for it"
                }
                _ => "start rdy as root to run the checks that need it. rdy never asks for it",
            }
            .to_owned(),
        );
    }
    cap
}

fn network_capability(allowed: bool) -> Capability {
    let mut cap = Capability::new(Need::Network.wire(), allowed);
    if !allowed {
        cap.detail = Some("--no-network".to_owned());
        cap.hint = Some("run rdy again without --no-network to run the network checks".to_owned());
    }
    cap
}

async fn command_capability(probe: &Probe, program: &'static str) -> Capability {
    let mut cap = Capability::new(Need::Command(program).wire(), false);
    cap.name = Some(program.to_owned());
    if probe.os() == Os::Windows {
        cap.detail = Some("commands do not run on Windows in this version".to_owned());
        return cap;
    }
    let extra = table::entry(program).map_or(&[][..], |entry| entry.extra_dirs);
    for dir in SEARCH_DIRS.iter().chain(extra) {
        let path = std::path::Path::new(dir).join(program);
        if let Ok(Some(meta)) = probe.stat(&path).await
            && meta.is_file
        {
            cap.available = true;
            cap.detail = Some(path.to_string_lossy().into_owned());
            return cap;
        }
    }
    cap.detail = Some("not found in the fixed search path".to_owned());
    cap.hint = Some(format!(
        "install {program}, or accept that checks that need it are skipped"
    ));
    cap
}
