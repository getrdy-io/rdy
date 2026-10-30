//! Native calls: the closed list of OS calls a check may ask the facade for (ADR 0014 decision 5).
//!
//! A check never passes code to run. It passes a [`NativeCall`], a plain value, and the backend runs
//! the matching call itself. Each variant has one policy row, found by the exhaustive `match` in
//! `NativeCall::policy`, and `NativeCall::expects` has no wildcard either. Adding a variant does not
//! compile until its row exists, and the snapshot test in `tests` fails until `variants.snap` and the
//! threat model table (05, INV-07) change in the same PR.
//!
//! | Variant | Who may ask | What the policy checks | What the log holds |
//! | --- | --- | --- | --- |
//! | `Statvfs { path }` | any probe | the path passes the read denylist and the check's `statfs` prefixes (not `reads`), as written and again on the real path | `api`, `path` |
//! | `Uname` | any probe | nothing to check | `api` |
//! | `Rlimit(resource)` | any probe | the resource is in a closed list | `api`, `resource` |
//! | `Hostname` | any probe | nothing to check | `api` |
//! | `MachineId` | run-level probes only | a check's probe is refused | `api` |
//! | `SystemRoots` | any probe | nothing to check; the answer is capped at [`MAX_SYSTEM_ROOTS`] certificates of [`MAX_ROOT_BYTES`] each, and names the files, directories or OS store it read | `api` |
//!
//! The log holds the call, never the answer. The machine id has a type of its own, [`MachineId`], that
//! cannot be printed, serialized or read by a check, so the raw value cannot reach a log, an error
//! or a report. Only the salted `host_id` of 01 section 5.1 does (M2-002).

use std::fmt;
use std::path::PathBuf;

use rdy_spec::result::ActionKind;
use serde_json::{Map, Value};

use super::{Probe, ProbeError, ReadGuard, refuse, settle};

/// The rule of a `MachineId` call from a check's probe.
pub const RULE_MACHINE_ID: &str = "the machine id is read by the engine only";

/// The most certificates a [`NativeCall::SystemRoots`] answer holds. The OS stores of the five targets
/// hold 150 to 300 roots, and an enterprise store a few hundred more. A longer list is cut here, so a
/// store (or a directory full of files) cannot make the facade hold an unbounded list (05, `system_roots`).
pub const MAX_SYSTEM_ROOTS: usize = 1024;

/// The largest certificate a [`NativeCall::SystemRoots`] answer holds, in DER bytes. A real root is 1 to
/// 3 KiB; one over this is dropped, not truncated.
pub const MAX_ROOT_BYTES: usize = 16 * 1024;

/// An OS call a check may ask for. The list is closed, and a new variant needs a policy row, a snapshot
/// change and a threat model row in the same PR.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NativeCall {
    /// File system size, free space, inodes and mount flags of the file system that holds `path`. The
    /// path passes the read denylist and the check's `CheckInfo::statfs` prefixes. `reads` does not
    /// count: a check that declares only `reads` is refused here.
    Statvfs {
        /// The path, absolute, with no `..`.
        path: PathBuf,
    },
    /// The kernel name, release, version and machine type.
    Uname,
    /// This process's soft and hard limit for one resource.
    Rlimit(Resource),
    /// The host name as the OS reports it.
    Hostname,
    /// The OS machine id, for run-level work. The value is opaque: see [`MachineId`].
    MachineId,
    /// The trust roots of the OS store, as DER certificates, at most [`MAX_SYSTEM_ROOTS`] of at most
    /// [`MAX_ROOT_BYTES`] each, with the places they were read from. Linux reads the PEM bundles
    /// (`SSL_CERT_FILE`, `SSL_CERT_DIR`, the standard paths) through the file rules; macOS and Windows
    /// ask the OS.
    SystemRoots,
}

/// A process limit that [`NativeCall::Rlimit`] can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// Open files (`RLIMIT_NOFILE`).
    Nofile,
    /// Processes of the user (`RLIMIT_NPROC`).
    Nproc,
    /// Core file size (`RLIMIT_CORE`).
    Core,
    /// Locked memory (`RLIMIT_MEMLOCK`).
    Memlock,
    /// Stack size (`RLIMIT_STACK`).
    Stack,
}

impl Resource {
    /// The name the action log uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nofile => "nofile",
            Self::Nproc => "nproc",
            Self::Core => "core",
            Self::Memlock => "memlock",
            Self::Stack => "stack",
        }
    }
}

/// Who may ask for a call. Part of the policy row of a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Who {
    /// Any probe.
    Any,
    /// Run-level probes only (`check: null` in the log).
    RunLevel,
}

/// The policy row of one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Policy {
    /// The `api` field of the log entry.
    pub(crate) api: &'static str,
    /// Who may ask.
    pub(crate) who: Who,
    /// Whether the call names a path that the read rules judge.
    pub(crate) path_rules: bool,
}

impl NativeCall {
    /// The policy row. There is no wildcard arm: a new variant must name its row here.
    pub(crate) fn policy(&self) -> Policy {
        let (api, who, path_rules) = match self {
            Self::Statvfs { .. } => ("statvfs", Who::Any, true),
            Self::Uname => ("uname", Who::Any, false),
            Self::Rlimit(_) => ("rlimit", Who::Any, false),
            Self::Hostname => ("hostname", Who::Any, false),
            Self::MachineId => ("machine_id", Who::RunLevel, false),
            Self::SystemRoots => ("system_roots", Who::Any, false),
        };
        Policy {
            api,
            who,
            path_rules,
        }
    }

    /// Whether `value` is the kind of answer this call expects. No wildcard: a new variant must name
    /// its answer here.
    fn expects(&self, value: &NativeValue) -> bool {
        match self {
            Self::Statvfs { .. } => matches!(value, NativeValue::Statvfs(_)),
            Self::Uname => matches!(value, NativeValue::Uname(_)),
            Self::Rlimit(_) => matches!(value, NativeValue::Rlimit(_)),
            Self::Hostname => matches!(value, NativeValue::Hostname(_)),
            Self::MachineId => matches!(value, NativeValue::MachineId(_)),
            Self::SystemRoots => matches!(value, NativeValue::SystemRoots(_)),
        }
    }
}

/// What a native call answered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeValue {
    /// The answer to [`NativeCall::Statvfs`].
    Statvfs(StatvfsInfo),
    /// The answer to [`NativeCall::Uname`].
    Uname(UnameInfo),
    /// The answer to [`NativeCall::Rlimit`].
    Rlimit(RlimitInfo),
    /// The answer to [`NativeCall::Hostname`]. Raw: redact before it is shown.
    Hostname(String),
    /// The answer to [`NativeCall::MachineId`].
    MachineId(MachineId),
    /// The answer to [`NativeCall::SystemRoots`]: the certificates and where they were read from.
    SystemRoots(SystemRoots),
}

/// What kind of place a trust store was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreKind {
    /// A PEM file that holds one or more certificates.
    Bundle,
    /// A directory of certificate files.
    Directory,
    /// The OS store itself ("System keychain" on macOS, "Windows Root store" on Windows), which has no
    /// path.
    OsStore,
}

/// Why a trust store place was read: it is a standard one, or the operator named it in a variable.
///
/// A path from a variable can hold a user name (`SSL_CERT_FILE=/home/alice/ca.pem`) and no redaction
/// rule rewrites a path, so a report must tell the two apart (M1-100): a standard path shows as it is, a
/// variable's path shows the variable name and the path with the home directory collapsed to `~` and
/// control characters removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreOrigin {
    /// A path of the OS or the distribution, or the OS store itself.
    Standard,
    /// The place the named environment variable (`SSL_CERT_FILE` or `SSL_CERT_DIR`) points at.
    Env(&'static str),
}

/// One place the roots of a [`NativeCall::SystemRoots`] answer were read from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StoreSource {
    /// What it is.
    pub kind: StoreKind,
    /// The path as the OS writes it, or for [`StoreKind::OsStore`] a fixed name such as "System
    /// keychain". It is raw: a report shows it by the rule of [`StoreOrigin`], not as it is.
    pub location: String,
    /// Whether the place is a standard one or came from an environment variable.
    pub origin: StoreOrigin,
}

impl StoreSource {
    /// A standard source of this kind at `location`.
    #[must_use]
    pub fn new(kind: StoreKind, location: impl Into<String>) -> Self {
        Self {
            kind,
            location: location.into(),
            origin: StoreOrigin::Standard,
        }
    }

    /// The same source, with this origin.
    #[must_use]
    pub fn origin(mut self, origin: StoreOrigin) -> Self {
        self.origin = origin;
        self
    }
}

/// The trust roots of the OS: one DER certificate per entry, and the places they came from.
///
/// A source is listed when it held at least one certificate, whether or not the certificate was kept
/// (the caps and the repeats of a directory of hashed names do not hide where a bundle was).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SystemRoots {
    /// The certificates, as DER.
    pub certs: Vec<Vec<u8>>,
    /// Where they were read from. Empty when no source held a certificate, and for a backend that
    /// does not say.
    pub sources: Vec<StoreSource>,
}

impl SystemRoots {
    /// Certificates with the places they were read from.
    #[must_use]
    pub fn new(certs: Vec<Vec<u8>>, sources: Vec<StoreSource>) -> Self {
        Self { certs, sources }
    }
}

impl From<Vec<Vec<u8>>> for SystemRoots {
    /// Certificates from no named source.
    fn from(certs: Vec<Vec<u8>>) -> Self {
        Self {
            certs,
            sources: Vec::new(),
        }
    }
}

/// The OS store is replaced by `SSL_CERT_FILE` or `SSL_CERT_DIR` and this OS may not read what they
/// name (Windows, which has no file reads in M1). It rides inside an `io::Error` and the probe turns it
/// back into [`ProbeError::StoreOverridden`], so the check can say how to fix it.
#[derive(Debug)]
pub(crate) struct RootsOverridden;

impl fmt::Display for RootsOverridden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SSL_CERT_FILE or SSL_CERT_DIR is set")
    }
}

impl std::error::Error for RootsOverridden {}

impl RootsOverridden {
    /// The error a backend returns.
    #[cfg(any(windows, test))]
    pub(crate) fn error() -> std::io::Error {
        std::io::Error::other(Self)
    }

    /// Whether `error` carries the marker.
    pub(crate) fn is_in(error: &std::io::Error) -> bool {
        error
            .get_ref()
            .is_some_and(|inner| inner.downcast_ref::<Self>().is_some())
    }
}

/// Applies the caps of [`NativeCall::SystemRoots`]: an empty certificate or one over [`MAX_ROOT_BYTES`]
/// is dropped, and the list is cut at [`MAX_SYSTEM_ROOTS`]. The probe applies it to every backend's
/// answer, so a replayed fixture and a live store are held to the same bound. A cut logs a warning with
/// the counts and no certificate.
pub(crate) fn cap_system_roots(roots: SystemRoots) -> SystemRoots {
    let SystemRoots { certs, sources } = roots;
    let total = certs.len();
    let kept: Vec<Vec<u8>> = certs
        .into_iter()
        .filter(|der| !der.is_empty() && der.len() <= MAX_ROOT_BYTES)
        .take(MAX_SYSTEM_ROOTS)
        .collect();
    if kept.len() < total {
        tracing::warn!(
            offered = total,
            kept = kept.len(),
            "the OS trust store was cut to the cap on certificates (count or size), so a root may be missing from the TLS verdict"
        );
    }
    SystemRoots {
        certs: kept,
        sources,
    }
}

/// File system numbers from `statvfs(2)`. Block counts are in units of `fragment_size` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StatvfsInfo {
    /// The unit of the block counts below (`f_frsize`).
    pub fragment_size: u64,
    /// Total size (`f_blocks`).
    pub blocks: u64,
    /// Free blocks, counting those only root may use (`f_bfree`).
    pub blocks_free: u64,
    /// Free blocks that an ordinary user may use (`f_bavail`).
    pub blocks_available: u64,
    /// Total inodes (`f_files`). 0 when the file system has no inode accounting.
    pub files: u64,
    /// Free inodes (`f_ffree`).
    pub files_free: u64,
    /// Mounted read only (`ST_RDONLY`).
    pub read_only: bool,
    /// Mounted with no program execution (`ST_NOEXEC`). `None` where the OS does not report it (macOS
    /// and the BSDs): unknown, which a check must not read as "not set".
    pub no_exec: Option<bool>,
    /// Mounted with set-user-id bits ignored (`ST_NOSUID`).
    pub no_suid: bool,
    /// The device of the file system as `(major, minor)`, the pair that field 3 of
    /// `/proc/self/mountinfo` prints as `major:minor`. A check uses it to find the mount line of the
    /// file system it measured. `None` where the OS has no such number (Windows).
    pub dev: Option<(u32, u32)>,
}

/// The fields of `uname(2)` that checks use. The node name is left out: `Hostname` has it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct UnameInfo {
    /// For example `Linux` or `Darwin`.
    pub sysname: String,
    /// For example `5.14.0-362.el9.x86_64`.
    pub release: String,
    /// The build string of the kernel.
    pub version: String,
    /// For example `x86_64` or `aarch64`.
    pub machine: String,
}

/// One process limit. `None` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RlimitInfo {
    /// The soft limit, which the process runs under.
    pub soft: Option<u64>,
    /// The hard limit, the most the soft limit can be raised to.
    pub hard: Option<u64>,
}

/// The OS machine id. It has no `Display`, no `Serialize` and no public accessor, and its `Debug`
/// shows nothing, so a check cannot put it in a result and a log line cannot hold it. The engine
/// derives the salted `host_id` from it (M2-002).
#[derive(Clone, PartialEq, Eq)]
pub struct MachineId(String);

impl MachineId {
    /// Wraps a raw id. The live backend and the fixture loader call this.
    #[cfg_attr(
        not(any(
            test,
            feature = "testing",
            all(feature = "runtime", target_os = "linux")
        )),
        expect(dead_code, reason = "only a backend makes a machine id")
    )]
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The raw id. M2-002 reads it for the `host_id` derivation; until then only tests do.
    #[cfg(test)]
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MachineId(..)")
    }
}

impl Probe {
    /// Asks the backend for an OS call from the closed list.
    ///
    /// Every call writes one `native` entry with the `api` name, and `path` or `resource` where the
    /// call has one. The entry never holds the answer.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for a `Statvfs` path the read rules refuse, a `MachineId` call from a
    /// check's probe, or a call after the check ended; [`ProbeError::Unsupported`] where the OS has no
    /// source yet; the other variants when the backend fails.
    pub async fn native(&self, call: NativeCall) -> Result<NativeValue, ProbeError> {
        let policy = call.policy();
        // The text an error and the log show for a path: `~/...` under the home directory.
        let what = match &call {
            NativeCall::Statvfs { path } => self.hub.as_ref().map_or_else(
                || path.to_string_lossy().into_owned(),
                |hub| hub.log.display_path(path),
            ),
            _ => policy.api.to_owned(),
        };
        let mut fields = Map::new();
        fields.insert("api".to_owned(), policy.api.into());
        if policy.path_rules {
            fields.insert("path".to_owned(), what.clone().into());
        }
        if let NativeCall::Rlimit(resource) = &call {
            fields.insert("resource".to_owned(), Value::from(resource.as_str()));
        }
        let (hub, entry) = self.begin(ActionKind::Native, fields, &what)?;
        // `Statvfs` is judged by the check's `statfs` prefixes, never by `reads`, so a check can be
        // given file system numbers for any path without being given the files. The denylist applies
        // either way. The backend gets this guard and judges the real path with it.
        let guard = ReadGuard::statfs(self.scope.os, self.scope.info.map(|info| info.statfs));
        let refusal = match (&call, policy.who) {
            (_, Who::RunLevel) if self.scope.check.is_some() => Some(RULE_MACHINE_ID),
            (NativeCall::Statvfs { path }, _) => guard.admit(path).err(),
            _ => None,
        };
        if let Some(rule) = refusal {
            return Err(refuse(entry, rule, &what));
        }
        let result = self
            .unless_ended(&what, async {
                let value = hub
                    .backend
                    .native(&call, &guard)
                    .await
                    .map_err(|e| ProbeError::from_native_io(&e, &what, policy.api))?;
                if call.expects(&value) {
                    Ok(match value {
                        NativeValue::SystemRoots(roots) => {
                            NativeValue::SystemRoots(cap_system_roots(roots))
                        }
                        other => other,
                    })
                } else {
                    Err(ProbeError::Io(
                        "the backend answered a native call with the wrong kind of value"
                            .to_owned(),
                    ))
                }
            })
            .await;
        settle(entry, result, |_, _| {})
    }
}

#[cfg(test)]
mod tests;
