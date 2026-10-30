//! The read policy (threat model I5, 02 "Files").
//!
//! Two layers apply to `read`, `read_tail`, `read_dir` and `stat`, both through [`ReadGuard`]:
//!
//! 1. **The path as the check wrote it.** [`ReadGuard::admit`] decides from the text alone, with no I/O,
//!    before any file is touched. The path must be absolute, with no `..`, off the denylist, and under
//!    one of the check's declared `reads` prefixes. A replayed run gets this layer too.
//! 2. **The real path.** The live backend resolves links without opening the file (Linux: `O_PATH`,
//!    then `/proc/self/fd/<n>`), calls [`ReadGuard::admit_real`] on the result, and only then opens it
//!    through the same descriptor. So a link to `/etc/shadow`, or a link out of the declared prefixes,
//!    is refused even though its own name looked fine. The check's `reads` must therefore name the real
//!    location too: a check that reads `/etc/os-release` on a system where it is a link to
//!    `/usr/lib/os-release` declares both.
//!
//! `Statvfs` uses the same two layers with the check's `statfs` prefixes in place of `reads`
//! ([`ReadGuard::statfs`]). A path outside them is refused with `RULE_OUTSIDE_STATFS`, which names
//! `statfs`, so the author widens the right field.
//!
//! Before the prefix match, `/proc/<rdy's pid>/...` and `/proc/net/...` are put in the `/proc/self/...`
//! form, on the path and on the declared prefixes alike. A check that declares `/proc/net` or
//! `/proc/self/mountinfo` is not refused for where those links lead.
//!
//! The decision follows the check's `Os`, not the machine rdy runs on: a Linux check's path is read as
//! a Unix path on any host, so a replay test of a Linux check runs on the Windows leg too. A Windows
//! check reads no files in M1 and is refused (`RULE_WINDOWS`). A probe built with no `CheckInfo`
//! (run-level work, `TestRun::context`) has no prefixes to enforce and keeps the denylist.
//!
//! The list is matched on path components, not on text, so `/etc//shadow`, `/etc/./shadow` and
//! `/etc/shadow/` are the same path. A path with a `..` component is refused outright, because
//! `/tmp/../etc/shadow` would otherwise pass a text match. On macOS names compare without regard to
//! case, and a leading `/private` is ignored (`/etc` is a link to `/private/etc` there).
//!
//! **Where a rule applies.** A name that marks a secret is matched at any depth, because the same file
//! shows up under a host mount (`/host/etc/shadow`), a container layer
//! (`.../overlay2/<id>/diff/etc/shadow`) and a data volume (`/System/Volumes/Data/private/etc/sudoers`).
//! That covers the `etc` rules, `.ssh`, `.kube`, the cloud and tool credential files, the cluster
//! credential paths and the process directories under `proc`. Only `/dev` and `/sys/kernel/...` are
//! matched at the root, because those names mean something else elsewhere.
//!
//! **Machine identity.** `etc/machine-id*`, `var/lib/dbus/machine-id*` and `run/machine-id*` are refused
//! to every reader but the `MachineId` guard, and so are the DMI `product_serial`, `product_uuid`,
//! `board_serial` and `chassis_serial` under `dmi/id/` (nothing reads those). The live backend also
//! knows the id files by inode, so a hard link or bind mount under another name is refused too.
//!
//! **`/proc/<pid>/`** is an allowlist, not a denylist: only `status`, `stat`, `statm`, `comm`, `cgroup`,
//! `mountinfo`, `mounts`, `limits` and `net` (and the same under `task/<tid>/`) are readable. Everything
//! else there is refused, including `cwd`, `exe`, `root`, `fd`, `environ`, `cmdline`, `mem`, `maps`
//! and `ns`, so `/proc/1/cwd/etc/shadow` cannot reach a file through a process link. `auxv` is readable
//! for `/proc/self` and, on the real path, for the directory of rdy's own process id. Never for another
//! pid.
//!
//! **Links (`read_link`, M1-169).** [`ReadGuard::link`] judges the link itself: its real path is the
//! real path of its parent plus its own name, and the link is not followed. The denylist and the
//! `reads` prefixes apply to that path, so a link outside the prefixes is refused. Where the link
//! points is not judged, and not logged. Two entries of `/proc/<pid>/` are open to it, and to nothing
//! else:
//!
//! - `/proc/self/ns/net`, for rdy's own process only, when the check's `reads` cover it.
//! - `/proc/<pid>/fd/<n>`, only for a check that declared [`FD_WALK`] in `reads`, for any process id
//!   or `self`. The links lead to files, pipes and sockets, and [`ReadGuard::admit_link`] returns only
//!   the sockets (`socket:[8841]`). Any other target is refused with `RULE_FD_TARGET` and never
//!   returned or logged. `read_dir` ([`ReadGuard::listing`]) may list `/proc/<pid>/fd` under the same
//!   declaration. `read`, `stat` and `Statvfs` of anything in an fd directory stay refused, so
//!   `/proc/1/fd/3` cannot reach the file behind the link, and `task/<tid>/fd` and `thread-self` stay
//!   refused.
//!
//! **`/dev`** is refused for `stat` and `read_dir` as well as `read`, because a device node name says
//! which hardware a machine has. M4 (GPU checks) adds a closed, stat-only list: `/dev/nvidia*`,
//! `/dev/dri/*` and `/dev/kfd`.
//!
//! The rules return a fixed text for the action log (`rule`) and the error.

use std::error::Error;
use std::fmt;
use std::path::Path;

use crate::check::{FD_WALK, Os};

/// The path is not absolute.
pub(crate) const RULE_RELATIVE: &str = "path must be absolute";
/// The path has a `..` component.
pub(crate) const RULE_DOT_DOT: &str = "path must not contain ..";
/// No M1 check reads files on Windows.
pub(crate) const RULE_WINDOWS: &str = "file reads are not available on Windows";
/// `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`, `/etc/security/opasswd`, `/etc/master.passwd`.
pub(crate) const RULE_SYSTEM_SECRET: &str = "password and sudo files are never read";
/// `/etc/machine-id`, `/var/lib/dbus/machine-id`, `/run/machine-id` and the DMI serial and UUID files.
/// The raw id never reaches a log or a report; only the engine's own `MachineId` call reads the three
/// id files (ADR 0014 decision 5), and nothing reads the DMI files.
pub(crate) const RULE_MACHINE_ID_FILE: &str = "the machine id file is read by the engine only";
/// Cloud, tool and keychain credential files in a home directory.
pub(crate) const RULE_CREDENTIALS: &str = "credential files are never read";
/// Kernel memory, log and debug files.
pub(crate) const RULE_KERNEL: &str = "kernel memory, log and debug files are never read";
/// A `.ssh` directory.
pub(crate) const RULE_SSH: &str = "ssh directories are never read";
/// A private key file by name.
pub(crate) const RULE_PRIVATE_KEY: &str = "private key files are never read";
/// A `.kube` directory, a cluster node's kubeconfig, etcd data and service account tokens.
pub(crate) const RULE_KUBECONFIG: &str = "kubeconfig and cluster credential files are never read";
/// `/proc/<pid>/` entries that are not on the short allowlist.
pub(crate) const RULE_PROC: &str = "process memory, environment and command lines are never read";
/// A link in `/proc/<pid>/fd` that does not lead to a socket. The target is never logged or returned.
pub(crate) const RULE_FD_TARGET: &str = "only socket links are read from a process's fd directory";
/// `/dev`.
pub(crate) const RULE_DEVICE: &str = "device files are never read";

/// The path is outside every prefix the check declared in `reads`.
pub(crate) const RULE_OUTSIDE_READS: &str = "path is outside the check's declared reads";
/// The path is outside every prefix the check declared in `statfs`. The fix is a `statfs` prefix, not
/// a wider `reads`.
pub(crate) const RULE_OUTSIDE_STATFS: &str =
    "path is outside the check's declared statfs prefixes; add the prefix to `statfs`";
/// The target is not a regular file (a FIFO, a socket, a device, a directory).
#[cfg_attr(
    not(any(test, feature = "testing", all(feature = "runtime", unix))),
    expect(dead_code, reason = "only the Unix live backend refuses a target")
)]
pub(crate) const RULE_NOT_REGULAR: &str = "only regular files are read";
/// The target is not a directory.
#[cfg_attr(
    not(any(test, feature = "testing", all(feature = "runtime", unix))),
    expect(dead_code, reason = "only the Unix live backend refuses a target")
)]
pub(crate) const RULE_NOT_DIR: &str = "only directories are listed";
/// The target is neither a regular file nor a directory.
#[cfg_attr(
    not(any(test, feature = "testing", all(feature = "runtime", unix))),
    expect(dead_code, reason = "only the Unix live backend refuses a target")
)]
pub(crate) const RULE_NOT_FILE_OR_DIR: &str = "only files and directories are measured";
/// The file changed between the check and the open.
#[cfg_attr(
    not(all(feature = "runtime", unix)),
    expect(dead_code, reason = "only the Unix live backend refuses a target")
)]
pub(crate) const RULE_CHANGED: &str = "the file changed while it was being opened";

/// The places systemd and D-Bus keep the machine id, in the order `MachineId` tries them. All are denied
/// to every reader but the engine's `MachineId` call, which reads through
/// [`ReadGuard::machine_id_files`]. `/run/machine-id` is the transient copy systemd keeps when `/etc` is
/// read only, and some images bind mount it over `/etc/machine-id`.
#[cfg_attr(
    not(any(test, all(feature = "runtime", unix))),
    expect(dead_code, reason = "only the Unix live backend reads the files")
)]
pub(crate) const MACHINE_ID_FILES: &[&str] = &[
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/run/machine-id",
];

/// The DMI files that hold a serial number or a UUID. Nothing reads them: a serial is as stable and as
/// identifying as the machine id. They are matched under `dmi/id/` at any depth.
const DMI_SECRET_FILES: &[&str] = &[
    "product_serial",
    "product_uuid",
    "board_serial",
    "chassis_serial",
];

/// Why the live backend refused a call. It travels inside an [`std::io::Error`] of kind
/// `PermissionDenied`, and the probe turns it back into `ProbeError::Denied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub(crate) rule: &'static str,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.rule)
    }
}

impl Error for Refused {}

impl Refused {
    /// The `io::Error` that carries this refusal out of a backend.
    #[cfg_attr(
        not(any(test, feature = "testing", all(feature = "runtime", unix))),
        expect(dead_code, reason = "only the Unix live backend refuses a target")
    )]
    pub(crate) fn into_io(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, self)
    }

    /// The refusal inside `error`, if it carries one.
    pub(crate) fn from_io(error: &std::io::Error) -> Option<Self> {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Self>())
            .copied()
    }
}

/// What a check may read: the rules of one check's file calls. The probe builds it from the check's
/// `Os` and `CheckInfo::reads` and hands it to the backend, which applies [`ReadGuard::admit_real`] to
/// the resolved path. The `Statvfs` call builds it with `ReadGuard::statfs` from `CheckInfo::statfs`
/// instead, and a refusal by prefix then names `statfs`.
#[derive(Debug, Clone, Copy)]
pub struct ReadGuard {
    os: Os,
    /// `None` for a probe with no manifest: the denylist applies and no prefix is enforced.
    reads: Option<&'static [&'static str]>,
    /// The `MachineId` call's guard: only these paths pass, and the denylist is not asked.
    only: Option<&'static [&'static str]>,
    /// True for the `MachineId` guard alone. A future `only` list would not set it.
    machine_id: bool,
    /// True for the `Statvfs` guard: `reads` holds the check's `statfs` prefixes, and a refusal by
    /// prefix names `statfs` ([`RULE_OUTSIDE_STATFS`]) instead of `reads`.
    statfs: bool,
    /// What the call does with the path. The `/proc/<pid>/fd` rule and the `ns/net` link are open to one
    /// kind of call each.
    access: Access,
}

/// What a file call does with a path. It decides which `/proc/<pid>/` entries the guard opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// `read`, `read_tail`, `stat` and the `Statvfs` call. No `/proc/<pid>/` entry beyond the
    /// allowlist.
    Content,
    /// `read_dir`. A check that declared [`FD_WALK`] may list `/proc/<pid>/fd`.
    List,
    /// `read_link`. A check that declared [`FD_WALK`] may read the links in `/proc/<pid>/fd`, and any
    /// check may read `/proc/self/ns/net` when its `reads` cover it.
    Link,
}

impl ReadGuard {
    pub(crate) fn new(os: Os, reads: Option<&'static [&'static str]>) -> Self {
        Self {
            os,
            reads,
            only: None,
            machine_id: false,
            statfs: false,
            access: Access::Content,
        }
    }

    /// The guard of `read_dir`: [`ReadGuard::new`], and `/proc/<pid>/fd` may be listed by a check that
    /// declared [`FD_WALK`].
    pub(crate) fn listing(os: Os, reads: Option<&'static [&'static str]>) -> Self {
        Self {
            access: Access::List,
            ..Self::new(os, reads)
        }
    }

    /// The guard of `read_link`: the path is the link itself, judged where it sits. The links of
    /// `/proc/<pid>/fd` and `/proc/self/ns/net` are open to it, as [`ReadGuard::admit_link`] and the
    /// module text say.
    pub(crate) fn link(os: Os, reads: Option<&'static [&'static str]>) -> Self {
        Self {
            access: Access::Link,
            ..Self::new(os, reads)
        }
    }

    /// The guard of the `Statvfs` call: the same rules as [`ReadGuard::new`], with the check's `statfs`
    /// prefixes in place of `reads`. A path outside them is refused with [`RULE_OUTSIDE_STATFS`], so the
    /// log and the report point at `statfs` and not at `reads`.
    pub(crate) fn statfs(os: Os, prefixes: Option<&'static [&'static str]>) -> Self {
        Self {
            statfs: true,
            ..Self::new(os, prefixes)
        }
    }

    /// The guard of the `MachineId` call: it admits [`MACHINE_ID_FILES`] and nothing else, on the real
    /// path. Every other guard refuses those files, so this is the only reader.
    #[cfg_attr(
        not(any(test, all(feature = "runtime", target_os = "linux"))),
        expect(dead_code, reason = "only the Linux live backend reads the files")
    )]
    pub(crate) fn machine_id_files() -> Self {
        Self {
            os: Os::Linux,
            reads: None,
            only: Some(MACHINE_ID_FILES),
            machine_id: true,
            statfs: false,
            access: Access::Content,
        }
    }

    /// Whether this is the `MachineId` guard. The live backend skips its inode check of the machine id
    /// files for this guard only, because the guard already admits them by real path.
    #[cfg_attr(
        not(all(feature = "runtime", unix)),
        expect(dead_code, reason = "only the Unix live backend knows files by inode")
    )]
    pub(crate) fn reads_machine_id(&self) -> bool {
        self.machine_id
    }

    /// Decides from the path text alone. Used before any I/O.
    pub(crate) fn admit(&self, path: &Path) -> Result<(), &'static str> {
        self.decide(path, None)
    }

    /// Decides on a resolved path. The `auxv` file of rdy's own process id passes here (and no other
    /// pid does).
    ///
    /// # Errors
    ///
    /// The rule that refused the path.
    pub fn admit_real(&self, real: &Path) -> Result<(), Refused> {
        let pid = std::process::id().to_string();
        self.decide(real, Some(&pid))
            .map_err(|rule| Refused { rule })
    }

    /// Judges what a link says, after the backend read it. `real` is the link's own real path (its
    /// parent resolved, the link not followed). A link in `/proc/<pid>/fd` may lead to a socket only
    /// (`socket:[8841]`): a file, a pipe or anything else is refused with the rule "only socket links are read from a process's fd directory", and the
    /// target is not kept. Any other link is judged by where it sits and says what it says.
    ///
    /// # Errors
    ///
    /// The rule that refused the target: any target but a socket in an fd directory.
    pub fn admit_link(&self, real: &Path, target: &[u8]) -> Result<(), Refused> {
        // A real path is absolute and has no `..`. If it is not, something is wrong: refuse.
        let names = split(real, self.os == Os::Macos).map_err(|rule| Refused { rule })?;
        if is_fd_link(&names) && !is_socket_target(target) {
            return Err(Refused {
                rule: RULE_FD_TARGET,
            });
        }
        Ok(())
    }

    fn decide(&self, path: &Path, self_pid: Option<&str>) -> Result<(), &'static str> {
        if self.os == Os::Windows {
            return Err(RULE_WINDOWS);
        }
        let mac = self.os == Os::Macos;
        let names = split(path, mac)?;
        if let Some(only) = self.only {
            let listed = only
                .iter()
                .any(|file| split(Path::new(file), mac).is_ok_and(|file| file == names));
            return if listed {
                Ok(())
            } else {
                Err(RULE_OUTSIDE_READS)
            };
        }
        let grant = self.grant();
        deny(
            &names.iter().map(String::as_str).collect::<Vec<_>>(),
            self_pid,
            grant,
        )
        .map_or(Ok(()), Err)?;
        let Some(reads) = self.reads else {
            return Ok(());
        };
        // `/proc/net` is a link to `/proc/self/net`, and `/proc/self` is `/proc/<our pid>` once
        // resolved. Both the path and the declared prefixes are put in the `self` form, so a check
        // that declares `/proc/net` or `/proc/self/mountinfo` is not refused for where they lead.
        // The pid is rewritten on the path only on a real path. As written, a path with our pid in it
        // would otherwise decide differently on each host (a replay run has no pid of its own).
        let pid = std::process::id().to_string();
        let names = proc_form(names, &pid, self_pid.is_some());
        // The fd walk declaration covers the fd directory and its links, whatever the process id. It is
        // no prefix: `/proc/<pid>/fd` names no real path.
        let covered = (grant.fd && is_fd_path(&names))
            || reads.iter().any(|prefix| {
                split(Path::new(prefix), mac)
                    .is_ok_and(|prefix| names.starts_with(&proc_form(prefix, &pid, true)))
            });
        if covered {
            Ok(())
        } else if self.statfs {
            Err(RULE_OUTSIDE_STATFS)
        } else {
            Err(RULE_OUTSIDE_READS)
        }
    }
}

impl ReadGuard {
    /// The `/proc/<pid>/` entries this guard opens beyond the allowlist.
    fn grant(&self) -> Grant {
        let walk = self.reads.is_some_and(|reads| reads.contains(&FD_WALK));
        Grant {
            fd: walk && self.access != Access::Content,
            list: self.access == Access::List,
            ns_net: self.access == Access::Link,
        }
    }
}

/// What a guard opens in `/proc/<pid>/` beyond the allowlist (see [`Access`]).
#[derive(Debug, Clone, Copy)]
struct Grant {
    /// The check declared [`FD_WALK`] and the call lists or reads links: `/proc/<pid>/fd` for a
    /// listing, `/proc/<pid>/fd/<n>` for a link.
    fd: bool,
    /// The call is a listing, so the fd directory is the entry. Otherwise the links in it are.
    list: bool,
    /// The call reads a link, so `/proc/self/ns/net` is open.
    ns_net: bool,
}

impl Grant {
    /// Nothing beyond the allowlist.
    #[cfg(test)]
    const NONE: Self = Self {
        fd: false,
        list: false,
        ns_net: false,
    };
}

/// Whether `names` is `proc/<pid>/fd` or a link in it, with a process id that is a number or `self`.
pub(crate) fn is_fd_path<S: AsRef<str>>(names: &[S]) -> bool {
    match names {
        [proc, pid, fd] => proc.as_ref() == "proc" && fd_pid(pid.as_ref()) && fd.as_ref() == "fd",
        [proc, pid, fd, n] => {
            proc.as_ref() == "proc"
                && fd_pid(pid.as_ref())
                && fd.as_ref() == "fd"
                && is_number(n.as_ref())
        }
        _ => false,
    }
}

/// Whether `names` is a link in an fd directory: `proc/<pid>/fd/<n>`.
fn is_fd_link(names: &[String]) -> bool {
    is_fd_path(names) && names.len() == 4
}

/// A process directory a walk may use: a number or `self`. `thread-self` is not one: it resolves into
/// `task/<tid>/`, which the rules refuse.
fn fd_pid(name: &str) -> bool {
    name == "self" || is_number(name)
}

fn is_number(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit())
}

/// Whether a link target is a socket: `socket:[` digits `]`. Nothing else is read from an fd directory.
fn is_socket_target(target: &[u8]) -> bool {
    target
        .strip_prefix(b"socket:[")
        .and_then(|rest| rest.strip_suffix(b"]"))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.len() <= 20 && digits.iter().all(u8::is_ascii_digit)
        })
}

/// Puts `proc/<our pid>/...` and `proc/net/...` in the `proc/self/...` form.
fn proc_form(mut names: Vec<String>, pid: &str, rewrite_pid: bool) -> Vec<String> {
    if names.first().map(String::as_str) == Some("proc") {
        match names.get(1).map(String::as_str) {
            Some("net") => names.insert(1, "self".to_owned()),
            Some(second) if rewrite_pid && second == pid => {
                if let Some(slot) = names.get_mut(1) {
                    "self".clone_into(slot);
                }
            }
            _ => {}
        }
    }
    names
}

/// The names of an absolute Unix path, read as text so that the result does not depend on the host.
/// On macOS they are lower case and a leading `private` is dropped.
fn split(path: &Path, mac: bool) -> Result<Vec<String>, &'static str> {
    let text = path.to_string_lossy();
    if !text.starts_with('/') {
        return Err(RULE_RELATIVE);
    }
    let mut names: Vec<String> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(RULE_DOT_DOT),
            name => names.push(if mac {
                name.to_ascii_lowercase()
            } else {
                name.to_owned()
            }),
        }
    }
    if mac && names.first().map(String::as_str) == Some("private") {
        names.remove(0);
    }
    Ok(names)
}

/// The denylist alone, with the macOS rules switchable so they are testable on every OS.
#[cfg(test)]
pub(super) fn check_names(path: &Path, mac: bool) -> Result<(), &'static str> {
    let names = split(path, mac)?;
    deny(
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
        None,
        Grant::NONE,
    )
    .map_or(Ok(()), Err)
}

fn deny(names: &[&str], self_pid: Option<&str>, grant: Grant) -> Option<&'static str> {
    for (index, name) in names.iter().enumerate() {
        let rest = names.get(index + 1..).unwrap_or_default();
        let rule = match *name {
            ".ssh" => Some(RULE_SSH),
            ".kube" => Some(RULE_KUBECONFIG),
            ".aws" | ".azure" | ".gnupg" | ".netrc" | ".git-credentials" | ".pgpass"
            | ".vault-token" => Some(RULE_CREDENTIALS),
            ".config" if rest.first() == Some(&"gcloud") => Some(RULE_CREDENTIALS),
            ".docker" if rest.first() == Some(&"config.json") => Some(RULE_CREDENTIALS),
            "secrets" if matches!(rest, ["kubernetes.io", _, ..]) => Some(RULE_KUBECONFIG),
            "etc" => etc_rule(rest),
            "var" => var_rule(rest),
            // `/var/run` is a link to `/run`, and the loop reaches `run` on the next component.
            "run" if matches!(rest, [name, ..] if name.starts_with("machine-id")) => {
                Some(RULE_MACHINE_ID_FILE)
            }
            // `/sys/class/dmi/id` and `/sys/devices/virtual/dmi/id`, and a copy of either under a host
            // mount or a container layer.
            "dmi" if matches!(rest, ["id", file, ..] if DMI_SECRET_FILES.contains(file)) => {
                Some(RULE_MACHINE_ID_FILE)
            }
            "proc" => proc_rule(rest, self_pid, index == 0, grant),
            // Docker and Kubernetes secrets mounted into a container.
            "run" if matches!(rest, ["secrets", name, ..] if *name != "kubernetes.io") => {
                Some(RULE_CREDENTIALS)
            }
            _ => None,
        };
        if rule.is_some() {
            return rule;
        }
    }
    match names {
        ["dev", ..] => return Some(RULE_DEVICE),
        ["sys", "kernel", "debug" | "tracing", ..] => return Some(RULE_KERNEL),
        _ => {}
    }
    names
        .last()
        .filter(|name| private_key_name(name))
        .map(|_| RULE_PRIVATE_KEY)
}

/// What follows an `etc` component.
fn etc_rule(rest: &[&str]) -> Option<&'static str> {
    match rest {
        // The prefix also catches `shadow-`, the backup copy, and `sudoers.d`.
        [name, ..]
            if ["shadow", "gshadow", "sudoers", "master.passwd", "spwd.db"]
                .iter()
                .any(|prefix| name.starts_with(prefix)) =>
        {
            Some(RULE_SYSTEM_SECRET)
        }
        ["security", "opasswd", ..] => Some(RULE_SYSTEM_SECRET),
        // The id is stable per host. Only the salted `host_id` may leave the engine (M2-002).
        // The prefix also catches a backup such as `machine-id.bak`.
        [name, ..] if name.starts_with("machine-id") => Some(RULE_MACHINE_ID_FILE),
        ["ssl", "private", ..] | ["pki", "tls", "private", ..] => Some(RULE_PRIVATE_KEY),
        // Let's Encrypt keeps `privkey.pem` in `live` and every old copy in `archive`.
        ["letsencrypt", "live" | "archive", ..] => Some(RULE_PRIVATE_KEY),
        // `admin.conf`, `kubelet.conf` and the other kubeconfigs of a control plane node.
        ["kubernetes", name, ..] if name.ends_with(".conf") => Some(RULE_KUBECONFIG),
        // `k3s.yaml`, `rke2.yaml` and `config.yaml`, which can hold the join token.
        ["rancher", "k3s" | "rke2", name, ..] if name.ends_with(".yaml") => Some(RULE_KUBECONFIG),
        _ => None,
    }
}

/// What follows a `var` component.
fn var_rule(rest: &[&str]) -> Option<&'static str> {
    match rest {
        ["lib", "kubelet", "kubeconfig" | "pki", ..]
        | ["lib", "etcd", ..]
        | [
            "lib",
            "rancher",
            _,
            "server",
            "token" | "node-token" | "cred",
            ..,
        ] => Some(RULE_KUBECONFIG),
        ["lib", "dbus", name, ..] if name.starts_with("machine-id") => Some(RULE_MACHINE_ID_FILE),
        // The macOS directory service: account records with password hashes.
        ["db", "dslocal", ..] => Some(RULE_SYSTEM_SECRET),
        _ => None,
    }
}

/// What follows a `proc` component: the process directories (an allowlist) and the kernel files.
fn proc_rule(
    rest: &[&str],
    self_pid: Option<&str>,
    root: bool,
    grant: Grant,
) -> Option<&'static str> {
    match rest {
        [first, tail @ ..] if is_pid(first) => {
            (!pid_entry_allowed(first, tail, self_pid, root, grant)).then_some(RULE_PROC)
        }
        [name, ..]
            if matches!(
                *name,
                "kcore" | "kmsg" | "vmcore" | "kallsyms" | "keys" | "key-users" | "sysrq-trigger"
            ) || name.starts_with("kpage") =>
        {
            Some(RULE_KERNEL)
        }
        _ => None,
    }
}

/// A process directory name: digits, `self` or `thread-self`.
fn is_pid(name: &str) -> bool {
    name == "self"
        || name == "thread-self"
        || (!name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
}

/// The entries of `/proc/<pid>/` a check may read.
const PID_ALLOWED: &[&str] = &[
    "status",
    "stat",
    "statm",
    "comm",
    "cgroup",
    "mountinfo",
    "mounts",
    "limits",
    "net",
];

/// Whether `tail`, the part of the path after `/proc/<pid>`, is on the allowlist. `pid` is the name
/// of the process directory. `auxv` is allowed for `self` only: the privilege snapshot (M1-042) reads
/// `AT_SECURE` from the running process's own `/proc/self/auxv`. Another process's auxv holds its
/// load addresses and is not on the list. On a real path `/proc/self` has become `/proc/<pid>`, and
/// `self_pid` is rdy's own process id: only that pid passes, never any pid. `root` is true when
/// `proc` is the first component of the path: `/host/proc/self/auxv` belongs to another mount, and
/// its `self` or its pid is not ours.
fn pid_entry_allowed(
    pid: &str,
    tail: &[&str],
    self_pid: Option<&str>,
    root: bool,
    grant: Grant,
) -> bool {
    let own = pid == "self" || self_pid == Some(pid);
    match tail {
        [] | ["task"] => true,
        ["auxv"] => root && own,
        // The network namespace link of rdy's own process, for a `read_link` that the check's `reads`
        // cover. Another process's namespace links are not on any list.
        ["ns", "net"] => root && own && grant.ns_net,
        // The fd walk (M1-169): the directory for a listing, the links in it for a `read_link`.
        // `fd_pid` keeps `thread-self` out, and `task/<tid>/fd` stays refused below.
        ["fd"] => root && grant.fd && grant.list && fd_pid(pid),
        ["fd", n] => root && grant.fd && !grant.list && fd_pid(pid) && is_number(n),
        ["task", _tid, rest @ ..] => entry_allowed(rest),
        _ => entry_allowed(tail),
    }
}

fn entry_allowed(tail: &[&str]) -> bool {
    tail.first().is_none_or(|name| PID_ALLOWED.contains(name))
}

/// File names that hold private keys. A certificate (`.pem`, `.crt`) is not on the list: checks read
/// the system trust bundle.
fn private_key_name(name: &str) -> bool {
    // Case does not matter for a key file name, on any OS. Being strict costs nothing.
    let lower = name.to_ascii_lowercase();
    let name = lower.as_str();
    if let Some(key) = name.strip_prefix("id_") {
        return !key.ends_with(".pub");
    }
    if name.starts_with("ssh_host_") && name.ends_with("_key") {
        return true;
    }
    // A key in PEM form: `privkey.pem`, `tls-key.pem`, `server_key.pem`, `key.pem`. A certificate
    // (`cert.pem`, `fullchain.pem`) stays readable. `private*` also refuses a certificate such as
    // `private-ca.pem`; refusing too much fails closed, which is the side we want.
    if name.ends_with(".pem")
        && (name == "key.pem"
            || name.ends_with("-key.pem")
            || name.ends_with("_key.pem")
            || name.ends_with(".key.pem")
            || name.contains("privkey")
            || name.starts_with("private"))
    {
        return true;
    }
    name.rsplit_once('.').is_some_and(|(_, extension)| {
        matches!(
            extension,
            "key"
                | "p12"
                | "pfx"
                | "jks"
                | "keystore"
                | "ppk"
                | "keytab"
                | "keychain"
                | "keychain-db"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALK: &[&str] = &[FD_WALK];
    const NS: &[&str] = &["/proc/self/ns/net"];
    const PROC: &[&str] = &["/proc"];
    const ETC: &[&str] = &["/etc"];

    fn link(reads: &'static [&'static str]) -> ReadGuard {
        ReadGuard::link(Os::Linux, Some(reads))
    }

    fn list(reads: &'static [&'static str]) -> ReadGuard {
        ReadGuard::listing(Os::Linux, Some(reads))
    }

    fn content(reads: &'static [&'static str]) -> ReadGuard {
        ReadGuard::new(Os::Linux, Some(reads))
    }

    fn verdict(guard: &ReadGuard, path: &str) -> Result<(), &'static str> {
        guard.admit(Path::new(path))
    }

    #[test]
    fn the_fd_walk_opens_the_fd_directory_to_a_listing_and_its_links_to_read_link() {
        // A listing sees the directory. A link read sees the links. Nothing else sees either.
        assert_eq!(verdict(&list(WALK), "/proc/1234/fd"), Ok(()));
        assert_eq!(verdict(&list(WALK), "/proc/self/fd"), Ok(()));
        assert_eq!(verdict(&link(WALK), "/proc/1234/fd/7"), Ok(()));
        assert_eq!(verdict(&link(WALK), "/proc/self/fd/7"), Ok(()));
        assert_eq!(verdict(&list(WALK), "/proc/1234/fd/7"), Err(RULE_PROC));
        assert_eq!(verdict(&link(WALK), "/proc/1234/fd"), Err(RULE_PROC));
        // `read`, `stat` and `Statvfs` never see an fd, so the file behind a link is out of reach.
        for path in ["/proc/1234/fd", "/proc/1234/fd/7", "/proc/self/fd/0"] {
            assert_eq!(verdict(&content(WALK), path), Err(RULE_PROC), "{path}");
        }
    }

    #[test]
    fn the_fd_walk_needs_the_declaration_and_a_real_process_directory() {
        // `/proc` in `reads` is a prefix and no declaration.
        assert_eq!(verdict(&link(PROC), "/proc/1234/fd/7"), Err(RULE_PROC));
        assert_eq!(verdict(&list(PROC), "/proc/1234/fd"), Err(RULE_PROC));
        assert_eq!(
            verdict(&ReadGuard::link(Os::Linux, None), "/proc/1234/fd/7"),
            Err(RULE_PROC)
        );
        // The names a walk may not use: a thread's own directory, a task, a name that is no number,
        // a deeper path, another entry, a proc that is not at the root, and the directory itself.
        for path in [
            "/proc/thread-self/fd/3",
            "/proc/self/task/1/fd/3",
            "/proc/1234/task/1234/fd/3",
            "/proc/1234/fd/x",
            "/proc/1234/fd/3/x",
            "/proc/1234/fdinfo/3",
            "/host/proc/1234/fd/3",
            "/proc/1234/fd/",
        ] {
            assert!(verdict(&link(WALK), path).is_err(), "{path}");
        }
        assert_eq!(
            verdict(&link(WALK), "/proc/1234/fd/../x"),
            Err(RULE_DOT_DOT)
        );
    }

    #[test]
    fn the_fd_walk_covers_the_fd_directory_and_nothing_else() {
        // The declaration is no prefix: it does not open `/proc` or `/etc`.
        assert_eq!(
            verdict(&content(WALK), "/proc/meminfo"),
            Err(RULE_OUTSIDE_READS)
        );
        assert_eq!(
            verdict(&link(WALK), "/etc/os-release"),
            Err(RULE_OUTSIDE_READS)
        );
        assert_eq!(
            verdict(&link(WALK), "/proc/1234/comm"),
            Err(RULE_OUTSIDE_READS)
        );
        // A check with prefixes and the walk keeps both.
        static BOTH: &[&str] = &["/etc", FD_WALK];
        assert_eq!(verdict(&link(BOTH), "/etc/os-release"), Ok(()));
        assert_eq!(verdict(&link(BOTH), "/proc/1234/fd/9"), Ok(()));
    }

    #[test]
    fn only_rdys_own_net_namespace_link_is_open_and_only_to_read_link() {
        assert_eq!(verdict(&link(NS), "/proc/self/ns/net"), Ok(()));
        assert_eq!(verdict(&link(PROC), "/proc/self/ns/net"), Ok(()));
        // The prefix still applies.
        assert_eq!(
            verdict(&link(ETC), "/proc/self/ns/net"),
            Err(RULE_OUTSIDE_READS)
        );
        // No other process, no other namespace, no other call.
        assert_eq!(verdict(&link(PROC), "/proc/1/ns/net"), Err(RULE_PROC));
        assert_eq!(verdict(&link(PROC), "/proc/self/ns/mnt"), Err(RULE_PROC));
        assert_eq!(verdict(&link(PROC), "/proc/self/ns"), Err(RULE_PROC));
        assert_eq!(verdict(&content(PROC), "/proc/self/ns/net"), Err(RULE_PROC));
        assert_eq!(verdict(&list(PROC), "/proc/self/ns"), Err(RULE_PROC));
        // On a real path the pid is ours and only ours.
        let own = format!("/proc/{}/ns/net", std::process::id());
        assert_eq!(link(PROC).admit_real(Path::new(&own)), Ok(()));
        assert_eq!(
            link(PROC).admit_real(Path::new("/proc/1/ns/net")),
            Err(Refused { rule: RULE_PROC })
        );
        assert_eq!(
            link(PROC).admit_real(Path::new("/host/proc/self/ns/net")),
            Err(Refused { rule: RULE_PROC })
        );
    }

    #[test]
    fn a_link_is_judged_by_the_denylist_where_it_sits() {
        let guard = link(ETC);
        assert_eq!(verdict(&guard, "/etc/os-release"), Ok(()));
        assert_eq!(verdict(&guard, "/etc/shadow"), Err(RULE_SYSTEM_SECRET));
        assert_eq!(
            verdict(&guard, "/etc/machine-id"),
            Err(RULE_MACHINE_ID_FILE)
        );
        assert_eq!(
            verdict(&guard, "/etc/ssl/private/ca.key"),
            Err(RULE_PRIVATE_KEY)
        );
        assert_eq!(verdict(&guard, "/var/lib/x"), Err(RULE_OUTSIDE_READS));
        assert_eq!(verdict(&guard, "etc/os-release"), Err(RULE_RELATIVE));
        assert_eq!(
            verdict(&ReadGuard::link(Os::Windows, Some(ETC)), "/etc/x"),
            Err(RULE_WINDOWS)
        );
    }

    #[test]
    fn an_fd_link_leads_to_a_socket_or_it_is_refused() {
        let guard = link(WALK);
        let fd = Path::new("/proc/1234/fd/7");
        let refused = Err(Refused {
            rule: RULE_FD_TARGET,
        });
        for target in [
            "socket:[8841]",
            "socket:[1]",
            "socket:[18446744073709551615]",
        ] {
            assert_eq!(guard.admit_link(fd, target.as_bytes()), Ok(()), "{target}");
        }
        for target in [
            "/home/ada/notes.txt",
            "pipe:[17]",
            "anon_inode:[eventpoll]",
            "/dev/null",
            "socket:[]",
            "socket:[x]",
            "socket:[1]x",
            "socket:[1][2]",
            "socket:[ 1]",
            "socket:[123456789012345678901]",
            "/tmp/socket:[1]",
            "",
        ] {
            assert_eq!(guard.admit_link(fd, target.as_bytes()), refused, "{target}");
        }
        assert_eq!(guard.admit_link(fd, b"/home/\xff\xfe"), refused);
        // A link anywhere else says what it says: its target is not judged.
        let etc = Path::new("/etc/os-release");
        assert_eq!(guard.admit_link(etc, b"/etc/shadow"), Ok(()));
        let ns = Path::new("/proc/self/ns/net");
        assert_eq!(guard.admit_link(ns, b"net:[4026531840]"), Ok(()));
        assert_eq!(
            guard.admit_link(Path::new("/proc/1234/fd"), b"anything"),
            Ok(())
        );
    }

    #[test]
    fn the_fd_rule_reads_the_check_not_the_machine() {
        // A macOS check has no /proc, but its names are judged the same way.
        let guard = ReadGuard::link(Os::Macos, Some(WALK));
        assert_eq!(guard.admit(Path::new("/proc/1234/fd/7")), Ok(()));
        assert_eq!(
            guard.admit_link(Path::new("/PROC/1234/FD/7"), b"/etc/x"),
            Err(Refused {
                rule: RULE_FD_TARGET
            })
        );
    }

    #[test]
    fn only_the_machine_id_guard_reads_the_machine_id() {
        assert!(ReadGuard::machine_id_files().reads_machine_id());
        assert!(!ReadGuard::new(Os::Linux, None).reads_machine_id());
        // Another `only` allowlist does not skip the inode check.
        let other = ReadGuard {
            only: Some(&["/etc/hostname"]),
            ..ReadGuard::new(Os::Linux, None)
        };
        assert!(!other.reads_machine_id());
    }
}
