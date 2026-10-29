//! The read denylist (threat model I5, 02 "Files").
//!
//! [`check_read`] decides from the path text alone, with no I/O. It runs before any file is touched,
//! for `read`, `read_dir` and `stat`. It is the first of two layers. M1-045 adds the second: the real
//! path (after links) is matched against the same list, and a check's declared `reads` prefixes are
//! enforced. Until then a link to a denied file is not caught here.
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
//! **`/proc/<pid>/`** is an allowlist, not a denylist: only `status`, `stat`, `statm`, `comm`, `cgroup`,
//! `mountinfo`, `mounts`, `limits` and `net` (and the same under `task/<tid>/`) are readable. Everything
//! else there is refused, including `cwd`, `exe`, `root`, `fd`, `environ`, `cmdline`, `mem`, `maps`
//! and `ns`, so `/proc/1/cwd/etc/shadow` cannot reach a file through a process link.
//!
//! **`/dev`** is refused for `stat` and `read_dir` as well as `read`, because a device node name says
//! which hardware a machine has. M4 (GPU checks) adds a closed, stat-only list: `/dev/nvidia*`,
//! `/dev/dri/*` and `/dev/kfd`.
//!
//! The rules return a fixed text for the action log (`rule`) and the error.

use std::path::{Component, Path};

/// The path is not absolute.
pub(crate) const RULE_RELATIVE: &str = "path must be absolute";
/// The path has a `..` component.
pub(crate) const RULE_DOT_DOT: &str = "path must not contain ..";
/// No M1 check reads files on Windows.
pub(crate) const RULE_WINDOWS: &str = "file reads are not available on Windows";
/// `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`, `/etc/security/opasswd`, `/etc/master.passwd`.
pub(crate) const RULE_SYSTEM_SECRET: &str = "password and sudo files are never read";
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
/// `/dev`.
pub(crate) const RULE_DEVICE: &str = "device files are never read";

/// Why a read of `path` is refused, or `Ok` when the denylist has no objection.
///
/// An `Ok` is not a grant. The caller still applies the declared `reads` prefixes (M1-045).
pub(crate) fn check_read(path: &Path) -> Result<(), &'static str> {
    if cfg!(windows) {
        return Err(RULE_WINDOWS);
    }
    check_names(path, cfg!(target_os = "macos"))
}

/// The matching, with the macOS rules switchable so they are testable on every OS.
pub(super) fn check_names(path: &Path, mac: bool) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err(RULE_RELATIVE);
    }
    let mut names: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => return Err(RULE_DOT_DOT),
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                names.push(if mac {
                    name.to_ascii_lowercase()
                } else {
                    name.into_owned()
                });
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    if mac && names.first().map(String::as_str) == Some("private") {
        names.remove(0);
    }
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    deny(&names).map_or(Ok(()), Err)
}

fn deny(names: &[&str]) -> Option<&'static str> {
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
            "proc" => proc_rule(rest),
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
        ["ssl", "private", ..] | ["pki", "tls", "private", ..] => Some(RULE_PRIVATE_KEY),
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
        ["lib", "kubelet", "kubeconfig", ..]
        | ["lib", "etcd", ..]
        | [
            "lib",
            "rancher",
            _,
            "server",
            "token" | "node-token" | "cred",
            ..,
        ] => Some(RULE_KUBECONFIG),
        // The macOS directory service: account records with password hashes.
        ["db", "dslocal", ..] => Some(RULE_SYSTEM_SECRET),
        _ => None,
    }
}

/// What follows a `proc` component: the process directories (an allowlist) and the kernel files.
fn proc_rule(rest: &[&str]) -> Option<&'static str> {
    match rest {
        [first, tail @ ..] if is_pid(first) => {
            (!pid_entry_allowed(first, tail)).then_some(RULE_PROC)
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
/// load addresses and is not on the list.
fn pid_entry_allowed(pid: &str, tail: &[&str]) -> bool {
    match tail {
        [] | ["task"] => true,
        ["auxv"] => pid == "self",
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
