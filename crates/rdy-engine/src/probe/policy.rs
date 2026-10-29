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
//! The rules return a fixed text for the action log (`rule`) and the error.

use std::path::{Component, Path};

/// The path is not absolute.
pub(crate) const RULE_RELATIVE: &str = "path must be absolute";
/// The path has a `..` component.
pub(crate) const RULE_DOT_DOT: &str = "path must not contain ..";
/// No M1 check reads files on Windows.
pub(crate) const RULE_WINDOWS: &str = "file reads are not available on Windows";
/// `/etc/shadow`, `/etc/gshadow` and `/etc/sudoers*`.
pub(crate) const RULE_SYSTEM_SECRET: &str = "password and sudo files are never read";
/// A `.ssh` directory.
pub(crate) const RULE_SSH: &str = "ssh directories are never read";
/// A private key file by name.
pub(crate) const RULE_PRIVATE_KEY: &str = "private key files are never read";
/// A `.kube` directory.
pub(crate) const RULE_KUBECONFIG: &str = "kubeconfig directories are never read";
/// `/proc/<pid>/environ` and friends, and `/proc/kcore`.
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
    if names.contains(&".ssh") {
        return Some(RULE_SSH);
    }
    if names.contains(&".kube") {
        return Some(RULE_KUBECONFIG);
    }
    match names {
        ["dev", ..] => return Some(RULE_DEVICE),
        ["proc", rest @ ..] if proc_secret(rest) => return Some(RULE_PROC),
        ["etc", name, ..] if system_secret(name) => return Some(RULE_SYSTEM_SECRET),
        ["etc", "ssl" | "pki", ..] if private_dir(names) => return Some(RULE_PRIVATE_KEY),
        _ => {}
    }
    names
        .last()
        .filter(|name| private_key_name(name))
        .map(|_| RULE_PRIVATE_KEY)
}

/// `/proc/kcore`, and the secret entries of a process directory and of its tasks.
fn proc_secret(rest: &[&str]) -> bool {
    match rest {
        ["kcore", ..] => true,
        [_pid, "task", _tid, name, ..] => proc_entry(name),
        [_pid, name, ..] => proc_entry(name),
        _ => false,
    }
}

fn proc_entry(name: &str) -> bool {
    matches!(
        name,
        "environ" | "cmdline" | "mem" | "fd" | "root" | "map_files"
    )
}

/// Names directly under `/etc` that start with `shadow`, `gshadow` or `sudoers`. The prefix also
/// catches `shadow-`, the backup copy, and `sudoers.d`.
fn system_secret(name: &str) -> bool {
    ["shadow", "gshadow", "sudoers"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// `/etc/ssl/private` and `/etc/pki/tls/private`, and everything below them.
fn private_dir(names: &[&str]) -> bool {
    matches!(
        names,
        ["etc", "ssl", "private", ..] | ["etc", "pki", "tls", "private", ..]
    )
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
            "key" | "p12" | "pfx" | "jks" | "keystore" | "ppk"
        )
    })
}
