//! Virtual paths of a fixture (08 section 2, "Plan corrections found").
//!
//! A `Path` from a check depends on the runner: `Path::new("/proc").join("net")` is `/proc\net` on
//! Windows. The replay backend therefore works on strings. A key is POSIX text: `/proc/meminfo`. For a
//! fixture whose `os` is `windows` it is lower case and starts with a drive, `c:/windows/system32`, and
//! `root/c/Windows/...` in the tree maps to it. Case is kept on Linux and macOS.

use crate::check::Os;

/// Whether `part` is a drive component such as `c:`.
pub(super) fn is_drive(part: &str) -> bool {
    part.len() == 2 && part.ends_with(':') && part.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// The components of path text, for a fixture of `os`. Empty parts and `.` are dropped; `..` stays.
pub(super) fn components(os: Os, text: &str) -> Vec<String> {
    // A Windows runner joins with a backslash whatever the fixture's os is.
    let slashed = if os == Os::Windows || cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
    };
    let text = if os == Os::Windows {
        slashed.to_lowercase()
    } else {
        slashed
    };
    text.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_owned)
        .collect()
}

/// The key for these components.
pub(super) fn join(os: Os, parts: &[String]) -> String {
    match parts.first() {
        None => "/".to_owned(),
        Some(first) if os == Os::Windows && is_drive(first) => {
            if parts.len() == 1 {
                format!("{first}/")
            } else {
                parts.join("/")
            }
        }
        Some(_) => format!("/{}", parts.join("/")),
    }
}

/// The key for path text.
pub(super) fn key(os: Os, text: &str) -> String {
    join(os, &components(os, text))
}

/// Whether link target text is an absolute path.
pub(super) fn is_absolute(os: Os, target: &str) -> bool {
    let slashed = if os == Os::Windows || cfg!(windows) {
        target.replace('\\', "/")
    } else {
        target.to_owned()
    };
    slashed.starts_with('/') || (os == Os::Windows && slashed.get(..2).is_some_and(is_drive))
}

/// The key of a file in `root/`, from its path below `root/` (`proc/meminfo`, or `c/Windows/x` for a
/// Windows fixture).
pub(super) fn tree_key(os: Os, rel: &str) -> String {
    if os == Os::Windows {
        let mut parts = rel.split('/');
        if let Some(first) = parts.next()
            && first.len() == 1
            && first.starts_with(|c: char| c.is_ascii_alphabetic())
        {
            let rest: Vec<&str> = parts.collect();
            return key(os, &format!("{first}:/{}", rest.join("/")));
        }
    }
    key(os, &format!("/{rel}"))
}

/// Whether a link target is not a path: what `/proc/<pid>/fd/<n>` shows for a socket, a pipe or an
/// anonymous inode (`socket:[8841]`, `pipe:[17]`, `anon_inode:[eventpoll]`).
pub(super) fn is_special_target(target: &str) -> bool {
    let Some((kind, rest)) = target.split_once(":[") else {
        return false;
    };
    let Some(inner) = rest.strip_suffix(']') else {
        return false;
    };
    !kind.is_empty()
        && kind.chars().all(|c| c.is_ascii_lowercase() || c == '_')
        && !inner.contains([']', '/', '\\'])
}
