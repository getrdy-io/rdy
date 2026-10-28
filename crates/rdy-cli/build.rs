//! Build script. It builds the version line `rdy --version` prints (ADR 0011).
//!
//! The line is `<version> (<commit> <date>)`. The commit is the first 7 characters of the hash of
//! `HEAD`. The date is the commit date in UTC, not the build date, so two builds of one commit print
//! the same line. The rules live in `build_version.rs` and are tested there:
//!
//! - In a `cargo package` tree (`.cargo_vcs_info.json` exists) git is never run. The line is
//!   `<version> (<commit>)` with the commit cargo recorded, or just `<version>`.
//! - Otherwise git is used only if its top-level directory is this workspace.
//! - Otherwise the line is just `<version>`.
//!
//! The script runs `git` and nothing else. It uses no network and writes only `RDY_VERSION`.

use std::path::{Path, PathBuf};
use std::process::Command;

mod build_version;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_version.rs");

    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let vcs_info = std::fs::read_to_string(manifest_dir.join(".cargo_vcs_info.json")).ok();
    if vcs_info.is_none() {
        watch_git_head();
    }

    let source = build_version::source(
        vcs_info.as_deref(),
        || toplevel_is_workspace(&manifest_dir),
        git_head,
    );
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let line = build_version::line(&version, &source);
    println!("cargo:rustc-env=RDY_VERSION={line}");
}

/// Run git in the package directory and return trimmed stdout, or `None` on any failure.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// True when git's top-level directory is the workspace root (two levels above this package).
fn toplevel_is_workspace(manifest_dir: &Path) -> bool {
    let Some(top) = git(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let workspace = manifest_dir.join("..").join("..");
    match (Path::new(&top).canonicalize(), workspace.canonicalize()) {
        (Ok(top), Ok(workspace)) => top == workspace,
        _ => false,
    }
}

/// The full hash and the commit time (Unix seconds) of `HEAD`.
fn git_head() -> Option<(String, i64)> {
    let out = git(&[
        "log",
        "-1",
        "--no-show-signature",
        "--format=%H%n%ct",
        "HEAD",
    ])?;
    let (hash, secs) = out.split_once('\n')?;
    Some((hash.trim().to_string(), secs.trim().parse().ok()?))
}

/// Rebuild when `HEAD`, the branch it points at, or the packed refs move.
fn watch_git_head() {
    for name in ["HEAD", "packed-refs"] {
        if let Some(path) = git(&["rev-parse", "--git-path", name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
}
