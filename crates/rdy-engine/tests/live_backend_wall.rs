//! Check crates cannot call `live_backend` (M1-046, INV-07).
//!
//! `rdy_engine::live_backend` builds the backend that reads the real machine. A check must use the
//! `Probe` it is handed, so the function is on the `disallowed-methods` list of every check crate.
//!
//! Clippy reads one `clippy.toml` per crate: the crate's own, or the workspace root's when the crate
//! has none. A crate's own file replaces the root file, so a check crate that adds a `clippy.toml`
//! must repeat the entry. This test finds the file clippy would read for each `crates/rdy-checks-*`
//! crate and fails if the entry is missing. That guards the case clippy itself cannot see: a new file
//! that silently drops the wall.
//!
//! The lint firing is proved by clippy in CI (`cargo clippy --workspace --all-targets`, which also
//! covers the engine's own tests, where the one allowed call carries an `expect`). M1-044 adds the
//! `tests/lint-wall` harness that uses every entry once.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

const ENTRY: &str = "rdy_engine::live_backend";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether `file` has a `disallowed-methods` entry for `ENTRY` that is not a comment.
fn lists_live_backend(file: &Path) -> bool {
    let text = fs::read_to_string(file).unwrap_or_default();
    text.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with('#') && line.contains(&format!("path = \"{ENTRY}\""))
    })
}

fn check_crates() -> Vec<PathBuf> {
    let mut crates: Vec<PathBuf> = fs::read_dir(workspace_root().join("crates"))
        .expect("read crates/")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rdy-checks-"))
        })
        .collect();
    crates.sort();
    crates
}

#[test]
fn the_root_clippy_file_lists_live_backend() {
    assert!(
        lists_live_backend(&workspace_root().join("clippy.toml")),
        "clippy.toml must list {ENTRY} in disallowed-methods"
    );
}

#[test]
fn every_check_crate_reads_a_clippy_file_that_lists_live_backend() {
    let crates = check_crates();
    assert!(!crates.is_empty(), "no check crates found under crates/");
    for dir in crates {
        let own = dir.join("clippy.toml");
        let effective = if own.exists() {
            own
        } else {
            workspace_root().join("clippy.toml")
        };
        assert!(
            lists_live_backend(&effective),
            "{} reads {}, which must list {ENTRY} in disallowed-methods. A crate's own clippy.toml \
             replaces the root file, so it must repeat the entry",
            dir.display(),
            effective.display()
        );
    }
}
