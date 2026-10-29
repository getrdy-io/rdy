//! Files made by `create_new_private` and `create_new_public` have exact modes under any umask
//! (M1-168).
//!
//! The umask is process wide, so this binary holds one test. Changing it inside the library's own
//! test binary would reach every test that creates a file in parallel.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rdy_cli::signing::files::{create_new_private, create_new_public};
use rustix::fs::Mode;

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat: {e}"))
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn new_files_have_exact_modes_under_umask_000_022_and_077() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
    for (label, mask) in [
        ("000", Mode::empty()),
        ("022", Mode::WGRP | Mode::WOTH),
        ("077", Mode::RWXG | Mode::RWXO),
    ] {
        rustix::process::umask(mask);
        let public = dir.path().join(format!("{label}.pub"));
        let private = dir.path().join(format!("{label}.key"));
        drop(create_new_public(&public).unwrap_or_else(|e| panic!("umask {label}: {e}")));
        drop(create_new_private(&private).unwrap_or_else(|e| panic!("umask {label}: {e}")));
        assert_eq!(mode_of(&public), 0o644, "public file, umask {label}");
        assert_eq!(mode_of(&private), 0o600, "private file, umask {label}");
    }
}
