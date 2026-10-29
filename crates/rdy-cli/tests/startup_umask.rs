//! `main_code` hardens the umask first (M1-168, ADR 0023), proved in process.
//!
//! This binary holds one test, because the umask is process wide. The black-box half, through the
//! built `rdy`, is in `startup_hardening.rs`.

#![cfg(unix)]

use rustix::fs::Mode;

#[test]
fn main_code_sets_the_umask_to_077() {
    rustix::process::umask(Mode::WGRP | Mode::WOTH);
    // The harness arguments are not an `rdy` command line: 64 (usage), or 0 (help) with none. It ran the
    // start-up steps first either way, which is all this test needs.
    let code = rdy_cli::entry::main_code();
    assert!(code == 64 || code == 0, "exit code {code}");
    let after = rustix::process::umask(Mode::empty());
    assert_eq!(
        after,
        Mode::RWXG | Mode::RWXO,
        "umask is {:o}",
        after.bits()
    );
}
