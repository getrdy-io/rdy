//! Shared helpers for the binary tests.
//!
//! CI runners and some shells leave descriptors above 2 open in the test process, and `rdy` warns
//! about them on stderr (M1-168). Tests that compare stderr exactly, or assert it is empty, drop that
//! one warning first. The binary has no flag or variable to silence it, and none must be added.

#![allow(dead_code)]

use std::process::Output;

/// The start of the inherited-descriptor warning line.
pub const FD_WARNING_PREFIX: &str = "warning: rdy inherited open file descriptor";

/// `stderr` without the lines that start with [`FD_WARNING_PREFIX`].
#[must_use]
pub fn without_fd_warning(stderr: &[u8]) -> Vec<u8> {
    let prefix = FD_WARNING_PREFIX.as_bytes();
    stderr
        .split_inclusive(|b| *b == b'\n')
        .filter(|line| !line.starts_with(prefix))
        .flatten()
        .copied()
        .collect()
}

/// `out` with the inherited-descriptor warning removed from its stderr.
#[must_use]
pub fn quiet(mut out: Output) -> Output {
    out.stderr = without_fd_warning(&out.stderr);
    out
}
