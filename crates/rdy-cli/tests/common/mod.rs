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

// In-process runs (M1-074). `rdy_cli::run` takes the privilege snapshot through its backend, so a test
// that runs a command in process hands it a replay machine that answers as an ordinary user.

use std::sync::Arc;

use rdy_cli::RunHooks;
use rdy_engine::check::{Os, current_os};
use rdy_engine::testing::Replay;

/// The text of `/proc/self/status` for the given ids and capability masks.
#[must_use]
pub fn proc_status(uid: [u32; 4], gid: [u32; 4], cap_eff: u64, cap_amb: u64) -> String {
    format!(
        "Name:\trdy\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nCapEff:\t{cap_eff:016x}\nCapPrm:\t{cap_eff:016x}\nCapAmb:\t{cap_amb:016x}\n",
        uid[0], uid[1], uid[2], uid[3], gid[0], gid[1], gid[2], gid[3]
    )
}

/// An auxiliary vector with `AT_PHDR`, `AT_SECURE` set to `secure`, and `AT_NULL`.
#[must_use]
pub fn proc_auxv(secure: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (key, value) in [(3_usize, 0x5555_0000_usize), (23, secure), (0, 0)] {
        bytes.extend(key.to_ne_bytes());
        bytes.extend(value.to_ne_bytes());
    }
    bytes
}

/// A machine whose privilege snapshot is clean: user 1000, no capability, no `AT_SECURE`. It is for
/// the OS the tests run on, because the snapshot reads the sources of that OS. On Windows the snapshot
/// has nothing to read without a `whoami` recording, and answers "unknown", which passes.
#[must_use]
pub fn unprivileged() -> Replay {
    let user = [1000; 4];
    match current_os() {
        Os::Windows => Replay::for_os(Os::Windows),
        Os::Macos => Replay::for_os(Os::Macos).ids(user, user),
        _ => Replay::new()
            .file("/proc/self/status", proc_status(user, user, 0, 0))
            .file("/proc/self/auxv", proc_auxv(0)),
    }
}

/// Runs `rdy_cli::run` on `machine` with default hooks and the given buffers. A runtime is built for
/// the call, so a plain `#[test]` can use it.
pub fn run_on<I, T>(machine: Replay, argv: I, out: &mut Vec<u8>, err: &mut Vec<u8>) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    runtime
        .block_on(rdy_cli::run(
            argv,
            Arc::new(machine),
            RunHooks::default(),
            out,
            err,
        ))
        .code()
}

/// Like [`run_on`], on an unprivileged machine.
pub fn run_in_process<I, T>(argv: I, out: &mut Vec<u8>, err: &mut Vec<u8>) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    run_on(unprivileged(), argv, out, err)
}
