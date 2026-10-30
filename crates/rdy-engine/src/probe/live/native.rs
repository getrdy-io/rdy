//! Unix native calls for the live backend. Each variant of `NativeCall` has one arm in [`call`], and
//! there is no wildcard, so a new variant does not compile until it has one.
//!
//! Everything here uses safe `rustix` wrappers. No answer is logged: the probe writes the entry before
//! it asks, and it holds the call only.

use std::io;

use rustix::process::{self, Resource as Limit};

use super::files::{self, Secrets};
use crate::probe::{
    NativeCall, NativeValue, ReadGuard, Resource, RlimitInfo, StatvfsInfo, UnameInfo,
};

/// Runs one call. Blocking: the caller puts it on the blocking pool.
pub(super) fn call(
    call: &NativeCall,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<NativeValue> {
    match call {
        NativeCall::Statvfs { path } => {
            let (raw, dev) = files::statvfs(path, guard, secrets)?;
            Ok(NativeValue::Statvfs(statvfs_info(&raw, dev)))
        }
        NativeCall::Uname => {
            let raw = rustix::system::uname();
            Ok(NativeValue::Uname(UnameInfo {
                sysname: text(raw.sysname()),
                release: text(raw.release()),
                version: text(raw.version()),
                machine: text(raw.machine()),
            }))
        }
        NativeCall::Rlimit(resource) => {
            let raw = process::getrlimit(limit(*resource));
            Ok(NativeValue::Rlimit(RlimitInfo {
                soft: raw.current,
                hard: raw.maximum,
            }))
        }
        NativeCall::Hostname => Ok(NativeValue::Hostname(text(
            rustix::system::uname().nodename(),
        ))),
        NativeCall::MachineId => machine_id(secrets),
        // The OS store is read by M1-092, which owns the TLS facade and the root handling.
        NativeCall::SystemRoots => Err(io::Error::from(io::ErrorKind::Unsupported)),
    }
}

fn text(raw: &std::ffi::CStr) -> String {
    raw.to_string_lossy().into_owned()
}

fn limit(resource: Resource) -> Limit {
    match resource {
        Resource::Nofile => Limit::Nofile,
        Resource::Nproc => Limit::Nproc,
        Resource::Core => Limit::Core,
        Resource::Memlock => Limit::Memlock,
        Resource::Stack => Limit::Stack,
    }
}

fn statvfs_info(raw: &rustix::fs::StatVfs, dev: rustix::fs::Dev) -> StatvfsInfo {
    use rustix::fs::StatVfsMountFlags as Flags;
    StatvfsInfo {
        fragment_size: raw.f_frsize,
        blocks: raw.f_blocks,
        blocks_free: raw.f_bfree,
        blocks_available: raw.f_bavail,
        files: raw.f_files,
        files_free: raw.f_ffree,
        read_only: raw.f_flag.contains(Flags::RDONLY),
        no_exec: no_exec(raw.f_flag),
        no_suid: raw.f_flag.contains(Flags::NOSUID),
        dev: Some((rustix::fs::major(dev), rustix::fs::minor(dev))),
    }
}

/// `ST_NOEXEC` where the OS has it. rustix defines the flag on Linux and Android only, and the macOS
/// `statvfs` flags carry no equivalent, so there the answer is unknown (`None`), never "not set": a
/// check that forbids `noexec` must not pass on a guess.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn no_exec(flags: rustix::fs::StatVfsMountFlags) -> Option<bool> {
    Some(flags.contains(rustix::fs::StatVfsMountFlags::NOEXEC))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn no_exec(flags: rustix::fs::StatVfsMountFlags) -> Option<bool> {
    let _ = flags;
    None
}

/// Linux reads the id as a file, through a guard that admits only [`MACHINE_ID_FILES`] (the denylist
/// refuses all three names to every other reader) and with a 128 byte cap. macOS has none in M1, so its
/// `host_id` is null.
#[cfg(target_os = "linux")]
fn machine_id(secrets: &Secrets) -> io::Result<NativeValue> {
    use crate::probe::policy::MACHINE_ID_FILES;
    use crate::probe::{MachineId, ReadRange};
    let guard = ReadGuard::machine_id_files();
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for file in MACHINE_ID_FILES {
        match files::read(
            std::path::Path::new(file),
            ReadRange::Head(128),
            &guard,
            secrets,
        ) {
            Ok(bytes) => {
                let raw = String::from_utf8_lossy(&bytes.bytes);
                return parse_machine_id(&raw)
                    .map(|id| NativeValue::MachineId(MachineId::new(id)))
                    .ok_or_else(|| {
                        // The text is the problem, never the value.
                        io::Error::other("the machine id file does not hold a 32 digit hex id")
                    });
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(not(target_os = "linux"))]
fn machine_id(secrets: &Secrets) -> io::Result<NativeValue> {
    let _ = secrets;
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// The id in the text of a machine id file: 32 hex digits and a newline. Anything else (the word
/// `uninitialized` on a first boot, an empty file) is not an id.
#[cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(
        dead_code,
        reason = "Linux reads the file; the tests run it everywhere"
    )
)]
fn parse_machine_id(raw: &str) -> Option<String> {
    let id = raw.trim();
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
