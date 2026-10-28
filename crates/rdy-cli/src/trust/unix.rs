//! Reading and writing a trust store on Unix, with every check on an open handle.
//!
//! The folder is opened first. For the system store it is opened with `O_NOFOLLOW`, so `/etc/rdy` as a
//! symlink is refused. The file is then opened inside that folder with `openat`, with `O_NOFOLLOW` and
//! `O_NONBLOCK`, so a symlink is refused and a FIFO cannot hang the read. The owner and the mode come
//! from the open handle. The path is never looked at again for a decision. A failed open looks at the
//! path once, only to name the reason.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

use rdy_spec::sig::MAX_TRUST_BYTES;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use super::{Insecurity, Layout, Scope, TrustStoreError};
use crate::error::IoReason;

/// Group and others may not write.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// The effective user id of this process.
pub(super) fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn insecure(path: &Path, scope: Scope, why: Insecurity) -> TrustStoreError {
    TrustStoreError::Insecure {
        path: path.to_path_buf(),
        scope,
        why,
    }
}

fn unreadable(path: &Path, errno: Errno) -> TrustStoreError {
    TrustStoreError::Unreadable {
        path: path.to_path_buf(),
        reason: IoReason::from_io(&std::io::Error::from(errno)),
    }
}

fn write_error(path: &Path, scope: Scope, err: &std::io::Error) -> TrustStoreError {
    TrustStoreError::Write {
        path: path.to_path_buf(),
        scope,
        reason: IoReason::from_io(err),
    }
}

/// True when `path` itself is a symbolic link. Only used to name why an open failed.
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// The folder and the name of a store path.
fn split(path: &Path) -> Result<(&Path, &OsStr), TrustStoreError> {
    let name = path
        .file_name()
        .ok_or_else(|| TrustStoreError::Unreadable {
            path: path.to_path_buf(),
            reason: IoReason::NotAFile,
        })?;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    Ok((dir.unwrap_or(Path::new(".")), name))
}

/// Opens the folder of a store. `None` when it does not exist.
fn open_dir(path: &Path, scope: Scope, layout: &Layout) -> Result<Option<File>, TrustStoreError> {
    let (dir_path, _) = split(path)?;
    let mut flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    if scope == Scope::System {
        flags |= OFlags::NOFOLLOW;
    }
    match rustix::fs::open(dir_path, flags, Mode::empty()) {
        Ok(fd) => {
            let dir = File::from(fd);
            if scope == Scope::System {
                check_dir(&dir, path, layout)?;
            }
            Ok(Some(dir))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(errno) => {
            if scope == Scope::System && is_symlink(dir_path) {
                Err(insecure(path, scope, Insecurity::DirSymlink))
            } else if errno == Errno::NOTDIR {
                Err(insecure(path, scope, Insecurity::DirNotDirectory))
            } else {
                Err(unreadable(path, errno))
            }
        }
    }
}

/// The folder of the system store: owned by root, and group and others cannot write in it.
fn check_dir(dir: &File, path: &Path, layout: &Layout) -> Result<(), TrustStoreError> {
    let meta = dir.metadata().map_err(|e| unreadable(path, errno_of(&e)))?;
    if meta.uid() != layout.system_owner {
        return Err(insecure(path, Scope::System, Insecurity::DirNotOwned));
    }
    if meta.mode() & GROUP_OTHER_WRITE != 0 {
        return Err(insecure(path, Scope::System, Insecurity::DirWritable));
    }
    Ok(())
}

fn errno_of(err: &std::io::Error) -> Errno {
    err.raw_os_error()
        .map_or(Errno::IO, Errno::from_raw_os_error)
}

/// Opens the store inside `dir`, checks the handle, and reads it. `None` when there is no such file.
fn open_file(
    dir: &File,
    path: &Path,
    scope: Scope,
    layout: &Layout,
) -> Result<Option<Vec<u8>>, TrustStoreError> {
    let (_, name) = split(path)?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(errno) => {
            return Err(if is_symlink(path) {
                insecure(path, scope, Insecurity::Symlink)
            } else {
                unreadable(path, errno)
            });
        }
    };
    let mut file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| unreadable(path, errno_of(&e)))?;
    if !meta.is_file() {
        return Err(insecure(path, scope, Insecurity::NotRegular));
    }
    let owned = match scope {
        Scope::System => meta.uid() == layout.system_owner,
        Scope::User => meta.uid() == layout.euid || meta.uid() == 0,
    };
    if !owned {
        return Err(insecure(path, scope, Insecurity::NotOwned));
    }
    if meta.mode() & GROUP_OTHER_WRITE != 0 {
        return Err(insecure(path, scope, Insecurity::Writable));
    }
    // One byte more than the limit, so that the parser can tell "too large" from "exactly the limit".
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_TRUST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unreadable(path, errno_of(&e)))?;
    Ok(Some(bytes))
}

/// Reads a store. `None` when the file or its folder does not exist.
pub(super) fn read(
    path: &Path,
    scope: Scope,
    layout: &Layout,
) -> Result<Option<Vec<u8>>, TrustStoreError> {
    match open_dir(path, scope, layout)? {
        Some(dir) => open_file(&dir, path, scope, layout),
        None => Ok(None),
    }
}

/// Creates the folder of a store: `/etc/rdy` (0755) or the user's `rdy` folder (0700, with parents).
fn create_dir(path: &Path, scope: Scope) -> Result<(), TrustStoreError> {
    let (dir_path, _) = split(path)?;
    let mut builder = std::fs::DirBuilder::new();
    match scope {
        Scope::System => builder.mode(0o755),
        Scope::User => builder.mode(0o700).recursive(true),
    };
    builder
        .create(dir_path)
        .map_err(|e| write_error(path, scope, &e))
}

/// Writes a store atomically: a new file next to it, then a rename.
pub(super) fn write(
    path: &Path,
    scope: Scope,
    layout: &Layout,
    bytes: &[u8],
) -> Result<(), TrustStoreError> {
    let dir = match open_dir(path, scope, layout)? {
        Some(dir) => dir,
        None => {
            create_dir(path, scope)?;
            let dir = open_dir(path, scope, layout)?.ok_or_else(|| TrustStoreError::Write {
                path: path.to_path_buf(),
                scope,
                reason: IoReason::NoSuchFile,
            })?;
            // The mode asked of `mkdir` is cut by the umask. The system folder must be 0755 exactly.
            if scope == Scope::System {
                let mode = Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH;
                rustix::fs::fchmod(&dir, mode).map_err(|e| write_error(path, scope, &e.into()))?;
                check_dir(&dir, path, layout)?;
            }
            dir
        }
    };
    // An old store that would be refused on read is not silently replaced.
    open_file(&dir, path, scope, layout)?;
    let (_, name) = split(path)?;
    let temp = format!(".{}.{}.tmp", name.to_string_lossy(), std::process::id());
    let result = write_temp_and_rename(&dir, &temp, name, scope, bytes);
    if result.is_err() {
        // Best effort. The temporary file may not exist.
        let _ = rustix::fs::unlinkat(&dir, temp.as_str(), AtFlags::empty());
    }
    result.map_err(|e| write_error(path, scope, &e))
}

fn write_temp_and_rename(
    dir: &File,
    temp: &str,
    name: &OsStr,
    scope: Scope,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mode = match scope {
        Scope::System => Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        Scope::User => Mode::RUSR | Mode::WUSR,
    };
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(dir, temp, flags, mode)?;
    let mut file = File::from(fd);
    // The mode given to `open` is cut by the umask. Set it exactly.
    rustix::fs::fchmod(&file, mode)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    rustix::fs::renameat(dir, temp, dir, name)?;
    // Make the rename durable. A failure here leaves a complete store, so it is not an error worth a
    // failed `trust add`.
    let _ = dir.sync_all();
    Ok(())
}
