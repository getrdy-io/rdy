//! Unix file access for the live backend. See the parent module for the order of steps.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags, Stat};

use crate::probe::policy::{RULE_CHANGED, RULE_NOT_DIR, RULE_NOT_REGULAR, ReadGuard, Refused};
use crate::probe::{DirEntry, FileBytes, FileMeta, MAX_DIR_ENTRIES, MAX_READ, ReadRange};

/// Reads part of a regular file.
pub(super) fn read(path: &Path, range: ReadRange, guard: &ReadGuard) -> io::Result<FileBytes> {
    let target = locate(path, guard)?;
    if file_type(&target.stat) != FileType::RegularFile {
        return Err(refused(RULE_NOT_REGULAR));
    }
    let size = u64::try_from(target.stat.st_size).unwrap_or(0);
    let fd = target.reopen(path, OFlags::empty())?;
    read_part(File::from(fd), size, range)
}

/// Lists a directory, sorted by name.
pub(super) fn read_dir(path: &Path, guard: &ReadGuard) -> io::Result<Vec<DirEntry>> {
    let target = locate(path, guard)?;
    if file_type(&target.stat) != FileType::Directory {
        return Err(refused(RULE_NOT_DIR));
    }
    let fd = target.reopen(path, OFlags::DIRECTORY)?;
    let spare = fd.try_clone()?;
    let mut entries = Vec::new();
    for entry in fs::Dir::new(fd)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if entries.len() >= MAX_DIR_ENTRIES {
            return Err(io::Error::other(format!(
                "the directory has more than {MAX_DIR_ENTRIES} entries"
            )));
        }
        let is_dir = match entry.file_type() {
            FileType::Directory => true,
            // Some file systems do not fill in the type. A link is not followed, as with `ls`.
            FileType::Unknown => fs::statat(&spare, name, AtFlags::SYMLINK_NOFOLLOW)
                .is_ok_and(|stat| file_type(&stat) == FileType::Directory),
            _ => false,
        };
        entries.push(DirEntry::new(
            String::from_utf8_lossy(name.to_bytes()).into_owned(),
            is_dir,
        ));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Inspects a path, following links. Nothing is opened, so a FIFO or a device is only described.
pub(super) fn stat(path: &Path, guard: &ReadGuard) -> io::Result<Option<FileMeta>> {
    let target = match locate(path, guard) {
        Ok(target) => target,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let kind = file_type(&target.stat);
    Ok(Some(FileMeta {
        is_file: kind == FileType::RegularFile,
        is_dir: kind == FileType::Directory,
        len: u64::try_from(target.stat.st_size).unwrap_or(0),
    }))
}

fn refused(rule: &'static str) -> io::Error {
    Refused { rule }.into_io()
}

fn file_type(stat: &Stat) -> FileType {
    FileType::from_raw_mode(stat.st_mode)
}

/// A path that was resolved and passed [`ReadGuard::admit_real`], and has not been read yet.
struct Target {
    stat: Stat,
    /// The `O_PATH` descriptor of the target. The check and the open both go through it, so they see
    /// one inode.
    #[cfg(target_os = "linux")]
    anchor: OwnedFd,
    #[cfg(not(target_os = "linux"))]
    real: PathBuf,
}

impl Target {
    /// Opens the target for reading, without blocking, and checks it is the file that was judged.
    /// `requested` is the path the check gave.
    fn reopen(&self, requested: &Path, extra: OFlags) -> io::Result<OwnedFd> {
        #[cfg(target_os = "linux")]
        {
            let _ = requested;
            reopen_through(&self.anchor, &self.stat, extra)
        }
        #[cfg(not(target_os = "linux"))]
        {
            reopen_by_path(requested, &self.real, &self.stat, extra)
        }
    }
}

/// Resolves `path` and applies the real-path rules.
#[cfg(target_os = "linux")]
fn locate(path: &Path, guard: &ReadGuard) -> io::Result<Target> {
    use std::os::unix::ffi::OsStringExt;
    // `O_PATH` follows links, opens no device, runs no driver and blocks on no FIFO.
    let anchor = fs::openat(CWD, path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
    let real = fs::readlink(fd_link(&anchor), Vec::new())?;
    let real = PathBuf::from(std::ffi::OsString::from_vec(real.into_bytes()));
    guard.admit_real(&real).map_err(Refused::into_io)?;
    let stat = fs::fstat(&anchor)?;
    Ok(Target { stat, anchor })
}

#[cfg(not(target_os = "linux"))]
fn locate(path: &Path, guard: &ReadGuard) -> io::Result<Target> {
    let (real, stat) = locate_by_path(path, guard)?;
    Ok(Target { stat, real })
}

#[cfg(target_os = "linux")]
fn fd_link(fd: &OwnedFd) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Opens the file behind `anchor` again, for reading.
#[cfg(target_os = "linux")]
fn reopen_through(anchor: &OwnedFd, stat: &Stat, extra: OFlags) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY | extra;
    let fd = fs::openat(CWD, fd_link(anchor), flags, Mode::empty())?;
    same_file(&fd, stat)?;
    Ok(fd)
}

/// The portable way: `realpath`, then the real-path rules, then a type check on the path. Compiled on
/// every Unix so Linux builds and tests it, and used where there is no `O_PATH`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn locate_by_path(path: &Path, guard: &ReadGuard) -> io::Result<(PathBuf, Stat)> {
    let real = std::fs::canonicalize(path)?;
    guard.admit_real(&real).map_err(Refused::into_io)?;
    // `real` has no links left, so this describes the file the rules were applied to.
    let stat = fs::stat(&real)?;
    Ok((real, stat))
}

/// Opens `real` without following a link, checks it is the file `stat` described, and checks that
/// `requested` still resolves to `real`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn reopen_by_path(
    requested: &Path,
    real: &Path,
    stat: &Stat,
    extra: OFlags,
) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY
        | OFlags::NONBLOCK
        | OFlags::NOFOLLOW
        | OFlags::CLOEXEC
        | OFlags::NOCTTY
        | extra;
    let fd = fs::openat(CWD, real, flags, Mode::empty())?;
    same_file(&fd, stat)?;
    if std::fs::canonicalize(requested)? != real {
        return Err(refused(RULE_CHANGED));
    }
    Ok(fd)
}

/// Refuses when `fd` is not the file `before` described.
fn same_file(fd: &OwnedFd, before: &Stat) -> io::Result<()> {
    let now = fs::fstat(fd)?;
    if now.st_dev == before.st_dev && now.st_ino == before.st_ino {
        Ok(())
    } else {
        Err(refused(RULE_CHANGED))
    }
}

/// Reads the part of `file` that `range` names. `size` is what `fstat` said; a file in `/proc` says 0.
pub(super) fn read_part(mut file: File, size: u64, range: ReadRange) -> io::Result<FileBytes> {
    let (ReadRange::Head(max) | ReadRange::Tail(max)) = range;
    let max = max.min(MAX_READ);
    // One byte more than wanted tells whether the file had more.
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut head_cut = false;
    if matches!(range, ReadRange::Tail(_)) {
        let start = size.saturating_sub(u64::try_from(max).unwrap_or(u64::MAX));
        if start > 0 {
            file.seek(SeekFrom::Start(start))?;
            head_cut = true;
        }
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit).read_to_end(&mut bytes)?;
    let over = bytes.len() > max;
    match range {
        ReadRange::Head(_) => {
            bytes.truncate(max);
            Ok(FileBytes {
                bytes,
                truncated_head: false,
                truncated_tail: over,
            })
        }
        ReadRange::Tail(_) => {
            if over {
                bytes.drain(..bytes.len() - max);
                head_cut = true;
            }
            Ok(FileBytes {
                bytes,
                truncated_head: head_cut,
                truncated_tail: false,
            })
        }
    }
}
