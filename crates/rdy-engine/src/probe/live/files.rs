//! Unix file access for the live backend. See the parent module for the order of steps.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags, Stat};

use crate::probe::policy::{
    MACHINE_ID_FILES, RULE_CHANGED, RULE_MACHINE_ID_FILE, RULE_NOT_DIR, RULE_NOT_FILE_OR_DIR,
    RULE_NOT_REGULAR, RULE_SYSTEM_SECRET, ReadGuard, Refused,
};
use crate::probe::{DirEntry, FileBytes, FileMeta, MAX_DIR_ENTRIES, MAX_READ, ReadRange};

/// The password and sudo files and the machine id files that exist on this machine, known by device and
/// inode. A hard link or a bind mount of one has another name and the same inode, so the name rules
/// cannot see it. Residual (05, I5): a copy at another inode, such as a backup or a snapshot, is not
/// known.
#[derive(Debug, Clone, Default)]
pub(super) struct Secrets {
    passwords: Vec<(u64, u64)>,
    machine_ids: Vec<(u64, u64)>,
}

/// The files whose inodes are remembered.
const SECRET_FILES: &[&str] = &[
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/sudoers",
    "/etc/master.passwd",
    "/etc/security/opasswd",
];

/// A number from `stat` as `u64`. The field types differ by OS (`dev_t` is `i32` on macOS), so this
/// is generic and clippy sees no useless conversion on any one of them.
fn wide<T: TryInto<u64>>(value: T) -> u64 {
    value.try_into().unwrap_or(0)
}

fn identity(stat: &Stat) -> (u64, u64) {
    (wide(stat.st_dev), wide(stat.st_ino))
}

/// The identities of the files at these paths. A path that is not there is skipped.
fn identities<P: AsRef<Path>>(paths: impl IntoIterator<Item = P>) -> Vec<(u64, u64)> {
    paths
        .into_iter()
        .filter_map(|path| fs::stat(path.as_ref()).ok())
        .map(|stat| identity(&stat))
        .collect()
}

impl Secrets {
    /// Looks the files up once, when the backend is made. A file that is not there is skipped.
    pub(super) fn collect() -> Self {
        Self {
            passwords: identities(SECRET_FILES),
            machine_ids: identities(MACHINE_ID_FILES),
        }
    }

    /// The inodes of these paths. For tests, which cannot put a file at `/etc/shadow`.
    #[cfg(test)]
    pub(super) fn from_paths(passwords: &[&Path], machine_ids: &[&Path]) -> Self {
        Self {
            passwords: identities(passwords),
            machine_ids: identities(machine_ids),
        }
    }

    /// The rule that refuses `stat`, if its inode is a known file. The machine id files are skipped for
    /// the `MachineId` guard, which must read them under their own names and which admits only those
    /// real paths. A password file is never skipped.
    pub(super) fn refuses(&self, stat: &Stat, guard: &ReadGuard) -> Option<&'static str> {
        let id = identity(stat);
        if self.passwords.contains(&id) {
            Some(RULE_SYSTEM_SECRET)
        } else if !guard.reads_machine_id() && self.machine_ids.contains(&id) {
            Some(RULE_MACHINE_ID_FILE)
        } else {
            None
        }
    }
}

/// What a call wants to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Want {
    File,
    Dir,
    /// A file or a directory: what `statvfs` measures. Linux asks through the `O_PATH` descriptor and
    /// does not open the target, so only the portable path names this.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Either,
}

impl Want {
    fn accepts(self, stat: &Stat) -> bool {
        let kind = file_type(stat);
        match self {
            Self::File => kind == FileType::RegularFile,
            Self::Dir => kind == FileType::Directory,
            Self::Either => matches!(kind, FileType::RegularFile | FileType::Directory),
        }
    }

    fn rule(self) -> &'static str {
        match self {
            Self::File => RULE_NOT_REGULAR,
            Self::Dir => RULE_NOT_DIR,
            Self::Either => RULE_NOT_FILE_OR_DIR,
        }
    }
}

/// Reads part of a regular file.
pub(super) fn read(
    path: &Path,
    range: ReadRange,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<FileBytes> {
    let target = locate(path, guard, secrets)?;
    let (fd, stat) = target.open(path, guard, Want::File)?;
    let size = u64::try_from(stat.st_size).unwrap_or(0);
    read_part(File::from(fd), size, range)
}

/// Lists a directory, sorted by name.
pub(super) fn read_dir(
    path: &Path,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<Vec<DirEntry>> {
    let target = locate(path, guard, secrets)?;
    let (fd, _) = target.open(path, guard, Want::Dir)?;
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
pub(super) fn stat(
    path: &Path,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<Option<FileMeta>> {
    let target = match locate(path, guard, secrets) {
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
    target.confirm(path)?;
    let kind = file_type(&target.stat);
    Ok(Some(FileMeta {
        is_file: kind == FileType::RegularFile,
        is_dir: kind == FileType::Directory,
        len: u64::try_from(target.stat.st_size).unwrap_or(0),
    }))
}

/// The size and mount flags of the file system that holds `path`. The path is resolved and judged
/// like a read, so a link to a denied place is refused. The answer comes from a descriptor of the
/// inode that passed the rules, never from the path a second time. Linux uses the judged `O_PATH`
/// descriptor. The portable path opens the real path with no link followed (macOS: `O_NOFOLLOW_ANY`
/// and `F_GETPATH`, judged again) and asks that descriptor, so a parent swapped after the judgment
/// cannot give the numbers of another file system. The guard here is the check's `statfs` prefixes,
/// not its `reads`. A path the user cannot open for reading is measured through its parent when both
/// are on one file system, and otherwise reported as `PermissionDenied` (see [`statvfs_by_path`]).
pub(super) fn statvfs(
    path: &Path,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<fs::StatVfs> {
    let target = locate(path, guard, secrets)?;
    #[cfg(target_os = "linux")]
    {
        target.confirm(path)?;
        Ok(fs::fstatvfs(&target.anchor)?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        statvfs_by_path(path, &target.real, &target.stat, guard, secrets)
    }
}

/// The portable `statvfs`: open the real path and ask that descriptor. The open needs read permission,
/// which Linux's `O_PATH` does not, so a directory the user can search but not read gets one more
/// step. The numbers belong to the file system, so the parent will do when it is on the same file
/// system (same device). A mount point is not: its parent is another file system, and its numbers
/// would be wrong for the path. That case, and a parent that cannot be opened or that the rules
/// refuse, return the original `PermissionDenied`, which the probe reports as
/// `ProbeError::PermissionDenied` and the check reports as not verified. It is never a guess.
/// Compiled on every Unix so Linux tests it.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn statvfs_by_path(
    requested: &Path,
    real: &Path,
    before: &Stat,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<fs::StatVfs> {
    let error = match open_by_path(requested, real, before, guard, Want::Either) {
        Ok((fd, _)) => return Ok(fs::fstatvfs(&fd)?),
        Err(error) => error,
    };
    // A refusal by the rules (`Refused`) is final. Only a plain permission error gets the parent.
    if error.kind() != io::ErrorKind::PermissionDenied || Refused::from_io(&error).is_some() {
        return Err(error);
    }
    statvfs_through_parent(error, real, before, guard, secrets)
}

/// The parent step of [`statvfs_by_path`]: numbers from the parent directory when it is on the same
/// file system as `real`, and `denied` (the error of the failed open) when it is not or cannot be used.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn statvfs_through_parent(
    denied: io::Error,
    real: &Path,
    before: &Stat,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<fs::StatVfs> {
    let Some(parent) = real.parent() else {
        return Err(denied);
    };
    // The parent goes through the same steps as any path: real path, rules, no secret, no link.
    let Ok((parent_real, parent_stat)) = locate_by_path(parent, guard, secrets) else {
        return Err(denied);
    };
    let Ok((fd, opened)) = open_by_path(parent, &parent_real, &parent_stat, guard, Want::Dir)
    else {
        return Err(denied);
    };
    if opened.st_dev != before.st_dev {
        return Err(denied);
    }
    Ok(fs::fstatvfs(&fd)?)
}

fn refused(rule: &'static str) -> io::Error {
    Refused { rule }.into_io()
}

fn file_type(stat: &Stat) -> FileType {
    FileType::from_raw_mode(stat.st_mode)
}

/// A path that was resolved and passed [`ReadGuard::admit_real`], and has not been read yet.
pub(super) struct Target {
    pub(super) stat: Stat,
    /// The real path. Linux does not need it after the check: it opens through `anchor`.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(super) real: PathBuf,
    /// The `O_PATH` descriptor of the target. The check and the open both go through it, so they see
    /// one inode.
    #[cfg(target_os = "linux")]
    anchor: OwnedFd,
}

impl Target {
    /// Opens the target for reading, without blocking, and checks it is the file that was judged and
    /// that it is of the kind wanted. `requested` is the path the check gave.
    fn open(&self, requested: &Path, guard: &ReadGuard, want: Want) -> io::Result<(OwnedFd, Stat)> {
        #[cfg(target_os = "linux")]
        {
            let _ = (requested, guard);
            // A FIFO, socket or device is refused here, before anything opens it.
            if !want.accepts(&self.stat) {
                return Err(refused(want.rule()));
            }
            let extra = if want == Want::Dir {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            };
            let fd = reopen_through(&self.anchor, &self.stat, extra)?;
            Ok((fd, self.stat))
        }
        #[cfg(not(target_os = "linux"))]
        {
            open_by_path(requested, &self.real, &self.stat, guard, want)
        }
    }

    /// For `stat`, which opens nothing: on the portable path, looks at the real path a second time.
    fn confirm(&self, requested: &Path) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _ = requested;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            if std::fs::canonicalize(requested)? == self.real {
                Ok(())
            } else {
                Err(refused(RULE_CHANGED))
            }
        }
    }
}

/// The error for a failed `/proc` lookup. Without `/proc` the real path of a descriptor cannot be
/// read, and rdy reads nothing rather than read unchecked.
#[cfg(target_os = "linux")]
fn proc_error(error: rustix::io::Errno) -> io::Error {
    if error == rustix::io::Errno::NOENT {
        io::Error::other(
            "/proc is not mounted, and rdy needs it to check a file before it reads it. Mount /proc, or run rdy where /proc is visible",
        )
    } else {
        error.into()
    }
}

/// Resolves `path` and applies the real-path rules.
#[cfg(target_os = "linux")]
fn locate(path: &Path, guard: &ReadGuard, secrets: &Secrets) -> io::Result<Target> {
    use std::os::unix::ffi::OsStringExt;
    // `O_PATH` follows links, opens no device, runs no driver and blocks on no FIFO.
    let anchor = fs::openat(CWD, path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
    let real = fs::readlink(fd_link(&anchor), Vec::new()).map_err(proc_error)?;
    let real = PathBuf::from(std::ffi::OsString::from_vec(real.into_bytes()));
    let stat = fs::fstat(&anchor)?;
    // A file with no names left was unlinked after the open. Its path reads "... (deleted)", which
    // would hide the end of its name from the rules.
    if stat.st_nlink == 0 {
        return Err(refused(RULE_CHANGED));
    }
    guard.admit_real(&real).map_err(Refused::into_io)?;
    if let Some(rule) = secrets.refuses(&stat, guard) {
        return Err(refused(rule));
    }
    Ok(Target { stat, real, anchor })
}

#[cfg(not(target_os = "linux"))]
fn locate(path: &Path, guard: &ReadGuard, secrets: &Secrets) -> io::Result<Target> {
    let (real, stat) = locate_by_path(path, guard, secrets)?;
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

/// The portable way: `realpath`, then the real-path rules, then a look at the path. Compiled on every
/// Unix so Linux builds and tests it, and used where there is no `O_PATH`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn locate_by_path(
    path: &Path,
    guard: &ReadGuard,
    secrets: &Secrets,
) -> io::Result<(PathBuf, Stat)> {
    let real = std::fs::canonicalize(path)?;
    guard.admit_real(&real).map_err(Refused::into_io)?;
    // `real` has no links left, so this describes the file the rules were applied to.
    let stat = fs::stat(&real)?;
    if stat.st_nlink == 0 {
        return Err(refused(RULE_CHANGED));
    }
    if let Some(rule) = secrets.refuses(&stat, guard) {
        return Err(refused(rule));
    }
    Ok((real, stat))
}

/// Opens the real path with no link followed anywhere along it, and takes the type from the
/// descriptor, not from a path. On macOS the path of the descriptor (`F_GETPATH`) is judged again.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn open_by_path(
    requested: &Path,
    real: &Path,
    before: &Stat,
    guard: &ReadGuard,
    want: Want,
) -> io::Result<(OwnedFd, Stat)> {
    // Nothing that is not the wanted kind is opened.
    if !want.accepts(before) {
        return Err(refused(want.rule()));
    }
    #[cfg(target_vendor = "apple")]
    let follow = OFlags::NOFOLLOW_ANY;
    #[cfg(not(target_vendor = "apple"))]
    let follow = OFlags::NOFOLLOW;
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY | follow;
    let fd = fs::openat(CWD, real, flags, Mode::empty())?;
    same_file(&fd, before)?;
    let now = fs::fstat(&fd)?;
    if !want.accepts(&now) {
        return Err(refused(want.rule()));
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::os::unix::ffi::OsStringExt;
        let again = fs::getpath(&fd)?;
        let again = PathBuf::from(std::ffi::OsString::from_vec(again.into_bytes()));
        guard.admit_real(&again).map_err(Refused::into_io)?;
        if again != real {
            return Err(refused(RULE_CHANGED));
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    let _ = guard;
    if std::fs::canonicalize(requested)? != real {
        return Err(refused(RULE_CHANGED));
    }
    Ok((fd, now))
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

/// The size of one read while a tail is streamed.
const CHUNK: usize = 64 * 1024;

/// The most a tail read streams before it gives up on reaching the end: 16 MiB. A file that grows as
/// fast as it is read would otherwise never finish.
const TAIL_SCAN_LIMIT: u64 = 16 << 20;

/// Reads the part of `file` that `range` names. `size` is what `fstat` said; a file in `/proc` says 0,
/// so a tail never trusts it for more than where to start.
pub(super) fn read_part(mut file: File, size: u64, range: ReadRange) -> io::Result<FileBytes> {
    let (ReadRange::Head(max) | ReadRange::Tail(max)) = range;
    let max = max.min(MAX_READ);
    match range {
        ReadRange::Head(_) => {
            // One byte more than wanted tells whether the file had more.
            let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
            let mut bytes = Vec::new();
            (&mut file).take(limit).read_to_end(&mut bytes)?;
            let over = bytes.len() > max;
            bytes.truncate(max);
            Ok(FileBytes {
                bytes,
                truncated_head: false,
                truncated_tail: over,
            })
        }
        ReadRange::Tail(_) => read_tail(file, size, max),
    }
}

/// Streams to the end of the file, keeping the last `max` bytes. Memory stays at `max` plus two
/// chunks, whatever the file.
fn read_tail(mut file: File, size: u64, max: usize) -> io::Result<FileBytes> {
    let start = size.saturating_sub(u64::try_from(max).unwrap_or(u64::MAX));
    let mut head_cut = false;
    if start > 0 {
        file.seek(SeekFrom::Start(start))?;
        head_cut = true;
    }
    let mut kept: Vec<u8> = Vec::new();
    let mut chunk = vec![0_u8; CHUNK];
    let mut scanned: u64 = 0;
    let mut tail_cut = false;
    loop {
        let n = match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if scanned >= TAIL_SCAN_LIMIT {
            // There is more after the budget, so the bytes held are not the tail. A file that ends
            // exactly at the budget never gets here: the read above returns 0 first.
            tail_cut = true;
            break;
        }
        kept.extend(chunk.iter().take(n));
        scanned = scanned.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if kept.len() > max.saturating_add(CHUNK) {
            kept.drain(..kept.len() - max);
            head_cut = true;
        }
    }
    if kept.len() > max {
        kept.drain(..kept.len() - max);
        head_cut = true;
    }
    Ok(FileBytes {
        bytes: kept,
        truncated_head: head_cut,
        truncated_tail: tail_cut,
    })
}
