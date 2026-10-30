//! Unix file access for the live backend. See the parent module for the order of steps.

use std::ffi::OsStr;
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

/// Whether `/proc/self` on this machine names rdy's own process id: the one fact that "rdy's own
/// process" in the read rules rests on. Another pid namespace's procfs (reached by `nsenter` or a
/// mount of the host's) numbers processes its own way, so its `/proc/<our pid>` is not us. A `/proc`
/// that is missing or unreadable says no.
pub(super) fn proc_self_is_own() -> bool {
    fs::readlink("/proc/self", Vec::new())
        .is_ok_and(|link| names_pid(link.as_bytes(), std::process::id()))
}

/// Whether the text of a `/proc/self` link is `pid`.
pub(super) fn names_pid(link: &[u8], pid: u32) -> bool {
    link == pid.to_string().as_bytes()
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

/// Reads where the link at `path` points, without following it (M1-169).
///
/// The parent directory is resolved, so a link in the path of the parent is followed, and the link
/// itself is not. The rules judge the link's real path (the real parent and the link's own name)
/// before anything is read, and again judge what was read ([`ReadGuard::admit_link`]: an fd link may
/// lead to a socket only). Where the link points is not judged. Linux holds the parent through an
/// `O_PATH` descriptor, so the real path that was judged and the directory that is read are one inode.
/// It also checks that the real path of the parent leads to that inode here and, for a procfs, that
/// it is `/proc` ([`confirm_real_parent`]), so a directory from another mount namespace is refused.
/// A Unix that is neither Linux nor Apple answers `Unsupported`.
pub(super) fn read_link(path: &Path, guard: &ReadGuard) -> io::Result<Vec<u8>> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path has no link name",
        ));
    };
    #[cfg(target_os = "linux")]
    {
        read_link_through_anchor(parent, name, guard)
    }
    #[cfg(target_vendor = "apple")]
    {
        read_link_by_path(parent, name, guard)
    }
    // Another Unix has neither `O_PATH` nor `O_NOFOLLOW_ANY`: `O_NOFOLLOW` covers the last name only,
    // so a parent swapped for a link after the judgment would go unseen. Not a release target.
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = (parent, name, guard);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this call is not available on this OS in this version of rdy",
        ))
    }
}

/// The Linux way: open the parent with `O_PATH` (links followed, nothing run), read its real path from
/// `/proc/self/fd/<n>`, judge the link's real path, then `readlinkat` on the same descriptor.
#[cfg(target_os = "linux")]
fn read_link_through_anchor(parent: &Path, name: &OsStr, guard: &ReadGuard) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt;
    let anchor = fs::openat(
        CWD,
        parent,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let real_parent = fs::readlink(fd_link(&anchor), Vec::new()).map_err(proc_error)?;
    let real_parent = PathBuf::from(std::ffi::OsString::from_vec(real_parent.into_bytes()));
    // A directory with no names left reads "... (deleted)", which would hide the end of its name.
    if fs::fstat(&anchor)?.st_nlink == 0 {
        return Err(refused(RULE_CHANGED));
    }
    // `d_path` names the directory in the mount namespace of its mount. A directory that came from
    // another one (through `/proc/<pid>/root`, or a bind mount of a procfs) reads back under a name
    // the rules do not know, so the name is only used after it is shown to lead to this inode on a
    // procfs that is not under another name (SEC-153-1).
    let named = fs::statat(CWD, &real_parent, AtFlags::SYMLINK_NOFOLLOW);
    let anchor_stat = fs::fstat(&anchor)?;
    let on_proc = fs::fstatfs(&anchor)?.f_type == fs::PROC_SUPER_MAGIC;
    confirm_real_parent(&anchor_stat, named, on_proc, &real_parent)?;
    let real = real_parent.join(name);
    guard.admit_real(&real).map_err(Refused::into_io)?;
    let target = fs::readlinkat(&anchor, name, Vec::new()).map_err(not_a_link)?;
    let target = target.into_bytes();
    guard.admit_link(&real, &target).map_err(Refused::into_io)?;
    Ok(target)
}

/// Whether the name `d_path` gave for the parent of a link can be trusted. `named` is a `lstat` of
/// that name. It must be the inode of the descriptor, so the name is not a path in another mount
/// namespace that happens to exist here. A procfs must be seen as `/proc`, because the `/proc/<pid>`
/// rules match on that name: a procfs mounted under another name would escape them.
///
/// # Errors
///
/// `RULE_CHANGED` when the name leads nowhere or to another inode, `RULE_PROC` for a procfs that is
/// not at `/proc`.
#[cfg(target_os = "linux")]
pub(super) fn confirm_real_parent(
    anchor: &Stat,
    named: rustix::io::Result<Stat>,
    on_proc: bool,
    real_parent: &Path,
) -> io::Result<()> {
    let Ok(named) = named else {
        return Err(refused(RULE_CHANGED));
    };
    if identity(&named) != identity(anchor) {
        return Err(refused(RULE_CHANGED));
    }
    if on_proc && !real_parent.starts_with("/proc") {
        return Err(refused(crate::probe::policy::RULE_PROC));
    }
    Ok(())
}

/// The portable way, for an OS with no `O_PATH`: `realpath` of the parent, the rules on the link's
/// real path, then the parent opened by that real path with no link followed (macOS: anywhere along
/// it, and the path of the descriptor is judged again). Compiled on Linux and Apple, so Linux tests it.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn read_link_by_path(
    parent: &Path,
    name: &OsStr,
    guard: &ReadGuard,
) -> io::Result<Vec<u8>> {
    let real_parent = std::fs::canonicalize(parent)?;
    let real = real_parent.join(name);
    guard.admit_real(&real).map_err(Refused::into_io)?;
    #[cfg(target_vendor = "apple")]
    let follow = OFlags::NOFOLLOW_ANY;
    #[cfg(not(target_vendor = "apple"))]
    let follow = OFlags::NOFOLLOW;
    let flags = OFlags::RDONLY
        | OFlags::DIRECTORY
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | OFlags::NOCTTY
        | follow;
    let dir = fs::openat(CWD, &real_parent, flags, Mode::empty())?;
    #[cfg(target_vendor = "apple")]
    {
        use std::os::unix::ffi::OsStringExt;
        let again = fs::getpath(&dir)?;
        let again = PathBuf::from(std::ffi::OsString::from_vec(again.into_bytes()));
        guard
            .admit_real(&again.join(name))
            .map_err(Refused::into_io)?;
        if again != real_parent {
            return Err(refused(RULE_CHANGED));
        }
    }
    let target = fs::readlinkat(&dir, name, Vec::new()).map_err(not_a_link)?;
    let target = target.into_bytes();
    guard.admit_link(&real, &target).map_err(Refused::into_io)?;
    Ok(target)
}

/// `readlinkat` fails with `EINVAL` on a path that is not a link. That is a plain, readable error.
fn not_a_link(error: rustix::io::Errno) -> io::Error {
    if error == rustix::io::Errno::INVAL {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path is not a symbolic link",
        )
    } else {
        error.into()
    }
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
) -> io::Result<(fs::StatVfs, fs::Dev)> {
    let target = locate(path, guard, secrets)?;
    // The device of the judged inode. When the portable path measures the parent instead, it has
    // checked that the parent is on this same device.
    let dev = target.stat.st_dev;
    #[cfg(target_os = "linux")]
    {
        target.confirm(path)?;
        Ok((fs::fstatvfs(&target.anchor)?, dev))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let raw = statvfs_by_path(path, &target.real, &target.stat, guard, secrets)?;
        Ok((raw, dev))
    }
}

/// The portable `statvfs`: open the real path and ask that descriptor. The open needs read permission,
/// which Linux's `O_PATH` does not, so a directory the user can search but not read gets one more
/// step. The numbers belong to the file system, so the parent will do when it is on the same file
/// system (same device, and on macOS the same mount name). A mount point is not: its parent is
/// another file system, and its numbers would be wrong for the path. That case, and a parent that
/// cannot be opened or that the rules refuse, return the original `PermissionDenied`, which the probe
/// reports as `ProbeError::PermissionDenied` and the check reports as not verified. It is never a
/// guess.
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
    let (parent_real, parent_stat) = match locate_by_path(parent, guard, secrets) {
        Ok(found) => found,
        Err(error) => return Err(plain_denied(denied, &error)),
    };
    let (fd, opened) = match open_by_path(parent, &parent_real, &parent_stat, guard, Want::Dir) {
        Ok(found) => found,
        Err(error) => return Err(plain_denied(denied, &error)),
    };
    if opened.st_dev != before.st_dev {
        return Err(denied);
    }
    // A bind or `nullfs` mount keeps the device number, so `st_dev` alone does not say it is the same
    // mount, and the mount flags (`f_flag`) could be another mount's. Apple compares the mount name.
    #[cfg(target_vendor = "apple")]
    if !same_mount_name(real, &fd) {
        return Err(denied);
    }
    Ok(fs::fstatvfs(&fd)?)
}

/// What the caller gets when the parent could not be used: the original `PermissionDenied`. When a
/// rule refused the parent, the rule is logged at debug level, with no path, so a check author can
/// find out why the fallback did not apply.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn plain_denied(denied: io::Error, parent: &io::Error) -> io::Error {
    if let Some(refusal) = Refused::from_io(parent) {
        tracing::debug!(
            rule = refusal.rule,
            "the parent was refused, so it gives no numbers"
        );
    }
    denied
}

/// Whether the file system at `target` (asked by path, which needs no read permission) and the one
/// `parent` is open on have the same mount point name (`f_mntonname`).
#[cfg(target_vendor = "apple")]
fn same_mount_name(target: &Path, parent: &OwnedFd) -> bool {
    let (Ok(target), Ok(parent)) = (fs::statfs(target), fs::fstatfs(parent)) else {
        return false;
    };
    let name = |info: &fs::StatFs| -> Vec<_> {
        info.f_mntonname
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect()
    };
    name(&target) == name(&parent)
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
