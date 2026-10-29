//! The output directory (ADR 0016, threat model SEC-19, INV-09 and T1).
//!
//! rdy writes its report files into one new folder, `rdy-report-<product>-<time>/`, and nowhere else.
//! [`OutputDir::create_new`] makes the folder right after the spec is verified and before the first
//! check, so a bad location fails in the first second and not after a long run. The handle stays open
//! for the whole run, and every later write goes through it.
//!
//! The rules, in the order they act:
//!
//! - **Safe names.** The product is re-checked against `^[a-z0-9][a-z0-9-]{0,62}$`, the time stamp
//!   against `YYYYMMDDTHHMMSSZ`, and every file name against a short allow list of characters. A name
//!   with a separator or a dot at the front never reaches the file system.
//! - **A new folder, never an old one.** The folder is made with `mkdir`. If the name is taken, by a
//!   folder, a file or a symlink, rdy tries `-2` to `-9` and then gives up. It never opens, writes
//!   into or removes something that was there before.
//! - **No symlinks.** The folder is opened without following a final symlink, and every path inside
//!   it is resolved by `cap-std`, which cannot leave the folder.
//! - **Owner and mode (Unix).** The opened handle must be a folder owned by the effective user.
//!   rdy then sets it to 0700 with `fchmod`, which also clears a setgid bit that the parent passed
//!   on, and reads the mode back. Nothing depends on the umask. The Windows checks are M1-037; until
//!   then Windows only gets the no-follow open and the checks of the next point.
//! - **Files.** Each file is made with `create_new` at 0600 (and `fchmod`, so the umask does not
//!   matter) as `.<name>.tmp`, written, flushed to disk, and then given its final name without
//!   replacing anything. A run that is killed leaves at most `.tmp` files, never a half-written file
//!   under a final name.
//! - **Typed input.** Report text comes in as [`Redacted`], and the spec copy as [`VerifiedSpecBytes`],
//!   the buffers [`rdy_spec::load`] verified. The spec copy uses the fixed names `spec.yaml` and
//!   `spec.yaml.minisig`, never the operator's file name.
//!
//! The methods block on file system calls. Call them from `spawn_blocking`, or from a plain thread.
//!
//! The watchdog's single-writer state (ADR 0016 decision 6) belongs to the run deadline ticket and is
//! not here.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use rdy_spec::VerifiedSpecBytes;
use rdy_spec::spec::ProductSlug;

use crate::redact::Redacted;

#[cfg(test)]
mod tests;

/// How many names are tried: the plain name, then `-2` to `-9`.
const MAX_NAME_TRIES: u32 = 9;

/// The longest file name `write_atomic` accepts.
const MAX_FILE_NAME: usize = 128;

/// The `action` of the [`ReportError::Io`] for a parent folder that cannot be opened.
pub const OPEN_PARENT: &str = "open the output folder";

/// The fixed name of the spec copy.
pub const SPEC_COPY_NAME: &str = "spec.yaml";

/// The fixed name of the signature copy.
pub const SIGNATURE_COPY_NAME: &str = "spec.yaml.minisig";

/// Why the output folder or a file in it could not be made.
///
/// Every message ends with a fix. The paths are the ones the operator gave, so they are safe to show.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReportError {
    /// The product is not a valid name, so it cannot be part of a folder name.
    #[error(
        "the product name is not a valid report name. \
         Fix: use a spec whose metadata.product matches ^[a-z0-9][a-z0-9-]{{0,62}}$"
    )]
    BadProduct,
    /// The time stamp is not `YYYYMMDDTHHMMSSZ`.
    #[error("the report time stamp is not in the form YYYYMMDDTHHMMSSZ. Fix: this is a bug in rdy")]
    BadTimestamp,
    /// A report file name is not allowed.
    #[error("the report file name is not allowed. Fix: this is a bug in rdy")]
    BadFileName,
    /// The nine names `rdy-report-<product>-<time>` to `-9` are all taken.
    #[error(
        "the names of the report folder are all taken in {parent}. \
         Fix: wait a second and run again, or use --out-dir <another folder>"
    )]
    NameTaken {
        /// The parent folder.
        parent: PathBuf,
    },
    /// A file system call failed.
    #[error(
        "cannot {action} {path}: {source}. \
         Fix: use --out-dir <a folder you can write to>, or --no-report to skip the files"
    )]
    Io {
        /// What rdy was doing, such as `create the report folder`.
        action: &'static str,
        /// The folder or file.
        path: PathBuf,
        /// The OS error.
        #[source]
        source: io::Error,
    },
    /// The new folder is not owned by the user running rdy.
    #[error(
        "the report folder {path} is owned by user {owner}, not by user {euid}. \
         Fix: use --out-dir <a folder on a local disk>; on NFS with root_squash, root cannot own new folders"
    )]
    NotOwner {
        /// The folder.
        path: PathBuf,
        /// The owner the OS reports.
        owner: u32,
        /// The effective user of rdy.
        euid: u32,
    },
    /// The new folder is not a folder, or its mode did not change to 0700.
    #[error(
        "the report folder {path} is not private (mode {mode:o}). \
         Fix: use --out-dir <a folder on a disk that keeps Unix permissions>"
    )]
    NotPrivate {
        /// The folder.
        path: PathBuf,
        /// The mode the OS reports, in the low twelve bits.
        mode: u32,
    },
    /// A file with this final name is already in the folder. rdy never replaces it.
    #[error("the report file {path} already exists. Fix: this is a bug in rdy; run again")]
    FileExists {
        /// The file.
        path: PathBuf,
    },
}

impl ReportError {
    /// The OS error behind this one, when there is one. The CLI maps it to plain words.
    #[must_use]
    pub fn io_error(&self) -> Option<&io::Error> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }

    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// A report folder that rdy made and holds open (see the module docs).
#[derive(Debug)]
pub struct OutputDir {
    dir: Dir,
    /// The folder name, also the stem of the report file names.
    name: String,
    /// `parent/name`, for messages only. Nothing is ever opened by this path.
    path: PathBuf,
}

impl OutputDir {
    /// Makes `<parent>/rdy-report-<product>-<ts>/` and opens it. Run it right after verification.
    ///
    /// `parent` must exist. It is opened once, following symlinks, because the operator chose it;
    /// nothing below it is reached through a symlink. `ts` is `YYYYMMDDTHHMMSSZ` in UTC, see
    /// [`report_timestamp`].
    ///
    /// # Errors
    ///
    /// [`ReportError::BadProduct`] and [`ReportError::BadTimestamp`] for names that do not fit,
    /// [`ReportError::NameTaken`] when `-9` is taken too, [`ReportError::NotOwner`] and
    /// [`ReportError::NotPrivate`] when the new folder is not ours and private, and
    /// [`ReportError::Io`] for anything the OS refuses.
    pub fn create_new(parent: &Path, product: &str, ts: &str) -> Result<Self, ReportError> {
        let product = ProductSlug::new(product).map_err(|_| ReportError::BadProduct)?;
        if !is_timestamp(ts) {
            return Err(ReportError::BadTimestamp);
        }
        let parent_dir = Dir::open_ambient_dir(parent, ambient_authority())
            .map_err(|e| ReportError::io(OPEN_PARENT, parent, e))?;
        let base = report_folder_name(product.as_ref(), ts);
        for attempt in 1..=MAX_NAME_TRIES {
            let name = if attempt == 1 {
                base.clone()
            } else {
                format!("{base}-{attempt}")
            };
            let path = parent.join(&name);
            match make_dir(&parent_dir, &name) {
                Ok(()) => {}
                // A folder, a file or a symlink is there already. A symlink is not followed: mkdir
                // reports the name as taken without looking at the target.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(ReportError::io("create the report folder", &path, e)),
            }
            #[cfg(test)]
            tests::after_make_dir(parent, &name);
            let opened = open_new_dir(&parent_dir, &name)
                .map_err(|e| ReportError::io("open the report folder", &path, e))
                .and_then(|dir| harden(&dir, &path).map(|()| dir));
            return match opened {
                Ok(dir) => Ok(Self { dir, name, path }),
                Err(err) => {
                    // Best effort: take away the empty folder this call made. It fails harmlessly
                    // if the name was swapped for something else in the meantime.
                    let _ = parent_dir.remove_dir(&name);
                    Err(err)
                }
            };
        }
        Err(ReportError::NameTaken {
            parent: parent.to_path_buf(),
        })
    }

    /// The folder as the operator would type it: the parent as given, then the folder name.
    ///
    /// For messages only. rdy never opens a file by this path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The folder name, `rdy-report-<product>-<time>` with `-2` to `-9` when the name was taken.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The file name of a report file with this extension, for example `json` gives
    /// `rdy-report-acme-20270309T143005Z.json`. The stem is the folder name, so a folder that moved
    /// to `-2` keeps its files apart from the first one's.
    #[must_use]
    pub fn report_file_name(&self, extension: &str) -> String {
        format!("{}.{extension}", self.name)
    }

    /// Writes redacted text as `name`, atomically and without replacing a file.
    ///
    /// Returns the path of the new file for the "Report written to" block.
    ///
    /// # Errors
    ///
    /// [`ReportError::BadFileName`] for a name with anything but letters, digits, `.`, `_` and `-`,
    /// or a dot at the front. [`ReportError::FileExists`] when `name` is already in the folder.
    /// [`ReportError::Io`] for anything the OS refuses.
    pub fn write_atomic<T: AsRef<[u8]>>(
        &self,
        name: &str,
        content: &Redacted<T>,
    ) -> Result<PathBuf, ReportError> {
        let bytes: &[u8] = (**content).as_ref();
        self.write_with(name, |file| file.write_all(bytes))
    }

    /// Writes the verified spec as `spec.yaml` and, for a signed spec, its signature as
    /// `spec.yaml.minisig`. The bytes are the ones [`rdy_spec::load`] verified.
    ///
    /// Returns the paths written, spec first.
    ///
    /// # Errors
    ///
    /// The same as [`OutputDir::write_atomic`].
    pub fn write_spec(&self, spec: &VerifiedSpecBytes) -> Result<Vec<PathBuf>, ReportError> {
        let mut written = vec![self.write_with(SPEC_COPY_NAME, |f| f.write_all(spec.yaml()))?];
        if let Some(signature) = spec.signature() {
            written.push(self.write_with(SIGNATURE_COPY_NAME, |f| f.write_all(signature))?);
        }
        Ok(written)
    }

    /// Creates `.<name>.tmp`, lets `fill` write it, flushes it to disk and gives it its final name.
    fn write_with(
        &self,
        name: &str,
        fill: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> Result<PathBuf, ReportError> {
        if !is_file_name(name) {
            return Err(ReportError::BadFileName);
        }
        let tmp = format!(".{name}.tmp");
        let final_path = self.path.join(name);
        let tmp_path = self.path.join(&tmp);
        let mut file = self
            .dir
            .open_with(&tmp, &new_file_options())
            .map_err(|e| ReportError::io("create", &tmp_path, e))?;
        let filled = set_private(&file)
            .and_then(|()| fill(&mut file))
            .and_then(|()| file.sync_all())
            .map_err(|e| ReportError::io("write", &tmp_path, e));
        drop(file);
        let result = filled.and_then(|()| self.publish(&tmp, name, &final_path));
        if result.is_err() {
            // The temp name is ours alone (create_new), so removing it cannot touch anything else.
            let _ = self.dir.remove_file(&tmp);
        } else {
            sync_dir(&self.dir);
        }
        result.map(|()| final_path)
    }

    /// Gives a finished temp file its final name. An existing file is never replaced.
    ///
    /// A hard link first: it fails if the name exists, and it is atomic. Only when the file system
    /// cannot make hard links does it fall back to a rename that refuses to replace, see
    /// [`no_hard_links`]. Any other error is an error.
    fn publish(&self, tmp: &str, name: &str, final_path: &Path) -> Result<(), ReportError> {
        match self.dir.hard_link(tmp, &self.dir, name) {
            Ok(()) => {
                // The data is complete under the final name. A leftover `.tmp` is harmless.
                let _ = self.dir.remove_file(tmp);
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ReportError::FileExists {
                    path: final_path.to_path_buf(),
                });
            }
            Err(e) if no_hard_links(&e) => {}
            Err(e) => return Err(ReportError::io("rename to", final_path, e)),
        }
        self.rename_no_replace(tmp, name, final_path)
    }

    /// The fallback for a file system without hard links. It never replaces a file.
    fn rename_no_replace(
        &self,
        tmp: &str,
        name: &str,
        final_path: &Path,
    ) -> Result<(), ReportError> {
        // The kernel can refuse to replace in one step (Linux 3.15 and later, macOS).
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use rustix::fs::{RenameFlags, renameat_with};
            use rustix::io::Errno;
            match renameat_with(&self.dir, tmp, &self.dir, name, RenameFlags::NOREPLACE) {
                Ok(()) => return Ok(()),
                Err(Errno::EXIST) => {
                    return Err(ReportError::FileExists {
                        path: final_path.to_path_buf(),
                    });
                }
                // This kernel or file system has no such flag. Check and rename below.
                Err(Errno::INVAL | Errno::NOSYS | Errno::OPNOTSUPP) => {}
                Err(e) => return Err(ReportError::io("rename to", final_path, e.into())),
            }
        }
        // The folder is private and new, so nobody else is adding names while this runs.
        if self.dir.symlink_metadata(name).is_ok() {
            return Err(ReportError::FileExists {
                path: final_path.to_path_buf(),
            });
        }
        // On Windows, security software briefly holds a new file, so the rename is retried.
        let tries = if cfg!(windows) { 5 } else { 1 };
        let mut last = None;
        for attempt in 0..tries {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            match self.dir.rename(tmp, &self.dir, name) {
                Ok(()) => return Ok(()),
                Err(e) => last = Some(e),
            }
        }
        let err = last.unwrap_or_else(|| io::Error::other("rename was not tried"));
        Err(ReportError::io("rename to", final_path, err))
    }
}

/// True when a failed `link` means "this file system has no hard links", and a rename may take over.
///
/// Unix: only `EPERM` (FAT, some FUSE and network file systems), `EOPNOTSUPP`, `EMLINK` and `ENOSYS`.
/// Every other error, such as `EACCES`, `EIO` or `ENOSPC`, is a real failure and is reported.
#[cfg(unix)]
fn no_hard_links(err: &io::Error) -> bool {
    use rustix::io::Errno;
    [Errno::PERM, Errno::OPNOTSUPP, Errno::MLINK, Errno::NOSYS]
        .iter()
        .any(|e| err.raw_os_error() == Some(e.raw_os_error()))
}

/// Windows: `CreateHardLink` fails on FAT, exFAT and some network shares with codes that std does
/// not map to a kind, so any error other than "exists" falls back to the checked rename.
#[cfg(not(unix))]
fn no_hard_links(_err: &io::Error) -> bool {
    true
}

/// The default parent folder when `--out-dir` is not given.
///
/// Unix: `.`. Windows will use `%USERPROFILE%\rdy-reports` (ADR 0016 decision 1); that default and
/// its reparse-point checks are M1-037, and until then it is `.` there too, with `harden` failing open.
#[must_use]
pub fn default_parent() -> PathBuf {
    PathBuf::from(".")
}

/// The folder name before any `-2` to `-9`: `rdy-report-<product>-<ts>`. For messages and for
/// [`OutputDir::create_new`], which checks both parts first.
#[must_use]
pub fn report_folder_name(product: &str, ts: &str) -> String {
    format!("rdy-report-{product}-{ts}")
}

/// The time stamp of a report folder, `YYYYMMDDTHHMMSSZ` in UTC, for [`OutputDir::create_new`].
///
/// A clock before 1970 reads as the epoch, and a clock after year 9999 as its last second.
#[must_use]
pub fn report_timestamp(now: SystemTime) -> String {
    const LAST_SECOND: u64 = 253_402_300_799;
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(LAST_SECOND));
    let (day, rest) = (secs / 86_400, secs % 86_400);
    let (year, month, date) = civil_from_days(i64::try_from(day).unwrap_or(0));
    let (hour, minute, second) = (rest / 3600, rest % 3600 / 60, rest % 60);
    format!("{year:04}{month:02}{date:02}T{hour:02}{minute:02}{second:02}Z")
}

/// The proleptic Gregorian date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `^[0-9]{8}T[0-9]{6}Z$`
fn is_timestamp(ts: &str) -> bool {
    let b = ts.as_bytes();
    b.len() == 16
        && b.iter().enumerate().all(|(i, c)| match i {
            8 => *c == b'T',
            15 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. The first character rules out `.`, `..` and the `.tmp` names.
fn is_file_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() <= MAX_FILE_NAME
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// `mkdir` with mode 0700 where the OS has modes. The umask can only take bits away.
fn make_dir(parent: &Dir, name: &str) -> io::Result<()> {
    #[cfg(unix)]
    let builder = {
        let mut builder = cap_std::fs::DirBuilder::new();
        cap_std::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = cap_std::fs::DirBuilder::new();
    parent.create_dir_with(name, &builder)
}

/// Opens the folder just made, and refuses to follow a symlink if the name was swapped for one.
///
/// Unix: `openat` with `O_NOFOLLOW | O_DIRECTORY` on the held parent. `name` is one path component
/// that this module built, so it cannot leave the parent. `cap-std` opens directories with `O_PATH`
/// on Linux, and `fchmod` and `fsync` do not work on such a descriptor, so this open is done by hand.
#[cfg(unix)]
fn open_new_dir(parent: &Dir, name: &str) -> io::Result<Dir> {
    use rustix::fs::{Mode, OFlags, openat};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = openat(parent, name, flags, Mode::empty())?;
    Ok(Dir::from_std_file(std::fs::File::from(fd)))
}

/// Opens the folder just made, and refuses to follow a symlink if the name was swapped for one.
#[cfg(not(unix))]
fn open_new_dir(parent: &Dir, name: &str) -> io::Result<Dir> {
    let start = parent.try_clone()?.into_std_file();
    let opened = cap_primitives::fs::open_dir_nofollow(&start, Path::new(name))?;
    Ok(Dir::from_std_file(opened))
}

/// Options for a new file: `create_new` (fails if the name exists, never follows a symlink) and 0600.
fn new_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    cap_std::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

/// Sets a new file to 0600 whatever the umask said.
#[cfg(unix)]
fn set_private(file: &File) -> io::Result<()> {
    rustix::fs::fchmod(file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)?;
    Ok(())
}

/// Windows files inherit the folder's ACL (ADR 0016 decision 7).
#[cfg(not(unix))]
fn set_private(_file: &File) -> io::Result<()> {
    Ok(())
}

/// Flushes the folder entry to disk. Not every file system can; that is not an error (ADR 0016).
#[cfg(unix)]
fn sync_dir(dir: &Dir) {
    let _ = rustix::fs::fsync(dir);
}

/// A no-op on Windows (ADR 0016 decision 4).
#[cfg(not(unix))]
fn sync_dir(_dir: &Dir) {}

/// The checks on the opened handle: a folder, ours, mode 0700.
#[cfg(unix)]
fn harden(dir: &Dir, path: &Path) -> Result<(), ReportError> {
    use cap_std::fs::MetadataExt as _;

    let stat = |what: &'static str| {
        dir.dir_metadata()
            .map_err(|e| ReportError::io(what, path, e))
    };
    let meta = stat("read the owner of")?;
    let euid = rustix::process::geteuid().as_raw();
    if !meta.is_dir() {
        return Err(ReportError::NotPrivate {
            path: path.to_path_buf(),
            mode: meta.mode() & 0o7777,
        });
    }
    if meta.uid() != euid {
        return Err(ReportError::NotOwner {
            path: path.to_path_buf(),
            owner: meta.uid(),
            euid,
        });
    }
    // 0700 clears a setgid bit passed on by the parent. Read it back: a file system that ignores
    // chmod must not pass as private.
    rustix::fs::fchmod(dir, rustix::fs::Mode::RWXU)
        .map_err(|e| ReportError::io("set the mode of", path, e.into()))?;
    let mode = stat("read the mode of")?.mode() & 0o7777;
    if mode != 0o700 {
        return Err(ReportError::NotPrivate {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Windows: not a reparse point, final path equals the expected one, ACL checks. M1-037 builds it.
///
/// This stub FAILS OPEN: it checks nothing and always returns `Ok`. Until M1-037 lands, a Windows
/// run relies on `open_dir_nofollow` alone, and the default parent is `.` and not a private folder.
/// M1-057 (wiring `rdy run`) depends on M1-037 for this reason.
#[cfg(not(unix))]
fn harden(_dir: &Dir, _path: &Path) -> Result<(), ReportError> {
    Ok(())
}
