//! Opening and creating key files (M1-125, threat model I1).
//!
//! Rules:
//!
//! - A key file that is read is opened once, without following a symlink (`O_NOFOLLOW`) and without
//!   blocking on a named pipe. Every check runs on the open handle, so nothing can be swapped in
//!   between the check and the read. It must be a regular file. On Unix it must be owned by the
//!   effective user and closed to group and others.
//! - A key file that is made is created with `create_new` (`O_EXCL`), so it never replaces a file or
//!   follows a link, and on Unix with mode 0600 from the first byte. No later `chmod` is needed.
//! - Windows has no mode bits. The file is opened without following a reparse point and checked for
//!   type only. A new file gets the access list of its folder. That is a named residual: the
//!   success message on Windows says so.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use zeroize::Zeroizing;

/// Why a key file could not be used. The messages are fixed text. The caller names the file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FileError {
    /// The file could not be opened or read.
    #[error("it cannot be read: {reason}")]
    Unreadable {
        /// What happened, in plain words.
        reason: crate::error::IoReason,
    },
    /// The path is a symlink.
    #[error("it is a symlink")]
    Symlink,
    /// The path is not a regular file.
    #[error("it is not a regular file")]
    NotRegular,
    /// Another user owns the file (Unix).
    #[error("it is owned by another user")]
    NotOwned,
    /// Group or others can read or write the file (Unix).
    #[error("it can be read or written by other users")]
    TooOpen,
    /// The file is larger than the cap.
    #[error("it is larger than a key file can be")]
    TooLarge,
}

/// Reads a private file of at most `cap` bytes, checking the open handle.
///
/// The bytes are wiped when the result is dropped.
///
/// # Errors
///
/// A [`FileError`] for each rule in the module docs.
pub fn read_private(path: &Path, cap: usize) -> Result<Zeroizing<Vec<u8>>, FileError> {
    let unreadable = |err: &io::Error| FileError::Unreadable {
        reason: crate::error::IoReason::from_io(err),
    };
    let mut file = open_private(path).map_err(|err| {
        // Only on the error path: was it refused because it is a symlink?
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            FileError::Symlink
        } else {
            unreadable(&err)
        }
    })?;
    let opened = file.metadata().map_err(|err| unreadable(&err))?;
    if opened.file_type().is_symlink() {
        return Err(FileError::Symlink);
    }
    if !opened.is_file() {
        return Err(FileError::NotRegular);
    }
    check_owner_and_mode(&opened)?;
    // The buffer is sized up front so it never reallocates and leaves an unwiped copy behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(cap + 1));
    let mut limited = (&mut file).take(cap as u64 + 1);
    limited
        .read_to_end(&mut buf)
        .map_err(|err| unreadable(&err))?;
    if buf.len() > cap {
        return Err(FileError::TooLarge);
    }
    Ok(buf)
}

/// Reads a public file of at most `cap` bytes, such as the `.pub` file given to `rdy trust add --key`.
///
/// Nothing in a public key is secret, so there is no owner or mode rule, and a symlink is followed:
/// the person who runs the command names the file and then compares the fingerprint it holds with the
/// one the vendor published, which is what makes the key trusted. The file must be a regular file.
///
/// Opening some devices has side effects (a watchdog arms, a tape rewinds), and a person may run this
/// under `sudo`. So the path is checked with `stat` first, which follows a symlink, and a target that is
/// not a regular file is refused before it is opened. On Unix the open handle is then compared with what
/// `stat` saw (device and inode), so a path swapped in between is refused too. That second check
/// refuses the read, but the open has already happened, so it does not keep a device that was swapped in
/// during the gap from seeing its open. The open does not block, so a named pipe that appears in that
/// window cannot hang the command.
///
/// # Errors
///
/// [`FileError::Unreadable`], [`FileError::NotRegular`] or [`FileError::TooLarge`].
pub fn read_public(path: &Path, cap: usize) -> Result<Vec<u8>, FileError> {
    let unreadable = |err: &io::Error| FileError::Unreadable {
        reason: crate::error::IoReason::from_io(err),
    };
    let seen = std::fs::metadata(path).map_err(|err| unreadable(&err))?;
    if !seen.is_file() {
        return Err(FileError::NotRegular);
    }
    let mut file = open_public(path).map_err(|err| unreadable(&err))?;
    let opened = file.metadata().map_err(|err| unreadable(&err))?;
    if !opened.is_file() || !same_file(&seen, &opened) {
        return Err(FileError::NotRegular);
    }
    let mut buf = Vec::new();
    (&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|err| unreadable(&err))?;
    if buf.len() > cap {
        return Err(FileError::TooLarge);
    }
    Ok(buf)
}

/// Unix: the handle is the file that `stat` looked at.
#[cfg(unix)]
fn same_file(seen: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    seen.dev() == opened.dev() && seen.ino() == opened.ino()
}

/// Other platforms have no inode to compare.
#[cfg(not(unix))]
fn same_file(_seen: &std::fs::Metadata, _opened: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn open_public(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::fs::OFlags;

    OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NONBLOCK | OFlags::NOCTTY).bits().cast_signed())
        .open(path)
}

#[cfg(not(unix))]
fn open_public(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn open_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::fs::OFlags;

    OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits().cast_signed())
        .open(path)
}

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a symlink or junction itself, do not follow it.
#[cfg(windows)]
fn open_private(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_private(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Unix: the effective user owns the file, and group and others have no access at all.
#[cfg(unix)]
fn check_owner_and_mode(opened: &std::fs::Metadata) -> Result<(), FileError> {
    use std::os::unix::fs::MetadataExt;

    if opened.uid() != rustix::process::geteuid().as_raw() {
        return Err(FileError::NotOwned);
    }
    if opened.mode() & 0o077 != 0 {
        return Err(FileError::TooOpen);
    }
    Ok(())
}

/// Other platforms have no mode bits or uid. Windows access lists are not checked.
#[cfg(not(unix))]
fn check_owner_and_mode(_opened: &std::fs::Metadata) -> Result<(), FileError> {
    Ok(())
}

/// Creates a new file that only the owner can read (mode 0600 on Unix), failing if the path exists.
///
/// # Errors
///
/// The OS error. [`io::ErrorKind::AlreadyExists`] means the path is taken, including by a symlink.
pub fn create_new_private(path: &Path) -> io::Result<File> {
    create_new(path, 0o600)
}

/// Creates a new file that anyone can read (mode 0644 on Unix), failing if the path exists.
///
/// # Errors
///
/// The OS error. [`io::ErrorKind::AlreadyExists`] means the path is taken, including by a symlink.
pub fn create_new_public(path: &Path) -> io::Result<File> {
    create_new(path, 0o644)
}

#[cfg(unix)]
fn create_new(path: &Path, mode: u32) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::fs::OFlags;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
}

#[cfg(not(unix))]
fn create_new(path: &Path, _mode: u32) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Writes all of `bytes` to `file` and flushes it to disk.
///
/// # Errors
///
/// The OS error.
pub fn write_and_sync(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

#[cfg(test)]
mod tests;
