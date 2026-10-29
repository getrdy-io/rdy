//! Where the trust store lives, who may own it, and how it is read and written (M1-121).
//!
//! The file format is `rdy_spec::sig::TrustStore::from_yaml`. This module is the file system side:
//! 01 section 4.3 and threat model INV-04.
//!
//! | Running as | Reads | Writes |
//! | --- | --- | --- |
//! | euid 0 on Unix | only `/etc/rdy/trust.yaml`, whatever `HOME`, `SUDO_USER` or `XDG_CONFIG_HOME` say | that file |
//! | a normal user | `$XDG_CONFIG_HOME/rdy/trust.yaml` (default `~/.config/rdy/trust.yaml`), then the system file | the user file |
//!
//! **A root run never builds, stats, opens or parses a path under a user's home.** [`Layout`] has no
//! user path when the euid is 0, so nothing downstream can reach one. `SUDO_USER` is never read.
//!
//! **Refusals** (exit 64, `trust_store_insecure`, with the reason). All checks run on open handles. The
//! folder is opened first, then the file inside it with `openat`, so a swap between the check and the
//! read changes nothing.
//!
//! - The system file: not a symlink, a regular file, owned by root, not writable by group or others. Its
//!   folder (`/etc/rdy`): not a symlink, owned by root, not writable by group or others. The folders
//!   above it (`/etc` and `/`) are not checked.
//! - The user file: not a symlink, a regular file, owned by the current user or by root, not writable by
//!   group or others. Its folder (`~/.config/rdy`): the same rules as for the file, and not a symlink.
//!   The folders above it are not checked, so a dotfile manager may link `~/.config`. (This is stricter
//!   than 01 section 4.3, which only names the mode of the file: a file or a folder that another user
//!   owns can be changed by that user.)
//! - Reads stop one byte past 256 KiB (INV-02). A FIFO or a device is refused without being read.
//!
//! **Windows and other systems.** rdy cannot yet check who may change a file there (the ACL rules are
//! M1-122). So any trust file that exists is refused as unverifiable, a missing file is an empty store,
//! and saving says it is not supported. This is the conservative reading of "refuse what you cannot
//! verify". `--key` runs are not affected, because they read no store. Extended ACLs on macOS are not in
//! the mode bits and are not checked. Reading them needs FFI, so this is a documented residual risk
//! (threat model 05, Surface 2, and ADR 0021), not a gap to close in this crate.
//!
//! **Test of the root rule.** `tests/root_trust_strace.rs` runs the load under `strace -f` as root with
//! `HOME`, `XDG_CONFIG_HOME` and `SUDO_USER` set to a fixture user, and fails on any call that mentions
//! that user's home.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use rdy_spec::Location;
use rdy_spec::sig::{MAX_TRUST_BYTES, TrustFileError, TrustSource, TrustStore};

use crate::error::{ErrorCode, IoReason};

#[cfg(unix)]
#[path = "trust/unix.rs"]
mod os;

#[cfg(not(unix))]
#[path = "trust/other.rs"]
mod os;

/// The system trust store on Unix.
pub const SYSTEM_STORE: &str = "/etc/rdy/trust.yaml";

/// The file name of every trust store.
const FILE_NAME: &str = "trust.yaml";

/// The folder rdy keeps in the system and user config folders.
const DIR_NAME: &str = "rdy";

/// Which of the two trust stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// The system store, `/etc/rdy/trust.yaml` or its Windows twin.
    System,
    /// The user's store.
    User,
}

impl Scope {
    /// The trust source that pins read from this store carry.
    #[must_use]
    pub fn source(self) -> TrustSource {
        match self {
            Self::System => TrustSource::System,
            Self::User => TrustSource::User,
        }
    }
}

/// The four environment values that place a trust store. Nothing else is read.
///
/// `SUDO_USER` is not among them, on purpose.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vars {
    /// `HOME`.
    pub home: Option<OsString>,
    /// `XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<OsString>,
    /// `APPDATA` (Windows).
    pub appdata: Option<OsString>,
    /// `ProgramData` (Windows).
    pub program_data: Option<OsString>,
}

impl Vars {
    /// Reads the four values from the process environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            home: std::env::var_os("HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            appdata: std::env::var_os("APPDATA"),
            program_data: std::env::var_os("ProgramData"),
        }
    }
}

/// Where the trust stores are for this process, and who must own them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    system_file: Option<PathBuf>,
    user_file: Option<PathBuf>,
    /// The uid that must own the folder of the system store. Always 0 outside tests.
    system_dir_owner: u32,
    /// The uid that must own the system store. Always 0 outside tests.
    system_file_owner: u32,
    /// The effective uid of this process.
    euid: u32,
}

/// A path that is set, not empty and absolute. A relative `HOME` would put the store under the working
/// folder, which is not the user's config.
fn absolute(value: Option<&OsString>) -> Option<PathBuf> {
    let path = PathBuf::from(value?);
    (!path.as_os_str().is_empty() && path.is_absolute()).then_some(path)
}

impl Layout {
    /// The layout of this process: its effective uid and its environment.
    #[must_use]
    pub fn detect() -> Self {
        Self::from_env(&Vars::from_process(), os::effective_uid())
    }

    /// The layout for a given environment and effective uid.
    #[must_use]
    pub fn from_env(vars: &Vars, euid: u32) -> Self {
        if cfg!(windows) {
            Self::windows(vars)
        } else {
            Self::unix(vars, euid)
        }
    }

    fn unix(vars: &Vars, euid: u32) -> Self {
        // A root run has no user path at all. That is the whole of INV-04: nothing can read what is not
        // there.
        let user_file = if euid == 0 {
            None
        } else {
            absolute(vars.xdg_config_home.as_ref())
                .or_else(|| absolute(vars.home.as_ref()).map(|home| home.join(".config")))
                .map(|dir| dir.join(DIR_NAME).join(FILE_NAME))
        };
        Self {
            system_file: Some(PathBuf::from(SYSTEM_STORE)),
            user_file,
            system_dir_owner: 0,
            system_file_owner: 0,
            euid,
        }
    }

    fn windows(vars: &Vars) -> Self {
        let under =
            |base: Option<&OsString>| absolute(base).map(|dir| dir.join(DIR_NAME).join(FILE_NAME));
        Self {
            system_file: under(vars.program_data.as_ref()),
            user_file: under(vars.appdata.as_ref()),
            system_dir_owner: 0,
            system_file_owner: 0,
            euid: u32::MAX,
        }
    }

    /// The path of one store, when this process has one.
    #[must_use]
    pub fn path(&self, scope: Scope) -> Option<&Path> {
        match scope {
            Scope::System => self.system_file.as_deref(),
            Scope::User => self.user_file.as_deref(),
        }
    }

    /// The store that `rdy trust add` writes: the system store for euid 0 on Unix, the user store
    /// otherwise.
    #[must_use]
    pub fn write_scope(&self) -> Scope {
        if self.euid == 0 {
            Scope::System
        } else {
            Scope::User
        }
    }

    /// The same layout with the system store somewhere else, and its folder and file owned by `owner`.
    /// Tests only: a test cannot write `/etc/rdy` or make a file that root owns.
    #[cfg(all(test, unix))]
    pub(crate) fn with_system_file(mut self, path: PathBuf, owner: u32) -> Self {
        self.system_file = Some(path);
        self.system_dir_owner = owner;
        self.system_file_owner = owner;
        self
    }

    /// The same layout with a different owner required for the system file only, so that the folder
    /// can pass while the file fails. Tests only.
    #[cfg(all(test, unix))]
    pub(crate) fn with_system_file_owner(mut self, owner: u32) -> Self {
        self.system_file_owner = owner;
        self
    }
}

/// Reads the stores this process may read: the user store, then the system store.
///
/// A store that does not exist adds nothing. A store that exists and cannot be trusted is an error, and
/// no pin of the other store is returned in that case: a run that cannot read all of its trust stops.
///
/// # Errors
///
/// A [`TrustStoreError`] if a store is unsafe, cannot be read or is not a valid trust file.
pub fn load(layout: &Layout) -> Result<TrustStore, TrustStoreError> {
    let mut store = TrustStore::new();
    store.extend(load_scope(layout, Scope::User)?);
    store.extend(load_scope(layout, Scope::System)?);
    Ok(store)
}

/// Reads one store. A store that does not exist, or that this process has no place for, is empty.
///
/// `rdy trust add` and `rdy trust remove` read the store they write with this, change it, and call
/// [`save`].
///
/// # Errors
///
/// The same as [`load`].
pub fn load_scope(layout: &Layout, scope: Scope) -> Result<TrustStore, TrustStoreError> {
    let Some(path) = layout.path(scope) else {
        return Ok(TrustStore::new());
    };
    let Some(bytes) = os::read(path, scope, layout)? else {
        return Ok(TrustStore::new());
    };
    TrustStore::from_yaml(&bytes, scope.source()).map_err(|source| TrustStoreError::Invalid {
        path: path.to_path_buf(),
        source,
    })
}

/// Writes `store` as the store of [`Layout::write_scope`] and returns the path.
///
/// The store should be one that [`load_scope`] returned for that scope, with the change applied. The
/// write is atomic: a temporary file next to the store, then a rename. The file is mode 0644 for the
/// system store and 0600 for the user store. A folder that is missing is created (0755 for
/// `/etc/rdy`, 0700 for the user's). An existing store that [`load_scope`] would refuse is not replaced.
///
/// # Errors
///
/// A [`TrustStoreError`] if there is no place to write, the folder or the old file is unsafe, the new
/// text is larger than a store may be, or the write fails.
pub fn save(layout: &Layout, store: &TrustStore) -> Result<PathBuf, TrustStoreError> {
    let scope = layout.write_scope();
    let path = layout.path(scope).ok_or(TrustStoreError::NoUserStore)?;
    let text = store.to_yaml();
    if text.len() > MAX_TRUST_BYTES {
        return Err(TrustStoreError::Invalid {
            path: path.to_path_buf(),
            source: TrustFileError::TooLarge {
                size: text.len(),
                limit: MAX_TRUST_BYTES,
            },
        });
    }
    os::write(path, scope, layout, text.as_bytes())?;
    Ok(path.to_path_buf())
}

/// Why a store cannot be trusted. Each is `trust_store_insecure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Insecurity {
    /// The file is a symbolic link.
    Symlink,
    /// The file is a folder, a pipe or a device.
    NotRegular,
    /// The wrong user owns the file. The system store must be owned by root. The user store must be
    /// owned by the current user or by root.
    NotOwned,
    /// Group or others can write the file.
    Writable,
    /// The folder of the store is a symbolic link.
    DirSymlink,
    /// The folder of the store is not a folder.
    DirNotDirectory,
    /// The folder of the store has the wrong owner: not root for the system store, not the current user
    /// or root for the user store.
    DirNotOwned,
    /// Group or others can write the folder of the store.
    DirWritable,
    /// rdy cannot check who may change the file on this system.
    Unverifiable,
}

/// Why a trust store could not be loaded or saved.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrustStoreError {
    /// The store, or its folder, can be changed by someone who should not. Code `trust_store_insecure`.
    #[error("{}", insecure_message(path, *scope, *why))]
    Insecure {
        /// The store file.
        path: PathBuf,
        /// Which store.
        scope: Scope,
        /// What is wrong.
        why: Insecurity,
    },
    /// The store exists but could not be read.
    #[error("cannot read {}: {reason}", path.display())]
    Unreadable {
        /// The store file.
        path: PathBuf,
        /// Why, in plain words.
        reason: IoReason,
    },
    /// The store is not a valid trust file.
    #[error("{source}")]
    Invalid {
        /// The store file.
        path: PathBuf,
        /// What is wrong.
        source: TrustFileError,
    },
    /// The store could not be written.
    #[error("cannot write {}: {reason}", path.display())]
    Write {
        /// The store file.
        path: PathBuf,
        /// Which store.
        scope: Scope,
        /// Why, in plain words.
        reason: IoReason,
    },
    /// There is no place for the user store: `HOME` and `XDG_CONFIG_HOME` are not set to a full path.
    #[error("rdy cannot tell where your trust store is")]
    NoUserStore,
    /// This system cannot write a trust store yet.
    #[error("rdy cannot write a trust store on this system yet")]
    Unsupported,
}

fn insecure_message(path: &Path, scope: Scope, why: Insecurity) -> String {
    let file = path.display();
    let dir = path.parent().unwrap_or(path).display();
    match why {
        Insecurity::Symlink => format!("{file} is a symbolic link"),
        Insecurity::NotRegular => format!("{file} is not a regular file"),
        Insecurity::NotOwned => match scope {
            Scope::System => format!("{file} is not owned by root"),
            Scope::User => format!("{file} is owned by another user"),
        },
        Insecurity::Writable => format!("{file} is writable by other users"),
        Insecurity::DirSymlink => format!("{dir} is a symbolic link"),
        Insecurity::DirNotDirectory => format!("{dir} is not a folder"),
        Insecurity::DirNotOwned => match scope {
            Scope::System => format!("{dir} is not owned by root"),
            Scope::User => format!("{dir} is owned by another user"),
        },
        Insecurity::DirWritable => format!("{dir} is writable by other users"),
        Insecurity::Unverifiable => {
            format!("rdy cannot check who can change {file} on this system yet")
        }
    }
}

impl TrustStoreError {
    /// The stable error code: `trust_store_insecure` for a store that cannot be trusted, and `usage`
    /// for the rest (all of them need the input to change, exit 64).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Insecure { .. } => ErrorCode::TrustStoreInsecure,
            _ => ErrorCode::Usage,
        }
    }

    /// The store file the error is about, when there is one.
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        match self {
            Self::Insecure { path, .. }
            | Self::Unreadable { path, .. }
            | Self::Invalid { path, .. }
            | Self::Write { path, .. } => Some(path),
            Self::NoUserStore | Self::Unsupported => None,
        }
    }

    /// The place in the file, when the error has one.
    #[must_use]
    pub fn location(&self) -> Option<Location> {
        match self {
            Self::Invalid { source, .. } => source.location(),
            _ => None,
        }
    }

    /// The fix line. Never empty.
    #[must_use]
    pub fn fix(&self) -> String {
        use crate::error::shell_word;
        match self {
            Self::Insecure {
                path, scope, why, ..
            } => {
                let file = shell_word(&path.to_string_lossy());
                let dir = shell_word(&path.parent().unwrap_or(path).to_string_lossy());
                match why {
                    Insecurity::Symlink => match scope {
                        Scope::System => {
                            format!("replace the link with a regular file that root owns: {file}")
                        }
                        Scope::User => {
                            format!("replace the link with a regular file that you own: {file}")
                        }
                    },
                    Insecurity::NotRegular => {
                        format!("remove {file}, then pin your keys again with rdy trust add")
                    }
                    Insecurity::NotOwned => match scope {
                        Scope::System => format!("chown root {file}"),
                        Scope::User => format!(
                            "check who put {file} there, then replace it with a file that you own"
                        ),
                    },
                    Insecurity::Writable => match scope {
                        Scope::System => format!("chmod 644 {file}"),
                        Scope::User => format!("chmod 600 {file}"),
                    },
                    Insecurity::DirSymlink => match scope {
                        Scope::System => format!("replace {dir} with a real folder that root owns"),
                        Scope::User => format!("replace {dir} with a real folder that you own"),
                    },
                    Insecurity::DirNotDirectory => {
                        format!("remove {dir}, then pin your keys again with rdy trust add")
                    }
                    Insecurity::DirNotOwned => match scope {
                        Scope::System => format!("chown root {dir}"),
                        Scope::User => format!(
                            "check who put {dir} there, then replace it with a folder that you own"
                        ),
                    },
                    Insecurity::DirWritable => match scope {
                        Scope::System => format!("chmod 755 {dir}"),
                        Scope::User => format!("chmod 700 {dir}"),
                    },
                    Insecurity::Unverifiable => {
                        "move the file away for now. rdy checks who can change a trust store on Linux and macOS, and Windows support comes in a later release.".to_owned()
                    }
                }
            }
            Self::Unreadable { reason, .. } => match reason {
                IoReason::NoSuchFile => "check that the file is still there",
                IoReason::PermissionDenied => {
                    "check who owns the file and that you are allowed to read it"
                }
                IoReason::NotAFile => {
                    "remove the folder and pin your keys again with rdy trust add"
                }
                IoReason::DiskFull | IoReason::Other => {
                    "check that the disk the file is on is still connected, then run again"
                }
            }
            .to_owned(),
            Self::Invalid { source, .. } => source.hint().to_owned(),
            Self::Write { scope, reason, .. } => match (reason, scope) {
                (IoReason::PermissionDenied, Scope::System) => {
                    "run the command as root, because the system store is in /etc/rdy".to_owned()
                }
                (IoReason::PermissionDenied, Scope::User) => {
                    "check that you may write to your config folder".to_owned()
                }
                (IoReason::DiskFull, _) => "make room on the disk, then run again".to_owned(),
                _ => "check that the disk is still connected, then run again".to_owned(),
            },
            Self::NoUserStore => {
                "set HOME to your home folder, or XDG_CONFIG_HOME to your config folder".to_owned()
            }
            Self::Unsupported => {
                "pin keys on a Linux or macOS host. Windows support comes in a later release."
                    .to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests;
