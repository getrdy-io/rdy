//! The replay backend: answers from a recorded fixture and touches nothing.
//!
//! Policy and the log sit above the backend, so a fixture run exercises the same denylist and the same
//! action log as a live run (02 "The probe facade"). Anything the fixture does not hold is "not found",
//! so a test that forgets a file fails loudly.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use super::sealed::Sealed;
use super::{Backend, Cmd, DirEntry, Executed, FileBytes, FileMeta, Output, ProbeError};
use crate::check::BoxFuture;

/// A recorded machine: files, directories and command output.
#[derive(Debug, Clone, Default)]
pub struct Replay {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashMap<PathBuf, Vec<DirEntry>>,
    commands: HashMap<(String, Vec<String>), Executed>,
}

impl Replay {
    /// An empty machine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file.
    #[must_use]
    pub fn file(mut self, path: impl Into<PathBuf>, bytes: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.into(), bytes.into());
        self
    }

    /// Adds a directory with these entries.
    #[must_use]
    pub fn dir(mut self, path: impl Into<PathBuf>, entries: Vec<DirEntry>) -> Self {
        self.dirs.insert(path.into(), entries);
        self
    }

    /// Adds the output of `program args...`, which ran from `/usr/bin/<program>`.
    #[must_use]
    pub fn command(mut self, program: &str, args: &[&str], exit: i32, stdout: &str) -> Self {
        let output = Output::new(Some(exit), stdout.as_bytes().to_vec());
        self.commands.insert(
            (
                program.to_owned(),
                args.iter().map(|a| (*a).to_owned()).collect(),
            ),
            Executed::new(format!("/usr/bin/{program}"), output),
        );
        self
    }
}

impl Sealed for Replay {}

fn not_found(what: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("not in the replay fixture: {}", what.display()),
    )
}

impl Backend for Replay {
    fn open_read<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<FileBytes>> {
        Box::pin(async move {
            self.files
                .get(path)
                .map(|bytes| FileBytes::new(bytes.clone()))
                .ok_or_else(|| not_found(path))
        })
    }

    fn read_dir<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
        Box::pin(async move { self.dirs.get(path).cloned().ok_or_else(|| not_found(path)) })
    }

    fn stat<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
        Box::pin(async move {
            let meta = if let Some(bytes) = self.files.get(path) {
                Some(FileMeta::file(
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                ))
            } else {
                self.dirs.contains_key(path).then(FileMeta::dir)
            };
            Ok(meta)
        })
    }

    fn spawn<'a>(&'a self, cmd: &'a Cmd) -> BoxFuture<'a, Result<Executed, ProbeError>> {
        Box::pin(async move {
            self.commands
                .get(&(cmd.program.to_owned(), cmd.args.clone()))
                .cloned()
                .ok_or(ProbeError::NotFound)
        })
    }
}
