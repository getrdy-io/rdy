//! The replay backend: answers from a recorded fixture and touches nothing.
//!
//! Policy and the log sit above the backend, so a fixture run exercises the same denylist and the same
//! action log as a live run (02 "The probe facade"). A command arrives here after the probe checked it
//! against the command table for the check's OS, so the fixture can never be asked to "run" a shell, a
//! privilege tool or any program the table does not list: the table refused it first. Nothing is
//! started and no program is looked up on the machine. Anything the fixture does not hold is "not
//! found", so a test that forgets a file fails loudly.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use super::sealed::Sealed;
use super::{Backend, DirEntry, FileBytes, FileMeta, Output, ProbeError, ReadGuard, ReadRange};
use crate::check::BoxFuture;
use crate::exec::policy::Cmd;

/// A recorded machine: files, directories and command output.
#[derive(Debug, Clone, Default)]
pub struct Replay {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashMap<PathBuf, Vec<DirEntry>>,
    env: HashMap<String, String>,
    commands: HashMap<(String, Vec<String>), Output>,
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

    /// Sets an environment variable. The check still has to declare the name.
    #[must_use]
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_owned(), value.to_owned());
        self
    }

    /// Adds a directory with these entries.
    #[must_use]
    pub fn dir(mut self, path: impl Into<PathBuf>, entries: Vec<DirEntry>) -> Self {
        self.dirs.insert(path.into(), entries);
        self
    }

    /// Adds the output of `program args...`. The command must still be one the table lists for the
    /// check's OS, or the probe refuses it before the fixture is asked.
    #[must_use]
    pub fn command(mut self, program: &str, args: &[&str], exit: i32, stdout: &str) -> Self {
        let output = Output::new(Some(exit), stdout.as_bytes().to_vec());
        self.commands.insert(
            (
                program.to_owned(),
                args.iter().map(|a| (*a).to_owned()).collect(),
            ),
            output,
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
    fn open_read<'a>(
        &'a self,
        path: &'a Path,
        range: ReadRange,
        _guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<FileBytes>> {
        Box::pin(async move {
            self.files
                .get(path)
                .map(|bytes| range.cut(bytes.clone()))
                .ok_or_else(|| not_found(path))
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a Path,
        _guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
        Box::pin(async move { self.dirs.get(path).cloned().ok_or_else(|| not_found(path)) })
    }

    fn stat<'a>(
        &'a self,
        path: &'a Path,
        _guard: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
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

    fn env(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }

    fn spawn<'a>(&'a self, cmd: Cmd) -> BoxFuture<'a, Result<Output, ProbeError>> {
        Box::pin(async move {
            let args = cmd
                .arguments()
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            self.commands
                .get(&(cmd.program().to_owned(), args))
                .cloned()
                .ok_or(ProbeError::NotFound)
        })
    }
}
