//! The fixture loader: reads the directory format of 08 section 2 and Appendix A into a [`Replay`].
//!
//! ```text
//! envs/all-pass/
//!   fixture.toml        the manifest (schema 1)
//!   root/               plain files; root/etc/os-release stands for /etc/os-release
//!   root.manifest.json  symlinks, unreadable files, modes, empty directories
//!   commands/*.json     one recorded command each, found by the argv inside the file
//!   native/*.json       one recorded native call each
//!   api/*.json          one recorded API response each, found by the request inside the file
//!   net.json            scripted names and connections
//!   env.json            environment variables
//! ```
//!
//! The loader is strict. An unknown file, an unknown key, a duplicate argv, a symlink in the tree, a
//! file over [`MAX_FILE_BYTES`] or a name with a character git or Windows cannot store is an error that
//! names the file. A fixture that loads on one runner loads on all five.
//!
//! **`base` and `remove`.** `base = "all-pass"` names `envs/all-pass`, one level only. The files of the
//! child replace the files of the base by path (`commands/chronyc.json` replaces
//! `commands/chronyc.json`), and `remove` deletes paths from the base first. The merged set is then
//! indexed, so two files that record the same argv are still a duplicate.
//!
//! **What is not read.** `golden/`, `expect.json`, the spec file, `caps.json` and `README.md` belong to
//! the harness and the docs. The needs a fixture offers are the `[caps]` table of the manifest.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde_json::{Map, Value};

use super::net::{DnsAnswer, TcpScript};
use super::{ApiRecord, CommandAnswer, NativeAnswer, NativeFailure, Replay, b64, paths};
use crate::check::{Need, Os};
use crate::probe::{
    DirEntry, MachineId, NativeCall, NativeValue, Output, Resource, RlimitInfo, StatvfsInfo,
    UnameInfo,
};

/// The largest fixture file the loader reads. The fixture lint (M1-050) is stricter.
pub const MAX_FILE_BYTES: u64 = 4 << 20;

/// The most bytes one fixture may hold, base included.
pub const MAX_TOTAL_BYTES: u64 = 64 << 20;

/// The most files one fixture may hold, base included.
pub const MAX_FILES: usize = 20_000;

/// Why a fixture did not load, or does not answer a check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FixtureError {
    /// A file or directory could not be read.
    #[error(
        "fixture {fixture}: cannot read {path}: {reason}. Fix: check that the fixture directory exists and is complete"
    )]
    Read {
        /// The fixture, as named to the loader.
        fixture: String,
        /// The file, below the fixture directory.
        path: String,
        /// What the OS said.
        reason: String,
    },
    /// A file is not what the format allows.
    #[error(
        "fixture {fixture}: {path}: {reason}. Fix: correct the file; tests/fixtures/README.md describes the format"
    )]
    Invalid {
        /// The fixture, as named to the loader.
        fixture: String,
        /// The file, below the fixture directory.
        path: String,
        /// What is wrong.
        reason: String,
    },
    /// Two files record the same thing.
    #[error(
        "fixture {fixture}: {first} and {second} both record {key}. Fix: keep one of the two files"
    )]
    Duplicate {
        /// The fixture, as named to the loader.
        fixture: String,
        /// What both record, such as an argv.
        key: String,
        /// The first file.
        first: String,
        /// The second file.
        second: String,
    },
    /// The fixture does not list the check in `answers`.
    #[error(
        "fixture {fixture} does not answer {check}. Fix: use a fixture that lists it in `answers`, or record what the check reads and add it"
    )]
    DoesNotAnswer {
        /// The fixture, as named to the loader.
        fixture: String,
        /// The check id.
        check: String,
    },
}

/// Where a fixture came from (08 section 2). A laptop is not an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// Written by us from a vendor doc or an RFC.
    Hand,
    /// Built at test time or by a script.
    Generated,
    /// Recorded on a CI runner, then scrubbed.
    CiRunner,
    /// Recorded on a rented machine made for the purpose, then scrubbed.
    Throwaway,
}

impl Origin {
    /// The word in `fixture.toml`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hand => "hand",
            Self::Generated => "generated",
            Self::CiRunner => "ci-runner",
            Self::Throwaway => "throwaway",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Hand, Self::Generated, Self::CiRunner, Self::Throwaway]
            .into_iter()
            .find(|origin| origin.as_str() == text)
    }
}

/// Which needs the fixture offers (`[caps]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Caps {
    /// The run is root.
    pub root: bool,
    /// Sockets are allowed.
    pub network: bool,
    /// A Kubernetes context is reachable.
    pub kube: bool,
}

/// What the in-process harness pins for the run (`[run]`). The loader keeps the text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunPins {
    /// The clock, such as `2026-11-02T09:00:00Z`.
    pub clock: Option<String>,
    /// The run id.
    pub run_id: Option<String>,
    /// The number of checks that run at once.
    pub jobs: Option<u32>,
    /// The run deadline.
    pub deadline_ms: Option<u64>,
}

/// What an environment must produce (`[expect]`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Expect {
    /// The verdict word.
    pub verdict: String,
    /// The exit code.
    pub exit_code: i32,
}

/// The parsed `fixture.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Manifest {
    /// The fixture's name.
    pub name: String,
    /// One line about the machine.
    pub summary: String,
    /// Where the data came from.
    pub origin: Origin,
    /// What the machine reports as its OS.
    pub os: Os,
    /// `x86_64` or `aarch64`.
    pub arch: String,
    /// The environment this one builds on, one level only.
    pub base: Option<String>,
    /// Paths deleted from the base.
    pub remove: Vec<String>,
    /// Files allowed to contain `\r`. The lint reads it.
    pub crlf: Vec<String>,
    /// The check ids the fixture can answer.
    pub answers: Vec<String>,
    /// The spec file name, for an environment.
    pub spec: Option<String>,
    /// Which needs are available.
    pub caps: Caps,
    /// What the harness pins.
    pub run: RunPins,
    /// What an environment must produce.
    pub expect: Option<Expect>,
    /// Matrix evidence, free text per key.
    pub matrix: BTreeMap<String, String>,
}

/// A loaded fixture: its manifest and the machine it describes.
#[derive(Debug, Clone)]
pub struct Fixture {
    name: String,
    manifest: Manifest,
    replay: Replay,
}

impl Fixture {
    /// Loads the fixture `name` (for example `checks/host.memory/pass` or `envs/all-pass`) from the
    /// fixtures directory `root`. A `base` is looked up as `envs/<base>` under the same `root`.
    ///
    /// # Errors
    ///
    /// [`FixtureError`] naming the first file that is wrong.
    pub fn load(root: &Path, name: &str) -> Result<Self, FixtureError> {
        check_name(name, name)?;
        let mut budget = Budget::default();
        let child = read_layer(root, name, &mut budget)?;
        let files = match child.manifest.base.clone() {
            None => {
                if !child.manifest.remove.is_empty() {
                    return Err(invalid(
                        name,
                        "fixture.toml",
                        "`remove` needs a `base` to remove from",
                    ));
                }
                child.files
            }
            Some(base) => {
                let base_name = format!("envs/{base}");
                let base_layer = read_layer(root, &base_name, &mut budget)?;
                if base_layer.manifest.base.is_some() {
                    return Err(invalid(
                        &base_name,
                        "fixture.toml",
                        "a base cannot have a base: reuse is one level",
                    ));
                }
                if base_layer.manifest.os != child.manifest.os {
                    return Err(invalid(
                        name,
                        "fixture.toml",
                        format!("`os` differs from the base {base_name}"),
                    ));
                }
                merge(name, base_layer.files, &child.manifest.remove, child.files)?
            }
        };
        let replay = build(name, &child.manifest, &files)?;
        Ok(Self {
            name: name.to_owned(),
            manifest: child.manifest,
            replay,
        })
    }

    /// The manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The machine.
    #[must_use]
    pub fn replay(&self) -> &Replay {
        &self.replay
    }

    /// The machine, by value.
    #[must_use]
    pub fn into_replay(self) -> Replay {
        self.replay
    }

    /// The OS the machine reports.
    #[must_use]
    pub fn os(&self) -> Os {
        self.manifest.os
    }

    /// The needs the fixture offers, for `TestRun::context`.
    #[must_use]
    pub fn available_needs(&self) -> Vec<Need> {
        let caps = self.manifest.caps;
        [
            (caps.root, Need::Root),
            (caps.network, Need::Network),
            (caps.kube, Need::KubeContext),
        ]
        .into_iter()
        .filter_map(|(on, need)| on.then_some(need))
        .collect()
    }

    /// Says whether the fixture can answer `check`. Without this a missing record shows up as a
    /// `NotRecorded` in the middle of a run.
    ///
    /// # Errors
    ///
    /// [`FixtureError::DoesNotAnswer`] when `check` is not in `answers`.
    pub fn ensure_answers(&self, check: &str) -> Result<(), FixtureError> {
        if self.manifest.answers.iter().any(|id| id == check) {
            Ok(())
        } else {
            Err(FixtureError::DoesNotAnswer {
                fixture: self.name.clone(),
                check: check.to_owned(),
            })
        }
    }
}

fn invalid(fixture: &str, path: &str, reason: impl Into<String>) -> FixtureError {
    FixtureError::Invalid {
        fixture: fixture.to_owned(),
        path: path.to_owned(),
        reason: reason.into(),
    }
}

/// Where an error is reported: a fixture and a file below it.
struct Ctx<'a> {
    fixture: &'a str,
    path: &'a str,
}

impl Ctx<'_> {
    fn err(&self, reason: impl Into<String>) -> FixtureError {
        invalid(self.fixture, self.path, reason)
    }
}

/// A fixture name is a relative path of plain components.
fn check_name(fixture: &str, name: &str) -> Result<(), FixtureError> {
    let plain = |part: &str| {
        !part.is_empty()
            && !part.starts_with('.')
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    if !name.is_empty() && name.split('/').all(plain) {
        Ok(())
    } else {
        Err(invalid(
            fixture,
            "(name)",
            "a fixture name is a relative path of letters, digits, `.`, `_` and `-`",
        ))
    }
}

// ---- reading the directory ---------------------------------------------------------------------

#[derive(Default)]
struct Budget {
    files: usize,
    bytes: u64,
}

/// One directory read: its manifest and the files the replay uses, by path below the directory.
struct Layer {
    manifest: Manifest,
    files: BTreeMap<String, Vec<u8>>,
}

fn read_layer(root: &Path, name: &str, budget: &mut Budget) -> Result<Layer, FixtureError> {
    check_name(name, name)?;
    let dir = name
        .split('/')
        .fold(root.to_path_buf(), |dir, part| dir.join(part));
    let manifest_text = read_file(name, &dir.join("fixture.toml"), "fixture.toml", budget)?;
    let manifest_text = String::from_utf8(manifest_text)
        .map_err(|_| invalid(name, "fixture.toml", "the file is not UTF-8"))?;
    let manifest = Manifest::parse(name, &manifest_text)?;
    let mut files = BTreeMap::new();
    walk(name, &dir, "", &manifest, budget, &mut files)?;
    Ok(Layer { manifest, files })
}

fn read_file(
    fixture: &str,
    path: &Path,
    shown: &str,
    budget: &mut Budget,
) -> Result<Vec<u8>, FixtureError> {
    let read_error = |error: &std::io::Error| FixtureError::Read {
        fixture: fixture.to_owned(),
        path: shown.to_owned(),
        reason: error.to_string(),
    };
    let len = fs::symlink_metadata(path)
        .map_err(|e| read_error(&e))?
        .len();
    if len > MAX_FILE_BYTES {
        return Err(invalid(
            fixture,
            shown,
            format!("the file is over {MAX_FILE_BYTES} bytes"),
        ));
    }
    budget.files += 1;
    budget.bytes += len;
    if budget.files > MAX_FILES || budget.bytes > MAX_TOTAL_BYTES {
        return Err(invalid(
            fixture,
            shown,
            format!("the fixture is over {MAX_FILES} files or {MAX_TOTAL_BYTES} bytes"),
        ));
    }
    fs::read(path).map_err(|e| read_error(&e))
}

/// What the loader does with an entry.
enum Entry {
    /// The harness or the docs read it.
    Skip,
    /// Descend into a directory, or read a file.
    Take,
    /// The format has no such entry.
    Unknown,
}

/// Decides from the path below the fixture directory. `depth` is the number of components.
fn classify(manifest: &Manifest, rel: &str) -> Entry {
    let top = rel.split('/').next().unwrap_or_default();
    let spec = manifest.spec.as_deref().unwrap_or("spec.yaml");
    match top {
        "fixture.toml" | "golden" | "expect.json" | "caps.json" | "README.md" => Entry::Skip,
        _ if top == spec => Entry::Skip,
        "root" | "root.manifest.json" | "commands" | "native" | "api" | "net.json" | "env.json" => {
            Entry::Take
        }
        _ => Entry::Unknown,
    }
}

fn walk(
    fixture: &str,
    dir: &Path,
    rel: &str,
    manifest: &Manifest,
    budget: &mut Budget,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), FixtureError> {
    let shown_dir = if rel.is_empty() { "." } else { rel };
    let read_error = |error: &std::io::Error| FixtureError::Read {
        fixture: fixture.to_owned(),
        path: shown_dir.to_owned(),
        reason: error.to_string(),
    };
    let mut entries = fs::read_dir(dir)
        .map_err(|e| read_error(&e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| read_error(&e))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid(fixture, shown_dir, "a file name is not UTF-8"))?;
        let path = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let kind = entry.file_type().map_err(|e| read_error(&e))?;
        if kind.is_symlink() {
            return Err(invalid(
                fixture,
                &path,
                "a symlink. The tree holds none: list links in root.manifest.json",
            ));
        }
        match classify(manifest, &path) {
            Entry::Skip => continue,
            Entry::Unknown => {
                return Err(invalid(
                    fixture,
                    &path,
                    "not part of the fixture format (root, root.manifest.json, commands, native, api, net.json, env.json)",
                ));
            }
            Entry::Take => {}
        }
        if path.starts_with("root/") && name.contains(['\\', ':', '[', ']']) {
            return Err(invalid(
                fixture,
                &path,
                "a name with `\\`, `:`, `[` or `]` cannot be stored on every runner: list it in root.manifest.json",
            ));
        }
        if kind.is_dir() {
            walk(fixture, &entry.path(), &path, manifest, budget, files)?;
        } else if kind.is_file() {
            let in_json_dir = ["commands/", "native/", "api/"]
                .iter()
                .any(|prefix| path.starts_with(prefix));
            if in_json_dir && (path.matches('/').count() != 1 || !name.ends_with(".json")) {
                return Err(invalid(
                    fixture,
                    &path,
                    "only .json files, directly in the directory, are read here",
                ));
            }
            let bytes = read_file(fixture, &entry.path(), &path, budget)?;
            files.insert(path, bytes);
        } else {
            return Err(invalid(fixture, &path, "not a plain file or directory"));
        }
    }
    Ok(())
}

/// A path in `remove` or in the manifest: relative, plain components.
fn check_rel(ctx: &Ctx<'_>, rel: &str) -> Result<(), FixtureError> {
    let plain = !rel.is_empty()
        && rel.split('/').all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', '\0'])
        });
    if plain {
        Ok(())
    } else {
        Err(ctx.err(format!(
            "`{rel}` is not a relative path of plain components with `/` between them"
        )))
    }
}

fn merge(
    name: &str,
    mut base: BTreeMap<String, Vec<u8>>,
    remove: &[String],
    child: BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, FixtureError> {
    let ctx = Ctx {
        fixture: name,
        path: "fixture.toml",
    };
    for path in remove {
        check_rel(&ctx, path)?;
        let before = base.len();
        let below = format!("{path}/");
        base.retain(|file, _| file != path && !file.starts_with(&below));
        if base.len() == before {
            return Err(ctx.err(format!(
                "`remove` names `{path}`, which the base does not hold"
            )));
        }
    }
    base.extend(child);
    Ok(base)
}

// ---- the manifest ------------------------------------------------------------------------------

impl Manifest {
    fn parse(fixture: &str, text: &str) -> Result<Self, FixtureError> {
        let ctx = Ctx {
            fixture,
            path: "fixture.toml",
        };
        let mut table = text
            .parse::<toml::Table>()
            .map_err(|e| ctx.err(e.message().to_owned()))?;
        let mut get = Toml {
            ctx: &ctx,
            section: "",
        };
        match table.remove("schema") {
            Some(toml::Value::Integer(1)) => {}
            _ => return Err(ctx.err("`schema` must be 1")),
        }
        let name = get.string(&mut table, "name")?;
        let summary = get.string(&mut table, "summary")?;
        let origin_text = get.string(&mut table, "origin")?;
        let origin = Origin::parse(&origin_text).ok_or_else(|| {
            ctx.err(format!(
                "`origin` is `{origin_text}`; it must be hand, generated, ci-runner or throwaway"
            ))
        })?;
        let os_text = get.string(&mut table, "os")?;
        let os = match os_text.as_str() {
            "linux" => Os::Linux,
            "macos" => Os::Macos,
            "windows" => Os::Windows,
            other => {
                return Err(ctx.err(format!(
                    "`os` is `{other}`; it must be linux, macos or windows"
                )));
            }
        };
        let arch = get.string(&mut table, "arch")?;
        if !matches!(arch.as_str(), "x86_64" | "aarch64") {
            return Err(ctx.err(format!("`arch` is `{arch}`; it must be x86_64 or aarch64")));
        }
        let base = get.optional_string(&mut table, "base")?;
        if let Some(base) = &base
            && (base.contains('/') || check_name(fixture, base).is_err())
        {
            return Err(ctx.err("`base` is the name of one environment under envs/"));
        }
        let remove = get.list(&mut table, "remove")?;
        let crlf = get.list(&mut table, "crlf")?;
        let answers = get.list_required(&mut table, "answers")?;
        let spec = get.optional_string(&mut table, "spec")?;

        let mut caps_table = get.table_required(&mut table, "caps")?;
        let mut caps_get = Toml {
            ctx: &ctx,
            section: "caps.",
        };
        let caps = Caps {
            root: caps_get.boolean(&mut caps_table, "root")?,
            network: caps_get.boolean(&mut caps_table, "network")?,
            kube: caps_get.boolean(&mut caps_table, "kube")?,
        };
        caps_get.finish(&caps_table)?;

        let mut run = RunPins::default();
        if let Some(mut run_table) = get.table(&mut table, "run")? {
            let mut run_get = Toml {
                ctx: &ctx,
                section: "run.",
            };
            run.clock = match run_table.remove("clock") {
                None => None,
                Some(toml::Value::String(text)) => Some(text),
                Some(toml::Value::Datetime(when)) => Some(when.to_string()),
                Some(_) => return Err(ctx.err("`run.clock` must be a string")),
            };
            run.run_id = run_get.optional_string(&mut run_table, "run_id")?;
            run.jobs = run_get
                .optional_integer(&mut run_table, "jobs")?
                .map(|jobs| {
                    u32::try_from(jobs)
                        .ok()
                        .filter(|jobs| *jobs >= 1)
                        .ok_or_else(|| ctx.err("`run.jobs` must be 1 or more"))
                })
                .transpose()?;
            run.deadline_ms = run_get
                .optional_integer(&mut run_table, "deadline_ms")?
                .map(|ms| {
                    u64::try_from(ms)
                        .ok()
                        .filter(|ms| *ms >= 1)
                        .ok_or_else(|| ctx.err("`run.deadline_ms` must be 1 or more"))
                })
                .transpose()?;
            run_get.finish(&run_table)?;
        }

        let expect = match get.table(&mut table, "expect")? {
            None => None,
            Some(mut expect_table) => {
                let mut expect_get = Toml {
                    ctx: &ctx,
                    section: "expect.",
                };
                let verdict = expect_get.string(&mut expect_table, "verdict")?;
                let exit_code = expect_get
                    .integer(&mut expect_table, "exit_code")
                    .and_then(|code| {
                        i32::try_from(code).map_err(|_| ctx.err("`expect.exit_code` is too large"))
                    })?;
                expect_get.finish(&expect_table)?;
                Some(Expect { verdict, exit_code })
            }
        };

        let mut matrix = BTreeMap::new();
        if let Some(matrix_table) = get.table(&mut table, "matrix")? {
            for (key, value) in matrix_table {
                let toml::Value::String(value) = value else {
                    return Err(ctx.err(format!("`matrix.{key}` must be a string")));
                };
                matrix.insert(key, value);
            }
        }
        get.finish(&table)?;
        for path in &remove {
            check_rel(&ctx, path)?;
        }
        Ok(Self {
            name,
            summary,
            origin,
            os,
            arch,
            base,
            remove,
            crlf,
            answers,
            spec,
            caps,
            run,
            expect,
            matrix,
        })
    }
}

/// Typed reads from a TOML table that take the key out, so `finish` can report what is left.
struct Toml<'a> {
    ctx: &'a Ctx<'a>,
    /// `caps.` for a key in `[caps]`, for the messages.
    section: &'static str,
}

impl Toml<'_> {
    fn wrong(&self, key: &str, wanted: &str) -> FixtureError {
        self.ctx
            .err(format!("`{}{key}` must be {wanted}", self.section))
    }

    fn string(&mut self, table: &mut toml::Table, key: &str) -> Result<String, FixtureError> {
        match table.remove(key) {
            Some(toml::Value::String(text)) if !text.is_empty() => Ok(text),
            Some(_) => Err(self.wrong(key, "a non-empty string")),
            None => Err(self.ctx.err(format!("`{}{key}` is missing", self.section))),
        }
    }

    fn optional_string(
        &mut self,
        table: &mut toml::Table,
        key: &str,
    ) -> Result<Option<String>, FixtureError> {
        match table.remove(key) {
            None => Ok(None),
            Some(toml::Value::String(text)) if !text.is_empty() => Ok(Some(text)),
            Some(_) => Err(self.wrong(key, "a non-empty string")),
        }
    }

    fn boolean(&mut self, table: &mut toml::Table, key: &str) -> Result<bool, FixtureError> {
        match table.remove(key) {
            Some(toml::Value::Boolean(on)) => Ok(on),
            Some(_) => Err(self.wrong(key, "true or false")),
            None => Err(self.ctx.err(format!("`{}{key}` is missing", self.section))),
        }
    }

    fn integer(&mut self, table: &mut toml::Table, key: &str) -> Result<i64, FixtureError> {
        self.optional_integer(table, key)?
            .ok_or_else(|| self.ctx.err(format!("`{}{key}` is missing", self.section)))
    }

    fn optional_integer(
        &mut self,
        table: &mut toml::Table,
        key: &str,
    ) -> Result<Option<i64>, FixtureError> {
        match table.remove(key) {
            None => Ok(None),
            Some(toml::Value::Integer(number)) => Ok(Some(number)),
            Some(_) => Err(self.wrong(key, "an integer")),
        }
    }

    fn list(&mut self, table: &mut toml::Table, key: &str) -> Result<Vec<String>, FixtureError> {
        match table.remove(key) {
            None => Ok(Vec::new()),
            Some(toml::Value::Array(items)) => items
                .into_iter()
                .map(|item| match item {
                    toml::Value::String(text) if !text.is_empty() => Ok(text),
                    _ => Err(self.wrong(key, "a list of non-empty strings")),
                })
                .collect(),
            Some(_) => Err(self.wrong(key, "a list of non-empty strings")),
        }
    }

    fn list_required(
        &mut self,
        table: &mut toml::Table,
        key: &str,
    ) -> Result<Vec<String>, FixtureError> {
        if table.contains_key(key) {
            self.list(table, key)
        } else {
            Err(self.ctx.err(format!("`{}{key}` is missing", self.section)))
        }
    }

    fn table(
        &mut self,
        table: &mut toml::Table,
        key: &str,
    ) -> Result<Option<toml::Table>, FixtureError> {
        match table.remove(key) {
            None => Ok(None),
            Some(toml::Value::Table(inner)) => Ok(Some(inner)),
            Some(_) => Err(self.wrong(key, "a table")),
        }
    }

    fn table_required(
        &mut self,
        table: &mut toml::Table,
        key: &str,
    ) -> Result<toml::Table, FixtureError> {
        self.table(table, key)?.ok_or_else(|| {
            self.ctx
                .err(format!("`[{}{key}]` is missing", self.section))
        })
    }

    /// An error for the first key nobody asked for.
    fn finish(&self, table: &toml::Table) -> Result<(), FixtureError> {
        match table.keys().next() {
            None => Ok(()),
            Some(key) => Err(self.ctx.err(format!(
                "`{}{key}` is not a key of the format",
                self.section
            ))),
        }
    }
}

// ---- building the replay -----------------------------------------------------------------------

/// Directory listings under construction: directory key to child name to "is a directory".
type Listing = BTreeMap<String, BTreeMap<String, bool>>;

/// Records that the path `parts` exists, and every directory above it.
fn note(listing: &mut Listing, os: Os, parts: &[String], leaf_is_dir: bool) {
    for (index, name) in parts.iter().enumerate() {
        let is_dir = index + 1 < parts.len() || leaf_is_dir;
        let parent = paths::join(os, &parts[..index]);
        let slot = listing.entry(parent).or_default().entry(name.clone());
        *slot.or_insert(false) |= is_dir;
        if is_dir {
            listing
                .entry(paths::join(os, &parts[..=index]))
                .or_default();
        }
    }
}

fn build(
    fixture: &str,
    manifest: &Manifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Replay, FixtureError> {
    let os = manifest.os;
    let mut replay = Replay::new().with_os(os);
    let mut listing = Listing::new();

    for (path, bytes) in files {
        if let Some(rel) = path.strip_prefix("root/") {
            let key = paths::tree_key(os, rel);
            if replay.files.insert(key.clone(), bytes.clone()).is_some() {
                return Err(invalid(
                    fixture,
                    path,
                    "another file maps to the same path (names compare without case for a Windows fixture)",
                ));
            }
            note(&mut listing, os, &paths::components(os, &key), false);
        }
    }
    if let Some(bytes) = files.get("root.manifest.json") {
        let ctx = Ctx {
            fixture,
            path: "root.manifest.json",
        };
        apply_root_manifest(&ctx, bytes, &mut replay, &mut listing)?;
    }
    for (dir, children) in listing {
        let entries = children
            .into_iter()
            .map(|(name, is_dir)| DirEntry::new(name, is_dir))
            .collect();
        replay.dirs.insert(dir, entries);
    }
    check_tree(fixture, &replay)?;

    let mut commands: HashMap<CommandKey, String> = HashMap::new();
    let mut natives: HashMap<NativeCall, String> = HashMap::new();
    let mut requests: HashMap<ApiKey, String> = HashMap::new();
    for (path, bytes) in files {
        let ctx = Ctx { fixture, path };
        if path.starts_with("commands/") {
            let (key, shown, answer) = command(&ctx, os, bytes)?;
            claim(&mut commands, &ctx, key.clone(), &shown)?;
            replay.commands.insert(key, answer);
        } else if path.starts_with("native/") {
            let (call, answer) = native(&ctx, os, bytes)?;
            let call = replay.normal_call(&call);
            claim(&mut natives, &ctx, call.clone(), &format!("{call:?}"))?;
            replay.native.insert(call, answer);
        } else if path.starts_with("api/") {
            if path == "api/reviews.json" {
                replay.reviews = Some(json_value(&ctx, bytes)?);
            } else {
                let (key, shown, record) = api(&ctx, bytes)?;
                claim(&mut requests, &ctx, key.clone(), &shown)?;
                replay.api.insert(key, record);
            }
        } else if path == "net.json" {
            replay.script = net(&ctx, bytes)?;
        } else if path == "env.json" {
            replay.env = env(&ctx, bytes)?;
        }
    }
    Ok(replay)
}

/// Notes that `ctx.path` records `key`, or fails when an earlier file did.
fn claim<K: std::hash::Hash + Eq>(
    seen: &mut HashMap<K, String>,
    ctx: &Ctx<'_>,
    key: K,
    shown: &str,
) -> Result<(), FixtureError> {
    match seen.insert(key, ctx.path.to_owned()) {
        None => Ok(()),
        Some(first) => Err(FixtureError::Duplicate {
            fixture: ctx.fixture.to_owned(),
            key: shown.to_owned(),
            first,
            second: ctx.path.to_owned(),
        }),
    }
}

/// A link, a file and a directory cannot share one path, and a manifest entry must name something.
fn check_tree(fixture: &str, replay: &Replay) -> Result<(), FixtureError> {
    let ctx = Ctx {
        fixture,
        path: "root.manifest.json",
    };
    for link in replay.links.keys() {
        if replay.files.contains_key(link) || replay.dirs.contains_key(link) {
            return Err(ctx.err(format!("the link `{link}` is also a file or a directory")));
        }
    }
    let exists = |key: &String| {
        replay.files.contains_key(key)
            || replay.dirs.contains_key(key)
            || replay.links.contains_key(key)
    };
    for key in replay.unreadable.iter().chain(replay.modes.keys()) {
        if !exists(key) {
            return Err(ctx.err(format!("`{key}` is named but is not in the tree")));
        }
    }
    Ok(())
}

fn apply_root_manifest(
    ctx: &Ctx<'_>,
    bytes: &[u8],
    replay: &mut Replay,
    listing: &mut Listing,
) -> Result<(), FixtureError> {
    let os = replay.os;
    let mut obj = Obj::parse(ctx, bytes)?;
    if let Some(symlinks) = obj.optional_object("symlinks")? {
        for (path, target) in symlinks {
            check_rel(ctx, &path)?;
            let Value::String(target) = target else {
                return Err(ctx.err(format!("the target of the link `{path}` must be a string")));
            };
            if target.is_empty() || target.contains('\0') {
                return Err(ctx.err(format!("the link `{path}` has an empty or invalid target")));
            }
            let key = paths::tree_key(os, &path);
            note(listing, os, &paths::components(os, &key), false);
            replay.links.insert(key, target);
        }
    }
    for path in obj.optional_strings("unreadable")? {
        check_rel(ctx, &path)?;
        replay.unreadable.insert(paths::tree_key(os, &path));
    }
    if let Some(modes) = obj.optional_object("modes")? {
        for (path, mode) in modes {
            check_rel(ctx, &path)?;
            let mode = mode
                .as_str()
                .and_then(|text| u32::from_str_radix(text, 8).ok())
                .filter(|mode| *mode <= 0o7777)
                .ok_or_else(|| {
                    ctx.err(format!(
                        "the mode of `{path}` must be an octal string such as \"0640\""
                    ))
                })?;
            replay.modes.insert(paths::tree_key(os, &path), mode);
        }
    }
    for path in obj.optional_strings("dirs")? {
        check_rel(ctx, &path)?;
        let key = paths::tree_key(os, &path);
        if replay.files.contains_key(&key) {
            return Err(ctx.err(format!("`{path}` is listed as a directory but is a file")));
        }
        note(listing, os, &paths::components(os, &key), true);
    }
    obj.finish()
}

// ---- JSON files --------------------------------------------------------------------------------

/// A JSON object whose keys are taken one by one, so `finish` can report a key nobody asked for.
struct Obj<'a> {
    ctx: &'a Ctx<'a>,
    map: Map<String, Value>,
}

fn json_value(ctx: &Ctx<'_>, bytes: &[u8]) -> Result<Value, FixtureError> {
    serde_json::from_slice(bytes).map_err(|e| ctx.err(format!("not valid JSON: {e}")))
}

impl<'a> Obj<'a> {
    fn parse(ctx: &'a Ctx<'a>, bytes: &[u8]) -> Result<Self, FixtureError> {
        match json_value(ctx, bytes)? {
            Value::Object(map) => Ok(Self { ctx, map }),
            _ => Err(ctx.err("the file must hold one JSON object")),
        }
    }

    fn from_value(ctx: &'a Ctx<'a>, value: Value, name: &str) -> Result<Self, FixtureError> {
        match value {
            Value::Object(map) => Ok(Self { ctx, map }),
            _ => Err(ctx.err(format!("`{name}` must be an object"))),
        }
    }

    fn take(&mut self, key: &str) -> Option<Value> {
        self.map.remove(key)
    }

    fn string(&mut self, key: &str) -> Result<String, FixtureError> {
        match self.take(key) {
            Some(Value::String(text)) => Ok(text),
            Some(_) => Err(self.ctx.err(format!("`{key}` must be a string"))),
            None => Err(self.ctx.err(format!("`{key}` is missing"))),
        }
    }

    fn optional_string(&mut self, key: &str) -> Result<Option<String>, FixtureError> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(_) => Err(self.ctx.err(format!("`{key}` must be a string"))),
        }
    }

    fn boolean(&mut self, key: &str) -> Result<bool, FixtureError> {
        match self.take(key) {
            Some(Value::Bool(on)) => Ok(on),
            Some(_) => Err(self.ctx.err(format!("`{key}` must be true or false"))),
            None => Err(self.ctx.err(format!("`{key}` is missing"))),
        }
    }

    fn unsigned(&mut self, key: &str) -> Result<u64, FixtureError> {
        match self.take(key) {
            Some(value) => value.as_u64().ok_or_else(|| {
                self.ctx
                    .err(format!("`{key}` must be a whole number, 0 or more"))
            }),
            None => Err(self.ctx.err(format!("`{key}` is missing"))),
        }
    }

    /// A number, or `null` for none.
    fn nullable_unsigned(&mut self, key: &str) -> Result<Option<u64>, FixtureError> {
        match self.take(key) {
            Some(Value::Null) => Ok(None),
            Some(value) => value.as_u64().map(Some).ok_or_else(|| {
                self.ctx
                    .err(format!("`{key}` must be a whole number or null"))
            }),
            None => Err(self.ctx.err(format!("`{key}` is missing"))),
        }
    }

    fn delay(&mut self) -> Result<Duration, FixtureError> {
        if self.map.contains_key("delay_ms") {
            self.unsigned("delay_ms").map(Duration::from_millis)
        } else {
            Ok(Duration::ZERO)
        }
    }

    fn optional_object(&mut self, key: &str) -> Result<Option<Map<String, Value>>, FixtureError> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Object(map)) => Ok(Some(map)),
            Some(_) => Err(self.ctx.err(format!("`{key}` must be an object"))),
        }
    }

    fn strings(&mut self, key: &str, value: Option<Value>) -> Result<Vec<String>, FixtureError> {
        match value {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .into_iter()
                .map(|item| match item {
                    Value::String(text) => Ok(text),
                    _ => Err(self.ctx.err(format!("`{key}` must be a list of strings"))),
                })
                .collect(),
            Some(_) => Err(self.ctx.err(format!("`{key}` must be a list of strings"))),
        }
    }

    fn optional_strings(&mut self, key: &str) -> Result<Vec<String>, FixtureError> {
        let value = self.take(key);
        self.strings(key, value)
    }

    fn finish(self) -> Result<(), FixtureError> {
        match self.map.keys().next() {
            None => Ok(()),
            Some(key) => Err(self.ctx.err(format!("`{key}` is not a key of the format"))),
        }
    }
}

/// The program name and the arguments: how a command is found.
type CommandKey = (String, Vec<String>);

/// The method, path and query: how an API request is found.
type ApiKey = (String, String, String);

/// `commands/*.json`. Returns the key, the argv as shown in an error, and the answer.
fn command(
    ctx: &Ctx<'_>,
    os: Os,
    bytes: &[u8],
) -> Result<(CommandKey, String, CommandAnswer), FixtureError> {
    let mut obj = Obj::parse(ctx, bytes)?;
    let argv = obj.take("argv");
    let argv = obj.strings("argv", argv)?;
    let Some(program) = argv.first() else {
        return Err(ctx.err("`argv` must hold the resolved program and its arguments"));
    };
    if !paths::is_absolute(os, program) {
        return Err(ctx.err(format!(
            "`argv[0]` is `{program}`; it must be the absolute path the program resolves to, such as /usr/bin/chronyc"
        )));
    }
    let name = paths::components(os, program)
        .pop()
        .filter(|name| !paths::is_drive(name))
        .ok_or_else(|| ctx.err("`argv[0]` names a directory, not a program"))?;
    let args: Vec<String> = argv.iter().skip(1).cloned().collect();

    let stdout = obj.optional_string("stdout")?;
    let stdout_b64 = obj.optional_string("stdout_b64")?;
    let stdout = match (stdout, stdout_b64) {
        (Some(_), Some(_)) => {
            return Err(ctx.err("`stdout` and `stdout_b64` are exclusive: use one"));
        }
        (Some(text), None) => text.into_bytes(),
        (None, Some(encoded)) => {
            b64::decode(&encoded).map_err(|reason| ctx.err(format!("`stdout_b64`: {reason}")))?
        }
        (None, None) => Vec::new(),
    };
    let stderr = obj.optional_string("stderr")?.unwrap_or_default();
    let exit = match obj.take("exit") {
        None => Some(0),
        Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_i64()
                .and_then(|code| i32::try_from(code).ok())
                .ok_or_else(|| ctx.err("`exit` must be a whole number or null"))?,
        ),
    };
    let delay = obj.delay()?;
    obj.finish()?;
    let output = Output {
        exit,
        stdout,
        stderr: stderr.into_bytes(),
        ..Output::default()
    };
    Ok((
        (name, args),
        argv.join(" "),
        CommandAnswer { output, delay },
    ))
}

/// `native/*.json`.
fn native(ctx: &Ctx<'_>, os: Os, bytes: &[u8]) -> Result<(NativeCall, NativeAnswer), FixtureError> {
    let mut obj = Obj::parse(ctx, bytes)?;
    let name = obj.string("call")?;
    let call = match name.as_str() {
        "statvfs" => {
            let path = obj.string("path")?;
            if !paths::is_absolute(os, &path) {
                return Err(ctx.err("`path` must be absolute"));
            }
            NativeCall::Statvfs { path: path.into() }
        }
        "uname" => NativeCall::Uname,
        "rlimit" => {
            let resource = obj.string("resource")?;
            let resource = [
                Resource::Nofile,
                Resource::Nproc,
                Resource::Core,
                Resource::Memlock,
                Resource::Stack,
            ]
            .into_iter()
            .find(|resource_name| resource_name.as_str() == resource)
            .ok_or_else(|| {
                ctx.err(format!(
                    "`resource` is `{resource}`; it must be nofile, nproc, core, memlock or stack"
                ))
            })?;
            NativeCall::Rlimit(resource)
        }
        "hostname" => NativeCall::Hostname,
        "machine_id" => NativeCall::MachineId,
        "system_roots" => NativeCall::SystemRoots,
        other => {
            return Err(ctx.err(format!(
                "`call` is `{other}`; it must be statvfs, uname, rlimit, hostname, machine_id or system_roots"
            )));
        }
    };
    let delay = obj.delay()?;
    let value = obj.take("value");
    let error = obj.optional_string("error")?;
    let result = match (value, error) {
        (Some(_), Some(_)) => return Err(ctx.err("`value` and `error` are exclusive: use one")),
        (None, None) => return Err(ctx.err("the file needs a `value` or an `error`")),
        (None, Some(error)) => Err(match error.as_str() {
            "unsupported" => NativeFailure::Unsupported,
            "permission_denied" => NativeFailure::PermissionDenied,
            "not_found" => NativeFailure::NotFound,
            "io" => NativeFailure::Io("the fixture records an I/O error".to_owned()),
            other => {
                return Err(ctx.err(format!(
                    "`error` is `{other}`; it must be unsupported, permission_denied, not_found or io"
                )));
            }
        }),
        (Some(value), None) => Ok(native_value(ctx, &call, value)?),
    };
    obj.finish()?;
    Ok((call, NativeAnswer { result, delay }))
}

fn native_value(
    ctx: &Ctx<'_>,
    call: &NativeCall,
    value: Value,
) -> Result<NativeValue, FixtureError> {
    let text = |value: Value| match value {
        Value::String(text) => Ok(text),
        _ => Err(ctx.err("`value` must be a string")),
    };
    match call {
        NativeCall::Statvfs { .. } => {
            let mut obj = Obj::from_value(ctx, value, "value")?;
            let info = StatvfsInfo {
                fragment_size: obj.unsigned("fragment_size")?,
                blocks: obj.unsigned("blocks")?,
                blocks_free: obj.unsigned("blocks_free")?,
                blocks_available: obj.unsigned("blocks_available")?,
                files: obj.unsigned("files")?,
                files_free: obj.unsigned("files_free")?,
                read_only: obj.boolean("read_only")?,
                no_exec: match obj.take("no_exec") {
                    Some(Value::Null) => None,
                    Some(Value::Bool(on)) => Some(on),
                    _ => {
                        return Err(ctx.err("`no_exec` must be true, false or null (not reported)"));
                    }
                },
                no_suid: obj.boolean("no_suid")?,
            };
            obj.finish()?;
            Ok(NativeValue::Statvfs(info))
        }
        NativeCall::Uname => {
            let mut obj = Obj::from_value(ctx, value, "value")?;
            let info = UnameInfo {
                sysname: obj.string("sysname")?,
                release: obj.string("release")?,
                version: obj.string("version")?,
                machine: obj.string("machine")?,
            };
            obj.finish()?;
            Ok(NativeValue::Uname(info))
        }
        NativeCall::Rlimit(_) => {
            let mut obj = Obj::from_value(ctx, value, "value")?;
            let info = RlimitInfo {
                soft: obj.nullable_unsigned("soft")?,
                hard: obj.nullable_unsigned("hard")?,
            };
            obj.finish()?;
            Ok(NativeValue::Rlimit(info))
        }
        NativeCall::Hostname => Ok(NativeValue::Hostname(text(value)?)),
        NativeCall::MachineId => Ok(NativeValue::MachineId(MachineId::new(text(value)?))),
        NativeCall::SystemRoots => {
            let Value::Array(items) = value else {
                return Err(ctx.err("`value` must be a list of base64 certificates"));
            };
            let roots = items
                .into_iter()
                .map(|item| {
                    let Value::String(encoded) = item else {
                        return Err(ctx.err("`value` must be a list of base64 certificates"));
                    };
                    b64::decode(&encoded).map_err(|reason| ctx.err(format!("`value`: {reason}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(NativeValue::SystemRoots(roots))
        }
    }
}

/// `api/*.json`.
fn api(ctx: &Ctx<'_>, bytes: &[u8]) -> Result<(ApiKey, String, ApiRecord), FixtureError> {
    let mut obj = Obj::parse(ctx, bytes)?;
    let request = obj
        .take("request")
        .ok_or_else(|| ctx.err("`request` is missing"))?;
    let mut request = Obj::from_value(ctx, request, "request")?;
    let method = request.string("method")?.to_ascii_uppercase();
    let path = request.string("path")?;
    let query = request.optional_string("query")?.unwrap_or_default();
    request.finish()?;
    let status = obj.unsigned("status").and_then(|status| {
        u16::try_from(status)
            .ok()
            .filter(|status| (100..600).contains(status))
            .ok_or_else(|| ctx.err("`status` must be an HTTP status"))
    })?;
    let body = obj.take("body").unwrap_or(Value::Null);
    let delay = obj.delay()?;
    obj.finish()?;
    let shown = format!(
        "{method} {path}{}{query}",
        if query.is_empty() { "" } else { "?" }
    );
    Ok((
        (method, path, query),
        shown,
        ApiRecord {
            status,
            body,
            delay,
        },
    ))
}

/// `net.json`.
fn net(ctx: &Ctx<'_>, bytes: &[u8]) -> Result<super::net::NetScript, FixtureError> {
    let mut obj = Obj::parse(ctx, bytes)?;
    let mut script = super::net::NetScript::default();
    for (host, answer) in obj.optional_object("dns")?.unwrap_or_default() {
        if host.is_empty() {
            return Err(ctx.err("`dns` has an empty host name"));
        }
        let answer = match answer {
            Value::String(word) if word == "NXDOMAIN" => DnsAnswer::NxDomain,
            Value::Array(items) => {
                let addrs = items
                    .into_iter()
                    .map(|item| {
                        item.as_str()
                            .and_then(|text| text.parse::<IpAddr>().ok())
                            .ok_or_else(|| {
                                ctx.err(format!("`dns` for `{host}` must list IP addresses"))
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                DnsAnswer::Addrs(addrs)
            }
            _ => {
                return Err(ctx.err(format!(
                    "`dns` for `{host}` must be a list of addresses or \"NXDOMAIN\""
                )));
            }
        };
        script.insert_dns(&host, answer);
    }
    for (addr, how) in obj.optional_object("tcp")?.unwrap_or_default() {
        let addr: SocketAddr = addr.parse().map_err(|_| {
            ctx.err(format!(
                "`tcp` key `{addr}` must be an address and port, such as 192.0.2.10:443"
            ))
        })?;
        let how = match &how {
            Value::String(word) => match word.as_str() {
                "refused" => TcpScript::Refused,
                "blackhole" => TcpScript::Blackhole,
                "reset" => TcpScript::Reset,
                other => {
                    return Err(ctx.err(format!(
                        "`tcp` for {addr} is `{other}`; it must be refused, blackhole, reset or {{\"serve\": name}}"
                    )));
                }
            },
            Value::Object(map) => match (map.len(), map.get("serve")) {
                (1, Some(Value::String(name))) if !name.is_empty() => {
                    TcpScript::Serve(name.clone())
                }
                _ => {
                    return Err(ctx.err(format!(
                        "`tcp` for {addr} must be {{\"serve\": name}} when it is an object"
                    )));
                }
            },
            _ => return Err(ctx.err(format!("`tcp` for {addr} has the wrong shape"))),
        };
        script.insert_tcp(addr, how);
    }
    obj.finish()?;
    Ok(script)
}

/// `env.json`.
fn env(ctx: &Ctx<'_>, bytes: &[u8]) -> Result<HashMap<String, String>, FixtureError> {
    let Value::Object(map) = json_value(ctx, bytes)? else {
        return Err(ctx.err("the file must hold one JSON object of strings"));
    };
    map.into_iter()
        .map(|(name, value)| match value {
            Value::String(value) => Ok((name, value)),
            _ => Err(ctx.err(format!("`{name}` must be a string"))),
        })
        .collect()
}
