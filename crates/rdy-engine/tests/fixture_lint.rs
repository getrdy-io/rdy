//! The fixture lint (M1-050, 08 section 2 "The fixture lint").
//!
//! It runs as a normal test on every leg, so a fixture that breaks a rule fails the PR that adds it.
//! Each finding names the file (or the directory) and says how to fix it.
//!
//! What it checks, over `tests/fixtures` and (for line endings, host names and addresses) `examples/specs`:
//!
//! - **names**: a file name unique only by case, a Windows reserved name (`con`, `nul`, `com1`), a trailing
//!   dot or space, one of `<>:"|?*[]\`, a path over 150 characters, a symlink, anything but a plain file
//!   or directory;
//! - **sizes**: a file over 256 KiB, a fixture directory over 1 MiB;
//! - **line endings**: a `\r` in a file that the fixture's `crlf` list and `allow.toml` do not allow;
//! - **synthetic data**: a URL host or host name that is not `.example`, `.test`, `.invalid`, `.local`,
//!   a reserved example domain or a vendor on the built-in list, and an IP address that is publicly
//!   routable (or link-local), unless `allow.toml` allows it;
//! - **the loader**: every `fixture.toml` directory loads with `rdy_engine::testing::Fixture`, so a bad
//!   manifest, an `origin` outside the four and a duplicate argv, native call or API request fail here
//!   with the loader's own message. There is no second parser;
//! - **required cases**: the cases in [`REQUIRED`] exist, so deleting one is a red test.
//!
//! The rules run on a [`Tree`], which is the real checkout (`DiskTree`) or an in-memory copy (`MemTree`).
//! The tests of the lint plant one violation in a copy of the real tree and expect exactly that finding.
//! They plant in memory so a file named `con.json` or a 2 MiB file never touches a Windows disk. Only the
//! loader rules need real directories, and those tests write small ones to a temporary directory.
//!
//! `tests/fixtures/allow.toml` holds the exceptions. See its header for the format. An entry that matches
//! nothing is itself a finding, so the list cannot go stale.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;

use rdy_engine::testing::{Fixture, FixtureError};
use regex::Regex;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The two trees the lint reads, from the repo root.
const FIXTURES: &str = "tests/fixtures";
const EXAMPLES: &str = "examples/specs";

const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;
const MAX_PATH_CHARS: usize = 150;

/// A case that must exist. Add a row when a ticket lands a check that needs a case the lint should guard,
/// for example the `Timeout` case of `host.disk` (M1-068). `holds` is a file below the case and a text it
/// must contain.
///
/// Not here: 08 also asks that every registered, implemented check has its cases. That rule needs the
/// registry, and this crate cannot link the check families. M1-075 owns it (correction-21): the in-process
/// env harness links the CLI and the families, so it can walk the registry and fail on a check with no
/// case. Until then this list guards single cases by hand.
struct Required {
    dir: &'static str,
    holds: Option<(&'static str, &'static str)>,
    why: &'static str,
}

const REQUIRED: &[Required] = &[
    Required {
        dir: "tests/fixtures/checks/_policy/symlink-to-shadow",
        holds: Some(("root.manifest.json", "/etc/shadow")),
        why: "the policy case: a link to the password file must be Denied (08 section 2)",
    },
    Required {
        dir: "tests/fixtures/checks/host.memory/pass",
        holds: None,
        why: "host.memory needs a passing case (03)",
    },
    Required {
        dir: "tests/fixtures/checks/host.disk/hung-nfs",
        holds: Some(("native/0-mnt-nfs-data.json", "delay_ms")),
        why: "host.disk needs a Timeout case: a statvfs on a hung mount that never answers (03)",
    },
];

// ---- findings -----------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    /// The file or directory, from the repo root with `/`.
    path: String,
    /// The rule that failed.
    rule: &'static str,
    /// What is wrong and how to fix it.
    detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: [{}] {}", self.path, self.rule, self.detail)
    }
}

fn finding(path: &str, rule: &'static str, detail: impl Into<String>) -> Finding {
    Finding {
        path: path.to_owned(),
        rule,
        detail: detail.into(),
    }
}

fn render(found: &[Finding]) -> String {
    found.iter().map(|f| format!("\n  {f}")).collect()
}

/// `(path, rule)` of each finding, for exact comparison in the tests.
fn summary(found: &[Finding]) -> Vec<(&str, &str)> {
    found.iter().map(|f| (f.path.as_str(), f.rule)).collect()
}

// ---- trees --------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone)]
struct Entry {
    /// From the repo root, with `/`.
    path: String,
    kind: Kind,
    len: u64,
}

trait Tree {
    fn entries(&self) -> io::Result<Vec<Entry>>;
    fn read(&self, path: &str) -> io::Result<Vec<u8>>;
}

/// The checkout on disk.
struct DiskTree {
    repo: PathBuf,
}

impl DiskTree {
    fn walk(&self, rel: &str, out: &mut Vec<Entry>) -> io::Result<()> {
        let dir = self.repo.join(rel);
        let mut names = Vec::new();
        for item in std::fs::read_dir(&dir)? {
            let item = item?;
            let name = item.file_name().into_string().map_err(|name| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{rel}: a name that is not UTF-8: {name:?}"),
                )
            })?;
            names.push(name);
        }
        names.sort();
        for name in names {
            let path = format!("{rel}/{name}");
            let meta = std::fs::symlink_metadata(self.repo.join(&path))?;
            let kind = if meta.file_type().is_symlink() {
                Kind::Symlink
            } else if meta.is_dir() {
                Kind::Dir
            } else if meta.is_file() {
                Kind::File
            } else {
                Kind::Other
            };
            out.push(Entry {
                path: path.clone(),
                kind,
                len: meta.len(),
            });
            if kind == Kind::Dir {
                self.walk(&path, out)?;
            }
        }
        Ok(())
    }
}

impl Tree for DiskTree {
    fn entries(&self) -> io::Result<Vec<Entry>> {
        let mut out = Vec::new();
        // The fixtures must exist. The examples are linted when the directory is there.
        self.walk(FIXTURES, &mut out)?;
        if self.repo.join(EXAMPLES).is_dir() {
            self.walk(EXAMPLES, &mut out)?;
        }
        Ok(out)
    }

    fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.repo.join(path))
    }
}

/// A copy in memory, to plant a violation in without touching the disk.
#[derive(Default, Clone)]
struct MemTree {
    files: BTreeMap<String, Vec<u8>>,
    symlinks: BTreeSet<String>,
}

impl MemTree {
    fn snapshot(tree: &dyn Tree) -> io::Result<Self> {
        let mut copy = Self::default();
        for entry in tree.entries()? {
            if entry.kind == Kind::File {
                let bytes = tree.read(&entry.path)?;
                copy.files.insert(entry.path, bytes);
            }
        }
        Ok(copy)
    }

    fn put(&mut self, path: &str, bytes: impl Into<Vec<u8>>) {
        self.files.insert(path.to_owned(), bytes.into());
    }

    fn remove_below(&mut self, dir: &str) {
        let prefix = format!("{dir}/");
        self.files.retain(|path, _| !path.starts_with(&prefix));
    }

    fn text(&self, path: &str) -> TestResult<String> {
        let bytes = self
            .files
            .get(path)
            .ok_or_else(|| format!("{path} is not in the tree"))?;
        Ok(String::from_utf8(bytes.clone())?)
    }
}

impl Tree for MemTree {
    fn entries(&self) -> io::Result<Vec<Entry>> {
        let mut dirs = BTreeSet::new();
        let mut out = Vec::new();
        for (path, bytes) in &self.files {
            let mut at = 0;
            while let Some(slash) = path[at..].find('/') {
                at += slash;
                dirs.insert(path[..at].to_owned());
                at += 1;
            }
            out.push(Entry {
                path: path.clone(),
                kind: Kind::File,
                len: bytes.len() as u64,
            });
        }
        out.extend(self.symlinks.iter().map(|path| Entry {
            path: path.clone(),
            kind: Kind::Symlink,
            len: 0,
        }));
        out.extend(dirs.into_iter().map(|path| Entry {
            path,
            kind: Kind::Dir,
            len: 0,
        }));
        Ok(out)
    }

    fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.to_owned()))
    }
}

// ---- allow.toml ---------------------------------------------------------------------------------

const ALLOW_PATH: &str = "tests/fixtures/allow.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowRule {
    Crlf,
    Host,
    Ip,
}

struct AllowEntry {
    index: usize,
    rule: AllowRule,
    /// A file from the repo root. Required for `crlf`, optional for the others.
    path: Option<String>,
    /// A host name (and its subdomains) or an IP address.
    value: Option<String>,
    used: Cell<bool>,
}

struct Allow {
    entries: Vec<AllowEntry>,
}

impl Allow {
    fn load(tree: &dyn Tree, found: &mut Vec<Finding>) -> io::Result<Self> {
        let mut allow = Self {
            entries: Vec::new(),
        };
        let bytes = match tree.read(ALLOW_PATH) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(allow),
            Err(error) => return Err(error),
        };
        let bad = |detail: String| finding(ALLOW_PATH, "allow.toml", detail);
        let table = match String::from_utf8_lossy(&bytes).parse::<toml::Table>() {
            Ok(table) => table,
            Err(error) => {
                found.push(bad(format!("not valid TOML: {}", error.message())));
                return Ok(allow);
            }
        };
        for (key, value) in &table {
            if key != "allow" {
                found.push(bad(format!(
                    "unknown key `{key}`; the file holds `[[allow]]` entries"
                )));
                continue;
            }
            let Some(list) = value.as_array() else {
                found.push(bad(
                    "`allow` must be an array of `[[allow]]` tables".to_owned()
                ));
                continue;
            };
            for (index, item) in list.iter().enumerate() {
                match parse_entry(index + 1, item) {
                    Ok(entry) => allow.entries.push(entry),
                    Err(detail) => found.push(bad(format!("entry {}: {detail}", index + 1))),
                }
            }
        }
        Ok(allow)
    }

    fn permits(&self, rule: AllowRule, path: &str, value: &str) -> bool {
        let mut permitted = false;
        for entry in &self.entries {
            if entry.rule != rule {
                continue;
            }
            if entry.path.as_deref().is_some_and(|p| p != path) {
                continue;
            }
            let value_matches = match (rule, entry.value.as_deref()) {
                (AllowRule::Crlf, _) => true,
                (AllowRule::Host, Some(v)) => value == v || value.ends_with(&format!(".{v}")),
                (AllowRule::Ip, Some(v)) => match (IpAddr::from_str(v), IpAddr::from_str(value)) {
                    (Ok(a), Ok(b)) => a == b,
                    _ => false,
                },
                _ => false,
            };
            if value_matches {
                entry.used.set(true);
                permitted = true;
            }
        }
        permitted
    }

    fn report_stale(&self, found: &mut Vec<Finding>) {
        for entry in self.entries.iter().filter(|e| !e.used.get()) {
            found.push(finding(
                ALLOW_PATH,
                "allow.toml",
                format!(
                    "entry {} matched nothing. Fix: remove it, or correct its path or value",
                    entry.index
                ),
            ));
        }
    }
}

fn parse_entry(index: usize, item: &toml::Value) -> Result<AllowEntry, String> {
    let table = item.as_table().ok_or("must be a table")?;
    let mut rule = None;
    let mut path = None;
    let mut value = None;
    let mut reason = None;
    for (key, v) in table {
        let text = || {
            v.as_str()
                .map(str::to_owned)
                .ok_or(format!("`{key}` must be a string"))
        };
        match key.as_str() {
            "rule" => rule = Some(text()?),
            "path" => path = Some(text()?),
            "value" => value = Some(text()?),
            "reason" => reason = Some(text()?),
            other => return Err(format!("unknown key `{other}` (rule, path, value, reason)")),
        }
    }
    let reason = reason.ok_or("`reason` is required: say in one line why the exception is safe")?;
    if reason.trim().is_empty() || reason.contains('\n') {
        return Err("`reason` must be one non-empty line".to_owned());
    }
    let rule = match rule.as_deref() {
        Some("crlf") => AllowRule::Crlf,
        Some("host") => AllowRule::Host,
        Some("ip") => AllowRule::Ip,
        _ => return Err("`rule` must be crlf, host or ip".to_owned()),
    };
    match rule {
        AllowRule::Crlf if path.is_none() => return Err("a crlf entry needs a `path`".to_owned()),
        AllowRule::Crlf if value.is_some() => {
            return Err("a crlf entry takes no `value`".to_owned());
        }
        AllowRule::Host | AllowRule::Ip if value.is_none() => {
            return Err("a host or ip entry needs a `value`".to_owned());
        }
        AllowRule::Ip
            if value
                .as_deref()
                .is_some_and(|v| IpAddr::from_str(v).is_err()) =>
        {
            return Err("`value` is not an IP address".to_owned());
        }
        _ => {}
    }
    Ok(AllowEntry {
        index,
        rule,
        path,
        value: value.map(|v| v.to_ascii_lowercase()),
        used: Cell::new(false),
    })
}

// ---- rule: names and sizes ----------------------------------------------------------------------

/// What is wrong with one path component, if anything.
fn name_problem(name: &str) -> Option<String> {
    if let Some(bad) = name
        .chars()
        .find(|c| "<>:\"|?*[]\\".contains(*c) || c.is_control())
    {
        return Some(format!(
            "the name has `{}`, which Windows or git cannot store. Fix: rename the file",
            bad.escape_default()
        ));
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some(
            "the name ends in a dot or a space, which Windows drops. Fix: rename the file"
                .to_owned(),
        );
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reserved = matches!(
        stem.as_str(),
        "con" | "prn" | "aux" | "nul" | "conin$" | "conout$"
    ) || ["com", "lpt"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "0" | "1"
                    | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{b9}"
                    | "\u{b2}"
                    | "\u{b3}"
            )
        })
    });
    reserved.then(|| {
        format!("`{name}` is a reserved device name on Windows. Fix: rename the file, for example `{stem}-out.json`")
    })
}

fn names(entries: &[Entry], found: &mut Vec<Finding>) {
    let mut by_lower: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for entry in entries {
        let leaf = entry.path.rsplit('/').next().unwrap_or_default();
        if let Some(detail) = name_problem(leaf) {
            found.push(finding(&entry.path, "name", detail));
        }
        if entry.path.chars().count() > MAX_PATH_CHARS {
            found.push(finding(
                &entry.path,
                "name",
                format!("the path is over {MAX_PATH_CHARS} characters. Fix: shorten the names"),
            ));
        }
        match entry.kind {
            Kind::Symlink => found.push(finding(
                &entry.path,
                "name",
                "a symlink. Git on Windows may not create it. Fix: list the link in root.manifest.json",
            )),
            Kind::Other => found.push(finding(
                &entry.path,
                "name",
                "not a plain file or directory. Fix: remove it",
            )),
            Kind::File | Kind::Dir => {}
        }
        by_lower
            .entry(entry.path.to_lowercase())
            .or_default()
            .push(&entry.path);
    }
    for paths in by_lower.values().filter(|paths| paths.len() > 1) {
        for path in paths {
            found.push(finding(
                path,
                "name",
                format!(
                    "differs only by case from {}. A Windows or macOS checkout would merge them. Fix: rename one",
                    paths.join(" and ")
                ),
            ));
        }
    }
}

fn sizes(entries: &[Entry], fixture_dirs: &BTreeSet<String>, found: &mut Vec<Finding>) {
    for entry in entries.iter().filter(|e| e.kind == Kind::File) {
        if entry.len > MAX_FILE_BYTES {
            found.push(finding(
                &entry.path,
                "size",
                format!(
                    "{} bytes; the limit is {MAX_FILE_BYTES}. Fix: cut the recording to what the check reads",
                    entry.len
                ),
            ));
        }
    }
    for dir in fixture_dirs {
        let prefix = format!("{dir}/");
        let total: u64 = entries
            .iter()
            .filter(|e| e.kind == Kind::File && e.path.starts_with(&prefix))
            .map(|e| e.len)
            .sum();
        if total > MAX_FIXTURE_BYTES {
            found.push(finding(
                dir,
                "size",
                format!("{total} bytes in all; the limit is {MAX_FIXTURE_BYTES}. Fix: split the fixture or cut files"),
            ));
        }
    }
}

// ---- rule: structure and required cases ---------------------------------------------------------

/// The directories that are cases or environments: `checks/<id>/<case>` and `envs/<env>`.
fn case_dirs(entries: &[Entry]) -> BTreeSet<String> {
    let checks = format!("{FIXTURES}/checks/");
    let envs = format!("{FIXTURES}/envs/");
    entries
        .iter()
        .filter(|e| e.kind == Kind::Dir)
        .filter(|e| {
            e.path
                .strip_prefix(&checks)
                .is_some_and(|rest| rest.matches('/').count() == 1)
                || e.path
                    .strip_prefix(&envs)
                    .is_some_and(|rest| !rest.contains('/'))
        })
        .map(|e| e.path.clone())
        .collect()
}

/// Directories that hold a `fixture.toml`.
fn fixture_dirs(entries: &[Entry]) -> BTreeSet<String> {
    entries
        .iter()
        .filter(|e| e.kind == Kind::File)
        .filter_map(|e| e.path.strip_suffix("/fixture.toml"))
        .map(str::to_owned)
        .collect()
}

fn structure(
    tree: &dyn Tree,
    entries: &[Entry],
    fixture_dirs: &BTreeSet<String>,
    found: &mut Vec<Finding>,
) -> io::Result<()> {
    for dir in case_dirs(entries).difference(fixture_dirs) {
        found.push(finding(
            dir,
            "structure",
            "a case or environment directory without a fixture.toml. Fix: add the manifest (tests/fixtures/README.md)",
        ));
    }
    for required in REQUIRED {
        if !fixture_dirs.contains(required.dir) {
            found.push(finding(
                required.dir,
                "required-case",
                format!("missing: {}. Fix: restore the case", required.why),
            ));
            continue;
        }
        if let Some((file, text)) = required.holds {
            let path = format!("{}/{file}", required.dir);
            let holds = match tree.read(&path) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).contains(text),
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            };
            if !holds {
                found.push(finding(
                    required.dir,
                    "required-case",
                    format!(
                        "{file} must name `{text}`: {}. Fix: restore the case",
                        required.why
                    ),
                ));
            }
        }
    }
    Ok(())
}

// ---- rule: the loader ---------------------------------------------------------------------------

/// Loads each fixture directory (a path below `tests/fixtures`, such as `checks/host.memory/pass`) with the
/// real loader and turns a failure into a finding that names the file.
fn loader_findings(fixtures_root: &Path, dirs: &[String]) -> Vec<Finding> {
    let mut found = Vec::new();
    for dir in dirs {
        let Err(error) = Fixture::load(fixtures_root, dir) else {
            continue;
        };
        if loader_pending(dir) && is_missing_base(&error) {
            continue;
        }
        let of = |fixture: &str, path: &str| {
            if path.is_empty() || path == "." || path.starts_with('(') {
                format!("{FIXTURES}/{fixture}")
            } else {
                format!("{FIXTURES}/{fixture}/{path}")
            }
        };
        let path = match &error {
            FixtureError::Invalid { fixture, path, .. }
            | FixtureError::Read { fixture, path, .. } => of(fixture, path),
            FixtureError::Duplicate { fixture, first, .. } => of(fixture, first),
            _ => format!("{FIXTURES}/{dir}"),
        };
        found.push(finding(&path, "loader", error.to_string()));
    }
    found
}

/// Fixture directories (from the repo root) that cannot finish loading yet, with the reason. Only one loader
/// error is excused for them: the `base` is not found. Every other lint rule still covers them, and a bad
/// manifest still fails. The loader stops at the missing base before it checks commands, so a duplicate argv
/// or bad command JSON in these cases is not seen until the base is where the loader looks. The test
/// `a_pending_case_fails_on_a_duplicate_argv_once_its_base_is_found` proves those checks run on a real
/// `host.firewall` case with its base under `envs/`. The `host.firewall`
/// cases were written before the loader (M1-147) and name a `base` that is a sibling directory, while the
/// loader looks a base up under `envs/`. M1-117 builds the fixture environments under `envs/`. It moves these
/// bases there and removes this row. A row that matches no fixture is a finding, so the list cannot outlive
/// its cases.
const LOADER_PENDING: &[(&str, &str)] = &[(
    "tests/fixtures/checks/host.firewall/",
    "the cases name a sibling `base`; M1-117 moves the bases to envs/",
)];

/// The loader's "base not found" error. The case itself is read first, so a `Read` error on a fixture below
/// `envs/` is always the base.
fn is_missing_base(error: &FixtureError) -> bool {
    matches!(error, FixtureError::Read { fixture, .. } if fixture.starts_with("envs/"))
}

/// Whether `dir` (a name below `tests/fixtures`) is covered by a `LOADER_PENDING` row.
fn loader_pending(dir: &str) -> bool {
    let full = format!("{FIXTURES}/{dir}/");
    LOADER_PENDING
        .iter()
        .any(|(prefix, _)| full.starts_with(prefix))
}

/// The fixture directories the loader rule covers, as names below `tests/fixtures`, and the findings
/// for pending rows that match nothing.
fn loadable(dirs: &BTreeSet<String>, found: &mut Vec<Finding>) -> Vec<String> {
    for (prefix, why) in LOADER_PENDING {
        if !dirs.iter().any(|dir| dir.starts_with(prefix)) {
            found.push(finding(
                prefix.trim_end_matches('/'),
                "loader",
                format!(
                    "LOADER_PENDING names a directory with no fixtures ({why}). Fix: remove the row"
                ),
            ));
        }
    }
    dirs.iter()
        .filter_map(|dir| dir.strip_prefix(&format!("{FIXTURES}/")))
        .map(str::to_owned)
        .collect()
}

// ---- rule: line endings, host names, addresses --------------------------------------------------

/// The allow file and the documentation files outside the cases are not scanned for host names and
/// addresses. A README inside `checks/` or `envs/` is case data, so it is scanned.
fn scans_text(path: &str) -> bool {
    let in_cases = [format!("{FIXTURES}/checks/"), format!("{FIXTURES}/envs/")]
        .iter()
        .any(|dir| path.starts_with(dir));
    path != ALLOW_PATH && (in_cases || !path.ends_with("/README.md"))
}

/// Top-level domains the lint treats as real: every country code and common generic labels, taken from the
/// IANA root zone list (<https://data.iana.org/TLD/tlds-alpha-by-domain.txt>, 2026-10-30). Brand TLDs are left
/// out on purpose: they name companies and products, and the repo does not name those. The file header says
/// why. It is checked in so the test needs no network.
///
/// 08 says "a public suffix". This is the deviation: a short list of country codes and common generic
/// labels, not the public suffix list and not the whole root zone, because the lint only needs to know that a
/// last label is a real TLD. A host under a brand TLD is still caught inside a URL, where any label counts.
const IANA_TLDS: &str = include_str!("data/iana-tlds.txt");

/// Labels that are in the list and are also file extensions in the fixtures or in common shell, script and
/// archive names (`install.sh`, `probe.py`, `lib.rs`, `README.md`, `libfoo.so`, `sh.in`, `a.zip`,
/// `license.link`). A dotted name that ends in one of them is a file name, not a host. A URL host is still
/// checked with any label.
const EXTENSION_LABELS: &[&str] = &[
    "cc", "in", "link", "md", "ml", "pl", "pm", "ps", "pub", "py", "rs", "run", "sh", "so",
];

/// Whether `label` ends a host name that is checked outside a URL.
fn is_tld(label: &str) -> bool {
    static TLDS: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
        IANA_TLDS
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_ascii_lowercase)
            .filter(|tld| !EXTENSION_LABELS.contains(&tld.as_str()))
            .collect()
    });
    TLDS.contains(label)
}

/// Domains where anyone can get a name: the service owns the domain, the customer owns the label. Only the
/// exact name, `<service>.<domain>` and `<service>.<region>.<domain>` pass, with a plain service label and a
/// region of the usual shape. `acme-backups.s3.amazonaws.com` and `ec2-54-1-2-3.compute-1.amazonaws.com`
/// carry a customer or a machine, so they fail.
const MULTI_TENANT: &[&str] = &["amazonaws.com", "azure.com", "googleapis.com"];

/// `s3`, `sts`, `storage`, `management`: one plain label, no hyphen.
fn is_service_label(label: &str) -> bool {
    label.starts_with(|c: char| c.is_ascii_lowercase())
        && label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// `us-east-1`, `eu-west-2`, `us-gov-west-1`, `us-central1`, `europe-west4`, `eastus`, `westeurope`.
fn is_region_label(label: &str) -> bool {
    static REGION: LazyLock<Regex> = LazyLock::new(|| {
        regex(
            r"^(?:[a-z]{2}(?:-[a-z]+)+-[0-9]+|[a-z]+-[a-z]{2,}[0-9]+|(?:east|west|central)us2?|(?:north|west)europe)$",
        )
    });
    REGION.is_match(label)
}

/// `Some(shape_ok)` when `host` is below a [`MULTI_TENANT`] domain, `None` when it is not.
fn multi_tenant_shape(host: &str) -> Option<bool> {
    MULTI_TENANT.iter().find_map(|domain| {
        let prefix = host.strip_suffix(&format!(".{domain}"))?;
        let labels: Vec<&str> = prefix.split('.').collect();
        Some(match labels.as_slice() {
            [service] => is_service_label(service),
            [service, region] => is_service_label(service) && is_region_label(region),
            _ => false,
        })
    })
}

/// Names that are not real hosts: the reserved labels of RFC 2606 and RFC 6761, the example domains, and
/// the vendors Rdy checks (OS vendors, Kubernetes distributions, NVIDIA, the clouds, GitHub). Every name
/// here also matches its subdomains, except the [`MULTI_TENANT`] ones.
const ALLOWED_HOSTS: &[&str] = &[
    "example",
    "test",
    "invalid",
    "local",
    "localhost",
    "example.com",
    "example.net",
    "example.org",
    "redhat.com",
    "fedoraproject.org",
    "centos.org",
    "rockylinux.org",
    "almalinux.org",
    "ubuntu.com",
    "canonical.com",
    "debian.org",
    "suse.com",
    "opensuse.org",
    "alpinelinux.org",
    "amazonlinux.com",
    "oracle.com",
    "kernel.org",
    "microsoft.com",
    "apple.com",
    "k8s.io",
    "kubernetes.io",
    "openshift.io",
    "nvidia.com",
    "aws.com",
    "amazonaws.com",
    "azure.com",
    "googleapis.com",
    "github.com",
];

fn host_is_synthetic(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if let Some(shape_ok) = multi_tenant_shape(host) {
        return shape_ok;
    }
    !host.contains('.')
        || ALLOWED_HOSTS
            .iter()
            .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

fn v4_is_synthetic(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
    o0 == 0
        || a.is_loopback()
        || a.is_private()
        || (o0 == 100 && (64..=127).contains(&o1))
        || (o0, o1, o2) == (192, 0, 2)
        || (o0, o1, o2) == (198, 51, 100)
        || (o0, o1, o2) == (203, 0, 113)
        || a.is_multicast()
        || o0 >= 240
}

fn v6_is_synthetic(a: Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return v4_is_synthetic(v4);
    }
    let s = a.segments();
    a.is_unspecified()
        || a.is_loopback()
        || (s[0], s[1]) == (0x2001, 0x0db8)
        || (s[0] == 0x3fff && s[1] < 0x1000)
        || s[0] >> 8 == 0xfd
        || s[0] >> 8 == 0xff
}

#[expect(
    clippy::expect_used,
    reason = "the patterns are literals, checked by the first run"
)]
fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a literal pattern")
}

static URL_HOST: LazyLock<Regex> =
    LazyLock::new(|| regex(r"(?i)[a-z][a-z0-9+.\-]*://([^/\s\x22'<>\\?#]*)"));
static NAME: LazyLock<Regex> = LazyLock::new(|| regex(r"[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+"));
static V4: LazyLock<Regex> = LazyLock::new(|| regex(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"));
static V6: LazyLock<Regex> = LazyLock::new(|| regex(r"[0-9A-Fa-f:.]{3,}"));

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Host names in one line: URL hosts of any kind, and dotted names that end in a known label.
fn hosts_in(line: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for caps in URL_HOST.captures_iter(line) {
        let authority = caps.get(1).map_or("", |m| m.as_str());
        let authority = authority.rsplit('@').next().unwrap_or_default();
        if authority.starts_with('[') {
            continue;
        }
        let host = authority
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let plain = host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !host.is_empty() && plain && Ipv4Addr::from_str(&host).is_err() {
            hosts.push(host);
        }
    }
    for m in NAME.find_iter(line) {
        let name = m.as_str().to_ascii_lowercase();
        let last = name.rsplit('.').next().unwrap_or_default();
        if is_tld(last) {
            hosts.push(name);
        }
    }
    hosts
}

/// IP addresses in one line.
fn ips_in(line: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for m in V4.find_iter(line) {
        let before = line[..m.start()].chars().next_back();
        let mut after = line[m.end()..].chars();
        let next = after.next();
        // A longer dotted number is a version, not an address.
        let longer = next == Some('.') && after.next().is_some_and(|c| c.is_ascii_digit());
        if before.is_some_and(|c| word_char(c) || c == '.') || next.is_some_and(word_char) || longer
        {
            continue;
        }
        if let Ok(ip) = Ipv4Addr::from_str(m.as_str()) {
            ips.push(IpAddr::V4(ip));
        }
    }
    for m in V6.find_iter(line) {
        let before = line[..m.start()].chars().next_back();
        let next = line[m.end()..].chars().next();
        let token = m.as_str();
        if before.is_some_and(word_char)
            || next.is_some_and(word_char)
            || token.matches(':').count() < 2
        {
            continue;
        }
        for candidate in [
            token,
            token.trim_end_matches('.'),
            token.trim_end_matches(['.', ':']),
        ] {
            // An address without `::` must have eight groups, the first of four digits. That keeps
            // hardware addresses and times out.
            let spelled = candidate.contains("::")
                || (candidate.split(':').count() == 8
                    && candidate.split(':').next().is_some_and(|g| g.len() == 4));
            if let (true, Ok(ip)) = (spelled, Ipv6Addr::from_str(candidate)) {
                // A mapped address is judged, and shown, as the IPv4 address it wraps.
                ips.push(ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4));
                break;
            }
        }
    }
    ips
}

fn first_cr_line(bytes: &[u8]) -> Option<usize> {
    let at = bytes.iter().position(|b| *b == b'\r')?;
    Some(bytes[..at].iter().filter(|b| **b == b'\n').count() + 1)
}

/// The `crlf` list of the fixture that holds `path`, as paths from the repo root.
fn crlf_allowed(tree: &dyn Tree, fixture_dirs: &BTreeSet<String>, path: &str) -> io::Result<bool> {
    let Some(dir) = fixture_dirs
        .iter()
        .filter(|dir| path.starts_with(&format!("{dir}/")))
        .max_by_key(|dir| dir.len())
    else {
        return Ok(false);
    };
    let text = String::from_utf8_lossy(&tree.read(&format!("{dir}/fixture.toml"))?).into_owned();
    let Ok(table) = text.parse::<toml::Table>() else {
        return Ok(false); // the loader rule names the bad manifest
    };
    let listed = table
        .get("crlf")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .any(|listed| format!("{dir}/{listed}") == path);
    Ok(listed)
}

fn content(
    tree: &dyn Tree,
    entries: &[Entry],
    fixture_dirs: &BTreeSet<String>,
    allow: &Allow,
    found: &mut Vec<Finding>,
) -> io::Result<()> {
    for entry in entries.iter().filter(|e| e.kind == Kind::File) {
        let path = entry.path.as_str();
        let bytes = tree.read(path)?;
        if let Some(line) = first_cr_line(&bytes)
            && !allow.permits(AllowRule::Crlf, path, "")
            && !crlf_allowed(tree, fixture_dirs, path)?
        {
            found.push(finding(
                path,
                "crlf",
                format!(
                    "a carriage return on line {line}. Fixtures are LF only. Fix: remove the \\r, or list the file in `crlf` in its fixture.toml"
                ),
            ));
        }
        if !scans_text(path) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let mut seen = BTreeSet::new();
        for (index, line) in text.lines().enumerate() {
            for host in hosts_in(line) {
                if !host_is_synthetic(&host)
                    && !allow.permits(AllowRule::Host, path, &host)
                    && seen.insert(host.clone())
                {
                    found.push(finding(
                        path,
                        "host",
                        format!(
                            "line {}: the host name {host} may be real. Fix: use a name that ends in .example, or add an entry with a reason to tests/fixtures/allow.toml",
                            index + 1
                        ),
                    ));
                }
            }
            for ip in ips_in(line) {
                let synthetic = match ip {
                    IpAddr::V4(a) => v4_is_synthetic(a),
                    IpAddr::V6(a) => v6_is_synthetic(a),
                };
                if !synthetic
                    && !allow.permits(AllowRule::Ip, path, &ip.to_string())
                    && seen.insert(ip.to_string())
                {
                    found.push(finding(
                        path,
                        "ip",
                        format!(
                            "line {}: the address {ip} is publicly routable or link-local. Fix: use a documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), or add an entry with a reason to tests/fixtures/allow.toml",
                            index + 1
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

// ---- the lint -----------------------------------------------------------------------------------

/// Every rule except the loader.
fn lint_tree(tree: &dyn Tree) -> io::Result<Vec<Finding>> {
    let entries = tree.entries()?;
    let fixture_dirs = fixture_dirs(&entries);
    let mut found = Vec::new();
    let allow = Allow::load(tree, &mut found)?;
    names(&entries, &mut found);
    sizes(&entries, &fixture_dirs, &mut found);
    structure(tree, &entries, &fixture_dirs, &mut found)?;
    content(tree, &entries, &fixture_dirs, &allow, &mut found)?;
    allow.report_stale(&mut found);
    found.sort();
    found.dedup();
    Ok(found)
}

/// Every rule, on the checkout at `repo`.
fn lint_disk(repo: &Path) -> io::Result<Vec<Finding>> {
    let tree = DiskTree {
        repo: repo.to_owned(),
    };
    let mut found = lint_tree(&tree)?;
    let dirs = loadable(&fixture_dirs(&tree.entries()?), &mut found);
    found.extend(loader_findings(&repo.join(FIXTURES), &dirs));
    found.sort();
    found.dedup();
    Ok(found)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---- tests --------------------------------------------------------------------------------------

const MEMORY_PASS: &str = "tests/fixtures/checks/host.memory/pass";
const DISK_TIMEOUT: &str = "tests/fixtures/checks/host.disk/hung-nfs";
const SHADOW_CASE: &str = "tests/fixtures/checks/_policy/symlink-to-shadow";
const CANARY: &str = "tests/fixtures/canary/netstat-crlf.txt";

fn real_copy() -> TestResult<MemTree> {
    Ok(MemTree::snapshot(&DiskTree { repo: repo_root() })?)
}

/// Plants `bytes` at `path` in a copy of the real tree and returns what the lint says.
fn plant(path: &str, bytes: impl Into<Vec<u8>>) -> TestResult<Vec<Finding>> {
    let mut tree = real_copy()?;
    tree.put(path, bytes);
    Ok(lint_tree(&tree)?)
}

#[test]
fn the_checked_in_fixtures_pass_the_lint() -> TestResult {
    let found = lint_disk(&repo_root())?;
    assert!(
        found.is_empty(),
        "the fixture lint found problems:{}",
        render(&found)
    );
    Ok(())
}

#[test]
fn a_planted_public_hostname_fails_with_the_file_named() -> TestResult {
    let path = "tests/fixtures/checks/host.memory/pass/commands/leak.json";
    let found = plant(path, r#"{"stdout": "registry.vendor-prod.com\n"}"#)?;
    assert_eq!(summary(&found), [(path, "host")], "{}", render(&found));
    assert!(found[0].detail.contains("registry.vendor-prod.com"));
    // A URL host with a label the list does not know is caught too.
    let found = plant(path, r#"{"stdout": "https://api.corp-prod.shop/v1"}"#)?;
    assert_eq!(summary(&found), [(path, "host")], "{}", render(&found));
    let found = plant(path, r#"{"stdout": "https://api.vendor.sh/v1"}"#)?;
    assert_eq!(summary(&found), [(path, "host")], "{}", render(&found));
    // A dotted name outside a URL is checked against the IANA list, so `.dev`, `.app` and country codes count.
    for text in [
        "pull from registry.corp.dev now",
        "tools.vendor.app",
        "git.vendor.me",
        "x.vendor.se",
    ] {
        let found = plant(path, format!(r#"{{"stdout": "{text}"}}"#))?;
        assert_eq!(
            summary(&found),
            [(path, "host")],
            "{text}: {}",
            render(&found)
        );
    }
    Ok(())
}

#[test]
fn the_tld_list_is_embedded_and_leaves_out_file_extensions() {
    assert!(
        IANA_TLDS.lines().filter(|l| !l.starts_with('#')).count() > 300,
        "every country code is there"
    );
    for tld in ["com", "dev", "app", "me", "se", "xn--p1ai", "cloud"] {
        assert!(is_tld(tld), "{tld}");
    }
    for extension in EXTENSION_LABELS {
        assert!(!is_tld(extension), "{extension} is a file extension here");
        assert!(
            IANA_TLDS
                .lines()
                .any(|line| line.eq_ignore_ascii_case(extension)),
            "{extension} is not in the list, so it needs no row in EXTENSION_LABELS"
        );
    }
    for not_tld in ["json", "yaml", "toml", "memory", "max", "service", "6"] {
        assert!(!is_tld(not_tld), "{not_tld}");
    }
}

#[test]
fn a_cloud_domain_passes_only_by_its_fixed_shape() -> TestResult {
    let path = "tests/fixtures/checks/host.memory/pass/commands/cloud.json";
    for ok in [
        "amazonaws.com",
        "sts.amazonaws.com",
        "s3.us-east-1.amazonaws.com",
        "ec2.eu-west-2.amazonaws.com",
        "sts.us-gov-west-1.amazonaws.com",
        "management.azure.com",
        "storage.googleapis.com",
        "compute.us-central1.googleapis.com",
        "ebs.csi.aws.com",
    ] {
        let found = plant(path, format!("https://{ok}/x {ok}"))?;
        assert!(found.is_empty(), "{ok}: {}", render(&found));
    }
    for bad in [
        "acme-backups.s3.amazonaws.com",
        "ec2-54-1-2-3.compute-1.amazonaws.com",
        "acme-backups.amazonaws.com",
        "a1b2c3.execute-api.us-east-1.amazonaws.com",
        "acme.blob.core.azure.com",
        "acme.s3.us-east-1.amazonaws.com",
        "acme-prod.us-east-1.amazonaws.com",
    ] {
        let found = plant(path, format!("https://{bad}/x"))?;
        assert_eq!(
            summary(&found),
            [(path, "host")],
            "{bad}: {}",
            render(&found)
        );
        let found = plant(path, bad)?;
        assert_eq!(
            summary(&found),
            [(path, "host")],
            "{bad} bare: {}",
            render(&found)
        );
    }
    Ok(())
}

#[test]
fn a_readme_is_skipped_outside_the_cases_and_scanned_inside() -> TestResult {
    let text = "see registry.vendor-prod.com and 8.8.8.8\n";
    let outside = "tests/fixtures/specs/README.md";
    let found = plant(outside, text)?;
    assert!(found.is_empty(), "{}", render(&found));
    let inside = format!("{MEMORY_PASS}/README.md");
    let found = plant(&inside, text)?;
    assert_eq!(
        summary(&found),
        [(inside.as_str(), "host"), (inside.as_str(), "ip")],
        "{}",
        render(&found)
    );
    let env = "tests/fixtures/envs/all-pass/README.md";
    let found = plant(env, text)?;
    assert!(
        found.iter().any(|f| f.path == env && f.rule == "host"),
        "{}",
        render(&found)
    );
    Ok(())
}

#[test]
fn names_that_are_synthetic_or_belong_to_a_vendor_pass() -> TestResult {
    let ok = "https://registry.acme.example:443/v2 proxy.corp.example node.cluster.local \
              http://user:pw@proxy:3128 https://k8s.gcr.example docs at https://www.redhat.com/ \
              rbac.authorization.k8s.io ebs.csi.aws.com libfoo.so.6 5.14.0-362.el9.x86_64 install.sh \
              host.memory cpu.max a@b.example";
    let found = plant("tests/fixtures/specs/malformed/names.yaml", ok)?;
    assert!(found.is_empty(), "{}", render(&found));
    Ok(())
}

#[test]
fn a_planted_public_address_fails_with_the_file_named() -> TestResult {
    let path = "tests/fixtures/checks/host.memory/pass/root/proc/net/route";
    for (text, shown) in [
        ("gw 8.8.8.8\n", "8.8.8.8"),
        ("dns=1.1.1.1:53\n", "1.1.1.1"),
        ("[2606:4700:4700::1111]:53\n", "2606:4700:4700::1111"),
        ("peer 169.254.169.254\n", "169.254.169.254"),
        ("::ffff:8.8.4.4\n", "8.8.4.4"),
    ] {
        let found = plant(path, text)?;
        assert_eq!(summary(&found), [(path, "ip")], "{text}{}", render(&found));
        assert!(found[0].detail.contains(shown), "{}", found[0]);
    }
    Ok(())
}

#[test]
fn addresses_that_are_synthetic_or_not_addresses_pass() -> TestResult {
    let ok = "192.0.2.10 198.51.100.7 203.0.113.9 10.1.2.3 172.16.0.1 192.168.1.1 100.64.0.9 127.0.0.1 \
              0.0.0.0 255.255.255.0 224.0.0.251 [::1]:6443 2001:db8::5 fd00::1 ff02::1 ::ffff:10.0.0.1 \
              5.14.0.362 10.0.19045.5247 1.2.3.4.5 aa:bb:cc:dd:ee:ff 2026-11-02T09:00:00Z std::string 192.0.2.0/24.";
    let found = plant("tests/fixtures/specs/malformed/addresses.yaml", ok)?;
    assert!(found.is_empty(), "{}", render(&found));
    Ok(())
}

#[test]
fn an_allow_entry_lets_one_address_or_host_through_and_goes_stale_without_it() -> TestResult {
    let mut tree = real_copy()?;
    let path = "tests/fixtures/checks/host.memory/pass/commands/meta.json";
    tree.put(path, "169.254.169.254 and https://cdn.vendor-prod.com/x");
    let found = lint_tree(&tree)?;
    assert_eq!(
        summary(&found),
        [(path, "host"), (path, "ip")],
        "{}",
        render(&found)
    );

    let allow = format!(
        "{}\n[[allow]]\nrule = \"ip\"\nvalue = \"169.254.169.254\"\nreason = \"the metadata tests\"\n\n\
         [[allow]]\nrule = \"host\"\npath = \"{path}\"\nvalue = \"vendor-prod.com\"\nreason = \"planted\"\n",
        tree.text(ALLOW_PATH)?
    );
    tree.put(ALLOW_PATH, allow.clone());
    let found = lint_tree(&tree)?;
    assert!(found.is_empty(), "{}", render(&found));

    // The same entries with nothing to allow are stale.
    tree.files.remove(path);
    let found = lint_tree(&tree)?;
    assert_eq!(
        summary(&found),
        [(ALLOW_PATH, "allow.toml"), (ALLOW_PATH, "allow.toml")],
        "{}",
        render(&found)
    );
    Ok(())
}

#[test]
fn a_bad_allow_file_is_a_finding() -> TestResult {
    for bad in [
        "[[allow]]\nrule = \"ip\"\nvalue = \"192.0.2.1\"\n",
        "[[allow]]\nrule = \"ip\"\nvalue = \"not-an-ip\"\nreason = \"x\"\n",
        "[[allow]]\nrule = \"crlf\"\nreason = \"x\"\n",
        "[[allow]]\nrule = \"host\"\nvalue = \"a.example\"\nreason = \"x\"\nextra = 1\n",
        "[[allow]]\nrule = \"other\"\nreason = \"x\"\n",
        "stray = 1\n",
        "not toml [",
    ] {
        let mut tree = real_copy()?;
        let kept = tree.text(ALLOW_PATH)?;
        tree.put(ALLOW_PATH, format!("{kept}\n{bad}"));
        let found = lint_tree(&tree)?;
        assert!(
            found
                .iter()
                .any(|f| f.path == ALLOW_PATH && f.rule == "allow.toml"),
            "{bad}{}",
            render(&found)
        );
    }
    Ok(())
}

#[test]
fn a_carriage_return_outside_crlf_fails_with_the_file_named() -> TestResult {
    let path = "tests/fixtures/specs/malformed/crlf.yaml";
    let found = plant(path, "a: 1\r\nb: 2\r\n")?;
    assert_eq!(summary(&found), [(path, "crlf")], "{}", render(&found));
    assert!(found[0].detail.contains("line 1"), "{}", found[0]);

    let example = "examples/specs/crlf.yaml";
    let found = plant(example, "a: 1\r\n")?;
    assert_eq!(summary(&found), [(example, "crlf")], "{}", render(&found));
    Ok(())
}

#[test]
fn a_file_in_the_crlf_list_may_carry_a_carriage_return() -> TestResult {
    let mut tree = real_copy()?;
    let manifest = format!("{MEMORY_PASS}/fixture.toml");
    let text = tree.text(&manifest)?;
    tree.put(&format!("{MEMORY_PASS}/root/proc/win.txt"), "a\r\nb\r\n");
    let found = lint_tree(&tree)?;
    assert_eq!(
        summary(&found),
        [(&*format!("{MEMORY_PASS}/root/proc/win.txt"), "crlf")]
    );

    tree.put(
        &manifest,
        text.replace("answers = [", "crlf = [\"root/proc/win.txt\"]\nanswers = ["),
    );
    let found = lint_tree(&tree)?;
    assert!(found.is_empty(), "{}", render(&found));
    Ok(())
}

#[test]
fn the_canary_needs_its_allow_entry() -> TestResult {
    let mut tree = real_copy()?;
    assert!(tree.files.contains_key(CANARY), "the canary is checked in");
    let allow = tree.text(ALLOW_PATH)?;
    assert!(allow.contains(CANARY), "allow.toml names the canary");
    // The same file without the canary's entry.
    let without: Vec<&str> = allow
        .split("[[allow]]")
        .filter(|block| !block.contains(CANARY))
        .collect();
    tree.put(ALLOW_PATH, without.join("[[allow]]"));
    let found = lint_tree(&tree)?;
    assert_eq!(summary(&found), [(CANARY, "crlf")], "{}", render(&found));
    Ok(())
}

#[test]
fn a_file_named_con_json_fails_with_the_file_named() -> TestResult {
    let path = "tests/fixtures/checks/host.memory/pass/commands/con.json";
    let found = plant(path, "{}")?;
    assert_eq!(summary(&found), [(path, "name")], "{}", render(&found));
    assert!(found[0].detail.contains("reserved"), "{}", found[0]);
    Ok(())
}

#[test]
fn name_rules() {
    for ok in [
        "ok-name_1.json",
        "meminfo",
        "host.memory",
        "console.txt",
        "com10",
        "a.b.c",
        "_policy",
    ] {
        assert_eq!(name_problem(ok), None, "{ok}");
    }
    for bad in [
        "con",
        "CON.json",
        "nul.txt",
        "Aux",
        "prn.x",
        "com1",
        "COM9.log",
        "lpt3.txt",
        "com0",
        "LPT0.txt",
        "conin$",
        "CONOUT$.log",
        "trailing.",
        "trailing ",
        "a<b",
        "a>b",
        "a:b",
        "a\"b",
        "a|b",
        "a?b",
        "a*b",
        "x[1]",
        "x]",
        "a\\b",
        "tab\there",
    ] {
        assert!(name_problem(bad).is_some(), "{bad:?} should be refused");
    }
}

#[test]
fn names_that_collide_by_case_or_run_long_or_link_fail() -> TestResult {
    let dup = "tests/fixtures/specs/malformed/Inf.yaml";
    let found = plant(dup, "a: 1\n")?;
    assert_eq!(
        summary(&found),
        [
            (dup, "name"),
            ("tests/fixtures/specs/malformed/inf.yaml", "name")
        ],
        "{}",
        render(&found)
    );

    let long = format!("tests/fixtures/specs/malformed/{}.yaml", "a".repeat(140));
    let found = plant(&long, "a: 1\n")?;
    assert_eq!(
        summary(&found),
        [(long.as_str(), "name")],
        "{}",
        render(&found)
    );

    let mut tree = real_copy()?;
    let link = "tests/fixtures/checks/host.memory/pass/root/etc/link";
    tree.symlinks.insert(link.to_owned());
    let found = lint_tree(&tree)?;
    assert_eq!(summary(&found), [(link, "name")], "{}", render(&found));
    Ok(())
}

#[test]
fn a_two_mib_file_fails_with_the_file_named() -> TestResult {
    let path = "tests/fixtures/specs/malformed/big.yaml";
    let found = plant(path, vec![b'a'; 2 << 20])?;
    assert_eq!(summary(&found), [(path, "size")], "{}", render(&found));

    // A file just under the limit passes, and a case of many such files does not.
    let found = plant(path, vec![b'a'; 256 * 1024])?;
    assert!(found.is_empty(), "{}", render(&found));
    let mut tree = real_copy()?;
    for n in 0..5 {
        tree.put(
            &format!("{MEMORY_PASS}/root/var/log/big-{n}"),
            vec![b'a'; 250 * 1024],
        );
    }
    let found = lint_tree(&tree)?;
    assert_eq!(
        summary(&found),
        [(MEMORY_PASS, "size")],
        "{}",
        render(&found)
    );
    Ok(())
}

#[test]
fn a_case_directory_without_a_manifest_fails() -> TestResult {
    let dir = "tests/fixtures/checks/host.memory/low";
    let found = plant(&format!("{dir}/root/proc/meminfo"), "MemTotal: 1 kB\n")?;
    assert_eq!(summary(&found), [(dir, "structure")], "{}", render(&found));
    Ok(())
}

#[test]
fn any_underscore_helper_directory_under_checks_is_accepted() -> TestResult {
    // `_policy` and `_loader` are not special; a new helper family such as `_cgroup` needs no lint change.
    let mut tree = real_copy()?;
    let manifest = tree.text(&format!("{SHADOW_CASE}/fixture.toml"))?;
    let dir = "tests/fixtures/checks/_cgroup/v2-nested";
    tree.put(&format!("{dir}/fixture.toml"), manifest);
    tree.put(&format!("{dir}/root/sys/fs/cgroup/memory.max"), "max\n");
    tree.put(
        &format!("{dir}/root/sys/fs/cgroup/cpu,cpuacct/cpu.max"),
        "max 100000\n",
    );
    let found = lint_tree(&tree)?;
    assert!(found.is_empty(), "{}", render(&found));
    // Without its manifest the same directory fails like any other case.
    tree.files.remove(&format!("{dir}/fixture.toml"));
    let found = lint_tree(&tree)?;
    assert_eq!(summary(&found), [(dir, "structure")], "{}", render(&found));
    Ok(())
}

#[test]
fn deleting_a_required_case_fails_with_its_path_named() -> TestResult {
    for dir in [SHADOW_CASE, MEMORY_PASS, DISK_TIMEOUT] {
        let mut tree = real_copy()?;
        tree.remove_below(dir);
        let found = lint_tree(&tree)?;
        assert_eq!(
            summary(&found),
            [(dir, "required-case")],
            "{}",
            render(&found)
        );
    }
    // The host.disk Timeout case must still hold a delay, or it times out nothing.
    let mut tree = real_copy()?;
    let file = format!("{DISK_TIMEOUT}/native/0-mnt-nfs-data.json");
    let text = tree.text(&file)?;
    tree.put(&file, text.replace("delay_ms", "note"));
    let found = lint_tree(&tree)?;
    assert!(
        found
            .iter()
            .any(|f| f.path == DISK_TIMEOUT && f.rule == "required-case"),
        "{}",
        render(&found)
    );
    // The shadow case must still link to the password file.
    let mut tree = real_copy()?;
    tree.put(
        &format!("{SHADOW_CASE}/root.manifest.json"),
        r#"{"symlinks": {}}"#,
    );
    let found = lint_tree(&tree)?;
    assert_eq!(
        summary(&found),
        [(SHADOW_CASE, "required-case")],
        "{}",
        render(&found)
    );
    tree.files
        .remove(&format!("{SHADOW_CASE}/root.manifest.json"));
    let found = lint_tree(&tree)?;
    assert_eq!(
        summary(&found),
        [(SHADOW_CASE, "required-case")],
        "{}",
        render(&found)
    );
    Ok(())
}

// The loader rules need real directories, but only small ones with plain names.

const MANIFEST: &str = "schema = 1\nname = \"case\"\nsummary = \"A planted case\"\norigin = \"hand\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = [\"host.test\"]\n\n[caps]\nroot = false\nnetwork = false\nkube = false\n";

fn command(argv_tail: &str, stdout: &str) -> String {
    format!(
        "{{\"argv\": [\"/usr/bin/{argv_tail}\"], \"stdout\": \"{stdout}\", \"stderr\": \"\", \"exit\": 0, \"delay_ms\": 0}}"
    )
}

fn write(root: &Path, rel: &str, text: &str) -> TestResult {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)?;
    Ok(())
}

const CASE: &str = "checks/host.test/case";

#[test]
fn the_loader_rules_pass_a_clean_case() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), &format!("{CASE}/fixture.toml"), MANIFEST)?;
    write(
        dir.path(),
        &format!("{CASE}/commands/one.json"),
        &command("one", "a\\n"),
    )?;
    write(
        dir.path(),
        &format!("{CASE}/commands/two.json"),
        &command("two", "b\\n"),
    )?;
    let found = loader_findings(dir.path(), &[CASE.to_owned()]);
    assert!(found.is_empty(), "{}", render(&found));
    Ok(())
}

#[test]
fn an_origin_of_laptop_fails_with_the_manifest_named() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(
        dir.path(),
        &format!("{CASE}/fixture.toml"),
        &MANIFEST.replace("origin = \"hand\"", "origin = \"laptop\""),
    )?;
    let found = loader_findings(dir.path(), &[CASE.to_owned()]);
    assert_eq!(
        summary(&found),
        [(
            "tests/fixtures/checks/host.test/case/fixture.toml",
            "loader"
        )],
        "{}",
        render(&found)
    );
    assert!(found[0].detail.contains("laptop"), "{}", found[0]);

    write(
        dir.path(),
        &format!("{CASE}/fixture.toml"),
        &MANIFEST.replace("origin = \"hand\"\n", ""),
    )?;
    let found = loader_findings(dir.path(), &[CASE.to_owned()]);
    assert_eq!(found.len(), 1, "{}", render(&found));
    assert!(found[0].path.ends_with("fixture.toml"), "{}", found[0]);
    Ok(())
}

#[test]
fn a_duplicate_argv_key_fails_with_both_files_named() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), &format!("{CASE}/fixture.toml"), MANIFEST)?;
    write(
        dir.path(),
        &format!("{CASE}/commands/one.json"),
        &command("one", "a\\n"),
    )?;
    write(
        dir.path(),
        &format!("{CASE}/commands/again.json"),
        &command("one", "b\\n"),
    )?;
    let found = loader_findings(dir.path(), &[CASE.to_owned()]);
    assert_eq!(found.len(), 1, "{}", render(&found));
    assert_eq!(found[0].rule, "loader");
    assert!(
        found[0]
            .path
            .starts_with("tests/fixtures/checks/host.test/case/commands/"),
        "{}",
        found[0]
    );
    assert!(found[0].detail.contains("again.json"), "{}", found[0]);
    assert!(found[0].detail.contains("one.json"), "{}", found[0]);
    Ok(())
}

#[test]
fn a_repeated_json_key_fails_with_the_file_named() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), &format!("{CASE}/fixture.toml"), MANIFEST)?;
    write(
        dir.path(),
        &format!("{CASE}/commands/one.json"),
        r#"{"argv": ["/usr/bin/one"], "stdout": "a", "stdout": "b", "stderr": "", "exit": 0}"#,
    )?;
    let found = loader_findings(dir.path(), &[CASE.to_owned()]);
    assert_eq!(
        summary(&found),
        [(
            "tests/fixtures/checks/host.test/case/commands/one.json",
            "loader"
        )],
        "{}",
        render(&found)
    );
    Ok(())
}

#[test]
fn a_pending_case_is_excused_only_for_its_missing_base() -> TestResult {
    let pending = "checks/host.firewall/ufw-planted";
    assert!(loader_pending(pending));
    assert!(!loader_pending("checks/host.memory/pass"));
    assert!(!loader_pending("checks/host.firewall-other/x"));

    let dir = tempfile::tempdir()?;
    let manifest = MANIFEST.replace("answers", "base = \"base-ufw\"\nanswers");
    write(dir.path(), &format!("{pending}/fixture.toml"), &manifest)?;
    // The base is a sibling, not under envs/: the one excused error.
    let found = loader_findings(dir.path(), &[pending.to_owned()]);
    assert!(found.is_empty(), "{}", render(&found));

    // The same missing base in a case that is not pending is a finding.
    let other = "checks/host.test/needs-base";
    write(dir.path(), &format!("{other}/fixture.toml"), &manifest)?;
    let found = loader_findings(dir.path(), &[other.to_owned()]);
    assert_eq!(found.len(), 1, "{}", render(&found));
    assert!(
        found[0].path.ends_with("envs/base-ufw/fixture.toml"),
        "{}",
        found[0]
    );

    // A bad manifest in a pending case still fails: the manifest is read before the base.
    write(
        dir.path(),
        &format!("{pending}/fixture.toml"),
        &manifest.replace("origin = \"hand\"", "origin = \"laptop\""),
    )?;
    let found = loader_findings(dir.path(), &[pending.to_owned()]);
    assert_eq!(found.len(), 1, "{}", render(&found));
    assert!(found[0].detail.contains("laptop"), "{}", found[0]);
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> TestResult {
    std::fs::create_dir_all(to)?;
    for item in std::fs::read_dir(from)? {
        let item = item?;
        let target = to.join(item.file_name());
        if item.file_type()?.is_dir() {
            copy_dir(&item.path(), &target)?;
        } else {
            std::fs::copy(item.path(), target)?;
        }
    }
    Ok(())
}

#[test]
fn a_pending_case_fails_on_a_duplicate_argv_once_its_base_is_found() -> TestResult {
    // A real case that names a `base`, with that sibling base copied to `envs/<base>`, where the loader looks.
    let real = repo_root().join(FIXTURES).join("checks/host.firewall");
    let case = "checks/host.firewall/ufw-closed";
    let dir = tempfile::tempdir()?;
    copy_dir(&real.join("ufw-closed"), &dir.path().join(case))?;
    copy_dir(&real.join("base-ufw"), &dir.path().join("envs/base-ufw"))?;
    assert!(loader_pending(case));
    let found = loader_findings(dir.path(), &[case.to_owned()]);
    assert!(found.is_empty(), "{}", render(&found));

    // The same case with a duplicate argv: the finding is not excused, because the base was found.
    write(
        dir.path(),
        &format!("{case}/commands/one.json"),
        &command("one", "a\\n"),
    )?;
    write(
        dir.path(),
        &format!("{case}/commands/again.json"),
        &command("one", "b\\n"),
    )?;
    let found = loader_findings(dir.path(), &[case.to_owned()]);
    assert_eq!(found.len(), 1, "{}", render(&found));
    assert_eq!(found[0].rule, "loader");
    assert!(found[0].detail.contains("again.json"), "{}", found[0]);
    assert!(found[0].detail.contains("one.json"), "{}", found[0]);
    Ok(())
}

#[test]
fn a_pending_row_with_no_fixtures_is_a_finding() {
    let mut found = Vec::new();
    let dirs = loadable(&BTreeSet::new(), &mut found);
    assert!(dirs.is_empty());
    assert_eq!(found.len(), LOADER_PENDING.len(), "{}", render(&found));
    assert!(
        found.iter().all(|f| f.rule == "loader"),
        "{}",
        render(&found)
    );
}
