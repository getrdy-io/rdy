//! `cargo xtask goldens check`: fails on a golden file that no test used (08 section 3).
//!
//! `rdy_engine::testing::assert_golden` appends the repo-relative path of every golden it is given to
//! `target/goldens-used/<pid>.txt`. After a full test run, this command lists the golden files under
//! `tests/fixtures/` and fails on each one that no record names. Such an orphan is a golden whose test
//! was renamed or deleted, so nothing would notice if the file went stale.
//!
//! What counts as a golden file on disk (paths below `tests/fixtures/`):
//!
//! - `envs/<env>/golden/<file>`: the reports and terminal text of an environment run;
//! - `checks/<check-id>/<case>/expect.json`: the reviewed result of a check case;
//! - `redaction/<category>/<case>.expected`: a redaction expectation;
//! - `reports/golden/<file>`: a report as the JSON writer emits it (M1-055) or as the HTML renderer
//!   renders it (M1-077).
//! - `summary/<case>.txt`: the summary line and last line of a result set (M1-054).
//!
//! A `<file>.actual` is a local failure output, git ignores it, and it is never a golden. Files under
//! `results/` are released result files that other tests parse, so they are not goldens.
//!
//! Run it after `cargo nextest run --workspace`, on a `target/goldens-used` that the run started
//! empty. A record left by an older run can hide an orphan, and a run of one package only makes every
//! other package's goldens look orphaned. CI deletes the folder before the tests and runs this after.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where the records are, below the target folder.
const USED_DIR: &str = "goldens-used";
/// The golden files live below this folder of the repo.
const FIXTURES: &str = "tests/fixtures";

/// Checks the goldens under `root`. `used_dir` is the folder of records; `None` means
/// `CARGO_TARGET_DIR` (a relative value is taken from `root`) or `<root>/target`, then `goldens-used`.
/// Returns `Ok(true)` when every golden on disk was used.
pub fn check(root: &Path, used_dir: Option<&Path>) -> Result<bool> {
    let used_dir = match used_dir {
        Some(dir) => dir.to_path_buf(),
        None => default_used_dir(root),
    };
    let on_disk = golden_files(root)?;
    let used = read_records(&used_dir)?;
    let orphans: Vec<&String> = on_disk
        .iter()
        .filter(|name| !used.contains(*name))
        .collect();
    if orphans.is_empty() {
        eprintln!(
            "goldens: {} golden file(s) on disk, none orphaned.",
            on_disk.len()
        );
        return Ok(true);
    }
    for orphan in &orphans {
        eprintln!("goldens: orphan {orphan}");
    }
    if used.is_empty() {
        eprintln!(
            "goldens: no test recorded a golden in {}. Run the tests first: `cargo nextest run --workspace`.",
            used_dir.display()
        );
    } else {
        eprintln!(
            "goldens: {} orphan(s). No test compared them with anything. Delete each file, or fix the test that should read it. \
             If the tests of some packages did not run, run `cargo nextest run --workspace` on an empty {USED_DIR} folder first.",
            orphans.len()
        );
    }
    Ok(false)
}

/// `<target>/goldens-used`, the same place `assert_golden` writes.
fn default_used_dir(root: &Path) -> PathBuf {
    let target = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) if !dir.is_empty() => root.join(dir),
        _ => root.join("target"),
    };
    target.join(USED_DIR)
}

/// The paths named in every `*.txt` record, as repo-relative `/` text. A line that is an absolute
/// path (a golden outside the repo, such as a test's own temporary folder) names nothing here and is
/// dropped. A missing folder is an empty set.
fn read_records(dir: &Path) -> Result<BTreeSet<String>> {
    let mut used = BTreeSet::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(used),
        Err(err) => return Err(err).with_context(|| format!("cannot read {}", dir.display())),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "txt") {
            continue;
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        used.extend(
            text.lines()
                .filter(|line| !line.is_empty() && !is_absolute_text(line))
                .map(str::to_owned),
        );
    }
    Ok(used)
}

/// `/x`, or `C:/x` (the helper writes `/` separators on every OS).
fn is_absolute_text(line: &str) -> bool {
    let bytes = line.as_bytes();
    line.starts_with('/') || (bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/')
}

/// Every golden file below `<root>/tests/fixtures`, as sorted repo-relative `/` text.
fn golden_files(root: &Path) -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    let base = root.join(FIXTURES);
    if base.is_dir() {
        walk(&base, FIXTURES.to_owned(), &mut found)?;
    }
    Ok(found)
}

/// Collects the golden files below `dir`, whose repo-relative text is `rel`. Symlinks are not followed.
fn walk(dir: &Path, rel: String, found: &mut BTreeSet<String>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let child = format!("{rel}/{name}");
        let kind = entry.file_type()?;
        if kind.is_dir() {
            walk(&entry.path(), child, found)?;
        } else if kind.is_file() && is_golden(&child) {
            found.insert(child);
        }
    }
    Ok(())
}

/// Whether the repo-relative `/` path of a file under `tests/fixtures/` is a golden (see the module doc).
fn is_golden(path: &str) -> bool {
    let Some(inside) = path
        .strip_prefix(FIXTURES)
        .and_then(|p| p.strip_prefix('/'))
    else {
        return false;
    };
    let parts: Vec<&str> = inside.split('/').collect();
    match parts.as_slice() {
        ["envs", _env, "golden", file] => !is_sidecar(file),
        ["checks", _id, _case, "expect.json"] => true,
        ["redaction", _category, file] => file.ends_with(".expected") && !is_sidecar(file),
        ["reports", "golden", file] => !is_sidecar(file),
        ["summary", file] => file.ends_with(".txt") && !is_sidecar(file),
        _ => false,
    }
}

/// `<name>.actual`: the output of a failed run, git ignored.
fn is_sidecar(file: &str) -> bool {
    file.ends_with(".actual")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_golden_shapes_are_recognised() {
        for yes in [
            "tests/fixtures/envs/all-pass/golden/report.json",
            "tests/fixtures/envs/all-block/golden/terminal.txt",
            "tests/fixtures/checks/host.memory/pass/expect.json",
            "tests/fixtures/redaction/url/proxy.expected",
            "tests/fixtures/reports/golden/not-ready-hostile-host.json",
            "tests/fixtures/summary/all-passed.txt",
        ] {
            assert!(is_golden(yes), "{yes}");
        }
    }

    #[test]
    fn inputs_sidecars_and_released_results_are_not_goldens() {
        for no in [
            "tests/fixtures/envs/all-pass/golden/report.json.actual",
            "tests/fixtures/envs/all-pass/spec.yaml",
            "tests/fixtures/envs/all-pass/root/etc/os-release",
            "tests/fixtures/checks/host.memory/pass/fixture.toml",
            // An `expect.json` inside a case's fake file tree is data the check reads.
            "tests/fixtures/checks/host.memory/pass/root/expect.json",
            "tests/fixtures/redaction/url/proxy.in",
            "tests/fixtures/redaction/url/proxy.toml",
            "tests/fixtures/redaction/url/proxy.expected.actual",
            "tests/fixtures/results/0.1.0-alpha.1/ready.json",
            "tests/fixtures/reports/not-ready-7.2.json",
            "tests/fixtures/reports/golden/not-ready-hostile-host.json.actual",
            "docs/golden/x.json",
        ] {
            assert!(!is_golden(no), "{no}");
        }
    }

    #[test]
    fn absolute_record_lines_are_foreign() {
        assert!(is_absolute_text("/tmp/x/golden/a.json"));
        assert!(is_absolute_text("C:/Users/x/a.json"));
        assert!(!is_absolute_text("tests/fixtures/a"));
    }
}
