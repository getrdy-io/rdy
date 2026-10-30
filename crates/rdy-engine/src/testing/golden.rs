//! `assert_golden`: compares a test's output with a golden file, byte for byte (08 section 3).
//!
//! A golden is the exact bytes the product writes. A test passes the path of the golden and the bytes it
//! produced:
//!
//! ```no_run
//! # use rdy_engine::testing::fixtures_dir;
//! # use rdy_engine::testing::golden::assert_golden;
//! let report_json = b"{}\n";
//! assert_golden(fixtures_dir().join("envs/all-pass/golden/report.json"), report_json);
//! ```
//!
//! What the helper does:
//!
//! - **Same bytes:** the test passes. A stale `<path>.actual` from an earlier failure is deleted.
//! - **Different bytes:** the test fails. The message holds the first 40 lines of a unified diff and the
//!   exact command that accepts the new output. The new bytes are written to `<path>.actual`, which git
//!   ignores, so you can open both files side by side.
//! - **No golden:** the test fails, the same way, and the new bytes go to `<path>.actual`.
//! - **`UPDATE_GOLDENS=1`:** writes the golden (and its parent folders), prints each file it wrote to
//!   stderr and passes. Any other value except empty or `0` is an error, so a typo never passes silently.
//!   The accept command is `UPDATE_GOLDENS=1 cargo nextest run -p <package>`. Read `git diff` after it.
//! - **`UPDATE_GOLDENS=1` with `CI` set (to anything but empty):** the test fails at once, even when the
//!   golden matches. A golden changes on a developer's machine, never in a pipeline.
//! - **A path under `tests/fixtures/redaction` or `tests/fixtures/results`:** `UPDATE_GOLDENS` never
//!   writes there. A golden you can regenerate is not a security test, and result files of released
//!   versions are append only. The comparison still runs and still fails with a diff. A symlink into
//!   those folders counts. Edit the file by hand.
//!
//! Every path the helper is given is appended, as repo-relative text with `/` separators, to
//! `target/goldens-used/<pid>.txt` (under `CARGO_TARGET_DIR` when it is set). `cargo xtask goldens check`
//! reads those files after a full test run and fails on a golden on disk that no test used.
//!
//! The helper does no scrubbing. The test hands it bytes that are already deterministic (see
//! `testing::normalize`). It has no dependencies beyond `std`, and no `insta`: the golden is the
//! product's own output, and `report.html` opens in a browser.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// The environment variable that turns the helper from "compare" to "write".
const UPDATE_VAR: &str = "UPDATE_GOLDENS";
/// Set by every CI system. The helper refuses to update when it is non-empty.
const CI_VAR: &str = "CI";
/// How many lines of the diff the failure message carries.
const DIFF_LINES: usize = 40;
/// Lines of context around a change.
const CONTEXT: usize = 3;
/// A diff of two very different files would need `old * new` cells. Past this the diff is one block.
const MAX_CELLS: usize = 4_000_000;
/// The folders (below `tests/fixtures`) that `UPDATE_GOLDENS` never writes.
const PROTECTED: [&str; 2] = ["redaction", "results"];

/// Compares `actual` with the golden file at `path`, or writes the golden when `UPDATE_GOLDENS=1`.
/// See the [module](self) for the rules.
///
/// # Panics
///
/// Fails the test, with a message that says what to do, when the bytes differ, the golden is missing
/// or unreadable, `UPDATE_GOLDENS` has a value that is not `1` or `0`, or `UPDATE_GOLDENS=1` meets `CI`.
#[track_caller]
pub fn assert_golden(path: impl AsRef<Path>, actual: impl AsRef<[u8]>) {
    let path = path.as_ref();
    let update = match Mode::from_env() {
        Ok(mode) => mode.update,
        Err(message) => panic!("{message}"),
    };
    if let Err(err) = record_used(&used_dir(), path) {
        // Without the record, `cargo xtask goldens check` would call this golden an orphan.
        eprintln!(
            "golden: cannot record {} in target/goldens-used: {err}",
            shown(path)
        );
    }
    if let Err(message) = compare(path, actual.as_ref(), update) {
        panic!("{message}");
    }
}

/// What the environment asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mode {
    /// `UPDATE_GOLDENS=1`.
    update: bool,
}

impl Mode {
    /// Reads `UPDATE_GOLDENS` and `CI` from the process environment.
    fn from_env() -> Result<Self, String> {
        Self::parse(|name| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned()))
    }

    /// Reads the two variables through `get`, so a test needs no environment.
    fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let update = match get(UPDATE_VAR).as_deref() {
            None | Some("" | "0") => false,
            Some("1") => true,
            Some(other) => {
                return Err(format!(
                    "{UPDATE_VAR} is {other:?}. Set it to 1 to write goldens, or unset it. Nothing was compared."
                ));
            }
        };
        if update && get(CI_VAR).is_some_and(|value| !value.is_empty()) {
            return Err(format!(
                "{UPDATE_VAR}=1 is refused when {CI_VAR} is set. Goldens change on a developer machine, then \
                 the diff is reviewed and committed. Unset {UPDATE_VAR} in the pipeline."
            ));
        }
        Ok(Self { update })
    }
}

/// What `compare` did when it did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Done {
    /// The golden holds exactly the bytes.
    Matched,
    /// `UPDATE_GOLDENS=1` wrote the golden.
    Written,
}

/// The comparison. `update` is `UPDATE_GOLDENS=1`. Returns the failure message as `Err`.
fn compare(path: &Path, actual: &[u8], update: bool) -> Result<Done, String> {
    let sidecar = actual_path(path);
    let golden = match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(format!(
                "golden unreadable: {}\n{err}\nFix the path or the permissions, then run the test again.",
                shown(path)
            ));
        }
    };
    if golden.as_deref() == Some(actual) {
        // A leftover from an earlier failure would only confuse the next reader.
        let _ = fs::remove_file(&sidecar);
        return Ok(Done::Matched);
    }
    let protected = is_protected(path);
    if update && !protected {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("cannot create {}: {err}", shown(parent)))?;
        }
        fs::write(path, actual)
            .map_err(|err| format!("cannot write golden {}: {err}", shown(path)))?;
        let _ = fs::remove_file(&sidecar);
        eprintln!("golden written: {}", shown(path));
        return Ok(Done::Written);
    }
    // A missing golden may have no folder yet. The output still goes next to where the golden belongs.
    if let Some(parent) = sidecar.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let saved = match fs::write(&sidecar, actual) {
        Ok(()) => format!("The output is saved in {}.", shown(&sidecar)),
        Err(err) => format!(
            "The output could not be saved to {}: {err}.",
            shown(&sidecar)
        ),
    };
    let next = if protected {
        format!(
            "{UPDATE_VAR} never writes under tests/fixtures/{} (08 section 3). Edit the golden by hand.",
            PROTECTED.join(" or tests/fixtures/")
        )
    } else {
        format!(
            "If the new output is right, accept it with:\n  {}",
            accept_command()
        )
    };
    Err(match golden {
        None => format!(
            "golden missing: {}\nThe test produced {} bytes. {saved}\n{next}",
            shown(path),
            actual.len()
        ),
        Some(old) => format!(
            "golden differs: {}\n{}\n{saved}\n{next}",
            shown(path),
            diff_head(&old, actual)
        ),
    })
}

/// The command that rewrites the goldens of the package whose tests are running.
fn accept_command() -> String {
    match std::env::var("CARGO_PKG_NAME") {
        Ok(package) if !package.is_empty() => {
            format!("{UPDATE_VAR}=1 cargo nextest run -p {package}")
        }
        _ => format!("{UPDATE_VAR}=1 cargo nextest run --workspace"),
    }
}

/// `<path>.actual`, next to the golden. `.gitignore` lists `*.actual`.
fn actual_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".actual");
    PathBuf::from(name)
}

// ---------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------

/// The repo root as `/`-separated text. It is two levels above this crate's manifest.
fn repo_root_text() -> String {
    text_of(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

/// `target/goldens-used` of this checkout (`CARGO_TARGET_DIR` first when it is set; a relative value is
/// taken from the repo root, as `cargo xtask goldens check` does).
fn used_dir() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) if !dir.is_empty() => root.join(dir),
        _ => root.join("target"),
    };
    target.join("goldens-used")
}

/// Appends the path to `<dir>/<pid>.txt`, one line each. One `write` per line, so two threads of a
/// test binary never split a line.
fn record_used(dir: &Path, path: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(format!("{}.txt", std::process::id())))?;
    file.write_all(format!("{}\n", shown(path)).as_bytes())
}

/// The path as the record and the messages show it: absolute, `/` separated, `.` and `..` resolved
/// without touching the disk, and relative to the repo root when it is inside it.
fn shown(path: &Path) -> String {
    let text = text_of(path);
    let root = repo_root_text();
    match text
        .strip_prefix(&root)
        .and_then(|rest| rest.strip_prefix('/'))
    {
        Some(rest) => rest.to_string(),
        None => text,
    }
}

/// Absolute `/`-separated text with `.` and `..` resolved. It is text, not a path to open: judging
/// `/`-separated names with `std::path` fails on Windows.
fn text_of(path: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    lexical(&absolute.to_string_lossy())
}

/// Resolves `.`, `..` and repeated separators in `text`, with `\` taken as `/`.
fn lexical(text: &str) -> String {
    let text = text.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    let lead = if text.starts_with('/') { "/" } else { "" };
    format!("{lead}{}", parts.join("/"))
}

/// Whether `path` is under `tests/fixtures/redaction` or `tests/fixtures/results`, by its own text or
/// after the symlinks of its folders are followed.
fn is_protected(path: &Path) -> bool {
    in_protected_folder(&text_of(path)) || in_protected_folder(&real_text(path))
}

/// The text of `path` with the symlinks of its longest existing ancestor resolved.
fn real_text(path: &Path) -> String {
    let absolute = PathBuf::from(text_of(path));
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut head = absolute.as_path();
    loop {
        if let Ok(real) = fs::canonicalize(head) {
            let mut full = real;
            full.extend(rest.iter().rev());
            return lexical(&full.to_string_lossy());
        }
        match (head.parent(), head.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                head = parent;
            }
            _ => return lexical(&absolute.to_string_lossy()),
        }
    }
}

/// Whether the `/`-separated `text` has the folders `tests/fixtures/<protected>` in a row.
fn in_protected_folder(text: &str) -> bool {
    let parts: Vec<&str> = text.split('/').collect();
    parts
        .windows(3)
        .any(|w| w[0] == "tests" && w[1] == "fixtures" && PROTECTED.contains(&w[2]))
}

// ---------------------------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------------------------

/// The first [`DIFF_LINES`] lines of the unified diff of `old` (the golden) and `new` (the output).
fn diff_head(old: &[u8], new: &[u8]) -> String {
    let (Ok(old_text), Ok(new_text)) = (std::str::from_utf8(old), std::str::from_utf8(new)) else {
        let at = old
            .iter()
            .zip(new)
            .position(|(a, b)| a != b)
            .unwrap_or(old.len().min(new.len()));
        return format!(
            "The files are not both UTF-8 text. Golden: {} bytes. Output: {} bytes. First difference at byte {at}.",
            old.len(),
            new.len()
        );
    };
    let diff = unified_diff(old_text, new_text);
    let lines: Vec<&str> = diff.lines().collect();
    if lines.len() <= DIFF_LINES {
        return diff.trim_end().to_string();
    }
    format!(
        "{}\n... {} more diff lines",
        lines[..DIFF_LINES].join("\n"),
        lines.len() - DIFF_LINES
    )
}

/// One line of the edit script.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep,
    Del,
    Add,
}

/// A unified diff with [`CONTEXT`] lines around each change. The golden is `---`, the output is `+++`.
fn unified_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let script = edit_script(&old_lines, &new_lines);

    // Where each edit sits in the two files (0-based).
    let mut at = Vec::with_capacity(script.len());
    let (mut o, mut n) = (0, 0);
    for (op, _) in &script {
        at.push((o, n));
        if *op != Op::Add {
            o += 1;
        }
        if *op != Op::Del {
            n += 1;
        }
    }

    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (i, (op, _)) in script.iter().enumerate() {
        if *op == Op::Keep {
            continue;
        }
        let (lo, hi) = (
            i.saturating_sub(CONTEXT),
            (i + CONTEXT + 1).min(script.len()),
        );
        match spans.last_mut() {
            Some(last) if lo <= last.1 => last.1 = hi,
            _ => spans.push((lo, hi)),
        }
    }

    let mut out = String::from("--- golden\n+++ output\n");
    for (lo, hi) in spans {
        let slice = &script[lo..hi];
        let old_count = slice.iter().filter(|(op, _)| *op != Op::Add).count();
        let new_count = slice.iter().filter(|(op, _)| *op != Op::Del).count();
        out.push_str(&format!(
            "@@ -{},{old_count} +{},{new_count} @@\n",
            at[lo].0 + 1,
            at[lo].1 + 1
        ));
        for (op, line) in slice {
            out.push(match op {
                Op::Keep => ' ',
                Op::Del => '-',
                Op::Add => '+',
            });
            out.push_str(&visible(line));
            out.push('\n');
        }
    }
    out
}

/// A line for the diff: no final newline, a `\r` shown as `\r`, and the usual marker when the line
/// had no newline.
fn visible(line: &str) -> String {
    let (body, ended) = match line.strip_suffix('\n') {
        Some(body) => (body, true),
        None => (line, false),
    };
    let body = body.replace('\r', "\\r");
    if ended {
        body
    } else {
        format!("{body}\n\\ No newline at end of file")
    }
}

/// The edit script from `old` to `new`. Equal lines at both ends are peeled off first. The middle is a
/// longest-common-subsequence diff, or one block of deletions and additions when it is too big.
fn edit_script<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<(Op, &'a str)> {
    let head = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let tail = old[head..]
        .iter()
        .rev()
        .zip(new[head..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (mid_old, mid_new) = (&old[head..old.len() - tail], &new[head..new.len() - tail]);

    let mut script: Vec<(Op, &str)> = old[..head].iter().map(|l| (Op::Keep, *l)).collect();
    if mid_old.len().saturating_mul(mid_new.len()) > MAX_CELLS {
        script.extend(mid_old.iter().map(|l| (Op::Del, *l)));
        script.extend(mid_new.iter().map(|l| (Op::Add, *l)));
    } else {
        // lcs[i][j] is the common length of mid_old[i..] and mid_new[j..].
        let width = mid_new.len() + 1;
        let mut lcs = vec![0u32; (mid_old.len() + 1) * width];
        for i in (0..mid_old.len()).rev() {
            for j in (0..mid_new.len()).rev() {
                lcs[i * width + j] = if mid_old[i] == mid_new[j] {
                    lcs[(i + 1) * width + j + 1] + 1
                } else {
                    lcs[(i + 1) * width + j].max(lcs[i * width + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < mid_old.len() && j < mid_new.len() {
            if mid_old[i] == mid_new[j] {
                script.push((Op::Keep, mid_old[i]));
                i += 1;
                j += 1;
            } else if lcs[(i + 1) * width + j] >= lcs[i * width + j + 1] {
                script.push((Op::Del, mid_old[i]));
                i += 1;
            } else {
                script.push((Op::Add, mid_new[j]));
                j += 1;
            }
        }
        script.extend(mid_old[i..].iter().map(|l| (Op::Del, *l)));
        script.extend(mid_new[j..].iter().map(|l| (Op::Add, *l)));
    }
    script.extend(old[old.len() - tail..].iter().map(|l| (Op::Keep, *l)));
    script
}
