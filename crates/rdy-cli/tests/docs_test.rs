//! The docs-test runner (M1-136, ADR 0048). It runs every fenced command that the README and the docs
//! pages mark `tested`, live against the built `rdy`.
//!
//! A fenced `sh`, `bash`, `console`, `powershell` or `pwsh` block carries exactly one marker in its info
//! string:
//!
//! - `tested exit=0|1|2 shape=<regex>`: the block runs. Its exit code must be in the set (`exit=` is `0`
//!   when absent) and its output (stdout, then stderr) must match the regex, with `^` and `$` at line
//!   edges. The regex has no spaces: write `\s`. A shape never holds a host number;
//! - `install-only`: runs only in the install-blocks workflow (ADR 0047), never here;
//! - `pending=<ticket>`: not built yet, owned by that ticket. The id is `M<n>-<nnn>` and has a `todo` row in
//!   `docs/plan/12-progress.md`, so a ticket that merged cannot keep a block pending;
//! - `skip=<reason>`: never runs. The reason is one of `SKIP_REASONS`.
//!
//! A block may also carry `transcript=<path>`, on the README only. Its body must equal that golden file below
//! the repo root. Every `console` block of the README has one, and every golden in `tests/fixtures/readme/`
//! is used. The golden's `$ echo $?` value must be in the block's exit set, and its verdict line must match
//! the block's shape.
//!
//! How a tested block runs: in a fresh folder that holds `examples/` and a flat copy of every example
//! spec, with an empty `HOME`, a cleared environment (so no proxy variable), and `rdy` as a wrapper script
//! in a temporary folder at the front of `PATH`. The wrapper adds `--no-network` to `rdy run` unless the
//! block gives it, so no tested block makes a lookup or a connection. A block that needs the network is
//! marked `skip=network`. A `sh` block runs as the script of `sh -c`, and its exit code is the last
//! command's, so a block with several commands checks only the last exit: split it in two. A `console`
//! block runs its first `$ ` line. Every block has a timeout, and on a timeout the whole process group is
//! killed.
//!
//! Windows has no POSIX shell that this runner can rely on, so the blocks do not run there. The parser
//! and the golden checks run on every OS. `first_run_page.rs` runs the same commands directly on Windows.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

/// The README and the folder of the published pages. Both are read; nothing else is.
const README: &str = "README.md";
const PAGES: &str = "docs/src/content/docs";
/// The folder of the README transcript goldens.
const GOLDENS: &str = "tests/fixtures/readme";
/// Languages whose blocks must carry a marker.
/// A fence with no language is checked too, so a bare block cannot hide a command.
const CHECKED: &[&str] = &[
    "",
    "sh",
    "bash",
    "shell",
    "zsh",
    "console",
    "powershell",
    "pwsh",
    "ps1",
];
/// The reasons a `skip=` block may give. A new reason is a reviewed change to this list and to ADR 0048.
const SKIP_REASONS: &[&str] = &[
    "placeholder",
    "builds",
    "network",
    "needs-release-files",
    "windows-only",
    "page-test",
];

/// The repo root: two levels above this crate's manifest (`crates/rdy-cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// What a block declares it is.
#[derive(Debug, PartialEq, Eq)]
enum Mark {
    /// Runs here. `exit` is the declared exit code set, `shape` a regex for the output.
    Tested {
        exit: BTreeSet<i32>,
        shape: String,
    },
    InstallOnly,
    Pending(String),
    Skip(String),
}

/// One fenced block.
#[derive(Debug)]
struct Block {
    /// File and line of the opening fence, for messages.
    at: String,
    lang: String,
    /// `None` for a block of a language that is not checked.
    mark: Option<Mark>,
    transcript: Option<String>,
    body: Vec<String>,
}

/// True for a ticket id: `M`, a digit, `-`, three digits.
fn is_ticket(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 6
        && b[0] == b'M'
        && b[1].is_ascii_digit()
        && b[2] == b'-'
        && b[3..].iter().all(u8::is_ascii_digit)
}

/// Parses the info string of a checked block into its marker and transcript path.
fn parse_info(words: &[&str]) -> Result<(Mark, Option<String>), String> {
    let mut tested = false;
    let mut install_only = false;
    let mut pending = None;
    let mut skip = None;
    let mut exit = None;
    let mut shape = None;
    let mut transcript = None;
    for word in words {
        match word.split_once('=') {
            None if *word == "tested" => tested = true,
            None if *word == "install-only" => install_only = true,
            Some(("pending", v)) => {
                if !is_ticket(v) {
                    return Err(format!("`{word}`: a ticket id looks like `M1-134`"));
                }
                pending = Some(v.to_owned());
            }
            Some(("skip", v)) => {
                if !SKIP_REASONS.contains(&v) {
                    return Err(format!(
                        "`{word}`: the reason is one of {}",
                        SKIP_REASONS.join(", ")
                    ));
                }
                skip = Some(v.to_owned());
            }
            Some(("exit", v)) => {
                let mut set = BTreeSet::new();
                for part in v.split('|') {
                    let code: i32 = part
                        .parse()
                        .map_err(|_| format!("`{word}`: `{part}` is not an exit code"))?;
                    set.insert(code);
                }
                exit = Some(set);
            }
            Some(("shape", v)) if !v.is_empty() => {
                Regex::new(&format!("(?m){v}"))
                    .map_err(|e| format!("`{word}`: the regex does not compile: {e}"))?;
                shape = Some(v.to_owned());
            }
            Some(("transcript", v)) if !v.is_empty() => transcript = Some(v.to_owned()),
            _ => return Err(format!("unknown word `{word}` in the info string")),
        }
    }
    let marks = [tested, install_only, pending.is_some(), skip.is_some()]
        .iter()
        .filter(|set| **set)
        .count();
    if marks != 1 {
        return Err(format!(
            "a block needs exactly one of `tested`, `install-only`, `pending=<ticket>` and `skip=<reason>`, this one has {marks}"
        ));
    }
    if !tested && (exit.is_some() || shape.is_some()) {
        return Err("`exit=` and `shape=` belong on a `tested` block".to_owned());
    }
    let mark = if tested {
        let shape = shape.ok_or("a `tested` block needs `shape=<regex>`")?;
        let exit = exit.unwrap_or_else(|| BTreeSet::from([0]));
        Mark::Tested { exit, shape }
    } else if install_only {
        Mark::InstallOnly
    } else if let Some(ticket) = pending {
        Mark::Pending(ticket)
    } else {
        Mark::Skip(skip.unwrap_or_default())
    };
    Ok((mark, transcript))
}

/// Every fenced block of `text`, and the problems found while reading their info strings.
fn blocks_of(file: &str, text: &str) -> (Vec<Block>, Vec<String>) {
    let mut blocks = Vec::new();
    let mut problems = Vec::new();
    let mut open: Option<(usize, usize, usize, Block)> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let indent = line.len() - line.trim_start().len();
        let rest = line.trim_start();
        let ticks = rest.chars().take_while(|c| *c == '`').count();
        if let Some((_, fence, strip, block)) = open.as_mut() {
            if ticks >= *fence && rest.len() == ticks {
                let (_, _, _, done) = open.take().expect("a block is open");
                blocks.push(done);
            } else {
                let cut = indent.min(*strip);
                block.body.push(line[cut..].to_owned());
            }
        } else if ticks >= 3 {
            let info = rest[ticks..].trim();
            let mut words = info.split_whitespace();
            let lang = words.next().unwrap_or("").to_owned();
            let at = format!("{file}:{}", index + 1);
            let (mark, transcript) = if CHECKED.contains(&lang.as_str()) {
                let words: Vec<&str> = words.collect();
                match parse_info(&words) {
                    Ok((mark, transcript)) => (Some(mark), transcript),
                    Err(why) => {
                        problems.push(format!("{at}: ```{lang}: {why}"));
                        (None, None)
                    }
                }
            } else {
                (None, None)
            };
            let block = Block {
                at,
                lang,
                mark,
                transcript,
                body: Vec::new(),
            };
            open = Some((index, ticks, indent, block));
        }
    }
    if let Some((index, _, _, block)) = open {
        problems.push(format!(
            "{}: the block opened on line {} is never closed",
            block.at,
            index + 1
        ));
    }
    (blocks, problems)
}

/// The Markdown files under `dir`, as repo-relative `/` paths, sorted.
fn markdown_under(root: &Path, dir: &str, out: &mut Vec<String>) {
    let mut names: Vec<_> = fs::read_dir(root.join(dir))
        .unwrap_or_else(|e| panic!("cannot read {dir}: {e}"))
        .map(|entry| entry.expect("a directory entry").file_name())
        .collect();
    names.sort();
    for name in names {
        let rel = format!("{dir}/{}", name.to_string_lossy());
        if root.join(&rel).is_dir() {
            markdown_under(root, &rel, out);
        } else if rel.ends_with(".md") {
            out.push(rel);
        }
    }
}

/// Every block of the README and the pages, and every problem found reading them.
fn scan() -> (Vec<Block>, Vec<String>) {
    let root = repo_root();
    let mut files = vec![README.to_owned()];
    markdown_under(&root, PAGES, &mut files);
    let mut blocks = Vec::new();
    let mut problems = Vec::new();
    for file in &files {
        let text = fs::read_to_string(root.join(file))
            .unwrap_or_else(|e| panic!("cannot read {file}: {e}"));
        let (found, bad) = blocks_of(file, &text);
        blocks.extend(found);
        problems.extend(bad);
    }
    (blocks, problems)
}

/// Why `block` is not valid, if it is not. A checked block with no valid marker is already a problem.
fn rule_problems(block: &Block) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(Mark::Tested { .. }) = &block.mark {
        if block.lang != "sh" && block.lang != "console" {
            out.push(format!(
                "{}: only `sh` and `console` blocks can be `tested`, this is `{}`",
                block.at, block.lang
            ));
        }
        if runnable(block).is_none() {
            out.push(format!(
                "{}: a tested block needs a command (a `console` block needs a line that starts with `$ `)",
                block.at
            ));
        }
    }
    if block.at.starts_with(README) && block.lang == "console" && block.transcript.is_none() {
        out.push(format!(
            "{}: a README `console` block is a transcript and needs `transcript=<golden file>`",
            block.at
        ));
    }
    if block.transcript.is_some() && !block.at.starts_with(README) {
        out.push(format!(
            "{}: `transcript=` belongs on a README block, not a docs page",
            block.at
        ));
    }
    if let Some(Mark::Pending(ticket)) = &block.mark
        && !todo_tickets().contains(ticket)
    {
        out.push(format!(
            "{}: `pending={ticket}` has no `todo` row in docs/plan/12-progress.md. Mark the block `tested`, or give it the ticket that owns it",
            block.at
        ));
    }
    if block.transcript.is_some() && block.lang != "console" {
        out.push(format!(
            "{}: `transcript=` belongs on a `console` block",
            block.at
        ));
    }
    out
}

/// The ids of the tickets that have a `todo` row in the progress file.
fn todo_tickets() -> BTreeSet<String> {
    let text = fs::read_to_string(repo_root().join("docs/plan/12-progress.md"))
        .expect("read docs/plan/12-progress.md");
    text.lines()
        .filter_map(|line| {
            let mut cells = line.strip_prefix("- ")?.split('|').map(str::trim);
            let id = cells.next()?;
            (cells.next()? == "todo").then(|| id.to_owned())
        })
        .collect()
}

/// The script a tested block runs: a `sh` block as written, a `console` block its first `$ ` line.
fn runnable(block: &Block) -> Option<String> {
    let script = if block.lang == "console" {
        block
            .body
            .iter()
            .find_map(|line| line.strip_prefix("$ "))?
            .to_owned()
    } else {
        block.body.join("\n")
    };
    (!script.trim().is_empty()).then_some(script)
}

/// `Ok` when `body` equals `golden`, line endings aside. `Err` names the first line that differs.
fn diff_transcript(body: &[String], golden: &str) -> Result<(), String> {
    let want: Vec<&str> = golden.lines().collect();
    for index in 0..body.len().max(want.len()) {
        let have = body.get(index).map(String::as_str);
        let expect = want.get(index).copied();
        if have != expect {
            return Err(format!(
                "line {}: the README has {have:?}, the golden has {expect:?}",
                index + 1
            ));
        }
    }
    Ok(())
}

/// Checks a golden against the block's declared exit set and shape. The value after `$ echo $?` must be in
/// the set, and the last line before it (the verdict) must match the shape.
fn check_transcript_against_mark(
    golden: &str,
    exit: &BTreeSet<i32>,
    shape: &str,
) -> Result<(), String> {
    let lines: Vec<&str> = golden.lines().collect();
    let at = lines
        .iter()
        .position(|line| *line == "$ echo $?")
        .ok_or("the golden has no `$ echo $?` line")?;
    let code: i32 = lines
        .get(at + 1)
        .and_then(|line| line.trim().parse().ok())
        .ok_or("the line after `$ echo $?` is not an exit code")?;
    if !exit.contains(&code) {
        return Err(format!(
            "the golden exits {code}, the block declares {exit:?}"
        ));
    }
    let verdict = at
        .checked_sub(1)
        .and_then(|i| lines.get(i))
        .ok_or("the golden has no verdict line before `$ echo $?`")?;
    let re = Regex::new(&format!("(?m){shape}")).expect("the shape compiled when parsed");
    if !re.is_match(verdict) {
        return Err(format!(
            "the verdict line `{verdict}` does not match `{shape}`"
        ));
    }
    Ok(())
}

#[cfg(unix)]
mod exec {
    use std::collections::BTreeSet;
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use regex::Regex;

    /// A block that runs longer than this is a failure, never a hang.
    pub const TIMEOUT: Duration = Duration::from_secs(60);

    /// Copies a folder tree. The examples are a few small files.
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).expect("create a folder");
        for entry in fs::read_dir(from).expect("read a folder") {
            let entry = entry.expect("a directory entry");
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("copy a file");
            }
        }
    }

    /// The folder with the `rdy` wrapper, made once per process before any block starts, so no thread forks
    /// while the script is open for writing. `rdy run` never opens a connection through it. Everything
    /// else is the binary.
    fn wrapper_dir() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let real = env!("CARGO_BIN_EXE_rdy");
            assert!(!real.contains('\''), "the rdy path has a quote: {real}");
            let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
                .join(format!("docs-test-bin-{}", std::process::id()));
            fs::create_dir_all(&dir).expect("a wrapper folder");
            let file = dir.join("rdy");
            let text = format!(
                "#!/bin/sh\nif [ \"$1\" = run ]; then shift; off=--no-network; for a in \"$@\"; do [ \"$a\" = --no-network ] && off=; done; exec '{real}' run $off \"$@\"; fi\nexec '{real}' \"$@\"\n"
            );
            fs::write(&file, text).expect("write the wrapper");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).expect("chmod");
            dir
        })
    }

    /// Runs `script` in a fresh folder and checks the exit code and the shape. `Err` holds the reason and
    /// the output.
    pub fn execute(
        root: &Path,
        script: &str,
        exit: &BTreeSet<i32>,
        shape: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let bin = wrapper_dir();
        let work = tempfile::tempdir().expect("a run folder");
        let out = tempfile::tempdir().expect("an output folder");
        let home = work.path().join("home");
        fs::create_dir_all(&home).expect("a home folder");
        copy_tree(&root.join("examples"), &work.path().join("examples"));
        for entry in fs::read_dir(root.join("examples/specs")).expect("the example specs") {
            let path = entry.expect("a directory entry").path();
            fs::copy(&path, work.path().join(path.file_name().expect("a name")))
                .expect("copy a spec");
        }
        let program = format!("{script}\n");
        let path = std::env::join_paths(std::iter::once(bin.to_path_buf()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .expect("a PATH");
        let stdout_path = out.path().join("stdout");
        let stderr_path = out.path().join("stderr");
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&program)
            .current_dir(work.path())
            .env_clear()
            .env("PATH", path)
            .env("HOME", &home)
            .env("NO_COLOR", "1")
            .env("LC_ALL", "C")
            .env("TERM", "dumb")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout_path).expect("an output file"))
            .stderr(File::create(&stderr_path).expect("an output file"))
            .spawn()
            .map_err(|e| format!("cannot start sh: {e}"))?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait for sh") {
                break status;
            }
            if started.elapsed() > timeout {
                // `sh` leads its own process group: kill the group, so a background child dies too.
                if let Some(pid) = i32::try_from(child.id())
                    .ok()
                    .and_then(rustix::process::Pid::from_raw)
                {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {} s", timeout.as_secs()));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = String::from_utf8_lossy(&fs::read(&stdout_path).expect("stdout")).into_owned();
        let stderr = String::from_utf8_lossy(&fs::read(&stderr_path).expect("stderr")).into_owned();
        let code = status.code().unwrap_or(-1);
        // A line break between the two streams, so `^` and `$` never join the end of one to the start of the other.
        let sep = if stdout.is_empty() || stdout.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        let seen = format!("{stdout}{sep}{stderr}");
        let shown = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
        if !exit.contains(&code) {
            return Err(format!("exit {code}, declared {exit:?}\n{shown}"));
        }
        let re = Regex::new(&format!("(?m){shape}")).expect("the shape compiled when parsed");
        if !re.is_match(&seen) {
            return Err(format!("the output does not match `{shape}`\n{shown}"));
        }
        Ok(())
    }
}

#[test]
fn every_checked_block_has_one_valid_marker() {
    let (blocks, mut problems) = scan();
    for block in &blocks {
        problems.extend(rule_problems(block));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_scan_finds_the_blocks_the_runner_exists_for() {
    let (blocks, _) = scan();
    let tested = |file: &str| {
        blocks
            .iter()
            .filter(|b| b.at.starts_with(file) && matches!(b.mark, Some(Mark::Tested { .. })))
            .count()
    };
    assert!(
        tested(README) >= 2,
        "the README has fewer than 2 tested blocks"
    );
    assert!(
        tested("docs/src/content/docs/first-run.md") >= 4,
        "the first run page has fewer than 4 tested blocks"
    );
    assert!(
        blocks
            .iter()
            .any(|b| matches!(b.mark, Some(Mark::InstallOnly))),
        "no install-only block was found: the marker of ADR 0047 is not read"
    );
}

#[test]
fn every_tested_block_runs_with_its_exit_set_and_shape() {
    let (blocks, _) = scan();
    #[cfg(not(unix))]
    {
        let n = blocks
            .iter()
            .filter(|b| matches!(b.mark, Some(Mark::Tested { .. })))
            .count();
        eprintln!(
            "docs-test: SKIPPED {n} tested blocks. This OS has no POSIX shell the runner can rely on. The unix legs run them."
        );
    }
    #[cfg(unix)]
    {
        let root = repo_root();
        let mut failures = Vec::new();
        let mut ran = 0;
        for block in &blocks {
            let Some(Mark::Tested { exit, shape }) = &block.mark else {
                continue;
            };
            let script =
                runnable(block).expect("checked by every_checked_block_has_one_valid_marker");
            ran += 1;
            if let Err(why) = exec::execute(&root, &script, exit, shape, exec::TIMEOUT) {
                failures.push(format!("{}: `{script}`: {why}", block.at));
            }
        }
        eprintln!("docs-test: ran {ran} tested blocks");
        assert!(ran > 0, "no tested block ran");
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    }
}

#[test]
fn every_readme_transcript_equals_its_golden_and_every_golden_is_used() {
    let (blocks, _) = scan();
    let root = repo_root();
    let mut used = BTreeSet::new();
    let mut failures = Vec::new();
    for block in blocks.iter().filter(|b| b.at.starts_with(README)) {
        let Some(path) = &block.transcript else {
            continue;
        };
        used.insert(path.clone());
        let Some(name) = path.strip_prefix(&format!("{GOLDENS}/")) else {
            failures.push(format!(
                "{}: the golden `{path}` is not under {GOLDENS}/",
                block.at
            ));
            continue;
        };
        if name.contains('/') || name.contains("..") {
            failures.push(format!(
                "{}: `{path}` is not a file directly in {GOLDENS}/",
                block.at
            ));
            continue;
        }
        match fs::read_to_string(root.join(path)) {
            Err(e) => failures.push(format!("{}: cannot read `{path}`: {e}", block.at)),
            Ok(golden) => {
                if let Err(why) = diff_transcript(&block.body, &golden) {
                    failures.push(format!("{}: differs from `{path}`, {why}", block.at));
                }
                if let Some(Mark::Tested { exit, shape }) = &block.mark
                    && let Err(why) = check_transcript_against_mark(&golden, exit, shape)
                {
                    failures.push(format!("{}: `{path}`: {why}", block.at));
                }
            }
        }
    }
    assert!(!used.is_empty(), "the README has no transcript");
    for entry in fs::read_dir(root.join(GOLDENS)).expect("the readme golden folder") {
        let name = entry.expect("a directory entry").file_name();
        let rel = format!("{GOLDENS}/{}", name.to_string_lossy());
        if !used.contains(&rel) {
            failures.push(format!("{rel} is used by no README transcript. Remove it."));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// The tests below prove the runner itself, on small inline pages.

fn parse_one(info: &str) -> Result<Mark, String> {
    let words: Vec<&str> = info.split_whitespace().collect();
    parse_info(&words).map(|(mark, _)| mark)
}

#[test]
fn a_tested_marker_reads_its_exit_set_and_shape() {
    let mark = parse_one(r"tested exit=0|1|2 shape=^NOT\sREADY").unwrap();
    assert_eq!(
        mark,
        Mark::Tested {
            exit: BTreeSet::from([0, 1, 2]),
            shape: r"^NOT\sREADY".to_owned()
        }
    );
    let mark = parse_one("tested shape=ok").unwrap();
    assert_eq!(
        mark,
        Mark::Tested {
            exit: BTreeSet::from([0]),
            shape: "ok".to_owned()
        }
    );
}

#[test]
fn the_other_markers_parse() {
    assert_eq!(parse_one("install-only").unwrap(), Mark::InstallOnly);
    assert_eq!(
        parse_one("pending=M1-134").unwrap(),
        Mark::Pending("M1-134".to_owned())
    );
    assert_eq!(
        parse_one("skip=network").unwrap(),
        Mark::Skip("network".to_owned())
    );
}

#[test]
fn a_bad_marker_is_refused_with_a_reason() {
    for (info, why) in [
        ("", "exactly one"),
        ("tested", "shape"),
        ("tested exit=2", "shape"),
        ("tested exit=x shape=a", "not an exit code"),
        ("tested shape=(", "does not compile"),
        ("skip=network exit=2", "belong on a `tested`"),
        ("skip=network shape=a", "belong on a `tested`"),
        ("tested install-only shape=a", "exactly one"),
        ("skip=", "the reason is one of"),
        ("skip=because", "the reason is one of"),
        ("pending=soon", "looks like `M1-134`"),
        ("pending=M1-12", "looks like `M1-134`"),
        ("pending=", "looks like `M1-134`"),
        ("tested shape=a bogus", "unknown word"),
    ] {
        let err = parse_one(info).expect_err(info);
        assert!(err.contains(why), "`{info}` gave `{err}`, want `{why}`");
    }
}

#[test]
fn the_reader_finds_blocks_marks_and_transcripts() {
    let page = "text\n```sh tested shape=a\nrdy version\n\n```\n- item\n  ```console skip=placeholder transcript=tests/fixtures/readme/a.txt\n  $ rdy\n  out\n  ```\n```text\nrdy ignored\n```\n```sh\nrdy bare\n```\n";
    let (blocks, problems) = blocks_of("page.md", page);
    assert_eq!(blocks.len(), 4);
    assert_eq!(blocks[0].at, "page.md:2");
    assert_eq!(blocks[0].body, ["rdy version", ""]);
    assert_eq!(
        blocks[1].body,
        ["$ rdy", "out"],
        "the list indent is removed"
    );
    assert_eq!(
        blocks[1].transcript.as_deref(),
        Some("tests/fixtures/readme/a.txt")
    );
    assert!(blocks[2].mark.is_none() && blocks[2].lang == "text");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].starts_with("page.md:14"), "{problems:?}");
}

#[test]
fn an_unclosed_block_is_a_problem() {
    let (_, problems) = blocks_of("p.md", "```sh skip=placeholder\nrdy\n");
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("never closed"));
}

#[test]
fn a_tested_console_block_runs_its_first_command_line() {
    let (blocks, _) = blocks_of(
        "p.md",
        "```console tested shape=a\nnote\n$ rdy version\nrdy 0\n$ echo $?\n0\n```\n",
    );
    assert_eq!(runnable(&blocks[0]).as_deref(), Some("rdy version"));
    let (blocks, _) = blocks_of("p.md", "```console tested shape=a\nrdy 0\n```\n");
    assert_eq!(runnable(&blocks[0]), None);
}

#[test]
fn a_transcript_that_differs_from_its_golden_names_the_line() {
    let body: Vec<String> = ["a", "b", "c"].map(str::to_owned).into();
    assert_eq!(diff_transcript(&body, "a\nb\nc\n"), Ok(()));
    assert_eq!(diff_transcript(&body, "a\r\nb\r\nc\r\n"), Ok(()));
    let err = diff_transcript(&body, "a\nB\nc\n").unwrap_err();
    assert!(err.starts_with("line 2"), "{err}");
    let err = diff_transcript(&body, "a\nb\n").unwrap_err();
    assert!(err.starts_with("line 3"), "{err}");
}

#[test]
fn a_golden_must_agree_with_its_block() {
    let golden = "out\nNOT READY\n$ echo $?\n2\n";
    let exit = BTreeSet::from([2]);
    assert_eq!(
        check_transcript_against_mark(golden, &exit, r"^NOT\sREADY"),
        Ok(())
    );
    let err = check_transcript_against_mark(golden, &BTreeSet::from([0, 1]), "NOT").unwrap_err();
    assert!(err.contains("exits 2"), "{err}");
    let err = check_transcript_against_mark(golden, &exit, "^READY").unwrap_err();
    assert!(err.contains("verdict line"), "{err}");
    let err = check_transcript_against_mark("NOT READY\n", &exit, "NOT").unwrap_err();
    assert!(err.contains("no `$ echo $?`"), "{err}");
}

#[test]
fn a_bare_fence_and_other_shell_names_are_checked() {
    let (_, problems) = blocks_of(
        "p.md",
        "```\nrdy run x\n```\n```zsh\nls\n```\n```ps1\nls\n```\n",
    );
    assert_eq!(problems.len(), 3, "{problems:?}");
}

#[cfg(unix)]
mod runner {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use super::{exec, repo_root};

    fn run(script: &str, exit: &[i32], shape: &str) -> Result<(), String> {
        let exit: BTreeSet<i32> = exit.iter().copied().collect();
        exec::execute(&repo_root(), script, &exit, shape, exec::TIMEOUT)
    }

    #[test]
    fn a_block_in_its_exit_set_with_the_shape_passes() {
        assert_eq!(run("echo ready; exit 2", &[1, 2], "^ready$"), Ok(()));
    }

    #[test]
    fn an_exit_code_outside_the_set_fails() {
        let err = run("exit 3", &[0, 1, 2], ".*").unwrap_err();
        assert!(err.starts_with("exit 3"), "{err}");
    }

    #[test]
    fn an_empty_shape_means_nothing_was_printed() {
        assert_eq!(run("true", &[0], r"\A\z"), Ok(()));
        let err = run("echo hi", &[0], r"\A\z").unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        // `^$` is not that: in multi-line mode it matches any empty line.
        assert_eq!(run("echo hi; echo", &[0], "^$"), Ok(()));
    }

    #[test]
    fn a_hung_block_loses_its_whole_process_group() {
        let exit = BTreeSet::from([0]);
        let marker = std::env::temp_dir().join(format!("docs-test-group-{}", std::process::id()));
        let script = format!("(sleep 2; echo late > '{}') & wait", marker.display());
        let err = exec::execute(
            &repo_root(),
            &script,
            &exit,
            ".*",
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(err.starts_with("timed out"), "{err}");
        std::thread::sleep(Duration::from_millis(2500));
        assert!(!marker.exists(), "a child outlived the timeout");
    }

    #[test]
    fn a_missing_shape_fails_and_shows_the_output() {
        let err = run("echo hello", &[0], "^goodbye").unwrap_err();
        assert!(
            err.contains("does not match") && err.contains("hello"),
            "{err}"
        );
    }

    #[test]
    fn a_block_that_hangs_times_out() {
        let exit = BTreeSet::from([0]);
        let err = exec::execute(
            &repo_root(),
            "sleep 30",
            &exit,
            ".*",
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(err.starts_with("timed out"), "{err}");
    }

    #[test]
    fn the_block_has_no_proxy_and_an_empty_home() {
        // env_clear: whatever the test process has, the block sees none of it.
        let script =
            "test -z \"${HTTPS_PROXY:-}${https_proxy:-}${RUST_LOG:-}\" && ls \"$HOME\" | wc -l";
        assert_eq!(run(script, &[0], r"^\s*0$"), Ok(()));
    }

    #[test]
    fn the_run_folder_holds_examples_and_a_flat_copy_of_the_specs() {
        let script = "test -f examples/specs/acme-quickstart.yaml && test -f acme-quickstart.yaml && echo here";
        assert_eq!(run(script, &[0], "^here$"), Ok(()));
    }

    #[test]
    fn rdy_run_is_offline_in_a_block() {
        // With the network, `net.egress` would look up the example's host names and BLOCK. Offline, it is
        // skipped. The flag is added by the `rdy` function, not written in the block.
        let script = "rdy run acme-quickstart.yaml --allow-unsigned --no-report";
        assert_eq!(run(script, &[2], r"(?m)^\s+SKIP\s+net\.egress"), Ok(()));
    }
}
