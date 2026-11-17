//! The M1 docs pages that the CLI points at (M1-133, 07 section 5, 09 section 4).
//!
//! Four checks:
//! - the exit codes page lists each exit code of `ExitCode`, and no other;
//! - every `https://docs.getrdy.io/<path>` in the Rust sources names a page of this repo or a redirect
//!   in `docs/redirects.txt`, so a fix line never points at a page that does not exist;
//! - every redirect target is a file of this repo;
//! - the unsigned page covers both flags and the Windows case.
//!
//! The pages live under `docs/src/content/docs/`. Only that folder is published (09 section 2).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use rdy_spec::result::ExitCode;

/// The repo root: two levels above this crate's manifest (`crates/rdy-cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// Every exit code of `ExitCode`, as the process exits with it.
fn every_exit_code() -> BTreeSet<u8> {
    [
        ExitCode::Ready,
        ExitCode::Warnings,
        ExitCode::Blockers,
        ExitCode::Usage,
        ExitCode::Internal,
    ]
    .into_iter()
    .map(ExitCode::code)
    .collect()
}

/// The numbers in the first column of the table rows of a page.
fn codes_in_first_column(page: &str) -> BTreeSet<u8> {
    page.lines()
        .filter_map(|line| {
            let first = line.strip_prefix("| ")?.split(" |").next()?;
            first.parse::<u8>().ok()
        })
        .collect()
}

#[test]
fn exit_codes_page_lists_every_exit_code_and_no_other() {
    let page = read("docs/src/content/docs/run/exit-codes.md");
    let listed = codes_in_first_column(&page);
    assert_eq!(listed, every_exit_code(), "exit codes listed on the page");
    assert_eq!(
        listed.into_iter().collect::<Vec<_>>(),
        vec![0, 1, 2, 64, 70]
    );
}

/// Adds the path of each docs URL in `text` to `paths`. A path is the run of URL path characters after
/// the host.
fn collect_paths(text: &str, paths: &mut BTreeSet<String>) {
    const HOST: &str = "https://docs.getrdy.io";
    let mut rest = text;
    while let Some(at) = rest.find(HOST) {
        rest = &rest[at + HOST.len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || "/-_.".contains(c)))
            .unwrap_or(rest.len());
        let path = &rest[..end];
        // The bare host names the site root, which is not an M1 page. Only paths are checked.
        if !path.trim_matches('/').is_empty() {
            paths.insert(path.to_owned());
        }
    }
}

/// Every docs URL path in the Rust sources under `crates/`.
fn docs_paths_in_sources() -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut stack = vec![repo_root().join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = fs::read_to_string(&path).unwrap_or_default();
                collect_paths(&text, &mut paths);
            }
        }
    }
    paths
}

/// The `from to` pairs of `docs/redirects.txt`. Blank lines and `#` comments are skipped.
fn redirects() -> Vec<(String, String)> {
    read("docs/redirects.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut parts = line.split_whitespace();
            let from = parts.next().unwrap_or_default().to_owned();
            let to = parts.next().unwrap_or_default().to_owned();
            assert!(
                parts.next().is_none(),
                "redirect line has extra text: {line}"
            );
            (from, to)
        })
        .collect()
}

/// True when a published page exists for the URL path `path`. `/unsigned` is `unsigned.md`, and
/// `/run/exit-codes/` is `run/exit-codes.md`.
fn page_exists(path: &str) -> bool {
    let rel = path.trim_matches('/');
    let root = repo_root().join("docs/src/content/docs");
    root.join(format!("{rel}.md")).is_file() || root.join(rel).join("index.md").is_file()
}

#[test]
fn every_docs_url_in_the_sources_names_a_page_or_a_redirect() {
    let redirected: BTreeSet<String> = redirects().into_iter().map(|(from, _)| from).collect();
    let missing: Vec<String> = docs_paths_in_sources()
        .into_iter()
        .filter(|path| {
            let trimmed = path.trim_end_matches('/');
            !(page_exists(path) || redirected.contains(trimmed) || redirected.contains(path))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "docs URLs in crates/ with no page and no redirect: {missing:?}. Add the page under docs/src/content/docs/ or a line in docs/redirects.txt."
    );
}

#[test]
fn every_redirect_target_is_a_file_of_this_repo() {
    const PREFIX: &str = "https://github.com/getrdy-io/rdy/blob/";
    let pairs = redirects();
    assert!(!pairs.is_empty(), "docs/redirects.txt has no redirect");
    for (from, to) in pairs {
        let rest = to.strip_prefix(PREFIX).unwrap_or_else(|| {
            panic!("redirect {from} must target a file in getrdy-io/rdy, got {to}")
        });
        // The first segment is the ref (a branch or a tag). The rest is the path in the repo.
        let (_ref, path) = rest
            .split_once('/')
            .unwrap_or_else(|| panic!("redirect {from} has no file path in {to}"));
        assert!(
            repo_root().join(path).is_file(),
            "redirect {from} points at {path}, which is not a file in this repo"
        );
    }
}

#[test]
fn unsigned_page_covers_both_flags_and_windows() {
    let page = read("docs/src/content/docs/unsigned.md");
    for needle in [
        "--allow-unsigned",
        "--key",
        "## Windows",
        "trust_store_insecure",
        "%ProgramData%",
        "exits 64",
    ] {
        assert!(page.contains(needle), "the unsigned page lacks {needle:?}");
    }
}
