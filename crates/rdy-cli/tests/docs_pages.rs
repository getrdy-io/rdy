//! The M1 docs pages that the CLI points at (M1-133, 07 section 5, 09 section 4).
//!
//! Six checks:
//! - the exit codes page lists the five documented codes, which are the codes of `ExitCode` today. The
//!   test cannot see a new `ExitCode` variant that is `#[non_exhaustive]`; a reviewer must add it to the
//!   list in `every_exit_code` and to the page;
//! - every `https://docs.getrdy.io/<path>` in the Rust sources names a page of this repo or a redirect
//!   in `docs/redirects.txt`, so a fix line never points at a page that does not exist;
//! - every redirect target is a file of this repo, at `main` or at a release tag, with no `..`, query,
//!   fragment or percent escape in its path;
//! - every relative link in a published page resolves to a file, and no page uses a root-relative link;
//! - the unsigned page covers both flags and the Windows case;
//! - the sign and verify page runs every `rdy` command it shows, in `sign_verify_page.rs`, and the
//!   unsigned and sign and verify pages both say to compare the full fingerprint, not the banner's.
//!
//! The pages live under `docs/src/content/docs/`. Only that folder is published (09 section 2).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rdy_spec::result::ExitCode;

/// The repo root: two levels above this crate's manifest (`crates/rdy-cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// The five documented exit codes, from `ExitCode`.
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

/// The reason a redirect target is refused, or `None` when it is allowed. The target must be a file of
/// getrdy-io/rdy at `main` or at a release tag. Its path may not hold `..`, a query, a fragment or a
/// percent escape, so a redirect cannot leave the repo or hide what it points at.
fn target_problem(to: &str) -> Option<String> {
    const PREFIX: &str = "https://github.com/getrdy-io/rdy/blob/";
    let Some(rest) = to.strip_prefix(PREFIX) else {
        return Some(format!("it must start with {PREFIX}"));
    };
    let Some((git_ref, path)) = rest.split_once('/') else {
        return Some("it has no file path after the ref".to_owned());
    };
    if git_ref != "main" && !is_release_tag(git_ref) {
        return Some(format!(
            "the ref {git_ref} is not main or a release tag such as v0.1.0"
        ));
    }
    if path.is_empty() {
        return Some("the file path is empty".to_owned());
    }
    for bad in ["..", "?", "#", "%"] {
        if path.contains(bad) {
            return Some(format!("the path holds {bad:?}"));
        }
    }
    None
}

/// True for `v<major>.<minor>.<patch>` with an optional `-<pre-release>` made of letters, digits and dots.
/// The same shape as the release tags in RELEASING.md.
fn is_release_tag(text: &str) -> bool {
    let Some(body) = text.strip_prefix('v') else {
        return false;
    };
    let (core, pre) = match body.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (body, None),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    let core_ok = numbers.len() == 3
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let pre_ok = pre
        .is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'));
    core_ok && pre_ok
}

#[test]
fn redirect_target_rules_accept_main_and_tags_and_refuse_the_rest() {
    let base = "https://github.com/getrdy-io/rdy/blob";
    for ok in [
        format!("{base}/main/docs/src/content/docs/unsigned.md"),
        format!("{base}/v0.1.0/docs/src/content/docs/unsigned.md"),
        format!("{base}/v0.1.0-alpha.3/docs/src/content/docs/unsigned.md"),
    ] {
        assert_eq!(target_problem(&ok), None, "{ok} should be allowed");
    }
    for bad in [
        format!("{base}/main/docs/../Cargo.toml"),
        format!("{base}/v0.1.0/docs/src/content/docs/unsigned.md?raw=1"),
        format!("{base}/v0.1.0/docs/src/content/docs/unsigned.md#top"),
        format!("{base}/main/docs/src/content/docs/%75nsigned.md"),
        format!("{base}/feature-x/docs/src/content/docs/unsigned.md"),
        format!("{base}/v0.1/docs/src/content/docs/unsigned.md"),
        "https://github.com/getrdy-io/other/blob/main/docs/x.md".to_owned(),
        format!("{base}/main/"),
    ] {
        assert!(target_problem(&bad).is_some(), "{bad} should be refused");
    }
}

#[test]
fn every_redirect_target_is_a_file_of_this_repo() {
    let pairs = redirects();
    assert!(!pairs.is_empty(), "docs/redirects.txt has no redirect");
    for (from, to) in pairs {
        if let Some(problem) = target_problem(&to) {
            panic!("redirect {from} targets {to}: {problem}");
        }
        let rest = to
            .split_once("/blob/")
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        let (_ref, path) = rest.split_once('/').unwrap_or_default();
        assert!(
            repo_root().join(path).is_file(),
            "redirect {from} points at {path}, which is not a file in this repo"
        );
    }
}

/// Every markdown link target `](target)` in `text`, as written.
fn link_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("](") {
        rest = &rest[at + 2..];
        if let Some(end) = rest.find(')') {
            targets.push(rest[..end].to_owned());
        }
    }
    targets
}

/// The markdown files under `dir`, found without a dependency.
fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            markdown_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
}

#[test]
fn relative_links_in_published_pages_resolve_and_no_link_is_root_relative() {
    let mut pages = Vec::new();
    markdown_files(&repo_root().join("docs/src/content/docs"), &mut pages);
    assert!(!pages.is_empty(), "no published pages found");
    let mut problems = Vec::new();
    for page in &pages {
        let text = fs::read_to_string(page).unwrap_or_default();
        let dir = page.parent().unwrap_or(Path::new("."));
        for target in link_targets(&text) {
            if target.starts_with("http")
                || target.starts_with('#')
                || target.starts_with("mailto:")
            {
                continue;
            }
            // M1 pages use relative links. Starlight (M3) takes root-relative ones. Convert then.
            if target.starts_with('/') {
                problems.push(format!("{}: {target} is root-relative", page.display()));
                continue;
            }
            let file = target.split('#').next().unwrap_or_default();
            if !dir.join(file).is_file() {
                problems.push(format!("{}: {target} does not resolve", page.display()));
            }
        }
    }
    assert!(problems.is_empty(), "broken links: {problems:#?}");
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
        "Do not delete or rename the `.minisig` file",
    ] {
        assert!(page.contains(needle), "the unsigned page lacks {needle:?}");
    }
}

/// The `rdy` command lines in the `sh` blocks of `page`, as written, and the `rdy` lines of any other
/// fence. A fence is open from its line to the next line that is exactly three backticks. An opening
/// fence whose info string is not exactly `sh` is not run by any test, so its `rdy` lines come back
/// as the second list and fail the test.
fn page_commands(page: &str) -> (Vec<String>, Vec<String>) {
    let mut run = Vec::new();
    let mut not_run = Vec::new();
    // None outside a fence. Some(true) inside an `sh` fence, Some(false) inside any other.
    let mut fence: Option<bool> = None;
    for line in page.lines() {
        match fence {
            Some(_) if line == "```" => fence = None,
            Some(is_sh) => {
                if line.starts_with("rdy ") {
                    if is_sh {
                        run.push(line.to_owned());
                    } else {
                        not_run.push(line.to_owned());
                    }
                }
            }
            None => {
                if let Some(info) = line.strip_prefix("```") {
                    fence = Some(info == "sh");
                }
            }
        }
    }
    (run, not_run)
}

#[test]
fn sign_and_verify_page_runs_every_command_it_shows() {
    let page = read("docs/src/content/docs/specs/signing.md");
    let (commands, not_run) = page_commands(&page);
    assert!(
        not_run.is_empty(),
        "these rdy lines are in a fence that is not exactly `sh`, so no test runs them: {not_run:?}"
    );
    assert!(
        commands.len() >= 4,
        "the page shows the keygen, sign, verify and trust commands: {commands:?}"
    );
    let tests = read("crates/rdy-cli/tests/sign_verify_page.rs");
    for command in &commands {
        // The test file holds each page command as the literal it runs. A page line with no test is
        // a command nobody runs.
        assert!(
            tests.contains(&format!("\"{command}\"")),
            "the page shows `{command}`, but crates/rdy-cli/tests/sign_verify_page.rs does not run it"
        );
    }
}

#[test]
fn sign_verify_and_unsigned_pages_say_to_compare_the_full_fingerprint() {
    // SF-02 (signing review, M1-132): the banner shows 48 bits, which a key can be ground to match.
    for path in [
        "docs/src/content/docs/specs/signing.md",
        "docs/src/content/docs/unsigned.md",
    ] {
        let page = read(path);
        for needle in [
            "Compare the full fingerprint",
            "Do not compare the short fingerprint in the `KEY NOT PINNED` banner",
        ] {
            assert!(page.contains(needle), "{path} lacks {needle:?}");
        }
    }
}
