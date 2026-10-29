//! The allow grep (M1-044, INV-07, ADR 0014 decision 7).
//!
//! `allow(clippy::disallowed_..)` is legal only in the facade's `live/` module and the k8s client module.
//! This test reads every `.rs` file of the workspace, and fails on a lint attribute that names a
//! `disallowed_*` lint (or a group that holds one) in a file that is not on the list below. A line of a
//! comment does not count. To add a place, edit the list in this file. `/tests/lint-wall/` is in CODEOWNERS,
//! so the change gets the security review.
//!
//! The check crates get no exemption for tests, except the client tests of `rdy-checks-k8s`, which start
//! mock servers and write kubeconfigs. A test of a check uses `TestRun`, not the machine.
//!
//! The grep also fails a check crate whose Cargo.toml turns the lint off with a `[lints.clippy]` table or
//! leaves the workspace lints, because that has the same effect.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{check_crates, name, root};
use std::path::{Path, PathBuf};

/// Where an attribute naming a disallowed lint is legal. Paths are relative to the workspace root, with
/// `/` separators. A path that ends in `/` is a directory prefix.
const ALLOWED: &[(&str, &str)] = &[
    // The two places the rule names.
    (
        "crates/rdy-checks-k8s/src/client/",
        "the k8s client module builds the one guarded kube client (ADR 0010, ADR 0031)",
    ),
    (
        "crates/rdy-engine/src/probe/live/",
        "the facade's live backend, M1-045 (ADR 0014); the directory does not exist yet",
    ),
    // The client module's integration tests.
    (
        "crates/rdy-checks-k8s/tests/client.rs",
        "tests of the client module: a mock API server, kubeconfig files, plugin scripts",
    ),
    (
        "crates/rdy-checks-k8s/tests/tls.rs",
        "tests of the client module: a TLS server with a throwaway CA",
    ),
    (
        "crates/rdy-checks-k8s/tests/live_cluster.rs",
        "the ignored kind test of the client module (M1-108)",
    ),
    (
        "crates/rdy-checks-k8s/tests/common/mod.rs",
        "helpers of the client module tests",
    ),
    // Outside the check crates the wall is the root list (clap, the clock, the raw runners). These files
    // call those on purpose, and each says why in its own words.
    (
        "crates/rdy-engine/src/probe.rs",
        "the one call of exec::table::run, in the probe spawn (ADR 0014, ADR 0028)",
    ),
    (
        "crates/rdy-engine/src/exec/policy.rs",
        "the tests of the policy call the raw runner",
    ),
    (
        "crates/rdy-engine/src/exec/runner/tests.rs",
        "the tests of the raw runner",
    ),
    (
        "crates/rdy-engine/src/exec/table/tests.rs",
        "the tests of the table runner",
    ),
    (
        "crates/rdy-engine/tests/exit_bound.rs",
        "an integration test of the raw runner",
    ),
    (
        "crates/rdy-engine/tests/sigchld_ignored.rs",
        "an integration test of the raw runner",
    ),
    (
        "crates/rdy-spec/tests/semantic_limits.rs",
        "a test that pins the clock with load_at",
    ),
    (
        "crates/xtask/src/main.rs",
        "xtask is a repo tool, not the `rdy` binary: it prints clap's own usage error",
    ),
];

/// Lints that cover `disallowed_*`: the three lints, and the groups that include them.
const COVERING: &[&str] = &[
    "clippy::disallowed_",
    "clippy::all",
    "clippy::style",
    "warnings",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // Build output and the vendored trees are not source.
            if file_name != "target" && !file_name.starts_with('.') {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// Whether a line is a lint attribute that silences or relaxes a lint it names. It sees `allow(`,
/// `expect(`, `warn(` and `cfg_attr(.., allow(..))`, and it skips comment lines. `deny` and `forbid`
/// tighten, so they pass.
fn relaxes_a_disallowed_lint(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") {
        return false;
    }
    let relaxes = ["allow(", "expect(", "warn("].iter().any(|a| t.contains(a));
    relaxes && COVERING.iter().any(|c| t.contains(c))
}

/// An attribute can span lines. Join each `#[..]` or `#![..]` into one string before looking.
fn attributes(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut open: Option<String> = None;
    for line in text.lines() {
        let t = line.trim_start();
        if open.is_none() && (t.starts_with("#[") || t.starts_with("#![")) {
            open = Some(String::new());
        }
        if let Some(buf) = open.as_mut() {
            buf.push_str(t);
            buf.push(' ');
            if t.trim_end().ends_with(']') {
                out.push(open.take().expect("open"));
            }
        }
    }
    out
}

fn allowed(relative: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(p, _)| relative == *p || (p.ends_with('/') && relative.starts_with(p)))
}

#[test]
fn an_allow_of_a_disallowed_lint_is_only_in_the_allowlisted_files() {
    let base = root();
    let mut files = Vec::new();
    rust_files(&base.join("crates"), &mut files);
    rust_files(&base.join("tests"), &mut files);
    assert!(files.len() > 50, "found only {} source files", files.len());
    let mut bad = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(&base)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).expect("read source");
        let hit = attributes(&text)
            .iter()
            .any(|a| relaxes_a_disallowed_lint(a));
        if hit && !allowed(&relative) {
            bad.push(relative);
        }
    }
    assert!(
        bad.is_empty(),
        "these files relax a disallowed_* lint and are not on the list in tests/lint-wall/tests/allow_grep.rs: {bad:#?}\nA check reaches the machine through its Probe. Do not allow the lint; use the facade."
    );
}

#[test]
fn every_allowlisted_file_still_exists_and_still_needs_the_allow() {
    // A stale entry is a hole nobody notices. `live/` does not exist yet.
    let base = root();
    for (path, why) in ALLOWED {
        if path.ends_with("probe/live/") {
            continue;
        }
        let full = base.join(path);
        assert!(
            full.exists(),
            "{path} is on the allowlist but missing ({why})"
        );
        let mut files = Vec::new();
        if full.is_dir() {
            rust_files(&full, &mut files);
        } else {
            files.push(full);
        }
        let used = files.iter().any(|f| {
            let text = std::fs::read_to_string(f).expect("read source");
            attributes(&text)
                .iter()
                .any(|a| relaxes_a_disallowed_lint(a))
        });
        assert!(
            used,
            "{path} is on the allowlist but no longer relaxes a disallowed_* lint: remove it from the list ({why})"
        );
    }
}

#[test]
fn the_grep_sees_the_forms_it_must() {
    for hit in [
        "#[allow(clippy::disallowed_methods)]",
        "#![allow(clippy::disallowed_types, clippy::disallowed_methods)]",
        "#[expect(clippy::disallowed_macros)]",
        "#[cfg_attr(test, allow(clippy::disallowed_methods))]",
        "#![allow(clippy::all)]",
        "#![allow(warnings)]",
        "#[allow(\n    clippy::disallowed_methods,\n    clippy::expect_used\n)]",
    ] {
        let found = attributes(hit).iter().any(|a| relaxes_a_disallowed_lint(a));
        assert!(found, "the grep missed: {hit}");
    }
    for miss in [
        "// #[allow(clippy::disallowed_methods)]",
        "#![allow(clippy::expect_used)]",
        "#![deny(clippy::disallowed_methods)]",
        "#![forbid(unsafe_code)]",
    ] {
        let found = attributes(miss)
            .iter()
            .any(|a| relaxes_a_disallowed_lint(a));
        assert!(!found, "the grep flagged: {miss}");
    }
}

#[test]
fn a_check_crate_keeps_the_workspace_lints() {
    for dir in check_crates() {
        let text = std::fs::read_to_string(dir.join("Cargo.toml")).expect("Cargo.toml");
        assert!(
            text.contains("[lints]\nworkspace = true"),
            "{}: Cargo.toml must have `[lints]` with `workspace = true`",
            name(&dir)
        );
        assert!(
            !text.contains("[lints."),
            "{}: Cargo.toml has a `[lints.*]` table; a check crate takes the workspace lints as they are",
            name(&dir)
        );
    }
}
