//! The lint wall (M1-044, INV-07, ADR 0014 decision 7, 02 Appendix A).
//!
//! Two kinds of proof:
//!
//! 1. Drift tests read the clippy.toml files. The root list is repeated in every check crate, the check
//!    crates carry one wall (k8s adds the kube entries), a new `crates/rdy-checks-*` directory must carry
//!    it too, and no entry is a wildcard.
//! 2. `every_entry_fails_clippy` runs `cargo clippy` over `src/uses.rs`, which uses each item once. It runs
//!    once under the root clippy.toml and once under each check crate's, through `CLIPPY_CONF_DIR`, and
//!    expects every entry of that file to be reported and the run to fail.
//!
//! The kube entries are not proven here. Their use file is
//! `crates/rdy-checks-k8s/lint-wall/kube-use.rs.txt` and M1-107 carries the proof (backlog correction-11).
//!
//! OS: the Unix-only and Windows-only entries are proven on the legs where their paths exist, and
//! `uses.rs` carries the `cfg` for each. Every other entry is proven on all five legs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Entry, Kind, check_crates, entries, name, root};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// Entries whose item does not exist yet, so no use can name it. Each has a ticket that adds the use.
/// `pending_entries_still_do_not_exist` fails when the item appears, so this list cannot go stale.
const PENDING: &[(&str, &str)] = &[("rdy_engine::live_backend", "M1-045")];

/// The three runners and the test helper the exit test names. Every check crate must list them.
const ENGINE_ENTRIES: &[&str] = &[
    "rdy_engine::exec::table::run",
    "rdy_engine::exec::run",
    "rdy_engine::exec::ExecSpec::new",
    "rdy_engine::testing::TestRun::context",
    "rdy_engine::live_backend",
];

fn paths(entries: &[Entry]) -> BTreeSet<&str> {
    entries.iter().map(|e| e.path.as_str()).collect()
}

fn wall_of(dir: &Path) -> Vec<Entry> {
    entries(&dir.join("clippy.toml"))
}

fn is_kube(e: &Entry) -> bool {
    e.path.starts_with("kube::")
}

#[test]
fn every_check_crate_has_a_clippy_toml_with_the_test_settings() {
    for dir in check_crates() {
        let text = std::fs::read_to_string(dir.join("clippy.toml"))
            .unwrap_or_else(|e| panic!("{}: no clippy.toml: {e}", name(&dir)));
        for setting in [
            "allow-unwrap-in-tests = true",
            "allow-expect-in-tests = true",
        ] {
            assert!(
                text.contains(setting),
                "{}: missing `{setting}`",
                name(&dir)
            );
        }
    }
}

#[test]
fn no_entry_is_a_wildcard_and_none_is_listed_twice() {
    let mut files = check_crates();
    files.push(root());
    for dir in files {
        let list = wall_of(&dir);
        let mut seen = BTreeSet::new();
        for e in &list {
            assert!(
                !e.path.contains('*') && !e.path.contains('?'),
                "{}: `{}` is a wildcard; clippy matches exact paths",
                dir.display(),
                e.path
            );
            assert!(
                seen.insert((e.kind, &e.path)),
                "{}: `{}` is listed twice; clippy matches the item, so a second path to it is never reported",
                dir.display(),
                e.path
            );
        }
    }
}

#[test]
fn every_check_crate_repeats_every_root_entry() {
    let root_list = wall_of(&root());
    assert!(
        !root_list.is_empty(),
        "the root clippy.toml has no entries?"
    );
    for dir in check_crates() {
        let own = wall_of(&dir);
        for e in &root_list {
            assert!(
                own.iter().any(|o| o.kind == e.kind && o.path == e.path),
                "{}/clippy.toml is missing the root entry `{}`: a crate file replaces the root file, so copy it (with `allow-invalid = true` if the crate does not depend on the crate it names)",
                name(&dir),
                e.path
            );
        }
    }
}

#[test]
fn every_check_crate_carries_the_same_wall() {
    let crates = check_crates();
    let host = wall_of(
        crates
            .iter()
            .find(|d| name(d) == "rdy-checks-host")
            .expect("rdy-checks-host"),
    );
    let host_set: BTreeSet<&Entry> = host.iter().filter(|e| !is_kube(e)).collect();
    assert!(
        host.iter().all(|e| !is_kube(e)),
        "the host crate lists a kube entry: only rdy-checks-k8s may (02 Appendix A)"
    );
    for dir in &crates {
        let own = wall_of(dir);
        // The root entries are in the host file too, so this compares whole lists less the kube entries.
        let own_set: BTreeSet<&Entry> = own.iter().filter(|e| !is_kube(e)).collect();
        assert_eq!(
            own_set,
            host_set,
            "{}/clippy.toml differs from rdy-checks-host/clippy.toml: the check crates carry one wall; edit them together",
            name(dir)
        );
        if name(dir) != "rdy-checks-k8s" {
            assert!(
                own.iter().all(|e| !is_kube(e)),
                "{}: only rdy-checks-k8s lists kube entries",
                name(dir)
            );
        }
    }
}

#[test]
fn the_engine_runners_are_on_every_check_crate_deny_list() {
    // The exit test of M1-044 (PR #53 review, PR #58 C1) names these.
    for dir in check_crates() {
        let list = wall_of(&dir);
        for want in ENGINE_ENTRIES {
            assert!(
                list.iter()
                    .any(|e| e.kind == Kind::Method && e.path == *want),
                "{}/clippy.toml does not list `{want}` in disallowed-methods",
                name(&dir)
            );
        }
    }
}

#[test]
fn std_io_escapes_are_on_every_check_crate_deny_list() {
    for dir in check_crates() {
        let list = wall_of(&dir);
        for (kind, want) in [
            (Kind::Method, "std::io::stdout"),
            (Kind::Method, "std::io::stderr"),
            (Kind::Method, "std::io::stdin"),
            (Kind::Macro, "std::print"),
            (Kind::Macro, "std::println"),
            (Kind::Macro, "std::eprint"),
            (Kind::Macro, "std::eprintln"),
        ] {
            assert!(
                list.iter().any(|e| e.kind == kind && e.path == want),
                "{}/clippy.toml does not list `{want}`",
                name(&dir)
            );
        }
    }
}

#[test]
fn pending_entries_still_do_not_exist() {
    for (path, ticket) in PENDING {
        let (_, item) = path.rsplit_once("::").expect("a path");
        let defined = std::fs::read_dir(root().join("crates/rdy-engine/src"))
            .expect("engine src")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .any(|p| {
                let text = std::fs::read_to_string(&p).expect("read");
                text.contains(&format!("pub fn {item}"))
            });
        assert!(
            !defined,
            "`{path}` exists now. Add its use to tests/lint-wall/src/uses.rs and delete it from PENDING ({ticket})"
        );
    }
}

/// What clippy said about the fixture.
struct Run {
    succeeded: bool,
    /// Every path named by a `disallowed_*` report.
    reported: BTreeSet<String>,
    /// Any other warning or error, which means the fixture or a clippy.toml is broken.
    stray: Vec<String>,
}

fn clippy_over_uses(conf_dir: &Path) -> Run {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(root())
        .env("CLIPPY_CONF_DIR", conf_dir)
        // The test job may set flags for the test build. The nested check build takes its own.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args([
            "clippy",
            "--locked",
            "--package",
            "rdy-lint-wall",
            // Lint the fixture only. The path dependencies would be linted under this clippy.toml too.
            "--no-deps",
            "--features",
            "use-all",
            "--message-format=json",
            "--",
            "-D",
            "warnings",
        ])
        .output()
        .expect("start cargo clippy");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut reported = BTreeSet::new();
    let mut stray = Vec::new();
    for line in stdout.lines().filter(|l| l.starts_with('{')) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value["reason"] != "compiler-message" {
            continue;
        }
        let message = &value["message"];
        let text = message["message"].as_str().unwrap_or_default();
        let code = message["code"]["code"].as_str().unwrap_or_default();
        if matches!(
            code,
            "clippy::disallowed_methods" | "clippy::disallowed_types" | "clippy::disallowed_macros"
        ) {
            // "use of a disallowed method `std::fs::read`"
            let path = text.split('`').nth(1).unwrap_or(text);
            reported.insert(path.to_owned());
        } else if !text.starts_with("aborting due to") && !text.contains("previous error") {
            stray.push(message["rendered"].as_str().unwrap_or(text).to_owned());
        }
    }
    Run {
        succeeded: output.status.success(),
        reported,
        stray,
    }
}

/// The entries of `dir` that `uses.rs` can use on this OS.
fn provable(list: &[Entry]) -> Vec<&Entry> {
    list.iter()
        .filter(|e| !is_kube(e))
        .filter(|e| PENDING.iter().all(|(p, _)| e.path != *p))
        .filter(|e| cfg!(unix) || !e.path.starts_with("std::os::unix::"))
        .filter(|e| cfg!(windows) || !e.path.starts_with("std::os::windows::"))
        .collect()
}

#[test]
fn every_entry_fails_clippy() {
    // The root file first, then every check crate. Each run changes CLIPPY_CONF_DIR, which cargo tracks,
    // so clippy looks at the fixture again every time. After the first run the dependencies are built.
    let mut dirs = vec![root()];
    dirs.extend(check_crates());
    let mut failures = Vec::new();
    for dir in dirs {
        let label = if dir == root() {
            "the root clippy.toml".to_owned()
        } else {
            format!("{}/clippy.toml", name(&dir))
        };
        let list = wall_of(&dir);
        let want = provable(&list);
        assert!(!want.is_empty(), "{label}: nothing to prove?");
        let run = clippy_over_uses(&dir);
        if run.succeeded {
            failures.push(format!(
                "{label}: clippy passed over uses.rs, but every use must fail"
            ));
        }
        for e in &want {
            if !run.reported.contains(&e.path) {
                failures.push(format!(
                    "{label}: `{}` was not reported. Is its use in tests/lint-wall/src/uses.rs, and is the path right?",
                    e.path
                ));
            }
        }
        // A path that clippy cannot find gives a warning with the path in it. The wall must not rot.
        for s in &run.stray {
            failures.push(format!("{label}: stray clippy output:\n{s}"));
        }
        // Everything reported is an entry of the file (the fixture uses items of the other files too, and
        // under this file they must not be reported, or the file would be wider than it says).
        let known = paths(&list);
        for r in &run.reported {
            if !known.contains(r.as_str()) {
                failures.push(format!(
                    "{label}: reported `{r}`, which is not one of its entries"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
