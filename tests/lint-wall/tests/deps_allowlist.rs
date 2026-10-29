//! The direct dependency allowlist of the check crates (M1-044, INV-07, 02 "Lint wall").
//!
//! `ci/check-crate-deps.toml` lists the crates each `rdy-checks-*` crate may depend on. These tests read
//! `cargo metadata` and fail on any direct normal or build dependency that is not listed. Clippy cannot
//! ban another crate's API, and deny's wrappers only decide who may depend on a few named crates, so this
//! allowlist is what keeps `tokio::fs`, `cap_std`, `TcpSocket` and the rest out of a check.
//!
//! The file is read by hand, so its layout is rigid: `[crate]`, then one `allow = [..]` line.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::root;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

/// Crates that no allowlist may name, because their APIs reach the machine. The same set as the walled
/// crates of deny.toml, and the ones the reviewers found open (tokio, cap-std, rustix, hyper-util).
const NEVER: &[&str] = &[
    "tokio",
    "cap-std",
    "cap-primitives",
    "rustix",
    "rustix-linux-procfs",
    "nix",
    "libc",
    "socket2",
    "hyper",
    "hyper-util",
    "hyper-rustls",
    "walkdir",
    "tempfile",
    "tokio-rustls",
    "sysinfo",
    "which",
    "ureq",
    "reqwest",
    "hickory-resolver",
    "hickory-proto",
    "hickory-client",
    "hickory-net",
    "rdy",
];

/// A direct dependency as `cargo metadata` reports it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Dep {
    name: String,
    /// `normal`, `dev` or `build`.
    kind: String,
}

fn allowlist() -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(root().join("ci/check-crate-deps.toml"))
        .expect("ci/check-crate-deps.toml");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(section) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            assert!(
                out.insert(section.to_owned(), BTreeSet::new()).is_none(),
                "check-crate-deps.toml:{}: section [{section}] twice",
                n + 1
            );
            current = Some(section.to_owned());
        } else if let Some(list) = t
            .strip_prefix("allow = [")
            .and_then(|r| r.strip_suffix(']'))
        {
            let crate_name = current.clone().expect("an allow line outside a section");
            let names: Vec<String> = list
                .split(',')
                .map(|w| w.trim().trim_matches('"').to_owned())
                .filter(|w| !w.is_empty())
                .collect();
            let mut sorted = names.clone();
            sorted.sort();
            assert_eq!(
                names,
                sorted,
                "check-crate-deps.toml:{}: keep the list sorted",
                n + 1
            );
            out.get_mut(&crate_name).expect("section").extend(names);
        } else {
            panic!(
                "check-crate-deps.toml:{}: unexpected line `{t}` (a section, or one `allow = [..]` line)",
                n + 1
            );
        }
    }
    out
}

/// The direct dependencies of every `rdy-checks-*` package, from `cargo metadata --no-deps`.
fn check_crate_deps() -> BTreeMap<String, Vec<Dep>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(root())
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .expect("start cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata json");
    let mut result = BTreeMap::new();
    for pkg in meta["packages"].as_array().expect("packages") {
        let name = pkg["name"].as_str().expect("name");
        if !name.starts_with("rdy-checks-") {
            continue;
        }
        let deps = pkg["dependencies"]
            .as_array()
            .expect("dependencies")
            .iter()
            .map(|d| Dep {
                name: d["name"].as_str().expect("dep name").to_owned(),
                kind: d["kind"].as_str().unwrap_or("normal").to_owned(),
            })
            .collect();
        result.insert(name.to_owned(), deps);
    }
    result
}

#[test]
fn a_check_crate_depends_only_on_what_the_allowlist_says() {
    let allow = allowlist();
    let crates = check_crate_deps();
    assert!(crates.len() >= 3, "found {:?}", crates.keys());
    let mut failures = Vec::new();
    for (name, deps) in &crates {
        let Some(allowed) = allow.get(name) else {
            failures.push(format!(
                "{name} has no section in ci/check-crate-deps.toml: add one (needs the security-review label)"
            ));
            continue;
        };
        for d in deps.iter().filter(|d| d.kind != "dev") {
            if !allowed.contains(&d.name) {
                failures.push(format!(
                    "{name} depends on `{}` ({}), which ci/check-crate-deps.toml does not list for it. A check reaches the machine through its Probe; if the crate is not an API to the machine, add it to the file with the security-review label",
                    d.name, d.kind
                ));
            }
        }
    }
    for name in allow.keys() {
        if !crates.contains_key(name) {
            failures.push(format!(
                "ci/check-crate-deps.toml has a section for {name}, which is not a check crate"
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn the_allowlist_never_names_a_crate_that_reaches_the_machine() {
    for (name, allowed) in allowlist() {
        for never in NEVER {
            assert!(
                !allowed.contains(*never),
                "{name}: the allowlist names `{never}`; no check crate may depend on it"
            );
        }
    }
}

#[test]
fn only_the_k8s_crate_lists_the_kube_crates_and_only_net_lists_x509() {
    for (name, allowed) in allowlist() {
        for only_k8s in ["kube", "k8s-openapi"] {
            assert!(
                name == "rdy-checks-k8s" || !allowed.contains(only_k8s),
                "{name} lists {only_k8s}; only rdy-checks-k8s may (deny.toml, ADR 0031)"
            );
        }
        assert!(
            name == "rdy-checks-net" || !allowed.contains("x509-parser"),
            "{name} lists x509-parser; only rdy-checks-net may (02)"
        );
    }
}

#[test]
fn tempfile_and_tokio_rustls_are_dev_dependencies_of_the_k8s_crate_only() {
    // deny.toml lists rdy-checks-k8s as a wrapper of both, because deny cannot tell a dev-dependency from a
    // normal one. This is the check that tells them apart.
    for (name, deps) in check_crate_deps() {
        for d in deps
            .iter()
            .filter(|d| d.name == "tempfile" || d.name == "tokio-rustls")
        {
            assert!(
                name == "rdy-checks-k8s" && d.kind == "dev",
                "{name} has {} as a {} dependency; only rdy-checks-k8s may have it, and only as a dev-dependency",
                d.name,
                d.kind
            );
        }
    }
}
