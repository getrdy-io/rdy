//! The deny wrappers (M1-044, INV-07, 02 "Lint wall").
//!
//! `deny.toml` keeps `socket2`, `walkdir` and the other crates of the wall out of the check crates. This
//! test builds a small throwaway workspace whose crates have the names of the real ones (`rdy-checks-host`,
//! `socket2`, `walkdir`, `tokio`), runs the real deny.toml over it with `cargo deny check bans`, and
//! expects:
//!
//! - a check crate that depends on `socket2` or `walkdir`, as a normal or a dev dependency, fails;
//! - `tokio` depending on `socket2` passes, so the wrappers are not a blanket ban and the failures above
//!   are caused by the wall and not by something else in the throwaway workspace.
//!
//! The throwaway workspace has only path crates, so the test needs no network.
//!
//! Needs the `cargo-deny` binary. A machine without it skips the test with a message, except where
//! `RDY_REQUIRE_CARGO_DENY` is set, which makes a missing binary a failure. The `deny` job of ci.yml sets
//! it and runs this test, and the same job runs `cargo deny check` over the real tree.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::root;
use std::path::{Path, PathBuf};
use std::process::Command;

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn have_cargo_deny() -> bool {
    let ok = Command::new(cargo())
        .args(["deny", "--version"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(
            std::env::var_os("RDY_REQUIRE_CARGO_DENY").is_none(),
            "RDY_REQUIRE_CARGO_DENY is set and `cargo deny` is not installed"
        );
        eprintln!("SKIPPED: `cargo deny` is not installed (the deny job of CI runs this test)");
    }
    ok
}

/// One crate of the throwaway workspace.
struct Krate<'a> {
    name: &'a str,
    deps: &'a [&'a str],
    dev_deps: &'a [&'a str],
}

/// Writes a workspace of `crates` under the target tmp dir and returns its manifest path.
fn workspace(case: &str, crates: &[Krate<'_>]) -> PathBuf {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("deny-wrappers")
        .join(case);
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create the case dir");
    let members: Vec<String> = crates.iter().map(|k| format!("\"{}\"", k.name)).collect();
    std::fs::write(
        base.join("Cargo.toml"),
        format!(
            "[workspace]\nmembers = [{}]\nresolver = \"3\"\n",
            members.join(", ")
        ),
    )
    .expect("write the workspace manifest");
    for k in crates {
        let dir = base.join(k.name);
        std::fs::create_dir_all(dir.join("src")).expect("create src");
        std::fs::write(dir.join("src/lib.rs"), "").expect("write lib.rs");
        let mut manifest = format!(
            "[package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n",
            k.name
        );
        manifest.push_str("\n[dependencies]\n");
        for d in k.deps {
            manifest.push_str(&format!("{d} = {{ path = \"../{d}\" }}\n"));
        }
        manifest.push_str("\n[dev-dependencies]\n");
        for d in k.dev_deps {
            manifest.push_str(&format!("{d} = {{ path = \"../{d}\" }}\n"));
        }
        std::fs::write(dir.join("Cargo.toml"), manifest).expect("write the crate manifest");
    }
    base.join("Cargo.toml")
}

/// Runs the real deny.toml's ban rules. Returns whether it passed and everything it printed.
fn deny_bans(manifest: &Path) -> (bool, String) {
    let out = Command::new(cargo())
        .args(["deny", "--color", "never", "--manifest-path"])
        .arg(manifest)
        .arg("--config")
        .arg(root().join("deny.toml"))
        .args(["check", "bans"])
        .output()
        .expect("start cargo deny");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn leaf(name: &str) -> Krate<'_> {
    Krate {
        name,
        deps: &[],
        dev_deps: &[],
    }
}

#[test]
fn a_check_crate_that_depends_on_a_walled_crate_fails_cargo_deny() {
    if !have_cargo_deny() {
        return;
    }
    // (case, banned crate, which check crate, normal deps, dev deps)
    for (case, banned, check_crate, dev) in [
        ("host-walkdir", "walkdir", "rdy-checks-host", false),
        ("host-walkdir-dev", "walkdir", "rdy-checks-host", true),
        ("net-socket2", "socket2", "rdy-checks-net", false),
        ("k8s-socket2-dev", "socket2", "rdy-checks-k8s", true),
        ("host-sysinfo", "sysinfo", "rdy-checks-host", false),
        ("host-nix", "nix", "rdy-checks-host", false),
        ("net-hyper", "hyper", "rdy-checks-net", false),
        ("net-rustix", "rustix", "rdy-checks-net", false),
        ("host-tempfile", "tempfile", "rdy-checks-host", false),
        ("net-tokio-rustls", "tokio-rustls", "rdy-checks-net", false),
    ] {
        let deps: &[&str] = if dev { &[] } else { &[banned] };
        let dev_deps: &[&str] = if dev { &[banned] } else { &[] };
        let manifest = workspace(
            case,
            &[
                leaf(banned),
                Krate {
                    name: check_crate,
                    deps,
                    dev_deps,
                },
            ],
        );
        let (passed, text) = deny_bans(&manifest);
        assert!(
            !passed,
            "{case}: {check_crate} depends on {banned} and cargo deny passed:\n{text}"
        );
        assert!(
            text.contains(&format!("crate '{banned} = 0.0.0' is explicitly banned")),
            "{case}: cargo deny failed, but not on the ban of {banned}:\n{text}"
        );
    }
}

#[test]
fn a_wrapper_may_depend_on_a_walled_crate() {
    if !have_cargo_deny() {
        return;
    }
    // tokio wraps socket2 and hyper-util wraps socket2 in the real tree. The control case: the same
    // throwaway layout passes when the parent is a wrapper, so the failures above come from the wall.
    let manifest = workspace(
        "control",
        &[
            leaf("socket2"),
            Krate {
                name: "tokio",
                deps: &["socket2"],
                dev_deps: &[],
            },
            Krate {
                name: "rdy-checks-host",
                deps: &["tokio"],
                dev_deps: &[],
            },
        ],
    );
    let (passed, text) = deny_bans(&manifest);
    assert!(passed, "a wrapper depending on socket2 must pass:\n{text}");
}

/// The `crate = ".."` and `wrappers = [..]` of each entry of the `deny` list.
fn deny_entries() -> Vec<(String, Vec<String>)> {
    let text = std::fs::read_to_string(root().join("deny.toml")).expect("deny.toml");
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || !t.starts_with("{ crate = \"") {
            continue;
        }
        let name = t["{ crate = \"".len()..]
            .split('"')
            .next()
            .expect("name")
            .to_owned();
        let wrappers = t
            .split_once("wrappers = [")
            .map(|(_, rest)| rest.split(']').next().expect("closing bracket"))
            .map(|list| {
                list.split(',')
                    .map(|w| w.trim().trim_matches('"').to_owned())
                    .filter(|w| !w.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        out.push((name, wrappers));
    }
    out
}

#[test]
fn no_wrapper_is_a_check_crate_except_the_named_dev_dependency_exceptions() {
    // Reading deny.toml needs no cargo-deny, so this runs everywhere. A check crate in a wrapper list
    // would let it depend on the banned crate. The two exceptions are the test-only dev-dependencies of
    // rdy-checks-k8s that deny.toml explains.
    const EXCEPTIONS: &[(&str, &str)] = &[
        ("tempfile", "rdy-checks-k8s"),
        ("tokio-rustls", "rdy-checks-k8s"),
    ];
    let entries = deny_entries();
    assert!(
        entries.len() > 20,
        "found only {} deny entries",
        entries.len()
    );
    for (banned, wrappers) in &entries {
        for w in wrappers {
            if w.starts_with("rdy-checks-") {
                assert!(
                    EXCEPTIONS.contains(&(banned.as_str(), w.as_str())) || banned == "kube",
                    "deny.toml lets {w} depend on {banned}: no check crate may be a wrapper (02 Lint wall)"
                );
            }
        }
    }
}

#[test]
fn the_wall_crates_the_exit_test_names_are_banned() {
    let entries = deny_entries();
    for want in ["socket2", "walkdir"] {
        assert!(
            entries.iter().any(|(n, _)| n == want),
            "deny.toml does not ban {want}"
        );
        let (_, wrappers) = entries.iter().find(|(n, _)| n == want).expect("entry");
        assert!(
            wrappers.iter().all(|w| !w.starts_with("rdy-checks-")),
            "{want} has a check crate as a wrapper"
        );
    }
}
