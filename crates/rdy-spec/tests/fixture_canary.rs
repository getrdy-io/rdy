//! The Windows line-ending canary (M1-047, docs/plan/08-testing.md, "Windows checkouts").
//!
//! A default Windows checkout rewrites LF to CRLF. That breaks a signed spec, because the signature covers
//! the raw bytes, and it would silently change any fixture that must stay as recorded. The `windows-x64`
//! leg of CI sets `core.autocrlf true` before checkout. These tests then prove, on every leg, that:
//!
//! - git reports the `text` attribute as `unset` for the fixtures, so it converts nothing;
//! - the signed fixture files and one fixture that must carry CRLF match digests committed here.
//!
//! The digests change only if a fixture is deliberately replaced. Do not update them to make a red leg
//! green: a red Windows leg means `.gitattributes` or the checkout is wrong.
//!
//! Helpers in this file avoid `unwrap` and `expect` because clippy only allows them inside `#[test]`
//! functions.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

/// Files that git must never convert, with the SHA-256 of their exact bytes.
const PINNED: &[(&str, &str)] = &[
    (
        "tests/fixtures/signed/acme-platform.yaml",
        "231d161afdf97fb9aa5a2ea3cfbd3f4645249d218e9aaefe3f4000dc598d0d4f",
    ),
    (
        "tests/fixtures/signed/acme-platform.yaml.minisig",
        "9f5b8e978db5b8b2606b745cd17403eb77f1c39ed15a11f38a733c8a3e9e25d4",
    ),
    (
        "tests/fixtures/signed/acme-platform.pub",
        "cdad852d19bea33f87893a0aef7ce2bb977eae3c155ffba6e433150cd93ddd78",
    ),
    // The one fixture that carries CRLF on purpose (recorded Windows console output).
    (
        "tests/fixtures/canary/netstat-crlf.txt",
        "31490dc642bb6e2e95b2c6a17b0d9cee2f9efa3a7c9e84ac99d20b68423c2bc1",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in Sha256::digest(bytes) {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Run `git` in the repo root and return stdout. A missing git is a loud failure, not a skip.
fn git(args: &[&str]) -> String {
    let output = match Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .args(args)
        .output()
    {
        Ok(output) => output,
        Err(e) => panic!("cannot run git (it must be on PATH): {e}"),
    };
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The value git reports for one attribute of one path, for example `unset`, `set` or `lf`.
fn attr(name: &str, path: &str) -> String {
    let out = git(&["check-attr", name, "--", path]);
    let prefix = format!("{path}: {name}: ");
    match out.trim_end().strip_prefix(&prefix) {
        Some(value) => value.to_owned(),
        None => panic!("unexpected check-attr output: {out:?}"),
    }
}

#[test]
fn pinned_files_match_their_committed_digests() {
    for (path, digest) in PINNED {
        let full = repo_root().join(path);
        let bytes = match std::fs::read(&full) {
            Ok(bytes) => bytes,
            Err(e) => panic!("cannot read {}: {e}", full.display()),
        };
        assert_eq!(
            sha256_hex(&bytes).as_str(),
            *digest,
            "{path} changed on disk. Check .gitattributes and core.autocrlf before touching the digest"
        );
    }
}

#[test]
fn the_crlf_fixture_keeps_its_crlf() {
    let full = repo_root().join("tests/fixtures/canary/netstat-crlf.txt");
    let bytes = match std::fs::read(&full) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read {}: {e}", full.display()),
    };
    let lf = bytes.iter().filter(|b| **b == b'\n').count();
    let crlf = bytes.windows(2).filter(|w| *w == b"\r\n").count();
    assert!(lf > 0, "the canary has no line breaks");
    assert_eq!(lf, crlf, "every LF in the canary must follow a CR");
}

#[test]
fn git_converts_nothing_under_tests_fixtures() {
    let mut paths: Vec<&str> = PINNED.iter().map(|(path, _)| *path).collect();
    // Other fixtures too, including ones that do not exist yet: check-attr only reads the rules.
    paths.extend([
        "tests/fixtures/wycheproof/ed25519_test.json",
        "tests/fixtures/specs/malformed/nan.yaml",
        "tests/fixtures/checks/host.memory/pass/root/proc/meminfo",
        "tests/fixtures/envs/all-pass/golden/report.html",
    ]);
    for path in paths {
        assert_eq!(attr("text", path), "unset", "text attribute of {path}");
    }
}

#[test]
fn the_other_rules_of_gitattributes_hold() {
    assert_eq!(attr("text", "elsewhere/x.minisig"), "unset");
    for path in [
        "examples/specs/acme-platform.yaml",
        "crates/rdy-engine/templates/report.html",
        "crates/rdy-engine/data/agents.toml",
        "crates/rdy-cli/tests/snapshots/help.txt",
        "docs/plan/08-testing.md",
    ] {
        assert_eq!(attr("eol", path), "lf", "eol attribute of {path}");
        assert_ne!(attr("text", path), "unset", "text attribute of {path}");
    }
}

/// Without this, the canary proves nothing on the Windows leg. CI sets the option before checkout.
#[cfg(windows)]
#[test]
fn the_windows_ci_leg_runs_with_autocrlf_true() {
    if std::env::var_os("CI").is_none() {
        return;
    }
    assert_eq!(
        git(&["config", "--get", "core.autocrlf"]).trim(),
        "true",
        "ci.yml must run `git config --global core.autocrlf true` before checkout on windows"
    );
}
