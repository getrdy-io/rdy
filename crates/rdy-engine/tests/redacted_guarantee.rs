//! Proves that code outside the crate cannot build a `Redacted` value or get one from raw text.
//!
//! Each file in `compile_fail/` must fail to compile, and its `.stderr` file records the exact error. A
//! rustdoc `compile_fail` test would not do alone, because stable rustdoc does not check the error code,
//! so a typo in such a test would pass for the wrong reason.
//!
//! The `.stderr` text depends on the compiler, so the test runs only on the toolchain pinned in
//! `rust-toolchain.toml`. On any other rustc it prints a skip message and passes, except when the `CI`
//! environment variable is set: CI always runs the pinned toolchain, so a skip there is a failure. The unit tests in
//! `src/redact` and the pinned CI toolchain still cover the guarantee. After a toolchain bump, refresh
//! the `.stderr` files with `TRYBUILD=overwrite` and read the diff.

use std::path::Path;
use std::process::Command;

/// The `channel` line of the workspace `rust-toolchain.toml`.
fn pinned_channel() -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust-toolchain.toml");
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_owned())
    })
}

/// The first line of `rustc -V`, for example `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
fn running_rustc() -> Option<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let out = Command::new(rustc).arg("-V").output().ok()?;
    String::from_utf8(out.stdout).ok()
}

/// Reports a skipped run. On CI a skip fails the test, so a toolchain mismatch cannot hide the check.
fn skip(reason: &str) {
    assert!(
        std::env::var_os("CI").is_none(),
        "the compile-fail check must run on CI, but it was skipped: {reason}"
    );
    eprintln!("SKIPPED: {reason}");
}

#[test]
fn redacted_cannot_be_built_outside_the_redactor() {
    let (Some(pinned), Some(running)) = (pinned_channel(), running_rustc()) else {
        skip(
            "cannot read rust-toolchain.toml or run rustc, so the compile-fail snapshots are not checked",
        );
        return;
    };
    if !running.starts_with(&format!("rustc {pinned} ")) {
        skip(&format!(
            "the compile-fail snapshots are for rustc {pinned}, but this is `{}`",
            running.trim()
        ));
        return;
    }
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
}
