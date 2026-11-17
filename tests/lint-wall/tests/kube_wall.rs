//! The kube entries of the lint wall (M1-107, ADR 0031, 02 Appendix A).
//!
//! `crates/rdy-checks-k8s/lint-wall/kube-use.rs.txt` uses each kube entry of `crates/rdy-checks-k8s/clippy.toml`
//! once, the trait routes and both re-export paths. This crate includes it as a module under its `use-kube`
//! feature. The test runs clippy over it under the k8s clippy.toml and expects:
//!
//! - every `// EXPECT` line to carry a `disallowed_*` report (on that line or the one before it, for a call that
//!   spans lines), so a use that stops being caught fails here;
//! - every kube entry of the file to be reported at least once, so an entry that nothing reaches fails here;
//! - nothing else: a path that does not exist makes clippy warn, and a warning is a stray here.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{entries, root};
use std::collections::BTreeSet;
use std::process::Command;

const USE_FILE: &str = "crates/rdy-checks-k8s/lint-wall/kube-use.rs.txt";

#[test]
fn every_kube_entry_fails_clippy() {
    let dir = root().join("crates/rdy-checks-k8s");
    let wanted: BTreeSet<String> = entries(&dir.join("clippy.toml"))
        .into_iter()
        .map(|entry| entry.path)
        .filter(|path| path.starts_with("kube::"))
        .collect();
    assert_eq!(
        wanted.len(),
        18,
        "the use file proves 18 kube entries: {wanted:?}"
    );

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(root())
        .env("CLIPPY_CONF_DIR", &dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args([
            "clippy",
            "--locked",
            "--package",
            "rdy-lint-wall",
            "--no-deps",
            "--features",
            "use-kube",
            "--message-format=json",
            "--",
            "-D",
            "warnings",
        ])
        .output()
        .expect("start cargo clippy");

    let mut reported: Vec<(String, u64)> = Vec::new();
    let mut stray = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| l.starts_with('{'))
    {
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
            "clippy::disallowed_methods" | "clippy::disallowed_types"
        ) {
            let path = text.split('`').nth(1).unwrap_or(text);
            let at = message["spans"]
                .as_array()
                .and_then(|spans| spans.iter().find(|s| s["is_primary"] == true))
                .and_then(|s| s["line_start"].as_u64())
                .unwrap_or(0);
            reported.push((path.to_owned(), at));
        } else if !text.starts_with("aborting due to") && !text.contains("previous error") {
            stray.push(message["rendered"].as_str().unwrap_or(text).to_owned());
        }
    }
    assert!(
        !output.status.success(),
        "clippy passed over the use file, but every use must fail"
    );
    assert!(
        stray.is_empty(),
        "stray clippy output:\n{}",
        stray.join("\n")
    );

    let mut failures = Vec::new();
    let text = std::fs::read_to_string(root().join(USE_FILE)).expect("the use file");
    for (index, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("//") || !line.contains("// EXPECT") {
            continue;
        }
        let n = index as u64 + 1;
        if !reported.iter().any(|(_, at)| *at == n || *at + 1 == n) {
            failures.push(format!(
                "{USE_FILE}:{n}: no disallowed report: {}",
                line.trim()
            ));
        }
    }
    let seen: BTreeSet<&str> = reported.iter().map(|(path, _)| path.as_str()).collect();
    for path in &wanted {
        if !seen.contains(path.as_str()) {
            failures.push(format!(
                "`{path}` is a kube entry that nothing in the use file reaches"
            ));
        }
    }
    for (path, _) in &reported {
        if !wanted.contains(path) {
            failures.push(format!(
                "reported `{path}`, which is not a kube entry of the k8s clippy.toml"
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
