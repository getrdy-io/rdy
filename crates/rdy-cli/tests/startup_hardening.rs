//! Start-up hardening on the real binary (M1-168, ADR 0023).
//!
//! The shell hands the binary descriptor 7 with `exec ... 7>/dev/null`, which leaves it open without
//! close-on-exec. That is how an operator's shell leaks one, and it needs no `unsafe` here.

#![cfg(unix)]

use std::process::{Command, Output};

fn rdy_via_sh(script: &str, args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("sh did not start rdy: {e}"))
}

fn rdy_with_fd7(args: &[&str]) -> Output {
    rdy_via_sh(r#"exec "$0" "$@" 7>/dev/null"#, args)
}

fn warning_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|l| l.starts_with("warning: "))
        .collect()
}

#[test]
fn an_inherited_descriptor_gets_one_warning_on_stderr() {
    let out = rdy_with_fd7(&["version"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let warnings = warning_lines(&stderr);
    assert_eq!(warnings.len(), 1, "{stderr}");
    assert!(warnings[0].contains("rdy inherited open file descriptor"));
    assert!(warnings[0].contains(" 7"), "{}", warnings[0]);
    assert!(warnings[0].contains("7>&-"), "{}", warnings[0]);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
}

#[test]
fn the_warning_never_reaches_stdout_with_json() {
    let out = rdy_with_fd7(&["version", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(warning_lines(&stderr).len(), 1, "{stderr}");
    assert!(!stdout.contains("warning"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON: {e}: {stdout}"));
    assert!(value.is_object(), "{stdout}");
}

#[test]
fn a_closed_descriptor_gets_no_warning_about_it() {
    let out = rdy_via_sh(r#"exec "$0" "$@" 7>&-"#, &["version"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The test harness may leave its own descriptors open, so only descriptor 7 is checked.
    assert!(
        !warning_lines(&stderr)
            .iter()
            .any(|l| l.contains("descriptor 7") || l.contains(" 7,") || l.contains(", 7")),
        "{stderr}"
    );
}
