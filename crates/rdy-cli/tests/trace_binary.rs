//! `RUST_LOG=trace` on the built `rdy` binary (M1-056, threat model I2, INV-15).
//!
//! Canaries sit in the environment and on the command line. At the most verbose level no canary may
//! reach stdout or stderr, and the trace must be live (a debug line is there).

use std::process::{Command, Output};

const ENV_CANARY: &str = "canary-binary-env-1";
const ARG_CANARY: &str = "canary-binary-arg-2";

fn rdy(args: &[&str], rust_log: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.args(args)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG")
        .env("API_TOKEN", ENV_CANARY)
        .env(
            "HTTPS_PROXY",
            format!("http://synthetic:{ENV_CANARY}@proxy.example"),
        );
    if let Some(level) = rust_log {
        cmd.env("RUST_LOG", level);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"))
}

fn all_text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn trace_is_live_and_no_canary_reaches_either_stream() {
    let flag = format!("--tokne={ARG_CANARY}");
    for args in [
        vec!["version"],
        vec!["trust", "list"],
        vec!["run", "spec.yaml", flag.as_str()],
        vec!["--bogus", ARG_CANARY],
    ] {
        let out = rdy(&args, Some("trace"));
        let text = all_text(&out);
        assert!(!text.contains(ENV_CANARY), "{args:?} leaked: {text}");
        assert!(!text.contains(ARG_CANARY), "{args:?} leaked: {text}");
    }
    let out = rdy(&["version"], Some("trace"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("command parsed"), "trace is not live: {err}");
    assert!(!err.contains('\u{1b}'), "{err:?}");
}

#[test]
fn without_rust_log_a_normal_run_writes_nothing_to_stderr() {
    let out = rdy(&["version"], None);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
}
