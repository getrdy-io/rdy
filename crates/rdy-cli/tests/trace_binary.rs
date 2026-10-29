//! `RUST_LOG=trace` on the built `rdy` binary (M1-056, threat model I2, INV-15).
//!
//! Canaries sit in the environment and on the command line. At the most verbose level no canary may
//! reach stdout or stderr, and the trace must be live. The live proof is a user-supplied value that
//! the binary does log at debug (the spec path): it must come out redacted, never raw.
//!
//! The proxy URL canary needs the URL userinfo rule, so it waits for M1-060
//! (`tests/log_redaction.rs`, ignored test).

use std::process::{Command, Output};

const ENV_CANARY: &str = "canary-binary-env-1";
const ARG_CANARY: &str = "canary-binary-arg-2";
const PATH_CANARY: &str = "canary-binary-path-3";

fn rdy(args: &[&str], rust_log: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.args(args)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG")
        .env("API_TOKEN", ENV_CANARY);
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
    for args in [
        vec!["version"],
        vec!["trust", "list"],
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
fn a_user_supplied_value_that_is_logged_comes_out_redacted() {
    let spec = format!("password={PATH_CANARY}.yaml");
    for command in ["run", "verify"] {
        let out = rdy(&[command, spec.as_str()], Some("trace"));
        let text = all_text(&out);
        assert!(
            text.contains(&format!(
                "{command} requested spec=password=[REDACTED:secret_by_key:"
            )),
            "{command}: the spec path was not logged, so the test proves nothing: {text}"
        );
        assert!(!text.contains(PATH_CANARY), "{command} leaked: {text}");
    }
}

#[test]
fn the_json_stdout_of_a_traced_run_holds_no_log_line() {
    let spec = format!("password={PATH_CANARY}.yaml");
    let out = rdy(&["run", spec.as_str(), "--json"], Some("trace"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("DEBUG"), "{stdout}");
    assert!(!stdout.contains(PATH_CANARY), "{stdout}");
}

#[test]
fn without_rust_log_a_normal_run_writes_nothing_to_stderr() {
    let out = rdy(&["version"], None);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
}

#[test]
fn without_rust_log_no_log_line_appears_even_for_a_failing_command() {
    let spec = format!("password={PATH_CANARY}.yaml");
    let out = rdy(&["run", spec.as_str()], None);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("DEBUG") && !err.contains("WARN"), "{err}");
    assert!(!err.contains(PATH_CANARY), "{err}");
}
