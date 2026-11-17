//! `rdy run` at `RUST_LOG=trace`, on the built binary (M1-057, carried from M1-056 and M1-062; threat
//! model I2, correction PC-43).
//!
//! Two promises. Log lines count nowhere in the report, so `redaction.by_rule` is the same with
//! `RUST_LOG` unset and at `trace`. And a canary that the binary logs in a tracing field (the spec path,
//! logged at debug) never reaches stderr, stdout, or any file in the report folder.
//!
//! The canary is in the file name of the spec, `password=<canary>.yaml`. The key-name rule hides the
//! part after `password=`, so the log and the report both show a placeholder.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

mod common;

const CANARY: &str = "canary-run-logging-5521";
const ACME: &str = "../../examples/specs/acme-platform.yaml";

fn rdy(spec: &Path, out: &Path, rust_log: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.arg("run")
        .arg(spec)
        .args(["--allow-unsigned", "--json", "--out-dir"])
        .arg(out)
        .env_remove("RDY_PROGRESS")
        .env_remove("RUST_LOG");
    if let Some(level) = rust_log {
        cmd.env("RUST_LOG", level);
    }
    common::quiet(
        cmd.output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}")),
    )
}

/// A copy of the example spec whose file name holds the canary.
fn canary_spec(dir: &Path) -> PathBuf {
    let spec = dir.join(format!("password={CANARY}.yaml"));
    std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join(ACME), &spec)
        .unwrap_or_else(|e| panic!("cannot copy the spec: {e}"));
    spec
}

fn report(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout}"))
}

/// Every file under `dir`, as text.
fn files_under(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", next.display()))
        {
            let path = entry
                .unwrap_or_else(|e| panic!("cannot list {}: {e}", next.display()))
                .path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                found.push((path, String::from_utf8_lossy(&bytes).into_owned()));
            }
        }
    }
    found
}

#[test]
fn by_rule_is_the_same_with_the_log_off_and_at_trace_and_no_canary_reaches_a_file_or_a_stream() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = canary_spec(dir.path());
    let quiet_out = dir.path().join("quiet");
    let loud_out = dir.path().join("loud");
    for folder in [&quiet_out, &loud_out] {
        std::fs::create_dir(folder).unwrap_or_else(|e| panic!("cannot make the folder: {e}"));
    }

    let quiet = rdy(&spec, &quiet_out, None);
    let loud = rdy(&spec, &loud_out, Some("trace"));

    // The trace is live: the debug event of the spec path is there, and it is redacted.
    let loud_err = String::from_utf8_lossy(&loud.stderr);
    assert!(
        loud_err.contains("run requested spec=")
            && loud_err.contains("password=[REDACTED:secret_by_key:"),
        "the spec path was not logged, so the test proves nothing: {loud_err}"
    );

    // Nothing holds the canary: not a stream, not a file of either report folder.
    for (name, output) in [("quiet", &quiet), ("loud", &loud)] {
        for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(CANARY), "{name} {stream} leaked: {text}");
        }
    }
    for folder in [&quiet_out, &loud_out] {
        let files = files_under(folder);
        assert!(
            files.len() >= 2,
            "{} holds {} files",
            folder.display(),
            files.len()
        );
        for (path, text) in files {
            assert!(!text.contains(CANARY), "{} leaked", path.display());
        }
    }

    // by_rule: the report counts the replacements its own walk made, and never the log's.
    let (quiet_doc, loud_doc) = (report(&quiet), report(&loud));
    let by_rule = |doc: &Value| doc["redaction"]["by_rule"].clone();
    assert_eq!(
        by_rule(&quiet_doc),
        by_rule(&loud_doc),
        "{quiet_doc} {loud_doc}"
    );
    assert_eq!(
        quiet_doc["redaction"]["total"],
        loud_doc["redaction"]["total"]
    );
    // And the count is real: the file name in the report was hidden by the key-name rule.
    assert!(
        quiet_doc["redaction"]["by_rule"]["secret_by_key"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "{quiet_doc}"
    );
    assert!(
        quiet_doc["spec"]["file_name"]
            .as_str()
            .unwrap_or_default()
            .starts_with("password=[REDACTED:secret_by_key:"),
        "{}",
        quiet_doc["spec"]
    );
}
