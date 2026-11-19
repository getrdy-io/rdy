//! `rdy run` on the built binary at `RUST_LOG=trace` with a kubeconfig that does not parse and holds a
//! canary token (M1-107, PR #96 reviews). The text of the kubeconfig must reach no stream and no file:
//! not stderr, not the `--json` stdout, and nothing in the report folder, the log included.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::NoProxyEnv;

const CANARY: &str = "KUBECONFIG-PARSE-CANARY-7731";

fn files_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                found.push((path, bytes));
            }
        }
    }
    found
}

#[test]
fn a_kubeconfig_parse_error_at_trace_leaks_the_canary_nowhere() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("spec.yaml");
    std::fs::write(
        &spec,
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: k8s.version\n    min: \"1.28\"\n  - id: k8s.access\n",
    )
    .unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    let kubeconfig = dir.path().join("kubeconfig");
    std::fs::write(
        &kubeconfig,
        format!("apiVersion: v1\nkind: Config\ntoken: {CANARY} [unclosed\n  : :\n"),
    )
    .unwrap_or_else(|e| panic!("cannot write the kubeconfig: {e}"));
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
    cmd.arg("run")
        .arg(&spec)
        .args(["--allow-unsigned", "--json", "--out-dir"])
        .arg(&out)
        .arg("--kubeconfig")
        .arg(&kubeconfig)
        .env_remove("RDY_PROGRESS")
        .env_remove("KUBECONFIG")
        .no_proxy_env()
        .env("RUST_LOG", "trace");
    let output = common::quiet(
        cmd.output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}")),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The run happened and k8s.access said why it could not reach a cluster: 2 is the blockers exit.
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stdout.contains("\"k8s.access\""), "{stdout}");
    assert!(!stdout.contains(CANARY), "the canary reached stdout");
    assert!(!stderr.contains(CANARY), "the canary reached stderr");
    let files = files_under(&out);
    assert!(!files.is_empty(), "the report folder has files");
    for (path, bytes) in files {
        assert!(
            !String::from_utf8_lossy(&bytes).contains(CANARY),
            "the canary reached {}",
            path.display()
        );
    }
}
