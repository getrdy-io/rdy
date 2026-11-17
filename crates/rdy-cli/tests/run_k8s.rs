//! `rdy run` with the Kubernetes family (M1-107): the family probes the cluster once, lazily, and the
//! checks read the answer.
//!
//! The machine is the replay backend. The API server is a real local socket, because the kube client
//! does not go through the probe facade (ADR 0031): it opens its own connection, which is why these tests
//! run the whole command in process and read what a user sees on stderr, stdout and in the report.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rdy_cli::RunHooks;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod common;

const VERSION_JSON: &str = r#"{"major":"1","minor":"29","gitVersion":"v1.29.4","gitCommit":"0000","gitTreeState":"clean","buildDate":"2024-04-01T00:00:00Z","goVersion":"go1.21.9","compiler":"gc","platform":"linux/amd64"}"#;
const TOKEN_CANARY: &str = "KUBECONFIG-TOKEN-CANARY-0001";

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("not UTF-8: {e}"))
}

/// The families of this build with the Kubernetes family reading an empty environment, so a test never
/// reads the kubeconfig of the machine it runs on. Only `--kubeconfig` can name one.
fn hermetic_families() -> Result<rdy_engine::family::Registry, rdy_engine::family::RegistryError> {
    let mut registry = rdy_engine::family::Registry::new();
    registry.register(rdy_checks_host::HostFamily)?;
    registry.register(rdy_checks_net::NetFamily)?;
    registry.register(rdy_checks_k8s::K8sFamily::with_env(
        rdy_checks_k8s::client::Env::empty(),
    ))?;
    Ok(registry)
}

async fn call(args: &[&str]) -> Ran {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut hooks = RunHooks::default();
    hooks.families = Some(hermetic_families);
    hooks.stderr_terminal = Some(false);
    hooks.stderr_columns = Some(100);
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = rdy_cli::run(
        argv,
        Arc::new(common::unprivileged()),
        hooks,
        &mut out,
        &mut err,
    )
    .await
    .code();
    Ran {
        code,
        stdout: text(out),
        stderr: text(common::without_fd_warning(&err)),
    }
}

fn spec(dir: &Path, checks: &str) -> PathBuf {
    let path = dir.join("spec.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n{checks}"
        ),
    )
    .unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    path
}

const K8S_CHECKS: &str = "  - id: k8s.version\n    min: \"1.28\"\n  - id: k8s.access\n";
const NET_CHECK: &str = "  - id: net.egress\n    endpoints: [\"web.acme.test:8080\"]\n";

fn kubeconfig(dir: &Path, server: &str) -> PathBuf {
    let path = dir.join("kubeconfig");
    std::fs::write(
        &path,
        format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: {server}\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n    token: {TOKEN_CANARY}\n"
        ),
    )
    .unwrap_or_else(|e| panic!("cannot write the kubeconfig: {e}"));
    path
}

fn json(ran: &Ran) -> Value {
    serde_json::from_str(&ran.stdout)
        .unwrap_or_else(|e| panic!("stdout is not the report: {e}\n{}", ran.stdout))
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["id"] == id))
        .unwrap_or_else(|| panic!("no result for {id}"))
}

fn run_args<'a>(spec: &'a str, out: &'a str, more: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["run", spec, "--allow-unsigned", "--json", "--out-dir", out];
    args.extend_from_slice(more);
    args
}

#[tokio::test]
async fn with_no_kubeconfig_k8s_access_blocks_and_the_other_k8s_check_is_skipped() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path(), K8S_CHECKS);
    let missing = dir.path().join("missing-kubeconfig");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));
    let ran = call(&run_args(
        spec.to_str().unwrap_or_default(),
        out.to_str().unwrap_or_default(),
        &["--kubeconfig", missing.to_str().unwrap_or_default()],
    ))
    .await;

    let report = json(&ran);
    let version = check(&report, "k8s.version");
    assert_eq!(version["status"], "skipped");
    assert_eq!(version["skip_kind"], "missing_need");
    let access = check(&report, "k8s.access");
    assert_eq!(access["status"], "block", "{access}");
    assert!(
        access["fix"].as_str().is_some_and(|fix| !fix.is_empty()),
        "k8s.access blocks with its fix: {access}"
    );
    assert_eq!(ran.code, 2, "{}", ran.stderr);
    assert!(!ran.stderr.contains("Cluster:"), "no cluster, so no line");
    assert!(report["identity"]["kube"].is_null());
}

#[tokio::test]
async fn a_spec_with_no_k8s_check_reads_no_kubeconfig() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path(), NET_CHECK);
    // A kubeconfig that cannot be read would end the k8s probe with a capability. Nothing asks for it.
    let missing = dir.path().join("missing-kubeconfig");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));
    let ran = call(&run_args(
        spec.to_str().unwrap_or_default(),
        out.to_str().unwrap_or_default(),
        &["--kubeconfig", missing.to_str().unwrap_or_default()],
    ))
    .await;

    let report = json(&ran);
    assert!(
        report["capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().all(|cap| cap["need"] != "kube_context")),
        "{}",
        report["capabilities"]
    );
    assert!(
        !ran.stdout.contains("missing-kubeconfig"),
        "no file was named"
    );
    assert!(report["identity"]["kube"].is_null());
}

#[tokio::test]
async fn with_no_network_no_kube_client_is_built_and_both_k8s_checks_are_skipped() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path(), K8S_CHECKS);
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));
    let ran = call(&run_args(
        spec.to_str().unwrap_or_default(),
        out.to_str().unwrap_or_default(),
        &["--no-network"],
    ))
    .await;

    let report = json(&ran);
    for id in ["k8s.version", "k8s.access"] {
        let result = check(&report, id);
        assert_eq!(result["status"], "skipped", "{id}: {result}");
        assert_eq!(result["skip_kind"], "missing_need", "{id}: {result}");
    }
    let actions = report["actions"].to_string();
    assert!(!actions.contains("\"kube\""), "no kube entry: {actions}");
}

#[tokio::test]
async fn a_reachable_cluster_prints_its_line_first_fills_the_identity_and_leaks_no_credential() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let first = String::from_utf8_lossy(&head);
                let (status, body) = if first.starts_with("GET /version ") {
                    (200, VERSION_JSON)
                } else {
                    (
                        404,
                        r#"{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}"#,
                    )
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path(), K8S_CHECKS);
    let kubeconfig = kubeconfig(dir.path(), &format!("http://{addr}"));
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));
    let ran = call(&run_args(
        spec.to_str().unwrap_or_default(),
        out.to_str().unwrap_or_default(),
        &["--kubeconfig", kubeconfig.to_str().unwrap_or_default()],
    ))
    .await;

    let report = json(&ran);
    // The line names the context, the server and the user, and nothing of the credential.
    let line = ran
        .stderr
        .lines()
        .find(|line| line.starts_with("Cluster: "))
        .unwrap_or_else(|| panic!("no cluster line on stderr:\n{}", ran.stderr));
    assert_eq!(line, format!("Cluster: ctx, http://{addr}, user usr"));
    let kube = &report["identity"]["kube"];
    assert_eq!(kube["context"], "ctx");
    assert_eq!(kube["user"], "usr");
    assert_eq!(kube["user_verified"], false);
    assert_ne!(check(&report, "k8s.version")["status"], "skipped");
    // The kubeconfig token is in no output.
    for (name, shown) in [("stderr", &ran.stderr), ("stdout", &ran.stdout)] {
        assert!(!shown.contains(TOKEN_CANARY), "the token reached {name}");
    }
}
