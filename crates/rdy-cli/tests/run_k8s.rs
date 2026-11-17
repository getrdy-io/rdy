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

#[tokio::test]
async fn with_no_kubeconfig_anywhere_k8s_access_blocks_with_the_hint_to_set_one() {
    // No flag at all, and the family reads an empty environment: no KUBECONFIG, no home, no pod.
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path(), K8S_CHECKS);
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));
    let ran = call(&run_args(
        spec.to_str().unwrap_or_default(),
        out.to_str().unwrap_or_default(),
        &[],
    ))
    .await;

    let report = json(&ran);
    let version = check(&report, "k8s.version");
    assert_eq!(version["skip_kind"], "missing_need");
    assert!(
        version["fix"]
            .as_str()
            .is_some_and(|fix| fix.contains("kubeconfig")),
        "{version}"
    );
    let access = check(&report, "k8s.access");
    assert_eq!(access["status"], "block");
    assert!(
        access["fix"]
            .as_str()
            .is_some_and(|fix| fix.contains("kubeconfig")),
        "{access}"
    );
    assert_eq!(ran.code, 2);
}

#[tokio::test]
async fn a_credential_the_known_secret_set_refuses_is_exit_70_and_no_check_runs() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path(), K8S_CHECKS);
    let huge = "x".repeat(70 * 1024);
    let path = dir.path().join("kubeconfig");
    std::fs::write(
        &path,
        format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: http://127.0.0.1:9\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n    token: {huge}\n"
        ),
    )
    .unwrap_or_else(|e| panic!("cannot write the kubeconfig: {e}"));
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));
    let ran = call(&run_args(
        spec.to_str().unwrap_or_default(),
        out.to_str().unwrap_or_default(),
        &["--kubeconfig", path.to_str().unwrap_or_default()],
    ))
    .await;

    assert_eq!(ran.code, 70, "{}", ran.stderr);
    assert!(ran.stderr.contains("credential"), "{}", ran.stderr);
    assert!(!ran.stderr.contains("xxxxxxxx"), "the value is never shown");
    assert!(!ran.stderr.contains("Cluster:"), "the line is not printed");
}

#[tokio::test]
async fn a_kubeconfig_that_does_not_parse_leaks_none_of_its_text_anywhere() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(dir.path(), K8S_CHECKS);
    let path = dir.path().join("kubeconfig");
    std::fs::write(
        &path,
        "apiVersion: v1\nkind: Config\ntoken: PARSE-ERROR-CANARY-0001 [unclosed\n  : :\n",
    )
    .unwrap_or_else(|e| panic!("cannot write the kubeconfig: {e}"));
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("no out dir: {e}"));
    let ran = call(&run_args(
        spec.to_str().unwrap_or_default(),
        out.to_str().unwrap_or_default(),
        &["--kubeconfig", path.to_str().unwrap_or_default()],
    ))
    .await;

    // stderr, stdout and every file of the report folder.
    let mut all = format!("{}{}", ran.stderr, ran.stdout);
    let mut stack = vec![out];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                all.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
    assert!(
        !all.contains("PARSE-ERROR-CANARY"),
        "the kubeconfig text leaked"
    );
    assert_eq!(check(&json(&ran), "k8s.access")["status"], "block");
}

// ---- M1-175: the family builds every k8s check, and a real run of k8s.rbac keeps `as:` and the OpenShift text ----

const APIS_OPENSHIFT: &str = r#"{"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"security.openshift.io","versions":[{"groupVersion":"security.openshift.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"security.openshift.io/v1","version":"v1"}}]}"#;
const NOT_FOUND: &str =
    r#"{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}"#;

fn review(allowed: bool) -> String {
    format!(
        r#"{{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","status":{{"allowed":{allowed},"reason":"no rule"}}}}"#
    )
}

/// An OpenShift API server on a local socket. It may impersonate the service account and nothing else is
/// allowed. Every request head and body is kept, lower-cased, in the list it returns.
async fn serve_openshift() -> (std::net::SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let kept = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => data.extend_from_slice(&buf[..n]),
                    }
                    let text = String::from_utf8_lossy(&data).to_ascii_lowercase();
                    let Some(end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let length = text[..end]
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if data.len() >= end + 4 + length {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&data).to_ascii_lowercase();
                kept.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(text.clone());
                let first = text.lines().next().unwrap_or_default();
                let allowed = text.contains("\"verb\":\"impersonate\"");
                let (status, body) = if first.starts_with("get /version ") {
                    (200, VERSION_JSON.to_owned())
                } else if first.starts_with("get /apis ") {
                    (200, APIS_OPENSHIFT.to_owned())
                } else if first
                    .starts_with("post /apis/authorization.k8s.io/v1/selfsubjectaccessreviews")
                {
                    (201, review(allowed))
                } else {
                    (404, NOT_FOUND.to_owned())
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
    (addr, seen)
}

#[tokio::test]
async fn a_real_run_builds_every_k8s_check_and_k8s_rbac_keeps_its_as_and_the_openshift_text() {
    let (addr, seen) = serve_openshift().await;
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = spec(
        dir.path(),
        "  - id: k8s.version\n  - id: k8s.access\n  - id: k8s.storageclass\n  - id: k8s.nodes\n  - id: k8s.admission\n    uses: [runAsRoot]\n    namespace: acme-system\n  - id: k8s.namespace\n    namespace: acme-system\n  - id: k8s.rbac\n    as: system:serviceaccount:acme-system:installer\n    can: [\"create namespaces\"]\n",
    );
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
    // Seven ids, seven results, none skipped as not in the build.
    for id in [
        "k8s.version",
        "k8s.access",
        "k8s.storageclass",
        "k8s.nodes",
        "k8s.admission",
        "k8s.namespace",
        "k8s.rbac",
    ] {
        let result = check(&report, id);
        assert_ne!(result["skip_kind"], "not_in_build", "{id}: {result}");
    }
    // k8s.rbac asked as the service account, and the fix names the OpenShift command.
    let rbac = check(&report, "k8s.rbac");
    assert_eq!(rbac["status"], "block", "{rbac}");
    let fix = rbac["fix"].as_str().unwrap_or_default();
    assert!(fix.contains("On OpenShift, `oc adm policy"), "{fix}");
    let seen = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        seen.iter().any(|request| {
            request.contains("\"resource\":\"namespaces\"")
                && request.contains("impersonate-user: system:serviceaccount:acme-system:installer")
        }),
        "no impersonated review of the item was sent: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|request| request.contains("\"verb\":\"impersonate\"")
                && !request.contains("impersonate-user:")),
        "the impersonation review is not impersonated"
    );
}
