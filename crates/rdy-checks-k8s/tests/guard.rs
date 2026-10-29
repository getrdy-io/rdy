//! The read-only guard on the real client stack (M1-103, INV-14): a kubeconfig is loaded, the client
//! connects, and a check gets a `ReadOnlyClient` from its own probe. The server is a local mock that
//! records every request that reaches it.
//!
//! The rule table is tested in `src/client/guard/tests.rs`. This file proves the wiring: that the only
//! client a check can get is guarded, that a refused request never reaches the socket, and that the
//! action log has one entry per call.

#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k8s_openapi::api::core::v1::{Namespace, Node, Pod, Secret};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::api::{DeleteParams, ListParams, PostParams};
use rdy_checks_k8s::client::{Env, GuardError, KubeOptions, load};
use rdy_engine::check::Os;
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::result::{ActionKind, ActionOutcome};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const VERSION_JSON: &str = r#"{"major":"1","minor":"29+","gitVersion":"v1.29.4-eks-abc123","gitCommit":"0000","gitTreeState":"clean","buildDate":"2024-04-01T00:00:00Z","goVersion":"go1.21.9","compiler":"gc","platform":"linux/amd64"}"#;
const NODES_JSON: &str = r#"{"apiVersion":"v1","kind":"NodeList","metadata":{},"items":[]}"#;
const CLASSES_JSON: &str =
    r#"{"apiVersion":"storage.k8s.io/v1","kind":"StorageClassList","metadata":{},"items":[]}"#;
const TIMEOUT: Duration = Duration::from_secs(10);

/// A mock API server. `GET /version` gets the version, any other request gets a list.
struct MockApi {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockApi {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let first = head.lines().next().unwrap_or_default().to_owned();
                    log.lock().expect("log").push(head);
                    let body = if first.starts_with("GET /version ") {
                        VERSION_JSON
                    } else if first.contains("/storageclasses") {
                        CLASSES_JSON
                    } else {
                        NODES_JSON
                    };
                    let reply = format!(
                        "HTTP/1.1 200 X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { addr, requests }
    }

    /// The request lines that reached the server, such as `GET /version HTTP/1.1`.
    fn lines(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("requests")
            .iter()
            .map(|head| head.lines().next().unwrap_or_default().to_owned())
            .collect()
    }
}

fn ca_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-ca.pem")
}

async fn connect(api: &MockApi, dir: &Path, run: &TestRun) -> rdy_checks_k8s::client::Connected {
    let path = dir.join("kubeconfig");
    let text = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: http://{}\n    certificate-authority: {}\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n    token: t0ken\n",
        api.addr,
        ca_path().display()
    );
    std::fs::write(&path, text).expect("write kubeconfig");
    let loaded = load(&KubeOptions::new(TIMEOUT).kubeconfig(path), &Env::empty())
        .await
        .expect("load");
    loaded
        .connect(&run.run_probe(Os::Linux), |_| {})
        .await
        .expect("connect")
}

fn rule_of(error: &kube::Error) -> Option<&'static str> {
    match error {
        kube::Error::Service(inner) => inner.downcast_ref::<GuardError>().map(GuardError::rule),
        _ => None,
    }
}

#[tokio::test]
async fn a_check_gets_only_a_guarded_client_and_a_refused_request_never_reaches_the_socket() {
    let api = MockApi::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let run = TestRun::new(Replay::new());
    let connected = connect(&api, dir.path(), &run).await;
    assert_eq!(api.lines(), ["GET /version HTTP/1.1"]);

    let check = run.context("k8s.nodes", Os::Linux, []);
    let client = connected.read_only(check.probe());

    // Allowed reads go through, with the credentials kube adds below the guard.
    let nodes = client.all::<Node>();
    nodes
        .list(&ListParams::default().limit(500))
        .await
        .expect("node list");
    client
        .all::<StorageClass>()
        .list(&ListParams::default())
        .await
        .expect("storageclass list");
    // The exact request lines on the wire: what the guard judged is what was sent.
    let allowed_lines = [
        "GET /version HTTP/1.1",
        "GET /api/v1/nodes?&limit=500 HTTP/1.1",
        "GET /apis/storage.k8s.io/v1/storageclasses? HTTP/1.1",
    ];
    assert_eq!(api.lines(), allowed_lines);
    let head = api.requests.lock().expect("requests")[1].to_lowercase();
    assert!(head.contains("authorization: bearer t0ken"), "{head}");

    // Writes, pods and Secrets are refused with the guard's own error, and nothing is sent.
    let pods = client.namespaced::<Pod>("app");
    let secrets = client.namespaced::<Secret>("app");
    let refused = [
        nodes
            .delete("n1", &DeleteParams::default())
            .await
            .map(|_| ()),
        pods.create(&PostParams::default(), &Pod::default())
            .await
            .map(|_| ()),
        pods.get("p").await.map(|_| ()),
        secrets.list(&ListParams::default()).await.map(|_| ()),
        secrets.get("token").await.map(|_| ()),
        client
            .all::<Namespace>()
            .list(&ListParams::default())
            .await
            .map(|_| ()),
    ];
    for result in refused {
        let error = result.expect_err("refused");
        assert!(rule_of(&error).is_some(), "{error:?}");
    }
    assert_eq!(api.lines(), allowed_lines);

    // The log has one entry per call, the first from the run and the rest from the check.
    let log = run.action_log().actions;
    assert_eq!(log.len(), 3 + 6);
    assert!(log.iter().all(|a| a.kind == ActionKind::Kube));
    let outcomes: Vec<_> = log
        .iter()
        .map(|a| (a.check.as_deref(), a.outcome.clone()))
        .collect();
    assert_eq!(outcomes[0], (None, ActionOutcome::Ok));
    assert!(
        outcomes[1..3]
            .iter()
            .all(|o| *o == (Some("k8s.nodes"), ActionOutcome::Ok))
    );
    assert!(
        outcomes[3..]
            .iter()
            .all(|o| *o == (Some("k8s.nodes"), ActionOutcome::Denied))
    );
    assert_eq!(log[0].fields["path"], "/version");
    assert_eq!(log[1].fields["path"], "/api/v1/nodes");
    assert_eq!(log[1].fields["status"], 200);
    // Neither the token nor a query string reaches the log.
    let text = serde_json::to_string(&log).expect("json");
    assert!(
        !text.contains("t0ken") && !text.contains("limit="),
        "{text}"
    );
}

#[tokio::test]
async fn two_checks_log_under_their_own_ids_over_one_connection() {
    let api = MockApi::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let run = TestRun::new(Replay::new());
    let connected = connect(&api, dir.path(), &run).await;

    let storage = run.context("k8s.storageclass", Os::Linux, []);
    let nodes = run.context("k8s.nodes", Os::Linux, []);
    let (a, b) = (
        connected.read_only(storage.probe()),
        connected.read_only(nodes.probe()),
    );
    a.all::<StorageClass>()
        .list(&ListParams::default())
        .await
        .expect("classes");
    b.all::<Node>()
        .list(&ListParams::default())
        .await
        .expect("nodes");
    let error = a
        .all::<Node>()
        .delete("n1", &DeleteParams::default())
        .await
        .expect_err("write");
    assert!(rule_of(&error).is_some());

    let checks: Vec<_> = run
        .action_log()
        .actions
        .iter()
        .map(|a| a.check.clone())
        .collect();
    assert_eq!(
        checks,
        [
            None,
            Some("k8s.storageclass".to_owned()),
            Some("k8s.nodes".to_owned()),
            Some("k8s.storageclass".to_owned())
        ]
    );
    assert_eq!(
        api.lines(),
        [
            "GET /version HTTP/1.1",
            "GET /apis/storage.k8s.io/v1/storageclasses? HTTP/1.1",
            "GET /api/v1/nodes? HTTP/1.1",
        ]
    );
}
