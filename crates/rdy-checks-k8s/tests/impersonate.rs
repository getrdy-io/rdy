//! Impersonation on the real client stack (M1-111, 02 Appendix B rule 8).
//!
//! The unit and fixture tests run the guard over a mock service. These run the production stack: a
//! kubeconfig is loaded, the client is connected to a local server, and `Connected::read_only_as` builds
//! the client that `k8s.rbac` uses. The server records the raw request heads, so the tests see exactly
//! which `Impersonate-*` headers reach the wire:
//!
//! - with a spec `as:`, the access review carries exactly one `Impersonate-User` with the spec's value
//!   and no `Impersonate-Group`, `-Uid` or `-Extra-*`, and `SelfSubjectReview` carries none;
//! - the action log marks that call `impersonated: true` and never holds the user name;
//! - when the kubeconfig user already sets an `as` field, kube adds its own headers below the guard, so
//!   `read_only_as` refuses before it builds a client.

#![allow(clippy::expect_used)]
// These are tests of the client module. They start mock servers and write kubeconfigs, which the lint
// wall bans in the rest of this crate (INV-07). This file is on the allowlist of
// tests/lint-wall/tests/allow_grep.rs. A test of a check does not belong here: use the probe.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use kube::api::{ObjectMeta, PostParams};
use rdy_checks_k8s::client::{Env, ImpersonateAs, ImpersonationError, KubeOptions, Loaded, load};
use rdy_engine::check::{Need, Os};
use rdy_engine::testing::{Replay, TestRun};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const VERSION_JSON: &str = r#"{"major":"1","minor":"30","gitVersion":"v1.30.2","gitCommit":"0000","gitTreeState":"clean","buildDate":"2024-06-01T00:00:00Z","goVersion":"go1.22.4","compiler":"gc","platform":"linux/arm64"}"#;
const REVIEW_JSON: &str = r#"{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","metadata":{},"spec":{},"status":{"allowed":true}}"#;
const WHO_JSON: &str = r#"{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","metadata":{},"status":{"userInfo":{"username":"acme-admin"}}}"#;

const AS: &str = "system:serviceaccount:acme-system:installer";

/// A plain HTTP server that records the head of every request.
struct Server {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&heads);
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
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let first = text.lines().next().unwrap_or_default().to_owned();
                    log.lock().expect("log").push(text);
                    let (status, body) = if first.starts_with("GET /version ") {
                        (200, VERSION_JSON)
                    } else if first
                        .starts_with("POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews")
                    {
                        (201, REVIEW_JSON)
                    } else if first
                        .starts_with("POST /apis/authentication.k8s.io/v1/selfsubjectreviews")
                    {
                        (201, WHO_JSON)
                    } else {
                        (404, "{}")
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
        Self { addr, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }

    /// The heads of requests whose first line starts with `prefix`.
    fn heads_of(&self, prefix: &str) -> Vec<String> {
        self.heads()
            .into_iter()
            .filter(|head| head.starts_with(prefix))
            .collect()
    }
}

/// The header lines of a request head whose name starts with `prefix` (case-insensitive).
fn headers_named(head: &str, prefix: &str) -> Vec<String> {
    head.lines()
        .skip(1)
        .filter(|line| line.to_ascii_lowercase().starts_with(prefix))
        .map(str::to_owned)
        .collect()
}

fn ca_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-ca.pem")
}

async fn loaded(dir: &Path, server: &Server, user: &str) -> Loaded {
    let text = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: http://{}\n    certificate-authority: {}\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n{user}",
        server.addr,
        ca_path().display()
    );
    let path = dir.join("kubeconfig");
    std::fs::write(&path, text).expect("write kubeconfig");
    load(
        &KubeOptions::new(Duration::from_secs(10)).kubeconfig(path),
        &Env::empty(),
    )
    .await
    .expect("load")
}

fn review() -> SelfSubjectAccessReview {
    SelfSubjectAccessReview {
        metadata: ObjectMeta::default(),
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some("create".to_owned()),
                resource: Some("namespaces".to_owned()),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        status: None,
    }
}

#[tokio::test]
async fn a_spec_as_reaches_the_wire_once_with_no_group_and_the_log_marks_it() {
    let server = Server::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let run = TestRun::new(Replay::new());
    let connected = loaded(dir.path(), &server, "    token: t\n")
        .await
        .connect(&run.run_probe(Os::Linux), |_| {})
        .await
        .expect("connect");
    let ctx = run.context("k8s.rbac", Os::Linux, [Need::KubeContext]);

    let user = ImpersonateAs::new(AS).expect("a valid user");
    let client = connected
        .read_only_as(ctx.probe(), user)
        .expect("the kubeconfig does not impersonate");
    let answer = client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &review())
        .await
        .expect("the review");
    assert!(answer.status.is_some_and(|status| status.allowed));
    // Who am I goes through the same client and is never impersonated.
    client.self_subject_review().await.expect("who am I");

    let reviews = server.heads_of("POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews");
    assert_eq!(reviews.len(), 1);
    let head = &reviews[0];
    // Exactly one Impersonate-User, with the spec's value, and nothing else that impersonates.
    assert_eq!(
        headers_named(head, "impersonate-user"),
        [format!("impersonate-user: {AS}")],
        "{head}"
    );
    assert!(
        headers_named(head, "impersonate-group").is_empty(),
        "{head}"
    );
    assert!(headers_named(head, "impersonate-uid").is_empty(), "{head}");
    assert!(
        headers_named(head, "impersonate-extra").is_empty(),
        "{head}"
    );
    // The kubeconfig credential still goes below the guard as usual.
    assert_eq!(
        headers_named(head, "authorization"),
        ["authorization: Bearer t"]
    );

    let who = server.heads_of("POST /apis/authentication.k8s.io/v1/selfsubjectreviews");
    assert_eq!(who.len(), 1);
    assert!(
        headers_named(&who[0], "impersonate-").is_empty(),
        "{}",
        who[0]
    );
    let version = server.heads_of("GET /version ");
    assert!(headers_named(&version[0], "impersonate-").is_empty());

    // The action log marks the review, and holds no user name anywhere.
    let log = run.action_log().actions;
    let reviews: Vec<_> = log
        .iter()
        .filter(|entry| {
            entry.fields["path"] == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        })
        .collect();
    assert_eq!(reviews.len(), 1);
    assert_eq!(reviews[0].check.as_deref(), Some("k8s.rbac"));
    assert_eq!(reviews[0].fields["impersonated"], true);
    for entry in log.iter().filter(|entry| {
        entry.fields["path"] != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
    }) {
        assert!(entry.fields.get("impersonated").is_none(), "{entry:?}");
    }
    for entry in &log {
        assert!(!format!("{entry:?}").contains("installer"), "{entry:?}");
    }
}

#[tokio::test]
async fn a_client_without_a_spec_as_sends_no_impersonate_header() {
    let server = Server::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let run = TestRun::new(Replay::new());
    let connected = loaded(dir.path(), &server, "    token: t\n")
        .await
        .connect(&run.run_probe(Os::Linux), |_| {})
        .await
        .expect("connect");
    let ctx = run.context("k8s.rbac", Os::Linux, [Need::KubeContext]);
    connected
        .read_only(ctx.probe())
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &review())
        .await
        .expect("the review");
    for head in server.heads() {
        assert!(headers_named(&head, "impersonate-").is_empty(), "{head}");
    }
}

#[tokio::test]
async fn a_kubeconfig_as_is_added_by_kube_below_the_guard_which_is_why_a_spec_as_is_refused() {
    // Without a spec `as:`, a kubeconfig `as` and `as-groups` reach the wire on every request, including
    // the GET of /version. The guard never sees them: kube adds them below it.
    let server = Server::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let user = "    token: t\n    as: kube-user\n    as-groups:\n    - kube-group\n";
    let run = TestRun::new(Replay::new());
    let connected = loaded(dir.path(), &server, user)
        .await
        .connect(&run.run_probe(Os::Linux), |_| {})
        .await
        .expect("connect");
    let version = &server.heads_of("GET /version ")[0];
    assert_eq!(
        headers_named(version, "impersonate-user"),
        ["impersonate-user: kube-user"]
    );
    assert_eq!(
        headers_named(version, "impersonate-group"),
        ["impersonate-group: kube-group"]
    );
    // The cluster line says so.
    assert!(connected.line().kubeconfig_impersonates());
    assert!(
        connected
            .line()
            .to_string()
            .ends_with(", the kubeconfig impersonates another user")
    );

    // So a spec `as:` would make two Impersonate-User headers. It is refused, and nothing is sent.
    let before = server.heads().len();
    let ctx = run.context("k8s.rbac", Os::Linux, [Need::KubeContext]);
    let refused = connected
        .read_only_as(ctx.probe(), ImpersonateAs::new(AS).expect("valid"))
        .expect_err("refused");
    assert_eq!(refused, ImpersonationError::Conflict);
    assert_eq!(server.heads().len(), before);
}

#[tokio::test]
async fn any_as_field_of_the_kubeconfig_user_is_a_conflict() {
    for field in [
        "    as: someone\n",
        "    as-uid: 0000\n",
        "    as-groups:\n    - g\n",
        "    as-user-extra:\n      scopes:\n      - read\n",
        // Present but empty still counts: kube sends the header for it.
        "    as: \"\"\n",
    ] {
        let server = Server::start().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let run = TestRun::new(Replay::new());
        let user = format!("    token: t\n{field}");
        let connected = loaded(dir.path(), &server, &user)
            .await
            .connect(&run.run_probe(Os::Linux), |_| {})
            .await
            .expect("connect");
        assert!(connected.line().kubeconfig_impersonates(), "{field}");
        let ctx = run.context("k8s.rbac", Os::Linux, [Need::KubeContext]);
        assert!(
            connected
                .read_only_as(ctx.probe(), ImpersonateAs::new(AS).expect("valid"))
                .is_err(),
            "{field}"
        );
    }
}

#[tokio::test]
async fn a_kubeconfig_without_an_as_field_is_not_a_conflict() {
    let server = Server::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = loaded(dir.path(), &server, "    token: t\n").await;
    assert!(!loaded.line().kubeconfig_impersonates());
    assert!(!loaded.line().to_string().contains("impersonates"));
}
