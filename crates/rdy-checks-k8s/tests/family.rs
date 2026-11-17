//! The `k8s` family's probe against a local API server (M1-107): what it reads, in what order, what it
//! registers as secret, and how it ends when the cluster is missing, forbidden or a plugin waits.
//!
//! The probe is called the way the engine calls it, with a context from `TestRun::family_probe`. The engine's
//! own side of the hook (the limit, the need gate, exit 70) is tested in `rdy-engine` and in `rdy-cli`.

#![allow(clippy::expect_used)]
// These are tests of the client module. They start mock servers and write kubeconfigs, which the lint wall
// bans in the rest of this crate (INV-07). This file is on the allowlist of tests/lint-wall/tests/allow_grep.rs.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rdy_checks_k8s::K8sFamily;
use rdy_checks_k8s::client::Env;
use rdy_engine::check::CheckInfo;
use rdy_engine::family::Family;
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::result::{ActionKind, Need as WireNeed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const VERSION_JSON: &str = r#"{"major":"1","minor":"29","gitVersion":"v1.29.4","gitCommit":"0000","gitTreeState":"clean","buildDate":"2024-04-01T00:00:00Z","goVersion":"go1.21.9","compiler":"gc","platform":"linux/amd64"}"#;

/// A server that answers `GET /version` and records "request" in `events` for every request it reads.
async fn serve(events: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    serve_heads(events, None).await
}

/// Like [`serve`], and every request head is kept in `heads`.
async fn serve_heads(
    events: Arc<Mutex<Vec<String>>>,
    heads: Option<Arc<Mutex<Vec<String>>>>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let events = Arc::clone(&events);
            let heads = heads.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                if let Some(heads) = &heads {
                    heads
                        .lock()
                        .expect("heads")
                        .push(String::from_utf8_lossy(&head).to_ascii_lowercase());
                }
                events.lock().expect("events").push("request".to_owned());
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{VERSION_JSON}",
                    VERSION_JSON.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// The infos the engine would hand the probe: both checks the family builds.
fn infos() -> Vec<&'static CheckInfo> {
    K8sFamily::new()
        .checks()
        .iter()
        .copied()
        .filter(|info| info.id == "k8s.version" || info.id == "k8s.access")
        .collect()
}

fn kubeconfig(server: &str, users: &str, exec: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: {server}\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n{exec}    token: CHOSEN-TOKEN-CANARY\n{users}"
    )
}

fn write(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("kubeconfig");
    std::fs::write(&path, text).expect("write kubeconfig");
    path
}

fn kube_context(caps: &[rdy_spec::result::Capability]) -> &rdy_spec::result::Capability {
    caps.iter()
        .find(|cap| cap.need == WireNeed::KubeContext)
        .expect("a kube_context capability")
}

#[tokio::test]
async fn the_line_comes_before_the_first_request_every_secret_is_known_and_the_files_are_logged() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let addr = serve(Arc::clone(&events)).await;
    let dir = tempfile::tempdir().expect("tempdir");
    // A second user that the context does not use: its token is a secret too.
    let others = "- name: other\n  user:\n    token: OTHER-USER-TOKEN-CANARY\n    password: OTHER-USER-PASSWORD\n";
    let path = write(
        dir.path(),
        &kubeconfig(&format!("http://{addr}"), others, ""),
    );
    let run = TestRun::new(Replay::new());
    let lines = Arc::clone(&events);
    let announce = move |line: &str| lines.lock().expect("events").push(format!("line: {line}"));
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);

    let caps = family.probe(ctx).await.expect("the probe ends");

    assert!(kube_context(&caps).available);
    let events = events.lock().expect("events").clone();
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(
        events[0].starts_with("line: ctx, http://127.0.0.1:") && events[0].ends_with(", user usr"),
        "the cluster line is first: {events:?}"
    );
    assert_eq!(events[1], "request");
    // The credentials of every user entry are known secrets, before anything is printed.
    for canary in [
        "CHOSEN-TOKEN-CANARY",
        "OTHER-USER-TOKEN-CANARY",
        "OTHER-USER-PASSWORD",
    ] {
        let shown = run.redact(&format!("saw {canary} here"));
        assert!(!shown.contains(canary), "{canary} was not registered");
    }
    // The kubeconfig read is one `read` entry with no check id.
    let log = run.action_log();
    let reads: Vec<_> = log
        .actions
        .iter()
        .filter(|entry| entry.kind == ActionKind::Read)
        .collect();
    assert_eq!(reads.len(), 1, "{:?}", log.actions);
    assert!(reads[0].check.is_none());
    // The identity of the run comes from the connection (no verified user without `k8s.access`).
    let kube = family.kube_identity(&[]).expect("an identity");
    assert_eq!(kube.context.as_deref(), Some("ctx"));
    assert_eq!(kube.user.as_deref(), Some("usr"));
    assert!(!kube.user_verified);
    // A spec with only these checks reads nothing else: no `exec` entry without a plugin.
    assert!(
        log.actions
            .iter()
            .all(|entry| entry.kind != ActionKind::Exec)
    );
}

#[tokio::test]
async fn with_no_network_no_config_is_read_and_no_client_is_built() {
    let run = TestRun::new(Replay::new());
    let announce = |_: &str| panic!("nothing is announced");
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let missing = Path::new("/no/such/kubeconfig");
    let ctx = run
        .family_probe(&infos, &announce)
        .with_network(false)
        .with_kubeconfig(missing);

    let caps = family.probe(ctx).await.expect("the probe ends");

    let cap = kube_context(&caps);
    assert!(!cap.available);
    assert_eq!(cap.detail.as_deref(), Some("--no-network"));
    assert!(run.action_log().actions.is_empty());
}

#[tokio::test]
async fn with_no_kubeconfig_the_capability_says_so_with_a_fix_and_nothing_is_sent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let run = TestRun::new(Replay::new());
    let announce = |_: &str| panic!("no cluster, so no line");
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty().with_home(dir.path()));
    let ctx = run.family_probe(&infos, &announce);

    let caps = family.probe(ctx).await.expect("the probe ends");

    let cap = kube_context(&caps);
    assert!(!cap.available);
    assert!(
        cap.hint
            .as_deref()
            .is_some_and(|hint| hint.contains("kubeconfig")),
        "{cap:?}"
    );
    assert!(run.action_log().actions.is_empty());
}

#[tokio::test]
async fn a_credential_the_known_secret_set_refuses_ends_the_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 70 KiB is over what the set takes.
    let huge = "x".repeat(70 * 1024);
    let text = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: http://127.0.0.1:9\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n    token: {huge}\n"
    );
    let path = write(dir.path(), &text);
    let run = TestRun::new(Replay::new());
    let announce = |_: &str| panic!("the run ends before the line");
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);

    let fatal = family.probe(ctx).await.expect_err("the run must end");

    assert!(fatal.message.contains("credential"), "{}", fatal.message);
    assert!(!fatal.message.contains("xxxx") && !fatal.hint.contains("xxxx"));
}

#[tokio::test]
async fn a_kubeconfig_that_does_not_parse_leaks_none_of_its_text_into_the_capability_or_the_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(
        dir.path(),
        "apiVersion: v1\nkind: Config\ntoken: PARSE-CANARY-TOKEN [unclosed\n  : :\n",
    );
    let run = TestRun::new(Replay::new());
    let announce = |_: &str| {};
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);

    let caps = family.probe(ctx).await.expect("the probe ends");

    let cap = kube_context(&caps);
    assert!(!cap.available);
    let shown = format!("{cap:?} {:?}", run.action_log().actions);
    assert!(!shown.contains("PARSE-CANARY-TOKEN"), "{shown}");
}

/// A plugin script, and the paths of the marker it touches and the pid it records.
#[cfg(unix)]
fn plugin_script(dir: &Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let plugin = dir.join("get-token");
    std::fs::write(&plugin, format!("#!/bin/sh\n{body}")).expect("write plugin");
    std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    plugin
}

#[cfg(unix)]
fn exec_user(plugin: &Path) -> String {
    format!(
        "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: {}\n",
        plugin.display()
    )
}

#[cfg(unix)]
#[tokio::test]
async fn a_plugin_token_is_a_known_secret_before_the_first_request_leaves_and_the_line_comes_first()
{
    let events = Arc::new(Mutex::new(Vec::new()));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let addr = serve_heads(Arc::clone(&events), Some(Arc::clone(&heads))).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("plugin-ran");
    let plugin = plugin_script(
        dir.path(),
        &format!(
            "touch {}\nprintf '%s' '{{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{{\"token\":\"k8s-aws-v1.aHR0cHM6Ly9zdHMuY2FuYXJ5LWVrcy1wcmVzaWduZWQ\"}}}}'\n",
            marker.display()
        ),
    );
    let text = kubeconfig(&format!("http://{addr}"), "", &exec_user(&plugin))
        .replace("    token: CHOSEN-TOKEN-CANARY\n", "");
    let path = write(dir.path(), &text);
    let run = TestRun::new(Replay::new());
    let seen = Arc::clone(&events);
    let marker_for_line = marker.clone();
    let announce = move |line: &str| {
        // The line is out before the plugin starts.
        assert!(!marker_for_line.exists(), "the plugin ran before the line");
        seen.lock().expect("events").push(format!("line: {line}"));
    };
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);

    let caps = family.probe(ctx).await.expect("the probe ends");

    assert!(kube_context(&caps).available);
    assert!(marker.exists(), "the plugin ran");
    // The first request carried the token, and it is a known secret now. It was registered before the
    // request was sent: the layer registers, then forwards.
    let heads = heads.lock().expect("heads").clone();
    assert!(
        heads[0].contains("authorization: bearer k8s-aws-v1.ahr0chm6"),
        "{heads:?}"
    );
    let shown = run.redact("k8s-aws-v1.aHR0cHM6Ly9zdHMuY2FuYXJ5LWVrcy1wcmVzaWduZWQ");
    assert!(!shown.contains("aHR0cHM6"), "{shown}");
    // The plugin is in the log once, with the way it ended.
    let log = run.action_log();
    let exec: Vec<_> = log
        .actions
        .iter()
        .filter(|entry| entry.kind == ActionKind::Exec)
        .collect();
    assert_eq!(exec.len(), 1, "{:?}", log.actions);
    assert_eq!(exec[0].outcome, rdy_spec::result::ActionOutcome::Ok);
    assert_eq!(exec[0].fields["form"], "delegated");
}

#[tokio::test]
async fn a_short_proxy_password_in_a_kubeconfig_is_refused_and_ends_the_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let text = kubeconfig("https://k8s.acme.example:6443", "", "").replace(
        "    server:",
        "    proxy-url: http://svc:pw@proxy.acme.example:3128\n    server:",
    );
    let path = write(dir.path(), &text);
    let run = TestRun::new(Replay::new());
    let announce = |_: &str| panic!("the run ends before the line");
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);

    let fatal = family
        .probe(ctx)
        .await
        .expect_err("a refused secret ends the run");

    assert!(fatal.message.contains("credential"), "{}", fatal.message);
}

#[tokio::test]
async fn the_identity_is_verified_only_when_the_identity_review_answered() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let addr = serve(Arc::clone(&events)).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), &kubeconfig(&format!("http://{addr}"), "", ""));
    let run = TestRun::new(Replay::new());
    let announce = |_: &str| {};
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);
    family.probe(ctx).await.expect("the probe ends");

    let mut access = rdy_spec::result::CheckResult::new(
        "k8s.access",
        "k8s",
        rdy_spec::result::Severity::Block,
        rdy_spec::result::Status::Pass,
    );
    let mut observed = serde_json::Map::new();
    observed.insert(
        "identity".to_owned(),
        serde_json::json!({"verified": true, "username": "jane@acme.example"}),
    );
    access.observed = Some(observed);
    let verified = family.kube_identity(&[access.clone()]).expect("identity");
    assert!(verified.user_verified);
    assert_eq!(verified.user.as_deref(), Some("jane@acme.example"));

    let mut observed = serde_json::Map::new();
    observed.insert(
        "identity".to_owned(),
        serde_json::json!({"verified": false}),
    );
    access.observed = Some(observed);
    let unverified = family.kube_identity(&[access]).expect("identity");
    assert!(!unverified.user_verified);
    assert_eq!(unverified.user.as_deref(), Some("usr"));
}

#[cfg(unix)]
#[tokio::test]
async fn a_plugin_that_waits_for_a_login_makes_the_cluster_unavailable_names_the_plugin_and_does_not_keep_the_process_from_ending()
 {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("plugin-ran");
    let pid_file = dir.path().join("plugin-pid");
    let plugin = plugin_script(
        dir.path(),
        &format!(
            "touch {}\necho $$ > {}\nexec sleep 600\n",
            marker.display(),
            pid_file.display()
        ),
    );
    let text = kubeconfig("http://127.0.0.1:9", "", &exec_user(&plugin))
        .replace("    token: CHOSEN-TOKEN-CANARY\n", "");
    let path = write(dir.path(), &text);
    let run = TestRun::new(Replay::new());
    let announce = |_: &str| {};
    let infos = infos();
    let family = K8sFamily::with_env(Env::empty());
    let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);

    // The engine's timer ends the probe. Here it ends when the plugin has really started, so the test
    // does not depend on a clock.
    let watcher = async {
        for _ in 0..500 {
            if marker.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the plugin never started");
    };
    tokio::select! {
        _ = family.probe(ctx) => panic!("the probe must still be waiting for the plugin"),
        () = watcher => {}
    }
    let caps = family.probe_timed_out();

    let cap = kube_context(&caps);
    assert!(!cap.available);
    let hint = cap.hint.as_deref().unwrap_or_default();
    assert!(
        hint.contains("get-token") && hint.contains("login"),
        "{hint}"
    );
    // The plugin is in the log once, as timed out.
    let log = run.action_log();
    let exec: Vec<_> = log
        .actions
        .iter()
        .filter(|entry| entry.kind == ActionKind::Exec)
        .collect();
    assert_eq!(exec.len(), 1, "{:?}", log.actions);
    assert_eq!(exec[0].outcome, rdy_spec::result::ActionOutcome::Timeout);
    // End the orphan: nothing else would.
    if let Ok(pid) = std::fs::read_to_string(&pid_file) {
        let _ = std::process::Command::new("kill").arg(pid.trim()).status();
    }
}
