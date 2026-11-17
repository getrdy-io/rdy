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
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let events = Arc::clone(&events);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
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
    let path = write(dir.path(), &kubeconfig(&format!("http://{addr}"), others, ""));
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
    assert!(log.actions.iter().all(|entry| entry.kind != ActionKind::Exec));
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

#[cfg(unix)]
#[test]
fn a_plugin_that_waits_for_a_login_makes_the_cluster_unavailable_and_does_not_keep_the_process_from_ending()
 {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let plugin = dir.path().join("get-token");
    std::fs::write(&plugin, "#!/bin/sh\nsleep 600\n").expect("write plugin");
    std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let exec = format!(
        "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: {}\n",
        plugin.display()
    );
    // The token line follows the exec block, which is not valid for one user: use a plugin-only user.
    let text = kubeconfig("http://127.0.0.1:9", "", &exec).replace("    token: CHOSEN-TOKEN-CANARY\n", "");
    let path = write(dir.path(), &text);

    // The runtime the CLI builds: one thread, and shut down without waiting for the blocking pool.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let started = std::time::Instant::now();
    let (caps, entries) = runtime.block_on(async {
        let run = TestRun::new(Replay::new());
        let announce = |_: &str| {};
        let infos = infos();
        let family = K8sFamily::with_env(Env::empty());
        let ctx = run.family_probe(&infos, &announce).with_kubeconfig(&path);
        // The engine's timer, as `Engine::execute` holds it. The engine's limit is 10 s. This one is short
        // and on a real clock, because tokio's paused clock does not advance while a blocking task waits.
        let ended = tokio::time::timeout(Duration::from_millis(300), family.probe(ctx)).await;
        assert!(ended.is_err(), "the probe must still be waiting for the plugin");
        family.probe_timed_out();
        (
            vec![family.kube_identity(&[]).is_none()],
            run.action_log()
                .actions
                .into_iter()
                .map(|entry| (entry.kind, entry.fields.get("program").cloned()))
                .collect::<Vec<_>>(),
        )
    });
    // The attempt ended with the facts the config gave: the identity is not empty (it is not "no config").
    assert_eq!(caps, [false]);
    // The plugin is in the log as one `exec` entry with the file the kubeconfig names.
    let exec_entries: Vec<_> = entries
        .iter()
        .filter(|(kind, _)| *kind == ActionKind::Exec)
        .collect();
    assert_eq!(exec_entries.len(), 1, "{entries:?}");
    runtime.shutdown_background();
    // The plugin sleeps 600 s. The process still ends at once, because nothing waits for it.
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the runtime waited for the plugin"
    );
}
