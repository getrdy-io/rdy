//! The kube client against a local mock API server: the order of announce and first request, the
//! version answer, the error classes, timeouts, and that a credential plugin's output never reaches an
//! error value or a log line, even with every `tracing` level on.
//!
//! The server speaks plain HTTP on 127.0.0.1, so no certificate is needed for the connection. The
//! kubeconfig still names a CA file, so the client never loads the system roots and the tests do not
//! depend on the machine.

#![allow(clippy::expect_used)]
// These are tests of the client module. They start mock servers, write kubeconfigs and run plugin
// scripts, which the lint wall bans in the rest of this crate (INV-07). This file is on the allowlist of
// tests/lint-wall/tests/allow_grep.rs. A test of a check does not belong here: use the probe.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

mod common;

use common::{is_child, run_child};
use rdy_checks_k8s::client::{Env, KubeError, KubeOptions, Loaded, load};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const VERSION_JSON: &str = r#"{"major":"1","minor":"29+","gitVersion":"v1.29.4-eks-abc123","gitCommit":"0000","gitTreeState":"clean","buildDate":"2024-04-01T00:00:00Z","goVersion":"go1.21.9","compiler":"gc","platform":"linux/amd64"}"#;

type Shared<T> = Arc<Mutex<Vec<T>>>;

#[derive(Clone, Copy)]
enum Mode {
    /// Answer `GET /version` with 200 and the version document.
    Version,
    /// Answer every request with this status and a `Status` body.
    Status(u16),
    /// Read the request and never answer.
    Hang,
    /// Answer `GET /version` with 200 and a body that is not a version document.
    NotJson,
}

struct MockApi {
    addr: SocketAddr,
    requests: Shared<String>,
    events: Shared<&'static str>,
}

impl MockApi {
    async fn start(mode: Mode) -> Self {
        Self::start_with(mode, Arc::new(Mutex::new(Vec::new()))).await
    }

    async fn start_with(mode: Mode, events: Shared<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests: Shared<String> = Arc::new(Mutex::new(Vec::new()));
        let (log, seen) = (Arc::clone(&requests), Arc::clone(&events));
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                seen.lock().expect("events").push("connection");
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
                    log.lock()
                        .expect("log")
                        .push(String::from_utf8_lossy(&head).into_owned());
                    let (status, body) = match mode {
                        Mode::Version => (200, VERSION_JSON.to_owned()),
                        Mode::Status(code) => (
                            code,
                            format!(
                                r#"{{"kind":"Status","apiVersion":"v1","status":"Failure","message":"nope","reason":"Denied","code":{code}}}"#
                            ),
                        ),
                        Mode::NotJson => (200, "<html>log in</html>".to_owned()),
                        Mode::Hang => {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                            return;
                        }
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
        Self {
            addr,
            requests,
            events,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests").clone()
    }
}

fn ca_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-ca.pem")
}

fn kubeconfig(server: &str, user: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: {server}\n    certificate-authority: {}\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n{user}",
        ca_path().display()
    )
}

async fn load_text(dir: &Path, server: &str, user: &str, timeout: Duration) -> Loaded {
    let path = dir.join("kubeconfig");
    std::fs::write(&path, kubeconfig(server, user)).expect("write kubeconfig");
    load(&KubeOptions::new(timeout).kubeconfig(path), &Env::empty())
        .await
        .expect("load")
}

fn token(value: &str) -> String {
    format!("    token: {value}\n")
}

const TIMEOUT: Duration = Duration::from_secs(10);

// ---- tracing capture ------------------------------------------------------------------------------

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("logs").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs one global subscriber with every level on and no cap, so this is stricter than the rdy
/// log layer (which caps kube at warn). It also takes the records of crates that log through the `log`
/// crate (rustls does), by way of the `tracing-log` bridge. Returns everything logged so far in the
/// process.
fn logs() -> String {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    let shared = LOGS.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&buffer);
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || LogWriter(Arc::clone(&writer)))
            .finish();
        tracing_subscriber::util::SubscriberInitExt::try_init(subscriber)
            .expect("one global subscriber and one log bridge");
        buffer
    });
    String::from_utf8_lossy(&shared.lock().expect("logs")).into_owned()
}

// ---- tests that need no plugin ---------------------------------------------------------------------

#[tokio::test]
async fn the_capture_sees_records_of_the_log_crate_too() {
    let _ = logs();
    log::error!("LOG-BRIDGE-CHECK");
    assert!(logs().contains("LOG-BRIDGE-CHECK"));
}

#[tokio::test]
async fn a_path_prefix_in_the_server_reaches_the_server() {
    let api = MockApi::start(Mode::Version).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let server = format!("{}/k8s/clusters/c-m-1", api.url());
    let loaded = load_text(dir.path(), &server, &token("t"), TIMEOUT).await;
    assert!(loaded.line().server().ends_with("/k8s/clusters/c-m-1"));

    loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect("connect");

    let requests = api.requests();
    assert!(
        requests[0].starts_with("GET /k8s/clusters/c-m-1/version HTTP/1.1"),
        "{}",
        requests[0]
    );
}

#[tokio::test]
async fn https_proxy_in_the_environment_is_ignored_even_when_malformed() {
    if !is_child() {
        run_child(
            "https_proxy_in_the_environment_is_ignored_even_when_malformed",
            &[
                ("HTTPS_PROXY", "::not a url::"),
                ("https_proxy", "http://127.0.0.1:1"),
            ],
        );
        return;
    }
    let env = Env::from_process();
    assert!(env.proxy_env_set, "the child was started with a proxy set");
    let api = MockApi::start(Mode::Version).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kubeconfig");
    std::fs::write(&path, kubeconfig(&api.url(), &token("t"))).expect("write");

    let loaded = load(&KubeOptions::new(TIMEOUT).kubeconfig(path), &env)
        .await
        .expect("a malformed HTTPS_PROXY must not fail the load");
    loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect("the request must go to the cluster, not to the proxy");

    assert_eq!(api.requests().len(), 1);
}

#[tokio::test]
async fn connects_sends_a_bearer_token_and_reads_the_version() {
    let _ = logs();
    let api = MockApi::start(Mode::Version).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = load_text(dir.path(), &api.url(), &token("TOKEN-CANARY-1"), TIMEOUT).await;

    let connected = loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect("connect");

    let version = connected.server_version();
    assert_eq!(version.git_version, "v1.29.4-eks-abc123");
    assert_eq!(version.minor, "29+");
    assert_eq!(version.platform, "linux/amd64");
    let requests = api.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(
        requests[0].starts_with("GET /version HTTP/1.1"),
        "{}",
        requests[0]
    );
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer token-canary-1"),
        "{}",
        requests[0]
    );
    let all = logs();
    assert!(!all.contains("TOKEN-CANARY-1"), "a token reached the log");
    assert!(
        all.contains("requesting"),
        "the capture saw nothing from kube: {all}"
    );
}

#[tokio::test]
async fn the_cluster_is_announced_before_the_first_connection() {
    let events: Shared<&'static str> = Arc::new(Mutex::new(Vec::new()));
    let api = MockApi::start_with(Mode::Version, Arc::clone(&events)).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = load_text(dir.path(), &api.url(), &token("t"), TIMEOUT).await;
    let announced = Arc::new(Mutex::new(String::new()));

    let (log, shown) = (Arc::clone(&events), Arc::clone(&announced));
    loaded
        .connect(&common::run_probe(), move |line| {
            log.lock().expect("events").push("announce");
            *shown.lock().expect("shown") = line.to_string();
        })
        .await
        .expect("connect");

    assert_eq!(*events.lock().expect("events"), ["announce", "connection"]);
    let shown = announced.lock().expect("shown").clone();
    assert_eq!(shown, format!("ctx, {}, user usr", api.url()));
    assert_eq!(api.events.lock().expect("events").len(), 2);
}

#[tokio::test]
async fn a_401_and_a_403_are_their_own_errors() {
    for (code, want_unauthorized) in [(401, true), (403, false)] {
        let api = MockApi::start(Mode::Status(code)).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let loaded = load_text(dir.path(), &api.url(), &token("t"), TIMEOUT).await;
        let error = loaded
            .connect(&common::run_probe(), |_| {})
            .await
            .expect_err("refused");
        if want_unauthorized {
            assert!(matches!(error, KubeError::Unauthorized { .. }), "{error:?}");
        } else {
            assert!(matches!(error, KubeError::Forbidden { .. }), "{error:?}");
        }
        assert!(!error.hint().is_empty());
        assert!(error.to_string().contains(&api.url()), "{error}");
    }
}

#[tokio::test]
async fn another_status_keeps_the_code_and_reason() {
    let api = MockApi::start(Mode::Status(500)).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = load_text(dir.path(), &api.url(), &token("t"), TIMEOUT).await;
    let error = loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("500");
    assert!(
        matches!(&error, KubeError::Api { code: 500, reason, .. } if reason == "Denied"),
        "{error:?}"
    );
    assert_eq!(api.requests().len(), 1, "kube must not retry");
}

#[tokio::test]
async fn an_answer_that_is_not_a_version_document_is_a_bad_answer() {
    let api = MockApi::start(Mode::NotJson).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = load_text(dir.path(), &api.url(), &token("t"), TIMEOUT).await;
    let error = loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("not json");
    assert!(
        matches!(&error, KubeError::BadAnswer { server } if *server == api.url()),
        "{error:?}"
    );
    assert!(error.hint().contains("API server"), "{}", error.hint());
    assert!(!error.to_string().contains("log in"), "{error}");
}

#[tokio::test]
async fn a_server_that_never_answers_times_out() {
    let api = MockApi::start(Mode::Hang).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = load_text(
        dir.path(),
        &api.url(),
        &token("t"),
        Duration::from_millis(300),
    )
    .await;
    let error = loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("timeout");
    assert!(matches!(error, KubeError::Timeout { .. }), "{error:?}");
    assert!(error.hint().contains("VPN"), "{}", error.hint());
}

#[tokio::test]
async fn a_closed_port_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = load_text(dir.path(), &format!("http://{addr}"), &token("t"), TIMEOUT).await;
    let error = loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("refused");
    assert!(
        matches!(&error, KubeError::Unreachable { cause, .. } if *cause == "the connection was refused"),
        "{error:?}"
    );
}

// ---- credential plugins (Unix: the plugins are shell scripts) -------------------------------------------

#[cfg(unix)]
mod plugin {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    fn exec_user(command: &Path) -> String {
        format!(
            "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: {}\n",
            command.display()
        )
    }

    fn credential(token: &str, expiry: Option<&str>) -> String {
        let expiry =
            expiry.map_or_else(String::new, |e| format!(r#","expirationTimestamp":"{e}""#));
        format!(
            r#"printf '%s' '{{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{{"token":"{token}"{expiry}}}}}'"#
        )
    }

    fn assert_clean(error: &KubeError) {
        let shown = format!("{error} | {error:?} | {}", error.hint());
        for canary in [
            "STDOUT-CANARY",
            "STDERR-CANARY",
            "ARG-CANARY",
            "REFRESH-CANARY",
        ] {
            assert!(!shown.contains(canary), "{canary} leaked into {shown}");
        }
    }

    #[tokio::test]
    async fn without_a_terminal_a_plugin_cannot_reach_stderr_and_gets_no_rdy_secrets() {
        const NAME: &str =
            "plugin::without_a_terminal_a_plugin_cannot_reach_stderr_and_gets_no_rdy_secrets";
        if !is_child() {
            let output = run_child(
                NAME,
                &[
                    ("RDY_TOKEN", "RDYTOKEN-CANARY"),
                    ("RDY_KEY_PASSWORD", "KEYPASSWORD-CANARY"),
                    ("RDY_EXTERNAL_ID_PROD", "EXTID-CANARY"),
                    ("AWS_SECRET_ACCESS_KEY", "AWSKEY-STAYS"),
                ],
            );
            // The kubeconfig sets no interactiveMode, so kube's default would hand the plugin this
            // process's stderr. The child has no terminal, so the plugin's stderr must be captured.
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains("STDERR-CHILD-CANARY"),
                "plugin stderr reached rdy's stderr: {stderr}"
            );
            return;
        }
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (dump, info) = (dir.path().join("env.dump"), dir.path().join("info.dump"));
        let plugin = script(
            dir.path(),
            "get-token",
            &format!(
                "echo STDERR-CHILD-CANARY >&2\nenv > '{}'\nprintf '%s' \"$KUBERNETES_EXEC_INFO\" > '{}'\n{}\n",
                dump.display(),
                info.display(),
                credential("t", None),
            ),
        );
        let path = dir.path().join("kubeconfig");
        std::fs::write(&path, kubeconfig(&api.url(), &exec_user(&plugin))).expect("write");
        let env = Env::from_process();
        assert!(!env.stdin_is_terminal && !env.stderr_is_terminal);

        let loaded = load(&KubeOptions::new(TIMEOUT).kubeconfig(path), &env)
            .await
            .expect("load");
        loaded
            .connect(&common::run_probe(), |_| {})
            .await
            .expect("connect");

        let seen = std::fs::read_to_string(&dump).expect("env dump");
        for name in [
            "RDY_TOKEN=",
            "RDY_KEY_PASSWORD=",
            "RDY_EXTERNAL_ID_PROD=",
            "RDY_TEST_CHILD=",
        ] {
            assert!(!seen.contains(name), "the plugin saw {name}");
        }
        assert!(
            seen.contains("AWS_SECRET_ACCESS_KEY=AWSKEY-STAYS"),
            "cloud credentials must stay for the cloud plugins"
        );
        let exec_info = std::fs::read_to_string(&info).expect("exec info");
        assert!(exec_info.contains(r#""interactive":false"#), "{exec_info}");
    }

    #[tokio::test]
    async fn a_plugin_token_is_used_and_nothing_of_the_plugin_is_logged() {
        let _ = logs();
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let plugin = script(
            dir.path(),
            "get-token",
            &format!(
                "echo STDERR-CANARY >&2\n{}\n",
                credential("PLUGIN-TOKEN-CANARY", None)
            ),
        );
        let loaded = load_text(dir.path(), &api.url(), &exec_user(&plugin), TIMEOUT).await;
        assert_eq!(loaded.line().plugin(), Some("get-token"));

        loaded
            .connect(&common::run_probe(), |_| {})
            .await
            .expect("connect");

        let requests = api.requests();
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer plugin-token-canary"),
            "{}",
            requests[0]
        );
        let all = logs();
        assert!(
            !all.contains("PLUGIN-TOKEN-CANARY"),
            "the plugin token reached the log"
        );
        assert!(
            !all.contains("STDERR-CANARY"),
            "plugin stderr reached the log"
        );
    }

    #[tokio::test]
    async fn the_cluster_is_announced_before_the_plugin_starts() {
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("plugin-ran");
        let plugin = script(
            dir.path(),
            "get-token",
            &format!("touch '{}'\n{}\n", marker.display(), credential("t", None)),
        );
        let loaded = load_text(dir.path(), &api.url(), &exec_user(&plugin), TIMEOUT).await;
        let seen = marker.clone();

        loaded
            .connect(&common::run_probe(), move |line| {
                assert!(
                    !seen.exists(),
                    "the plugin ran before the cluster was announced"
                );
                assert!(
                    line.to_string().contains("credential plugin: get-token"),
                    "{line}"
                );
            })
            .await
            .expect("connect");

        assert!(marker.exists(), "the plugin never ran");
    }

    #[tokio::test]
    async fn a_failing_plugin_keeps_its_exit_code_and_none_of_its_output() {
        let _ = logs();
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let plugin = script(
            dir.path(),
            "get-token",
            "echo STDOUT-CANARY\necho STDERR-CANARY >&2\nexit 3\n",
        );
        let loaded = load_text(dir.path(), &api.url(), &exec_user(&plugin), TIMEOUT).await;

        let error = loaded
            .connect(&common::run_probe(), |_| {})
            .await
            .expect_err("plugin fails");

        assert!(
            matches!(&error, KubeError::PluginFailed { plugin, exit_code: Some(3) } if plugin == "get-token"),
            "{error:?}"
        );
        assert_clean(&error);
        assert!(
            api.requests().is_empty(),
            "no request may follow a failed plugin"
        );
        let all = logs();
        assert!(
            !all.contains("STDOUT-CANARY") && !all.contains("STDERR-CANARY"),
            "plugin output reached the log"
        );
    }

    #[tokio::test]
    async fn a_plugin_that_prints_garbage_is_reported_without_quoting_it() {
        let _ = logs();
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let plugin = script(dir.path(), "get-token", "echo 'STDOUT-CANARY: [not json'\n");
        let loaded = load_text(dir.path(), &api.url(), &exec_user(&plugin), TIMEOUT).await;

        let error = loaded
            .connect(&common::run_probe(), |_| {})
            .await
            .expect_err("bad output");

        assert!(
            matches!(error, KubeError::PluginOutputInvalid { .. }),
            "{error:?}"
        );
        assert_clean(&error);
        assert!(
            !logs().contains("STDOUT-CANARY"),
            "plugin output reached the log"
        );
    }

    #[tokio::test]
    async fn a_plugin_that_cannot_start_is_reported() {
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let loaded = load_text(
            dir.path(),
            &api.url(),
            &exec_user(&dir.path().join("does-not-exist")),
            TIMEOUT,
        )
        .await;
        let error = loaded
            .connect(&common::run_probe(), |_| {})
            .await
            .expect_err("no plugin");
        assert!(
            matches!(&error, KubeError::PluginNotStarted { reason, .. } if *reason == "no such command"),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_refresh_that_fails_during_the_request_leaks_nothing() {
        let _ = logs();
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        // The first run hands out a token that has already expired, so the first request refreshes
        // it inside kube. The second run fails and prints canaries.
        let counter = dir.path().join("count");
        let plugin = script(
            dir.path(),
            "get-token",
            &format!(
                "n=$(cat '{c}' 2>/dev/null || echo 0)\necho $((n+1)) > '{c}'\nif [ \"$n\" -eq 0 ]; then\n{first}\nelse\necho REFRESH-CANARY\necho STDERR-CANARY >&2\nexit 4\nfi\n",
                c = counter.display(),
                first = credential("FIRST-TOKEN", Some("2000-01-01T00:00:00Z")),
            ),
        );
        let loaded = load_text(dir.path(), &api.url(), &exec_user(&plugin), TIMEOUT).await;

        let error = loaded
            .connect(&common::run_probe(), |_| {})
            .await
            .expect_err("refresh fails");

        assert!(
            matches!(
                &error,
                KubeError::PluginFailed {
                    exit_code: Some(4),
                    ..
                }
            ),
            "{error:?}"
        );
        assert_clean(&error);
        let all = logs();
        assert!(
            !all.contains("REFRESH-CANARY") && !all.contains("STDERR-CANARY"),
            "plugin output reached the log"
        );
        assert!(
            !all.contains("FIRST-TOKEN"),
            "a plugin token reached the log"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_slow_plugin_does_not_hold_the_only_worker() {
        let api = MockApi::start(Mode::Version).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let flag = dir.path().join("release");
        // The plugin waits for the flag. If building the client ran on the runtime thread, the thread
        // would sit in the plugin and the task below, which sets the flag, could never run.
        let plugin = script(
            dir.path(),
            "get-token",
            &format!(
                "i=0\nwhile [ ! -f '{f}' ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done\nif [ ! -f '{f}' ]; then exit 9; fi\n{cred}\n",
                f = flag.display(),
                cred = credential("t", None),
            ),
        );
        let loaded = load_text(
            dir.path(),
            &api.url(),
            &exec_user(&plugin),
            Duration::from_secs(30),
        )
        .await;

        let release = async {
            tokio::task::yield_now().await;
            std::fs::write(&flag, "go").expect("write flag");
        };
        let probe = common::run_probe();
        let (connected, ()) = tokio::join!(loaded.connect(&probe, |_| {}), release);

        connected.expect("the client was built while the runtime thread stayed free");
    }
}
