//! The kube client over real TLS (rustls on ring) against a local server with a throwaway CA.
//!
//! These prove the pieces `client.rs` cannot with plain HTTP: the CA in the kubeconfig is the trust
//! anchor, a certificate from another CA is refused with the rustls reason in the error, and
//! `insecure-skip-tls-verify` is honoured and shown on the cluster line. A kubeconfig with no CA trusts
//! the bundled web roots and nothing the system or the environment adds (ADR 0031 decision 9). Keys are
//! made in memory for each test. Nothing is written but the CA certificate.

#![allow(clippy::expect_used)]
// These are tests of the client module. They start mock servers, write kubeconfigs and run plugin
// scripts, which the lint wall bans in the rest of this crate (INV-07). This file is on the allowlist of
// tests/lint-wall/tests/allow_grep.rs. A test of a check does not belong here: use the probe.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{is_child, run_child};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rdy_checks_k8s::client::{Env, KubeError, KubeOptions, Loaded, load};
use rdy_engine::check::Os;
use rdy_engine::testing::{Replay, TestRun};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const VERSION_JSON: &str = r#"{"major":"1","minor":"30","gitVersion":"v1.30.2","gitCommit":"0000","gitTreeState":"clean","buildDate":"2024-06-01T00:00:00Z","goVersion":"go1.22.4","compiler":"gc","platform":"linux/arm64"}"#;

/// A CA, and a server certificate for 127.0.0.1 signed by it.
struct Pki {
    ca_pem: String,
    server: TlsAcceptor,
}

fn pki(name: &str) -> Pki {
    pki_for(name, "127.0.0.1")
}

/// A CA, and a server certificate for `leaf_name` signed by it.
fn pki_for(name: &str, leaf_name: &str) -> Pki {
    pki_dated(name, leaf_name, false)
}

/// Like [`pki_for`]. With `expired` the server certificate ended in 2021.
fn pki_dated(name: &str, leaf_name: &str, expired: bool) -> Pki {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, name);
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec![leaf_name.to_owned()]).expect("leaf params");
    if expired {
        leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    }
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![leaf.der().clone()], key)
    .expect("server config");
    Pki {
        ca_pem: ca.pem(),
        server: TlsAcceptor::from(Arc::new(config)),
    }
}

/// Serves `GET /version` over TLS until the test ends.
async fn serve(acceptor: TlsAcceptor) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
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

/// A kubeconfig that trusts `ca_pem`, with the extra cluster lines.
async fn loaded(dir: &Path, addr: SocketAddr, ca_pem: &str, cluster_extra: &str) -> Loaded {
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ca_pem).expect("write ca");
    let text = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: https://{addr}\n    certificate-authority: {}\n{cluster_extra}contexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n    token: t\n",
        ca_file.display()
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

#[tokio::test]
async fn a_server_certificate_from_the_kubeconfig_ca_is_trusted() {
    let pki = pki("rdy test ca");
    let addr = serve(pki.server.clone()).await;
    let dir = tempfile::tempdir().expect("tempdir");

    let connected = loaded(dir.path(), addr, &pki.ca_pem, "")
        .await
        .connect(&common::run_probe(), |_| {})
        .await
        .expect("connect over TLS");

    assert_eq!(connected.server_version().git_version, "v1.30.2");
    assert_eq!(connected.server_version().platform, "linux/arm64");
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused_with_the_reason() {
    let served = pki("rdy served ca");
    let other = pki("rdy other ca");
    let addr = serve(served.server.clone()).await;
    let dir = tempfile::tempdir().expect("tempdir");

    let error = loaded(dir.path(), addr, &other.ca_pem, "")
        .await
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("unknown issuer");

    assert!(
        matches!(&error, KubeError::Unreachable { cause, ca_set: true, .. } if cause.contains("UnknownIssuer")),
        "{error:?}"
    );
    // A CA is set, so the hint is about the CA that does not match (03, k8s.access).
    assert!(
        error.hint().contains("does not match this server")
            && error.hint().contains("net.tls_intercept"),
        "{}",
        error.hint()
    );
}

#[tokio::test]
async fn a_certificate_for_another_name_gets_its_own_phrase() {
    // rustls 0.23 words this as "certificate not valid for name ...", not with the Debug name.
    let pki = pki_for("rdy test ca", "localhost");
    let addr = serve(pki.server.clone()).await;
    let dir = tempfile::tempdir().expect("tempdir");

    let error = loaded(dir.path(), addr, &pki.ca_pem, "")
        .await
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("the certificate is for localhost, the address is 127.0.0.1");

    assert!(
        matches!(&error, KubeError::Unreachable { cause, .. } if cause.contains("NotValidForName")),
        "{error:?}"
    );
}

#[tokio::test]
async fn insecure_skip_tls_verify_connects_and_the_line_says_so() {
    let served = pki("rdy served ca");
    let other = pki("rdy other ca");
    let addr = serve(served.server.clone()).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let loaded = loaded(
        dir.path(),
        addr,
        &other.ca_pem,
        "    insecure-skip-tls-verify: true\n",
    )
    .await;
    assert!(loaded.line().tls_verification_off());
    let shown = Arc::new(std::sync::Mutex::new(String::new()));
    let seen = Arc::clone(&shown);

    loaded
        .connect(&common::run_probe(), move |line| {
            *seen.lock().expect("shown") = line.to_string()
        })
        .await
        .expect("connect with verification off");

    assert!(
        shown
            .lock()
            .expect("shown")
            .ends_with(", TLS verification is OFF")
    );
}

#[tokio::test]
async fn without_a_ca_in_the_kubeconfig_only_the_bundled_roots_are_trusted() {
    const NAME: &str = "without_a_ca_in_the_kubeconfig_only_the_bundled_roots_are_trusted";
    if !is_child() {
        // SSL_CERT_FILE is how the system trust store is steered on Linux. A verifier that reads the
        // system roots would trust the CA the child writes there. The bundled roots ignore it.
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("system-ca.pem");
        run_child(
            NAME,
            &[
                ("SSL_CERT_FILE", ca.to_str().expect("utf8 path")),
                (
                    "SSL_CERT_DIR",
                    dir.path().join("none").to_str().expect("utf8 path"),
                ),
                ("RDY_TEST_DIR", dir.path().to_str().expect("utf8 path")),
            ],
        );
        return;
    }
    let dir = PathBuf::from(std::env::var_os("RDY_TEST_DIR").expect("RDY_TEST_DIR"));
    let pki = pki("rdy system ca");
    std::fs::write(dir.join("system-ca.pem"), &pki.ca_pem).expect("write the system CA");
    let addr = serve(pki.server.clone()).await;
    let text = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: https://{addr}\ncontexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n    token: t\n"
    );
    let path = dir.join("kubeconfig");
    std::fs::write(&path, text).expect("write kubeconfig");
    let loaded = load(
        &KubeOptions::new(Duration::from_secs(10)).kubeconfig(path),
        &Env::empty(),
    )
    .await
    .expect("load");

    let error = loaded
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("the CA in SSL_CERT_FILE must not be trusted");

    assert!(
        matches!(&error, KubeError::Unreachable { cause, ca_set: false, .. } if cause.contains("UnknownIssuer")),
        "{error:?}"
    );
    // No CA is set, so the hint says rdy trusts only its bundled roots (ADR 0031 decision 9).
    let hint = error.hint();
    assert!(
        hint.contains("names no certificate authority")
            && hint.contains("not this machine's store")
            && hint.contains("certificate-authority"),
        "{hint}"
    );
}

// ---- the proxy (ADR 0037) ---------------------------------------------------------------------------------

/// What the stand-in proxy does with a `CONNECT`.
#[derive(Clone, Copy)]
enum ProxyMode {
    /// Answer 200 and carry the bytes to this server.
    Tunnel(SocketAddr),
    /// Answer with this status and close.
    Status(u16),
}

/// A proxy on 127.0.0.1 and the request heads it was sent.
async fn proxy(mode: ProxyMode) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let heads = Arc::new(std::sync::Mutex::new(Vec::new()));
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
                log.lock()
                    .expect("log")
                    .push(String::from_utf8_lossy(&head).into_owned());
                match mode {
                    ProxyMode::Status(code) => {
                        let reply = format!("HTTP/1.1 {code} X\r\ncontent-length: 0\r\n\r\n");
                        let _ = stream.write_all(reply.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    }
                    ProxyMode::Tunnel(target) => {
                        let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                            return;
                        };
                        if stream
                            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                    }
                }
            });
        }
    });
    (addr, heads)
}

const API_NAME: &str = "k8s.acme.example";
const API_URL: &str = "https://k8s.acme.example:6443";

/// A kubeconfig for `API_URL` that trusts `ca_pem`, with the extra cluster lines, loaded with `env`.
async fn loaded_for_name(
    dir: &Path,
    ca_pem: &str,
    cluster_extra: &str,
    env: &Env,
) -> Result<Loaded, KubeError> {
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ca_pem).expect("write ca");
    let text = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n- name: cl\n  cluster:\n    server: {API_URL}\n    certificate-authority: {}\n{cluster_extra}contexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\nusers:\n- name: usr\n  user:\n    token: t\n",
        ca_file.display()
    );
    let path = dir.join("kubeconfig");
    std::fs::write(&path, text).expect("write kubeconfig");
    load(
        &KubeOptions::new(Duration::from_secs(10)).kubeconfig(path),
        env,
    )
    .await
}

#[tokio::test]
async fn a_kubeconfig_proxy_url_carries_the_tls_session_through_a_connect_tunnel() {
    let pki = pki_for("rdy test ca", API_NAME);
    let server = serve(pki.server.clone()).await;
    let (proxy_addr, heads) = proxy(ProxyMode::Tunnel(server)).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let extra = format!("    proxy-url: http://svc:PROXY%2BCANARY-2@{proxy_addr}\n");

    let loaded = loaded_for_name(dir.path(), &pki.ca_pem, &extra, &Env::empty())
        .await
        .expect("load");
    assert_eq!(
        loaded.proxy().rule(),
        &rdy_checks_k8s::client::ProxyRule::KubeconfigProxyUrl
    );
    // The password was written with %2B. Both the written and the decoded form are known secrets.
    for form in ["PROXY%2BCANARY-2", "PROXY+CANARY-2"] {
        assert!(loaded.known_secrets().contains(&form.to_owned()), "{form}");
    }
    let run = TestRun::new(Replay::new());
    let connected = loaded
        .connect(&run.run_probe(Os::Linux), |_| {})
        .await
        .expect("connect through the proxy");

    assert_eq!(connected.server_version().git_version, "v1.30.2");
    // INV-07: the proxy hop is in the action log. The `kube` entry names the proxy origin, with no user
    // info.
    let log = run.action_log();
    let kube: Vec<_> = log
        .actions
        .iter()
        .filter(|entry| entry.kind == rdy_spec::result::ActionKind::Kube)
        .collect();
    assert_eq!(kube.len(), 1, "{kube:?}");
    for entry in kube {
        assert_eq!(
            entry.fields["via_proxy"],
            format!("http://{proxy_addr}"),
            "{entry:?}"
        );
    }
    let logged = serde_json::to_string(&log.actions).expect("json");
    assert!(
        !logged.contains("CANARY") && !logged.contains("svc"),
        "{logged}"
    );
    let heads = heads.lock().expect("heads");
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(
        heads[0].starts_with(&format!("CONNECT {API_NAME}:6443 HTTP/1.1")),
        "{}",
        heads[0]
    );
    // The user info of the proxy URL is sent as Basic credentials, percent-decoded as the facade does.
    assert!(
        heads[0].contains("c3ZjOlBST1hZK0NBTkFSWS0y"),
        "{}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization: basic"),
        "{}",
        heads[0]
    );
    // The proxy password is in no text rdy can show.
    let shown = format!("{connected:?} {:?}", connected.facts());
    assert!(!shown.contains("CANARY"), "{shown}");
    assert!(connected.facts().proxy().is_proxied());
}

#[tokio::test]
async fn https_proxy_in_the_environment_alone_carries_the_session_the_same_way() {
    let pki = pki_for("rdy test ca", API_NAME);
    let server = serve(pki.server.clone()).await;
    let (proxy_addr, heads) = proxy(ProxyMode::Tunnel(server)).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let env = Env::empty().with_https_proxy(format!("http://{proxy_addr}"));

    let loaded = loaded_for_name(dir.path(), &pki.ca_pem, "", &env)
        .await
        .expect("load");
    assert_eq!(
        loaded.proxy().rule(),
        &rdy_checks_k8s::client::ProxyRule::Environment("HTTPS_PROXY")
    );
    let run = TestRun::new(Replay::new());
    loaded
        .connect(&run.run_probe(Os::Linux), |_| {})
        .await
        .expect("connect through the proxy named by HTTPS_PROXY");
    let log = run.action_log();
    let versions: Vec<_> = log
        .actions
        .iter()
        .filter(|entry| entry.kind == rdy_spec::result::ActionKind::Kube)
        .map(|entry| entry.fields["via_proxy"].clone())
        .collect();
    assert_eq!(
        versions,
        [serde_json::json!(format!("http://{proxy_addr}"))]
    );

    let heads = heads.lock().expect("heads");
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(heads[0].starts_with(&format!("CONNECT {API_NAME}:6443 HTTP/1.1")));
    assert!(
        !heads[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
}

#[tokio::test]
async fn a_proxy_that_refuses_the_tunnel_is_named_in_the_cause_and_the_hint() {
    for (code, cause) in [
        (403, "the proxy refused to open a tunnel to the API server"),
        (407, "the proxy asked for credentials (407)"),
        (502, "the proxy refused to open a tunnel to the API server"),
    ] {
        let pki = pki_for("rdy test ca", API_NAME);
        let (proxy_addr, _) = proxy(ProxyMode::Status(code)).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let extra = format!("    proxy-url: http://{proxy_addr}\n");

        let error = loaded_for_name(dir.path(), &pki.ca_pem, &extra, &Env::empty())
            .await
            .expect("load")
            .connect(&common::run_probe(), |_| {})
            .await
            .expect_err("the proxy refuses");

        assert!(
            matches!(&error, KubeError::Unreachable { cause: got, proxied: true, .. } if *got == cause),
            "{code}: {error:?}"
        );
        assert!(
            error.hint().contains("allows CONNECT"),
            "{code}: {}",
            error.hint()
        );
    }
}

#[tokio::test]
async fn a_proxy_nobody_listens_on_is_a_connection_failure_through_a_proxy() {
    let pki = pki_for("rdy test ca", API_NAME);
    // Bind and drop to get a port nothing listens on.
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind")
        .local_addr()
        .expect("addr");
    let dir = tempfile::tempdir().expect("tempdir");
    let extra = format!("    proxy-url: http://{dead}\n");

    let error = loaded_for_name(dir.path(), &pki.ca_pem, &extra, &Env::empty())
        .await
        .expect("load")
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("nothing listens");

    assert!(
        matches!(&error, KubeError::Unreachable { proxied: true, .. }),
        "{error:?}"
    );
    assert!(error.hint().contains("through a proxy"), "{}", error.hint());
}

#[tokio::test]
async fn an_expired_server_certificate_gets_its_own_phrase() {
    let pki = pki_dated("rdy test ca", "127.0.0.1", true);
    let addr = serve(pki.server.clone()).await;
    let dir = tempfile::tempdir().expect("tempdir");

    let error = loaded(dir.path(), addr, &pki.ca_pem, "")
        .await
        .connect(&common::run_probe(), |_| {})
        .await
        .expect_err("the certificate ended in 2021");

    assert!(
        matches!(&error, KubeError::Unreachable { cause, .. } if cause.contains("(Expired)")),
        "{error:?}"
    );
}
