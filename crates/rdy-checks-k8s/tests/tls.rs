//! The kube client over real TLS (rustls on ring) against a local server with a throwaway CA.
//!
//! These prove the pieces `client.rs` cannot with plain HTTP: the CA in the kubeconfig is the trust
//! anchor, a certificate from another CA is refused with the rustls reason in the error, and
//! `insecure-skip-tls-verify` is honoured and shown on the cluster line. A kubeconfig with no CA trusts
//! the bundled web roots and nothing the system or the environment adds (ADR 0031 decision 9). Keys are
//! made in memory for each test. Nothing is written but the CA certificate.

#![allow(clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{is_child, run_child};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rdy_checks_k8s::client::{Env, KubeError, KubeOptions, Loaded, load};
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
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, name);
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = CertificateParams::new(vec![leaf_name.to_owned()])
        .expect("leaf params")
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
        .connect(|_| {})
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
        .connect(|_| {})
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
        .connect(|_| {})
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
        .connect(move |line| *seen.lock().expect("shown") = line.to_string())
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
        .connect(|_| {})
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
