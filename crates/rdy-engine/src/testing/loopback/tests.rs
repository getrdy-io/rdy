//! The smoke tests of M1-090: each server is started and a raw client sees the behaviour it is for.
//! They run on all five legs, so they use only loopback, port 0 and upper-bound timeouts.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::client::ClientConfig;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{CertificateError, Error as TlsError, RootCertStore};
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::*;

/// Upper bound for any wait in these tests. Nothing sleeps to this long when the server behaves.
const LIMIT: Duration = Duration::from_secs(20);

fn client_config(roots: &[&CertificateDer<'static>]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add((*root).clone()).expect("add the root");
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// A TCP connect that cannot hang the test. A timeout is an `io::Error` of kind `TimedOut`.
async fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    timeout(LIMIT, TcpStream::connect(addr))
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

async fn tls_connect(
    addr: SocketAddr,
    name: &'static str,
    config: Arc<ClientConfig>,
) -> io::Result<TlsStream<TcpStream>> {
    let tcp = connect(addr).await?;
    let name = ServerName::try_from(name).expect("a server name");
    timeout(LIMIT, TlsConnector::from(config).connect(name, tcp)).await?
}

/// The rustls error inside the `io::Error` of a failed handshake.
fn tls_error(e: &io::Error) -> &TlsError {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
        .unwrap_or_else(|| panic!("not a TLS error: {e:?}"))
}

async fn read_all(mut stream: impl AsyncReadExt + Unpin) -> String {
    let mut out = Vec::new();
    let _ = timeout(LIMIT, stream.read_to_end(&mut out))
        .await
        .expect("no hang");
    String::from_utf8_lossy(&out).into_owned()
}

async fn get_over_tls(mut tls: TlsStream<TcpStream>) -> String {
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write the request");
    read_all(tls).await
}

#[tokio::test]
async fn the_tls_server_validates_only_when_the_test_ca_is_trusted() {
    let ca = TestCa::root("rdy test root");
    let server = HttpServer::start(HttpOptions::tls(
        &ca.issue(&["localhost"], Validity::Always),
    ))
    .await
    .expect("start");

    let tls = tls_connect(server.addr(), "localhost", client_config(&[ca.root_der()]))
        .await
        .expect("a chain from a trusted CA validates");
    let reply = get_over_tls(tls).await;
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    assert!(
        reply.contains("Date: Thu, 01 Jan 2026 00:00:00 GMT\r\n"),
        "{reply}"
    );
    assert_eq!(server.sni_seen(), [Some("localhost".to_owned())]);
    assert_eq!(server.requests()[0].method, "GET");

    let other = TestCa::root("another root");
    let e = tls_connect(
        server.addr(),
        "localhost",
        client_config(&[other.root_der()]),
    )
    .await
    .expect_err("an unknown issuer is refused");
    assert!(
        matches!(
            tls_error(&e),
            TlsError::InvalidCertificate(CertificateError::UnknownIssuer)
        ),
        "{e:?}"
    );

    let e = tls_connect(
        server.addr(),
        "wrong.example",
        client_config(&[ca.root_der()]),
    )
    .await
    .expect_err("a name the leaf does not cover is refused");
    assert!(
        matches!(
            tls_error(&e),
            TlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            )
        ),
        "{e:?}"
    );
}

#[tokio::test]
async fn an_ip_address_leaf_validates_for_an_ip_server_name() {
    let ca = TestCa::root("rdy test root");
    let server = HttpServer::start(HttpOptions::tls(
        &ca.issue(&["127.0.0.1"], Validity::Always),
    ))
    .await
    .expect("start");
    let tls = tls_connect(server.addr(), "127.0.0.1", client_config(&[ca.root_der()]))
        .await
        .expect("the IP SAN matches");
    assert!(get_over_tls(tls).await.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn an_intermediate_is_sent_and_the_root_is_not() {
    let root = TestCa::root("rdy test root");
    let inner = root.intermediate("rdy test intermediate");
    let leaf = inner.issue(&["localhost"], Validity::Always);
    assert_eq!(leaf.chain().len(), 2, "leaf and intermediate");
    let server = HttpServer::start(HttpOptions::tls(&leaf))
        .await
        .expect("start");

    let tls = tls_connect(
        server.addr(),
        "localhost",
        client_config(&[root.root_der()]),
    )
    .await
    .expect("the chain validates to the root");
    let sent = tls.get_ref().1.peer_certificates().expect("a chain").len();
    assert_eq!(sent, 2);

    // `root_der` of an intermediate is the root's, and its own certificate differs.
    assert_eq!(root.root_der(), inner.root_der());
    assert_ne!(root.der(), inner.der());
}

#[tokio::test]
async fn an_expired_and_a_not_yet_valid_leaf_are_refused_for_their_dates() {
    let ca = TestCa::root("rdy test root");
    for (validity, expired) in [(Validity::Expired, true), (Validity::NotYetValid, false)] {
        let server = HttpServer::start(HttpOptions::tls(&ca.issue(&["localhost"], validity)))
            .await
            .expect("start");
        let e = tls_connect(server.addr(), "localhost", client_config(&[ca.root_der()]))
            .await
            .expect_err("a leaf outside its dates is refused");
        let TlsError::InvalidCertificate(c) = tls_error(&e) else {
            panic!("{e:?}");
        };
        if expired {
            assert!(
                matches!(
                    c,
                    CertificateError::Expired | CertificateError::ExpiredContext { .. }
                ),
                "{c:?}"
            );
        } else {
            assert!(
                matches!(
                    c,
                    CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
                ),
                "{c:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_handshake_that_sends_no_request_costs_the_server_zero_application_bytes() {
    let ca = TestCa::root("rdy test root");
    let server = HttpServer::start(
        HttpOptions::tls(&ca.issue(&["localhost"], Validity::Always)).alpn(&["http/1.1"]),
    )
    .await
    .expect("start");
    let mut tls = tls_connect(server.addr(), "localhost", client_config(&[ca.root_der()]))
        .await
        .expect("handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    tls.shutdown().await.expect("close_notify");
    // The server closes after it reads the close_notify, so the end of the stream is the proof that
    // its counters are final.
    let rest = read_all(tls).await;
    assert!(rest.is_empty(), "{rest}");
    assert_eq!(server.handshakes(), 1);
    assert_eq!(server.application_bytes(), 0);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn the_server_replies_with_the_status_and_date_it_was_given() {
    let server = HttpServer::start(
        HttpOptions::plain()
            .reply(Reply::Status(503))
            .date("Fri, 02 Jan 2026 00:00:00 GMT"),
    )
    .await
    .expect("start");
    let mut tcp = connect(server.addr()).await.expect("connect");
    tcp.write_all(b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .expect("write");
    let reply = read_all(tcp).await;
    assert!(
        reply.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "{reply}"
    );
    assert!(
        reply.contains("Date: Fri, 02 Jan 2026 00:00:00 GMT\r\n"),
        "{reply}"
    );
    assert_eq!(server.requests()[0].target, "/x");
    assert_eq!(server.requests()[0].header("host"), Some("h"));
}

#[tokio::test]
async fn the_redirect_server_answers_302_with_a_location() {
    let server = HttpServer::redirect("https://second.acme.example/")
        .await
        .expect("start");
    let mut tcp = connect(server.addr()).await.expect("connect");
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: first\r\n\r\n")
        .await
        .expect("write");
    let reply = read_all(tcp).await;
    assert!(reply.starts_with("HTTP/1.1 302 Found\r\n"), "{reply}");
    assert!(
        reply.contains("Location: https://second.acme.example/\r\n"),
        "{reply}"
    );
}

/// Sends a CONNECT with a synthetic credential and returns what the proxy answered up to the blank
/// line, with the stream for a tunnel.
async fn connect_through(proxy: SocketAddr, target: &str) -> (String, TcpStream) {
    let mut tcp = connect(proxy).await.expect("connect to the proxy");
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"
    );
    tcp.write_all(request.as_bytes())
        .await
        .expect("write CONNECT");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = timeout(LIMIT, tcp.read(&mut byte))
            .await
            .expect("no hang")
            .expect("read");
        if n == 0 {
            break;
        }
        head.push(byte[0]);
    }
    (String::from_utf8_lossy(&head).into_owned(), tcp)
}

#[tokio::test]
async fn the_proxy_in_ok_mode_tunnels_to_a_routed_loopback_server() {
    let origin = HttpServer::start(HttpOptions::plain())
        .await
        .expect("origin");
    let proxy = ConnectProxy::start_with_routes(
        ProxyMode::Ok,
        &[("Registry.Acme.Example:443", origin.addr())],
    )
    .await
    .expect("proxy");

    let (head, mut tunnel) = connect_through(proxy.addr(), "registry.acme.example:443").await;
    assert!(
        head.starts_with("HTTP/1.1 200 Connection Established\r\n"),
        "{head}"
    );
    tunnel
        .write_all(b"GET / HTTP/1.1\r\nHost: registry.acme.example\r\n\r\n")
        .await
        .expect("write through the tunnel");
    let reply = read_all(tunnel).await;
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");

    let requests = proxy.requests();
    assert_eq!(requests[0].target, "registry.acme.example:443");
    assert_eq!(
        requests[0].proxy_authorization.as_deref(),
        Some("Basic dGVzdDp0ZXN0")
    );
    assert!(proxy.url().starts_with("http://127.0.0.1:"));
}

#[tokio::test]
async fn the_proxy_in_ok_mode_never_dials_a_name_it_has_no_route_for() {
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let (head, _) = connect_through(proxy.addr(), "registry.acme.example:443").await;
    assert!(head.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{head}");
    let (head, _) = connect_through(proxy.addr(), "169.254.169.254:80").await;
    assert!(head.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{head}");
}

#[tokio::test]
async fn the_proxy_refuses_with_403_and_with_both_407_challenges() {
    for (mode, status, challenge) in [
        (ProxyMode::Forbidden, "403 Forbidden", None),
        (
            ProxyMode::Basic407,
            "407 Proxy Authentication Required",
            Some("Proxy-Authenticate: Basic realm=\"rdy-test\"\r\n"),
        ),
        (
            ProxyMode::Negotiate407,
            "407 Proxy Authentication Required",
            Some("Proxy-Authenticate: Negotiate\r\n"),
        ),
    ] {
        let proxy = ConnectProxy::start(mode).await.expect("proxy");
        let (head, tcp) = connect_through(proxy.addr(), "127.0.0.1:443").await;
        assert!(
            head.starts_with(&format!("HTTP/1.1 {status}\r\n")),
            "{mode:?}: {head}"
        );
        if let Some(challenge) = challenge {
            assert!(head.contains(challenge), "{mode:?}: {head}");
        }
        assert!(
            read_all(tcp).await.is_empty(),
            "{mode:?}: the proxy closes after a refusal"
        );
        assert_eq!(proxy.requests().len(), 1);
    }
}

#[tokio::test]
async fn a_client_that_sends_nothing_leaves_the_proxy_with_zero_bytes() {
    let proxy = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let mut tcp = connect(proxy.addr()).await.expect("connect");
    tcp.shutdown().await.expect("shutdown");
    assert!(read_all(tcp).await.is_empty());
    assert_eq!(proxy.bytes_received(), 0);
    assert!(proxy.requests().is_empty());
}

#[tokio::test]
async fn the_proxy_refuses_a_method_that_is_not_connect() {
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let mut tcp = connect(proxy.addr()).await.expect("connect");
    tcp.write_all(b"GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n")
        .await
        .expect("write");
    let reply = read_all(tcp).await;
    assert!(reply.starts_with("HTTP/1.1 405 "), "{reply}");
    assert!(proxy.requests().is_empty());
}

#[tokio::test]
async fn a_closed_port_refuses_the_connection() {
    let addr = closed_port().await.expect("a port");
    let e = connect(addr).await.expect_err("nothing listens");
    assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "{e:?}");
}

#[tokio::test]
async fn a_listener_that_never_accepts_completes_the_connect_and_never_answers() {
    let server = NeverAccepts::start().await.expect("start");
    let mut tcp = connect(server.addr())
        .await
        .expect("the kernel completes the connect");
    tcp.write_all(b"hello").await.expect("a write succeeds");
    let mut buf = [0u8; 1];
    let waited = timeout(Duration::from_millis(300), tcp.read(&mut buf)).await;
    assert!(waited.is_err(), "a read returned: {waited:?}");
}

#[tokio::test]
async fn a_reset_after_the_client_hello_is_a_reset_and_not_a_close() {
    let server = ResetAfterClientHello::start().await.expect("start");
    let mut tcp = connect(server.addr()).await.expect("connect");
    // A TLS handshake record header (type 22, version 3.1, length 4) and a four byte body.
    tcp.write_all(&[0x16, 3, 1, 0, 4, 1, 0, 0, 0])
        .await
        .expect("write the hello");
    let mut buf = [0u8; 16];
    let read = timeout(LIMIT, tcp.read(&mut buf)).await.expect("no hang");
    let e = read.expect_err("a reset is an error, not an end of stream");
    assert!(
        matches!(
            e.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
        ),
        "{e:?}"
    );
    assert_eq!(server.accepted(), 1);
    assert_eq!(server.hello_bytes(), 9);
}

#[tokio::test]
async fn a_real_tls_client_sees_the_reset_as_an_error() {
    // This accepts `UnexpectedEof` too, because rustls may report a reset as an end of stream, so it
    // cannot tell a reset from a FIN. The raw client test above carries the proof that it is a reset.
    let server = ResetAfterClientHello::start().await.expect("start");
    let ca = TestCa::root("rdy test root");
    let e = tls_connect(server.addr(), "localhost", client_config(&[ca.root_der()]))
        .await
        .expect_err("the handshake cannot finish");
    assert!(
        matches!(
            e.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::UnexpectedEof
        ),
        "{e:?}"
    );
    assert!(server.hello_bytes() > 5, "the server read a ClientHello");
}

#[tokio::test]
async fn the_dual_stack_case_has_a_live_v4_address_and_a_dead_v6_address_on_one_port() {
    let ca = TestCa::root("rdy test root");
    let dual = DualStack::start(HttpOptions::tls(
        &ca.issue(&["localhost"], Validity::Always),
    ))
    .await
    .expect("start");
    assert_eq!(dual.v4().port(), dual.dead_v6().port());
    assert!(dual.v4().is_ipv4() && dual.dead_v6().is_ipv6());

    let e = connect(dual.dead_v6())
        .await
        .expect_err("the v6 address is dead");
    if ipv6_loopback_available().await {
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "{e:?}");
    }

    let tls = tls_connect(dual.v4(), "localhost", client_config(&[ca.root_der()]))
        .await
        .expect("the v4 address answers");
    assert!(get_over_tls(tls).await.starts_with("HTTP/1.1 200"));
    assert_eq!(dual.server().handshakes(), 1);
}

#[tokio::test]
async fn dropping_a_server_closes_its_port() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("start");
    let addr = server.addr();
    drop(server);
    // The accept task ends on its next poll, which needs a turn of the scheduler.
    let mut refused = false;
    for _ in 0..200 {
        tokio::task::yield_now().await;
        if connect(addr).await.is_err() {
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "the port still accepts after the server was dropped"
    );
}

#[test]
#[should_panic(expected = "not a loopback address")]
fn a_route_to_an_address_off_loopback_panics() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let off_loopback = SocketAddr::from(([203, 0, 113, 7], 443));
    let _ = runtime.block_on(ConnectProxy::start_with_routes(
        ProxyMode::Ok,
        &[("registry.acme.example:443", off_loopback)],
    ));
}

#[test]
fn a_leaf_does_not_print_its_key() {
    let ca = TestCa::root("rdy test root");
    let leaf = ca.issue(&["localhost"], Validity::Always);
    let shown = format!("{leaf:?}");
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(!shown.contains("key_pkcs8: ["), "{shown}");
}
