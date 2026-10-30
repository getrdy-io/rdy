//! Tests for the TLS facade (M1-092).
//!
//! The exit test: against loopback servers a test-CA chain validates only when the CA is in the fixture
//! system bundle, `tls_chain` returns the chain without sending application data, SNI always equals the
//! permitted host, the action log has one entry per tls call, and the `SystemRoots` answer is capped.
//! (`cargo tree -i aws-lc-sys` being empty is a CI step and `deny.toml` ban.)
//!
//! The replay backend serves the system bundle from `native/system_roots` and sends each connection to a
//! real loopback server, so the handshakes are real and the roots are the test's own. One test runs the
//! live backend end to end on loopback.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rdy_spec::Target;
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::*;
use crate::check::{CheckInfo, CheckMeta, Os, OsSupport, PeerClass, Support};
use crate::family::HostSet;
use crate::probe::net::{AttemptOutcome, RULE_PROXY_UNDECLARED, RULE_TCP_ADDRESS, RULE_TCP_HOST};
use crate::probe::replay::NativeFailure;
use crate::probe::replay::{Replay, TcpScript};
use crate::probe::{Backend, ProbeHub};
use crate::redact::{Redactor, TagKey};
use crate::testing::loopback::{
    ConnectProxy, HttpOptions, HttpServer, NeverAccepts, ProxyMode, ResetAfterClientHello, TestCa,
    Validity, closed_port,
};

const META: CheckMeta = CheckMeta {
    title: "Fixture check",
    remediation: "Nothing to fix. This check is a test double.",
};

const ALL_OS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

macro_rules! info {
    ($id:literal, $peers:expr) => {{
        static INFO: CheckInfo = CheckInfo {
            id: $id,
            family: "net",
            summary: "A fixture check.",
            meta: META,
            needs: &[],
            wants: &[],
            default_timeout: None,
            os: ALL_OS,
            reads: &[],
            statfs: &[],
            env: &[],
            commands: &[],
            peers: $peers,
        };
        &INFO
    }};
}

fn intercept() -> &'static CheckInfo {
    info!(
        "net.tls_intercept",
        &[PeerClass::SpecHosts, PeerClass::Proxy]
    )
}

fn direct_only() -> &'static CheckInfo {
    info!("net.direct", &[PeerClass::SpecHosts])
}

fn hub_over(backend: impl Backend) -> ProbeHub {
    ProbeHub::new(Arc::new(backend), Redactor::new(TagKey::fixed([5; 32])))
}

fn target(text: &str) -> Target {
    Target::parse(text).expect("a valid target")
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn probe_for(hub: &ProbeHub, info: &'static CheckInfo, hosts: &[&str]) -> Probe {
    let probe = hub.check_probe(info.id, Os::Linux, Some(info));
    probe.permit_hosts(HostSet::new(hosts.iter().map(|t| target(t))));
    probe
}

fn probe(hub: &ProbeHub, hosts: &[&str]) -> Probe {
    probe_for(hub, intercept(), hosts)
}

/// Short waits for the failure cases that end by timeout.
fn quick(probe: &Probe) {
    probe
        .scope
        .peers
        .timeout
        .set(Duration::from_millis(400))
        .expect("set once");
}

fn entries(hub: &ProbeHub) -> Vec<Action> {
    hub.action_log().actions
}

fn of_kind(hub: &ProbeHub, kind: ActionKind) -> Vec<Action> {
    entries(hub)
        .into_iter()
        .filter(|a| a.kind == kind)
        .collect()
}

fn field<'a>(action: &'a Action, name: &str) -> Option<&'a Value> {
    action.fields.get(name)
}

fn der(ca: &TestCa) -> Vec<u8> {
    ca.root_der().as_ref().to_vec()
}

/// A replay machine whose `web.acme.test` is the loopback server, with this OS trust bundle.
fn machine(server: SocketAddr, bundle: Option<Vec<Vec<u8>>>) -> Replay {
    let replay = Replay::new()
        .host("web.acme.test", [ip("127.0.0.1")])
        .tcp(server, TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server);
    match bundle {
        Some(roots) => replay.native(NativeCall::SystemRoots, NativeValue::SystemRoots(roots)),
        None => replay,
    }
}

async fn tls_server(ca: &TestCa, names: &[&str], validity: Validity) -> HttpServer {
    HttpServer::start(HttpOptions::tls(&ca.issue(names, validity)))
        .await
        .expect("server")
}

fn web(server: &HttpServer) -> String {
    format!("web.acme.test:{}", server.addr().port())
}

fn rejected(failure: TrustFailure) -> TrustVerdict {
    TrustVerdict::Rejected(failure)
}

// ---- the verdicts -------------------------------------------------------------------------------

#[tokio::test]
async fn a_chain_validates_only_when_its_ca_is_in_the_system_bundle() {
    let ca = TestCa::root("Acme Test Root");
    let issuing = ca.intermediate("Acme Issuing CA");
    let leaf = issuing.issue(&["web.acme.test"], Validity::Always);
    let server = HttpServer::start(HttpOptions::tls(&leaf))
        .await
        .expect("server");
    let at = web(&server);

    // The CA is in the fixture system bundle: valid. The bundled Mozilla roots do not hold it.
    let hub = hub_over(machine(server.addr(), Some(vec![der(&ca)])));
    let chain = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.system, TrustVerdict::Valid);
    assert_eq!(chain.bundled, rejected(TrustFailure::UnknownIssuer));
    assert_eq!(chain.system_roots, 1);
    assert_eq!(chain.verdict(Roots::System), TrustVerdict::Valid);
    // The chain is what the server sent: the leaf, then the issuing CA, and not the root.
    let sent: Vec<Vec<u8>> = leaf.chain().iter().map(|c| c.as_ref().to_vec()).collect();
    assert_eq!(sent.len(), 2);
    assert_eq!(chain.certs, sent);
    assert!(!chain.certs.contains(&der(&ca)));

    // The bundle holds another CA only: the same chain is rejected, with the same server.
    let other = TestCa::root("Other Root");
    let hub = hub_over(machine(server.addr(), Some(vec![der(&other)])));
    let chain = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.system, rejected(TrustFailure::UnknownIssuer));
    assert_eq!(chain.certs, sent);

    // An OS with no trust store at all: nothing to judge against, which is not a rejection.
    let hub = hub_over(machine(server.addr(), Some(Vec::new())));
    let chain = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.system, TrustVerdict::Unavailable(NoRoots::Empty));
    assert_eq!(chain.system_roots, 0);
    assert_eq!(chain.bundled, rejected(TrustFailure::UnknownIssuer));
}

#[tokio::test]
async fn expired_not_yet_valid_and_misnamed_leaves_are_told_apart() {
    let ca = TestCa::root("Acme Test Root");
    let cases = [
        (
            Validity::Expired,
            "web.acme.test",
            TrustFailure::Expired,
            true,
        ),
        (
            Validity::NotYetValid,
            "web.acme.test",
            TrustFailure::NotYetValid,
            true,
        ),
        (
            Validity::Always,
            "other.acme.test",
            TrustFailure::NameMismatch,
            false,
        ),
    ];
    for (validity, name, expected, clock) in cases {
        let server = tls_server(&ca, &[name], validity).await;
        let at = web(&server);
        let hub = hub_over(machine(server.addr(), Some(vec![der(&ca)])));
        let chain = probe(&hub, &[&at])
            .tls_chain(&target(&at), Route::Direct)
            .await
            .expect("a chain is still returned");
        assert_eq!(chain.system, rejected(expected), "{validity:?} {name}");
        assert_eq!(expected.is_clock_or_expiry(), clock);
        assert_eq!(chain.certs.len(), 1);
    }
}

#[test]
fn verifier_errors_map_to_failure_classes() {
    use record::failure_of;
    use rustls::CertificateError as C;
    use rustls::Error as E;
    use rustls::pki_types::UnixTime;
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1));
    let table = [
        (C::UnknownIssuer, TrustFailure::UnknownIssuer),
        (C::Expired, TrustFailure::Expired),
        (
            C::ExpiredContext {
                time: now,
                not_after: now,
            },
            TrustFailure::Expired,
        ),
        (C::NotValidYet, TrustFailure::NotYetValid),
        (
            C::NotValidYetContext {
                time: now,
                not_before: now,
            },
            TrustFailure::NotYetValid,
        ),
        (C::NotValidForName, TrustFailure::NameMismatch),
        (C::BadSignature, TrustFailure::BadSignature),
        (C::BadEncoding, TrustFailure::Policy),
        (C::Revoked, TrustFailure::Policy),
    ];
    for (error, expected) in table {
        assert_eq!(failure_of(&E::InvalidCertificate(error)), expected);
    }
    assert_eq!(
        failure_of(&E::General("x".to_owned())),
        TrustFailure::Policy
    );
}

#[test]
fn the_bundled_roots_build_a_verifier_and_an_empty_set_does_not() {
    let provider = provider();
    let bundled = Trust::bundled(&provider);
    assert!(bundled.roots() > 100, "{}", bundled.roots());
    assert!(bundled.verifier.is_some());
    let none = Trust::from_der(&[], &provider);
    assert_eq!(none.roots(), 0);
    assert!(none.verifier.is_none());
    // Bytes that are not a certificate are left out of the count.
    let junk = Trust::from_der(&[vec![1, 2, 3]], &provider);
    assert_eq!(junk.roots(), 0);
}

// ---- no application data, and SNI --------------------------------------------------------------

/// Waits for the server to count a finished handshake: the client is done a moment before the server.
async fn handshakes_settle(server: &HttpServer, expected: usize) {
    for _ in 0..200 {
        if server.handshakes() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the server counted {} handshakes", server.handshakes());
}

#[tokio::test]
async fn tls_chain_writes_no_application_data() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test"], Validity::Always).await;
    let at = web(&server);
    let hub = hub_over(machine(server.addr(), Some(vec![der(&ca)])));
    let chain = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.system, TrustVerdict::Valid);
    handshakes_settle(&server, 1).await;
    assert_eq!(server.application_bytes(), 0);
    assert!(server.requests().is_empty());
    assert_eq!(server.handshakes(), 1);
    // The handshake offered h2 and http/1.1 and the server (no ALPN configured) chose neither.
    assert_eq!(chain.alpn, None);
    assert!(matches!(chain.protocol, Some("TLS 1.2" | "TLS 1.3")));

    // Positive control: the counter does count when a client does send a request, so the zero above
    // is not a counter that never moves.
    let mut roots = RootCertStore::empty();
    roots.add(ca.root_der().clone()).expect("root");
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(server.addr()).await.expect("connect");
    let name = ServerName::try_from("web.acme.test").expect("name");
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("a trusted chain validates");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: web.acme.test\r\n\r\n")
        .await
        .expect("write");
    let mut reply = Vec::new();
    let _ = timeout(Duration::from_secs(10), tls.read_to_end(&mut reply)).await;
    assert!(server.application_bytes() > 0);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn sni_is_the_permitted_host_and_nothing_else() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test", "127.0.0.1"], Validity::Always).await;
    let at = web(&server);

    // Direct: the server sees the spec host, not the address the lookup returned.
    let hub = hub_over(machine(server.addr(), Some(vec![der(&ca)])));
    let direct = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(direct.sni.as_deref(), Some("web.acme.test"));
    // The server records each handshake when it finishes it, so wait before the next call or the order
    // of `sni_seen` is the server's to choose.
    handshakes_settle(&server, 1).await;

    // Through a proxy: the CONNECT target and the SNI are the spec host, not the proxy's name.
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let replay = Replay::new()
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(
            addr("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_tcp("proxy", proxy.addr())
        .native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(vec![der(&ca)]),
        );
    let proxied_hub = hub_over(replay);
    proxied_hub
        .set_proxy_text("http://proxy.acme.test:3128")
        .expect("proxy");
    let via = probe(&proxied_hub, &[&at])
        .tls_chain(&target(&at), Route::ViaProxy)
        .await
        .expect("a chain through the proxy");
    assert_eq!(via.sni.as_deref(), Some("web.acme.test"));
    assert_eq!(via.system, TrustVerdict::Valid);
    assert_eq!(via.connect.proxy_status, Some(200));
    assert_eq!(proxy.requests()[0].target, at);
    handshakes_settle(&server, 2).await;

    // An address host sends no SNI at all.
    let literal = format!("127.0.0.1:{}", server.addr().port());
    let hub = hub_over(
        Replay::new()
            .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
            .serve_tcp("web", server.addr())
            .native(
                NativeCall::SystemRoots,
                NativeValue::SystemRoots(vec![der(&ca)]),
            ),
    );
    let by_address = probe(&hub, &[&literal])
        .tls_chain(&target(&literal), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(by_address.sni, None);
    assert_eq!(by_address.system, TrustVerdict::Valid);
    handshakes_settle(&server, 3).await;
    assert_eq!(
        server.sni_seen(),
        [
            Some("web.acme.test".to_owned()),
            Some("web.acme.test".to_owned()),
            None
        ]
    );
    // The log agrees: the name host has an `sni` field and the address host has none.
    let literal_entry = &of_kind(&hub, ActionKind::Tls)[0];
    assert_eq!(field(literal_entry, "sni"), None);
}

// ---- failures -----------------------------------------------------------------------------------

#[tokio::test]
async fn failures_have_their_own_typed_errors() {
    // Nothing listens: the connection itself failed.
    let closed = closed_port().await.expect("closed port");
    let at = format!("127.0.0.1:{}", closed.port());
    let hub = hub_over(Replay::new().tcp(closed, TcpScript::Refused));
    let error = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect_err("refused");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::NotConnected {
            target: at.clone(),
            reason: AttemptOutcome::Refused.phrase(),
        })
    );
    assert!(error.to_string().contains("Fix:"));

    // A reset right after the ClientHello.
    let reset = ResetAfterClientHello::start().await.expect("server");
    let at = format!("127.0.0.1:{}", reset.addr().port());
    let hub = hub_over(
        Replay::new()
            .tcp(reset.addr(), TcpScript::Serve("reset".to_owned()))
            .serve_tcp("reset", reset.addr())
            .native(NativeCall::SystemRoots, NativeValue::SystemRoots(vec![])),
    );
    let error = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect_err("reset");
    assert_eq!(error, ProbeError::Net(NetFailure::TlsReset { target: at }));
    assert!(reset.hello_bytes() > 0);

    // A server that offers only an ALPN protocol the client did not ask for answers with an alert.
    let ca = TestCa::root("Acme Test Root");
    let leaf = ca.issue(&["web.acme.test"], Validity::Always);
    let picky = HttpServer::start(HttpOptions::tls(&leaf).alpn(&["acme/1"]))
        .await
        .expect("server");
    let at = web(&picky);
    let hub = hub_over(machine(picky.addr(), Some(vec![der(&ca)])));
    let error = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect_err("alert");
    assert!(
        matches!(&error, ProbeError::Net(NetFailure::TlsAlert { alert, .. }) if alert == "NoApplicationProtocol"),
        "{error:?}"
    );
    assert!(error.to_string().contains("Fix:"));
}

#[tokio::test]
async fn a_server_that_never_answers_the_hello_times_out() {
    let silent = NeverAccepts::start().await.expect("listener");
    let at = format!("127.0.0.1:{}", silent.addr().port());
    let hub = hub_over(
        Replay::new()
            .tcp(silent.addr(), TcpScript::Serve("silent".to_owned()))
            .serve_tcp("silent", silent.addr())
            .native(NativeCall::SystemRoots, NativeValue::SystemRoots(vec![])),
    );
    let probe = probe(&hub, &[&at]);
    quick(&probe);
    let error = probe
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect_err("timeout");
    assert_eq!(error, ProbeError::Timeout);
    let log = of_kind(&hub, ActionKind::Tls);
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, ActionOutcome::Timeout);
}

#[tokio::test]
async fn a_fixture_with_no_system_roots_is_not_recorded() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test"], Validity::Always).await;
    let at = web(&server);
    let hub = hub_over(machine(server.addr(), None));
    let error = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect_err("not recorded");
    assert!(matches!(error, ProbeError::NotRecorded(_)), "{error:?}");
}

#[tokio::test]
async fn an_os_with_no_source_for_roots_leaves_the_verdict_unavailable() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test"], Validity::Always).await;
    let at = web(&server);
    let replay = machine(server.addr(), None).native_unsupported(NativeCall::SystemRoots);
    let hub = hub_over(replay);
    let chain = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.system, TrustVerdict::Unavailable(NoRoots::Empty));
    assert_eq!(chain.bundled, rejected(TrustFailure::UnknownIssuer));
}

#[tokio::test]
async fn a_store_that_would_not_read_is_unreadable_and_kept_but_a_timeout_is_asked_again() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test"], Validity::Always).await;
    let at = web(&server);

    // A read error is a fact about the machine: the verdict says "could not be read", and the run
    // asks once.
    for failure in [
        NativeFailure::Io("the fixture records an I/O error".to_owned()),
        NativeFailure::NotFound,
        NativeFailure::PermissionDenied,
    ] {
        let hub =
            hub_over(machine(server.addr(), None).native_failure(NativeCall::SystemRoots, failure));
        for _ in 0..2 {
            let chain = probe(&hub, &[&at])
                .tls_chain(&target(&at), Route::Direct)
                .await
                .expect("a chain");
            assert_eq!(chain.system, TrustVerdict::Unavailable(NoRoots::Unreadable));
            assert_eq!(chain.system_roots, 0);
        }
        assert_eq!(of_kind(&hub, ActionKind::Native).len(), 1);
    }

    // A timeout says nothing about the store: this call gets "could not be read", the next one asks.
    let hub = hub_over(
        machine(server.addr(), None)
            .native_failure(NativeCall::SystemRoots, NativeFailure::TimedOut),
    );
    for _ in 0..2 {
        let chain = probe(&hub, &[&at])
            .tls_chain(&target(&at), Route::Direct)
            .await
            .expect("a chain");
        assert_eq!(chain.system, TrustVerdict::Unavailable(NoRoots::Unreadable));
    }
    assert_eq!(of_kind(&hub, ActionKind::Native).len(), 2);
}

// ---- policy and the log -------------------------------------------------------------------------

#[tokio::test]
async fn the_policy_of_tcp_applies_before_anything_is_opened() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test"], Validity::Always).await;
    let at = web(&server);
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let replay = machine(server.addr(), Some(vec![der(&ca)]))
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(
            addr("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_tcp("proxy", proxy.addr());
    let hub = hub_over(replay);
    hub.set_proxy_text("http://proxy.acme.test:3128")
        .expect("proxy");
    let denied = |error: ProbeError| match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a denial, got {other:?}"),
    };

    // A host the check does not list.
    let unlisted = probe(&hub, &["other.acme.test:443"]);
    let error = unlisted
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect_err("not a spec host");
    assert_eq!(denied(error), RULE_TCP_HOST);

    // A proxied call from a check that did not declare the proxy.
    let no_proxy = probe_for(&hub, direct_only(), &[&at]);
    let error = no_proxy
        .tls_chain(&target(&at), Route::ViaProxy)
        .await
        .expect_err("proxy undeclared");
    assert_eq!(denied(error), RULE_PROXY_UNDECLARED);

    // A metadata address as a literal host, direct and through the proxy: no byte is sent anywhere.
    let metadata = probe(&hub, &["169.254.169.254:443"]);
    for route in [Route::Direct, Route::ViaProxy] {
        let error = metadata
            .tls_chain(&target("169.254.169.254:443"), route)
            .await
            .expect_err("metadata address");
        assert_eq!(denied(error), RULE_TCP_ADDRESS);
    }
    assert_eq!(proxy.accepted(), 0);
    assert_eq!(proxy.bytes_received(), 0);
    assert_eq!(server.accepted(), 0);

    // Every refused call is a `denied` tls entry, and the roots were never asked for.
    let log = entries(&hub);
    assert_eq!(log.len(), 4);
    assert!(log.iter().all(|e| e.kind == ActionKind::Tls));
    assert!(log.iter().all(|e| e.outcome == ActionOutcome::Denied));

    // Positive control: the allowed call through the same proxy reaches it.
    let ok = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::ViaProxy)
        .await
        .expect("allowed");
    assert_eq!(ok.system, TrustVerdict::Valid);
    assert_eq!(proxy.accepted(), 1);
}

#[tokio::test]
async fn the_log_has_one_tls_entry_per_call_and_one_run_level_roots_read() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test"], Validity::Always).await;
    let at = web(&server);
    let closed = closed_port().await.expect("closed port");
    let dead = format!("127.0.0.1:{}", closed.port());
    let replay = machine(server.addr(), Some(vec![der(&ca)])).tcp(closed, TcpScript::Refused);
    let hub = hub_over(replay);
    let one = probe(&hub, &[&at, &dead]);
    let two = probe_for(&hub, direct_only(), &[&at]);

    one.tls_chain(&target(&at), Route::Direct).await.expect("1");
    two.tls_chain(&target(&at), Route::Direct).await.expect("2");
    one.tls_chain(&target(&at), Route::Direct).await.expect("3");
    one.tls_chain(&target(&dead), Route::Direct)
        .await
        .expect_err("4: refused");

    let tls = of_kind(&hub, ActionKind::Tls);
    assert_eq!(tls.len(), 4, "{tls:?}");
    assert_eq!(
        tls.iter().map(|e| e.outcome.clone()).collect::<Vec<_>>(),
        [
            ActionOutcome::Ok,
            ActionOutcome::Ok,
            ActionOutcome::Ok,
            ActionOutcome::Failed
        ]
    );
    for entry in &tls[..3] {
        assert_eq!(field(entry, "host"), Some(&Value::from("web.acme.test")));
        assert_eq!(
            field(entry, "port"),
            Some(&Value::from(server.addr().port()))
        );
        assert_eq!(field(entry, "sni"), Some(&Value::from("web.acme.test")));
        assert_eq!(field(entry, "via_proxy"), Some(&Value::Null));
        assert_eq!(field(entry, "addr"), Some(&Value::from("127.0.0.1")));
    }
    assert_eq!(tls[0].check.as_deref(), Some("net.tls_intercept"));
    assert_eq!(tls[1].check.as_deref(), Some("net.direct"));
    assert_eq!(field(&tls[3], "addr"), Some(&Value::Null));
    assert!(field(&tls[3], "error").is_some());

    // The OS store was asked for once for the run, by the run-level probe, not once per check or call.
    let native = of_kind(&hub, ActionKind::Native);
    assert_eq!(native.len(), 1, "{native:?}");
    assert_eq!(native[0].check, None);
    assert_eq!(field(&native[0], "api"), Some(&Value::from("system_roots")));
    assert_eq!(entries(&hub).len(), 5);

    // No certificate, key or alert text is in the log.
    let text = serde_json::to_string(&entries(&hub)).expect("json");
    for leaked in ["BEGIN CERTIFICATE", "Acme Test Root", "MII"] {
        assert!(!text.contains(leaked), "{leaked:?} in {text}");
    }
}

#[tokio::test]
async fn a_call_after_the_check_ended_is_refused_and_logged() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["web.acme.test"], Validity::Always).await;
    let at = web(&server);
    let hub = hub_over(machine(server.addr(), Some(vec![der(&ca)])));
    let probe = probe(&hub, &[&at]);
    probe.end();
    let error = probe
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect_err("ended");
    assert!(
        matches!(error, ProbeError::Denied { rule, .. } if rule == crate::probe::RULE_CHECK_FINISHED)
    );
    assert_eq!(server.accepted(), 0);
}

// ---- the live backend ---------------------------------------------------------------------------

#[tokio::test]
async fn the_live_backend_handshakes_on_loopback_and_reads_the_real_store() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, &["127.0.0.1"], Validity::Always).await;
    let at = server.addr().to_string();
    let hub = crate::probe::net::tests::live_hub();
    let chain = probe(&hub, &[&at])
        .tls_chain(&target(&at), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.certs.len(), 1);
    assert_eq!(chain.sni, None);
    assert_eq!(chain.bundled, rejected(TrustFailure::UnknownIssuer));
    // The test CA is in no real store. A Linux machine with no store at all (a bare container) says so.
    assert!(
        matches!(
            chain.system,
            TrustVerdict::Rejected(TrustFailure::UnknownIssuer)
                | TrustVerdict::Unavailable(NoRoots::Empty)
        ),
        "{:?}",
        chain.system
    );
    assert_eq!(
        matches!(chain.system, TrustVerdict::Unavailable(_)),
        chain.system_roots == 0
    );
    // macOS and Windows always have an OS store, so a reader that gave nothing is a broken reader.
    #[cfg(any(target_os = "macos", windows))]
    assert!(chain.system_roots > 0, "the OS store gave no root");
    assert!(chain.system_roots <= crate::probe::MAX_SYSTEM_ROOTS);
    handshakes_settle(&server, 1).await;
    assert_eq!(server.application_bytes(), 0);
}
