//! Tests for the HTTP/1.1 probe (M1-093).
//!
//! The exit test: a 302 returns its `Location` host without a second request, a body canary never
//! reaches the report, each failure class is produced by its loopback case, the action log has one
//! entry per http call, the strict client config refuses a chain the roots do not accept (with a
//! pinned clock past the leaf's `notAfter` it fails), and the fixture bundle's path and its CA's
//! SHA-256 are returned.
//!
//! The replay backend sends each connection to a real loopback server, so the handshakes and the
//! requests are real and the roots are the test's own. One test runs the live backend end to end.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rdy_spec::Target;
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::Value;
use tempfile::TempDir;

use super::*;
use crate::check::{CheckInfo, CheckMeta, Os, OsSupport, PeerClass, Support};
use crate::family::HostSet;
use crate::probe::net::tests::assert_matches_result_schema;
use crate::probe::net::{AttemptOutcome, RULE_PROXY_UNDECLARED, RULE_TCP_ADDRESS, RULE_TCP_HOST};
use crate::probe::net::{NoRoots, TrustFailure, TrustStore, TrustVerdict};
use crate::probe::replay::{Fixture, NativeFailure, Replay, TcpScript};
use crate::probe::{Backend, NativeCall, NativeValue, StoreKind, StoreSource, SystemRoots};
use crate::redact::{Redactor, TagKey};
use crate::testing::loopback::{
    ConnectProxy, HttpOptions, HttpServer, NeverAccepts, ProxyMode, Reply, ResetAfterClientHello,
    TestCa, Validity, closed_port,
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

fn egress() -> &'static CheckInfo {
    info!("net.egress", &[PeerClass::SpecHosts, PeerClass::Proxy])
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
    probe_for(hub, egress(), hosts)
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

/// Standard base64 with padding, for a fixture value.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn log_text(hub: &ProbeHub) -> String {
    serde_json::to_string(&entries(hub)).expect("the log is JSON")
}

fn denied_rule(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A replay machine whose `web.acme.test` is the loopback `server`, with this OS trust bundle.
fn machine(server: SocketAddr, bundle: Option<SystemRoots>) -> Replay {
    let replay = Replay::new()
        .host("web.acme.test", [ip("127.0.0.1")])
        .tcp(server, TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server);
    match bundle {
        Some(roots) => replay.native(NativeCall::SystemRoots, NativeValue::SystemRoots(roots)),
        None => replay,
    }
}

fn trusting(ca: &TestCa) -> SystemRoots {
    SystemRoots::new(
        vec![der(ca)],
        vec![StoreSource::new(
            StoreKind::Bundle,
            "/etc/ssl/certs/ca-certificates.crt",
        )],
    )
}

async fn tls_server(ca: &TestCa, validity: Validity, reply: Reply) -> HttpServer {
    HttpServer::start(HttpOptions::tls(&ca.issue(&["web.acme.test"], validity)).reply(reply))
        .await
        .expect("server")
}

async fn plain_server(reply: Reply) -> HttpServer {
    HttpServer::start(HttpOptions::plain().reply(reply))
        .await
        .expect("server")
}

fn https(server: &HttpServer, tail: &str) -> Target {
    target(&format!(
        "https://web.acme.test:{}{tail}",
        server.addr().port()
    ))
}

fn http_url(server: &HttpServer, tail: &str) -> Target {
    target(&format!(
        "http://web.acme.test:{}{tail}",
        server.addr().port()
    ))
}

fn hosts_of(server: &HttpServer) -> String {
    format!("web.acme.test:{}", server.addr().port())
}

fn get(target: Target) -> HttpProbe {
    HttpProbe::new(target, HttpMethod::Get)
}

// ---- the exit test: redirects, bodies and headers -----------------------------------------------

#[tokio::test]
async fn a_302_returns_its_location_host_without_a_second_request() {
    // The `Location` has a path and a query with a token: only its host may come back.
    let location = "https://second.acme.example:8443/next?token=hunter2-canary#frag";
    let ca = TestCa::root("Acme Test Root");
    for (server, url) in [
        (
            plain_server(Reply::Redirect(location.to_owned())).await,
            false,
        ),
        (
            HttpServer::start(
                HttpOptions::tls(&ca.issue(&["web.acme.test"], Validity::Always))
                    .reply(Reply::Redirect(location.to_owned())),
            )
            .await
            .expect("server"),
            true,
        ),
    ] {
        let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
        let at = hosts_of(&server);
        let target = if url {
            https(&server, "/start?q=1")
        } else {
            http_url(&server, "/start?q=1")
        };
        let outcome = probe(&hub, &[&at])
            .http(get(target))
            .await
            .expect("the 302 is an answer");
        assert_eq!(outcome.status, 302);
        assert_eq!(
            outcome.location_host.as_deref(),
            Some("second.acme.example")
        );
        // One request, no second, and nothing was looked up or dialled for the new host.
        assert_eq!(server.requests().len(), 1, "no second request");
        assert_eq!(server.accepted(), 1);
        assert_eq!(of_kind(&hub, ActionKind::Http).len(), 1);
        assert_eq!(
            entries(&hub).len(),
            if url { 2 } else { 1 },
            "the roots read, if https"
        );
        // Neither the path, the query, the port nor the token of the `Location` is kept.
        let shown = format!("{outcome:?} {}", log_text(&hub));
        for leaked in ["hunter2", "canary", "/next", "8443", "frag"] {
            assert!(!shown.contains(leaked), "{leaked:?} in {shown}");
        }
    }
}

#[tokio::test]
async fn location_hosts_are_read_from_absolute_urls_only() {
    for (value, want) in [
        ("https://a.acme.example/x", Some("a.acme.example")),
        ("http://A.ACME.example:8080/x?y=1", Some("a.acme.example")),
        ("//cdn.acme.example/x", Some("cdn.acme.example")),
        ("https://[2001:db8::1]/x", Some("[2001:db8::1]")),
        ("https://10.0.0.7:8443/", Some("10.0.0.7")),
        ("/relative/path", None),
        ("next", None),
        ("https://user:pw@evil.example/", None),
        ("ftp://a.acme.example/", None),
        ("", None),
    ] {
        assert_eq!(location_host(value).as_deref(), want, "{value:?}");
    }
    assert_eq!(location_host(&"a".repeat(MAX_LOCATION + 1)), None);
}

#[tokio::test]
async fn a_body_canary_never_reaches_the_report_and_the_discard_is_capped() {
    let ca = TestCa::root("Acme Test Root");
    let canary = "BODY-CANARY-4f9a";
    let small = format!("{canary} {}", "x".repeat(100)).into_bytes();
    let big = [canary.as_bytes(), &vec![b'y'; 1 << 20]].concat();

    for (reply, counted, cut) in [
        (Reply::Body(small.clone()), small.len(), false),
        (Reply::Body(big.clone()), MAX_BODY, true),
        (Reply::Chunked(big.clone()), MAX_BODY, true),
        (Reply::Chunked(small.clone()), small.len(), false),
    ] {
        let server = tls_server(&ca, Validity::Always, reply.clone()).await;
        let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
        let at = hosts_of(&server);
        let outcome = probe(&hub, &[&at])
            .http(get(https(&server, "/")))
            .await
            .expect("an answer");
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.body_bytes, counted, "{}", reply_name(&reply));
        assert_eq!(outcome.body_cut, cut, "{}", reply_name(&reply));
        // Not in the outcome, its debug text, the log or the report that carries the log.
        let shown = format!("{outcome:?} {}", log_text(&hub));
        assert!(!shown.contains(canary), "{shown}");
        assert!(!shown.contains("yyyy"), "{shown}");
    }

    // A HEAD gets no body even though the length is announced.
    let server = tls_server(&ca, Validity::Always, Reply::Body(small.clone())).await;
    let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
    let at = hosts_of(&server);
    let outcome = probe(&hub, &[&at])
        .http(HttpProbe::new(https(&server, "/"), HttpMethod::Head))
        .await
        .expect("an answer");
    assert_eq!(outcome.body_bytes, 0);
    assert!(!outcome.body_cut);
    assert_eq!(
        outcome.header("content-length"),
        Some(small.len().to_string().as_str())
    );
    assert_eq!(server.requests()[0].method, "HEAD");
}

fn reply_name(reply: &Reply) -> &'static str {
    match reply {
        Reply::Body(_) => "body",
        Reply::Chunked(_) => "chunked",
        _ => "other",
    }
}

#[tokio::test]
async fn only_the_fixed_headers_are_kept_and_they_are_cleaned() {
    let long = "z".repeat(1000);
    let raw = format!(
        "HTTP/1.1 200 OK\r\nServer: acme-gw/2.1\r\nSet-Cookie: session=SESSION-CANARY\r\n\
         X-Auth-Token: TOKEN-CANARY\r\nContent-Type: text/plain\r\nVia: 1.1 edge\r\n\
         Retry-After: 30\r\nDate: Thu, 01 Jan 2026 00:00:00 GMT\r\nX-Long: {long}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let server = plain_server(Reply::Raw(raw.into_bytes())).await;
    let hub = hub_over(machine(server.addr(), None));
    let at = hosts_of(&server);
    let outcome = probe(&hub, &[&at])
        .http(get(http_url(&server, "/")))
        .await
        .expect("an answer");
    let names: Vec<&str> = outcome.headers.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "server",
            "content-type",
            "content-length",
            "date",
            "via",
            "retry-after"
        ]
    );
    assert_eq!(outcome.header("server"), Some("acme-gw/2.1"));
    assert_eq!(
        outcome.header("date"),
        Some("Thu, 01 Jan 2026 00:00:00 GMT")
    );
    let shown = format!("{outcome:?} {}", log_text(&hub));
    for leaked in ["CANARY", "session", "X-Long", "zzzz"] {
        assert!(!shown.contains(leaked), "{leaked:?} in {shown}");
    }
    // A long value is cut and a control character never survives.
    assert_eq!(printable(b"ab\x01cd\r\nef\x7f").as_str(), "abcdef");
    assert_eq!(printable("z".repeat(1000).as_bytes()).len(), MAX_VALUE);
}

#[tokio::test]
async fn a_reply_head_is_read_up_to_16_kib_and_no_further() {
    for (size, ok) in [(12_000, true), (20_000, false), (40_000, false)] {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "b".repeat(size)
        );
        let server = plain_server(Reply::Raw(raw.into_bytes())).await;
        let hub = hub_over(machine(server.addr(), None));
        let at = hosts_of(&server);
        let result = probe(&hub, &[&at]).http(get(http_url(&server, "/"))).await;
        if ok {
            assert_eq!(result.expect("a large head under the cap").status, 200);
        } else {
            let error = result.expect_err("a head over the cap");
            assert!(
                matches!(error, ProbeError::Net(NetFailure::HttpFailed { .. })),
                "{error:?}"
            );
        }
    }
}

#[tokio::test]
async fn the_request_is_a_plain_get_with_no_credentials() {
    let server = plain_server(Reply::Ok).await;
    let hub = hub_over(machine(server.addr(), None));
    let at = hosts_of(&server);
    probe(&hub, &[&at])
        .http(get(http_url(&server, "/v1/ping?token=QUERY-CANARY&a=b")))
        .await
        .expect("an answer");
    let seen = server.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    // The query is sent: the check asked for it. It is never recorded.
    assert_eq!(seen[0].target, "/v1/ping?token=QUERY-CANARY&a=b");
    assert_eq!(
        seen[0].header("host"),
        Some(format!("web.acme.test:{}", server.addr().port()).as_str())
    );
    assert!(
        seen[0]
            .header("user-agent")
            .is_some_and(|v| v.starts_with("rdy/"))
    );
    assert_eq!(seen[0].header("connection"), Some("close"));
    for absent in [
        "authorization",
        "cookie",
        "proxy-authorization",
        "accept-encoding",
    ] {
        assert_eq!(seen[0].header(absent), None, "{absent}");
    }
    let log = of_kind(&hub, ActionKind::Http);
    assert_eq!(
        field(&log[0], "url"),
        Some(&Value::from(format!(
            "http://web.acme.test:{}/v1/ping",
            server.addr().port()
        )))
    );
    assert!(!log_text(&hub).contains("QUERY-CANARY"));
}

// ---- the failure classes ------------------------------------------------------------------------

#[tokio::test]
async fn an_http_status_is_data_not_an_error() {
    let server = plain_server(Reply::Status(503)).await;
    let hub = hub_over(machine(server.addr(), None));
    let at = hosts_of(&server);
    let outcome = probe(&hub, &[&at])
        .http(get(http_url(&server, "/")))
        .await
        .expect("a 503 is an answer");
    assert_eq!(outcome.status, 503);
    let log = of_kind(&hub, ActionKind::Http);
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
    assert_eq!(field(&log[0], "status"), Some(&Value::from(503)));
}

#[tokio::test(start_paused = true)]
async fn dns_refused_blackhole_and_blocked_address_are_their_own_failures() {
    let closed = closed_port().await.expect("closed port");
    let dead = format!("dead.acme.test:{}", closed.port());
    let hub = hub_over(
        Replay::new()
            .host("gone.acme.test", Vec::<IpAddr>::new())
            .host("dead.acme.test", [ip("127.0.0.1")])
            .tcp(closed, TcpScript::Refused)
            .host("hole.acme.test", [ip("192.0.2.9")])
            .tcp(addr("192.0.2.9:80"), TcpScript::Blackhole)
            .host("meta.acme.test", [ip("169.254.169.254")]),
    );
    let p = probe(
        &hub,
        &[
            &dead,
            "gone.acme.test:80",
            "hole.acme.test:80",
            "meta.acme.test:80",
            "169.254.169.254:80",
        ],
    );

    let error = p
        .http(get(target("http://gone.acme.test/")))
        .await
        .expect_err("NXDOMAIN");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::Dns {
            host: "gone.acme.test".to_owned()
        })
    );

    let error = p
        .http(get(target(&format!("http://{dead}/"))))
        .await
        .expect_err("refused");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::NotConnected {
            target: dead.clone(),
            reason: AttemptOutcome::Refused.phrase(),
        })
    );

    let error = p
        .http(get(target("http://hole.acme.test/")))
        .await
        .expect_err("a black hole");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::NotConnected {
            target: "hole.acme.test:80".to_owned(),
            reason: AttemptOutcome::TimedOut.phrase(),
        })
    );

    for text in ["http://meta.acme.test/", "http://169.254.169.254/"] {
        let error = p.http(get(target(text))).await.expect_err("blocked");
        assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "{text}");
    }
    let log = of_kind(&hub, ActionKind::Http);
    assert_eq!(log.len(), 5);
    assert_eq!(
        log.iter().map(|e| e.outcome.clone()).collect::<Vec<_>>(),
        [
            ActionOutcome::Failed,
            ActionOutcome::Failed,
            ActionOutcome::Failed,
            ActionOutcome::Denied,
            ActionOutcome::Denied
        ]
    );
}

#[tokio::test]
async fn an_unknown_issuer_and_an_expired_leaf_fail_before_a_request_is_sent() {
    let ca = TestCa::root("Acme Test Root");
    let other = TestCa::root("Other Root");
    let cases = [
        (Validity::Always, Some(&other), TrustFailure::UnknownIssuer),
        (Validity::Expired, Some(&ca), TrustFailure::Expired),
        (Validity::NotYetValid, Some(&ca), TrustFailure::NotYetValid),
    ];
    for (validity, trusted, expected) in cases {
        let server = tls_server(&ca, validity, Reply::Body(b"never-read".to_vec())).await;
        let hub = hub_over(machine(server.addr(), trusted.map(trusting)));
        let at = hosts_of(&server);
        let error = probe(&hub, &[&at])
            .http(get(https(&server, "/")))
            .await
            .expect_err("the roots refuse the chain");
        assert_eq!(
            error,
            ProbeError::Net(NetFailure::TlsUntrusted {
                target: at.clone(),
                failure: expected,
            }),
            "{validity:?}"
        );
        assert!(error.to_string().contains("Fix:"), "{error}");
        assert_eq!(
            expected.is_clock_or_expiry(),
            expected != TrustFailure::UnknownIssuer
        );
        // The handshake ended with an alert, and the server read no application byte.
        assert!(server.requests().is_empty(), "{validity:?}");
        assert_eq!(server.application_bytes(), 0, "{validity:?}");
        let log = of_kind(&hub, ActionKind::Http);
        assert_eq!(log[0].outcome, ActionOutcome::Failed);
        assert!(field(&log[0], "status").is_none());
    }
}

#[tokio::test]
async fn a_name_the_certificate_does_not_list_is_a_name_mismatch() {
    let ca = TestCa::root("Acme Test Root");
    let server = HttpServer::start(HttpOptions::tls(
        &ca.issue(&["other.acme.test"], Validity::Always),
    ))
    .await
    .expect("server");
    let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
    let at = hosts_of(&server);
    let error = probe(&hub, &[&at])
        .http(get(https(&server, "/")))
        .await
        .expect_err("name mismatch");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::TlsUntrusted {
            target: at,
            failure: TrustFailure::NameMismatch,
        })
    );
    assert_eq!(server.application_bytes(), 0);
}

#[tokio::test]
async fn a_reset_after_the_hello_and_an_alert_are_their_own_failures() {
    let reset = ResetAfterClientHello::start().await.expect("server");
    let at = format!("web.acme.test:{}", reset.addr().port());
    let hub = hub_over(machine(
        reset.addr(),
        Some(SystemRoots::from(vec![der(&TestCa::root(
            "Acme Test Root",
        ))])),
    ));
    let error = probe(&hub, &[&at])
        .http(get(target(&format!("https://{at}/"))))
        .await
        .expect_err("reset");
    assert_eq!(error, ProbeError::Net(NetFailure::TlsReset { target: at }));

    // A server that offers only a protocol the client did not ask for answers with an alert, which
    // also shows the strict handshake offers `http/1.1` and not `h2`.
    let ca = TestCa::root("Acme Test Root");
    let picky = HttpServer::start(
        HttpOptions::tls(&ca.issue(&["web.acme.test"], Validity::Always)).alpn(&["h2"]),
    )
    .await
    .expect("server");
    let at = hosts_of(&picky);
    let hub = hub_over(machine(picky.addr(), Some(trusting(&ca))));
    let error = probe(&hub, &[&at])
        .http(get(https(&picky, "/")))
        .await
        .expect_err("alert");
    assert!(
        matches!(&error, ProbeError::Net(NetFailure::TlsAlert { alert, .. }) if alert == "NoApplicationProtocol"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_server_that_speaks_something_else_or_nothing_is_an_http_failure() {
    for (reply, reason) in [
        (
            Reply::Raw(b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()),
            "the reply is not valid HTTP/1.1, or its head is too large",
        ),
        (
            Reply::Raw(Vec::new()),
            "the connection closed before the reply ended",
        ),
        (
            Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Le".to_vec()),
            "the connection closed before the reply ended",
        ),
    ] {
        let server = plain_server(reply).await;
        let hub = hub_over(machine(server.addr(), None));
        let at = hosts_of(&server);
        let error = probe(&hub, &[&at])
            .http(get(http_url(&server, "/")))
            .await
            .expect_err("not HTTP");
        assert_eq!(
            error,
            ProbeError::Net(NetFailure::HttpFailed { target: at, reason })
        );
        assert!(error.to_string().contains("Fix:"));
    }

    // Plain HTTP spoken to a TLS port is not HTTP either.
    let ca = TestCa::root("Acme Test Root");
    let tls = tls_server(&ca, Validity::Always, Reply::Ok).await;
    let at = hosts_of(&tls);
    let hub = hub_over(machine(tls.addr(), None));
    let error = probe(&hub, &[&at])
        .http(get(http_url(&tls, "/")))
        .await
        .expect_err("a TLS server does not answer plain text");
    assert!(
        matches!(error, ProbeError::Net(NetFailure::HttpFailed { .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_server_that_never_answers_times_out() {
    let silent = NeverAccepts::start().await.expect("listener");
    let at = format!("web.acme.test:{}", silent.addr().port());
    let hub = hub_over(machine(silent.addr(), None));
    let p = probe(&hub, &[&at]);
    quick(&p);
    let error = p
        .http(get(target(&format!("http://{at}/"))))
        .await
        .expect_err("silent");
    assert_eq!(error, ProbeError::Timeout);
    let log = of_kind(&hub, ActionKind::Http);
    assert_eq!(log[0].outcome, ActionOutcome::Timeout);
}

#[tokio::test]
async fn the_proxy_answers_403_and_407_as_typed_errors_and_a_200_tunnels_https() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, Validity::Always, Reply::Ok).await;
    let port = server.addr().port();
    let at = format!("web.acme.test:{port}");
    for (mode, want) in [
        (
            ProxyMode::Forbidden,
            NetFailure::ProxyForbidden { target: at.clone() },
        ),
        (
            ProxyMode::Basic407,
            NetFailure::ProxyAuthRequired {
                target: at.clone(),
                challenge: crate::probe::ProxyChallenge::Basic,
                sent_credentials: false,
            },
        ),
    ] {
        let proxy = ConnectProxy::start_with_routes(mode, &[(&at, server.addr())])
            .await
            .expect("proxy");
        let hub = hub_over(proxied(proxy.addr(), Some(trusting(&ca))));
        hub.set_proxy_text("http://proxy.acme.test:3128")
            .expect("proxy");
        let error = probe(&hub, &[&at])
            .http(get(https(&server, "/")).route(Route::ViaProxy))
            .await
            .expect_err("the proxy says no");
        assert_eq!(error, ProbeError::Net(want), "{mode:?}");
        assert_eq!(server.accepted(), 0, "the tunnel never opened");
    }

    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let hub = hub_over(proxied(proxy.addr(), Some(trusting(&ca))));
    hub.set_proxy_text("http://proxy.acme.test:3128")
        .expect("proxy");
    let outcome = probe(&hub, &[&at])
        .http(get(https(&server, "/")).route(Route::ViaProxy))
        .await
        .expect("through the tunnel");
    assert_eq!(outcome.status, 200);
    assert!(outcome.connect.via_proxy);
    assert_eq!(outcome.connect.proxy_status, Some(200));
    let log = of_kind(&hub, ActionKind::Http);
    assert_eq!(
        field(&log[0], "via_proxy"),
        Some(&Value::from("http://proxy.acme.test:3128"))
    );
    assert_eq!(field(&log[0], "addr"), Some(&Value::Null));
}

fn proxied(proxy: SocketAddr, bundle: Option<SystemRoots>) -> Replay {
    let replay = Replay::new()
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(
            addr("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_tcp("proxy", proxy);
    match bundle {
        Some(roots) => replay.native(NativeCall::SystemRoots, NativeValue::SystemRoots(roots)),
        None => replay,
    }
}

#[tokio::test]
async fn plain_http_through_the_proxy_is_refused_before_a_byte_is_sent() {
    let server = plain_server(Reply::Ok).await;
    let at = hosts_of(&server);
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let hub = hub_over(proxied(proxy.addr(), None));
    hub.set_proxy_text("http://proxy.acme.test:3128")
        .expect("proxy");
    let error = probe(&hub, &[&at])
        .http(get(http_url(&server, "/")).route(Route::ViaProxy))
        .await
        .expect_err("not built yet");
    assert_eq!(denied_rule(&error), RULE_HTTP_PLAIN_VIA_PROXY);
    assert_eq!(proxy.accepted(), 0);
    assert_eq!(server.accepted(), 0);
}

// ---- policy -------------------------------------------------------------------------------------

#[tokio::test]
async fn the_policy_of_tcp_applies_before_anything_is_opened() {
    let server = plain_server(Reply::Ok).await;
    let at = hosts_of(&server);
    let hub = hub_over(machine(server.addr(), None));

    // Another check's host, a check that declared no spec hosts, a proxy it did not declare, and a
    // target that is not a URL.
    let error = probe(&hub, &["other.acme.test:80"])
        .http(get(http_url(&server, "/")))
        .await
        .expect_err("not this check's host");
    assert_eq!(denied_rule(&error), RULE_TCP_HOST);

    let error = probe_for(&hub, direct_only(), &[&at])
        .http(get(http_url(&server, "/")).route(Route::ViaProxy))
        .await
        .expect_err("proxy not declared");
    assert_eq!(denied_rule(&error), RULE_PROXY_UNDECLARED);

    let error = probe(&hub, &[&at])
        .http(get(target(&at)))
        .await
        .expect_err("host:port is not a URL");
    assert_eq!(denied_rule(&error), RULE_HTTP_NOT_URL);

    let bare = hub.check_probe("net.bare", Os::Linux, None);
    bare.permit_hosts(HostSet::new([target(&at)]));
    let error = bare
        .http(get(http_url(&server, "/")))
        .await
        .expect_err("no manifest");
    assert_eq!(denied_rule(&error), crate::probe::net::RULE_TCP_UNDECLARED);

    assert_eq!(server.accepted(), 0);
    assert!(
        entries(&hub)
            .iter()
            .all(|e| e.outcome == ActionOutcome::Denied && e.kind == ActionKind::Http)
    );
}

#[tokio::test]
async fn a_call_after_the_check_ended_is_refused_and_logged() {
    let server = plain_server(Reply::Ok).await;
    let at = hosts_of(&server);
    let hub = hub_over(machine(server.addr(), None));
    let p = probe(&hub, &[&at]);
    p.end();
    let error = p
        .http(get(http_url(&server, "/")))
        .await
        .expect_err("ended");
    assert_eq!(denied_rule(&error), crate::probe::RULE_CHECK_FINISHED);
    assert_eq!(server.accepted(), 0);
    assert_eq!(of_kind(&hub, ActionKind::Http).len(), 1);
}

// ---- the log ------------------------------------------------------------------------------------

#[tokio::test]
async fn the_log_has_one_http_entry_per_call_and_matches_the_result_schema() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, Validity::Always, Reply::Status(404)).await;
    let at = hosts_of(&server);
    let closed = closed_port().await.expect("closed port");
    let dead = format!("web.acme.test:{}", closed.port());
    let hub = hub_over(machine(server.addr(), Some(trusting(&ca))).tcp(closed, TcpScript::Refused));
    let one = probe(&hub, &[&at, &dead]);
    let two = probe_for(&hub, direct_only(), &[&at]);

    one.http(get(https(&server, "/a?x=1"))).await.expect("1");
    two.http(HttpProbe::new(https(&server, "/b"), HttpMethod::Head))
        .await
        .expect("2");
    one.http(get(target(&format!("https://{dead}/"))))
        .await
        .expect_err("3: refused");
    one.http(get(target("https://web.acme.test:1/")))
        .await
        .expect_err("4: not a spec host");

    let http = of_kind(&hub, ActionKind::Http);
    assert_eq!(http.len(), 4, "{http:?}");
    assert_eq!(
        http.iter().map(|e| e.outcome.clone()).collect::<Vec<_>>(),
        [
            ActionOutcome::Ok,
            ActionOutcome::Ok,
            ActionOutcome::Failed,
            ActionOutcome::Denied
        ]
    );
    assert_eq!(http[0].check.as_deref(), Some("net.egress"));
    assert_eq!(http[1].check.as_deref(), Some("net.direct"));
    assert_eq!(field(&http[0], "method"), Some(&Value::from("GET")));
    assert_eq!(field(&http[1], "method"), Some(&Value::from("HEAD")));
    assert_eq!(
        field(&http[0], "url"),
        Some(&Value::from(format!(
            "https://web.acme.test:{}/a",
            server.addr().port()
        )))
    );
    assert_eq!(field(&http[0], "status"), Some(&Value::from(404)));
    assert_eq!(field(&http[0], "addr"), Some(&Value::from("127.0.0.1")));
    assert_eq!(field(&http[0], "via_proxy"), Some(&Value::Null));
    assert_eq!(field(&http[2], "addr"), Some(&Value::Null));
    assert!(field(&http[2], "error").is_some());
    assert!(field(&http[3], "rule").is_some());
    // The roots were read once for the run, by the run-level probe.
    let native = of_kind(&hub, ActionKind::Native);
    assert_eq!(native.len(), 1);
    assert_eq!(native[0].check, None);
    assert!(!log_text(&hub).contains("x=1"));

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample =
        std::fs::read_to_string(root.join("../../tests/fixtures/reports/not-ready-7.2.json"))
            .expect("the fixture is in the repo");
    let mut report: rdy_spec::result::Report = serde_json::from_str(&sample).expect("a report");
    hub.action_log().apply(&mut report);
    assert_matches_result_schema(&serde_json::to_value(&report).expect("report"));
}

// ---- the roots ----------------------------------------------------------------------------------

#[tokio::test]
async fn trust_system_uses_the_os_roots_and_trust_bundled_never_asks_for_them() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, Validity::Always, Reply::Ok).await;
    let at = hosts_of(&server);

    // The test CA is in the OS bundle: valid with `System`, and with `Bundled` it is unknown.
    let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
    let p = probe(&hub, &[&at]);
    let outcome = p
        .http(get(https(&server, "/")))
        .await
        .expect("trusted by the OS");
    assert_eq!(outcome.status, 200);
    let error = p
        .http(get(https(&server, "/")).roots(Roots::Bundled))
        .await
        .expect_err("not a public CA");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::TlsUntrusted {
            target: at.clone(),
            failure: TrustFailure::UnknownIssuer,
        })
    );

    // No OS answer is recorded at all: `Bundled` does not ask, so it fails on trust and not on the
    // missing fixture, and the log has no `native` entry.
    let hub = hub_over(machine(server.addr(), None));
    let error = probe(&hub, &[&at])
        .http(get(https(&server, "/")).roots(Roots::Bundled))
        .await
        .expect_err("not a public CA");
    assert!(
        matches!(
            error,
            ProbeError::Net(NetFailure::TlsUntrusted {
                failure: TrustFailure::UnknownIssuer,
                ..
            })
        ),
        "{error:?}"
    );
    assert!(of_kind(&hub, ActionKind::Native).is_empty());
}

#[tokio::test]
async fn an_empty_or_unreadable_os_store_is_no_roots_and_not_a_pass() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, Validity::Always, Reply::Ok).await;
    let at = hosts_of(&server);
    let cases = [
        (
            machine(server.addr(), Some(SystemRoots::default())),
            NoRoots::Empty,
        ),
        (
            machine(server.addr(), None)
                .native_failure(NativeCall::SystemRoots, NativeFailure::Unsupported),
            NoRoots::Empty,
        ),
        (
            machine(server.addr(), None).native_failure(
                NativeCall::SystemRoots,
                NativeFailure::Io("the fixture records an I/O error".to_owned()),
            ),
            NoRoots::Unreadable,
        ),
        (
            machine(server.addr(), None)
                .native_failure(NativeCall::SystemRoots, NativeFailure::Overridden),
            NoRoots::Overridden,
        ),
    ];
    for (replay, reason) in cases {
        let hub = hub_over(replay);
        let error = probe(&hub, &[&at])
            .http(get(https(&server, "/")))
            .await
            .expect_err("nothing to verify with");
        assert_eq!(
            error,
            ProbeError::Net(NetFailure::NoTrustRoots {
                target: at.clone(),
                reason
            }),
            "{reason:?}"
        );
        assert!(error.to_string().contains("Fix:"));
        assert!(error.to_string().contains(reason.phrase()));
    }
    assert_eq!(server.application_bytes(), 0);
}

#[tokio::test]
async fn the_strict_client_offers_http_1_1_only() {
    let ca = TestCa::root("Acme Test Root");
    // The server prefers h2 and offers http/1.1. The recording handshake offers both and would get h2;
    // the strict one offers http/1.1 alone.
    let server = HttpServer::start(
        HttpOptions::tls(&ca.issue(&["web.acme.test"], Validity::Always)).alpn(&["h2", "http/1.1"]),
    )
    .await
    .expect("server");
    let at = hosts_of(&server);
    let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
    let p = probe(&hub, &[&at]);
    let chain = p
        .tls_chain(&https(&server, "/"), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.alpn, Some("h2"));
    let outcome = p.http(get(https(&server, "/"))).await.expect("an answer");
    let tls = outcome.tls.expect("a TLS session");
    assert_eq!(tls.alpn, Some("http/1.1"));
    assert!(matches!(tls.protocol, Some("TLS 1.2" | "TLS 1.3")));
    assert_eq!(server.requests().len(), 1);
}

// ---- the pinned clock ---------------------------------------------------------------------------

const MID_2020: Duration = Duration::from_secs(1_590_969_600);
const YEAR_4097: Duration = Duration::from_secs(67_121_740_800);
const YEAR_3999: Duration = Duration::from_secs(64_029_052_800);

#[tokio::test]
async fn a_pinned_clock_past_the_leafs_not_after_fails_the_strict_handshake() {
    let ca = TestCa::root("Acme Test Root");
    // `Always` is valid from 1975 to 4096.
    let server = tls_server(&ca, Validity::Always, Reply::Ok).await;
    let at = hosts_of(&server);
    let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
    let p = probe(&hub, &[&at]);

    // On the real clock it is valid, to both configurations.
    assert_eq!(
        p.http(get(https(&server, "/")))
            .await
            .expect("valid")
            .status,
        200
    );
    let chain = p
        .tls_chain(&https(&server, "/"), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.system, TrustVerdict::Valid);

    // Pinned past `notAfter`: the strict handshake fails, and the recording verdict says expired.
    hub.pin_clock(YEAR_4097);
    let error = p
        .http(get(https(&server, "/")))
        .await
        .expect_err("expired by the pinned clock");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::TlsUntrusted {
            target: at.clone(),
            failure: TrustFailure::Expired,
        })
    );
    let chain = p
        .tls_chain(&https(&server, "/"), Route::Direct)
        .await
        .expect("a chain");
    assert_eq!(chain.system, TrustVerdict::Rejected(TrustFailure::Expired));
    assert_eq!(chain.bundled, TrustVerdict::Rejected(TrustFailure::Expired));
    assert!(TrustFailure::Expired.is_clock_or_expiry());

    // Unpinned, the real clock is back.
    hub.unpin_clock();
    assert_eq!(
        p.http(get(https(&server, "/")))
            .await
            .expect("valid again")
            .status,
        200
    );
}

#[tokio::test]
async fn a_pinned_clock_inside_an_expired_leafs_window_makes_it_valid() {
    let ca = TestCa::root("Acme Test Root");
    // `Expired` is valid from 2020-01-01 to 2021-01-01; `NotYetValid` from 4000 to 4001.
    let old = tls_server(&ca, Validity::Expired, Reply::Ok).await;
    let future = tls_server(&ca, Validity::NotYetValid, Reply::Ok).await;
    for (server, inside, outside) in [
        (&old, MID_2020, YEAR_4097),
        (&future, Duration::from_secs(64_073_721_600), YEAR_3999),
    ] {
        let at = hosts_of(server);
        let hub = hub_over(machine(server.addr(), Some(trusting(&ca))));
        let p = probe(&hub, &[&at]);

        hub.pin_clock(inside);
        assert_eq!(
            p.http(get(https(server, "/")))
                .await
                .expect("inside")
                .status,
            200
        );
        let chain = p
            .tls_chain(&https(server, "/"), Route::Direct)
            .await
            .expect("a chain");
        assert_eq!(chain.system, TrustVerdict::Valid);

        hub.pin_clock(outside);
        let error = p
            .http(get(https(server, "/")))
            .await
            .expect_err("outside the window");
        assert!(
            matches!(
                error,
                ProbeError::Net(NetFailure::TlsUntrusted { failure, .. })
                    if failure.is_clock_or_expiry()
            ),
            "{error:?}"
        );
    }
}

// ---- the trust store facts ----------------------------------------------------------------------

#[tokio::test]
async fn the_trust_store_location_and_each_roots_sha256_are_returned() {
    let ca = TestCa::root("Acme Test Root");
    let second = TestCa::root("Second Root");
    let roots = SystemRoots::new(
        vec![der(&ca), der(&second)],
        vec![StoreSource::new(
            StoreKind::Bundle,
            "/etc/ssl/certs/ca-certificates.crt",
        )],
    );
    let hub =
        hub_over(Replay::new().native(NativeCall::SystemRoots, NativeValue::SystemRoots(roots)));
    let p = hub.check_probe("net.tls_intercept", Os::Linux, None);
    let store = p.trust_store().await.expect("the store");
    assert_eq!(store.missing, None);
    assert_eq!(
        store.sources,
        [StoreSource::new(
            StoreKind::Bundle,
            "/etc/ssl/certs/ca-certificates.crt"
        )]
    );
    // The hashes are SHA-256 of the DER, in store order, computed here without the facade's helper.
    let expected: Vec<[u8; 32]> = [&ca, &second]
        .iter()
        .map(|ca| {
            let digest = ring::digest::digest(&ring::digest::SHA256, ca.root_der().as_ref());
            <[u8; 32]>::try_from(digest.as_ref()).expect("32 bytes")
        })
        .collect();
    assert_eq!(store.roots, expected);
    assert!(store.contains(&TrustStore::hash(ca.root_der().as_ref())));
    assert!(!store.contains(&[0; 32]));
    assert_eq!(TrustStore::hex(&expected[0]).len(), 64);

    // A known answer for the hash and the hex form.
    assert_eq!(
        TrustStore::hex(&TrustStore::hash(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // Asked once for the run, the same answer the TLS calls use.
    let again = p.trust_store().await.expect("the store");
    assert_eq!(again, store);
    assert_eq!(of_kind(&hub, ActionKind::Native).len(), 1);

    // An empty store, a store that did not read, and a store that is overridden are not errors.
    for (replay, want) in [
        (
            Replay::new().native(
                NativeCall::SystemRoots,
                NativeValue::SystemRoots(SystemRoots::default()),
            ),
            NoRoots::Empty,
        ),
        (
            Replay::new().native_failure(
                NativeCall::SystemRoots,
                NativeFailure::Io("the fixture records an I/O error".to_owned()),
            ),
            NoRoots::Unreadable,
        ),
        (
            Replay::new().native_failure(NativeCall::SystemRoots, NativeFailure::Overridden),
            NoRoots::Overridden,
        ),
    ] {
        let hub = hub_over(replay);
        let store = hub
            .check_probe("net.tls_intercept", Os::Linux, None)
            .trust_store()
            .await
            .expect("not an error");
        assert_eq!(store.missing, Some(want));
        assert!(store.sources.is_empty());
        assert!(store.roots.is_empty());
    }
}

#[tokio::test]
async fn the_fixture_bundle_path_and_its_cas_hash_come_back_through_a_fixture() {
    let ca = TestCa::root("Fixture Root");
    let b64 = base64(ca.root_der().as_ref());
    let dir = TempDir::new().expect("temp dir");
    let base = dir.path().join("envs/x");
    std::fs::create_dir_all(base.join("native")).expect("dirs");
    std::fs::write(
        base.join("fixture.toml"),
        "schema = 1\nname = \"x\"\nsummary = \"A test machine\"\norigin = \"hand\"\nos = \"linux\"\n\
         arch = \"x86_64\"\nanswers = [\"net.tls_intercept\"]\n\n[caps]\nroot = false\nnetwork = true\nkube = false\n",
    )
    .expect("manifest");
    std::fs::write(
        base.join("native/roots.json"),
        format!(
            r#"{{"call":"system_roots","value":{{"certs":["{b64}"],"sources":[{{"kind":"bundle","location":"/etc/pki/tls/certs/ca-bundle.crt"}}]}}}}"#
        ),
    )
    .expect("native");
    let fixture = Fixture::load(dir.path(), "envs/x").expect("the fixture loads");
    let hub = hub_over(fixture.replay().clone());
    let store = hub
        .check_probe("net.tls_intercept", Os::Linux, None)
        .trust_store()
        .await
        .expect("the store");
    assert_eq!(
        store.sources,
        [StoreSource::new(
            StoreKind::Bundle,
            "/etc/pki/tls/certs/ca-bundle.crt"
        )]
    );
    assert!(store.contains(&TrustStore::hash(ca.root_der().as_ref())));
    assert_eq!(store.roots.len(), 1);
}

#[tokio::test]
async fn trust_store_is_refused_after_the_check_ended() {
    let hub = hub_over(Replay::new().native(
        NativeCall::SystemRoots,
        NativeValue::SystemRoots(SystemRoots::default()),
    ));
    let p = hub.check_probe("net.tls_intercept", Os::Linux, None);
    p.end();
    let error = p.trust_store().await.expect_err("ended");
    assert_eq!(denied_rule(&error), crate::probe::RULE_CHECK_FINISHED);
    assert!(of_kind(&hub, ActionKind::Native).is_empty());
}

// ---- helpers and the live backend ---------------------------------------------------------------

#[test]
fn the_host_header_and_the_logged_url_follow_the_target() {
    for (text, host, shown) in [
        (
            "https://a.acme.test/x?y=1",
            "a.acme.test",
            "https://a.acme.test:443/x",
        ),
        (
            "https://a.acme.test:8443",
            "a.acme.test:8443",
            "https://a.acme.test:8443/",
        ),
        (
            "http://a.acme.test:80/p",
            "a.acme.test",
            "http://a.acme.test:80/p",
        ),
        (
            "http://a.acme.test:8080/?q",
            "a.acme.test:8080",
            "http://a.acme.test:8080/",
        ),
        (
            "https://[2001:db8::1]:443/x",
            "[2001:db8::1]",
            "https://[2001:db8::1]:443/x",
        ),
        ("https://10.0.0.7/", "10.0.0.7", "https://10.0.0.7:443/"),
    ] {
        let t = target(text);
        assert_eq!(host_header(&t), host, "{text}");
        assert_eq!(shown_url(&t), shown, "{text}");
    }
    // The request line is the path and query, or `/`.
    for (text, path) in [
        ("https://a.acme.test", "/"),
        ("https://a.acme.test?x=1", "/?x=1"),
        ("https://a.acme.test/a/b?x=1", "/a/b?x=1"),
    ] {
        let request = build_request(&target(text), HttpMethod::Get).expect("a request");
        assert_eq!(request.uri().to_string(), path, "{text}");
    }
}

#[tokio::test]
async fn the_live_backend_gets_a_status_over_plain_http_and_refuses_an_unknown_issuer_over_tls() {
    let hub = crate::probe::net::tests::live_hub();
    let plain = plain_server(Reply::Status(204)).await;
    let at = plain.addr().to_string();
    let outcome = probe(&hub, &[&at])
        .http(get(target(&format!("http://{at}/ping"))))
        .await
        .expect("a status");
    assert_eq!(outcome.status, 204);
    assert_eq!(outcome.tls, None);
    assert_eq!(outcome.connect.addr, Some(plain.addr()));

    // The test CA is in no real store, so the live strict handshake refuses it (or, on a bare
    // container with no store at all, says there is nothing to verify with). No request is sent.
    let ca = TestCa::root("Acme Test Root");
    let tls = HttpServer::start(HttpOptions::tls(
        &ca.issue(&["127.0.0.1"], Validity::Always),
    ))
    .await
    .expect("server");
    let at = tls.addr().to_string();
    let error = probe(&hub, &[&at])
        .http(get(target(&format!("https://{at}/"))))
        .await
        .expect_err("the test CA is in no store");
    assert!(
        matches!(
            error,
            ProbeError::Net(
                NetFailure::TlsUntrusted {
                    failure: TrustFailure::UnknownIssuer,
                    ..
                } | NetFailure::NoTrustRoots { .. }
            )
        ),
        "{error:?}"
    );
    assert_eq!(tls.application_bytes(), 0);
}
