//! Tests for the TCP calls and the proxy `CONNECT` (M1-091).
//!
//! The exit test: a host listed only by another check is denied, a `CONNECT` to a literal
//! 169.254.169.254 is refused before any byte is sent, proxy 403 and 407 return typed errors,
//! `Proxy-Authorization` never appears in the log, the log has one entry per tcp call, the proxy
//! password is a known secret, and the facade connects the duplex stream that a Replay `dial` names.
//!
//! The replay tests run on paused time. The loopback tests (`testing::loopback`) use real sockets and
//! the real clock, with short timeouts where a test waits for one.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rdy_spec::Target;
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::check::{CheckInfo, CheckMeta, Os, OsSupport, Support};
use crate::family::HostSet;
use crate::probe::proxy::ProxyChallenge;
use crate::probe::replay::{Fixture, Replay, TcpScript};
use crate::probe::{FileBytes, ProxyError, RULE_CHECK_FINISHED};
use crate::redact::{Redactor, TagKey};
use crate::testing::loopback::{
    ConnectProxy, HttpOptions, HttpServer, NeverAccepts, ProxyMode, closed_port,
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

/// A check that reaches its spec hosts, direct or through the proxy.
pub(super) fn egress() -> &'static CheckInfo {
    info!("net.egress", &[PeerClass::SpecHosts, PeerClass::Proxy])
}

/// A check that declares no peer class at all.
pub(super) fn no_peers() -> &'static CheckInfo {
    info!("net.none", &[])
}

/// A check that reaches its spec hosts and declares no proxy.
pub(super) fn direct_only() -> &'static CheckInfo {
    info!("net.direct", &[PeerClass::SpecHosts])
}

pub(super) fn hub_over(backend: impl Backend) -> ProbeHub {
    ProbeHub::new(Arc::new(backend), Redactor::new(TagKey::fixed([5; 32])))
}

pub(super) fn target(text: &str) -> Target {
    Target::parse(text).expect("a valid target")
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

pub(super) fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

pub(super) fn probe_with(
    hub: &ProbeHub,
    info: &'static CheckInfo,
    key: &str,
    hosts: &[&str],
) -> Probe {
    let probe = hub.check_probe(key, Os::Linux, Some(info));
    probe.permit_hosts(HostSet::new(hosts.iter().map(|t| target(t))));
    probe
}

pub(super) fn probe(hub: &ProbeHub, hosts: &[&str]) -> Probe {
    probe_with(hub, egress(), "net.egress", hosts)
}

pub(super) fn entries(hub: &ProbeHub) -> Vec<Action> {
    hub.action_log().actions
}

pub(super) fn field<'a>(action: &'a Action, name: &str) -> Option<&'a Value> {
    action.fields.get(name)
}

pub(super) fn denied_rule(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A factory that counts the connections made to it and hands out the client end of a pipe whose
/// server end is dropped.
fn counting(
    count: &Arc<AtomicUsize>,
) -> impl Fn() -> std::future::Ready<io::Result<BoxedStream>> + use<> {
    let count = Arc::clone(count);
    move || {
        count.fetch_add(1, Ordering::SeqCst);
        let (client, _server) = tokio::io::duplex(64);
        std::future::ready(Ok(Box::new(client) as BoxedStream))
    }
}

fn web_script(replay: Replay, address: &str) -> Replay {
    replay.tcp(addr(address), TcpScript::Serve("web".to_owned()))
}

// ---- peers: the host set ----------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_host_listed_only_by_another_check_is_denied() {
    let opened = Arc::new(AtomicUsize::new(0));
    let replay = web_script(
        web_script(
            Replay::new()
                .host("a.acme.test", [ip("192.0.2.1")])
                .host("b.acme.test", [ip("192.0.2.2")]),
            "192.0.2.1:443",
        ),
        "192.0.2.2:443",
    )
    .serve("web", counting(&opened));
    let hub = hub_over(replay);
    let a = probe_with(&hub, egress(), "net.egress/a", &["a.acme.test:443"]);
    let b = probe_with(&hub, egress(), "net.egress/b", &["b.acme.test:443"]);

    // A may not reach what only B lists, and the backend never sees the call.
    let error = a
        .tcp(&target("b.acme.test:443"), Route::Direct)
        .await
        .expect_err("not A's host");
    assert_eq!(denied_rule(&error), RULE_TCP_HOST);
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    // A different port on its own host is another peer.
    let error = a
        .tcp(&target("a.acme.test:8443"), Route::Direct)
        .await
        .expect_err("not A's port");
    assert_eq!(denied_rule(&error), RULE_TCP_HOST);
    assert_eq!(opened.load(Ordering::SeqCst), 0);

    // Each reaches its own.
    let report = a
        .tcp(&target("a.acme.test:443"), Route::Direct)
        .await
        .expect("A's host");
    assert!(report.connected);
    b.tcp(&target("b.acme.test:443"), Route::Direct)
        .await
        .expect("B's host");
    let error = b
        .tcp(&target("a.acme.test:443"), Route::Direct)
        .await
        .expect_err("not B's host");
    assert_eq!(denied_rule(&error), RULE_TCP_HOST);
    assert_eq!(opened.load(Ordering::SeqCst), 2);

    // The log names the check that asked and the rule.
    let log = entries(&hub);
    assert_eq!(log.len(), 5, "one entry per call: {log:?}");
    assert_eq!(log[0].check.as_deref(), Some("net.egress/a"));
    assert_eq!(log[0].outcome, ActionOutcome::Denied);
    assert_eq!(field(&log[0], "rule"), Some(&Value::from(RULE_TCP_HOST)));
    assert_eq!(field(&log[0], "host"), Some(&Value::from("b.acme.test")));
    assert_eq!(log[4].check.as_deref(), Some("net.egress/b"));
    assert_eq!(log[4].outcome, ActionOutcome::Denied);
}

#[tokio::test(start_paused = true)]
async fn a_probe_with_no_hosts_or_no_declaration_can_reach_nothing() {
    let opened = Arc::new(AtomicUsize::new(0));
    let replay = web_script(
        Replay::new().host("a.acme.test", [ip("192.0.2.1")]),
        "192.0.2.1:443",
    )
    .serve("web", counting(&opened));
    let hub = hub_over(replay);
    let a = target("a.acme.test:443");

    // Nobody gave the probe hosts.
    let none = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    let error = none.tcp(&a, Route::Direct).await.expect_err("no hosts");
    assert_eq!(denied_rule(&error), RULE_TCP_HOST);
    // The host is listed, and the check did not declare the peer class.
    let undeclared = probe_with(
        &hub,
        info!("net.silent", &[]),
        "net.silent",
        &["a.acme.test:443"],
    );
    let error = undeclared
        .tcp(&a, Route::Direct)
        .await
        .expect_err("undeclared");
    assert_eq!(denied_rule(&error), RULE_TCP_UNDECLARED);
    // A probe with no manifest at all is closed too.
    let bare = hub.check_probe("net.bare", Os::Linux, None);
    bare.permit_hosts(HostSet::new([a.clone()]));
    let error = bare.tcp(&a, Route::Direct).await.expect_err("no manifest");
    assert_eq!(denied_rule(&error), RULE_TCP_UNDECLARED);
    // The proxy is its own class.
    let direct = probe_with(&hub, direct_only(), "net.direct", &["a.acme.test:443"]);
    let error = direct
        .tcp(&a, Route::ViaProxy)
        .await
        .expect_err("proxy undeclared");
    assert_eq!(denied_rule(&error), RULE_PROXY_UNDECLARED);
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    assert!(
        entries(&hub)
            .iter()
            .all(|e| e.outcome == ActionOutcome::Denied)
    );
}

// ---- the address rule ---------------------------------------------------------------------------

#[tokio::test]
async fn a_connect_to_a_literal_metadata_address_sends_no_byte() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let proxy =
        ConnectProxy::start_with_routes(ProxyMode::Ok, &[("web.acme.test:443", server.addr())])
            .await
            .expect("proxy");
    let hub = hub_over(proxied(proxy.addr()));
    hub.set_proxy_text("http://proxy.acme.test:3128")
        .expect("proxy");
    let literals = [
        "169.254.169.254:443",
        "169.254.0.1:80",
        "100.100.100.200:443",
        "[fe80::1]:443",
        "[fd00:ec2::254]:443",
        "[fd20:ce::254]:443",
        "168.63.129.16:80",
        "0.0.0.0:443",
    ];
    let mut hosts = literals.to_vec();
    hosts.push("web.acme.test:443");
    let probe = probe(&hub, &hosts);
    for text in literals {
        for route in [Route::ViaProxy, Route::Direct] {
            let error = probe
                .tcp(&target(text), route)
                .await
                .expect_err("a forbidden literal");
            assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "{text}");
        }
    }
    // Not a connection to the proxy, not a byte, not a request.
    assert_eq!(proxy.accepted(), 0);
    assert_eq!(proxy.bytes_received(), 0);
    assert!(proxy.requests().is_empty());
    let log = entries(&hub);
    assert_eq!(log.len(), literals.len() * 2);
    assert!(log.iter().all(|e| e.outcome == ActionOutcome::Denied));
    assert!(
        log.iter()
            .all(|e| field(e, "rule") == Some(&Value::from(RULE_TCP_ADDRESS)))
    );

    // Positive control: an allowed target through the same proxy does reach it, so the zero counts
    // above are not true of a proxy that nothing can reach.
    let report = probe
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect("an allowed target");
    assert!(report.connected);
    assert_eq!(proxy.accepted(), 1);
    assert!(proxy.bytes_received() > 0);
    assert_eq!(proxy.requests().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_proxy_that_resolves_to_a_forbidden_address_is_refused_as_the_proxy() {
    let opened = Arc::new(AtomicUsize::new(0));
    let replay = web_script(
        Replay::new()
            .host("proxy.acme.test", [ip("169.254.169.254")])
            .host("mixed.acme.test", [ip("192.0.2.7"), ip("fe80::1")]),
        "192.0.2.7:3128",
    )
    .serve("web", counting(&opened));
    for text in [
        "http://proxy.acme.test:3128",
        "http://mixed.acme.test:3128",
        "http://169.254.169.254:3128",
        "http://[fe80::1]:3128",
    ] {
        let hub = hub_over(replay.clone());
        hub.set_proxy_text(text).expect("proxy");
        let probe = probe(&hub, &["web.acme.test:443"]);
        let error = probe
            .tcp(&target("web.acme.test:443"), Route::ViaProxy)
            .await
            .expect_err("the proxy address is refused");
        // The rule names the proxy, not the target the check asked for.
        assert_eq!(denied_rule(&error), RULE_PROXY_ADDRESS, "{text}");
        assert_ne!(RULE_PROXY_ADDRESS, RULE_TCP_ADDRESS);
        assert_eq!(opened.load(Ordering::SeqCst), 0, "{text}");
        let log = entries(&hub);
        assert_eq!(log.len(), 1);
        assert_eq!(
            field(&log[0], "rule"),
            Some(&Value::from(RULE_PROXY_ADDRESS))
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_name_that_resolves_to_a_forbidden_address_is_refused_for_the_whole_call() {
    let opened = Arc::new(AtomicUsize::new(0));
    let mut replay = Replay::new()
        .host("meta.acme.test", [ip("169.254.169.254")])
        .host("mapped.acme.test", [ip("::ffff:169.254.169.254")])
        .host("nat64.acme.test", [ip("64:ff9b::a9fe:a9fe")])
        .host("linklocal.acme.test", [ip("fe80::1")])
        .host("aliyun.acme.test", [ip("100.100.100.200")])
        .host("gcp6.acme.test", [ip("fd20:ce::254")])
        .host("azure.acme.test", [ip("168.63.129.16")])
        .host("azure-mapped.acme.test", [ip("::ffff:168.63.129.16")])
        // One good answer does not save a bad one.
        .host("mixed.acme.test", [ip("192.0.2.7"), ip("169.254.169.254")])
        .host("zero.acme.test", [ip("0.0.0.0")]);
    replay = web_script(replay, "192.0.2.7:443").serve("web", counting(&opened));
    let hub = hub_over(replay);
    let names = [
        "meta",
        "mapped",
        "nat64",
        "linklocal",
        "aliyun",
        "gcp6",
        "azure",
        "azure-mapped",
        "mixed",
        "zero",
    ];
    let hosts: Vec<String> = names.iter().map(|n| format!("{n}.acme.test:443")).collect();
    let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
    let probe = probe(&hub, &hosts);
    for host in &hosts {
        let error = probe
            .tcp(&target(host), Route::Direct)
            .await
            .expect_err("a forbidden answer");
        assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "{host}");
    }
    assert_eq!(opened.load(Ordering::SeqCst), 0, "nothing was opened");
    let log = entries(&hub);
    assert_eq!(log.len(), hosts.len());
    assert!(log.iter().all(|e| e.outcome == ActionOutcome::Denied));
}

#[tokio::test(start_paused = true)]
async fn loopback_and_private_addresses_are_allowed() {
    let opened = Arc::new(AtomicUsize::new(0));
    let replay = Replay::new()
        .host("lan.acme.test", [ip("10.1.2.3")])
        .tcp(addr("10.1.2.3:443"), TcpScript::Serve("web".to_owned()))
        .tcp(addr("127.0.0.1:443"), TcpScript::Serve("web".to_owned()))
        .serve("web", counting(&opened));
    let hub = hub_over(replay);
    let probe = probe(&hub, &["lan.acme.test:443", "127.0.0.1:443"]);
    for host in ["lan.acme.test:443", "127.0.0.1:443"] {
        assert!(
            probe
                .tcp(&target(host), Route::Direct)
                .await
                .expect(host)
                .connected
        );
    }
    assert_eq!(opened.load(Ordering::SeqCst), 2);
}

// ---- the replay dial: a check's connect reaches the started server --------------------------------

#[tokio::test(start_paused = true)]
async fn the_duplex_stream_a_replay_dial_names_is_what_the_connect_gets() {
    let replay = Replay::new()
        .tcp(addr("192.0.2.10:443"), TcpScript::Serve("echo".to_owned()))
        .tcp(addr("192.0.2.11:443"), TcpScript::Refused)
        .tcp(addr("192.0.2.12:443"), TcpScript::Reset)
        .serve_duplex("echo", |mut server| async move {
            let mut buf = [0_u8; 16];
            let n = server.read(&mut buf).await.expect("read");
            server.write_all(b"echo:").await.expect("write");
            server.write_all(&buf[..n]).await.expect("write");
        });
    // The backend end of the seam: the stream is the pipe to the started server.
    let mut stream = replay
        .connect(addr("192.0.2.10:443"))
        .await
        .expect("served");
    stream.write_all(b"ping").await.expect("send");
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.expect("read");
    assert_eq!(got, b"echo:ping");
    for (to, kind) in [
        ("192.0.2.11:443", io::ErrorKind::ConnectionRefused),
        ("192.0.2.12:443", io::ErrorKind::ConnectionReset),
    ] {
        assert_eq!(
            replay.connect(addr(to)).await.err().map(|e| e.kind()),
            Some(kind)
        );
    }
    // A name nobody registered, and an address nobody scripted, are not recorded.
    let unnamed = Replay::new().tcp(addr("192.0.2.10:443"), TcpScript::Serve("gone".to_owned()));
    let error = unnamed
        .connect(addr("192.0.2.10:443"))
        .await
        .err()
        .expect("not recorded");
    assert_eq!(
        ProbeError::from_io(&error),
        ProbeError::NotRecorded("a server named gone".to_owned())
    );
    let error = replay
        .connect(addr("192.0.2.99:443"))
        .await
        .err()
        .expect("not recorded");
    assert_eq!(
        ProbeError::from_io(&error),
        ProbeError::NotRecorded("a connection to 192.0.2.99:443".to_owned())
    );
}

#[tokio::test(start_paused = true)]
async fn a_check_connects_through_a_net_json_serve_entry() {
    // The 08 form: `net.json` scripts the name and the address, and the test registers the server.
    let fixture = load_net(
        r#"{"dns": {"registry.acme.test": ["192.0.2.10"], "gone.acme.test": "NXDOMAIN"},
            "tcp": {"192.0.2.10:443": {"serve": "registry"}, "192.0.2.11:443": "refused"}}"#,
    );
    let served = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&served);
    let replay = fixture
        .into_replay()
        .serve_duplex("registry", move |_server| {
            seen.fetch_add(1, Ordering::SeqCst);
            async {}
        });
    let hub = hub_over(replay);
    let probe = probe(&hub, &["registry.acme.test:443", "gone.acme.test:443"]);

    let report = probe
        .tcp(&target("registry.acme.test:443"), Route::Direct)
        .await
        .expect("served");
    assert!(report.connected);
    assert_eq!(report.addr, Some(addr("192.0.2.10:443")));
    tokio::task::yield_now().await;
    assert_eq!(served.load(Ordering::SeqCst), 1, "the started server ran");

    let error = probe
        .tcp(&target("gone.acme.test:443"), Route::Direct)
        .await
        .expect_err("NXDOMAIN");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::Dns {
            host: "gone.acme.test".to_owned()
        })
    );
    assert!(error.to_string().contains("Fix:"));
    let log = entries(&hub);
    assert_eq!(log.len(), 2);
    assert_eq!(log[1].outcome, ActionOutcome::Failed);
}

pub(super) fn load_net(net_json: &str) -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let base = dir.path().join("envs/x");
    std::fs::create_dir_all(&base).expect("dirs");
    std::fs::write(
        base.join("fixture.toml"),
        "schema = 1\nname = \"x\"\nsummary = \"A test machine\"\norigin = \"hand\"\nos = \"linux\"\n\
         arch = \"x86_64\"\nanswers = [\"net.egress\"]\n\n[caps]\nroot = false\nnetwork = true\nkube = false\n",
    )
    .expect("manifest");
    std::fs::write(base.join("net.json"), net_json).expect("net.json");
    Fixture::load(dir.path(), "envs/x").expect("the fixture loads")
}

// ---- attempts -----------------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_silent_ipv6_address_falls_through_to_ipv4_after_the_stagger() {
    let opened = Arc::new(AtomicUsize::new(0));
    let replay = Replay::new()
        .host("dual.acme.test", [ip("192.0.2.1"), ip("2001:db8::1")])
        .tcp(addr("[2001:db8::1]:443"), TcpScript::Blackhole)
        .tcp(addr("192.0.2.1:443"), TcpScript::Serve("web".to_owned()))
        .serve("web", counting(&opened));
    let hub = hub_over(replay);
    let report = probe(&hub, &["dual.acme.test:443"])
        .tcp(&target("dual.acme.test:443"), Route::Direct)
        .await
        .expect("connected");
    assert!(report.connected);
    assert_eq!(report.addr, Some(addr("192.0.2.1:443")));
    // IPv6 first. The IPv4 attempt starts one stagger later and wins, and the silent one is named.
    assert_eq!(report.attempts.len(), 2);
    assert_eq!(report.attempts[0].addr, addr("[2001:db8::1]:443"));
    assert_eq!(report.attempts[0].started, Duration::ZERO);
    assert_eq!(report.attempts[0].outcome, AttemptOutcome::Abandoned);
    assert_eq!(report.attempts[0].elapsed, STAGGER);
    assert_eq!(report.attempts[1].addr, addr("192.0.2.1:443"));
    assert_eq!(report.attempts[1].started, STAGGER);
    assert_eq!(report.attempts[1].outcome, AttemptOutcome::Connected);
    assert_eq!(opened.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn a_failed_attempt_starts_the_next_at_once() {
    let opened = Arc::new(AtomicUsize::new(0));
    let replay = Replay::new()
        .host("dual.acme.test", [ip("192.0.2.1"), ip("2001:db8::1")])
        .tcp(addr("[2001:db8::1]:443"), TcpScript::Refused)
        .tcp(addr("192.0.2.1:443"), TcpScript::Serve("web".to_owned()))
        .serve("web", counting(&opened));
    let hub = hub_over(replay);
    let report = probe(&hub, &["dual.acme.test:443"])
        .tcp(&target("dual.acme.test:443"), Route::Direct)
        .await
        .expect("connected");
    assert_eq!(report.attempts[0].outcome, AttemptOutcome::Refused);
    assert_eq!(report.attempts[1].outcome, AttemptOutcome::Connected);
    assert_eq!(report.attempts[1].started, Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn nothing_connecting_is_a_report_not_an_error() {
    let replay = Replay::new()
        .host("dead.acme.test", [ip("192.0.2.1"), ip("2001:db8::1")])
        .host("shut.acme.test", [ip("192.0.2.2")])
        .host("reset.acme.test", [ip("192.0.2.3")])
        .tcp(addr("[2001:db8::1]:443"), TcpScript::Blackhole)
        .tcp(addr("192.0.2.1:443"), TcpScript::Blackhole)
        .tcp(addr("192.0.2.2:443"), TcpScript::Refused)
        .tcp(addr("192.0.2.3:443"), TcpScript::Reset);
    let hub = hub_over(replay);
    let probe = probe(
        &hub,
        &[
            "dead.acme.test:443",
            "shut.acme.test:443",
            "reset.acme.test:443",
        ],
    );

    let started = tokio::time::Instant::now();
    let silent = probe
        .tcp(&target("dead.acme.test:443"), Route::Direct)
        .await
        .expect("a report");
    assert!(!silent.connected);
    assert_eq!(silent.addr, None);
    assert!(
        silent
            .attempts
            .iter()
            .all(|a| a.outcome == AttemptOutcome::TimedOut)
    );
    assert_eq!(silent.attempts[0].elapsed, ATTEMPT_TIMEOUT);
    // The second attempt started one stagger after the first, and both waited the full limit.
    assert_eq!(started.elapsed(), ATTEMPT_TIMEOUT + STAGGER);

    let refused = probe
        .tcp(&target("shut.acme.test:443"), Route::Direct)
        .await
        .expect("a report");
    assert_eq!(refused.attempts[0].outcome, AttemptOutcome::Refused);
    let reset = probe
        .tcp(&target("reset.acme.test:443"), Route::Direct)
        .await
        .expect("a report");
    assert_eq!(reset.attempts[0].outcome, AttemptOutcome::Reset);

    let log = entries(&hub);
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].outcome, ActionOutcome::Timeout);
    assert_eq!(
        field(&log[0], "error"),
        Some(&Value::from("no answer in time"))
    );
    assert_eq!(log[1].outcome, ActionOutcome::Failed);
    assert_eq!(
        field(&log[1], "error"),
        Some(&Value::from("connection refused"))
    );
    assert_eq!(log[2].outcome, ActionOutcome::Failed);
}

#[tokio::test(start_paused = true)]
async fn at_most_four_addresses_are_tried_in_alternating_order() {
    let mut replay = Replay::new().host(
        "many.acme.test",
        [
            ip("192.0.2.1"),
            ip("192.0.2.2"),
            ip("192.0.2.3"),
            ip("2001:db8::1"),
            ip("2001:db8::2"),
            ip("2001:db8::3"),
            // A repeat is one address.
            ip("192.0.2.1"),
        ],
    );
    for a in [
        "192.0.2.1:443",
        "192.0.2.2:443",
        "192.0.2.3:443",
        "[2001:db8::1]:443",
        "[2001:db8::2]:443",
        "[2001:db8::3]:443",
    ] {
        replay = replay.tcp(addr(a), TcpScript::Refused);
    }
    let hub = hub_over(replay);
    let report = probe(&hub, &["many.acme.test:443"])
        .tcp(&target("many.acme.test:443"), Route::Direct)
        .await
        .expect("a report");
    let tried: Vec<SocketAddr> = report.attempts.iter().map(|a| a.addr).collect();
    assert_eq!(
        tried,
        [
            addr("[2001:db8::1]:443"),
            addr("192.0.2.1:443"),
            addr("[2001:db8::2]:443"),
            addr("192.0.2.2:443"),
        ]
    );
}

#[test]
fn addresses_alternate_families_with_ipv6_first_and_stop_at_the_cap() {
    let ips = |list: &[&str]| -> Vec<IpAddr> { list.iter().map(|t| ip(t)).collect() };
    assert_eq!(order(&[]), Vec::<IpAddr>::new());
    assert_eq!(order(&ips(&["192.0.2.1"])), ips(&["192.0.2.1"]));
    assert_eq!(
        order(&ips(&["192.0.2.1", "192.0.2.2", "2001:db8::1"])),
        ips(&["2001:db8::1", "192.0.2.1", "192.0.2.2"])
    );
    assert_eq!(
        order(&ips(&[
            "2001:db8::1",
            "2001:db8::2",
            "2001:db8::3",
            "2001:db8::4",
            "2001:db8::5"
        ])),
        ips(&["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"])
    );
    assert_eq!(
        order(&ips(&["192.0.2.1", "192.0.2.1", "192.0.2.1"])),
        ips(&["192.0.2.1"])
    );
}

#[tokio::test(start_paused = true)]
async fn an_address_the_fixture_does_not_script_is_not_recorded() {
    let replay = Replay::new().host("odd.acme.test", [ip("192.0.2.99")]);
    let hub = hub_over(replay);
    let error = probe(&hub, &["odd.acme.test:443", "unknown.acme.test:443"])
        .tcp(&target("odd.acme.test:443"), Route::Direct)
        .await
        .expect_err("not recorded");
    assert_eq!(
        error,
        ProbeError::NotRecorded("a connection to 192.0.2.99:443".to_owned())
    );
    // A name the fixture does not hold is not recorded either, and is not "does not resolve".
    let error = probe_with(&hub, egress(), "net.egress", &["unknown.acme.test:443"])
        .tcp(&target("unknown.acme.test:443"), Route::Direct)
        .await
        .expect_err("not recorded");
    assert_eq!(
        error,
        ProbeError::NotRecorded("a lookup of unknown.acme.test".to_owned())
    );
}

#[tokio::test(start_paused = true)]
async fn a_call_after_the_check_ended_is_denied_and_logged() {
    let opened = Arc::new(AtomicUsize::new(0));
    let replay = web_script(Replay::new(), "192.0.2.1:443").serve("web", counting(&opened));
    let hub = hub_over(replay);
    let probe = probe(&hub, &["192.0.2.1:443"]);
    probe.end();
    let error = probe
        .tcp(&target("192.0.2.1:443"), Route::Direct)
        .await
        .expect_err("ended");
    assert_eq!(denied_rule(&error), RULE_CHECK_FINISHED);
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    assert_eq!(entries(&hub).len(), 1);
}

// ---- the proxy ------------------------------------------------------------------------------------

/// The canary password, as the URL writes it, and as it is after percent-decoding.
const PASSWORD_RAW: &str = "Pa55%2Dcanary%40x";
const PASSWORD: &str = "Pa55-canary@x";
/// The base64 of `svc:Pa55-canary@x`: what the proxy should see.
const AUTH: &str = "Basic c3ZjOlBhNTUtY2FuYXJ5QHg=";

/// A replay machine whose only route is the proxy: `proxy.acme.test:3128` is served by `proxy`.
fn proxied(proxy: SocketAddr) -> Replay {
    Replay::new()
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(
            addr("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_tcp("proxy", proxy)
}

fn proxy_url(with_password: bool) -> String {
    if with_password {
        format!("http://svc:{PASSWORD_RAW}@proxy.acme.test:3128")
    } else {
        "http://proxy.acme.test:3128".to_owned()
    }
}

/// Everything the log and the redacted report could show, as text.
fn log_text(hub: &ProbeHub) -> String {
    serde_json::to_string(&hub.action_log().actions).expect("the log is JSON")
}

fn assert_no_credentials(text: &str) {
    for leaked in [
        PASSWORD,
        PASSWORD_RAW,
        "Pa55",
        "canary",
        "c3ZjOlBhNTUtY2FuYXJ5QHg",
        "Proxy-Authorization",
        "Authorization",
        "Basic ",
    ] {
        assert!(!text.contains(leaked), "{leaked:?} leaked into: {text}");
    }
}

#[tokio::test]
async fn proxy_403_and_407_return_typed_errors_and_no_credential_reaches_the_log() {
    let cases = [
        (
            ProxyMode::Forbidden,
            NetFailure::ProxyForbidden {
                target: "web.acme.test:443".to_owned(),
            },
        ),
        (
            ProxyMode::Basic407,
            NetFailure::ProxyAuthRequired {
                target: "web.acme.test:443".to_owned(),
                challenge: ProxyChallenge::Basic,
                sent_credentials: true,
            },
        ),
        (
            ProxyMode::Negotiate407,
            NetFailure::ProxyAuthRequired {
                target: "web.acme.test:443".to_owned(),
                challenge: ProxyChallenge::Negotiate,
                sent_credentials: true,
            },
        ),
    ];
    for (mode, want) in cases {
        let proxy = ConnectProxy::start(mode).await.expect("proxy");
        let hub = hub_over(proxied(proxy.addr()));
        hub.set_proxy_text(&proxy_url(true)).expect("proxy");
        let probe = probe(&hub, &["web.acme.test:443"]);

        let error = probe
            .tcp(&target("web.acme.test:443"), Route::ViaProxy)
            .await
            .expect_err("the proxy says no");
        assert_eq!(error, ProbeError::Net(want), "{mode:?}");
        assert!(error.to_string().contains("Fix:"), "{error}");

        // The proxy did receive the credentials, so the tests below prove the log does not repeat them.
        let seen = proxy.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].target, "web.acme.test:443");
        assert_eq!(seen[0].proxy_authorization.as_deref(), Some(AUTH));

        // One entry for the call, proxy CONNECT included.
        let log = entries(&hub);
        assert_eq!(log.len(), 1, "{mode:?}: {log:?}");
        assert_eq!(log[0].kind, ActionKind::Connect);
        assert_eq!(log[0].outcome, ActionOutcome::Failed);
        assert_eq!(field(&log[0], "host"), Some(&Value::from("web.acme.test")));
        assert_eq!(field(&log[0], "port"), Some(&Value::from(443)));
        assert_eq!(
            field(&log[0], "via_proxy"),
            Some(&Value::from("http://proxy.acme.test:3128"))
        );
        // The log holds the fixed phrase of the failure, not the user message with its host and fix.
        let ProbeError::Net(failure) = &error else {
            panic!("expected a network failure, got {error:?}");
        };
        let phrase = field(&log[0], "error")
            .and_then(Value::as_str)
            .expect("an error phrase");
        assert_eq!(phrase, failure.log_phrase(), "{mode:?}");
        assert!(
            phrase.contains("CONNECT") || phrase.contains("407"),
            "{phrase}"
        );
        assert!(
            !phrase.contains("Fix:") && !phrase.contains("web.acme.test"),
            "{phrase}"
        );
        assert_eq!(field(&log[0], "addr"), Some(&Value::Null));
        assert_no_credentials(&log_text(&hub));
        assert_no_credentials(&format!("{error} {error:?}"));
    }
}

/// The result schema, as the generator wrote it.
pub(super) fn assert_matches_result_schema(report: &Value) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("../rdy-spec/schema/result.v1.schema.json"))
        .expect("schema file");
    let schema: Value = serde_json::from_str(&text).expect("schema json");
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(report)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the report fails the schema: {errors:#?}"
    );
}

#[tokio::test]
async fn failed_and_denied_connect_entries_match_the_result_schema() {
    let proxy = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let hub = hub_over(proxied(proxy.addr()));
    hub.set_proxy_text(&proxy_url(true)).expect("proxy");
    let probe = probe(&hub, &["web.acme.test:443", "169.254.169.254:443"]);
    // A proxied call that failed and one that was denied.
    probe
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect_err("403");
    probe
        .tcp(&target("169.254.169.254:443"), Route::ViaProxy)
        .await
        .expect_err("denied");

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample =
        std::fs::read_to_string(root.join("../../tests/fixtures/reports/not-ready-7.2.json"))
            .expect("the fixture is in the repo");
    let mut report: rdy_spec::result::Report = serde_json::from_str(&sample).expect("a report");
    hub.action_log().apply(&mut report);
    let json = serde_json::to_value(&report).expect("report");
    assert_matches_result_schema(&json);
    let connects: Vec<&Value> = json["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .filter(|a| a["kind"] == "connect")
        .collect();
    assert_eq!(connects.len(), 2);
    for entry in connects {
        assert_eq!(entry["addr"], Value::Null, "{entry}");
    }
}

#[tokio::test]
async fn a_407_without_credentials_in_the_url_says_so_and_sends_no_authorization() {
    let proxy = ConnectProxy::start(ProxyMode::Basic407)
        .await
        .expect("proxy");
    let hub = hub_over(proxied(proxy.addr()));
    hub.set_proxy_text(&proxy_url(false)).expect("proxy");
    let error = probe(&hub, &["web.acme.test:443"])
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect_err("407");
    assert_eq!(
        error,
        ProbeError::Net(NetFailure::ProxyAuthRequired {
            target: "web.acme.test:443".to_owned(),
            challenge: ProxyChallenge::Basic,
            sent_credentials: false,
        })
    );
    assert!(error.to_string().contains("http://user:password@host:port"));
    assert_eq!(proxy.requests()[0].proxy_authorization, None);
}

#[tokio::test]
async fn a_connect_through_the_proxy_opens_a_tunnel_and_logs_one_entry() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let proxy =
        ConnectProxy::start_with_routes(ProxyMode::Ok, &[("web.acme.test:443", server.addr())])
            .await
            .expect("proxy");
    let hub = hub_over(proxied(proxy.addr()));
    hub.set_proxy_text(&proxy_url(true)).expect("proxy");
    let probe = probe(&hub, &["web.acme.test:443"]);

    let report = probe
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect("a tunnel");
    assert!(report.connected && report.via_proxy);
    assert_eq!(report.proxy_status, Some(200));
    // The attempts are to the proxy. The target's address is not known here.
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].addr, addr("192.0.2.50:3128"));
    assert_eq!(proxy.requests()[0].target, "web.acme.test:443");
    assert_eq!(
        proxy.requests()[0].proxy_authorization.as_deref(),
        Some(AUTH)
    );

    let log = entries(&hub);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
    assert_eq!(
        field(&log[0], "proto"),
        None,
        "no proto marks a TCP connection"
    );
    assert_eq!(field(&log[0], "addr"), Some(&Value::Null));
    assert_no_credentials(&log_text(&hub));
}

#[tokio::test]
async fn a_proxy_that_is_not_http_or_not_set_is_a_typed_failure() {
    // No proxy set for the run.
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let hub = hub_over(proxied(proxy.addr()));
    let error = probe(&hub, &["web.acme.test:443"])
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect_err("no proxy");
    assert_eq!(error, ProbeError::Net(NetFailure::NoProxy));
    assert_eq!(proxy.accepted(), 0);

    // A server that speaks something else, a head that never ends and a close with no reply.
    let replay = Replay::new()
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(
            addr("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_duplex("proxy", |mut server| async move {
            let mut buf = [0_u8; 512];
            let _ = server.read(&mut buf).await;
            let _ = server.write_all(b"SSH-2.0-OpenSSH_9.6\r\n\r\n").await;
        });
    let hub = hub_over(replay);
    hub.set_proxy_text(&proxy_url(false)).expect("proxy");
    let probe = probe(&hub, &["web.acme.test:443"]);
    let error = probe
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect_err("not HTTP");
    assert!(
        matches!(error, ProbeError::Net(NetFailure::ProxyBadReply { .. })),
        "{error:?}"
    );
    assert!(error.to_string().contains("Fix:"));

    let endless = Replay::new()
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(
            addr("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_duplex("proxy", |mut server| async move {
            let mut buf = [0_u8; 512];
            let _ = server.read(&mut buf).await;
            let _ = server.write_all(b"HTTP/1.1 200 OK\r\n").await;
            for _ in 0..20_000 {
                if server.write_all(b"X-Padding: yes\r\n").await.is_err() {
                    return;
                }
            }
        });
    let hub = hub_over(endless);
    hub.set_proxy_text(&proxy_url(false)).expect("proxy");
    let error = probe_with(&hub, egress(), "net.egress", &["web.acme.test:443"])
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect_err("a head over 8 KiB");
    assert!(
        matches!(&error, ProbeError::Net(NetFailure::ProxyBadReply { reason }) if reason.contains("8 KiB")),
        "{error:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_connect_head_is_read_byte_by_byte_and_none_of_the_tunnel_is_taken() {
    // A server that answers 200 and sends its greeting in the same write. The facade must leave the
    // greeting in the stream for the next layer.
    let replay = Replay::new()
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(
            addr("192.0.2.50:3128"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_duplex("proxy", |mut server| async move {
            let mut buf = [0_u8; 512];
            let _ = server.read(&mut buf).await;
            let _ = server
                .write_all(
                    b"HTTP/1.1 200 Connection Established\r\n\r\n220 mail.acme.test ESMTP\r\n",
                )
                .await;
        });
    let backend: Arc<dyn Backend> = Arc::new(replay);
    let mut stream = backend
        .connect(addr("192.0.2.50:3128"))
        .await
        .expect("stream");
    let proxy = ProxyUrl::parse("http://proxy.acme.test:3128").expect("proxy");
    let status = tunnel(
        &mut stream,
        &proxy,
        "mail.acme.test:25",
        Duration::from_secs(5),
    )
    .await
    .expect("a tunnel");
    assert_eq!(status, 200);
    let mut greeting = vec![0_u8; b"220 mail.acme.test ESMTP\r\n".len()];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("the greeting");
    assert_eq!(greeting, b"220 mail.acme.test ESMTP\r\n");
}

// ---- the proxy password is a known secret ---------------------------------------------------------

#[tokio::test]
async fn the_proxy_password_is_registered_raw_and_decoded_when_the_proxy_is_set() {
    let hub = hub_over(Replay::new());
    let probe = hub.run_probe();
    let show = |text: &str| {
        probe
            .file_text(&FileBytes::new(text.as_bytes().to_vec()))
            .expect("text")
            .to_string()
    };
    // Nothing is known yet.
    assert_eq!(show("pw is Pa55-canary@x"), "pw is Pa55-canary@x");

    hub.set_proxy_text(&proxy_url(true)).expect("proxy");
    let decoded = show("the password is Pa55-canary@x here");
    assert!(!decoded.contains(PASSWORD), "{decoded}");
    let raw = show("the url had Pa55%2Dcanary%40x in it");
    assert!(!raw.contains("canary"), "{raw}");
    let pair = show("Proxy-Authorization: Basic c3ZjOlBhNTUtY2FuYXJ5QHg=");
    assert!(!pair.contains("c3ZjOlBhNTUtY2FuYXJ5QHg"), "{pair}");
    // Once only.
    assert_eq!(
        hub.set_proxy_text("http://other.acme.test:3128"),
        Err(ProxyError::AlreadySet)
    );
}

#[tokio::test]
async fn a_password_the_set_refuses_stops_the_run_and_sets_no_proxy() {
    let hub = hub_over(proxied(addr("127.0.0.1:9")));
    // Under 6 bytes, so the set cannot match it without redacting common words.
    let error = hub
        .set_proxy_text("http://svc:pw@proxy.acme.test:3128")
        .expect_err("refused");
    assert_eq!(error, ProxyError::SecretRefused);
    assert!(error.to_string().contains("Fix:"));
    assert!(!error.to_string().contains("pw"));
    // The refusal is counted in the report's redaction counts, with no value.
    let counts = hub.action_log().redaction;
    assert_eq!(counts.get("known_secret_refused"), 1);
    // The proxy was not set, so a corrected URL is accepted (it is not `AlreadySet`).
    hub.set_proxy_text("http://svc:longer-canary-pw@proxy.acme.test:3128")
        .expect("accepted");
    // A bad URL is a typed error that echoes nothing.
    let hub = hub_over(Replay::new());
    let error = hub
        .set_proxy_text("socks5://svc:Canary-pw-1@proxy.acme.test:1080")
        .expect_err("scheme");
    assert!(matches!(error, ProxyError::Url(_)));
    assert!(!error.to_string().contains("Canary"));
}

#[tokio::test]
async fn a_user_with_no_password_is_the_secret() {
    // The token-as-user pattern: `http://TOKEN@proxy`. The token goes out in `Proxy-Authorization`.
    for text in [
        "http://tok-canary-7@proxy.acme.test:3128",
        "http://tok-canary-7:@proxy.acme.test:3128",
    ] {
        let hub = hub_over(Replay::new());
        let probe = hub.run_probe();
        let show = |text: &str| {
            probe
                .file_text(&FileBytes::new(text.as_bytes().to_vec()))
                .expect("text")
                .to_string()
        };
        hub.set_proxy_text(text).expect("proxy");
        let user = show("the token is tok-canary-7 here");
        assert!(!user.contains("canary"), "{text}: {user}");
        // base64 of `tok-canary-7:`.
        let pair = show("Proxy-Authorization: Basic dG9rLWNhbmFyeS03Og==");
        assert!(!pair.contains("dG9rLWNhbmFyeS03Og"), "{text}: {pair}");
    }
    // A user name under 6 bytes is not a token: the proxy is set, nothing is registered and nothing is
    // refused. A short password is still a refusal (see the test above).
    for text in [
        "http://tok@proxy.acme.test:3128",
        "http://admin@proxy.acme.test:3128",
        "http://admin:@proxy.acme.test:3128",
    ] {
        let hub = hub_over(Replay::new());
        hub.set_proxy_text(text).expect("proxy");
        assert_eq!(hub.action_log().redaction.get("known_secret_refused"), 0);
        assert_eq!(
            hub.set_proxy_text("http://other.acme.test:3128"),
            Err(ProxyError::AlreadySet),
            "{text}"
        );
    }
}

#[tokio::test]
async fn the_proxy_cannot_be_set_once_the_run_has_started() {
    // A check's probe was opened, with no call made.
    let hub = hub_over(Replay::new());
    let _probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    assert_eq!(
        hub.set_proxy_text(&proxy_url(true)),
        Err(ProxyError::TooLate)
    );
    assert!(entries(&hub).is_empty());

    // The action log has an entry from run-level work, and no check probe was opened.
    let hub = hub_over(Replay::new());
    let run = hub.run_probe();
    run.begin(ActionKind::Read, serde_json::Map::new(), "/proc/cpuinfo")
        .expect("run probe")
        .1
        .finish(ActionOutcome::Ok);
    let error = hub.set_proxy_text(&proxy_url(true)).expect_err("too late");
    assert_eq!(error, ProxyError::TooLate);
    assert!(error.to_string().contains("Fix:"));
    // Nothing was registered and no proxy is set: the password is not hidden, and no call may use it.
    let probe = hub.run_probe();
    let shown = probe
        .file_text(&FileBytes::new(PASSWORD.as_bytes().to_vec()))
        .expect("text")
        .to_string();
    assert_eq!(shown, PASSWORD);

    // Before either, it works, and the order is the same for a clone of the hub.
    let hub = hub_over(Replay::new());
    let clone = hub.clone();
    clone.set_proxy_text(&proxy_url(true)).expect("proxy");
    let _probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
}

// ---- real sockets, through the live backend ----------------------------------------------------

/// A hub over the live backend. The TLS tests use it too, so only this file builds the live backend.
pub(super) fn live_hub() -> ProbeHub {
    // The engine's own tests build the live backend; check crates may not.
    #[expect(
        clippy::disallowed_methods,
        reason = "the engine's own tests build the live backend; check crates may not"
    )]
    let live = crate::probe::live_backend();
    hub_over_arc(live)
}

fn hub_over_arc(backend: Arc<dyn Backend>) -> ProbeHub {
    ProbeHub::new(backend, Redactor::new(TagKey::fixed([5; 32])))
}

#[tokio::test]
async fn the_live_backend_connects_refuses_and_tunnels_on_loopback() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let hub = live_hub();
    let listen = server.addr();
    let closed = closed_port().await.expect("a closed port");
    // A real proxy that routes the name to the server. The proxy is set before the first probe.
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[("web.acme.test:443", listen)])
        .await
        .expect("proxy");
    hub.set_proxy_text(&format!("svc:{PASSWORD_RAW}@{}", proxy.addr()))
        .expect("proxy");
    let probe = probe(
        &hub,
        &[
            &listen.to_string(),
            &closed.to_string(),
            "web.acme.test:443",
        ],
    );
    // A refused connect to a closed loopback port is instant on Linux and macOS, but Windows retries
    // the SYN for about 2 s before it reports the refusal. A wait of 10 s keeps that from being read
    // as a silent host (a timeout), which would hide the `Refused` this test asserts.
    probe
        .scope
        .peers
        .timeout
        .set(Duration::from_secs(10))
        .expect("set once");

    let up = probe
        .tcp(&target(&listen.to_string()), Route::Direct)
        .await
        .expect("connects");
    assert!(up.connected);
    assert_eq!(up.addr, Some(listen));
    assert_eq!(up.attempts[0].outcome, AttemptOutcome::Connected);

    let down = probe
        .tcp(&target(&closed.to_string()), Route::Direct)
        .await
        .expect("a report");
    assert!(!down.connected);
    assert_eq!(down.attempts[0].outcome, AttemptOutcome::Refused);

    // Through the real proxy.
    let tunnel = probe
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect("a tunnel");
    assert!(tunnel.connected);
    assert_eq!(tunnel.proxy_status, Some(200));
    assert_eq!(
        proxy.requests()[0].proxy_authorization.as_deref(),
        Some(AUTH)
    );

    let log = entries(&hub);
    assert_eq!(log.len(), 3, "{log:?}");
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
    assert_eq!(field(&log[0], "addr"), Some(&Value::from("127.0.0.1")));
    assert_eq!(log[1].outcome, ActionOutcome::Failed);
    assert_eq!(log[2].outcome, ActionOutcome::Ok);
    assert_no_credentials(&log_text(&hub));
}

#[tokio::test]
async fn a_proxy_that_never_answers_ends_at_the_connect_timeout() {
    let silent = NeverAccepts::start().await.expect("listener");
    let hub = live_hub();
    hub.set_proxy_text(&format!("http://{}", silent.addr()))
        .expect("proxy");
    let probe = probe(&hub, &["web.acme.test:443"]);
    probe
        .scope
        .peers
        .timeout
        .set(Duration::from_millis(150))
        .expect("set once");
    let error = probe
        .tcp(&target("web.acme.test:443"), Route::ViaProxy)
        .await
        .expect_err("no reply");
    assert_eq!(error, ProbeError::Timeout);
    let log = entries(&hub);
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, ActionOutcome::Timeout);
}

// ---- the scheduler gives each check its own hosts -----------------------------------------------------

mod scheduler {
    use super::*;
    use crate::check::{BoxFuture, Check, CheckContext, CheckOutcome, Finding};
    use crate::sched::{End, Planned, Scheduler};

    /// Asks for one host and says what happened in its message.
    struct Dialer(&'static CheckInfo, &'static str);

    impl Check for Dialer {
        fn info(&self) -> &'static CheckInfo {
            self.0
        }

        fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
            Box::pin(async move {
                let answer = ctx.probe().tcp(&target(self.1), Route::Direct).await;
                Ok(Finding::pass(match answer {
                    Ok(report) if report.connected => "connected".to_owned(),
                    Ok(_) => "no connection".to_owned(),
                    Err(ProbeError::Denied { rule, .. }) => format!("denied: {rule}"),
                    Err(other) => format!("error: {other}"),
                }))
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn planned_hosts_reach_the_probe_of_that_check_only() {
        let replay = Replay::new()
            .host("a.acme.test", [ip("192.0.2.1")])
            .host("b.acme.test", [ip("192.0.2.2")])
            .tcp(addr("192.0.2.1:443"), TcpScript::Refused)
            .tcp(addr("192.0.2.2:443"), TcpScript::Refused);
        let hub = hub_over(replay);
        let scheduler = Scheduler::new(2, Os::Linux, []).with_probes(hub.clone());
        let hosts = |text: &str| HostSet::new([target(text)]);
        let ran = scheduler
            .run(vec![
                // Lists its own host and asks for the other check's.
                Planned::new(
                    Arc::new(Dialer(egress(), "b.acme.test:443")),
                    "net.egress/a",
                )
                .with_hosts(hosts("a.acme.test:443")),
                // Lists the host it asks for.
                Planned::new(
                    Arc::new(Dialer(egress(), "b.acme.test:443")),
                    "net.egress/b",
                )
                .with_hosts(hosts("b.acme.test:443")),
                // Planned with no hosts.
                Planned::new(
                    Arc::new(Dialer(egress(), "a.acme.test:443")),
                    "net.egress/c",
                ),
            ])
            .await;
        let messages: Vec<String> = ran
            .iter()
            .map(|r| match &r.end {
                End::Done(outcome) => outcome
                    .as_ref()
                    .as_ref()
                    .map(|f| f.message.clone())
                    .expect("a finding"),
                other => panic!("unexpected end: {other:?}"),
            })
            .collect();
        assert_eq!(
            messages,
            [
                format!("denied: {RULE_TCP_HOST}"),
                "no connection".to_owned(),
                format!("denied: {RULE_TCP_HOST}"),
            ]
        );
        let rules: Vec<(Option<String>, ActionOutcome)> = entries(&hub)
            .into_iter()
            .map(|e| (e.check, e.outcome))
            .collect();
        assert_eq!(rules.len(), 3);
        assert!(rules.contains(&(Some("net.egress/b".to_owned()), ActionOutcome::Failed)));
        assert_eq!(
            rules
                .iter()
                .filter(|(_, o)| *o == ActionOutcome::Denied)
                .count(),
            2
        );
    }
}
