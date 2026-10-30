//! Tests for the datagram and unix socket calls (M1-144).
//!
//! The exit test: an SNTP query to a server that is not in the spec's `ntp_servers`, and a POST on the
//! Docker socket, are refused and logged, and the backend never sees either. The replay tests prove the
//! policy. The loopback tests (a UDP server on 127.0.0.1, a unix socket in a temp directory) prove the
//! live I/O, the caps and the timeouts. Nothing here leaves the machine.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rdy_spec::Target;
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::Value;

use super::*;
use crate::check::{CheckInfo, CheckMeta, OsSupport, Support};
use crate::probe::replay::Replay;
use crate::probe::{ProbeHub, RULE_CHECK_FINISHED};
use crate::redact::{Redactor, TagKey};

const META: CheckMeta = CheckMeta {
    title: "Fixture check",
    remediation: "Nothing to fix. This check is a test double.",
};

const ALL_OS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

/// A check info with these peers and nothing else.
macro_rules! info {
    ($id:literal, $peers:expr) => {{
        static INFO: CheckInfo = CheckInfo {
            id: $id,
            family: "host",
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

fn time_sync() -> &'static CheckInfo {
    info!("host.time_sync", &[PeerClass::NtpServers])
}

fn runtime() -> &'static CheckInfo {
    info!(
        "host.container_runtime",
        &[
            PeerClass::UnixSocket("/var/run/docker.sock"),
            PeerClass::UnixSocket("/run/user/{uid}/docker.sock"),
        ]
    )
}

fn hub(backend: impl crate::probe::Backend) -> ProbeHub {
    ProbeHub::new(Arc::new(backend), Redactor::new(TagKey::fixed([3; 32])))
}

fn target(text: &str) -> Target {
    Target::parse(text).expect("a valid target")
}

fn hosts(list: &[&str]) -> HostSet {
    HostSet::new(list.iter().map(|t| target(t)))
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn probe(hub: &ProbeHub, info: &'static CheckInfo, os: Os, spec_hosts: &[&str]) -> Probe {
    let probe = hub.check_probe(info.id, os, Some(info));
    probe.permit_hosts(hosts(spec_hosts));
    probe
}

fn only(hub: &ProbeHub) -> Action {
    let mut actions = hub.action_log().actions;
    assert_eq!(actions.len(), 1, "one entry per call: {actions:?}");
    actions.remove(0)
}

/// The one request entry of a unix socket call, set apart from the `process_ids` entry that a
/// declared `{uid}` socket makes the probe log first.
fn request_entry(hub: &ProbeHub) -> Action {
    let mut actions = hub.action_log().actions;
    actions.retain(|a| a.kind != ActionKind::Native);
    assert_eq!(actions.len(), 1, "one request entry: {actions:?}");
    actions.remove(0)
}

fn field<'a>(action: &'a Action, name: &str) -> Option<&'a Value> {
    action.fields.get(name)
}

fn rule(action: &Action) -> &str {
    field(action, "rule")
        .and_then(Value::as_str)
        .expect("a rule")
}

fn denied_rule(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A 48 byte SNTP-like request and a reply that echoes its bytes 24 to 32.
fn echo(sent: &[u8]) -> Vec<u8> {
    let mut reply = vec![0x24; 48];
    reply[24..32].copy_from_slice(&sent[24..32]);
    reply
}

fn request() -> Vec<u8> {
    let mut sent = vec![0x1b; 48];
    sent[24..32].copy_from_slice(b"RANDOM!!");
    sent
}

// --- exit test, clause 1: an SNTP query to a server that is not in ntp_servers ---

#[tokio::test]
async fn sntp_to_a_server_not_in_the_spec_is_refused_and_logged() {
    let asked = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&asked);
    let hub = hub(Replay::new()
        .host("pool.example", [ip("192.0.2.10")])
        .host("rogue.example", [ip("192.0.2.66")])
        .udp_server(addr("192.0.2.66:123"), move |sent| {
            seen.fetch_add(1, Ordering::SeqCst);
            echo(sent)
        }));
    let probe = probe(&hub, time_sync(), Os::Linux, &["pool.example:123"]);

    let error = probe
        .udp_exchange(&target("rogue.example:123"), &request(), 48)
        .await
        .expect_err("not a spec host");
    assert_eq!(denied_rule(&error), RULE_UDP_HOST);
    assert_eq!(
        asked.load(Ordering::SeqCst),
        0,
        "the server was never asked"
    );

    let entry = only(&hub);
    assert_eq!(entry.kind, ActionKind::Connect);
    assert_eq!(entry.outcome, ActionOutcome::Denied);
    assert_eq!(entry.check.as_deref(), Some("host.time_sync"));
    assert_eq!(rule(&entry), RULE_UDP_HOST);
    assert_eq!(field(&entry, "host"), Some(&Value::from("rogue.example")));
    assert_eq!(field(&entry, "port"), Some(&Value::from(123)));
    assert_eq!(field(&entry, "proto"), Some(&Value::from("udp")));
}

/// An IPv6 literal is shown in brackets, so the port is not mistaken for part of the address.
#[tokio::test]
async fn an_ipv6_literal_is_shown_in_brackets() {
    let hub = hub(Replay::new());
    let probe = probe(&hub, time_sync(), Os::Linux, &["pool.example:123"]);
    let error = probe
        .udp_exchange(&target("[2001:db8::1]:123"), &request(), 48)
        .await
        .expect_err("not a spec host");
    let text = error.to_string();
    assert!(text.contains("[2001:db8::1]:123"), "{text}");
}

#[tokio::test]
async fn the_same_host_on_another_port_is_not_a_spec_host() {
    let hub = hub(Replay::new().host("pool.example", [ip("192.0.2.10")]));
    let probe = probe(&hub, time_sync(), Os::Linux, &["pool.example:123"]);
    let error = probe
        .udp_exchange(&target("pool.example:53"), &request(), 48)
        .await
        .expect_err("another port");
    assert_eq!(denied_rule(&error), RULE_UDP_HOST);
}

#[tokio::test]
async fn a_listed_server_answers_and_the_entry_holds_no_payload() {
    let hub = hub(Replay::new()
        .host("pool.example", [ip("192.0.2.10")])
        .udp_server(addr("192.0.2.10:123"), echo));
    let probe = probe(&hub, time_sync(), Os::Linux, &["pool.example:123"]);
    let reply = probe
        .udp_exchange(&target("pool.example:123"), &request(), 48)
        .await
        .expect("a reply");
    assert_eq!(reply.bytes.len(), 48);
    assert_eq!(
        &reply.bytes[24..32],
        b"RANDOM!!",
        "the echo is the check's to verify"
    );
    assert_eq!(reply.addr, ip("192.0.2.10"));
    assert!(!reply.truncated);

    let entry = only(&hub);
    assert_eq!(entry.outcome, ActionOutcome::Ok);
    assert_eq!(field(&entry, "addr"), Some(&Value::from("192.0.2.10")));
    assert_eq!(field(&entry, "bytes"), Some(&Value::from(48)));
    let text = serde_json::to_string(&entry).expect("json");
    assert!(!text.contains("RANDOM"), "the payload is never logged");
}

#[tokio::test]
async fn the_check_must_declare_the_peer_class() {
    let hub = hub(Replay::new().udp_server(addr("192.0.2.10:123"), echo));
    let nothing: &'static CheckInfo = info!("host.memory", &[]);
    let probe = probe(&hub, nothing, Os::Linux, &["192.0.2.10:123"]);
    let error = probe
        .udp_exchange(&target("192.0.2.10:123"), &request(), 48)
        .await
        .expect_err("undeclared");
    assert_eq!(denied_rule(&error), RULE_UDP_UNDECLARED);
    assert_eq!(only(&hub).outcome, ActionOutcome::Denied);
}

#[tokio::test]
async fn a_probe_with_no_spec_hosts_sends_nothing() {
    let hub = hub(Replay::new().udp_server(addr("192.0.2.10:123"), echo));
    let probe = hub.check_probe("host.time_sync", Os::Linux, Some(time_sync()));
    let error = probe
        .udp_exchange(&target("192.0.2.10:123"), &request(), 48)
        .await
        .expect_err("no hosts");
    assert_eq!(denied_rule(&error), RULE_UDP_HOST);
    // The run-level probe has no manifest and no hosts either.
    let error = hub
        .run_probe_for(Os::Linux)
        .udp_exchange(&target("192.0.2.10:123"), &request(), 48)
        .await
        .expect_err("run level");
    assert_eq!(denied_rule(&error), RULE_UDP_UNDECLARED);
}

#[tokio::test]
async fn forbidden_literals_and_answers_are_refused_before_any_send() {
    let asked = Arc::new(AtomicUsize::new(0));
    let (a, b, c) = (Arc::clone(&asked), Arc::clone(&asked), Arc::clone(&asked));
    let hub = hub(Replay::new()
        .host("meta.example", [ip("169.254.169.254")])
        .host("mixed.example", [ip("192.0.2.10"), ip("fe80::1")])
        .host("mapped.example", [ip("::ffff:169.254.169.254")])
        .udp_server(addr("169.254.169.254:123"), move |s| {
            a.fetch_add(1, Ordering::SeqCst);
            echo(s)
        })
        .udp_server(addr("192.0.2.10:123"), move |s| {
            b.fetch_add(1, Ordering::SeqCst);
            echo(s)
        })
        .udp_server(addr("224.0.0.1:123"), move |s| {
            c.fetch_add(1, Ordering::SeqCst);
            echo(s)
        }));
    let probe = probe(
        &hub,
        time_sync(),
        Os::Linux,
        &[
            "169.254.169.254:123",
            "meta.example:123",
            "mixed.example:123",
            "mapped.example:123",
            "224.0.0.1:123",
            "[64:ff9b::a9fe:a9fe]:123",
            "100.100.100.200:123",
        ],
    );
    for server in [
        "169.254.169.254:123",
        "meta.example:123",
        "mixed.example:123",
        "mapped.example:123",
        "224.0.0.1:123",
        "[64:ff9b::a9fe:a9fe]:123",
        "100.100.100.200:123",
    ] {
        let error = probe
            .udp_exchange(&target(server), &request(), 48)
            .await
            .expect_err(server);
        assert_eq!(denied_rule(&error), RULE_UDP_ADDRESS, "{server}");
    }
    assert_eq!(asked.load(Ordering::SeqCst), 0, "nothing was sent");
    assert!(
        hub.action_log()
            .actions
            .iter()
            .all(|a| a.outcome == ActionOutcome::Denied)
    );
}

#[tokio::test]
async fn size_limits_are_enforced() {
    let hub = hub(Replay::new().udp_server(addr("192.0.2.10:123"), echo));
    let probe = probe(&hub, time_sync(), Os::Linux, &["192.0.2.10:123"]);
    let server = target("192.0.2.10:123");
    for (payload, reply) in [
        (Vec::new(), 48),
        (vec![0; MAX_UDP_PAYLOAD + 1], 48),
        (request(), 0),
    ] {
        let error = probe
            .udp_exchange(&server, &payload, reply)
            .await
            .expect_err("bad size");
        assert_eq!(denied_rule(&error), RULE_UDP_SIZE);
    }
    // A reply is cut at the caller's limit and flagged.
    let reply = probe
        .udp_exchange(&server, &request(), 16)
        .await
        .expect("cut reply");
    assert_eq!(reply.bytes.len(), 16);
    assert!(reply.truncated);
}

#[tokio::test]
async fn a_silent_server_times_out_and_is_logged_as_a_timeout() {
    let hub = hub(Replay::new().udp_silent(addr("192.0.2.10:123")));
    let probe = probe(&hub, time_sync(), Os::Linux, &["192.0.2.10:123"]);
    let error = probe
        .udp_exchange(&target("192.0.2.10:123"), &request(), 48)
        .await
        .expect_err("silent");
    assert_eq!(error, ProbeError::Timeout);
    assert_eq!(only(&hub).outcome, ActionOutcome::Timeout);
}

#[tokio::test]
async fn a_call_after_the_check_ended_is_refused_and_logged() {
    let hub = hub(Replay::new()
        .udp_server(addr("192.0.2.10:123"), echo)
        .unix_get("/var/run/docker.sock", "/info", 200, "{}"));
    let probe = probe(&hub, time_sync(), Os::Linux, &["192.0.2.10:123"]);
    probe.end();
    let error = probe
        .udp_exchange(&target("192.0.2.10:123"), &request(), 48)
        .await
        .expect_err("ended");
    assert_eq!(denied_rule(&error), RULE_CHECK_FINISHED);

    let docker = self::probe(&hub, runtime(), Os::Linux, &[]);
    docker.end();
    let error = docker
        .unix_get(Path::new("/var/run/docker.sock"), "/info")
        .await
        .expect_err("ended");
    assert_eq!(denied_rule(&error), RULE_CHECK_FINISHED);
    let actions = hub.action_log().actions;
    assert_eq!(actions.len(), 2);
    assert!(actions.iter().all(|a| rule(a) == RULE_CHECK_FINISHED));
}

/// The harness door a check's own test uses: hosts come in with the context, as `Built::hosts` does.
#[cfg(feature = "testing")]
#[tokio::test]
async fn a_check_test_context_carries_its_spec_hosts() {
    use crate::check::Need;
    use crate::testing::TestRun;

    let run = TestRun::new(
        Replay::new()
            .host("pool.example", [ip("192.0.2.10")])
            .udp_server(addr("192.0.2.10:123"), echo),
    );
    let ctx = run.context_for_hosts(
        time_sync(),
        "host.time_sync",
        Os::Linux,
        [Need::Root],
        hosts(&["pool.example:123"]),
    );
    let reply = ctx
        .probe()
        .udp_exchange(&target("pool.example:123"), &request(), 48)
        .await
        .expect("a reply");
    assert_eq!(reply.bytes.len(), 48);
    let error = ctx
        .probe()
        .udp_exchange(&target("other.example:123"), &request(), 48)
        .await
        .expect_err("not listed");
    assert_eq!(denied_rule(&error), RULE_UDP_HOST);
    assert_eq!(run.action_log().actions.len(), 2);
}

// --- exit test, clause 2: a POST on the Docker socket ---

const DOCKER: &str = "/var/run/docker.sock";

fn docker_fixture() -> Replay {
    Replay::new()
        .unix_get(DOCKER, "/info", 200, r#"{"Driver":"overlay2"}"#)
        .unix_get(DOCKER, "/version", 200, r#"{"Version":"27.0.1"}"#)
        .unix_get(DOCKER, "/containers/json", 200, "[]")
        .unix_get(DOCKER, "/containers/create", 200, "created")
}

#[tokio::test]
async fn an_unreadable_socket_gives_permission_denied_and_a_failed_entry() {
    // A socket the fixture marks unreadable stands for one the user may not open (M1-150).
    let hub = hub(docker_fixture().unreadable(DOCKER));
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    let error = probe
        .unix_get(Path::new(DOCKER), "/version")
        .await
        .expect_err("not in the group");
    assert_eq!(error, ProbeError::PermissionDenied);
    assert_eq!(request_entry(&hub).outcome, ActionOutcome::Failed);

    // A directory above it does the same.
    let hub = self::hub(docker_fixture().unreadable("/var/run"));
    let probe = self::probe(&hub, runtime(), Os::Linux, &[]);
    let error = probe
        .unix_get(Path::new(DOCKER), "/version")
        .await
        .expect_err("hidden");
    assert_eq!(error, ProbeError::PermissionDenied);
}

#[tokio::test(start_paused = true)]
async fn a_delayed_unix_reply_arrives_after_its_delay_and_a_huge_one_is_a_hang() {
    use std::time::Duration;

    // M1-150: a fixture `delay_ms` on a Docker reply. Under a paused clock it costs no real time.
    let hub = hub(Replay::new().unix_get_after(
        DOCKER,
        "/version",
        200,
        r#"{"Version":"27.0.1"}"#,
        Duration::from_secs(2),
    ));
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    let started = tokio::time::Instant::now();
    let reply = probe
        .unix_get(Path::new(DOCKER), "/version")
        .await
        .expect("answered");
    assert_eq!(reply.status, 200);
    assert_eq!(started.elapsed(), Duration::from_secs(2));

    let hub = self::hub(Replay::new().unix_get_after(
        DOCKER,
        "/version",
        200,
        "{}",
        Duration::from_secs(3600),
    ));
    let probe = self::probe(&hub, runtime(), Os::Linux, &[]);
    let hung = tokio::time::timeout(
        Duration::from_secs(5),
        probe.unix_get(Path::new(DOCKER), "/version"),
    )
    .await;
    assert!(hung.is_err(), "the daemon never answered");
}

#[tokio::test]
async fn a_post_on_the_docker_socket_is_refused_and_logged() {
    let hub = hub(docker_fixture());
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    let error = probe
        .unix_request("POST", Path::new(DOCKER), "/containers/create")
        .await
        .expect_err("a POST");
    assert_eq!(denied_rule(&error), RULE_UNIX_METHOD);

    let entry = only(&hub);
    assert_eq!(entry.kind, ActionKind::Http);
    assert_eq!(entry.outcome, ActionOutcome::Denied);
    assert_eq!(rule(&entry), RULE_UNIX_METHOD);
    assert_eq!(field(&entry, "method"), Some(&Value::from("POST")));
    assert_eq!(field(&entry, "path"), Some(&Value::from(DOCKER)));
    assert_eq!(
        field(&entry, "url"),
        Some(&Value::from("/containers/create"))
    );
}

#[tokio::test]
async fn no_other_method_gets_through_even_on_an_allowed_path() {
    let hub = hub(docker_fixture());
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    for method in [
        "POST", "PUT", "DELETE", "PATCH", "HEAD", "get", "GET ", "CONNECT", "",
    ] {
        let error = probe
            .unix_request(method, Path::new(DOCKER), "/info")
            .await
            .expect_err(method);
        assert_eq!(denied_rule(&error), RULE_UNIX_METHOD, "{method:?}");
    }
}

#[tokio::test]
async fn get_reads_the_two_api_calls_the_catalog_needs() {
    let hub = hub(docker_fixture());
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    let info = probe
        .unix_get(Path::new(DOCKER), "/info")
        .await
        .expect("a reply");
    assert_eq!(info.status, 200);
    assert_eq!(info.body, br#"{"Driver":"overlay2"}"#);

    let entry = &hub.action_log().actions[0];
    assert_eq!(entry.outcome, ActionOutcome::Ok);
    assert_eq!(field(entry, "method"), Some(&Value::from("GET")));
    assert_eq!(field(entry, "status"), Some(&Value::from(200)));
    assert_eq!(field(entry, "bytes"), Some(&Value::from(21)));
    let text = serde_json::to_string(entry).expect("json");
    assert!(!text.contains("overlay2"), "the body is never logged");
}

#[tokio::test]
async fn only_the_allowlisted_api_paths_are_asked() {
    let hub = hub(docker_fixture());
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    for path in [
        "/containers/json",
        "/containers/create",
        "/info?verbose=1",
        "/info#x",
        "/info/",
        "//info",
        "/./info",
        "/v1.43/../info",
        "/v1.43//info",
        "/v1/info",
        "/v1.43",
        "/v1.4x/info",
        "/v1.2.3/info",
        "/v1234.43/info",
        "/vinfo",
        "info",
        "",
        "/info HTTP/1.1\r\nX: y",
        "/INFO",
    ] {
        let error = probe
            .unix_get(Path::new(DOCKER), path)
            .await
            .expect_err(path);
        assert_eq!(denied_rule(&error), RULE_UNIX_API_PATH, "{path:?}");
    }
    for path in [
        "/info",
        "/version",
        "/_ping",
        "/v1.43/info",
        "/v1.0/version",
        "/v1.43/_ping",
    ] {
        assert!(api_path_allowed(path), "{path}");
    }
}

#[tokio::test]
async fn only_declared_sockets_are_opened() {
    let hub = hub(docker_fixture()
        .unix_get("/run/containerd/containerd.sock", "/info", 200, "{}")
        .unix_get("/run/user/1000/docker.sock", "/info", 200, "{}")
        .unix_get("/run/user/1001/docker.sock", "/info", 200, "{}")
        .ids([1000; 4], [1000; 4]));
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    for socket in [
        "/run/containerd/containerd.sock",
        "/var/run/docker.sock/",
        "/var/run//docker.sock",
        "/var/run/./docker.sock",
        "/var/run/docker.sock.bak",
        "/run/user/x/docker.sock",
        "/run/user/1001/docker.sock",
        "/run/user/0/docker.sock",
        "/run/user//docker.sock",
        "/run/user/1000/other.sock",
        "/run/user/1000/sub/docker.sock",
    ] {
        let error = probe
            .unix_get(Path::new(socket), "/info")
            .await
            .expect_err(socket);
        assert_eq!(denied_rule(&error), RULE_UNIX_UNDECLARED, "{socket}");
    }
    for socket in ["relative/docker.sock", "/var/run/../run/docker.sock", ""] {
        let error = probe
            .unix_get(Path::new(socket), "/info")
            .await
            .expect_err(socket);
        assert_eq!(denied_rule(&error), RULE_UNIX_PATH_SHAPE, "{socket:?}");
    }
    // The declared socket, and the rootless pattern with a user id.
    for socket in [DOCKER, "/run/user/1000/docker.sock"] {
        let reply = probe
            .unix_get(Path::new(socket), "/info")
            .await
            .expect(socket);
        assert_eq!(reply.status, 200);
    }
    // A check that declared nothing opens nothing.
    let nothing: &'static CheckInfo = info!("host.memory", &[]);
    let bare = self::probe(&hub, nothing, Os::Linux, &[]);
    let error = bare
        .unix_get(Path::new(DOCKER), "/info")
        .await
        .expect_err("undeclared");
    assert_eq!(denied_rule(&error), RULE_UNIX_UNDECLARED);
}

#[tokio::test]
async fn a_missing_socket_is_not_found_not_a_denial() {
    let hub = hub(Replay::new());
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    let error = probe
        .unix_get(Path::new(DOCKER), "/info")
        .await
        .expect_err("no such socket");
    assert_eq!(error, ProbeError::NotFound);
    assert_eq!(request_entry(&hub).outcome, ActionOutcome::Failed);
}

/// The user id lookup goes through the probe, so it is logged as a `native` call.
#[tokio::test]
async fn the_user_id_lookup_for_a_uid_socket_is_logged() {
    let hub = hub(Replay::new().ids([1000; 4], [1000; 4]).unix_get(
        "/run/user/1000/docker.sock",
        "/info",
        200,
        "{}",
    ));
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    let reply = probe
        .unix_get(Path::new("/run/user/1000/docker.sock"), "/info")
        .await
        .expect("the declared uid socket");
    assert_eq!(reply.status, 200);
    let actions = hub.action_log().actions;
    let native = actions
        .iter()
        .find(|a| a.kind == ActionKind::Native)
        .expect("a native entry");
    assert_eq!(
        field(native, "api").and_then(Value::as_str),
        Some("process_ids")
    );
}

/// Windows has no unix sockets. The call is refused with a fixed rule and logged, whatever the host
/// running the test is, so a check can map it to Skipped with a reason.
#[tokio::test]
async fn windows_refuses_unix_sockets_with_a_logged_rule() {
    let hub = hub(docker_fixture());
    let probe = probe(&hub, runtime(), Os::Windows, &[]);
    let error = probe
        .unix_get(Path::new(DOCKER), "/info")
        .await
        .expect_err("windows");
    assert_eq!(denied_rule(&error), RULE_UNIX_OS);
    let entry = only(&hub);
    assert_eq!(entry.outcome, ActionOutcome::Denied);
    assert_eq!(rule(&entry), RULE_UNIX_OS);
}

/// With no readable user id the rootless pattern matches nothing, so the call fails closed.
#[tokio::test]
async fn a_uid_socket_needs_a_known_user_id() {
    let hub = hub(Replay::new().unix_get("/run/user/1000/docker.sock", "/info", 200, "{}"));
    let probe = probe(&hub, runtime(), Os::Linux, &[]);
    let error = probe
        .unix_get(Path::new("/run/user/1000/docker.sock"), "/info")
        .await
        .expect_err("no ids");
    assert_eq!(denied_rule(&error), RULE_UNIX_UNDECLARED);
}

#[test]
fn socket_patterns_match_whole_segments() {
    let at = |pattern, socket, uid| socket_matches(pattern, Path::new(socket), uid);
    assert!(at("/var/run/docker.sock", "/var/run/docker.sock", None));
    assert!(at(
        "/run/user/{uid}/docker.sock",
        "/run/user/0/docker.sock",
        Some(0)
    ));
    assert!(at(
        "/run/user/{uid}/docker.sock",
        "/run/user/1000/docker.sock",
        Some(1000)
    ));
    for socket in [
        "/run/user/0a/docker.sock",
        "/run/user/+1000/docker.sock",
        "/run/user/01000/docker.sock",
        "/run/user/1001/docker.sock",
        "/run/user/0/docker.sock",
        "/run/user/docker.sock",
    ] {
        assert!(
            !at("/run/user/{uid}/docker.sock", socket, Some(1000)),
            "{socket}"
        );
    }
    // With no known id, `{uid}` matches nothing.
    assert!(!at(
        "/run/user/{uid}/docker.sock",
        "/run/user/1000/docker.sock",
        None
    ));
    assert!(!at("var/run/docker.sock", "/var/run/docker.sock", None));
}

#[test]
fn the_error_texts_tell_the_user_what_to_do() {
    for rule in [
        RULE_UDP_UNDECLARED,
        RULE_UDP_HOST,
        RULE_UDP_SIZE,
        RULE_UDP_ADDRESS,
        RULE_UNIX_OS,
        RULE_UNIX_PATH_SHAPE,
        RULE_UNIX_UNDECLARED,
        RULE_UNIX_METHOD,
        RULE_UNIX_API_PATH,
    ] {
        assert!(ProbeError::denied(rule, "x").to_string().contains("Fix:"));
    }
}

// --- live I/O on loopback and in a temp directory ---

#[cfg(feature = "runtime")]
mod live {
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::*;
    use crate::probe::Backend;
    use crate::probe::sealed::Sealed;

    /// A backend that does no file I/O and hands every socket call to the live backend, so these tests
    /// run the live socket bodies.
    struct Sockets(Arc<dyn Backend>);

    impl Sockets {
        fn new() -> Self {
            #[expect(
                clippy::disallowed_methods,
                reason = "the engine's own tests build the live backend; check crates may not"
            )]
            let live = crate::probe::live_backend();
            Self(live)
        }
    }

    impl Sealed for Sockets {}

    impl Backend for Sockets {
        fn open_read<'a>(
            &'a self,
            _: &'a Path,
            _: crate::probe::ReadRange,
            _: &'a crate::probe::ReadGuard,
        ) -> crate::check::BoxFuture<'a, std::io::Result<crate::probe::FileBytes>> {
            Box::pin(async { Err(std::io::ErrorKind::NotFound.into()) })
        }
        fn read_dir<'a>(
            &'a self,
            _: &'a Path,
            _: &'a crate::probe::ReadGuard,
        ) -> crate::check::BoxFuture<'a, std::io::Result<Vec<crate::probe::DirEntry>>> {
            Box::pin(async { Err(std::io::ErrorKind::NotFound.into()) })
        }
        fn stat<'a>(
            &'a self,
            _: &'a Path,
            _: &'a crate::probe::ReadGuard,
        ) -> crate::check::BoxFuture<'a, std::io::Result<Option<crate::probe::FileMeta>>> {
            Box::pin(async { Ok(None) })
        }
        fn env(&self, _: &str) -> Option<String> {
            None
        }
        fn native<'a>(
            &'a self,
            _: &'a crate::probe::NativeCall,
            _: &'a crate::probe::ReadGuard,
        ) -> crate::check::BoxFuture<'a, std::io::Result<crate::probe::NativeValue>> {
            Box::pin(async { Err(std::io::ErrorKind::NotFound.into()) })
        }
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            port: u16,
            timeout: Duration,
        ) -> crate::check::BoxFuture<'a, std::io::Result<Vec<IpAddr>>> {
            self.0.resolve(host, port, timeout)
        }
        fn udp_exchange<'a>(
            &'a self,
            to: SocketAddr,
            payload: &'a [u8],
            max_reply: usize,
            timeout: Duration,
        ) -> crate::check::BoxFuture<'a, Result<UdpReply, ProbeError>> {
            self.0.udp_exchange(to, payload, max_reply, timeout)
        }
        fn unix_get<'a>(
            &'a self,
            socket: &'a Path,
            path: &'a str,
            timeout: Duration,
        ) -> crate::check::BoxFuture<'a, Result<UnixResponse, ProbeError>> {
            self.0.unix_get(socket, path, timeout)
        }
    }

    fn short(probe: &Probe) {
        probe
            .scope
            .peers
            .timeout
            .set(Duration::from_millis(300))
            .expect("set once");
    }

    #[tokio::test]
    async fn udp_on_loopback_reads_only_the_servers_own_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let spoofer = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (n, client) = server.recv_from(&mut buf).await.expect("recv");
            // A datagram from another source arrives first. The connected socket drops it.
            spoofer.send_to(b"evil", client).await.expect("spoof");
            server
                .send_to(&echo(&buf[..n]), client)
                .await
                .expect("send");
        });

        let hub = hub(Sockets::new());
        let text = format!("127.0.0.1:{port}");
        let probe = probe(&hub, time_sync(), Os::Linux, &[&text]);
        let reply = probe
            .udp_exchange(&target(&text), &request(), 4096)
            .await
            .expect("a reply");
        assert_eq!(reply.bytes.len(), 48, "the spoofed datagram was not read");
        assert_eq!(&reply.bytes[24..32], b"RANDOM!!");
        assert_eq!(reply.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let entry = only(&hub);
        assert_eq!(entry.outcome, ActionOutcome::Ok);
        assert_eq!(field(&entry, "addr"), Some(&Value::from("127.0.0.1")));
    }

    #[tokio::test]
    async fn udp_reply_is_cut_at_the_limit() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (_, client) = server.recv_from(&mut buf).await.expect("recv");
            server.send_to(&[7; 100], client).await.expect("send");
        });
        let hub = hub(Sockets::new());
        let text = format!("127.0.0.1:{port}");
        let probe = probe(&hub, time_sync(), Os::Linux, &[&text]);
        let reply = probe
            .udp_exchange(&target(&text), &request(), 64)
            .await
            .expect("a reply");
        assert_eq!(reply.bytes.len(), 64);
        assert!(reply.truncated);
    }

    /// A datagram far past the cap is cut in user space and flagged. A reply of exactly the cap is
    /// whole. The buffer is the largest datagram on every OS, so Windows does not fail the receive.
    #[tokio::test]
    async fn udp_reply_far_past_the_cap_is_cut_and_one_of_exactly_the_cap_is_whole() {
        for (sent, truncated) in [(8000_usize, true), (64, false)] {
            let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let port = server.local_addr().expect("addr").port();
            tokio::spawn(async move {
                let mut buf = [0_u8; 512];
                let (_, client) = server.recv_from(&mut buf).await.expect("recv");
                server.send_to(&vec![7; sent], client).await.expect("send");
            });
            let hub = hub(Sockets::new());
            let text = format!("127.0.0.1:{port}");
            let probe = probe(&hub, time_sync(), Os::Linux, &[&text]);
            let reply = probe
                .udp_exchange(&target(&text), &request(), 64)
                .await
                .expect("a reply");
            assert_eq!(reply.bytes.len(), 64, "{sent}");
            assert_eq!(reply.truncated, truncated, "{sent}");
        }
    }

    #[tokio::test]
    async fn udp_to_a_silent_server_times_out() {
        // Bound and never read: nothing answers.
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = silent.local_addr().expect("addr").port();
        let hub = hub(Sockets::new());
        let text = format!("127.0.0.1:{port}");
        let probe = probe(&hub, time_sync(), Os::Linux, &[&text]);
        short(&probe);
        let started = std::time::Instant::now();
        let error = probe
            .udp_exchange(&target(&text), &request(), 48)
            .await
            .expect_err("silent");
        assert_eq!(error, ProbeError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(only(&hub).outcome, ActionOutcome::Timeout);
        drop(silent);
    }

    #[tokio::test]
    async fn a_name_is_resolved_for_the_spec_host_only() {
        // `localhost` resolves through the system resolver to loopback.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = server.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            if let Ok((n, client)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(&echo(&buf[..n]), client).await;
            }
        });
        let hub = hub(Sockets::new());
        let text = format!("localhost:{port}");
        let probe = probe(&hub, time_sync(), Os::Linux, &[&text]);
        short(&probe);
        // `localhost` may resolve to ::1 first on some machines, where nothing listens. Either way the
        // call ends in a reply or a timeout, never a hang, and never a denial.
        match probe.udp_exchange(&target(&text), &request(), 48).await {
            Ok(reply) => assert_eq!(reply.bytes.len(), 48),
            Err(error) => assert!(
                matches!(error, ProbeError::Timeout | ProbeError::Io(_)),
                "{error:?}"
            ),
        }
        let entry = only(&hub);
        assert_ne!(entry.outcome, ActionOutcome::Denied);
        assert_eq!(field(&entry, "host"), Some(&Value::from("localhost")));
    }

    #[cfg(unix)]
    mod unix {
        use std::sync::OnceLock;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        use super::*;

        static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
        static SOCKET: OnceLock<String> = OnceLock::new();
        static PEERS: OnceLock<[PeerClass; 1]> = OnceLock::new();
        static INFO: OnceLock<CheckInfo> = OnceLock::new();

        /// A check info that declares the one socket of this test, whose path is only known at run time.
        fn declared() -> &'static CheckInfo {
            let socket = SOCKET.get_or_init(|| {
                let dir = DIR.get_or_init(|| tempfile::tempdir().expect("a temp dir"));
                dir.path()
                    .join("docker.sock")
                    .to_string_lossy()
                    .into_owned()
            });
            let peers = PEERS.get_or_init(|| [PeerClass::UnixSocket(socket.as_str())]);
            INFO.get_or_init(|| CheckInfo {
                id: "host.container_runtime",
                family: "host",
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
                peers,
            })
        }

        /// What the server saw: the first line and whether the head had a body or credentials.
        #[derive(Default)]
        struct Seen {
            connections: AtomicUsize,
            requests: std::sync::Mutex<Vec<String>>,
        }

        async fn serve(listener: UnixListener, seen: Arc<Seen>) {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                seen.connections.fetch_add(1, Ordering::SeqCst);
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut buf = vec![0_u8; 4096];
                    let mut got = 0;
                    while !buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf[got..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got += n,
                        }
                    }
                    let head = String::from_utf8_lossy(&buf[..got]).into_owned();
                    let first = head.lines().next().unwrap_or_default().to_owned();
                    seen.requests.lock().expect("lock").push(head);
                    let reply: &[u8] = match first.as_str() {
                        "GET /info HTTP/1.1" => {
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{\"Driver\":\"overlay2\"}"
                        }
                        "GET /version HTTP/1.1" => {
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n{\"Vers\r\na\r\nion\":\"27\"}\r\n0\r\n\r\n"
                        }
                        "GET /v1.43/_ping HTTP/1.1" => {
                            // A whole chunked reply, then the connection stays open.
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n")
                                .await;
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            return;
                        }
                        "GET /v1.43/info HTTP/1.1" => b"SSH-2.0-OpenSSH_9.6\r\n\r\n",
                        "GET /_ping HTTP/1.1" => {
                            // Never answers.
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            return;
                        }
                        _ => b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
                    };
                    let _ = stream.write_all(reply).await;
                });
            }
        }

        #[tokio::test]
        async fn unix_socket_requests_end_to_end() {
            let socket = Path::new(
                declared()
                    .peers
                    .iter()
                    .find_map(|p| match p {
                        PeerClass::UnixSocket(path) => Some(*path),
                        _ => None,
                    })
                    .expect("declared"),
            );
            let listener = UnixListener::bind(socket).expect("bind in the temp dir");
            let seen = Arc::new(Seen::default());
            tokio::spawn(serve(listener, Arc::clone(&seen)));

            let hub = hub(Sockets::new());
            let probe = probe(&hub, declared(), Os::Linux, &[]);
            short(&probe);

            // A Content-Length body.
            let info = probe.unix_get(socket, "/info").await.expect("info");
            assert_eq!(info.status, 200);
            assert_eq!(info.body, br#"{"Driver":"overlay2"}"#);
            assert!(!info.truncated);

            // A chunked body.
            let version = probe.unix_get(socket, "/version").await.expect("version");
            assert_eq!(version.body, br#"{"Version":"27"}"#);

            // The request was a bare GET: no body, no credential, one connection each.
            {
                let requests = seen.requests.lock().expect("lock");
                assert_eq!(requests.len(), 2);
                assert!(requests[0].starts_with("GET /info HTTP/1.1\r\n"));
                assert!(requests[0].contains("Connection: close"));
                assert!(!requests[0].to_lowercase().contains("authorization"));
                assert!(!requests[0].to_lowercase().contains("content-length"));
            }

            // A POST never reaches the socket.
            let before = seen.connections.load(Ordering::SeqCst);
            let error = probe
                .unix_request("POST", socket, "/containers/create")
                .await
                .expect_err("a POST");
            assert_eq!(denied_rule(&error), RULE_UNIX_METHOD);
            let error = probe
                .unix_get(socket, "/containers/json")
                .await
                .expect_err("not on the list");
            assert_eq!(denied_rule(&error), RULE_UNIX_API_PATH);
            assert_eq!(seen.connections.load(Ordering::SeqCst), before);

            // Something that is not HTTP is a failure, not a panic or a hang.
            let error = probe
                .unix_get(socket, "/v1.43/info")
                .await
                .expect_err("not http");
            assert!(matches!(error, ProbeError::Io(_)), "{error:?}");

            // A 500 is a reply the check reads, not an error.
            let failed = probe
                .unix_get(socket, "/v1.43/version")
                .await
                .expect("a 500 is a reply");
            assert_eq!(failed.status, 500);
            assert!(failed.body.is_empty());

            // A whole chunked reply on a connection the server keeps open returns the body, not a
            // timeout.
            let ping = probe
                .unix_get(socket, "/v1.43/_ping")
                .await
                .expect("a complete chunked reply");
            assert_eq!(ping.body, b"OK");
            assert!(!ping.truncated);

            // A server that never answers hits the timeout.
            let error = probe.unix_get(socket, "/_ping").await.expect_err("silent");
            assert_eq!(error, ProbeError::Timeout);

            let outcomes: Vec<_> = hub
                .action_log()
                .actions
                .iter()
                .map(|a| a.outcome.clone())
                .collect();
            assert_eq!(
                outcomes,
                [
                    ActionOutcome::Ok,
                    ActionOutcome::Ok,
                    ActionOutcome::Denied,
                    ActionOutcome::Denied,
                    ActionOutcome::Failed,
                    ActionOutcome::Ok,
                    ActionOutcome::Ok,
                    ActionOutcome::Timeout,
                ]
            );
        }

        #[tokio::test]
        async fn a_socket_that_does_not_exist_is_not_found() {
            let missing = "/nonexistent-rdy-dir/docker.sock";
            static PEERS: [PeerClass; 1] =
                [PeerClass::UnixSocket("/nonexistent-rdy-dir/docker.sock")];
            static INFO: CheckInfo = CheckInfo {
                id: "host.container_runtime",
                family: "host",
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
                peers: &PEERS,
            };
            let hub = hub(Sockets::new());
            let probe = probe(&hub, &INFO, Os::Linux, &[]);
            let error = probe
                .unix_get(Path::new(missing), "/info")
                .await
                .expect_err("missing");
            assert_eq!(error, ProbeError::NotFound);
        }
    }
}
