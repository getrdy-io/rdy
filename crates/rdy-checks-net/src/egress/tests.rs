//! Tests of `net.egress` (M1-095).
//!
//! Scripted cases (the `net.json` fixtures under `tests/fixtures/checks/net.egress/`) run on a paused
//! clock with no socket: the dead IPv6 address, the silent IPv6 address, the blackhole, the closed port
//! and the missing name. They are the same on all five legs because no real network or IPv6 stack is
//! used. The TLS cases run against loopback servers (`rdy_engine::testing::loopback`) on the real
//! clock, with scripted addresses that point at the server, so a dead IPv6 address is still only a
//! script.
//!
//! Each case asserts the finding and the `CheckResult` that `map_outcome` makes from it, and that the
//! check stayed inside its manifest.

use std::net::SocketAddr;

use rdy_engine::check::{
    Check, CheckContext, CheckError, CheckOutcome, Finding, Level, Need, Os, PeerClass,
};
use rdy_engine::family::{Family, HostSet};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::{NativeCall, NativeValue};
use rdy_engine::testing::loopback::{
    HttpOptions, HttpServer, ResetAfterClientHello, TestCa, Validity,
};
use rdy_engine::testing::{
    Fixture, Replay, TcpScript, TestRun, assert_within_manifest, fixtures_dir,
};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{CheckResult, SkipKind, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;
use crate::NetFamily;

// ---- the harness --------------------------------------------------------------------------------

struct Ran {
    outcome: CheckOutcome,
    ctx: CheckContext,
    entry: CheckSpec,
    run: TestRun,
}

impl Ran {
    fn finding(&self) -> &Finding {
        self.outcome.as_ref().expect("a finding")
    }

    fn endpoint(&self, at: usize) -> &Value {
        &self.finding().observed["endpoints"][at]
    }

    fn result(&self) -> CheckResult {
        map_outcome(&INFO, &self.entry, &self.ctx, self.outcome.clone(), 0, 0)
    }

    fn everything_text(&self) -> String {
        let finding = self.finding();
        format!(
            "{} {} {:?} {:?} {:?}",
            finding.message,
            finding.observed,
            finding.fix,
            finding.notes,
            self.run.action_log()
        )
    }
}

fn entry(endpoints: &Value, extra: &Value) -> CheckSpec {
    let mut entry = json!({"id": "net.egress", "endpoints": endpoints});
    for (key, value) in extra.as_object().expect("an object") {
        entry[key] = value.clone();
    }
    serde_json::from_value(entry).expect("a check entry")
}

fn params(entry: &CheckSpec) -> NetEgress {
    match entry.decode_params() {
        CheckParams::NetEgress(params) => params,
        other => panic!("not net.egress: {other:?}"),
    }
}

async fn run_on(replay: Replay, endpoints: Value, extra: Value, needs: &[Need]) -> Ran {
    let entry = entry(&endpoints, &extra);
    let params = params(&entry);
    let hosts = HostSet::new(params.endpoints.iter().map(|e| e.target.clone()));
    let check = EgressCheck::new(params);
    let run = TestRun::new(replay);
    let ctx = run.context_for_hosts(&INFO, "net.egress", Os::Linux, needs.iter().cloned(), hosts);
    let outcome = check.run(&ctx).await;
    assert_within_manifest("net.egress", &INFO, &run.action_log());
    Ran {
        outcome,
        ctx,
        entry,
        run,
    }
}

/// The machine of a fixture case, with the `web` server that its `serve` entries name.
fn case(name: &str) -> Replay {
    Fixture::load(&fixtures_dir(), &format!("checks/net.egress/{name}"))
        .expect("the fixture loads")
        .into_replay()
        .serve_duplex("web", |_server| async {})
}

const NET: &[Need] = &[Need::Network];

// ---- scripted: the plain TCP stages -------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_reachable_endpoint_passes_with_a_timing_for_each_stage() {
    let ran = run_on(
        case("pass-plain"),
        json!(["web.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.message, "1 of 1 endpoints reachable");
    let e = ran.endpoint(0);
    assert_eq!(e["endpoint"], "web.acme.test:8080");
    assert_eq!(e["result"], "reached");
    assert_eq!(e["lookup"]["ipv4"], 1);
    assert_eq!(e["lookup"]["ipv6"], 0);
    assert!(e["lookup"]["ms"].is_u64(), "the lookup stage has a time");
    assert!(e["connect_ms"].is_u64(), "the connect stage has a time");
    assert_eq!(e["attempts"][0]["outcome"], "connected");
    assert_eq!(e["tls"], false, "port 8080 is plain TCP");
    assert!(e.get("tls_stage").is_none());
    let result = ran.result();
    assert_eq!(result.status, Status::Pass);
    assert!(result.fix.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_dead_ipv6_address_falls_through_to_ipv4_and_is_named() {
    let ran = run_on(
        case("dual-dead-v6-refused"),
        json!(["dual.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("the ipv6 address failed (refused)"),
        "{}",
        finding.message
    );
    let e = ran.endpoint(0);
    assert_eq!(e["result"], "reached");
    assert_eq!(e["lookup"]["ipv6"], 1);
    assert_eq!(e["lookup"]["ipv4"], 1);
    assert_eq!(e["attempts"][0]["family"], "ipv6");
    assert_eq!(e["attempts"][0]["outcome"], "refused");
    assert_eq!(e["attempts"][1]["family"], "ipv4");
    assert_eq!(e["attempts"][1]["outcome"], "connected");
    // A refusal is an answer, so IPv4 starts at once and not after the stagger.
    assert_eq!(
        e["attempts"][1]["started_ms"],
        e["attempts"][0]["elapsed_ms"]
    );
    assert_eq!(ran.result().status, Status::Warn);
}

#[tokio::test(start_paused = true)]
async fn a_silent_ipv6_address_is_named_when_ipv4_carries_the_connection() {
    let ran = run_on(
        case("dual-silent-v6"),
        json!(["dual.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("the ipv6 address failed (no answer after 250 ms)"),
        "{}",
        finding.message
    );
    let e = ran.endpoint(0);
    // IPv6 first; IPv4 starts one stagger later and wins; the silent attempt was cut.
    assert_eq!(e["attempts"][0]["family"], "ipv6");
    assert_eq!(e["attempts"][0]["outcome"], "abandoned");
    assert_eq!(e["attempts"][1]["family"], "ipv4");
    assert_eq!(e["attempts"][1]["started_ms"], 250);
    assert_eq!(e["connect_ms"], 250);
}

#[tokio::test(start_paused = true)]
async fn a_scripted_blackhole_gives_the_blackhole_class_and_its_fix() {
    let ran = run_on(
        case("blackhole"),
        json!(["hole.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "1 of 1 endpoints unreachable: hole.acme.test:8080 (blackhole)"
    );
    let e = ran.endpoint(0);
    assert_eq!(e["class"], "blackhole");
    assert_eq!(e["attempts"][0]["outcome"], "timed_out");
    assert_eq!(
        e["attempts"][0]["elapsed_ms"], 3000,
        "the attempt waited its 3 s"
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.starts_with("No reply to SYN from 192.0.2.9:8080 in 3s"),
        "{fix}"
    );
    assert!(fix.contains("allow tcp/8080 to hole.acme.test"), "{fix}");
    let result = ran.result();
    assert_eq!(result.status, Status::Block);
    assert_eq!(result.fix.as_deref(), finding.fix.as_deref());
}

#[tokio::test(start_paused = true)]
async fn a_closed_port_is_refused_and_a_missing_name_is_dns() {
    let ran = run_on(
        case("refused"),
        json!(["closed.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "refused");
    assert!(
        ran.finding()
            .fix
            .as_deref()
            .expect("fix")
            .contains("refused the connection")
    );

    let ran = run_on(
        case("nxdomain"),
        json!(["gone.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "dns");
    assert!(
        ran.endpoint(0)
            .get("attempts")
            .is_some_and(|a| a == &json!([]))
    );
    assert!(
        ran.finding()
            .fix
            .as_deref()
            .expect("fix")
            .contains("/etc/hosts")
    );
    assert_eq!(ran.result().status, Status::Block);
}

#[tokio::test(start_paused = true)]
async fn an_optional_endpoint_warns_and_severity_warn_caps_a_failure() {
    let ran = run_on(
        case("blackhole"),
        json!([{"target": "hole.acme.test:8080", "optional": true}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        ran.finding()
            .message
            .contains("optional, unreachable: blackhole")
    );
    assert_eq!(ran.result().status, Status::Warn);

    let ran = run_on(
        case("blackhole"),
        json!(["hole.acme.test:8080"]),
        json!({"severity": "warn"}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(
        ran.result().status,
        Status::Warn,
        "the spec severity caps the failure"
    );
}

#[tokio::test(start_paused = true)]
async fn a_connect_slower_than_max_latency_warns() {
    // The server takes 2.5 s to answer: above the default 2 s, under the 3 s attempt limit.
    let replay = Replay::new()
        .host("slow.acme.test", ["192.0.2.5".parse().expect("ip")])
        .tcp(
            "192.0.2.5:8080".parse().expect("addr"),
            TcpScript::Serve("slow".to_owned()),
        )
        .serve("slow", || async {
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
            let (client, _server) = tokio::io::duplex(1024);
            Ok(Box::new(client) as rdy_engine::probe::net::BoxedStream)
        });
    let ran = run_on(
        replay.clone(),
        json!(["slow.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        ran.finding()
            .message
            .contains("took 2500 ms to connect, above 2000 ms"),
        "{}",
        ran.finding().message
    );
    // The spec raises the limit.
    let ran = run_on(
        replay,
        json!(["slow.acme.test:8080"]),
        json!({"max_latency": "3s"}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
}

#[tokio::test(start_paused = true)]
async fn a_proxy_only_endpoint_is_not_tried_and_the_result_is_partial() {
    let ran = run_on(
        case("pass-plain"),
        json!(["web.acme.test:8080"]),
        json!({"via_proxy": "proxy_only"}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["result"], "not_tried");
    assert!(
        ran.run
            .action_log()
            .actions
            .iter()
            .all(|a| a.kind != rdy_spec::result::ActionKind::Connect)
    );
    let result = ran.result();
    assert_eq!(
        result.status,
        Status::Warn,
        "an unverified pass is a warning"
    );
    assert!(
        result.message.starts_with("not verified:"),
        "{}",
        result.message
    );
    assert!(result.partial.is_some());
}

#[tokio::test(start_paused = true)]
async fn without_the_network_need_the_check_skips_as_missing_need_and_opens_no_socket() {
    let ran = run_on(
        case("pass-plain"),
        json!(["web.acme.test:8080"]),
        json!({}),
        &[],
    )
    .await;
    assert_eq!(ran.outcome, Err(CheckError::MissingNeed(Need::Network)));
    let result = ran.result();
    assert_eq!(result.status, Status::Skipped);
    assert_eq!(result.skip_kind, Some(SkipKind::MissingNeed));
    assert!(
        ran.run.action_log().actions.is_empty(),
        "no lookup, no connect"
    );
}

// ---- the address policy -------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_link_local_endpoint_is_refused_by_policy_and_never_dialed() {
    for endpoint in ["169.254.169.254:80", "[fd20:ce::254]:80", "0.0.0.0:443"] {
        let ran = run_on(Replay::new(), json!([endpoint]), json!({}), NET).await;
        assert_eq!(ran.endpoint(0)["class"], "refused_by_policy", "{endpoint}");
        let fix = ran.finding().fix.as_deref().expect("a fix");
        assert!(fix.contains("will not contact"), "{fix}");
        let log = ran.run.action_log();
        assert!(
            log.actions
                .iter()
                .all(|a| a.outcome == rdy_spec::result::ActionOutcome::Denied),
            "{endpoint}: every call is denied and none reaches the backend"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_name_that_resolves_to_a_metadata_address_is_refused() {
    let replay = Replay::new().host("meta.acme.test", ["169.254.169.254".parse().expect("ip")]);
    let ran = run_on(replay, json!(["meta.acme.test:8080"]), json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["class"], "refused_by_policy");
    assert_eq!(ran.endpoint(0)["attempts"], json!([]));
}

// ---- TLS and ALPN on loopback -------------------------------------------------------------------

fn der(ca: &TestCa) -> Vec<u8> {
    ca.root_der().as_ref().to_vec()
}

/// A replay machine whose `name` resolves to the loopback `server`, with this OS trust bundle.
fn machine(name: &str, server: SocketAddr, bundle: Option<Vec<Vec<u8>>>) -> Replay {
    let replay = Replay::new()
        .host(name, ["127.0.0.1".parse().expect("ip")])
        .tcp(server, TcpScript::Serve("tls".to_owned()))
        .serve_tcp("tls", server);
    match bundle {
        Some(roots) => replay.native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(roots.into()),
        ),
        None => replay,
    }
}

async fn tls_server(ca: &TestCa, name: &str, validity: Validity) -> HttpServer {
    let options = HttpOptions::tls(&ca.issue(&[name], validity)).alpn(&["h2", "http/1.1"]);
    HttpServer::start(options).await.expect("a server")
}

fn tls_endpoint(name: &str, server: &HttpServer) -> Value {
    json!([{"target": format!("{name}:{}", server.addr().port()), "tls": true}])
}

#[tokio::test]
async fn a_trusted_chain_completes_with_protocol_alpn_and_depth_and_sends_no_application_data() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "web.acme.test", Validity::Always).await;
    let replay = machine("web.acme.test", server.addr(), Some(vec![der(&ca)]));
    let ran = run_on(
        replay,
        tls_endpoint("web.acme.test", &server),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(
        ran.finding().level,
        Level::Pass,
        "{}",
        ran.finding().message
    );
    let stage = &ran.endpoint(0)["tls_stage"];
    assert_eq!(stage["protocol"], "TLS 1.3");
    assert_eq!(stage["alpn"], "h2");
    assert_eq!(stage["chain_depth"], 1);
    assert_eq!(stage["roots"], "system");
    assert!(stage["handshake_ms"].is_u64());
    assert!(ran.endpoint(0)["connect_ms"].is_u64());
    // The server notes the handshake a moment after the client has closed.
    for _ in 0..200 {
        if server.handshakes() == 1 && !server.sni_seen().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(server.application_bytes(), 0, "no HTTP request is sent");
    assert_eq!(server.sni_seen(), vec![Some("web.acme.test".to_owned())]);
    assert_eq!(ran.result().status, Status::Pass);
}

#[tokio::test]
async fn an_issuer_this_machine_does_not_trust_is_tls_unknown_issuer() {
    let ca = TestCa::root("Acme Test Root");
    let other = TestCa::root("Some Other Root");
    let server = tls_server(&ca, "web.acme.test", Validity::Always).await;
    let replay = machine("web.acme.test", server.addr(), Some(vec![der(&other)]));
    let ran = run_on(
        replay,
        tls_endpoint("web.acme.test", &server),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.endpoint(0)["class"], "tls_unknown_issuer");
    assert_eq!(ran.endpoint(0)["tls_stage"]["chain_depth"], 1);
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("net.tls_intercept"), "{fix}");
    assert!(fix.contains("update-ca-trust"), "{fix}");
}

#[tokio::test]
async fn an_expired_certificate_is_clock_or_expiry_and_not_interception() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "web.acme.test", Validity::Expired).await;
    let replay = machine("web.acme.test", server.addr(), Some(vec![der(&ca)]));
    let ran = run_on(
        replay,
        tls_endpoint("web.acme.test", &server),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "clock_or_expiry");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("timedatectl"), "{fix}");
    assert!(!fix.contains("inspect"), "{fix}");
}

#[tokio::test]
async fn a_machine_without_a_trust_store_falls_back_to_the_bundled_roots_and_says_so() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "web.acme.test", Validity::Always).await;
    let replay = machine("web.acme.test", server.addr(), Some(Vec::new()));
    let ran = run_on(
        replay,
        tls_endpoint("web.acme.test", &server),
        json!({}),
        NET,
    )
    .await;
    let stage = &ran.endpoint(0)["tls_stage"];
    assert_eq!(stage["roots"], "bundled");
    assert!(
        stage["fallback"]
            .as_str()
            .is_some_and(|s| s.contains("no usable OS trust store")),
        "{stage}"
    );
    // The test CA is not a public root, so the bundled verdict rejects it.
    assert_eq!(ran.endpoint(0)["class"], "tls_unknown_issuer");
}

#[tokio::test]
async fn trust_bundled_ignores_the_os_store() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "web.acme.test", Validity::Always).await;
    // The OS store holds the CA, but the spec asks for the bundled public roots.
    let replay = machine("web.acme.test", server.addr(), Some(vec![der(&ca)]));
    let ran = run_on(
        replay,
        tls_endpoint("web.acme.test", &server),
        json!({"trust": "bundled"}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "tls_unknown_issuer");
    assert_eq!(ran.endpoint(0)["tls_stage"]["roots"], "bundled");
    assert_eq!(ran.finding().expected["trust"], "bundled");
}

#[tokio::test]
async fn a_reset_after_the_client_hello_is_reset_after_hello_with_the_openssl_hint() {
    let server = ResetAfterClientHello::start().await.expect("a server");
    let replay = machine("filtered.acme.test", server.addr(), Some(vec![]));
    let endpoints =
        json!([{"target": format!("filtered.acme.test:{}", server.addr().port()), "tls": true}]);
    let ran = run_on(replay, endpoints, json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["class"], "reset_after_hello");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(
        fix.contains("openssl s_client -connect filtered.acme.test:"),
        "{fix}"
    );
    assert!(fix.contains("-servername filtered.acme.test"), "{fix}");
}

#[tokio::test]
async fn a_dead_ipv6_address_in_front_of_a_tls_server_is_named_and_the_handshake_completes() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "dual.acme.test", Validity::Always).await;
    let port = server.addr().port();
    let replay = Replay::new()
        .host(
            "dual.acme.test",
            [
                "2001:db8::1".parse().expect("ip"),
                "127.0.0.1".parse().expect("ip"),
            ],
        )
        .tcp(
            format!("[2001:db8::1]:{port}").parse().expect("addr"),
            TcpScript::Refused,
        )
        .tcp(server.addr(), TcpScript::Serve("tls".to_owned()))
        .serve_tcp("tls", server.addr())
        .native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(vec![der(&ca)].into()),
        );
    let ran = run_on(
        replay,
        tls_endpoint("dual.acme.test", &server),
        json!({}),
        NET,
    )
    .await;
    let e = ran.endpoint(0);
    assert_eq!(e["result"], "reached");
    assert_eq!(e["attempts"][0]["family"], "ipv6");
    assert_eq!(e["attempts"][0]["outcome"], "refused");
    assert_eq!(e["tls_stage"]["alpn"], "h2");
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        ran.finding()
            .message
            .contains("the ipv6 address failed (refused)")
    );
}

#[tokio::test(start_paused = true)]
async fn an_all_blackhole_tls_endpoint_names_the_silent_address_from_the_attempts() {
    let ran = run_on(
        case("blackhole"),
        json!([{"target": "hole.acme.test:8080", "tls": true}]),
        json!({}),
        NET,
    )
    .await;
    let e = ran.endpoint(0);
    assert_eq!(e["class"], "blackhole");
    assert_eq!(e["attempts"][0]["outcome"], "timed_out");
    assert!(
        ran.finding()
            .fix
            .as_deref()
            .expect("fix")
            .starts_with("No reply to SYN from 192.0.2.9:8080"),
        "{:?}",
        ran.finding().fix
    );
}

// ---- secrets, bounds, ordering ------------------------------------------------------------------

#[tokio::test]
async fn a_query_string_token_and_a_path_never_reach_the_result_or_the_log() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "web.acme.test", Validity::Always).await;
    let port = server.addr().port();
    let replay = machine("web.acme.test", server.addr(), Some(vec![der(&ca)]));
    let url = format!("https://web.acme.test:{port}/v2/private/path?token=hunter2-canary-token");
    let ran = run_on(replay, json!([url]), json!({}), NET).await;
    assert_eq!(
        ran.finding().level,
        Level::Pass,
        "{}",
        ran.finding().message
    );
    let text = ran.everything_text();
    assert!(!text.contains("hunter2-canary-token"), "{text}");
    assert!(!text.contains("/v2/private/path"), "{text}");
    assert!(text.contains(&format!("web.acme.test:{port}")));
}

#[tokio::test(start_paused = true)]
async fn many_endpoints_are_reported_in_spec_order_and_the_message_is_bounded() {
    let mut replay = Replay::new().serve_duplex("web", |_server| async {});
    let mut endpoints = Vec::new();
    for n in 0..12_u8 {
        let name = format!("h{n}.acme.test");
        let ip: std::net::IpAddr = format!("192.0.2.{}", 20 + n).parse().expect("ip");
        replay = replay.host(&name, [ip]);
        // Even endpoints answer; odd ones are closed.
        let script = if n % 2 == 0 {
            TcpScript::Serve("web".to_owned())
        } else {
            TcpScript::Refused
        };
        replay = replay.tcp(SocketAddr::new(ip, 8080), script);
        endpoints.push(format!("{name}:8080"));
    }
    let ran = run_on(replay, json!(endpoints), json!({}), NET).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .starts_with("6 of 12 endpoints unreachable: h1.acme.test:8080 (refused)")
    );
    assert!(
        finding.message.ends_with("and 1 more"),
        "{}",
        finding.message
    );
    for n in 0..12 {
        assert_eq!(ran.endpoint(n)["endpoint"], format!("h{n}.acme.test:8080"));
    }
    // One fix per distinct class, not one per endpoint.
    assert_eq!(
        finding
            .fix
            .as_deref()
            .expect("fix")
            .matches("refused the connection")
            .count(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn expect_status_is_noted_as_not_checked_yet() {
    let ran = run_on(
        case("pass-plain"),
        json!([{"target": "http://web.acme.test:8080/health", "expect_status": [200]}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("expect_status is not checked yet"))
    );
}

// ---- the family ---------------------------------------------------------------------------------

#[test]
fn the_info_declares_the_network_need_and_only_the_spec_hosts() {
    assert_eq!(INFO.id, "net.egress");
    assert_eq!(INFO.needs, &[Need::Network]);
    assert!(INFO.wants.is_empty(), "root adds nothing to this check");
    assert_eq!(INFO.peers, &[PeerClass::SpecHosts]);
    assert!(INFO.reads.is_empty() && INFO.commands.is_empty() && INFO.env.is_empty());
    assert_eq!(
        INFO.default_timeout,
        Some(std::time::Duration::from_secs(60))
    );
}

#[test]
fn the_family_builds_the_check_with_exactly_the_endpoint_hosts() {
    let spec = rdy_spec::parse_unverified(
        b"apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: net.egress\n    endpoints:\n      - registry.acme.test:443\n      - https://api.acme.test:8443/v1?x=1\n      - registry.acme.test:443\n  - id: net.proxy\n",
    )
    .expect("a spec");
    let family = NetFamily;
    assert_eq!(family.name(), "net");
    let entry = spec.checks.first().expect("an entry");
    let built = family
        .build(entry, entry.decode_params(), &spec)
        .expect("builds");
    let hosts: Vec<String> = built
        .hosts
        .iter()
        .map(|t| format!("{}:{}", t.host(), t.port()))
        .collect();
    assert_eq!(hosts, ["registry.acme.test:443", "api.acme.test:8443"]);
    // The other net ids are not built, so the planner skips them as not in the build.
    let other = spec.checks.get(1).expect("net.proxy");
    assert!(family.build(other, other.decode_params(), &spec).is_err());
}
