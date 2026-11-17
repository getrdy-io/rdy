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
    HttpOptions, HttpServer, Reply, ResetAfterClientHello, TestCa, Validity,
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

    /// Fails when `secret` is anywhere in the finding, the serialized result or the action log.
    fn assert_no_secret(&self, secret: &str) {
        let written = serde_json::to_string(&self.result()).expect("the result serialises");
        assert!(
            !written.contains(secret),
            "the result holds {secret}: {written}"
        );
        let text = self.everything_text();
        assert!(
            !text.contains(secret),
            "the finding or log holds {secret}: {text}"
        );
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
async fn a_silent_ipv6_address_is_a_note_and_not_a_warning_when_ipv4_carries_the_connection() {
    let ran = run_on(
        case("dual-silent-v6"),
        json!(["dual.acme.test:8080"]),
        json!({}),
        NET,
    )
    .await;
    let finding = ran.finding();
    // A slow path that works is not a fault: the race cut it, so it is a note (03, C3).
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("the ipv6 address had no reply within 250 ms")),
        "{:?}",
        finding.notes
    );
    let e = ran.endpoint(0);
    // IPv6 first; IPv4 starts one stagger later and wins; the silent attempt was cut.
    assert_eq!(e["attempts"][0]["family"], "ipv6");
    assert_eq!(e["attempts"][0]["outcome"], "abandoned");
    assert_eq!(e["attempts"][1]["family"], "ipv4");
    assert_eq!(e["attempts"][1]["started_ms"], 250);
    assert_eq!(e["connect_ms"], 250);
    assert_eq!(ran.result().status, Status::Pass);
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
    let mut seen = false;
    for _ in 0..3000 {
        if server.handshakes() == 1 && !server.sni_seen().is_empty() {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(seen, "the server never recorded the handshake");
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
            .is_some_and(|s| s.contains("no OS trust store found")),
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
async fn a_query_string_token_never_reaches_the_result_or_the_log_and_the_path_only_the_log() {
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
    // The facade logs the path of an http call and never its query (M1-093). The result holds neither.
    let finding = ran.finding();
    let result_text = format!(
        "{} {} {:?} {:?}",
        finding.message, finding.observed, finding.fix, finding.notes
    );
    assert!(!result_text.contains("/v2/private/path"), "{result_text}");
    let written = serde_json::to_string(&ran.result()).expect("the result serialises");
    assert!(!written.contains("hunter2-canary-token"), "{written}");
    assert!(!written.contains("/v2/private/path"), "{written}");
    // The request itself carried them, so the server did see the path and query.
    let seen = server.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0].target,
        "/v2/private/path?token=hunter2-canary-token"
    );
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 200);
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
async fn expect_status_on_a_host_port_endpoint_is_ignored_and_says_so() {
    let ran = run_on(
        case("pass-plain"),
        json!([{"target": "web.acme.test:8080", "expect_status": [200]}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert!(ran.endpoint(0).get("http_stage").is_none());
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("expect_status is ignored for 1 endpoint(s) written as host:port")),
        "{:?}",
        ran.finding().notes
    );
}

// ---- the HTTP stage ------------------------------------------------------------------------------

/// A TLS server with `reply`, and a machine whose OS store trusts its CA.
async fn https_machine(name: &str, reply: Reply) -> (Replay, HttpServer) {
    let ca = TestCa::root("Acme Test Root");
    let options = HttpOptions::tls(&ca.issue(&[name], Validity::Always))
        .alpn(&["h2", "http/1.1"])
        .reply(reply);
    let server = HttpServer::start(options).await.expect("a server");
    (machine(name, server.addr(), Some(vec![der(&ca)])), server)
}

fn url(name: &str, server: &HttpServer, path: &str) -> String {
    format!("https://{name}:{}{path}", server.addr().port())
}

#[tokio::test]
async fn a_url_gets_one_head_and_a_200_passes_with_the_stage_timings() {
    let (replay, server) = https_machine("api.acme.test", Reply::Ok).await;
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/health")]),
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
    let http = &ran.endpoint(0)["http_stage"];
    assert_eq!(http["method"], "HEAD");
    assert_eq!(http["status"], 200);
    assert_eq!(http["expect_status"], json!([]));
    assert!(http["first_byte_ms"].is_u64() && http["total_ms"].is_u64());
    let requests = server.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].method, "HEAD");
    assert_eq!(requests[0].target, "/health");
    assert_eq!(ran.result().status, Status::Pass);
}

#[tokio::test]
async fn the_method_of_the_spec_is_sent() {
    let (replay, server) = https_machine("api.acme.test", Reply::Ok).await;
    let endpoints = json!([{"target": url("api.acme.test", &server, "/"), "method": "GET"}]);
    let ran = run_on(replay, endpoints, json!({}), NET).await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert_eq!(ran.endpoint(0)["http_stage"]["method"], "GET");
    assert_eq!(server.requests()[0].method, "GET");
}

#[tokio::test]
async fn a_5xx_is_http_status_with_the_status_in_the_message_and_a_fix() {
    let (replay, server) = https_machine("api.acme.test", Reply::Status(503)).await;
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/?token=canary-503")]),
        json!({}),
        NET,
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("(http_status 503)"),
        "{}",
        finding.message
    );
    assert_eq!(ran.endpoint(0)["class"], "http_status");
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 503);
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("answered 503"), "{fix}");
    assert!(fix.contains("is failing"), "{fix}");
    assert_eq!(ran.result().status, Status::Block);
    ran.assert_no_secret("canary-503");
}

#[tokio::test]
async fn a_status_outside_expect_status_fails_and_one_inside_passes() {
    let (replay, server) = https_machine("api.acme.test", Reply::Status(401)).await;
    let target = url("api.acme.test", &server, "/v2/");
    let ran = run_on(
        replay.clone(),
        json!([{"target": target, "expect_status": [200]}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.endpoint(0)["class"], "http_status");
    assert!(
        ran.finding()
            .fix
            .as_deref()
            .expect("fix")
            .contains("add the status to `expect_status`")
    );

    let ran = run_on(
        replay,
        json!([{"target": target, "expect_status": [200, 401]}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert_eq!(
        ran.endpoint(0)["http_stage"]["expect_status"],
        json!([200, 401])
    );
    assert!(ran.finding().notes.is_empty(), "{:?}", ran.finding().notes);
}

#[tokio::test]
async fn a_4xx_with_no_expect_status_counts_as_reachable_and_is_noted() {
    let (replay, server) = https_machine("api.acme.test", Reply::Status(404)).await;
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("answered 404: the spec lists no expect_status")),
        "{:?}",
        ran.finding().notes
    );
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_its_status_is_the_answer() {
    let (replay, server) = https_machine(
        "api.acme.test",
        Reply::Redirect("https://other.acme.test/x?token=canary-redirect".to_owned()),
    )
    .await;
    let ran = run_on(
        replay.clone(),
        json!([url("api.acme.test", &server, "/")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass, "a 302 is below 500");
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 302);
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("answered 302: the redirect was not followed")),
        "{:?}",
        ran.finding().notes
    );
    assert_eq!(server.requests().len(), 1, "no second request");
    assert!(!ran.everything_text().contains("canary-redirect"));
    let ran = run_on(
        replay,
        json!([{"target": url("api.acme.test", &server, "/"), "expect_status": [200]}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "http_status");
}

#[tokio::test]
async fn a_reply_that_is_not_http_is_http_failed() {
    let (replay, server) = https_machine(
        "api.acme.test",
        Reply::Raw(b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()),
    )
    .await;
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/?token=canary-nothttp")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "http_failed");
    assert_eq!(ran.finding().level, Level::Fail);
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("did not answer HTTP correctly"), "{fix}");
    assert!(
        !ran.everything_text().contains("OpenSSH"),
        "a reply is never echoed"
    );
    ran.assert_no_secret("canary-nothttp");
}

#[tokio::test]
async fn an_optional_url_that_answers_5xx_warns() {
    let (replay, server) = https_machine("api.acme.test", Reply::Status(502)).await;
    let ran = run_on(
        replay,
        json!([{"target": url("api.acme.test", &server, "/"), "optional": true}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        ran.finding()
            .message
            .contains("optional, failed: http_status 502"),
        "{}",
        ran.finding().message
    );
}

#[tokio::test]
async fn an_untrusted_issuer_stops_before_any_request_is_sent() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "api.acme.test", Validity::Always).await;
    // The OS store does not hold the CA.
    let replay = machine("api.acme.test", server.addr(), Some(vec![]));
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/?token=canary-untrusted")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "tls_unknown_issuer");
    assert!(ran.endpoint(0).get("http_stage").is_none());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        server.requests().is_empty(),
        "no HTTP over an untrusted chain"
    );
    assert_eq!(server.application_bytes(), 0);
    ran.assert_no_secret("canary-untrusted");
}

#[tokio::test]
async fn an_expired_certificate_on_a_url_is_clock_or_expiry_and_no_request_is_sent() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "api.acme.test", Validity::Expired).await;
    let replay = machine("api.acme.test", server.addr(), Some(vec![der(&ca)]));
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/?token=canary-expired")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "clock_or_expiry");
    assert!(server.requests().is_empty());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(server.application_bytes(), 0);
    ran.assert_no_secret("canary-expired");
}

#[tokio::test]
async fn a_reset_after_hello_on_a_url_is_reset_after_hello() {
    let server = ResetAfterClientHello::start().await.expect("a server");
    let replay = machine("filtered.acme.test", server.addr(), Some(vec![]));
    let endpoints = json!([format!(
        "https://filtered.acme.test:{}/",
        server.addr().port()
    )]);
    let ran = run_on(replay, endpoints, json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["class"], "reset_after_hello");
}

#[tokio::test(start_paused = true)]
async fn a_closed_port_on_a_url_is_refused() {
    let ran = run_on(
        case("refused"),
        json!(["http://closed.acme.test:8080/health?token=canary-refused"]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "refused");
    assert!(ran.endpoint(0).get("http_stage").is_none());
    ran.assert_no_secret("canary-refused");
}

#[tokio::test]
async fn trust_bundled_judges_the_request_by_the_bundled_roots() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "api.acme.test", Validity::Always).await;
    let replay = machine("api.acme.test", server.addr(), Some(vec![der(&ca)]));
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/")]),
        json!({"trust": "bundled"}),
        NET,
    )
    .await;
    // The bundled public roots do not hold the test CA: the TLS stage says so and no request goes out.
    assert_eq!(ran.endpoint(0)["class"], "tls_unknown_issuer");
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_407_on_the_direct_route_fails_as_http_status_and_the_fix_names_the_proxy() {
    let (replay, server) = https_machine("api.acme.test", Reply::Status(407)).await;
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/?token=canary-407")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.endpoint(0)["class"], "http_status");
    assert!(
        ran.finding().message.contains("endpoints failed"),
        "{}",
        ran.finding().message
    );
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(
        fix.contains("answered 407") && fix.contains("proxy"),
        "{fix}"
    );
    ran.assert_no_secret("canary-407");
}

#[tokio::test]
async fn a_403_with_no_expect_status_warns_that_a_proxy_deny_page_looks_the_same() {
    let (replay, server) = https_machine("api.acme.test", Reply::Status(403)).await;
    let ran = run_on(
        replay.clone(),
        json!([url("api.acme.test", &server, "/")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        ran.finding()
            .message
            .contains("answered 403: a deny page may come from a proxy"),
        "{}",
        ran.finding().message
    );
    assert_eq!(ran.result().status, Status::Warn);
    // Listed, it passes quietly.
    let ran = run_on(
        replay,
        json!([{"target": url("api.acme.test", &server, "/"), "expect_status": [403]}]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
}

#[tokio::test]
async fn with_no_expect_status_401_404_and_other_4xx_pass_with_a_note_and_2xx_without() {
    for (status, noted) in [(200_u16, false), (401, true), (404, true), (418, true)] {
        let (replay, server) = https_machine("api.acme.test", Reply::Status(status)).await;
        let ran = run_on(
            replay,
            json!([url("api.acme.test", &server, "/")]),
            json!({}),
            NET,
        )
        .await;
        assert_eq!(ran.finding().level, Level::Pass, "{status}");
        assert_eq!(!ran.finding().notes.is_empty(), noted, "{status}");
    }
}

#[tokio::test]
async fn a_redirect_to_the_metadata_address_is_one_request_and_no_dial_to_it() {
    let (replay, server) = https_machine(
        "api.acme.test",
        Reply::Redirect("http://169.254.169.254/latest/meta-data?token=canary-meta".to_owned()),
    )
    .await;
    let ran = run_on(
        replay,
        json!([url("api.acme.test", &server, "/")]),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 302);
    let log = ran.run.action_log();
    let http = log
        .actions
        .iter()
        .filter(|a| a.kind == rdy_spec::result::ActionKind::Http)
        .count();
    assert_eq!(http, 1, "{log:?}");
    let text = format!("{log:?}");
    assert!(
        !text.contains("169.254.169.254"),
        "no lookup or tcp for it: {text}"
    );
    assert_eq!(server.requests().len(), 1);
    ran.assert_no_secret("canary-meta");
}

#[tokio::test(start_paused = true)]
async fn a_request_that_cannot_start_in_the_time_left_is_not_tried_and_partial() {
    // IPv6 is silent, so IPv4 connects 250 ms in. With a 3 s deadline that leaves under the 2 s reserve
    // plus the 1 s minimum for the HTTP stage.
    let replay = case("dual-silent-v6");
    let entry = entry(
        &json!(["http://dual.acme.test:8080/"]),
        &json!({"timeout": "3s"}),
    );
    let params = params(&entry);
    let hosts = HostSet::new(params.endpoints.iter().map(|e| e.target.clone()));
    let check: Arc<dyn Check> = Arc::new(EgressCheck::new(params));
    let run = TestRun::new(replay);
    let scheduler = run.scheduler(1, Os::Linux, [Need::Network]);
    let planned = Planned::new(check, "net.egress")
        .with_hosts(hosts)
        .with_timeout(Duration::from_secs(3));
    let mut ran = scheduler.run(vec![planned]).await;
    let End::Done(outcome) = ran.remove(0).end else {
        panic!("the check did not finish");
    };
    let finding = (*outcome).expect("a finding");
    assert_eq!(finding.observed["endpoints"][0]["result"], "not_tried");
    assert!(finding.partial.is_some(), "{finding:?}");
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

// ---- budgets, reasons, trust fallback, rebinding, words (PR #45 reviews) -------------------------

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rdy_engine::sched::{End, Planned};

/// Runs the check through the scheduler, so it has its own deadline and the paused clock moves.
async fn run_scheduled(replay: Replay, endpoints: Value) -> CheckOutcome {
    let entry = entry(&endpoints, &json!({}));
    let params = params(&entry);
    let hosts = HostSet::new(params.endpoints.iter().map(|e| e.target.clone()));
    let check: Arc<dyn Check> = Arc::new(EgressCheck::new(params));
    let run = TestRun::new(replay);
    let scheduler = run.scheduler(1, Os::Linux, [Need::Network]);
    let mut ran = scheduler
        .run(vec![Planned::new(check, "net.egress").with_hosts(hosts)])
        .await;
    match ran.remove(0).end {
        End::Done(outcome) => *outcome,
        other => panic!("the check did not finish: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn sixty_four_blackholed_tls_endpoints_fail_with_a_list_and_do_not_time_out() {
    let mut replay = Replay::new();
    let mut endpoints = Vec::new();
    for n in 0..64_u8 {
        let name = format!("b{n}.acme.test");
        let ip: std::net::IpAddr = format!("192.0.2.{}", 100 + n).parse().expect("ip");
        replay = replay
            .host(&name, [ip])
            .tcp(SocketAddr::new(ip, 443), TcpScript::Blackhole);
        endpoints.push(format!("{name}:443"));
    }
    let outcome = run_scheduled(replay, json!(endpoints)).await;
    let finding = outcome.expect("a finding and not a timeout");
    assert_eq!(finding.level, Level::Fail);
    let list = finding.observed["endpoints"].as_array().expect("a list");
    assert_eq!(list.len(), 64, "every endpoint is in the result");
    // On the paused clock the count is exact: every endpoint reaches its blackhole class.
    let blackholes = list.iter().filter(|e| e["class"] == "blackhole").count();
    assert_eq!(blackholes, 64, "{}", finding.message);
    let run = TestRun::new(Replay::new());
    let ctx = run.context_for(&INFO, "net.egress", Os::Linux, [Need::Network]);
    let spec = entry(&json!(["a.acme.test:443"]), &json!({}));
    let result = map_outcome(&INFO, &spec, &ctx, Ok(finding.clone()), 0, 0);
    assert_eq!(result.status, Status::Block);
    for e in list {
        let result = e["result"].as_str().unwrap_or_default();
        assert!(matches!(result, "failed" | "not_tried"), "{e}");
    }
}

#[tokio::test(start_paused = true)]
async fn an_endpoint_that_runs_past_its_budget_is_a_timeout_that_keeps_its_finished_stages() {
    // The lookup alone takes longer than the 10 s endpoint budget.
    let replay = Replay::new()
        .host("slow.acme.test", ["192.0.2.5".parse().expect("ip")])
        .lookup_delay("slow.acme.test", Duration::from_secs(30));
    let outcome = run_scheduled(
        replay,
        json!(["http://slow.acme.test:8080/x?token=canary-timeout"]),
    )
    .await;
    let finding = outcome.expect("a finding");
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(finding.observed["endpoints"][0]["class"], "timeout");
    let text = format!(
        "{} {} {:?} {:?}",
        finding.message, finding.observed, finding.fix, finding.notes
    );
    assert!(!text.contains("canary-timeout"), "{text}");
}

#[tokio::test(start_paused = true)]
async fn the_lookup_stage_reads_the_exact_delay_under_a_deadline() {
    let replay = case("pass-plain").lookup_delay("web.acme.test", Duration::from_millis(1500));
    let outcome = run_scheduled(replay, json!(["web.acme.test:8080"])).await;
    let finding = outcome.expect("a finding");
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.observed["endpoints"][0]["lookup"]["ms"], 1500);
}

#[test]
fn endpoints_not_tried_are_grouped_by_their_own_reason() {
    let entry = entry(
        &json!(["a.acme.test:8080", "b.acme.test:8080", "c.acme.test:8080"]),
        &json!({}),
    );
    let params = params(&entry);
    let specs: Vec<_> = params.endpoints.iter().cloned().collect();
    let probed = vec![
        stage::Probed::not_tried(&specs[0], PROXY_LATER),
        stage::Probed::not_tried(&specs[1], stage::OUT_OF_TIME),
        stage::Probed::not_tried(&specs[2], stage::OUT_OF_TIME),
    ];
    let finding = EgressCheck::new(params).judge(Os::Linux, &probed);
    let note = finding.partial.expect("partial").note;
    assert!(
        note.contains(&format!("1 of 3 endpoints were not tried: {PROXY_LATER}")),
        "{note}"
    );
    assert!(
        note.contains(&format!(
            "2 of 3 endpoints were not tried: {}",
            stage::OUT_OF_TIME
        )),
        "{note}"
    );
}

#[tokio::test]
async fn an_overridden_os_store_says_so_and_names_the_variables_in_the_fix() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "web.acme.test", Validity::Always).await;
    let replay = Replay::new()
        .host("web.acme.test", ["127.0.0.1".parse().expect("ip")])
        .tcp(server.addr(), TcpScript::Serve("tls".to_owned()))
        .serve_tcp("tls", server.addr())
        .system_roots_overridden();
    let ran = run_on(
        replay,
        tls_endpoint("web.acme.test", &server),
        json!({}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "tls_unknown_issuer");
    let stage = &ran.endpoint(0)["tls_stage"];
    assert_eq!(stage["roots"], "bundled");
    assert!(
        stage["fallback"]
            .as_str()
            .is_some_and(|t| t.contains("SSL_CERT_FILE or SSL_CERT_DIR")),
        "{stage}"
    );
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("SSL_CERT_FILE or SSL_CERT_DIR is set")),
        "{:?}",
        ran.finding().notes
    );
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("Unset both variables"), "{fix}");

    // A store that is only empty gets its own words and no advice about the variables.
    let replay = machine("web.acme.test", server.addr(), Some(Vec::new()));
    let ran = run_on(
        replay,
        tls_endpoint("web.acme.test", &server),
        json!({}),
        NET,
    )
    .await;
    let stage = &ran.endpoint(0)["tls_stage"];
    assert!(
        stage["fallback"]
            .as_str()
            .is_some_and(|t| t.starts_with("no OS trust store found"))
    );
    assert!(
        !ran.finding()
            .fix
            .as_deref()
            .expect("fix")
            .contains("Unset both variables")
    );
}

#[tokio::test(start_paused = true)]
async fn a_name_that_rebinds_to_a_metadata_address_between_lookups_is_refused_and_never_dialed() {
    let dialed = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&dialed);
    let replay = Replay::new()
        // The check's own lookup sees a public address. The connect-time lookup sees the metadata one.
        .host_rebinding(
            "rebind.acme.test",
            ["192.0.2.50".parse().expect("ip")],
            ["169.254.169.254".parse().expect("ip")],
        )
        .tcp(
            "192.0.2.50:8080".parse().expect("addr"),
            TcpScript::Serve("web".to_owned()),
        )
        .tcp(
            "169.254.169.254:8080".parse().expect("addr"),
            TcpScript::Serve("web".to_owned()),
        )
        .serve("web", move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { Err(std::io::Error::other("a dial that must not happen")) }
        });
    let ran = run_on(replay, json!(["rebind.acme.test:8080"]), json!({}), NET).await;
    assert_eq!(ran.endpoint(0)["class"], "refused_by_policy");
    assert_eq!(dialed.load(Ordering::SeqCst), 0, "no connection was opened");
    assert_eq!(ran.result().status, Status::Block);
}

#[test]
fn every_fix_text_on_every_os_names_only_listed_commands_and_no_foreign_paths() {
    for os in [Os::Linux, Os::Macos, Os::Windows] {
        for class in Class::ALL {
            let text = class.fix(os, "web.acme.test", 8443, Some("192.0.2.9:8443"));
            if let Err(error) = rdy_engine::fixtext::check(&text) {
                panic!("{os:?} {}: {error}", class.id());
            }
            if os != Os::Linux {
                for linux_only in [
                    "timedatectl",
                    "update-ca-certificates",
                    "ip route",
                    "apt-get",
                ] {
                    assert!(!text.contains(linux_only), "{os:?} {}: {text}", class.id());
                }
            }
            if os == Os::Windows {
                assert!(!text.contains("/etc/hosts"), "{}: {text}", class.id());
            }
            if os == Os::Windows && text.contains("openssl") {
                assert!(
                    text.contains("Where openssl is installed"),
                    "{}: {text}",
                    class.id()
                );
            }
        }
    }
    let windows = Class::Dns.fix(Os::Windows, "h.acme.test", 443, None);
    assert!(windows.contains("%SystemRoot%"), "{windows}");
    assert!(
        Class::ClockOrExpiry
            .fix(Os::Windows, "h", 1, None)
            .contains("w32tm /query /status")
    );
    assert!(
        Class::Unreachable
            .fix(Os::Windows, "h", 1, None)
            .contains("route print")
    );
    assert!(
        Class::TlsUnknownIssuer
            .fix(Os::Windows, "h", 1, None)
            .contains("certlm.msc")
    );
    assert!(
        Class::ClockOrExpiry
            .fix(Os::Macos, "h", 1, None)
            .contains("sntp")
    );
    assert!(
        Class::Unreachable
            .fix(Os::Macos, "h", 1, None)
            .contains("netstat -rn")
    );
    assert!(
        Class::TlsUnknownIssuer
            .fix(Os::Macos, "h", 1, None)
            .contains("security add-trusted-cert")
    );
    rdy_engine::fixtext::check(INFO.meta.remediation)
        .expect("the remediation names listed commands");
}
