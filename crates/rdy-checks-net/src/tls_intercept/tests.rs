//! Tests of `net.tls_intercept` (M1-099).
//!
//! The class table is a pure function and is tested for every pair of verdicts. The handshake cases run
//! against loopback TLS servers with certificates generated at test time (`rdy_engine::testing::loopback`),
//! with scripted addresses that point at the server. A generated CA plays three roles: a public root
//! (`TestRun::trust_as_public`), a root in this machine's store (the `system_roots` answer of the replay),
//! and a CA nobody trusts. The clock is pinned with `TestRun::pin_clock`, so no case depends on the date.

use std::net::SocketAddr;
use std::time::Duration;

use rdy_engine::check::{Check, CheckContext, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::family::HostSet;
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::net::{TrustFailure, TrustVerdict};
use rdy_engine::probe::{NativeCall, NativeValue, NoRoots};
use rdy_engine::testing::loopback::{HttpOptions, HttpServer, TestCa, Validity};
use rdy_engine::testing::{
    Fixture, Replay, TcpScript, TestRun, assert_within_manifest, fixtures_dir,
};
use rdy_spec::check::CheckParams;
use rdy_spec::parse_unverified;
use rdy_spec::result::{CheckResult, Status};
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::{Value, json};

use super::*;

const ACME: &str = include_str!("../../../../examples/specs/acme-platform.yaml");

/// 2022-06-01T00:00:00Z: after the `Expired` leaf's notAfter (2021-01-01).
const JUNE_2022: Duration = Duration::from_secs(1_654_041_600);

/// 2020-06-01T00:00:00Z: inside the `Expired` leaf's window (2020-01-01 to 2021-01-01).
const JUNE_2020: Duration = Duration::from_secs(1_590_969_600);

// ---- the class table ----------------------------------------------------------------------------

fn rejected(failure: TrustFailure) -> TrustVerdict {
    TrustVerdict::Rejected(failure)
}

#[test]
fn the_class_follows_the_pair_of_verdicts() {
    use TrustVerdict::{Unavailable, Valid};
    let none = Unavailable(NoRoots::Empty);
    let unknown = rejected(TrustFailure::UnknownIssuer);
    let cases = [
        // Public roots validate: public, whatever this machine's store says.
        (Valid, Valid, Class::Public),
        (Valid, unknown, Class::Public),
        (Valid, none, Class::Public),
        (Valid, rejected(TrustFailure::Expired), Class::Public),
        // Only the OS store validates.
        (unknown, Valid, Class::MachineOnly),
        (rejected(TrustFailure::Policy), Valid, Class::MachineOnly),
        // Nothing validates.
        (unknown, unknown, Class::UnknownCa),
        (
            unknown,
            rejected(TrustFailure::BadSignature),
            Class::UnknownCa,
        ),
        (unknown, none, Class::NoTrustStore),
        (
            unknown,
            Unavailable(NoRoots::Unreadable),
            Class::NoTrustStore,
        ),
        (
            unknown,
            Unavailable(NoRoots::Overridden),
            Class::NoTrustStore,
        ),
        // A clock failure in either verdict is never interception, and wins over the issuer.
        (
            unknown,
            rejected(TrustFailure::Expired),
            Class::ClockOrExpiry,
        ),
        (
            unknown,
            rejected(TrustFailure::NotYetValid),
            Class::ClockOrExpiry,
        ),
        (rejected(TrustFailure::Expired), none, Class::ClockOrExpiry),
        (
            rejected(TrustFailure::Expired),
            rejected(TrustFailure::Expired),
            Class::ClockOrExpiry,
        ),
        // A wrong name is not an issuer problem either.
        (
            rejected(TrustFailure::NameMismatch),
            rejected(TrustFailure::NameMismatch),
            Class::NameMismatch,
        ),
        (
            unknown,
            rejected(TrustFailure::NameMismatch),
            Class::NameMismatch,
        ),
        // Anything else that is refused.
        (
            rejected(TrustFailure::Policy),
            rejected(TrustFailure::Policy),
            Class::Untrusted,
        ),
        (rejected(TrustFailure::BadSignature), none, Class::Untrusted),
    ];
    for (bundled, system, expected) in cases {
        assert_eq!(
            Class::of_verdicts(bundled, system),
            expected,
            "bundled {bundled:?}, system {system:?}"
        );
    }
}

#[test]
fn the_levels_follow_the_catalog() {
    assert_eq!(Class::Public.level(false), Level::Pass);
    assert_eq!(Class::Public.level(true), Level::Pass);
    assert_eq!(Class::MachineOnly.level(false), Level::Warn);
    assert_eq!(Class::MachineOnly.level(true), Level::Fail);
    for class in [
        Class::UnknownCa,
        Class::ClockOrExpiry,
        Class::NameMismatch,
        Class::Untrusted,
        Class::NoTrustStore,
    ] {
        assert_eq!(class.level(false), Level::Fail, "{class:?}");
    }
}

#[test]
fn every_class_has_its_own_id_and_every_fix_passes_the_audit() {
    let mut ids: Vec<&str> = Class::ALL.iter().map(|c| c.id()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), Class::ALL.len());
    for class in Class::ALL {
        for os in [Os::Linux, Os::Macos, Os::Windows] {
            for forbid in [false, true] {
                let fix = class.fix(os, "web.acme.test", 443, forbid);
                assert_eq!(fix.is_none(), class == Class::Public, "{class:?}");
                let Some(text) = fix else { continue };
                if let Err(error) = rdy_engine::fixtext::check(&text) {
                    panic!("{class:?} on {os:?}: {error}\n{text}");
                }
                assert!(!text.contains('\u{2014}'), "no em dash: {text}");
                assert!(text.contains("web.acme.test"), "{text}");
            }
        }
    }
    let text = INFO.meta.remediation;
    rdy_engine::fixtext::check(text).expect("the remediation passes the audit");
}

#[test]
fn a_clock_fix_points_at_host_time_sync_and_never_says_inspection() {
    let fix = Class::ClockOrExpiry
        .fix(Os::Linux, "web.acme.test", 443, false)
        .expect("a fix");
    assert!(fix.contains("host.time_sync"), "{fix}");
    assert!(fix.contains("timedatectl"), "{fix}");
    assert!(!fix.to_lowercase().contains("inspect"), "{fix}");
}

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

    fn host(&self, at: usize) -> &Value {
        &self.finding().observed["hosts"][at]
    }

    fn result(&self) -> CheckResult {
        map_outcome(&INFO, &self.entry, &self.ctx, self.outcome.clone(), 0, 0)
    }

    fn text(&self) -> String {
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

fn spec_with(entries: &[Value]) -> Spec {
    let mut spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    spec.checks = entries
        .iter()
        .map(|v| serde_json::from_value::<CheckSpec>(v.clone()).expect("a check entry"))
        .collect();
    spec
}

fn entry(extra: &Value) -> Value {
    let mut entry = json!({"id": "net.tls_intercept"});
    for (key, value) in extra.as_object().expect("an object") {
        entry[key] = value.clone();
    }
    entry
}

fn built(spec: &Spec, at: usize) -> (TlsInterceptCheck, HostSet, CheckSpec) {
    let entry = spec.checks[at].clone();
    let CheckParams::NetTlsIntercept(params) = entry.decode_params() else {
        panic!("not net.tls_intercept");
    };
    let (hosts, dropped) = hosts_for(&params, spec);
    let set = HostSet::new(hosts.iter().cloned());
    (TlsInterceptCheck::new(&params, hosts, dropped), set, entry)
}

async fn run_with(run: TestRun, extra: Value) -> Ran {
    let spec = spec_with(&[entry(&extra)]);
    let (check, hosts, entry) = built(&spec, 0);
    let ctx = run.context_for_hosts(
        &INFO,
        "net.tls_intercept",
        Os::Linux,
        [Need::Network],
        hosts,
    );
    let outcome = check.run(&ctx).await;
    assert_within_manifest("net.tls_intercept", &INFO, &run.action_log());
    Ran {
        outcome,
        ctx,
        entry,
        run,
    }
}

fn der(ca: &TestCa) -> Vec<u8> {
    ca.root_der().as_ref().to_vec()
}

/// A replay machine whose `name` resolves to the loopback `server`, with this OS trust bundle.
fn machine(name: &str, server: SocketAddr, bundle: Vec<Vec<u8>>) -> Replay {
    Replay::new()
        .host(name, ["127.0.0.1".parse().expect("ip")])
        .tcp(server, TcpScript::Serve("tls".to_owned()))
        .serve_tcp("tls", server)
        .native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(bundle.into()),
        )
}

async fn server(ca: &TestCa, name: &str, validity: Validity) -> HttpServer {
    let options = HttpOptions::tls(&ca.issue(&[name], validity)).alpn(&["h2", "http/1.1"]);
    HttpServer::start(options).await.expect("a server")
}

fn hosts_of(name: &str, server: &HttpServer) -> Value {
    json!({"hosts": [format!("{name}:{}", server.addr().port())]})
}

const NAME: &str = "web.acme.test";

// ---- handshakes ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_chain_the_public_roots_validate_passes_and_sends_no_application_data() {
    let ca = TestCa::root("Acme Test Public Root");
    let web = server(&ca, NAME, Validity::Always).await;
    // The machine's store holds a different CA: public wins regardless.
    let other = TestCa::root("Some Other Root");
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&other)]));
    run.trust_as_public(&der(&ca));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    assert_eq!(ran.host(0)["class"], "public");
    assert_eq!(ran.host(0)["public_roots"], "valid");
    assert_eq!(ran.host(0)["os_store"], "unknown_issuer");
    assert_eq!(ran.host(0)["chain_depth"], 1);
    assert!(finding.fix.is_none());
    assert!(finding.partial.is_none());
    assert_eq!(ran.result().status, Status::Pass);
    settle(&web).await;
    assert_eq!(web.handshakes(), 1, "one handshake per host");
    assert_eq!(web.application_bytes(), 0, "zero application bytes");
    assert_eq!(web.sni_seen(), vec![Some(NAME.to_owned())]);
}

#[tokio::test]
async fn a_chain_only_this_machine_trusts_warns_and_blocks_when_interception_is_forbidden() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let replay = || machine(NAME, web.addr(), vec![der(&ca)]);

    let ran = run_with(TestRun::new(replay()), hosts_of(NAME, &web)).await;
    assert_eq!(
        ran.finding().level,
        Level::Warn,
        "{}",
        ran.finding().message
    );
    assert_eq!(ran.host(0)["class"], "machine_only");
    assert_eq!(ran.host(0)["public_roots"], "unknown_issuer");
    assert_eq!(ran.host(0)["os_store"], "valid");
    assert!(
        ran.finding()
            .message
            .contains("trusted by this machine only"),
        "{}",
        ran.finding().message
    );
    assert_eq!(ran.result().status, Status::Warn);
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("bypass inspection"), "{fix}");
    assert!(!fix.contains("forbids"), "{fix}");

    let mut extra = hosts_of(NAME, &web);
    extra["forbid_interception"] = json!(true);
    let ran = run_with(TestRun::new(replay()), extra).await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.result().status, Status::Block);
    assert!(
        ran.finding()
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("forbids"))
    );
}

#[tokio::test]
async fn a_chain_nobody_trusts_blocks_as_an_unknown_ca() {
    let ca = TestCa::root("Acme Inspection Root");
    let other = TestCa::root("Some Other Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&other)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.host(0)["class"], "unknown_ca");
    assert_eq!(ran.host(0)["os_store"], "unknown_issuer");
    assert_eq!(ran.host(0)["os_store_roots"], 1);
    assert_eq!(ran.result().status, Status::Block);
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("update-ca-certificates"), "{fix}");
    assert!(fix.contains(NAME), "{fix}");
}

#[tokio::test]
async fn an_expired_leaf_with_a_pinned_clock_is_clock_or_expiry_and_not_interception() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Expired).await;

    // Inside the leaf's window the same chain is only trusted by this machine.
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    run.pin_clock(JUNE_2020);
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    assert_eq!(ran.host(0)["class"], "machine_only");

    // After notAfter it is a clock or expiry problem, in every verdict, whoever signed it.
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    run.pin_clock(JUNE_2022);
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.host(0)["class"], "clock_or_expiry");
    assert_eq!(ran.host(0)["os_store"], "expired");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("host.time_sync"), "{fix}");
    assert!(
        !ran.text().to_lowercase().contains("bypass inspection"),
        "{}",
        ran.text()
    );
}

#[tokio::test]
async fn a_certificate_not_valid_yet_is_clock_or_expiry() {
    let ca = TestCa::root("Acme Test Root");
    let web = server(&ca, NAME, Validity::NotYetValid).await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    assert_eq!(ran.host(0)["class"], "clock_or_expiry");
}

#[tokio::test]
async fn a_certificate_for_another_name_is_a_name_mismatch() {
    let ca = TestCa::root("Acme Test Root");
    let web = server(&ca, "other.acme.test", Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    assert_eq!(ran.host(0)["class"], "tls_name_mismatch");
    assert_eq!(ran.finding().level, Level::Fail);
}

#[tokio::test]
async fn an_empty_os_store_says_no_os_trust_store_found() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), Vec::new()));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    assert_eq!(ran.host(0)["class"], "no_trust_store");
    assert_eq!(ran.host(0)["os_store"], "no_store");
    assert_eq!(ran.host(0)["os_store_roots"], 0);
    assert_eq!(ran.finding().level, Level::Fail);
    assert!(
        ran.finding().message.contains("no OS trust store found"),
        "{}",
        ran.finding().message
    );
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("no OS trust store found")),
        "{:?}",
        ran.finding().notes
    );
}

#[tokio::test]
async fn a_host_that_cannot_be_reached_is_not_tested_and_is_never_a_pass() {
    // The fixture case `refused`: the name resolves to an address with nothing listening.
    let replay = Fixture::load(&fixtures_dir(), "checks/net.tls_intercept/refused")
        .expect("the fixture loads")
        .into_replay();
    let run = TestRun::new(replay);
    let ran = run_with(run, json!({"hosts": ["closed.acme.test"]})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn, "{}", finding.message);
    assert_eq!(ran.host(0)["class"], "not_tested");
    assert!(finding.partial.is_some());
    assert!(
        finding.message.contains("no host could be tested"),
        "{}",
        finding.message
    );
}

#[tokio::test]
async fn a_set_expected_issuer_or_pin_makes_the_result_partial_and_says_so() {
    let ca = TestCa::root("Acme Test Public Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), Vec::new()));
    run.trust_as_public(&der(&ca));
    let mut extra = hosts_of(NAME, &web);
    extra["expected_issuer"] = json!("^Acme");
    let ran = run_with(run, extra).await;
    let partial = ran.finding().partial.as_ref().expect("partial");
    assert!(partial.note.contains("expected_issuer"), "{}", partial.note);
    assert!(partial.note.contains("pin_sha256"), "{}", partial.note);
}

#[tokio::test]
async fn the_report_holds_no_certificate_text_or_key_material() {
    let ca = TestCa::root("Canary Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    let text = ran.text();
    assert!(!text.contains("Canary"), "{text}");
    assert!(!text.contains("BEGIN"), "{text}");
    assert!(!text.contains('\u{2014}'), "no em dash: {text}");
}

// ---- hosts --------------------------------------------------------------------------------------

#[test]
fn the_default_hosts_are_the_tls_endpoints_of_the_egress_entries_once_each() {
    let spec = spec_with(&[
        json!({"id": "net.egress", "endpoints": [
            "api.acme.test:443",
            "https://api.acme.test/v1/health",
            "plain.acme.test:8080",
            {"target": "tls.acme.test:8443", "tls": true},
            {"target": "off.acme.test:443", "tls": false},
            "[fd00::1]:443"
        ]}),
        json!({"id": "net.tls_intercept"}),
    ]);
    let (_, hosts, _) = built(&spec, 1);
    let names: Vec<String> = hosts
        .iter()
        .map(|t| format!("{}:{}", t.host(), t.port()))
        .collect();
    assert_eq!(
        names,
        ["api.acme.test:443", "tls.acme.test:8443", "[fd00::1]:443"]
    );
}

#[test]
fn listed_hosts_replace_the_defaults_and_are_capped() {
    let spec = spec_with(&[
        json!({"id": "net.egress", "endpoints": ["api.acme.test:443"]}),
        json!({"id": "net.tls_intercept", "hosts": ["only.acme.test"]}),
    ]);
    let (_, hosts, _) = built(&spec, 1);
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts.iter().next().expect("one").port(), 443);

    let many = |from: usize| -> Vec<String> {
        (from..from + 35)
            .map(|n| format!("h{n}.acme.test:443"))
            .collect()
    };
    let spec = spec_with(&[
        json!({"id": "net.egress", "endpoints": many(0)}),
        json!({"id": "net.egress", "endpoints": many(35)}),
        json!({"id": "net.tls_intercept"}),
    ]);
    let CheckParams::NetTlsIntercept(params) = spec.checks[2].decode_params() else {
        panic!("not net.tls_intercept");
    };
    let (hosts, dropped) = hosts_for(&params, &spec);
    assert_eq!((hosts.len(), dropped), (MAX_HOSTS, 70 - MAX_HOSTS));
}

#[tokio::test]
async fn without_the_network_the_check_ends_with_a_missing_need_and_opens_no_socket() {
    let run = TestRun::new(Replay::new()).offline();
    let spec = spec_with(&[entry(&json!({"hosts": ["web.acme.test"]}))]);
    let (check, hosts, _) = built(&spec, 0);
    let ctx = run.context_for_hosts(&INFO, "net.tls_intercept", Os::Linux, [], hosts);
    let outcome = check.run(&ctx).await;
    assert!(
        matches!(
            outcome,
            Err(rdy_engine::check::CheckError::MissingNeed(Need::Network))
        ),
        "{outcome:?}"
    );
}

/// The server notes a handshake a moment after the client has closed.
async fn settle(web: &HttpServer) {
    for _ in 0..3000 {
        if web.handshakes() >= 1 && !web.sni_seen().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the server never recorded the handshake");
}
