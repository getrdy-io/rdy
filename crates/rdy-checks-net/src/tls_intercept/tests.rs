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
use rdy_engine::probe::{
    NativeCall, NativeValue, NoRoots, StoreKind, StoreOrigin, StoreSource, SystemRoots,
};
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
                let fix = class.fix(os, "web.acme.test", 443, forbid, None);
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
        .fix(Os::Linux, "web.acme.test", 443, false, None)
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
    let check = TlsInterceptCheck::new(&params, hosts, dropped).expect("the entry builds");
    (check, set, entry)
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
async fn an_overridden_or_unreadable_store_gets_its_own_words_and_fix() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let replay = machine(NAME, web.addr(), Vec::new()).system_roots_overridden();
    let ran = run_with(TestRun::new(replay), hosts_of(NAME, &web)).await;
    assert_eq!(ran.host(0)["class"], "no_trust_store");
    assert_eq!(ran.host(0)["os_store"], "store_overridden");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("Unset SSL_CERT_FILE"), "{fix}");
    assert!(!fix.contains("ca-certificates"), "{fix}");
    assert!(
        ran.finding().message.contains("SSL_CERT_FILE"),
        "{}",
        ran.finding().message
    );
}

#[test]
fn the_no_trust_store_words_follow_the_reason() {
    for (why, phrase, fix) in [
        (None, "no OS trust store found", "ca-certificates"),
        (
            Some(NoRoots::Empty),
            "no OS trust store found",
            "ca-certificates",
        ),
        (Some(NoRoots::Unreadable), "could not be read", "can read"),
        (
            Some(NoRoots::Overridden),
            "SSL_CERT_FILE",
            "Unset SSL_CERT_FILE",
        ),
    ] {
        assert!(Class::NoTrustStore.phrase(why).contains(phrase), "{why:?}");
        let text = Class::NoTrustStore
            .fix(Os::Linux, "web.acme.test", 443, false, why)
            .expect("a fix");
        assert!(text.contains(fix), "{why:?}: {text}");
        rdy_engine::fixtext::check(&text).expect("passes the audit");
    }
}

#[test]
fn the_openssl_hint_has_no_brackets_in_the_servername_and_none_for_an_address() {
    let name = Class::Untrusted
        .fix(Os::Linux, "web.acme.test", 443, false, None)
        .expect("a fix");
    assert!(
        name.contains("-connect web.acme.test:443 -servername web.acme.test`"),
        "{name}"
    );
    let v6 = Class::Untrusted
        .fix(Os::Linux, "[fd00::1]", 443, false, None)
        .expect("a fix");
    assert!(v6.contains("-connect [fd00::1]:443`"), "{v6}");
    assert!(!v6.contains("-servername"), "{v6}");
    let v4 = Class::Untrusted
        .fix(Os::Linux, "192.0.2.7", 443, false, None)
        .expect("a fix");
    assert!(!v4.contains("-servername"), "{v4}");
}

#[tokio::test]
async fn no_host_to_test_is_a_warning_and_not_a_pass() {
    let run = TestRun::new(Replay::new());
    let spec = spec_with(&[json!({"id": "net.tls_intercept"})]);
    let (check, hosts, entry) = built(&spec, 0);
    assert!(hosts.is_empty());
    let ctx = run.context_for_hosts(
        &INFO,
        "net.tls_intercept",
        Os::Linux,
        [Need::Network],
        hosts,
    );
    let outcome = check.run(&ctx).await;
    let finding = outcome.as_ref().expect("a finding");
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("`hosts`"), "{}", finding.message);
    let result = map_outcome(&INFO, &entry, &ctx, outcome, 0, 0);
    assert_eq!(result.status, Status::Warn);
}

#[tokio::test(start_paused = true)]
async fn a_host_that_runs_past_its_budget_is_not_tested_with_a_reason() {
    use rdy_engine::sched::{End, Planned};
    // The lookup alone takes longer than the 10 s host budget.
    let replay = Replay::new()
        .host("slow.acme.test", ["192.0.2.5".parse().expect("ip")])
        .lookup_delay("slow.acme.test", Duration::from_secs(30));
    let spec = spec_with(&[entry(&json!({"hosts": ["slow.acme.test"]}))]);
    let (check, hosts, _) = built(&spec, 0);
    let run = TestRun::new(replay);
    let scheduler = run.scheduler(1, Os::Linux, [Need::Network]);
    let check: std::sync::Arc<dyn Check> = std::sync::Arc::new(check);
    let mut ran = scheduler
        .run(vec![
            Planned::new(check, "net.tls_intercept").with_hosts(hosts),
        ])
        .await;
    let End::Done(outcome) = ran.remove(0).end else {
        panic!("the check did not finish");
    };
    let finding = (*outcome).expect("a finding and not a timeout");
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.observed["hosts"][0]["class"], "not_tested");
    assert_eq!(
        finding.observed["hosts"][0]["reason"],
        "a step ran out of time"
    );
    assert!(finding.partial.is_some());
}

#[tokio::test]
async fn the_report_holds_no_certificate_text_or_key_material() {
    let ca = TestCa::root("Canary Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    let text = ran.text();
    // The issuer is evidence (M1-100). PEM text, key material and the DER bytes are never in the report.
    assert!(text.contains("Canary Inspection Root"), "{text}");
    assert!(!text.contains("BEGIN"), "{text}");
    assert!(!text.contains("PRIVATE"), "{text}");
    assert!(!text.contains("MII"), "{text}");
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

// ---- evidence (M1-100) --------------------------------------------------------------------------

/// A server whose chain is leaf, issuing CA (the root is not sent), and the root CA.
async fn deep(root_cn: &str, issuing_cn: &str) -> (TestCa, TestCa, HttpServer) {
    let root = TestCa::root(root_cn);
    let issuing = root.intermediate(issuing_cn);
    let options = HttpOptions::tls(&issuing.issue(&[NAME], Validity::Always)).alpn(&["http/1.1"]);
    let web = HttpServer::start(options).await.expect("a server");
    (root, issuing, web)
}

fn hex_of(der: &[u8]) -> String {
    rdy_engine::probe::net::TrustStore::hex(&rdy_engine::probe::net::TrustStore::hash(der))
}

#[tokio::test]
async fn the_result_names_the_issuer_the_depth_and_the_hash_of_the_last_certificate() {
    let (root, issuing, web) = deep("Acme Test Root CA", "Acme Test Issuing CA").await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&root)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    let host = ran.host(0);
    assert_eq!(host["class"], "machine_only");
    assert_eq!(host["chain_depth"], 2);
    assert_eq!(host["issuer"], "CN=Acme Test Issuing CA");
    assert_eq!(host["subject"], format!("CN={NAME}"));
    assert_eq!(host["last_sha256"], hex_of(issuing.der().as_ref()));
    // The server did not send the root, so there is no root hash and no answer about the OS store.
    assert_eq!(host["root_sha256"], Value::Null);
    assert_eq!(host["root_in_os_store"], Value::Null);
    assert!(
        ran.finding()
            .message
            .contains("issuer CN=Acme Test Issuing CA"),
        "{}",
        ran.finding().message
    );
}

#[test]
fn a_root_the_server_sends_is_read_as_self_signed() {
    // The leaf is signed by a root, and the server sends the root too.
    let root = TestCa::root("Acme Sent Root");
    let leaf = root.issue(&[NAME], Validity::Always);
    let mut chain: Vec<Vec<u8>> = leaf.chain().iter().map(|c| c.as_ref().to_vec()).collect();
    chain.push(der(&root));
    let evidence = evidence::ChainEvidence::of(&chain);
    assert_eq!(evidence.root_sha256, Some(hex_of(&der(&root))));
    assert_eq!(evidence.last_sha256, evidence.root_sha256);
    assert!(evidence.root_hash.is_some());
    assert_eq!(evidence.issuer.as_deref(), Some("CN=Acme Sent Root"));
    assert_eq!(evidence.hashes.len(), 2);
}

#[test]
fn a_chain_that_is_not_a_certificate_reads_as_no_issuer_and_still_hashes() {
    let evidence = evidence::ChainEvidence::of(&[vec![1, 2, 3]]);
    assert_eq!(evidence.issuer, None);
    assert_eq!(evidence.subject, None);
    assert_eq!(evidence.root_sha256, None);
    assert_eq!(evidence.last_sha256, Some(hex_of(&[1, 2, 3])));
    assert_eq!(evidence.hashes, [hex_of(&[1, 2, 3])]);
    let none = evidence::ChainEvidence::of(&[]);
    assert_eq!(none.root_sha256, None);
    assert!(
        !none.issuer_matches(&|_| true),
        "an unread issuer never matches"
    );
}

#[tokio::test]
async fn a_hostile_issuer_name_is_cleaned_before_it_reaches_the_report() {
    let evil = "Evil\u{1b}[2J\u{202e}`CA\u{7}\u{61c}\u{2028}\u{e0041}";
    let ca = TestCa::root(evil);
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    let issuer = ran.host(0)["issuer"]
        .as_str()
        .expect("an issuer")
        .to_owned();
    assert_eq!(issuer, "CN=Evil[2JCA");
    // The names reach the message and the observed object. The fix holds backticks of its own, so only
    // those two are judged.
    let text = format!("{} {}", ran.finding().message, ran.finding().observed);
    assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}') && !text.contains('`'));
    let long = TestCa::root(&"x".repeat(400));
    let shown = evidence::ChainEvidence::of(&[der(&long)]).shown_issuer();
    assert_eq!(
        shown.map(|s| s.chars().count()),
        Some(evidence::SHOWN_CHARS)
    );
}

// ---- the trust store report ---------------------------------------------------------------------

fn store_machine(
    name: &str,
    server: SocketAddr,
    certs: Vec<Vec<u8>>,
    sources: Vec<StoreSource>,
) -> Replay {
    Replay::new()
        .host(name, ["127.0.0.1".parse().expect("ip")])
        .tcp(server, TcpScript::Serve("tls".to_owned()))
        .serve_tcp("tls", server)
        .native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(SystemRoots::new(certs, sources)),
        )
}

#[tokio::test]
async fn the_store_location_is_the_bundle_file_on_linux_and_a_fixed_name_elsewhere() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    for (kind, location, shown) in [
        (
            StoreKind::Bundle,
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/certs/ca-certificates.crt",
        ),
        (StoreKind::OsStore, "System keychain", "System keychain"),
        (
            StoreKind::OsStore,
            "Windows Root store",
            "Windows Root store",
        ),
    ] {
        let replay = store_machine(
            NAME,
            web.addr(),
            vec![der(&ca)],
            vec![StoreSource::new(kind, location)],
        );
        let ran = run_with(TestRun::new(replay), hosts_of(NAME, &web)).await;
        let store = &ran.finding().observed["trust_store"];
        assert_eq!(store["status"], "found");
        assert_eq!(store["roots"], 1);
        assert_eq!(store["sources"][0]["location"], shown);
        assert!(store["sources"][0].get("from").is_none(), "{store}");
    }
}

#[tokio::test]
async fn an_empty_store_says_no_os_trust_store_found_and_lists_no_source() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), Vec::new()));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    let store = &ran.finding().observed["trust_store"];
    assert_eq!(store["status"], "missing");
    assert_eq!(store["reason"], "no OS trust store found");
    assert_eq!(store["sources"], json!([]));
    assert_eq!(ran.host(0)["root_in_os_store"], Value::Null);
}

/// The canary user name no report may hold.
const CANARY: &str = "canary-user-7f3a";

#[tokio::test]
async fn a_store_named_by_an_environment_variable_shows_the_variable_and_no_user_name() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let file = format!("/home/{CANARY}/certs/ca\u{1b}[31m.pem");
    let dir = format!("/data/homes/{CANARY}/trust");
    let sources = vec![
        StoreSource::new(StoreKind::Bundle, file).origin(StoreOrigin::Env("SSL_CERT_FILE")),
        StoreSource::new(StoreKind::Directory, dir).origin(StoreOrigin::Env("SSL_CERT_DIR")),
        StoreSource::new(StoreKind::Bundle, "/etc/ssl/certs/ca-certificates.crt"),
    ];
    // HOME names the second place, which no usual home pattern covers.
    let replay = store_machine(NAME, web.addr(), vec![der(&ca)], sources)
        .env("HOME", &format!("/data/homes/{CANARY}"));
    let ran = run_with(TestRun::new(replay), hosts_of(NAME, &web)).await;
    let store = &ran.finding().observed["trust_store"];
    assert_eq!(
        store["sources"][0],
        json!({"kind": "bundle", "from": "SSL_CERT_FILE", "location": "~/certs/ca[31m.pem"})
    );
    assert_eq!(
        store["sources"][1],
        json!({"kind": "directory", "from": "SSL_CERT_DIR", "location": "~/trust"})
    );
    assert_eq!(
        store["sources"][2],
        json!({"kind": "bundle", "location": "/etc/ssl/certs/ca-certificates.crt"})
    );
    let text = ran.text();
    assert!(
        !text.contains(CANARY),
        "the canary user name leaked: {text}"
    );
    assert!(!text.contains('\u{1b}'), "{text}");
    // The two variables are read to collapse the path, and the log holds the names and never the values.
    assert!(!format!("{:?}", ran.run.action_log()).contains(CANARY));
}

#[test]
fn a_variable_path_collapses_the_home_directory_in_every_usual_form() {
    for (path, homes, shown) in [
        ("/home/alice/ca.pem", vec![], "~/ca.pem"),
        ("/HOME/alice/ca.pem", vec![], "~/ca.pem"),
        ("/Users/alice/Library/ca.pem", vec![], "~/Library/ca.pem"),
        ("/root/ca.pem", vec![], "~/ca.pem"),
        ("/root", vec![], "~"),
        ("C:\\Users\\alice\\ca.pem", vec![], "~\\ca.pem"),
        ("c:/users/alice/ca.pem", vec![], "~/ca.pem"),
        ("/srv/trust/ca.pem", vec![], "/srv/trust/ca.pem"),
        ("/data/u/alice/ca.pem", vec!["/data/u/alice/"], "~/ca.pem"),
        ("/data/u/alice", vec!["/data/u/alice"], "~"),
        // A longer name that starts with the home value is another directory.
        (
            "/data/u/alicia/ca.pem",
            vec!["/data/u/ali"],
            "/data/u/alicia/ca.pem",
        ),
        // Controls are removed first, so a split name cannot hide from the match.
        ("/ho\u{0}me/alice\u{7}/ca.pem", vec![], "~/ca.pem"),
        ("/a\u{202e}b", vec![], "/ab"),
        ("", vec![], ""),
    ] {
        let homes: Vec<String> = homes.into_iter().map(str::to_owned).collect();
        assert_eq!(evidence::show_env_path(path, &homes), shown, "{path:?}");
    }
    let long = format!("/srv/{}", "d".repeat(500));
    assert_eq!(
        evidence::show_env_path(&long, &[]).chars().count(),
        evidence::SHOWN_CHARS
    );
}

#[tokio::test]
async fn at_most_eight_sources_are_listed_and_the_rest_are_counted() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let sources: Vec<StoreSource> = (0..11)
        .map(|n| StoreSource::new(StoreKind::Bundle, format!("/etc/ssl/b{n}.pem")))
        .collect();
    let replay = store_machine(NAME, web.addr(), vec![der(&ca)], sources);
    let ran = run_with(TestRun::new(replay), hosts_of(NAME, &web)).await;
    let store = &ran.finding().observed["trust_store"];
    assert_eq!(store["sources"].as_array().map(Vec::len), Some(8));
    assert_eq!(store["more_sources"], 3);
}

#[tokio::test]
async fn an_overridden_store_is_missing_and_the_report_names_the_variables() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let replay = machine(NAME, web.addr(), Vec::new()).system_roots_overridden();
    let ran = run_with(TestRun::new(replay), hosts_of(NAME, &web)).await;
    let store = &ran.finding().observed["trust_store"];
    assert_eq!(store["status"], "missing");
    assert!(
        store["reason"]
            .as_str()
            .is_some_and(|r| r.contains("SSL_CERT_FILE")),
        "{store}"
    );
}

#[tokio::test]
async fn a_run_that_reached_no_host_reports_no_store_and_asks_for_none() {
    let replay = Fixture::load(&fixtures_dir(), "checks/net.tls_intercept/refused")
        .expect("the fixture loads")
        .into_replay();
    let ran = run_with(TestRun::new(replay), json!({"hosts": ["closed.acme.test"]})).await;
    assert!(ran.finding().observed.get("trust_store").is_none());
}

// ---- the fix text -------------------------------------------------------------------------------

#[test]
fn the_linux_fix_carries_the_debian_rhel_suse_alpine_and_java_forms() {
    for class in [Class::MachineOnly, Class::UnknownCa] {
        let fix = class
            .fix(Os::Linux, "web.acme.test", 443, false, None)
            .expect("a fix");
        for form in [
            "Debian and Ubuntu: copy the CA to `/usr/local/share/ca-certificates/acme-inspection.crt`",
            "`update-ca-certificates`",
            "RHEL: copy it to `/etc/pki/ca-trust/source/anchors/`, then run `update-ca-trust`",
            "SUSE: copy it to `/usr/share/pki/trust/anchors/`",
            "Alpine: copy it to `/usr/local/share/ca-certificates/`",
            "Java: `keytool -importcert -cacerts -alias acme-inspection -file ca.crt`",
            "Container images and Java do not read the host store.",
        ] {
            assert!(fix.contains(form), "{class:?}: {form}\n{fix}");
        }
    }
    for os in [Os::Macos, Os::Windows] {
        let fix = Class::UnknownCa
            .fix(os, "web.acme.test", 443, false, None)
            .expect("a fix");
        assert!(
            fix.contains("keytool -importcert -cacerts"),
            "{os:?}: {fix}"
        );
        assert!(!fix.contains("RHEL"), "{os:?}: {fix}");
    }
    let empty = Class::NoTrustStore
        .fix(Os::Linux, "web.acme.test", 443, false, None)
        .expect("a fix");
    for form in [
        "apt-get install ca-certificates",
        "dnf install ca-certificates",
        "zypper install ca-certificates",
        "apk add ca-certificates",
    ] {
        assert!(empty.contains(form), "{form}\n{empty}");
    }
    for text in [
        class::issuer_fix("web.acme.test"),
        class::pin_fix("web.acme.test"),
    ] {
        rdy_engine::fixtext::check(&text).expect("passes the audit");
        assert!(!text.contains('\u{2014}'), "{text}");
    }
}

// ---- expected_issuer and pin_sha256 -------------------------------------------------------------

/// A public chain (leaf and issuing CA under a root the run trusts as public), ready to run.
async fn public_chain() -> (TestCa, TestCa, HttpServer, TestRun) {
    let (root, issuing, web) = deep("Acme Test Root CA", "Acme Test Issuing CA").await;
    let run = TestRun::new(machine(NAME, web.addr(), Vec::new()));
    run.trust_as_public(&der(&root));
    (root, issuing, web, run)
}

#[tokio::test]
async fn an_issuer_that_does_not_match_expected_issuer_blocks_with_its_own_fix() {
    let (_root, _issuing, web, run) = public_chain().await;
    let mut extra = hosts_of(NAME, &web);
    extra["expected_issuer"] = json!("^CN=Acme Corp CA$");
    let ran = run_with(run, extra).await;
    let finding = ran.finding();
    // The chain is public, and still blocks: the issuer is not the one the vendor expects.
    assert_eq!(ran.host(0)["class"], "public");
    assert_eq!(ran.host(0)["expected_issuer_matches"], false);
    assert_eq!(finding.level, Level::Fail, "{}", finding.message);
    assert_eq!(ran.result().status, Status::Block);
    assert!(
        finding
            .message
            .contains("issuer does not match expected_issuer"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("`expected_issuer`") && fix.contains(NAME),
        "{fix}"
    );
    assert!(finding.partial.is_none(), "{:?}", finding.partial);
    assert_eq!(finding.expected["expected_issuer"], "^CN=Acme Corp CA$");
}

#[tokio::test]
async fn an_issuer_that_matches_expected_issuer_passes_the_rule() {
    let (_root, _issuing, web, run) = public_chain().await;
    let mut extra = hosts_of(NAME, &web);
    extra["expected_issuer"] = json!("Acme Test Issuing CA");
    let ran = run_with(run, extra).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    assert_eq!(ran.host(0)["expected_issuer_matches"], true);
    assert!(
        finding.message.contains("the issuer matches"),
        "{}",
        finding.message
    );
    assert!(finding.partial.is_none());
    assert_eq!(ran.result().status, Status::Pass);
}

#[tokio::test]
async fn the_issuer_of_the_leaf_is_what_expected_issuer_reads_and_not_the_root() {
    let (_root, _issuing, web, run) = public_chain().await;
    let mut extra = hosts_of(NAME, &web);
    // The root is not the issuer of the leaf.
    extra["expected_issuer"] = json!("Acme Test Root CA");
    let ran = run_with(run, extra).await;
    assert_eq!(ran.host(0)["expected_issuer_matches"], false);
    assert_eq!(ran.finding().level, Level::Fail);
}

#[tokio::test]
async fn a_pin_that_does_not_match_the_leaf_blocks() {
    let (_root, _issuing, web, run) = public_chain().await;
    let mut extra = hosts_of(NAME, &web);
    extra["pin_sha256"] = json!([format!("{:0>64}", "ab")]);
    let ran = run_with(run, extra).await;
    let finding = ran.finding();
    assert_eq!(ran.host(0)["pin_sha256_matches"], "none");
    assert_eq!(finding.level, Level::Fail, "{}", finding.message);
    assert_eq!(ran.result().status, Status::Block);
    assert!(
        finding
            .message
            .contains("the leaf does not match pin_sha256"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("`pin_sha256`")),
        "{:?}",
        finding.fix
    );
    assert!(finding.partial.is_none());
}

#[tokio::test]
async fn a_pin_on_any_certificate_of_the_chain_passes_the_rule() {
    let root = TestCa::root("Acme Test Root CA");
    let issuing = root.intermediate("Acme Test Issuing CA");
    let leaf = issuing.issue(&[NAME], Validity::Always);
    let leaf_hash = hex_of(leaf.chain()[0].as_ref());
    let web = HttpServer::start(HttpOptions::tls(&leaf).alpn(&["http/1.1"]))
        .await
        .expect("a server");
    let other = format!("{:0>64}", "cd");
    // The leaf alone, and the leaf after a wrong pin.
    for pins in [
        vec![leaf_hash.clone()],
        vec![other.clone(), leaf_hash.clone()],
    ] {
        let run = TestRun::new(machine(NAME, web.addr(), Vec::new()));
        run.trust_as_public(&der(&root));
        let mut extra = hosts_of(NAME, &web);
        extra["pin_sha256"] = json!(pins);
        let ran = run_with(run, extra).await;
        assert_eq!(ran.host(0)["pin_sha256_matches"], "leaf", "{pins:?}");
        assert_eq!(
            ran.finding().level,
            Level::Pass,
            "{}",
            ran.finding().message
        );
        assert!(
            ran.finding().message.contains("the pin matches"),
            "{}",
            ran.finding().message
        );
        assert!(ran.finding().partial.is_none());
    }
}

#[tokio::test]
async fn a_pin_on_a_ca_certificate_is_a_partial_result_and_never_a_pass() {
    let (_root, issuing, web, run) = public_chain().await;
    let mut extra = hosts_of(NAME, &web);
    extra["pin_sha256"] = json!([hex_of(issuing.der().as_ref())]);
    let ran = run_with(run, extra).await;
    let finding = ran.finding();
    assert_eq!(ran.host(0)["pin_sha256_matches"], "ca_only");
    assert_eq!(finding.level, Level::Warn, "{}", finding.message);
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial
            .note
            .contains("pin_sha256 matches a CA certificate the server sent; rdy cannot yet prove it is in the verified path"),
        "{}",
        partial.note
    );
    assert!(finding.fix.as_deref().is_some_and(|f| f.contains("leaf")));
    assert_eq!(ran.result().status, Status::Warn);
}

#[tokio::test]
async fn a_forged_chain_with_the_real_leaf_appended_does_not_meet_the_pin() {
    // The attacker's CA is trusted (a public root, or one this machine installed), the attacker's leaf
    // comes first, and the real server's leaf is appended after it. Only the first certificate is bound
    // to the server by the handshake, so the appended one must not satisfy the pin.
    let real_root = TestCa::root("Acme Real Root");
    let real_leaf = real_root.issue(&[NAME], Validity::Always);
    let real_der = real_leaf.chain()[0].as_ref().to_vec();
    let attacker = TestCa::root("Attacker Root");
    let forged = attacker
        .issue(&[NAME], Validity::Always)
        .append(real_der.clone());
    let web = HttpServer::start(HttpOptions::tls(&forged).alpn(&["http/1.1"]))
        .await
        .expect("a server");
    let run = TestRun::new(machine(NAME, web.addr(), Vec::new()));
    run.trust_as_public(&der(&attacker));
    let mut extra = hosts_of(NAME, &web);
    extra["pin_sha256"] = json!([hex_of(&real_der)]);
    let ran = run_with(run, extra).await;
    let finding = ran.finding();
    // The appended certificate is a leaf, not a CA, so the pin is a miss and the host blocks.
    assert_eq!(ran.host(0)["pin_sha256_matches"], "none");
    assert_eq!(finding.level, Level::Fail, "{}", finding.message);
    assert_eq!(ran.result().status, Status::Block);
    // The pin of the attacker's own leaf is the only way to meet it, and the vendor never has that.
    assert_eq!(ran.host(0)["chain_depth"], 2);
}

/// A server that sends a leaf from `issuing` and then `later`, run with a pin on `later`.
async fn pin_on_appended(issuing: &TestCa, root: &TestCa, later: Vec<u8>) -> String {
    let leaf = issuing.issue(&[NAME], Validity::Always);
    let pinned = hex_of(&later);
    let web = HttpServer::start(HttpOptions::tls(&leaf.append(later)).alpn(&["http/1.1"]))
        .await
        .expect("a server");
    let run = TestRun::new(machine(NAME, web.addr(), Vec::new()));
    run.trust_as_public(&der(root));
    let mut extra = hosts_of(NAME, &web);
    extra["pin_sha256"] = json!([pinned]);
    let ran = run_with(run, extra).await;
    ran.host(0)["pin_sha256_matches"]
        .as_str()
        .expect("a pin state")
        .to_owned()
}

#[tokio::test]
async fn a_pinned_later_certificate_counts_only_when_it_is_a_readable_single_ca() {
    let root = TestCa::root("Acme Test Root CA");
    let issuing = root.intermediate("Acme Test Issuing CA");
    // A CA certificate with one basicConstraints extension: partial.
    let ca = root.intermediate("Acme Other Issuing CA");
    assert_eq!(
        pin_on_appended(&issuing, &root, ca.der().as_ref().to_vec()).await,
        "ca_only"
    );
    // The same CA with the extension twice: basic_constraints errors, so it is a miss.
    let twice = root.intermediate_with_duplicate_basic_constraints("Acme Twice CA");
    {
        use x509_parser::prelude::{FromDer, X509Certificate};
        let bytes = twice.der().as_ref().to_vec();
        let (_, cert) = X509Certificate::from_der(&bytes).expect("parses");
        let count = cert
            .extensions()
            .iter()
            .filter(|e| e.oid.to_id_string() == "2.5.29.19")
            .count();
        assert_eq!(count, 2, "the rig must write the extension twice");
    }
    assert_eq!(
        pin_on_appended(&issuing, &root, twice.der().as_ref().to_vec()).await,
        "none"
    );
    // A leaf (no CA), bytes that are not a certificate, and a certificate over 16 KiB are misses.
    let other_leaf = root.issue(&["other.acme.test"], Validity::Always);
    assert_eq!(
        pin_on_appended(&issuing, &root, other_leaf.chain()[0].as_ref().to_vec()).await,
        "none"
    );
    assert_eq!(
        pin_on_appended(&issuing, &root, b"not a certificate".to_vec()).await,
        "none"
    );
    let mut big = ca.der().as_ref().to_vec();
    big.resize(rdy_engine::probe::MAX_ROOT_BYTES + 1, 0);
    assert_eq!(pin_on_appended(&issuing, &root, big).await, "none");
}

#[test]
fn an_unreadable_leaf_says_so_when_expected_issuer_is_not_met() {
    let rules = Rules {
        issuer: Some(IssuerRule {
            pattern: "x".to_owned(),
            matches: Box::new(|_| true),
        }),
        pins: Vec::new(),
    };
    let certs = vec![b"not a certificate".to_vec()];
    let evidence = ChainEvidence::of(&certs);
    let issuer_ok = rules
        .issuer
        .as_ref()
        .map(|r| evidence.issuer_matches(&*r.matches));
    let tested = Tested {
        label: "web.acme.test:443".to_owned(),
        host: "web.acme.test".to_owned(),
        port: 443,
        what: What::Chain {
            class: Class::Public,
            seen: Box::new(Seen {
                depth: 1,
                bundled: "valid",
                system: "valid",
                system_roots: 1,
                protocol: None,
                no_roots: None,
                evidence,
                issuer_ok,
                pin: None,
            }),
        },
        in_store: None,
    };
    let verdict = Verdict::of(&tested).expect("a chain");
    assert_eq!(verdict.level(false), Level::Fail);
    let reasons = verdict.reasons();
    assert_eq!(
        reasons,
        ["issuer could not be read, so expected_issuer is not met"]
    );
}

#[tokio::test]
async fn the_pin_of_the_root_does_not_count_when_the_server_did_not_send_it() {
    let (root, _issuing, web, run) = public_chain().await;
    let mut extra = hosts_of(NAME, &web);
    extra["pin_sha256"] = json!([hex_of(root.root_der().as_ref())]);
    let ran = run_with(run, extra).await;
    assert_eq!(ran.host(0)["pin_sha256_matches"], "none");
    assert_eq!(ran.finding().level, Level::Fail);
}

#[tokio::test]
async fn both_rules_block_on_either_miss_and_a_matching_chain_still_warns_for_its_class() {
    let root = TestCa::root("Acme Test Root CA");
    let issuing = root.intermediate("Acme Test Issuing CA");
    let leaf = issuing.issue(&[NAME], Validity::Always);
    let leaf_hex = hex_of(leaf.chain()[0].as_ref());
    let web = HttpServer::start(HttpOptions::tls(&leaf).alpn(&["http/1.1"]))
        .await
        .expect("a server");
    // Machine-only chain, issuer and pin both right: the class still warns, and no rule fails.
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&root)]));
    let mut extra = hosts_of(NAME, &web);
    extra["expected_issuer"] = json!("Acme Test Issuing CA");
    extra["pin_sha256"] = json!([leaf_hex]);
    let ran = run_with(run, extra.clone()).await;
    assert_eq!(
        ran.finding().level,
        Level::Warn,
        "{}",
        ran.finding().message
    );
    assert_eq!(ran.host(0)["expected_issuer_matches"], true);
    assert_eq!(ran.host(0)["pin_sha256_matches"], "leaf");
    // A wrong pin turns the same chain into a block, with both fixes in one text.
    extra["pin_sha256"] = json!([format!("{:0>64}", "ee")]);
    extra["expected_issuer"] = json!("Nobody");
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&root)]));
    let ran = run_with(run, extra).await;
    assert_eq!(ran.finding().level, Level::Fail);
    let message = &ran.finding().message;
    assert!(
        message.contains("trusted by this machine only")
            && message.contains("expected_issuer")
            && message.contains("pin_sha256"),
        "{message}"
    );
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(
        fix.contains("update-ca-trust") && fix.contains("`expected_issuer`"),
        "{fix}"
    );
}

#[tokio::test]
async fn a_host_that_was_not_tested_is_never_read_as_meeting_a_rule() {
    let replay = Fixture::load(&fixtures_dir(), "checks/net.tls_intercept/refused")
        .expect("the fixture loads")
        .into_replay();
    let ran = run_with(
        TestRun::new(replay),
        json!({"hosts": ["closed.acme.test"], "pin_sha256": [format!("{:0>64}", "ab")], "expected_issuer": "x"}),
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn);
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial
            .note
            .contains("expected_issuer and pin_sha256 were not checked"),
        "{}",
        partial.note
    );
    assert!(ran.host(0).get("pin_sha256_matches").is_none());
}

#[test]
fn an_unreadable_leaf_cannot_meet_expected_issuer() {
    // A server that sends bytes that are not a certificate cannot be built, so the evidence is proven
    // on the type: an unread issuer is a miss, and the pin still reads the DER.
    let certs = vec![b"not a certificate".to_vec()];
    let evidence = evidence::ChainEvidence::of(&certs);
    assert!(!evidence.issuer_matches(&|_| true));
    assert_eq!(
        evidence.pin_state(&certs, &[hex_of(b"not a certificate")]),
        evidence::PinState::Leaf
    );
}

#[test]
fn an_expected_issuer_that_does_not_compile_is_refused_at_build() {
    let spec = spec_with(&[entry(
        &json!({"hosts": ["web.acme.test"], "expected_issuer": "(abc"}),
    )]);
    let CheckParams::NetTlsIntercept(params) = spec.checks[0].decode_params() else {
        panic!("not net.tls_intercept");
    };
    let (hosts, dropped) = hosts_for(&params, &spec);
    let error = TlsInterceptCheck::new(&params, hosts, dropped).expect_err("does not compile");
    assert!(!error.is_empty() && !error.contains('\n'), "{error}");
}

#[tokio::test(start_paused = true)]
async fn a_host_whose_step_never_completes_is_bounded_and_named_as_timed_out() {
    use rdy_engine::sched::{End, Planned};
    let replay = Replay::new()
        .host("slow.acme.test", ["192.0.2.5".parse().expect("ip")])
        .lookup_delay("slow.acme.test", Duration::from_secs(3600));
    let spec = spec_with(&[entry(&json!({"hosts": ["slow.acme.test"]}))]);
    let (check, hosts, _) = built(&spec, 0);
    let run = TestRun::new(replay);
    let scheduler = run.scheduler(1, Os::Linux, [Need::Network]);
    let check: std::sync::Arc<dyn Check> = std::sync::Arc::new(check);
    let mut ran = scheduler
        .run(vec![
            Planned::new(check, "net.tls_intercept").with_hosts(hosts),
        ])
        .await;
    let End::Done(outcome) = ran.remove(0).end else {
        panic!("the check did not finish");
    };
    let finding = (*outcome).expect("a finding and not a timeout");
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("1 of 1 hosts timed out: slow.acme.test:443")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_store_that_could_not_be_asked_is_reported_as_not_read() {
    let shown = evidence::store_json(&Err(ProbeError::Timeout), &[]);
    assert_eq!(shown["status"], "not_read");
    assert!(shown.get("sources").is_none());
}

#[test]
fn a_home_value_cannot_turn_another_users_home_into_a_tilde_path() {
    // `HOME=/home` is odd, and the usual places go first, so the user name still goes.
    let homes = vec!["/home".to_owned()];
    assert_eq!(
        evidence::show_env_path("/home/alice/ca.pem", &homes),
        "~/ca.pem"
    );
    // A place the usual rules do not know falls to the HOME value.
    let homes = vec!["/srv/alice".to_owned()];
    assert_eq!(
        evidence::show_env_path("/srv/alice/ca.pem", &homes),
        "~/ca.pem"
    );
    // Under sudo with HOME=/root another user's home still collapses by the usual rule, and a name
    // outside a home place is the documented residual.
    let homes = vec!["/root".to_owned()];
    assert_eq!(
        evidence::show_env_path("/Users/bob/ca.pem", &homes),
        "~/ca.pem"
    );
    assert_eq!(
        evidence::show_env_path("/srv/carol/ca.pem", &homes),
        "/srv/carol/ca.pem"
    );
}

#[tokio::test]
async fn home_is_read_only_when_a_source_came_from_a_variable() {
    let ca = TestCa::root("Acme Inspection Root");
    let web = server(&ca, NAME, Validity::Always).await;
    let standard = vec![StoreSource::new(
        StoreKind::Bundle,
        "/etc/ssl/certs/ca-certificates.crt",
    )];
    let replay = store_machine(NAME, web.addr(), vec![der(&ca)], standard).env("HOME", "/home/x");
    let ran = run_with(TestRun::new(replay), hosts_of(NAME, &web)).await;
    assert!(
        !format!("{:?}", ran.run.action_log()).contains("HOME"),
        "HOME was read with no variable source"
    );
    let named = vec![
        StoreSource::new(StoreKind::Bundle, "/opt/ca.pem")
            .origin(StoreOrigin::Env("SSL_CERT_FILE")),
    ];
    let replay = store_machine(NAME, web.addr(), vec![der(&ca)], named).env("HOME", "/home/x");
    let ran = run_with(TestRun::new(replay), hosts_of(NAME, &web)).await;
    assert!(format!("{:?}", ran.run.action_log()).contains("HOME"));
    assert_eq!(INFO.env, ["HOME"]);
}

#[tokio::test]
async fn an_issuer_with_several_parts_is_written_in_certificate_order() {
    let ca = TestCa::root_with_parts("Acme Issuing CA", "Acme Corp", "US");
    let web = server(&ca, NAME, Validity::Always).await;
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, hosts_of(NAME, &web)).await;
    assert_eq!(
        ran.host(0)["issuer"],
        "C=US, O=Acme Corp, CN=Acme Issuing CA"
    );
    // The anchored form that suits one name part does not match the whole text.
    let mut extra = hosts_of(NAME, &web);
    extra["expected_issuer"] = json!("^CN=Acme Issuing CA$");
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, extra).await;
    assert_eq!(ran.host(0)["expected_issuer_matches"], false);
    // A pattern that names the part it means does.
    let mut extra = hosts_of(NAME, &web);
    extra["expected_issuer"] = json!("O=Acme Corp, CN=Acme Issuing CA$");
    let run = TestRun::new(machine(NAME, web.addr(), vec![der(&ca)]));
    let ran = run_with(run, extra).await;
    assert_eq!(ran.host(0)["expected_issuer_matches"], true);
}

#[test]
fn a_huge_certificate_or_issuer_is_never_read_or_matched() {
    assert!(evidence::names_of(&vec![0x30; rdy_engine::probe::MAX_ROOT_BYTES + 1]).is_none());
    let long = TestCa::root(&"y".repeat(1100));
    let evidence = evidence::ChainEvidence::of(&[der(&long)]);
    // The issuer is over 1024 characters: no prefix is matched, even by a pattern that would match it.
    assert!(!evidence.issuer_matches(&|_| true));
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    #[test]
    fn evidence_never_panics_on_arbitrary_chains(
        certs in proptest::collection::vec(
            proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300),
            0..40
        )
    ) {
        let evidence = evidence::ChainEvidence::of(&certs);
        let _ = evidence.pin_state(&certs, &[hex_of(b"x")]);
        let _ = evidence.pin_state(&certs, &evidence.hashes);
        let _ = evidence.issuer_matches(&|s| s.contains('a'));
        let _ = evidence.shown_issuer();
    }

    #[test]
    fn path_and_name_cleaning_never_panic_on_arbitrary_text(
        text in ".{0,300}",
        home in ".{0,40}",
        max in 0_usize..300
    ) {
        let shown = evidence::show_env_path(&text, &[home]);
        proptest::prop_assert!(shown.chars().count() <= evidence::SHOWN_CHARS.max(3));
        let cleaned = evidence::clean(&text, max);
        proptest::prop_assert!(!cleaned.contains('`') && !cleaned.chars().any(char::is_control));
        proptest::prop_assert!(!cleaned.chars().any(rdy_engine::text::is_invisible));
    }
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_opens_the_connection_and_never_answers_the_hello_is_bounded_and_named() {
    // Fully in memory: the peer holds its end of the pipe and never reads or writes, so a paused clock
    // cannot race a real connect.
    let replay = Replay::new()
        .host(NAME, ["192.0.2.7".parse().expect("ip")])
        .tcp(
            "192.0.2.7:443".parse().expect("addr"),
            TcpScript::Serve("silent".to_owned()),
        )
        .serve_duplex("silent", |stream| async move {
            let _held = stream;
            std::future::pending::<()>().await;
        })
        .native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(Vec::new().into()),
        );
    let ran = run_with(TestRun::new(replay), json!({"hosts": [NAME]})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Warn, "{}", finding.message);
    assert_eq!(ran.host(0)["class"], "not_tested");
    assert_eq!(ran.host(0)["reason"], "a step ran out of time");
    assert!(
        finding.notes.iter().any(|n| n.contains("timed out")),
        "{:?}",
        finding.notes
    );
    assert!(finding.partial.is_some());
}
