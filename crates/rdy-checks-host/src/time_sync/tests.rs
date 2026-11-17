//! Tests of `host.time_sync` against the synthetic machines under `tests/fixtures/checks/host.time_sync/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest, the peer policy and the action log are the ones a run has. The time server is a
//! scripted responder (`Replay::udp_server`) that builds its reply from the request it gets, so the echo
//! check is really exercised. The local clock is pinned, so the offsets are exact. Each case has an
//! `expect.json` with the spec entry, the reviewed result and the status the engine maps it to.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rdy_engine::check::{CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::family::HostSet;
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::probe::sock::{RULE_UDP_ADDRESS, RULE_UDP_HOST};
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::expect_bytes;
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, Replay, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{Action, ActionKind, ActionOutcome, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::sntp::Fixed;
use super::sntp::tests::{reply_to, wire_bytes};
use super::*;

macro_rules! expect {
    ($case:literal) => {
        (
            $case,
            include_str!(concat!(
                "../../../../tests/fixtures/checks/host.time_sync/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case, with its golden.
const CASES: &[(&str, &str)] = &[
    expect!("synced"),
    expect!("offset-400s"),
    expect!("recommended-skew-only"),
    expect!("warn-offset"),
    expect!("echo-mismatch"),
    expect!("silent-server"),
    expect!("refused-range"),
    expect!("refused-range-v6"),
    expect!("no-servers"),
    expect!("not-synced-required"),
    expect!("not-synced"),
    expect!("conflict"),
    expect!("systemd-219"),
    expect!("chrony-only"),
    expect!("chronyd-down"),
    expect!("no-sources"),
    expect!("named-server"),
    expect!("second-server"),
    expect!("hung-chronyc"),
    expect!("hung-timedatectl"),
    expect!("silent-server-and-hung-tools"),
    expect!("named-server-metadata"),
];

/// 2026-11-02 09:00:00 UTC, the pinned local clock.
const NOW_SECS: u64 = 1_793_005_200;

fn clock() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS)
}

fn now_fixed() -> Fixed {
    i128::from(NOW_SECS) << 32
}

/// What a scripted time server does.
#[derive(Clone, Copy)]
enum Server {
    /// A good reply with the server's clock this many seconds ahead of ours.
    Offset(f64),
    /// A reply whose origin timestamp is not the request's.
    BadEcho,
    /// Never answers.
    Silent,
}

/// The time servers a case runs against.
fn servers(case: &str) -> Vec<(&'static str, Server)> {
    match case {
        "synced" => vec![("192.0.2.10:123", Server::Offset(0.012))],
        "offset-400s" | "recommended-skew-only" => {
            vec![("192.0.2.10:123", Server::Offset(400.0))]
        }
        "warn-offset" => vec![("192.0.2.10:123", Server::Offset(-12.0))],
        "hung-timedatectl" => vec![("192.0.2.10:123", Server::Offset(400.0))],
        "silent-server-and-hung-tools" => vec![("192.0.2.10:123", Server::Silent)],
        "echo-mismatch" => vec![("192.0.2.10:123", Server::BadEcho)],
        "silent-server" => vec![("192.0.2.10:123", Server::Silent)],
        "named-server" => vec![("192.0.2.20:123", Server::Offset(0.5))],
        "second-server" => vec![("192.0.2.11:1123", Server::Offset(-0.25))],
        _ => Vec::new(),
    }
}

fn add_servers(replay: Replay, list: &[(&str, Server)]) -> Replay {
    let mut replay = replay;
    for (addr, server) in list {
        let addr: SocketAddr = addr.parse().expect("an address");
        replay = match *server {
            Server::Offset(seconds) => replay.udp_server(addr, move |sent| {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "a test offset of a few hundred seconds"
                )]
                let shift = (seconds * 4_294_967_296.0).round() as i128;
                reply_to(sent, now_fixed() + shift, 0b00_100_100, 2)
            }),
            Server::BadEcho => replay.udp_server(addr, |sent| {
                let mut bytes = reply_to(sent, now_fixed(), 0b00_100_100, 2);
                bytes[24] ^= 0xff;
                bytes
            }),
            Server::Silent => replay.udp_silent(addr),
        };
    }
    replay
}

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.time_sync/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture
        .ensure_answers("host.time_sync")
        .expect("it answers");
    fixture
}

fn time_sync(entry: &Value) -> TimeSync {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::HostTimeSync(params) => TimeSync::from_params(&params).with_clock(clock),
        other => panic!("not host.time_sync: {other:?}"),
    }
}

fn entry_of(case: &str) -> Value {
    let text = CASES
        .iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("{case} is not a listed case"))
        .1;
    let golden: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{case}: {e}"));
    golden["entry"].clone()
}

/// What a run produced.
struct Run {
    end: End,
    log: ActionLogOutput,
    hosts: HostSet,
}

impl Run {
    fn outcome(&self) -> &CheckOutcome {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        done
    }

    fn finding(&self) -> &Finding {
        self.outcome().as_ref().expect("a finding")
    }

    fn connects(&self) -> Vec<&Action> {
        self.log
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::Connect)
            .collect()
    }
}

/// Runs `check` on the machine of `fixture` with the scripted `list` of servers, through the scheduler
/// on a paused clock. `give_hosts` is false only in the test that proves a probe without hosts sends
/// nothing.
fn run_with(fixture: &Fixture, check: TimeSync, list: &[(&str, Server)], give_hosts: bool) -> Run {
    let replay = add_servers(fixture.replay().clone(), list);
    run_replay(fixture, check, replay, give_hosts)
}

/// Like `run_with`, with the replay already holding its servers.
fn run_replay(fixture: &Fixture, check: TimeSync, replay: Replay, give_hosts: bool) -> Run {
    run_replay_within(fixture, check, replay, give_hosts, None)
}

/// Like `run_replay`, with the spec's `timeout` for the check.
fn run_replay_within(
    fixture: &Fixture,
    check: TimeSync,
    replay: Replay,
    give_hosts: bool,
    timeout: Option<Duration>,
) -> Run {
    let test_run = TestRun::new(replay);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let hosts = HostSet::new(check.servers().iter().cloned());
    let mut planned = Planned::new(Arc::new(check), "host.time_sync");
    if give_hosts {
        planned = planned.with_hosts(hosts.clone());
    }
    if let Some(timeout) = timeout {
        planned = planned.with_timeout(timeout);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let mut ran = runtime.block_on(scheduler.run(vec![planned]));
    Run {
        end: ran.remove(0).end,
        log: test_run.action_log(),
        hosts,
    }
}

fn run_case(case: &str) -> Run {
    run_with(
        &load(case),
        time_sync(&entry_of(case)),
        &servers(case),
        true,
    )
}

/// The result as the engine maps it, for the status.
fn mapped(entry: &Value, outcome: CheckOutcome) -> rdy_spec::result::CheckResult {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    let test_run = TestRun::new(Replay::default());
    let ctx = test_run.context_for(&INFO, "host.time_sync", Os::Linux, Vec::<Need>::new());
    map_outcome(&INFO, &spec, &ctx, outcome, 0, 0)
}

#[test]
fn every_case_matches_its_golden() {
    for (case, _) in CASES {
        let entry = entry_of(case);
        let result = run_case(case);
        assert_golden(
            fixtures_dir().join(format!("checks/host.time_sync/{case}/expect.json")),
            expect_bytes(&entry, &result.end),
        );
    }
}

#[test]
fn the_case_list_has_no_repeat() {
    let mut names: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "a case is listed twice");
}

fn level_of(case: &str) -> Level {
    run_case(case).finding().level
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    assert_eq!(level_of("synced"), Level::Pass);
    assert_eq!(level_of("offset-400s"), Level::Fail);
    assert_eq!(level_of("recommended-skew-only"), Level::Fail);
    assert_eq!(level_of("warn-offset"), Level::Warn);
    assert_eq!(level_of("echo-mismatch"), Level::Warn);
    assert_eq!(level_of("silent-server"), Level::Warn);
    assert_eq!(level_of("refused-range"), Level::Pass);
    assert_eq!(level_of("refused-range-v6"), Level::Warn);
    assert_eq!(level_of("no-servers"), Level::Pass);
    assert_eq!(level_of("not-synced-required"), Level::Fail);
    assert_eq!(level_of("not-synced"), Level::Warn);
    assert_eq!(level_of("conflict"), Level::Warn);
    assert_eq!(level_of("systemd-219"), Level::Pass);
    assert_eq!(level_of("chrony-only"), Level::Pass);
    assert_eq!(level_of("chronyd-down"), Level::Pass);
    assert_eq!(level_of("no-sources"), Level::Warn);
    assert_eq!(level_of("named-server"), Level::Pass);
    assert_eq!(level_of("second-server"), Level::Pass);
    assert_eq!(level_of("hung-chronyc"), Level::Pass);
    assert_eq!(level_of("hung-timedatectl"), Level::Fail);
    assert_eq!(level_of("silent-server-and-hung-tools"), Level::Warn);
    assert_eq!(level_of("named-server-metadata"), Level::Pass);
}

fn status_of(case: &str) -> Status {
    let run = run_case(case);
    mapped(&entry_of(case), run.outcome().clone()).status
}

#[test]
fn the_engine_maps_the_levels_to_block_warn_and_pass() {
    assert_eq!(status_of("offset-400s"), Status::Block);
    assert_eq!(status_of("hung-timedatectl"), Status::Block);
    assert_eq!(status_of("silent-server-and-hung-tools"), Status::Warn);
    assert_eq!(status_of("recommended-skew-only"), Status::Block);
    assert_eq!(status_of("not-synced-required"), Status::Block);
    assert_eq!(status_of("warn-offset"), Status::Warn);
    assert_eq!(status_of("echo-mismatch"), Status::Warn);
    assert_eq!(status_of("synced"), Status::Pass);
    assert_eq!(status_of("no-servers"), Status::Pass);
}

#[test]
fn a_400_second_offset_blocks_at_the_default_level() {
    let run = run_case("offset-400s");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "Clock is 6 min 40 s behind `192.0.2.10`, over the 5 min limit."
    );
    assert_eq!(finding.observed["offset_seconds"], json!(400.0));
    assert_eq!(finding.observed["offset_source"], "sntp");
    assert_eq!(finding.expected["max_skew_seconds"], json!(300.0));
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("timedatectl set-ntp true"), "{fix}");
    assert!(fix.contains("chronyc makestep"), "{fix}");
    assert!(fix.contains("6 min 40 s"), "{fix}");
}

#[test]
fn recommended_skew_alone_does_not_move_the_block_level() {
    // PR #108 review: recommended_skew 600s with no max_skew still blocks at the 300 s default.
    let run = run_case("recommended-skew-only");
    assert_eq!(run.finding().level, Level::Fail);
    assert_eq!(run.finding().expected["max_skew_seconds"], json!(300.0));
    assert_eq!(
        run.finding().expected["recommended_skew_seconds"],
        json!(300.0)
    );
}

#[test]
fn an_offset_at_exactly_the_limit_does_not_block() {
    let fixture = load("offset-400s");
    let entry = json!({"id": "host.time_sync", "max_skew": "400s", "ntp_servers": ["192.0.2.10"]});
    let run = run_with(
        &fixture,
        time_sync(&entry),
        &[("192.0.2.10:123", Server::Offset(400.0))],
        true,
    );
    assert_eq!(run.finding().level, Level::Warn);
    let entry = json!({"id": "host.time_sync", "max_skew": "399s", "ntp_servers": ["192.0.2.10"]});
    let run = run_with(
        &fixture,
        time_sync(&entry),
        &[("192.0.2.10:123", Server::Offset(400.0))],
        true,
    );
    assert_eq!(run.finding().level, Level::Fail);
}

#[test]
fn a_reply_that_fails_the_echo_check_is_rejected_and_never_used() {
    let run = run_case("echo-mismatch");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(finding.observed["offset_seconds"], Value::Null);
    assert_eq!(finding.observed["servers"][0]["result"], "rejected");
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("did not echo the request")),
        "{:?}",
        finding.notes
    );
    assert!(finding.partial.is_some());
}

#[test]
fn a_server_in_a_refused_range_is_not_queried_and_chronyc_gives_the_offset() {
    let run = run_case("refused-range");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.observed["offset_source"], "chronyc");
    assert_eq!(finding.observed["servers"][0]["result"], "refused_range");
    assert_eq!(
        finding.observed["servers"][0]["detail"],
        "offset not measured, server in a refused range"
    );
    assert!(
        finding.notes.iter().any(|n| n
            == "`169.254.169.123`: offset not measured, server in a refused range. Using the offset from chronyc instead."),
        "{:?}",
        finding.notes
    );
    // The facade refused the address, so nothing left the machine.
    let connects = run.connects();
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0].outcome, ActionOutcome::Denied);
    assert_eq!(
        connects[0].fields.get("rule").and_then(Value::as_str),
        Some(RULE_UDP_ADDRESS)
    );
}

#[test]
fn the_ipv6_metadata_address_is_refused_the_same_way() {
    let run = run_case("refused-range-v6");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(
        finding.message,
        "Offset not measured, server in a refused range."
    );
    assert!(finding.partial.is_some());
    let connects = run.connects();
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0].outcome, ActionOutcome::Denied);
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("ntp_servers")),
        "{:?}",
        finding.fix
    );
}

#[test]
fn with_no_servers_the_offset_is_not_measured_and_no_datagram_is_sent() {
    let run = run_case("no-servers");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding.message.contains("Offset not measured"),
        "{}",
        finding.message
    );
    assert!(run.hosts.is_empty());
    assert!(run.connects().is_empty());
}

#[test]
fn the_host_set_is_the_ntp_servers_and_nothing_else() {
    let entry = json!({"id": "host.time_sync", "ntp_servers": ["time.acme.example", "192.0.2.10:1123", "[fd00::1]"]});
    let check = time_sync(&entry);
    let shown: Vec<String> = check
        .servers()
        .iter()
        .map(|t| format!("{}:{}", t.host(), t.port()))
        .collect();
    assert_eq!(
        shown,
        ["time.acme.example:123", "192.0.2.10:1123", "[fd00::1]:123"]
    );
    let none = time_sync(&json!({"id": "host.time_sync", "max_skew": "2s"}));
    assert!(none.servers().is_empty());
}

#[test]
fn a_probe_without_the_hosts_refuses_every_datagram() {
    // INV-11: the servers reach the probe only through Built::hosts. Without them the facade refuses.
    let fixture = load("synced");
    let run = run_with(
        &fixture,
        time_sync(&entry_of("synced")),
        &servers("synced"),
        false,
    );
    let error = run
        .outcome()
        .as_ref()
        .expect_err("the policy refusal ends the check");
    assert!(error.to_string().contains(RULE_UDP_HOST), "{error}");
    let connects = run.connects();
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0].outcome, ActionOutcome::Denied);
}

#[test]
fn a_silent_server_is_a_warning_inside_the_check_timeout() {
    let run = run_case("silent-server");
    assert_eq!(run.finding().level, Level::Warn);
    assert_eq!(run.finding().observed["servers"][0]["result"], "silent");
}

#[test]
fn servers_are_asked_in_spec_order_and_the_first_good_one_is_used() {
    let run = run_case("second-server");
    let finding = run.finding();
    assert_eq!(finding.observed["servers"][0]["result"], "failed");
    assert_eq!(finding.observed["servers"][1]["result"], "ok");
    assert_eq!(finding.observed["reference"], "192.0.2.11:1123");
    assert_eq!(finding.observed["offset_seconds"], json!(-0.25));
}

#[test]
fn systemd_219_falls_back_to_timedatectl_status() {
    let run = run_case("systemd-219");
    let execs: Vec<&str> = run
        .log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Exec)
        .filter_map(|a| a.fields.get("program").and_then(Value::as_str))
        .collect();
    assert_eq!(execs.iter().filter(|p| **p == "timedatectl").count(), 2);
    assert_eq!(run.finding().observed["state"], "synchronized");
}

#[test]
fn a_hung_tool_never_turns_the_check_into_a_timeout() {
    // Correction-37: each command form has 3 s and is cut to the budget left, so the check answers
    // before the engine's 5 s timer, and the SNTP verdict is kept.
    let run = run_case("hung-chronyc");
    assert_eq!(run.finding().level, Level::Pass);
    assert!(
        run.finding()
            .notes
            .iter()
            .any(|n| n == "chronyc gave no answer: it timed out."),
        "{:?}",
        run.finding().notes
    );

    let run = run_case("hung-timedatectl");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail, "the 400 s offset still blocks");
    assert_eq!(finding.observed["offset_seconds"], json!(400.0));
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n == "timedatectl gave no answer: it timed out."),
        "{:?}",
        finding.notes
    );
    // `status` is not tried after a `show` that timed out.
    let td = run
        .log
        .actions
        .iter()
        .filter(|a| a.fields.get("program").and_then(Value::as_str) == Some("timedatectl"))
        .count();
    assert_eq!(td, 1);
    assert_eq!(
        mapped(&entry_of("hung-timedatectl"), run.outcome().clone()).status,
        Status::Block
    );
}

#[test]
fn a_silent_server_and_two_hung_tools_still_answer_and_chronyc_is_not_run() {
    let run = run_case("silent-server-and-hung-tools");
    assert!(matches!(run.end, End::Done(_)), "{:?}", run.end);
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n == "timedatectl gave no answer: it timed out."),
        "{:?}",
        finding.notes
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.starts_with("chronyc gave no answer: it was not run")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_step_the_budget_cannot_hold_is_not_started() {
    // A 3.3 s check limit: timedatectl takes its 3 s, 0.3 s is left, less the 250 ms margin is under
    // the 100 ms minimum, so chronyc is not run. The check still answers.
    let fixture = load("silent-server-and-hung-tools");
    let replay = add_servers(
        fixture.replay().clone(),
        &servers("silent-server-and-hung-tools"),
    );
    let check = time_sync(&entry_of("silent-server-and-hung-tools"));
    let run = run_replay_within(
        &fixture,
        check,
        replay,
        true,
        Some(Duration::from_millis(3300)),
    );
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.starts_with("chronyc gave no answer: it was not run")),
        "{:?}",
        finding.notes
    );
    let chronyc_runs = run
        .log
        .actions
        .iter()
        .filter(|a| a.fields.get("program").and_then(Value::as_str) == Some("chronyc"))
        .count();
    assert_eq!(chronyc_runs, 0);
}

#[test]
fn later_servers_are_not_measured_once_one_answers() {
    let fixture = load("synced");
    let second = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&second);
    let replay = add_servers(
        fixture.replay().clone(),
        &[("192.0.2.10:123", Server::Offset(0.5))],
    )
    .udp_server("192.0.2.12:123".parse().expect("an address"), move |sent| {
        seen.fetch_add(1, Ordering::SeqCst);
        reply_to(sent, now_fixed(), 0b00_100_100, 2)
    });
    let entry = json!({"id": "host.time_sync", "ntp_servers": ["192.0.2.10", "192.0.2.12"]});
    let run = run_replay(&fixture, time_sync(&entry), replay, true);
    let finding = run.finding();
    assert_eq!(finding.observed["servers"][0]["result"], "ok");
    assert_eq!(finding.observed["servers"][1]["result"], "not_measured");
    assert_eq!(second.load(Ordering::SeqCst), 0);
    assert_eq!(run.connects().len(), 1);
}

#[test]
fn two_requests_never_carry_the_same_transmit_timestamp() {
    assert_ne!(nonce(1), nonce(1));
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        assert!(seen.insert(nonce(now_fixed())));
    }
}

#[test]
fn a_refused_address_gets_no_packet_even_with_a_listening_server() {
    // A responder sits on the refused address. It must see nothing: the facade refuses first.
    for (case, addr, name) in [
        ("refused-range", "169.254.169.123:123", "literal v4"),
        ("refused-range-v6", "[fd00:ec2::123]:123", "literal v6"),
        (
            "named-server-metadata",
            "169.254.169.123:123",
            "a name that resolves there",
        ),
    ] {
        let fixture = load(case);
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        let replay =
            fixture
                .replay()
                .clone()
                .udp_server(addr.parse().expect("an address"), move |sent| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    reply_to(sent, now_fixed(), 0b00_100_100, 2)
                });
        let run = run_replay(&fixture, time_sync(&entry_of(case)), replay, true);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "{name}");
        let connects = run.connects();
        assert_eq!(connects.len(), 1, "{name}");
        assert_eq!(connects[0].outcome, ActionOutcome::Denied, "{name}");
        assert_eq!(
            run.finding().observed["servers"][0]["result"],
            "refused_range",
            "{name}"
        );
    }
}

#[test]
fn a_run_stays_inside_the_manifest() {
    for (case, _) in CASES {
        let run = run_case(case);
        for action in &run.log.actions {
            assert!(
                matches!(action.kind, ActionKind::Exec | ActionKind::Connect),
                "{case}: {:?}",
                action.kind
            );
            if action.outcome == ActionOutcome::Denied {
                // Two refusals are expected: a program that is not installed, and a time server in
                // a refused range. Nothing else may be refused.
                let rule = action
                    .fields
                    .get("rule")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let missing_program =
                    action.kind == ActionKind::Exec && rule.contains("was not found");
                let refused_range = action.kind == ActionKind::Connect && rule == RULE_UDP_ADDRESS;
                assert!(missing_program || refused_range, "{case}: {action:?}");
            }
        }
        assert_within_manifest(case, &INFO, &run.log);
    }
    assert!(INFO.reads.is_empty() && INFO.statfs.is_empty() && INFO.env.is_empty());
    assert_eq!(INFO.peers, [PeerClass::NtpServers]);
    assert!(INFO.wants.is_empty() && INFO.needs.is_empty());
}

#[test]
fn an_address_the_wire_helper_writes_round_trips() {
    // A guard on the test helper: 1970-01-01 is NTP second 2208988800.
    assert_eq!(wire_bytes(0)[..4], 2_208_988_800_u32.to_be_bytes());
}
