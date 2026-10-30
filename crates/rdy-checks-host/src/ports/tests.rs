//! Tests of `host.ports` against the synthetic machines under `tests/fixtures/checks/host.ports/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the read policy (including the fd walk rule of ADR 0040) and the action log are the ones a run
//! has. Each case has an `expect.json` with the spec entry and the reviewed result. The goldens are
//! compiled in with `include_str!` only to read the spec entry. `assert_golden` compares the bytes, and
//! `UPDATE_GOLDENS=1` rewrites the file for review.

use std::sync::Arc;

use rdy_engine::check::{Finding, Level, Need};
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

macro_rules! expect {
    ($case:literal) => {
        (
            $case,
            include_str!(concat!(
                "../../../../tests/fixtures/checks/host.ports/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case, with its golden.
const CASES: &[(&str, &str)] = &[
    expect!("free"),
    expect!("held-by-named-process"),
    expect!("held-no-root"),
    expect!("own-process-no-root"),
    expect!("udp-listener"),
    expect!("dual-stack"),
    expect!("loopback-only"),
    expect!("bind-loopback"),
    expect!("ephemeral-overlap"),
    expect!("allowed-owner-cut-comm"),
    expect!("comm-cut-not-cmdline"),
    expect!("container-view"),
    expect!("owner-elsewhere"),
    expect!("no-ipv6"),
    expect!("table-unreadable"),
];

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.ports/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture.ensure_answers("host.ports").expect("it answers");
    fixture
}

fn ports(entry: &Value) -> Ports {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::HostPorts(params) => Ports::from_params(&params),
        other => panic!("not host.ports: {other:?}"),
    }
}

fn entry_of(case: &str) -> Value {
    let text = CASES
        .iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("no case {case}"))
        .1;
    let golden: Value = serde_json::from_str(text).expect("json");
    golden["entry"].clone()
}

/// What a run produced.
struct Run {
    end: End,
    log: ActionLogOutput,
}

impl Run {
    fn finding(&self) -> &Finding {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        done.as_ref().as_ref().expect("a finding")
    }

    /// The paths of the calls of one kind, in order.
    fn paths(&self, kind: ActionKind) -> Vec<String> {
        self.log
            .actions
            .iter()
            .filter(|a| a.kind == kind)
            .filter_map(|a| a.fields.get("path").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
    }

    fn all_paths(&self) -> Vec<String> {
        self.log
            .actions
            .iter()
            .filter_map(|a| a.fields.get("path").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
    }
}

/// Runs `check` on the machine of `fixture` through the scheduler, on a paused clock.
fn run(fixture: &Fixture, check: Ports) -> Run {
    let test_run = TestRun::for_fixture(fixture);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let planned = Planned::new(Arc::new(check), "host.ports");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let mut ran = runtime.block_on(scheduler.run(vec![planned]));
    Run {
        end: ran.remove(0).end,
        log: test_run.action_log(),
    }
}

fn run_case(case: &str) -> Run {
    run(&load(case), ports(&entry_of(case)))
}

fn level_word(level: Level) -> &'static str {
    match level {
        Level::Pass => "pass",
        Level::Warn => "warn",
        Level::Fail => "fail",
    }
}

/// The result as the goldens hold it.
fn render(end: &End) -> Value {
    match end {
        End::TimedOut { after } => json!({ "timed_out_ms": after.as_millis() }),
        End::Done(done) => match done.as_ref() {
            Ok(finding) => json!({
                "level": level_word(finding.level),
                "message": finding.message,
                "observed": finding.observed,
                "expected": finding.expected,
                "fix": finding.fix,
                "notes": finding.notes,
                "partial": finding.partial.as_ref().map(|p| json!({
                    "missing": p.missing.iter().map(|n| format!("{n:?}")).collect::<Vec<_>>(),
                    "note": p.note,
                })),
            }),
            Err(error) => json!({ "error": error.to_string() }),
        },
        other => panic!("unexpected end: {other:?}"),
    }
}

/// The value with every object's keys in order. The goldens have sorted keys, and a build where another
/// crate turns on serde_json's `preserve_order` would otherwise write them in insertion order.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

#[test]
fn every_case_matches_its_golden() {
    for (case, _) in CASES {
        let entry = entry_of(case);
        let result = run(&load(case), ports(&entry));
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        let mut bytes = serde_json::to_string_pretty(&sorted(actual)).expect("json");
        bytes.push('\n');
        assert_golden(
            fixtures_dir().join(format!("checks/host.ports/{case}/expect.json")),
            bytes,
        );
    }
}

#[test]
fn the_case_list_has_no_repeat() {
    // This does not look at the directory: the test crate may not list it. A case directory without a
    // row is not caught here.
    let names: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "a case is listed twice");
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    for (case, level) in [
        ("free", Level::Pass),
        ("held-by-named-process", Level::Fail),
        ("held-no-root", Level::Fail),
        ("own-process-no-root", Level::Fail),
        ("udp-listener", Level::Fail),
        ("dual-stack", Level::Fail),
        ("loopback-only", Level::Warn),
        ("bind-loopback", Level::Pass),
        ("ephemeral-overlap", Level::Warn),
        ("allowed-owner-cut-comm", Level::Pass),
        ("comm-cut-not-cmdline", Level::Fail),
        ("container-view", Level::Warn),
        ("owner-elsewhere", Level::Fail),
        ("no-ipv6", Level::Pass),
        ("table-unreadable", Level::Warn),
    ] {
        assert_eq!(run_case(case).finding().level, level, "{case}");
    }
}

#[test]
fn a_named_process_holding_6443_blocks_and_the_fix_names_the_service() {
    let ran = run_case("held-by-named-process");
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message
            .contains("Port 6443/tcp is held by `kube-apiserver` (pid 812)."),
        "{}",
        f.message
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("`systemctl stop kube-apiserver.service`"),
        "{fix}"
    );
    assert_eq!(f.observed["tcp"][1]["state"], "free");
    assert_eq!(f.observed["tcp"][0]["holders"][0]["owner"]["pid"], 812);
    assert!(f.partial.is_none());
}

#[test]
fn the_walk_stops_at_the_first_match_and_lists_only_the_pids_it_needs() {
    let ran = run_case("held-by-named-process");
    // Pids 1, 640 and 812 come first and 812 holds the socket. 2000 and 2001 are never listed.
    assert_eq!(
        ran.paths(ActionKind::ReadDir),
        ["/proc", "/proc/1/fd", "/proc/640/fd", "/proc/812/fd"]
    );
    let links: Vec<String> = ran
        .paths(ActionKind::ReadLink)
        .into_iter()
        .filter(|p| p != "/proc/self/ns/net")
        .collect();
    assert_eq!(links.last().map(String::as_str), Some("/proc/812/fd/7"));
    assert!(
        !links
            .iter()
            .any(|p| p.contains("/2000/") || p.contains("/2001/"))
    );
    // The refused links (files and pipes) are logged without their targets.
    let json = serde_json::to_string(&ran.log.actions).expect("json");
    assert!(
        !json.contains("/dev/null") && !json.contains("pipe:["),
        "{json}"
    );
}

#[test]
fn a_free_port_costs_no_walk() {
    let ran = run_case("free");
    assert!(
        ran.paths(ActionKind::ReadDir).is_empty(),
        "{:?}",
        ran.paths(ActionKind::ReadDir)
    );
    assert!(
        ran.paths(ActionKind::ReadLink)
            .iter()
            .all(|p| p == "/proc/self/ns/net")
    );
    let f = ran.finding();
    assert_eq!(
        f.message,
        "80/tcp, 443/tcp, 6443/tcp, 10250/tcp and 8472/udp are free."
    );
    // The client connection with local port 443 is not a listener.
    assert_eq!(f.observed["tcp"][1]["state"], "free");
    assert_eq!(f.observed["netns"], "net:[4026531992]");
    assert!(f.fix.is_none() && f.partial.is_none());
}

#[test]
fn without_root_a_port_of_another_user_is_in_use_with_the_owner_unknown() {
    let ran = run_case("held-no-root");
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message.contains("Port 6443/tcp is in use on 0.0.0.0."),
        "{}",
        f.message
    );
    assert!(
        f.message
            .contains("belongs to another user and rdy is not root"),
        "{}",
        f.message
    );
    let partial = f.partial.as_ref().expect("partial");
    assert_eq!(partial.missing, [Need::Root]);
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("Run rdy as root"), "{fix}");
    assert!(fix.contains("`ss -ltnp 'sport = :6443'`"), "{fix}");
    // No process directory was searched: the answer was known from the socket's owner.
    assert_eq!(ran.paths(ActionKind::ReadDir), Vec::<String>::new());
    assert_eq!(f.observed["tcp"][0]["holders"][0]["owner"], Value::Null);
}

#[test]
fn without_root_the_users_own_process_is_still_found() {
    let ran = run_case("own-process-no-root");
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message.contains("held by `python3` (pid 3100)"),
        "{}",
        f.message
    );
    assert!(f.partial.is_none(), "{:?}", f.partial);
    // The other users' fd directories were tried and refused: that is not a gap, the socket was found.
    assert_eq!(ran.paths(ActionKind::ReadDir)[0], "/proc");
}

#[test]
fn a_udp_listener_is_found() {
    let ran = run_case("udp-listener");
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message
            .contains("Port 5353/udp is held by `avahi-daemon` (pid 702)."),
        "{}",
        f.message
    );
    assert_eq!(f.observed["udp"][0]["state"], "in_use");
    assert_eq!(f.observed["udp"][1]["state"], "free");
}

#[test]
fn a_listener_on_the_ipv6_wildcard_covers_ipv4() {
    let ran = run_case("dual-stack");
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message
            .contains("Port 6443/tcp is held by `etcd` (pid 950)."),
        "{}",
        f.message
    );
    assert_eq!(f.observed["tcp"][0]["holders"][0]["address"], "[::]");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("[::]") && n.contains("IPv4")),
        "{:?}",
        f.notes
    );
}

#[test]
fn a_loopback_only_holder_of_a_public_port_is_a_warning() {
    let f = run_case("loopback-only").finding().clone();
    assert!(
        f.message
            .contains("held on 127.0.0.1 by `envoy` (pid 1200)"),
        "{}",
        f.message
    );
    assert!(f.message.contains("binds every address"), "{}", f.message);
}

#[test]
fn a_product_that_binds_loopback_does_not_conflict_with_another_address() {
    let f = run_case("bind-loopback").finding().clone();
    assert_eq!(f.observed["tcp"][0]["bind"], "loopback");
    assert_eq!(f.observed["tcp"][0]["state"], "free");
}

#[test]
fn the_ephemeral_overlap_names_ip_local_reserved_ports_and_keeps_the_reserved_ones() {
    let f = run_case("ephemeral-overlap").finding().clone();
    assert!(
        f.message
            .contains("32800/tcp is inside the ephemeral port range 32768-60999"),
        "{}",
        f.message
    );
    assert!(
        !f.message.contains("40000/udp"),
        "40000 is reserved: {}",
        f.message
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains(
            "echo 'net.ipv4.ip_local_reserved_ports = 8000-8010,32800,40000' | sudo tee /etc/sysctl.d/90-reserved-ports.conf && sudo sysctl --system"
        ),
        "{fix}"
    );
    assert_eq!(f.observed["tcp"][1]["ephemeral"], true);
    assert_eq!(f.observed["tcp"][0]["ephemeral"], false);
    assert_eq!(f.observed["udp"][0]["ephemeral"], false);
}

#[test]
fn an_allowed_owner_matches_the_name_the_kernel_cut_to_15_bytes() {
    let f = run_case("allowed-owner-cut-comm").finding().clone();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(f.observed["tcp"][0]["holders"][0]["allowed"], true);
    assert_eq!(
        f.observed["tcp"][0]["holders"][0]["owner"]["name"],
        "acme-controller"
    );
    assert!(
        f.message.contains("held by a process the spec allows"),
        "{}",
        f.message
    );
    // The same machine with no allow list blocks.
    let blocked = run(
        &load("allowed-owner-cut-comm"),
        ports(&json!({"id": "host.ports", "free": [6443]})),
    );
    assert_eq!(blocked.finding().level, Level::Fail);
    // A name that only shares a prefix does not match.
    let other = run(
        &load("allowed-owner-cut-comm"),
        ports(&json!({"id": "host.ports", "free": [6443], "allow_owner": ["acme"]})),
    );
    assert_eq!(other.finding().level, Level::Fail);
}

#[test]
fn an_unknown_owner_with_an_allow_list_is_a_warning_not_a_block() {
    let ran = run(
        &load("held-no-root"),
        ports(&json!({"id": "host.ports", "free": [6443], "allow_owner": ["kube-apiserver"]})),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert!(f.message.contains("may be one of them"), "{}", f.message);
    assert!(f.partial.is_some());
}

#[test]
fn the_name_is_comm_and_cmdline_is_never_read() {
    let ran = run_case("comm-cut-not-cmdline");
    let f = ran.finding();
    assert_eq!(
        f.observed["tcp"][0]["holders"][0]["owner"]["name"],
        "kube-controller"
    );
    assert!(
        ran.all_paths().iter().all(|p| !p.ends_with("/cmdline")),
        "{:?}",
        ran.all_paths()
    );
    let everything = format!(
        "{}{}",
        render(&ran.end),
        serde_json::to_string(&ran.log.actions).expect("json")
    );
    assert!(!everything.contains("REDACTED-TEST-TOKEN"), "{everything}");
}

#[test]
fn a_container_marker_warns_that_the_view_is_the_containers() {
    let f = run_case("container-view").finding().clone();
    assert_eq!(f.level, Level::Warn);
    assert!(
        f.message
            .contains("running in a container (/.dockerenv exists)"),
        "{}",
        f.message
    );
    assert_eq!(f.observed["netns"], "net:[4026532600]");
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("hostNetwork: true"), "{fix}");
}

#[test]
fn a_socket_no_visible_process_holds_is_unknown_even_as_root() {
    let f = run_case("owner-elsewhere").finding().clone();
    assert_eq!(f.level, Level::Fail);
    assert!(f.message.contains("another PID namespace"), "{}", f.message);
    let partial = f.partial.as_ref().expect("partial");
    assert!(partial.missing.is_empty(), "root is not what is missing");
}

#[test]
fn a_missing_ipv6_table_is_a_note_and_a_missing_ipv4_table_is_not_proof() {
    let f = run_case("no-ipv6").finding().clone();
    assert_eq!(f.level, Level::Pass);
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("/proc/net/tcp6 is absent")),
        "{:?}",
        f.notes
    );
    let f = run_case("table-unreadable").finding().clone();
    assert_eq!(f.level, Level::Warn);
    assert!(
        f.message
            .contains("could not confirm that 6443/tcp is free"),
        "{}",
        f.message
    );
    assert!(
        f.message
            .contains("/proc/net/tcp could not be read (permission denied)"),
        "{}",
        f.message
    );
    assert!(f.partial.is_some());
}

#[test]
fn a_run_stays_inside_the_manifest() {
    for (case, _) in CASES {
        let result = run_case(case);
        assert!(matches!(result.end, End::Done(_)), "{case}");
        for action in &result.log.actions {
            assert!(
                matches!(
                    action.kind,
                    ActionKind::Read
                        | ActionKind::ReadDir
                        | ActionKind::ReadLink
                        | ActionKind::Stat
                        | ActionKind::Env
                ),
                "{case}: {:?}",
                action.kind
            );
            // Only the refusal of a link that is not a socket is expected.
            if action.outcome == ActionOutcome::Denied {
                assert_eq!(action.kind, ActionKind::ReadLink, "{case}: {action:?}");
                assert_eq!(
                    action.fields.get("rule").and_then(Value::as_str),
                    Some(owner::FD_TARGET_RULE),
                    "{case}"
                );
            }
        }
        assert_within_manifest(case, &INFO, &result.log);
    }
    assert_eq!(
        INFO.reads,
        ["/proc", FD_WALK, "/.dockerenv", "/run/.containerenv"]
    );
    assert!(INFO.commands.is_empty() && INFO.peers.is_empty() && INFO.statfs.is_empty());
    assert_eq!(INFO.env, ["KUBERNETES_SERVICE_HOST"]);
}

#[test]
fn the_facade_still_says_the_rule_the_walk_matches() {
    // The walk tells a refused non-socket link from a policy bug by this text. If the facade changes it,
    // this fails here and not as a silent "owner unknown" on a customer's machine.
    let ran = run_case("held-by-named-process");
    let refused: Vec<&Action> = ran
        .log
        .actions
        .iter()
        .filter(|a| a.outcome == ActionOutcome::Denied)
        .collect();
    assert!(!refused.is_empty());
    for action in refused {
        assert_eq!(
            action.fields.get("rule").and_then(Value::as_str),
            Some(owner::FD_TARGET_RULE)
        );
    }
}

#[test]
fn the_other_os_is_not_yet() {
    let fixture = load("free");
    let test_run = TestRun::for_fixture(&fixture);
    let ctx = test_run.context_for(
        &INFO,
        "host.ports",
        rdy_engine::check::Os::Macos,
        Vec::<Need>::new(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(ports(&entry_of("free")).run(&ctx));
    assert!(
        matches!(outcome, Err(CheckError::Unsupported(_))),
        "{outcome:?}"
    );
}
