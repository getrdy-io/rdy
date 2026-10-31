//! Tests of `net.mtu` against the synthetic machines under `tests/fixtures/checks/net.mtu/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest (`reads`) and the action log are the ones a run has. Each case has an
//! `expect.json` with the spec entry and the reviewed result. The test crate may not read files, so the
//! goldens are compiled in with `include_str!` to read the spec entry. `assert_golden` compares the
//! bytes: a mismatch fails with a diff, and `UPDATE_GOLDENS=1` rewrites the file for review.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckError, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

macro_rules! expect {
    ($case:literal) => {
        (
            $case,
            include_str!(concat!(
                "../../../../tests/fixtures/checks/net.mtu/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case, with its golden.
const CASES: &[(&str, &str)] = &[
    expect!("pass-1500"),
    expect!("ec2-jumbo"),
    expect!("jumbo-geneve"),
    expect!("vxlan-room-exact"),
    expect!("vxlan-too-tight"),
    expect!("small-1280"),
    expect!("below-min-no-overlay"),
    expect!("wireguard-ipv6-underlay"),
    expect!("no-default-route"),
    expect!("tunnel-default"),
    expect!("kube-node"),
    expect!("unreadable-mtu"),
    expect!("garbage-mtu"),
    expect!("two-default-routes"),
    expect!("geneve-ovn"),
    expect!("dual-stack-split"),
    expect!("no-sysfs"),
    expect!("symlinked-sysfs"),
];

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/net.mtu/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture.ensure_answers("net.mtu").expect("it answers");
    fixture
}

fn check(entry: &Value) -> MtuCheck {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::NetMtu(params) => MtuCheck::from_params(&params),
        other => panic!("not net.mtu: {other:?}"),
    }
}

/// What a run produced.
struct Run {
    end: End,
    log: ActionLogOutput,
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
}

/// Runs `check` on the machine of `fixture` through the scheduler, on a paused clock.
fn run(fixture: &Fixture, check: MtuCheck) -> Run {
    let test_run = TestRun::for_fixture(fixture);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let planned = Planned::new(Arc::new(check), "net.mtu");
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

/// The value with every object's keys in order. The goldens have sorted keys, and a build where
/// another crate turns on serde_json's `preserve_order` would otherwise write them in insertion order.
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

fn entry_of(case: &str) -> Value {
    let text = CASES
        .iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("{case} is not in CASES"))
        .1;
    let golden: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{case}: {e}"));
    golden["entry"].clone()
}

fn run_case(case: &str) -> Run {
    run(&load(case), check(&entry_of(case)))
}

#[test]
fn every_case_matches_its_golden() {
    for (case, _) in CASES {
        let entry = entry_of(case);
        let result = run(&load(case), check(&entry));
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        let mut bytes = serde_json::to_string_pretty(&sorted(actual)).expect("json");
        bytes.push('\n');
        assert_golden(
            fixtures_dir().join(format!("checks/net.mtu/{case}/expect.json")),
            bytes,
        );
    }
}

#[test]
fn the_case_list_names_the_cases_the_catalog_needs_and_lists_none_twice() {
    // This does not look at the directory: a new case directory without a row is not caught here.
    let names: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    for expected in [
        "pass-1500",
        "ec2-jumbo",
        "vxlan-room-exact",
        "vxlan-too-tight",
        "small-1280",
        "no-default-route",
        "kube-node",
        "no-sysfs",
    ] {
        assert!(names.contains(&expected), "{expected}");
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "a case is listed twice");
}

fn level_of(case: &str) -> Level {
    run_case(case).finding().level
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    assert_eq!(level_of("pass-1500"), Level::Pass);
    // 9001 is informational with no overlay and no minimum.
    assert_eq!(level_of("ec2-jumbo"), Level::Pass);
    // The same MTU is a warning once the spec names an overlay.
    assert_eq!(level_of("jumbo-geneve"), Level::Warn);
    assert_eq!(level_of("vxlan-room-exact"), Level::Pass);
    assert_eq!(level_of("vxlan-too-tight"), Level::Fail);
    assert_eq!(level_of("small-1280"), Level::Warn);
    assert_eq!(level_of("below-min-no-overlay"), Level::Warn);
    assert_eq!(level_of("wireguard-ipv6-underlay"), Level::Pass);
    assert_eq!(level_of("no-default-route"), Level::Warn);
    assert_eq!(level_of("tunnel-default"), Level::Pass);
    assert_eq!(level_of("kube-node"), Level::Pass);
    assert_eq!(level_of("unreadable-mtu"), Level::Warn);
    assert_eq!(level_of("garbage-mtu"), Level::Warn);
    assert_eq!(level_of("two-default-routes"), Level::Warn);
    assert_eq!(level_of("geneve-ovn"), Level::Pass);
    assert_eq!(level_of("dual-stack-split"), Level::Pass);
    assert_eq!(level_of("symlinked-sysfs"), Level::Pass);
}

#[test]
fn the_ticket_case_1450_with_vxlan_blocks_when_the_minimum_does_not_fit() {
    let fixture = load("vxlan-too-tight");
    // 1450 less 50 leaves 1400. A minimum of 1401 is the smallest that does not fit.
    for (min, level) in [
        (1400, Level::Pass),
        (1401, Level::Fail),
        (1450, Level::Fail),
    ] {
        let ran = run(
            &fixture,
            check(&json!({"id": "net.mtu", "min_mtu": min, "overlay": "vxlan"})),
        );
        assert_eq!(ran.finding().level, level, "min_mtu {min}");
    }
}

#[test]
fn a_blocking_case_names_the_numbers_and_the_fix() {
    let ran = run_case("vxlan-too-tight");
    let finding = ran.finding();
    assert_eq!(
        finding.message,
        "`eth0` has MTU 1450 and VXLAN needs 50 bytes, so the pod network must use 1400 or less, and 1450 is needed."
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("to 1500 or more"), "{fix}");
    assert!(fix.contains("set the CNI MTU to 1400 or less"), "{fix}");
    assert_eq!(finding.observed["default_interface"], "eth0");
    assert_eq!(finding.observed["overhead"], 50);
    assert_eq!(finding.observed["pod_mtu"], 1400);
    assert_eq!(finding.expected["min_mtu"], 1450);
}

#[test]
fn a_jumbo_mtu_is_informational_with_no_overlay_and_a_warning_with_one() {
    let plain = run_case("ec2-jumbo");
    let finding = plain.finding();
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.fix, None);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("9001") && n.contains("clamped to 1500")),
        "{:?}",
        finding.notes
    );
    let overlay = run_case("jumbo-geneve");
    let finding = overlay.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.contains("clamped to 1500"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("fragmentation needed"), "{fix}");
    // A spec with only a minimum asks about the MTU too.
    let min_only = run(
        &load("ec2-jumbo"),
        check(&json!({"id": "net.mtu", "min_mtu": 1400})),
    );
    assert_eq!(min_only.finding().level, Level::Warn);
}

#[test]
fn a_small_mtu_with_no_spec_warns_and_a_minimum_replaces_that_rule() {
    let ran = run_case("small-1280");
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(ran.finding().message.contains("below 1400"));
    // With a minimum the 1400 rule is off: 1280 meets a minimum of 1200.
    let met = run(
        &load("small-1280"),
        check(&json!({"id": "net.mtu", "min_mtu": 1200})),
    );
    assert_eq!(met.finding().level, Level::Pass);
    assert_eq!(met.finding().expected["warn_below"], Value::Null);
}

#[test]
fn a_default_route_to_a_tunnel_is_judged_and_noted() {
    let ran = run_case("tunnel-default");
    let finding = ran.finding();
    assert_eq!(finding.observed["default_interface"], "wg0");
    assert_eq!(finding.observed["default_mtu"], 1420);
    assert!(
        finding.notes.iter().any(|n| n.contains("tunnel interface")),
        "{:?}",
        finding.notes
    );
    let kinds: Vec<(&str, &str)> = finding.observed["interfaces"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|i| {
            (
                i["name"].as_str().unwrap_or(""),
                i["kind"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(kinds, [("eth0", "ethernet"), ("wg0", "tunnel")]);
}

#[test]
fn the_lowest_metric_decides_which_interface_is_judged() {
    let ran = run_case("two-default-routes");
    let finding = ran.finding();
    assert_eq!(finding.observed["default_interface"], "eth1");
    assert_eq!(finding.observed["default_mtu"], 1400);
}

#[test]
fn the_ipv6_underlay_prefers_the_ipv6_default_route() {
    let ran = run_case("wireguard-ipv6-underlay");
    let finding = ran.finding();
    assert_eq!(finding.observed["default_family"], "ipv6");
    assert_eq!(finding.observed["overhead"], 80);
    assert_eq!(finding.observed["pod_mtu"], 1420);
    // One byte more than fits blocks.
    let tight = run(
        &load("wireguard-ipv6-underlay"),
        check(
            &json!({"id": "net.mtu", "min_mtu": 1421, "overlay": "wireguard", "underlay": "ipv6"}),
        ),
    );
    assert_eq!(tight.finding().level, Level::Fail);
}

#[test]
fn a_split_default_route_judges_the_ipv4_interface_and_says_so() {
    let ran = run_case("dual-stack-split");
    let finding = ran.finding();
    assert_eq!(finding.observed["default_interface"], "eth0");
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("different interfaces") && n.contains("`eth0`")),
        "{:?}",
        finding.notes
    );
    // With an IPv6 underlay the other one is judged.
    let v6 = run(
        &load("dual-stack-split"),
        check(&json!({"id": "net.mtu", "underlay": "ipv6"})),
    );
    assert_eq!(v6.finding().observed["default_interface"], "eth1");
    assert_eq!(v6.finding().observed["default_mtu"], 1450);
}

#[test]
fn no_default_route_is_a_warning_only_when_the_spec_asks_about_the_mtu() {
    let asked = run_case("no-default-route");
    assert_eq!(asked.finding().level, Level::Warn);
    assert!(asked.finding().message.contains("No default route"));
    let quiet = run(&load("no-default-route"), check(&json!({"id": "net.mtu"})));
    assert_eq!(quiet.finding().level, Level::Pass);
    assert_eq!(quiet.finding().observed["default_interface"], Value::Null);
}

#[test]
fn an_unreadable_or_garbled_mtu_of_the_default_interface_is_not_checked_not_assumed() {
    for case in ["unreadable-mtu", "garbage-mtu"] {
        let ran = run_case(case);
        let finding = ran.finding();
        assert_eq!(finding.level, Level::Warn, "{case}");
        assert!(
            finding.message.contains("could not be read"),
            "{case}: {}",
            finding.message
        );
        assert_eq!(finding.observed["default_mtu"], Value::Null, "{case}");
    }
    let denied = run_case("unreadable-mtu");
    assert!(
        denied
            .finding()
            .notes
            .iter()
            .any(|n| n.contains("permission denied")),
        "{:?}",
        denied.finding().notes
    );
}

#[test]
fn a_machine_with_no_sysfs_is_an_error_with_a_hint() {
    let ran = run_case("no-sysfs");
    match ran.outcome() {
        Err(CheckError::Failed { message, hint }) => {
            assert!(
                message.contains("/sys/class/net does not exist"),
                "{message}"
            );
            assert!(hint.contains("/sys is mounted"), "{hint}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn container_plumbing_is_counted_and_never_read() {
    let ran = run_case("kube-node");
    let finding = ran.finding();
    assert_eq!(finding.observed["container_interfaces"], 5);
    let read: Vec<&str> = ran
        .log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Read)
        .filter_map(|a| a.fields.get("path").and_then(Value::as_str))
        .collect();
    assert!(!read.is_empty());
    assert!(
        read.iter()
            .all(|p| !p.contains("/veth") && !p.contains("/cali")),
        "{read:?}"
    );
    // Down interfaces are counted, not listed.
    assert_eq!(finding.observed["interfaces_down"], 1);
    let names: Vec<&str> = finding.observed["interfaces"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|i| i["name"].as_str())
        .collect();
    assert_eq!(names, ["cni0", "docker0", "eth0", "flannel.1"]);
}

#[test]
fn geneve_adds_the_ovn_note_and_the_other_overlays_do_not() {
    let ran = run_case("geneve-ovn");
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("OVN-Kubernetes reserves 100") && n.contains("1400")),
        "{:?}",
        finding.notes
    );
    let vxlan = run(
        &load("geneve-ovn"),
        check(&json!({"id": "net.mtu", "min_mtu": 1400, "overlay": "vxlan"})),
    );
    assert!(vxlan.finding().notes.iter().all(|n| !n.contains("OVN")));
}

#[test]
fn an_overlay_with_no_minimum_tells_the_cni_what_to_use() {
    let ran = run(
        &load("pass-1500"),
        check(&json!({"id": "net.mtu", "overlay": "vxlan"})),
    );
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("Set the CNI MTU to 1450 or less")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_run_stays_inside_the_manifest_and_reads_a_bounded_number_of_files() {
    for (case, _) in CASES {
        let ran = run_case(case);
        for action in &ran.log.actions {
            assert!(
                matches!(action.kind, ActionKind::Read | ActionKind::ReadDir),
                "{case}: {:?}",
                action.kind
            );
            assert_ne!(action.outcome, ActionOutcome::Denied, "{case}");
        }
        assert!(
            ran.log.actions.len() < 100,
            "{case}: {}",
            ran.log.actions.len()
        );
        assert_within_manifest(case, &INFO, &ran.log);
    }
    assert_eq!(
        INFO.reads,
        ["/sys/class/net", "/proc/net/route", "/proc/net/ipv6_route"]
    );
    assert!(INFO.statfs.is_empty() && INFO.commands.is_empty());
    assert!(INFO.env.is_empty() && INFO.peers.is_empty());
    assert!(INFO.needs.is_empty() && INFO.wants.is_empty());
}

#[test]
fn macos_and_windows_are_not_yet_and_the_check_says_so_if_it_is_run() {
    assert_eq!(INFO.os.on(Os::Linux), Support::Full);
    for os in [Os::Macos, Os::Windows] {
        assert_eq!(INFO.os.on(os), Support::NotYet);
        let fixture = load("pass-1500");
        let test_run = TestRun::for_fixture(&fixture);
        let ctx = test_run.context_for(&INFO, "net.mtu", os, Vec::<Need>::new());
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
            .block_on(check(&json!({"id": "net.mtu"})).run(&ctx));
        assert!(
            matches!(outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {outcome:?}"
        );
        // It touched nothing.
        assert!(test_run.action_log().actions.is_empty());
    }
}

#[test]
fn every_fix_a_case_gives_passes_the_fix_text_audit_and_is_one_plain_line() {
    // The text ships in reports. Every command in it must be on the reviewed list (ADR 0028).
    for (case, _) in CASES {
        let ran = run_case(case);
        let Ok(finding) = ran.outcome() else {
            continue;
        };
        if let Some(fix) = &finding.fix {
            if let Err(error) = rdy_engine::fixtext::check(fix) {
                panic!("{case}: fix text is not on the lists: {error}");
            }
            assert!(!fix.contains('\n'), "{case}");
        }
        assert!(!finding.message.contains('\n'), "{case}");
    }
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("the remediation is not on the lists: {error}");
    }
}

/// What the engine makes of the finding of `case`, for its own spec entry.
fn status_of(case: &str) -> Status {
    let entry = entry_of(case);
    let ran = run(&load(case), check(&entry));
    let fixture = load(case);
    let test_run = TestRun::for_fixture(&fixture);
    let ctx = test_run.context_for(&INFO, "net.mtu", Os::Linux, Vec::<Need>::new());
    let spec: CheckSpec = serde_json::from_value(entry).expect("a check entry");
    let outcome = ran.outcome().clone();
    map_outcome(&INFO, &spec, &ctx, outcome, 0, 0).status
}

#[test]
fn the_engine_maps_the_levels_to_the_statuses_the_catalog_names() {
    // The ticket cases: a fail is a block for a required check, a jumbo MTU alone passes.
    assert_eq!(status_of("vxlan-too-tight"), Status::Block);
    assert_eq!(status_of("ec2-jumbo"), Status::Pass);
    assert_eq!(status_of("vxlan-room-exact"), Status::Pass);
    assert_eq!(status_of("small-1280"), Status::Warn);
    assert_eq!(status_of("jumbo-geneve"), Status::Warn);
    assert_eq!(status_of("no-default-route"), Status::Warn);
}

#[test]
fn a_link_into_sys_devices_is_read_through_and_nothing_else_there_is_readable() {
    // SEC-28-2: `/sys/class/net/eth0` is a link to `/sys/devices/platform/acme-nic0/net/eth0`.
    let ran = run_case("symlinked-sysfs");
    let finding = ran.finding();
    assert_eq!(finding.observed["default_mtu"], 1500);
    assert_eq!(finding.observed["default_interface"], "eth0");
    assert!(finding.notes.is_empty(), "{:?}", finding.notes);

    let fixture = load("symlinked-sysfs");
    let test_run = TestRun::for_fixture(&fixture);
    let ctx = test_run.context_for(&INFO, "net.mtu", Os::Linux, Vec::<Need>::new());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let probe = ctx.probe();
    // The file exists in the tree, and a text read of it is refused: `/sys/devices` is not declared.
    for path in [
        "/sys/devices/virtual/dmi/id/board_asset_tag",
        "/sys/devices/platform/acme-nic0/net/eth0/mtu",
    ] {
        let refused = runtime.block_on(probe.read(Path::new(path)));
        assert!(
            matches!(refused, Err(ProbeError::Denied { .. })),
            "{path}: {refused:?}"
        );
    }
    // Reading through the link still works.
    let mtu = runtime
        .block_on(probe.read(Path::new("/sys/class/net/eth0/mtu")))
        .expect("the link is followed");
    assert_eq!(mtu.bytes, b"1500\n");
    // A path through the link to a file of another shape is refused by the real-path rule.
    let other =
        runtime.block_on(probe.read(Path::new("/sys/class/net/eth0/../../virtual/dmi/id/x")));
    assert!(other.is_err());
}
