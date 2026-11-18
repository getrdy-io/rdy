//! Tests of `net.dns`, system answer (M1-153).
//!
//! Cases are the `commands/` and `net.json` fixtures under `tests/fixtures/checks/net.dns/`: recorded
//! `getent ahosts` output (found, dual-stack rows, AAAA only, not found, a tool error, a hang) and the
//! facade resolver for a machine without `getent`. They run on a paused clock with no socket and no
//! process, so they are the same on all five CI legs. Each case asserts the finding, the `CheckResult`
//! the engine makes from it, and that the check stayed inside its manifest.

use std::time::Duration;

use rdy_engine::check::{
    Check, CheckContext, CheckError, CheckOutcome, Finding, Level, Need, Os, PeerClass,
};
use rdy_engine::outcome::map_outcome;
use rdy_engine::testing::{Fixture, Replay, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, CheckResult, SkipKind, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::judge::{Answer, Looked, Problem, Rule, Source};
use super::split;
use super::*;

// ---- the harness --------------------------------------------------------------------------------

pub(super) struct Ran {
    pub(super) outcome: CheckOutcome,
    pub(super) ctx: CheckContext,
    pub(super) entry: CheckSpec,
    pub(super) run: TestRun,
}

impl Ran {
    pub(super) fn finding(&self) -> &Finding {
        self.outcome.as_ref().expect("a finding")
    }

    pub(super) fn name(&self, at: usize) -> &Value {
        &self.finding().observed["names"][at]
    }

    pub(super) fn result(&self) -> CheckResult {
        map_outcome(&INFO, &self.entry, &self.ctx, self.outcome.clone(), 0, 0)
    }

    pub(super) fn everything_text(&self) -> String {
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

    /// The finding as text, without the action log. The log is the facade's, and it names the nameserver
    /// it asked (ADR 0051). The result never does.
    pub(super) fn result_text(&self) -> String {
        let finding = self.finding();
        format!(
            "{} {} {:?} {:?} {:?}",
            finding.message, finding.observed, finding.fix, finding.notes, finding.partial
        )
    }

    fn execs(&self) -> usize {
        self.run
            .action_log()
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::Exec)
            .count()
    }
}

fn entry(names: &Value, extra: &Value) -> CheckSpec {
    let mut entry = json!({"id": "net.dns", "names": names});
    for (key, value) in extra.as_object().expect("an object") {
        entry[key] = value.clone();
    }
    serde_json::from_value(entry).expect("a check entry")
}

fn check_of(entry: &CheckSpec) -> DnsCheck {
    match entry.decode_params() {
        CheckParams::NetDns(params) => DnsCheck::from_params(&params),
        other => panic!("not net.dns: {other:?}"),
    }
}

pub(super) async fn run_with(
    run: TestRun,
    names: Value,
    extra: Value,
    os: Os,
    needs: &[Need],
) -> Ran {
    let entry = entry(&names, &extra);
    let check = check_of(&entry);
    let ctx = run.with_deadline(
        run.context_for_hosts(&INFO, "net.dns", os, needs.iter().cloned(), check.hosts()),
        Duration::from_secs(60),
    );
    let outcome = check.run(&ctx).await;
    assert_within_manifest("net.dns", &INFO, &run.action_log());
    Ran {
        outcome,
        ctx,
        entry,
        run,
    }
}

pub(super) async fn run_on(replay: Replay, names: Value, extra: Value) -> Ran {
    run_with(TestRun::new(replay), names, extra, Os::Linux, NET).await
}

/// The machine of a fixture case.
pub(super) fn case(name: &str) -> Replay {
    Fixture::load(&fixtures_dir(), &format!("checks/net.dns/{name}"))
        .expect("the fixture loads")
        .into_replay()
}

pub(super) const NET: &[Need] = &[Need::Network];

// ---- found --------------------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_dual_stack_name_passes_and_its_six_rows_are_two_addresses() {
    let ran = run_on(
        case("found-dual-stack"),
        json!(["web.acme.test"]),
        json!({}),
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.message, "1 of 1 names resolve");
    let n = ran.name(0);
    assert_eq!(n["source"], "getent");
    assert_eq!(n["result"], "found");
    assert_eq!(n["ipv4"], 1);
    assert_eq!(n["ipv6"], 1);
    assert_eq!(n["addresses"], json!(["2001:db8::10", "192.0.2.10"]));
    assert_eq!(n["addresses_total"], 2);
    assert!(finding.notes.is_empty(), "{:?}", finding.notes);
    assert_eq!(ran.execs(), 1);
    let result = ran.result();
    assert_eq!(result.status, Status::Pass);
    assert!(result.fix.is_none());
}

#[tokio::test(start_paused = true)]
async fn an_aaaa_only_name_is_seen_and_noted() {
    let ran = run_on(case("aaaa-only"), json!(["v6.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    let n = ran.name(0);
    assert_eq!(n["ipv4"], 0);
    assert_eq!(n["ipv6"], 1);
    assert!(
        finding.notes.iter().any(|n| n.contains("only IPv6")),
        "{:?}",
        finding.notes
    );
}

// ---- not found, timeout --------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn getent_exit_two_is_not_found_and_blocks_with_a_fix() {
    let ran = run_on(case("not-found"), json!(["gone.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "1 of 1 names do not resolve: `gone.acme.test` (not found)"
    );
    assert_eq!(ran.name(0)["result"], "not_found");
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("`acme.test`"), "the zone: {fix}");
    assert!(fix.contains("`/etc/hosts`"), "{fix}");
    assert!(fix.contains("nsswitch.conf"), "{fix}");
    let result = ran.result();
    assert_eq!(result.status, Status::Block);
}

#[tokio::test(start_paused = true)]
async fn a_stopped_getent_is_a_timeout_with_the_resolver_settings() {
    let ran = run_on(case("timeout"), json!(["slow.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(ran.name(0)["result"], "timeout");
    let resolver = &finding.observed["resolver"];
    assert_eq!(resolver["timeout_s"], 3);
    assert_eq!(resolver["attempts"], 3);
    assert_eq!(resolver["nameservers"], 2);
    assert_eq!(resolver["worst_case_s"], 18);
    assert!(
        finding.notes.iter().any(|n| n.contains("up to about 18 s")),
        "{:?}",
        finding.notes
    );
    // The addresses of the nameservers are not copied into the result.
    assert!(!ran.result_text().contains("192.0.2.53"));
}

// ---- the fallback ---------------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn without_getent_the_facade_resolver_answers_and_says_so() {
    let ran = run_on(case("getent-missing"), json!(["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    let n = ran.name(0);
    assert_eq!(n["source"], "rdy_resolver");
    assert_eq!(n["fallback"], "getent is not installed");
    assert_eq!(n["addresses"], json!(["192.0.2.10"]));
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("getent is not installed") && n.contains("nsswitch.conf")),
        "{:?}",
        finding.notes
    );
}

#[tokio::test(start_paused = true)]
async fn the_fallback_note_is_written_once_for_many_names() {
    let ran = run_on(
        case("getent-missing"),
        json!(["web.acme.test", "gone.acme.test"]),
        json!({}),
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(ran.name(1)["result"], "not_found");
    assert_eq!(
        finding
            .notes
            .iter()
            .filter(|n| n.contains("getent is not installed"))
            .count(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn a_getent_tool_error_falls_back_and_names_the_exit_code() {
    let ran = run_on(case("getent-broken"), json!(["web.acme.test"]), json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    let n = ran.name(0);
    assert_eq!(n["source"], "rdy_resolver");
    assert_eq!(n["fallback"], "getent exited with code 1");
    assert_eq!(ran.execs(), 1, "getent was tried once");
}

#[tokio::test(start_paused = true)]
async fn the_fallback_refuses_an_answer_in_a_refused_range_and_shows_no_address() {
    let ran = run_on(
        case("getent-missing-link-local"),
        json!(["meta.acme.test"]),
        json!({}),
    )
    .await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(ran.name(0)["result"], "refused_by_policy");
    assert!(
        !ran.everything_text().contains("169.254.169.123"),
        "the refused address is not shown"
    );
}

#[tokio::test(start_paused = true)]
async fn on_macos_the_facade_lookup_is_the_system_answer_and_no_command_runs() {
    let run = TestRun::new(case("getent-missing"));
    let ran = run_with(run, json!(["web.acme.test"]), json!({}), Os::Macos, NET).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Pass);
    let n = ran.name(0);
    assert_eq!(n["source"], "getaddrinfo");
    assert!(n.get("fallback").is_none());
    assert!(finding.notes.is_empty(), "{:?}", finding.notes);
    assert_eq!(ran.execs(), 0);
}

// ---- names are untrusted --------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_name_that_reads_as_an_option_is_rejected_before_any_command_runs() {
    for bad in [
        "-x",
        "--help",
        "-v.acme.test",
        "a b",
        "a\nb",
        "a;id",
        "$(id)",
    ] {
        let run = TestRun::new(case("found-dual-stack"));
        let ctx = run.context_for_hosts(
            &INFO,
            "net.dns",
            Os::Linux,
            [Need::Network],
            HostSet::empty(),
        );
        let looked = look_up(&ctx, bad, 0).await.expect("a result, not an error");
        assert!(
            matches!(looked.answer, Answer::Rejected(_)),
            "{bad:?}: {:?}",
            looked.answer
        );
        let log = run.action_log();
        assert!(
            log.actions.is_empty(),
            "{bad:?} reached the facade: {:?}",
            log.actions
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_rejected_name_blocks_with_its_own_text_and_is_never_sent() {
    // The judge is fed a rejected name, as it would be if a later spec field let one through.
    let rules = [rule("-x", &[], None)];
    let looked = [Looked {
        answer: Answer::Rejected(
            "the name starts with a hyphen, so a command would read it as an option",
        ),
        ..Looked::new("-x")
    }];
    let finding = judge::judge(
        Os::Linux,
        &rules,
        &looked,
        Duration::from_millis(500),
        None,
        &split::Machine::default(),
    );
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("not a valid name"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["names"][0]["result"], "rejected");
}

#[test]
fn the_command_table_is_the_only_door_and_lists_net_dns() {
    let entry = table::entry("getent").expect("getent is in the table");
    assert!(entry.checks.contains(&"net.dns"));
    assert!(
        entry.network,
        "getent is a network command: --no-network refuses it"
    );
    assert_eq!(INFO.commands.len(), 1);
    assert_eq!(INFO.commands[0].program, "getent");
    assert_eq!(
        INFO.peers,
        &[PeerClass::SpecHosts, PeerClass::SystemResolver]
    );
    // The table refuses the same names the check does.
    for bad in ["-x", "a b", "a\nb"] {
        assert!(
            entry.cmd_for(Os::Linux, "ahosts", &[bad]).is_err(),
            "{bad:?}"
        );
    }
    assert!(
        entry
            .cmd_for(Os::Linux, "ahosts", &["web.acme.test"])
            .is_ok()
    );
}

// ---- the network gate -----------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn without_the_network_need_the_check_skips_as_missing_need_and_runs_nothing() {
    let ran = run_with(
        TestRun::new(case("offline")),
        json!(["web.acme.test"]),
        json!({}),
        Os::Linux,
        &[],
    )
    .await;
    assert_eq!(ran.outcome, Err(CheckError::MissingNeed(Need::Network)));
    let result = ran.result();
    assert_eq!(result.status, Status::Skipped);
    assert_eq!(result.skip_kind, Some(SkipKind::MissingNeed));
    assert!(
        ran.run.action_log().actions.is_empty(),
        "no command, no lookup"
    );
}

#[tokio::test(start_paused = true)]
async fn if_the_facade_refuses_under_no_network_the_check_still_skips_and_never_fails() {
    // The need was granted, as in a build where the gate is missing, but the run is offline: the
    // facade's refusal of the command ends the check as `missing_need`, not as a failed lookup.
    let run = TestRun::new(case("found-dual-stack")).offline();
    let ran = run_with(run, json!(["web.acme.test"]), json!({}), Os::Linux, NET).await;
    assert_eq!(ran.outcome, Err(CheckError::MissingNeed(Need::Network)));
    assert_eq!(ran.result().skip_kind, Some(SkipKind::MissingNeed));
    // The facade lookup refuses too, on an OS with no command.
    let run = TestRun::new(case("getent-missing")).offline();
    let ran = run_with(run, json!(["web.acme.test"]), json!({}), Os::Macos, NET).await;
    assert_eq!(ran.outcome, Err(CheckError::MissingNeed(Need::Network)));
}

// ---- thresholds from the spec ----------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn expect_in_and_expect_public_judge_the_answers() {
    let names = json!([
        {"name": "app.acme.test", "expect_in": ["10.0.0.0/8"], "expect_public": false},
        {"name": "cdn.acme.test", "expect_public": true},
        "gone.acme.test",
    ]);
    let ran = run_on(case("mixed"), names, json!({})).await;
    let finding = ran.finding();
    // Only the missing name fails: the two answers sit where the spec expects them.
    assert_eq!(
        finding.message,
        "1 of 3 names do not resolve: `gone.acme.test` (not found)"
    );
    assert_eq!(ran.name(0)["result"], "found");
    assert_eq!(
        finding.expected["names"][0]["expect_in"],
        json!(["10.0.0.0/8"])
    );
}

#[tokio::test(start_paused = true)]
async fn an_answer_outside_the_expected_range_blocks_and_names_the_address() {
    let names = json!([
        {"name": "app.acme.test", "expect_in": ["172.16.0.0/12"]},
        {"name": "cdn.acme.test", "expect_public": false},
    ]);
    let ran = run_on(case("mixed"), names, json!({})).await;
    let finding = ran.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .contains("10.20.30.40 is outside 172.16.0.0/12"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .message
            .contains("198.51.100.7 is a public address and the spec expects a private one"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("split-horizon"), "{fix}");
    assert_eq!(ran.result().status, Status::Block);
}

// ---- the verdict, on its own ----------------------------------------------------------------------------

fn rule(name: &str, expect_in: &[&str], expect_public: Option<bool>) -> Rule {
    Rule {
        name: name.to_owned(),
        expect_in: expect_in
            .iter()
            .map(|c| serde_json::from_value(json!(c)).expect("a range"))
            .collect(),
        expect_public,
    }
}

fn found(name: &str, addrs: &[&str], took_ms: u64) -> Looked {
    Looked {
        answer: Answer::Found(
            addrs
                .iter()
                .map(|a| a.parse().expect("an address"))
                .collect(),
        ),
        took: Duration::from_millis(took_ms),
        ..Looked::new(name)
    }
}

fn with(name: &str, answer: Answer) -> Looked {
    Looked {
        answer,
        ..Looked::new(name)
    }
}

const MAX: Duration = Duration::from_millis(500);

#[test]
fn a_slow_lookup_warns_and_the_boundary_passes() {
    let rules = [
        rule("a.acme.test", &[], None),
        rule("b.acme.test", &[], None),
    ];
    let at = [
        found("a.acme.test", &["192.0.2.1"], 500),
        found("b.acme.test", &["192.0.2.2"], 501),
    ];
    let finding = judge::judge(
        Os::Linux,
        &rules,
        &at,
        MAX,
        None,
        &split::Machine::default(),
    );
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(
        finding.message,
        "`b.acme.test` took 501 ms to resolve, above 500 ms"
    );
    let ok = judge::judge(
        Os::Linux,
        &rules[..1],
        &at[..1],
        MAX,
        None,
        &split::Machine::default(),
    );
    assert_eq!(ok.level, Level::Pass);
    // The spec's own limit replaces the default.
    let loose = judge::judge(
        Os::Linux,
        &rules,
        &at,
        Duration::from_secs(2),
        None,
        &split::Machine::default(),
    );
    assert_eq!(loose.level, Level::Pass);
}

#[test]
fn a_failure_outranks_a_slow_answer() {
    let rules = [
        rule("a.acme.test", &[], None),
        rule("b.acme.test", &[], None),
    ];
    let at = [
        found("a.acme.test", &["192.0.2.1"], 900),
        with("b.acme.test", Answer::NotFound),
    ];
    let finding = judge::judge(
        Os::Linux,
        &rules,
        &at,
        MAX,
        None,
        &split::Machine::default(),
    );
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.notes.iter().any(|n| n.contains("took 900 ms")));
}

#[test]
fn many_failures_are_named_five_at_a_time() {
    let names: Vec<String> = (0..8).map(|n| format!("n{n}.acme.test")).collect();
    let rules: Vec<Rule> = names.iter().map(|n| rule(n, &[], None)).collect();
    let at: Vec<Looked> = names.iter().map(|n| with(n, Answer::NotFound)).collect();
    let finding = judge::judge(
        Os::Linux,
        &rules,
        &at,
        MAX,
        None,
        &split::Machine::default(),
    );
    assert!(finding.message.starts_with("8 of 8 names do not resolve: "));
    assert!(
        finding.message.ends_with("and 3 more"),
        "{}",
        finding.message
    );
    // One fix for the one class, not eight.
    let fix = finding.fix.expect("a fix");
    assert_eq!(fix.matches("does not resolve on this machine").count(), 1);
}

#[test]
fn names_the_check_ran_out_of_time_for_are_partial_and_not_a_pass() {
    let rules = [
        rule("a.acme.test", &[], None),
        rule("b.acme.test", &[], None),
    ];
    let at = [
        found("a.acme.test", &["192.0.2.1"], 10),
        with("b.acme.test", Answer::NotTried),
    ];
    let finding = judge::judge(
        Os::Linux,
        &rules,
        &at,
        MAX,
        None,
        &split::Machine::default(),
    );
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.message, "1 of 2 names resolve");
    let partial = finding.partial.expect("partial");
    assert!(partial.note.contains("1 of 2 names were not looked up"));
    let none = judge::judge(
        Os::Linux,
        &rules[1..],
        &[with("b.acme.test", Answer::NotTried)],
        MAX,
        None,
        &split::Machine::default(),
    );
    assert_eq!(none.message, "no name was looked up");
}

#[test]
fn a_range_of_the_other_family_never_matches() {
    let rules = [rule("a.acme.test", &["10.0.0.0/8"], None)];
    let at = [found("a.acme.test", &["2001:db8::1"], 1)];
    let finding = judge::judge(
        Os::Linux,
        &rules,
        &at,
        MAX,
        None,
        &split::Machine::default(),
    );
    assert_eq!(finding.level, Level::Fail);
}

// ---- text -----------------------------------------------------------------------------------------------

#[test]
fn every_fix_and_the_remediation_pass_the_fix_text_audit() {
    let resolver = Some(parse::resolver("nameserver 192.0.2.1\noptions timeout:2\n"));
    for os in [Os::Linux, Os::Macos, Os::Windows] {
        for problem in [
            Problem::NotFound,
            Problem::Timeout,
            Problem::Refused,
            Problem::Failed,
            Problem::Rejected,
        ] {
            for r in [None, resolver] {
                let text = judge::fix_for(os, problem, "web.acme.test", r);
                if let Err(error) = rdy_engine::fixtext::check(&text) {
                    panic!("{os:?} {problem:?}: {error}\n{text}");
                }
                assert!(!text.contains("  "), "{text}");
                assert!(!text.contains('\u{2014}'), "no em dash: {text}");
            }
        }
    }
    rdy_engine::fixtext::check(INFO.meta.remediation).expect("the remediation passes");
}

#[test]
fn text_from_the_machine_in_a_note_is_escaped() {
    let rules = [rule("a.acme.test", &[], None)];
    let at = [with(
        "a.acme.test",
        Answer::Failed("bad\u{1b}[2Jtext".to_owned()),
    )];
    let finding = judge::judge(
        Os::Linux,
        &rules,
        &at,
        MAX,
        None,
        &split::Machine::default(),
    );
    let all = format!("{:?}", finding.notes);
    assert!(!all.contains('\u{1b}'), "{all}");
}

#[test]
fn sources_have_stable_ids() {
    let l = Looked::new("a.acme.test");
    assert_eq!(l.source, Source::Getent);
    let v = judge::judge(
        Os::Linux,
        &[rule("a.acme.test", &[], None)],
        &[Looked {
            source: Source::Fallback,
            answer: Answer::Found(vec!["192.0.2.1".parse().expect("an address")]),
            fallback: Some("getent exited with code 3".to_owned()),
            ..l
        }],
        MAX,
        None,
        &split::Machine::default(),
    );
    assert_eq!(v.observed["names"][0]["source"], "rdy_resolver");
    assert_eq!(
        v.observed["names"][0]["fallback"],
        "getent exited with code 3"
    );
}

// ---- the reviewed results ---------------------------------------------------------------------------------

/// The golden of a case, compiled in: a check crate test may not read files.
macro_rules! expect {
    ($case:literal) => {
        (
            $case,
            include_str!(concat!(
                "../../../../tests/fixtures/checks/net.dns/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case of `tests/fixtures/checks/net.dns/`, with the check run by the real scheduler on a paused
/// clock and given its host set, as `rdy run` gives it. A new directory is a new line here.
const CASES: [(&str, &str); 18] = [
    expect!("aaaa-only"),
    expect!("direct-nxdomain"),
    expect!("found-dual-stack"),
    expect!("getent-broken"),
    expect!("getent-empty"),
    expect!("getent-missing"),
    expect!("getent-missing-link-local"),
    expect!("getent-refused-forms"),
    expect!("getent-signal"),
    expect!("mixed"),
    expect!("not-found"),
    expect!("nsswitch-sss-mdns"),
    expect!("offline"),
    expect!("resolv-link-systemd"),
    expect!("resolv-link-undeclared"),
    expect!("slow-first-nameserver"),
    expect!("split-horizon"),
    expect!("timeout"),
];

fn expect_path(case: &str) -> std::path::PathBuf {
    fixtures_dir().join(format!("checks/net.dns/{case}/expect.json"))
}

fn entry_of(case: &str) -> Value {
    let text = CASES
        .iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("{case} is not a listed case"))
        .1;
    let golden: Value = serde_json::from_str(text).expect("expect.json is JSON");
    golden["entry"].clone()
}

fn run_case(
    case: &str,
) -> (
    Value,
    rdy_engine::sched::End,
    rdy_engine::probe::ActionLogOutput,
) {
    let entry = entry_of(case);
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    let check = check_of(&spec);
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/net.dns/{case}"))
        .expect("the fixture loads");
    fixture
        .ensure_answers("net.dns")
        .expect("it answers net.dns");
    // The cases that have nameservers in `resolv.conf` get scripted servers (they cannot live in a file).
    let test_run = TestRun::new(super::direct_tests::with_servers(
        case,
        fixture.replay().clone(),
    ));
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let planned = rdy_engine::sched::Planned::new(std::sync::Arc::new(check.clone()), "net.dns")
        .with_hosts(check.hosts());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let mut ran = runtime.block_on(scheduler.run(vec![planned]));
    let log = test_run.action_log();
    // The one refusal a case may hold: `/etc/resolv.conf` links to a file the check does not declare, and
    // the check shrugs it off (it only loses the evidence of a timeout). Anything else is a violation.
    let violations: Vec<String> = rdy_engine::testing::manifest_violations(&INFO, &log)
        .into_iter()
        .filter(|v| !(case == "resolv-link-undeclared" && v.contains("read /etc/resolv.conf")))
        .collect();
    assert!(violations.is_empty(), "{case}: {violations:?}");
    (entry, ran.remove(0).end, log)
}

#[test]
fn every_case_matches_its_expect_json() {
    for (case, _) in CASES {
        let (entry, end, _) = run_case(case);
        rdy_engine::testing::golden::assert_golden(
            expect_path(case),
            rdy_engine::testing::expect_bytes(&entry, &end),
        );
    }
}

#[test]
fn the_case_list_is_every_directory_of_the_fixtures() {
    let mut on_disk = rdy_engine::testing::fixture_cases("net.dns");
    on_disk.sort();
    let listed: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    assert_eq!(on_disk, listed);
}

#[test]
fn no_case_connects_anywhere() {
    // The host set carries port 443 as a placeholder, so nothing but exec, lookup, read and the facade's nameserver `dns` calls may appear.
    for (case, _) in CASES {
        let (_, _, log) = run_case(case);
        for action in &log.actions {
            assert!(
                action.kind == ActionKind::Exec
                    || action.kind == ActionKind::Lookup
                    || action.kind == ActionKind::Read
                    || action.kind == ActionKind::Dns,
                "{case}: {:?} is not exec, lookup, read or dns",
                action.kind
            );
        }
    }
}

fn result_of(case: &str) -> Value {
    let (entry, end, _) = run_case(case);
    let bytes = rdy_engine::testing::expect_bytes(&entry, &end);
    serde_json::from_str::<Value>(&bytes).expect("json")["result"].clone()
}

#[test]
fn getent_answers_in_refused_ranges_block_in_every_form_and_stay_visible() {
    let result = result_of("getent-refused-forms");
    assert_eq!(result["level"], "fail");
    for (at, shown) in [
        (0, "169.254.169.123"),
        (1, "169.254.169.123"),
        (2, "64:ff9b::a9fe:a97b"),
    ] {
        let n = &result["observed"]["names"][at];
        assert_eq!(n["result"], "refused_by_policy", "{n}");
        assert_eq!(n["source"], "getent");
        assert_eq!(n["addresses"], json!([shown]));
    }
}

#[test]
fn a_getent_ended_by_a_signal_or_printing_nothing_falls_back_with_its_reason() {
    let signal = result_of("getent-signal");
    assert_eq!(signal["level"], "pass");
    assert_eq!(
        signal["observed"]["names"][0]["fallback"],
        "getent was ended by a signal"
    );
    let empty = result_of("getent-empty");
    assert_eq!(empty["level"], "pass");
    assert_eq!(
        empty["observed"]["names"][0]["fallback"],
        "getent printed no address"
    );
    assert_eq!(empty["observed"]["names"][0]["source"], "rdy_resolver");
}

#[test]
fn a_resolv_conf_link_to_a_declared_file_gives_evidence_and_to_another_gives_none() {
    let declared = result_of("resolv-link-systemd");
    assert_eq!(declared["observed"]["resolver"]["worst_case_s"], 18);
    let other = result_of("resolv-link-undeclared");
    assert_eq!(other["level"], "fail", "no error, still a timeout finding");
    assert!(other["observed"].get("resolver").is_none(), "{other}");
}

#[test]
fn a_timeout_note_names_the_name_and_matches_the_source() {
    let getent = result_of("timeout");
    let note = getent["notes"][0].as_str().expect("a note");
    assert!(
        note.starts_with("`slow.acme.test` timed out: getent is stopped after 5 s"),
        "{note}"
    );
    // A timeout from the fallback or the budget does not blame getent.
    let rules = [rule("a.acme.test", &[], None)];
    for source in [Source::Fallback, Source::System] {
        let at = [Looked {
            source,
            answer: Answer::Timeout,
            ..Looked::new("a.acme.test")
        }];
        let finding = judge::judge(
            Os::Linux,
            &rules,
            &at,
            MAX,
            None,
            &split::Machine::default(),
        );
        let note = &finding.notes[0];
        assert!(note.starts_with("`a.acme.test` timed out: "), "{note}");
        assert!(!note.contains("getent"), "{note}");
        assert!(note.contains("9 s"), "{note}");
    }
}
