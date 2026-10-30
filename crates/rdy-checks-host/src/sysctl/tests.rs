//! Tests of `host.sysctl` against the synthetic machines under `tests/fixtures/checks/host.sysctl/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest (`reads`) and the action log are the ones a run has. Each case has an
//! `expect.json` with the spec entry and the reviewed result (the shape `host.disk` uses). The entry
//! of each case is in `CASES` below, and `assert_golden` compares the bytes: a mismatch fails with a
//! diff, and `UPDATE_GOLDENS=1` rewrites the file for review. The `render` helper is a copy of
//! `host.disk`'s; M1-174 moves both into `rdy_engine::testing`.

use std::sync::Arc;

use rdy_engine::check::{Check, CheckOutcome, Finding, Level};
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

/// The spec entry each case runs with, in the order of the 03 case list.
fn cases() -> Vec<(&'static str, Value)> {
    let mm = json!({"id": "host.sysctl", "expect": {"vm.max_map_count": ">=262144"}});
    let nofile = json!({"id": "host.sysctl", "limits": {"nofile": ">=65536"}});
    vec![
        (
            "pass",
            json!({"id": "host.sysctl", "expect": {
                "vm.max_map_count": ">=262144",
                "net.ipv4.ip_forward": 1,
                "net.ipv4.tcp_rmem": "4096 131072 6291456",
                "kernel.shmmax": ">=4294967296",
            }, "limits": {"nofile": ">=65536"}}),
        ),
        ("wrong-live", mm.clone()),
        ("not-persisted", mm.clone()),
        ("masked-name", mm.clone()),
        ("later-file-wins", mm.clone()),
        ("etc-wins-same-name", mm.clone()),
        ("null-mask", mm.clone()),
        ("sysctl-conf-last", mm.clone()),
        ("sysctl-conf-linked", mm.clone()),
        (
            "missing-parameter",
            json!({"id": "host.sysctl", "expect": {"net.bridge.bridge-nf-call-iptables": 1}}),
        ),
        ("unreadable-parameter", mm.clone()),
        ("unreadable-sysctl-d", mm),
        (
            "glob-and-exclusion",
            json!({"id": "host.sysctl", "expect": {
                "net.ipv4.conf.eth0.rp_filter": 1,
                "net.ipv4.conf.lo.rp_filter": 1,
            }}),
        ),
        (
            "vlan-interface",
            json!({"id": "host.sysctl", "expect": {"net/ipv4/conf/eth0.100/rp_filter": 1}}),
        ),
        ("nofile-built-in", nofile.clone()),
        ("nofile-low", nofile.clone()),
        ("nofile-dropin-wins", nofile),
        (
            "nofile-above-nr-open",
            json!({"id": "host.sysctl", "limits": {"nofile": ">=2097152"}}),
        ),
        (
            "hostile-live",
            json!({"id": "host.sysctl", "expect": {"net.ipv4.tcp_congestion_control": "cubic"}}),
        ),
    ]
}

fn entry_of(case: &str) -> Value {
    cases()
        .into_iter()
        .find(|(name, _)| *name == case)
        .unwrap_or_else(|| panic!("no case {case}"))
        .1
}

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.sysctl/{case}"))
        .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture.ensure_answers("host.sysctl").expect("it answers");
    fixture
}

fn sysctl(entry: &Value) -> Sysctl {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::HostSysctl(params) => Sysctl::new(&params),
        other => panic!("not host.sysctl: {other:?}"),
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
fn run_with(fixture: &Fixture, check: Sysctl) -> Run {
    let test_run = TestRun::for_fixture(fixture);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let planned = Planned::new(Arc::new(check), "host.sysctl");
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
    run_with(&load(case), sysctl(&entry_of(case)))
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

#[test]
fn every_case_matches_its_golden() {
    for (case, entry) in cases() {
        let result = run_with(&load(case), sysctl(&entry));
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        let mut bytes = serde_json::to_string_pretty(&sorted(actual)).expect("json");
        bytes.push('\n');
        assert_golden(
            fixtures_dir().join(format!("checks/host.sysctl/{case}/expect.json")),
            bytes,
        );
    }
}

#[test]
fn the_case_list_names_each_case_once() {
    let names: Vec<&str> = cases().iter().map(|(name, _)| *name).collect();
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "a case is listed twice");
    for needed in [
        "pass",
        "wrong-live",
        "not-persisted",
        "masked-name",
        "unreadable-parameter",
    ] {
        assert!(names.contains(&needed), "{needed}");
    }
}

fn level_of(case: &str) -> Level {
    run_case(case).finding().level
}

// ---- the exit tests ------------------------------------------------------------------------------

#[test]
fn a_right_live_value_with_no_sysctl_d_entry_warns_not_persisted() {
    let run = run_case("not-persisted");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.contains("is not persisted"),
        "{}",
        finding.message
    );
    assert!(finding.message.contains("`vm.max_map_count` is `262144`"));
    assert_eq!(
        finding.observed["parameters"]["vm.max_map_count"]["state"],
        "not_persisted"
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("echo 'vm.max_map_count = 262144' | sudo tee -a /etc/sysctl.d/99-rdy.conf"),
        "{fix}"
    );
    assert!(fix.contains("sysctl --system"), "{fix}");
    assert!(
        fix.contains("`sysctl -p` does not read `sysctl.d`"),
        "{fix}"
    );
    assert!(finding.partial.is_none(), "every source was read");
}

#[test]
fn a_masked_file_name_resolves_by_the_precedence_rule() {
    // The vendor line is in /usr/lib/sysctl.d/99-acme.conf. A file of the same name in /etc hides it,
    // so the value is not persisted, and the message names both files.
    let run = run_case("masked-name");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("is not persisted"));
    assert!(
        finding
            .message
            .contains("`/usr/lib/sysctl.d/99-acme.conf` sets it")
            && finding
                .message
                .contains("`/etc/sysctl.d/99-acme.conf` has the same name"),
        "{}",
        finding.message
    );

    // The other way round: the /etc file wins its name, and the /usr/lib value below it is ignored.
    let run = run_case("etc-wins-same-name");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    assert_eq!(
        finding.observed["parameters"]["vm.max_map_count"]["persisted"]["file"],
        "/etc/sysctl.d/50-acme.conf"
    );
}

#[test]
fn files_apply_in_the_order_of_their_names_whatever_the_directory() {
    let run = run_case("later-file-wins");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(
        finding.observed["parameters"]["vm.max_map_count"]["state"],
        "persisted_wrong"
    );
    assert!(
        finding
            .message
            .contains("`/usr/lib/sysctl.d/90-hardening.conf` sets it to `65530` at boot"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(
        fix.contains(
            "Change the line for `vm.max_map_count` in `/usr/lib/sysctl.d/90-hardening.conf`"
        ),
        "{fix}"
    );
}

#[test]
fn etc_sysctl_conf_is_applied_after_the_directories() {
    let run = run_case("sysctl-conf-last");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("`/etc/sysctl.conf` sets it to `65530`")
    );
    assert!(
        finding.notes.iter().any(|n| n.contains(
            "systemd-sysctl, reads it only when a file in a sysctl.d directory links to it"
        )),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_link_from_sysctl_d_to_etc_sysctl_conf_is_one_file_read_in_the_directory() {
    let run = run_case("sysctl-conf-linked");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    // The directory applies it, so the name is the link and the sysctl.conf warning does not show.
    assert_eq!(
        finding.observed["parameters"]["vm.max_map_count"]["persisted"]["file"],
        "/etc/sysctl.d/99-sysctl.conf"
    );
    assert!(
        !finding.notes.iter().any(|n| n.contains("systemd-sysctl")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_link_to_dev_null_masks_the_lower_file() {
    let run = run_case("null-mask");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("is not persisted"));
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("`/etc/sysctl.d/99-acme.conf` is a link to /dev/null")),
        "{:?}",
        finding.notes
    );
    // The refused read of the device is expected: it is how rdy sees the link, and it is inside the
    // declared reads.
    assert_within_manifest("null-mask", &INFO, &run.log);
}

#[test]
fn a_wrong_live_value_blocks() {
    let run = run_case("wrong-live");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .starts_with("`vm.max_map_count` is `65530`, need at least 262144."),
        "{}",
        finding.message
    );
}

#[test]
fn a_missing_parameter_blocks_and_names_the_module() {
    let run = run_case("missing-parameter");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.message.contains("does not exist on this machine"));
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("modprobe br_netfilter"), "{fix}");
    assert!(
        fix.contains("/etc/modules-load.d/br_netfilter.conf"),
        "{fix}"
    );
}

#[test]
fn tabs_and_spaces_are_the_same_in_a_value() {
    // The kernel prints tabs, the spec and the file use spaces, and the file has two spaces.
    let run = run_case("pass");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    let rmem = &finding.observed["parameters"]["net.ipv4.tcp_rmem"];
    assert_eq!(rmem["live"], "4096 131072 6291456");
    assert_eq!(rmem["state"], "ok");
    // A u64 above i64::MAX compares as a number.
    assert_eq!(
        finding.observed["parameters"]["kernel.shmmax"]["live"],
        "18446744073709551615"
    );
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    assert_eq!(level_of("pass"), Level::Pass);
    assert_eq!(level_of("wrong-live"), Level::Fail);
    assert_eq!(level_of("not-persisted"), Level::Warn);
    assert_eq!(level_of("masked-name"), Level::Warn);
    assert_eq!(level_of("later-file-wins"), Level::Warn);
    assert_eq!(level_of("etc-wins-same-name"), Level::Pass);
    assert_eq!(level_of("null-mask"), Level::Warn);
    assert_eq!(level_of("sysctl-conf-last"), Level::Warn);
    assert_eq!(level_of("sysctl-conf-linked"), Level::Pass);
    assert_eq!(level_of("missing-parameter"), Level::Fail);
    assert_eq!(level_of("unreadable-parameter"), Level::Warn);
    assert_eq!(level_of("unreadable-sysctl-d"), Level::Warn);
    assert_eq!(level_of("glob-and-exclusion"), Level::Warn);
    assert_eq!(level_of("vlan-interface"), Level::Pass);
    assert_eq!(level_of("nofile-built-in"), Level::Fail);
    assert_eq!(level_of("nofile-low"), Level::Fail);
    assert_eq!(level_of("nofile-dropin-wins"), Level::Pass);
    assert_eq!(level_of("nofile-above-nr-open"), Level::Fail);
    assert_eq!(level_of("hostile-live"), Level::Fail);
}

#[test]
fn a_wildcard_line_covers_a_key_and_a_minus_line_takes_it_out() {
    let run = run_case("glob-and-exclusion");
    let finding = run.finding();
    let eth0 = &finding.observed["parameters"]["net.ipv4.conf.eth0.rp_filter"];
    let lo = &finding.observed["parameters"]["net.ipv4.conf.lo.rp_filter"];
    assert_eq!(eth0["state"], "ok");
    assert_eq!(eth0["persisted"]["file"], "/etc/sysctl.d/10-net.conf");
    assert_eq!(lo["state"], "not_persisted");
}

#[test]
fn a_name_with_slashes_and_a_file_with_dots_are_one_key() {
    let run = run_case("vlan-interface");
    assert_eq!(
        run.finding().level,
        Level::Pass,
        "{}",
        run.finding().message
    );
}

// ---- no privilege --------------------------------------------------------------------------------

#[test]
fn an_unreadable_parameter_is_not_verified_and_never_blocks() {
    let run = run_case("unreadable-parameter");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("could not be read (permission denied)")
    );
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("sysctl -n vm.max_map_count"))
    );
    let partial = finding.partial.as_ref().expect("partial");
    assert!(
        partial.note.starts_with("Not verified:"),
        "{}",
        partial.note
    );
}

#[test]
fn an_unreadable_sysctl_d_is_not_verified_and_never_blocks() {
    let run = run_case("unreadable-sysctl-d");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("whether it survives a reboot is not verified"),
        "{}",
        finding.message
    );
    assert!(finding.partial.is_some());
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.starts_with("Not read: /etc/sysctl.d")),
        "{:?}",
        finding.notes
    );
}

// ---- limits --------------------------------------------------------------------------------------

#[test]
fn nothing_setting_the_limit_leaves_the_built_in_default() {
    let run = run_case("nofile-built-in");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .contains("No file sets `DefaultLimitNOFILE`")
    );
    assert_eq!(
        finding.observed["limits"]["nofile"]["source"],
        "built-in default"
    );
    // The shell limit is shown and labelled.
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("is a shell limit and does not apply to services")),
        "{:?}",
        finding.notes
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("LimitNOFILE=65536"), "{fix}");
    assert!(fix.contains("systemctl daemon-reexec"), "{fix}");
}

#[test]
fn a_low_soft_limit_in_a_drop_in_blocks() {
    let run = run_case("nofile-low");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .contains("in `/etc/systemd/system.conf.d/10-defaults.conf` gives services an open files limit of 1024"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["limits"]["nofile"]["soft"], 1024);
    assert_eq!(finding.observed["limits"]["nofile"]["hard"], 524_288);
}

#[test]
fn drop_ins_apply_by_name_and_a_same_name_file_in_etc_hides_the_lower_one() {
    // 10-vendor.conf in /usr/lib sets 4096 but /etc has a file of that name. 20-acme.conf comes last.
    let run = run_case("nofile-dropin-wins");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Pass, "{}", finding.message);
    assert_eq!(
        finding.observed["limits"]["nofile"]["default_limit_nofile"],
        "65536:infinity"
    );
    assert_eq!(
        finding.observed["limits"]["nofile"]["file"],
        "/etc/systemd/system.conf.d/20-acme.conf"
    );
}

#[test]
fn a_limit_above_the_kernel_ceiling_cannot_be_set() {
    let run = run_case("nofile-above-nr-open");
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("`fs.nr_open` is 1048576"),
        "{}",
        finding.message
    );
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(fix.contains("fs.nr_open = 2097152"), "{fix}");
}

// ---- hostile text --------------------------------------------------------------------------------

#[test]
fn a_spec_value_with_shell_syntax_is_never_pasted_into_a_command() {
    let hostile = "x'; touch /tmp/pwn; '";
    let entry = json!({"id": "host.sysctl", "expect": {"vm.max_map_count": hostile}});
    let run = run_with(&load("wrong-live"), sysctl(&entry));
    let finding = run.finding();
    assert_eq!(finding.level, Level::Fail);
    let fix = finding.fix.as_deref().expect("a fix");
    assert!(!fix.contains("touch"), "{fix}");
    assert!(!fix.contains("echo"), "{fix}");
    assert!(fix.contains("the value the spec asks for"), "{fix}");
}

#[test]
fn a_live_value_with_an_escape_and_a_backtick_is_shown_escaped() {
    let run = run_case("hostile-live");
    let finding = run.finding();
    assert!(finding.message.contains("\\x1b[2J"), "{}", finding.message);
    assert!(!finding.message.contains('\u{1b}'));
    // The evidence is escaped too, so no escape byte reaches a report or a terminal.
    let live = finding.observed["parameters"]["net.ipv4.tcp_congestion_control"]["live"]
        .as_str()
        .expect("text");
    assert_eq!(live, "bbr\\x1b[2J`touch x`");
    // A backtick would end the code span, so the value is shown without the wrapping.
    assert!(
        finding.message.contains("bbr\\x1b[2J`touch x`, need cubic"),
        "{}",
        finding.message
    );
}

// ---- manifest, log and fix text ------------------------------------------------------------------

#[test]
fn a_run_stays_inside_the_manifest_and_only_reads() {
    for (case, _) in cases() {
        let result = run_case(case);
        assert!(result.outcome().is_ok(), "{case}: {:?}", result.outcome());
        for action in &result.log.actions {
            assert!(
                matches!(
                    action.kind,
                    ActionKind::Read | ActionKind::ReadDir | ActionKind::Native
                ),
                "{case}: {:?}",
                action.kind
            );
            if action.kind == ActionKind::Native {
                assert_eq!(
                    action.fields.get("api").and_then(Value::as_str),
                    Some("rlimit"),
                    "{case}"
                );
            }
            if case != "null-mask" {
                assert_ne!(action.outcome, ActionOutcome::Denied, "{case}: {action:?}");
            }
        }
        assert_within_manifest(case, &INFO, &result.log);
    }
    assert!(INFO.needs.is_empty() && INFO.wants.is_empty());
    assert!(INFO.commands.is_empty() && INFO.env.is_empty() && INFO.peers.is_empty());
    assert!(INFO.statfs.is_empty());
}

#[test]
fn the_check_reads_no_command_and_stays_under_the_timeout() {
    assert_eq!(
        INFO.default_timeout,
        Some(std::time::Duration::from_secs(2))
    );
}

#[test]
fn every_fix_the_cases_produce_passes_the_fix_text_audit() {
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("the remediation is not on the lists: {error}");
    }
    for (case, _) in cases() {
        let result = run_case(case);
        let finding = result.finding();
        // A parameter name comes from the spec, so it is not on the reviewed list. The audit reads
        // the template, and `vm.max_map_count` stands for any name in it.
        let names: Vec<String> = entry_of(case)["expect"]
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        for text in finding.fix.iter().chain(&finding.notes) {
            let text = names.iter().fold(text.clone(), |t, name| {
                t.replace(name.as_str(), "vm.max_map_count")
            });
            if let Err(error) = rdy_engine::fixtext::check(&text) {
                panic!("{case}: fix text is not on the lists: {error}\n{text}");
            }
        }
    }
}

#[test]
fn a_non_linux_run_is_not_yet_on_this_os() {
    use rdy_engine::check::Os;
    let fixture = load("pass");
    let test_run = TestRun::for_fixture(&fixture);
    let ctx = test_run.context_for(
        &INFO,
        "host.sysctl",
        Os::Macos,
        Vec::<rdy_engine::check::Need>::new(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(sysctl(&entry_of("pass")).run(&ctx));
    assert!(
        matches!(outcome, Err(CheckError::Unsupported(_))),
        "{outcome:?}"
    );
    assert!(
        test_run.action_log().actions.is_empty(),
        "nothing is read on macOS"
    );
}
