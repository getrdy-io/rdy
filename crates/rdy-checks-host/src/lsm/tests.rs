//! Tests of `host.lsm` against the synthetic machines under `tests/fixtures/checks/host.lsm/` (the 08
//! format, read by the Replay fixture loader).
//!
//! Every machine is a hand-written guess at a system, with invented names and times. No line comes
//! from a real host. The clock is fixed at 1730000000, so the 24 hour window starts at 1729913600.

use rdy_engine::check::{Check, Finding, Level, Need, Os, Support};
use rdy_engine::testing::{Fixture, Replay, TestRun, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

const NOW: u64 = 1_730_000_000;

/// A check built the way the family builds it, from the parameters of a spec entry.
fn check(params: Value) -> Lsm {
    let mut entry = json!({"id": "host.lsm"});
    if let (Some(into), Some(from)) = (entry.as_object_mut(), params.as_object()) {
        into.extend(from.clone());
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("an entry");
    let CheckParams::HostLsm(params) = entry.decode_params() else {
        panic!("not host.lsm parameters");
    };
    Lsm::new(&params).at(NOW)
}

/// What one run produced and what it did to the machine.
struct Ran {
    outcome: CheckOutcome,
    run: TestRun,
}

impl Ran {
    fn finding(&self) -> &Finding {
        self.outcome.as_ref().expect("a finding")
    }

    /// The path of every file call the run made, with its outcome.
    fn calls(&self) -> Vec<(String, ActionOutcome)> {
        self.run
            .action_log()
            .actions
            .iter()
            .filter_map(|a| {
                let path = a.fields.get("path").and_then(Value::as_str)?;
                Some((path.to_owned(), a.outcome.clone()))
            })
            .collect()
    }

    fn read(&self, path: &str) -> bool {
        self.calls().iter().any(|(p, _)| p == path)
    }
}

use rdy_engine::check::CheckOutcome;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
        .block_on(future)
}

fn execute(replay: Replay, needs: Vec<Need>, os: Os, lsm: &Lsm) -> Ran {
    let run = TestRun::new(replay);
    let ctx = run.context_for(&INFO, "host.lsm", os, needs);
    let outcome = block_on(lsm.run(&ctx));
    Ran { outcome, run }
}

fn case(name: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.lsm/{name}"))
        .expect("the fixture loads");
    fixture.ensure_answers("host.lsm").expect("it answers");
    fixture
}

fn run_case(name: &str, params: Value) -> Ran {
    let fixture = case(name);
    execute(
        fixture.replay().clone(),
        fixture.available_needs(),
        fixture.os(),
        &check(params),
    )
}

const CASES: [&str; 16] = [
    "enforcing-clean",
    "enforcing-watched-denials",
    "enforcing-other-denials",
    "enforcing-root-less",
    "enforcing-no-audit-log",
    "permissive-config-enforcing",
    "disabled",
    "masked-mount",
    "container-marker",
    "apparmor-profile-loaded",
    "apparmor-profile-missing",
    "apparmor-root-less",
    "apparmor-container",
    "apparmor-off",
    "container-overlay-root",
    "enforcing-hostile-avc",
];

// ---- the exit tests ------------------------------------------------------------------------------

#[test]
fn enforcing_with_two_denials_for_a_watched_context_blocks() {
    let ran = run_case(
        "enforcing-watched-denials",
        json!({"selinux": {"allow": ["enforcing"], "watch": ["acme_t"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "SELinux is enforcing and denied 2 actions in the last 24h for acme_t."
    );
    assert!(f.partial.is_none());
    // The third denial is three days old and outside the window.
    let denials = &f.observed["selinux"]["denials"];
    assert_eq!(denials["count"], 2);
    assert_eq!(denials["watched"], json!({"acme_t": 2}));
    assert_eq!(denials["window_truncated"], false);
    assert_eq!(
        denials["groups"],
        json!([{"source": "acme_t", "target": "var_lib_t", "class": "file", "count": 2}])
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("`ausearch -m avc -ts yesterday`"), "{fix}");
    assert!(
        fix.contains("`chcon -Rt container_file_t <volume path>`"),
        "{fix}"
    );
    assert!(fix.contains("`setenforce 0`"), "{fix}");
    assert!(fix.contains("ask the security team first"), "{fix}");
    assert!(
        fix.contains(
            "The `chcon` label does not survive a relabel. Ask the vendor for the persistent rule."
        ),
        "{fix}"
    );
}

#[test]
fn an_unreadable_audit_log_gives_partial() {
    let ran = run_case(
        "enforcing-root-less",
        json!({"selinux": {"allow": ["enforcing"], "watch": ["acme_t"]}}),
    );
    let f = ran.finding();
    // The mode is fine. The denials were not looked at, which the engine turns into a warning.
    assert_eq!(f.level, Level::Pass, "{f:?}");
    let partial = f.partial.as_ref().expect("partial");
    assert_eq!(partial.missing, vec![Need::Root]);
    assert_eq!(
        partial.note,
        "SELinux denials were not inspected: the audit log needs root."
    );
    assert_eq!(f.observed["selinux"]["state"], "enforcing");
    assert_eq!(
        f.observed["selinux"]["denials"],
        json!({"inspected": false, "why": "needs root"})
    );
    // The modes were read, the log was asked for and refused by the machine, not by rdy's policy.
    assert!(
        ran.calls()
            .contains(&("/var/log/audit/audit.log".to_owned(), ActionOutcome::Failed))
    );
}

#[test]
fn a_masked_selinux_directory_says_not_visible() {
    for name in ["masked-mount", "container-marker", "container-overlay-root"] {
        let ran = run_case(name, json!({"selinux": {"allow": ["enforcing"]}}));
        let f = ran.finding();
        assert_eq!(f.level, Level::Warn, "{name}: {f:?}");
        assert_eq!(
            f.message, "SELinux is not visible from here, so its mode cannot be checked.",
            "{name}"
        );
        assert_eq!(f.observed["selinux"]["state"], "not visible", "{name}");
        assert!(
            f.notes
                .iter()
                .any(|n| n.starts_with("SELinux is not visible: ")),
            "{name}: {:?}",
            f.notes
        );
        // Not visible is not disabled: nothing said "disabled" and no audit log was read.
        assert!(!f.message.contains("disabled"), "{name}");
        assert!(!ran.read("/var/log/audit/audit.log"), "{name}");
    }
}

#[test]
fn the_two_ways_to_see_a_mask_give_different_reasons() {
    let mount = run_case("masked-mount", json!({}));
    let why = mount.finding().observed["selinux"]["why"]
        .as_str()
        .expect("why")
        .to_owned();
    assert!(why.contains("covered by a tmpfs mount"), "{why}");
    let marker = run_case("container-marker", json!({}));
    let why = marker.finding().observed["selinux"]["why"]
        .as_str()
        .expect("why")
        .to_owned();
    assert!(why.contains("/run/.containerenv exists"), "{why}");
    // containerd and CRI-O leave neither a marker nor a mask, only an overlay root.
    let overlay = run_case("container-overlay-root", json!({}));
    let why = overlay.finding().observed["selinux"]["why"]
        .as_str()
        .expect("why")
        .to_owned();
    assert!(why.contains("root file system is an overlay"), "{why}");
}

#[test]
fn denials_asked_on_a_host_that_cannot_be_seen_warn_and_say_not_inspected() {
    for name in ["masked-mount", "container-overlay-root"] {
        for (params, message) in [
            (
                json!({"selinux": {"watch": ["acme_t"]}}),
                "SELinux is not visible from here, so its denials cannot be checked.",
            ),
            (
                json!({"selinux": {"allow": ["enforcing"], "denials_max": 1}}),
                "SELinux is not visible from here, so its mode and denials cannot be checked.",
            ),
        ] {
            let ran = run_case(name, params);
            let f = ran.finding();
            assert_eq!(f.level, Level::Warn, "{name}: {f:?}");
            assert_eq!(f.message, message, "{name}");
            assert_eq!(
                f.observed["selinux"]["denials"]["inspected"], false,
                "{name}: {f:?}"
            );
            assert!(!ran.read("/var/log/audit/audit.log"), "{name}");
        }
    }
    // A spec that asks for neither stays a pass with a note.
    let ran = run_case("masked-mount", json!({"selinux": {}}));
    assert_eq!(ran.finding().level, Level::Pass);
}

#[test]
fn an_unreadable_selinux_state_with_denials_asked_warns() {
    let replay = Replay::new().file("/sys/fs/selinux/enforce", "maybe\n");
    let ran = execute(
        replay,
        vec![Need::Root],
        Os::Linux,
        &check(json!({"selinux": {"denials_window": "7d"}})),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.message,
        "The SELinux state could not be read, so its denials cannot be checked."
    );
    assert_eq!(f.observed["selinux"]["denials"]["inspected"], false);
}

#[test]
fn a_fake_mount_type_is_not_repeated_in_the_message() {
    let mountinfo = "1 0 0:1 / / rw - xfs /dev/sda rw\n\
        2 1 0:2 / /sys/fs/selinux rw - fuse.\u{1b}[31mevil x rw\n";
    let replay = Replay::new().file("/proc/self/mountinfo", mountinfo);
    let ran = execute(
        replay,
        vec![],
        Os::Linux,
        &check(json!({"selinux": {"allow": ["enforcing"]}})),
    );
    let f = ran.finding();
    let why = f.observed["selinux"]["why"].as_str().expect("why");
    assert!(why.contains("covered by another file system,"), "{why}");
    assert!(!why.contains("evil") && !why.contains('\u{1b}'), "{why}");
}

// ---- SELinux modes -------------------------------------------------------------------------------

#[test]
fn a_bare_spec_reports_and_passes() {
    for name in CASES {
        let ran = run_case(name, json!({}));
        let f = ran.finding();
        assert_eq!(f.level, Level::Pass, "{name}: {f:?}");
        assert!(f.partial.is_none(), "{name}");
        assert!(f.fix.is_none(), "{name}");
        assert!(
            !ran.read("/var/log/audit/audit.log"),
            "{name}: no rule, no audit log"
        );
        assert!(
            !ran.read("/sys/kernel/security/apparmor/profiles"),
            "{name}"
        );
    }
    let f = run_case("enforcing-clean", json!({}));
    assert_eq!(
        f.finding().message,
        "SELinux is enforcing. AppArmor is off."
    );
    assert_eq!(f.finding().expected, json!({}));
}

#[test]
fn a_clean_log_passes_and_an_old_denial_is_outside_the_window() {
    let ran = run_case(
        "enforcing-clean",
        json!({"selinux": {"allow": ["enforcing"], "watch": ["acme_t"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "SELinux is enforcing. AppArmor is off.");
    assert_eq!(f.observed["selinux"]["denials"]["count"], 0);
    assert_eq!(f.expected["selinux"]["denials_max"], 0);
    assert_eq!(f.expected["selinux"]["denials_window"], "24h");

    // A wider window reaches the old denial.
    let ran = run_case(
        "enforcing-clean",
        json!({"selinux": {"denials_window": "7d", "watch": ["acme_t"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert!(
        f.message
            .contains("denied 1 action in the last 7d for acme_t"),
        "{}",
        f.message
    );
    assert!(f.fix.as_deref().is_some_and(|x| x.contains("-ts week-ago")));
}

#[test]
fn denials_that_name_no_watched_context_warn() {
    let ran = run_case(
        "enforcing-other-denials",
        json!({"selinux": {"watch": ["acme_t"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.message,
        "SELinux is enforcing and denied 3 actions in the last 24h for container_t."
    );
    assert_eq!(f.observed["selinux"]["denials"]["permissive"], 1);
    assert_eq!(f.observed["selinux"]["denials"]["watched"], json!({}));
    assert!(
        f.notes
            .iter()
            .any(|n| n.starts_with("1 of the denials were logged in permissive mode")),
        "{:?}",
        f.notes
    );
}

#[test]
fn denials_max_is_the_line_between_pass_and_warn() {
    let at = |max: u32| {
        run_case(
            "enforcing-other-denials",
            json!({"selinux": {"denials_max": max}}),
        )
    };
    assert_eq!(at(2).finding().level, Level::Warn);
    assert_eq!(at(3).finding().level, Level::Pass);
    assert_eq!(at(3).finding().observed["selinux"]["denials"]["count"], 3);
}

#[test]
fn a_permissive_host_whose_config_says_enforcing() {
    let name = "permissive-config-enforcing";
    let ran = run_case(name, json!({"selinux": {"allow": ["enforcing"]}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "SELinux is permissive, and the spec allows enforcing."
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("`setenforce 1`"), "{fix}");
    assert_eq!(f.observed["selinux"]["configured"], "enforcing");

    // Both are allowed: it passes, and the note says the next boot changes the mode.
    let ran = run_case(
        name,
        json!({"selinux": {"allow": ["enforcing", "permissive"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("The next boot applies the configured mode")),
        "{:?}",
        f.notes
    );

    // Permissive is allowed and enforcing is not: fine now, wrong after a reboot.
    let ran = run_case(name, json!({"selinux": {"allow": ["permissive"]}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message
            .contains("which the spec does not allow after a reboot"),
        "{}",
        f.message
    );
}

#[test]
fn a_disabled_host_is_a_pass_by_absence_when_the_spec_allows_it() {
    let ran = run_case(
        "disabled",
        json!({"selinux": {"allow": ["permissive", "disabled"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "SELinux is disabled. The spec allows that.");
    assert!(
        !ran.read("/var/log/audit/audit.log"),
        "a disabled host has no denials to read"
    );

    let ran = run_case("disabled", json!({"selinux": {"allow": ["enforcing"]}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "SELinux is disabled, and the spec allows enforcing."
    );
    assert!(
        f.fix
            .as_deref()
            .is_some_and(|x| x.contains("`SELINUX=enforcing`"))
    );
}

#[test]
fn an_empty_allow_list_accepts_no_mode() {
    let ran = run_case("enforcing-clean", json!({"selinux": {"allow": []}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert!(
        f.message
            .contains("the spec's allow list is empty, so no mode is accepted"),
        "{}",
        f.message
    );
    assert_eq!(
        f.fix.as_deref(),
        Some("Ask the vendor to fix the spec's allow list."),
        "the fix points at the spec"
    );
    let ran = run_case(
        "apparmor-profile-loaded",
        json!({"apparmor": {"allow": []}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert!(f.message.contains("no state is accepted"), "{}", f.message);
    assert_eq!(
        f.fix.as_deref(),
        Some("Ask the vendor to fix the spec's allow list.")
    );
}

#[test]
fn no_audit_log_is_a_note_unless_the_spec_asked_about_denials() {
    let ran = run_case(
        "enforcing-no-audit-log",
        json!({"selinux": {"allow": ["enforcing"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("denials were not inspected")),
        "{:?}",
        f.notes
    );
    assert!(f.partial.is_none());

    let ran = run_case(
        "enforcing-no-audit-log",
        json!({"selinux": {"denials_max": 0}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.message,
        "SELinux denials were not inspected: there is no audit log."
    );
    assert!(
        f.fix
            .as_deref()
            .is_some_and(|x| x.contains("`systemctl enable --now auditd`"))
    );
}

#[test]
fn an_unreadable_log_as_root_follows_the_same_rule_as_a_missing_log() {
    let fixture = case("enforcing-root-less");
    let run = |params: Value| {
        execute(
            fixture.replay().clone(),
            vec![Need::Root],
            Os::Linux,
            &check(params),
        )
    };
    // The spec asked about denials: a warning, not a partial.
    let ran = run(json!({"selinux": {"allow": ["enforcing"], "denials_max": 0}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message
            .contains("could not be read as root (permission denied)"),
        "{}",
        f.message
    );
    assert!(f.partial.is_none());
    assert!(
        f.fix
            .as_deref()
            .is_some_and(|x| x.contains("`ausearch -m avc -ts yesterday`"))
    );

    // The spec did not: a note, as for a missing log.
    let ran = run(json!({"selinux": {"allow": ["enforcing"]}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(f.partial.is_none());
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("could not be read as root (permission denied)")),
        "{:?}",
        f.notes
    );
    assert_eq!(
        f.observed["selinux"]["denials"]["inspected"], false,
        "{f:?}"
    );
}

// ---- the audit log window ------------------------------------------------------------------------

/// `n` filler records, each about 1 KiB, all stamped `at`.
fn filler(n: usize, at: u64) -> String {
    let pad = "x".repeat(900);
    (0..n)
        .map(|i| {
            format!(
                "type=SYSCALL msg=audit({at}.{:03}:{i}): arch=c000003e syscall=2 comm=\"filler\" key=\"{pad}\"\n",
                i % 1000
            )
        })
        .collect()
}

fn avc_line(at: u64, id: u64) -> String {
    format!(
        "type=AVC msg=audit({at}.100:{id}): avc:  denied  {{ read }} for  pid=9 comm=\"worker\" scontext=system_u:system_r:acme_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=0\n"
    )
}

fn big_log_machine(log: String) -> Replay {
    Replay::new()
        .file("/sys/fs/selinux/enforce", "1\n")
        .file("/var/log/audit/audit.log", log)
}

#[test]
fn a_log_that_does_not_reach_back_to_the_window_says_truncated() {
    // 1500 records of 1 KiB, all inside the window, so the 1 MiB tail starts inside it too.
    let log = format!("{}{}", filler(1500, NOW - 3600), avc_line(NOW - 60, 7));
    let ran = execute(
        big_log_machine(log),
        vec![Need::Root],
        Os::Linux,
        &check(json!({"selinux": {"watch": ["acme_t"]}})),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.observed["selinux"]["denials"]["window_truncated"], true);
    assert!(
        f.notes.iter().any(|n| n.starts_with(
            "Window truncated: the last 1 MiB of the audit log reaches back 1h 0m, not 24h."
        )),
        "{:?}",
        f.notes
    );
}

#[test]
fn a_cut_log_that_still_reaches_the_window_start_is_not_truncated() {
    // The first 700 records are two days old. The tail keeps some of them, so it reaches past the
    // start of the window.
    let log = format!(
        "{}{}{}",
        filler(700, NOW - 172_800),
        filler(800, NOW - 3600),
        avc_line(NOW - 60, 7)
    );
    let ran = execute(
        big_log_machine(log),
        vec![Need::Root],
        Os::Linux,
        &check(json!({"selinux": {"watch": ["acme_t"]}})),
    );
    let f = ran.finding();
    assert_eq!(
        f.observed["selinux"]["denials"]["window_truncated"], false,
        "{f:?}"
    );
    assert_eq!(f.observed["selinux"]["denials"]["count"], 1);
    assert!(!f.notes.iter().any(|n| n.starts_with("Window truncated")));
}

#[test]
fn a_small_log_is_never_truncated() {
    let log = format!("{}{}", filler(3, NOW - 100), avc_line(NOW - 60, 7));
    let ran = execute(
        big_log_machine(log),
        vec![Need::Root],
        Os::Linux,
        &check(json!({"selinux": {}})),
    );
    assert_eq!(
        ran.finding().observed["selinux"]["denials"]["window_truncated"],
        false
    );
}

// ---- evidence ------------------------------------------------------------------------------------

#[test]
fn evidence_holds_no_user_name_file_name_or_command_from_the_log() {
    let ran = run_case(
        "enforcing-watched-denials",
        json!({"selinux": {"watch": ["acme_t"]}}),
    );
    let f = ran.finding();
    let everything = format!("{f:?}");
    for secret in [
        "svc-acme-ops",
        "license.dat",
        "/opt/acme",
        "grantors",
        "1048601",
    ] {
        assert!(
            !everything.contains(secret),
            "{secret} reached the finding: {everything}"
        );
    }
}

#[test]
fn hostile_text_in_an_audit_line_never_reaches_the_finding() {
    let ran = run_case(
        "enforcing-hostile-avc",
        json!({"selinux": {"watch": ["acme_t"]}}),
    );
    let f = ran.finding();
    // The first line is a real denial for acme_t. The second still counts, but its bad type and class
    // are shown as `unknown`.
    assert_eq!(f.level, Level::Fail, "{f:?}");
    let denials = &f.observed["selinux"]["denials"];
    assert_eq!(denials["count"], 2, "{f:?}");
    assert_eq!(denials["watched"], json!({"acme_t": 1}));
    assert!(
        denials["groups"].as_array().is_some_and(|groups| groups
            .iter()
            .any(|g| g["source"] == "unknown" && g["class"] == "unknown")),
        "{f:?}"
    );
    let everything = format!(
        "{f:?} {} {} {}",
        f.observed,
        f.message,
        f.fix.as_deref().unwrap_or_default()
    );
    for bad in ['\u{1b}', '\u{7}', '\u{202e}'] {
        assert!(!everything.contains(bad), "{bad:?} reached the finding");
    }
    for bad in [
        "\\u{1b}",
        "\\u{202e}",
        "\\u001b",
        "evil",
        "gnp.exe",
        "AAAAAAAAAAAAAAAA",
    ] {
        assert!(!everything.contains(bad), "{bad:?} reached the finding");
    }
    assert!(everything.len() < 8192, "{}", everything.len());
}

// ---- AppArmor ------------------------------------------------------------------------------------

const REQUIRE: fn() -> Value =
    || json!({"apparmor": {"allow": ["enabled"], "require_profiles": ["acme-agent"]}});

#[test]
fn a_loaded_required_profile_passes() {
    let ran = run_case("apparmor-profile-loaded", REQUIRE());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "SELinux is disabled. AppArmor is on.");
    assert_eq!(
        f.observed["apparmor"]["profiles"],
        json!({"loaded": 4, "enforce": 3, "complain": 1})
    );
    assert_eq!(
        f.observed["apparmor"]["required_profiles"]["missing"],
        json!([])
    );
}

#[test]
fn a_missing_required_profile_blocks() {
    let ran = run_case("apparmor-profile-missing", REQUIRE());
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.message, "The AppArmor profile acme-agent is not loaded.");
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("`apparmor_parser -r <profile file>`"), "{fix}");
    assert_eq!(
        f.observed["apparmor"]["required_profiles"]["missing"],
        json!(["acme-agent"])
    );
}

#[test]
fn an_unreadable_profile_list_gives_partial() {
    let ran = run_case("apparmor-root-less", REQUIRE());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    let partial = f.partial.as_ref().expect("partial");
    assert_eq!(partial.missing, vec![Need::Root]);
    assert_eq!(
        partial.note,
        "The AppArmor profile list was not read: it needs root."
    );
}

#[test]
fn both_modules_can_need_root_in_one_partial() {
    let fixture = case("apparmor-root-less");
    // Add SELinux files whose audit log is refused.
    let replay = fixture
        .replay()
        .clone()
        .file("/sys/fs/selinux/enforce", "1\n")
        .file("/var/log/audit/audit.log", "")
        .unreadable("/var/log/audit/audit.log");
    let mut params = REQUIRE();
    params["selinux"] = json!({"watch": ["acme_t"]});
    let ran = execute(replay, vec![], Os::Linux, &check(params));
    let f = ran.finding();
    let partial = f.partial.as_ref().expect("partial");
    assert_eq!(partial.missing, vec![Need::Root]);
    assert!(
        partial.note.contains("audit log needs root"),
        "{}",
        partial.note
    );
    assert!(
        partial.note.contains("profile list was not read"),
        "{}",
        partial.note
    );
}

#[test]
fn a_profile_list_that_is_not_mounted_is_not_visible() {
    let ran = run_case("apparmor-container", REQUIRE());
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("not visible from here"), "{}", f.message);
    assert!(f.partial.is_none());
}

#[test]
fn apparmor_off_is_a_pass_by_absence_only_when_allowed() {
    let ran = run_case("disabled", json!({"apparmor": {"allow": ["disabled"]}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "AppArmor is off. The spec allows that.");

    let ran = run_case("disabled", json!({"apparmor": {"allow": ["enabled"]}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "AppArmor is disabled, and the spec allows enabled."
    );
    assert!(
        f.fix
            .as_deref()
            .is_some_and(|x| x.contains("`systemctl enable --now apparmor`"))
    );

    // A profile cannot be loaded while AppArmor is off.
    let ran = run_case(
        "disabled",
        json!({"apparmor": {"require_profiles": ["acme-agent"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert!(
        f.message
            .contains("AppArmor is off, so the required profile cannot be loaded"),
        "{}",
        f.message
    );
}

#[test]
fn an_apparmor_host_with_apparmor_forbidden() {
    let ran = run_case(
        "apparmor-profile-loaded",
        json!({"apparmor": {"allow": ["disabled"]}}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "AppArmor is enabled, and the spec allows disabled."
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("`apparmor=0`"), "{fix}");
    assert!(
        fix.contains("This turns AppArmor protection off, so ask the security team first."),
        "{fix}"
    );
}

#[test]
fn a_kernel_without_the_apparmor_file_reads_as_off() {
    let ran = run_case("apparmor-off", json!({"apparmor": {"allow": ["disabled"]}}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.observed["apparmor"]["state"], "disabled");
    assert_eq!(f.message, "AppArmor is off. The spec allows that.");
    let ran = run_case("apparmor-off", json!({"apparmor": {"allow": ["enabled"]}}));
    assert_eq!(ran.finding().level, Level::Fail);
}

// ---- the machine ---------------------------------------------------------------------------------

#[test]
fn the_check_reads_only_what_it_declares_and_is_never_refused() {
    // The probe applies the real read policy and the declared `reads`: a path outside them is
    // `Denied` and ends the check with an error, so `is_ok` and the outcome below prove both.
    for name in CASES {
        for params in [
            json!({}),
            json!({"selinux": {"allow": ["enforcing"], "watch": ["acme_t"]}, "apparmor": REQUIRE()["apparmor"]}),
        ] {
            let ran = run_case(name, params);
            assert!(ran.outcome.is_ok(), "{name}: {:?}", ran.outcome);
            for action in ran.run.action_log().actions {
                assert_ne!(action.outcome, ActionOutcome::Denied, "{name}: {action:?}");
                assert!(
                    matches!(
                        action.kind,
                        ActionKind::Read | ActionKind::Stat | ActionKind::ReadDir
                    ),
                    "{name}: {action:?}"
                );
            }
        }
    }
}

#[test]
fn the_audit_log_is_read_from_its_tail_and_never_whole() {
    let ran = run_case("enforcing-clean", json!({"selinux": {}}));
    let log = ran.run.action_log();
    let call = log
        .actions
        .iter()
        .find(|a| a.fields.get("path").and_then(Value::as_str) == Some("/var/log/audit/audit.log"))
        .expect("the log was read");
    // Bounded: the bytes returned fit in the 1 MiB tail.
    let bytes = call
        .fields
        .get("bytes")
        .and_then(Value::as_u64)
        .expect("bytes");
    assert!(bytes > 0 && bytes <= 1 << 20, "{bytes}");
}

#[test]
fn every_message_and_fix_the_cases_produce_passes_the_fix_text_audit() {
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("remediation: {error}");
    }
    let specs = [
        json!({}),
        json!({"selinux": {"allow": ["enforcing"], "watch": ["acme_t"], "denials_window": "7d"}}),
        json!({"selinux": {"allow": ["disabled"]}, "apparmor": {"allow": ["disabled"]}}),
        json!({"selinux": {"allow": []}, "apparmor": {"allow": [], "require_profiles": ["acme-agent"]}}),
        json!({"selinux": {"denials_max": 0}, "apparmor": REQUIRE()["apparmor"]}),
        json!({"selinux": {"allow": ["permissive"]}, "apparmor": {"allow": ["enabled"]}}),
        json!({"selinux": {"allow": ["enforcing"]}, "apparmor": {"allow": ["disabled"]}}),
    ];
    for name in CASES {
        for params in &specs {
            let ran = run_case(name, params.clone());
            let f = ran.finding();
            for text in f
                .fix
                .iter()
                .chain(std::iter::once(&f.message))
                .chain(&f.notes)
            {
                if let Err(error) = rdy_engine::fixtext::check(text) {
                    panic!("{name} {params}: {error}");
                }
            }
        }
    }
}

#[test]
fn the_declared_facts_match_the_catalog() {
    assert_eq!((INFO.id, INFO.family), ("host.lsm", "host"));
    assert_eq!(
        INFO.default_timeout,
        Some(std::time::Duration::from_secs(3))
    );
    assert!(INFO.needs.is_empty());
    assert_eq!(INFO.wants.len(), 1);
    assert_eq!(INFO.wants[0].need, Need::Root);
    assert!(!INFO.wants[0].evidence_only);
    assert_eq!(INFO.os.on(Os::Linux), Support::Full);
    assert_eq!(INFO.os.on(Os::Macos), Support::NotYet);
    assert!(INFO.reads.iter().all(|p| p.starts_with('/')));
    assert!(INFO.commands.is_empty() && INFO.peers.is_empty() && INFO.env.is_empty());
}

#[test]
fn on_another_os_it_has_no_data_source() {
    let fixture = case("enforcing-clean");
    for os in [Os::Macos, Os::Windows] {
        let ran = execute(fixture.replay().clone(), vec![], os, &check(json!({})));
        assert!(
            matches!(ran.outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {:?}",
            ran.outcome
        );
    }
}

#[test]
fn parameters_are_read_with_their_defaults() {
    let lsm =
        check(json!({"selinux": {"watch": ["acme_t"]}, "apparmor": {"require_profiles": ["a"]}}));
    let rule = lsm.selinux.expect("selinux rule");
    assert_eq!(rule.allow, None);
    assert_eq!(rule.denials_max, 0);
    assert_eq!(
        (rule.window_secs, rule.window_text.as_str()),
        (86_400, "24h")
    );
    assert!(rule.denials_asked);
    let aa = lsm.apparmor.expect("apparmor rule");
    assert_eq!(
        (aa.allow, aa.require_profiles),
        (None, vec!["a".to_owned()])
    );

    let rule = check(json!({"selinux": {"denials_window": "90m"}}))
        .selinux
        .expect("rule");
    assert_eq!(rule.window_secs, 5_400);
    let rule = check(json!({"selinux": {"allow": ["enforcing"]}}))
        .selinux
        .expect("rule");
    assert!(!rule.denials_asked);
    assert_eq!(check(json!({})), Lsm::default().at(NOW));
}
