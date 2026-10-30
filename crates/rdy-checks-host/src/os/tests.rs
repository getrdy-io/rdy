//! Tests of `host.os` against synthetic machines.
//!
//! The machines are the cases under `tests/fixtures/checks/host.os/` (the layout of
//! docs/plan/08-testing.md), loaded by the Replay fixture loader. The spec is built in each test from
//! JSON, as a spec entry would be, so one machine is judged against many lists.

use rdy_engine::check::{Check, CheckInfo, CheckOutcome, Finding, Need, Support};
use rdy_engine::testing::{Fixture, Replay, TestRun, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{ActionKind, ActionOutcome};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

/// Every machine under `tests/fixtures/checks/host.os/`.
const CASES: &[&str] = &[
    "rhel-9",
    "ubuntu-2204",
    "alpine",
    "rocky-9",
    "amazon-linux-2",
    "amazon-linux-2023",
    "linux-mint",
    "rhel-8-usr-lib",
    "rhel-9-fips",
    "ubuntu-docker",
    "ubuntu-wsl",
    "no-os-release",
];

fn machine(case: &str) -> Fixture {
    let fixture = Fixture::load(&fixtures_dir(), &format!("checks/host.os/{case}"))
        .unwrap_or_else(|e| panic!("{case}: {e}"));
    fixture.ensure_answers("host.os").expect("answers host.os");
    fixture
}

/// The check a spec entry with these keys builds.
fn check(keys: &Value) -> OsCheck {
    let mut entry = json!({"id": "host.os"});
    if let (Some(map), Some(extra)) = (entry.as_object_mut(), keys.as_object()) {
        map.extend(extra.clone());
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("an entry");
    let CheckParams::HostOs(params) = entry.decode_params() else {
        panic!("not host.os parameters");
    };
    OsCheck::from_params(&params)
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
}

fn info() -> &'static CheckInfo {
    OsCheck::default().info()
}

fn execute(replay: Replay, os: Os, check: &OsCheck) -> Ran {
    let run = TestRun::new(replay);
    let ctx = run.context_for(info(), "host.os", os, Vec::<Need>::new());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(check.run(&ctx));
    Ran { outcome, run }
}

fn run_case(case: &str, keys: &Value) -> Ran {
    execute(machine(case).replay().clone(), Os::Linux, &check(keys))
}

/// RHEL 8 and 9, Ubuntu 22.04: the list of 03.
fn rhel_ubuntu() -> Value {
    json!({"supported": [
        {"id": "rhel", "versions": ["8", "9"]},
        {"id": "ubuntu", "versions": ["22.04"]},
    ]})
}

fn level(case: &str, keys: &Value) -> Level {
    run_case(case, keys).finding().level
}

#[test]
fn the_six_named_machines_match_or_miss_the_list_as_the_rules_say() {
    let list = rhel_ubuntu();
    for (case, want) in [
        ("rhel-9", Level::Pass),
        ("ubuntu-2204", Level::Pass),
        ("rocky-9", Level::Pass),
        ("alpine", Level::Fail),
        ("amazon-linux-2", Level::Fail),
        ("linux-mint", Level::Fail),
    ] {
        let ran = run_case(case, &list);
        let f = ran.finding();
        assert_eq!(f.level, want, "{case}: {f:?}");
    }
}

#[test]
fn rocky_matches_rhel_through_id_like_and_says_so() {
    let ran = run_case("rocky-9", &rhel_ubuntu());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("rocky") && n.contains("ID_LIKE")),
        "{:?}",
        f.notes
    );
    // The version still counts: Rocky 9.3 is not RHEL 8.
    assert_eq!(
        level(
            "rocky-9",
            &json!({"supported": [{"id": "rhel", "versions": ["8"]}]})
        ),
        Level::Fail
    );
}

#[test]
fn amazon_linux_2_and_linux_mint_never_match_through_id_like() {
    // Amazon Linux 2 says ID_LIKE="centos rhel fedora" and its VERSION_ID is "2", which would match no
    // RHEL version. Mint says ID_LIKE="ubuntu debian" and its "21.3" is not an Ubuntu version.
    for (case, id) in [
        ("amazon-linux-2", "rhel"),
        ("amazon-linux-2", "centos"),
        ("linux-mint", "ubuntu"),
    ] {
        let ran = run_case(case, &json!({"supported": [{"id": id}]}));
        assert_eq!(ran.finding().level, Level::Fail, "{case} as {id}");
    }
    // A spec that lists the derived id does match, with or without versions.
    assert_eq!(
        level("linux-mint", &json!({"supported": [{"id": "linuxmint"}]})),
        Level::Pass
    );
    assert_eq!(
        level(
            "amazon-linux-2",
            &json!({"supported": [{"id": "amzn", "versions": ["2"]}]})
        ),
        Level::Pass
    );
    // "2" is a major match: it does not cover Amazon Linux 2023.
    assert_eq!(
        level(
            "amazon-linux-2023",
            &json!({"supported": [{"id": "amzn", "versions": ["2"]}]})
        ),
        Level::Fail
    );
    assert_eq!(
        level(
            "amazon-linux-2023",
            &json!({"supported": [{"id": "amzn", "versions": ["2023"]}]})
        ),
        Level::Pass
    );
}

#[test]
fn a_dotted_version_is_exact_and_a_bare_one_is_a_major_match() {
    for (case, versions, want) in [
        ("rhel-9", json!(["9"]), Level::Pass),
        ("rhel-9", json!(["9.2"]), Level::Pass),
        ("rhel-9", json!(["9.4"]), Level::Fail),
        ("rhel-9", json!(["8", "10"]), Level::Fail),
        ("alpine", json!(["3"]), Level::Pass),
        ("alpine", json!(["3.19.1"]), Level::Pass),
        // Exact, as 03 says: Alpine's VERSION_ID carries the patch level.
        ("alpine", json!(["3.19"]), Level::Fail),
    ] {
        let id = if case == "alpine" { "alpine" } else { "rhel" };
        let keys = json!({"supported": [{"id": id, "versions": versions}]});
        assert_eq!(level(case, &keys), want, "{case} {versions}");
    }
}

#[test]
fn a_miss_names_the_found_os_the_list_and_a_fix() {
    let ran = run_case("alpine", &rhel_ubuntu());
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(
        f.message.contains("Alpine Linux v3.19 (alpine 3.19.1)"),
        "{}",
        f.message
    );
    assert!(
        f.message.contains("rhel 8 or 9, ubuntu 22.04"),
        "{}",
        f.message
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("alpine 3.19.1"), "{fix}");
    assert_eq!(f.expected["supported"][0]["id"], "rhel");
    assert_eq!(f.observed["os"]["id"], "alpine");
    assert_eq!(f.observed["os"]["version_id"], "3.19.1");
    assert_eq!(f.observed["os"]["source"], "/etc/os-release");
    assert_eq!(f.observed["arch"], "x86_64");
    assert_eq!(f.observed["kernel"], "6.6.14-0-lts");
}

#[test]
fn usr_lib_os_release_is_the_fallback() {
    let ran = run_case("rhel-8-usr-lib", &rhel_ubuntu());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.observed["os"]["source"], "/usr/lib/os-release");
}

#[test]
fn no_os_release_is_a_warning_when_the_spec_lists_distros_and_a_pass_when_it_does_not() {
    let ran = run_case("no-os-release", &rhel_ubuntu());
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message.contains("Cannot tell which OS this is"),
        "{}",
        f.message
    );
    assert!(f.observed["os"].is_null());
    assert_eq!(level("no-os-release", &json!({})), Level::Pass);
}

#[test]
fn a_spec_with_no_keys_reports_what_it_found_and_passes() {
    for case in CASES {
        let ran = run_case(case, &json!({}));
        let f = ran.finding();
        assert_eq!(f.level, Level::Pass, "{case}: {f:?}");
        assert!(f.fix.is_none(), "{case}");
    }
    let f = run_case("rhel-9", &json!({})).outcome.expect("a finding");
    assert_eq!(
        f.message,
        "Found Red Hat Enterprise Linux 9.2 (Plow) on x86_64. The spec sets no OS requirement."
    );
}

#[test]
fn arch_accepts_both_spellings_and_blocks_the_other_architecture() {
    for (case, arch, want) in [
        ("rhel-9", json!(["x86_64"]), Level::Pass),
        ("rhel-9", json!(["amd64"]), Level::Pass),
        ("rhel-9", json!(["aarch64"]), Level::Fail),
        ("rhel-9", json!(["arm64", "amd64"]), Level::Pass),
        ("amazon-linux-2023", json!(["arm64"]), Level::Pass),
        ("amazon-linux-2023", json!(["x86_64"]), Level::Fail),
    ] {
        let ran = run_case(case, &json!({ "arch": arch }));
        let f = ran.finding();
        assert_eq!(f.level, want, "{case} {arch}: {f:?}");
        if want == Level::Fail {
            assert!(f.message.contains("The spec needs"), "{}", f.message);
        }
    }
}

#[test]
fn fips_mode_is_judged_and_the_fix_follows_the_distribution() {
    let on = run_case("rhel-9-fips", &json!({"fips": "forbid"}));
    let f = on.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(f.message, "FIPS mode is on, and the spec forbids it.");
    assert!(
        f.fix
            .as_deref()
            .expect("fix")
            .contains("fips-mode-setup --disable")
    );
    assert_eq!(f.observed["fips"], true);

    assert_eq!(
        level("rhel-9-fips", &json!({"fips": "require"})),
        Level::Pass
    );
    assert_eq!(level("rhel-9-fips", &json!({"fips": "any"})), Level::Pass);
    assert_eq!(level("rhel-9", &json!({"fips": "forbid"})), Level::Pass);

    let off = run_case("rhel-9", &json!({"fips": "require"}));
    let f = off.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(f.message, "FIPS mode is off, and the spec requires it.");
    assert!(
        f.fix
            .as_deref()
            .expect("fix")
            .contains("fips-mode-setup --enable")
    );

    let ubuntu = run_case("ubuntu-2204", &json!({"fips": "require"}));
    assert!(
        ubuntu
            .finding()
            .fix
            .as_deref()
            .expect("fix")
            .contains("pro enable fips-updates")
    );
    let alpine = run_case("alpine", &json!({"fips": "require"}));
    assert!(
        alpine
            .finding()
            .fix
            .as_deref()
            .expect("fix")
            .contains("OS vendor's procedure")
    );
}

#[test]
fn a_kernel_without_the_fips_file_counts_as_off_and_says_so() {
    let forbid = run_case("alpine", &json!({"fips": "forbid"}));
    let f = forbid.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(
        f.notes.iter().any(|n| n.contains("fips_enabled")),
        "{:?}",
        f.notes
    );
    assert_eq!(f.observed["fips"], Value::Null);
    assert_eq!(level("alpine", &json!({"fips": "require"})), Level::Fail);
}

#[test]
fn an_unreadable_fips_file_is_a_warning_not_a_guess() {
    let replay = machine("rhel-9")
        .replay()
        .clone()
        .unreadable("/proc/sys/crypto/fips_enabled");
    for fips in ["require", "forbid"] {
        let ran = execute(replay.clone(), Os::Linux, &check(&json!({ "fips": fips })));
        let f = ran.finding();
        assert_eq!(f.level, Level::Warn, "{fips}: {f:?}");
        assert!(f.message.contains("Cannot read FIPS mode"), "{}", f.message);
    }
}

#[test]
fn a_container_and_wsl_are_reported_in_the_evidence_and_the_notes_and_never_block() {
    let docker = run_case("ubuntu-docker", &rhel_ubuntu());
    let f = docker.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.observed["container"], json!(["docker", "kubernetes"]));
    assert!(
        f.notes.iter().any(|n| n.contains("docker and kubernetes")),
        "{:?}",
        f.notes
    );
    assert_eq!(f.observed["init"], "other");
    // The variable's value is a cluster address. It is recorded nowhere.
    assert!(!f.observed.to_string().contains("10.96.0.1"));
    for action in docker.run.action_log().actions {
        assert!(
            !action
                .fields
                .values()
                .any(|v| v.to_string().contains("10.96.0.1"))
        );
    }

    let wsl = run_case("ubuntu-wsl", &rhel_ubuntu());
    let f = wsl.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.observed["wsl"], true);
    assert!(f.notes.iter().any(|n| n.contains("WSL")), "{:?}", f.notes);

    let plain = run_case("rhel-9", &rhel_ubuntu());
    let f = plain.finding();
    assert_eq!(f.observed["container"], json!([]));
    assert_eq!(f.observed["wsl"], false);
    assert_eq!(f.observed["init"], "systemd");
    assert!(f.notes.is_empty(), "{:?}", f.notes);
}

#[test]
fn problems_add_up_and_the_worst_level_wins() {
    let keys = json!({
        "supported": [{"id": "rhel", "versions": ["9"]}],
        "arch": ["aarch64"],
        "fips": "require",
    });
    let ran = run_case("ubuntu-2204", &keys);
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    for part in [
        "is not supported",
        "The spec needs aarch64",
        "FIPS mode is off",
    ] {
        assert!(f.message.contains(part), "{part}: {}", f.message);
    }
    assert_eq!(f.expected["fips"], "require");
    assert_eq!(f.expected["arch"], json!(["aarch64"]));
}

/// The `no-os-release` machine with these files added.
fn bare_with(files: &[(&str, &str)]) -> Replay {
    let mut replay = machine("no-os-release").replay().clone();
    for (path, text) in files {
        replay = replay.file(*path, *text);
    }
    replay
}

#[test]
fn a_release_with_no_version_id_cannot_meet_a_versioned_entry() {
    let replay = bare_with(&[("/etc/os-release", "NAME=\"Arch Linux\"\nID=arch\n")]);
    let ran = execute(
        replay.clone(),
        Os::Linux,
        &check(&json!({"supported": [{"id": "arch", "versions": ["1"]}]})),
    );
    assert_eq!(ran.finding().level, Level::Warn, "{:?}", ran.finding());
    // With no versions listed it is a plain match.
    let ran = execute(
        replay,
        Os::Linux,
        &check(&json!({"supported": [{"id": "arch"}]})),
    );
    assert_eq!(ran.finding().level, Level::Pass);
}

#[test]
fn an_unreadable_os_release_falls_back_and_then_warns() {
    let text = "ID=rhel\nVERSION_ID=\"9.2\"\n";
    let list = check(&json!({"supported": [{"id": "rhel", "versions": ["9"]}]}));
    let with_usr = bare_with(&[("/etc/os-release", text), ("/usr/lib/os-release", text)])
        .unreadable("/etc/os-release");
    let ran = execute(with_usr, Os::Linux, &list);
    assert_eq!(ran.finding().level, Level::Pass);
    let without = bare_with(&[("/etc/os-release", text)]).unreadable("/etc/os-release");
    let ran = execute(without, Os::Linux, &list);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("permission denied"), "{}", f.message);
}

#[test]
fn a_file_that_is_not_an_os_release_is_a_warning() {
    let replay = bare_with(&[("/etc/os-release", "hello\nworld\n")]);
    let ran = execute(replay, Os::Linux, &check(&rhel_ubuntu()));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message.contains("holds none of ID, NAME"),
        "{}",
        f.message
    );
}

#[test]
fn a_known_secret_in_os_release_does_not_reach_the_result() {
    // os-release holds no secrets, but its text goes into a result, so it goes through the redactor
    // that removes the run's known secrets. The rest of the report is redacted again at the end.
    let secret = "REDACTED-TEST-TOKEN-0123456789";
    let text = format!("ID=acme\nPRETTY_NAME=\"Acme {secret}\"\nVERSION_ID=1\n");
    let replay = bare_with(&[("/etc/os-release", &text)]);
    let run = TestRun::new(replay);
    assert!(run.add_known_secret(secret));
    let ctx = run.context_for(info(), "host.os", Os::Linux, Vec::<Need>::new());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let f = runtime
        .block_on(check(&json!({})).run(&ctx))
        .expect("a finding");
    let all = format!("{} {} {:?}", f.message, f.observed, f.notes);
    assert!(!all.contains(secret), "{all}");
    assert!(all.contains("Acme"), "{all}");
}

#[test]
fn on_macos_and_windows_the_check_is_not_yet_on_this_os() {
    for os in [Os::Macos, Os::Windows] {
        let ran = execute(Replay::new(), os, &check(&rhel_ubuntu()));
        assert!(
            matches!(ran.outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {:?}",
            ran.outcome
        );
        assert!(ran.run.action_log().actions.is_empty());
    }
}

#[test]
fn every_case_stays_inside_the_manifest_and_only_reads() {
    // A path outside `reads`, an undeclared variable or a native call the policy refuses ends in a
    // `Denied` entry. A finding for every case, and no refused entry, proves the manifest covers what
    // the check does.
    let every_key = json!({
        "supported": [{"id": "rhel"}], "arch": ["x86_64"], "fips": "require",
    });
    for case in CASES {
        let ran = run_case(case, &every_key);
        assert!(ran.outcome.is_ok(), "{case}: {:?}", ran.outcome);
        let actions = ran.run.action_log().actions;
        assert!(!actions.is_empty(), "{case}");
        for action in actions {
            assert_ne!(action.outcome, ActionOutcome::Denied, "{case}: {action:?}");
            assert!(
                matches!(
                    action.kind,
                    ActionKind::Read | ActionKind::Stat | ActionKind::Native | ActionKind::Env
                ),
                "{case}: {action:?}"
            );
            if let Some(path) = action.fields.get("path").and_then(Value::as_str) {
                assert!(
                    info().reads.contains(&path),
                    "{case}: {path} is not a declared read"
                );
            }
        }
    }
}

#[test]
fn every_message_and_fix_the_cases_produce_passes_the_fix_text_audit() {
    if let Err(error) = rdy_engine::fixtext::check(info().meta.remediation) {
        panic!("remediation: {error}");
    }
    let keys = [
        rhel_ubuntu(),
        json!({"fips": "require", "arch": ["aarch64"]}),
        json!({"fips": "forbid"}),
        json!({"supported": [{"id": "rhel", "versions": ["9"]}]}),
    ];
    for case in CASES {
        for key in &keys {
            let ran = run_case(case, key);
            let f = ran.finding();
            for text in f
                .fix
                .iter()
                .chain(std::iter::once(&f.message))
                .chain(&f.notes)
            {
                if let Err(error) = rdy_engine::fixtext::check(text) {
                    panic!("{case} {key}: {error}");
                }
            }
        }
    }
}

#[test]
fn the_declared_facts_match_the_catalog() {
    let info = info();
    assert_eq!((info.id, info.family), ("host.os", "host"));
    assert_eq!(
        info.default_timeout,
        Some(std::time::Duration::from_secs(2))
    );
    assert!(info.needs.is_empty() && info.wants.is_empty());
    assert_eq!(info.os.on(Os::Linux), Support::Full);
    assert_eq!(info.os.on(Os::Macos), Support::NotYet);
    assert!(info.reads.iter().all(|p| p.starts_with('/')));
    assert!(info.commands.is_empty() && info.statfs.is_empty());
    assert_eq!(info.env, ["KUBERNETES_SERVICE_HOST"]);
}

#[test]
fn from_params_reads_the_keys_a_spec_entry_can_carry() {
    let c = check(&json!({
        "supported": [{"id": "rhel", "versions": ["8"]}, {"id": "ubuntu"}],
        "arch": ["amd64", "x86_64", "arm64"],
        "fips": "forbid",
        "windows_min_build": 20348,
    }));
    assert_eq!(c.supported.len(), 2);
    assert_eq!(c.supported[0].id, "rhel");
    assert_eq!(c.supported[1].versions, None);
    assert_eq!(c.arch, ["aarch64", "x86_64"]);
    let sorted = check(&json!({"arch": ["x86_64", "aarch64", "amd64"]}));
    assert_eq!(sorted.arch, ["aarch64", "x86_64"]);
    assert_eq!(c.fips, Fips::Forbid);
    assert_eq!(check(&json!({})), OsCheck::default());
}

/// A fix text for the host of one `os-release`, FIPS required or forbidden.
fn fips_fix_for(os_release: &str, fips: &str, enabled: bool) -> String {
    let replay = bare_with(&[
        ("/etc/os-release", os_release),
        (
            "/proc/sys/crypto/fips_enabled",
            if enabled { "1\n" } else { "0\n" },
        ),
    ]);
    let ran = execute(replay, Os::Linux, &check(&json!({ "fips": fips })));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    let fix = f.fix.clone().expect("fix");
    if let Err(error) = rdy_engine::fixtext::check(&fix) {
        panic!("{os_release}: {error}");
    }
    fix
}

#[test]
fn the_fips_fix_follows_the_id_and_the_major_version() {
    // Amazon Linux 2 has no fips-mode-setup: the AWS steps.
    let al2 = run_case("amazon-linux-2", &json!({"fips": "require"}));
    let fix = al2.finding().fix.clone().expect("fix");
    assert!(!fix.contains("fips-mode-setup"), "{fix}");
    for part in [
        "dracut-fips",
        "dracut -f",
        "grubby --update-kernel=ALL --args=fips=1",
    ] {
        assert!(fix.contains(part), "{fix}");
    }
    let fix = fips_fix_for("ID=amzn\nVERSION_ID=\"2\"\n", "forbid", true);
    assert!(
        fix.contains("grubby") && !fix.contains("fips-mode-setup"),
        "{fix}"
    );

    // Amazon Linux 2023 and EL 8 and 9 keep fips-mode-setup.
    let fix = fips_fix_for("ID=amzn\nVERSION_ID=\"2023\"\n", "require", false);
    assert!(fix.contains("fips-mode-setup --enable"), "{fix}");
    let fix = fips_fix_for(
        "ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"8.9\"\n",
        "require",
        false,
    );
    assert!(fix.contains("fips-mode-setup --enable"), "{fix}");

    // RHEL 10 and later: no tool, so a reinstall.
    for (os_release, fips, enabled) in [
        ("ID=rhel\nVERSION_ID=\"10.0\"\n", "require", false),
        (
            "ID=almalinux\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.1\"\n",
            "forbid",
            true,
        ),
        (
            "ID=ol\nID_LIKE=fedora\nVERSION_ID=\"11.0\"\n",
            "require",
            false,
        ),
    ] {
        let fix = fips_fix_for(os_release, fips, enabled);
        assert!(fix.contains("Reinstall the host"), "{fix}");
        assert!(fix.contains("fips=1"), "{fix}");
        assert!(!fix.contains("fips-mode-setup"), "{fix}");
    }

    // Fedora, EL 7, an unknown version and Alpine get the vendor text.
    for os_release in [
        "ID=fedora\nVERSION_ID=\"40\"\n",
        "ID=centos\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"\n",
        "ID=rhel\n",
        "ID=amzn\nVERSION_ID=\"1\"\n",
        "ID=alpine\nVERSION_ID=3.19.1\n",
    ] {
        let fix = fips_fix_for(os_release, "require", false);
        assert!(fix.contains("OS vendor's procedure"), "{os_release}: {fix}");
    }
}

#[test]
fn the_ubuntu_fix_for_fips_on_uses_the_pro_client() {
    let fix = fips_fix_for("ID=ubuntu\nVERSION_ID=\"22.04\"\n", "forbid", true);
    assert!(fix.contains("pro disable fips-updates"), "{fix}");
    assert!(fix.contains("Canonical's procedure"), "{fix}");
    assert!(
        !fix.contains("update-grub") && !fix.contains("GRUB"),
        "{fix}"
    );
}

#[test]
fn the_remediation_names_rhel_8_and_9_only() {
    let text = info().meta.remediation;
    assert!(text.contains("On RHEL 8 and 9"), "{text}");
    assert!(!text.contains("RHEL family"), "{text}");
}

#[test]
fn oracle_linux_matches_rhel_through_its_id_even_though_id_like_says_fedora() {
    let text = "NAME=\"Oracle Linux Server\"\nID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.3\"\n";
    let replay = bare_with(&[("/etc/os-release", text)]);
    let list = |id: &str| check(&json!({"supported": [{"id": id, "versions": ["9"]}]}));
    let ran = execute(replay.clone(), Os::Linux, &list("rhel"));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(
        f.notes.iter().any(|n| n.contains("ID_LIKE")),
        "{:?}",
        f.notes
    );
    // Listed as itself it matches, and fedora does not stand for it.
    let ran = execute(replay.clone(), Os::Linux, &list("ol"));
    assert_eq!(ran.finding().level, Level::Pass);
    let ran = execute(replay, Os::Linux, &list("fedora"));
    assert_eq!(ran.finding().level, Level::Fail);
}

#[test]
fn a_spec_version_that_is_a_prefix_of_the_host_version_is_explained() {
    let ran = run_case(
        "alpine",
        &json!({"supported": [{"id": "alpine", "versions": ["3.19"]}]}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    let note = f
        .notes
        .iter()
        .find(|n| n.contains("3.19.1"))
        .expect("a note");
    assert!(
        note.contains("the spec lists 3.19, which matches only 3.19 exactly"),
        "{note}"
    );
    for text in &f.notes {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("{error}");
        }
    }
    // No note when nothing is a prefix, or when it matches.
    for versions in [json!(["3.18"]), json!(["3"])] {
        let ran = run_case(
            "alpine",
            &json!({"supported": [{"id": "alpine", "versions": versions}]}),
        );
        assert!(
            ran.finding()
                .notes
                .iter()
                .all(|n| !n.contains("matches only"))
        );
    }
}

#[test]
fn wsl_is_seen_from_the_uname_release_when_the_proc_file_is_unreadable() {
    let replay = machine("ubuntu-wsl")
        .replay()
        .clone()
        .unreadable("/proc/sys/kernel/osrelease");
    let ran = execute(replay, Os::Linux, &check(&json!({})));
    let f = ran.finding();
    assert_eq!(f.observed["wsl"], true, "{f:?}");
    assert!(f.notes.iter().any(|n| n.contains("WSL")), "{:?}", f.notes);
}

#[test]
fn both_os_release_paths_are_named_when_neither_can_be_used() {
    let list = check(&rhel_ubuntu());
    let replay = bare_with(&[]).unreadable("/usr/lib/os-release");
    let ran = execute(replay, Os::Linux, &list);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message.contains("/etc/os-release does not exist"),
        "{}",
        f.message
    );
    assert!(
        f.message
            .contains("/usr/lib/os-release could not be read (permission denied)"),
        "{}",
        f.message
    );
    let ran = execute(bare_with(&[]), Os::Linux, &list);
    assert!(
        ran.finding()
            .message
            .contains("neither /etc/os-release nor /usr/lib/os-release exists"),
        "{}",
        ran.finding().message
    );
}
