//! Tests of `host.security_agents` against synthetic machines.
//!
//! The machines are the cases under `tests/fixtures/checks/host.security_agents/` (08 section 2), read by
//! the Replay fixture loader. Every run goes through the real read policy and writes the real action
//! log, so a path the check reads outside its declaration, or one the policy refuses, fails here.

use rdy_engine::check::{Check, CheckError, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::probe::DirEntry;
use rdy_engine::testing::{Fixture, Replay, TestRun, fixtures_dir};
use rdy_spec::result::{ActionKind, ActionOutcome};
use serde_json::Value;

use super::*;

/// What one run produced and what it did to the machine.
struct Ran {
    outcome: CheckOutcome,
    run: TestRun,
}

impl Ran {
    fn finding(&self) -> &Finding {
        self.outcome.as_ref().expect("a finding")
    }

    /// The path of every file call the run made.
    fn paths(&self) -> Vec<String> {
        self.run
            .action_log()
            .actions
            .iter()
            .filter_map(|a| a.fields.get("path").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
    }

    fn detected(&self) -> Vec<String> {
        self.finding().observed["detected"]
            .as_array()
            .expect("a detected list")
            .iter()
            .map(|d| d["id"].as_str().expect("an id").to_owned())
            .collect()
    }
}

fn fixture(case: &str) -> Fixture {
    let fixture = Fixture::load(
        &fixtures_dir(),
        &format!("checks/host.security_agents/{case}"),
    )
    .expect("the fixture loads");
    fixture
        .ensure_answers("host.security_agents")
        .expect("it answers the check");
    fixture
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
        .block_on(future)
}

fn execute(replay: Replay, needs: Vec<Need>, os: Os, check: &SecurityAgents, max: usize) -> Ran {
    let run = TestRun::new(replay);
    let ctx = run.context_for(&INFO, "host.security_agents", os, needs);
    let outcome = block_on(check.inspect(&ctx, max));
    Ran { outcome, run }
}

/// Runs the check on the fixture `case` with the needs the fixture offers.
fn run_case(case: &str, check: &SecurityAgents) -> Ran {
    let fixture = fixture(case);
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(
        &INFO,
        "host.security_agents",
        Os::Linux,
        fixture.available_needs(),
    );
    let outcome = block_on(check.run(&ctx));
    Ran { outcome, run }
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn check(forbid: &[&str], allow: &[&str]) -> SecurityAgents {
    SecurityAgents::new(ids(forbid), ids(allow))
}

fn bare() -> SecurityAgents {
    SecurityAgents::default()
}

#[test]
fn each_catalog_entry_is_found_by_its_own_machine() {
    // The exit test: each entry has a fixture, and the fixture runs the entry's processes. The names are
    // the ones the kernel shows, so a name over 15 bytes appears cut.
    for agent in agents::catalog().expect("the catalog").agents() {
        let ran = run_case(&format!("agent-{}", agent.id), &bare());
        let f = ran.finding();
        assert_eq!(f.level, Level::Warn, "{}: {f:?}", agent.id);
        assert_eq!(
            ran.detected(),
            std::slice::from_ref(&agent.id),
            "{}",
            agent.id
        );
        let mut shown: Vec<String> = f.observed["detected"][0]["processes"]
            .as_array()
            .expect("processes")
            .iter()
            .map(|p| p.as_str().expect("a name").to_owned())
            .collect();
        shown.sort();
        let mut want: Vec<String> = agent
            .process_names
            .iter()
            .map(|n| n.chars().take(agents::COMM_MAX).collect())
            .collect();
        want.sort();
        assert_eq!(shown, want, "{}", agent.id);
        assert!(
            f.message
                .contains(&format!("Detected {} (", agent.display_name)),
            "{}: {}",
            agent.id,
            f.message
        );
    }
}

#[test]
fn a_detected_product_is_a_warning_with_neutral_advice() {
    let ran = run_case("agent-falco", &bare());
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert_eq!(f.message, "Detected Falco (EDR).");
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("Software in this category often inspects file opens and process launches."),
        "{fix}"
    );
    assert!(fix.contains("ask the security team to review exclusions for the product's paths"));
    assert!(f.partial.is_none());
    assert_eq!(f.observed["processes_read"], 4);
    assert_eq!(f.observed["detected"][0]["category"], "edr");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("does not show that the product is installed"))
    );
}

#[test]
fn the_vendors_own_exclusion_page_is_offered_when_the_catalog_has_one() {
    let ran = run_case("agent-microsoft-defender-endpoint-linux", &bare());
    let fix = ran.finding().fix.clone().expect("a fix");
    assert!(
        fix.contains("https://learn.microsoft.com/defender-endpoint/linux-exclusions"),
        "{fix}"
    );
    let ran = run_case("agent-falco", &bare());
    assert!(
        !ran.finding()
            .fix
            .clone()
            .expect("a fix")
            .contains("https://")
    );
}

#[test]
fn forbid_blocks_a_detected_product() {
    let ran = run_case(
        "agent-carbon-black-cloud-linux",
        &check(&["carbon-black-cloud-linux"], &[]),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "The spec forbids Carbon Black Cloud sensor for Linux (EDR)."
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("do not allow Carbon Black Cloud sensor for Linux"),
        "{fix}"
    );
    assert_eq!(
        f.expected["forbid"],
        serde_json::json!(["carbon-black-cloud-linux"])
    );
}

#[test]
fn forbid_of_a_product_that_is_not_running_passes() {
    let ran = run_case("agent-falco", &check(&["clamav"], &[]));
    let f = ran.finding();
    // Falco is not forbidden and not allowed, so it is still flagged. The forbidden one is absent.
    assert_eq!(f.level, Level::Warn);
    let ran = run_case("none", &check(&["clamav"], &[]));
    assert_eq!(ran.finding().level, Level::Pass);
}

#[test]
fn allow_silences_a_detected_product() {
    let ran = run_case("agent-falco", &check(&[], &["falco"]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "The spec allows Falco (EDR).");
    assert!(f.fix.is_none());
    assert_eq!(ran.detected(), ["falco"]);
}

#[test]
fn allow_silences_only_the_ids_it_names() {
    let ran = run_case(
        "two-agents",
        &check(&[], &["wdavdaemon-is-not-an-id", "falco"]),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert!(f.message.contains("Detected Microsoft Defender for Endpoint on Linux (EDR) and Veeam Agent for Linux (backup)."), "{}", f.message);
    assert!(
        f.message.contains("The spec allows Falco (EDR)."),
        "{}",
        f.message
    );
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("wdavdaemon-is-not-an-id") && n.contains("no effect")),
        "{:?}",
        f.notes
    );
}

#[test]
fn forbid_wins_over_allow_for_the_same_id() {
    let ran = run_case("agent-falco", &check(&["falco"], &["falco"]));
    assert_eq!(ran.finding().level, Level::Fail);
}

#[test]
fn forbid_and_allow_work_together_on_a_machine_with_three_products() {
    let ran = run_case(
        "two-agents",
        &check(
            &["veeam-agent-linux"],
            &["microsoft-defender-endpoint-linux", "falco"],
        ),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "The spec forbids Veeam Agent for Linux (backup). The spec allows Microsoft Defender for Endpoint on Linux (EDR) and Falco (EDR)."
    );
    assert_eq!(ran.detected().len(), 3);
    // Two processes share a name: the count is of processes, the list of names.
    let mde = f.observed["detected"]
        .as_array()
        .expect("detected")
        .iter()
        .find(|d| d["id"] == "microsoft-defender-endpoint-linux")
        .expect("mde");
    assert_eq!(mde["count"], 2);
    assert_eq!(mde["processes"], serde_json::json!(["wdavdaemon"]));
}

#[test]
fn a_name_the_kernel_cut_to_fifteen_bytes_still_matches() {
    let ran = run_case("comm-truncation", &bare());
    let mut got = ran.detected();
    got.sort();
    assert_eq!(got, ["elastic-defend", "sophos-protection-linux"]);
    let f = ran.finding();
    let seen = |id: &str| -> Vec<String> {
        f.observed["detected"]
            .as_array()
            .expect("detected")
            .iter()
            .find(|d| d["id"] == id)
            .expect("the id")["processes"]
            .as_array()
            .expect("processes")
            .iter()
            .map(|p| p.as_str().expect("name").to_owned())
            .collect()
    };
    // The near misses (`elastic-endpoix`, `sophos_threat`, `clam`, `wdavdaemon-x`) are not in any list. Two
    // daemons that a Wazuh manager runs too (`wazuh-syscheckd`, `wazuh-logcollec`) are not in the catalog,
    // so a manager is not reported as an agent.
    assert_eq!(seen("elastic-defend"), ["elastic-endpoin"]);
    assert_eq!(seen("sophos-protection-linux"), ["sophos_threat_d"]);
}

#[test]
fn a_machine_without_known_software_passes_with_the_count() {
    let ran = run_case("none", &bare());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(
        f.message,
        "No known security software process was found among 5 processes."
    );
    assert!(f.partial.is_none() && f.fix.is_none());
    assert_eq!(f.observed["limited_view"], false);
    assert!(f.notes.iter().any(|n| n.contains("In a container")));
}

#[test]
fn a_non_root_run_that_can_see_every_process_does_not_claim_a_limited_view() {
    let ran = run_case("none-root-less", &check(&["falco"], &[]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(f.partial.is_none());
}

#[test]
fn a_hidden_proc_makes_absence_a_limited_view_and_names_root() {
    let ran = run_case("hidepid", &bare());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert!(f.message.contains("(limited view)"), "{}", f.message);
    let partial = f.partial.as_ref().expect("a partial");
    assert_eq!(partial.missing, [Need::Root]);
    assert_eq!(f.observed["limited_view"], true);
}

#[test]
fn a_limited_view_is_a_warning_when_the_spec_forbids_something() {
    let ran = run_case("hidepid", &check(&["falco"], &[]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message
            .contains("Cannot confirm that the forbidden software is absent.")
    );
    assert!(f.fix.as_deref().expect("a fix").contains("Run rdy as root"));
}

#[test]
fn an_unreadable_process_directory_is_a_limited_view_for_a_non_root_run() {
    let ran = run_case("unreadable-comm-no-agent", &check(&["clamav"], &[]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(f.observed["processes_unreadable"], 1);
    assert_eq!(f.partial.as_ref().expect("a partial").missing, [Need::Root]);
}

#[test]
fn a_detection_in_a_limited_view_is_still_a_detection() {
    let ran = run_case("unreadable-comm", &check(&["falco"], &[]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert!(f.partial.is_some());
}

#[test]
fn root_with_an_unreadable_process_cannot_confirm_absence() {
    // Root should read everything. A name that still cannot be read (a security module denies it, or the
    // read timed out) is a gap, and a forbidden agent could sit in it. A process that merely ended is
    // NotFound and is not counted here.
    let fixture = fixture("unreadable-comm-no-agent");
    let ran = execute(
        fixture.replay().clone(),
        vec![Need::Root],
        Os::Linux,
        &check(&["clamav"], &[]),
        MAX_PIDS,
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message
            .contains("Cannot confirm that the forbidden software is absent."),
        "{f:?}"
    );
    assert_eq!(f.observed["processes_unreadable"], 1);
    assert_eq!(f.observed["limited_view"], true);
    let partial = f.partial.as_ref().expect("a partial");
    assert!(partial.missing.is_empty(), "root is not what is missing");
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("even as root"), "{fix}");
    assert!(!fix.contains("Run rdy as root"), "{fix}");
}

#[test]
fn root_with_a_gap_and_a_cut_list_says_both() {
    // Both can be true at once. The reason and the fix name each, so fixing one does not hide the other.
    let fixture = fixture("unreadable-comm-no-agent");
    let ran = execute(
        fixture.replay().clone(),
        vec![Need::Root],
        Os::Linux,
        &check(&["clamav"], &[]),
        3,
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(f.observed["list_cut"], true);
    assert_eq!(f.observed["processes_unreadable"], 1);
    let partial = f.partial.as_ref().expect("a partial");
    assert!(partial.missing.is_empty());
    assert!(partial.note.contains("even as root"), "{partial:?}");
    assert!(partial.note.contains("cut short"), "{partial:?}");
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("even as root"), "{fix}");
    assert!(fix.contains("more processes than rdy reads"), "{fix}");
}

#[test]
fn root_with_an_unreadable_process_and_no_forbid_still_passes() {
    // Nothing is forbidden, so there is nothing to confirm absent. The view is still reported as limited.
    let fixture = fixture("unreadable-comm-no-agent");
    let ran = execute(
        fixture.replay().clone(),
        vec![Need::Root],
        Os::Linux,
        &bare(),
        MAX_PIDS,
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.observed["limited_view"], true);
}

#[test]
fn the_check_never_reads_a_command_line_or_an_environment() {
    let ran = run_case("planted-cmdline", &bare());
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    let shown = format!("{f:?}");
    assert!(!shown.contains("REDACTED-TEST-TOKEN"), "{shown}");
    assert!(!shown.contains("--token"), "{shown}");
    let paths = ran.paths();
    assert!(!paths.is_empty());
    for path in &paths {
        assert!(
            path == "/proc" || path.ends_with("/comm") || path.ends_with("/mountinfo"),
            "unexpected read of {path}"
        );
    }
    // The evidence holds the product, the process names, and counts. No user, no argv.
    let mut keys: Vec<&str> = f.observed["detected"][0]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["category", "count", "display_name", "id", "processes"]
    );
}

#[test]
fn the_read_policy_would_refuse_a_command_line_if_the_check_asked() {
    let fixture = fixture("planted-cmdline");
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(&INFO, "host.security_agents", Os::Linux, [Need::Root]);
    let error = block_on(ctx.probe().read(Path::new("/proc/412/cmdline"))).expect_err("refused");
    assert!(
        matches!(error, ProbeError::Denied { .. } | ProbeError::Policy(_)),
        "{error:?}"
    );
    let log = run.action_log();
    assert!(
        log.actions
            .iter()
            .any(|a| a.kind == ActionKind::Read && a.outcome != ActionOutcome::Ok),
        "{:?}",
        log.actions
    );
}

#[test]
fn the_run_reads_files_and_nothing_else() {
    let ran = run_case("two-agents", &bare());
    for action in ran.run.action_log().actions {
        assert!(
            matches!(action.kind, ActionKind::ReadDir | ActionKind::Read),
            "{:?}",
            action.kind
        );
    }
}

#[test]
fn a_spec_id_this_rdy_does_not_know_cannot_be_checked_so_it_warns() {
    let ran = run_case("none", &check(&["acme-agent-from-the-future"], &[]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message
            .contains("acme-agent-from-the-future, which this rdy does not know"),
        "{}",
        f.message
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("Run rdy spec lint to see the known ids."),
        "{fix}"
    );
}

#[test]
fn a_process_that_ends_between_the_listing_and_the_read_is_skipped() {
    let replay = Replay::new()
        .dir(
            "/proc",
            vec![
                DirEntry::new("1", true),
                DirEntry::new("999", true),
                DirEntry::new("cpuinfo", false),
                DirEntry::new("sys", true),
                DirEntry::new("12x", true),
            ],
        )
        .file("/proc/1/comm", "falco\n");
    let ran = execute(replay, vec![Need::Root], Os::Linux, &bare(), MAX_PIDS);
    let f = ran.finding();
    assert_eq!(ran.detected(), ["falco"]);
    assert_eq!(f.observed["processes_read"], 1);
    assert_eq!(f.observed["processes_unreadable"], 0);
}

#[test]
fn a_comm_with_odd_bytes_does_not_break_the_check() {
    let replay = Replay::new()
        .dir(
            "/proc",
            vec![
                DirEntry::new("1", true),
                DirEntry::new("2", true),
                DirEntry::new("3", true),
            ],
        )
        .file("/proc/1/comm", vec![0xff, 0xfe, b'\n'])
        .file("/proc/2/comm", "\n")
        .file("/proc/3/comm", "falco\0\n");
    let ran = execute(replay, vec![Need::Root], Os::Linux, &bare(), MAX_PIDS);
    assert_eq!(ran.detected(), ["falco"]);
    assert_eq!(ran.finding().observed["processes_read"], 2);
}

#[test]
fn a_list_longer_than_the_cap_is_cut_and_absence_is_not_proven() {
    let entries: Vec<DirEntry> = (1..=30)
        .map(|n| DirEntry::new(n.to_string(), true))
        .collect();
    let mut replay = Replay::new().dir("/proc", entries);
    for n in 1..=30 {
        replay = replay.file(format!("/proc/{n}/comm"), "chronyd\n");
    }
    // Pid 30 is the agent, past the cap of ten, so it is never read.
    replay = replay.file("/proc/30/comm", "falco\n");
    let ran = execute(replay.clone(), vec![Need::Root], Os::Linux, &bare(), 10);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(f.observed["list_cut"], true);
    assert_eq!(f.observed["processes_read"], 10);
    assert!(f.partial.as_ref().expect("a partial").missing.is_empty());
    assert!(f.message.contains("(limited view)"));
    let forbidding = execute(
        replay.clone(),
        vec![Need::Root],
        Os::Linux,
        &check(&["falco"], &[]),
        10,
    );
    assert_eq!(forbidding.finding().level, Level::Warn);
    // With a cap that covers the list, the agent is found.
    let all = execute(
        replay,
        vec![Need::Root],
        Os::Linux,
        &check(&["falco"], &[]),
        30,
    );
    assert_eq!(all.finding().level, Level::Fail);
}

#[test]
fn the_pids_are_read_in_numeric_order_so_the_cut_is_the_same_every_run() {
    let entries: Vec<DirEntry> = ["100", "9", "20"]
        .iter()
        .map(|n| DirEntry::new(*n, true))
        .collect();
    let replay = Replay::new()
        .dir("/proc", entries)
        .file("/proc/9/comm", "chronyd\n")
        .file("/proc/20/comm", "falco\n")
        .file("/proc/100/comm", "veeamservice\n");
    let ran = execute(replay, vec![Need::Root], Os::Linux, &bare(), 2);
    assert_eq!(ran.detected(), ["falco"]);
}

#[test]
fn a_machine_with_no_proc_is_a_failed_check_not_a_pass() {
    let ran = execute(
        Replay::new(),
        vec![Need::Root],
        Os::Linux,
        &bare(),
        MAX_PIDS,
    );
    assert!(
        matches!(ran.outcome, Err(CheckError::Probe(ProbeError::NotFound))),
        "{:?}",
        ran.outcome
    );
}

#[test]
fn on_macos_and_windows_the_check_has_no_source_yet() {
    for os in [Os::Macos, Os::Windows] {
        let ran = execute(Replay::for_os(os), vec![Need::Root], os, &bare(), MAX_PIDS);
        assert!(
            matches!(ran.outcome, Err(CheckError::Unsupported(_))),
            "{os:?}"
        );
        assert!(ran.run.action_log().actions.is_empty());
    }
}

#[test]
fn the_text_the_check_prints_passes_the_fix_text_audit() {
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("remediation is not on the lists: {error}");
    }
    let cases = [
        ("agent-falco", bare()),
        ("agent-microsoft-defender-endpoint-linux", bare()),
        (
            "agent-carbon-black-cloud-linux",
            check(&["carbon-black-cloud-linux"], &[]),
        ),
        ("hidepid", check(&["falco"], &[])),
        ("none", check(&["from-the-future"], &[])),
        ("two-agents", check(&["veeam-agent-linux"], &["falco"])),
    ];
    for (case, spec) in cases {
        let ran = run_case(case, &spec);
        let f = ran.finding();
        for text in f.fix.iter().chain(std::iter::once(&f.message)) {
            if let Err(error) = rdy_engine::fixtext::check(text) {
                panic!("{case}: text is not on the lists: {error}\n{text}");
            }
            assert!(!text.contains('\u{2014}'), "{case}: {text}");
        }
    }
}

#[test]
fn the_words_never_say_that_a_product_breaks_anything() {
    for agent in agents::catalog().expect("the catalog").agents() {
        let ran = run_case(&format!("agent-{}", agent.id), &bare());
        let f = ran.finding();
        let text = format!("{} {}", f.message, f.fix.clone().unwrap_or_default()).to_lowercase();
        for word in [
            "break",
            "cause",
            "bug",
            "slow down",
            "unsafe",
            "dangerous",
            "vulnerab",
        ] {
            assert!(!text.contains(word), "{}: {word}", agent.id);
        }
    }
}

#[test]
fn spec_lists_are_sorted_and_deduplicated() {
    let check = check(&["b", "a", "b"], &["z", "z"]);
    assert_eq!(check.forbid(), ["a", "b"]);
    assert_eq!(check.allow(), ["z"]);
}

#[test]
fn the_manifest_declares_proc_and_no_command() {
    assert_eq!(INFO.reads, ["/proc"]);
    assert!(INFO.commands.is_empty() && INFO.peers.is_empty() && INFO.env.is_empty());
    assert_eq!(INFO.default_timeout, Some(Duration::from_secs(5)));
}

#[test]
fn comm_of_takes_the_first_line_and_drops_nuls() {
    assert_eq!(comm_of(b"falco\n").as_deref(), Some("falco"));
    assert_eq!(comm_of(b"falco").as_deref(), Some("falco"));
    assert_eq!(comm_of(b"Web Content\n").as_deref(), Some("Web Content"));
    assert_eq!(comm_of(b"falco\0\n").as_deref(), Some("falco"));
    assert_eq!(comm_of(b"\n"), None);
    assert_eq!(comm_of(b""), None);
    assert_eq!(comm_of(&[b'a'; 200]).map(|s| s.len()), Some(64));
}

const PLAIN: &str = "21 28 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n";

#[test]
fn mountinfo_with_hidepid_hides_and_without_does_not() {
    assert!(!proc_mount_hides(PLAIN));
    assert!(proc_mount_hides(
        &PLAIN.replace("proc rw\n", "proc rw,hidepid=2\n")
    ));
    assert!(proc_mount_hides(
        &PLAIN.replace("proc rw\n", "proc rw,hidepid=1\n")
    ));
    assert!(proc_mount_hides(
        &PLAIN.replace("proc rw\n", "proc rw,hidepid=invisible\n")
    ));
    assert!(proc_mount_hides(
        &PLAIN.replace("proc rw\n", "proc rw,hidepid=noaccess,gid=100\n")
    ));
    assert!(proc_mount_hides(
        &PLAIN.replace("relatime", "relatime,hidepid=2")
    ));
    assert!(!proc_mount_hides(
        &PLAIN.replace("proc rw\n", "proc rw,hidepid=0\n")
    ));
    assert!(!proc_mount_hides(
        &PLAIN.replace("proc rw\n", "proc rw,hidepid=off\n")
    ));
    assert!(!proc_mount_hides(
        &PLAIN.replace("proc rw\n", "proc rw,hidepid=\n")
    ));
}

#[test]
fn only_the_mount_at_slash_proc_counts() {
    // A second proc mount for a container, and a different file system, both with hidepid.
    let other_mount = "30 28 0:9 / /host/proc rw - proc proc rw,hidepid=2\n";
    assert!(!proc_mount_hides(other_mount));
    let other_fs = "30 28 0:9 / /proc rw - tmpfs tmpfs rw,hidepid=2\n";
    assert!(!proc_mount_hides(other_fs));
    assert!(proc_mount_hides(&format!(
        "{other_mount}{}",
        PLAIN.replace("proc rw\n", "proc rw,hidepid=2\n")
    )));
    assert!(!proc_mount_hides(""));
    assert!(!proc_mount_hides("garbage with no dash"));
}
