//! Tests of `host.firewall` against synthetic machines.
//!
//! The machines are the cases under `tests/fixtures/checks/host.firewall/` (the layout of
//! docs/plan/08-testing.md). `crate::expect_cases` runs every case through the Replay fixture loader and
//! compares it with its `expect.json`. The tests below wire the same cases by hand (the files with
//! `include_str!`, the `base` as a parent) to look inside a run: the action log, the order of the
//! calls, a machine with a tool changed. The test code reads no real file.

use rdy_engine::check::{Check, CheckError, CheckInfo, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::probe::DirEntry;
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::result::{ActionKind, ActionOutcome};
use serde_json::Value;

use super::*;

/// A file of a case (`fx!("ufw-closed", "root/etc/ufw/user.rules")`) or of one of the two base
/// environments, which the loader looks up under `tests/fixtures/envs/` (`fx!(ufw "root/proc/net/route")`).
/// The base paths are whole literals, so the lint wall can allow exactly these directories.
macro_rules! fx {
    (firewalld $file:literal) => {
        include_str!(concat!(
            "../../../../tests/fixtures/envs/base-firewalld/",
            $file
        ))
    };
    (ufw $file:literal) => {
        include_str!(concat!("../../../../tests/fixtures/envs/base-ufw/", $file))
    };
    ($case:literal, $file:literal) => {
        include_str!(concat!(
            "../../../../tests/fixtures/checks/host.firewall/",
            $case,
            "/",
            $file
        ))
    };
}

/// One fixture case: its files, its recorded commands, its empty directories and whether the run is root.
struct Case {
    base: Option<&'static Case>,
    root: bool,
    dirs: &'static [&'static str],
    /// `(virtual path, text)`.
    files: &'static [(&'static str, &'static str)],
    /// `commands/*.json` texts.
    commands: &'static [&'static str],
}

const EMPTY: Case = Case {
    base: None,
    root: true,
    dirs: &[],
    files: &[],
    commands: &[],
};

const BASE_FIREWALLD: Case = Case {
    dirs: &["/run/firewalld"],
    files: &[
        ("/proc/net/route", fx!(firewalld "root/proc/net/route")),
        (
            "/usr/lib/firewalld/services/ssh.xml",
            fx!(firewalld "root/usr/lib/firewalld/services/ssh.xml"),
        ),
    ],
    commands: &[
        fx!(firewalld "commands/state.json"),
        fx!(firewalld "commands/active-zones.json"),
    ],
    ..EMPTY
};

const FIREWALLD_PORT_OPEN: Case = Case {
    base: Some(&BASE_FIREWALLD),
    commands: &[fx!("firewalld-port-open", "commands/list-all-public.json")],
    ..EMPTY
};

const FIREWALLD_SERVICE_OPEN: Case = Case {
    base: Some(&BASE_FIREWALLD),
    files: &[
        (
            "/usr/lib/firewalld/services/acme-api.xml",
            fx!(
                "firewalld-service-open",
                "root/usr/lib/firewalld/services/acme-api.xml"
            ),
        ),
        (
            "/usr/lib/firewalld/services/acme-kubelet.xml",
            fx!(
                "firewalld-service-open",
                "root/usr/lib/firewalld/services/acme-kubelet.xml"
            ),
        ),
        (
            "/etc/firewalld/services/acme-kubelet.xml",
            fx!(
                "firewalld-service-open",
                "root/etc/firewalld/services/acme-kubelet.xml"
            ),
        ),
    ],
    commands: &[fx!(
        "firewalld-service-open",
        "commands/list-all-public.json"
    )],
    ..EMPTY
};

const FIREWALLD_CLOSED: Case = Case {
    base: Some(&BASE_FIREWALLD),
    commands: &[
        fx!("firewalld-closed", "commands/list-all-public.json"),
        fx!("firewalld-closed", "commands/list-all-docker.json"),
    ],
    ..EMPTY
};

const FIREWALLD_RICH_RULE: Case = Case {
    base: Some(&BASE_FIREWALLD),
    commands: &[fx!("firewalld-rich-rule", "commands/list-all-public.json")],
    ..EMPTY
};

const FIREWALLD_SOURCE_ZONE: Case = Case {
    base: Some(&BASE_FIREWALLD),
    commands: &[
        fx!("firewalld-source-zone", "commands/active-zones.json"),
        fx!("firewalld-source-zone", "commands/list-all-public.json"),
    ],
    ..EMPTY
};

const FIREWALLD_DIRECT_RULE: Case = Case {
    base: Some(&BASE_FIREWALLD),
    files: &[(
        "/etc/firewalld/direct.xml",
        fx!("firewalld-direct-rule", "root/etc/firewalld/direct.xml"),
    )],
    commands: &[fx!(
        "firewalld-direct-rule",
        "commands/list-all-public.json"
    )],
    ..EMPTY
};

const FIREWALLD_NOT_RUNNING: Case = Case {
    base: Some(&BASE_FIREWALLD),
    commands: &[fx!("firewalld-not-running", "commands/state.json")],
    ..EMPTY
};

const FIREWALLD_ROOT_LESS: Case = Case {
    base: Some(&BASE_FIREWALLD),
    root: false,
    commands: &[fx!("firewalld-root-less", "commands/list-all-public.json")],
    ..EMPTY
};

const BASE_UFW: Case = Case {
    files: &[
        ("/proc/net/route", fx!(ufw "root/proc/net/route")),
        ("/etc/ufw/ufw.conf", fx!(ufw "root/etc/ufw/ufw.conf")),
        ("/etc/default/ufw", fx!(ufw "root/etc/default/ufw")),
    ],
    ..EMPTY
};

const UFW_ALLOWED: Case = Case {
    base: Some(&BASE_UFW),
    files: &[(
        "/etc/ufw/user.rules",
        fx!("ufw-allowed", "root/etc/ufw/user.rules"),
    )],
    ..EMPTY
};

const UFW_CLOSED: Case = Case {
    base: Some(&BASE_UFW),
    files: &[(
        "/etc/ufw/user.rules",
        fx!("ufw-closed", "root/etc/ufw/user.rules"),
    )],
    ..EMPTY
};

const UFW_LIMITED_SOURCE: Case = Case {
    base: Some(&BASE_UFW),
    files: &[(
        "/etc/ufw/user.rules",
        fx!("ufw-limited-source", "root/etc/ufw/user.rules"),
    )],
    ..EMPTY
};

const UFW_COMMENT_AND_LOG: Case = Case {
    base: Some(&BASE_UFW),
    files: &[(
        "/etc/ufw/user.rules",
        fx!("ufw-comment-and-log", "root/etc/ufw/user.rules"),
    )],
    ..EMPTY
};

const UFW_UNREAD_RULE: Case = Case {
    base: Some(&BASE_UFW),
    files: &[(
        "/etc/ufw/user.rules",
        fx!("ufw-unread-rule", "root/etc/ufw/user.rules"),
    )],
    ..EMPTY
};

const UFW_ROOT_LESS: Case = Case {
    base: Some(&BASE_UFW),
    root: false,
    files: &[(
        "/etc/ufw/user.rules",
        fx!("ufw-root-less", "root/etc/ufw/user.rules"),
    )],
    ..EMPTY
};

const UFW_DISABLED: Case = Case {
    base: Some(&BASE_UFW),
    files: &[(
        "/etc/ufw/ufw.conf",
        fx!("ufw-disabled", "root/etc/ufw/ufw.conf"),
    )],
    ..EMPTY
};

const NO_FIREWALL: Case = EMPTY;

/// Every case, for the tests that run them all.
const ALL: &[(&str, &Case)] = &[
    ("firewalld-port-open", &FIREWALLD_PORT_OPEN),
    ("firewalld-service-open", &FIREWALLD_SERVICE_OPEN),
    ("firewalld-closed", &FIREWALLD_CLOSED),
    ("firewalld-rich-rule", &FIREWALLD_RICH_RULE),
    ("firewalld-source-zone", &FIREWALLD_SOURCE_ZONE),
    ("firewalld-direct-rule", &FIREWALLD_DIRECT_RULE),
    ("firewalld-not-running", &FIREWALLD_NOT_RUNNING),
    ("firewalld-root-less", &FIREWALLD_ROOT_LESS),
    ("ufw-allowed", &UFW_ALLOWED),
    ("ufw-comment-and-log", &UFW_COMMENT_AND_LOG),
    ("ufw-unread-rule", &UFW_UNREAD_RULE),
    ("ufw-closed", &UFW_CLOSED),
    ("ufw-limited-source", &UFW_LIMITED_SOURCE),
    ("ufw-root-less", &UFW_ROOT_LESS),
    ("ufw-disabled", &UFW_DISABLED),
    ("no-firewall", &NO_FIREWALL),
];

/// Adds a case on top of its base.
fn load(case: &Case, mut replay: Replay) -> Replay {
    if let Some(base) = case.base {
        replay = load(base, replay);
    }
    for dir in case.dirs {
        replay = replay.dir(*dir, vec![DirEntry::new("firewalld.pid", false)]);
    }
    for (path, text) in case.files {
        replay = replay.file(*path, *text);
    }
    for text in case.commands {
        replay = with_command(replay, text);
    }
    replay
}

/// Adds one `commands/*.json` record: `{argv, stdout, exit}`.
fn with_command(replay: Replay, text: &str) -> Replay {
    let record: Value = serde_json::from_str(text).expect("a command record");
    let argv: Vec<&str> = record["argv"]
        .as_array()
        .expect("argv")
        .iter()
        .map(|a| a.as_str().expect("an argv word"))
        .collect();
    let program = argv[0].rsplit('/').next().expect("a program");
    let exit = i32::try_from(record["exit"].as_i64().expect("exit")).expect("an exit code");
    replay.command(
        program,
        &argv[1..],
        exit,
        record["stdout"].as_str().expect("stdout"),
    )
}

fn info() -> &'static CheckInfo {
    Firewall::default().info()
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

    /// The argv of every command the run started, as one string each.
    fn commands(&self) -> Vec<String> {
        self.run
            .action_log()
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::Exec)
            .map(|a| a.fields["argv"].to_string())
            .collect()
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
}

fn execute(replay: Replay, root: bool, os: Os, ports: &[u16]) -> Ran {
    let run = TestRun::new(replay);
    let needs: Vec<Need> = if root { vec![Need::Root] } else { vec![] };
    let ctx = run.context_for(info(), "host.firewall", os, needs);
    let check = Firewall::new(ports.iter().copied());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(check.run(&ctx));
    Ran { outcome, run }
}

fn run_case(case: &Case, ports: &[u16]) -> Ran {
    execute(load(case, Replay::new()), case.root, Os::Linux, ports)
}

const PORTS: &[u16] = &[6443, 10250];

#[test]
fn ports_open_by_number_in_the_default_route_zone_pass() {
    let ran = run_case(&FIREWALLD_PORT_OPEN, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(
        f.message,
        "firewalld zone public allows 6443/tcp and 10250/tcp inbound."
    );
    assert!(f.partial.is_none() && f.fix.is_none());
    assert_eq!(f.observed["active"][0]["ports"]["6443"]["verdict"], "open");
    assert_eq!(f.observed["active"][0]["interface"], "eth0");
    assert_eq!(f.expected["open_inbound"], serde_json::json!([6443, 10250]));
}

#[test]
fn a_closed_port_in_the_default_route_zone_blocks_even_when_another_zone_opens_it() {
    let ran = run_case(&FIREWALLD_CLOSED, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.message, "firewalld blocks 6443/tcp in zone public.");
    assert_eq!(
        f.fix.as_deref(),
        Some(
            "Run `firewall-cmd --permanent --zone=public --add-port=6443/tcp && firewall-cmd --reload`."
        )
    );
    assert_eq!(f.observed["active"][0]["ports"]["10250"]["verdict"], "open");
    // Only the zone of the default-route interface is listed.
    let commands = ran.commands().join("\n");
    assert!(commands.contains("--zone=public"), "{commands}");
    assert!(!commands.contains("--zone=docker"), "{commands}");
}

#[test]
fn a_port_open_by_service_passes_and_the_admin_file_wins_over_the_packaged_one() {
    // 6443 comes from the packaged acme-api.xml. 10250 only from the /etc override of acme-kubelet.xml:
    // the packaged file says 10249.
    let ran = run_case(&FIREWALLD_SERVICE_OPEN, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(
        f.observed["active"][0]["ports"]["6443"]["detail"],
        "service acme-api"
    );
    assert_eq!(
        f.observed["active"][0]["ports"]["10250"]["detail"],
        "service acme-kubelet"
    );
    // The packaged kubelet file is not even read when the admin file exists.
    assert!(
        !ran.paths()
            .iter()
            .any(|p| p == "/usr/lib/firewalld/services/acme-kubelet.xml"),
        "{:?}",
        ran.paths()
    );
}

#[test]
fn a_service_that_has_no_file_is_unknown_not_closed() {
    // The listing names acme-api and acme-kubelet and the machine has neither file.
    let bare = Case {
        files: &[],
        ..FIREWALLD_SERVICE_OPEN
    };
    let ran = execute(load(&bare, Replay::new()), true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message.contains("has no definition file"),
        "{}",
        f.message
    );
    assert!(f.partial.is_none());
}

#[test]
fn a_rich_rule_that_touches_the_port_gives_a_warning_not_a_block() {
    let ran = run_case(&FIREWALLD_RICH_RULE, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message
            .starts_with("Cannot confirm 6443/tcp and 10250/tcp in firewalld zone public")
    );
    assert!(f.message.contains("rich rule"), "{}", f.message);
    // Any rich rule in the zone is a warning for every port (03: "any rich rule present: warn").
    assert_eq!(
        f.observed["active"][0]["ports"]["10250"]["verdict"],
        "unknown"
    );
    assert!(
        f.fix
            .as_deref()
            .is_some_and(|t| t.contains("--list-all --zone=public"))
    );
    // The message describes the rule from its parts. The source network and the rule text are not in it.
    let everything = format!("{} {}", f.message, f.observed);
    assert!(everything.contains("ipv4, source address, port 6443/tcp, drop"));
    assert!(!everything.contains("192.0.2"), "{everything}");
}

#[test]
fn a_direct_rule_file_with_a_rule_gives_a_warning_even_for_open_ports() {
    let ran = run_case(&FIREWALLD_DIRECT_RULE, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("direct rules"), "{}", f.message);
    assert_eq!(
        f.observed["active"][0]["ports"]["6443"]["verdict"],
        "unknown"
    );
    // The same listing with no direct.xml passes.
    let plain = run_case(&FIREWALLD_PORT_OPEN, PORTS);
    assert_eq!(plain.finding().level, Level::Pass);
}

#[test]
fn a_direct_passthrough_gives_a_warning_even_for_open_ports() {
    let replay = load(&FIREWALLD_PORT_OPEN, Replay::new()).file(
        "/etc/firewalld/direct.xml",
        "<?xml version='1.0'?><direct><passthrough ipv=\"ipv4\">-A INPUT -p tcp --dport 6443 -j DROP</passthrough></direct>",
    );
    let ran = execute(replay, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("direct rules"), "{}", f.message);
}

#[test]
fn a_direct_rule_file_that_is_cut_off_is_unknown_not_clear() {
    for xml in [
        "<direct><rule ipv=\"ipv4\"",
        "<direct><!-- ",
        "<!DOCTYPE direct>",
    ] {
        let replay =
            load(&FIREWALLD_PORT_OPEN, Replay::new()).file("/etc/firewalld/direct.xml", xml);
        let ran = execute(replay, true, Os::Linux, PORTS);
        assert_eq!(ran.finding().level, Level::Warn, "{xml}");
    }
    let empty = load(&FIREWALLD_PORT_OPEN, Replay::new()).file(
        "/etc/firewalld/direct.xml",
        "<?xml version='1.0'?><direct/>",
    );
    assert_eq!(
        execute(empty, true, Os::Linux, PORTS).finding().level,
        Level::Pass
    );
}

#[test]
fn a_closed_port_is_unknown_when_another_active_zone_is_bound_to_a_source_network() {
    let ran = run_case(&FIREWALLD_SOURCE_ZONE, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.observed["active"][0]["ports"]["6443"]["verdict"],
        "unknown"
    );
    assert_eq!(f.observed["active"][0]["ports"]["10250"]["verdict"], "open");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("trusted") && n.contains("bound to source addresses")),
        "{:?}",
        f.notes
    );
    // Without the source-bound zone the same listing blocks.
    let plain = run_case(&FIREWALLD_CLOSED, PORTS);
    assert_eq!(plain.finding().level, Level::Fail);
}

#[test]
fn a_zone_that_opens_all_tcp_by_protocol_passes() {
    let replay = firewalld_machine().command(
        "firewall-cmd",
        &["--list-all", "--zone=public"],
        0,
        "public (active)\n  target: default\n  ports: \n  protocols: tcp\n",
    );
    let ran = execute(replay, true, Os::Linux, PORTS);
    assert_eq!(ran.finding().level, Level::Pass, "{:?}", ran.finding());
    assert_eq!(
        ran.finding().observed["active"][0]["ports"]["6443"]["detail"],
        "protocols: tcp"
    );
}

#[test]
fn a_zone_listing_cut_by_a_limit_warns_and_does_not_block() {
    let listing = format!(
        "public (active)\n  target: default\n{}",
        "  masquerade: no\n".repeat(700)
    );
    let replay = firewalld_machine().command(
        "firewall-cmd",
        &["--list-all", "--zone=public"],
        0,
        &listing,
    );
    let ran = execute(replay, true, Os::Linux, PORTS);
    assert_eq!(ran.finding().level, Level::Warn, "{:?}", ran.finding());
}

#[test]
fn a_root_less_run_warns_and_reads_no_rules() {
    let ran = run_case(&FIREWALLD_ROOT_LESS, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("need root"), "{}", f.message);
    let partial = f.partial.as_ref().expect("a partial result");
    assert_eq!(partial.missing, vec![Need::Root]);
    assert!(f.fix.as_deref().is_some_and(|t| t.contains("as root")));
    // Only the state query ran. The zone listing needs root, and the check did not try.
    let commands = ran.commands();
    assert_eq!(commands.len(), 1, "{commands:?}");
    assert!(commands[0].contains("--state"));

    let ufw = run_case(&UFW_ROOT_LESS, PORTS);
    let f = ufw.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.partial.as_ref().expect("partial").missing,
        vec![Need::Root]
    );
    assert!(
        !ufw.paths().iter().any(|p| p == "/etc/ufw/user.rules"),
        "{:?}",
        ufw.paths()
    );
}

#[test]
fn a_stopped_firewalld_and_no_firewall_pass_and_say_what_was_not_read() {
    for case in [&FIREWALLD_NOT_RUNNING, &NO_FIREWALL, &UFW_DISABLED] {
        let ran = run_case(case, PORTS);
        let f = ran.finding();
        assert_eq!(f.level, Level::Pass, "{f:?}");
        assert!(f.message.starts_with("No host firewall manager is active"));
        assert!(f.notes.iter().any(|n| n.contains("nftables or iptables")));
        assert!(f.fix.is_none() && f.partial.is_none());
    }
}

#[test]
fn ufw_with_the_ports_allowed_passes() {
    let ran = run_case(&UFW_ALLOWED, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "ufw allows 6443/tcp and 10250/tcp inbound.");
    assert_eq!(f.observed["active"][0]["interface"], "eth0");
}

#[test]
fn ufw_blocks_a_port_that_no_rule_allows_under_a_drop_policy() {
    let ran = run_case(&UFW_CLOSED, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.message, "ufw blocks 6443/tcp.");
    assert_eq!(f.fix.as_deref(), Some("Run `ufw allow 6443/tcp`."));
    let detail = f.observed["active"][0]["ports"]["6443"]["detail"]
        .as_str()
        .unwrap_or_default();
    assert!(detail.contains("default input policy is DROP"), "{detail}");
}

#[test]
fn ufw_rules_with_log_actions_and_comments_pass() {
    let ran = run_case(&UFW_COMMENT_AND_LOG, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "ufw allows 6443/tcp and 10250/tcp inbound.");
}

#[test]
fn a_ufw_rule_line_rdy_cannot_read_warns_and_does_not_block() {
    let ran = run_case(&UFW_UNREAD_RULE, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message.contains("not in the form rdy reads"),
        "{}",
        f.message
    );
}

#[test]
fn an_unreadable_rules_file_read_as_root_does_not_ask_for_root_again() {
    let found = super::ufw_rules_unreadable(&[6443], "permission denied");
    assert!(found.missing.is_empty());
    let Verdict::Unknown(why) = &found.verdicts[0].1 else {
        panic!("expected unknown");
    };
    assert!(
        why.contains("could not be read as root (permission denied)"),
        "{why}"
    );
}

#[test]
fn ufw_rule_limited_to_one_network_is_unknown() {
    let ran = run_case(&UFW_LIMITED_SOURCE, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("6443/tcp"), "{}", f.message);
    assert_eq!(f.observed["active"][0]["ports"]["10250"]["verdict"], "open");
}

#[test]
fn no_ports_requested_reports_the_manager_and_passes() {
    let ran = run_case(&FIREWALLD_ROOT_LESS, &[]);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(f.message.contains("firewalld is active"), "{}", f.message);
    assert!(f.partial.is_none());
}

#[test]
fn on_macos_and_windows_the_check_is_not_yet_on_this_os() {
    for os in [Os::Macos, Os::Windows] {
        let ran = execute(Replay::new(), true, os, PORTS);
        assert!(
            matches!(ran.outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {:?}",
            ran.outcome
        );
        assert!(ran.run.action_log().actions.is_empty());
    }
}

#[test]
fn every_case_stays_inside_the_manifest_and_runs_only_listed_commands() {
    // A call outside `reads`, an undeclared program or an argv the table does not list is refused by the
    // probe, and the check ends in an error. So a finding for every case, and no refused entry, proves
    // the manifest covers what the check does.
    for (name, case) in ALL {
        let ran = run_case(case, PORTS);
        assert!(ran.outcome.is_ok(), "{name}: {:?}", ran.outcome);
        for action in ran.run.action_log().actions {
            assert_ne!(action.outcome, ActionOutcome::Denied, "{name}: {action:?}");
            if action.kind == ActionKind::Exec {
                assert_eq!(action.fields["program"], "firewall-cmd", "{name}");
            }
        }
    }
}

#[test]
fn every_message_and_fix_the_cases_produce_passes_the_fix_text_audit() {
    if let Err(error) = rdy_engine::fixtext::check(info().meta.remediation) {
        panic!("remediation: {error}");
    }
    for (name, case) in ALL {
        let ran = run_case(case, PORTS);
        let f = ran.finding();
        for text in f.fix.iter().chain(std::iter::once(&f.message)) {
            if let Err(error) = rdy_engine::fixtext::check(text) {
                panic!("{name}: {error}");
            }
        }
    }
}

#[test]
fn the_declared_facts_match_the_catalog() {
    let info = info();
    assert_eq!((info.id, info.family), ("host.firewall", "host"));
    assert_eq!(info.default_timeout, Some(Duration::from_secs(5)));
    assert!(info.needs.is_empty());
    assert_eq!(info.wants.len(), 1);
    assert_eq!(info.wants[0].need, Need::Root);
    assert!(!info.wants[0].evidence_only);
    assert_eq!(info.os.on(Os::Linux), rdy_engine::check::Support::Full);
    assert_eq!(info.os.on(Os::Macos), rdy_engine::check::Support::NotYet);
    assert!(info.reads.iter().all(|p| p.starts_with('/')));
    let entry = table::entry("firewall-cmd").expect("a table entry");
    assert!(entry.checks.contains(&"host.firewall"));
    assert_eq!(info.commands.len(), 1);
    assert_eq!(info.commands[0].program, "firewall-cmd");
}

#[test]
fn new_sorts_dedups_and_drops_port_zero() {
    assert_eq!(Firewall::new([10250, 6443, 6443, 0]).ports(), [6443, 10250]);
    assert_eq!(Firewall::new(0..=u16::MAX).ports().len(), 256);
}

// Machines that are not fixture cases: odd tools and odd text.

fn firewalld_machine() -> Replay {
    load(&BASE_FIREWALLD, Replay::new())
}

#[test]
fn a_zone_name_that_fails_the_command_table_rule_is_not_passed_to_the_tool() {
    let replay = Replay::new()
        .dir("/run/firewalld", vec![])
        .file("/proc/net/route", fx!(firewalld "root/proc/net/route"))
        .command("firewall-cmd", &["--state"], 0, "running\n")
        .command(
            "firewall-cmd",
            &["--get-active-zones"],
            0,
            "pub.lic\n  interfaces: eth0\n",
        );
    let ran = execute(replay, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message.contains("characters rdy does not pass"),
        "{}",
        f.message
    );
    assert_eq!(ran.commands().len(), 2, "{:?}", ran.commands());
}

#[test]
fn a_missing_firewall_cmd_with_a_run_directory_warns_and_names_the_program() {
    let replay = Replay::new()
        .dir("/run/firewalld", vec![])
        .missing("firewall-cmd");
    let ran = execute(replay, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(
        f.partial.as_ref().expect("partial").missing,
        vec![Need::Command("firewall-cmd")]
    );
}

#[test]
fn an_exit_code_the_table_does_not_know_is_a_warning_not_a_crash() {
    let replay =
        Replay::new()
            .dir("/run/firewalld", vec![])
            .command("firewall-cmd", &["--state"], 2, "");
    let ran = execute(replay, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("exited with code 2"), "{}", f.message);
}

#[test]
fn several_zones_and_no_default_route_is_unknown_and_one_zone_is_used_with_a_note() {
    let two = Replay::new()
        .dir("/run/firewalld", vec![])
        .command("firewall-cmd", &["--state"], 0, "running\n")
        .command(
            "firewall-cmd",
            &["--get-active-zones"],
            0,
            "public\n  interfaces: eth0\ndocker\n  interfaces: docker0\n",
        );
    let ran = execute(two, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(f.message.contains("no default route"), "{}", f.message);

    let one = Replay::new()
        .dir("/run/firewalld", vec![])
        .command("firewall-cmd", &["--state"], 0, "running\n")
        .command(
            "firewall-cmd",
            &["--get-active-zones"],
            0,
            "public\n  interfaces: eth0\n",
        )
        .command(
            "firewall-cmd",
            &["--list-all", "--zone=public"],
            0,
            "public (active)\n  target: default\n  ports: 6443/tcp 10250/tcp\n",
        );
    let ran = execute(one, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert!(
        f.notes.iter().any(|n| n.contains("only active zone")),
        "{:?}",
        f.notes
    );
}

#[test]
fn a_listing_that_is_not_a_zone_is_a_warning() {
    // A zone header starts in the first column.
    let replay = firewalld_machine().command(
        "firewall-cmd",
        &["--list-all", "--zone=public"],
        0,
        "  indented first\n",
    );
    let ran = execute(replay, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert!(
        f.message.contains("not in the form rdy reads"),
        "{}",
        f.message
    );
}

#[test]
fn a_zone_whose_target_is_accept_opens_every_port() {
    let replay = firewalld_machine().command(
        "firewall-cmd",
        &["--list-all", "--zone=public"],
        0,
        "public (active)\n  target: ACCEPT\n  ports: \n",
    );
    let ran = execute(replay, true, Os::Linux, PORTS);
    assert_eq!(ran.finding().level, Level::Pass, "{:?}", ran.finding());
}

#[test]
fn both_managers_enabled_are_both_judged_and_a_closed_port_in_either_blocks() {
    let replay = load(&UFW_CLOSED, Replay::new());
    let replay = load(&FIREWALLD_PORT_OPEN, replay);
    let ran = execute(replay, true, Os::Linux, PORTS);
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.message, "ufw blocks 6443/tcp.");
    assert_eq!(f.observed["active"].as_array().map(Vec::len), Some(2));
}
