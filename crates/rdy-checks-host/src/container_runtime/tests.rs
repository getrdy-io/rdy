//! Tests of `host.container_runtime` against the synthetic machines under
//! `tests/fixtures/checks/host.container_runtime/`.
//!
//! Every case loads with the real fixture loader and runs through the real scheduler, so the check
//! timeout, the manifest (`reads`, `env`, `commands` and the declared sockets) and the action log are
//! the ones a run has. The Docker and Podman API replies are `api/*.json` files in the case: a record
//! with an empty query answers `/var/run/docker.sock`, and `socket=<path>` in the query names another
//! socket. Each case has an `expect.json` with the spec entry and the reviewed result. The test crate
//! may not read files, so the goldens are compiled in with `include_str!` to read the spec entry.

use std::sync::Arc;
use std::time::Duration;

use rdy_engine::check::{CheckContext, CheckError, Level, Need, Os};
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned};
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, Replay, TestRun, assert_within_manifest, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::{Action, ActionKind, ActionOutcome, CheckResult, Status};
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

macro_rules! expect {
    ($case:literal) => {
        (
            $case,
            include_str!(concat!(
                "../../../../tests/fixtures/checks/host.container_runtime/",
                $case,
                "/expect.json"
            )),
        )
    };
}

/// Every case, with its golden.
const CASES: &[(&str, &str)] = &[
    expect!("docker-ok"),
    expect!("docker-slow"),
    expect!("docker-hung"),
    expect!("docker-group-user"),
    expect!("docker-no-dtype"),
    expect!("docker-old-version"),
    expect!("docker-cgroupfs"),
    expect!("docker-vfs"),
    expect!("docker-proxy"),
    expect!("docker-no-access"),
    expect!("docker-down"),
    expect!("docker-down-bad-json"),
    expect!("docker-dropin-proxy"),
    expect!("docker-rootless"),
    expect!("docker-podman-shim"),
    expect!("podman-ok"),
    expect!("podman-no-dtype"),
    expect!("containerd-ok"),
    expect!("containerd-v2-cgroupfs"),
    expect!("containerd-v3-cgroupfs"),
    expect!("containerd-v3-ok"),
    expect!("containerd-no-config"),
    expect!("containerd-misplaced"),
    expect!("containerd-stopped"),
    expect!("containerd-imports"),
    expect!("containerd-bad-config"),
    expect!("containerd-snapshotter"),
    expect!("containerd-no-access"),
    expect!("containerd-v3-snapshotter"),
    expect!("containerd-registry-auth"),
    expect!("docker-and-containerd"),
    expect!("docker-dtype-and-containerd"),
    expect!("docker-slow-containerd-ok"),
    expect!("crio-ok"),
    expect!("crio-cgroup-spec"),
    expect!("none"),
    expect!("none-spec-lists-docker"),
];

/// Cases that end in a timeout and so have no finding.
const HUNG: &[&str] = &["docker-hung"];

/// The secret that sits in two of the cases, in a Docker `/info` body and in `daemon.json`.
const SECRET: &str = "REDACTED-TEST-TOKEN";

fn load(case: &str) -> Fixture {
    let fixture = Fixture::load(
        &fixtures_dir(),
        &format!("checks/host.container_runtime/{case}"),
    )
    .unwrap_or_else(|e| panic!("{case} does not load: {e}"));
    fixture
        .ensure_answers("host.container_runtime")
        .expect("it answers");
    fixture
}

fn check(entry: &Value) -> ContainerRuntimeCheck {
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    match spec.decode_params() {
        CheckParams::HostContainerRuntime(params) => ContainerRuntimeCheck::from_params(&params),
        other => panic!("not host.container_runtime: {other:?}"),
    }
}

/// The machine of the fixture, with its recorded API replies served on the sockets they name.
fn machine(case: &str, fixture: &Fixture) -> Replay {
    let uid = if case == "docker-rootless" || !fixture.available_needs().contains(&Need::Root) {
        1000
    } else {
        0
    };
    let mut replay = fixture.replay().clone().ids([uid; 4], [uid; 4]);
    let records: Vec<(String, String, u16, Value, Duration)> = fixture
        .replay()
        .api_records()
        .map(|(method, path, query, record)| {
            assert_eq!(method, "GET", "{case}: only GET is recorded");
            let socket = query.strip_prefix("socket=").unwrap_or(DOCKER_SOCKET);
            (
                socket.to_owned(),
                path.to_owned(),
                record.status,
                record.body.clone(),
                record.delay,
            )
        })
        .collect();
    for (socket, path, status, body, delay) in records {
        replay = replay.unix_get_after(
            &socket,
            &path,
            status,
            serde_json::to_vec(&body).expect("json"),
            delay,
        );
    }
    replay
}

const DOCKER_SOCKET: &str = SOCK_DOCKER;

/// What a run produced.
struct Run {
    end: End,
    log: ActionLogOutput,
    ctx: CheckContext,
    entry: CheckSpec,
}

impl Run {
    fn finding(&self) -> &rdy_engine::check::Finding {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        done.as_ref().as_ref().expect("a finding")
    }

    /// The result entry the engine writes for this run: the level after the severity cap and the
    /// partial rule, which is what the report shows.
    fn result(&self) -> CheckResult {
        let End::Done(done) = &self.end else {
            panic!("the check did not finish: {:?}", self.end);
        };
        map_outcome(&INFO, &self.entry, &self.ctx, done.as_ref().clone(), 0, 0)
    }
}

/// A spec `timeout` in the entry, as the scheduler gets it.
fn spec_timeout(entry: &Value) -> Option<Duration> {
    match entry.get("timeout").and_then(Value::as_str) {
        Some("1s") => Some(Duration::from_secs(1)),
        Some(other) => panic!("the tests know only a 1s timeout, not {other}"),
        None => None,
    }
}

fn run_on(case: &str, entry: &Value, os: Os) -> Run {
    let fixture = load(case);
    let test_run = TestRun::new(machine(case, &fixture));
    let scheduler = test_run.scheduler(1, os, fixture.available_needs());
    let mut planned = Planned::new(Arc::new(check(entry)), "host.container_runtime");
    if let Some(timeout) = spec_timeout(entry) {
        planned = planned.with_timeout(timeout);
    }
    let ctx = test_run.context_for(
        &INFO,
        "host.container_runtime",
        os,
        fixture.available_needs(),
    );
    let spec: CheckSpec = serde_json::from_value(entry.clone()).expect("a check entry");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let mut ran = runtime.block_on(scheduler.run(vec![planned]));
    Run {
        end: ran.remove(0).end,
        log: test_run.action_log(),
        ctx,
        entry: spec,
    }
}

fn run(case: &str) -> Run {
    run_on(case, &entry_of(case), Os::Linux)
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

/// The value with every object's keys in order, so the goldens do not depend on `preserve_order`.
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
        let result = run(case);
        let actual = json!({ "entry": entry, "result": render(&result.end) });
        let mut bytes = serde_json::to_string_pretty(&sorted(actual)).expect("json");
        bytes.push('\n');
        assert_golden(
            fixtures_dir().join(format!("checks/host.container_runtime/{case}/expect.json")),
            bytes,
        );
    }
}

#[test]
fn the_case_list_has_no_repeat_and_names_the_exit_test_cases() {
    let names: Vec<&str> = CASES.iter().map(|(name, _)| *name).collect();
    for expected in [
        "docker-ok",
        "docker-no-dtype",
        "docker-cgroupfs",
        "docker-no-access",
        "containerd-v2-cgroupfs",
        "containerd-v3-cgroupfs",
        "none",
    ] {
        assert!(names.contains(&expected), "{expected}");
    }
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "a case is listed twice");
}

#[test]
fn the_levels_are_what_the_catalog_says() {
    let expected = [
        ("docker-ok", Level::Pass),
        ("docker-slow", Level::Warn),
        ("docker-group-user", Level::Pass),
        ("docker-no-dtype", Level::Fail),
        ("docker-old-version", Level::Fail),
        ("docker-cgroupfs", Level::Fail),
        ("docker-vfs", Level::Fail),
        ("docker-proxy", Level::Pass),
        ("docker-no-access", Level::Warn),
        ("docker-down", Level::Warn),
        ("docker-down-bad-json", Level::Warn),
        ("docker-dropin-proxy", Level::Warn),
        ("docker-rootless", Level::Pass),
        ("docker-podman-shim", Level::Fail),
        ("podman-ok", Level::Pass),
        ("podman-no-dtype", Level::Fail),
        ("containerd-ok", Level::Pass),
        ("containerd-v2-cgroupfs", Level::Fail),
        ("containerd-v3-cgroupfs", Level::Fail),
        ("containerd-v3-ok", Level::Pass),
        ("containerd-no-config", Level::Fail),
        ("containerd-misplaced", Level::Fail),
        ("containerd-stopped", Level::Warn),
        ("containerd-imports", Level::Warn),
        ("containerd-bad-config", Level::Warn),
        ("containerd-snapshotter", Level::Fail),
        ("containerd-no-access", Level::Warn),
        ("containerd-v3-snapshotter", Level::Fail),
        ("containerd-registry-auth", Level::Pass),
        ("docker-and-containerd", Level::Pass),
        ("docker-dtype-and-containerd", Level::Fail),
        ("docker-slow-containerd-ok", Level::Pass),
        ("crio-ok", Level::Pass),
        ("crio-cgroup-spec", Level::Warn),
        ("none", Level::Fail),
        ("none-spec-lists-docker", Level::Fail),
    ];
    // A case that ends in a timeout has no level; its own test checks it.
    assert_eq!(
        expected.len() + HUNG.len(),
        CASES.len(),
        "a case has no level here"
    );
    for (case, level) in expected {
        let result = run(case);
        assert_eq!(result.finding().level, level, "{case}");
        // The report shows the mapped status, with the partial rule applied. A run without root passes
        // when it read what it needed: root is evidence only.
        let status = match level {
            Level::Pass => Status::Pass,
            Level::Warn => Status::Warn,
            Level::Fail => Status::Block,
        };
        assert_eq!(result.result().status, status, "{case}: the mapped status");
    }
}

#[test]
fn a_pass_without_root_stays_a_pass_in_the_report() {
    for case in ["docker-group-user", "docker-rootless"] {
        let result = run(case);
        let mapped = result.result();
        assert_eq!(mapped.status, Status::Pass, "{case}: {:?}", mapped.message);
        assert!(
            !mapped.message.starts_with("not verified"),
            "{case}: {}",
            mapped.message
        );
        // The missing root is still on the record.
        assert!(
            mapped
                .partial
                .as_ref()
                .is_some_and(|p| !p.missing.is_empty()),
            "{case}: {:?}",
            mapped.partial
        );
    }
}

#[test]
fn a_cgroup_mismatch_names_the_table_of_the_config_version() {
    let v2 = run("containerd-v2-cgroupfs");
    let fix = v2.finding().fix.clone().expect("a fix");
    assert!(
        fix.contains("[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]"),
        "{fix}"
    );
    assert!(fix.contains("SystemdCgroup = true"), "{fix}");
    assert!(fix.contains("systemctl restart containerd"), "{fix}");
    assert!(!fix.contains("cri.v1.runtime"), "{fix}");
    assert!(
        v2.finding().message.contains("cgroupfs")
            && v2.finding().message.contains("kubelet uses systemd"),
        "{}",
        v2.finding().message
    );

    let v3 = run("containerd-v3-cgroupfs");
    let fix = v3.finding().fix.clone().expect("a fix");
    assert!(
        fix.contains("[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]"),
        "{fix}"
    );
    assert!(!fix.contains("grpc.v1.cri"), "{fix}");
}

#[test]
fn a_setting_under_the_wrong_version_table_is_called_out() {
    let result = run("containerd-misplaced");
    let finding = result.finding();
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("which a version 3 file does not read")
            && fix.contains("io.containerd.cri.v1.runtime"),
        "{fix}"
    );
    assert!(
        finding.notes.iter().any(|n| n.contains("does not read")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn no_config_file_means_the_default_cgroupfs_and_the_fix_writes_the_file() {
    let result = run("containerd-no-config");
    let finding = result.finding();
    assert_eq!(finding.observed["runtimes"][0]["cgroup_driver"], "cgroupfs");
    assert_eq!(
        finding.observed["runtimes"][0]["cgroup_driver_source"],
        "containerd's built-in default (no config file)"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("containerd config default | sudo tee /etc/containerd/config.toml"),
        "{fix}"
    );
    // containerd 2 writes a version 3 file.
    assert!(fix.contains("io.containerd.cri.v1.runtime"), "{fix}");
}

#[test]
fn d_type_unsupported_blocks_with_the_docker_fix() {
    let result = run("docker-no-dtype");
    let finding = result.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.message.contains("d_type"), "{}", finding.message);
    assert_eq!(finding.observed["runtimes"][0]["d_type"], false);
    assert!(
        finding
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("data-root"))
    );
}

#[test]
fn the_best_allowed_runtime_decides_and_the_other_becomes_a_note() {
    let result = run("docker-and-containerd");
    let finding = result.finding();
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding.message.starts_with("containerd 1.7.13 is running"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.starts_with("docker:") && n.contains("kubelet uses systemd")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn a_docker_socket_served_by_podman_is_podman() {
    let result = run("docker-podman-shim");
    let finding = result.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("only podman was found"),
        "{}",
        finding.message
    );
    assert_eq!(finding.observed["runtimes"][0]["runtime"], "podman");
}

#[test]
fn the_rootless_socket_is_found_through_xdg_runtime_dir() {
    let result = run("docker-rootless");
    let finding = result.finding();
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(
        finding.message,
        "docker (rootless) 24.0.7 is running (cgroup driver systemd, storage driver overlay2)."
    );
    assert_eq!(finding.observed["runtimes"][0]["rootless"], true);
    assert_eq!(
        finding.observed["runtimes"][0]["socket"],
        "/run/user/1000/docker.sock"
    );
}

#[test]
fn a_user_outside_the_docker_group_gets_a_partial_result_not_a_failure() {
    let result = run("docker-no-access");
    let finding = result.finding();
    assert_eq!(finding.level, Level::Warn);
    let partial = finding.partial.as_ref().expect("partial");
    assert_eq!(partial.missing, [Need::Root]);
    assert!(
        partial.note.contains("run rdy as root")
            && partial
                .note
                .contains("Membership of the docker group is the same as root"),
        "{}",
        partial.note
    );
    assert!(
        finding.message.contains("may not open its socket"),
        "{}",
        finding.message
    );
    // daemon.json still tells the configured driver, and the note says it is not the live value.
    assert_eq!(finding.observed["runtimes"][0]["cgroup_driver"], "systemd");
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("not from the running daemon")),
        "{:?}",
        finding.notes
    );
    // The kubelet directory is root only, and the drivers are compared, so that is a warning of the
    // runtime and not a note (root is evidence only, so the engine would not catch it).
    assert!(
        finding.message.contains("kubelet config"),
        "{}",
        finding.message
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(fix.contains("Run rdy as root"), "{fix}");
}

#[test]
fn nothing_found_is_a_block_that_names_what_rdy_looked_for() {
    let none = run("none");
    assert!(
        none.finding()
            .message
            .starts_with("No container runtime was found.")
    );
    let listed = run("none-spec-lists-docker");
    assert_eq!(
        listed.finding().message,
        "No allowed container runtime was found. The spec needs docker or containerd."
    );
    assert!(
        listed
            .finding()
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("systemctl enable --now docker"))
    );
}

#[test]
fn the_docker_info_body_is_redacted_before_anything_is_kept() {
    for case in ["docker-proxy", "docker-no-access", "docker-dropin-proxy"] {
        let result = run(case);
        let finding = result.finding();
        let everything = format!(
            "{} {} {:?} {:?} {:?}",
            finding.message, finding.observed, finding.notes, finding.fix, result.log
        );
        assert!(
            !everything.contains(SECRET),
            "{case}: the secret reached the finding"
        );
        assert!(
            !everything.contains("acme-svc:"),
            "{case}: the user and password reached the finding"
        );
    }
    // The proxy is still reported, with the credentials masked.
    let result = run("docker-proxy");
    let proxy = &result.finding().observed["runtimes"][0]["proxy"];
    let http = proxy["http"].as_str().expect("a proxy");
    assert!(http.contains("proxy.acme.example:3128"), "{http}");
    assert_eq!(proxy["source"], "docker info");
}

#[test]
fn a_proxy_in_a_drop_in_is_reported_when_the_api_cannot_be() {
    let result = run("docker-dropin-proxy");
    let finding = result.finding();
    let proxy = &finding.observed["runtimes"][0]["proxy"];
    assert_eq!(proxy["source"], "a systemd drop-in");
    assert_eq!(proxy["no_proxy"], "localhost,.cluster.local");
    assert!(
        finding.notes.iter().any(|n| n.contains("has a proxy set")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn every_request_is_a_get_to_a_declared_socket_and_the_log_says_so() {
    let mut requests = 0;
    for (case, _) in CASES {
        let result = run(case);
        for action in &result.log.actions {
            if action.kind != ActionKind::Http {
                continue;
            }
            requests += 1;
            let get: &Action = action;
            assert_eq!(
                get.fields.get("method").and_then(Value::as_str),
                Some("GET"),
                "{case}"
            );
            let url = get.fields.get("url").and_then(Value::as_str).expect("url");
            assert!(url == "/version" || url == "/info", "{case}: {url}");
            assert_ne!(get.outcome, ActionOutcome::Denied, "{case}: {get:?}");
        }
    }
    assert!(requests > 20, "the cases made only {requests} requests");
}

#[test]
fn a_run_stays_inside_the_manifest() {
    for (case, _) in CASES {
        if HUNG.contains(case) {
            continue;
        }
        let result = run(case);
        assert!(result.finding().observed.is_object(), "{case}");
        for action in &result.log.actions {
            // A program that is not installed is logged as refused: "was not found in the search path".
            let absent = action.kind == ActionKind::Exec
                && action
                    .fields
                    .get("rule")
                    .and_then(Value::as_str)
                    .is_some_and(|rule| rule.contains("was not found in"));
            if !absent {
                assert_ne!(action.outcome, ActionOutcome::Denied, "{case}: {action:?}");
            }
        }
        assert_within_manifest(case, &INFO, &result.log);
    }
}

#[test]
fn a_daemon_that_never_answers_ends_in_the_check_timeout() {
    let result = run("docker-hung");
    assert_eq!(
        result.end,
        End::TimedOut {
            after: Duration::from_secs(1)
        }
    );
    // One request went out and never came back. Nothing else was asked of the daemon.
    let requests: Vec<&Action> = result
        .log
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::Http)
        .collect();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(
        requests[0].fields.get("url").and_then(Value::as_str),
        Some("/version")
    );
}

#[test]
fn the_manifest_names_exactly_the_sockets_and_programs_the_check_uses() {
    assert_eq!(
        INFO.peers,
        [
            PeerClass::UnixSocket("/var/run/docker.sock"),
            PeerClass::UnixSocket("/run/podman/podman.sock"),
            PeerClass::UnixSocket("/run/user/{uid}/docker.sock"),
            PeerClass::UnixSocket("/run/user/{uid}/podman/podman.sock"),
        ]
    );
    let programs: Vec<&str> = INFO.commands.iter().map(|c| c.program).collect();
    assert_eq!(programs, ["containerd", "crio"]);
    assert_eq!(INFO.env, ["XDG_RUNTIME_DIR"]);
    assert!(INFO.needs.is_empty());
    assert_eq!(INFO.wants.len(), 1);
    assert_eq!(INFO.wants[0].need, Need::Root);
    assert!(INFO.wants[0].evidence_only);
    // No prefix grant to every user's session files: the rootless sockets are not read or stat-ed.
    assert!(
        INFO.reads.iter().all(|r| !r.starts_with("/run/user")),
        "{:?}",
        INFO.reads
    );
    assert_eq!(
        INFO.default_timeout,
        Some(std::time::Duration::from_secs(5))
    );
}

#[test]
fn a_spec_that_names_one_runtime_never_asks_the_others() {
    // `docker-and-containerd` records both daemons. With `runtime: [containerd]` the Docker socket is
    // not touched, not even a stat.
    let result = run_on(
        "docker-and-containerd",
        &json!({"id": "host.container_runtime", "runtime": ["containerd"]}),
        Os::Linux,
    );
    assert_eq!(result.finding().level, Level::Pass);
    for action in &result.log.actions {
        let touched = action
            .fields
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(!touched.contains("docker.sock"), "{action:?}");
        assert_ne!(action.kind, ActionKind::Http);
    }
}

#[test]
fn macos_and_windows_are_skipped_not_yet() {
    for os in [Os::Macos, Os::Windows] {
        let result = run_on("docker-ok", &entry_of("docker-ok"), os);
        let End::Done(done) = &result.end else {
            panic!("did not finish");
        };
        assert!(
            matches!(done.as_ref(), Err(CheckError::Unsupported(_))),
            "{os:?}: {done:?}"
        );
        assert!(
            result.log.actions.is_empty(),
            "{os:?}: {:?}",
            result.log.actions
        );
    }
}

#[test]
fn a_hostile_version_string_is_cleaned_before_it_is_shown() {
    // Control and bidirectional characters in a version string cannot reach a sentence.
    let mut seen = Seen::new(ContainerRuntime::Docker, false, SOCK_DOCKER);
    seen.socket_present = true;
    seen.api = Api::Read;
    seen.version = Some(clip("24.0.7\u{1b}[2J\u{202e}evil"));
    let finding = judge::judge(
        &ContainerRuntimeCheck::default(),
        &[seen],
        &Kubelet::default(),
        true,
    );
    assert!(!finding.message.contains('\u{1b}'), "{:?}", finding.message);
    assert!(
        !finding.message.contains('\u{202e}'),
        "{:?}",
        finding.message
    );
}

#[test]
fn every_fix_passes_the_fix_text_audit() {
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("the remediation is not on the lists: {error}");
    }
    for (case, _) in CASES {
        if HUNG.contains(case) {
            continue;
        }
        let result = run(case);
        for text in result
            .finding()
            .fix
            .iter()
            .chain(result.finding().notes.iter())
        {
            if let Err(error) = rdy_engine::fixtext::check(text) {
                panic!("{case}: {error}\n{text}");
            }
        }
    }
}

#[test]
fn a_docker_d_type_failure_is_not_hidden_by_a_good_containerd() {
    let result = run("docker-dtype-and-containerd");
    let finding = result.finding();
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.message.contains("d_type"), "{}", finding.message);
    assert!(
        finding.message.starts_with("docker 24.0.7"),
        "{}",
        finding.message
    );
    assert_eq!(result.result().status, Status::Block);
}

#[test]
fn podman_d_type_names_graphroot() {
    let result = run("podman-no-dtype");
    let fix = result.finding().fix.clone().expect("a fix");
    assert!(
        fix.contains("graphroot") && fix.contains("/etc/containers/storage.conf"),
        "{fix}"
    );
    assert!(!fix.contains("data-root"), "{fix}");
}

#[test]
fn a_hung_daemon_does_not_cost_the_other_runtimes_their_result() {
    // The request limit (1.5 s) is under the check budget (5 s), so docker is reported as not answering
    // and containerd decides.
    let result = run("docker-slow-containerd-ok");
    let finding = result.finding();
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding.message.starts_with("containerd 1.7.13"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.starts_with("docker:") && n.contains("within 1500 ms")),
        "{:?}",
        finding.notes
    );
    let alone = run("docker-slow");
    assert_eq!(alone.finding().level, Level::Warn);
    assert!(
        alone.finding().message.contains("within 1500 ms"),
        "{}",
        alone.finding().message
    );
    // The timed-out request is in the log as a timeout.
    assert!(
        alone
            .log
            .actions
            .iter()
            .any(|a| a.kind == ActionKind::Http && a.outcome == ActionOutcome::Timeout),
        "{:?}",
        alone.log.actions
    );
}

#[test]
fn the_snapshotter_fix_names_the_table_of_the_config_version_and_the_value_of_the_spec() {
    let v3 = run("containerd-v3-snapshotter");
    let fix = v3.finding().fix.clone().expect("a fix");
    assert!(
        fix.contains(
            "`snapshotter = \"overlayfs\"` under `[plugins.\"io.containerd.cri.v1.images\"]`"
        ),
        "{fix}"
    );
    assert!(!fix.contains("grpc.v1.cri"), "{fix}");
    let v2 = run("containerd-snapshotter");
    let fix = v2.finding().fix.clone().expect("a fix");
    assert!(
        fix.contains("`snapshotter = \"overlayfs\"` under `[plugins.\"io.containerd.grpc.v1.cri\".containerd]`"),
        "{fix}"
    );
}

#[test]
fn any_fix_that_names_usermod_carries_the_docker_group_warning() {
    let mut seen_usermod = false;
    for (case, _) in CASES {
        if HUNG.contains(case) {
            continue;
        }
        let result = run(case);
        let finding = result.finding();
        let texts = finding
            .fix
            .iter()
            .chain(finding.notes.iter())
            .chain(finding.partial.iter().map(|p| &p.note));
        for text in texts {
            if text.contains("usermod") {
                seen_usermod = true;
                assert!(text.contains(judge::DOCKER_GROUP_WARNING), "{case}: {text}");
                assert!(
                    text.find("Run rdy as root").is_some_and(|root| {
                        text.find("usermod").is_some_and(|user| root < user)
                    }),
                    "{case}: root comes first: {text}"
                );
            }
        }
    }
    assert!(seen_usermod, "no case showed the docker group fix");
    assert!(
        judge::DOCKER_GROUP_WARNING.starts_with("Membership of the docker group is the same as root on this host; running rdy as root once is the smaller grant."),
    );
    assert!(INFO.meta.remediation.contains(judge::DOCKER_GROUP_WARNING));
}

#[test]
fn the_whole_result_is_searched_for_secrets() {
    // The registry password of a containerd config and the proxy password of Docker never reach any
    // part of the result: the finding, its notes and fix, the mapped result entry, or the log.
    for case in [
        "containerd-registry-auth",
        "docker-proxy",
        "docker-no-access",
        "docker-dropin-proxy",
    ] {
        let result = run(case);
        let everything = format!("{:?} {:?} {:?}", result.end, result.result(), result.log);
        assert!(
            !everything.contains(SECRET),
            "{case}: the secret reached the result"
        );
        assert!(
            !everything.contains("acme-svc:"),
            "{case}: user and password reached the result"
        );
    }
    // The config with the password still parses, so the case is judged on its cgroup driver.
    let result = run("containerd-registry-auth");
    assert_eq!(result.finding().level, Level::Pass);
    assert_eq!(
        result.finding().observed["runtimes"][0]["cgroup_driver"],
        "systemd"
    );
}
