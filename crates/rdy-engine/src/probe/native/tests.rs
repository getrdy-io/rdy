//! Tests of native calls through the facade, on the replay backend.
//!
//! The exit test of M1-046 is spread over these tests:
//! - `statvfs_outside_the_declared_prefixes_is_refused_and_logged`;
//! - `every_variant_is_logged_as_native_and_never_with_its_answer`;
//! - `the_raw_machine_id_appears_nowhere_in_the_log_or_in_any_debug_text`;
//! - `the_variant_snapshot_fails_on_a_new_variant`;
//! - the lint wall half (check crates cannot call `live_backend`) is `tests/lint-wall` (M1-044: `wall_intact` floor and `uses.rs`).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::{Value, json};

use super::*;
use crate::check::{BoxFuture, CheckInfo, CheckMeta, Os, OsSupport, Support};
use crate::probe::policy::{
    RULE_MACHINE_ID_FILE, RULE_OUTSIDE_READS, RULE_OUTSIDE_STATFS, RULE_SYSTEM_SECRET,
};
use crate::probe::replay::Replay;
use crate::probe::sealed::Sealed;
use crate::probe::{
    Backend, DirEntry, FileBytes, FileMeta, ProbeHub, RULE_CHECK_FINISHED, ReadRange,
};
use crate::redact::{Redactor, TagKey};

/// A made-up id. It must not occur in any log or debug text.
const RAW_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

static DISK_CHECK: CheckInfo = CheckInfo {
    id: "host.fixture",
    family: "host",
    summary: "Asks for free space.",
    meta: CheckMeta {
        title: "Fixture check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::NotYet,
    },
    reads: &[],
    statfs: &["/var/lib"],
    env: &[],
    commands: &[],
    peers: &[],
};

/// A check that declared `/` as a read prefix and as a `statfs` prefix: it can read and measure anywhere
/// the denylist allows.
static BROAD_CHECK: CheckInfo = CheckInfo {
    id: "host.fixture",
    family: "host",
    summary: "Asks for free space on any path.",
    meta: CheckMeta {
        title: "Fixture check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::NotYet,
    },
    reads: &["/"],
    statfs: &["/"],
    env: &[],
    commands: &[],
    peers: &[],
};

/// A disk check as M1-068 declares it: `statfs: ["/"]` and no `reads`, so any path gets file system
/// numbers and no file can be read.
static STATFS_ONLY: CheckInfo = CheckInfo {
    id: "host.fixture",
    family: "host",
    summary: "Asks for free space on any path and reads no file.",
    meta: CheckMeta {
        title: "Fixture check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::NotYet,
    },
    reads: &[],
    statfs: &["/"],
    env: &[],
    commands: &[],
    peers: &[],
};

/// A check that declared `reads` over the tree and no `statfs`: `reads` does not judge `Statvfs`.
static READS_ONLY: CheckInfo = CheckInfo {
    id: "host.fixture",
    family: "host",
    summary: "Reads files and asks for no file system numbers.",
    meta: CheckMeta {
        title: "Fixture check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Full,
        windows: Support::NotYet,
    },
    reads: &["/"],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

fn hub(replay: Replay) -> ProbeHub {
    ProbeHub::new(Arc::new(replay), Redactor::new(TagKey::fixed([3; 32])))
}

fn field<'a>(action: &'a Action, name: &str) -> Option<&'a Value> {
    action.fields.get(name)
}

fn disk() -> StatvfsInfo {
    StatvfsInfo {
        fragment_size: 4096,
        blocks: 1000,
        blocks_free: 400,
        blocks_available: 300,
        files: 5000,
        files_free: 4000,
        no_exec: Some(true),
        ..StatvfsInfo::default()
    }
}

fn statvfs(path: &str) -> NativeCall {
    NativeCall::Statvfs {
        path: PathBuf::from(path),
    }
}

/// One of each variant, in the order of the snapshot.
fn all_calls() -> Vec<NativeCall> {
    vec![
        statvfs("/var/lib"),
        NativeCall::Uname,
        NativeCall::Rlimit(Resource::Nofile),
        NativeCall::Hostname,
        NativeCall::MachineId,
        NativeCall::SystemRoots,
    ]
}

fn answers() -> Replay {
    let uname = UnameInfo {
        sysname: "Linux".to_owned(),
        release: "5.14.0-362.el9.x86_64".to_owned(),
        ..UnameInfo::default()
    };
    let limit = RlimitInfo {
        soft: Some(1024),
        ..RlimitInfo::default()
    };
    Replay::new()
        .native(statvfs("/var/lib"), NativeValue::Statvfs(disk()))
        .native(NativeCall::Uname, NativeValue::Uname(uname))
        .native(
            NativeCall::Rlimit(Resource::Nofile),
            NativeValue::Rlimit(limit),
        )
        .native(
            NativeCall::Hostname,
            NativeValue::Hostname("node-01.example".to_owned()),
        )
        .native(
            NativeCall::MachineId,
            NativeValue::MachineId(MachineId::new(RAW_ID)),
        )
        .native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]]),
        )
}

fn rule_of(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---- Statvfs and the read rules ----------------------------------------------------------------

#[tokio::test]
async fn statvfs_outside_the_declared_prefixes_is_refused_and_logged() {
    let hub = hub(answers().native(statvfs("/etc"), NativeValue::Statvfs(disk())));
    let probe = hub.check_probe("host.fixture", Os::Linux, Some(&DISK_CHECK));

    // Inside the prefix: answered.
    assert_eq!(
        probe.native(statvfs("/var/lib")).await,
        Ok(NativeValue::Statvfs(disk()))
    );
    // Outside it: refused before the backend, though the fixture holds an answer for it.
    let error = probe
        .native(statvfs("/etc"))
        .await
        .expect_err("outside the declared reads");
    assert_eq!(rule_of(&error), RULE_OUTSIDE_STATFS);
    // The denylist applies inside a prefix too, and a relative path or `..` is refused.
    for path in ["/var/lib/../../etc", "var/lib"] {
        assert!(matches!(
            probe.native(statvfs(path)).await,
            Err(ProbeError::Denied { .. })
        ));
    }

    let log = hub.action_log();
    let outcomes: Vec<_> = log
        .actions
        .iter()
        .map(|a| (a.kind.as_str(), a.outcome.clone()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("native", ActionOutcome::Ok),
            ("native", ActionOutcome::Denied),
            ("native", ActionOutcome::Denied),
            ("native", ActionOutcome::Denied),
        ]
    );
    let refused = &log.actions[1];
    assert_eq!(field(refused, "api"), Some(&json!("statvfs")));
    assert_eq!(field(refused, "path"), Some(&json!("/etc")));
    assert_eq!(field(refused, "rule"), Some(&json!(RULE_OUTSIDE_STATFS)));
}

#[tokio::test]
async fn a_statfs_prefix_of_slash_measures_any_path_and_reads_no_file() {
    let replay = answers()
        .native(statvfs("/data/disk0"), NativeValue::Statvfs(disk()))
        .file("/data/disk0/notes.txt", "hello");
    let hub = hub(replay);
    let probe = hub.check_probe("host.fixture", Os::Linux, Some(&STATFS_ONLY));
    assert_eq!(
        probe.native(statvfs("/data/disk0")).await,
        Ok(NativeValue::Statvfs(disk()))
    );
    // No `reads`, so no file, directory or stat is available, wherever it is.
    let file = Path::new("/data/disk0/notes.txt");
    let errors = [
        probe.read(file).await.expect_err("no reads"),
        probe.stat(file).await.expect_err("no reads"),
        probe
            .read_dir(Path::new("/data/disk0"))
            .await
            .expect_err("no reads"),
    ];
    for error in &errors {
        assert_eq!(rule_of(error), RULE_OUTSIDE_READS);
    }
}

#[tokio::test]
async fn the_denylist_still_applies_under_a_statfs_prefix_of_slash() {
    let hub = hub(Replay::new().native(statvfs("/etc/shadow"), NativeValue::Statvfs(disk())));
    let probe = hub.check_probe("host.fixture", Os::Linux, Some(&STATFS_ONLY));
    for path in [
        "/etc/shadow",
        "/home/alice/.ssh/id_rsa",
        "/etc/../etc/shadow",
    ] {
        assert!(
            matches!(
                probe.native(statvfs(path)).await,
                Err(ProbeError::Denied { .. })
            ),
            "{path}"
        );
    }
}

#[tokio::test]
async fn reads_alone_do_not_judge_statvfs() {
    let hub = hub(Replay::new().native(statvfs("/var/lib"), NativeValue::Statvfs(disk())));
    let probe = hub.check_probe("host.fixture", Os::Linux, Some(&READS_ONLY));
    let error = probe
        .native(statvfs("/var/lib"))
        .await
        .expect_err("no statfs prefix");
    assert_eq!(rule_of(&error), RULE_OUTSIDE_STATFS);
}

#[tokio::test]
async fn a_statfs_prefix_matches_whole_components() {
    let hub = hub(Replay::new().native(statvfs("/var/library"), NativeValue::Statvfs(disk())));
    let probe = hub.check_probe("host.fixture", Os::Linux, Some(&DISK_CHECK));
    let error = probe
        .native(statvfs("/var/library"))
        .await
        .expect_err("not under /var/lib");
    assert_eq!(rule_of(&error), RULE_OUTSIDE_STATFS);
}

#[tokio::test]
async fn statvfs_keeps_the_denylist_for_a_probe_with_no_manifest() {
    let hub = hub(Replay::new().native(statvfs("/etc/shadow"), NativeValue::Statvfs(disk())));
    let run = hub.run_probe_for(Os::Linux);
    let error = run
        .native(statvfs("/etc/shadow"))
        .await
        .expect_err("password file");
    assert_eq!(rule_of(&error), RULE_SYSTEM_SECRET);
    // The error shows the path as the log does, and nothing else.
    assert!(error.to_string().contains("/etc/shadow"));
}

#[tokio::test]
async fn a_statvfs_path_under_the_home_directory_is_shown_with_a_tilde() {
    let hub = hub(Replay::new()).with_home("/home/alice");
    let run = hub.run_probe_for(Os::Linux);
    let error = run
        .native(statvfs("/home/alice/data"))
        .await
        .expect_err("not recorded");
    assert!(!error.to_string().contains("alice"), "{error}");
    let log = hub.action_log();
    assert_eq!(field(&log.actions[0], "path"), Some(&json!("~/data")));
}

// ---- every variant is logged as native ---------------------------------------------------------

#[tokio::test]
async fn every_variant_is_logged_as_native_and_never_with_its_answer() {
    let hub = hub(answers());
    let run = hub.run_probe_for(Os::Linux);
    for call in all_calls() {
        run.native(call.clone()).await.expect("recorded");
    }
    let log = hub.action_log();
    assert_eq!(log.actions.len(), all_calls().len());
    let names: Vec<_> = log
        .actions
        .iter()
        .map(|a| field(a, "api").and_then(Value::as_str).unwrap_or_default())
        .collect();
    assert_eq!(
        names,
        [
            "statvfs",
            "uname",
            "rlimit",
            "hostname",
            "machine_id",
            "system_roots"
        ]
    );
    for action in &log.actions {
        assert_eq!(action.kind, ActionKind::Native);
        assert_eq!(action.outcome, ActionOutcome::Ok);
        assert_eq!(action.check, None, "a run-level probe logs check: null");
    }
    assert_eq!(field(&log.actions[0], "path"), Some(&json!("/var/lib")));
    assert_eq!(field(&log.actions[2], "resource"), Some(&json!("nofile")));
    // Only `api`, and `path` or `resource` where the call has one. No answer is in the entry.
    let text = serde_json::to_string(&log.actions).expect("log");
    for answer in ["node-01.example", "5.14.0", RAW_ID] {
        assert!(!text.contains(answer), "{answer} is in the log: {text}");
    }
}

#[tokio::test]
async fn a_call_with_no_recorded_answer_fails_and_is_still_logged() {
    let hub = hub(Replay::new());
    let run = hub.run_probe_for(Os::Linux);
    assert_eq!(
        run.native(NativeCall::Uname).await,
        Err(ProbeError::NotRecorded("the native call uname".to_owned()))
    );
    let log = hub.action_log();
    assert_eq!(log.actions.len(), 1);
    assert_eq!(log.actions[0].kind, ActionKind::Native);
    assert_eq!(log.actions[0].outcome, ActionOutcome::Failed);
}

#[tokio::test]
async fn a_call_after_the_check_ended_is_refused_and_logged() {
    let hub = hub(answers());
    let probe = hub.check_probe("host.fixture", Os::Linux, None);
    probe.end();
    let error = probe
        .native(NativeCall::Uname)
        .await
        .expect_err("check finished");
    assert_eq!(rule_of(&error), RULE_CHECK_FINISHED);
    let log = hub.action_log();
    assert_eq!(log.actions[0].kind, ActionKind::Native);
    assert_eq!(log.actions[0].outcome, ActionOutcome::Denied);
    assert_eq!(log.actions[0].check.as_deref(), Some("host.fixture"));
}

#[tokio::test]
async fn a_closed_probe_refuses_native_calls() {
    let closed = Probe::closed();
    let error = closed
        .native(NativeCall::Hostname)
        .await
        .expect_err("no probe");
    assert_eq!(rule_of(&error), crate::probe::RULE_NO_PROBE);
}

/// A backend with one fixed answer to every native call.
struct Fixed(io::ErrorKind, Option<NativeValue>);

impl Sealed for Fixed {}

impl Backend for Fixed {
    fn open_read<'a>(
        &'a self,
        _: &'a Path,
        _: ReadRange,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<FileBytes>> {
        Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
    }
    fn read_dir<'a>(
        &'a self,
        _: &'a Path,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Vec<DirEntry>>> {
        Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
    }
    fn stat<'a>(
        &'a self,
        _: &'a Path,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<Option<FileMeta>>> {
        Box::pin(async { Ok(None) })
    }
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn native<'a>(
        &'a self,
        _: &'a NativeCall,
        _: &'a ReadGuard,
    ) -> BoxFuture<'a, io::Result<NativeValue>> {
        Box::pin(async move { self.1.clone().ok_or_else(|| io::Error::from(self.0)) })
    }
}

fn fixed_hub(kind: io::ErrorKind, value: Option<NativeValue>) -> ProbeHub {
    ProbeHub::new(
        Arc::new(Fixed(kind, value)),
        Redactor::new(TagKey::fixed([3; 32])),
    )
}

#[tokio::test]
async fn an_os_without_a_source_reports_unsupported_not_an_io_error() {
    let hub = fixed_hub(io::ErrorKind::Unsupported, None);
    let run = hub.run_probe_for(Os::Macos);
    let error = run
        .native(NativeCall::SystemRoots)
        .await
        .expect_err("unsupported");
    assert_eq!(
        error,
        ProbeError::Unsupported("the native call system_roots".to_owned())
    );
    assert!(error.to_string().contains("Fix:"), "{error}");
    assert_eq!(hub.action_log().actions[0].outcome, ActionOutcome::Failed);
}

#[tokio::test]
async fn an_answer_of_the_wrong_kind_is_an_error_not_a_value() {
    let hub = fixed_hub(
        io::ErrorKind::Other,
        Some(NativeValue::Hostname("x".to_owned())),
    );
    let run = hub.run_probe_for(Os::Linux);
    assert!(matches!(
        run.native(NativeCall::Uname).await,
        Err(ProbeError::Io(_))
    ));
    assert!(run.native(NativeCall::Hostname).await.is_ok());
}

// ---- the machine id ----------------------------------------------------------------------------

#[tokio::test]
async fn a_check_cannot_ask_for_the_machine_id_even_when_the_fixture_has_one() {
    let hub = hub(answers());
    let probe = hub.check_probe("host.fixture", Os::Linux, Some(&DISK_CHECK));
    let error = probe
        .native(NativeCall::MachineId)
        .await
        .expect_err("run-level only");
    assert_eq!(rule_of(&error), RULE_MACHINE_ID);
    let log = hub.action_log();
    assert_eq!(log.actions[0].outcome, ActionOutcome::Denied);
    assert_eq!(
        field(&log.actions[0], "rule"),
        Some(&json!(RULE_MACHINE_ID))
    );
}

#[tokio::test]
async fn a_check_with_broad_reads_cannot_read_the_machine_id_files() {
    let replay = Replay::new()
        .file("/etc/machine-id", format!("{RAW_ID}\n"))
        .file("/var/lib/dbus/machine-id", format!("{RAW_ID}\n"));
    let hub = hub(replay);
    let probe = hub.check_probe("host.fixture", Os::Linux, Some(&BROAD_CHECK));
    for file in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        let error = probe.read(Path::new(file)).await.expect_err("denied");
        assert_eq!(rule_of(&error), RULE_MACHINE_ID_FILE, "{file}");
        let error = probe.stat(Path::new(file)).await.expect_err("denied");
        assert_eq!(rule_of(&error), RULE_MACHINE_ID_FILE, "{file}");
        // The same file through `Statvfs` is judged by the same rules.
        let error = probe.native(statvfs(file)).await.expect_err("denied");
        assert_eq!(rule_of(&error), RULE_MACHINE_ID_FILE, "{file}");
    }
    let log = serde_json::to_string(&hub.action_log().actions).expect("log");
    assert!(!log.contains(RAW_ID), "{log}");
}

#[tokio::test]
async fn the_raw_machine_id_appears_nowhere_in_the_log_or_in_any_debug_text() {
    let hub = hub(answers());
    let run = hub.run_probe_for(Os::Linux);
    let value = run.native(NativeCall::MachineId).await.expect("id");
    let NativeValue::MachineId(id) = &value else {
        panic!("not a machine id: {value:?}");
    };
    assert_eq!(id.expose(), RAW_ID, "the value itself is intact");

    let log = serde_json::to_string(&hub.action_log().actions).expect("log");
    let shown = [
        log,
        format!("{value:?}"),
        format!("{id:?}"),
        format!("{:#?}", Ok::<_, ProbeError>(&value)),
        format!("{:?}", answers()),
    ];
    for text in shown {
        assert!(!text.contains(RAW_ID), "the raw id leaked: {text}");
    }
}

#[test]
fn the_machine_id_type_cannot_be_displayed_or_serialized() {
    // Compile-time facts, written as a test so a change shows in review. `MachineId` has `Debug`
    // (which shows nothing), `Clone` and `Eq`, and no `Display`, `Serialize` or public getter.
    let id = MachineId::new(RAW_ID);
    assert_eq!(format!("{id:?}"), "MachineId(..)");
    assert_eq!(id.clone(), id);
}

// ---- the variant snapshot ----------------------------------------------------------------------

/// The index of a variant. There is no wildcard arm, so a new variant does not compile until it is
/// listed here and in `all_calls`.
fn index(call: &NativeCall) -> usize {
    match call {
        NativeCall::Statvfs { .. } => 0,
        NativeCall::Uname => 1,
        NativeCall::Rlimit(_) => 2,
        NativeCall::Hostname => 3,
        NativeCall::MachineId => 4,
        NativeCall::SystemRoots => 5,
    }
}

/// Like [`index`], for the resources.
fn resource_index(resource: Resource) -> usize {
    match resource {
        Resource::Nofile => 0,
        Resource::Nproc => 1,
        Resource::Core => 2,
        Resource::Memlock => 3,
        Resource::Stack => 4,
    }
}

fn snapshot_of_code() -> String {
    let mut lines = Vec::new();
    for call in all_calls() {
        let policy = call.policy();
        let who = match policy.who {
            Who::Any => "any probe",
            Who::RunLevel => "run-level probes only",
        };
        let rules = if policy.path_rules {
            "read denylist and statfs prefixes apply"
        } else {
            "none"
        };
        lines.push(format!("{} | {who} | {rules}", policy.api));
    }
    lines.push("# Resources of Rlimit".to_owned());
    for resource in [
        Resource::Nofile,
        Resource::Nproc,
        Resource::Core,
        Resource::Memlock,
        Resource::Stack,
    ] {
        lines.push(resource.as_str().to_owned());
    }
    lines.join("\n")
}

/// The lines of the snapshot file that are not comments before the resources.
fn snapshot_of_file() -> String {
    include_str!("variants.snap")
        .lines()
        .filter(|line| !line.starts_with('#') || line.starts_with("# Resources"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The variant rows of the snapshot file: every line before `# Resources`, comments left out.
fn snapshot_rows() -> Vec<String> {
    snapshot_of_file()
        .lines()
        .take_while(|line| !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_variant_snapshot_fails_on_a_new_variant() {
    // The real guard is the compile error: `policy`, `expects` and `index` have no wildcard arm, so a
    // new variant does not build until each names it. This test catches what the compiler cannot: a
    // variant that was added to those matches but not to `all_calls` or to `variants.snap`.
    let indexes: Vec<usize> = all_calls().iter().map(index).collect();
    assert_eq!(indexes, [0, 1, 2, 3, 4, 5]);
    assert_eq!(
        snapshot_rows().len(),
        all_calls().len(),
        "variants.snap and all_calls list a different number of variants"
    );
    let resources = [
        Resource::Nofile,
        Resource::Nproc,
        Resource::Core,
        Resource::Memlock,
        Resource::Stack,
    ];
    let resource_indexes: Vec<usize> = resources.into_iter().map(resource_index).collect();
    assert_eq!(resource_indexes, [0, 1, 2, 3, 4]);

    // The policy rows must match the checked-in snapshot. To add a variant, change this file, the
    // module docs and the INV-07 row of the threat model in the same PR.
    assert_eq!(
        snapshot_of_code(),
        snapshot_of_file(),
        "the native call list or a policy row changed: update variants.snap, the module docs and the INV-07 row of docs/plan/05-threat-model.md"
    );
}

#[test]
fn every_api_name_is_distinct_and_fits_the_log() {
    let mut names: Vec<_> = all_calls().iter().map(|c| c.policy().api).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), all_calls().len());
    assert!(names.iter().all(|n| n.len() < 32 && n.is_ascii()));
}

/// The threat model has one row per variant (ADR 0014 decision 5), named by its `api` in backticks.
#[test]
fn the_threat_model_has_a_row_for_every_variant() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/plan/05-threat-model.md");
    let doc = std::fs::read_to_string(&path)
        .expect("docs/plan/05-threat-model.md is in the repository")
        .replace("\r\n", "\n");
    let start = doc
        .find("### Native calls")
        .expect("05 has a Native calls table");
    let section = &doc[start..];
    let end = section[3..].find("\n#").map_or(section.len(), |i| i + 3);
    let rows: Vec<&str> = section[..end]
        .lines()
        .filter(|line| line.starts_with("| `") && !line.starts_with("| `api` |"))
        .collect();
    assert_eq!(
        rows.len(),
        all_calls().len(),
        "one row per variant: {rows:#?}"
    );
    for call in all_calls() {
        let api = call.policy().api;
        assert!(
            rows.iter()
                .any(|row| row.starts_with(&format!("| `{api}` |"))),
            "05 has no row for {api}"
        );
    }
}

/// The `SystemRoots` answer is capped for every backend (M1-092, 05 `system_roots`): at most
/// `MAX_SYSTEM_ROOTS` certificates, none empty and none over `MAX_ROOT_BYTES`.
#[tokio::test]
async fn the_system_roots_answer_is_capped_in_count_and_in_size() {
    let mut offered: Vec<Vec<u8>> = (0..MAX_SYSTEM_ROOTS + 100)
        .map(|i| format!("certificate {i}").into_bytes())
        .collect();
    offered.insert(0, Vec::new());
    offered.insert(1, vec![9; MAX_ROOT_BYTES + 1]);
    offered.insert(2, vec![8; MAX_ROOT_BYTES]);
    let replay = Replay::new().native(
        NativeCall::SystemRoots,
        NativeValue::SystemRoots(offered.clone()),
    );
    let hub = hub(replay);
    let value = hub
        .run_probe_for(Os::Linux)
        .native(NativeCall::SystemRoots)
        .await
        .expect("an answer");
    let NativeValue::SystemRoots(kept) = value else {
        panic!("the wrong kind of answer");
    };
    assert_eq!(kept.len(), MAX_SYSTEM_ROOTS);
    assert_eq!(
        kept[0],
        vec![8; MAX_ROOT_BYTES],
        "the cap on size is inclusive"
    );
    assert!(
        kept.iter()
            .all(|der| !der.is_empty() && der.len() <= MAX_ROOT_BYTES)
    );
    assert_eq!(kept[1], b"certificate 0".to_vec(), "the order is kept");

    // A short answer passes unchanged.
    assert_eq!(cap_system_roots(vec![vec![1], vec![2]]), [vec![1], vec![2]]);
}
