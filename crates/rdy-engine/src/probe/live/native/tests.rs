//! Tests of the live native calls, against the real machine and a temporary directory.

#![allow(clippy::expect_used)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rdy_spec::result::ActionOutcome;
use tempfile::TempDir;

use super::*;
use crate::check::{CheckInfo, CheckMeta, Os, OsSupport, Support};
use crate::probe::policy::RULE_OUTSIDE_READS;
use crate::probe::{Backend, Probe, ProbeError, ProbeHub};
use crate::redact::{Redactor, TagKey};

fn manifest(reads: &[&Path]) -> &'static CheckInfo {
    let reads: Vec<&'static str> = reads
        .iter()
        .map(|path| &*Box::leak(path.to_string_lossy().into_owned().into_boxed_str()))
        .collect();
    Box::leak(Box::new(CheckInfo {
        id: "host.fixture",
        family: "host",
        summary: "A test double.",
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
        reads: Box::leak(reads.into_boxed_slice()),
        env: &[],
        commands: &[],
        peers: &[],
    }))
}

struct Sandbox {
    _dir: TempDir,
    root: PathBuf,
    hub: ProbeHub,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("real path");
        #[expect(
            clippy::disallowed_methods,
            reason = "the engine's own tests build the live backend; check crates may not"
        )]
        let backend: Arc<dyn Backend> = crate::probe::live_backend();
        let hub = ProbeHub::new(backend, Redactor::new(TagKey::fixed([5; 32])));
        Self {
            _dir: dir,
            root,
            hub,
        }
    }

    fn check(&self) -> Probe {
        self.hub
            .check_probe("host.fixture", Os::Linux, Some(manifest(&[&self.root])))
    }
}

fn statvfs(path: &Path) -> NativeCall {
    NativeCall::Statvfs {
        path: path.to_path_buf(),
    }
}

#[tokio::test]
async fn statvfs_of_a_directory_inside_the_prefixes_answers_real_numbers() {
    let sandbox = Sandbox::new();
    let value = sandbox
        .check()
        .native(statvfs(&sandbox.root))
        .await
        .expect("statvfs");
    let NativeValue::Statvfs(info) = value else {
        panic!("not a statvfs answer: {value:?}");
    };
    assert!(info.fragment_size > 0);
    assert!(info.blocks > 0);
    assert!(info.blocks_free <= info.blocks);
    assert!(info.blocks_available <= info.blocks_free);
    let log = sandbox.hub.action_log().actions;
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
}

#[tokio::test]
async fn statvfs_outside_the_prefixes_is_refused_before_the_file_system_is_asked() {
    let sandbox = Sandbox::new();
    let error = sandbox
        .check()
        .native(statvfs(Path::new("/")))
        .await
        .expect_err("outside the reads");
    assert!(
        matches!(&error, ProbeError::Denied { rule, .. } if *rule == RULE_OUTSIDE_READS),
        "{error:?}"
    );
}

#[tokio::test]
async fn statvfs_through_a_link_to_a_place_outside_the_prefixes_is_refused() {
    let sandbox = Sandbox::new();
    let link = sandbox.root.join("escape");
    symlink("/", &link).expect("symlink");
    let error = sandbox
        .check()
        .native(statvfs(&link))
        .await
        .expect_err("the real path is outside the reads");
    assert!(matches!(error, ProbeError::Denied { .. }), "{error:?}");
    let log = sandbox.hub.action_log().actions;
    assert_eq!(log[0].outcome, ActionOutcome::Denied);
}

#[tokio::test]
async fn statvfs_of_a_missing_path_is_not_found() {
    let sandbox = Sandbox::new();
    let error = sandbox
        .check()
        .native(statvfs(&sandbox.root.join("absent")))
        .await
        .expect_err("missing");
    assert_eq!(error, ProbeError::NotFound);
}

#[tokio::test]
async fn uname_hostname_and_rlimit_answer() {
    let sandbox = Sandbox::new();
    let probe = sandbox.check();
    let NativeValue::Uname(uname) = probe.native(NativeCall::Uname).await.expect("uname") else {
        panic!("wrong kind");
    };
    assert!(!uname.sysname.is_empty());
    assert!(!uname.machine.is_empty());
    let NativeValue::Hostname(name) = probe.native(NativeCall::Hostname).await.expect("host")
    else {
        panic!("wrong kind");
    };
    assert!(!name.is_empty());
    let NativeValue::Rlimit(limit) = probe
        .native(NativeCall::Rlimit(Resource::Nofile))
        .await
        .expect("rlimit")
    else {
        panic!("wrong kind");
    };
    // A soft limit never exceeds the hard one; `None` is unlimited.
    if let (Some(soft), Some(hard)) = (limit.soft, limit.hard) {
        assert!(soft <= hard);
    }
    assert!(limit.soft.is_none_or(|soft| soft > 0));
}

#[tokio::test]
async fn every_resource_in_the_closed_list_can_be_read() {
    let sandbox = Sandbox::new();
    let probe = sandbox.check();
    for resource in [
        Resource::Nofile,
        Resource::Nproc,
        Resource::Core,
        Resource::Memlock,
        Resource::Stack,
    ] {
        let value = probe
            .native(NativeCall::Rlimit(resource))
            .await
            .expect("rlimit");
        assert!(matches!(value, NativeValue::Rlimit(_)));
    }
}

#[tokio::test]
async fn the_os_trust_roots_are_not_read_yet() {
    let sandbox = Sandbox::new();
    let error = sandbox
        .check()
        .native(NativeCall::SystemRoots)
        .await
        .expect_err("M1-092 owns this");
    assert!(matches!(error, ProbeError::Unsupported(_)), "{error:?}");
    assert_eq!(
        sandbox.hub.action_log().actions[0].outcome,
        ActionOutcome::Failed
    );
}

#[tokio::test]
async fn the_machine_id_is_run_level_and_never_in_the_log() {
    let sandbox = Sandbox::new();
    let check_error = sandbox
        .check()
        .native(NativeCall::MachineId)
        .await
        .expect_err("a check may not ask");
    assert!(matches!(check_error, ProbeError::Denied { .. }));

    let run = sandbox.hub.run_probe_for(Os::Linux);
    let answer = run.native(NativeCall::MachineId).await;
    // A container may have no id. Either way the log and the error text hold no id.
    let raw = [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/run/machine-id",
    ]
    .iter()
    .find_map(|file| std::fs::read_to_string(file).ok())
    .and_then(|text| parse_machine_id(&text));
    let mut shown = serde_json::to_string(&sandbox.hub.action_log().actions).expect("log");
    shown.push_str(&format!("{answer:?}"));
    if let Some(raw) = raw {
        assert!(!shown.contains(&raw), "the raw id leaked");
        // The read itself works through the guard that admits only the two files.
        #[cfg(target_os = "linux")]
        match answer {
            Ok(NativeValue::MachineId(id)) => assert_eq!(id.expose(), raw),
            other => panic!("the id file holds an id, but the call gave {other:?}"),
        }
    }
}

#[test]
fn only_a_32_digit_hex_id_is_an_id() {
    let id = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    assert_eq!(parse_machine_id(&format!("{id}\n")).as_deref(), Some(id));
    assert_eq!(
        parse_machine_id(&id.to_ascii_uppercase()).as_deref(),
        Some(id)
    );
    for bad in [
        "",
        "\n",
        "uninitialized\n",
        &id[..31],
        &format!("{id}0"),
        "zf1e2d3c4b5a69788796a5b4c3d2e1f0",
    ] {
        assert_eq!(parse_machine_id(bad), None, "{bad:?}");
    }
}
