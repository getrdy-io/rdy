//! Tests of the privilege gate (M1-042). The ids, masks and auxv are injected through the replay
//! backend, so no test reads the real process.

use std::cell::Cell;

use rdy_engine::check::Os;
use rdy_engine::privilege::{Privilege, PrivilegeError};
use rdy_engine::testing::{Replay, TestRun};
use serde_json::Value;

use super::{gate_then, privilege_gate};
use crate::error::{CliError, ErrorCode};

const USER: [u32; 4] = [1000; 4];

fn status(uid: [u32; 4], gid: [u32; 4], cap_eff: u64, cap_amb: u64) -> String {
    format!(
        "Name:\trdy\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nCapEff:\t{cap_eff:016x}\nCapAmb:\t{cap_amb:016x}\n",
        uid[0], uid[1], uid[2], uid[3], gid[0], gid[1], gid[2], gid[3]
    )
}

/// An auxv with `AT_PHDR`, `AT_SECURE`, `AT_NULL`, in native-endian words.
fn auxv(secure: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (key, value) in [(3_usize, 0x5555_0000_usize), (23, secure), (0, 0)] {
        bytes.extend(key.to_ne_bytes());
        bytes.extend(value.to_ne_bytes());
    }
    bytes
}

async fn snapshot(
    uid: [u32; 4],
    gid: [u32; 4],
    cap_eff: u64,
    cap_amb: u64,
    secure: usize,
) -> Result<Privilege, PrivilegeError> {
    let run = TestRun::new(
        Replay::new()
            .file("/proc/self/status", status(uid, gid, cap_eff, cap_amb))
            .file("/proc/self/auxv", auxv(secure)),
    );
    Privilege::snapshot(&run.run_probe(Os::Linux)).await
}

/// Runs the gate as `rdy run` will and returns the exit code, the two streams and whether the
/// spec-reading step ran.
fn gated(snapshot: Result<Privilege, PrivilegeError>, json: bool) -> (u8, String, String, bool) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let read_the_spec = Cell::new(false);
    let code = gate_then(snapshot, json, &mut out, &mut err, |_, _, _| {
        read_the_spec.set(true);
        0
    });
    (
        code,
        String::from_utf8(out).expect("utf8"),
        String::from_utf8(err).expect("utf8"),
        read_the_spec.get(),
    )
}

#[cfg(not(windows))]
mod linux {
    use super::*;

    #[tokio::test]
    async fn a_clean_snapshot_passes_and_the_next_step_runs() {
        let (code, out, err, ran) = gated(snapshot(USER, USER, 0, 0, 0).await, true);
        assert_eq!((code, ran), (0, true));
        assert!(out.is_empty() && err.is_empty());
        assert!(privilege_gate(snapshot(USER, USER, 0, 0, 0).await).is_ok());
    }

    /// Every injected case of the exit test, with what it injects.
    async fn refusals() -> Vec<(&'static str, Result<Privilege, PrivilegeError>)> {
        vec![
            ("euid", snapshot([1000, 0, 1000, 1000], USER, 0, 0, 0).await),
            (
                "saved uid",
                snapshot([1000, 1000, 0, 1000], USER, 0, 0, 0).await,
            ),
            (
                "fsuid",
                snapshot([1000, 1000, 1000, 0], USER, 0, 0, 0).await,
            ),
            (
                "real uid",
                snapshot([1001, 1000, 1000, 1000], USER, 0, 0, 0).await,
            ),
            ("egid", snapshot(USER, [1000, 0, 1000, 1000], 0, 0, 0).await),
            (
                "saved gid",
                snapshot(USER, [1000, 1000, 0, 1000], 0, 0, 0).await,
            ),
            (
                "fsgid",
                snapshot(USER, [1000, 1000, 1000, 0], 0, 0, 0).await,
            ),
            ("CapEff", snapshot(USER, USER, 1 << 21, 0, 0).await),
            ("CapAmb", snapshot(USER, USER, 0, 1 << 21, 0).await),
            ("AT_SECURE", snapshot(USER, USER, 0, 0, 1).await),
        ]
    }

    #[tokio::test]
    async fn each_injected_mismatch_exits_70_with_the_hint_and_never_runs_the_next_step() {
        for (what, snap) in refusals().await {
            let (code, out, err, ran) = gated(snap, false);
            assert_eq!(code, 70, "{what}");
            assert!(!ran, "{what}: the spec was read");
            assert!(out.is_empty(), "{what}: {out}");
            let lines: Vec<&str> = err.lines().collect();
            assert_eq!(lines.len(), 2, "{what}: {err}");
            assert!(
                lines[0].starts_with("error: rdy will not run"),
                "{what}: {err}"
            );
            assert!(lines[1].starts_with("fix: "), "{what}: {err}");
            for hint in ["chmod u-s,g-s", "setcap -r", "ambient capabilities"] {
                assert!(lines[1].contains(hint), "{what}: {err}");
            }
        }
    }

    #[tokio::test]
    async fn with_json_stdout_carries_the_error_object() {
        let (code, out, _, ran) = gated(snapshot(USER, USER, 0, 0, 1).await, true);
        assert_eq!((code, ran), (70, false));
        let json: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(json["error"]["code"], "internal");
        assert!(
            json["error"]["fix"]
                .as_str()
                .is_some_and(|f| f.contains("setcap -r"))
        );
    }

    #[tokio::test]
    async fn the_gate_gives_a_cli_error_with_exit_code_70() {
        let error = privilege_gate(snapshot(USER, USER, 0, 0, 1).await).expect_err("refused");
        assert!(matches!(error, CliError::Internal(_)));
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(error.exit_code().code(), 70);
        assert!(!error.hint().is_empty());
    }

    #[tokio::test]
    async fn a_snapshot_that_cannot_be_taken_is_a_refusal_too() {
        let run = TestRun::new(Replay::new());
        let snap = Privilege::snapshot(&run.run_probe(Os::Linux)).await;
        assert!(snap.is_err());
        let (code, _, err, ran) = gated(snap, false);
        assert_eq!((code, ran), (70, false));
        assert!(
            err.starts_with("error: rdy could not read /proc/self/status"),
            "{err}"
        );
        assert!(err.contains("fix: check that /proc is mounted"), "{err}");
    }
}

#[tokio::test]
async fn a_windows_snapshot_passes_whether_or_not_whoami_answered() {
    for replay in [
        Replay::new(),
        Replay::new().command("whoami.exe", &["/groups", "/fo", "csv"], 1, ""),
    ] {
        let run = TestRun::new(replay);
        let snap = Privilege::snapshot(&run.run_probe(Os::Windows)).await;
        let (code, _, _, ran) = gated(snap, false);
        assert_eq!((code, ran), (0, true));
    }
}
