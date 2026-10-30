//! Tests for the privilege snapshot (M1-042). Every id, mask and auxv value is injected through the
//! replay backend, so no test reads the real process.

use serde_json::{Value, json};

use super::*;
use crate::testing::{Replay, TestRun};

#[cfg(not(windows))]
const STATUS: &str = "/proc/self/status";
#[cfg(not(windows))]
const AUXV: &str = "/proc/self/auxv";
const WHOAMI_ARGS: [&str; 3] = ["/groups", "/fo", "csv"];

/// A `/proc/self/status` the way the kernel writes it, with the four lines the snapshot reads.
fn status(uid: [u32; 4], gid: [u32; 4], cap_eff: u64, cap_amb: Option<u64>) -> String {
    let mut text = format!(
        "Name:\trdy\nUmask:\t0022\nState:\tR (running)\nTgid:\t4242\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nGroups:\t4 24 \nCapInh:\t0000000000000000\nCapPrm:\t{cap_eff:016x}\nCapEff:\t{cap_eff:016x}\nCapBnd:\t000001ffffffffff\n",
        uid[0], uid[1], uid[2], uid[3], gid[0], gid[1], gid[2], gid[3]
    );
    if let Some(amb) = cap_amb {
        text.push_str(&format!("CapAmb:\t{amb:016x}\n"));
    }
    text.push_str("NoNewPrivs:\t0\n");
    text
}

/// One native-endian machine word.
fn word(value: u64) -> Vec<u8> {
    usize::try_from(value)
        .expect("fits a word")
        .to_ne_bytes()
        .to_vec()
}

/// An auxv like a real one: other entries with distinctive values, `AT_SECURE`, then `AT_NULL`.
fn auxv(secure: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (key, value) in [
        (33, 0x7ffd_dead_b000_u64), // AT_SYSINFO_EHDR
        (3, 0x5555_cafe_f00d),      // AT_PHDR
        (7, 0x7f12_3456_7000),      // AT_BASE
        (25, 0x7ffd_feed_face),     // AT_RANDOM, a pointer to 16 random bytes
        (31, 0x7ffd_babe_c0de),     // AT_EXECFN, a pointer to the program name
        (AT_SECURE, secure),
        (6, 4096), // AT_PAGESZ
        (AT_NULL, 0),
    ] {
        bytes.extend(word(key));
        bytes.extend(word(value));
    }
    bytes
}

const USER: [u32; 4] = [1000; 4];

#[cfg(not(windows))]
/// A status file whose `CapPrm` line is `cap_prm` and whose `CapEff` is zero, the way a file with
/// `cap_net_raw+p` and no `e` bit looks.
fn status_with_prm(cap_prm: u64) -> String {
    status(USER, USER, 0, Some(0)).replace(
        "CapPrm:\t0000000000000000",
        &format!("CapPrm:\t{cap_prm:016x}"),
    )
}

#[cfg(not(windows))]
fn linux(uid: [u32; 4], gid: [u32; 4], cap_eff: u64, cap_amb: u64, secure: u64) -> Replay {
    Replay::new()
        .file(STATUS, status(uid, gid, cap_eff, Some(cap_amb)))
        .file(AUXV, auxv(secure))
}

#[cfg(not(windows))]
async fn snapshot_of(replay: Replay) -> (Result<Privilege, PrivilegeError>, TestRun) {
    let run = TestRun::new(replay);
    let result = Privilege::snapshot(&run.run_probe(Os::Linux)).await;
    (result, run)
}

#[cfg(not(windows))]
async fn refused_with(replay: Replay) -> Vec<Refusal> {
    let (snapshot, _) = snapshot_of(replay).await;
    match snapshot.expect("the snapshot parses").check() {
        Err(PrivilegeError::Refused(reasons)) => reasons,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// The Linux sources go through `Probe::read`, which refuses every file on a Windows host (no M1 check
// reads files there). The parsers have their own tests below, which run everywhere.

#[cfg(not(windows))]
mod linux_snapshot {
    use std::path::Path;

    use rdy_spec::result::Report;

    use super::*;

    #[tokio::test]
    async fn an_ordinary_user_is_clean() {
        let (snapshot, _) = snapshot_of(linux(USER, USER, 0, 0, 0)).await;
        let privilege = snapshot.expect("snapshot");
        assert_eq!(privilege.ids, Some(ProcessIds::new(USER, USER)));
        assert_eq!(privilege.elevation, Elevation::NotElevated);
        assert!(!privilege.is_elevated());
        assert_eq!(privilege.euid(), Some(1000));
        assert!(privilege.refusals().is_empty());
        assert_eq!(privilege.check(), Ok(()));
    }

    #[tokio::test]
    async fn root_with_a_full_capability_set_is_clean() {
        let all = 0x0000_01ff_ffff_ffff;
        let (snapshot, _) = snapshot_of(linux([0; 4], [0; 4], all, 0, 0)).await;
        let privilege = snapshot.expect("snapshot");
        assert_eq!(privilege.elevation, Elevation::Root);
        assert!(privilege.is_elevated());
        assert_eq!(privilege.cap_eff, all);
        assert_eq!(privilege.check(), Ok(()));
    }

    #[tokio::test]
    async fn every_uid_slot_that_differs_from_the_real_one_is_refused() {
        // Effective, saved and filesystem, one at a time.
        for slot in 1..4 {
            let mut uid = USER;
            uid[slot] = 0;
            assert_eq!(
                refused_with(linux(uid, USER, 0, 0, 0)).await,
                [Refusal::UidMismatch],
                "uid slot {slot}"
            );
        }
        // A different real id, with the other three the same.
        let uid = [1001, 1000, 1000, 1000];
        assert_eq!(
            refused_with(linux(uid, USER, 0, 0, 0)).await,
            [Refusal::UidMismatch]
        );
    }

    #[tokio::test]
    async fn every_gid_slot_that_differs_from_the_real_one_is_refused() {
        for slot in 0..4 {
            let mut gid = [1000, 1000, 1000, 1000];
            gid[slot] = if slot == 0 { 1001 } else { 0 };
            assert_eq!(
                refused_with(linux(USER, gid, 0, 0, 0)).await,
                [Refusal::GidMismatch],
                "gid slot {slot}"
            );
        }
    }

    #[tokio::test]
    async fn a_setuid_root_binary_run_by_a_user_is_refused() {
        // Real uid 1000, effective 0: what a setuid-root binary has before it drops anything.
        let reasons = refused_with(linux([1000, 0, 0, 0], USER, 0x1ff_ffff_ffff, 0, 1)).await;
        assert_eq!(
            reasons,
            [
                Refusal::UidMismatch,
                Refusal::Capabilities,
                Refusal::AtSecure
            ]
        );
    }

    #[tokio::test]
    async fn a_nonzero_cap_eff_for_a_non_root_user_is_refused() {
        assert_eq!(
            refused_with(linux(USER, USER, 1 << 12, 0, 0)).await,
            [Refusal::Capabilities]
        );
    }

    #[tokio::test]
    async fn a_nonzero_cap_amb_for_a_non_root_user_is_refused() {
        assert_eq!(
            refused_with(linux(USER, USER, 0, 1 << 10, 0)).await,
            [Refusal::Capabilities]
        );
    }

    #[tokio::test]
    async fn a_permitted_only_capability_for_a_non_root_user_is_refused() {
        // `cap_net_raw+p`: CapEff and CapAmb are zero, CapPrm is not.
        let replay = Replay::new()
            .file(STATUS, status_with_prm(1 << 13))
            .file(AUXV, auxv(0));
        assert_eq!(refused_with(replay).await, [Refusal::Capabilities]);
        // Root holds a full permitted set and is clean.
        let all = 0x0000_01ff_ffff_ffff;
        let (snapshot, _) = snapshot_of(linux([0; 4], [0; 4], all, 0, 0)).await;
        assert_eq!(snapshot.expect("snapshot").check(), Ok(()));
    }

    #[tokio::test]
    async fn a_dirty_status_is_refused_even_when_the_auxv_is_hidden() {
        // A file-capability process is not dumpable, so its auxv is not readable. The status file
        // already shows the capability, so the answer is the capability refusal, not a read error.
        let replay = Replay::new()
            .file(STATUS, status(USER, USER, 1 << 13, Some(0)))
            .unreadable(AUXV);
        assert_eq!(refused_with(replay).await, [Refusal::Capabilities]);
        let replay = Replay::new()
            .file(STATUS, status_with_prm(1 << 13))
            .unreadable(AUXV);
        assert_eq!(refused_with(replay).await, [Refusal::Capabilities]);
        let replay = Replay::new()
            .file(STATUS, status([1000, 0, 0, 0], USER, 0, Some(0)))
            .unreadable(AUXV);
        assert_eq!(refused_with(replay).await, [Refusal::UidMismatch]);
    }

    #[tokio::test]
    async fn a_hidden_own_auxv_after_a_clean_status_is_a_not_dumpable_refusal() {
        let replay = Replay::new()
            .file(STATUS, status(USER, USER, 0, Some(0)))
            .unreadable(AUXV);
        let (snapshot, _) = snapshot_of(replay).await;
        let error = snapshot.expect_err("refused");
        assert_eq!(error, PrivilegeError::NotDumpable);
        let text = error.to_string();
        assert!(text.contains("will not run with more privilege"), "{text}");
        assert!(text.contains("not dumpable"), "{text}");
        assert!(text.contains("ls -l"), "{text}");
        assert!(text.contains("getcap"), "{text}");
        assert!(text.contains("Fix: "), "{text}");
        assert_eq!(error.hint(), PrivilegeError::HINT_NOT_DUMPABLE);
        assert!(!error.message().contains("Fix"), "{}", error.message());
    }

    #[tokio::test]
    async fn only_a_permission_denied_auxv_is_a_not_dumpable_refusal() {
        // A missing auxv (no /proc, a stripped container) stays an unreadable source with the /proc hint.
        let replay = Replay::new().file(STATUS, status(USER, USER, 0, Some(0)));
        let (snapshot, _) = snapshot_of(replay).await;
        match snapshot.expect_err("unreadable") {
            PrivilegeError::Unreadable(Unreadable {
                what: Source::ProcAuxv,
                cause,
            }) => assert_ne!(cause, ProbeError::PermissionDenied),
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn at_secure_is_refused_for_any_uid() {
        assert_eq!(
            refused_with(linux(USER, USER, 0, 0, 1)).await,
            [Refusal::AtSecure]
        );
        // Root too: a root-owned file with capabilities still carries them.
        assert_eq!(
            refused_with(linux([0; 4], [0; 4], 0, 0, 1)).await,
            [Refusal::AtSecure]
        );
    }

    #[tokio::test]
    async fn the_refusal_names_the_three_fixes() {
        let reasons = refused_with(linux(USER, USER, 0, 0, 1)).await;
        let error = PrivilegeError::Refused(reasons);
        let text = error.to_string();
        assert!(text.contains("chmod u-s,g-s"), "{text}");
        assert!(text.contains("setcap -r"), "{text}");
        assert!(text.contains("ambient capabilities"), "{text}");
        assert!(text.contains("Fix: "), "{text}");
        assert!(!error.hint().is_empty());
        // No id and no path leaks into the text.
        assert!(!text.contains("1000"), "{text}");
    }

    #[tokio::test]
    async fn a_kernel_without_cap_amb_means_zero() {
        let replay = Replay::new()
            .file(STATUS, status(USER, USER, 0, None))
            .file(AUXV, auxv(0));
        let (snapshot, _) = snapshot_of(replay).await;
        assert_eq!(snapshot.expect("snapshot").cap_amb, 0);
    }

    #[tokio::test]
    async fn a_source_that_cannot_be_read_is_an_error_not_a_default() {
        let (missing_status, _) = snapshot_of(Replay::new().file(AUXV, auxv(0))).await;
        assert!(matches!(
            missing_status,
            Err(PrivilegeError::Unreadable(Unreadable {
                what: Source::ProcStatus,
                ..
            }))
        ));
        let (missing_auxv, _) =
            snapshot_of(Replay::new().file(STATUS, status(USER, USER, 0, Some(0)))).await;
        assert!(matches!(
            missing_auxv,
            Err(PrivilegeError::Unreadable(Unreadable {
                what: Source::ProcAuxv,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn a_source_with_the_wrong_shape_is_an_error() {
        for bad in [
            "Name:\trdy\n",
            "Uid:\t1000\t1000\t1000\nGid:\t1\t1\t1\t1\nCapEff:\t0\n",
            "Uid:\t1000\t1000\t1000\t1000\nGid:\t1\t1\t1\t1\nCapEff:\tzz\n",
        ] {
            let replay = Replay::new().file(STATUS, bad).file(AUXV, auxv(0));
            let (snapshot, _) = snapshot_of(replay).await;
            assert_eq!(
                snapshot.expect_err("malformed"),
                PrivilegeError::Malformed(Source::ProcStatus),
                "{bad}"
            );
        }
        let replay = Replay::new()
            .file(STATUS, status(USER, USER, 0, Some(0)))
            .file(AUXV, vec![1, 2, 3]);
        let (snapshot, _) = snapshot_of(replay).await;
        assert_eq!(
            snapshot.expect_err("malformed"),
            PrivilegeError::Malformed(Source::ProcAuxv)
        );
    }

    #[tokio::test]
    async fn the_snapshot_reads_through_the_run_level_probe_and_logs_it() {
        let (snapshot, run) = snapshot_of(linux(USER, USER, 0, 0, 0)).await;
        snapshot.expect("snapshot");
        let log = run.action_log();
        let seen: Vec<(Option<&str>, String, String, Option<&str>)> = log
            .actions
            .iter()
            .map(|a| {
                (
                    a.check.as_deref(),
                    a.kind.as_str().to_owned(),
                    a.outcome.as_str().to_owned(),
                    a.fields.get("path").and_then(Value::as_str),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                (None, "read".to_owned(), "ok".to_owned(), Some(STATUS)),
                (None, "read".to_owned(), "ok".to_owned(), Some(AUXV)),
            ]
        );
    }

    #[tokio::test]
    async fn no_raw_auxv_value_reaches_the_snapshot_the_log_or_the_report() {
        let (snapshot, run) = snapshot_of(linux(USER, USER, 0, 0, 1)).await;
        let privilege = snapshot.expect("snapshot");
        let mut report = sample_report();
        report.identity = privilege.identity();
        run.action_log().apply(&mut report);
        let everything = format!(
            "{privilege:?}{}{}",
            serde_json::to_string(&report).expect("report"),
            PrivilegeError::Refused(privilege.refusals())
        );
        // The distinctive values of `auxv()`, as hex and as decimal, and the raw bytes as text.
        for value in [
            0x7ffd_dead_b000_u64,
            0x5555_cafe_f00d,
            0x7f12_3456_7000,
            0x7ffd_feed_face,
            0x7ffd_babe_c0de,
        ] {
            for shown in [format!("{value:x}"), format!("{value}")] {
                assert!(!everything.contains(&shown), "{shown} reached the output");
            }
        }
        assert!(!everything.to_lowercase().contains("auxv\":"));
        // The log keeps a byte count for the file and no content.
        let entry = report
            .actions
            .iter()
            .find(|a| a.fields.get("path") == Some(&json!(AUXV)))
            .expect("auxv entry");
        assert_eq!(entry.fields.get("bytes"), Some(&json!(auxv(1).len())));
        assert!(
            entry
                .fields
                .keys()
                .all(|k| matches!(k.as_str(), "path" | "bytes" | "truncated"))
        );
    }

    #[tokio::test]
    async fn the_fixture_runs_json_action_log_records_the_identity_from_the_snapshot() {
        let (snapshot, run) = snapshot_of(linux(USER, USER, 0, 0, 0)).await;
        let privilege = snapshot.expect("snapshot");
        let mut report = sample_report();
        report.identity = privilege.identity();
        run.action_log().apply(&mut report);
        let json = serde_json::to_value(&report).expect("report");
        assert_matches_result_schema(&json);

        assert_eq!(json["identity"]["euid"], 1000);
        assert_eq!(json["identity"]["elevated"], false);
        let actions = json["actions"].as_array().expect("actions");
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().all(|a| a["check"].is_null()));
        assert_eq!(actions[0]["path"], STATUS);
        assert_eq!(actions[1]["path"], AUXV);
    }

    #[tokio::test]
    async fn a_root_snapshot_gives_an_elevated_identity() {
        let (snapshot, _) = snapshot_of(linux([0; 4], [0; 4], 0x1ff_ffff_ffff, 0, 0)).await;
        let identity = snapshot.expect("snapshot").identity();
        assert_eq!(identity.euid, Some(0));
        assert!(identity.elevated);
    }

    /// The report of 01 section 7.2, as a fixture.
    fn sample_report() -> Report {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/reports/not-ready-7.2.json");
        let text = std::fs::read_to_string(path).expect("the fixture is in the repo");
        serde_json::from_str(&text).expect("the sample is a report")
    }

    fn assert_matches_result_schema(report: &Value) {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
        let schema: Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("schema file"))
                .expect("schema json");
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .expect("schema compiles");
        let errors: Vec<String> = validator
            .iter_errors(report)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "the report fails the schema: {errors:#?}"
        );
    }
}

// The pure parsers, on every OS.

#[test]
fn auxv_keeps_only_at_secure() {
    assert_eq!(parse_at_secure(&auxv(0)), Some(false));
    assert_eq!(parse_at_secure(&auxv(1)), Some(true));
    // Any nonzero value is set.
    assert_eq!(parse_at_secure(&auxv(7)), Some(true));
}

#[test]
fn auxv_stops_at_at_null() {
    let mut bytes = Vec::new();
    for (key, value) in [(AT_NULL, 0), (AT_SECURE, 1)] {
        bytes.extend(word(key));
        bytes.extend(word(value));
    }
    // AT_SECURE after AT_NULL is not part of the vector.
    assert_eq!(parse_at_secure(&bytes), None);
}

#[test]
fn auxv_that_is_cut_or_has_no_at_secure_is_not_trusted() {
    let full = auxv(0);
    let w = word(0).len();
    // Cut in the middle of the second pair.
    assert_eq!(parse_at_secure(&full[..3 * w + 3]), None);
    // Cut at a pair boundary after AT_SECURE: no AT_NULL, so the vector is not complete.
    assert_eq!(parse_at_secure(&full[..full.len() - 2 * w]), None);
    // Only the value of the closing AT_NULL pair is cut: the vector is complete.
    assert_eq!(parse_at_secure(&full[..full.len() - 3]), Some(false));
    assert_eq!(parse_at_secure(&[]), None);
    // No AT_SECURE before the end.
    let mut bytes = Vec::new();
    for (key, value) in [(6, 4096), (AT_NULL, 0)] {
        bytes.extend(word(key));
        bytes.extend(word(value));
    }
    assert_eq!(parse_at_secure(&bytes), None);
    // AT_SECURE with half a value.
    let mut bytes = word(AT_SECURE);
    bytes.extend_from_slice(&[1, 0]);
    assert_eq!(parse_at_secure(&bytes), None);
}

#[test]
fn the_parser_returns_a_flag_and_nothing_else() {
    // The type is the proof: `parse_at_secure` gives `Option<bool>`, so there is no way for it to
    // carry another value out. This line fails to compile if that changes.
    let _flag: Option<bool> = parse_at_secure(&auxv(0));
}

#[test]
fn status_lines_parse() {
    let parsed =
        parse_status(&status([1, 2, 3, 4], [5, 6, 7, 8], 0xa80425fb, Some(0x10))).expect("parses");
    assert_eq!(parsed.ids, ProcessIds::new([1, 2, 3, 4], [5, 6, 7, 8]));
    assert_eq!(parsed.cap_eff, 0xa80425fb);
    assert_eq!(parsed.cap_prm, 0xa80425fb);
    assert_eq!(parsed.cap_amb, 0x10);
}

#[test]
fn status_with_extra_or_missing_fields_is_rejected() {
    assert!(parse_status("Uid:\t1\t2\t3\t4\t5\nGid:\t1\t2\t3\t4\nCapEff:\t0\n").is_none());
    assert!(parse_status("Uid:\t1\t2\t3\t4\nGid:\t1\t2\t3\t4\n").is_none());
    assert!(parse_status("Uid:\t-1\t2\t3\t4\nGid:\t1\t2\t3\t4\nCapEff:\t0\n").is_none());
    assert!(
        parse_status("Uid:\t1\t2\t3\t4\nGid:\t1\t2\t3\t4\nCapEff:\t00000000000000000\n").is_none()
    );
}

#[test]
fn a_repeated_status_line_is_malformed() {
    // The kernel writes each line once. A repeat is not a way to change the answer, whichever comes first.
    let base = status(USER, USER, 0, Some(0));
    for extra in [
        "Uid:\t0\t0\t0\t0\n",
        "Gid:\t0\t0\t0\t0\n",
        "CapEff:\t0000000000000000\n",
        "CapPrm:\t0000000000000000\n",
        "CapAmb:\t0000000000000000\n",
    ] {
        assert!(parse_status(&format!("{base}{extra}")).is_none(), "{extra}");
        assert!(parse_status(&format!("{extra}{base}")).is_none(), "{extra}");
    }
}

#[test]
fn a_repeated_at_secure_is_ored() {
    let pairs = |values: &[u64]| {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend(word(AT_SECURE));
            bytes.extend(word(*value));
        }
        bytes.extend(word(AT_NULL));
        bytes.extend(word(0));
        bytes
    };
    assert_eq!(parse_at_secure(&pairs(&[0, 1])), Some(true));
    assert_eq!(parse_at_secure(&pairs(&[1, 0])), Some(true));
    assert_eq!(parse_at_secure(&pairs(&[0, 0])), Some(false));
}

#[test]
fn an_unreadable_error_keeps_the_probe_error_as_its_source_and_hints_by_source() {
    use std::error::Error as _;
    let proc = PrivilegeError::Unreadable(Unreadable {
        what: Source::ProcStatus,
        cause: ProbeError::NotFound,
    });
    let ids = PrivilegeError::Unreadable(Unreadable {
        what: Source::ProcessIds,
        cause: ProbeError::NotFound,
    });
    assert!(proc.to_string().contains("check that /proc is mounted"));
    assert!(!ids.to_string().contains("/proc"), "{ids}");
    assert_ne!(proc.hint(), ids.hint());
    // transparent: the source of the wrapped error is the probe error.
    let source = proc.source().expect("source");
    assert_eq!(source.to_string(), ProbeError::NotFound.to_string());
    assert_eq!(proc.message(), "rdy could not read /proc/self/status");
}

// macOS.

#[tokio::test]
async fn macos_takes_the_ids_through_the_probe_and_logs_a_native_call() {
    let run = TestRun::new(Replay::new().ids([501, 501, 501, 501], [20, 20, 20, 20]));
    let privilege = Privilege::snapshot(&run.run_probe(Os::Macos))
        .await
        .expect("snapshot");
    assert_eq!(privilege.euid(), Some(501));
    assert_eq!(privilege.check(), Ok(()));
    let log = run.action_log();
    assert_eq!(log.actions.len(), 1);
    assert_eq!(log.actions[0].kind.as_str(), "native");
    assert_eq!(
        log.actions[0].fields.get("api"),
        Some(&json!("process_ids"))
    );
    assert!(log.actions[0].check.is_none());
}

#[tokio::test]
async fn macos_refuses_a_real_and_effective_mismatch() {
    let run = TestRun::new(Replay::new().ids([501, 0, 0, 0], [20, 20, 20, 20]));
    let privilege = Privilege::snapshot(&run.run_probe(Os::Macos))
        .await
        .expect("snapshot");
    assert_eq!(
        privilege.check(),
        Err(PrivilegeError::Refused(vec![Refusal::UidMismatch]))
    );
    let run = TestRun::new(Replay::new().ids([501; 4], [20, 0, 0, 0]));
    let privilege = Privilege::snapshot(&run.run_probe(Os::Macos))
        .await
        .expect("snapshot");
    assert_eq!(privilege.refusals(), [Refusal::GidMismatch]);
}

#[tokio::test]
async fn macos_without_ids_is_an_error() {
    let run = TestRun::new(Replay::new());
    let error = Privilege::snapshot(&run.run_probe(Os::Macos))
        .await
        .expect_err("no ids");
    assert!(matches!(
        error,
        PrivilegeError::Unreadable(Unreadable {
            what: Source::ProcessIds,
            ..
        })
    ));
}

// Windows: `whoami /groups /fo csv`.

/// The output of `whoami /groups /fo csv` on English Windows, with the mandatory label row `label`.
fn whoami_output(label_name: &str, sid: &str) -> String {
    format!(
        "\"Group Name\",\"Type\",\"SID\",\"Attributes\"\r\n\
         \"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group, Enabled by default, Enabled group\"\r\n\
         \"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Group used for deny only\"\r\n\
         \"NT AUTHORITY\\INTERACTIVE\",\"Well-known group\",\"S-1-5-4\",\"Mandatory group, Enabled by default, Enabled group\"\r\n\
         \"{label_name}\",\"Label\",\"{sid}\",\"Mandatory group, Enabled by default, Enabled group\"\r\n"
    )
}

async fn windows(output: Option<(i32, &str)>) -> (Privilege, TestRun) {
    let base = Replay::new().env("SystemRoot", r"C:\Windows");
    let replay = match output {
        Some((exit, text)) => base.command("whoami.exe", &WHOAMI_ARGS, exit, text),
        None => base,
    };
    let run = TestRun::new(replay);
    let privilege = Privilege::snapshot(&run.run_probe(Os::Windows))
        .await
        .expect("windows never fails the snapshot");
    (privilege, run)
}

#[tokio::test]
async fn whoami_high_and_system_map_to_elevated() {
    for (name, sid, want) in [
        (
            "Mandatory Label\\High Mandatory Level",
            "S-1-16-12288",
            Elevation::High,
        ),
        (
            "Mandatory Label\\System Mandatory Level",
            "S-1-16-16384",
            Elevation::System,
        ),
    ] {
        let (privilege, _) = windows(Some((0, &whoami_output(name, sid)))).await;
        assert_eq!(privilege.elevation, want);
        assert!(privilege.is_elevated());
        assert!(privilege.identity().elevated);
        assert_eq!(privilege.identity().euid, None);
        assert_eq!(privilege.check(), Ok(()));
    }
}

#[tokio::test]
async fn whoami_medium_and_low_are_not_elevated() {
    for (name, sid) in [
        ("Mandatory Label\\Medium Mandatory Level", "S-1-16-8192"),
        (
            "Mandatory Label\\Medium Plus Mandatory Level",
            "S-1-16-8448",
        ),
        ("Mandatory Label\\Low Mandatory Level", "S-1-16-4096"),
    ] {
        let (privilege, _) = windows(Some((0, &whoami_output(name, sid)))).await;
        assert_eq!(privilege.elevation, Elevation::NotElevated, "{sid}");
        assert!(!privilege.identity().elevated);
    }
}

#[tokio::test]
async fn whoami_in_another_language_still_maps_by_sid() {
    // German Windows: the names and the header change, the SID does not.
    let text = "\"Gruppenname\",\"Typ\",\"SID\",\"Attribute\"\r\n\
        \"Obligatorische Bezeichnung\\Hohe obligatorische Ebene\",\"Bezeichnung\",\"S-1-16-12288\",\"Obligatorische Gruppe\"\r\n";
    let (privilege, _) = windows(Some((0, text))).await;
    assert_eq!(privilege.elevation, Elevation::High);
}

#[tokio::test]
async fn a_whoami_failure_gives_an_unknown_root_need_not_an_error() {
    for output in [
        None,                 // not recorded: the probe fails
        Some((1, "")),        // exit 1
        Some((0, "")),        // no output
        Some((0, "garbage")), // no integrity row
        Some((0, "\"x\",\"y\",\"S-1-16-notanumber\",\"z\"")),
        Some((0, "\"x\",\"y\",\"S-1-16-20480\",\"z\"")), // a level that is not listed
    ] {
        let (privilege, _) = windows(output).await;
        assert_eq!(privilege.elevation, Elevation::Unknown, "{output:?}");
        assert!(!privilege.is_elevated());
        assert!(!privilege.identity().elevated);
    }
    let both = format!(
        "{}{}",
        whoami_output("a", "S-1-16-8192"),
        "\"b\",\"Label\",\"S-1-16-12288\",\"x\"\r\n"
    );
    let (privilege, _) = windows(Some((0, &both))).await;
    assert_eq!(privilege.elevation, Elevation::Unknown);
}

#[tokio::test]
async fn windows_runs_whoami_from_the_table_through_the_probe() {
    let output = whoami_output("Mandatory Label\\High Mandatory Level", "S-1-16-12288");
    let (_, run) = windows(Some((0, &output))).await;
    let log = run.action_log();
    assert_eq!(log.actions.len(), 2);
    // First the environment name, never its value, then the command.
    assert_eq!(log.actions[0].kind.as_str(), "env");
    assert!(log.actions[0].check.is_none());
    assert_eq!(
        log.actions[0].fields.get("name"),
        Some(&json!("SystemRoot"))
    );
    assert!(!log.actions[0].fields.contains_key("value"));
    let entry = &log.actions[1];
    assert_eq!(entry.kind.as_str(), "exec");
    assert!(entry.check.is_none());
    assert_eq!(entry.fields.get("program"), Some(&json!("whoami.exe")));
    assert_eq!(entry.fields.get("form"), Some(&json!("groups")));
    assert_eq!(
        entry.fields.get("argv"),
        Some(&json!(["/groups", "/fo", "csv"]))
    );
    // The group names and SIDs of the user are not in the log.
    let text = serde_json::to_string(&log.actions).expect("log");
    assert!(!text.contains("S-1-5-32-544"), "{text}");
}

/// A High integrity answer that would map to elevated, if whoami were run.
fn high() -> String {
    whoami_output("Mandatory Label\\High Mandatory Level", "S-1-16-12288")
}

#[tokio::test]
async fn whoami_is_not_run_when_system_root_is_not_c_windows() {
    // A Windows on another drive or folder: the constant C:\Windows\System32\whoami.exe could be a file
    // a standard user planted, so rdy does not run it.
    for root in [
        Some(r"D:\Windows"),
        Some(r"C:\Windows.old"),
        Some(r"C:\Temp"),
        Some(""),
        None,
    ] {
        let mut replay = Replay::new().command("whoami.exe", &WHOAMI_ARGS, 0, &high());
        if let Some(root) = root {
            replay = replay.env("SystemRoot", root);
        }
        let run = TestRun::new(replay);
        let privilege = Privilege::snapshot(&run.run_probe(Os::Windows))
            .await
            .expect("snapshot");
        assert_eq!(privilege.elevation, Elevation::Unknown, "{root:?}");
        assert!(!privilege.identity().elevated);
        let kinds: Vec<String> = run
            .action_log()
            .actions
            .iter()
            .map(|a| a.kind.as_str().to_owned())
            .collect();
        assert_eq!(kinds, ["env"], "whoami ran for {root:?}");
    }
}

#[tokio::test]
async fn system_root_is_compared_without_regard_to_case() {
    for root in [r"C:\Windows", r"c:\windows", r"C:\WINDOWS\"] {
        let replay =
            Replay::new()
                .env("SystemRoot", root)
                .command("whoami.exe", &WHOAMI_ARGS, 0, &high());
        let run = TestRun::new(replay);
        let privilege = Privilege::snapshot(&run.run_probe(Os::Windows))
            .await
            .expect("snapshot");
        assert_eq!(privilege.elevation, Elevation::High, "{root}");
    }
}

#[test]
fn only_the_sid_column_of_a_four_field_row_is_read() {
    // A group named like a High label, in the name and in the attributes column, on a Medium token.
    let text = "\"Group Name\",\"Type\",\"SID\",\"Attributes\"\r\n\
        \"S-1-16-12288\",\"Group\",\"S-1-5-21-1-2-3-1001\",\"S-1-16-16384\"\r\n\
        \"Mandatory Label\\Medium Mandatory Level\",\"Label\",\"S-1-16-8192\",\"Mandatory group\"\r\n";
    assert_eq!(parse_integrity(text), Elevation::NotElevated);
    // A row with five fields (an unquoted comma) is skipped, not read.
    let text = "\"a\",\"b\",\"S-1-16-12288\",\"c\",\"d\"\r\n";
    assert_eq!(parse_integrity(text), Elevation::Unknown);
    // A label SID in the name column alone is not a label.
    let text = "\"S-1-16-12288\",\"Label\",\"S-1-1-0\",\"x\"\r\n";
    assert_eq!(parse_integrity(text), Elevation::Unknown);
}

#[test]
fn csv_fields_handle_quotes_and_commas() {
    assert_eq!(csv_fields("\"a,b\",\"c\"\"d\",e\r\n"), ["a,b", "c\"d", "e"]);
    assert_eq!(csv_fields(""), [""]);
}

// Needs: only what the plan holds is probed.

fn kinds_and_paths(run: &TestRun) -> Vec<(String, Option<String>)> {
    run.action_log()
        .actions
        .iter()
        .map(|a| {
            (
                a.kind.as_str().to_owned(),
                a.fields
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
        })
        .collect()
}

fn user() -> Privilege {
    Privilege {
        ids: Some(ProcessIds::new(USER, USER)),
        cap_eff: 0,
        cap_prm: 0,
        cap_amb: 0,
        at_secure: false,
        elevation: Elevation::NotElevated,
    }
}

#[tokio::test]
async fn needs_absent_from_the_plan_are_not_probed() {
    let run = TestRun::new(Replay::new().file("/usr/sbin/getenforce", "x"));
    let probe = run.run_probe(Os::Linux);
    // An empty plan, and a plan with only root and network: no stat, no read, no exec.
    assert!(capabilities(&probe, &user(), &[], true).await.is_empty());
    let found = capabilities(&probe, &user(), &[Need::Root, Need::Network], true).await;
    assert_eq!(found.len(), 2);
    assert!(
        run.action_log().actions.is_empty(),
        "{:?}",
        kinds_and_paths(&run)
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn a_command_in_the_plan_is_stat_ed_in_the_fixed_search_path_only() {
    let run = TestRun::new(
        Replay::new()
            .file("/usr/sbin/getenforce", "x")
            // Not in the fixed path, so never found.
            .file("/opt/bin/aide", "x"),
    );
    let probe = run.run_probe(Os::Linux);
    let wanted = [
        Need::Command("getenforce"),
        Need::Command("getenforce"), // twice in the plan, probed once
        Need::Command("aide"),
    ];
    let found = capabilities(&probe, &user(), &wanted, true).await;
    assert_eq!(found.len(), 2);
    assert!(found[0].available);
    assert_eq!(found[0].name.as_deref(), Some("getenforce"));
    assert_eq!(found[0].detail.as_deref(), Some("/usr/sbin/getenforce"));
    assert!(found[0].hint.is_none());
    assert!(!found[1].available);
    assert!(found[1].hint.is_some());
    let log = kinds_and_paths(&run);
    // getenforce: /usr/sbin hit, so one stat. aide: the four fixed directories, then nothing more.
    assert_eq!(
        log,
        [
            ("stat".to_owned(), Some("/usr/sbin/getenforce".to_owned())),
            ("stat".to_owned(), Some("/usr/sbin/aide".to_owned())),
            ("stat".to_owned(), Some("/usr/bin/aide".to_owned())),
            ("stat".to_owned(), Some("/sbin/aide".to_owned())),
            ("stat".to_owned(), Some("/bin/aide".to_owned())),
        ]
    );
}

#[tokio::test]
async fn a_command_never_runs_on_windows_in_m1() {
    let run = TestRun::new(Replay::new());
    let probe = run.run_probe(Os::Windows);
    let found = capabilities(&probe, &user(), &[Need::Command("getenforce")], true).await;
    assert!(!found[0].available);
    assert!(run.action_log().actions.is_empty());
}

#[tokio::test]
async fn root_and_network_come_from_the_snapshot_and_the_option() {
    let run = TestRun::new(Replay::new());
    let probe = run.run_probe(Os::Linux);
    let found = capabilities(&probe, &user(), &[Need::Root, Need::Network], false).await;
    assert!(!found[0].available);
    assert_eq!(found[0].detail.as_deref(), Some("uid 1000"));
    assert!(
        found[0]
            .hint
            .as_deref()
            .is_some_and(|h| !h.contains("sudo"))
    );
    assert!(!found[1].available);
    assert_eq!(found[1].detail.as_deref(), Some("--no-network"));

    let root = Privilege {
        elevation: Elevation::Root,
        ids: Some(ProcessIds::new([0; 4], [0; 4])),
        ..user()
    };
    let found = capabilities(&probe, &root, &[Need::Root], true).await;
    assert!(found[0].available);
    assert!(found[0].hint.is_none());
}

#[tokio::test]
async fn an_unknown_elevation_is_a_root_need_that_is_not_met_and_says_why() {
    let unknown = Privilege {
        ids: None,
        elevation: Elevation::Unknown,
        ..user()
    };
    let run = TestRun::new(Replay::new());
    let found = capabilities(&run.run_probe(Os::Windows), &unknown, &[Need::Root], true).await;
    assert!(!found[0].available);
    assert!(
        found[0]
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("could not tell"))
    );
    assert!(found[0].hint.is_some());
}

#[tokio::test]
async fn kube_context_is_left_to_the_family_probe() {
    let run = TestRun::new(Replay::new());
    let found = capabilities(
        &run.run_probe(Os::Linux),
        &user(),
        &[Need::KubeContext],
        true,
    )
    .await;
    assert!(found.is_empty());
}

#[test]
fn every_error_has_a_message_and_a_hint() {
    for error in [
        PrivilegeError::Refused(vec![Refusal::AtSecure]),
        PrivilegeError::NotDumpable,
        PrivilegeError::Unreadable(Unreadable {
            what: Source::ProcStatus,
            cause: ProbeError::NotFound,
        }),
        PrivilegeError::Malformed(Source::ProcAuxv),
    ] {
        assert!(!error.message().is_empty());
        assert!(!error.hint().is_empty());
        assert!(error.to_string().contains(". Fix: "), "{error}");
    }
}
