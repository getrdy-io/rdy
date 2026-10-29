//! Tests of the live file backend, on real files in a temporary directory.
//!
//! The exit test of M1-045 is `the_exit_test_refusals_are_logged`: `/etc/shadow`, a link to it, a `..`
//! path, a FIFO and `/dev/zero` under an allowed prefix, and a read outside the declared prefixes.
// The helpers below set up files and cannot return an error to a test.
#![allow(clippy::expect_used)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rdy_spec::result::{Action, ActionOutcome};
use rustix::fs::{CWD, FileType, Mode};
use serde_json::Value;
use tempfile::TempDir;

use super::*;
use crate::check::{CheckInfo, CheckMeta, Os, OsSupport, Support};
use crate::probe::policy::{
    RULE_CHANGED, RULE_DEVICE, RULE_DOT_DOT, RULE_NOT_DIR, RULE_NOT_REGULAR, RULE_OUTSIDE_READS,
    RULE_PROC, RULE_SSH, RULE_SYSTEM_SECRET,
};
use crate::probe::{MAX_READ, Probe, ProbeError, ProbeHub};
use crate::redact::{Redactor, TagKey};

/// A check manifest with the given prefixes. Leaked: it must be `'static`, and a test process is short.
fn manifest(reads: &[&Path], env: &'static [&'static str]) -> &'static CheckInfo {
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
        env,
        commands: &[],
        peers: &[],
    }))
}

/// A real directory, named by its real path, so link-free prefixes match.
struct Sandbox {
    _dir: TempDir,
    root: PathBuf,
    hub: ProbeHub,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("real path");
        let hub = ProbeHub::new(live_backend(), Redactor::new(TagKey::fixed([5; 32])));
        Self {
            _dir: dir,
            root,
            hub,
        }
    }

    /// A probe that may read under `root` and the extra prefixes.
    fn probe(&self, extra: &[&Path], env: &'static [&'static str]) -> Probe {
        let mut reads = vec![self.root.as_path()];
        reads.extend_from_slice(extra);
        self.hub
            .check_probe("host.fixture", Os::Linux, Some(manifest(&reads, env)))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&path, bytes).expect("write");
        path
    }

    fn actions(&self) -> Vec<Action> {
        self.hub.action_log().actions
    }
}

fn rule_of(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Denied { rule, .. } => rule,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn field<'a>(action: &'a Action, name: &str) -> Option<&'a Value> {
    action.fields.get(name)
}

#[tokio::test]
async fn a_regular_file_is_read_whole() {
    let sandbox = Sandbox::new();
    let path = sandbox.write("meminfo", b"MemTotal: 1 kB\n");
    let probe = sandbox.probe(&[], &[]);
    let file = probe.read(&path).await.expect("read");
    assert_eq!(file.bytes, b"MemTotal: 1 kB\n");
    assert!(!file.truncated());
    let log = sandbox.actions();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
    assert_eq!(field(&log[0], "bytes"), Some(&Value::from(15)));
}

#[tokio::test]
async fn a_two_mib_file_returns_one_mib_and_says_it_was_cut() {
    let sandbox = Sandbox::new();
    let mut big = vec![b'a'; MAX_READ];
    big.extend(vec![b'b'; MAX_READ]);
    let path = sandbox.write("big", &big);
    let probe = sandbox.probe(&[], &[]);

    let file = probe.read(&path).await.expect("read");
    assert_eq!(file.bytes.len(), MAX_READ);
    assert!(file.bytes.iter().all(|b| *b == b'a'), "the first MiB");
    assert!(file.truncated_tail);
    assert!(!file.truncated_head);
    assert!(file.truncated());

    let log = sandbox.actions();
    assert_eq!(field(&log[0], "bytes"), Some(&Value::from(MAX_READ)));
    assert_eq!(field(&log[0], "truncated"), Some(&Value::Bool(true)));
}

#[tokio::test]
async fn a_file_of_exactly_one_mib_is_not_cut() {
    let sandbox = Sandbox::new();
    let path = sandbox.write("exact", &vec![b'x'; MAX_READ]);
    let file = sandbox.probe(&[], &[]).read(&path).await.expect("read");
    assert_eq!(file.bytes.len(), MAX_READ);
    assert!(!file.truncated());
}

#[tokio::test]
async fn read_tail_returns_the_end_and_marks_the_head() {
    let sandbox = Sandbox::new();
    let path = sandbox.write("log", b"one\ntwo\nthree\n");
    let probe = sandbox.probe(&[], &[]);

    let tail = probe.read_tail(&path, 6).await.expect("tail");
    assert_eq!(tail.bytes, b"three\n");
    assert!(tail.truncated_head);
    assert!(!tail.truncated_tail);

    let whole = probe.read_tail(&path, 100).await.expect("tail");
    assert_eq!(whole.bytes, b"one\ntwo\nthree\n");
    assert!(!whole.truncated());

    // A request past the cap is cut to the cap.
    let mut big = vec![b'a'; MAX_READ];
    big.extend(vec![b'b'; 10]);
    let path = sandbox.write("big", &big);
    let tail = probe.read_tail(&path, usize::MAX).await.expect("tail");
    assert_eq!(tail.bytes.len(), MAX_READ);
    assert!(tail.bytes.ends_with(b"bbbbbbbbbb"));
    assert!(tail.truncated_head);
}

#[tokio::test]
async fn the_exit_test_refusals_are_logged() {
    let sandbox = Sandbox::new();
    // A file shaped like the secret, inside the allowed directory, so a link to it resolves.
    let shadow = sandbox.write("etc/shadow", b"root:$6$salt$hash::\n");
    symlink(&shadow, sandbox.path("looks-fine")).expect("symlink");
    // A FIFO under the allowed prefix.
    let fifo = sandbox.path("pipe");
    rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o600), 0).expect("mkfifo");
    // A link to a device, under the allowed prefix.
    symlink("/dev/zero", sandbox.path("zero")).expect("symlink");
    let outside = tempfile::tempdir().expect("tempdir");
    let elsewhere = std::fs::canonicalize(outside.path())
        .expect("real path")
        .join("notes");
    std::fs::write(&elsewhere, b"not declared").expect("write");
    // `/dev` is allowed on purpose: the denylist, not the prefix, has to stop `/dev/zero`.
    let probe = sandbox.probe(&[Path::new("/dev"), Path::new("/etc")], &[]);

    let cases: Vec<(PathBuf, &str)> = vec![
        (PathBuf::from("/etc/shadow"), RULE_SYSTEM_SECRET),
        (sandbox.path("looks-fine"), RULE_SYSTEM_SECRET),
        (sandbox.path("a/../etc/shadow"), RULE_DOT_DOT),
        (fifo, RULE_NOT_REGULAR),
        (PathBuf::from("/dev/zero"), RULE_DEVICE),
        (sandbox.path("zero"), RULE_DEVICE),
        (elsewhere, RULE_OUTSIDE_READS),
    ];
    for (path, rule) in &cases {
        // A FIFO with no writer would block an `open`. Nothing may wait on it.
        let result = tokio::time::timeout(Duration::from_secs(10), probe.read(path))
            .await
            .expect("the refusal does not wait");
        let error = result.expect_err("refused");
        assert_eq!(rule_of(&error), *rule, "{}", path.display());
    }

    let log = sandbox.actions();
    assert_eq!(log.len(), cases.len(), "every refusal is logged");
    for (action, (_, rule)) in log.iter().zip(&cases) {
        assert_eq!(action.outcome, ActionOutcome::Denied);
        assert_eq!(field(action, "rule"), Some(&Value::from(*rule)));
        assert!(field(action, "bytes").is_none());
    }
}

#[tokio::test]
async fn a_link_out_of_the_declared_prefixes_is_refused() {
    let sandbox = Sandbox::new();
    let outside = tempfile::tempdir().expect("tempdir");
    let target = std::fs::canonicalize(outside.path())
        .expect("real path")
        .join("data");
    std::fs::write(&target, b"data").expect("write");
    symlink(&target, sandbox.path("link")).expect("symlink");
    let probe = sandbox.probe(&[], &[]);
    let error = probe
        .read(&sandbox.path("link"))
        .await
        .expect_err("refused");
    assert_eq!(rule_of(&error), RULE_OUTSIDE_READS);
    // The message shows the path the check asked for, not the target of the link.
    let ProbeError::Denied { what, .. } = &error else {
        panic!("{error:?}")
    };
    assert_eq!(what, &sandbox.path("link").to_string_lossy());
    // A link that stays inside is fine.
    let inside = sandbox.write("real", b"ok");
    symlink(&inside, sandbox.path("inside-link")).expect("symlink");
    let file = probe
        .read(&sandbox.path("inside-link"))
        .await
        .expect("read");
    assert_eq!(file.bytes, b"ok");
}

#[tokio::test]
async fn a_directory_in_the_middle_of_the_path_may_be_a_link_to_a_denied_one() {
    let sandbox = Sandbox::new();
    sandbox.write("real/etc/shadow", b"x");
    symlink(sandbox.path("real/etc"), sandbox.path("etc-link")).expect("symlink");
    let probe = sandbox.probe(&[], &[]);
    let error = probe
        .read(&sandbox.path("etc-link/shadow"))
        .await
        .expect_err("refused");
    assert_eq!(rule_of(&error), RULE_SYSTEM_SECRET);
    let error = probe
        .stat(&sandbox.path("etc-link/shadow"))
        .await
        .expect_err("refused");
    assert_eq!(rule_of(&error), RULE_SYSTEM_SECRET);
}

#[tokio::test]
async fn a_directory_and_a_missing_file_are_not_read() {
    let sandbox = Sandbox::new();
    sandbox.write("dir/file", b"x");
    let probe = sandbox.probe(&[], &[]);
    let error = probe.read(&sandbox.path("dir")).await.expect_err("refused");
    assert_eq!(rule_of(&error), RULE_NOT_REGULAR);
    let error = probe
        .read(&sandbox.path("missing"))
        .await
        .expect_err("not found");
    assert_eq!(error, ProbeError::NotFound);
    let log = sandbox.actions();
    assert_eq!(log[1].outcome, ActionOutcome::Failed);
}

#[tokio::test]
async fn stat_describes_without_opening() {
    let sandbox = Sandbox::new();
    let file = sandbox.write("dir/file", b"12345");
    let fifo = sandbox.path("pipe");
    rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o600), 0).expect("mkfifo");
    let probe = sandbox.probe(&[], &[]);

    let meta = probe.stat(&file).await.expect("stat").expect("exists");
    assert!(meta.is_file && !meta.is_dir);
    assert_eq!(meta.len, 5);
    let meta = probe
        .stat(&sandbox.path("dir"))
        .await
        .expect("stat")
        .expect("exists");
    assert!(meta.is_dir && !meta.is_file);
    let meta = probe.stat(&fifo).await.expect("stat").expect("exists");
    assert!(!meta.is_file && !meta.is_dir);
    assert_eq!(probe.stat(&sandbox.path("missing")).await, Ok(None));
    assert_eq!(
        probe.stat(&sandbox.path("dir/file/below")).await,
        Ok(None),
        "a file used as a directory does not exist"
    );
}

#[tokio::test]
async fn read_dir_lists_sorted_names_and_marks_directories() {
    let sandbox = Sandbox::new();
    sandbox.write("d/b", b"");
    sandbox.write("d/a", b"");
    sandbox.write("d/sub/x", b"");
    symlink(sandbox.path("d/sub"), sandbox.path("d/link")).expect("symlink");
    let probe = sandbox.probe(&[], &[]);
    let entries = probe.read_dir(&sandbox.path("d")).await.expect("list");
    let seen: Vec<(&str, bool)> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.is_dir))
        .collect();
    assert_eq!(
        seen,
        [("a", false), ("b", false), ("link", false), ("sub", true)]
    );
    let error = probe
        .read_dir(&sandbox.path("d/a"))
        .await
        .expect_err("a file");
    assert_eq!(rule_of(&error), RULE_NOT_DIR);
}

#[tokio::test]
async fn a_listing_follows_the_same_real_path_rules() {
    let sandbox = Sandbox::new();
    sandbox.write("real/.ssh/known", b"x");
    symlink(sandbox.path("real/.ssh"), sandbox.path("plain-name")).expect("symlink");
    let probe = sandbox.probe(&[], &[]);
    let error = probe
        .read_dir(&sandbox.path("plain-name"))
        .await
        .expect_err("refused");
    assert_eq!(rule_of(&error), RULE_SSH);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn proc_self_is_read_through_its_real_path() {
    let sandbox = Sandbox::new();
    let probe = sandbox.probe(&[Path::new("/proc")], &[]);
    let status = probe
        .read(Path::new("/proc/self/status"))
        .await
        .expect("status");
    assert!(status.bytes.starts_with(b"Name:"));
    // A file in /proc reports size 0, so the cap and the tail still work.
    let tail = probe
        .read_tail(Path::new("/proc/self/status"), 16)
        .await
        .expect("tail");
    assert_eq!(tail.bytes.len(), 16);
    assert!(tail.truncated_head);

    // auxv is rdy's own, through `self`: the real path carries rdy's pid.
    let auxv = probe
        .read(Path::new("/proc/self/auxv"))
        .await
        .expect("own auxv");
    assert!(!auxv.bytes.is_empty());

    // Only the name `self` opens it. A pid in the path is refused as written, even our own.
    let own = format!("/proc/{}/auxv", std::process::id());
    let error = probe.read(Path::new(&own)).await.expect_err("refused");
    assert_eq!(rule_of(&error), RULE_PROC);
    // Everything else of the process stays closed, and a link in /proc does not open it.
    let error = probe
        .read(Path::new("/proc/self/environ"))
        .await
        .expect_err("refused");
    assert_eq!(rule_of(&error), RULE_PROC);
    let error = probe
        .read(Path::new("/proc/self/cwd/etc/passwd"))
        .await
        .expect_err("refused");
    assert_eq!(rule_of(&error), RULE_PROC);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_link_to_another_pids_auxv_is_refused() {
    let sandbox = Sandbox::new();
    let other = std::process::id().wrapping_add(1);
    // Not a real process, so the link dangles and the open fails with not found. A real one would be
    // refused by the allowlist; the guard unit test covers the decision.
    symlink(format!("/proc/{other}/auxv"), sandbox.path("auxv")).expect("symlink");
    let probe = sandbox.probe(&[Path::new("/proc")], &[]);
    let error = probe.read(&sandbox.path("auxv")).await.expect_err("fails");
    assert!(
        matches!(error, ProbeError::NotFound | ProbeError::Denied { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn env_reads_declared_names_and_logs_no_value() {
    let sandbox = Sandbox::new();
    let probe = sandbox.probe(&[], &["PATH"]);
    let value = probe.env("PATH").expect("declared").expect("set");
    assert!(!value.is_empty());
    let error = probe.env("HOME").expect_err("not declared");
    assert_eq!(rule_of(&error), crate::probe::RULE_ENV_NOT_DECLARED);
    let log = sandbox.actions();
    assert_eq!(log.len(), 2);
    assert_eq!(field(&log[0], "name"), Some(&Value::from("PATH")));
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
    assert_eq!(log[1].outcome, ActionOutcome::Denied);
    let json = serde_json::to_string(&log).expect("json");
    assert!(!json.contains(&value), "the value is never logged");
}

#[test]
fn the_portable_path_gives_the_same_answers() {
    // Linux uses O_PATH; macOS uses this. It is compiled everywhere, so it is tested here.
    let sandbox = Sandbox::new();
    let shadow = sandbox.write("etc/shadow", b"x");
    let plain = sandbox.write("plain", b"y");
    symlink(&shadow, sandbox.path("link")).expect("symlink");
    symlink(&plain, sandbox.path("plain-link")).expect("symlink");
    let guard = ReadGuard::new(Os::Linux, None);

    let error = files::locate_by_path(&sandbox.path("link"), &guard).expect_err("refused");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_SYSTEM_SECRET)
    );
    let (real, stat) = files::locate_by_path(&sandbox.path("plain-link"), &guard).expect("ok");
    assert_eq!(real, plain);
    let fd = files::reopen_by_path(
        &sandbox.path("plain-link"),
        &real,
        &stat,
        rustix::fs::OFlags::empty(),
    )
    .expect("open");
    let file = files::read_part(std::fs::File::from(fd), 1, ReadRange::Head(10)).expect("read");
    assert_eq!(file.bytes, b"y");

    // The file is replaced between the check and the open: refused. The new file is made first, so it
    // cannot reuse the old inode number.
    let other = sandbox.write("other", b"z");
    std::fs::rename(&other, &plain).expect("rename");
    let error = files::reopen_by_path(
        &sandbox.path("plain-link"),
        &real,
        &stat,
        rustix::fs::OFlags::empty(),
    )
    .expect_err("changed");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_CHANGED)
    );
}
