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
use serde_json::Value;
use tempfile::TempDir;

use super::*;
use crate::check::{CheckInfo, CheckMeta, Os, OsSupport, Support};
#[cfg(target_os = "linux")]
use crate::probe::policy::RULE_PROC;
use crate::probe::policy::{
    RULE_CHANGED, RULE_DEVICE, RULE_DOT_DOT, RULE_NOT_DIR, RULE_NOT_REGULAR, RULE_OUTSIDE_READS,
    RULE_SSH, RULE_SYSTEM_SECRET,
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

/// Makes a FIFO. `mknodat` is not in rustix on macOS, and `mkfifo` is on every Unix.
fn mkfifo(path: &Path) {
    let status = std::process::Command::new("/usr/bin/mkfifo")
        .arg(path)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed");
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
    mkfifo(&fifo);
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
    mkfifo(&fifo);
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
async fn a_link_to_another_pids_auxv_is_refused_and_one_to_ours_is_read() {
    let sandbox = Sandbox::new();
    // Our parent is a real process that is not us, so the link resolves and the allowlist decides.
    let parent = std::os::unix::process::parent_id();
    assert_ne!(parent, std::process::id());
    symlink(format!("/proc/{parent}/auxv"), sandbox.path("other")).expect("symlink");
    symlink(
        format!("/proc/{}/auxv", std::process::id()),
        sandbox.path("own"),
    )
    .expect("symlink");
    let probe = sandbox.probe(&[Path::new("/proc")], &[]);
    let error = probe
        .read(&sandbox.path("other"))
        .await
        .expect_err("another pid");
    assert_eq!(rule_of(&error), RULE_PROC);
    // The real path of the second link is `/proc/<our pid>/auxv`, and that pid passes.
    let own = probe.read(&sandbox.path("own")).await.expect("our auxv");
    assert!(!own.bytes.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn declared_proc_paths_that_resolve_elsewhere_are_still_read() {
    let sandbox = Sandbox::new();
    // `/proc/net` is a link to `/proc/self/net`, which resolves to `/proc/<pid>/net`.
    let probe = sandbox.probe(&[Path::new("/proc/net")], &[]);
    let dev = probe
        .read(Path::new("/proc/net/dev"))
        .await
        .expect("/proc/net/dev");
    assert!(dev.bytes.starts_with(b"Inter-|"));
    assert!(probe.read_dir(Path::new("/proc/net")).await.is_ok());

    let probe = sandbox.probe(&[Path::new("/proc/self/mountinfo")], &[]);
    assert!(probe.read(Path::new("/proc/self/mountinfo")).await.is_ok());
    // A pid in the declaration means the same thing as `self`.
    let own = format!("/proc/{}/mountinfo", std::process::id());
    let own: &'static str = Box::leak(own.into_boxed_str());
    let probe = sandbox.probe(&[Path::new(own)], &[]);
    assert!(probe.read(Path::new("/proc/self/mountinfo")).await.is_ok());

    // `/etc/mtab` is usually a link to `/proc/self/mounts`; the link and its target are both declared.
    if Path::new("/etc/mtab").exists() {
        let probe = sandbox.probe(
            &[Path::new("/etc/mtab"), Path::new("/proc/self/mounts")],
            &[],
        );
        assert!(probe.read(Path::new("/etc/mtab")).await.is_ok());
    }
    // A prefix of another process is not ours.
    let probe = sandbox.probe(&[Path::new("/proc/1/mountinfo")], &[]);
    if std::process::id() != 1 {
        let error = probe
            .read(Path::new("/proc/self/mountinfo"))
            .await
            .expect_err("outside");
        assert_eq!(rule_of(&error), RULE_OUTSIDE_READS);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_tail_of_a_proc_file_is_the_end_of_the_file() {
    let sandbox = Sandbox::new();
    let probe = sandbox.probe(&[Path::new("/proc")], &[]);
    // `limits` is the same text on every read of one process, and reports size 0.
    let path = Path::new("/proc/self/limits");
    let full = probe.read(path).await.expect("read");
    assert!(full.bytes.len() > 64 && !full.truncated());
    let tail = probe.read_tail(path, 64).await.expect("tail");
    assert_eq!(tail.bytes, &full.bytes[full.bytes.len() - 64..]);
    assert!(tail.truncated_head && !tail.truncated_tail);
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
    let none = files::Secrets::default();

    let error = files::locate_by_path(&sandbox.path("link"), &guard, &none).expect_err("refused");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_SYSTEM_SECRET)
    );
    let (real, stat) =
        files::locate_by_path(&sandbox.path("plain-link"), &guard, &none).expect("ok");
    assert_eq!(real, plain);
    let requested = sandbox.path("plain-link");
    let (fd, now) =
        files::open_by_path(&requested, &real, &stat, &guard, files::Want::File).expect("open");
    assert_eq!(now.st_ino, stat.st_ino);
    let file = files::read_part(std::fs::File::from(fd), 1, ReadRange::Head(10)).expect("read");
    assert_eq!(file.bytes, b"y");

    // The type comes from the descriptor: a directory is not a file, and nothing is read.
    let dir_real = sandbox.root.clone();
    let dir_stat = rustix::fs::stat(&dir_real).expect("stat");
    let error = files::open_by_path(&dir_real, &dir_real, &dir_stat, &guard, files::Want::File)
        .expect_err("not a file");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_NOT_REGULAR)
    );

    // The file is replaced between the check and the open: refused. The new file is made first, so it
    // cannot reuse the old inode number.
    let other = sandbox.write("other", b"z");
    std::fs::rename(&other, &plain).expect("rename");
    let error = files::open_by_path(&requested, &real, &stat, &guard, files::Want::File)
        .expect_err("changed");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_CHANGED)
    );
}

#[test]
fn a_directory_swapped_for_a_link_is_not_followed() {
    // The attack on the portable path: after the check, a directory on the path becomes a link to
    // somewhere else. The open refuses to follow it.
    let sandbox = Sandbox::new();
    sandbox.write("d/file", b"inside");
    sandbox.write("elsewhere/file", b"outside");
    let guard = ReadGuard::new(Os::Linux, None);
    let none = files::Secrets::default();
    let requested = sandbox.path("d/file");
    let (real, _) = files::locate_by_path(&requested, &guard, &none).expect("ok");
    std::fs::rename(sandbox.path("d"), sandbox.path("d-moved")).expect("rename");
    symlink(sandbox.path("elsewhere"), sandbox.path("d")).expect("symlink");
    // The attacker also won the race for the stat: `before` describes the file the swapped path
    // leads to, so the device and inode test cannot be what stops the open.
    let before = rustix::fs::stat(sandbox.path("elsewhere/file")).expect("stat");
    let error = files::open_by_path(&requested, &real, &before, &guard, files::Want::File)
        .expect_err("the swapped path is not read");
    #[cfg(target_vendor = "apple")]
    assert_eq!(
        error.raw_os_error(),
        Some(rustix::io::Errno::LOOP.raw_os_error()),
        "O_NOFOLLOW_ANY refuses a link in the middle of the path"
    );
    // Without `O_NOFOLLOW_ANY` the open follows the middle link, and the second `realpath` of the
    // requested path is what catches it.
    #[cfg(not(target_vendor = "apple"))]
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_CHANGED),
        "{error:?}"
    );
}

/// The path of the descriptor is judged again after the open (`F_GETPATH`). Calling the open directly
/// with a guard that does not cover the file shows the second judgement is wired.
#[cfg(target_vendor = "apple")]
#[test]
fn the_path_of_the_descriptor_is_judged_again_on_macos() {
    let sandbox = Sandbox::new();
    let file = sandbox.write("a/file", b"x");
    let root: &'static str =
        Box::leak(sandbox.root.to_string_lossy().into_owned().into_boxed_str());
    let covered: &'static [&'static str] = Box::leak(Box::new([root]));
    let wide = ReadGuard::new(Os::Macos, Some(covered));
    let (real, stat) =
        files::locate_by_path(&file, &wide, &files::Secrets::default()).expect("located");
    assert!(files::open_by_path(&file, &real, &stat, &wide, files::Want::File).is_ok());
    let narrow = ReadGuard::new(Os::Macos, Some(&["/nowhere-near-here"]));
    let error = files::open_by_path(&file, &real, &stat, &narrow, files::Want::File)
        .expect_err("judged again");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_OUTSIDE_READS)
    );
}

#[tokio::test]
async fn a_hard_link_to_a_secret_file_is_refused_by_inode() {
    let sandbox = Sandbox::new();
    let secret = sandbox.write("passwords", b"root:x");
    std::fs::hard_link(&secret, sandbox.path("innocent")).expect("hard link");
    // The backend learns the inode when it is made; here the secret is the file just written.
    let secrets = files::Secrets::from_paths(&[secret.as_path()]);
    let guard = ReadGuard::new(Os::Linux, None);
    let error = files::read(
        &sandbox.path("innocent"),
        ReadRange::Head(MAX_READ),
        &guard,
        &secrets,
    )
    .expect_err("refused");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_SYSTEM_SECRET)
    );
    let ok = files::read(
        &sandbox.write("other", b"fine"),
        ReadRange::Head(MAX_READ),
        &guard,
        &secrets,
    )
    .expect("an unrelated file");
    assert_eq!(ok.bytes, b"fine");
}

#[cfg(target_os = "linux")]
#[test]
fn a_file_with_no_names_left_is_refused() {
    use std::os::fd::AsRawFd;
    let sandbox = Sandbox::new();
    let path = sandbox.write("gone.key", b"x");
    let held = std::fs::File::open(&path).expect("open");
    std::fs::remove_file(&path).expect("remove");
    // Another name for the same inode, as `/proc/self/fd/N` shows it: the open file with no name.
    let via = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    let guard = ReadGuard::new(Os::Linux, None);
    let error = files::read(
        &via,
        ReadRange::Head(MAX_READ),
        &guard,
        &files::Secrets::default(),
    )
    .expect_err("refused");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_CHANGED),
        "{error:?}"
    );
}

#[test]
fn a_tail_streams_to_the_end_and_says_when_it_could_not() {
    let sandbox = Sandbox::new();
    // The size is passed as 0, as `/proc` reports it.
    let path = sandbox.write("log", b"0123456789abcdefghij");
    let file = std::fs::File::open(&path).expect("open");
    let tail = files::read_part(file, 0, ReadRange::Tail(5)).expect("tail");
    assert_eq!(tail.bytes, b"fghij");
    assert!(tail.truncated_head && !tail.truncated_tail);

    let file = std::fs::File::open(&path).expect("open");
    let whole = files::read_part(file, 0, ReadRange::Tail(100)).expect("tail");
    assert_eq!(whole.bytes, b"0123456789abcdefghij");
    assert!(!whole.truncated());

    // A file past the scan budget: the end was not reached, and that is said.
    let big = sandbox.write("big", &vec![b'x'; 17 << 20]);
    let file = std::fs::File::open(&big).expect("open");
    let tail = files::read_part(file, 0, ReadRange::Tail(10)).expect("tail");
    assert_eq!(tail.bytes.len(), 10);
    assert!(tail.truncated_head && tail.truncated_tail);

    // A file that ends exactly at the budget has been read to its end: no cut.
    let exact = sandbox.write("exact", &vec![b'y'; 16 << 20]);
    let file = std::fs::File::open(&exact).expect("open");
    let tail = files::read_part(file, 0, ReadRange::Tail(10)).expect("tail");
    assert_eq!(tail.bytes, b"yyyyyyyyyy");
    assert!(tail.truncated_head && !tail.truncated_tail);
}
