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
    RULE_CHANGED, RULE_DEVICE, RULE_DOT_DOT, RULE_MACHINE_ID_FILE, RULE_NOT_DIR,
    RULE_NOT_FILE_OR_DIR, RULE_NOT_REGULAR, RULE_OUTSIDE_READS, RULE_SSH, RULE_SYSTEM_SECRET,
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
        statfs: &[],
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
        #[expect(
            clippy::disallowed_methods,
            reason = "the engine's own tests build the live backend; check crates may not"
        )]
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
async fn the_machine_id_files_are_refused_to_a_check_that_declares_the_root() {
    let sandbox = Sandbox::new();
    // Files shaped like the id files, inside the sandbox: the deny rule matches at any depth, so no real
    // `/etc` is needed. A link to each looks fine by name and is judged on its real path.
    let etc = sandbox.write("etc/machine-id", b"0f1e2d3c4b5a69788796a5b4c3d2e1f0\n");
    let dbus = sandbox.write(
        "var/lib/dbus/machine-id",
        b"0f1e2d3c4b5a69788796a5b4c3d2e1f0\n",
    );
    symlink(&etc, sandbox.path("looks-fine")).expect("symlink");
    symlink(&dbus, sandbox.path("also-fine")).expect("symlink");
    let run = sandbox.write("run/machine-id", b"0f1e2d3c4b5a69788796a5b4c3d2e1f0\n");
    symlink(&run, sandbox.path("run-looks-fine")).expect("symlink");
    // The DMI files, under both sysfs names, and a copy of one under a host mount.
    let dmi: Vec<PathBuf> = [
        "sys/class/dmi/id/product_serial",
        "sys/class/dmi/id/product_uuid",
        "sys/devices/virtual/dmi/id/board_serial",
        "sys/devices/virtual/dmi/id/chassis_serial",
        "host/sys/class/dmi/id/board_serial",
    ]
    .map(|name| sandbox.write(name, b"SN-0001\n"))
    .into();
    symlink(&dmi[0], sandbox.path("dmi-looks-fine")).expect("symlink");
    let mut cases = vec![
        etc,
        dbus,
        run,
        sandbox.path("looks-fine"),
        sandbox.path("also-fine"),
        sandbox.path("run-looks-fine"),
        sandbox.path("dmi-looks-fine"),
    ];
    cases.extend(dmi);
    // The same names on the real machine, where they exist.
    cases.extend(
        [
            "/etc/machine-id",
            "/var/lib/dbus/machine-id",
            "/run/machine-id",
            "/sys/class/dmi/id/product_serial",
            "/sys/class/dmi/id/product_uuid",
            "/sys/class/dmi/id/board_serial",
            "/sys/class/dmi/id/chassis_serial",
        ]
        .map(PathBuf::from)
        .into_iter()
        .filter(|file| file.exists()),
    );
    let probe = sandbox.probe(&[Path::new("/")], &[]);
    for path in &cases {
        let error = probe.read(path).await.expect_err("refused");
        assert_eq!(rule_of(&error), RULE_MACHINE_ID_FILE, "{}", path.display());
        let error = probe.stat(path).await.expect_err("refused");
        assert_eq!(rule_of(&error), RULE_MACHINE_ID_FILE, "{}", path.display());
    }
    // A sibling that is not a machine id file is still read.
    let other = sandbox.write("etc/hostname", b"node\n");
    assert_eq!(probe.read(&other).await.expect("read").bytes, b"node\n");
    let model = sandbox.write("sys/class/dmi/id/product_name", b"Model 1\n");
    assert_eq!(probe.read(&model).await.expect("read").bytes, b"Model 1\n");
}

/// A hard link (and so a bind mount, which has the same identity) of a machine id file has another
/// name, so only its inode gives it away. The `MachineId` guard is the one reader that is let through.
#[tokio::test]
async fn a_hard_link_to_a_machine_id_file_is_refused_by_inode() {
    let sandbox = Sandbox::new();
    let id = sandbox.write("id", b"0f1e2d3c4b5a69788796a5b4c3d2e1f0\n");
    std::fs::hard_link(&id, sandbox.path("innocent")).expect("hard link");
    // The backend learns the inode when it is made; here the id file is the file just written.
    let secrets = files::Secrets::from_paths(&[], &[id.as_path()]);
    let guard = ReadGuard::new(Os::Linux, None);
    let wide = ReadGuard::new(Os::Linux, Some(&["/"]));
    for guard in [&guard, &wide] {
        let name = sandbox.path("innocent");
        let error =
            files::read(&name, ReadRange::Head(MAX_READ), guard, &secrets).expect_err("refused");
        assert_eq!(
            crate::probe::Refused::from_io(&error).map(|r| r.rule),
            Some(RULE_MACHINE_ID_FILE)
        );
        let error = files::stat(&name, guard, &secrets).expect_err("refused");
        assert_eq!(
            crate::probe::Refused::from_io(&error).map(|r| r.rule),
            Some(RULE_MACHINE_ID_FILE)
        );
        let Err(error) = files::statvfs(&name, guard, &secrets) else {
            panic!("statvfs of a machine id link was not refused");
        };
        assert_eq!(
            crate::probe::Refused::from_io(&error).map(|r| r.rule),
            Some(RULE_MACHINE_ID_FILE)
        );
    }
    let other = sandbox.write("other", b"fine");
    let ok = files::read(&other, ReadRange::Head(MAX_READ), &guard, &secrets)
        .expect("an unrelated file");
    assert_eq!(ok.bytes, b"fine");
}

/// The skip is for the `MachineId` guard and for the machine id files only.
#[test]
fn only_the_machine_id_guard_skips_the_machine_id_inodes() {
    let sandbox = Sandbox::new();
    let id = sandbox.write("id", b"0f1e2d3c4b5a69788796a5b4c3d2e1f0\n");
    let password = sandbox.write("passwords", b"root:x");
    let secrets = files::Secrets::from_paths(&[password.as_path()], &[id.as_path()]);
    let id_stat = rustix::fs::stat(&id).expect("stat");
    let password_stat = rustix::fs::stat(&password).expect("stat");
    let other = ReadGuard::new(Os::Linux, None);
    let engine = ReadGuard::machine_id_files();
    assert_eq!(
        secrets.refuses(&id_stat, &other),
        Some(RULE_MACHINE_ID_FILE)
    );
    assert_eq!(secrets.refuses(&id_stat, &engine), None);
    // A password file is refused to every guard, the engine's too.
    assert_eq!(
        secrets.refuses(&password_stat, &other),
        Some(RULE_SYSTEM_SECRET)
    );
    assert_eq!(
        secrets.refuses(&password_stat, &engine),
        Some(RULE_SYSTEM_SECRET)
    );
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
fn the_portable_statvfs_asks_the_descriptor_it_opened() {
    // Linux asks the judged `O_PATH` descriptor; macOS opens the real path and asks that descriptor.
    // The second is compiled everywhere, so its pieces are tested here. A file or a directory is
    // measured; a FIFO is not opened.
    let sandbox = Sandbox::new();
    let file = sandbox.write("data/file", b"x");
    let fifo = sandbox.path("pipe");
    mkfifo(&fifo);
    let guard = ReadGuard::new(Os::Linux, None);
    let none = files::Secrets::default();
    for path in [sandbox.path("data"), file] {
        let (real, stat) = files::locate_by_path(&path, &guard, &none).expect("ok");
        let (fd, _) =
            files::open_by_path(&path, &real, &stat, &guard, files::Want::Either).expect("open");
        let info = rustix::fs::fstatvfs(&fd).expect("fstatvfs");
        assert!(info.f_blocks > 0, "{}", path.display());
    }
    let (real, stat) = files::locate_by_path(&fifo, &guard, &none).expect("a FIFO is described");
    let error = files::open_by_path(&fifo, &real, &stat, &guard, files::Want::Either)
        .expect_err("not opened");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_NOT_FILE_OR_DIR)
    );
}

#[test]
fn the_portable_statvfs_measures_a_readable_path_by_itself() {
    let sandbox = Sandbox::new();
    sandbox.write("data/file", b"x");
    let guard = ReadGuard::new(Os::Linux, None);
    let none = files::Secrets::default();
    let dir = sandbox.path("data");
    let (real, stat) = files::locate_by_path(&dir, &guard, &none).expect("ok");
    let info = files::statvfs_by_path(&dir, &real, &stat, &guard, &none).expect("numbers");
    assert!(info.f_blocks > 0);
}

#[test]
fn a_rule_refusal_of_the_target_is_final_and_gets_no_parent() {
    // A FIFO is refused by `open_by_path` with a `Refused`. `statvfs_by_path` returns it unchanged
    // and does not try the parent.
    let sandbox = Sandbox::new();
    let fifo = sandbox.path("pipe");
    mkfifo(&fifo);
    let guard = ReadGuard::new(Os::Linux, None);
    let none = files::Secrets::default();
    let (real, stat) = files::locate_by_path(&fifo, &guard, &none).expect("described");
    let error = files::statvfs_by_path(&fifo, &real, &stat, &guard, &none)
        .map(|_| ())
        .expect_err("refused");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_NOT_FILE_OR_DIR)
    );
}

#[test]
fn the_parent_step_measures_through_a_parent_on_the_same_file_system() {
    // `statvfs_through_parent` runs when the open of the target fails with a plain permission error
    // (macOS opens the directory for reading; Linux uses `O_PATH` and never gets here). The real
    // permission error is driven in `an_unreadable_directory_is_measured_through_its_parent`.
    let sandbox = Sandbox::new();
    sandbox.write("data/inner/file", b"x");
    let guard = ReadGuard::new(Os::Linux, None);
    let none = files::Secrets::default();
    let (real, stat) =
        files::locate_by_path(&sandbox.path("data/inner"), &guard, &none).expect("ok");
    let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
    let info = files::statvfs_through_parent(denied(), &real, &stat, &guard, &none)
        .expect("the parent is on the same file system");
    assert!(info.f_blocks > 0);

    // The check's prefixes cover the target and not its parent: the parent is refused, nothing is
    // guessed, and the caller gets the original error.
    let narrow = ReadGuard::new(Os::Linux, Some(leak_prefixes(&[&real])));
    let error = files::statvfs_through_parent(denied(), &real, &stat, &narrow, &none)
        .map(|_| ())
        .expect_err("the parent is outside the prefixes");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(crate::probe::Refused::from_io(&error).is_none());
}

fn leak_prefixes(paths: &[&Path]) -> &'static [&'static str] {
    let list: Vec<&'static str> = paths
        .iter()
        .map(|path| &*Box::leak(path.to_string_lossy().into_owned().into_boxed_str()))
        .collect();
    Box::leak(list.into_boxed_slice())
}

/// A directory the user can enter but not list (`0o311`), restored when dropped so the temporary
/// directory can be removed.
struct EnterOnly(PathBuf);

impl EnterOnly {
    /// Makes `data/inner` enter-only. `None` when the test runs as root, which can list anything: that
    /// run says so on stderr and the test returns. Every other run proves the precondition first: a
    /// plain open of the directory fails with `EACCES`, so the tests really start from that error.
    fn make(sandbox: &Sandbox) -> Option<Self> {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            eprintln!("skipped: root can list any directory (CI runners are not root)");
            return None;
        }
        sandbox.write("data/inner/file", b"x");
        let inner = sandbox.path("data/inner");
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o311)).expect("chmod");
        let guard = Self(inner);
        let error = std::fs::File::open(&guard.0).expect_err("a 0o311 directory cannot be opened");
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "the precondition of the test is EACCES, got {error:?}"
        );
        Some(guard)
    }
}

impl Drop for EnterOnly {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn an_unreadable_directory_is_measured_through_its_parent() {
    // The real error, not a made-up one: the open of a `0o311` directory fails with `EACCES`, and
    // `statvfs_by_path` answers with the numbers of the parent, which is on the same file system.
    let sandbox = Sandbox::new();
    let Some(inner) = EnterOnly::make(&sandbox) else {
        return;
    };
    let guard = ReadGuard::new(Os::Linux, None);
    let none = files::Secrets::default();
    let (real, stat) = files::locate_by_path(&inner.0, &guard, &none).expect("located");
    let info = files::statvfs_by_path(&inner.0, &real, &stat, &guard, &none)
        .expect("the parent gives the numbers");
    let data = sandbox.path("data");
    let (parent_fd, _) = files::open_by_path(
        &data,
        &data,
        &rustix::fs::stat(&data).expect("stat"),
        &guard,
        files::Want::Dir,
    )
    .expect("open the parent");
    let parent = rustix::fs::fstatvfs(&parent_fd).expect("fstatvfs");
    assert!(info.f_blocks > 0);
    assert_eq!(info.f_fsid, parent.f_fsid);
    assert_eq!(info.f_blocks, parent.f_blocks);
}

#[test]
fn an_unreadable_directory_whose_parent_is_outside_the_prefixes_is_denied() {
    // The prefixes cover the directory and not its parent. The rules refuse the parent and the
    // caller gets the plain `PermissionDenied`, not a refusal and not a guess.
    let sandbox = Sandbox::new();
    let Some(inner) = EnterOnly::make(&sandbox) else {
        return;
    };
    let none = files::Secrets::default();
    let narrow = ReadGuard::new(Os::Linux, Some(leak_prefixes(&[&inner.0])));
    let (real, stat) = files::locate_by_path(&inner.0, &narrow, &none).expect("located");
    let error = files::statvfs_by_path(&inner.0, &real, &stat, &narrow, &none)
        .map(|_| ())
        .expect_err("the parent is outside the prefixes");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        crate::probe::Refused::from_io(&error).is_none(),
        "{error:?}"
    );
}

/// `/proc` is its own file system, so the numbers of `/` would be wrong for it. A Linux machine
/// always has it, so a missing mount fails the test.
#[cfg(target_os = "linux")]
#[test]
fn a_mount_point_is_reported_not_measured_through_its_parent() {
    let guard = ReadGuard::new(Os::Linux, None);
    let none = files::Secrets::default();
    let (real, stat) = files::locate_by_path(Path::new("/proc"), &guard, &none).expect("ok");
    let root = rustix::fs::stat("/").expect("stat /");
    assert_ne!(root.st_dev, stat.st_dev, "/proc is not a separate mount");
    let denied = io::Error::from(io::ErrorKind::PermissionDenied);
    let error = files::statvfs_through_parent(denied, &real, &stat, &guard, &none)
        .map(|_| ())
        .expect_err("a mount point is not measured through its parent");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
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
    let secrets = files::Secrets::from_paths(&[secret.as_path()], &[]);
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

// ---- read_link (M1-169) ------------------------------------------------------------------------

fn text_of(file: &crate::probe::FileBytes) -> String {
    String::from_utf8(file.bytes.clone()).expect("utf-8")
}

fn link_entries(sandbox: &Sandbox) -> Vec<Action> {
    sandbox
        .actions()
        .into_iter()
        .filter(|action| action.kind == rdy_spec::result::ActionKind::ReadLink)
        .collect()
}

#[tokio::test]
async fn read_link_returns_the_target_without_following_it() {
    let sandbox = Sandbox::new();
    // The target does not exist, and a read of the link would fail. The link itself is fine.
    symlink("../gone/away.txt", sandbox.path("dangling")).expect("symlink");
    let shadow = sandbox.write("etc/shadow", b"root:!:19000::::::\n");
    symlink(&shadow, sandbox.path("to-shadow")).expect("symlink");
    let probe = sandbox.probe(&[], &[]);

    let target = probe
        .read_link(&sandbox.path("dangling"))
        .await
        .expect("the link");
    assert_eq!(text_of(&target), "../gone/away.txt");
    // Where it points is not judged: the link to the password file says so, and opens nothing.
    let target = probe
        .read_link(&sandbox.path("to-shadow"))
        .await
        .expect("the link");
    assert_eq!(Path::new(&text_of(&target)), shadow);
    assert_eq!(
        rule_of(
            &probe
                .read(&sandbox.path("to-shadow"))
                .await
                .expect_err("the file behind it stays closed")
        ),
        RULE_SYSTEM_SECRET
    );

    // One entry per link read, holding the link's path and not its target.
    let log = link_entries(&sandbox);
    assert_eq!(log.len(), 2);
    for entry in &log {
        assert_eq!(entry.outcome, ActionOutcome::Ok);
        let keys: Vec<&str> = entry.fields.keys().map(String::as_str).collect();
        assert_eq!(keys, ["path"]);
    }
    let json = serde_json::to_string(&sandbox.actions()).expect("json");
    assert!(!json.contains("away.txt"), "{json}");
}

#[tokio::test]
async fn read_link_resolves_a_link_in_the_parent_and_judges_the_real_link() {
    let sandbox = Sandbox::new();
    sandbox.write("real/placeholder", b"x");
    symlink("target-name", sandbox.path("real/inner")).expect("symlink");
    symlink(sandbox.path("real"), sandbox.path("via")).expect("symlink");
    let probe = sandbox.probe(&[], &[]);
    let target = probe
        .read_link(&sandbox.path("via/inner"))
        .await
        .expect("through the directory link");
    assert_eq!(text_of(&target), "target-name");

    // The real parent is outside the declared prefixes: refused, though the name looked fine.
    let outside = Sandbox::new();
    outside.write("elsewhere/placeholder", b"x");
    symlink("t", outside.path("elsewhere/inner")).expect("symlink");
    symlink(outside.path("elsewhere"), sandbox.path("escape")).expect("symlink");
    let error = probe
        .read_link(&sandbox.path("escape/inner"))
        .await
        .expect_err("outside the prefixes");
    assert_eq!(rule_of(&error), RULE_OUTSIDE_READS, "{error:?}");
    let log = link_entries(&sandbox);
    assert_eq!(log.last().map(|a| &a.outcome), Some(&ActionOutcome::Denied));
}

#[tokio::test]
async fn read_link_refuses_the_denylist_the_prefixes_and_bad_paths() {
    let sandbox = Sandbox::new();
    symlink("x", sandbox.path("id_rsa")).expect("symlink");
    symlink("x", sandbox.path("fine")).expect("symlink");
    let probe = sandbox.probe(&[], &[]);
    let error = probe
        .read_link(&sandbox.path("id_rsa"))
        .await
        .expect_err("a key name");
    assert!(matches!(error, ProbeError::Denied { .. }), "{error:?}");
    let error = probe
        .read_link(Path::new("/etc/os-release"))
        .await
        .expect_err("outside the prefixes");
    assert_eq!(rule_of(&error), RULE_OUTSIDE_READS);
    let error = probe
        .read_link(Path::new("etc/os-release"))
        .await
        .expect_err("relative");
    assert!(matches!(error, ProbeError::Denied { .. }), "{error:?}");
    let dotted = format!("{}/x/../fine", sandbox.root.display());
    let error = probe
        .read_link(Path::new(&dotted))
        .await
        .expect_err("dot dot");
    assert_eq!(rule_of(&error), RULE_DOT_DOT);
    // The one fine link reads, so the refusals above are the rules' and not the setup's.
    probe.read_link(&sandbox.path("fine")).await.expect("fine");
}

#[tokio::test]
async fn read_link_says_not_found_and_not_a_link() {
    let sandbox = Sandbox::new();
    sandbox.write("plain", b"x");
    let probe = sandbox.probe(&[], &[]);
    assert_eq!(
        probe.read_link(&sandbox.path("missing")).await,
        Err(ProbeError::NotFound)
    );
    assert_eq!(
        probe.read_link(&sandbox.path("no-such-dir/link")).await,
        Err(ProbeError::NotFound)
    );
    match probe.read_link(&sandbox.path("plain")).await {
        Err(ProbeError::Io(text)) => assert!(text.contains("not a symbolic link"), "{text}"),
        other => panic!("expected an Io error, got {other:?}"),
    }
    // A directory is not a link either.
    sandbox.write("dir/f", b"x");
    assert!(matches!(
        probe.read_link(&sandbox.path("dir")).await,
        Err(ProbeError::Io(_))
    ));
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn the_portable_read_link_gives_the_same_answers() {
    // Linux uses O_PATH; macOS uses this. It is compiled on both, so it is tested here.
    let sandbox = Sandbox::new();
    sandbox.write("real/placeholder", b"x");
    symlink("target-name", sandbox.path("real/inner")).expect("symlink");
    symlink(sandbox.path("real"), sandbox.path("via")).expect("symlink");
    symlink("/etc/shadow", sandbox.path("real/shadow-link")).expect("symlink");
    // The target is text: it need not exist.
    let reads = leak_prefixes(&[sandbox.root.as_path()]);
    let guard = ReadGuard::link(Os::Linux, Some(reads));
    let read = |parent: &Path, name: &str| {
        files::read_link_by_path(parent, std::ffi::OsStr::new(name), &guard)
    };

    assert_eq!(
        read(&sandbox.path("via"), "inner").expect("through the directory link"),
        b"target-name"
    );
    assert_eq!(
        read(&sandbox.path("real"), "shadow-link").expect("a target is not judged"),
        b"/etc/shadow"
    );
    let error = read(&sandbox.path("real"), "placeholder").expect_err("not a link");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let error = read(&sandbox.path("real"), "missing").expect_err("missing");
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let error = read(Path::new("/etc"), "os-release").expect_err("outside the prefixes");
    assert_eq!(
        crate::probe::Refused::from_io(&error).map(|r| r.rule),
        Some(RULE_OUTSIDE_READS)
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn the_net_namespace_link_is_not_found_on_macos() {
    // There is no /proc here. The grant is for Linux, and the answer is the one a missing file gives.
    let sandbox = Sandbox::new();
    let probe = sandbox.probe(&[Path::new("/proc/self/ns/net")], &[]);
    assert_eq!(
        probe.read_link(Path::new("/proc/self/ns/net")).await,
        Err(ProbeError::NotFound)
    );
}

#[test]
fn the_text_of_proc_self_names_our_pid_or_it_is_not_ours() {
    assert!(files::names_pid(b"1234", 1234));
    assert!(!files::names_pid(b"1235", 1234));
    assert!(!files::names_pid(b"", 1234));
    assert!(!files::names_pid(b"1234\n", 1234));
    assert!(!files::names_pid(b"self", 1234));
    assert!(!files::names_pid(b"12340", 1234));
}

#[cfg(target_os = "linux")]
mod proc_links {
    use super::*;
    use crate::check::FD_WALK;
    use crate::probe::policy::RULE_FD_TARGET;
    use std::os::unix::net::UnixListener;

    fn walker(sandbox: &Sandbox) -> Probe {
        sandbox.probe(&[Path::new(FD_WALK), Path::new("/proc/self/ns/net")], &[])
    }

    /// A backend whose `/proc/self` is not rdy's own process, as under another pid namespace's procfs.
    fn foreign_proc_hub() -> ProbeHub {
        let backend = Live {
            secrets: files::Secrets::default(),
            own_proc: false,
        };
        ProbeHub::new(Arc::new(backend), Redactor::new(TagKey::fixed([5; 32])))
    }

    /// The test process must see the procfs of its own PID namespace, as it does on a CI runner and on a
    /// laptop. A run in a container that mounts the host's `/proc` fails here, and that is a fact about
    /// the test machine, not about the code.
    #[test]
    fn a_test_run_sees_the_proc_of_its_own_pid_namespace() {
        assert!(files::proc_self_is_own());
    }

    #[tokio::test]
    async fn the_own_process_grants_close_when_proc_self_is_not_rdys_own() {
        let hub = foreign_proc_hub();
        let probe = hub.check_probe(
            "host.fixture",
            Os::Linux,
            Some(manifest(&[Path::new("/proc")], &[])),
        );
        let error = probe
            .read_link(Path::new("/proc/self/ns/net"))
            .await
            .expect_err("closed");
        assert_eq!(rule_of(&error), RULE_PROC);
        let error = probe
            .read(Path::new("/proc/self/auxv"))
            .await
            .expect_err("closed");
        assert_eq!(rule_of(&error), RULE_PROC);
        // What is not tied to the own process still reads.
        probe
            .read(Path::new("/proc/self/status"))
            .await
            .expect("status");
    }

    #[test]
    fn a_parent_named_through_another_mount_is_not_trusted() {
        use crate::probe::Refused;
        use rustix::fs::{AtFlags, CWD, stat, statat};
        let rule = |result: io::Result<()>| {
            Refused::from_io(&result.expect_err("refused")).map(|refusal| refusal.rule)
        };
        let anchor = stat("/").expect("stat /");
        let mut other = anchor;
        other.st_ino = other.st_ino.wrapping_add(1);

        // The name leads to the same inode, on a file system that is no procfs: fine.
        let confirm = |named: rustix::io::Result<rustix::fs::Stat>, on_proc: bool, parent: &str| {
            files::confirm_real_parent(&anchor, named, on_proc, Path::new(parent))
        };
        confirm(Ok(anchor), false, "/mnt/anywhere").expect("same inode");
        // A procfs seen as /proc, deep or not, is fine.
        confirm(Ok(anchor), true, "/proc").expect("proc root");
        confirm(Ok(anchor), true, "/proc/1234/fd").expect("fd directory");
        // The name leads to another inode, or nowhere: it came from another mount namespace.
        assert_eq!(
            rule(confirm(Ok(other), false, "/mnt/p/1")),
            Some(RULE_CHANGED)
        );
        assert_eq!(
            rule(confirm(Err(rustix::io::Errno::NOENT), false, "/mnt/p/1")),
            Some(RULE_CHANGED)
        );
        // A procfs under another name (a bind mount, or a procfs mounted elsewhere): the `/proc/<pid>`
        // rules match on the name `proc`, so the directory is refused.
        for parent in ["/mnt/p/1/fd", "/mnt/hostproc/1234/fd", "/procfs/1/fd", "/"] {
            assert_eq!(
                rule(confirm(Ok(anchor), true, parent)),
                Some(RULE_PROC),
                "{parent}"
            );
        }
        // The real thing: the directory of the namespace links, as the live call sees it.
        let ns = stat("/proc/self/ns").expect("stat ns");
        let named = statat(CWD, "/proc/self/ns", AtFlags::SYMLINK_NOFOLLOW);
        files::confirm_real_parent(&ns, named, true, Path::new("/proc/self/ns")).expect("proc");
    }

    #[tokio::test]
    async fn the_fd_walk_text_is_no_prefix_for_a_read() {
        let sandbox = Sandbox::new();
        let probe = walker(&sandbox);
        for path in ["/proc/<pid>/fd/x", "/proc/<pid>/fd/3"] {
            let error = probe.read(Path::new(path)).await.expect_err(path);
            assert_eq!(rule_of(&error), RULE_OUTSIDE_READS, "{path}");
        }
        // A real fd is closed to a content read, as before.
        let error = probe
            .read(Path::new("/proc/self/fd/0"))
            .await
            .expect_err("closed");
        assert_eq!(rule_of(&error), RULE_PROC);
    }

    #[tokio::test]
    async fn the_net_namespace_of_rdy_resolves() {
        let sandbox = Sandbox::new();
        let probe = sandbox.probe(&[Path::new("/proc/self/ns/net")], &[]);
        let ns = probe
            .read_link(Path::new("/proc/self/ns/net"))
            .await
            .expect("the namespace link");
        let text = text_of(&ns);
        assert!(text.starts_with("net:["), "{text}");
        assert!(text.ends_with(']'), "{text}");
        // It is the namespace of this process: the kernel says the same.
        let own = std::fs::read_link("/proc/self/ns/net").expect("the real link");
        assert_eq!(Path::new(&text), own);
        let log = link_entries(&sandbox);
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].outcome, ActionOutcome::Ok);

        // Another process's namespace and another namespace are closed.
        let error = probe
            .read_link(Path::new("/proc/1/ns/net"))
            .await
            .expect_err("refused");
        assert_eq!(rule_of(&error), RULE_PROC);
        let wide = sandbox.probe(&[Path::new("/proc")], &[]);
        let error = wide
            .read_link(Path::new("/proc/self/ns/mnt"))
            .await
            .expect_err("refused");
        assert_eq!(rule_of(&error), RULE_PROC);
        // A pid in the path is refused as written, even our own, as with `auxv`.
        let own = format!("/proc/{}/ns/net", std::process::id());
        let error = wide.read_link(Path::new(&own)).await.expect_err("refused");
        assert_eq!(rule_of(&error), RULE_PROC);
    }

    #[tokio::test]
    async fn a_walk_over_this_processs_fds_returns_only_sockets() {
        let sandbox = Sandbox::new();
        // A socket, a regular file and a directory held open by this process, under names the test
        // can look for.
        let socket_path = sandbox.path("walk.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind");
        let secret_name = "rdy-169-held-open-file.txt";
        let held = sandbox.write(secret_name, b"x");
        let file = std::fs::File::open(&held).expect("open");
        let inode = rustix::fs::fstat(&listener).expect("fstat").st_ino;

        let probe = walker(&sandbox);
        let names: Vec<String> = probe
            .read_dir(Path::new("/proc/self/fd"))
            .await
            .expect("the fd directory")
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert!(!names.is_empty());
        let mut sockets = Vec::new();
        let mut refused = 0_usize;
        for name in &names {
            let path = format!("/proc/self/fd/{name}");
            match probe.read_link(Path::new(&path)).await {
                Ok(target) => {
                    let text = text_of(&target);
                    assert!(
                        text.starts_with("socket:["),
                        "only sockets come back: {text}"
                    );
                    sockets.push(text);
                }
                Err(ProbeError::Denied { rule, what }) => {
                    assert_eq!(rule, RULE_FD_TARGET);
                    assert!(!what.contains(secret_name), "{what}");
                    refused += 1;
                }
                // An fd that closed between the listing and the read (the listing's own, a runner
                // thread's).
                Err(ProbeError::NotFound) => {}
                Err(other) => panic!("{path}: {other:?}"),
            }
        }
        assert!(
            sockets.contains(&format!("socket:[{inode}]")),
            "{sockets:?} holds the listener {inode}"
        );
        assert!(refused > 0, "files, pipes and the like are refused");
        drop((listener, file));

        // Nothing logged names what the refused fds pointed to.
        let json = serde_json::to_string(&sandbox.actions()).expect("json");
        assert!(!json.contains(secret_name), "{json}");
        assert!(!json.contains("walk.sock"), "{json}");
        let log = link_entries(&sandbox);
        assert!(log.iter().any(|a| a.outcome == ActionOutcome::Denied
            && a.fields.get("rule").and_then(Value::as_str) == Some(RULE_FD_TARGET)));
    }

    #[tokio::test]
    async fn the_fd_directory_is_closed_without_the_declaration_and_to_other_calls() {
        let sandbox = Sandbox::new();
        let proc_only = sandbox.probe(&[Path::new("/proc")], &[]);
        for path in ["/proc/self/fd/0", "/proc/self/fd"] {
            let error = proc_only.read_link(Path::new(path)).await.expect_err(path);
            assert_eq!(rule_of(&error), RULE_PROC, "{path}");
        }
        let error = proc_only
            .read_dir(Path::new("/proc/self/fd"))
            .await
            .expect_err("no declaration");
        assert_eq!(rule_of(&error), RULE_PROC);

        // With it, the file behind a link is still out of reach: read, stat and a deeper walk fail.
        let probe = walker(&sandbox);
        for path in ["/proc/self/fd/0", "/proc/self/fd"] {
            let error = probe.read(Path::new(path)).await.expect_err(path);
            assert_eq!(rule_of(&error), RULE_PROC, "{path}");
            let error = probe.stat(Path::new(path)).await.expect_err(path);
            assert_eq!(rule_of(&error), RULE_PROC, "{path}");
        }
        for path in [
            "/proc/thread-self/fd/0",
            "/proc/self/task/1/fd/0",
            "/proc/self/fd/0/x",
        ] {
            let error = probe.read_link(Path::new(path)).await.expect_err(path);
            assert!(
                matches!(error, ProbeError::Denied { .. }),
                "{path}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_link_to_the_fd_directory_does_not_hide_the_rule() {
        // `<sandbox>/fds` is a link to `/proc/self/fd`. As written the path is under the sandbox. The
        // real link is `/proc/<pid>/fd/<n>`, and the target rule applies to it all the same.
        let sandbox = Sandbox::new();
        let held = sandbox.write("held-open.txt", b"x");
        let file = std::fs::File::open(&held).expect("open");
        symlink("/proc/self/fd", sandbox.path("fds")).expect("symlink");
        let probe = sandbox.probe(&[Path::new(FD_WALK)], &[]);
        let names: Vec<String> = probe
            .read_dir(&sandbox.path("fds"))
            .await
            .expect("the listing")
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert!(!names.is_empty());
        let mut refused = false;
        for name in names {
            match probe.read_link(&sandbox.path(&format!("fds/{name}"))).await {
                Ok(target) => assert!(text_of(&target).starts_with("socket:["), "{target:?}"),
                Err(ProbeError::Denied { rule, .. }) => {
                    assert_eq!(rule, RULE_FD_TARGET);
                    refused = true;
                }
                Err(ProbeError::NotFound) => {}
                Err(other) => panic!("{other:?}"),
            }
        }
        assert!(
            refused,
            "a regular file's fd is refused through the link too"
        );
        drop(file);
    }
}
