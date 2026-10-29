//! Process runner tests.
//!
//! The process tests run real `sh` and `sleep`, so they are Unix only. They use real time with
//! generous timeouts and check upper bounds only. The registry tests are portable.

use super::*;

static IDLE: Registry<REGISTRY_SLOTS> = Registry::new();

#[test]
fn registry_hands_out_each_slot_once_and_refuses_when_full() {
    let registry: Registry<2> = Registry::new();
    let a = registry.reserve().expect("first slot");
    let b = registry.reserve().expect("second slot");
    assert_ne!(a, b);
    assert!(registry.reserve().is_none());
    registry.release(a);
    assert_eq!(registry.reserve(), Some(a));
}

#[test]
fn registry_kill_all_skips_free_and_reserved_slots_and_sets_the_flag_first() {
    use std::sync::Mutex;
    static SEEN: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static REGISTRY_UNDER_TEST: Registry<4> = Registry::new();
    fn record(pid: u32) {
        // The flag is already set when the first kill happens.
        assert!(REGISTRY_UNDER_TEST.shutting_down());
        SEEN.lock().expect("lock").push(pid);
    }
    let first = REGISTRY_UNDER_TEST.reserve().expect("slot");
    REGISTRY_UNDER_TEST.set(first, 4242);
    let _reserved_only = REGISTRY_UNDER_TEST.reserve().expect("slot");
    // `live` counts reserved slots too.
    assert_eq!(REGISTRY_UNDER_TEST.live(), 2);
    assert!(!REGISTRY_UNDER_TEST.shutting_down());
    REGISTRY_UNDER_TEST.kill_all(record);
    assert_eq!(*SEEN.lock().expect("lock"), vec![4242]);
    assert!(REGISTRY_UNDER_TEST.shutting_down());
}

#[test]
fn the_defaults_match_the_design() {
    assert_eq!(REAP_GRACE, Duration::from_secs(1));
    assert_eq!(DEFAULT_STDOUT_CAP, 1024 * 1024);
    assert_eq!(DEFAULT_STDERR_CAP, 64 * 1024);
    assert_eq!(KILLS_PROCESS_TREE, cfg!(unix));
}

#[test]
fn debug_output_shows_env_names_and_never_values() {
    let spec = ExecSpec::new("/bin/true", Duration::from_secs(1))
        .env([("HTTPS_PROXY", "http://user:hunter2@proxy.example:3128")]);
    let text = format!("{spec:?}");
    assert!(text.contains("HTTPS_PROXY"), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
    assert!(!text.contains("proxy.example"), "{text}");
}

#[tokio::test]
async fn a_program_that_is_not_an_absolute_path_is_refused_before_any_lookup() {
    for program in ["whoami", "./whoami", "bin/whoami"] {
        let error = run_with(
            ExecSpec::new(program, Duration::from_secs(1)),
            &IDLE,
            LIVE,
            REAP_GRACE,
        )
        .await
        .expect_err("refused");
        let ExecError::Spawn(inner) = error else {
            panic!("expected Spawn for {program}, got {error:?}");
        };
        assert_eq!(inner.kind(), io::ErrorKind::InvalidInput, "{program}");
    }
    assert_eq!(IDLE.live(), 0);
}

#[tokio::test]
async fn nothing_starts_after_the_run_has_ended() {
    static ENDED: Registry<REGISTRY_SLOTS> = Registry::new();
    ENDED.kill_all(nothing);
    let program = if cfg!(unix) {
        "/bin/sh"
    } else {
        "C:\\Windows\\System32\\whoami.exe"
    };
    let error = run_with(
        ExecSpec::new(program, Duration::from_secs(1)),
        &ENDED,
        LIVE,
        REAP_GRACE,
    )
    .await
    .expect_err("shutting down");
    assert!(matches!(error, ExecError::ShuttingDown), "{error:?}");
    assert_eq!(ENDED.live(), 0);
}

#[cfg(unix)]
mod process {
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use super::*;
    use crate::check::{
        BoxFuture, Check, CheckContext, CheckInfo, CheckOutcome, Finding, Need, OsSupport, Support,
        current_os,
    };
    use crate::sched::{End, Planned, Scheduler};

    const SECOND: Duration = Duration::from_secs(1);

    fn sh(script: &str, timeout: Duration) -> ExecSpec {
        ExecSpec::new("/bin/sh", timeout).args(["-c", script])
    }

    /// A script that forks `sleep 600` and records the sleeper's pid in `$0` (the first argument).
    fn forks_sleeper(pid_file: &Path, timeout: Duration) -> ExecSpec {
        ExecSpec::new("/bin/sh", timeout).args([
            "-c",
            "sleep 600 & echo $! > \"$0\"; wait",
            pid_file.to_str().expect("utf-8 temp path"),
        ])
    }

    /// Waits up to `limit` for the pid file to hold a pid, and returns it.
    async fn read_pid(pid_file: &Path, limit: Duration) -> u32 {
        let start = Instant::now();
        loop {
            if let Ok(text) = std::fs::read_to_string(pid_file)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            assert!(start.elapsed() < limit, "the script never wrote its pid");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// True when `pid` is gone. A zombie that nothing has reaped yet counts as gone.
    fn is_gone(pid: u32) -> bool {
        let Some(pid) = to_pid(pid) else {
            return true;
        };
        if rustix::process::test_kill_process(pid).is_err() {
            return true;
        }
        std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero()))
            .ok()
            .and_then(|stat| stat.rsplit(')').next().map(str::to_owned))
            .is_some_and(|rest| rest.trim_start().starts_with('Z'))
    }

    /// True while the kernel still knows `pid`, zombie or not. Reaping makes this false.
    fn exists(pid: u32) -> bool {
        to_pid(pid).is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
    }

    async fn wait_gone(pid: u32) {
        let start = Instant::now();
        while !is_gone(pid) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "process {pid} is still alive"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn collects_output_and_status() {
        let out = run(sh("echo out; echo err >&2; exit 3", SECOND * 10))
            .await
            .expect("runs");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
        assert!(!out.stdout_truncated && !out.stderr_truncated);
    }

    #[tokio::test]
    async fn caps_output_and_keeps_draining() {
        let spec = sh(
            "head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2",
            SECOND * 10,
        )
        .caps(10, 20);
        let out = run(spec).await.expect("a chatty child still finishes");
        assert_eq!(out.stdout.len(), 10);
        assert_eq!(out.stderr.len(), 20);
        assert!(out.stdout_truncated && out.stderr_truncated);
    }

    #[tokio::test]
    async fn the_parent_environment_is_not_inherited() {
        let spec = sh("echo \"${HOME-unset}:${RDY_T-unset}\"", SECOND * 10).env([("RDY_T", "yes")]);
        let out = run(spec).await.expect("runs");
        assert_eq!(out.stdout, b"unset:yes\n");
    }

    #[tokio::test]
    async fn the_child_starts_in_the_root_directory() {
        let out = run(sh("pwd", SECOND * 10)).await.expect("runs");
        assert_eq!(out.stdout, b"/\n");
    }

    /// The child role of the next test. It does nothing unless the parent set the marker. The umask is
    /// process-wide, so setting it to zero must happen in a process of its own, not in the shared
    /// test binary where other tests create files in parallel.
    #[tokio::test]
    async fn umask_probe() {
        if std::env::var_os("RDY_UMASK_PROBE").is_none() {
            return;
        }
        let _ = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o000));
        let out = run(sh("umask", SECOND * 10)).await.expect("runs");
        assert_eq!(out.stdout, b"0077\n");
        println!("umask probe ok");
    }

    #[test]
    fn the_child_gets_a_tight_umask_even_when_the_parent_had_a_loose_one() {
        let exe = std::env::current_exe().expect("test binary");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "exec::tests::process::umask_probe",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RDY_UMASK_PROBE", "1")
            .output()
            .expect("start the test binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("umask probe ok"), "{stdout}");
        assert_eq!(CHILD_UMASK, 0o077);
    }

    /// Descriptors the standard library opens do not reach a child. One whose close-on-exec flag was
    /// cleared (as a descriptor inherited from a shell would be) does. That second half is the
    /// documented residual of ADR 0023, and `inherited_fds` lists it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn only_descriptors_without_close_on_exec_reach_a_child() {
        use std::os::fd::AsRawFd;
        let kept = std::fs::File::open("/dev/null").expect("open");
        let leaked = std::fs::File::open("/dev/null").expect("open");
        rustix::io::fcntl_setfd(&leaked, rustix::io::FdFlags::empty()).expect("clear CLOEXEC");
        let (kept_fd, leaked_fd) = (kept.as_raw_fd(), leaked.as_raw_fd());

        let listed = inherited_fds();
        let fd = |raw: i32| u32::try_from(raw).expect("fd is not negative");
        assert!(listed.contains(&fd(kept_fd)) && listed.contains(&fd(leaked_fd)));

        let script =
            format!("test ! -e /proc/self/fd/{kept_fd} && test -e /proc/self/fd/{leaked_fd}");
        let out = run(sh(&script, SECOND * 10)).await.expect("runs");
        assert!(out.status.success(), "{out:?}");
    }

    #[test]
    fn the_standard_descriptors_are_never_listed() {
        assert!(inherited_fds().iter().all(|fd| *fd > 2));
    }

    #[tokio::test]
    async fn a_missing_program_is_a_spawn_error_and_frees_the_slot() {
        static OWN: Registry<REGISTRY_SLOTS> = Registry::new();
        let error = run_with(
            ExecSpec::new("/nonexistent/rdy-test", SECOND),
            &OWN,
            LIVE,
            REAP_GRACE,
        )
        .await
        .expect_err("cannot start");
        assert!(matches!(error, ExecError::Spawn(_)), "{error:?}");
        assert_eq!(OWN.live(), 0);
    }

    #[tokio::test]
    async fn timeout_kills_the_whole_process_group() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        let started = Instant::now();
        let error = run(forks_sleeper(&pid_file, SECOND * 2))
            .await
            .expect_err("times out");
        assert!(matches!(error, ExecError::Timeout), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(6));
        let sleeper = read_pid(&pid_file, SECOND).await;
        wait_gone(sleeper).await;
    }

    #[tokio::test]
    async fn dropping_the_future_kills_the_process_group() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        let task = tokio::spawn(run(forks_sleeper(&pid_file, Duration::from_secs(600))));
        let sleeper = read_pid(&pid_file, Duration::from_secs(5)).await;
        assert!(!is_gone(sleeper));
        task.abort();
        let _ = task.await;
        wait_gone(sleeper).await;
    }

    #[tokio::test]
    async fn a_normal_exit_also_clears_what_the_leader_left_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        // The sleeper's output is detached, so the pipes close as soon as the shell exits.
        let script = "sleep 600 >/dev/null 2>&1 & echo $! > \"$0\"";
        let spec = ExecSpec::new("/bin/sh", SECOND * 10).args([
            "-c",
            script,
            pid_file.to_str().expect("utf-8 temp path"),
        ]);
        let out = run(spec).await.expect("runs");
        assert!(out.status.success());
        let sleeper = read_pid(&pid_file, SECOND).await;
        wait_gone(sleeper).await;
    }

    #[tokio::test]
    async fn a_member_holding_the_pipe_does_not_hide_the_leaders_exit() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        // The sleeper keeps stdout open. Before the group kill on exit, the run waited for it.
        let script = "sleep 600 & echo $! > \"$0\"; echo done; exit 7";
        let spec = ExecSpec::new("/bin/sh", SECOND * 20).args([
            "-c",
            script,
            pid_file.to_str().expect("utf-8 temp path"),
        ]);
        let started = Instant::now();
        let out = run(spec).await.expect("the leader's exit is reported");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(out.stdout, b"done\n");
        let sleeper = read_pid(&pid_file, SECOND).await;
        wait_gone(sleeper).await;
    }

    #[tokio::test]
    async fn the_slot_is_freed_after_the_kill_and_before_the_reap() {
        static OWN: Registry<REGISTRY_SLOTS> = Registry::new();
        static RELEASED_PID: AtomicU32 = AtomicU32::new(0);
        static LIVE_AT_RELEASE: AtomicUsize = AtomicUsize::new(usize::MAX);
        static KILLED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
        static EXISTED_AT_RELEASE: AtomicBool = AtomicBool::new(false);
        fn killed(pid: u32) {
            // The slot is still held while the group is signalled.
            assert_eq!(OWN.live(), 1);
            KILLED.lock().expect("lock").push(pid);
            kill_group(pid);
        }
        fn released(pid: u32) {
            RELEASED_PID.store(pid, Ordering::SeqCst);
            LIVE_AT_RELEASE.store(OWN.live(), Ordering::SeqCst);
            // The leader has not been reaped: it is a zombie, and its group id is still held.
            EXISTED_AT_RELEASE.store(exists(pid), Ordering::SeqCst);
        }
        let hooks = Hooks {
            kill: killed,
            released,
        };
        let out = run_with(sh("exit 0", SECOND * 10), &OWN, hooks, REAP_GRACE)
            .await
            .expect("runs");
        assert!(out.status.success());
        let pid = RELEASED_PID.load(Ordering::SeqCst);
        assert_ne!(pid, 0, "the release hook never ran");
        assert_eq!(*KILLED.lock().expect("lock"), vec![pid]);
        assert_eq!(LIVE_AT_RELEASE.load(Ordering::SeqCst), 0);
        assert!(
            EXISTED_AT_RELEASE.load(Ordering::SeqCst),
            "the leader was already reaped when the slot was freed"
        );
        // After the run the leader is reaped.
        assert!(!exists(pid));
        assert_eq!(OWN.live(), 0);
    }

    #[tokio::test]
    async fn the_group_of_a_reaped_leader_is_not_signalled() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        // The leader leaves a sleeper in its group and exits at once.
        let mut leader = tokio::process::Command::new("/bin/sh")
            .args([
                "-c",
                "sleep 600 >/dev/null 2>&1 & echo $! > \"$0\"",
                pid_file.to_str().expect("utf-8 temp path"),
            ])
            .process_group(0)
            .spawn()
            .expect("starts");
        let leader_pid = leader.id().expect("pid");
        let sleeper = read_pid(&pid_file, Duration::from_secs(5)).await;
        wait_exited(leader_pid).await.expect("exits");
        // A live (zombie) leader: the group kill goes through.
        assert!(leader_unreaped(to_pid(leader_pid).expect("pid")));
        leader.wait().await.expect("reaps");
        // Reaped: the group id could belong to someone else now, so nothing is signalled.
        assert!(!leader_unreaped(to_pid(leader_pid).expect("pid")));
        kill_group(leader_pid);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!is_gone(sleeper), "the group of a reaped leader was killed");
        // Clean up the sleeper directly.
        let sleeper_pid = to_pid(sleeper).expect("pid");
        let _ = rustix::process::kill_process(sleeper_pid, rustix::process::Signal::KILL);
        wait_gone(sleeper).await;
    }

    #[tokio::test]
    async fn polling_for_an_exit_leaves_the_zombie_in_place() {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("starts");
        let pid = child.id().expect("pid");
        wait_exited(pid).await.expect("sees the exit");
        // WNOWAIT: still there to be reaped, so a group kill here would still be safe.
        assert!(exists(pid));
        assert!(child.wait().await.expect("reaps").success());
        assert!(!exists(pid));
    }

    #[tokio::test]
    async fn killing_the_registered_groups_ends_a_running_command() {
        static OWN: Registry<REGISTRY_SLOTS> = Registry::new();
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        let spec = forks_sleeper(&pid_file, Duration::from_secs(600));
        let task = tokio::spawn(run_with(spec, &OWN, LIVE, REAP_GRACE));
        let sleeper = read_pid(&pid_file, Duration::from_secs(5)).await;
        OWN.kill_all(kill_group);
        let out = task.await.expect("joins").expect("ends with a status");
        assert_eq!(out.status.signal(), Some(9));
        wait_gone(sleeper).await;
        assert_eq!(OWN.live(), 0);
        assert!(OWN.shutting_down());
    }

    #[tokio::test]
    async fn a_child_that_survives_sigkill_returns_hung_within_the_grace() {
        static OWN: Registry<REGISTRY_SLOTS> = Registry::new();
        static KILLED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
        // The kill function only records the pid, so the child outlives the "SIGKILL" like a process
        // stuck in the kernel would.
        fn record_only(pid: u32) {
            KILLED.lock().expect("lock").push(pid);
        }
        let hooks = Hooks {
            kill: record_only,
            released: nothing,
        };
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        let timeout = SECOND * 2;
        let spec = forks_sleeper(&pid_file, timeout);
        let started = Instant::now();
        let error = run_with(spec, &OWN, hooks, REAP_GRACE)
            .await
            .expect_err("hung");
        let took = started.elapsed();
        let ExecError::Hung { pid } = error else {
            panic!("expected Hung, got {error:?}");
        };
        // The run, then at most the one second grace, plus slack for a slow machine.
        assert!(took < timeout + REAP_GRACE + SECOND * 3, "took {took:?}");
        assert!(
            took >= timeout + REAP_GRACE - Duration::from_millis(100),
            "{took:?}"
        );
        assert_eq!(*KILLED.lock().expect("lock"), vec![pid]);
        // The group was signalled and the slot freed before the reap was attempted.
        assert_eq!(OWN.live(), 0);

        // Clean up for real: the detached reaper then collects the child.
        kill_group(pid);
        let sleeper = read_pid(&pid_file, SECOND).await;
        wait_gone(sleeper).await;
    }

    // A check that runs a command the way the facade will: through `exec::run`, with a long command
    // timeout, so only the scheduler's timeout can end it.
    static EXEC_CHECK: CheckInfo = CheckInfo {
        id: "fake.exec",
        family: "fake",
        summary: "A fake check that runs a script.",
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: OsSupport {
            linux: Support::Full,
            macos: Support::Full,
            windows: Support::Full,
        },
        reads: &[],
        env: &[],
        commands: &[],
        peers: &[],
    };

    struct ExecCheck {
        pid_file: std::path::PathBuf,
    }

    impl Check for ExecCheck {
        fn info(&self) -> &'static CheckInfo {
            &EXEC_CHECK
        }

        fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
            Box::pin(async move {
                let out = run(forks_sleeper(&self.pid_file, Duration::from_secs(600)))
                    .await
                    .map_err(|error| crate::check::CheckError::Failed {
                        message: error.to_string(),
                        hint: String::new(),
                    })?;
                Ok(Finding::pass(format!("{:?}", out.status)))
            })
        }
    }

    #[tokio::test]
    async fn a_scheduler_timeout_leaves_no_process_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        let check = Arc::new(ExecCheck {
            pid_file: pid_file.clone(),
        });
        let scheduler = Scheduler::new(2, current_os(), std::iter::empty::<Need>());
        let planned = Planned::new(check, "fake.exec").with_timeout(SECOND * 4);
        let started = Instant::now();
        let ran = scheduler.run(vec![planned]).await;
        assert!(started.elapsed() < Duration::from_secs(8));
        assert!(
            matches!(ran[0].end, End::TimedOut { .. }),
            "{:?}",
            ran[0].end
        );
        let sleeper = read_pid(&pid_file, SECOND).await;
        wait_gone(sleeper).await;
    }
}
