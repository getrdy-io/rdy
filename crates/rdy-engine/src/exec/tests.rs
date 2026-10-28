//! Process runner tests.
//!
//! The process tests run real `sh` and `sleep`, so they are Unix only. They use real time with short
//! timeouts and check upper bounds only. The registry tests are portable.

use super::*;

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
fn registry_kill_all_skips_free_and_reserved_slots() {
    use std::sync::Mutex;
    static SEEN: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    fn record(pid: u32) {
        SEEN.lock().expect("lock").push(pid);
    }
    let registry: Registry<4> = Registry::new();
    let first = registry.reserve().expect("slot");
    registry.set(first, 4242);
    let _reserved_only = registry.reserve().expect("slot");
    assert_eq!(registry.live(), 2);
    registry.kill_all(record);
    assert_eq!(*SEEN.lock().expect("lock"), vec![4242]);
}

#[test]
fn the_defaults_match_the_design() {
    assert_eq!(REAP_GRACE, Duration::from_secs(1));
    assert_eq!(DEFAULT_STDOUT_CAP, 1024 * 1024);
    assert_eq!(DEFAULT_STDERR_CAP, 64 * 1024);
    assert_eq!(KILLS_PROCESS_TREE, cfg!(unix));
}

#[cfg(unix)]
mod process {
    use std::path::Path;
    use std::sync::Arc;
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
        let Some(pid) = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        else {
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
    async fn a_missing_program_is_a_spawn_error_and_frees_the_slot() {
        static OWN: Registry<REGISTRY_SLOTS> = Registry::new();
        let error = run_with(
            ExecSpec::new("/nonexistent/rdy-test", SECOND),
            &OWN,
            kill_group,
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
        let error = run(forks_sleeper(&pid_file, Duration::from_millis(400)))
            .await
            .expect_err("times out");
        assert!(matches!(error, ExecError::Timeout), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
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
        // The sleeper's output is detached, so the command ends as soon as the shell does.
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
    async fn killing_the_registered_groups_ends_a_running_command() {
        use std::os::unix::process::ExitStatusExt;
        static OWN: Registry<REGISTRY_SLOTS> = Registry::new();
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        let spec = forks_sleeper(&pid_file, Duration::from_secs(600));
        let task = tokio::spawn(run_with(spec, &OWN, kill_group, REAP_GRACE));
        let sleeper = read_pid(&pid_file, Duration::from_secs(5)).await;
        OWN.kill_all(kill_group);
        let out = task.await.expect("joins").expect("ends with a status");
        assert_eq!(out.status.signal(), Some(9));
        wait_gone(sleeper).await;
        assert_eq!(OWN.live(), 0);
    }

    #[tokio::test]
    async fn a_child_that_survives_sigkill_returns_hung_within_the_grace() {
        fn no_kill(_pid: u32) {}
        // Its own registry, so other tests running in parallel do not change the counts.
        static OWN: Registry<REGISTRY_SLOTS> = Registry::new();
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("sleeper.pid");
        let spec = forks_sleeper(&pid_file, Duration::from_millis(200));
        let started = Instant::now();
        // The kill function does nothing, so the child outlives the "SIGKILL" like a process stuck in
        // the kernel would.
        let error = run_with(spec, &OWN, no_kill, REAP_GRACE)
            .await
            .expect_err("hung");
        let took = started.elapsed();
        let ExecError::Hung { pid } = error else {
            panic!("expected Hung, got {error:?}");
        };
        // 200 ms of run, then at most the one second grace, plus slack for a slow machine.
        assert!(took < Duration::from_millis(2500), "took {took:?}");
        assert!(
            took >= Duration::from_millis(1100),
            "returned early: {took:?}"
        );
        // The slot stays in the registry until the child is reaped.
        assert_eq!(OWN.live(), 1);

        // Clean up for real: kill the group, and the detached reaper then frees the slot.
        kill_group(pid);
        let sleeper = read_pid(&pid_file, SECOND).await;
        wait_gone(sleeper).await;
        let start = Instant::now();
        while OWN.live() > 0 {
            assert!(start.elapsed() < Duration::from_secs(5), "slot never freed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
        let planned = Planned::new(check, "fake.exec").with_timeout(Duration::from_millis(500));
        let started = Instant::now();
        let ran = scheduler.run(vec![planned]).await;
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(
            matches!(ran[0].end, End::TimedOut { .. }),
            "{:?}",
            ran[0].end
        );
        let sleeper = read_pid(&pid_file, SECOND).await;
        wait_gone(sleeper).await;
    }
}
