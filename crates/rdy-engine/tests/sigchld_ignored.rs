//! Process-level test for M1-038: the runner works when `rdy` starts with `SIGCHLD` ignored.
//!
//! With `SIGCHLD` ignored the kernel reaps every child at its exit, so there is no zombie to hold the
//! process group id and a later group kill could hit an unrelated group. The runner registers a
//! `SIGCHLD` handler before it starts a child, which replaces the ignore. This test starts a copy of
//! itself through `bash -c 'trap "" CHLD; exec ...'` so the ignore is inherited, and checks that exit
//! status, output, timeout and group kill all still work.
#![cfg(all(unix, feature = "runtime"))]
// These tests drive the raw runner on purpose; a check never may (root clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::error::Error;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use rdy_engine::exec::{self, ExecError, ExecSpec};

const CHILD_ENV: &str = "RDY_SIGCHLD_IGNORED_PID_FILE";
const HARD_LIMIT: Duration = Duration::from_secs(60);

/// The child role. It does nothing unless the parent set the env var.
#[test]
fn sigchld_child() {
    let Ok(pid_file) = std::env::var(CHILD_ENV) else {
        return;
    };
    // Prove the set-up: on Linux the ignored-signals mask has the SIGCHLD bit (signal 17).
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").expect("status");
        let mask = status
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .map(str::trim)
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .expect("SigIgn line");
        assert!(mask & (1 << 16) != 0, "SIGCHLD is not ignored: {mask:x}");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        // A child that exits at once still gives its real status and output.
        let spec =
            ExecSpec::new("/bin/sh", Duration::from_secs(20)).args(["-c", "echo hi; exit 3"]);
        let out = exec::run(spec).await.expect("the status is reported");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"hi\n");

        // A timeout still kills the group.
        let spec = ExecSpec::new("/bin/sh", Duration::from_secs(2)).args([
            "-c",
            "sleep 600 & echo $! > \"$0\"; wait",
            pid_file.as_str(),
        ]);
        let error = exec::run(spec).await.expect_err("times out");
        assert!(matches!(error, ExecError::Timeout), "{error:?}");
        let sleeper: u32 = std::fs::read_to_string(&pid_file)
            .expect("pid file")
            .trim()
            .parse()
            .expect("pid");
        let start = Instant::now();
        while !is_gone(sleeper) {
            assert!(start.elapsed() < Duration::from_secs(5), "sleeper alive");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

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
    // A zombie that nothing has reaped yet is gone for our purposes.
    std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero()))
        .ok()
        .and_then(|stat| stat.rsplit(')').next().map(str::to_owned))
        .is_some_and(|rest| rest.trim_start().starts_with('Z'))
}

fn wait_gone(path: &Path) -> Result<(), Box<dyn Error>> {
    let pid: u32 = std::fs::read_to_string(path)?.trim().parse()?;
    let start = Instant::now();
    while !is_gone(pid) {
        if start.elapsed() > Duration::from_secs(5) {
            return Err(format!("process {pid} is still alive").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
fn the_runner_works_when_sigchld_is_ignored() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let pid_file = dir.path().join("sleeper.pid");
    // dash does not really ignore SIGCHLD for `trap '' CHLD`, so this needs bash. Linux and macOS
    // both have it. Without it the test says so and passes.
    let Some(bash) = ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .find(|path| Path::new(path).exists())
    else {
        eprintln!("skipped: no bash to ignore SIGCHLD with");
        return Ok(());
    };
    // `$0` is the test binary and `$@` the test arguments. The ignore is inherited across `exec`.
    let mut child = Command::new(bash)
        .args([
            "-c",
            "trap '' CHLD; exec \"$0\" \"$@\"",
            std::env::current_exe()?
                .to_str()
                .ok_or("non-utf-8 test binary path")?,
            "sigchld_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, &pid_file)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > HARD_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("the child run was still going after {HARD_LIMIT:?}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "the child run ended with {status}");
    wait_gone(&pid_file)
}
