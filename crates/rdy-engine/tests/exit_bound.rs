//! Process-level test for M1-038: a timed-out command leaves nothing behind and the process exits
//! soon after the deadline.
//!
//! The test binary runs itself. In the parent role it starts a copy of itself with an env var set and
//! times it. In the child role (`exit_bound_child`) it plays the part of `rdy`: it runs a check that
//! forks `sleep 600`, waits for the scheduler's timeout, kills leftover groups and calls
//! `std::process::exit`, the way the CLI will. Timing is an upper bound only.
#![cfg(all(unix, feature = "runtime"))]
// These tests drive the raw runner on purpose; a check never may (root clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::error::Error;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Need,
    OsSupport, Support, current_os,
};
use rdy_engine::exec::{self, ExecSpec};
use rdy_engine::sched::{End, Planned, Scheduler};

const CHILD_ENV: &str = "RDY_EXIT_BOUND_PID_FILE";
const DEADLINE: Duration = Duration::from_secs(1);
const EXIT_BOUND: Duration = Duration::from_secs(2);
const HARD_LIMIT: Duration = Duration::from_secs(10);

static SCRIPT_CHECK: CheckInfo = CheckInfo {
    id: "fake.script",
    family: "fake",
    summary: "A fake check that runs a script which forks a long sleep.",
    meta: CheckMeta {
        title: "Fake check",
        remediation: "Nothing to fix. This check is a test double.",
    },
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

struct ScriptCheck {
    pid_file: String,
}

impl Check for ScriptCheck {
    fn info(&self) -> &'static CheckInfo {
        &SCRIPT_CHECK
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let spec = ExecSpec::new("/bin/sh", Duration::from_secs(600)).args([
                "-c",
                "sleep 600 & echo $! > \"$0\"; wait",
                self.pid_file.as_str(),
            ]);
            exec::run(spec).await.map_err(|error| CheckError::Failed {
                message: error.to_string(),
                hint: String::new(),
            })?;
            Ok(Finding::pass("done"))
        })
    }
}

/// The child role. It does nothing unless the parent set the env var.
#[test]
fn exit_bound_child() {
    let Ok(pid_file) = std::env::var(CHILD_ENV) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let scheduler = Scheduler::new(2, current_os(), std::iter::empty::<Need>());
    let planned =
        Planned::new(Arc::new(ScriptCheck { pid_file }), "fake.script").with_timeout(DEADLINE);
    let ran = runtime.block_on(scheduler.run(vec![planned]));
    let timed_out = matches!(ran[0].end, End::TimedOut { .. });
    // The normal exit path: kill what is left and exit without waiting for the runtime to drop.
    exec::kill_all_groups();
    std::process::exit(if timed_out { 0 } else { 3 });
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

fn wait_gone(pid: u32) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    while !is_gone(pid) {
        if start.elapsed() > Duration::from_secs(5) {
            return Err(format!("process {pid} is still alive").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn read_pid(path: &Path) -> Result<u32, Box<dyn Error>> {
    Ok(std::fs::read_to_string(path)?.trim().parse()?)
}

#[test]
fn a_timed_out_script_leaves_no_process_and_the_process_exits_in_time() -> Result<(), Box<dyn Error>>
{
    let dir = tempfile::tempdir()?;
    let pid_file = dir.path().join("sleeper.pid");
    let started = Instant::now();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "exit_bound_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, &pid_file)
        .spawn()?;
    // The test must not hang if the child does: poll, and kill it after a hard limit.
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
    let took = started.elapsed();
    assert!(status.success(), "the child run ended with {status}");
    assert!(
        took < DEADLINE + EXIT_BOUND,
        "the process took {took:?} for a {DEADLINE:?} deadline"
    );
    assert!(
        took >= DEADLINE,
        "the check cannot have timed out in {took:?}"
    );
    wait_gone(read_pid(&pid_file)?)
}
