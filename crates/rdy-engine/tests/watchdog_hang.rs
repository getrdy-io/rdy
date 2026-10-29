//! Process-level test for M1-043: a run that hangs for real still ends with a report and exit 70.
//!
//! The test binary runs itself. In the parent role it starts a copy of itself with an env var set,
//! and never reads the copy's stdout. In the child role (`watchdog_hang_child`) it plays the part of
//! `rdy`:
//!
//! - one check forks `sleep 600`, so there is a live process group to kill;
//! - two checks spin on a two-worker runtime, so the scheduler's own timers can never fire;
//! - a thread writes to stdout until the pipe is full and then blocks, holding std's stdout lock;
//! - a thread holds the run board's lock for good.
//!
//! Only the watchdog is left to end the run. The parent asserts exit 70, a report with `complete:
//! false`, the time bound of 02 (deadline plus 22 s) and that nothing of the process group is left.
//! The time bound is an upper bound only, so a slow machine cannot make it flaky.
#![cfg(all(unix, feature = "runtime"))]

use std::error::Error;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Need,
    OsSupport, Support, current_os,
};
use rdy_engine::exec::{self, ExecSpec};
use rdy_engine::outcome::timeout_result;
use rdy_engine::output::{OutputDir, ReportError};
use rdy_engine::redact::{RedactedReport, Redactor, TagKey};
use rdy_engine::sched::{End, Observer, Planned, Scheduler};
use rdy_engine::watchdog::{Board, ReportSink, Watchdog, WatchdogConfig, WriteState};
use rdy_spec::result::{
    CheckResult, Host, HostOs, HostOsFamily, Identity, Producer, Report, Run, RunOptions, Severity,
    Signature, SpecRef, Status,
};

const CHILD_ENV: &str = "RDY_WATCHDOG_HANG_DIR";
const DEADLINE: Duration = Duration::from_secs(1);
/// 02: the worst case from the deadline.
const EXIT_BOUND: Duration = Duration::from_secs(22);
const HARD_LIMIT: Duration = Duration::from_secs(60);
const TS: &str = "20270101T000000Z";

static FAKE: CheckInfo = CheckInfo {
    id: "fake.hang",
    family: "fake",
    summary: "A fake check that hangs.",
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

/// Forks `sleep 600` and waits for it.
struct ExecCheck {
    pid_file: PathBuf,
}

impl Check for ExecCheck {
    fn info(&self) -> &'static CheckInfo {
        &FAKE
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let spec = ExecSpec::new("/bin/sh", Duration::from_secs(600)).args([
                "-c",
                "sleep 600 & echo $! > \"$0\"; wait",
                &self.pid_file.to_string_lossy(),
            ]);
            exec::run(spec).await.map_err(|error| CheckError::Failed {
                message: error.to_string(),
                hint: String::new(),
            })?;
            Ok(Finding::pass("done"))
        })
    }
}

/// Holds its worker for good, once the sleeper's pid file exists.
struct SpinCheck {
    pid_file: PathBuf,
}

impl Check for SpinCheck {
    fn info(&self) -> &'static CheckInfo {
        &FAKE
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            while !self.pid_file.exists() {
                std::hint::spin_loop();
            }
            loop {
                std::hint::spin_loop();
            }
        })
    }
}

fn base_report() -> Report {
    Report::new(
        Producer::new("0.1.0", "0.1.0", "x86_64-unknown-linux-musl"),
        Run::new(
            "00000000-0000-4000-8000-000000000000",
            "2027-02-08T10:00:00.000Z",
            "2027-02-08T10:05:00.000Z",
            300_000,
            RunOptions::new(4, 1000),
        ),
        SpecRef::new("acme", "0".repeat(64), "spec.yaml", 10),
        Signature::unsigned(),
        Host::new("host.example", HostOs::new(HostOsFamily::Linux), "x86_64"),
        Identity::new(Some(1000), Some("ada".to_owned()), false),
        Vec::new(),
    )
}

/// Writes the JSON of the report into the held folder. The real writer (M1-055) will go through
/// `OutputDir::write_atomic`. Here the bytes of the already redacted report go straight to the file,
/// because redacting the JSON text a second time would eat the `pass` counter of the summary.
struct JsonSink {
    out: Arc<OutputDir>,
}

impl ReportSink for JsonSink {
    fn write(&self, report: &RedactedReport) -> Result<(), ReportError> {
        let json = serde_json::to_string(&**report).unwrap_or_default();
        let path = self.out.path().join(self.out.report_file_name("json"));
        std::fs::write(&path, json).map_err(|error| ReportError::Io {
            action: "write the test report",
            path,
            source: error,
        })
    }
}

/// The child role. It does nothing unless the parent set the env var.
#[test]
fn watchdog_hang_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let pid_file = dir.join("sleeper.pid");
    let out_parent = dir.join("out");
    let redactor = Redactor::new(TagKey::fixed([3; 32]));
    let out = Arc::new(OutputDir::create_new(&out_parent, "acme", TS).expect("output dir"));

    let templates: Vec<CheckResult> = ["host.exec", "host.spin_a", "host.spin_b"]
        .iter()
        .map(|id| CheckResult::new(*id, "host", Severity::Block, Status::Pass))
        .collect();
    let for_map = templates.clone();
    let board = Arc::new(Board::new(
        base_report(),
        templates,
        redactor.clone(),
        DEADLINE,
        Box::new(move |index, ran| match &ran.end {
            End::TimedOut { after } => timeout_result(&for_map[index], *after, ran.started),
            _ => for_map[index].clone(),
        }),
    ));

    let state = Arc::new(WriteState::new());
    let watchdog = Watchdog::start(WatchdogConfig::new(DEADLINE, state, redactor.clone()))
        .expect("watchdog thread");
    watchdog.arm(Arc::clone(&board), Arc::new(JsonSink { out }));

    // A blocked stdout: the parent never reads the pipe, so this thread stops in `write` while it
    // holds std's stdout lock. The watchdog must not need that lock.
    std::thread::spawn(|| {
        let mut stdout = std::io::stdout().lock();
        let chunk = [b'x'; 64 * 1024];
        loop {
            if stdout.write_all(&chunk).is_err() {
                return;
            }
        }
    });

    // A snapshot lock that nobody ever lets go of, once the checks are running.
    let holder = Arc::clone(&board);
    let held = pid_file.clone();
    std::thread::spawn(move || {
        while !held.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }
        let _hold = holder.hold_lock_for_test();
        loop {
            std::thread::park();
        }
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let scheduler =
        Scheduler::new(3, current_os(), std::iter::empty::<Need>()).with_deadline(DEADLINE);
    let planned = vec![
        Planned::new(
            Arc::new(ExecCheck {
                pid_file: pid_file.clone(),
            }),
            "host.exec",
        ),
        Planned::new(
            Arc::new(SpinCheck {
                pid_file: pid_file.clone(),
            }),
            "host.spin_a",
        ),
        Planned::new(Arc::new(SpinCheck { pid_file }), "host.spin_b"),
    ];
    let observer: Arc<dyn Observer> = board;
    let _run = runtime.spawn(async move { scheduler.run_observed(planned, observer).await });

    // The CLI would wait here. Nothing the run does can end it: only the watchdog can.
    let never = AtomicBool::new(false);
    while !never.load(Ordering::Relaxed) {
        std::thread::park();
    }
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

fn find_report(parent: &Path) -> Result<PathBuf, Box<dyn Error>> {
    for entry in std::fs::read_dir(parent)? {
        let folder = entry?.path();
        let json = folder.join(format!(
            "{}.json",
            folder.file_name().ok_or("no name")?.to_string_lossy()
        ));
        if json.is_file() {
            return Ok(json);
        }
    }
    Err("no report file in the output folder".into())
}

#[test]
fn a_hung_run_ends_with_an_incomplete_report_and_exit_70_inside_the_bound()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::create_dir(dir.path().join("out"))?;
    let started = Instant::now();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "watchdog_hang_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, dir.path())
        // Piped and never read until the child is gone: the child's stdout blocks.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > HARD_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("the child was still running after {HARD_LIMIT:?}").into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();

    assert_eq!(status.code(), Some(70), "exit status {status}");
    assert!(
        took < DEADLINE + EXIT_BOUND,
        "took {took:?} for a {DEADLINE:?} deadline"
    );
    assert!(
        took >= DEADLINE + Duration::from_secs(10),
        "the watchdog fires at the deadline plus 10 s, not at {took:?}"
    );

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)?;
    }
    assert!(stderr.contains("rdy stopped it"), "stderr: {stderr}");

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(find_report(&dir.path().join("out"))?)?)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["kind"], "Report");
    let checks = report["checks"].as_array().ok_or("no checks")?;
    assert_eq!(checks.len(), 3);
    // The board's lock was held, so the watchdog had no results to read: every check is unfinished.
    assert!(checks.iter().all(|check| check["status"] == "error"));
    assert_eq!(report["verdict"], "not_ready");

    let pid: u32 = std::fs::read_to_string(dir.path().join("sleeper.pid"))?
        .trim()
        .parse()?;
    wait_gone(pid)
}
