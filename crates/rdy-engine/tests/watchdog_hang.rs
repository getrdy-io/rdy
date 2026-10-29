//! Process-level test for M1-043: a run that hangs for real still ends with a report and exit 70.
//!
//! The test binary runs itself. In the parent role it starts a copy of itself with an env var set,
//! and never reads the copy's stdout. In the child role (`watchdog_hang_child`) it plays the part of
//! `rdy`:
//!
//! - two checks spin on a two-worker runtime, so the scheduler's own timers can never fire;
//! - a thread writes to stdout until the pipe is full and then blocks, holding std's stdout lock;
//! - a thread holds the run board's lock for good;
//! - on Unix, a third check forks `sleep 600`, so there is a live process group to kill.
//!
//! Only the watchdog is left to end the run. The parent asserts exit 70, a report with `complete:
//! false` that holds none of the canaries planted in the base report and a template, and the time bound
//! of 02 (deadline plus 22 s). On Unix it also asserts the fixed stderr text and that nothing of the
//! process group is left. The rest runs on every target. The time bound is an upper bound only, so a
//! slow machine cannot make it flaky.
#![cfg(feature = "runtime")]

use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Need, OsSupport, Support,
    current_os,
};
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

/// Secrets in the parts of the report that nothing redacted before the watchdog did.
const HOST_CANARY: &str = "canary-host-pw-1";
const USER_CANARY: &str = "canary-user-tok-2";
const NAME_CANARY: &str = "canary-name-pw-3";

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

/// Holds its worker for good. On Unix it first waits, by sleeping so the exec check can run, for the
/// sleeper's pid file.
struct SpinCheck {
    pid_file: PathBuf,
}

impl Check for SpinCheck {
    fn info(&self) -> &'static CheckInfo {
        &FAKE
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            while cfg!(unix) && !self.pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            loop {
                std::hint::spin_loop();
            }
        })
    }
}

// The test starts a shell with the raw runner on purpose: it needs a live process group and no policy
// in the way (as in `exit_bound.rs`).
#[cfg(unix)]
#[allow(clippy::disallowed_methods)]
mod unix_only {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use rdy_engine::check::{
        BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckOutcome, Finding,
    };
    use rdy_engine::exec::{self, ExecSpec};

    /// Forks `sleep 600` and waits for it. The shell writes its own pid (the group id) first and
    /// the sleeper's pid second, which is what the spinning checks wait for.
    pub struct ExecCheck {
        pub pid_file: PathBuf,
    }

    impl Check for ExecCheck {
        fn info(&self) -> &'static CheckInfo {
            &super::FAKE
        }

        fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
            Box::pin(async move {
                let spec = ExecSpec::new("/bin/sh", Duration::from_secs(600)).args([
                    "-c",
                    "echo $$ > \"$0.pgid\"; sleep 600 & echo $! > \"$0\"; wait",
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

    /// The state letter of a process and its group, from `/proc/<pid>/stat`. Linux only.
    fn proc_state(pid: &str) -> Option<(char, u32)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = stat.rsplit(')').next()?;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.chars().next()?;
        let _ppid = fields.next()?;
        Some((state, fields.next()?.parse().ok()?))
    }

    fn is_gone(pid: u32) -> bool {
        let Some(raw) = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        else {
            return true;
        };
        if rustix::process::test_kill_process(raw).is_err() {
            return true;
        }
        // A zombie that nothing has reaped yet is gone for our purposes.
        proc_state(&pid.to_string()).is_some_and(|(state, _)| state == 'Z')
    }

    /// No live process in the group. On Linux, zombies do not count. Elsewhere, a signal to the
    /// group that finds nobody.
    fn group_gone(pgid: u32) -> bool {
        if Path::new("/proc/self/stat").exists() {
            let Ok(entries) = std::fs::read_dir("/proc") else {
                return false;
            };
            return !entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.bytes().all(|b| b.is_ascii_digit()))
                .filter_map(|name| proc_state(&name))
                .any(|(state, group)| group == pgid && state != 'Z');
        }
        i32::try_from(pgid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .is_none_or(|pid| rustix::process::test_kill_process_group(pid).is_err())
    }

    pub fn wait_gone(pid_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let pid: u32 = std::fs::read_to_string(pid_file)?.trim().parse()?;
        let pgid: u32 = std::fs::read_to_string(format!("{}.pgid", pid_file.display()))?
            .trim()
            .parse()?;
        let start = Instant::now();
        while !(is_gone(pid) && group_gone(pgid)) {
            if start.elapsed() > Duration::from_secs(5) {
                return Err(format!("process {pid} or its group {pgid} is still alive").into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
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
        Host::new(
            format!("build-01 password={HOST_CANARY}"),
            HostOs::new(HostOsFamily::Linux),
            "x86_64",
        ),
        Identity::new(Some(1000), Some(format!("ada token={USER_CANARY}")), false),
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
    // The one origin of the run, for the watchdog and the scheduler alike.
    let origin = Instant::now();
    let dir = PathBuf::from(dir);
    let pid_file = dir.join("sleeper.pid");
    let out_parent = dir.join("out");
    let redactor = Redactor::new(TagKey::fixed([3; 32]));
    let out = Arc::new(OutputDir::create_new(&out_parent, "acme", TS).expect("output dir"));

    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut ids = vec!["host.spin_a", "host.spin_b"];
    #[cfg(unix)]
    ids.insert(0, "host.exec");
    let templates: Vec<CheckResult> = ids
        .iter()
        .map(|id| {
            let mut template = CheckResult::new(*id, "host", Severity::Block, Status::Pass);
            template.name = Some(format!("primary password={NAME_CANARY}"));
            template
        })
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
    let watchdog = Watchdog::start(WatchdogConfig::new(
        origin,
        DEADLINE,
        state,
        redactor.clone(),
    ))
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
        while cfg!(unix) && !held.exists() {
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
    let scheduler = Scheduler::new(3, current_os(), std::iter::empty::<Need>())
        .with_deadline(DEADLINE)
        .with_origin(origin);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut planned = vec![
        Planned::new(
            Arc::new(SpinCheck {
                pid_file: pid_file.clone(),
            }),
            "host.spin_a",
        ),
        Planned::new(Arc::new(SpinCheck { pid_file }), "host.spin_b"),
    ];
    #[cfg(unix)]
    planned.insert(
        0,
        Planned::new(
            Arc::new(unix_only::ExecCheck {
                pid_file: dir.join("sleeper.pid"),
            }),
            "host.exec",
        ),
    );
    let observer: Arc<dyn Observer> = board;
    let _run = runtime.spawn(async move { scheduler.run_observed(planned, observer).await });

    // The CLI would wait here. Nothing the run does can end it: only the watchdog can.
    let never = AtomicBool::new(false);
    while !never.load(Ordering::Relaxed) {
        std::thread::park();
    }
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

    let raw = std::fs::read_to_string(find_report(&dir.path().join("out"))?)?;
    for canary in [HOST_CANARY, USER_CANARY, NAME_CANARY] {
        assert!(!raw.contains(canary), "{canary} is in the report");
    }
    let report: serde_json::Value = serde_json::from_str(&raw)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["kind"], "Report");
    let expected_checks = if cfg!(unix) { 3 } else { 2 };
    let checks = report["checks"].as_array().ok_or("no checks")?;
    assert_eq!(checks.len(), expected_checks);
    // The board's lock was held, so the watchdog had no results to read: every check is unfinished.
    assert!(checks.iter().all(|check| check["status"] == "error"));
    assert_eq!(report["verdict"], "not_ready");
    // The watchdog's own pass hid the planted secrets: host, user and one name per check.
    let hidden = report["redaction"]["total"].as_u64().unwrap_or(0);
    assert!(hidden >= 2 + expected_checks as u64, "{hidden}");

    #[cfg(unix)]
    {
        use std::io::Read;

        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            pipe.read_to_string(&mut stderr)?;
        }
        assert!(
            stderr.starts_with("error: the run did not finish, so rdy stopped itself."),
            "stderr: {stderr}"
        );
        assert!(
            stderr.contains("\nfix: run it again and tell the vendor which check was running.\n"),
            "stderr: {stderr}"
        );
        unix_only::wait_gone(&dir.path().join("sleeper.pid"))?;
    }
    Ok(())
}
