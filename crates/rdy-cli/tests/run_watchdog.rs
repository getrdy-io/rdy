//! The watchdog in `rdy run` (M1-176, 02 "Watchdog", 07 section 5.2), proved at the process level.
//!
//! The shipped `rdy` cannot be steered (ADR 0011 decision 4): it has the real families and a five
//! minute deadline, so it has no check that hangs and no way to make the deadline short. So the test
//! binary runs itself. In the parent role it starts a copy of itself with an env var set and watches
//! it from outside. In the child role it does what `main` does: it runs `rdy_cli::run` on the process
//! streams with a one second deadline and the families of the scenario, then exits with the code. The
//! watchdog is the real one, with the real effects (kill the groups, write the notice, exit 70).
//!
//! Two scenarios, each ending in exit 70 inside the deadline plus 22 s (02), with a report whose
//! `complete` is false in the report folder:
//!
//! - `spin`: a check that never yields on the run's single-threaded runtime, so the scheduler's own
//!   timers can never fire, and (on Unix) a second check with a live `sleep` process group.
//! - `pipe`: a `--json` run whose stdout is a pipe nobody reads, with a report bigger than the pipe.
//!
//! The upper bound is an upper bound only, so a slow machine cannot make the test flaky.

use std::error::Error;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdy_cli::RunHooks;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, OsSupport, Support,
};
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

mod common;

const CHILD_ENV: &str = "RDY_RUN_WATCHDOG_CHILD";
const DIR_ENV: &str = "RDY_RUN_WATCHDOG_DIR";
/// The spin run gets time to start its sleeper before the runtime is stuck, even on a slow leg.
const SPIN_DEADLINE: Duration = Duration::from_secs(5);
/// The pipe run has nothing to wait for.
const PIPE_DEADLINE: Duration = Duration::from_secs(1);
/// A secret in the message of the pipe run's check. It must not reach the report or the pipe.
const CANARY: &str = "canary-watchdog-pipe-9";
/// The watchdog fires this long after the deadline (M1-043).
const GRACE: Duration = Duration::from_secs(10);
/// 02: the worst case from the deadline.
const EXIT_BOUND: Duration = Duration::from_secs(22);
const HARD_LIMIT: Duration = Duration::from_secs(60);

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

const fn info(id: &'static str) -> CheckInfo {
    CheckInfo {
        id,
        family: "host",
        summary: "A test check.",
        meta: CheckMeta {
            title: "Test",
            remediation: "Nothing to fix. This check is a test double.",
        },
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: FULL,
        reads: &[],
        statfs: &[],
        env: &[],
        commands: &[],
        peers: &[],
    }
}

static CPU: CheckInfo = info("host.cpu");
static MEMORY: CheckInfo = info("host.memory");
static DISK: CheckInfo = info("host.disk");
static LIST: [&CheckInfo; 3] = [&CPU, &MEMORY, &DISK];

fn work_dir() -> PathBuf {
    std::env::var_os(DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// `host.cpu`: passes at once, with a report entry far bigger than a pipe buffer when `loud`.
struct Quick {
    loud: bool,
}

impl Check for Quick {
    fn info(&self) -> &'static CheckInfo {
        &CPU
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let mut finding = Finding::pass("4 CPUs");
            if self.loud {
                finding = Finding::pass(format!("4 CPUs, password={CANARY}"));
                // 60 keys of 2 KiB each: about 120 KiB, past the 64 KiB of a Linux pipe.
                let words = "alpha beta gamma delta ".repeat(90);
                let observed: serde_json::Map<String, serde_json::Value> = (0..60)
                    .map(|n| {
                        (
                            format!("key_{n:02}"),
                            serde_json::Value::from(words.clone()),
                        )
                    })
                    .collect();
                finding = finding.with_observed(serde_json::Value::Object(observed));
            }
            Ok(finding)
        })
    }
}

/// `host.disk`: holds its thread for good. On Unix it first waits, yielding, for the pid file of the
/// sleeper, so the process group exists before the runtime is stuck.
struct Spin;

impl Check for Spin {
    fn info(&self) -> &'static CheckInfo {
        &DISK
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let pid_file = work_dir().join("sleeper.pid");
            while cfg!(unix) && !pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            loop {
                std::hint::spin_loop();
            }
        })
    }
}

/// `host.memory`: forks `sleep 600` in its own process group and waits for it.
struct Sleeper;

impl Check for Sleeper {
    fn info(&self) -> &'static CheckInfo {
        &MEMORY
    }

    #[cfg(unix)]
    #[allow(clippy::disallowed_methods)] // a test double: it needs a live group and no policy
    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        use rdy_engine::exec::{self, ExecSpec};
        Box::pin(async move {
            let pid_file = work_dir().join("sleeper.pid");
            let spec = ExecSpec::new("/bin/sh", Duration::from_secs(600)).args([
                "-c",
                // The shell's own pid is the group id. The pid file comes last: the spin check waits for it.
                "echo $$ > \"$0.pgid\"; sleep 600 & echo $! > \"$0\"; wait",
                &pid_file.to_string_lossy(),
            ]);
            let _ = exec::run(spec).await;
            Ok(Finding::pass("done"))
        })
    }

    #[cfg(not(unix))]
    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async { Ok(Finding::pass("done")) })
    }
}

struct Doubles {
    loud: bool,
}

impl Family for Doubles {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &LIST
    }

    fn build(&self, entry: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        let check: Box<dyn Check> = match entry.id.as_str() {
            "host.memory" => Box::new(Sleeper),
            "host.disk" => Box::new(Spin),
            _ => Box::new(Quick { loud: self.loud }),
        };
        Ok(Built::new(check))
    }
}

fn spin_families() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Doubles { loud: false })?;
    Ok(registry)
}

fn pipe_families() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Doubles { loud: true })?;
    Ok(registry)
}

const SPIN_SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n  - id: host.memory\n    min: 1Gi\n  - id: host.disk\n    path: /\n    min: 1Gi\n";
const PIPE_SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n";

/// The child role. It does nothing unless the parent set the env var.
#[test]
fn run_watchdog_child() {
    let Ok(scenario) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = work_dir();
    let (families, json, deadline): (rdy_cli::FamiliesFn, bool, Duration) = match scenario.as_str()
    {
        "spin" => (spin_families, false, SPIN_DEADLINE),
        "pipe" => (pipe_families, true, PIPE_DEADLINE),
        other => panic!("unknown scenario {other}"),
    };
    let spec = dir.join("spec.yaml");
    let out = dir.join("out");
    let mut args = vec![
        "rdy".to_owned(),
        "run".to_owned(),
        spec.to_string_lossy().into_owned(),
        "--allow-unsigned".to_owned(),
        "--out-dir".to_owned(),
        out.to_string_lossy().into_owned(),
    ];
    if json {
        args.push("--json".to_owned());
    }
    let mut hooks = RunHooks::default();
    hooks.families = Some(families);
    hooks.deadline = Some(deadline);
    // What `main` does: a single-threaded runtime, the process streams, then the exit code. The watchdog
    // is the one the command starts, with the real effects.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let code = runtime
        .block_on(rdy_cli::run(
            args,
            Arc::new(common::unprivileged()),
            hooks,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        ))
        .code();
    std::process::exit(i32::from(code));
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

struct Outcome {
    status: std::process::ExitStatus,
    took: Duration,
    deadline: Duration,
    // Read on Unix only (the notice text assert).
    #[cfg_attr(not(unix), allow(dead_code))]
    stderr: String,
    stdout: String,
    dir: tempfile::TempDir,
}

/// Starts the child, never reads its stdout until it is gone, and waits for it.
fn run_child(scenario: &str, spec: &str, deadline: Duration) -> Result<Outcome, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::create_dir(dir.path().join("out"))?;
    std::fs::write(dir.path().join("spec.yaml"), spec)?;
    let started = Instant::now();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "run_watchdog_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, scenario)
        .env(DIR_ENV, dir.path())
        .env_remove("RUST_LOG")
        // Piped and not read until the child is gone: its stdout fills up and blocks.
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
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let mut raw = Vec::new();
        pipe.read_to_end(&mut raw)?;
        stderr = String::from_utf8_lossy(&common::without_fd_warning(&raw)).into_owned();
    }
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let mut raw = Vec::new();
        pipe.read_to_end(&mut raw)?;
        stdout = String::from_utf8_lossy(&raw).into_owned();
    }
    Ok(Outcome {
        status,
        took,
        deadline,
        stderr,
        stdout,
        dir,
    })
}

fn assert_ended_by_the_watchdog(outcome: &Outcome) {
    let deadline = outcome.deadline;
    assert_eq!(outcome.status.code(), Some(70), "{:?}", outcome.status);
    assert!(
        outcome.took < deadline + EXIT_BOUND,
        "took {:?} for a {deadline:?} deadline",
        outcome.took
    );
    assert!(
        outcome.took >= deadline + GRACE,
        "the watchdog fires at the deadline plus 10 s, not at {:?}",
        outcome.took
    );
    #[cfg(unix)]
    {
        assert!(
            outcome
                .stderr
                .contains("error: the run did not finish, so rdy stopped itself."),
            "stderr: {}",
            outcome.stderr
        );
        assert!(
            outcome
                .stderr
                .contains("\nfix: run it again and tell the vendor which check was running.\n"),
            "stderr: {}",
            outcome.stderr
        );
    }
}

fn read_partial(outcome: &Outcome) -> Result<serde_json::Value, Box<dyn Error>> {
    let out = outcome.dir.path().join("out");
    let report = find_report(&out)?;
    let folder = report.parent().ok_or("no folder")?;
    assert!(folder.join("spec.yaml").is_file(), "no spec copy");
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report)?)?;
    assert_eq!(doc["kind"], "Report");
    assert_eq!(
        doc["complete"], false,
        "the watchdog's report is incomplete"
    );
    Ok(doc)
}

fn status_of<'a>(doc: &'a serde_json::Value, id: &str) -> Result<&'a str, Box<dyn Error>> {
    doc["checks"]
        .as_array()
        .ok_or("no checks")?
        .iter()
        .find(|check| check["id"] == id)
        .and_then(|check| check["status"].as_str())
        .ok_or_else(|| format!("no check {id}").into())
}

#[test]
fn a_check_that_never_yields_ends_in_exit_70_with_an_incomplete_report_and_no_child_left()
-> Result<(), Box<dyn Error>> {
    let outcome = run_child("spin", SPIN_SPEC, SPIN_DEADLINE)?;
    assert_ended_by_the_watchdog(&outcome);
    let doc = read_partial(&outcome)?;
    let checks = doc["checks"].as_array().ok_or("no checks")?;
    assert_eq!(checks.len(), 3);
    // The one that spins is a timeout. The quick one finished, but the scheduler task that tells the
    // board is on the same single thread as the spinner, so the spinner can start first and the quick
    // one still counts as running. On Windows that is always so: with no sleeper to wait for, the spinner
    // starts at once and `host.cpu` is always a timeout. Either is a correct snapshot; a finished result
    // being kept is proved in the pipe run below and in the engine tests.
    let cpu = status_of(&doc, "host.cpu")?;
    assert!(cpu == "pass" || cpu == "timeout", "{cpu}");
    assert_eq!(status_of(&doc, "host.disk")?, "timeout");
    #[cfg(unix)]
    {
        assert_eq!(status_of(&doc, "host.memory")?, "timeout");
        gone::wait_gone(&outcome.dir.path().join("sleeper.pid"))?;
    }
    Ok(())
}

#[test]
fn a_json_run_into_a_pipe_nobody_reads_ends_in_exit_70_with_an_incomplete_report()
-> Result<(), Box<dyn Error>> {
    let outcome = run_child("pipe", PIPE_SPEC, PIPE_DEADLINE)?;
    assert_ended_by_the_watchdog(&outcome);
    // The pipe really was full: the child wrote until it blocked. (A Windows pipe buffer is smaller and
    // its blocking differs, so the size is checked on Unix only.)
    #[cfg(unix)]
    assert!(
        outcome.stdout.len() >= 16 * 1024,
        "only {} bytes reached the pipe",
        outcome.stdout.len()
    );
    let doc = read_partial(&outcome)?;
    // The run itself had finished, so the check has its real result, in a report marked incomplete.
    assert_eq!(status_of(&doc, "host.cpu")?, "pass");
    // The secret in the check's message was hidden when the result was kept, is hidden in the partial
    // report, and never reached the pipe or the file.
    let report = find_report(&outcome.dir.path().join("out"))?;
    let raw = std::fs::read_to_string(report)?;
    assert!(!raw.contains(CANARY), "the secret is in the partial report");
    assert!(
        !outcome.stdout.contains(CANARY),
        "the secret reached the pipe"
    );
    assert!(
        doc["redaction"]["total"].as_u64().unwrap_or(0) > 0,
        "the redaction counts are lost: {}",
        doc["redaction"]
    );
    Ok(())
}

/// Whether the sleeper and its group are gone.
#[cfg(unix)]
mod gone {
    use std::error::Error;
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// The state letter and group of a process, from `/proc/<pid>/stat`. Linux only.
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

    pub fn wait_gone(pid_file: &Path) -> Result<(), Box<dyn Error>> {
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
