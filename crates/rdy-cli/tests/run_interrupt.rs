//! Ctrl-C, SIGINT and SIGTERM during `rdy run` (M1-058, 07 section 5.1), proved at the process level.
//!
//! The shipped `rdy` cannot be steered (ADR 0011 decision 4), so, as in `run_watchdog.rs`, the test
//! binary runs itself. The child role does what `main` does: it starts a `Rig`, starts the signal thread
//! (`Rig::watch_signals`), and runs `rdy_cli::run_watched` with the families of the scenario: a check
//! that holds a live `sleep` process group and a check that never ends. The parent role waits for the
//! sleeper, sends the signal once from outside and looks at what is left.
//!
//! The child's report folder has been made by then and holds nothing, so it must be gone. The terminal
//! side (a password prompt on a pty, echo back on) is in `interrupt_pty.rs`.
#![cfg(unix)]
// Helper functions in tests/ are not covered by clippy.toml.
#![allow(clippy::expect_used)]

use std::error::Error;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdy_cli::{Rig, RunHooks};
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, OsSupport, Support,
};
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};
use rustix::process::{Pid, Signal};

mod common;

const CHILD_ENV: &str = "RDY_RUN_INTERRUPT_CHILD";
const DIR_ENV: &str = "RDY_RUN_INTERRUPT_DIR";
const UNSIGNED: &str =
    "warning: this spec is not signed. rdy cannot tell who wrote it or if it was changed.\n";
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

static MEMORY: CheckInfo = info("host.memory");
static DISK: CheckInfo = info("host.disk");
static LIST: [&CheckInfo; 2] = [&MEMORY, &DISK];

fn work_dir() -> PathBuf {
    std::env::var_os(DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// `host.memory`: starts `sleep 600` in its own process group and waits for it.
struct Sleeper;

impl Check for Sleeper {
    fn info(&self) -> &'static CheckInfo {
        &MEMORY
    }

    #[allow(clippy::disallowed_methods)] // a test double: it needs a live group and no policy
    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        use rdy_engine::exec::{self, ExecSpec};
        Box::pin(async move {
            let pid_file = work_dir().join("sleeper.pid");
            let spec = ExecSpec::new("/bin/sh", Duration::from_secs(600)).args([
                "-c",
                // The shell's own pid is the group id. The pid file comes last: the parent waits for it. Both are
                // written to a temp name and moved into place, so a reader never sees half a number.
                "echo $$ > \"$0.pgid.tmp\" && mv \"$0.pgid.tmp\" \"$0.pgid\"; sleep 600 & echo $! > \"$0.tmp\" && mv \"$0.tmp\" \"$0\"; wait",
                &pid_file.to_string_lossy(),
            ]);
            let _ = exec::run(spec).await;
            Ok(Finding::pass("done"))
        })
    }
}

/// `host.disk`: never ends, and yields, so the run is plainly "in the middle of the checks".
struct Forever;

impl Check for Forever {
    fn info(&self) -> &'static CheckInfo {
        &DISK
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            std::future::pending::<()>().await;
            Ok(Finding::pass("never"))
        })
    }
}

struct Doubles;

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
            _ => Box::new(Forever),
        };
        Ok(Built::new(check))
    }
}

fn families() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Doubles)?;
    Ok(registry)
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.memory\n    min: 1Gi\n  - id: host.disk\n    path: /\n    min: 1Gi\n";

/// The child role. It does nothing unless the parent set the env var.
#[test]
fn run_interrupt_child() {
    let Ok(scenario) = std::env::var(CHILD_ENV) else {
        return;
    };
    let json = scenario == "json";
    let dir = work_dir();
    let args = vec![
        "rdy".to_owned(),
        "run".to_owned(),
        dir.join("spec.yaml").to_string_lossy().into_owned(),
        "--allow-unsigned".to_owned(),
        "--out-dir".to_owned(),
        dir.join("out").to_string_lossy().into_owned(),
    ]
    .into_iter()
    .chain(json.then(|| "--json".to_owned()))
    .collect::<Vec<_>>();
    let mut hooks = RunHooks::default();
    hooks.families = Some(families);
    let rig = Rig::start(Instant::now(), Duration::from_secs(300)).expect("rig");
    rig.watch_signals(json).expect("signal thread");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let code = runtime
        .block_on(rdy_cli::run_watched(
            args,
            Arc::new(common::unprivileged()),
            hooks,
            rig.clone(),
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        ))
        .code();
    // What `main` does at the end: a signal that took over has the last word on the exit code.
    rig.claim_exit();
    std::process::exit(i32::from(code));
}

struct Outcome {
    status: std::process::ExitStatus,
    stderr: String,
    stdout: String,
    dir: tempfile::TempDir,
}

fn pid_of(raw: u32) -> Pid {
    i32::try_from(raw)
        .ok()
        .and_then(Pid::from_raw)
        .expect("a valid pid")
}

/// Starts the child, waits until the sleeper runs, sends `signal` once and waits for the exit.
fn interrupt_child(scenario: &str, signal: Signal) -> Result<Outcome, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::create_dir(dir.path().join("out"))?;
    std::fs::write(dir.path().join("spec.yaml"), SPEC)?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "run_interrupt_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, scenario)
        .env(DIR_ENV, dir.path())
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    let pid_file = dir.path().join("sleeper.pid");
    while !pid_file.exists() {
        if started.elapsed() > HARD_LIMIT || child.try_wait()?.is_some() {
            let _ = child.kill();
            return Err("the sleeper never started".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // The folder is made before the first check, so it is there now, and empty.
    let folders = std::fs::read_dir(dir.path().join("out"))?.count();
    assert_eq!(
        folders, 1,
        "the report folder should exist before the signal"
    );
    rustix::process::kill_process(pid_of(child.id()), signal)?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > HARD_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("the child ignored the signal".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let read = |pipe: Option<&mut dyn Read>| -> Result<String, Box<dyn Error>> {
        let mut raw = Vec::new();
        if let Some(pipe) = pipe {
            pipe.read_to_end(&mut raw)?;
        }
        Ok(String::from_utf8_lossy(&common::without_fd_warning(&raw)).into_owned())
    };
    let stderr = read(child.stderr.as_mut().map(|p| p as &mut dyn Read))?;
    let stdout = read(child.stdout.as_mut().map(|p| p as &mut dyn Read))?;
    // libtest announces the child on stdout before the test runs. What follows is rdy's own.
    let stdout = match stdout.split_once("test run_interrupt_child ... ") {
        Some((_, rest)) => rest.to_owned(),
        None => stdout,
    };
    Ok(Outcome {
        status,
        stderr,
        stdout,
        dir,
    })
}

fn assert_interrupted_cleanly(outcome: &Outcome) -> Result<(), Box<dyn Error>> {
    assert_eq!(outcome.status.code(), Some(70), "{:?}", outcome.status);
    // The unsigned-spec warning comes first (the run had started); the two lines are the end of stderr.
    assert_eq!(
        outcome.stderr.strip_prefix(UNSIGNED),
        Some("error: interrupted. No report was written.\nfix: run rdy again and let it finish\n"),
        "{}",
        outcome.stderr
    );
    // No report folder and no file.
    assert_eq!(
        std::fs::read_dir(outcome.dir.path().join("out"))?.count(),
        0,
        "the empty report folder is still there"
    );
    gone::wait_gone(&outcome.dir.path().join("sleeper.pid"))?;
    Ok(())
}

/// The text scenario at a terminal: the Ctrl-C key (the byte 0x03 on a pty with the signal key on) makes
/// the terminal send SIGINT to the foreground group, as a person's Ctrl-C does. The terminal echoes
/// `^C`, and `error:` must start at column 0 after it (07 section 5.1).
#[test]
fn ctrl_c_at_a_terminal_aborts_with_the_two_lines_at_column_0_exit_70_no_folder_no_child_left()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::create_dir(dir.path().join("out"))?;
    std::fs::write(dir.path().join("spec.yaml"), SPEC)?;
    let mut cmd = Command::new("sh");
    // Echo on, as a login shell has it: rexpect starts its terminals with echo off.
    cmd.arg("-c")
        .arg("stty echo && exec \"$0\" \"$@\"")
        .arg(std::env::current_exe()?)
        .args([
            "run_interrupt_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "text")
        .env(DIR_ENV, dir.path())
        .env_remove("RUST_LOG");
    let mut session = rexpect::session::spawn_command(cmd, Some(30_000))
        .map_err(|e| format!("cannot start the child on a pty: {e:?}"))?;
    let started = Instant::now();
    let pid_file = dir.path().join("sleeper.pid");
    while !pid_file.exists() {
        if started.elapsed() > HARD_LIMIT {
            return Err("the sleeper never started".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(std::fs::read_dir(dir.path().join("out"))?.count(), 1);
    session
        .send_control('c')
        .map_err(|e| format!("cannot send Ctrl-C: {e:?}"))?;
    let seen = session
        .exp_eof()
        .map_err(|e| format!("the child did not end: {e:?}"))?;
    let status = session
        .process()
        .wait()
        .map_err(|e| format!("cannot wait: {e:?}"))?;
    assert!(
        matches!(status, rexpect::process::WaitStatus::Exited(_, 70)),
        "{status:?}: {seen:?}"
    );
    assert!(
        seen.contains(
            "^C\r\nerror: interrupted. No report was written.\r\nfix: run rdy again and let it finish\r\n"
        ),
        "error: must start at column 0 after the echoed ^C: {seen:?}"
    );
    assert_eq!(std::fs::read_dir(dir.path().join("out"))?.count(), 0);
    gone::wait_gone(&pid_file)?;
    Ok(())
}

#[test]
fn sigterm_does_the_same() -> Result<(), Box<dyn Error>> {
    let outcome = interrupt_child("text", Signal::TERM)?;
    assert_interrupted_cleanly(&outcome)?;
    assert_eq!(outcome.stdout, "");
    Ok(())
}

#[test]
fn with_json_stdout_is_an_error_output_with_code_interrupted() -> Result<(), Box<dyn Error>> {
    let outcome = interrupt_child("json", Signal::INT)?;
    assert_interrupted_cleanly(&outcome)?;
    let doc: serde_json::Value = serde_json::from_str(&outcome.stdout)?;
    assert_eq!(doc["api_version"], "rdy/v1");
    assert_eq!(doc["kind"], "Error");
    assert_eq!(doc["error"]["code"], "interrupted");
    assert_eq!(doc["complete"], false);
    Ok(())
}

/// Whether the sleeper and its group are gone.
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
