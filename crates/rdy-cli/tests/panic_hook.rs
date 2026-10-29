//! The panic hook and `guarded` (M1-056, ADR 0015 decision 6, 07 section 5).
//!
//! The hook is process-wide and must be seen on the real stderr, so the scenarios run in a child
//! process: this test binary, started again with `RDY_PANIC_CHILD` set. The parent checks the child's
//! exit code and that its stderr is empty. The default Rust text (`thread '...' panicked at`) and every
//! canary must be absent, because the hook prints nothing.

use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use rdy_cli::entry::guarded;
use rdy_cli::{logging, panic_hook, redaction};
use rdy_engine::redact::PANIC_TRIGGER;

const CHILD_VAR: &str = "RDY_PANIC_CHILD";

/// `guarded` with in-memory streams. Returns the code, stdout and stderr.
fn run_guarded(json: bool, f: impl FnOnce() -> u8) -> (u8, String, String) {
    ensure_log();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = guarded(json, &mut stdout, &mut stderr, |_, _| f());
    (
        code,
        String::from_utf8(stdout).unwrap_or_else(|e| panic!("stdout is not UTF-8: {e}")),
        String::from_utf8(stderr).unwrap_or_else(|e| panic!("stderr is not UTF-8: {e}")),
    )
}

fn assert_two_standard_lines(stderr: &str) {
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "want error and fix lines: {stderr}");
    assert_eq!(lines[0], "error: rdy hit an internal error");
    assert!(
        lines[1].starts_with("fix: this is a bug in rdy"),
        "{stderr}"
    );
    assert!(!stderr.contains("canary"), "{stderr}");
    assert!(!stderr.contains("panicked at"), "{stderr}");
}

#[test]
fn a_panic_outside_a_check_exits_70_with_the_two_standard_lines() {
    let (code, stdout, stderr) =
        run_guarded(false, || panic!("bad config password=canary-guard-1"));
    assert_eq!(code, 70);
    assert!(stdout.is_empty(), "{stdout}");
    assert_two_standard_lines(&stderr);
}

#[test]
fn a_panic_with_json_also_prints_an_error_object_on_stdout() {
    let (code, stdout, stderr) = run_guarded(true, || panic!("token=canary-guard-2"));
    assert_eq!(code, 70);
    assert_two_standard_lines(&stderr);
    assert!(!stdout.contains("canary"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON: {e}: {stdout}"));
    assert_eq!(value["error"]["code"], "internal", "{stdout}");
}

#[test]
fn a_closure_that_returns_keeps_its_code() {
    let (code, stdout, stderr) = run_guarded(true, || 2);
    assert_eq!((code, stdout.as_str(), stderr.as_str()), (2, "", ""));
}

#[test]
fn a_non_text_payload_is_the_same_error() {
    let (code, _, stderr) = run_guarded(false, || panic::panic_any(42_u8));
    assert_eq!(code, 70);
    assert_two_standard_lines(&stderr);
}

#[test]
fn a_panicking_redactor_behind_a_panic_still_exits_70() {
    // The panic text goes to the log with the trigger in it. The log writer's redaction panics, the
    // writer catches it and drops the event, and guarded still prints the two lines and returns 70.
    let (code, _, stderr) =
        run_guarded(false, || panic!("{PANIC_TRIGGER} password=canary-guard-3"));
    assert_eq!(code, 70);
    assert_two_standard_lines(&stderr);
    let logged = log_text();
    assert!(
        logged.contains("[REDACTED:redactor_error:00000000]"),
        "{logged}"
    );
    assert!(!logged.contains("canary-guard-3"), "{logged}");
}

/// What the process-wide log subscriber has written. The subscriber is global, not scoped: tests run in
/// parallel threads, and a scoped subscriber races with the callsite cache of `tracing`.
static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

fn ensure_log() -> &'static Arc<Mutex<Vec<u8>>> {
    LOG.get_or_init(|| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let make = {
            let log = Arc::clone(&log);
            move || LogSink(Arc::clone(&log))
        };
        let redactor = redaction::init()
            .unwrap_or_else(|e| panic!("the test host has a random source: {e}"))
            .clone();
        let subscriber = logging::subscriber(make, redactor, Some("trace"));
        tracing::subscriber::set_global_default(subscriber)
            .unwrap_or_else(|e| panic!("a global subscriber was already set: {e}"));
        log
    })
}

fn log_text() -> String {
    let log = ensure_log().lock().unwrap_or_else(|e| e.into_inner());
    String::from_utf8_lossy(&log).into_owned()
}

struct LogSink(Arc<Mutex<Vec<u8>>>);

impl Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The parent: runs `scenario` in a child and checks the child printed nothing to stderr.
fn in_child(scenario: &str) {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("no test binary path: {e}"));
    let out = Command::new(exe)
        .args([
            "--exact",
            "child_scenarios",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_VAR, scenario)
        .env_remove("RUST_LOG")
        .output()
        .unwrap_or_else(|e| panic!("the child did not start: {e}"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{scenario}: {stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!("scenario {scenario} done")),
        "{scenario} did not run: {stdout}"
    );
    assert_eq!(stderr.trim(), "", "{scenario}: the hook printed: {stderr}");
}

#[test]
fn the_hook_prints_nothing_for_a_panic_caught_in_the_same_thread() {
    in_child("caught");
}

#[test]
fn the_hook_prints_nothing_for_a_panic_in_a_joined_thread() {
    in_child("thread");
}

#[test]
fn the_hook_prints_nothing_for_a_panic_in_a_tokio_task() {
    in_child("tokio");
}

#[test]
fn the_hook_prints_nothing_for_a_panic_in_a_detached_thread() {
    in_child("detached");
}

#[test]
fn the_hook_prints_nothing_when_the_redactor_panics_inside_a_caught_panic() {
    in_child("redactor");
}

/// Not a test of its own: the body of each child scenario. It does nothing unless the parent set the
/// variable.
#[test]
fn child_scenarios() {
    let Ok(scenario) = std::env::var(CHILD_VAR) else {
        return;
    };
    let redactor = redaction::init()
        .unwrap_or_else(|e| panic!("the test host has a random source: {e}"))
        .clone();
    panic_hook::install();
    match scenario.as_str() {
        "caught" => {
            let caught =
                panic::catch_unwind(AssertUnwindSafe(|| panic!("password=canary-child-1")));
            assert!(caught.is_err());
            assert!(panic_hook::take_location().is_some_and(|at| at.contains("panic_hook.rs:")));
        }
        "thread" => {
            let joined = std::thread::spawn(|| panic!("token=canary-child-2")).join();
            assert!(joined.is_err());
        }
        "tokio" => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap_or_else(|e| panic!("no runtime: {e}"));
            let joined = rt
                .block_on(async { tokio::spawn(async { panic!("secret=canary-child-3") }).await });
            assert!(joined.is_err_and(|e| e.is_panic()));
        }
        "detached" => {
            let handle = std::thread::spawn(|| panic!("secret=canary-child-4"));
            // Wait for it to end without reading its result through the panic payload.
            while !handle.is_finished() {
                std::thread::yield_now();
            }
            drop(handle);
        }
        "redactor" => {
            // A redactor panic is caught inside the writer path, outside any hook.
            let text = redaction::redact_guarded(&redactor, &format!("{PANIC_TRIGGER} x"));
            assert_eq!(text, redaction::DROPPED);
            let caught = panic::catch_unwind(AssertUnwindSafe(|| {
                let _ = redactor.redact_str(PANIC_TRIGGER);
            }));
            assert!(caught.is_err());
        }
        other => panic!("unknown scenario {other}"),
    }
    let _ = writeln!(std::io::stdout(), "scenario {scenario} done");
}
