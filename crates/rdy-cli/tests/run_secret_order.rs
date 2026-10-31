//! The order of the start of `rdy run` (M1-057, ADR 0015 decision 3, threat model I2): a secret that a
//! check declares is in the known-secret set before the first log event and before any check starts.
//!
//! This test binary installs one global subscriber. A global subscriber sees the events of every
//! thread, `spawn_blocking` threads included, which a thread-local one in a unit test does not. The
//! subscriber is a layer that asks the process redactor, at each event, whether the canary of the run
//! is already hidden. It runs in its own binary because the subscriber and the process redactor are
//! global, and because the order can only be proved for the first run that registers a canary: each run
//! here has a canary of its own.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rdy_cli::RunHooks;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, OsSupport, Support,
};
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt;

mod common;

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

/// Declares a secret-named variable, and puts the secret in its message without ever reading it.
static LEAKY: CheckInfo = CheckInfo {
    id: "host.cpu",
    family: "host",
    summary: "A test check.",
    meta: CheckMeta {
        title: "Test",
        remediation: "Fix it.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: FULL,
    reads: &[],
    statfs: &[],
    env: &["API_TOKEN"],
    commands: &[],
    peers: &[],
};
static LIST: [&CheckInfo; 1] = [&LEAKY];

/// The canary of the run in progress. The check and the layer both read it.
static CURRENT: Mutex<String> = Mutex::new(String::new());

fn current() -> String {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

struct Said;

impl Check for Said {
    fn info(&self) -> &'static CheckInfo {
        &LEAKY
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async { Ok(Finding::pass(format!("the check saw {}", current()))) })
    }
}

struct Leaky;

impl Family for Leaky {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &LIST
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Ok(Built::new(Box::new(Said)))
    }
}

fn leaky_families() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Leaky)?;
    Ok(registry)
}

/// How many events the layer saw, and how many of them showed the canary of the moment.
static EVENTS: AtomicUsize = AtomicUsize::new(0);
static SHOWN: AtomicUsize = AtomicUsize::new(0);

struct HiddenAtEvent;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for HiddenAtEvent {
    fn on_event(
        &self,
        _event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let canary = current();
        if canary.is_empty() {
            return;
        }
        EVENTS.fetch_add(1, Ordering::SeqCst);
        if rdy_cli::redaction::redact_text(&canary).contains(&canary) {
            SHOWN.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn install_subscriber() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let subscriber = tracing_subscriber::registry().with(HiddenAtEvent);
        tracing::subscriber::set_global_default(subscriber)
            .unwrap_or_else(|e| panic!("a global subscriber was already set: {e}"));
    });
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n";

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn run(spec: &Path, canary: &str, extra: &[&str]) -> Ran {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    let spec = spec.to_string_lossy().into_owned();
    let mut args = vec!["rdy", "run", &spec, "--allow-unsigned", "--json"];
    args.extend(extra);
    let mut hooks = RunHooks::default();
    hooks.families = Some(leaky_families);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = runtime
        .block_on(rdy_cli::run(
            args,
            Arc::new(common::unprivileged().env("API_TOKEN", canary)),
            hooks,
            &mut out,
            &mut err,
        ))
        .code();
    Ran {
        code,
        stdout: String::from_utf8(out).unwrap_or_else(|e| panic!("stdout is not UTF-8: {e}")),
        stderr: String::from_utf8(err).unwrap_or_else(|e| panic!("stderr is not UTF-8: {e}")),
    }
}

/// Every file under `dir`, with its text.
fn files_under(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", next.display()))
        {
            let path = entry
                .unwrap_or_else(|e| panic!("cannot list {}: {e}", next.display()))
                .path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                found.push((path, String::from_utf8_lossy(&bytes).into_owned()));
            }
        }
    }
    found
}

#[test]
fn a_declared_secret_is_hidden_at_every_log_event_of_the_run_and_in_every_file_it_writes() {
    install_subscriber();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let spec = dir.path().join("spec.yaml");
    std::fs::write(&spec, SPEC).unwrap_or_else(|e| panic!("cannot write the spec: {e}"));

    // Run one: no files. The log was live, and the secret was hidden at every event, the first one
    // included, on every thread.
    let canary = "canary-order-one-4471".to_owned();
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = canary.clone();
    let ran = run(&spec, &canary, &["--no-report"]);
    let (events, shown) = (EVENTS.load(Ordering::SeqCst), SHOWN.load(Ordering::SeqCst));
    assert_eq!(ran.code, 0, "{}", ran.stdout);
    assert!(events > 0, "no log event was seen, so this proves nothing");
    assert_eq!(
        shown, 0,
        "the canary was visible at {shown} of {events} events"
    );
    assert!(!ran.stdout.contains(&canary), "{}", ran.stdout);
    assert!(!ran.stderr.contains(&canary), "{}", ran.stderr);
    let report: Value =
        serde_json::from_str(&ran.stdout).unwrap_or_else(|e| panic!("not JSON ({e})"));
    let message = report["checks"][0]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("the check saw [REDACTED:known_secret:"),
        "{message}"
    );

    // Run two: files. A new canary, so the order is proved again. Nothing in the report folder holds it.
    let canary = "canary-order-two-8813".to_owned();
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = canary.clone();
    let before = EVENTS.load(Ordering::SeqCst);
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap_or_else(|e| panic!("cannot make the folder: {e}"));
    let ran = run(&spec, &canary, &["--out-dir", &out.to_string_lossy()]);
    assert_eq!(ran.code, 0, "{}", ran.stdout);
    assert!(
        EVENTS.load(Ordering::SeqCst) > before,
        "no event in run two"
    );
    assert_eq!(
        SHOWN.load(Ordering::SeqCst),
        shown,
        "the canary of run two was visible at an event"
    );
    assert!(!ran.stdout.contains(&canary), "{}", ran.stdout);
    assert!(!ran.stderr.contains(&canary), "{}", ran.stderr);
    let files = files_under(&out);
    assert!(files.len() >= 2, "the folder holds {} files", files.len());
    for (path, text) in &files {
        assert!(
            !text.contains(&canary),
            "{} holds the canary",
            path.display()
        );
    }
    let json = files
        .iter()
        .find(|(path, _)| path.extension().is_some_and(|ext| ext == "json"))
        .unwrap_or_else(|| panic!("no .json file"));
    assert!(json.1.contains("the check saw [REDACTED:known_secret:"));
}
