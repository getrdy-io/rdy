//! `--quiet` and `--verbose` end to end (M1-143): in process on a replay machine, with stderr and stdout
//! kept apart. The byte for byte goldens of the two modes are in `src/terminal/tests/detail.rs`.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use rdy_cli::RunHooks;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckInfo, CheckMeta, CheckOutcome, Finding, OsSupport, Support,
};
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

mod common;

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

static CPU: CheckInfo = CheckInfo {
    id: "host.cpu",
    family: "host",
    summary: "Passes. A test double.",
    meta: CheckMeta {
        title: "Cpu",
        remediation: "Nothing to fix. A test double.",
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
};

static MEMORY: CheckInfo = CheckInfo {
    id: "host.memory",
    family: "host",
    summary: "Passes. A test double.",
    meta: CheckMeta {
        title: "Memory",
        remediation: "Nothing to fix. A test double.",
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
};

/// A check that passes at once.
struct Passes(&'static CheckInfo);

impl Check for Passes {
    fn info(&self) -> &'static CheckInfo {
        self.0
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move { Ok(Finding::pass("fine".to_owned())) })
    }
}

static LIST: [&CheckInfo; 2] = [&CPU, &MEMORY];

struct HostFamily;

impl Family for HostFamily {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &LIST
    }

    fn build(&self, spec: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        let info = if spec.id == "host.memory" {
            &MEMORY
        } else {
            &CPU
        };
        Ok(Built::new(Box::new(Passes(info))))
    }
}

fn registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(HostFamily)?;
    Ok(registry)
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n  - id: host.memory\n    min: 1\n";

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn run(extra: &[&str]) -> Ran {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let path = dir.path().join("acme.yaml");
    std::fs::write(&path, SPEC).unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    let mut hooks = RunHooks::default();
    hooks.clock = Some(UNIX_EPOCH + Duration::from_millis(1_804_587_302_123));
    hooks.run_id = Some("00000000-0000-4000-8000-000000000001".to_owned());
    hooks.families = Some(registry);
    // A pipe: stderr is not a terminal.
    hooks.stderr_terminal = Some(false);
    hooks.stderr_columns = Some(100);
    hooks.style_env = Some(rdy_cli::style::StyleEnv::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    let spec = path.to_string_lossy().into_owned();
    let mut args = vec!["rdy", "run", &spec, "--allow-unsigned", "--no-report"];
    args.extend(extra);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = runtime
        .block_on(rdy_cli::run(
            args,
            Arc::new(common::unprivileged()),
            hooks,
            &mut out,
            &mut err,
        ))
        .code();
    Ran {
        code,
        stdout: String::from_utf8(out).unwrap_or_else(|e| panic!("stdout: {e}")),
        stderr: String::from_utf8(err).unwrap_or_else(|e| panic!("stderr: {e}")),
    }
}

fn events(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| line.contains(".. finished "))
        .collect()
}

#[test]
fn verbose_prints_one_event_line_per_finished_check_on_a_pipe_before_the_header() {
    let ran = run(&["--verbose"]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    let lines = events(&ran.stderr);
    assert_eq!(lines.len(), 2, "{}", ran.stderr);
    // The two checks run at once, so the order of the lines is the order they ended.
    for key in ["host.cpu", "host.memory"] {
        let text = format!("  .. finished {key} (PASS, ");
        assert!(
            lines.iter().any(|line| line.starts_with(&text)),
            "{}",
            ran.stderr
        );
    }
    // Both lines come before the header, then one blank line.
    let header = ran.stderr.find("\nrdy 0.").unwrap_or(0);
    let last_event = ran.stderr.rfind(".. finished ").unwrap_or(usize::MAX);
    assert!(last_event < header, "{}", ran.stderr);
    assert!(ran.stderr.contains(" ms)\n\nrdy 0."), "{}", ran.stderr);
    assert!(ran.stderr.contains("  took      "), "{}", ran.stderr);
    assert_eq!(ran.stderr.lines().last(), Some("READY"));
    assert!(ran.stdout.is_empty(), "{}", ran.stdout);
}

#[test]
fn the_default_and_quiet_print_no_event_lines() {
    for extra in [&[][..], &["--quiet"][..]] {
        let ran = run(extra);
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert!(events(&ran.stderr).is_empty(), "{}", ran.stderr);
    }
}

#[test]
fn quiet_drops_the_header_and_the_passed_lines_and_keeps_the_verdict_last() {
    let ran = run(&["--quiet"]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(!ran.stderr.contains("rdy 0."), "{}", ran.stderr);
    assert!(!ran.stderr.contains("PASS"), "{}", ran.stderr);
    assert!(ran.stderr.contains("0 blocks, 0 warnings, 2 passed"));
    assert!(ran.stderr.starts_with("WARNING: UNSIGNED SPEC\n"));
    assert_eq!(ran.stderr.lines().last(), Some("READY"));
}

#[test]
fn json_stdout_is_the_same_document_in_every_mode() {
    let documents: Vec<serde_json::Value> = [&[][..], &["--quiet"][..], &["--verbose"][..]]
        .iter()
        .map(|extra| {
            let mut args = vec!["--json"];
            args.extend(extra.iter().copied());
            let ran = run(&args);
            assert_eq!(ran.code, 0, "{}", ran.stderr);
            assert!(ran.stdout.starts_with('{'), "{}", ran.stdout);
            assert!(!ran.stdout.contains(".. finished"), "{}", ran.stdout);
            assert!(!ran.stdout.contains('\x1b'));
            serde_json::from_str(&ran.stdout).unwrap_or_else(|e| panic!("not JSON: {e}"))
        })
        .collect();
    // The whole document, with the fields that count time taken out (`duration_ms`, `started_ms`, `at_ms`).
    let scrubbed: Vec<serde_json::Value> = documents.into_iter().map(scrub).collect();
    assert_eq!(scrubbed[0], scrubbed[1]);
    assert_eq!(scrubbed[0], scrubbed[2]);
}

/// `value` without any object key that ends in `_ms`.
fn scrub(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .filter(|(key, _)| !key.ends_with("_ms"))
                .map(|(key, value)| (key, scrub(value)))
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(scrub).collect())
        }
        other => other,
    }
}

#[test]
fn the_text_of_a_json_run_still_goes_to_stderr_in_verbose() {
    let ran = run(&["--json", "--verbose"]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert_eq!(events(&ran.stderr).len(), 2, "{}", ran.stderr);
    assert_eq!(ran.stderr.lines().last(), Some("READY"));
}

#[test]
fn event_lines_are_dim_with_colour_and_plain_without() {
    let plain = run(&["--verbose", "--color", "never"]);
    assert!(!plain.stderr.contains('\x1b'), "{:?}", plain.stderr);
    let coloured = run(&["--verbose", "--color", "always"]);
    assert!(
        coloured
            .stderr
            .contains("\x1b[2m  .. finished \x1b[0mhost.cpu\x1b[2m ("),
        "{:?}",
        coloured.stderr
    );
}

#[test]
fn quiet_and_verbose_together_are_a_usage_error() {
    let ran = run(&["--quiet", "--verbose"]);
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    assert!(ran.stdout.is_empty());
    let short = run(&["-q", "-v"]);
    assert_eq!(short.code, 64, "{}", short.stderr);
    assert!(short.stdout.is_empty());
}

#[test]
fn quiet_and_verbose_together_with_json_leave_only_the_error_on_stdout() {
    let ran = run(&["-q", "-v", "--json"]);
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    let doc: serde_json::Value =
        serde_json::from_str(&ran.stdout).unwrap_or_else(|e| panic!("not JSON: {e}"));
    // One error document, and none of the report.
    assert!(doc.get("checks").is_none(), "{}", ran.stdout);
    assert!(
        doc.get("error").is_some() || doc.get("code").is_some(),
        "{}",
        ran.stdout
    );
    assert!(!ran.stdout.contains(".. finished"));
}

#[test]
fn an_event_line_is_exactly_the_shape_of_the_plan() {
    let ran = run(&["--verbose"]);
    for line in events(&ran.stderr) {
        let ok = ["host.cpu", "host.memory"].iter().any(|key| {
            line.strip_prefix(&format!("  .. finished {key} (PASS, "))
                .and_then(|rest| rest.strip_suffix(" ms)"))
                .is_some_and(|ms| !ms.is_empty() && ms.bytes().all(|b| b.is_ascii_digit()))
        });
        assert!(ok, "{line:?}");
    }
}
