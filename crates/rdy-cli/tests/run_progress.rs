//! The live progress line of `rdy run` end to end (M1-142): drawn on a slow run on a terminal, cleared
//! before the check list, and not drawn at all on a fast run, a pipe, `--quiet`, `--progress never`,
//! `TERM=dumb` or `RUST_LOG`. Never on stdout.
//!
//! The terminal is a buffer here (`RunHooks::progress_capture`), so no pty is needed. The glyph and gate
//! tables are in `src/progress/tests.rs`.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use rdy_cli::RunHooks;
use rdy_cli::progress::{ProgressCapture, ProgressEnv};
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

static NAP: CheckInfo = CheckInfo {
    id: "host.cpu",
    family: "host",
    summary: "Waits a while and passes.",
    meta: CheckMeta {
        title: "Nap",
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

/// How long the slow check takes. Long enough for the first frame (250 ms) and a few more.
const SLOW: Duration = Duration::from_millis(900);

struct Nap(Duration);

impl Check for Nap {
    fn info(&self) -> &'static CheckInfo {
        &NAP
    }

    fn run<'a>(&'a self, _: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok(Finding::pass("rested".to_owned()))
        })
    }
}

static NAP_LIST: [&CheckInfo; 1] = [&NAP];

struct NapFamily(Duration);

impl Family for NapFamily {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &NAP_LIST
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Ok(Built::new(Box::new(Nap(self.0))))
    }
}

fn slow_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(NapFamily(SLOW))?;
    Ok(registry)
}

fn fast_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(NapFamily(Duration::ZERO))?;
    Ok(registry)
}

const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 1\n";

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
    drawn: String,
    cleared: bool,
}

fn env(vars: &[(&str, &str)]) -> ProgressEnv {
    ProgressEnv::from_lookup(|name| {
        vars.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| OsString::from(value))
    })
}

fn run(families: rdy_cli::FamiliesFn, terminal: bool, env: ProgressEnv, args: &[&str]) -> Ran {
    run_after(None, families, terminal, env, args)
}

fn run_after(
    first_frame: Option<Duration>,
    families: rdy_cli::FamiliesFn,
    terminal: bool,
    env: ProgressEnv,
    args: &[&str],
) -> Ran {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let path = dir.path().join("acme.yaml");
    std::fs::write(&path, SPEC).unwrap_or_else(|e| panic!("cannot write the spec: {e}"));
    let capture = ProgressCapture::default();
    let mut hooks = RunHooks::default();
    hooks.clock = Some(UNIX_EPOCH + Duration::from_millis(1_804_587_302_123));
    hooks.run_id = Some("00000000-0000-4000-8000-000000000001".to_owned());
    hooks.families = Some(families);
    hooks.stderr_terminal = Some(terminal);
    hooks.stderr_columns = Some(100);
    hooks.style_env = Some(rdy_cli::style::StyleEnv::default());
    hooks.progress_env = Some(env);
    hooks.progress_capture = Some(capture.clone());
    hooks.progress_first_frame = first_frame;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("no runtime: {e}"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let spec = path.to_string_lossy().into_owned();
    let argv = ["rdy", "run", &spec, "--allow-unsigned", "--no-report"]
        .into_iter()
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let code = runtime
        .block_on(rdy_cli::run(
            argv,
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
        drawn: capture.text(),
        cleared: capture.cleared(),
    }
}

#[test]
fn a_slow_run_on_a_terminal_draws_one_line_and_clears_it_before_the_check_list() {
    let ran = run(slow_registry, true, env(&[("TERM", "xterm")]), &[]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(ran.drawn.contains("Running 1 check"), "{:?}", ran.drawn);
    // ASCII spinner: no locale says UTF-8.
    assert!(
        ["-", "\\", "|", "/"]
            .iter()
            .any(|f| ran.drawn.contains(&format!("{f} Running"))),
        "{:?}",
        ran.drawn
    );
    assert!(ran.cleared, "{:?}", ran.drawn);
    assert!(!ran.drawn.contains('\n'), "{:?}", ran.drawn);
    // The result text is written to the run's stderr writer, with none of the spinner in it.
    assert!(!ran.stderr.contains("Running 1 check"), "{}", ran.stderr);
    assert!(ran.stderr.contains("PASS"), "{}", ran.stderr);
    assert!(ran.stdout.is_empty(), "{}", ran.stdout);
}

#[test]
fn with_json_the_line_is_still_stderr_only_and_stdout_is_one_document() {
    let ran = run(slow_registry, true, env(&[]), &["--json"]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(!ran.drawn.is_empty());
    assert!(ran.stdout.starts_with('{'), "{}", ran.stdout);
    assert!(!ran.stdout.contains("Running 1 check"));
    assert!(!ran.stdout.contains('\x1b'));
}

#[test]
fn braille_is_drawn_when_the_locale_is_utf8() {
    let ran = run(slow_registry, true, env(&[("LANG", "en_US.UTF-8")]), &[]);
    #[cfg(not(windows))]
    assert!(
        rdy_cli::progress::BRAILLE
            .iter()
            .any(|f| ran.drawn.contains(f)),
        "{:?}",
        ran.drawn
    );
    #[cfg(windows)]
    assert!(ran.drawn.contains("Running 1 check"), "{:?}", ran.drawn);
}

#[test]
fn a_run_that_ends_before_the_first_frame_draws_nothing() {
    // The first frame is an hour away, so how fast this machine is cannot matter. The 250 ms rule is
    // proved on a paused clock in `src/progress/tests.rs`.
    let ran = run_after(
        Some(Duration::from_secs(3600)),
        fast_registry,
        true,
        env(&[]),
        &[],
    );
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert_eq!(ran.drawn, "");
}

/// A case of the off-switch table: name, stderr is a terminal, variables, extra arguments.
type OffRow<'a> = (&'a str, bool, ProgressEnv, &'a [&'a str]);

#[test]
fn every_off_switch_draws_nothing_on_a_slow_run() {
    let cases: [OffRow; 7] = [
        ("pipe", false, env(&[]), &[]),
        ("--quiet", true, env(&[]), &["--quiet"]),
        ("--verbose", true, env(&[]), &["--verbose"]),
        ("--progress never", true, env(&[]), &["--progress", "never"]),
        ("TERM=dumb", true, env(&[("TERM", "dumb")]), &[]),
        ("RUST_LOG", true, env(&[("RUST_LOG", "rdy=debug")]), &[]),
        ("pipe and json", false, env(&[]), &["--json"]),
    ];
    for (name, terminal, env, args) in cases {
        let ran = run(slow_registry, terminal, env, args);
        assert_eq!(ran.code, 0, "{name}: {}", ran.stderr);
        assert_eq!(ran.drawn, "", "{name}");
    }
}
