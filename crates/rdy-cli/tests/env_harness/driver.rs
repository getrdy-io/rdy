//! Runs one fixture environment through the engine and returns its report (M1-075).
//!
//! This is the engine-level driver: it loads `envs/<name>`, parses the env's spec, plans it against the
//! registered families, runs the plan through `TestRun::scheduler` on a paused clock and builds a
//! `Report` with the engine's own mapping (`map_outcome`, `timeout_result`, the verdict rule of
//! `Report::new`). Nothing here reads the real machine: the environment is a `Replay`.
//!
//! It stands where `rdy_cli::run` will stand. `rdy run` is not wired yet (M1-057), so the harness
//! cannot call it, and there is no terminal renderer (M1-086), so there is no `terminal.txt`. When
//! M1-057 lands, `run_env` calls `rdy_cli::run` with the same `Replay` and returns the report from
//! `--json`; the tests in `main` do not change. Until then the mapping below is the engine's, and the
//! three things it does not map (a panic, a cancel, a per-check `timeout:` in the spec) stop the
//! driver with a message instead of guessing.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rdy_engine::check::{BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckOutcome, Os};
use rdy_engine::outcome::{map_outcome, run_deadline_result, timeout_result};
use rdy_engine::plan::{PlanAction, RunPlan};
use rdy_engine::probe::ActionLogOutput;
use rdy_engine::sched::{End, Planned, Ran};
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir, manifest_violations};
use rdy_spec::result::{
    CheckResult, Host, HostOs, HostOsFamily, Identity, Producer, Report, Run, RunOptions,
    Signature, SpecRef,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::families;

/// The deadline when the manifest pins none.
const DEFAULT_DEADLINE_MS: u64 = 300_000;

/// What the driver returns.
pub struct EnvRun {
    /// The report, with the clock, run id and host pinned and the action log inside.
    pub report: Report,
    /// One line per refusal that shows a check went beyond its declared `CheckInfo`. Empty when none did.
    pub violations: Vec<String>,
}

/// The names of the environments under `tests/fixtures/envs` that carry a spec, in order.
///
/// A directory with no `spec` in its manifest is a base other environments build on (08 section 2), so it
/// is not an environment to run. Adding a directory with a spec adds a run, with no code change.
pub fn env_names() -> Result<Vec<String>, String> {
    let dir = fixtures_dir().join("envs");
    let mut names = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let fixture = Fixture::load(&fixtures_dir(), &format!("envs/{name}"))
            .map_err(|e| format!("envs/{name}: {e}"))?;
        if fixture.manifest().spec.is_some() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Runs the environment `env` with `jobs` checks at once.
pub fn run_env(env: &str, jobs: usize) -> Result<EnvRun, String> {
    let root = fixtures_dir();
    let name = format!("envs/{env}");
    let fixture = Fixture::load(&root, &name).map_err(|e| format!("{name}: {e}"))?;
    let manifest = fixture.manifest();
    let spec_file = manifest
        .spec
        .as_deref()
        .ok_or_else(|| format!("{name} has no `spec` in fixture.toml"))?;
    let spec_bytes = std::fs::read(root.join("envs").join(env).join(spec_file))
        .map_err(|e| format!("{name}/{spec_file}: {e}"))?;
    let spec =
        rdy_spec::parse_unverified(&spec_bytes).map_err(|e| format!("{name}/{spec_file}: {e}"))?;
    if spec.checks.iter().any(|entry| entry.timeout.is_some()) {
        return Err(format!(
            "{name}/{spec_file}: the driver does not apply a per-check `timeout:` yet (M1-057)"
        ));
    }

    let os = fixture.os();
    let available = fixture.available_needs();
    let deadline = Duration::from_millis(manifest.run.deadline_ms.unwrap_or(DEFAULT_DEADLINE_MS));
    let registry = families::registry().map_err(|e| e.to_string())?;
    let plan = Arc::new(registry.plan(&spec, os, rdy_spec::VERSION));

    let mut planned = Vec::new();
    for (at, entry) in plan.entries().iter().enumerate() {
        if let PlanAction::Run(built) = &entry.action {
            let shared = Shared {
                plan: Arc::clone(&plan),
                at,
                info: built.check.info(),
            };
            planned.push(
                Planned::new(Arc::new(shared), entry.key.clone()).with_hosts(built.hosts.clone()),
            );
        }
    }

    let test_run = TestRun::for_fixture(&fixture);
    let scheduler = test_run
        .scheduler(jobs, os, available.iter().cloned())
        .with_deadline(deadline);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .map_err(|e| format!("cannot build a runtime: {e}"))?;
    let (ran, host_os) = runtime.block_on(async {
        let host_os = host_os(&test_run, os).await;
        (scheduler.run(planned).await, host_os)
    });

    let mut ran = ran.into_iter();
    let mut results = Vec::new();
    for entry in plan.entries() {
        if let Some(skipped) = entry.skip_result() {
            results.push(skipped);
            continue;
        }
        let one = ran
            .next()
            .ok_or_else(|| format!("{name}: the scheduler returned fewer results than checks"))?;
        let spec_entry = spec
            .checks
            .get(entry.index)
            .ok_or_else(|| format!("{name}: plan entry {} has no spec entry", entry.index))?;
        let PlanAction::Run(built) = &entry.action else {
            return Err(format!("{name}: {} is neither run nor skipped", entry.key));
        };
        let info = built.check.info();
        let ctx = test_run.context(&entry.key, os, available.iter().cloned());
        results.push(result_of(info, spec_entry, &ctx, one, deadline)?);
    }

    let log = test_run.action_log();
    let violations = violations(&plan, &log);

    let pins = &manifest.run;
    let started = pinned_time(pins.clock.as_deref().unwrap_or("2026-01-01T00:00:00Z"));
    let run = Run::new(
        pins.run_id
            .as_deref()
            .unwrap_or("00000000-0000-4000-8000-000000000000"),
        &started,
        &started,
        0,
        run_options(jobs, deadline, manifest.caps.network),
    );
    let mut spec_ref = SpecRef::new(
        spec.metadata.product.as_str(),
        format!("{:x}", Sha256::digest(&spec_bytes)),
        spec_file,
        u64::try_from(spec_bytes.len()).unwrap_or(u64::MAX),
    );
    spec_ref.version.clone_from(&spec.metadata.version);
    let mut host = Host::new(format!("{env}.example"), host_os, manifest.arch.as_str());
    host.container = false;
    let root_run = manifest.caps.root;
    let identity = Identity::new(Some(if root_run { 0 } else { 1000 }), None, root_run);
    let mut report = Report::new(
        Producer::new("0.0.0-test", rdy_spec::VERSION, "x86_64-unknown-linux-musl"),
        run,
        spec_ref,
        Signature::unsigned(),
        host,
        identity,
        results,
    );
    log.apply(&mut report);
    Ok(EnvRun { report, violations })
}

/// The report as the golden holds it: normalised first by the caller, keys sorted at every level, two
/// space indent and a final newline.
///
/// Keys are sorted here because another crate turns on serde_json's `preserve_order` in a workspace
/// build, which would write the free-form `observed` objects in insertion order and not in key order.
pub fn report_json(report: &Report) -> Result<String, String> {
    let value = serde_json::to_value(report).map_err(|e| e.to_string())?;
    let mut text = serde_json::to_string_pretty(&sorted(value)).map_err(|e| e.to_string())?;
    text.push('\n');
    Ok(text)
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// The result entry for one scheduled check, by the engine's own mapping.
fn result_of(
    info: &'static CheckInfo,
    spec_entry: &rdy_spec::spec::CheckSpec,
    ctx: &CheckContext,
    ran: Ran,
    deadline: Duration,
) -> Result<CheckResult, String> {
    let millis = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    match ran.end {
        End::Done(outcome) => Ok(map_outcome(
            info,
            spec_entry,
            ctx,
            *outcome,
            millis(ran.started),
            millis(ran.elapsed),
        )),
        End::TimedOut { after } => Ok(timeout_result(
            &template(info, spec_entry, ctx),
            after,
            ran.started,
        )),
        End::RunDeadline => Ok(run_deadline_result(
            &template(info, spec_entry, ctx),
            deadline,
        )),
        End::Panicked { .. } | End::Cancelled => Err(format!(
            "{}: the driver does not map a panic or a cancel yet (M1-057)",
            ran.key
        )),
        _ => Err(format!("{}: an end this driver does not know", ran.key)),
    }
}

/// A result of the same entry, from which the not-run constructors keep the identity only.
fn template(
    info: &'static CheckInfo,
    spec_entry: &rdy_spec::spec::CheckSpec,
    ctx: &CheckContext,
) -> CheckResult {
    map_outcome(
        info,
        spec_entry,
        ctx,
        Err(CheckError::Unsupported("template")),
        0,
        0,
    )
}

/// Refusals that show a check went beyond its `CheckInfo`, per check.
fn violations(plan: &RunPlan, log: &ActionLogOutput) -> Vec<String> {
    let mut found = Vec::new();
    for entry in plan.entries() {
        let PlanAction::Run(built) = &entry.action else {
            continue;
        };
        let mut own = log.clone();
        own.actions
            .retain(|action| action.check.as_deref() == Some(entry.key.as_str()));
        for line in manifest_violations(built.check.info(), &own) {
            found.push(format!("{}: {line}", entry.key));
        }
    }
    found
}

/// A pinned clock as the wire writes it, with milliseconds.
fn pinned_time(clock: &str) -> String {
    match clock.strip_suffix('Z') {
        Some(head) if !head.contains('.') => format!("{head}.000Z"),
        _ => clock.to_owned(),
    }
}

fn run_options(jobs: usize, deadline: Duration, network: bool) -> RunOptions {
    let mut options = RunOptions::new(
        u32::try_from(jobs).unwrap_or(u32::MAX),
        u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
    );
    options.allow_unsigned = true;
    options.network = network;
    options
}

/// The host's OS from the machine's own `/etc/os-release`, read through the run-level probe like any
/// other fact. A machine with no readable file gets the family alone.
async fn host_os(run: &TestRun, os: Os) -> HostOs {
    let family = match os {
        Os::Macos => HostOsFamily::Macos,
        Os::Windows => HostOsFamily::Windows,
        _ => HostOsFamily::Linux,
    };
    let mut host_os = HostOs::new(family);
    let probe = run.run_probe(os);
    if let Ok(file) = probe.read(Path::new("/etc/os-release")).await {
        let text = String::from_utf8_lossy(&file.bytes).into_owned();
        let field = |key: &str| {
            text.lines().find_map(|line| {
                let value = line.strip_prefix(key)?.strip_prefix('=')?;
                Some(value.trim().trim_matches('"').to_owned())
            })
        };
        host_os.id = field("ID");
        host_os.version = field("VERSION_ID");
        host_os.pretty_name = field("PRETTY_NAME");
    }
    host_os
}

/// A check of the plan, shared so the scheduler (which wants an `Arc<dyn Check>`) can own it while the
/// plan keeps the built check. `RunPlan` has no way to hand its checks out by value.
struct Shared {
    plan: Arc<RunPlan>,
    at: usize,
    info: &'static CheckInfo,
}

impl Check for Shared {
    fn info(&self) -> &'static CheckInfo {
        self.info
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        match self.plan.entries().get(self.at).map(|entry| &entry.action) {
            Some(PlanAction::Run(built)) => built.check.run(ctx),
            _ => Box::pin(async {
                Err(CheckError::Failed {
                    message: "the plan holds no check at this position".to_owned(),
                    hint: String::new(),
                })
            }),
        }
    }
}
