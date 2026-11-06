//! Runs one fixture environment through `rdy_cli::run` and returns its report and its terminal text
//! (M1-075, M1-086).
//!
//! The environment is a `Replay` machine, so nothing here reads the real one. `run_env` calls
//! `rdy_cli::run` in process with the hooks a user cannot reach (the clock, the run id and the deadline
//! pinned by the manifest's `[run]` table, and the harness families), exactly as `rdy run <spec>
//! --allow-unsigned --json --no-report --color never` would. The report is read back from the `--json`
//! stdout, so the golden `report.json` is what a user's pipe gets. The human output on stderr is the
//! golden `terminal.txt`.
//!
//! The run plans for the OS it runs on, so the caller skips an environment of another OS (`main`).
//!
//! What the run does not do yet: `--jobs` is recorded but not applied until M1-059, so the harness
//! writes the requested value into the report's `run.options.jobs`, and the golden does not change when
//! that lands. A fixture that sets `kube = true` gets no cluster until M1-107, because `rdy run` builds
//! no Kubernetes client yet.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rdy_cli::RunHooks;
use rdy_engine::check::Os;
use rdy_engine::probe::{NativeCall, NativeValue, UnameInfo};
use rdy_engine::testing::{Fixture, Replay, TestRun, fixtures_dir, manifest_violations};
use rdy_spec::result::Report;
use serde_json::Value;

use super::families;

/// The deadline when the manifest pins none.
const DEFAULT_DEADLINE_MS: u64 = 300_000;

/// What the driver returns.
pub struct EnvRun {
    /// The report, as `rdy run --json` printed it, with the clock, run id and host pinned.
    pub report: Report,
    /// The human output on stderr, without colour, with the spec path shown as `spec.yaml` and the version
    /// as `<version>`.
    pub terminal: String,
    /// One line per refusal that shows a check went beyond its declared `CheckInfo`. Empty when none did.
    pub violations: Vec<String>,
}

/// The names of the environments under `<root>/envs` that carry a spec, in order. `root` is the fixtures
/// directory, `fixtures_dir()` for the real tree.
///
/// A directory with no `spec` in its manifest is a base other environments build on (08 section 2), so it
/// is not an environment to run. Adding a directory with a spec adds a run, with no code change.
pub fn env_names(root: &Path) -> Result<Vec<String>, String> {
    let dir = root.join("envs");
    let mut names = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let fixture = Fixture::load(root, &format!("envs/{name}"))
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
    let spec_path = root.join("envs").join(env).join(spec_file);
    let spec_arg = spec_path.to_string_lossy().into_owned();
    let spec_bytes = std::fs::read(&spec_path).map_err(|e| format!("{name}/{spec_file}: {e}"))?;
    let spec =
        rdy_spec::parse_unverified(&spec_bytes).map_err(|e| format!("{name}/{spec_file}: {e}"))?;
    if spec.checks.iter().any(|entry| entry.timeout.is_some()) {
        return Err(format!(
            "{name}/{spec_file}: the driver does not apply a per-check `timeout:` yet (M1-057)"
        ));
    }

    let pins = &manifest.run;
    let mut hooks = RunHooks::default();
    hooks.clock = Some(pinned_time(
        pins.clock.as_deref().unwrap_or("2026-01-01T00:00:00Z"),
    )?);
    hooks.run_id = Some(
        pins.run_id
            .clone()
            .unwrap_or_else(|| "00000000-0000-4000-8000-000000000000".to_owned()),
    );
    hooks.deadline = Some(Duration::from_millis(
        pins.deadline_ms.unwrap_or(DEFAULT_DEADLINE_MS),
    ));
    hooks.families = Some(families::registry);
    // The terminal text is a golden: no colour and one width, whatever runs the test.
    hooks.stderr_terminal = Some(false);
    hooks.stderr_columns = Some(100);

    let machine = machine(&fixture, env);
    let jobs_arg = jobs.to_string();
    let mut args = vec![
        "rdy",
        "run",
        &spec_arg,
        "--allow-unsigned",
        "--json",
        "--no-report",
        "--color",
        "never",
        "--jobs",
        &jobs_arg,
    ];
    if !manifest.caps.network {
        args.push("--no-network");
    }

    // A paused clock, so a source that hangs for an hour costs no real time.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .map_err(|e| format!("cannot build a runtime: {e}"))?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = runtime
        .block_on(rdy_cli::run(
            args,
            Arc::new(machine),
            hooks,
            &mut out,
            &mut err,
        ))
        .code();
    let stdout = String::from_utf8(out).map_err(|e| format!("{name}: stdout is not UTF-8: {e}"))?;
    let stderr = String::from_utf8(err).map_err(|e| format!("{name}: stderr is not UTF-8: {e}"))?;
    let mut report: Report = serde_json::from_str(&stdout)
        .map_err(|e| format!("{name}: stdout is not a report ({e}). stderr:\n{stderr}"))?;
    if code != report.exit_code {
        return Err(format!(
            "{name}: rdy run exited {code} but the report says {}. stderr:\n{stderr}",
            report.exit_code
        ));
    }
    // Remove this overwrite when M1-059 (PR #39, `--jobs` applied) is on main: the run then records it.
    report.run.options.jobs = u32::try_from(jobs).unwrap_or(u32::MAX);

    let violations = violations(&report)?;
    // Two things differ between machines and releases: where the checkout is, and the version of rdy.
    let version_line = format!("rdy {}", report.producer.version);
    let terminal: String = stderr
        .replace(&spec_arg, "spec.yaml")
        .split_inclusive('\n')
        .map(|line| {
            if line.trim_end_matches('\n') == version_line {
                "rdy <version>\n"
            } else {
                line
            }
        })
        .collect();
    Ok(EnvRun {
        report,
        terminal,
        violations,
    })
}

/// The fixture's machine with what `rdy run` asks of it before any check: the privilege files for the
/// manifest's `root`, the host name and the kernel.
fn machine(fixture: &Fixture, env: &str) -> Replay {
    let manifest = fixture.manifest();
    let id: u32 = if manifest.caps.root { 0 } else { 1000 };
    let ids = [id; 4];
    let mut replay = fixture.replay().clone();
    replay = match fixture.os() {
        Os::Macos => replay.ids(ids, ids),
        Os::Windows => replay,
        _ => replay
            .file(
                "/proc/self/status",
                format!(
                    "Name:\trdy\nUid:\t{id}\t{id}\t{id}\t{id}\nGid:\t{id}\t{id}\t{id}\t{id}\n\
                     CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\n"
                ),
            )
            .file("/proc/self/auxv", auxv()),
    };
    let mut uname = UnameInfo::default();
    "Linux".clone_into(&mut uname.sysname);
    "5.14.0-362.el9.x86_64".clone_into(&mut uname.release);
    "#1 SMP".clone_into(&mut uname.version);
    manifest.arch.clone_into(&mut uname.machine);
    replay
        .native(
            NativeCall::Hostname,
            NativeValue::Hostname(format!("{env}.example")),
        )
        .native(NativeCall::Uname, NativeValue::Uname(uname))
}

/// An auxiliary vector with `AT_PHDR`, `AT_SECURE` off, and `AT_NULL`.
fn auxv() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (key, value) in [(3_usize, 0x5555_0000_usize), (23, 0), (0, 0)] {
        bytes.extend(key.to_ne_bytes());
        bytes.extend(value.to_ne_bytes());
    }
    bytes
}

/// A pinned clock such as `2026-11-02T09:00:00Z` (or with milliseconds) as a `SystemTime`.
fn pinned_time(clock: &str) -> Result<SystemTime, String> {
    let bad = || format!("the pinned clock {clock:?} is not like 2026-11-02T09:00:00Z");
    let text = clock.strip_suffix('Z').ok_or_else(bad)?;
    let (date, time) = text.split_once('T').ok_or_else(bad)?;
    let (time, millis) = match time.split_once('.') {
        Some((time, fraction)) => (time, fraction.parse::<u64>().map_err(|_| bad())?),
        None => (time, 0),
    };
    let number = |part: Option<&str>| part.and_then(|p| p.parse::<i64>().ok()).ok_or_else(bad);
    let mut d = date.split('-');
    let (year, month, day) = (number(d.next())?, number(d.next())?, number(d.next())?);
    let mut t = time.split(':');
    let (hour, minute, second) = (number(t.next())?, number(t.next())?, number(t.next())?);
    // Days since 1970-01-01 (the civil-from-days algorithm, inverted).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds =
        u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).map_err(|_| bad())?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(millis))
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

/// Refusals that show a check went beyond its `CheckInfo`, per check, read from the report's action log.
fn violations(report: &Report) -> Result<Vec<String>, String> {
    let registry = families::registry().map_err(|e| e.to_string())?;
    let mut found = Vec::new();
    for check in &report.checks {
        let Some(info) = registry.infos().find(|info| info.id == check.id) else {
            continue;
        };
        // An empty log of the harness's kind, with this check's entries put in.
        let mut own = TestRun::new(Replay::new()).action_log();
        own.actions = report
            .actions
            .iter()
            .filter(|action| action.check.as_deref() == Some(check.key.as_str()))
            .cloned()
            .collect();
        for line in manifest_violations(info, &own) {
            found.push(format!("{}: {line}", check.key));
        }
    }
    Ok(found)
}
