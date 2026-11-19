//! The env-level harness, in process (M1-075, 08 sections 2 and 3), and the fixture completeness rule
//! (correction-21).
//!
//! Environments. Every directory under `tests/fixtures/envs` that has a `spec` in its `fixture.toml` is
//! run through `rdy_cli::run` (`driver::run_env`, M1-086) with the clock, run id and environment pinned by
//! its `[run]` table. The test compares the exit code and verdict with `[expect]`, the report (read from
//! the `--json` stdout) with `golden/report.json`, the human output on stderr with `golden/terminal.txt`,
//! both through `assert_golden`, and the report at `jobs = 1` with the report at `jobs = 8`. Adding a
//! directory adds a run, with no code change. A directory with no `spec` is a base that other
//! environments build on and is skipped. An environment whose `os` is not the OS the test runs on is
//! skipped too, with a line on stderr: `rdy_cli::run` plans for `current_os()` and has no hook to change it.
//!
//! Clusters (M1-185). An environment whose `kube` cap is true serves its `api/` tree as a scripted cluster (the
//! kube mock of `rdy-checks-k8s`, behind its `testing` feature), and the driver audits INV-14 over the run.
//! `driver` says how.
//!
//! `report.html`: the run writes it next to the `.json` (M1-181). The goldens are taken with `--no-report`,
//! so the page golden of each env in `HTML_ENVS` is rendered here from the normalised report. One test
//! runs the host-min environment into a folder (exit 0) and checks the written page against the structure
//! rules of M1-082. `driver` says what else the run does not do.
//!
//! Generated chains. `chains` runs every case of `net.tls_intercept` through `NetFamily` and the real
//! scheduler, building the certificate chain a case's `chain.json` names with rcgen at test time (M1-100).
//!
//! Completeness. `completeness` walks the registered families and fails when an implemented check has no
//! fixture case for a class 08 names. The rule is proven on a planted family below.

mod chains;
mod completeness;
mod driver;
mod families;
mod readme;
#[path = "../common/readme_goldens.rs"]
mod readme_goldens;
// The structure rules of the HTML report (M1-082), run here over the page a run wrote (M1-181). Its own
// tests run a second time in this binary, which costs milliseconds.
#[path = "../../../rdy-engine/tests/html_structure.rs"]
mod html_structure;

use std::error::Error;
use std::path::Path;

use completeness::{Class, Pending, findings};
use jsonschema::Validator;
use rdy_engine::check::{CheckInfo, CheckMeta, Need, OsSupport, Support, Want, current_os};
use rdy_engine::family::{BuildError, Built, Family};
use rdy_engine::summary::last_line;
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{
    Fixture, assert_static_html, fixtures_dir, normalize, normalize_across_jobs,
};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::Value;

use families::Row;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The envs that have a `golden/report.html` (08 section 3). Add the name when the env lands.
const HTML_ENVS: &[&str] = &["all-pass", "warnings-only", "all-block"];

// ---- environments -------------------------------------------------------------------------------

/// The result schema, rooted at the report.
fn report_validator() -> TestResult<Validator> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    Ok(jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?)
}

#[test]
fn host_min_is_found() -> TestResult {
    let names = driver::env_names(&fixtures_dir())?;
    assert!(
        names.iter().any(|name| name == "host-min"),
        "env_names found {names:?}"
    );
    Ok(())
}

/// 31.3 GiB against `min: 32Gi` passes with the tolerance note (M1-117 exit test), and every check of the
/// all-pass env passes: no skip, no partial result, so the golden cannot hide a check that did not run.
#[test]
fn all_pass_passes_every_check_and_memory_carries_its_note() -> TestResult {
    // The run plans for the OS it runs on, so a Linux env cannot run on a macOS or Windows leg.
    if Fixture::load(&fixtures_dir(), "envs/all-pass")?.os() != current_os() {
        eprintln!("env_harness: skipping all-pass: it is a Linux machine");
        return Ok(());
    }
    let run = driver::run_env("all-pass", 1)?;
    assert_eq!(run.report.exit_code, 0);
    let ids: Vec<&str> = run.report.checks.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), 16, "checks that ran: {ids:?}");
    for check in &run.report.checks {
        assert_eq!(
            check.status,
            rdy_spec::result::Status::Pass,
            "{}: {}",
            check.key,
            check.message
        );
        assert!(check.partial.is_none(), "{} is partial", check.key);
    }
    // M1-185: k8s.version reads the scripted three-node cluster, and the audit of the run (INV-14) is clean.
    let version = run
        .report
        .checks
        .iter()
        .find(|c| c.id == "k8s.version")
        .ok_or("k8s.version did not run")?;
    assert_eq!(version.message, "Server v1.29.4, 1.27 to 1.31 needed");
    assert!(run.violations.is_empty(), "{:?}", run.violations);
    assert_eq!(
        run.kube_requests.first().map(String::as_str),
        Some("GET /version")
    );
    assert!(
        run.kube_requests
            .iter()
            .any(|line| line.starts_with("GET /api/v1/nodes")),
        "{:?}",
        run.kube_requests
    );
    let memory = run
        .report
        .checks
        .iter()
        .find(|c| c.id == "host.memory")
        .ok_or("host.memory did not run")?;
    assert_eq!(
        memory.message,
        "31.3 GiB found, 32 GiB needed, inside the 5% tolerance"
    );
    assert!(
        memory.notes.iter().any(|n| n.contains("tolerance_percent")),
        "{:?}",
        memory.notes
    );
    Ok(())
}

/// M1-119: the `timeouts` env under paused time at `jobs = 1` and `jobs = 8`.
///
/// A hung `statvfs` ends `host.disk` in `timeout` at the facade's 5 s limit. A black-hole endpoint does not
/// give `timeout`: `net.egress` cuts each endpoint to its own budget by design (03), so the check returns
/// a bounded `block` that names the black hole. The run ends inside `deadline_ms` in virtual time. The end
/// is read from the checks' own `started_ms + duration_ms`, which come from the paused tokio clock, before
/// the golden normaliser zeroes them (`run.duration_ms` is wall clock and proves nothing here). No real
/// sleep and no real socket is involved, so a slow runner cannot change the result. At `jobs = 1` the
/// checks run one after the other, so virtual time is the sum (10 s for the cluster probe, then 5 s, then the
/// black hole's 3 s). At `jobs = 8` both start at once, after the probe.
///
/// M1-187: the env also holds a cluster whose `/version` does not answer while the cluster client is
/// built (`api/version.json`, `delay_ms` of 10 minutes). The engine cuts the family probe at
/// `FAMILY_PROBE_LIMIT` (10 s) and leaves the `kube_context` need unmet, so `k8s.version` is skipped
/// `missing_need` in the `required_not_run` bucket and never starts a request of its own. Every check
/// starts after the probe, so the run ends inside `deadline_ms` only because the limit is shorter than
/// the 10 minute delay. What is proven: the one `GET /version` was dropped at the limit and logged as
/// `timeout`, and nothing else asked the cluster. The mock's delay is a tokio sleep, so this does not
/// by itself show that no worker thread was blocked (the family-level test in rdy-checks-k8s does that
/// on a one-thread runtime). The INV-14 audit (`run.violations`) passes.
#[test]
fn timeouts_env_ends_inside_its_deadline_in_virtual_time_at_any_jobs() -> TestResult {
    use rdy_spec::result::{Bucket, SkipKind, Status};
    if Fixture::load(&fixtures_dir(), "envs/timeouts")?.os() != current_os() {
        eprintln!("env_harness: skipping timeouts: it is a Linux machine");
        return Ok(());
    }
    let probe_ms = u64::try_from(rdy_engine::family::FAMILY_PROBE_LIMIT.as_millis())?;
    // `started_ms` loses the real gap before the scheduler's origin, so allow 100 ms below the limit.
    let probe_low = probe_ms - 100;
    for jobs in [1, 8] {
        let run = driver::run_env("timeouts", jobs)?;
        let report = &run.report;
        let check = |id: &str| {
            report
                .checks
                .iter()
                .find(|c| c.id == id)
                .ok_or_else(|| format!("{id} did not run at jobs = {jobs}"))
        };
        let disk = check("host.disk")?;
        assert_eq!(
            disk.status,
            Status::Timeout,
            "jobs {jobs}: {}",
            disk.message
        );
        assert_eq!(disk.timeout_after_ms, Some(5000), "jobs {jobs}");
        // The hang cost its full limit in virtual time, so the paused clock really ran.
        assert!(
            disk.duration_ms >= 5000,
            "jobs {jobs}: {} ms",
            disk.duration_ms
        );
        let egress = check("net.egress")?;
        assert_eq!(
            egress.status,
            Status::Block,
            "jobs {jobs}: {}",
            egress.message
        );
        assert!(egress.message.contains("blackhole"), "{}", egress.message);
        // M1-187: the cluster client is built before any check runs, and the `/version` never answers, so
        // the engine cuts the family probe at its limit. No check starts before that. The request was
        // dropped at the limit and logged as `timeout`; it was the only one.
        assert_eq!(run.kube_requests, ["GET /version"], "jobs {jobs}");
        let actions = serde_json::to_value(&report.actions)?;
        let kube_actions: Vec<_> = actions
            .as_array()
            .ok_or("actions is not an array")?
            .iter()
            .filter(|a| a.get("kind").and_then(|k| k.as_str()) == Some("kube"))
            .collect();
        assert_eq!(kube_actions.len(), 1, "jobs {jobs}: {kube_actions:?}");
        assert_eq!(kube_actions[0]["path"], "/version", "jobs {jobs}");
        assert_eq!(kube_actions[0]["outcome"], "timeout", "jobs {jobs}");
        let version = check("k8s.version")?;
        assert_eq!(version.status, Status::Skipped, "jobs {jobs}");
        assert_eq!(
            version.skip_kind,
            Some(SkipKind::MissingNeed),
            "jobs {jobs}"
        );
        assert_eq!(
            version.bucket,
            Bucket::RequiredNotRun,
            "jobs {jobs}: {}",
            version.message
        );
        assert!(
            version
                .needs
                .iter()
                .any(|n| n.need == rdy_spec::result::Need::KubeContext && !n.met),
            "jobs {jobs}: {:?}",
            version.needs
        );
        assert_eq!(version.duration_ms, 0, "jobs {jobs}: the check never ran");
        assert!(
            run.violations.is_empty(),
            "jobs {jobs}: INV-14 audit: {:?}",
            run.violations
        );
        let end = report
            .checks
            .iter()
            .map(|c| c.started_ms + c.duration_ms)
            .max()
            .unwrap_or(0);
        let deadline = report.run.options.deadline_ms;
        assert!(
            (probe_low + 5000..=deadline).contains(&end),
            "jobs {jobs}: the checks ended at {end} ms of virtual time, deadline_ms is {deadline}"
        );
        // Every check starts after the probe limit.
        assert!(
            (probe_low..=probe_ms + 100).contains(&disk.started_ms),
            "jobs {jobs}: host.disk started at {} ms",
            disk.started_ms
        );
        // The jobs differ: one at a time the black hole waits behind the hung statvfs, eight at once both
        // start together.
        if jobs == 1 {
            assert!(
                egress.started_ms >= disk.started_ms + disk.duration_ms,
                "jobs 1: net.egress started at {} ms, host.disk ended at {} ms",
                egress.started_ms,
                disk.started_ms + disk.duration_ms
            );
        } else {
            assert!(
                (probe_low..=probe_ms + 100).contains(&egress.started_ms),
                "jobs {jobs}: started at {} and {} ms",
                disk.started_ms,
                egress.started_ms
            );
        }
        assert!(!report.interrupted, "jobs {jobs}");
        assert_eq!(report.verdict.as_str(), "not_ready", "jobs {jobs}");
        assert_eq!(report.exit_code, 2, "jobs {jobs}");
    }
    Ok(())
}

/// Runs `env` at `jobs = 1`, or `None` on a leg of another OS (these envs are Linux machines).
fn run_linux_env(env: &str) -> TestResult<Option<driver::EnvRun>> {
    if Fixture::load(&fixtures_dir(), &format!("envs/{env}"))?.os() != current_os() {
        eprintln!("env_harness: skipping {env}: it is a Linux machine");
        return Ok(None);
    }
    Ok(Some(driver::run_env(env, 1)?))
}

/// The ids of the checks of `run` that ended with `status`.
fn ids_with(run: &driver::EnvRun, status: rdy_spec::result::Status) -> Vec<&str> {
    let mut ids: Vec<&str> = run
        .report
        .checks
        .iter()
        .filter(|c| c.status == status)
        .map(|c| c.id.as_str())
        .collect();
    ids.sort_unstable();
    ids
}

/// M1-118, M1-185: `warnings-only` exits 1 with three warnings and no block, and no check is partial or
/// skipped. The third warning is k8s.storageclass: the scripted cluster has two classes and no default.
#[test]
fn warnings_only_exits_1_with_three_warnings_and_nothing_else() -> TestResult {
    use rdy_spec::result::{Status, Verdict};
    let Some(run) = run_linux_env("warnings-only")? else {
        return Ok(());
    };
    assert_eq!(run.report.exit_code, 1, "{}", run.terminal);
    assert_eq!(run.report.verdict, Verdict::ReadyWithWarnings);
    assert_eq!(run.report.verdict_reason, None);
    assert_eq!(
        ids_with(&run, Status::Warn),
        ["host.lsm", "host.sysctl", "k8s.storageclass"]
    );
    let storage = run
        .report
        .checks
        .iter()
        .find(|c| c.id == "k8s.storageclass")
        .ok_or("k8s.storageclass did not run")?;
    assert!(
        storage.message.starts_with("No default storage class"),
        "{}",
        storage.message
    );
    assert_eq!(run.report.summary.block, 0);
    assert!(run.report.checks.iter().all(|c| c.partial.is_none()));
    Ok(())
}

/// M1-118, M1-185: `all-block` exits 2 on six blockers: memory, disk, a held port, refused egress, a cluster
/// too old for the spec (k8s.version) and an identity that may not create namespaces (k8s.rbac). The
/// k8s.storageclass result is partial and names the grant it lacks, because the `CSINode` list is refused.
#[test]
fn all_block_exits_2_on_six_blockers() -> TestResult {
    use rdy_spec::result::{Status, Verdict};
    let Some(run) = run_linux_env("all-block")? else {
        return Ok(());
    };
    assert_eq!(run.report.exit_code, 2, "{}", run.terminal);
    assert_eq!(run.report.verdict, Verdict::NotReady);
    assert_eq!(run.report.verdict_reason, None, "a block was seen");
    assert_eq!(
        ids_with(&run, Status::Block),
        [
            "host.disk",
            "host.memory",
            "host.ports",
            "k8s.rbac",
            "k8s.version",
            "net.egress"
        ]
    );
    let storage = run
        .report
        .checks
        .iter()
        .find(|c| c.id == "k8s.storageclass")
        .ok_or("k8s.storageclass did not run")?;
    let partial = storage
        .partial
        .as_ref()
        .ok_or("k8s.storageclass is not partial")?;
    assert_eq!(partial.missing_grants, ["list csinodes (storage.k8s.io)"]);
    assert!(run.violations.is_empty(), "{:?}", run.violations);
    assert_eq!(run.terminal.lines().last(), Some("NOT READY"));
    Ok(())
}

/// M1-118: `no-privileges` (uid 1000, an audit log and other users' sockets out of reach, no kubeconfig)
/// shows `partial` results, a `missing_need` skip, and no block, so the verdict reason is
/// `required_check_not_run` and the exit code is 2.
///
/// `partial.missing_grants` stays empty here: only the k8s checks fill it, and this env has no kubeconfig,
/// so it serves no cluster (`kube = false`) and sends no request. `all-block` shows the field (M1-185).
#[test]
fn no_privileges_shows_partial_results_and_a_missing_need_skip() -> TestResult {
    use rdy_spec::result::{Need, SkipKind, Status, Verdict, VerdictReason};
    let Some(run) = run_linux_env("no-privileges")? else {
        return Ok(());
    };
    assert_eq!(run.report.exit_code, 2, "{}", run.terminal);
    assert_eq!(run.report.verdict, Verdict::NotReady);
    assert_eq!(
        run.report.verdict_reason,
        Some(VerdictReason::RequiredCheckNotRun)
    );
    assert_eq!(run.report.summary.block, 0);
    assert_eq!(run.report.summary.required_not_run, 1);

    let skipped = ids_with(&run, Status::Skipped);
    assert_eq!(skipped, ["k8s.version"]);
    assert!(run.kube_requests.is_empty(), "{:?}", run.kube_requests);
    let version = run
        .report
        .checks
        .iter()
        .find(|c| c.id == "k8s.version")
        .ok_or("k8s.version missing")?;
    assert_eq!(version.skip_kind, Some(SkipKind::MissingNeed));

    // The root-optional owner lookup of host.ports: the port is held, the owner is not named.
    let ports = run
        .report
        .checks
        .iter()
        .find(|c| c.id == "host.ports")
        .ok_or("host.ports missing")?;
    assert_eq!(ports.status, Status::Warn);
    assert!(ports.message.contains("could not identify the holder"));

    let mut partial: Vec<&str> = run
        .report
        .checks
        .iter()
        .filter(|c| {
            c.partial
                .as_ref()
                .is_some_and(|p| p.missing == [Need::Root])
        })
        .map(|c| c.id.as_str())
        .collect();
    partial.sort_unstable();
    assert_eq!(
        partial,
        [
            "host.container_runtime",
            "host.firewall",
            "host.lsm",
            "host.ports",
            "host.security_agents"
        ]
    );
    let all_partial = run
        .report
        .checks
        .iter()
        .filter(|c| c.partial.is_some())
        .count();
    assert_eq!(all_partial, 5, "every partial result needs root");
    assert_eq!(
        run.terminal.lines().last(),
        Some("NOT READY: 1 required check was not run")
    );
    Ok(())
}

/// The one file of `folder` that ends in `.extension`.
fn only_file(folder: &Path, extension: &str) -> TestResult<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(folder)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == extension) {
            found.push(path);
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(format!(
            "want one .{extension} in {}, found {found:?}",
            folder.display()
        )
        .into()),
    }
}

#[test]
fn the_host_min_env_writes_a_page_that_passes_the_structure_rules() -> TestResult {
    use sha2::{Digest as _, Sha256};

    let fixture = Fixture::load(&fixtures_dir(), "envs/host-min")?;
    if fixture.os() != current_os() {
        eprintln!("env_harness: skipping the written page: host-min is another OS");
        return Ok(());
    }
    let out = tempfile::tempdir()?;
    let ran = driver::run_env_into("host-min", 1, Some(out.path()))?;
    assert_eq!(ran.report.exit_code, 0, "{}", ran.terminal);

    let folders: Vec<_> = std::fs::read_dir(out.path())?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    let [folder] = folders.as_slice() else {
        return Err(format!("want one report folder, found {folders:?}").into());
    };
    let json = std::fs::read(only_file(folder, "json")?)?;
    let html_path = only_file(folder, "html")?;
    assert!(html_path.is_file());
    let page = std::fs::read_to_string(&html_path)?;
    assert!(only_file(folder, "yaml").is_ok());

    // The page carries the bytes of the `.json` and their hash.
    let hash: String = Sha256::digest(&json)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(page.contains(&format!("data-sha256=\"{hash}\"")), "hash");
    assert!(page.contains(String::from_utf8(json)?.trim_end()), "json");

    assert!(page.contains("WARNING: UNSIGNED SPEC"), "no banner title");
    assert!(page.contains("This report is marked UNSIGNED SPEC."));

    // The terminal lists the page.
    assert!(ran.terminal.contains(".html\n"), "{}", ran.terminal);

    assert_eq!(
        html_structure::all_rules(&page, Some("acme-min")),
        Vec::<String>::new()
    );
    Ok(())
}

#[test]
fn a_base_without_a_spec_is_not_an_env() -> TestResult {
    let root = tempfile::tempdir()?;
    for (name, spec) in [("a-base", ""), ("an-env", "spec = \"spec.yaml\"\n")] {
        let dir = root.path().join("envs").join(name);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("fixture.toml"),
            format!(
                "schema = 1\nname = \"{name}\"\nsummary = \"planted\"\norigin = \"hand\"\nos = \"linux\"\n\
                 arch = \"x86_64\"\nanswers = []\n{spec}\n[caps]\nroot = false\nnetwork = false\nkube = false\n"
            ),
        )?;
    }
    assert_eq!(driver::env_names(root.path())?, ["an-env"]);
    Ok(())
}

#[test]
fn every_env_gives_its_exit_code_and_its_golden_and_the_same_report_at_any_jobs() -> TestResult {
    let validator = report_validator()?;
    for env in driver::env_names(&fixtures_dir())? {
        let fixture = Fixture::load(&fixtures_dir(), &format!("envs/{env}"))?;
        // `rdy_cli::run` plans for the OS it runs on (`current_os()`), and has no hook to change that on
        // purpose, so an environment of another OS cannot run here. Say so and move on.
        if fixture.os() != current_os() {
            eprintln!(
                "env_harness: skipping env {env}: it is a {:?} machine and this is {:?}",
                fixture.os(),
                current_os()
            );
            continue;
        }
        let manifest = fixture.manifest();
        let jobs = manifest.run.jobs.map_or(1, |jobs| jobs as usize);

        let one = driver::run_env(&env, jobs)?;
        assert!(
            one.violations.is_empty(),
            "env {env}: a check went beyond its CheckInfo:\n  {}",
            one.violations.join("\n  ")
        );
        if let Some(expect) = &manifest.expect {
            assert_eq!(
                one.report.verdict.as_str(),
                expect.verdict,
                "env {env}: verdict"
            );
            assert_eq!(
                i32::from(one.report.exit_code),
                expect.exit_code,
                "env {env}: exit code"
            );
        }

        let mut golden = one.report.clone();
        normalize(&mut golden);
        let text = driver::report_json(&golden)?;
        let doc: Value = serde_json::from_str(&text)?;
        let errors: Vec<String> = validator
            .iter_errors(&doc)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "env {env}: fails the schema: {errors:#?}"
        );
        assert_golden(
            fixtures_dir().join(format!("envs/{env}/golden/report.json")),
            text,
        );
        assert_golden(
            fixtures_dir().join(format!("envs/{env}/golden/terminal.txt")),
            &one.terminal,
        );
        // 08 section 3: HTML goldens exist for these envs only. The page is rendered from the normalised
        // report, as `render_html` gets it in a run, through a redactor with a fixed tag key.
        if HTML_ENVS.contains(&env.as_str()) {
            let html = driver::report_html(&golden)?;
            // The ADR 0003 static checks (CSP, no off-file src or href, one script, the data hash).
            assert_static_html(&format!("env {env}"), &html)?;
            assert_golden(
                fixtures_dir().join(format!("envs/{env}/golden/report.html")),
                html,
            );
        } else {
            assert!(
                !fixtures_dir()
                    .join(format!("envs/{env}/golden/report.html"))
                    .exists(),
                "env {env} has a report.html golden, and 08 section 3 gives one to {HTML_ENVS:?} only"
            );
        }
        assert_eq!(
            one.terminal.lines().last(),
            Some(last_line(&one.report.checks).as_str()),
            "env {env}: the verdict is the last line"
        );

        // The same environment at one job and at eight gives the same report. Host-min has one check;
        // all-pass has sixteen, so the order of completion has something to change.
        let mut serial = driver::run_env(&env, 1)?.report;
        let mut parallel = driver::run_env(&env, 8)?.report;
        normalize_across_jobs(&mut serial);
        normalize_across_jobs(&mut parallel);
        assert_eq!(
            driver::report_json(&serial)?,
            driver::report_json(&parallel)?,
            "env {env}: the report differs between jobs = 1 and jobs = 8"
        );
    }
    Ok(())
}

// ---- completeness: the real tree ----------------------------------------------------------------

/// What the implemented checks still owe, by check. See `completeness`.
///
/// Empty since M1-174, and again since M1-179: every implemented check has its cases, each with a reviewed
/// `expect.json`, the Timeout class of the checks that cut a hang themselves included. A check merged
/// without its cases goes here with the ticket that owes them, and the stale-row finding forces the row
/// out when they land.
const PENDING: &[Pending] = &[];

/// The level each case of `net.tls_intercept` must end at. This is the review of the `expect.json` files
/// in one place: a golden can be regenerated with `UPDATE_GOLDENS=1`, this table cannot.
const TLS_LEVELS: &[(&str, &str)] = &[
    ("empty-os-store", "fail"),
    ("env-store-canary-user", "warn"),
    ("expired-inside-window", "warn"),
    ("expired-pinned-clock", "fail"),
    ("handshake-never-completes", "warn"),
    ("issuer-match", "pass"),
    ("issuer-mismatch", "fail"),
    ("machine-only", "warn"),
    ("machine-only-forbidden", "fail"),
    ("pin-ca-only", "warn"),
    ("pin-match", "pass"),
    ("pin-mismatch", "fail"),
    ("pin-root-not-sent", "fail"),
    ("public", "pass"),
    ("refused", "warn"),
    ("unknown-ca", "fail"),
];

#[test]
fn every_tls_intercept_case_matches_its_expect_json_with_the_chain_it_names() -> TestResult {
    let root = fixtures_dir();
    let names = chains::case_names(&root)?;
    let listed: Vec<&str> = TLS_LEVELS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names.iter().map(String::as_str).collect::<Vec<_>>(),
        listed,
        "a case was added or removed: list its level in TLS_LEVELS"
    );
    let mut failures = Vec::new();
    for (case, level) in TLS_LEVELS {
        let ran = std::panic::catch_unwind(|| chains::run_case(&root, case));
        match ran {
            Ok(Ok(result)) => {
                if result["level"] != *level {
                    failures.push(format!(
                        "{case}: ended {}, expected {level}",
                        result["level"]
                    ));
                }
            }
            Ok(Err(error)) => failures.push(format!("{case}: {error}")),
            Err(payload) => {
                let text = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("a panic with no message");
                failures.push(format!("{case}: {text}"));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n---\n"));
    Ok(())
}

#[test]
fn the_canary_user_name_is_in_the_case_and_in_no_golden() -> TestResult {
    let dir = fixtures_dir().join("checks/net.tls_intercept/env-store-canary-user");
    let chain = std::fs::read_to_string(dir.join("chain.json"))?;
    assert!(
        chain.contains("canary-user-7f3a"),
        "the case must hold the canary"
    );
    let golden = std::fs::read_to_string(dir.join("expect.json"))?;
    assert!(
        !golden.contains("canary-user"),
        "the canary reached the golden:\n{golden}"
    );
    assert!(golden.contains("~/certs/inspection.pem"), "{golden}");
    assert!(golden.contains("SSL_CERT_FILE"), "{golden}");
    Ok(())
}

#[test]
fn every_implemented_check_has_its_fixture_cases() -> TestResult {
    let found = findings(&families::rows(), &fixtures_dir(), PENDING)?;
    assert!(
        found.is_empty(),
        "the fixture tree is incomplete:\n  {}",
        found.join("\n  ")
    );
    Ok(())
}

// ---- completeness: proven on a planted family ---------------------------------------------------

/// What the planted checks share: no needs, no reads, every OS.
const BASE: CheckInfo = CheckInfo {
    id: "",
    family: "plant",
    summary: "Planted",
    meta: CheckMeta {
        title: "Planted",
        remediation: "Nothing to fix. A test double.",
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
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// A check that wants root and has a hang source, so it needs all four classes.
static FULL: CheckInfo = CheckInfo {
    id: "plant.full",
    wants: &[Want {
        need: Need::Root,
        evidence_only: false,
    }],
    statfs: &["/"],
    ..BASE
};

/// A check with no root want and no hang source: pass and non-pass only.
static PLAIN: CheckInfo = CheckInfo {
    id: "plant.plain",
    ..BASE
};

/// A check on the stub list: the rule must not ask anything of it.
static STUB: CheckInfo = CheckInfo {
    id: "plant.stub",
    ..BASE
};

static PLANT_CHECKS: [&CheckInfo; 3] = [&FULL, &PLAIN, &STUB];

struct Plant;

impl Family for Plant {
    fn name(&self) -> &'static str {
        "plant"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &PLANT_CHECKS
    }

    fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        Err(BuildError::Unsupported(
            "a planted family builds nothing".to_owned(),
        ))
    }
}

static PLANT: Plant = Plant;

fn plant_rows(stubs: &'static [&'static str]) -> Vec<Row> {
    vec![Row {
        family: &PLANT,
        stubs,
    }]
}

/// One planted case: a loadable fixture that answers `check`, with the `expect.json` the rule reads.
struct Case {
    check: &'static str,
    name: &'static str,
    level: &'static str,
    partial: bool,
    root: bool,
    hang: Option<&'static str>,
    /// Whether the scheduler ended the check (`timed_out_ms`). Off for a hang the check survived.
    ends: bool,
    /// A note in `result.notes`.
    note: Option<&'static str>,
}

impl Case {
    fn new(check: &'static str, name: &'static str, level: &'static str) -> Self {
        Self {
            check,
            name,
            level,
            partial: false,
            root: false,
            hang: None,
            ends: true,
            note: None,
        }
    }

    fn write(&self, fixtures: &Path) -> TestResult {
        let dir = fixtures.join("checks").join(self.check).join(self.name);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("fixture.toml"),
            format!(
                "schema = 1\nname = \"{}\"\nsummary = \"planted\"\norigin = \"hand\"\nos = \"linux\"\n\
                 arch = \"x86_64\"\nanswers = [\"{}\"]\n\n[caps]\nroot = {}\nnetwork = false\nkube = false\n",
                self.name, self.check, self.root
            ),
        )?;
        let partial = if self.partial {
            r#"{"missing": [], "note": "not verified"}"#
        } else {
            "null"
        };
        let timed_out = if self.hang.is_some() && self.ends {
            r#", "timed_out_ms": 5000"#
        } else {
            ""
        };
        let notes = self
            .note
            .map_or_else(String::new, |n| format!(", \"notes\": [\"{n}\"]"));
        std::fs::write(
            dir.join("expect.json"),
            format!(
                "{{\"entry\": {{\"id\": \"{}\"}}, \"result\": {{\"level\": \"{}\", \"partial\": {partial}{timed_out}{notes}}}}}\n",
                self.check, self.level
            ),
        )?;
        if let Some(delay) = self.hang {
            std::fs::create_dir_all(dir.join("native"))?;
            std::fs::write(
                dir.join("native/0-hang.json"),
                format!(
                    "{{\"call\": \"statvfs\", \"path\": \"/mnt/x\", {delay}\"value\": {{\"fragment_size\": 4096, \
                     \"blocks\": 10, \"blocks_free\": 5, \"blocks_available\": 5, \"files\": 10, \"files_free\": 5, \
                     \"read_only\": false, \"no_exec\": false, \"no_suid\": false, \"dev\": \"0:45\"}}}}\n"
                ),
            )?;
        }
        Ok(())
    }
}

/// The four cases `plant.full` needs.
fn full_cases() -> Vec<Case> {
    let mut partial = Case::new("plant.full", "no-root", "warn");
    partial.partial = true;
    let mut hung = Case::new("plant.full", "hung", "warn");
    hung.hang = Some("\"delay_ms\": 3600000, ");
    vec![
        Case::new("plant.full", "pass", "pass"),
        Case::new("plant.full", "fails", "fail"),
        partial,
        hung,
    ]
}

fn plain_cases() -> Vec<Case> {
    vec![
        Case::new("plant.plain", "pass", "pass"),
        Case::new("plant.plain", "warns", "warn"),
    ]
}

fn plant_tree(cases: &[Case]) -> TestResult<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    for case in cases {
        case.write(dir.path())?;
    }
    Ok(dir)
}

fn all_cases() -> Vec<Case> {
    let mut all = full_cases();
    all.extend(plain_cases());
    all
}

const STUBBED: &[&str] = &["plant.stub"];

#[test]
fn a_complete_planted_family_has_no_findings() -> TestResult {
    let tree = plant_tree(&all_cases())?;
    let found = findings(&plant_rows(STUBBED), tree.path(), &[])?;
    assert!(found.is_empty(), "{found:#?}");
    Ok(())
}

#[test]
fn an_implemented_check_with_no_directory_fails_and_a_stub_does_not() -> TestResult {
    let tree = plant_tree(&[])?;
    let found = findings(&plant_rows(STUBBED), tree.path(), &[])?;
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(found.iter().any(|f| f.contains("checks/plant.full")));
    assert!(found.iter().any(|f| f.contains("checks/plant.plain")));
    assert!(!found.iter().any(|f| f.contains("plant.stub")));
    Ok(())
}

#[test]
fn a_check_that_is_not_a_stub_is_asked_for_every_class_and_the_finding_names_the_class()
-> TestResult {
    // Drop one case at a time from plant.full: exactly that class is reported.
    for (dropped, label) in [
        ("pass", "a passing case"),
        ("fails", "a non-passing case"),
        ("no-root", "a no-privilege partial case"),
        ("hung", "a Timeout case"),
    ] {
        let mut cases = plain_cases();
        // `fails` is the only non-pass case of plant.full except the two warn cases, so give the other
        // two cases a pass level when the non-pass class is the one under test.
        for mut case in full_cases() {
            if case.name == dropped {
                continue;
            }
            if dropped == "fails" && case.level == "warn" {
                case.level = "pass";
            }
            cases.push(case);
        }
        let tree = plant_tree(&cases)?;
        let found = findings(&plant_rows(STUBBED), tree.path(), &[])?;
        assert_eq!(found.len(), 1, "without {dropped}: {found:#?}");
        let line = found.first().map_or("", String::as_str);
        assert!(
            line.contains("plant.full") && line.contains(label),
            "without {dropped}: {line}"
        );
    }
    Ok(())
}

#[test]
fn a_partial_case_that_ran_as_root_and_a_timeout_without_a_hung_source_do_not_count() -> TestResult
{
    let mut cases = plain_cases();
    for mut case in full_cases() {
        if case.name == "no-root" {
            case.root = true;
        }
        if case.name == "hung" {
            case.hang = None;
            // The golden says `timed_out_ms`, but nothing in the case hangs.
            case.level = "warn";
        }
        cases.push(case);
    }
    let tree = plant_tree(&cases)?;
    // Restore the claim without the file: write the timed_out_ms field by hand.
    let hung = tree.path().join("checks/plant.full/hung/expect.json");
    std::fs::write(
        hung,
        r#"{"entry": {"id": "plant.full"}, "result": {"level": "warn", "timed_out_ms": 5000}}"#,
    )?;
    let found = findings(&plant_rows(STUBBED), tree.path(), &[])?;
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(
        found
            .iter()
            .any(|f| f.contains("a no-privilege partial case"))
    );
    assert!(found.iter().any(|f| f.contains("a Timeout case")));
    Ok(())
}

/// The findings for `plant.full` when only its hung case is changed by `edit`.
fn hung_case_findings(edit: impl FnOnce(&Path) -> TestResult) -> TestResult<Vec<String>> {
    let tree = plant_tree(&all_cases())?;
    edit(&tree.path().join("checks/plant.full/hung"))?;
    Ok(findings(&plant_rows(STUBBED), tree.path(), &[])?)
}

#[test]
fn a_delay_below_the_check_timeout_or_a_stray_word_is_not_a_hang() -> TestResult {
    // plant.full has no default timeout, so the engine gives it 10 s. A delay of 9.999 s lets it finish.
    let found = hung_case_findings(|dir| {
        let file = dir.join("native/0-hang.json");
        let text = std::fs::read_to_string(&file)?.replace("3600000", "9999");
        Ok(std::fs::write(file, text)?)
    })?;
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(found.iter().all(|f| f.contains("a Timeout case")));

    // The word `blackhole` in a host name, or a `delay_ms` of 0 in a recording, is not a hang.
    let found = hung_case_findings(|dir| {
        let file = dir.join("native/0-hang.json");
        let text = std::fs::read_to_string(&file)?.replace("3600000", "0");
        std::fs::write(file, text)?;
        Ok(std::fs::write(
            dir.join("net.json"),
            r#"{"dns": {"blackhole.acme.example": ["192.0.2.10"]}}"#,
        )?)
    })?;
    assert_eq!(found.len(), 1, "{found:#?}");
    Ok(())
}

#[test]
fn a_delay_at_the_check_timeout_and_a_blackhole_in_net_json_are_hangs() -> TestResult {
    let found = hung_case_findings(|dir| {
        let file = dir.join("native/0-hang.json");
        let text = std::fs::read_to_string(&file)?.replace("3600000", "10000");
        Ok(std::fs::write(file, text)?)
    })?;
    assert!(found.is_empty(), "{found:#?}");

    let found = hung_case_findings(|dir| {
        std::fs::remove_dir_all(dir.join("native"))?;
        Ok(std::fs::write(
            dir.join("net.json"),
            r#"{"tcp": {"192.0.2.12:443": "blackhole"}}"#,
        )?)
    })?;
    assert!(found.is_empty(), "{found:#?}");

    // A `silent` chain in chain.json is the net.tls_intercept form of a black hole.
    let found = hung_case_findings(|dir| {
        std::fs::remove_dir_all(dir.join("native"))?;
        Ok(std::fs::write(
            dir.join("chain.json"),
            r#"{"host": "web.acme.test", "chain": "silent"}"#,
        )?)
    })?;
    assert!(found.is_empty(), "{found:#?}");
    let found = hung_case_findings(|dir| {
        std::fs::remove_dir_all(dir.join("native"))?;
        Ok(std::fs::write(
            dir.join("chain.json"),
            r#"{"host": "web.acme.test", "chain": "public"}"#,
        )?)
    })?;
    assert_eq!(found.len(), 1, "{found:#?}");
    Ok(())
}

/// A tree whose `plant.full` hung case is the survived form: a hang in its files, no `timed_out_ms`, and
/// `note` as its only note.
fn survived_findings(note: Option<&'static str>) -> TestResult<Vec<String>> {
    let mut cases = plain_cases();
    for mut case in full_cases() {
        if case.name == "hung" {
            case.ends = false;
            case.note = note;
        }
        cases.push(case);
    }
    let tree = plant_tree(&cases)?;
    Ok(findings(&plant_rows(STUBBED), tree.path(), &[])?)
}

#[test]
fn a_hang_the_check_survived_counts_when_a_note_names_it() -> TestResult {
    for note in [
        "chronyc gave no answer: it timed out.",
        "`192.0.2.10`: no reply within 3 s.",
    ] {
        let found = survived_findings(Some(note))?;
        assert!(found.is_empty(), "{note}: {found:#?}");
    }
    Ok(())
}

#[test]
fn a_hang_with_neither_timed_out_ms_nor_a_note_that_names_it_is_a_finding() -> TestResult {
    // No note at all, and a note about something else.
    for note in [None, Some("Offset not measured.")] {
        let found = survived_findings(note)?;
        assert_eq!(found.len(), 1, "{note:?}: {found:#?}");
        assert!(found.iter().all(|f| f.contains("a Timeout case")));
    }
    Ok(())
}

#[test]
fn a_note_that_names_a_hang_does_not_count_without_a_hang_in_the_files() -> TestResult {
    let mut cases = plain_cases();
    for mut case in full_cases() {
        if case.name == "hung" {
            case.hang = None;
            case.note = Some("chronyc gave no answer: it timed out.");
        }
        cases.push(case);
    }
    let tree = plant_tree(&cases)?;
    let found = findings(&plant_rows(STUBBED), tree.path(), &[])?;
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(found.iter().all(|f| f.contains("a Timeout case")));
    Ok(())
}

#[test]
fn a_case_that_does_not_answer_the_check_is_a_finding() -> TestResult {
    let tree = plant_tree(&all_cases())?;
    let toml = tree.path().join("checks/plant.plain/pass/fixture.toml");
    let text = std::fs::read_to_string(&toml)?.replace("plant.plain", "plant.other");
    std::fs::write(&toml, text)?;
    let found = findings(&plant_rows(STUBBED), tree.path(), &[])?;
    assert!(
        found
            .iter()
            .any(|f| f.contains("plant.plain/pass") && f.contains("answers")),
        "{found:#?}"
    );
    Ok(())
}

static OWED: &[Pending] = &[Pending {
    check: "plant.plain",
    classes: &[Class::Pass, Class::NonPass],
    owner: "M1-000",
    why: "planted",
}];

#[test]
fn a_pending_row_excuses_what_it_names_and_goes_stale_when_the_case_arrives() -> TestResult {
    // Only plant.full has cases: plant.plain has a directory but nothing in it that counts.
    let tree = plant_tree(&full_cases())?;
    std::fs::create_dir_all(tree.path().join("checks/plant.plain/empty"))?;
    assert!(findings(&plant_rows(STUBBED), tree.path(), OWED)?.is_empty());
    // Without the row the same tree fails for both classes.
    assert_eq!(findings(&plant_rows(STUBBED), tree.path(), &[])?.len(), 2);
    // Once the cases exist the row is stale.
    let tree = plant_tree(&all_cases())?;
    let found = findings(&plant_rows(STUBBED), tree.path(), OWED)?;
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(found.iter().all(|f| f.contains("PENDING lists")));
    Ok(())
}

static BAD_ROWS: &[Pending] = &[
    Pending {
        check: "plant.stub",
        classes: &[Class::Pass],
        owner: "M1-000",
        why: "a stub is not asked",
    },
    Pending {
        check: "plant.nowhere",
        classes: &[Class::Pass],
        owner: "M1-000",
        why: "not registered",
    },
];

#[test]
fn a_pending_row_for_a_stub_or_an_unregistered_check_is_a_finding() -> TestResult {
    let tree = plant_tree(&all_cases())?;
    let found = findings(&plant_rows(STUBBED), tree.path(), BAD_ROWS)?;
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(
        found
            .iter()
            .any(|f| f.contains("plant.stub") && f.contains("a stub"))
    );
    assert!(found.iter().any(|f| f.contains("plant.nowhere")));
    Ok(())
}

#[test]
fn a_stub_id_the_family_does_not_register_is_a_finding() -> TestResult {
    let tree = plant_tree(&all_cases())?;
    let found = findings(
        &plant_rows(&["plant.stub", "plant.ghost"]),
        tree.path(),
        &[],
    )?;
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(found.iter().all(|f| f.contains("plant.ghost")));
    Ok(())
}

#[test]
fn a_real_stub_that_gains_its_code_is_asked_for_its_cases() -> TestResult {
    // Implemented is registered minus the stub list. With an empty list the six host stubs count as
    // implemented, and none of them has a directory yet.
    let rows = vec![Row {
        family: &rdy_checks_host::HostFamily,
        stubs: &[],
    }];
    let found = findings(&rows, &fixtures_dir(), PENDING)?;
    for id in rdy_checks_host::HostFamily::stub_ids() {
        let dir = format!("checks/{id}: the check is implemented and has no fixture directory");
        assert!(found.iter().any(|f| f.contains(&dir)), "{id}: {found:#?}");
    }
    Ok(())
}

/// The registry and the rows agree.
#[test]
fn the_real_rows_build_a_registry_that_lists_every_row_check() -> TestResult {
    let registry = families::registry()?;
    let listed: Vec<&str> = registry.infos().map(|info| info.id).collect();
    for row in families::rows() {
        for info in row.family.checks() {
            assert!(listed.contains(&info.id), "{} is not registered", info.id);
        }
    }
    Ok(())
}
