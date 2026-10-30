//! Tests for the engine: a fake `host` family over `FakeCheck`, a real loaded spec, a replay hub.

use std::sync::Arc;
use std::time::Duration;

use rdy_spec::result::{Bucket, ErrorKind, FixSource, Need as WireNeed, SkipKind, Status};
use rdy_spec::sig::{Policy, TrustStore};
use rdy_spec::spec::{CheckSpec, Spec};

use super::*;
use crate::check::{CheckMeta, OsSupport, Support};
use crate::family::{BuildError, Built, Family};
use crate::privilege::{Elevation, ProcessIds};
use crate::redact::{Redactor, TagKey};
use crate::testing::{Fake, FakeCheck, Replay};
use rdy_spec::check::CheckParams;

const CANARY: &str = "canary-engine-secret-1";
const PANIC_TEXT: &str = "canary-engine-panic-2";

const FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

const fn info(id: &'static str, needs: &'static [Need]) -> CheckInfo {
    CheckInfo {
        id,
        family: "host",
        summary: "A fake check.",
        meta: CheckMeta {
            title: "Fake",
            remediation: "Fix it the general way.",
        },
        needs,
        wants: &[],
        default_timeout: None,
        os: FULL,
        reads: &[],
        statfs: &[],
        env: &["API_TOKEN", "HOME"],
        commands: &[],
        peers: &[],
    }
}

static CPU: CheckInfo = info("host.cpu", &[]);
static MEMORY: CheckInfo = info("host.memory", &[]);
static DISK: CheckInfo = info("host.disk", &[Need::Root]);
static CHECKS: [&CheckInfo; 3] = [&CPU, &MEMORY, &DISK];

/// A check that behaves as the spec entry's `name` says.
struct Fakes;

impl Family for Fakes {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &CHECKS
    }

    fn build(&self, entry: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        let name = entry
            .name
            .as_ref()
            .and_then(rdy_spec::spec::Lenient::valid)
            .map(|n| n.as_str().to_owned());
        let check = match (entry.id.as_str(), name.as_deref()) {
            ("host.cpu", Some("slow")) => FakeCheck::with_info(&CPU, Fake::Forever),
            ("host.cpu", Some("boom")) => {
                FakeCheck::with_info(&CPU, Fake::Panic(PANIC_TEXT.to_owned()))
            }
            ("host.cpu", _) => {
                FakeCheck::with_info(&CPU, Fake::Outcome(Box::new(FakeCheck::passed("host.cpu"))))
            }
            ("host.memory", Some("leak")) => FakeCheck::with_info(
                &MEMORY,
                Fake::Outcome(Box::new(Ok(Finding::fail(format!(
                    "low memory, password={CANARY}"
                ))))),
            ),
            ("host.memory", _) => FakeCheck::with_info(
                &MEMORY,
                Fake::Outcome(Box::new(Ok(Finding::fail("low memory")))),
            ),
            ("host.disk", _) => FakeCheck::with_info(
                &DISK,
                Fake::Outcome(Box::new(FakeCheck::passed("host.disk"))),
            ),
            _ => return Err(BuildError::Unsupported("not a fake".to_owned())),
        };
        Ok(Built::new(Box::new(check)))
    }
}

const SPEC: &str = "\
apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme
checks:
  - id: host.cpu
    min: 1
  - id: host.cpu
    name: slow
    min: 1
    timeout: 1s
  - id: host.cpu
    name: boom
    min: 1
  - id: host.memory
    min: 1Gi
  - id: host.memory
    name: leak
    min: 1Gi
  - id: host.disk
    path: /
    min: 1Gi
  - id: net.egress
    endpoints: [\"registry.acme.example:443\"]
";

fn loaded(text: &str) -> LoadedSpec {
    rdy_spec::load(
        text.as_bytes(),
        None,
        &TrustStore::new(),
        Policy::AllowUnsigned,
    )
    .expect("the spec loads")
}

fn privilege(elevated: bool) -> Privilege {
    let (euid, elevation) = if elevated {
        (0, Elevation::Root)
    } else {
        (1000, Elevation::NotElevated)
    };
    Privilege {
        ids: Some(ProcessIds::new([euid; 4], [euid; 4])),
        cap_eff: 0,
        cap_prm: 0,
        cap_amb: 0,
        at_secure: false,
        elevation,
    }
}

fn engine(replay: Replay) -> Engine {
    let mut registry = Registry::new();
    registry.register(Fakes).expect("registers");
    let hub = ProbeHub::new(Arc::new(replay), Redactor::new(TagKey::fixed([7; 32])));
    Engine::new(registry, hub)
}

async fn run_with(replay: Replay, elevated: bool, options: &RunOptions) -> Executed {
    let engine = engine(replay);
    let spec = loaded(SPEC);
    let plan = engine.plan(&spec, Os::Linux, "0.1.0");
    engine
        .execute(&spec, plan, &privilege(elevated), options)
        .await
}

fn find<'a>(done: &'a Executed, key: &str) -> &'a CheckResult {
    done.results
        .iter()
        .find(|r| r.key == key)
        .unwrap_or_else(|| panic!("no result {key}"))
}

#[tokio::test(start_paused = true)]
async fn every_entry_has_one_result_in_spec_order() {
    let done = run_with(Replay::new(), false, &RunOptions::new()).await;
    let keys: Vec<&str> = done.results.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "host.cpu",
            "host.cpu/slow",
            "host.cpu/boom",
            "host.memory",
            "host.memory/leak",
            "host.disk",
            "net.egress"
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn each_way_a_check_can_end_becomes_the_right_result() {
    let done = run_with(Replay::new(), false, &RunOptions::new()).await;

    let pass = find(&done, "host.cpu");
    assert_eq!(pass.status, Status::Pass);

    let slow = find(&done, "host.cpu/slow");
    assert_eq!(slow.status, Status::Timeout);
    assert_eq!(slow.timeout_after_ms, Some(1000));

    let boom = find(&done, "host.cpu/boom");
    assert_eq!(boom.status, Status::Error);
    assert_eq!(boom.error_kind, Some(ErrorKind::Panic));
    let all = serde_json::to_string(&done.results).expect("json");
    assert!(!all.contains(PANIC_TEXT), "the panic text reached a result");

    // Not built: the plan's skip, with rdy's own text.
    let net = find(&done, "net.egress");
    assert_eq!(net.status, Status::Skipped);
    assert_eq!(net.skip_kind, Some(SkipKind::NotInBuild));
    assert_eq!(net.bucket, Bucket::RequiredNotRun);
}

#[tokio::test(start_paused = true)]
async fn a_block_with_no_fix_anywhere_shows_the_check_remediation() {
    let done = run_with(Replay::new(), false, &RunOptions::new()).await;
    let memory = find(&done, "host.memory");
    assert_eq!(memory.status, Status::Block);
    assert_eq!(memory.fix.as_deref(), Some("Fix it the general way."));
    assert_eq!(memory.fix_source, Some(FixSource::Rdy));
}

#[tokio::test(start_paused = true)]
async fn the_root_fix_names_the_spec_as_the_user_typed_it() {
    let mut options = RunOptions::new();
    options.spec_arg = "'my specs/a.yaml'".to_owned();
    let done = run_with(Replay::new(), false, &options).await;
    let disk = find(&done, "host.disk");
    assert_eq!(disk.status, Status::Skipped);
    assert_eq!(disk.skip_kind, Some(SkipKind::MissingNeed));
    assert_eq!(
        disk.fix.as_deref(),
        Some("Rerun as root: sudo rdy run 'my specs/a.yaml'")
    );
    let root = done
        .capabilities
        .iter()
        .find(|c| c.need == WireNeed::Root)
        .expect("the root need was probed");
    assert!(!root.available);
    assert!(root.hint.is_some());
}

#[tokio::test(start_paused = true)]
async fn an_elevated_run_meets_the_root_need_and_runs_the_check() {
    let done = run_with(Replay::new(), true, &RunOptions::new()).await;
    assert_eq!(find(&done, "host.disk").status, Status::Pass);
    let root = done
        .capabilities
        .iter()
        .find(|c| c.need == WireNeed::Root)
        .expect("the root need was probed");
    assert!(root.available);
}

#[tokio::test(start_paused = true)]
async fn results_are_redacted_and_counted() {
    let done = run_with(Replay::new(), false, &RunOptions::new()).await;
    let leak = find(&done, "host.memory/leak");
    assert!(!leak.message.contains(CANARY), "{}", leak.message);
    assert!(leak.message.contains("[REDACTED:"), "{}", leak.message);
    assert!(done.counts.total() >= 1);
}

#[tokio::test(start_paused = true)]
async fn the_run_deadline_ends_a_check_that_has_not_started() {
    let mut options = RunOptions::new();
    options.jobs = 1;
    options.deadline = Duration::from_millis(10);
    let done = run_with(Replay::new(), false, &options).await;
    // One job and a check that never returns: the deadline passes while `slow` runs, so everything
    // behind it never starts.
    let boom = find(&done, "host.cpu/boom");
    assert_eq!(boom.skip_kind, Some(SkipKind::RunDeadline));
    assert_eq!(boom.status, Status::Skipped);
}

#[tokio::test]
async fn no_network_leaves_the_network_need_unmet() {
    // The need is in no check of this family, so ask the probe directly through `capabilities`.
    let hub = ProbeHub::new(
        Arc::new(Replay::new()),
        Redactor::new(TagKey::fixed([7; 32])),
    );
    let found = capabilities(&hub.run_probe(), &privilege(false), &[Need::Network], false).await;
    assert_eq!(found.len(), 1);
    assert!(!found.first().expect("one").available);
}

#[test]
fn declared_secret_env_values_join_the_known_secrets_before_any_check() {
    let replay = Replay::new()
        .env("API_TOKEN", CANARY)
        .env("HOME", "/home/synthetic-user")
        .env("DB_PASSWORD", "abc");
    let redactor = Redactor::new(TagKey::fixed([7; 32]));
    let hub = ProbeHub::new(Arc::new(replay), redactor.clone());
    // `HOME` is not a secret name, `DB_PASSWORD` is not declared, `API_TOKEN` is both.
    let names = CHECKS.iter().flat_map(|info| info.env.iter().copied());
    assert!(hub.add_declared_env_secrets(names).is_empty());
    let line = format!("seen {CANARY} in a log line");
    let shown = redactor.redact_str(&line);
    assert!(!shown.contains(CANARY), "{}", *shown);
    assert!(
        redactor
            .redact_str("home /home/synthetic-user")
            .contains("/home/synthetic-user")
    );
    // Nothing was written to the action log: a proxy can still be set.
    assert!(hub.action_log().actions.is_empty());
}

#[test]
fn a_refused_declared_secret_is_reported_and_counted() {
    // Under 6 bytes: the set refuses it.
    let replay = Replay::new().env("API_TOKEN", "abcde");
    let hub = ProbeHub::new(Arc::new(replay), Redactor::new(TagKey::fixed([7; 32])));
    assert_eq!(
        hub.add_declared_env_secrets(["API_TOKEN"]),
        ["API_TOKEN"],
        "the name is returned, and never the value"
    );
    assert_eq!(
        hub.action_log().redaction.get("known_secret_refused"),
        1,
        "the refusal is counted"
    );
}
