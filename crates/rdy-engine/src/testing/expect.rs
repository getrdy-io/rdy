//! `expect.json`: the reviewed result of one check in one fixture case (08 section 2, M1-174).
//!
//! Every case directory under `tests/fixtures/checks/<id>/` that answers `<id>` holds an `expect.json`
//! with two parts:
//!
//! ```json
//! {
//!   "entry": { "id": "host.disk", "path": "/var/lib/acme", "min": "20Gi" },
//!   "result": { "level": "pass", "message": "...", "observed": {}, "expected": {}, "fix": null,
//!               "notes": [], "partial": null }
//! }
//! ```
//!
//! `entry` is the spec entry the check runs with. `result` is [`render`] of how the check ended: a
//! finding, an error, or a timeout. [`assert_cases`] runs every case of a check through the real
//! scheduler on a paused clock, with the case's OS and needs, and compares the bytes through
//! [`assert_golden`](super::golden::assert_golden). A changed message, a new note or a different
//! level fails with a diff, and `UPDATE_GOLDENS=1` writes the new file for review.

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;

use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::golden::assert_golden;
use super::{Fixture, TestRun, assert_within_manifest, fixtures_dir};
use crate::check::{Check, Level};
use crate::sched::{End, Planned};

/// The result as `expect.json` holds it.
///
/// A finding gives `level`, `message`, `observed`, `expected`, `fix`, `notes` and `partial` (its
/// `missing` needs and `note`). A check that returned an error gives `{ "error": "<text>" }`. A check
/// that the scheduler ended at its deadline gives `{ "timed_out_ms": <ms> }`.
///
/// # Panics
///
/// On an end a fixture run cannot reach: a panic, a cancel or a run deadline.
#[must_use]
pub fn render(end: &End) -> Value {
    match end {
        End::TimedOut { after } => json!({ "timed_out_ms": after.as_millis() }),
        End::Done(done) => match done.as_ref() {
            Ok(finding) => json!({
                "level": level_word(finding.level),
                "message": finding.message,
                "observed": finding.observed,
                "expected": finding.expected,
                "fix": finding.fix,
                "notes": finding.notes,
                "partial": finding.partial.as_ref().map(|p| json!({
                    "missing": p.missing.iter().map(|n| format!("{n:?}")).collect::<Vec<_>>(),
                    "note": p.note,
                })),
            }),
            Err(error) => json!({ "error": error.to_string() }),
        },
        other => panic!("unexpected end: {other:?}"),
    }
}

fn level_word(level: Level) -> &'static str {
    match level {
        Level::Pass => "pass",
        Level::Warn => "warn",
        Level::Fail => "fail",
    }
}

/// The value with every object's keys in order. A golden has sorted keys, and a build where another
/// crate turns on serde_json's `preserve_order` would otherwise write them in insertion order.
#[must_use]
pub fn sorted(value: Value) -> Value {
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

/// The bytes of an `expect.json`: `entry` and the [`render`] of `end`, keys sorted, two-space indent,
/// one trailing newline.
///
/// # Panics
///
/// On an end [`render`] refuses.
#[must_use]
pub fn expect_bytes(entry: &Value, end: &End) -> String {
    let both = json!({ "entry": entry, "result": render(end) });
    let mut text = serde_json::to_string_pretty(&sorted(both))
        .unwrap_or_else(|e| panic!("a JSON value serialises: {e}"));
    text.push('\n');
    text
}

/// Runs `check` on the machine of `fixture` through the scheduler with a paused clock, so a hang ends
/// at the check's timeout without waiting, and returns how it ended.
///
/// The check must stay inside its `CheckInfo` ([`assert_within_manifest`]).
///
/// # Panics
///
/// When the runtime cannot start or the check goes beyond its manifest.
#[must_use]
pub fn run_case(fixture: &Fixture, check: Arc<dyn Check>) -> End {
    let info = check.info();
    let test_run = TestRun::for_fixture(fixture);
    let scheduler = test_run.scheduler(1, fixture.os(), fixture.available_needs());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|e| panic!("a runtime: {e}"));
    let mut ran = runtime.block_on(scheduler.run(vec![Planned::new(check, info.id)]));
    assert_within_manifest(fixture.name(), info, &test_run.action_log());
    ran.remove(0).end
}

/// Runs every case of `id` under the shared fixtures and compares each with its `expect.json`. Returns
/// the case names, sorted. See [`assert_cases_in`].
///
/// # Panics
///
/// See [`assert_cases_in`].
#[must_use]
pub fn assert_cases(id: &str, build: impl Fn(&CheckSpec) -> Arc<dyn Check>) -> Vec<String> {
    assert_cases_in(&fixtures_dir(), id, build)
}

/// Runs every case of `id` under the fixtures in `root` and compares each with its `expect.json`.
/// Returns the case names, sorted.
///
/// `build` makes the check from the `entry` of a case. Every directory under `checks/<id>/` is a case:
/// its fixture must load and answer `id`, and it needs an `expect.json` that holds an `entry` whose `id`
/// is `id`. One that has none fails and says how to write it, so a case cannot hide from this test.
///
/// Every case runs. The failures are collected and reported together at the end, so one run shows all
/// the cases that need attention.
///
/// # Panics
///
/// When any case does not load, does not answer `id`, has no `expect.json` or `entry`, has an `entry`
/// for another check, or differs from its `expect.json`. The message lists every failing case.
#[must_use]
pub fn assert_cases_in(
    root: &Path,
    id: &str,
    build: impl Fn(&CheckSpec) -> Arc<dyn Check>,
) -> Vec<String> {
    let dir = root.join("checks").join(id);
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap_or_else(|e| panic!("{}: {e}", dir.display())))
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut failures = Vec::new();
    for case in &names {
        let ran = catch_unwind(AssertUnwindSafe(|| assert_case(root, id, case, &build)));
        if let Err(payload) = ran {
            let text = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("the case panicked without a message");
            failures.push(format!("checks/{id}/{case}: {text}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases of {id} failed:\n{}",
        failures.len(),
        names.len(),
        failures.join("\n---\n")
    );
    names
}

/// One case of [`assert_cases_in`].
fn assert_case(root: &Path, id: &str, case: &str, build: &impl Fn(&CheckSpec) -> Arc<dyn Check>) {
    let name = format!("checks/{id}/{case}");
    let fixture =
        Fixture::load(root, &name).unwrap_or_else(|e| panic!("{name} does not load: {e}"));
    fixture
        .ensure_answers(id)
        .unwrap_or_else(|e| panic!("{name} is under checks/{id}/ and must answer it: {e}"));
    let path = root.join("checks").join(id).join(case).join("expect.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{name} has no expect.json. Fix: write {{\"entry\": {{\"id\": \"{id}\", ...}}}} \
             there, then run with UPDATE_GOLDENS=1 and read the result"
        )
    });
    let golden: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}/expect.json: {e}"));
    let entry = golden
        .get("entry")
        .unwrap_or_else(|| panic!("{name}/expect.json has no `entry`"));
    assert_eq!(
        entry.get("id").and_then(Value::as_str),
        Some(id),
        "{name}/expect.json: the entry is for another check. Fix: set `entry.id` to {id}"
    );
    let spec: CheckSpec = serde_json::from_value(entry.clone())
        .unwrap_or_else(|e| panic!("{name}/expect.json `entry` is not a check entry: {e}"));
    let end = run_case(&fixture, build(&spec));
    assert_golden(&path, expect_bytes(entry, &end));
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::check::{CheckError, Finding, Need, Partial};
    use crate::testing::FakeCheck;

    fn done(outcome: Result<Finding, CheckError>) -> End {
        End::Done(Box::new(outcome))
    }

    fn host_min() -> Fixture {
        Fixture::load(&fixtures_dir(), "envs/host-min").expect("the smallest env loads")
    }

    #[test]
    fn a_finding_renders_every_field_and_the_partial() {
        let mut finding = Finding::warn("8 vCPUs found");
        finding.fix = Some("Add CPUs.".to_owned());
        finding.partial = Some(Partial::new(vec![Need::Root], "needs root"));
        finding.notes.push("a note".to_owned());
        let value = render(&done(Ok(finding)));
        assert_eq!(value["level"], "warn");
        assert_eq!(value["message"], "8 vCPUs found");
        assert_eq!(value["fix"], "Add CPUs.");
        assert_eq!(value["notes"], json!(["a note"]));
        assert_eq!(
            value["partial"],
            json!({"missing": ["Root"], "note": "needs root"})
        );
        let plain = render(&done(Ok(Finding::pass("fine"))));
        assert_eq!(plain["level"], "pass");
        assert_eq!(plain["partial"], Value::Null);
        assert_eq!(plain["fix"], Value::Null);
    }

    #[test]
    fn an_error_and_a_timeout_render_their_own_shapes() {
        let error = render(&done(Err(CheckError::Unsupported("no source here"))));
        assert!(error["error"].as_str().is_some(), "{error}");
        assert_eq!(error.as_object().map(serde_json::Map::len), Some(1));
        let timeout = render(&End::TimedOut {
            after: Duration::from_secs(5),
        });
        assert_eq!(timeout, json!({"timed_out_ms": 5000}));
    }

    #[test]
    #[should_panic(expected = "unexpected end")]
    fn an_end_a_fixture_run_cannot_reach_is_refused() {
        let _ = render(&End::Cancelled);
    }

    #[test]
    fn the_bytes_have_sorted_keys_at_every_depth_and_one_final_newline() {
        let end = done(Ok(Finding::pass("ok")));
        let entry = json!({"min": 1, "id": "x", "nest": {"b": 1, "a": 2}});
        let bytes = expect_bytes(&entry, &end);
        assert!(bytes.ends_with("}\n") && !bytes.ends_with("\n\n"));
        let id = bytes.find("\"id\"").expect("id");
        let min = bytes.find("\"min\"").expect("min");
        let nest = bytes.find("\"nest\"").expect("nest");
        assert!(id < min && min < nest, "{bytes}");
        let a = bytes.find("\"a\": 2").expect("a");
        let b = bytes.find("\"b\": 1").expect("b");
        assert!(a < b, "{bytes}");
        // "entry" sorts before "result".
        assert!(bytes.find("\"entry\"") < bytes.find("\"result\""));
    }

    #[test]
    fn a_check_that_never_returns_ends_at_its_timeout_without_waiting() {
        let started = std::time::Instant::now();
        let end = run_case(&host_min(), Arc::new(FakeCheck::forever()));
        assert!(matches!(end, End::TimedOut { .. }), "{end:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    // ---- assert_cases_in, on planted trees ----

    const MANIFEST: &str = "schema = 1\nname = \"case\"\nsummary = \"A planted case\"\norigin = \"hand\"\nos = \"linux\"\narch = \"x86_64\"\nanswers = [\"fake.plain\"]\n\n[caps]\nroot = false\nnetwork = false\nkube = false\n";

    fn build(_: &CheckSpec) -> Arc<dyn Check> {
        Arc::new(FakeCheck::pass())
    }

    /// A tree with one case of `fake.plain`, a manifest as given and an `expect.json` if any.
    fn plant(manifest: &str, expect: Option<&str>) -> tempfile::TempDir {
        let tree = tempfile::tempdir().expect("a temp dir");
        let case = tree.path().join("checks/fake.plain/case");
        fs::create_dir_all(&case).expect("a case dir");
        fs::write(case.join("fixture.toml"), manifest).expect("a manifest");
        if let Some(text) = expect {
            fs::write(case.join("expect.json"), text).expect("an expect.json");
        }
        tree
    }

    fn right_bytes() -> String {
        let end = run_case(&host_min(), Arc::new(FakeCheck::pass()));
        expect_bytes(&json!({"id": "fake.plain"}), &end)
    }

    #[test]
    fn a_case_with_the_right_result_passes_and_is_named() {
        let tree = plant(MANIFEST, Some(&right_bytes()));
        let names = assert_cases_in(tree.path(), "fake.plain", build);
        assert_eq!(names, ["case"]);
    }

    #[test]
    #[should_panic(expected = "has no expect.json")]
    fn a_case_with_no_expect_json_fails() {
        let tree = plant(MANIFEST, None);
        let _ = assert_cases_in(tree.path(), "fake.plain", build);
    }

    #[test]
    #[should_panic(expected = "has no `entry`")]
    fn an_expect_json_with_no_entry_fails() {
        let tree = plant(MANIFEST, Some("{\"result\": {}}\n"));
        let _ = assert_cases_in(tree.path(), "fake.plain", build);
    }

    #[test]
    #[should_panic(expected = "the entry is for another check")]
    fn an_entry_for_another_check_fails() {
        let text = right_bytes().replace("\"id\": \"fake.plain\"", "\"id\": \"host.memory\"");
        let tree = plant(MANIFEST, Some(&text));
        let _ = assert_cases_in(tree.path(), "fake.plain", build);
    }

    #[test]
    #[should_panic(expected = "must answer it")]
    fn a_case_that_does_not_answer_the_check_fails() {
        let manifest = MANIFEST.replace("fake.plain", "host.memory");
        let tree = plant(&manifest, Some(&right_bytes()));
        let _ = assert_cases_in(tree.path(), "fake.plain", build);
    }

    #[test]
    #[should_panic(expected = "1 of 1 cases of fake.plain failed")]
    fn a_result_that_differs_from_the_golden_fails() {
        let text = right_bytes().replace("\"pass\"", "\"fail\"");
        let tree = plant(MANIFEST, Some(&text));
        let _ = assert_cases_in(tree.path(), "fake.plain", build);
    }

    #[test]
    #[should_panic(expected = "2 of 2 cases of fake.plain failed")]
    fn every_failing_case_is_reported_not_only_the_first() {
        let tree = plant(MANIFEST, None);
        let second = tree.path().join("checks/fake.plain/second");
        fs::create_dir_all(&second).expect("a second case");
        fs::write(second.join("fixture.toml"), MANIFEST).expect("a manifest");
        let _ = assert_cases_in(tree.path(), "fake.plain", build);
    }

    #[test]
    fn a_check_that_passes_ends_done() {
        let end = run_case(&host_min(), Arc::new(FakeCheck::pass()));
        assert_eq!(render(&end)["level"], "pass");
    }
}
