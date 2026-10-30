//! `run_fixture`: runs one check against one fixture and keeps what it returned and what it did to the
//! machine (08 sections 1 and 2).
//!
//! The check runs the way the scheduler runs it, minus the clock: the context is bound to the check's
//! own `CheckInfo`, so a read, command, variable or peer outside its declaration is refused and logged,
//! and a hard need the fixture does not offer gives `MissingNeed` without running the check. There is
//! no timer. A hang is a fixture with a `delay_ms` or `blackhole` past the facade's limit, which the
//! probe turns into `Timeout` itself.
//!
//! So a check that hangs outside the probe (a loop that never awaits, a lock) hangs the test too, until
//! the test runner kills it. Wrap the call in `tokio::time::timeout` if the check could do that. In a
//! real run the scheduler's timeout ends such a check.

use std::path::{Component, Path};

use rdy_spec::result::{Action, ActionKind, ActionOutcome};
use serde_json::Value;

use super::{Fixture, FixtureError, TestRun, fixtures_dir};
use crate::check::{Check, CheckError, CheckInfo, CheckOutcome, Finding};
use crate::probe::sock::{RULE_UDP_UNDECLARED, RULE_UNIX_UNDECLARED};
use crate::probe::{
    ActionLogOutput, RULE_COMMAND_UNDECLARED, RULE_ENV_NOT_DECLARED, RULE_ENV_UNDECLARED,
    RULE_OUTSIDE_READS, RULE_OUTSIDE_STATFS,
};

/// The refusals that mean "the check went beyond what its `CheckInfo` declares".
const MANIFEST_RULES: [&str; 7] = [
    RULE_OUTSIDE_READS,
    RULE_OUTSIDE_STATFS,
    RULE_COMMAND_UNDECLARED,
    RULE_ENV_UNDECLARED,
    RULE_ENV_NOT_DECLARED,
    RULE_UDP_UNDECLARED,
    RULE_UNIX_UNDECLARED,
];

/// What one check did against one fixture.
#[derive(Debug)]
pub struct FixtureRun {
    fixture: Fixture,
    info: &'static CheckInfo,
    outcome: CheckOutcome,
    log: ActionLogOutput,
}

impl FixtureRun {
    /// The fixture the check ran against.
    #[must_use]
    pub fn fixture(&self) -> &Fixture {
        &self.fixture
    }

    /// The check's static facts.
    #[must_use]
    pub fn info(&self) -> &'static CheckInfo {
        self.info
    }

    /// What the check returned.
    #[must_use]
    pub fn outcome(&self) -> &CheckOutcome {
        &self.outcome
    }

    /// The finding, for a test that expects the check to have one.
    ///
    /// # Panics
    ///
    /// When the check returned an error. The message names the fixture and the error.
    #[must_use]
    pub fn finding(&self) -> &Finding {
        match &self.outcome {
            Ok(finding) => finding,
            Err(error) => panic!(
                "{} on fixture {} returned an error, not a finding: {error}",
                self.info.id,
                self.fixture.name()
            ),
        }
    }

    /// The error, for a test that expects the check to have failed or been skipped.
    ///
    /// # Panics
    ///
    /// When the check returned a finding.
    #[must_use]
    pub fn error(&self) -> &CheckError {
        match &self.outcome {
            Err(error) => error,
            Ok(finding) => panic!(
                "{} on fixture {} returned a finding, not an error: {:?}",
                self.info.id,
                self.fixture.name(),
                finding.level
            ),
        }
    }

    /// The action log the run wrote.
    #[must_use]
    pub fn log(&self) -> &ActionLogOutput {
        &self.log
    }

    /// Fails the test if the check went beyond its declaration. See [`assert_within_manifest`].
    ///
    /// # Panics
    ///
    /// When the log holds a refusal by the check's manifest, or a refused file call outside its declared
    /// reads.
    pub fn assert_within_manifest(&self) {
        assert_within_manifest(self.fixture.name(), self.info, &self.log);
    }
}

/// Runs `check` against the fixture `name` under `tests/fixtures` (for example
/// `checks/host.memory/pass`).
///
/// The fixture must list the check in `answers` (`Fixture::ensure_answers`). Otherwise this fails with
/// [`FixtureError::DoesNotAnswer`], which names the check, before the check runs, so a fixture that was
/// never recorded for it does not show up as a `NotRecorded` in the middle of a run.
///
/// # Errors
///
/// [`FixtureError`] when the fixture does not load or does not answer the check.
pub async fn run_fixture(check: &dyn Check, name: &str) -> Result<FixtureRun, FixtureError> {
    run_fixture_in(&fixtures_dir(), check, name).await
}

/// Like [`run_fixture`], with the fixtures directory `root`. The loader's own tests use it with a
/// temporary directory.
///
/// # Errors
///
/// [`FixtureError`] when the fixture does not load or does not answer the check.
pub async fn run_fixture_in(
    root: &Path,
    check: &dyn Check,
    name: &str,
) -> Result<FixtureRun, FixtureError> {
    run_loaded(check, Fixture::load(root, name)?).await
}

/// Like [`run_fixture`], over a fixture that is already loaded.
///
/// # Errors
///
/// [`FixtureError::DoesNotAnswer`] when the fixture does not list the check.
pub async fn run_loaded(check: &dyn Check, fixture: Fixture) -> Result<FixtureRun, FixtureError> {
    let info = check.info();
    fixture.ensure_answers(info.id)?;

    let available = fixture.available_needs();
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(info, info.id, fixture.os(), available.iter().cloned());
    // The scheduler does not start a check whose hard need is missing. Neither does this.
    let outcome = match info.needs.iter().find(|need| !available.contains(need)) {
        Some(need) => Err(CheckError::MissingNeed(need.clone())),
        None => check.run(&ctx).await,
    };
    Ok(FixtureRun {
        log: run.action_log(),
        fixture,
        info,
        outcome,
    })
}

/// What in `log` went beyond a check's declaration, one line per refusal. Empty when nothing did.
///
/// A probe bound to a `CheckInfo` refuses a read, `stat`, listing, command, environment variable or
/// peer that the info does not declare, and logs the refusal as `denied` with the rule. A check that
/// swallows the error still leaves the entry, so this finds it.
///
/// The read policy runs other rules first: the deny list (`/etc/shadow`, `~/.ssh`, `/dev`), the
/// relative path and `..` rules, and the Windows rule. A file entry refused by one of those hides the
/// manifest rule. So a refused file entry also counts when its logged path is not covered by the info's
/// `reads` (or `statfs`, for a `statvfs` call). A declared prefix that covers a denied path is the
/// check's own bug and is not reported here.
#[must_use]
pub fn manifest_violations(info: &CheckInfo, log: &ActionLogOutput) -> Vec<String> {
    log.actions
        .iter()
        .filter(|action| action.outcome == ActionOutcome::Denied)
        .filter_map(|action| {
            let rule = action.fields.get("rule").and_then(Value::as_str)?;
            if !MANIFEST_RULES.contains(&rule) && !undeclared_file(info, action) {
                return None;
            }
            let kind = serde_json::to_value(&action.kind)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("{:?}", action.kind));
            let target = ["path", "program", "name", "host"]
                .iter()
                .find_map(|key| action.fields.get(*key).and_then(Value::as_str))
                .unwrap_or("?");
            Some(format!("entry {} ({kind} {target}): {rule}", action.seq))
        })
        .collect()
}

/// A file call (read, listing, `stat`, `statvfs`) whose logged path no declared prefix covers.
fn undeclared_file(info: &CheckInfo, action: &Action) -> bool {
    let declared: &[&str] = if action.kind == ActionKind::Read
        || action.kind == ActionKind::ReadDir
        || action.kind == ActionKind::Stat
    {
        info.reads
    } else if action.kind == ActionKind::Native
        && action.fields.get("api").and_then(Value::as_str) == Some("statvfs")
    {
        info.statfs
    } else {
        return false;
    };
    let Some(path) = action.fields.get("path").and_then(Value::as_str) else {
        return false;
    };
    let path = Path::new(path);
    // Compared as written, by whole components. A relative path, `..` or the `~` the log shows for a
    // home directory is never inside an absolute prefix, so `/etc/../etc/shadow` does not pass for
    // `/etc`.
    let plain = path.is_absolute() && path.components().all(|c| c != Component::ParentDir);
    !(plain && declared.iter().any(|prefix| path.starts_with(prefix)))
}

/// Fails the test if the check in `log` went beyond what `info` declares.
///
/// `what` names the fixture or case in the failure text.
///
/// # Panics
///
/// When [`manifest_violations`] is not empty. The message lists each refusal.
pub fn assert_within_manifest(what: &str, info: &CheckInfo, log: &ActionLogOutput) {
    let violations = manifest_violations(info, log);
    assert!(
        violations.is_empty(),
        "{what}: the check went beyond its declared manifest. Fix: declare the read, command, \
         variable or peer in its CheckInfo, or stop the check from using it.\n  {}",
        violations.join("\n  ")
    );
}
