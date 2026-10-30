//! The fixture completeness rule (M1-075, correction-21, 08 section 2 "The fixture lint").
//!
//! The fixture lint in `rdy-engine` cannot see the check families, so it cannot ask which checks exist.
//! This module can. For every check that a registered family lists and that is not on the family's stub
//! list (an implemented check), `tests/fixtures/checks/<id>/` must hold the cases 08 names:
//!
//! | Class | Needed when | What counts |
//! | --- | --- | --- |
//! | `Pass` | always | a case whose `expect.json` has `result.level` `pass` |
//! | `NonPass` | always | a case whose `result.level` is `warn` or `fail` |
//! | `Partial` | the check has a `Root` want | a case with `caps.root = false` and `result.partial` set |
//! | `Timeout` | the check declares a command, a peer or a `statfs` prefix | a case with `result.timed_out_ms` whose `native`, `commands`, `api` or `net.json` files hold a `blackhole` or a `delay_ms` of at least the check's timeout |
//!
//! A case counts only through its `expect.json`, the reviewed result. A case that loads but has no
//! `expect.json` proves nothing about what the check says, so it is not counted. The shape of the `result`
//! object that this rule reads is in `tests/fixtures/README.md`.
//!
//! `PENDING` lists what is still owed, per check and class, with the ticket that owes it. A class that is
//! missing and not listed is a finding, so a new check cannot ship without its cases. A listed class that
//! is no longer missing is a finding too, so the list cannot go stale.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{CheckInfo, Need};
use rdy_engine::testing::Fixture;
use serde_json::Value;

use super::families::Row;

/// A kind of case an implemented check needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// A passing case.
    Pass,
    /// A warn or fail case.
    NonPass,
    /// A run without root that gives a partial result.
    Partial,
    /// A source that hangs, so the check ends in `Timeout`.
    Timeout,
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pass => "a passing case (expect.json with result.level pass)",
            Self::NonPass => "a non-passing case (result.level warn or fail)",
            Self::Partial => {
                "a no-privilege partial case (caps.root false, result.partial set)"
            }
            Self::Timeout => {
                "a Timeout case (result.timed_out_ms, and a blackhole or a delay_ms at the check's timeout in its files)"
            }
        })
    }
}

/// Cases an implemented check still owes, and who owes them.
pub struct Pending {
    /// The check id.
    pub check: &'static str,
    /// The classes that are still missing.
    pub classes: &'static [Class],
    /// The ticket that adds them.
    pub owner: &'static str,
    /// Why they are not there.
    pub why: &'static str,
}

/// The time the engine gives `info` before it ends the check: its own default, or 10 s, and never more
/// than 60 s (`CheckInfo::default_timeout`).
fn timeout_ms(info: &CheckInfo) -> u128 {
    info.default_timeout
        .unwrap_or(Duration::from_secs(10))
        .min(Duration::from_secs(60))
        .as_millis()
}

/// The classes `info` needs.
fn required(info: &CheckInfo) -> BTreeSet<Class> {
    let mut classes = BTreeSet::from([Class::Pass, Class::NonPass]);
    if info.wants.iter().any(|want| want.need == Need::Root) {
        classes.insert(Class::Partial);
    }
    if !info.commands.is_empty() || !info.peers.is_empty() || !info.statfs.is_empty() {
        classes.insert(Class::Timeout);
    }
    classes
}

/// Every finding for `rows` against the fixtures in `fixtures`, sorted. Empty means complete.
///
/// `Err` is for a tree that cannot be read at all, not for a missing case.
pub fn findings(rows: &[Row], fixtures: &Path, pending: &[Pending]) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut implemented: BTreeSet<&str> = BTreeSet::new();
    let mut stubbed: BTreeSet<&str> = BTreeSet::new();

    for row in rows {
        let ids: BTreeSet<&str> = row.family.checks().iter().map(|info| info.id).collect();
        for stub in row.stubs {
            if ids.contains(stub) {
                stubbed.insert(stub);
            } else {
                found.push(format!(
                    "{stub}: on the stub list of family {} but not registered by it. Fix: remove it from the stub list",
                    row.family.name()
                ));
            }
        }
        for info in row.family.checks() {
            if !row.stubs.contains(&info.id) {
                implemented.insert(info.id);
            }
        }
    }

    for row in rows {
        for info in row.family.checks() {
            if !implemented.contains(info.id) {
                continue;
            }
            let rows_for: Vec<&Pending> = pending.iter().filter(|p| p.check == info.id).collect();
            if rows_for.len() > 1 {
                found.push(format!(
                    "{}: two PENDING rows. Fix: merge them into one",
                    info.id
                ));
            }
            let owed: BTreeSet<Class> = rows_for
                .iter()
                .flat_map(|p| p.classes.iter().copied())
                .collect();
            let dir = fixtures.join("checks").join(info.id);
            if !dir.is_dir() {
                found.push(format!(
                    "tests/fixtures/checks/{}: the check is implemented and has no fixture directory (08 section 2). Fix: add cases with expect.json, one per class in 08",
                    info.id
                ));
                continue;
            }
            let have = classes_of(fixtures, info.id, timeout_ms(info), &mut found)?;
            let missing: BTreeSet<Class> = required(info).difference(&have).copied().collect();
            for class in missing.difference(&owed) {
                found.push(format!(
                    "tests/fixtures/checks/{}: lacks {class} (08 section 2). Fix: add the case with an expect.json, or add a PENDING row naming the ticket that will",
                    info.id
                ));
            }
            for class in owed.difference(&missing) {
                let (owner, why) = rows_for
                    .iter()
                    .find(|p| p.classes.contains(class))
                    .map_or(("", ""), |p| (p.owner, p.why));
                found.push(format!(
                    "{}: PENDING lists {class}, but it is not missing (or the check does not need it). It was owed by {owner}: {why}. Fix: delete it from the row",
                    info.id
                ));
            }
        }
    }

    for row in pending {
        if stubbed.contains(row.check) {
            found.push(format!(
                "{}: PENDING row for a stub. Fix: delete it; the rule starts when the check is implemented",
                row.check
            ));
        } else if !implemented.contains(row.check) {
            found.push(format!(
                "{}: PENDING row for a check no family registers. Fix: delete it",
                row.check
            ));
        }
    }

    found.sort();
    found.dedup();
    Ok(found)
}

/// The classes the cases of `id` cover, from their `expect.json`. A case that does not load, or does not
/// answer `id`, is a finding. `timeout_ms` is what a hang has to reach.
fn classes_of(
    fixtures: &Path,
    id: &str,
    timeout_ms: u128,
    found: &mut Vec<String>,
) -> Result<BTreeSet<Class>, String> {
    let dir = fixtures.join("checks").join(id);
    let mut cases = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        if entry.path().is_dir() {
            cases.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    cases.sort();

    let mut have = BTreeSet::new();
    for case in cases {
        let case_dir = dir.join(&case);
        let expect_path = case_dir.join("expect.json");
        if !expect_path.is_file() {
            continue;
        }
        let name = format!("checks/{id}/{case}");
        let text = std::fs::read_to_string(&expect_path)
            .map_err(|e| format!("{}: {e}", expect_path.display()))?;
        let Ok(expect) = serde_json::from_str::<Value>(&text) else {
            found.push(format!(
                "tests/fixtures/{name}/expect.json: not JSON. Fix: regenerate it with UPDATE_GOLDENS=1"
            ));
            continue;
        };
        let fixture = match Fixture::load(fixtures, &name) {
            Ok(fixture) => fixture,
            Err(error) => {
                found.push(format!("tests/fixtures/{name}: does not load: {error}"));
                continue;
            }
        };
        if fixture.ensure_answers(id).is_err() {
            found.push(format!(
                "tests/fixtures/{name}: has an expect.json for {id} but its `answers` does not list it. Fix: add {id} to `answers`"
            ));
            continue;
        }
        let result = expect.get("result").unwrap_or(&Value::Null);
        match result.get("level").and_then(Value::as_str) {
            Some("pass") => {
                have.insert(Class::Pass);
            }
            Some("warn" | "fail") => {
                have.insert(Class::NonPass);
            }
            _ => {}
        }
        if !fixture.manifest().caps.root && result.get("partial").is_some_and(|p| !p.is_null()) {
            have.insert(Class::Partial);
        }
        if result.get("timed_out_ms").is_some_and(Value::is_number)
            && holds_a_hang(&case_dir, timeout_ms)?
        {
            have.insert(Class::Timeout);
        }
    }
    Ok(have)
}

/// Whether the case in `dir` scripts a hang: a `delay_ms` of at least `timeout_ms` in a `native`,
/// `commands` or `api` file, or a `blackhole` entry in `net.json`. A shorter delay lets the check finish,
/// and a `delay_ms` of 0 is what a recording writes by default, so neither is a hang. Every file is parsed,
/// so a text that only mentions the word does not count.
fn holds_a_hang(dir: &Path, timeout_ms: u128) -> Result<bool, String> {
    for sub in ["native", "commands", "api"] {
        let sub_dir = dir.join(sub);
        if !sub_dir.is_dir() {
            continue;
        }
        for path in json_files(&sub_dir)? {
            if has_delay(&read_json(&path)?, timeout_ms) {
                return Ok(true);
            }
        }
    }
    let net = dir.join("net.json");
    Ok(net.is_file() && has_blackhole(&read_json(&net)?))
}

/// Every `.json` file below `dir`, in name order.
fn json_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            files.extend(json_files(&path)?);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: not JSON: {e}", path.display()))
}

/// A `delay_ms` of at least `timeout_ms` on the file's own object.
fn has_delay(file: &Value, timeout_ms: u128) -> bool {
    file.get("delay_ms")
        .and_then(Value::as_u64)
        .is_some_and(|delay| u128::from(delay) >= timeout_ms)
}

/// A `blackhole` as the value of a `tcp` address in a `net.json`.
fn has_blackhole(net: &Value) -> bool {
    net.get("tcp")
        .and_then(Value::as_object)
        .is_some_and(|tcp| tcp.values().any(|v| v.as_str() == Some("blackhole")))
}
