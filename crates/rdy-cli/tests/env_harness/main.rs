//! The env-level harness, in process (M1-075, 08 sections 2 and 3), and the fixture completeness rule
//! (correction-21).
//!
//! Environments. Every directory under `tests/fixtures/envs` that has a `spec` in its `fixture.toml` is
//! run through the engine (`driver::run_env`) with the clock, run id and environment pinned by its
//! `[run]` table. The test compares the exit code and verdict with `[expect]`, the report with
//! `golden/report.json` through `assert_golden`, and the report at `jobs = 1` with the report at
//! `jobs = 8`. Adding a directory adds a run, with no code change. A directory with no `spec` is a base
//! that other environments build on and is skipped.
//!
//! Not here yet: `terminal.txt` (the human renderer, M1-086), `report.html` (M1-077) and the call to
//! `rdy_cli::run` itself (M1-086, which also regenerates the golden from `--json` stdout). `driver` says
//! where they plug in.
//!
//! Completeness. `completeness` walks the registered families and fails when an implemented check has no
//! fixture case for a class 08 names. The rule is proven on a planted family below.

mod completeness;
mod driver;
mod families;

use std::error::Error;
use std::path::Path;

use completeness::{Class, Pending, findings};
use jsonschema::Validator;
use rdy_engine::check::{CheckInfo, CheckMeta, Need, OsSupport, Support, Want};
use rdy_engine::family::{BuildError, Built, Family};
use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, fixtures_dir, normalize, normalize_across_jobs};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::Value;

use families::Row;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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

        // The same environment at one job and at eight gives the same report. With one check this proves
        // little; M1-117's all-pass env is what gives it something to order.
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
/// A case counts only through its `expect.json`. The checks below were merged with cases that their own
/// Rust tests assert by hand, so the goldens are owed, not the cases. M1-174 (backlog correction-29) writes
/// the `expect.json` files for all six. Each row shrinks when its files land, and the stale-row finding
/// forces the edit.
const PENDING: &[Pending] = &[
    Pending {
        check: "host.cpu",
        classes: &[Class::Pass, Class::NonPass],
        owner: "M1-174",
        why: "its cases are asserted in rdy-checks-host tests and have no expect.json",
    },
    Pending {
        check: "host.firewall",
        classes: &[Class::Pass, Class::NonPass, Class::Partial, Class::Timeout],
        owner: "M1-174",
        why: "no expect.json, and Replay cannot yet hang or deny the firewall reads (PR #98)",
    },
    Pending {
        check: "host.lsm",
        classes: &[Class::Pass, Class::NonPass, Class::Partial],
        owner: "M1-174",
        why: "its cases are asserted in rdy-checks-host tests and have no expect.json",
    },
    Pending {
        check: "host.memory",
        classes: &[Class::Pass, Class::NonPass],
        owner: "M1-174",
        why: "expect.json goldens were deferred in PR #116",
    },
    Pending {
        check: "host.os",
        classes: &[Class::Pass, Class::NonPass],
        owner: "M1-174",
        why: "its cases are asserted in rdy-checks-host tests and have no expect.json",
    },
    Pending {
        check: "host.security_agents",
        classes: &[Class::Pass, Class::NonPass, Class::Partial],
        owner: "M1-174",
        why: "its cases are asserted in rdy-checks-host tests and have no expect.json",
    },
];

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
        let timed_out = if self.hang.is_some() {
            r#", "timed_out_ms": 5000"#
        } else {
            ""
        };
        std::fs::write(
            dir.join("expect.json"),
            format!(
                "{{\"entry\": {{\"id\": \"{}\"}}, \"result\": {{\"level\": \"{}\", \"partial\": {partial}{timed_out}}}}}\n",
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
