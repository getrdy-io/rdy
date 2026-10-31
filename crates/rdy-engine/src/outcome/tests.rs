//! Tests for the outcome mapping, with fake check infos. No scheduler is needed: each test builds the
//! outcome by hand and maps it.

use std::time::Duration;

use rdy_spec::result::{
    Bucket, ErrorKind, FixSource, Need as WireNeed, Severity, SkipKind, Status, Verdict, verdict,
};
use rdy_spec::spec::{CheckSpec, FixText, Lenient, Severity as SpecSeverity};
use serde_json::json;

use super::*;
use crate::check::{CheckMeta, Level, OsSupport, Want};

const VENDOR_FIX: &str = "Add RAM or choose a larger node class.";
const RDY_FIX: &str = "Add memory to the machine.";

static FULL: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

static PARTIAL_ON_WINDOWS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Partial("environment variables only"),
};

const fn info(
    id: &'static str,
    needs: &'static [Need],
    wants: &'static [Want],
    os: OsSupport,
) -> CheckInfo {
    CheckInfo {
        id,
        family: "fake",
        summary: "A fake check.",
        meta: CheckMeta {
            title: "Fake check",
            remediation: "Nothing to fix. This check is a test double.",
        },
        needs,
        wants,
        default_timeout: Some(Duration::from_secs(5)),
        os,
        reads: &[],
        statfs: &[],
        env: &[],
        commands: &[],
        peers: &[],
    }
}

/// No needs, full support everywhere.
static PLAIN: CheckInfo = info("fake.plain", &[], &[], FULL);

/// A hard need for root, a soft want for `ss` that only adds detail, and a soft want for `ip` that
/// can change the level.
static WITH_WANTS: CheckInfo = info(
    "fake.wants",
    &[Need::Root],
    &[
        Want {
            need: Need::Command("ss"),
            evidence_only: true,
        },
        Want {
            need: Need::Command("ip"),
            evidence_only: false,
        },
    ],
    FULL,
);

/// Only the evidence-only want.
static EVIDENCE_WANT: CheckInfo = info(
    "fake.evidence",
    &[],
    &[Want {
        need: Need::Command("ss"),
        evidence_only: true,
    }],
    FULL,
);

/// Full on Linux, partial on Windows, with an evidence-only want.
static PARTIAL_OS: CheckInfo = info(
    "fake.partial_os",
    &[],
    &[Want {
        need: Need::Command("ss"),
        evidence_only: true,
    }],
    PARTIAL_ON_WINDOWS,
);

fn ctx_on(os: Os, key: &str, available: &[Need]) -> CheckContext {
    CheckContext::new(key, os, available.iter().cloned())
}

fn ctx(key: &str, available: &[Need]) -> CheckContext {
    ctx_on(Os::Linux, key, available)
}

fn entry(id: &str) -> CheckSpec {
    CheckSpec::new(id)
}

fn entry_with_fix(id: &str) -> CheckSpec {
    let mut entry = CheckSpec::new(id);
    entry.fix = Some(Lenient::Valid(FixText::new(VENDOR_FIX).expect("valid fix")));
    entry
}

fn warn_only(mut entry: CheckSpec) -> CheckSpec {
    entry.severity = Some(Lenient::Valid(SpecSeverity::Warn));
    entry
}

fn map(
    info: &CheckInfo,
    entry: &CheckSpec,
    ctx: &CheckContext,
    outcome: CheckOutcome,
) -> CheckResult {
    map_outcome(info, entry, ctx, outcome, 5, 7)
}

#[test]
fn a_spec_fix_replaces_the_built_in_text_on_block() {
    let finding = Finding::fail("3 GiB of 16 GiB").with_fix(RDY_FIX);
    let result = map(
        &PLAIN,
        &entry_with_fix("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Block);
    assert_eq!(result.bucket, Bucket::Blocker);
    assert_eq!(result.fix.as_deref(), Some(VENDOR_FIX));
    assert_eq!(result.fix_source, Some(FixSource::FromSpec));
    assert_eq!(result.builtin_fix.as_deref(), Some(RDY_FIX));
}

#[test]
fn a_spec_fix_replaces_the_built_in_text_on_warn_and_is_kept_verbatim() {
    let mut entry = warn_only(entry("fake.plain"));
    entry.fix = Some(Lenient::Valid(
        FixText::new("Line one.\n{not a template} <b>x</b>").expect("valid fix"),
    ));
    let result = map(
        &PLAIN,
        &entry,
        &ctx("fake.plain", &[]),
        Ok(Finding::fail("low").with_fix(RDY_FIX)),
    );
    assert_eq!(result.severity, Severity::Warn);
    assert_eq!(result.status, Status::Warn);
    assert_eq!(result.bucket, Bucket::Warning);
    assert_eq!(
        result.fix.as_deref(),
        Some("Line one.\n{not a template} <b>x</b>")
    );
    assert_eq!(result.fix_source, Some(FixSource::FromSpec));

    let level_warn = map(
        &PLAIN,
        &entry_with_fix("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::warn("close to the limit")),
    );
    assert_eq!(level_warn.status, Status::Warn);
    assert_eq!(level_warn.fix.as_deref(), Some(VENDOR_FIX));
    assert_eq!(level_warn.builtin_fix, None, "rdy gave no text to move");
}

#[test]
fn a_spec_fix_is_hidden_on_every_skipped_result() {
    let with_fix = entry_with_fix("fake.wants");
    let context = ctx("fake.wants", &[]);
    let errors = [
        CheckError::MissingNeed(Need::Root),
        CheckError::MissingNeed(Need::KubeContext),
        CheckError::MissingNeed(Need::Network),
        CheckError::MissingNeed(Need::Command("ss")),
        CheckError::Unsupported("no data source"),
    ];
    for error in errors {
        let result = map(&WITH_WANTS, &with_fix, &context, Err(error.clone()));
        assert_eq!(result.status, Status::Skipped, "{error:?}");
        assert_eq!(result.fix_source, Some(FixSource::Rdy), "{error:?}");
        assert_eq!(result.builtin_fix, None, "{error:?}");
        let fix = result.fix.expect("a skip has a fix");
        assert!(!fix.is_empty(), "{error:?}");
        assert_ne!(fix, VENDOR_FIX, "{error:?}");
        assert!(result.message.starts_with("Not run."), "{}", result.message);
    }
}

#[test]
fn a_failed_check_is_an_error_with_rdy_text_and_the_spec_fix_hidden() {
    let result = map(
        &PLAIN,
        &entry_with_fix("fake.plain"),
        &ctx("fake.plain", &[]),
        Err(CheckError::Failed {
            message: "could not parse /proc/meminfo".to_owned(),
            hint: "Report this to the vendor.".to_owned(),
        }),
    );
    assert_eq!(result.status, Status::Error);
    assert_eq!(result.error_kind, Some(ErrorKind::CheckFailed));
    assert_eq!(result.skip_kind, None);
    assert_eq!(result.message, "could not parse /proc/meminfo");
    assert_eq!(result.fix.as_deref(), Some("Report this to the vendor."));
    assert_eq!(result.fix_source, Some(FixSource::Rdy));
    assert_eq!(result.bucket, Bucket::RequiredNotRun);

    let empty_hint = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Err(CheckError::Failed {
            message: "boom".to_owned(),
            hint: String::new(),
        }),
    );
    assert!(!empty_hint.fix.expect("fix").is_empty());
}

#[test]
fn a_pass_has_no_fix_and_no_fix_source() {
    let finding = Finding::pass("16 GiB").with_fix("never shown");
    let result = map(
        &PLAIN,
        &entry_with_fix("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Pass);
    assert_eq!(result.bucket, Bucket::Passed);
    assert_eq!(result.fix, None);
    assert_eq!(result.fix_source, None);
    assert_eq!(result.builtin_fix, None);
    assert_eq!(result.partial, None);
}

#[test]
fn without_a_spec_fix_rdy_text_is_the_fix_and_there_is_no_builtin_fix() {
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::fail("low").with_fix(RDY_FIX)),
    );
    assert_eq!(result.fix.as_deref(), Some(RDY_FIX));
    assert_eq!(result.fix_source, Some(FixSource::Rdy));
    assert_eq!(result.builtin_fix, None);
}

#[test]
fn a_block_or_warn_with_no_fix_of_its_own_and_none_in_the_spec_shows_the_check_remediation() {
    for finding in [Finding::fail("low"), Finding::warn("low")] {
        let result = map(
            &PLAIN,
            &entry("fake.plain"),
            &ctx("fake.plain", &[]),
            Ok(finding),
        );
        assert_eq!(result.fix.as_deref(), Some(PLAIN.meta.remediation));
        assert_eq!(result.fix_source, Some(FixSource::Rdy));
        assert_eq!(result.builtin_fix, None);
    }
}

#[test]
fn a_spec_fix_still_wins_over_the_remediation() {
    let result = map(
        &PLAIN,
        &entry_with_fix("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::fail("low")),
    );
    assert_eq!(result.fix.as_deref(), Some(VENDOR_FIX));
    assert_eq!(result.fix_source, Some(FixSource::FromSpec));
    assert_eq!(result.builtin_fix, None);
}

#[test]
fn a_blank_remediation_falls_back_to_the_generic_no_advice_text() {
    static BLANK: CheckInfo = CheckInfo {
        meta: CheckMeta {
            title: "Blank",
            remediation: "  ",
        },
        ..info("fake.blank", &[], &[], FULL)
    };
    let result = map(
        &BLANK,
        &entry("fake.blank"),
        &ctx("fake.blank", &[]),
        Ok(Finding::fail("low")),
    );
    assert_eq!(
        result.fix.as_deref(),
        Some("rdy has no advice for this result. Tell the vendor which check it was.")
    );
}

#[test]
fn an_invalid_spec_fix_is_not_used() {
    let mut bad = entry("fake.plain");
    bad.fix = Some(Lenient::Invalid(json!("")));
    let result = map(
        &PLAIN,
        &bad,
        &ctx("fake.plain", &[]),
        Ok(Finding::fail("low").with_fix(RDY_FIX)),
    );
    assert_eq!(result.fix.as_deref(), Some(RDY_FIX));
    assert_eq!(result.fix_source, Some(FixSource::Rdy));
}

#[test]
fn level_and_severity_give_the_status() {
    let cases = [
        (Level::Pass, false, Status::Pass),
        (Level::Warn, false, Status::Warn),
        (Level::Fail, false, Status::Block),
        (Level::Pass, true, Status::Pass),
        (Level::Warn, true, Status::Warn),
        (Level::Fail, true, Status::Warn),
    ];
    for (level, optional, expected) in cases {
        let base = entry("fake.plain");
        let entry = if optional { warn_only(base) } else { base };
        let result = map(
            &PLAIN,
            &entry,
            &ctx("fake.plain", &[]),
            Ok(Finding::new(level, "m")),
        );
        assert_eq!(result.status, expected, "{level:?} optional={optional}");
    }
}

#[test]
fn a_partial_pass_on_a_block_check_becomes_warn() {
    let finding = Finding::pass("looks fine")
        .with_fix("Run as root.")
        .with_partial(Partial::new(
            vec![Need::Root],
            "Root-only counters were not read.",
        ));
    let result = map(
        &PLAIN,
        &entry_with_fix("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Warn);
    assert_eq!(result.bucket, Bucket::Warning);
    assert_eq!(result.message, "not verified: root");
    assert_eq!(
        result.notes,
        ["What the check could read passed: looks fine"]
    );
    let partial = result.partial.expect("partial is kept");
    assert_eq!(partial.missing, [WireNeed::Root]);
    assert_eq!(partial.note, "Root-only counters were not read.");
    // Nothing was measured as failing, so the vendor's fix is not shown.
    assert_eq!(result.fix.as_deref(), Some("Run as root."));
    assert_eq!(result.fix_source, Some(FixSource::Rdy));
    assert_eq!(result.builtin_fix, None);
}

#[test]
fn a_partial_pass_without_a_check_fix_gets_a_generic_fix_naming_the_need() {
    let finding =
        Finding::pass("ok").with_partial(Partial::new(vec![Need::KubeContext], "no cluster"));
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Warn);
    assert_eq!(
        result.fix.as_deref(),
        Some("Make kube_context available and run rdy again.")
    );
}

#[test]
fn a_partial_pass_on_an_optional_check_stays_pass() {
    let finding = Finding::pass("ok").with_partial(Partial::new(vec![Need::Root], "no root"));
    let result = map(
        &PLAIN,
        &warn_only(entry("fake.plain")),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Pass);
    assert!(result.partial.is_some());
    assert_eq!(result.fix, None);
}

#[test]
fn a_partial_pass_stays_pass_when_every_missing_need_is_evidence_only() {
    let finding = Finding::pass("ok")
        .with_partial(Partial::new(vec![Need::Command("ss")], "ss was not found"));
    let result = map(
        &EVIDENCE_WANT,
        &entry("fake.evidence"),
        &ctx("fake.evidence", &[]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Pass);
    assert_eq!(result.bucket, Bucket::Passed);
    let partial = result.partial.expect("still marked partial");
    assert_eq!(partial.missing, [WireNeed::Command]);
}

#[test]
fn a_missing_want_makes_the_result_partial_without_the_check_saying_so() {
    // The check passes and does not mention that `ss` is missing. The engine does.
    let result = map(
        &EVIDENCE_WANT,
        &entry("fake.evidence"),
        &ctx("fake.evidence", &[]),
        Ok(Finding::pass("ok")),
    );
    assert_eq!(
        result.status,
        Status::Pass,
        "evidence only cannot change the level"
    );
    let partial = result.partial.expect("partial");
    assert_eq!(partial.missing, [WireNeed::Command]);
    assert_eq!(partial.note, "Could not use: command ss.");

    // With the want met there is no partial.
    let met = map(
        &EVIDENCE_WANT,
        &entry("fake.evidence"),
        &ctx("fake.evidence", &[Need::Command("ss")]),
        Ok(Finding::pass("ok")),
    );
    assert_eq!(met.partial, None);
}

#[test]
fn a_missing_want_that_can_change_the_level_downgrades_a_pass() {
    let result = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx("fake.wants", &[Need::Root, Need::Command("ss")]),
        Ok(Finding::pass("ok")),
    );
    assert_eq!(result.status, Status::Warn);
    assert_eq!(result.message, "not verified: command ip");
}

#[test]
fn two_commands_are_not_confused_when_only_one_is_evidence_only() {
    // `ss` (evidence only) and `ip` (not) are both missing. They share the wire value `command`.
    let result = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx("fake.wants", &[Need::Root]),
        Ok(Finding::pass("ok")),
    );
    assert_eq!(result.status, Status::Warn);
    assert_eq!(result.message, "not verified: command ss, command ip");
    let partial = result.partial.expect("partial");
    assert_eq!(
        partial.missing,
        [WireNeed::Command],
        "wire needs are listed once"
    );
}

#[test]
fn a_failed_level_with_a_partial_is_not_changed() {
    let finding = Finding::fail("low").with_partial(Partial::new(vec![Need::Root], "no root"));
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Block);
    assert_eq!(result.message, "low");
    assert!(result.partial.is_some());
}

#[test]
fn a_result_from_a_partial_os_is_marked_partial_and_a_pass_becomes_warn() {
    let result = map(
        &PARTIAL_OS,
        &entry("fake.partial_os"),
        &ctx_on(Os::Windows, "fake.partial_os", &[Need::Command("ss")]),
        Ok(Finding::pass("ok")),
    );
    let partial = result.partial.expect("a partial OS always sets partial");
    assert_eq!(partial.note, "environment variables only");
    assert!(partial.missing.is_empty());
    assert_eq!(result.status, Status::Warn);
    assert_eq!(result.message, "not verified: environment variables only");
    assert_eq!(
        result.fix.as_deref(),
        Some("Run rdy again on an OS where this check has full support.")
    );

    // Full support on Linux: no partial, a plain pass.
    let linux = map(
        &PARTIAL_OS,
        &entry("fake.partial_os"),
        &ctx("fake.partial_os", &[Need::Command("ss")]),
        Ok(Finding::pass("ok")),
    );
    assert_eq!(linux.status, Status::Pass);
    assert_eq!(linux.partial, None);
}

#[test]
fn a_partial_os_never_gets_the_evidence_only_exception() {
    // The missing want is evidence only, but the OS note is a reason of its own.
    let result = map(
        &PARTIAL_OS,
        &entry("fake.partial_os"),
        &ctx_on(Os::Windows, "fake.partial_os", &[]),
        Ok(Finding::pass("ok")),
    );
    assert_eq!(result.status, Status::Warn);
    let partial = result.partial.expect("partial");
    assert_eq!(partial.missing, [WireNeed::Command]);
    assert_eq!(partial.note, "environment variables only");
}

#[test]
fn a_partial_os_keeps_the_note_of_the_check_too() {
    let finding = Finding::fail("bad").with_partial(Partial::new(vec![], "proxy file not read"));
    let result = map(
        &PARTIAL_OS,
        &warn_only(entry("fake.partial_os")),
        &ctx_on(Os::Windows, "fake.partial_os", &[Need::Command("ss")]),
        Ok(finding),
    );
    assert_eq!(result.status, Status::Warn);
    let partial = result.partial.expect("partial");
    assert_eq!(
        partial.note,
        "environment variables only. proxy file not read"
    );
}

#[test]
fn missing_grants_are_a_field_of_the_wire_partial_once_each() {
    let finding = Finding::fail("denied").with_partial(
        Partial::new(vec![], "RBAC denied some reads").with_missing_grants(vec![
            "list nodes".to_owned(),
            "get pods".to_owned(),
            "list nodes".to_owned(),
        ]),
    );
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    let partial = result.partial.expect("partial");
    assert_eq!(partial.missing_grants, ["list nodes", "get pods"]);
    // They no longer go to the notes.
    assert!(
        result.notes.iter().all(|note| !note.contains("grants")),
        "{:?}",
        result.notes
    );
}

#[test]
fn missing_grants_are_cut_at_the_schema_cap_and_the_result_says_so() {
    let grants: Vec<String> = (0..1005).map(|n| format!("list thing{n}")).collect();
    let finding = Finding::pass("ok")
        .with_partial(Partial::new(vec![], "RBAC denied reads").with_missing_grants(grants));
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    let partial = result.partial.expect("partial");
    assert_eq!(partial.missing_grants.len(), 1000);
    assert_eq!(partial.missing_grants[0], "list thing0");
    assert_eq!(partial.missing_grants[999], "list thing999");
    assert!(result.truncated);

    // Exactly the cap, and duplicates past it, cut nothing.
    let mut exact: Vec<String> = (0..1000).map(|n| format!("list thing{n}")).collect();
    exact.push("list thing0".to_owned());
    let finding = Finding::pass("ok")
        .with_partial(Partial::new(vec![], "RBAC denied reads").with_missing_grants(exact));
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(finding),
    );
    assert_eq!(result.partial.expect("partial").missing_grants.len(), 1000);
    assert!(!result.truncated);
}

#[test]
fn a_partial_without_grants_has_an_empty_list() {
    let finding = Finding::pass("ok").with_partial(Partial::new(vec![Need::Root], "no root"));
    let result = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx("fake.wants", &[]),
        Ok(finding),
    );
    assert!(result.partial.expect("partial").missing_grants.is_empty());
}

#[test]
fn needs_carry_met_flags_in_order_with_names() {
    let met = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx("fake.wants", &[Need::Root, Need::Command("ss")]),
        Ok(Finding::pass("ok")),
    );
    let flat: Vec<(WireNeed, Option<&str>, bool, bool)> = met
        .needs
        .iter()
        .map(|n| (n.need.clone(), n.name.as_deref(), n.hard, n.met))
        .collect();
    assert_eq!(
        flat,
        [
            (WireNeed::Root, None, true, true),
            (WireNeed::Command, Some("ss"), false, true),
            (WireNeed::Command, Some("ip"), false, false),
        ]
    );

    // A skipped result lists them too, with the hard need unmet.
    let skipped = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx("fake.wants", &[]),
        Err(CheckError::MissingNeed(Need::Root)),
    );
    assert_eq!(skipped.needs.len(), 3);
    assert!(skipped.needs[0].hard && !skipped.needs[0].met);
    assert!(PLAIN.needs.is_empty());
    let plain = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::pass("ok")),
    );
    assert!(plain.needs.is_empty());
}

#[test]
fn a_missing_hard_need_is_skipped_missing_need() {
    let result = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx("fake.wants", &[]),
        Err(CheckError::MissingNeed(Need::Root)),
    );
    assert_eq!(result.status, Status::Skipped);
    assert_eq!(result.skip_kind, Some(SkipKind::MissingNeed));
    assert_eq!(result.bucket, Bucket::RequiredNotRun);
    assert_eq!(result.message, "Not run. This check needs root.");
    assert_eq!(result.partial, None);

    let optional = map(
        &WITH_WANTS,
        &warn_only(entry("fake.wants")),
        &ctx("fake.wants", &[]),
        Err(CheckError::MissingNeed(Need::Root)),
    );
    assert_eq!(optional.bucket, Bucket::Warning);
}

#[test]
fn an_unsupported_check_is_not_yet_on_os_and_names_the_os() {
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx_on(Os::Macos, "fake.plain", &[]),
        Err(CheckError::Unsupported("no /proc on macOS")),
    );
    assert_eq!(result.status, Status::Skipped);
    assert_eq!(result.skip_kind, Some(SkipKind::NotYetOnOs));
    assert_eq!(
        result.message,
        "Not run. This check does not work on macOS yet."
    );
    assert_eq!(result.notes, ["no /proc on macOS"]);
}

#[test]
fn no_outcome_maps_to_not_applicable() {
    let outcomes = [
        Ok(Finding::pass("p")),
        Ok(Finding::pass_by_absence("nothing to check here")),
        Ok(Finding::warn("w")),
        Ok(Finding::fail("f")),
        Err(CheckError::MissingNeed(Need::Root)),
        Err(CheckError::Unsupported("x")),
        Err(CheckError::Failed {
            message: "m".to_owned(),
            hint: "h".to_owned(),
        }),
    ];
    for outcome in outcomes {
        for optional in [false, true] {
            let base = entry("fake.plain");
            let entry = if optional { warn_only(base) } else { base };
            let result = map(&PLAIN, &entry, &ctx("fake.plain", &[]), outcome.clone());
            assert_ne!(result.skip_kind, Some(SkipKind::NotApplicable));
            assert_ne!(result.bucket, Bucket::NotApplicable);
        }
    }
}

#[test]
fn every_result_that_is_not_a_pass_has_a_non_empty_fix() {
    let outcomes = [
        Ok(Finding::warn("w")),
        Ok(Finding::fail("f")),
        Ok(Finding::pass("p").with_partial(Partial::new(vec![Need::Root], "n"))),
        Err(CheckError::MissingNeed(Need::Network)),
        Err(CheckError::Unsupported("x")),
        Err(CheckError::Failed {
            message: "m".to_owned(),
            hint: String::new(),
        }),
    ];
    for outcome in outcomes {
        let result = map(
            &PLAIN,
            &entry("fake.plain"),
            &ctx("fake.plain", &[]),
            outcome,
        );
        assert!(result.fix.as_deref().is_some_and(|f| !f.is_empty()));
        assert!(result.fix_source.is_some());
    }
}

#[test]
fn identity_timing_and_values_are_filled_in() {
    let mut named = entry("fake.plain");
    named.name = Some(Lenient::Valid(
        rdy_spec::spec::CheckName::new("data").expect("valid name"),
    ));
    let finding = Finding::pass("ok")
        .with_observed(json!({ "total_bytes": 42 }))
        .with_expected(json!({ "min_bytes": 40 }));
    let result = map_outcome(
        &PLAIN,
        &named,
        &ctx("fake.plain/data", &[]),
        Ok(finding),
        120,
        34,
    );
    assert_eq!(result.key, "fake.plain/data");
    assert_eq!(result.id, "fake.plain");
    assert_eq!(result.name.as_deref(), Some("data"));
    assert_eq!(result.family, "fake");
    assert_eq!(result.severity, Severity::Block);
    assert_eq!(result.started_ms, 120);
    assert_eq!(result.duration_ms, 34);
    assert!(!result.truncated);
    assert_eq!(result.observed.expect("observed")["total_bytes"], json!(42));
    assert_eq!(result.expected.expect("expected")["min_bytes"], json!(40));
}

#[test]
fn observed_and_expected_follow_the_object_rule() {
    let none = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::pass("ok")),
    );
    assert_eq!(none.observed, None);
    assert_eq!(none.expected, None);

    let scalar = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::pass("ok").with_observed(json!(3.5))),
    );
    assert_eq!(
        scalar.observed.expect("wrapped")["value"],
        json!(3.5),
        "a bare value is kept under `value`"
    );
}

#[test]
fn a_pass_by_absence_shows_its_note_once() {
    let note = "SELinux is not installed, and the spec allows disabled";
    let result = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::pass_by_absence(note)),
    );
    assert_eq!(result.status, Status::Pass);
    assert_eq!(result.message, note);
    assert!(result.notes.is_empty());
}

#[test]
fn the_mapped_results_feed_the_verdict() {
    let pass = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::pass("ok")),
    );
    let skipped = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx("fake.wants", &[]),
        Err(CheckError::MissingNeed(Need::Root)),
    );
    let judgement = verdict(&[pass.clone(), skipped]);
    assert_eq!(judgement.verdict, Verdict::NotReady);

    let downgraded = map(
        &PLAIN,
        &entry("fake.plain"),
        &ctx("fake.plain", &[]),
        Ok(Finding::pass("ok").with_partial(Partial::new(vec![Need::Root], "n"))),
    );
    assert_eq!(
        verdict(&[pass, downgraded]).verdict,
        Verdict::ReadyWithWarnings
    );
}

#[test]
fn the_root_fix_is_the_01_text_with_a_spec_placeholder_and_an_elevated_prompt_on_windows() {
    let unix = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx_on(Os::Linux, "fake.wants", &[]),
        Err(CheckError::MissingNeed(Need::Root)),
    );
    assert_eq!(
        unix.fix.as_deref(),
        Some("Rerun as root: sudo rdy run <spec>")
    );
    assert!(unix.fix.expect("fix").contains(SPEC_PLACEHOLDER));

    let mac = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx_on(Os::Macos, "fake.wants", &[]),
        Err(CheckError::MissingNeed(Need::Root)),
    );
    assert_eq!(
        mac.fix.as_deref(),
        Some("Rerun as root: sudo rdy run <spec>")
    );

    let windows = map(
        &WITH_WANTS,
        &entry("fake.wants"),
        &ctx_on(Os::Windows, "fake.wants", &[]),
        Err(CheckError::MissingNeed(Need::Root)),
    );
    assert_eq!(
        windows.fix.as_deref(),
        Some(
            "Run rdy from an elevated prompt: open Terminal or PowerShell with Run as administrator, then run it again."
        )
    );
    assert_eq!(windows.fix_source, Some(FixSource::Rdy));
}
