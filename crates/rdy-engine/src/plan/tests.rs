//! Tests for the run plan. The families are fakes: no real check exists yet.
//!
//! The plan is pure, so every test here is a plain synchronous test with no runtime, no files and no
//! network. `plan_calls_build_only_for_entries_that_can_run` proves the families are asked only about
//! entries that survive the earlier rules.

use std::sync::atomic::{AtomicUsize, Ordering};

use rdy_spec::result::{Bucket, FixSource, Status, Verdict, verdict};
use rdy_spec::spec::OsFamily;
use rdy_spec::{Target, parse_unverified};
use serde_json::json;

use super::*;
use crate::family::tests::{FakeHost, FakeNet};

const ACME: &str = include_str!("../../../../examples/specs/acme-platform.yaml");
const VERSION: &str = "0.1.0";

static BUILDS: AtomicUsize = AtomicUsize::new(0);

fn host_only() -> Registry {
    let mut registry = Registry::new();
    registry
        .register(FakeHost { builds: &BUILDS })
        .expect("host registers");
    registry
}

fn host_and_net() -> Registry {
    let mut registry = host_only();
    registry.register(FakeNet).expect("net registers");
    registry
}

fn entry(value: serde_json::Value) -> CheckSpec {
    serde_json::from_value(value).expect("a check entry")
}

fn acme() -> Spec {
    parse_unverified(ACME.as_bytes()).expect("the example spec parses")
}

fn spec_of(checks: Vec<CheckSpec>) -> Spec {
    let mut spec = acme();
    spec.checks = checks;
    spec
}

fn plan(registry: &Registry, checks: Vec<CheckSpec>, os: Os) -> RunPlan {
    registry.plan(&spec_of(checks), os, VERSION)
}

fn skip(plan: &RunPlan, key: &str) -> PlanSkip {
    match &entry_of(plan, key).action {
        PlanAction::Skip(skip) => skip.clone(),
        PlanAction::Run(_) => panic!("{key} should be skipped"),
    }
}

fn entry_of<'a>(plan: &'a RunPlan, key: &str) -> &'a PlanEntry {
    plan.entries()
        .iter()
        .find(|e| e.key == key)
        .unwrap_or_else(|| panic!("no entry {key}"))
}

fn runs(plan: &RunPlan, key: &str) -> bool {
    matches!(entry_of(plan, key).action, PlanAction::Run(_))
}

fn kinds(plan: &RunPlan) -> Vec<(String, SkipKind)> {
    plan.skipped()
        .filter_map(|e| match &e.action {
            PlanAction::Skip(s) => Some((e.key.clone(), s.kind.clone())),
            PlanAction::Run(_) => None,
        })
        .collect()
}

#[test]
fn the_acme_plan_on_linux() {
    let plan = host_only().plan(&acme(), Os::Linux, VERSION);
    assert_eq!(plan.entries().len(), 8, "one plan entry per spec entry");
    let order: Vec<&str> = plan.entries().iter().map(|e| e.id.as_str()).collect();
    assert_eq!(order[0], "host.cpu");
    assert_eq!(order[7], "aws.iam");

    assert!(runs(&plan, "host.cpu"));
    assert!(runs(&plan, "host.memory"));
    // Reserved, and the host family exists, but this build does not have the check.
    assert_eq!(skip(&plan, "host.disk").kind, SkipKind::NotInBuild);
    // Reserved families this build does not have.
    for key in ["gpu.cuda", "aws.iam", "net.egress", "k8s.version"] {
        let s = skip(&plan, key);
        assert_eq!(s.kind, SkipKind::NotInBuild, "{key}");
        assert!(
            s.message
                .starts_with("Not run. This version of rdy has no ")
        );
        assert_eq!(
            s.fix.as_deref(),
            Some("Install a newer rdy. If there is none yet, ask the vendor how to go on.")
        );
    }
    assert_eq!(
        skip(&plan, "gpu.cuda").message,
        "Not run. This version of rdy has no gpu checks yet."
    );
    assert_eq!(
        skip(&plan, "host.disk").message,
        "Not run. This version of rdy does not have the check host.disk yet."
    );
}

#[test]
fn a_typo_id_is_unknown_check_and_not_a_parse_error() {
    let mut spec = acme();
    spec.checks
        .push(entry(json!({"id": "host.memroy", "min": "1Gi"})));
    spec.checks.push(entry(json!({"id": "upload.now"})));
    let plan = host_only().plan(&spec, Os::Linux, VERSION);

    let typo = skip(&plan, "host.memroy");
    assert_eq!(typo.kind, SkipKind::UnknownCheck);
    assert_eq!(
        typo.message,
        "Not run. rdy 0.1.0 does not know the check 'host.memroy'."
    );
    assert_eq!(
        typo.fix.as_deref(),
        Some(
            "Tell the vendor. The spec may have a typo (did you mean 'host.memory'?), or it may need a newer rdy than 0.1.0."
        )
    );

    let nobody = skip(&plan, "upload.now");
    assert_eq!(nobody.kind, SkipKind::UnknownCheck);
    assert_eq!(
        nobody.message,
        "Not run. No version of rdy has checks named upload."
    );
    // Nothing near: no parenthesis.
    assert_eq!(
        nobody.fix.as_deref(),
        Some("Tell the vendor. The spec may have a typo.")
    );
}

#[test]
fn a_typo_in_an_unreserved_family_gets_a_hint_in_the_short_sentence() {
    let mut spec = acme();
    spec.checks.push(entry(json!({"id": "hots.cpu", "min": 1})));
    let plan = host_only().plan(&spec, Os::Linux, VERSION);
    let typo = skip(&plan, "hots.cpu");
    assert_eq!(typo.kind, SkipKind::UnknownCheck);
    assert_eq!(
        typo.message,
        "Not run. No version of rdy has checks named hots."
    );
    assert_eq!(
        typo.fix.as_deref(),
        Some("Tell the vendor. The spec may have a typo (did you mean 'host.cpu'?).")
    );
}

#[test]
fn a_mistyped_field_of_a_known_check_gets_the_near_field_in_its_fix() {
    let mut spec = acme();
    spec.checks
        .push(entry(json!({"id": "host.cpu", "name": "typo", "mn": 1})));
    spec.checks.push(entry(
        json!({"id": "host.memory", "name": "far", "zzzzzz": 1}),
    ));
    let plan = host_only().plan(&spec, Os::Linux, VERSION);
    let near = skip(&plan, "host.cpu/typo");
    assert_eq!(near.kind, SkipKind::UnsupportedSpec);
    assert_eq!(
        near.fix.as_deref(),
        Some(
            "Tell the vendor. The spec may have a typo (did you mean 'min'?), or it may need a newer rdy than 0.1.0."
        )
    );
    // A field with nothing near it: no hint.
    let far = skip(&plan, "host.memory/far");
    assert_eq!(
        far.fix.as_deref(),
        Some("Tell the vendor. The spec may have a typo, or it may need a newer rdy than 0.1.0.")
    );
}

#[test]
fn host_checks_are_not_yet_on_os_on_windows_and_macos() {
    for os in [Os::Windows, Os::Macos] {
        let plan = host_only().plan(&acme(), os, VERSION);
        for key in ["host.cpu", "host.memory"] {
            let s = skip(&plan, key);
            assert_eq!(s.kind, SkipKind::NotYetOnOs, "{key} on {os:?}");
            assert_eq!(
                s.fix.as_deref(),
                Some("Run rdy on the machine you will install on.")
            );
        }
    }
    let windows = host_only().plan(&acme(), Os::Windows, VERSION);
    assert_eq!(
        skip(&windows, "host.cpu").message,
        "Not run. This check does not work on Windows yet."
    );
    // A check with full support on every OS runs on all of them.
    let net = host_and_net();
    for os in [Os::Linux, Os::Macos, Os::Windows] {
        let plan = plan(&net, vec![egress("a.example:443")], os);
        assert!(runs(&plan, "net.egress"), "{os:?}");
    }
}

#[test]
fn not_applicable_comes_only_from_the_specs_os_list() {
    let checks = || {
        vec![
            entry(json!({"id": "host.cpu", "min": 4, "os": ["linux"]})),
            entry(json!({"id": "host.memory", "min": "1Gi"})),
            entry(
                json!({"id": "net.egress", "endpoints": ["a.example:443"], "os": ["linux", "windows"]}),
            ),
        ]
    };
    let registry = host_and_net();

    let mac = plan(&registry, checks(), Os::Macos);
    let cpu = skip(&mac, "host.cpu");
    assert_eq!(cpu.kind, SkipKind::NotApplicable);
    assert_eq!(
        cpu.message,
        "Does not apply here. This check is for linux only."
    );
    assert_eq!(cpu.fix, None);
    // No os list on macOS: not_yet_on_os, which counts as not run.
    assert_eq!(skip(&mac, "host.memory").kind, SkipKind::NotYetOnOs);
    assert_eq!(
        skip(&mac, "net.egress").message,
        "Does not apply here. This check is for linux and windows only."
    );

    let linux = plan(&registry, checks(), Os::Linux);
    assert!(runs(&linux, "host.cpu"));
    assert!(runs(&linux, "host.memory"));
    assert!(runs(&linux, "net.egress"));

    let windows = plan(&registry, checks(), Os::Windows);
    assert_eq!(skip(&windows, "host.cpu").kind, SkipKind::NotApplicable);
    assert_eq!(skip(&windows, "host.memory").kind, SkipKind::NotYetOnOs);
    assert!(runs(&windows, "net.egress"));
}

#[test]
fn nothing_else_ever_makes_not_applicable() {
    let mut spec = acme();
    spec.checks.push(entry(json!({"id": "host.memroy"})));
    spec.checks.push(entry(json!({"id": "host.cpu", "mn": 4})));
    for os in [Os::Linux, Os::Macos, Os::Windows] {
        let plan = host_and_net().plan(&spec, os, VERSION);
        assert!(
            kinds(&plan)
                .iter()
                .all(|(_, kind)| *kind != SkipKind::NotApplicable),
            "{os:?}"
        );
    }
}

#[test]
fn an_empty_os_list_is_refused_and_does_not_hide_the_check() {
    let plan = plan(
        &host_only(),
        vec![entry(json!({"id": "host.cpu", "min": 4, "os": []}))],
        Os::Linux,
    );
    let s = skip(&plan, "host.cpu");
    assert_eq!(s.kind, SkipKind::UnsupportedSpec);
    assert_eq!(s.message, "Not run. The 'os' list in host.cpu is empty.");
}

#[test]
fn an_unreadable_common_field_is_unsupported_spec() {
    let plan = plan(
        &host_only(),
        vec![
            entry(json!({"id": "host.cpu", "min": 4, "os": ["rhel"]})),
            entry(json!({"id": "host.memory", "min": "1Gi", "severity": "blok"})),
        ],
        Os::Linux,
    );
    assert_eq!(skip(&plan, "host.cpu").kind, SkipKind::UnsupportedSpec);
    assert_eq!(skip(&plan, "host.memory").kind, SkipKind::UnsupportedSpec);
    // An unreadable severity still counts as block.
    assert_eq!(entry_of(&plan, "host.memory").severity, Severity::Block);
}

#[test]
fn a_known_id_with_a_field_this_rdy_cannot_read_is_unsupported_spec() {
    let plan = plan(
        &host_only(),
        vec![
            entry(json!({"id": "host.cpu", "mn": 4})),
            entry(json!({"id": "host.memory"})),
        ],
        Os::Linux,
    );
    let field = skip(&plan, "host.cpu");
    assert_eq!(field.kind, SkipKind::UnsupportedSpec);
    assert_eq!(
        field.message,
        "Not run. rdy 0.1.0 cannot read 'mn' in host.cpu."
    );
    let bare = skip(&plan, "host.memory");
    assert_eq!(bare.kind, SkipKind::UnsupportedSpec);
    assert!(
        bare.message.contains("has no threshold"),
        "{}",
        bare.message
    );
}

#[test]
fn a_family_that_refuses_the_entry_gives_unsupported_spec() {
    // The fake host family refuses an id it does not build. Route one through by listing it in a
    // family that claims it, then asking for a different entry id is not possible, so use a family
    // that always refuses.
    use crate::check::{CheckInfo, CheckMeta, OsSupport, Support};
    static REFUSED: CheckInfo = CheckInfo {
        id: "host.cpu",
        family: "host",
        summary: "A fake check.",
        meta: CheckMeta {
            title: "Fake check",
            remediation: "Nothing to fix. This check is a test double.",
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
    static REFUSED_LIST: [&CheckInfo; 1] = [&REFUSED];
    struct Refuses;
    impl crate::family::Family for Refuses {
        fn name(&self) -> &'static str {
            "host"
        }
        fn checks(&self) -> &'static [&'static CheckInfo] {
            &REFUSED_LIST
        }
        fn build(
            &self,
            _: &CheckSpec,
            _: rdy_spec::check::CheckParams,
            _: &Spec,
        ) -> Result<crate::family::Built, crate::family::BuildError> {
            Err(crate::family::BuildError::Unsupported(
                "the value is too large".to_owned(),
            ))
        }
    }
    let mut registry = Registry::new();
    registry.register(Refuses).expect("registers");
    let plan = plan(
        &registry,
        vec![entry(json!({"id": "host.cpu", "min": 4}))],
        Os::Linux,
    );
    let s = skip(&plan, "host.cpu");
    assert_eq!(s.kind, SkipKind::UnsupportedSpec);
    assert_eq!(
        s.message,
        "Not run. host.cpu: rdy cannot use this entry: the value is too large."
    );
}

#[test]
fn each_check_has_its_own_host_set_with_derived_defaults() {
    let spec = spec_of(vec![
        entry(json!({
            "id": "net.egress",
            "name": "registry",
            "endpoints": ["registry.acme.example:443", "license.acme.example:443"]
        })),
        entry(json!({
            "id": "net.egress",
            "name": "other",
            "endpoints": ["other.example:443"]
        })),
        entry(json!({"id": "net.tls_intercept"})),
        entry(json!({"id": "host.cpu", "min": 4})),
        entry(json!({
            "id": "net.egress",
            "name": "mac_only",
            "endpoints": ["other.example:443"],
            "os": ["macos"]
        })),
    ]);
    let plan = host_and_net().plan(&spec, Os::Linux, VERSION);

    // Each net.egress check reaches its own endpoints and no others.
    let registry = plan.entries()[0].hosts().expect("runs");
    assert_eq!(registry.len(), 2);
    assert!(registry.contains(&Target::parse("registry.acme.example:443").expect("target")));
    let other = plan.entries()[1].hosts().expect("runs");
    assert_eq!(other.len(), 1);
    assert!(other.contains(&Target::parse("other.example:443").expect("target")));
    assert!(!other.contains(&Target::parse("registry.acme.example:443").expect("target")));

    // tls_intercept without `hosts` defaults to every egress host in the spec, from the decoded params.
    let tls = plan.entries()[2].hosts().expect("runs");
    assert_eq!(tls.len(), 3);
    assert!(tls.contains(&Target::parse("license.acme.example:443").expect("target")));

    assert!(plan.entries()[3].hosts().expect("runs").is_empty());
    assert!(
        plan.entries()[4].hosts().is_none(),
        "a skipped entry reaches no host"
    );
}

#[test]
fn plan_calls_build_only_for_entries_that_can_run() {
    static LOCAL: AtomicUsize = AtomicUsize::new(0);
    let mut registry = Registry::new();
    registry
        .register(FakeHost { builds: &LOCAL })
        .expect("registers");
    let spec = spec_of(vec![
        entry(json!({"id": "host.cpu", "min": 4})),
        entry(json!({"id": "host.memory", "min": "1Gi", "os": ["windows"]})),
        entry(json!({"id": "host.memroy"})),
        entry(json!({"id": "host.cpu", "name": "bad", "mn": 1})),
        entry(json!({"id": "gpu.cuda", "min": "12.4"})),
        entry(json!({"id": "host.cpu", "name": "empty", "min": 1, "os": []})),
    ]);
    let plan = registry.plan(&spec, Os::Linux, VERSION);
    assert_eq!(plan.runnable().count(), 1);
    assert_eq!(plan.skipped().count(), 5);
    assert_eq!(
        LOCAL.load(Ordering::SeqCst),
        1,
        "one build, for the one entry that runs"
    );
}

#[test]
fn planning_is_deterministic() {
    let render = |plan: &RunPlan| -> Vec<Option<CheckResult>> {
        plan.entries().iter().map(PlanEntry::skip_result).collect()
    };
    let first = host_and_net().plan(&acme(), Os::Macos, VERSION);
    let second = host_and_net().plan(&acme(), Os::Macos, VERSION);
    assert_eq!(render(&first), render(&second));
    assert_eq!(first.os(), Os::Macos);
}

#[test]
fn a_skip_becomes_a_result_with_rdys_own_fix() {
    let plan = host_only().plan(&acme(), Os::Linux, VERSION);
    let result = entry_of(&plan, "gpu.cuda").skip_result().expect("skipped");
    assert_eq!(result.key, "gpu.cuda");
    assert_eq!(result.id, "gpu.cuda");
    assert_eq!(result.family, "gpu");
    assert_eq!(result.status, Status::Skipped);
    assert_eq!(result.skip_kind, Some(SkipKind::NotInBuild));
    assert_eq!(result.severity, Severity::Block);
    assert_eq!(result.fix_source, Some(FixSource::Rdy));
    assert_eq!(result.bucket, Bucket::RequiredNotRun);
    assert!(result.fix.is_some());
    assert!(entry_of(&plan, "host.cpu").skip_result().is_none());
}

#[test]
fn the_vendors_fix_is_not_shown_for_a_check_that_did_not_run() {
    // The acme spec has a vendor fix on gpu.cuda. The skip result must carry rdy's text instead.
    let plan = host_only().plan(&acme(), Os::Linux, VERSION);
    let result = entry_of(&plan, "gpu.cuda").skip_result().expect("skipped");
    assert!(
        !result
            .fix
            .as_deref()
            .unwrap_or_default()
            .contains("CUDA 12.4"),
        "{:?}",
        result.fix
    );
}

#[test]
fn a_not_applicable_result_has_no_fix_and_does_not_count() {
    let plan = plan(
        &host_only(),
        vec![entry(
            json!({"id": "host.cpu", "min": 4, "os": ["linux"], "fix": "Use more cores."}),
        )],
        Os::Macos,
    );
    let result = plan.entries()[0].skip_result().expect("skipped");
    assert_eq!(result.skip_kind, Some(SkipKind::NotApplicable));
    assert_eq!(result.fix, None);
    assert_eq!(result.fix_source, None);
    assert_eq!(result.bucket, Bucket::NotApplicable);
}

#[test]
fn the_acme_plan_alone_is_not_ready_on_every_os() {
    // Every entry is skipped or waiting. A required entry that is skipped (and not not_applicable)
    // makes the verdict NOT READY, so the skips alone already give it.
    for os in [Os::Linux, Os::Macos, Os::Windows] {
        let plan = host_only().plan(&acme(), os, VERSION);
        let results: Vec<CheckResult> = plan
            .entries()
            .iter()
            .filter_map(PlanEntry::skip_result)
            .collect();
        assert_eq!(verdict(&results).verdict, Verdict::NotReady, "{os:?}");
    }
}

#[test]
fn keys_carry_the_name_and_stay_unique_for_unreadable_names() {
    let plan = plan(
        &host_only(),
        vec![
            entry(json!({"id": "host.cpu", "min": 4, "name": "a"})),
            entry(json!({"id": "host.cpu", "min": 4, "name": "BAD NAME"})),
            entry(json!({"id": "host.cpu", "min": 4, "name": "BAD NAME"})),
        ],
        Os::Linux,
    );
    let keys: Vec<&str> = plan.entries().iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys, ["host.cpu/a", "host.cpu#1", "host.cpu#2"]);
    assert_eq!(skip(&plan, "host.cpu#1").kind, SkipKind::UnsupportedSpec);
}

#[test]
fn spec_text_is_cut_and_has_no_control_characters_in_keys_or_messages() {
    let nasty = format!("host.\u{1b}[31m{}", "x".repeat(200));
    let plan = plan(
        &host_only(),
        vec![
            entry(json!({"id": nasty, "name": "n"})),
            entry(json!({"id": "host.cpu", "min": 4, "\u{7}bell": 1})),
        ],
        Os::Linux,
    );
    for entry in plan.entries() {
        let result = entry.skip_result().expect("skipped");
        for text in [&result.key, &result.id, &result.message] {
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }
    }
    let nasty = &plan.entries()[0];
    assert!(nasty.id.starts_with("host.\\u{1b}[31m"), "{}", nasty.id);
    assert!(nasty.id.ends_with("..."), "{}", nasty.id);
}

#[test]
fn the_os_list_names_match_the_spec_type() {
    // The planner compares the spec's OsFamily with the engine's Os. They are one type.
    let os: Os = OsFamily::Linux;
    assert_eq!(os, Os::Linux);
}

/// Bidirectional overrides, isolates and zero-width characters are not control characters, but they
/// can reorder or hide text on a terminal.
const INVISIBLE: [char; 6] = [
    '\u{202e}', '\u{202a}', '\u{2066}', '\u{2069}', '\u{200b}', '\u{feff}',
];

#[test]
fn bidi_and_zero_width_characters_are_escaped() {
    let ids = [
        "host.\u{202e}cpu",
        "host.\u{2066}cpu\u{2069}",
        "host.\u{200b}cpu",
        "\u{feff}host.cpu",
    ];
    let checks = ids
        .iter()
        .map(|id| entry(json!({"id": id, "min": 4, "name": "n", "mn": "\u{202e}x"})))
        .collect();
    let planned = plan(&host_only(), checks, Os::Linux);
    for entry in planned.entries() {
        let result = entry.skip_result().expect("skipped");
        let fix = result.fix.clone().unwrap_or_default();
        for text in [&result.key, &result.id, &result.message, &fix] {
            assert!(!text.chars().any(|c| INVISIBLE.contains(&c)), "{text:?}");
        }
    }
    assert!(planned.entries()[0].id.contains("\\u{202e}"));

    // A bad field name is escaped too.
    let second = plan(
        &host_only(),
        vec![entry(json!({"id": "host.cpu", "min": 4, "\u{202e}x": 1}))],
        Os::Linux,
    );
    let s = skip(&second, "host.cpu");
    assert!(
        !s.message.chars().any(|c| INVISIBLE.contains(&c)),
        "{}",
        s.message
    );
}

#[test]
fn result_keys_never_collide() {
    let long = "x".repeat(100);
    let checks = vec![
        entry(json!({"id": format!("host.{long}a"), "min": 1})),
        entry(json!({"id": format!("host.{long}b"), "min": 1})),
        entry(json!({"id": "host.cpu/x", "min": 4})),
        entry(json!({"id": "host.cpu", "name": "x", "min": 4})),
        entry(json!({"id": "host.cpu", "min": 4})),
    ];
    let plan = plan(&host_only(), checks, Os::Linux);
    let keys: Vec<&str> = plan.entries().iter().map(|e| e.key.as_str()).collect();
    let unique: std::collections::HashSet<&&str> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len(), "{keys:?}");
    // The two cut ids share their text but not their keys.
    assert_eq!(plan.entries()[0].id, plan.entries()[1].id);
    assert!(
        keys[0].ends_with("#0") && keys[1].ends_with("#1"),
        "{keys:?}"
    );
    assert_eq!(keys[2], "host.cpu/x#2");
    assert_eq!(keys[3], "host.cpu/x");
    assert_eq!(keys[4], "host.cpu");
}

#[test]
fn a_family_that_builds_the_wrong_check_fails_closed_with_a_fixed_message() {
    use crate::check::CheckInfo;
    use crate::family::tests::{Fake, HOST_CPU, HOST_MEMORY};
    static LIST: [&CheckInfo; 1] = [&HOST_CPU];
    struct Wrong;
    impl crate::family::Family for Wrong {
        fn name(&self) -> &'static str {
            "host"
        }
        fn checks(&self) -> &'static [&'static CheckInfo] {
            &LIST
        }
        fn build(
            &self,
            _: &CheckSpec,
            _: rdy_spec::check::CheckParams,
            _: &Spec,
        ) -> Result<crate::family::Built, crate::family::BuildError> {
            Ok(crate::family::Built::new(Box::new(Fake(&HOST_MEMORY))))
        }
    }
    let mut registry = Registry::new();
    registry.register(Wrong).expect("registers");
    let plan = plan(
        &registry,
        vec![entry(json!({"id": "host.cpu", "min": 4}))],
        Os::Linux,
    );
    let s = skip(&plan, "host.cpu");
    assert_eq!(s.kind, SkipKind::NotInBuild);
    assert_eq!(
        s.message,
        "Not run. rdy could not set up the check host.cpu. This is a bug in rdy."
    );
    let fix = s.fix.expect("a fix");
    assert!(!fix.contains("newer rdy"), "{fix}");
    assert!(fix.contains("bug"), "{fix}");
}

#[test]
fn an_id_a_family_lists_as_not_built_is_skipped_and_never_built() {
    use crate::check::CheckInfo;
    use crate::family::tests::{Fake, HOST_CPU, HOST_MEMORY};
    static LIST: [&CheckInfo; 2] = [&HOST_CPU, &HOST_MEMORY];
    static BUILT: AtomicUsize = AtomicUsize::new(0);
    struct Stubby;
    impl crate::family::Family for Stubby {
        fn name(&self) -> &'static str {
            "host"
        }
        fn checks(&self) -> &'static [&'static CheckInfo] {
            &LIST
        }
        fn not_built(&self) -> &'static [&'static str] {
            &["host.memory"]
        }
        fn build(
            &self,
            _: &CheckSpec,
            _: rdy_spec::check::CheckParams,
            _: &Spec,
        ) -> Result<crate::family::Built, crate::family::BuildError> {
            BUILT.fetch_add(1, Ordering::SeqCst);
            Ok(crate::family::Built::new(Box::new(Fake(&HOST_CPU))))
        }
    }
    let mut registry = Registry::new();
    registry.register(Stubby).expect("registers");
    let plan = plan(
        &registry,
        vec![
            entry(json!({"id": "host.cpu", "min": 4})),
            entry(json!({"id": "host.memory", "min": "1Gi"})),
        ],
        Os::Linux,
    );
    assert!(runs(&plan, "host.cpu"));
    let s = skip(&plan, "host.memory");
    assert_eq!(s.kind, SkipKind::NotInBuild);
    assert_eq!(
        s.message,
        "Not run. This version of rdy does not have the check host.memory yet."
    );
    assert_eq!(s.fix.as_deref(), Some(NEWER_RDY));
    assert_eq!(BUILT.load(Ordering::SeqCst), 1, "only host.cpu is built");
}

fn egress(endpoint: &str) -> CheckSpec {
    entry(json!({"id": "net.egress", "endpoints": [endpoint]}))
}
