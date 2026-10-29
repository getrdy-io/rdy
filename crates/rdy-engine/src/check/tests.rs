//! Tests for the check contract, with fake checks.
//!
//! There is no scheduler yet (M1-034), so `drive` below does the one step these tests need: look at the
//! hard needs, then run the check and read the skip kind off the outcome.

use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use rdy_spec::result::{Need as WireNeed, SkipKind};
use serde_json::json;

use super::*;

/// Polls a future that never waits. The fake checks below are always ready.
fn block_on<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a fake check must not wait"),
    }
}

static LINUX_ONLY: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::NotYet,
    windows: Support::Partial("environment variables only"),
};

static PASSING_INFO: CheckInfo = CheckInfo {
    id: "fake.pass",
    family: "fake",
    summary: "Always passes.",
    meta: CheckMeta {
        title: "Fake check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[],
    wants: &[],
    default_timeout: None,
    os: LINUX_ONLY,
    reads: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

static NEEDY_INFO: CheckInfo = CheckInfo {
    id: "fake.needs_root",
    family: "fake",
    summary: "Needs root.",
    meta: CheckMeta {
        title: "Fake check",
        remediation: "Nothing to fix. This check is a test double.",
    },
    needs: &[Need::Root],
    wants: &[Want {
        need: Need::Command("ss"),
        evidence_only: true,
    }],
    default_timeout: Some(Duration::from_secs(5)),
    os: LINUX_ONLY,
    reads: &["/proc/meminfo"],
    env: &["TZ"],
    commands: &[CommandSpec {
        program: "ss",
        extra_dirs: &[],
        max_stdout: 1024,
        env: &[],
    }],
    peers: &[PeerClass::SpecHosts],
};

struct Passing;

impl Check for Passing {
    fn info(&self) -> &'static CheckInfo {
        &PASSING_INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            Ok(Finding::pass(format!("{} is fine", ctx.key()))
                .with_observed(json!({ "total_bytes": 34_359_738_368_u64 }))
                .with_expected(json!({ "min_bytes": 17_179_869_184_u64 })))
        })
    }
}

struct NeedsRoot;

impl Check for NeedsRoot {
    fn info(&self) -> &'static CheckInfo {
        &NEEDY_INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            if !ctx.has(&Need::Root) {
                return Err(CheckError::MissingNeed(Need::Root));
            }
            Ok(Finding::pass("root is available"))
        })
    }
}

/// What the scheduler will do first: refuse to run a check whose hard needs are not all met.
fn drive(check: &dyn Check, ctx: &CheckContext) -> CheckOutcome {
    if let Some(missing) = check.info().needs.iter().find(|need| !ctx.has(need)) {
        return Err(CheckError::MissingNeed(missing.clone()));
    }
    block_on(check.run(ctx))
}

fn ctx(key: &str, available: &[Need]) -> CheckContext {
    CheckContext::new(key, Os::Linux, available.iter().cloned())
}

#[test]
fn a_passing_fake_check_returns_a_pass_finding() {
    let outcome = drive(&Passing, &ctx("fake.pass", &[]));
    let finding = outcome.expect("the check passes");
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.message, "fake.pass is fine");
    assert_eq!(
        finding.observed,
        json!({ "total_bytes": 34_359_738_368_u64 })
    );
    assert_eq!(finding.expected, json!({ "min_bytes": 17_179_869_184_u64 }));
    assert_eq!(finding.partial, None);
}

#[test]
fn a_check_with_a_missing_need_maps_to_skipped_missing_need() {
    let outcome = drive(&NeedsRoot, &ctx("fake.needs_root", &[]));
    let error = outcome.expect_err("root is missing");
    assert_eq!(error, CheckError::MissingNeed(Need::Root));
    assert_eq!(error.skip_kind(), Some(SkipKind::MissingNeed));
}

#[test]
fn the_same_check_passes_when_the_need_is_met() {
    let outcome = drive(&NeedsRoot, &ctx("fake.needs_root", &[Need::Root]));
    assert_eq!(outcome.expect("root is there").level, Level::Pass);
}

#[test]
fn a_check_can_report_its_own_missing_need() {
    let context = ctx("fake.needs_root", &[]);
    let outcome = block_on(NeedsRoot.run(&context));
    assert_eq!(outcome, Err(CheckError::MissingNeed(Need::Root)));
}

#[test]
fn the_trait_is_object_safe_and_the_run_future_can_be_spawned() {
    fn assert_send_static<T: Send + 'static>(_: &T) {}

    let checks: Vec<Arc<dyn Check>> = vec![Arc::new(Passing), Arc::new(NeedsRoot)];
    let ids: Vec<&str> = checks.iter().map(|check| check.info().id).collect();
    assert_eq!(ids, ["fake.pass", "fake.needs_root"]);

    // The scheduler spawns `async move { check.run(&ctx).await }`. This is the same shape.
    let check = Arc::clone(&checks[0]);
    let context = Arc::new(ctx("fake.pass", &[]));
    let task = async move { check.run(&context).await };
    assert_send_static(&task);
    assert_eq!(block_on(task).expect("passes").level, Level::Pass);
}

#[test]
fn the_context_answers_key_os_and_needs() {
    let context = CheckContext::new(
        "host.disk/data",
        Os::Macos,
        [Need::Network, Need::Command("ss")],
    );
    assert_eq!(context.key(), "host.disk/data");
    assert_eq!(context.os(), Os::Macos);
    assert!(context.has(&Need::Network));
    assert!(context.has(&Need::Command("ss")));
    assert!(!context.has(&Need::Command("ip")));
    assert!(!context.has(&Need::Root));
}

/// Every `CheckError`. The match has no wildcard, so a new variant stops compiling until it is listed
/// here and the not_applicable test below covers it.
fn every_check_error() -> Vec<CheckError> {
    let all = vec![
        CheckError::MissingNeed(Need::KubeContext),
        CheckError::Unsupported("no /proc on this OS"),
        CheckError::Probe(crate::probe::ProbeError::NotFound),
        CheckError::Failed {
            message: "parse failed".to_owned(),
            hint: "report it".to_owned(),
        },
    ];
    for error in &all {
        match error {
            CheckError::MissingNeed(_)
            | CheckError::Unsupported(_)
            | CheckError::Probe(_)
            | CheckError::Failed { .. } => {}
        }
    }
    all
}

/// Every `Support`, with the same compile-time guard.
fn every_support() -> Vec<Support> {
    let all = vec![Support::Full, Support::Partial("env only"), Support::NotYet];
    for support in &all {
        match support {
            Support::Full | Support::Partial(_) | Support::NotYet => {}
        }
    }
    all
}

#[test]
fn no_check_error_or_support_variant_can_produce_not_applicable() {
    for error in every_check_error() {
        assert_ne!(
            error.skip_kind(),
            Some(SkipKind::NotApplicable),
            "{error:?}"
        );
    }
    for support in every_support() {
        assert_ne!(
            support.skip_kind(),
            Some(SkipKind::NotApplicable),
            "{support:?}"
        );
    }
}

#[test]
fn check_errors_map_to_the_documented_outcome() {
    let kinds: Vec<Option<SkipKind>> = every_check_error()
        .iter()
        .map(CheckError::skip_kind)
        .collect();
    assert_eq!(
        kinds,
        [
            Some(SkipKind::MissingNeed),
            Some(SkipKind::NotYetOnOs),
            None,
            None
        ]
    );
}

#[test]
fn check_errors_print_what_is_missing() {
    assert_eq!(
        CheckError::MissingNeed(Need::Command("nvidia-smi")).to_string(),
        "missing need: command nvidia-smi"
    );
    assert_eq!(
        CheckError::MissingNeed(Need::KubeContext).to_string(),
        "missing need: kube_context"
    );
    assert_eq!(
        CheckError::Unsupported("no /proc on this OS").to_string(),
        "not supported here: no /proc on this OS"
    );
    let failed = CheckError::Failed {
        message: "parse failed".to_owned(),
        hint: "report it".to_owned(),
    };
    assert_eq!(failed.to_string(), "parse failed");
}

#[test]
fn os_support_picks_the_level_for_each_os() {
    assert_eq!(LINUX_ONLY.on(Os::Linux), Support::Full);
    assert_eq!(LINUX_ONLY.on(Os::Macos), Support::NotYet);
    assert_eq!(
        LINUX_ONLY.on(Os::Windows),
        Support::Partial("environment variables only")
    );
}

#[test]
fn support_maps_to_not_yet_on_os_or_to_a_partial_note() {
    assert_eq!(Support::Full.skip_kind(), None);
    assert_eq!(Support::Partial("x").skip_kind(), None);
    assert_eq!(Support::NotYet.skip_kind(), Some(SkipKind::NotYetOnOs));
    assert_eq!(Support::Full.partial_note(), None);
    assert_eq!(Support::NotYet.partial_note(), None);
    assert_eq!(
        Support::Partial("env only").partial_note(),
        Some("env only")
    );
}

#[test]
fn a_need_converts_to_the_wire_need_and_name() {
    assert_eq!(Need::Root.wire(), WireNeed::Root);
    assert_eq!(Need::Root.name(), None);
    assert_eq!(Need::KubeContext.wire(), WireNeed::KubeContext);
    assert_eq!(Need::Network.wire(), WireNeed::Network);
    assert_eq!(Need::Command("ss").wire(), WireNeed::Command);
    assert_eq!(Need::Command("ss").name(), Some("ss"));
}

#[test]
fn the_check_info_manifest_is_readable_without_running_anything() {
    let info = Passing.info();
    assert_eq!(info.id, "fake.pass");
    assert_eq!(info.family, "fake");

    let info = NeedsRoot.info();
    assert_eq!(info.needs, [Need::Root]);
    assert!(info.wants[0].evidence_only);
    assert_eq!(info.default_timeout, Some(Duration::from_secs(5)));
    assert_eq!(info.reads, ["/proc/meminfo"]);
    assert_eq!(info.env, ["TZ"]);
    assert_eq!(info.commands[0].program, "ss");
    assert_eq!(info.peers, [PeerClass::SpecHosts]);
}

#[test]
fn finding_builders_set_the_level_and_detail() {
    assert_eq!(Finding::pass("a").level, Level::Pass);
    assert_eq!(Finding::warn("a").level, Level::Warn);
    assert_eq!(Finding::fail("a").level, Level::Fail);

    let finding = Finding::fail("3.7 GiB of 4 GiB")
        .with_observed(json!(3.7))
        .with_expected(json!(4))
        .with_fix("Add memory.")
        .with_note("swap is off")
        .with_partial(
            Partial::new(vec![Need::Root], "not verified: root-only counters")
                .with_missing_grants(vec!["get nodes".to_owned()]),
        );
    assert_eq!(finding.observed, json!(3.7));
    assert_eq!(finding.expected, json!(4));
    assert_eq!(finding.fix.as_deref(), Some("Add memory."));
    assert_eq!(finding.notes, ["swap is off"]);
    let partial = finding.partial.expect("partial is set");
    assert_eq!(partial.missing, [Need::Root]);
    assert_eq!(partial.missing_grants, ["get nodes"]);
    assert_eq!(partial.note, "not verified: root-only counters");
}

#[test]
fn pass_by_absence_is_a_pass_whose_message_is_its_note() {
    let finding =
        Finding::pass_by_absence("SELinux is not installed, and the spec allows disabled");
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(finding.partial, None);
    assert_eq!(
        finding.message,
        "SELinux is not installed, and the spec allows disabled"
    );
    assert!(finding.notes.is_empty(), "the note must not show twice");
}

#[test]
fn the_current_os_is_one_of_the_three() {
    let os = current_os();
    assert!(matches!(os, Os::Linux | Os::Macos | Os::Windows));
    #[cfg(target_os = "linux")]
    assert_eq!(os, Os::Linux);
    #[cfg(target_os = "macos")]
    assert_eq!(os, Os::Macos);
    #[cfg(windows)]
    assert_eq!(os, Os::Windows);
}
