//! Tests of `host.cpu` against the synthetic machines under `tests/fixtures/checks/host.cpu/` (the 08
//! format, read by the Replay fixture loader).
//!
//! Each run goes through a probe that applies the real read policy and `CheckInfo::reads`, so a path
//! the check reads outside its manifest fails here as it would in a run.

use rdy_engine::check::{Check, CheckError, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};
use rdy_spec::check::CheckParams;
use rdy_spec::result::ActionKind;
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;

/// What one run produced and what it did to the machine.
struct Ran {
    outcome: CheckOutcome,
    run: TestRun,
}

impl Ran {
    fn finding(&self) -> &Finding {
        self.outcome.as_ref().expect("a finding")
    }

    /// The path of every file call the run made.
    fn paths(&self) -> Vec<String> {
        self.run
            .action_log()
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::Read)
            .filter_map(|a| a.fields.get("path").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
    }
}

fn fixture(case: &str) -> Fixture {
    Fixture::load(&fixtures_dir(), &format!("checks/host.cpu/{case}")).expect("the fixture loads")
}

fn run_on(case: &str, os: Os, check: &CpuCheck) -> Ran {
    let fixture = fixture(case);
    let run = TestRun::for_fixture(&fixture);
    let ctx = run.context_for(&INFO, "host.cpu", os, Vec::<Need>::new());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(check.run(&ctx));
    Ran { outcome, run }
}

fn run_case(case: &str, check: &CpuCheck) -> Ran {
    run_on(case, Os::Linux, check)
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// A check with a core minimum only.
fn min(n: u16) -> CpuCheck {
    CpuCheck::new(Some(n), None, [], [])
}

/// A check with flags only.
fn flags(list: &[&str]) -> CpuCheck {
    CpuCheck::new(None, None, [], names(list))
}

const CASES: [&str; 9] = [
    "pass",
    "no-avx2",
    "quota-2",
    "quota-v1",
    "affinity",
    "no-cpuinfo",
    "cgroup-unreadable",
    "bare-metal",
    "arm64",
];

#[test]
fn a_machine_with_enough_cpus_passes_and_says_what_it_found() {
    let ran = run_case("pass", &min(8));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "8 vCPUs found, 8 needed");
    assert!(f.fix.is_none() && f.partial.is_none());
    assert_eq!(f.expected, json!({"min": 8}));
    let seen = &f.observed;
    assert_eq!(seen["logical_cores"], 8);
    assert_eq!(seen["allowed_cores"], 8);
    assert_eq!(seen["physical_cores"], 4);
    assert_eq!(seen["effective_cores"], 8.0);
    assert_eq!(seen["quota_cores"], Value::Null);
    assert_eq!(seen["arch"], "x86_64");
    assert_eq!(seen["hypervisor"], true);
    assert_eq!(seen["virtualization"], "vm");
    assert_eq!(seen["x86_64_level"], 4);
}

#[test]
fn arch_and_flags_are_judged_together_with_the_cores() {
    let check = CpuCheck::new(
        Some(4),
        None,
        names(&["amd64"]),
        names(&["avx2", "bmi2", "x86-64-v3", "lzcnt"]),
    );
    let ran = run_case("pass", &check);
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(
        f.message,
        "8 vCPUs found, 4 needed; arch x86_64; flags present: avx2, bmi2, x86-64-v3 and lzcnt"
    );
    assert_eq!(f.observed["flags"]["lzcnt"], true);
    assert_eq!(f.observed["flags"]["x86-64-v3"], true);
    assert_eq!(f.expected["arch"], json!(["x86_64"]));
}

#[test]
fn a_cpuinfo_without_avx2_blocks_with_the_passthrough_fix() {
    let ran = run_case(
        "no-avx2",
        &CpuCheck::new(Some(4), None, [], names(&["avx2"])),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "8 vCPUs found, 4 needed; missing CPU flags: avx2"
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("host passthrough"), "{fix}");
    assert!(fix.contains("<cpu mode='host-passthrough'/>"), "{fix}");
    assert!(fix.contains("VMware EVC"), "{fix}");
    assert!(
        fix.contains("Set-VMProcessor -VMName <name> -CompatibilityForMigrationEnabled $false"),
        "{fix}"
    );
    assert!(fix.contains("public cloud"), "{fix}");
    assert_eq!(f.observed["flags"]["avx2"], false);
    assert_eq!(f.observed["x86_64_level"], 1);
}

#[test]
fn a_level_that_is_not_met_names_the_features_the_cpu_lacks() {
    let ran = run_case("no-avx2", &flags(&["x86-64-v2", "x86-64-v3"]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "8 vCPUs found; missing CPU flags: x86-64-v2 and x86-64-v3"
    );
    assert_eq!(
        f.notes,
        [
            "x86-64-v2 is not met: the CPU lacks popcnt, sse4_1, sse4_2 and ssse3.",
            "x86-64-v3 is not met: the CPU lacks popcnt, sse4_1, sse4_2, ssse3, avx, avx2, bmi1, bmi2 and 5 more."
        ]
    );
}

#[test]
fn a_cgroup_quota_of_two_cpus_reports_two_cores() {
    let ran = run_case("quota-2", &min(2));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(
        f.message,
        "2 vCPUs found, 2 needed (a cgroup CPU quota limits the 8 CPUs of the host)"
    );
    assert_eq!(f.observed["logical_cores"], 8);
    assert_eq!(f.observed["quota_cores"], 2.0);
    assert_eq!(f.observed["effective_cores"], 2.0);
    // The service itself has no limit; its parent slice does. The note says where.
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("200000/100000") && n.contains("/system.slice/acme.slice")),
        "{:?}",
        f.notes
    );
}

#[test]
fn a_quota_below_the_minimum_blocks_and_the_fix_names_the_quota() {
    let ran = run_case("quota-2", &min(4));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "2 vCPUs found, 4 needed (a cgroup CPU quota limits the 8 CPUs of the host)"
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.starts_with("A cgroup CPU quota caps rdy at 2 vCPUs. Raise it to 4 or more"),
        "{fix}"
    );
    assert!(
        fix.contains("`--cpus`") && fix.contains("`resources.limits.cpu`"),
        "{fix}"
    );
    assert!(fix.contains("`CPUQuota=`"), "{fix}");
}

#[test]
fn the_v1_quota_form_counts_a_fraction_exactly() {
    let blocked = run_case("quota-v1", &min(2));
    let f = blocked.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "1.5 vCPUs found, 2 needed (a cgroup CPU quota limits the 8 CPUs of the host)"
    );
    assert_eq!(f.observed["quota_cores"], 1.5);
    let passed = run_case("quota-v1", &min(1));
    assert_eq!(passed.finding().level, Level::Pass);
    assert_eq!(
        passed.finding().message,
        "1.5 vCPUs found, 1 needed (a cgroup CPU quota limits the 8 CPUs of the host)"
    );
}

#[test]
fn a_cpuset_that_narrows_the_mask_limits_the_count() {
    let ran = run_case("affinity", &min(4));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "2 vCPUs found, 4 needed (a CPU affinity mask limits the 8 CPUs of the host)"
    );
    assert_eq!(f.observed["logical_cores"], 8);
    assert_eq!(f.observed["allowed_cores"], 2);
    let fix = f.fix.as_deref().expect("a fix");
    assert!(
        fix.contains("`--cpuset-cpus`") && fix.contains("`AllowedCPUs=`"),
        "{fix}"
    );
}

#[test]
fn fewer_cpus_than_recommended_warns_and_fewer_than_the_minimum_blocks() {
    let check = CpuCheck::new(Some(4), Some(16), [], []);
    let warned = run_case("pass", &check);
    let f = warned.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(f.message, "8 vCPUs found, 4 needed, 16 recommended");
    assert_eq!(
        f.fix.as_deref(),
        Some("Resize the instance to at least 16 vCPUs. This host has 8 vCPUs.")
    );
    assert_eq!(f.expected, json!({"min": 4, "recommended": 16}));

    let blocked = run_case("pass", &CpuCheck::new(Some(12), Some(16), [], []));
    let f = blocked.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.message, "8 vCPUs found, 12 needed");
    assert_eq!(
        f.fix.as_deref(),
        Some("Resize the instance to at least 12 vCPUs. This host has 8 vCPUs.")
    );
}

#[test]
fn the_wrong_architecture_blocks() {
    let check = CpuCheck::new(None, None, names(&["x86_64"]), []);
    let ran = run_case("arm64", &check);
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.message,
        "4 vCPUs found; arch is aarch64, the spec allows x86_64"
    );
    let fix = f.fix.as_deref().expect("a fix");
    assert!(fix.contains("does not run on aarch64"), "{fix}");

    let ok = CpuCheck::new(None, None, names(&["arm64", "x86_64"]), []);
    let f = run_case("arm64", &ok).outcome.expect("a finding");
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "4 vCPUs found; arch aarch64");
}

#[test]
fn arm_features_are_read_from_the_features_line_and_a_vm_is_found_from_dmi() {
    let ran = run_case("arm64", &flags(&["asimd", "neon", "aes", "sve"]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.message, "4 vCPUs found; missing CPU flags: sve");
    assert_eq!(f.observed["flags"]["neon"], true);
    assert_eq!(f.observed["hypervisor"], true);
    assert_eq!(f.observed["x86_64_level"], Value::Null);
    assert_eq!(f.observed["physical_cores"], Value::Null);
}

#[test]
fn an_x86_level_asked_of_an_arm_host_is_missing_with_a_reason() {
    let ran = run_case("arm64", &flags(&["x86-64-v3"]));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(
        f.notes,
        ["x86-64-v3 is an x86_64 level and this host is aarch64."]
    );
}

#[test]
fn a_bare_metal_server_is_not_told_to_change_a_vm_setting() {
    let ran = run_case(
        "bare-metal",
        &CpuCheck::new(None, None, [], names(&["avx512f", "gfni"])),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail, "{f:?}");
    assert_eq!(f.message, "8 vCPUs found; missing CPU flags: gfni");
    assert_eq!(
        f.fix.as_deref(),
        Some("This CPU has no gfni. Use a CPU generation that has it.")
    );
    assert_eq!(f.observed["virtualization"], "none");
    assert_eq!(f.observed["hypervisor"], false);
    // Two sockets of two cores each, two threads per core.
    assert_eq!(f.observed["physical_cores"], 4);
    assert_eq!(f.observed["x86_64_level"], 4);
}

#[test]
fn a_machine_with_no_cpuinfo_still_counts_cpus_and_warns_about_flags() {
    let counted = run_case("no-cpuinfo", &min(8));
    let f = counted.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.message, "8 vCPUs found, 8 needed");
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("/proc/cpuinfo does not exist")),
        "{:?}",
        f.notes
    );
    assert_eq!(f.observed["virtualization"], "unknown");
    assert_eq!(f.observed["hypervisor"], Value::Null);

    let flagged = run_case("no-cpuinfo", &flags(&["avx2"]));
    let f = flagged.finding();
    assert_eq!(f.level, Level::Warn, "{f:?}");
    assert_eq!(f.message, "8 vCPUs found; could not read the CPU flags");
    assert!(
        f.fix
            .as_deref()
            .is_some_and(|fix| fix.contains("/proc/cpuinfo"))
    );
}

#[test]
fn an_unreadable_cgroup_file_is_a_note_and_the_count_stays_the_hardware_count() {
    let ran = run_case("cgroup-unreadable", &min(8));
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass, "{f:?}");
    assert_eq!(f.observed["effective_cores"], 8.0);
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("cgroup CPU limit files could not be read")),
        "{:?}",
        f.notes
    );
}

#[test]
fn a_spec_with_no_threshold_passes_and_reports() {
    let ran = run_case("pass", &CpuCheck::default());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(f.message, "8 vCPUs found");
    assert_eq!(f.expected, json!({}));
}

#[test]
fn macos_and_windows_have_no_data_source_yet() {
    for os in [Os::Macos, Os::Windows] {
        let ran = run_on("pass", os, &min(2));
        assert!(
            matches!(ran.outcome, Err(CheckError::Unsupported(_))),
            "{os:?}: {:?}",
            ran.outcome
        );
        assert!(ran.paths().is_empty(), "nothing is read on {os:?}");
    }
}

#[test]
fn the_check_reads_only_what_it_declares_and_only_the_cpu_files() {
    let all = CpuCheck::new(Some(2), Some(4), names(&["x86_64"]), names(&["avx2"]));
    for case in CASES {
        let ran = run_case(case, &all);
        // A read outside `reads` would be `Denied`, which is an error and not a finding.
        assert!(ran.outcome.is_ok(), "{case}: {:?}", ran.outcome);
        for path in ran.paths() {
            assert!(
                INFO.reads.iter().any(|prefix| path == *prefix
                    || path
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/'))),
                "{case} read {path}, which is outside its reads"
            );
        }
    }
    // The helper's own list is part of the manifest.
    for path in crate::cgroup::READS {
        assert!(INFO.reads.contains(&path), "{path} is missing from reads");
    }
}

#[test]
fn an_x86_machine_never_reads_the_arm_virtualization_files() {
    let ran = run_case("pass", &min(2));
    let paths = ran.paths();
    assert!(paths.iter().any(|p| p == "/proc/cpuinfo"), "{paths:?}");
    for arm_only in [DMI_PRODUCT, DMI_VENDOR, HYPERVISOR_TYPE] {
        assert!(!paths.iter().any(|p| p == arm_only), "{paths:?}");
    }
    // Arm reads the hypervisor type first, then the DMI text.
    let arm = run_case("arm64", &min(2)).paths();
    assert!(arm.iter().any(|p| p == DMI_PRODUCT), "{arm:?}");
}

#[test]
fn the_declared_facts_match_the_catalog() {
    assert_eq!((INFO.id, INFO.family), ("host.cpu", "host"));
    assert_eq!(INFO.default_timeout, Some(Duration::from_secs(2)));
    assert!(INFO.needs.is_empty() && INFO.wants.is_empty());
    assert!(INFO.commands.is_empty() && INFO.env.is_empty() && INFO.statfs.is_empty());
    assert_eq!(CpuCheck::default().info().id, "host.cpu");
}

#[test]
fn every_message_and_fix_the_cases_produce_passes_the_fix_text_audit() {
    if let Err(error) = rdy_engine::fixtext::check(INFO.meta.remediation) {
        panic!("remediation: {error}");
    }
    // Every problem at once, so every fix template is built.
    let hard = CpuCheck::new(
        Some(64),
        Some(128),
        names(&["x86_64"]),
        names(&["avx2", "x86-64-v3", "sve"]),
    );
    for case in CASES {
        for check in [&hard, &min(4), &flags(&["avx2"])] {
            let ran = run_case(case, check);
            let f = ran.finding();
            for text in f.fix.iter().chain(std::iter::once(&f.message)) {
                if let Err(error) = rdy_engine::fixtext::check(text) {
                    panic!("{case}: {error}");
                }
            }
        }
    }
}

#[test]
fn the_family_builds_the_real_check_from_the_spec_entry() {
    let entry: CheckSpec = serde_json::from_value(json!({
        "id": "host.cpu",
        "min": 2,
        "recommended": 4,
        "arch": ["amd64", "arm64"],
        "flags": ["avx2", "x86-64-v3"],
    }))
    .expect("an entry");
    let CheckParams::HostCpu(params) = entry.decode_params() else {
        panic!("host.cpu decodes to HostCpu");
    };
    assert_eq!(
        CpuCheck::from_params(&params),
        CpuCheck::new(
            Some(2),
            Some(4),
            names(&["x86_64", "aarch64"]),
            names(&["avx2", "x86-64-v3"])
        )
    );
}
