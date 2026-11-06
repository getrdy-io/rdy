//! `--no-network` and `--jobs` through `rdy run` (M1-059), with registries of the test's own.

use rdy_engine::check::{CheckInfo, Need};
use rdy_engine::family::{Registry, RegistryError};
use serde_json::Value;

use super::{Only, SPEC, call, info, leaky_registry, unprivileged};

/// Needs the network.
static NEEDS_NET: CheckInfo = info(&[Need::Network], &[]);
static NET_LIST: [&CheckInfo; 1] = [&NEEDS_NET];
/// Needs a Kubernetes cluster.
static NEEDS_KUBE: CheckInfo = info(&[Need::KubeContext], &[]);
static KUBE_LIST: [&CheckInfo; 1] = [&NEEDS_KUBE];
/// Needs nothing.
static PLAIN: CheckInfo = info(&[], &[]);
static PLAIN_LIST: [&CheckInfo; 1] = [&PLAIN];

fn net_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Only(&NEEDS_NET, &NET_LIST))?;
    Ok(registry)
}

fn kube_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Only(&NEEDS_KUBE, &KUBE_LIST))?;
    Ok(registry)
}

fn plain_registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(Only(&PLAIN, &PLAIN_LIST))?;
    Ok(registry)
}

fn run_json(extra: &[&str], make: fn() -> Result<Registry, RegistryError>) -> (u8, Value, String) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let spec = dir.path().join("spec.yaml");
    std::fs::write(&spec, SPEC).expect("write the spec");
    let spec = spec.to_string_lossy().into_owned();
    let mut args = vec![
        "run",
        spec.as_str(),
        "--allow-unsigned",
        "--json",
        "--no-report",
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = call(unprivileged(), &args, make);
    let report = serde_json::from_str(&stdout).unwrap_or(Value::Null);
    (code, report, stderr)
}

#[test]
fn no_network_skips_a_network_check_as_missing_need_and_records_the_option() {
    let (code, report, stderr) = run_json(&["--no-network"], net_registry);
    assert_eq!(code, 2, "{stderr}");
    let check = &report["checks"][0];
    assert_eq!(check["status"], "skipped");
    assert_eq!(check["skip_kind"], "missing_need");
    assert_eq!(report["run"]["options"]["network"], false);
    let kinds: Vec<&str> = report["actions"]
        .as_array()
        .map(|all| all.iter().filter_map(|a| a["kind"].as_str()).collect())
        .unwrap_or_default();
    assert!(!kinds.contains(&"connect"), "{kinds:?}");
}

#[test]
fn without_the_flag_the_network_check_runs() {
    let (code, report, stderr) = run_json(&[], net_registry);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(report["checks"][0]["status"], "pass");
    assert_eq!(report["run"]["options"]["network"], true);
}

#[test]
fn no_network_skips_a_kubernetes_check_and_a_kube_flag_is_not_an_error() {
    let (code, report, stderr) = run_json(
        &["--no-network", "--kube-context", "staging"],
        kube_registry,
    );
    assert_eq!(code, 2, "{stderr}");
    assert_eq!(report["checks"][0]["skip_kind"], "missing_need");
}

#[test]
fn jobs_zero_is_a_usage_error_with_a_fix_and_reads_no_spec() {
    // The spec path does not exist: the jobs check comes first.
    let (code, stdout, stderr) = call(
        unprivileged(),
        &["run", "no-such-spec.yaml", "--jobs", "0"],
        leaky_registry,
    );
    assert_eq!(code, 64, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(
        stderr,
        "error: --jobs must be 1 or more\nfix: use a number from 1 to 32, for example --jobs 8\n"
    );
}

#[test]
fn jobs_above_the_limit_is_capped_with_a_note_and_recorded_as_the_cap() {
    let (code, report, stderr) = run_json(&["--jobs", "500"], plain_registry);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains(
            "note: --jobs 500 is more than the limit of 32, so rdy runs 32 checks at once\n"
        ),
        "{stderr}"
    );
    assert_eq!(report["run"]["options"]["jobs"], 32);
}

#[test]
fn jobs_inside_the_limit_prints_no_note() {
    let (_, report, stderr) = run_json(&["--jobs", "32"], plain_registry);
    assert!(!stderr.contains("note:"), "{stderr}");
    assert_eq!(report["run"]["options"]["jobs"], 32);
    let (_, report, stderr) = run_json(&["--jobs", "3"], plain_registry);
    assert!(!stderr.contains("note:"), "{stderr}");
    assert_eq!(report["run"]["options"]["jobs"], 3);
    let (_, report, _) = run_json(&[], plain_registry);
    assert_eq!(report["run"]["options"]["jobs"], 8);
}

#[test]
fn jobs_that_is_not_a_number_is_a_usage_error() {
    let (code, _, stderr) = call(
        unprivileged(),
        &["run", "x.yaml", "--jobs", "abc"],
        plain_registry,
    );
    assert_eq!(code, 64, "{stderr}");
}

#[test]
fn jobs_from_maps_each_case() {
    use crate::run_cmd::jobs_from;
    assert_eq!(jobs_from(None).expect("default").count, 8);
    assert!(jobs_from(Some(0)).is_err());
    assert_eq!(jobs_from(Some(1)).expect("one").count, 1);
    assert!(jobs_from(Some(32)).expect("max").note.is_none());
    let capped = jobs_from(Some(u32::MAX)).expect("capped");
    assert_eq!(capped.count, 32);
    assert!(capped.note.is_some());
}
