//! Tests for the net family. They run on every CI leg with the same expectations: the OS is an argument
//! of the plan and of the scheduler, never `cfg!`.

use rdy_engine::check::{Os, Support};
use rdy_engine::family::{Registry, RegistryError};
use rdy_engine::plan::{PlanAction, RunPlan};
use rdy_spec::parse_unverified;
use rdy_spec::result::SkipKind;
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::json;

use super::*;

const ACME: &str = include_str!("../../../../examples/specs/acme-platform.yaml");

fn registry() -> Registry {
    let mut registry = Registry::new();
    registry.register(NetFamily).expect("net registers");
    registry
}

fn plan(os: Os, entries: &[serde_json::Value]) -> RunPlan {
    let mut spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    spec.checks = entries
        .iter()
        .map(|value| serde_json::from_value::<CheckSpec>(value.clone()).expect("a check entry"))
        .collect();
    registry().plan(&spec, os, "0.1.0")
}

fn skip_kind(plan: &RunPlan, key: &str) -> Option<SkipKind> {
    let entry = plan
        .entries()
        .iter()
        .find(|entry| entry.key == key)
        .unwrap_or_else(|| panic!("no entry {key}"));
    match &entry.action {
        PlanAction::Skip(skip) => Some(skip.kind.clone()),
        _ => None,
    }
}

#[test]
fn the_family_lists_net_mtu_and_registers_once() {
    let ids: Vec<&str> = NetFamily.checks().iter().map(|info| info.id).collect();
    assert_eq!(ids, ["net.mtu"]);
    let mut twice = registry();
    assert_eq!(
        twice.register(NetFamily).map(|_| ()),
        Err(RegistryError::DuplicateFamily("net"))
    );
}

#[test]
fn every_info_is_filed_under_net_with_a_timeout() {
    for info in NetFamily.checks() {
        assert!(info.id.starts_with("net."), "{}", info.id);
        assert_eq!(info.family, "net");
        let timeout = info.default_timeout.expect("a timeout from the catalog");
        assert!(timeout.as_secs() >= 1 && timeout <= rdy_engine::check::MAX_TIMEOUT);
        assert!(info.needs.is_empty(), "{} has a hard need", info.id);
    }
    // 03 gives net.mtu 3 seconds.
    assert_eq!(mtu::INFO.default_timeout.map(|d| d.as_secs()), Some(3));
}

#[test]
fn net_mtu_is_planned_to_run_on_linux_and_is_not_yet_elsewhere() {
    let entries = [json!({"id": "net.mtu", "min_mtu": 1400, "overlay": "vxlan"})];
    let linux = plan(Os::Linux, &entries);
    assert_eq!(linux.runnable().count(), 1);
    assert_eq!(skip_kind(&linux, "net.mtu"), None);
    for os in [Os::Macos, Os::Windows] {
        let other = plan(os, &entries);
        assert_eq!(other.runnable().count(), 0);
        assert_eq!(skip_kind(&other, "net.mtu"), Some(SkipKind::NotYetOnOs));
        let result = other.entries()[0].skip_result().expect("a skip result");
        assert!(result.message.starts_with("Not run."), "{}", result.message);
    }
    assert_eq!(mtu::INFO.os.on(Os::Linux), Support::Full);
}

#[test]
fn a_net_id_that_is_not_built_yet_is_not_in_build() {
    let plan = plan(Os::Linux, &[json!({"id": "net.bandwidth"})]);
    assert_eq!(
        skip_kind(&plan, "net.bandwidth"),
        Some(SkipKind::NotInBuild)
    );
}

#[test]
fn build_makes_the_check_from_its_params_and_refuses_another_id() {
    let spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    let entry: CheckSpec =
        serde_json::from_value(json!({"id": "net.mtu", "min_mtu": 1400})).expect("an entry");
    let built = NetFamily
        .build(&entry, entry.decode_params(), &spec)
        .expect("it builds");
    assert_eq!(built.check.info().id, "net.mtu");
    assert!(built.hosts.is_empty());

    let other: CheckSpec =
        serde_json::from_value(json!({"id": "host.memory", "min": "8Gi"})).expect("an entry");
    assert!(
        NetFamily
            .build(&other, other.decode_params(), &spec)
            .is_err()
    );
}

#[test]
fn every_remediation_passes_the_fix_text_audit() {
    for info in NetFamily.checks() {
        if let Err(error) = rdy_engine::fixtext::check(info.meta.remediation) {
            panic!("{} has fix text that is not on the lists: {error}", info.id);
        }
    }
}
