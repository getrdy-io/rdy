//! Every fixture case of the implemented host checks against its `expect.json` (M1-174).
//!
//! One test per check. Each runs every directory under `tests/fixtures/checks/<id>/` through the real
//! scheduler, with the OS and needs of the case, and compares the finding (or the error, or the
//! timeout) with the reviewed `expect.json` through `rdy_engine::testing::assert_cases`. A new case
//! directory is a new test case with no code change here, and one without an `expect.json` fails.
//!
//! The checks are built by [`HostFamily`], from the `entry` in the `expect.json`, as `rdy run`
//! builds them.

use std::sync::Arc;

use rdy_engine::check::Check;
use rdy_engine::family::Family;
use rdy_engine::testing::assert_cases;
use rdy_spec::check::CheckParams;
use rdy_spec::parse_unverified;
use rdy_spec::spec::{CheckSpec, Spec};

use super::{HostFamily, Lsm};

/// The least a spec says. The host checks read nothing from it, so the entry decides everything.
const SPEC: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme-platform\n  version: \">=4.2\"\nchecks:\n  - id: host.cpu\n    min: 1\n";

/// The Unix time the audit logs of `host.lsm` cases are written against (the one the `host.lsm` unit
/// tests use). A real run counts the denial window back from the clock, so without this pin the
/// result of `enforcing-watched-denials` would change with the date.
const NOW: u64 = 1_730_000_000;

/// The check the family builds for `entry`. Only `host.lsm` is built by hand, to pin the clock.
fn build(entry: &CheckSpec) -> Arc<dyn Check> {
    let params = entry.decode_params();
    if let CheckParams::HostLsm(lsm) = &params {
        return Arc::new(Lsm::new(lsm).at(NOW));
    }
    let spec: Spec = parse_unverified(SPEC.as_bytes()).expect("the example spec parses");
    let built = HostFamily
        .build(entry, params, &spec)
        .expect("the family builds the entry");
    Arc::from(built.check)
}

fn check(id: &str, at_least: usize) {
    let cases = assert_cases(id, build);
    assert!(
        cases.len() >= at_least,
        "{id}: {} cases, expected at least {at_least}: {cases:?}",
        cases.len()
    );
}

#[test]
fn host_cpu_cases_match_their_expect_json() {
    check("host.cpu", 12);
}

#[test]
fn host_disk_cases_match_their_expect_json() {
    check("host.disk", 15);
}

#[test]
fn host_firewall_cases_match_their_expect_json() {
    check("host.firewall", 15);
}

#[test]
fn host_lsm_cases_match_their_expect_json() {
    check("host.lsm", 16);
}

#[test]
fn host_memory_cases_match_their_expect_json() {
    check("host.memory", 14);
}

#[test]
fn host_os_cases_match_their_expect_json() {
    check("host.os", 12);
}

#[test]
fn host_security_agents_cases_match_their_expect_json() {
    check("host.security_agents", 18);
}
