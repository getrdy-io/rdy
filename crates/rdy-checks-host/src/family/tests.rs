//! Tests for the host family. They run on every CI leg with the same expectations: the OS is an
//! argument of the plan and of the scheduler, never `cfg!`, so the macOS and Windows plans are checked
//! on Linux and the Linux plan is checked on macOS and Windows.

use rdy_engine::check::{CheckError, Os, Support};
use rdy_engine::family::{Registry, RegistryError};
use rdy_engine::plan::{PlanAction, RunPlan};
use rdy_engine::sched::{End, Planned, Scheduler};
use rdy_spec::check::KNOWN_IDS;
use rdy_spec::parse_unverified;
use rdy_spec::result::SkipKind;
use rdy_spec::spec::{CheckSpec, Spec};
use serde_json::json;
use std::sync::Arc;

use super::*;

const ACME: &str = include_str!("../../../../examples/specs/acme-platform.yaml");

/// One valid entry for each host id, with the least a spec must say.
fn entries() -> Vec<CheckSpec> {
    [
        json!({"id": "host.disk", "path": "/var/lib", "min": "10Gi"}),
        json!({"id": "host.memory", "min": "8Gi"}),
        json!({"id": "host.ports", "free": [6443]}),
        json!({"id": "host.lsm", "selinux": {"allow": ["enforcing"]}}),
        json!({"id": "host.security_agents", "forbid": ["acme-agent"]}),
        json!({"id": "host.firewall", "open_inbound": [6443]}),
        json!({"id": "host.time_sync", "max_skew": "5s"}),
        json!({"id": "host.cpu", "min": 2}),
        json!({"id": "host.sysctl", "expect": {"vm.max_map_count": ">=262144"}}),
        json!({"id": "host.container_runtime", "runtime": ["containerd"]}),
        json!({"id": "host.cgroups", "version": "v2"}),
        json!({"id": "host.os", "fips": "forbid"}),
        json!({"id": "host.kernel", "min": "5.4"}),
    ]
    .into_iter()
    .map(|value| serde_json::from_value(value).expect("a check entry"))
    .collect()
}

fn registry() -> Registry {
    let mut registry = Registry::new();
    registry.register(HostFamily).expect("host registers");
    registry
}

fn plan(os: Os) -> RunPlan {
    let mut spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    spec.checks = entries();
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
fn the_family_lists_every_host_id_the_spec_knows_and_registers_once() {
    let mut ids: Vec<&str> = HostFamily.checks().iter().map(|info| info.id).collect();
    ids.sort_unstable();
    let mut known: Vec<&str> = KNOWN_IDS
        .iter()
        .copied()
        .filter(|id| id.starts_with("host."))
        .collect();
    known.sort_unstable();
    assert_eq!(ids, known);

    let mut twice = registry();
    assert_eq!(
        twice.register(HostFamily).map(|_| ()),
        Err(RegistryError::DuplicateFamily("host"))
    );
}

#[test]
fn every_info_is_filed_under_host_with_a_timeout() {
    for info in HostFamily.checks() {
        assert!(info.id.starts_with("host."), "{}", info.id);
        assert_eq!(info.family, "host");
        let timeout = info.default_timeout.expect("a timeout from the catalog");
        assert!(timeout.as_secs() >= 1 && timeout <= rdy_engine::check::MAX_TIMEOUT);
        assert!(info.needs.is_empty(), "{} has a hard need", info.id);
    }
}

#[test]
fn m1_support_is_full_on_linux_and_not_yet_elsewhere() {
    for info in HostFamily.checks() {
        assert_eq!(info.os.on(Os::Linux), Support::Full, "{}", info.id);
        assert_eq!(info.os.on(Os::Macos), Support::NotYet, "{}", info.id);
        assert_eq!(info.os.on(Os::Windows), Support::NotYet, "{}", info.id);
    }
}

#[test]
fn on_linux_every_host_check_is_planned_to_run() {
    let plan = plan(Os::Linux);
    assert_eq!(plan.entries().len(), 13);
    assert_eq!(plan.runnable().count(), 13);
    for entry in plan.entries() {
        assert!(skip_kind(&plan, &entry.key).is_none(), "{}", entry.key);
    }
}

#[test]
fn on_macos_and_windows_every_host_check_is_not_yet_on_os() {
    for os in [Os::Macos, Os::Windows] {
        let plan = plan(os);
        assert_eq!(plan.entries().len(), 13);
        assert_eq!(plan.runnable().count(), 0);
        for entry in plan.entries() {
            assert_eq!(
                skip_kind(&plan, &entry.key),
                Some(SkipKind::NotYetOnOs),
                "{}",
                entry.key
            );
            let result = entry.skip_result().expect("a skip result");
            assert!(result.message.starts_with("Not run."), "{}", result.message);
        }
    }
}

#[test]
fn a_stub_that_reaches_the_scheduler_follows_the_run_os_not_the_build() {
    let built = |os: Os| {
        let checks: Vec<Planned> = HostFamily
            .checks()
            .iter()
            .filter(|info| HostFamily::stub_ids().contains(&info.id))
            .map(|info| Planned::new(Arc::new(Stub(info)), info.id))
            .collect();
        (Scheduler::new(2, os, []), checks)
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");

    for os in [Os::Macos, Os::Windows] {
        let (scheduler, checks) = built(os);
        let ran = runtime.block_on(scheduler.run(checks));
        assert_eq!(ran.len(), HostFamily::stub_ids().len());
        for one in ran {
            let End::Done(done) = one.end else {
                panic!("{} did not end", one.key);
            };
            let Err(error) = *done else {
                panic!("{} did not end in an error", one.key);
            };
            assert_eq!(error.skip_kind(), Some(SkipKind::NotYetOnOs), "{}", one.key);
        }
    }

    let (scheduler, checks) = built(Os::Linux);
    for one in runtime.block_on(scheduler.run(checks)) {
        let End::Done(done) = one.end else {
            panic!("{} did not end", one.key);
        };
        let Err(error) = *done else {
            panic!("{} did not end in an error", one.key);
        };
        assert!(
            matches!(error, CheckError::Failed { .. }),
            "{}: {error:?}",
            one.key
        );
        assert_eq!(error.skip_kind(), None, "not_yet_on_os on Linux");
    }
}

#[test]
fn every_remediation_passes_the_fix_text_audit() {
    // The text ships in reports. Every command and sysctl name in it must be on the reviewed lists
    // (ADR 0028), so a typo or an unreviewed tool fails here and not in a customer's report.
    for info in HostFamily.checks() {
        let text = info.meta.remediation;
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("{} has fix text that is not on the lists: {error}", info.id);
        }
    }
}

#[test]
fn build_refuses_an_id_the_family_does_not_have() {
    let spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    let entry: CheckSpec = serde_json::from_value(json!({"id": "net.egress"})).expect("an entry");
    let params = entry.decode_params();
    assert!(HostFamily.build(&entry, params, &spec).is_err());
}

#[test]
fn these_ids_are_still_stubs_so_the_family_stays_out_of_the_cli() {
    // Delete an id here in the ticket that writes its real check. When the list is empty, the
    // registering ticket (M1-057) may wire the family into the CLI.
    assert_eq!(
        HostFamily::stub_ids(),
        [
            "host.disk",
            "host.ports",
            "host.time_sync",
            "host.cpu",
            "host.sysctl",
            "host.container_runtime",
            "host.cgroups",
            "host.kernel",
        ]
    );
    let listed: Vec<&str> = HostFamily.checks().iter().map(|info| info.id).collect();
    for id in HostFamily::stub_ids() {
        assert!(listed.contains(id), "{id} is not a host check");
    }
}

#[test]
fn host_firewall_builds_the_real_check_from_a_spec_entry() {
    let spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    let entry: CheckSpec =
        serde_json::from_value(json!({"id": "host.firewall", "open_inbound": [6443, 443]}))
            .expect("an entry");
    let built = HostFamily
        .build(&entry, entry.decode_params(), &spec)
        .expect("the entry builds");
    assert_eq!(built.check.info().id, "host.firewall");
    assert_eq!(
        built.check.info().summary,
        "Host firewall active, inbound ports allowed"
    );
    assert!(!HostFamily::stub_ids().contains(&"host.firewall"));
}

#[test]
fn host_lsm_builds_the_real_check_from_a_spec_entry() {
    let spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    let entry: CheckSpec =
        serde_json::from_value(json!({"id": "host.lsm", "selinux": {"allow": ["enforcing"]}}))
            .expect("an entry");
    let built = HostFamily
        .build(&entry, entry.decode_params(), &spec)
        .expect("the entry builds");
    assert_eq!(built.check.info().id, "host.lsm");
    assert_eq!(
        built.check.info().summary,
        "SELinux and AppArmor state, recent denials"
    );
    assert!(!HostFamily::stub_ids().contains(&"host.lsm"));
}

#[test]
fn host_memory_builds_the_real_check_from_a_spec_entry() {
    let spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    let entry: CheckSpec =
        serde_json::from_value(json!({"id": "host.memory", "min": "8Gi"})).expect("an entry");
    let built = HostFamily
        .build(&entry, entry.decode_params(), &spec)
        .expect("the entry builds");
    assert_eq!(built.check.info().id, "host.memory");
    assert_eq!(built.check.info().summary, "RAM, swap, cgroup limit");
    assert!(!HostFamily::stub_ids().contains(&"host.memory"));
    // The helper's reads are declared, or the cgroup files would be refused at run time.
    for path in crate::cgroup::READS {
        assert!(built.check.info().reads.contains(&path), "{path}");
    }
}

#[test]
fn host_os_builds_the_real_check_from_a_spec_entry() {
    let spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    let entry: CheckSpec = serde_json::from_value(json!({
        "id": "host.os",
        "supported": [{"id": "rhel", "versions": ["8", "9"]}],
        "arch": ["amd64"],
        "fips": "forbid"
    }))
    .expect("an entry");
    let built = HostFamily
        .build(&entry, entry.decode_params(), &spec)
        .expect("the entry builds");
    assert_eq!(built.check.info().id, "host.os");
    assert_eq!(built.check.info().summary, "Distro, version, arch, FIPS");
    assert!(!HostFamily::stub_ids().contains(&"host.os"));
}

#[test]
fn host_security_agents_builds_the_real_check_from_a_spec_entry() {
    let spec: Spec = parse_unverified(ACME.as_bytes()).expect("the example spec parses");
    let entry: CheckSpec = serde_json::from_value(
        json!({"id": "host.security_agents", "forbid": ["falco", "clamav"], "allow": ["veeam-agent-linux"]}),
    )
    .expect("an entry");
    let built = HostFamily
        .build(&entry, entry.decode_params(), &spec)
        .expect("the entry builds");
    assert_eq!(built.check.info().id, "host.security_agents");
    assert_eq!(
        built.check.info().summary,
        "Security software processes that inspect file and process activity"
    );
    assert!(!HostFamily::stub_ids().contains(&"host.security_agents"));

    // The bare entry builds too: any detected product is a warning.
    let bare: CheckSpec =
        serde_json::from_value(json!({"id": "host.security_agents"})).expect("an entry");
    assert!(HostFamily.build(&bare, bare.decode_params(), &spec).is_ok());
}
