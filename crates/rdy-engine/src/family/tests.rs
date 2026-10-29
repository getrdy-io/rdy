//! Tests for the registry and `HostSet`. The fake families here are shared with the plan tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::check::{BoxFuture, CheckContext, CheckMeta, CheckOutcome, Finding, OsSupport, Support};

/// Linux only: a data source on Linux, none yet elsewhere.
pub(crate) static LINUX_ONLY: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::NotYet,
    windows: Support::NotYet,
};

/// Full support on every OS.
pub(crate) static EVERYWHERE: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::Full,
    windows: Support::Full,
};

const fn info(id: &'static str, family: &'static str, os: OsSupport) -> CheckInfo {
    CheckInfo {
        id,
        family,
        summary: "A fake check.",
        meta: CheckMeta {
            title: "Fake check",
            remediation: "Nothing to fix. This check is a test double.",
        },
        needs: &[],
        wants: &[],
        default_timeout: None,
        os,
        reads: &[],
        env: &[],
        commands: &[],
        peers: &[],
    }
}

pub(crate) static HOST_CPU: CheckInfo = info("host.cpu", "host", LINUX_ONLY);
pub(crate) static HOST_MEMORY: CheckInfo = info("host.memory", "host", LINUX_ONLY);
pub(crate) static NET_EGRESS: CheckInfo = info("net.egress", "net", EVERYWHERE);
pub(crate) static NET_TLS: CheckInfo = info("net.tls_intercept", "net", EVERYWHERE);
static HOST_CHECKS: [&CheckInfo; 2] = [&HOST_CPU, &HOST_MEMORY];
static NET_CHECKS: [&CheckInfo; 2] = [&NET_EGRESS, &NET_TLS];

/// A check that passes. It is never run in these tests.
pub(crate) struct Fake(pub(crate) &'static CheckInfo);

impl Check for Fake {
    fn info(&self) -> &'static CheckInfo {
        self.0
    }

    fn run<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async { Ok(Finding::pass("fine")) })
    }
}

/// A `host` family with `host.cpu` and `host.memory`, Linux only. It counts its `build` calls.
pub(crate) struct FakeHost {
    pub(crate) builds: &'static AtomicUsize,
}

impl Family for FakeHost {
    fn name(&self) -> &'static str {
        "host"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &HOST_CHECKS
    }

    fn build(&self, entry: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        match entry.id.as_str() {
            "host.cpu" => Ok(Built::new(Box::new(Fake(&HOST_CPU)))),
            "host.memory" => Ok(Built::new(Box::new(Fake(&HOST_MEMORY)))),
            _ => Err(BuildError::Unsupported("not a host check".to_owned())),
        }
    }
}

/// A `net` family. `net.egress` reaches its own endpoints. `net.tls_intercept` without `hosts` defaults
/// to the endpoints of every `net.egress` entry, which is how 02 describes the real one. Both read
/// the decoded parameters of `rdy-spec`.
pub(crate) struct FakeNet;

impl Family for FakeNet {
    fn name(&self) -> &'static str {
        "net"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &NET_CHECKS
    }

    fn build(&self, _: &CheckSpec, params: CheckParams, spec: &Spec) -> Result<Built, BuildError> {
        match params {
            CheckParams::NetEgress(egress) => {
                let hosts = egress.endpoints.iter().map(|e| e.target.clone());
                Ok(Built::new(Box::new(Fake(&NET_EGRESS))).with_hosts(HostSet::new(hosts)))
            }
            CheckParams::NetTlsIntercept(tls) if tls.hosts.is_none() => {
                let hosts = spec
                    .checks
                    .iter()
                    .filter_map(|sibling| match sibling.decode_params() {
                        CheckParams::NetEgress(egress) => Some(egress),
                        _ => None,
                    })
                    .flat_map(|egress| {
                        egress
                            .endpoints
                            .iter()
                            .map(|e| e.target.clone())
                            .collect::<Vec<_>>()
                    });
                Ok(Built::new(Box::new(Fake(&NET_TLS))).with_hosts(HostSet::new(hosts)))
            }
            _ => Err(BuildError::Unsupported(
                "this fake builds only the defaults".to_owned(),
            )),
        }
    }
}

fn target(text: &str) -> Target {
    Target::parse(text).expect("a valid target")
}

static BUILDS: AtomicUsize = AtomicUsize::new(0);

fn registry() -> Registry {
    let mut registry = Registry::new();
    registry
        .register(FakeNet)
        .expect("net registers")
        .register(FakeHost { builds: &BUILDS })
        .expect("host registers");
    registry
}

#[test]
fn a_registry_finds_checks_and_families() {
    let registry = registry();
    assert_eq!(registry.family("host").map(Family::name), Some("host"));
    assert!(registry.family("gpu").is_none());
    let (family, info) = registry.check("net.tls_intercept").expect("registered");
    assert_eq!(family.name(), "net");
    assert_eq!(info.id, "net.tls_intercept");
    assert!(registry.check("host.disk").is_none());
    assert!(registry.check("host").is_none());
}

#[test]
fn infos_are_ordered_by_id_whatever_the_registration_order() {
    let ids: Vec<&str> = registry().infos().map(|info| info.id).collect();
    assert_eq!(
        ids,
        ["host.cpu", "host.memory", "net.egress", "net.tls_intercept"]
    );
}

#[test]
fn families_keep_registration_order_and_their_checks_keep_catalog_order() {
    let registry = registry();
    let names: Vec<&str> = registry.families().map(Family::name).collect();
    assert_eq!(names, ["net", "host"]);
    let ids: Vec<&str> = registry
        .families()
        .flat_map(|family| family.checks().iter().map(|info| info.id))
        .collect();
    assert_eq!(
        ids,
        ["net.egress", "net.tls_intercept", "host.cpu", "host.memory"]
    );
}

#[test]
fn a_family_registers_once() {
    let mut registry = registry();
    assert_eq!(
        registry.register(FakeNet).expect_err("twice"),
        RegistryError::DuplicateFamily("net")
    );
    assert_eq!(registry.infos().count(), 4, "the registry is unchanged");
}

#[test]
fn a_check_belongs_to_the_family_that_lists_it() {
    static STRAY: CheckInfo = info("gpu.cuda", "gpu", EVERYWHERE);
    static WRONG_FAMILY_FIELD: CheckInfo = info("misc.one", "other", EVERYWHERE);
    static NO_NAME: CheckInfo = info("misc.", "misc", EVERYWHERE);
    static PREFIX_ONLY: CheckInfo = info("miscellaneous.one", "misc", EVERYWHERE);
    static A: [&CheckInfo; 1] = [&STRAY];
    static B: [&CheckInfo; 1] = [&WRONG_FAMILY_FIELD];
    static C: [&CheckInfo; 1] = [&NO_NAME];
    static D: [&CheckInfo; 1] = [&PREFIX_ONLY];

    struct Misc(&'static [&'static CheckInfo]);
    impl Family for Misc {
        fn name(&self) -> &'static str {
            "misc"
        }
        fn checks(&self) -> &'static [&'static CheckInfo] {
            self.0
        }
        fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
            Err(BuildError::Unsupported(String::new()))
        }
    }

    for (infos, id) in [
        (&A[..], "gpu.cuda"),
        (&B[..], "misc.one"),
        (&C[..], "misc."),
        (&D[..], "miscellaneous.one"),
    ] {
        let mut registry = Registry::new();
        let error = registry.register(Misc(infos)).expect_err("misfiled");
        assert_eq!(error, RegistryError::Misfiled { id, family: "misc" });
        assert_eq!(registry.infos().count(), 0);
    }
}

#[test]
fn a_check_id_is_listed_once() {
    static ONE: CheckInfo = info("misc.one", "misc", EVERYWHERE);
    static TWICE: [&CheckInfo; 2] = [&ONE, &ONE];
    struct Twice;
    impl Family for Twice {
        fn name(&self) -> &'static str {
            "misc"
        }
        fn checks(&self) -> &'static [&'static CheckInfo] {
            &TWICE
        }
        fn build(&self, _: &CheckSpec, _: CheckParams, _: &Spec) -> Result<Built, BuildError> {
            Err(BuildError::Unsupported(String::new()))
        }
    }
    let mut registry = Registry::new();
    assert_eq!(
        registry.register(Twice).expect_err("duplicate"),
        RegistryError::DuplicateCheck("misc.one")
    );
    assert_eq!(registry.infos().count(), 0, "nothing half registered");
}

#[test]
fn a_host_set_keeps_order_and_drops_duplicates() {
    let set = HostSet::new([
        target("b.example:443"),
        target("a.example:443"),
        target("b.example:443"),
        target("a.example:8443"),
    ]);
    assert_eq!(set.len(), 3);
    let order: Vec<u16> = set.iter().map(Target::port).collect();
    assert_eq!(order, [443, 443, 8443]);
    assert!(set.contains(&target("a.example:8443")));
    assert!(!set.contains(&target("c.example:443")));
    assert!(HostSet::empty().is_empty());
}
