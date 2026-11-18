//! The families this build registers, and the stub list of each (M1-075).
//!
//! This is the one place the env harness names a family. M1-057 moves the real list into `rdy_cli`;
//! until then, a ticket that registers a family (M1-107 for `k8s`) adds its row here, and the
//! completeness rule starts to cover its checks in the same change.

use rdy_checks_host::HostFamily;
use rdy_checks_k8s::K8sFamily;
use rdy_checks_k8s::client::Env;
use rdy_checks_net::NetFamily;
use rdy_engine::check::CheckInfo;
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

/// A registered family and the ids in it that are still stubs.
///
/// An implemented check is a registered one that is not a stub (`checks()` minus `stubs`).
#[derive(Clone, Copy)]
pub struct Row {
    /// The family.
    pub family: &'static dyn Family,
    /// The check ids that have no code yet.
    pub stubs: &'static [&'static str],
}

/// The families of this build, in registration order.
///
/// `k8s` is not here: it is added to the registry only (see `registry`).
pub fn rows() -> Vec<Row> {
    vec![
        Row {
            family: &HostFamily,
            stubs: HostFamily::stub_ids(),
        },
        // `net` lists only the checks that are written, so it has no stubs (M1-157).
        Row {
            family: &NetFamily,
            stubs: &[],
        },
    ]
}

/// A registry with every family of [`rows`], and the `k8s` family over an empty environment (M1-118).
///
/// The empty `Env` has no `KUBECONFIG`, no home directory and no pod, so the lazy probe finds no kubeconfig
/// and every k8s check is skipped `missing_need`, whatever the machine running the test has. The family is
/// not a row: the harness has no kube mock to serve a cluster (the mock is test code inside
/// `rdy-checks-k8s`), so the completeness rule does not ask the k8s checks for env cases.
pub fn registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    for row in rows() {
        registry.register(Shared(row.family))?;
    }
    registry.register(K8sFamily::with_env(Env::default()))?;
    Ok(registry)
}

/// A `&'static dyn Family` that the registry can own.
struct Shared(&'static dyn Family);

impl Family for Shared {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        self.0.checks()
    }

    fn build(
        &self,
        entry: &CheckSpec,
        params: CheckParams,
        spec: &Spec,
    ) -> Result<Built, BuildError> {
        self.0.build(entry, params, spec)
    }
}
