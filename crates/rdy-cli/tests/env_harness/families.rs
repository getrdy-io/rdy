//! The families this build registers, and the stub list of each (M1-075).
//!
//! This is the one place the env harness names a family. M1-057 moves the real list into `rdy_cli`;
//! until then, a ticket that registers a family (M1-107 for `k8s`) adds its row here, and the
//! completeness rule starts to cover its checks in the same change.

use rdy_checks_host::HostFamily;
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
/// `k8s` is not here: its checks exist but `K8sFamily` does not (M1-107), so nothing registers them yet.
pub fn rows() -> Vec<Row> {
    vec![Row {
        family: &HostFamily,
        stubs: HostFamily::stub_ids(),
    }]
}

/// A registry with every family of [`rows`].
pub fn registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    for row in rows() {
        registry.register(Shared(row.family))?;
    }
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
