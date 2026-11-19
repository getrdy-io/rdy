//! The families this build registers, and the stub list of each (M1-075).
//!
//! This is the one place the env harness names a family. M1-057 moves the real list into `rdy_cli`;
//! until then, a ticket that registers a family (M1-107 for `k8s`) adds its row here, and the
//! completeness rule starts to cover its checks in the same change.

use rdy_checks_host::HostFamily;
use rdy_checks_k8s::K8sFamily;
use rdy_checks_k8s::client::Env;
use rdy_checks_k8s::testing::ScriptedCluster;
use rdy_checks_net::NetFamily;
use rdy_engine::check::CheckInfo;
use rdy_engine::family::{BuildError, Built, Family, Registry, RegistryError};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};
use std::cell::RefCell;

thread_local! {
    /// The scripted cluster of the env being run on this thread. `RunHooks::families` is a plain function
    /// with no state, and `run_env` runs the whole run on the thread that set this, so the cell is how the
    /// env's cluster reaches `registry`.
    static CLUSTER: RefCell<Option<ScriptedCluster>> = const { RefCell::new(None) };
}

/// Serves `cluster` to the `k8s` family of the next `registry` call on this thread. `None` serves none.
pub fn serve(cluster: Option<ScriptedCluster>) {
    CLUSTER.with(|cell| *cell.borrow_mut() = cluster);
}

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

/// A registry with every family of [`rows`], and the `k8s` family.
///
/// With a scripted cluster ([`serve`], an env whose `kube` cap is true) the family reads it, in process,
/// with the read-only guard in front (M1-185). Without one the family reads an empty `Env`: no
/// `KUBECONFIG`, no home directory and no pod, so the lazy probe finds no kubeconfig and every k8s check
/// is skipped `missing_need`, whatever the machine running the test has (M1-118). The family is not a row:
/// the completeness rule does not ask the k8s checks for env cases.
pub fn registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    for row in rows() {
        registry.register(Shared(row.family))?;
    }
    let scripted = CLUSTER.with(|cell| cell.borrow().as_ref().map(ScriptedCluster::family));
    registry.register(scripted.unwrap_or_else(|| K8sFamily::with_env(Env::empty())))?;
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
