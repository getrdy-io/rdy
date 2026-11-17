//! The check families of this build, in one place (M1-057, ADR 0026 decision 5).
//!
//! [`registry`] is the list `rdy run` plans against and the list `cargo xtask checks` and the docs read,
//! so the docs and the binary cannot disagree about which checks exist.
//!
//! - `host`: registered. Its stubs are skipped as `not_in_build` by the planner
//!   ([`rdy_engine::family::Family::not_built`]), so none runs on a customer's machine.
//! - `net`: registered with `net.egress` (M1-095) and `net.mtu` (M1-157). The other `net.*` ids are not built, so the planner skips
//!   them as `not_in_build`. The check declares the `network` need, so `--no-network` skips it as
//!   `missing_need`.
//! - `k8s`: registered (M1-107) with every k8s check of the crate (M1-175): `k8s.version`, `k8s.access`,
//!   `k8s.storageclass`, `k8s.rbac`, `k8s.nodes`, `k8s.admission` and `k8s.namespace`. The family probes
//!   `kube_context` once per run, and only when the plan holds a runnable k8s check.
//!
//! Each family ticket adds its line here, and nowhere else.

use rdy_engine::family::{Registry, RegistryError};

/// The families this build registers, in the order the docs list them.
///
/// # Errors
///
/// [`RegistryError`] if two families or two check ids collide. That is a mistake in the build and
/// not something an operator can cause, so `rdy run` reports it as a bug.
pub fn registry() -> Result<Registry, RegistryError> {
    let mut registry = Registry::new();
    registry.register(rdy_checks_host::HostFamily)?;
    registry.register(rdy_checks_net::NetFamily)?;
    registry.register(rdy_checks_k8s::K8sFamily::new())?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::registry;

    /// Checks that reach a network peer and handle the facade's `--no-network` refusal themselves
    /// instead of naming the `network` need. Add the id here with the reason in the check.
    /// `host.time_sync` keeps its `timedatectl` verdict and says the offset was not measured
    /// (correction-39), so it must run offline.
    const HANDLES_REFUSAL: &[&str] = &["host.time_sync"];

    #[test]
    fn every_check_that_reaches_the_network_gates_on_it() {
        let registry = registry().expect("the registry builds");
        for info in registry.infos() {
            assert!(
                !info.reaches_network()
                    || info.gates_on_network()
                    || HANDLES_REFUSAL.contains(&info.id),
                "{} reaches the network and declares no network or kube_context need",
                info.id
            );
        }
    }

    #[test]
    fn the_registry_builds_and_holds_the_host_net_and_k8s_families() {
        let registry = registry().expect("the registry builds");
        assert!(registry.family("host").is_some());
        assert!(registry.check("host.cpu").is_some());
        assert!(registry.family("net").is_some());
        assert!(registry.check("net.egress").is_some());
        assert!(registry.check("net.proxy").is_some());
        assert!(registry.check("net.dns").is_none());
        assert!(registry.family("k8s").is_some());
        assert!(registry.check("k8s.version").is_some());
        assert!(registry.check("k8s.access").is_some());
    }
}
