//! The check families of this build, in one place (M1-057, ADR 0026 decision 5).
//!
//! [`registry`] is the list `rdy run` plans against and the list `cargo xtask checks` and the docs read,
//! so the docs and the binary cannot disagree about which checks exist.
//!
//! - `host`: registered. Its stubs are skipped as `not_in_build` by the planner
//!   ([`rdy_engine::family::Family::not_built`]), so none runs on a customer's machine.
//! - `net`: not registered yet. Its entries are skipped as `not_in_build` with "no net checks yet".
//! - `k8s`: not registered yet. The checks exist in `rdy-checks-k8s`, but the family arrives with the
//!   lazy kube context probe (M1-107).
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
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::registry;

    #[test]
    fn the_registry_builds_and_holds_the_host_family() {
        let registry = registry().expect("the registry builds");
        assert!(registry.family("host").is_some());
        assert!(registry.check("host.cpu").is_some());
        assert!(registry.family("net").is_none());
        assert!(registry.family("k8s").is_none());
    }
}
