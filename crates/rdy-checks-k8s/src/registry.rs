//! The registry of the checks this crate has built.

use rdy_engine::check::CheckInfo;

use crate::{access, admission, dns, namespace, nodes, rbac, storageclass, version};

/// Every `k8s.*` check this crate has built, in catalog order.
static INFOS: [&CheckInfo; 8] = [
    &access::INFO,
    &admission::INFO,
    &dns::INFO,
    &namespace::INFO,
    &nodes::INFO,
    &rbac::INFO,
    &storageclass::INFO,
    &version::INFO,
];

/// The `CheckInfo` of every `k8s.*` check this crate has built.
///
/// Every k8s check registers its info here. The citation test in `client/guard/tests/parser.rs` reads
/// this list and requires that each check id cited by `ALLOWED` is either here or on its `NOT_BUILT_YET`
/// list, and never both. So each check ticket (every k8s check of M1 has landed) adds
/// its info here and removes its id from `NOT_BUILT_YET` in the same change. M1-115 requires
/// `NOT_BUILT_YET` to be empty. `k8s.access` (M1-109) cites no `ALLOWED` entry (discovery and the reviews
/// are exempt), so it is registered and appears in no `NOT_BUILT_YET` list.
pub(crate) fn infos() -> &'static [&'static CheckInfo] {
    &INFOS
}

#[cfg(test)]
mod tests {
    /// A check that reaches the Kubernetes API must name `kube_context` or `network`, so `--no-network`
    /// skips it at the need gate. A check that handles the facade refusal itself is listed here.
    const HANDLES_REFUSAL: &[&str] = &[];

    #[test]
    fn every_check_that_reaches_the_api_gates_on_the_network() {
        for info in super::infos() {
            assert!(
                !info.reaches_network()
                    || info.gates_on_network()
                    || HANDLES_REFUSAL.contains(&info.id),
                "{} reaches the network and does not declare a network or kube_context need",
                info.id
            );
        }
    }
}
