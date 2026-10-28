//! A stand-in for `rdy_spec::reserved` (M1-023, not on main yet).
//!
//! It exists so the planner can tell `not_in_build` from `unknown_check` today. When M1-023 merges,
//! delete this file and call `CheckParams::unknown_kind` in `plan.rs` instead. [`classify`] is the only
//! thing the planner uses, so the swap is one call site. The list is copied from M1-023 and is sorted.

/// The families the spec format reserves (01 section 2.4).
const RESERVED_FAMILIES: &[&str] = &[
    "aws", "azure", "custom", "gcp", "gpu", "host", "k8s", "net", "store",
];

/// Every reserved check id, sorted. It holds the ids of the catalog sections 2 to 8, the `gcp.*` and
/// `azure.*` ids of section 5 and the reserved ids of section 9. It includes the ids this build
/// implements (`rdy_spec::check::KNOWN_IDS`).
const RESERVED_IDS: &[&str] = &[
    "aws.eks",
    "aws.iam",
    "aws.identity",
    "aws.imds",
    "aws.quota",
    "aws.region",
    "aws.vpc",
    "azure.providers",
    "azure.quota",
    "azure.rbac",
    "azure.region",
    "custom.exec",
    "custom.file",
    "gcp.apis",
    "gcp.iam",
    "gcp.quota",
    "gcp.region",
    "gpu.cuda",
    "gpu.devices",
    "gpu.driver",
    "gpu.fabric",
    "gpu.health",
    "gpu.model_egress",
    "gpu.rocm",
    "gpu.runtime",
    "gpu.vgpu_license",
    "gpu.vram",
    "host.cgroups",
    "host.container_runtime",
    "host.cpu",
    "host.disk",
    "host.firewall",
    "host.hostname",
    "host.kernel",
    "host.lsm",
    "host.memory",
    "host.os",
    "host.ports",
    "host.security_agents",
    "host.sysctl",
    "host.time_sync",
    "host.virtualization",
    "k8s.access",
    "k8s.admission",
    "k8s.cni",
    "k8s.crds",
    "k8s.device_plugins",
    "k8s.dns",
    "k8s.egress_probe",
    "k8s.images",
    "k8s.ingress",
    "k8s.metrics",
    "k8s.namespace",
    "k8s.nodes",
    "k8s.rbac",
    "k8s.snapshots",
    "k8s.storageclass",
    "k8s.version",
    "net.bandwidth",
    "net.dns",
    "net.egress",
    "net.mtu",
    "net.pmtu",
    "net.proxy",
    "net.registry",
    "net.tls_intercept",
    "store.kafka",
    "store.postgres",
    "store.redis",
    "store.s3",
];

/// Why an id this build does not implement is skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Why {
    /// The id is reserved. A newer rdy may have it.
    NotInBuild,
    /// The id is not reserved. It is probably a typo.
    UnknownCheck {
        /// Whether the family part is reserved, so a newer rdy may know the check.
        family_reserved: bool,
    },
}

/// Classifies an id that decoding did not recognise.
pub(super) fn classify(id: &str) -> Why {
    if RESERVED_IDS.binary_search(&id).is_ok() {
        return Why::NotInBuild;
    }
    let family_reserved = id
        .split_once('.')
        .is_some_and(|(family, _)| RESERVED_FAMILIES.binary_search(&family).is_ok());
    Why::UnknownCheck { family_reserved }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_are_sorted() {
        assert!(RESERVED_IDS.windows(2).all(|w| w[0] < w[1]));
        assert!(RESERVED_FAMILIES.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn reserved_ids_are_not_in_build_and_typos_are_unknown() {
        assert_eq!(classify("gpu.cuda"), Why::NotInBuild);
        assert_eq!(classify("host.kernel"), Why::NotInBuild);
        assert_eq!(
            classify("host.memroy"),
            Why::UnknownCheck {
                family_reserved: true
            }
        );
        assert_eq!(
            classify("upload.now"),
            Why::UnknownCheck {
                family_reserved: false
            }
        );
        assert_eq!(
            classify("nodots"),
            Why::UnknownCheck {
                family_reserved: false
            }
        );
    }
}
