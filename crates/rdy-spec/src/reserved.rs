//! The reserved check ids.
//!
//! `docs/plan/01-spec-format.md` section 2.4 says `rdy-spec` ships the list of every id that
//! `docs/plan/03-check-catalog.md` names, built or not. An id on the list that this rdy does not
//! implement is `not_in_build`: a newer rdy may have it. An id off the list is `unknown_check`: no
//! version of rdy has it, so it is probably a typo.
//!
//! Adding an id to the list is additive. Removing one is a breaking change of the spec format.

/// Every reserved check id, sorted. It holds the ids of the catalog sections 2 to 8, the `gcp.*` and
/// `azure.*` ids of section 5 and the reserved ids of section 9. It includes the ids this build
/// implements ([`crate::check::KNOWN_IDS`]).
pub const RESERVED_IDS: &[&str] = &[
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
///
/// See [`crate::check::CheckParams::unknown_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnknownKind {
    /// The id is reserved. A newer rdy may implement it. Lint warns and sign allows it.
    NotInBuild,
    /// The id is not reserved. No version of rdy has it, so it is probably a typo. Lint and sign
    /// treat it as an error.
    UnknownCheck,
}

/// Whether `id` is on the reserved list. The match is exact: ids are lowercase.
#[must_use]
pub fn is_reserved_id(id: &str) -> bool {
    RESERVED_IDS.binary_search(&id).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::KNOWN_IDS;

    #[test]
    fn the_list_is_sorted_and_has_no_duplicates() {
        assert!(RESERVED_IDS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn every_reserved_id_reads_as_a_check_id() {
        for id in RESERVED_IDS {
            assert!(crate::spec::CheckId::new(*id).is_ok(), "{id}");
        }
    }

    #[test]
    fn every_id_this_build_implements_is_reserved() {
        for id in KNOWN_IDS {
            assert!(is_reserved_id(id), "{id}");
        }
    }

    #[test]
    fn typos_and_other_families_are_not_reserved() {
        for id in ["host.memroy", "upload.now", "host.Kernel", "", "host"] {
            assert!(!is_reserved_id(id), "{id:?}");
        }
        assert!(is_reserved_id("host.kernel"));
        assert!(is_reserved_id("gpu.cuda"));
    }
}
