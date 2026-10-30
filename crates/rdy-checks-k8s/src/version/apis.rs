//! The APIs a spec requires, and why one is not served.
//!
//! The usual cause of a missing API is a removed beta. The table below is from the Kubernetes
//! deprecation guide: the minor in which each beta group version stopped being served, and the group
//! version to use instead. It only words the fix. Whether an API is served comes from discovery.

use rdy_spec::check::ApiRef;

/// One removed group version. `kind` is set when the group version was removed per kind, at different
/// times.
struct Removed {
    group: &'static str,
    version: &'static str,
    kind: Option<&'static str>,
    /// The Kubernetes minor that stopped serving it (the `29` of 1.29).
    minor: u32,
    /// The group version to use instead.
    instead: &'static str,
}

const fn removed(
    group: &'static str,
    version: &'static str,
    minor: u32,
    instead: &'static str,
) -> Removed {
    Removed {
        group,
        version,
        kind: None,
        minor,
        instead,
    }
}

/// Every row is a group version served as a beta, then removed.
const REMOVED: &[Removed] = &[
    removed(
        "extensions",
        "v1beta1",
        22,
        "networking.k8s.io/v1 or apps/v1",
    ),
    removed("networking.k8s.io", "v1beta1", 22, "networking.k8s.io/v1"),
    removed(
        "apiextensions.k8s.io",
        "v1beta1",
        22,
        "apiextensions.k8s.io/v1",
    ),
    removed(
        "admissionregistration.k8s.io",
        "v1beta1",
        22,
        "admissionregistration.k8s.io/v1",
    ),
    removed(
        "rbac.authorization.k8s.io",
        "v1beta1",
        22,
        "rbac.authorization.k8s.io/v1",
    ),
    removed(
        "certificates.k8s.io",
        "v1beta1",
        22,
        "certificates.k8s.io/v1",
    ),
    removed(
        "coordination.k8s.io",
        "v1beta1",
        22,
        "coordination.k8s.io/v1",
    ),
    removed("scheduling.k8s.io", "v1beta1", 22, "scheduling.k8s.io/v1"),
    removed(
        "apiregistration.k8s.io",
        "v1beta1",
        22,
        "apiregistration.k8s.io/v1",
    ),
    Removed {
        group: "storage.k8s.io",
        version: "v1beta1",
        kind: Some("CSIStorageCapacity"),
        minor: 27,
        instead: "storage.k8s.io/v1",
    },
    removed("storage.k8s.io", "v1beta1", 22, "storage.k8s.io/v1"),
    removed("batch", "v1beta1", 25, "batch/v1"),
    removed("discovery.k8s.io", "v1beta1", 25, "discovery.k8s.io/v1"),
    removed("events.k8s.io", "v1beta1", 25, "events.k8s.io/v1"),
    removed("node.k8s.io", "v1beta1", 25, "node.k8s.io/v1"),
    removed("policy", "v1beta1", 25, "policy/v1"),
    removed("autoscaling", "v2beta1", 25, "autoscaling/v2"),
    removed("autoscaling", "v2beta2", 26, "autoscaling/v2"),
    removed(
        "flowcontrol.apiserver.k8s.io",
        "v1beta1",
        26,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    removed(
        "flowcontrol.apiserver.k8s.io",
        "v1beta2",
        29,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    removed(
        "flowcontrol.apiserver.k8s.io",
        "v1beta3",
        32,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
];

/// The group version a spec reference names, as discovery writes it: `autoscaling/v2` or `v1`.
pub(super) fn group_version(api: &ApiRef) -> String {
    match api.group() {
        Some(group) => format!("{group}/{}", api.version()),
        None => api.version().to_owned(),
    }
}

/// The reference as the spec wrote it: `autoscaling/v2 HorizontalPodAutoscaler`.
pub(super) fn show(api: &ApiRef) -> String {
    format!("{} {}", group_version(api), api.kind())
}

/// The sentence for an API the server does not serve, with what to do about it.
///
/// `server_minor` is the minor of the server (the `29` of 1.29). A known removal says so and names the
/// group version to use instead. Anything else gets the general causes.
pub(super) fn why_missing(api: &ApiRef, server_minor: Option<u32>) -> String {
    let shown = show(api);
    let row = api.group().and_then(|group| {
        REMOVED.iter().find(|row| {
            row.group == group
                && row.version == api.version()
                && row.kind.is_none_or(|kind| kind == api.kind())
        })
    });
    if let (Some(row), Some(minor)) = (row, server_minor)
        && minor >= row.minor
    {
        return format!(
            "\"{shown}\" was removed in Kubernetes 1.{removed}. This cluster is 1.{minor}, so this product build is older than the cluster. Ask the vendor for a build that uses \"{instead}\".",
            removed = row.minor,
            instead = row.instead,
        );
    }
    match api.group() {
        Some(group) => format!(
            "\"{shown}\" is not served. If it is a built-in API, the cluster is too old or the API is switched off: `kubectl api-versions` lists what the cluster serves, and the group is \"{group}\". If a CRD or an add-on provides it, install that."
        ),
        None => format!("\"{shown}\" is not served. The cluster may be too old for it."),
    }
}
