//! The APIs a spec requires, and why one is not served.
//!
//! The usual cause of a missing API is a removed beta. The table below is from the Kubernetes
//! deprecation guide: the minor in which each beta group version stopped being served, and the group
//! version to use instead. It only words the fix. Whether an API is served comes from discovery.

use rdy_spec::check::ApiRef;

/// What replaces a removed group version.
enum Instead {
    /// Use this group version.
    Use(&'static str),
    /// Use the first group version, or the second from the given Kubernetes minor on.
    UseOrFrom(&'static str, &'static str, u32),
    /// There is no replacement API. The text says what to do instead.
    Nothing(&'static str),
}

/// One removed group version. `kind` is set when the group version was removed per kind, or the kinds
/// have different replacements.
struct Removed {
    group: &'static str,
    version: &'static str,
    kind: Option<&'static str>,
    /// The Kubernetes minor that stopped serving it (the `29` of 1.29).
    minor: u32,
    instead: Instead,
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
        instead: Instead::Use(instead),
    }
}

const fn removed_kind(
    group: &'static str,
    version: &'static str,
    kind: &'static str,
    minor: u32,
    instead: Instead,
) -> Removed {
    Removed {
        group,
        version,
        kind: Some(kind),
        minor,
        instead,
    }
}

/// What to say about a PodSecurityPolicy that is gone.
const PSP_TEXT: &str = "Kubernetes has no replacement API for PodSecurityPolicy. Pod Security Admission does its job, and the product or its spec must stop asking for it.";

/// Every row is a group version served as a beta, then removed. A row with a kind comes before the row
/// for the whole group version, because the first match wins.
const REMOVED: &[Removed] = &[
    // Removed in 1.16.
    removed_kind(
        "extensions",
        "v1beta1",
        "Deployment",
        16,
        Instead::Use("apps/v1"),
    ),
    removed_kind(
        "extensions",
        "v1beta1",
        "DaemonSet",
        16,
        Instead::Use("apps/v1"),
    ),
    removed_kind(
        "extensions",
        "v1beta1",
        "ReplicaSet",
        16,
        Instead::Use("apps/v1"),
    ),
    removed_kind(
        "extensions",
        "v1beta1",
        "NetworkPolicy",
        16,
        Instead::Use("networking.k8s.io/v1"),
    ),
    removed_kind(
        "extensions",
        "v1beta1",
        "PodSecurityPolicy",
        16,
        Instead::Nothing(PSP_TEXT),
    ),
    removed("apps", "v1beta1", 16, "apps/v1"),
    removed("apps", "v1beta2", 16, "apps/v1"),
    // Removed in 1.22.
    removed_kind(
        "extensions",
        "v1beta1",
        "Ingress",
        22,
        Instead::Use("networking.k8s.io/v1"),
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
    // TokenReview.
    removed(
        "authentication.k8s.io",
        "v1beta1",
        22,
        "authentication.k8s.io/v1",
    ),
    // SubjectAccessReview, LocalSubjectAccessReview, SelfSubjectAccessReview, SelfSubjectRulesReview.
    removed(
        "authorization.k8s.io",
        "v1beta1",
        22,
        "authorization.k8s.io/v1",
    ),
    removed_kind(
        "storage.k8s.io",
        "v1beta1",
        "CSIStorageCapacity",
        27,
        Instead::Use("storage.k8s.io/v1"),
    ),
    removed("storage.k8s.io", "v1beta1", 22, "storage.k8s.io/v1"),
    // Removed in 1.25 and later.
    removed("batch", "v1beta1", 25, "batch/v1"),
    removed("discovery.k8s.io", "v1beta1", 25, "discovery.k8s.io/v1"),
    removed("events.k8s.io", "v1beta1", 25, "events.k8s.io/v1"),
    removed("node.k8s.io", "v1beta1", 25, "node.k8s.io/v1"),
    removed_kind(
        "policy",
        "v1beta1",
        "PodSecurityPolicy",
        25,
        Instead::Nothing(PSP_TEXT),
    ),
    removed("policy", "v1beta1", 25, "policy/v1"),
    removed("autoscaling", "v2beta1", 25, "autoscaling/v2"),
    removed("autoscaling", "v2beta2", 26, "autoscaling/v2"),
    Removed {
        group: "flowcontrol.apiserver.k8s.io",
        version: "v1beta1",
        kind: None,
        minor: 26,
        // v1beta3 is served from 1.26, v1 only from 1.29.
        instead: Instead::UseOrFrom(
            "flowcontrol.apiserver.k8s.io/v1beta3",
            "flowcontrol.apiserver.k8s.io/v1",
            29,
        ),
    },
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
        let removed = row.minor;
        let what = match &row.instead {
            Instead::Use(instead) => {
                format!("Ask the vendor for a build that uses \"{instead}\".")
            }
            Instead::UseOrFrom(first, later, from) => format!(
                "Ask the vendor for a build that uses \"{first}\", or \"{later}\" from Kubernetes 1.{from}."
            ),
            Instead::Nothing(text) => (*text).to_owned(),
        };
        return format!(
            "\"{shown}\" was removed in Kubernetes 1.{removed}. This cluster is 1.{minor}, so the product or its spec is older than the cluster. {what}"
        );
    }
    match api.group() {
        Some(group) => format!(
            "\"{shown}\" is not served. If it is a built-in API, the cluster is too old or the API is switched off: `kubectl api-versions` lists what the cluster serves, and the group is \"{group}\". If a CRD or an add-on provides it, install that."
        ),
        None => format!("\"{shown}\" is not served. The cluster may be too old for it."),
    }
}
