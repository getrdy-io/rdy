//! Policy engines and OpenShift, found by their API groups.
//!
//! Discovery says which groups the API server serves. It does not say whether a policy is enforced, whether
//! the engine's webhook is up, or which namespaces a policy matches, and it cannot tell a running engine
//! from the CRDs that an uninstall left behind. So a group is evidence that an engine is installed, and the
//! text says so. The policies themselves are read by the M1-late half of this check (M1-160).
//!
//! The categories, from each project's own documentation:
//!
//! - **Policy engines that run as admission webhooks and bring their own policy CRDs.** Kyverno serves
//!   `kyverno.io` (`ClusterPolicy` and `Policy`, marked for deprecation in Kyverno 1.17, deprecated in 1.19,
//!   removal planned for 1.20; they live in `kyverno.io/v1` and `v2beta1`, never in `v2`, which the server
//!   prefers) and `policies.kyverno.io` (the CEL-based `ValidatingPolicy` and its siblings,
//!   promoted to `v1` in 1.17; the Kyverno policy types page lists them as stable since 1.18). After the
//!   removal `kyverno.io` still serves other kinds such as `PolicyException`, so a group is not proof that
//!   the legacy kinds exist: the kinds are read, and the fix text names a command only for a kind that is
//!   served (or when the read failed, so it is not known). Gatekeeper serves
//!   `templates.gatekeeper.sh` (`ConstraintTemplate`) and `constraints.gatekeeper.sh`, where each template
//!   creates one constraint kind. A constraint with `enforcementAction: deny` (the default) rejects.
//! - **What Kubernetes itself ships**: Pod Security admission (the namespace labels, read by this check),
//!   `ValidatingAdmissionPolicy` and the webhook configurations (M1-160).
//! - **A distribution's own gate**: OpenShift serves `security.openshift.io`, whose
//!   `SecurityContextConstraints` decide whether a pod is admitted.

/// The group that says the cluster is OpenShift.
pub(super) const OPENSHIFT_GROUP: &str = "security.openshift.io";

/// The most kinds of one group that a sentence lists.
const MAX_KINDS: usize = 8;

/// The engines this check recognises, each with the groups that show it, in the order they are shown.
pub(super) const ENGINES: &[(&str, &[&str])] = &[
    ("Kyverno", &["kyverno.io", "policies.kyverno.io"]),
    (
        "Gatekeeper",
        &["templates.gatekeeper.sh", "constraints.gatekeeper.sh"],
    ),
];

/// One group of an engine that the server serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FoundGroup {
    pub(super) group: &'static str,
    /// The group version discovery read, when it was read.
    pub(super) version: Option<String>,
    /// The kinds that version serves, sorted, subresources left out, at most [`MAX_KINDS`]. Empty when
    /// the group version could not be read.
    pub(super) kinds: Vec<String>,
    /// How many kinds were left out of `kinds` because the list was cut.
    pub(super) more: usize,
    /// Whether the group serves `ClusterPolicy` or `Policy` in any version that was read, found before the
    /// list was cut. `None` when a read that could have said failed (forbidden, a status, no time left),
    /// which the fix text treats as "maybe": it shows the command. Only `kyverno.io` is asked.
    pub(super) legacy_policies: Option<bool>,
}

/// One group of `GET /apis`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Group {
    pub(super) name: String,
    /// The version the server prefers, else the first one it lists.
    pub(super) preferred: Option<String>,
    /// Every version the server lists, in its order.
    pub(super) versions: Vec<String>,
}

/// The group that holds the legacy Kyverno kinds.
pub(super) const KYVERNO_GROUP: &str = "kyverno.io";

/// The version of [`KYVERNO_GROUP`] that holds `ClusterPolicy` and `Policy` once a newer version (`v2`, with
/// `PolicyException`) is the preferred one. The server prefers the highest version of any kind in the group
/// (Kyverno 1.12 to 1.19 serve `v2`, `v1` and `v2beta1`), so the preferred version alone does not show them.
const LEGACY_VERSION: &str = "v1";

/// The other version to read for the legacy kinds: `v1` of `kyverno.io`, when the server lists it and it is
/// not the preferred version (which is read anyway).
pub(super) fn legacy_version(group: &Group) -> Option<&'static str> {
    (group.name == KYVERNO_GROUP
        && group.preferred.as_deref() != Some(LEGACY_VERSION)
        && group.versions.iter().any(|v| v == LEGACY_VERSION))
    .then_some(LEGACY_VERSION)
}

/// An engine that at least one of its groups shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Found {
    pub(super) engine: &'static str,
    pub(super) groups: Vec<FoundGroup>,
}

/// The engine groups to read, as `(engine, group)`, for the groups the server serves.
pub(super) fn served(groups: &[Group]) -> Vec<(&'static str, &'static str)> {
    ENGINES
        .iter()
        .flat_map(|(engine, names)| names.iter().map(move |name| (*engine, *name)))
        .filter(|(_, name)| groups.iter().any(|group| group.name == *name))
        .collect()
}

/// The longest name a kind can have (a DNS label, 63 characters).
const MAX_KIND_LEN: usize = 63;

/// True when `kind` has the shape of a real Kubernetes kind: a letter, then letters and digits, at most
/// [`MAX_KIND_LEN`] characters.
fn is_kind_shaped(kind: &str) -> bool {
    kind.len() <= MAX_KIND_LEN
        && kind.starts_with(|c: char| c.is_ascii_alphabetic())
        && kind.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// True when the kinds name the legacy Kyverno policy kinds.
pub(super) fn has_legacy_policies(kinds: &[String]) -> bool {
    kinds
        .iter()
        .any(|kind| kind == "ClusterPolicy" || kind == "Policy")
}

/// A discovery kind list cut to what a sentence lists: no repeats, no empty name, sorted with the names
/// shaped like a kind first, so a server that serves hostile names cannot push the real kinds out.
pub(super) fn cut_kinds(mut kinds: Vec<String>) -> (Vec<String>, usize) {
    kinds.retain(|kind| !kind.is_empty());
    kinds.sort_by(|a, b| (!is_kind_shaped(a), a).cmp(&(!is_kind_shaped(b), b)));
    kinds.dedup();
    let more = kinds.len().saturating_sub(MAX_KINDS);
    kinds.truncate(MAX_KINDS);
    (kinds, more)
}

/// Groups the found group versions by engine, in the order of [`ENGINES`].
pub(super) fn found(read: Vec<(&'static str, FoundGroup)>) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    for (engine, _) in ENGINES {
        let groups: Vec<FoundGroup> = read
            .iter()
            .filter(|(name, _)| name == engine)
            .map(|(_, group)| group.clone())
            .collect();
        if !groups.is_empty() {
            out.push(Found { engine, groups });
        }
    }
    out
}
