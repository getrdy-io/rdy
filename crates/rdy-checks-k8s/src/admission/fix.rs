//! The fix text of `k8s.admission` (03, "Fix"). Short, specific, and each command is on the fix-text
//! allow-list (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! The namespace and the SCC come from the spec, which `rdy-spec` holds to the shape of a Kubernetes name,
//! so they are safe in a command. Nothing here repeats text the server sent.

use super::level::Need;
use super::level::Standard;

/// How the namespace is written in a command: its name, or a placeholder when the spec has none.
fn ns_arg(namespace: Option<&str>) -> &str {
    namespace.unwrap_or("<namespace>")
}

/// Why the product needs its level, as a sentence.
fn because(need: &Need) -> String {
    let level = need.level.name();
    if need.because.is_empty() {
        return format!("The spec says the product needs `{level}`.");
    }
    let uses = join(&need.because);
    match need.level {
        Standard::Privileged => format!(
            "The product needs `privileged` because it uses {uses} (`baseline` forbids hostPath volumes, host networking, the host PID namespace and privileged containers)."
        ),
        Standard::Baseline => format!(
            "The product needs `baseline` because it uses {uses} (`restricted` requires `runAsNonRoot`)."
        ),
        Standard::Restricted => format!("The product needs `{level}` because it uses {uses}."),
    }
}

/// `a`, `a and b`, `a, b and c`.
fn join(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The fix for an enforce label stricter than the product needs. `have` is what the namespace enforces, as
/// a word; `read_as` says so when the label value was invalid.
pub(super) fn enforce(namespace: &str, have: Standard, invalid: bool, need: &Need) -> String {
    let level = need.level.name();
    let had = if invalid {
        "an invalid Pod Security enforce label, which the API server reads as `restricted`"
            .to_owned()
    } else {
        format!("`{}`", have.name())
    };
    let verb = if invalid { "has" } else { "enforces" };
    format!(
        "Namespace `{namespace}` {verb} {had}. {} Either set the level: `kubectl label ns {namespace} pod-security.kubernetes.io/enforce={level} --overwrite`, or ask the vendor for chart values that fit `{}`.",
        because(need),
        have.name()
    )
}

/// The fix for a `warn` or `audit` label stricter than the product needs.
pub(super) fn soften(namespace: &str, mode: &str, have: Standard, need: &Need) -> String {
    let level = need.level.name();
    format!(
        "Namespace `{namespace}` sets `{mode}` to `{}`. {} To silence it: `kubectl label ns {namespace} pod-security.kubernetes.io/{mode}={level} --overwrite`.",
        have.name(),
        because(need)
    )
}

/// The fix for OpenShift when the spec names no SCC (03, "Fix").
pub(super) fn openshift(namespace: Option<&str>) -> String {
    let ns = ns_arg(namespace);
    format!(
        "On OpenShift the SCC decides, not the namespace label. `restricted-v2` is the default: it requires a UID in the namespace range and drops all capabilities, and the usual failure is an image or chart that pins `runAsUser`. First remove `runAsUser` and let the range apply. Only then grant an SCC: `oc adm policy add-scc-to-user <scc> -z <service-account> -n {ns}`. Ask the vendor which SCC the product needs, and ask them to name it as `scc` in the spec."
    )
}

/// The note for an SCC the spec names.
pub(super) fn bind_scc(scc: &str, namespace: Option<&str>) -> String {
    let ns = ns_arg(namespace);
    format!(
        "The product documents the SCC `{scc}`. After the vendor's steps, bind it to the service account that runs the product: `oc adm policy add-scc-to-user {scc} -z <service-account> -n {ns}`."
    )
}

/// The fix for a policy engine that is installed. `legacy_policies` is true when discovery showed that
/// `ClusterPolicy` or `Policy` is served: Kyverno is removing them, and `kyverno.io` goes on serving other
/// kinds, so the group alone does not say the command works.
pub(super) fn engines(
    names: &[&str],
    groups: &[&str],
    legacy_policies: bool,
    namespace: Option<&str>,
) -> String {
    let ns = ns_arg(namespace);
    let mut list: Vec<&str> = Vec::new();
    if legacy_policies {
        list.push("`kubectl get clusterpolicies.kyverno.io,policies.kyverno.io -A`");
    }
    if groups.contains(&"policies.kyverno.io") {
        list.push("`kubectl get validatingpolicies.policies.kyverno.io`");
    }
    if groups.iter().any(|group| group.ends_with(".gatekeeper.sh")) {
        list.push("`kubectl get constraints`");
    }
    let listing = if list.is_empty() {
        String::new()
    } else {
        format!(" List them with {}.", list.join(" and "))
    };
    format!(
        "Ask the platform team which {} policies apply to namespace `{ns}`.{listing} Test the vendor's manifests before install day with a server-side dry run, which creates nothing: `kubectl apply --dry-run=server -n {ns} -f <manifest>`.",
        join(names)
    )
}

/// The fix for permissions the identity lacked: what to ask for, and the commands that check each.
pub(super) fn grants(commands: &[String], wanted: &[String]) -> String {
    format!(
        "Ask the cluster admin to grant this identity: {}. Check each with {}.",
        wanted.join(", "),
        commands.join(", ")
    )
}

/// The fix for a spec that names no namespace, so the labels were not read.
pub(super) fn name_the_namespace() -> &'static str {
    "Name the install namespace in the `k8s.admission` entry (`namespace: <name>`), so its Pod Security labels can be read."
}
