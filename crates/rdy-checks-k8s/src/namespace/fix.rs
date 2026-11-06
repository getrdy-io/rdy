//! The fix text of `k8s.namespace` (03, "Fix"). Short, specific, and each command is on the fix-text
//! allow-list (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! The namespace comes from the spec, which `rdy-spec` holds to the shape of a Kubernetes name, so it is
//! safe in a command. A quota or limit range name comes from the server: it goes into a command only when
//! it has the shape of a name, and is a placeholder otherwise. Nothing else the server sent is repeated here.

use super::judge::Via;

/// The longest object name.
const MAX_NAME: usize = 253;

/// True when `text` has the shape of a Kubernetes object name (a DNS subdomain), so it is safe in a
/// command: lower case letters, digits, `-` and `.`, starting and ending with a letter or digit, with no
/// empty part.
pub(super) fn is_name(text: &str) -> bool {
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    !text.is_empty()
        && text.len() <= MAX_NAME
        && text.starts_with(edge)
        && text.ends_with(edge)
        && !text.contains("..")
        && text.chars().all(|c| edge(c) || c == '-' || c == '.')
}

/// The name of an object from the server, as it may appear in a command.
fn object(name: &str) -> &str {
    if is_name(name) { name } else { "<name>" }
}

/// The fix for a spec that names no namespace.
pub(super) fn name_the_namespace() -> &'static str {
    "Name the install namespace in the `k8s.namespace` entry (`namespace: <name>`), so it can be read."
}

/// The fix for a namespace that is being deleted.
pub(super) fn terminating(namespace: &str) -> String {
    format!(
        "Namespace `{namespace}` is being deleted. Wait for it to finish, then install. If it stays stuck, find what holds it: `kubectl get namespace {namespace} -o yaml`, and read `status.conditions`. Ask the owner of the namespace before anyone removes a finalizer."
    )
}

/// The note for a missing namespace that the identity may create.
pub(super) fn create_it(namespace: &str, via: Via) -> String {
    match via {
        Via::ProjectRequests => format!(
            "Namespace `{namespace}` does not exist yet. This identity may request a project, which creates it: `oc new-project {namespace}`."
        ),
        Via::Namespaces { .. } => format!(
            "Namespace `{namespace}` does not exist yet. This identity may create it: `kubectl create namespace {namespace}`, or let the installer do it."
        ),
    }
}

/// The fix for a missing namespace that the identity may not create.
pub(super) fn ask_platform(namespace: &str, via: Via) -> String {
    match via {
        Via::ProjectRequests => format!(
            "Ask the platform team to create `{namespace}` and grant your identity admin in it: `oc new-project {namespace}`, then `oc adm policy add-role-to-user admin <identity> -n {namespace}`."
        ),
        Via::Namespaces { sure: true } => format!(
            "Ask the platform team to create `{namespace}` and grant your identity admin in it: `kubectl create namespace {namespace}`, then `kubectl create rolebinding installer-admin --clusterrole=admin --user=<identity> -n {namespace}`."
        ),
        Via::Namespaces { sure: false } => format!(
            "Ask the platform team to create `{namespace}` and grant your identity admin in it: `kubectl create namespace {namespace}`, or on OpenShift `oc new-project {namespace}`. Also ask for the right to read the API group list (check it with `kubectl get --raw /apis`), so rdy can tell the two apart."
        ),
    }
}

/// The fix for a quota with too little left.
pub(super) fn quota(
    name: &str,
    namespace: &str,
    resource: &str,
    left: &str,
    hard: &str,
    used: &str,
    need: &str,
) -> String {
    let name = object(name);
    format!(
        "Quota `{name}` in `{namespace}` allows {hard} of `{resource}` and {used} are used, so {left} is left and the product needs {need}. Ask an admin to raise it: `kubectl edit resourcequota {name} -n {namespace}`."
    )
}

/// The fix for a limit range that caps a container below what the product needs.
pub(super) fn limit_max(name: &str, namespace: &str, kind: &str, max: &str, need: &str) -> String {
    let name = object(name);
    format!(
        "LimitRange `{name}` in `{namespace}` caps a {kind} at {max} of memory, and the product's largest container needs {need}. Ask an admin to raise its max: `kubectl edit limitrange {name} -n {namespace}`."
    )
}

/// The note for a limit range whose default limit is below what the product needs.
///
/// A container with no resources gets the default limit, and the default request, or the default limit
/// again when `defaultRequest` is unset. So a big product is killed at runtime, not refused at admission.
pub(super) fn limit_default(
    name: &str,
    namespace: &str,
    default: &str,
    default_request: Option<&str>,
    need: &str,
) -> String {
    let name = object(name);
    let given = match default_request {
        Some(request) => format!("a request of {request} and a limit of {default}"),
        None => format!("a request and a limit of {default} both (its defaultRequest is unset)"),
    };
    format!(
        "LimitRange `{name}` in `{namespace}` gives a container that sets no memory resources {given}. A product container that needs {need} and sets nothing is OOM-killed at runtime, not refused at admission. One that sets a request of {need} and no limit gets {default} as its limit, and the pod is rejected. Set memory requests and limits on the product's containers (ask the vendor for chart values), or ask an admin to raise the default: `kubectl edit limitrange {name} -n {namespace}`."
    )
}

/// The line for a quota that could not be judged: look at it by hand.
pub(super) fn check_quota(name: &str, namespace: &str) -> String {
    let name = object(name);
    format!("Check quota `{name}` by hand: `kubectl describe resourcequota {name} -n {namespace}`.")
}

/// The line for limit ranges with an amount that could not be read.
pub(super) fn check_limit_ranges(namespace: &str) -> String {
    format!(
        "Check the limit ranges by hand: `kubectl describe limitrange -n {namespace}`, and look at the memory max and default."
    )
}

/// The line for a create right that could not be checked.
pub(super) fn check_create(namespace: &str, via: Via) -> String {
    match via {
        Via::ProjectRequests => format!(
            "Check it by hand: `oc auth can-i create projectrequests`, and `kubectl auth can-i create namespaces`. Namespace `{namespace}` does not exist yet."
        ),
        Via::Namespaces { .. } => format!(
            "Check it by hand: `kubectl auth can-i create namespaces`. Namespace `{namespace}` does not exist yet."
        ),
    }
}

/// The line for a quota amount in the spec that is not a quantity.
pub(super) fn spec_amount() -> &'static str {
    "Write each `quota_needs` amount as a Kubernetes quantity, such as `16`, `500m` or `64Gi`."
}

/// The line for a list that has a second page.
pub(super) fn cut_list(namespace: &str, kind: &str) -> String {
    format!("Read the rest by hand: `kubectl get {kind} -n {namespace}`.")
}

/// The fix for permissions the identity lacked: what to ask for, and the commands that check each.
pub(super) fn grants(commands: &[String], wanted: &[String]) -> String {
    format!(
        "Ask the cluster admin to grant this identity: {}. Check each with {}.",
        wanted.join(", "),
        commands.join(", ")
    )
}
