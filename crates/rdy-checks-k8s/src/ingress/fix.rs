//! The fix text of `k8s.ingress` (03, "Fix"). Short, specific, and each command is on the fix-text allow-list
//! (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! The controller and the namespace come from the spec, which `rdy-spec` holds to the shape of a name, so
//! they are safe in a command span. A class or Service name comes from the server: it goes into a command
//! span only when it has the shape of an object name, and is a placeholder otherwise. Every other thing the
//! server sent goes into prose through `super::judge::shown`, never into a span.

/// The longest object name.
const MAX_NAME: usize = 253;

/// True when `text` has the shape of a Kubernetes object name (a DNS subdomain), so it is safe in a command:
/// lower case letters, digits, `-` and `.`, starting and ending with a letter or digit, with no empty part.
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

/// The retirement text of 03 for the community Ingress NGINX controller.
pub(super) fn retired() -> &'static str {
    "Ingress NGINX (`k8s.io/ingress-nginx`) was retired upstream in March 2026. It still runs but gets no releases or security fixes. If the product needs an ingress controller, pick one your platform team supports (a Gateway API implementation, Traefik, or a cloud controller). Existing Ingress objects with `nginx` annotations do not carry over unchanged; the `ingress2gateway` tool helps convert them. The F5 controller (`nginx.org/ingress-controller`) is a different project and is not retired."
}

/// The fix for a required controller that no class names.
pub(super) fn no_class(controller: &str) -> String {
    if controller == "any" {
        "No `IngressClass` exists. Install an ingress controller your platform team supports, or tell the vendor which classes exist. List the classes with `kubectl get ingressclass`.".to_owned()
    } else {
        format!(
            "No `IngressClass` with controller `{controller}`. Install an ingress controller your platform team supports, or tell the vendor which classes exist. List the classes with `kubectl get ingressclass`."
        )
    }
}

/// The line for a platform that has its own ingress, where a missing class proves nothing.
pub(super) fn built_in(gke: bool) -> &'static str {
    if gke {
        "GKE has a built-in ingress controller that needs no `IngressClass`, so whether the product's ingress works is not verified. Ask the vendor which ingress it uses on GKE, and list any classes with `kubectl get ingressclass`."
    } else {
        "OpenShift serves ingress through its router and prefers a `Route`, so whether the product's ingress works is not verified. Check it by hand: `oc get ingresscontroller -n openshift-ingress-operator`."
    }
}

/// The fix for classes that exist and none is the default.
pub(super) fn no_default(first: &str) -> String {
    let name = object(first);
    format!(
        "No `IngressClass` is the default, so an Ingress with no `ingressClassName` is ignored. Ask the vendor to set `ingressClassName` in its chart values, or mark the class you want as the default: `kubectl annotate ingressclass {name} ingressclass.kubernetes.io/is-default-class=true`."
    )
}

/// The fix for a Gateway API that is not installed, or not at `v1`.
pub(super) fn no_gateway_api(gke: bool, openshift: bool) -> &'static str {
    if gke {
        "The Gateway API is not installed. On GKE, enable it on the cluster and check with `kubectl get gatewayclass`."
    } else if openshift {
        "The Gateway API is not installed. OpenShift installs it with the Ingress Operator on recent releases; check with `kubectl get gatewayclass`."
    } else {
        "The Gateway API is not installed at `v1`. Install the Gateway API standard channel CRDs (bundle 1.0 or later) from your platform team's mirror or the Gateway API releases page, then a controller that implements it. Check with `kubectl get crd gateways.gateway.networking.k8s.io`."
    }
}

/// The fix for a Gateway API with no accepted class.
pub(super) fn no_accepted_class() -> &'static str {
    "No `GatewayClass` is accepted by a controller. Install a Gateway API controller, or read why a class is not accepted: `kubectl describe gatewayclass`."
}

/// The fix for an OpenShift `Route` the product needs on a cluster that does not serve it.
pub(super) fn no_route_api() -> &'static str {
    "This cluster does not serve `route.openshift.io`, so the product's `Route` objects cannot be created. Run the install on OpenShift, or ask the vendor for the Ingress or Gateway API form of the chart."
}

/// The fix for a LoadBalancer Service with no address.
pub(super) fn pending_balancer(name: &str, namespace: &str, minutes: i64, metallb: bool) -> String {
    let name = object(name);
    let hint = if metallb {
        "MetalLB is installed: create an `IPAddressPool` and an `L2Advertisement`, or check them with `kubectl get ipaddresspools -A`."
    } else {
        "On bare metal install MetalLB and an `IPAddressPool`. In a cloud, check the cloud controller manager logs for an error about this Service."
    };
    format!(
        "Service `{name}` in `{namespace}` has had no load balancer address for {minutes} minutes. {hint} Its events say why: `kubectl describe service {name} -n {namespace}`."
    )
}

/// The line for a list that has a second page.
pub(super) fn cut_list(what: &str, command: &str) -> String {
    format!("Read the rest of the {what} by hand: `{command}`.")
}

/// The fix for permissions the identity lacked: what to ask for, and the commands that check each.
pub(super) fn grants(commands: &[String], wanted: &[String]) -> String {
    format!(
        "Ask the cluster admin to grant this identity: {}. Check each with {}.",
        wanted.join(", "),
        commands.join(", ")
    )
}
