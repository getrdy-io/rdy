//! The fix text of `k8s.crds` (03, "Fix"). Short, specific, and each command is on the fix-text allow-list
//! (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! Every name in a command comes from the spec, which `rdy-spec` holds to the shape of a Kubernetes name
//! (a CRD name, its group, a namespace and a deployment name), or is a placeholder (`<release>`, `<chart>`,
//! `<namespace>`). Nothing the server sent is put in a command.

/// The fix for definitions that are not installed, by API group.
///
/// The chart is never named: the vendor knows it, and a mirror may hold it under another path. The one group
/// with a known install line is cert-manager's, because its flag changed between chart versions and a wrong
/// flag installs a chart without its CRDs.
pub(super) fn install(group: &str) -> String {
    if group == "cert-manager.io" {
        return "The cert-manager CRDs are missing. Install the chart from your registry or mirror: `helm install cert-manager <chart> -n cert-manager --create-namespace --set crds.enabled=true` (`crds.enabled` is for chart 1.15 and later; older charts use `installCRDs=true`). Public source: `helm repo add jetstack https://charts.jetstack.io`. On an air-gapped cluster use the chart from your own mirror."
            .to_owned();
    }
    format!(
        "The CRDs of API group `{group}` are missing. Install the chart that ships them, from your registry or mirror: `helm install <release> <chart> -n <namespace> --create-namespace`. Use the chart reference your vendor gave you. On an air-gapped cluster that is your own mirror, not a public repository. See what the cluster serves: `kubectl api-resources --api-group={group}`."
    )
}

/// The fix for definitions that are installed without a version the product needs.
pub(super) fn upgrade(group: &str) -> String {
    format!(
        "The installed CRDs of API group `{group}` are older than the product needs. Helm does not upgrade CRDs that a chart ships in its crds directory, so apply the CRDs of the newer chart version first: `kubectl apply --server-side -f <crds.yaml>`, then upgrade the release: `helm upgrade <release> <chart> -n <namespace>`. See what the cluster serves: `kubectl api-resources --api-group={group}`."
    )
}

/// The fix for an operator Deployment that is not found.
pub(super) fn operator_missing(namespace: &str, deployment: &str) -> String {
    format!(
        "No Deployment `{deployment}` was found in namespace `{namespace}`. The operator may be a StatefulSet, or managed by OLM (check with `kubectl get statefulsets,subscriptions -A`). If it is not installed, install the operator from your registry or mirror: `helm install <release> <chart> -n {namespace} --create-namespace`. If it runs under another name, list what is there: `kubectl get deployments -n {namespace}`, and tell the vendor the right name."
    )
}

/// The fix for an operator that has fewer replicas ready than it wants.
pub(super) fn operator_not_ready(namespace: &str, deployment: &str, desired: i64) -> String {
    if desired == 0 {
        return format!(
            "Deployment `{deployment}` in `{namespace}` is scaled to 0. If that was not on purpose, scale it back up: `kubectl scale deployment {deployment} -n {namespace} --replicas=1`. Then see why it was stopped: `kubectl describe deployment {deployment} -n {namespace}`."
        );
    }
    format!(
        "Find out why the pods of `{deployment}` in `{namespace}` are not ready: `kubectl describe deployment {deployment} -n {namespace}`, then `kubectl get pods -n {namespace}`, then `kubectl logs deployment/{deployment} -n {namespace}`."
    )
}

/// The fix for an operator below the minimum version.
pub(super) fn operator_old(namespace: &str, deployment: &str) -> String {
    format!(
        "Upgrade the operator from your registry or mirror: `helm upgrade <release> <chart> -n {namespace}`. Apply the CRDs of the new version first when the chart's notes say so. See what runs now: `kubectl get deployment {deployment} -n {namespace} -o wide`."
    )
}

/// The line for an operator whose version could not be read: look at the image by hand.
pub(super) fn check_version(namespace: &str, deployment: &str) -> String {
    format!(
        "Check the version of `{deployment}` by hand: `kubectl get deployment {deployment} -n {namespace} -o wide`, and read the image tag."
    )
}

/// The line for a definition name that has no group.
pub(super) fn crd_name() -> &'static str {
    "Write each `crds` name as `<plural>.<group>`, such as `certificates.cert-manager.io`."
}

/// The fix for permissions the identity lacked: what to ask for, and the commands that check each.
pub(super) fn grants(commands: &[String], wanted: &[String]) -> String {
    let mut text = format!(
        "Ask the cluster admin to grant this identity: {}. Check each with {}.",
        wanted.join(", "),
        commands.join(", ")
    );
    if wanted
        .iter()
        .any(|grant| grant.contains("deployments.apps"))
    {
        text.push_str(
            " The file examples/rbac/rdy-readonly-operator.yaml in the rdy repository is a Role for it, one namespace and one name.",
        );
    }
    text
}
