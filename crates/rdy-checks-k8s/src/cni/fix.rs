//! The fix text of `k8s.cni` (03, "Fix"). Short, specific, and each command is on the fix-text allow-list
//! (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! The namespace and the `host:port` values come from the spec, which `rdy-spec` holds to the shape of a
//! Kubernetes name and of a target. Nothing the server sent goes into a command: names of policies and
//! ranges from the cluster appear only in the message and the notes, escaped and cut short.

/// The fix for a plugin that does not enforce `NetworkPolicy`.
pub(super) fn not_enforced(plugin: &str) -> String {
    format!(
        "{plugin} does not enforce NetworkPolicy, so the policies the product ships would be ignored. Ask the platform team to run a plugin that enforces it (Calico, Cilium or Antrea), or to add Calico in policy-only mode next to it. See what runs now: `kubectl get daemonset -A`."
    )
}

/// The fix for the AWS VPC CNI with its policy agent off.
pub(super) fn vpc_cni_policy_off() -> &'static str {
    "The VPC CNI network policy agent is off. Turn it on in the add-on settings (`enableNetworkPolicy` set to true, which sets `ENABLE_NETWORK_POLICY=true` on the aws-node DaemonSet), then check it: `kubectl get daemonset aws-node -n kube-system -o yaml`."
}

/// The fix for a pod or service range that overlaps a range the spec says to avoid.
pub(super) fn overlap_pod(avoid: &str) -> String {
    format!(
        "The pod range is chosen when the cluster is built and is hard to change. Ask the vendor whether the product can use another range, or build the cluster with a pod range outside {avoid} (kubeadm: `--pod-network-cidr`). See the ranges now: `kubectl get nodes -o custom-columns=NAME:.metadata.name,CIDR:.spec.podCIDRs`."
    )
}

/// The fix for a service range that overlaps a range the spec says to avoid.
pub(super) fn overlap_service(avoid: &str) -> String {
    format!(
        "The service range is chosen when the cluster is built and is hard to change. Ask the vendor whether the product can use another range, or build the cluster with a service range outside {avoid} (kubeadm: `--service-cidr`). See it now: `kubectl get servicecidr`, or `kubectl get svc kubernetes -n default`."
    )
}

/// The fix for a default-deny egress policy while the product needs egress.
pub(super) fn default_deny(namespace: &str, needs: &[String]) -> String {
    let list = needs
        .iter()
        .take(5)
        .map(|need| format!("`{need}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let more = if needs.len() > 5 {
        format!(" and {} more", needs.len() - 5)
    } else {
        String::new()
    };
    format!(
        "Namespace `{namespace}` has a default-deny egress policy. Add a NetworkPolicy there that allows egress from the product's pods to {list}{more}, and to the cluster DNS. See the current ones: `kubectl get networkpolicy -n {namespace}`."
    )
}

/// The fix for a spec with an egress need and no namespace to read.
pub(super) fn name_the_namespace() -> &'static str {
    "Name the install namespace for the Kubernetes checks of the spec, so the network policies of that namespace can be read."
}

/// The line for a policy list that has a second page.
pub(super) fn cut_policies(namespace: &str) -> String {
    format!("Read the rest by hand: `kubectl get networkpolicy -n {namespace}`.")
}

/// The line for the AWS VPC CNI setting that could not be read.
pub(super) fn check_vpc_cni() -> &'static str {
    "Check the VPC CNI by hand: `kubectl get daemonset aws-node -n kube-system -o yaml`, and look at ENABLE_NETWORK_POLICY."
}

/// The line for k3s, which runs its own policy controller unless it was told not to.
pub(super) fn check_k3s() -> &'static str {
    "Check the k3s server for the flag `--disable-network-policy` (its service file or config.yaml). Without it, k3s enforces NetworkPolicy."
}

/// The fix for permissions the identity lacked: what to ask for, and the commands that check each.
pub(super) fn grants(commands: &[String], wanted: &[String]) -> String {
    format!(
        "Ask the cluster admin to grant this identity: {}. The optional role file examples/rbac/rdy-readonly-cni.yaml holds them. Check each with {}.",
        wanted.join(", "),
        commands.join(", ")
    )
}
