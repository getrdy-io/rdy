//! The fix text of `k8s.nodes`. Short, specific, and each command is on the fix-text allow-list
//! (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! A node name goes into a command only through `command_arg`, so a hostile name cannot become a flag.

use super::facts::{Excluded, command_arg};

/// The fix for too few counted nodes. `first` holds the first node of each reason a node does not count.
pub(super) fn add_nodes(first: &[(Excluded, &str)]) -> String {
    let mut text = String::from(
        "Add nodes the product can use: Ready, not cordoned, Linux, and with no `NoSchedule` or `NoExecute` taint the spec does not tolerate. EKS: `eksctl create nodegroup --cluster <cluster> --nodes 3 --node-type m6i.2xlarge`.",
    );
    for (reason, name) in first {
        let name = command_arg(name, "<node>");
        match reason {
            Excluded::Cordoned => {
                text.push_str(&format!(" Uncordon a node with `kubectl uncordon {name}`."));
            }
            Excluded::NotReady => text.push_str(&format!(
                " See why a node is not Ready with `kubectl describe node {name}`."
            )),
            Excluded::Tainted => text.push_str(&format!(
                " See the taints with `kubectl describe node {name}`, and add a matching toleration to the spec's `tolerations`."
            )),
            _ => {}
        }
    }
    text
}

/// The fix for a count that an autoscaler may close.
pub(super) fn scale_up() -> String {
    "Check that the autoscaler can add nodes of the size the product needs, then run rdy again once they are Ready: `kubectl get nodes`.".to_owned()
}

/// The fix for counted nodes whose allocatable CPU, memory or storage is below the need.
pub(super) fn bigger_nodes() -> String {
    "Add a node group with larger nodes (EKS: `eksctl create nodegroup --cluster <cluster> --nodes 3 --node-type m6i.2xlarge`) or lower the product's requests. Compare allocatable with `kubectl describe node <node>`: allocatable is less than the machine size.".to_owned()
}

/// The fix for a pod-count limit that is below the need.
pub(super) fn pod_limit(cloud: Option<&str>, node: &str) -> String {
    match cloud {
        Some("aws") => format!(
            "The pod limit comes from the instance type with the VPC CNI. Use a larger instance type, or turn on prefix delegation with `kubectl set env daemonset aws-node -n kube-system ENABLE_PREFIX_DELEGATION=true` and replace the nodes. Check a node with `kubectl describe node {node}`."
        ),
        _ => format!(
            "Raise `maxPods` in the kubelet configuration of the node pool, or use larger nodes. Check a node with `kubectl describe node {node}`."
        ),
    }
}

/// The fix for a pressure condition.
pub(super) fn pressure(node: &str) -> String {
    format!(
        "Find what the node is short of with `kubectl describe node {node}`: the condition has a reason. Free the resource or move the load before the install."
    )
}

/// The fix for too few zones.
pub(super) fn more_zones() -> String {
    "Spread the nodes over more zones. EKS: add subnets in other zones to the node group. GKE: `gcloud container node-pools update <pool> --cluster <cluster> --node-locations <zone-a>,<zone-b>`. AKS sets zones when a pool is made, so add one with `az aks nodepool add --resource-group <group> --cluster-name <cluster> --name <pool> --zones 1 2 3`.".to_owned()
}

/// The fix for a node list the identity may not read.
pub(super) fn grant_list() -> String {
    "Ask the cluster admin to grant this identity `list` on `nodes`. Check with `kubectl auth can-i list nodes`.".to_owned()
}

/// The fix for a node list that could not be read for another reason.
pub(super) fn by_hand() -> String {
    "Check the nodes by hand: `kubectl get nodes -o wide`.".to_owned()
}
