//! The fix text of `k8s.version`, by distribution (03, "Fix, by distribution").
//!
//! The cluster name and the resource group are not known to rdy, so the commands carry `<cluster>` and
//! `<resource-group>` for the customer to fill in. Every text is short and names the command to run.

use super::server::{Distro, Reported, dotted};

/// How many one-minor steps a text lists before it says "and so on".
const MAX_STEPS: usize = 6;

/// The minors to pass through, one at a time, from `have` up to `need`: `["1.27", "1.28"]`, and whether
/// the list was cut at [`MAX_STEPS`].
///
/// Empty when `need` has no minor, is on another major, or is not ahead of `have`.
fn steps(have: &Reported, need: &[u32]) -> (Vec<String>, bool) {
    let (Some(&major), Some(&target)) = (need.first(), need.get(1)) else {
        return (Vec::new(), false);
    };
    if major != have.major() || target <= have.minor() {
        return (Vec::new(), false);
    }
    let all: Vec<String> = (have.minor() + 1..=target)
        .map(|minor| format!("{major}.{minor}"))
        .collect();
    let capped = all.len() > MAX_STEPS;
    (all.into_iter().take(MAX_STEPS).collect(), capped)
}

/// `1.28` for a bound written `1.28`, `1.28.3` for `1.28.3`.
fn need_text(need: &[u32]) -> String {
    dotted(need)
}

/// The text for a cluster below `min` (a Kubernetes version), by distribution.
///
/// `have` is the server. `need` is the parts of the spec's `min`.
pub(super) fn below_min(distro: Distro, have: &Reported, need: &[u32]) -> String {
    let need_text = need_text(need);
    let head = format!(
        "Cluster is {}, product needs {need_text} or newer.",
        have.dotted()
    );
    let (steps, capped) = steps(have, need);
    let first = steps.first().cloned().unwrap_or_else(|| need_text.clone());
    let mut then = String::new();
    if steps.len() > 1 {
        then = format!(", then repeat for {}", steps[1..].join(", then "));
        if capped {
            then.push_str(&format!(", and so on up to {need_text}"));
        }
    }
    match distro {
        Distro::Eks => format!(
            "{head} EKS upgrades one minor at a time. Run `aws eks update-cluster-version --name <cluster> --kubernetes-version {first}`, wait for it to finish{then}. Then upgrade the node groups to the same version."
        ),
        Distro::Gke => format!(
            "{head} Run `gcloud container clusters upgrade <cluster> --master --cluster-version {need_text}`, then upgrade the node pools."
        ),
        Distro::Aks => format!(
            "{head} AKS upgrades one minor at a time. Run `az aks upgrade -g <resource-group> -n <cluster> --kubernetes-version {first}`, wait for it to finish{then}."
        ),
        Distro::OpenShift => format!(
            "{head} Upgrade OpenShift with `oc adm upgrade`: it lists the updates the channel offers. Set the channel with `oc adm upgrade channel stable-<4.x>` first if it has none."
        ),
        Distro::K3s => format!(
            "{head} On each server node, then each agent node, run the k3s install script again with `INSTALL_K3S_CHANNEL=v{need_text}`."
        ),
        Distro::Rke2 => format!(
            "{head} On each server node, then each agent node, run the RKE2 install script again with `INSTALL_RKE2_CHANNEL=v{need_text}`, then restart the `rke2-server` or `rke2-agent` service."
        ),
        Distro::Kind => format!(
            "{head} kind cannot upgrade in place. Delete the cluster and run `kind create cluster --image kindest/node:<tag for {need_text}>` (the tags are in the kind release notes)."
        ),
        Distro::Vanilla => format!(
            "{head} Upgrade the control plane, then the nodes, one minor at a time with your cluster tool. For kubeadm, run `kubeadm upgrade plan` on a control plane node."
        ),
    }
}

/// The text for an OpenShift cluster below `openshift_min`.
pub(super) fn below_openshift_min(have: &str, need: &[u32]) -> String {
    let need_text = need_text(need);
    let channel = need
        .iter()
        .take(2)
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".");
    format!(
        "OpenShift is {have}, product needs {need_text} or newer. Run `oc adm upgrade` to see the updates the channel offers. Set the channel with `oc adm upgrade channel stable-{channel}`, then run `oc adm upgrade --to-latest`."
    )
}

/// The text for a cluster above `max`.
pub(super) fn above_max(have: &Reported, max: &[u32]) -> String {
    format!(
        "Cluster is {}, newer than the {} this product is tested on. Ask the vendor whether it supports this version, or install on a cluster at {} or older.",
        have.dotted(),
        dotted(max),
        dotted(max)
    )
}

/// The text for a kubelet that is more than three minors behind, or newer than the API server.
pub(super) fn skew() -> &'static str {
    "Kubernetes supports kubelets up to three minors older than the API server, and never newer. Upgrade the listed nodes (node group, node pool or `kubeadm upgrade node`), or upgrade the control plane first if the kubelet is newer. `kubectl get nodes` shows each kubelet version."
}
