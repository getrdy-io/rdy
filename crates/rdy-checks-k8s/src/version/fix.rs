//! The fix text of `k8s.version`, by distribution (03, "Fix, by distribution").
//!
//! The cluster name, the region and the resource group are not known to rdy, so the commands carry
//! `<cluster>`, `<region>`, `<location>` and `<resource-group>` for the customer to fill in. Every text is
//! short and names the command to run. The commands were checked against each vendor's current upgrade
//! guide. Every command here is built from fixed text and numbers, never from text the server sent.

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

/// `1.28` for a bound written `1.28` or `1.28.3`: the channels and the managed services name minors.
fn major_minor(need: &[u32]) -> String {
    dotted(&need[..need.len().min(2)])
}

/// What the managed OpenShift services say. Their upgrades go through the service, not `oc`.
const MANAGED_OPENSHIFT: &str = "On managed OpenShift (ROSA, ARO, OpenShift Dedicated) upgrade through the service's own console or command line instead: the service runs the update.";

/// OpenShift does not skip minors, except from one extended update support release to the next.
const OPENSHIFT_STEPS: &str = "OpenShift moves one minor at a time (only an extended update support release to the next one may skip a minor), so repeat for each minor.";

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
    let first = steps
        .first()
        .cloned()
        .unwrap_or_else(|| major_minor(need));
    let mut then = String::new();
    if steps.len() > 1 {
        then = format!(", then repeat for {}", steps[1..].join(", then "));
        if capped {
            then.push_str(&format!(", and so on up to {need_text}"));
        }
    }
    match distro {
        Distro::Eks => format!(
            "{head} EKS upgrades one minor at a time. Run `aws eks update-cluster-version --region <region> --name <cluster> --kubernetes-version {first}`, wait for it to finish{then}. Then upgrade the node groups to the same version."
        ),
        Distro::Gke => format!(
            "{head} GKE moves the control plane one minor at a time. Find the {first} version with `gcloud container get-server-config --location=<location>`, then run `gcloud container clusters upgrade <cluster> --master --location=<location> --cluster-version <the {first} version>`, wait for it to finish{then}. Then upgrade the node pools."
        ),
        Distro::Aks => format!(
            "{head} AKS upgrades one minor at a time. Run `az aks upgrade -g <resource-group> -n <cluster> --kubernetes-version {first}`, wait for it to finish{then}."
        ),
        Distro::OpenShift => format!(
            "{head} Upgrade OpenShift with `oc adm upgrade`: it lists the updates the channel offers. Set the channel with `oc adm upgrade channel stable-<4.x>` first if it has none. {OPENSHIFT_STEPS} {MANAGED_OPENSHIFT}"
        ),
        Distro::K3s => format!(
            "{head} k3s upgrades one minor at a time. On each server node, one at a time, then each agent node, run the install command again: `curl -sfL https://get.k3s.io | sh -`. Repeat your original environment and arguments, and add `INSTALL_K3S_CHANNEL=v{first}` to select {first}{then}.{patch}",
            patch = pin_patch(need, "INSTALL_K3S_VERSION", "k3s1", "k3s")
        ),
        Distro::Rke2 => format!(
            "{head} RKE2 upgrades one minor at a time. On each server node, one at a time, then each agent node, run the install command again: `curl -sfL https://get.rke2.io | sh -`. Repeat your original environment and arguments, and add `INSTALL_RKE2_CHANNEL=v{first}` to select {first}{then}.{patch} Then restart with `systemctl restart rke2-server` (`rke2-agent` on an agent node).",
            patch = pin_patch(need, "INSTALL_RKE2_VERSION", "rke2r1", "RKE2")
        ),
        Distro::Kind => format!(
            "{head} kind cannot upgrade in place. Delete the cluster and run `kind create cluster --image kindest/node:<tag for {need_text}>` (the tags are in the kind release notes)."
        ),
        Distro::Vanilla => format!(
            "{head} Upgrade the control plane, then the nodes, one minor at a time with your cluster tool. For kubeadm, run `kubeadm upgrade plan` on a control plane node."
        ),
    }
}

/// For a bound with a patch, how to pin it. A channel only names a minor.
fn pin_patch(need: &[u32], variable: &str, release_suffix: &str, product: &str) -> String {
    if need.len() < 3 {
        return String::new();
    }
    format!(
        " To pin the patch {need}, set `{variable}=v{need}+{release_suffix}` instead of the channel (the exact release name is on the {product} releases page).",
        need = dotted(need)
    )
}

/// The text for an OpenShift cluster below `openshift_min`.
///
/// `have` is the OpenShift version as numbers (`4.12.5`), never the text the server sent.
pub(super) fn below_openshift_min(have: &str, need: &[u32]) -> String {
    let need_text = need_text(need);
    let channel = major_minor(need);
    format!(
        "OpenShift is {have}, product needs {need_text} or newer. Run `oc adm upgrade` to see the updates the channel offers. Set the channel with `oc adm upgrade channel stable-{channel}`, then run `oc adm upgrade --to-latest`. {OPENSHIFT_STEPS} {MANAGED_OPENSHIFT}"
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

/// The text for a kubelet that is too far behind, or newer than the API server.
pub(super) fn skew() -> &'static str {
    "Kubernetes supports kubelets up to three minors older than the API server (two for a kubelet older than 1.25), and never newer. Upgrade the listed nodes (node group, node pool or `kubeadm upgrade node`), or upgrade the control plane first if the kubelet is newer. `kubectl get nodes` shows each kubelet version. A control plane with several API servers can run them at different versions. rdy saw one of them, so the oldest may be further behind."
}
