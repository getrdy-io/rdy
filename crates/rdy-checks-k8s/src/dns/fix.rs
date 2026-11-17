//! The fix text of `k8s.dns` (03, "Fix"). Short, specific, and each command is on the fix-text allow-list
//! (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! A workload or pod name comes from the server: it goes into a command only when it has the shape of a
//! Kubernetes name, and is a placeholder otherwise. Nothing else the server sent is repeated here.

use super::objects::Workload;
use super::{KUBE_SYSTEM, OPENSHIFT_DNS};

/// The longest object name.
const MAX_NAME: usize = 253;

/// True when `text` has the shape of a Kubernetes object name (a DNS subdomain), so it is safe in a
/// command.
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
pub(super) fn object(name: &str) -> &str {
    if is_name(name) { name } else { "<name>" }
}

/// The label selector of the DNS pods in `namespace`, for `kubectl get pods -l`.
fn pod_label(namespace: &str) -> &'static str {
    if namespace == OPENSHIFT_DNS {
        "dns.operator.openshift.io/daemonset-dns=default"
    } else {
        "k8s-app=kube-dns"
    }
}

/// The fix for a DNS workload with fewer ready pods than wanted.
pub(super) fn not_ready(namespace: &str, workload: &Workload) -> String {
    let name = object(&workload.name);
    let short = workload.kind.short();
    let label = pod_label(namespace);
    format!(
        "Find out why the DNS pods are not ready: `kubectl -n {namespace} get pods -l {label}`, then `kubectl -n {namespace} describe {short}/{name}` and `kubectl -n {namespace} logs {short}/{name}`. Nothing in the cluster resolves names until they are."
    )
}

/// The fix for a cluster with no DNS workload and no DNS Service.
pub(super) fn none_found() -> String {
    "No cluster DNS was found. Check that it is installed: `kubectl -n kube-system get deployments,daemonsets,services`, and on OpenShift `oc -n openshift-dns get daemonsets,services`. Install CoreDNS with your distribution's DNS add-on (`kubeadm init phase addon coredns` on a kubeadm cluster).".to_owned()
}

/// The line for a DNS workload that is there, with no Service to reach it.
pub(super) fn no_service(namespace: &str, service: &str) -> String {
    format!(
        "Pods get their DNS server from the Service `{service}`. Check it: `kubectl -n {namespace} get service {service}`. A cluster without it needs its DNS add-on repaired."
    )
}

/// The fix for a Service with no ClusterIP.
pub(super) fn headless(namespace: &str, service: &str) -> String {
    format!(
        "Kubelet hands pods the ClusterIP of Service `{service}`, and it has none. Check it: `kubectl -n {namespace} get service {service} -o yaml`. The DNS Service must not be headless (`clusterIP: None`)."
    )
}

/// The fix for a crash loop with a root forward to `/etc/resolv.conf` (03, "Fix").
pub(super) fn forward_loop(workload: &Workload) -> String {
    let name = object(&workload.name);
    let short = workload.kind.short();
    format!(
        "CoreDNS forwards to `/etc/resolv.conf`, which on these nodes may be the systemd-resolved stub, so it forwards to itself. Edit the `coredns` ConfigMap to `forward . {{upstream}}`, or point kubelet `--resolv-conf` at `/run/systemd/resolve/resolv.conf`: `kubectl -n kube-system edit configmap coredns`. Confirm with the log line `plugin/loop: Loop ... detected` in `kubectl -n kube-system logs {short}/{name}`. If rdy runs on a node, `net.dns` shows that node's file."
    )
}

/// The line for a crash loop whose cause is not the loop.
pub(super) fn crash_logs(workload: &Workload) -> String {
    let name = object(&workload.name);
    let short = workload.kind.short();
    format!("Read why it stops: `kubectl -n {KUBE_SYSTEM} logs {short}/{name} --previous`.")
}

/// The fix for a cluster domain that is not the one the spec wants.
pub(super) fn domain(have: &str, want: &str) -> String {
    format!(
        "The cluster domain is `{have}` and the product expects `{want}`. Set the product's cluster domain to `{have}` (ask the vendor for the chart value), or change the `kubernetes` line of the `coredns` ConfigMap and kubelet `--cluster-domain` together: `kubectl -n kube-system edit configmap coredns`."
    )
}

/// The line for a Corefile that was not read.
pub(super) fn read_corefile_by_hand() -> &'static str {
    "Read the Corefile by hand: `kubectl -n kube-system get configmap coredns -o yaml`."
}

/// The line for a pod list or a workload that could not be judged.
pub(super) fn look_by_hand(namespace: &str) -> String {
    let label = pod_label(namespace);
    format!("Look at the DNS pods by hand: `kubectl -n {namespace} get pods -l {label}`.")
}

/// The fix for permissions the identity lacked: what to ask for, and the commands that check each.
pub(super) fn grants(commands: &[String], wanted: &[String], openshift: bool) -> String {
    let file = if openshift {
        "examples/rbac/rdy-readonly-openshift-dns.yaml"
    } else {
        "examples/rbac/rdy-readonly.yaml"
    };
    format!(
        "Ask the cluster admin to grant this identity: {}. Check each with {}. The role in {file} has them.",
        wanted.join(", "),
        commands.join(", ")
    )
}
