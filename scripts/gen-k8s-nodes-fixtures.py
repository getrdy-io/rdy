#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.nodes` under tests/fixtures/checks/k8s.nodes/.

Usage: python3 -I scripts/gen-k8s-nodes-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-nodes-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster. The manifests say `origin = "generated"` because this script builds them
(tests/fixtures/README.md). `--check` writes nothing and fails when a committed file differs from what the
script would write, or when the fixture folder holds a file the script did not write (the mock serves every
`api/*.json` of a case, so a stale file would change a test without a diff in the script).
"""

import json
import os
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.nodes")
DIFFERENT = []
WRITTEN = set()

NODES_PATH = "/api/v1/nodes"
DEPLOYMENTS_PATH = "/apis/apps/v1/namespaces/kube-system/deployments"
SCALER_QUERY = "limit=500"


def write(case, name, value, text=False):
    path = os.path.join(BASE, case, name)
    WRITTEN.add(os.path.normpath(path))
    data = value if text else json.dumps(value, indent=2) + "\n"
    if CHECK:
        try:
            with open(path, newline="") as f:
                same = f.read() == data
        except FileNotFoundError:
            same = False
        if not same:
            DIFFERENT.append(path)
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="\n") as f:
        f.write(data)


def manifest(case, summary):
    write(
        case,
        "fixture.toml",
        f'''schema = 1
name = "k8s-nodes-{case}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.nodes"]

[caps]
root = false
network = true
kube = true
''',
        text=True,
    )


def status(code, reason, message):
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "details": {},
        "code": code,
    }


def put(case, file, path, body, code=200, query=""):
    request = {"method": "GET", "path": path}
    if query:
        request["query"] = query
    write(case, f"api/{file}.json", {"request": request, "status": code, "body": body})


def listing(kind, api_version, items, cont=None):
    meta = {"resourceVersion": "1000"}
    if cont:
        meta["continue"] = cont
    return {"apiVersion": api_version, "kind": kind, "metadata": meta, "items": items}


def conditions(ready="True", pressure=()):
    out = [
        {"type": "MemoryPressure", "status": "True" if "MemoryPressure" in pressure else "False"},
        {"type": "DiskPressure", "status": "True" if "DiskPressure" in pressure else "False"},
        {"type": "PIDPressure", "status": "True" if "PIDPressure" in pressure else "False"},
        {"type": "Ready", "status": ready},
    ]
    return out


def node(name, cpu="7910m", memory="29567452Ki", ephemeral="95551679124", pods="58",
         cap_cpu="8", cap_memory="32Gi", ready="True", cordoned=False, os_="linux", arch="amd64",
         zone=None, instance=None, labels=None, taints=None, provider=None, pressure=(),
         allocatable=True, kubelet="v1.29.4-eks-abc1234"):
    meta_labels = {"kubernetes.io/os": os_, "kubernetes.io/arch": arch, "kubernetes.io/hostname": name}
    if zone:
        meta_labels["topology.kubernetes.io/zone"] = zone
    if instance:
        meta_labels["node.kubernetes.io/instance-type"] = instance
    if labels:
        meta_labels.update(labels)
    spec = {}
    if cordoned:
        spec["unschedulable"] = True
    if taints:
        spec["taints"] = taints
    if provider:
        spec["providerID"] = provider
    status_ = {
        "capacity": {"cpu": cap_cpu, "memory": cap_memory, "ephemeral-storage": "104857600Ki", "pods": pods},
        "conditions": conditions(ready, pressure),
        "nodeInfo": {
            "machineID": "", "systemUUID": "", "bootID": "",
            "kernelVersion": "5.10.0", "osImage": "Acme Linux",
            "containerRuntimeVersion": "containerd://acme-1",
            "kubeletVersion": kubelet, "kubeProxyVersion": kubelet,
            "operatingSystem": os_, "architecture": arch,
        },
    }
    if allocatable:
        status_["allocatable"] = {"cpu": cpu, "memory": memory, "ephemeral-storage": ephemeral, "pods": pods}
    return {
        "metadata": {"name": name, "labels": meta_labels},
        "spec": spec,
        "status": status_,
    }


def nodes(case, items, cont=None, code=200, fails=True):
    body = listing("NodeList", "v1", items, cont) if code == 200 else status(
        403, "Forbidden",
        'nodes is forbidden: User "acme-reader" cannot list resource "nodes" in API group "" at the cluster scope')
    put(case, "nodes", NODES_PATH, body, code, "limit=500")
    if cont and fails:
        put(case, "nodes-page-2", NODES_PATH,
            status(503, "ServiceUnavailable", "the server is overloaded, try again"), 503,
            f"continue={cont}&limit=500")


def groups(case, names=(), code=200):
    items = [
        {
            "name": n,
            "versions": [{"groupVersion": f"{n}/v1", "version": "v1"}],
            "preferredVersion": {"groupVersion": f"{n}/v1", "version": "v1"},
        }
        for n in ("storage.k8s.io", *names)
    ]
    body = {"kind": "APIGroupList", "apiVersion": "v1", "groups": items} if code == 200 else status(
        403, "Forbidden", 'forbidden: User "acme-reader" cannot get path "/apis"')
    put(case, "discovery-apis", "/apis", body, code)


def scaler_deployments(case, found=False, code=200, items=None):
    if items is None:
        items = [{"metadata": {"name": "cluster-autoscaler", "namespace": "kube-system"},
                  "status": {"readyReplicas": 1}}] if found else []
        if not found:
            items = [{"metadata": {"name": "coredns", "namespace": "kube-system", "labels": {"k8s-app": "kube-dns"}}}]
    body = listing("DeploymentList", "apps/v1", items) if code == 200 else status(
        403, "Forbidden",
        'deployments.apps is forbidden: User "acme-reader" cannot list resource "deployments" in API group "apps" in the namespace "kube-system"')
    put(case, "deployments", DEPLOYMENTS_PATH, body, code, SCALER_QUERY)


def no_scaler(case):
    """The answers of the two autoscaler reads when there is no autoscaler: a count shortfall asks both."""
    groups(case)
    scaler_deployments(case)


PODS_PATH = "/api/v1/pods"
PHASE = "status.phase!=Succeeded,status.phase!=Failed"


def container(name, cpu=None, memory=None, ephemeral=None, sidecar=False, env=None):
    requests = {}
    if cpu:
        requests["cpu"] = cpu
    if memory:
        requests["memory"] = memory
    if ephemeral:
        requests["ephemeral-storage"] = ephemeral
    out = {"name": name, "image": "registry.acme.example/acme/app:1", "resources": {"requests": requests}}
    if sidecar:
        out["restartPolicy"] = "Always"
    if env:
        out["env"] = env
    return out


def pod(name, node_name, containers, init=None, phase="Running", overhead=None, pod_level=None):
    spec = {"containers": containers}
    if node_name:
        spec["nodeName"] = node_name
    if init:
        spec["initContainers"] = init
    if overhead:
        spec["overhead"] = overhead
    if pod_level:
        spec["resources"] = {"requests": pod_level}
    return {"metadata": {"name": name, "namespace": "app"}, "spec": spec, "status": {"phase": phase}}


def pods(case, items, cont=None, code=200, fails=True, node_name=None):
    """The cluster-wide Pod list, or with `node_name` the list of one node (the fallback of a cut list)."""
    selector = f"spec.nodeName={node_name},{PHASE}" if node_name else PHASE
    file = f"pods-{node_name}" if node_name else "pods"
    body = listing("PodList", "v1", items, cont) if code == 200 else status(
        403, "Forbidden",
        'pods is forbidden: User "acme-reader" cannot list resource "pods" in API group "" at the cluster scope')
    put(case, file, PODS_PATH, body, code, f"limit=500&fieldSelector={selector}")
    if cont and fails:
        put(case, file + "-page-2", PODS_PATH,
            status(503, "ServiceUnavailable", "the server is overloaded, try again"), 503,
            f"continue={cont}&limit=500&fieldSelector={selector}")


def loaded(prefix, per_node, cpu="500m", memory="512Mi", count=1):
    """`count` pods on each of the first `per_node` nodes of `healthy()`."""
    return [pod(f"{prefix}-{i + 1}-{j + 1}", f"acme-node-{i + 1}", [container("main", cpu, memory)])
            for i in range(per_node) for j in range(count)]


SUMMARIES = {}


def case(name, summary):
    manifest(name, summary)
    SUMMARIES[name] = summary


ZONES = ["us-east-1a", "us-east-1b", "us-east-1c"]
GPU = {"key": "nvidia.com/gpu", "value": "present", "effect": "NoSchedule"}
CONTROL = {"key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"}
UNREACHABLE = [
    {"key": "node.kubernetes.io/unreachable", "effect": "NoSchedule"},
    {"key": "node.kubernetes.io/unreachable", "effect": "NoExecute"},
]


def healthy(n=3, **kwargs):
    return [node(f"acme-node-{i + 1}", zone=ZONES[i % 3], instance="m6i.2xlarge", **kwargs) for i in range(n)]


# ---- sizes and quantity forms ---------------------------------------------------------------------------------
case("healthy", "Three healthy 8 vCPU nodes in three zones, allocatable written as 7910m and Ki values")
nodes("healthy", healthy())

case("quantities", "Allocatable in the other forms of a quantity: plain cores, M and G, an exponent and plain bytes")
nodes("quantities", [
    node("acme-node-1", cpu="8", memory="32G", ephemeral="1e11", pods="110", zone="us-east-1a"),
    node("acme-node-2", cpu="7500m", memory="30064771072", ephemeral="100Gi", pods="1.1e2", zone="us-east-1b"),
    node("acme-node-3", cpu="7.9", memory="29Gi", ephemeral="100000000k", pods="110", zone="us-east-1c"),
])

case("small", "Three 4 vCPU nodes with 3920m and 14Gi allocatable")
nodes("small", [
    node(f"acme-node-{i + 1}", cpu="3920m", memory="14680064Ki", cap_cpu="4", cap_memory="16Gi", zone=ZONES[i],
         instance="m6i.xlarge")
    for i in range(3)
])

case("one-small", "Two big nodes and one small one")
nodes("one-small", [
    node("acme-node-1", zone="us-east-1a"),
    node("acme-node-2", zone="us-east-1b"),
    node("acme-node-3", cpu="1930m", memory="6Gi", cap_cpu="2", cap_memory="8Gi", zone="us-east-1c"),
])

case("pods-limit", "Three EKS t3.medium nodes that allow 17 pods each")
nodes("pods-limit", [
    node(f"acme-node-{i + 1}", cpu="1930m", memory="3500Mi", cap_cpu="2", cap_memory="4Gi", pods="17",
         zone=ZONES[i], instance="t3.medium", provider=f"aws:///us-east-1a/i-0abc{i}")
    for i in range(3)
])

case("pods-limit-other", "Three self-managed nodes outside AWS that allow 30 pods each")
nodes("pods-limit-other", [
    node(f"acme-node-{i + 1}", pods="30", zone=ZONES[i], kubelet="v1.29.4",
         provider=f"gce://acme-project/us-east1-b/acme-node-{i + 1}")
    for i in range(3)
])

case("no-allocatable", "A node that reports no allocatable at all")
nodes("no-allocatable", [node("acme-node-1", allocatable=False, zone="us-east-1a")])

# ---- which nodes count ------------------------------------------------------------------------------------------
case("excluded", "Three healthy nodes, and one NotReady, one cordoned, one Windows, one Fargate, one virtual, a GPU pool and a control plane")
nodes("excluded", healthy() + [
    node("acme-notready", ready="Unknown", zone="us-east-1a", taints=UNREACHABLE),
    node("acme-cordoned", cordoned=True, zone="us-east-1a",
         taints=[{"key": "node.kubernetes.io/unschedulable", "effect": "NoSchedule"}]),
    node("acme-windows", os_="windows", zone="us-east-1a"),
    node("fargate-ip-10-0-0-1", labels={"eks.amazonaws.com/compute-type": "fargate"}, zone="us-east-1a",
         taints=[{"key": "eks.amazonaws.com/compute-type", "value": "fargate", "effect": "NoSchedule"}]),
    node("acme-virtual", labels={"type": "virtual-kubelet"}, zone="us-east-1a",
         taints=[{"key": "virtual-kubelet.io/provider", "value": "acme", "effect": "NoSchedule"}]),
    node("acme-gpu-1", zone="us-east-1b", taints=[GPU], instance="g5.2xlarge"),
    node("acme-control-1", zone="us-east-1c", taints=[CONTROL]),
])
no_scaler("excluded")

case("prefer-no-schedule", "A node with a PreferNoSchedule taint, which does not keep pods off")
nodes("prefer-no-schedule", [
    node("acme-node-1", zone="us-east-1a"),
    node("acme-node-2", zone="us-east-1b", taints=[{"key": "acme.example/spot", "value": "true", "effect": "PreferNoSchedule"}]),
])

case("arch", "Two amd64 and two arm64 nodes")
nodes("arch", [
    node("acme-amd-1", zone="us-east-1a"),
    node("acme-amd-2", zone="us-east-1b"),
    node("acme-arm-1", arch="arm64", zone="us-east-1a"),
    node("acme-arm-2", arch="arm64", zone="us-east-1b"),
    node("acme-power-1", arch="ppc64le", zone="us-east-1c"),
])
no_scaler("arch")

case("selector", "Two nodes in the product pool and one in another pool")
nodes("selector", [
    node("acme-node-1", zone="us-east-1a", labels={"acme.example/pool": "product"}),
    node("acme-node-2", zone="us-east-1b", labels={"acme.example/pool": "product"}),
    node("acme-node-3", zone="us-east-1c", labels={"acme.example/pool": "other"}),
])
no_scaler("selector")

# ---- zones -----------------------------------------------------------------------------------------------------------
case("single-zone", "Three healthy nodes in one zone")
nodes("single-zone", [node(f"acme-node-{i + 1}", zone="us-east-1a") for i in range(3)])

case("no-zones", "Three healthy nodes with no zone label")
nodes("no-zones", [node(f"acme-node-{i + 1}") for i in range(3)])

# ---- conditions -------------------------------------------------------------------------------------------------------
case("pressure", "Two healthy nodes and one with memory and disk pressure")
nodes("pressure", [
    node("acme-node-1", zone="us-east-1a"),
    node("acme-node-2", zone="us-east-1b"),
    node("acme-node-3", zone="us-east-1c", pressure=("MemoryPressure", "DiskPressure"),
         taints=[{"key": "node.kubernetes.io/memory-pressure", "effect": "NoSchedule"},
                 {"key": "node.kubernetes.io/disk-pressure", "effect": "NoSchedule"}]),
])

# ---- autoscalers -------------------------------------------------------------------------------------------------------
case("scaler-karpenter", "One node, and the cluster serves the Karpenter API group")
nodes("scaler-karpenter", [node("acme-node-1", zone="us-east-1a")])
groups("scaler-karpenter", ["karpenter.sh"])

case("scaler-deployment", "One node, no Karpenter, and a cluster-autoscaler deployment in kube-system")
nodes("scaler-deployment", [node("acme-node-1", zone="us-east-1a")])
groups("scaler-deployment")
scaler_deployments("scaler-deployment", found=True)

case("scaler-none", "One node, no Karpenter and no cluster-autoscaler")
nodes("scaler-none", [node("acme-node-1", zone="us-east-1a")])
groups("scaler-none")
scaler_deployments("scaler-none")

case("scaler-unreadable", "One node, and the identity may not read the group list or the deployments")
nodes("scaler-unreadable", [node("acme-node-1", zone="us-east-1a")])
groups("scaler-unreadable", code=403)
scaler_deployments("scaler-unreadable", code=403)

case("scaler-auto-mode", "One node that EKS Auto Mode manages")
nodes("scaler-auto-mode", [node("acme-node-1", zone="us-east-1a", labels={"eks.amazonaws.com/compute-type": "auto"})])

case("scaler-karpenter-node", "One node that Karpenter launched")
nodes("scaler-karpenter-node", [node("acme-node-1", zone="us-east-1a", labels={"karpenter.sh/nodepool": "default"})])

case("scaler-autopilot", "One node whose name starts with gk3-")
nodes("scaler-autopilot", [node("gk3-acme-pool-1-abc", zone="us-east-1a")])

case("scaler-small", "One node that is too small, and the cluster serves the Karpenter API group")
nodes("scaler-small", [node("acme-node-1", cpu="1930m", cap_cpu="2", zone="us-east-1a")])
groups("scaler-small", ["karpenter.sh"])

case("scaler-nap", "One node in a GKE node auto-provisioning pool")
nodes("scaler-nap", [node("acme-node-1", zone="us-east-1a", labels={"cloud.google.com/gke-nodepool": "nap-e2-standard-4-abc"})])

case("scaler-openshift", "One node, and the cluster serves the OpenShift machine autoscaler group")
nodes("scaler-openshift", [node("acme-node-1", zone="us-east-1a")])
groups("scaler-openshift", ["autoscaling.openshift.io"])

case("scaler-helm", "One node, and a Helm-named cluster autoscaler Deployment found by its label")
nodes("scaler-helm", [node("acme-node-1", zone="us-east-1a")])
groups("scaler-helm")
scaler_deployments("scaler-helm", items=[
    {"metadata": {"name": "acme-autoscaler", "namespace": "kube-system",
                  "labels": {"app.kubernetes.io/name": "aws-cluster-autoscaler"}},
     "status": {"readyReplicas": 2}},
])

case("scaler-stopped", "One node, and a cluster autoscaler Deployment with no ready replica, and a lookalike name")
nodes("scaler-stopped", [node("acme-node-1", zone="us-east-1a")])
groups("scaler-stopped")
scaler_deployments("scaler-stopped", items=[
    {"metadata": {"name": "cluster-autoscaler", "namespace": "kube-system"}, "status": {"readyReplicas": 0}},
    {"metadata": {"name": "my-cluster-autoscaler-proxy", "namespace": "kube-system"}, "status": {"readyReplicas": 1}},
])

case("scaler-gke-hosted", "One GKE node and no autoscaler object to read")
nodes("scaler-gke-hosted", [node("acme-node-1", zone="us-east-1a", kubelet="v1.29.4-gke.1000", labels={"cloud.google.com/gke-nodepool": "default-pool"})])
no_scaler("scaler-gke-hosted")

case("zero-auto-mode", "Every node is cordoned, and one is managed by EKS Auto Mode")
nodes("zero-auto-mode", [node("acme-node-1", cordoned=True, zone="us-east-1a", labels={"eks.amazonaws.com/compute-type": "auto"})])

case("zero-plain", "Every node is cordoned and there is no autoscaler")
nodes("zero-plain", [node("acme-node-1", cordoned=True, zone="us-east-1a")])
no_scaler("zero-plain")

case("aks-no-zone", "Three AKS nodes whose zone label is 0, which means no zone")
nodes("aks-no-zone", [node(f"acme-node-{i + 1}", zone="0") for i in range(3)])

# ---- lists ---------------------------------------------------------------------------------------------------------------
case("forbidden", "The identity may not list nodes")
nodes("forbidden", [], code=403)

case("empty", "The cluster has no node")
nodes("empty", [])
no_scaler("empty")

case("paged", "Two healthy nodes on page one and one on page two")
nodes("paged", [node("acme-node-1", zone="us-east-1a"), node("acme-node-2", zone="us-east-1b")],
      cont="tok-more", fails=False)
put("paged", "nodes-page-2", NODES_PATH, listing("NodeList", "v1", [node("acme-node-3", zone="us-east-1c")]),
    200, "continue=tok-more&limit=500")

case("capped", "Two healthy nodes on page one and the server fails on page two")
nodes("capped", [node("acme-node-1", zone="us-east-1a"), node("acme-node-2", zone="us-east-1b")], cont="tok-more")
no_scaler("capped")

# ---- free capacity (M1-159) -----------------------------------------------------------------------------------------
case("free-ok", "Three healthy nodes with light requests, a finished pod and a pod with no node that do not count")
nodes("free-ok", healthy())
pods("free-ok", [
    pod("web-1", "acme-node-1", [container("main", "500m", "512Mi")]),
    pod("web-2", "acme-node-1", [container("main", "500m", "512Mi")]),
    pod("done-1", "acme-node-2", [container("main", "7", "20Gi")], phase="Succeeded"),
    pod("waiting-1", None, [container("main", "7", "20Gi")], phase="Pending"),
])

case("free-90pct", "Three healthy nodes whose pods request 90% of the CPU")
nodes("free-90pct", healthy())
pods("free-90pct", [pod(f"big-{i + 1}", f"acme-node-{i + 1}", [container("main", "7100m", "1Gi")]) for i in range(3)])

case("free-margin", "Three healthy nodes with 17 CPU left, which meets 16 and misses the 120% margin")
nodes("free-margin", healthy())
pods("free-margin", [pod("big-1", "acme-node-1", [container("main", "6730m", "1Gi")])])

case("free-effective", "One 4 CPU node with a pod that has a sidecar, an init container and overhead, and a pod that finished")
nodes("free-effective", [node("acme-node-1", cpu="4", memory="8Gi", ephemeral="100Gi", pods="110", cap_cpu="4",
                              cap_memory="8Gi", zone="us-east-1a")])
pods("free-effective", [
    pod("web-1", "acme-node-1", [container("main", "1", "200Mi")],
        init=[container("proxy", "1", "100Mi", sidecar=True), container("setup", "2", "500Mi")],
        overhead={"cpu": "250m", "memory": "50Mi"}),
    pod("done-1", "acme-node-1", [container("main", "3", "1Gi")], phase="Failed"),
])

case("free-forbidden", "Three healthy nodes and the identity may not list pods")
nodes("free-forbidden", healthy())
pods("free-forbidden", [], code=403)

case("free-capped", "The cluster-wide pod list is cut, and each counted node is listed on its own")
nodes("free-capped", healthy())
pods("free-capped", loaded("big", 3, cpu="7100m"), cont="tok-more")
for i in range(3):
    pods("free-capped", [pod(f"big-{i + 1}", f"acme-node-{i + 1}", [container("main", "7100m", "1Gi")])],
         node_name=f"acme-node-{i + 1}")

case("free-capped-node", "The cluster-wide pod list is cut, and so is the list of the second node")
nodes("free-capped-node", healthy())
pods("free-capped-node", loaded("big", 3, cpu="7100m"), cont="tok-more")
pods("free-capped-node", [pod("big-1", "acme-node-1", [container("main", "7100m", "1Gi")])],
     node_name="acme-node-1")
pods("free-capped-node", [pod("big-2", "acme-node-2", [container("main", "7100m", "1Gi")])],
     node_name="acme-node-2", cont="tok-more")

case("free-bad-request", "Light requests, and one pod whose CPU request is not a quantity")
nodes("free-bad-request", healthy())
pods("free-bad-request", [
    pod("web-1", "acme-node-1", [container("main", "500m", "512Mi")]),
    pod("odd-1", "acme-node-2", [container("main", "lots", "512Mi")]),
])

case("free-pod-level", "One 4 CPU node and a pod whose pod-level request (3 CPU) is above its containers' (500m)")
nodes("free-pod-level", [node("acme-node-1", cpu="4", memory="8Gi", ephemeral="100Gi", pods="110", cap_cpu="4",
                              cap_memory="8Gi", zone="us-east-1a")])
pods("free-pod-level", [
    pod("web-1", "acme-node-1", [container("main", "500m", "256Mi", ephemeral="1Gi")],
        overhead={"cpu": "250m"}, pod_level={"cpu": "3", "memory": "1Gi"}),
])

CANARY = "canary-env-value-0a1b2c3d4e5f"
case("free-canary", "A pod whose environment holds a credential-looking value that must never be held or shown")
nodes("free-canary", healthy())
pods("free-canary", [
    pod("web-1", "acme-node-1", [container("main", "500m", "512Mi", env=[
        {"name": "DB_PASSWORD", "value": CANARY},
        {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "acme-secret", "key": "token"}}},
    ])]),
])

case("free-many-nodes", "Twenty-six healthy nodes and a cut pod list: more nodes than are listed one by one")
nodes("free-many-nodes", [node(f"acme-node-{i + 1}", zone=ZONES[i % 3]) for i in range(26)])
pods("free-many-nodes", [pod("web-1", "acme-node-1", [container("main", "500m", "512Mi")])], cont="tok-more")

case("free-odd-name", "One node whose name is not a DNS name and a cut pod list")
nodes("free-odd-name", [node("Acme_Node_1", zone="us-east-1a")])
pods("free-odd-name", [pod("web-1", "Acme_Node_1", [container("main", "500m", "512Mi")])], cont="tok-more")

# ---- hostile text -----------------------------------------------------------------------------------------------------------
case("hostile", "Node names, labels and quantities that try to reach the terminal or a command")
nodes("hostile", [
    node("acme-node-1", zone="us-east-1a"),
    node("--all", cordoned=True, zone="us-east-1b"),
    node("evil\u001b[2Jname", ready="False", zone="us-east-1c", instance="\u202etxet"),
    node("acme-garbage", cpu="1e999999", memory="NaN", ephemeral="-5", pods="many", zone="us-east-1a"),
])
no_scaler("hostile")

if CHECK:
    for folder, _, names in os.walk(BASE):
        for found in names:
            path = os.path.normpath(os.path.join(folder, found))
            if path not in WRITTEN:
                DIFFERENT.append(path + " (the script does not write this file)")
    if DIFFERENT:
        sys.stderr.write("these fixtures differ from what the script writes:\n")
        for path in DIFFERENT:
            sys.stderr.write(f"  {path}\n")
        sys.stderr.write("Fix: delete any file the script does not write, run python3 -I scripts/gen-k8s-nodes-fixtures.py and commit the result.\n")
        sys.exit(1)
