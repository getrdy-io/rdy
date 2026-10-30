#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.version` under tests/fixtures/checks/k8s.version/.

Usage: python3 -I scripts/gen-k8s-version-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-version-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names, zero GUIDs and zero hashes.
No byte came from a real cluster. The manifests say `origin = "generated"` because this script builds
them (tests/fixtures/README.md). `--check` writes nothing and fails when a committed file differs from
what the script would write, so the files and the script cannot drift.
"""

import json
import os
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.version")
DIFFERENT = []


def write(case, name, value, text=False):
    path = os.path.join(BASE, case, name)
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
name = "k8s-version-{case}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.version"]

[caps]
root = false
network = true
kube = true
''',
        text=True,
    )


def version(case, git, major="1", minor=None):
    parts = git.lstrip("v").split(".")
    minor = minor if minor is not None else parts[1].split("-")[0].split("+")[0]
    write(
        case,
        "api/version.json",
        {
            "request": {"method": "GET", "path": "/version"},
            "status": 200,
            "body": {
                "major": major,
                "minor": minor,
                "gitVersion": git,
                "gitCommit": "0000000000000000000000000000000000000000",
                "gitTreeState": "clean",
                "buildDate": "2026-01-01T00:00:00Z",
                "goVersion": "go1.21.9",
                "compiler": "gc",
                "platform": "linux/amd64",
            },
        },
    )


def group(name, versions):
    return {
        "name": name,
        "versions": [{"groupVersion": f"{name}/{v}", "version": v} for v in versions],
        "preferredVersion": {"groupVersion": f"{name}/{versions[0]}", "version": versions[0]},
    }


def refusal(code, reason, message, details):
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "details": details,
        "code": code,
    }


def apis(case, groups, status=200):
    if status == 403:
        body = refusal(
            403,
            "Forbidden",
            'forbidden: User "acme-reader" cannot get path "/apis"',
            {},
        )
    else:
        body = {
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": [group(n, v) for n, v in groups],
        }
    write(
        case,
        "api/discovery-apis.json",
        {"request": {"method": "GET", "path": "/apis"}, "status": status, "body": body},
    )


STANDARD = [
    ("apps", ["v1"]),
    ("autoscaling", ["v2", "v1"]),
    ("batch", ["v1"]),
    ("networking.k8s.io", ["v1"]),
    ("storage.k8s.io", ["v1"]),
]


def resources(case, file, path, group_version, kinds):
    write(
        case,
        f"api/{file}.json",
        {
            "request": {"method": "GET", "path": path},
            "status": 200,
            "body": {
                "kind": "APIResourceList",
                "apiVersion": "v1",
                "groupVersion": group_version,
                "resources": [
                    {
                        "name": name,
                        "singularName": "",
                        "namespaced": True,
                        "kind": kind,
                        "verbs": ["get", "list"],
                    }
                    for name, kind in kinds
                ],
            },
        },
    )


def node(name, kubelet, provider=None, labels=None):
    obj = {
        "metadata": {"name": name, "labels": {"kubernetes.io/os": "linux", **(labels or {})}},
        "spec": {},
        "status": {
            "nodeInfo": {
                "machineID": "",
                "systemUUID": "",
                "bootID": "",
                "kernelVersion": "5.14.0",
                "osImage": "Acme Linux",
                "containerRuntimeVersion": "containerd",
                "kubeletVersion": kubelet,
                "kubeProxyVersion": kubelet,
                "operatingSystem": "linux",
                "architecture": "amd64",
            }
        },
    }
    if provider:
        obj["spec"]["providerID"] = provider
    return obj


def nodes(case, items, cont=None, status=200):
    if status != 200:
        body = {
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": 'nodes is forbidden: User "acme-reader" cannot list resource "nodes" in API group "" at the cluster scope',
            "reason": "Forbidden",
            "details": {"kind": "nodes"},
            "code": 403,
        }
    else:
        meta = {"resourceVersion": "1000"}
        if cont:
            meta["continue"] = cont
        body = {"apiVersion": "v1", "kind": "NodeList", "metadata": meta, "items": items}
    write(
        case,
        "api/nodes.json",
        {"request": {"method": "GET", "path": "/api/v1/nodes", "query": "limit=500"}, "status": status, "body": body},
    )


AWS = "aws:///us-east-1a/i-0123456789abcdef"
EKS_LABEL = {"eks.amazonaws.com/nodegroup": "acme-ng"}
GKE_LABEL = {"cloud.google.com/gke-nodepool": "acme-pool"}
AKS_LABEL = {"kubernetes.azure.com/cluster": "MC_acme-rg_acme_eastus"}
AZURE = "azure:///subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/acme-rg/providers/Microsoft.Compute/virtualMachineScaleSets/acme-pool/virtualMachines/"

# eks: a pass with every API of the spec served, one kubelet a minor behind.
case = "eks"
manifest(case, "EKS 1.29 with the APIs a product needs served and one kubelet a minor behind")
version(case, "v1.29.4-eks-abc123")
apis(case, STANDARD)
resources(case, "discovery-api-v1", "/api/v1", "v1", [("pods", "Pod"), ("pods/status", "Pod"), ("services", "Service")])
resources(case, "discovery-autoscaling-v2", "/apis/autoscaling/v2", "autoscaling/v2", [("horizontalpodautoscalers", "HorizontalPodAutoscaler")])
resources(case, "discovery-batch-v1", "/apis/batch/v1", "batch/v1", [("jobs", "Job"), ("cronjobs", "CronJob")])
resources(case, "discovery-networking-v1", "/apis/networking.k8s.io/v1", "networking.k8s.io/v1", [("ingresses", "Ingress"), ("ingressclasses", "IngressClass")])
nodes(case, [
    node("acme-node-1", "v1.29.4-eks-abc123", AWS + "a", EKS_LABEL),
    node("acme-node-2", "v1.28.9-eks-def456", AWS + "b", EKS_LABEL),
])

case = "gke"
manifest(case, "GKE 1.26 with nodes that carry the node pool label")
version(case, "v1.26.9-gke.1000")
apis(case, STANDARD)
nodes(case, [node("acme-gke-1", "v1.26.9-gke.1000", "gce://acme-project/us-central1-a/acme-gke-1", GKE_LABEL)])

case = "aks"
manifest(case, "AKS 1.29: the version has no suffix and the nodes carry the AKS cluster label")
version(case, "v1.29.4")
apis(case, STANDARD)
nodes(case, [node("aks-pool-1", "v1.29.4", AZURE + "0", AKS_LABEL)])

case = "openshift"
manifest(case, "OpenShift 4.14.9 on Kubernetes 1.27, with the ClusterVersion readable")
version(case, "v1.27.8+3f8e0c1")
apis(case, STANDARD + [("config.openshift.io", ["v1"])])
write(case, "api/clusterversion.json", {
    "request": {"method": "GET", "path": "/apis/config.openshift.io/v1/clusterversions/version"},
    "status": 200,
    "body": {
        "apiVersion": "config.openshift.io/v1",
        "kind": "ClusterVersion",
        "metadata": {"name": "version"},
        "status": {
            "desired": {"version": "4.14.9", "image": "registry.acme.example/ocp-release@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
            "history": [{"state": "Completed", "version": "4.14.9", "startedTime": "2026-01-01T00:00:00Z", "completionTime": "2026-01-01T01:00:00Z"}],
        },
    },
})
nodes(case, [node("acme-ocp-1", "v1.27.8+3f8e0c1", AWS + "a")])

case = "openshift-forbidden"
manifest(case, "OpenShift where the identity may not read the ClusterVersion")
version(case, "v1.27.8+3f8e0c1")
apis(case, STANDARD + [("config.openshift.io", ["v1"])])
write(case, "api/clusterversion.json", {
    "request": {"method": "GET", "path": "/apis/config.openshift.io/v1/clusterversions/version"},
    "status": 403,
    "body": {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": 'clusterversions.config.openshift.io "version" is forbidden: User "acme-reader" cannot get resource "clusterversions" in API group "config.openshift.io" at the cluster scope',
        "reason": "Forbidden",
        "details": {"name": "version", "group": "config.openshift.io", "kind": "clusterversions"},
        "code": 403,
    },
})
nodes(case, [node("acme-ocp-1", "v1.27.8+3f8e0c1", AWS + "a")])

case = "k3s"
manifest(case, "k3s 1.29 with no provider id")
version(case, "v1.29.4+k3s1")
apis(case, STANDARD)
nodes(case, [node("acme-k3s-1", "v1.29.4+k3s1")])

case = "rke2"
manifest(case, "RKE2 1.29")
version(case, "v1.29.4+rke2r1")
apis(case, STANDARD)
nodes(case, [node("acme-rke2-1", "v1.29.4+rke2r1")])

case = "kind"
manifest(case, "kind 1.29: the provider id scheme is kind")
version(case, "v1.29.4")
apis(case, STANDARD)
nodes(case, [node("acme-control-plane", "v1.29.4", "kind://docker/acme/acme-control-plane")])

case = "vanilla"
manifest(case, "A self-managed 1.29 cluster on AWS machines: no suffix, aws provider ids, no managed labels")
version(case, "v1.29.4")
apis(case, STANDARD)
nodes(case, [node("acme-vm-1", "v1.29.4", AWS + "a"), node("acme-vm-2", "v1.29.4", AWS + "b")])

case = "missing-apis"
manifest(case, "1.29 where autoscaling/v2beta2 is gone, batch/v1 has no CronJob and autoscaling/v2 is not listed")
version(case, "v1.29.4")
apis(case, [("apps", ["v1"]), ("autoscaling", ["v1"]), ("batch", ["v1"])])
resources(case, "discovery-api-v1", "/api/v1", "v1", [("pods", "Pod")])
resources(case, "discovery-batch-v1", "/apis/batch/v1", "batch/v1", [("jobs", "Job")])
nodes(case, [node("acme-vm-1", "v1.29.4")])

case = "nodes-forbidden"
manifest(case, "EKS 1.29 where the identity may not list nodes")
version(case, "v1.29.4-eks-abc123")
apis(case, STANDARD)
nodes(case, [], status=403)

case = "skew"
manifest(case, "1.29 with a kubelet five minors behind, one newer, one a minor behind and a virtual kubelet")
version(case, "v1.29.4")
apis(case, STANDARD)
nodes(case, [
    node("acme-old-1", "v1.24.3"),
    node("acme-new-1", "v1.30.0"),
    node("acme-ok-1", "v1.28.9"),
    node("acme-edge-1", "v1.26.2"),
    {**node("acme-virtual-1", "v1.14.0-vk-azure-aci-v1.4.1"), "metadata": {"name": "acme-virtual-1", "labels": {"type": "virtual-kubelet"}}},
])

case = "paged"
manifest(case, "1.29 where the node list has a second page that the check does not read")
version(case, "v1.29.4")
apis(case, STANDARD)
nodes(case, [node("acme-vm-1", "v1.29.4")], cont="tok-page-2")

case = "unreadable-version"
manifest(case, "A server whose version text is not a Kubernetes version")
version(case, "acme-build-7", minor="x")
apis(case, STANDARD)
nodes(case, [node("acme-vm-1", "v1.29.4")])


# The group list is not readable. The ClusterVersion decides whether this is OpenShift.
CV_PATH = "/apis/config.openshift.io/v1/clusterversions/version"


def cluster_version(case, history, desired, status=200):
    if status == 200:
        body = {
            "apiVersion": "config.openshift.io/v1",
            "kind": "ClusterVersion",
            "metadata": {"name": "version"},
            "status": {
                "desired": {"version": desired},
                "history": history,
            },
        }
    elif status == 403:
        body = refusal(
            403,
            "Forbidden",
            'clusterversions.config.openshift.io "version" is forbidden: User "acme-reader" cannot get resource "clusterversions" in API group "config.openshift.io" at the cluster scope',
            {"name": "version", "group": "config.openshift.io", "kind": "clusterversions"},
        )
    else:
        body = refusal(
            404,
            "NotFound",
            "the server could not find the requested resource",
            {},
        )
    write(
        case,
        "api/clusterversion.json",
        {"request": {"method": "GET", "path": CV_PATH}, "status": status, "body": body},
    )


def done(version):
    return {
        "state": "Completed",
        "version": version,
        "startedTime": "2026-01-01T00:00:00Z",
        "completionTime": "2026-01-01T01:00:00Z",
    }


case = "openshift-updating"
manifest(case, "OpenShift on 4.14.9 with an update to 4.15.2 running")
version(case, "v1.28.5+3f8e0c1")
apis(case, STANDARD + [("config.openshift.io", ["v1"])])
cluster_version(
    case,
    [{"state": "Partial", "version": "4.15.2", "startedTime": "2026-01-02T00:00:00Z"}, done("4.14.9")],
    "4.15.2",
)
nodes(case, [node("acme-ocp-1", "v1.27.8+3f8e0c1", AWS + "a")])

case = "apis-unreadable-openshift"
manifest(case, "OpenShift 4.14.9 where the identity may not read /apis, so the ClusterVersion says what it is")
version(case, "v1.27.8+3f8e0c1")
apis(case, [], status=403)
cluster_version(case, [done("4.14.9")], "4.14.9")
nodes(case, [node("acme-ocp-1", "v1.27.8+3f8e0c1", AWS + "a")])

case = "apis-unreadable-forbidden"
manifest(case, "1.27 where the identity may read neither /apis nor the ClusterVersion")
version(case, "v1.27.8+3f8e0c1")
apis(case, [], status=403)
cluster_version(case, [], "", status=403)
nodes(case, [node("acme-ocp-1", "v1.27.8+3f8e0c1", AWS + "a")])

case = "apis-unreadable-vanilla"
manifest(case, "A self-managed 1.27 cluster where the identity may not read /apis and there is no ClusterVersion")
version(case, "v1.27.4")
apis(case, [], status=403)
cluster_version(case, [], "", status=404)
nodes(case, [node("acme-vm-1", "v1.27.4", AWS + "a")])

if CHECK:
    if DIFFERENT:
        sys.stderr.write("fixtures differ from the script:\n" + "\n".join(DIFFERENT) + "\n")
        sys.exit(1)
