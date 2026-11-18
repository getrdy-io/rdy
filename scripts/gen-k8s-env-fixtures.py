#!/usr/bin/env python3
"""Writes the synthetic `api/` trees of the fixture envs under tests/fixtures/envs/ (M1-185).

Usage: python3 -I scripts/gen-k8s-env-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-env-fixtures.py --check [<repo root>]

The env harness serves each tree as a scripted cluster (08, section 2). The trees follow the shape of the
check cases that the other `gen-k8s-*-fixtures.py` scripts write, with `acme` names and zero GUIDs and
hashes. No byte came from a real cluster.

- `all-pass`: a vanilla three-node cluster on 1.29.4, and an identity that may list nodes.
- `warnings-only` (base `all-pass`): adds two storage classes and neither is the default.
- `all-block` (base `all-pass`): a cluster on 1.24.9 (too old for the spec), an identity that may not
  create namespaces, and a default class on a CSI driver whose `CSINode` list is refused.

`--check` writes nothing and fails when a committed file differs from what the script would write, or when
an `api/` folder holds a file the script did not write (the mock serves every `api/*.json`, so a stale file
would change a run without a diff in the script).
"""

import json
import os
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/envs")
ENVS = ["all-pass", "warnings-only", "all-block"]
DIFFERENT = []
WRITTEN = set()

DEFAULT = "storageclass.kubernetes.io/is-default-class"
EBS = "ebs.csi.aws.com"
USER = "system:serviceaccount:acme-system:installer"


def write(env, name, value):
    path = os.path.join(BASE, env, "api", name)
    WRITTEN.add(os.path.normpath(path))
    data = json.dumps(value, indent=2) + "\n"
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


def listing(kind, api_version, items):
    return {"apiVersion": api_version, "kind": kind, "metadata": {"resourceVersion": "1000"}, "items": items}


def put(env, file, path, body, code=200, query="", method="GET"):
    request = {"method": method, "path": path}
    if query:
        request["query"] = query
    write(env, f"{file}.json", {"request": request, "status": code, "body": body})


def version(env, git):
    minor = git.lstrip("v").split(".")[1]
    put(env, "version", "/version", {
        "major": "1",
        "minor": minor,
        "gitVersion": git,
        "gitCommit": "0000000000000000000000000000000000000000",
        "gitTreeState": "clean",
        "buildDate": "2026-01-01T00:00:00Z",
        "goVersion": "go1.21.9",
        "compiler": "gc",
        "platform": "linux/amd64",
    })


def group(name, versions):
    return {
        "name": name,
        "versions": [{"groupVersion": f"{name}/{v}", "version": v} for v in versions],
        "preferredVersion": {"groupVersion": f"{name}/{versions[0]}", "version": versions[0]},
    }


def apis(env):
    groups = [
        ("apps", ["v1"]),
        ("autoscaling", ["v2", "v1"]),
        ("batch", ["v1"]),
        ("networking.k8s.io", ["v1"]),
        ("storage.k8s.io", ["v1"]),
    ]
    put(env, "discovery-apis", "/apis", {
        "kind": "APIGroupList",
        "apiVersion": "v1",
        "groups": [group(n, v) for n, v in groups],
    })


def node(name, kubelet):
    return {
        "metadata": {"name": name, "labels": {"kubernetes.io/os": "linux"}},
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


def nodes(env, kubelet):
    items = [node(f"acme-node-{n}", kubelet) for n in (1, 2, 3)]
    put(env, "nodes", "/api/v1/nodes", listing("NodeList", "v1", items), query="limit=500")


def review(spec, allowed, reason=""):
    return {"spec": spec, "status": {"allowed": allowed, "reason": reason}}


LIST_NODES = {"resourceAttributes": {"verb": "list", "resource": "nodes"}}
CREATE_NAMESPACES = {"resourceAttributes": {"verb": "create", "resource": "namespaces"}}


def reviews(env, access):
    write(env, "reviews.json", {"access": access})


def identity(env):
    # A 1.24 server has no SelfSubjectReview (GA in 1.28): the API answers 404 and the user is not verified.
    put(env, "self-subject-review", "/apis/authentication.k8s.io/v1/selfsubjectreviews", status(
        404, "NotFound",
        "the server could not find the requested resource",
    ), 404, method="POST")


def storage_class(name, provisioner, default):
    meta = {"name": name, "creationTimestamp": "2026-01-01T00:00:00Z"}
    if default:
        meta["annotations"] = {DEFAULT: "true"}
    return {
        "metadata": meta,
        "provisioner": provisioner,
        "volumeBindingMode": "WaitForFirstConsumer",
        "allowVolumeExpansion": True,
        "reclaimPolicy": "Delete",
    }


def classes(env, items):
    put(env, "storageclasses", "/apis/storage.k8s.io/v1/storageclasses",
        listing("StorageClassList", "storage.k8s.io/v1", items), query="limit=500")


# all-pass: a vanilla three-node cluster. The identity may list nodes, so k8s.version reads the kubelets.
env = "all-pass"
version(env, "v1.29.4")
apis(env)
nodes(env, "v1.29.4")
reviews(env, [review(LIST_NODES, True)])

# warnings-only: the same cluster with two classes and no default.
env = "warnings-only"
classes(env, [
    storage_class("acme-fast", "rancher.io/local-path", False),
    storage_class("acme-slow", "rancher.io/local-path", False),
])

# all-block: too old for the spec, an install identity that may not create namespaces, and a default class
# on a CSI driver whose CSINode list is refused (the CSIDriver object is the only evidence).
env = "all-block"
version(env, "v1.24.9")
nodes(env, "v1.24.9")
reviews(env, [
    review(LIST_NODES, True),
    review(CREATE_NAMESPACES, False, "no RBAC policy matched"),
])
identity(env)
classes(env, [storage_class("acme-gp3", EBS, True)])
put(env, "csinodes", "/apis/storage.k8s.io/v1/csinodes", status(
    403, "Forbidden",
    'csinodes.storage.k8s.io is forbidden: User "%s" cannot list resource "csinodes.storage.k8s.io" at the cluster scope' % USER,
), 403, "limit=500")
put(env, "csidrivers", "/apis/storage.k8s.io/v1/csidrivers", listing("CSIDriverList", "storage.k8s.io/v1", [
    {"metadata": {"name": EBS}, "spec": {"attachRequired": True, "podInfoOnMount": False}},
]), query="limit=500")

# A file under an env's api/ folder that this script did not write.
STALE = []
for e in ENVS:
    folder = os.path.join(BASE, e, "api")
    if os.path.isdir(folder):
        for name in sorted(os.listdir(folder)):
            path = os.path.normpath(os.path.join(folder, name))
            if path not in WRITTEN:
                STALE.append(path)

if CHECK:
    for path in DIFFERENT:
        print(f"differs from the script: {path}", file=sys.stderr)
    for path in STALE:
        print(f"not written by the script: {path}", file=sys.stderr)
    if DIFFERENT or STALE:
        sys.exit(1)
else:
    for path in STALE:
        os.remove(path)
