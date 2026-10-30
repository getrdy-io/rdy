#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.storageclass` under tests/fixtures/checks/k8s.storageclass/.

Usage: python3 -I scripts/gen-k8s-storageclass-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-storageclass-fixtures.py --check [<repo root>]

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
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.storageclass")
DIFFERENT = []
WRITTEN = set()

NS = "acme-system"
DEFAULT = "storageclass.kubernetes.io/is-default-class"
BETA = "storageclass.beta.kubernetes.io/is-default-class"
SC_PATH = "/apis/storage.k8s.io/v1/storageclasses"
SUMMARIES = {}


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
name = "k8s-storageclass-{case}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.storageclass"]

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


def forbidden(what):
    return status(
        403,
        "Forbidden",
        f'{what} is forbidden: User "acme-reader" cannot list resource "{what}" at the cluster scope',
    )


def put(case, file, path, body, code=200, query="", method="GET"):
    request = {"method": method, "path": path}
    if query:
        request["query"] = query
    write(case, f"api/{file}.json", {"request": request, "status": code, "body": body})


def sc(name, provisioner, default=False, beta=False, binding="WaitForFirstConsumer",
       expansion=None, reclaim=None, created="2026-01-01T00:00:00Z", annotation=None,
       parameters=None):
    notes = {}
    if default:
        notes[DEFAULT] = "true"
    if beta:
        notes[BETA] = "true"
    if annotation:
        notes.update(annotation)
    meta = {"name": name, "creationTimestamp": created}
    if notes:
        meta["annotations"] = notes
    obj = {"metadata": meta, "provisioner": provisioner}
    if binding:
        obj["volumeBindingMode"] = binding
    if expansion is not None:
        obj["allowVolumeExpansion"] = expansion
    if reclaim:
        obj["reclaimPolicy"] = reclaim
    if parameters:
        obj["parameters"] = parameters
    return obj


def listing(kind, api_version, items, cont=None):
    meta = {"resourceVersion": "1000"}
    if cont:
        meta["continue"] = cont
    return {"apiVersion": api_version, "kind": kind, "metadata": meta, "items": items}


def classes(case, items, cont=None, code=200):
    body = listing("StorageClassList", "storage.k8s.io/v1", items, cont) if code == 200 \
        else forbidden("storageclasses.storage.k8s.io")
    put(case, "storageclasses", SC_PATH, body, code, "limit=500")


def csinode(name, drivers):
    return {
        "metadata": {"name": name},
        "spec": {"drivers": [{"name": d, "nodeID": name} for d in drivers]},
    }


def csinodes(case, nodes, code=200, cont=None):
    body = listing("CSINodeList", "storage.k8s.io/v1", nodes, cont) if code == 200 \
        else forbidden("csinodes.storage.k8s.io")
    put(case, "csinodes", "/apis/storage.k8s.io/v1/csinodes", body, code, "limit=500")


def csidrivers(case, names, code=200):
    items = [
        {"metadata": {"name": n}, "spec": {"attachRequired": True, "podInfoOnMount": False}}
        for n in names
    ]
    body = listing("CSIDriverList", "storage.k8s.io/v1", items) if code == 200 \
        else forbidden("csidrivers.storage.k8s.io")
    put(case, "csidrivers", "/apis/storage.k8s.io/v1/csidrivers", body, code, "limit=500")


def pvc(name, phase, created, cls=None):
    spec = {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "10Gi"}}}
    if cls:
        spec["storageClassName"] = cls
    return {
        "metadata": {"name": name, "namespace": NS, "creationTimestamp": created},
        "spec": spec,
        "status": {"phase": phase},
    }


def namespace(case, code=200):
    body = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": NS, "creationTimestamp": "2026-01-01T00:00:00Z"},
        "status": {"phase": "Active"},
    } if code == 200 else status(
        code,
        "Forbidden" if code == 403 else "NotFound",
        f'namespaces "{NS}" is forbidden: User "acme-reader" cannot get resource "namespaces" at the cluster scope'
        if code == 403 else f'namespaces "{NS}" not found',
    )
    put(case, "namespace", f"/api/v1/namespaces/{NS}", body, code)


def claims(case, items, code=200):
    path = f"/api/v1/namespaces/{NS}/persistentvolumeclaims"
    body = listing("PersistentVolumeClaimList", "v1", items) if code == 200 \
        else status(403, "Forbidden", f'persistentvolumeclaims is forbidden: User "acme-reader" cannot list resource "persistentvolumeclaims" in the namespace "{NS}"')
    put(case, "claims", path, body, code, "limit=500")


def event(claim, reason, n=1, message="synthetic"):
    return {
        "metadata": {"name": f"{claim}.{n:04x}", "namespace": NS},
        "involvedObject": {"kind": "PersistentVolumeClaim", "name": claim, "namespace": NS},
        "reason": reason,
        "type": "Warning" if reason == "ProvisioningFailed" else "Normal",
        "message": message,
    }


def events(case, items, code=200):
    path = f"/api/v1/namespaces/{NS}/events"
    body = listing("EventList", "v1", items) if code == 200 \
        else status(403, "Forbidden", f'events is forbidden: User "acme-reader" cannot list resource "events" in the namespace "{NS}"')
    put(case, "events", path, body, code,
        "fieldSelector=involvedObject.kind=PersistentVolumeClaim&limit=500")


def by_name(case, obj, code=200):
    name = obj["metadata"]["name"] if obj else "gp3"
    body = {"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", **obj} if code == 200 \
        else status(403, "Forbidden", f'storageclasses.storage.k8s.io "{name}" is forbidden: User "acme-reader" cannot get resource "storageclasses" at the cluster scope')
    put(case, "storageclass", f"{SC_PATH}/{name}", body, code)


def case(name, summary):
    manifest(name, summary)
    SUMMARIES[name] = summary


EBS = "ebs.csi.aws.com"
ACME = "csi.acme.example"
ODF = "openshift-storage.rbd.csi.ceph.com"
ODF_FS = "openshift-storage.cephfs.csi.ceph.com"
LOCAL = "rancher.io/local-path"
PD = "pd.csi.storage.gke.io"
AUTO = "ebs.csi.eks.amazonaws.com"
# One marker in every value that must never leave the cluster (see the `secret-params` case and its test).
SENTINEL = "sentinel-7f3a"
KMS_ARN = f"arn:aws:kms:us-east-1:111122223333:key/{SENTINEL}-kms"
SECRET_NAME = f"{SENTINEL}-secret"
SECRET_NS = f"{SENTINEL}-secret-ns"

# ---- EKS -----------------------------------------------------------------------------------------------------
case("eks-gp2-no-csi", "EKS default gp2 on the in-tree EBS name with no CSI add-on: no node lists the driver")
classes("eks-gp2-no-csi", [sc("gp2", "kubernetes.io/aws-ebs", default=True)])
csinodes("eks-gp2-no-csi", [csinode("node-a", []), csinode("node-b", [])])
csidrivers("eks-gp2-no-csi", [])

case("eks-ebs-csi", "EKS with the EBS CSI add-on: gp3 is the default and three nodes list the driver")
classes("eks-ebs-csi", [
    sc("gp2", "kubernetes.io/aws-ebs"),
    sc("gp3", EBS, default=True, expansion=True, created="2026-02-01T00:00:00Z"),
])
csinodes("eks-ebs-csi", [csinode(n, [EBS]) for n in ("node-a", "node-b", "node-c")])

case("eks-auto-mode", "EKS Auto Mode: the class is on the Auto Mode provisioner and no node lists a driver")
classes("eks-auto-mode", [sc("auto-ebs-sc", AUTO, default=True)])

case("eks-gp2-with-addon", "EKS gp2 on the in-tree name, served through CSI migration, with the add-on installed")
classes("eks-gp2-with-addon", [sc("gp2", "kubernetes.io/aws-ebs", default=True)])
csinodes("eks-gp2-with-addon", [csinode("node-a", [EBS]), csinode("node-b", [EBS])])

# ---- other distributions -------------------------------------------------------------------------------------
case("k3s-local-path", "k3s: local-path is the default and is not CSI")
classes("k3s-local-path", [sc("local-path", LOCAL, default=True, reclaim="Delete")])

case("gke-immediate", "GKE persistent disk class with Immediate binding, and the driver registered")
classes("gke-immediate", [sc("standard-rwo", PD, default=True, binding="Immediate", expansion=True)])
csinodes("gke-immediate", [csinode("node-a", [PD])])

case("no-provisioner", "A default class on kubernetes.io/no-provisioner")
classes("no-provisioner", [sc("local-static", "kubernetes.io/no-provisioner", default=True)])

case("unknown-provisioner", "A default class on a provisioner the table does not know")
classes("unknown-provisioner", [sc("acme-fast", ACME, default=True)])

case("odf", "OpenShift Data Foundation: an rbd default and a cephfs class, both registered with a prefix")
classes("odf", [
    sc("ocs-storagecluster-ceph-rbd", ODF, default=True, expansion=True),
    sc("ocs-storagecluster-cephfs", ODF_FS, expansion=True),
])
csinodes("odf", [csinode("node-a", [ODF, ODF_FS]), csinode("node-b", [ODF, ODF_FS])])

# ---- default class rules -------------------------------------------------------------------------------------
case("none", "A cluster with no storage class")
classes("none", [])

case("no-default", "Two classes and neither is the default")
classes("no-default", [sc("standard", LOCAL), sc("managed-csi", "disk.csi.azure.com")])

case("two-defaults", "Two classes marked default, one with the legacy annotation")
classes("two-defaults", [
    sc("acme-old", ACME, default=True, created="2026-01-01T00:00:00Z"),
    sc("acme-new", ACME, beta=True, created="2026-03-01T00:00:00Z"),
])

case("capped", "The first page of the class list has no default and the server has more")
classes("capped", [sc("acme-a", ACME)], cont="tok-more")

# ---- evidence ---------------------------------------------------------------------------------------------------
case("driver-object-only", "A CSIDriver object exists and no CSINode lists the driver")
classes("driver-object-only", [sc("gp3", EBS, default=True)])
csinodes("driver-object-only", [csinode("node-a", []), csinode("node-b", [])])
csidrivers("driver-object-only", [EBS])

case("csinode-forbidden", "The identity may not list CSINode, and a CSIDriver object exists")
classes("csinode-forbidden", [sc("gp3", EBS, default=True)])
csinodes("csinode-forbidden", [], code=403)
csidrivers("csinode-forbidden", [EBS])

case("csinode-forbidden-no-object", "The identity may not list CSINode, and no CSIDriver object exists")
classes("csinode-forbidden-no-object", [sc("gp3", EBS, default=True)])
csinodes("csinode-forbidden-no-object", [], code=403)
csidrivers("csinode-forbidden-no-object", [])

case("both-forbidden", "The identity may list neither CSINode nor CSIDriver")
classes("both-forbidden", [sc("gp3", EBS, default=True)])
csinodes("both-forbidden", [], code=403)
csidrivers("both-forbidden", [], code=403)

case("csidriver-forbidden", "No node lists the driver, and the CSIDriver list is refused")
classes("csidriver-forbidden", [sc("gp3", EBS, default=True)])
csinodes("csidriver-forbidden", [csinode("node-a", [])])
csidrivers("csidriver-forbidden", [], code=403)

case("csinode-capped", "The first CSINode page has no hit and there are more pages, and no CSIDriver object")
classes("csinode-capped", [sc("gp3", EBS, default=True)])
csinodes("csinode-capped", [csinode("node-a", [])], cont="tok-more")
csidrivers("csinode-capped", [])

# ---- list refused ------------------------------------------------------------------------------------------------
case("list-forbidden", "The identity may not list storage classes")
classes("list-forbidden", [], code=403)

case("list-forbidden-named", "The list is refused and the class named in the spec can be read by name")
classes("list-forbidden-named", [], code=403)
by_name("list-forbidden-named", sc("gp3", EBS, expansion=True))
csinodes("list-forbidden-named", [csinode("node-a", [EBS])])

case("list-and-get-forbidden", "The list and the get by name are both refused")
classes("list-and-get-forbidden", [], code=403)
by_name("list-and-get-forbidden", None, code=403)

# ---- claims ------------------------------------------------------------------------------------------------------
case("pending-failed", "A claim has been Pending for 20 minutes and its events say ProvisioningFailed")
classes("pending-failed", [sc("gp3", EBS, default=True)])
csinodes("pending-failed", [csinode("node-a", [EBS])])
namespace("pending-failed")
claims("pending-failed", [
    pvc("data-db-0", "Pending", "2026-06-01T11:40:00Z"),
    pvc("data-db-1", "Pending", "2026-06-01T11:58:00Z"),
    pvc("data-web-0", "Bound", "2026-06-01T10:00:00Z"),
    pvc("scratch-0", "Pending", "2026-06-01T11:00:00Z", cls="other"),
])
events("pending-failed", [event("data-db-0", "ProvisioningFailed"), event("data-db-1", "ProvisioningFailed")])

case("pending-waiting", "A claim has been Pending for 20 minutes and waits for a first consumer, which is normal")
classes("pending-waiting", [sc("gp3", EBS, default=True)])
csinodes("pending-waiting", [csinode("node-a", [EBS])])
namespace("pending-waiting")
claims("pending-waiting", [pvc("data-db-0", "Pending", "2026-06-01T11:40:00Z", cls="gp3")])
events("pending-waiting", [event("data-db-0", "WaitForFirstConsumer")])

case("claims-forbidden", "The identity may not list claims in the target namespace")
classes("claims-forbidden", [sc("gp3", EBS, default=True)])
csinodes("claims-forbidden", [csinode("node-a", [EBS])])
namespace("claims-forbidden")
claims("claims-forbidden", [], code=403)

case("events-forbidden", "Claims wait, and the identity may not list events")
classes("events-forbidden", [sc("gp3", EBS, default=True)])
csinodes("events-forbidden", [csinode("node-a", [EBS])])
namespace("events-forbidden")
claims("events-forbidden", [pvc("data-db-0", "Pending", "2026-06-01T11:40:00Z")])
events("events-forbidden", [], code=403)

case("no-waiting", "No claim waits")
classes("no-waiting", [sc("gp3", EBS, default=True)])
csinodes("no-waiting", [csinode("node-a", [EBS])])
namespace("no-waiting")
claims("no-waiting", [pvc("data-db-0", "Bound", "2026-06-01T10:00:00Z")])

case("namespace-missing", "The target namespace does not exist, so the claim list is not asked for")
classes("namespace-missing", [sc("gp3", EBS, default=True)])
csinodes("namespace-missing", [csinode("node-a", [EBS])])
namespace("namespace-missing", code=404)

case("namespace-forbidden", "The identity may not get the namespace, and may list its claims")
classes("namespace-forbidden", [sc("gp3", EBS, default=True)])
csinodes("namespace-forbidden", [csinode("node-a", [EBS])])
namespace("namespace-forbidden", code=403)
claims("namespace-forbidden", [pvc("data-db-0", "Bound", "2026-06-01T10:00:00Z")])

# ---- values that must not leave ------------------------------------------------------------------------------------
case("secret-params", "A class whose parameters, annotations and events hold a KMS key ARN and secret names")
LAST_APPLIED = json.dumps({
    "parameters": {
        "kmsKeyId": KMS_ARN,
        "csi.storage.k8s.io/provisioner-secret-name": SECRET_NAME,
        "csi.storage.k8s.io/provisioner-secret-namespace": SECRET_NS,
    }
})
classes("secret-params", [sc(
    "gp3", EBS, default=True, expansion=True,
    parameters={
        "type": "gp3",
        "encrypted": "true",
        "kmsKeyId": KMS_ARN,
        "csi.storage.k8s.io/provisioner-secret-name": SECRET_NAME,
        "csi.storage.k8s.io/provisioner-secret-namespace": SECRET_NS,
    },
    annotation={"kubectl.kubernetes.io/last-applied-configuration": LAST_APPLIED},
)])
csinodes("secret-params", [csinode("node-a", [EBS])])
namespace("secret-params")
claims("secret-params", [pvc("data-db-0", "Pending", "2026-06-01T11:40:00Z")])
events("secret-params", [event(
    "data-db-0", "ProvisioningFailed",
    message=f"failed to provision volume with StorageClass \"gp3\": kms key {KMS_ARN} secret {SECRET_NS}/{SECRET_NAME} denied",
)])

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
        sys.stderr.write("Fix: delete any file the script does not write, run python3 -I scripts/gen-k8s-storageclass-fixtures.py and commit the result.\n")
        sys.exit(1)
