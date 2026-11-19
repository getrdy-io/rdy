#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.crds` under tests/fixtures/checks/k8s.crds/.

Usage: python3 -I scripts/gen-k8s-crds-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-crds-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster. The manifests say `origin = "generated"` because this script builds them
(tests/fixtures/README.md). `--check` writes nothing and fails when a committed file differs from what the
script would write, or when the fixture folder holds a file the script did not write (the mock serves every
`api/*.json` of a case, so a stale file would change a test without a diff in the script).

A case holds `api/discovery-apis.json` (`GET /apis`), one `api/discovery-<group>-<version>.json` per
`GET /apis/<group>/<version>` the check asks for, and one `api/deployment-<name>.json` per operator
`Deployment` it reads. A request that a case does not hold is answered 501 and fails the run, so a case that
leaves a file out proves the check does not ask for it.

The Deployments carry what a real one carries and the check must drop: a `last-applied-configuration`
annotation and an environment variable with a marker value (`MARKER-...`). The tests assert that no marker
reaches a finding.
"""

import json
import os
import re
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.crds")
DIFFERENT = []
WRITTEN = set()

USER = "acme-installer"
GROUP = "pki.acme.example"
OPERATOR_NS = "acme-system"
OPERATOR = "acme-operator"
MARKER_ANNOTATION = "MARKER-ANNOTATION-7731"
MARKER_ENV = "MARKER-ENV-5520"


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


def case(name, summary):
    write(
        name,
        "fixture.toml",
        f'''schema = 1
name = "k8s-crds-{name}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.crds"]

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


def version_priority(version):
    found = re.fullmatch(r"v(\d+)(?:(alpha|beta)(\d+))?", version)
    assert found, version
    stage = {None: 2, "beta": 1, "alpha": 0}[found.group(2)]
    return (stage, int(found.group(1)), int(found.group(3) or 0))


def group_entry(name, versions):
    ordered = sorted(versions, key=version_priority, reverse=True)
    return {
        "name": name,
        "versions": [{"groupVersion": f"{name}/{v}", "version": v} for v in ordered],
        "preferredVersion": {"groupVersion": f"{name}/{ordered[0]}", "version": ordered[0]},
    }


BASE_GROUPS = [
    ("apiextensions.k8s.io", ["v1"]),
    ("apps", ["v1"]),
    ("batch", ["v1"]),
    ("networking.k8s.io", ["v1"]),
    ("rbac.authorization.k8s.io", ["v1"]),
    ("storage.k8s.io", ["v1"]),
]


def apis(case_name, extra=(), code=200):
    """`GET /apis`. `extra` is a list of (group, [versions]) the cluster serves besides the base groups."""
    if code == 200:
        body = {
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": [group_entry(n, v) for n, v in list(BASE_GROUPS) + list(extra)],
        }
    else:
        body = status(code, "Forbidden", f'forbidden: User "{USER}" cannot get path "/apis"')
    write(
        case_name,
        "api/discovery-apis.json",
        {"request": {"method": "GET", "path": "/apis"}, "status": code, "body": body},
    )


VERBS = ["delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"]


def resource(plural, kind, short=None):
    """One entry of an `APIResourceList`, as the server writes a namespaced custom resource, and its
    `status` subresource."""
    entry = {
        "name": plural,
        "singularName": plural.rstrip("s") if not plural.endswith("ies") else plural[:-3] + "y",
        "namespaced": True,
        "kind": kind,
        "verbs": VERBS,
        "storageVersionHash": "k3nVq1mZ8xw=",
    }
    if short:
        entry["shortNames"] = short
    entry["categories"] = ["acme"]
    return [
        entry,
        {
            "name": plural + "/status",
            "singularName": "",
            "namespaced": True,
            "kind": kind,
            "verbs": ["get", "patch", "update"],
        },
    ]


def served(case_name, group, version, plurals, code=200):
    """`GET /apis/<group>/<version>`: the resources the version serves. `plurals` is a list of
    (plural, kind, shortNames)."""
    if code == 200:
        items = []
        for plural, kind, short in plurals:
            items.extend(resource(plural, kind, short))
        body = {
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": f"{group}/{version}",
            "resources": items,
        }
    elif code == 404:
        body = status(404, "NotFound", "the server could not find the requested resource")
    else:
        body = status(
            code,
            "Forbidden",
            f'forbidden: User "{USER}" cannot get path "/apis/{group}/{version}"',
        )
    write(
        case_name,
        f"api/discovery-{group}-{version}.json",
        {"request": {"method": "GET", "path": f"/apis/{group}/{version}"}, "status": code, "body": body},
    )


CERTS = [
    ("certificates", "Certificate", ["cert", "certs"]),
    ("issuers", "Issuer", None),
    ("clusterissuers", "ClusterIssuer", None),
]


def deployment(
    case_name,
    ns=OPERATOR_NS,
    name=OPERATOR,
    replicas=1,
    ready=1,
    containers=None,
    labels=None,
    code=200,
):
    """`GET` of an operator Deployment, written the way the API server answers, with the parts the check
    must not keep: annotations (a last-applied copy of the object) and environment values."""
    path = f"/apis/apps/v1/namespaces/{ns}/deployments/{name}"
    if code == 200:
        containers = containers or [
            {"name": name, "image": "registry.acme.example/acme/operator:v1.14.5"}
        ]
        full = []
        for c in containers:
            full.append(
                {
                    "name": c["name"],
                    "image": c["image"],
                    "args": ["--leader-elect=true", f"--secret-ref={MARKER_ENV}"],
                    "env": [
                        {"name": "ACME_LICENSE_KEY", "value": MARKER_ENV},
                        {
                            "name": "POD_NAMESPACE",
                            "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}},
                        },
                    ],
                    "ports": [{"containerPort": 9402, "name": "metrics", "protocol": "TCP"}],
                    "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}},
                    "terminationMessagePath": "/dev/termination-log",
                    "terminationMessagePolicy": "File",
                    "imagePullPolicy": "IfNotPresent",
                }
            )
        base_labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/managed-by": "acme-installer"}
        base_labels.update(labels or {})
        body = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "namespace": ns,
                "uid": "5c0e1c3f-3b5e-4f55-9d4a-2c0b6f0a1e10",
                "resourceVersion": "48211",
                "generation": 3,
                "creationTimestamp": "2026-10-01T12:00:00Z",
                "labels": base_labels,
                "annotations": {
                    "deployment.kubernetes.io/revision": "3",
                    "kubectl.kubernetes.io/last-applied-configuration": json.dumps(
                        {"spec": {"template": {"spec": {"containers": [{"env": [{"value": MARKER_ANNOTATION}]}]}}}}
                    ),
                    "acme.example/note": MARKER_ANNOTATION,
                },
            },
            "spec": {
                "replicas": replicas,
                "revisionHistoryLimit": 10,
                "progressDeadlineSeconds": 600,
                "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
                "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": "25%", "maxSurge": "25%"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": name}},
                    "spec": {
                        "containers": full,
                        "restartPolicy": "Always",
                        "serviceAccountName": name,
                        "terminationGracePeriodSeconds": 30,
                    },
                },
            },
            "status": {
                "observedGeneration": 3,
                "replicas": replicas,
                "updatedReplicas": replicas,
                "readyReplicas": ready,
                "availableReplicas": ready,
                "conditions": [
                    {
                        "type": "Available",
                        "status": "True" if ready else "False",
                        "lastUpdateTime": "2026-10-01T12:01:00Z",
                        "lastTransitionTime": "2026-10-01T12:01:00Z",
                        "reason": "MinimumReplicasAvailable" if ready else "MinimumReplicasUnavailable",
                        "message": "Deployment has minimum availability."
                        if ready
                        else "Deployment does not have minimum availability.",
                    }
                ],
            },
        }
        # A deployment scaled to zero has no `readyReplicas` or `availableReplicas` in its status.
        if not ready:
            del body["status"]["readyReplicas"]
            del body["status"]["availableReplicas"]
    elif code == 404:
        body = status(404, "NotFound", f'deployments.apps "{name}" not found')
        body["details"] = {"name": name, "group": "apps", "kind": "deployments"}
    else:
        body = status(
            code,
            "Forbidden",
            f'deployments.apps "{name}" is forbidden: User "{USER}" cannot get resource "deployments" in API group "apps" in the namespace "{ns}"',
        )
    write(
        case_name,
        f"api/deployment-{ns}-{name}.json",
        {"request": {"method": "GET", "path": path}, "status": code, "body": body},
    )


def good_cluster(name, versions=("v1",), plurals=CERTS, extra_versions=()):
    """A cluster that serves the acme group at `versions` with `plurals`."""
    apis(name, extra=[(GROUP, list(versions) + list(extra_versions))])
    for v in versions:
        served(name, GROUP, v, plurals)


# ---- definitions ----------------------------------------------------------------------------------------------

case("crds-present", "Two definitions served at v1, and an operator at 1.14.5 with its pods ready")
good_cluster("crds-present")
deployment("crds-present")

case("crd-group-missing", "The cluster serves no API group of the definitions")
apis("crd-group-missing")

case("crd-version-old", "The definitions are installed at v1beta1 only, and the spec needs v1")
apis("crd-version-old", extra=[(GROUP, ["v1beta1"])])
served("crd-version-old", GROUP, "v1beta1", CERTS)

case("crd-not-in-group", "The group is served at v1, but not the definition the spec names")
apis("crd-not-in-group", extra=[(GROUP, ["v1"])])
served("crd-not-in-group", GROUP, "v1", [("issuers", "Issuer", None)])

case("crd-any-version", "The definition is served at v1beta1 and not at the preferred v1, and the spec names no version")
apis("crd-any-version", extra=[(GROUP, ["v1", "v1beta1"])])
served("crd-any-version", GROUP, "v1", [("issuers", "Issuer", None)])
served("crd-any-version", GROUP, "v1beta1", CERTS)

case("crd-aggregated", "An aggregated API (metrics.k8s.io) is listed, so a name from it passes: installed means served")
apis("crd-aggregated", extra=[("metrics.k8s.io", ["v1beta1"])])
served("crd-aggregated", "metrics.k8s.io", "v1beta1", [("pods", "PodMetrics", None), ("nodes", "NodeMetrics", None)])

case("crd-discovery-forbidden", "The identity may not read the API group list")
apis("crd-discovery-forbidden", code=403)

case("crd-document-forbidden", "The group list is readable and the document of the version is not")
apis("crd-document-forbidden", extra=[(GROUP, ["v1"])])
served("crd-document-forbidden", GROUP, "v1", [], code=403)

case("crd-document-gone", "The group lists v1 but its document answers 404, as a CRD does that was just deleted")
apis("crd-document-gone", extra=[(GROUP, ["v1"])])
served("crd-document-gone", GROUP, "v1", [], code=404)

# ---- operators ------------------------------------------------------------------------------------------------

case("operator-ready", "An operator at 1.14.5 with 2 of 2 replicas ready")
deployment("operator-ready", replicas=2, ready=2)

case("operator-not-ready", "An operator with 0 of 1 replicas ready")
deployment("operator-not-ready", replicas=1, ready=0)

case("operator-partly-ready", "An operator with 1 of 3 replicas ready")
deployment("operator-partly-ready", replicas=3, ready=1)

case("operator-scaled-to-zero", "An operator scaled to 0 replicas")
deployment("operator-scaled-to-zero", replicas=0, ready=0)

case("operator-missing", "The operator Deployment does not exist")
deployment("operator-missing", code=404)

case("operator-forbidden", "The identity may not get the operator Deployment")
deployment("operator-forbidden", code=403)

case("operator-old", "An operator at 1.12.3, below the minimum")
deployment(
    "operator-old",
    containers=[{"name": OPERATOR, "image": "registry.acme.example/acme/operator:v1.12.3"}],
)

case("operator-prerelease", "An operator at 1.14.0-rc.1, which is below 1.14.0")
deployment(
    "operator-prerelease",
    containers=[{"name": OPERATOR, "image": "registry.acme.example/acme/operator:v1.14.0-rc.1"}],
)

case("operator-equal", "An operator at exactly the minimum, with a distro suffix on the tag")
deployment(
    "operator-equal",
    containers=[{"name": OPERATOR, "image": "registry.acme.example/acme/operator:1.14.0-ubi8"}],
)

case("operator-digest-label", "An image pinned by digest, and the version in the version label")
deployment(
    "operator-digest-label",
    containers=[
        {
            "name": OPERATOR,
            "image": "registry.acme.example/acme/operator@sha256:" + "ab" * 32,
        }
    ],
    labels={"app.kubernetes.io/version": "1.14.5"},
)

case("operator-label-differs", "The image says 1.12.3 and the version label says 1.14.5")
deployment(
    "operator-label-differs",
    containers=[{"name": OPERATOR, "image": "registry.acme.example/acme/operator:v1.12.3"}],
    labels={"app.kubernetes.io/version": "1.14.5"},
)

case("operator-latest", "An image tagged latest and no version label")
deployment(
    "operator-latest",
    containers=[{"name": OPERATOR, "image": "registry.acme.example/acme/operator:latest"}],
)

case("operator-sidecar", "A controller container named like the Deployment plus a proxy sidecar with its own version")
deployment(
    "operator-sidecar",
    containers=[
        {"name": OPERATOR + "-controller", "image": "registry.acme.example/acme/operator:v1.14.5"},
        {"name": "proxy", "image": "registry.acme.example/acme/proxy:v0.15.0"},
    ],
)

case("operator-ambiguous", "Two containers, neither named like the Deployment, with different versions")
deployment(
    "operator-ambiguous",
    containers=[
        {"name": "manager", "image": "registry.acme.example/acme/operator:v1.14.5"},
        {"name": "proxy", "image": "registry.acme.example/acme/proxy:v0.15.0"},
    ],
)

case("operator-registry-port", "An image from a registry with a port and no tag")
deployment(
    "operator-registry-port",
    containers=[{"name": OPERATOR, "image": "registry.acme.example:5000/acme/operator"}],
)

case("operator-hostile", "An operator whose tag and label carry terminal escapes and a command")
deployment(
    "operator-hostile",
    containers=[
        {"name": OPERATOR, "image": "registry.acme.example/acme/operator:v1.14.5\u001b[2J`rm -rf /`"}
    ],
    labels={"app.kubernetes.io/version": "1.14.5\u001b[2J`rm -rf /`"},
)

# ---- both -----------------------------------------------------------------------------------------------------

case("everything-wrong", "A missing group, an operator that is not ready, and an operator below the minimum")
apis("everything-wrong")
deployment("everything-wrong", replicas=1, ready=0)
deployment(
    "everything-wrong",
    ns="acme-data",
    name="acme-store",
    containers=[{"name": "acme-store", "image": "registry.acme.example/acme/store:2.3.1"}],
)

case("warn-only", "Everything is served, and one operator is not ready")
good_cluster("warn-only")
deployment("warn-only", replicas=2, ready=1)

case("two-groups", "Two groups: one is missing and one serves only an old version")
apis("two-groups", extra=[(GROUP, ["v1beta1"])])
served("two-groups", GROUP, "v1beta1", CERTS)

case("namespace-secrets", "An operator in a namespace called secrets, which the guard refuses to read through")

# ---- the whole folder -----------------------------------------------------------------------------------------------

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
        sys.stderr.write(
            "Fix: delete any file the script does not write, run python3 -I scripts/gen-k8s-crds-fixtures.py and commit the result.\n"
        )
        sys.exit(1)
