#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.admission` under tests/fixtures/checks/k8s.admission/.

Usage: python3 -I scripts/gen-k8s-admission-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-admission-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster. The manifests say `origin = "generated"` because this script builds them
(tests/fixtures/README.md). `--check` writes nothing and fails when a committed file differs from what the
script would write, or when the fixture folder holds a file the script did not write (the mock serves every
`api/*.json` of a case, so a stale file would change a test without a diff in the script).

A case holds `api/discovery-apis.json` (`GET /apis`), `api/namespace.json` (the target namespace, where a
test reads it), `api/group-<group>-<version>.json` (the kinds an engine group serves) and
`api/scc.json` (the OpenShift SCC list), as the case needs them.
"""

import json
import os
import re
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.admission")
DIFFERENT = []
WRITTEN = set()

NS = "acme-system"
PSA = "pod-security.kubernetes.io/"
SCC_PATH = "/apis/security.openshift.io/v1/securitycontextconstraints"


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
name = "k8s-admission-{case}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.admission"]

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
    """Sort key of a version by Kubernetes version priority: GA above beta above alpha, then the higher
    major, then the higher minor. So v2 > v1 > v2beta1 > v1beta1 > v2alpha1 > v1alpha1."""
    found = re.fullmatch(r"v(\d+)(?:(alpha|beta)(\d+))?", version)
    assert found, version
    stage = {None: 2, "beta": 1, "alpha": 0}[found.group(2)]
    return (stage, int(found.group(1)), int(found.group(3) or 0))


def group(name, versions):
    # The API server lists the versions of a group newest first and prefers the first, whatever order a
    # file lists them in.
    ordered = sorted(versions, key=version_priority, reverse=True)
    return {
        "name": name,
        "versions": [{"groupVersion": f"{name}/{v}", "version": v} for v in ordered],
        "preferredVersion": {"groupVersion": f"{name}/{ordered[0]}", "version": ordered[0]},
    }


BASE_GROUPS = [
    ("apps", ["v1"]),
    ("batch", ["v1"]),
    ("networking.k8s.io", ["v1"]),
    ("rbac.authorization.k8s.io", ["v1"]),
    ("storage.k8s.io", ["v1"]),
]


def apis(case, extra=(), code=200):
    if code == 200:
        body = {
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": [group(n, v) for n, v in list(BASE_GROUPS) + list(extra)],
        }
    else:
        body = status(
            code,
            "Forbidden",
            'forbidden: User "acme-reader" cannot get path "/apis"',
        )
    write(
        case,
        "api/discovery-apis.json",
        {"request": {"method": "GET", "path": "/apis"}, "status": code, "body": body},
    )


def namespace(case, labels=None, annotations=None, code=200):
    if code == 200:
        meta = {"name": NS}
        if labels is not None:
            meta["labels"] = labels
        if annotations is not None:
            meta["annotations"] = annotations
        body = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": meta,
            "status": {"phase": "Active"},
        }
    elif code == 404:
        body = status(404, "NotFound", f'namespaces "{NS}" not found')
        body["details"] = {"name": NS, "kind": "namespaces"}
    else:
        body = status(
            code,
            "Forbidden",
            f'namespaces "{NS}" is forbidden: User "acme-reader" cannot get resource "namespaces" in API group "" in the namespace "{NS}"',
        )
    write(
        case,
        "api/namespace.json",
        {"request": {"method": "GET", "path": f"/api/v1/namespaces/{NS}"}, "status": code, "body": body},
    )


def kinds(case, group_name, version, names, code=200):
    resources = []
    for kind, plural in names:
        resources.append(
            {
                "name": plural,
                "singularName": plural.rstrip("s"),
                "namespaced": False,
                "kind": kind,
                "verbs": ["get", "list", "watch"],
            }
        )
        # A subresource has a slash in its name and is never a kind of its own.
        resources.append(
            {
                "name": f"{plural}/status",
                "singularName": "",
                "namespaced": False,
                "kind": kind,
                "verbs": ["get"],
            }
        )
    if code == 200:
        body = {
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": f"{group_name}/{version}",
            "resources": resources,
        }
    else:
        body = status(
            code,
            "Forbidden",
            f'forbidden: User "acme-reader" cannot get path "/apis/{group_name}/{version}"',
        )
    write(
        case,
        f"api/group-{group_name}-{version}.json",
        {
            "request": {"method": "GET", "path": f"/apis/{group_name}/{version}"},
            "status": code,
            "body": body,
        },
    )


def scc_list(case, names, more=False, code=200):
    if code == 200:
        items = [
            {
                "metadata": {"name": n},
                "allowHostDirVolumePlugin": n in ("privileged", "hostmount-anyuid"),
                "allowPrivilegedContainer": n == "privileged",
                "users": ["system:admin"] if n == "privileged" else [],
                "groups": ["system:authenticated"] if n == "restricted-v2" else [],
                "volumes": ["configMap", "secret", "emptyDir"],
            }
            for n in names
        ]
        meta = {"resourceVersion": "1000"}
        if more:
            meta["continue"] = "page-2"
        body = {
            "apiVersion": "security.openshift.io/v1",
            "kind": "SecurityContextConstraintsList",
            "metadata": meta,
            "items": items,
        }
    else:
        body = status(
            code,
            "Forbidden",
            'securitycontextconstraints.security.openshift.io is forbidden: User "acme-reader" cannot list resource "securitycontextconstraints" in API group "security.openshift.io" at the cluster scope',
        )
    write(
        case,
        "api/scc.json",
        {
            "request": {"method": "GET", "path": SCC_PATH, "query": "limit=500"},
            "status": code,
            "body": body,
        },
    )


def case(name, summary):
    manifest(name, summary)


# ---- Pod Security labels, no engine, not OpenShift ----------------------------------------------------------

case("restricted", "A namespace that enforces, warns and audits restricted, on a plain cluster")
apis("restricted")
namespace(
    "restricted",
    {
        PSA + "enforce": "restricted",
        PSA + "enforce-version": "latest",
        PSA + "audit": "restricted",
        PSA + "warn": "restricted",
    },
)

case("baseline", "A namespace that enforces baseline and sets no warn or audit label")
apis("baseline")
namespace("baseline", {PSA + "enforce": "baseline", PSA + "enforce-version": "v1.29"})

case("privileged", "A namespace that enforces privileged")
apis("privileged")
namespace("privileged", {PSA + "enforce": "privileged"})

case("warn-audit", "A namespace that enforces baseline and warns and audits restricted")
apis("warn-audit")
namespace(
    "warn-audit",
    {PSA + "enforce": "baseline", PSA + "audit": "restricted", PSA + "warn": "restricted"},
)

case("no-labels", "A namespace with no Pod Security label at all, so the cluster default applies")
apis("no-labels")
namespace("no-labels", {"team": "acme"})

case("no-metadata-labels", "A namespace whose metadata holds no labels member")
apis("no-metadata-labels")
namespace("no-metadata-labels")

case("invalid-labels", "An enforce label that is not a level, and warn and audit labels that are not levels")
apis("invalid-labels")
namespace(
    "invalid-labels",
    {
        PSA + "enforce": "Restricted",
        PSA + "enforce-version": "v1.x",
        PSA + "audit": "\u001b[2Jstrict",
        PSA + "warn": "`rm -rf`",
    },
)

case("invalid-warn", "A warn label that is not a level on a namespace that enforces baseline")
apis("invalid-warn")
namespace("invalid-warn", {PSA + "enforce": "baseline", PSA + "warn": "strict"})

case("namespace-missing", "The target namespace does not exist")
apis("namespace-missing")
namespace("namespace-missing", code=404)

case("namespace-forbidden", "The identity may not read the namespace")
apis("namespace-forbidden")
namespace("namespace-forbidden", code=403)

case("no-namespace", "A plain cluster; the spec names no namespace, so no namespace request is sent")
apis("no-namespace")

case("apis-forbidden", "The identity may not read the group list")
apis("apis-forbidden", code=403)
namespace("apis-forbidden", {PSA + "enforce": "baseline"})

# ---- OpenShift ----------------------------------------------------------------------------------------------

OPENSHIFT = [("security.openshift.io", ["v1"]), ("config.openshift.io", ["v1"])]
SCCS = ["anyuid", "hostmount-anyuid", "nonroot-v2", "privileged", "restricted-v2"]
RANGE = {"openshift.io/sa.scc.uid-range": "1000680000/10000"}
SYNCED = {PSA + "audit": "restricted", PSA + "warn": "restricted"}

case("openshift", "OpenShift: warn and audit labels synced to restricted, a UID range, the SCCs listable")
apis("openshift", OPENSHIFT)
namespace("openshift", SYNCED, RANGE)
scc_list("openshift", SCCS)

case("openshift-enforce", "OpenShift where someone set enforce to restricted by hand")
apis("openshift-enforce", OPENSHIFT)
namespace("openshift-enforce", dict(SYNCED, **{PSA + "enforce": "restricted"}), RANGE)
scc_list("openshift-enforce", SCCS)

case("openshift-sync-off", "OpenShift where label sync is switched off, so the warn and audit labels are the namespace's own")
apis("openshift-sync-off", OPENSHIFT)
namespace(
    "openshift-sync-off",
    dict(SYNCED, **{"security.openshift.io/scc.podSecurityLabelSync": "false"}),
    RANGE,
)
scc_list("openshift-sync-off", SCCS)

case("openshift-scc-forbidden", "OpenShift where the identity may not list the SCCs")
apis("openshift-scc-forbidden", OPENSHIFT)
namespace("openshift-scc-forbidden", SYNCED, RANGE)
scc_list("openshift-scc-forbidden", [], code=403)

case("openshift-scc-cut", "OpenShift with an SCC list that has a second page")
apis("openshift-scc-cut", OPENSHIFT)
namespace("openshift-scc-cut", SYNCED, RANGE)
scc_list("openshift-scc-cut", SCCS, more=True)

case("openshift-hostile-range", "OpenShift with a UID range annotation that is not a range")
apis("openshift-hostile-range", OPENSHIFT)
namespace(
    "openshift-hostile-range",
    SYNCED,
    {"openshift.io/sa.scc.uid-range": "1000680000/10000; oc delete project acme"},
)
scc_list("openshift-hostile-range", SCCS)

# ---- Policy engines ------------------------------------------------------------------------------------------

# Kyverno 1.12 to 1.19 serve kyverno.io as v2, v1 and v2beta1. The server prefers v2, which holds
# PolicyException, the cleanup kinds and UpdateRequest; ClusterPolicy and Policy live in v1 (and v2beta1).
KYVERNO = [
    ("kyverno.io", ["v2", "v1", "v2beta1"]),
    ("policies.kyverno.io", ["v1", "v1beta1"]),
]
KYVERNO_LEGACY_GROUP = [("kyverno.io", ["v1"])]
KYVERNO_V2_ONLY = [("kyverno.io", ["v2"]), ("policies.kyverno.io", ["v1", "v1beta1"])]
GATEKEEPER = [
    ("templates.gatekeeper.sh", ["v1", "v1beta1", "v1alpha1"]),
    ("constraints.gatekeeper.sh", ["v1beta1", "v1alpha1"]),
]
KYVERNO_LEGACY = [("ClusterPolicy", "clusterpolicies"), ("Policy", "policies")]
KYVERNO_V2 = [
    ("PolicyException", "policyexceptions"),
    ("CleanupPolicy", "cleanuppolicies"),
    ("ClusterCleanupPolicy", "clustercleanuppolicies"),
    ("UpdateRequest", "updaterequests"),
]
EXCEPTION = [("PolicyException", "policyexceptions")]
KYVERNO_CEL = [("ValidatingPolicy", "validatingpolicies"), ("MutatingPolicy", "mutatingpolicies")]
CONSTRAINTS = [("K8sAllowedRepos", "k8sallowedrepos"), ("K8sRequiredLabels", "k8srequiredlabels")]

case("kyverno", "Kyverno 1.12 to 1.19: kyverno.io prefers v2 and keeps ClusterPolicy in v1, and the CEL group is served")
apis("kyverno", KYVERNO)
namespace("kyverno", {PSA + "enforce": "baseline"})
kinds("kyverno", "kyverno.io", "v2", KYVERNO_V2)
kinds("kyverno", "kyverno.io", "v1", KYVERNO_LEGACY)
kinds("kyverno", "policies.kyverno.io", "v1", KYVERNO_CEL)

case("kyverno-legacy-only", "Kyverno: only the legacy group is served, as v1")
apis("kyverno-legacy-only", KYVERNO_LEGACY_GROUP)
namespace("kyverno-legacy-only", {PSA + "enforce": "baseline"})
kinds("kyverno-legacy-only", "kyverno.io", "v1", KYVERNO_LEGACY)

case("kyverno-no-legacy", "Kyverno 1.20 shape: kyverno.io serves only v2, with PolicyException")
apis("kyverno-no-legacy", KYVERNO_V2_ONLY)
namespace("kyverno-no-legacy", {PSA + "enforce": "baseline"})
kinds("kyverno-no-legacy", "kyverno.io", "v2", EXCEPTION)
kinds("kyverno-no-legacy", "policies.kyverno.io", "v1", KYVERNO_CEL)

case("kyverno-v1-forbidden", "Kyverno: kyverno.io prefers v2 and can be read, but v1 may not be, so the legacy kinds are unknown")
apis("kyverno-v1-forbidden", KYVERNO[:1])
namespace("kyverno-v1-forbidden", {PSA + "enforce": "baseline"})
kinds("kyverno-v1-forbidden", "kyverno.io", "v2", KYVERNO_V2)
kinds("kyverno-v1-forbidden", "kyverno.io", "v1", [], code=403)

case("gatekeeper", "Gatekeeper: templates and two constraint kinds")
apis("gatekeeper", GATEKEEPER)
namespace("gatekeeper", {PSA + "enforce": "baseline"})
kinds("gatekeeper", "templates.gatekeeper.sh", "v1", [("ConstraintTemplate", "constrainttemplates")])
kinds("gatekeeper", "constraints.gatekeeper.sh", "v1beta1", CONSTRAINTS)

case("both-engines", "Kyverno and Gatekeeper are both installed")
apis("both-engines", KYVERNO + GATEKEEPER)
namespace("both-engines", {PSA + "enforce": "baseline"})
kinds("both-engines", "kyverno.io", "v2", KYVERNO_V2)
kinds("both-engines", "kyverno.io", "v1", KYVERNO_LEGACY)
kinds("both-engines", "policies.kyverno.io", "v1", KYVERNO_CEL)
kinds("both-engines", "templates.gatekeeper.sh", "v1", [("ConstraintTemplate", "constrainttemplates")])
kinds("both-engines", "constraints.gatekeeper.sh", "v1beta1", CONSTRAINTS)

case("engine-forbidden", "Kyverno is served but its group versions may not be read")
apis("engine-forbidden", KYVERNO)
namespace("engine-forbidden", {PSA + "enforce": "baseline"})
kinds("engine-forbidden", "kyverno.io", "v2", [], code=403)
kinds("engine-forbidden", "kyverno.io", "v1", [], code=403)
kinds("engine-forbidden", "policies.kyverno.io", "v1", [], code=403)

case("openshift-and-engine", "OpenShift with Gatekeeper installed")
apis("openshift-and-engine", OPENSHIFT + GATEKEEPER)
namespace("openshift-and-engine", SYNCED, RANGE)
kinds("openshift-and-engine", "templates.gatekeeper.sh", "v1", [("ConstraintTemplate", "constrainttemplates")])
kinds("openshift-and-engine", "constraints.gatekeeper.sh", "v1beta1", CONSTRAINTS)
scc_list("openshift-and-engine", SCCS)

MANY = [(f"K8sCheck{n:02d}", f"k8scheck{n:02d}") for n in range(12)]
HOSTILE = [
    ("Evil\u001b[2JKind", "evil1"),
    ("`rm -rf /`", "evil2"),
    ("A\u202eB", "evil3"),
    ("L" * 100, "evil4"),
]
case("many-kinds", "Gatekeeper serving twelve constraint kinds and four with hostile names")
apis("many-kinds", GATEKEEPER)
namespace("many-kinds", {PSA + "enforce": "baseline"})
kinds("many-kinds", "templates.gatekeeper.sh", "v1", [("ConstraintTemplate", "constrainttemplates")])
kinds("many-kinds", "constraints.gatekeeper.sh", "v1beta1", MANY + HOSTILE)

case("hostile-kinds", "Kyverno serving kinds with escape bytes, a backtick and an overlong name")
apis("hostile-kinds", KYVERNO_LEGACY_GROUP)
namespace("hostile-kinds", {PSA + "enforce": "baseline"})
kinds("hostile-kinds", "kyverno.io", "v1", HOSTILE)

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
            "Fix: delete any file the script does not write, run python3 -I scripts/gen-k8s-admission-fixtures.py and commit the result.\n"
        )
        sys.exit(1)
