#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.namespace` under tests/fixtures/checks/k8s.namespace/.

Usage: python3 -I scripts/gen-k8s-namespace-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-namespace-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster. The manifests say `origin = "generated"` because this script builds them
(tests/fixtures/README.md). `--check` writes nothing and fails when a committed file differs from what the
script would write, or when the fixture folder holds a file the script did not write (the mock serves every
`api/*.json` of a case, so a stale file would change a test without a diff in the script).

A case holds `api/namespace.json` (the target namespace), `api/quotas.json` (the `ResourceQuota` list),
`api/limitranges.json` (the `LimitRange` list), and, for a namespace that does not exist,
`api/discovery-apis.json` (`GET /apis`) and `api/reviews.json` (the `SelfSubjectAccessReview` table).
A request that a case does not hold is answered 501 and fails the run, so a case that leaves a file out
proves the check does not ask for it.
"""

import json
import os
import re
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.namespace")
DIFFERENT = []
WRITTEN = set()

NS = "acme-system"
USER = "acme-installer"


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
name = "k8s-namespace-{case}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.namespace"]

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


def group(name, versions):
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
OPENSHIFT = [("project.openshift.io", ["v1"]), ("security.openshift.io", ["v1"])]


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
            f'forbidden: User "{USER}" cannot get path "/apis"',
        )
    write(
        case,
        "api/discovery-apis.json",
        {"request": {"method": "GET", "path": "/apis"}, "status": code, "body": body},
    )


def namespace(case, name=NS, phase="Active", code=200, conditions=None, deleting=False):
    if code == 200:
        meta = {"name": name}
        if deleting:
            meta["deletionTimestamp"] = "2026-10-01T12:00:00Z"
        body = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": meta,
            "spec": {"finalizers": ["kubernetes"]},
            "status": {"phase": phase},
        }
        if conditions:
            body["status"]["conditions"] = conditions
    elif code == 404:
        body = status(404, "NotFound", f'namespaces "{name}" not found')
        body["details"] = {"name": name, "kind": "namespaces"}
    else:
        body = status(
            code,
            "Forbidden",
            f'namespaces "{name}" is forbidden: User "{USER}" cannot get resource "namespaces" in API group "" in the namespace "{name}"',
        )
    write(
        case,
        "api/namespace.json",
        {"request": {"method": "GET", "path": f"/api/v1/namespaces/{name}"}, "status": code, "body": body},
    )


def condition(kind, state, reason, message):
    return {
        "type": kind,
        "status": state,
        "lastTransitionTime": "2026-10-01T12:00:05Z",
        "reason": reason,
        "message": message,
    }


def quota(name, hard, used=None, scopes=None, selector=False):
    spec = {"hard": hard}
    if scopes:
        spec["scopes"] = scopes
    if selector:
        spec["scopeSelector"] = {
            "matchExpressions": [
                {"scopeName": "PriorityClass", "operator": "In", "values": ["acme-high"]}
            ]
        }
    obj = {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": name, "namespace": NS},
        "spec": spec,
    }
    if used is not None:
        obj["status"] = {"hard": hard, "used": used}
    return obj


def listing(kind, items, more=False):
    meta = {"resourceVersion": "1000"}
    if more:
        meta["continue"] = "page-2"
    return {"apiVersion": "v1", "kind": kind + "List", "metadata": meta, "items": items}


def lists(case, resource, kind, items, more=False, code=200, name=NS, what="resourcequotas"):
    if code == 200:
        body = listing(kind, items, more)
    else:
        body = status(
            code,
            "Forbidden",
            f'{what} is forbidden: User "{USER}" cannot list resource "{what}" in API group "" in the namespace "{name}"',
        )
    write(
        case,
        f"api/{resource}.json",
        {
            "request": {
                "method": "GET",
                "path": f"/api/v1/namespaces/{name}/{what}",
                "query": "limit=500",
            },
            "status": code,
            "body": body,
        },
    )


def quotas(case, items=(), more=False, code=200, name=NS):
    lists(case, "quotas", "ResourceQuota", list(items), more, code, name, "resourcequotas")


def limit_range(name, items):
    return {
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": {"name": name, "namespace": NS},
        "spec": {"limits": items},
    }


def limits(case, items=(), more=False, code=200, name=NS):
    lists(case, "limitranges", "LimitRange", list(items), more, code, name, "limitranges")


def resource_row(verb, resource, group_name=None, allowed=True, reason=""):
    attrs = {"verb": verb, "resource": resource}
    if group_name:
        attrs["group"] = group_name
    if allowed:
        answer = {
            "allowed": True,
            "reason": reason
            or f'RBAC: allowed by ClusterRoleBinding "{USER}" of ClusterRole "{USER}" to User "{USER}"',
        }
    else:
        answer = {"allowed": False, "reason": reason}
    return {"spec": {"resourceAttributes": attrs}, "status": answer}


def reviews(case, rows):
    write(case, "api/reviews.json", {"access": rows})


def case(name, summary):
    manifest(name, summary)


# ---- the amounts -------------------------------------------------------------------------------------------------

SHORT_HARD = {
    "requests.cpu": "8",
    "requests.memory": "64Gi",
    "pods": "50",
    "persistentvolumeclaims": "10",
    "requests.storage": "500Gi",
}
SHORT_USED = {
    "requests.cpu": "6",
    "requests.memory": "20Gi",
    "pods": "12",
    "persistentvolumeclaims": "2",
    "requests.storage": "100Gi",
}
ROOMY_HARD = {
    "requests.cpu": "64",
    "requests.memory": "256Gi",
    "pods": "200",
    "persistentvolumeclaims": "50",
    "requests.storage": "2Ti",
}
HOSTILE_NAME = "q\u001b[2J`rm -rf /`‮" + "x" * 80

# ---- the namespace ------------------------------------------------------------------------------------------------

case("active-plain", "An active namespace with no quota and no limit range")
namespace("active-plain")
quotas("active-plain")
limits("active-plain")

case("terminating", "A namespace that is being deleted, with its deletion conditions; nothing else is asked")
namespace(
    "terminating",
    phase="Terminating",
    deleting=True,
    conditions=[
        condition("NamespaceDeletionDiscoveryFailure", "False", "ResourcesDiscovered", "All resources successfully discovered"),
        condition("NamespaceDeletionContentFailure", "True", "ContentDeletionFailed", "Some resources are remaining"),
        condition("NamespaceContentRemaining", "True", "SomeResourcesRemain", "Some resources are remaining: pods. has 2 resource instances"),
        condition("NamespaceFinalizersRemaining", "False", "ContentHasNoFinalizers", "All content-preserving finalizers finished"),
    ],
)

case("namespace-forbidden", "The identity may not read the namespace but may list its quotas and limit ranges")
namespace("namespace-forbidden", code=403)
quotas("namespace-forbidden", [quota("compute", SHORT_HARD, SHORT_USED)])
limits("namespace-forbidden")

case("namespace-named-secrets", "A namespace that is called secrets: the guard refuses the lists under it")
namespace("namespace-named-secrets", name="secrets")

case("no-namespace", "The spec names no namespace, so no request is sent")

# ---- a namespace that does not exist -------------------------------------------------------------------------------

case("missing-creatable", "A missing namespace that the identity may create")
namespace("missing-creatable", code=404)
apis("missing-creatable")
reviews("missing-creatable", [resource_row("create", "namespaces")])

case("missing-denied", "A missing namespace that the identity may not create")
namespace("missing-denied", code=404)
apis("missing-denied")
reviews(
    "missing-denied",
    [
        resource_row(
            "create",
            "namespaces",
            allowed=False,
            reason='RBAC: no rule allows "create" on "namespaces" for User "acme-installer"',
        )
    ],
)

case("missing-openshift", "OpenShift: a missing namespace, and the identity may create project requests")
namespace("missing-openshift", code=404)
apis("missing-openshift", OPENSHIFT)
reviews("missing-openshift", [resource_row("create", "projectrequests", "project.openshift.io")])

case("missing-openshift-denied", "OpenShift: a missing namespace, and project requests are denied")
namespace("missing-openshift-denied", code=404)
apis("missing-openshift-denied", OPENSHIFT)
reviews(
    "missing-openshift-denied",
    [
        resource_row(
            "create",
            "projectrequests",
            "project.openshift.io",
            allowed=False,
            reason='RBAC: no rule allows "create" on "projectrequests.project.openshift.io" for User "acme-installer"',
        )
    ],
)

case("missing-apis-forbidden", "A missing namespace; the group list may not be read, so OpenShift is not known")
namespace("missing-apis-forbidden", code=404)
apis("missing-apis-forbidden", code=403)
reviews(
    "missing-apis-forbidden",
    [resource_row("create", "namespaces", allowed=False, reason="not allowed")],
)

case("missing-review-refused", "A missing namespace; the access review itself is refused")
namespace("missing-review-refused", code=404)
apis("missing-review-refused")
reviews(
    "missing-review-refused",
    [{"spec": {"resourceAttributes": {"verb": "create", "resource": "namespaces"}}, "refuse": 403}],
)

# ---- quotas ---------------------------------------------------------------------------------------------------------

case("quota-short", "One quota with 2 CPU of requests left, and the other resources roomy")
namespace("quota-short")
quotas("quota-short", [quota("compute", SHORT_HARD, SHORT_USED)])
limits("quota-short")

case("quota-roomy", "One quota with room for everything the spec needs")
namespace("quota-roomy")
quotas("quota-roomy", [quota("compute", ROOMY_HARD, SHORT_USED)])
limits("quota-roomy")

case("quota-two", "Two unscoped quotas; the second has 5 pods left")
namespace("quota-two")
quotas(
    "quota-two",
    [
        quota("compute", ROOMY_HARD, SHORT_USED),
        quota("object-counts", {"pods": "110"}, {"pods": "105"}),
    ],
)
limits("quota-two")

case("quota-aliases", "A quota written with the short names cpu and memory")
namespace("quota-aliases")
quotas(
    "quota-aliases",
    [quota("legacy", {"cpu": "4", "memory": "8Gi"}, {"cpu": "1", "memory": "1Gi"})],
)
limits("quota-aliases")

case("quota-scoped", "Only scoped quotas: a scopeSelector and a scopes list, neither is evaluated")
namespace("quota-scoped")
quotas(
    "quota-scoped",
    [
        quota("high-priority", {"requests.cpu": "2"}, {"requests.cpu": "1"}, selector=True),
        quota("long-running", {"requests.memory": "4Gi"}, {"requests.memory": "1Gi"}, scopes=["NotTerminating"]),
    ],
)
limits("quota-scoped")

case("quota-scoped-and-short", "A scoped quota and an unscoped one with 2 CPU left")
namespace("quota-scoped-and-short")
quotas(
    "quota-scoped-and-short",
    [
        quota("high-priority", {"requests.cpu": "32"}, {"requests.cpu": "1"}, selector=True),
        quota("compute", SHORT_HARD, SHORT_USED),
    ],
)
limits("quota-scoped-and-short")

case("quota-unused", "A quota the controller has not filled in yet: no status")
namespace("quota-unused")
quotas("quota-unused", [quota("compute", SHORT_HARD)])
limits("quota-unused")

case("quota-forbidden", "The identity may not list quotas")
namespace("quota-forbidden")
quotas("quota-forbidden", code=403)
limits("quota-forbidden")

case("quota-cut", "A quota list with a second page")
namespace("quota-cut")
quotas("quota-cut", [quota("compute", ROOMY_HARD, SHORT_USED)], more=True)
limits("quota-cut")

case("quota-hostile", "A quota with a hostile name and an amount that is not one")
namespace("quota-hostile")
quotas(
    "quota-hostile",
    [
        quota(HOSTILE_NAME, {"requests.cpu": "8"}, {"requests.cpu": "6"}),
        quota("garbled", {"requests.memory": "lots"}, {"requests.memory": "\u001b[2J1Gi"}),
    ],
)
limits("quota-hostile")

# ---- limit ranges ---------------------------------------------------------------------------------------------------

case("limit-low", "A container max of 8Gi and a default limit of 512Mi")
namespace("limit-low")
quotas("limit-low")
limits(
    "limit-low",
    [
        limit_range(
            "container-caps",
            [
                {
                    "type": "Container",
                    "max": {"cpu": "4", "memory": "8Gi"},
                    "default": {"cpu": "500m", "memory": "512Mi"},
                    "defaultRequest": {"cpu": "100m", "memory": "256Mi"},
                },
                {"type": "PersistentVolumeClaim", "max": {"storage": "10Gi"}},
            ],
        )
    ],
)

case("limit-pod-low", "A pod max of 8Gi and no container item")
namespace("limit-pod-low")
quotas("limit-pod-low")
limits("limit-pod-low", [limit_range("pod-caps", [{"type": "Pod", "max": {"memory": "8Gi"}}])])

case("limit-default-low", "A default limit of 512Mi under a container max of 64Gi")
namespace("limit-default-low")
quotas("limit-default-low")
limits(
    "limit-default-low",
    [
        limit_range(
            "defaults",
            [{"type": "Container", "max": {"memory": "64Gi"}, "default": {"memory": "512Mi"}}],
        )
    ],
)

case("limit-ok", "A container max of 64Gi and a default limit of 32Gi")
namespace("limit-ok")
quotas("limit-ok")
limits(
    "limit-ok",
    [
        limit_range(
            "container-caps",
            [{"type": "Container", "max": {"memory": "64Gi"}, "default": {"memory": "32Gi"}}],
        )
    ],
)

case("limit-forbidden", "The identity may not list limit ranges")
namespace("limit-forbidden")
quotas("limit-forbidden")
limits("limit-forbidden", code=403)

case("limit-cut", "A limit range list with a second page")
namespace("limit-cut")
quotas("limit-cut")
limits(
    "limit-cut",
    [limit_range("container-caps", [{"type": "Container", "max": {"memory": "64Gi"}}])],
    more=True,
)

case("limit-hostile", "A limit range with a hostile name, one amount that is not one, and a cap of 8Gi")
namespace("limit-hostile")
quotas("limit-hostile")
limits(
    "limit-hostile",
    [
        limit_range(HOSTILE_NAME, [{"type": "Container", "max": {"memory": "8Gi"}}]),
        limit_range("garbled", [{"type": "Pod", "max": {"memory": "\u001b[2Jbig"}}]),
    ],
)

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
            "Fix: delete any file the script does not write, run python3 -I scripts/gen-k8s-namespace-fixtures.py and commit the result.\n"
        )
        sys.exit(1)
