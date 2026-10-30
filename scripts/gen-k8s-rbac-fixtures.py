#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.rbac` under tests/fixtures/checks/k8s.rbac/.

Usage: python3 -I scripts/gen-k8s-rbac-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-rbac-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster. The manifests say `origin = "generated"` because this script builds them
(tests/fixtures/README.md). `--check` writes nothing and fails when a committed file differs from what the
script would write, so the files and the script cannot drift.

A case holds `api/self-subject-review.json` (who the identity is), `api/reviews.json` (the table of
`SelfSubjectAccessReview` and `SelfSubjectRulesReview` answers, see tests/fixtures/README.md) and, where
a test needs it, a recorded namespace or a recorded refusal of the review POSTs.

`--check` also fails on a file under the case directories that this script did not write. Without
`--check`, such a file is deleted.
"""

import json
import os
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.rbac")
DIFFERENT = []
WRITTEN = set()

USER = "system:serviceaccount:acme-system:installer"
GROUPS = [
    "system:serviceaccounts",
    "system:serviceaccounts:acme-system",
    "system:authenticated",
]
RBAC = "rbac.authorization.k8s.io"


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
name = "k8s-rbac-{case}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.rbac"]

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
        "code": code,
    }


def identity(case, user=USER, groups=GROUPS, code=201, body=None):
    if body is None and code == 201:
        body = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "SelfSubjectReview",
            "metadata": {"creationTimestamp": None},
            "status": {
                "userInfo": {
                    "username": user,
                    "uid": "00000000-0000-4000-8000-000000000001",
                    "groups": groups,
                }
            },
        }
    write(
        case,
        "api/self-subject-review.json",
        {
            "request": {
                "method": "POST",
                "path": "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            },
            "status": code,
            "body": body,
        },
    )


def resource(verb, resource_name, group=None, namespace=None, name=None, subresource=None):
    attrs = {"verb": verb, "resource": resource_name}
    if group:
        attrs["group"] = group
    if namespace:
        attrs["namespace"] = namespace
    if name:
        attrs["name"] = name
    if subresource:
        attrs["subresource"] = subresource
    return {"resourceAttributes": attrs}


def path(verb, url):
    return {"nonResourceAttributes": {"verb": verb, "path": url}}


def yes(spec, reason=None):
    return {
        "spec": spec,
        "status": {
            "allowed": True,
            "reason": reason
            or 'RBAC: allowed by ClusterRoleBinding "acme-installer" of ClusterRole "acme-installer" to ServiceAccount "acme-system/installer"',
        },
    }


def no(spec, reason=""):
    return {"spec": spec, "status": {"allowed": False, "reason": reason}}


def denied(spec, reason):
    return {"spec": spec, "status": {"allowed": False, "denied": True, "reason": reason}}


def unclear(spec, error):
    return {
        "spec": spec,
        "status": {"allowed": False, "reason": "", "evaluationError": error},
    }


def rules_row(namespace, resource_rules, non_resource_rules=None, incomplete=False):
    return {
        "spec": {"namespace": namespace},
        "status": {
            "resourceRules": resource_rules,
            "nonResourceRules": non_resource_rules or [],
            "incomplete": incomplete,
        },
    }


def reviews(case, access, rules=None):
    table = {"access": access}
    if rules:
        table["rules"] = rules
    write(case, "api/reviews.json", table)


def namespace(case, name, code=200):
    if code == 200:
        body = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": name},
            "status": {"phase": "Active"},
        }
    else:
        body = status(
            code,
            "NotFound" if code == 404 else "Forbidden",
            f'namespaces "{name}" not found'
            if code == 404
            else f'namespaces "{name}" is forbidden: User "{USER}" cannot get resource "namespaces" in API group "" in the namespace "{name}"',
        )
    write(
        case,
        f"api/namespace-{name}.json",
        {"request": {"method": "GET", "path": f"/api/v1/namespaces/{name}"}, "status": code, "body": body},
    )


def refuse_reviews(case):
    """Every review POST is refused: the table has no rows and the POSTs are recorded as 403."""
    for kind in ("selfsubjectaccessreviews", "selfsubjectrulesreviews"):
        write(
            case,
            f"api/{kind}-forbidden.json",
            {
                "request": {
                    "method": "POST",
                    "path": f"/apis/authorization.k8s.io/v1/{kind}",
                },
                "status": 403,
                "body": status(
                    403,
                    "Forbidden",
                    f'{kind}.authorization.k8s.io is forbidden: User "{USER}" cannot create resource "{kind}" in API group "authorization.k8s.io" at the cluster scope',
                ),
            },
        )


def case_all_allowed():
    c = "all-allowed"
    manifest(c, "The install identity may do everything the spec lists, one item of each shape")
    identity(c)
    reviews(
        c,
        [
            yes(resource("create", "namespaces")),
            yes(resource("create", "deployments", "apps", "acme-system")),
            yes(resource("get", "pods", None, "acme-system", None, "log")),
            yes(path("get", "/healthz")),
        ],
    )


def case_two_denied():
    c = "two-denied"
    manifest(
        c,
        "Two of four items are refused: one plain not allowed, one denied by a webhook authorizer; the namespace exists",
    )
    identity(c)
    reviews(
        c,
        [
            no(resource("create", "namespaces"), "no RBAC policy matched"),
            yes(resource("create", "deployments", "apps", "acme-system")),
            denied(
                resource("list", "pods", None, "acme-system"),
                "denied by the admission webhook acme-guard",
            ),
            yes(path("get", "/healthz")),
        ],
        [
            rules_row(
                "acme-system",
                [
                    {"verbs": ["get", "list"], "apiGroups": [""], "resources": ["configmaps"]},
                    {"verbs": ["create"], "apiGroups": ["apps"], "resources": ["deployments"]},
                ],
                [{"verbs": ["get"], "nonResourceURLs": ["/healthz", "/version"]}],
            )
        ],
    )
    namespace(c, "acme-system")


def refuse_one_rules(case):
    write(
        case,
        "api/selfsubjectrulesreviews-forbidden.json",
        {
            "request": {
                "method": "POST",
                "path": "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            },
            "status": 403,
            "body": status(403, "Forbidden", "selfsubjectrulesreviews is forbidden"),
        },
    )


def case_escalate():
    c = "escalate-denied"
    manifest(
        c,
        "The spec creates a ClusterRole and a ClusterRoleBinding; escalate and bind are refused, the items themselves are allowed",
    )
    identity(c)
    reviews(
        c,
        [
            yes(resource("create", "clusterroles", RBAC)),
            yes(resource("create", "clusterrolebindings", RBAC)),
            no(resource("escalate", "clusterroles", RBAC)),
            no(resource("bind", "clusterroles", RBAC)),
        ],
        [
            rules_row(
                "acme-system",
                [{"verbs": ["create"], "apiGroups": [RBAC], "resources": ["clusterroles", "clusterrolebindings"]}],
            )
        ],
    )


def case_escalate_held():
    c = "escalate-allowed"
    manifest(c, "The identity may create roles and bindings and also escalate and bind")
    identity(c)
    reviews(
        c,
        [
            yes(resource("create", "clusterroles", RBAC)),
            yes(resource("create", "clusterrolebindings", RBAC)),
            yes(resource("escalate", "clusterroles", RBAC)),
            yes(resource("bind", "clusterroles", RBAC)),
        ],
    )


def case_evaluation_error():
    c = "evaluation-error"
    manifest(c, "An authorizer failed: allowed false with an evaluationError")
    identity(c)
    reviews(
        c,
        [
            yes(resource("create", "namespaces")),
            unclear(
                resource("create", "deployments", "apps", "acme-system"),
                "webhook authorizer acme-guard: context deadline exceeded",
            ),
        ],
        [rules_row("acme-system", [{"verbs": ["create"], "apiGroups": ["apps"], "resources": ["deployments"]}], incomplete=True)],
    )
    namespace(c, "acme-system")


def case_non_resource():
    c = "non-resource"
    manifest(c, "Two URLs that are not resources: one allowed, one not")
    identity(c)
    reviews(c, [yes(path("get", "/healthz")), no(path("get", "/metrics"))])


def case_reviews_forbidden():
    c = "reviews-forbidden"
    manifest(c, "The identity may not create access reviews: every review POST is a 403")
    identity(c)
    refuse_reviews(c)


def case_rules_forbidden():
    c = "rules-forbidden"
    manifest(c, "A namespaced item is refused, the namespace exists, and the rules review is a 403")
    identity(c)
    reviews(c, [no(resource("create", "deployments", "apps", "acme-system"))])
    refuse_one_rules(c)
    namespace(c, "acme-system")


def case_old_server():
    c = "old-server"
    manifest(c, "A server before 1.28: SelfSubjectReview is a 404, the access reviews work")
    identity(c, code=404, body=status(404, "NotFound", "the server could not find the requested resource"))
    reviews(c, [yes(resource("create", "namespaces")), no(resource("create", "nodes"))])


def case_identity_forbidden():
    c = "identity-forbidden"
    manifest(c, "SelfSubjectReview is refused with a 403; the access reviews work")
    identity(c, code=403, body=status(403, "Forbidden", "selfsubjectreviews is forbidden"))
    reviews(c, [yes(resource("create", "namespaces"))])


def case_as_allowed():
    c = "as-allowed"
    manifest(
        c,
        "The spec tests as a service account; the kubeconfig identity may impersonate it; one item is refused",
    )
    identity(c, user="acme-admin", groups=["system:authenticated"])
    reviews(
        c,
        [
            yes(resource("impersonate", "serviceaccounts", None, "acme-system", "installer")),
            yes(resource("create", "namespaces")),
            no(resource("create", "nodes")),
            no(resource("list", "pods", None, "acme-system")),
        ],
        [rules_row("acme-system", [{"verbs": ["create"], "apiGroups": [""], "resources": ["namespaces"]}])],
    )
    namespace(c, "acme-system")


def case_as_forbidden():
    c = "as-forbidden"
    manifest(
        c,
        "The identity may impersonate the service account, but the first impersonated review is refused with a 403",
    )
    identity(c, user="acme-admin", groups=["system:authenticated"])
    rows = [
        yes(resource("impersonate", "serviceaccounts", None, "acme-system", "installer")),
        {"spec": resource("create", "namespaces"), "refuse": 403},
    ]
    reviews(c, rows)


def case_as_refused():
    c = "as-refused"
    manifest(c, "The kubeconfig identity may not impersonate the user the spec names")
    identity(c, user="acme-reader", groups=["system:authenticated"])
    reviews(
        c,
        [
            no(resource("impersonate", "serviceaccounts", None, "acme-system", "installer")),
            yes(resource("create", "namespaces")),
        ],
    )


def case_namespace_missing():
    c = "namespace-missing"
    manifest(c, "A namespaced item is refused and its namespace does not exist")
    identity(c)
    reviews(
        c,
        [no(resource("create", "deployments", "apps", "ghost"))],
        [rules_row("ghost", [{"verbs": ["get"], "apiGroups": [""], "resources": ["namespaces"]}])],
    )
    namespace(c, "ghost", 404)


def case_namespace_forbidden():
    c = "namespace-forbidden"
    manifest(c, "A namespaced item is refused and the identity may not read namespaces")
    identity(c)
    reviews(
        c,
        [no(resource("create", "deployments", "apps", "ghost"))],
        [rules_row("ghost", [])],
    )
    namespace(c, "ghost", 403)


def case_as_at_the_cap():
    c = "as-at-the-cap"
    manifest(
        c,
        "A spec with 100 items and an as: the impersonate question is one of the 100, so the last item is not asked",
    )
    identity(c, user="acme-admin", groups=["system:authenticated"])
    rows = [yes(resource("impersonate", "serviceaccounts", None, "acme-system", "installer"))]
    rows += [yes(resource("get", "configmaps", None, "acme-system", f"cfg-{i:03d}")) for i in range(99)]
    reviews(c, rows)


def case_at_the_cap():
    c = "at-the-cap"
    manifest(c, "A spec with 100 items, one of them a ClusterRole: the escalate review does not fit")
    identity(c)
    rows = [yes(resource("get", "configmaps", None, "acme-system", f"cfg-{i:03d}")) for i in range(99)]
    rows.append(yes(resource("create", "clusterroles", RBAC)))
    reviews(c, rows)


def case_fixed_hostile():
    c = "hostile-reasons"
    manifest(c, "Reasons and an identity with control characters, backticks and long text")
    identity(c, user="acme\u001b[2J`rm -rf`", groups=["g`x`"])
    reviews(
        c,
        [
            no(resource("create", "namespaces", None, "acme-system"), "\u001b[31mred\u001b[0m `evil` " + "x" * 400),
        ],
        [rules_row("acme-system", [{"verbs": ["get"], "apiGroups": ["a`b`"], "resources": ["pods"]}])],
    )
    namespace(c, "acme-system")


for build in (
    case_all_allowed,
    case_two_denied,
    case_escalate,
    case_escalate_held,
    case_evaluation_error,
    case_non_resource,
    case_reviews_forbidden,
    case_rules_forbidden,
    case_old_server,
    case_identity_forbidden,
    case_as_allowed,
    case_as_forbidden,
    case_as_refused,
    case_namespace_missing,
    case_namespace_forbidden,
    case_at_the_cap,
    case_as_at_the_cap,
    case_fixed_hostile,
):
    build()

# A file the script did not write is stale: it names a case that was removed or renamed.
for folder, _, files in os.walk(BASE):
    for file_name in files:
        found = os.path.normpath(os.path.join(folder, file_name))
        if found in WRITTEN:
            continue
        if CHECK:
            DIFFERENT.append(found)
        else:
            os.remove(found)
if not CHECK:
    for folder, _, _ in sorted(os.walk(BASE), reverse=True):
        if folder != BASE and not os.listdir(folder):
            os.rmdir(folder)

if CHECK and DIFFERENT:
    for path_ in DIFFERENT:
        print(f"differs from the script: {os.path.relpath(path_, ROOT)}")
    print("Run: python3 -I scripts/gen-k8s-rbac-fixtures.py")
    sys.exit(1)
