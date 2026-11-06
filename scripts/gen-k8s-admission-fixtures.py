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
`api/scc.json` (the OpenShift SCC list), as the case needs them. M1-160 adds the lists of the webhook
configurations (`api/webhooks-*.json`), the Services and EndpointSlices behind them
(`api/service-*.json`, `api/slices-*.json`), the `ValidatingAdmissionPolicy` objects (`api/vap-*.json`) and
the engines' policies (`api/policies-*.json`). `finish()` writes an empty list for every one of them that a
case does not write itself, because the check asks for them on every cluster and the mock fails a request
no file answers.
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
CASES_SEEN = []

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
        if code == 200:
            SERVED.append((CASES_SEEN[-1], group_name, version, kind, plural, False))
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
    CASES_SEEN.append(name)
    manifest(name, summary)


SERVED = []

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

# No file for kyverno.io/v1: the preferred version is forbidden, so the check does not ask for v1 (a test asserts
# the requests).
case("engine-forbidden", "Kyverno is served but its group versions may not be read")
apis("engine-forbidden", KYVERNO)
namespace("engine-forbidden", {PSA + "enforce": "baseline"})
kinds("engine-forbidden", "kyverno.io", "v2", [], code=403)
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

# ---- Admission webhooks, ValidatingAdmissionPolicy and the engines' policies (M1-160) ---------------------------

HOOKS_NS = "acme-hooks"
ADMISSION = "/apis/admissionregistration.k8s.io/v1"
VW_PATH = ADMISSION + "/validatingwebhookconfigurations"
MW_PATH = ADMISSION + "/mutatingwebhookconfigurations"
VAP_PATH = ADMISSION + "/validatingadmissionpolicies"
VAPB_PATH = ADMISSION + "/validatingadmissionpolicybindings"
CASES = CASES_SEEN
# Every group version a case serves, for the policy lists the check makes: (case, group, version, kind, plural,
# namespaced). The finalizer writes an empty list for each one the case did not write itself.
LISTS_WRITTEN = set()


def reject(code, what):
    if code == 404:
        return status(404, "NotFound", "the server could not find the requested resource")
    return status(
        code,
        "Forbidden",
        f'{what} is forbidden: User "acme-reader" cannot list resource "{what}" at the cluster scope',
    )


def list_file(case, fname, path, query, api_version, kind, items=(), code=200, more=False, what="resources"):
    if code == 200:
        meta = {"resourceVersion": "1000"}
        if more:
            meta["continue"] = "page-2"
        body = {"apiVersion": api_version, "kind": kind + "List", "metadata": meta, "items": list(items)}
    else:
        body = reject(code, what)
    write(
        case,
        f"api/{fname}.json",
        {"request": {"method": "GET", "path": path, "query": query}, "status": code, "body": body},
    )


def webhook_configs(case, validating=None, mutating=None, code=200):
    """The two webhook configuration lists. `validating` and `mutating` are lists of webhook objects, wrapped
    in one configuration each (`acme-validating` and `acme-mutating`)."""

    def config(kind, name, hooks):
        return {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": kind,
            "metadata": {"name": name},
            "webhooks": hooks,
        }

    for fname, path, kind, name, hooks in (
        ("webhooks-validating", VW_PATH, "ValidatingWebhookConfiguration", "acme-validating", validating),
        ("webhooks-mutating", MW_PATH, "MutatingWebhookConfiguration", "acme-mutating", mutating),
    ):
        items = [config(kind, name, hooks)] if hooks else []
        list_file(case, fname, path, "limit=500", "admissionregistration.k8s.io/v1", kind, items, code,
                  what=kind.lower().replace("webhookconfiguration", "webhookconfigurations"))


POD_RULE = {
    "apiGroups": [""],
    "apiVersions": ["v1"],
    "operations": ["CREATE"],
    "resources": ["pods"],
    "scope": "Namespaced",
}
NOT_KUBE_SYSTEM = {
    "matchExpressions": [
        {"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": ["kube-system"]}
    ]
}
NS_LABELS = {"kubernetes.io/metadata.name": NS}


def hook(name, service="hooks", fail="Fail", rules=None, ns_selector=NOT_KUBE_SYSTEM, obj_selector=None,
         conditions=None, url=None, service_ns=HOOKS_NS):
    client = {"url": url} if url else {"service": {"namespace": service_ns, "name": service, "path": "/validate", "port": 443}}
    client["caBundle"] = "Zm9vYmFy"
    out = {
        "name": name,
        "clientConfig": client,
        "rules": rules if rules is not None else [POD_RULE],
        "admissionReviewVersions": ["v1"],
        "sideEffects": "None",
        "timeoutSeconds": 10,
    }
    if fail is not None:
        out["failurePolicy"] = fail
    if ns_selector is not None:
        out["namespaceSelector"] = ns_selector
    if obj_selector is not None:
        out["objectSelector"] = obj_selector
    if conditions:
        out["matchConditions"] = [{"name": "not-system", "expression": "request.userInfo.username != 'system:admin'"}]
    return out


def service(case, name="hooks", svc_ns=HOOKS_NS, kind="ClusterIP", items=None, code=200):
    if items is None:
        spec = {"type": kind, "ports": [{"port": 443}]}
        if kind == "ExternalName":
            spec["externalName"] = "hooks.example.invalid"
        else:
            spec["selector"] = {"app": name}
        items = [
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": svc_ns}, "spec": spec}
        ]
    list_file(
        case, f"service-{svc_ns}-{name}", f"/api/v1/namespaces/{svc_ns}/services",
        f"fieldSelector=metadata.name={name}&limit=2", "v1", "Service", items, code, what="services",
    )


def slices(case, endpoints, name="hooks", svc_ns=HOOKS_NS, code=200):
    """`endpoints` is a list of endpoint objects, or None for the slice the controller writes when no pod
    backs the Service (`endpoints` is null)."""
    items = [
        {
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": f"{name}-x7k2p",
                "namespace": svc_ns,
                "labels": {"kubernetes.io/service-name": name},
            },
            "addressType": "IPv4",
            "endpoints": endpoints,
            "ports": [{"name": "https", "port": 8443, "protocol": "TCP"}],
        }
    ]
    list_file(
        case, f"slices-{svc_ns}-{name}", f"/apis/discovery.k8s.io/v1/namespaces/{svc_ns}/endpointslices",
        f"labelSelector=kubernetes.io/service-name={name}&limit=500", "discovery.k8s.io/v1", "EndpointSlice",
        items, code, what="endpointslices",
    )


def endpoint(ip, ready="unset"):
    out = {"addresses": [ip], "nodeName": "acme-node-1"}
    if ready == "unset":
        out["conditions"] = {}
    else:
        out["conditions"] = {"ready": ready, "serving": ready, "terminating": False}
    return out


def webhook_case(name, summary, validating=None, mutating=None, wcode=200, svc=True, endpoints=None, slice_code=200,
                 svc_code=200, svc_kind="ClusterIP", svc_items=None):
    case(name, summary)
    apis(name)
    namespace(name, dict({PSA + "enforce": "baseline"}, **NS_LABELS))
    webhook_configs(name, validating, mutating, wcode)
    if svc:
        service(name, kind=svc_kind, items=svc_items, code=svc_code)
    if svc and svc_code == 200 and svc_kind == "ClusterIP" and svc_items is None:
        slices(name, endpoints, code=slice_code)


webhook_case("webhook-fail-empty", "A Fail webhook whose EndpointSlice exists and has no endpoints", [hook("pods.acme-hooks.example")])
webhook_case("webhook-default-fail", "A webhook with no failurePolicy (the v1 default is Fail) and no endpoint", [hook("pods.acme-hooks.example", fail=None)])
webhook_case(
    "webhook-ready",
    "A Fail webhook with a ready endpoint, one with ready unset, and one that is not ready",
    [hook("pods.acme-hooks.example")],
    endpoints=[endpoint("10.0.0.5", True), endpoint("10.0.0.6"), endpoint("10.0.0.7", False)],
)
webhook_case(
    "webhook-not-ready",
    "A Fail webhook whose endpoints all report ready false",
    [hook("pods.acme-hooks.example")],
    endpoints=[endpoint("10.0.0.5", False), endpoint("10.0.0.6", False)],
)
webhook_case("webhook-mutating", "A mutating Fail webhook with no endpoint", mutating=[hook("inject.acme-hooks.example")])
webhook_case(
    "webhook-service-missing", "A Fail webhook whose Service does not exist", [hook("pods.acme-hooks.example")], svc_items=[]
)
webhook_case(
    "webhook-match-conditions",
    "A Fail webhook with matchConditions and no endpoint",
    [hook("pods.acme-hooks.example", conditions=True)],
)
webhook_case(
    "webhook-object-selector",
    "A Fail webhook with an objectSelector and no endpoint",
    [hook("pods.acme-hooks.example", obj_selector={"matchLabels": {"acme.example/inject": "true"}})],
)
webhook_case(
    "webhook-url",
    "A Fail webhook whose backend is a URL",
    [hook("pods.acme-hooks.example", url="https://hooks.example.invalid/validate")],
    svc=False,
)
webhook_case(
    "webhook-external-name",
    "A Fail webhook whose Service is of type ExternalName",
    [hook("pods.acme-hooks.example")],
    svc_kind="ExternalName",
)
webhook_case(
    "webhook-ignore",
    "A webhook that fails open and has no endpoint",
    [hook("pods.acme-hooks.example", fail="Ignore")],
    svc=False,
)
webhook_case(
    "webhook-not-matching",
    "Fail webhooks with no endpoint that do not match: another namespace, deployments only, update only, a subresource",
    [
        hook("other-ns.acme-hooks.example", service="other-ns", ns_selector={"matchLabels": {"team": "other"}}),
        hook("deployments.acme-hooks.example", service="deploys", rules=[dict(POD_RULE, resources=["deployments"], apiGroups=["apps"])]),
        hook("updates.acme-hooks.example", service="updates", rules=[dict(POD_RULE, operations=["UPDATE"])]),
        hook("sub.acme-hooks.example", service="sub", rules=[dict(POD_RULE, resources=["pods/exec"])]),
    ],
    svc=False,
)
webhook_case("webhooks-forbidden", "The identity may not list webhook configurations", wcode=403, svc=False)
webhook_case(
    "webhook-slices-forbidden", "The identity may list Services but not EndpointSlices", [hook("pods.acme-hooks.example")], slice_code=403
)
webhook_case(
    "webhook-services-forbidden", "The identity may not list Services", [hook("pods.acme-hooks.example")], svc_code=403
)

many = "webhook-many-services"
case(many, "Ten Fail webhooks on ten Services: only eight are read")
apis(many)
namespace(many, dict({PSA + "enforce": "baseline"}, **NS_LABELS))
webhook_configs(many, [hook(f"w{n}.acme-hooks.example", service=f"hooks{n}") for n in range(10)])
for n in range(8):
    service(many, name=f"hooks{n}")
    slices(many, [endpoint("10.0.0.5", True)], name=f"hooks{n}")

# ValidatingAdmissionPolicy.
POLICY_NAME = "require-labels"


def vap_objects(case_name, binding_actions=("Deny",), policy_rules=None, binding_ns_selector=None, bindings_code=200):
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": policy_rules if policy_rules is not None else [
                    {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods"]}
                ]
            },
            "validations": [{"expression": "has(object.metadata.labels.owner)", "message": "needs an owner label"}],
        },
    }
    list_file(case_name, "vap-policies", VAP_PATH, "limit=500", "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", [policy], what="validatingadmissionpolicies")
    binding_spec = {"policyName": POLICY_NAME, "validationActions": list(binding_actions)}
    if binding_ns_selector:
        binding_spec["matchResources"] = {"namespaceSelector": binding_ns_selector}
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": "require-labels-acme"},
        "spec": binding_spec,
    }
    list_file(case_name, "vap-bindings", VAPB_PATH, "limit=500", "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", [binding], bindings_code, what="validatingadmissionpolicybindings")


def vap_case(name, summary, **kw):
    case(name, summary)
    apis(name)
    namespace(name, dict({PSA + "enforce": "baseline"}, **NS_LABELS))
    vap_objects(name, **kw)


vap_case("vap-deny", "A policy and a binding that denies, matching pod creates in every namespace")
vap_case("vap-warn-only", "A binding whose actions are Warn and Audit, which reject nothing", binding_actions=("Warn", "Audit"))
vap_case(
    "vap-not-matching",
    "A policy for deployments only, and a binding for another namespace",
    policy_rules=[{"apiGroups": ["apps"], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["deployments"]}],
)
vap_case(
    "vap-other-namespace",
    "A denying binding whose namespaceSelector names another team",
    binding_ns_selector={"matchLabels": {"team": "other"}},
)
vap_case("vap-bindings-forbidden", "The identity may list policies but not bindings", bindings_code=403)
case("vap-not-served", "A cluster older than 1.30: ValidatingAdmissionPolicy v1 is not served")
apis("vap-not-served")
namespace("vap-not-served", dict({PSA + "enforce": "baseline"}, **NS_LABELS))
list_file("vap-not-served", "vap-policies", VAP_PATH, "limit=500", "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", code=404)
case("vap-forbidden", "The identity may not list ValidatingAdmissionPolicy")
apis("vap-forbidden")
namespace("vap-forbidden", dict({PSA + "enforce": "baseline"}, **NS_LABELS))
list_file("vap-forbidden", "vap-policies", VAP_PATH, "limit=500", "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", code=403, what="validatingadmissionpolicies")


# The engines' own policies.
def policy_list(case_name, group_name, version, kind, plural, items, code=200, more=False):
    LISTS_WRITTEN.add((case_name, group_name, plural))
    list_file(
        case_name, f"policies-{group_name}-{plural}", f"/apis/{group_name}/{version}/{plural}", "limit=500",
        f"{group_name}/{version}", kind, items, code, more, what=f"{plural}.{group_name}",
    )


def kyverno_policy(name, action="Enforce", kinds=("Pod",), namespaces=None, rule_action=None):
    resources = {"kinds": list(kinds)}
    if namespaces:
        resources["namespaces"] = namespaces
    validate = {"message": "needs a label", "pattern": {"metadata": {"labels": {"owner": "?*"}}}}
    if rule_action:
        validate["failureAction"] = rule_action
    return {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {"name": name},
        "spec": {
            "validationFailureAction": action,
            "background": True,
            "rules": [{"name": "check-owner", "match": {"any": [{"resources": resources}]}, "validate": validate}],
        },
    }


def cel_policy(name, actions=("Deny",)):
    return {
        "apiVersion": "policies.kyverno.io/v1",
        "kind": "ValidatingPolicy",
        "metadata": {"name": name},
        "spec": {
            "validationActions": list(actions),
            "matchConstraints": {
                "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]
            },
            "validations": [{"expression": "object.spec.hostNetwork != true", "message": "no host network"}],
        },
    }


def constraint(kind, name, action=None, namespaces=None, kinds=None):
    spec = {"match": {"kinds": kinds or [{"apiGroups": [""], "kinds": ["Pod"]}]}, "parameters": {"labels": ["owner"]}}
    if namespaces:
        spec["match"]["namespaces"] = namespaces
    if action:
        spec["enforcementAction"] = action
    return {
        "apiVersion": "constraints.gatekeeper.sh/v1beta1",
        "kind": kind,
        "metadata": {"name": name},
        "spec": spec,
    }


case("engine-policies", "Kyverno and Gatekeeper with policies: enforcing, audit-only, and not matching pods")
apis("engine-policies", KYVERNO + GATEKEEPER)
namespace("engine-policies", dict({PSA + "enforce": "baseline"}, **NS_LABELS))
kinds("engine-policies", "kyverno.io", "v2", KYVERNO_V2)
kinds("engine-policies", "kyverno.io", "v1", KYVERNO_LEGACY)
kinds("engine-policies", "policies.kyverno.io", "v1", KYVERNO_CEL)
kinds("engine-policies", "templates.gatekeeper.sh", "v1", [("ConstraintTemplate", "constrainttemplates")])
kinds("engine-policies", "constraints.gatekeeper.sh", "v1beta1", CONSTRAINTS)
policy_list(
    "engine-policies", "kyverno.io", "v1", "ClusterPolicy", "clusterpolicies",
    [
        kyverno_policy("require-owner", namespaces=["acme-*"]),
        kyverno_policy("audit-only", action="Audit"),
        kyverno_policy("deployments-only", kinds=("Deployment",)),
        kyverno_policy("other-namespace", namespaces=["other-*"]),
        kyverno_policy("rule-level-enforce", action="Audit", rule_action="Enforce"),
    ],
)
policy_list("engine-policies", "policies.kyverno.io", "v1", "ValidatingPolicy", "validatingpolicies", [cel_policy("no-host-network"), cel_policy("warn-only", actions=("Warn",))])
policy_list(
    "engine-policies", "constraints.gatekeeper.sh", "v1beta1", "K8sAllowedRepos", "k8sallowedrepos",
    [constraint("K8sAllowedRepos", "repos-acme", namespaces=["acme-system"]), constraint("K8sAllowedRepos", "repos-dryrun", action="dryrun")],
)
policy_list(
    "engine-policies", "constraints.gatekeeper.sh", "v1beta1", "K8sRequiredLabels", "k8srequiredlabels",
    [constraint("K8sRequiredLabels", "labels-everywhere", action="deny"), constraint("K8sRequiredLabels", "labels-other", namespaces=["other"])],
)

case("engine-policies-forbidden", "Kyverno and Gatekeeper are installed and the identity may not list their policies")
apis("engine-policies-forbidden", KYVERNO + GATEKEEPER)
namespace("engine-policies-forbidden", dict({PSA + "enforce": "baseline"}, **NS_LABELS))
kinds("engine-policies-forbidden", "kyverno.io", "v2", KYVERNO_V2)
kinds("engine-policies-forbidden", "kyverno.io", "v1", KYVERNO_LEGACY)
kinds("engine-policies-forbidden", "policies.kyverno.io", "v1", KYVERNO_CEL)
kinds("engine-policies-forbidden", "templates.gatekeeper.sh", "v1", [("ConstraintTemplate", "constrainttemplates")])
kinds("engine-policies-forbidden", "constraints.gatekeeper.sh", "v1beta1", CONSTRAINTS)
policy_list("engine-policies-forbidden", "kyverno.io", "v1", "ClusterPolicy", "clusterpolicies", [], code=403)
policy_list("engine-policies-forbidden", "policies.kyverno.io", "v1", "ValidatingPolicy", "validatingpolicies", [], code=403)
policy_list("engine-policies-forbidden", "constraints.gatekeeper.sh", "v1beta1", "K8sAllowedRepos", "k8sallowedrepos", [], code=403)
policy_list("engine-policies-forbidden", "constraints.gatekeeper.sh", "v1beta1", "K8sRequiredLabels", "k8srequiredlabels", [], code=403)

case("kyverno-exception-only", "Kyverno 1.20 with no CEL group: kyverno.io serves only PolicyException, so no policy is listed")
apis("kyverno-exception-only", [("kyverno.io", ["v2"])])
namespace("kyverno-exception-only", dict({PSA + "enforce": "baseline"}, **NS_LABELS))
kinds("kyverno-exception-only", "kyverno.io", "v2", EXCEPTION)


# ---- the lists every case needs ---------------------------------------------------------------------------------


def kind_shaped(kind):
    return re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,62}", kind) is not None


def planned(group_name, version, resources):
    """The policy lists the check makes for one served group version: the same rules as `policies::plan`."""
    cluster = [r for r in resources if not r[2]]
    if (group_name, version) == ("kyverno.io", "v1"):
        return [r for r in cluster if (r[0], r[1]) == ("ClusterPolicy", "clusterpolicies")]
    if group_name == "policies.kyverno.io" and version in ("v1", "v1beta1"):
        return [r for r in cluster if (r[0], r[1]) in (("ValidatingPolicy", "validatingpolicies"), ("ImageValidatingPolicy", "imagevalidatingpolicies"))]
    if (group_name, version) == ("constraints.gatekeeper.sh", "v1beta1"):
        shaped = [r for r in cluster if re.fullmatch(r"[a-z0-9]{1,63}", r[1])]
        ordered = sorted({r[1]: r for r in shaped}.values(), key=lambda r: (not kind_shaped(r[0]), r[1]))
        return ordered[:6]
    return []


def finish():
    """Writes the lists a case did not write itself: empty webhook and policy lists (a 1.30+ cluster with
    none of them), and an empty list for each policy kind a served group version calls for."""
    for name in CASES:
        for fname, path, kind in (
            ("webhooks-validating", VW_PATH, "ValidatingWebhookConfiguration"),
            ("webhooks-mutating", MW_PATH, "MutatingWebhookConfiguration"),
        ):
            if os.path.normpath(os.path.join(BASE, name, f"api/{fname}.json")) not in WRITTEN:
                list_file(name, fname, path, "limit=500", "admissionregistration.k8s.io/v1", kind)
        if os.path.normpath(os.path.join(BASE, name, "api/vap-policies.json")) not in WRITTEN:
            list_file(name, "vap-policies", VAP_PATH, "limit=500", "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy")
        by_group = {}
        for (case_name, group_name, version, kind, plural, namespaced) in SERVED:
            if case_name == name:
                by_group.setdefault((group_name, version), []).append((kind, plural, namespaced))
        for (group_name, version), resources in sorted(by_group.items()):
            for kind, plural, _ in planned(group_name, version, resources):
                if (name, group_name, plural) not in LISTS_WRITTEN:
                    policy_list(name, group_name, version, kind, plural, [])


finish()


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
