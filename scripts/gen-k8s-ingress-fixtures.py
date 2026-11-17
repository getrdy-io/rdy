#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.ingress` under tests/fixtures/checks/k8s.ingress/.

Usage: python3 -I scripts/gen-k8s-ingress-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-ingress-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster. The controller strings are the ones each project documents (ingress-nginx, the F5 NGINX controller,
Traefik, the AWS Load Balancer Controller, OpenShift's router, GKE's Gateway controller, Istio and Envoy
Gateway). The manifests say `origin = "generated"` because this script builds them (tests/fixtures/README.md).
`--check` writes nothing and fails when a committed file differs from what the script would write, or when
the fixture folder holds a file the script did not write (the mock serves every `api/*.json` of a case, so a
stale file would change a test without a diff in the script).

A case holds `api/ingressclasses.json` (the `IngressClass` list) and `api/discovery-apis.json` (`GET /apis`)
always, `api/gateway-v1.json` (`GET /apis/gateway.networking.k8s.io/v1`) and `api/gatewayclasses.json` when the
cluster serves the Gateway API at v1, and `api/services.json` for a case that asks about load balancers.
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
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.ingress")
DIFFERENT = []
WRITTEN = set()

NS = "acme-system"
USER = "acme-installer"
GW = "gateway.networking.k8s.io"


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
name = "k8s-ingress-{case}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.ingress"]

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


def forbidden(what, group_name, scope=""):
    return status(
        403,
        "Forbidden",
        f'{what} is forbidden: User "{USER}" cannot list resource "{what}" in API group "{group_name}"{scope} at the cluster scope',
    )


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
OPENSHIFT = [("route.openshift.io", ["v1"]), ("project.openshift.io", ["v1"])]
GATEWAY_V1 = [(GW, ["v1", "v1beta1"])]
GATEWAY_OLD = [(GW, ["v1beta1", "v1alpha2"])]
METALLB = [("metallb.io", ["v1beta1", "v1beta2"])]


def apis(case, extra=(), code=200):
    if code == 200:
        body = {
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": [group(n, v) for n, v in list(BASE_GROUPS) + list(extra)],
        }
    else:
        body = status(code, "Forbidden", f'forbidden: User "{USER}" cannot get path "/apis"')
    write(
        case,
        "api/discovery-apis.json",
        {"request": {"method": "GET", "path": "/apis"}, "status": code, "body": body},
    )


# ---- IngressClass ---------------------------------------------------------------------------------------------

STAMP = "2026-09-01T08:00:00Z"
NOW_TEXT = "2026-11-17T12:00:00Z"


def ingress_class(name, controller, default=False, labels=None, annotations=None, parameters=None):
    meta = {
        "name": name,
        "uid": "00000000-0000-4000-8000-0000000000a1",
        "resourceVersion": "4711",
        "generation": 1,
        "creationTimestamp": STAMP,
    }
    if labels:
        meta["labels"] = labels
    notes = dict(annotations or {})
    if default:
        notes["ingressclass.kubernetes.io/is-default-class"] = "true"
    if notes:
        meta["annotations"] = notes
    spec = {"controller": controller}
    if parameters:
        spec["parameters"] = parameters
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "IngressClass",
        "metadata": meta,
        "spec": spec,
    }


def helm_labels(name, chart, version, component=None):
    labels = {
        "app.kubernetes.io/instance": name,
        "app.kubernetes.io/managed-by": "Helm",
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/version": version,
        "helm.sh/chart": chart,
    }
    if component:
        labels["app.kubernetes.io/component"] = component
    return labels


NGINX_COMMUNITY = ingress_class(
    "nginx",
    "k8s.io/ingress-nginx",
    default=True,
    labels={**helm_labels("ingress-nginx", "ingress-nginx-4.11.2", "1.11.2", "controller"), "app.kubernetes.io/part-of": "ingress-nginx"},
    annotations={"meta.helm.sh/release-name": "ingress-nginx", "meta.helm.sh/release-namespace": "ingress-nginx"},
)
NGINX_F5 = ingress_class(
    "nginx",
    "nginx.org/ingress-controller",
    default=True,
    labels=helm_labels("nginx-ingress", "nginx-ingress-1.3.1", "3.6.1"),
    annotations={"meta.helm.sh/release-name": "nginx-ingress", "meta.helm.sh/release-namespace": "nginx-ingress"},
)
TRAEFIK_K3S = ingress_class(
    "traefik",
    "traefik.io/ingress-controller",
    default=True,
    labels={"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": "traefik-kube-system", "app.kubernetes.io/name": "traefik", "helm.sh/chart": "traefik-27.0.201"},
    annotations={"meta.helm.sh/release-name": "traefik", "meta.helm.sh/release-namespace": "kube-system"},
)
EKS_ALB = ingress_class(
    "alb",
    "ingress.k8s.aws/alb",
    labels=helm_labels("aws-load-balancer-controller", "aws-load-balancer-controller-1.8.1", "v2.8.1"),
    annotations={"meta.helm.sh/release-name": "aws-load-balancer-controller", "meta.helm.sh/release-namespace": "kube-system"},
    parameters={"apiGroup": "elbv2.k8s.aws", "kind": "IngressClassParams", "name": "acme-alb"},
)
EKS_ALB_DEFAULT = ingress_class("alb", "ingress.k8s.aws/alb", default=True, labels=EKS_ALB["metadata"]["labels"])
# OpenShift's router creates this class with no default annotation: its router takes an Ingress with no class.
OPENSHIFT_DEFAULT = ingress_class("openshift-default", "openshift.io/ingress-to-route")
# AKS application routing: the managed NGINX class uses the community controller string.
AKS_ROUTING = ingress_class(
    "webapprouting.kubernetes.azure.com",
    "k8s.io/ingress-nginx",
    default=True,
    labels={"app.kubernetes.io/managed-by": "aks-app-routing-operator"},
)
# RKE2 bundles the community controller as rke2-ingress-nginx, with the class `nginx`.
RKE2_NGINX = ingress_class(
    "nginx",
    "k8s.io/ingress-nginx",
    labels={"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/name": "rke2-ingress-nginx", "helm.sh/chart": "rke2-ingress-nginx-4.12.1"},
    annotations={"meta.helm.sh/release-name": "rke2-ingress-nginx", "meta.helm.sh/release-namespace": "kube-system"},
)
HOSTILE_NAME = "c\u001b[2J`rm -rf /`‮" + "x" * 80
LAST_APPLIED = ingress_class(
    "nginx-applied",
    "k8s.io/ingress-nginx",
    default=True,
    annotations={
        "kubectl.kubernetes.io/last-applied-configuration": '{"apiVersion":"networking.k8s.io/v1","kind":"IngressClass","metadata":{"name":"nginx-applied","annotations":{"acme/token":"ACME-MARKER-LAST-APPLIED"}}}'
    },
)


def classes(case, items=(), more=False, code=200):
    if code == 200:
        meta = {"resourceVersion": "9100"}
        if more:
            meta["continue"] = "page-2"
        body = {"apiVersion": "networking.k8s.io/v1", "kind": "IngressClassList", "metadata": meta, "items": list(items)}
    elif code == 404:
        body = status(404, "NotFound", "the server could not find the requested resource")
        body["details"] = {}
    else:
        body = forbidden("ingressclasses", "networking.k8s.io")
    write(
        case,
        "api/ingressclasses.json",
        {
            "request": {"method": "GET", "path": "/apis/networking.k8s.io/v1/ingressclasses", "query": "limit=500"},
            "status": code,
            "body": body,
        },
    )


# ---- Gateway API ----------------------------------------------------------------------------------------------

ALL_KINDS = [
    ("gatewayclasses", "GatewayClass", False, ["gc"]),
    ("gateways", "Gateway", True, ["gtw"]),
    ("httproutes", "HTTPRoute", True, []),
    ("grpcroutes", "GRPCRoute", True, []),
    ("referencegrants", "ReferenceGrant", True, ["refgrant"]),
]


def gateway_v1(case, kinds=None):
    rows = []
    for plural, kind, namespaced, short in ALL_KINDS:
        if kinds is not None and plural not in kinds:
            continue
        verbs = ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
        row = {"name": plural, "singularName": "", "namespaced": namespaced, "kind": kind, "verbs": verbs}
        if short:
            row["shortNames"] = short
        rows.append(row)
        rows.append(
            {
                "name": plural + "/status",
                "singularName": "",
                "namespaced": namespaced,
                "kind": kind,
                "verbs": ["get", "patch", "update"],
            }
        )
    body = {"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": f"{GW}/v1", "resources": rows}
    write(
        case,
        "api/gateway-v1.json",
        {"request": {"method": "GET", "path": f"/apis/{GW}/v1"}, "status": 200, "body": body},
    )


def condition(kind, state, reason, message):
    return {
        "type": kind,
        "status": state,
        "observedGeneration": 1,
        "lastTransitionTime": STAMP,
        "reason": reason,
        "message": message,
    }


def gateway_class(name, controller, accepted="True", supported=True):
    conditions = []
    if accepted is not None:
        conditions.append(
            condition(
                "Accepted",
                accepted,
                "Accepted" if accepted == "True" else "Pending",
                "Handled by Gateway controller" if accepted == "True" else "Waiting for controller",
            )
        )
    if supported and accepted == "True":
        conditions.append(condition("SupportedVersion", "True", "SupportedVersion", "Gateway API CRD versions are supported"))
    return {
        "apiVersion": f"{GW}/v1",
        "kind": "GatewayClass",
        "metadata": {
            "name": name,
            "uid": "00000000-0000-4000-8000-0000000000b1",
            "resourceVersion": "5120",
            "generation": 1,
            "creationTimestamp": STAMP,
            "annotations": {"gateway.networking.k8s.io/bundle-version": "v1.2.0", "gateway.networking.k8s.io/channel": "standard"},
        },
        "spec": {"controllerName": controller},
        "status": {"conditions": conditions},
    }


def gateway_classes(case, items=(), more=False, code=200):
    if code == 200:
        meta = {"resourceVersion": "9200"}
        if more:
            meta["continue"] = "page-2"
        body = {"apiVersion": f"{GW}/v1", "kind": "GatewayClassList", "metadata": meta, "items": list(items)}
    else:
        body = forbidden("gatewayclasses", GW)
    write(
        case,
        "api/gatewayclasses.json",
        {
            "request": {"method": "GET", "path": f"/apis/{GW}/v1/gatewayclasses", "query": "limit=500"},
            "status": code,
            "body": body,
        },
    )


GKE_GATEWAY = gateway_class("gke-l7-global-external-managed", "networking.gke.io/gateway")
GKE_GATEWAY_RC = gateway_class("gke-l7-rilb", "networking.gke.io/gateway")
ISTIO_GATEWAY = gateway_class("istio", "istio.io/gateway-controller")
ENVOY_GATEWAY = gateway_class("eg", "gateway.envoyproxy.io/gatewayclass-controller")
ENVOY_PENDING = gateway_class("eg", "gateway.envoyproxy.io/gatewayclass-controller", accepted="Unknown")
ENVOY_NO_STATUS = gateway_class("eg", "gateway.envoyproxy.io/gatewayclass-controller", accepted=None)
EKS_GATEWAY = gateway_class("aws-alb", "gateway.k8s.aws/alb")


# ---- Services -------------------------------------------------------------------------------------------------


def service(name, kind="LoadBalancer", created="2026-11-17T11:40:00Z", address=None, annotations=None):
    meta = {
        "name": name,
        "namespace": NS,
        "uid": "00000000-0000-4000-8000-0000000000c1",
        "resourceVersion": "8800",
        "labels": {"app.kubernetes.io/name": "acme-gateway"},
    }
    if created:
        meta["creationTimestamp"] = created
    if annotations:
        meta["annotations"] = annotations
    spec = {
        "type": kind,
        "selector": {"app.kubernetes.io/name": "acme-gateway"},
        "ports": [{"name": "https", "port": 443, "protocol": "TCP", "targetPort": 8443}],
        "clusterIP": "10.96.12.34",
        "clusterIPs": ["10.96.12.34"],
        "sessionAffinity": "None",
    }
    if kind == "LoadBalancer":
        spec["externalTrafficPolicy"] = "Cluster"
    ingress = []
    if address == "ip":
        ingress = [{"ip": "203.0.113.20", "ipMode": "VIP"}]
    elif address == "hostname":
        ingress = [{"hostname": "acme-gateway-1234.elb.acme.example"}]
    lb = {"ingress": ingress} if ingress else {}
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": meta,
        "spec": spec,
        "status": {"loadBalancer": lb},
    }


def services(case, items=(), more=False, code=200):
    if code == 200:
        meta = {"resourceVersion": "9300"}
        if more:
            meta["continue"] = "page-2"
        body = {"apiVersion": "v1", "kind": "ServiceList", "metadata": meta, "items": list(items)}
    else:
        body = status(
            403,
            "Forbidden",
            f'services is forbidden: User "{USER}" cannot list resource "services" in API group "" in the namespace "{NS}"',
        )
    write(
        case,
        "api/services.json",
        {
            "request": {"method": "GET", "path": f"/api/v1/namespaces/{NS}/services", "query": "limit=500"},
            "status": code,
            "body": body,
        },
    )


def case(name, summary, groups=(), items=None, more=False, class_code=200, apis_code=200):
    """A cluster: the class list and the group list. Everything else is added by the caller."""
    manifest(name, summary)
    classes(name, items if items is not None else [], more, class_code)
    apis(name, groups, apis_code)


# ---- ingress classes ------------------------------------------------------------------------------------------

case("nginx-community", "A community ingress-nginx class, the default: the retirement warning", items=[NGINX_COMMUNITY])
case("nginx-f5", "An F5 NGINX controller class, the default: no retirement warning", items=[NGINX_F5])
case("traefik-k3s", "k3s with its bundled Traefik class, the default", items=[TRAEFIK_K3S])
case("aks-app-routing", "AKS application routing: the managed class uses the community controller, so it warns", items=[AKS_ROUTING])
case("rke2-nginx", "RKE2 ships the community ingress-nginx as the class nginx", items=[RKE2_NGINX])
case("classes-mixed-case", "A controller string with capitals: the match is exact", items=[ingress_class("acme", "Acme.example/Ingress", default=True)])
case("eks-alb", "EKS with the AWS Load Balancer Controller class, not marked default", items=[EKS_ALB])
case("eks-alb-default", "EKS with the AWS Load Balancer Controller class marked default", items=[EKS_ALB_DEFAULT])
case("gke-no-class", "GKE has no IngressClass objects: its built-in ingress needs none")
case("openshift", "OpenShift: the openshift-default class and the Route API", groups=OPENSHIFT, items=[OPENSHIFT_DEFAULT])
case("none-bare", "A bare cluster with no ingress class and no Gateway API")
case("two-classes", "Community ingress-nginx and Traefik side by side, neither the default", items=[
    ingress_class("nginx", "k8s.io/ingress-nginx"),
    ingress_class("traefik", "traefik.io/ingress-controller"),
])
case("two-defaults", "Two classes both marked default", items=[
    ingress_class("nginx", "nginx.org/ingress-controller", default=True),
    ingress_class("traefik", "traefik.io/ingress-controller", default=True),
])
case("classes-forbidden", "The identity may not list ingress classes", class_code=403)
case("classes-not-served", "The server does not serve IngressClass at all (404)", class_code=404)
case("classes-cut", "The class list has a second page that is not read", items=[NGINX_F5], more=True)
case("classes-cut-no-match", "A cut class list where the first page has no class for the wanted controller", items=[TRAEFIK_K3S], more=True)
case("classes-hostile", "A class with a hostile name and a hostile controller", items=[
    ingress_class(HOSTILE_NAME, "evil\u001b[2J`rm -rf /`.example/ctl", default=True)
])
case("last-applied", "A class that carries a last-applied-configuration annotation with a marker", items=[LAST_APPLIED])

# ---- Gateway API ----------------------------------------------------------------------------------------------

c = "gateway-istio"
case(c, "Gateway API v1 with an Istio class that a controller accepted", groups=GATEWAY_V1, items=[])
gateway_v1(c)
gateway_classes(c, [ISTIO_GATEWAY])

c = "gateway-gke"
case(c, "GKE with the Gateway API and two accepted Google classes", groups=GATEWAY_V1)
gateway_v1(c)
gateway_classes(c, [GKE_GATEWAY, GKE_GATEWAY_RC])

c = "gateway-eks"
case(c, "EKS with the AWS Load Balancer Controller Gateway class and an ingress class", groups=GATEWAY_V1, items=[EKS_ALB_DEFAULT])
gateway_v1(c)
gateway_classes(c, [EKS_GATEWAY])

c = "gateway-pending"
case(c, "The Gateway API CRDs are installed and a class exists, but no controller accepted it", groups=GATEWAY_V1)
gateway_v1(c)
gateway_classes(c, [ENVOY_PENDING])

c = "gateway-no-condition"
case(c, "A class with no Accepted condition at all", groups=GATEWAY_V1)
gateway_v1(c)
gateway_classes(c, [ENVOY_NO_STATUS])

c = "gateway-no-class"
case(c, "The Gateway API CRDs are installed and no class exists", groups=GATEWAY_V1)
gateway_v1(c)
gateway_classes(c, [])

c = "gateway-cut"
case(c, "A cut class list whose first page has no accepted class", groups=GATEWAY_V1)
gateway_v1(c)
gateway_classes(c, [ENVOY_PENDING], more=True)

c = "gateway-v1beta1-only"
case(c, "An old Gateway API bundle that serves v1beta1 and v1alpha2 only", groups=GATEWAY_OLD)

c = "gateway-missing-kinds"
case(c, "Gateway API v1 installed with GatewayClass and Gateway but without HTTPRoute", groups=GATEWAY_V1)
gateway_v1(c, kinds=["gatewayclasses", "gateways"])
gateway_classes(c, [ENVOY_GATEWAY])

c = "gateway-classes-forbidden"
case(c, "The Gateway API is served and the identity may not list its classes", groups=GATEWAY_V1)
gateway_v1(c)
gateway_classes(c, code=403)

c = "gateway-openshift-absent"
case(c, "OpenShift without the Gateway API", groups=OPENSHIFT, items=[OPENSHIFT_DEFAULT])

c = "gateway-gke-absent"
case(c, "GKE without the Gateway API enabled")

c = "apis-forbidden"
case(c, "The group list is refused", items=[NGINX_F5], apis_code=403)

# ---- LoadBalancer services ------------------------------------------------------------------------------------

c = "lb-pending-old"
case(c, "A LoadBalancer service with no address for 20 minutes", items=[NGINX_F5])
services(c, [service("acme-gateway")])

c = "lb-pending-old-two"
case(c, "Two LoadBalancer services with no address for 20 and 45 minutes, and one that has an address", items=[NGINX_F5])
services(c, [
    service("acme-gateway"),
    service("acme-metrics", created="2026-11-17T11:15:00Z"),
    service("acme-public", address="hostname"),
])

c = "lb-pending-young"
case(c, "A LoadBalancer service with no address for 3 minutes", items=[NGINX_F5])
services(c, [service("acme-gateway", created="2026-11-17T11:57:00Z")])

c = "lb-pending-boundary"
case(c, "A LoadBalancer service with no address for exactly 10 minutes (600 seconds): not older than 10 minutes", items=[NGINX_F5])
services(c, [service("acme-gateway", created="2026-11-17T11:50:00Z")])

c = "lb-pending-over"
case(c, "A LoadBalancer service with no address for 10 minutes and 1 second (601 seconds)", items=[NGINX_F5])
services(c, [service("acme-gateway", created="2026-11-17T11:49:59Z")])

c = "lb-pending-under"
case(c, "A LoadBalancer service with no address for 599 seconds", items=[NGINX_F5])
services(c, [service("acme-gateway", created="2026-11-17T11:50:01Z")])

c = "lb-assigned"
case(c, "LoadBalancer services that have an address, a ClusterIP service and a NodePort service", items=[NGINX_F5])
services(c, [
    service("acme-gateway", address="ip"),
    service("acme-public", address="hostname"),
    service("acme-internal", kind="ClusterIP"),
    service("acme-nodeport", kind="NodePort"),
])

c = "lb-none"
case(c, "No LoadBalancer service in the namespace yet", items=[NGINX_F5])
services(c, [service("acme-internal", kind="ClusterIP")])

c = "lb-forbidden"
case(c, "The identity may not list services", items=[NGINX_F5])
services(c, code=403)

c = "lb-metallb"
case(c, "MetalLB is installed and a LoadBalancer service has no address for 20 minutes", groups=METALLB, items=[NGINX_F5])
services(c, [service("acme-gateway")])

c = "lb-hostile"
case(c, "A pending LoadBalancer service with a hostile name", items=[NGINX_F5])
services(c, [service(HOSTILE_NAME)])

c = "lb-cut"
case(c, "A service list with a second page, and a pending load balancer on the first", items=[NGINX_F5])
services(c, [service("acme-gateway")], more=True)

c = "lb-no-timestamp"
case(c, "A pending LoadBalancer service that carries no creation time", items=[NGINX_F5])
services(c, [service("acme-gateway", created=None)])

c = "lb-annotated"
case(c, "A pending LoadBalancer service with a last-applied-configuration annotation and a marker", items=[NGINX_F5])
services(c, [service("acme-gateway", annotations={
    "kubectl.kubernetes.io/last-applied-configuration": '{"metadata":{"annotations":{"acme/token":"ACME-MARKER-LAST-APPLIED"}}}'
})])

c = "no-lb-ask"
case(c, "A cluster with a pending LoadBalancer that the spec does not ask about: no service request is sent", items=[NGINX_F5])

# ---- Route ----------------------------------------------------------------------------------------------------

c = "route-missing"
case(c, "A cluster that does not serve the OpenShift Route API", items=[NGINX_F5])

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
            "Fix: delete any file the script does not write, run python3 -I scripts/gen-k8s-ingress-fixtures.py and commit the result.\n"
        )
        sys.exit(1)
