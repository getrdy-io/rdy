#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.cni` under tests/fixtures/checks/k8s.cni/.

Usage: python3 -I scripts/gen-k8s-cni-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-cni-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster. The objects follow what each network plugin project documents: the DaemonSet names, namespaces
and labels of its manifests, and the node condition reasons its agent sets. The manifests say
`origin = "generated"` because this script builds them (tests/fixtures/README.md). `--check` writes
nothing and fails when a committed file differs from what the script would write, or when the fixture
folder holds a file the script did not write (the mock serves every `api/*.json` of a case, so a stale
file would change a test without a diff in the script).

A case holds one file per request the check makes: `api/nodes.json` (`GET /api/v1/nodes`),
`api/discovery-apis.json` (`GET /apis`), the service range reads (`servicecidrs-v1.json`,
`servicecidrs-v1beta1.json`, `kubeadm-config.json`, or `ocp-network.json` on OpenShift), the DaemonSets
read by name (`ds-<namespace>-<name>.json`, in the order of `crates/rdy-checks-k8s/data/cni.toml`, only
when the cheaper signals do not name the plugin) and `api/policies.json` (the install namespace). A request
that a case does not hold is answered 501 and fails the run, so a case that leaves a file out proves the
check does not ask for it.
"""

import json
import os
import sys
import tomllib

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.cni")
DIFFERENT = []
WRITTEN = set()

NS = "acme-system"
USER = "acme-installer"
MARKER = "ENV-VALUE-MARKER-4f9c2a7e1b3d"

with open(os.path.join(ROOT, "crates/rdy-checks-k8s/data/cni.toml"), "rb") as f:
    TABLE = tomllib.load(f)["cni"]


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


def forbidden(what, group="", namespace=None, name=None):
    where = f' in the namespace "{namespace}"' if namespace else " at the cluster scope"
    return status(
        403,
        "Forbidden",
        f'{what} is forbidden: User "{USER}" cannot get resource "{what}" in API group "{group}"{where}',
    )


def not_found(what, name):
    body = status(404, "NotFound", f'{what} "{name}" not found')
    body["details"] = {"name": name, "kind": what}
    return body


def request(path, query=None):
    r = {"method": "GET", "path": path}
    if query:
        r["query"] = query
    return r


# ---- the case ---------------------------------------------------------------------------------------------------


class Case:
    def __init__(self, name, summary):
        self.name = name
        self.summary = summary
        self.nodes = None
        self.groups = []
        self.ocp = None
        self.service = "none"
        self.ds = None
        self.policies = []

    def emit(self):
        write(
            self.name,
            "fixture.toml",
            f'''schema = 1
name = "k8s-cni-{self.name}"
summary = "{self.summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.cni"]

[caps]
root = false
network = true
kube = true
''',
            text=True,
        )
        # nodes
        nodes = self.nodes
        if isinstance(nodes, int):
            write(self.name, "api/nodes.json", {"request": request("/api/v1/nodes", "limit=500"), "status": nodes,
                                                "body": forbidden("nodes")})
        else:
            items, more = nodes if isinstance(nodes, tuple) else (nodes, False)
            meta = {"resourceVersion": "5127"}
            if more:
                meta["continue"] = "page-2"
            write(self.name, "api/nodes.json", {"request": request("/api/v1/nodes", "limit=500"), "status": 200,
                                                "body": {"apiVersion": "v1", "kind": "NodeList", "metadata": meta, "items": items}})
        # discovery
        write(self.name, "api/discovery-apis.json", {"request": request("/apis"), "status": 200,
                                                      "body": {"kind": "APIGroupList", "apiVersion": "v1",
                                                               "groups": [group(n, v) for n, v in BASE_GROUPS + self.groups]}})
        # service ranges
        if self.ocp is not None:
            write(self.name, "api/ocp-network.json", {"request": request("/apis/config.openshift.io/v1/networks/cluster"),
                                                       "status": 200, "body": self.ocp})
        else:
            self.emit_service()
        if self.ds is not None:
            self.emit_daemonsets()
        if self.policies is not None:
            path = f"/apis/networking.k8s.io/v1/namespaces/{NS}/networkpolicies"
            if self.policies == 403:
                body = forbidden("networkpolicies", "networking.k8s.io", NS)
                code = 403
            else:
                items, more = self.policies if isinstance(self.policies, tuple) else (self.policies, False)
                meta = {"resourceVersion": "9001"}
                if more:
                    meta["continue"] = "page-2"
                body = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicyList", "metadata": meta, "items": items}
                code = 200
            write(self.name, "api/policies.json", {"request": request(path, "limit=500"), "status": code, "body": body})

    def emit_service(self):
        """The reads the check makes for the service range, in its order: ServiceCIDR v1, then v1beta1 when
        v1 is not served (404), then kubeadm-config when neither gave a range."""
        s = self.service
        v1 = beta = kubeadm = "404"
        if s == "none":
            pass
        elif s == "forbidden":
            v1, kubeadm = "403", "403"
        elif s == "server-error":
            v1 = "500"
        elif s[0] == "v1":
            v1 = s[1]
        elif s[0] == "v1beta1":
            beta = s[1]
        elif s[0] == "kubeadm":
            kubeadm = s[1]
        self.service_file("v1", v1)
        effective = v1
        if v1 == "404":
            self.service_file("v1beta1", beta)
            effective = beta
        if isinstance(effective, list):
            return
        path = "/api/v1/namespaces/kube-system/configmaps/kubeadm-config"
        if kubeadm == "404":
            code, body = 404, not_found("configmaps", "kubeadm-config")
        elif kubeadm == "403":
            code, body = 403, forbidden("configmaps", "", "kube-system", "kubeadm-config")
        else:
            code, body = 200, kubeadm_config(kubeadm)
        write(self.name, "api/kubeadm-config.json", {"request": request(path), "status": code, "body": body})

    def service_file(self, version, value):
        path = f"/apis/networking.k8s.io/{version}/servicecidrs"
        if value == "404":
            code, body = 404, status(404, "NotFound", "the server could not find the requested resource")
        elif value == "403":
            code, body = 403, forbidden("servicecidrs", "networking.k8s.io")
        elif value == "500":
            code, body = 500, status(500, "InternalError", "an error on the server has prevented the request from succeeding")
        else:
            code = 200
            body = {"apiVersion": f"networking.k8s.io/{version}", "kind": "ServiceCIDRList",
                    "metadata": {"resourceVersion": "7"}, "items": [service_cidr(version, value)]}
        write(self.name, f"api/servicecidrs-{version}.json",
              {"request": request(path, "limit=20"), "status": code, "body": body})

    def emit_daemonsets(self):
        found = self.ds.get("found")  # (namespace, name, object) or None
        family = self.ds.get("family")
        refused = self.ds.get("forbidden", set())
        order = []
        for entry in TABLE:
            for pair in entry["daemonsets"]:
                ns, name = pair.split("/")
                order.append((ns, name, entry["family"]))
        order.sort(key=lambda row: row[2] != family)  # stable: the hinted family first
        skipped = set()
        missing = self.ds.get("missing_ns", set())
        asked = {"kube-system"}
        for ns, name, _ in order:
            if ns in skipped:
                continue
            if ns not in asked:
                # The check asks whether a namespace exists before it asks for a DaemonSet in it.
                asked.add(ns)
                npath = f"/api/v1/namespaces/{ns}"
                if ns in missing:
                    skipped.add(ns)
                    write(self.name, f"api/ns-{ns}.json", {"request": request(npath), "status": 404, "body": not_found("namespaces", ns)})
                    # The DaemonSet answers a refusal, which is not a grant anyone can give: the check
                    # never asks, and the file proves it by the test that no such request is made.
                    write(self.name, f"api/ds-{ns}-unasked.json", {"request": request(f"/apis/apps/v1/namespaces/{ns}/daemonsets/{name}"), "status": 403, "body": forbidden("daemonsets", "apps", ns, name)})
                    continue
                write(self.name, f"api/ns-{ns}.json", {"request": request(npath), "status": 200,
                                                         "body": {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}, "spec": {"finalizers": ["kubernetes"]}, "status": {"phase": "Active"}}})
            path = f"/apis/apps/v1/namespaces/{ns}/daemonsets/{name}"
            if ns in refused:
                skipped.add(ns)
                write(self.name, f"api/ds-{ns}-{name}.json", {"request": request(path), "status": 403,
                                                                "body": forbidden("daemonsets", "apps", ns, name)})
                continue
            if found and (ns, name) == (found[0], found[1]):
                write(self.name, f"api/ds-{ns}-{name}.json", {"request": request(path), "status": 200, "body": found[2]})
                break
            write(self.name, f"api/ds-{ns}-{name}.json", {"request": request(path), "status": 404,
                                                            "body": not_found("daemonsets.apps", name)})


CASES = []


def case(name, summary):
    c = Case(name, summary)
    CASES.append(c)
    return c


# ---- objects ----------------------------------------------------------------------------------------------------


def version_priority(version):
    return (0 if "alpha" in version else 1 if "beta" in version else 2, version)


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

REASONS = {
    "flannel": ("FlannelIsUp", "Flannel is running on this node"),
    "calico": ("CalicoIsUp", "Calico is running on this node"),
    "cilium": ("CiliumIsUp", "Cilium is running on this node"),
    "weave": ("WeaveIsUp", "Weave pod has set this"),
    "route": ("RouteCreated", "RouteController created a route"),
}


def node(name, kind=None, kubelet="v1.30.2", cidrs=(), unavailable=False, reason=None, message=None, extra_labels=None):
    conditions = []
    if kind or reason:
        r, m = REASONS[kind] if kind else (reason, message or "x")
        conditions.append({"type": "NetworkUnavailable", "status": "True" if unavailable else "False",
                           "lastHeartbeatTime": "2026-11-01T09:00:00Z", "lastTransitionTime": "2026-11-01T09:00:00Z",
                           "reason": r, "message": m})
    for t, r in (("MemoryPressure", "KubeletHasSufficientMemory"), ("DiskPressure", "KubeletHasNoDiskPressure"),
                 ("PIDPressure", "KubeletHasSufficientPID")):
        conditions.append({"type": t, "status": "False", "lastHeartbeatTime": "2026-11-01T09:05:00Z",
                           "lastTransitionTime": "2026-11-01T09:00:00Z", "reason": r, "message": "kubelet is posting ready status"})
    conditions.append({"type": "Ready", "status": "True", "lastHeartbeatTime": "2026-11-01T09:05:00Z",
                       "lastTransitionTime": "2026-11-01T09:00:00Z", "reason": "KubeletReady", "message": "kubelet is posting ready status"})
    labels = {"kubernetes.io/arch": "amd64", "kubernetes.io/hostname": name, "kubernetes.io/os": "linux"}
    labels.update(extra_labels or {})
    spec = {}
    if cidrs:
        spec["podCIDR"] = cidrs[0]
        spec["podCIDRs"] = list(cidrs)
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {
            "name": name,
            "labels": labels,
            "annotations": {
                "node.alpha.kubernetes.io/ttl": "0",
                "volumes.kubernetes.io/controller-managed-attach-detach": "true",
                # A real node can carry anything in an annotation. The check must not keep it.
                "acme.example/note": MARKER,
            },
        },
        "spec": spec,
        "status": {
            "conditions": conditions,
            "nodeInfo": {"kubeletVersion": kubelet, "osImage": "Ubuntu 22.04.4 LTS",
                         "architecture": "amd64", "operatingSystem": "linux"},
        },
    }


def nodes_of(count, **kw):
    cidrs = kw.pop("cidrs", None)
    out = []
    for i in range(count):
        c = cidrs(i) if cidrs else ()
        out.append(node(f"acme-node-{i + 1}", cidrs=c, **kw))
    return out


def pod24(prefix):
    return lambda i: (f"{prefix}.{i}.0/24",)


def service_cidr(version, ranges):
    return {"apiVersion": f"networking.k8s.io/{version}", "kind": "ServiceCIDR",
            "metadata": {"name": "kubernetes", "creationTimestamp": "2026-11-01T08:00:00Z", "finalizers": ["networking.k8s.io/service-cidr-finalizer"]},
            "spec": {"cidrs": ranges}, "status": {"conditions": [{"type": "Ready", "status": "True", "reason": "", "message": ""}]}}


def kubeadm_config(service_subnet, pod_subnet="10.244.0.0/16"):
    text = (
        f"apiServer:\n  extraArgs:\n    authorization-mode: Node,RBAC\n    oidc-client-secret: {MARKER}\n  timeoutForControlPlane: 4m0s\n"
        "apiVersion: kubeadm.k8s.io/v1beta3\ncertificatesDir: /etc/kubernetes/pki\nclusterName: acme\n"
        "controllerManager: {}\ndns: {}\netcd:\n  local:\n    dataDir: /var/lib/etcd\n"
        "imageRepository: registry.example\nkind: ClusterConfiguration\nkubernetesVersion: v1.30.2\n"
        f"networking:\n  dnsDomain: cluster.local\n  podSubnet: {pod_subnet}\n  serviceSubnet: {service_subnet}\nscheduler: {{}}\n"
    )
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "kubeadm-config", "namespace": "kube-system"},
            "data": {"ClusterConfiguration": text, "ClusterStatus": "apiEndpoints:\n  acme-node-1:\n    advertiseAddress: 192.0.2.10\n"}}


def daemonset(ns, name, labels, containers, desired=3, ready=3):
    return {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "name": name,
            "namespace": ns,
            "labels": labels,
            "annotations": {
                "deprecated.daemonset.template.generation": "1",
                # The whole applied object, env values included.
                "kubectl.kubernetes.io/last-applied-configuration": json.dumps({"env": [{"name": "SYNTHETIC_TOKEN", "value": MARKER}]}),
            },
        },
        "spec": {
            "selector": {"matchLabels": {k: v for k, v in labels.items() if k in ("k8s-app", "app", "name", "component")}},
            "template": {"metadata": {"labels": labels}, "spec": {"containers": containers, "hostNetwork": True}},
        },
        "status": {"currentNumberScheduled": desired, "desiredNumberScheduled": desired, "numberMisscheduled": 0,
                   "numberReady": ready, "numberAvailable": ready, "observedGeneration": 1, "updatedNumberScheduled": desired},
    }


def plain(ns, name, labels, container, image, desired=3, ready=3):
    env = [{"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
           {"name": "SYNTHETIC_TOKEN", "value": MARKER},
           {"name": "LOG_LEVEL", "value": "info"}]
    return daemonset(ns, name, labels, [{"name": container, "image": image, "env": env,
                                         "args": ["--token=" + MARKER]}], desired, ready)


def aws_node(enable=None, ready=3, desired=3):
    env = [
        {"name": "ADDITIONAL_ENI_TAGS", "value": "{}"},
        {"name": "AWS_VPC_K8S_CNI_LOGLEVEL", "value": "DEBUG"},
        {"name": "AWS_VPC_K8S_CNI_RANDOMIZESNAT", "value": "prng"},
        {"name": "ENABLE_PREFIX_DELEGATION", "value": "false"},
        {"name": "SYNTHETIC_TOKEN", "value": MARKER},
        {"name": "MY_NODE_NAME", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "spec.nodeName"}}},
    ]
    if enable is not None:
        env.append({"name": "ENABLE_NETWORK_POLICY", "value": enable})
    agent = {"name": "aws-eks-nodeagent", "image": "registry.example/amazon/aws-network-policy-agent:v1.1.2-eksbuild.1",
             "args": ["--enable-ipv6=false", "--enable-network-policy=" + (enable or "false"), "--token=" + MARKER]}
    return daemonset("kube-system", "aws-node", {"app.kubernetes.io/instance": "aws-vpc-cni", "app.kubernetes.io/name": "aws-node", "k8s-app": "aws-node"},
                     [{"name": "aws-node", "image": "registry.example/amazon-k8s-cni:v1.18.2-eksbuild.1", "env": env}, agent], desired, ready)


def calico_node(ns="kube-system"):
    return plain(ns, "calico-node", {"k8s-app": "calico-node"}, "calico-node", "registry.example/calico/node:v3.28.0")


def cilium():
    return plain("kube-system", "cilium", {"app.kubernetes.io/name": "cilium-agent", "app.kubernetes.io/part-of": "cilium", "k8s-app": "cilium"},
                 "cilium-agent", "registry.example/cilium/cilium:v1.16.1")


def anetd():
    return plain("kube-system", "anetd", {"k8s-app": "cilium", "addonmanager.kubernetes.io/mode": "Reconcile"}, "cilium-agent",
                 "registry.example/gke/anetd:v1.30.4")


def weave():
    return plain("kube-system", "weave-net", {"name": "weave-net"}, "weave", "registry.example/weave-kube:2.8.1")


def antrea():
    return plain("kube-system", "antrea-agent", {"app": "antrea", "component": "antrea-agent"}, "antrea-agent", "registry.example/antrea/antrea-agent:v2.1.0")


def kube_router():
    return plain("kube-system", "kube-router", {"k8s-app": "kube-router", "tier": "node"}, "kube-router", "registry.example/kube-router:v2.2.1")


def azure_npm():
    return plain("kube-system", "azure-npm", {"k8s-app": "azure-npm"}, "azure-npm", "registry.example/azure-npm:v1.5.5")


def flannel_ds(ns="kube-flannel"):
    return plain(ns, "kube-flannel-ds", {"tier": "node", "app": "flannel", "k8s-app": "flannel"}, "kube-flannel", "registry.example/flannel:v0.25.5")


def policy(name, selector=None, types=None, egress=None, ingress=None, labels=None):
    spec = {"podSelector": selector if selector is not None else {}}
    if types is not None:
        spec["policyTypes"] = types
    if egress is not None:
        spec["egress"] = egress
    if ingress is not None:
        spec["ingress"] = ingress
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": NS, "labels": labels or {},
                         "annotations": {"kubectl.kubernetes.io/last-applied-configuration": json.dumps({"note": MARKER})}},
            "spec": spec}


DENY_EGRESS = policy("default-deny-egress", types=["Egress"])
DENY_ALL = policy("default-deny-all", types=["Ingress", "Egress"])
ALLOW_DNS = policy("allow-dns", types=["Egress"], egress=[{"to": [{"namespaceSelector": {"matchLabels": {"name": "kube-system"}}}],
                                                           "ports": [{"protocol": "UDP", "port": 53}]}])
APP_ONLY = policy("acme-web", selector={"matchLabels": {"app": "acme-web"}}, types=["Egress"])


def ocp_network(kind, pods, services):
    return {"apiVersion": "config.openshift.io/v1", "kind": "Network", "metadata": {"name": "cluster"},
            "spec": {"clusterNetwork": [{"cidr": c, "hostPrefix": 23} for c in pods], "networkType": kind, "serviceNetwork": services},
            "status": {"clusterNetwork": [{"cidr": c, "hostPrefix": 23} for c in pods], "clusterNetworkMTU": 1400,
                       "networkType": kind, "serviceNetwork": services}}


HOSTILE = "q\u001b[2J`rm -rf /`‮" + "x" * 80

# ---- the exit test ----------------------------------------------------------------------------------------------

c = case("k3s-flannel", "k3s runs Flannel with no DaemonSet: the node condition names it")
c.nodes = nodes_of(3, kind="flannel", kubelet="v1.30.4+k3s1", cidrs=pod24("10.42"), extra_labels={"node.kubernetes.io/instance-type": "k3s"})

c = case("kubeadm-flannel", "Flannel on a kubeadm cluster, which is not k3s: Flannel alone does not enforce")
c.nodes = nodes_of(3, kind="flannel", cidrs=pod24("10.244"))
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = []

c = case("default-deny-egress", "A default-deny egress policy in the install namespace, and a rule for DNS only")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = [DENY_EGRESS, ALLOW_DNS, APP_ONLY]

c = case("default-deny-all", "A default-deny policy for both directions with no rules: all egress is blocked")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = [DENY_ALL]

c = case("egress-allow-all", "A default-deny egress policy, and another policy that selects every pod and allows every destination")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = [DENY_EGRESS, policy("allow-all-egress", types=["Egress"], egress=[{}])]

c = case("ingress-deny-only", "A default-deny policy for ingress only: egress is open")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = [policy("default-deny-ingress", types=["Ingress"])]

c = case("policies-forbidden", "The identity may not list network policies")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = 403

c = case("policy-hostile-name", "A default-deny policy whose name carries a terminal escape and a command")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = [policy(HOSTILE, types=["Egress"])]

c = case("policies-cut", "The policy list has a second page")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = ([ALLOW_DNS], True)

c = case("no-namespace", "No install namespace is named, so no policy is read")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")

# ---- plugins named by cheap signals -----------------------------------------------------------------------------

c = case("restricting-policy", "A policy that selects every pod and lists destinations is not a default-deny")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = [ALLOW_DNS]

c = case("flannel-default-deny", "A default-deny egress policy on Flannel, which does not enforce it")
c.nodes = nodes_of(3, kind="flannel", cidrs=pod24("10.244"))
c.service = ("kubeadm", "10.96.0.0/12")
c.policies = [DENY_EGRESS]

c = case("calico-over-vpc-cni", "Calico policy on EKS, where the VPC CNI is the base plugin")
c.nodes = nodes_of(3, kubelet="v1.30.4-eks-a737599")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "172.20.0.0/16")

c = case("namespaces-missing", "No plugin is named, and calico-system and kube-flannel do not exist")
c.nodes = nodes_of(3)
c.ds = {"found": None, "missing_ns": {"calico-system", "kube-flannel"}}
c.service = ("kubeadm", "10.96.0.0/12")

c = case("calico-crd", "Calico: the node condition and the API group name it, so no DaemonSet is read")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")

c = case("cilium-crd", "Cilium: the node condition and the API group name it")
c.nodes = nodes_of(3, kind="cilium")
c.groups = [("cilium.io", ["v2", "v2alpha1"])]
c.service = ("v1", ["10.96.0.0/12"])

c = case("canal", "Canal: the Flannel condition and the Calico API group together")
c.nodes = nodes_of(3, kind="flannel", cidrs=pod24("10.42"))
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.43.0.0/16")

c = case("rke2-canal", "RKE2 with its default Canal: Flannel condition, Calico API group, RKE2 kubelet")
c.nodes = nodes_of(3, kind="flannel", kubelet="v1.30.4+rke2r1", cidrs=pod24("10.42"))
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.43.0.0/16")

c = case("weave-condition", "Weave Net names itself in the node condition")
c.nodes = nodes_of(3, reason="WeaveIsUp", message="Weave pod has set this")
c.service = ("kubeadm", "10.96.0.0/12")

c = case("antrea-crd", "Antrea: its API group names it")
c.nodes = nodes_of(3, cidrs=pod24("10.10"))
c.groups = [("crd.antrea.io", ["v1beta1", "v1alpha1"])]
c.service = ("kubeadm", "10.96.0.0/12")

c = case("calico-and-cilium", "Signals of two plugins: a cluster in the middle of a move")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"]), ("cilium.io", ["v2"])]
c.service = ("kubeadm", "10.96.0.0/12")

c = case("multus", "Calico with Multus next to it")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"]), ("k8s.cni.cncf.io", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")

c = case("route-created", "Only the cloud route controller condition: it names no plugin")
c.nodes = nodes_of(3, kind="route", cidrs=pod24("10.8"))
c.service = ("kubeadm", "10.96.0.0/12")
c.ds = {"found": None}

c = case("node-network-down", "A node reports NetworkUnavailable as true")
c.nodes = nodes_of(2, kind="calico") + [node("acme-node-3", kind="calico", unavailable=True)]
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")

c = case("nodes-cut", "The node list has a second page")
c.nodes = (nodes_of(2, kind="calico"), True)
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("kubeadm", "10.96.0.0/12")

c = case("nodes-forbidden", "The identity may not list nodes")
c.nodes = 403
c.ds = {"found": None}
c.service = ("kubeadm", "10.96.0.0/12")

# ---- plugins named by a DaemonSet -------------------------------------------------------------------------------

c = case("eks-vpc-cni-on", "EKS with the VPC CNI and its network policy agent turned on")
c.nodes = nodes_of(3, kubelet="v1.30.4-eks-a737599")
c.ds = {"found": ("kube-system", "aws-node", aws_node("true")), "family": "aws-vpc-cni"}
c.service = ("kubeadm", "172.20.0.0/16")
c.policies = []

c = case("eks-vpc-cni-off", "EKS with the VPC CNI and its network policy agent turned off")
c.nodes = nodes_of(3, kubelet="v1.30.4-eks-a737599")
c.ds = {"found": ("kube-system", "aws-node", aws_node("false")), "family": "aws-vpc-cni"}
c.service = ("kubeadm", "172.20.0.0/16")

c = case("eks-vpc-cni-unset", "EKS with a VPC CNI that sets no ENABLE_NETWORK_POLICY")
c.nodes = nodes_of(3, kubelet="v1.30.4-eks-a737599")
c.ds = {"found": ("kube-system", "aws-node", aws_node(None)), "family": "aws-vpc-cni"}
c.service = ("kubeadm", "172.20.0.0/16")

c = case("eks-vpc-cni-forbidden", "EKS where the identity may not read the aws-node DaemonSet")
c.nodes = nodes_of(3, kubelet="v1.30.4-eks-a737599")
c.ds = {"found": None, "family": "aws-vpc-cni", "forbidden": {"kube-system", "calico-system", "kube-flannel"}}
c.service = ("kubeadm", "172.20.0.0/16")

c = case("gke-anetd", "GKE Dataplane V2: the anetd DaemonSet, found by the kubelet version hint")
c.nodes = nodes_of(3, kubelet="v1.30.4-gke.1348000", cidrs=pod24("10.64"))
c.ds = {"found": ("kube-system", "anetd", anetd()), "family": "cilium"}
c.service = ("kubeadm", "10.68.0.0/20")

c = case("aks-azure-npm", "AKS with the Azure network policy manager")
c.nodes = nodes_of(3, kubelet="v1.30.4")
c.ds = {"found": ("kube-system", "azure-npm", azure_npm())}
c.service = ("kubeadm", "10.0.0.0/16")

c = case("kube-router-ds", "kube-router, found by its DaemonSet")
c.nodes = nodes_of(3, cidrs=pod24("10.244"))
c.ds = {"found": ("kube-system", "kube-router", kube_router())}
c.service = ("kubeadm", "10.96.0.0/12")

c = case("flannel-ds", "Flannel with no node condition, found by its DaemonSet in kube-flannel")
c.nodes = nodes_of(3, cidrs=pod24("10.244"))
c.ds = {"found": ("kube-flannel", "kube-flannel-ds", flannel_ds())}
c.service = ("kubeadm", "10.96.0.0/12")

c = case("weave-ds", "Weave Net, found by its DaemonSet")
c.nodes = nodes_of(3)
c.ds = {"found": ("kube-system", "weave-net", weave())}
c.service = ("kubeadm", "10.96.0.0/12")

c = case("calico-operator-ds", "Calico installed by its operator, found in calico-system")
c.nodes = nodes_of(3)
c.ds = {"found": ("calico-system", "calico-node", calico_node("calico-system"))}
c.service = ("kubeadm", "10.96.0.0/12")

c = case("no-plugin", "Nothing names a plugin and no DaemonSet of the list exists (a kind-style cluster)")
c.nodes = nodes_of(3, cidrs=pod24("10.244"))
c.ds = {"found": None}
c.service = ("kubeadm", "10.96.0.0/12")

c = case("daemonsets-forbidden", "Nothing names a plugin and the identity may read no DaemonSet")
c.nodes = nodes_of(3)
c.ds = {"found": None, "forbidden": {"kube-system", "calico-system", "kube-flannel"}}
c.service = ("kubeadm", "10.96.0.0/12")

# ---- OpenShift --------------------------------------------------------------------------------------------------

c = case("openshift-ovn", "OpenShift with OVN-Kubernetes: the Network object names it and holds both ranges")
c.nodes = nodes_of(3, kubelet="v1.30.4+openshift")
c.groups = [("config.openshift.io", ["v1"]), ("k8s.ovn.org", ["v1"])]
c.ocp = ocp_network("OVNKubernetes", ["10.128.0.0/14"], ["172.30.0.0/16"])

c = case("openshift-sdn", "OpenShift with OpenShift SDN, which is at end of life")
c.nodes = nodes_of(3, kubelet="v1.26.7+openshift")
c.groups = [("config.openshift.io", ["v1"])]
c.ocp = ocp_network("OpenShiftSDN", ["10.128.0.0/14"], ["172.30.0.0/16"])

# ---- the ranges -------------------------------------------------------------------------------------------------

c = case("servicecidr-v1", "A ServiceCIDR object at v1 (1.33 and later)")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("v1", ["10.96.0.0/12", "fd00:10:96::/112"])

c = case("servicecidr-beta", "A ServiceCIDR object at v1beta1 only (1.31 and 1.32)")
c.nodes = nodes_of(3, kind="calico")
c.groups = [("crd.projectcalico.org", ["v1"])]
c.service = ("v1beta1", ["10.96.0.0/12"])

c = case("service-unreadable", "The identity may read neither a ServiceCIDR nor kubeadm-config")
c.nodes = nodes_of(3, kind="flannel", cidrs=pod24("10.244"))
c.service = "forbidden"

c = case("service-none", "No source holds a service range (a managed cluster)")
c.nodes = nodes_of(3, kind="flannel", cidrs=pod24("10.244"))

c = case("service-server-error", "The ServiceCIDR read fails with a server error")
c.nodes = nodes_of(3, kind="flannel", cidrs=pod24("10.244"))
c.service = "server-error"

c = case("service-not-a-range", "kubeadm-config holds a service subnet that is not a range")
c.nodes = nodes_of(3, kind="flannel", cidrs=pod24("10.244"))
c.service = ("kubeadm", HOSTILE)

c = case("dual-stack", "A dual-stack cluster: two service ranges and two pod ranges per node")
c.nodes = [node(f"acme-node-{i + 1}", kind="flannel", cidrs=(f"10.244.{i}.0/24", f"fd00:244:{i}::/64")) for i in range(3)]
c.service = ("kubeadm", "10.96.0.0/12,fd00:96::/108")

c = case("hostile-reason", "A node condition reason with a terminal escape and a command")
c.nodes = nodes_of(2, reason=HOSTILE, message="x")
c.ds = {"found": None}
c.service = ("kubeadm", "10.96.0.0/12")

c = case("hostile-version", "A kubelet version with a terminal escape and a command")
c.nodes = nodes_of(2, kind="flannel", kubelet=HOSTILE, cidrs=pod24("10.244"))
c.service = ("kubeadm", "10.96.0.0/12")


def main():
    for c in CASES:
        c.emit()
    if CHECK:
        bad = list(DIFFERENT)
        for dirpath, _dirs, files in os.walk(BASE):
            for name in files:
                path = os.path.normpath(os.path.join(dirpath, name))
                if path not in WRITTEN:
                    bad.append(path + " (not written by the script)")
        if bad:
            print("k8s.cni fixtures are out of date. Run: python3 -I scripts/gen-k8s-cni-fixtures.py", file=sys.stderr)
            for path in bad:
                print("  " + path, file=sys.stderr)
            sys.exit(1)
        print("k8s.cni fixtures are current")
    else:
        print(f"wrote {len(CASES)} cases under {BASE}")


main()
