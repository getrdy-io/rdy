# Review of section 4 (Kubernetes family) of the check catalog, by k8s-expert

Reviewed: `/home/user/rdy/docs/plan/03-check-catalog.md` section 4, the k8s rows in Appendix B and the k8s tickets, against `CLAUDE.md`, the plan milestones and `docs/adr/0010-kubernetes-client-kube-rs.md`. I did not edit the catalog.

## Verdict

Approve with changes. The shape is right: SelfSubjectAccessReview instead of trial actions, GET only (lists included), partial results that name the denied verb and resource, discovery for CRDs and engines, and an off-by-default dry-run. But 8 items would produce a wrong result or a wrong fix on the common path (EKS with no CSI driver, nodes that always block on allocatable, a false "authenticated", a remediation that is factually wrong). Fix those before the k8s tickets start. Everything else can be fixed in the same pass or filed.

Must fix: 8. Should fix: 17. Nit: 9.

## Ingress-nginx lookup (the item the author flagged)

Confirmed, not unconfirmed. Kubernetes SIG Network and the Security Response Committee announced the retirement of Ingress NGINX on 2025-11-11. Best-effort maintenance ended in March 2026. After that: no releases, no bug fixes, no security fixes, repositories read-only. Existing installs keep running. A joint Steering and Security Response statement on 2026-01-29 told users to migrate and said nothing is a drop-in replacement. Scope: only the community controller (`spec.controller: k8s.io/ingress-nginx`). The F5 NGINX controller (`nginx.org/ingress-controller`) is a different project and is not retired. A distro vendor may still patch critical CVEs for its own build (SUSE says through December 2027 for Rancher Prime LTS). That is a vendor promise, not upstream support.

The catalog never states this. It only uses `class: nginx|any` in the `k8s.ingress` threshold line, which presents nginx as a normal target. See S2 for the replacement text.

Sources: [Kubernetes blog, 2025-11-11](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/), [Steering and SRC statement, 2026-01-29](https://www.kubernetes.io/blog/2026/01/29/ingress-nginx-statement/), [SUSE retirement guide](https://documentation.suse.com/cloudnative/rancher-manager/latest/en/cluster-admin/kubernetes-resources/load-balancer-and-ingress-controller/guide-to-ingress-retirement.html).

Other facts I checked: `SelfSubjectReview` is stable (`authentication.k8s.io/v1`) in 1.28 (KEP-3325), so the catalog is right there. `ValidatingAdmissionPolicy` GA in 1.30 is right. Kubelet may be up to three minors older than the API server since 1.28, so that is right too. EndpointSlice over Endpoints is right (core `Endpoints` is deprecated from 1.33).

## Must fix

### M1. `k8s.storageclass`: the most common real failure is not caught, and non-CSI classes are falsely blocked

Problems:
1. The rule "CSI provisioner without a `CSIDriver`: block" only fires for names that look like CSI. On EKS the default class is `gp2` with provisioner `kubernetes.io/aws-ebs`. That provisioner is only served through CSI migration, so with no EBS CSI add-on every PVC stays Pending. This is the number one EKS storage failure and the check as written says nothing. Same for `kubernetes.io/gce-pd` (older GKE `standard`), `kubernetes.io/azure-disk`, `kubernetes.io/azure-file`, `kubernetes.io/vsphere-volume`, `kubernetes.io/cinder`.
2. A `CSIDriver` object is optional for a driver. Absence of the object does not mean the driver is missing, and presence does not mean the node plugin runs. The reliable evidence is `CSINode` (`storage.k8s.io/v1`, `spec.drivers[].name`), which lists drivers registered by kubelet on each node.
3. Non-CSI provisioners exist and are normal. k3s default is `local-path` (`rancher.io/local-path`), node-local, RWO, `WaitForFirstConsumer`. `kubernetes.io/no-provisioner` is local volumes. These must not hit the CSI rule.
4. `provisioners.toml` (Appendix B) lacks entries that matter: `ebs.csi.eks.amazonaws.com` (EKS Auto Mode), `filestore.csi.storage.gke.io` (RWX), `rancher.io/local-path`, `driver.longhorn.io` (RWO, and RWX through its share manager), and OpenShift Data Foundation names, which are prefixed (`openshift-storage.rbd.csi.ceph.com`, `openshift-storage.cephfs.csi.ceph.com`). Match ceph by suffix. OpenShift also ships `gp3-csi` and `thin-csi`.

Fix: replace the Source and Thresholds text with:

> Source: `StorageClass` list. Normalise the provisioner: map in-tree names to their CSI driver (`kubernetes.io/aws-ebs` to `ebs.csi.aws.com`, `kubernetes.io/gce-pd` to `pd.csi.storage.gke.io`, `kubernetes.io/azure-disk` to `disk.csi.azure.com`, `kubernetes.io/azure-file` to `file.csi.azure.com`, `kubernetes.io/cinder` to `cinder.csi.openstack.org`, `kubernetes.io/vsphere-volume` to `csi.vsphere.vmware.com`). Driver evidence, strongest first: `CSINode` `spec.drivers[].name` on at least one schedulable node; then a `CSIDriver` object. Classes with `local-path`, `no-provisioner` or a provisioner not in the table are "not CSI or unknown, driver not verified" and never block on driver grounds.
>
> Thresholds: normalised provisioner has no `CSINode` registration and no `CSIDriver`: block. `CSIDriver` exists but no `CSINode` lists it: warn "driver object found, no node has registered it, the node plugin may be down". `CSINode` list forbidden: use `CSIDriver` only and mark partial.

Fix text for EKS must include the IAM role, or the add-on installs and the controller still fails with `UnauthorizedOperation`:

> No EBS CSI driver is registered, so PVCs on `{class}` stay Pending. Install it with a role: `eksctl create addon --cluster {c} --name aws-ebs-csi-driver --service-account-role-arn {role_arn}`. The role needs the `AmazonEBSCSIDriverPolicy` managed policy and a trust relationship for the add-on service account (IRSA or EKS Pod Identity).

Also add GKE (driver on by default, class `standard-rwo`), AKS (`managed-csi`) and OpenShift (`gp3-csi`) as one line each, so the fix names the class to select.

### M2. `k8s.nodes`: the example thresholds block the exact node class they were written for, and several node kinds are miscounted

Problems:
1. `per_node: {cpu: 8, memory: 32Gi}` is compared with `status.allocatable`. An 8 vCPU, 32 GiB node (EKS `m6i.2xlarge`) shows about 7.9 CPU and 29 GiB allocatable after kube-reserved, system-reserved and the eviction threshold. GKE and AKS reserve similar amounts. The 5% memory band in section 1 does not cover this, and no band exists for CPU. A healthy cluster would block.
2. Cordoned nodes (`spec.unschedulable`) are read but never excluded in the thresholds.
3. Windows nodes are not excluded by default. Add a default selector `kubernetes.io/os: linux`.
4. Nodes that cannot run the product are counted: EKS Fargate (`eks.amazonaws.com/compute-type: fargate`, no DaemonSets, no hostPath, no privileged), AKS virtual nodes (virtual-kubelet taint), GKE Autopilot managed nodes.
5. Autoscaled clusters (Karpenter, Cluster Autoscaler at zero, EKS Auto Mode, Autopilot) have fewer nodes than they can have. `min_ready: 3` would block a cluster that scales up on demand.
6. When the Pod list is forbidden the catalog "compares allocatable only". A pass on allocatable overstates free capacity. The `free` threshold must become "not evaluated", never pass.
7. The 5000 object cap on the Pod list silently breaks the free-capacity sum on a big cluster. A capped list must mark the free-capacity part as not evaluated.
8. The most common node-level install failure on EKS is the pod-count limit (`status.allocatable.pods`, for example 17 on a `t3.medium`). It is read but has no threshold.
9. The Node list is cluster-scoped and often forbidden for namespace-level identities. The default must be `partial: needs list nodes`, never a block.

Fix: replace the threshold sentence with:

> Spec values are allocatable, not instance size. The report prints capacity and allocatable side by side. An 8 vCPU, 32 GiB instance shows about 7.9 CPU and 29 GiB allocatable, so write `cpu: 7`, `memory: 28Gi`. Counted nodes: `Ready`, not cordoned, `kubernetes.io/os=linux` by default, not Fargate or virtual, matching `selector`, and either untainted (NoSchedule and NoExecute only; `PreferNoSchedule` does not exclude) or tolerated by `tolerations`. Add `free.pods` and `per_node.pods`. If a node autoscaler is detected (Karpenter `karpenter.sh` or `karpenter.k8s.aws` discovery, a `cluster-autoscaler` Deployment, EKS Auto Mode or Autopilot node labels), a node-count shortfall is a warn "capacity may scale, not verified", not a block. Pod list forbidden or capped: `free` is not evaluated.

Free CPU is allocatable minus pod requests. Use the effective request: max of init containers and the sum of app containers, plus restartable (sidecar) init containers and `spec.overhead`. List pods with `fieldSelector=status.phase!=Succeeded,status.phase!=Failed` so terminal pods never count. Over the cap, query per matching node with `spec.nodeName=<node>`.

Fixtures: add quantity forms (`7910m`, `Ki` memory values, plain bytes for `ephemeral-storage`, `hugepages-2Mi`) and an autoscaled single-node case.

### M3. `k8s.admission` fix text is factually wrong

The fix says "the product needs `baseline` (hostPath volumes)". The Baseline Pod Security Standard forbids hostPath volumes, hostPorts, hostNetwork, hostPID and hostIPC. A product that needs hostPath needs `privileged`. As written the customer would label the namespace `baseline`, rerun, and still fail.

Replacement:

> Namespace `{ns}` enforces `{have}`. The product needs `{need}` because it uses `{feature}` (hostPath volumes, host networking and privileged containers all need `privileged`). Either set the level: `kubectl label ns {ns} pod-security.kubernetes.io/enforce={need} --overwrite`, or ask the vendor for chart values that fit `{have}`.

Better: spec `needs_pod_security` should accept the reason (`uses: [hostPath, hostNetwork, privileged, runAsRoot]`) and the check derives the minimum level from a three-row table. That removes the class of mistake. Keep the plain level field as a shortcut.

### M4. Dry-run: safe only if restricted, and the ADR guard test must change

The default-off decision is correct and I agree with it. Keep the two keys (spec `dry_run: true` plus a CLI flag). What is missing:

1. Restrict the probe to core `v1` `Pod` in the target namespace. Parse it into a typed `Pod` and reject any other kind. Reason: an aggregated API server that does not honour `dryRun` would persist the object. The built-in API server honours it for core kinds. Add an assertion in the guard test (ADR 0010 ticket) that the only non-GET calls are the review kinds and (with the flag) one `POST /api/v1/namespaces/{ns}/pods?dryRun=All`.
2. Before the call, run an access review for `create pods` in the namespace. If denied, report "dry-run not evaluated: cannot create pods in `{ns}`".
3. A webhook with `sideEffects: Unknown` or `Some` makes the API server reject dry-run requests ("does not support dry run"). That is not a product denial. Classify that status text as `inconclusive: webhook {name} does not support dry-run`, not a block.
4. The namespace must exist, otherwise the result is `NotFound`. Report "namespace does not exist, cluster default PSA not evaluated".
5. The probe runs as the install identity. SCC and some policy-engine rules (Kyverno `exclude` by user, Gatekeeper exclusions) depend on who asks. A cluster-admin passes SCC admission for any SCC because it holds `use` on all of them, while the real workload runs as its own service account. A pass must carry the note: "admitted as `{user}`; workload will run as `{sa}`; SCC and user-based policy exclusions may differ".
6. Value statement for the docs: this is the only way to see the cluster-wide PSA default (set in the API server `AdmissionConfiguration`, unreadable) and the only way to see real ResourceQuota and LimitRange effects without creating anything. That is the argument for the flag.
7. The probe uses `generateName: rdy-probe-`. Never a fixed name.

### M5. `k8s.access`: `/version` does not prove authentication, and the most common failures have no fix text

1. `/version`, `/api` and `/readyz` are open to `system:unauthenticated` through `system:public-info-viewer`. With an empty or anonymous kubeconfig these calls succeed. ADR 0010 meets the `KubeContext` need on "`/version` answers". The check can report "auth works" for `system:anonymous`. Fix: after `/version`, call `SelfSubjectReview` (1.28 and later; `v1beta1` on 1.27; on older servers fall back to one cheap `SelfSubjectAccessReview`). Warn when the user is `system:anonymous`. Print user and groups.
2. Credential expiry "under 7 days: warn" is wrong for exec plugins. `aws eks get-token`, `gke-gcloud-auth-plugin` and `kubelogin` tokens live minutes to an hour. Every cloud cluster would warn. Fix: read expiry only for static JWT tokens and client certificates. For exec plugins record "short-lived, refreshed by `{binary}`" with no expiry warning. Skip for in-cluster tokens.
3. Exec plugins can prompt (`kubelogin` device code, `az login`, OIDC browser flow). With no TTY the 10s timeout fires while the child may live on. Fix: kill the child on timeout, and report "credential plugin `{binary}` needs an interactive login. Run `kubectl get ns` once, or `{login_cmd}`, then rerun." Classify plugin exit errors (expired AWS SSO: `aws sso login --profile {p}`).
4. The Fix text covers `x509` and `Unauthorized` only. Add the common ones:
   - Connection timeout or refused (private or IP-restricted API endpoint): "No reply from `{server}`. The API endpoint is private or limited to allowed networks. EKS: check `endpointPublicAccess` and `publicAccessCidrs`. GKE: master authorized networks. AKS: `--api-server-authorized-ip-ranges`. Run from a host inside the network."
   - EKS `Unauthorized` after a good `aws eks get-token`: "The IAM principal is not mapped. Add an access entry: `aws eks create-access-entry --cluster-name {c} --principal-arn {arn}` then `aws eks associate-access-policy ...`, or edit `aws-auth` on older clusters. Only the cluster creator is admin by default."
   - GKE needs a location: `gcloud container clusters get-credentials {cluster} --location {loc}`, and `gke-gcloud-auth-plugin` on `PATH`.
   - AKS with Entra ID: `az aks get-credentials -g {rg} -n {cluster}`, then `kubelogin convert-kubeconfig -l azurecli`.
   - OpenShift: `oc login {server}`.
   - k3s and RKE2 on the same host: the kubeconfig is root-only at `/etc/rancher/k3s/k3s.yaml` or `/etc/rancher/rke2/rke2.yaml`. Copy it to `~/.kube/config` (`sudo cat ... > ~/.kube/config`, then `chmod 600`) instead of running `rdy` as root.
5. The x509 text quotes a Go error. `rdy` uses rustls, so the user sees `invalid peer certificate: UnknownIssuer`. Quote what `rdy` really prints and keep the Go text as a second line so a search still finds it.

### M6. kube-rs does not read `HTTPS_PROXY`, so `rdy` and `kubectl` can disagree about the API server

Section 4 says `HTTPS_PROXY`/`NO_PROXY` handling "is reported". `kube` takes a proxy only from the kubeconfig `proxy-url` field, and only with the proxy cargo feature on (docs.rs for `Config`: "Proxy support requires the `socks5` feature"; HTTP proxy has its own feature). It does not read the environment. `kubectl` does. A customer whose API endpoint is reachable only through a corporate proxy sees `kubectl` work and `rdy` time out. The plan says proxies are where most real POCs fail.

ADR 0010 allows only `client` and `rustls-tls`. Fix: in ADR 0010 add the proxy feature(s). In `k8s.access` resolve the proxy the way `net.proxy` does (kubeconfig `proxy-url` first, then `HTTPS_PROXY` with `NO_PROXY` applied to the API host) and set `Config.proxy_url`. Report which rule applied. Add fixtures: kubeconfig with `proxy-url`, and env-only proxy. Check the pinned `kube` version before the ticket starts, because feature names have changed across releases.

### M7. `k8s.rbac`: false blocks and an unsafe fix

1. "Any item denied: block" is wrong for the `escalate` and `bind` probes. Escalation prevention passes when the installer already holds every permission in the role it creates, even with no `escalate` verb. A denied `escalate` or `bind` is unproven, not a failure. Fix: denied `escalate`/`bind` is warn "cannot prove the identity may grant `{role}`; it passes if the identity already holds those rules". Block only when the spec supplies the granted rule set and the identity lacks one of them.
2. `SelfSubjectAccessReview` status has `allowed`, `denied` and `reason`. `allowed: false, denied: false` means no authorizer had an opinion, which is a plain no. `denied: true` is an explicit deny (a webhook authorizer, for example). Print which. `evaluationError` with `allowed: false` is "unknown", warn (the catalog has this, good).
3. The fix recommends `kubectl create clusterrolebinding acme-installer --clusterrole=cluster-admin --user={user}`. A vendor-neutral tool should not hand a security reviewer a cluster-admin one-liner, and `--user` is wrong for group-based or prefixed OIDC and EKS identities. Replace with:

> `{user}` (groups `{groups}`) cannot `{verb}` `{resource}` in `{ns}`. Ask the cluster admin to bind the vendor installer role to this identity: `kubectl apply -f {role_url}` and a binding for `{user}` or one of its groups. On a throwaway test cluster only, `cluster-admin` works.

4. Add non-resource URL items (`nonResourceAttributes`) to the item shape. Some installers need `/metrics` or `/healthz`.
5. Say in the report that each item is one audit-log entry (up to 100). The calls are read-only but visible.
6. The catalog calls the review POSTs "two" in the intro and uses three kinds. See M8.

### M8. Read-only guard list disagrees with ADR 0010, and the tier list disagrees with CLAUDE.md and the ADR

1. ADR 0010 decision 4 and its guard-test ticket allow GET plus "the two review kinds". The catalog adds `SelfSubjectRulesReview` and the optional dry-run POST. Pick one list and write it in both files. Recommended: an allow-list of three review kinds, plus the dry-run Pod create only when the flag is set, enforced by a test that runs the full fixture set both ways.
2. `CLAUDE.md` and ADR 0010 list admission and device plugins as part of the week-5 Kubernetes slice. The catalog makes both `M1-late` and adds five more checks (`namespace`, `ingress`, `crds`, `cni`, `dns`). Either update ADR 0010 "Context" to the catalog's split, or move admission's PSA and SCC-detection half into M1 (S1). Record the change under "Plan corrections found".

## Should fix

### S1. Ordering, M1 versus M1-late, and the cut order

- Rank by real install failures. My field order for customer-controlled clusters: access, storageclass, rbac, admission (PSA labels, OpenShift detection, policy engine presence), nodes, version, namespace, crds, ingress, cni, dns, device_plugins. The catalog puts `k8s.admission` at 4 but ships it late. Admission, mostly PSA and SCC, is the top or second cause of "chart installs, pods never start" on clusters the vendor does not control.
- Split `k8s.admission`: M1 gets the cheap half (Namespace label GET, discovery of `security.openshift.io`, `kyverno.io`, `templates.gatekeeper.sh`; about 1.5h). M1-late keeps webhooks and endpoint checks. This honours the ADR.
- The cut order in "Plan corrections found" is `k8s.nodes`, `k8s.rbac`. Do not cut `k8s.rbac`. It is the cheapest (3h) and the most vendor-specific check (can the install identity create CRDs, ClusterRoles, webhooks). Cut instead: the pod-requests half of `k8s.nodes` (needs a cluster-wide Pod list that is often forbidden anyway), then the kubelet-skew part of `k8s.version`. Keep `nodes` allocatable.
- `k8s.version` is cheap (2h) and its output (server minor, distribution) feeds other checks (default StorageClass behaviour differs before 1.26). Run it right after `access` even if the report order differs.
- The k8s hours (15h) leave out the two ADR 0010 tickets (kube client 3h, read-only guard 1h). The Kube mock harness is counted in plumbing. State the total (about 19h plus the harness) so the overrun warning in section 1 is honest.

### S2. `k8s.ingress`: ingress-nginx text, and class detection that false-blocks on GKE, OpenShift and k3s

- Replace the Thresholds example `class: nginx|any` with `controller: any` and the example `controller: k8s.io/ingress-nginx`. Match on `IngressClass.spec.controller`, not on the class name, which people rename.
- Add to Thresholds: an `IngressClass` whose controller is `k8s.io/ingress-nginx`: warn.

> Ingress NGINX (`k8s.io/ingress-nginx`) was retired upstream in March 2026. It still runs but gets no releases or security fixes. If the product needs an ingress controller, pick one your platform team supports (a Gateway API implementation, Traefik, or a cloud controller). Existing Ingress objects with `nginx` annotations do not carry over unchanged; the `ingress2gateway` tool helps convert them.

- "No IngressClass `{class}`: block" false-blocks. GKE built-in ingress works with no `IngressClass` object. OpenShift serves Ingress through the router and prefers `Route`. k3s ships Traefik with class `traefik` and `servicelb` for LoadBalancer Services. Some Ingresses carry only the old `kubernetes.io/ingress.class` annotation. Rule: on GKE or OpenShift, absence of an `IngressClass` is "not verified", not block. Add a spec option `route: true` for OpenShift (`route.openshift.io` discovery).
- Pending LoadBalancer: a Service has no "pending since" field. Use `metadata.creationTimestamp` older than 10 minutes with no `status.loadBalancer.ingress`, only in the target namespace (a cluster-wide Service list is usually forbidden, and bare-metal clusters have unrelated pending ones). A read-only check cannot prove a load balancer works. Say so: "load balancer not verified (no canary Service is created)". Detect the implementation from the cloud `providerID` prefix, MetalLB discovery, or k3s `servicelb`.
- Gateway API: read the CRD annotations `gateway.networking.k8s.io/bundle-version` and `gateway.networking.k8s.io/channel` (standard or experimental) when `get customresourcedefinitions` is allowed. Let the spec name the kinds and version it needs (`GatewayClass`, `Gateway`, `HTTPRoute`; `GRPCRoute` is v1 from bundle 1.1; `TLSRoute` is still experimental).

### S3. `k8s.version`: distribution detection and the version number that matters

- AKS has no suffix: `/version` returns plain `v1.29.4`. Detect from node `spec.providerID` prefixes (`aws://`, `gce://`, `azure://`) and labels (`kubernetes.azure.com/cluster`, `eks.amazonaws.com/nodegroup`, `cloud.google.com/gke-nodepool`). RKE2 shows `+rke2r1`. Vanilla and kind are plain.
- OpenShift: the vendor's minimum is an OpenShift version (4.14), the API server says Kubernetes 1.27. Read `config.openshift.io/v1` `ClusterVersion` `version` (`status.desired.version`) and add spec `openshift_min`. Without it, `min: "1.27"` is ambiguous.
- Kubelet skew: add "kubelet newer than the API server: warn, unsupported". The catalog covers only older.
- Fix text is EKS-only. Add GKE `gcloud container clusters upgrade {c} --master --cluster-version {v}` and AKS `az aks upgrade -g {rg} -n {c} --kubernetes-version {v}`; note EKS upgrades one minor at a time. Pick by detected distribution.
- Tell spec authors that removed beta APIs are the usual cause of a failed `apis` check (`flowcontrol.apiserver.k8s.io/v1beta3` removed in 1.32, `autoscaling/v2beta2` in 1.26, `policy/v1beta1` PodDisruptionBudget in 1.25).
- Kubelet skew needs the Node list. State that `k8s.version` degrades to "kubelet skew not evaluated" when `nodes` is forbidden, and that node data is fetched once (S6).

### S4. `k8s.dns`: breaks on OpenShift and GKE, and infers a loop it cannot see

- Selector: use label `k8s-app=kube-dns` on Deployments and DaemonSets, not the name `coredns`. RKE2 names it `rke2-coredns-rke2-coredns`. OpenShift runs a `dns-default` DaemonSet in `openshift-dns` and has no `kube-dns` Service. GKE runs `kube-dns` (not CoreDNS) with no `loop` plugin Corefile.
- "Node uses the 127.0.0.53 stub, so loop risk" cannot be read from the API. Kubelet commonly points CoreDNS pods at `/run/systemd/resolve/resolv.conf` already. Evidence available through the API: pod `CrashLoopBackOff`, `lastState.terminated`, and (if `pods/log` is allowed) a log tail with `plugin/loop: Loop ... detected`. Rewrite: loop is `block` when the log line is seen, or restarts are recent and the Corefile has `forward . /etc/resolv.conf`. Otherwise no loop verdict. Point to `net.dns` for the node file when `rdy` runs on a node.
- Restart count above 5 is lifetime. Use restarts with `lastState.terminated.finishedAt` in the last hour.
- Add spec `cluster_domain` (default `cluster.local`), read from the Corefile `kubernetes` plugin. Products often hardcode the domain.
- Say that in-cluster external resolution cannot be tested without a pod (see `k8s.egress_probe`).

### S5. `k8s.cni`: names miss several distros, and there is a cheaper signal

- Add `anetd` (GKE Dataplane V2, Cilium-based, enforces NetworkPolicy), `rke2-canal` and `canal` (flannel plus Calico, enforces), `rke2-calico`, `rke2-cilium`, `azure-npm`, `kube-router`, `kube-ovn-cni`, `openshift-sdn` (end of life). k3s embeds flannel in the k3s process and has no DaemonSet, so name matching reports "no CNI".
- Cheaper signal that needs only `list nodes`: `Node.status.conditions[NetworkUnavailable].reason` is `FlannelIsUp`, `CalicoIsUp`, `CiliumIsUp`, or `RouteCreated` (cloud routes). Plus CRD discovery: `crd.projectcalico.org`, `cilium.io`, `k8s.cni.cncf.io`. Use these first and DaemonSets second. A cluster-wide DaemonSet list is usually forbidden.
- Service CIDR: the `kubeadm-config` ConfigMap exists only on kubeadm clusters. Use `networking.k8s.io/v1` `ServiceCIDR` (GA in 1.33, beta before) when served, OpenShift `config.openshift.io/v1` `Network` (`status.clusterNetwork`, `serviceNetwork`), and `Node.spec.podCIDR` only where node IPAM allocates (not Calico `IPPool`, Cilium cluster-pool, or AWS VPC CNI).
- `aws-node`: VPC CNI enforces NetworkPolicy from add-on v1.14 when `ENABLE_NETWORK_POLICY=true`. Read that env from the DaemonSet instead of "depends on configuration".
- State what is not read: Calico `GlobalNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, `AdminNetworkPolicy`. A "no default-deny" pass says "namespace policies only".

### S6. One shared set of cluster facts, and a family-level `k8s:` block in the spec

- Nodes, version, discovery documents and the target `Namespace` are read by many checks (`version` for kubelet skew, `storageclass` for zones, `cni`, `device_plugins`, `admission`). Fetch them once into a cached `ClusterFacts` in the engine `Context`, record which list calls were forbidden, and let each check use that. Without it five checks list nodes five times and a 403 is reported five times. Add a ticket (1.5h) after the Kube mock harness.
- Add a family-level block so checks do not repeat fields:

```yaml
k8s:
  context_pattern: "^acme-prod-"
  namespace: acme-system
  service_account: acme-controller   # used in SCC and RBAC fix text
```

  `{sa}` appears in the OpenShift fix text but no spec field supplies it today. `context_pattern` also needs a `server_pattern` companion, because context names are arbitrary.
- CLI flag names differ: the catalog says `--context` and `--namespace`, ADR 0010 says `--kube-context`. Choose with cli-ux (`--context` matches `kubectl`).

### S7. Fixtures: add per-distro recordings, pagination, and one real-cluster test

- Add a distro set `tests/fixtures/k8s/distros/{eks,gke,aks,openshift,k3s,rke2,kind}/` with `version.json`, `nodes.json` (allocatable shapes, `providerID`, labels), `storageclasses.json`, `csidrivers.json`, `csinodes.json`, `ingressclasses.json`, and one `Namespace` with the distro's PSA labels. The current list covers version for EKS, GKE, k3s and vanilla only. The quirks in this review need these.
- The `tower` mock must model paging (`limit`, `continue`, `410 Gone` on an expired token), field and label selectors (or one recorded file per full query string) and discovery. Without paging, the 500 limit and 5000 cap are untested.
- Recording script: ship `scripts/record-k8s-fixture.sh` with a `jq` allow-list that drops `metadata.managedFields`, `kubectl.kubernetes.io/last-applied-configuration`, and node `status.images` (hundreds of KB, real image names). Rewrite `providerID`, instance ids, cluster ARNs and internal DNS names to synthetic acme values, keeping the shapes.
- Add one CI job against `kind` (ADR 0010 already asks for it for `k8s.version`) that also runs the SSAR and `SelfSubjectReview` round trips and a namespace with `pod-security.kubernetes.io/enforce=restricted`. The mock proves parsing. Only a real API server proves serialisation, `apiVersion` and review semantics. Run on the oldest and newest supported minors.
- Exit tests to add: SSAR `denied` versus plain not-allowed; EKS `gp2` with no CSI add-on gives block; k3s `local-path` gives pass with "driver not verified"; Fargate and Windows nodes excluded; cordoned node excluded; an anonymous kubeconfig gives a warn.

### S8. Air-gapped registry mirrors have no cluster-side check, and fix text assumes internet

- `net.registry` probes from the machine running `rdy`, not from the nodes (section 3 says so). Nothing in the k8s family covers images on the nodes. A cheap read-only addition, M2, in `k8s.namespace` or a new `k8s.images`: (a) OpenShift `ImageDigestMirrorSet`, `ImageTagMirrorSet` and the older `ImageContentSourcePolicy`, to tell the vendor whether tag pulls are mirrored (IDMS applies to digests only, ITMS to tags); (b) pull secret presence: `GET serviceaccounts/{sa}` in the target namespace for `imagePullSecrets` names, then `GET secrets/{name}` for type `kubernetes.io/dockerconfigjson` (never read values); (c) report that containerd `certs.d`, k3s and RKE2 `registries.yaml` are node files, which `host.container_runtime` reads when `rdy` runs on the node.
- Remediation text assumes public sources (`jetstack/cert-manager` in `k8s.crds`, `aws eks create-addon`). In an air-gapped site those fail. Make `k8s.crds` text:

> cert-manager CRDs are missing. Install the chart from your registry or mirror: `helm install cert-manager {chart_ref} -n cert-manager --create-namespace --set crds.enabled=true` (`crds.enabled` is for 1.15 and later; older charts use `installCRDs=true`). Public source: `helm repo add jetstack https://charts.jetstack.io`.

  The spec `fix` field already replaces built-in text. Document that an air-gapped spec should set `fix` or `{mirror}` for every install command.

### S9. `k8s.device_plugins` (gpu-expert reviews the NVIDIA labels; these are k8s points)

- MIG strategy: under `mixed`, MIG slices appear as `nvidia.com/mig-<profile>`. Under `single`, they appear as `nvidia.com/gpu`. The rule "product requests `nvidia.com/gpu` but MIG strategy exposes `nvidia.com/mig-*`: block" must apply only to `mixed`. Read `nvidia.com/mig.strategy` (`none`, `single`, `mixed`).
- "Any resource name containing `/`" misses `hugepages-*` (no slash, but listed in Measures) and `attachable-volumes-*` (per-node volume attach limit, a real storage failure on EBS). Add both.
- Free GPUs matter more than allocatable. Reuse the pod-requests sum from `k8s.nodes` for extended resources (requests equal limits) and add `min_free`.
- Distinguish "no GPU hardware" from "GPU but no plugin": NFD label `feature.node.kubernetes.io/pci-10de.present=true` (vendor 10de) works with no NVIDIA software installed. Add GKE (`cloud.google.com/gke-accelerator`) and AKS GPU pool hints as one line each.
- Taints: GPU pools are commonly tainted, and the product must tolerate them. The `ExtendedResourceToleration` admission plugin adds a toleration for a taint named after the requested extended resource, but only where it is enabled (GKE does; do not assume it elsewhere). `k8s.nodes` with no `tolerations` in the spec excludes tainted GPU nodes, so a GPU spec with no tolerations sees zero nodes. State this in the check text.
- "Labelled `gpu.present=true`, zero allocatable: block" can be transient when a node has just joined or the operator is rolling. Warn if the plugin pod is younger than 10 minutes.

### S10. `k8s.storageclass`: other points

- "More than one default: warn (behaviour differs by version)" should be exact. Before 1.26, creating a PVC with no class fails when there are two defaults. From 1.26 the newest default is used. Rule: block below 1.26, warn from 1.26.
- Add a read-only evidence source for broken provisioning that needs no canary: list `PersistentVolumeClaim` in the target namespace with `status.phase=Pending` older than 5 minutes and read their Event reasons (`ProvisioningFailed`, `WaitForFirstConsumer`). It catches the IAM-role and quota failures the static check cannot.
- The zonal warning needs the zone count from `nodes`; take it from `ClusterFacts` (S6). Absent zone labels (bare metal) mean "unknown", not one zone.
- Accept `ReadWriteOncePod` (GA in 1.29) in the access-mode list. Rename the spec field `needs` to `access_modes`, because `needs` already means privilege in the engine and in every "Needs:" bullet.
- `volume_mode` is in the spec fields but Thresholds never say how it is evaluated, and a class does not carry it. Drop it or say "not evaluated".

### S11. `k8s.admission`: details

- Webhook matching: "matches the namespace" must use `namespaceSelector` against the namespace's labels, `objectSelector`, `rules` (apiGroups, resources, operations including CREATE), `matchPolicy` and `matchConditions` (GA in 1.30). Non-empty `matchConditions`: "not evaluated, may exempt".
- `clientConfig.url` webhooks (external) have no Service. Report "external backend, not verified".
- EndpointSlice readiness: `endpoints[].conditions.ready` can be unset. By API contract unset means ready.
- A webhook Service in another namespace needs list rights there. If denied, partial.
- Kyverno: policies are `ClusterPolicy` (`kyverno.io/v1`, `validationFailureAction: Enforce`, or per-rule `failureAction`), and newer releases add `policies.kyverno.io` kinds (`ValidatingPolicy` and friends). Discover both. Gatekeeper: constraints live under `constraints.gatekeeper.sh/v1beta1/<Kind>`. Count only `enforcementAction: deny` (the default), not `warn` or `dryrun`.
- "Enforcing policy engine present, N policies, review" is not actionable. List names and the kinds and namespaces they match when readable, and point to the dry-run flag: "rerun with the admission dry-run flag to test the product's pod against these".
- Per-distro PSA text: OpenShift syncs `pod-security.kubernetes.io/*` labels from SCC annotations and SCCs are the real gate. RKE2 with the CIS profile enforces a cluster default of `restricted` from a node file with exemptions (`kube-system` and a few operator namespaces). Rancher applies a PSA configuration template per cluster. In all three the namespace labels do not show the default, so say "cluster default not readable".
- OpenShift SCC text: `restricted-v2` (4.11 and later) requires a UID inside the namespace range (annotation `openshift.io/sa.scc.uid-range`), drops all capabilities, forbids hostPath and host namespaces. The usual failure is an image or chart that pins `runAsUser`. First fix: remove `runAsUser` and let the range apply. Only then `oc adm policy add-scc-to-user {scc} -z {sa} -n {ns}` (the command itself is right).

### S12. `k8s.access`: kubeconfig details

- `Config::infer` tries kubeconfig first and falls back to in-cluster. Say so, and report which was used. Honour `KUBECONFIG` with several paths (the OS list separator, `;` on Windows).
- Rancher kubeconfigs point at the Rancher server (`https://rancher.example/k8s/clusters/c-xxxxx`, a path prefix on the URL) or at an authorized cluster endpoint. Add both as fixtures and test that the base path is kept.
- Report the server host with userinfo stripped, never the token. Keep a golden test.

### S13. `k8s.namespace`

- OpenShift: `create namespaces` is denied for normal users, `create projectrequests` (`project.openshift.io`) is allowed. Check that, and say `oc new-project {ns}`.
- Missing-namespace block text: "Ask the platform team to create `{ns}` and grant your identity admin in it." A namespace-level installer cannot create it.
- Quota scopes: a `ResourceQuota` with `scopeSelector` (PriorityClass, `NotTerminating`) applies only to matching pods. Evaluate unscoped quotas and list scoped ones as "not evaluated".
- A `LimitRange` default limit below the product's request is not a warn. A container whose request is above the defaulted limit fails admission. Block when the product sets requests without limits.
- Share the `Namespace` GET with `k8s.admission` (S6).

### S14. Result shape for "could not evaluate"

Section 1's `partial` mark is good. For k8s each result should list calls made, calls forbidden (verb, group, resource) and the grant that would complete it, in a fixed `not_evaluated: [{what, why, grant}]` array that the HTML report can render. Add to the Kube mock harness exit test: a run with an identity that can only `get namespaces` must produce a report where every check is `partial` or `skipped` and none is `block` on data it could not read.

### S15. Use SSAR before listing

Run one batch of read SSARs at the start (nodes, pods, storageclasses, csidrivers, csinodes, namespaces, webhook configs, CRDs). Then checks skip forbidden calls up front. This removes noisy 403s from the audit log and produces the exact "grant `list nodes`" text in one place. Fall back to the 403 `Status` message when the review itself is refused.

### S16. Exec plugin execution

ADR 0010 allows exec plugins with the user's environment. Add to the catalog: print the plugin command and arguments before running (the intro already says the report names the binary), refuse a plugin whose `command` is a relative path that is not on `PATH`, and put "this kubeconfig runs `{cmd}`" in the report header. A kubeconfig received from someone else is a code-execution vector, so the `--kubeconfig` help text should say so.

### S17. Thresholds and spec fields: sensible, with these edits

- `k8s.access`: `max_latency` has no default. Use warn above 2s round trip for `/version`.
- `k8s.nodes`: leave `min_zones` unset by default. Absent zone labels give "not evaluated". Kubernetes arch names are `amd64` and `arm64` while `host.cpu` uses `x86_64` and `aarch64`: accept both and normalise.
- `k8s.version`: `max_severity` is a good idea. Keep.
- `k8s.rbac`: 100 items max is fine. Add `as:` per spec (not only a CLI `--as`) so a vendor can test the workload identity (`system:serviceaccount:{ns}:{sa}`) when the user holds `impersonate`. Otherwise "not evaluated".
- `k8s.storageclass`: add `reclaim_policy: Retain|Delete` (warn on mismatch). Data stores on `Delete` are a known data-loss trap.
- 30s for list calls with `limit=500` is fine. Handle `410 Gone` (expired continue token) by restarting once, then mark partial.

## Nits

1. The section 4 intro says "GET and LIST only". LIST is a GET; say "GET (including list)".
2. `k8s.access` Measures lists `GET /api`. kube-rs `list_core_api_versions` calls `/api` and `list_api_groups` calls `/apis`. Name the discovery calls so the mock records the right paths.
3. Aggregated discovery (`apidiscovery.k8s.io`, GA in 1.30) is a different document, selected by Accept header. The client asks for the legacy document by default. Record the legacy one and say so.
4. `k8s.version` fix uses `{v}` for both "cluster is" and "target". Use `{have}` and `{need}`.
5. `k8s.ingress` Measures says "`GatewayClass` condition `Accepted`". Write the path `status.conditions[type=Accepted].status=True`.
6. `k8s.cni` should use the same pod restart evidence as `k8s.dns`. A crash-looping CNI pod shows up as NotReady nodes.
7. The section 4 intro names exec plugins `aws`, `gke-gcloud-auth-plugin`, `kubelogin`. Others are common (`aws-iam-authenticator`, `kubectl-oidc_login`, `tsh`). Write "for example".
8. The `k8s.dns` ticket exit test ("crash-looping CoreDNS with `forward . /etc/resolv.conf` blocks with the loop text") must match S4: it needs the log line or recent restart evidence.
9. The device plugin fix quotes `ds/nvidia-device-plugin-daemonset`. With the standalone Helm chart the name is `nvidia-device-plugin`. Use the discovered DaemonSet name in the text.

## Ticket and tier changes I recommend

- Add `[M1] Cluster facts cache (version, discovery, nodes, namespace) with forbidden-call record | est 1.5h`.
- Split `k8s.admission` into `[M1] k8s.admission PSA labels and engine/SCC discovery | est 1.5h` and keep the webhook half M1-late.
- `k8s.nodes` 4h to 5h (quantities, effective requests, paging, node-kind filters). `k8s.storageclass` 3h to 4h (CSINode, in-tree map, version rule). `k8s.access` 3h to 4h (anonymous detection, exec classes, proxy).
- Add `[M2] k8s.images: pull secrets and OpenShift mirror sets | est 3h`.
- Add `[M1] kind-based integration job with a PSA restricted namespace and review round trips | est 2h`.
- Update the ADR 0010 guard-test ticket to list the allowed POSTs exactly (M8).

## Plan corrections found

- `docs/adr/0010-kubernetes-client-kube-rs.md`, Decision 1: features `client` and `rustls-tls` only. `kube` reads a proxy only from the kubeconfig `proxy-url` and needs the proxy feature; it ignores `HTTPS_PROXY`. Fix: add the proxy feature and resolve env proxies in `rdy` (M6).
- `docs/adr/0010-kubernetes-client-kube-rs.md`, Decision 3: "`GET /version` answers" meets the `KubeContext` need. `/version` is open to anonymous callers. Fix: the need is met when `/version` answers; `k8s.access` then identifies the user with a review call and warns on `system:anonymous` (M5).
- `docs/adr/0010-kubernetes-client-kube-rs.md`, Decision 4 and the guard-test ticket: "the two review kinds". The catalog uses three plus an optional dry-run create. Fix: list them exactly (M8).
- `docs/adr/0010-kubernetes-client-kube-rs.md`, Context: admission and device plugins are in the week-5 slice; the catalog marks both M1-late. Fix: reconcile (M8, S1).
- `docs/plan/03-check-catalog.md`, "Plan corrections found", cut order `k8s.nodes`, `k8s.rbac`: protect `k8s.rbac`, cut the pod-requests half of `k8s.nodes` first (S1).
