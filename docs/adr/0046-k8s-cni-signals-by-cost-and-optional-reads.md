# ADR 0046: `k8s.cni` names the plugin from signals that need no grant first, reads DaemonSets only by name, and keeps every new grant in an optional file

- Status: Accepted, pending review (M1-165)
- Date: 2026-11-17

## Context

`k8s.cni` (03, M1-165) names the network plugin, says whether it enforces `NetworkPolicy`, finds
default-deny egress policies in the install namespace, and reads the pod and service ranges. 03 lists the
node condition, CRD discovery and DaemonSet names as sources, and says that a cluster-wide DaemonSet list
is usually forbidden. A DaemonSet holds env values and args, and the VPC CNI setting that decides
enforcement is an env value. The reviews of PR #62, #64 and #65 settled the rules for a new read: prefer no
grant, put a needed read in an optional namespaced Role with `resourceNames`, never list a namespaced
resource that holds secrets or env cluster wide, and cut every object down while parsing.

## Decision

1. **Signals that need no new grant come first.** The node list (already granted for `k8s.nodes`) gives the
   `NetworkUnavailable` reason (`FlannelIsUp`, `CalicoIsUp`, `CiliumIsUp`, `WeaveIsUp`), `spec.podCIDRs`
   and the kubelet version. `GET /apis` (discovery, no grant) gives the API groups. On OpenShift,
   `config.openshift.io/v1` `Network` `cluster` gives the network type and both ranges. `RouteCreated` is
   the cloud route controller and names no plugin.
2. **DaemonSets are read by name, and only when needed.** After steps 1 the check asks for DaemonSets only
   when no plugin was named, or the one named needs a DaemonSet setting (the VPC CNI). One `GET` per name
   and namespace pair of `data/cni.toml` (16 pairs: 14 in `kube-system`, `calico-system/calico-node`,
   `kube-flannel/kube-flannel-ds`; a namespace other than `kube-system` is read by `GET` first, through the
   existing `get namespaces` grant, and its pairs are skipped when it does not exist, because a refusal in
   a namespace that is missing is a grant nobody can give), the named family first, then the table order, stopping at the first that
   exists. A kubelet version hint (`-eks-`, `-gke.`, `+rke2`) only orders the reads. A refusal in a
   namespace skips the rest of it. At most 16 requests, inside the 20 s timeout. No DaemonSet list exists
   in the guard.
3. **OpenShift is named by the `Network` object, not by DaemonSets.** `OVNKubernetes` and `OpenShiftSDN`
   come from `status.networkType`. 03 listed `ovnkube-node` and `openshift-sdn` as DaemonSet names, which
   would need two more namespaces and grants for a fact the `Network` object already states.
4. **One new guard shape is reused, not invented.** `Access::GetIn { namespace, name }` is the same variant
   as PR #62's (ADR 0043). New entries: `daemonsets` (16 `GetIn` pairs), `configmaps` `kube-system/kubeadm-config`,
   `networkpolicies` (list in the target namespace), `servicecidrs` at `v1` and `v1beta1` (list),
   `config.openshift.io` `networks` (get `cluster`), and `k8s.cni` cited on `nodes`.
5. **No change to the main role file.** Every new grant is in `examples/rbac/rdy-readonly-cni.yaml`: a
   ClusterRole for the two cluster-scoped reads (`servicecidrs`, the OpenShift `Network`), a Role in each of
   `kube-system`, `calico-system` and `kube-flannel` with `resourceNames`, and a template Role for
   `networkpolicies` in the install namespace. Without the file the check still runs and every read it could
   not make is partial, with the grant named. The role test reads both files, `live_cluster` lists the new
   grants and counts the new reads, and the kind script applies the file (creating the two namespaces that
   kind lacks, and deleting only those).
6. **Cut-down types.** Node, DaemonSet, NetworkPolicy, ServiceCIDR, OpenShift `Network` and the
   `kubeadm-config` ConfigMap are read into private types. Metadata goes through a `{name, namespace}`
   struct, so annotations (and `last-applied-configuration`) and labels never become strings. The one env
   value kept is `ENABLE_NETWORK_POLICY`: the reader allocates a string only for a value of 8 bytes or less
   of a variable with that name. `kubeadm-config` keeps its `ClusterConfiguration` key only.
7. **Levels follow 03.** Blocks: `network_policy: enforced` with a plugin known not to enforce, and a pod or
   service range that overlaps `avoid_cidrs`. Warn: a default-deny egress policy while the spec lists
   `needs_egress`. Everything unreadable or unknown is partial with named grants, never a block.
8. **Builder decisions where 03 is silent or too coarse** (03 records them):
   - Flannel on k3s is partial, not a block. k3s runs its own network policy controller unless it was
     started with `--disable-network-policy`, which rdy cannot read. The cluster is k3s when a kubelet
     version has `+k3s`. Flannel on any other cluster is a block when enforcement is required.
   - Flannel with Calico is Canal, which enforces. Each table entry has a role: base (Flannel, the AWS VPC
     CNI, Azure CNI), policy (Calico, Cilium, the Azure network policy manager) or full. One policy plugin
     on top of base plugins is the policy plugin, like Canal. Anything else with two families, and no
     plugin, is partial.
   - The pod ranges are `Node.spec.podCIDRs` only for a plugin that uses node IPAM (`pod_cidr = "node"`),
     or the OpenShift `Network` object. For a plugin with its own pool, or an unknown plugin, `avoid_cidrs`
     is partial for the pod side.
   - The AWS VPC CNI enforces when `ENABLE_NETWORK_POLICY` is `true`, does not when it is `false`, and is
     partial when it is absent or unreadable.
   - A default-deny egress policy is 03's: it selects all pods, governs egress and has no rules. A policy
     that lists destinations is not one. A rule with no destination and no port in another policy that
     selects every pod lifts it. On a plugin that does not enforce, it is a note. Every result says that
     only namespace NetworkPolicy objects are read.
   - `cni.toml` entries carry `verified`. Only Flannel and the AWS VPC CNI were read from a page for this
     ticket; the rest are `verified = false` with no date. The AWS `ENABLE_NETWORK_POLICY` env on the
     `aws-node` container is the name 03 gives and is unverified against a live cluster: if it is wrong,
     EKS is partial, never a false block. `rke2-calico` is not an entry: RKE2 installs Calico through the
     Tigera operator (`calico-system/calico-node`).
   - A range from the server that is not a range (not the spec's grammar) is a note and is never compared.
9. **Deferred.** The restart evidence of crash-looping plugin pods (03 says it follows `k8s.dns`) is not
   read: it would add a pod read that is PR #62's. A ready-below-desired DaemonSet is not reported either.
   Both go to M2. The check is not built from `CheckParams` in the family yet (M1-175).

## Consequences

- A cluster whose plugin is named by node condition or API group (k3s, kubeadm Flannel, Calico, Cilium,
  Canal, RKE2, Weave, Antrea, OpenShift) needs no grant beyond the main file.
- EKS, GKE and AKS name their plugin from a DaemonSet, so they need the optional file to be fully judged.
  Without it the result says which grant to ask for.
- `cni.toml` entries are from the projects' public manifests and docs. The Flannel manifest and the AWS
  VPC CNI page were read for this ticket; the others are from the projects' documented names, and
  k8s-expert confirms each against a live cluster before the table is called checked.
- PR #62 adds the same `GetIn` variant and a `daemonsets` entry. The two `daemonsets` entries must be one
  when both merge, because the guard finds an entry by group, version and resource.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| List DaemonSets in `kube-system` and match names | A list returns every DaemonSet in full, env values included. |
| Add `daemonsets get`, `networkpolicies list` and `servicecidrs list` to the cluster role | The least-privilege rule of the PR #62, #64 and #65 reviews: a needed read is optional and narrow. |
| Read the CNI pods and their logs | The guard refuses `pods/log`, and pods are PR #62's read. |
| Block when the plugin is unknown and enforcement is required | 03 names no such block, and unreadable data is partial. |
