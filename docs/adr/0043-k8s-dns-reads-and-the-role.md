# ADR 0043: `k8s.dns` reads the cluster DNS by label, the Corefile from one named ConfigMap, and the OpenShift namespace through a second role file

- Status: Accepted, security-reviewed (PR #62)
- Date: 2026-11-17

## Context

`k8s.dns` (03, M1-162) must find the cluster DNS in RKE2, OpenShift and GKE, where the name `coredns` is
wrong. It reads the Corefile for a root `forward . /etc/resolv.conf` and the cluster domain. The guard
had no shape for a named object inside a namespace, allowed a pod list only cluster wide, and the example
role had no read of `services` or `configmaps`. M1-161 showed that every new read must reach the guard
table, the example role, the kind job's grant list and its request count together.

## Decision

1. **Workloads are found by label.** Deployments by `k8s-app=kube-dns`, DaemonSets by
   `k8s-app in (kube-dns,node-local-dns)`, both in `kube-system`. When `kube-system` holds none, the
   DaemonSets in `openshift-dns` with the DNS operator's label. The OpenShift labels are unconfirmed
   against a live cluster, like the GPU labels of 03.
2. **Pods stay a cluster-wide list.** The guard allows a pod list only cluster wide with a `status.phase`
   selector, and the cluster role already grants it. `k8s.dns` adds a label selector and keeps the pods of
   `kube-system` or `openshift-dns`. No new pod grant, no new guard shape for pods. The pod list is skipped
   when no DNS workload was found, because there is nothing to explain.
3. **A new guard shape, `Access::GetIn { namespace, name }`.** One named object of one namespace, both
   fixed in the table. It carries exactly three entries: `services` `kube-dns` in `kube-system`,
   `services` `dns-default` in `openshift-dns`, and `configmaps` `coredns` in `kube-system`. A role can
   grant each with `resourceNames` in a `Role` of that namespace, so the grant is as narrow as the read.
4. **One ConfigMap, `get` only.** Only `kube-system/coredns`, and only its `Corefile` key is deserialized;
   every other key is dropped while parsing. A distribution that names the ConfigMap otherwise (RKE2) gets
   a note and no loop verdict. That is the safe side: no verdict is never a false block. A second name
   would be a second grant, so it needs its own decision. The Service has one such second name, because
   RKE2 names it after its Deployment: `rke2-coredns-rke2-coredns` is asked only when `kube-dns` is not
   there and the workload carries that name.
5. **Cut-down types for everything.** Pods, Deployments, DaemonSets and the ConfigMap are read into types
   that name the few fields used (02 Appendix B rule 6), so env values, args and pod specs never become
   strings in rdy.
6. **The OpenShift grants are a second file.** `examples/rbac/rdy-readonly-openshift-dns.yaml` holds the
   `openshift-dns` Role. The main file cannot hold it, because applying a Role into a namespace that does
   not exist fails the whole apply on every other cluster. The role test reads both files.

## Consequences

- `list daemonsets` and `list deployments` in `kube-system` let the token holder read every DaemonSet and
  Deployment spec there, env values included. rdy drops them while parsing, but the grant is the grant.
  The cluster-scope `list pods` has the same reach and is accepted. Both appear in `missing_grants` when
  absent, and the kube-system Role stays optional.
- The old Role `rdy-readonly-deployments` is orphaned by the rename and must be deleted by hand (the role
  file header and the changelog say how).
- The kube-system Role of the main file grows from one rule to three, and is renamed
  `rdy-readonly-kube-system`. It stays optional.
- The kind job grants and checks the same four rules, and runs `k8s.dns` as the read-only identity.
- RKE2's loop verdict waits for a decision on a second ConfigMap name.
