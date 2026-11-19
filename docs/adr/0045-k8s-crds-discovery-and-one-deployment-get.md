# ADR 0045: `k8s.crds` reads definitions from API discovery and operators with one `get deployments` grant

- Status: Proposed, security-reviewed with fixes (PR #64)
- Date: 2026-11-17

## Context

`k8s.crds` (03, M1-164) asks whether each CRD the spec names is installed at the needed version, and whether
each operator runs at an acceptable version. 03 named two reads beyond discovery: the
`CustomResourceDefinition` object by name, for `Established` and the storage version "when allowed", and the
`Deployment` of each operator. A CRD object holds its whole `openAPIV3Schema` and can be megabytes. Prefer no
new grant (M1-161 and M1-162 each had to move the guard table, the example role and the kind job together).

## Decision

1. **Definitions come from discovery.** `GET /apis` gives the groups and their served versions. One
   `GET /apis/<group>/<version>` per distinct version lists the resources; a CRD is installed at that version
   when its plural is listed. The API server lists a CRD in discovery only once it is established, so this
   answers "installed and served" with no grant beyond the one every signed-in user has. A CRD that is still
   being installed, or whose names conflict, shows as missing, and a note says so on every result. The
   `Established` condition and the storage version are not shown. No spec key needs them.
2. **No CRD object is read.** So no schema, annotation or `last-applied-configuration` of a CRD is ever
   fetched, and no `customresourcedefinitions` entry joins the guard table.
3. **One new grant: `get` on `apps` `deployments` by name, in the namespace the spec names.** The operator
   lives in a namespace the spec chooses, so the guard shape is new: `Access::GetInNamespace(Only)`, a named
   object of a namespaced resource in the namespaces `Only` admits (any, for this entry). It is the one
   grant this ticket adds. It is not in the cluster role. `examples/rbac/rdy-readonly-operator.yaml` is an
   optional template: a `Role` and `RoleBinding` in the operator namespace with `resourceNames` of the one
   Deployment and `get` only, applied once per operator (like the optional `kube-system` Role). Without it the
   operator is partial with `get deployments.apps/<name> in <namespace>` and a `kubectl auth can-i` hint that
   names the object. A list of deployments outside `kube-system` stays refused.
4. **The Deployment is read through a private wire type.** It names the name, namespace, version label,
   `spec.replicas`, `status.readyReplicas` and the name and image of each container (at most 16), and
   nothing else. Environment values, arguments and annotations are skipped by serde while parsing, so they
   are never held. A test puts markers in the annotation, the environment and the arguments and proves none
   reaches the object or a result.
5. **A version is read from the image tag, else the label.** Two to four numbers and an optional suffix; a
   digest, `latest`, a date or a bare number is not a version, so it can never pass a minimum. A pre-release
   sorts below its release. An unreadable version is partial, never a block.
6. **Bounds.** At most 32 discovery documents and 16 Deployments (the spec caps operators at 16 and
   definitions at 64) in a run, each read once and dropped; a run that is out of time reports what it did
   not read. The M2-122 response cap is not built here.

## Consequences

- A token holder with the template applied can `get` the named Deployment, env values included. rdy drops
  them while parsing. The grant is one namespace and one name per operator, so it is narrower than the
  `kube-system` list of `k8s.nodes`, and the cluster role is unchanged.
- The deployment `get` appears in `missing_grants` as `get deployments.apps/<name> in <namespace>` when absent.
- "Installed" means "served". Aggregated APIs and built-in groups count (`pods.metrics.k8s.io` and
  `deployments.apps` pass), a CRD that is being deleted stays listed, and storage versions and deprecation are
  not visible. A fixture (`crd-aggregated`) documents it.
- A 404 on the Deployment is a warn that says the operator may be a StatefulSet or OLM-managed.
- If a vendor needs `Established` or the storage version later, that is a spec key and a new decision,
  with a `get customresourcedefinitions` grant of its own.
