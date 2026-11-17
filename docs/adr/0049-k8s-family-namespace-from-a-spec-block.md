# ADR 0049: The Kubernetes family namespace comes from a spec `k8s:` block in M2, and `rdy run` gets no `--namespace`

- Status: Proposed. cli-ux and security-reviewer review it in M2-142, before the block is built
- Date: 2026-11-17

## Context

M1-175 builds every k8s check with a family namespace (`K8sFamily::with_namespace`). It is the target
namespace of the claim evidence of `k8s.storageclass`, the LoadBalancer Services of `k8s.ingress` and the
NetworkPolicies of `k8s.cni`, and the fallback of `k8s.admission` and `k8s.namespace` when their entry
names none. In M1 nothing sets it. rdy/v1 has no `k8s:` block: 03 section 4 sketched one, but 01 never
took it. 07 puts `--namespace` on `rdy bundle` only. The client never uses the kubeconfig's namespace
(ADR 0031 decision 12). So in M1 those reads never happen. k8s.storageclass leaves the claim evidence
out without a note; the others say what they did not read.

Two sources were proposed for M2: a spec key or a `rdy run` flag. Either one changes a contract: the
rdy/v1 spec schema, or the command surface.

## Decision

1. **M1 adds neither.** The family namespace stays empty. A check reads a namespace only when its own
   entry names one. 03 section 4 ("Not in M1") and 07 say so.
2. **M2-142 adds an optional top-level `k8s:` block with one key, `namespace`** (a Kubernetes name). It is
   an additive revision of rdy/v1 (01 section 3.2), with a revision line in `schema/README.md`. An unknown
   key inside the block exits 64, like one in `metadata` or `bundle`. An entry's own `namespace` still
   wins. 03's sketch shrinks to that key: `context_pattern` and `server_pattern` stay on `k8s.access`
   (01 section 2.7), and `service_account` is not planned.
3. **No `rdy run --namespace` in M2-142.** The namespace decides which objects the checks judge, so it
   belongs with the requirements the vendor signs. M2-126 pins the namespaced reads of the guard to the
   namespaces the spec names, and a flag would put unsigned input under that pin. 07 keeps `--namespace`
   on `rdy bundle`, where 04 already takes the union of it and the spec's namespaces.
4. **Never the kubeconfig's namespace.** ADR 0031 decision 12 stands.

## Consequences

- An older rdy (0.1.x) refuses a spec with the block: exit 64 with the upgrade hint (01 section 2.5).
  That is loud, never a silent pass.
- A customer who installs into a namespace the spec does not name needs a spec that names it: one the
  vendor signs again, or one the portal writes. If design partners hit this often, a later ticket adds
  `rdy run --namespace` as an override, with the header and `run.options` saying which source set it,
  after cli-ux and security review. That ticket supersedes decision 3.
- The no-namespace fixes of `k8s.admission` and `k8s.namespace` already name a real key, the entry's
  `namespace`. Only the `k8s.ingress` fix of PR #65 names the missing block, and the `k8s.cni` fix names
  no key. M2-142 makes both name the block.

## Alternatives

- **`rdy run --namespace` only.** It matches `kubectl` and the install-day choice. But the signed spec
  would not say what was judged, and M2-126's pin would rest on unsigned input.
- **A `namespace` key on the `k8s.storageclass`, `k8s.ingress` and `k8s.cni` entries.** An older rdy only
  skips those checks, which is gentler than exit 64. But the vendor repeats one value in up to five
  entries, which is what 03's block was meant to avoid, and the entries can disagree.
- **Both a key and a flag in M2-142.** Two sources and a precedence rule before anyone has asked for the
  override.

## Tickets implied

- [M2] M2-142: the spec `k8s:` block and its `namespace`, handed to the family by `rdy run` | owner:
  rust-engineer | est: 3h | depends on: M1-175, M1-161, M1-163, M1-165 | exit test: the row in
  docs/plan/11-backlog.md.
