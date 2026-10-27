# ADR 0010: Use kube-rs (client only) for Kubernetes checks in M1, not raw REST or kubectl

- Status: Accepted
- Date: 2026-10-27

## Context

M1 week 5 ships Kubernetes checks: server version, storage classes, RBAC for the install identity,
admission policies, node resources, device plugins. The plan says no kubectl dependency. The hard part is
not the REST calls; it is connecting the way `kubectl` does: kubeconfig merging, contexts, client certs,
bearer tokens, exec credential plugins (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`),
in-cluster service account config, and custom CAs.

## Decision

1. Depend on `kube` with default features off and only `client` and `rustls-tls`; no `runtime`, `derive`
   or `ws`. Types from `k8s-openapi` with the newest `v1_*` feature, set once in the workspace.
2. `rdy-checks-k8s` builds one client per run with `Config::infer()` (kubeconfig, then in-cluster), or the
   `--kube-context` flag. Connect and read timeouts are set from the check timeout. The client is shared
   by all k8s checks through the engine `Context`.
3. The `KubeContext` need is met when `Config::infer()` succeeds and `GET /version` answers. Otherwise
   every k8s check is `Skipped` with "no reachable cluster" and the fix hint.
4. RBAC uses `SelfSubjectAccessReview` per required verb and resource, never by reading Roles.
   Checks only read. The client never creates, patches or deletes any object; a unit test asserts the
   check crate never builds a non-GET request except the two review kinds, which are create-only
   subresources with no side effects.
5. Exec credential plugins run with the user's environment, because that is what they need. This is the
   one subprocess path that does not get the cleared environment of ADR 0004. Documented in the threat
   model.

## Consequences

- Same auth behaviour as kubectl for the cases customers hit. Less security-sensitive code of our own.
- `kube` and `k8s-openapi` add compile time and about 2 to 4 MB to the binary. Accepted.
- `k8s-openapi` releases often and bumps MSRV; we update it on a schedule, not on every release.
- Using one API version's types against older servers is fine for stable APIs; for newer kinds
  (`ValidatingAdmissionPolicy`) we use API discovery first and skip when the server lacks them.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Raw REST with reqwest | Reimplementing kubeconfig, exec plugins and in-cluster auth is weeks of security-sensitive work. |
| Shell out to `kubectl` | Not present on many target boxes, and the plan sells "no kubectl". Version skew in output. |
| `kube` with `runtime` | Watchers and controllers are not needed for one-shot reads. |

## Tickets implied

- [M1] Kube client from kubeconfig or in-cluster with rustls and timeouts | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: against a kind cluster in CI, k8s.version passes; with no kubeconfig every k8s check reports Skipped with the hint.
- [M1] Read-only guard test for rdy-checks-k8s | owner: k8s-expert | est: 1h | depends on: Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a mock API server records only GET and the two self-review POSTs across the full k8s fixture run.
