# ADR 0010: Use kube-rs (client only) behind a runtime read-only guard, not raw REST or kubectl

- Status: Accepted (revised 2026-10-28 after security-reviewer review; amended 2026-10-28: `selfsubjectreviews` POST in M1, family-owned client, per the review of ADRs 0013 to 0016; decisions 1, 3, 4 and 7 refined by ADR 0031: the features (`ring`, `webpki-roots`), how the kubeconfig is read, the plugin exception (terminal use and environment), and errors that hold no plugin output)
- Date: 2026-10-27

## Context

M1 ships Kubernetes checks: server version, storage classes, RBAC for the install identity, admission
policies, node resources, device plugins. The plan says no kubectl dependency. The hard part is
connecting the way `kubectl` does: kubeconfig merging, contexts, client certs, tokens, exec credential
plugins, in-cluster config and custom CAs. The identity `rdy` uses is often cluster-admin, so a bug or a
future check could write to a production cluster unless something stops it at runtime.

## Decision

1. `kube` with default features off and only `client` and `rustls-tls`; no `runtime`, `derive` or `ws`.
   Types from `k8s-openapi` with the newest `v1_*` feature, set once in the workspace.
2. **Read-only guard.** A tower layer wraps the kube client and rejects, at runtime and failing closed,
   everything not on its allowlist (rules in 02-engine-design.md Appendix B): GET only on a const list
   of resources the M1 checks cite; no subresources, no `watch`, no dry run; any path naming `secrets`.
   POST only to `selfsubjectaccessreviews` and `selfsubjectrulesreviews` (`authorization.k8s.io/v1`),
   and to `selfsubjectreviews` (`authentication.k8s.io/v1`) with no query string and exactly the body
   `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`, compared byte for byte. No
   `v1beta1` or `v1alpha1`. From its response only `username` and `groups` are kept; `uid` and `extra`
   (which can carry cloud key ids and ARNs) are dropped. On clusters before 1.28 the report shows the
   kubeconfig user marked "not verified by the API server". `connect()` returns only the guarded type
   (`ReadOnlyClient`), and `K8sFamily` accepts only that type. ConfigMaps are listed metadata-only. A
   mock API server test that records every request is the second line of defence.
3. **Config sources.** Kubeconfig only from the default path, `KUBECONFIG` or `--kubeconfig`; in-cluster
   config when running in a pod. A context flag picks the context (name set by 07-cli-ux.md). Connect
   and read timeouts come from the check timeout. One client per run, owned by the k8s family, which
   builds it in its probe hook only when the run plan needs `kube_context`; `rdy-engine` has no kube
   dependency.
4. **Identity is visible.** Before the first request, and in the report: context, server URL and the
   authenticated user from `SelfSubjectReview` (decision 2). `insecure-skip-tls-verify: true` is
   reported as a warning.
5. The `KubeContext` need is met when config loads and `GET /version` answers. Otherwise every k8s check
   is `Skipped` with "no reachable cluster" and the fix hint.
6. RBAC uses `SelfSubjectAccessReview` per required verb and resource, never by reading Roles.
7. Exec credential plugins run with the user's environment, because that is what they need: the one
   exception to ADR 0004's cleared environment. Their output is never logged, at any level.

## Consequences

- Same auth behaviour as kubectl for the cases customers hit, with less security-sensitive code of ours.
- A future check or dependency upgrade cannot write to the cluster or read Secrets: the request never
  leaves the process.
- `kube` and `k8s-openapi` add compile time and about 2 to 4 MB. `k8s-openapi` bumps MSRV often; we
  update it on a schedule.
- Newer kinds (`ValidatingAdmissionPolicy`) go through API discovery first and skip when absent.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Raw REST with reqwest | Reimplementing kubeconfig, exec plugins and in-cluster auth is weeks of security-sensitive work. |
| Shell out to `kubectl` | Missing on many target boxes; the plan sells "no kubectl". |
| Read-only by test only | A test covers the paths it runs; a new check could still write with admin rights. |
| Ask customers for a read-only identity | Recommended (an example ClusterRole ships), but cannot be relied on. |

## Tickets implied

- [M1] Kube client from kubeconfig or in-cluster with rustls and timeouts | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: on a kind cluster in CI k8s.version passes and the context, server and user print before the first request; with no kubeconfig every k8s check is SKIP with the hint; exec plugin output never appears at RUST_LOG=trace; each 02 Appendix A kube entry, re-checked against the pinned kube version and used once in tests/lint-wall, fails clippy.
- [M1] Read-only guard layer and test for rdy-checks-k8s | owner: k8s-expert | est: 3h | depends on: Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: the runtime layer rejects any write, any POST other than the three reviews, a SelfSubjectReview with a different body or a query string, and any secrets path, and the mock API server records only allowed requests across the full k8s fixture run.
