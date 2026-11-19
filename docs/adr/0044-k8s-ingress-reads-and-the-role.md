# ADR 0044: `k8s.ingress` reads classes, Gateway API classes and the Services of the target namespace, by three lists and no role of its own

- Status: Accepted, security-reviewed (PR #65)
- Date: 2026-11-17
- Amended at the catch-up of PR #65 (see Decision 2 and Consequences).

## Context

`k8s.ingress` (03, M1-163) needs the `IngressClass` list, the Gateway API classes and the LoadBalancer Services of
the target namespace. None of the three was on the guard's `ALLOWED` table or in the example role. M1-161 and
M1-162 showed that every new read must reach the guard table, the example role, the kind job's grant list and its
request count together.

## Decision

1. **Two new `ALLOWED` entries and one shared entry, all `list`.** `networking.k8s.io` `ingressclasses` and
   `gateway.networking.k8s.io` `gatewayclasses` (both cluster scope) are new. Core `services` in a namespace is
   already an entry (M1-160, M1-162). `k8s.ingress` joins it: the entry cites `k8s.admission`, `k8s.dns` and
   `k8s.ingress`, and keeps the three `GetIn` gets and the namespaced list. No watch, no write. The example
   cluster role gets a rule for each class list.
2. **Services only when the spec asks.** The Service list is sent only when `loadbalancer: true` and a family
   namespace is known. A cluster-wide Service list is never asked: the path is always one namespace's. The
   cluster role already grants `list services` (M1-160, for `k8s.admission`), so `k8s.ingress` needs no role
   of its own and the optional target-namespace template of the first draft is dropped. Without the grant the
   result is partial with `list services` in `missing_grants` and a `kubectl auth can-i list services -n <ns>`
   hint. Because the shared entry now serves a list that names no object, its field selector requirement is
   `NotRequired`: the `metadata.name` selector that `k8s.admission` sends is no longer enforced by the guard
   (the check still sends it). A Service carries a selector, ports and annotations that can hold sensitive
   configuration, so rdy drops all but four facts while parsing (decision 4).
3. **Discovery before the Gateway API.** `GET /apis` (open to every signed-in caller) tells whether the Gateway
   API group is served at `v1`. Only then is `GET /apis/gateway.networking.k8s.io/v1` and the `GatewayClass`
   list sent. On a cluster without the CRDs the check never asks for a list that would answer 404. The kind job
   still asks the list once, as the role holder, and tolerates only a 404, so a 403 proves the grant.
4. **Cut-down types, annotations never held.** Each object is read into a type that names its few fields. The
   metadata goes through a private struct of name, creation time and one annotation read by its exact key
   (`ingressclass.kubernetes.io/is-default-class`, kept as a flag). `last-applied-configuration` and every
   other annotation, a Service spec and its load balancer addresses (counted with `IgnoredAny`) never become
   strings. Tests hold a marker in annotations and check it appears nowhere.
5. **No CRD read.** The Gateway API CRD annotations (`bundle-version`, `channel`) need `get customresourcedefinitions`,
   a grant no other M1 check holds. M1 proves the API by its `v1` kinds in discovery. A later ticket can add the
   grant with its own decision.
6. **Unreadable is partial.** A refused list is `missing_grants` with the exact `kubectl auth can-i` command,
   never a block. A negative answer from a list that has a second page is "not verified".

## Consequences

- The role holder can read every Service of every namespace (spec, selector, ports, annotations), because the
  cluster role grants `list services` since M1-160. rdy drops all but four facts while parsing.
- The guard no longer requires a `metadata.name` selector on a Service list, and does not tie the namespace of
  the list to the spec's namespace. Pinning both per check is a follow-up ticket.
- Open question for a correction: whether two default classes should warn. 03 does not say, so they are a note.
- `services` is one table entry cited by three checks (the fold this ADR planned with `k8s.dns`).
- The kind job's request count goes from 12 to 15 reads. Its grant list gains the two cluster lists. The Service list needs no new grant.
- GKE and OpenShift are told apart by `-gke.` in the server version and by `route.openshift.io` (or the cluster
  facts), so a missing class or Gateway API there is "not verified". A heuristic that fails shows a block, which
  the spec's `severity` can lower.

## Tickets implied

- [M2] Pin the Service list namespace to the spec namespace, and keep the `metadata.name` selector for `k8s.admission`, in the guard | owner: rust-engineer | est: 2h | depends on: M1-163 | exit test: a Service list in any other namespace than the one the check was built with is refused by the guard, and a `k8s.admission` list without the selector is refused.
- [M2] Gateway API bundle version and channel from the CRD annotations | owner: check-author | est: 1.5h | depends on: M1-163 | exit test: a role with `get customresourcedefinitions` by name reads the two annotations, and a spec key names the bundle it needs.
