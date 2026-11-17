# ADR 0044: `k8s.ingress` reads classes, Gateway API classes and namespace Services, and the example role grows by three lists

- Status: Accepted, security-reviewed and k8s-reviewed (PR pending)
- Date: 2026-11-17

## Context

`k8s.ingress` (03, M1-163) needs the `IngressClass` list, the Gateway API classes and the LoadBalancer Services of
the target namespace. None of the three was on the guard's `ALLOWED` table or in the example role. M1-161 and
M1-162 showed that every new read must reach the guard table, the example role, the kind job's grant list and its
request count together.

## Decision

1. **Three new `ALLOWED` entries, all `list`.** `networking.k8s.io` `ingressclasses` (cluster scope),
   `gateway.networking.k8s.io` `gatewayclasses` (cluster scope) and core `services` in a namespace. No get by
   name, no watch, no write. The example role gets one rule for each, and `services` joins the core list rule.
2. **Services only when the spec asks.** The Service list is sent only when `loadbalancer: true` and a family
   namespace is known. A cluster-wide Service list is never asked. The role grant is cluster wide, because
   the table's `ListInNamespace(Any)` shape is a `list` in any namespace (as for claims, quotas and limit
   ranges), and a `Service` holds no secret.
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

- The role holder can read every Service of every namespace (spec, selector, ports, annotations). rdy drops
  all but four facts while parsing. A cluster that wants less can bind the role per namespace.
- `services` is also read by `k8s.dns` (PR #62) by name in two namespaces. Whichever lands second folds the two
  table entries into one `services` entry that cites both checks and lists both access shapes.
- The kind job's request count goes from 12 to 15 reads. Its grant list gains the three lists.
- GKE and OpenShift are told apart by `-gke.` in the server version and by `route.openshift.io` (or the cluster
  facts), so a missing class or Gateway API there is "not verified". A heuristic that fails shows a block, which
  the spec's `severity` can lower.

## Tickets implied

- [M2] Gateway API bundle version and channel from the CRD annotations | owner: check-author | est: 1.5h | depends on: M1-163 | exit test: a role with `get customresourcedefinitions` by name reads the two annotations, and a spec key names the bundle it needs.
