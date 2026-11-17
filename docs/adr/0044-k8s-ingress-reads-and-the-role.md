# ADR 0044: `k8s.ingress` reads classes, Gateway API classes and namespace Services, by two lists and an optional namespace Role

- Status: Accepted, security-reviewed (PR #65)
- Date: 2026-11-17

## Context

`k8s.ingress` (03, M1-163) needs the `IngressClass` list, the Gateway API classes and the LoadBalancer Services of
the target namespace. None of the three was on the guard's `ALLOWED` table or in the example role. M1-161 and
M1-162 showed that every new read must reach the guard table, the example role, the kind job's grant list and its
request count together.

## Decision

1. **Three new `ALLOWED` entries, all `list`.** `networking.k8s.io` `ingressclasses` (cluster scope),
   `gateway.networking.k8s.io` `gatewayclasses` (cluster scope) and core `services` in a namespace. No get by
   name, no watch, no write. The example cluster role gets a rule for each class list. `services` is in the optional target-namespace Role.
2. **Services only when the spec asks, and only through a namespaced Role.** The Service list is sent only when
   `loadbalancer: true` and a family namespace is known. A cluster-wide Service list is never asked. The cluster
   role does not hold `services`. The grant is `examples/rbac/rdy-readonly-target-namespace.yaml`, an optional
   template with a `Role` and `RoleBinding` of the one install namespace (`list` only), applied with
   `sed -e 's/<target-namespace>/<ns>/g' ... | kubectl apply -f -`, like the other optional Roles. Without it the
   result is partial with `list services` in `missing_grants` and a `kubectl auth can-i list services -n <ns>`
   hint. A Service carries a selector, ports and annotations that can hold sensitive configuration, so the
   grant is as narrow as the read. The kind job renders the template for `default`.
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

- The Role holder can read every Service of the one namespace it is applied in (spec, selector, ports,
  annotations). rdy drops all but four facts while parsing. The cluster role reads no Service.
- The guard does not tie the namespace of the Service list to the spec's namespace: any namespace in the
  Role's reach is accepted. Pinning it is a follow-up ticket.
- Open question for a correction: whether two default classes should warn. 03 does not say, so they are a note.
- `services` is also read by `k8s.dns` (PR #62) by name in two namespaces. Whichever lands second folds the two
  table entries into one `services` entry that cites both checks and lists both access shapes.
- The kind job's request count goes from 12 to 15 reads. Its grant list gains the two cluster lists, and the Service list is a Role of `default`.
- GKE and OpenShift are told apart by `-gke.` in the server version and by `route.openshift.io` (or the cluster
  facts), so a missing class or Gateway API there is "not verified". A heuristic that fails shows a block, which
  the spec's `severity` can lower.

## Tickets implied

- [M2] Pin the Service list namespace to the spec namespace in the guard | owner: rust-engineer | est: 1.5h | depends on: M1-163 | exit test: a Service list in any other namespace than the one the check was built with is refused by the guard.
- [M2] Gateway API bundle version and channel from the CRD annotations | owner: check-author | est: 1.5h | depends on: M1-163 | exit test: a role with `get customresourcedefinitions` by name reads the two annotations, and a spec key names the bundle it needs.
