# ADR 0038: k8s.rbac tests as the spec's `as:` user above the guard, refuses a kubeconfig that already impersonates, and takes URL items

- Status: Accepted, pending security review (the change touches headers and identities)
- Date: 2026-10-30

## Context

M1-111 builds `k8s.rbac`. Three things in the plan need a decision.

1. **The spec has no `as:` and no URL item.** 03 says `k8s.rbac` takes an `as:` user and items for URLs that
   are not resources (`/healthz`, `/metrics`). 01 lists only `can` (resource items) and `namespace`, and the
   spec crate refused `as` on purpose. The backlog row for M1-111 requires a spec `as:`.
2. **kube's `Api` cannot set a header, and kube adds its own.** The guard must see `Impersonate-User` to
   judge it, so the header has to be added above the guard. Below the guard, kube writes `Impersonate-User`
   and `Impersonate-Group` for a kubeconfig user that sets `as` or `as-groups`. If both sources wrote the
   header, the server would see two values (an HTTP proxy or a gateway may keep either).
3. **The log did not say a call was impersonated.** M1-104 left it to M1-111.

## Decision

1. **The spec gains two things, both additive.** `k8s.rbac` takes `as` (1 to 253 printable ASCII
   characters) and URL items: a string `get /healthz` or an object `{verb, path}`. A path starts with `/`,
   may end in `*`, and has no `//` and no `..`. `rdy-spec` checks the shape only. The check applies the
   stricter rules of `ImpersonateAs::new` (no space at either end, the exact form of a service account
   user), and a value that fails is a check error with the rule as the hint. 01, the JSON schema and the
   generated reference say so.
2. **The header is added by a thin service above the guard.** `AddImpersonation` wraps the guarded service,
   writes one `Impersonate-User` on the two access review POSTs and on nothing else, and replaces any value
   a caller set. The guard below it is built with `guarded_service_as`, so it passes exactly that value,
   once. `Connected::read_only_as` and the mock harness's `client_as` both call `ReadOnlyClient::over_as`,
   so a fixture run goes through the production order. `SelfSubjectReview` never carries the header: it
   shows who rdy really is.
3. **A spec `as:` is refused when the kubeconfig user sets any `as` field.** `as`, `as-uid`, `as-groups` and
   `as-user-extra` count, even when empty (kube sends the header for an empty `as`). `read_only_as` returns
   `ImpersonationConflict` before it builds a client, the check ends with status `error` and a hint, and no
   request is sent. The alternative, stripping the kubeconfig's fields, would change who rdy is for every
   other call. The cluster line says "the kubeconfig impersonates another user" so the operator sees it
   without a spec `as:`. A kubeconfig `as` without a spec `as:` stays the operator's choice (05).
4. **The question comes first.** With `as:`, one review that is not impersonated asks whether the identity
   may `impersonate` the service account (or the user). If it may not, nothing is evaluated and the result
   is partial with that grant, never a block.
5. **The log marks the call.** A `kube` entry of a call sent with `Impersonate-User` has
   `impersonated: true`, never the user name. The field is new in the result schema (additive). The mock
   audit requires that a recorded request with the header pairs with such an entry, and no other does.
6. **Escalate and bind are derived, not configured.** An item that creates, updates or patches roles or
   bindings in `rbac.authorization.k8s.io` adds the asks the server makes of the caller. They warn when
   denied. M1 has no key for the rule set a role grants, so the "block when the identity lacks a granted
   rule" case in 03 waits for one.

## Consequences

- A spec written for an older rdy with `as` in a `k8s.rbac` entry used to be refused as an unknown key and
  is now accepted. No released spec has it.
- A kubeconfig that impersonates cannot be used to test as another user. The hint says to use another
  kubeconfig or drop `as:`.
- The result schema, the spec schema and the generated references changed. Readers that ignore unknown
  keys are unaffected.
