# ADR 0038: k8s.rbac tests as the spec's `as:` service account above the guard, refuses a kubeconfig that already impersonates, and takes URL items

- Status: Accepted, security-reviewed (PR #135)
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

1. **The spec gains two things, both additive.** `k8s.rbac` takes `as` and URL items: a string
   `get /healthz` or an object `{verb, path}`. A path starts with `/`, may end in `*`, has 253 characters at
   most (the `*` counts) and has no `//` and no `..`. `rdy-spec` checks the shape, and `ImpersonateAs::new`
   applies the exact DNS-1123 rules at run time. 01, the JSON schema and the generated reference say so.
   The `namespace` of the entry stays what 01 says: it applies to string items only, and an object item
   names its own. A string item on a well-known cluster-scoped resource (`namespaces`, `nodes`,
   `clusterroles` and a short list of others) does not take it. To tell the two forms apart after parsing,
   `RbacRule` has a `from_text` flag.
2. **`as:` is a service account in M1.** The value is `system:serviceaccount:<namespace>:<name>` and nothing
   else. `rdy-spec` refuses any other value with the form to write, and `ImpersonateAs::new` refuses it
   again (defense in depth). Why:
   - For a service account the API server derives the groups (`system:serviceaccounts`,
     `system:serviceaccounts:<ns>` and `system:authenticated`). For a plain user it adds only
     `system:authenticated`, and the guard bans `Impersonate-Group`, so every grant that reaches the user
     through a group (OIDC, LDAP) would be missing and the check would report a false block.
   - A spec `as:` borrows the operator's `impersonate` right. Limiting it to service accounts and to the
     two read-only review calls keeps a vendor spec from using that right to list the rules of any person
     (05).
   - Groups can be added later (an `as_groups` key) when the guard learns to pass `Impersonate-Group`. That
     is a loosening, so it is additive.
3. **`SelfSubjectAccessReview` with `Impersonate-User`, not `SubjectAccessReview`.** A `SubjectAccessReview`
   takes a user and groups in its body, but creating one needs `create subjectaccessreviews`, which the
   default `system:basic-user` role does not give. An install identity rarely has it. A
   `SelfSubjectAccessReview` needs only `create selfsubjectaccessreviews`, which every authenticated user
   has, plus `impersonate` on the service account for the header. Impersonation also runs the real
   authorization path for the tested identity, groups included.
4. **The header is added by a thin service above the guard.** `AddImpersonation` wraps the guarded service,
   writes one `Impersonate-User` on the two access review POSTs and on nothing else, and replaces any value
   a caller set. A value that is not a valid header value is an error (`ImpersonationError::BadValue`), not
   a fallback value. The guard below it is built with `guarded_service_as`, so it passes exactly that value,
   once. `Connected::read_only_as` and the mock harness's `client_as` both call `ReadOnlyClient::over_as`,
   so a fixture run goes through the production order, and the proxy origin is recorded on those entries as
   on any other. `SelfSubjectReview` never carries the header: it shows who rdy really is.
5. **A spec `as:` is refused when the kubeconfig user sets any `as` field.** `as`, `as-uid`, `as-groups` and
   `as-user-extra` count, even when empty (kube sends the header for an empty `as`). `read_only_as` returns
   `ImpersonationError::Conflict` before it builds a client, the check ends with status `error` and a hint,
   and no request is sent. The alternative, stripping the kubeconfig's fields, would change who rdy is for
   every other call. `Cluster::read_only_as` has no default, so an implementor cannot answer with a refusal
   that blames the kubeconfig by mistake (M1-113 implements it on the lazy connection of M1-107).
6. **A kubeconfig `as` is visible in the result.** The run-level `GET /version` entry of the action log has
   `kubeconfig_impersonates: true` when the kubeconfig user sets any `as*` field, because kube then adds
   `Impersonate-*` to every request below the guard where the guard cannot see it. The cluster line on
   stderr says so too. The field is additive and holds no user name, so a reader of the log can tell "not
   impersonated" from "not said". A kubeconfig `as` without a spec `as:` stays the operator's choice (05).
7. **The question comes first, and it counts.** With `as:`, one review that is not impersonated asks whether
   the identity may `impersonate` the service account. If it may not, nothing is evaluated and the result is
   partial with that grant, never a block. A 403 on the first impersonated review reads the same way. The
   question counts toward the 100 reviews of a run: a spec with 100 items and an `as:` leaves the last item
   not asked, and the result says so. The note says that a cluster with constrained impersonation can grant
   `impersonate:user-info` or `impersonate-on:*` instead, which the check does not ask about.
8. **The log marks the call.** A `kube` entry of a call sent with `Impersonate-User` has
   `impersonated: true`, never the user name. The field is new in the result schema (additive). The mock
   audit requires that a recorded request with the header pairs with such an entry, and no other does.
9. **Escalate and bind are derived, not configured.** An item that creates, updates or patches roles or
   bindings in `rbac.authorization.k8s.io` adds the asks the server makes of the caller: `escalate` on the
   role, and `bind` on `clusterroles` (and on `roles` for a RoleBinding) in the binding's namespace, as the
   server asks it. They warn when denied. M1 has no key for the rule set a role grants, so the "block when
   the identity lacks a granted rule" case in 03 waits for one.

## Consequences

- A spec written for an older rdy with `as` in a `k8s.rbac` entry used to be refused as an unknown key and
  is now accepted. No released spec has it. An older rdy skips an entry with a URL item or `as` as
  `unsupported_spec`.
- A kubeconfig that impersonates cannot be used to test as another user. The hint says to use another
  kubeconfig or drop `as:`.
- A plain user cannot be tested as in M1. The error says to write a service account.
- The result schema, the spec schema and the generated references changed. Readers that ignore unknown
  keys are unaffected.
