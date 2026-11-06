# ADR 0042: The read guard admits a list of every resource in `constraints.gatekeeper.sh/v1beta1`

- Status: Proposed, for the security-reviewer (M1-160)
- Date: 2026-11-06

## Context

`k8s.admission` (M1-160) lists the engines' own policies. For Gatekeeper those are constraints. A
constraint kind is not fixed: each `ConstraintTemplate` creates a CRD in `constraints.gatekeeper.sh`,
named by the template author (`K8sRequiredLabels`, `K8sAllowedRepos`, or anything else). The guard's
table (`ALLOWED`) names one group, version and plural resource per entry, so it cannot list the kinds
ahead of time. The role in `examples/rbac/rdy-readonly.yaml` is tested to match the table, and that test
also forbids `*` in the role.

Three choices were open: skip constraints and only name the kinds (what M1-114 does), put a short list of
well-known constraint kinds in the table, or admit the whole group.

## Decision

1. **One entry with `resource: ANY_RESOURCE` (`"*"`) for `constraints.gatekeeper.sh/v1beta1`, list only.**
   The guard matches it for any resource name of that group and version. No get by name, no namespaced
   list, no other version, no subresource. The `secrets` rule runs before the table and still refuses a
   path with that segment.
2. **Why it is safe.** The group is created by Gatekeeper's `ConstraintTemplate` controller and holds
   constraints, which are policy objects (`match`, `enforcementAction`, `parameters`). It holds no Secret
   and no workload. The check keeps the name, kind, enforcement action and match fields, and drops
   `parameters`.
3. **The role grants the same.** `rdy-readonly.yaml` gets one rule with `resources: ["*"]` in the group
   `constraints.gatekeeper.sh`, verb `list`. The role test now allows `*` in exactly that rule and nowhere
   else, and it still equals the table.
4. **Bounds.** The check lists at most six constraint kinds (and eight policy lists in all), first page of
   500 each. Kinds come from discovery of the group, and a plural that is not shaped like one (lower case
   letters and digits, 63 at most) is never put in a path.

## Consequences

- A cluster whose Gatekeeper group has a hostile CRD can only make rdy list that CRD, once, read-only.
- The other direction was rejected: a fixed list would miss every custom template, which is most of them,
  and would say "no constraints" when there are some.
- If the security review wants the table stricter, the fallback is to drop the constraint lists and keep
  the kind names (the M1-114 behaviour). The check degrades without code changes elsewhere: the lists are
  one function.
