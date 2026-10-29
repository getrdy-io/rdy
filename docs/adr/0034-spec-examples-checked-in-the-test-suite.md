# ADR 0034: Spec reference examples are validated by the test suite, not by the render

- Status: Accepted (2026-10-29, M1-084). Narrows docs/plan/09-docs-site.md, section 5, for the examples only.
- Date: 2026-10-29

## Context

docs/plan/09-docs-site.md says the spec reference renderer validates each example against its schema, then
shows it as YAML. M1-084 builds that. The validator is `jsonschema`, the one rdy-spec uses.

`jsonschema` is a normal dependency of `xtask` in that design. Its dependency `borrow-or-share` is MIT-0, and
`deny.toml` does not allow MIT-0. `cargo deny check` then fails for the first time on this branch. Main passes
because `jsonschema` reaches only the dev-dependencies there.

## Decision

1. `jsonschema` is a dev-dependency of `xtask`. The license policy does not change.
2. The test suite checks every example against the schema. The test
   `every_example_in_the_committed_schema_validates_with_the_rdy_spec_validator` runs in `cargo test --workspace`,
   which CI runs on every pull request.
3. The render still does the checks that need no validator. Each example reads back from its YAML as the same
   value, and a variant example must carry the value that selects its variant (for example `id`).
4. A missing description still fails `cargo xtask docs` and names the property path.

## Consequences

- `cargo xtask docs` alone does not reject a bad example. A bad example fails the test job. A docs-only
  change must still pass `cargo test -p xtask`.
- If the coordinator allows MIT-0 in `deny.toml`, the render can validate again, as 09 section 5 says. That is
  a one-line change to the policy and a move of one function. It is a license decision and needs its own review.
