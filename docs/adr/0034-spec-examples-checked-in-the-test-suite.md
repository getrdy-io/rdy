# ADR 0034: Spec reference examples are validated by the test suite, not by the render

- Status: Accepted, architect-reviewed (PR #89). Narrows docs/plan/09-docs-site.md, section 5, for the examples only. Logged as PC-47 in docs/plan/13-plan-corrections.md.
- Date: 2026-10-29

## Context

docs/plan/09-docs-site.md says the spec reference renderer validates each example against its schema, then
shows it as YAML. M1-084 builds that. The validator is `jsonschema`, the one rdy-spec uses in its tests.

`jsonschema` as a normal dependency of `xtask` fails the license policy. Its dependency `borrow-or-share` is
MIT-0, and `deny.toml` does not allow MIT-0. cargo-deny leaves dev-dependencies out of the license check by
default (`licenses.include-dev` is false, and `deny.toml` does not change it). The first run on this branch
confirmed it: the crate fails as a normal dependency and passes as a dev dependency, which is why main passes.

## Decision

1. `jsonschema` is a dev-dependency of `xtask`. The license policy does not change.
2. The test `every_example_validates_under_its_node_and_decodes` in `crates/xtask/src/spec_reference.rs` runs
   in `cargo test --workspace`, which CI runs on every pull request. For each check example it:
   - validates the example against the schema node it sits under, which is `Check`, the object whose `allOf`
     names the variant;
   - writes the example as one check of a spec document, parses it with `rdy_spec::parse_unverified`, and
     checks that `decode_params` gives a typed variant.
3. The render still does the checks that need no validator. Each example reads back from its YAML as the
   same value, and a variant example must carry the value that selects its variant (for example `id`).
4. A missing description still fails `cargo xtask docs` and names the property path. A binary test,
   `crates/xtask/tests/cli.rs`, runs the xtask binary and expects exit 70 and that path.

## Alternatives considered

- **Allow MIT-0 in `deny.toml` for every crate.** Rejected. A license allow-list change needs its own review,
  and it would apply to every crate in the graph, not to this one.
- **A per-crate exception, `{ crate = "borrow-or-share", allow = ["MIT-0"] }`, as `deny.toml` already does for
  `winx`.** Not taken in M1-084. It is narrower than a global allow, and it is still a license decision for the
  release-engineer, who owns `deny.toml`. If the render must validate again, this is the first thing to try.
- **A hand-written validator in `xtask`.** Rejected. A second validator drifts from the one rdy-spec uses, so
  the check would test something other than what rdy reads.

## Consequences

- `cargo xtask docs` alone does not reject a bad example. A bad example fails `cargo test -p xtask` in the test
  job. A docs-only change must still pass that test.
- If the license policy allows MIT-0 for `borrow-or-share`, or the per-crate exception lands, the render can
  validate again, as 09 section 5 says. That is a move of one function and a policy review.

## Tickets implied

- Derive `JsonSchema` on the 17 check parameter types and delete `crates/rdy-spec/src/schema/check_params.json`,
  so the descriptions come from doc comments and the examples come from the types. It is filed as a backlog row
  in correction-14.
