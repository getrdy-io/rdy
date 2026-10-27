# ADR 0012: All `rdy/v1` wire types live in rdy-spec; JSON schemas are generated from them

- Status: Accepted
- Date: 2026-10-27

## Context

There are two wire formats: the spec (vendor to customer) and the result (customer to vendor). CLAUDE.md
puts the result model in `rdy-engine`, which also holds the tokio scheduler and the HTML renderer. The
kickoff puts both JSON schema files under `crates/rdy-spec/schema/`. `rdy-cloud` must ingest results and
validate specs authored in the portal. If the result types sit in `rdy-engine`, `rdy-cloud` pulls the
scheduler and every result change bumps a crate full of unrelated code. There is also a choice between a
hand-written schema and one generated from Rust types.

## Decision

1. `rdy-spec` owns every `rdy/v1` wire type: `rdy_spec::spec` (the spec, including the typed parameters
   of every known check id) and `rdy_spec::result` (the report, check results, statuses, verdict).
   `rdy-spec` has no async, no tokio, no I/O beyond reading bytes it is handed.
2. `rdy-engine` produces `rdy_spec::result::Report` values and renders them (JSON, HTML). It re-exports
   the result module so check authors only import one crate. Its scheduler sits behind the default
   `runtime` feature; `rdy-cloud` can use `default-features = false, features = ["html"]`.
3. Rust types are the source of truth. `schemars` (1.x, JSON Schema 2020-12) derives the schemas.
   `cargo xtask schema` writes `crates/rdy-spec/schema/rdy-v1-spec.schema.json` and
   `rdy-v1-result.schema.json`. The files are committed. CI regenerates them and fails on any diff.
4. Doc comments on the types become schema descriptions, which feed the docs site reference pages.
5. The binary does not validate against the JSON schema at runtime. serde types plus `rdy_spec::validate`
   (semantic rules: ids unique, thresholds parse, quantities in range) do it, with better errors.

## Consequences

- One crate, one semver line, one schema directory for the whole contract (ADR 0007).
- Adding a check id means adding its parameter type to `rdy-spec`. That is the right friction: it is a
  wire format change and gets reviewed as one.
- The JSON schema reads like serde's view of the types; we tune it with `#[schemars(..)]` attributes, and
  golden schema files make every change visible in review.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Result types in `rdy-engine` (as CLAUDE.md says) | `rdy-cloud` would depend on the scheduler; schema files would come from two crates. |
| A third crate `rdy-result` | More crates and versions to publish for one founder. Revisit only if `rdy-spec` gets heavy. |
| Hand-written JSON schema, types generated from it (`typify`) | Generated Rust is awkward to document and extend; two sources to keep in sync. |
| Hand-written schema and hand-written types | They drift. The docs promise they cannot. |
| Validate with the `jsonschema` crate at runtime | Large dependency, worse error messages than typed parsing. |

## Tickets implied

- [M1] Define public spec types in rdy-spec | owner: rust-engineer | est: 3h | depends on: Create workspace skeleton | exit test: the plan's example spec deserializes into typed values and round-trips through serde_json.
- [M1] Generate JSON schemas with schemars and check drift in CI | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: changing a doc comment without rerunning cargo xtask schema fails CI.
