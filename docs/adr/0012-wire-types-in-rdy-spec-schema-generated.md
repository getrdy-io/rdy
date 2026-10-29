# ADR 0012: All `rdy/v1` wire types live in rdy-spec; JSON schemas are generated from them

- Status: Accepted (revised 2026-10-28 after security-reviewer review)
- Date: 2026-10-27

## Context

There are two wire formats: the spec (vendor to customer) and the result (customer to vendor). CLAUDE.md
puts the result model in `rdy-engine`, which also holds the tokio scheduler and the HTML renderer. The
kickoff puts both JSON schema files under `crates/rdy-spec/schema/`. `rdy-cloud` must ingest results and
validate specs authored in the portal. A security reviewer's first questions about a result are "what
did it do" and "what spec ran, signed by whom", so the result must carry its own provenance.

## Decision

1. `rdy-spec` owns every `rdy/v1` wire type: `rdy_spec::spec` (the spec, including the typed parameters
   of every known check id) and `rdy_spec::result` (report, check results, statuses, verdict, error
   object). No async, no tokio, no I/O beyond the bytes it is handed and the trust store file.
2. **API shape follows ADR 0002.** `load()` (verify, then parse, then validate) is the only way to get a
   `LoadedSpec`; its constructor is private. `parse_unverified()` returns a plain `Spec` for `spec lint`,
   `--allow-unsigned` and portal authoring. No public function turns a `Spec` into a `LoadedSpec`.
3. **Provenance in every `Report`:** `spec: SpecRef { product, version, sha256 }`; `signature:
   SignatureState` (`Verified { key_id, product, signed_at }`, `Unsigned`, `Invalid { reason }`);
   `identity { euid, user, kube: { context, server, user } }`; `actions: Vec<Action>` listing every
   command, file read, endpoint and kube request with its outcome; `redactions: u32`; `complete: bool`.
4. `rdy-engine` produces `Report` values and renders them (JSON, HTML). It re-exports the result module.
   Its scheduler sits behind the default `runtime` feature; `rdy-cloud` can use
   `default-features = false, features = ["html"]`.
5. Rust types are the source of truth. `schemars` (1.x, JSON Schema 2020-12) derives the schemas.
   `cargo xtask schema` writes `crates/rdy-spec/schema/spec.v1.schema.json` and
   `result.v1.schema.json`, committed. CI regenerates them and fails on any diff. (Amended 2026-10-28,
   M1-022: the files are named as in 01-spec-format.md, which the docs site also uses. ADR 0019 says how
   the parts without a type yet are covered.)
6. Doc comments become schema descriptions, which feed the docs site reference pages.
7. The binary does not validate against the JSON schema at runtime. Typed parsing plus
   `rdy_spec::validate` (ids unique, thresholds parse, `metadata.product` slug rule) do it, with better
   errors.

## Consequences

- One crate, one semver line, one schema directory for the whole contract (ADR 0007).
- Adding a check id means adding its parameter type to `rdy-spec`: a wire format change, reviewed as one.
- `rdy-cloud` cannot accidentally treat an unverified spec as verified; the type system says which is which.
- The result grows by the action log; a typical run adds a few KB.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Result types in `rdy-engine` (as CLAUDE.md says) | `rdy-cloud` would depend on the scheduler; schema files would come from two crates. |
| A third crate `rdy-result` | More crates to publish for one founder. Revisit if `rdy-spec` gets heavy. |
| Public `parse()` returning a usable `Spec` for runs | Any caller could skip verification. |
| Hand-written schema, types generated from it (`typify`) | Awkward generated Rust; two sources to sync. |
| Validate with the `jsonschema` crate at runtime | Large dependency, worse errors than typed parsing. |

## Tickets implied

- [M1] Define public spec types in rdy-spec | owner: rust-engineer | est: 3h | depends on: Create workspace skeleton | exit test: the plan's example spec deserializes through parse_unverified into typed values, round-trips through serde_json, and no public path builds a LoadedSpec without load().
- [M1] Generate JSON schemas with schemars and check drift in CI | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: changing a doc comment without rerunning cargo xtask schema fails CI.
- [M1] SEC-17 Action log in the result via mediated Context handles | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture run's JSON lists every command, file read, endpoint and kube request the checks used, plus identity and the redaction count.
