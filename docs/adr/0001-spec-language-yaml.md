# ADR 0001: Spec language is YAML, parsed with serde-saphyr

- Status: Accepted (revised 2026-10-28 after security-reviewer review)
- Date: 2026-10-27

## Context

Vendors write a readiness spec once and send it to many customers. The audience is sales engineers and
DevOps people who already write Kubernetes manifests and Helm values. The plan's example spec is YAML
with `apiVersion: rdy/v1` and `kind: Readiness`. The parser runs as root on customer machines. Since
ADR 0002 verifies the signature before parsing, partner runs parse only verified bytes, but `spec lint`,
`--allow-unsigned` and portal authoring still parse untrusted input. So the parser must not panic, must
bound memory and time, and must carry as little unsafe code as we can manage.

The plan names `serde_yaml`. Its author deprecated and archived it in March 2024 (last release
`0.9.34+deprecated`). The best-known successor, `serde_yml`, is archived and covered by RUSTSEC-2025-0068
(unsound `libyml`). `serde_yaml_ng` and `serde_norway` are maintained forks, but both still sit on
`unsafe-libyaml`, a machine translation of C libyaml with a large unsafe surface.

## Decision

1. The spec format is YAML 1.2, one document per file, extension `.yaml` or `.yml`. JSON is valid YAML
   1.2 and parses on the same path. We document YAML.
2. The parser is `serde-saphyr` (pure Rust, fuzzed, designed to be panic-free, configurable budgets). It
   is used only inside `rdy-spec` (ADR 0012), never named in a public signature.
3. Limits, enforced before and during parsing: file size 1 MiB, nesting depth 64, one document only,
   duplicate keys rejected, merge keys (`<<`) rejected, **anchors and aliases rejected** (alias limit
   zero, so any anchor or alias is an error with line and column). A spec never needs them. The budget
   stays on as a second limit.
4. YAML 1.2 core schema only: `no`, `on`, `yes` are strings. Version-like fields are typed as strings and
   must keep their text: `cuda: 12.10` reaches the field as `"12.10"`, never as the float `12.1`. A plain
   scalar that the parser has already resolved to a float is rejected for those fields, with a hint to
   quote it.
5. Signatures cover the raw file bytes (ADR 0002), so no YAML canonicalization is ever needed.
6. "No unsafe" is a claim from the crate's docs, not something we have checked. Before the parser ticket
   merges, `cargo geiger` (or a grep of the sources) runs over `serde-saphyr` and its parser crate, and
   the result is written into this ADR.

## Consequences

- Vendors copy and paste from the docs. Editors validate through the generated JSON schema (ADR 0012).
- We depend on a younger, mostly single-maintainer crate. Mitigation: one call site, proptest and fuzz
  over the parser, and `serde_yaml_ng` as the documented fallback (about one day to swap).
- `cargo deny` bans `serde_yaml`, `serde_yml` and `libyml`.
- YAML errors carry line and column, wrapped in `SpecError`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| JSON only | No comments, noisy to hand-write. Still accepted as a YAML subset. |
| TOML | Arrays of tables (`[[checks]]`) read badly for 20 checks with nested params. Unfamiliar to the Kubernetes audience. |
| KCL or CUE | Real languages with evaluation; evaluating spec code on a customer box is attack surface. Vendors can generate YAML from either. |
| `serde_yaml_ng` or `serde_norway` | Maintained, drop-in, but built on `unsafe-libyaml`. Kept as the fallback. |
| `serde_yml` | Archived, RUSTSEC-2025-0068. |
| `noyalib` | Pre-1.0 (0.0.x), very new. Revisit in a year. |
| Cap aliases instead of rejecting them | A cap limits the damage of a billion-laughs file; rejecting removes it. Specs gain nothing from aliases. |

## Tickets implied

- [M1] Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a 2 MiB file, an anchor or alias, a duplicate key and `cuda: 12.10` unquoted each give the documented SpecError with line and column, never a panic, and the geiger result is recorded in ADR 0001.
- [M1] Property and fuzz tests for rdy_spec::parse | owner: qa-engineer | est: 3h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: proptest over 10k random inputs in CI finds no panic.
