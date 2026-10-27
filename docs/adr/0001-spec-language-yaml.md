# ADR 0001: Spec language is YAML, parsed with serde-saphyr

- Status: Accepted
- Date: 2026-10-27

## Context

Vendors write a readiness spec once and send it to many customers. The audience is sales engineers and
DevOps people who already write Kubernetes manifests, Helm values and existing preflight specs. The plan's
example spec is YAML with `apiVersion: rdy/v1` and `kind: Readiness`. The spec is untrusted input until
its signature checks out, and the parser runs as root on customer machines, so the parser must not panic,
must not use unsafe code we cannot audit, and must bound memory and time.

The plan names `serde_yaml`. Its author deprecated and archived it in March 2024 (last release
`0.9.34+deprecated`). The best-known successor, `serde_yml`, is archived and covered by RUSTSEC-2025-0068
(unsound `libyml`). `serde_yaml_ng` and `serde_norway` are maintained forks, but both still sit on
`unsafe-libyaml`, a machine translation of C libyaml with a large unsafe surface.

## Decision

1. The spec format is YAML 1.2, one document per file, file extension `.yaml` or `.yml`. JSON is valid
   YAML 1.2, so a `.json` spec parses with the same code path. We document YAML as the format.
2. The parser is `serde-saphyr` (pure Rust, no unsafe in the crate, fuzzed, designed to be panic-free,
   configurable budgets). It is used only inside `rdy_spec::parse`, never named in a public signature.
3. Parser limits, enforced before and during parsing: file size 1 MiB, nesting depth 64, alias count
   and alias expansion capped by a serde-saphyr `Budget`, one document only, duplicate keys rejected,
   merge keys (`<<`) rejected.
4. YAML 1.2 core schema only. `no`, `on`, `yes` are strings, not booleans. Typed serde structs do the
   rest: every field has a Rust type, so `"12.4"` and `12.4` both reach the `cuda` field as a string.
5. Signatures cover the raw file bytes (ADR 0002), so no YAML canonicalization is ever needed.

## Consequences

- Vendors copy and paste from the docs and from their Helm habits. Editors validate the file through
  the generated JSON schema (ADR 0012) with yaml-language-server.
- We depend on a younger, mostly single-maintainer crate. Mitigation: one call site, a proptest and
  fuzz suite on `rdy_spec::parse`, and `serde_yaml_ng` as the documented fallback (about one day to swap).
- `cargo deny` bans `serde_yaml`, `serde_yml` and `libyml` so they cannot come back as transitive deps.
- YAML errors must carry line and column. serde-saphyr reports locations; we wrap them in `SpecError`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| JSON only | No comments, noisy to hand-write. Vendors annotate thresholds with comments. Still accepted as a YAML subset. |
| TOML | Arrays of tables (`[[checks]]`) read badly for a list of 20 checks with nested params. Unfamiliar to the Kubernetes audience. |
| KCL or CUE | Real languages with evaluation. CUE has no Rust implementation; KCL's runtime is heavy. Evaluating code from a spec on a customer box is attack surface. Vendors can generate YAML from either tool. |
| `serde_yaml_ng` or `serde_norway` | Maintained, drop-in, but built on `unsafe-libyaml`. Kept as the fallback. |
| `serde_yml` | Archived, RUSTSEC-2025-0068. |
| `noyalib` | Pre-1.0 (0.0.x), very new, same author as the archived `serde_yml`. Revisit in a year. |

## Tickets implied

- [M1] Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a 2 MiB file, a billion-laughs file and a duplicate-key file each return a SpecError with line and column, never a panic.
- [M1] Property and fuzz tests for rdy_spec::parse | owner: qa-engineer | est: 3h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: proptest over 10k random inputs in CI finds no panic.
