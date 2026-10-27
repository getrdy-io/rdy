# Architecture decision records

One file per decision that someone could reasonably argue the other way. Numbered in order, never
renumbered. To change a decision, write a new ADR that supersedes the old one and set the old one's status
to `Superseded by NNNN`. Owner: rust-architect. Each ADR stays under one page.

## Index

| Number | Title | Status |
| --- | --- | --- |
| [0001](0001-spec-language-yaml.md) | Spec language is YAML, parsed with serde-saphyr | Accepted |
| [0002](0002-spec-signatures-ed25519-minisign.md) | Specs are signed with ed25519 in minisign format, keys pinned per product | Accepted |
| [0003](0003-report-format-html-json.md) | Reports are one JSON file plus one self-contained HTML file, rendered with askama | Accepted |
| [0004](0004-async-runtime-tokio.md) | tokio multi-thread runtime, blocking work on spawn_blocking, every check under a timeout | Accepted |
| [0005](0005-plugin-model-custom-checks.md) | No plugins in M1; a sandboxed `custom.exec` check later; no dynamic loading or WASM in v1 | Accepted |
| [0006](0006-static-musl-linux.md) | Linux binaries are static musl for x86_64 and aarch64, built on native runners | Accepted |
| [0007](0007-crate-publishing-and-versioning.md) | Crate publishing and versioning policy | Accepted |
| [0008](0008-errors-and-result-model.md) | Error handling and the result model; Timeout and Skipped are outcomes, never crashes | Accepted |
| [0009](0009-http-client-and-tls.md) | HTTP with reqwest on rustls, ring as the only crypto provider, two root stores | Accepted |
| [0010](0010-kubernetes-client-kube-rs.md) | Use kube-rs (client only) for Kubernetes checks in M1, not raw REST or kubectl | Accepted |
| [0011](0011-binary-name-and-cli-package.md) | The package is `rdy`, it lives in `crates/rdy-cli`, the binary is `rdy` | Accepted |
| [0012](0012-wire-types-in-rdy-spec-schema-generated.md) | All `rdy/v1` wire types live in rdy-spec; JSON schemas are generated from them | Accepted |

Status values: `Proposed`, `Accepted`, `Superseded by NNNN`, `Rejected`.

## Template

Copy this into `NNNN-short-slug.md`.

```markdown
# ADR NNNN: <decision stated as a sentence>

- Status: Proposed
- Date: YYYY-MM-DD

## Context

What forces are at play. Facts, constraints, links to the plan or CLAUDE.md. No decision yet.

## Decision

What we will do, as numbered, testable statements.

## Consequences

What gets easier, what gets harder, what we now have to watch.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| ... | ... |

## Tickets implied

- [M1] <title> | owner: <agent> | est: <n>h | depends on: <ticket titles or none> | exit test: <one sentence>
```

## Plan corrections found

- docs/plan/rdy-plan.md, Rust build plan, crate table, `rdy-spec` row: names `serde_yaml`, deprecated and
  archived by its author in March 2024. Fix: replace with `serde-saphyr` (ADR 0001); ban `serde_yaml`
  and `serde_yml` (RUSTSEC-2025-0068) in deny.toml.
- docs/plan/rdy-plan.md, Rust build plan, crate table, `rdy-spec` row: names `ed25519-dalek`. Fix: the
  scheme is still ed25519, but in minisign format via `minisign-verify` and `minisign` (ADR 0002).
- docs/plan/rdy-plan.md, Release engineering: "Binaries and specs signed with Sigstore (cosign)"
  contradicts CLAUDE.md rule 3 (specs signed by the vendor's ed25519 key). Fix: "Binaries and checksums
  signed with Sigstore cosign; specs signed by the vendor's ed25519 key" (ADR 0002).
- docs/plan/rdy-plan.md, Rust build plan, crate table, `rdy-checks-gpu` row: `nvml-wrapper` loads
  `libnvidia-ml.so` with `dlopen`, which a static musl binary cannot do. Fix: `nvidia-smi` and
  `/proc/driver/nvidia` on Linux; drop `nvml-wrapper` (ADR 0006).
- docs/plan/rdy-plan.md, Product definition, "Check families at launch": lists Custom (script check) and
  Data stores, but no milestone owns them and M1 excludes them. Fix: `custom.exec` in M3 (ADR 0005),
  data stores in M4; say so in the milestone table.
- CLAUDE.md, Commands: `cargo run -p rdy-cli` fails once the package is named `rdy`. Fix:
  `cargo run -p rdy -- run examples/specs/acme-platform.yaml --json` (ADR 0011).
- CLAUDE.md, Repo layout, `rdy-engine` line: "result model" lives in `rdy-engine`. Fix: wire types
  (spec and result) live in `rdy-spec`; `rdy-engine` runs checks and renders reports (ADR 0012).
- docs/plan/rdy-plan.md, crate table, `rdy-checks-net` row: "reqwest with rustls" is not enough since
  reqwest 0.13 defaults to `aws-lc-rs`. Fix: "reqwest with rustls on ring, no default features" (ADR 0009).

## Tickets implied

- [M1] Review ADRs 0002, 0003, 0005 and 0008 for user-visible behaviour | owner: security-reviewer | est: 2h | depends on: none | exit test: each ADR has a review note and any requested change is merged before the first M1 code ticket that depends on it.
- [M1] Review ADRs 0002, 0003, 0008 and 0011 for command surface and output | owner: cli-ux | est: 2h | depends on: none | exit test: provisional command names in ADR 0002 are confirmed or replaced in 07-cli-ux.md.
