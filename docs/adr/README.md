# Architecture decision records

One file per decision that someone could reasonably argue the other way. Numbered in order, never
renumbered. To change a decision, write a new ADR that supersedes the old one and set the old one's status
to `Superseded by NNNN`. Owner: rust-architect. Each ADR stays under one page.

## Index

| Number | Title | Status |
| --- | --- | --- |
| [0001](0001-spec-language-yaml.md) | Spec language is YAML, parsed with serde-saphyr | Accepted |
| [0002](0002-spec-signatures-ed25519-minisign.md) | Specs are signed with ed25519 in minisign format, verified before parsing, keys pinned per product | Accepted; decision 5 amended 2026-10-28 (declined `trust add` exits 64); decision 2 amended by 0018 (verifier crate) and 0022 (signing crate) |
| [0003](0003-report-format-html-json.md) | Reports are one JSON file plus one self-contained HTML file, rendered with askama | Accepted; decisions 1, 2 and 6 amended 2026-10-28 (ADR 0016 timing, banner first) |
| [0004](0004-async-runtime-tokio.md) | tokio multi-thread runtime, blocking work on spawn_blocking, every check under a timeout | Accepted; decision 5 tightened by 0014 |
| [0005](0005-plugin-model-custom-checks.md) | No plugins in M1; a sandboxed `custom.exec` check in M4; no dynamic loading or WASM in v1 | Accepted; amended 2026-10-28 (`custom.exec` in M4, not M3) |
| [0006](0006-static-musl-linux.md) | Linux binaries are static musl for x86_64 and aarch64, built on native runners | Accepted; decision 5 amended 2026-10-28 (`getent ahosts`, hickory as fallback) |
| [0007](0007-crate-publishing-and-versioning.md) | Crate publishing and versioning policy | Accepted |
| [0008](0008-errors-and-result-model.md) | Error handling and the result model; Timeout and Skipped are outcomes, never crashes | Accepted; decision 3 refined by 0013; decisions 4 and 7 amended 2026-10-28 (Ctrl-C, new codes, `report_write`) |
| [0009](0009-http-client-and-tls.md) | HTTP with reqwest on rustls and ring, a strict egress policy, dual roots only for the interception probe | Accepted; decisions 1, 2, 3 and 5 superseded by 0014 |
| [0010](0010-kubernetes-client-kube-rs.md) | Use kube-rs (client only) behind a runtime read-only guard, not raw REST or kubectl | Accepted; amended 2026-10-28 (selfsubjectreviews in M1, family-owned client) |
| [0011](0011-binary-name-and-cli-package.md) | The package is `rdy`, it lives in `crates/rdy-cli`, the binary is `rdy` | Accepted; decision 4 amended 2026-10-28 (in-process test entry point) |
| [0012](0012-wire-types-in-rdy-spec-schema-generated.md) | All `rdy/v1` wire types live in rdy-spec; JSON schemas are generated from them | Accepted; decision 5 amended 2026-10-28 (file names, M1-022; see 0019) |
| [0013](0013-verdict-refinements-not-run.md) | Verdict refinements: what counts as not run, and the one thing that never counts | Accepted |
| [0014](0014-probe-facade-owns-side-effects.md) | The probe facade owns every check side effect, including TCP, proxy CONNECT, TLS and HTTP | Accepted; decision 7 amended 2026-10-28 (MF-04: wall over std and kube plus the dependency allowlist) |
| [0015](0015-redactor-in-rdy-engine.md) | The minimal redactor lives in rdy-engine and runs on whole strings before any cap or write | Accepted (security-reviewer sign-off in PR #13, 2026-10-28); decision 10 added (span union, keyed tags, `Redacted<T>`, `ring`) |
| [0016](0016-output-dir-confinement-cap-std.md) | Output is confined to one new directory, opened early through a cap-std handle | Accepted |
| [0017](0017-changelog-fragments.md) | Changelog fragments: each PR adds one file in changelog.d/, and the release step assembles CHANGELOG.md | Accepted |
| [0018](0018-verify-minisign-envelope-with-strict-ed25519.md) | rdy-spec checks the minisign envelope itself, over strict ed25519 and BLAKE2b | Accepted |
| [0019](0019-schema-generation-derive-and-fragments.md) | Schemas are derived from the types where they are typed, and from fragments where they are not yet | Accepted |
| [0020](0020-dist-release-workflow-settings.md) | Releases are built by a generated and hardened dist workflow, published last, and gated by an artifact check | Accepted |
| [0021](0021-trust-store-file-rules.md) | Trust store file rules where the design is silent are the strict ones (user symlink and owner, Windows stays refused in M1, ADR 0027) | Accepted |
| [0022](0022-secret-key-file-and-signing-in-rdy-cli.md) | rdy writes minisign secret keys with scrypt at the stock cost, and signs in rdy-cli | Accepted, security-reviewed (PR #52) |
| [0023](0023-inherited-descriptors-detect-not-close.md) | Descriptors inherited by `rdy` are listed and reported in M1, not closed | Accepted, security-reviewed (PR #53) |
| [0024](0024-release-proofs-are-founder-hand-steps.md) | Release proofs that need the sandbox, an environment approval or a tag push are founder hand steps; agents build and test the repo side only | Accepted by the coordinator, founder ratification pending |
| [0025](0025-install-sh-core.md) | install.sh refuses a cut-off copy by an end marker, stops when it cannot check a signature, and trusts only what it has hashed | Accepted, security-reviewed (PR #65) |
| [0026](0026-checkmeta-in-checkinfo.md) | CheckMeta holds a check's title and remediation and lives in its static CheckInfo | Accepted |
| [0027](0027-windows-trust-stores-stay-refused-in-m1.md) | Windows trust stores stay refused in M1: reading a DACL needs FFI or unmaintained crates, and Windows has no user store | Accepted, security-reviewed and architect-reviewed (PR #68) |
| [0028](0028-command-table-and-fix-text-lists.md) | The command table is typed data in `rdy-engine`, and fix text is audited against two reviewed lists | Accepted, security-reviewed (PR #70) |
| [0033](0033-trust-add-key-argument-and-store-api.md) | `trust add` takes a key as a file or as text, refuses secret keys by form, and edits the store through `rdy-spec` | Accepted, security-reviewed (PR #77) |

Status values: `Proposed`, `Accepted`, `Superseded by NNNN`, `Rejected`. All twelve were revised on
2026-10-28 after the security-reviewer and cli-ux reviews in `docs/plan/reviews/`.

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

These were merged into `docs/plan/13-plan-corrections.md` and applied or closed there in M1-009 (2026-10-28).
They are kept as the record of what was found.

- docs/plan/rdy-plan.md, Rust build plan, crate table, `rdy-spec` row: names `serde_yaml`, deprecated and
  archived by its author in March 2024. Fix: replace with `serde-saphyr` (ADR 0001); ban `serde_yaml`
  and `serde_yml` (RUSTSEC-2025-0068) in deny.toml.
- docs/plan/rdy-plan.md, crate table, `rdy-spec` row: names `ed25519-dalek`. Fix: the scheme is still
  ed25519, in minisign format via `minisign-verify` and `minisign` (ADR 0002).
- docs/plan/rdy-plan.md, Release engineering: "Binaries and specs signed with Sigstore (cosign)"
  contradicts CLAUDE.md rule 3. Fix: "Binaries and checksums signed with Sigstore cosign; specs signed by
  the vendor's ed25519 key" (ADR 0002).
- CLAUDE.md, rule 3: "refuses unsigned or tampered specs unless `--allow-unsigned` is set" lets the flag
  run a spec whose signature fails. Fix: "refuses unsigned specs unless `--allow-unsigned` is set, and
  always refuses a spec whose signature fails" (ADR 0002 decision 7).
- docs/plan/rdy-plan.md, crate table, `rdy-checks-gpu` row: `nvml-wrapper` needs `dlopen`, which a
  static musl binary cannot do. Fix: `nvidia-smi` and `/proc/driver/nvidia` on Linux (ADR 0006).
- docs/plan/rdy-plan.md, Product definition, "Check families at launch": lists Custom (script check) and
  Data stores, but no milestone owns them. Fix: `custom.exec` in M4 (ADR 0005, amended 2026-10-28), data stores in M4.
- docs/plan/rdy-plan.md, crate table, `rdy-checks-net` row: "reqwest with rustls" is not enough since
  reqwest 0.13 defaults to `aws-lc-rs`. Fix: "reqwest with rustls on ring, no default features" (ADR 0009).
- CLAUDE.md, Commands: `cargo run -p rdy-cli` fails once the package is named `rdy`. Fix:
  `cargo run -p rdy -- run examples/specs/acme-platform.yaml --json` (ADR 0011).
- CLAUDE.md, Repo layout, `rdy-engine` line: "result model" lives in `rdy-engine`. Fix: wire types (spec
  and result) live in `rdy-spec`; `rdy-engine` runs checks and renders reports (ADR 0012).
- CLAUDE.md, Repo layout, `rdy-cli` command list `run, verify, bundle, upload, spec (init|sign|lint),
  report, version, self-update`: missing `spec keygen` and `trust add|list|remove`, and silent on
  milestones. Fix: M1 `run`, `verify`, `spec lint|sign|keygen`, `trust add|list|remove`, `version`;
  M2 `bundle`, `upload`, `report`; M3 `spec init`, `self-update` (cli-ux review).

## Review notes

Where I did not take a reviewer's fix exactly as written, and why. Everything else in both reviews was
applied.

- **cli-ux M3 (product slug `[a-z0-9][a-z0-9._-]{0,63}`).** I took security-reviewer's stricter
  `^[a-z0-9][a-z0-9-]{0,62}$` (ADR 0003). Dots invite `..` and extension tricks in file names, and
  underscores add nothing for a product id. cli-ux's intent (scriptable names, lint with line and
  column) is kept.
- **cli-ux S1 (exit 70 only if the fallback also fails).** Partly. The full terminal result always prints
  when the report directory is not writable, so the customer sees the verdict. The exit code is still
  70, because a script that asked for a report must know it did not get one. The fix hint names
  `--out-dir`.
- **security-reviewer SF-13 (Context holds four handles: exec, fs, net, kube).** Partly. `Context` holds
  `exec`, `fs` and the shared action log. The policy HTTP client and the guarded kube client are owned
  by their families (`NetFamily`, `K8sFamily`) and write to the same action log. Same mediation, but
  `rdy-engine` stays free of `reqwest` and `kube`, which `rdy-cloud` would otherwise pull in.
- **security-reviewer MF-07 option (a) (extend M1 by two weeks).** Not enough once the check catalog's
  core M1 tickets are counted. See the M1 calendar in docs/plan/00-overview.md: about 194 hours, a
  15-week recommendation, and a cut list.
- **Coordinator summary of cli-ux names** grouped `spec init` with the M1 commands. The cli-ux review
  marks it M3. I kept M3.
- **cli-ux N7.** Kept "not built yet" as the skip reason for the week-4 alpha only; from the first
  real checks the reason for an unknown id is "needs a newer rdy".

## Tickets implied

- [M1] Confirm revised ADRs close security findings MF-01 to MF-07 | owner: security-reviewer | est: 1h | depends on: none | exit test: each must-fix is marked closed or reopened in docs/plan/reviews/ before the first M1 code ticket.
- [M1] Confirm revised ADRs close cli-ux findings M1 to M3 and the final command names | owner: cli-ux | est: 1h | depends on: none | exit test: 07-cli-ux.md uses the verdict words, status words and commands from ADRs 0002, 0003 and 0008.
