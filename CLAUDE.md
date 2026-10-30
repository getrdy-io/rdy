# CLAUDE.md for `rdy` (public repo)

This is the open-source half of Rdy: the `rdy` CLI, the spec and result formats, the check engine, the check
families, the bundle pipeline, the install script and the docs site. Apache-2.0.

## What Rdy is

Rdy is a vendor-neutral readiness and diagnostics tool for software that ships into customer-controlled
environments (on-prem, BYOC in the customer's cloud account, air-gapped sites, GPU clusters). The customer
runs one signed Rust binary (`rdy`). It checks their environment against the vendor's signed requirements
spec, scores readiness with remediation steps, writes HTML and JSON reports, and optionally builds a redacted
diagnostics bundle. The vendor's sales engineers and support team see results in a portal (Rdy Cloud) before
install day. Tagline under test: "Install day should be boring."

Phase one (Option A) sells to software vendors: VP Sales Engineering and Head of Support. Phase two
(Option B, working name Tower) flips the same agent around and sells enterprises a control tower over every
vendor data plane running in their cloud accounts. Full plan: `docs/plan/rdy-plan.md` (copied from the
product plan doc). Read it before planning anything.

## Non-negotiable product rules

1. Least privilege. Every check declares what it needs (root, kube context, cloud credentials). The CLI runs
   what it can and reports what it could not. It never asks for `sudo` up front.
2. Nothing leaves the machine by default. Upload is an explicit flag or an interactive prompt. Redaction runs
   before anything is written to disk.
3. Specs are signed by the vendor's key (ed25519). The CLI refuses unsigned specs unless
   `--allow-unsigned` is set, and says so loudly. It always refuses a spec whose signature fails, with or
   without the flag.
4. Offline first. Every command works with no network. The portal is additive.
5. One static binary, no runtime. musl on Linux, rustls everywhere, no OpenSSL.
6. The public crates (`rdy-spec`, `rdy-engine`) are the source of truth for the spec and result formats.
   `rdy-cloud` consumes them from crates.io, never by path.
7. The upload client and the HTML report renderer are open source so security reviewers can read exactly
   what leaves a customer's box.

## Names and places

- Product: Rdy. Command: `rdy`. Company entity: Apostolic Path LLC (Wisconsin).
- Site: getrdy.io. Install: in M1, the pinned release `install.sh`, then `"$HOME/.local/bin/rdy" run <spec>`. From M2,
  `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh` (root shells: `sh -s -- --allow-root`). Docs: docs.getrdy.io. Portal: app.getrdy.io.
- GitHub org: `getrdy-io`. Repos: `rdy` (public, Apache-2.0) and `rdy-cloud` (private).
- crates: `rdy`, `rdy-spec`, `rdy-engine`, `rdy-bundle`, `rdy-checks-host`, `rdy-checks-net`, `rdy-checks-k8s`, `rdy-checks-cloud`, `rdy-checks-gpu`.
- Do not use the old working name (dropped 2026-10-20 after a trademark search) anywhere in code, docs or copy.
- Do not name competitor companies or competitor products anywhere in this repo (code, docs, copy, examples, URLs). Describe them by category instead. Vendors Rdy builds on or checks (clouds, Kubernetes distros, NVIDIA, GitHub, Sigstore, Cloudflare, Stripe) may be named.

## Founder context

One founder, a senior sales engineer with a DevOps background, building part time (10 to 15 hours a week)
with an AI coding agent doing most of the typing. Optimize every plan for that: small vertical slices that
ship a usable binary every week, boring tooling, no speculative abstractions. Full-time is not assumed.

## How to work in this repo

- Plan before code. Big work starts as a design note in `docs/plan/` or an ADR in `docs/adr/`, reviewed by
  the relevant subagents, then built.
- Use the subagents in `.claude/agents/`. Each one is the top expert for its slice and runs on the cheapest
  model that does that job well. Delegate review to a subagent that did not write the code.
- Every PR: tests pass, `cargo clippy -- -D warnings` clean, `cargo fmt` clean, `cargo deny check` clean,
  docs updated, changelog fragment in `changelog.d/` (ADR 0017). Commit messages in imperative mood with a
  one-line summary.
- Never commit secrets, real customer data, or real spec files from design partners. Fixtures are synthetic.
- Short sentences in docs and UI copy. No corporate language. No em dashes.

## Repo layout (target)

```text
rdy/
  Cargo.toml              workspace; shared [workspace.dependencies] and lints
  rust-toolchain.toml     pinned stable
  deny.toml               cargo-deny policy (licenses, advisories, bans)
  dist-workspace.toml     dist release config
  .cargo/config.toml      per-target build settings
  CHANGELOG.md            assembled from changelog.d/ at each release (ADR 0017)
  RELEASING.md            release runbook
  crates/                 a crate enters the workspace when its milestone starts; crates.io placeholders hold the names
    rdy-spec/             schema (schemars), wire types for specs, results and the bundle manifest, YAML parsing, validation, ed25519 signatures, versioning
    rdy-engine/           check trait, scheduler, probe facade, privilege negotiation, redactor, HTML and JSON reports; custom.exec (M4)
    rdy-checks-host/      cpu, memory, disk, kernel, cgroups, time sync, ports, selinux/apparmor, AV agents; custom.file (M2)
    rdy-checks-net/       egress via proxy, DNS, TLS interception, MTU, bandwidth sample; data stores (M4, feature-gated)
    rdy-checks-k8s/       version, storage classes, RBAC for install identity, admission, node resources; device plugins and VRAM per node (M4)
    rdy-checks-cloud/     (M3) AWS first: IAM simulate, service quotas, regions, VPC/subnet capacity; GCP/Azure via REST later
    rdy-checks-gpu/       (M4) driver, CUDA, VRAM, model-download egress
    rdy-bundle/           (M2) collectors, tar+zstd, manifest; reuses rdy_engine::redact
    rdy-cli/              package and binary `rdy` (clap). M1: run, verify, spec (lint|sign|keygen), trust (add|list|remove), version. M2: bundle, upload, report, redact. M3: spec init, self-update, completion
  install.sh              served at getrdy.io/install; verifies checksum and cosign signature
  scripts/                verify-release.sh and other repo scripts
  changelog.d/            one changelog fragment per PR (ADR 0017)
  docs/                   M1: Markdown pages, reference pages generated from the JSON schema. M3: Astro Starlight site; only docs/src/content/docs/ is published
  docs/plan/              rdy-plan.md plus the plans this kickoff produces; never published
  docs/adr/               architecture decision records; never published
  examples/specs/         synthetic example specs
  tests/fixtures/         synthetic environments, recorded command output, golden reports
  .github/workflows/      ci.yml, release.yml (generated by dist), sign-release.yml, audit.yml; docs preview (M2) and docs-deploy.yml (M3)
```

## Engineering standards

- Rust stable, edition 2024, MSRV documented. `#![forbid(unsafe_code)]` in every crate except where an FFI
  crate needs it, and that crate documents each unsafe block.
- Errors: `thiserror` in libraries, `anyhow` only at the binary edge. Every user-facing error has a fix hint.
- Async: tokio, but checks that are naturally blocking run on `spawn_blocking`. No check may hang: every
  check has a timeout and reports `Timeout` as a result, not a crash.
- Output: human output to stderr with progress (indicatif), machine output to stdout as JSON when
  `--json`. Exit codes: 0 ready, 1 warnings only, 2 blockers, 64 usage, 70 internal. clap usage errors are mapped to
  64; `Parser::parse`, `Command::get_matches` and `Error::exit` are banned by clippy `disallowed-methods`,
  and a test runs `rdy --bogus`.
- Logging: `tracing`, `RUST_LOG` respected, never log secrets. Redaction is tested with golden files.
- Five release targets: Linux x86_64 and aarch64 (musl), macOS aarch64 and x86_64, Windows x86_64. Five CI
  legs, each running the full test job. If the Intel macOS image is retired, `x86_64-apple-darwin` is built on
  the arm64 runner and tested nightly (06). Every check compiles and runs on every target from day one; where
  a data source is not built yet, the check reports Skipped, not yet on this OS.
- Supply chain: `cargo-deny`, `cargo-audit`, `cargo-auditable`, SBOM via `cargo-cyclonedx`, releases via
  `dist` (`dist-workspace.toml`), signed with Sigstore cosign. Reproducible builds are a goal, document deviations.
- Tests: unit tests per crate, integration tests that run the binary against fixtures, golden-file tests
  for reports and redaction, property tests (proptest) for the spec parser. Coverage is tracked, not gated.
- Docs: every public item documented; `cargo doc` warnings are errors; the schema generates the spec
  reference page so docs can't drift. The docs.rs pages of `rdy-spec` and `rdy-engine` go live with their
  first crates.io release (M2), and the docs site links there.

## Commands

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check
cargo run -p rdy -- run examples/specs/acme-platform.yaml --allow-unsigned --json
```

## Subagents

See `.claude/agents/`. Summary: `rust-architect` owns structure and APIs; `rust-engineer` builds;
`check-author` writes check families with `k8s-expert`, `cloud-iam-expert` and `gpu-expert` as domain
reviewers; `security-reviewer` threat-models and reviews every change that touches privileges, network,
redaction or signing; `release-engineer` owns CI, signing and distribution; `qa-engineer` owns fixtures and
golden tests; `cli-ux` owns command surface and output; `docs-writer` owns docs.getrdy.io; `devrel` owns
README, examples and launch content; `code-reviewer` reviews every PR cold.
