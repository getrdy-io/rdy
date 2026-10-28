# ADR 0007: Crate publishing and versioning policy

- Status: Accepted (revised 2026-10-28 after security-reviewer and cli-ux review)
- Date: 2026-10-27

## Context

`rdy-cloud` (private) consumes `rdy-spec` and `rdy-engine` from crates.io, never by path (CLAUDE.md
rule 6). A report produced offline on an air-gapped box years ago must still open in the portal. Three
version numbers are in play: the wire format (`apiVersion: rdy/v1`), each crate's semver, and the `rdy`
binary's version. Mixing them up is how compatibility promises break by accident.

## Decision

1. **Published crates.** All workspace crates are published, because `cargo install rdy` needs every
   dependency on crates.io. Only `rdy-spec` and `rdy-engine` carry a semver contract. The check crates
   and `rdy-bundle` say in their crate docs: "Internal to rdy. No API stability promise."
2. **Independent versions.** Each crate has its own version. Nothing needs crates.io until `rdy-cloud`
   starts in M2, so the first real publish (beyond the 0.0.1 placeholders) is M2. From then `release-plz`
   opens release PRs with per-crate bumps and changelogs, publishing through crates.io trusted publishing
   from a job with minimal `permissions` (no long-lived token). A `v*` tag on `rdy` triggers the binary
   release (release-engineer owns the pipeline).
3. **Semver in 0.x.** In `0.y.z`, a `y` bump is breaking, a `z` bump is compatible. From M2,
   `cargo-semver-checks` runs in CI on `rdy-spec` and `rdy-engine`. MSRV raises are a minor bump in 0.x.
4. **1.0.** `rdy-spec` and `rdy-engine` go 1.0 at the M3 public launch. After that a breaking change is a
   major bump and needs an ADR.
5. **Wire format versions are separate from crate versions.** `rdy/v1` names the spec schema, the result
   schema and the stable error `code` strings printed with `--json` (ADR 0008). Within `v1` only
   additive changes: new optional fields, new check ids, new enum values in results, new error codes. A
   removal, a rename or a changed meaning requires `rdy/v2`.
6. **Forward compatibility, with limits.** Public result enums are `#[non_exhaustive]`; the result
   schema says consumers must accept unknown enum values. Inside a check entry, an unknown check id or
   an unknown field makes that check `Skipped` with a reason that names the field (never silently
   ignored: dropping a stricter threshold would be a false pass). Unknown keys at the top level, in
   `metadata` or in `bundle`, and duplicate keys anywhere, exit 64: an unknown `upload:` or `exec:` block
   must fail, not degrade.
7. **Backward compatibility.** Every `rdy-engine` release can deserialize every `rdy/v1` result ever
   written. From the first crates.io release, golden result files from each released version are kept
   in `tests/fixtures/results/` and parsed in CI forever.
8. **Supporting `v2` later.** A `rdy` that knows `v2` keeps reading `v1` specs for at least 12 months.

## Consequences

- `rdy-cloud` can pin `rdy-spec = "0.3"` and move when it wants to.
- Contributors cannot break the contract without CI noticing, from M2 on. In M1 nothing is published,
  so there is nothing to break.
- A little release ceremony per crate; release-plz does the typing.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Lockstep versions for every crate | Every CLI-only change forces a contract-crate bump, which in 0.x is breaking for `rdy-cloud`. |
| Publish only rdy-spec and rdy-engine | Breaks `cargo install rdy`; packagers expect it. |
| Tie `apiVersion` to crate major | A Rust rename would force a wire format bump for no reason. |
| Lenient unknown fields | A newer spec's stricter threshold would be dropped and the check would pass. |
| Skip on unknown top-level keys too | A new security-relevant block would quietly do nothing on an old rdy. |

## Tickets implied

- [M2] cargo-semver-checks in CI for rdy-spec and rdy-engine | owner: release-engineer | est: 2h | depends on: none | exit test: a PR that removes a public field without a version bump fails CI.
- [M2] release-plz config with trusted publishing for per-crate versions and changelogs | owner: release-engineer | est: 3h | depends on: none | exit test: a dry run opens a release PR bumping only the crates that changed, and the publish job holds no crates.io token secret.
- [M2] Keep golden result files per released version and parse them in CI | owner: qa-engineer | est: 1h | depends on: none | exit test: CI deserializes every file under tests/fixtures/results/ with the current rdy-engine.
- [M3] Release rdy-spec and rdy-engine 1.0 | owner: rust-architect | est: 4h | depends on: none | exit test: 1.0 published and the cargo-semver-checks baseline moved to 1.0.
