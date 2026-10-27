# ADR 0007: Crate publishing and versioning policy

- Status: Accepted
- Date: 2026-10-27

## Context

`rdy-cloud` (private) consumes `rdy-spec` and `rdy-engine` from crates.io, never by path (CLAUDE.md
rule 6). A report produced offline on an air-gapped box years ago must still open in the portal. There
are three version numbers in play: the wire format (`apiVersion: rdy/v1`), each crate's semver, and the
`rdy` binary's version. Mixing them up is how compatibility promises get broken by accident.

## Decision

1. **Published crates.** All workspace crates are published, because `cargo install rdy` needs every
   dependency on crates.io. Only `rdy-spec` and `rdy-engine` carry a semver contract. The check crates
   and `rdy-bundle` say in their crate docs: "Internal to rdy. No API stability promise."
2. **Independent versions.** Each crate has its own version. Nothing needs crates.io until `rdy-cloud`
   starts in M2, so the first real publish (beyond the 0.0.1 placeholders) is an M2 task. `release-plz` opens the release PR with
   per-crate bumps and changelogs; a `v*` tag on `rdy` triggers the binary release (release-engineer
   owns the pipeline). Crates that did not change are not republished.
3. **Semver in 0.x.** Cargo's rule: in `0.y.z`, a `y` bump is breaking, a `z` bump is compatible.
   `cargo-semver-checks` runs in CI on `rdy-spec` and `rdy-engine` and fails a PR that breaks API
   without the matching bump. MSRV raises are a minor bump in 0.x.
4. **1.0.** `rdy-spec` and `rdy-engine` go 1.0 at the M3 public launch, after design partners have used
   `rdy/v1` for two milestones. From then on a breaking change is a major bump and needs an ADR.
5. **Wire format versions are separate from crate versions.** `rdy/v1` names the spec schema and the
   result schema. Within `v1` only additive changes are allowed: new optional fields, new check ids, new
   enum values in results. A removal, a rename, or a changed meaning requires `rdy/v2`.
6. **Forward compatibility.** Public enums in results are `#[non_exhaustive]` and the result JSON schema
   documents that consumers must accept unknown enum values. A spec field this `rdy` does not know makes
   that check `Skipped` with reason "needs a newer rdy", never silently ignored (ignoring a stricter
   threshold would be a false pass).
7. **Backward compatibility.** Every `rdy-engine` release can deserialize every `rdy/v1` result ever
   written. Golden result files from each released version are kept in `tests/fixtures/results/` and
   parsed in CI forever.
8. **Supporting `v2` later.** A `rdy` that knows `v2` keeps reading `v1` specs for at least 12 months.

## Consequences

- `rdy-cloud` can pin `rdy-spec = "0.3"` and only moves when it wants to.
- Contributors cannot break the contract without CI noticing.
- A small amount of release ceremony per crate; release-plz does the typing.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Lockstep versions for every crate | Every CLI-only change forces a contract-crate bump, which in 0.x is a breaking bump for `rdy-cloud`. |
| Publish only rdy-spec and rdy-engine | Breaks `cargo install rdy`; Homebrew and distro packagers expect it. |
| Tie `apiVersion` to crate major | Crate API breaks (renaming a Rust type) would force a wire format bump for no reason. |
| Lenient unknown fields | A newer spec's stricter threshold would be dropped and the check would pass. |

## Tickets implied

- [M1] cargo-semver-checks in CI for rdy-spec and rdy-engine | owner: release-engineer | est: 2h | depends on: Create workspace skeleton | exit test: a PR that removes a public field without a version bump fails CI.
- [M2] release-plz config for per-crate versions and changelogs | owner: release-engineer | est: 3h | depends on: Reserve crates.io names with 0.0.1 placeholders | exit test: a dry run opens a release PR bumping only the crates that changed.
- [M1] Keep golden result files per released version and parse them in CI | owner: qa-engineer | est: 1h | depends on: Golden tests for JSON and HTML reports | exit test: CI deserializes every file under tests/fixtures/results/ with the current rdy-engine.
- [M3] Release rdy-spec and rdy-engine 1.0 | owner: rust-architect | est: 4h | depends on: none | exit test: 1.0 published and cargo-semver-checks baseline moved to 1.0.
