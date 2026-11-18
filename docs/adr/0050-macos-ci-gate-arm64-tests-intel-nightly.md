# ADR 0050: The PR gate runs macOS arm64 tests and an x86_64 macOS compile; the Intel tests run on main and nightly

- Status: Accepted. Decided by the founder on 2026-11-18
- Date: 2026-11-18
- Supersedes: ADR 0006, decision 8

## Context

Both macOS legs of `ci.yml` ran on `macos-15-intel`. Those runners queue for a long time and often fail
with "The job was not acquired by Runner". CI is the bottleneck for every PR. A merge queue would not
help and is not available: `getrdy-io` is a personal account, not an organization.

ADR 0006 decision 8 recorded that `macos-15` (arm64) had never been assigned a runner. That was
observed on the old organization. The repository was recreated on 2026-10-30 (ADR 0041). The founder
decided to use the arm64 image again. 06 already allows this fallback for a slow Intel image.

## Decision

1. `ci.yml` has `macos-arm64` on `macos-15`, target `aarch64-apple-darwin`, with the full tests.
2. `ci.yml` has `macos-x64-build` on `macos-15`, target `x86_64-apple-darwin`, compile only (build and
   `cargo test --no-run`). Every PR still compiles all five targets.
3. `macos-intel.yml` runs the full tests for `x86_64-apple-darwin` on `macos-15-intel`, on push to
   `main`, nightly and by `workflow_dispatch`. It is not in `ci-ok`.
4. `ci-ok` still lists only the `test` matrix job, so no required check name changes.
5. `macos-arm64.yml` is deleted. Its job is now a gating leg.
6. Release builds are unchanged. `dist-workspace.toml` builds both macOS targets on `macos-15-intel`.
   Release is not the PR gate.

## Risk

A failure that appears only on Intel macOS is caught after merge, by the push run on `main` or by the
nightly run, within a day. The fix is a follow-up PR. A red `macos-intel` run on `main` blocks the next
release until it is fixed or explained. If `macos-15` gets no runner, the `macos-arm64` leg queues and
blocks PRs: see the revert below.

## How to revert

1. In `ci.yml`, replace the two macOS legs with `macos-x64` on `macos-15-intel` (full tests) and a
   `macos-arm64-compile` leg on `macos-15-intel` (compile only), and move the install.sh `sh` step back.
2. Delete `macos-intel.yml`. Restore `macos-arm64.yml` from git history if `macos-15` still gets no
   runner.
3. Retire this ADR and update 06 and CLAUDE.md. `ci-ok` needs no change.
