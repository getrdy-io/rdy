# ADR 0024: Release proofs that need the sandbox, an environment approval or a tag push are founder hand steps; agents build and test the repo side only and never push tags or publish releases

- Status: Accepted (2026-10-29, M1-010). Decided by the coordinator while the founder was away, taking the
  most conservative option. The founder can relax it.
- Date: 2026-10-29

## Context

Some release proofs cannot run from a build agent's checkout:

- The sandbox repo `getrdy-io/release-sandbox` is out of reach for agents (M1-007, 06 "Sandbox proof").
- A GitHub environment with a required reviewer needs a human to click Approve. An agent must not approve
  its own deployment, even if it had the access.
- A tag push starts the release workflow. In `getrdy-io/rdy` it ends in a public release that customers
  can install. A mistake there burns a version number for good (06, contract table: tags never change).

M1-010 (sign-release) has an exit test that needs all three: the signing job waits for approval, the
release appears only after signing, and `cosign verify-blob` with the exact identity passes on a clean
machine and fails after one byte of `SHA256SUMS` changes. An agent can build everything but cannot run that
test end to end.

## Decision

1. A release proof that needs the sandbox, an environment approval, a tag push, a published release or
   any other GitHub setting an agent cannot change is a founder hand step. It is listed in
   `docs/plan/11-backlog.md`, "Founder hand steps", and its exact steps are written in the repo (for
   M1-010: 06, "Sandbox proof, signing (M1-010)").
2. Agents build and test the repo side only: the workflows, the scripts, the script tests, the docs and
   the checklist. They test locally with stubs and fakes, and in CI.
3. Agents never push a tag, never publish or delete a release, never approve an environment deployment and
   never change repository or environment settings. This holds even if a token that could do it exists.
4. A ticket whose exit test needs such a proof is merged with the repo side done and the proof recorded as
   a deferral in its `12-progress.md` line. The hand step goes in the Done log with its evidence, before
   the ticket or event named in "Needed before".
5. A test that an agent could not run (for example a script that needs a binary the agent may not install)
   is written so CI or the founder runs it. If it has never been seen green, its CI job is not in `ci-ok`
   until the first green run. The ticket says so.

## Applied to M1-010

The repo side that M1-010 ships, and what stays a hand step:

- `release.yml` (generated, then hardened) gets a publish job `custom-sign-release`. It calls
  `.github/workflows/sign-release.yml`, which runs in the environment `release`. It waits for the check job
  (`custom-check-release-artifacts`), so a build that fails the artifact check is never signed.
- With `github-release = "announce"` (ADR 0020, decision 2) no release exists while signing runs, not even a
  draft. So the sandbox shows "no release" during the approval wait, not "draft". This is stronger than the
  exit test's wording. The signing job hands `SHA256SUMS`, its bundle and the stamped `install.sh` to
  `announce` as a workflow artifact, and `announce` publishes after it has checked that `SHA256SUMS` lists
  exactly the files it uploads.
- The signing job needs `contents: read` and `id-token: write`. It does not need `contents: write`, because
  there is no release to upload to. `announce` stays the only job that can write contents. It cannot be
  narrower: `gh release create` needs it. The plan (06, Appendix B) listed `contents = "write"` for
  `sign-release`. That was written for a draft release and is wrong for the announce flow.
- `cosign` comes from `scripts/install-release-tool.sh`, with a hash in `.github/release-tools.txt`, not
  from an install action. The one job that holds an OIDC token then runs no third-party action code.
- `scripts/sign-release.sh` verifies with `--certificate-identity` and `--certificate-oidc-issuer`, never a
  regular expression, using `https://github.com/<repo>/.github/workflows/sign-release.yml@refs/tags/<tag>`.
  A signature that does not verify deletes `SHA256SUMS` and the bundle and fails the job.
- `install.sh` does not exist before M1-014. When it does, it must hold the text `@RDY_VERSION@` on exactly
  one line. `sign-release.sh` replaces that text with the tag and signs the stamped copy.
- Tests: `scripts/test-sign-release.sh` uses a fake `cosign` (identity, issuer and one-byte tamper). The
  fake cannot show what Fulcio puts in a real certificate. `scripts/test-cosign-roundtrip.sh` runs the real
  `verify-blob` form against cosign's own keyless release signature and flips one byte. It was written
  without a cosign binary to run it on, so its CI job `cosign-roundtrip` is outside `ci-ok` until the first
  green run.
- Hand step: create the environment `release` with a required reviewer, create the sandbox, and run the
  signing proof (06). It also shows the real certificate identity, the immutable state of the release, and
  that `announce` works with the artifact flow.

## Consequences

- Merging M1-010 does not prove the exit test. The sandbox proof does. M1-012 (first signed alpha) waits for
  that proof in the Done log.
- If the sandbox shows that `gh release create artifacts/*` attaches assets after the release is public (an
  immutable release then fails), change `announce` to create a draft, upload, then publish. That is a small
  edit to `scripts/harden-release-workflow.py`.
- The exit test's word "draft" in the M1-010 row should read "no release exists, not even a draft, until
  signing ends". The coordinator files that as a correction.
- Agents can do more later if the founder grants a scoped token for the sandbox only. That would be a new
  ADR, not a quiet change.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Let the agent push a sandbox tag with a scoped token | No token exists, and the founder is not here to issue one. A tag push is the action this ADR keeps with a human. |
| Mark M1-010 blocked until the founder runs the sandbox | Stops the weekly slice. The repo side is useful and reviewable now. |
| Skip the environment gate | The gate is the control that stops a stolen tag from signing. 05 asks for it (E2, T4). |
| Download a cosign binary and run it in the build session | The coordinator ruled that agents install no tool for this ticket. The tests are written for CI and the founder instead. |
