# ADR 0024: Release proofs that need the sandbox, an environment approval or a tag push are founder hand steps; agents build and test the repo side only and never push tags or publish releases

- Status: Accepted by the coordinator, founder ratification pending (2026-10-29, M1-010). The coordinator
  took the most conservative option while the founder was away. The founder can relax it.
- Date: 2026-10-29

## Context

Some release proofs cannot run from a build agent's checkout:

- The sandbox repo `getrdy-io/release-sandbox` is out of reach for agents (M1-007, 06 "Sandbox proof").
- A GitHub environment with a required reviewer needs a human to click Approve. An agent must not approve
  its own deployment.
- A tag push starts the release workflow. In `getrdy-io/rdy` it ends in a public release, and a tag never
  changes (06, contract table). A mistake burns a version number for good.

The M1-010 exit test (sign-release) needs all three.

## Decision

1. A release proof that needs the sandbox, an environment approval, a tag push, a published release or a
   GitHub setting an agent cannot change is a founder hand step. It is listed in `docs/plan/11-backlog.md`
   ("Founder hand steps") and its exact steps are in the repo (for M1-010: 06, "Sandbox proof, signing
   (M1-010)").
2. Agents build and test the repo side only: workflows, scripts, script tests, docs and the checklist. They
   use stubs and fakes locally, and the real tools in CI.
3. Agents never push a tag, publish or delete a release, approve an environment deployment, or change
   repository or environment settings, even if a token that could do it exists.
4. A ticket whose exit test needs such a proof merges with the repo side done and the proof recorded as a
   deferral in its `12-progress.md` line. The hand step goes in the Done log with its evidence before the
   ticket or event named in "Needed before".
5. A test an agent cannot run is written so CI or the founder runs it. `cosign-roundtrip` (real keyless
   signatures, real `cosign verify-blob`) is in `ci-ok` on the M1-010 PR, so that PR cannot merge until
   it is green.

## Applied to M1-010

The design is in 06: the contract table (signer identity and caller claims), the CI section
(`sign-release` steps), Appendix B and "Sandbox proof, signing (M1-010)". The decisions:

- With `github-release = "announce"` (ADR 0020, decision 2) no release exists while signing runs, not even a
  draft. The signing job needs `contents: read` and `id-token: write`, not `contents: write`. `announce`
  verifies the signature again before it publishes.
- `cosign` comes from `scripts/install-release-tool.sh` with a committed hash, not an install action.
- Verification is by exact identity, issuer and the caller claims (repository, ref, trigger), never by
  regular expression. The identity names the called workflow file, so the claims and the job condition
  `github.repository_owner == 'getrdy-io'` close the hole where another repository calls it.

## Consequences

- Merging M1-010 does not prove the exit test. The sandbox proof does. M1-012 waits for it in the Done log.
- If the sandbox shows that `gh release create` with all assets does not make an immutable release, change
  `announce` to create a draft, upload, then publish (an edit to `scripts/harden-release-workflow.py`).
- A scoped sandbox token could let agents do more later. That needs a new ADR.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Let the agent push a sandbox tag with a scoped token | No token exists. A tag push is the action this ADR keeps with a human. |
| Mark M1-010 blocked until the founder runs the sandbox | Stops the weekly slice. The repo side is useful now. |
| Skip the environment gate | It stops a tag pushed by anything but the founder (05, E2 and T4). |
| Download a cosign binary in the build session | Not needed: CI installs the pinned, hash-checked cosign and runs the tests. |
