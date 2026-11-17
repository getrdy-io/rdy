# ADR 0047: Install-only blocks run against the newest published release, and the `/unsigned` redirect is a declared file

- Status: Proposed (M1-133). Needs security-reviewer on the workflow and the redirect, and code-reviewer, before merge.
- Date: 2026-11-17

## Context

M1-133 asks for two things the plan does not spell out.

First, the install page has commands that must run on a real release. The exit test says they run in CI
against the latest alpha's pinned `install.sh` on a fresh Linux container. 09 section 10 calls them
`install-only` blocks, and says a block extraction script owned by 06 runs them. 06 does not define that
script. No release exists yet. The founder tags 0.1.0 by hand (M1-138). So a job that fetches a fixed URL
would 404 today, and a red job before the first release would teach people to ignore red.

Second, the CLI prints `https://docs.getrdy.io/unsigned` in its fix lines (01 sections 4.7 and 4.8, ADR 0027).
07 says the page must answer at that URL by 0.1.0. M1 pages are Markdown. The Starlight site and its
redirect config come in M3 (09). So a redirect in M1 is a hosting step, and the repo must say what it is.

## Decision

1. **Install-only blocks are marked by the info string.** A fenced block whose info string ends in
   `install-only` (for example ```` ```sh install-only ````) runs in CI. Every other block does not. The
   docs-test runner (M1-136) reads the same marker for its own cases.

2. **The release is read from GitHub, not from a pin file.** `scripts/install-blocks.sh --resolve-tag` asks
   the REST route `repos/getrdy-io/rdy/releases` through `gh api` for the newest release that is not a draft.
   REST, not `gh release list`, because the list command uses GraphQL, which some hosts cannot reach. A pin
   file would need an edit at every release, and it would drift from what customers get. The API answer is
   the release customers get.
   - No release: the job prints `SKIPPED` and the blocks job does not run. The workflow stays green, and the
     step summary says why.
   - API error: the job fails. A failed lookup never looks like a skip.
   - Tag shape: the tag must match `v<x>.<y>.<z>` with an optional pre-release part. Any other character fails.

3. **The install URL is built in one place.** `RELEASE_BASE` in `scripts/install-blocks.sh` is the only
   template for the `install.sh` URL in the test path. The blocks read `$RDY_INSTALL_URL`. The page shows the
   URL pattern in prose, not in a block, so a reader sees a real address and no placeholder.

4. **The blocks run in a fresh container as a user with no rights.** The job uses `ubuntu:24.04`. It installs
   `curl` and CA certificates, which the image lacks, then cosign from `.github/release-tools.txt`
   (sha256 checked). The blocks run as `tester`, with `env -i` and a fixed `PATH`. That is what a customer on
   a clean host has. Nothing runs as root, and the install page says the script refuses root.

5. **The workflow is not in `ci-ok`.** It reads a published release. A release outage must not block merges
   (the same reasoning as `kind.yml`, ADR 0039). It runs on PRs that touch the install page or these scripts,
   weekly, and by hand. The founder decides whether it becomes a gate.

6. **The shell tests need no network.** `scripts/test-install-blocks.sh` stubs `gh` and `curl`. The stub `curl`
   writes a fake `install.sh` that puts a fake `rdy` in `$HOME`. The test runs the real install page through
   the runner, so a broken block fails a test, not only the weekly job.

7. **The redirect is a declared file.** `docs/redirects.txt` lists each path that the binary prints, and the
   file it redirects to. The founder adds each line as a 301 rule on the docs host. The target is a file at
   `main` until 0.1.0, then the tag. `crates/rdy-cli/tests/docs_pages.rs` fails when a docs URL in
   `crates/` has no page and no line here, or when a target is not a file of this repo. It cannot test the
   host, so the founder checks the redirect by hand after each change (below).

8. **Exit codes come from the enum.** The exit codes page lists the rows of `ExitCode`, and the test fails when
   they differ. Exits 0, 1 and 2 are proved by the fixture goldens, and 64 and 70 by `exit_code_goldens.rs`.

## Consequences

- Until 0.1.0, the install job prints SKIPPED. That is intended, and the step summary says so.
- After 0.1.0, a broken `install.sh` or a broken block fails the weekly job within a week. A PR that touches
  the page or these scripts runs the job at once.
- The container tag is not pinned by digest. This is a deviation from the pinning rule that applies to `uses:`.
  The founder pins it by digest before the job becomes a gate. The job does not hold a secret and it has
  `contents: read` only, so the exposure is a changed base image, not a token.
- The releases API returns the newest release by creation time. A release that is published and then
  withdrawn is a manual fix on GitHub.

## Founder steps

1. Add the redirect `https://docs.getrdy.io/unsigned` to the docs host as a 301 to the target in
   `docs/redirects.txt`. Check it with `curl -sSI https://docs.getrdy.io/unsigned`: the status is 301 and the
   location is the GitHub page. After 0.1.0, change the target to the tag, in the same PR.
2. Pin `ubuntu:24.04` by digest in `.github/workflows/install-blocks.yml`, or decide the tag is enough.
3. Decide whether `install-blocks` joins `ci-ok`. The default here is no.
4. After 0.1.0 is published, run the workflow by hand (`workflow_dispatch`). The blocks job must pass. Paste the
   run URL into the Done log.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| A pin file with the alpha tag, edited at each release | A manual edit that drifts. It can point at a release that does not match what is published. |
| Test the URL of a fixed tag in the docs | The tag does not exist until 0.1.0. A red job before then trains people to ignore red. |
| Run the blocks on the runner, not in a container | The runner has cosign, gh and a warm cache. A customer does not. The fresh container is the point. |
| Serve `/unsigned` from a Worker in M1 | Needs a new hosting account and a deploy path (06 Worker, M2). A redirect rule is enough for a link. |
| Put the redirect in Starlight config now | Starlight is M3. The site does not build in M1. |

## Tickets implied

- [M1] M1-133 this PR: install page, exit codes page, unsigned page, the install-only runner and its workflow.
- [M1] M1-136 (docs-test runner) reads the `install-only` marker and the `pending=` marker that this PR uses.
- [M2] M2-108 updates the install page and the `install.sh` override row, as 11 says.
