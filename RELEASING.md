# Releasing rdy

This is the runbook for one release. The design is in `docs/plan/06-release-and-distribution.md`. The
reasons for the hand steps are in `docs/adr/0020-dist-release-workflow-settings.md` and
`docs/adr/0024-release-proofs-are-founder-hand-steps.md`.

## Rules

- Only the founder pushes a release tag and clicks Approve. Agents never push a tag, publish or delete a
  release, or approve the `release` environment (ADR 0024).
- A tag never changes. A failed release burns its version number. The next try is the next number.
- Tag only from `main`, with `ci-ok` and `release-workflow` green. Never tag red. Skip the week instead.
- Cadence: `v0.1.0-alpha.N`, weekly on Thursday, with Friday as buffer. A skipped week keeps its number.
  `v0.1.0` comes when M1 core is done (ticket M1-138).
- No release exists until signing ends, not even a draft (ADR 0020, ADR 0024). That is by design.

## Once, before the first tag

Do each step and put its evidence in the Done log of `docs/plan/11-backlog.md` (Founder hand steps).

1. M1-010 and M1-011 are merged.
2. The signing proof in `docs/plan/06-release-and-distribution.md`, "Sandbox proof, signing (M1-010)", has
   run on `getrdy-io/release-sandbox` and is in the Done log. It proves the approval wait, the signature, the
   failing tamper and wrong-repository checks, and what `immutable` says.
3. `getrdy-io/rdy` has the environment `release`, with you as required reviewer and only `v*` tags allowed
   (`docs/security/github-settings.md`, section 11). The name must be exactly `release`.
4. The `v*` tag ruleset and immutable releases are on. Run
   `GH_TOKEN=$(gh auth token) scripts/check-org-settings.sh` and read every line. GitHub makes a release
   immutable only if the setting was on when it was published.

## Every release

Pick the next number `N`. The examples use `v0.1.0-alpha.1`.

1. **Preflight.** `main` is green. The checks in `.github/workflows/ci.yml` passed on the last merge
   commit. The `kind` workflow (`.github/workflows/kind.yml`, live Kubernetes tests, not a required
   check: ADR 0039) is green on that same commit, or on the nightly run after it. A red `kind` run means
   the client or the read-only role broke against a real API server. Fix it before you tag. No release PR
   is open.
2. **Release PR.** Branch `release/v0.1.0-alpha.1` from `main`, one commit.
   - Set `version` in `crates/rdy-cli/Cargo.toml` to `0.1.0-alpha.1`. The tag must equal the `rdy` package
     version, or the plan job fails (ADR 0020). Other crates keep their own versions (ADR 0007).
   - Run `cargo update --workspace` so `Cargo.lock` follows. Run `cargo build --workspace --locked`.
   - Assemble the changelog (ADR 0017). Move the lines of every file in `changelog.d/` under a new heading
     `## 0.1.0-alpha.1 - <date>` in `CHANGELOG.md`, in ticket id order. Delete the fragments in the same
     commit. `## Unreleased` keeps one line: changes wait in `changelog.d/`.
   - Open the PR, wait for `ci-ok`, merge.
3. **Tag.** On your machine:

   ```sh
   git fetch origin && git switch main && git pull --ff-only
   git log -1 --oneline        # must be the release PR merge
   git tag -a v0.1.0-alpha.1 -m "rdy v0.1.0-alpha.1"
   git push origin v0.1.0-alpha.1
   ```

4. **Watch the `Release` run.** `gh run list --repo getrdy-io/rdy --workflow Release`. `plan`, five
   builds, `build-global-artifacts`, `host` and `custom-check-release-artifacts` go green. Then
   `custom-sign-release` shows Waiting.
5. **While it waits,** `gh release view v0.1.0-alpha.1 --repo getrdy-io/rdy` must say the release was not
   found. If a release exists now, stop and read ADR 0024.
6. **Approve.** In the run, Review deployments, tick `release`, Approve and deploy. The `sign` job must end
   with `signed and verified SHA256SUMS` and lines for `identity:`, `claims:`, `sha256:` and `rekor log:`.
   Copy the last two. `announce` then verifies the signature again and publishes.
7. **Check the release.**

   ```sh
   gh release view v0.1.0-alpha.1 --repo getrdy-io/rdy --json isPrerelease,isDraft,isImmutable,assets
   ```

   `isPrerelease` must be true and `isDraft` false. The assets must include `SHA256SUMS`,
   `SHA256SUMS.sigstore.json` and five archives. If the CLI has no `isImmutable`, use
   `gh api repos/getrdy-io/rdy/releases/tags/v0.1.0-alpha.1 --jq .immutable`.
8. **Verify on a clean Linux machine.** A fresh VM or container with `git`, `curl`, `awk`, `grep`,
   `mktemp` and `sha256sum`, and no earlier checkout of rdy. It needs the network: cosign fetches the
   Sigstore trust root, also for `--dir`. The script and the pinned cosign hash come from the checkout,
   so the checkout is what you trust. The tag points at the head of `main`, so a checkout of the tag is
   the same code. What matters is that you read the script before the release. Check out a commit SHA
   of `main` that you reviewed earlier (a merged PR), not a commit you picked after the tag. Record that
   SHA in the Done log. The script is never taken from the release assets, which are the thing under
   test:

   ```sh
   git clone https://github.com/getrdy-io/rdy.git
   cd rdy
   git checkout --detach <sha>     # a main commit you reviewed before the tag
   git log -1 --oneline            # record this SHA in the Done log
   sh scripts/install-release-tool.sh cosign     # the pinned cosign, sha256 checked
   PATH="$HOME/.cargo/bin:$PATH" scripts/verify-release.sh v0.1.0-alpha.1
   echo "exit $?"
   ```

   It must print `PASS signature`, one `PASS sha256` line per file, `verified v0.1.0-alpha.1`, and exit 0.
   The script refuses cosign older than 3.1.3, a bundle that is not the v0.3 format, and any of these
   variables when set: `SIGSTORE_ROOT_FILE`, `SIGSTORE_REKOR_PUBLIC_KEY`,
   `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE`, `SIGSTORE_TSA_CERTIFICATE_FILE`, `TUF_MIRROR`, `TUF_ROOT_JSON` and
   `TUF_ROOT`. It checks the
   issuer, the exact identity, the repository `getrdy-io/rdy`, the ref `refs/tags/v0.1.0-alpha.1` and the
   trigger `push`, then the sha256 of every asset in `SHA256SUMS`.

   Then show that it can fail. Download the two signed-list files with `curl`, change one byte of
   `SHA256SUMS`, and run the script on the folder. No `gh` is needed.

   ```sh
   rel=$(mktemp -d)
   for f in SHA256SUMS SHA256SUMS.sigstore.json; do
     curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$rel/$f" \
       "https://github.com/getrdy-io/rdy/releases/download/v0.1.0-alpha.1/$f"
   done
   printf 'X' | dd of="$rel/SHA256SUMS" bs=1 count=1 conv=notrunc
   PATH="$HOME/.cargo/bin:$PATH" scripts/verify-release.sh --dir "$rel" v0.1.0-alpha.1
   echo "exit $?"        # must be 1, with an invalid signature error
   rm -rf "$rel"
   ```

   Then run the installer from the release (M1-015). Use the same machine, the cosign from above on
   `PATH`, and a throwaway install folder. Add `--allow-root` after `sh -s --` if the shell is root.
   This is the pinned URL that design partners use in M1:

   ```sh
   dest=$(mktemp -d)
   PATH="$HOME/.cargo/bin:$PATH" RDY_INSTALL_DIR="$dest" sh -c \
     "curl --proto '=https' --tlsv1.2 -sSf https://github.com/getrdy-io/rdy/releases/download/v0.1.0-alpha.1/install.sh | sh"
   echo "exit $?"        # must be 0
   "$dest/rdy" version   # rdy 0.1.0-alpha.1
   ```

   The output must have `signature ok: SHA256SUMS is signed by` followed by the identity, then
   `sha256 ok`, then `Installed rdy 0.1.0-alpha.1`. Then show that it fails closed: run the same
   command with a `PATH` that has no cosign, into a new empty `$dest`. It must exit 1 with
   `cosign is not installed` and leave `$dest` empty. The tamper cases (bad hash, bad signature, wrong
   identity, wrong caller repository, ref or trigger, missing bundle, old cosign, trust variables)
   cannot be staged on a real release. `scripts/test-install-sh.sh` proves them with a fake cosign.
9. **Record.** In the Done log add `- M1-012 hand | <date> | <evidence>` (for the first tag) with: the run
   URL, the `gh release view` output, the `immutable` value, the verify output, the sha256 of `SHA256SUMS`
   and the Rekor log index. For the first tag also add `- M1-015 hand | <date> | <evidence>` with the
   `install.sh` output from step 8 (the `signature ok` and `Installed` lines, exit 0) and the output of
   the run without cosign (`cosign is not installed`, exit 1, empty folder). For every release, keep the sha256 and the Rekor index. They go on
   `getrdy.io/security` and in `SECURITY.md` when M2 publishes the trust anchors.

## Bumping the pinned cosign

`.github/release-tools.txt` holds the pin. A bump changes what `verify-release.sh`, `sign-release.sh` and
`install.sh` trust, so before you merge it, re-check that cosign still has no environment-to-flag binding
(ADR 0025, update for M1-015). Only the seven trust variables that `install.sh` and `verify-release.sh`
refuse may change trust. Read `cmd/cosign/cli/commands.go` and `cmd/cosign/main.go` of the new version.
If a `COSIGN_` variable can weaken a check, add it to the refused list in both scripts.

## If something fails

| What you see | What it means | What to do |
| --- | --- | --- |
| The plan job fails on the tag | The tag does not equal the `rdy` version, or is not `v<major>.<minor>.<patch>[-<pre>]` | The tag is burned. Fix the version in a PR and use the next number. |
| A build or `custom-check-release-artifacts` fails | The artifacts are not fit to sign. No release exists | Fix on `main`. Use the next number. Do not move or delete the tag. |
| `custom-sign-release` never shows Waiting | The environment is not named exactly `release`, or does not allow `v*` tags | Fix the environment. Use the next number. |
| `sign` fails in `cosign sign-blob` with an OIDC error | The caller job lacks `id-token: write` | Check `release.yml` against `scripts/harden-release-workflow.py`. |
| `sign` fails on the self-verify | The identity or the caller claims are not what the contract expects (06) | Do not publish. Read the `error:` and `fix:` lines. Ask `security-reviewer`. |
| You click Reject, or nobody approves | Signing did not run. No release exists | The number is burned. Start again with the next one. |
| `announce` fails on `gh release create` | The release may not exist, or a partial or draft one may | First run `gh release list --repo getrdy-io/rdy` and look for the tag. Then read ADR 0024, Consequences, before you retry. The number is burned. |
| `verify-release.sh` fails on the signature | The release is not signed as the contract says, or the machine cannot reach Sigstore (read the cosign lines above the error) | Do not use it. Tell `security@getrdy.io` and `security-reviewer`. Cut a new number. |
| `verify-release.sh` says cosign is missing or too old | The machine has no cosign, or one below 3.1.3 | `sh scripts/install-release-tool.sh cosign`, then put `$HOME/.cargo/bin` on `PATH`. |
| `install.sh` says `cosign is not installed`, or `cosign ... is too old` | The machine has no cosign, or one below 3.1.3. The script stops before it downloads anything | Install cosign 3.1.3 or newer and run it again, or verify by hand with `scripts/verify-release.sh`. The override `RDY_INSECURE_SKIP_SIGNATURE=1` skips the signature only and prints a warning. Use it only on a host you control. |
| `install.sh` says `this release looks incomplete: it has SHA256SUMS but no SHA256SUMS.sigstore.json` | The release is still being published, or it was never signed | Wait and try again. A published release without a bundle is a signing failure: do not use it, and cut a new number. |
| `install.sh` says `does not verify as` | Wrong signer, wrong caller, changed files, or cosign could not reach Sigstore (read the cosign lines above the error) | Do not use it. Tell `security@getrdy.io`. |

## Version and support policy

The full text is in `docs/plan/06-release-and-distribution.md` (Version and support policy) and
`SECURITY.md`. In short:

- The tag `vX.Y.Z[-pre]` equals the `rdy` package version. Library crates have their own versions (ADR 0007).
- In 0.x a minor bump may break CLI flags and `--json`. A patch never does.
- Only the latest release gets fixes until 1.0. Security fixes ship the same day.
- The signed release is `SHA256SUMS`. Verify it with `scripts/verify-release.sh <tag>` before you trust a
  file from the release.
