# Release and distribution plan

Owner: release-engineer. Revised 2026-10-27 after review by code-reviewer. Scope: CI, release automation, signing, SBOM, install script, package managers, self-update, version policy. It does not design the CLI or the engine.

## Summary

1. CI runs on five native runners: Linux x86_64 musl, Linux aarch64 musl, macOS arm64, macOS x86_64, Windows x86_64. Nothing is cross-compiled. One aggregate job, `ci-ok`, is the only required check.
2. Releases are built by `dist` (formerly cargo-dist), pinned to an exact version, with the generated workflow committed.
3. One file is signed: `SHA256SUMS`, which lists every release asset. It is signed with cosign keyless (GitHub OIDC). Customers verify one file, then check hashes.
4. `install.sh` fails closed. No cosign on the host means stop, unless the named override is set.
5. M1 release work is capped at 24 hours in 8 tickets: CI, one signed alpha, install.sh. Everything else is M2 or later.
6. Self-update is deferred to M3. Crate publishing and versions follow ADR 0007. Static musl follows ADR 0006. TLS follows ADR 0009.

The repo must be public from the first commit, so CI minutes are free (see Cost).

## Install and signing contract (agreed with 05)

`05-threat-model.md` wins on security behaviour. This table is the single place the security-reviewer confirms it. Mechanics (file names, workflow paths) are release-engineer's. Where 05 names a mechanic that does not work, the row says so.

| Item | Agreed value | 05 ref |
| --- | --- | --- |
| Customer command | `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install \| sh` (live in M2). In M1, design partners use the pinned release URL: `.../releases/download/v0.1.0-alpha.N/install.sh` | Surface 3 |
| Script shape | POSIX sh, `set -eu`, all logic in `main()` called on the last line, shellcheck clean | T2 |
| Root | Refuses uid 0 unless `--allow-root` (`sh -s -- --allow-root`). No environment variable. With the flag the default dir is `/usr/local/bin` | E1, INV-18 |
| Install dir | `$HOME/.local/bin`, or `RDY_INSTALL_DIR`. Never `sudo`, never shell rc files, never setuid. Prints a PATH hint | E1, E2 |
| Allowed environment variables | `RDY_VERSION`, `RDY_INSTALL_DIR`, `RDY_INSECURE_SKIP_SIGNATURE`. No variable changes the download host. Tests use a stub `curl` on `PATH` | INV-18 |
| Version | Each release's copy of `install.sh` has its own tag stamped in as the default. The source `install.sh` holds the line `RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'` exactly once (M1-014), and `sign-release` replaces the whole line with `RDY_STAMPED_VERSION='<tag>'`, with the `v`, and checks that exactly one such line results. The script never calls the GitHub API and never reads `GITHUB_TOKEN` | D1 |
| Downloads | `curl --proto '=https' --tlsv1.2 -fsSL` into `mktemp -d` with a cleanup trap. OS and CPU from an allowlist; unknown means stop | Surface 3 |
| What is signed | `SHA256SUMS`, one file listing every release asset: archives, SBOM, `install.sh`. Bundle: `SHA256SUMS.sigstore.json`. Archives are not signed one by one | Surface 3 |
| Signer identity | Issuer `https://token.actions.githubusercontent.com`. Subject `https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml@refs/tags/v<VERSION>`. Caller claims: repository `getrdy-io/rdy`, ref `refs/tags/v<VERSION>`, trigger `push`. Every verify passes all of them: the subject names the called workflow file, not the repository that called it, and any repository can call a public reusable workflow. `install.sh` pins the exact version it installs, not a pattern | S2 |
| Order | Verify `SHA256SUMS` signature, then the archive hash against it, then extract. Nothing is made executable before both pass. The binary first runs after that (`rdy version`) | Surface 3 |
| Cosign missing | Stop, exit 1, print the two-line manual verification path | Surface 3 |
| Override | `RDY_INSECURE_SKIP_SIGNATURE=1` skips the signature only. The sha256 check still runs. Prints a loud warning | Surface 3 |
| Bad signature | Abort, delete everything, say "do not run this file", point to `security@getrdy.io` | INV-18 |
| Missing bundle (404) | Abort with "this release looks incomplete", not the attack wording | none (new) |
| Signing job | Runs in the GitHub environment `release` with a required manual approval. It is the only job with `id-token: write` | E2, T4 |
| Release publication | Immutable releases on. Assets, including signatures, must be attached before the release is published. Proven in the sandbox repo before the first real tag | T3 |
| Tags | Ruleset: only admins create `v*`, no update, no delete. A failed release burns its version number | E2 |
| Specs | Not part of this contract. Specs use the vendor's ed25519 key | rule 3 |

Verification command (customers, docs, and `install.sh` all use this form; replace the version):

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml@refs/tags/v0.1.0-alpha.3" \
  --certificate-github-workflow-repository getrdy-io/rdy \
  --certificate-github-workflow-ref refs/tags/v0.1.0-alpha.3 \
  --certificate-github-workflow-trigger push \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # macOS: shasum -a 256 -c on the matching line
```

The last three flags are required, not optional. Without them a workflow in any other repository that calls `getrdy-io/rdy/.github/workflows/sign-release.yml@v0.1.0-alpha.3` would get a certificate with the same subject and pass. Fulcio puts the called file in the subject and the caller's run in the repository, ref and trigger claims. The flags exist in cosign v3.1.4 (the pinned version). They read the Fulcio certificate extensions with the OIDs `1.3.6.1.4.1.57264.1.2` (trigger), `.1.5` (repository) and `.1.6` (ref). If Fulcio stops issuing one of them, or cosign stops reading it, verification fails closed: every verify, including the `announce` job and `install.sh`, refuses the release. That is a known way a release can break. The fix is a new pinned cosign or a contract change reviewed by security-reviewer, never dropping a flag. Who must follow this contract: `sign-release.sh` (self-verify), the `announce` job (verifies before it publishes), M1-012's `scripts/verify-release.sh` and M1-015's `install.sh` (the docs and `SECURITY.md` already show it). Defence in depth: `sign-release.yml` has the job condition `github.repository_owner == 'getrdy-io'`, so a fork or another organization that calls it gets no certificate from us at all.

For a human who accepts any release, an anchored regexp is fine: `^https://github\.com/getrdy-io/rdy/\.github/workflows/sign-release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)*$`. Keep `--certificate-github-workflow-repository getrdy-io/rdy` and `--certificate-github-workflow-trigger push` with it. Never use a loose pattern such as `.*`.

Where this differs from 05 as written (listed again under Plan corrections):

- 05 names the identity `release.yml`. dist runs signing as a separate reusable workflow, and the certificate carries the called file's path, so the identity is `sign-release.yml`.
- 05's example regexp ends in `[0-9]+$`, which rejects every `-alpha.N` tag. Exact pinning avoids the problem; the human regexp above allows prerelease suffixes.
- 05 says `SHA256SUMS`. dist's own file is `sha256.sum`. `sign-release` checks dist's file, then writes the signed `SHA256SUMS` over all assets.

## CI

| Leg | Runner | Rust target |
| --- | --- | --- |
| linux-x64 | `ubuntu-24.04` | `x86_64-unknown-linux-musl` |
| linux-arm64 | `ubuntu-24.04-arm` | `aarch64-unknown-linux-musl` |
| macos-arm64 | `macos-15` | `aarch64-apple-darwin` |
| macos-x64 | `macos-15-intel` | `x86_64-apple-darwin` |
| windows-x64 | `windows-2022` | `x86_64-pc-windows-msvc` |

Rules:

- Pin runner images by name, never `-latest`. Review the names each April and October.
- Temporary (correction 05): the org has no macOS arm64 runners. `ci-ok` gates an `aarch64-apple-darwin` compile leg on `macos-15-intel` instead of the macos-arm64 test leg, and `macos-arm64.yml` runs the full test job on `macos-15` outside `ci-ok`. A founder hand step ends it (ADR 0006, decision 8).
- `macos-13` is retired. `macos-15-intel` is the last Intel image. If it is slow or dies, build `x86_64-apple-darwin` on the arm64 runner and test it nightly.
- Linux tests run against the musl targets, so CI tests what we ship.
- No `pull_request_target`. Fork PRs get a read-only token.

### Jobs in `ci.yml`

| Job | Gates merge | What it does |
| --- | --- | --- |
| `lint` | yes | `cargo fmt --check`, `clippy -D warnings`, `cargo doc` with warnings as errors |
| `zizmor` | yes | `zizmor` on workflows. Its own job, with no cargo step, so PR build scripts never run beside its token |
| `deny` | yes | `cargo deny check` (licenses, bans incl. `openssl` and `aws-lc-sys`, sources, advisories) |
| `dco` | yes | `scripts/check-dco.sh`: every non-merge commit in the PR has a `Signed-off-by:` trailer. Passes without checking on push to `main`. Also runs `shellcheck` and the DCO script tests on `scripts/*.sh`. No third-party app |
| `test` (5 legs) | yes | build, `cargo nextest run --locked`. Linux legs also prove the binary is static (below) |
| `root` | yes | linux-x64 only. Installs `strace`, builds a nextest archive as the runner user, runs the `root_*` tests from it under `sudo` with the nextest `root` profile (`docs/plan/08-testing.md`, section 6) |
| `install-sh` | yes | `shellcheck`, then the shell test suite with a stub `curl` and stub cosign |
| `ci-ok` | the only required check | `needs:` exactly the gating jobs above; fails on any result other than `success` |

`ci-ok` lists only gating jobs. A job skipped on PRs must never sit in its `needs:`. A renamed matrix leg would otherwise block every PR.

Static-link proof (ADR 0006). Since Rust 1.59 the musl targets build static-pie, so `file` says "static-pie linked" and `ldd` output varies. The check is: `readelf -lW rdy` shows no `INTERP` header, `readelf -d rdy` shows no `NEEDED` entry, then run `rdy version` in a `scratch` container. `scripts/check-static.sh` runs the `readelf` checks from ADR 0006 (static-pie, full RELRO, non-executable stack) and `ci.yml` runs it on both Linux legs. `scratch` cannot be pulled, so CI imports an empty tar as the image. If `ring` needs a C compiler, set `CC_<target>` only. Never set the linker to `musl-gcc`; its wrappers do not handle static-pie.

Caching, in short: `Swatinem/rust-cache` per leg, saved only from `main`; `CARGO_INCREMENTAL=0`; prebuilt tools via `taiki-e/install-action`; no `cargo install`; `--locked` everywhere; no cache in release builds. Target: warm PR runs under ten minutes. Details and the time budget are in Appendix A.

Repo settings (done in ticket "Rulesets on main and v* tags, Dependabot, SHA-pinned actions"): ruleset on `main` (PR required, `ci-ok` required, linear history, no force-push, zero approvals since there is one founder); the tag ruleset above; read-only default token; approval for first-time contributors; Dependabot for `cargo` and `github-actions` (and `npm` in `docs/`, see `09-docs-site.md`); every action pinned to a commit SHA. The org-level half (2FA, private vulnerability reporting) is SEC-04, owned by security-reviewer.

## Workflows

- `ci.yml`: above.
- `release.yml`: generated by `dist generate`, never hand-edited. Fires on a semver tag, prereleases included. It plans, builds the five targets, hosts the artifacts as workflow artifacts (no release exists yet), calls `sign-release`, then publishes. `dist-workspace.toml` sets `pr-run-mode = "plan"`, and dist's plan job fails if `release.yml` has drifted, so no extra drift check is needed.
- `sign-release.yml`: a reusable workflow named in `dist-workspace.toml` (`publish-jobs`). `release.yml` calls it as `custom-sign-release`, after `custom-check-release-artifacts` passes, so a build that fails the check is never signed. With `github-release = "announce"` (ADR 0020) no release exists yet, so there is no draft to download from or upload to. The job works on the workflow's artifacts. Steps: wait for approval in environment `release`; check out the tag with credentials not persisted; download every `artifacts-*` artifact; install cosign from the pinned, hash-checked file (`scripts/install-release-tool.sh cosign`); run `scripts/sign-release.sh`; upload `SHA256SUMS`, `SHA256SUMS.sigstore.json` and the stamped `install.sh` as the artifact `artifacts-sign-release`. `sign-release.sh` removes dist's per-job manifests (as `announce` does), checks the file names, checks the archives against dist's `sha256.sum`, stamps `install.sh` (when the tag has one), writes `SHA256SUMS` over every remaining file, runs `cosign sign-blob --yes --bundle`, and self-verifies with `cosign verify-blob`, the exact identity (no regexp) and the repository, ref and trigger claims. A failed verify deletes the signature files and fails the job. `announce` then downloads all `artifacts-*`, runs `check-release-artifacts.sh --files-only --signed` (the names, and that `SHA256SUMS` lists exactly the files it is about to upload, with matching hashes), verifies the signature with the pinned cosign and the full identity and claims, and only then creates the release. It runs only when `custom-sign-release` succeeded: a skipped signing job does not publish. So the release is not public, not even as a draft, until signing ends. Permissions: dist's default for custom publish jobs adds `packages: write`, so the config sets `[dist.github-custom-job-permissions]` with `sign-release = { contents = "read", id-token = "write" }` (listing both, since an override drops the defaults). It needs no `contents: write`: there is no release to write to. Only `announce` writes contents, and cannot do with less, because `gh release create` needs it. Decision record: ADR 0024.
- `audit.yml` (M2): daily `cargo audit`, `cargo deny check advisories`, an issue opened on failure. Until then the `deny` job checks advisories on every PR.
- Ordering risk. Immutable releases need signatures attached before publication. With `github-release = "announce"` no release exists until `announce` creates it, after signing (ADR 0020, ADR 0024). Whether `gh release create` with all assets makes an immutable release is unproven. The sandbox ticket proves it.

## dist

- Pin `cargo-dist-version = "0.33.0"` (v0.33.1, released 2026-10-21, is too new to pin yet). The tool is now called `dist`. Releases are published at `github.com/axodotdev/cargo-dist`. Ownership changed in 2025, so treat it as community maintained. Fallback if it stalls: a hand-written release workflow, about a day, because signing, SBOM and `install.sh` live outside dist.
- Targets, archive formats and options are in Appendix B. Archives are `.tar.gz` and `.zip`, not dist's default `.xz`, because minimal hosts may lack `xz`. Installers are off in M1. Our own `install.sh` carries the verification.
- Musl: dist installs the Rust target and calls cargo. On a runner of the same CPU as the target, the build needs only `musl-tools`. That is why aarch64 builds on `ubuntu-24.04-arm` and `cargo-zigbuild` and `cross` are not used (ADR 0006 keeps zigbuild as the fallback). The TLS backend is `ring` (ADR 0009), which keeps the C toolchain simple.
- Windows: dist links the C runtime statically by default. Do not set `RUSTFLAGS` in workflows; a `RUSTFLAGS` variable replaces `.cargo/config.toml` flags and silently drops `+crt-static`. A release check confirms `rdy.exe` does not import `VCRUNTIME140.dll`.
- Package name `rdy`, directory `crates/rdy-cli` (ADR 0011). dist names archives from the package, so archives are `rdy-<triple>.tar.gz`, not `.tar.xz` as ADR 0011 says.

## Sandbox proof (M1-007)

The ticket's exit test needs a tag in `getrdy-io/release-sandbox`. The repo-side work is done and checked locally, but the sandbox run needs a repo and an account the build agent does not have. These are the manual steps. They are a Founder hand step (see `11-backlog.md`), needed before M1-010.

1. Create the private or public repo `getrdy-io/release-sandbox`. Push a copy of this repo at the M1-007 merge commit to its `main`, with the workflows and `dist-workspace.toml` unchanged. In the sandbox settings, allow Actions and set workflow permissions to "Read repository contents".
2. In the sandbox, push the tag `v0.1.0-alpha.0` (it must equal the `rdy` package version in `crates/rdy-cli/Cargo.toml`).
3. Wait for the `Release` run. Five `build-local-artifacts` jobs, one `build-global-artifacts`, `host`, `custom-check-release-artifacts` and `announce` must be green. Open `custom-check-release-artifacts` and confirm every line is PASS, including `cargo audit bin lists N dependencies` for all five targets.
4. Download the release assets with `gh release download v0.1.0-alpha.0 --repo getrdy-io/release-sandbox --dir /tmp/sbx`, then run `scripts/check-release-artifacts.sh /tmp/sbx` on a clean Linux machine with `cargo-audit` installed. It must print `release artifacts ok`.
5. By hand, on that machine: `tar -xzf rdy-x86_64-unknown-linux-musl.tar.gz`, then `cargo audit bin rdy-x86_64-unknown-linux-musl/rdy` lists the dependencies, and `scripts/check-static.sh rdy-x86_64-unknown-linux-musl/rdy` passes. Unzip the Windows archive and run `objdump -p rdy.exe | grep 'DLL Name'`: no `VCRUNTIME140.dll`.
6. Open `rdy.cdx.xml`. It is CycloneDX XML (see ADR 0020, decision 8), not JSON.
7. Negative test: in the sandbox only, change `scripts/check-static.sh` to `exit 1` on its first line, tag `v0.1.0-alpha.1` after bumping the crate versions, and confirm `custom-check-release-artifacts` fails and `announce` does not run, so no release exists. Delete the tag and the change.
8. Record in the Done log of `11-backlog.md`: the run URL, the output of step 4, and the `ls` of the release assets. Add the observed `release` state after `announce` (published, `immutable` false in the sandbox unless the setting is on).

If step 3 fails on the `aarch64-apple-darwin` leg because dist asks for `cargo-zigbuild`, stop: dist's wrapper rule changed, and ADR 0020 decision 7 and ADR 0006 decision 8 need a new look.

## Sandbox proof, signing (M1-010)

The ticket's exit test needs the sandbox, a required-reviewer approval and a tag push, none of which the build agent can do (ADR 0024). The repo side is built and tested with a fake `cosign` (`scripts/test-sign-release.sh`). These steps are a Founder hand step (see `11-backlog.md`). Run them after M1-010 merges and before M1-012 tags the first signed alpha.

1. Sandbox settings. In `getrdy-io/release-sandbox`, Settings, Environments, create `release`. Add yourself as a required reviewer and leave "Prevent self-review" off (one founder). Under deployment branches and tags, allow only the tag pattern `v*`.
2. Update the sandbox. Push a copy of `getrdy-io/rdy` at the M1-010 merge commit to the sandbox `main`. Bump the `rdy` crate versions in the sandbox copy to a version that was not used there before, for example `0.1.0-alpha.2`. Do not change the workflows.
3. Push the tag `v0.1.0-alpha.2` in the sandbox. Open the `Release` run. `plan`, the five builds, `host` and `custom-check-release-artifacts` go green. `custom-sign-release` shows "Waiting" for review.
4. While it waits, run `gh release view v0.1.0-alpha.2 --repo getrdy-io/release-sandbox` and `gh release list --repo getrdy-io/release-sandbox`. Both must show no release for the tag, not even a draft. Paste the output.
5. Approve the deployment in the run ("Review deployments"). The `sign` job must end green. In its log find the lines `signed and verified SHA256SUMS`, the `identity:` line (it must be `https://github.com/getrdy-io/release-sandbox/.github/workflows/sign-release.yml@refs/tags/v0.1.0-alpha.2`), `claims:` (it must be `repository=getrdy-io/release-sandbox ref=refs/tags/v0.1.0-alpha.2 trigger=push`), `sha256:` and `rekor log:`. `announce` runs after it, its step "Verify the release signature" passes, and it goes green.
6. `gh release view v0.1.0-alpha.2 --repo getrdy-io/release-sandbox --json isPrerelease,isDraft,assets,isImmutable` (if the CLI has no `isImmutable`, use `gh api repos/getrdy-io/release-sandbox/releases/tags/v0.1.0-alpha.2 --jq .immutable`). The assets must include `SHA256SUMS` and `SHA256SUMS.sigstore.json`. Record `immutable`. If `announce` failed on `gh release create`, see ADR 0024, Consequences.
7. On a clean machine with no checkout, with cosign 3 installed: `gh release download v0.1.0-alpha.2 --repo getrdy-io/release-sandbox --dir /tmp/sbx`. In `/tmp/sbx` run the verification command from the contract table with the sandbox identity above and `--certificate-github-workflow-repository getrdy-io/release-sandbox --certificate-github-workflow-ref refs/tags/v0.1.0-alpha.2 --certificate-github-workflow-trigger push`. It must print `Verified OK`. Then `sha256sum --ignore-missing -c SHA256SUMS` must pass.
8. Tamper test. Change one byte of `SHA256SUMS` (`printf 'X' | dd of=SHA256SUMS bs=1 count=1 conv=notrunc`) and run the same `cosign verify-blob`. It must fail. Run the unchanged file with the identity of `getrdy-io/rdy` in place of the sandbox: it must fail too. Run the unchanged file once more with the sandbox identity but `--certificate-github-workflow-repository getrdy-io/rdy`: it must fail on the repository claim. That is the check that stops another repository's call of `sign-release.yml` from passing. Paste all four outputs.
9. Reject test. Push the tag `v0.1.0-alpha.3` (bump the versions first), and at the approval click "Reject". `sign` fails, `announce` does not run, and `gh release view` shows no release.
10. Record in the Done log of `11-backlog.md`: the run URL, the outputs of steps 4, 6, 7 and 8 (the four outputs of step 8), the Rekor log index and the sha256 of `SHA256SUMS` from step 5. Note the `immutable` value.

If step 3 never shows the waiting job, the environment name in the sandbox is not exactly `release`. If step 5 fails in `cosign sign-blob` with an OIDC error, the caller job lacks `id-token: write`: check `release.yml`.

## verify-release.sh and RELEASING.md (M1-012)

`scripts/verify-release.sh [--dir <folder>] <tag>` is the verification command in script form (05, Surface 3; `install.sh` follows the same contract). From the tag alone it downloads `SHA256SUMS` and `SHA256SUMS.sigstore.json` with `curl` (`--proto '=https' --proto-redir '=https' --tlsv1.2`, `--max-filesize` 1 MiB for these two). The URLs are only `github.com/getrdy-io/rdy/releases/download/<tag>/`. GitHub redirects the file bytes to its own asset host, so the script names one host but the transfer can touch another, over https only. It runs cosign 3.1.3 or newer (cosign 3.0.0 to 3.1.2 have GHSA-fx35-mq7g-6g98, where a legacy bundle skips the identity checks; a note when it differs from the pin in `.github/release-tools.txt`) and only on a bundle with the media type `application/vnd.dev.sigstore.bundle.v0.3+json`. It runs the full contract: issuer, exact identity, repository, ref and trigger. It refuses to run when `SIGSTORE_ROOT_FILE`, `SIGSTORE_REKOR_PUBLIC_KEY` or `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` is set. It copies the two signed-list files into a private temporary folder (with `--dir`, symbolic links are refused), verifies the copies by absolute path without changing directory, and reads only the copies, so the folder cannot change between check and use. Only after the signature passes does it read `SHA256SUMS`: plain file names only, the five archives must be listed, and every listed file is downloaded and its sha256 compared. It prints the sha256 of `SHA256SUMS` and the Rekor log index, which the founder records for each release. The repository and host are fixed in the script. Run it from a reviewed commit of `main`, not from the tag it checks. `--dir` checks files already on disk, but it is not an offline mode: cosign still fetches the Sigstore trust root (TUF) over the network, and with no network it fails closed with an error that looks like a bad signature. The honest route for a machine with no network is to verify on a connected machine, carry the files across, and on the target compare the sha256 of each file with its line in `SHA256SUMS` (see "Air-gapped route and trust roots"). A `--trusted-root` mode for fully offline verify moves to M2. Exit 0 verified, 1 a check failed, 64 usage, a missing or too old tool, or a set `SIGSTORE_*` trust variable. A missing cosign is never skipped.

The tests (`scripts/test-verify-release.sh`, in the `release-workflow` CI job) use a fake cosign and a stub `curl`. A wrong caller repository, ref and trigger each fail. The fake accepts the wrong caller when the claim flags are left off, so those tests prove the script passes them. A wrong identity, a changed byte, a changed archive, a missing archive, a missing bundle, an unsafe file name, cosign below 3.1.3, a bundle that is not v0.3, a set `SIGSTORE_*` trust variable, a tag with a newline, a symbolic link and an oversize file fail too, and each has a test that fails for that reason. The stub `curl` honors `-f`, `-w` and `--max-filesize`, so dropping one changes the result. `scripts/test-cosign-roundtrip.sh` parses the real `cosign version` output and checks the media type of a real bundle.

`RELEASING.md` is the founder's runbook: the one-time hand steps (the signing proof above, the `release` environment, the rulesets), the release PR (version bump, changelog assembly per ADR 0017), the tag push, the approval click, and the clean-machine `verify-release.sh` run that closes the M1-012 exit test. Agents never push the tag (ADR 0024).

## SBOM and auditable binaries

- `cargo-auditable` (`cargo-auditable = true`) embeds the dependency list in every binary. `cargo audit bin ./rdy` works on any shipped file. Confirmed in M1-007: the section survives `strip = "symbols"` (`[profile.dist]`), and `scripts/check-release-artifacts.sh` runs `cargo audit bin` on all five binaries.
- `cargo-cyclonedx` via dist (`cargo-cyclonedx = true`) produces one SBOM per package, not per target. M1 ships the SBOM dist makes for `rdy`, listed in `SHA256SUMS`. It is CycloneDX XML (`rdy.cdx.xml`): dist runs a fixed `cargo cyclonedx -v` and has no JSON setting (ADR 0020, decision 8; correction 07, PR #46). If per-target SBOMs are wanted later, generate them in `sign-release` from each shipped binary with `auditable2cdx`. That needs no build and describes the bytes we ship.

## install.sh behaviour

Served as a release asset in M1 and at `https://getrdy.io/install` from M2. The table above is the contract. The mechanics:

1. Parse `--allow-root`, `--help`. Anything else is exit 64.
2. Root check, then OS and CPU detection. `Linux` and `Darwin` only. `x86_64`/`amd64` and `aarch64`/`arm64`. On macOS, if `sysctl -n sysctl.proc_translated` is 1, choose arm64. Linux always gets the musl archive, so no glibc detection.
3. Pick `curl` or `wget`. Both honor `HTTPS_PROXY`. A TLS failure behind a corporate proxy prints `SSL_CERT_FILE` and `CURL_CA_BUNDLE` advice and the manual route.
4. Version: `RDY_VERSION`, else the version stamped into this copy of the script.
5. Download the archive, `SHA256SUMS` and `SHA256SUMS.sigstore.json` into a temp dir. Set `TUF_ROOT` inside the temp dir so cosign leaves nothing in `~/.sigstore`.
6. Find `cosign` (version 3 or newer). If absent, apply the contract row: stop, or continue on hash only with the override.
7. Run `cosign verify-blob` with the exact identity and the three caller claims (contract table). Compare the archive's sha256 with its line in `SHA256SUMS` (`sha256sum`, else `shasum -a 256`).
8. Extract, `chmod 0755`, run `rdy version`. Copy to `<dir>/.rdy.new.$$`, then `mv -f` for an atomic replace. If an old `rdy` exists, print old and new versions.
9. Print a PATH hint and the full path on stderr. Stdout stays empty. Exit 0, 1 (failure) or 64 (usage).

`install.sh` is built in two tickets. M1-014 has everything above except the cosign check: root refusal, the truncation guard, platform detection, the sha256 rule and the atomic install. Its seam is `verify_signature`, which M1-015 fills in. Until then a copy stops as if cosign were missing, unless `RDY_INSECURE_SKIP_SIGNATURE=1`. The details where the script is stricter than the list above (end marker on the last line, `--proto-redir`, no user config file for curl or wget, stall timeouts, GNU wget only, `mktemp` for the temp file, the version check on `rdy version`, a stop on any carriage return in `SHA256SUMS`) and the stamp that `sign-release` writes are in ADR 0025. The stop message for an unchecked signature gives the manual path (`scripts/verify-release.sh`) and does not name the override. Tests: `sh scripts/test-install-sh.sh` (dash, busybox sh in a pinned Alpine container, and macOS `/bin/sh`; stub `curl`).

Every error follows one shape: what happened, likely cause, what to do, under five lines. Cosign is not preinstalled on most hosts, so the first-run hit is real. The docs show a two-line cosign install; the override is the escape for a host that cannot reach Sigstore.

### Air-gapped route and trust roots

The documented manual path: on a connected machine download the archive, `SHA256SUMS` and its bundle; run the verification command above; carry the archive across on approved media; re-check its sha256 on the target; `tar -xzf` and `install -m 0755`.

Trust must not come from the channel being checked. So:

- We never publish a Sigstore trusted root. A copy shipped inside a release could be replaced together with the archive and bundle, and the attacker's bundle would then verify. For offline verification on the target, copy the root cosign itself fetched through Sigstore's TUF on the connected machine (the cache under `TUF_ROOT`, default `~/.sigstore/root/`) and pass it with `--trusted-root`. `scripts/verify-release.sh` has no such mode in M1, so `--dir` still needs the network (M2).
- What the founder must publish out of band, on `getrdy.io/security` and in `SECURITY.md` in the repo (two origins, neither a release asset):
  1. The expected OIDC issuer, repo, and signing workflow path.
  2. Per release: the sha256 of `SHA256SUMS` and the Rekor log index of its signature. A customer can compare these with what they downloaded, and the vendor's SE can relay them in the sales channel.
  3. The pinned cosign version and its release sha256.
- If GitHub and getrdy.io are both compromised, nothing here helps. This is stated in the docs.

### Serving (M2)

`curl ... | sh` has no `-L`, so the endpoint must answer 200 with the script, not redirect. The apex is already a Pages custom domain for the marketing site, and Pages cannot route one path to a second project. So a small Cloudflare Worker with a route on `getrdy.io/install` returns the newest release's stamped `install.sh`. The Worker picks the newest release that has `SHA256SUMS.sigstore.json`, caches the answer for five minutes, and reads GitHub with a read-only token held as a Worker secret. It is deployed by hand from the founder's machine with `wrangler login`. No Cloudflare secret lives in GitHub Actions. Domain and account hardening (SEC-05) comes first.

## Package managers

| Channel | Milestone | Note |
| --- | --- | --- |
| GitHub Releases + `install.sh` | M1 | Above. |
| Windows zip | M1 | Manual download and `cosign verify-blob`, documented. |
| crates.io | M2 | All crates published, per ADR 0007. Trusted publishing, no stored token. |
| Homebrew tap | M3 | `getrdy-io/homebrew-tap`, dist `homebrew` installer, one fine-grained token. |
| winget | M3 | Zip with a portable nested installer, submitted with `wingetcreate`. Confirm the entity name before choosing the package id. |
| `install.ps1` | M3 | Same checks as `install.sh`. |
| apt and yum | M5 | `.deb` and `.rpm` from the static binary with `nfpm`. Repo hosting and key are an ADR. |

macOS notarization and Windows signing cost money and are deferred to an M3 decision. Files fetched with `curl` carry no quarantine flag, so unsigned macOS binaries run from `install.sh`. A browser download is blocked by Gatekeeper, and SmartScreen warns on unsigned Windows executables (SEC-50).

## Self-update

Decision: defer to M3 (SEC-49, never automatic, same cosign verification as `install.sh`). In M1 the `rdy self-update` subcommand is left out, so there is nothing to stub. `install-updater = false` in dist. The `self_update` crate in the plan cannot verify cosign, and dist's updater only works for dist installers. Customers re-run the install command. The M3 trust-model options go in an ADR after a spike (Decisions below).

## Version and support policy

Follows ADR 0007.

- Versions are per crate. The `rdy` binary tag `vX.Y.Z[-pre]` equals the `rdy` package version only. dist releases the packages whose version equals the tag; libraries are not apps.
- M1: before `release-plz` exists, the `rdy` version is bumped by hand in a PR and tagged, following `RELEASING.md`. The tag is `v0.1.0-alpha.N`, weekly on a fixed weekday (suggest Thursday, Friday as buffer). Skipped weeks keep the number. When M1 core is done, tag `v0.1.0` (11-backlog.md calendar). After that, tag `v0.1.N` weekly until M1 ends, then `0.2.0-alpha.N` while building toward `0.2.0`. Never tag red; skip the week. From M4, every two weeks plus patches. Security fixes ship the same day.
- In 0.x a minor bump may break CLI flags and `--json`; a patch never does. The spec format `rdy/v1` and result schema have their own versions (ADR 0007 point 5).
- MSRV: edition 2024 needs Rust 1.85. Policy is stable minus two minor versions, a minor bump when raised, enforced by a CI job from M2 (it matters to `rdy-cloud`, not to binary users). `rust-toolchain.toml` pins an exact stable; bump it every six weeks.
- Support: 0.x supports the latest release only. From 1.0, the latest and previous minor get security fixes for six months. Platforms: Linux musl on any kernel Rust's musl targets support, macOS 11 or newer, Windows 10 and Server 2016 or newer. Check the exact aarch64 Linux floor against Rust's platform-support page before the first non-alpha.
- crates.io: `rdy-spec` and `rdy-engine` go to 1.0 at M3 (ADR 0007). `cargo-semver-checks` needs a published baseline, so it starts in M2 with the first real publish.

## Reproducible builds

M1 does the cheap part: exact toolchain, `--locked`, committed `Cargo.lock`, no cache in release jobs. M2 adds path remapping, `SOURCE_DATE_EPOCH` and a rebuild check in a pinned container; first check how dist passes `RUSTFLAGS` so extra flags go in one place. Known deviations are in Appendix D.

## Cost

Public repo, standard runners (including arm64 Linux and Intel macOS): $0, no minute cap. A private repo would get 2,000 minutes with macOS at 10x and Windows at 2x, about 12 full CI runs a month, which is why the repo is public from day one. Sigstore, GitHub Releases, Cloudflare Workers and Pages free tiers, crates.io, Homebrew and winget are free. Deferred paid items: Apple Developer ID (about $99 a year) and Windows signing. New spend in M1: $0. Verify at ticket time that arm64 Linux and `macos-15-intel` remain free for public repos.

## Appendix A: ci.yml skeleton and time budget

```yaml
test:
  runs-on: ${{ matrix.os }}
  timeout-minutes: 25
  permissions: { contents: read }
  strategy:
    fail-fast: false
    matrix:
      include:
        - { name: linux-x64,   os: ubuntu-24.04,     target: x86_64-unknown-linux-musl }
        - { name: linux-arm64, os: ubuntu-24.04-arm, target: aarch64-unknown-linux-musl }
        - { name: macos-arm64, os: macos-15,         target: aarch64-apple-darwin }
        - { name: macos-x64,   os: macos-15-intel,   target: x86_64-apple-darwin }
        - { name: windows-x64, os: windows-2022,     target: x86_64-pc-windows-msvc }
  steps:
    - uses: actions/checkout@<sha>
      with: { persist-credentials: false }
    - if: runner.os == 'Linux'
      run: sudo apt-get update && sudo apt-get install -y musl-tools
    - run: rustup target add ${{ matrix.target }}
    - uses: Swatinem/rust-cache@<sha>
      with:
        shared-key: test-${{ matrix.name }}
        save-if: ${{ github.ref == 'refs/heads/main' }}
    - uses: taiki-e/install-action@<sha>
      with: { tool: "cargo-nextest@<pinned>" }
    - run: cargo nextest run --workspace --locked --target ${{ matrix.target }}
```

Caching notes: PRs read the `main` cache and never write, which keeps the 10 GB quota clean and stops cache poisoning. Release builds never use the cache. Set `CARGO_PROFILE_DEV_DEBUG=line-tables-only` and `CARGO_INCREMENTAL=0`. No path filters (a path-filtered required check goes pending and blocks merges).

Time budget (targets; the test-matrix ticket measures them on real runs once there is real code):

| Job | Cold cache | Warm cache |
| --- | --- | --- |
| lint | 6 min | 2 min |
| deny, install-sh | 2 to 4 min | 1 to 2 min |
| test linux (each) | 9 min | 4 min |
| test macos (each) | 10 min | 5 min |
| test windows | 13 min | 7 min |
| `ci-ok` wall clock | about 13 min | under 8 min |

If Windows creeps past ten minutes warm: lighter `[profile.dev]`, then a faster drive for the target dir, then split slow integration tests. No paid runners.

## Appendix B: dist-workspace.toml

```toml
[workspace]
members = ["cargo:."]

[dist]
cargo-dist-version = "0.33.0"
ci = "github"
targets = [
  "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
  "aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
]
installers = []                 # M3 adds "homebrew"
unix-archive = ".tar.gz"
windows-archive = ".zip"
checksum = "sha256"
cargo-auditable = true
cargo-cyclonedx = true
github-attestations = false     # conflicts with the one-job id-token rule (ADR 0020); cosign is the signature
install-updater = false
precise-builds = true
fail-fast = false
github-release = "announce"     # no release exists until announce publishes, not even a draft (ADR 0020, 0024)
publish-jobs = ["./sign-release"]
pr-run-mode = "plan"

[dist.github-custom-runners]
x86_64-unknown-linux-musl = "ubuntu-24.04"
aarch64-unknown-linux-musl = "ubuntu-24.04-arm"
aarch64-apple-darwin = "macos-15"
x86_64-apple-darwin = "macos-15-intel"
x86_64-pc-windows-msvc = "windows-2022"

[dist.github-custom-job-permissions]
sign-release = { contents = "read", id-token = "write" }   # read: no release exists while it runs (M1-010)
```

Key names were confirmed in M1-007 by running `dist generate` 0.33.0. The live file is `dist-workspace.toml` at the repo root and wins over this block. It differs in these ways (ADR 0020 has the reasons):

- `github-release = "announce"`, not `"host"`. With `"host"`, dist 0.33.0 publishes the release in the host job, before any publish job runs.
- `github-attestations` is off. It gives the build jobs `id-token: write`, and the signing job is meant to be the only job with it.
- `publish-jobs = ["./check-release-artifacts", "./sign-release"]`, with `publish-prereleases = true`. M1-010 added `./sign-release`, which waits for the check (`scripts/harden-release-workflow.py` adds the `needs`). The check is a publish job because only publish jobs hold back the announce job when they fail.
- `allow-dirty = ["ci"]` turns off dist's own drift check. `release.yml` is dist's output plus `scripts/harden-release-workflow.py` (no default token, `contents: write` only in `announce`, tag shape check and tag passed through `env:`, pinned tool files, no containers, no `GH_TOKEN` in the build jobs). The CI job `release-workflow` regenerates it with `scripts/gen-release-workflow.sh --check` and fails on any difference (ADR 0020, decisions 1 and 5).
- `github-build-setup = "../build-setup.yml"` installs the pinned toolchain and the target, and points C code at `musl-gcc`.
- `[dist.github-action-commits]` pins the three actions dist uses to commit SHAs.
- `aarch64-apple-darwin` builds on `macos-15-intel` while the org has no macOS arm64 runners (ADR 0006, decision 8).
- `[dist.github-custom-job-permissions]` gives the check `contents: read` only, and `sign-release` `contents: read` plus `id-token: write` (M1-010). `announce` is still the only job that writes contents.
- Cargo.toml has `[profile.dist]`, which dist needs. `xtask` sets `dist = false`.

## Appendix C: release assets

| Asset | Contents |
| --- | --- |
| `rdy-<triple>.tar.gz` (`.zip` on Windows) | `rdy-<triple>/` with `rdy` (`rdy.exe`), `LICENSE`, `README.md`, `CHANGELOG.md` |
| `rdy-<triple>.tar.gz.sha256`, `sha256.sum` | dist's checksums, checked by `sign-release` |
| SBOM | the CycloneDX file dist makes for `rdy` |
| `install.sh` | this tag's copy, version stamped in |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | the signed list of every asset above, and its bundle |
| `source.tar.gz` | source archive |

File names carry the target, not the version. The version is in the download URL.

## Appendix D: reproducibility deviations

| Deviation | Why | Mitigation |
| --- | --- | --- |
| macOS and Windows not expected bit-for-bit | Apple ad-hoc signing, MSVC timestamps and PDB paths | Documented. Provenance attestation and signed sources cover the trust question |
| Runner images change | `musl-tools`, Xcode, MSVC versions move | Rebuild Linux in a pinned container; record image versions in release notes |
| C code in dependencies (`ring`) | Compiler version differences | Same pinned container |
| Signatures differ each run | Per-signing certificates and timestamps | Expected. The bytes are what we claim to reproduce |
| SBOM names the runner's build path | cargo-cyclonedx writes `bom-ref` values like `path+file:///home/runner/work/rdy/rdy/crates/rdy-cli#rdy@...` and a timestamp | Expected and public. Not a secret. Per-target SBOMs from `auditable2cdx` would avoid it |
| Release tool hashes are trusted on first read | dist and cargo-cyclonedx are pinned in `.github/release-tools.txt` with hashes read from the projects' release pages. cargo-auditable is pinned by version through a SHA-pinned install action (ADR 0020, decision 6) | A later change fails the build. A tool that was already malicious on the day it was pinned is not caught. M2 can add a rebuild check |
| tar and zip metadata | Mtimes, file order | `SOURCE_DATE_EPOCH`; check whether dist honors it, else repack in `sign-release` |

## Plan corrections found

- `docs/plan/05-threat-model.md`, Surface 3 (identity and verification command): the identity is `release.yml` and the regexp ends in `[0-9]+$`. dist signs from a called workflow, so the certificate carries `sign-release.yml`, and the regexp rejects every `-alpha.N` tag. Fix: use the identity and exact-version pin in the contract table.
- `docs/plan/05-threat-model.md`, Surface 3 (checksum file): `SHA256SUMS` is not dist's file name (`sha256.sum`). Fix: `sign-release` writes `SHA256SUMS` over all assets; 05 refers to the contract table.
- `docs/plan/05-threat-model.md`, SEC-02, SEC-05, SEC-11 are scheduled in M1 but total about 5 hours of release work beyond the 24-hour cap. Fix: SEC-02 and SEC-11 move to M2 (nothing is published before M2, the `deny` job covers advisories). SEC-05 moves to M2 with the Worker, before `getrdy.io/install` serves anything. SEC-10 (qa-engineer) is merged into the install.sh tickets and reviewed by qa-engineer.
- `docs/adr/0011-binary-name-and-cli-package.md`, Consequences: "artefacts are `rdy-<target>.tar.xz`". Fix: `.tar.gz`, as configured here.
- `docs/plan/rdy-plan.md`, Release engineering: "`cargo-zigbuild` for cross-compiling" is stale. Native arm64 runners remove the need (ADR 0006 keeps zigbuild as a fallback only). "cargo-dist" is now `dist`, config in `dist-workspace.toml`. Crate table lists `self_update` for `rdy-cli`; it cannot verify cosign and self-update is deferred to M3.
- `docs/plan/rdy-plan.md`, user flow step 1 and `CLAUDE.md` Names and places: `curl ... | sh && rdy run ...` fails when `~/.local/bin` is not on `PATH` in that shell, and many customer shells are root, which `install.sh` refuses without `--allow-root`. Fix: the sales one-liner calls `"$HOME/.local/bin/rdy"`, and docs explain `sh -s -- --allow-root`.
- `CLAUDE.md`, Repo layout: add `sign-release.yml`, `dist-workspace.toml`, `.cargo/config.toml`, `RELEASING.md`, `scripts/verify-release.sh`. Engineering standards say "CI runs all four" but there are five legs.
- `docs/plan/rdy-plan.md`, public repo: nothing says the repo is public from week one. Private CI runs out of free minutes in about a dozen runs. Fix: create `getrdy-io/rdy` as public before the first CI ticket. The plan file also holds pricing and employment-agreement rows; the founder decides what stays public first (see `09-docs-site.md`).
- `KICKOFF.md`, M1 scope: "signing" reads as spec signing only. Release signing lands in weeks 1 to 2. Fix: say "spec signing and release signing".
- Runner label `macos-13` is retired; any template using it is stale.
- Appendix B and the immutable-release note (found in M1-007, ADR 0020): `github-release = "host"` publishes the release in the host job in dist 0.33.0, so it is not a draft until announce. Use `"announce"`. A failed host job does not stop announce, so the artifact check is a publish job. `github-attestations = true` conflicts with the one-job `id-token` rule.
- dist 0.33.0 writes a workflow with a `contents: write` token in every job, unhashed `curl | sh` tool installers, a trigger that matches any tag, and the tag name inside shell text (found in the PR #47 security review). `scripts/harden-release-workflow.py` fixes each and a CI job checks the result (ADR 0020, decision 5).
- M1-010 (found while building it, ADR 0024): the plan says `sign-release` downloads the draft's assets and uploads to the draft, with `contents = write`. With `github-release = "announce"` (ADR 0020) there is no draft while signing runs. The job reads the workflow's artifacts, hands three files to `announce` as an artifact, and needs only `contents: read` and `id-token: write`. The exit test's "stays a draft until signing ends" reads "no release exists, not even a draft, until signing ends".
- M1-007 exit test: "the SBOM is valid JSON". dist's SBOM is CycloneDX XML. Fix: "the SBOM is valid CycloneDX (XML or JSON)" (correction 07, PR #46).

## Decisions needing an ADR

- install.sh when cosign is missing. Taken for M1, per 05: fail closed with the named override. Release-engineer's view: this makes the first run harder than needed. Alternative (d): download a cosign whose version and sha256 are written in the script, adding about 30 MB and one more pinned artifact. 05's options (b) hash only and (c) pinned ECDSA key remain open. Revisit after design partners try it; M2 ticket if chosen.
- Immutable releases against dist ordering. 05 requires immutable releases in M1. Settled by ADR 0020 and 0024: `github-release = "announce"`, so no release exists, not even a draft, until `announce` publishes. Still unproven until the sandbox run: that one `gh release create` with all assets makes the release immutable. If it does not, `announce` creates a draft, uploads, then publishes (ADR 0024, Consequences).
- Where the Worker token lives and who deploys it. Taken: founder deploys by hand, no Cloudflare secret in Actions. Alternative: a deploy workflow in a restricted GitHub environment, with a token in a separate Cloudflare account.
- Self-update trust model (M3). Options: shell out to `cosign`, the `sigstore` crate if its tree is rustls-only, or an offline ed25519 release key. Lean: the crate if a spike is clean.
- macOS notarization and Windows signing (M3). Paid. Options: neither, both, or Homebrew and winget only.
- apt and yum hosting and repo key (M5). Options: self-hosted on object storage with a GPG key, or a hosted free OSS tier.
- Pinning dist at 0.33.0, with a hand-written workflow as the fallback.
- Per-release approval click in environment `release`. Accepted from 05 (E2). It adds a minute to each weekly release and a dependency on the founder being at a keyboard. No alternative proposed.

## Tickets implied

M1 release-engineer work: 24 hours, 8 tickets. Each carries the 05 or ADR ticket it closes. SEC-10 is qa-engineer's; qa-engineer reviews the tamper tests inside the two install.sh tickets.

- [M1] CI lint and deny job: fmt, clippy, doc, cargo-deny, zizmor (SEC-01) | owner: release-engineer | est: 2h | depends on: Create workspace skeleton | exit test: a PR is green, and throwaway PRs that add a clippy warning and add `openssl` both turn it red
- [M1] CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | owner: release-engineer | est: 4h | depends on: CI lint and deny job: fmt, clippy, doc, cargo-deny, zizmor (SEC-01) | exit test: a run with all five legs green, both Linux binaries pass the `readelf` no-INTERP and no-NEEDED check and run in a scratch container, and a PR with one red leg cannot merge
- [M1] Rulesets on main and v* tags, Dependabot, SHA-pinned actions (SEC-03, SEC-04) | owner: release-engineer | est: 1h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: a direct push to `main` and a non-admin `v*` tag are rejected, the Dependabot job shows a green run in Insights, and a grep finds no `uses:` line without a commit SHA
- [M1] dist init for five targets with cargo-auditable and SBOM, proven in release-sandbox | owner: release-engineer | est: 3h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: a tag in `getrdy-io/release-sandbox` builds five archives with checksums, `cargo audit bin` lists dependencies from a downloaded binary, the SBOM is valid JSON, and `rdy.exe` imports no `VCRUNTIME140.dll`
- [M1] sign-release with cosign keyless, SHA256SUMS and self-verify (SEC-06, SEC-07) | owner: release-engineer | est: 4h | depends on: dist init for five targets with cargo-auditable and SBOM, proven in release-sandbox | exit test: in the sandbox, the signing job waits for approval, no release exists, not even a draft, until signing ends, and it is then published immutable, `cosign verify-blob` with the exact identity passes on a clean machine and fails after changing one byte of `SHA256SUMS`
- [M1] First signed alpha, scripts/verify-release.sh and RELEASING.md | owner: release-engineer | est: 2h | depends on: sign-release with cosign keyless, SHA256SUMS and self-verify (SEC-06, SEC-07) | exit test: `v0.1.0-alpha.1` exists on `getrdy-io/rdy` and `scripts/verify-release.sh v0.1.0-alpha.1` passes on a clean Linux machine
- [M1] install.sh core with root refusal, truncation guard, sha256 and shell tests (SEC-08) | owner: release-engineer | est: 4h | depends on: dist init for five targets with cargo-auditable and SBOM, proven in release-sandbox | exit test: shellcheck is clean, the shell tests pass under dash and busybox sh, uid 0 without `--allow-root` exits 1 with the fix, and a cut-off script run installs nothing
- [M1] install.sh signature check, fail closed, with tamper tests (SEC-09, SEC-10) | owner: release-engineer | est: 4h | depends on: install.sh core with root refusal, truncation guard, sha256 and shell tests (SEC-08), First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: with a real cosign the alpha.1 install passes, and bad hash, bad signature, wrong identity, missing bundle and missing cosign (with and without the override) each fail with the documented message
- [M2] Reserve crates.io names with 0.0.1 placeholders (SEC-11) | owner: release-engineer | est: 1h | depends on: none | exit test: all nine crate names plus `rdy-cli` show as owned by the `getrdy-io` team
- [M2] Scheduled audit.yml: cargo-audit, deny advisories, issue on failure (SEC-02) | owner: release-engineer | est: 2h | depends on: CI lint and deny job: fmt, clippy, doc, cargo-deny, zizmor (SEC-01) | exit test: a `workflow_dispatch` run on a branch pinning a vulnerable crate opens a `security` issue
- [M2] MSRV job and six-weekly toolchain bump reminder | owner: release-engineer | est: 1h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: raising a dependency's MSRV above the declared one turns the job red
- [M2] release-smoke on main: release build, binary size budget, cargo audit bin | owner: release-engineer | est: 2h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: a push to `main` runs it on five legs and a binary over budget fails it
- [M2] Publish crates with trusted publishing and release-plz per-crate versions (ADR 0007) | owner: release-engineer | est: 7h | depends on: Reserve crates.io names with 0.0.1 placeholders (SEC-11) | exit test: a dry run opens a release PR bumping only changed crates, and a real publish of `rdy-spec` needs no stored token
- [M2] cargo-semver-checks in CI for rdy-spec and rdy-engine (ADR 0007) | owner: release-engineer | est: 2h | depends on: Publish crates with trusted publishing and release-plz per-crate versions (ADR 0007) | exit test: a PR that removes a public field without a bump fails CI
- [M2] Post-release verify job on four environments and the Windows zip | owner: release-engineer | est: 3h | depends on: First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: after a tag, a run installs from the real release on ubuntu x64, ubuntu arm64, macOS arm64 and an Alpine container (one without cosign, to prove the fail-closed message) and verifies the Windows zip
- [M2] Harden getrdy.io domain and hosting accounts (SEC-05) | owner: release-engineer | est: 2h | depends on: none | exit test: registrar lock, DNSSEC, CAA and HSTS check out with public tools, and hardware-key MFA is confirmed on registrar and Cloudflare
- [M2] Worker route serving install.sh at getrdy.io/install | owner: release-engineer | est: 3h | depends on: Harden getrdy.io domain and hosting accounts (SEC-05), First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: `curl -sSf https://getrdy.io/install` returns 200 with bytes identical to the newest release's `install.sh`
- [M2] Publish out-of-band trust anchors on getrdy.io/security and SECURITY.md | owner: release-engineer | est: 2h | depends on: Worker route serving install.sh at getrdy.io/install | exit test: the page lists issuer, workflow path, cosign version and hash, and each release's `SHA256SUMS` digest and Rekor index, and the digests match the release
- [M2] Reproducibility flags and rebuild check in a pinned container | owner: release-engineer | est: 8h | depends on: First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: `scripts/repro-check.sh` reports the same sha256 for the Linux x64 musl binary of a released tag
- [M2] install.sh offline mode from a local folder with a TUF-cached trust root | owner: release-engineer | est: 4h | depends on: install.sh signature check, fail closed, with tamper tests (SEC-09, SEC-10) | exit test: on a host with the network blocked, the script verifies and installs from a local folder
- [M2] Allocator benchmark musl against glibc in CI (ADR 0006) | owner: release-engineer | est: 2h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: CI prints both timings and fails above the 20 percent threshold
- [M2] Nightly coverage job, not gating | owner: release-engineer | est: 3h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: a nightly run uploads an lcov report and shows a percentage
- [M3] Homebrew tap and dist homebrew installer | owner: release-engineer | est: 4h | depends on: First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: `brew install getrdy-io/tap/rdy` installs the latest release and `brew test` passes
- [M3] winget manifest and submission automation | owner: release-engineer | est: 6h | depends on: First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: a winget-pkgs PR passes validation and `winget install` works on a clean Windows VM
- [M3] Windows install.ps1 with the same verification as install.sh | owner: release-engineer | est: 4h | depends on: install.sh signature check, fail closed, with tamper tests (SEC-09, SEC-10) | exit test: on a clean Windows VM the script installs and fails closed on a tampered zip
- [M3] macOS notarization and Windows signing, after ADR (SEC-50) | owner: release-engineer | est: 8h | depends on: ADR for code signing | exit test: a browser-downloaded archive runs on macOS without a Gatekeeper block and `rdy.exe` shows a verified publisher
- [M3] Self-update spike and ADR | owner: release-engineer | est: 4h | depends on: First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: an ADR picks a verification method, backed by a Rust test that verifies a signed manifest
- [M3] Verified, explicit self-update (SEC-49) | owner: release-engineer | est: 12h | depends on: Self-update spike and ADR | exit test: a tampered or wrong-identity release is refused, and a good one upgrades alpha N to N+1 on all five platforms and rolls back if the new binary fails `rdy version`
- [M3] Verify reproducible builds across independent builders (SEC-51) | owner: release-engineer | est: 8h | depends on: Reproducibility flags and rebuild check in a pinned container | exit test: two independent builds of a tag match, or the deviations are documented
- [M5] deb and rpm packages with nfpm | owner: release-engineer | est: 8h | depends on: First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: `dpkg -i` and `rpm -i` install on Debian and Rocky containers and `rdy version` runs
- [M5] apt and yum repository hosting with signed metadata | owner: release-engineer | est: 12h | depends on: deb and rpm packages with nfpm | exit test: `apt install rdy` and `dnf install rdy` work from the public repo on clean containers with the repo key verified
