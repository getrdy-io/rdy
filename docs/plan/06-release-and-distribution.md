# Release and distribution plan

Owner: release-engineer. Written 2026-10-27. Scope: CI, release automation, signing, SBOM, install script, package managers, self-update, version policy. It does not design the CLI or the engine.

## Summary

Five things to know before reading the rest.

1. CI runs on five native runners (Linux x86_64 musl, Linux aarch64 musl, macOS arm64, macOS x86_64, Windows x86_64). Nothing is cross-compiled in CI. One aggregate job, `ci-ok`, is the only required check.
2. Releases are built by `dist` (the tool formerly called cargo-dist), pinned to an exact version, with the generated workflow committed. We do not need `cargo-zigbuild` or `cross`. Native GitHub arm64 runners build aarch64 musl.
3. Every release asset is signed with cosign keyless (GitHub OIDC). A customer verifies one archive with one `cosign verify-blob` command that pins our workflow identity.
4. `install.sh` verifies sha256 and the cosign signature by default. If `cosign` is not installed, the script downloads a pinned cosign whose sha256 is written in the script. Skipping the signature check is an explicit opt-out with a loud warning.
5. Self-update is deferred. In M1 `rdy self-update` prints the install command. A design for M3 is sketched below.

The repo must be public from the first commit. That makes every CI minute free (see Cost).

## CI matrix

| Leg | Runner | Rust target | Runs |
| --- | --- | --- | --- |
| linux-x64 | `ubuntu-24.04` | `x86_64-unknown-linux-musl` | build, nextest, doc tests, static-link check |
| linux-arm64 | `ubuntu-24.04-arm` | `aarch64-unknown-linux-musl` | build, nextest, static-link check |
| macos-arm64 | `macos-15` | `aarch64-apple-darwin` | build, nextest |
| macos-x64 | `macos-15-intel` | `x86_64-apple-darwin` | build, nextest |
| windows-x64 | `windows-2022` | `x86_64-pc-windows-msvc` | build, nextest |

Rules:

- Pin runner images by name, never `-latest`. Review the names every April and October.
- Linux tests run against the musl target, so CI tests the binary we ship, not a glibc cousin.
- Windows builds link the C runtime statically (`-C target-feature=+crt-static` in `.cargo/config.toml`), so customers need no VC redistributable.
- macOS builds set `MACOSX_DEPLOYMENT_TARGET=11.0`. The spike ticket confirms what rustc actually writes into the binary.
- The Intel macOS image (`macos-15-intel`) is the last x86_64 hosted image. GitHub retired `macos-13` in late 2025. Verify the retirement date when writing the CI matrix ticket. If the Intel leg is slow or dies, build `x86_64-apple-darwin` on the arm64 runner (Apple's toolchain cross-compiles cleanly) and run its tests nightly only.
- Fork PRs run with a read-only token. No `pull_request_target` anywhere.

### Jobs and what gates merge

| Job (in `ci.yml`) | Runs on | Gates merge | What it does |
| --- | --- | --- | --- |
| `lint` | ubuntu-24.04 | yes | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS=-D warnings` |
| `deny` | ubuntu-24.04 | yes | `cargo deny check` (licenses, bans, sources, advisories) |
| `msrv` | ubuntu-24.04 | yes | `cargo +<msrv> check --workspace --locked` |
| `test` (5 legs) | table above | yes | build, `cargo nextest run`, then on Linux x64 `cargo test --doc` |
| `dist-check` | ubuntu-24.04 | yes | `dist generate --mode=ci --check` fails if `release.yml` drifted; `dist plan` proves the config parses |
| `install-sh` | ubuntu-24.04, macos-15 | yes | `shellcheck install.sh`, then run it against a local fixture release server (ticket "install.sh CI tests") |
| `release-smoke` | the 5 legs | no, main pushes only | `cargo build --release --locked -p rdy`, run `rdy version`, check static linking, check binary size budget, `cargo audit bin` |
| `ci-ok` | ubuntu-24.04 | yes, the only required check | `needs:` all of the above, `if: always()`, fails if any need failed or was cancelled |

Why one aggregate job: matrix legs rename when the matrix changes, and a renamed required check blocks every PR. `ci-ok` never renames.

Coverage is tracked, not gated (CLAUDE.md). A nightly `cargo-llvm-cov` job is an M2 ticket.

Repo settings (ticket "Repo settings, rulesets and Dependabot"):

- Ruleset on `main`: PR required, `ci-ok` required, linear history, no force-push, no deletion, zero required approvals (one founder; `code-reviewer` comments but cannot approve).
- Ruleset on tags `v*`: only repo admins create them, no update, no delete. Tags never move. A failed release burns the version number (`alpha.4` failed, ship `alpha.5`).
- Actions: default `GITHUB_TOKEN` read-only, approval required for first-time contributors' workflow runs.
- Dependabot: `cargo` weekly and grouped, `github-actions` weekly. Every third-party action is pinned to a commit SHA with the version in a comment.

### Caching and the ten-minute budget

- `Swatinem/rust-cache`, one `shared-key` per leg. `save-if` is true only on `main`, so PRs read the `main` cache and never write. This keeps the 10 GB repo cache quota clean and stops a PR from poisoning the cache.
- `CARGO_INCREMENTAL=0` and reduced debug info (`CARGO_PROFILE_DEV_DEBUG=line-tables-only`). Smaller caches, faster link.
- Tools come from `taiki-e/install-action` (prebuilt, version pinned): `cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-cyclonedx`, `cargo-auditable`, `zizmor`. No `cargo install` in CI, ever.
- `--locked` on every cargo command. `Cargo.lock` is committed.
- Release builds do not use the cache. A cache hit must never be able to alter a shipped binary.
- No path filters. Path-filtered required checks go pending and block merges. Docs-only PRs pay the full run. If that hurts, cache hits make it cheap.

Time budget (targets; ticket "ci-ok gate job and timing check" measures them on three consecutive runs):

| Job | Cold cache | Warm cache |
| --- | --- | --- |
| lint | 6 min | 2 min |
| deny, msrv, dist-check, install-sh | 2 to 4 min each | 1 to 2 min |
| test linux (each) | 9 min | 4 min |
| test macos (each) | 10 min | 5 min |
| test windows | 13 min | 7 min |
| `ci-ok` wall clock | about 13 min | under 8 min |

Cold runs (a new dependency set, an evicted cache) can pass ten minutes. The rule is: warm PR runs finish under ten minutes. If Windows creeps over, first try a lighter `[profile.dev]`, then move its target dir to the faster drive, then split slow integration tests into a second job. Do not add paid larger runners.

## Workflow files

CLAUDE.md lists `ci.yml`, `release.yml`, `audit.yml`. We add a fourth, `sign-release.yml`, called by `release.yml`. See Plan corrections.

### ci.yml

Triggers: `pull_request`, `push` to `main`. `concurrency` cancels superseded PR runs but never `main` runs. Top-level `permissions: {}`, each job grants `contents: read` only. Jobs are the table above. Test job skeleton:

```yaml
test:
  runs-on: ${{ matrix.os }}
  timeout-minutes: 25
  permissions: { contents: read }
  strategy:
    fail-fast: false
    matrix:
      include:
        - { name: linux-x64,   os: ubuntu-24.04,    target: x86_64-unknown-linux-musl }
        - { name: linux-arm64, os: ubuntu-24.04-arm, target: aarch64-unknown-linux-musl }
        - { name: macos-arm64, os: macos-15,        target: aarch64-apple-darwin }
        - { name: macos-x64,   os: macos-15-intel,  target: x86_64-apple-darwin }
        - { name: windows-x64, os: windows-2022,    target: x86_64-pc-windows-msvc }
  steps:
    - uses: actions/checkout@<sha>        # pinned
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

### release.yml

Generated by `dist generate`. Never edited by hand. `dist-check` fails CI if it drifts. Trigger: push of a tag matching a semver pattern, which includes `v0.1.0-alpha.3`. Stages (names as in current dist):

1. `plan`: reads tags and config, decides what to build.
2. `build-local-artifacts`: one job per target, on the runner from `github-custom-runners`. Builds with `--locked`, cargo-auditable, makes the archive and its sha256, makes the per-target SBOM.
3. `build-global-artifacts`: unified `sha256.sum`, source tarball.
4. `host`: uploads to GitHub Releases.
5. Our custom job `./sign-release` (see ordering note below).
6. `announce`: publishes the release with notes from `CHANGELOG.md`.

Permissions: `contents: write` only on the host and announce jobs. `id-token: write` and `attestations: write` only where needed.

### sign-release.yml

A reusable workflow (`on: workflow_call`). Job steps:

1. `permissions: { contents: write, id-token: write }`. No checkout of repo code. It only handles release assets.
2. Download all release assets with `gh release download "$TAG"`.
3. Check each archive against `sha256.sum` before signing. This catches a tampered upload between build and sign.
4. Install cosign 3.x (pinned `sigstore/cosign-installer` SHA and an exact cosign version).
5. For every archive, `sha256.sum`, and SBOM file: `cosign sign-blob --yes --bundle "$f.sigstore.json" "$f"`.
6. Sign `install.sh` the same way and upload it as a release asset.
7. `gh release upload "$TAG" *.sigstore.json install.sh`.

Ordering note. Best case: `github-release = "host"` plus `publish-jobs = ["./sign-release"]` leaves the release as a draft until `announce`, so no customer ever sees an unsigned release, and this also works if we later turn on GitHub immutable releases. I am not sure dist drafts in that mode. The sign-release ticket verifies it. Fallback: `post-announce-jobs`. There is then a few minutes of unsigned public release. `install.sh` fails closed on a missing signature, so the window is harmless, but immutable releases cannot be enabled in that case.

### audit.yml

Triggers: daily cron (06:17 UTC), PRs that touch `Cargo.lock`, `deny.toml` or `.github/`, and `workflow_dispatch`.

| Job | What | On failure |
| --- | --- | --- |
| `cargo-audit` | `cargo audit` against the RustSec DB. Fails on vulnerabilities. Warnings (unmaintained, yanked) are reported, not fatal | cron run opens or updates one GitHub issue labelled `security` |
| `deny-advisories` | `cargo deny check advisories` | same |
| `zizmor` | static analysis of `.github/workflows/*` (injection, excessive permissions, unpinned actions) | blocks PRs that touch workflows |

`cargo-audit` and `cargo-deny` read the same database. We keep both because CLAUDE.md asks for both and the cost is a minute.

## cargo-dist configuration

### Which version, and who owns it

- The tool is now called `dist`, the crate and repo still say `cargo-dist`. Config moved from `[workspace.metadata.dist]` in `Cargo.toml` to `dist-workspace.toml` in 0.23 (2024).
- Lookup on 2026-10-27: releases are still published at `github.com/axodotdev/cargo-dist`. The latest release was v0.33.1 (2026-10-21, dependency updates only). The previous one, v0.33.0 (2026-09-10), is the version I propose to pin, since it is more than two weeks old and has no known problems.
- The maintainers changed in 2025. Astral ran its own fork for `uv`, and 0.29.0 (2025-07-31) merged all of the fork's features back and removed support for the Axo Releases hosting service. I could not confirm the current owning org from the releases page. Treat it as community maintained.
- Risk control: pin the exact version, commit the generated `release.yml`, keep the dist surface small (no installers in M1). If the project stalls, the fallback is a hand-written release workflow, about a day of work, because all the hard parts (signing, SBOM, install.sh) already live outside dist.

### Config

```toml
# dist-workspace.toml
[workspace]
members = ["cargo:."]

[dist]
cargo-dist-version = "0.33.0"
ci = "github"
targets = [
  "x86_64-unknown-linux-musl",
  "aarch64-unknown-linux-musl",
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "x86_64-pc-windows-msvc",
]
installers = []                 # M1. M3 adds "homebrew".
unix-archive = ".tar.gz"        # busybox and minimal hosts may lack xz
windows-archive = ".zip"
checksum = "sha256"
cargo-auditable = true
cargo-cyclonedx = true
github-attestations = true
install-updater = false
precise-builds = true           # build only the rdy package
fail-fast = false
github-release = "host"         # see ordering note; the sign-release ticket may change this
publish-jobs = ["./sign-release"]
pr-run-mode = "plan"

[dist.github-custom-runners]
x86_64-unknown-linux-musl = "ubuntu-24.04"
aarch64-unknown-linux-musl = "ubuntu-24.04-arm"
aarch64-apple-darwin = "macos-15"
x86_64-apple-darwin = "macos-15-intel"
x86_64-pc-windows-msvc = "windows-2022"
```

Treat key names as "confirmed by running `dist init` in the dist init ticket". The dist docs I could reach confirm the installer list, attestations and the custom-runners table. They did not confirm every key above.

### Archive layout and files per release

For tag `v0.1.0-alpha.3`, GitHub release assets:

| Asset | Contents |
| --- | --- |
| `rdy-<triple>.tar.gz` (Linux, macOS) or `.zip` (Windows) | one top directory `rdy-<triple>/` holding `rdy` (or `rdy.exe`), `LICENSE`, `README.md`, `CHANGELOG.md` |
| `rdy-<triple>.tar.gz.sha256` | sha256 of that archive |
| `sha256.sum` | all checksums in one file, `sha256sum -c` compatible |
| `rdy-<triple>.cdx.json` | CycloneDX SBOM for that target |
| `<asset>.sigstore.json` | cosign bundle (signature, certificate, transparency log proof) for every asset above |
| `install.sh`, `install.sh.sigstore.json` | the install script as of that tag |
| `source.tar.gz` | source archive |

File names carry the target but not the version. The version is in the download URL. This is dist's default and the install script relies on it.

### musl, zigbuild, cross

- dist does not make musl cross-compilation magic. It installs the Rust target and calls cargo. On a runner of the same CPU as the target, a musl build needs only `musl-tools`.
- Known failure: building `aarch64-unknown-linux-musl` on an x86_64 runner fails when `ring` cannot find `aarch64-linux-musl-gcc` (dist issue 1581). Recent rustc also passes a linker flag that zig rejects unless `cargo-zigbuild` is 0.23 or newer. Both are cross-compilation problems.
- Our answer: avoid cross-compilation. GitHub's free arm64 Linux runner builds aarch64 musl natively with `musl-tools`. So `cargo-zigbuild` and `cross` are not needed, and the plan's line "cargo-zigbuild for cross-compiling" is stale for us.
- The native musl build may still need `CC_aarch64_unknown_linux_musl=musl-gcc` for `ring`. The dist init ticket settles this by building both musl targets and running `file` plus `ldd` on the result: it must say "statically linked" and `ldd` must refuse it.
- Fallback if the arm64 runner is unavailable or unreliable: `cargo-zigbuild` on x86_64 (dist 0.32 made cargo-auditable work with it). Keep this as a documented fallback, not a build path.
- TLS crypto backend (ring or aws-lc-rs) is rust-architect's call. For release it matters: `aws-lc-sys` needs a C and C++ toolchain per target and is the harder musl case. Prefer `ring` for M1. Flag this to rust-architect.

## Signing and verification

### What gets signed and how

- Tool: cosign 3.x keyless. No long-lived key exists, so no key can leak. GitHub issues an OIDC token to the `sign-release` job, Sigstore Fulcio turns it into a short-lived certificate, the signature and certificate go into the `.sigstore.json` bundle and a record goes into the Rekor transparency log.
- Cosign 3 changed flags: one `--bundle` file replaces `--output-signature` and `--output-certificate`. Recent cosign also refuses keyless `verify-blob` unless an identity is given. Newer work in cosign (PRs in October 2026) makes bundle-only verification mandatory. Pin the cosign version in the workflow and in `install.sh`, and re-test on each bump.
- The certificate identity is the workflow that ran the signing job. Because signing lives in a called workflow, the identity is the path of `sign-release.yml`, not `release.yml`. The sign-release ticket signs a real release and records the exact string. That string goes into `install.sh`, `scripts/verify-release.sh` and the docs.
- Second layer: dist's `github-attestations = true` adds GitHub artifact attestations (SLSA build provenance). It is one config line. Customers with `gh` can run `gh attestation verify`. Cosign is the primary path because it needs no GitHub account.
- Specs are not signed with cosign. They use the vendor's ed25519 key (CLAUDE.md rule 3). Do not mix the two.

### Customer verification

Expected identity: the `sign-release.yml` workflow in `getrdy-io/rdy`, run from a version tag. Exact form (replace the version):

```sh
cosign verify-blob \
  --bundle rdy-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml@refs/tags/v0.1.0-alpha.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  rdy-x86_64-unknown-linux-musl.tar.gz
sha256sum -c rdy-x86_64-unknown-linux-musl.tar.gz.sha256
```

To accept any release, use `--certificate-identity-regexp` with an anchored pattern:
`^https://github\.com/getrdy-io/rdy/\.github/workflows/sign-release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)*$`.
Never use a loose regexp such as `.*`. That accepts a bundle signed by any identity at all.

Other checks a security reviewer can run: `gh attestation verify <file> --repo getrdy-io/rdy`, and `cargo audit bin rdy` to list dependencies baked into the binary.

## SBOM and auditable binaries

- `cargo-auditable`: dist builds with it (`cargo-auditable = true`). The dependency list sits inside the binary, so `cargo audit bin ./rdy` works on any shipped file, even years later. `release-smoke` and the post-release job both run it. Check that `strip` keeps the section (ticket "cargo-auditable, CycloneDX SBOM and reproducibility flags").
- `cargo-cyclonedx`: one CycloneDX 1.5 JSON per target triple, because dependencies differ by OS (`nix` on Linux, `windows-sys` on Windows). Named `rdy-<triple>.cdx.json`, signed like every other asset. dist 0.2x and later can generate it (`cargo-cyclonedx = true`). The SBOM ticket checks that the output covers the `rdy` binary and its normal dependencies, not every workspace crate. If it does not, replace with one explicit `cargo cyclonedx` step in `sign-release`.
- SBOM validity check in CI: parse with `jq` and assert a non-empty `components` array and the right `metadata.component.version`.

## install.sh behaviour

Served at `https://getrdy.io/install`, and attached to every release as a signed asset. POSIX `sh` only (must run under dash, busybox ash and macOS sh). `shellcheck` clean. No `sudo`, ever.

Environment variables (all optional): `RDY_VERSION`, `RDY_INSTALL_DIR`, `RDY_ALLOW_ROOT=1`, `RDY_VERIFY=full|checksum`. There is no variable that changes the download host. Tests put a stub `curl` first on `PATH` (agreed in review of `09-docs-site.md`).

Step by step:

1. Everything lives in a `main` function called on the last line. A truncated download then executes nothing.
2. `set -eu`. Traps remove the temp directory on any exit.
3. Root check. If `id -u` is 0 and `RDY_ALLOW_ROOT` is not `1`, stop with: what happened (running as root), why (Rdy checks what a normal user can do and installs nothing system-wide), what to do (rerun as a normal user, or set `RDY_ALLOW_ROOT=1` to install to `/usr/local/bin`). With `RDY_ALLOW_ROOT=1` the default install dir becomes `/usr/local/bin`.
4. Detect OS from `uname -s`: `Linux` or `Darwin`. Anything else: stop, name the OS, point to the manual Windows zip or the releases page.
5. Detect CPU from `uname -m`: `x86_64` or `amd64` gives `x86_64`; `aarch64` or `arm64` gives `aarch64`. Else stop and list supported pairs. On macOS, if `sysctl -n sysctl.proc_translated` says 1 (Rosetta shell), choose `aarch64`.
6. Map to the target triple. Linux always gets the musl archive, so no glibc detection.
7. Pick a downloader: `curl` (with `--proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15`), else `wget`. Both honor `HTTPS_PROXY` and `NO_PROXY`. If neither exists, stop and say how to install one or download by hand.
8. Resolve the version. `RDY_VERSION` if set. Otherwise: while every release is a prerelease (all of 0.1.0-alpha.N), `releases/latest/download` returns 404 because GitHub's "latest" skips prereleases. So the script asks `https://api.github.com/repos/getrdy-io/rdy/releases?per_page=1`, reading `GITHUB_TOKEN` if present to avoid the 60 requests per hour unauthenticated cap per IP (which hurts behind a shared corporate NAT). Once a non-prerelease exists, the script switches to the `releases/latest/download` redirect and needs no API call. `--prerelease` via `RDY_VERSION=alpha` forces the API path.
9. Download into `mktemp -d`: the archive, its `.sha256`, its `.sigstore.json`.
10. Verify sha256 with `sha256sum`, else `shasum -a 256`. Mismatch: delete everything, stop, say "download is corrupt or has been altered", show both hashes.
11. Verify the signature (unless `RDY_VERIFY=checksum`). Use `cosign` from `PATH` if it is version 3 or newer. Otherwise download the cosign release binary whose version and per-platform sha256 are written into `install.sh`, check that hash, and use it from the temp dir. Run `cosign verify-blob` with the pinned identity regexp and issuer. Any failure is fatal. The message says: do not run this file, how to retry, and to report it to `security@getrdy.io`.
12. If Sigstore cannot be reached (TUF or Rekor blocked by a proxy), say so plainly and show two options: set `RDY_VERIFY=checksum` (prints a warning that this only protects against corruption, not tampering), or follow the air-gapped steps below.
13. Extract with `tar -xzf` into the temp dir. Confirm exactly one `rdy` file. `chmod 0755`. Run `rdy version` once as a smoke test. This is the first time the binary runs, and it runs only after verification.
14. Install dir: `RDY_INSTALL_DIR`, else `$HOME/.local/bin` (or `/usr/local/bin` in the root case). Create it with `mkdir -p`. If not writable, stop, name the directory, and suggest `RDY_INSTALL_DIR`. Copy to `<dir>/.rdy.new.$$`, then `mv -f` for an atomic replace. If an old `rdy` exists, print old and new versions.
15. PATH check. If the dir is not on `PATH`, print the exact line to add for bash, zsh and fish. The script never edits shell profile files. It also prints the full path, because the script cannot change the PATH of the shell that called it.
16. Print a summary on stderr: version, path, which checks passed, and `rdy run --help`. Stdout stays empty, so the script is safe in pipelines. Exit codes: 0 success, 1 failure, 64 bad usage.

Every error follows one shape: what happened, the most likely cause, what to do next, in under five lines. Corporate TLS interception gets its own message: name `SSL_CERT_FILE` and `CURL_CA_BUNDLE`, and the manual route.

Tests (ticket "install.sh CI tests"): `shellcheck`; a stub `curl` on `PATH` that serves a fake release from a local directory, plus a stub cosign, run under `dash` and `busybox sh`; negative cases for bad hash, bad signature, root refusal, unsupported OS and an unwritable dir. After each real release, a post-release job installs from the real GitHub release on ubuntu x64, ubuntu arm64, macOS arm64 and an Alpine container, then runs `cosign verify-blob` on the Windows zip (ticket "Post-release verify job").

### Air-gapped alternative

The documented manual route (docs-writer turns this into a page):

1. On a connected machine, download for the target triple: the archive, its `.sha256`, its `.sigstore.json`. Optionally download a `cosign` release and `sigstore-trusted-root.json` (a release asset we publish, dated; Sigstore rotates its roots, so use a fresh one).
2. Verify there: `sha256sum -c`, then `cosign verify-blob` as above. For fully offline verification add `--trusted-root sigstore-trusted-root.json`.
3. Carry the archive across on approved media. Verify the sha256 again on the target host.
4. `tar -xzf rdy-<triple>.tar.gz`, then `install -m 0755 rdy-<triple>/rdy /usr/local/bin/rdy` (or any directory).

M2 ticket: `RDY_LOCAL_DIR=/media/dl sh install.sh` runs the same checks against local files, so the air-gapped path is one command.

Serving: `curl -sSf https://getrdy.io/install | sh` has no `-L`, so the endpoint must answer 200 with the script bytes, not a redirect. Mechanism (ticket "Serve install.sh at getrdy.io/install"): the apex `getrdy.io` is already a Pages custom domain for the marketing site, and Pages cannot route a single path to a second project. So use a tiny Cloudflare Worker with a route on `getrdy.io/install`, deployed once with `wrangler deploy` (not on every release). It fetches `install.sh` from the newest release (through the same version resolution as step 8) and returns it with a 200. That removes the per-release deploy and keeps Cloudflare tokens out of the release workflow. Cloudflare API tokens are account-scoped, not project-scoped, so the Worker token lives in a GitHub Environment limited to `main`, and ideally in a separate Cloudflare account from the docs site. Docs examples should use `curl --proto '=https' --tlsv1.2 -sSf`.

## Package managers

| Channel | Milestone | Plan |
| --- | --- | --- |
| GitHub Releases + `install.sh` | M1 | Above. |
| Windows zip | M1 | Manual download, verify with cosign, documented. No installer script in M1, because dist's PowerShell installer checks only sha256 and our bar is a signature. |
| Homebrew tap | M3 | Repo `getrdy-io/homebrew-tap`. Turn on dist's `homebrew` installer with `tap = "getrdy-io/homebrew-tap"` and `publish-jobs = ["homebrew", "./sign-release"]`. Customers run `brew install getrdy-io/tap/rdy`. Needs one secret, `HOMEBREW_TAP_TOKEN` (fine-grained PAT scoped to the tap repo only, or a GitHub App). The formula pins archive sha256. Works on macOS and Linuxbrew. |
| winget | M3 | Package id `RdyLabs.Rdy`. Manifest type `zip` with nested installer type `portable`. Automate with `wingetcreate update --submit` in a Windows job after the release is public, using a PAT that can push to a fork of `microsoft/winget-pkgs`. Each version is a PR that Microsoft's validation must pass, so expect hours of delay. Unsigned binaries may trip SmartScreen checks. See Windows signing below. I did not verify the status of the community `winget-releaser` action, so prefer Microsoft's own tool. |
| Windows `install.ps1` | M3 | Same checks as `install.sh`. |
| apt and yum | M5 | Build `.deb` and `.rpm` from the static binary with `nfpm` (one YAML file, both formats, both CPUs). Repo hosting and a GPG repo key are a separate decision (ADR below). Needed for Enterprise customers who mirror repos. |
| crates.io | M2 | `rdy-spec` and `rdy-engine` must be on crates.io because `rdy-cloud` consumes them from there. Use crates.io trusted publishing (OIDC) from a tag workflow so no token is stored. Names are free today (checked 2026-10-27: `rdy`, `rdy-spec`, `rdy-engine`, `rdy-bundle` all return 404), so reserve them in M1. |

macOS and Windows code signing (decision for M3, see ADR list): files downloaded by `curl` carry no quarantine flag, so unsigned macOS binaries run fine from `install.sh` and Homebrew. A browser download of the archive would be blocked by Gatekeeper. Windows SmartScreen warns on unsigned `rdy.exe` from a browser. Apple Developer ID costs about $99 a year. Windows options range from a code-signing certificate to Azure Trusted Signing. Both are paid services and I do not decide them here.

## Self-update

Decision: defer. In M1 `rdy self-update` does not download anything. It prints the install command, and prints `brew upgrade rdy` when the binary path looks like Homebrew's. Reasons:

- The plan lists the `self_update` crate. It verifies only `zipsign` signatures, not cosign. dist's own updater (`axoupdater`) works only for dist-made installers and checks no cosign signature. Neither fits our trust model.
- A binary that replaces itself with root in a customer environment is exactly what a security reviewer will probe. It needs a threat-model pass first (security-reviewer, `05-threat-model.md`).
- Customers re-run `install.sh`, which already verifies everything. That is one command and costs us nothing.
- `install-updater = false` in dist config. No `axoupdater` in the dependency tree.

Design for M3 (so M1 choices do not block it), to be settled in an ADR after a spike:

- The release job publishes `release-manifest.json`: version, per-target asset URL, sha256, size, `min_supported_version`, publish time. It is signed with cosign like every other asset.
- `rdy self-update` fetches the manifest, verifies it, downloads the archive, verifies sha256 and the archive's own bundle, swaps the binary atomically, keeps the old one as `rdy.old`, and supports `--check` and `--dry-run`. It refuses to run when `rdy` is root-owned and the user is not root, and when installed by a package manager.
- In-process verification options: (a) shell out to `cosign` if present (weak for customers), (b) the `sigstore` Rust crate if its dependency tree is rustls-only and acceptable (needs a spike), (c) an ed25519 release-metadata key held offline, reusing `rdy-spec` code. Option (c) is simplest in code but adds key custody for one founder and a manual signing step every week. My lean is (b) if the spike is clean, else (c).
- Never auto-update. Never check for updates unless the user asked. Offline first.

## Version and support policy

Versioning:

- Semver, pre-1.0. In 0.x a minor bump may break CLI flags and `--json` fields. Patch bumps never do. The spec format (`rdy/v1`) and the result schema carry their own version numbers, independent of the binary version. A 0.x binary reads `rdy/v1` specs for the whole of 0.x.
- Workspace crates share one version in `[workspace.package]`. The git tag is `vMAJOR.MINOR.PATCH[-pre]`.
- M1: a tagged build every week named `0.1.0-alpha.N` (`N` from 1, counting up each week; skipped weeks keep the number). When the M1 exit test passes, tag `0.1.0` without a suffix. After that, `0.2.0-alpha.N` while building toward `0.2.0`, and so on. Prereleases are marked as GitHub prereleases automatically.
- Cadence: M1 to M3, a tagged build every week if `main` is green, cut on a fixed weekday so it is a habit (suggest Thursday, with Friday as buffer). If `main` is red, skip the week. Never tag red. From M4: every two weeks plus patch releases on demand. Security fixes release the same day.
- Release is a short runbook (ticket "Release runbook"): changelog PR, `cargo release` bump PR, tag, watch the run, run `scripts/verify-release.sh <tag>`, post the link.

MSRV:

- Edition 2024 needs Rust 1.85 or newer, so that is the floor. Policy: MSRV is the stable release from about 12 weeks before the release date (stable minus two minor versions), recorded as `rust-version` in `[workspace.package]`. It is raised only in minor releases and noted in the changelog.
- `rust-toolchain.toml` pins an exact stable for everything we build and ship. MSRV matters to library users (`rdy-spec`, `rdy-engine`), not to binary users. The `msrv` CI job enforces it. A calendar ticket every six weeks bumps the pinned toolchain.

Support window:

- 0.x: the latest release only gets fixes. Older ones are unsupported. Design partners are told this in the alpha welcome note.
- From 1.0: the latest minor and the previous minor get security fixes for six months. Longer backports are a contract term for Enterprise, decided case by case.
- Platforms: Linux x86_64 and aarch64 on any kernel the Rust musl targets support (3.2 or newer for x86_64, 3.7 or newer for aarch64), macOS 11 or newer, Windows 10 and Server 2016 or newer. Confirm with a test on the oldest image we can get before the first non-alpha.
- A breaking change to the spec format needs a new `rdy/vN` and an overlap period. That is rust-architect's document (`01-spec-format.md`), not this one.

## Reproducible builds

Goal (CLAUDE.md): reproducible where practical, deviations documented. M1 does the cheap part. M2 adds a checker.

What we do in M1 (ticket "cargo-auditable, CycloneDX SBOM and reproducibility flags"):

- Exact toolchain from `rust-toolchain.toml`. `--locked`. Committed `Cargo.lock`.
- `RUSTFLAGS` with `--remap-path-prefix` for the workspace and `CARGO_HOME`, so no runner paths end up in the binary.
- `SOURCE_DATE_EPOCH` set to the tag commit time before the archive step.
- Fixed `[profile.release]` settings for `codegen-units`, `lto` and `strip` (rust-architect picks the values, release-engineer wires them), same for every target.
- No build cache in release jobs.

M2: `scripts/repro-check.sh <tag>` rebuilds `x86_64-unknown-linux-musl` inside a Rust container image pinned by digest and compares the sha256 of the `rdy` binary with the one in the released archive. Expectation: bit-identical on Linux musl. Publish the result in the release notes.

Known deviations (to be listed in docs as they are found):

| Deviation | Why | Mitigation |
| --- | --- | --- |
| macOS and Windows binaries are not expected to be bit-for-bit reproducible | Apple linker ad-hoc signing, MSVC linker timestamps and PDB paths, runner image toolchain versions | We document it. Provenance attestation plus signed sources cover the trust question. |
| Hosted runner images change over time | `musl-tools`, Xcode and MSVC versions move | Use the container rebuild for Linux. Record runner image versions in the release notes. |
| C code in dependencies (`ring`) | Compiler version differences | Same pinned container. |
| Signatures differ on every signing run | Sigstore certificates and timestamps are per-signing | Expected. We sign the bytes, we do not claim the signature is reproducible. |
| tar and zip metadata | Mtimes and file order | `SOURCE_DATE_EPOCH`; check in the spike whether dist honors it, else repack in `sign-release`. |

## Cost on the free tier

| Item | Cost | Notes |
| --- | --- | --- |
| GitHub Actions, public repo, standard runners (Linux x64, Linux arm64, Windows, macOS arm64 and Intel) | $0, no minute cap | Verify that arm64 Linux and `macos-15-intel` remain free for public repos when writing tickets 3 and 7. |
| GitHub Actions, if the repo were private | 2,000 min/month, with macOS counted 10x and Windows 2x | One full CI run is roughly 160 billable minutes. That is about 12 runs a month. Not workable. So: public from the first commit. CLAUDE.md already bans real specs and secrets, but `docs/plan/rdy-plan.md` holds pricing, an employment-agreement risk row and trademark history. The founder must decide what stays in the public tree before the repo goes public (see `09-docs-site.md`, first correction). |
| Larger paid runners | avoid | Never needed if CI meets the budget above. |
| Sigstore (Fulcio, Rekor, TUF root) | $0 | Public-good service, no SLA. An outage delays a release; it does not break installed binaries. Rerun the job later. |
| GitHub Releases storage and bandwidth, Actions cache (10 GB) | $0 | |
| GitHub artifact attestations | $0 for public repos | |
| Cloudflare Worker route for `getrdy.io/install` | $0 | Free Workers plan covers 100,000 requests a day. |
| crates.io, Homebrew tap, winget | $0 | |
| Apple Developer ID | about $99/year | Deferred to M3 decision. |
| Windows code signing | roughly $10/month to a few hundred dollars a year | Deferred to M3 decision. |
| apt and yum hosting | $0 self-hosted on object storage, or a hosted free OSS tier | M5 decision. |

Total new spend in M1: $0.

## Plan corrections found

- `docs/plan/rdy-plan.md`, "Release engineering": "`cargo-zigbuild` for cross-compiling" is stale for us. dist does not use zigbuild by default, and native arm64 runners remove the need. Fix: delete the zigbuild mention; keep it only as a documented fallback.
- `docs/plan/rdy-plan.md`, "Release engineering": "Binaries and specs signed with Sigstore (cosign)". Specs are signed with the vendor's ed25519 key (CLAUDE.md rule 3). Fix: "Release binaries signed with Sigstore cosign; specs signed with vendor ed25519 keys."
- `docs/plan/rdy-plan.md`, "Release engineering" and crate table: "cargo-dist" is now called `dist`, its config lives in `dist-workspace.toml`, and the project changed maintainers in 2025. Fix: say "dist (formerly cargo-dist), pinned to an exact version".
- `docs/plan/rdy-plan.md`, crate table, `rdy-cli` row: lists the `self_update` crate. It cannot verify cosign signatures and self-update is deferred in M1. Fix: remove `self_update` from M1 dependencies.
- `docs/plan/rdy-plan.md`, Marketing "Stack": "`get.<domain>` serves the install script". CLAUDE.md and the pitch use `getrdy.io/install`. Fix: use `https://getrdy.io/install` everywhere, and remove the `get.` host.
- `docs/plan/rdy-plan.md`, user flow (the "SE sends a link" step) and CLAUDE.md "Names and places": `curl -sSf https://getrdy.io/install | sh && rdy run ...` has two problems. (1) The script cannot change `PATH` of the calling shell, and `~/.local/bin` is often not on it, so `rdy` is not found. (2) Customer shells on servers are often root, which `install.sh` refuses by default. Fix for cli-ux and devrel: the sales one-liner should call the installed path, for example `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh && "$HOME/.local/bin/rdy" run ...`, and the docs must tell root users about `RDY_ALLOW_ROOT=1`.
- `CLAUDE.md`, "Repo layout": `.github/workflows/` lists three files. A fourth, `sign-release.yml`, is needed because dist runs custom jobs as reusable workflows. Fix: add it. Also add `dist-workspace.toml`, `.cargo/config.toml`, `scripts/verify-release.sh` and `CHANGELOG.md` to the tree.
- `CLAUDE.md`, "Engineering standards": "CI runs all four" lists Linux x86_64, Linux aarch64, macOS and Windows. Macs come in two CPU types, so there are five legs. Fix: "all five".
- `CLAUDE.md`, "Repo layout": the crate directory is `rdy-cli` but the published package and binary are `rdy`. dist names archives from the package, so `crates/rdy-cli/Cargo.toml` must say `name = "rdy"` with `[[bin]] name = "rdy"`. Fix: state it explicitly in the layout note.
- `docs/plan/rdy-plan.md`, "Public repo ... To create" and KICKOFF.md: nothing says the repo is public from week one. Private CI exhausts the free minutes in about a dozen runs because macOS counts 10x. Fix: create `getrdy-io/rdy` as public before the first CI ticket.
- `KICKOFF.md`, M1 scope: lists "signing" which reads as spec signing only. Release signing (cosign) is also needed, and it lands in weeks 1 and 2 under "Workspace plus CI" because the plan says the release pipeline comes first. Fix: say "spec signing and release signing" in the backlog.
- `docs/plan/rdy-plan.md`, milestones: `rdy-cloud` consumes `rdy-spec` and `rdy-engine` from crates.io (CLAUDE.md rule 6) but no milestone publishes them. Fix: add the crates.io publish ticket to M2.
- `docs/plan/rdy-plan.md`, Release engineering: "apt and yum repos for the Enterprise tier" with no milestone. This plan puts them in M5. Fix: record it.
- Tooling note: the GitHub runner label `macos-13` (the old Intel Mac image) is retired. Any plan text or template that uses it is stale.

## Decisions needing an ADR

- install.sh signature verification default. Chosen (most conservative): verify with cosign by default, downloading a pinned cosign when absent, with `RDY_VERIFY=checksum` as a loud opt-out. Alternatives: (a) verify only if cosign is already installed, else sha256 only; (b) require cosign installed or fail; (c) embed hashes in the script. (a) is the weakest. (b) breaks the one-liner. (c) needs a script deploy on each release.
- Release signing order. Chosen: sign before the release is published (`github-release = "host"` plus `publish-jobs`) if dist leaves a draft. Alternative: `post-announce-jobs` with fail-closed install, which rules out GitHub immutable releases.
- Musl builds on native runners instead of cross-compiling. Chosen: native `ubuntu-24.04-arm` plus `musl-tools`. Alternatives: `cargo-zigbuild`, `cross`, or a container. This belongs in the existing "musl vs glibc" ADR family as a build-method note.
- How `getrdy.io/install` is served. Chosen: a Cloudflare Worker route on `getrdy.io/install` that proxies the newest release's `install.sh`, deployed once. Alternatives: the marketing site build copying the script per release (needs a deploy per release), or a manual copy. Cloudflare tokens are account-scoped, so the token must sit in a restricted GitHub Environment, apart from any docs-deploy token. Security-reviewer should review it.
- Self-update trust model (M3). Alternatives: shell out to cosign, `sigstore` crate, or an offline ed25519 release key. Decide after the spike.
- macOS notarization and Windows Authenticode (M3). Paid services. Alternatives: do neither and document, buy both, or use Homebrew and winget only.
- apt and yum hosting and the repo signing key (M5). Alternatives: self-hosted on object storage with a GPG key, or a hosted free OSS tier with its own key.
- Pinning dist at 0.33.0 and the plan to fall back to a hand-written workflow if the project stalls. Alternative: write the release workflow by hand now. dist saves about two days today, at the cost of a dependency on a tool whose ownership changed.

## Tickets implied

- [M1] Repo settings, rulesets and Dependabot | owner: release-engineer | est: 2h | depends on: none | exit test: a direct push to `main` is rejected, a `v*` tag push by a non-admin is rejected, and Dependabot opens its first PR
- [M1] Reserve crate names on crates.io | owner: release-engineer | est: 1h | depends on: none | exit test: `rdy`, `rdy-spec`, `rdy-engine`, `rdy-bundle` and the other six names show as owned by the `getrdy-io` team on crates.io
- [M1] CI lint job: fmt, clippy, doc, MSRV, cargo-deny with baseline deny.toml | owner: release-engineer | est: 3h | depends on: Workspace skeleton and rust-toolchain.toml | exit test: green `lint`, `deny` and `msrv` jobs on a PR, and a throwaway PR with a clippy warning turns them red
- [M1] CI test matrix on five native runners with nextest and rust-cache | owner: release-engineer | est: 4h | depends on: CI lint job: fmt, clippy, doc, MSRV, cargo-deny with baseline deny.toml | exit test: a workflow run where all five legs are green and the Linux legs print "statically linked"
- [M1] ci-ok gate job and timing check | owner: release-engineer | est: 1h | depends on: CI test matrix on five native runners with nextest and rust-cache | exit test: a PR with one red leg cannot merge, and three consecutive warm runs finish in under ten minutes
- [M1] audit.yml: cargo-audit, deny advisories, zizmor, issue on failure | owner: release-engineer | est: 3h | depends on: CI lint job: fmt, clippy, doc, MSRV, cargo-deny with baseline deny.toml | exit test: a manual `workflow_dispatch` run is green, and a run against a deliberately vulnerable pinned crate on a throwaway branch opens a labelled issue
- [M1] dist init, five-target config and dist-check in CI | owner: release-engineer | est: 4h | depends on: CI test matrix on five native runners with nextest and rust-cache | exit test: pushing tag `v0.1.0-alpha.1` on a test branch builds five archives with `.sha256` files attached to a GitHub prerelease, and `dist generate --check` is green in CI
- [M1] cargo-auditable, CycloneDX SBOM and reproducibility flags | owner: release-engineer | est: 3h | depends on: dist init, five-target config and dist-check in CI | exit test: `cargo audit bin` lists dependencies from a downloaded release binary, each target has a valid `.cdx.json`, and a rebuild on the same runner image gives an identical Linux binary hash
- [M1] sign-release workflow with cosign keyless and ordering decision | owner: release-engineer | est: 4h | depends on: dist init, five-target config and dist-check in CI | exit test: on a clean machine `cosign verify-blob` with the pinned identity passes for a downloaded archive and fails for the same archive with one byte changed
- [M1] First alpha release and scripts/verify-release.sh | owner: release-engineer | est: 2h | depends on: cargo-auditable, CycloneDX SBOM and reproducibility flags; sign-release workflow with cosign keyless and ordering decision | exit test: `scripts/verify-release.sh v0.1.0-alpha.1` passes on a clean Linux machine and the GitHub release shows archives, checksums, SBOMs and bundles
- [M1] install.sh core: detection, root refusal, download, sha256, install dir | owner: release-engineer | est: 4h | depends on: dist init, five-target config and dist-check in CI | exit test: on clean ubuntu and macOS machines the script installs the alpha.1 binary to `~/.local/bin`, and a root run without `RDY_ALLOW_ROOT=1` prints the fix and exits 1
- [M1] install.sh signature verification and pinned cosign fetch | owner: release-engineer | est: 3h | depends on: install.sh core: detection, root refusal, download, sha256, install dir; sign-release workflow with cosign keyless and ordering decision | exit test: install passes with and without cosign on `PATH`, and a tampered archive aborts with the documented message
- [M1] install.sh CI tests: shellcheck, fixture server, dash and busybox | owner: release-engineer | est: 3h | depends on: install.sh signature verification and pinned cosign fetch | exit test: the `install-sh` job is green and the negative cases (bad hash, bad signature, root, unsupported OS, unwritable dir) each fail with the expected text
- [M1] Serve install.sh at getrdy.io/install | owner: release-engineer | est: 2h | depends on: install.sh signature verification and pinned cosign fetch | exit test: `curl -sSf https://getrdy.io/install` returns 200 with bytes identical to the release's `install.sh`, and the sha256 matches
- [M1] Post-release verify job on four environments and Windows zip | owner: release-engineer | est: 3h | depends on: Serve install.sh at getrdy.io/install | exit test: after a tag, a workflow run installs from the real release on ubuntu x64, ubuntu arm64, macOS arm64 and Alpine and verifies the Windows zip, all green
- [M1] Release runbook, cargo-release config and changelog check | owner: release-engineer | est: 3h | depends on: First alpha release and scripts/verify-release.sh | exit test: the founder cuts `v0.1.0-alpha.2` by following the runbook alone in under 30 minutes, and the release notes show the changelog section
- [M1] rdy self-update prints the install command | owner: cli-ux | est: 1h | depends on: Serve install.sh at getrdy.io/install | exit test: `rdy self-update` exits 0 after printing the install command and downloads nothing (verified with network off)
- [M2] Repro-check script and pinned-container rebuild | owner: release-engineer | est: 6h | depends on: First alpha release and scripts/verify-release.sh | exit test: `scripts/repro-check.sh` reports identical sha256 for the Linux x64 musl binary of a released tag
- [M2] install.sh offline mode (RDY_LOCAL_DIR) with trusted root asset | owner: release-engineer | est: 4h | depends on: install.sh signature verification and pinned cosign fetch | exit test: on a host with the network blocked, the script verifies and installs from a local folder
- [M2] Publish rdy-spec and rdy-engine to crates.io via trusted publishing | owner: release-engineer | est: 4h | depends on: Reserve crate names on crates.io | exit test: a tag run publishes both crates and `cargo add rdy-spec` works in an empty project
- [M2] Nightly coverage job, not gating | owner: release-engineer | est: 3h | depends on: CI test matrix on five native runners with nextest and rust-cache | exit test: a nightly run uploads an lcov report and shows a percentage
- [M3] Homebrew tap and dist homebrew installer | owner: release-engineer | est: 4h | depends on: First alpha release and scripts/verify-release.sh | exit test: `brew install getrdy-io/tap/rdy` installs the latest release on macOS and `brew test` passes
- [M3] winget manifest and submission automation | owner: release-engineer | est: 6h | depends on: First alpha release and scripts/verify-release.sh | exit test: a winget-pkgs PR for the release passes Microsoft validation and `winget install RdyLabs.Rdy` works on a clean Windows VM
- [M3] Windows install.ps1 with the same verification as install.sh | owner: release-engineer | est: 4h | depends on: install.sh signature verification and pinned cosign fetch | exit test: on a clean Windows VM the script installs and fails closed on a tampered zip
- [M3] macOS notarization and Windows signing, after ADR | owner: release-engineer | est: 8h | depends on: ADR for code signing | exit test: a browser-downloaded archive runs on macOS without a Gatekeeper block and `rdy.exe` shows a verified publisher
- [M3] Self-update spike and ADR | owner: release-engineer | est: 4h | depends on: First alpha release and scripts/verify-release.sh | exit test: an ADR chooses a verification method, backed by a prototype that verifies a signed manifest in a Rust test
- [M4] Implement rdy self-update | owner: rust-engineer | est: 8h | depends on: Self-update spike and ADR | exit test: `rdy self-update` upgrades from alpha N to N+1 on all five platforms and rolls back when the new binary fails `rdy version`
- [M5] deb and rpm packages with nfpm | owner: release-engineer | est: 8h | depends on: First alpha release and scripts/verify-release.sh | exit test: `dpkg -i` and `rpm -i` install the package on Debian and Rocky containers and `rdy version` runs
- [M5] apt and yum repository hosting with signed metadata | owner: release-engineer | est: 12h | depends on: deb and rpm packages with nfpm | exit test: `apt install rdy` and `dnf install rdy` work from the public repo on clean containers with the repo key verified
