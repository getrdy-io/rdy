# ADR 0020: Releases are built by a generated and hardened dist workflow, published last, and gated by an artifact check

- Status: Accepted (2026-10-29, M1-007). security-reviewer signed off on decisions 3 to 6 in PR #47.
  Amends the dist settings in 06, Appendix B.
- Date: 2026-10-28

## Context

M1-007 turns `dist` 0.33.0 on for the five targets. Reading the workflow that `dist generate` writes
showed that four settings in 06, Appendix B do not do what the plan assumed. The security review of
PR #47 then found that the generated workflow is not safe to ship as it is: every job holds a
`contents: write` token while it builds dependencies, tools are installed with an unhashed
`curl | sh`, any tag starts a release, and the tag name is pasted into shell text. The sandbox run is a
manual step (06, "Sandbox proof"), so these decisions come from the generated file, a local build and
script tests, not from a sandbox run.

## Decision

1. `release.yml` is dist's generated workflow plus `scripts/harden-release-workflow.py`, and is never
   edited by hand. `dist-workspace.toml` sets `allow-dirty = ["ci"]`, which turns off dist's own drift
   check. In its place the CI job `release-workflow` installs dist from a hash-checked file, regenerates
   the workflow in a scratch copy (`scripts/gen-release-workflow.sh --check`) and fails on any
   difference. The script matches each edit exactly once and stops when dist's output changes, so a dist
   bump forces a review. Every action is pinned to a commit SHA (`[dist.github-action-commits]`, and the
   install action in the script).
2. `github-release = "announce"`, not `"host"`. In 0.33.0, `"host"` runs `gh release create` in the host
   job, so the release is public before any publish job runs, and a signature added later would come
   after publication. `"announce"` creates the release in the last job, from the workflow's artifacts,
   after every publish job. This also answers the open question in 06 about immutable releases.
3. The artifact check is a **publish job**, not a host job. In 0.33.0 the announce job waits for publish
   jobs and stops if one fails, but it ignores a failed host job. `publish-prereleases = true`, because
   otherwise dist skips publish jobs on every `-alpha.N` tag and announce treats a skipped job as
   passed. The check is `scripts/check-release-artifacts.sh`. It holds an exact list of file names and
   rejects any other name, folder or symlink. The `announce` job runs the same list check again
   (`--files-only`) on the folder it publishes, right before `gh release create`. The check also
   runs `scripts/check-static.sh` on both Linux archives, because a linker override such as
   `cargo-zigbuild` bypasses `scripts/musl-pie-linker.sh` (ADR 0006, decision 2), and it checks hashes,
   archive paths, each binary's format and CPU (PE machine 0x8664, Mach-O arm64 and x86-64), the
   Windows imports, `cargo audit bin`, the SBOM, and that `cargo tree -p rdy -e features` for each target
   shows no `preserve_order` (the schema tooling's serde_json feature, used only by xtask). That command
   resolves features for `rdy` alone, so it cannot see a workspace build. The setting that stops one is
   `precise-builds = true`, which makes dist build `--package=rdy`. The check therefore also fails
   unless `dist-workspace.toml` sets `precise-builds = true` under `[dist]` (read with a TOML parser).
4. `github-attestations` stays off. It adds `id-token: write` to the build jobs, and 06 says the signing
   job is the only job that has it. The cosign signature of `SHA256SUMS` (M1-010) is the trust path.
   Revisit in M2.
5. What the hardening script changes:
   - The workflow has no default token (`permissions: {}`). `plan`, both build jobs and `host` get
     `contents: read`. Only `announce` gets `contents: write`. The plan job no longer holds a write token
     on same-repo pull requests.
   - The build jobs get no `GH_TOKEN` variable, so build scripts see no token variable. The test script
     fails if one comes back.
   - Only tags like `v1.2.3` and `v1.2.3-alpha.1` start a release. The plan job checks the tag against
     `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$` before anything else uses it. Later jobs read the tag from
     `env:` and quote it. dist's `tag-flag` output, which put the tag into shell text, is removed.
   - `dist` and `cargo-cyclonedx` are installed by `scripts/install-release-tool.sh` from a pinned
     release file. The script compares the file's sha256 (from `sha256sum`, or `shasum` on macOS) with the
     pin in `.github/release-tools.txt` and unpacks nothing on a difference. `cargo-auditable` is
     installed by `taiki-e/install-action` (SHA-pinned) at the exact version 0.7.7, not from `latest`,
     with `fallback: none` so it never builds from source with `cargo install`.
   - The musl packages are installed by a fixed step, not by text from the build matrix. Container builds
     and the `curl | sh` Rust installer that serves them are removed: we configure none.
   - dist's typo `steps.cargo-cyclonedx.output.paths` becomes `outputs`, so the SBOM path is no longer
     empty. The checker fails the release if the SBOM is missing.
   - `secrets: inherit` is removed from the check job, which reads no secret.
6. Gaps that remain, for security-reviewer to confirm:
   - The pinned hashes in `.github/release-tools.txt` were read from the projects' own release pages
     over HTTPS. A tool that was already malicious on that day is not caught. A later change is.
   - The build jobs still run every dependency's build script, now with a read-only token that is
     not exposed as a variable, and no `id-token`. A malicious dependency can still change the binary it
     builds. `cargo deny`, the lock file and the artifact check (static-pie, `cargo audit bin`) are the
     controls.
   - `taiki-e/install-action` is a third-party action trusted to fetch `cargo-auditable` correctly. It is
     pinned by SHA and checks its own hashes.
   - The Windows and macOS install paths of `install-release-tool.sh` and the changed Windows build
     shell (now `bash`) are not run here. The sandbox run proves them.
   - `.github/zizmor.yml` ignores one rule for `release.yml` only (`self-repository`, a style note).
7. `aarch64-apple-darwin` is built on `macos-15-intel` with plain `cargo` (dist uses no wrapper from
   Darwin to Darwin) and is never run there (ADR 0006, decision 8). The check reads the Mach-O header for
   the arm64 CPU type. A smoke run on arm64 waits for the founder hand step.
8. The SBOM is CycloneDX **XML** (`rdy.cdx.xml`). dist runs a fixed `cargo cyclonedx -v`, which writes XML,
   and has no setting for JSON. The M1-007 exit test said JSON; correction 07 (PR #46) changes it to
   "valid CycloneDX (XML or JSON)". A JSON SBOM per target can come from `auditable2cdx` in
   `sign-release` (06, SBOM section).
9. `[profile.dist]` inherits `release` with thin LTO, one codegen unit and stripped symbols. Unwinding
   stays on, because the scheduler isolates a panicking check with `catch_unwind`. The cargo-auditable
   data survives `strip` (checked on the x86_64 musl build: 63 dependencies listed).
10. A founder hand step adds a tag-creation ruleset on the repo (11, Founder hand steps). The trigger
    pattern and the plan job's shape check are the code side. The ruleset is the control that says who can
    create a `v*` tag at all.

## Consequences

- A tag must equal a package version (`v0.1.0-alpha.0` today). Bump the crate versions before tagging
  `-alpha.N`, per ADR 0007.
- The SBOM holds the build path of the runner in `bom-ref` values. It is public. Appendix D lists it.
- Bumping `dist` is a deliberate change: new version and hashes in `dist-workspace.toml` and
  `.github/release-tools.txt`, `sh scripts/gen-release-workflow.sh`, then read the diff. If the script
  stops, dist's output moved and the script needs a review.
- M1-010 adds `sign-release` as another publish job with its own permissions. It starts from a workflow
  where no job holds a write token except `announce`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Hand-written release workflow now | About a day, outside M1-007. Stays the fallback if dist stalls or the script cannot keep up with dist. |
| Ship dist's file and ignore zizmor findings (the first version of this ADR) | The write token, the unhashed installers and the tag in shell text were real findings, not style. |
| Check as a host job | A failed host job does not stop announce (decision 3). |
| `github-attestations = true` | Breaks the one-job `id-token` rule (decision 4). It does give the build jobs `contents: read`, which decision 5 now does without it. |
| Install dist with `cargo install` | Compiles for minutes on every run and trusts crates.io at that moment. A hash-checked release file is faster and as strong. |
