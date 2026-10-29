#!/usr/bin/env python3
"""Harden the release workflow that `dist generate` writes (ADR 0020).

Usage: python3 -I scripts/harden-release-workflow.py <generated release.yml> <output release.yml>

dist 0.33.0 writes a workflow that gives every job a write token, installs tools with an unhashed
`curl | sh`, lets any tag start a release, and puts the tag name straight into shell text. This
script rewrites those parts and nothing else:

  1. No job has a token by default. Each job names the one it needs: read, except `announce`.
  2. Only tags like v1.2.3 or v1.2.3-alpha.1 start a release, and the plan job checks the shape.
  3. The tag reaches shell commands through `env:` and is quoted, never pasted into the script.
  4. dist and cargo-cyclonedx come from pinned files checked against a committed sha256
     (scripts/install-release-tool.sh). cargo-auditable comes from a SHA-pinned install action
     at an exact version, not from `latest`.
  5. The build jobs get no GH_TOKEN variable, so a dependency's build script cannot read one.
     The musl packages are installed by a fixed step, not by text from the build matrix. Container
     builds are removed: we configure none, and dist's fallback installs Rust with `curl | sh`.
  6. The SBOM upload uses `outputs`, not the misspelt `output` that dist writes.
  7. `announce` checks the exact file list again just before it publishes, and that SHA256SUMS and its
     bundle are there and list exactly those files (--files-only --signed).
  8. The signing job waits for the artifact check, and neither publish workflow inherits secrets.

Every edit must match exactly once. If dist changes its output, the script stops with the text it
could not find. Then read the new output, update this script and ADR 0020, and re-run
scripts/gen-release-workflow.sh. The CI job `release-workflow` runs the same steps and fails on any
difference from the committed file.
"""

import sys

INSTALL_ACTION = "taiki-e/install-action@5488ac5a951645ce95062214902ac4b6bc1a1037 # v2.87.32"
AUDITABLE = "cargo-auditable@0.7.7"

# The tag a release may have. Keep equal to the trigger pattern, scripts/check-release-artifacts.sh
# and the plan step below.
TAG_RE = r"^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$"


def harden(text: str) -> str:
    def sub(old: str, new: str) -> None:
        nonlocal text
        n = text.count(old)
        if n != 1:
            sys.exit(
                f"error: expected the text below once in the generated workflow, found it {n} times.\n"
                f"fix: dist's output changed. Read it, update scripts/harden-release-workflow.py and "
                f"ADR 0020, then re-run scripts/gen-release-workflow.sh.\n--- text ---\n{old}"
            )
        text = text.replace(old, new)

    # 1. No default token.
    sub(
        'name: Release\npermissions:\n  "contents": "write"\n',
        "name: Release\n"
        "# Hardened by scripts/harden-release-workflow.py (ADR 0020). No job has a token unless it\n"
        "# names one. Only `announce` can write.\n"
        "permissions: {}\n",
    )
    read = "    permissions:\n      contents: read\n"
    sub("  plan:\n    runs-on:", "  plan:\n" + read + "    runs-on:")
    sub(
        "  build-local-artifacts:\n    name: build-local-artifacts (${{ join(matrix.targets, ', ') }})\n",
        "  build-local-artifacts:\n    name: build-local-artifacts (${{ join(matrix.targets, ', ') }})\n"
        + read,
    )
    sub("  build-global-artifacts:\n    needs:", "  build-global-artifacts:\n" + read + "    needs:")
    sub("  host:\n    needs:", "  host:\n" + read + "    needs:")
    sub(
        "  announce:\n    needs:",
        "  announce:\n    permissions:\n      contents: write\n    needs:",
    )

    # 2. Trigger: v-prefixed version tags only.
    sub("      - '**[0-9]+.[0-9]+.[0-9]+*'\n", "      - 'v[0-9]+.[0-9]+.[0-9]+*'\n")

    # 3. The tag never goes into shell text. The plan job validates it first.
    sub(
        "      tag-flag: ${{ !github.event.pull_request && format('--tag={0}', github.ref_name) || '' }}\n",
        "",
    )
    sub(
        "      - id: plan\n"
        "        run: |\n"
        "          dist ${{ (!github.event.pull_request && format('host --steps=create --tag={0}', github.ref_name)) || 'plan' }} --output-format=json > plan-dist-manifest.json\n",
        "      - id: plan\n"
        "        shell: bash\n"
        "        env:\n"
        "          IS_PR: ${{ github.event.pull_request && 'true' || 'false' }}\n"
        "          TAG: ${{ github.ref_name }}\n"
        "        run: |\n"
        '          if [ "$IS_PR" = true ]; then\n'
        "            dist plan --output-format=json > plan-dist-manifest.json\n"
        "          else\n"
        "            # The tag reaches the shell as data. Check its shape before anything uses it.\n"
        f"            if ! printf '%s\\n' \"$TAG\" | grep -Eq '{TAG_RE}'; then\n"
        "              echo \"error: the tag is not a release tag: $TAG\" >&2\n"
        '              echo "fix: tag releases as v<major>.<minor>.<patch>, with an optional -<prerelease>, for example v0.1.0-alpha.1" >&2\n'
        "              exit 1\n"
        "            fi\n"
        '            dist host --steps=create "--tag=$TAG" --output-format=json > plan-dist-manifest.json\n'
        "          fi\n",
    )
    sub(
        "      - name: Build artifacts\n"
        "        run: |\n"
        "          # Actually do builds and make zips and whatnot\n"
        "          dist build ${{ needs.plan.outputs.tag-flag }} --print=linkage --output-format=json ${{ matrix.dist_args }} > dist-manifest.json\n",
        "      - name: Build artifacts\n"
        "        shell: bash\n"
        "        env:\n"
        "          TAG: ${{ needs.plan.outputs.tag }}\n"
        "          DIST_ARGS: ${{ matrix.dist_args }}\n"
        "        run: |\n"
        "          # Actually do builds and make zips and whatnot\n"
        '          dist build ${TAG:+"--tag=$TAG"} --print=linkage --output-format=json $DIST_ARGS > dist-manifest.json\n',
    )
    sub(
        "      - id: cargo-dist\n"
        "        shell: bash\n"
        "        run: |\n"
        '          dist build ${{ needs.plan.outputs.tag-flag }} --output-format=json "--artifacts=global" > dist-manifest.json\n',
        "      - id: cargo-dist\n"
        "        shell: bash\n"
        "        env:\n"
        "          TAG: ${{ needs.plan.outputs.tag }}\n"
        "        run: |\n"
        '          dist build ${TAG:+"--tag=$TAG"} --output-format=json "--artifacts=global" > dist-manifest.json\n',
    )
    sub(
        "      - id: host\n"
        "        shell: bash\n"
        "        run: |\n"
        "          dist host ${{ needs.plan.outputs.tag-flag }} --steps=upload --steps=release --output-format=json > dist-manifest.json\n",
        "      - id: host\n"
        "        shell: bash\n"
        "        env:\n"
        "          TAG: ${{ needs.plan.outputs.tag }}\n"
        "        run: |\n"
        '          dist host ${TAG:+"--tag=$TAG"} --steps=upload --steps=release --output-format=json > dist-manifest.json\n',
    )
    sub(
        '          RELEASE_COMMIT: "${{ github.sha }}"\n',
        '          RELEASE_COMMIT: "${{ github.sha }}"\n'
        "          TAG: ${{ needs.plan.outputs.tag }}\n",
    )
    sub(
        '          gh release create "${{ needs.plan.outputs.tag }}" --target',
        '          gh release create "$TAG" --target',
    )

    # 4. Pinned tools.
    sub(
        "      - name: Install dist\n"
        "        # we specify bash to get pipefail; it guards against the `curl` command\n"
        "        # failing. otherwise `sh` won't catch that `curl` returned non-0\n"
        "        shell: bash\n"
        '        run: "curl --proto \'=https\' --tlsv1.2 -LsSf https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-installer.sh | sh"\n',
        "      - name: Install dist\n"
        "        # A pinned release file, checked against a committed sha256 (ADR 0020).\n"
        "        shell: bash\n"
        "        run: sh scripts/install-release-tool.sh dist\n",
    )
    sub(
        "      - name: Install dist\n        run: ${{ matrix.install_dist.run }}\n",
        "      - name: Install dist\n        shell: bash\n        run: sh scripts/install-release-tool.sh dist\n",
    )
    sub(
        "      - name: Install cargo-auditable\n        run: ${{ matrix.install_cargo_auditable.run }}\n",
        "      - name: Install cargo-auditable\n"
        f"        uses: {INSTALL_ACTION}\n"
        "        with:\n"
        f"          tool: {AUDITABLE}\n"
        "          fallback: none\n",
    )
    sub(
        "      - name: Install cargo-cyclonedx\n"
        "        # we specify bash to get pipefail; it guards against the `curl` command\n"
        "        # failing. otherwise `sh` won't catch that `curl` return non-0\n"
        '        run: "curl --proto \'=https\' --tlsv1.2 -LsSf https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-0.5.5/cargo-cyclonedx-installer.sh | sh"\n'
        "        shell: bash\n",
        "      - name: Install cargo-cyclonedx\n"
        "        shell: bash\n"
        "        run: sh scripts/install-release-tool.sh cargo-cyclonedx\n",
    )

    # 5. Fixed musl packages. Our two Linux targets are both musl.
    sub(
        "      - name: Install dependencies\n"
        "        run: |\n"
        "          ${{ matrix.packages_install }}\n",
        "      - name: Install dependencies\n"
        "        if: runner.os == 'Linux'\n"
        "        run: |\n"
        "          sudo apt-get update\n"
        "          sudo apt-get install -y --no-install-recommends musl-tools\n",
    )

    # 5b. No container builds: we set none, and the fallback would install Rust with `curl | sh`.
    sub(
        "    container: ${{ matrix.container && matrix.container.image || null }}\n",
        "",
    )
    sub(
        "      - name: Install Rust non-interactively if not already installed\n"
        "        if: ${{ matrix.container }}\n"
        "        run: |\n"
        "          if ! command -v cargo > /dev/null 2>&1; then\n"
        "            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y\n"
        '            echo "$HOME/.cargo/bin" >> $GITHUB_PATH\n'
        "          fi\n",
        "",
    )

    # 5c. The two publish workflows read no secret, so they get none. (The signing job gets its
    # certificate from the OIDC token, not from a secret.)
    for wf in ("check-release-artifacts", "sign-release"):
        sub(
            f"    uses: ./.github/workflows/{wf}.yml\n"
            "    with:\n"
            "      plan: ${{ needs.plan.outputs.val }}\n"
            "    secrets: inherit\n",
            f"    uses: ./.github/workflows/{wf}.yml\n"
            "    with:\n"
            "      plan: ${{ needs.plan.outputs.val }}\n",
        )

    # 5e. Sign only what passed the artifact check. Publish jobs otherwise run side by side, and a
    # signature on a build that failed the check would sit in the public Sigstore log for ever.
    sub(
        "  custom-sign-release:\n    needs:\n      - plan\n      - host\n",
        "  custom-sign-release:\n    needs:\n      - plan\n      - host\n      - custom-check-release-artifacts\n",
    )

    # 5d. Dependency build scripts run in the build jobs, so those jobs get no GH_TOKEN variable.
    sub(
        "    env:\n      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n      BUILD_MANIFEST_NAME: target/distrib/${{ join(matrix.targets, '-') }}",
        "    env:\n      BUILD_MANIFEST_NAME: target/distrib/${{ join(matrix.targets, '-') }}",
    )
    sub(
        "    env:\n      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n      BUILD_MANIFEST_NAME: target/distrib/global-dist-manifest.json",
        "    env:\n      BUILD_MANIFEST_NAME: target/distrib/global-dist-manifest.json",
    )

    # 6. dist's typo: the step output is `outputs`, so the SBOM path was always empty.
    sub("steps.cargo-cyclonedx.output.paths", "steps.cargo-cyclonedx.outputs.paths")

    # 7. Check the exact file list again, on the files announce itself publishes.
    sub(
        "          rm -f artifacts/*-dist-manifest.json\n      - name: Create GitHub Release\n",
        "          rm -f artifacts/*-dist-manifest.json\n"
        "      - name: Check the files to publish\n"
        "        # Only the expected names, regular files only, all listed in the signed SHA256SUMS (ADR 0020).\n"
        "        run: sh scripts/check-release-artifacts.sh --files-only --signed artifacts\n"
        "      - name: Verify the release signature\n"
        "        # The same exact identity and caller claims as sign-release.sh, install.sh and the docs\n"
        "        # (06, trust roots). The hashes above prove the files match SHA256SUMS. This proves SHA256SUMS\n"
        "        # was signed by sign-release.yml of this repository at this tag. The job token is not passed\n"
        "        # to the downloaded tool.\n"
        "        env:\n"
        "          TAG: ${{ needs.plan.outputs.tag }}\n"
        "          REPO: ${{ github.repository }}\n"
        "        run: |\n"
        "          env -u GH_TOKEN sh scripts/install-release-tool.sh cosign\n"
        '          cd artifacts && env -u GH_TOKEN "$HOME/.cargo/bin/cosign" verify-blob \\\n'
        "            --bundle SHA256SUMS.sigstore.json \\\n"
        '            --certificate-identity "https://github.com/$REPO/.github/workflows/sign-release.yml@refs/tags/$TAG" \\\n'
        "            --certificate-oidc-issuer https://token.actions.githubusercontent.com \\\n"
        '            --certificate-github-workflow-repository "$REPO" \\\n'
        '            --certificate-github-workflow-ref "refs/tags/$TAG" \\\n'
        "            --certificate-github-workflow-trigger push \\\n"
        "            SHA256SUMS\n"
        "      - name: Create GitHub Release\n",
    )

    # 7b. Publish only after the signing job succeeded. A skipped signing job must not publish
    # unsigned files. (publish-prereleases is on, so the job runs for alpha tags too.)
    sub(
        "(needs.custom-sign-release.result == 'skipped' || needs.custom-sign-release.result == 'success')",
        "needs.custom-sign-release.result == 'success'",
    )

    return text


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: harden-release-workflow.py <generated release.yml> <output release.yml>")
    with open(sys.argv[1], encoding="utf-8") as f:
        text = f.read()
    out = harden(text)
    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
        f.write(out)


if __name__ == "__main__":
    main()
