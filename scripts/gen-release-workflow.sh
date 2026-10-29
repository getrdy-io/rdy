#!/bin/sh
# gen-release-workflow.sh: write or check .github/workflows/release.yml (ADR 0020).
#
# Usage: scripts/gen-release-workflow.sh [--write | --check]    (default: --write)
# The release workflow is dist's generated workflow plus scripts/harden-release-workflow.py. This
# script runs both in a scratch copy of the repo, so dist-workspace.toml's `allow-dirty` (which
# makes `dist generate` skip the file) does not matter, then either replaces the committed file or
# fails when it differs. CI runs --check in the job `release-workflow`.
# Needs: dist 0.33.0 on PATH (scripts/install-release-tool.sh dist), cargo, python3, diff.
# Exit: 0 ok, 1 the committed file differs or a step failed, 64 usage error or a missing tool.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

mode=--write
if [ "$#" -gt 1 ]; then
    echo "usage: scripts/gen-release-workflow.sh [--write | --check]" >&2
    exit 64
fi
if [ "$#" -eq 1 ]; then
    mode=$1
fi
case $mode in
    --write | --check) ;;
    *)
        echo "usage: scripts/gen-release-workflow.sh [--write | --check]" >&2
        exit 64
        ;;
esac

for tool in dist cargo python3 diff; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "error: $tool is not installed" >&2
        echo "fix: for dist run 'sh scripts/install-release-tool.sh dist'. For cargo use the toolchain in rust-toolchain.toml." >&2
        exit 64
    fi
done

want=$(sed -n 's/^cargo-dist-version = "\(.*\)"$/\1/p' "$root/dist-workspace.toml")
have=$(dist --version | awk '{ print $2 }')
if [ -z "$want" ] || [ "$want" != "$have" ]; then
    echo "error: dist-workspace.toml pins dist '$want' and the installed dist is '$have'" >&2
    echo "fix: run 'sh scripts/install-release-tool.sh dist' to install the pinned version" >&2
    exit 64
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# A scratch copy with only what `dist generate` reads. `allow-dirty` is dropped so it generates.
mkdir -p "$work/.github/workflows"
cp "$root/Cargo.toml" "$root/Cargo.lock" "$root/rust-toolchain.toml" "$work/"
cp -R "$root/crates" "$work/crates"
cp "$root/.github/build-setup.yml" "$work/.github/"
# The reusable workflows that release.yml calls (publish-jobs in dist-workspace.toml).
cp "$root/.github/workflows/check-release-artifacts.yml" "$root/.github/workflows/sign-release.yml" "$work/.github/workflows/"
grep -v '^allow-dirty' "$root/dist-workspace.toml" > "$work/dist-workspace.toml"

(cd "$work" && dist generate > /dev/null)
python3 -I "$here/harden-release-workflow.py" "$work/.github/workflows/release.yml" "$work/release.hardened.yml"

target=$root/.github/workflows/release.yml
if [ "$mode" = "--write" ]; then
    cp "$work/release.hardened.yml" "$target"
    echo "wrote .github/workflows/release.yml"
    exit 0
fi
if diff -u "$target" "$work/release.hardened.yml"; then
    echo "release.yml matches dist plus the hardening script"
else
    echo "error: .github/workflows/release.yml is not what dist and scripts/harden-release-workflow.py produce" >&2
    echo "fix: run 'sh scripts/gen-release-workflow.sh' and commit the result. Do not edit release.yml by hand." >&2
    exit 1
fi
