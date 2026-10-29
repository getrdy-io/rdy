#!/bin/sh
# sign-release.sh: write SHA256SUMS for a release folder, sign it with cosign keyless, and verify
# the signature with the exact identity before anything is published (M1-010, SEC-06, SEC-07).
#
# Usage: scripts/sign-release.sh <dir> <tag> <owner/repo> [<repo root>]
#   <dir>        the release assets in one flat folder: what dist built, from the workflow's artifacts
#   <tag>        the release tag, for example v0.1.0-alpha.1
#   <owner/repo> the repository that runs the workflow, for example getrdy-io/rdy
#   <repo root>  the checkout of the tag, where install.sh lives. Default: this script's repo.
# The signing workflow (.github/workflows/sign-release.yml) runs it in the job that holds the
# OIDC token. 06-release-and-distribution.md has the contract.
#
# Steps, in order. Any failure stops the script, and nothing is signed unless every step before
# the signature passes:
#   1. The tag and repository have the expected shape.
#   2. dist's per-job manifests are removed. The `announce` job removes the same files, so the
#      list that is signed is the list that is published.
#   3. The folder holds only expected release files (check-release-artifacts.sh --files-only).
#   4. Every archive has a line in dist's sha256.sum and the hash matches.
#   5. install.sh from the tagged source is stamped with the tag and copied in. It must hold the
#      line RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@' exactly once. The whole line becomes
#      RDY_STAMPED_VERSION='<tag>' (with the v), and exactly one such line must exist afterwards.
#      The tag has no install.sh before M1-014, and then this step is skipped with a note.
#   6. SHA256SUMS is written over every file in the folder (scripts/make-sha256sums.sh).
#   7. `cosign sign-blob` signs SHA256SUMS and writes SHA256SUMS.sigstore.json.
#   8. Self-verify: `cosign verify-blob` with the exact issuer and identity
#        https://github.com/<owner/repo>/.github/workflows/sign-release.yml@refs/tags/<tag>
#      and with the caller's claims, because the identity names the called workflow file, not the
#      repository that called it (any repository can call a public reusable workflow):
#        --certificate-github-workflow-repository <owner/repo>
#        --certificate-github-workflow-ref refs/tags/<tag>
#        --certificate-github-workflow-trigger push
#      then SHA256SUMS is compared with the folder again. If anything fails, SHA256SUMS and the
#      bundle are deleted and the script exits 1.
# The Rekor log index and the sha256 of SHA256SUMS are printed, and written to
# $GITHUB_STEP_SUMMARY when it is set. The founder publishes them out of band (06, trust roots).
#
# Needs: cosign 3 or newer (scripts/install-release-tool.sh cosign), jq, awk, cmp, and sha256sum
# or shasum.
# Exit: 0 signed and verified, 1 a check or the signature failed, 64 usage error or a missing tool.

set -u

LC_ALL=C
export LC_ALL

here=$(cd "$(dirname "$0")" && pwd)

usage() {
    echo "usage: scripts/sign-release.sh <dir> <tag> <owner/repo> [<repo root>]" >&2
    exit 64
}
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    usage
fi
dir=${1%/}
tag=$2
repo=$3
root=${4:-$here/..}

# The issuer that GitHub Actions tokens carry. Keep equal to the contract table in 06.
issuer=https://token.actions.githubusercontent.com

# 1. Shapes. The tag regexp is the same as the trigger, the plan job and the artifact checker.
if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
    echo "error: '$tag' is not a release tag" >&2
    echo "fix: tags look like v0.1.0-alpha.1. The workflow should only start on such a tag." >&2
    exit 64
fi
if ! printf '%s\n' "$repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
    echo "error: '$repo' is not owner/repo" >&2
    echo "fix: pass GITHUB_REPOSITORY, for example getrdy-io/rdy" >&2
    exit 64
fi
if [ ! -d "$dir" ]; then
    echo "error: $dir is not a directory" >&2
    echo "fix: pass the folder with the downloaded release artifacts" >&2
    exit 64
fi
for tool in cosign jq awk cmp find; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "error: $tool is not installed" >&2
        echo "fix: for cosign run 'sh scripts/install-release-tool.sh cosign'. Install the others from your package manager." >&2
        exit 64
    fi
done
if command -v sha256sum > /dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{ print $1 }'; }
elif command -v shasum > /dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | awk '{ print $1 }'; }
else
    echo "error: neither sha256sum nor shasum is installed" >&2
    echo "fix: install coreutils (sha256sum) or perl (shasum)" >&2
    exit 64
fi

identity="https://github.com/$repo/.github/workflows/sign-release.yml@refs/tags/$tag"
# The Fulcio certificate also carries the claims of the run that called this reusable workflow.
# Without these three, a workflow in any other repository that calls ours would pass.
wf_ref="refs/tags/$tag"
wf_trigger=push

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
# cosign keeps its trust root cache here, not in the home folder.
TUF_ROOT=${TUF_ROOT:-$work/tuf}
export TUF_ROOT

die() {
    printf 'error: %s\n' "$1" >&2
    printf 'fix: %s\n' "$2" >&2
    exit 1
}

# If anything after this point fails, leave no signature files behind.
cleanup_signature() {
    rm -f "$dir/SHA256SUMS" "$dir/SHA256SUMS.sigstore.json"
}

for f in SHA256SUMS SHA256SUMS.sigstore.json; do
    if [ -e "$dir/$f" ] || [ -L "$dir/$f" ]; then
        die "$dir/$f already exists" "only this script writes it, once per run. Find out what wrote it, and start from a fresh download of the artifacts."
    fi
done

# 2. The announce job removes dist's per-job manifests (plan-, global- and <target>-dist-manifest.json)
# and keeps dist-manifest.json. Do the same, so the signed list is the published list.
find "$dir" -maxdepth 1 -type f -name '*-dist-manifest.json' -delete

# 3. Only the expected files.
if ! "$here/check-release-artifacts.sh" --files-only "$dir" > "$work/files.out" 2>&1; then
    cat "$work/files.out" >&2
    die "the release folder holds files that must not be signed" "see the lines above. Do not sign. Find out what wrote them."
fi

# 4. dist's own checksums. sha256.sum has "<hash> *<name>" lines.
if [ ! -f "$dir/sha256.sum" ]; then
    die "$dir/sha256.sum is missing" "dist writes it in build-global-artifacts. Check that job in the release run."
fi
seen=0
for f in "$dir"/rdy-*.tar.gz "$dir"/rdy-*.zip "$dir"/source.tar.gz; do
    [ -f "$f" ] || continue
    name=${f##*/}
    want=$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print $1; exit } }' "$dir/sha256.sum")
    got=$(sha256_of "$f")
    if [ -z "$want" ]; then
        die "sha256.sum has no line for $name" "the archive was added after dist hashed it. Do not sign. Rebuild from the tag."
    fi
    if [ "$want" != "$got" ]; then
        die "$name does not match sha256.sum" "the archive changed after dist hashed it. Do not sign. Rebuild from the tag."
    fi
    seen=$((seen + 1))
done
if [ "$seen" -eq 0 ]; then
    die "no archive in $dir to check against sha256.sum" "the folder should hold dist's archives. Check the artifact download step."
fi

# 5. install.sh from the tagged source, with the tag stamped in as the default version.
src=$root/install.sh
if [ -f "$src" ]; then
    placeholder="RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'"
    stamped="RDY_STAMPED_VERSION='$tag'"
    n=$(grep -c -x -F "$placeholder" "$src")
    if [ "$n" -ne 1 ]; then
        die "install.sh has the line $placeholder on $n lines, not one" "keep that line in install.sh exactly once. This script replaces the whole line with $stamped."
    fi
    if [ -e "$dir/install.sh" ]; then
        die "$dir/install.sh already exists" "only this script adds install.sh. Find out what wrote it."
    fi
    # The tag matched the release tag shape above, so it holds no character that sed treats as special.
    sed "s/^RDY_STAMPED_VERSION='@@RDY_STAMPED_VERSION@@'\$/RDY_STAMPED_VERSION='$tag'/" "$src" > "$dir/install.sh"
    if [ "$(grep -c -x -F "$stamped" "$dir/install.sh")" -ne 1 ] || [ "$(grep -c -x -F "$placeholder" "$dir/install.sh")" -ne 0 ]; then
        die "the stamp did not leave exactly one $stamped line" "check install.sh for a second copy of the line, or for trailing spaces on it"
    fi
    echo "stamped install.sh with $tag"
else
    echo "NOTE: $src does not exist, so this release has no install.sh (it arrives with M1-014)"
fi

# 6. SHA256SUMS over every file in the folder, then 7. the signature.
if ! "$here/make-sha256sums.sh" "$dir" > "$work/SHA256SUMS" 2> "$work/sums.err"; then
    cat "$work/sums.err" >&2
    die "SHA256SUMS could not be written" "see the line above"
fi
cp "$work/SHA256SUMS" "$dir/SHA256SUMS"
echo "SHA256SUMS lists $(wc -l < "$dir/SHA256SUMS" | tr -d ' ') files"

if ! (cd "$dir" && cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS > /dev/null); then
    cleanup_signature
    die "cosign could not sign SHA256SUMS" "check that the job has 'id-token: write', and read the cosign lines above. Sigstore outages end after a few minutes: re-run the job."
fi

# 8. Self-verify, with the exact identity. No regular expression, so a different workflow, tag or
# repository cannot pass.
if ! (cd "$dir" && cosign verify-blob \
    --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$issuer" \
    --certificate-github-workflow-repository "$repo" \
    --certificate-github-workflow-ref "$wf_ref" \
    --certificate-github-workflow-trigger "$wf_trigger" \
    SHA256SUMS); then
    cleanup_signature
    die "the signature does not verify as $identity" "do not publish. The signing identity is not the one install.sh will check. Look for a renamed workflow file, a different tag, a different repository or a trigger other than a tag push."
fi
if ! "$here/make-sha256sums.sh" "$dir" > "$work/SHA256SUMS.again" 2> /dev/null || ! cmp -s "$work/SHA256SUMS.again" "$dir/SHA256SUMS"; then
    cleanup_signature
    die "the files in $dir changed while signing" "do not publish. Find out what wrote to the folder."
fi

digest=$(sha256_of "$dir/SHA256SUMS")
rekor=$(jq -r '.verificationMaterial.tlogEntries[0].logIndex // "unknown"' "$dir/SHA256SUMS.sigstore.json" 2> /dev/null || echo unknown)
echo "signed and verified SHA256SUMS"
echo "  identity:  $identity"
echo "  issuer:    $issuer"
echo "  claims:    repository=$repo ref=$wf_ref trigger=$wf_trigger"
echo "  sha256:    $digest"
echo "  rekor log: $rekor"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Release signature"
        echo
        echo "- Tag: \`$tag\`"
        echo "- Identity: \`$identity\`"
        echo "- Issuer: \`$issuer\`"
        echo "- Claims: repository \`$repo\`, ref \`$wf_ref\`, trigger \`$wf_trigger\`"
        echo "- sha256 of SHA256SUMS: \`$digest\`"
        echo "- Rekor log index: \`$rekor\`"
    } >> "$GITHUB_STEP_SUMMARY"
fi
