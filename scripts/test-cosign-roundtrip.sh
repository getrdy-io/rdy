#!/bin/sh
# test-cosign-roundtrip.sh: run the real cosign verify-blob form from 06 against a real keyless
# signature, and show that it fails when one byte changes (M1-010 exit test, the cosign part).
#
# Usage: scripts/test-cosign-roundtrip.sh        Exit 0 when all pass, 1 on a failure.
#
# Our own release is signed in the sandbox and on the first alpha, which an agent cannot run
# (ADR 0024). This test needs only the network. It downloads two released checksum files with their
# Sigstore bundles. Each bundle holds a real keyless signature. Every file is pinned by sha256 below, so
# a changed download fails loudly. Then it runs `cosign verify-blob` in the form that install.sh and
# the docs use.
#
# Part 1, cosign's own v3.1.4 release (signed by a Google service account): the exact identity and
# issuer pass, and a changed byte, a wrong identity and a wrong issuer fail.
#
# Part 2, goreleaser v2.19.0 (signed by a GitHub Actions workflow on a tag push, the same kind of
# certificate our release gets): the full form of 06 passes, that is exact identity, issuer, and the
# three claims --certificate-github-workflow-repository, -ref and -trigger. A wrong repository, a wrong
# ref and a wrong trigger each fail. That is the check that stops another repository's run from passing.
# This upstream workflow is not a reusable workflow that another repository called, so the case where
# the identity is right and the caller is wrong is shown by the fake cosign in test-sign-release.sh and
# by the release-sandbox run (06, "Sandbox proof, signing"), not here. No stable public bundle of that
# shape is known; add one here when it is.
# It needs cosign 3 on PATH (scripts/install-release-tool.sh cosign), curl and sha256sum, and
# reaches Sigstore's TUF root over the network. Without cosign it skips on a developer machine and
# fails in CI ($CI set), so a missing install cannot become a silent pass.

set -u

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

for tool in cosign curl sha256sum cmp tail; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        if [ -n "${CI:-}" ]; then
            echo "FAIL $tool is missing in CI"
            exit 1
        fi
        echo "SKIP all: $tool is missing here"
        exit 0
    fi
done

# The files of cosign v3.1.4 and what they must hash to.
base=https://github.com/sigstore/cosign/releases/download/v3.1.4
blob_sha=e70e59b328d52949b3a9ae3e0d04721ea8f380c4e91c28197aa91df02afbf4c0
bundle_sha=8fc87b5562359b0414655ee281b80eb3752f58c4e137d5f0e4881f095bc26309
# The identity of cosign's release pipeline: a Google service account, so the issuer is Google's.
identity=keyless@projectsigstore.iam.gserviceaccount.com
issuer=https://accounts.google.com

TUF_ROOT="$tmp/tuf"
export TUF_ROOT

fetch() {
    # fetch <base url> <file name> <expected sha256> <local path under $tmp>
    if ! curl --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 3 -fsSL -o "$tmp/$4" "$1/$2"; then
        bad "download $1/$2"
        echo "fix: check the network. The test needs the release host and Sigstore's TUF mirror."
        exit 1
    fi
    got=$(sha256sum "$tmp/$4" | awk '{ print $1 }')
    if [ "$got" != "$3" ]; then
        bad "$2 has the pinned sha256"
        echo "fix: the release file changed ($got). Check it by hand, then update the pin in this script."
        exit 1
    fi
}
mkdir "$tmp/cosign" "$tmp/gr"
fetch "$base" cosign_checksums.txt "$blob_sha" cosign/cosign_checksums.txt
fetch "$base" cosign_checksums.txt.sigstore.json "$bundle_sha" cosign/cosign_checksums.txt.sigstore.json

# Part 2 files: goreleaser v2.19.0, signed by .github/workflows/release.yml of its own repository on
# the push of the tag v2.19.0.
gr_base=https://github.com/goreleaser/goreleaser/releases/download/v2.19.0
gr_blob_sha=f326ec8ef1e68d76cc9cdfeaedfbe34cea85ffd775d781e8fc2d6bb3fd80923e
gr_bundle_sha=c906456654c1d9e25469ce384e90e166af51baf571aa011e4a74560faf268df1
gr_identity=https://github.com/goreleaser/goreleaser/.github/workflows/release.yml@refs/tags/v2.19.0
gr_issuer=https://token.actions.githubusercontent.com
fetch "$gr_base" checksums.txt "$gr_blob_sha" gr/checksums.txt
fetch "$gr_base" checksums.txt.sigstore.json "$gr_bundle_sha" gr/checksums.txt.sigstore.json

# ---- part 1 ------------------------------------------------------------------------------------
cd "$tmp/cosign" || exit 1

verify() {
    # verify <blob> <identity> <issuer>
    cosign verify-blob \
        --bundle cosign_checksums.txt.sigstore.json \
        --certificate-identity "$2" \
        --certificate-oidc-issuer "$3" \
        "$1" > "$tmp/verify.out" 2>&1
}

if verify cosign_checksums.txt "$identity" "$issuer"; then
    ok "verify-blob passes with the exact identity and issuer"
else
    bad "verify-blob passes with the exact identity and issuer"
    cat "$tmp/verify.out"
fi

# One byte changed: the first byte becomes an X. The length stays the same.
{ printf 'X'; tail -c +2 cosign_checksums.txt; } > changed.txt
if cmp -s cosign_checksums.txt changed.txt; then
    bad "the changed copy differs from the original"
else
    ok "the changed copy differs from the original"
fi
if verify changed.txt "$identity" "$issuer"; then
    bad "verify-blob fails after one byte changes"
else
    ok "verify-blob fails after one byte changes"
fi

if verify cosign_checksums.txt "someone-else@example.com" "$issuer"; then
    bad "verify-blob fails with a wrong identity"
else
    ok "verify-blob fails with a wrong identity"
fi
if verify cosign_checksums.txt "$identity" "https://token.actions.githubusercontent.com"; then
    bad "verify-blob fails with a wrong issuer"
else
    ok "verify-blob fails with a wrong issuer"
fi

# ---- part 2: the GitHub Actions form of 06 -----------------------------------------------------
cd "$tmp/gr" || exit 1

gr_verify() {
    # gr_verify <blob> <repository> <ref> <trigger>: the full form, with exact identity and issuer.
    cosign verify-blob \
        --bundle checksums.txt.sigstore.json \
        --certificate-identity "$gr_identity" \
        --certificate-oidc-issuer "$gr_issuer" \
        --certificate-github-workflow-repository "$2" \
        --certificate-github-workflow-ref "$3" \
        --certificate-github-workflow-trigger "$4" \
        "$1" > "$tmp/verify.out" 2>&1
}

if gr_verify checksums.txt goreleaser/goreleaser refs/tags/v2.19.0 push; then
    ok "verify-blob passes with identity, issuer, repository, ref and trigger"
else
    bad "verify-blob passes with identity, issuer, repository, ref and trigger"
    cat "$tmp/verify.out"
fi
if gr_verify checksums.txt evil-org/goreleaser refs/tags/v2.19.0 push; then
    bad "verify-blob fails with a wrong repository"
else
    ok "verify-blob fails with a wrong repository"
fi
if gr_verify checksums.txt goreleaser/goreleaser refs/tags/v2.19.1 push; then
    bad "verify-blob fails with a wrong ref"
else
    ok "verify-blob fails with a wrong ref"
fi
if gr_verify checksums.txt goreleaser/goreleaser refs/heads/main push; then
    bad "verify-blob fails with a branch ref"
else
    ok "verify-blob fails with a branch ref"
fi
if gr_verify checksums.txt goreleaser/goreleaser refs/tags/v2.19.0 workflow_dispatch; then
    bad "verify-blob fails with a wrong trigger"
else
    ok "verify-blob fails with a wrong trigger"
fi
{ printf 'X'; tail -c +2 checksums.txt; } > changed.txt
if gr_verify changed.txt goreleaser/goreleaser refs/tags/v2.19.0 push; then
    bad "verify-blob fails after one byte changes, with all claims right"
else
    ok "verify-blob fails after one byte changes, with all claims right"
fi

exit "$fail"
