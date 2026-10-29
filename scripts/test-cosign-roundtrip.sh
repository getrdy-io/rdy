#!/bin/sh
# test-cosign-roundtrip.sh: run the real cosign verify-blob form from 06 against a real keyless
# signature, and show that it fails when one byte changes (M1-010 exit test, the cosign part).
#
# Usage: scripts/test-cosign-roundtrip.sh        Exit 0 when all pass, 1 on a failure.
#
# Our own release is signed in the sandbox and on the first alpha, which an agent cannot run
# (ADR 0024). This test needs only the network. It downloads the checksum file of cosign's own
# v3.1.4 release and its Sigstore bundle. The bundle holds a keyless signature made by cosign's
# release pipeline. Both files are pinned by sha256 below, so a changed download fails loudly. Then it
# runs `cosign verify-blob` in the exact-identity form that install.sh and the docs use:
#   - the right identity and issuer pass,
#   - a blob with one byte changed fails,
#   - a wrong identity fails,
#   - a wrong issuer fails.
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
    # fetch <file name> <expected sha256>
    if ! curl --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 3 -fsSL -o "$tmp/$1" "$base/$1"; then
        bad "download $1"
        echo "fix: check the network. The test needs github.com and Sigstore's TUF mirror."
        exit 1
    fi
    got=$(sha256sum "$tmp/$1" | awk '{ print $1 }')
    if [ "$got" != "$2" ]; then
        bad "$1 has the pinned sha256"
        echo "fix: the release file changed ($got). Check it by hand, then update the pin in this script."
        exit 1
    fi
}
fetch cosign_checksums.txt "$blob_sha"
fetch cosign_checksums.txt.sigstore.json "$bundle_sha"
cd "$tmp" || exit 1

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

exit "$fail"
