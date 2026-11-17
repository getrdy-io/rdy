#!/bin/sh
# validate-html.sh: run the Nu HTML Checker (vnu.jar) over the HTML report goldens (M1-077 exit test:
# the page passes an HTML validator).
#
# Usage: scripts/validate-html.sh [file.html ...]
#   With no files it checks tests/fixtures/reports/golden/*.html.
# It uses the Java that is on PATH (the GitHub runners ship one). It downloads the pinned release of the
# checker, checks its sha256, and only then runs it. A hash that does not match runs nothing.
# `--Werror` makes warnings fail the run too. The checker also checks the inline CSS.
# CI runs it in the `html-validator` job (checkout and Java only, no cargo, no cache). The five-leg smoke
# test is `well_formed` in crates/rdy-engine/tests/html_report.rs.
# Exit: 0 valid, 1 invalid or failed, 64 usage error.
#
# The pin. The checker is published as the npm package `vnu-jar` by the validator project, built by its own
# workflow and published with an npm provenance attestation (SLSA v1, signed with Sigstore). Nothing in the
# registry is trusted by itself, because it serves both the tarball and its attestation. To bump the pin:
#   1. Choose a release. Download the tarball vnu-jar-<version>.tgz and the attestation bundle from
#      https://registry.npmjs.org/-/npm/v1/attestations/vnu-jar@<version> (the SLSA provenance one).
#   2. Check that the tarball sha512 equals `dist.integrity` in the registry metadata.
#   3. Verify the signed chain with cosign (3.1.3 or newer):
#        cosign verify-blob-attestation --bundle <slsa-bundle.json> \
#          --type https://slsa.dev/provenance/v1 \
#          --certificate-identity https://github.com/validator/validator/.github/workflows/build.yml@refs/heads/main \
#          --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#          vnu-jar-<version>.tgz
#   4. Write the sha256 of the tarball and the new version below. Pin both lines together.
# Pinned 26.10.12: built from validator/validator commit 973e40b16d1c653cf52523b126ef92aec8bf9e0e
# (the jar's manifest says 26.10.12 (973e40b)), Rekor log index 3228121956 (2026-10-12), verified by the
# security review of PR #149 (SEC-149-8). The jar runs in CI only and is never shipped.

set -eu

LC_ALL=C
export LC_ALL

VNU_VERSION=26.10.12
VNU_SHA256=3925f07364f5e5a111cef54a7baefa575b22d05c70f8ced048f0616d4579b7ab
VNU_URL="https://registry.npmjs.org/vnu-jar/-/vnu-jar-${VNU_VERSION}.tgz"

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

if [ "$#" -eq 0 ]; then
    set -- "$root"/tests/fixtures/reports/golden/*.html
fi
for f in "$@"; do
    if [ ! -f "$f" ]; then
        echo "error: $f is not a file" >&2
        echo "fix: run the script from a full checkout, or name existing .html files" >&2
        exit 64
    fi
done

if ! command -v java >/dev/null 2>&1; then
    echo "error: java is not on PATH" >&2
    echo "fix: install a Java runtime (the GitHub runners have one)" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash_file() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
    hash_file() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
    echo "error: neither sha256sum nor shasum is on PATH" >&2
    echo "fix: install coreutils (sha256sum) or perl's shasum, then run again" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    --connect-timeout 20 --max-time 300 \
    --output "$work/vnu-jar.tgz" "$VNU_URL"
got=$(hash_file "$work/vnu-jar.tgz")
if [ -z "$got" ]; then
    echo "error: could not compute the sha256 of the download" >&2
    echo "fix: check that sha256sum or shasum works on this machine" >&2
    exit 1
fi
if [ "$got" != "$VNU_SHA256" ]; then
    echo "error: vnu-jar ${VNU_VERSION} has sha256 $got, expected $VNU_SHA256" >&2
    echo "fix: the download changed. Do not bump the pin without the checks in this script's header" >&2
    exit 1
fi
tar -xzf "$work/vnu-jar.tgz" -C "$work" package/build/dist/vnu.jar

# One message is filtered (M1-078). The embedded result is `<script type="application/json">`, a data block
# that no browser runs, and the page's CSP has no `script-src` on purpose (default-src 'none', ADR 0003
# decision 3). The checker warns that an "inline script" is blocked by that policy, which is true of a
# script that runs and does not apply to a data block. The page must not have an executable script, and
# html_report.rs asserts that the page has exactly one `<script`, the data block. The CSP is not
# loosened and not given a hash to quiet the checker. The pattern matches the whole message (the curly
# quotes are any one to three characters), so a different message about a script still fails. Every other
# warning and error still fails the run.
java -jar "$work/package/build/dist/vnu.jar" --Werror \
    --filterpattern 'Inline script violates Content Security Policy \(meta tag\): blocked by .script-src. directive \(missing .{1,3}unsafe-inline.{1,3} or nonce/hash\)\.' \
    "$@"
echo "ok: $# file(s) pass the Nu HTML Checker ${VNU_VERSION}"
