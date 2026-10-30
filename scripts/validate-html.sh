#!/bin/sh
# validate-html.sh: run the Nu HTML Checker (vnu.jar) over the HTML report goldens (M1-077 exit test:
# the page passes an HTML validator).
#
# Usage: scripts/validate-html.sh [file.html ...]
#   With no files it checks tests/fixtures/reports/golden/*.html.
# It uses the Java that is on PATH (the GitHub runners ship one). It downloads the pinned release of the
# checker, checks its sha256, and only then runs it. A hash that does not match runs nothing.
# `--Werror` makes warnings fail the run too. The checker also checks the inline CSS.
# CI runs it on the linux-x64 test leg only. The five-leg smoke test is `well_formed` in
# crates/rdy-engine/tests/html_report.rs.
# Exit: 0 valid, 1 invalid or failed, 64 usage error.
#
# The pin. The checker is published as the npm package `vnu-jar` by the validator project, built by its own
# workflow with an npm provenance attestation. To bump it: choose a release, download the tarball, check
# that its sha512 matches both `dist.integrity` in the registry metadata and the subject digest of the
# provenance attestation (https://registry.npmjs.org/-/npm/v1/attestations/vnu-jar@<version>), then
# write the sha256 of the tarball below. Pin both lines together.

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

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    --output "$work/vnu-jar.tgz" "$VNU_URL"
got=$(sha256sum "$work/vnu-jar.tgz" | cut -d ' ' -f 1)
if [ "$got" != "$VNU_SHA256" ]; then
    echo "error: vnu-jar ${VNU_VERSION} has sha256 $got, expected $VNU_SHA256" >&2
    echo "fix: the download changed. Do not bump the pin without the checks in this script's header" >&2
    exit 1
fi
tar -xzf "$work/vnu-jar.tgz" -C "$work" package/build/dist/vnu.jar

java -jar "$work/package/build/dist/vnu.jar" --Werror "$@"
echo "ok: $# file(s) pass the Nu HTML Checker ${VNU_VERSION}"
