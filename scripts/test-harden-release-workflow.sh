#!/bin/sh
# test-harden-release-workflow.sh: tests for scripts/harden-release-workflow.py and the committed
# .github/workflows/release.yml. Exit 0 when all pass.
#
# The drift check (scripts/gen-release-workflow.sh --check) proves the file is what dist plus the
# script produce. These tests prove the script fails loudly on output it does not know, and that the
# committed file keeps the properties ADR 0020 promises, whatever produced it.

set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
script="$here/harden-release-workflow.py"
wf="$root/.github/workflows/release.yml"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

if ! command -v python3 > /dev/null 2>&1; then
    if [ -n "${CI:-}" ]; then
        echo "FAIL python3 is missing in CI"
        exit 1
    fi
    echo "SKIP all: python3 is missing"
    exit 0
fi

# Output the script does not know must stop it, not pass through.
printf 'name: Release\njobs: {}\n' > "$tmp/unknown.yml"
out=$(python3 -I "$script" "$tmp/unknown.yml" "$tmp/out.yml" 2>&1)
code=$?
if [ "$code" -ne 0 ] && printf '%s\n' "$out" | grep -q "expected the text below once" && [ ! -e "$tmp/out.yml" ]; then
    ok "unknown dist output stops the script and writes nothing"
else
    bad "unknown dist output stops the script and writes nothing (exit $code)"
fi
if python3 -I "$script" > /dev/null 2>&1; then bad "no arguments is an error"; else ok "no arguments is an error"; fi

# Properties of the committed file.
# prop <name> has|lacks <regex>: the committed workflow has, or lacks, a line matching the regex.
prop() {
    if grep -Eq -- "$3" "$wf"; then found=has; else found=lacks; fi
    if [ "$found" = "$2" ]; then ok "$1"; else bad "$1"; fi
}

prop "the workflow has no default token" has '^permissions: \{\}$'
prop "no workflow-level write permission" lacks '^permissions:$'
prop "only tags like v1.2.3 start a release" has "^      - 'v\[0-9\]\+\.\[0-9\]\+\.\[0-9\]\+\*'$"
prop "the old any-tag trigger is gone" lacks "\*\*\[0-9\]"
prop "no curl piped to a shell" lacks '\| *sh'
prop "no dist install script from a URL" lacks 'installer\.(sh|ps1)'
prop "no latest download" lacks 'releases/latest'
prop "the tag is not pasted into shell text" lacks '\$\{\{ *needs\.plan\.outputs\.tag'"(-flag)? *\}\}\"? *--"
prop "the old tag-flag output is gone" lacks 'tag-flag'
prop "the plan step checks the tag shape" has "grep -Eq '\^v\[0-9\]\+"
prop "the SBOM step output name is outputs" lacks 'cargo-cyclonedx\.output\.'
prop "announce checks the files it publishes" has 'check-release-artifacts.sh --files-only artifacts'

# Every `uses:` is a full commit SHA, except the local reusable workflow.
unpinned=$(grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$wf" | grep -Ev 'uses: \./' | grep -Ev '@[0-9a-f]{40}( |$)' || true)
if [ -z "$unpinned" ]; then
    ok "every action is pinned to a commit SHA"
else
    bad "every action is pinned to a commit SHA"
    printf '%s\n' "$unpinned"
fi

# Every job names its permissions, and only announce can write.
jobs=$(awk '/^jobs:/ { j = 1; next } j && /^  [a-z][a-z-]*:$/ { sub(/:$/, "", $1); print $1 }' "$wf")
missing=""
for j in $jobs; do
    block=$(awk -v j="$j" '$0 == "  " j ":" { f = 1; next } f && /^  [a-z][a-z-]*:$/ { exit } f { print }' "$wf")
    if ! printf '%s\n' "$block" | grep -q '^    permissions:$'; then
        missing="$missing $j"
    fi
done
if [ -z "$missing" ]; then
    ok "every job names its permissions"
else
    bad "every job names its permissions (missing:$missing)"
fi
writers=$(awk '/^jobs:/ { j = 1; next } j && /^  [a-z][a-z-]*:$/ { name = $1; sub(/:$/, "", name) } j && /contents.*write/ { print name }' "$wf" | sort -u | tr '\n' ' ')
if [ "$writers" = "announce " ]; then
    ok "only announce can write contents"
else
    bad "only announce can write contents (found: $writers)"
fi

exit "$fail"
