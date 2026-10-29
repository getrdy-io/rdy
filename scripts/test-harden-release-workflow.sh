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
prop "announce checks the files it publishes, and the signed list" has 'check-release-artifacts.sh --files-only --signed artifacts'
prop "the signing job waits for the artifact check" has '^      - custom-check-release-artifacts$'
prop "no workflow inherits secrets" lacks 'secrets: inherit'

# Every `uses:` is a full commit SHA, except the local reusable workflow.
unpinned=$(grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$wf" | grep -Ev 'uses: \./' | grep -Ev '@[0-9a-f]{40}( |$)' || true)
if [ -z "$unpinned" ]; then
    ok "every action is pinned to a commit SHA"
else
    bad "every action is pinned to a commit SHA"
    printf '%s\n' "$unpinned"
fi

# The build jobs run dependency build scripts, so they get no GH_TOKEN variable.
for j in build-local-artifacts build-global-artifacts; do
    block=$(awk -v j="$j" '$0 == "  " j ":" { f = 1; next } f && /^  [a-z][a-z-]*:$/ { exit } f { print }' "$wf")
    if [ -z "$block" ]; then
        bad "$j has no GH_TOKEN variable (job not found in the workflow)"
    elif printf '%s\n' "$block" | grep -q 'GH_TOKEN'; then
        bad "$j has no GH_TOKEN variable"
    else
        ok "$j has no GH_TOKEN variable"
    fi
done
# Every taiki-e/install-action step has its own `fallback: none`, so a missing prebuilt binary fails
# the job instead of running `cargo install`. A count of the two strings would pass when one step has
# two and another has none, so this reads step by step. A step starts at a "- " list line.
# missing_fallback <file>: line numbers of install-action steps that lack the setting.
missing_fallback() {
    awk '
        function flush() { if (inst && !fb) printf "%s ", start; inst = 0; fb = 0 }
        /^[[:space:]]*- / { flush(); start = NR }
        /taiki-e\/install-action@/ { inst = 1; seen = 1 }
        /^[[:space:]]+fallback: none[[:space:]]*(#.*)?$/ { fb = 1 }
        END { flush(); if (!seen) printf "none-found" }
    ' "$1"
}
# The checker itself: a file where only the second step has the setting, and a file where only the
# first has it.
cat > "$tmp/fb-bad.yml" << 'EOF'
steps:
  - name: one
    uses: taiki-e/install-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    with:
      tool: a@1
  - name: two
    uses: taiki-e/install-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    with:
      tool: b@1
      fallback: none
EOF
cat > "$tmp/fb-dup.yml" << 'EOF'
steps:
  - uses: taiki-e/install-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    with:
      tool: a@1
      fallback: none
  - uses: taiki-e/install-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    with:
      tool: b@1
EOF
if [ "$(missing_fallback "$tmp/fb-bad.yml")" = "2 " ] && [ "$(missing_fallback "$tmp/fb-dup.yml")" = "6 " ]; then
    ok "the fallback check finds the step that lacks fallback: none"
else
    bad "the fallback check finds the step that lacks fallback: none"
fi
for f in "$wf" "$root/.github/workflows/check-release-artifacts.yml" "$root/.github/workflows/sign-release.yml"; do
    name=${f##*/}
    m=$(missing_fallback "$f")
    case $m in
        "") ok "$name: every install-action step sets fallback: none" ;;
        none-found) ok "$name: no install-action step" ;;
        *) bad "$name: install-action steps without fallback: none start at line $m" ;;
    esac
done

# Every job names its permissions, and only announce can write.
jobs=$(awk '/^jobs:/ { j = 1; next } j && /^  [a-z][a-z-]*:$/ { sub(/:$/, "", $1); print $1 }' "$wf")
missing=""
[ -n "$jobs" ] || missing=" (no jobs found)"
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
# Only the signing job has an OIDC token. Find every id-token line and the job it sits in.
idjobs=$(awk '/^jobs:/ { j = 1; next } j && /^  [a-z][a-z-]*:$/ { name = $1; sub(/:$/, "", name) } j && /id-token/ { print name }' "$wf" | sort -u | tr '\n' ' ')
if [ "$idjobs" = "custom-sign-release " ]; then
    ok "only custom-sign-release has id-token"
else
    bad "only custom-sign-release has id-token (found: $idjobs)"
fi
sw="$root/.github/workflows/sign-release.yml"
if grep -q '^    environment: release$' "$sw"; then
    ok "the signing job runs in the environment release"
else
    bad "the signing job runs in the environment release"
fi
if grep -q 'contents: write' "$sw"; then
    bad "the signing workflow has no write token"
else
    ok "the signing workflow has no write token"
fi
writers=$(awk '/^jobs:/ { j = 1; next } j && /^  [a-z][a-z-]*:$/ { name = $1; sub(/:$/, "", name) } j && /contents.*write/ { print name }' "$wf" | sort -u | tr '\n' ' ')
if [ "$writers" = "announce " ]; then
    ok "only announce can write contents"
else
    bad "only announce can write contents (found: $writers)"
fi

exit "$fail"
