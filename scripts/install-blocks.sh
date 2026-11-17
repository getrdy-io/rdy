#!/bin/sh
# install-blocks.sh: run the install-only blocks of the install page against a published release (M1-133,
# ADR 0047).
#
# Usage:
#   scripts/install-blocks.sh --resolve-tag            print the newest published release tag, or nothing
#   scripts/install-blocks.sh [--tag <tag>] [--page <md>]   run the install-only blocks for <tag>
#
# --resolve-tag asks GitHub for the newest release that is not a draft. It prints `tag=<tag>` on stdout
# when one exists. When none exists it prints a SKIPPED line on stderr and exits 0, so CI shows a skip,
# not a failure. A failed API call exits 1. The release is never guessed.
#
# Running the blocks: every block marked `install-only` in the page (an info string that ends in
# `install-only`) is copied, in order, into one script. The script runs under bash with `set -eo pipefail`.
# It gets RDY_INSTALL_URL, the install.sh of <tag>. The URL is built in this file only, from RELEASE_BASE.
# A block that fails fails the run, and so does a page with no install-only block.
#
# Exit: 0 ran and passed, or skipped (--resolve-tag with no release), 1 failed, 64 usage.
# CI runs this inside a fresh Ubuntu container, as a user with no rights (.github/workflows/install-blocks.yml).

set -eu
LC_ALL=C
export LC_ALL

REPO='getrdy-io/rdy'
RELEASE_BASE="https://github.com/$REPO/releases/download"
TAG_PATTERN='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
page="$root/docs/src/content/docs/install.md"
tag=''
mode=run

usage() {
    echo "usage: scripts/install-blocks.sh --resolve-tag" >&2
    echo "       scripts/install-blocks.sh [--tag <tag>] [--page <md>]" >&2
    exit 64
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --resolve-tag) mode=resolve ;;
        --tag)
            [ "$#" -ge 2 ] || usage
            tag=$2
            shift
            ;;
        --page)
            [ "$#" -ge 2 ] || usage
            page=$2
            shift
            ;;
        *) usage ;;
    esac
    shift
done

resolve_tag() {
    # REST, not `gh release list`: the list command uses GraphQL, which some hosts cannot reach. The API
    # returns the newest release first. The jq filter drops drafts, then keeps the first tag name.
    if ! found=$(gh api "repos/$REPO/releases?per_page=30" --jq '[.[] | select(.draft == false)] | .[0].tag_name // empty'); then
        echo "error: cannot list the releases of $REPO with gh." >&2
        echo "fix: set GH_TOKEN to a token that can read $REPO, then run this again." >&2
        return 1
    fi
    if [ -z "$found" ]; then
        echo "SKIPPED: $REPO has no published release yet. The install-only blocks need a release to run against. Nothing was tested." >&2
        return 0
    fi
    case $found in
        *[!A-Za-z0-9.+-]* | '')
            echo "error: the release tag '$found' has characters the install check does not accept." >&2
            echo "fix: check the release on github.com and remove it if it is wrong." >&2
            return 1
            ;;
    esac
    echo "tag=$found"
}

# extract_blocks <md>: prints the install-only blocks of a page, one after another. A block is the text
# between a fence line that starts with three backticks and the next fence line. Other blocks are skipped
# whole, so a fence inside one of them cannot leak a command.
extract_blocks() {
    awk '
        /^```/ {
            if (in_block) { in_block = 0; keep = 0; next }
            in_block = 1
            keep = ($0 ~ /^```.* install-only([ \t]|$)/)
            if (keep) { print "# --- install-only block from the install page ---" }
            next
        }
        in_block && keep { print }
    ' "$1"
}

run_blocks() {
    if ! printf '%s' "$tag" | grep -Eq "$TAG_PATTERN"; then
        echo "error: '$tag' is not a release tag such as v0.1.0 or v0.1.0-alpha.3." >&2
        echo "fix: pass --tag with a tag from the releases page." >&2
        return 1
    fi
    if [ ! -f "$page" ]; then
        echo "error: cannot read $page." >&2
        echo "fix: run this from a full checkout, or pass --page." >&2
        return 1
    fi
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    script="$work/install-blocks.sh"
    extract_blocks "$page" > "$script"
    if ! grep -q 'install-only block' "$script"; then
        echo "error: $page has no install-only block. Nothing was tested." >&2
        echo "fix: mark the commands that run in CI with the info string install-only." >&2
        return 1
    fi
    RDY_INSTALL_URL="$RELEASE_BASE/$tag/install.sh"
    export RDY_INSTALL_URL
    echo "install-blocks: running the install-only blocks of $page against $tag" >&2
    echo "install-blocks: RDY_INSTALL_URL=$RDY_INSTALL_URL" >&2
    if bash -eo pipefail "$script"; then
        echo "install-blocks: PASS for $tag" >&2
        return 0
    fi
    echo "install-blocks: FAIL for $tag. Read the output above for the command that failed." >&2
    return 1
}

case $mode in
    resolve)
        out=$(resolve_tag) || exit 1
        if [ -n "$out" ]; then
            printf '%s\n' "$out"
        fi
        ;;
    run)
        if [ -z "$tag" ]; then
            out=$(resolve_tag) || exit 1
            if [ -z "$out" ]; then
                exit 0
            fi
            tag=${out#tag=}
        fi
        run_blocks || exit 1
        ;;
esac
