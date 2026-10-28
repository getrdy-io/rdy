#!/bin/sh
# check-dco.sh: fail when any commit in a range lacks a Signed-off-by trailer (DCO).
#
# Usage: scripts/check-dco.sh <base-sha> <head-sha>
# Checks every non-merge commit reachable from head and not from base.
# A valid trailer is a line `Signed-off-by: Name <email>` in the trailer block.
# Exit:  0 all commits signed off, 1 at least one is not, 64 usage error.
#
# CI runs this on pull requests with the PR base and head SHAs. It needs full history
# for the range (fetch-depth: 0). It needs only git. No third-party app is involved.

set -u

if [ "$#" -ne 2 ]; then
    echo "usage: scripts/check-dco.sh <base-sha> <head-sha>" >&2
    exit 64
fi
base=$1
head=$2

if ! commits=$(git rev-list --no-merges "$base..$head"); then
    echo "error: could not list commits in $base..$head" >&2
    echo "fix: fetch full history (actions/checkout with fetch-depth: 0) and check both SHAs exist" >&2
    exit 64
fi

bad=0
count=0
for c in $commits; do
    count=$((count + 1))
    if ! git log -1 --format=%B "$c" | git interpret-trailers --parse |
        grep -Eq '^Signed-off-by: .+ <[^<>@ ]+@[^<>@ ]+>$'; then
        bad=$((bad + 1))
        printf 'error: commit %s has no Signed-off-by line: %s\n' \
            "$(git log -1 --format=%h "$c")" "$(git log -1 --format=%s "$c")" >&2
    fi
done

if [ "$bad" -gt 0 ]; then
    echo "fix: sign off the commit with 'git commit --amend -s'." >&2
    echo "fix: for several commits, run 'git rebase --signoff origin/main' and force-push your branch." >&2
    echo "The DCO is at https://developercertificate.org/. See CONTRIBUTING.md." >&2
    exit 1
fi

echo "DCO ok: $count commit(s) signed off."
