#!/bin/sh
# test-check-dco.sh: tests for scripts/check-dco.sh on a throwaway repo. Exit 0 when all pass.

set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/check-dco.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

ok() { printf 'PASS %s\n' "$1"; }
bad() {
    printf 'FAIL %s\n' "$1"
    fail=1
}

cd "$tmp" || exit 1
git init -q -b main .
git config user.name "Test Author"
git config user.email "author@example.test"
git config commit.gpgsign false
git commit -q --allow-empty -m "base commit"
base=$(git rev-parse HEAD)

# check <name> <expected exit> [<base> <head>]
check() {
    name=$1
    want=$2
    shift 2
    out=$("$script" "$@" 2>&1)
    code=$?
    if [ "$code" -eq "$want" ]; then ok "$name"; else
        bad "$name (exit $code, want $want)"
        echo "$out"
    fi
}

git commit -q --allow-empty -s -m "signed commit"
signed=$(git rev-parse HEAD)
check "signed commit passes" 0 "$base" "$signed"

git commit -q --allow-empty -m "unsigned commit"
unsigned=$(git rev-parse HEAD)
check "unsigned commit fails" 1 "$signed" "$unsigned"
check "unsigned commit in a longer range fails" 1 "$base" "$unsigned"

out=$("$script" "$signed" "$unsigned" 2>&1)
case $out in
*"fix:"*) ok "failure prints a fix line" ;;
*) bad "failure prints a fix line" ;;
esac

# A sign-off in prose, outside the trailer block, does not count.
git commit -q --allow-empty -m "prose mention" -m "I would say Signed-off-by: Test Author <author@example.test> here, then more text." -m "More prose after."
prose=$(git rev-parse HEAD)
check "sign-off inside prose fails" 1 "$unsigned" "$prose"

# A sign-off added by hand in the trailer block counts.
git commit -q --allow-empty -m "manual trailer" -m "Body text." -m "Signed-off-by: Other Person <other@example.test>"
manual=$(git rev-parse HEAD)
check "hand-written trailer passes" 0 "$prose" "$manual"

# A malformed trailer (no email) fails.
git commit -q --allow-empty -m "no email" -m "Signed-off-by: Nobody"
noemail=$(git rev-parse HEAD)
check "trailer without an email fails" 1 "$manual" "$noemail"

# Sign-off followed by other trailers still passes.
git commit -q --allow-empty -s -m "with co-author" -m "Co-Authored-By: Claude <noreply@anthropic.com>"
co=$(git rev-parse HEAD)
check "sign-off then other trailers passes" 0 "$noemail" "$co"

# Merge commits are skipped. Their parents are still checked.
git checkout -q -b side "$signed"
git commit -q --allow-empty -s -m "side signed"
git checkout -q main
git merge -q --no-ff --no-edit side
merge=$(git rev-parse HEAD)
check "unsigned merge commit is skipped" 0 "$co" "$merge"

check "empty range passes" 0 "$merge" "$merge"

check "no arguments is a usage error" 64
check "unknown sha is a usage error" 64 "$base" 0000000000000000000000000000000000000001

[ "$fail" -eq 0 ] && echo "all tests passed"
exit "$fail"
