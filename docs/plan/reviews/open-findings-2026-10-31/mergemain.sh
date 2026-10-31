#!/bin/sh
# usage: mergemain.sh <branch>   merges origin/main into the branch in a scratch worktree and pushes
set -e
S=<scratchpad>
b=$1; w=$S/wt/$(echo $b | tr / _)
cd /home/user/rdy
git fetch -q origin main "$b"
[ -d "$w" ] || git worktree add -q --detach "$w" origin/$b
cd "$w"
git checkout -q -B "$b" origin/$b
if git merge-base --is-ancestor origin/main HEAD; then echo "up to date $(git rev-parse --short HEAD)"; exit 0; fi
git merge -q --no-ff --no-edit origin/main -m "Merge main into $b

Signed-off-by: Rdy <dev@getrdy.io>
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: <the coordinator session URL>" || { echo CONFLICT; git status --short | grep -E '^(UU|AA|DU|UD)'; exit 1; }
git push -q origin HEAD:$b
echo "pushed $(git rev-parse --short HEAD)"
