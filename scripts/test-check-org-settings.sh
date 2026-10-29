#!/bin/sh
# test-check-org-settings.sh: offline stub tests for scripts/check-org-settings.sh.
# A fake curl on PATH answers from synthetic replies in scripts/test-check-org-settings.json.
# Each scenario is a route table: one "PATH CODE REPLY" line per API path. Needs jq.
# Exit 0 when all pass.

set -u

here=$(dirname "$0")
case "$here" in
/*) ;;
*) here="$PWD/$here" ;;
esac
script="$here/check-org-settings.sh"
FIXTURES="$here/test-check-org-settings.json"
tmp=$(mktemp -d) || exit 70
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$tmp/bin"
cat >"$tmp/bin/curl" <<'EOF'
#!/bin/sh
# Fake curl. Looks up the URL path in $ROUTES (the last matching line wins), writes the named reply from $FIXTURES to the
# -o file and prints the status code. A path with no route is a 404.
# Every argv goes to $LOGS/argv.log, and any header read from stdin to $LOGS/headers.log.
out=""
prev=""
url=""
for a; do
  if [ "$prev" = -o ]; then out=$a; fi
  if [ "$prev" = -H ] && [ "$a" = @- ]; then cat >>"$LOGS/headers.log"; fi
  prev=$a
  url=$a
done
printf '%s\n' "$*" >>"$LOGS/argv.log"
[ "$ROUTES" = down ] && exit 6
path=${url#https://api.github.com/}
[ "$path" = "$url" ] && exit 3
line=$(printf '%s\n' "$ROUTES" | awk -v p="$path" '$1 == p { l = $0 } END { if (l != "") print l }')
if [ -z "$line" ]; then
  line="$path 404 not-found"
fi
set -- $line
jq -r --arg n "$3" '.[$n] | if type == "string" then . else tojson end' "$FIXTURES" | tee "$out" >/dev/null
printf '%s' "$2"
EOF
chmod +x "$tmp/bin/curl"

failures=0

# expect NAME GREP_PATTERN: the captured output must match the pattern.
expect() {
  if printf '%s\n' "$out" | grep -Eq "$2"; then
    echo "ok      $1"
  else
    echo "NOT OK  $1 (wanted: $2)"
    printf '%s\n' "$out" | sed 's/^/        | /'
    failures=$((failures + 1))
  fi
}

# expect_code NAME CODE: the last run must exit with CODE.
expect_code() {
  if [ "$code" = "$2" ]; then
    echo "ok      $1"
  else
    echo "NOT OK  $1 (wanted exit $2, got $code)"
    printf '%s\n' "$out" | sed 's/^/        | /'
    failures=$((failures + 1))
  fi
}

# route PATH CODE REPLY: answer GET https://api.github.com/PATH with CODE and the named reply.
route() {
  ROUTES="$ROUTES
$1 $2 $3"
}

R=repos/getrdy-io/rdy

# all_good: an organization where every item passes for an admin token.
all_good() {
  ROUTES=""
  route "$R" 200 repo-org-admin
  route user 200 user
  route orgs/getrdy-io 200 org-2fa-on
  route "$R/private-vulnerability-reporting" 200 enabled-true
  route "$R/immutable-releases" 200 immutable-on
  route "$R/rules/branches/main?per_page=100" 200 main-rules
  route "$R/rulesets/1" 200 ruleset-1-pr-bypass
  route "$R/rulesets?includes_parents=true&per_page=100" 200 rulesets
  route "$R/rulesets/2?includes_parents=true" 200 ruleset-2-admin
  route "$R/contents/SECURITY.md" 200 security-both
}

# run [ARGS...]: run the script with the token in TOKEN_FOR_RUN (empty means none).
run() {
  rm -f "$tmp/logs/argv.log" "$tmp/logs/headers.log"
  out=$(PATH="$tmp/bin:$PATH" ROUTES="$ROUTES" FIXTURES="$FIXTURES" LOGS="$tmp/logs" \
    GH_TOKEN="${TOKEN_FOR_RUN:-}" GITHUB_TOKEN='' sh "$script" "$@" 2>&1)
  code=$?
}
mkdir "$tmp/logs"

# A synthetic value in the token alphabet. It is not a real token and has no real prefix.
TOKEN_FOR_RUN=synthetic_test_token_0123456789

# 1. every setting on, admin token: all PASS, exit 0, and the token stays off argv and output.
all_good
run
expect_code "all settings on exits 0" 0
expect "org 2FA passes" '^PASS +org 2FA: two_factor_requirement_enabled is true'
expect "private reporting passes" '^PASS +private vulnerability reporting: enabled'
expect "immutable releases pass" '^PASS +immutable releases: enabled'
expect "main ruleset passes" '^PASS +main ruleset:'
expect "tag ruleset passes" '^PASS +v\* tag ruleset:'
expect "policy passes" '^PASS +Security tab policy:'
expect "the caller is named" '^Caller: token for synthetic-founder, repo admin: yes'
expect "summary counts six passes" 'Summary: 6 passed, 0 failed, 0 unknown'
if grep -q "$TOKEN_FOR_RUN" "$tmp/logs/argv.log"; then
  echo "NOT OK  the token appeared on the curl command line"
  failures=$((failures + 1))
else
  echo "ok      the token never appears on the curl command line"
fi
if grep -qx "Authorization: Bearer $TOKEN_FOR_RUN" "$tmp/logs/headers.log"; then
  echo "ok      the token is sent as a header on stdin"
else
  echo "NOT OK  the token was not sent as a header on stdin"
  failures=$((failures + 1))
fi
case "$out" in
*"$TOKEN_FOR_RUN"*)
  echo "NOT OK  the token was printed"
  failures=$((failures + 1))
  ;;
*) echo "ok      the token is never printed" ;;
esac
# Every request has a time limit and never follows a redirect, so the token stays on api.github.com.
if [ -s "$tmp/logs/argv.log" ] && ! grep -vq -- '--max-time 20' "$tmp/logs/argv.log"; then
  echo "ok      every curl call has --max-time"
else
  echo "NOT OK  a curl call has no --max-time"
  failures=$((failures + 1))
fi
if grep -Eq -- '(^| )(-L|--location|--location-trusted)( |$)' "$tmp/logs/argv.log"; then
  echo "NOT OK  a curl call follows redirects"
  failures=$((failures + 1))
else
  echo "ok      no curl call follows redirects"
fi

# 2. a personal account cannot require 2FA: FAIL, not PASS.
all_good
route "$R" 200 repo-user
run
expect_code "personal account exits 1" 1
expect "personal account fails org 2FA" '^FAIL +org 2FA: getrdy-io is a personal account'

# 3. 2FA off and private reporting off are failures with fix lines.
all_good
route orgs/getrdy-io 200 org-2fa-off
route "$R/private-vulnerability-reporting" 200 enabled-false
run
expect "2FA off fails" '^FAIL +org 2FA: two_factor_requirement_enabled is false'
expect "a fix line follows a failure" '^ +fix: Organization settings > Authentication security'
expect "private reporting off fails" '^FAIL +private vulnerability reporting: disabled'

# 4. 2FA hidden from a non-owner is UNKNOWN, and UNKNOWN alone exits 2.
all_good
route orgs/getrdy-io 200 org-2fa-hidden
run
expect "hidden 2FA is unknown" '^UNKNOWN org 2FA: GitHub shows two_factor_requirement_enabled only to org owners'
expect "unknown has a rerun fix line" '^ +fix: Rerun with a repo admin token'
expect_code "unknown without failures exits 2" 2

# 5. immutable releases: 404 to an admin fails, 404 to a non-admin and 403 are unknown.
all_good
route "$R/immutable-releases" 404 not-found
run
expect "404 to an admin fails" '^FAIL +immutable releases: not enabled'
all_good
route "$R" 200 repo-org-nonadmin
route "$R/immutable-releases" 404 not-found
run
expect "404 to a non-admin is unknown" '^UNKNOWN immutable releases: HTTP 404 means off'
all_good
route "$R/immutable-releases" 403 forbidden
run
expect "403 is unknown with the reason" '^UNKNOWN immutable releases: cannot read the setting \(HTTP 403 Resource not accessible'

# 6. main ruleset: missing rules fail, a direct-push bypass fails, a hidden bypass list is unknown.
all_good
route "$R/rules/branches/main?per_page=100" 200 main-rules-pr-only
run
expect "missing main rules fail" '^FAIL +main ruleset: the active rules on main lack: non_fast_forward deletion required_linear_history required_status_checks\(ci-ok from GitHub Actions\)'
all_good
route "$R/rules/branches/main?per_page=100" 200 empty-list
run
expect "no rules on main fails" '^FAIL +main ruleset: the active rules on main lack: pull_request'
all_good
route "$R/rulesets/1" 200 ruleset-1-always-bypass
run
expect "an always bypass on main fails" '^FAIL +main ruleset: .*push to main without a PR: ruleset 1: RepositoryRole:5\(always\)'
all_good
route "$R/rulesets/1" 200 ruleset-1-hidden
run
expect "a hidden main bypass list is unknown" '^UNKNOWN main ruleset: the rules are on, but GitHub hides the bypass list of ruleset 1'
all_good
route "$R/rules/branches/main?per_page=100" 200 main-rules-ci-ok-any-source
run
expect "ci-ok from any source fails" '^FAIL +main ruleset: the active rules on main lack: required_status_checks\(ci-ok from GitHub Actions\)'
all_good
route "$R/rules/branches/main?per_page=100" 200 main-rules-ci-ok-other-app
run
expect "ci-ok from another app fails" '^FAIL +main ruleset: the active rules on main lack: required_status_checks\(ci-ok from GitHub Actions\)'
# The emergency path in section 4: Repository admin "for pull requests" passes (all_good uses it),
# but the same mode for a non-admin role fails, because it merges without ci-ok.
all_good
route "$R/rulesets/1" 200 ruleset-1-write-pr-bypass
run
expect "a non-admin pull request bypass on main fails" '^FAIL +main ruleset: .*not admins and can merge to main without ci-ok: ruleset 1: RepositoryRole:4\(pull_request\)'

# 7. tag ruleset: none, an app that bypasses, no bypass at all, hidden bypass, other tags, evaluate only.
all_good
route "$R/rulesets?includes_parents=true&per_page=100" 200 empty-list
run
expect "no tag ruleset fails" '^FAIL +v\* tag ruleset: no active tag ruleset that covers refs/tags/v\* has: creation update deletion'
all_good
route "$R/rulesets/2?includes_parents=true" 200 ruleset-2-app
run
expect "an app that bypasses tag creation fails" '^FAIL +v\* tag ruleset: actors other than admins can bypass the v\* tag rules .*: ruleset 2: Integration:99\(always\)'
all_good
route "$R/rulesets/2?includes_parents=true" 200 ruleset-2-nobody
run
expect "no bypass at all fails" '^FAIL +v\* tag ruleset: ruleset 2 blocks v\* tag creation with no bypass'
all_good
route "$R/rulesets/2?includes_parents=true" 200 ruleset-2-hidden
run
expect "a hidden tag bypass list is unknown" '^UNKNOWN v\* tag ruleset: GitHub hides ruleset 2'
all_good
route "$R/rulesets/2?includes_parents=true" 200 ruleset-2-other-tags
run
expect "a ruleset on other tags does not count" '^FAIL +v\* tag ruleset: no active tag ruleset that covers'
all_good
route "$R/rulesets?includes_parents=true&per_page=100" 200 rulesets-evaluate
run
expect "an evaluate-only ruleset does not count" '^FAIL +v\* tag ruleset: no active tag ruleset'

# 7b. the two-ruleset layout from section 5: "release tags: create" (creation, admin bypass) and
# "release tags: frozen" (update, deletion, force push, no bypass). Any non-admin bypass on the
# frozen ruleset fails, because it could move or delete a released tag.
two_tag() {
  all_good
  route "$R/rulesets?includes_parents=true&per_page=100" 200 rulesets-two-tag
  route "$R/rulesets/2?includes_parents=true" 200 ruleset-2-create
  route "$R/rulesets/3?includes_parents=true" 200 ruleset-3-frozen
}
two_tag
run
expect_code "the two-ruleset layout exits 0" 0
expect "the two-ruleset layout passes" '^PASS +v\* tag ruleset: .*\(ruleset 2 3\)'
two_tag
route "$R/rulesets/3?includes_parents=true" 200 ruleset-3-frozen-write
run
expect_code "a Write-role bypass on the frozen ruleset exits 1" 1
expect "a Write-role bypass on the frozen ruleset fails" '^FAIL +v\* tag ruleset: actors other than admins can bypass the v\* tag rules .*: ruleset 3: RepositoryRole:4\(always\)'
two_tag
route "$R/rulesets/3?includes_parents=true" 200 ruleset-3-frozen-deploy-key
run
expect "a deploy key bypass on the frozen ruleset fails" '^FAIL +v\* tag ruleset: actors other than admins .*: ruleset 3: DeployKey:-\(always\)'
two_tag
route "$R/rulesets/3?includes_parents=true" 200 ruleset-3-frozen-hidden
run
expect "a hidden frozen bypass list is unknown" '^UNKNOWN v\* tag ruleset: GitHub hides ruleset 3'
two_tag
route "$R/rulesets/3?includes_parents=true" 404 not-found
run
expect "an unreadable frozen ruleset is unknown, not a pass" '^UNKNOWN v\* tag ruleset: GitHub hides ruleset 3 \(HTTP 404'

# 8. Security tab policy: no file fails, one channel fails, a file under .github/ passes.
all_good
route "$R/contents/SECURITY.md" 404 not-found
run
expect "no SECURITY.md fails" '^FAIL +Security tab policy: no SECURITY.md'
all_good
route "$R/contents/SECURITY.md" 200 security-mail-only
run
expect "one channel only fails" '^FAIL +Security tab policy: SECURITY.md does not name: private vulnerability reporting'
all_good
route "$R/contents/SECURITY.md" 404 not-found
route "$R/contents/.github/SECURITY.md" 200 security-advisory-link
run
expect "SECURITY.md under .github passes" '^PASS +Security tab policy: .github/SECURITY.md'

# 9. no network: every item is UNKNOWN, never PASS, and the run exits 2.
ROUTES=down
run
expect "no network is never a pass" 'Summary: 0 passed, 0 failed, 6 unknown'
expect "a failed request says so" '^UNKNOWN private vulnerability reporting: cannot read the setting \(request failed'
expect_code "no network exits 2" 2

# 10. no token: no Authorization header is sent, and the run says so.
all_good
TOKEN_FOR_RUN='' run
if [ -s "$tmp/logs/headers.log" ]; then
  echo "NOT OK  a header was sent with no token"
  failures=$((failures + 1))
else
  echo "ok      no token means no Authorization header"
fi
expect "no token is said up front" '^Caller: no token'

# 11. usage errors exit 64.
all_good
run 'getrdy-io/rdy/extra'
expect_code "a path with two slashes is a usage error" 64
run '-x'
expect_code "a flag is a usage error" 64
run 'norepo'
expect_code "a name without a slash is a usage error" 64
run 'a/b' 'c/d'
expect_code "two arguments are a usage error" 64
TOKEN_FOR_RUN='bad token' run
expect_code "a token with a space is refused" 64
TOKEN_FOR_RUN='line1
X-Injected: 1' run
expect_code "a token with a newline is refused" 64
run --help
expect_code "--help exits 0" 0

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
echo "all check-org-settings tests passed"
