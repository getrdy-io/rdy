#!/bin/sh
# check-org-settings.sh: repeatable check of the GitHub account and repo settings (SEC-04, M1-011).
#
# Reads each setting through the GitHub REST API and prints one line per item:
#   PASS     the setting is on and matches docs/security/github-settings.md
#   FAIL     the setting is off or wrong; a fix line follows
#   UNKNOWN  the API would not show the setting to this caller; a fix line follows
# UNKNOWN is never a pass. Most items need a token from a repo admin (and an org owner for 2FA).
#
# Items:
#   1. org 2FA                       2FA required for every member of the owning organization
#   2. private vulnerability reports the "Report a vulnerability" button on the Security tab
#   3. immutable releases            published releases cannot change
#   4. main ruleset                  PR required, ci-ok from GitHub Actions required, linear history,
#                                    no force push, no deletion, nobody may push to main directly.
#                                    Only an admin role may bypass, and only "for pull requests"
#                                    (the emergency path in the settings doc, section 4).
#   5. v* tag ruleset                only repo or org admins create v* tags; no update, no delete.
#                                    Every covering ruleset with creation, update or deletion fails
#                                    on any bypass actor that is not an admin role.
#   6. Security tab policy           SECURITY.md on the default branch names both channels
#
# Usage: scripts/check-org-settings.sh [owner/repo]     (default getrdy-io/rdy)
# Exit:  0 all items PASS, 1 at least one FAIL, 2 no FAIL but at least one UNKNOWN, 64 usage error,
#        70 internal error (no temporary directory), 130 or 143 interrupted.
#
# Tools: curl and jq. Only GET requests, only to https://api.github.com. Nothing is changed.
#
# Environment:
#   GH_TOKEN or GITHUB_TOKEN   optional token. With the GitHub CLI: GH_TOKEN=$(gh auth token).
#                              The token goes to curl on stdin, never on its command line, and is
#                              never printed. Without a token the script reads what is public.

set -u

API=https://api.github.com
REPO="${1:-getrdy-io/rdy}"
TOKEN="${GH_TOKEN:-}"
if [ -z "$TOKEN" ]; then TOKEN="${GITHUB_TOKEN:-}"; fi
# The base URL is fixed and there is no -L, so the token never goes to another host or scheme.
CURL_OPTS="--silent --show-error --max-time 20 --tlsv1.2"
DOC=docs/security/github-settings.md
RERUN="Rerun with a repo admin token: GH_TOKEN=\$(gh auth token) scripts/check-org-settings.sh"

case "$REPO" in
-h | --help)
  sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
  ;;
-* | */*/* | .* | */.* | *[!A-Za-z0-9._/-]*)
  echo "usage: scripts/check-org-settings.sh [owner/repo]" >&2
  exit 64
  ;;
?*/?*) ;;
*)
  echo "usage: scripts/check-org-settings.sh [owner/repo]  (needs a name like getrdy-io/rdy)" >&2
  exit 64
  ;;
esac
if [ $# -gt 1 ]; then
  echo "usage: scripts/check-org-settings.sh [owner/repo]" >&2
  exit 64
fi
OWNER="${REPO%%/*}"

# A token is sent as an HTTP header. Refuse anything that could add a second header line.
case "$TOKEN" in
*[!A-Za-z0-9_]*)
  echo "GH_TOKEN or GITHUB_TOKEN holds characters a GitHub token never has. Check the variable." >&2
  exit 64
  ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }
if ! have curl || ! have jq; then
  echo "check-org-settings.sh needs curl and jq" >&2
  exit 64
fi

tmp=$(mktemp -d) || exit 70
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PASSES=0
FAILS=0
UNKNOWNS=0

pass() {
  PASSES=$((PASSES + 1))
  printf 'PASS    %s: %s\n' "$1" "$2"
}

fail() {
  FAILS=$((FAILS + 1))
  printf 'FAIL    %s: %s\n' "$1" "$2"
  printf '        fix: %s\n' "$3"
}

unknown() {
  UNKNOWNS=$((UNKNOWNS + 1))
  printf 'UNKNOWN %s: %s\n' "$1" "$2"
  printf '        fix: %s\n' "$3"
}

# api PATH [ACCEPT]: GET $API/PATH. Sets HTTP to the status code (000 when the request itself
# failed) and leaves the body in $tmp/body.
api() {
  ap_accept="${2:-application/vnd.github+json}"
  : >"$tmp/body"
  if [ -n "$TOKEN" ]; then
    # shellcheck disable=SC2086
    HTTP=$(printf 'Authorization: Bearer %s\n' "$TOKEN" |
      curl $CURL_OPTS -H @- -H "Accept: $ap_accept" -H 'X-GitHub-Api-Version: 2022-11-28' \
        -o "$tmp/body" -w '%{http_code}' "$API/$1" 2>"$tmp/err") || HTTP=000
  else
    # shellcheck disable=SC2086
    HTTP=$(curl $CURL_OPTS -H "Accept: $ap_accept" -H 'X-GitHub-Api-Version: 2022-11-28' \
      -o "$tmp/body" -w '%{http_code}' "$API/$1" 2>"$tmp/err" </dev/null) || HTTP=000
  fi
  case "$HTTP" in
  [0-9][0-9][0-9]) ;;
  *) HTTP=000 ;;
  esac
}

# why: a short reason for the last request that did not answer 200, for UNKNOWN lines.
why() {
  if [ "$HTTP" = 000 ]; then
    w_err=$(head -n 1 "$tmp/err" 2>/dev/null)
    printf 'request failed: %s' "${w_err:-no response}"
    return
  fi
  w_msg=$(jq -r '.message // empty' "$tmp/body" 2>/dev/null | head -n 1 | cut -c 1-120)
  printf 'HTTP %s %s' "$HTTP" "$w_msg"
}

# jqb FILTER: run jq on the last body. Prints nothing when the body is not JSON.
jqb() {
  jq -r "$1" "$tmp/body" 2>/dev/null
}

# ---- the repository and the caller --------------------------------------------------
OWNER_TYPE=unknown
ADMIN=unknown
api "repos/$REPO"
if [ "$HTTP" = 200 ]; then
  OWNER_TYPE=$(jqb '.owner.type // "unknown"')
  ADMIN=$(jqb 'if .permissions.admin == true then "yes" elif .permissions.admin == false then "no" else "unknown" end')
fi
REPO_HTTP="$HTTP"
REPO_WHY=$(why)

echo "GitHub settings check for $REPO on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ -n "$TOKEN" ]; then
  api user
  login=unknown
  if [ "$HTTP" = 200 ]; then login=$(jqb '.login // "unknown"'); fi
  echo "Caller: token for $login, repo admin: $ADMIN"
else
  echo "Caller: no token (GH_TOKEN and GITHUB_TOKEN are empty). Admin-only items print UNKNOWN."
fi
if [ "$REPO_HTTP" = 200 ]; then
  echo "Owner: $OWNER ($OWNER_TYPE)"
else
  echo "Owner: $OWNER (could not read the repository: $REPO_WHY)"
fi

# ---- 1. org 2FA ---------------------------------------------------------------------
check_2fa() {
  item="org 2FA"
  fixmsg="Organization settings > Authentication security > Require two-factor authentication ($DOC, section 1)."
  case "$OWNER_TYPE" in
  Organization)
    api "orgs/$OWNER"
    if [ "$HTTP" != 200 ]; then
      unknown "$item" "cannot read organization $OWNER ($(why))" "$RERUN. The token's user must be an org owner."
      return
    fi
    case "$(jqb '.two_factor_requirement_enabled | tostring')" in
    true) pass "$item" "two_factor_requirement_enabled is true for $OWNER (via GET /orgs/$OWNER)" ;;
    false) fail "$item" "two_factor_requirement_enabled is false for $OWNER (via GET /orgs/$OWNER)" "$fixmsg" ;;
    *) unknown "$item" "GitHub shows two_factor_requirement_enabled only to org owners (via GET /orgs/$OWNER)" \
      "$RERUN. The token's user must be an org owner, and a classic token needs read:org." ;;
    esac
    ;;
  User)
    fail "$item" "$OWNER is a personal account, not an organization, so GitHub cannot require 2FA for everyone with access (via GET /repos/$REPO)" \
      "Move the repo to an organization, then require 2FA ($DOC, section 1). Until then keep the collaborator list empty."
    ;;
  *)
    unknown "$item" "cannot tell whether $OWNER is an organization (repository read: $REPO_WHY)" "$RERUN."
    ;;
  esac
}

# ---- 2. private vulnerability reporting ---------------------------------------------
check_pvr() {
  item="private vulnerability reporting"
  api "repos/$REPO/private-vulnerability-reporting"
  if [ "$HTTP" != 200 ]; then
    unknown "$item" "cannot read the setting ($(why))" "$RERUN."
    return
  fi
  case "$(jqb '.enabled | tostring')" in
  true) pass "$item" "enabled (via GET /repos/$REPO/private-vulnerability-reporting)" ;;
  false) fail "$item" "disabled (via GET /repos/$REPO/private-vulnerability-reporting)" \
    "Repo Settings > Advanced Security > Private vulnerability reporting > Enable ($DOC, section 2)." ;;
  *) unknown "$item" "the reply has no enabled field (via GET /repos/$REPO/private-vulnerability-reporting)" "$RERUN." ;;
  esac
}

# ---- 3. immutable releases ----------------------------------------------------------
check_immutable() {
  item="immutable releases"
  fixmsg="Repo Settings > General > Releases > Enable release immutability ($DOC, section 3)."
  api "repos/$REPO/immutable-releases"
  case "$HTTP" in
  200)
    if [ "$(jqb '.enabled | tostring')" = true ]; then
      pass "$item" "enabled, enforced_by_owner: $(jqb '.enforced_by_owner | tostring') (via GET /repos/$REPO/immutable-releases)"
    else
      fail "$item" "the reply says enabled is not true (via GET /repos/$REPO/immutable-releases)" "$fixmsg"
    fi
    ;;
  404)
    # GitHub answers 404 both for "not enabled" and for "you may not see this".
    if [ "$ADMIN" = yes ]; then
      fail "$item" "not enabled: HTTP 404 to a repo admin (via GET /repos/$REPO/immutable-releases)" "$fixmsg"
    else
      unknown "$item" "HTTP 404 means off or no admin read access, and the caller is not a known repo admin" "$RERUN."
    fi
    ;;
  *)
    unknown "$item" "cannot read the setting ($(why))" "$RERUN."
    ;;
  esac
}

# actors_that SELECT: print the bypass actors of the ruleset in the last body that match the jq
# select expression, as type:id(mode) separated by spaces. Call only when bypass_actors is present.
actors_that() {
  jqb "[.bypass_actors[] | select($1) | \"\(.actor_type):\(.actor_id // \"-\")(\(.bypass_mode // \"always\"))\"] | join(\" \")"
}

# The admin roles, as a jq test on one bypass actor. Repository admin is RepositoryRole 5
# (4 is Write, 2 is Maintain). OrganizationAdmin is the org owner role. Anything else, such as
# another role, a team, an app or a deploy key, is not an admin.
IS_ADMIN='((.actor_type == "RepositoryRole" and .actor_id == 5) or .actor_type == "OrganizationAdmin")'

# ---- 4. main ruleset ----------------------------------------------------------------
check_main() {
  item="main ruleset"
  fixmsg="Repo Settings > Rules > Rulesets > New branch ruleset for main ($DOC, section 4)."
  api "repos/$REPO/rules/branches/main?per_page=100"
  if [ "$HTTP" != 200 ]; then
    unknown "$item" "cannot read the rules for main ($(why))" "$RERUN."
    return
  fi
  cp "$tmp/body" "$tmp/main-rules"
  missing=""
  for r in pull_request non_fast_forward deletion required_linear_history; do
    if ! jq -e --arg r "$r" 'any(.[]; .type == $r)' "$tmp/main-rules" >/dev/null 2>&1; then
      missing="$missing $r"
    fi
  done
  # 15368 is the GitHub Actions app. Without integration_id any app or token could post ci-ok.
  if ! jq -e 'any(.[]; .type == "required_status_checks"
        and any(.parameters.required_status_checks[]?; .context == "ci-ok" and .integration_id == 15368))' \
    "$tmp/main-rules" >/dev/null 2>&1; then
    missing="$missing required_status_checks(ci-ok from GitHub Actions)"
  fi
  if [ -n "$missing" ]; then
    fail "$item" "the active rules on main lack:$missing (via GET /repos/$REPO/rules/branches/main)" "$fixmsg"
    return
  fi

  # An actor who may bypass "always" (or is "exempt") can push to main without a PR. A bypass
  # "for pull requests" is the documented emergency path (section 4): it passes for an admin role
  # only, because it lets the actor merge a PR without ci-ok.
  direct=""
  merge=""
  unread=""
  for id in $(jq -r '[.[].ruleset_id | numbers] | unique | .[]' "$tmp/main-rules" 2>/dev/null); do
    api "repos/$REPO/rulesets/$id"
    if [ "$HTTP" != 200 ]; then
      unread="$unread $id ($(why))"
      continue
    fi
    if [ "$(jqb 'has("bypass_actors") | tostring')" != true ]; then
      unread="$unread $id"
      continue
    fi
    found=$(actors_that '(.bypass_mode // "always") != "pull_request"')
    if [ -n "$found" ]; then direct="$direct ruleset $id: $found;"; fi
    found=$(actors_that "(.bypass_mode // \"always\") == \"pull_request\" and ($IS_ADMIN | not)")
    if [ -n "$found" ]; then merge="$merge ruleset $id: $found;"; fi
  done
  if [ -n "$direct" ]; then
    fail "$item" "the rules are on, but these actors can push to main without a PR:$direct" \
      "Remove them from the bypass list, or set their bypass mode to pull requests only ($DOC, section 4)."
    return
  fi
  if [ -n "$merge" ]; then
    fail "$item" "the rules are on, but these actors are not admins and can merge to main without ci-ok:$merge" \
      "Remove them from the bypass list. Only Repository admin may bypass, for pull requests only ($DOC, section 4)."
    return
  fi
  if [ -n "$unread" ]; then
    unknown "$item" "the rules are on, but GitHub hides the bypass list of ruleset$unread from this caller" "$RERUN."
    return
  fi
  pass "$item" "PR, ci-ok from GitHub Actions, linear history, no force push, no deletion, no direct-push bypass, admin-only PR bypass (via GET /repos/$REPO/rules/branches/main and /rulesets)"
}

# ---- 5. v* tag ruleset ---------------------------------------------------------------
check_tags() {
  item="v* tag ruleset"
  fixmsg="Repo Settings > Rules > Rulesets > New tag ruleset for refs/tags/v* ($DOC, section 5)."
  api "repos/$REPO/rulesets?includes_parents=true&per_page=100"
  if [ "$HTTP" != 200 ]; then
    unknown "$item" "cannot list rulesets ($(why))" "$RERUN."
    return
  fi
  ids=$(jqb '[.[] | select(.target == "tag" and .enforcement == "active") | .id] | .[]')
  : >"$tmp/tag-rules"
  guarded=""
  bad=""
  noone=""
  unread=""
  for id in $ids; do
    api "repos/$REPO/rulesets/$id?includes_parents=true"
    if [ "$HTTP" != 200 ]; then
      unread="$unread $id ($(why))"
      continue
    fi
    # Does the ruleset cover v* tags? The patterns are compared as written, not expanded as globs.
    covers=$(jqb '((.conditions.ref_name.include // [])
          | any(.[]; . == "~ALL" or . == "refs/tags/*" or . == "refs/tags/**"
                     or . == "refs/tags/v*" or . == "refs/tags/v**"))
        and ((.conditions.ref_name.exclude // [])
          | all(.[]; (startswith("refs/tags/v") or . == "~ALL" or . == "refs/tags/*"
                      or . == "refs/tags/**") | not))
        | tostring')
    if [ "$covers" != true ]; then continue; fi
    jqb '.rules[]?.type' >>"$tmp/tag-rules"
    # Every covering ruleset that guards creation, update or deletion is checked, not only the one
    # with creation. Section 5 of the settings doc puts update and deletion in a separate "frozen"
    # ruleset, and a bypass actor there could move or delete a released tag.
    if [ "$(jqb 'any(.rules[]?; .type == "creation" or .type == "update" or .type == "deletion") | tostring')" != true ]; then
      continue
    fi
    guarded="$guarded $id"
    if [ "$(jqb 'has("bypass_actors") | tostring')" != true ]; then
      unread="$unread $id"
      continue
    fi
    found=$(actors_that "$IS_ADMIN | not")
    if [ -n "$found" ]; then bad="$bad ruleset $id: $found;"; fi
    # Creation with no bypass at all means nobody, not even an admin, can push a release tag.
    if [ "$(jqb 'any(.rules[]?; .type == "creation") and (.bypass_actors | length) == 0 | tostring')" = true ]; then
      noone="$noone $id"
    fi
  done

  missing=""
  for r in creation update deletion; do
    if ! grep -qx "$r" "$tmp/tag-rules"; then missing="$missing $r"; fi
  done
  if [ -n "$missing" ] && [ -z "$unread" ]; then
    fail "$item" "no active tag ruleset that covers refs/tags/v* has:$missing (via GET /repos/$REPO/rulesets)" "$fixmsg"
    return
  fi
  if [ -n "$bad" ]; then
    fail "$item" "actors other than admins can bypass the v* tag rules (create, move or delete a tag):$bad" \
      "Keep only the Repository admin role (or Organization admin) in the create ruleset, and nobody in the frozen ruleset ($DOC, section 5)."
    return
  fi
  if [ -n "$noone" ]; then
    fail "$item" "ruleset$noone blocks v* tag creation with no bypass, so no release can start" \
      "Add the Repository admin role to the bypass list ($DOC, section 5)."
    return
  fi
  if [ -n "$unread" ]; then
    unknown "$item" "GitHub hides ruleset$unread or its bypass list from this caller" "$RERUN."
    return
  fi
  pass "$item" "creation, update and deletion of refs/tags/v* are blocked and only admins may bypass (ruleset$guarded)"
}

# ---- 6. Security tab policy ----------------------------------------------------------
check_policy() {
  item="Security tab policy"
  found=""
  for p in SECURITY.md .github/SECURITY.md docs/SECURITY.md; do
    api "repos/$REPO/contents/$p" application/vnd.github.raw+json
    case "$HTTP" in
    200)
      found="$p"
      break
      ;;
    404) ;;
    *)
      unknown "$item" "cannot read $p ($(why))" "$RERUN."
      return
      ;;
    esac
  done
  if [ -z "$found" ]; then
    fail "$item" "no SECURITY.md in the root, .github/ or docs/ of the default branch (via GET /repos/$REPO/contents)" \
      "Merge SECURITY.md to the default branch ($DOC, section 6)."
    return
  fi
  lack=""
  grep -qi 'security@' "$tmp/body" || lack="$lack the security@ mailbox,"
  grep -qiE 'report a vulnerability|security/advisories/new' "$tmp/body" || lack="$lack private vulnerability reporting,"
  if [ -n "$lack" ]; then
    fail "$item" "$found does not name:${lack%,}" "Name both channels in $found ($DOC, section 6)."
    return
  fi
  pass "$item" "$found on the default branch names both channels (via GET /repos/$REPO/contents/$found)"
}

check_2fa
check_pvr
check_immutable
check_main
check_tags
check_policy

echo "Summary: $PASSES passed, $FAILS failed, $UNKNOWNS unknown."
if [ "$FAILS" -gt 0 ]; then
  exit 1
fi
if [ "$UNKNOWNS" -gt 0 ]; then
  exit 2
fi
exit 0
