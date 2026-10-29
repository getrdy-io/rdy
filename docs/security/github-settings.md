# GitHub account and repo settings for getrdy-io/rdy

Ticket: M1-011 (SEC-04, with SEC-03 and SEC-32 folded in). Threats: E2 (maintainer takeover), T3 (asset
swapped after publish) and T4 (compromised Action) in `docs/plan/05-threat-model.md`. Someone who takes
over the account, or pushes a tag, can ship a bad release. This page is the founder's checklist for the
settings, plus the record of the check. The settings are Founder hand steps in `docs/plan/11-backlog.md`.
They must be in the Done log before the M1-139 announcement goes out.

## How the check works

`scripts/check-org-settings.sh` reads six settings through the GitHub REST API. It sends only GET
requests, only to `https://api.github.com`, and changes nothing. Each item prints one of:

- `PASS`: the setting is on and matches this page.
- `FAIL`: the setting is off or wrong. A fix line follows.
- `UNKNOWN`: GitHub would not show the setting to this caller. A fix line follows. This is never a pass.

Exit codes: 0 all PASS, 1 at least one FAIL, 2 no FAIL but at least one UNKNOWN, 64 usage error,
70 internal error (it could not make a temporary directory), 130 or 143 interrupted.

```sh
GH_TOKEN=$(gh auth token) scripts/check-org-settings.sh            # checks getrdy-io/rdy
GH_TOKEN=$(gh auth token) scripts/check-org-settings.sh owner/repo
```

Without a token it reads what is public, and admin-only items print UNKNOWN. The token is read from
`GH_TOKEN` or `GITHUB_TOKEN`. It goes to curl on stdin as a header, never on the command line, and it is
never printed. A token with any character other than letters, digits and `_` is refused.

| Item | Passes when | Endpoint | Caller needs |
| --- | --- | --- | --- |
| org 2FA | The owner is an organization and `two_factor_requirement_enabled` is true | `GET /orgs/{org}` | org owner |
| private vulnerability reporting | `enabled` is true | `GET /repos/{repo}/private-vulnerability-reporting` | none (public repo) |
| immutable releases | `enabled` is true. A 404 is FAIL only when the caller is a known repo admin | `GET /repos/{repo}/immutable-releases` | repo admin |
| main ruleset | Active rules on `main` include pull request, required check `ci-ok` with GitHub Actions as its source (`integration_id` 15368), linear history, block force push and restrict deletion. No bypass actor has mode `always` or `exempt`. A bypass "for pull requests" passes only for Repository admin or Organization admin: it is the emergency path in section 4 | `GET /repos/{repo}/rules/branches/main`, then `GET /repos/{repo}/rulesets/{id}` | read for the rules, write to see bypass lists |
| v* tag ruleset | Active tag rulesets that cover `refs/tags/v*` restrict creation, update and deletion. Every covering ruleset with any of those rules lets only the Repository admin role or Organization admin bypass, and the one with creation lets at least one of them bypass | `GET /repos/{repo}/rulesets`, then each `rulesets/{id}` | read for the rules, write to see bypass lists |
| Security tab policy | `SECURITY.md` is in the root, `.github/` or `docs/` of the default branch and names both the `security@` mailbox and private vulnerability reporting | `GET /repos/{repo}/contents/{path}` | none (public repo) |

Token scopes. `gh auth token` with the default scopes (`repo`, `read:org`) is enough when the `gh` login
is a repo admin and an org owner. A fine-grained token needs repository Administration (read), Contents
(read) and Metadata (read), and organization Administration (read).

Offline stub tests are in `scripts/test-check-org-settings.sh`, with synthetic replies in
`scripts/test-check-org-settings.json`. CI runs them in the `dco` job, next to `shellcheck`.

## Checklist for the founder

Do the items in order. Tick each box. Add the evidence to the Done log as
`- M1-011 hand | <date> | <evidence>`, as "Founder hand steps" in `docs/plan/11-backlog.md` says.

### 1. Org 2FA

The first check run (below) found that `getrdy-io` is a personal account, not an organization. GitHub
can require 2FA only for an organization's members, so this item fails until the repo is in an
organization. Choose one way:

- **Turn the `getrdy-io` account into an organization.** The name and the repo URLs stay. You need a
  second personal account to own it (a separate personal account works). Settings, Access,
  Organizations, Transform account, "Turn getrdy-io into an organization". After this you cannot sign in
  as `getrdy-io`: its tokens, SSH keys and sessions stop working. Any automation that signs in as
  `getrdy-io` needs a new token from the owner account first. The account must leave every organization
  before it can convert.
- **Create a new organization and transfer the repo.** This keeps the personal account, but the
  organization needs a different name, so every `getrdy-io/rdy` URL in the repo, the signer identity in
  `install.sh` and the docs would change. Avoid this before the first release.

Then:

- [ ] Organization settings, Authentication security, "Require two-factor authentication for everyone in
  the organization". Save. GitHub removes members without 2FA.
- [ ] Every owner account uses a hardware security key or passkey as its second factor. Remove SMS.
  Store recovery codes offline, as in `docs/security/domain-hardening.md`, section 3.
- [ ] Until the move, keep the collaborator list of `getrdy-io/rdy` empty apart from your own accounts.
- [ ] How to verify: `scripts/check-org-settings.sh` shows PASS for org 2FA.

### 2. Private vulnerability reporting

- [ ] Repo Settings, Advanced Security, Private vulnerability reporting, Enable.
- [ ] How to verify: the repo Security tab shows "Report a vulnerability", and the script shows PASS.
  `SECURITY.md` already names this channel first.

### 3. Immutable releases

- [ ] Repo Settings, General, Releases, Enable release immutability. With an organization, you can also
  turn it on for every repo under Organization settings, Repository, Immutable releases.
- [ ] GitHub makes only releases published after the setting immutable. Cut a fresh tag afterwards, as in
  the Founder hand step that follows this one in `11-backlog.md`.
- [ ] How to verify: the script shows PASS, and
  `gh api repos/getrdy-io/rdy/releases/tags/<tag> --jq .immutable` prints `true` for the fresh tag.

### 4. Ruleset on `main`

This is the setting from `docs/plan/06-release-and-distribution.md`, "Repo settings".

- [ ] Repo Settings, Rules, Rulesets, New ruleset, New branch ruleset. Name `main`. Enforcement status
  Active.
- [ ] Bypass list: empty. If you want an emergency path, add Repository admin with "For pull requests
  only", never "Always". An "Always" bypass lets that actor push to `main` with no PR, and the script
  fails on it. The script passes a "For pull requests only" bypass for an admin role, because that is
  this emergency path, and fails it for any other actor, who could then merge without `ci-ok`.
- [ ] Target branches: Include default branch.
- [ ] Rules: Restrict deletions. Require linear history. Require a pull request before merging, with 0
  required approvals (one maintainer). Require status checks to pass, add `ci-ok`, and pick GitHub
  Actions as its source so no other app can post that check. The script fails if `ci-ok` has any
  other source or none. Block force pushes.
- [ ] Leave "Require review from Code Owners" off while there is one maintainer (section 9).
- [ ] How to verify: the script shows PASS for main ruleset, and a test direct push to `main` from a
  clean clone is rejected. Paste both into the Done log.

### 5. Ruleset on `v*` tags

From 06, "Tags": only admins create `v*`, nobody updates or deletes one. A failed release burns its
version number. Two rulesets do this best:

- [ ] Ruleset `release tags: create`. New tag ruleset. Active. Target: Include by pattern `v*`. Rules:
  Restrict creations. Bypass list: Repository admin, "Always". Nothing else.
- [ ] Ruleset `release tags: frozen`. New tag ruleset. Active. Target: Include by pattern `v*`. Rules:
  Restrict updates, Restrict deletions, Block force pushes. Bypass list: empty, so not even an admin
  session can move a released tag.
- [ ] One ruleset with all four rules and Repository admin in the bypass list also passes the script. It
  is weaker, because an admin could then move a tag.
- [ ] The script checks the bypass list of every covering ruleset with creation, update or deletion.
  Any actor other than Repository admin or Organization admin fails it, in any mode. A Write role,
  team, app or deploy key in the frozen ruleset could move or delete a released tag.
- [ ] How to verify: the script shows PASS for v* tag ruleset, and a `v*` tag push from a non-admin test
  account is rejected. Paste both into the Done log.

### 6. Security policy on the Security tab

- [ ] `SECURITY.md` is in the repo root on `main`. It names both channels: private vulnerability
  reporting first, then `security@getrdy.io`.
- [ ] How to verify: the Security tab shows "Security policy" as enabled, and the script shows PASS.

### 7. Dependabot

`.github/dependabot.yml` asks for weekly version updates for `cargo` and `github-actions`, grouped, with
a 7-day cooldown. Security updates skip the cooldown. Alerts are a repo setting.

- [ ] Repo Settings, Advanced Security: turn on Dependency graph, Dependabot alerts and Dependabot security
  updates.
- [ ] Dependabot commits carry a `Signed-off-by` line, so they pass the `dco` job. They have no changelog
  fragment. Add one in the PR if the update changes something users see (ADR 0017).
- [ ] How to verify: Insights, Dependency graph, Dependabot shows a green run for both ecosystems. Link it
  in the Done log.

### 8. Security mailbox and security.txt (SEC-32)

`docs/security/security.txt` is the source of truth. It lists both channels: GitHub private reporting
first, then `security@getrdy.io`.

- [ ] Create the `security@getrdy.io` mailbox, protected like the domain accounts (hardware key MFA).
  Send a test mail from an outside address and check that it arrives.
- [ ] Copy `docs/security/security.txt` unchanged into the marketing site so it is served at
  `https://getrdy.io/.well-known/security.txt` as `text/plain`.
- [ ] Renew `Expires` before 2027-10-28. Set a reminder a month earlier. RFC 9116 asks for less than a
  year ahead.
- [ ] How to verify: `curl -sSf https://getrdy.io/.well-known/security.txt` matches the repo file. Note it
  and the test mail in the Done log.

### 9. CODEOWNERS

`.github/CODEOWNERS` names `@getrdy-io`, the owner account, for every path. A separate block lists the
security paths: CI and release files, dependency and toolchain files (including every crate's
`Cargo.toml`), `scripts/`, `install.sh`, the policy and threat model, spec signing and trust code, the
consent and password prompts, the redactor and its corpus, the probe facade and exec code, the network
and cluster crates, and the security ADRs. A change there needs a
security-reviewer review (05, 04 section 4, ADR 0014).

- [ ] Code owner review cannot be required yet: nobody can approve their own PR, and a required review
  would block every merge. When a second maintainer joins, give the security block to them (or to a
  security team in the organization), then turn on "Require review from Code Owners" in the `main`
  ruleset.
- [ ] If the repo moves to an organization, keep `@getrdy-io` or switch to a team such as
  `@getrdy-io/maintainers`. A code owner needs write access, or GitHub ignores the line.
- [ ] How to verify: the CODEOWNERS file view on GitHub shows no errors, or
  `gh api repos/getrdy-io/rdy/codeowners/errors` returns an empty `errors` list.

### 10. Every `uses:` pinned to a commit SHA (SEC-03)

The `zizmor` job in `ci.yml` is a required part of `ci-ok`. `.github/zizmor.yml` sets the
`unpinned-uses` audit to `hash-pin` for every owner, so a `uses:` line with a tag or branch instead of a
full commit SHA fails the job. Dependabot updates the pins and their version comments. Nothing to click.

### 11. Other repo settings from 06

The script does not read these. Check them by hand once.

- [ ] Settings, Actions, General, Workflow permissions: "Read repository contents and packages
  permissions". Leave "Allow GitHub Actions to create and approve pull requests" off.
- [ ] Settings, Actions, General, Fork pull request workflows: require approval for first-time
  contributors.
- [ ] Settings, Environments: create `release` (M1-010). Add yourself as a required reviewer, leave
  "Prevent self-review" off while there is one maintainer, and allow deployments only from the tag
  pattern `v*`. The signing job in `.github/workflows/sign-release.yml` waits for this approval on every
  release. Do the same in `getrdy-io/release-sandbox` for the signing proof in 06. The name must be
  exactly `release`.

## Exit test for M1-011

`.github/CODEOWNERS` covers the security paths. `.github/dependabot.yml` covers `cargo` and
`github-actions`. The `zizmor` job fails on any `uses:` line without a commit SHA and passes on the
branch. `scripts/check-org-settings.sh` reads the six items and prints PASS, FAIL or UNKNOWN with a fix
line. Its first run is below. `docs/security/security.txt` holds both channels, and this page is the
checklist. The settings themselves are Founder hand steps.

## Check run 2026-10-29

Run from the build machine of the M1-011 branch, by `scripts/check-org-settings.sh` with no arguments and
no token. It exited 1. HTTPS from this machine goes through an agent proxy that serves reads for this
repo only. GitHub answered the immutable releases read with "Resource not accessible by integration", so
that item is UNKNOWN, not PASS.

```text
GitHub settings check for getrdy-io/rdy on 2026-10-29T00:47:38Z
Caller: no token (GH_TOKEN and GITHUB_TOKEN are empty). Admin-only items print UNKNOWN.
Owner: getrdy-io (User)
FAIL    org 2FA: getrdy-io is a personal account, not an organization, so GitHub cannot require 2FA for everyone with access (via GET /repos/getrdy-io/rdy)
        fix: Move the repo to an organization, then require 2FA (docs/security/github-settings.md, section 1). Until then keep the collaborator list empty.
FAIL    private vulnerability reporting: disabled (via GET /repos/getrdy-io/rdy/private-vulnerability-reporting)
        fix: Repo Settings > Advanced Security > Private vulnerability reporting > Enable (docs/security/github-settings.md, section 2).
UNKNOWN immutable releases: cannot read the setting (HTTP 403 Resource not accessible by integration)
        fix: Rerun with a repo admin token: GH_TOKEN=$(gh auth token) scripts/check-org-settings.sh.
FAIL    main ruleset: the active rules on main lack: pull_request non_fast_forward deletion required_linear_history required_status_checks(ci-ok) (via GET /repos/getrdy-io/rdy/rules/branches/main)
        fix: Repo Settings > Rules > Rulesets > New branch ruleset for main (docs/security/github-settings.md, section 4).
FAIL    v* tag ruleset: no active tag ruleset that covers refs/tags/v* has: creation update deletion (via GET /repos/getrdy-io/rdy/rulesets)
        fix: Repo Settings > Rules > Rulesets > New tag ruleset for refs/tags/v* (docs/security/github-settings.md, section 5).
PASS    Security tab policy: SECURITY.md on the default branch names both channels (via GET /repos/getrdy-io/rdy/contents/SECURITY.md)
Summary: 1 passed, 4 failed, 1 unknown.
```

What it shows:

- `getrdy-io` is a personal account (`owner.type` is `User`). Org-wide 2FA needs an organization first
  (section 1). The plan assumed an organization, so this is a founder decision.
- Private vulnerability reporting is off. Public reads of that setting are reliable.
- `main` has no active rules and no tag ruleset exists. `GET /repos/getrdy-io/rdy/branches/main` also
  says `"protected": false`, so there is no classic branch protection either.
- Immutable releases could not be read without an admin token.
- `SECURITY.md` on `main` already names both channels.

Result: 1 of 6 pass, as expected before the founder does sections 1 to 5. Rerun with
`GH_TOKEN=$(gh auth token)` after them and paste the PASS output into the Done log.
