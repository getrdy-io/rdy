# M1 build runbook

This file lets a new coordinator session resume the M1 build where the last one paused. Read it after
`CLAUDE.md`, `docs/plan/00-overview.md`, `docs/plan/11-backlog.md` and `docs/plan/12-progress.md`.
`12-progress.md` is the record of what merged. This file is the record of how the work runs and what was in
flight at the pause.

## The founder's rules for the build

These are the founder's instructions for M1, kept here so they survive a session reset.

- Read CLAUDE.md, 00-overview.md, 11-backlog.md and the design doc each ticket points to before that ticket.
- Use the subagents in `.claude/agents/` as the backlog assigns them. The coordinator never does a
  subagent's job. Run independent tickets in parallel.
- One branch and one PR per ticket, ticket id in the title. Before opening each PR run `cargo build`,
  `cargo test`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check` and
  `cargo deny check`.
- Cold review from code-reviewer on every PR. Add security-reviewer when the ticket touches privileges,
  network, redaction, signing or install.sh. Fix every high or critical finding.
- Squash-merge green PRs only. Never merge a red PR.
- Keep `12-progress.md` current: one line per ticket (id, PR link, merged at, deferrals and why), updated in
  the PR that completes the ticket.
- A ticket that is wrong or impossible as written gets the smallest correction in `11-backlog.md`, in its own
  PR, noted in `12-progress.md`. Do not improvise.
- When a decision cannot be made safely, take the most conservative option, write an ADR, keep going.
  Never wait for the founder. The founder is not answering questions during the build.
- Never commit secrets. Fixtures are synthetic. The product's old working name must not appear anywhere.
  No competitor company or product names anywhere.
- If a tool call is blocked and no allowed route exists, note it in `12-progress.md` and move on.

Done means: every M1 ticket merged and CI green on main; `cargo install --path crates/rdy-cli` builds;
`rdy run examples/specs/acme-platform.yaml` gives the expected report against the fixtures; `rdy verify`
rejects a tampered spec; `12-progress.md` summarizes what shipped and what moved to M2 and why. The final
reply to the founder gives that summary, the install command a design partner runs, and the three decisions
the founder should look at.

## How one ticket runs

1. Pick tickets whose dependencies are merged (the `depends on` column in `11-backlog.md`, and the
   dependency table at its end). Take them in id order, as "How to work the backlog" says, and run the
   ones that do not depend on each other in parallel, as the founder's rules allow.
2. Launch the backlog owner as a background agent with `isolation: worktree` and the implementer brief
   below, adding the ticket id, branch name and any carried notes for that ticket.
3. When it reports, open the PR from its branch. Title `M1-NNN: <summary>`. Body: what changed, exit test
   and proof, check output, deferrals. Run `fill.sh` on its worktree first so the progress line carries the PR
   number and date.
4. Launch code-reviewer (and security-reviewer where the rules say so) read-only on the PR diff.
5. Send high and critical findings back to the same implementer (SendMessage to its agent id if it is still
   reachable, or a fresh agent of the same role with the findings). Mediums: fix when cheap, else carry them
   as a note to the ticket that owns them (list below). Re-review after the fix round.
6. Wait for `ci-ok` on the head (`wait-ci.sh <sha>` in the background). Then post one review-record comment
   on the PR (who reviewed, verdict, what was fixed, what was carried) and squash-merge with this message
   ending:

   ```text
   Signed-off-by: Rdy <dev@getrdy.io>
   Co-Authored-By: Claude <model name> <noreply@anthropic.com>
   Claude-Session: <the coordinator session URL>
   ```

7. When main moves under an open PR: merge main into the branch, resolve `Cargo.toml` by taking the union of
   both sides, run `git checkout origin/main -- Cargo.lock` and let `cargo build` refresh it, run every
   check (plus `cargo run -p xtask -- docs --check` and `docs-lint`), push. A PR whose `mergeable_state` is
   `dirty` gets no CI run at all, so a missing CI run usually means a conflict.

### Environment facts

- Toolchain 1.99.1 from `rust-toolchain.toml`, MSRV 1.97, sccache wraps rustc. The machine has 4 CPUs, so
  run at most three or four implementers at once.
- Resolve action SHAs with `git ls-remote --tags https://github.com/<owner>/<repo>`. The proxy serves
  anonymous reads of public repos. `api.github.com` answers for this repo only.
- `curl https://api.github.com/repos/getrdy-io/rdy/...` works for check runs and PR state.
- The proxy rejects remote branch deletes. Leave merged branches for the founder.
- Reviewer agents cannot commit. Record their verdict in the review-record comment, never commit on their
  behalf.
- Agents refuse to edit `CLAUDE.md`. In M1-009 the coordinator applied the architect's exact text, and the
  founder is asked to look at that. Do not do it again: if a ticket needs a CLAUDE.md change, the architect
  writes the exact text, it goes into `12-progress.md` as a founder hand step, and the build keeps going.

## Implementer brief

Every implementing agent gets this text, plus the ticket id and branch name.

```markdown
# M1 build brief for every implementing subagent

You implement exactly one M1 ticket from docs/plan/11-backlog.md. The coordinator gives you its id.

Read first, completely: CLAUDE.md, your role file in .claude/agents/, the ticket's row in
docs/plan/11-backlog.md (title, depends on, exit test), the design doc sections the ticket names or implies
(docs/plan/00 to 10 and docs/adr/), and docs/plan/00-overview.md for crate boundaries. The planning docs are
approved. Build what they say. Do not widen the ticket.

## Where you work
- You are in your own git worktree. Run `git fetch -q origin main && git checkout -q -B <branch> origin/main`
  where <branch> is `m1/<NNN>-<short-slug>` (e.g. m1/003-workspace-skeleton).
- Never touch the coordinator's checkout (/home/user/rdy) and never push to main.
- Commit as `Rdy <dev@getrdy.io>` (the repo's git config; never override it), in imperative mood, with a
  one-line summary that starts with the ticket id, e.g. `M1-003: create workspace skeleton`. End every
  commit message, merges included, with these three lines:
  Signed-off-by: Rdy <dev@getrdy.io>
  Co-Authored-By: Claude <your model name> <noreply@anthropic.com>
  Claude-Session: <the coordinator session URL>
- Push with `git push -q -u origin <branch>`. Do not open the PR; the coordinator does.

## Every ticket must
- Pass, from the worktree root: `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, `cargo deny check`,
  `cargo run -q -p xtask -- docs --check` and `cargo run -q -p xtask -- docs-lint`.
  Paste the last lines of each into your reply. A red check means you are not done.
- Add a changelog fragment `changelog.d/M1-NNN.md` (one or two lines, user-facing wording) unless the
  ticket is docs-only plan bookkeeping.
- Update your ticket's line in docs/plan/12-progress.md to: `- M1-NNN | PR #TBD | | <deferrals and why, or none>`.
  Change only your own line. The coordinator fills in the PR number and date.
- Update docs touched by the change in the same branch.
- Keep tests deterministic and fixtures synthetic. Never commit secrets, real hostnames of real companies,
  or real specs.
- No em dashes anywhere, short sentences, the product's old working name never appears, no competitor
  company or product names anywhere (describe by category). `#![forbid(unsafe_code)]` in every crate.

## If the ticket is wrong or impossible as written
Do not improvise. Stop, push nothing that pretends to satisfy it, and reply with: what is wrong, the smallest
correction to the ticket row, and what you could safely build now. The coordinator files the correction.
If you must choose between options and cannot decide safely, take the most conservative one and write a
short ADR in docs/adr/ (next free number, same format as the others, add it to docs/adr/README.md).

## Tools you lack
You cannot open PRs, read CI, or change GitHub settings. If the ticket needs a GitHub setting, an account you
do not have, or a human, build every repo-side part (scripts, checklists, docs), and list the remaining
manual steps in your reply and in your 12-progress.md line as a deferral.

## Reply format (under 250 words)
Branch and head commit SHA, files changed, the exit test and how you proved it, the check command results,
deferrals, and anything the reviewer should look at hard.
```

## Coordinator scripts

Save these in the session scratchpad. They are not part of the product.

`fill.sh <worktree> <ticket-id> <pr-number>` writes the PR link and date into the ticket's progress line,
commits and pushes:

```sh
#!/bin/sh
# usage: fill.sh <worktree> <ticket-id> <pr-number>
set -e
cd "$1"
d=$(date -u +%F)
python3 -I - "$2" "$3" "$d" <<'PY'
import sys
t,n,d=sys.argv[1:4]
p='docs/plan/12-progress.md'; L=open(p).read().split('\n')
for i,l in enumerate(L):
    if l.startswith(f'- {t} |'):
        parts=[x.strip() for x in l[2:].split('|')]
        rest=' | '.join(parts[3:]) if len(parts)>3 else 'none'
        L[i]=f'- {t} | [#{n}](https://github.com/getrdy-io/rdy/pull/{n}) | {d} | {rest}'
        break
else: sys.exit('line not found')
open(p,'w').write('\n'.join(L))
PY
git add docs/plan/12-progress.md
git commit -q -m "$2: record PR #$3 in progress tracker

Signed-off-by: Rdy <dev@getrdy.io>
Co-Authored-By: Claude <model name> <noreply@anthropic.com>
Claude-Session: <the coordinator session URL>"
git push -q
grep "^- $2 |" docs/plan/12-progress.md
git rev-parse --short HEAD
```

`wait-ci.sh <sha>` polls the `ci-ok` gate for a commit and prints `ci-ok <conclusion> <sha>`. Run it in the
background:

```sh
#!/bin/sh
sha=$1; n=0
while [ $n -lt 120 ]; do
  out=$(curl -s --max-time 15 "https://api.github.com/repos/getrdy-io/rdy/commits/$sha/check-runs?check_name=ci-ok" || true)
  c=$(printf '%s' "$out" | python3 -I -c 'import sys,json
try:
  d=json.load(sys.stdin); r=[x for x in d.get("check_runs",[]) if x["status"]=="completed"]
  print(r[0]["conclusion"] if r else "")
except Exception: print("")')
  if [ -n "$c" ]; then echo "ci-ok $c $sha"; exit 0; fi
  n=$((n+1)); sleep 20
done
echo "ci-ok timeout $sha"
```

## State at the pause (2026-10-30, about 19:30 UTC)

The third coordinator session paused here at the founder's request. Read this section, then check every
open PR's head and CI before acting. Agents were stopped at the pause; two of them (the #151 and #156 fix
rounds) were mid-run and pushed nothing after the heads below, so rerun those rounds from their briefs.

**Identity, from 2026-10-30.** Every commit is authored and committed as `Rdy <dev@getrdy.io>`, and every
sign-off line is `Signed-off-by: Rdy <dev@getrdy.io>`. Set it first in a new container:
`git config user.name Rdy && git config user.email dev@getrdy.io`. Older commits keep their old identity;
never rewrite pushed history. PRs and squash merges carry the GitHub account connected to Claude; the
founder is moving that connection to the `getrdy-up` account. Confirm with `get_me` before the first PR or
merge, and report to the founder if it still names a personal account.

**Ownership, from 2026-10-30.** Apostolic Path LLC owns the code, the copyright and the marks (founder
decision). PR #157 writes that into NOTICE and TRADEMARKS.md. No document may name the founder as owner.

Merged in this session (main at 410284f): M1-060 (#142), M1-093 (#143), M1-075 (#145), correction-31 (#150),
plus the earlier merges of this session listed in 12-progress (M1-044 to M1-055 and the rest; #85 to #146).
101 of 174 M1 tickets are merged: 96 of 145 core, 5 non-core.

Open PRs at the pause. "Approved" means every required reviewer approved the current fix round; every
row still needs main merged in, a clean `mergeable_state` and `ci-ok` green on the head before merging.
Review findings and fix briefs are in `reviews/open-findings-2026-10-30/` (named `pr-<PR>-<kind>.md`).

| PR | Ticket | State and next step |
| --- | --- | --- |
| #147 | M1-108 | Approved (code, security; confirm 2 at d3922e1). Head 53ed43f has main merged; CI was running. Merge on green, then #148. Info note SEC-147-9 ("every service account" in the `SERVER_DEFAULTS` comment) rides the next k8s change. |
| #148 | correction-30 | Approved. Merge after #147 (it cites ADR 0039 from #147). Head d7ed12f is behind main. |
| #149 | M1-077 | Approved (code confirm, security confirm 2) at fix round 2. Head ba81bda has main merged; CI was running. Merge on green. |
| #151 | M1-114 | Code confirm: changes (`legacy_policies` reads only `kyverno.io`'s preferred version; the fixture generator marks the first version preferred). k8s-expert verified the Kyverno CRD versions. Run fix round 2 from `pr-151-fix2.md` (check-author), then code and k8s confirm. Head 78bdd9e is behind main. |
| #152 | correction-32 | Approved, fixed. Head 3be147b has main merged; CI was running. Merge on green. |
| #144 | correction-28 | Approved. Head 8225dda has main merged; CI was running. Merge on green. #144, #152 and #158 all change the totals: after each merge, recompute the totals table, 00-overview and the calendar from the rows. |
| #153 | M1-169 | Approved (code confirm with nits, security confirm; ADR 0040 accepted). Head 4d2f6c7 has main merged; CI was running. The macOS leg must pass (it is the only one that runs `read_link_by_path`). Code nits N1 to N3 (stale 12-progress text, a host-assuming test name, a double `fstat`) can ride M1-072. |
| #154 | M1-057 | Fix round 1 at c4d8bf7. Security confirm: approve once correction-33 (#158) exists, which it now does. Code confirm was stopped at the pause: rerun it from `pr-154-code.md`. Then CI, merge. After it merges `rdy run` works on main, so the README (#155 or a follow-up) must drop "rdy run exits 70 today" (fix brief items 16 and 17). |
| #155 | README (founder ask) | Approved (confirm). Head a63968b has main merged; CI was running. Merge on green. |
| #156 | M1-063 | Code and security: changes (forms the corpus does not claim, `value_from` proves nothing, fragment check). Run fix round 1 from `pr-156-fix1.md` (qa-engineer); do not change the redactor. Then confirms. Head 0893d77 is behind main. |
| #157 | NOTICE, TRADEMARKS.md (founder ask) | Approved (confirm), then changed to Apostolic Path LLC at a11afe5 (coordinator checked the diff). Merge on green. |
| #158 | correction-33 | Opened at 77462d3: watchdog in `rdy run` (new M1-176, week 14), real-path checks (new M2-115), M2-061 redactor gaps, review carries. Its review was stopped at the pause: rerun code-reviewer with `correction-33-list.md` and the source findings. |
| #63, #64 | Dependabot | Leave for the founder (ADR 0018). |

Next tickets once the open work is done, in id order, at most three builders: M1-058 and M1-059 (after
M1-057), M1-078 to M1-083 (after M1-077), M1-086 to M1-088, M1-094 to M1-101 (after M1-093), M1-072, M1-107,
M1-113, M1-115 to M1-119, M1-124, M1-126 to M1-130, M1-132 to M1-139, M1-141, M1-174 to M1-176; then the
non-core list (M1-140, M1-142, M1-143, M1-148 to M1-167, M1-173).

Next PR number: #160 (#159 is this pause-state PR). ADR numbers: 0039 is #147's kind gate, 0040 is #153's `read_link`; the next free is
0041. 0029, 0030 and 0032 were never used. New ticket ids: M1-177 and M2-116 are next (M2-113 is in #144,
M2-114 in #152, M1-176 and M2-115 in #158).

Coordinator decisions taken in this session (conservative, recorded in PRs and ADRs):

- The kind job stays out of `ci-ok` (ADR 0039, Proposed); the founder decides.
- The HTML validator jar (vnu-jar 26.10.12 from npm) is pinned by sha256 and its npm provenance was
  verified with cosign; it runs in its own `html-validator` job with a read-only token.
- `rdy run` prints a fixed warning for an unsigned spec now, ahead of M1-126, so product rule 3 holds in
  every alpha.
- `read_link` on Windows returns Denied (the M1 Windows file rule), not NotFound.

Lessons from this session:

- GitHub sometimes accepts a push but never updates the PR (heads stuck for an hour). Compare
  `git ls-remote` with the PR's head; the next push resyncs it.
- Merging a docs-only PR forces every open code PR to merge main and rerun about an hour of CI. Merge code
  PRs first when both are close.
- Reviewer and builder agents leave scratch clones and big target folders in the scratchpad; remove them
  with `rm -r` (not `rm -rf`, which the sandbox refuses).

## Notes carried to later tickets

Review findings that belong to a later ticket. Give each note to that ticket's implementer and reviewer.

- M1-024 and M1-025: a bare `- id: host.memory` with no threshold must decode to `unsupported_spec` with
  reason `no_threshold` (01 section 2.5). Add a per-struct test so the FIELDS lists cannot drift.
- M1-026: stop recording parse entries after 257.
- M1-033: `pass_by_absence` shows its note twice (as the message and in notes); add `#[non_exhaustive]`
  to `PeerClass`; add a `compile_error!` for Unix targets other than linux and macos (PR #32 review).
- M1-040: `CheckError` derives Clone, PartialEq and Eq, so `ProbeError` and `NetFailure` must too, or drop
  the derives before the M2 publish. Give check crates a test constructor for `CheckContext` (PR #32 review).
- M1-044: use `allow-invalid = true` for disallowed paths that do not resolve in every crate. Add
  `std::io::stdout`, `std::io::stderr`, the print macros, and the clippy lints `print_stdout`, `print_stderr`
  and `dbg_macro`.
- M1-058: SIGINT and SIGTERM during a password prompt must restore the terminal. Test it.
- M1-063: the redaction corpus is 28 cases, per 04.
- M1-125: wire `spec sign` and `spec keygen` to `rdy_cli::password::read_key_password`. The exit test covers
  `RDY_KEY_PASSWORD` and `--password-file -` with no prompt.
- M1-126: print `SpecError::fix()` (it fills in the product). Mention the signature error codes in the
  changelog (PR #31 nit). Add the CRLF note to every signature error. Read the `.minisig` file once; an unreadable or
  non-regular file passes `Some`, never `None`. Show the KEY NOT PINNED banner from `TrustSource::Flag`.
- M1-031: did-you-mean for unknown keys including nested key paths; regex compile; line numbers and
  `LintReport`; `assert!(!ids.is_empty())` in the reserved drift test; mention `no_threshold` in the M1-023
  changelog; rename `gpu.device_plugin` in acme-inference-gpu.yaml; distance 2 or less.
- M1-039: CLOEXEC on inherited fds (or an ADR), the umask, the shell and sudo refusal, PATH and env policy.
- M1-043: the narrow window where the watchdog can kill after a reap, and a check that the
  SIGCHLD-ignored test really ignores SIGCHLD on macOS.
- M1-044: also prove the clippy disallowed-methods list, including the M1-030 bans. Add
  `cargo clippy -p rdy-engine --no-default-features --all-targets -- -D warnings` to CI. Delete the stale
  `strsim` row in 07 (around line 2591). Add a test that pins near-miss echoes (`--allow-unsigne`).
- M1-050: add an allow entry for `tests/fixtures/canary/netstat-crlf.txt` in the `\r` lint.
- M1-056 and M1-062: the CLI panic hook never prints default panic text. `End::Panicked` text is raw.
  `CliError::from_anyhow` text goes through the redactor.
- M1-057: End to CheckResult glue (TimedOut becomes timeout, Panicked becomes error with a fixed message,
  Cancelled becomes a cancelled skip). Reconcile plan skip text with `rdy_cli::error::SkipWhy`. Test that
  the CLI fills in `<spec>`.
- M1-060: commented-out blocks, including commented PEM lines; crafted escapes of the bracket and quote
  counts; tuning of over-redaction (all-quoted .env files, stray apostrophes, sibling `- ` items);
  `--password hunter2` as separate words.
- M1-073: what an os `arch: []` means. M1-145: what `allow: []` and `supported: []` mean.
- M1-110: owns the `partial.missing_grants` wire field (13-plan-corrections open item). Its row needs the
  rdy-spec work and the hours.
- M1-126: also exit 64 on an expired spec, and the file-prefix wording.
- The HostFamily registering ticket must drop the stubs, or first add an engine `NotInBuild` skip.
- M1-137: the README leads with the pinned GitHub release URL in M1, not getrdy.io/install.
- CF-03: the upload transport is an open M2 item.

- From this session:
  - M1-010: done in #66 (the PR #47 security lows).
  - M1-015: the fake `rdy` drops a canary file, and the bad-hash and bad-signature cases assert it is
    absent; `fetch` takes the missing-bundle message (06 "this release looks incomplete"); the stop message
    prints a reachable URL for `scripts/verify-release.sh` at the tag, then 06's manual path.
  - M1-044: `exec::run`, `ExecSpec`, `exec::policy::run` (and anything but `exec::table::run`) on the
    check-crate deny list; `ExecSpec` may need `disallowed-types`.
  - M1-060: accept `\\+t` as a blank in `ASSIGNMENT` (a tab inside a Debug-printed field); the proxy URL
    canary (PC-43); `--password hunter2` as separate words.
  - M1-061: known secrets shared through `Arc` so the log writer and CLI errors see them.
  - M1-066: programs that take code or a command line never enter the allow-list (done in #70).
  - M1-102: the run probe denies `.kube`, so the engine's own kubeconfig read needs a settled path.
  - M1-121, M1-122, M1-128: `sudo` resets HOME and XDG_CONFIG_HOME; root tests set them on the child.
  - M1-126: `--key` runs never read the trust stores; the INV-04 strace check runs the real `rdy verify`
    (correction-10).
  - M3: `CAPPED_TARGETS` needs `reqwest`, `aws_smithy_*` and `aws_config` when cloud checks land.

- From the 2026-10-30 session:
  - M1-072: process name from `comm`, never `cmdline`; walk only the needed pids and stop at the first
    match (correction-33); the #153 code nits N1 to N3.
  - M1-086 and the README: once M1-057 merges, the README's status and build-from-source sections change
    (`rdy run` works on main). Link NOTICE and TRADEMARKS.md once #157 merges. Add host.firewall and
    k8s.access to "Works on main today".
  - M1-115: two OpenShift label-sync checks (correction-33).
  - M1-141: test string `"x\u{2069}\u{202e}"` in a banner line, a `<bdi>` field and the title.
  - M1-110 or the next k8s change: SEC-147-9 comment wording.

## For the founder

Hand steps an agent cannot do (also in the Founder hand steps list in `11-backlog.md`):

- Create the labels in `.github/labels.yml`.
- Add the branch rulesets and make `ci-ok` a required check.
- Turn on immutable releases, then cut a fresh tag. Releases stay pre-releases until M1-139 is sent.
- Domain hardening from M1-008: hardware-key MFA, registrar lock, DNSSEC, CAA, HSTS. Rerun
  `scripts/check-domain.sh` after.
- Delete the throwaway branches `tmp/m1-005-clippy`, `tmp/m1-005-openssl`, `tmp/m1-005-unsigned` and
  `tmp/m1-005-signed`, and any merged `m1/*` branches. The agent proxy refuses branch deletes.

- Enable macOS arm64 runners for the org (none are assigned today; see #21 and correction-05). Then
  move the macos-arm64 test leg back into ci-ok.
- Update CLAUDE.md's "Five CI legs" wording for the temporary arm64 exception (correction-05).
- Run the release-sandbox proof in 06 "Sandbox proof" before M1-010 (correction-07).
- Add a ruleset that restricts tag creation (M1-007).
- Delete `tmp/m1-006-macos-probe` as well.
- Scratchpad reviewer build folders could not be removed. The `rm` was denied by permissions and was not
  worked around. They disappear with the session.

Decisions to look at:

- `CLAUDE.md` was edited by the coordinator in M1-009 (edits C-1 to C-9, the architect's text), under the
  build instruction, because agents refuse to edit it.
- ADR 0018 replaces the planned minisign verification crate with an in-tree envelope parser on
  `ed25519-dalek` `verify_strict` and `blake2`.
- M1 started before the M0 go or no-go gate (decision 2 in `13-plan-corrections.md`).

- Correction-05: four native test legs plus an arm64 compile leg gate PRs until arm64 runners exist.
- M1-022 boxes `End::Done(Box<CheckOutcome>)` and turns on serde_json preserve_order behind a `schema`
  feature (ADR 0019).
- M1-048's redactor fails closed and over-redacts on purpose. M1-060 tunes it with corpus evidence.

Process events worth knowing:

- During M1-008 an agent tried to rewrite a URL to get past a guard. The guard denied it and the agent did
  not retry.
- The security-reviewer could not commit its sign-off file in M1-009. The verdict is recorded as a PR comment.


From the 2026-10-29 session:

- Decision: `getrdy-io` is a personal account, not an organization, so org-wide 2FA cannot be enforced.
  Convert it or move the repo to a new org (docs/security/github-settings.md section 1). Either choice
  changes the login or the signing identity.
- Add `--proto =https` to the curl calls in `scripts/check-org-settings.sh` by hand; the agent sandbox
  refused to write it.
- Dependabot PRs #63 and #64 bump crypto crates by a major version; review by hand per ADR 0018.
- Ratify ADR 0024 (release proofs are founder steps) and ADR 0027 (Windows trust stores refused in M1).
- Delete the branch `tmp/m1-011-unpinned` (proof PR #61, closed).
\n

From the 2026-10-30 session:

- Reconnect Claude's GitHub connection to the `getrdy-up` account, give it write access to
  `getrdy-io/rdy`, and set `dev@getrdy.io` as its commit email with "Keep my email addresses private" off,
  so PRs and merges carry Rdy.
- Change CLAUDE.md's "Company entity" line to Apostolic Path LLC (the coordinator does not edit CLAUDE.md).
- Decide the kind gate (ADR 0039): keep the kind job out of `ci-ok`, or require it.
- Run the trademark search and filing in Apostolic Path LLC's name.

