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
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   Claude-Session: https://claude.ai/code/session_011oBtEfTsAHp3D8SPZaBQJq
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
- Commit with `git commit -s` (DCO sign-off) in imperative mood, one-line summary that starts with the ticket
  id, e.g. `M1-003: create workspace skeleton`. End every commit message with these two lines:
  Co-Authored-By: Claude <your model name> <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_011oBtEfTsAHp3D8SPZaBQJq
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
git commit -q -s -m "$2: record PR #$3 in progress tracker

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011oBtEfTsAHp3D8SPZaBQJq"
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

## State at the pause (2026-10-28, about 20:00 UTC)

Merged tickets are listed with their PRs in `12-progress.md`. Main's CI now runs the full test matrix
(M1-006): linux-x64, linux-arm64, windows-x64, macos-x64 and an aarch64-apple-darwin compile leg.

Merged in M1 so far (34 tickets): M1-001 to 006, 008, 009, 013, 016 to 026, 029, 030, 032 to 035, 038,
047, 048, 064, 112, 120, 123. Backlog corrections 01 to 07 are merged (#4, #5, #8, #30, #40, #41, #46).

Open PRs. Check each branch head first. A commit newer than the head named here means the fix round
landed: re-review the new diff, wait for CI, then merge. If there is no newer commit, send the listed
findings to a fresh agent of the owner's role on that branch.

| PR | Ticket | Branch | Head at pause | State and next step |
| --- | --- | --- | --- | --- |
| #47 | M1-007 | m1/007-dist-init | 1da6d0a | Security approved 0527512. The final fix round landed in 1da6d0a: the precise-builds guard, the correction-07 merge, the ADR 0020 Done-log fix, and all five lows. Next: a quick code re-review of 0527512..1da6d0a, then CI, then merge. The cargo test suite was not rerun locally this round, so let CI decide. |
| #48 | M1-022 | m1/022-json-schemas | 6f27287 | Approved with two mediums, both landed in 6f27287: the cargo-tree feature guard and a `cargo test -p rdy -p rdy-engine` step. Main (#43) is merged, with its schema edits in the fragments. Next: confirm the diff since c85b122 is only those, then CI, then merge. It keeps ADR 0019. |
| #49 | M1-067 | m1/067-host-os-stubs | 4d98195 | Approved with nits; nits landed in 4d98195: `stub_ids()` with a test, and the no-register rule naming M1-057. Next: CI, then merge. |

Implementers running at the pause, none pushed yet. Each pushes its branch only when done, so check
`git ls-remote` for the branch. If the branch is missing, relaunch the ticket from its row with the carried
notes below.

- M1-121 trust store, branch `m1/121-trust-store`.
- M1-056 redacting tracing writer and panic hook, `m1/056-redacting-tracing`. Pushed at 149da84, with no PR yet. Next: open its PR, then code and security review. Its reviewers should judge the default filter with RUST_LOG unset (`warn` plus caps, while 07 says no log output) and the process-global redactor. The proxy URL canary waits for M1-060.
- M1-125 `spec keygen` and `spec sign`, `m1/125-spec-keygen-sign`. Needs a security review.
- M1-031 `spec lint`, `m1/031-spec-lint`.
- M1-039 command policy, `m1/039-command-policy`. Needs a security review.

Unlocked and not started: M1-011 (mostly founder steps), M1-027, M1-028, M1-040, M1-062, M1-089,
M1-102, M1-152. Recompute against the dependency table before launching.

Next PR number: #51 (#50 is the PR that updated this runbook).

Lessons from this stretch:

- Merging main into a branch can break it even without conflicts: new variants and lint triggers show up.
  Run clippy and the full tests after every merge of main.
- A PR whose `mergeable_state` is `dirty` gets no CI. Re-check before every merge.
- Feature unification hides release-only behavior. M1-022 gates preserve_order behind a `schema` feature.
- The redactor (M1-048) took eight review rounds. Structural parsing kept leaking. The fix was a
  fail-closed design. Prefer fail-closed rules over clever parsers for security code.
- Reviewers must not build. The disk filled several times. Run `cargo clean` after each merge, and keep
  the coordinator checkout's `target/` empty.
- The stop hook flags work in progress in agent worktrees. Those changes are the running agents' and
  need no action.
- `git config user.email noreply@anthropic.com` and `user.name Claude` are set in the shared repo config,
  as the stop hook asked.

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
