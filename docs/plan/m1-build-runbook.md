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
   dependency table at its end). Prefer core tickets on the critical path.
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
- Agents refuse to edit `CLAUDE.md`. When a ticket needs a CLAUDE.md change, the architect writes the exact
  text and the coordinator applies it in that ticket's PR, citing the founder's build instruction.

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
git push -q 2>&1 | tail -1
grep "^- $2 |" docs/plan/12-progress.md
git rev-parse --short HEAD
```

`wait-ci.sh <sha>` polls the `ci-ok` gate for a commit and prints `ci-ok <conclusion> <sha>`. Run it in the
background:

```sh
#!/bin/sh
sha=$1; n=0
while [ $n -lt 120 ]; do
  out=$(curl -s "https://api.github.com/repos/getrdy-io/rdy/commits/$sha/check-runs?check_name=ci-ok" || true)
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

## State at the pause (2026-10-28, about 14:10 UTC)

Merged tickets are listed with their PRs in `12-progress.md`. Work that was in flight:

Merged in M1 so far: M1-001, 002, 003, 004, 005, 008, 009, 013, 016, 017, 018, 019, 020, 029, 032, 112,
120, 123, plus backlog corrections 01 to 04 (#4, #5, #8, #30) and the macOS test fix (#26).

Open PRs. First check each branch head: if it has a new commit after the head named here, the fix round
landed and the PR needs a re-review, then CI, then merge. If not, send the listed findings to a fresh agent
of the owner's role on that branch.

| PR | Ticket | Branch | Head at pause | State and next step |
| --- | --- | --- | --- | --- |
| #21 | M1-006 | m1/006-ci-matrix | a0d9e7b | Review fixes pushed (crtbeginS/crtendS swap, ADR 0006 linker-override note, check-static requires PIE and fails on TEXTREL). code-reviewer approved the previous head. Waiting on CI. The macos-arm64 leg (`macos-15`) sat queued for 15 minutes on the last run before the push cancelled it. If it stays queued, that is runner capacity, not the PR. Wait for it; never merge without ci-ok. Merge when green. |
| #28 | M1-024 | m1/024-host-params | 6e93785 | code-reviewer running at pause. If the verdict is lost, re-run the cold review. Open question for the reviewer: the `$defs/Bundle` regex in spec.v1.schema.json is refused by the jsonschema crate; file it for the schema owner. |
| #29 | M1-048 | m1/048-minimal-redactor | fa42619 | Both reviewers asked for changes. Fix round sent. Highs: bare values stop at the first whitespace (run to end of line); `password=""hunter2` leaks; the reference exemption leaks (`${X:-secret}`, `$(echo secret)`, `{{ ... "secret" }}`); a reference that does not end the word leaks its tail. Mediums: `author` exempts `Authorization`; YAML `|` and `>` blocks leak; O(N^2) rescans; nothing keeps the `testing` feature out of release. Lows: inverted span fails closed, `/run/secrets/` exemption too broad, doc fixes, trybuild skip under CI, note the 4-byte tag oracle and missing 16 KiB cap in 04 and 05. After the fix: re-review by both reviewers. |
| #31 | M1-021 | m1/021-error-types | 40cab8e | code-reviewer approved with nits. Fix round sent: merge main (M1-120 is in), map the signature errors to their own codes instead of the `spec_invalid` wildcard, "stripped" to "escaped" in the M1-021 row and ADR 0008, escape default-ignorable code points, Windows fix line instead of sudo, 07 section 4.1 note. Then a quick re-review, CI, merge. |

Next PR number: #34 (#33 is the PR that added this runbook).

Unlocked tickets not started at the pause (their dependencies are merged): M1-022, M1-023, M1-025,
M1-026, plus everything that depends only on merged tickets. Recompute from the dependency table in
`11-backlog.md` against the merged list above before launching.

Disk: the session's writable allowance is about 40 GB and each worktree's `target/` grows to 2 to 4 GB.
Run `cargo clean` in a worktree once its PR merges. Reviewers must not build in new target dirs.

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
- M1-126: add the CRLF note to every signature error. Read the `.minisig` file once; an unreadable or
  non-regular file passes `Some`, never `None`. Show the KEY NOT PINNED banner from `TrustSource::Flag`.
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

Decisions to look at:

- `CLAUDE.md` was edited by the coordinator in M1-009 (edits C-1 to C-9, the architect's text), under the
  build instruction, because agents refuse to edit it.
- ADR 0018 replaces the planned minisign verification crate with an in-tree envelope parser on
  `ed25519-dalek` `verify_strict` and `blake2`.
- M1 started before the M0 go or no-go gate (decision 2 in `13-plan-corrections.md`).

Process events worth knowing:

- During M1-008 an agent tried to rewrite a URL to get past a guard. The guard denied it and the agent did
  not retry.
- The security-reviewer could not commit its sign-off file in M1-009. The verdict is recorded as a PR comment.
