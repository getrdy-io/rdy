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
  Claude-Session: https://claude.ai/code/session_011oBtEixZfL4UFD3bkJUSPh
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

## Session notes from the coordinator
- The disk is shared and small (about 40 GB for every agent together). Build in your worktree's own `target/`.
  Use `cargo test --workspace -j 2` and avoid release builds. When you have pushed your final commit, run
  `cargo clean` in your worktree. If a write fails with "no space left", run `cargo clean` and retry.
- Before any cargo command run `export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`.
  A full debug build otherwise takes 6 GB per worktree and the shared disk fills.
- `cargo-deny` and `cargo-nextest` are installed. `sccache` is not.
- The machine has 4 CPUs and other agents build at the same time. Use `cargo test --workspace -j 2` if builds are slow.
- If `cargo deny` or `cargo nextest` is missing, say so in your reply; do not download binaries.
- The latest ADR on main is 0019 (from #48). Open PRs hold 0020 (#47), 0021 (#51), 0022 (#52), 0023 (#53).
  A new ADR takes the next number after the highest one on main or in those open PRs, and you say which
  number you took in your reply. The coordinator renumbers on merge if two collide.
- When your branch is behind main, merge origin/main (never rebase a pushed branch) and rerun every check.
