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
- Commit as `Rdy <dev@getrdy.io>`: the coordinator sets `git config user.name Rdy` and `git config user.email dev@getrdy.io` in the repo, and worktrees share it. Never override it.
- Commit in imperative mood, one-line summary that starts with the ticket id, and write the DCO line out in EVERY commit message (merges too): `Signed-off-by: Rdy <dev@getrdy.io>`. CI rejects any commit without it, and history may not be rewritten, so an unsigned commit costs a whole new PR. Check before every push.
  Example summary: `M1-003: create workspace skeleton`. End every commit message with these three lines:
  Signed-off-by: Rdy <dev@getrdy.io>
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
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

## Session notes from the coordinator
- The disk is shared and small (about 40 GB for every agent together). Build in your worktree's own `target/`.
  Use `cargo test --workspace -j 2` and avoid release builds. When you have pushed your final commit, run
  `cargo clean` in your worktree. If a write fails with "no space left", run `cargo clean` and retry.
- Before any cargo command run `export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`.
  A full debug build otherwise takes 6 GB per worktree and the shared disk fills.
- `cargo-deny` and `cargo-nextest` are installed. `sccache` is not.
- The machine has 4 CPUs and other agents build at the same time. Use `cargo test --workspace -j 2` if builds are slow.
- If `cargo deny` or `cargo nextest` is missing, say so in your reply; do not download binaries.
- When your branch is behind main, merge origin/main (never rebase a pushed branch) and rerun every check.
- Windows CI leg: never judge Linux-style path text (fixture paths, /proc, /etc, declared prefixes, logged paths) with std::path APIs (Path::join, is_absolute, components, file_name): on Windows they use `\` and drive prefixes. Build and compare such paths as `/`-separated text (the helpers in rdy_engine exec/policy.rs and probe/policy.rs). Platform-only APIs (rustix mknodat, fstatfs fields) must be gated by OS; read rustix's Apple cfgs before using them in tests.
- The next free ADR number is in the runbook pause state. Do not use `git commit -s` (the local identity signs as someone else); write the trailers in the message.
- tests/fixtures/README.md 'What exists today' conflicts with every fixture PR: keep main's text and add your own cases.
- EVERY commit (fix rounds and merges too) needs the line `Signed-off-by: Rdy <dev@getrdy.io>` written out in the message. Check `git log origin/main..HEAD --format=%B | grep -c Signed-off-by` against the commit count before every push. An unsigned commit fails DCO and cannot be fixed without rewriting history (PR #119 had to be redone as #122).
- This session's coordinator URL (use it in the Claude-Session line): <the coordinator session URL>
- The repository was recreated on 2026-10-30 and GitHub PR numbers restarted (ADR 0041). PR numbers in older docs refer to the previous repository.
- cargo-deny is NOT installed in this container (and cargo-nextest may not be): say so in your reply; CI's deny job covers it. The pinned toolchain 1.99.1 works; use plain cargo.
