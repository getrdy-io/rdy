# M1 review brief (read-only reviewer)

You review one M1 PR cold. You did not write it. Do not edit, commit, push, build or run cargo
(the disk is shared and small; CI builds every leg). Reading files and running `git` read commands is fine.

Repo: /home/user/rdy (the coordinator's checkout; do not check out branches or fetch there; the refs below
are already fetched). Read files from the branch with `git -C /home/user/rdy show origin/<branch>:<path>`
and the change with `git -C /home/user/rdy diff origin/main...origin/<branch>` (three dots: changes on the
branch only). PR state and CI: `curl -s https://api.github.com/repos/getrdy-io/rdy/pulls/<n>`.

Read first: CLAUDE.md, your role file in .claude/agents/, the ticket row in docs/plan/11-backlog.md
(title, depends on, exit test), and the design doc sections it names (docs/plan/00 to 10, docs/adr/).
Build rules: the planning docs are approved; the ticket must not be widened; no em dashes; no old working
name; no competitor names; `#![forbid(unsafe_code)]`; every user-facing error has a fix hint; tests
deterministic and fixtures synthetic; a changelog fragment and the ticket's 12-progress line.

Report under 450 words:
- Verdict: approve, approve with fixes, or changes required.
- Findings, each with severity (critical, high, medium, low, nit), file:line, what is wrong, a concrete fix.
  High and critical mean: a security hole, wrong behavior against the exit test or design doc, a test that
  does not prove what it claims, or something that will break CI on a leg.
- Whether the exit test is really proven.
