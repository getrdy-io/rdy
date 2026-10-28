# Planning pass status (handoff note)

Written 2026-10-28 so the next session can resume without re-reading the transcript.
Delete this file when the planning pass is complete.

## Done and pushed to main

Every file below was written by its owning subagent and reviewed by a subagent that did not write it.
Review files live in `docs/plan/reviews/`. Revisions after review are applied and committed.

| Document | Author | Reviewed by | State |
| --- | --- | --- | --- |
| docs/plan/00-overview.md | rust-architect | security-reviewer, cli-ux | final, but its M1 calendar and hour totals predate the later revisions below and must be re-synced in the backlog step |
| docs/plan/01-spec-format.md plus crates/rdy-spec/schema/*.json and examples/specs/*.yaml | rust-architect | security-reviewer, cli-ux | final; all examples validate |
| docs/plan/02-engine-design.md | rust-architect | security-reviewer (twice) | final |
| docs/plan/03-check-catalog.md | check-author | k8s-expert, cloud-iam-expert, gpu-expert, rust-engineer | final |
| docs/plan/04-bundle-and-redaction.md | rust-engineer, security-reviewer | code-reviewer | final |
| docs/plan/05-threat-model.md and SECURITY.md | security-reviewer | code-reviewer | final |
| docs/plan/06-release-and-distribution.md | release-engineer | code-reviewer | final |
| docs/plan/07-cli-ux.md | cli-ux | code-reviewer | review in progress when the session paused, see below |
| docs/plan/08-testing.md | qa-engineer | code-reviewer | final |
| docs/plan/09-docs-site.md | docs-writer | release-engineer | final |
| docs/plan/10-devrel-and-launch.md, examples, CONTRIBUTING.md | devrel | cli-ux | final, but about ten README transcript lines must be re-synced to 07 (list is in 07's "Plan corrections found") |
| docs/adr/0001 to 0016 and README.md | rust-architect | security-reviewer, cli-ux | final, all Accepted |

## Remaining steps, in order

1. If `docs/plan/reviews/07-cli-ux-review-by-code-reviewer.md` does not exist, run code-reviewer on 07 (cold review:
   KICKOFF item 8 coverage, exit codes and samples against 01, ADR 0008 and 0013, JSON samples against the schema,
   Ctrl-C 70 versus 130, `--timeout` guard, HTML brief against ADR 0003, M1 tickets cut from 51 to about 30 hours).
   Then cli-ux applies it to 07.
2. devrel re-syncs the README transcripts and install lines in 10 to the final 07 and 01 (field renames:
   `over_max`, `tolerance_percent`, `forbid`; summary-line grammar; banners).
3. If `docs/plan/13-plan-corrections.md` does not exist, rust-architect compiles it from every document's
   "Plan corrections found" section and the review files, deduplicated, as a table (id, where, what is wrong,
   proposed fix, severity, raised by), plus "Decisions the founder must make" and "Process notes from the planning pass".
4. rust-architect writes `docs/plan/11-backlog.md` from every document's "Tickets implied" section: one table
   (id, milestone, title, owner subagent, estimate in hours, depends on, exit test), M1 fully ticketed at one to
   four hours each, M2 to M5 coarser. Add a `core` column marking the six-week minimum so the founder can cut.
   Re-sync 00-overview.md's calendar and totals to the backlog. Then code-reviewer and qa-engineer review 11
   (dependency titles resolve, estimates honest, exit tests observable), rust-architect applies.
5. Final checks before the last push: the old working name appears in no file (`grep -rni` for it, excluding .git,
   must return nothing); no competitor company or product name appears in any file (the denylist used in this
   session lived outside the repo on purpose; rebuild it from the categories in CLAUDE.md and the plan's
   competitor tables); no em dashes; `git status` clean; everything on main.
6. Finish with the one-page summary: the plan, the M1 ticket count and total hours, and the three decisions
   for the founder.

## Hour totals reported by the documents (M1, before backlog reconciliation)

| Slice | Hours | Source |
| --- | --- | --- |
| Engine and workspace (rust-architect, rust-engineer) | 84.5 | 02 |
| Core checks, M1 tier (host, net, k8s plus plumbing) | 79 | 03 (M1-late adds 72 more, proposed for M2) |
| Security standalone tickets | 27 (plus 8 folded) | 05 |
| Release and CI | 24 | 06 |
| CLI UX | 51 (reviewer asked for about 30) | 07 |
| Testing | 32 | 08 |
| Docs site | 48 | 09 |
| Devrel (README, examples, contributing) | see 10 | 10 |
| Redactor, M1 minimum | 15 | 04 |

The plan budgets 60 to 90 founder hours for a six-week M1. The documents sum to roughly 250 hours before the
backlog step reconciles overlaps and applies the cut lists each document carries. This is the first decision
for the founder: a smaller six-week M1 or a longer M1 (the architect recommends about 15 weeks ending early
March 2027, after the Nov 20 go or no-go).

## Rules in force for every file in this repo

- The old working name (dropped 2026-10-20) appears nowhere.
- No competitor company or product names anywhere, including URLs. Categories only.
- No em dashes. Short sentences. Synthetic fixtures only. No secrets.
