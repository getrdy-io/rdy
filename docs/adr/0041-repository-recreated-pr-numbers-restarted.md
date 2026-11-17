# ADR 0041: Repository recreated on 2026-10-30; PR numbers restarted

- Status: Accepted, code-reviewed (PR #16)
- Date: 2026-10-30

## Context

`getrdy-io/rdy` was recreated at 2026-10-30T18:58:48Z, and the history was pushed again. The PRs, review
comments and review-record comments of the previous repository are gone. GitHub numbering restarted.
Dependabot opened #1 and #2.

Squash-merge titles on main, 12-progress links, 13-plan-corrections entries, review files and ADRs cite the
previous repository's PR numbers (#1 to #159). Those links now return 404 or point to an unrelated new PR.

The open work at the pause was reopened from the same branches:

| Old PR | New PR | Work |
| --- | --- | --- |
| #159 | #3 | runbook pause state |
| #147 | #4 | M1-108 |
| #148 | #5 | correction-30 |
| #149 | #6 | M1-077 |
| #151 | #7 | M1-114 |
| #152 | #8 | correction-32 |
| #144 | #9 | correction-28 |
| #153 | #10 | M1-169 |
| #154 | #11 | M1-057 |
| #155 | #12 | interim README |
| #156 | #13 | M1-063 |
| #157 | #14 | NOTICE and TRADEMARKS.md |
| #158 | #15 | correction-33 |

This ADR's own PR is #16.

## Decision

1. **Old references are not rewritten.** History is never rewritten, and the text is still true of the
   previous repository.
2. **The date tells which repository a number means.** A PR number cited in a file or commit dated before
   2026-10-30T18:58Z refers to the previous repository. So does a link in a 12-progress line merged before
   then. The date is when the text was written. A reopened branch may still cite its own old number; the
   table above maps it. One exception: a reopened branch's own 12-progress line is changed to its new PR
   number before it merges. The coordinator does this with each pre-merge commit, so no 12-progress line
   merged after 18:58Z keeps an old link.
3. **Review evidence for old PRs lives in `docs/plan/reviews/`.** The deleted comments are not the record.
4. **New text uses new numbers.** From now on 12-progress links and squash titles carry the new numbers.
   A short number such as (#4) can appear twice in `git log`. The date tells them apart.
5. **Reopened PRs keep their review state from the pause.** That state is recorded in
   `docs/plan/reviews/open-findings-2026-10-30/` (added by PR #3) and in `m1-build-runbook.md`. Their review-record comments
   are posted again on the new PRs.
6. **No product or format change.** The spec, result and bundle formats are untouched. No crate version
   moves.

## Consequences

- Nothing changes for users.
- Reviewers who follow an old link must apply the date rule. A link from an old file to
  `github.com/getrdy-io/rdy/pull/N` with N up to 159 may open the wrong PR or none.
- 12-progress points here so a reader finds the rule.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Rewrite every old `#N` to a commit SHA or a new number | Rewrites history and merged text. The old PRs have no new number. |
| Prefix old numbers (for example `old#42`) in place | Same edit to merged text, for a lookup the date already gives. |
| Recreate the old PRs as closed placeholders to keep numbers | The numbers have already moved. Placeholders carry no review content. |

## Tickets implied

- [M1] Post the review-record comments again on the reopened PRs #3 to #15 | owner: coordinator | est: 1h | depends on: none | exit test: each of #3 to #15 has a review-record comment that matches its entry in `docs/plan/reviews/open-findings-2026-10-30/` (added by PR #3).
