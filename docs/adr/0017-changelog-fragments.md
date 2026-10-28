# ADR 0017: Changelog fragments: each PR adds one file in changelog.d/, and the release step assembles CHANGELOG.md

- Status: Accepted
- Date: 2026-10-28

## Context

CLAUDE.md asks for a CHANGELOG entry in every PR. M1 runs about 140 ticket PRs, and several are open
at once. If each one edits `CHANGELOG.md` under `## Unreleased`, every pair of open PRs conflicts on the
same lines, and each conflict costs a rebase and a CI wait. M1-003 creates `CHANGELOG.md` in Keep a
Changelog form with one H2 per version, and `changelog.d/` for fragments. ADR 0007 brings `release-plz`
in M2, which writes per-crate changelogs for crates.io releases. 09 section 7 renders the docs
`/changelog/` page from `CHANGELOG.md` from M2, and a release runbook step writes the schema-change line.

## Decision

1. **One fragment per PR.** Every PR that changes something a user can see adds
   `changelog.d/<ticket-id>.md` (for example `changelog.d/M1-042.md`): one or two bullet lines in plain,
   user-facing words. A PR without a ticket uses a short slug. A PR does not edit `CHANGELOG.md`.
2. **Docs-only plan bookkeeping adds no fragment.** Planning and backlog PRs change nothing a user of
   `rdy` sees.
3. **The release step assembles.** At each tag, the release step (M1-138 for 0.1.0, the `RELEASING.md`
   runbook for weekly tags) moves every fragment under a new `## <version>` heading in `CHANGELOG.md`,
   in ticket id order, and deletes the fragments in the same commit. `## Unreleased` then says the
   fragments are waiting in `changelog.d/`.
4. **This is the CLAUDE.md "CHANGELOG entry".** The CLAUDE.md PR checklist line becomes "changelog
   fragment in `changelog.d/`" (edit C-4 in `docs/plan/13-plan-corrections.md`).
5. **With ADR 0007.** `release-plz` (M2) keeps writing per-crate changelogs for `rdy-spec` and
   `rdy-engine`. The root `CHANGELOG.md` stays the binary's user-facing history, and the release step
   still builds it from fragments. If `release-plz` is configured to write the root file, it must
   read the assembled text, not replace it.
6. **With 09.** The `/changelog/` renderer (M2) reads only the committed `CHANGELOG.md`, never
   `changelog.d/`, so unreleased fragments never appear on the docs site. The schema-change line is
   still written at release time by the runbook step.

## Consequences

- Parallel ticket PRs do not conflict on the changelog.
- One more step at each release. It is mechanical and the release step owns it.
- A fragment name says which ticket a change came from, which helps the Done log.
- Reviewers check for a fragment instead of a `CHANGELOG.md` diff.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Every PR edits `CHANGELOG.md` | Conflicts between every pair of open PRs. |
| Changelog written from commit messages at release | Commit summaries are written for reviewers, not users; the wording would need a second pass anyway. |
| A fragment tool such as towncrier | A Python runtime in CI for what a short script or the release step does by hand. |
| `release-plz` writes the only changelog | It is M2, and it writes per-crate notes, not the binary's user-facing history. |

## Tickets implied

None new. M1-003 creates `changelog.d/`. The release step of decision 3 assembles the fragments: M1-138
for 0.1.0, and the `RELEASING.md` runbook for weekly tags. The CLAUDE.md checklist line is edit C-4 in
`docs/plan/13-plan-corrections.md`, for the founder to apply.
