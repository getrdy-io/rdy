# Plan corrections

Owner: rust-architect. Date: 2026-10-28, revised the same day after the code-reviewer review in
`docs/plan/reviews/13-plan-corrections-review-by-code-reviewer.md`. This file is the one list of every place where
`docs/plan/rdy-plan.md` (the plan), `CLAUDE.md` or `KICKOFF.md` is wrong, stale or contradictory. It merges
the "Plan corrections found" sections of `docs/plan/00-*.md` to `10-*.md` and `docs/adr/README.md`, plus the
review files in `docs/plan/reviews/` where a reviewer caught a plan error the author missed. When several
documents flagged the same thing, it is one entry here and every source is listed. Corrections that only
concern one planning document or ADR against another stay in the document that raised them; they are not
repeated here.

How to use it: the founder edits the source file (the plan, `CLAUDE.md` or `KICKOFF.md`) as proposed, or
writes a better fix, then deletes the entry from this table. Where the fix needs a founder decision, the
entry points to "Decisions the founder must make" below. Severity: **blocks M1** means an agent following
the text as written builds the wrong thing in M1 or M1 cannot start or finish as defined; **should fix
before M1** means the text is wrong and an M1 ticket touches it; **cosmetic** means wrong or stale but no M1
ticket depends on it. "Raised by" uses document numbers (00 to 10), `ADR` for `docs/adr/README.md`,
`rv<doc>-<reviewer>` for a review file (`rvADR` is the review of the ADRs and 00), and `13` for items first
found in this pass.

**Status after M1-009 (2026-10-28).** rust-architect worked through every row. Each blocks-M1 and
should-fix row is applied, rejected or moved, and its row is deleted; "Closed during M1-009" at the end
says what happened to each. Two cosmetic rows stay. The `CLAUDE.md` edits are listed in "CLAUDE.md edits"
below.

## Corrections

| id | where | what is wrong | proposed fix | severity | raised by |
| --- | --- | --- | --- | --- | --- |
| PC-35 | Plan, lines 9, 28, 218 and 288 ("the incumbent Kubernetes-only preflight tool") and evidence point 3 (remote host collectors) | The incumbent tool also has host collectors and preflights. Its remote-node limit is no rdy advantage while rdy also runs only where it is started. | Say "Kubernetes-first". Keep any multi-node claim out of public copy until rdy can run against remote hosts. Changing the descriptor is a repo-wide sweep, and the common brief that prescribes it needs the same edit. | cosmetic | 10 |
| PC-37 | Plan, Milestones table, M3 | The M3 exit test ("First 10 paying vendors") can only be measured after the launch that M3 contains. | Launch when M3 scope is done; measure the exit test over the next eight weeks. The 12-month star and install targets start on launch day. | cosmetic | 10 |
| PC-45 | 02 "Scheduling, timeouts and hangs", Watchdog, Snapshot bullet | It says that with no snapshot the watchdog reports every check as `error`, `interrupted`. `error_kind` has only `check_failed` and `panic` (01 section 5.2), and `interrupted` is a field of the report that means Ctrl-C. | Say "as `error` with `error_kind: check_failed`". M1-043 builds it that way (`unfinished_result`). | cosmetic | M1-043 review |

## Decisions made

1. **M1 length (2026-10-28).** M1 is extended, not cut. It is planned at its real size, at 10 to 15 founder
   hours a week, and was planned to start after the Nov 20, 2026 go or no-go. Every document's cut list
   stays as a `core` marker so you can still trim. The M1-late tier stays in M1 and is marked `core: no`. A usable
   binary still ships every week. `11-backlog.md` sets the numbers, after the code-reviewer and
   qa-engineer reviews of it and correction 02: M1 is 167 tickets and 368.5 hours, 309.5 of them core.
   At 13 hours a week from Nov 23, 2026, with core tickets first, 0.1.0 ships in week 25 (May 10 to 16,
   2027) and **M1 ends on Sunday Jun 20, 2027** (week 30, after the M1-009 re-cut). At 10 hours a week
   M1 ends in the week of Aug 9, 2027; at 15 hours, in the week of May 17, 2027 (not recomputed after
   correction 02). The code-reviewer's bottom-up estimate of the core is 229 hours. Decision 2 moved the
   start to 2026-10-28; the calendar dates are unchanged.

2. **Starting M1 (2026-10-28).** The founder approved the planning pass as it stands and told the coordinator
   to build M1 now, ahead of the Nov 20, 2026 go or no-go. This closes open decision 1 below ("Starting M1
   before the M0 gates") in favour of starting now. The employment-agreement read and the validation gates
   stay the founder's to finish in parallel.

### Background: how the M1 count grew

The budget in `KICKOFF.md` is six weeks at 10 to 15 hours: 60 to 90 hours.

| Count | Source | M1 hours |
| --- | --- | --- |
| Calendar, by slice: architecture, engine, report, signing and CLI edge 81; security 27; release 24; check families core 62 | 00-overview.md, first calendar | about 194 |
| Calendar plus the probe facade and the review fixes | 02-engine-design.md, "M1 hours and cut list" | about 248 (19 weeks at 13 h) |
| Check families only: M1 tier 79 plus 6 of reviews; M1-late tier 72, kept in M1 as `core: no` | 03-check-catalog.md, "Capacity and cut order" | 157 |
| Merged backlog, first draft | 11-backlog.md before review | 571 (438 core) |
| Merged backlog after the code-reviewer and qa-engineer reviews | 11-backlog.md | 365 (306 core) |
| Merged backlog after correction 02 (PR #5) | 11-backlog.md | 368.5 (309.5 core) |
| Bottom-up estimate of the core | 11 review by code-reviewer | 229 core |

M1 tickets in each document's "Tickets implied" section:

| Document | M1 tickets | Hours |
| --- | --- | --- |
| 00-overview | 42 | 108 |
| 01-spec-format | 32 | 73 |
| 02-engine-design | 31 | 84.5 |
| 03-check-catalog | 54 (24 of them M1-late) | 157 (72 M1-late) |
| 04-bundle-and-redaction | 6 | 14.5 |
| 05-threat-model | 11 | 27 |
| 06-release-and-distribution | 8 | 24 |
| 07-cli-ux | 26 | 44.5 |
| 08-testing | 16 | 38 |
| 09-docs-site | 19 | 53 |
| 10-devrel-and-launch | 19 | 32 |
| ADRs 0001 to 0016 and the ADR index | 39 | 109.5 |

These lists overlap: SEC tickets appear in 00, 04 and 05, and ADR tickets in 00 and 02. Merging by exact
title gives about 237 distinct tickets and 575 hours, an upper bound. The backlog merge also folds
renamed duplicates (about 30 hours), but adds about 25 hours: four M2 facade tickets the M1-late checks
need, 08's add-back items, and gap tickets such as wiring `rdy run` and tagging 0.1.0. That is why the
first draft, 571 hours, sat close to the upper bound. The review of 11 then removed 49 hours of duplicates
and 99 hours of padding, moved 62.5 hours to M2 to M4, and added 5 hours of qa-engineer must-fixes. The
194 and 248 hour counts did not include 07, 08, 09 or 10.

## Decisions the founder must make

In each case the documents took the conservative option and left the choice to you.

### 1. Starting M1 before the M0 gates (resolved 2026-10-28)

**Resolved** by Decisions made 2: the founder started M1 on 2026-10-28, ahead of the Nov 20 go or no-go.
The gates and the employment-agreement read stay the founder's to finish in parallel. The text below is
kept as the record.

The plan says no Rust until the gates are met, with go or no-go on Nov 20, 2026, and says to read the
employment agreement before writing code. `KICKOFF.md` starts M1 when the backlog is approved. Taken (00,
option 1): finish planning, build only the throwaway demo prototype in a scratch repo, start M1 on Nov 23
only on a "go". The alternative is to start now and treat the gate as a later checkpoint. The 2026-10-28 M1
decision assumes a start after a go on Nov 20. Confirm, and this decision moves to Decisions made. Two gate-safe
steps can happen now: reserving the crates.io names (decision 4) and creating the repo (decision 2 first).

### 2. Public repo versus plan content

The repo must be public before the first CI ticket for free CI minutes (06), and design partners must be
able to read the code (10). The plan copy in it holds pricing, ARR scenarios, the employment-agreement risk
row and the trademark history. Options: keep it as is, trim the business sections, or move them to
`rdy-cloud` and keep only the technical plan public. Taken until you decide: agents add no business content
to `docs/plan/` (09).

Update 2026-10-28 (M1-009): `getrdy-io/rdy` now exists and is public, and `docs/plan/rdy-plan.md` is in it
with the pricing tiers, ARR scenarios, the employment-agreement row and the trademark history. This
decision is now urgent. Two related rows moved here: PC-05 (the whole question, including the `CLAUDE.md`
layout line "docs/plan/ holds the plan") and the optional half of PC-40 (whether to replace "$16.5M" at
plan lines 9, 30 and 133 with "a large round", since the exact figure also identifies the company). M1-009
applied the other half of PC-40: the investor and angel names are gone.

### 3. Paid services and credentials

- **Cloudflare.** A docs-only account and an API token for the docs deploy, stored only in the GitHub
  environment `docs-production` (09). A second account and token for M2 previews. The Worker that serves
  `getrdy.io/install` is deployed by hand by you, with no Cloudflare secret in Actions (06).
- **Accounts and MFA.** Hardware-key MFA on the registrar and hosting accounts, registrar lock, DNSSEC and
  CAA (SEC-05). GitHub org 2FA and rulesets (SEC-04). A `release` environment where you click approve on
  each weekly release (06).
- **Mail.** A working `security@getrdy.io` inbox (SEC-32).
- **Example spec signing key.** A public demo key in the repo with the private half only in a CI secret
  (09 option a, M2). Until then the examples are unsigned and need `--allow-unsigned`.
- **CI.** No paid runners (06).

### 4. crates.io name reservation

The plan says to publish 0.0.1 placeholders now. 00 puts it in week 1 and calls it gate-safe. 06 puts it
in M2 (SEC-11). The set is the nine crates in `CLAUDE.md` plus a `rdy-cli` placeholder pointing to `rdy`.
It needs your crates.io account and a short-lived API token; trusted publishing replaces tokens later (ADR
0007). Taken: no agent publishes anything. Recommended: you reserve the names by hand now and delete the
token afterwards. `11-backlog.md` treats it as that hand step before the go, outside M1 hours.

### 5. Trademark search

Still to run: the USPTO export for RDY, READY and REDY, then an intent-to-use filing in classes 9 and 42,
and the Wisconsin LLC name check. The winget id `RdyLabs.Rdy` and any copy naming "Rdy Labs LLC" wait for
it (rv06-code). Taken: documents say "Rdy" and "entity pending", and nothing is filed. Filing may cost fees
and counsel time.

### 6. macOS notarization and Windows signing (M3)

SEC-50, about 8 hours plus yearly cost: an Apple developer membership and a Windows code-signing certificate
or service. Options: neither, both, or only for Homebrew and winget users. Until then SmartScreen and some
EDR tools will flag `rdy` on Windows. On macOS, files fetched by `curl` carry no quarantine flag, so the
install.sh path still works. Taken: deferred to an M3 decision (05, 06).

### 7. Smaller calls already taken

- Contributor terms: DCO sign-off, not a CLA (10). A CLA now is easier than later if relicensing is ever
  needed.
- The free spec draft offer in the launch post is left out until you decide on the paid spec-authoring
  offer (10).

## Process notes from the planning pass

1. The project subagents in `.claude/agents/` were not registered as agent types when the session started.
   The first wave therefore ran as general-purpose agents, each given its role file and the model named in
   that file's frontmatter. The types became available part way through the pass, and every later task used
   them.
2. `KICKOFF.md` numbers twelve documents (00 to 11) and gives the ADRs item 13. There is no document 12. This
   corrections file is numbered 13 because the founder asked for that number.
3. The founder added one repo-wide rule during the pass (2026-10-27): no competitor company or product may
   be named anywhere in the repo. The old-name rule was already in `CLAUDE.md` at bootstrap. The plan
   copy's competitor tables, its Option B section and its source list were rewritten with category
   descriptors, and the competitor links were withheld. That closes the competitor-name item in 05 and
   the matching note in rv05-code. The denylist used to check for both is kept outside the repo on
   purpose, so the check never writes the names it guards against. `CLAUDE.md` now states both rules.

## Plan corrections found

This file is the corrections list.

## Tickets implied

- [M1] Apply blocks-M1 and should-fix plan corrections to CLAUDE.md, KICKOFF.md and rdy-plan.md | owner: rust-architect | est: 3h | depends on: none | exit test: every blocks-M1 and should-fix entry is applied or rejected, and its row is deleted from 13.

## Open items for later milestones

- **CF-03, the upload transport (blocks M2-026, not M1).** ADR 0014 sends the M2 upload client to the
  M3 `http_exchange` primitive and bans reqwest in `deny.toml`. M2-026 builds the upload client on
  reqwest with the platform verifier, which ADR 0014 rejects. Not resolved here. Before M2-026 starts,
  rust-architect writes one ADR that picks the upload stack, its verifier and its `deny.toml` entry,
  reviewed by security-reviewer (`reviews/adr-and-00-review-by-security-reviewer.md`, CF-03).

- **`partial.missing_grants` has no wire field and no owner (blocks M1-110).** 02 (engine design review
  table, row 6, and the 01 edit list) accepts `partial.missing_grants: [string]` as an additive field of
  01 section 5.2 that the k8s 403 partials need in M1. `rdy_spec::result::Partial` and the result schema
  do not have it, and no ticket adds it. M1-033 writes the grants into the result `notes` as a stopgap.
  Proposed owner: M1-110 (k8s.storageclass, "`CSINode` forbidden gives partial"), the earliest ticket
  that returns a 403 partial. M1-020 is done, so no rdy-spec result ticket is open. M1-110 starts with a
  small rdy-spec change: the `missing_grants` field on `Partial`, the schema, 01 section 5.2 and the
  regenerated docs. Then M1-033's `notes` line moves to the field. M1-109 (k8s.access) reports a block
  with a fix and does not need it.

## CLAUDE.md edits

rust-architect wrote the `CLAUDE.md` halves of the rows above as exact text, C-1 to C-9. The coordinator
applied them to `CLAUDE.md` in this PR (#13, commit `c469ac2`), under the founder's standing instruction
to build every M1 ticket. The founder may revert any of them.

- C-1: rule 3, refuse unsigned specs, always refuse a failing signature (PC-03).
- C-2: Commands, `cargo run -p rdy -- run ... --allow-unsigned --json` (PC-04).
- C-3: Names and places, the install line (PC-16).
- C-4: PR checklist, changelog fragment in `changelog.d/` (ADR 0017).
- C-5: Repo layout (PC-18, PC-19, PC-22, PC-23, PC-24, PC-27, PC-28, PC-29, PC-30).
- C-6: five release targets and CI legs (PC-20).
- C-7: clap usage errors exit 64 (PC-21).
- C-8: releases via `dist` (PC-28).
- C-9: docs.rs pages from M2 (PC-32).

## Closed during M1-009

Plan corrections. "Applied" names the file edited; "C-n" is a `CLAUDE.md` edit from the list above.

- PC-01: deleted. Resolved by Decisions made 2; open decision 1 is marked resolved, and 00 and 11 say M1
  started on 2026-10-28.
- PC-02: applied to `KICKOFF.md` (constraints) and the plan (Rust build plan: 0.1.0 after 25 weeks, M1
  after 30; "Build order inside M1"). The KICKOFF text names the 2026-10-28 start instead of "after a
  go on Nov 20".
- PC-03: applied to the plan (design rules). C-1.
- PC-04: applied to the plan (crate table: `rdy` in `crates/rdy-cli`). C-2.
- PC-05: moved to founder decisions (decision 2), with the fact that the repo is now public.
- PC-06, PC-25: applied to `KICKOFF.md` (spec signing and release signing; minimum docs, security and
  release work) and the plan (M1 scope gets minimal Markdown docs; M3 says hosted docs site).
- PC-07: applied to the plan (Milestones table gets an Engineering done column from 00).
- PC-08, PC-38: applied to the plan (alpha builds, `--allow-unsigned`, version policy).
- PC-09: applied to the plan (two workspaces).
- PC-10, PC-11, PC-12: applied to the plan (release engineering and crate table). The `serde_yaml` and
  `serde_yml` bans are already in the M1-004 exit test.
- PC-13: applied to the plan crate row, except the clause "`reqwest` only for the M2 upload client":
  rejected, because ADR 0014 bans reqwest and the upload stack is open (CF-03 above).
- PC-14, PC-16: applied to the plan (POC flow step 1, terminal demo, names table). C-3.
- PC-15: applied to the plan (install endpoint).
- PC-17: applied to the plan (design sample label, `.example` hosts, `access_modes`, `gpu.cuda`
  `built_with`, `source` and `compat`, the nominal band note, IAM simulation wording).
- PC-18, PC-34: applied to the plan family list (milestone per family, `aws.*` ids). C-5.
- PC-19 (cosmetic), PC-27: applied to the plan (family list, crate table). C-5.
- PC-20: C-6. PC-21: C-7. PC-22, PC-24, PC-29: C-5. PC-29 had `docs-deploy.yml` in M1; the 11 review
  moved the hosted docs to M3, so C-5 says M3.
- PC-23, PC-30: applied to the plan (crate table, public layout). C-5.
- PC-26: applied to the plan (conversion flow step 4).
- PC-28: applied to the plan and `KICKOFF.md` item 7. C-5, C-8.
- PC-31, PC-33, PC-36, PC-39, PC-41, PC-42 (cosmetic): applied to the plan.
- PC-32 (cosmetic): C-9.
- PC-35 (cosmetic): left in the table. It is a repo-wide wording sweep plus a brief kept outside the
  repo, and no M1 ticket depends on it.
- PC-37 (cosmetic): left in the table. It changes how a business milestone is measured, which is the
  founder's call when M3 is planned.
- PC-40: applied to the plan (investor and angel names dropped). The optional "$16.5M" change moved to
  founder decisions (decision 2).
- PC-43: applied in 02, 04, 05, 11. Unset, empty or invalid `RUST_LOG` means no log output (07 D.6),
  and the five dependency caps hold whatever a valid `RUST_LOG` says. The proxy URL canary moved to
  M1-060 and the JSON and HTML parts of the M1-056 exit test to M1-062.

ADR amendments in the ticket title:

- ADR 0006 decision 5: `net.dns` takes the Linux system answer from `getent ahosts`, with
  `hickory-resolver` as the per-nameserver tool and the fallback (03 `net.dns`, rv03-rust-engineer item
  6). 02's M2 ticket for this amendment is done early.
- ADR 0015 decision 10: the 04 bullet (span union, keyed HMAC tags, `Redacted<T>`, `ring`, schema-aware
  walk, rules compiled in, fail closed). Status: Accepted (security-reviewer sign-off in PR #13,
  2026-10-28).

Review follow-ups collected during the build:

- ADR 0008 decision 7 and 01 section 4.8: `spec_unreadable` (exit 64) and `interrupted` (exit 70)
  added. ADR 0008 also gains `spec_expired` and `trust_store_insecure`, which 01 section 4.8 already said
  were added. The result schema's ErrorOutput code list matches.
- ADR 0003 decisions 1 and 2 and ADR 0008 decision 4: aligned with ADR 0016 (folder created before the
  first check, `-2` to `-9`, exit 70 before any check; Windows default).
- ADR 0003 decision 6: the banner comes first. 01 section 6 still listed the banner second, below the
  header, against its own 4.7, 07 sections 2.1 and 8, and 07's correction; it is moved to item 1 too.
- ADR 0008 decision 4: Ctrl-C added to the exit 70 list (07 "Decisions needing an ADR").
- ADR 0008 decision 7: `report_write` is an error object only when no verdict exists, as in 07 section
  4.1.
- ADR 0002 decision 5: a declined `trust add` exits 64.
- Totals: 00 and 13 say 368.5 hours and 309.5 core, as 11 does. The 11 calendar is re-cut from week 19
  (11 h, 12 h, 12.5 h, 13.5 h, 11.5 h, 13.5 h, 13 h to week 25; no week over 13.5 h). Core still ends in
  week 25; M1 ends in week 30, Sunday Jun 20, 2027. 00's calendar is copied from 11 (00 had also
  drifted in weeks 7 and 19).
- `reviews/adr-and-00-review-by-security-reviewer.md`: the MF-03 quotes have their `<` and
  `>` escapes back. Both closure checks now say the check itself edited no file, and name the M1-001
  commits that did. `reviews/adr-0013-0016-review-by-security-reviewer.md`: CF-04 to CF-06 marked done by
  backlog correction 02 (PR #5).
- ADR 0014: amendment note for MF-04 in the status line and decision 7.
- 11: the stale SEC-21 correction is deleted; 05 revision 3 already says "no redirects".
- Corpus count: M1-063, M1-138, the week 13 row and the reconciliation note say 28, as 04 does. The
  M1-063 title copy in 12-progress.md still says 30; that line belongs to the coordinator.
- CF-03: recorded above as an open M2 item, not resolved.
- CF-07: 01 section 5 and the 7.2 sample take `identity.kube.user` from `SelfSubjectReview`. A
  kubeconfig-only user (1.27 and older, or a failed call) is marked with `user_verified: false` and shown
  as "not verified by the API server". `user_verified` is a new field, required whenever `identity.kube` is an object, in revision 0 of the
  result schema, which has not shipped, so no `rdy-spec` bump.
- CF-02 (assigned to M1-009 by the adr-and-00 closure check): 00's report writer sketch takes
  `RedactedReport` and `OutputDir`, `rdy-checks-net` names the probe facade (ADR 0014), and the
  reqwest and `rustls-platform-verifier` rows say they are not used in M1; a hyper row is added.
- ADR 0017 (changelog fragments) added and indexed. C-4 carries the `CLAUDE.md` checklist line.
- M1-003: the exit test says the 12 labels of 10 section 6, so "the 10 section 6 labels" cannot be read
  as a count.
