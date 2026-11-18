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
| PC-46 | 02 "Scheduling, timeouts and hangs", Watchdog, "One writer" bullet | It says that when the watchdog loses the write race it waits for `Done` and then does nothing. M1-043 adds a backstop: once the state is `Done`, a process that is still alive `loser_wait` (5 s) after the watchdog fires is killed and exits with the code stored by `WriteState::finish`. It covers a print to a blocked stdout after the report is written. | Add the backstop to the bullet. The M2 upload prompt after the result (07 section 5) must disarm or re-bound the watchdog first, or it is killed at deadline plus 15 s. | should-fix | M1-043 review |
| PC-47 | 09-docs-site.md, section 5, "Examples are stored as JSON" bullet | It says the renderer validates each example against its schema. M1-084 does not validate in the render, because `jsonschema` as a normal dependency of `xtask` fails the license policy (MIT-0 through `borrow-or-share`). The test suite validates each example, with rdy-spec's validator, and decodes it with `parse_unverified` (ADR 0034). | Amend the bullet to: "Examples are stored as JSON in the schema. The test suite checks each one against its schema (ADR 0034). The renderer shows each as YAML and reads it back to the same value." Restore the render-time check if the license policy allows the crate. | should fix before M1 | M1-084 review (PR #89), ADR 0034 |
| PC-49 | 08 Appendix C, Normalisation table | The table lists `producer.version`, `commit` and `target` only. M1-051 `normalize` also scrubs `producer.rdy_spec` (`<rdy_spec>`), which moves with every release of the crate. `normalize_across_jobs` also resets `run.options.jobs` to 1, because the report records the jobs value and the `jobs = 1` against `jobs = 8` comparison varies it. The table's last two rows (certificate serials and digests as `<serial>` and `<sha256>`) are not built. | Add `producer.rdy_spec` to the version row. Add a row for `run.options.jobs`: set to 1, in `normalize_across_jobs` only (the jobs comparison). Mark the serial and digest row as deferred to M1-090, which owns the first golden that holds a generated certificate. | should-fix | M1-051 review (PR #111) |
| PC-50 | 07 section 4.1 (files that cannot be written after the verdict), 02 "Watchdog" | 07 says that when the files cannot be written, `--json` stdout gets the Report with `complete: false`. M1-176 prints stdout before it claims the write state and writes the files, because a blocked stdout is the one write that can hang for good and the watchdog must still own the report while it does (M1-043 carry). So the document is already on stdout when the files fail. | With `--json`, a failed file write after the verdict leaves the document on stdout as printed and puts the summary and the error on stderr, exit 70. Without `--json`, stdout stays empty. The exit code is the authority: 07 section 4.1 and the `complete` doc in `rdy-spec` say that a printed report can read `complete: true` with exit 70. cli-ux signed off. A script checks the exit code (`set -o pipefail`, or stdout to a file and `$?`), never the document alone; stderr says `error: report files not written. The JSON on stdout is complete but the exit code is 70.` Check the number at merge. | should-fix | M1-176 |
| PC-51 | 11 backlog, M1-176 exit test ("proved with the real binary") and M1-088 (watchdog clause) | The exit test needs the shipped `rdy` to hang on a check that never yields, and to end within the deadline plus grace. The shipped binary cannot do either: ADR 0011 decision 4 gives it no hook, so it has only the real families (none hangs) and the fixed five minute deadline. | M1-176 proves the spin clause with a test binary that calls `rdy_cli::run` with a one second hook deadline and the real watchdog (`crates/rdy-cli/tests/run_watchdog.rs`, a pipe run and a spin run). The blocked-pipe clause is also proved on the real unsteered binary by `crates/rdy-cli/tests/run_watchdog_binary.rs`, which is `#[ignore]`d because it takes about 5 min 10 s, and is run by hand (no nightly test job exists). M1-088's watchdog clause (blocked stdout pipe, exit 70, `complete: false` in the folder) is the same case: it relies on that test and does not repeat it. Check the number at merge. | should-fix | M1-176 (PR #34 review) |
| PC-52 | M1-043 carry (macOS SIGCHLD-ignored check), M1-176 | The carry asks for a check that the SIGCHLD-ignored test really ignores SIGCHLD on macOS. M1-176 tried a behavioural probe (a child's `wait` fails with ECHILD when the ignore holds). The macos-x64 CI run on ee62985e failed that probe in `sigchld_ignored` (0.195 s), so macOS does not auto-reap the way the probe assumes, or the ignore does not survive `exec` there. The runner itself works there (the rest of the test passes without the probe). | The probe is Linux only (`/proc` SigIgn plus ECHILD). The macOS carry stays open. Owner: qa-engineer, a follow-up to find out how SIGCHLD-ignored behaves on macOS (does the ignore survive `bash -c 'trap "" CHLD; exec ...'`, and what does a child of an ignoring parent report) and to write a probe that holds there. Check the number at merge. | should-fix | M1-176 (macos-x64 CI) |
| PC-53 | Plan, Milestones table, M1, engineering done column ("Fixture envs exit 0, 1 and 2 on all five targets") | In M1 the in-process env harness runs an environment only on the legs of its own OS. `rdy_cli::run` plans for `current_os()` with no hook to change it (decided in M1-086, PR #42), and every M1 environment is a Linux machine, so the macOS and Windows legs skip them. The real-binary smoke and the unsigned and tampered spec tests still run on all five. | Say "Fixture envs exit 0, 1 and 2 on the Linux targets and write both reports" for M1, and keep "all five targets" for the real-binary smoke and the unsigned and tampered specs. M2-130 adds a `RunHooks` OS override, and then the envs run on all five (correction-48). 00's milestone table and 11's M1-138 already say so. Check the number at merge. | should-fix | PR #80 review (M1-117) |
| PC-54 | 11 backlog, M1-088 (static line clause) and M1-142 | M1-088 prints a static `Running N checks...` line on a terminal, and M1-142 (PR #60) draws a live line that also says `Running N checks`. Both on one stderr would draw twice. | Whichever of PR #60 and PR #82 merges second deletes `crates/rdy-cli/src/static_line.rs`, `static_line/tests.rs`, `crates/rdy-cli/tests/run_static_line_pty.rs` and the gate call in `run_cmd`. M1-088's static-line clause is then retired, and PR #60's `run_progress_pty.rs` holds the proof for a pipe, `--quiet` and `TERM=dumb`. The `--verbose` part of the gate moves with M1-143 (PR #68). Check the number at merge. | should-fix | M1-088 (PR #82 review) |

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

Still to run: the USPTO export for RDY, READY and REDY, then an intent-to-use filing in classes 9 and 42.
The legal entity that owns the code, the copyright and the marks is Apostolic Path LLC (founder decision
2026-10-30). It replaces "Rdy Labs LLC (pending)", so the old Wisconsin name check for that LLC no longer
applies. The winget publisher id (earlier drafts said `RdyLabs.Rdy`) waits on the founder, who picks it (rv06-code).
Taken: nothing is filed. Filing may cost fees and counsel time.

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

### 8. Two Kubernetes verdicts (correction-43)

No change now. The checks ship as built, and either answer is a small change to one check.

- **k8s.dns, CoreDNS below its desired replicas.** M1-162 (PR #62) blocks when fewer replicas are ready
  than desired. k8s-expert suggests a block only when none is ready, and a warn when some but not all are
  ready, since DNS still answers. k8s-expert also suggests a block for a headless DNS Service, which pods
  cannot use as a nameserver. Taken until you decide: the block, as built.
- **k8s.ingress, two default classes.** M1-163 (PR #65) gives a note. A warn may fit better: the
  `DefaultIngressClass` admission plugin, on by default, makes the API server reject an Ingress with no
  class while two classes are marked default. Taken until you decide: the note, as built.

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
- **Correction-35, the adjtimex source (blocks the adjtimex half of M2-004, not M1).** M1-148 and 03 read
  `adjtimex(2)` through `native`, but the closed `NativeCall` enum has no variant for it, rustix 1.1.6 has no
  `clock_adjtime` or `adjtimex`, and `forbid(unsafe_code)` rules out a raw call. Correction-35 moves the
  variant, its policy row, snapshot, 05 row, Live and Replay arms, `native/adjtimex.json` and the "`EPERM` is
  partial" clause to M2-004 (3.5 h to 5 h). M1-148 takes the sync state from `timedatectl` and `chronyc` and
  the offset from its SNTP client. Before M2-004 starts, rust-engineer names the Live source: a safe wrapper
  in a rustix release, or another crate that passes the new-dependency review (05 Appendix C T5, `deny.toml`), reviewed
  by security-reviewer. If neither exists, rust-architect writes an ADR first. The review and any ADR come out
  of M2-004's 5 h. The host.time_sync half of M2-004 is check-author's work. `ci/check-crate-deps.toml`
  does not change, because the call sits in rdy-engine and host.time_sync reaches it through the Probe.
- **Correction-36, k8s.namespace follow-ups (M2-116 and M2-117, not M1).** A `LimitRange` `Container`
  default limit below `container_max_memory` is a note in M1, not a block, because the spec cannot say that
  the product sets requests without limits. M1-161's builder chose this and k8s-expert confirmed it on
  PR #32, which edits 03 to match. M2-116 adds the spec key, owned by rust-architect, before rdy-spec's
  first crates.io release. M2-117 makes k8s.namespace work on OpenShift without cluster-scoped reads:
  `AppliedClusterResourceQuota` instead of `ClusterResourceQuota`, and the project GET when
  `get namespaces` is Forbidden. Its two new guard reads need a security-reviewer review.

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
- PC-44 (found by the M1-040 review, PR #58): applied in 01 section 5.4, 02 (the Files deny list and the
  `Backend` sketch) and 05 I5. The backlog row changed in correction-12 (PR #82). The ticket lines quoted in ADR 0014 and 02 are
  frozen inputs and keep their old wording; 11 is the authority. Four changes. (1) One `Cmd` type, the one in
  `exec::policy`, built with `CommandEntry::cmd` (ADR 0028). `Probe::exec` applies the check's
  `CommandSpec` (extra directories, environment names, stdout cap), then checks the command with
  `table::validate_for(os, ..)` for the check's OS, then calls
  `Backend::spawn(Cmd) -> Result<Output, ProbeError>`. The provided `spawn` is the live path and calls
  `exec::table::run`, the only public runner (`policy::run` is crate-private); the replay backend
  overrides it. 02's `io::Result<Output>` is replaced, because a start failure, a timeout and a hung
  child are not `io::Error` kinds. The gate runs for every backend, so a fixture can never "run" `sh`,
  `sudo` or any program the table does not list, and a replayed run depends on no tool of the test
  machine. There is no `ResolvedCmd`, no `resolves_on_disk` and no second `Cmd`. (2) The action log keeps a `denied` entry always. A `denied` or `failed` file call folds into one
  `coalesced` entry after 20 per (check, kind, rule or error, directory); the entry carries `rule` or
  `error` as well as `of`, `under` and `count` (schema description of `under` and `count` and the docs of
  `actions_truncated` and `actions_dropped` updated through `cargo xtask schema`; `ActionKind::Coalesced`
  and the fields already existed). A check holds 1000 entries. Drop order: `ok` file entries, then
  `failed` ones, then (last resort, with a `tracing` warning and a counter) other kept entries. (3) The
  M1-040 exit test says "retention drops ok read, read_dir and stat entries first, then failed ones, and
  never a denied entry" in place of "truncation drops only ok read, read_dir and stat entries" (the
  row in 11 changed in correction-12, PR #82). (4) The deny list in 02 and 05 I5 gains the any-depth `etc` rules, the credential files,
  the cluster credential paths, the `/proc/<pid>/` allowlist, the kernel files and `/dev` for `stat` and
  `read_dir`. Carried: M1-091 and M1-103 inherit "every tcp, http and kube call writes one entry"; M1-102
  settled the engine's own kubeconfig read (not a probe read, ADR 0031); M4 adds a closed stat-only
  `/dev` list (`/dev/nvidia*`, `/dev/dri/*`, `/dev/kfd`).
  Fix round 2 (re-review of 2cd0026): (5) `/proc/self/auxv` is allowed for `self` only, because M1-042
  reads `AT_SECURE` from it (02 Files, 05 I5). (6) A `denied` call of any kind folds too, per
  (check, kind, rule, program or host or path), so 1001 denied execs hold 21 entries and none is
  dropped; "never a denied entry" means never dropped for another kind of entry, and only a check with
  more than 1000 distinct denied targets can lose one (01 section 5.4, the schema, ADR 0014 unchanged).
  (7) The `exec::run` and `ExecSpec` deny clause lives only in M1-044, and since M1-066 the cfg gate
  enforces it at compile time. `exec::table::run`, `exec::run` and `ExecSpec::new` are also on the root
  `clippy.toml` `disallowed-methods` list now, so a check crate that calls the table runner without a
  `Probe` fails clippy. The one call in `probe.rs` carries `#[expect(clippy::disallowed_methods)]`.

- PC-48 (found by the security review of PR #85, applied in M1-044): applied in 02 Appendix A, in the
  `clippy.toml` of every check crate and in `tests/lint-wall/src/uses.rs`. The wall list gains the
  first-party items a check must not call, because clippy bans only what is listed: the output folder
  (`rdy_engine::output::{ReportParent::open, OutputDir::create_new, create_new_in, write_atomic,
  write_spec, default_report_parent}`), the process-wide effects (`rdy_engine::exec::{kill_all_groups,
  harden_umask, inherited_fds, live_groups}`), the watchdog (`watchdog::ProcessEffects`,
  `watchdog::Effects::{exit, kill_groups, notice}`, `Watchdog::start`, `WriteState::{claim,
  claim_or_park, finish}`), `probe::ProbeHub::{new, run_probe}`, `rdy_spec::load`, `std::env::args` and `args_os`, the terminal
  (`std::io::{stdout, stderr, stdin}`, the print macros) and `TestRun::context`. `privilege_gate` and `gate_then`
  (M1-042) are in `rdy-cli`, which no check crate may depend on. `rdy_engine::live_backend` (M1-045) is
  on the list, in `uses.rs` and in the floor. The direct dependency
  allowlist (`ci/check-crate-deps.toml`) is built in M1-044, because old M1-065 was merged into it.

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

## Applied during the M1 build

Corrections that a build review found and that were applied to the planning documents at once. Each one is also in
the corrections log of `11-backlog.md`.

- **Correction-37, host.time_sync commands and peers.** 03 named `chronyc -n -c -t 3 tracking`, but chronyc has
  no `-t` option, so that form fails on every host. 03 now says `chronyc -n -c tracking`, and PR #35 fixes the
  command table. A command limit equal to the check limit let a hung `timedatectl` throw away a good SNTP
  sample. Each step is now cut to the time left in the 5 s budget minus a 250 ms margin, SNTP stops at the first
  good reply, each command form has at most 3 s, and a timed-out command keeps the SNTP verdict with a note. 05
  INV-11 names the local IPC of exactly two allowlisted commands as a third exception, M1-128 allows exactly
  those destinations (both the `/run` and the `/var/run` paths), and 05 Appendix A T5 accepts unauthenticated
  SNTP.
- **Correction-38, review follow-ups from PR #34 and PR #35.** The env harness gets a Timeout class for a hang the
  check survived (M1-179, `core: no`), so host.time_sync needs no `PENDING` row. The watchdog's partial report
  keeps the action log in M2 (M2-118), and host.time_sync asks its servers at once in M2 (M2-119). M1-130 takes
  three carries from PR #34. No test-pinned document changed.
- **Correction-39, what `--no-network` means.** rdy and its children open only `AF_UNIX` sockets.
  That local IPC still runs: the commands 05 INV-11 names and rdy's own `Probe::unix_get` to a
  socket a check declares (INV-28). INV-11's exception now covers exactly `chronyc`, `timedatectl`
  and `firewall-cmd`. Under `--no-network` `chronyc` is not run, because its loopback UDP is an
  `AF_INET` socket. The facade refuses `tcp`, `udp` and lookups with `RULE_NO_NETWORK` (M1-059).
  M1-059's strace test flags any family but `AF_UNIX`, and M1-128 limits the `AF_UNIX`
  destinations.
- **Correction-40, the unsigned banner may name its flag.** M1-126's exit test banned `--allow-unsigned` from
  every stderr line, but the unsigned banner's `sig` line names it on purpose: it is the loud warning of
  product rule 3. The rule now covers fix, hint and error lines (M1-126, 07 rule 8, 01 section 4.7). PR #42 also re-wraps
  07 C.12 to 07's own wrap rule.
- **Correction-41, host facts and a reserved product name.** No row filled `report.host.os` from os-release,
  so the header printed `linux`. New M1-180 (core) does it, and the env goldens and README transcripts depend
  on it. A product named `rdy` would print `fix from rdy:` like rdy's own lines; M2-120 makes `ProductSlug`
  refuse it before rdy-spec's first crates.io release. The renderer refuses it in M1 (PR #42).
- **Correction-42, the printed banner, the HTML size cap and five M2 tickets.** A print banner fixed in the
  page margin cannot be built and proven in headless Chrome. The full banners stay in the page flow and print
  once, at the top of page one, and every printed page carries the banner title in its top margin as fixed
  text that rdy writes. Nothing covers the first lines (07 D.3, 01 section 6, M1-081). Past the 5 MiB cap the
  action table loses rows first, then Found and Needed lines (07 D.4). M1-141 tests the Found and Needed
  labels and lines. New M2-121 to M2-123 take the 2026-11-06 follow-ups, and new M2-124 adds the engine
  progress observer and the full 07 section 3 line. 07 D.5 allows a test-only indicatif draw target. M1-175
  also builds k8s.dns, and new M2-125 reads the RKE2 and OpenShift Corefiles that M1-162 leaves out.
- **Correction-43, the 03 sections of k8s.crds and k8s.ingress, and two M2 tickets.** PR #64 (M1-164) and
  PR #65 (M1-163) change their own 03 sections, and k8s-expert and security-reviewer signed off on both.
  The 03 text lands with each PR; this entry approves it. k8s.crds reads discovery (`GET /apis` and
  `GET /apis/<group>/<version>`), not CRD objects, so "installed" means "served": aggregated and built-in
  groups count, a terminating CRD stays listed, and storage versions and deprecation are not visible. The
  operator Deployment is a GET by name through an optional Role of one namespace and one name
  (`examples/rbac/rdy-readonly-operator.yaml`). A missing Deployment warns and says the operator may be a
  StatefulSet or OLM-managed. A 404 on a version that `/apis` listed blocks. Versions follow a fixed
  grammar with pre-releases below their release, and a run reads at most 32 discovery documents (ADR 0045).
  k8s.ingress lists Services only in the target namespace, through an optional Role
  (`examples/rbac/rdy-readonly-target-namespace.yaml`, ADR 0044). Controllers match exactly. A pending load
  balancer warns when strictly older than 10 minutes, counted from creation. The retirement warning names
  the managed and bundled copies. "No default class" warns only when `controller` is set, and is not judged
  on GKE and OpenShift. A required Gateway API served at `v1` with no accepted class warns. `route` is outside
  the GKE and OpenShift "not verified" exception. Two default classes are a note. M1-163 and M1-164 must
  leave 03 saying so. M1-175 also builds k8s.crds and k8s.ingress, ten k8s ids in all, still 1.5 h. Two
  verdicts go to the founder (decision 8). New M2-126 pins the two namespaced Role reads to the spec's
  namespaces, and new M2-127 builds the pty probe examples once in CI before nextest.
- **Correction-44, the order of the run header, `--verbose` and the live line, and one M2 ticket.** From the
  reviews of PR #68 (M1-143). PR #68 edits 07 C.1, C.2, 2.8, 3 and A.3, 02's `RunOptions` lines and M2-017's
  dependencies; this entry records those decisions. The header prints at the end of the run, because it
  holds facts known only then (the `needs` row). With `--verbose` the event lines print live after the
  banner and before the header, one blank line follows them, and then come the header and the list (C.2).
  07's rule for the M1-142 code now says so, and that "the header prints once before progress starts" is not
  met until new M2-128 moves the header before progress (which also prints the `cluster` row before the first
  Kubernetes request, as 07 section 2.1 says). `--verbose` turns the live line off: M1-142's exit test says
  `quiet or verbose`, and the code lands with whichever of PR #60 and PR #68 merges second. 07 section 5.2
  says that a `--verbose` line written into a full stderr pipe blocks the run, and the watchdog ends it with
  exit 70 and a partial report. M1-143 builds 02's `on_progress` seam with `Progress::Finished` only; M2-124
  adds the started and phase events on it, and M2-017 depends on M2-124.
- **Correction-45, `rdy run` writes the HTML report, and M1-100 takes PR #71's deferrals.** 01 section 5.5,
  02 "Output and reports" and 07 sections 2.1 and 5.2 put a `.html` next to the `.json` in every report folder,
  and the `rdy` and `rdy run` help says the run writes one. No ticket wired it: M1-057 writes the JSON only,
  and the HTML tickets build and test the renderer. New M1-181 (core, week 19) writes the page through
  `OutputDir::write_html`, with the `.json` written last, and the watchdog writes the INCOMPLETE page by the
  same rules. M1-138 depends on it. PR #71 (M1-099) left `expected_issuer` and `pin_sha256`, the
  generated-chain fixture rig and the Timeout case to M1-100, whose exit test did not hold them. M1-100 now
  does all three (3.5 h), and M1-101 moves to week 21. No test-pinned document changed.
- **Correction-47, the 03 section of k8s.cni, and one M2 ticket.** PR #78 (M1-165) changes its own 03
  section after the code-reviewer, security-reviewer and k8s-expert reviews. The 03 text lands with the PR;
  this entry approves it. k8s.cni never lists DaemonSets, because a DaemonSet holds env values. It reads 16
  namespace and name pairs by name through optional Roles (`examples/rbac/rdy-readonly-cni.yaml`, ADR 0046):
  14 in `kube-system`, `calico-system/calico-node` and `kube-flannel/kube-flannel-ds`. A namespace other than
  `kube-system` is read by `GET` first, and its pair is skipped on a 404. DaemonSets are read only when the
  node condition, the API groups and the OpenShift `Network` object did not name the plugin, or for the AWS
  VPC CNI. OpenShift is named by `Network` `status.networkType`. Crash-loop restart evidence is not read in
  M1, and ready below desired is not reported. Unknown, unreadable or two plugins is partial with the grants
  named, never a block. Flannel with Calico is Canal, which enforces. A policy plugin on top of a base plugin
  is the policy plugin (each `cni.toml` entry is base, policy or full); Azure CNI alone does not enforce.
  Flannel on k3s is partial, because rdy cannot read `--disable-network-policy`. The AWS VPC CNI follows
  `ENABLE_NETWORK_POLICY`, and is partial when it is absent. Pod ranges come from `Node.spec.podCIDRs` only
  for a node-IPAM plugin or the OpenShift `Network` object; otherwise the pod side of `avoid_cidrs` is
  partial. Default-deny egress is 03's definition: a policy that selects all pods and governs egress with no
  rules. It warns only with `needs_egress`; otherwise, and on a plugin that does not enforce, it is a note.
  Every result notes that only namespace `NetworkPolicy` objects are read. M1-165 must leave 03 saying so.
  M1-175 also builds k8s.cni, eleven k8s ids in all, still 1.5 h. New M2-129 reads the plugin pods' restart
  evidence with k8s.dns's pod read, reports ready below desired, and has k8s-expert confirm the 13 `cni.toml`
  entries marked `verified = false` against a live cluster. M1-115's reviewer reads their source pages first.
  No test-pinned document changed.
- **Correction-48, the env harness skips Linux envs on macOS and Windows, and one M2 ticket.** M1-086 (PR #42)
  made the env harness call `rdy_cli::run`, which plans for `current_os()` and has no hook to change it, so
  the harness skips an env of another OS. Every M1 env is a Linux machine, so they run on the two Linux legs
  only. M1-117's exit test said five legs; it now says the Linux legs. M1-138, the engineering done test in
  11 and 00, the week 21 check and 08 (rule 3, the test-layer table, Environments) say the same. M1-118,
  M1-119, M1-135 and M1-166 never said five legs and are unchanged. The plan's M1 row is PC-53. New M2-130
  (qa-engineer, 3 h) adds a `RunHooks` OS override, `None` in the shipped binary, so every env runs on every
  leg; security-reviewer reviews it. From the PR #80 review: M1-117's `all-pass` env has no cluster, because
  the k8s family joins `rdy run` with M1-107. M1-107 adds k8s.version and the `api/` tree to it and
  regenerates its goldens (4 h); the item moves to M1-117 if M1-117 is not merged first. M1-175 gets a
  missing comma (PR #79 review). No test-pinned document changed.
- **Correction-50, `--key` needs a signature, the unknown-key line, the proxy carries of M1-097, the `timeouts`
  env, and M2-037.** From the reviews of PR #84 (M1-126) and of the M1-097 and M1-119 builds.
  Correction-49 is PR #85. A `--key` run of a spec with no signature exits 64 even with `--allow-unsigned`,
  with its own first line (01 section 4.7). The `spec_key_unknown` line shows the key id and no fingerprint,
  because the sidecar carries only the key id, and its fix says to compare the vendor's fingerprint, because
  a key id can be forged (01 section 4.8, 07 C.5). M1-181 writes the page that says UNSIGNED SPEC, the HTML
  half of M1-126's "both reports say unsigned". 05 Surface 2 lists a residual for M1-132: a `--key` file read
  as root has no owner check, and the fingerprint in the KEY NOT PINNED banner is the mitigation. The
  "direct works, proxy fails" sentence of `auto` needs the `NO_PROXY` rules and moves to M1-098, which also
  reports upper- and lower-case proxy variables that disagree and extends `ProbeHub::set_proxy_from_env`.
  M1-107 must not use a proxy read from `HTTP_PROXY` for https (05 INV-11, ADR 0037). In the `timeouts` env
  only the hung statvfs gives Timeout; the black-hole endpoint gives a bounded Block, because net.egress cuts
  each endpoint to its own budget. k8s.version never calls `/version`, so M1-119 proves a slow cluster at
  family level by delaying `GET /apis`, and the slow `/version` case in the CLI env moves to M1-107. 08 says
  the same. The real-time `Fake::Block` test is M1-051's and is built. M2-037 takes the cancellation tests of
  08 section 5: running checks marked cancelled, the drop guard that counts live futures, and the verdict
  rule (4 h). 07 C.5 changed, but no test reads it; no 01 block changed.
- **Correction-51, a proxy password in host.container_runtime evidence, and the proxy carries of M1-098.**
  From the security review and the build of M1-098. Correction-49 is PR #85. host.container_runtime (M1-150,
  PR #23) stores the proxy URL of a systemd drop-in, `daemon.json` or the Engine API `/info` as text.
  `url_userinfo` finds userinfo only after `scheme://`, so a proxy with no scheme (`svc:pw@proxy:3128`)
  reaches `observed.runtimes[].proxy` whole. New core M1-182 (2 h) stores each proxy as `ProxyUrl::origin`
  with a credentials flag, as net.proxy does, and proves a canary from all three sources never appears. It
  adds a `url_userinfo` form for a value with no scheme after a `*_proxy=` key or a Docker proxy JSON key,
  with corpus cases, and records the residual in 05 I1. The corpus test reads 04 Appendix B, so M1-182's PR
  edits that row, not this correction. M1-138 depends on M1-182. 05 INV-11: system resolvers also resolve
  the proxy's name, and INV-11 lists `Probe::proxy_reach` and net.egress's one direct retry under `auto`.
  M1-107: `Probe::route_for` does not look at `proxy_source` or the scheme, so the k8s client checks the
  source itself and never uses an `HTTP_PROXY` proxy for an https API server. 03 net.proxy reads the
  `proxies` of `daemon.json`, which Docker gives precedence over the drop-ins. No test-pinned document
  changed.
- **Correction-52, live controls in the result JSON, the fix `<bdi>`, `FixText` controls, and the carries of
  M1-100.** From the security review of PR #89 and the reviews and deferrals of PR #91 (M1-100). Correction-49
  is PR #85. The JSON writer leaves Cc, Cf and zero-width characters live. 05 T3 and T4 do not promise the
  JSON rule for 0.1.0, and M1-141 escapes them in the page, so new M2-131 (2 h) writes them as `\uXXXX` and
  05 T3 says any renderer of result JSON, the portal included, applies the same rule. New M2-132 (1 h) puts
  `unicode-bidi: isolate-override; direction: ltr` on the fix and builtin-fix `<bdi>`. Right-to-left letters
  reorder text with no control character, but fix text comes from the signed spec and a copy gives the
  logical order, so it stays M2. 01 sections 2.6 and 6 and the `FixText` rustdoc say controls are stripped
  before the text is printed, but the HTML and the terminal show them as escapes, and `FixText::new` checks
  only the length. New M2-133 (1.5 h) refuses them at parse in `rdy spec lint`, `rdy spec sign`, `rdy verify`
  and `rdy run`, because the signature covers the text as written.
  M1-100 cannot delete the net.tls_intercept `PENDING` row: each host is cut to its own budget, so a hung
  handshake gives a bounded warning, not `Timeout`. The row is narrowed to `Timeout` and moves to M1-179; the
  second of PR #91 and PR #70 to merge deletes it. A pin matches the leaf only (SEC-100-1), and a pin equal
  to a later certificate is partial until new M2-135 (2.5 h) records the verified path. `last_sha256` is
  always the last certificate's hash, and `root_sha256` is null when that certificate is not self-signed;
  new M2-136 (1.5 h) replaces `root_sha256` with the real anchor's, through `TrustStore` root subjects.
  New M2-134 (2 h) reports the Java `cacerts` and `NODE_EXTRA_CA_CERTS` stores. 03 net.tls_intercept's
  Source line says so; PR #91 edits its Thresholds line. No new M1 ticket. No test-pinned document changed.
- **Correction-53, spec reads that hang on a FIFO, `spec sign` of an expired spec, and the signing review
  carries.** From the M1-132 signing review (PR #96) and the security review of PR #92 (M1-182).
  Correction-49 is PR #85. The spec reader of `rdy run`, `rdy verify` and `rdy spec lint` stats the path,
  then opens it again with a blocking open and never checks the handle, so a FIFO swapped in hangs the
  command before the watchdog arms and a swapped device is opened. `rdy spec sign` opens before it checks,
  so a FIFO hangs it outright. That breaks 05 INV-02 (MF-01). `spec sign` lints with `lint_checks` only, so
  an expired spec is signed, then fails the self-check with exit 70 (MF-01). New core M1-183 (2.5 h) reads
  every spec through `signing::files::read_public`, proves a direct FIFO, a swapped FIFO and `/dev/zero`
  exit 64 within 1 s for run, verify and sign, refuses an expired spec in `spec sign` with exit 64 and
  `spec_expired` before any password prompt, keeps today's oversize results, and records in 05 Surface 2 that `read_public` still opens a device swapped in
  during the gap. M1-138 depends on it. 01 section 4.2's future `signed_at` warning was never built; it
  moves to M2-032 (0.5 h more) and 01 says "from M2-032" (SF-01). M1-134's page and M1-133's unsigned page
  say to compare the full fingerprint from `rdy verify --key`, never the 48-bit short form in the banner
  (SF-02); M1-134 depends on M1-133. New M2-137 (1.5 h) adds the container runtime proxy password to the
  known-secret set (PR #92 F8, INV-15). M2-107 (0.25 h more) also refuses invisible code points in
  trust-store notes (N-01). M1-133 moves to week 16 and M1-168 to week 17, so no week holds
  more than 15 h. Only 01 prose changed; no test-pinned text changed.
- **Correction-54, the plugin token and the `delegated` outcome, the `all-pass` k8s item, the
  `nothing_verified` sentence, and four M2 tickets.** From the reviews of the M1-107 build, the security
  review of PR #98 (M1-183) and the review of PR #100 (M1-140). Correction-49 is PR #85. The exec plugin
  runs after the cluster line and kube does not hand rdy its token, so M1-107's row now says the token is
  registered before the first request leaves, by a layer under kube's auth layer. 02 asks for an action-log
  outcome `delegated`, which rdy-spec lacks, so M1-107 writes a `form: delegated` field; new M2-138 (1.5 h)
  adds the value to rdy-spec, 01 section 5.4 and the result schema, and 02 says so. Whichever of M1-107 and
  M1-117 (PR #80) merges second adds k8s.version and the `api/` tree to `all-pass`; M1-117's row now says
  so, which correction-48 did not. New M2-139 (1.5 h) opens spec reads with `O_PATH` on Linux, so a device
  swapped in is never opened. New M2-140 (1.5 h) makes `rdy spec sign` open `--sig` and `--secret-key` at
  identification level on Windows. New M2-141 (2 h) runs `rdy run` on a k8s.version spec in the kind job
  and pages the node list on a three-node cluster. 07 D.7's `nothing_verified` sentence said every check is
  for another OS; the verdict rule also gives it when every check is optional and was not run, so the
  sentence now says that too. The rule is unchanged. No new M1 ticket, and no test-pinned text changed.
- **Correction-55, the handshake signature test, the "no revocation check" note, the OS roots source,
  the CA pin advice and the `as:` run proof.** From the M1-101 TLS verifier review
  (`docs/plan/reviews/tls-verifier-review.md`), its cold review and the M1-113 code review. Correction-49 is PR #85. The recording verifier accepts every chain, and only the
  handshake signature ties the chain to the server, but no test proves that rdy checks it, so a change to
  `assertion()` would pass every test and let any server replay a pinned leaf (SF-02). ADR 0014, 02 and 05
  say the report says "no revocation check", and no check does (SF-01). The review folded SF-01 into
  M1-096, but PR #74 (M1-096) is approved and not merged, so it is not widened. New core M1-184 (1.5 h)
  takes both: a server that presents leaf A and signs with key B fails `Probe::tls_chain` on TLS 1.2 and
  1.3, net.tls_intercept with that leaf pinned gives `not_tested`, its unknown-CA case asserts zero
  application bytes, and each net.tls_intercept result with a chain and each net.egress result with a TLS
  stage carries `REVOCATION_NOTE` once. It depends on M1-096, M1-099 and M1-100, and M1-138 depends on it.
  02 says the note comes from M1-184. 03's net.tls_intercept Source line and section 3's "Shared stack"
  named `rustls-native-certs` as the OS store; they now name `NativeCall::SystemRoots`: PEM bundles
  through the facade on Linux, and on macOS when a variable is set, and `rustls-native-certs` on macOS
  and Windows otherwise. 03's Thresholds line and M1-116's network page say that until M2-135 a CA pin is
  at best a warning, so pin the leaf or set `forbid_interception` to block (AR-01). PR #91 rewrites the
  same Thresholds line; the second to merge keeps both. M1-073 (merged) moves back to week 14, so weeks 14
  and 18 hold 15 h. From the M1-113 code review: M1-113 cannot prove in a real run that a spec `as:`
  works and k8s.rbac shows the OpenShift grant text until the family builds k8s.rbac from its
  parameters, which is M1-175, so that proof moves to M1-175's exit test. M1-113 keeps
  `Cluster::read_only_as` and `Cluster::is_openshift`, tested through the family holder. No 03 `###`
  heading or Appendix A row changed, and no test-pinned text changed.
- **Correction-56, the family namespace in M1, the k8s registrations of M1-162 to M1-165, and the
  autoscaler status ConfigMap.** From the reviews of the M1-175 build and the M1-113 k8s review.
  Correction-49 is PR #85. `rdy run` has no source for the Kubernetes family namespace in M1: rdy/v1 has
  no `k8s:` block (03's "Spec block" was never in 01), 07 puts `--namespace` on `rdy bundle` only, and the
  client never uses the kubeconfig's namespace (ADR 0031 decision 12). So k8s.storageclass never reads
  claim evidence, k8s.ingress and k8s.cni read no Service or NetworkPolicy of the install namespace, and
  k8s.admission and k8s.namespace fall back to the entry's own `namespace`. M1 adds no key and no flag.
  03 says what M1 does in a "Not in M1" note under the Spec block and in the k8s.storageclass,
  k8s.admission and k8s.namespace sections; its flag sentence now names `--kubeconfig` and
  `--kube-context` (correction-07 asked for it); 07's kube flag row says `rdy run` has no `--namespace`.
  The k8s.admission line also loses a wrong grant: a spec with no namespace is partial with a fix, not
  `get namespaces`. ADR 0049 (Proposed) chooses the M2 source: a top-level `k8s:` block with one key,
  `namespace`, and no run flag, because the namespace decides what the checks judge and M2-126 pins reads
  to the namespaces the spec names. New M2-142 (3 h) builds it, with cli-ux and security review. M1-162 to
  M1-165 now register their check in the family (M1-175's `build_check` arm, registry info, family test
  counts) if M1-175 merges first, as M1-175's progress line defers. New M2-143 (3 h): k8s.nodes reads
  `kube-system/cluster-autoscaler-status` by name, so GKE Standard and AKS managed autoscalers soften a
  node shortfall; one guarded GET, a cut-down type, the 03 grant text, the role, the kind job, a new ADR
  (ADR 0043 decision 4) and a security review. No M1 hours change. No 03 `###` heading or Appendix A row
  changed, and no test-pinned text changed.
- **Correction-57, the k8s.nodes pod list returns with M1-159, the Kubernetes page API reads, and two M2
  tickets.** From the M1-115 k8s checks review (`docs/plan/reviews/k8s-checks-review.md`, on the M1-115
  branch) and its code review, and from the M1-116 review. Correction-49 is PR #85. The `v1` `pods`
  `ALLOWED` entry cites k8s.nodes, but only the free capacity half reads pods, and that is M1-159, so no
  fixture read the pair and 0.1.0 would grant `list pods` for nothing (SF-01). M1-115 (approved, not
  merged) removes the entry, the `pods` rule in `examples/rbac/rdy-readonly.yaml`, the pod reads of
  `live_cluster.rs` and the guard's pod selector tests, and words 03's k8s.nodes Needs line and 02
  Appendix B's `pods` row to say the Pod list arrives with M1-159. M1-159's row now adds all of it back,
  with a fixture that reads the (`pods`, k8s.nodes) pair and the kind workflow green, and depends on
  M1-115. It keeps its 1.5 h. Main still has the entry, the rule and the 03 text, so 02 and 03 do not
  change here. New M2-144 (1 h) scopes k8s.version's three `v1beta1` removed-API rows to the kinds
  removed in 1.22 (SF-03). New M2-145 (1 h) adds AKS `managed-csi` and a vSphere or Longhorn class
  fixture to k8s.storageclass (SF-04). The review's folds onto M2-125 (SF-06) and M2-126 (SF-05) are
  already in those rows, so they are not filed. M1-116's row now says the Kubernetes page gives each check
  an API reads line from the guard's `ALLOWED` table, with a test. SF-02: PRs #62, #64, #65 and #78 add
  duplicate `ALLOWED` entries and #62 and #78 both add `Access::GetIn`, so M1-115's one-entry-per-resource
  guard test fails once they land. Each of M1-162 to M1-165, if M1-115 merged first, now folds its entries
  into those on main, adds `Access::GetIn` only if no earlier PR did, and copies the pair test, +0.5 h
  each. #62 also extends the `pods` entry that M1-115 removes, so the first of M1-159 and M1-162 to merge
  adds the entry, the role rule and the live read citing only its own check, and the second adds its id.
  Weeks 29 and 30 go to 13.5 h. No 03 `###` heading or Appendix A row changed, and no test-pinned text changed.
