# Review of 13-plan-corrections.md by code-reviewer

Reviewer: code-reviewer, cold. I did not write 13. Date: 2026-10-28. Read against `CLAUDE.md`, `KICKOFF.md`,
`docs/plan/rdy-plan.md` (the plan), the founder decision of 2026-10-28 (M1 is extended, not cut), and the
"Plan corrections found" sections of all of 00 to 10, `docs/adr/README.md` and the review files that have one.
Line numbers are for 13 unless a file is named.

## Summary

The where and what of PC-01 to PC-40 hold up. I checked each one against its cited line. Coverage is good: I
read the corrections section of every document 00 to 10 and found no plan, `CLAUDE.md` or `KICKOFF.md` item
that 13 dropped. The 00 claim that `CLAUDE.md` "founder context" says "M1 is six weeks" is false, and 13 was
right to drop it. The ticket counts and hours in the decision 1 table match the files. The dates are right
(Nov 20, 2026 is a Friday, Nov 23 a Monday, 19 weeks from Nov 23 is early April 2027).

Three entries now contradict the founder's decision. The same decision also changes the calendar math that
13 reports. Some severities break the file's own definitions. One process note is false.

House rules: 13 is pure ASCII, so it has no em or en dashes. It names no competitor. PC-35 and PC-40 use
category descriptors and do not name the investors. I found no candidate for the old working name. A full
check needs the denylist kept outside the repo.

## Findings

### Must fix

1. **Decisions section, decision 1 (lines 69 to 111).** It is still written as open. "Taken until you
   decide: the M1-late tier moves to M2" (line 110) and the table row "M1-late tier 72, moved to M2"
   (line 77) contradict the founder's decision: "do not drop M1 scope to fit six weeks". The options list
   (lines 102 to 108) offers "Smaller M1", which the founder rejected.
   Fix: add a short `## Decisions made` section above the open list, and renumber the open decisions. Entry:
   "1. M1 length (2026-10-28). M1 is extended, not cut. It is planned at its real size, at 10 to 15 founder
   hours a week, and starts after the Nov 20, 2026 go or no-go. Every document's cut list stays as a `core`
   marker (the six-week minimum) so you can still trim. The M1-late tier stays in M1 and is marked non-core.
   A usable binary still ships every week." Keep the hours tables as background. Fix the calendar sentence
   too (lines 96 to 100). With M1-late kept, the merged upper bound is about 570 to 580 hours: about 44 weeks
   at 13 hours (late September 2027), or 39 weeks if the M1-late tier is trimmed. The pre-merge per-slice sum
   the founder saw was about 250 hours, about 19 weeks (early April 2027). State the range plainly, so the
   founder knows the decision may cost 19 to 44 weeks until `11-backlog.md` sets the real number.

2. **PC-02 (line 25), proposed fix.** "State M1 at its real length, or cut M1 scope, once the founder
   decides" is stale. Fix: "Decision made: M1 is extended (see Decisions made). `KICKOFF.md` constraints:
   replace 'M1 is six weeks' with 'M1 runs at its real size from `11-backlog.md`, starting after a recorded go
   on Nov 20, 2026; tickets marked `core` are the six-week minimum.' Plan line 141: replace 'about 12 weeks'
   with the backlog figure. Plan line 198: retitle 'Build order inside M1'." Leave the `KICKOFF.md` scope
   list as it is. PC-25 deals with that separately.

3. **PC-19 (line 42).** Its fix, "Move the M1-late tier to M2 in `11-backlog.md`", is now the opposite of
   the decision. Its count is also wrong. 03 has 24 M1-late tickets, not 25 (03 lines 785 to 812; host 11,
   net 6, k8s 7), at exactly 72 hours (03 line 24). Decision 1 at line 86 already says 24. Fix: "Keep the
   M1-late tier in M1, marked non-core in `11-backlog.md`. In the `CLAUDE.md` layout, add nothing about
   tiers. `CLAUDE.md` is now correct that admission and device plugins are M1 work." Then downgrade it to
   cosmetic, or delete it and leave the tier marking to the backlog. Raised by: 00, 03, rv03-k8s.

### Should fix

4. **Severities break the file's own definition (lines 13 to 16).** "Should fix before M1" means "an M1
   ticket touches it". These five are graded cosmetic, but an M1 ticket touches each one:
   - PC-28: the zigbuild and `dist` naming. The 06 release tickets in week 1 use it.
   - PC-29: the workflow list. M1 tickets create `sign-release.yml`, `docs-deploy.yml` and `CHANGELOG.md`.
   - PC-30: the docs content root. The M1 docs tickets from PC-25 touch it.
   - PC-27: the `k8s.device_plugins` home. Its ticket stays in M1 now (03 line 812).
   - PC-38: the version policy. The `0.1.0-alpha.N` tags start in week 1 (06 line 172).

   Fix: regrade all five to "should fix before M1". Split PC-28 if you want, since `self_update` (M3) can
   stay cosmetic.

5. **PC-20 (line 43).** "`x86_64-apple-darwin` is built and smoke-tested only" contradicts 06. In the 06 CI
   table (06 lines 62 to 68 and 200), `macos-15-intel` runs the full test job. Build-only on arm64 is just
   the fallback "if it is slow or dies" (06 line 73). The text came from 00 line 35, which is stale. Fix:
   "Five release targets and five CI legs, each running the full test job. If the Intel macOS image is
   retired, `x86_64-apple-darwin` is built on the arm64 runner and tested nightly (06)."

6. **Process note 3 (line 179) is not accurate.** "The founder added two repo-wide rules during the pass:
   the old working name must appear nowhere, and no competitor..." The old-name rule was already in
   `CLAUDE.md` at bootstrap: `git show 590f84c:CLAUDE.md`, line 41. Only the competitor rule was new. It came
   on 2026-10-27, in commits `ad72266` (rule) and `d6184c9` (plan scrub). Fix: "The founder added one
   repo-wide rule during the pass (2026-10-27): no competitor company or product may be named anywhere in the
   repo. The old-name rule was already in `CLAUDE.md`." Keep the rest of the note. It matches `d6184c9`.

7. **PC-14 (line 37) and PC-16 (line 39) partly duplicate each other.** Both rewrite plan line 88, and
   neither gives the final line. A founder who applies them one after the other gets two edits. Fix: give
   the final text once, in PC-16, and have PC-14 point to it. For example, M1 docs say "download the pinned
   release `install.sh` (06), then `"$HOME/.local/bin/rdy" run acme-platform.yaml`". From M2 the line is
   `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh && "$HOME/.local/bin/rdy" run
   acme-platform`, with the token from `RDY_TOKEN` or a prompt.

8. **PC-03 (line 26) leaves out a location.** Plan line 171 ("Design rules") has the same text: "The CLI
   refuses unsigned or tampered specs unless `--allow-unsigned` is set." Fix: add "plan, Design rules, third
   bullet" to "where", with the same fix.

9. **PC-23 (line 46) leaves out the plan.** The same placement errors are in the plan's crate table, line 154
   (`rdy-engine`: "result model") and line 160 (`rdy-bundle`: "Collect, redact"). They are also in the plan's
   public repo layout, line 397 ("result model") and line 399 ("collect, redact, compress"). Fix: add both
   plan locations to "where", with the same fix.

10. **PC-25 (line 48) leaves out `KICKOFF.md`.** `KICKOFF.md` lines 47 to 49 say M1 "contains only workspace
    plus CI, ... and signing. Anything else is M2 or later." That shuts out the M1 docs site this entry
    adds, and the M1 security and devrel tickets. Fix: add `KICKOFF.md` constraints to "where". Change "Anything
    else is M2 or later" to "plus the minimum docs, security and release work those need; anything else is
    M2 or later". Or fold this into PC-06, which edits the same sentence.

11. **PC-17 (line 40).** The fix labels the plan sample "not runnable in M1". Two 00 tickets use that
    sample as M1 test input: "Define public spec types" (00 line 443) and "Unknown check ids report Skipped"
    (00 line 452). Fix: add "Re-point both tickets to `examples/specs/acme-platform.yaml` in `11-backlog.md`."

12. **Decision 2 (lines 113 to 119).** The founder's decision on M1 already says M1 starts "after the Nov 20,
    2026 go or no-go". Fix: keep decision 2 open, as asked, but add one line. "The 2026-10-28 M1 decision
    assumes a start after a go on Nov 20. Confirm, and this decision moves to Decisions made." PC-01's "see
    decision 2" stays.

13. **No "Tickets implied" section.** The common brief says every document ends with one. Fix: add
    `## Tickets implied` with at least
    `- [M1] Apply blocks-M1 and should-fix plan corrections to CLAUDE.md, KICKOFF.md and rdy-plan.md | owner: rust-architect | est: 3h | depends on: none | exit test: every blocks-M1 and should-fix entry is applied or rejected, and its row is deleted from 13.`

### Nits

14. **Missing entry.** Plan line 354 ("Still to do: ... GitHub org") contradicts plan line 378 ("GitHub org
    | getrdy-io | Owned"). Fix: add a cosmetic entry. Drop "GitHub org" from line 354.

15. **PC-28 (line 51) leaves out a location.** `KICKOFF.md` line 31 says "cargo-dist config". Fix: add it,
    with the new wording "dist config (`dist-workspace.toml`)".

16. **PC-06 (line 29).** It says release signing lands in "weeks 1 to 3". 06 line 305 says "weeks 1 to 2".
    Fix: use 06's figure, or cite where 3 comes from.

17. **Decision 1 merge figure (lines 96 to 97).** I merged the M1 lines by exact title and got 231 distinct
    tickets and 579 hours (298 lines in total). 13 says 226 and about 570. Fix: say how titles were matched,
    or round to "about 230 tickets and 570 to 580 hours".

18. **PC-16 (line 39).** "What is wrong" lists the missing `-L`, but the fix does not add it. It relies on
    PC-15's "200, never a redirect". Fix: say so: "`-L` is not added; the endpoint serves 200 and the 09
    verify job asserts it."

19. **PC-35 (line 58).** "Kubernetes-only" appears at plan lines 9, 28, 213 and 283. "The incumbent
    Kubernetes-only preflight tool" is also the descriptor the common brief prescribes. Fix: list all four
    lines. Note that changing the descriptor means a repo-wide sweep, and the brief needs the same edit.

20. **PC-36 (line 59).** Plan line 22 already says "(2022 study, vendor-reported)", and line 294 already
    says "with its source". Fix: narrow the entry to "add the year at line 294; keep it out of the HN post".

21. **PC-17, nominal band.** 03 line 43 applies the band by default, so `min: 32Gi` does not block a
    31.3 GiB VM. Fix: reword to "the sample should mention that a nominal band applies by default".

22. **PC-18 (line 41).** It picks M4 for data stores, while 03 (the catalog owner) says M3. Fix: give the
    reason, for example "M3 already carries AWS, billing and launch", or mark it for check-author to confirm.

23. **PC-40 (line 63).** The repo goes public (PC-05), and the investor names identify the company. Fix:
    regrade to should fix before the repo is created. Consider "a BYOC deployment platform raised a large
    round" at plan lines 9, 30 and 128, since the exact figure also identifies it.

24. **Light overlaps.** PC-08 and PC-38 both define `0.1.0-alpha.N`. PC-28 and PC-29 both edit the
    `release.yml (cargo-dist)` line. PC-19 and PC-27 both cover where `k8s.device_plugins` lives. Fix: add
    "see PC-nn" cross-references so the founder edits each line once.

25. **Process note 4 (line 185)** repeats PC-05 and decision 3. Fix: delete it.

## Verdict

Request changes. 3 must fix (findings 1 to 3), all caused by the founder's M1 decision, plus 10 should fix.
The entries are accurate and well deduplicated, and coverage of 00 to 10 is complete. Once the decision
section and PC-02 and PC-19 match the decision, this is approve with nits.
