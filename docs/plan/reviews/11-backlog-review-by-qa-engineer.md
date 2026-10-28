# Review of 11-backlog.md by qa-engineer

Reviewer: qa-engineer (did not write the backlog). Date: 2026-10-28. Reviewed: `docs/plan/11-backlog.md`
(M1 rows, calendar, weekly ship list, "How to work the backlog"), against `08-testing.md`,
`03-check-catalog.md`, `07-cli-ux.md` section 4.2 and `KICKOFF.md`. I checked the table mechanically:
235 M1 rows, 571 h, 438 core h (matches the totals), no unknown ids, no forward-id dependencies, and no
ticket depends on a ticket the calendar puts in a later week.

## Verdict

**Approve with changes.** The structure is sound and the 08 tickets are all there. Nine items must be
fixed before M1-001 starts, because an exit test cannot run when its week comes, or a promised artifact has
no test behind it. Most fixes are one-line edits to deps or exit tests. Three small tickets are added
(about 7 h).

Must-fix: **9**. Should-fix: **13**. Nit: **9**.

## Must fix

**MF-1. M1-094, M1-103, M1-107, M1-109 (weeks 19 to 21): the golden and env tickets need environments that
do not exist until week 31.**
M1-094 says "one test per env" in week 19. The first env is M1-150 in week 31, and it needs host.memory,
net.egress and k8s.version. M1-103 (week 20) promises goldens for "the ready, warning and not-ready runs"
and the week-20 ship line says they pass on five legs. M1-107 (week 21) promises 07 B.1 to B.3 byte for
byte. None of them depends on an env or on M1-075. As written they are vacuous or cannot pass.
Fix:
- 07 section 4.2 already says B.1 to B.3 are fixtures under `tests/fixtures/results/`, and M1-029
  round-trips the 01 samples 7.2 to 7.4. Make those result files the input of M1-103 and M1-107. Exit
  test for M1-103: "`render_html` and `write_json` on the three result fixtures produce goldens that
  pass the static checks on five legs." Exit test for M1-107: "the terminal renderer on the three result
  fixtures equals C.17, C.18 and 2.7 byte for byte at width 100."
- M1-094 ships with one tiny env `host-min` (host.memory only, `os-release`, `meminfo`, a spec). Its exit
  test becomes: "`host-min` gives exit 0, `report.json`, `terminal.txt` and equal reports at jobs 1 and 8
  on five legs; adding an env directory adds a test with no code change."
- Add M1-075 to the deps of M1-095 and M1-107. The env goldens of M1-150 to M1-152 then become the
  second layer and keep their own exit tests.

**MF-2. M1-109 and M1-180: `assert_cmd` cannot run the ready, warning and not-ready rows, and nothing
ticketed runs the five-target exit-code proof.**
08 rule 4 says the shipped binary has no fixture backend, and `assert_cmd` is Live only. M1-109 says
"Assert_cmd runs one fixture per row (ready, warnings, not ready...)". M1-180 then requires, on all five
targets, `rdy run` on a signed fixture spec exiting 0, 1 and 2, an unsigned spec 64, and a tampered spec
64. No ticket builds that test. 08's real-OS smoke is M2.
Fix:
- M1-109: keep only the rows that need no fixture backend (bad flag 64, missing file 64, unwritable
  `--out-dir` 70, unsigned 64 once M1-162 lands). Drop the 0, 1 and 2 rows: M1-094 and M1-150 to M1-152
  already assert them in process. Estimate 2 h to 1 h.
- New ticket, qa-engineer, 3 h, depends on M1-162 and M1-121: "Real-binary smoke on five legs". The test
  binds a loopback listener on port 0 and writes three signed specs at test time (net.egress to the open
  port gives 0, a `severity: warn` check on a closed port gives 1, a `severity: block` check on a closed
  port gives 2), then runs the shipped `rdy` with the Live backend. Net checks only, so macOS and Windows
  work. Also: unsigned gives 64, a spec with one byte flipped gives 64 even with `--allow-unsigned`. Add
  it to the deps of M1-180 and make it the exit test M1-180 quotes.

**MF-3. M1-174, M1-175, M1-177: README transcripts are either nondeterministic or break rule 4.**
M1-174 starts a real refusing proxy and a fake kube API and runs `rdy run` twice for "stable output". On
a live runner the host checks print real memory, disk and kernel values, so the output differs per
machine. If the intent is Replay, then it is not a lab of real servers. M1-175 says "reproduce byte for
byte from fixtures". M1-177 runs fenced commands "against the build" and matches output.
Fix: split by what is being proved.
- Transcripts (M1-175, M1-176) are goldens made in process from a Replay env (use `all-pass`, `all-block`
  and the unsigned variants; add `quickstart` to `answers` if needed). The README block is compared with
  the golden file, not with a live run. Exit test: "each README transcript block equals its golden file."
- M1-174 is dropped, or reduced to 1 h: a doc note that says the transcripts come from Replay.
- M1-177 runs commands live and asserts only the exit code set and shape (a regex per block, for example
  `^NOT READY`), never host numbers.

**MF-4. No ticket builds the root, strace and sudo job in `ci.yml`.**
M1-056 (strace, zero `socket(2)`, week 11), M1-158 (root run under strace, week 32), M1-183 (`unshare -n`
plus strace), and the root parts of M1-052 and M1-061 all need the linux-x64 job from 08 section 6: a
prebuilt nextest archive run under `sudo` with `root_*` filters, with `strace` installed. M1-007 does not
mention it. M1-056 will land with an exit test that CI cannot run.
Fix: new ticket, release-engineer with qa-engineer, 2 h, before M1-056: "linux-x64 root job:
nextest archive under sudo, `root_*` filter, strace installed". Exit test: a planted `root_whoami_is_zero`
test passes under it, the same test is not run by the normal job, and `strace -V` prints in the log. Add it
to the deps of M1-056, M1-158 and M1-183.

**MF-5. M1-104: alpha.1 cannot write a result file.**
The exit test says `results/0.1.0-alpha.N/` and 08 says start at `0.1.0-alpha.1`. In this calendar
alpha.1 (week 3) is a version-only binary. The first tag that writes a result is alpha.9 (week 11). The
M1-104 dependency on M1-016 (alpha.1) also points at the wrong tag.
Fix: depend on M1-103 only. Exit test: "`tests/fixtures/results/0.1.0-alpha.18/report.json`, produced by
that tag's binary running the `host-min` spec, parses with the current rdy-engine on five legs; a changed
byte in an older version directory fails the lint (compared with `main`)." Add a step to RELEASING.md:
each tag from alpha.18 adds its directory.

**MF-6. M1-098 (core): the exit test needs a headless browser job that is a later non-core ticket.**
"A headless render with dark preferred and print media has text contrast of at least 4.5 to 1" needs the
job in M1-197 (non-core, week 38). 10's rule says a ticket a core ticket depends on is core. 08 itself
moved the browser render to M2.
Fix: replace with a static test. Exit test: "a template grep finds no raw JSON key as visible text, and the
M1-100 contrast script passes on the print and dark-preferred token sets." M1-197 and M1-198 stay
non-core.

**MF-7. M1-195: parser property tests are demoted to non-core and cannot test what they promise.**
CLAUDE.md names proptest for the spec parser as an engineering standard, and 08 kept it inside the 32 h.
The backlog marks it `core: no` (week 38), so `v0.1.0` ships a parser that takes untrusted files with
only example fixtures. The first row of the 08 section 4 table that is hard to fake, "verify before parse",
needs M1-155, but the ticket depends on M1-024 only.
Fix: `core: yes`, schedule it after M1-037 (about week 8), and split the signature row into the exit test of
M1-155: "changing any byte of the signed fixture gives a SignatureError and the parser spy count stays 0,
proptest 256 cases". Exit test for M1-195 otherwise as written. Net core change: +3 h.

**MF-8. M1-073 lost the completeness gate.**
08 section 8 calls the fixture-completeness rule "the number that does gate". The 08 exit test had "a
missing `checks/_policy/symlink-to-shadow` fails". The backlog dropped it, and nothing ticketed creates
that case. The rule "a registered, implemented check with no `checks/<id>/`, or without a passing case, a
non-passing case, a no-privilege partial case where a root-optional need exists, and a Timeout case where
it runs a command or opens a socket, fails" is in no exit test, so the check tickets can merge with thin
fixtures.
Fix: M1-073 exit test adds: "deleting `checks/_policy/symlink-to-shadow`, or the pass case of
`checks/host.memory`, or the Timeout case of `checks/host.disk` each fails the lint with the path
named." Add M1-051 (registry) to its deps. M1-072 creates the `_policy/symlink-to-shadow` case.

**MF-9. Week 36 and M1-180 name a test that a trim would drop.**
Week 36's "How to check" says "the strace contact-set test is green". That is M1-183 (SEC-22),
`core: no`, and M1-180 does not depend on it. The "How to work" rule says never trim "0.1.0 gate" security
tickets, and the weekly list says SEC-22, SEC-24 and SEC-31 are closed at the tag, while the core note
says those come "by 0.1.1".
Fix: pick one. Recommended: M1-183 `core: yes`, depends on the new smoke ticket (MF-2) and the root job
(MF-4), and is added to M1-180's deps. SEC-24 and SEC-31 stay non-core and leave the week-36 line.

## Should fix

**SF-1. Check tickets do not depend on the 08 loader, lint or helpers (requirement 2).**
M1-089, M1-091, M1-092, M1-206, M1-207, M1-210 and M1-222 depend on M1-070, which is the older fixture
format. M1-088 and M1-090 depend on M1-084 (which depends on M1-069). None depends on M1-072 (08 format),
M1-073 (lint) or M1-074 (`run_fixture`, `assert_within_manifest`). Most exit tests do carry cases in the
text, so no check ticket is fixture-less, but they will be written against the wrong format.
Fix: add M1-072 and M1-074 to M1-088 and replace M1-070 with M1-072 in the seven above. Add one sentence to
"How to work": every check ticket meets 08 Appendix E, and its exit test is read as "plus the Appendix E
minimum cases". The kube checks M1-141 to M1-146 and M1-225 to M1-233 get M1-072 too.

**SF-2. Report tickets without a golden-test dependency (requirement 2).**
M1-043, M1-044, M1-046, M1-095, M1-099, M1-100, M1-101, M1-102, M1-105, M1-107, M1-194 and M1-196 all say
golden or snapshot. Only M1-103 and M1-075 are golden tickets, and M1-103 depends on M1-096 (it comes after
the HTML tickets). Fix: add M1-075 to M1-043, M1-044, M1-046, M1-095 and M1-105. The rest inherit it
through M1-095 and M1-107. After MF-1, M1-103 is the layer that makes the three goldens a five-leg gate.

**SF-3. Redaction tickets and the corpus gate.**
M1-081 (30 cases) is a dependency of M1-180, which is right. But M1-078, M1-079 and M1-080 (wiring) do not
depend on it, and M1-077 quotes "the 23 positive corpus inputs" before the corpus exists.
Fix: M1-077 creates the 23 positives under `tests/fixtures/redaction/`. M1-081 adds negatives and brings it
to 30, and becomes a dependency of M1-078 to M1-080 so the corpus runs on every wiring PR. Also add the
08 rule to M1-081: "`UPDATE_GOLDENS=1` leaves `tests/fixtures/redaction/**` untouched" is in M1-075 only.

**SF-4. Duplicates (requirement 3).** All 13 qa-engineer tickets from 08 appear exactly once (M1-018, 071,
073, 074, 075, 094, 103, 104, 150, 151, 152, 195, and 081 plus 178). The rust-engineer 08 tickets appear as
M1-072 and M1-093. The compat page is M1-153. The overlaps are:

| Remove or fold | Hours | Why |
| --- | --- | --- |
| M1-219 musl resolver fixture (qa) | -2.0 | 08's correction moves it into the net.dns ticket. Fold the `sss` warning clause into M1-220 (+0.5 h on that ticket). |
| M1-070 placeholder and "Windows-safe command names" clause | -1.0 | 08 indexes command and api files by content with free slugs, so Windows-safe names are moot. Placeholder comparison is M1-074 and M1-075. Re-estimate M1-070 at 1 h. |
| M1-109 rows 0, 1 and 2 | -1.0 | Covered in process by M1-094 and M1-150 to M1-152 (see MF-2). |
| M1-102 versus M1-103 static href and src checks | -0.5 | Same property tested twice. M1-102 owns structure. M1-103 owns CSP, no `<link>` or `url(`, no `\|safe` and the round trip. |
| M1-174 | -1.0 to -2.0 | See MF-3. |

Total about 5.5 to 6.5 h removed. Not duplicates, despite similar names: M1-069 and M1-072 (engine Replay
versus the 08 format), M1-018 and M1-013 (CI profile versus PR template).

**SF-5. M1-013 (PR template) should be core.** 08 section 9 and Appendix E live in
`.github/pull_request_template.md`, and the "## Golden changes" and "Compat matrix: unchanged because"
rules are enforced by hand through that template in M1. It is 1 h, scheduled in week 2, and nothing core
works without it. Mark `core: yes`.

**SF-6. pty tests have no shared helper and no Windows rule.**
M1-063, M1-108, M1-160 and M1-200 each need a pty. 08 forbids sleeps and wall-clock bounds, and the
Windows leg has no Unix pty. Fix: new ticket, qa-engineer, 2 h, before M1-063: "pty test helper (Unix only):
spawn, read-until-pattern with a 10 s upper bound, no sleeps." The four exit tests add "Unix legs; Windows
asserts the non-TTY branch." Check that the helper crate passes `cargo deny` (M1-005).

**SF-7. Weekly ship list: artifacts without a named test (requirement 5).** Most lines name a command.
These need a test name or are wrong:

| Week | Problem | Replacement |
| --- | --- | --- |
| 12 | "action log lists every command" has no test | "`action_log_lists_commands` (M1-059) passes on five legs." |
| 13 | "`sudo` and setuid launches are refused" is wrong. Running under `sudo` is allowed (real, effective and saved ids all 0). Only an id mismatch is refused (INV-10, unit test with injected ids) | "The injected-id refusal test exits 70; a pty Ctrl-C test exits 70 and leaves no folder (Unix legs)." |
| 17 | "`rdy run` on a fixture spec" implies the shipped binary reads fixtures | "The in-process `host-min` test shows host.memory PASS with the nominal-band note." |
| 18 | "On a Linux VM the five host checks give real results" is manual | "The Live smoke on linux-x64 shows host checks not skipped" (from MF-2), plus the founder's VM run as extra. |
| 20 and 21 | See MF-1 | Result-fixture goldens. |
| 22 | "docs.getrdy.io loads" | "docs-build job green and `curl -fsS https://docs.getrdy.io/ -o /dev/null` returns 0." |
| 27 | "run header shows kube context before the first request" | Name the M1-134 test (mock records no request before the header). |
| 36 | strace test (MF-9) | Keep, once M1-183 is core. |

**SF-8. M1-151 and M1-152 stories use non-core checks.** The 08 `no-privileges` story needs "audit log
unreadable", which is host.lsm (M1-206, non-core). The `timeouts` story has "commands with `delay_ms`", and
no core check runs a command. Fix: no-privileges uses the root-optional need of host.ports (owner unknown)
and a missing kubeconfig; the audit-log case moves to M1-206. Timeouts env uses the hung `statvfs`, the
black-hole endpoint and the slow `/version`; command timeouts stay with M1-057 and `FakeCheck`.
Also add M1-089, M1-091, M1-129, M1-130, M1-143, M1-144 to the deps of M1-151, since all-block needs them.

**SF-9. M1-121 does not say where the servers live.** 08 and its corrections put them behind a non-default
`test-support` feature of `rdy-checks-net`, with `serve: <name>` factories registered on the Replay
builder. Add to the exit test: "the release feature tree (`cargo tree -e features -p rdy`) does not contain
`test-support`; a `net.json` entry `serve: tls-private-ca` starts the factory."

**SF-10. M1-075 and xtask.** The exit test uses `cargo xtask goldens check` but the ticket does not depend
on M1-033 (xtask skeleton) and does not say that `ci.yml` runs it after nextest on linux-x64. Add both.

**SF-11. Core tickets that cannot run when scheduled.**
- M1-021 (week 3): "decodes through `parse_unverified`" needs M1-024 (week 4). Move that clause to M1-024
  or M1-031.
- M1-031 (core) validates every file in `examples/specs`; the alignment of `gpu.device_plugin` and the
  selinux field in the other four examples is M1-192, non-core, week 37. Move the rename (0.5 h) into
  M1-031, or state the expected lint status per file.
- M1-170, M1-171 and M1-173 say their commands "run as M1 integration test cases". The runner is M1-177,
  which depends on them. Rewrite: "every command carries the `testable` marker; M1-177 runs them."

**SF-12. "How to work the backlog" versus KICKOFF (requirement 6).** The KICKOFF review rules are present
and correct. Gaps:
- KICKOFF says `qa-engineer` adds or updates fixtures and goldens on each ticket. The section keeps the
  sentence, but check tickets are owned by check-author with their own fixtures, and qa-engineer hours
  appear only on 24 infrastructure tickets. State who does it: check-author writes the cases (Appendix E),
  and qa-engineer reviews fixtures and goldens on every PR that touches `tests/fixtures/**` or a golden.
- KICKOFF says `security-reviewer` reviews each ticket that touches network, privileges, redaction, signing
  or the install script. The table has batch reviews (M1-082, M1-132, M1-168). Say they add to, and do not
  replace, the per-PR review for M1-121 to M1-131, M1-135 to M1-138, M1-076 to M1-080, M1-155 to M1-166
  and M1-022 to M1-023.
- Add the 08 PR rules: `## Golden changes` section, `Compat matrix: unchanged because <reason>` line,
  code-reviewer reads the golden diff first, and Appendix E in the template.
- "docs-writer updates docs in the same PR": the table has separate docs tickets (M1-120, M1-133, M1-148).
  Say that reference pages are updated in the same PR by `cargo xtask docs --check` (required through
  ci-ok), and that the family intro pages are separate tickets by design.
- Domain reviewers from CLAUDE.md (k8s-expert for the k8s checks) are only in M1-147, at the end. Fine for
  M1, but say so.

**SF-13. qa-engineer hours (requirement 7).** M1 qa-engineer total is **53 h** (36.5 core) against the
**32 h** 08 settled on. The gap is explained, not an error:

| Item | Hours |
| --- | --- |
| 08's 13 tickets, all present once | 32.0 |
| minus M1-195 and M1-178 marked non-core | -4.5 |
| plus README transcripts and docs-test (M1-174 to M1-177, from 10) | +9.0 |
| core total | 36.5 |
| plus non-core add-backs: M1-183 (2), M1-227 (1), M1-234 (2), M1-197 (3), M1-198 (1), M1-193 (1), M1-219 (2) | +12.0 |
| total | 53.0 |

If this review's changes are applied: -6 h from SF-4, +3 h smoke (MF-2), +2 h pty helper (SF-6), +3 h
property tests back to core (MF-7), +2 h SEC-22 to core (MF-9): core becomes about 44 h, total about 52 h.
The 32 h figure covers infrastructure only. It does not budget qa review of fixtures and goldens on the
roughly 60 core PRs that touch them. At 0.25 h each that is about 15 h of founder review time. Either
state that check and facade estimates include it (recommended, one sentence in "How to work"), or add it.

## Nit

- **N1. M1-001, M1-002, M1-066, M1-082, M1-132, M1-147, M1-168 (review tickets):** "marked closed", "uses
  the words", "review signed off", "written review with every finding fixed or filed" are checked by
  reading. Make each checkable with a grep. Example for M1-168: "`docs/plan/reviews/signing-review.md` has
  no row with status `open`, and M1-180 greps for it." For M1-002: "`cargo xtask docs-lint` finds the five
  verdict words of ADR 0002 in 07."
- **N2. M1-055:** "07-cli-ux.md confirms the headline, the Ctrl-C message, the flags". Replace with: "the
  M1-039 help snapshot and the M1-063 stderr golden contain the same five strings that 07 quotes."
- **N3. M1-011:** "the founder published them by hand and deleted the token" is not observable. Replace with
  a script exit test: `scripts/check-crates.sh` loops over the ten names, calls the crates.io API, and
  exits non-zero unless each has version 0.0.1 and the getrdy-io owner.
- **N4. M1-095:** "passes an HTML validator" names no tool. Replace with: "the golden HTML passes the 08
  section 3 static checks (CSP meta, `lang`, `color-scheme`) in a Rust test." The validator is not needed
  in M1.
- **N5. M1-185, M1-187, M1-188, M1-181, M1-186:** settings and emails. Use `gh api` for the checkable ones
  (`gh api repos/getrdy-io/rdy --jq '.has_discussions'`, the community profile for CODE_OF_CONDUCT and
  SECURITY). M1-181: add the sent date and recipient count to the Done log line. M1-186 stays a human
  timing test.
- **N6. M1-180 deps:** add M1-153 (compat page), M1-169 (exit codes page), M1-018, and the new smoke and
  root-job tickets. Its exit test quotes "every 0.1.0-gate security ticket is closed"; list the ids.
- **N7. M1-073 deps:** add M1-051 (registry), see MF-8. M1-071 deps are right. Move its removed clause
  ("verifies the signed spec, digests match") into M1-155, which creates the signed fixture, and add
  "`git check-attr text` is `unset` for `tests/fixtures/signed/*`" there.
- **N8. M1-063 and M1-200:** the exit tests say "pty" with no Unix gate (see SF-6).
- **N9. Windows-only legs:** M1-053, M1-158 and M1-205 have Windows-only exit tests. The "How to work"
  section should say a Windows-only test is `#[cfg(windows)]` and the other four legs must still be green
  (08 section 6).

## Checks that passed

- (1) Exit tests: of the 235 M1 rows, about 205 are a command, a golden, a CI job or a fixture run. The
  vague ones are the 20 or so listed in MF-1, MF-3, MF-6, SF-11 and N1 to N5.
- (4) Fixture environments for M1 checks: all five M1 envs (08) are ticketed as M1-094, M1-150, M1-151 and
  M1-152. The loopback servers (M1-121), kube mock (M1-137), SNTP and DNS responders (inside M1-209 and
  M1-220), registry mock (inside M1-221), fake exec plugin (M1-138) and Docker socket stream (M1-204,
  M1-211) are all ticketed. Nothing is counted twice. M2-only items now in M1 are all `core: no` and
  explained in the reconciliation list: M1-183, M1-197, M1-198, M1-202, M1-204, M1-205, M1-227, M1-234.
  They should be re-checked against the founder's hour count, but they do not break the core path.
- (6) Review rules: present, with the gaps in SF-12.
- Calendar versus dependencies: no ticket is scheduled before one of its dependencies.
