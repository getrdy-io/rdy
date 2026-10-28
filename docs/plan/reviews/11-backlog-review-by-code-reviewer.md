# Review of 11-backlog.md, 00-overview.md and 13-plan-corrections.md by code-reviewer

Reviewer: code-reviewer (cold, did not write these files). Date: 2026-10-28.
Reviewed: `docs/plan/11-backlog.md` (rust-architect), plus the re-synced `docs/plan/00-overview.md` and
`docs/plan/13-plan-corrections.md`. Checked against `CLAUDE.md`, `KICKOFF.md` item 12, the plan's milestone
table and build order, ADR 0005 and the founder decision of 2026-10-28.

Method: the backlog table was parsed by a script. Totals, the calendar, the dependency graph and every
number below come from that parse, not from reading. The ledger behind this review sets one action per
ticket: duplicate, padding, move, or keep.

## Summary

| Item | Tickets | Hours | Core hours |
| --- | --- | --- | --- |
| M1 as written | 235 | 571 | 438 |
| Removed as duplicates (merged into the ticket that already does the work) | 44 rows touched | 49 | 42 |
| Removed as padding (same ticket, honest estimate) | 123 rows touched | 99 | 78 |
| Moved out as speculative for M1 (27 h to M2, 31.5 h to M3, 4 h to M4) | 27 | 62.5 | 22.5 |
| M1-184 kept at 0.5 h and made core (the read-only ClusterRole file) | | | +0.5 |
| **Resulting M1** | **about 165 after merging sub-hour tickets (194 rows before)** | **360.5** | **296** |
| My own bottom-up estimate of core (table at the end) | | | 229 |

Dates at 13 hours a week from Monday Nov 23, 2026, with the two half-capacity holiday weeks:

| Plan | 0.1.0 (core done) | M1 ends |
| --- | --- | --- |
| As written (571, 438 core) | week 36, Jul 26 to Aug 1, 2027 | week 46, Sunday Oct 10, 2027 |
| **After this review (360.5, 296 core)** | **week 24, May 3 to May 9, 2027** | **week 29, Sunday Jun 13, 2027** |
| Same, at 10 h a week | week 31, Jun 21 to Jun 27, 2027 | week 38, Aug 9 to Aug 15, 2027 |
| Same, at 15 h a week | week 21, Apr 12 to Apr 18, 2027 | week 26, May 17 to May 23, 2027 |

My dates carry fractional hours across weeks. The backlog packs whole tickets, which can add up to one
week. Neither plan has slack (see SF-4).

**Where the 438 hours come from.** Not from the six build steps. A third of the core is overhead that sits
around them: 62 h of docs site and docs pages (the plan puts docs in M3), about 30 h of security tickets
that re-test the engineering ticket they harden, about 25 h of fixture, golden and transcript tickets that
re-estimate artifacts other tickets already produce, and a floor of 1 to 2 hours on tickets that are a
config file or a paragraph. The six build steps themselves come to about 230 h.

## What checks out

- Totals: 235 tickets, 571 h, 438 core, 57 non-core at 133 h. M2 to M5 sums (398, 223, 114, 124) and the
  grand total (411 tickets, 1430 h) match the table.
- Every M1 ticket is 1 to 4 hours. Every "depends on" resolves to an id. No cycles. No M1 ticket depends on
  a later id, so "work in id order" is safe. No core M1 ticket depends on a non-core one.
- Calendar: each week's hours equal the sum of its tickets. Weeks run M1-001 to M1-235 with no gap or
  overlap. Nov 23, 2026 and Oct 4, 2027 are Mondays. Week 46 ends Sunday Oct 10, 2027. The 10 h and 15 h
  sentences are right to within a week.
- 00 agrees with 11 on totals, the full week table (identical rows), the cut list (11 host tickets at
  35 h, 6 net at 17 h, 7 k8s at 20 h, 57 at 133 h) and both dates. 13 agrees on 235, 571, 438, week 36 and
  Oct 10, 2027.

## Findings

Ranked. Severity: must fix (blocks approval), should fix (before M1 starts), nit.

### MF-1 (must fix): 49 hours of duplicate tickets survived the merge

Each row merges the second ticket into the first. Its exit test clauses move with it. "Hours removed" is
the net saving after the surviving ticket absorbs any extra work.

| Keep | Merge in (new estimate) | Why it is the same work | Hours removed |
| --- | --- | --- | --- |
| M1-008 | M1-012 (0) | CLAUDE.md command fix is a plan correction, and M1-004 already proves `cargo run -p rdy` | 1 |
| M1-002 | M1-055 (0) | Both are cli-ux confirming 07 uses the ADR words and flags | 1 |
| M1-001 | M1-082 (0) | Both are security-reviewer marking MF items closed on the revised ADRs | 1 |
| M1-024 (3 to 3.5) | M1-025 SEC-62 (0) | Tags, directives and `.inf` are parser limits, same file, same fixtures | 0.5 |
| M1-029 | M1-030 (0) | 029's exit test already covers unknown severity and status | 1 |
| M1-034 (3 to 3.5) | M1-031 (0) | Validating the hand-written schemas, then replacing them with generated ones, is the same CI step twice | 1.5 |
| M1-032 | M1-041 "extends M1 error types" (4 to 2) | Exit 64, `fix:` and the ErrorOutput code are in 032. Keep only the no-echo canaries | 2 |
| M1-046 (2 to 1.5) | M1-096 (2.5 to 1.5), M1-097 SEC-64 (0) | One artifact, the HTML-safe embedded JSON, in three tickets with the same `</script>` test | 2.5 |
| M1-051 (3 to 3.5) | M1-050 (0) | Same fixtures (gpu.cuda, aws.iam, typo id), same not_in_build and unknown_check reasons | 1.5 |
| M1-059 | M1-060 SEC-63 (2 to 1) | Action-log truncation rule is in 059's exit test. Keep the schema caps | 1 |
| M1-047 | M1-061 (3.5 to 2.5) | Setuid refusal (INV-10) is asserted in both | 1 |
| M1-069 (3 to 4) | M1-070 (0), M1-072 (0) | One replay loader, specified by 02 and by 08, ticketed three times | 4 |
| M1-069 | M1-093 (2.5 to 2) | The release feature-tree check is already in 069 | 0.5 |
| M1-080 | M1-079 (3 to 2) | The PEM-across-a-cap case is in both | 1 |
| M1-077, M1-081 | M1-085 (2 to 0.5) | URL userinfo rule and planted-secret canaries repeat 077, 078 and 081. Keep the URL storage rule | 1.5 |
| M2-050 SEC-44 | M1-178 (0, non-core) | "Cases 31 to 60 with chunk-boundary cases" is the M2 full corpus; chunk boundaries need the M2 streaming redactor | 1.5 |
| M1-058 SEC-18 | M1-086 (2 to 1) | The command allow-list is the SEC-18 policy table | 1 |
| M1-150, M1-151 | M1-109 (2 to 1) | Exits 0, 1 and 2 are the fixture env goldens. Keep 64 and 70 rows | 1 |
| M1-121, M1-137, M1-094 | M1-174 (0) | The "fixture lab" rebuilds the loopback servers, the kube mock and the env harness | 2 |
| M1-107, M1-150 | M1-175 (2 to 1), M1-176 (1 to 0.5) | README transcripts are the renderer and env goldens. Add three cases, do not build a second path | 1.5 |
| M1-122, M1-124 | M1-125 SEC-21 (3 to 1.5) | No redirects and no bodies are tested in 124 and 128. Keep the address rule on DNS answers and IPv4-mapped targets | 1.5 |
| M1-122, M1-123 | M1-126 (3 to 2) | Lookup, connect and TLS stages are facade calls | 1 |
| M1-122, M1-124 | M1-128 (4 to 2) | CONNECT, 403, 407 and the not-followed 302 are already in the facade tickets | 2 |
| M1-123 | M1-130 (3 to 1.5) | The recording verifier is built in 123. Keep the three classes | 1.5 |
| M1-135 | M1-136 (3.5 to 1) | The path parser is the guard. Keep the hostile path cases | 2.5 |
| M1-134, M1-060 | M1-184 SEC-24 (2 to 0.5, and core) | Identity and exec plugin display are in 134 and 060. Keep `examples/rbac/rdy-readonly.yaml`; rule 1 needs it at 0.1.0 | 1.5 |
| M1-155 | M1-156 SEC-61 (2 to 0.5) | Verify before parse on one buffer is 155's parser-spy test. Keep the fingerprint field | 1.5 |
| M1-157 | M1-158 SEC-60 (3 to 1.5) | "As root only /etc/rdy/trust.yaml is read" is 157's test. Keep the Windows ACL cases | 1.5 |
| M1-163 SEC-59 | M1-164 "extends SEC-59" (1.5 to 0.5) | Same banners and the same fix-source label (also in 099) | 1 |
| M1-161, M1-162, M1-166 | M1-165 (1 to 0.5), M1-167 (1 to 0.5) | Output goldens belong in the command tickets | 1 |
| M1-049, M1-062 | M1-152 (4 to 2) | Timeout and deadline tests under paused time are in both. Keep the `timeouts` env | 2 |
| M1-056 | M1-183 SEC-22 (2 to 1, non-core) | Both are strace contact tests on Linux CI | 1 |
| M1-177 | M1-189 (0, non-core) | docs-test already diffs README transcripts against goldens | 1 |
| M1-040, M1-042 | M1-192 (1.5 to 0.5), M1-193 (0), non-core | acme-platform's two not_in_build warnings are 040's test; 031/034 already run every example in CI | 2 |
| | | **Total** | **49 (42 core)** |

Fix: apply the merges, fold the exit-test clauses into the surviving row, keep the merged ids as
"merged into M1-NNN" so references in other documents still resolve.

### MF-2 (must fix): 99 hours of padding

These tickets are right in scope and wrong in size for a founder reviewing agent-written code. The
pattern: a 2 h floor on config files and a 3 to 4 h floor on anything with "page" or "renderer" in the
title. Proposed estimates, by area:

| Area | Tickets (as written to proposed) | Hours removed |
| --- | --- | --- |
| Workspace, CI, release | M1-003 2 to 1.5; 004 1 to 0.5; 005 2 to 1; 006 2 to 1; 007 4 to 3; 009 3 to 2; 010 4 to 3; 011 1 to 0.5; 013 1 to 0.5; 014 2 to 1 (do the settings by hand with a checklist; the `gh api` check script is extra); 015 1 to 0.5; 017 1 to 0.5; 018 1 to 0.5; 019 2 to 1 (one-time check, no CI job); 020 1 to 0.5; 022 4 to 3; 023 4 to 2.5 | 13.5 |
| Planning edits | M1-066 1 to 0.5; 217 1 to 0.5 (one-paragraph ADR edits) | 1 |
| Spec, lint, CLI edge | M1-026 3 to 2.5; 027 2 to 1.5; 028 2 to 1.5; 032 3.5 to 3; 033 4 to 2 (no docs-site modes in M1, see MF-3); 035 3 to 2; 036 4 to 2.5 (serde structs plus fixtures); 038 1 to 0.5; 039 3 to 2.5; 042 1 to 0.5; 043 2 to 1; 044 1.5 to 1 | 9.5 |
| Engine | M1-052 4 to 3; 056 1.5 to 1; 062 3.5 to 3; 063 2 to 1.5; 064 2 to 1 (clippy `disallowed-methods` plus deny bans; no lint-wall test crate); 065 1 to 0.5 | 4 |
| Facade and test helpers | M1-068 2.5 to 2; 071 2 to 1; 073 3 to 1.5; 074 2 to 1.5; 075 2 to 1 (08 calls it a 60-line helper); 094 3 to 2.5 | 5 |
| Redaction | M1-077 3.5 to 3 | 0.5 |
| Host checks | M1-083 2 to 1.5; 084 2 to 1.5; 087 2 to 1; 088 3 to 2.5; 089 4 to 3.5; 090 3 to 2 (drop Rosetta, see N-3); 091 4 to 3; 092 2 to 1.5 | 5.5 |
| HTML and terminal | M1-095 4 to 3.5; 098 2 to 1; 101 2 to 1.5; 102 1.5 to 1; 103 2 to 1.5; 105 1.5 to 1; 106 1 to 0.5; 108 1 to 0.5; 110 1.5 to 1 | 5 |
| Docs that stay in M1 (Markdown in `docs/`, see MF-3) | M1-115 3 to 2; 116 4 to 2.5; 117 4 to 1.5; 118 2 to 1; 119 3 to 1.5; 120, 133, 148 2 to 0.5 each (one intro paragraph); 159 1 to 0.5; 169 1 to 0.5; 170 3 to 1; 171 3 to 1; 173 3 to 1.5; 177 4 to 2; 179 3 to 2.5; 181 2 to 1 (one email) | 22 |
| Network | M1-121 4 to 3; 124 3 to 2; 127 3 to 2.5; 129 3 to 2.5; 131 2 to 1.5; 132 3 to 1.5 | 5 |
| Kubernetes | M1-137 4 to 3.5; 138 2.5 to 2; 141 4 to 3; 142 2 to 1.5; 143 4 to 3; 144 3 to 2.5; 145 3 to 2.5; 147 3 to 1.5 | 6 |
| Signing | M1-160 2 to 1.5; 168 2 to 1.5 | 1 |
| Fixture envs | M1-150 3 to 2.5; 151 3 to 2 | 1.5 |
| Non-core output polish | M1-195 3 to 2; 199 1.5 to 0.5 (indicatif picks the glyphs); 200 3 to 1.5; 201 2.5 to 1.5; 235 1 to 0.5 | 5 |
| Non-core checks | M1-204 4 to 3.5; 206 3 to 2.5; 207 3 to 2.5; 208 4 to 3; 209 4 to 3; 210 3 to 2; 211 4 to 3; 212 2 to 1.5; 213 3 to 2; 218 3 to 2.5; 219 2 to 1; 220 3 to 2.5; 221 4 to 3.5; 222 2 to 1.5; 223 2 to 1.5; 225 2 to 1.5; 226 3 to 2.5; 228 2 to 1.5; 229 3 to 2.5; 230 3 to 2.5; 231 3 to 2.5; 232 2 to 1.5; 234 2 to 1.5 | 14.5 |
| | **Total** | **99 (78 core)** |

Check tickets were cut least (0.5 h each). That is where domain review time is real.

Fix: apply the estimates. Then merge every ticket now under 1 h into a neighbour so the KICKOFF rule
"1 to 4 hours" still holds (see SF-6). Hours stay as above; the ticket count drops to about 165.

### MF-3 (must fix): 62.5 hours are speculative for M1

The plan's milestone table puts "docs" in M3, and build step 2 says only "write the JSON schema and
generate docs from it". A hosted docs site, its CI jobs, its deploy and its hand-written pages are M3
work. M1 needs the generated reference, five how-to pages and the README, as Markdown in the repo.
macOS and Windows host data sources have no design partner asking for them: install targets are Linux
servers and clusters, and the binary already runs net and k8s checks on every OS.

| Ticket | Hours | Core | Why speculative | Move to |
| --- | --- | --- | --- | --- |
| M1-111 Starlight scaffold | 4 | yes | Hosted site is M3 scope | M3 |
| M1-112 docs-gen and docs-build CI jobs | 4 | yes | `cargo xtask docs --check` in the lint job covers drift | M3 |
| M1-113 Production deploy to docs.getrdy.io | 3 | yes | No site in M1 | M3 |
| M1-114 Overview, Concepts, sidebar | 3 | yes | README covers it for five design partners | M3 |
| M1-149 Check catalog index | 1 | yes | Three family files in one folder need no index | M3 |
| M1-153 Compatibility page | 1 | yes | The generator is M2-075; the page is launch copy | M3 |
| M1-100 Contrast script | 1.5 | yes | Tooling to check a palette picked once. Pick it with a checker | M3 |
| M1-104 Golden results per released version | 1 | yes | Matters once rdy-cloud reads older results. 00 had it in M2 | M2 |
| M1-045 HMAC host_id | 2 | yes | A portal dedupe key. M1 writes `host_id: null` | M2 |
| M1-140 Cluster facts cache | 2 | yes | An optimisation with no measured need; six checks, small POC clusters | M2 |
| M1-182 SEC-31 docs security page | 2 | no | M3-033 extends it; needs the site | M3 |
| M1-185 Code of conduct | 1 | no | Launch item. Put SECURITY.md in M1-014 instead (SF-2) | M3 |
| M1-187, 188, 190, 191 Issue forms, repo hygiene, claims audit, cast | 7 | no | Launch content. Partners report by email (M1-181) | M3 |
| M1-197, 198 Headless browser render and layout | 4 | no | Static HTML checks in M1-103 cover 0.1.0 | M3 |
| M1-202, 203 sysinfo variants and macOS and Windows subset | 6 | no | No partner asked; Linux is the install target | M2, on demand |
| M1-205 Windows job objects | 3 | no | Only needed when the Windows exec allowlist opens (M1-215) | M2, on demand |
| M1-214, 215, 216, 224 macOS and Windows sources for host and net | 12 | no | Same | M2, on demand |
| M1-227 windows-2022-stub env | 1 | no | 08 itself tickets it in M2 | M2 |
| M1-233 k8s.device_plugins | 4 | no | GPU family is M4; it ships with gpu.* | M4 |
| | **62.5 (22.5 core)** | | | |

Fix: move the rows. Repoint dependencies: M1-159, 169, 170, 171 and 173 depend on M1-118 instead of M1-113;
M1-141 to 146, 225 and 228 to 232 depend on M1-137 instead of M1-140; M3-041 drops M1-224 and M1-233. The CLI prints `https://docs.getrdy.io/unsigned` (01 section 4.8): keep the URL and add a single
redirect to the Markdown page in the repo inside M1-159 (0.5 h).

### MF-4 (must fix): "core done" is not encoded in the graph

M1-180 (tag 0.1.0) transitively depends on only 103 of the 178 core tickets. 73 core tickets (156.5 h)
are not upstream of it, including all five host checks (M1-088 to 092), net.egress's HTTP and proxy
stages and net.proxy (M1-127 to 129), SEC-21 (M1-125), report-string redaction (M1-080), the tracing
redactor (M1-078), the banners (M1-163) and the fixture envs (M1-150, 151). Under the rule "a ticket
starts only when every id in its depends on is in the Done log", 0.1.0 can be tagged without host checks.
The claim "every 0.1.0 gate security ticket is closed" is prose, not a dependency.

Fix: add the 41 core leaves to M1-180's "depends on": M1-008, 011, 012, 020, 025, 030, 038, 045, 053, 056,
060, 063, 065, 073, 078, 080, 087, 089, 090, 097, 099, 102, 106, 108, 110, 114, 118, 136, 138, 139, 149, 151,
152, 153, 159, 164, 165, 167, 169, 172, 173 (prune those merged or moved by MF-1 and MF-3). Or add a
`gate` column and make M1-180 depend on "every row with gate: 0.1.0".

### MF-5 (must fix): the five-target exit tests cannot pass as written

- M1-180 and 00's engineering done test require the shipped `rdy` on all five targets to exit 0, 1 and 2
  on the ready, warning and not-ready fixtures. The shipped binary runs only the Live backend (M1-093).
  In core, every host check is `not_yet_on_os` on macOS and Windows (M1-087), so any spec with a host
  check is NOT READY there. Exit 0 on macOS and Windows is not observable.
- M1-150 requires the all-pass env, with host.memory passing, to exit 0 "on all five legs". M1-087's
  compile stubs gate gather functions by `#[cfg(target_os)]`, so a Linux fixture cannot pass host.memory
  on a macOS leg. 08 records this ("gate only the closures passed to `probe.native`"), but 11's M1-087
  exit test still says the opposite.

Fix: M1-087 exit test: "OS support is taken from the backend's OS; a Linux fixture runs the Linux
parser on every leg; only `probe.native` closures are cfg-gated." M1-180 and 00: "replay fixture envs exit
0, 1 and 2 on all five legs; the shipped binary exits 0, 1 and 2 live on both Linux legs; on macOS and
Windows the live smoke of 08 section 6 checks shape only; unsigned and tampered exit 64 on all five."

### MF-6 (must fix): custom.exec milestone. Pick M4.

ADR 0005 (Accepted), its index row, 02 (line 444), 03 (lines 17, 626, 636, 847) and 10 (lines 1245, 1259)
say M3. 11, 00 and 13 (PC-18) say M4. 09 and 11's own M5-013 put the custom checks page in M5.

Decision: **M4.** Reasons: M3 already carries AWS, the public launch and 223 h. custom.exec turns a signed
spec into code execution, often as root, and should not ship in the same milestone as the launch. Its
consent flow reuses the `--dry-run` plan (M2-029), so M4 also gives that a milestone of use first. 10's
launch claim "Specs cannot run commands" then stays true on launch day. No design partner has asked.

Documents that must change: **ADR 0005** (title, decision 3, both Tickets implied lines to `[M4]`), and
`docs/adr/README.md` (index row 0005 and the line 80 fix text). One-line follow-ons: 02 line 444; 03
lines 17, 626, 636 and 847; 10 lines 1245 and 1259 ("Until M4"). In 11, move M5-013 (custom checks page)
to M4. No ticket amends ADR 0005 today: add it to M1-008. 00's Tickets implied gives custom.exec 14 h; 11
gives M4-016 4 h plus M4-017 16 h. Use 11's figures in 00 or drop 00's list (SF-1).

### Should fix

- **SF-1. 00's "Tickets implied" is stale against 11.** It still lists the shared HTTP client builder in
  M1 (11: M2-015), "Property and fuzz tests" (11: property only, non-core), "Keep golden result files" in
  M2 (11: M1-104, core), SEC-26 as one 3 h ticket (11: split), SEC-21 owned by check-author and depending
  on the HTTP client builder, and custom.exec at 14 h. Fix: replace the section body with "Merged into
  11-backlog.md; see the ids there", or regenerate it from 11.
- **SF-2. Two artifacts are reviewed or linked but never written.** M1-172 reviews CONTRIBUTING.md and
  M1-185 links SECURITY.md; no ticket writes either. Security reviewers at design partners need
  SECURITY.md at 0.1.0. Fix: retitle M1-172 "Write CONTRIBUTING.md and check it on a fresh clone" (1 h);
  add SECURITY.md to M1-014's exit test.
- **SF-3. Missing dependency edges.** M1-062 and M1-063 assert "no child process group left" but do not
  depend on M1-057 (the process-group kill); neither reaches it transitively. Fix: add M1-057 to both.
- **SF-4. No slack.** Every week is filled to 12 to 13.5 h for 46 weeks. From 0.1.0 on, the founder also
  supports design partners. The "twice its estimate" rule only splits tickets; it never adds time. Fix:
  one ticket-free week every eight weeks (three in the reduced plan, M1 end about Jul 4, 2027), or label
  the calendar a no-slack lower bound.
- **SF-5. Trimming at M1-181 breaks later milestones.** Eleven M2 to M5 core tickets depend on non-core
  M1 tickets: M2-037 on 226, M2-038 on 228, M2-039 on 208, M2-041 on 211, M2-043 on 178, M2-052 on 195,
  M2-073 on 183, M3-033 on 182, M3-041 on 224 and 233, M5-004 on 234. Fix: in "How to work the backlog",
  say that skipped non-core tickets move to the head of M2, and repoint the moved ones from MF-3.
- **SF-6. Keep the 1 to 4 hour rule after this review.** 29 proposed estimates are under 1 h. Merge them
  into a neighbour: 004 into 003; 015 and 020 into 014; 017 and 018 into 006 and 007; 013 into 003; 011
  is a hand step before the go (00 calls it gate-safe), take it out of M1 hours; 038 into 037; 042 into
  040; 065 into 064; 066 and 217 into 008; 085 into 077; 106 and 108 into 107; 120, 133, 148 into 119; 156
  into 155; 159 and 169 into 170; 164 into 163; 165 into 162; 167 into 166; 176 into 175; 184 into 135;
  192 into 042; 199 into 200; 235 into 039. Each PR also carries a CHANGELOG entry and a CI wait, so
  fewer tiny PRs is real time saved.
- **SF-7. Planning work is booked as M1 build time.** M1-001, 002, 008, 055, 066, 082 and 217 are review
  sign-offs and document edits (10 h). Fix: do them in the planning pass before the Nov 20 go, as one 3 h
  ticket, so week 1 starts with code.
- **SF-8. Weak exit tests.** M1-147 ("Written review with every finding fixed or filed") and M1-168
  ("Review notes filed") name no artifact. M1-132's second clause repeats M1-086's test. M1-019 is a
  manual confirmation. Fix: each review ticket names its file under `docs/plan/reviews/` and passes when
  that file lists zero open must-fix items; drop the repeated clause from M1-132.

### Nits

- **N-1.** Week 5 holds 7 h against 6.5 h of capacity. The 13.5 h overflow rule was meant for full weeks.
- **N-2.** The 10 h sentence runs through the Christmas 2027 weeks at full capacity. M1 end slips to about
  mid-January 2028 at 10 h as written.
- **N-3.** M1-090 (core) detects Rosetta, a macOS-only signal, while macOS host checks are
  `not_yet_on_os` in core. Drop it from 090; add it with the macOS sources.
- **N-4.** M1-108's static "Running N checks" line is replaced by M1-200's progress line. Fold it into
  M1-107 and let 200 replace it.
- **N-5.** For M1-177, `trycmd` runs fenced commands from Markdown with expected output out of the box.
  That is the boring choice over a custom extractor, and fits the 2 h estimate.
- **N-6.** 13, PC-18, problem column says "ADR and 00: custom.exec M3". 00 now says M4. Reword to "ADR
  0005" only.
- **N-7.** 13's "Background" table should gain a row for this review's figure once the founder accepts it,
  so the history of the count stays in one place.

## Bottom-up estimate of the M1 core

From scratch, for a seasoned Rust engineer reviewing agent-written code, with the security posture the
product rules require (facade, kube guard, redaction, signing, root-only trust store). The middle column is
the core after this review's ledger, for comparison.

| Build step | Backlog core | After this review | My bottom-up |
| --- | --- | --- | --- |
| 1 Workspace, CI, release, install.sh, repo hardening | 42 | 28.5 | 20 |
| 2 Spec parser, result model, schema, lint, CLI edge | 60.5 | 42.5 | 30 |
| 2 Engine core: trait, registry, scheduler, timeouts, runner, privileges, output dir, `rdy run` | 48 | 40.5 | 30 |
| 2 and 3 Probe facade, replay fixtures, test harness | 28.5 | 19 | 16 |
| 2 and 3 Redaction for reports and logs | 19 | 14.5 | 10 |
| 3 Host checks (five, Linux) | 24 | 17.5 | 14 |
| 3 HTML report and terminal output | 29.5 | 19 | 15 |
| 4 Network: facade TCP, TLS, HTTP, address policy, three checks | 38 | 27 | 22 |
| 5 Kubernetes: client, guard, mock, kind job, six checks | 42 | 32 | 27 |
| 6 Signing, `rdy verify`, trust store | 31.5 | 25.5 | 22 |
| Fixture envs | 10 | 6.5 | 5 |
| Docs: generated reference, five Markdown pages, README, doc tests | 62 | 21.5 | 15 |
| Tag 0.1.0 and announce | 3 | 2 | 3 |
| **Total** | **438** | **296** | **229** |

The gap between 296 and 229 is mostly the floor cost of 158 separate PRs. Merging further gets closer to
229. Without the security posture the floor would be about 170 h, but that posture is a product rule, not
an option.

## Verdict

**Request changes.** The arithmetic is clean and the plan is honest about its size. But the size is
inflated: 49 h of duplicates, 99 h of padding and 62.5 h of M2 to M4 work sit inside M1. The graph does
not encode "core done", and two five-target exit tests cannot pass. Apply MF-1 to MF-6. That gives M1 at
360.5 h with 296 h core: 0.1.0 in week 24 (May 3 to 9, 2027) and M1 end in week 29 (Sunday Jun 13, 2027)
at 13 h a week. Design partners get a build about twelve weeks sooner. Then re-sync 00 and 13 from 11.
