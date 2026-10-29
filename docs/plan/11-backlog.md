# Rdy backlog, M1 to M5

Owner: rust-architect. Date: 2026-10-28, revised the same day after the code-reviewer and qa-engineer
reviews in `docs/plan/reviews/11-backlog-review-by-*.md`. Everyone contributes; rust-architect keeps the
table.

This is the one ticket list for M1 to M5. It merges the "Tickets implied" sections of `00-overview.md`
to `10-devrel-and-launch.md`, `docs/adr/README.md`, ADRs 0001 to 0016, and the ticket the review of
`13-plan-corrections.md` asked for. Where two documents named the same work, it is one ticket with both
exit tests folded in. Where a ticket "extends" another, it is merged into it or listed as a dependent
ticket. Every "depends on" is an id in this table, and the graph has no cycles. Estimates are founder
hours, including review of agent-written code.

The founder decided on 2026-10-28: M1 is extended, not cut. It is planned at its real size at 13 founder
hours a week. The calendar starts on Monday Nov 23, 2026. The founder started M1 early, on 2026-10-28
(`13`, Decisions made 2), so work can run ahead of these dates. A tagged binary ships every week.

**Two estimates of the M1 core.** This table says 315.5 hours of core and 374.5 hours in all.
The code-reviewer's own bottom-up estimate of the same core, from scratch and with the same security
posture, is **229 hours**. Most of the gap is the fixed cost of about 140 separate PRs (CHANGELOG entry,
CI wait, review). Plan on the table's figure. If the first eight weeks run at the bottom-up rate, re-plan
from the Done log.

**What the review pass changed.** The reviewed draft had 235 M1 tickets, 571 hours and 438 core. This
revision removes 49 hours of duplicates and 99 hours of padding, and moves 62.5 hours out of M1 as
speculative: the hosted docs site and launch content to M3, the macOS and Windows host and network data
sources to M2, and `k8s.device_plugins` to M4 with the GPU family. M1 docs are Markdown pages under
`docs/`, generated from the schema and the check registry. qa-engineer's must-fixes add 5 hours: a
real-binary smoke test on five legs and a root CI job for the `sudo` and `strace` tests. Parser property
tests and SEC-22 move into core (3 hours of core). The id map at the end of this file maps every id in the
reviewed draft to its id now.

**The core column.** In M1, `core: no` marks what a document put on its cut list: the 03 M1-late check
tickets still in M1, the 07 and 10 tickets marked `core: no`, and the M2 facade ticket that two M1-late
checks need. Everything else is `core: yes`. A ticket that a core ticket depends on is core (10's rule).
The alpha announcement (M1-139) is core although 10 marks it `core: no`, because the plan's exit
test needs design partners to get the build. Every core ticket comes before every non-core ticket in the
calendar, and M1-138 (tag 0.1.0) depends on every core ticket, so trimming M1 means stopping after
M1-139. In M2 to M5 every ticket is `core: yes`; the marker only matters for the M1 trim.

**Reconciliation choices.** These are the merges and moves that are not obvious from the titles:

- ADR 0014 gave the probe facade every TCP, TLS and HTTP side effect, so ADR 0009's shared HTTP client
  builder has no M1 consumer. It moves to M2 as the base of the upload client (03 said the same).
- SEC-21 follows ADR 0014: no redirects are followed. 05's "capped redirects, sixth hop refused" is
  superseded.
- 03's "Command runner" is folded into the blocking helper and SEC-18. 09's schema emitter is the
  schemars ticket. 02's replay backend and 08's fixture format are one loader. 00's coarse `rdy-bundle`,
  AWS family, GPU family, data store and self-update tickets are replaced by the detailed tickets in 03,
  04 and 06.
- SEC-26 keeps the 28 cases that gate 0.1.0 in M1 (04 section 4). The 32 M2 cases (60 in all) and the
  chunk-boundary cases need the M2 streaming redactor, so they are part of SEC-44 in M2.
- SEC-05 and SEC-22 stay in M1 (00, 05). Reserving the crates.io names is a hand step for the founder
  (13, open decision 4), not M1 hours.
- `--dry-run` and `--timeout` stay in M2, as 07 decided. 10 dropped its M1 `--dry-run` stretch ticket;
  the work is SEC-40 in M2.
- 01's tickets marked "done in this revision" are not listed. Tickets that used "the plan's example spec"
  as input now use `examples/specs/acme-platform.yaml`.
- README transcripts are goldens made in process from Replay envs. docs-test runs commands live and checks
  only exit codes and shape, never host numbers (qa-engineer).
- Gaps no document ticketed are added: wiring `rdy run` end to end, tagging 0.1.0, the real-binary smoke
  and the root CI job (M1), the launch release candidate (M3) and the air-gapped kit (M5).
- `custom.exec` is in M4 with the GPU and store checks (ADR 0005, amended). The custom checks page moves
  with it. Store checks are M4 (00, ADRs); 03 had M3.
- Portal-side scope (results dashboard, bundle viewer, Slack alerts, Stripe billing, CRM sync, analytics,
  SSO, self-hosted portal, licensing server) lives in the private `rdy-cloud` backlog. This table holds
  the CLI and crate side of each milestone.

## Totals

| Milestone | Tickets | Hours | Core hours | Weeks at 13 h |
| --- | --- | --- | --- | --- |
| M1 | 171 | 374.5 | 315.5 | 30 (calendar below) |
| M2 | 109 | 424.5 | 424.5 | about 33 |
| M3 | 64 | 271.5 | 271.5 | about 21 |
| M4 | 24 | 121 | 121 | about 9 |
| M5 | 12 | 121 | 121 | about 9 |
| **All** | **380** | **1312.5** | **1253.5** | about 100 |

M2 to M5 tickets are coarse. When a milestone starts, rust-architect splits every ticket over 4 hours into
tickets of 1 to 4 hours, keeping the exit tests.

## M1 calendar

13 founder hours a week from Monday Nov 23, 2026. The weeks of Dec 21 and Dec 28 run at half capacity. A
full week holds up to 13.5 hours of tickets so small tickets are not split; a half week holds no more
than 6.5. Builds are tagged on Thursday (06). Builds before 0.1.0 are `0.1.0-alpha.N` and are not given to
design partners for real POCs (PC-08). Until `rdy verify` lands they run specs only with
`--allow-unsigned`. `v0.1.0` ships when core is done; the non-core weeks ship `v0.1.N` until M1 ends.
`0.2.0-alpha.N` starts with M2.

- **0.1.0, the design-partner build:** week 25, May 10 to May 16, 2027, with the alpha announcement
  (M1-139). That is the core-only end date.
- **M1 ends:** week 30, Jun 14 to Jun 20, 2027. End date: Sunday Jun 20, 2027.
- **Correction 02 (2026-10-28) added 3.5 core hours.** M1-001's extra hour (05 revision 3) runs in week
  7, which had 1 h of room and comes before M1-040, so week 1 holds 14.5 h of tickets and week 7 13.5 h.
  M1-104's extra 2.5 h is absorbed by the re-cut from week 19 in M1-009: core still ends in week 25, and
  the non-core tickets M1-140 to M1-144 move to week 26, so M1 ends in week 30. The 10 and 15 hour dates
  are not recomputed.
- **Correction 08 (2026-10-29) added 1 core hour.** M1-168 runs in week 16, the first week after its
  dependencies (M1-056, week 11) with room, so week 16 holds 12.5 h. Core still ends in week 25 and M1
  in week 30. M2-104 adds 2 h to M2.
- **Correction 11 (2026-10-29) moved 0.5 h.** M1-102 gives 0.5 h to M1-107, so week 19 holds 10.5 h and
  week 20 holds 12.5 h. Core still ends in week 25 and M1 in week 30. M2-106 adds 2 h to M2.
  M2-107 adds 1.5 h to M2.
- **Correction 12 (2026-10-29) added 0.5 core hours.** M1-107 goes from 2.5 h to 3 h for the Windows
  `.cmd` plugin test, PATH resolution of a bare plugin name and SystemRoots trust, so week 20 holds 13 h.
  Core still ends in week 25 and M1 in week 30.
- **Correction 13 (2026-10-29) added 0.5 core hours.** M1-074 goes from 2 h to 2.5 h for the setuid
  and file-capability binary tests. Week 14 was full, so M1-073 (1.5 h, the smallest ticket there not
  yet built) moves to week 18, the first week with room after its dependency M1-049 (week 11) and before
  its dependent M1-116 (week 22). Week 14 holds 12.5 h and week 18 13 h. Core still ends in week 25 and
  M1 in week 30. The 10 and 15 hour dates are not recomputed.
- **Correction 16 (2026-10-29) added 2 core hours.** New M1-171 (1 h, `statfs` prefixes for `Statvfs`) runs in
  week 13 before host.disk (M1-068). M1-070 (1 h) moves from week 13 to week 14, before its dependents
  M1-086 (week 16) and M1-142. New M1-170 (1 h, machine identity files) runs in week 14. Week 13 holds
  13.5 h and week 14 13 h. Core still ends in week 25 and M1 in week 30. The 10 and 15 hour dates are not
  recomputed.
- **Correction 15 (2026-10-29) added 0.5 core hours.** M1-105 goes from 3.5 h to 4 h for the two
  `ReadOnlyClient` routes (discovery and the raw `SelfSubjectReview`). Week 20 holds 13.5 h. Core still ends
  in week 25 and M1 in week 30. The 10 and 15 hour dates are not recomputed.
- **Correction 14 (2026-10-29) added 1.5 core hours.** New M1-169 (1.5 h, the facade `read_link`) runs in
  week 14, after its dependency M1-045 (week 10). Week 14 had 1 h of room, so M1-072 (3 h) moves to week
  19, the first week with room after M1-169 and before its dependents M1-116 and M1-118 (week 22). Week 14
  holds 11 h and week 19 13.5 h. Core still ends in week 25 and M1 in week 30. The 10 and 15 hour dates
  are not recomputed. M2-108 adds 1 h to M2. M2-109 adds 2 h to M2.
- At 10 hours a week (holiday weeks at half): 0.1.0 in the week of Jun 28, 2027 and M1 end in the week
  of Aug 9, 2027. At 15 hours a week: 0.1.0 in the week of Apr 19, 2027 and M1 end in the week of May 17,
  2027.
- The calendar has no slack. From 0.1.0 on, the founder also supports design partners. One ticket-free
  week every eight weeks adds three weeks: 0.1.0 in early June 2027 and M1 end in early July 2027.

| Week | Dates | Capacity | Hours | Build step | Tickets | Ships |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Nov 23 to Nov 29, 2026 | 13 | 13.5 | 1 Workspace, CI, release | M1-001 to M1-008 | `v0.1.0-alpha.0` (CI artefacts): `rdy version` built and tested on five CI legs and by dist in the release sandbox |
| 2 | Nov 30 to Dec 6, 2026 | 13 | 13 | 1 Workspace, CI, release; 2 Spec parser, result model, engine core | M1-009 to M1-013 | `v0.1.0-alpha.1`: first cosign-signed pre-release on GitHub Releases; domain and org settings check scripts in the repo |
| 3 | Dec 7 to Dec 13, 2026 | 13 | 13.5 | 1 Workspace, CI, release; 2 Spec parser, result model, engine core | M1-014 to M1-018 | `v0.1.0-alpha.2`: install.sh that checks the cosign signature, from the pinned release URL |
| 4 | Dec 14 to Dec 20, 2026 | 13 | 13 | 2 Spec parser, result model, engine core | M1-019 to M1-022 | `v0.1.0-alpha.3`: result model and generated JSON schemas; errors carry fix hints; `rdy version --json` |
| 5 | Dec 21 to Dec 27, 2026 | 6.5 | 6 | 2 Spec parser, result model, engine core | M1-023 to M1-025 | `v0.1.0-alpha.4`: same CLI; typed parameters for the M1 host, net and k8s check ids |
| 6 | Dec 28, 2026 to Jan 3, 2027 | 6.5 | 6.5 | 2 Spec parser, result model, engine core | M1-026 to M1-028 | `v0.1.0-alpha.5`: same CLI; semantic validation, parser property tests, root CI job |
| 7 | Jan 4 to Jan 10, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core | M1-029 to M1-032 | `v0.1.0-alpha.6`: `rdy spec lint <file>` with did-you-mean; usage errors exit 64 |
| 8 | Jan 11 to Jan 17, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core | M1-033 to M1-037 | `v0.1.0-alpha.7`: engine runs checks with timeouts and panic isolation; unknown ids SKIP |
| 9 | Jan 18 to Jan 24, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core | M1-038 to M1-042 | `v0.1.0-alpha.8`: commands only through the mediated runner; action log; privilege snapshot |
| 10 | Jan 25 to Jan 31, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core; 3 Host checks, HTML report | M1-043 to M1-048 | `v0.1.0-alpha.9`: run deadline and watchdog; facade file policy; redactor core |
| 11 | Feb 1 to Feb 7, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core; 3 Host checks, HTML report | M1-049 to M1-056 | `v0.1.0-alpha.10`: replay fixtures, fixture lint and golden helpers; logs redacted |
| 12 | Feb 8 to Feb 14, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core; 3 Host checks, HTML report | M1-057 to M1-062 | `v0.1.0-alpha.11`: `rdy run <file> --allow-unsigned --json` writes a 0700 report dir, every check SKIP; Ctrl-C exits 70; `--no-network` |
| 13 | Feb 15 to Feb 21, 2027 | 13 | 13.5 | 3 Host checks, HTML report | M1-063 to M1-069, M1-171 | `v0.1.0-alpha.12`: every report string redacted, 28-case corpus gates CI; host.memory and host.disk |
| 14 | Feb 22 to Feb 28, 2027 | 13 | 13 | 3 Host checks, HTML report | M1-070, M1-071, M1-074 to M1-076, M1-169, M1-170 | `v0.1.0-alpha.13`: host.cpu on Linux; facade `read_link`; machine identity files denied; terminal styling; in-process env harness |
| 15 | Mar 1 to Mar 7, 2027 | 13 | 13.5 | 3 Host checks, HTML report | M1-077 to M1-085 | `v0.1.0-alpha.14`: HTML report next to the JSON, with golden reports; generated spec reference |
| 16 | Mar 8 to Mar 14, 2027 | 13 | 12.5 | 3 Host checks, HTML report; 4 Network checks | M1-086 to M1-090, M1-168 | `v0.1.0-alpha.15`: the demo: bucket-sorted terminal output with fix lines and the verdict last; umask 077 and an inherited-descriptor warning at start-up |
| 17 | Mar 15 to Mar 21, 2027 | 13 | 12.5 | 4 Network checks | M1-091 to M1-095 | `v0.1.0-alpha.16`: facade TCP, TLS and HTTP; net.egress direct with the address policy |
| 18 | Mar 22 to Mar 28, 2027 | 13 | 13 | 3 Host checks, HTML report; 4 Network checks | M1-096 to M1-101, M1-073 | `v0.1.0-alpha.17`: net.egress through the customer's proxy, net.proxy, net.tls_intercept; host.os on Linux |
| 19 | Mar 29 to Apr 4, 2027 | 13 | 13.5 | 3 Host checks, HTML report; 5 Kubernetes checks | M1-102 to M1-104, M1-072 | `v0.1.0-alpha.18`: kube client with context, server and user shown; read-only guard with path parser and resource allowlist; host.ports on Linux |
| 20 | Apr 5 to Apr 11, 2027 | 13 | 13.5 | 5 Kubernetes checks | M1-105 to M1-109 | `v0.1.0-alpha.19`: k8s.version, k8s.access; kind job in CI |
| 21 | Apr 12 to Apr 18, 2027 | 13 | 12.5 | 5 Kubernetes checks; 6 Signing, `rdy verify`, 0.1.0 | M1-110 to M1-115 | `v0.1.0-alpha.20`: k8s.storageclass, k8s.rbac, k8s.nodes, k8s.admission (PSA); k8s review closed |
| 22 | Apr 19 to Apr 25, 2027 | 13 | 13.5 | 3 Host checks, HTML report; 5 Kubernetes checks; 6 Signing, `rdy verify`, 0.1.0 | M1-116 to M1-120 | `v0.1.0-alpha.21`: family pages; fixture envs for every verdict; timeouts env; signatures verified before parsing |
| 23 | Apr 26 to May 2, 2027 | 13 | 11.5 | 6 Signing, `rdy verify`, 0.1.0 | M1-121 to M1-125 | `v0.1.0-alpha.22`: trust store; `rdy spec keygen`, `rdy spec sign` |
| 24 | May 3 to May 9, 2027 | 13 | 13.5 | 6 Signing, `rdy verify`, 0.1.0 | M1-126 to M1-131 | `v0.1.0-alpha.23`: `rdy verify`; unsigned refused; real-binary smoke on five legs; first-run page; `rdy trust add\|list\|remove` |
| 25 | May 10 to May 16, 2027 | 13 | 13 | 6 Signing, `rdy verify`, 0.1.0 | M1-132 to M1-139 | **`v0.1.0`**: signing review closed; install and sign pages; README ready, core done, announcement sent to design partners |
| 26 | May 17 to May 23, 2027 | 13 | 11.5 | Non-core, steps 2 and 3 | M1-140 to M1-145 | `v0.1.1`: progress line, quiet and verbose modes, HTML wording; UDP and unix socket facade; host.lsm |
| 27 | May 24 to May 30, 2027 | 13 | 13.5 | Non-core, step 3 | M1-146 to M1-150 | `v0.1.2`: host.security_agents, host.firewall, host.time_sync, host.sysctl, host.container_runtime |
| 28 | May 31 to Jun 6, 2027 | 13 | 13 | Non-core, steps 3 and 4 | M1-151 to M1-156 | `v0.1.3`: host.cgroups, host.kernel; net.dns; net.registry |
| 29 | Jun 7 to Jun 13, 2027 | 13 | 12.5 | Non-core, steps 4 and 5 | M1-157 to M1-163 | `v0.1.4`: net.mtu, net.bandwidth; k8s.nodes free capacity, webhooks, namespace, dns, ingress |
| 30 | Jun 14 to Jun 20, 2027 | 13 | 8.5 | Non-core, steps 5 and 6 | M1-164 to M1-167 | `v0.1.5`: k8s.crds, k8s.cni; air-gapped fixture env; quickstart timed; M1 complete |

## Backlog

| id | milestone | title | owner subagent | estimate (h) | core | depends on | exit test |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M1-001 | M1 | Confirm the revised ADRs close security findings MF-01 to MF-07 | security-reviewer | 2 | yes | none | Each must-fix is marked closed or reopened in docs/plan/reviews/ before the first M1 code ticket; and MF-01 to MF-06 of the ADR 0013 to 0016 review are marked closed; and before M1-040 starts, 05 revision 3 carries the four edits in 02 (INV-12 `is_forbidden` ranges, Appendix A I3 with ADR 0016 and `%USERPROFILE%\rdy-reports`, Appendix F cap-boundary redaction cases in M1, INV-08 fixed PATH always) and names ADRs 0014 to 0016. |
| M1-002 | M1 | Confirm the revised ADRs close cli-ux findings M1 to M3 and the final command names | cli-ux | 1 | yes | none | 07-cli-ux.md uses the verdict words, status words and commands from ADRs 0002, 0003 and 0008; and 07 confirms the headline, the M1 Ctrl-C exit 70 message, `--no-network`, `--out-dir` and the plan flag name. |
| M1-003 | M1 | Create workspace skeleton and package rdy in crates/rdy-cli with binary name rdy | rust-engineer | 2.5 | yes | M1-001, M1-002 | `cargo build`, `clippy -D warnings`, `fmt --check` and `cargo doc` with warnings as errors pass on edition 2024 crates with `forbid(unsafe_code)`, a pinned toolchain and shared lints, and `CHANGELOG.md` exists with `changelog.d/` for one fragment per PR (ADR 0017); `cargo run -p rdy -- version` and `-- --version` print the documented line and `cargo package -p rdy --list` contains no stray files; and `.github/pull_request_template.md` carries the CLAUDE.md checklist and 08 Appendix E, with the 12 labels of 10-devrel-and-launch.md section 6 created; and a minimal `deny.toml` carries only the license allowlist the skeleton's dependency tree needs, so `cargo deny check` passes, and `LICENSE` holds the Apache-2.0 text. |
| M1-004 | M1 | Extend deny.toml with crate bans and the full license allowlist | release-engineer | 1 | yes | M1-003 | The M1-003 `deny.toml` gains the bans, the full license allowlist and the webpki-roots CDLA-Permissive-2.0 entry. Adding serde_yaml, serde_yml, libyml, openssl-sys, native-tls, aws-lc-sys or atty fails `cargo deny check` in CI, and webpki-roots passes under its CDLA-Permissive-2.0 entry. |
| M1-005 | M1 | CI lint and deny job: fmt, clippy, doc, cargo-deny, zizmor (SEC-01) | release-engineer | 1.5 | yes | M1-004 | A PR is green, and throwaway PRs that add a clippy warning and add `openssl` both turn it red; a PR with an unsigned commit fails the DCO check and one with `Signed-off-by` passes. |
| M1-006 | M1 | CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | release-engineer | 3.5 | yes | M1-005 | A run with all gating legs green: native test legs on linux-x64, linux-arm64, windows-x64 and macos-x64, plus an `aarch64-apple-darwin` compile leg on `macos-15-intel` that builds the workspace and runs `cargo test --no-run` for that target, so every check still compiles for all five targets on every PR. Both Linux binaries pass the `readelf` no-INTERP and no-NEEDED check and run in a scratch container. A PR with one red leg cannot merge. A test that fails once in three runs is not retried and `cargo test --doc` runs on linux-x64. A separate workflow `macos-arm64.yml` runs the full test job on `macos-15` nightly, on push to `main` and by `workflow_dispatch`. It is not in ci-ok until the org has macOS arm64 runners (correction 05, Founder hand steps). |
| M1-007 | M1 | dist init for five targets with cargo-auditable and SBOM, proven in release-sandbox | release-engineer | 2 | yes | M1-006 | A tag in `getrdy-io/release-sandbox` builds five archives with checksums, `cargo audit bin` lists dependencies from a downloaded binary, the SBOM is valid CycloneDX (XML or JSON), and `rdy.exe` imports no `VCRUNTIME140.dll`. |
| M1-008 | M1 | SEC-05 Harden getrdy.io domain and hosting accounts | release-engineer | 1 | yes | none | `scripts/check-domain.sh` prints a PASS or FAIL line with a fix line for registrar lock, DNSSEC, CAA and HSTS, prints hardware-key MFA as MANUAL, exits 0, 1 or 64 as documented, and its first run against getrdy.io is in the PR; `docs/security/domain-hardening.md` lists every account step. The account steps are founder hand steps. |
| M1-009 | M1 | Close the planning pass: apply plan corrections and amend ADRs 0006 and 0015 | rust-architect | 4 | yes | M1-003 | Every blocks-M1 and should-fix entry in 13-plan-corrections.md is applied or rejected, and its row is deleted from 13; the CLAUDE.md Commands block uses `cargo run -p rdy` (PC-04); ADR 0015 is Accepted with the 04 span-union bullet and a security-reviewer sign-off; ADR 0006 names `getent ahosts` with hickory as fallback. |
| M1-010 | M1 | sign-release with cosign keyless, SHA256SUMS and self-verify (SEC-06, SEC-07) | release-engineer | 3 | yes | M1-007 | In the sandbox the signing job waits for approval, no release exists until signing ends, then it is published, and `cosign verify-blob` with the exact identity passes on a clean machine and fails after one byte of `SHA256SUMS` changes. |
| M1-011 | M1 | SEC-04 Org 2FA, private reporting, immutable releases, CODEOWNERS and a settings check script | security-reviewer | 2 | yes | M1-006, M1-008 | `.github/CODEOWNERS` covers the security paths, `.github/dependabot.yml` covers cargo and GitHub Actions, and a CI check fails on any `uses:` line without a commit SHA and passes on the branch (SEC-03); `scripts/check-org-settings.sh` reads org-wide 2FA, private vulnerability reporting, immutable releases, the `main` and `v*` rulesets and the Security tab policy through the REST API, prints PASS or FAIL per item with a fix line, and its first run is in the PR; the security.txt content with both channels (SEC-32) and the settings checklist are in the repo. The account and settings steps are founder hand steps. |
| M1-012 | M1 | First signed alpha, scripts/verify-release.sh and RELEASING.md | release-engineer | 2 | yes | M1-010, M1-011 | `v0.1.0-alpha.1` exists on `getrdy-io/rdy`, published as a pre-release, and `scripts/verify-release.sh v0.1.0-alpha.1` passes on a clean Linux machine; and a wrong caller repository, ref and trigger each fail (PR #66 security review, finding 1). |
| M1-013 | M1 | xtask skeleton with schema, docs, docs-lint and --check modes, dist and publish off | docs-writer | 2 | yes | M1-003 | `cargo xtask docs --check` exits 1 after a generated Markdown page under docs/ is hand-edited and 0 on a clean tree, and docs-lint fails on a planted em dash and a planted banned-token hash match. |
| M1-014 | M1 | install.sh core with root refusal, truncation guard, sha256 and shell tests (SEC-08) | release-engineer | 3 | yes | M1-007 | Shellcheck is clean, the shell tests pass under dash and busybox sh, uid 0 without `--allow-root` exits 1 with the fix, and a cut-off script run installs nothing. |
| M1-015 | M1 | install.sh signature check, fail closed, with tamper tests (SEC-09, SEC-10) | release-engineer | 2.5 | yes | M1-014, M1-012 | With a real cosign the alpha.1 install passes, and bad hash, bad signature, wrong identity, missing bundle and missing cosign (with and without the override) each fail with the documented message; and a wrong caller repository, ref and trigger each fail (PR #66 security review, finding 1). |
| M1-016 | M1 | Define public spec types in rdy-spec | rust-engineer | 3 | yes | M1-003 | The spec types cover every field of 01 section 2.2, the metadata fields round-trip through serde_json, and no public path builds a LoadedSpec without load(). |
| M1-017 | M1 | Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | rust-engineer | 3.5 | yes | M1-016 | A 2 MiB file, an anchor or alias, a duplicate key and `cuda: 12.10` unquoted each give the documented SpecError with line and column, never a panic, and the geiger result is recorded in ADR 0001; and `!!binary`, `!custom`, `%YAML 1.1`, `.inf` and `.nan` fixtures each exit 64 with line and column (SEC-62), and every file in examples/specs decodes through parse_unverified into typed values. |
| M1-018 | M1 | Scalar types Quantity, Duration, Version and Target with strict grammars | rust-engineer | 1.5 | yes | M1-016 | Unit tests reject `32G`, unquoted `1.30`, `10 s`, `host:99999` and `https://u:p@host/`, and accept `32Gi`, `"1.30"`, `14`, `7d` and `[::1]:443`. |
| M1-019 | M1 | Two-step check decoding with Unknown and Unsupported variants | rust-engineer | 2.5 | yes | M1-016, M1-017 | `gpu.cuda` decodes to Unknown, `host.memory` with `mn` to Unsupported naming `mn`, and a missing id or duplicate entry key is a SpecError with line and column. |
| M1-020 | M1 | Define result model and verdict mapping in rdy-spec | rust-engineer | 3.5 | yes | M1-016 | A table test covers every severity and status pair, unknown severity and status, the partial rule including Partial OS support, the not_applicable source rule and the empty run, asserts verdict_reason and exit codes (a skipped block check gives not_ready and exit 2), and the 01 samples 7.2 to 7.4 round-trip byte for byte; and a result with an extra top-level field, status "quarantined" and bucket "frozen" deserializes and maps both to Unknown. |
| M1-021 | M1 | Error types with fix hints and exit code mapping at the CLI edge | rust-engineer | 3 | yes | M1-020 | Every error variant and every SpecError and skip kind has the 01 section 2.5 or 5.2 message and a non-empty hint, exit 64 and 70 cases print `fix:`, `--json` failures print the error object with a stable code, and control characters in a spec string are escaped as visible text, not sent to the terminal; clap usage errors exit 64 with the two-line form and help and version exit 0 on stdout, and `--json` gives an ErrorOutput with code `usage`. |
| M1-022 | M1 | Generate JSON schemas with schemars behind cargo xtask schema and check drift in CI | rust-engineer | 4 | yes | M1-020, M1-013, M1-016, M1-003 | The generated files accept and reject the same fixtures as the hand-written ones and replace them, `cargo xtask schema --check` fails after a type or doc-comment change that is not regenerated, and a description containing "ADR" or a milestone name fails CI; and CI validates every file in examples/specs, the 01 7.x samples and every golden result with a 2020-12 validator, the hostile fixtures of both 01 reviews giving the documented accept or reject; and `rdy version --json` matches 07 4.3 and C.11 and validates against the new `Version` definition. |
| M1-023 | M1 | Reserved check ids and the not_in_build lint rule | rust-engineer | 1.5 | yes | M1-019 | `host.kernel` lints as not_in_build, a `gpu.cuda` entry only warns, and `mn: 32Gi`, `min: 32G` and `host.memroy` are lint errors with a fix. |
| M1-024 | M1 | Typed parameters for M1 host check ids | rust-engineer | 2 | yes | M1-019, M1-018 | Every host id in 01 section 2.7 decodes from a fixture covering each field, each field has a rejecting case, and a missing required threshold is Unsupported. |
| M1-025 | M1 | Typed parameters for M1 net and k8s check ids | rust-engineer | 2.5 | yes | M1-019, M1-018 | Acme-platform.yaml and acme-k8s-only.yaml decode, `needs` on k8s.storageclass is Unsupported, and every net and k8s id in 01 section 2.7 has an accepting and a rejecting fixture. |
| M1-026 | M1 | Semantic validation and structural limits for specs | rust-engineer | 2.5 | yes | M1-019 | Fixtures for 257 checks, 65 distinct hosts counted across `net.egress` endpoints, `net.tls_intercept` hosts and `net.dns` names (INV-11), a duplicate key, a bad product, an unknown metadata key, an unknown bundle key and a relative `file:` collector each exit 64 with the 01 section 2.5 wording; an expired fixture exits 64 with spec_expired, both dates in the first line, before any check runs. |
| M1-027 | M1 | Property tests for rdy_spec::parse | qa-engineer | 2 | yes | M1-017, M1-026 | The 08 section 4 table holds, 10,000 cases for never-panics and limits and 256 for the rest, with a fixed seed on PRs, committed regressions and the suite under 60 s on linux-x64. |
| M1-028 | M1 | linux-x64 root job: nextest archive under sudo, root_* filter, strace installed | release-engineer | 2 | yes | M1-006 | A planted `root_whoami_is_zero` test passes under the root job and is not run by the normal job, and `strace -V` prints in the log. |
| M1-029 | M1 | clap command tree in rdy-cli exposed as library rdy_cli | rust-engineer | 3 | yes | M1-003 | Snapshots of `-h` and `--help` for `rdy`, `rdy run` and `rdy verify` match 07 Appendix A (`--timeout` and `--dry-run` absent), the other commands print the compact form, and bare `rdy`, `rdy spec` and `rdy trust` print help on stdout and exit 0; and `--help` snapshots for every command in 07 A.5 to A.12 match Appendix A. |
| M1-030 | M1 | No-echo rule for usage errors: canaries and near-miss flags (extends M1 error types) | rust-engineer | 2 | yes | M1-029, M1-021 | Canaries in `--tokne=` and `--pasword` and the near-misses `--keey`, `--allow-unsgned` and `--kye` never put a secret, `--key` or `--allow-unsigned` in stderr or `ErrorOutput.fix`, and `clap::Command::get_matches` and `clap::Error::exit` are clippy `disallowed-methods`. |
| M1-031 | M1 | rdy spec lint with errors, warnings and did-you-mean | rust-engineer | 4 | yes | M1-023, M1-026, M1-024, M1-025, M1-029 | Lint exits 1 on acme-platform.yaml with two not_in_build warnings, 2 on `mn: 32Gi` with "did you mean min" and its line, and `--json` output validates as LintReport; `acme-quickstart.yaml` exits 0 and runs on Linux with only M1 checks; every file in examples/specs has a `fix` on each block and warn check, `acme-platform.yaml` has exactly two `not_in_build` warnings, and `acme-inference-gpu.yaml` no longer names `gpu.device_plugin`. |
| M1-032 | M1 | Check trait, Need and Context in rdy-engine | rust-engineer | 3.5 | yes | M1-020 | A fake family with one passing and one need-missing check maps to pass and skipped missing_need through the outcome types, and no CheckError or Support variant can produce not_applicable. |
| M1-033 | M1 | Map outcomes to CheckResult with fix source, partial and needs | rust-engineer | 2 | yes | M1-032 | A spec fix replaces the built-in text on block with fix_source spec and is hidden on skipped, a partial pass on a block check becomes warn unless evidence_only, a Partial OS result is marked partial, and needs carry met flags. |
| M1-034 | M1 | Scheduler with concurrency limit, per-check timeout and panic isolation | rust-engineer | 4 | yes | M1-032 | With the timer on the join handle a check that sleeps forever reports Timeout, one that panics reports Error, Spin on a 2-worker runtime still lets the other checks finish, and `--jobs 500` is capped at 32; and a fake family's passing and need-missing checks come back through the scheduler as pass and skipped missing_need. |
| M1-035 | M1 | Family trait, registry and run plan | rust-engineer | 3.5 | yes | M1-032 | The plan for acme-platform.yaml gives not_in_build for gpu.cuda and aws.iam, unknown_check for a typo id, not_yet_on_os for host checks on Windows, not_applicable only for an `os: [linux]` entry on macOS, per-check host sets, and does no I/O; and acme-platform.yaml with its unknown id reports SKIP with the "needs a newer rdy" reason and fix line, not a parse error. |
| M1-036 | M1 | SEC-19 Confine writes to a new output dir with safe names | rust-engineer | 3 | yes | M1-016, M1-028 | Product `../x` fails validation, a pre-planted symlink is not followed, an existing file is never overwritten and a taken name moves to `-2`, modes are 0700 and 0600 under a setgid parent, the spec copy matches the verified bytes, a killed run leaves no file under a final name, and `--out-dir` and `--no-report` behave as written. |
| M1-037 | M1 | Windows output directory default and reparse-point checks | rust-engineer | 1 | yes | M1-036 | On the Windows CI leg the default lands under %USERPROFILE%\rdy-reports; a pre-planted junction or symlink with the target name is never followed or written through (the name moves to -2); and one swapped in after the folder is made exits 70 before the first check. |
| M1-038 | M1 | Blocking helper and subprocess kill on timeout | rust-engineer | 4 | yes | M1-034 | A check running a script that forks `sleep 600` times out, the whole process group is gone, a child that ignores reaping returns Hung within 1 s of SIGKILL, and `rdy` exits within 2 s of the deadline. |
| M1-039 | M1 | SEC-18 Command policy: search path, declared directories, caps and Windows whoami only | rust-engineer | 2 | yes | M1-038 | Shells and the sudo family are refused, PATH is fixed for root and non-root runs so a fake binary earlier in PATH is not used, LD_PRELOAD in the parent never reaches the child, a declared extra directory resolves, inherited descriptors above 2 that are not close-on-exec are detected and listed by `inherited_fds()` (detect, do not close; ADR 0023, accepted by security-reviewer in PR #53), and on Windows only the constant whoami.exe path runs. |
| M1-040 | M1 | SEC-17 Mediated Context handles with action log and read denylist | rust-engineer | 4 | yes | M1-032, M1-038 | The fixture run's JSON action log lists every command and file (ok file calls past 200 per check, kind and directory fold into one coalesced entry with a count, M1-041) and the redaction count; a read of /proc/1/environ is refused; a Probe call after its check ends is denied and logged; `Probe::exec` runs only commands built from the command table, so an unlisted program, `sh` and `sudo` are refused for the replay backend too; `exec::table::run`, `exec::run` and `ExecSpec::new` are on the root clippy disallowed list; retention drops ok read, read_dir and stat entries first, then failed ones, and never drops a denied entry for another kind (6000 failed reads then one denied read keeps it; 1001 denied execs fold into one coalesced entry). |
| M1-041 | M1 | SEC-63 Result schema caps, identity.kube exec plugin and action log retention | rust-engineer | 1 | yes | M1-020, M1-040 | A 5 MiB message fails the result schema and an exec plugin shows in the JSON. |
| M1-042 | M1 | Privilege snapshot, binary refusal and capability probes | rust-engineer | 2.5 | yes | M1-040 | Injected mismatches of real, effective, saved and filesystem uid or gid, a nonzero CapEff or CapAmb, and AT_SECURE each exit 70 with the hint before the spec is read, recorded whoami output maps High and System to elevated, and needs absent from the plan are not probed; and the fixture run's JSON action log records the identity from the snapshot (moved from M1-040). |
| M1-043 | M1 | Run deadline and watchdog with a report on hang | rust-engineer | 3 | yes | M1-034, M1-036, M1-038 | Under paused time running checks become timeout and unstarted ones run_deadline, a finish at deadline plus 9.9 s keeps the complete report, and two Spin checks with a blocked stdout pipe and a held snapshot lock still give a `complete: false` report and exit 70 within deadline plus 22 s with no child process group left. |
| M1-044 | M1 | Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers | rust-engineer | 1.5 | yes | M1-040 | Every 02 Appendix A entry except the kube ones (M1-102) is a clippy `disallowed-methods` or `disallowed-types` entry, and each entry, used once in tests/lint-wall, fails clippy; and a check crate depending on socket2 fails cargo deny; and adding `walkdir` to rdy-checks-host fails CI; and `rdy_engine::exec::table::run`, `rdy_engine::exec::run` and `ExecSpec::new` are on the check-crate deny list (clippy `disallowed-methods` or `disallowed-types`) and each, used once in a check crate, fails clippy (PR #53 review, PR #58 C1). |
| M1-045 | M1 | File and env read policy in the facade | rust-engineer | 3.5 | yes | M1-040 | /etc/shadow, a symlink to it, a `..` path, a FIFO and /dev/zero under an allowed prefix are refused and logged, a 2 MiB file returns 1 MiB with truncated true, and an undeclared env name is refused; and a file read outside the check's `reads` prefixes is refused and logged. |
| M1-046 | M1 | Closed NativeCall enum in the facade | rust-engineer | 2 | yes | M1-045 | Statvfs outside the check's prefixes is refused, every variant is logged as native, the raw machine id appears nowhere in the report, the variant snapshot test fails on a new variant, and check crates cannot call live_backend. |
| M1-047 | M1 | Fixture format README, .gitattributes and Windows canary | qa-engineer | 1 | yes | M1-006 | `tests/fixtures/README.md` documents every file in 08 section 2 and Appendix A, `.gitattributes` has the 08 lines, and the windows-x64 leg checks out with `core.autocrlf true`, shows `git check-attr text` as `unset` for fixtures and keeps one CRLF fixture intact. |
| M1-048 | M1 | SEC-25 Minimal redactor for evidence, errors and logs | rust-engineer | 2.5 | yes | M1-009, M1-020 | Overlapping spans give one placeholder, equal secrets share a tag per Redactor, `password=[REDACTED:x:00000000]hunter2` is redacted, and `Redacted` has no public constructor or Deserialize. |
| M1-049 | M1 | Replay backend and fixture loader in the 08 format | rust-engineer | 4 | yes | M1-045, M1-046 | A host.memory fixture runs with no real file read, an unrecorded argv fails with NotRecorded, a recorded link-local lookup is refused by the address rule, and the release feature tree excludes `testing`; a `/proc/<pid>/fd` symlink fixture and an unreadable audit log load on the Windows leg, and placeholders compare equal across runs; a 08-format `fixture.toml` with `base`, `remove` and `answers` loads, a manifest symlink to `/etc/shadow` is Denied, `delay_ms` and `blackhole` run on the tokio clock, and the `checks/_policy/symlink-to-shadow` case exists. |
| M1-050 | M1 | Fixture lint as a nextest test | qa-engineer | 1.5 | yes | M1-047, M1-049, M1-035 | A planted public hostname, a `\r` outside `crlf`, a file named `con.json`, a 2 MiB file, a public IP and a duplicate argv key each fail with the file named, and deleting `checks/_policy/symlink-to-shadow`, the pass case of `checks/host.memory` or the Timeout case of `checks/host.disk` each fails the lint with the path named. |
| M1-051 | M1 | Engine test helpers FakeCheck, run_fixture and normalize | qa-engineer | 1.5 | yes | M1-049 | Scheduler tests use FakeCheck for every status including Spin, `Fake::Block` waits on a receiver the test releases, `assert_within_manifest` fails on an undeclared read, and `normalize` gives equal reports for `jobs = 1` and `jobs = 8`. |
| M1-052 | M1 | Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check | qa-engineer | 1 | yes | M1-051 | A changed output fails with a diff and an `.actual` file, a missing golden fails, `UPDATE_GOLDENS=1` is refused when `CI` is set and never touches `tests/fixtures/redaction/**`, and `cargo xtask goldens check` fails on an orphan. |
| M1-053 | M1 | Add bucket to CheckResult and sort by it in terminal and HTML | rust-engineer | 1 | yes | M1-020, M1-052 | A fixture with every outcome sorts blocker, required_not_run, warning, passed, not_applicable, and the bucket counts equal the summary. |
| M1-054 | M1 | Summary line grammar and nothing-verified last line | rust-engineer | 1 | yes | M1-020, M1-052 | Golden strings for the three samples in 01 section 5.3, each last line in its table, and singular and plural forms pass. |
| M1-055 | M1 | HTML-safe deterministic JSON writer with size caps | rust-engineer | 1.5 | yes | M1-020, M1-052, M1-041 | A hostname with `</script>` is written as `\u003c/script\u003e`, and the .json file, `--json` stdout and the HTML copy hash the same; the writer truncates lists past their schema caps, `observed` and `expected` past three levels and past 64 keys, and sets `truncated`, so a large real cluster still gives a valid report. |
| M1-056 | M1 | Redacting tracing writer, panic hook and CLI error text | rust-engineer | 2 | yes | M1-048 | Canaries in env, kubeconfig, command output and a tracing field never reach stderr at RUST_LOG=trace (the proxy URL canary moves to M1-060 and the JSON and HTML parts to M1-062, correction PC-43). |
| M1-057 | M1 | Wire rdy run end to end: load, needs, families, engine, report, exit code | rust-engineer | 3 | yes | M1-029, M1-035, M1-034, M1-033, M1-021, M1-055, M1-036, M1-037, M1-042, M1-061 | `rdy run examples/specs/acme-platform.yaml --allow-unsigned --json` writes a new report directory, prints one Report on stdout that validates against the result schema, lists every check (SKIP "not built yet" until its family lands) and exits by the verdict; the run report records `identity` from the privilege snapshot (M1-042); a warn or block result with no fix of its own and no spec `fix` shows the check's `CheckMeta.remediation`, not the generic no-advice text; and `cargo xtask checks` reads the same family list as `rdy run`; and the run builds the probe hub from the run's redactor and registers each declared secret-named env value before the first tracing event and the first check (PR #96 reviews). |
| M1-058 | M1 | Ctrl-C in M1: abort, remove the empty report folder, exit 70 | rust-engineer | 1.5 | yes | M1-034, M1-036, M1-002, M1-038, M1-057 | A pty test sends SIGINT once and gets the two-line error of 07 section 5.1, exit 70, no report folder and no child process left, SIGTERM does the same, and `--json` prints an ErrorOutput with code `interrupted`. |
| M1-059 | M1 | --no-network and --jobs flags | rust-engineer | 1 | yes | M1-034, M1-029, M1-028, M1-057 | `--no-network` skips network and Kubernetes checks as `missing_need` with zero `socket(2)` calls under strace and no `connect` entries in the action log, `--jobs 500` prints a cap note, and `--jobs 0` exits 64. |
| M1-060 | M1 | M1 redaction rules for URLs, auth headers, AWS keys, PEM keys, JWTs, rdy tokens and key names | rust-engineer | 3.5 | yes | M1-048, M1-052, M1-061 | The 23 positive corpus inputs come out typed with quotes kept, and `secretName: acme-tls`, `${DB_PASSWORD}`, `passed: 12` and a certificate are unchanged; and URLs in evidence are stored as `scheme://host:port/path`, and a proxy URL with userinfo logged at `RUST_LOG=trace` never reaches stderr (the ignored test in `tests/log_redaction.rs` is enabled); and M1-061's held cut-buffer cases in `tests/cut_buffers.rs` (an AWS key id and a URL with userinfo ending at cap minus 1 to cap minus 64, and a complete PEM block ending there, for every cap) are enabled and pass (PR #96 reviews). |
| M1-061 | M1 | Redact facade-truncated buffers and a run-scoped known-secret set | rust-engineer | 2 | yes | M1-048, M1-045 | A PEM key, an AWS key id and a URL with userinfo placed across the stdout, stderr, file and tail caps at offsets cap minus 1 to cap minus 64 never appear in JSON, HTML or stderr, and the kubeconfig token is redacted wherever it appears. |
| M1-062 | M1 | Redact then cap every Report string and return RedactedReport | rust-engineer | 2.5 | yes | M1-048, M1-033 | A PEM key across a 64 KiB cap is fully redacted, results are redacted as they complete, the 01 samples round-trip byte-identical apart from planted canaries, `by_rule` is the same with RUST_LOG unset and at trace, the watchdog report is redacted, and write_json, render_html and the terminal renderer do not compile with a plain Report. |
| M1-063 | M1 | SEC-26 M1 redaction corpus, first 28 cases (0.1.0 gate) | qa-engineer | 1.5 | yes | M1-060, M1-052 | At least 28 synthetic cases (04 section 4 and Appendix D, `FLOOR` 28), secrets built from parts and including negatives, run in `cargo test` on five legs with zero misses, and the harness fails on a survivor or on a rule or syntax form with no positive case. |
| M1-064 | M1 | Shared helpers: units, quantities, dotted version compare, nominal band, severity cap | check-author | 1.5 | yes | M1-032 | Table tests pass, including 31.3 GiB against `min: 32Gi` and 3.8 GiB against `4Gi` passing with a note, `535.54.03` below `535.104.05`, and `severity: warn` capping a fail. |
| M1-065 | M1 | cgroup helper for memory, cpu and controllers | rust-engineer | 1.5 | yes | M1-049 | Fixtures for a v2 nested slice, a v1 tree and an unlimited cgroup return the minimum along the parent chain, treat `max` and `9223372036854771712` as unlimited, and read `memory.swap.max`. |
| M1-066 | M1 | Command table and argument allow-lists from 03 Appendix A | check-author | 1 | yes | M1-039 | Every 03 Appendix A row is a typed entry in the SEC-18 policy table with absolute path and timeout, and a test fails when fix text names a sysctl or command missing from the allow-list files. |
| M1-067 | M1 | OS support table and compile stubs for rdy-checks-host | check-author | 1 | yes | M1-035 | All five CI targets build, OS support is taken from the backend's OS so a Linux fixture runs the Linux parser on every leg, only `probe.native` closures are cfg-gated, and live host checks on macOS and Windows report not_yet_on_os. |
| M1-068 | M1 | host.disk (Linux: statvfs flags, mountinfo with escapes, whole-component match, hung-mount timeout) | check-author | 3.5 | yes | M1-064, M1-049, M1-171 | Golden results for plenty, tight, no inode accounting, `noexec` /tmp, NFS, a `\040` mount point and the hung-mount fixture. |
| M1-069 | M1 | host.memory (meminfo, swap, cgroup limit, nominal band) | check-author | 2.5 | yes | M1-064, M1-065 | A 31.3 GiB meminfo against `min: 32Gi` passes with a note, 24 GiB blocks, `swap: off` with swap blocks, and a nested cgroup limit is reported. |
| M1-070 | M1 | Terminal styling layer: colour choice, width, escaping and ASCII text | rust-engineer | 1 | yes | M1-029, M1-052 | Table tests cover the colour rules of 07 section 6, `TERM=dumb` and `COLUMNS` clamping, and a hostname holding an ANSI escape and a bidi override prints as `\x1b` and `\u{202e}`. |
| M1-071 | M1 | host.cpu (cores with quota, arch, flags through std macros, levels, Rosetta) | check-author | 2 | yes | M1-064, M1-065 | A cpuinfo without `avx2` blocks with the passthrough fix text and `cpu.max` 200000/100000 reports 2 cores (Rosetta detection moves with the macOS sources). |
| M1-072 | M1 | host.ports (Linux /proc/net TCP and UDP, lazy owner lookup, ephemeral overlap) | check-author | 3 | yes | M1-049, M1-169 | 6443 held by a named process blocks, the same without root reports owner unknown, a UDP listener is found, `[::]` covers IPv4, and the fix text names `ip_local_reserved_ports`. |
| M1-073 | M1 | host.os (os-release, uname, FIPS, container and WSL detection, match rules) | check-author | 1.5 | yes | M1-049 | RHEL 9, Ubuntu 22.04, Alpine, Rocky (`ID_LIKE`), Amazon Linux 2 and Linux Mint fixtures match or miss a `supported` list as the rules say. |
| M1-074 | M1 | In-process CLI entry point rdy_cli::run taking a Backend | rust-engineer | 2.5 | yes | M1-029, M1-049, M1-042 | A test calls `run` with the Replay backend, RunHooks and capture buffers and gets the exit code, stdout and stderr, `main.rs` calls it with the Live backend only, and security-reviewer signs the ADR 0011 decision 4 amendment; the entry point calls the privilege gate (`gate_then`, M1-042) before any command reads a spec or writes trust.yaml; on the linux-x64 leg, in a test gated on `RDY_REQUIRE_SETUID=1` (CI installs `libcap2-bin`), a setuid-root `rdy` (`chown root`, `chmod u+s`) and, separately, an `rdy` with a file capability (`setcap cap_net_raw+ep`), each run as the CI user with a spec path that is a FIFO with no writer, exit 70 within 5 s, which shows the spec is never opened. |
| M1-075 | M1 | Env-level harness, in process | qa-engineer | 2.5 | yes | M1-074, M1-052, M1-069 | The tiny env `host-min` (host.memory only, os-release, meminfo, a spec) gives exit 0, `report.json`, `terminal.txt` and equal reports at jobs 1 and 8 on five legs, with clock, run id and environment pinned, and adding an env directory adds a test with no code change. |
| M1-076 | M1 | Spec renderer for objects and scalars | docs-writer | 2.5 | yes | M1-013, M1-022 | The readiness schema renders to a golden Markdown file with one table row per property. |
| M1-077 | M1 | askama HTML report with inline CSS, dark mode and print | rust-engineer | 3.5 | yes | M1-020, M1-055, M1-052, M1-041 | The golden HTML shows the verdict and blocks first and passes an HTML validator with lang and color-scheme set, and the golden HTML run details show the credential plugin name (01 section 6, item 6) for a fixture with `identity.kube.exec_plugin` set. |
| M1-078 | M1 | Embed result JSON in the HTML report safely | rust-engineer | 1.5 | yes | M1-077 | A hostname of `</script><img onerror>` round-trips through the embedded JSON unchanged and renders as text, and the CSP and link attributes match ADR 0003 (INV-16); CI fails on any `\|safe` in templates, and the golden HTML data-sha256 equals the SHA-256 of the golden .json (SEC-64). |
| M1-079 | M1 | HTML print override, labels and legend | rust-engineer | 1 | yes | M1-077 | A template grep finds no raw JSON key as visible text, and a Rust test asserts the print stylesheet sets text black on white and overrides the dark palette. |
| M1-080 | M1 | HTML fix source label and action log table | rust-engineer | 1 | yes | M1-077, M1-033, M1-040 | The golden blocked HTML labels vendor fix text with the product name and shows the action log as one table with no details element. |
| M1-081 | M1 | HTML Found and Needed rendering and the footer link (extends HTML print override) | cli-ux | 1.5 | yes | M1-079 | `_bytes`, `_ms` and `_percent` values print as sizes, milliseconds and percents, the footer link has only `ref=report` and the product with `rel="noopener noreferrer"`, and print has a top padding equal to the banner height. |
| M1-082 | M1 | HTML structure test: headings, landmarks, tables and links | cli-ux | 1 | yes | M1-081 | A Rust test over the three goldens asserts heading levels never skip, `lang` is set, every `h3` has a status word, tables have `th scope`, ids are unique, every `href="#id"` has a target, and no other `href` or `src` is anything but `data:`, the footer link or the repo link. |
| M1-083 | M1 | Golden tests for JSON and HTML reports | qa-engineer | 1.5 | yes | M1-078, M1-052, M1-060, M1-061 | `render_html` and `write_json` on the three result fixtures under tests/fixtures/results/ (07 B.1 to B.3, the 01 samples) produce goldens that pass the static checks (CSP, no `<link>` or `url(`, no off-file src or href, `</script>` hostname round trip) on five legs; and the HTML of a fixture run holding a machine id, cut-buffer canaries and a known secret contains none of them (the HTML halves of M1-046 and M1-061, PR #94 and PR #96 reviews). |
| M1-084 | M1 | Spec renderer for enums, oneOf or allOf if/then variants and YAML examples, with the missing-description failure | docs-writer | 1.5 | yes | M1-076 | Every schema example validates and renders as YAML, and a property without a description fails `cargo xtask docs` with its path. |
| M1-085 | M1 | Spec and result reference pages with hand-written intro | docs-writer | 1 | yes | M1-084 | /reference/spec/ and /reference/result/ build, and each schema field appears once. |
| M1-086 | M1 | Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | cli-ux | 4 | yes | M1-053, M1-070, M1-054, M1-057, M1-052, M1-060, M1-061 | The terminal renderer on the three result fixtures under tests/fixtures/results/ equals 07 C.17, C.18 and 2.7 byte for byte at width 100 with `--color never`, the goldens C.12, C.13 and C.14 match, and the last line is the verdict; and a PEM key, AWS key id and URL with userinfo cut at a buffer edge never reach stderr (the stderr half of M1-061, PR #96 review). |
| M1-087 | M1 | Exit-code golden suite for 0, 1, 2, 64 and 70 | rust-engineer | 1 | yes | M1-086, M1-030, M1-075 | Assert_cmd runs the rows that need no fixture backend (bad flag 64, missing file 64, unwritable `--out-dir` 70) and compares exit code and stderr golden, and with `--json` validates stdout against the schema; the unsigned row joins with the M1 verify ticket and exits 0, 1 and 2 are the fixture env goldens. |
| M1-088 | M1 | --json stdout hygiene on every exit path and the static TTY line | rust-engineer | 1.5 | yes | M1-087, M1-043, M1-086 | For each exit path except the watchdog, stdout is exactly one JSON document equal to the `.json` file with no ANSI under `--color always`, `--no-report --json` still prints the Report, and on the watchdog path with a blocked stdout pipe the exit is 70 and the folder holds a Report with `complete: false`; and a pty capture shows the static "Running N checks..." line before the first check and nothing on a pipe, `--quiet` or `TERM=dumb` (Unix legs). |
| M1-089 | M1 | CheckMeta in the check registry, read by xtask | rust-architect | 2 | yes | M1-035, M1-013 | Xtask lists each registered check with id, family, title and remediation, and fails on an empty remediation. |
| M1-090 | M1 | Loopback network test support (TLS server with generated CA, CONNECT proxy modes, closed port, never-accepting listener, reset after ClientHello, 302 server, dual-stack case) | rust-engineer | 3 | yes | M1-049 | A smoke test starts each server and a raw client observes the expected behaviour on Linux, macOS and Windows CI, and `cargo deny check` passes with `rcgen` on ring. |
| M1-091 | M1 | Facade TCP attempts, proxy CONNECT and per-check host sets | rust-engineer | 4 | yes | M1-040, M1-090, M1-061 | A host listed only by another check is denied, a CONNECT to a literal 169.254.169.254 is refused before any byte is sent, proxy 403 and 407 return typed errors, and Proxy-Authorization never appears in the log; and the action log has one entry per tcp call, proxy CONNECT included (moved from M1-040); and the proxy password is registered as a known secret, raw and percent-decoded, when the proxy URL is parsed, and the run exits 70 if the set refuses it (PR #96 reviews). |
| M1-092 | M1 | Facade TLS with system roots and the recording chain probe | rust-engineer | 3 | yes | M1-091 | Against loopback servers a test-CA chain validates only when the CA is in the fixture system bundle, tls_chain returns the chain without sending application data, SNI always equals the permitted host, and `cargo tree -i aws-lc-sys` is empty; and the action log has one entry per tls call (moved from M1-040); and the `SystemRoots` native arm caps the number of certificates and each one's size (PR #94 review). |
| M1-093 | M1 | Facade HTTP/1.1 probe with 64 KiB discard and no redirects | rust-engineer | 2 | yes | M1-092 | A 302 returns its Location host without a second request, a body canary never reaches the report, and each failure class is produced by its loopback case; and the action log has one entry per http call (moved from M1-040). |
| M1-094 | M1 | SEC-21 Egress address policy, no redirects, no bodies | rust-engineer | 1.5 | yes | M1-093 | Link-local, metadata and IPv4-mapped targets are refused when they come from DNS answers and as CONNECT targets, an unlisted endpoint is refused, and more than 64 distinct hosts fail spec validation with exit 64; and the GCP IPv6 metadata address `fd20:ce::254` is refused (INV-12 and ADR 0014 decision 2 gain it; PR #91 review). |
| M1-095 | M1 | net.egress staged connector (lookup, dual-stack connect, TLS, ALPN) | check-author | 2 | yes | M1-064, M1-090, M1-092 | Loopback cases give per-stage timings, a dead IPv6 address falls through to IPv4 and is named, and a scripted blackhole yields the `blackhole` class. |
| M1-096 | M1 | net.egress HTTP stage and failure classes | check-author | 2.5 | yes | M1-095, M1-060, M1-093 | Refused, TLS unknown issuer, expired certificate, reset after hello and HTTP status classify correctly, and a query-string token never reaches the result. |
| M1-097 | M1 | net.egress via proxy (own CONNECT, absolute-form for http, 407) and redirect host evidence | check-author | 2 | yes | M1-096, M1-094 | CONNECT modes work, 403 and 407 give the right text, an `http://` endpoint uses the absolute form, and a 302 records the `Location` host and is not followed. |
| M1-098 | M1 | net.proxy (process env, systemd drop-ins, NO_PROXY coverage, PAC detection, reachability) | check-author | 2.5 | yes | M1-060, M1-090, M1-091 | A shell proxy with no docker drop-in warns and prints the drop-in text, NO_PROXY coverage is reported, a PAC case warns without any fetch, and userinfo and the planted `auths` secret never appear. |
| M1-099 | M1 | net.tls_intercept recording verifier and classes | check-author | 1.5 | yes | M1-095 | Generated chains classify as public, trusted-by-this-machine-only and unknown-CA, and an expired leaf with a pinned clock gives `clock_or_expiry`. |
| M1-100 | M1 | net.tls_intercept evidence, trust-store report and fix text | check-author | 1.5 | yes | M1-099 | The result lists issuer, chain depth, root hash (placeholder in goldens) and store location per OS, the empty-store case says "no OS trust store found", and the fix text carries the Debian, RHEL, SUSE, Alpine and Java forms. |
| M1-101 | M1 | Security review of the TLS recording verifier and 03 Appendix A | security-reviewer | 1.5 | yes | M1-100, M1-066 | `docs/plan/reviews/tls-verifier-review.md` exists, lists zero open must-fix items, and Appendix A matches the command table in code. |
| M1-102 | M1 | Kube client from kubeconfig or in-cluster with rustls and timeouts | rust-engineer | 3.5 | yes | M1-032 | The context, server and kubeconfig user are passed to an announce callback before the first request; with no kubeconfig, load fails with `no kubeconfig found` and the 07 hint; exec plugin output never appears at RUST_LOG=trace, with any `interactiveMode` and with no TTY; and each 02 Appendix A kube entry, re-checked against the pinned kube version, is a clippy entry in the crate, and a committed use file exercises every entry for M1-107. |
| M1-103 | M1 | Read-only guard layer and test for rdy-checks-k8s | k8s-expert | 3.5 | yes | M1-102 | The runtime layer rejects any write, any POST other than the three reviews, a SelfSubjectReview with a different body or a query string, and any secrets path, and a mock API server behind guarded_service records only allowlisted requests across the full k8s fixture run (INV-14); and `examples/rbac/rdy-readonly.yaml` exists and the guard test passes on kind with only that role (SEC-24); and the action log has one entry per kube call (moved from M1-040). |
| M1-104 | M1 | Kube guard path parser, resource allowlist and pending log entries | rust-engineer | 3.5 | yes | M1-103 | `%73ecrets`, `secrets` in every segment position, `/api/v1/namespaces/x/finalize`, GET pods/exec with Upgrade, a dryRun POST, Impersonate-User on a GET and an unlisted resource are each refused and logged, `/api/v1/namespaces/secrets` is allowed, every ALLOWED entry is cited by a CheckInfo, and a dropped request leaves a timeout entry with its check id. |
| M1-105 | M1 | Kube mock harness (tower service replaying api/ JSON, paging and 410, selectors, legacy discovery, review table) | rust-engineer | 4 | yes | M1-049, M1-103 | A `kube::Client` on the mock with the guard in front pages through a recorded `nodes.json`, restarts once on `410 Gone`, and answers a `SelfSubjectAccessReview` from a table; `ReadOnlyClient` gains the discovery routes (`/api`, `/apis`, `/apis/<group>/<version>`) and a raw route that sends the fixed `SelfSubjectReview` bytes, both through the guard; and after every fixture run the harness checks each request the mock recorded against `ALLOWED`, with a test where an unlisted recorded request fails the run, so each k8s check's fixture tests prove INV-14 with real check code (PR #92 reviews); each recorded request also matches an entry whose `checks` holds the check id in its log entry, with a test where a request logged under a check id that does not cite its entry fails the run (PR #95 review). |
| M1-106 | M1 | k8s.version (gitVersion parse, distribution, discovery API availability) | check-author | 1.5 | yes | M1-105 | EKS `v1.29.4-eks-abc123` parses to 1.29, plain `v1.29.4` with Azure labels is AKS, OpenShift reads `ClusterVersion`, and a missing `autoscaling/v2` blocks. |
| M1-107 | M1 | Family probe hook and lazy KubeContext probe | rust-engineer | 3 | yes | M1-042, M1-102, M1-044, M1-092, M1-061 | A spec with no k8s checks loads no kubeconfig and sends no request, `--no-network` builds no client, and a fake exec plugin that sleeps 600 s makes kube_context unavailable after 10 s with no worker blocked; and with no kubeconfig every k8s check is SKIP with the hint, the cluster line (context, server, user) prints to stderr before the first request, and after an exec plugin timeout the plugin process does not keep rdy from exiting (the ADR 0031 residual: kube does not kill the plugin); and each kube entry from M1-102's committed use file, used once in tests/lint-wall, fails clippy; and a Windows `.cmd` exec plugin test passes on the Windows leg; a bare plugin name is resolved on PATH for the exec action-log entry; and with no CA in the kubeconfig, the client trusts the facade SystemRoots (ADR 0031 decision 9); and the credentials of every kubeconfig user and the exec plugin's token are registered as known secrets before the cluster line, the run exits 70 if the set refuses one, and a kubeconfig canary at `RUST_LOG=trace` (including a kubeconfig parse error) never reaches stderr, the JSON or the log (PR #96 reviews). |
| M1-108 | M1 | kind integration job with a restricted PSA namespace and review round trips | rust-engineer | 2 | yes | M1-102, M1-103, M1-006, M1-106 | CI on the oldest and newest supported minors runs `tests/live_cluster.rs` (the ignored kind test from M1-102), passes `k8s.version`, a `SelfSubjectReview` and access reviews, and shows `restricted` enforce on the test namespace; and with `examples/rbac/rdy-readonly.yaml` applied and `RDY_READONLY_KUBECONFIG` set to a kubeconfig for its service account, `the_readonly_role_serves_every_allowed_read_and_nothing_else` passes (SEC-24, carried from M1-103). |
| M1-109 | M1 | k8s.access (kubeconfig, version, SelfSubjectReview, anonymous warn, exec classes, proxy resolution) | check-author | 3 | yes | M1-105 | Fixtures for good, 401, 403, x509 error, expired cert, anonymous kubeconfig, `proxy-url`, env-only proxy, Rancher path prefix and a plugin needing login give the expected result and fix text; and the `SelfSubjectReview` uses M1-105's raw route, not a typed k8s-openapi review (PR #92 review). |
| M1-110 | M1 | k8s.storageclass (normalised provisioners, CSINode evidence, default rules, provisioner table) | check-author | 3 | yes | M1-105 | EKS `gp2` with no CSI add-on blocks, k3s `local-path` passes with "driver not verified", two defaults block on 1.25 and warn on 1.28, and `CSINode` forbidden gives partial. |
| M1-111 | M1 | k8s.rbac (SelfSubjectReview, access reviews, non-resource items, escalate and bind as warn) | check-author | 2.5 | yes | M1-105 | A table with two denied items blocks and lists both with reasons and the `denied` versus not-allowed distinction, and a denied `escalate` warns; and a spec `as:` uses `ImpersonateAs::new` and `guarded_service_as`, is refused with a fix hint when the kubeconfig already sets any `as` field, a wire test on the real client stack sees exactly one `Impersonate-User` and no `Impersonate-Group`, and the log entry marks the impersonated call (PR #95 reviews). |
| M1-112 | M1 | Refuse --password on argv and read key passwords from env or file | rust-engineer | 1 | yes | M1-029 | `--password` exits 64 with the reason of 07 section 10, and `RDY_KEY_PASSWORD` and `--password-file -` sign a spec in CI without a prompt. |
| M1-113 | M1 | k8s.nodes allocatable, node filters, conditions, zones and pod-count limit | check-author | 2.5 | yes | M1-105 | Cordoned, Windows, Fargate and tainted nodes are excluded, `cpu: 7` passes on an 8 vCPU node, a forbidden Node list is partial, and an autoscaled single node warns instead of blocking. |
| M1-114 | M1 | k8s.admission PSA labels, policy engine and SCC discovery | check-author | 2 | yes | M1-105 | A `restricted` namespace blocks a `privileged` need and the fix says `privileged`, OpenShift discovery gives the SCC text, and Gatekeeper and Kyverno discovery warns with names. |
| M1-115 | M1 | Review k8s checks and fixtures (semantics, API groups, RBAC degrade, per-distro sets) | k8s-expert | 1.5 | yes | M1-113, M1-110, M1-111, M1-114, M1-109, M1-106 | `docs/plan/reviews/k8s-checks-review.md` exists and lists zero open must-fix items, and the guard's citation test has an empty `NOT_BUILT_YET` with every k8s check registered in `infos()`, and every `ALLOWED` entry and citing check pair is hit by some fixture (PR #95 reviews). |
| M1-116 | M1 | Check family renderer and the host, network and Kubernetes pages with hand-written intros | docs-writer | 3 | yes | M1-013, M1-089, M1-072, M1-073, M1-097, M1-098, M1-100, M1-115 | Each family page under docs/ has one H2 per check and each Remediation block equals the registry string, and the host, network and Kubernetes pages list every M1 check of their family; no id still in `HostFamily::stub_ids()` gets a section; and reads are listed without an OS split until the manifest is keyed by OS. |
| M1-117 | M1 | Fixture env all-pass | qa-engineer | 2.5 | yes | M1-075, M1-069, M1-095, M1-106 | The env exits 0 on all five legs with golden JSON, HTML and terminal text, and 31.3 GiB against `min: 32Gi` passes with its note. |
| M1-118 | M1 | Fixture envs warnings-only, all-block and no-privileges | qa-engineer | 2 | yes | M1-117, M1-068, M1-072, M1-096, M1-098, M1-110, M1-111 | Exit codes 1, 2 and 2 with goldens; `no-privileges` uses the root-optional owner lookup of host.ports and a missing kubeconfig, shows `partial` results and `missing_need` skips, and gives verdict reason `required_check_not_run`. |
| M1-119 | M1 | Timeouts env and scheduler timeout and deadline tests under paused time | qa-engineer | 2 | yes | M1-117, M1-043 | The `timeouts` env (hung statvfs, black-hole endpoint, slow `/version`) runs in process under paused time at `jobs = 1` and `jobs = 8`, every hung source gives `Timeout`, and the run ends inside `deadline_ms` in virtual time. |
| M1-120 | M1 | Verify minisign signatures in rdy-spec against a trust store with product binding | rust-engineer | 4 | yes | M1-016, M1-017 | A tampered byte, a changed comment, a legacy Ed signature, a missing prefix, a product mismatch and an unpinned key each fail with a distinct SignatureError before the YAML is parsed (a parser spy proves it), Wycheproof vectors pass, and the signed fixtures verify on the windows-x64 leg with `core.autocrlf true`, and a proptest of 256 cases shows that changing any byte of the signed fixture gives a SignatureError with the parser spy count at 0. |
| M1-121 | M1 | Trust store load and save in user and system locations | rust-engineer | 3.5 | yes | M1-120 | As root with HOME and XDG_CONFIG_HOME pointing at a user store only /etc/rdy/trust.yaml is read, as a user the user file then the system file, and symlinked, non-root-owned or group-writable files exit 64 with trust_store_insecure; and the result carries signature.key_fingerprint, and a forged key with the vendor's key id fails (SEC-61). |
| M1-122 | M1 | SEC-60 Root trust lookup touches no user path, Windows store ACL rules | rust-engineer | 1.5 | yes | M1-121, M1-028 | On Windows CI a ProgramData\rdy directory created by a non-admin user, or with a Users write ACE, exits 64 with trust_store_insecure, and a root run under strace opens no path under SUDO_USER's home. The real-binary strace check of `rdy verify` moves to M1-126 (correction 10). |
| M1-123 | M1 | Prompt helper: y/N, no-terminal refusal and hidden input | rust-engineer | 1.5 | yes | M1-029 | Pty tests cover `y`, `yes`, `n`, empty and EOF, a missing TTY exits 64 with the fix line of 07 C.10, and a password is read with echo off. |
| M1-124 | M1 | Review CONTRIBUTING.md on a fresh clone | devrel | 1 | yes | M1-006, M1-057 | Every command in the "Build and test" block of CONTRIBUTING.md runs green on a clean checkout, and `cargo run -p rdy -- run examples/specs/acme-quickstart.yaml --allow-unsigned --out-dir /tmp` prints the banner and exits as the file says. |
| M1-125 | M1 | rdy spec keygen and rdy spec sign | rust-engineer | 4 | yes | M1-120, M1-023, M1-123, M1-112 | An rdy signature verifies with stock minisign and the reverse with the 01 4.2 comment, keys are 0600 `create_new` and encrypted unless `--unencrypted`, sign refuses a lint error, the typos `mn: 32Gi`, `min: 32G` and `host.memroy` and a key readable by others, and it prints the fingerprint. |
| M1-126 | M1 | rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | rust-engineer | 4 | yes | M1-125, M1-057, M1-087, M1-031 | Every code in 01 section 4.8 comes from a fixture, unsigned exits 64 and the exit-code suite gains its unsigned row, `--allow-unsigned` runs and both reports say unsigned but still exits 64 for an unpinned key, an invalid signature and a permission-denied sidecar, and no ErrorOutput.fix or stderr line contains `--allow-unsigned`; and golden output for 07 C.4 and C.8 matches; on windows-x64, with a ProgramData trust store present, `rdy verify --key <pub>` exits 0 and `rdy verify` without `--key` exits 64 with `trust_store_insecure` (`--key` runs never read the trust stores; ADR 0027); and the INV-04 strace check runs the real `rdy verify` on a signed fixture as root (carried from M1-122). |
| M1-127 | M1 | Real-binary smoke on five legs: live exit codes 0, 1, 2 and 64 | qa-engineer | 3 | yes | M1-126, M1-090, M1-028 | The test binds a loopback listener on port 0, signs three net-only specs at test time and runs the shipped `rdy` live on all five legs: an open port gives 0, a `severity: warn` check on a closed port gives 1, a `severity: block` check on a closed port gives 2, an unsigned spec gives 64, and a spec with one byte flipped gives 64 even with `--allow-unsigned`. |
| M1-128 | M1 | SEC-22 No-phone-home strace test on Linux CI | qa-engineer | 1 | yes | M1-094, M1-090, M1-028, M1-127 | Under `sudo unshare -n` and `strace -f -e trace=connect,sendto,sendmsg`, every destination in the fixture suite is a loopback fixture address. |
| M1-129 | M1 | First run page and M1 example spec | docs-writer | 1 | yes | M1-126, M1-031, M1-085 | Each command on the page is a case in the M1 integration tests, and the page shows the output shape those tests check. |
| M1-130 | M1 | SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading | rust-engineer | 2 | yes | M1-126, M1-086 | Both 01 4.7 banners match byte for byte, a `--key` run prints KEY NOT PINNED on stderr and every HTML page, and the fix label reads "From the spec file (not verified)" for unsigned and flag-key runs; and a 130-character message wraps at 100 with a hanging indent, both banners print before the first check and again above the verdict, and both Tip forms of 07 2.1 match. |
| M1-131 | M1 | rdy trust add, list and remove | rust-engineer | 2.5 | yes | M1-121, M1-123, M1-125 | `trust add` without a TTY and without `--yes` exits 64 with a fix line, with `--yes` it pins and `trust list` shows key id and fingerprint, and `run --key` leaves the store unchanged; and golden output for 07 C.9 and C.10 matches with the fingerprint in groups of four. |
| M1-132 | M1 | Security review of spec signing and trust store | security-reviewer | 1.5 | yes | M1-126, M1-122, M1-121, M1-131 | `docs/plan/reviews/signing-review.md` exists and lists zero open must-fix items before the 0.1.0 tag. |
| M1-133 | M1 | Install, exit codes and unsigned pages | docs-writer | 2 | yes | M1-015, M1-085, M1-087 | The install-only blocks run in CI against the latest alpha's pinned install.sh URL on a fresh Linux container, the exit codes page lists 0, 1, 2, 64 and 70, and `https://docs.getrdy.io/unsigned` redirects to the Markdown page on what `--allow-unsigned` and `--key` do; and the unsigned page has a Windows section on verifying with the vendor key while Windows trust stores are refused (ADR 0027). |
| M1-134 | M1 | Sign and verify page | docs-writer | 1.5 | yes | M1-125, M1-126, M1-131, M1-085 | The page's commands run as M1 integration test cases and verify a copy of the example spec signed with a test key. |
| M1-135 | M1 | Golden README transcripts from Replay envs (acme-quickstart refusal, NOT READY, READY; acme-platform skipped checks) | qa-engineer | 1.5 | yes | M1-118, M1-086, M1-126 | Each README transcript block equals its golden file, made in process from the Replay envs (all-pass, all-block and the unsigned variants): the 07 C.5 refusal with exit 64, the unsigned NOT READY run with exit 2, the unsigned READY run with exit 0, and the acme-platform run ending `NOT READY: 3 required checks were not run` with exit 2. |
| M1-136 | M1 | docs-test runner for README and docs tested blocks | qa-engineer | 2 | yes | M1-014, M1-133, M1-129 | A CI job runs every fenced command marked testable in README.md and the docs pages live against the build and asserts only the declared exit code set and a shape regex per block (for example `^NOT READY`), never host numbers, and every README transcript is diffed against its golden file. |
| M1-137 | M1 | README draft from 10 section 1 | devrel | 2.5 | yes | M1-031, M1-135, M1-126, M1-015, M1-136 | README.md exists, its install block and manual path equal the text in 06, all testable commands pass the docs-test harness, every transcript is pasted from a golden file, and no command line contains `--timeout`, `--dry-run`, `--plan` or `self-update`. |
| M1-138 | M1 | Tag and release 0.1.0 | release-engineer | 1 | yes | M1-132, M1-063, M1-001, M1-101, M1-115, M1-137, M1-133, M1-027, M1-037, M1-041, M1-058, M1-059, M1-044, M1-050, M1-056, M1-061, M1-062, M1-067, M1-071, M1-080, M1-082, M1-083, M1-088, M1-116, M1-104, M1-107, M1-108, M1-119, M1-128, M1-130, M1-134, M1-124, M1-168, M1-074 | `v0.1.0` is published as a signed pre-release and `scripts/verify-release.sh v0.1.0` passes on a clean machine; the replay fixture envs exit 0, 1 and 2 on all five legs; the real-binary smoke exits 0, 1 and 2 live on all five legs; unsigned and tampered specs exit 64 on all five; every 0.1.0-gate security ticket (SEC-04, SEC-05, SEC-17, SEC-19, SEC-21, SEC-22, SEC-24, SEC-25, SEC-26 first 28, SEC-32) is closed, except that for SEC-04, SEC-05 and SEC-32 the repo side is closed and their hand steps are tracked in Founder hand steps; and RELEASING.md and 06 say that `v0.1.N` ships weekly until M1 ends and `0.2.0-alpha.N` starts with M2. |
| M1-139 | M1 | Alpha announcement to design partners | devrel | 1 | yes | M1-138 | The announcement email text (install command, quickstart spec, what is rough, how to report a blocker), the design-partner recipient checklist and the Done log line format for the sent date and recipient count are in the repo. Sending is a founder hand step. |
| M1-140 | M1 | HTML next-step sentences and the nothing-verified wording | cli-ux | 1 | no | M1-081 | Golden HTML carries the sentences of 07 D.7 by verdict, including the `nothing_verified` sentence for C.13. |
| M1-141 | M1 | HTML untrusted strings in bdi with bidi controls shown as escapes | cli-ux | 1 | no | M1-082 | A hostname holding U+202E and a vendor `fix` holding U+2066 render inside `<bdi>` as `\u{202e}` and `\u{2066}`, and the structure test asserts it. |
| M1-142 | M1 | Progress line with indicatif, TTY only | rust-engineer | 2 | no | M1-086, M1-070 | A pty capture shows one spinner line cleared before the check list, a 250 ms run draws nothing, a pipe, `--quiet`, `--progress never`, `RDY_PROGRESS=never`, `TERM=dumb` and `RUST_LOG` each produce zero progress bytes, and nothing is drawn on stdout; and the glyph choice follows 07 D.1. |
| M1-143 | M1 | Quiet and verbose output modes | cli-ux | 1.5 | no | M1-086 | Golden stderr for 07 C.1 (`--quiet`) and C.2 (`--verbose`), and `--verbose` prints one event line per finished check on a pipe. |
| M1-144 | M1 | Facade methods for UDP exchanges and unix sockets with a GET-only Docker API guard | rust-engineer | 3.5 | no | M1-040 | An SNTP query to a server not in spec ntp_servers and a POST on the Docker socket are refused and logged. |
| M1-145 | M1 | host.lsm (SELinux, AppArmor, audit log denials) (M1-late) | check-author | 2.5 | no | M1-049 | Enforcing with two AVC lines for a watched context blocks, an unreadable audit log gives partial, and a masked `/sys/fs/selinux` says "not visible". |
| M1-146 | M1 | host.security_agents (process names, agents.toml format, seed list) (M1-late) | check-author | 2.5 | no | M1-049 | Each catalog entry has a fixture, `comm` truncation is handled, `forbid` blocks and `allow` silences, and the founder has approved the seed list. |
| M1-147 | M1 | host.firewall (firewalld zone and service XML, ufw) (M1-late) | check-author | 3 | no | M1-066 | A closed port in the default-route zone blocks, a port open by service passes, a rich rule gives warn, and a root-less run warns. |
| M1-148 | M1 | host.time_sync (adjtimex, timedatectl, chronyc, SNTP client) (M1-late) | check-author | 3 | no | M1-066, M1-144, M1-094 | A scripted SNTP responder with a 400 s offset blocks, a reply failing the echo check is rejected, and `EPERM` on adjtimex is partial; the UDP host set comes only from a new `ntp_servers` parameter, is fed to `Built::hosts` and counts toward the 64-host limit (INV-11); and a server in an `is_forbidden` range, such as 169.254.169.123 or fd00:ec2::123, gives "offset not measured, server in a refused range" and falls back to `chronyc` (PR #91 reviews). |
| M1-149 | M1 | host.sysctl (live and persisted values, precedence, systemd limits) (M1-late) | check-author | 2 | no | M1-049 | A right live value with no `sysctl.d` entry warns "not persisted", and a masked file name resolves per the precedence rule. |
| M1-150 | M1 | host.container_runtime (sockets, daemon.json, containerd v2 and v3, kubelet driver, API over unix socket) (M1-late) | check-author | 3 | no | M1-066, M1-144 | A cgroupfs versus systemd mismatch blocks with the matching table path for the config version, and `d_type` unsupported blocks; and the Docker `/info` body is redacted before any of it is kept as evidence (PR #91 review). |
| M1-151 | M1 | host.cgroups (v1, hybrid, v2, controllers) (M1-late) | check-author | 1.5 | no | M1-065 | V1, hybrid, v2 and memory-controller-off fixtures give the expected levels and the fix text follows `host.os`. |
| M1-152 | M1 | host.kernel (version and modules) (M1-late) | check-author | 2 | no | M1-064 | A module present only in `modules.dep` as `.ko.xz` warns, absent blocks, and `distro_min` overrides the upstream compare. |
| M1-153 | M1 | net.dns system answer (getent path, name validation, fallback, timeout evidence) (M1-late) | check-author | 2.5 | no | M1-066, M1-095, M1-009 | Found, not found (exit 2), AAAA-only and deduped dual-stack rows classify, a leading-`-` name is rejected, and with `getent` absent the fallback is used and says so. |
| M1-154 | M1 | musl resolver behaviour fixture for net.dns | qa-engineer | 1 | no | M1-153 | A fixture resolv.conf and nsswitch.conf with `sss` produce the documented warning. |
| M1-155 | M1 | net.dns direct nameserver lookups, resolv.conf and nsswitch analysis, scripted DNS server (M1-late) | check-author | 2.5 | no | M1-153 | Split-horizon and slow-first-nameserver fixtures warn, NXDOMAIN blocks, and `cargo deny check` passes with `hickory` default features off. |
| M1-156 | M1 | net.registry (v2 ping, token realm, manifest and config blob host, HEAD versus GET) (M1-late) | check-author | 3.5 | no | M1-097 | A mock whose listed blob host is closed blocks and names it, an unlisted blob host warns "add it", and a multi-arch index resolves. |
| M1-157 | M1 | net.mtu (Linux sysfs, sysinfo elsewhere, overlay overhead tables) (M1-late) | check-author | 1.5 | no | M1-049 | MTU 1450 with `overlay: vxlan` and `min_mtu: 1400` blocks, and MTU 9001 is informational without `overlay`. |
| M1-158 | M1 | net.bandwidth (ranged sample, injected clock) (M1-late) | check-author | 1.5 | no | M1-097 | Fixed `(bytes, instant)` samples give the expected rate, a 500 KiB response says "sample too small", and a loose loopback smoke test is within a factor of 2. |
| M1-159 | M1 | k8s.nodes free capacity from pod requests (cut 2) | check-author | 1.5 | no | M1-113 | Requests using 90% of CPU block a 16 CPU free need, and a forbidden or capped Pod list gives "not evaluated", never pass. |
| M1-160 | M1 | k8s.admission webhooks, validating admission policies and the dry-run guard test (M1-late) | check-author | 2.5 | no | M1-114 | A `Fail` webhook with an empty EndpointSlice blocks, `matchConditions` and URL webhooks are "not evaluated", forbidden webhook lists give partial, and the only non-GET call across the fixture set is the allowed review kinds. |
| M1-161 | M1 | k8s.namespace (existence, terminating, quota, limit range, project request) (M1-late) | check-author | 1.5 | no | M1-105 | A quota with 2 CPU left blocks a 16 CPU need, a scoped quota is "not evaluated", and OpenShift uses the project request review. |
| M1-162 | M1 | k8s.dns (label-based selection, Corefile, restart evidence) (M1-late) | check-author | 1.5 | no | M1-105 | RKE2, OpenShift and GKE fixtures select the right workload, and a crash-looping CoreDNS with `forward . /etc/resolv.conf` and a recent termination blocks while lifetime restarts alone do not. |
| M1-163 | M1 | k8s.ingress (IngressClass by controller, Gateway API, route, pending LoadBalancer, retirement warning) (M1-late) | check-author | 2.5 | no | M1-105 | A community ingress-nginx class warns with the retirement text, an F5 class does not, GKE with no class is "not verified", and a 20-minute-old pending LB warns. |
| M1-164 | M1 | k8s.crds (CRDs, served versions, operator version) (M1-late) | check-author | 2.5 | no | M1-105 | A missing CRD blocks with the mirror-aware Helm fix, and an operator below `min_version` blocks. |
| M1-165 | M1 | k8s.cni (node-condition and CRD signals, DaemonSets, NetworkPolicy, CIDRs, cni.toml) (M1-late) | check-author | 2.5 | no | M1-105 | K3s with no DaemonSet is detected as flannel from the node condition, Flannel with `network_policy: enforced` blocks on a non-k3s fixture, and default-deny egress warns. |
| M1-166 | M1 | Fixture env net-airgapped | qa-engineer | 1.5 | no | M1-117, M1-128 | `acme-airgap-host.yaml` runs in process with goldens, every public endpoint is refused or black-holed, and the SEC-22 strace check passes over it. |
| M1-167 | M1 | Time the quickstart with two design-partner SEs | devrel | 2 | no | M1-138 | A session script for timing the quickstart (task, start and stop points, the five-minute bar, what to note) and an issue template for quickstart stumbles are in the repo. Running the two sessions is a founder hand step. |
| M1-168 | M1 | CLI start-up hardening: call `harden_umask()` and warn on inherited descriptors | rust-engineer | 1 | yes | M1-039, M1-056 | At start-up `rdy` sets umask 077 before any file is created and, when `inherited_fds()` is not empty, prints one redacted `warning:` line naming the descriptor numbers; a `cfg(unix)` test that passes an inherited fd to the real binary sees the warning (Windows prints no warning). |
| M1-169 | M1 | Facade `read_link` with an action-log kind and the /proc fd walk rule | rust-engineer | 1.5 | yes | M1-045 | `Probe::read_link` resolves a link under the check's `reads` prefixes and logs one `read_link` entry; `/proc/self/ns/net` resolves on Linux and is NotFound elsewhere; a link outside the prefixes is refused and logged; reading `/proc/<pid>/fd` for socket inodes is allowed only by the rule host.ports declares, the walk returns only `socket:[N]` targets, and any other target is refused and logged without the path; Replay serves the 08 `symlinks` map; and security-reviewer signs off (PR #88 review). |
| M1-170 | M1 | Machine identity files denied in the read policy | rust-engineer | 1 | yes | M1-046 | With `reads: ["/"]`, `/run/machine-id` (which the `MachineId` call may also read as a real path), `/sys/class/dmi/id/product_serial`, `product_uuid`, `board_serial` and `chassis_serial` (also under `/sys/devices/virtual/dmi/id/`) are refused at any depth, a hard link or bind mount of either machine id file under another name is refused by inode, and the `MachineId` native call still reads its own files (PR #94 review). |
| M1-171 | M1 | `statfs` prefixes judge `NativeCall::Statvfs` | rust-engineer | 1 | yes | M1-046 | `CheckInfo` gains a `statfs` prefix list that judges `Statvfs` (with the read denylist still applied), a check with `statfs: ["/"]` and no `reads` gets file system numbers for any path but cannot read a file, on macOS a directory the user cannot read is opened through its parent or reported, not failed, and 02 and 05 say so (PR #94 reviews). |
| M2-001 | M2 | Keep golden result files per released version and parse them in CI | qa-engineer | 1 | yes | M1-083 | `tests/fixtures/results/0.1.0/report.json`, produced by the v0.1.0 binary running the host-min spec, parses with the current rdy-engine on five legs, a changed byte in an older version directory fails the lint, and RELEASING.md says each tag adds its directory. |
| M2-002 | M2 | Host identity and host_id derivation | rust-engineer | 2 | yes | M1-020, M1-061 | M1 writes `host_id: null`; after this ticket a fixture machine id gives the documented HMAC host_id, another product gives a different one, macOS gives null, and a fixture run's JSON has no MAC, home path or environment value; and the raw machine id is added to the run's known-secret set before any write (PR #94 review). |
| M2-003 | M2 | Cluster facts cache and read-review batch | check-author | 2 | yes | M1-105 | Five checks cause one Node list per run, a forbidden Node list is recorded once with its grant, and forbidden calls are skipped up front. |
| M2-004 | M2 | sysinfo NativeCall variants without process environ or cmdline | rust-engineer | 3 | yes | M1-046 | Host.memory and host.cpu run on macOS and Windows CI and strace or the equivalent shows no environ or cmdline reads. |
| M2-005 | M2 | sysinfo-only subset on macOS and Windows for host.disk, memory, cpu and os | check-author | 3 | yes | M1-067, M2-004, M1-068, M1-069, M1-071, M1-073 | The four checks return real results from `native/sysinfo_*.json` fixtures on the macOS and Windows CI jobs and `Partial` shows in `CheckInfo`. |
| M2-006 | M2 | Windows job objects so a timeout kills the whole process tree | rust-engineer | 3 | yes | M1-038 | A Windows fixture command that spawns a grandchild leaves no process after its timeout, and the Windows exec allowlist then opens to 03 Appendix A's Windows rows. |
| M2-007 | M2 | macOS data sources for host.ports, cpu flags and security_agents (M1-late) | check-author | 3 | yes | M2-005, M1-146 | Recorded `netstat` (with `*.6443`) and `sysctl` fixtures pass on the macOS CI job, and `proc_translated=1` (Rosetta) warns. |
| M2-008 | M2 | Windows data sources for host.ports and host.os registry, registry helper included (M1-late) | check-author | 4 | yes | M2-005, M2-006 | Recorded `NETSTAT`, excluded-port-range and `CurrentVersion` registry fixtures pass on the Windows CI job. |
| M2-009 | M2 | macOS and Windows sources for host.time_sync SNTP and security_agents process names (M1-late) | check-author | 2 | yes | M1-148, M1-146 | The SNTP offset fixture passes on all five CI legs and the process-name fixtures pass on macOS and Windows. |
| M2-010 | M2 | macOS and Windows sources for net.proxy, net.dns and net.mtu (M1-late) | check-author | 3 | yes | M1-098, M1-153, M1-157 | `scutil` and registry fixtures parse to the expected proxy and nameserver lists. |
| M2-011 | M2 | Fixture env windows-2022-stub | qa-engineer | 1 | yes | M1-117, M1-067 | Host checks are `not_yet_on_os`, net runs, and CRLF command output stays intact on the Windows env. |
| M2-012 | M2 | Scheduled audit.yml: cargo-audit, deny advisories, issue on failure (SEC-02) | release-engineer | 2 | yes | M1-005 | A `workflow_dispatch` run on a branch pinning a vulnerable crate opens a `security` issue. |
| M2-013 | M2 | MSRV job and six-weekly toolchain bump reminder | release-engineer | 1 | yes | M1-006 | Raising a dependency's MSRV above the declared one turns the job red. |
| M2-014 | M2 | release-smoke on main: release build, binary size budget, cargo audit bin | release-engineer | 2 | yes | M1-006 | A push to `main` runs it on five legs and a binary over budget fails it. |
| M2-015 | M2 | Publish crates with trusted publishing and release-plz per-crate versions and changelogs (ADR 0007) | release-engineer | 7 | yes | none | A dry run opens a release PR bumping only the crates that changed, and a real publish of `rdy-spec` holds no stored crates.io token. |
| M2-016 | M2 | cargo-semver-checks in CI for rdy-spec and rdy-engine (ADR 0007) | release-engineer | 2 | yes | M2-015 | A PR that removes a public field without a version bump fails CI. |
| M2-017 | M2 | First crates.io release of rdy-spec and rdy-engine for rdy-cloud | release-engineer | 2 | yes | M2-015 | A scratch crate outside the repo depends on both from crates.io and parses a golden result. |
| M2-018 | M2 | Post-release verify job on four environments and the Windows zip | release-engineer | 3 | yes | M1-012 | After a tag a run installs from the real release on ubuntu x64, ubuntu arm64, macOS arm64 and an Alpine container (one without cosign, to prove the fail-closed message) and verifies the Windows zip. |
| M2-019 | M2 | Worker route serving install.sh at getrdy.io/install | release-engineer | 3 | yes | M1-008, M1-012 | `curl -sSf https://getrdy.io/install` returns 200 with bytes identical to the newest release's `install.sh`, and the docs install page switches to that line. |
| M2-020 | M2 | Publish out-of-band trust anchors on getrdy.io/security and SECURITY.md | release-engineer | 2 | yes | M2-019 | The page lists issuer, workflow path, cosign version and hash, and each release's `SHA256SUMS` digest and Rekor index, and the digests match the release. |
| M2-021 | M2 | Reproducibility flags and rebuild check in a pinned container | release-engineer | 8 | yes | M1-012 | `scripts/repro-check.sh` reports the same sha256 for the Linux x64 musl binary of a released tag. |
| M2-022 | M2 | install.sh offline mode from a local folder with a TUF-cached trust root | release-engineer | 4 | yes | M1-015 | On a host with the network blocked, the script verifies and installs from a local folder. |
| M2-023 | M2 | Allocator benchmark musl against glibc in CI (ADR 0006) | release-engineer | 2 | yes | M1-006 | CI prints both timings for the fixture spec and fails above the 20 percent threshold. |
| M2-024 | M2 | Nightly coverage job, not gating | release-engineer | 3 | yes | M1-006 | A nightly run uploads an lcov report and shows a percentage. |
| M2-025 | M2 | Verify the AWS SDK runs on rustls with ring | cloud-iam-expert | 3 | yes | none | A spike branch builds aws-sdk-iam for both musl targets with no aws-lc-sys in cargo tree, or an ADR records why not. |
| M2-026 | M2 | Shared HTTP client builder for the upload client: reqwest on rustls with ring and the platform verifier (ADR 0009) | rust-engineer | 3 | yes | M1-040 | An integration test with a local CONNECT proxy shows traffic through the proxy, NO_PROXY honoured, `cargo tree -i aws-lc-sys` empty, and a proxy password never in Debug output. |
| M2-027 | M2 | SEC-42 Share-link token format and scope | security-reviewer | 6 | yes | none | The token spec is agreed with rdy-cloud and the `rdy_st_` prefix is covered by the redaction corpus. |
| M2-028 | M2 | Share-link spec fetch: rdy run <product> with the token from RDY_TOKEN, --token-file or a prompt | rust-engineer | 6 | yes | M2-026, M2-027, M2-017, M1-126 | `rdy run acme-platform` with a synthetic token from RDY_TOKEN fetches a signed spec from staging, shows the key fingerprint before pinning, and a `--token` value on argv exits 64. |
| M2-029 | M2 | Hidden --token and --secret refusals | rust-engineer | 1 | yes | M2-028 | `--token` and `--secret` exit 64 with the reason of 07 C.6 and echo nothing after the flag name. |
| M2-030 | M2 | Portal import of HTML reports via the embedded JSON | rust-engineer | 4 | yes | M2-017 | Rdy-cloud imports a golden HTML report, rejects one whose embedded JSON fails the schema, and labels it customer-reported. |
| M2-031 | M2 | rdy report re-renders HTML from a result JSON | rust-engineer | 2 | yes | M1-083 | Rendering a golden result file reproduces the golden HTML byte for byte. |
| M2-032 | M2 | SEC-46 Vendor key rotation, signed_at and serial rollback warnings | rust-engineer | 9 | yes | M1-121, M1-026 | A rotated key passes, a removed key fails, and running serial 6 after serial 7 or an older `signed_at` for the same product warns and is recorded in the result. |
| M2-033 | M2 | SEC-47 Portal-delivered spec and key trust | security-reviewer | 4 | yes | M2-032 | A written decision exists and a key change for a pinned product fails in a fixture. |
| M2-034 | M2 | TTY confirmation for unsigned specs (SEC-56) | cli-ux | 1 | yes | M1-130 | On a pty answering no exits 64 for both banners with default no, and without a TTY the flag alone runs. |
| M2-035 | M2 | Option to replace the hostname in reports | rust-engineer | 2 | yes | M2-002 | With the option set no report file contains the real hostname and host_id is unchanged. |
| M2-036 | M2 | Signed demo key and signed example specs for the quickstart | devrel | 2 | yes | M1-125 | The README quickstart runs on a clean machine with `rdy trust add` and no flags beyond the file name. |
| M2-037 | M2 | Family limits and graceful Ctrl-C with a partial report | rust-engineer | 3 | yes | M1-043 | Ctrl-C writes a report with interrupted true and unstarted checks skipped cancelled, k8s never has more than 3 checks in flight, and the 08 timeouts env shows `skip_kind: cancelled` under paused time. |
| M2-038 | M2 | Graceful first Ctrl-C with a partial report and the second-Ctrl-C message | rust-engineer | 3 | yes | M2-037 | A pty test gets exit 2 with `interrupted` true after one SIGINT and exit 70 with the message of 07 5.1 after two. |
| M2-039 | M2 | rdy run --timeout with the lower-always, raise-defaults-only guard | rust-engineer | 2 | yes | M1-034 | `--timeout 3s` ends a 10 s default at 3 s, a spec `timeout: 5s` is not raised by `--timeout 20s` but is lowered by `--timeout 2s`, a bare `20` exits 64, and the header prints the limit and its source. |
| M2-040 | M2 | SEC-40 rdy run --dry-run preview (was --plan) | rust-engineer | 6 | yes | M1-040 | The plan lists each check's reads, connects and needs, matches the action log of a real run on the same fixtures, runs nothing and exits 0. |
| M2-041 | M2 | --dry-run output C.3 (extends SEC-40) | cli-ux | 2 | yes | M2-040 | Golden output for 07 C.3, no report folder is created, no socket is opened under strace, and `--dry-run --json` exits 64 until the plan has a schema. |
| M2-042 | M2 | JSON for trust list and the dry-run plan | rust-engineer | 4 | yes | M2-041, M1-131 | Both outputs validate against new schema definitions and the stable-output promise of 07 4.2 lists them. |
| M2-043 | M2 | Family-scoped facts with detached fetch and fact attribution | rust-engineer | 4 | yes | M1-035 | Two k8s checks share one nodes fetch, a check that times out does not abort it, and its log entries carry the fact name. |
| M2-044 | M2 | Nonblocking record reads for /dev/kmsg | rust-engineer | 2 | yes | M1-045 | A fixture kmsg with 10,000 records returns within its cap and timeout and no other device path is allowed. |
| M2-045 | M2 | Kube connector built on the facade | rust-engineer | 4 | yes | M1-091 | Every kube socket appears as a facade connect entry and the address rule applies to the API server. |
| M2-046 | M2 | custom.file | check-author | 4 | yes | M1-068 | Good, expired, world-readable and unreadable fixtures give the expected results. |
| M2-047 | M2 | k8s.admission dry-run parameters after the ADR 0010 amendment | rust-engineer | 2 | yes | M1-025 | `dry_run` and `probe_pod` decode, appear in the schema revision table, and are refused at run time if the guard does not allow the call. |
| M2-048 | M2 | k8s.admission dry-run mode, after its ADR, core Pod only | check-author | 4 | yes | M1-160, M2-047 | Recorded dry-run denial bodies surface the text, an unsafe-webhook refusal is inconclusive, a non-Pod kind is rejected, and the default run makes no create call. |
| M2-049 | M2 | k8s.images: pull secrets and OpenShift mirror sets | check-author | 3 | yes | M1-161 | A service account with a pull secret passes, a missing one warns, and an `ImageDigestMirrorSet` is reported without reading secret values. |
| M2-050 | M2 | host.firewall nft and iptables parsing, host.security_agents directories, units and modules, Windows inbound rules | check-author | 5 | yes | M1-147 | A recorded `nft list ruleset` with a drop policy blocks and a unit-file fixture detects an agent. |
| M2-051 | M2 | k8s.metrics and k8s.snapshots | check-author | 4 | yes | M1-109 | Missing APIService and missing VolumeSnapshotClass fixtures warn. |
| M2-052 | M2 | Docker over Windows named pipe for host.container_runtime | check-author | 2 | yes | M1-150 | A scripted named-pipe stream returns the recorded `/version` JSON on the Windows CI job. |
| M2-053 | M2 | Verdict, exit-code and redactor property tests with the schema-walk canary | qa-engineer | 5 | yes | M1-020, M1-062 | The 08 Appendix D properties and the redactor idempotence and planted-secret properties hold, and a new string field added to the result schema is covered with no test change. |
| M2-054 | M2 | CI redaction gate with known-gaps ledger | release-engineer | 2 | yes | M1-063 | A separate job in ci-ok fails below FLOOR 60 and on a gap that starts to pass. |
| M2-055 | M2 | Streaming redactor with line framing and PEM state | rust-engineer | 7 | yes | M1-063 | Stream output equals whole-input output at every split offset. |
| M2-056 | M2 | Binary, compressed and UTF-16 handling in the redaction pipeline | rust-engineer | 4 | yes | M2-055 | Gzip is skipped with a reason and UTF-16 is redacted. |
| M2-057 | M2 | Bundle rules for emails, SaaS tokens and cloud credentials | rust-engineer | 6 | yes | M2-055 | The new cases pass and `--keep-emails` sets `groups_off_by_flags`. |
| M2-058 | M2 | Bundle rules for entropy, IPv4, IPv6 and MAC | rust-engineer | 6 | yes | M2-055 | Opt-in groups stay off unless asked and false positives are under 2%. |
| M2-059 | M2 | Spec and CLI additions for redact_patterns, max_size and --redact-pattern | rust-engineer | 2 | yes | M2-055 | 33 patterns or an unknown group exit 64. |
| M2-060 | M2 | Residual scan, per-entry fail-closed handling and non-dumpable process | rust-engineer | 4 | yes | M2-055 | A planted rule gap shows `residual_hits` and Linux shows `Dumpable: 0`. |
| M2-061 | M2 | SEC-44 Full redaction corpus with chunk-boundary cases | qa-engineer | 10 | yes | M2-057 | The corpus reaches the CI floor of 60 cases on the way to the 300 of 05, every case passes at every split offset with zero misses, CI fails under 25 MiB/s or over 128 MiB RSS, and a pinned second-opinion scanner finds only allowlisted false positives. |
| M2-062 | M2 | SEC-65 Redaction span union with hostile custom patterns | rust-engineer | 3 | yes | M2-061 | Every built-in positive in the corpus, run with custom patterns `@`, `.`, the first secret byte and the key name, has zero survivors. |
| M2-063 | M2 | SEC-45 Fuzz targets for spec parser and redactor | qa-engineer | 6 | yes | M1-048, M1-027 | A weekly 30-minute fuzz run per target finds no crashes. |
| M2-064 | M2 | Bundle manifest wire types and schema in rdy-spec | rust-engineer | 4 | yes | M1-022 | The 04 Appendix C sample validates and no field holds a raw hash. |
| M2-065 | M2 | Collector trait and registry, caps and truncation markers | rust-engineer | 8 | yes | M2-064 | Unknown kinds are skipped and every cut carries the 04 section 5.2 marker. |
| M2-066 | M2 | Bundle scope in the probe facade with streaming reads and deny-list additions | rust-engineer | 7 | yes | M1-045 | A 32 MiB file streams under its cap and every deny-list path is refused. |
| M2-067 | M2 | SEC-43 Bundle collector path policy | security-reviewer | 6 | yes | M2-066 | Denylisted paths and symlink escapes are refused and `--dry-run` shows the resolved file list before collection. |
| M2-068 | M2 | SEC-66 rdy bundle ignores spec collectors unless the spec is verified with a pinned key | rust-engineer | 1 | yes | M2-067 | An unsigned or `--key` spec with `collect: ["file:/etc/acme/*"]` builds a bundle from the built-in set only and says so. |
| M2-069 | M2 | Collectors for file glob, Linux host, journal and container runtime | rust-engineer | 20 | yes | M2-067, M2-065 | Fixtures produce the 04 Appendix A files and cmdline and environ are never read. |
| M2-070 | M2 | Kubernetes guard amendment and collectors for events and describe | rust-engineer | 10 | yes | M1-104, M2-065 | The mock API server sees only list and get on the 04 Appendix A kinds and env values are stripped. |
| M2-071 | M2 | macOS and Windows host collectors | rust-engineer | 8 | yes | M2-069 | Recorded outputs produce the files. |
| M2-072 | M2 | Archive writer with layout, deterministic headers and archive cap | rust-engineer | 6 | yes | M2-065 | A fixed key, clock and bundle id give identical bytes, and incompressible fixtures never give an archive over 100 MiB. |
| M2-073 | M2 | rdy bundle and rdy redact commands, plan and built-in collector set | rust-engineer | 8 | yes | M2-072, M2-069, M2-060 | A fixture run writes the bundle and `--dry-run` reads no file and opens no socket. |
| M2-074 | M2 | Bundle block strict validation in rdy bundle | rust-engineer | 3 | yes | M2-073 | An unknown redactor or collector kind refuses to build a bundle with a fix line. |
| M2-075 | M2 | No-socket and no-stray-file tests for rdy bundle | qa-engineer | 3 | yes | M2-073 | Only the kube fixture is contacted and canaries appear in no file. |
| M2-076 | M2 | Upload pre-flight with single-pass scan, hash and bounded decode | rust-engineer | 4 | yes | M2-060 | A zstd bomb and a 20,000-entry tar exit 64 within 5 s. |
| M2-077 | M2 | Upload token input and consent screen | rust-engineer | 4 | yes | M2-027, M2-076 | FIFO and group-readable token files and `--token` exit 64. |
| M2-078 | M2 | SEC-41 rdy upload client with consent, receipt and exact bytes | rust-engineer | 4 | yes | M2-077, M2-026 | Fake-server tests prove the 05 Surface 4 requirements and 04 steps 3 to 5, nothing uploads without the flag or a yes, and retries reuse the upload id. |
| M2-079 | M2 | Share-link run output: fetch notice, key fingerprint question, upload offer above the verdict | cli-ux | 4 | yes | M2-028, M2-078 | Golden transcripts for a TTY yes, a TTY no and no TTY each end in the verdict, and `--no-network` fails with a fix. |
| M2-080 | M2 | Fake upload server and offline behaviour tests | qa-engineer | 4 | yes | M2-078 | Every test in 04 section 6 passes on five legs. |
| M2-081 | M2 | Output for bundle, upload, report and redact | cli-ux | 4 | yes | M2-073, M2-078, M2-031 | Golden output for the 04 section 6 and Appendix C samples, and each command's exit codes match 07 section 5. |
| M2-082 | M2 | Security review of the bundle pipeline and upload client | security-reviewer | 4 | yes | M2-080, M2-061 | Blockers are fixed before a design partner gets an M2 build. |
| M2-083 | M2 | Bundles page and bundle and upload docs | docs-writer | 3 | yes | M2-073 | The Bundles page lists each collector and redactor name exactly as `--list-collectors` reports it. |
| M2-084 | M2 | SEC-57 Contact-set tests on macOS and Windows | qa-engineer | 4 | yes | M1-128 | Equivalent destination checks pass on both CI legs. |
| M2-085 | M2 | SEC-58 Windows output dir and key file ACL hardening | rust-engineer | 3 | yes | M1-036, M1-125 | Report files and the key files that `rdy spec keygen` makes carry an owner-only ACL on Windows CI, and `rdy spec sign` refuses a key file whose ACL lets others read it. |
| M2-086 | M2 | Compatibility matrix source and generator, and the compat-touched PR check | qa-engineer | 4 | yes | M1-117 | `cargo xtask matrix --check` fails on a row citing a missing env, and a PR that changes a check crate without touching the page or the body line fails. |
| M2-087 | M2 | Fixture envs host-ubuntu2204-container, net-corp-proxy and k8s-openshift-restricted | qa-engineer | 6 | yes | M1-117 | Each env runs in process with goldens, and the proxy env shows the 407 Basic classification and private-CA interception with no userinfo in any output. |
| M2-088 | M2 | Fixture env macos-15-arm64-stub | qa-engineer | 2 | yes | M1-117 | Host checks report the documented support state on the macOS leg and net runs. |
| M2-089 | M2 | Process-level timeout and Ctrl-C tests on Unix | qa-engineer | 3 | yes | M1-038, M1-119, M2-038 | The two M2 rows of 08 section 5 pass on linux and macos legs with upper-bound timing only. |
| M2-090 | M2 | Dev-only fixture record mode with a scrub step, and the record-fixtures workflow | qa-engineer | 7 | yes | M1-049, M1-050 | Recording `host.memory` on a CI runner writes nothing raw to disk and replays to the same result, planted hostname, address, MAC and serial are replaced consistently, and a manual run uploads scrubbed macOS and Windows directories. |
| M2-091 | M2 | Fixture lint redactor rule, golden-section PR check, ignore lint, nightly flake hunt and fixture drift job | qa-engineer | 6 | yes | M1-050, M1-083 | A secret-shaped string in a fixture fails the lint, a golden change without `## Golden changes` fails, a bare `#[ignore]` fails, and a planted 1-in-10 flake is caught nightly with its seed. |
| M2-092 | M2 | Kubernetes distro fixture set | qa-engineer | 6 | yes | M2-087 | `eks`, `gke`, `aks`, `rke2`, `k3s` and `kind` cases hold the files named in the k8s-expert review and the matrix rows move to `fixture`. |
| M2-093 | M2 | CLI reference generated from the clap command tree | docs-writer | 3 | yes | M1-029, M1-013 | Every command and flag in `rdy --help` appears on /reference/cli/, and a new flag fails `docs --check` until regenerated. |
| M2-094 | M2 | Sync check between 03-check-catalog.md and the check registry | docs-writer | 2 | yes | M1-089 | A registry id missing from 03 fails docs-lint. |
| M2-095 | M2 | Changelog page generated from CHANGELOG.md | docs-writer | 2 | yes | M1-013 | Each version heading in CHANGELOG.md appears once as an H2 on /changelog/, and `docs --check` output is identical on a shallow clone. |
| M2-096 | M2 | Privileges and data page with generated privilege table | docs-writer | 3 | yes | M1-089 | `docs --check` fails if a privilege string on the page differs from its registry value. |
| M2-097 | M2 | Read a report page | docs-writer | 3 | yes | M1-082, M1-085 | Every blocker field in the JSON result has a row on the page. |
| M2-098 | M2 | Contributor setup page with the exact cargo and pnpm commands | docs-writer | 2 | yes | M1-009 | Each command on the page appears in ci.yml or is marked local-only. |
| M2-099 | M2 | Writing docs page and docs-lint rules | docs-writer | 2 | yes | M1-013 | The page's examples pass docs-lint, and the banned-token list stays hash-only. |
| M2-100 | M2 | Offline and upload page | docs-writer | 3 | yes | M2-078, M1-136 | Its tested blocks pass in docs-test with the network namespace disabled. |
| M2-101 | M2 | lobste.rs account and weekly comment habit | devrel | 6 | yes | none | An account exists with an invite and at least ten useful comments on other people's posts before launch week minus 3. |
| M2-102 | M2 | First case study draft from a design-partner run | devrel | 4 | yes | M1-139 | One written, approved, anonymised case study exists. |
| M2-103 | M2 | README update for bundle, redaction and --dry-run | devrel | 2 | yes | M2-073, M2-041 | The README shows `rdy bundle` and `rdy run --dry-run` output pasted from real runs, the Security table has the redaction test, and the `[M2]` marks are gone. |
| M2-104 | M2 | INV-18 FFI module that closes inherited descriptors before exec | rust-engineer | 2 | yes | M1-039 | A descriptor above 2 that `rdy` inherited does not reach the child, on Linux and macOS, with each unsafe block justified (ADR 0023 follow-up). |
| M2-105 | M2 | rdy-winacl FFI crate: admin-only ProgramData trust store and elevation detection | rust-engineer | 8 | yes | M1-122 | On Windows CI a ProgramData\rdy store owned by Administrators or SYSTEM with no write ACE for other users is accepted, one with a Users write ACE or a non-admin owner exits 64 with trust_store_insecure, an elevated run is detected, and every unsafe block is documented (ADR 0027 follow-up, PR #68). |
| M2-106 | M2 | Offline `scripts/verify-release.sh --trusted-root <file>` for air-gapped verify | release-engineer | 2 | yes | M1-012 | With the network off, `verify-release.sh --dir <folder> --trusted-root <file>` passes for a real signed alpha and fails for a one-byte change to SHA256SUMS, and the docs say where to get the trusted root file and how to check it. |
| M2-107 | M2 | Lock the trust store folder across load and save (`rdy trust add` and `remove`) | rust-engineer | 1.5 | yes | M1-131 | Two `rdy trust add` runs and one `remove` started together on Linux, macOS and Windows end with every change kept, and a remove done while an add waits at its prompt is never undone. |
| M2-108 | M2 | `install.sh` override needs a flag as well as the env var | release-engineer | 1 | yes | M1-015, M1-133 | `RDY_INSECURE_SKIP_SIGNATURE=1` alone no longer skips the signature check; it needs the `--insecure-skip-signature` flag too, and a Dockerfile `ENV` line alone cannot disable verification; the 06 override row, ADR 0025 and the install page say so (PR #87 security review). |
| M2-109 | M2 | Derive `JsonSchema` on the check parameter types and delete `check_params.json` | rust-engineer | 2 | yes | M1-084 | The spec schema's check parameters are generated from the rdy-spec types, `check_params.json` is gone, and `schema --check` and the spec page are unchanged in meaning (PR #89 review, ADR 0034). |
| M3-001 | M3 | Starlight scaffold in docs/ with pinned pnpm and Node | docs-writer | 4 | yes | M1-003 | A clean clone runs `pnpm install --frozen-lockfile` and `pnpm build` with Node read from docs/.node-version and pnpm read from packageManager. |
| M3-002 | M3 | docs-gen and docs-build jobs in ci.yml, both required through ci-ok | docs-writer | 4 | yes | M3-001, M1-005 | A PR that breaks a generated page or an internal link fails ci-ok, and neither docs job appears as a separate required check. |
| M3-003 | M3 | Production deploy from main to docs.getrdy.io | docs-writer | 3 | yes | M3-002 | A merge to main updates docs.getrdy.io, and a pull request run cannot read the production token, which the founder created on the docs-only Cloudflare account and stored only in GitHub Environment docs-production. |
| M3-004 | M3 | Overview, Concepts and sidebar config | docs-writer | 3 | yes | M3-001 | The sidebar matches 09 section 3 and /concepts/ defines spec, check, severity, finding and result in one sentence each. |
| M3-005 | M3 | Check catalog index page | docs-writer | 1 | yes | M1-116 | /checks/ links to each family page and to no page that does not exist. |
| M3-006 | M3 | Hand-written compatibility page with the day-one rows | docs-writer | 1 | yes | M1-117 | `docs/compatibility.md` lists the 08 Appendix B rows with the four state words and each fixture row shows its origin. |
| M3-007 | M3 | HTML colour tokens and the contrast script (extends the askama report) | cli-ux | 1.5 | yes | M1-077 | A script reads the CSS variables and fails any text or border pair under 4.5:1 in light, dark, dark-preferred print and light print, and the golden HTML for 07 B.1 to B.3 matches. |
| M3-008 | M3 | SEC-31 Docs security page and verify-first install | docs-writer | 2 | yes | M1-012, M3-003 | The page lists what rdy reads and contacts, the report fields and link parameters, and CI runs its verify commands against the latest alpha. |
| M3-009 | M3 | CODE_OF_CONDUCT.md and link SECURITY.md | devrel | 1 | yes | M1-011 | Both files exist and the repo Security tab shows the policy and private reporting. |
| M3-010 | M3 | Issue forms and config (bug report, check request, security contact link) | devrel | 2 | yes | M1-011 | The New Issue page on a test fork shows the two forms and the private security link, and blank issues are off. |
| M3-011 | M3 | Repo hygiene: topics, social preview, Discussions | devrel | 1 | yes | none | All three settings are on in the repo and a screenshot of the repo page is in the PR. |
| M3-012 | M3 | Public claims audit table in docs | devrel | 2 | yes | M1-137 | Each claim in the README security table links to a test or a file, and any without one is removed or ticketed. |
| M3-013 | M3 | Record the README terminal cast | devrel | 2 | yes | M1-137 | An asciinema cast of the NOT READY then READY runs, from the release build, is linked from the README. |
| M3-014 | M3 | Headless browser render of the golden HTML with no network | qa-engineer | 3 | yes | M1-083 | Each HTML golden renders in the ADR 0003 headless-browser job with zero network requests and no console errors. |
| M3-015 | M3 | Headless layout checks: 320 px and print with dark preferred | qa-engineer | 1 | yes | M3-014 | `scrollWidth <= 320` at a 320 px viewport for the three goldens, and print media with dark preferred renders black on white. |
| M3-016 | M3 | PR preview deploys in a separate workflow | docs-writer | 4 | yes | M3-003 | A same-repo PR gets a pr-N preview URL on the founder's separate preview account, and a Dependabot or fork PR never reaches the preview deploy job. |
| M3-017 | M3 | Canonical links and noindex on preview builds | docs-writer | 1 | yes | M3-016 | A preview page carries the noindex meta tag and a production page does not. |
| M3-018 | M3 | Version picker in the Starlight header reading versions.json | docs-writer | 4 | yes | M3-003 | The select lists each archived version and opens the same page in it when that page exists. |
| M3-019 | M3 | docs-archive custom dist job, one archive per stable tag | docs-writer | 4 | yes | M1-010, M1-007 | A test stable tag produces `rdy-docs-<tag>.tar.zst` with a checksum that sign-release signs with the other assets. |
| M3-020 | M3 | Docs assembly: root from newest stable tag, /next from main, archives from release assets, versions.json, latest redirect | docs-writer | 4 | yes | M3-019, M3-018 | A preview of the assembled tree serves each documented path with status 200. |
| M3-021 | M3 | Freeze rdy/v1 for the 1.0 release of rdy-spec | rust-architect | 3 | yes | M2-016 | Schema files, golden results and 01 agree, and schema/README.md lists every revision since 0.1. |
| M3-022 | M3 | Decide the 1.0 stability scope of Check, Family and Probe | rust-architect | 3 | yes | none | An ADR says whether these modules are semver-covered at 1.0 or move under rdy_engine::unstable, before rdy-engine 1.0 ships. |
| M3-023 | M3 | Release rdy-spec and rdy-engine 1.0 | rust-architect | 4 | yes | M3-021, M3-022, M2-017 | 1.0 is published and the cargo-semver-checks baseline moved to 1.0. |
| M3-024 | M3 | http_exchange and Need::Consent for SDK adapters | rust-engineer | 4 | yes | M1-093 | The AWS SDK adapter fixture runs through the facade with every call in the action log and no body in the report, and assume-role without consent is skipped missing_need. |
| M3-025 | M3 | AWS HTTP adapter over the facade (FacadeHttpClient) with proxy, roots and request ids | rust-engineer | 5 | yes | M2-025, M3-024 | With a local CONNECT proxy an SDK call succeeds only through the proxy and appears in the action log with its request id. |
| M3-026 | M3 | AWS common: credential chain without credential_process, source detection, session cache, assume with consent and the RDY_ id rule, replay harness | check-author | 10 | yes | M3-025 | A no-credentials run skips every `aws.*`, a spec naming `AWS_SECRET_ACCESS_KEY` as external id is refused, the assume fixture runs only with `--allow-assume-role`, and a `credential_process` profile is skipped with the export hint. |
| M3-027 | M3 | SEC-48 Read-only cloud API allowlist | check-author | 6 | yes | M3-026 | Every AWS operation the checks can call is read-only or simulate, reviewed by cloud-iam-expert. |
| M3-028 | M3 | aws.identity | check-author | 2 | yes | M3-026 | A wrong-account fixture blocks, IMDS and assumed sessions never warn on expiry, and static near-expiry warns. |
| M3-029 | M3 | aws.iam (simulate, role ARN resolution, SCP and boundary text, labels) | check-author | 6 | yes | M3-028 | Implicit deny, org-SCP deny, missing context, SSO and regional SSO path role, denied `GetRole` and paged results all classify correctly. |
| M3-030 | M3 | aws.iam EC2 dry-run fallback, ec2_dryrun.toml and trust-policy inspection for vendor roles | check-author | 5 | yes | M3-029 | Dry-run fixtures classify, a validation error is `unknown`, `principal:` with `probe: dry_run` fails lint, and correct, ExternalId-less and wildcard-principal trust fixtures give pass, block and block. |
| M3-031 | M3 | aws.quota with aws_quotas.toml, UsageMetric usage, API-count fallback and pending requests | check-author | 8 | yes | M3-028 | A 64 vCPU need against a 32 vCPU limit blocks with the CLI fix, a quota without `UsageMetric` still reports usage from a Describe count, and a pending request changes the fix text. |
| M3-032 | M3 | aws.vpc (capacity formula, routes, NAT, DNS attributes, endpoint reachability) | check-author | 6 | yes | M3-028 | A 9-free-IP subnet, main-table association, a blackhole route and a closed endpoint security group classify correctly. |
| M3-033 | M3 | aws.region (documented SSM paths, supported-region routing, ZoneId, paging) | check-author | 5 | yes | M3-028 | Supported region, unsupported region and SCP region deny give pass, pass and unknown, and an opt-in region not enabled blocks. |
| M3-034 | M3 | aws.eks | check-author | 5 | yes | M3-028 | Private-only endpoint and missing OIDC provider fixtures block. |
| M3-035 | M3 | Publish the reader policy as JSON plus a CloudFormation snippet, tested against the action list | docs-writer | 2 | yes | M3-034, M3-027 | A test compares every operation the cloud checks can call with the policy actions and fails on any difference. |
| M3-036 | M3 | Review AWS checks (actions, simulator caveats, quota codes against a live listing) | cloud-iam-expert | 3 | yes | M3-034, M3-030, M3-031, M3-032, M3-033 | Written review with every finding fixed or filed. |
| M3-037 | M3 | Cloud account check family page | docs-writer | 2 | yes | M3-036, M1-116 | /checks/cloud/ lists each AWS check with its remediation text. |
| M3-038 | M3 | Pod logs collector with its own ADR | k8s-expert | 6 | yes | M2-070 | Tail-limited logs are collected through an amended guard. |
| M3-039 | M3 | OS log collectors for macOS and Windows | rust-engineer | 8 | yes | M2-071 | Recorded unified-log and event-log fixtures are collected and redacted. |
| M3-040 | M3 | Resumable upload | rust-engineer | 8 | yes | M2-078 | A cut upload resumes with the remaining bytes only. |
| M3-041 | M3 | SEC-52 cargo-vet for direct dependencies | security-reviewer | 6 | yes | none | `cargo vet` passes in CI. |
| M3-042 | M3 | Homebrew tap and dist homebrew installer | release-engineer | 4 | yes | M1-012 | `brew install getrdy-io/tap/rdy` installs the latest release and `brew test` passes. |
| M3-043 | M3 | winget manifest and submission automation | release-engineer | 6 | yes | M1-012 | A winget-pkgs PR passes validation and `winget install` works on a clean Windows VM. |
| M3-044 | M3 | Windows install.ps1 with the same verification as install.sh | release-engineer | 4 | yes | M1-015 | On a clean Windows VM the script installs and fails closed on a tampered zip. |
| M3-045 | M3 | SEC-50 macOS notarization and Windows signing, after open decision 6 in 13 | release-engineer | 8 | yes | none | A browser-downloaded archive runs on macOS without a Gatekeeper block and `rdy.exe` shows a verified publisher. |
| M3-046 | M3 | Self-update spike and ADR | release-engineer | 4 | yes | M1-012 | An ADR picks a verification method, backed by a Rust test that verifies a signed manifest. |
| M3-047 | M3 | Verified, explicit rdy self-update | release-engineer | 12 | yes | M3-046 | A tampered or wrong-identity release is refused and the old binary keeps working, a good one upgrades alpha N to N+1 on all five platforms and rolls back if the new binary fails `rdy version`, and it never runs unprompted. |
| M3-048 | M3 | SEC-49 Review of verified self-update | security-reviewer | 4 | yes | M3-047 | 06's self-update build refuses tampered or wrong-identity assets and never runs unprompted, and every blocker is fixed before it ships. |
| M3-049 | M3 | Verify reproducible builds across independent builders (SEC-51) | release-engineer | 8 | yes | M2-021 | Two independent builds of a tag match, or the deviations are documented. |
| M3-050 | M3 | rdy completion and man pages from the clap tree | rust-engineer | 4 | yes | M1-029 | `rdy completion <shell>` output sources cleanly in bash, zsh, fish and PowerShell CI jobs, `cargo xtask man` writes one page per command, and the release archive holds `completions/` and `man/`. |
| M3-051 | M3 | rdy spec init command and the init and self-update output | cli-ux | 4 | yes | M3-047, M1-031 | Golden output for init (refuses overwrite without `--force`) and for update, decline, check-only and a refused tampered release, each with the exit codes of 07 E.2. |
| M3-052 | M3 | Write a spec page | docs-writer | 3 | yes | M3-051, M1-136 | The tested blocks run `rdy spec init` and `rdy spec lint` and pass in docs-test. |
| M3-053 | M3 | Security page: signing, SBOM and vulnerability reporting (extends SEC-31) | docs-writer | 3 | yes | M3-008, M2-020 | Each claim on the page links to a file or a release asset. |
| M3-054 | M3 | Portal docs decision and pages | docs-writer | 4 | yes | none | The portal section builds from content that is public in the repo it names, after the founder decides where portal docs live. |
| M3-055 | M3 | Launch release candidate and feature freeze | release-engineer | 2 | yes | M3-036, M3-042, M3-043, M3-023, M3-048 | A signed release candidate is tagged, the post-release verify job passes on it, and only launch-blocking fixes merge after it. |
| M3-056 | M3 | Public launch pass over every page | docs-writer | 3 | yes | M3-053, M3-055 | No page says alpha or pre-release outside the version banner. |
| M3-057 | M3 | Launch assets final (HN post, first comment, Reddit and lobste.rs posts, FAQ) | devrel | 8 | yes | M3-055 | Every sentence is checked against the release candidate, every transcript equals a golden file, every founder placeholder is filled or deleted, and the claims table has no gaps. |
| M3-058 | M3 | Series posts 1 to 5 written, recorded and scheduled | devrel | 12 | yes | M3-055 | Five posts exist with terminal output pasted from the release candidate in 07's format and are scheduled. |
| M3-059 | M3 | Partner outreach (five emails, reply tracker) | devrel | 5 | yes | none | Emails are sent in launch week minus 3 to each category, reply status is tracked, and nothing is announced without written approval. |
| M3-060 | M3 | PreSales Collective post and roundtable booked | devrel | 5 | yes | none | The community team approved the post and the roundtable has a date and a listing. |
| M3-061 | M3 | Ten good-first-issue and check-request issues | devrel | 3 | yes | M1-138 | Ten issues exist, each with an exit test and a pointer to the code. |
| M3-062 | M3 | Metrics script and weekly routine | devrel | 3 | yes | none | `scripts/metrics.sh` writes one CSV row with stars, release downloads and crates.io downloads. |
| M3-063 | M3 | Launch-week runbook and response board | devrel | 3 | yes | M3-057 | The day-by-day table is on a calendar, and the `launch-fixes` board exists with the playbook linked. |
| M3-064 | M3 | Three-stranger quickstart test | devrel | 4 | yes | M3-055 | Median time to a report is under five minutes and all stumbles are fixed. |
| M4-001 | M4 | k8s.device_plugins (extended resources, GFD labels, MIG strategy, DRA, validator pod) (M1-late) | check-author | 4 | yes | M1-159 | GPU-labelled nodes with zero allocatable block, DRA slices with zero allocatable do not, MIG `single` does not trigger the `mixed` block, and a young plugin pod warns. |
| M4-002 | M4 | GPU capture set from rented machines with DTDs and the NVIDIA XML scrub tool | qa-engineer | 8 | yes | M2-090 | Captures with `-q -x --dtd` for a T4 or L4, an A10G, an A100 with MIG and an HGX scrub clean, a test fails if any committed fixture holds a real-shaped UUID, serial or bus id, and the matrix rows for those driver lines move to `fixture`. |
| M4-003 | M4 | Review nvidia-smi tag names against the recorded DTDs, complete cuda_driver_min.toml, gpu_arch.toml and xid.toml | gpu-expert | 3 | yes | M4-002 | Written review, and every tag path the code will read exists in each DTD. |
| M4-004 | M4 | GPU shared layer: tool search list, kernel-side gate, exit-code classifier, circuit breaker, shared collector | check-author | 5 | yes | M4-003 | Every exit code and string classifies, a hung run abandons the PID and stops further calls, the module-absent case never runs `nvidia-smi`, and the operator layout is found. |
| M4-005 | M4 | GPU XML parser: three value states, units, DTD test, no-DTD-fetch parser | check-author | 5 | yes | M4-004 | XML from 525, 535 and 550 parses to one model, an absent required tag gives partial, and the DTD path test passes. |
| M4-006 | M4 | gpu.driver, including DKMS and Secure Boot diagnosis | check-author | 4 | yes | M4-005 | Mismatch, nouveau, module built for another kernel and WSL2 fixtures give the expected results. |
| M4-007 | M4 | gpu.runtime (TOML parse, imports, drop-ins, Rancher paths, CDI staleness) | check-author | 4 | yes | M4-004 | Toolkit present but not registered with containerd blocks with the `nvidia-ctk` fix, a stale CDI spec blocks, and an unreadable config is partial. |
| M4-008 | M4 | gpu.cuda with built_with and compat rules | check-author | 5 | yes | M4-005 | Driver reporting 12.2 with product built with 12.4 passes with a note under `compat: minor` and blocks with the 550.54.14 hint under `compat: strict`. |
| M4-009 | M4 | gpu.devices and gpu.vram with gpu_arch.toml, MIG and vGPU handling | check-author | 7 | yes | M4-005 | An H100 at 81559 MiB and an A100 give the same result for `80Gi`, an L4 at 23034 MiB against `24Gi` passes with a note, and MIG on with no instances blocks. |
| M4-010 | M4 | gpu.health with xid.toml and the nonblocking kmsg reader | check-author | 6 | yes | M4-005, M2-044 | Xid 79 with a failing `nvidia-smi` blocks and with a healthy one warns, Xid 63 is info, row remap failure blocks, and a root-less run is partial. |
| M4-011 | M4 | gpu.fabric | check-author | 6 | yes | M4-005 | NVSwitch with no fabric manager blocks, the `comm` truncation tree does not false-block, and IB `INIT` blocks only on InfiniBand. |
| M4-012 | M4 | gpu.model_egress with offline mode | check-author | 5 | yes | M1-097 | An unlisted redirect host warns "add it", `HF_HUB_OFFLINE=1` switches to the offline path check, and a gated 401 warns. |
| M4-013 | M4 | Review GPU checks end to end | gpu-expert | 3 | yes | M4-006, M4-007, M4-008, M4-009, M4-010, M4-011, M4-012 | Written review with every finding fixed or filed, and the checks pass on one real node. |
| M4-014 | M4 | GPU and AI check family page | docs-writer | 2 | yes | M4-013 | /checks/gpu/ lists each GPU check with its remediation text. |
| M4-015 | M4 | GPU check family stand-alone post and example spec update | devrel | 4 | yes | M4-013 | `acme-inference-gpu.yaml` runs without skips on a GPU fixture and the post uses real output. |
| M4-016 | M4 | SEC-53 Threat model and design note for custom.exec | security-reviewer | 4 | yes | M1-040 | A section is added to 05-threat-model.md and reviewed by rust-architect before the custom.exec build ticket starts. |
| M4-017 | M4 | Spec-origin exec policy, hash-bound consent and temp workdir for custom.exec | rust-engineer | 4 | yes | M4-016 | A bare `--allow-exec` is refused, the right hash runs commands as an unprivileged user under euid 0 in a fresh temp dir with 64 KiB caps, and a wrong hash runs nothing. |
| M4-018 | M4 | Implement custom.exec with argv, expectations, caps and hash-bound consent | check-author | 16 | yes | M4-017, M1-049 | The six synthetic commands of 03 and the pass, fail, timeout, refused-without-consent, wrong-hash and unsigned-spec fixtures produce the documented statuses and exit codes on Linux, macOS and Windows. |
| M4-019 | M4 | store.postgres | check-author | 6 | yes | M1-049, M1-092 | PG 15 without `CREATE` on `public` and a missing extension block. |
| M4-020 | M4 | store.s3 | check-author | 5 | yes | M3-025 | Skew, missing bucket and checksum-rejecting server classify correctly. |
| M4-021 | M4 | store.redis | check-author | 4 | yes | M1-049, M1-092 | `allkeys-lru` against `noeviction` blocks and disabled `CONFIG` is partial. |
| M4-022 | M4 | Data stores check family page | docs-writer | 2 | yes | M4-019, M4-020, M4-021 | /checks/data-stores/ lists each data-store check with its remediation text. |
| M4-023 | M4 | Custom-branded report from data | rust-engineer | 6 | yes | M1-081 | A branding block in the spec changes name, logo and accent colour in the golden HTML and nothing else. |
| M4-024 | M4 | Custom checks page | docs-writer | 3 | yes | M4-018 | The page's example check runs in docs-test and its sandbox limits match the registry. |
| M5-001 | M5 | rdy-ffi and rdy-wasm builds of the engine | rust-engineer | 30 | yes | M3-023 | The C-ABI and WASM builds pass the same golden result tests as the CLI. |
| M5-002 | M5 | Embed SDK reference | docs-writer | 4 | yes | M5-001 | Every exported function in the C ABI header appears on the reference page. |
| M5-003 | M5 | Embed SDK developer guide and example | devrel | 8 | yes | M5-001 | A stranger builds the example installer integration from the guide alone. |
| M5-004 | M5 | Air-gapped kit: offline bundle of binary, signatures, trust root and signed specs, plus an offline licence check design note | rust-architect | 6 | yes | M2-022, M1-166 | A design note in docs/plan lists its tickets, and an install plus `rdy run` on a VM with no network, using only the kit, verifies every signature and produces a report. |
| M5-005 | M5 | deb and rpm packages with nfpm | release-engineer | 8 | yes | M1-012 | `dpkg -i` and `rpm -i` install on Debian and Rocky containers and `rdy version` runs. |
| M5-006 | M5 | apt and yum repository hosting with signed metadata | release-engineer | 12 | yes | M5-005 | `apt install rdy` and `dnf install rdy` work from the public repo on clean containers with the repo key verified. |
| M5-007 | M5 | Evaluate Sigstore keyless signing and vendor-domain keys for specs | security-reviewer | 4 | yes | none | An ADR accepts or rejects each with an offline-verification story. |
| M5-008 | M5 | SEC-54 Independent security audit | security-reviewer | 8 | yes | none | The report is received and every high finding has a fix ticket. |
| M5-009 | M5 | Provider-neutral cloud session before GCP and Azure checks | cloud-iam-expert | 4 | yes | M3-026 | GCP and Azure stubs use the same facade `Http`, action log and degrade rules with no AWS types. |
| M5-010 | M5 | gcp.iam, gcp.quota, gcp.apis, gcp.region | check-author | 14 | yes | M5-009 | Recorded REST responses for allowed, denied and quota-short cases classify correctly. |
| M5-011 | M5 | azure.rbac, azure.quota, azure.providers, azure.region | check-author | 14 | yes | M5-009 | Recorded ARM responses for allowed, denied and quota-short cases classify correctly. |
| M5-012 | M5 | store.kafka and full gpu.vgpu_license | check-author | 9 | yes | M4-021, M4-009 | Recorded broker and licence fixtures classify correctly. |

## Weekly ship list

Every week ends with a tag from the release pipeline, or the week is skipped and the number kept (06).
Each tag is a usable binary: it installs, runs `rdy version`, and does everything the earlier tags did.
Week 1 is a CI build. From week 2 every tag is a signed GitHub pre-release that
`scripts/verify-release.sh` checks. Alphas are for the founder and for demos on calls. `v0.1.0` and later
go to design partners.

| Week | Tag | Who runs it | How to check it |
| --- | --- | --- | --- |
| 1 | `v0.1.0-alpha.0` (CI artefacts) | founder | The CI run is green on five legs and the downloaded artefact prints `rdy --version`. |
| 2 | `v0.1.0-alpha.1` | founder | `scripts/verify-release.sh v0.1.0-alpha.1` passes on a clean Linux machine. |
| 3 | `v0.1.0-alpha.2` | founder | The pinned install.sh installs alpha.2 and refuses a tampered checksum. |
| 4 | `v0.1.0-alpha.3` | founder | `cargo xtask schema --check` is green and `rdy version --json` validates against the schema. |
| 5 | `v0.1.0-alpha.4` | founder | The parameter fixture tests in rdy-spec pass on five legs. |
| 6 | `v0.1.0-alpha.5` | founder | Proptest runs 10,000 cases in CI and the root job log shows `strace -V`. |
| 7 | `v0.1.0-alpha.6` | founder | `rdy spec lint` on a `mn: 32Gi` typo prints "did you mean min" and exits 2; `rdy --bogus` exits 64. |
| 8 | `v0.1.0-alpha.7` | founder | Engine tests: a hung check reports Timeout and a panicking one Error. |
| 9 | `v0.1.0-alpha.8` | founder | `action_log_lists_commands` passes on five legs and the injected-id refusal test exits 70. |
| 10 | `v0.1.0-alpha.9` | founder | Under paused time a hung check becomes timeout and the watchdog report has `complete: false`. |
| 11 | `v0.1.0-alpha.10` | founder | A planted public hostname in a fixture fails fixture lint. |
| 12 | `v0.1.0-alpha.11` | founder | `rdy run examples/specs/acme-platform.yaml --allow-unsigned --json` exits 2 and validates; a pty Ctrl-C test exits 70 and leaves no folder (Unix legs). |
| 13 | `v0.1.0-alpha.12` | founder | Canary secrets in env, proxy URL and kubeconfig appear nowhere at `RUST_LOG=trace`. |
| 14 | `v0.1.0-alpha.13` | founder | The in-process `host-min` test shows host.memory PASS with the nominal-band note. |
| 15 | `v0.1.0-alpha.14` | founder | The result-fixture goldens for HTML and JSON pass on five legs. |
| 16 | `v0.1.0-alpha.15` | founder, shown on calls | The terminal renderer matches 07 C.17, C.18 and 2.7; demo only, not handed over. |
| 17 | `v0.1.0-alpha.16` | founder | Net.egress blocks a closed loopback port and refuses 169.254.169.254. |
| 18 | `v0.1.0-alpha.17` | founder | Against the loopback proxy, 407 and an intercepting CA are classified with fix text. |
| 19 | `v0.1.0-alpha.18` | founder | The kube mock records no request before the header prints context, server and user. |
| 20 | `v0.1.0-alpha.19` | founder | On kind with the read-only role, k8s.access, k8s.storageclass and k8s.rbac give real results. |
| 21 | `v0.1.0-alpha.20` | founder | The all-pass, warnings, all-block and no-privileges envs exit 0, 1, 2 and 2 on five legs. |
| 22 | `v0.1.0-alpha.21` | founder | A tampered spec fails before parsing in the parser-spy test. |
| 23 | `v0.1.0-alpha.22` | founder | The real-binary smoke exits 0, 1, 2 and 64 live on all five legs. |
| 24 | `v0.1.0-alpha.23` | founder | Docs-test runs every README and docs command green and the transcripts equal their goldens. |
| 25 | **`v0.1.0`** | design partners | `scripts/verify-release.sh v0.1.0` passes, the README quickstart reaches a report, and the strace contact-set test is green. |
| 26 | `v0.1.1` | design partners | An enforcing SELinux fixture with AVC denials blocks and a 400 s clock offset blocks. |
| 27 | `v0.1.2` | design partners | A cgroupfs and systemd driver mismatch blocks, and net.dns finds and misses names through getent. |
| 28 | `v0.1.3` | design partners | A closed registry blob host blocks and is named, and a `Fail` webhook with no endpoints blocks. |
| 29 | `v0.1.4` | design partners | The air-gapped env passes and every M1 row is in the Done log. |

**M1 exit test (the plan):** one design partner catches a real install blocker with it. It can be met
from week 25, when design partners get `v0.1.0` and the announcement. M1 is not closed until a
partner reports a blocker that rdy caught and the report is linked in the Done log as `M1-exit`, even if
every row is built. The engineering done test in `00-overview.md` is part of the exit test of
M1-138: replay fixture envs exit 0, 1 and 2 on all five legs, the real-binary smoke exits 0, 1, 2
and 64 live on all five legs, and tampered specs exit 64 even with `--allow-unsigned`.

## Founder hand steps

The build agent has no registrar, Cloudflare, mail or org-settings access and cannot work with design
partners. These steps came out of four exit tests on 2026-10-28 (see the Corrections log). The ticket's
PR ships the repo side. The founder does the step by hand and adds the evidence to the Done log as
`- <id> hand | <date> | <evidence>`. A step must be in the Done log before the ticket or event in "Needed
before".

| Step | From | Needed before | How the founder verifies it |
| --- | --- | --- | --- |
| Enable macOS arm64 runners for the getrdy-io org (or ask GitHub support why `macos-15` is never assigned), then move the macos-arm64 test back into the gate: add a macos-arm64 matrix leg on macos-15 back to the test job, drop the macos-arm64-compile leg, delete macos-arm64.yml, and retire ADR 0006 decision 8 and the 06 note | M1-006 | M1-138 | Link a `macos-arm64.yml` run on `macos-15` that got a runner and passed. After the move, a PR run shows `test (macos-arm64)` green under ci-ok. Add the run link and the PR to the Done log. |
| Edit CLAUDE.md, Engineering standards, "Five release targets" bullet: say that the macOS arm64 leg is compile-only on the PR gate and tested nightly until the org has macOS arm64 runners (correction 05), then restore "each running the full test job" when the Founder step above ends the fallback. The build agent does not edit CLAUDE.md. | M1-006 | M1-138 | Link the commit that changed CLAUDE.md in the Done log. |
| Before M1-010, run the release-sandbox proof in 06 "Sandbox proof" on getrdy-io/release-sandbox (agents have no access). After M1-010 merges and before M1-012, run the signing proof in 06 "Sandbox proof, signing (M1-010)" there too: create the environment `release` with a required reviewer, tag, approve, then verify on a clean machine (ADR 0024) | M1-007, M1-010 | M1-010 (the first proof), M1-012 (the signing proof) | Link the sandbox `Release` run, paste the PASS lines of `custom-check-release-artifacts` and the output of `scripts/check-release-artifacts.sh` on the downloaded assets into the Done log. For the signing proof also paste: `gh release view` showing no release during the approval wait, the `sign` job's "signed and verified" lines, the passing `cosign verify-blob` (with the repository, ref and trigger claims) and the two failing ones (one byte of `SHA256SUMS` changed, and a wrong `--certificate-github-workflow-repository`), and the release's `immutable` value. |
| Cut the first signed alpha by hand: merge a release PR that sets the `rdy` version to `0.1.0-alpha.1`, push the tag `v0.1.0-alpha.1`, click Approve on the `release` environment, then run `scripts/verify-release.sh v0.1.0-alpha.1` on a clean Linux machine. Steps are in `RELEASING.md` (ADR 0024) | M1-010, M1-012 | M1-015 | Paste into the Done log: the run URL, `gh release view v0.1.0-alpha.1 --json isPrerelease,isDraft,isImmutable,assets` (pre-release true, draft false), the full `verify-release.sh` output with exit 0, the one-byte `SHA256SUMS` failure with exit 1, the sha256 of `SHA256SUMS` and the Rekor log index. The signing proof in the row above comes first. |
| Hardware-key MFA on the registrar and Cloudflare, recovery codes stored offline | M1-008 | sending the M1-139 announcement | The script prints MANUAL for MFA. Write "MFA hardware keys confirmed" and the date in the Done log. |
| Registrar lock, DNSSEC (DS record at the registrar) and CAA records for getrdy.io | M1-008 | sending the M1-139 announcement | Run `scripts/check-domain.sh` and paste the PASS lines into the Done log. |
| HSTS on https://getrdy.io once the site is live | M1-008 | M2-019 | Run `scripts/check-domain.sh` and paste the full PASS output into the Done log. |
| Org-wide 2FA, private vulnerability reporting, immutable releases and SECURITY.md shown on the Security tab | M1-011 | sending the M1-139 announcement | Run `scripts/check-org-settings.sh` and paste the PASS output into the Done log. |
| Rulesets that reject a direct push to `main` and a `v*` tag from a non-admin | M1-011 | sending the M1-139 announcement | `scripts/check-org-settings.sh` shows PASS for both rulesets, a test direct push to `main` is rejected, and a `v*` tag push from a non-admin test account is rejected. Paste all three into the Done log. |
| After immutable releases are on, cut a fresh tag (for example `v0.1.1`) through the normal release workflow. GitHub makes only releases published after the setting immutable, so earlier tags stay mutable. | M1-010, M1-138 | sending the M1-139 announcement | Run `gh api repos/getrdy-io/rdy/releases/tags/v0.1.1 --jq .immutable` and `scripts/verify-release.sh v0.1.1`, and paste the `true` output and the passing verify output into the Done log. The announcement names this tag. |
| Dependabot alerts and version updates on | M1-011 | sending the M1-139 announcement | Link the first green Dependabot run in the Done log. |
| security@getrdy.io mailbox, and security.txt served at `https://getrdy.io/.well-known/security.txt` | M1-011 | sending the M1-139 announcement | Send a test mail and note that it arrived. Run `curl -sSf https://getrdy.io/.well-known/security.txt` and check it matches the repo file. Note both in the Done log. |
| Send the alpha announcement to every design partner | M1-139 | M1 complete | Pin the install command to the immutable tag from the step above. Tick the recipient checklist and add the Done log line in the M1-139 format with the sent date and recipient count. |
| Run the timed quickstart with two design-partner SEs | M1-167 | M1 complete | Follow the session script. Both reach a report in under five minutes and every stumble is filed with the issue template. Put both times and the issue links in the Done log. |
| Create a ruleset on getrdy-io/rdy that restricts creation of `v*` tags to admins (no update, no delete), so only an admin can start a release (the workflow also accepts only `v<major>.<minor>.<patch>[-<pre>]` tags) | M1-007 | M1-010 | `scripts/check-org-settings.sh` (M1-011) shows PASS for the tag ruleset and a push of the tag `vtest` from a non-admin test account is rejected. `vtest` matches the `v*` ruleset but not the release trigger, so a mistake cannot start a release. Paste both into the Done log. |

## How to work the backlog

- M1 started on 2026-10-28, when the founder approved the planning pass (13, Decisions made 2; open
  decision 1 is resolved). The founder still reserves the crates.io names by hand (13, open decision 4).
- Work tickets in id order. A ticket starts only when every id in its "depends on" is in the Done log.
- One PR per ticket. Title: `M1-042: <ticket title>`. The PR description quotes the exit test and shows
  the evidence: the test name, the CI run, or the command and its output.
- Review rules from KICKOFF "After the plan": the owning subagent implements. `code-reviewer` reviews
  cold. `security-reviewer` reviews if the ticket touches privileges, network, redaction, signing or the
  install script; the batch review tickets add to that per-PR review and do not replace it. `qa-engineer`
  adds or updates fixtures and golden tests: check-author writes the 08 Appendix E cases for each check,
  and qa-engineer reviews every PR that touches `tests/fixtures/**` or a golden. `docs-writer` updates
  docs in the same PR; generated reference pages are kept in sync by `cargo xtask docs --check` in CI.
  One PR per ticket, small, green.
- Every PR also meets CLAUDE.md: tests pass, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --all --check` and `cargo deny check` are clean, docs are updated, there is a CHANGELOG
  entry, and commit messages are in imperative mood with a one-line summary. PRs that change a golden
  carry a `## Golden changes` section, and every PR carries the `Compat matrix` line from the 08 template.
- Every check ticket meets 08 Appendix E: its exit test is read as "plus the Appendix E minimum cases".
- A Windows-only or Unix-only test is gated with `#[cfg]`; the other legs must still be green.
- A ticket that runs past twice its estimate stops and is split. New tickets take the next free number
  in their milestone and are added at the end of that milestone's rows. Ids are never reused or
  renumbered. After a split, the calendar, not the id, gives the order.
- Changing a ticket's exit test or estimate is a PR to this file, reviewed by rust-architect, with the
  reason in the PR description.
- To trim M1, stop after M1-139 or mark more tickets `core: no` in a PR. Skipped non-core tickets
  move to the head of M2, because some M2 tickets depend on them. Never trim a "0.1.0 gate" security
  ticket, the root-only trust store, verify before parse, the egress address policy, the kube guard, or
  the facade policies (00, 02).
- **Marking a ticket done:** in the PR that closes it, add one line to the Done log below:
  `- M1-042 | PR #123 | 2027-01-12`. Leave the table row as it is, so ids and dependencies stay stable.
  The Done log is the source for "what is built".

### Done log

None yet.

## Plan corrections found

- `09-docs-site.md`, M1 tickets: the hosted Starlight site, its CI jobs, deploy and hand-written pages
  are M1 there. The code-reviewer review moved them to M3; M1 keeps Markdown pages under `docs/`
  generated by xtask. The M1 install page tests the pinned release URL (PC-16), and
  `https://docs.getrdy.io/unsigned` is a single redirect to the Markdown page until the site exists.
  Fix: docs-writer re-syncs 09.
- `02-engine-design.md` (line 444), `03-check-catalog.md` (lines 17, 626, 636 and 847) and
  `10-devrel-and-launch.md` (lines 1245 and 1259) said `custom.exec` was M3; they now say M4 to match ADR 0005.
  Fix: one-line edits by their owners.
- `08-testing.md`: the `host-min` env, the real-binary smoke and the root job are new M1 tickets here.
  Fix: qa-engineer adds them to 08.

## Id map from the reviewed draft

The reviews of this file cite the draft's ids. This table maps each draft M1 id to its id now.

| Reviewed draft id | Now | Note |
| --- | --- | --- |
| M1-001 | M1-001 |  |
| M1-002 | M1-002 |  |
| M1-003 | M1-003 |  |
| M1-004 | M1-003 | merged |
| M1-005 | M1-004 |  |
| M1-006 | M1-005 |  |
| M1-007 | M1-006 |  |
| M1-008 | M1-009 |  |
| M1-009 | M1-007 |  |
| M1-010 | M1-010 |  |
| M1-011 | none | hand step before the go, not M1 hours |
| M1-012 | M1-009 | merged |
| M1-013 | M1-003 | merged |
| M1-014 | M1-011 |  |
| M1-015 | M1-011 | merged |
| M1-016 | M1-012 |  |
| M1-017 | M1-005 | merged |
| M1-018 | M1-006 | merged |
| M1-019 | M1-008 |  |
| M1-020 | M1-011 | merged |
| M1-021 | M1-016 |  |
| M1-022 | M1-014 |  |
| M1-023 | M1-015 |  |
| M1-024 | M1-017 |  |
| M1-025 | M1-017 | merged |
| M1-026 | M1-019 |  |
| M1-027 | M1-018 |  |
| M1-028 | M1-023 |  |
| M1-029 | M1-020 |  |
| M1-030 | M1-020 | merged |
| M1-031 | M1-022 | merged |
| M1-032 | M1-021 |  |
| M1-033 | M1-013 |  |
| M1-034 | M1-022 |  |
| M1-035 | M1-024 |  |
| M1-036 | M1-025 |  |
| M1-037 | M1-026 |  |
| M1-038 | M1-026 | merged |
| M1-039 | M1-029 |  |
| M1-040 | M1-031 |  |
| M1-041 | M1-030 |  |
| M1-042 | M1-031 | merged |
| M1-043 | M1-053 |  |
| M1-044 | M1-054 |  |
| M1-045 | M2-002 | moved to M2 |
| M1-046 | M1-055 |  |
| M1-047 | M1-032 |  |
| M1-048 | M1-033 |  |
| M1-049 | M1-034 |  |
| M1-050 | M1-035 | merged |
| M1-051 | M1-035 |  |
| M1-052 | M1-036 |  |
| M1-053 | M1-037 |  |
| M1-054 | M1-057 |  |
| M1-055 | M1-002 | merged |
| M1-056 | M1-059 |  |
| M1-057 | M1-038 |  |
| M1-058 | M1-039 |  |
| M1-059 | M1-040 |  |
| M1-060 | M1-041 |  |
| M1-061 | M1-042 |  |
| M1-062 | M1-043 |  |
| M1-063 | M1-058 |  |
| M1-064 | M1-044 |  |
| M1-065 | M1-044 | merged |
| M1-066 | M1-009 | merged |
| M1-067 | M1-045 |  |
| M1-068 | M1-046 |  |
| M1-069 | M1-049 |  |
| M1-070 | M1-049 | merged |
| M1-071 | M1-047 |  |
| M1-072 | M1-049 | merged |
| M1-073 | M1-050 |  |
| M1-074 | M1-051 |  |
| M1-075 | M1-052 |  |
| M1-076 | M1-048 |  |
| M1-077 | M1-060 |  |
| M1-078 | M1-056 |  |
| M1-079 | M1-061 |  |
| M1-080 | M1-062 |  |
| M1-081 | M1-063 |  |
| M1-082 | M1-001 | merged |
| M1-083 | M1-064 |  |
| M1-084 | M1-065 |  |
| M1-085 | M1-060 | merged |
| M1-086 | M1-066 |  |
| M1-087 | M1-067 |  |
| M1-088 | M1-069 |  |
| M1-089 | M1-068 |  |
| M1-090 | M1-071 |  |
| M1-091 | M1-072 |  |
| M1-092 | M1-073 |  |
| M1-093 | M1-074 |  |
| M1-094 | M1-075 |  |
| M1-095 | M1-077 |  |
| M1-096 | M1-078 |  |
| M1-097 | M1-078 | merged |
| M1-098 | M1-079 |  |
| M1-099 | M1-080 |  |
| M1-100 | M3-007 | moved to M3 |
| M1-101 | M1-081 |  |
| M1-102 | M1-082 |  |
| M1-103 | M1-083 |  |
| M1-104 | M2-001 | moved to M2 |
| M1-105 | M1-070 |  |
| M1-106 | M1-022 | merged |
| M1-107 | M1-086 |  |
| M1-108 | M1-088 | merged |
| M1-109 | M1-087 |  |
| M1-110 | M1-088 |  |
| M1-111 | M3-001 | moved to M3 |
| M1-112 | M3-002 | moved to M3 |
| M1-113 | M3-003 | moved to M3 |
| M1-114 | M3-004 | moved to M3 |
| M1-115 | M1-089 |  |
| M1-116 | M1-076 |  |
| M1-117 | M1-084 |  |
| M1-118 | M1-085 |  |
| M1-119 | M1-116 |  |
| M1-120 | M1-116 | merged |
| M1-121 | M1-090 |  |
| M1-122 | M1-091 |  |
| M1-123 | M1-092 |  |
| M1-124 | M1-093 |  |
| M1-125 | M1-094 |  |
| M1-126 | M1-095 |  |
| M1-127 | M1-096 |  |
| M1-128 | M1-097 |  |
| M1-129 | M1-098 |  |
| M1-130 | M1-099 |  |
| M1-131 | M1-100 |  |
| M1-132 | M1-101 |  |
| M1-133 | M1-116 | merged |
| M1-134 | M1-102 |  |
| M1-135 | M1-103 |  |
| M1-136 | M1-104 |  |
| M1-137 | M1-105 |  |
| M1-138 | M1-107 |  |
| M1-139 | M1-108 |  |
| M1-140 | M2-003 | moved to M2 |
| M1-141 | M1-109 |  |
| M1-142 | M1-106 |  |
| M1-143 | M1-110 |  |
| M1-144 | M1-111 |  |
| M1-145 | M1-113 |  |
| M1-146 | M1-114 |  |
| M1-147 | M1-115 |  |
| M1-148 | M1-116 | merged |
| M1-149 | M3-005 | moved to M3 |
| M1-150 | M1-117 |  |
| M1-151 | M1-118 |  |
| M1-152 | M1-119 |  |
| M1-153 | M3-006 | moved to M3 |
| M1-154 | M1-112 |  |
| M1-155 | M1-120 |  |
| M1-156 | M1-121 | merged |
| M1-157 | M1-121 |  |
| M1-158 | M1-122 |  |
| M1-159 | M1-133 | merged |
| M1-160 | M1-123 |  |
| M1-161 | M1-125 |  |
| M1-162 | M1-126 |  |
| M1-163 | M1-130 |  |
| M1-164 | M1-130 | merged |
| M1-165 | M1-126 | merged |
| M1-166 | M1-131 |  |
| M1-167 | M1-131 | merged |
| M1-168 | M1-132 | draft id only; the M1-168 in the backlog today is the correction-08 ticket |
| M1-169 | M1-133 | merged; draft id only; the M1-169 in the backlog today is the correction-14 ticket |
| M1-170 | M1-133 | draft id only; the M1-170 in the backlog today is the correction-16 ticket |
| M1-171 | M1-129 | draft id only; the M1-171 in the backlog today is the correction-16 ticket |
| M1-172 | M1-124 |  |
| M1-173 | M1-134 |  |
| M1-174 | none | removed; the work sits in the tickets it duplicated |
| M1-175 | M1-135 |  |
| M1-176 | M1-135 | merged |
| M1-177 | M1-136 |  |
| M1-178 | M2-061 | merged into the M2 full corpus |
| M1-179 | M1-137 |  |
| M1-180 | M1-138 |  |
| M1-181 | M1-139 |  |
| M1-182 | M3-008 | moved to M3 |
| M1-183 | M1-128 |  |
| M1-184 | M1-103 | merged |
| M1-185 | M3-009 | moved to M3 |
| M1-186 | M1-167 |  |
| M1-187 | M3-010 | moved to M3 |
| M1-188 | M3-011 | moved to M3 |
| M1-189 | M1-136 | merged |
| M1-190 | M3-012 | moved to M3 |
| M1-191 | M3-013 | moved to M3 |
| M1-192 | M1-031 | merged |
| M1-193 | M1-031 | merged |
| M1-194 | M1-140 |  |
| M1-195 | M1-027 |  |
| M1-196 | M1-141 |  |
| M1-197 | M3-014 | moved to M3 |
| M1-198 | M3-015 | moved to M3 |
| M1-199 | M1-142 | merged |
| M1-200 | M1-142 |  |
| M1-201 | M1-143 |  |
| M1-202 | M2-004 | moved to M2 |
| M1-203 | M2-005 | moved to M2 |
| M1-204 | M1-144 |  |
| M1-205 | M2-006 | moved to M2 |
| M1-206 | M1-145 |  |
| M1-207 | M1-146 |  |
| M1-208 | M1-147 |  |
| M1-209 | M1-148 |  |
| M1-210 | M1-149 |  |
| M1-211 | M1-150 |  |
| M1-212 | M1-151 |  |
| M1-213 | M1-152 |  |
| M1-214 | M2-007 | moved to M2 |
| M1-215 | M2-008 | moved to M2 |
| M1-216 | M2-009 | moved to M2 |
| M1-217 | M1-009 | merged |
| M1-218 | M1-153 |  |
| M1-219 | M1-154 |  |
| M1-220 | M1-155 |  |
| M1-221 | M1-156 |  |
| M1-222 | M1-157 |  |
| M1-223 | M1-158 |  |
| M1-224 | M2-010 | moved to M2 |
| M1-225 | M1-159 |  |
| M1-226 | M1-160 |  |
| M1-227 | M2-011 | moved to M2 |
| M1-228 | M1-161 |  |
| M1-229 | M1-163 |  |
| M1-230 | M1-164 |  |
| M1-231 | M1-165 |  |
| M1-232 | M1-162 |  |
| M1-233 | M4-001 | moved to M4 |
| M1-234 | M1-166 |  |
| M1-235 | M1-029 | merged |

## Corrections log

- 2026-10-28 | M1-008, M1-011, M1-139, M1-167 | The build agent has no registrar, Cloudflare, mail,
  org-settings or design-partner access, so each exit test now covers the repo-side deliverable and the
  human and account steps moved to "Founder hand steps". Ids, owners, estimates, dependencies and core
  marks are unchanged. The estimates stay because the founder still spends those hours on the hand steps.
- 2026-10-28 | M1-008, M1-011, M1-012, M1-138 | The founder is unreachable during the build, so the
  MFA and M1-011 settings steps are needed before the M1-139 announcement, not before M1-012. Until
  the founder enables immutable releases and rulesets and sends the announcement, every release is a
  pre-release labelled alpha in its notes, and no one is invited to install it.
- 2026-10-28 | M1-010, M1-138, M1-008, M1-011 | Code review of PR #4. GitHub makes only releases
  published after the setting immutable, and the build cannot turn the setting on. So M1-010 and M1-138
  no longer require immutability, and a new hand step cuts a fresh immutable tag for the announcement.
  Registrar lock, DNSSEC and CAA are needed before the announcement, because it and security.txt rely
  on getrdy.io. M1-138 closes only the repo side of SEC-04, SEC-05 and SEC-32.
- 2026-10-28 | M1-061, M1-043, M1-104, M1-001, Founder hand steps | Security closure check of M1-001,
  CF-04 to CF-06 and CF-08, and review of correction 01. M1-061 gets back "a PEM key" (ADR 0015 line 63,
  02 line 594). M1-043 gets back "a held snapshot lock" (02 lines 476 and 574, the test for the
  `try_lock` bound in 02 line 192). M1-104 gets back "an unlisted resource", "every ALLOWED entry is
  cited by a CheckInfo" and "a dropped request leaves a timeout entry with its check id" (02 line 586).
  CF-08: 05 revision 3 folds into M1-001, the only security-reviewer ticket that lands before M1-040;
  M1-101 and M1-132 land after it. Ids, owners, dependencies and core marks are unchanged. The CF-06
  re-estimate of M1-104 (1 h to 3.5 h) and the extra hour in M1-001 were first left out. Code review of
  PR #5 applied both: M1-104 is 3.5 h and M1-001 is 2 h, and the Totals and calendar intro say so. The
  fresh-tag hand step also runs `scripts/verify-release.sh v0.1.1` on that tag. HSTS stays needed before
  M2-019, although 05 T1 marks HSTS as an M1 control, because M1 installs use the pinned GitHub release
  URL, not getrdy.io. security-reviewer signed off 2026-10-28 in review of PR #5:
  `curl --proto '=https'` gains nothing from HSTS. 05 T1 is retagged in M1-001's threat model revision 3.
- 2026-10-28 | M1-003, M1-004 | Found while building M1-003. Every PR must pass `cargo deny check`,
  and with no deny.toml cargo-deny allows no licenses, so M1-003 could not be green. The repo also had
  no LICENSE file, although CLAUDE.md says Apache-2.0 and ADR 0007 publishes every crate. M1-003 now
  adds a minimal deny.toml with only the licenses the skeleton needs, plus LICENSE with the Apache-2.0
  text. M1-004 extends that file with the bans, the full allowlist and the webpki-roots entry. Ids,
  owners, estimates, dependencies and core marks are unchanged.
- 2026-10-28 | M1-003, M1-063, M1-138, calendar | M1-009 closes the planning pass. The calendar is
  re-cut from week 19 so no week holds more than 13.5 h: core still ends in week 25 and M1 ends in week
  30. M1-063 and M1-138 say 28 corpus cases, as 04 does. M1-003 says the 10 section 6 label set has 12
  labels, so "the 10 labels" cannot be misread. The SEC-21 correction is removed: 05 revision 3 says
  "no redirects". Ids, owners, estimates, dependencies and core marks are unchanged.
- 2026-10-28 | M1-003 | Code review of PR #13. M1-003 (PR #7) already built `changelog.d/` with its own
  fragment, and ADR 0017 makes fragments the CHANGELOG rule, so the exit test now names `changelog.d/`.
  The work is done; ids, owners, estimates, dependencies and core marks are unchanged.
- 2026-10-28 | M1-032, M1-034, M1-045 | Correction 04, found while building M1-032 (commit bca7981).
  M1-032 adds only the Check trait, CheckInfo, Need and CheckContext, so its exit test now checks the
  outcome types. The `Engine::run` clause moves to M1-034 as "through the scheduler": `Engine::run`
  also needs the Registry (M1-035) and an OutputDir (M1-036), which M1-034 does not depend on.
  `HostFs` and `host_root` are the pre-ADR 0014 names for the probe facade's read confinement, so
  M1-045 gains a read outside the check's `reads` prefixes; M1-049 already proves a replay run does no
  real file read. The setuid refusal (INV-10) is already M1-042's exit test, so it needs no edit. Ids,
  owners, estimates, dependencies and core marks are unchanged.
- 2026-10-28 | M1-006, Founder hand steps | Correction 05, found while building M1-006 (PR #21). The `test (macos-arm64)` leg on `macos-15` was never assigned a runner: four runs in a row queued about 15 minutes with an empty `runner_name`, no steps and no log, then cancelled. Nothing in `ci.yml` explains it (the matrix job's `timeout-minutes` is 25). A probe workflow on a throwaway branch, run 40737208354, queued `macos-15`, `macos-latest`, `macos-14` and `macos-26` and only `macos-15-intel` got a runner, so the org has no macOS arm64 runners. Main runs no tests until #21 merges, so blocking it is worse than a fallback. This mirrors the fallback 06 already allows for a retired Intel image: the PR gate runs four native test legs plus an `aarch64-apple-darwin` compile leg on `macos-15-intel` (build and `cargo test --no-run`), and `macos-arm64.yml` runs the full test job on `macos-15` nightly, on push to `main` and by dispatch, outside ci-ok. A Founder hand step ends the fallback. ADR 0006 records it. CLAUDE.md says "Five CI legs, each running the full test job"; that now has a temporary exception, and the wording change is a Founder hand step (see that table). Ids, owners, estimates, dependencies and core marks are unchanged.
- 2026-10-28 | M1-064 | Correction 06, found while building M1-064. The exit test said 3.7 GiB against
  `4Gi` passes with a note, but the documented memory band is max(5%, 256 MiB) (01 section 2.7, 03). For
  4Gi, 5% is 205 MiB, so the 256 MiB floor sets the band and the lowest passing value is 4 GiB minus 256
  MiB = 3.75 GiB. So 3.7 GiB blocks. The exit test now uses 3.8 GiB, which a 4096 MiB VM reports, and the
  band is unchanged. A VM that reports 3.7 GiB needs `tolerance_percent` raised in the spec. Ids, owners,
  estimates, dependencies and core marks are unchanged.
- 2026-10-28 | M1-007, Founder hand steps | Correction 07, found while building M1-007 (PR #47). The exit test said the SBOM is valid JSON. dist 0.33.0 runs a fixed `cargo cyclonedx -v`, which emits CycloneDX XML (`rdy.cdx.xml`), and has no setting for JSON. The exit test now says the SBOM is valid CycloneDX (XML or JSON). A JSON SBOM per target can come later from `auditable2cdx` in sign-release. The release-sandbox run needs a repo the build agent cannot reach, so a Founder hand step runs it before M1-010 using the steps in 06 "Sandbox proof". Ids, owners, estimates, dependencies and core marks are unchanged. ADR 0020 records the dist settings that differ from the plan.
- 2026-10-29 | M1-039, M1-040, M1-044, M1-138, M1-168, M2-104, calendar | Correction 08, from the build and review of M1-039 (PR #53). The exit test said a descriptor above 2 that `rdy` inherited does not reach the child. Closing or marking a descriptor by its raw number needs `unsafe`, and M1-039 keeps `#![forbid(unsafe_code)]`. ADR 0023 decides to detect, not close, in M1, and security-reviewer accepted it in PR #53. The exit test now says that `inherited_fds()` detects and lists inherited descriptors above 2 that are not close-on-exec. New M1-168 (1 h, core) calls `harden_umask()` and prints a redacted warning for inherited descriptors at CLI start-up. M1-138 depends on it, so it ships before the first public release. It runs in week 16. New M2-104 (2 h) is the ADR 0023 follow-up: the INV-18 FFI module that closes inherited descriptors before exec on Linux and macOS. The PR #53 review also put `rdy_engine::exec::run` and `ExecSpec` on the check-crate deny list, so M1-040 and M1-044 say so. M1 is now 168 tickets, 369.5 hours and 310.5 core; M2 is 104 tickets and 410 hours. Other ids, owners, estimates, dependencies and core marks are unchanged. The id map lists only draft ids, so the new ids are not in it.
- 2026-10-29 | M2-085 | Widened by the security review of PR #52 (M1-125). SEC-58 now covers the key files that `rdy spec keygen` makes as well as the report folder: on Windows they get an owner-only ACL, and `rdy spec sign` refuses a key file whose ACL lets others read it. M2-085 now depends on M1-125 too. The estimate is unchanged at 3 h, because the ACL code is the same and the key file is one more caller. Ids, owners and core marks are unchanged.
- 2026-10-29 | M1-057, M1-116 | Correction 09, from the review of M1-089 (PR #62, ADR 0026). 09 section 6 says the report prints the registry remediation, but no exit test checked it, and `rdy_engine::outcome` falls back to a generic no-advice text. M1-057's exit test now says a result with no fix of its own shows the check's `CheckMeta.remediation`, and that `cargo xtask checks` reads the same family list as `rdy run` (ADR 0026 decision 5). M1-116's exit test now says ids still in `HostFamily::stub_ids()` get no section (09 section 6, release scope), and reads are listed without an OS split, because `CheckInfo.reads` is one list for every OS until the manifest is keyed by OS. Ids, owners, estimates, dependencies and core marks are unchanged.
- 2026-10-29 | M1-010, M1-122, M1-126, M1-133, M2-105 | Correction 10, from the reviews of M1-010 (PR #66, ADR 0024) and M1-122 (PR #68, ADR 0027). With dist's `github-release = "announce"` (ADR 0020), no release exists while signing runs, not even a draft. M1-010's exit test now says no release exists until signing ends, then it is published. ADR 0024 makes the sandbox proof a founder hand step that runs after M1-010 merges; PR #66 updates that Founder hand steps row. ADR 0027 keeps every existing Windows trust store refused in M1, because reading a DACL or an elevated token needs `unsafe`. New M2-105 (8 h, core, the estimate in ADR 0027) is the follow-up: a `rdy-winacl` FFI crate that accepts an admin-only ProgramData store and detects an elevated run, with every unsafe block documented. The PR #68 security review adds two exit-test clauses. M1-126: on windows-x64, with a ProgramData trust store present, `rdy verify --key <pub>` exits 0 and `rdy verify` without `--key` exits 64 with `trust_store_insecure`, because `--key` runs never read the trust stores; and the INV-04 strace check, carried from M1-122, runs the real `rdy verify` on a signed fixture as root. M1-133: the unsigned page has a Windows section on verifying with the vendor key while Windows trust stores are refused. M1-122 notes that the real-binary strace check moves to M1-126. M2 is now 105 tickets and 418 hours. Other ids, owners, estimates, dependencies and core marks are unchanged. The id map lists only draft ids, so M2-105 is not in it.
- 2026-10-29 | M1-012, M1-015, M1-057, M1-102, M1-107, M1-108, M2-106, M2-107, calendar | Correction 11, from the reviews of M1-102 (PR #76), PR #75 and the security reviews of PR #66, PR #71 and PR #77. M1-057 now depends on M1-037: until M1-037 lands, the Windows output-folder harden step is a stub that fails open (PR #71 security review, finding 3), and `rdy run` must not write reports there. M1-102's exit test is trimmed to what a library ticket can prove: the context, server and kubeconfig user are passed to an announce callback before the first request; with no kubeconfig, load fails with `no kubeconfig found` and the 07 hint; exec plugin output never appears at RUST_LOG=trace, with any `interactiveMode` and with no TTY; and each kube entry is a clippy entry with a committed use file. The parts that move out go to two rows. M1-107: with no kubeconfig every k8s check is SKIP with the hint, the cluster line prints to stderr before the first request, after an exec plugin timeout the plugin process does not keep rdy from exiting (the ADR 0031 residual), and each kube entry from M1-102's use file, used once in tests/lint-wall, fails clippy; M1-107 now depends on M1-044 too. M1-044 keeps its scope and week, so the lint wall does not wait for the kube client. M1-108 depends on M1-106 and runs `tests/live_cluster.rs`, the ignored kind test from M1-102. The user shown before the first request is the kubeconfig user name; the SelfSubjectReview identity stays with M1-109. M1-012 and M1-015 add that a wrong caller repository, ref and trigger each fail (PR #66 security review, finding 1). M1-102 goes from 4 h to 3.5 h and M1-107 from 2 h to 2.5 h, because the SKIP wiring, the stderr line and the plugin exit test move to M1-107. M1 totals are unchanged. The PR #75 reviews found that `verify-release.sh --dir` still needs the network for the Sigstore trust root, so new M2-106 (2 h, core) adds an offline `--trusted-root <file>` mode for air-gapped verify. The PR #77 security review (finding 2) found that `rdy trust add` and `remove` can lose a change when they run at the same time, so new M2-107 (1.5 h, core) locks the trust store folder across load and save. M2 is now 107 tickets and 421.5 hours. Other ids, owners, estimates and core marks are unchanged. The id map lists only draft ids, so M2-106 and M2-107 are not in it.
- 2026-10-29 | M1-037, M1-040, M1-042, M1-044, M1-084, M1-091, M1-092, M1-093, M1-103, M1-107, calendar | Correction 12, from the reviews of PR #58 (M1-040), PR #76 (M1-102), PR #79 (M1-037) and PR #80. M1-040's exit test now lists every command and file and the redaction count. It adds that `Probe::exec` runs only commands built from the command table, so an unlisted program, `sh` and `sudo` are refused for the replay backend too, and that `exec::table::run`, `exec::run` and `ExecSpec::new` are on the root clippy disallowed list. It states the retention order: ok read, read_dir and stat entries go first, then failed ones, and a denied entry is never dropped for another kind. The facades and the kube client do not exist in M1-040's week, so their per-call entries move to the tickets that build them: one action-log entry per tcp call to M1-091, per tls call to M1-092, per http call to M1-093 and per kube call to M1-103. M1-040's "endpoint" covered tls too (02 line 272). The http entry goes to M1-093, not M1-091, because the HTTP probe is built there. The identity moves to M1-042, which takes the privilege snapshot. M1-044 adds `exec::table::run` to the check-crate deny list and names `ExecSpec::new` as M1-040 does (PR #58 C1). M1-107 adds a Windows `.cmd` exec plugin test, PATH resolution of a bare plugin name for the exec action-log entry, and, with no CA in the kubeconfig, trust in the facade SystemRoots (the follow-up in ADR 0031 decision 9). M1-107 now depends on M1-092, which runs in week 17, before M1-107 in week 20. M1-037's exit test now says a pre-planted junction or symlink with the target name is never followed or written through (the name moves to -2), and one swapped in after the folder is made exits 70 before the first check. M1-084's title and 09 section 5 now say oneOf or allOf if/then variants, because the schema emits check parameters as `allOf` with if/then (PR #80 review). M1-107 goes from 2.5 h to 3 h for its three new clauses, so week 20 holds 13 h, M1 is 370 hours with 311 core, and all milestones are 1305 hours. The moved log entries keep their tickets' estimates, because each is one line in a facade call. Other ids, owners, estimates and core marks are unchanged.
- 2026-10-29 | M1-040, M1-041, M1-057, M1-073, M1-074, M1-077, M1-138, calendar | Correction 13, from the reviews of PR #83 (M1-041) and PR #84 (M1-042). M1-041's exit test drops the HTML half: a 5 MiB message fails the result schema and an exec plugin shows in the JSON. The HTML half moves to M1-077, which builds the HTML report: the golden HTML run details show the credential plugin name (01 section 6, item 6) for a fixture with `identity.kube.exec_plugin` set. The terminal header (07 section 2.1) is not the HTML report. M1-077 now depends on M1-041, which adds that field. M1-040's exit test said the action log lists every command and file. Since M1-041, ok file calls past 200 per (check, kind, directory) fold into one coalesced entry with a count, and the row now says so. M1-074's entry point calls the privilege gate (`gate_then`, M1-042) before any command reads a spec or writes trust.yaml. On the linux-x64 leg a setuid-root `rdy` and, separately, an `rdy` with a file capability, run as the CI user, each exit 70 and never open the spec. The spec path is a FIFO with no writer, so an open would block: an exit 70 within 5 s proves the spec is never opened. The test is gated on `RDY_REQUIRE_SETUID=1` on the linux-x64 leg, like the minisign gate, and CI installs `libcap2-bin` for `setcap`. M1-138's edge to M1-074 is redundant but keeps the release gate explicit. M1-074 now depends on M1-042, and M1-138 on M1-074. M1-057's exit test adds that the run report records `identity` from the privilege snapshot, and M1-057 now depends on M1-042. Every new dependency runs in an earlier week (M1-041 and M1-042 in week 9, M1-057 in week 12, M1-074 in week 14). M1-074 goes from 2 h to 2.5 h for the two binary tests, which need sudo in CI. Week 14 was full, so M1-073 (1.5 h) moves to week 18, after M1-049 (week 11) and before M1-116 (week 22): week 14 holds 12.5 h and week 18 13 h, M1 is 370.5 hours with 311.5 core, and all milestones are 1305.5 hours. Other estimates stay: the HTML run details line is one field, and the identity is one field copied from the snapshot. Ids, owners, other estimates and core marks are unchanged.
- 2026-10-29 | M1-055, M1-072, M1-169, M2-108, M2-109, calendar | Correction 14, from the reviews of PR #83 (M1-041), PR #87 (M1-015), PR #88 (M1-045) and PR #89 (M1-084). host.ports (M1-072) reads `/proc/self/ns/net` and walks `/proc/<pid>/fd` for socket inodes, so it needs `read_link`, and the read denylist refuses `/proc/<pid>/fd` today (PR #88 review). New M1-169 (1.5 h, core) adds `Probe::read_link` with its own action-log kind and the /proc fd walk rule that host.ports declares. M1-072 now depends on M1-169. M1-169 runs in week 14, after M1-045 (week 10). Week 14 had 1 h of room, so M1-072 (3 h) moves to week 19, before its dependents M1-116 and M1-118 (week 22): week 14 holds 11 h and week 19 13.5 h. M1-055's exit test adds that the writer truncates lists past their schema caps, `observed` and `expected` past three levels and past 64 keys, and sets `truncated`, so a large real cluster still gives a valid report (PR #83 review). The estimate stays at 1.5 h, because the caps are the ones M1-041 puts in the schema. New M2-108 (1 h, core): `RDY_INSECURE_SKIP_SIGNATURE=1` alone no longer skips the `install.sh` signature check; it also needs a `--insecure-skip-signature` flag, so a Dockerfile `ENV` line alone cannot disable verification (PR #87 security review). The flag name follows the variable; cli-ux confirms it in the M2-108 PR. New M2-109 (2 h, core) derives `JsonSchema` on the check parameter types and deletes `check_params.json` (PR #89 review, ADR 0034). M1 is now 169 tickets, 372 hours and 313 core; M2 is 109 tickets and 424.5 hours, about 33 weeks; all milestones are 1310 hours with 1251 core. Core still ends in week 25 and M1 in week 30. Other ids, owners, estimates, dependencies and core marks are unchanged. The id map lists only draft ids; its M1-169 row is the draft id, not the new ticket. The review of PR #90 added: M1-055 depends on M1-041 (week 9), which sets the schema caps. M1-169's exit test returns only `socket:[N]` targets from the `/proc/<pid>/fd` walk, refuses and logs any other target without the path, says `/proc/self/ns/net` is NotFound off Linux and that Replay serves the 08 `symlinks` map, and needs security-reviewer's sign-off. M2-108 also updates the 06 override row, ADR 0025 and the install page, so it depends on M1-133 too. The 00-overview week table now matches this calendar for weeks 14, 18, 19 and 20.
- 2026-10-29 | M1-094, M1-105, M1-108, M1-109, M1-148, M1-150, calendar | Correction 15, from the reviews of PR #91 (M1-144), PR #92 (M1-103) and PR #93. M1-103's kind clause (SEC-24, a 0.1.0 gate) had no owner: M1-108 did not depend on M1-103 and ran the live test with an admin kubeconfig. M1-108 now depends on M1-103 and its exit test applies `examples/rbac/rdy-readonly.yaml` and passes the read-only live test with that service account. M1-103's fixture run used a hand-written call list because no k8s check exists yet, so M1-105's harness now checks every request the mock recorded against `ALLOWED` after each fixture run (INV-14). M1-105 also builds the two `ReadOnlyClient` routes M1-103 left out, discovery and the raw `SelfSubjectReview`, because M1-106, M1-108, M1-109, M1-113 and M1-114 all need them and all follow M1-105; M1-105 goes from 3.5 h to 4 h and week 20 to 13.5 h; M1 is now 372.5 h with 313.5 core, and all milestones 1310.5 h with 1251.5 core. M1-144's UDP facade admits a datagram only to a host in `Built::hosts`, which nothing fills yet, so a real run refuses every datagram: M1-148 now depends on M1-094 (the 64-host limit), adds the `ntp_servers` parameter as the only UDP host source, counts it toward INV-11 and handles a time server in a refused range. M1-150 redacts the Docker `/info` body it keeps. M1-094 refuses the GCP IPv6 metadata address. The opt-in dry-run `POST` in 03's k8s.admission needs no change: 03 already puts it in M2 after its ADR, and the M1 guard refuses it.
- 2026-10-29 | M1-057, M1-060, M1-068, M1-070, M1-083, M1-086, M1-091, M1-092, M1-105, M1-107, M1-111, M1-115, M1-170, M1-171, M2-002, calendar | Correction 16, from the reviews of PR #94 (M1-046), PR #95 (M1-104), PR #96 (M1-061) and PR #97. M1-061's whole-secret cut cases need M1-060's rules, so M1-060 now depends on M1-061 and enables them; the HTML halves of M1-046 and M1-061 go to M1-083 and the stderr half of M1-061 to M1-086. The known-secret set is only useful if the run fills it before the first write, so M1-057 now depends on M1-061 and registers declared secret env values first, M1-091 registers the proxy password, and M1-107 registers every kubeconfig user's credentials and the exec plugin's token, each exiting 70 if the set refuses one; M1-083, M1-086, M1-091, M1-107 and M2-002 now depend on M1-061 too, and M1-083 and M1-086 on M1-060. M1-104's citation test cannot finish before the k8s checks exist, so M1-115 requires its `NOT_BUILT_YET` list to be empty and every entry and check pair to be hit, and M1-105 checks each recorded request against the citing check. M1-111 owns the impersonation wiring and refuses a spec `as:` when the kubeconfig already impersonates, because kube adds its own headers below the guard. M1-092 caps `SystemRoots`. M2-002 registers the raw machine id. New M1-170 (1 h) denies the other machine identity files; new M1-171 (1 h) judges `Statvfs` by its own prefix list so host.disk does not need file reads over the whole tree, and M1-068 depends on it. M1-070 moves from week 13 to week 14 to make room. M1 is now 171 tickets, 374.5 h with 315.5 core, and all milestones 1312.5 h with 1253.5 core.
