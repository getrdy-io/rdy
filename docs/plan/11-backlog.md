# Rdy backlog, M1 to M5

Owner: rust-architect. Date: 2026-10-28. Everyone contributes; rust-architect keeps the table.

This is the one ticket list for M1 to M5. It merges the "Tickets implied" sections of `00-overview.md`
to `10-devrel-and-launch.md`, `docs/adr/README.md`, ADRs 0001 to 0016, and the ticket the review of
`13-plan-corrections.md` asked for. Where two documents named the same work, it is one ticket with both
exit tests folded in. Where a ticket "extends" another, it is merged into it or listed as a dependent
ticket. Every "depends on" is an id in this table. Estimates are founder hours, including review of
agent-written code.

The founder decided on 2026-10-28: M1 is extended, not cut. It is planned at its real size at 13 founder
hours a week and starts on Monday Nov 23, 2026, after a "go" on Nov 20 (open decision 1 in `13`). A tagged
binary ships every week.

**The core column.** In M1, `core: no` marks every ticket that a document put on its cut list or
marked `core: no`: the 24 M1-late check tickets from 03, the "by 0.1.1" security tickets, the tickets
07 and 10 marked `core: no`, the 08 add-back items, and the M2 facade tickets that the M1-late checks
now need. Everything else is `core: yes`. Two rules sit on top. A ticket that a core ticket depends on
is core (10's rule), so the README transcript fixtures and docs-test are core. The alpha announcement
(M1-181) is core although 10 marks it `core: no`, because the plan's exit test needs design
partners to get the build. Core tickets come first in the calendar. Trimming M1 means stopping after
M1-181 and skipping the three non-core tickets before it (M1-013, M1-017 and M1-178), not reshuffling.
Core is not a six-week build: core alone is 438 hours. In M2 to M5 every ticket is `core: yes`;
the marker only matters for the M1 trim.

**Reconciliation choices.** These are the merges and moves that are not obvious from the titles:

- ADR 0014 gave the probe facade every TCP, TLS and HTTP side effect, so ADR 0009's shared HTTP client
  builder has no M1 consumer. It moves to M2 as the base of the upload client (03 said the same).
- SEC-21 follows ADR 0014: no redirects are followed. 05's "capped redirects, sixth hop refused" is
  superseded.
- 03's "Command runner" is folded into the blocking helper and SEC-18. 09's schema emitter is the
  schemars ticket. 00's coarse `rdy-bundle`, AWS family, GPU family, data store and self-update tickets
  are replaced by the detailed tickets in 03, 04 and 06.
- SEC-26 is split into the 30 cases that gate 0.1.0 and the 30 that land by 0.1.1, as the security
  budget in the ADR review says.
- SEC-05, SEC-22 and the crates.io names stay in M1 (00, 05). 06 and 08 had them in M2.
- Four M2 tickets move into M1 as `core: no`, because the M1-late checks need them: UDP and unix socket
  facade methods (host.time_sync, host.container_runtime), Windows job objects (Windows host sources),
  sysinfo native calls (the macOS and Windows subset) and the ADR 0006 getent amendment (net.dns). 08's
  add-back items (net-airgapped, windows-2022-stub, the headless browser job) come back the same way.
- `--dry-run` and `--timeout` stay in M2, as 07 decided. 10 dropped its M1 `--dry-run` stretch ticket;
  the work is SEC-40 in M2.
- 01's tickets marked "done in this revision" are not listed. Their remaining test clauses are folded
  into the error types and example spec tickets. Tickets that used "the plan's example spec" as input now
  use `examples/specs/acme-platform.yaml`.
- Gaps no document ticketed are added: wiring `rdy run` end to end and tagging 0.1.0 with the version
  policy note (M1), the launch release candidate (M3) and the air-gapped kit (M5).
- `custom.exec` is in M4 with the GPU and store checks, as the scope set for this backlog asks. ADR 0005
  says M3; see "Plan corrections found". 00 now says M4. Store checks are M4 (00, ADRs); 03 had M3.
- Portal-side scope (results dashboard, bundle viewer, Slack alerts, Stripe billing, CRM sync, analytics,
  SSO, self-hosted portal, licensing server) lives in the private `rdy-cloud` backlog. This table holds
  the CLI and crate side of each milestone.

## Totals

| Milestone | Tickets | Hours | Core hours | Weeks at 13 h |
| --- | --- | --- | --- | --- |
| M1 | 235 | 571 | 438 | 46 (calendar below) |
| M2 | 97 | 398 | 398 | about 31 |
| M3 | 44 | 223 | 223 | about 17 |
| M4 | 22 | 114 | 114 | about 9 |
| M5 | 13 | 124 | 124 | about 10 |
| **All** | **411** | **1430** | **1297** | about 113 |

M2 to M5 tickets are coarse. When a milestone starts, rust-architect splits every ticket over 4 hours into
tickets of 1 to 4 hours, keeping the exit tests.

## M1 calendar

13 founder hours a week from Monday Nov 23, 2026. The weeks of Dec 21 and Dec 28 run at half capacity. A
week holds up to 13.5 hours of tickets so small tickets are not split. Builds are tagged on Thursday
(06). Builds before 0.1.0 (weeks 1 to 35) are `0.1.0-alpha.N` and are not given to design partners
for real POCs (PC-08). Until `rdy verify` lands in week 33 they run specs only with `--allow-unsigned`. `v0.1.0` ships when core is done; the non-core weeks
ship `v0.1.N` until M1 ends. `0.2.0-alpha.N` starts with M2.

- **0.1.0, the design-partner build:** week 36, Jul 26 to Aug 1, 2027. The alpha announcement
  (M1-181) goes out the same week. That is the core-only end date.
- **M1 ends:** week 46, Oct 4 to Oct 10, 2027. End date: Sunday Oct 10, 2027.
- At 10 hours a week the same order gives 0.1.0 in early October 2027 and the M1 end in early January
  2028. At 15 hours a week: 0.1.0 in late June 2027, M1 end in late August 2027.

| Week | Dates | Capacity | Hours | Build step | Tickets | Ships |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Nov 23 to Nov 29, 2026 | 13 | 13 | 1 Workspace, CI, release | M1-001 to M1-007 | `v0.1.0-alpha.0` (CI artefacts): `rdy version` built and tested on five CI legs |
| 2 | Nov 30 to Dec 6, 2026 | 13 | 13 | 1 Workspace, CI, release; plus non-core | M1-008 to M1-013 | sandbox pre-release: the same binary built by dist and cosign-signed in `getrdy-io/release-sandbox` |
| 3 | Dec 7 to Dec 13, 2026 | 13 | 13 | 1 Workspace, CI, release; 2 Spec parser, result model, engine core; plus non-core | M1-014 to M1-021 | `v0.1.0-alpha.1`: first signed pre-release on GitHub Releases; org and domain hardened |
| 4 | Dec 14 to Dec 20, 2026 | 13 | 12 | 1 Workspace, CI, release; 2 Spec parser, result model, engine core | M1-022 to M1-025 | `v0.1.0-alpha.2`: install.sh that checks the cosign signature, from the pinned release URL |
| 5 | Dec 21 to Dec 27, 2026 | 6.5 | 7 | 2 Spec parser, result model, engine core | M1-026 to M1-028 | `v0.1.0-alpha.3`: same CLI; rdy-spec parses specs with limits and line and column errors |
| 6 | Dec 28, 2026 to Jan 3, 2027 | 6.5 | 6.5 | 2 Spec parser, result model, engine core | M1-029 to M1-031 | `v0.1.0-alpha.4`: same CLI; result model and verdict mapping in rdy-spec |
| 7 | Jan 4 to Jan 10, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core | M1-032 to M1-035 | `v0.1.0-alpha.5`: generated JSON schemas in `crates/rdy-spec/schema/`; errors carry fix hints |
| 8 | Jan 11 to Jan 17, 2027 | 13 | 13 | 2 Spec parser, result model, engine core | M1-036 to M1-040 | `v0.1.0-alpha.6`: `rdy spec lint <file>` with line and column |
| 9 | Jan 18 to Jan 24, 2027 | 13 | 12.5 | 2 Spec parser, result model, engine core | M1-041 to M1-046 | `v0.1.0-alpha.7`: lint with did-you-mean and `--json`; bad flags exit 64; the quickstart example lints clean |
| 10 | Jan 25 to Jan 31, 2027 | 13 | 11.5 | 2 Spec parser, result model, engine core | M1-047 to M1-050 | `v0.1.0-alpha.8`: engine runs checks with timeouts and panic isolation; unknown ids SKIP |
| 11 | Feb 1 to Feb 7, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core | M1-051 to M1-056 | `v0.1.0-alpha.9`: `rdy run <file> --allow-unsigned --json` writes a 0700 report dir, every check SKIP, exit 2 |
| 12 | Feb 8 to Feb 14, 2027 | 13 | 12 | 2 Spec parser, result model, engine core | M1-057 to M1-060 | `v0.1.0-alpha.10`: commands run only through the mediated runner; action log in the JSON |
| 13 | Feb 15 to Feb 21, 2027 | 13 | 13 | 2 Spec parser, result model, engine core; 3 Host checks, HTML report | M1-061 to M1-066 | `v0.1.0-alpha.11`: privilege snapshot, run deadline and watchdog, Ctrl-C exits 70 cleanly |
| 14 | Feb 22 to Feb 28, 2027 | 13 | 13 | 3 Host checks, HTML report | M1-067 to M1-071 | `v0.1.0-alpha.12`: facade file policy and replay fixtures (internal, same CLI) |
| 15 | Mar 1 to Mar 7, 2027 | 13 | 12.5 | 3 Host checks, HTML report | M1-072 to M1-076 | `v0.1.0-alpha.13`: fixture lint, golden helpers, redactor core |
| 16 | Mar 8 to Mar 14, 2027 | 13 | 13.5 | 3 Host checks, HTML report | M1-077 to M1-082 | `v0.1.0-alpha.14`: every report string, log line and error redacted; 30-case corpus gates CI |
| 17 | Mar 15 to Mar 21, 2027 | 13 | 13 | 3 Host checks, HTML report | M1-083 to M1-088 | `v0.1.0-alpha.15`: first real check: host.memory with the nominal band |
| 18 | Mar 22 to Mar 28, 2027 | 13 | 13 | 3 Host checks, HTML report | M1-089 to M1-092 | `v0.1.0-alpha.16`: host.disk, host.cpu, host.ports, host.os on Linux |
| 19 | Mar 29 to Apr 4, 2027 | 13 | 13 | 3 Host checks, HTML report | M1-093 to M1-097 | `v0.1.0-alpha.17`: first HTML report next to the JSON |
| 20 | Apr 5 to Apr 11, 2027 | 13 | 13.5 | 3 Host checks, HTML report | M1-098 to M1-106 | `v0.1.0-alpha.18`: finished HTML report and golden reports; `rdy version --json` |
| 21 | Apr 12 to Apr 18, 2027 | 13 | 12.5 | 3 Host checks, HTML report | M1-107 to M1-111 | `v0.1.0-alpha.19`: the demo: bucket-sorted terminal output with fix lines and the verdict last |
| 22 | Apr 19 to Apr 25, 2027 | 13 | 13 | 3 Host checks, HTML report | M1-112 to M1-115 | `v0.1.0-alpha.20`: docs.getrdy.io live: overview and concepts |
| 23 | Apr 26 to May 2, 2027 | 13 | 13 | 3 Host checks, HTML report | M1-116 to M1-119 | `v0.1.0-alpha.21`: spec and result reference generated from the schema |
| 24 | May 3 to May 9, 2027 | 13 | 13 | 3 Host checks, HTML report; 4 Network checks | M1-120 to M1-123 | `v0.1.0-alpha.22`: host checks page; facade TCP and TLS (internal) |
| 25 | May 10 to May 16, 2027 | 13 | 12 | 4 Network checks | M1-124 to M1-127 | `v0.1.0-alpha.23`: net.egress direct, with the egress address policy |
| 26 | May 17 to May 23, 2027 | 13 | 12 | 4 Network checks | M1-128 to M1-131 | `v0.1.0-alpha.24`: net.egress through the customer's proxy, net.proxy, net.tls_intercept |
| 27 | May 24 to May 30, 2027 | 13 | 12 | 4 Network checks; 5 Kubernetes checks | M1-132 to M1-135 | `v0.1.0-alpha.25`: network checks page; kube client shows context, server and user |
| 28 | May 31 to Jun 6, 2027 | 13 | 12 | 5 Kubernetes checks | M1-136 to M1-139 | `v0.1.0-alpha.26`: read-only kube guard, lazy kube probe, kind job in CI |
| 29 | Jun 7 to Jun 13, 2027 | 13 | 12 | 5 Kubernetes checks | M1-140 to M1-143 | `v0.1.0-alpha.27`: k8s.access, k8s.version, k8s.storageclass |
| 30 | Jun 14 to Jun 20, 2027 | 13 | 13 | 5 Kubernetes checks | M1-144 to M1-148 | `v0.1.0-alpha.28`: k8s.rbac, k8s.nodes, k8s.admission (PSA); Kubernetes page |
| 31 | Jun 21 to Jun 27, 2027 | 13 | 13 | 5 Kubernetes checks; 6 Signing, `rdy verify`, 0.1.0 | M1-149 to M1-154 | `v0.1.0-alpha.29`: fixture envs for every verdict and for timeouts; compatibility page |
| 32 | Jun 28 to Jul 4, 2027 | 13 | 13 | 6 Signing, `rdy verify`, 0.1.0 | M1-155 to M1-159 | `v0.1.0-alpha.30`: signatures verified before parsing; trust store (library); /unsigned page |
| 33 | Jul 5 to Jul 11, 2027 | 13 | 13.5 | 6 Signing, `rdy verify`, 0.1.0 | M1-160 to M1-165 | `v0.1.0-alpha.31`: `rdy spec keygen`, `rdy spec sign`, `rdy verify`; unsigned refused without the flag |
| 34 | Jul 12 to Jul 18, 2027 | 13 | 13 | 6 Signing, `rdy verify`, 0.1.0 | M1-166 to M1-172 | `v0.1.0-alpha.32`: `rdy trust add\|list\|remove`; signing review closed; install, first-run, exit-code pages |
| 35 | Jul 19 to Jul 25, 2027 | 13 | 13.5 | 6 Signing, `rdy verify`, 0.1.0; plus non-core | M1-173 to M1-178 | `v0.1.0-alpha.33`: sign and verify page; README transcripts and docs-test; 60-case redaction corpus |
| 36 | Jul 26 to Aug 1, 2027 | 13 | 13 | 6 Signing, `rdy verify`, 0.1.0; plus non-core | M1-179 to M1-185 | **`v0.1.0`**: README ready, core done, announcement sent to design partners; SEC-22, SEC-24, SEC-31 closed |
| 37 | Aug 2 to Aug 8, 2027 | 13 | 13.5 | Non-core, steps 2 and 3 and 6 | M1-186 to M1-194 | `v0.1.1`: quickstart timed with two SEs; issue forms, repo hygiene, claims audit, cast; all example specs lint in CI |
| 38 | Aug 9 to Aug 15, 2027 | 13 | 12.5 | Non-core, steps 2 and 3 | M1-195 to M1-200 | `v0.1.2`: parser property tests; HTML bdi and headless checks; progress line |
| 39 | Aug 16 to Aug 22, 2027 | 13 | 12.5 | Non-core, step 3 | M1-201 to M1-204 | `v0.1.3`: quiet and verbose; macOS and Windows host checks from sysinfo; UDP and socket facade |
| 40 | Aug 23 to Aug 29, 2027 | 13 | 13 | Non-core, step 3 | M1-205 to M1-208 | `v0.1.4`: Windows job objects; host.lsm, host.security_agents, host.firewall |
| 41 | Aug 30 to Sep 5, 2027 | 13 | 13 | Non-core, step 3 | M1-209 to M1-212 | `v0.1.5`: host.time_sync, host.sysctl, host.container_runtime, host.cgroups |
| 42 | Sep 6 to Sep 12, 2027 | 13 | 13 | Non-core, steps 3 and 4 | M1-213 to M1-217 | `v0.1.6`: host.kernel; macOS and Windows host sources |
| 43 | Sep 13 to Sep 19, 2027 | 13 | 12 | Non-core, step 4 | M1-218 to M1-221 | `v0.1.7`: net.dns system and direct answers; net.registry |
| 44 | Sep 20 to Sep 26, 2027 | 13 | 13 | Non-core, steps 4 and 5 | M1-222 to M1-227 | `v0.1.8`: net.mtu, net.bandwidth, macOS and Windows net sources; k8s.nodes free capacity; admission webhooks |
| 45 | Sep 27 to Oct 3, 2027 | 13 | 13 | Non-core, step 5 | M1-228 to M1-232 | `v0.1.9`: k8s.namespace, k8s.ingress, k8s.crds, k8s.cni, k8s.dns |
| 46 | Oct 4 to Oct 10, 2027 | 13 | 7 | Non-core, steps 5 and 6 | M1-233 to M1-235 | `v0.1.10`: k8s.device_plugins, air-gapped fixture env, full help text; M1 complete |

## Backlog

| id | milestone | title | owner subagent | estimate (h) | core | depends on | exit test |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M1-001 | M1 | Confirm the revised ADRs close security findings MF-01 to MF-07 | security-reviewer | 1 | yes | none | Each must-fix is marked closed or reopened in docs/plan/reviews/ before the first M1 code ticket. |
| M1-002 | M1 | Confirm the revised ADRs close cli-ux findings M1 to M3 and the final command names | cli-ux | 1 | yes | none | 07-cli-ux.md uses the verdict words, status words and commands from ADRs 0002, 0003 and 0008. |
| M1-003 | M1 | Create workspace skeleton | rust-engineer | 2 | yes | M1-001, M1-002 | `cargo build`, `clippy -D warnings`, `fmt --check` and `cargo doc` with warnings as errors pass on edition 2024 crates with `forbid(unsafe_code)`, a pinned toolchain and shared lints, and `CHANGELOG.md` exists. |
| M1-004 | M1 | Package rdy in crates/rdy-cli with binary name rdy | rust-engineer | 1 | yes | M1-003 | `cargo run -p rdy -- version` and `-- --version` print the documented line and `cargo package -p rdy --list` contains no stray files. |
| M1-005 | M1 | Add deny.toml with crate bans and license allowlist | release-engineer | 2 | yes | M1-003 | Adding serde_yaml, serde_yml, libyml, openssl-sys, native-tls, aws-lc-sys or atty fails `cargo deny check` in CI, and webpki-roots passes under its CDLA-Permissive-2.0 entry. |
| M1-006 | M1 | CI lint and deny job: fmt, clippy, doc, cargo-deny, zizmor (SEC-01) | release-engineer | 2 | yes | M1-005 | A PR is green, and throwaway PRs that add a clippy warning and add `openssl` both turn it red. |
| M1-007 | M1 | CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | release-engineer | 4 | yes | M1-006 | A run with all five legs green, both Linux binaries pass the `readelf` no-INTERP and no-NEEDED check and run in a scratch container, and a PR with one red leg cannot merge. |
| M1-008 | M1 | Apply blocks-M1 and should-fix plan corrections to CLAUDE.md, KICKOFF.md and rdy-plan.md | rust-architect | 3 | yes | none | Every blocks-M1 and should-fix entry in 13-plan-corrections.md is applied or rejected, and its row is deleted from 13. |
| M1-009 | M1 | dist init for five targets with cargo-auditable and SBOM, proven in release-sandbox | release-engineer | 3 | yes | M1-007 | A tag in `getrdy-io/release-sandbox` builds five archives with checksums, `cargo audit bin` lists dependencies from a downloaded binary, the SBOM is valid JSON, and `rdy.exe` imports no `VCRUNTIME140.dll`. |
| M1-010 | M1 | sign-release with cosign keyless, SHA256SUMS and self-verify (SEC-06, SEC-07) | release-engineer | 4 | yes | M1-009 | In the sandbox the signing job waits for approval, the release stays a draft until signing ends and is then published immutable, and `cosign verify-blob` with the exact identity passes on a clean machine and fails after one byte of `SHA256SUMS` changes. |
| M1-011 | M1 | Reserve crates.io names with 0.0.1 placeholders (SEC-11) | release-engineer | 1 | yes | none | The nine crate names in CLAUDE.md plus `rdy-cli` resolve on crates.io to a getrdy-io-owned 0.0.1, `rdy-cli`'s description says "install rdy", and the founder published them by hand and deleted the token. |
| M1-012 | M1 | Update CLAUDE.md commands to cargo run -p rdy | docs-writer | 1 | yes | M1-004 | Every command in the CLAUDE.md Commands block runs green on a fresh clone. |
| M1-013 | M1 | PR template and labels | devrel | 1 | no | M1-003 | A test PR shows the checklist from CLAUDE.md and the 08 Appendix E items, and the labels from 10 section 6 exist. |
| M1-014 | M1 | SEC-04 Org 2FA, private reporting, immutable releases, CODEOWNERS and a settings check script | security-reviewer | 2 | yes | none | `scripts/check-org-settings.sh` uses `gh api` to confirm org-wide 2FA, private vulnerability reporting, immutable releases and CODEOWNERS on security paths, and fails when one is off. |
| M1-015 | M1 | Rulesets on main and v* tags, Dependabot, SHA-pinned actions (SEC-03) | release-engineer | 1 | yes | M1-007, M1-014 | A direct push to `main` and a non-admin `v*` tag are rejected, the Dependabot job shows a green run, and a grep finds no `uses:` line without a commit SHA. |
| M1-016 | M1 | First signed alpha, scripts/verify-release.sh and RELEASING.md | release-engineer | 2 | yes | M1-010, M1-015 | `v0.1.0-alpha.1` exists on `getrdy-io/rdy` and `scripts/verify-release.sh v0.1.0-alpha.1` passes on a clean Linux machine. |
| M1-017 | M1 | DCO sign-off check in CI | release-engineer | 1 | no | M1-006 | A PR with an unsigned commit fails the check and one with `Signed-off-by` passes. |
| M1-018 | M1 | Nextest ci profile and cargo test --doc in CI | qa-engineer | 1 | yes | M1-007 | A test that fails once in three runs is not retried and `cargo test --doc` runs on linux-x64. |
| M1-019 | M1 | SEC-05 Harden getrdy.io domain and hosting accounts | release-engineer | 2 | yes | none | Registrar lock and hardware-key MFA are confirmed on the registrar and Cloudflare, and a CI job runs `dig +dnssec`, `dig CAA` and `curl -sI https://getrdy.io` with an HSTS grep, and all pass. |
| M1-020 | M1 | SEC-32 Security mailbox and security.txt | security-reviewer | 1 | yes | M1-014, M1-019 | Security@getrdy.io receives a test mail and `https://getrdy.io/.well-known/security.txt` returns both channels. |
| M1-021 | M1 | Define public spec types in rdy-spec | rust-engineer | 3 | yes | M1-003 | Every file in examples/specs (acme-platform.yaml included) decodes through parse_unverified into typed values, the metadata fields of 01 section 2.2 round-trip through serde_json, and no public path builds a LoadedSpec without load(). |
| M1-022 | M1 | install.sh core with root refusal, truncation guard, sha256 and shell tests (SEC-08) | release-engineer | 4 | yes | M1-009 | Shellcheck is clean, the shell tests pass under dash and busybox sh, uid 0 without `--allow-root` exits 1 with the fix, and a cut-off script run installs nothing. |
| M1-023 | M1 | install.sh signature check, fail closed, with tamper tests (SEC-09, SEC-10) | release-engineer | 4 | yes | M1-022, M1-016 | With a real cosign the alpha.1 install passes, and bad hash, bad signature, wrong identity, missing bundle and missing cosign (with and without the override) each fail with the documented message. |
| M1-024 | M1 | Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | rust-engineer | 3 | yes | M1-021 | A 2 MiB file, an anchor or alias, a duplicate key and `cuda: 12.10` unquoted each give the documented SpecError with line and column, never a panic, and the geiger result is recorded in ADR 0001. |
| M1-025 | M1 | SEC-62 Parser rejects tags, directives and non-finite floats | rust-engineer | 1 | yes | M1-024 | `!!binary`, `!custom`, `%YAML 1.1`, `.inf` and `.nan` fixtures each exit 64 with line and column. |
| M1-026 | M1 | Two-step check decoding with Unknown and Unsupported variants | rust-engineer | 3 | yes | M1-021, M1-024 | `gpu.cuda` decodes to Unknown, `host.memory` with `mn` to Unsupported naming `mn`, and a missing id or duplicate entry key is a SpecError with line and column. |
| M1-027 | M1 | Scalar types Quantity, Duration, Version and Target with strict grammars | rust-engineer | 2 | yes | M1-021 | Unit tests reject `32G`, unquoted `1.30`, `10 s`, `host:99999` and `https://u:p@host/`, and accept `32Gi`, `"1.30"`, `14`, `7d` and `[::1]:443`. |
| M1-028 | M1 | Reserved check ids and the not_in_build lint rule | rust-engineer | 2 | yes | M1-026 | `host.kernel` lints as not_in_build, a `gpu.cuda` entry only warns, and `mn: 32Gi`, `min: 32G` and `host.memroy` are lint errors with a fix. |
| M1-029 | M1 | Define result model and verdict mapping in rdy-spec | rust-engineer | 3.5 | yes | M1-021 | A table test covers every severity and status pair, unknown severity and status, the partial rule including Partial OS support, the not_applicable source rule and the empty run, asserts verdict_reason and exit codes (a skipped block check gives not_ready and exit 2), and the 01 samples 7.2 to 7.4 round-trip byte for byte. |
| M1-030 | M1 | Forward-compatibility fixtures for results | rust-engineer | 1 | yes | M1-029 | A result with an extra top-level field, status "quarantined" and bucket "frozen" deserializes, maps both to Unknown and keeps its recorded verdict. |
| M1-031 | M1 | Validate hand-written schemas against examples in CI | rust-engineer | 2 | yes | M1-021, M1-029 | CI validates every file in examples/specs, the 01 7.x samples and every golden result with a 2020-12 validator, and the hostile fixtures of both 01 reviews give the documented accept or reject. |
| M1-032 | M1 | Error types with fix hints and exit code mapping at the CLI edge | rust-engineer | 3.5 | yes | M1-029 | Every error variant and every SpecError and skip kind has the 01 section 2.5 or 5.2 message and a non-empty hint, exit 64 and 70 cases print `fix:`, `--json` failures print the error object with a stable code, and control characters in a spec string are stripped. |
| M1-033 | M1 | xtask skeleton with schema, docs, docs-lint and --check modes, dist and publish off | docs-writer | 4 | yes | M1-003 | `cargo xtask docs --check` exits 1 after a generated page is hand-edited and 0 on a clean tree, and docs-lint fails on a planted em dash and a planted banned-token hash match. |
| M1-034 | M1 | Generate JSON schemas with schemars behind cargo xtask schema and check drift in CI | rust-engineer | 3 | yes | M1-029, M1-033, M1-031 | The generated files accept and reject the same fixtures as the hand-written ones and replace them, `cargo xtask schema --check` fails after a type or doc-comment change that is not regenerated, and a description containing "ADR" or a milestone name fails CI. |
| M1-035 | M1 | Typed parameters for M1 host check ids | rust-engineer | 3 | yes | M1-026, M1-027 | Every host id in 01 section 2.7 decodes from a fixture covering each field, each field has a rejecting case, and a missing required threshold is Unsupported. |
| M1-036 | M1 | Typed parameters for M1 net and k8s check ids | rust-engineer | 4 | yes | M1-026, M1-027 | Acme-platform.yaml and acme-k8s-only.yaml decode, `needs` on k8s.storageclass is Unsupported, and every net and k8s id in 01 section 2.7 has an accepting and a rejecting fixture. |
| M1-037 | M1 | Semantic validation and structural limits for specs | rust-engineer | 2 | yes | M1-026 | Fixtures for 257 checks, 65 endpoints, a duplicate key, a bad product, an unknown metadata key, an unknown bundle key and a relative `file:` collector each exit 64 with the 01 section 2.5 wording. |
| M1-038 | M1 | Spec expiry and serial in metadata | rust-engineer | 1 | yes | M1-037 | An expired fixture exits 64 with spec_expired, both dates in the first line, before any check runs. |
| M1-039 | M1 | clap command tree in rdy-cli exposed as library rdy_cli | rust-engineer | 3 | yes | M1-004 | Snapshots of `-h` and `--help` for `rdy`, `rdy run` and `rdy verify` match 07 Appendix A (`--timeout` and `--dry-run` absent), the other commands print the compact form, and bare `rdy`, `rdy spec` and `rdy trust` print help on stdout and exit 0. |
| M1-040 | M1 | rdy spec lint with errors, warnings and did-you-mean | rust-engineer | 3 | yes | M1-028, M1-037, M1-035, M1-036, M1-039 | Lint exits 1 on acme-platform.yaml with two not_in_build warnings, 2 on `mn: 32Gi` with "did you mean min" and its line, and `--json` output validates as LintReport. |
| M1-041 | M1 | Usage errors, the flag suggester and no echo (extends M1 error types) | rust-engineer | 4 | yes | M1-039, M1-032 | Clap usage errors exit 64 with the two-line form and help and version exit 0 on stdout, `--json` gives an ErrorOutput with code `usage`, golden stderr covers `--out-dri`, a missing argument, a bad value and `-q` with `-v`, and canaries in `--tokne=` and `--pasword` and the near-misses `--keey`, `--allow-unsgned` and `--kye` never put a secret, `--key` or `--allow-unsigned` in stderr or `ErrorOutput.fix`. |
| M1-042 | M1 | Review and lint acme-quickstart.yaml | devrel | 1 | yes | M1-040 | `rdy spec lint examples/specs/acme-quickstart.yaml` exits 0, every block and warn check has a `fix`, and the file runs on Linux with only M1 checks. |
| M1-043 | M1 | Add bucket to CheckResult and sort by it in terminal and HTML | rust-engineer | 2 | yes | M1-029 | A fixture with every outcome sorts blocker, required_not_run, warning, passed, not_applicable, and the bucket counts equal the summary. |
| M1-044 | M1 | Summary line grammar and nothing-verified last line | rust-engineer | 1.5 | yes | M1-029 | Golden strings for the three samples in 01 section 5.3, each last line in its table, and singular and plural forms pass. |
| M1-045 | M1 | Host identity and host_id derivation | rust-engineer | 2 | yes | M1-029 | A fixture machine id gives the documented HMAC host_id, another product gives a different one, macOS gives null, and a fixture run's JSON has no MAC, home path or environment value. |
| M1-046 | M1 | HTML-safe deterministic JSON writer with size caps | rust-engineer | 2 | yes | M1-029 | A hostname with `</script>` is written as `\u003c/script\u003e`, and the .json file, `--json` stdout and the HTML copy hash the same. |
| M1-047 | M1 | Check trait, Need and Context in rdy-engine | rust-engineer | 3.5 | yes | M1-029 | A fixture family with one passing and one need-missing check produces pass and skipped missing_need through Engine::run, HostFs reads only under host_root, a setuid launch is refused (INV-10), and no CheckError or Support variant can produce not_applicable. |
| M1-048 | M1 | Map outcomes to CheckResult with fix source, partial and needs | rust-engineer | 2 | yes | M1-047 | A spec fix replaces the built-in text on block with fix_source spec and is hidden on skipped, a partial pass on a block check becomes warn unless evidence_only, a Partial OS result is marked partial, and needs carry met flags. |
| M1-049 | M1 | Scheduler with concurrency limit, per-check timeout and panic isolation | rust-engineer | 4 | yes | M1-047 | With the timer on the join handle a check that sleeps forever reports Timeout, one that panics reports Error, Spin on a 2-worker runtime still lets the other checks finish, and `--jobs 500` is capped at 32. |
| M1-050 | M1 | Unknown check ids report Skipped with a "needs a newer rdy" reason | rust-engineer | 2 | yes | M1-047 | Examples/specs/acme-platform.yaml with its unknown id, plus a fixture holding gpu.cuda and aws.iam, runs and reports each as SKIP with the reason and fix line, not as a parse error. |
| M1-051 | M1 | Family trait, registry and run plan | rust-engineer | 3 | yes | M1-050 | The plan for acme-platform.yaml gives not_in_build for gpu.cuda and aws.iam, unknown_check for a typo id, not_yet_on_os for host checks on Windows, not_applicable only for an `os: [linux]` entry on macOS, per-check host sets, and does no I/O. |
| M1-052 | M1 | SEC-19 Confine writes to a new output dir with safe names | rust-engineer | 4 | yes | M1-021 | Product `../x` fails validation, a pre-planted symlink is not followed, an existing file is never overwritten and a taken name moves to `-2`, modes are 0700 and 0600 under a setgid parent, the spec copy matches the verified bytes, a killed run leaves no file under a final name, and `--out-dir` and `--no-report` behave as written. |
| M1-053 | M1 | Windows output directory default and reparse-point checks | rust-engineer | 1 | yes | M1-052 | On the Windows CI leg the default lands under %USERPROFILE%\rdy-reports, and a pre-planted junction and a symlink with the target name are both refused before the first check. |
| M1-054 | M1 | Wire rdy run end to end: load, needs, families, engine, report, exit code | rust-engineer | 3 | yes | M1-039, M1-051, M1-049, M1-048, M1-032, M1-046, M1-052 | `rdy run examples/specs/acme-platform.yaml --allow-unsigned --json` writes a new report directory, prints one Report on stdout that validates against the result schema, lists every check (SKIP "not built yet" until its family lands) and exits by the verdict. |
| M1-055 | M1 | cli-ux review of verdict wording, interrupt behaviour and output naming in 02 | cli-ux | 1 | yes | none | 07-cli-ux.md confirms the headline, the M1 Ctrl-C exit 70 message, `--no-network`, `--out-dir` and the plan flag name. |
| M1-056 | M1 | --no-network and --jobs flags | rust-engineer | 1.5 | yes | M1-049, M1-039 | `--no-network` skips network and Kubernetes checks as `missing_need` with zero `socket(2)` calls under strace and no `connect` entries in the action log, `--jobs 500` prints a cap note, and `--jobs 0` exits 64. |
| M1-057 | M1 | Blocking helper and subprocess kill on timeout | rust-engineer | 4 | yes | M1-049 | A check running a script that forks `sleep 600` times out, the whole process group is gone, a child that ignores reaping returns Hung within 1 s of SIGKILL, and `rdy` exits within 2 s of the deadline. |
| M1-058 | M1 | SEC-18 Command policy: search path, declared directories, caps and Windows whoami only | rust-engineer | 2 | yes | M1-057 | Shells and the sudo family are refused, PATH is fixed for root and non-root runs so a fake binary earlier in PATH is not used, LD_PRELOAD in the parent never reaches the child, a declared extra directory resolves, and on Windows only the constant whoami.exe path runs. |
| M1-059 | M1 | SEC-17 Mediated Context handles with action log and read denylist | rust-engineer | 4 | yes | M1-047, M1-057 | The fixture run's JSON action log lists every command, file, endpoint and kube request plus identity and the redaction count, a read of /proc/1/environ is refused, a Probe call after its check ends is denied and logged, and truncation drops only ok read, read_dir and stat entries. |
| M1-060 | M1 | SEC-63 Result schema caps, identity.kube exec plugin and action log retention | rust-engineer | 2 | yes | M1-029, M1-059 | A 5 MiB message fails the result schema, an exec plugin shows in JSON and HTML, and a 300-check flood keeps every connect and kube entry with actions_dropped counts. |
| M1-061 | M1 | Privilege snapshot, binary refusal and capability probes | rust-engineer | 3.5 | yes | M1-059 | Injected mismatches of real, effective, saved and filesystem uid or gid, a nonzero CapEff or CapAmb, and AT_SECURE each exit 70 with the hint before the spec is read, recorded whoami output maps High and System to elevated, and needs absent from the plan are not probed. |
| M1-062 | M1 | Run deadline and watchdog with a report on hang | rust-engineer | 3.5 | yes | M1-049, M1-052 | Under paused time running checks become timeout and unstarted ones run_deadline, a finish at deadline plus 9.9 s keeps the complete report, and two Spin checks with a blocked stdout pipe still give a `complete: false` report and exit 70 within deadline plus 22 s with no child process group left. |
| M1-063 | M1 | Ctrl-C in M1: abort, remove the empty report folder, exit 70 | rust-engineer | 2 | yes | M1-049, M1-052, M1-055 | A pty test sends SIGINT once and gets the two-line error of 07 section 5.1, exit 70, no report folder and no child process left, SIGTERM does the same, and `--json` prints an ErrorOutput with code `interrupted`. |
| M1-064 | M1 | Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers | rust-engineer | 2 | yes | M1-059 | Every 02 Appendix A entry used in tests/lint-wall fails clippy, an allow attribute outside the allowlisted files fails CI, and a check crate depending on socket2 fails cargo deny. |
| M1-065 | M1 | Direct dependency allowlist for check crates | rust-engineer | 1 | yes | M1-064 | Adding `walkdir` to rdy-checks-host fails CI, and the lint-wall crate has one exact entry per item with no wildcard. |
| M1-066 | M1 | Amend ADR 0015 with span union, keyed tags, Redacted<T> and ring | rust-architect | 1 | yes | none | ADR 0015 is Accepted with the 04 bullet and a security-reviewer sign-off. |
| M1-067 | M1 | File and env read policy in the facade | rust-engineer | 3.5 | yes | M1-059 | /etc/shadow, a symlink to it, a `..` path, a FIFO and /dev/zero under an allowed prefix are refused and logged, a 2 MiB file returns 1 MiB with truncated true, and an undeclared env name is refused. |
| M1-068 | M1 | Closed NativeCall enum in the facade | rust-engineer | 2.5 | yes | M1-067 | Statvfs outside the check's prefixes is refused, every variant is logged as native, the raw machine id appears nowhere in the report, the variant snapshot test fails on a new variant, and check crates cannot call live_backend. |
| M1-069 | M1 | Replay backend and fixture loader | rust-engineer | 3 | yes | M1-067, M1-068 | A host.memory fixture runs with no real file read, an unrecorded argv fails with NotRecorded, a recorded link-local lookup is refused by the address rule, and the release feature tree excludes `testing`. |
| M1-070 | M1 | Fixture manifest (symlinks, unreadable, dirs), placeholders and Windows-safe command names | rust-engineer | 2 | yes | M1-069 | A `/proc/<pid>/fd` symlink fixture and an unreadable audit log load on the Windows CI job, and a golden file with `"<sha256>"` placeholders compares equal across runs. |
| M1-071 | M1 | Fixture format README, .gitattributes and Windows canary | qa-engineer | 2 | yes | M1-007 | `tests/fixtures/README.md` documents every file in 08 section 2 and Appendix A, `.gitattributes` has the 08 lines, and the windows-x64 leg checks out with `core.autocrlf true`, shows `git check-attr text` as `unset` for fixtures and keeps one CRLF fixture intact. |
| M1-072 | M1 | Replay loader reads the 08 fixture format | rust-engineer | 3 | yes | M1-069, M1-070 | A `fixture.toml` with `base`, `remove` and `answers` loads, `root/c/Windows/...` answers only when `os = "windows"`, a manifest symlink to `/etc/shadow` is Denied, and `delay_ms` and `blackhole` run on the tokio clock with no blocking thread. |
| M1-073 | M1 | Fixture lint as a nextest test | qa-engineer | 3 | yes | M1-071, M1-072 | A planted public hostname, a `\r` outside `crlf`, a file named `con.json`, a 2 MiB file, a public IP, an `origin = "laptop"` and a duplicate argv key each fail with the file named. |
| M1-074 | M1 | Engine test helpers FakeCheck, run_fixture and normalize | qa-engineer | 2 | yes | M1-072 | Scheduler tests use FakeCheck for every status including Spin, `Fake::Block` waits on a receiver the test releases, `assert_within_manifest` fails on an undeclared read, and `normalize` gives equal reports for `jobs = 1` and `jobs = 8`. |
| M1-075 | M1 | Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check | qa-engineer | 2 | yes | M1-074 | A changed output fails with a diff and an `.actual` file, a missing golden fails, `UPDATE_GOLDENS=1` is refused when `CI` is set and never touches `tests/fixtures/redaction/**`, and `cargo xtask goldens check` fails on an orphan. |
| M1-076 | M1 | SEC-25 Minimal redactor for evidence, errors and logs | rust-engineer | 2.5 | yes | M1-066, M1-029 | Overlapping spans give one placeholder, equal secrets share a tag per Redactor, `password=[REDACTED:x:00000000]hunter2` is redacted, and `Redacted` has no public constructor or Deserialize. |
| M1-077 | M1 | M1 redaction rules for URLs, auth headers, AWS keys, PEM keys, JWTs, rdy tokens and key names | rust-engineer | 3.5 | yes | M1-076 | The 23 positive corpus inputs come out typed with quotes kept, and `secretName: acme-tls`, `${DB_PASSWORD}`, `passed: 12` and a certificate are unchanged. |
| M1-078 | M1 | Redacting tracing writer, panic hook and CLI error text | rust-engineer | 2 | yes | M1-076 | Canaries in env, a proxy URL, kubeconfig, command output and a tracing field never reach JSON, HTML or stderr at RUST_LOG=trace. |
| M1-079 | M1 | Redact facade-truncated buffers and a run-scoped known-secret set | rust-engineer | 3 | yes | M1-076, M1-067 | A PEM key, an AWS key id and a URL with userinfo placed across the stdout, stderr, file and tail caps at offsets cap minus 1 to cap minus 64 never appear in JSON, HTML or stderr, and the kubeconfig token is redacted wherever it appears. |
| M1-080 | M1 | Redact then cap every Report string and return RedactedReport | rust-engineer | 2.5 | yes | M1-076, M1-048 | A PEM key across a 64 KiB cap is fully redacted, results are redacted as they complete, the 01 samples round-trip byte-identical apart from planted canaries, `by_rule` is the same with RUST_LOG unset and at trace, the watchdog report is redacted, and write_json, render_html and the terminal renderer do not compile with a plain Report. |
| M1-081 | M1 | SEC-26 M1 redaction corpus, first 30 cases (0.1.0 gate) | qa-engineer | 1.5 | yes | M1-077, M1-075 | At least 30 synthetic cases, secrets built from parts and including negatives, run in `cargo test` on five legs with zero misses, and the harness fails on a survivor or on a rule or syntax form with no positive case. |
| M1-082 | M1 | Security re-review sign-off of 02 revision 3 and ADRs 0014 to 0016 | security-reviewer | 1 | yes | M1-079 | MF-01 to MF-06 of the ADR 0013 to 0016 review are marked closed in the reviewed files. |
| M1-083 | M1 | Shared helpers: units, quantities, dotted version compare, nominal band, severity cap | check-author | 2 | yes | M1-047 | Table tests pass, including 31.3 GiB against `min: 32Gi` and 3.7 GiB against `4Gi` passing with a note, `535.54.03` below `535.104.05`, and `severity: warn` capping a fail. |
| M1-084 | M1 | cgroup helper for memory, cpu and controllers | rust-engineer | 2 | yes | M1-069 | Fixtures for a v2 nested slice, a v1 tree and an unlimited cgroup return the minimum along the parent chain, treat `max` and `9223372036854771712` as unlimited, and read `memory.swap.max`. |
| M1-085 | M1 | Evidence URL and secret rules with a planted-secret golden helper | check-author | 2 | yes | M1-076, M1-075 | A helper that plants a proxy password, a query-string token and an `auths` value fails any golden result that contains them, and a unit test shows URLs stored as `scheme://host:port/path`. |
| M1-086 | M1 | Command table and argument allow-lists from 03 Appendix A | check-author | 2 | yes | M1-058 | Every Appendix A row is a typed entry with absolute path and timeout, a leading-`-` argument is rejected, and a test fails when fix text names a sysctl or command missing from the allow-list files. |
| M1-087 | M1 | OS support table and compile stubs for rdy-checks-host | check-author | 2 | yes | M1-051 | All five CI targets build, every host check on macOS and Windows reports not_yet_on_os, and none does on Linux. |
| M1-088 | M1 | host.memory (meminfo, swap, cgroup limit, nominal band) | check-author | 3 | yes | M1-083, M1-084 | A 31.3 GiB meminfo against `min: 32Gi` passes with a note, 24 GiB blocks, `swap: off` with swap blocks, and a nested cgroup limit is reported. |
| M1-089 | M1 | host.disk (Linux: statvfs flags, mountinfo with escapes, whole-component match, hung-mount timeout) | check-author | 4 | yes | M1-083, M1-070 | Golden results for plenty, tight, no inode accounting, `noexec` /tmp, NFS, a `\040` mount point and the hung-mount fixture. |
| M1-090 | M1 | host.cpu (cores with quota, arch, flags through std macros, levels, Rosetta) | check-author | 3 | yes | M1-083, M1-084 | A cpuinfo without `avx2` blocks with the passthrough fix text, `cpu.max` 200000/100000 reports 2 cores, and `proc_translated=1` warns. |
| M1-091 | M1 | host.ports (Linux /proc/net TCP and UDP, lazy owner lookup, ephemeral overlap) | check-author | 4 | yes | M1-070 | 6443 held by a named process blocks, the same without root reports owner unknown, a UDP listener is found, `[::]` covers IPv4, and the fix text names `ip_local_reserved_ports`. |
| M1-092 | M1 | host.os (os-release, uname, FIPS, container and WSL detection, match rules) | check-author | 2 | yes | M1-070 | RHEL 9, Ubuntu 22.04, Alpine, Rocky (`ID_LIKE`), Amazon Linux 2 and Linux Mint fixtures match or miss a `supported` list as the rules say. |
| M1-093 | M1 | In-process CLI entry point rdy_cli::run taking a Backend | rust-engineer | 2.5 | yes | M1-039, M1-069 | A test calls `run` with the Replay backend, RunHooks and capture buffers and gets the exit code, stdout and stderr, `main.rs` calls it with the Live backend only, the ADR 0011 decision 4 grep, feature-tree and marker-string checks pass on every leg, and security-reviewer signs the amendment. |
| M1-094 | M1 | Env-level harness, in process | qa-engineer | 3 | yes | M1-093, M1-075 | One test per env checks exit code, `report.json`, `terminal.txt` and `report.html` where present, with clock, run id and environment pinned, and the `jobs = 1` and `jobs = 8` reports are equal. |
| M1-095 | M1 | askama HTML report with inline CSS, dark mode and print | rust-engineer | 4 | yes | M1-029, M1-046 | The golden HTML shows the verdict and blocks first and passes an HTML validator with lang and color-scheme set. |
| M1-096 | M1 | Embed result JSON in the HTML report safely | rust-engineer | 2.5 | yes | M1-095 | A hostname of `</script><img onerror>` round-trips through the embedded JSON unchanged and renders as text, and the CSP and link attributes match ADR 0003 (INV-16). |
| M1-097 | M1 | SEC-64 HtmlSafeJson as the only unescaped template value | rust-engineer | 1 | yes | M1-096 | CI fails on any `\|safe` in templates, and the golden HTML's data-sha256 equals the SHA-256 of the golden .json. |
| M1-098 | M1 | HTML print override, labels and legend | rust-engineer | 2 | yes | M1-095 | A headless render with dark preferred and print media has text contrast of at least 4.5 to 1, and a template grep finds no raw JSON key as visible text. |
| M1-099 | M1 | HTML fix source label and action log table | rust-engineer | 1 | yes | M1-095, M1-048, M1-059 | The golden blocked HTML labels vendor fix text with the product name and shows the action log as one table with no details element. |
| M1-100 | M1 | HTML colour tokens and the contrast script (extends the askama report) | cli-ux | 1.5 | yes | M1-095 | A script reads the CSS variables and fails any text or border pair under 4.5:1 in light, dark, dark-preferred print and light print, and the golden HTML for 07 B.1 to B.3 matches. |
| M1-101 | M1 | HTML Found and Needed rendering and the footer link (extends HTML print override) | cli-ux | 2 | yes | M1-098, M1-100 | `_bytes`, `_ms` and `_percent` values print as sizes, milliseconds and percents, the footer link has only `ref=report` and the product with `rel="noopener noreferrer"`, and print has a top padding equal to the banner height. |
| M1-102 | M1 | HTML structure test: headings, landmarks, tables and links | cli-ux | 1.5 | yes | M1-101 | A Rust test over the three goldens asserts heading levels never skip, `lang` is set, every `h3` has a status word, tables have `th scope`, ids are unique, every `href="#id"` has a target, and no other `href` or `src` is anything but `data:`, the footer link or the repo link. |
| M1-103 | M1 | Golden tests for JSON and HTML reports | qa-engineer | 2 | yes | M1-096, M1-075 | `report.json` for the ready, warning and not-ready runs validates against the result schema, `report.html` passes the static checks (CSP, no off-file src or href, `</script>` hostname round trip), and all pass on five legs. |
| M1-104 | M1 | Keep golden result files per released version and parse them in CI | qa-engineer | 1 | yes | M1-103, M1-016 | `tests/fixtures/results/0.1.0-alpha.N/` parses with the current rdy-engine on every leg, and a modified file under an older version directory fails the lint. |
| M1-105 | M1 | Terminal styling layer: colour choice, width, escaping and ASCII text | rust-engineer | 1.5 | yes | M1-039 | Table tests cover the colour rules of 07 section 6, `TERM=dumb` and `COLUMNS` clamping, and a hostname holding an ANSI escape and a bidi override prints as `\x1b` and `\u{202e}`. |
| M1-106 | M1 | rdy version --json (extends Package rdy) | rust-engineer | 1 | yes | M1-004, M1-034 | Golden stdout for both forms equals 07 4.3 and C.11, `rdy --version` prints the first form, and the object validates against the new `Version` definition. |
| M1-107 | M1 | Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | cli-ux | 4 | yes | M1-043, M1-105, M1-044, M1-054 | Golden stderr for 07 B.1, B.2 and B.3 equals C.17, C.18 and 2.7 byte for byte at width 100 with `--color never`, the goldens C.12, C.13 and C.14 match, and the last line is the verdict. |
| M1-108 | M1 | Static "Running N checks..." line on a TTY | rust-engineer | 1 | yes | M1-107 | A pty capture shows the line before the first check and no trace of it in the final screen, and a pipe, `--quiet` and `TERM=dumb` print nothing. |
| M1-109 | M1 | Exit-code golden suite for 0, 1, 2, 64 and 70 | rust-engineer | 2 | yes | M1-107, M1-041, M1-094 | Assert_cmd runs one fixture per row of 07 section 5 (ready, warnings, not ready by a block, not ready by a required check not run, bad flag, missing file, unwritable `--out-dir`), compares exit code and stderr golden, and with `--json` validates stdout against the schema; the unsigned row joins with the M1 verify ticket. |
| M1-110 | M1 | --json stdout hygiene on every exit path | rust-engineer | 1.5 | yes | M1-109, M1-062 | For each exit path except the watchdog, stdout is exactly one JSON document equal to the `.json` file with no ANSI under `--color always`, `--no-report --json` still prints the Report, and on the watchdog path with a blocked stdout pipe the exit is 70 and the folder holds a Report with `complete: false`. |
| M1-111 | M1 | Starlight scaffold in docs/ with pinned pnpm and Node | docs-writer | 4 | yes | M1-003 | A clean clone runs `pnpm install --frozen-lockfile` and `pnpm build` with Node read from docs/.node-version and pnpm read from packageManager. |
| M1-112 | M1 | docs-gen and docs-build jobs in ci.yml, both required through ci-ok | docs-writer | 4 | yes | M1-111, M1-006 | A PR that breaks a generated page or an internal link fails ci-ok, and neither docs job appears as a separate required check. |
| M1-113 | M1 | Production deploy from main to docs.getrdy.io | docs-writer | 3 | yes | M1-112 | A merge to main updates docs.getrdy.io, and a pull request run cannot read the production token, which the founder created on the docs-only Cloudflare account and stored only in GitHub Environment docs-production. |
| M1-114 | M1 | Overview, Concepts and sidebar config | docs-writer | 3 | yes | M1-111 | The sidebar matches 09 section 3 and /concepts/ defines spec, check, severity, finding and result in one sentence each. |
| M1-115 | M1 | CheckMeta in the check registry, read by xtask | rust-architect | 3 | yes | M1-051, M1-033 | Xtask lists each registered check with id, family, title and remediation, and fails on an empty remediation. |
| M1-116 | M1 | Spec renderer for objects and scalars | docs-writer | 4 | yes | M1-033, M1-034 | The readiness schema renders to a golden Markdown file with one table row per property. |
| M1-117 | M1 | Spec renderer for enums, oneOf variants and YAML examples, with the missing-description failure | docs-writer | 4 | yes | M1-116 | Every schema example validates and renders as YAML, and a property without a description fails `cargo xtask docs` with its path. |
| M1-118 | M1 | Spec and result reference pages with hand-written intro | docs-writer | 2 | yes | M1-117 | /reference/spec/ and /reference/result/ build, and each schema field appears once. |
| M1-119 | M1 | Check family renderer: one page per family, one section per check | docs-writer | 3 | yes | M1-033, M1-115 | The host family page has one H2 per host check, and each Remediation block equals the registry string. |
| M1-120 | M1 | Host check family page with hand-written intro | docs-writer | 2 | yes | M1-119, M1-091, M1-092 | /checks/host/ lists every M1 host check with its remediation text. |
| M1-121 | M1 | Loopback network test support (TLS server with generated CA, CONNECT proxy modes, closed port, never-accepting listener, reset after ClientHello, 302 server, dual-stack case) | rust-engineer | 4 | yes | M1-069 | A smoke test starts each server and a raw client observes the expected behaviour on Linux, macOS and Windows CI, and `cargo deny check` passes with `rcgen` on ring. |
| M1-122 | M1 | Facade TCP attempts, proxy CONNECT and per-check host sets | rust-engineer | 4 | yes | M1-059, M1-121 | A host listed only by another check is denied, a CONNECT to a literal 169.254.169.254 is refused before any byte is sent, proxy 403 and 407 return typed errors, and Proxy-Authorization never appears in the log. |
| M1-123 | M1 | Facade TLS with system roots and the recording chain probe | rust-engineer | 3 | yes | M1-122 | Against loopback servers a test-CA chain validates only when the CA is in the fixture system bundle, tls_chain returns the chain without sending application data, SNI always equals the permitted host, and `cargo tree -i aws-lc-sys` is empty. |
| M1-124 | M1 | Facade HTTP/1.1 probe with 64 KiB discard and no redirects | rust-engineer | 3 | yes | M1-123 | A 302 returns its Location host without a second request, a body canary never reaches the report, and each failure class is produced by its loopback case. |
| M1-125 | M1 | SEC-21 Egress address policy, no redirects, no bodies | rust-engineer | 3 | yes | M1-124 | Link-local, metadata and IPv4-mapped targets are refused directly, by DNS and as CONNECT targets, a redirect to 169.254.169.254 is never followed, an unlisted endpoint is refused, more than 64 distinct hosts fail spec validation with exit 64, and a body canary never reaches the report. |
| M1-126 | M1 | net.egress staged connector (lookup, dual-stack connect, TLS, ALPN) | check-author | 3 | yes | M1-083, M1-121, M1-123 | Loopback cases give per-stage timings, a dead IPv6 address falls through to IPv4 and is named, and a scripted blackhole yields the `blackhole` class. |
| M1-127 | M1 | net.egress HTTP stage and failure classes | check-author | 3 | yes | M1-126, M1-085, M1-124 | Refused, TLS unknown issuer, expired certificate, reset after hello and HTTP status classify correctly, and a query-string token never reaches the result. |
| M1-128 | M1 | net.egress via proxy (own CONNECT, absolute-form for http, 407) and redirect host evidence | check-author | 4 | yes | M1-127, M1-125 | CONNECT modes work, 403 and 407 give the right text, an `http://` endpoint uses the absolute form, and a 302 records the `Location` host and is not followed. |
| M1-129 | M1 | net.proxy (process env, systemd drop-ins, NO_PROXY coverage, PAC detection, reachability) | check-author | 3 | yes | M1-085, M1-121, M1-122 | A shell proxy with no docker drop-in warns and prints the drop-in text, NO_PROXY coverage is reported, a PAC case warns without any fetch, and userinfo and the planted `auths` secret never appear. |
| M1-130 | M1 | net.tls_intercept recording verifier and classes | check-author | 3 | yes | M1-126 | Generated chains classify as public, trusted-by-this-machine-only and unknown-CA, an expired leaf with a pinned clock gives `clock_or_expiry`, and a test proves zero application bytes are written. |
| M1-131 | M1 | net.tls_intercept evidence, trust-store report and fix text | check-author | 2 | yes | M1-130 | The result lists issuer, chain depth, root hash (placeholder in goldens) and store location per OS, the empty-store case says "no OS trust store found", and the fix text carries the Debian, RHEL, SUSE, Alpine and Java forms. |
| M1-132 | M1 | Security review of the TLS recording verifier and 03 Appendix A | security-reviewer | 3 | yes | M1-131, M1-086 | Review signed off and Appendix A matches the command table in code. |
| M1-133 | M1 | Network check family page with hand-written intro | docs-writer | 2 | yes | M1-119, M1-128, M1-129, M1-131 | /checks/network/ lists every M1 network check with its remediation text. |
| M1-134 | M1 | Kube client from kubeconfig or in-cluster with rustls and timeouts | rust-engineer | 4 | yes | M1-047 | On a kind cluster in CI k8s.version passes and the context, server and user print before the first request, with no kubeconfig every k8s check is SKIP with the hint, and exec plugin output never appears at RUST_LOG=trace. |
| M1-135 | M1 | Read-only guard layer and test for rdy-checks-k8s | k8s-expert | 3 | yes | M1-134 | The runtime layer rejects any write, any POST other than the three reviews, a SelfSubjectReview with a different body or a query string, and any secrets path, and a mock API server behind guarded_service records only allowlisted requests across the full k8s fixture run (INV-14). |
| M1-136 | M1 | Kube guard path parser, resource allowlist and pending log entries | rust-engineer | 3.5 | yes | M1-135 | `%73ecrets`, `secrets` in every segment position, `/api/v1/namespaces/x/finalize`, GET pods/exec with Upgrade, a dryRun POST and Impersonate-User on a GET are each refused and logged, `/api/v1/namespaces/secrets` is allowed, every ALLOWED entry is cited by a CheckInfo, and a dropped request leaves a timeout entry with its check id. |
| M1-137 | M1 | Kube mock harness (tower service replaying api/ JSON, paging and 410, selectors, legacy discovery, review table) | rust-engineer | 4 | yes | M1-069, M1-135 | A `kube::Client` on the mock with the guard in front pages through a recorded `nodes.json`, restarts once on `410 Gone`, and answers a `SelfSubjectAccessReview` from a table. |
| M1-138 | M1 | Family probe hook and lazy KubeContext probe | rust-engineer | 2.5 | yes | M1-061, M1-134 | A spec with no k8s checks loads no kubeconfig and sends no request, `--no-network` builds no client, and a fake exec plugin that sleeps 600 s makes kube_context unavailable after 10 s with no worker blocked. |
| M1-139 | M1 | kind integration job with a restricted PSA namespace and review round trips | rust-engineer | 2 | yes | M1-134, M1-007 | CI on the oldest and newest supported minors passes `k8s.version`, a `SelfSubjectReview` and access reviews, and shows `restricted` enforce on the test namespace. |
| M1-140 | M1 | Cluster facts cache and read-review batch | check-author | 2 | yes | M1-137 | Five checks cause one Node list per run, a forbidden Node list is recorded once with its grant, and forbidden calls are skipped up front. |
| M1-141 | M1 | k8s.access (kubeconfig, version, SelfSubjectReview, anonymous warn, exec classes, proxy resolution) | check-author | 4 | yes | M1-137 | Fixtures for good, 401, 403, x509 error, expired cert, anonymous kubeconfig, `proxy-url`, env-only proxy, Rancher path prefix and a plugin needing login give the expected result and fix text. |
| M1-142 | M1 | k8s.version (gitVersion parse, distribution, discovery API availability) | check-author | 2 | yes | M1-140 | EKS `v1.29.4-eks-abc123` parses to 1.29, plain `v1.29.4` with Azure labels is AKS, OpenShift reads `ClusterVersion`, and a missing `autoscaling/v2` blocks. |
| M1-143 | M1 | k8s.storageclass (normalised provisioners, CSINode evidence, default rules, provisioner table) | check-author | 4 | yes | M1-140 | EKS `gp2` with no CSI add-on blocks, k3s `local-path` passes with "driver not verified", two defaults block on 1.25 and warn on 1.28, and `CSINode` forbidden gives partial. |
| M1-144 | M1 | k8s.rbac (SelfSubjectReview, access reviews, non-resource items, escalate and bind as warn) | check-author | 3 | yes | M1-140 | A table with two denied items blocks and lists both with reasons and the `denied` versus not-allowed distinction, and a denied `escalate` warns. |
| M1-145 | M1 | k8s.nodes allocatable, node filters, conditions, zones and pod-count limit | check-author | 3 | yes | M1-140 | Cordoned, Windows, Fargate and tainted nodes are excluded, `cpu: 7` passes on an 8 vCPU node, a forbidden Node list is partial, and an autoscaled single node warns instead of blocking. |
| M1-146 | M1 | k8s.admission PSA labels, policy engine and SCC discovery | check-author | 2 | yes | M1-140 | A `restricted` namespace blocks a `privileged` need and the fix says `privileged`, OpenShift discovery gives the SCC text, and Gatekeeper and Kyverno discovery warns with names. |
| M1-147 | M1 | Review k8s checks and fixtures (semantics, API groups, RBAC degrade, per-distro sets) | k8s-expert | 3 | yes | M1-145, M1-143, M1-144, M1-146, M1-141, M1-142 | Written review with every finding fixed or filed. |
| M1-148 | M1 | Kubernetes check family page with hand-written intro | docs-writer | 2 | yes | M1-119, M1-147 | /checks/kubernetes/ lists every M1 Kubernetes check with its remediation text. |
| M1-149 | M1 | Check catalog index page | docs-writer | 1 | yes | M1-120, M1-133, M1-148 | /checks/ links to each family page and to no page that does not exist. |
| M1-150 | M1 | Fixture env all-pass | qa-engineer | 3 | yes | M1-094, M1-088, M1-126, M1-142 | The env exits 0 on all five legs with golden JSON, HTML and terminal text, and 31.3 GiB against `min: 32Gi` passes with its note. |
| M1-151 | M1 | Fixture envs warnings-only, all-block and no-privileges | qa-engineer | 3 | yes | M1-150 | Exit codes 1, 2 and 2 with goldens, `no-privileges` shows `partial` results and `missing_need` skips, and its verdict reason is `required_check_not_run`. |
| M1-152 | M1 | Timeouts env and scheduler timeout and deadline tests under paused time | qa-engineer | 4 | yes | M1-150, M1-062 | The `timeouts` env runs in process under paused time at `jobs = 1` and `jobs = 8`, every hung source gives `Timeout`, the run ends inside `deadline_ms` in virtual time, and only the `Fake::Block` test uses real time with a 1 s upper bound. |
| M1-153 | M1 | Hand-written compatibility page with the day-one rows | docs-writer | 1 | yes | M1-150 | `docs/compatibility.md` lists the 08 Appendix B rows with the four state words and each fixture row shows its origin. |
| M1-154 | M1 | Refuse --password on argv and read key passwords from env or file | rust-engineer | 1 | yes | M1-039 | `--password` exits 64 with the reason of 07 section 10, and `RDY_KEY_PASSWORD` and `--password-file -` sign a spec in CI without a prompt. |
| M1-155 | M1 | Verify minisign signatures in rdy-spec against a trust store with product binding | rust-engineer | 4 | yes | M1-021, M1-024 | A tampered byte, a changed comment, a legacy Ed signature, a missing prefix, a product mismatch and an unpinned key each fail with a distinct SignatureError before the YAML is parsed (a parser spy proves it), Wycheproof vectors pass, and the signed fixtures verify on the windows-x64 leg with `core.autocrlf true`. |
| M1-156 | M1 | SEC-61 Single-buffer spec load and key fingerprints | rust-engineer | 2 | yes | M1-155 | A file swapped after the first read does not change the parsed, hashed or copied bytes, a forged key with the vendor's key id fails, and the result carries signature.key_fingerprint. |
| M1-157 | M1 | Trust store load and save in user and system locations | rust-engineer | 3 | yes | M1-155 | As root with HOME and XDG_CONFIG_HOME pointing at a user store only /etc/rdy/trust.yaml is read, as a user the user file then the system file, and symlinked, non-root-owned or group-writable files exit 64 with trust_store_insecure. |
| M1-158 | M1 | SEC-60 Root trust lookup touches no user path, Windows store ACL rules | rust-engineer | 3 | yes | M1-157 | A root run under strace opens no path under SUDO_USER's home, and on Windows CI a ProgramData\rdy directory created by a non-admin user, or with a Users write ACE, exits 64 with trust_store_insecure. |
| M1-159 | M1 | Serve https://docs.getrdy.io/unsigned | docs-writer | 1 | yes | M1-113 | The URL in 01 section 4.8 returns the page on what `--allow-unsigned` and `--key` do and when not to use them, and the docs link check passes. |
| M1-160 | M1 | Prompt helper: y/N, no-terminal refusal and hidden input | rust-engineer | 2 | yes | M1-039 | Pty tests cover `y`, `yes`, `n`, empty and EOF, a missing TTY exits 64 with the fix line of 07 C.10, and a password is read with echo off. |
| M1-161 | M1 | rdy spec keygen and rdy spec sign | rust-engineer | 4 | yes | M1-155, M1-028, M1-160, M1-154 | An rdy signature verifies with stock minisign and the reverse with the 01 4.2 comment, keys are 0600 `create_new` and encrypted unless `--unencrypted`, sign refuses a lint error, the typos `mn: 32Gi`, `min: 32G` and `host.memroy` and a key readable by others, and it prints the fingerprint. |
| M1-162 | M1 | rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | rust-engineer | 3.5 | yes | M1-161, M1-054, M1-109 | Every code in 01 section 4.8 comes from a fixture, unsigned exits 64 and the exit-code suite gains its unsigned row, `--allow-unsigned` runs and both reports say unsigned but still exits 64 for an unpinned key, an invalid signature and a permission-denied sidecar, and no ErrorOutput.fix or stderr line contains `--allow-unsigned`. |
| M1-163 | M1 | SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading | rust-engineer | 1.5 | yes | M1-162 | Both 01 4.7 banners match byte for byte, a `--key` run prints KEY NOT PINNED on stderr and every HTML page, and the fix label reads "From the spec file (not verified)" for unsigned and flag-key runs. |
| M1-164 | M1 | Fix source labels, wrapping, banner placement and the root Tip (extends SEC-59) | cli-ux | 1.5 | yes | M1-107, M1-163 | Unsigned and `--key` runs label spec fixes "the spec file (not verified)", a pinned run labels the product, a 130-character message wraps at 100 with a hanging indent, both banners print before the first check and again above the verdict, and both Tip forms of 07 2.1 match. |
| M1-165 | M1 | Output goldens for rdy verify and rdy spec lint | cli-ux | 1 | yes | M1-162, M1-040 | Golden output for 07 C.4 and C.8, the Verification and LintReport JSON validate against the schema, and `verify --key` prints the KEY NOT PINNED banner and ends `VERIFIED, KEY NOT PINNED`. |
| M1-166 | M1 | rdy trust add, list and remove | rust-engineer | 2 | yes | M1-157, M1-160 | `trust add` without a TTY and without `--yes` exits 64 with a fix line, with `--yes` it pins and `trust list` shows key id and fingerprint, and `run --key` leaves the store unchanged. |
| M1-167 | M1 | Output goldens for rdy spec keygen, rdy spec sign and rdy trust | cli-ux | 1 | yes | M1-161, M1-166 | Golden output for 07 C.9 and C.10, the fingerprint prints in groups of four and matches `signature.key_fingerprint`, and a secret key given to `trust add` is refused with the C.10 fix. |
| M1-168 | M1 | Security review of spec signing and trust store | security-reviewer | 2 | yes | M1-162, M1-158, M1-156, M1-166 | Review notes filed and every blocker fixed before the 0.1.0 tag. |
| M1-169 | M1 | Exit codes page | docs-writer | 1 | yes | M1-109, M1-113 | The page lists 0, 1, 2, 64 and 70, and a test in the repo produces each of 0, 1 and 2. |
| M1-170 | M1 | Install page with the pinned-release command and platform table | docs-writer | 3 | yes | M1-023, M1-113 | The install-only blocks run in CI against the latest alpha's pinned install.sh URL and pass on a fresh Linux container; the getrdy.io/install line arrives with the M2 Worker route. |
| M1-171 | M1 | First run page and M1 example spec | docs-writer | 3 | yes | M1-162, M1-042, M1-113 | Each command on the page is a case in the M1 integration tests, and the page shows the output shape those tests check. |
| M1-172 | M1 | Review CONTRIBUTING.md on a fresh clone | devrel | 1 | yes | M1-007, M1-018, M1-054 | Every command in the "Build and test" block of CONTRIBUTING.md runs green on a clean checkout, and `cargo run -p rdy -- run examples/specs/acme-quickstart.yaml --allow-unsigned --out-dir /tmp` prints the banner and exits as the file says. |
| M1-173 | M1 | Sign and verify page | docs-writer | 3 | yes | M1-161, M1-162, M1-166, M1-113 | The page's commands run as M1 integration test cases and verify a copy of the example spec signed with a test key. |
| M1-174 | M1 | Fixture lab for README transcripts on the loopback servers and kube mock | qa-engineer | 2 | yes | M1-121, M1-137, M1-094 | A script starts a refusing proxy and a fake kube API, and `rdy run` against them gives stable output twice in a row. |
| M1-175 | M1 | Golden transcripts for acme-quickstart (refusal, NOT READY, READY) | qa-engineer | 2 | yes | M1-174, M1-107, M1-162 | The three README transcripts (the 07 C.5 refusal with exit 64, the unsigned NOT READY run with exit 2, the unsigned READY run with exit 0) reproduce byte for byte from fixtures, banner, header, bucket order, summary line and report block included. |
| M1-176 | M1 | Golden transcript for a skipped required check (acme-platform) | qa-engineer | 1 | yes | M1-174, M1-107 | `rdy run acme-platform.yaml --allow-unsigned` on a fixture with no kubeconfig ends `NOT READY: 3 required checks were not run` with exit 2, and the summary line reads `3 required checks not run, 1 optional check not run`. |
| M1-177 | M1 | docs-test runner for README and docs tested blocks | qa-engineer | 4 | yes | M1-174, M1-022, M1-170, M1-171 | A CI job extracts every fenced command marked testable from README.md and the docs pages, runs it against the build, and fails on an exit code outside its declared set or non-matching output. |
| M1-178 | M1 | SEC-26 M1 redaction corpus, cases 31 to 60 with chunk-boundary cases | qa-engineer | 1.5 | no | M1-081 | 60 synthetic cases across the M1 categories, including chunk-boundary and negative cases, pass with zero misses in CI. |
| M1-179 | M1 | README draft from 10 section 1 | devrel | 3 | yes | M1-042, M1-175, M1-176, M1-162, M1-023, M1-177 | README.md exists, its install block and manual path equal the text in 06, all testable commands pass the docs-test harness, every transcript is pasted from a golden file, and no command line contains `--timeout`, `--dry-run`, `--plan` or `self-update`. |
| M1-180 | M1 | Tag and release 0.1.0 | release-engineer | 1 | yes | M1-168, M1-081, M1-082, M1-132, M1-147, M1-179, M1-170, M1-104 | `v0.1.0` is published, signed and immutable and `scripts/verify-release.sh v0.1.0` passes on a clean machine; on all five targets `rdy run` on a signed fixture spec writes JSON and HTML into a new report directory and exits 0, 1 and 2 on the ready, warning and not-ready fixtures, an unsigned spec exits 64 and a tampered spec exits 64 even with `--allow-unsigned`; every 0.1.0-gate security ticket is closed; and RELEASING.md and 06 say that `v0.1.N` ships weekly until M1 ends and `0.2.0-alpha.N` starts with M2. |
| M1-181 | M1 | Alpha announcement to design partners | devrel | 2 | yes | M1-180 | A short email with the install command, the quickstart spec, what is rough and how to report a blocker is sent to every design partner. |
| M1-182 | M1 | SEC-31 Docs security page and verify-first install | docs-writer | 2 | no | M1-016, M1-113 | The page lists what rdy reads and contacts, the report fields and link parameters, and CI runs its verify commands against the latest alpha. |
| M1-183 | M1 | SEC-22 No-phone-home strace test on Linux CI | qa-engineer | 2 | no | M1-125, M1-121 | Under `sudo unshare -n` and `strace -f -e trace=connect,sendto,sendmsg`, every destination in the fixture suite is a loopback fixture address. |
| M1-184 | M1 | SEC-24 Read-only ClusterRole example and kube identity display | k8s-expert | 2 | no | M1-135, M1-144 | M1 k8s checks pass on kind with only `examples/rbac/rdy-readonly.yaml`, and the report shows context, server, user and any exec plugin run. |
| M1-185 | M1 | CODE_OF_CONDUCT.md and link SECURITY.md | devrel | 1 | no | M1-014 | Both files exist and the repo Security tab shows the policy and private reporting. |
| M1-186 | M1 | Time the quickstart with two design-partner SEs | devrel | 2 | no | M1-180 | Both reach a report in under five minutes and every stumble is a filed issue. |
| M1-187 | M1 | Issue forms and config (bug report, check request, security contact link) | devrel | 2 | no | M1-014 | The New Issue page on a test fork shows the two forms and the private security link, and blank issues are off. |
| M1-188 | M1 | Repo hygiene: topics, social preview, Discussions | devrel | 1 | no | none | All three settings are on in the repo and a screenshot of the repo page is in the PR. |
| M1-189 | M1 | Sync README and series samples with 07-cli-ux | devrel | 1 | no | M1-179, M1-177 | A diff of every transcript in README.md and in 10 against the 07 samples and the goldens shows no difference in bucket order, fix lines, summary grammar, last line, exit code or banner text, without a note. |
| M1-190 | M1 | Public claims audit table in docs | devrel | 2 | no | M1-179 | Each claim in the README security table links to a test or a file, and any without one is removed or ticketed. |
| M1-191 | M1 | Record the README terminal cast | devrel | 2 | no | M1-179 | An asciinema cast of the NOT READY then READY runs, from the release build, is linked from the README. |
| M1-192 | M1 | Review and lint the other four example specs, acme-platform.yaml included | devrel | 1.5 | no | M1-042 | `acme-platform.yaml` lints with exit 1 and exactly two `not_in_build` warnings, uses only M1 host, net and k8s checks plus one unknown id that reports SKIP, and matches the 01 section 7.1 SHA-256, the other three exit 0 or 1 with warnings only, every block and warn check has a `fix`, and `acme-inference-gpu.yaml` no longer names `gpu.device_plugin`. |
| M1-193 | M1 | CI job: lint every example spec | qa-engineer | 1 | no | M1-040, M1-192 | A PR that breaks an example spec fails CI with the file name in the error (lint exit 2 or 64 fails; exit 0 and 1 pass). |
| M1-194 | M1 | HTML next-step sentences and the nothing-verified wording | cli-ux | 1 | no | M1-101 | Golden HTML carries the sentences of 07 D.7 by verdict, including the `nothing_verified` sentence for C.13. |
| M1-195 | M1 | Property tests for rdy_spec::parse | qa-engineer | 3 | no | M1-024 | The 08 section 4 table holds, 10,000 cases for never-panics and limits and 256 for the rest, with a fixed seed on PRs, committed regressions and the suite under 60 s on linux-x64. |
| M1-196 | M1 | HTML untrusted strings in bdi with bidi controls shown as escapes | cli-ux | 1 | no | M1-102 | A hostname holding U+202E and a vendor `fix` holding U+2066 render inside `<bdi>` as `\u{202e}` and `\u{2066}`, and the structure test asserts it. |
| M1-197 | M1 | Headless browser render of the golden HTML with no network | qa-engineer | 3 | no | M1-103 | Each HTML golden renders in the ADR 0003 headless-browser job with zero network requests and no console errors. |
| M1-198 | M1 | Headless layout checks: 320 px and print with dark preferred | qa-engineer | 1 | no | M1-197 | `scrollWidth <= 320` at a 320 px viewport for the three goldens, and print media with dark preferred renders black on white. |
| M1-199 | M1 | Unicode choice for the spinner: locale, WT_SESSION and TERM_PROGRAM | rust-engineer | 1.5 | no | M1-105 | Table tests cover 07 D.1 (UTF-8 locale and `TERM` on Unix, `WT_SESSION` and `TERM_PROGRAM=vscode` on Windows, ASCII otherwise) and no FFI is used. |
| M1-200 | M1 | Progress line with indicatif, TTY only | rust-engineer | 3 | no | M1-107, M1-199 | A pty capture shows one spinner line cleared before the check list, a 250 ms run draws nothing, a pipe, `--quiet`, `--progress never`, `RDY_PROGRESS=never`, `TERM=dumb` and `RUST_LOG` each produce zero progress bytes, and nothing is drawn on stdout. |
| M1-201 | M1 | Quiet and verbose output modes | cli-ux | 2.5 | no | M1-107 | Golden stderr for 07 C.1 (`--quiet`) and C.2 (`--verbose`), and `--verbose` prints one event line per finished check on a pipe. |
| M1-202 | M1 | sysinfo NativeCall variants without process environ or cmdline | rust-engineer | 3 | no | M1-068 | Host.memory and host.cpu run on macOS and Windows CI and strace or the equivalent shows no environ or cmdline reads. |
| M1-203 | M1 | sysinfo-only subset on macOS and Windows for host.disk, memory, cpu and os | check-author | 3 | no | M1-087, M1-202, M1-089, M1-088, M1-090, M1-092 | The four checks return real results from `native/sysinfo_*.json` fixtures on the macOS and Windows CI jobs and `Partial` shows in `CheckInfo`. |
| M1-204 | M1 | Facade methods for UDP exchanges and unix sockets with a GET-only Docker API guard | rust-engineer | 4 | no | M1-059 | An SNTP query to a server not in spec ntp_servers and a POST on the Docker socket are refused and logged. |
| M1-205 | M1 | Windows job objects so a timeout kills the whole process tree | rust-engineer | 3 | no | M1-057 | A Windows fixture command that spawns a grandchild leaves no process after its timeout, and the Windows exec allowlist then opens to 03 Appendix A's Windows rows. |
| M1-206 | M1 | host.lsm (SELinux, AppArmor, audit log denials) (M1-late) | check-author | 3 | no | M1-070 | Enforcing with two AVC lines for a watched context blocks, an unreadable audit log gives partial, and a masked `/sys/fs/selinux` says "not visible". |
| M1-207 | M1 | host.security_agents (process names, agents.toml format, seed list) (M1-late) | check-author | 3 | no | M1-070 | Each catalog entry has a fixture, `comm` truncation is handled, `forbid` blocks and `allow` silences, and the founder has approved the seed list. |
| M1-208 | M1 | host.firewall (firewalld zone and service XML, ufw) (M1-late) | check-author | 4 | no | M1-086 | A closed port in the default-route zone blocks, a port open by service passes, a rich rule gives warn, and a root-less run warns. |
| M1-209 | M1 | host.time_sync (adjtimex, timedatectl, chronyc, SNTP client) (M1-late) | check-author | 4 | no | M1-086, M1-204 | A scripted SNTP responder with a 400 s offset blocks, a reply failing the echo check is rejected, and `EPERM` on adjtimex is partial. |
| M1-210 | M1 | host.sysctl (live and persisted values, precedence, systemd limits) (M1-late) | check-author | 3 | no | M1-070 | A right live value with no `sysctl.d` entry warns "not persisted", and a masked file name resolves per the precedence rule. |
| M1-211 | M1 | host.container_runtime (sockets, daemon.json, containerd v2 and v3, kubelet driver, API over unix socket) (M1-late) | check-author | 4 | no | M1-086, M1-204 | A cgroupfs versus systemd mismatch blocks with the matching table path for the config version, and `d_type` unsupported blocks. |
| M1-212 | M1 | host.cgroups (v1, hybrid, v2, controllers) (M1-late) | check-author | 2 | no | M1-084 | V1, hybrid, v2 and memory-controller-off fixtures give the expected levels and the fix text follows `host.os`. |
| M1-213 | M1 | host.kernel (version and modules) (M1-late) | check-author | 3 | no | M1-083 | A module present only in `modules.dep` as `.ko.xz` warns, absent blocks, and `distro_min` overrides the upstream compare. |
| M1-214 | M1 | macOS data sources for host.ports, cpu flags and security_agents (M1-late) | check-author | 3 | no | M1-203, M1-207 | Recorded `netstat` (with `*.6443`) and `sysctl` fixtures pass on the macOS CI job. |
| M1-215 | M1 | Windows data sources for host.ports and host.os registry, registry helper included (M1-late) | check-author | 4 | no | M1-203, M1-205 | Recorded `NETSTAT`, excluded-port-range and `CurrentVersion` registry fixtures pass on the Windows CI job. |
| M1-216 | M1 | macOS and Windows sources for host.time_sync SNTP and security_agents process names (M1-late) | check-author | 2 | no | M1-209, M1-207 | The SNTP offset fixture passes on all five CI legs and the process-name fixtures pass on macOS and Windows. |
| M1-217 | M1 | Amend ADR 0006 item 5 for getent as the Linux system answer | rust-architect | 1 | no | none | ADR 0006 names `getent ahosts` with hickory as fallback, and net.dns cites it. |
| M1-218 | M1 | net.dns system answer (getent path, name validation, fallback, timeout evidence) (M1-late) | check-author | 3 | no | M1-086, M1-126, M1-217 | Found, not found (exit 2), AAAA-only and deduped dual-stack rows classify, a leading-`-` name is rejected, and with `getent` absent the fallback is used and says so. |
| M1-219 | M1 | musl resolver behaviour fixture for net.dns | qa-engineer | 2 | no | M1-218 | A fixture resolv.conf and nsswitch.conf with `sss` produce the documented warning. |
| M1-220 | M1 | net.dns direct nameserver lookups, resolv.conf and nsswitch analysis, scripted DNS server (M1-late) | check-author | 3 | no | M1-218 | Split-horizon and slow-first-nameserver fixtures warn, NXDOMAIN blocks, and `cargo deny check` passes with `hickory` default features off. |
| M1-221 | M1 | net.registry (v2 ping, token realm, manifest and config blob host, HEAD versus GET) (M1-late) | check-author | 4 | no | M1-128 | A mock whose listed blob host is closed blocks and names it, an unlisted blob host warns "add it", and a multi-arch index resolves. |
| M1-222 | M1 | net.mtu (Linux sysfs, sysinfo elsewhere, overlay overhead tables) (M1-late) | check-author | 2 | no | M1-070 | MTU 1450 with `overlay: vxlan` and `min_mtu: 1400` blocks, and MTU 9001 is informational without `overlay`. |
| M1-223 | M1 | net.bandwidth (ranged sample, injected clock) (M1-late) | check-author | 2 | no | M1-128 | Fixed `(bytes, instant)` samples give the expected rate, a 500 KiB response says "sample too small", and a loose loopback smoke test is within a factor of 2. |
| M1-224 | M1 | macOS and Windows sources for net.proxy, net.dns and net.mtu (M1-late) | check-author | 3 | no | M1-129, M1-218, M1-222 | `scutil` and registry fixtures parse to the expected proxy and nameserver lists. |
| M1-225 | M1 | k8s.nodes free capacity from pod requests (cut 2) | check-author | 2 | no | M1-145 | Requests using 90% of CPU block a 16 CPU free need, and a forbidden or capped Pod list gives "not evaluated", never pass. |
| M1-226 | M1 | k8s.admission webhooks, validating admission policies and the dry-run guard test (M1-late) | check-author | 3 | no | M1-146 | A `Fail` webhook with an empty EndpointSlice blocks, `matchConditions` and URL webhooks are "not evaluated", forbidden webhook lists give partial, and the only non-GET call across the fixture set is the allowed review kinds. |
| M1-227 | M1 | Fixture env windows-2022-stub | qa-engineer | 1 | no | M1-150, M1-087 | Host checks are `not_yet_on_os`, net runs, and CRLF command output stays intact on the Windows env. |
| M1-228 | M1 | k8s.namespace (existence, terminating, quota, limit range, project request) (M1-late) | check-author | 2 | no | M1-140 | A quota with 2 CPU left blocks a 16 CPU need, a scoped quota is "not evaluated", and OpenShift uses the project request review. |
| M1-229 | M1 | k8s.ingress (IngressClass by controller, Gateway API, route, pending LoadBalancer, retirement warning) (M1-late) | check-author | 3 | no | M1-140 | A community ingress-nginx class warns with the retirement text, an F5 class does not, GKE with no class is "not verified", and a 20-minute-old pending LB warns. |
| M1-230 | M1 | k8s.crds (CRDs, served versions, operator version) (M1-late) | check-author | 3 | no | M1-140 | A missing CRD blocks with the mirror-aware Helm fix, and an operator below `min_version` blocks. |
| M1-231 | M1 | k8s.cni (node-condition and CRD signals, DaemonSets, NetworkPolicy, CIDRs, cni.toml) (M1-late) | check-author | 3 | no | M1-140 | K3s with no DaemonSet is detected as flannel from the node condition, Flannel with `network_policy: enforced` blocks on a non-k3s fixture, and default-deny egress warns. |
| M1-232 | M1 | k8s.dns (label-based selection, Corefile, restart evidence) (M1-late) | check-author | 2 | no | M1-140 | RKE2, OpenShift and GKE fixtures select the right workload, and a crash-looping CoreDNS with `forward . /etc/resolv.conf` and a recent termination blocks while lifetime restarts alone do not. |
| M1-233 | M1 | k8s.device_plugins (extended resources, GFD labels, MIG strategy, DRA, validator pod) (M1-late) | check-author | 4 | no | M1-225 | GPU-labelled nodes with zero allocatable block, DRA slices with zero allocatable do not, MIG `single` does not trigger the `mixed` block, and a young plugin pod warns. |
| M1-234 | M1 | Fixture env net-airgapped | qa-engineer | 2 | no | M1-150, M1-183 | `acme-airgap-host.yaml` runs in process with goldens, every public endpoint is refused or black-holed, and the SEC-22 strace check passes over it. |
| M1-235 | M1 | Full help text for spec, trust and version commands | rust-engineer | 1 | no | M1-039, M1-166, M1-161 | Snapshots of `--help` for every command in 07 A.5 to A.12 match Appendix A in wording, section order and examples. |
| M2-001 | M2 | Scheduled audit.yml: cargo-audit, deny advisories, issue on failure (SEC-02) | release-engineer | 2 | yes | M1-006 | A `workflow_dispatch` run on a branch pinning a vulnerable crate opens a `security` issue. |
| M2-002 | M2 | MSRV job and six-weekly toolchain bump reminder | release-engineer | 1 | yes | M1-007 | Raising a dependency's MSRV above the declared one turns the job red. |
| M2-003 | M2 | release-smoke on main: release build, binary size budget, cargo audit bin | release-engineer | 2 | yes | M1-007 | A push to `main` runs it on five legs and a binary over budget fails it. |
| M2-004 | M2 | Publish crates with trusted publishing and release-plz per-crate versions and changelogs (ADR 0007) | release-engineer | 7 | yes | M1-011 | A dry run opens a release PR bumping only the crates that changed, and a real publish of `rdy-spec` holds no stored crates.io token. |
| M2-005 | M2 | cargo-semver-checks in CI for rdy-spec and rdy-engine (ADR 0007) | release-engineer | 2 | yes | M2-004 | A PR that removes a public field without a version bump fails CI. |
| M2-006 | M2 | First crates.io release of rdy-spec and rdy-engine for rdy-cloud | release-engineer | 2 | yes | M2-004 | A scratch crate outside the repo depends on both from crates.io and parses a golden result. |
| M2-007 | M2 | Post-release verify job on four environments and the Windows zip | release-engineer | 3 | yes | M1-016 | After a tag a run installs from the real release on ubuntu x64, ubuntu arm64, macOS arm64 and an Alpine container (one without cosign, to prove the fail-closed message) and verifies the Windows zip. |
| M2-008 | M2 | Worker route serving install.sh at getrdy.io/install | release-engineer | 3 | yes | M1-019, M1-016 | `curl -sSf https://getrdy.io/install` returns 200 with bytes identical to the newest release's `install.sh`, and the docs install page switches to that line. |
| M2-009 | M2 | Publish out-of-band trust anchors on getrdy.io/security and SECURITY.md | release-engineer | 2 | yes | M2-008 | The page lists issuer, workflow path, cosign version and hash, and each release's `SHA256SUMS` digest and Rekor index, and the digests match the release. |
| M2-010 | M2 | Reproducibility flags and rebuild check in a pinned container | release-engineer | 8 | yes | M1-016 | `scripts/repro-check.sh` reports the same sha256 for the Linux x64 musl binary of a released tag. |
| M2-011 | M2 | install.sh offline mode from a local folder with a TUF-cached trust root | release-engineer | 4 | yes | M1-023 | On a host with the network blocked, the script verifies and installs from a local folder. |
| M2-012 | M2 | Allocator benchmark musl against glibc in CI (ADR 0006) | release-engineer | 2 | yes | M1-007 | CI prints both timings for the fixture spec and fails above the 20 percent threshold. |
| M2-013 | M2 | Nightly coverage job, not gating | release-engineer | 3 | yes | M1-007 | A nightly run uploads an lcov report and shows a percentage. |
| M2-014 | M2 | Verify the AWS SDK runs on rustls with ring | cloud-iam-expert | 3 | yes | none | A spike branch builds aws-sdk-iam for both musl targets with no aws-lc-sys in cargo tree, or an ADR records why not. |
| M2-015 | M2 | Shared HTTP client builder for the upload client: reqwest on rustls with ring and the platform verifier (ADR 0009) | rust-engineer | 3 | yes | M1-059 | An integration test with a local CONNECT proxy shows traffic through the proxy, NO_PROXY honoured, `cargo tree -i aws-lc-sys` empty, and a proxy password never in Debug output. |
| M2-016 | M2 | SEC-42 Share-link token format and scope | security-reviewer | 6 | yes | none | The token spec is agreed with rdy-cloud and the `rdy_st_` prefix is covered by the redaction corpus. |
| M2-017 | M2 | Share-link spec fetch: rdy run <product> with the token from RDY_TOKEN, --token-file or a prompt | rust-engineer | 6 | yes | M2-015, M2-016, M2-006, M1-162 | `rdy run acme-platform` with a synthetic token from RDY_TOKEN fetches a signed spec from staging, shows the key fingerprint before pinning, and a `--token` value on argv exits 64. |
| M2-018 | M2 | Hidden --token and --secret refusals | rust-engineer | 1 | yes | M2-017 | `--token` and `--secret` exit 64 with the reason of 07 C.6 and echo nothing after the flag name. |
| M2-019 | M2 | Portal import of HTML reports via the embedded JSON | rust-engineer | 4 | yes | M2-006 | Rdy-cloud imports a golden HTML report, rejects one whose embedded JSON fails the schema, and labels it customer-reported. |
| M2-020 | M2 | rdy report re-renders HTML from a result JSON | rust-engineer | 2 | yes | M1-103 | Rendering a golden result file reproduces the golden HTML byte for byte. |
| M2-021 | M2 | SEC-46 Vendor key rotation, signed_at and serial rollback warnings | rust-engineer | 9 | yes | M1-157, M1-038 | A rotated key passes, a removed key fails, and running serial 6 after serial 7 or an older `signed_at` for the same product warns and is recorded in the result. |
| M2-022 | M2 | SEC-47 Portal-delivered spec and key trust | security-reviewer | 4 | yes | M2-021 | A written decision exists and a key change for a pinned product fails in a fixture. |
| M2-023 | M2 | TTY confirmation for unsigned specs (SEC-56) | cli-ux | 1 | yes | M1-163 | On a pty answering no exits 64 for both banners with default no, and without a TTY the flag alone runs. |
| M2-024 | M2 | Option to replace the hostname in reports | rust-engineer | 2 | yes | M1-045 | With the option set no report file contains the real hostname and host_id is unchanged. |
| M2-025 | M2 | Signed demo key and signed example specs for the quickstart | devrel | 2 | yes | M1-161 | The README quickstart runs on a clean machine with `rdy trust add` and no flags beyond the file name. |
| M2-026 | M2 | Family limits and graceful Ctrl-C with a partial report | rust-engineer | 3 | yes | M1-062 | Ctrl-C writes a report with interrupted true and unstarted checks skipped cancelled, k8s never has more than 3 checks in flight, and the 08 timeouts env shows `skip_kind: cancelled` under paused time. |
| M2-027 | M2 | Graceful first Ctrl-C with a partial report and the second-Ctrl-C message | rust-engineer | 3 | yes | M2-026 | A pty test gets exit 2 with `interrupted` true after one SIGINT and exit 70 with the message of 07 5.1 after two. |
| M2-028 | M2 | rdy run --timeout with the lower-always, raise-defaults-only guard | rust-engineer | 2 | yes | M1-049 | `--timeout 3s` ends a 10 s default at 3 s, a spec `timeout: 5s` is not raised by `--timeout 20s` but is lowered by `--timeout 2s`, a bare `20` exits 64, and the header prints the limit and its source. |
| M2-029 | M2 | SEC-40 rdy run --dry-run preview (was --plan) | rust-engineer | 6 | yes | M1-059 | The plan lists each check's reads, connects and needs, matches the action log of a real run on the same fixtures, runs nothing and exits 0. |
| M2-030 | M2 | --dry-run output C.3 (extends SEC-40) | cli-ux | 2 | yes | M2-029 | Golden output for 07 C.3, no report folder is created, no socket is opened under strace, and `--dry-run --json` exits 64 until the plan has a schema. |
| M2-031 | M2 | JSON for trust list and the dry-run plan | rust-engineer | 4 | yes | M2-030, M1-166 | Both outputs validate against new schema definitions and the stable-output promise of 07 4.2 lists them. |
| M2-032 | M2 | Family-scoped facts with detached fetch and fact attribution | rust-engineer | 4 | yes | M1-051 | Two k8s checks share one nodes fetch, a check that times out does not abort it, and its log entries carry the fact name. |
| M2-033 | M2 | Nonblocking record reads for /dev/kmsg | rust-engineer | 2 | yes | M1-067 | A fixture kmsg with 10,000 records returns within its cap and timeout and no other device path is allowed. |
| M2-034 | M2 | Kube connector built on the facade | rust-engineer | 4 | yes | M1-122 | Every kube socket appears as a facade connect entry and the address rule applies to the API server. |
| M2-035 | M2 | custom.file | check-author | 4 | yes | M1-089 | Good, expired, world-readable and unreadable fixtures give the expected results. |
| M2-036 | M2 | k8s.admission dry-run parameters after the ADR 0010 amendment | rust-engineer | 2 | yes | M1-036 | `dry_run` and `probe_pod` decode, appear in the schema revision table, and are refused at run time if the guard does not allow the call. |
| M2-037 | M2 | k8s.admission dry-run mode, after its ADR, core Pod only | check-author | 4 | yes | M1-226, M2-036 | Recorded dry-run denial bodies surface the text, an unsafe-webhook refusal is inconclusive, a non-Pod kind is rejected, and the default run makes no create call. |
| M2-038 | M2 | k8s.images: pull secrets and OpenShift mirror sets | check-author | 3 | yes | M1-228 | A service account with a pull secret passes, a missing one warns, and an `ImageDigestMirrorSet` is reported without reading secret values. |
| M2-039 | M2 | host.firewall nft and iptables parsing, host.security_agents directories, units and modules, Windows inbound rules | check-author | 5 | yes | M1-208 | A recorded `nft list ruleset` with a drop policy blocks and a unit-file fixture detects an agent. |
| M2-040 | M2 | k8s.metrics and k8s.snapshots | check-author | 4 | yes | M1-141 | Missing APIService and missing VolumeSnapshotClass fixtures warn. |
| M2-041 | M2 | Docker over Windows named pipe for host.container_runtime | check-author | 2 | yes | M1-211 | A scripted named-pipe stream returns the recorded `/version` JSON on the Windows CI job. |
| M2-042 | M2 | Verdict, exit-code and redactor property tests with the schema-walk canary | qa-engineer | 5 | yes | M1-029, M1-080 | The 08 Appendix D properties and the redactor idempotence and planted-secret properties hold, and a new string field added to the result schema is covered with no test change. |
| M2-043 | M2 | CI redaction gate with known-gaps ledger | release-engineer | 2 | yes | M1-178 | A separate job in ci-ok fails below FLOOR 60 and on a gap that starts to pass. |
| M2-044 | M2 | Streaming redactor with line framing and PEM state | rust-engineer | 7 | yes | M1-081 | Stream output equals whole-input output at every split offset. |
| M2-045 | M2 | Binary, compressed and UTF-16 handling in the redaction pipeline | rust-engineer | 4 | yes | M2-044 | Gzip is skipped with a reason and UTF-16 is redacted. |
| M2-046 | M2 | Bundle rules for emails, SaaS tokens and cloud credentials | rust-engineer | 6 | yes | M2-044 | The new cases pass and `--keep-emails` sets `groups_off_by_flags`. |
| M2-047 | M2 | Bundle rules for entropy, IPv4, IPv6 and MAC | rust-engineer | 6 | yes | M2-044 | Opt-in groups stay off unless asked and false positives are under 2%. |
| M2-048 | M2 | Spec and CLI additions for redact_patterns, max_size and --redact-pattern | rust-engineer | 2 | yes | M2-044 | 33 patterns or an unknown group exit 64. |
| M2-049 | M2 | Residual scan, per-entry fail-closed handling and non-dumpable process | rust-engineer | 4 | yes | M2-044 | A planted rule gap shows `residual_hits` and Linux shows `Dumpable: 0`. |
| M2-050 | M2 | SEC-44 Full redaction corpus with chunk-boundary cases | qa-engineer | 10 | yes | M2-046 | The corpus reaches the CI floor of 60 cases on the way to the 300 of 05, every case passes at every split offset with zero misses, CI fails under 25 MiB/s or over 128 MiB RSS, and a pinned second-opinion scanner finds only allowlisted false positives. |
| M2-051 | M2 | SEC-65 Redaction span union with hostile custom patterns | rust-engineer | 3 | yes | M2-050 | Every built-in positive in the corpus, run with custom patterns `@`, `.`, the first secret byte and the key name, has zero survivors. |
| M2-052 | M2 | SEC-45 Fuzz targets for spec parser and redactor | qa-engineer | 6 | yes | M1-076, M1-195 | A weekly 30-minute fuzz run per target finds no crashes. |
| M2-053 | M2 | Bundle manifest wire types and schema in rdy-spec | rust-engineer | 4 | yes | M1-034 | The 04 Appendix C sample validates and no field holds a raw hash. |
| M2-054 | M2 | Collector trait and registry, caps and truncation markers | rust-engineer | 8 | yes | M2-053 | Unknown kinds are skipped and every cut carries the 04 section 5.2 marker. |
| M2-055 | M2 | Bundle scope in the probe facade with streaming reads and deny-list additions | rust-engineer | 7 | yes | M1-067 | A 32 MiB file streams under its cap and every deny-list path is refused. |
| M2-056 | M2 | SEC-43 Bundle collector path policy | security-reviewer | 6 | yes | M2-055 | Denylisted paths and symlink escapes are refused and `--dry-run` shows the resolved file list before collection. |
| M2-057 | M2 | SEC-66 rdy bundle ignores spec collectors unless the spec is verified with a pinned key | rust-engineer | 1 | yes | M2-056 | An unsigned or `--key` spec with `collect: ["file:/etc/acme/*"]` builds a bundle from the built-in set only and says so. |
| M2-058 | M2 | Collectors for file glob, Linux host, journal and container runtime | rust-engineer | 20 | yes | M2-056, M2-054 | Fixtures produce the 04 Appendix A files and cmdline and environ are never read. |
| M2-059 | M2 | Kubernetes guard amendment and collectors for events and describe | rust-engineer | 10 | yes | M1-136, M2-054 | The mock API server sees only list and get on the 04 Appendix A kinds and env values are stripped. |
| M2-060 | M2 | macOS and Windows host collectors | rust-engineer | 8 | yes | M2-058 | Recorded outputs produce the files. |
| M2-061 | M2 | Archive writer with layout, deterministic headers and archive cap | rust-engineer | 6 | yes | M2-054 | A fixed key, clock and bundle id give identical bytes, and incompressible fixtures never give an archive over 100 MiB. |
| M2-062 | M2 | rdy bundle and rdy redact commands, plan and built-in collector set | rust-engineer | 8 | yes | M2-061, M2-058, M2-049 | A fixture run writes the bundle and `--dry-run` reads no file and opens no socket. |
| M2-063 | M2 | Bundle block strict validation in rdy bundle | rust-engineer | 3 | yes | M2-062 | An unknown redactor or collector kind refuses to build a bundle with a fix line. |
| M2-064 | M2 | No-socket and no-stray-file tests for rdy bundle | qa-engineer | 3 | yes | M2-062 | Only the kube fixture is contacted and canaries appear in no file. |
| M2-065 | M2 | Upload pre-flight with single-pass scan, hash and bounded decode | rust-engineer | 4 | yes | M2-049 | A zstd bomb and a 20,000-entry tar exit 64 within 5 s. |
| M2-066 | M2 | Upload token input and consent screen | rust-engineer | 4 | yes | M2-016, M2-065 | FIFO and group-readable token files and `--token` exit 64. |
| M2-067 | M2 | SEC-41 rdy upload client with consent, receipt and exact bytes | rust-engineer | 4 | yes | M2-066, M2-015 | Fake-server tests prove the 05 Surface 4 requirements and 04 steps 3 to 5, nothing uploads without the flag or a yes, and retries reuse the upload id. |
| M2-068 | M2 | Share-link run output: fetch notice, key fingerprint question, upload offer above the verdict | cli-ux | 4 | yes | M2-017, M2-067 | Golden transcripts for a TTY yes, a TTY no and no TTY each end in the verdict, and `--no-network` fails with a fix. |
| M2-069 | M2 | Fake upload server and offline behaviour tests | qa-engineer | 4 | yes | M2-067 | Every test in 04 section 6 passes on five legs. |
| M2-070 | M2 | Output for bundle, upload, report and redact | cli-ux | 4 | yes | M2-062, M2-067, M2-020 | Golden output for the 04 section 6 and Appendix C samples, and each command's exit codes match 07 section 5. |
| M2-071 | M2 | Security review of the bundle pipeline and upload client | security-reviewer | 4 | yes | M2-069, M2-050 | Blockers are fixed before a design partner gets an M2 build. |
| M2-072 | M2 | Bundles page and bundle and upload docs | docs-writer | 3 | yes | M2-062 | The Bundles page lists each collector and redactor name exactly as `--list-collectors` reports it. |
| M2-073 | M2 | SEC-57 Contact-set tests on macOS and Windows | qa-engineer | 4 | yes | M1-183 | Equivalent destination checks pass on both CI legs. |
| M2-074 | M2 | SEC-58 Windows output dir ACL hardening | rust-engineer | 3 | yes | M1-052 | Report files carry an owner-only ACL on Windows CI. |
| M2-075 | M2 | Compatibility matrix source and generator, and the compat-touched PR check | qa-engineer | 4 | yes | M1-153 | `cargo xtask matrix --check` fails on a row citing a missing env, and a PR that changes a check crate without touching the page or the body line fails. |
| M2-076 | M2 | Fixture envs host-ubuntu2204-container, net-corp-proxy and k8s-openshift-restricted | qa-engineer | 6 | yes | M1-150 | Each env runs in process with goldens, and the proxy env shows the 407 Basic classification and private-CA interception with no userinfo in any output. |
| M2-077 | M2 | Fixture env macos-15-arm64-stub | qa-engineer | 2 | yes | M1-150 | Host checks report the documented support state on the macOS leg and net runs. |
| M2-078 | M2 | Process-level timeout and Ctrl-C tests on Unix | qa-engineer | 3 | yes | M1-057, M1-152, M2-027 | The two M2 rows of 08 section 5 pass on linux and macos legs with upper-bound timing only. |
| M2-079 | M2 | Dev-only fixture record mode with a scrub step, and the record-fixtures workflow | qa-engineer | 7 | yes | M1-072, M1-073 | Recording `host.memory` on a CI runner writes nothing raw to disk and replays to the same result, planted hostname, address, MAC and serial are replaced consistently, and a manual run uploads scrubbed macOS and Windows directories. |
| M2-080 | M2 | Fixture lint redactor rule, golden-section PR check, ignore lint, nightly flake hunt and fixture drift job | qa-engineer | 6 | yes | M1-073, M1-103 | A secret-shaped string in a fixture fails the lint, a golden change without `## Golden changes` fails, a bare `#[ignore]` fails, and a planted 1-in-10 flake is caught nightly with its seed. |
| M2-081 | M2 | Kubernetes distro fixture set | qa-engineer | 6 | yes | M2-076 | `eks`, `gke`, `aks`, `rke2`, `k3s` and `kind` cases hold the files named in the k8s-expert review and the matrix rows move to `fixture`. |
| M2-082 | M2 | CLI reference generated from the clap command tree | docs-writer | 3 | yes | M1-039, M1-033 | Every command and flag in `rdy --help` appears on /reference/cli/, and a new flag fails `docs --check` until regenerated. |
| M2-083 | M2 | Sync check between 03-check-catalog.md and the check registry | docs-writer | 2 | yes | M1-115 | A registry id missing from 03 fails docs-lint. |
| M2-084 | M2 | Changelog page generated from CHANGELOG.md | docs-writer | 2 | yes | M1-003, M1-112 | Each version heading in CHANGELOG.md appears once as an H2 on /changelog/, and `docs --check` output is identical on a shallow clone. |
| M2-085 | M2 | Privileges and data page with generated privilege table | docs-writer | 3 | yes | M1-115 | `docs --check` fails if a privilege string on the page differs from its registry value. |
| M2-086 | M2 | Read a report page | docs-writer | 3 | yes | M1-102, M1-118 | Every blocker field in the JSON result has a row on the page. |
| M2-087 | M2 | Contributor setup page with the exact cargo and pnpm commands | docs-writer | 2 | yes | M1-012 | Each command on the page appears in ci.yml or is marked local-only. |
| M2-088 | M2 | Writing docs page and docs-lint rules | docs-writer | 2 | yes | M1-033 | The page's examples pass docs-lint, and the banned-token list stays hash-only. |
| M2-089 | M2 | PR preview deploys in a separate workflow | docs-writer | 4 | yes | M1-113 | A same-repo PR gets a pr-N preview URL on the founder's separate preview account, and a Dependabot or fork PR never reaches the preview deploy job. |
| M2-090 | M2 | Canonical links and noindex on preview builds | docs-writer | 1 | yes | M2-089 | A preview page carries the noindex meta tag and a production page does not. |
| M2-091 | M2 | Version picker in the Starlight header reading versions.json | docs-writer | 4 | yes | M1-113 | The select lists each archived version and opens the same page in it when that page exists. |
| M2-092 | M2 | docs-archive custom dist job, one archive per stable tag | docs-writer | 4 | yes | M1-010, M1-009 | A test stable tag produces `rdy-docs-<tag>.tar.zst` with a checksum that sign-release signs with the other assets. |
| M2-093 | M2 | Docs assembly: root from newest stable tag, /next from main, archives from release assets, versions.json, latest redirect | docs-writer | 4 | yes | M2-092, M2-091 | A preview of the assembled tree serves each documented path with status 200. |
| M2-094 | M2 | Offline and upload page | docs-writer | 3 | yes | M2-067, M1-177 | Its tested blocks pass in docs-test with the network namespace disabled. |
| M2-095 | M2 | lobste.rs account and weekly comment habit | devrel | 6 | yes | none | An account exists with an invite and at least ten useful comments on other people's posts before launch week minus 3. |
| M2-096 | M2 | First case study draft from a design-partner run | devrel | 4 | yes | M1-181 | One written, approved, anonymised case study exists. |
| M2-097 | M2 | README update for bundle, redaction and --dry-run | devrel | 2 | yes | M2-062, M2-030 | The README shows `rdy bundle` and `rdy run --dry-run` output pasted from real runs, the Security table has the redaction test, and the `[M2]` marks are gone. |
| M3-001 | M3 | Freeze rdy/v1 for the 1.0 release of rdy-spec | rust-architect | 3 | yes | M2-005 | Schema files, golden results and 01 agree, and schema/README.md lists every revision since 0.1. |
| M3-002 | M3 | Decide the 1.0 stability scope of Check, Family and Probe | rust-architect | 3 | yes | none | An ADR says whether these modules are semver-covered at 1.0 or move under rdy_engine::unstable, before rdy-engine 1.0 ships. |
| M3-003 | M3 | Release rdy-spec and rdy-engine 1.0 | rust-architect | 4 | yes | M3-001, M3-002, M2-006 | 1.0 is published and the cargo-semver-checks baseline moved to 1.0. |
| M3-004 | M3 | http_exchange and Need::Consent for SDK adapters | rust-engineer | 4 | yes | M1-124 | The AWS SDK adapter fixture runs through the facade with every call in the action log and no body in the report, and assume-role without consent is skipped missing_need. |
| M3-005 | M3 | AWS HTTP adapter over the facade (FacadeHttpClient) with proxy, roots and request ids | rust-engineer | 5 | yes | M2-014, M3-004 | With a local CONNECT proxy an SDK call succeeds only through the proxy and appears in the action log with its request id. |
| M3-006 | M3 | AWS common: credential chain without credential_process, source detection, session cache, assume with consent and the RDY_ id rule, replay harness | check-author | 10 | yes | M3-005 | A no-credentials run skips every `aws.*`, a spec naming `AWS_SECRET_ACCESS_KEY` as external id is refused, the assume fixture runs only with `--allow-assume-role`, and a `credential_process` profile is skipped with the export hint. |
| M3-007 | M3 | SEC-48 Read-only cloud API allowlist | check-author | 6 | yes | M3-006 | Every AWS operation the checks can call is read-only or simulate, reviewed by cloud-iam-expert. |
| M3-008 | M3 | aws.identity | check-author | 2 | yes | M3-006 | A wrong-account fixture blocks, IMDS and assumed sessions never warn on expiry, and static near-expiry warns. |
| M3-009 | M3 | aws.iam (simulate, role ARN resolution, SCP and boundary text, labels) | check-author | 6 | yes | M3-008 | Implicit deny, org-SCP deny, missing context, SSO and regional SSO path role, denied `GetRole` and paged results all classify correctly. |
| M3-010 | M3 | aws.iam EC2 dry-run fallback, ec2_dryrun.toml and trust-policy inspection for vendor roles | check-author | 5 | yes | M3-009 | Dry-run fixtures classify, a validation error is `unknown`, `principal:` with `probe: dry_run` fails lint, and correct, ExternalId-less and wildcard-principal trust fixtures give pass, block and block. |
| M3-011 | M3 | aws.quota with aws_quotas.toml, UsageMetric usage, API-count fallback and pending requests | check-author | 8 | yes | M3-008 | A 64 vCPU need against a 32 vCPU limit blocks with the CLI fix, a quota without `UsageMetric` still reports usage from a Describe count, and a pending request changes the fix text. |
| M3-012 | M3 | aws.vpc (capacity formula, routes, NAT, DNS attributes, endpoint reachability) | check-author | 6 | yes | M3-008 | A 9-free-IP subnet, main-table association, a blackhole route and a closed endpoint security group classify correctly. |
| M3-013 | M3 | aws.region (documented SSM paths, supported-region routing, ZoneId, paging) | check-author | 5 | yes | M3-008 | Supported region, unsupported region and SCP region deny give pass, pass and unknown, and an opt-in region not enabled blocks. |
| M3-014 | M3 | aws.eks | check-author | 5 | yes | M3-008 | Private-only endpoint and missing OIDC provider fixtures block. |
| M3-015 | M3 | Publish the reader policy as JSON plus a CloudFormation snippet, tested against the action list | docs-writer | 2 | yes | M3-014, M3-007 | A test compares every operation the cloud checks can call with the policy actions and fails on any difference. |
| M3-016 | M3 | Review AWS checks (actions, simulator caveats, quota codes against a live listing) | cloud-iam-expert | 3 | yes | M3-014, M3-010, M3-011, M3-012, M3-013 | Written review with every finding fixed or filed. |
| M3-017 | M3 | Cloud account check family page | docs-writer | 2 | yes | M3-016, M1-119 | /checks/cloud/ lists each AWS check with its remediation text. |
| M3-018 | M3 | Pod logs collector with its own ADR | k8s-expert | 6 | yes | M2-059 | Tail-limited logs are collected through an amended guard. |
| M3-019 | M3 | OS log collectors for macOS and Windows | rust-engineer | 8 | yes | M2-060 | Recorded unified-log and event-log fixtures are collected and redacted. |
| M3-020 | M3 | Resumable upload | rust-engineer | 8 | yes | M2-067 | A cut upload resumes with the remaining bytes only. |
| M3-021 | M3 | SEC-52 cargo-vet for direct dependencies | security-reviewer | 6 | yes | none | `cargo vet` passes in CI. |
| M3-022 | M3 | Homebrew tap and dist homebrew installer | release-engineer | 4 | yes | M1-016 | `brew install getrdy-io/tap/rdy` installs the latest release and `brew test` passes. |
| M3-023 | M3 | winget manifest and submission automation | release-engineer | 6 | yes | M1-016 | A winget-pkgs PR passes validation and `winget install` works on a clean Windows VM. |
| M3-024 | M3 | Windows install.ps1 with the same verification as install.sh | release-engineer | 4 | yes | M1-023 | On a clean Windows VM the script installs and fails closed on a tampered zip. |
| M3-025 | M3 | SEC-50 macOS notarization and Windows signing, after open decision 6 in 13 | release-engineer | 8 | yes | none | A browser-downloaded archive runs on macOS without a Gatekeeper block and `rdy.exe` shows a verified publisher. |
| M3-026 | M3 | Self-update spike and ADR | release-engineer | 4 | yes | M1-016 | An ADR picks a verification method, backed by a Rust test that verifies a signed manifest. |
| M3-027 | M3 | Verified, explicit rdy self-update | release-engineer | 12 | yes | M3-026 | A tampered or wrong-identity release is refused and the old binary keeps working, a good one upgrades alpha N to N+1 on all five platforms and rolls back if the new binary fails `rdy version`, and it never runs unprompted. |
| M3-028 | M3 | SEC-49 Review of verified self-update | security-reviewer | 4 | yes | M3-027 | 06's self-update build refuses tampered or wrong-identity assets and never runs unprompted, and every blocker is fixed before it ships. |
| M3-029 | M3 | Verify reproducible builds across independent builders (SEC-51) | release-engineer | 8 | yes | M2-010 | Two independent builds of a tag match, or the deviations are documented. |
| M3-030 | M3 | rdy completion and man pages from the clap tree | rust-engineer | 4 | yes | M1-039 | `rdy completion <shell>` output sources cleanly in bash, zsh, fish and PowerShell CI jobs, `cargo xtask man` writes one page per command, and the release archive holds `completions/` and `man/`. |
| M3-031 | M3 | rdy spec init command and the init and self-update output | cli-ux | 4 | yes | M3-027, M1-040 | Golden output for init (refuses overwrite without `--force`) and for update, decline, check-only and a refused tampered release, each with the exit codes of 07 E.2. |
| M3-032 | M3 | Write a spec page | docs-writer | 3 | yes | M3-031, M1-177 | The tested blocks run `rdy spec init` and `rdy spec lint` and pass in docs-test. |
| M3-033 | M3 | Security page: signing, SBOM and vulnerability reporting (extends SEC-31) | docs-writer | 3 | yes | M1-182, M2-009 | Each claim on the page links to a file or a release asset. |
| M3-034 | M3 | Portal docs decision and pages | docs-writer | 4 | yes | none | The portal section builds from content that is public in the repo it names, after the founder decides where portal docs live. |
| M3-035 | M3 | Launch release candidate and feature freeze | release-engineer | 2 | yes | M3-016, M3-022, M3-023, M3-003, M3-028 | A signed release candidate is tagged, the post-release verify job passes on it, and only launch-blocking fixes merge after it. |
| M3-036 | M3 | Public launch pass over every page | docs-writer | 3 | yes | M3-033, M3-035 | No page says alpha or pre-release outside the version banner. |
| M3-037 | M3 | Launch assets final (HN post, first comment, Reddit and lobste.rs posts, FAQ) | devrel | 8 | yes | M3-035 | Every sentence is checked against the release candidate, every transcript equals a golden file, every founder placeholder is filled or deleted, and the claims table has no gaps. |
| M3-038 | M3 | Series posts 1 to 5 written, recorded and scheduled | devrel | 12 | yes | M3-035 | Five posts exist with terminal output pasted from the release candidate in 07's format and are scheduled. |
| M3-039 | M3 | Partner outreach (five emails, reply tracker) | devrel | 5 | yes | none | Emails are sent in launch week minus 3 to each category, reply status is tracked, and nothing is announced without written approval. |
| M3-040 | M3 | PreSales Collective post and roundtable booked | devrel | 5 | yes | none | The community team approved the post and the roundtable has a date and a listing. |
| M3-041 | M3 | Ten good-first-issue and check-request issues | devrel | 3 | yes | M1-233, M1-224 | Ten issues exist, each with an exit test and a pointer to the code. |
| M3-042 | M3 | Metrics script and weekly routine | devrel | 3 | yes | none | `scripts/metrics.sh` writes one CSV row with stars, release downloads and crates.io downloads. |
| M3-043 | M3 | Launch-week runbook and response board | devrel | 3 | yes | M3-037 | The day-by-day table is on a calendar, and the `launch-fixes` board exists with the playbook linked. |
| M3-044 | M3 | Three-stranger quickstart test | devrel | 4 | yes | M3-035 | Median time to a report is under five minutes and all stumbles are fixed. |
| M4-001 | M4 | GPU capture set from rented machines with DTDs and the NVIDIA XML scrub tool | qa-engineer | 8 | yes | M2-079 | Captures with `-q -x --dtd` for a T4 or L4, an A10G, an A100 with MIG and an HGX scrub clean, a test fails if any committed fixture holds a real-shaped UUID, serial or bus id, and the matrix rows for those driver lines move to `fixture`. |
| M4-002 | M4 | Review nvidia-smi tag names against the recorded DTDs, complete cuda_driver_min.toml, gpu_arch.toml and xid.toml | gpu-expert | 3 | yes | M4-001 | Written review, and every tag path the code will read exists in each DTD. |
| M4-003 | M4 | GPU shared layer: tool search list, kernel-side gate, exit-code classifier, circuit breaker, shared collector | check-author | 5 | yes | M4-002 | Every exit code and string classifies, a hung run abandons the PID and stops further calls, the module-absent case never runs `nvidia-smi`, and the operator layout is found. |
| M4-004 | M4 | GPU XML parser: three value states, units, DTD test, no-DTD-fetch parser | check-author | 5 | yes | M4-003 | XML from 525, 535 and 550 parses to one model, an absent required tag gives partial, and the DTD path test passes. |
| M4-005 | M4 | gpu.driver, including DKMS and Secure Boot diagnosis | check-author | 4 | yes | M4-004 | Mismatch, nouveau, module built for another kernel and WSL2 fixtures give the expected results. |
| M4-006 | M4 | gpu.runtime (TOML parse, imports, drop-ins, Rancher paths, CDI staleness) | check-author | 4 | yes | M4-003 | Toolkit present but not registered with containerd blocks with the `nvidia-ctk` fix, a stale CDI spec blocks, and an unreadable config is partial. |
| M4-007 | M4 | gpu.cuda with built_with and compat rules | check-author | 5 | yes | M4-004 | Driver reporting 12.2 with product built with 12.4 passes with a note under `compat: minor` and blocks with the 550.54.14 hint under `compat: strict`. |
| M4-008 | M4 | gpu.devices and gpu.vram with gpu_arch.toml, MIG and vGPU handling | check-author | 7 | yes | M4-004 | An H100 at 81559 MiB and an A100 give the same result for `80Gi`, an L4 at 23034 MiB against `24Gi` passes with a note, and MIG on with no instances blocks. |
| M4-009 | M4 | gpu.health with xid.toml and the nonblocking kmsg reader | check-author | 6 | yes | M4-004, M2-033 | Xid 79 with a failing `nvidia-smi` blocks and with a healthy one warns, Xid 63 is info, row remap failure blocks, and a root-less run is partial. |
| M4-010 | M4 | gpu.fabric | check-author | 6 | yes | M4-004 | NVSwitch with no fabric manager blocks, the `comm` truncation tree does not false-block, and IB `INIT` blocks only on InfiniBand. |
| M4-011 | M4 | gpu.model_egress with offline mode | check-author | 5 | yes | M1-128 | An unlisted redirect host warns "add it", `HF_HUB_OFFLINE=1` switches to the offline path check, and a gated 401 warns. |
| M4-012 | M4 | Review GPU checks end to end | gpu-expert | 3 | yes | M4-005, M4-006, M4-007, M4-008, M4-009, M4-010, M4-011 | Written review with every finding fixed or filed, and the checks pass on one real node. |
| M4-013 | M4 | GPU and AI check family page | docs-writer | 2 | yes | M4-012 | /checks/gpu/ lists each GPU check with its remediation text. |
| M4-014 | M4 | GPU check family stand-alone post and example spec update | devrel | 4 | yes | M4-012 | `acme-inference-gpu.yaml` runs without skips on a GPU fixture and the post uses real output. |
| M4-015 | M4 | SEC-53 Threat model and design note for custom.exec | security-reviewer | 4 | yes | M1-059 | A section is added to 05-threat-model.md and reviewed by rust-architect before the custom.exec build ticket starts. |
| M4-016 | M4 | Spec-origin exec policy, hash-bound consent and temp workdir for custom.exec | rust-engineer | 4 | yes | M4-015 | A bare `--allow-exec` is refused, the right hash runs commands as an unprivileged user under euid 0 in a fresh temp dir with 64 KiB caps, and a wrong hash runs nothing. |
| M4-017 | M4 | Implement custom.exec with argv, expectations, caps and hash-bound consent | check-author | 16 | yes | M4-016, M1-069 | The six synthetic commands of 03 and the pass, fail, timeout, refused-without-consent, wrong-hash and unsigned-spec fixtures produce the documented statuses and exit codes on Linux, macOS and Windows. |
| M4-018 | M4 | store.postgres | check-author | 6 | yes | M1-070, M1-123 | PG 15 without `CREATE` on `public` and a missing extension block. |
| M4-019 | M4 | store.s3 | check-author | 5 | yes | M3-005 | Skew, missing bucket and checksum-rejecting server classify correctly. |
| M4-020 | M4 | store.redis | check-author | 4 | yes | M1-070, M1-123 | `allkeys-lru` against `noeviction` blocks and disabled `CONFIG` is partial. |
| M4-021 | M4 | Data stores check family page | docs-writer | 2 | yes | M4-018, M4-019, M4-020 | /checks/data-stores/ lists each data-store check with its remediation text. |
| M4-022 | M4 | Custom-branded report from data | rust-engineer | 6 | yes | M1-101 | A branding block in the spec changes name, logo and accent colour in the golden HTML and nothing else. |
| M5-001 | M5 | rdy-ffi and rdy-wasm builds of the engine | rust-engineer | 30 | yes | M3-003 | The C-ABI and WASM builds pass the same golden result tests as the CLI. |
| M5-002 | M5 | Embed SDK reference | docs-writer | 4 | yes | M5-001 | Every exported function in the C ABI header appears on the reference page. |
| M5-003 | M5 | Embed SDK developer guide and example | devrel | 8 | yes | M5-001 | A stranger builds the example installer integration from the guide alone. |
| M5-004 | M5 | Air-gapped kit: offline bundle of binary, signatures, trust root and signed specs, plus an offline licence check design note | rust-architect | 6 | yes | M2-011, M1-234 | A design note in docs/plan lists its tickets, and an install plus `rdy run` on a VM with no network, using only the kit, verifies every signature and produces a report. |
| M5-005 | M5 | deb and rpm packages with nfpm | release-engineer | 8 | yes | M1-016 | `dpkg -i` and `rpm -i` install on Debian and Rocky containers and `rdy version` runs. |
| M5-006 | M5 | apt and yum repository hosting with signed metadata | release-engineer | 12 | yes | M5-005 | `apt install rdy` and `dnf install rdy` work from the public repo on clean containers with the repo key verified. |
| M5-007 | M5 | Evaluate Sigstore keyless signing and vendor-domain keys for specs | security-reviewer | 4 | yes | none | An ADR accepts or rejects each with an offline-verification story. |
| M5-008 | M5 | SEC-54 Independent security audit | security-reviewer | 8 | yes | none | The report is received and every high finding has a fix ticket. |
| M5-009 | M5 | Provider-neutral cloud session before GCP and Azure checks | cloud-iam-expert | 4 | yes | M3-006 | GCP and Azure stubs use the same facade `Http`, action log and degrade rules with no AWS types. |
| M5-010 | M5 | gcp.iam, gcp.quota, gcp.apis, gcp.region | check-author | 14 | yes | M5-009 | Recorded REST responses for allowed, denied and quota-short cases classify correctly. |
| M5-011 | M5 | azure.rbac, azure.quota, azure.providers, azure.region | check-author | 14 | yes | M5-009 | Recorded ARM responses for allowed, denied and quota-short cases classify correctly. |
| M5-012 | M5 | store.kafka and full gpu.vgpu_license | check-author | 9 | yes | M4-020, M4-008 | Recorded broker and licence fixtures classify correctly. |
| M5-013 | M5 | Custom checks page | docs-writer | 3 | yes | M4-017 | The page's example check runs in docs-test and its sandbox limits match the registry. |

## Weekly ship list

Every week ends with a tag from the release pipeline, or the week is skipped and the number kept (06).
Each tag is a usable binary: it installs, runs `rdy version`, and does everything the earlier tags did.
Until week 3 the tag is a CI or sandbox build. From week 3 it is a signed GitHub pre-release that
`scripts/verify-release.sh` checks. Alphas are for the founder and for demos on calls. `v0.1.0` and later
go to design partners.

| Week | Tag | Who runs it | How to check it |
| --- | --- | --- | --- |
| 1 | `v0.1.0-alpha.0` (CI artefacts) | founder | The CI run is green on five legs and the downloaded artefact prints `rdy --version`. |
| 2 | sandbox pre-release | founder | `cosign verify-blob` passes on the sandbox `SHA256SUMS` and fails after one byte changes. |
| 3 | `v0.1.0-alpha.1` | founder | `scripts/verify-release.sh v0.1.0-alpha.1` passes on a clean Linux machine. |
| 4 | `v0.1.0-alpha.2` | founder | The pinned install.sh installs alpha.2 and refuses a tampered checksum. |
| 5 | `v0.1.0-alpha.3` | founder | `cargo test -p rdy-spec` parser fixtures pass; `rdy version` still works. |
| 6 | `v0.1.0-alpha.4` | founder | The 01 samples 7.2 to 7.4 round-trip in CI. |
| 7 | `v0.1.0-alpha.5` | founder | `cargo xtask schema --check` is green and the schema files are in the release source. |
| 8 | `v0.1.0-alpha.6` | founder | `rdy spec lint examples/specs/acme-platform.yaml` exits 1 with two not_in_build warnings. |
| 9 | `v0.1.0-alpha.7` | founder | `rdy spec lint` on a `mn: 32Gi` typo prints "did you mean min" and exits 2; `rdy --bogus` exits 64. |
| 10 | `v0.1.0-alpha.8` | founder | Engine tests: a hung check reports Timeout and a panicking one Error. |
| 11 | `v0.1.0-alpha.9` | founder | `rdy run examples/specs/acme-platform.yaml --allow-unsigned --json` exits 2 and the JSON validates. |
| 12 | `v0.1.0-alpha.10` | founder | The run JSON's action log lists every command. |
| 13 | `v0.1.0-alpha.11` | founder | `sudo` and setuid launches are refused; Ctrl-C during a run exits 70 and leaves no folder. |
| 14 | `v0.1.0-alpha.12` | founder | Replay fixture tests pass on five legs. |
| 15 | `v0.1.0-alpha.13` | founder | A planted public hostname in a fixture fails fixture lint. |
| 16 | `v0.1.0-alpha.14` | founder | Canary secrets in env, proxy URL and kubeconfig appear nowhere at `RUST_LOG=trace`. |
| 17 | `v0.1.0-alpha.15` | founder | `rdy run` on a fixture spec shows host.memory PASS with the nominal-band note. |
| 18 | `v0.1.0-alpha.16` | founder | On a Linux VM the five host checks give real results. |
| 19 | `v0.1.0-alpha.17` | founder | The report folder holds `report.html` and `report.json` that agree. |
| 20 | `v0.1.0-alpha.18` | founder | Golden ready, warning and not-ready reports pass on five legs. |
| 21 | `v0.1.0-alpha.19` | founder, shown on calls | The terminal output matches 07 B.1 to B.3; demo only, not handed over. |
| 22 | `v0.1.0-alpha.20` | anyone | Https://docs.getrdy.io loads. |
| 23 | `v0.1.0-alpha.21` | anyone | /reference/spec/ lists every schema field once. |
| 24 | `v0.1.0-alpha.22` | anyone | /checks/host/ shows every host check with its fix text. |
| 25 | `v0.1.0-alpha.23` | founder | Net.egress blocks a closed port and refuses 169.254.169.254. |
| 26 | `v0.1.0-alpha.24` | founder | Against the loopback proxy, 407 and an intercepting CA are classified with fix text. |
| 27 | `v0.1.0-alpha.25` | founder | The run header shows kube context, server and user before the first request. |
| 28 | `v0.1.0-alpha.26` | founder | The guard test passes on kind; a write request is refused. |
| 29 | `v0.1.0-alpha.27` | founder | On kind, k8s.access, k8s.version and k8s.storageclass give real results. |
| 30 | `v0.1.0-alpha.28` | founder | On kind with the read-only role, the five core k8s checks give real results. |
| 31 | `v0.1.0-alpha.29` | founder | All fixture envs pass on five legs with exit codes 0, 1, 2 and 2. |
| 32 | `v0.1.0-alpha.30` | founder | A tampered spec fails before parsing in the parser-spy test. |
| 33 | `v0.1.0-alpha.31` | founder | `rdy spec sign` then `rdy verify` passes; an unsigned spec exits 64. |
| 34 | `v0.1.0-alpha.32` | founder | `rdy trust add --yes` pins a key and a signed run reports Verified. |
| 35 | `v0.1.0-alpha.33` | founder | Docs-test runs every README and docs command green and the 60-case corpus passes. |
| 36 | **`v0.1.0`** | design partners | `scripts/verify-release.sh v0.1.0` passes, the README quickstart reaches a report, and the strace contact-set test is green. |
| 37 | `v0.1.1` | design partners | Two SEs reach a report in under five minutes and every example spec lints in CI. |
| 38 | `v0.1.2` | design partners | The HTML report renders at 320 px with no network requests. |
| 39 | `v0.1.3` | design partners | Host.memory and host.cpu give real results on macOS and Windows. |
| 40 | `v0.1.4` | design partners | An enforcing SELinux fixture with AVC denials blocks. |
| 41 | `v0.1.5` | design partners | A 400 s clock offset blocks and a cgroupfs and systemd driver mismatch blocks. |
| 42 | `v0.1.6` | design partners | Recorded netstat and registry fixtures pass on the macOS and Windows legs. |
| 43 | `v0.1.7` | design partners | Net.dns finds and misses names through getent, and a closed registry blob host blocks and is named. |
| 44 | `v0.1.8` | design partners | MTU 1450 with a vxlan overlay blocks, and a `Fail` webhook with no endpoints blocks. |
| 45 | `v0.1.9` | design partners | A missing CRD blocks with the Helm fix. |
| 46 | `v0.1.10` | design partners | GPU nodes with zero allocatable block, the air-gapped env passes, and every M1 row is in the Done log. |

**M1 exit test (the plan):** one design partner catches a real install blocker with it. It can be met
from week 36, when design partners get `v0.1.0` and the announcement. M1 is not closed until a
partner reports a blocker that rdy caught and the report is linked in the Done log as `M1-exit`, even if
every row is built. The engineering done test in `00-overview.md` (signed fixture spec on all five
targets, exit codes 0, 1, 2 and 64, every 0.1.0 gate security ticket closed) is part of the exit test of
M1-180.

## How to work the backlog

- Start M1 only after a recorded "go" on Nov 20, 2026 (13, open decision 1), and after the founder approves
  this file (KICKOFF, "After the plan").
- Work tickets in id order. A ticket starts only when every id in its "depends on" is in the Done log.
- One PR per ticket. Title: `M1-042: <ticket title>`. The PR description quotes the exit test and shows
  the evidence: the test name, the CI run, or the command and its output.
- Review rules from KICKOFF "After the plan": the owning subagent implements. `code-reviewer` reviews
  cold. `security-reviewer` reviews if the ticket touches privileges, network, redaction, signing or the
  install script. `qa-engineer` adds or updates fixtures and golden tests. `docs-writer` updates docs in
  the same PR. One PR per ticket, small, green.
- Every PR also meets CLAUDE.md: tests pass, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --all --check` and `cargo deny check` are clean, docs are updated, there is a CHANGELOG
  entry, and commit messages are in imperative mood with a one-line summary.
- A ticket that runs past twice its estimate stops and is split. New tickets take the next free number
  in their milestone and are added at the end of that milestone's rows. Ids are never reused or
  renumbered. After a split, the calendar, not the id, gives the order.
- Changing a ticket's exit test or estimate is a PR to this file, reviewed by rust-architect, with the
  reason in the PR description.
- To trim M1, mark more tickets `core: no` in a PR, or stop after M1-181 and skip the non-core
  tickets before it. Never trim a "0.1.0 gate" security ticket, the root-only trust store, verify before
  parse, the egress address policy, the kube guard, or the facade policies (00, 02).
- **Marking a ticket done:** in the PR that closes it, add one line to the Done log below:
  `- M1-042 | PR #123 | 2027-01-12`. Leave the table row as it is, so ids and dependencies stay stable.
  The Done log is the source for "what is built".

### Done log

None yet.

## Plan corrections found

- `docs/adr/0005-plugin-model-custom-checks.md`, title and decision 3: `custom.exec` in M3. The scope set
  for this backlog puts it in M4, which also takes load off M3 (AWS, launch, billing). This backlog and
  00 use M4. Fix: amend ADR 0005 to say M4, or move M4-015 to M4-017 back to M3 and revert 00.
- `06-release-and-distribution.md`, version policy: "When M1 exits, tag v0.1.0. After that,
  0.2.0-alpha.N". With core first, 0.1.0 ships ten weeks before M1 ends. Fix: folded into M1-180.
- `05-threat-model.md`, SEC-21: "capped redirects, sixth hop refused". ADR 0014 and 02 follow no redirects
  at all. Fix: reword SEC-21 in 05 to "no redirects".
- `09-docs-site.md`, install page ticket: depends on the M2 Worker route and post-release job. M1 design
  partners use the pinned release URL (PC-16). Fix: the M1 install page tests the pinned URL; the
  `getrdy.io/install` line arrives with the Worker route.
