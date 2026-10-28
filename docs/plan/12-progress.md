# M1 progress

One line per M1 ticket from `11-backlog.md`. The PR that completes a ticket updates its line:
`id | PR | merged at (UTC date) | deferrals and why`. Lines are separated by blank lines so parallel PRs
that each touch one line do not conflict.

Start: the founder approved the planning pass and started M1 on 2026-10-28, ahead of the Nov 20, 2026
go or no-go in the plan. This is recorded as decision 2 under "Decisions made" in `13-plan-corrections.md`.

## Tickets

- M1-001 | [#6](https://github.com/getrdy-io/rdy/pull/6) | 2026-10-28 | none; MF-04 was reopened and closed after 74e162a, 05 revision 3 applied, follow-ups CF-01 to CF-07 are filed in both review files for their owners

- M1-002 | [#2](https://github.com/getrdy-io/rdy/pull/2) | 2026-10-28 | none. Three ADR gaps reported for the ADR owners (0008 error codes, 0003 vs 0016, 0003 banner order); 07 needed no edit

- M1-003 | [#7](https://github.com/getrdy-io/rdy/pull/7) | 2026-10-28 | Founder or maintainer: create the 12 GitHub labels from `.github/labels.yml` (the ticket says "created"; an agent cannot create labels), then paste `gh label list` into the PR. `deny.toml` is licenses-only (Apache-2.0, MIT, Unicode-3.0); M1-004 adds the bans. LICENSE is copied into each crate dir so it packages; a CI check that the copies match the root file is not built. A bare `rdy` and a bad flag exit 2 (clap default) until M1-029 and the exit-64 ticket

- M1-004 | [#9](https://github.com/getrdy-io/rdy/pull/9) | 2026-10-28 | Exit test proven locally in a scratch copy, not in CI (M1-005 adds CI). Wrappers that keep I/O crates out of check crates are not set; they need `ci/check-crate-deps.toml` from the lint-wall ticket. `reqwest` is banned per 05 and ADR 0014; the M2 upload ticket must lift it with a reviewed change

- M1-005 | [#14](https://github.com/getrdy-io/rdy/pull/14) | 2026-10-28 | zizmor ran with --offline locally only (online audits run in CI); the exit-test throwaway PRs are run by the coordinator

- M1-006 | todo | | CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006)

- M1-007 | todo | | dist init for five targets with cargo-auditable and SBOM, proven in release-sandbox

- M1-008 | [#3](https://github.com/getrdy-io/rdy/pull/3) | 2026-10-28 | Founder-only, account side: hardware-key MFA on registrar and Cloudflare, recovery codes offline, registrar lock, DNSSEC (DS at registrar), CAA records, HSTS after the Pages site is live. The script cannot read MFA. First run 2026-10-28 shows 0 of 4 passing; rerun `scripts/check-domain.sh` after the founder acts and paste the PASS output into the PR. Also: install whois on the founder machine (.io has no RDAP), shellcheck not run (not installed here) | backlog corrected 2026-10-28: account steps moved to Founder hand steps

- M1-009 | [#13](https://github.com/getrdy-io/rdy/pull/13) | 2026-10-28 | none for the repo: CLAUDE.md edits C-1 to C-9 (rust-architect's exact text) applied by the coordinator in this PR; ADR 0015 sign-off is security-reviewer's in this PR; PC-35 and PC-37 left as cosmetic

- M1-010 | todo | | sign-release with cosign keyless, SHA256SUMS and self-verify (SEC-06, SEC-07)

- M1-011 | todo | | SEC-04 Org 2FA, private reporting, immutable releases, CODEOWNERS and a settings check script | backlog corrected 2026-10-28: account steps moved to Founder hand steps

- M1-012 | todo | | First signed alpha, scripts/verify-release.sh and RELEASING.md

- M1-013 | [#11](https://github.com/getrdy-io/rdy/pull/11) | 2026-10-28 | `schema` writes no file yet (M1-022 adds the schemars output). `docs` writes one placeholder page under `docs/src/content/docs/reference/spec/`, and M1-076 replaces it. The page is not published yet because the Starlight scaffold is not in the repo. `docs --check` and `docs-lint` are not in `ci.yml`. 09 section 10 puts the docs-gen job in M1, but the backlog has it only at M3-002, so the coordinator should file a correction. The banned-token list holds the coordinator's hash list, with the synthetic test hash. The lint applies NFKC normalization before it matches tokens, and it lints every tracked file with no NUL byte, replacing invalid UTF-8 bytes. A UTF-16 file has NUL bytes, so the lint skips it. A generator path that climbs out of its root or is absolute is refused. The check does not yet find stale generated files that no generator emits

- M1-014 | todo | | install.sh core with root refusal, truncation guard, sha256 and shell tests (SEC-08)

- M1-015 | todo | | install.sh signature check, fail closed, with tamper tests (SEC-09, SEC-10)

- M1-016 | [#10](https://github.com/getrdy-io/rdy/pull/10) | 2026-10-28 | check params stay a raw map (M1-019), timeout, max_size and expires stay text (M1-018, M1-026), load() is a fail-closed stub (M1-017, M1-120)

- M1-017 | todo | | Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits

- M1-018 | todo | | Scalar types Quantity, Duration, Version and Target with strict grammars

- M1-019 | todo | | Two-step check decoding with Unknown and Unsupported variants

- M1-020 | todo | | Define result model and verdict mapping in rdy-spec

- M1-021 | todo | | Error types with fix hints and exit code mapping at the CLI edge

- M1-022 | todo | | Generate JSON schemas with schemars behind cargo xtask schema and check drift in CI

- M1-023 | todo | | Reserved check ids and the not_in_build lint rule

- M1-024 | todo | | Typed parameters for M1 host check ids

- M1-025 | todo | | Typed parameters for M1 net and k8s check ids

- M1-026 | todo | | Semantic validation and structural limits for specs

- M1-027 | todo | | Property tests for rdy_spec::parse

- M1-028 | todo | | linux-x64 root job: nextest archive under sudo, root_* filter, strace installed

- M1-029 | [#12](https://github.com/getrdy-io/rdy/pull/12) | 2026-10-28 | `spec init` is M3 (07 section 1) so it is not in the tree; `version --json` waits for the Version schema and exits 70; usage errors print generic text with no flag names or did-you-mean until M1-030; `--help` puts each option text on the line below the flag (clap layout), see 07 Appendix A note

- M1-030 | todo | | No-echo rule for usage errors: canaries and near-miss flags (extends M1 error types)

- M1-031 | todo | | rdy spec lint with errors, warnings and did-you-mean

- M1-032 | todo | | Check trait, Need and Context in rdy-engine

- M1-033 | todo | | Map outcomes to CheckResult with fix source, partial and needs

- M1-034 | todo | | Scheduler with concurrency limit, per-check timeout and panic isolation

- M1-035 | todo | | Family trait, registry and run plan

- M1-036 | todo | | SEC-19 Confine writes to a new output dir with safe names

- M1-037 | todo | | Windows output directory default and reparse-point checks

- M1-038 | todo | | Blocking helper and subprocess kill on timeout

- M1-039 | todo | | SEC-18 Command policy: search path, declared directories, caps and Windows whoami only

- M1-040 | todo | | SEC-17 Mediated Context handles with action log and read denylist

- M1-041 | todo | | SEC-63 Result schema caps, identity.kube exec plugin and action log retention

- M1-042 | todo | | Privilege snapshot, binary refusal and capability probes

- M1-043 | todo | | Run deadline and watchdog with a report on hang

- M1-044 | todo | | Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers

- M1-045 | todo | | File and env read policy in the facade

- M1-046 | todo | | Closed NativeCall enum in the facade

- M1-047 | todo | | Fixture format README, .gitattributes and Windows canary

- M1-048 | todo | | SEC-25 Minimal redactor for evidence, errors and logs

- M1-049 | todo | | Replay backend and fixture loader in the 08 format

- M1-050 | todo | | Fixture lint as a nextest test

- M1-051 | todo | | Engine test helpers FakeCheck, run_fixture and normalize

- M1-052 | todo | | Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check

- M1-053 | todo | | Add bucket to CheckResult and sort by it in terminal and HTML

- M1-054 | todo | | Summary line grammar and nothing-verified last line

- M1-055 | todo | | HTML-safe deterministic JSON writer with size caps

- M1-056 | todo | | Redacting tracing writer, panic hook and CLI error text

- M1-057 | todo | | Wire rdy run end to end: load, needs, families, engine, report, exit code

- M1-058 | todo | | Ctrl-C in M1: abort, remove the empty report folder, exit 70

- M1-059 | todo | | --no-network and --jobs flags

- M1-060 | todo | | M1 redaction rules for URLs, auth headers, AWS keys, PEM keys, JWTs, rdy tokens and key names

- M1-061 | todo | | Redact facade-truncated buffers and a run-scoped known-secret set

- M1-062 | todo | | Redact then cap every Report string and return RedactedReport

- M1-063 | todo | | SEC-26 M1 redaction corpus, first 30 cases (0.1.0 gate)

- M1-064 | todo | | Shared helpers: units, quantities, dotted version compare, nominal band, severity cap

- M1-065 | todo | | cgroup helper for memory, cpu and controllers

- M1-066 | todo | | Command table and argument allow-lists from 03 Appendix A

- M1-067 | todo | | OS support table and compile stubs for rdy-checks-host

- M1-068 | todo | | host.disk (Linux: statvfs flags, mountinfo with escapes, whole-component match, hung-mount timeout)

- M1-069 | todo | | host.memory (meminfo, swap, cgroup limit, nominal band)

- M1-070 | todo | | Terminal styling layer: colour choice, width, escaping and ASCII text

- M1-071 | todo | | host.cpu (cores with quota, arch, flags through std macros, levels, Rosetta)

- M1-072 | todo | | host.ports (Linux /proc/net TCP and UDP, lazy owner lookup, ephemeral overlap)

- M1-073 | todo | | host.os (os-release, uname, FIPS, container and WSL detection, match rules)

- M1-074 | todo | | In-process CLI entry point rdy_cli::run taking a Backend

- M1-075 | todo | | Env-level harness, in process

- M1-076 | todo | | Spec renderer for objects and scalars

- M1-077 | todo | | askama HTML report with inline CSS, dark mode and print

- M1-078 | todo | | Embed result JSON in the HTML report safely

- M1-079 | todo | | HTML print override, labels and legend

- M1-080 | todo | | HTML fix source label and action log table

- M1-081 | todo | | HTML Found and Needed rendering and the footer link (extends HTML print override)

- M1-082 | todo | | HTML structure test: headings, landmarks, tables and links

- M1-083 | todo | | Golden tests for JSON and HTML reports

- M1-084 | todo | | Spec renderer for enums, oneOf variants and YAML examples, with the missing-description failure

- M1-085 | todo | | Spec and result reference pages with hand-written intro

- M1-086 | todo | | Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict

- M1-087 | todo | | Exit-code golden suite for 0, 1, 2, 64 and 70

- M1-088 | todo | | --json stdout hygiene on every exit path and the static TTY line

- M1-089 | todo | | CheckMeta in the check registry, read by xtask

- M1-090 | todo | | Loopback network test support (TLS server with generated CA, CONNECT proxy modes, closed port, never-accepting listener, reset after ClientHello, 302 server, dual-stack case)

- M1-091 | todo | | Facade TCP attempts, proxy CONNECT and per-check host sets

- M1-092 | todo | | Facade TLS with system roots and the recording chain probe

- M1-093 | todo | | Facade HTTP/1.1 probe with 64 KiB discard and no redirects

- M1-094 | todo | | SEC-21 Egress address policy, no redirects, no bodies

- M1-095 | todo | | net.egress staged connector (lookup, dual-stack connect, TLS, ALPN)

- M1-096 | todo | | net.egress HTTP stage and failure classes

- M1-097 | todo | | net.egress via proxy (own CONNECT, absolute-form for http, 407) and redirect host evidence

- M1-098 | todo | | net.proxy (process env, systemd drop-ins, NO_PROXY coverage, PAC detection, reachability)

- M1-099 | todo | | net.tls_intercept recording verifier and classes

- M1-100 | todo | | net.tls_intercept evidence, trust-store report and fix text

- M1-101 | todo | | Security review of the TLS recording verifier and 03 Appendix A

- M1-102 | todo | | Kube client from kubeconfig or in-cluster with rustls and timeouts

- M1-103 | todo | | Read-only guard layer and test for rdy-checks-k8s

- M1-104 | todo | | Kube guard path parser, resource allowlist and pending log entries

- M1-105 | todo | | Kube mock harness (tower service replaying api/ JSON, paging and 410, selectors, legacy discovery, review table)

- M1-106 | todo | | k8s.version (gitVersion parse, distribution, discovery API availability)

- M1-107 | todo | | Family probe hook and lazy KubeContext probe

- M1-108 | todo | | kind integration job with a restricted PSA namespace and review round trips

- M1-109 | todo | | k8s.access (kubeconfig, version, SelfSubjectReview, anonymous warn, exec classes, proxy resolution)

- M1-110 | todo | | k8s.storageclass (normalised provisioners, CSINode evidence, default rules, provisioner table)

- M1-111 | todo | | k8s.rbac (SelfSubjectReview, access reviews, non-resource items, escalate and bind as warn)

- M1-112 | todo | | Refuse --password on argv and read key passwords from env or file

- M1-113 | todo | | k8s.nodes allocatable, node filters, conditions, zones and pod-count limit

- M1-114 | todo | | k8s.admission PSA labels, policy engine and SCC discovery

- M1-115 | todo | | Review k8s checks and fixtures (semantics, API groups, RBAC degrade, per-distro sets)

- M1-116 | todo | | Check family renderer and the host, network and Kubernetes pages with hand-written intros

- M1-117 | todo | | Fixture env all-pass

- M1-118 | todo | | Fixture envs warnings-only, all-block and no-privileges

- M1-119 | todo | | Timeouts env and scheduler timeout and deadline tests under paused time

- M1-120 | todo | | Verify minisign signatures in rdy-spec against a trust store with product binding

- M1-121 | todo | | Trust store load and save in user and system locations

- M1-122 | todo | | SEC-60 Root trust lookup touches no user path, Windows store ACL rules

- M1-123 | todo | | Prompt helper: y/N, no-terminal refusal and hidden input

- M1-124 | todo | | Review CONTRIBUTING.md on a fresh clone

- M1-125 | todo | | rdy spec keygen and rdy spec sign

- M1-126 | todo | | rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner

- M1-127 | todo | | Real-binary smoke on five legs: live exit codes 0, 1, 2 and 64

- M1-128 | todo | | SEC-22 No-phone-home strace test on Linux CI

- M1-129 | todo | | First run page and M1 example spec

- M1-130 | todo | | SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading

- M1-131 | todo | | rdy trust add, list and remove

- M1-132 | todo | | Security review of spec signing and trust store

- M1-133 | todo | | Install, exit codes and unsigned pages

- M1-134 | todo | | Sign and verify page

- M1-135 | todo | | Golden README transcripts from Replay envs (acme-quickstart refusal, NOT READY, READY; acme-platform skipped checks)

- M1-136 | todo | | docs-test runner for README and docs tested blocks

- M1-137 | todo | | README draft from 10 section 1

- M1-138 | todo | | Tag and release 0.1.0

- M1-139 | todo | | Alpha announcement to design partners | backlog corrected 2026-10-28: human steps moved to Founder hand steps

- M1-140 | todo | | HTML next-step sentences and the nothing-verified wording

- M1-141 | todo | | HTML untrusted strings in bdi with bidi controls shown as escapes

- M1-142 | todo | | Progress line with indicatif, TTY only

- M1-143 | todo | | Quiet and verbose output modes

- M1-144 | todo | | Facade methods for UDP exchanges and unix sockets with a GET-only Docker API guard

- M1-145 | todo | | host.lsm (SELinux, AppArmor, audit log denials) (M1-late)

- M1-146 | todo | | host.security_agents (process names, agents.toml format, seed list) (M1-late)

- M1-147 | todo | | host.firewall (firewalld zone and service XML, ufw) (M1-late)

- M1-148 | todo | | host.time_sync (adjtimex, timedatectl, chronyc, SNTP client) (M1-late)

- M1-149 | todo | | host.sysctl (live and persisted values, precedence, systemd limits) (M1-late)

- M1-150 | todo | | host.container_runtime (sockets, daemon.json, containerd v2 and v3, kubelet driver, API over unix socket) (M1-late)

- M1-151 | todo | | host.cgroups (v1, hybrid, v2, controllers) (M1-late)

- M1-152 | todo | | host.kernel (version and modules) (M1-late)

- M1-153 | todo | | net.dns system answer (getent path, name validation, fallback, timeout evidence) (M1-late)

- M1-154 | todo | | musl resolver behaviour fixture for net.dns

- M1-155 | todo | | net.dns direct nameserver lookups, resolv.conf and nsswitch analysis, scripted DNS server (M1-late)

- M1-156 | todo | | net.registry (v2 ping, token realm, manifest and config blob host, HEAD versus GET) (M1-late)

- M1-157 | todo | | net.mtu (Linux sysfs, sysinfo elsewhere, overlay overhead tables) (M1-late)

- M1-158 | todo | | net.bandwidth (ranged sample, injected clock) (M1-late)

- M1-159 | todo | | k8s.nodes free capacity from pod requests (cut 2)

- M1-160 | todo | | k8s.admission webhooks, validating admission policies and the dry-run guard test (M1-late)

- M1-161 | todo | | k8s.namespace (existence, terminating, quota, limit range, project request) (M1-late)

- M1-162 | todo | | k8s.dns (label-based selection, Corefile, restart evidence) (M1-late)

- M1-163 | todo | | k8s.ingress (IngressClass by controller, Gateway API, route, pending LoadBalancer, retirement warning) (M1-late)

- M1-164 | todo | | k8s.crds (CRDs, served versions, operator version) (M1-late)

- M1-165 | todo | | k8s.cni (node-condition and CRD signals, DaemonSets, NetworkPolicy, CIDRs, cni.toml) (M1-late)

- M1-166 | todo | | Fixture env net-airgapped

- M1-167 | todo | | Time the quickstart with two design-partner SEs | backlog corrected 2026-10-28: human steps moved to Founder hand steps

## Summary

Written when the last M1 ticket merges: what shipped, what moved to M2 and why.

