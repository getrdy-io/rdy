# M1 progress

One line per M1 ticket from `11-backlog.md`. The PR that completes a ticket updates its line:
`id | PR | merged at (UTC date) | deferrals and why`. Lines are separated by blank lines so parallel PRs
that each touch one line do not conflict.

Start: the founder approved the planning pass and started M1 on 2026-10-28, ahead of the Nov 20, 2026
go or no-go in the plan. This is recorded as decision 2 under "Decisions made" in `13-plan-corrections.md`.

The build process, the implementer brief and the state at each pause are in `m1-build-runbook.md`.

## Tickets

- M1-001 | [#6](https://github.com/getrdy-io/rdy/pull/6) | 2026-10-28 | none; MF-04 was reopened and closed after 74e162a, 05 revision 3 applied, follow-ups CF-01 to CF-07 are filed in both review files for their owners

- M1-002 | [#2](https://github.com/getrdy-io/rdy/pull/2) | 2026-10-28 | none. Three ADR gaps reported for the ADR owners (0008 error codes, 0003 vs 0016, 0003 banner order); 07 needed no edit

- M1-003 | [#7](https://github.com/getrdy-io/rdy/pull/7) | 2026-10-28 | Founder or maintainer: create the 12 GitHub labels from `.github/labels.yml` (the ticket says "created"; an agent cannot create labels), then paste `gh label list` into the PR. `deny.toml` is licenses-only (Apache-2.0, MIT, Unicode-3.0); M1-004 adds the bans. LICENSE is copied into each crate dir so it packages; a CI check that the copies match the root file is not built. A bare `rdy` and a bad flag exit 2 (clap default) until M1-029 and the exit-64 ticket

- M1-004 | [#9](https://github.com/getrdy-io/rdy/pull/9) | 2026-10-28 | Exit test proven locally in a scratch copy, not in CI (M1-005 adds CI). Wrappers that keep I/O crates out of check crates are not set; they need `ci/check-crate-deps.toml` from the lint-wall ticket. `reqwest` is banned per 05 and ADR 0014; the M2 upload ticket must lift it with a reviewed change

- M1-005 | [#14](https://github.com/getrdy-io/rdy/pull/14) | 2026-10-28 | zizmor ran with --offline locally only (online audits run in CI); the exit-test throwaway PRs are run by the coordinator

- M1-006 | [#21](https://github.com/getrdy-io/rdy/pull/21) | 2026-10-28 | The macos-arm64 test runs in macos-arm64.yml outside ci-ok until the org has arm64 runners (a Founder hand step). The run, the scratch container and the red-leg-blocks-ci-ok behaviour are for the coordinator to watch on the PR; cargo-nextest and zizmor were not run locally (binary downloads were denied here), so the nextest config and workflow lint are first proven in CI | backlog corrected 2026-10-28 (correction-05, [#40](https://github.com/getrdy-io/rdy/pull/40)): the org has no macOS arm64 runners (probe run 40737208354), so ci-ok gates four native test legs plus an `aarch64-apple-darwin` compile leg on `macos-15-intel`; `macos-arm64.yml` runs the full test job on `macos-15` outside ci-ok; a Founder hand step ends the fallback

- M1-007 | [#47](https://github.com/getrdy-io/rdy/pull/47) | 2026-10-28 | Deferred: the release-sandbox run (the build agent has no access to that repo); exact steps are in 06 "Sandbox proof". Built and proven locally: dist 0.33.0 generate, the hardening script and its drift check, the x86_64 musl dist build (static-pie, `cargo audit bin` lists 63 dependencies after strip), the installer and checker script tests. Not proven: the other four builds, `rdy.exe` imports, the arm64 Mach-O cross build, the Windows and macOS paths of `install-release-tool.sh`. Backlog corrected (correction-07, [#46](https://github.com/getrdy-io/rdy/pull/46)): dist's SBOM is CycloneDX XML, and the sandbox proof is a Founder hand step. Security review round (PR #47): `release.yml` is now dist plus `scripts/harden-release-workflow.py` with a CI drift check (no default token, write only in `announce`, tag shape check, pinned tool files, exact file allowlist). ADR 0020 is Proposed until security-reviewer signs off. The artifact check also fails if `cargo tree -p rdy -e features` shows `preserve_order` for any release target (PR #48 review). New Founder hand step: tag-creation ruleset

- M1-008 | [#3](https://github.com/getrdy-io/rdy/pull/3) | 2026-10-28 | Founder-only, account side: hardware-key MFA on registrar and Cloudflare, recovery codes offline, registrar lock, DNSSEC (DS at registrar), CAA records, HSTS after the Pages site is live. The script cannot read MFA. First run 2026-10-28 shows 0 of 4 passing; rerun `scripts/check-domain.sh` after the founder acts and paste the PASS output into the PR. Also: install whois on the founder machine (.io has no RDAP), shellcheck not run (not installed here) | backlog corrected 2026-10-28: account steps moved to Founder hand steps

- M1-009 | [#13](https://github.com/getrdy-io/rdy/pull/13) | 2026-10-28 | none for the repo: CLAUDE.md edits C-1 to C-9 (rust-architect's exact text) applied by the coordinator in this PR; ADR 0015 sign-off is security-reviewer's in this PR; PC-35 and PC-37 left as cosmetic

- M1-010 | PR #TBD | | Deferred (ADR 0024, agents never push tags or approve environments): the release-sandbox signing proof in 06 "Sandbox proof, signing (M1-010)" (environment `release` with a required reviewer, tag push, approval click, `cosign verify-blob` on a clean machine, one-byte tamper), and `scripts/test-cosign-roundtrip.sh`, written without a cosign binary to run it on; its CI job `cosign-roundtrip` is outside `ci-ok` until its first green run. Built and tested locally with a fake cosign: `sign-release.yml`, `scripts/sign-release.sh`, `scripts/make-sha256sums.sh`, the `custom-sign-release` job in the regenerated `release.yml`, and `check-release-artifacts.sh --files-only --signed` in `announce`. No release exists until signing ends, not even a draft (ADR 0020, decision 2), so the exit test's "draft" should read "no release". `sign-release` needs only `contents: read` and `id-token: write`, so the plan's `contents = write` is dropped. PR #47 carried notes done. ADR 0024.

- M1-011 | todo | | SEC-04 Org 2FA, private reporting, immutable releases, CODEOWNERS and a settings check script | backlog corrected 2026-10-28: account steps moved to Founder hand steps

- M1-012 | todo | | First signed alpha, scripts/verify-release.sh and RELEASING.md

- M1-013 | [#11](https://github.com/getrdy-io/rdy/pull/11) | 2026-10-28 | `schema` writes no file yet (M1-022 adds the schemars output). `docs` writes one placeholder page under `docs/src/content/docs/reference/spec/`, and M1-076 replaces it. The page is not published yet because the Starlight scaffold is not in the repo. `docs --check` and `docs-lint` are not in `ci.yml`. 09 section 10 puts the docs-gen job in M1, but the backlog has it only at M3-002, so the coordinator should file a correction. The banned-token list holds the coordinator's hash list, with the synthetic test hash. The lint applies NFKC normalization before it matches tokens, and it lints every tracked file with no NUL byte, replacing invalid UTF-8 bytes. A UTF-16 file has NUL bytes, so the lint skips it. A generator path that climbs out of its root or is absolute is refused. The check does not yet find stale generated files that no generator emits

- M1-014 | todo | | install.sh core with root refusal, truncation guard, sha256 and shell tests (SEC-08)

- M1-015 | todo | | install.sh signature check, fail closed, with tamper tests (SEC-09, SEC-10)

- M1-016 | [#10](https://github.com/getrdy-io/rdy/pull/10) | 2026-10-28 | check params stay a raw map (M1-019), timeout, max_size and expires stay text (M1-018, M1-026), load() is a fail-closed stub (M1-017, M1-120)

- M1-017 | [#24](https://github.com/getrdy-io/rdy/pull/24) | 2026-10-28 | none. load() still fails closed until M1-120

- M1-018 | [#20](https://github.com/getrdy-io/rdy/pull/20) | 2026-10-28 | version constraints such as ">=4.2" are not a type: metadata.version stays free text per 01 (not evaluated); Version has no ordering yet (first comparing check adds it); CheckParams wiring is M1-019, M1-024, M1-025; timeout range 1s to 60s is checked by the field that uses Duration

- M1-019 | [#25](https://github.com/getrdy-io/rdy/pull/25) | 2026-10-28 | parameter structs for the 17 M1 ids are empty placeholders, so every parameter reads as Unsupported until M1-024 and M1-025; Unknown stands for both not_in_build and unknown_check until M1-023 adds the reserved-id list; did-you-mean and the skip messages are M1-021 and M1-031

- M1-020 | [#22](https://github.com/getrdy-io/rdy/pull/22) | 2026-10-28 | The evidence_only and pass_by_absence snapshot of ADR 0013 decision 6 waits for the check registry (nothing to list yet). `ErrorOutput`, `Verification` and `LintReport` are not typed (M1-021, `rdy verify` and `spec lint` own them). The action log keeps kind-specific fields as a JSON map until M1-040 types them. The 7.x samples round-trip as canonical JSON (equal keys and values), not as raw text, because the samples are hand formatted; the writer's byte layout is M1-055. `FixSource::FromSpec` is not called `Spec` because a variant of that name breaks the M1-016 compile-fail goldens.

- M1-021 | [#31](https://github.com/getrdy-io/rdy/pull/31) | 2026-10-28 | `spec_expired` and `trust_store_insecure` are in the code list with exit 64 but have no `CliError` source: rdy-spec does not check `metadata.expires` and the trust file loader is not built (M1-126 adds the variants and fixtures). The signature codes `spec_unsigned`, `spec_key_unknown` and `spec_signature_invalid` are mapped from `SignatureError`; the exact 01 section 4.8 first-line wording is M1-126's golden. `ErrorOutput` is typed in rdy-cli, not rdy-spec (rdy-spec is in parallel work); move it to `rdy_spec::result` when rdy-cloud needs it. Did-you-mean for unknown spec keys needs the key lists from rdy-spec (M1-031); `SkipWhy` and `timeout_text` hold the 01 section 5.2 words but nothing builds results yet (M1-057). Control characters are escaped as `\x1b` or `\u{202e}` per 07 section 9 rule 9, not deleted. A new `SpecError` variant in rdy-spec falls into `spec_invalid` through a wildcard (the enum is non-exhaustive), so rdy-spec's own hint test is its guard.

- M1-022 | [#48](https://github.com/getrdy-io/rdy/pull/48) | 2026-10-28 | Three parts of the schema come from JSON fragments in crates/rdy-spec/src/schema/ until their types derive (ADR 0019): the parameters of the 17 check ids (M1-024, M1-025), the kind-specific action fields (action log ticket), and ErrorOutput, Verification and LintReport (verify, lint and error tickets). The generator is the `schema` feature of rdy-spec, off by default; xtask and the rdy-spec tests turn it on, so `serde_json/preserve_order` stays out of a `-p rdy` build but is on in `--workspace` builds, which is why `End::Done` is boxed (ADR 0019 decision 4). No tests/fixtures/results/ directory exists, so the golden results checked are B.1 to B.3 of the CLI plan, and files in that directory are checked once it exists. `docs --check` and `docs-lint` are still not in ci.yml; the schema check is a step of the lint job. Quantity sums and URL host labels stay the parser's job (the pattern is looser)

- M1-023 | [#35](https://github.com/getrdy-io/rdy/pull/35) | 2026-10-28 | per-line locations and did-you-mean are M1-031; the bare-threshold case (`no_threshold`) maps to unsupported_spec with a fix naming the missing keys

- M1-024 | [#28](https://github.com/getrdy-io/rdy/pull/28) | 2026-10-28 | none. Net and k8s structs stay placeholders (M1-025). The rule is no_threshold only where 01 names a required key, so host.lsm, host.os and host.security_agents read bare. AbsPath keeps the text as written (the check resolves it). Deferred to M1-031: did-you-mean for a nested unknown key needs the nested key path (it reads as BadValue on the outer key). Deferred, schema fix: change `[^\0]` to `[^\x00]` in the Bundle pattern of spec.v1.schema.json, so the schema loads whole in jsonschema (host_params_schema.rs leaves Bundle out until then)

- M1-025 | [#36](https://github.com/getrdy-io/rdy/pull/36) | 2026-10-28 | Regex fields (expected_issuer, context_pattern, server_pattern) are checked for length only (rdy-spec has no regex engine); compiling them is for lint and sign (M1-031). Schema entries for my ids were tightened to match the structs: minItems 1 on hosts, pin_sha256, apis, arch, expect_in, expect_status; maxItems 16 on expect_status; a host pattern with a port range; maxLength on RBAC parts; scc is a K8sName; typed tolerations; minProperties 1 on K8sResources; stricter cpu string. expect_status and method on a non-URL target are read but not refused (the check decides). Toleration has no tolerationSeconds (refused by name). For M1-026: count egress endpoints, tls_intercept hosts and DNS names against the 64-host spec-wide limit (INV-11). For the k8s.nodes check ticket: a toleration with no key and operator Exists matches every taint, so the check must report control-plane nodes as their own item

- M1-026 | [#43](https://github.com/getrdy-io/rdy/pull/43) | 2026-10-28 | regex compile of redact_patterns (M1-031), did-you-mean in the unknown-key fix line (M1-031), Windows paths in file: collectors (schema allows `/` only; M2); the CLI prints the `expired on` line with no `:` after the file name, and CLI exit 64 on an expired spec (M1-126)

- M1-027 | todo | | Property tests for rdy_spec::parse

- M1-028 | todo | | linux-x64 root job: nextest archive under sudo, root_* filter, strace installed

- M1-029 | [#12](https://github.com/getrdy-io/rdy/pull/12) | 2026-10-28 | `spec init` is M3 (07 section 1) so it is not in the tree; `version --json` waits for the Version schema and exits 70; usage errors print generic text with no flag names or did-you-mean until M1-030; `--help` puts each option text on the line below the flag (clap layout), see 07 Appendix A note

- M1-030 | [#38](https://github.com/getrdy-io/rdy/pull/38) | 2026-10-28 | An unknown flag name is echoed only when it is a typo of a known flag (every long flag in the tree, hidden ones included, plus token, secret, yes, password), so `--hunter2`, UUIDs and hex keys get the generic line; typos that contain `--key` or `--allow-unsigned` are never echoed. Short flags get no did-you-mean. Also bans `parse_from`, `get_matches_from`, `get_matches_mut`, `update_from` and `Error::print`. The did-you-mean limit is capped at 2 and 07 now says swaps count as one. No test greps clippy.toml: M1-044 proves the lint wall. The M1-029 floor test now uses `--CANARY_7f3a=x`

- M1-031 | todo | | rdy spec lint with errors, warnings and did-you-mean

- M1-032 | [#32](https://github.com/getrdy-io/rdy/pull/32) | 2026-10-28 | The row's exit test is split across later tickets: `Engine::run` is M1-034/M1-035, `HostFs` is superseded by the Probe facade (02, M1-040/M1-038), and the setuid refusal is the privilege snapshot ticket. Built here: Check, CheckInfo, Need, CheckContext, Finding, CheckOutcome, with fake-check tests for pass, missing_need skip and no not_applicable. `CheckContext::probe()` and `remaining()` and `CheckError::Probe` wait for M1-040 and M1-034. `rdy_spec::result` is not re-exported yet.

- M1-032 correction-04 | backlog corrected 2026-10-28: exit test narrowed to the outcome types; pass and missing_need through the scheduler moved to M1-034, HostFs reads under host_root moved to M1-045 as the `reads` prefix rule, setuid refusal (INV-10) already in M1-042

- M1-033 | [#34](https://github.com/getrdy-io/rdy/pull/34) | 2026-10-28 | Redaction and size caps stay with M1-062. Timeout, panic and plan-level skips are built by M1-034 and M1-035 on the same CheckResult constructors. M1-057 reconciles the skip text in `rdy_engine::outcome` with `rdy_cli::error::SkipWhy` (the root fix carries a `<spec>` placeholder). `partial.missing_grants` goes to notes until it has a wire field and an owner: see 13, proposed M1-110.

- M1-034 | [#37](https://github.com/getrdy-io/rdy/pull/37) | 2026-10-28 | The run deadline, the "time left in the run" cap and the watchdog are M1-043. `CheckContext::remaining()` is the time left on the check's own timeout until then. A check that hard-spins is never freed (abort needs a yield point): its permit is released at timeout and it keeps one worker until it returns. `probe()` and `CheckError::Probe` still wait for M1-040. The scheduler returns `Ran`/`End` and does not use M1-033's outcome mapping. M1-057 or M1-062 exit test: the CLI panic hook does not print the default panic text. `sched` and tokio are behind the default `runtime` feature.

- M1-035 | [#39](https://github.com/getrdy-io/rdy/pull/39) | 2026-10-28 | `Family::probe` waits for M1-040 and the family probe ticket. `Registry::plan` takes `&Spec` and the rdy version, not `&LoadedSpec`; `Engine::plan` is a thin call to it once `Engine` exists (M1-057). No did-you-mean in plan text; M1-057 reconciles it with `SkipWhy`. Empty `os: []` is `unsupported_spec`, not `not_applicable`. No bridge from `PlanEntry` to the scheduler's `Planned`, and no `End` to `CheckResult` mapping yet: M1-057 must map `End::TimedOut` to timeout, `End::Panicked` to error with a fixed message (the raw panic text is never put in a result; redaction is M1-062), and `End::Cancelled` to cancelled. A family that builds the wrong check plans as a fixed "bug in rdy" not_in_build skip (no tracing dependency yet). `rdy_spec::echo_capped` is now public so plan text uses the same escaping; INV-01 is enforced at `Engine::run(&LoadedSpec)` (M1-057)

- M1-036 | todo | | SEC-19 Confine writes to a new output dir with safe names

- M1-037 | todo | | Windows output directory default and reparse-point checks

- M1-038 | [#44](https://github.com/getrdy-io/rdy/pull/44) | 2026-10-28 | Built as `rdy_engine::blocking` and `rdy_engine::exec` (async `tokio::process`, so no command runs on an abandoned blocking thread). Windows kills only the child, not its tree, until job objects (M2-006): `KILLS_PROCESS_TREE` is false there and M1-039 limits Windows to `whoami.exe`. The exit wait polls `waitid(WNOWAIT)` on every Unix instead of using `pidfd_open`, because every safe `tokio::io::unix::AsyncFd` constructor is deprecated in tokio 1.54 and the supported one is `unsafe`. Descriptors above 2 inherited by `rdy` still reach children (safe rustix cannot set CLOEXEC on a raw descriptor): M1-039 or the CLI start-up closes them. Shell and sudo refusal, PATH and env-name policy are M1-039. Wiring into `Probe` and `ProbeError` is M1-040. The watchdog and Ctrl-C callers of `kill_all_groups` are M1-043 and M1-058. The Hung proof uses a no-op kill function because a test cannot make a process survive SIGKILL.

- M1-039 | todo | | SEC-18 Command policy: search path, declared directories, caps and Windows whoami only

- M1-040 | todo | | SEC-17 Mediated Context handles with action log and read denylist

- M1-041 | todo | | SEC-63 Result schema caps, identity.kube exec plugin and action log retention

- M1-042 | todo | | Privilege snapshot, binary refusal and capability probes

- M1-043 | todo | | Run deadline and watchdog with a report on hang

- M1-044 | todo | | Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers

- M1-045 | todo | | File and env read policy in the facade

- M1-046 | todo | | Closed NativeCall enum in the facade

- M1-047 | [#45](https://github.com/getrdy-io/rdy/pull/45) | 2026-10-28 | The Windows leg is unproven until CI runs it. Not added: `.editorconfig` (08 mentions it, no ticket owns it). The fixture lint (M1-050) must add an allow entry for `tests/fixtures/canary/netstat-crlf.txt` with a reason

- M1-048 | [#29](https://github.com/getrdy-io/rdy/pull/29) | 2026-10-28 | M1-060 also owns the space-separated flag form `--password hunter2` and tuning the over-redaction of bare values (they run to the end of the line on purpose: it fails closed, and splitting at ` --` would leak a password with spaces seen in `ps` output). The key rule parses no quotes, brackets or escapes (every such parser leaked). `value_span` in `redact/rules.rs` says how it fails closed: a simple value (`A-Za-z0-9._~+/=:@%-`) is redacted in place with the deeper lines below it, and any other value takes the rest of its line and every following line up to the next line that is at or left of the key's indent and starts with a key (`name:`, `name=`, `"name":`), or to the end of the text. That stop is held back while a plain count of `[{` exceeds `]}`. It over-redacts on purpose, and M1-060 tunes it with corpus evidence: a one-line JSON object after a secret key loses the rest of its line, `[INFO]` log lines are not keys so a quoted secret in a log can take every line below it, and sibling list items and closing brackets go with the value. A test-only byte counter proves the work is linear. The stop is also held back while the value's opening quote count is odd, while a `-----BEGIN ` has no `-----END `, and `name=` followed by `=`, a quote or the line end is not a key (so `QUJD==` is not). Carried to M1-060: commented-out blocks, including commented PEM lines (`# token: |` then `#   hunter2`; add a corpus case), escapes of the bracket and quote counts (`{"a}": x,` then `v: ...`), and tuning for all-quoted .env files and stray apostrophes. The M1 rules other than `secret_by_key` (M1-060), the report walk and `RedactedReport` (M1-062), the tracing writer and panic hook (M1-056), and the truncated-edge and known-secret handling (M1-061) are their own tickets. `TagKey::fixed` is behind the `testing` feature; the CI check that keeps that feature out of the release binary is not part of this ticket.

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

- M1-064 | [#42](https://github.com/getrdy-io/rdy/pull/42) | 2026-10-28 | Exit test follows correction-06 (3.8 GiB against `4Gi`; 3.7 GiB blocks at the default band). Tolerant kernel-release parsing (5.14.0-362.el9) is left to M1-152. The cgroup helper is a separate ticket.
- M1-064 correction-06 | backlog corrected 2026-10-28: exit test uses 3.8 GiB against `4Gi`, not 3.7 GiB; the band max(5%, 256 MiB) puts the lowest passing value at 4 GiB minus 256 MiB = 3.75 GiB

- M1-065 | todo | | cgroup helper for memory, cpu and controllers

- M1-066 | todo | | Command table and argument allow-lists from 03 Appendix A

- M1-067 | [#49](https://github.com/getrdy-io/rdy/pull/49) | 2026-10-28 | The seven host ids are stubs. On Linux a stub that is run returns a check error, not a finding, until M1-068 and later replace it. Rule: `HostFamily` must not be registered in the CLI while `HostFamily::stub_ids()` is not empty, because a Linux stub reports `error` `check_failed`. M1-057 (wire `rdy run`) must either drop the stubs or have the engine add a `not_in_build` skip first. The facade backend does not exist yet, so the OS comes from the plan and from `CheckContext::os`, and no `probe.native` closure exists to gate.

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

- M1-112 | [#19](https://github.com/getrdy-io/rdy/pull/19) | 2026-10-28 | The "sign a spec in CI" half of the exit test is proved at the helper level (`RDY_KEY_PASSWORD` and `--password-file -` through `rdy_cli::password`); `spec sign` itself is M1-125, which must call `read_key_password`. `--password` is refused by a raw argv check, not a hidden clap flag, so it wins over missing-argument errors; only `spec sign` and `spec keygen` get the reason. Windows checks the file type and refuses reparse points but not ACLs; its file tests run on the Windows CI leg only (compiled here, not run). `read_key_password` now takes stderr for the env-variable note (tty only); it adds the `rustix` dependency (Unix only) for O_NOFOLLOW and geteuid without unsafe. Follow-up fix PR for macOS test build.

- M1-113 | todo | | k8s.nodes allocatable, node filters, conditions, zones and pod-count limit

- M1-114 | todo | | k8s.admission PSA labels, policy engine and SCC discovery

- M1-115 | todo | | Review k8s checks and fixtures (semantics, API groups, RBAC degrade, per-distro sets)

- M1-116 | todo | | Check family renderer and the host, network and Kubernetes pages with hand-written intros

- M1-117 | todo | | Fixture env all-pass

- M1-118 | todo | | Fixture envs warnings-only, all-block and no-privileges

- M1-119 | todo | | Timeouts env and scheduler timeout and deadline tests under paused time

- M1-120 | [#27](https://github.com/getrdy-io/rdy/pull/27) | 2026-10-28 | The verifier is ed25519-dalek verify_strict over our own minisign envelope reader, not minisign-verify (ADR 0018). The Windows autocrlf case is covered by tests (`-text` and `eol=lf` rules in .gitattributes and a CR-free fixture test); the Windows CI leg arrives with M1-006 (#21) and M1-047. Deferred: signed_at future-date warning and expiry check (need a clock, M1-026), trust.yaml I/O (M1-121), key text files for --key (M1-121), CLI wiring and error codes (M1-126), the CRLF note on every error kind (today only `Tampered` carries it, M1-126) and reading the .minisig exactly once (M1-126)

- M1-121 | todo | | Trust store load and save in user and system locations

- M1-122 | todo | | SEC-60 Root trust lookup touches no user path, Windows store ACL rules

- M1-123 | [#23](https://github.com/getrdy-io/rdy/pull/23) | 2026-10-28 | Windows has no pty test and no Ctrl-C handling at the password prompt (the scripted-terminal unit tests cover the logic there, and rpassword does the console work); a signal sent from outside during the hidden read (kill -INT) is not caught, the M1 Ctrl-C ticket owns it; Unix pty tests use rexpect via an examples/prompt_probe helper; `trust add` and `spec sign` wire the helper in M1-131 and M1-125

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

