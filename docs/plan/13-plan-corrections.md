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

## Corrections

| id | where | what is wrong | proposed fix | severity | raised by |
| --- | --- | --- | --- | --- | --- |
| PC-01 | `KICKOFF.md`, "After the plan"; plan, "Risks, validation gates" ("The gates below come before M1") and "Next 30 days" ("No Rust until the gates are met", go or no-go on Nov 20, 2026) | KICKOFF starts M1 as soon as the backlog is approved, which can be before Nov 20. The plan forbids Rust before a "go". The plan also contradicts itself: the same 30-day list budgets two weekends for a throwaway Rust prototype. | KICKOFF: start M1 only after a recorded "go" against the gates, earliest Monday Nov 23, 2026. Plan: "No product Rust until the gates are met. A throwaway demo prototype in a scratch repo is allowed." Founder decides; see open decision 1. | blocks M1 | 00 |
| PC-02 | `KICKOFF.md`, constraints ("M1 is six weeks"); plan, "Rust build plan" ("a usable CLI in about 12 weeks") and "Build order inside M1 (first six weeks)" | Six weeks at 10 to 15 hours is 60 to 90 hours. M1 as scoped counts about 194 hours (00), then about 248 hours (02), before the cli-ux, testing, docs and devrel tickets are added. The plan's "12 weeks" matches neither. `11-backlog.md` counts 365 hours (306 core). | Decision made: M1 is extended (see Decisions made). `KICKOFF.md` constraints: replace "M1 is six weeks" with "M1 runs at its real size from `11-backlog.md`, starting after a recorded go on Nov 20, 2026; tickets marked `core: yes` are the minimum and `core: no` is the trim list." Plan line 141: replace "about 12 weeks" with the backlog figure (0.1.0 after 25 weeks and all of M1 after 29 weeks, at 13 hours a week). Plan line 198: retitle "Build order inside M1 (first six weeks)" to "Build order inside M1". Leave the `KICKOFF.md` scope list to PC-25. | blocks M1 | 00, 02, 03, 07, rv02-security, rvADR-security |
| PC-03 | `CLAUDE.md`, rule 3; plan, "Rust build plan", Design rules, third bullet | "refuses unsigned or tampered specs unless `--allow-unsigned` is set" lets the flag run a spec whose signature fails. ADR 0002 decision 7 and 01 section 4.7 refuse that always. | "The CLI refuses unsigned specs unless `--allow-unsigned` is set, and says so loudly. It always refuses a spec whose signature fails, with or without the flag." | blocks M1 | ADR, rvADR-security, rv01-security, 01, 05 |
| PC-04 | `CLAUDE.md`, Commands (`cargo run -p rdy-cli -- run examples/specs/acme-platform.yaml --json`); plan, crate table row `rdy-cli` | The package is `rdy` in `crates/rdy-cli` (ADR 0011), so `-p rdy-cli` fails. The example spec ships unsigned, so the command exits 64 (`spec_unsigned`). | `cargo run -p rdy -- run examples/specs/acme-platform.yaml --allow-unsigned --json` until signed examples ship in M2. Crate table: "`rdy` (directory `crates/rdy-cli`)". | blocks M1 | ADR, 00, 01, 09, 10, rv01-cli-ux |
| PC-05 | Plan, "Business model and revenue" (tiers, ARR scenarios), Risks row "Employment agreement", "Website plan" and "Name, domain and repositories" (trademark history), Option B pricing; `CLAUDE.md`, Repo layout (`docs/plan/` holds the plan) | The repo must be public before the first CI ticket (06: private CI runs out of free minutes in about a dozen runs; 10 also chose public from M1). The plan copy would then publish pricing, ARR scenarios, the employment-agreement row and the trademark history. | Founder decides before `getrdy-io/rdy` is created: keep, trim, or move the business sections to `rdy-cloud` and leave a short technical summary. See open decision 2. | blocks M1 | 06, 09, 10, rv09-release |
| PC-06 | `KICKOFF.md`, constraints ("... and signing") | Reads as spec signing only. Release signing (cosign, checksums, install.sh verification) lands in weeks 1 to 3 of the `11-backlog.md` calendar (the first signed alpha in week 2, the install.sh signature check in week 3). | "spec signing and release signing". PC-25 edits the same sentence. | should fix before M1 | 06 |
| PC-07 | Plan, "Milestones" table, Exit test column | Every exit test is a business outcome that CI cannot check, so no ticket can close a milestone. | Keep the business test and add an "engineering done" column, as in the 00-overview.md milestone table. | should fix before M1 | 00 |
| PC-08 | Plan, "Build order inside M1" (signing is step 6) | Builds before step 6 cannot refuse unsigned specs, which breaks `CLAUDE.md` rule 3. | Add: "Builds before signing lands are tagged `0.1.0-alpha.N`, run specs only with `--allow-unsigned`, and are not given to design partners for real POCs." See PC-38. | should fix before M1 | 00 |
| PC-09 | Plan, "Architecture" ("One Cargo workspace. The CLI and the portal share the spec and result types") | There are two repos and two workspaces. A shared workspace would let `rdy-cloud` use the types by path, which `CLAUDE.md` rule 6 forbids. | "Two workspaces. `rdy-cloud` depends on `rdy-spec` and `rdy-engine` from crates.io, never by path (ADR 0007)." | should fix before M1 | 00 |
| PC-10 | Plan, "Release engineering" ("Binaries and specs signed with Sigstore (cosign)"); crate table row `rdy-spec` (`ed25519-dalek`) | Specs are signed by the vendor's ed25519 key (`CLAUDE.md` rule 3), not cosign. The format is minisign (ADR 0002), so the crates are not `ed25519-dalek`. | "Binaries and checksums are signed with Sigstore cosign. Specs are signed by the vendor's ed25519 key in minisign format." Crate row: `minisign-verify` (verify) and `minisign` (sign). | should fix before M1 | ADR, 05, rv06-code |
| PC-11 | Plan, crate table row `rdy-spec` (`serde_yaml`) | `serde_yaml` was deprecated and archived by its author in March 2024. The fork `serde_yml` carries RUSTSEC-2025-0068. | Replace with `serde-saphyr` (ADR 0001). Ban `serde_yaml` and `serde_yml` in `deny.toml`. | should fix before M1 | ADR, 05 |
| PC-12 | Plan, crate table row `rdy-checks-host` (`sysinfo, nix, windows-sys`) | Direct `windows-sys` calls need `unsafe`, against `#![forbid(unsafe_code)]` in `CLAUDE.md`. `nix` duplicates `rustix`. | `sysinfo` (no default features), `rustix`, `winreg`, `plist`, `toml`: safe-API crates that keep the unsafe inside them. | should fix before M1 | 03, rv03-rust-engineer, rv05-code |
| PC-13 | Plan, crate table row `rdy-checks-net` (`reqwest with rustls, hickory-resolver`) | reqwest 0.13 defaults to `aws-lc-rs`, and since ADR 0014 the probe facade owns every TCP, CONNECT, TLS and HTTP side effect. reqwest hides the peer chain and per-stage failures. | "Probe facade over `tokio-rustls` and `hyper` on ring, `rustls-native-certs`, `webpki-roots`, `x509-parser`, `hickory-resolver` (default features off). `reqwest` (rustls on ring, no default features) only for the M2 upload client." | should fix before M1 | ADR, 02, 03, rv03-rust-engineer |
| PC-14 | Plan, "How a POC flows" step 1 (`rdy run acme-platform --token abc123`) and Home page copy, terminal demo (`rdy run acme-platform`) | Running a spec by product name and a share token both need the M2 portal. A token on argv is readable in `ps`, `/proc/<pid>/cmdline` and shell history. M1 `run` takes a spec file. | M1 copy uses `rdy run <spec file>`. From M2, `rdy run <product>` takes the token from `RDY_TOKEN`, `--token-file` or a prompt, and a `--token` value on argv exits 64. The final text for plan line 88 is given once, in PC-16. | should fix before M1 | 00, 04, 05, 09, 10 |
| PC-15 | Plan, "Website plan", Stack ("Install endpoint: `get.<domain>`") against `CLAUDE.md` Names and places and the plan's names table (`getrdy.io/install`) | Two install URLs. Also the apex is the marketing site's Pages custom domain, and a Pages project cannot serve one path of it. | `https://getrdy.io/install` everywhere; delete `get.<domain>`. Served with a 200 by a Worker route owned by 06, never by a redirect. | should fix before M1 | 00, 05, 09, 10 |
| PC-16 | `CLAUDE.md`, Names and places (install line); plan, "How a POC flows" step 1 and names table | `curl -sSf` lacks `--proto '=https' --tlsv1.2` (06 uses them). Without `-L` a redirect makes `sh` run an empty script and exit 0. `&& rdy run` fails when `~/.local/bin` is not on `PATH` in that shell. Many customer shells are root, and install.sh refuses root without `--allow-root`. | Final text, used in the plan (line 88 and the names table) and `CLAUDE.md`. M1 docs: download the pinned release `install.sh` (06), then `"$HOME/.local/bin/rdy" run acme-platform.yaml`. From M2, when the Worker route ships (11-backlog.md M2-019): `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install \| sh && "$HOME/.local/bin/rdy" run acme-platform`, with the token from `RDY_TOKEN` or a prompt. Docs show `sh -s -- --allow-root` for root shells. `-L` is not added: the endpoint serves 200 and the 09 verify job asserts it (PC-15). PC-14 points here. | should fix before M1 | 05, 06, 09, rv09-release |
| PC-17 | Plan, "Product definition", Example spec | It mixes milestones (`bundle:` is M2, `aws.iam` M3, `gpu.cuda` M4). `needs:` is now `access_modes`. `registry.acme.io` and `license.acme.io` are real domains that every run would query. `gpu.cuda min: "12.4"` is ambiguous and false-blocks under CUDA minor version compatibility. The sample does not say that a nominal band applies by default (03), so `min: 32Gi` passes a nominal 32 GiB VM that reports about 31.3 GiB. `aws.iam simulate` needs `iam:SimulatePrincipalPolicy`, and "IAM permissions dry-run" is really simulation. 00 tickets use "the plan's example spec" as a test input. | Label the sample "design sample, not runnable in M1". Use `.example` hosts (RFC 2606, as `examples/specs/` does). Rename to `access_modes`. Give `gpu.cuda` `built_with`, `source: driver\|toolkit` and `compat: minor\|strict\|forward`. Say that a nominal band applies by default. Say "IAM simulation, with EC2 dry-run as an opt-in fallback". The runnable M1 example is `examples/specs/acme-platform.yaml`: host, net and k8s checks plus one unknown id. The two 00 tickets that used this sample as M1 input now use `examples/specs/acme-platform.yaml` (11-backlog.md M1-016 and M1-035). | should fix before M1 | 00, 01, 03, 09, 10, rv01-cli-ux, rv03-gpu, rv03-cloud-iam |
| PC-18 | Plan, "Check families at launch" (Data stores, Custom) and Milestones table; `CLAUDE.md`, Repo layout | Data stores and Custom have no milestone and no crate. The documents disagree on where they go (03: stores M3; 09: stores M4, custom M5; ADR 0005: custom.exec M3; 00: stores M4). Launch copy would claim families that do not ship. | Add a milestone column to the family list: host, network, Kubernetes M1; bundle M2; AWS account M3; GPU M4; data stores M4 as a feature-gated module of `rdy-checks-net` (M3 already carries AWS, billing and launch; 03 said M3, check-author to confirm); `custom.file` M2 in `rdy-checks-host`; `custom.exec` M4 in `rdy-engine`, as in `11-backlog.md` and ADR 0005 (amended 2026-10-28). Launch copy claims only what ships by the end of M3. | should fix before M1 | ADR, 00, 03, 09, 10 |
| PC-19 | `CLAUDE.md`, Repo layout rows for `rdy-checks-host`, `rdy-checks-net`, `rdy-checks-k8s`; plan, "Check families at launch", Host, Network and Kubernetes bullets | 03 marks 24 tickets (72 hours) as M1-late: host 11, net 6, k8s 7. The first draft of this entry moved them to M2, which the founder's decision reverses. The 11 review then moved the macOS and Windows data sources to M2 and `k8s.device_plugins` to M4 with the GPU family. | Keep the rest of the M1-late tier in M1, marked `core: no` in `11-backlog.md` (done there). In the `CLAUDE.md` layout, mark device plugins as M4 and nothing else about tiers. See PC-27 for where `k8s.device_plugins` lives. | cosmetic | 00, 03, rv03-k8s |
| PC-20 | `CLAUDE.md`, Engineering standards ("Cross-platform from day one ... CI runs all four") | macOS ships two arches, so there are five release targets and five CI legs (06). Host data sources for macOS and Windows cannot all land in M1. | "Five release targets: Linux x86_64 and aarch64 (musl), macOS aarch64 and x86_64, Windows x86_64. Five CI legs, each running the full test job. If the Intel macOS image is retired, `x86_64-apple-darwin` is built on the arm64 runner and tested nightly (06). Every check compiles and runs on every target from day one; where a data source is not built yet, the check reports Skipped, not yet on this OS." | should fix before M1 | 00, 03, 06, 08 |
| PC-21 | `CLAUDE.md`, Engineering standards (exit codes) | clap exits 2 on a usage error by default, and 2 means NOT READY here. | Add: "clap usage errors are mapped to 64, and a test runs `rdy --bogus`." | should fix before M1 | 07, 08 |
| PC-22 | `CLAUDE.md`, Repo layout (every crate listed from day one) | Reads as a workspace with nine crates in week 1. Cloud and GPU crates have no M1 work. | Add: "A crate enters the workspace when its milestone starts. crates.io placeholders hold the names." | should fix before M1 | 00 |
| PC-23 | `CLAUDE.md`, Repo layout lines `rdy-engine` ("result model") and `rdy-bundle` ("redactors"); plan, crate table rows `rdy-engine` ("result model", line 154) and `rdy-bundle` ("Collect, redact", line 160); plan, public repo layout lines for `rdy-engine/` (line 393) and `rdy-bundle/` (line 399) | All `rdy/v1` wire types, results and the bundle manifest included, live in `rdy-spec` (ADR 0012). The minimal redactor lives in `rdy-engine` and runs before any write (ADR 0015). | `rdy-spec`: "schema, wire types for specs, results and the bundle manifest". `rdy-engine`: "check trait, scheduler, probe facade, privilege negotiation, redactor, HTML and JSON reports". `rdy-bundle`: "collectors, tar+zstd, manifest; reuses `rdy_engine::redact`". | should fix before M1 | ADR, 04 |
| PC-24 | `CLAUDE.md`, Repo layout, `rdy-cli` command list | Missing `spec keygen`, `trust add\|list\|remove` and `redact`. No milestones. | M1: `run`, `verify`, `spec lint\|sign\|keygen`, `trust add\|list\|remove`, `version`. M2: `bundle`, `upload`, `report`, `redact`. M3: `spec init`, `self-update`, `completion`. | should fix before M1 | ADR, 07, rvADR-cli-ux |
| PC-25 | Plan, Milestones table (docs only in M3); `KICKOFF.md`, constraints ("Anything else is M2 or later") | `CLAUDE.md` requires docs in every PR, and the M1 exit test needs a design partner who can follow install and first-run steps. `KICKOFF.md` shuts out the M1 docs pages, and the M1 security and devrel tickets. | Add minimal docs to M1 as Markdown pages under `docs/`: install, first run, exit codes, unsigned specs, sign and verify, plus the generated reference. The hosted site is M3 (11 review). In `KICKOFF.md`, change "Anything else is M2 or later" to "plus the minimum docs, security and release work those need; anything else is M2 or later" (the same sentence as PC-06). | should fix before M1 | 09 |
| PC-26 | Plan, "Conversion flow" step 4 ("see which prospects clicked through") and "Metrics that matter" | Conflicts with "nothing leaves the machine". The M1 HTML report already carries the link. | "The report link carries only the public product name. Clicks are counted by site analytics on getrdy.io, never by the CLI." State it on the trust page. | should fix before M1 | 10 |
| PC-27 | Plan, crate table row `rdy-checks-gpu` (`nvml-wrapper (optional)`); `CLAUDE.md`, Repo layout row `rdy-checks-gpu` ("VRAM per node", "device plugin") | `nvml-wrapper` needs `dlopen`, which a static musl binary cannot do (ADR 0006). The in-cluster half has no home in the GPU crate. | GPU checks use `nvidia-smi` and `/proc/driver/nvidia`. Move the device plugin and VRAM per node (from GPU Feature Discovery labels) to `rdy-checks-k8s` as `k8s.device_plugins`, shipped in M4 with the GPU family. See PC-19. | should fix before M1 | ADR, 03, rv03-gpu |
| PC-28 | Plan, "Release engineering" (`cargo-zigbuild`, `cargo-dist`); `CLAUDE.md`, Supply chain and layout (`release.yml (cargo-dist)`); `KICKOFF.md` item 7 ("cargo-dist config") | Native arm64 runners remove the need for zigbuild (fallback only, ADR 0006). `cargo-dist` is now `dist`, configured in `dist-workspace.toml`. The week 1 release tickets use these names. | Drop zigbuild from the main path. Say `dist`. In `KICKOFF.md` item 7 say "dist config (`dist-workspace.toml`)". See PC-29, which edits the same layout line. | should fix before M1 | 05, 06 |
| PC-29 | `CLAUDE.md`, Repo layout (`.github/workflows/` and root files) | Lists `ci.yml`, `release.yml`, `audit.yml` only. | Add `sign-release.yml`, `docs-deploy.yml` (M1), a docs preview workflow (M2), `dist-workspace.toml`, `.cargo/config.toml`, `RELEASING.md`, `CHANGELOG.md`, `scripts/verify-release.sh`. Note that dist generates `release.yml`. See PC-28. | should fix before M1 | 06, 09, rv09-release |
| PC-30 | `CLAUDE.md` and plan, Repo layouts (`docs/`) | Neither says that Starlight publishes only `src/content/docs/`, so readers cannot tell whether `docs/plan/` and `docs/adr/` are published. | State the content root in both layouts. The published-content guard in 09 enforces it. | should fix before M1 | 09 |
| PC-31 | Plan, crate table rows `rdy-server`, `rdy-ffi`, `rdy-wasm` | The table mixes repos. `rdy-server` is private, and the Embed SDK crates have no home. | Mark `rdy-server` as `rdy-cloud`. Put `rdy-ffi` and `rdy-wasm` in the public repo at M5. | cosmetic | 00 |
| PC-32 | `CLAUDE.md`, Engineering standards, Docs bullet | `cargo doc` warnings are errors, but nothing publishes the API docs. | Say the docs.rs pages of `rdy-spec` and `rdy-engine` go live with their first crates.io release (M2), and the docs site links there. | cosmetic | 09 |
| PC-33 | Plan, "Website plan", Pages table, Docs row ("portal API") | The portal is private, so the public docs cannot document its API yet. | Drop "portal API" from the public docs until M3, and decide then where portal docs live. | cosmetic | 09 |
| PC-34 | Plan, Example spec and Check families ("Cloud account" family, `aws.` ids) | Unclear whether ids are `aws.*` or `cloud.aws.*`. | Keep `aws.*`, as 03 does, with `gcp.*` and `azure.*` reserved. Say so in the family list. | cosmetic | 09 |
| PC-35 | Plan, lines 9, 28, 213 and 283 ("the incumbent Kubernetes-only preflight tool") and evidence point 3 (remote host collectors) | The incumbent tool also has host collectors and preflights. Its remote-node limit is no rdy advantage while rdy also runs only where it is started. | Say "Kubernetes-first". Keep any multi-node claim out of public copy until rdy can run against remote hosts. Changing the descriptor is a repo-wide sweep, and the common brief that prescribes it needs the same edit. | cosmetic | 10 |
| PC-36 | Plan, "Home page copy outline", proof row (line 294, "7x faster installs") | The figure is a 2022 study by the incumbent vendor about its own product. Line 22 already says "(2022 study, vendor-reported)". Line 294 says "with its source" but gives no year. | Add the year at line 294. Leave the figure out of the HN post. | cosmetic | 10 |
| PC-37 | Plan, Milestones table, M3 | The M3 exit test ("First 10 paying vendors") can only be measured after the launch that M3 contains. | Launch when M3 scope is done; measure the exit test over the next eight weeks. The 12-month star and install targets start on launch day. | cosmetic | 10 |
| PC-38 | Plan, "Rust build plan" and "Release engineering" | Weekly binaries, but no version policy. | Point to ADR 0007 and 06: weekly builds are `0.1.0-alpha.N` pre-releases, crates version independently, one docs version per stable minor. See PC-08. | should fix before M1 | 09, rv06-code |
| PC-39 | Plan, "Architecture" and "Milestones" (`[embedded content: architecture ...]`, `[embedded content: build timeline ...]`) | Two embeds from the source document did not survive the copy, and the text refers to diagrams the reader cannot see. | Replace each with a short text diagram or table, or delete the line. | cosmetic | 13 |
| PC-40 | Plan, "Why the numbers hold up", second bullet | It lists the lead investors and angels of the BYOC deployment platform's round next to the round size. That does not break the no-competitor rule as written, but it identifies the company. | Drop the investor and angel names; keep "a BYOC deployment platform raised $16.5M". Do it before `getrdy-io/rdy` is created (PC-05). Consider "a BYOC deployment platform raised a large round" at plan lines 9, 30 and 128, since the exact figure also identifies the company. | should fix before M1 | 13 |
| PC-41 | Plan, crate table row `rdy-cli` (`self_update`) | `self_update` cannot verify cosign, and self-update is M3. | Replace `self_update` with "signed self-update, M3, trust model by ADR". | cosmetic | 05, 06 |
| PC-42 | Plan, "Next 30 days" (line 354, "Still to do: ... GitHub org") against the names table (line 378, "GitHub org \| getrdy-io \| Owned") | The plan says both that the GitHub org is still to do and that it is owned. | Drop "GitHub org" from line 354. | cosmetic | rv13-code |

## Decisions made

1. **M1 length (2026-10-28).** M1 is extended, not cut. It is planned at its real size, at 10 to 15 founder
   hours a week, and starts after the Nov 20, 2026 go or no-go. Every document's cut list stays as a
   `core` marker so you can still trim. The M1-late tier stays in M1 and is marked `core: no`. A usable
   binary still ships every week. `11-backlog.md` sets the numbers, after the code-reviewer and
   qa-engineer reviews of it: M1 is 167 tickets and 365 hours, 306 of them core. At 13 hours a week from
   Nov 23, 2026, with core tickets first, 0.1.0 ships in week 25 (May 10 to 16, 2027) and **M1 ends on
   Sunday Jun 13, 2027** (week 29). At 10 hours a week M1 ends in the week of Aug 9, 2027; at 15 hours,
   in the week of May 17, 2027. The code-reviewer's bottom-up estimate of the core is 229 hours.

### Background: how the M1 count grew

The budget in `KICKOFF.md` is six weeks at 10 to 15 hours: 60 to 90 hours.

| Count | Source | M1 hours |
| --- | --- | --- |
| Calendar, by slice: architecture, engine, report, signing and CLI edge 81; security 27; release 24; check families core 62 | 00-overview.md, first calendar | about 194 |
| Calendar plus the probe facade and the review fixes | 02-engine-design.md, "M1 hours and cut list" | about 248 (19 weeks at 13 h) |
| Check families only: M1 tier 79 plus 6 of reviews; M1-late tier 72, kept in M1 as `core: no` | 03-check-catalog.md, "Capacity and cut order" | 157 |
| Merged backlog, first draft | 11-backlog.md before review | 571 (438 core) |
| Merged backlog after the code-reviewer and qa-engineer reviews | 11-backlog.md | 365 (306 core) |
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

### 1. Starting M1 before the M0 gates

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
to `docs/plan/` (09), and the repo is not created.

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
