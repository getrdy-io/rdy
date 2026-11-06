# Rdy Product Plan

Oct 19, 2026 · Rdy

## Summary

Build Rdy (command: rdy, site: getrdy.io): a vendor-neutral readiness and diagnostics tool for software that ships into customer environments (on-prem, BYOC, air-gapped, GPU clusters). The customer runs one signed Rust binary. It checks their environment against the vendor's requirements, scores readiness with fixes, and packages a redacted diagnostics bundle. The vendor's sales engineers and support team see the result in a portal before install day.

**Why now.** Enterprises are pulling SaaS into their own clouds. A CISO at a $100B+ revenue firm told [The Stack](https://www.thestack.technology/bring-your-own-cloud-how-it-works/) in 2026 that BYOC is now their preferred deployment model and most of their SaaS partners have it on the roadmap. A BYOC deployment platform raised $16.5M to help vendors deploy into customer accounts, and most of its customers are early-stage AI companies. Every one of those vendors hits the same wall. As the incumbent Kubernetes-only preflight and support-bundle vendor puts it, installs fail because the environment isn't ready, not because the product is broken.

**The gap.** The only established tooling is the incumbent vendor's open-source preflight and support-bundle tool: a kubectl plugin, Kubernetes-first, built for that vendor's own platform. Everyone else writes bash scripts (a code host, a container-security vendor, an enterprise-software vendor and a security-analytics vendor each ship their own homegrown support-bundle tool). Nothing covers VMs, cloud accounts, GPUs and Kubernetes in one signed binary with a sales-facing workflow.

**Revenue thesis.** The incumbent's median buyer pays about $87k a year (third-party pricing data) for its distribution platform. Rdy sells one focused piece of that job at $6k to $24k a year, with enterprise deals above $50k. 300 paying vendors at a $15k average is $4.5M ARR. A free open-source CLI drives adoption. The portal is the paid product.

**One caveat.** Nothing in software is fully non-existent. The real claim is that nobody sells this as a standalone product, and the two closest players (the incumbent preflight vendor and a BYOC deployment platform) are busy elsewhere. The Risks section has the validation gates to prove demand before the heavy build. Option B, a customer-side BYOC control tower, is laid out near the end as the phase-two company built on the same agent. Three other options (model delivery, document accessibility, CNC verification) were researched and dropped on 2026-10-20; A and B are the plan.

## The gap and the evidence

The deployment-into-customer-environments market is growing fast, but readiness tooling has not kept up. Four signals from the research:

1. **BYOC is a buyer-driven trend, not a vendor fad.** Two BYOC platform vendors both published 2026 BYOC guides. The driver is compliance, data residency, and committed cloud spend that CFOs want to burn down. A US government agency compared it to the Kubernetes mandate of a decade ago (as reported by a BYOC deployment platform).
2. **Readiness checks are proven to work.** The incumbent preflight vendor found vendors using its preflight checks get customers running 7x faster than market average (2022 study, vendor-reported). Their advice to vendors: build a catalog of checks from past install failures (CPU, RAM, ports, proxies, GPUs, antivirus conflicts) and make customers run it before install day.
3. **The one open-source tool is Kubernetes-bound.** The incumbent tool is a kubectl plugin. Its host collectors cannot run on remote nodes, so multi-node VM installs mean one bundle per machine, by hand.
4. **Everyone else rolls their own.** A code host ([GitHub Enterprise Server](https://docs.github.com/en/enterprise-server@3.20/admin/monitoring-and-managing-your-instance/monitoring-your-instance/about-support-bundles)) and container-security, enterprise-software and security-analytics vendors each maintain a bespoke support-bundle tool. That is engineering time every vendor spends on the same problem. [NVIDIA NIM](https://docs.nvidia.com/nim/large-language-models/2.0.13/index.html) alone documents Kubernetes, CSP, air-gap, multi-node and vGPU deployments, with GPU OOM and OpenShift admission failures as top troubleshooting topics.

| Player | What it does | Where it stops |
| --- | --- | --- |
| The incumbent Kubernetes-only preflight and support-bundle tool | Open-source preflights and support bundles, YAML specs, redactors, analyzers | Kubernetes-first kubectl plugin; no cloud-account or GPU checks; no hosted results or sales workflow outside its vendor's platform |
| The incumbent's distribution platform | Full on-prem distribution: installers, licensing, portal | Median $87k/yr; you adopt the whole platform to get the checks |
| A BYOC deployment platform that raised $16.5M | BYOC deployment platform; runner and actions for in-account health checks | Checks only exist inside its own deployments; nothing pre-sale, nothing for VMs or air-gap |
| A second BYOC platform | BYOC platform with an egress-only vendor access connector | Deployment and access, not readiness; tied to its own packaging |
| Homegrown scripts | Bash, PowerShell, per-vendor binaries | No signing, inconsistent redaction, no shared results, rebuilt by every vendor |
| **Rdy** | Signed single binary, any target (VM, K8s, cloud account, GPU, air-gap), readiness score, redacted bundle, SE and support portal | New entrant; must earn trust running inside customer environments |

The hole is the intersection: vendor-neutral, any deployment target, pre-sale as well as post-sale, delivered as a product rather than a platform feature.

## Product definition

Rdy answers one question for software vendors: is this customer's environment ready for our product, and if not, what exactly is wrong? Three parts:

1. **`rdy` CLI (open source, Rust).** One static binary for Linux (x86\_64, arm64), macOS and Windows. Runs a vendor-signed spec of checks. Prints a pass/warn/block report with remediation steps, writes an HTML and JSON report, and optionally builds a redacted diagnostics bundle (`.tar.zst`). Works fully offline for air-gapped sites; the customer carries the report file out.
2. **Rdy Cloud (paid portal).** Vendors author and version specs, generate a share link per prospect or customer, and see results as they land. Readiness score per account, failure trends across all accounts, bundle viewer with analyzers, Slack and CRM hooks. Self-hosted option for vendors who need it.
3. **Embed SDK (later).** A C-ABI and WASM build of the check engine so vendors can brand the CLI or run checks inside their own installer.

**Check families at launch**

Each family names the milestone it ships in. Launch copy claims only what ships by the end of M3.

- Host (M1): CPU, RAM, disk, kernel version, cgroups, time sync, open ports, SELinux and AppArmor state, antivirus agents known to break containers.
- Network (M1): egress to required endpoints through the customer's proxy, DNS, TLS interception detection, MTU, bandwidth sample.
- Kubernetes (M1): version, storage classes, RBAC for the install identity, admission policies, node resources. Device plugins and VRAM per node ship in M4 with the GPU family, as `k8s.device_plugins`.
- Bundle (M2): the redacted diagnostics bundle.
- Cloud account (M3): IAM simulation, with EC2 dry-run as an opt-in fallback, service quotas, region availability, VPC and subnet capacity (AWS first, then GCP and Azure). Check ids are `aws.*`; `gcp.*` and `azure.*` are reserved.
- GPU and AI (M4): driver and CUDA versions, NCCL and fabric sanity, model-download egress.
- Data stores (M4): reachability and version for Postgres, Redis, Kafka, S3-compatible storage, as a feature-gated module of `rdy-checks-net`.
- Custom: `custom.file` (M2, in `rdy-checks-host`) and `custom.exec` (M4, in `rdy-engine`), a script check with a declared expected output, sandboxed (ADR 0005).

**Example spec** (design sample, not runnable in M1: `bundle:` is M2, `aws.iam` M3 and `gpu.cuda` M4. The runnable M1 example is `examples/specs/acme-platform.yaml`.)

```yaml
apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme-platform
  version: ">=4.2"
checks:
  - id: host.memory
    min: 32Gi            # a nominal band applies by default: a "32 GB" VM that shows 31.3 GiB passes with a note
    severity: block
    fix: "Add RAM or choose a larger node class."
  - id: net.egress
    endpoints: ["registry.acme.example:443", "license.acme.example:443"]
    via_proxy: auto
    severity: block
  - id: k8s.storageclass
    access_modes: ["ReadWriteOnce"]
    severity: warn
  - id: gpu.cuda
    built_with: "12.4"
    source: driver       # driver | toolkit
    compat: minor        # minor | strict | forward
    severity: block
  - id: aws.iam
    simulate: ["eks:DescribeCluster", "ec2:CreateSecurityGroup"]   # IAM simulation; needs iam:SimulatePrincipalPolicy
    severity: block
bundle:
  collect: ["journal:7d", "k8s:events", "file:/etc/acme/*.yaml"]
  redact: ["aws_keys", "bearer_tokens", "emails"]
```

**How a POC flows**

1. The SE picks a spec and sends it to the prospect. In M1 the prospect downloads the pinned release `install.sh`, then runs `"$HOME/.local/bin/rdy" run acme-platform.yaml`. From M2 the SE sends a link: `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh && "$HOME/.local/bin/rdy" run acme-platform`, with the token from `RDY_TOKEN` or a prompt, never on the command line. Root shells use `sh -s -- --allow-root`.
2. The prospect runs it in the target environment. Nothing leaves the box unless they approve the upload.
3. The SE sees a readiness score and the exact blockers within minutes, before the kickoff call.
4. The prospect fixes the blockers using the remediation text. Reruns show green.
5. Install day works the first time. Support later asks for a bundle with the same tool.

**Who buys**

- Primary: VP or Director of Sales Engineering at B2B infrastructure, data, security and AI platform vendors that offer self-hosted or BYOC deployment. Pain: POCs stall for weeks on environment issues, SE hours burn on debugging the customer's setup.
- Secondary: Head of Support or Customer Success at the same vendors. Pain: slow, incomplete diagnostic collection, data sensitivity, bespoke tooling to maintain.
- Champion: the senior SE who has written the bash version three times.

**Why Rust is a selling point here, not just a build choice**

- The binary runs with elevated privileges inside the customer's environment. Memory safety and a small dependency surface are things security reviewers ask about.
- A single static binary with no runtime (no Python, no JVM, no kubectl) installs in air-gapped and locked-down environments.
- Low footprint matters on constrained nodes and on edge hardware.

## Business model and revenue

Open-core: the CLI is free and Apache-2.0, the portal is paid per vendor, not per customer environment. Vendors pay for workflow, history, and analytics, never for the right to run a check.

| Tier | Price | Includes | Who it is for |
| --- | --- | --- | --- |
| Free | $0 | Open-source CLI, 1 spec, 25 portal runs/month, share links, 7-day retention | Solo SEs trying it on one deal |
| Team | $499/month, billed yearly ($5,988) | Unlimited runs, 5 specs, 10 seats, bundle viewer, Slack alerts, 90-day retention | Vendors with 3 to 15 SEs |
| Business | $1,999/month, billed yearly ($23,988) | Unlimited specs and seats, SSO, custom-branded CLI, Salesforce and HubSpot sync, failure analytics, API, 1-year retention | Vendors with 15 to 60 SEs and a support org |
| Enterprise | From $50,000/year | Self-hosted or air-gapped portal, Embed SDK, SLA, security questionnaire support, dedicated onboarding | Large vendors, regulated buyers, platform partners |

**ARR scenarios at 36 months** (assumptions, not forecasts; a solo founder with a day job lands near Conservative unless a cofounder or funding changes the pace)

| Scenario | Paying vendors | Mix (Team / Business / Enterprise) | ARR |
| --- | --- | --- | --- |
| Conservative | 60 | 45 / 12 / 3 | $738k |
| Base | 200 | 140 / 50 / 10 | $2.6M |
| Upside | 500 | 330 / 140 / 30 | $7.1M |

**Why the numbers hold up**

- Buyers already pay $76k to $796k a year (third-party pricing data) for the incumbent platform. A $6k to $24k line item for the readiness piece is an easy add, or a cheap partial replacement for vendors who only wanted the checks.
- Investors are funding the category: a BYOC deployment platform raised $16.5M. That is the same buyer set Rdy targets.
- Gross margin should exceed 85%. Results are small JSON documents. Bundles are the only real storage cost and can be capped per tier.
- Every prospect who runs the CLI sees the Rdy name. The product markets itself to the next vendor through the customer's own engineers.

**Extra revenue levers once the base works**

- Spec-authoring services for the first ten customers ($5k each). Pays the bills early and seeds the check catalog.
- Bundle storage overage and longer retention.
- A yearly "State of Enterprise Installs" benchmark report built from anonymized failure data, sold as a sponsorship vehicle.
- The phase-two product: a customer-side control tower for enterprises that run dozens of vendor data planes in their own clouds (see Risks and alternatives).

## Rust build plan

Ship 0.1.0, the design-partner build, after 25 weeks and all of M1 after 30 weeks of part-time work (13 hours a week, `docs/plan/11-backlog.md`), then add the portal. Everything below assumes 10 to 15 hours a week with an AI coding agent doing most of the typing. Full-time would roughly halve the dates. Weekly builds are `0.1.0-alpha.N` pre-releases until 0.1.0; crates version independently; the docs keep one version per stable minor (ADR 0007, `docs/plan/06-release-and-distribution.md`).

**Architecture**

Two workspaces. `rdy-cloud` depends on `rdy-spec` and `rdy-engine` from crates.io, never by path (ADR 0007), so a result produced offline on an air-gapped box opens in the portal unchanged.

Specs flow from the vendor to the customer. Results flow back only when the customer approves the upload; air-gapped sites carry the report file out by hand.

| Crate | Purpose | Key dependencies |
| --- | --- | --- |
| `rdy-spec` | Schema, wire types for specs, results and the bundle manifest, YAML parsing, validation, signature verification | serde, serde-saphyr, schemars, minisign-verify (verify), minisign (sign) |
| `rdy-engine` | Check trait, scheduler, probe facade, privilege negotiation, redactor, HTML and JSON reports | tokio, tracing, askama |
| `rdy-checks-host` | CPU, memory, disk, kernel, cgroups, ports, security agents | sysinfo (no default features), rustix, winreg, plist, toml |
| `rdy-checks-net` | Egress via proxy, DNS, TLS interception, MTU | probe facade over tokio-rustls and hyper on ring, rustls-native-certs, webpki-roots, x509-parser, hickory-resolver (default features off) |
| `rdy-checks-k8s` | Version, storage classes, RBAC, admission, node resources; `k8s.device_plugins` and VRAM per node in M4 | kube, k8s-openapi |
| `rdy-checks-cloud` | IAM simulation, quotas, regions (AWS first) | aws-sdk-iam, aws-sdk-servicequotas, aws-sdk-ec2; REST for GCP and Azure |
| `rdy-checks-gpu` | Driver, CUDA, VRAM | `nvidia-smi` and `/proc/driver/nvidia` (no `nvml-wrapper`: a static musl binary cannot `dlopen`, ADR 0006) |
| `rdy-bundle` | Collectors, tar+zstd, manifest; reuses `rdy_engine::redact` | tar, zstd, regex, aho-corasick |
| `rdy` (directory `crates/rdy-cli`) | The `rdy` binary | clap, indicatif; signed self-update in M3, trust model by ADR |
| `rdy-server` (in `rdy-cloud`) | Portal API, auth, storage, billing webhooks | axum, sqlx with Postgres, tower, jsonwebtoken, object\_store |
| `rdy-ffi`, `rdy-wasm` (public repo, M5) | Embed SDK | cbindgen, wasm-bindgen |

Portal frontend: SvelteKit in TypeScript against the Rust API. It is the fastest path to a good UI. Leptos is the all-Rust option if you want the story to be pure Rust; it will cost you iteration speed early on.

**Design rules that matter for this product**

- Least privilege. Each check declares what it needs (root, kube context, cloud credentials). The CLI runs what it can and reports what it could not, instead of failing or asking for `sudo` up front.
- Nothing leaves the machine by default. Upload is an explicit flag or a prompt. Redaction runs before anything is written to disk.
- Specs are signed by the vendor's key. The CLI refuses unsigned specs unless `--allow-unsigned` is set, and says so loudly. It always refuses a spec whose signature fails, with or without the flag.
- Offline first. Every command works without network; the portal is additive.
- One binary, no runtime. Static musl builds on Linux, no OpenSSL dependency (rustls everywhere).

**Release engineering**

- `dist` (configured in `dist-workspace.toml`) for cross-platform releases, built on native runners, musl targets for Linux. `cargo-zigbuild` is only the fallback for local cross builds (ADR 0006).
- Binaries and checksums are signed with Sigstore cosign; the install script verifies checksums and signatures. Specs are signed by the vendor's ed25519 key in minisign format (ADR 0002).
- SBOM on every release via `cargo-cyclonedx`; `cargo-audit` and `cargo-deny` in CI; `cargo-auditable` so the binary carries its own dependency list.
- Distribution: install script, GitHub Releases, Homebrew tap, winget, then apt and yum repos for the Enterprise tier.
- Independent security audit before the Enterprise tier goes on sale. Budget $15k to $25k.

**Milestones**

The private beta gates M2 and the public launch gates M4. Dates move if the validation gates in the Risks section are not met on time.

The exit test is the business outcome. The engineering done test is what CI and a ticket can check (`docs/plan/00-overview.md`).

| Milestone | Scope | Exit test | Engineering done |
| --- | --- | --- | --- |
| M0 Validate | 15 interviews with SE and support leaders, 5 design partners signed, landing page waitlist live | 5 vendors agree to run the alpha on a real POC | Not engineering. |
| M1 CLI alpha | Spec format, host, network and Kubernetes checks, HTML and JSON report, signed specs, minimal Markdown docs (install, first run, exit codes, unsigned specs, sign and verify, generated reference) | One design partner catches a real install blocker with it | Fixture envs exit 0, 1 and 2 on all five targets and write both reports; unsigned and tampered specs exit 64; every 0.1.0 gate security ticket is closed. |
| M2 Portal MVP | Share links, results dashboard, redacted bundles, bundle viewer, Slack alerts | Design partners run it on 20 prospect environments | `rdy run <product>` fetches a signed spec with the token never on argv; the redaction golden suite passes; nothing uploads without the flag or a yes. |
| M3 Launch | AWS account checks, Stripe billing, hosted docs site, public open-source launch, Team tier on sale | First 10 paying vendors | AWS checks pass on recorded fixtures; the docs site builds its reference from the schema; `rdy-spec` and `rdy-engine` are 1.0. |
| M4 Business tier | GPU and AI checks, CRM sync, analytics, custom-branded CLI, SSO | First Business-tier deal | GPU checks pass on fixtures and one real node; data store checks ship; `custom.exec` runs only with hash-bound consent. |
| M5 Enterprise | Embed SDK, self-hosted portal, air-gapped licensing, security audit | First $50k+ contract | C-ABI and WASM builds pass the same golden tests; audit findings closed. |

**Build order inside M1**

Builds before signing lands are tagged `0.1.0-alpha.N`, run specs only with `--allow-unsigned`, and are not given to design partners for real POCs.

1. Workspace, CI, release pipeline. Boring, do it first so every later week ships a binary.
2. Spec parser and the result model. Write the JSON schema and generate docs from it.
3. Host checks and the HTML report. This is the demo.
4. Network checks. Proxy and TLS interception are where most real POCs fail.
5. Kubernetes checks.
6. Spec signing and the `rdy verify` command.

## Marketing strategy

Sell to sales engineering leaders first. They feel the pain weekly, control a tooling budget, and talk to each other in one place. Support leaders come second through the same product.

**Positioning**

For sales engineering and support teams at vendors who ship into customer environments, Rdy is the readiness check that catches install blockers before install day. Unlike the incumbent Kubernetes-only preflight tool (tied to its vendor's platform) or homegrown scripts, Rdy runs anywhere as one signed binary and shows results to both sides of the deal.

Tagline to test first: **Install day should be boring.**

**Ideal customer profile**

- B2B software vendors with a self-hosted, BYOC or agent-based deployment option. Categories: data platforms, observability, security, developer tools, AI inference and agent platforms.
- 5 to 60 sales engineers. Series A through public. Below 5 SEs the budget is thin; above 60 they often have a platform team that wants to build it.
- Trigger events: a new BYOC offering, a GPU-heavy product, a support org hiring to keep up with install tickets, a renewal of the incumbent distribution platform.

**Message by persona**

| Persona | Pain they say out loud | Rdy message |
| --- | --- | --- |
| VP Sales Engineering | POCs slip weeks on environment issues; SEs debug customer networks instead of selling | Cut POC time. Know the environment is ready before kickoff. |
| Head of Support | Logs arrive by email, half missing, full of secrets | One command gives you a redacted bundle. No more back and forth. |
| Customer security reviewer | What is this binary doing on our boxes? | Signed Rust binary, open source, redaction before write, nothing uploaded without approval. |
| Senior SE (champion) | I wrote this script three times at three companies | Stop rewriting it. Point us at your checklist. |

**Channels**

| Channel | Play | Cost | 12-month target |
| --- | --- | --- | --- |
| Open-source launch | Show HN, r/devops, r/rust, r/kubernetes, lobste.rs. Angle: the preflight problem, solved in one Rust binary | Time | 3,000 GitHub stars, 20,000 CLI installs |
| [PreSales Collective](https://www.presalescollective.com/community-overview) | 50,000+ member Slack, community roundtables, regional meetups, Sol/Con. Give a talk on POC readiness, run a roundtable, sponsor one event | $0 to $5k | 500 waitlist signups, 25 design-partner conversations |
| Founder-led content | Weekly LinkedIn post on a real POC failure pattern; monthly blog teardown; yearly "State of Enterprise Installs" report from anonymized data | Time | 5,000 followers inside the ICP |
| Warm network | Direct outreach to SE leaders you already know at DevOps, observability, data and security vendors | Time | 5 design partners, 3 case studies |
| Ecosystem partners | BYOC deployment platforms, Rancher, OpenShift (named targets are in a private note outside the repo). Rdy is the pre-flight for their deployments, not a competitor | Time | 3 listed integrations, 1 co-marketing webinar |
| Built-in loop | Every prospect who runs the CLI sees the brand and a "Use Rdy for your product" link in the report | Built-in | 10% of paying vendors sourced from a prospect-side run |
| Outbound (after launch) | Build a list of vendors whose pricing page says self-hosted or BYOC; sequence SE leaders with a free readiness spec for their product | $200/month tooling | 100 targeted sequences a month, 5% reply rate |

**Launch sequence**

1. Weeks 1 to 5 (M0): waitlist page live, 15 interviews, start the weekly LinkedIn cadence with stories from interviews.
2. Private beta (M2): 5 design partners on real POCs. Write the three case studies as they happen, not after.
3. Public launch week (end of M3): Show HN on Tuesday, PreSales Collective post and roundtable the same week, partner announcements, five days of short posts showing one check family per day.
4. After launch: one visible feature drop a month, one partner webinar a quarter, the benchmark report once a year.

**Metrics that matter**

- Adoption: CLI installs, specs created, runs per vendor per month.
- Conversion: waitlist to signup, free to paid (target 5%), time from first run to first paid plan.
- Value: blockers caught per 100 runs, days saved per POC (ask design partners to measure it).
- Money: ARR, net revenue retention, Enterprise pipeline.

## Website plan

The site has one job at each stage: collect a waitlist in M0, convert design partners in M2, and sell the Team tier self-serve from M3. Build it in a weekend with a static generator and grow it, never a rebuild.

**Stack**

- Marketing site and docs: Astro with Tailwind, docs via Starlight. Static, fast, cheap. Hosted on Cloudflare Pages.
- Domain: `getrdy.io` (bought 2026-10-20). The command is `rdy`; the site, portal and docs live on getrdy.io, the install script at `getrdy.io/install`, docs at `docs.getrdy.io`. Add `getrdy.dev` as a redirect if it opens up. Naming history: the old working name was dropped after the trademark search turned up an existing LLC (a Minneapolis software consultancy with 14 years of use) and a live registration of the same mark in class 9. The old name is not written anywhere in this repo. Still to run: a USPTO export for RDY, READY and REDY before filing.
- App: `app.<domain>`, SvelteKit frontend talking to the Rust API from the build plan.
- Billing: Stripe Checkout and Customer Portal. Yearly plans only at first.
- Analytics: Plausible. CRM: HubSpot free tier. Email: Resend for transactional, a simple newsletter tool for the launch list.
- Install endpoint: `https://getrdy.io/install`, served with a 200 by a Worker route (never a redirect), from M2. The script verifies checksums and signatures; GitHub Releases hosts the binaries.

**Pages**

| Page | Purpose | Key element |
| --- | --- | --- |
| Home | Explain the product in 10 seconds and get a run started | Hero, animated terminal running a check, three-step flow, logos, pricing teaser |
| Product | Walk through CLI, portal and SDK | Screenshots of a readiness report and the portal dashboard |
| Solutions: Sales Engineering | Speak to the primary buyer | POC timeline before and after, case study quote |
| Solutions: Support | Speak to the secondary buyer | Bundle viewer screenshot, redaction demo |
| Solutions: BYOC and AI vendors | Catch the trend searches | GPU and cloud-account check examples |
| Pricing | Convert self-serve | Four tiers, yearly pricing, FAQ, "book a demo" for Enterprise |
| Docs | Make the CLI usable without talking to you | Install, first run, spec reference, check catalog |
| Open source | Build trust with security reviewers | License, repo link, signing and SBOM details, security policy |
| Compare | Win the comparison searches | Rdy vs the incumbent Kubernetes-only preflight tool, Rdy vs homegrown scripts |
| Blog and changelog | SEO and proof of momentum | Monthly posts, every release noted |
| Trust | Pass procurement | Security practices, data handling, roadmap to SOC 2 |

**Home page copy outline**

- Headline: Install day should be boring.
- Subhead: Rdy checks a customer's environment against your requirements before install day. One signed binary. Any target. Results your SEs and support team can see.
- Primary button: Run your first check. Secondary: Read the docs.
- Terminal demo: `rdy run acme-platform.yaml` producing a report with two blocks, one warning and the fixes, ending in NOT READY, then a rerun ending in READY.
- Three steps: Write the spec. Send the link. Fix blockers before kickoff.
- Proof row: design partner logos, then the "7x faster installs with preflight checks" industry stat with its source (2022 study, vendor-reported).
- Security strip: open source, Rust, signed releases, redaction before write, no upload by default.
- Pricing teaser with a link to the full page.
- Footer: docs, GitHub, changelog, security, contact.

**Conversion flow**

1. M0: home page with waitlist form only. Ask one question on signup: what do you ship into customer environments?
2. M2: waitlist gets beta invites in batches of 10. Beta users land on a portal onboarding that creates their first spec from a template in under five minutes.
3. M3: self-serve signup, free tier, Stripe for Team. Pricing page gets a "start free" and a "book a demo" path.
4. Every report the CLI renders links back to the site. The link carries only the public product name. Clicks are counted by site analytics on getrdy.io, never by the CLI. The trust page says so.

**SEO targets**

- Head terms: preflight checks, support bundle, deployment readiness, customer environment validation.
- Trend terms: BYOC deployment, bring your own cloud readiness, air-gapped installation checklist, GPU deployment prerequisites.
- Comparison terms: alternative-to searches for the incumbent preflight tool (exact terms are in a private note outside the repo).
- Long tail from the docs: one page per check family, which doubles as a reference for people searching how to verify egress through a proxy or check CUDA versions on Kubernetes.

## Risks, validation gates, and alternatives

The biggest risk is not competition. It is spending six months on Rust before five vendors have said they will pay. The gates below were meant to come before M1. On 2026-10-28 the founder chose to start M1 now and finish the gates in parallel (`docs/plan/13-plan-corrections.md`, Decisions made 2), so the gates are now a checkpoint, not a precondition.

**Risks**

| Risk | Why it is real | Mitigation |
| --- | --- | --- |
| The incumbent preflight vendor or a BYOC deployment platform ships the same thing | Both own an adjacent workflow and could add it | Stay vendor-neutral and any-target, which neither can do without hurting their platform story. Partner with BYOC deployment platforms early. Move fast on cloud-account and GPU checks. |
| Trust: a new binary with root in a customer's environment | Security reviewers will push back on day one | Open source, signed releases, SBOM, least privilege, no upload by default, independent audit before Enterprise. |
| No competitor can mean no market | Vendors may be fine with their bash scripts | The validation gates below. Charge from the first paying tier; free users are not proof. |
| Founder capacity | 10 to 15 hours a week next to a full-time job | MVP is CLI plus report plus share link, nothing more. Lean on an AI coding agent. Find a GTM-side cofounder by M3 if it is working. |
| Employment agreement | IP assignment and moonlighting clauses are standard | Read the agreement before writing code. Personal hardware and accounts only. This product does not compete with CI/CD or feature-flag tooling, which keeps the conflict risk low. |
| Enterprise sales cycles | $50k+ deals take 6 to 9 months | Team tier is self-serve and pays the bills. Enterprise is M5, not M1. |
| Cloud breadth | GCP and Azure Rust SDKs lag AWS | AWS first. REST clients for the rest. Accept community-contributed check families. |

**Validation gates (finish in parallel with M1, by the Nov 20, 2026 checkpoint)**

- [ ] 15 interviews with SE and support leaders completed
- [ ] At least 10 of 15 say environment readiness costs them real POC time, with a number
- [ ] 5 design partners commit in writing to run the alpha on a live POC
- [ ] 3 of those 5 say they would pay $499 a month for the portal
- [ ] Nobody in the interviews names a product that already does this across VM, Kubernetes, cloud account and GPU

Kill rule: fewer than 3 design partners after 30 outreach attempts means the pain is not sharp enough. Pivot to the phase-two product below or drop it.

**Alternatives considered**

| Idea | Why it lost (for now) |
| --- | --- |
| Customer-side BYOC control tower: inventory and govern every vendor data plane running in an enterprise's cloud (IAM, egress, update cadence, audit evidence) | Most unique and the biggest ACV, but a top-down enterprise security sale with SOC 2 and long cycles. Keep it as phase two. The same Rust agent powers it. |
| Demo environment control plane for SE teams | Real pain you know well, but demo-environment vendors already own the demo budget. Rust gives no edge. |
| Telemetry cost firewall | Rust fits, but established observability-pipeline vendors are already there. |
| AI agent sandbox and governance | Dozens of funded startups since 2025. No gap. |
| Rust-native observability backend | several open-source observability backends already did it. |

## Next 30 days

M1 started on 2026-10-28, ahead of the gates (Decisions made 2 in `docs/plan/13-plan-corrections.md`). The next month still holds interviews and a waitlist page next to the M1 build.

- [ ] Read your employment agreement for IP and moonlighting terms
- [ ] Name picked (rdy) and getrdy.io bought. Still to do: USPTO export for RDY, READY and REDY; crates.io name; Wisconsin LLC name check
- [ ] Write the 10-question interview script (current process, time lost per POC, tools tried, willingness to pay)
- [ ] List 30 SE and support leaders you can reach warm; book 15 calls
- [ ] Ship the waitlist landing page on Astro and Cloudflare Pages
- [ ] Join the PreSales Collective Slack and start posting one install-failure story a week on LinkedIn
- [ ] Build a throwaway prototype in Rust (host and network checks, text report) only to demo on calls; budget two weekends
- [ ] Draft the first spec with a design partner's real prerequisites list
- [ ] Decide go or no-go against the validation gates

Nov 20, 2026 is the go or no-go checkpoint.

## Name, domain and repositories

The product is Rdy. The command is `rdy`. The site is getrdy.io, bought 2026-10-20. The old working name was dropped the same day after the trademark search turned up an existing LLC (a Minneapolis software consultancy with 14 years of use) plus a live registration of the same mark in class 9.

| Asset | Value | Status |
| --- | --- | --- |
| Product name and legal owner | Rdy. The legal entity that owns the code, the copyright and the marks is Apostolic Path LLC | Founder decision 2026-10-30. Trademark search pending |
| CLI command | `rdy` | Decided |
| Primary domain | getrdy.io | Owned |
| Install script | M1: the pinned release `install.sh`. From M2: `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install \| sh` | To build |
| Docs | docs.getrdy.io | To build |
| Portal | app.getrdy.io | To build |
| Defensive domains | getrdy.dev if it opens; skip .ai, .sg and $200 aftermarket names | Watch |
| GitHub org | getrdy-io | Owned |
| Public repo | `github.com/getrdy-io/rdy`, Apache-2.0: CLI, spec, engine, checks, bundle, install script, docs | To create |
| Private repo | `github.com/getrdy-io/rdy-cloud`: portal API, analyzers, web app, deploy | To create |
| crates.io | `rdy`, `rdy-spec`, `rdy-engine`, `rdy-bundle` and the `rdy-checks-*` crates; publish 0.0.1 placeholders now | Check and reserve |
| Trademark | USPTO export for RDY, READY and REDY before filing an intent-to-use application in classes 9 and 42 | To run |

**Repo split rule.** `rdy-cloud` depends on `rdy-spec` and `rdy-engine` as published crates from crates.io, never by path. The public crates stay the source of truth for the spec and result formats, so a report produced offline always opens in the portal. The upload client and the HTML report renderer live in the public CLI so security reviewers can read exactly what leaves a customer's box.

**Public repo layout**

```text
rdy/
  Cargo.toml            workspace
  crates/
    rdy-spec/           schema, wire types for specs, results and the bundle manifest, YAML parsing, signature verification
    rdy-engine/         check trait, scheduler, probe facade, privilege negotiation, redactor, HTML and JSON reports
    rdy-checks-host/
    rdy-checks-net/
    rdy-checks-k8s/
    rdy-checks-cloud/
    rdy-checks-gpu/
    rdy-bundle/         collectors, tar+zstd, manifest; reuses rdy_engine::redact
    rdy-cli/            the rdy binary, including the opt-in upload client
  install.sh            served at getrdy.io/install
  docs/                 Starlight site (M3), deployed to docs.getrdy.io; only docs/src/content/docs/ is published, never docs/plan/ or docs/adr/
```

**Private repo layout**

```text
rdy-cloud/
  Cargo.toml            workspace
  crates/
    rdy-server/         axum API, auth, share links, storage, Stripe webhooks
    rdy-analyzers/      paid bundle analysis and cross-account failure trends
    tower-*/            Option B crates when phase two starts
  web/                  SvelteKit portal at app.getrdy.io
  site/                 Astro marketing site at getrdy.io
  deploy/
```

## Option B: customer-side BYOC control tower

Flip Rdy around and sell to the enterprise instead of the vendor. Every BYOC vendor now ships its own agent, IAM roles, egress paths and update cadence into the customer's cloud accounts, and nothing gives the customer's security team one view across all of them. Working name: Tower.

**The evidence**

- Vendors are shipping data planes into customer accounts at scale. [Pinecone](https://www.pinecone.io/blog/byoc/), [Zilliz](https://docs.zilliz.com/docs/byoc/byoc-intro), [StarTree](https://startree.ai/resources/byoc-beyond-the-checkbox/), [Braintrust](https://braintrust.dev/docs/admin/deployment/byoc), [Stigg](https://docs.stigg.io/documentation/high-availability-and-scale/byoc/networking-and-security), [Ververica](https://docs.ververica.com/docs/zero-trust-architecture) and [Restate](https://docs.restate.dev/byoc/security) all published BYOC security models in 2025 and 2026. Each one brings a runner, a scoped role, an egress-only tunnel and its own definition of least privilege.
- The customer is told to govern it themselves. Braintrust's docs say the customer [remains responsible](https://braintrust.dev/docs/admin/deployment/byoc) for IAM constraints, allowed regions, audit-log export and SIEM routing in the BYOC account. A BYOC platform vendor's buyer guide says enterprise BYOC requires visibility into both platform events and application activity.
- Standing vendor access is the known failure. A non-human identity research group maps it to NIST SP 800-207 and the OWASP NHI Top 10: continuous vendor reach breaks zero-trust assumptions, and the fix is short-lived, customer-approved access per event. A zero-trust access vendor frames every vendor in the stack as an extension of the customer's attack surface.
- The detection playbook exists but nobody packages it. A cloud security vendor's threat catalog tells defenders to track vendor-managed role usage against expected patterns; a cloud governance vendor lists third-party roles without an ExternalId and roles never decommissioned after a contract ends as top findings. Today that is CloudTrail queries and spreadsheets.

| What exists | What it does | Where it stops |
| --- | --- | --- |
| CSPM and CNAPP (cloud security posture vendors) | Finds misconfigured resources across accounts | Sees a role or a pod, not which vendor owns it or what was agreed at procurement |
| Non-human identity tools (NHI vendors) | Inventory and risk of service accounts and API keys | Identity-centric; no view of the data plane, its egress, its updates or drift from the contract |
| SaaS security posture (SSPM vendors) | Governs SaaS apps the vendor hosts | Built for the opposite deployment model |
| Vendor-side BYOC platforms (BYOC deployment platforms) | Help vendors deploy and operate | Serve the vendor; the customer gets whatever audit trail the vendor chooses to expose |
| Third-party risk management (TPRM vendors) | Questionnaires and contract evidence | Paper, not runtime truth |
| **Tower** | Per-vendor inventory of data planes, access ledger, permission drift, egress map, update log, offboarding, audit evidence packs | New entrant; needs SOC 2 and a reference customer before anyone signs |

**Product**

- Read-only collectors for AWS first (CloudTrail, IAM, Config, VPC flow logs, EKS and ECR), then Azure and GCP. Optional in-cluster agent for Kubernetes-hosted data planes. All Rust, all read-only, deployable inside the customer's own account.
- Vendor fingerprinting: match roles, trust policies, OIDC providers, image registries, tags and egress destinations to a maintained catalog of vendor account IDs and patterns. The catalog is the moat; it grows with every customer.
- Six views: Inventory (which vendors run what, where), Access ledger (every vendor session, standing vs just-in-time, who approved), Drift (what the role can do today vs what procurement agreed), Egress (where each data plane sends traffic), Updates (image digests and chart versions over time), Offboarding (vendor roles still trusted after a contract ended).
- Evidence packs: one click produces the SOC 2, ISO 27001, DORA or HIPAA artifact for the vendor-access control.
- A two-sided angle worth testing: a vendor can pay for a Tower-verified posture report to hand its own prospects, proving the zero-access claims on its BYOC page.

**Who buys**

- Economic buyer: CISO or VP Cloud Security at regulated enterprises (healthcare, financial services, logistics, public sector) with 10 or more BYOC or vendor-operated deployments.
- Champion: the cloud security architect who gets asked "what does this vendor's role actually have access to?" every quarter.
- Second buyer: third-party risk teams who need runtime evidence instead of questionnaires.

**Pricing and revenue**

| Tier | Price | Scope |
| --- | --- | --- |
| Pilot | $25,000 for 90 days | One cloud account family, up to 10 vendors, written findings |
| Standard | $90,000 a year | Up to 25 vendor deployments, AWS, evidence packs, SSO |
| Enterprise | $150,000 to $250,000 a year | Unlimited vendors, three clouds, in-cluster agent, air-gapped deployment, dedicated support |

Ten Standard customers is $900k ARR. Forty customers at a $120k blend is $4.8M. The sales cycle is six to twelve months, so year one is pilots and year two is contracts.

**Build notes (deltas from Rdy)**

- Reuse `rdy-checks-cloud` as the collector base. Add `tower-ingest` (aws-sdk-cloudtrail, aws-sdk-config, aws-sdk-iam, flow-log parsing), `tower-fingerprint` (the vendor catalog and matchers), `tower-graph` (vendor to role to resource to destination, in Postgres), and `tower-evidence` (report rendering).
- The product must itself deploy BYOC into the customer's account. Dogfood that from day one; it is the sales demo.
- SOC 2 Type II before the first Standard contract. Budget $40k to $60k and six months.
- This is not a solo, part-time build. Plan on a cofounder and a seed round, or treat it as the company Rdy grows into once Rdy funds it.

**Go-to-market**

- Start with the regulated enterprises you have worked inside. Healthcare and logistics security teams already know the vendor-access problem by name.
- Top-down: CISO briefings, cloud security conferences (fwd:cloudsec, AWS re:Inforce), analyst briefings once there is a reference customer.
- Bottom-up wedge: open-source the fingerprint catalog and a read-only CLI that prints "vendors in this account" from CloudTrail. Security engineers run it, the CISO buys the product.
- Partner angle: BYOC vendors want to prove their zero-access claims. Offer the verified posture report to the vendors in the evidence list above.

**Website deltas**

- Enterprise shape: trust page first, architecture page, "request a briefing" instead of self-serve, a one-page explainer a champion can forward to a CISO.
- The open-source CLI gets its own developer-style page with the install command.

**Risks and gates**

- A CSPM or CNAPP vendor adds vendor attribution as a feature. Mitigation: the fingerprint catalog, the contract-drift view and the evidence packs are workflow, not a scan.
- Long cycles and SOC 2 before revenue. Mitigation: paid pilots at $25k.
- Gates before building: 10 CISO or cloud-security-lead conversations, 6 confirm they cannot answer "which vendors have roles in our accounts" today, 3 agree to a paid pilot.

## Sources

All pages below were read on 2026-10-19. Pricing and funding figures are as reported by those pages and should be re-checked before any pitch.

- [The Stack: Bring your own cloud, how it works](https://www.thestack.technology/bring-your-own-cloud-how-it-works/)
- (source link withheld from the public repo: names a competitor)
- [GitHub Enterprise Server: About support bundles](https://docs.github.com/en/enterprise-server@3.20/admin/monitoring-and-managing-your-instance/monitoring-your-instance/about-support-bundles)
- (source link withheld from the public repo: names a competitor)
- [NVIDIA NIM for LLMs documentation](https://docs.nvidia.com/nim/large-language-models/2.0.13/index.html)
- [PreSales Collective: Community overview](https://www.presalescollective.com/community-overview)
- (source link withheld from the public repo: names a competitor)

Added for Option B and the dropped model-delivery option, read 2026-10-19:

- [Pinecone: BYOC with a zero-access model](https://www.pinecone.io/blog/byoc/)
- [Zilliz: BYOC intro](https://docs.zilliz.com/docs/byoc/byoc-intro)
- [StarTree: BYOC beyond the checkbox](https://startree.ai/resources/byoc-beyond-the-checkbox/)
- [Braintrust: BYOC deployment docs](https://braintrust.dev/docs/admin/deployment/byoc)
- [Stigg: BYOC networking and security](https://docs.stigg.io/documentation/high-availability-and-scale/byoc/networking-and-security)
- [Ververica: Zero trust BYOC architecture](https://docs.ververica.com/docs/zero-trust-architecture)
- [Restate: BYOC security](https://docs.restate.dev/byoc/security)
- (source link withheld from the public repo: names a competitor)
- [Lyzr: On-premise AI vs cloud AI 2026 (Broadcom figure)](https://www.lyzr.ai/blog/on-premise-ai-vs-cloud-ai/)
- [Taazaa: Practical guide to sovereign AI (McKinsey figures)](https://www.taazaa.com/blog/a-practical-guide-to-sovereign-ai-for-enterprises)
- (source link withheld from the public repo: names a competitor)
