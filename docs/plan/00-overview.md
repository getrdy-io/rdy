# Rdy plan overview

Owner: rust-architect. Date: 2026-10-27, revised 2026-10-28 after the security-reviewer and cli-ux
reviews in `docs/plan/reviews/`. Sources: `docs/plan/rdy-plan.md` (the plan), `CLAUDE.md`, `KICKOFF.md`.
Decisions referenced as ADR NNNN live in `docs/adr/`.

## Read this first: the M0 gate

The plan says "No Rust until the gates are met" and sets Nov 20, 2026 as the go or no-go date. The
gates: 15 interviews done, 10 of 15 report real POC time lost with a number, 5 design partners commit in
writing, 3 of those 5 would pay $499 a month, and nobody names an existing product that covers VM,
Kubernetes, cloud account and GPU. The plan also says to read the employment agreement before writing
code.

**This plan assumes the gates pass.** Its calendar starts M1 on Monday Nov 23, 2026. KICKOFF.md says to
start M1 as soon as the backlog is approved, which would mean building before Nov 20. That contradicts
the plan, so it is recorded below as a plan correction and as a decision for the founder:

- **Option 1 (recommended):** finish the planning pass now, build nothing but the throwaway demo
  prototype the plan allows (two weekends, separate scratch repo), start M1 on Nov 23 only on a "go".
- **Option 2:** start M1 now and treat the gate as a later checkpoint. Faster, but spends the hours the
  plan reserves for interviews, on a market that may fail the kill rule.

Two cheap, gate-safe steps from the plan's own 30-day list can happen now: reserving the crates.io
names with 0.0.1 placeholders, and creating the `getrdy-io/rdy` repo.

**Resolved 2026-10-28:** the founder approved the planning pass and started M1 now, which is option 2
(`13-plan-corrections.md`, Decisions made 2). The validation gates and the employment-agreement read run
in parallel.

## Phases

| Phase | What | Buyer | Where the code lives | Starts |
| --- | --- | --- | --- | --- |
| Option A: Rdy | Readiness CLI (open source) plus Rdy Cloud portal (paid) | VP Sales Engineering, Head of Support at software vendors | `rdy` (public), `rdy-cloud` (private) | M1, after the M0 gate |
| Option B: Tower | Customer-side control tower over every vendor data plane in an enterprise's cloud accounts | CISO, VP Cloud Security | `tower-*` crates in `rdy-cloud`; reuses `rdy-checks-cloud` | After Rdy funds it, and only after its own gates: 10 CISO conversations, 6 confirm the gap, 3 agree to a paid pilot |

Option B is not a solo part-time build (the plan says so). Nothing in M1 to M5 is designed for Tower
beyond keeping `rdy-checks-cloud` read-only and reusable.

## Milestones

The "Exit test" column is copied exactly from the plan's milestone table. Those are business outcomes CI
cannot check, so each milestone also gets an engineering "done" test (proposed, see Plan corrections).

| Milestone | Scope (plan) | Exit test (plan, exact) | Engineering done test (proposed) |
| --- | --- | --- | --- |
| M0 Validate | 15 interviews, 5 design partners signed, landing page waitlist live | 5 vendors agree to run the alpha on a real POC | Not engineering. Go or no-go on Nov 20, 2026. |
| M1 CLI alpha | Spec format, host, network and Kubernetes checks, HTML and JSON report, signed specs | One design partner catches a real install blocker with it | On all five targets, the replay fixture envs exit 0, 1 and 2 on the ready, warning and not-ready fixtures and write JSON and HTML into a new report directory; the shipped binary exits 0, 1 and 2 live in the real-binary smoke (net-only signed specs on loopback); an unsigned spec exits 64; a tampered spec exits 64 even with `--allow-unsigned`; every "0.1.0 gate" security ticket is closed. |
| M2 Portal MVP | Share links, results dashboard, redacted bundles, bundle viewer, Slack alerts | Design partners run it on 20 prospect environments | `rdy run <product>` with the token from `RDY_TOKEN`, `--token-file` or a prompt (never argv) fetches a signed spec from staging, the redaction golden suite passes, nothing uploads without the flag or a yes. |
| M3 Launch | AWS account checks, Stripe billing, docs, public open-source launch, Team tier on sale | First 10 paying vendors | AWS checks pass against recorded fixtures, the docs site builds its reference from the schema, `rdy-spec` and `rdy-engine` are 1.0. |
| M4 Business tier | GPU and AI checks, CRM sync, analytics, custom-branded CLI, SSO | First Business-tier deal | GPU checks pass on fixtures and one real node, branded report renders from data, data store checks ship, `custom.exec` runs only with hash-bound consent. |
| M5 Enterprise | Embed SDK, self-hosted portal, air-gapped licensing, security audit | First $50k+ contract | C-ABI and WASM builds of the engine pass the same golden tests; audit findings closed. |

## Public and private

| Public: `getrdy-io/rdy`, Apache-2.0 | Private: `getrdy-io/rdy-cloud` |
| --- | --- |
| `rdy` CLI, including the opt-in upload client and the HTML renderer (rule 7) | `rdy-server`: axum API, auth, share links, storage, Stripe webhooks |
| `rdy-spec` and `rdy-engine`: the `rdy/v1` contract, published to crates.io | `rdy-analyzers`: paid bundle analysis, cross-account failure trends |
| All check families and `rdy-bundle` (collectors, redactors) | SvelteKit portal at app.getrdy.io |
| `install.sh`, docs site (docs.getrdy.io), example specs, fixtures | Astro marketing site at getrdy.io, deploy config |
| Embed SDK crates `rdy-ffi`, `rdy-wasm` (M5, proposed public) | `tower-*` crates (Option B) |

The rule that matters: `rdy-cloud` depends on `rdy-spec` and `rdy-engine` from crates.io, never by
path (ADR 0007). The wire types for both specs and results live in `rdy-spec` (ADR 0012).

## M1 calendar

`docs/plan/11-backlog.md` is the source of truth for every M1 ticket, estimate and week. This section
copies its totals, calendar and cut list. If the two ever differ, 11 wins and this section is re-synced.

### Founder decision (2026-10-28)

M1 is extended, not cut. It is planned at its real size, at 13 founder hours a week. The calendar starts
on Monday Nov 23, 2026; the founder started M1 early, on 2026-10-28. Each document's cut list is kept
as a `core: no` marker so the founder can still trim. The 03 M1-late tier stays in M1, marked `core:
no`. A tagged binary ships every week.

- **M1 ends: Sunday Jun 20, 2027** (week 30, after the M1-009 re-cut from week 19). Revised after the
  code-reviewer and qa-engineer reviews of 11: duplicates and padding removed, the hosted docs site and
  launch content moved to M3, macOS and Windows data sources to M2, `k8s.device_plugins` to M4.
- **0.1.0, the build design partners get, ships in week 25 (May 10 to May 16, 2027),** with the
  alpha announcement. Core tickets come first, so this is also the core-only end date.
- At 10 hours a week: 0.1.0 in the week of Jun 28, 2027, M1 end in the week of Aug 9, 2027. At 15 hours
  a week: 0.1.0 in the week of Apr 19, 2027, M1 end in the week of May 17, 2027. The calendar has no
  slack; one ticket-free week every eight weeks adds three weeks.
- The code-reviewer's bottom-up estimate of the same core is 229 hours. 11 plans on its own figure.

### Totals

| | Tickets | Hours |
| --- | --- | --- |
| M1, all | 176 | 387 |
| M1, core | 147 | 325.5 |
| M1, `core: no` (the cut list) | 29 | 61.5 |

The KICKOFF budget, six weeks at 10 to 15 hours, is 60 to 90 hours. Core alone is more than three times
that. The earlier counts here (about 194 hours, then 248 in 02, then 571 in the first draft of 11) were
before the merges and moves of the 11 review. M2 to M5 totals are in 11.

### Week by week

Hours are founder hours including review of agent-written code. Ticket ids are 11's. The weeks of Dec 21
and Dec 28 run at half capacity.

| Week | Dates | Capacity | Hours | Build step | Tickets | Ships |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Nov 23 to Nov 29, 2026 | 13 | 14.5 | 1 Workspace, CI, release | M1-001 to M1-008 | `v0.1.0-alpha.0` (CI artefacts): `rdy version` built and tested on five CI legs and by dist in the release sandbox |
| 2 | Nov 30 to Dec 6, 2026 | 13 | 13 | 1 Workspace, CI, release; 2 Spec parser, result model, engine core | M1-009 to M1-013 | `v0.1.0-alpha.1`: first cosign-signed pre-release on GitHub Releases; domain and org settings check scripts in the repo |
| 3 | Dec 7 to Dec 13, 2026 | 13 | 13.5 | 1 Workspace, CI, release; 2 Spec parser, result model, engine core | M1-014 to M1-018 | `v0.1.0-alpha.2`: install.sh that checks the cosign signature, from the pinned release URL |
| 4 | Dec 14 to Dec 20, 2026 | 13 | 13 | 2 Spec parser, result model, engine core | M1-019 to M1-022 | `v0.1.0-alpha.3`: result model and generated JSON schemas; errors carry fix hints; `rdy version --json` |
| 5 | Dec 21 to Dec 27, 2026 | 6.5 | 6 | 2 Spec parser, result model, engine core | M1-023 to M1-025 | `v0.1.0-alpha.4`: same CLI; typed parameters for the M1 host, net and k8s check ids |
| 6 | Dec 28, 2026 to Jan 3, 2027 | 6.5 | 6.5 | 2 Spec parser, result model, engine core | M1-026 to M1-028 | `v0.1.0-alpha.5`: same CLI; semantic validation, parser property tests, root CI job |
| 7 | Jan 4 to Jan 10, 2027 | 13 | 12.5 | 2 Spec parser, result model, engine core | M1-029 to M1-032 | `v0.1.0-alpha.6`: `rdy spec lint <file>` with did-you-mean; usage errors exit 64 |
| 8 | Jan 11 to Jan 17, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core | M1-033 to M1-037 | `v0.1.0-alpha.7`: engine runs checks with timeouts and panic isolation; unknown ids SKIP |
| 9 | Jan 18 to Jan 24, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core | M1-038 to M1-042 | `v0.1.0-alpha.8`: commands only through the mediated runner; action log; privilege snapshot |
| 10 | Jan 25 to Jan 31, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core; 3 Host checks, HTML report | M1-043 to M1-048 | `v0.1.0-alpha.9`: run deadline and watchdog; facade file policy; redactor core |
| 11 | Feb 1 to Feb 7, 2027 | 13 | 13.5 | 2 Spec parser, result model, engine core; 3 Host checks, HTML report | M1-049 to M1-056 | `v0.1.0-alpha.10`: replay fixtures, fixture lint and golden helpers; logs redacted |
| 12 | Feb 8 to Feb 14, 2027 | 13 | 15 | 2 Spec parser, result model, engine core; 3 Host checks, HTML report | M1-057 to M1-062, M1-176 | `v0.1.0-alpha.11`: `rdy run <file> --allow-unsigned --json` writes a 0700 report dir, every check SKIP; `rdy run` exits 70 on a hang; Ctrl-C exits 70; `--no-network` |
| 13 | Feb 15 to Feb 21, 2027 | 13 | 14 | 3 Host checks, HTML report | M1-063 to M1-069, M1-171 | `v0.1.0-alpha.12`: every report string redacted, 28-case corpus gates CI; host.memory and host.disk |
| 14 | Feb 22 to Feb 28, 2027 | 13 | 13.5 | 3 Host checks, HTML report | M1-070, M1-071, M1-074 to M1-076, M1-169, M1-170 | `v0.1.0-alpha.13`: host.cpu on Linux; facade `read_link`; machine identity files denied; terminal styling; in-process env harness |
| 15 | Mar 1 to Mar 7, 2027 | 13 | 13.5 | 3 Host checks, HTML report | M1-077 to M1-085 | `v0.1.0-alpha.14`: HTML report next to the JSON, with golden reports; generated spec reference |
| 16 | Mar 8 to Mar 14, 2027 | 13 | 13.5 | 3 Host checks, HTML report; 4 Network checks | M1-086 to M1-090, M1-168 | `v0.1.0-alpha.15`: the demo: bucket-sorted terminal output with fix lines and the verdict last; umask 077 and an inherited-descriptor warning at start-up |
| 17 | Mar 15 to Mar 21, 2027 | 13 | 14 | 4 Network checks | M1-091 to M1-095, M1-141 | `v0.1.0-alpha.16`: facade TCP, TLS and HTTP; net.egress direct with the address policy |
| 18 | Mar 22 to Mar 28, 2027 | 13 | 13 | 3 Host checks, HTML report; 4 Network checks | M1-096 to M1-101, M1-073 | `v0.1.0-alpha.17`: net.egress through the customer's proxy, net.proxy, net.tls_intercept; host.os on Linux |
| 19 | Mar 29 to Apr 4, 2027 | 13 | 13.5 | 3 Host checks, HTML report; 5 Kubernetes checks | M1-102 to M1-104, M1-072 | `v0.1.0-alpha.18`: kube client with context, server and user shown; read-only guard with path parser and resource allowlist; host.ports on Linux |
| 20 | Apr 5 to Apr 11, 2027 | 13 | 14 | 5 Kubernetes checks | M1-105 to M1-109 | `v0.1.0-alpha.19`: k8s.version, k8s.access; kind job in CI |
| 21 | Apr 12 to Apr 18, 2027 | 13 | 13.5 | 5 Kubernetes checks; 6 Signing, `rdy verify`, 0.1.0 | M1-110 to M1-115 | `v0.1.0-alpha.20`: k8s.storageclass, k8s.rbac, k8s.nodes, k8s.admission (PSA); k8s review closed |
| 22 | Apr 19 to Apr 25, 2027 | 13 | 13.5 | 3 Host checks, HTML report; 5 Kubernetes checks; 6 Signing, `rdy verify`, 0.1.0 | M1-116 to M1-120 | `v0.1.0-alpha.21`: family pages; fixture envs for every verdict; timeouts env; signatures verified before parsing |
| 23 | Apr 26 to May 2, 2027 | 13 | 14.5 | 6 Signing, `rdy verify`, 0.1.0 | M1-121 to M1-125, M1-174, M1-175 | `v0.1.0-alpha.22`: trust store; `rdy spec keygen`, `rdy spec sign` |
| 24 | May 3 to May 9, 2027 | 13 | 13.5 | 6 Signing, `rdy verify`, 0.1.0 | M1-126 to M1-131 | `v0.1.0-alpha.23`: `rdy verify`; unsigned refused; real-binary smoke on five legs; first-run page; `rdy trust add\|list\|remove` |
| 25 | May 10 to May 16, 2027 | 13 | 13.5 | 6 Signing, `rdy verify`, 0.1.0 | M1-132 to M1-139 | **`v0.1.0`**: signing review closed; install and sign pages; README ready, core done, announcement sent to design partners |
| 26 | May 17 to May 23, 2027 | 13 | 12 | Non-core, steps 2 and 3 | M1-140, M1-142, M1-144, M1-145, M1-172 | `v0.1.1`: progress line, HTML wording; UDP and unix socket facade; host.lsm; parameters for the M1-late check ids |
| 27 | May 24 to May 30, 2027 | 13 | 13.5 | Non-core, step 3 | M1-146 to M1-150 | `v0.1.2`: host.security_agents, host.firewall, host.time_sync, host.sysctl, host.container_runtime |
| 28 | May 31 to Jun 6, 2027 | 13 | 13 | Non-core, steps 3 and 4 | M1-151 to M1-156 | `v0.1.3`: host.cgroups, host.kernel; net.dns; net.registry |
| 29 | Jun 7 to Jun 13, 2027 | 13 | 12.5 | Non-core, steps 4 and 5 | M1-157 to M1-163 | `v0.1.4`: net.mtu, net.bandwidth; k8s.nodes free capacity, webhooks, namespace, dns, ingress |
| 30 | Jun 14 to Jun 20, 2027 | 13 | 10.5 | Non-core, steps 2, 5 and 6 | M1-143, M1-164 to M1-167, M1-173 | `v0.1.5`: quiet and verbose modes; k8s.crds, k8s.cni; air-gapped fixture env; quickstart timed; agent catalog staleness gate; M1 complete |

Builds before 0.1.0 (weeks 1 to 24) are `0.1.0-alpha.N` and are not handed to design partners for real
POCs. Until `rdy verify` lands in week 24 they run specs only with `--allow-unsigned`, so rule 3 holds
before signing exists. The week 16 build is the demo shown on calls.

### Cut list

These are every M1 ticket marked `core: no` in 11. They all come after the 0.1.0 tag in the calendar.

- 03 M1-late host checks: M1-145, M1-146, M1-147, M1-148, M1-149, M1-150, M1-151, M1-152 (8 tickets, 19.5 h).
- 03 M1-late network checks: M1-153, M1-155, M1-156, M1-157, M1-158 (5 tickets, 11.5 h).
- 03 M1-late Kubernetes checks: M1-160, M1-161, M1-162, M1-163, M1-164, M1-165 (6 tickets, 13 h).
- M1-140 HTML next-step sentences and the nothing-verified wording (1 h).
- M1-142 Progress line with indicatif, TTY only (2 h).
- M1-143 Quiet and verbose output modes (1.5 h).
- M1-144 Facade methods for UDP exchanges and unix sockets with a GET-only Docker API guard (3.5 h).
- M1-154 musl resolver behaviour fixture for net.dns (1 h).
- M1-159 k8s.nodes free capacity from pod requests (cut 2) (1.5 h).
- M1-166 Fixture env net-airgapped (1.5 h).
- M1-167 Time the quickstart with two design-partner SEs (2 h).
- M1-172 Parameter types for the M1-late check ids (3 h).
- M1-173 Agent catalog staleness gate and lint-wall include gaps (0.5 h).
- Total: 29 tickets, 61.5 h.

Never on the cut list: the "0.1.0 gate" security tickets, the root-only system trust store, verify
before parse, the egress address policy, the kube guard and the facade policies.

## Crates and their public API

Rules for every crate: edition 2024, `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`, clippy
`unwrap_used` and `expect_used` denied outside tests, one public error enum whose `hint()` is never
empty. No third-party types in the public API of `rdy-spec` except serde traits and
`serde_json::Value`. A crate enters the workspace when its milestone starts; crates.io placeholders hold
the names (including a no-code `rdy-cli`, ADR 0011).

**rdy-spec (M1, contract crate).** Owns every `rdy/v1` wire type: the spec, the typed parameters of every
known check id, the result report and the `--json` error object (ADR 0012). Verifies the minisign
signature against a per-product trust store **before** parsing (ADR 0002), parses YAML with limits and no
aliases (ADR 0001), validates (including the `metadata.product` slug rule, ADR 0003), and exposes the
generated JSON schemas. No async, no tokio. `rdy-cloud` uses it to validate authored specs and ingest
results.

```rust
pub const API_VERSION: &str = "rdy/v1";

/// The only way to get a LoadedSpec: verify raw bytes, then parse, then validate.
pub fn load(bytes: &[u8], sig: Option<&[u8]>, trust: &sig::TrustStore, policy: sig::Policy)
    -> Result<LoadedSpec, SpecError>;
/// For `spec lint`, `--allow-unsigned` runs and portal authoring. Never yields a LoadedSpec.
pub fn parse_unverified(bytes: &[u8]) -> Result<spec::Spec, SpecError>;
pub fn validate(spec: &spec::Spec) -> Result<(), SpecError>;
pub fn spec_schema_json() -> String;
pub fn result_schema_json() -> String;

pub struct LoadedSpec { /* private fields, private constructor */ }
impl LoadedSpec {
    pub fn spec(&self) -> &spec::Spec;
    pub fn spec_ref(&self) -> &result::SpecRef;              // product, version, sha256
    pub fn signature(&self) -> &result::SignatureState;
}

pub mod spec {
    pub struct Spec { pub api_version: String, pub kind: Kind, pub metadata: Metadata,
                      pub checks: Vec<CheckSpec>, pub bundle: Option<BundleSpec> }
    pub struct Metadata { pub product: ProductSlug, pub version: Option<String> }
    pub struct ProductSlug(String);                          // ^[a-z0-9][a-z0-9-]{0,62}$
    pub struct CheckSpec { pub id: CheckId, pub name: Option<String>, pub severity: Severity,
                           pub fix: Option<String>, pub timeout: Option<Duration>, pub params: CheckParams }
    #[non_exhaustive]
    pub enum CheckParams { HostMemory(HostMemory), HostDisk(HostDisk), NetEgress(NetEgress),
                           K8sStorageClass(K8sStorageClass), /* one variant per known id */
                           Unknown { id: String, unknown_fields: Vec<String> } }
    pub enum Severity { Warn, Block }
    pub struct CheckId(String);                              // "family.name"
    pub struct Quantity(u64);                                // bytes; parses "32Gi"
}

pub mod result {
    pub struct Report { pub api_version: String, pub run_id: String, pub rdy_version: String,
                        pub spec: SpecRef, pub signature: SignatureState, pub identity: Identity,
                        pub started_at: String, pub duration_ms: u64, pub verdict: Verdict,
                        pub verdict_reason: Option<VerdictReason>, pub summary: Summary,
                        pub checks: Vec<CheckResult>, pub actions: Vec<Action>,
                        pub redactions: u32, pub complete: bool }
    pub struct SpecRef { pub product: String, pub version: Option<String>, pub sha256: String }
    #[non_exhaustive]
    pub enum SignatureState { Verified { key_id: String, product: String, signed_at: String },
                              Unsigned, Invalid { reason: String } }
    pub struct Identity { pub euid: Option<u32>, pub user: String, pub kube: Option<KubeIdentity> }
    pub struct Action { pub kind: ActionKind, pub target: String, pub outcome: String }  // command, file, endpoint, kube
    pub struct CheckResult { pub id: CheckId, pub name: Option<String>, pub severity: Severity,
                             pub status: Status, pub message: String, pub observed: Option<serde_json::Value>,
                             pub expected: Option<serde_json::Value>, pub fix: Option<String>, pub duration_ms: u64 }
    #[non_exhaustive]
    pub enum Status { Pass, Warn, Block, Skipped { reason: String }, Timeout { after_ms: u64 },
                      Error { message: String, hint: String } }
    pub enum Verdict { Ready, ReadyWithWarnings, NotReady }   // JSON: ready, ready_with_warnings, not_ready
    pub enum VerdictReason { RequiredCheckNotRun }
    impl Verdict { pub fn exit_code(self) -> u8; }            // 0, 1, 2
    pub fn verdict(checks: &[CheckResult]) -> (Verdict, Option<VerdictReason>);
    pub struct ErrorOutput { pub code: ErrorCode, pub message: String, pub fix: String }  // `--json` on exit 64 or 70
}

pub mod sig {
    pub struct TrustStore { /* product -> pinned keys */ }
    impl TrustStore {
        /// euid 0: only /etc/rdy/trust.yaml, with owner, mode and symlink checks. Otherwise the XDG path.
        pub fn load_for_current_user() -> Result<Self, SignatureError>;
        pub fn pin(&mut self, product: &spec::ProductSlug, key: PublicKey, note: &str);
        pub fn unpin(&mut self, product: &spec::ProductSlug, key_id: Option<&str>);
        pub fn save(&self) -> Result<(), SignatureError>;      // atomic write
        pub fn one_shot(product: &spec::ProductSlug, key: PublicKey) -> Self;  // `run --key`, never saved
    }
    pub struct PublicKey { /* minisign public key */ }
    impl PublicKey { pub fn parse(s: &str) -> Result<Self, SignatureError>; pub fn key_id(&self) -> String;
                     pub fn fingerprint(&self) -> String; }
    pub enum Policy { RequireSigned, AllowUnsigned }          // AllowUnsigned never accepts an invalid signature
}
```

**rdy-engine (M1, contract crate).** Runs checks and renders reports. Defines the `Check` and `Family`
traits (several implementations across the family crates), the needs model, the scheduler (tokio,
concurrency cap, per-check timeout, panic isolation, ADR 0004), the mapping from check outcomes to
`Status` and the verdict (ADR 0008), the mediated `Exec` and `HostFs` handles, the shared action log,
the M1 redactor applied to every string before output, and the JSON and HTML renderers (askama, safe
output directory, ADR 0003). The scheduler sits behind the default `runtime` feature so `rdy-cloud` can
take only `html`. `Exec` is a trait because it has two implementations from day one: real subprocesses
and recorded fixtures.

```rust
pub use rdy_spec::result;

pub trait Check: Send + Sync + 'static {
    fn id(&self) -> &str;
    fn needs(&self) -> &[Need] { &[] }
    fn supported_on(&self, os: Os) -> bool { true }
    fn run(self: Arc<Self>, ctx: Arc<Context>) -> BoxFuture<'static, Result<Finding, CheckError>>;
}
pub trait Family: Send + Sync {
    fn prefix(&self) -> &'static str;                        // "host", "net", "k8s"
    fn build(&self, spec: &rdy_spec::spec::CheckSpec) -> Option<Arc<dyn Check>>;
}
pub trait Exec: Send + Sync {                                // argv only, fixed PATH as root, process-group kill
    fn run(&self, cmd: &Cmd) -> BoxFuture<'_, Result<Output, ExecError>>;
}

pub struct Context { pub os: Os, pub available: Vec<Need>, pub exec: Arc<dyn Exec>,
                     pub fs: HostFs, pub actions: ActionLog }
pub struct HostFs { /* read-only, rooted at host_root, size-capped reads, logs to ActionLog */ }
impl HostFs { pub fn read_to_string(&self, path: &str, max: usize) -> Result<String, CheckError>; }
#[derive(Clone)] pub struct ActionLog { /* shared, append-only */ }

#[non_exhaustive]
pub enum Need { Root, KubeContext, Network, Command(&'static str) }
pub enum Finding { Pass { observed: serde_json::Value },
                   Fail { observed: serde_json::Value, expected: serde_json::Value, message: String } }
#[non_exhaustive]
pub enum CheckError { MissingNeed(Need), Unsupported(&'static str), Failed { message: String, hint: String } }

pub struct RunOptions { pub jobs: usize /* capped at 32 */, pub default_timeout: Duration,
                        pub deadline: Duration, pub on_progress: Option<Box<dyn Fn(Progress) + Send + Sync>> }
pub struct Engine { /* families */ }
impl Engine {
    pub fn new(families: Vec<Box<dyn Family>>) -> Self;
    pub async fn run(&self, spec: &rdy_spec::LoadedSpec, ctx: Context, opts: RunOptions) -> result::Report;
    pub async fn run_unsigned(&self, spec: &rdy_spec::spec::Spec, ctx: Context, opts: RunOptions) -> result::Report;
}
pub fn blocking<T, F>(f: F) -> BoxFuture<'static, Result<T, CheckError>>
where F: FnOnce() -> Result<T, CheckError> + Send + 'static, T: Send + 'static;

pub mod report {
    /// Writers take only a RedactedReport (ADR 0015).
    pub fn write_json(r: &RedactedReport, out: &mut dyn std::io::Write) -> Result<(), ReportError>;
    pub fn render_html(r: &RedactedReport) -> Result<String, ReportError>;
}
/// Creates <out_dir>/rdy-report-<product>-<ts>/ (0700) before the first check; files 0600, no symlinks
/// followed (ADR 0016). Full sketch in 02 Appendix A.
impl OutputDir { pub fn create_new(parent: &Path, product: &str, ts: &str) -> Result<Self, ReportError>;
                 pub fn write_report(&self, r: &RedactedReport) -> Result<(), ReportError>; }
```

**rdy-checks-host (M1).** CPU, memory, disk, ports and OS in the core M1 set. Kernel, cgroups, time sync,
SELinux and AppArmor, security agents and the rest are 03's M1-late tier: still M1, marked `core: no`.
macOS and Windows data sources are M2, on demand; until then live host checks there report not yet on
this OS.
Reads `/proc` and `/sys` only through `HostFs`, so fixtures are directories, and runs commands only
through `Exec`. Uses `sysinfo`, `rustix` on Unix, `windows-sys` on Windows. Refuses to run setuid. No
stability promise.

```rust
pub struct HostFamily;
impl rdy_engine::Family for HostFamily { /* host.* */ }
```

**rdy-checks-net (M1).** Egress direct and through the customer's proxy, proxy discovery, TLS
interception detection. DNS, registry, MTU and bandwidth are 03's M1-late tier: still M1, marked `core:
no`. Every TCP, CONNECT, TLS and HTTP step goes through the probe facade (ADR 0014): no redirects,
metadata and link-local addresses blocked, spec endpoints only, bodies discarded. The recording TLS
verifier is private to the interception probe. No
stability promise.

```rust
pub struct NetFamily { /* policy client, endpoint allowlist from the spec, ActionLog */ }
impl NetFamily { pub fn new(proxy: ProxyConfig, endpoints: Vec<Endpoint>, actions: ActionLog) -> Result<Self, NetError>; }
pub struct ProxyConfig { pub https: Option<ProxyUrl>, pub http: Option<ProxyUrl>, pub no_proxy: Vec<String> }
impl ProxyConfig { pub fn from_env() -> Self; }
pub struct ProxyUrl(/* private */);                          // Debug and Display mask userinfo; built in rdy_engine::probe (M1-091)
```

**rdy-checks-k8s (M1).** Access and identity, server version, storage classes, RBAC through
`SelfSubjectAccessReview`, node resources. Admission webhooks, namespace, ingress, CRDs, CNI and DNS are
03's M1-late tier: still M1, marked `core: no`. `k8s.device_plugins` ships in M4 with the GPU family. Read-only by a runtime guard layer
that rejects writes, non-review POSTs and Secrets (ADR 0010); the family accepts only the guarded client
type.

```rust
pub struct ReadOnlyClient(/* kube::Client wrapped in the guard layer */);
pub async fn connect(kubeconfig: Option<&Path>, context: Option<&str>, timeout: Duration, actions: ActionLog)
    -> Result<(ReadOnlyClient, result::KubeIdentity), K8sError>;
pub struct K8sFamily { client: Option<ReadOnlyClient> }
impl K8sFamily { pub fn new(client: Option<ReadOnlyClient>) -> Self; }
```

**rdy (crate dir `rdy-cli`, M1).** The binary (ADR 0011). Commands (cli-ux final names): M1 `run`,
`verify`, `spec lint`, `spec sign`, `spec keygen`, `trust add`, `trust list`, `trust remove`, `version`;
M2 `bundle`, `upload`, `report`; M3 `spec init`, `self-update`. `run` flags in M1: `--allow-unsigned`
(argv only), `--key` (one run, never pinned), `--sig`, `--json`, `--out-dir`, `--no-report`,
`--kube-context`, `--kubeconfig`, `--jobs`, `--no-network`; `--timeout` and `--dry-run` in M2 (07);
`--allow-exec=<hash>` in M4. Pinning happens only in `trust add`, with `--yes` for scripts. Builds the
tokio runtime, installs the ring provider, probes needs (euid, kube, proxy env), assembles the families,
writes reports, maps errors to exit codes and the `--json` error object with `anyhow` at the edge, and
shows progress on stderr only when it is a TTY. No library API.

**rdy-bundle (M2).** Collectors (journal, Kubernetes events, files by glob), redactors (AWS keys, bearer
tokens, emails, custom regex) applied before any byte is written, `tar` plus `zstd`, and a manifest that
lists every file and every redaction count. Designed in 04-bundle-and-redaction.md. `Redactor` is a
trait because it has several implementations at launch; the M1 engine redactor becomes one of them.

```rust
pub fn build(spec: &rdy_spec::spec::BundleSpec, ctx: &BundleContext, out_dir: &Path) -> Result<Manifest, BundleError>;
pub trait Redactor: Send + Sync { fn name(&self) -> &str; fn redact<'a>(&self, input: &'a str) -> Cow<'a, str>; }
```

**rdy-checks-cloud (M3).** AWS first: IAM policy simulation for the install identity, service quotas,
region availability, VPC and subnet capacity. GCP and Azure later through REST. Read-only APIs only,
which is also what Option B reuses. Blocked on the TLS provider spike in ADR 0009.

**rdy-checks-gpu (M4).** Driver and CUDA versions, VRAM per node, device plugin, model-download egress.
On Linux it uses `nvidia-smi` and `/proc/driver/nvidia`, not NVML, because a static musl binary cannot
`dlopen` (ADR 0006). NCCL and fabric sanity need a real design-partner fixture before they are scoped.

**rdy-ffi and rdy-wasm (M5).** C-ABI and WASM builds of `rdy-engine` for the Embed SDK. Not created
until M5.

## Workspace dependencies

Exact versions are pinned by the "Create workspace skeleton" ticket from crates.io on the day it runs.
The line shown is the major line this plan expects.

| Crate | Line | Used by | Why | Flag |
| --- | --- | --- | --- | --- |
| serde, serde_json | 1 | all | (de)serialization, result JSON | |
| serde-saphyr | 2 | rdy-spec | YAML parser, pure Rust, budgets (ADR 0001) | Young, mostly one maintainer. Unsafe count checked with cargo geiger on 2026-10-28, result in ADR 0001. Fallback `serde_yaml_ng`. |
| serde_yaml | | none | named in the plan | **Deprecated** (March 2024). Banned in deny.toml. |
| serde_yml | | none | common successor | **Archived**, RUSTSEC-2025-0068. Banned. |
| schemars | 1 | rdy-spec | JSON Schema from types (ADR 0012) | 1.x changed API from 0.8; start on 1.x. |
| ed25519-dalek, blake2 | 2.2 and 0.10, exact pins | rdy-spec | `verify_strict` over the minisign envelope that rdy-spec reads itself (ADR 0018) | Wycheproof vectors in the test suite, every bump reviewed. `minisign-verify` was dropped: it hides the key id and is not strict. |
| minisign | current | rdy; dev-dependency of rdy-spec | key generation and signing; tests sign with it | |
| sha2 | current | rdy-spec | spec digest in results | |
| thiserror | 2 | libraries | typed errors | |
| anyhow | 1 | rdy | edge errors | |
| tokio | 1 | engine, net, k8s, rdy | runtime (ADR 0004) | Only `rdy` enables `rt-multi-thread`. |
| futures-util | 0.3 | rdy-engine | `BoxFuture` | |
| tracing, tracing-subscriber | 0.1, 0.3 | all, rdy | logging, `RUST_LOG` | Never log secrets or exec-plugin output. |
| askama | current (0.14 or later) | rdy-engine | compile-time HTML templates (ADR 0003) | Rinja merged back into askama in 2025; take the current line. |
| cap-std | current | rdy-engine | report writes that never follow symlinks (ADR 0003) | Added after security review. |
| jiff | current | rdy-spec, rdy-engine | timestamps and durations (`10s`, `7d`) | Pre-1.0 at last check; fallback `time`. |
| uuid | 1 | rdy-engine | run ids | |
| semver | 1 | rdy-spec | `metadata.version` ranges | Kernel and CUDA versions are not semver; own lenient compare. |
| sysinfo | current | rdy-checks-host | CPU, memory, disk | Frequent breaking releases. Pin and update on purpose. |
| rustix | 1 | rdy-checks-host, rdy-engine, rdy-cli | Unix syscalls (euid, statvfs, process groups, waitid), all safe wrappers | Chosen over `nix`; `forbid(unsafe_code)` holds. |
| windows-sys | current | rdy-checks-host, rdy-engine | Windows APIs, job objects | |
| reqwest | | none in M1 | named in ADR 0009 | Banned in `deny.toml` by ADR 0014. The probe facade does HTTP with hyper. The M2 upload stack is an open item (13). |
| hyper | 1 | rdy-engine (`runtime` feature) | facade HTTP/1.1 HEAD and GET (ADR 0014) | Client connection API only. |
| rustls, tokio-rustls | 0.23, 0.26 | net, rdy | TLS and the interception probe | Provider: ring only. |
| rustls-platform-verifier | | none | OS trust | Rejected for M1 by ADR 0014: on macOS and Windows it can fetch revocation and AIA URLs outside the peer set. |
| webpki-roots, rustls-native-certs | current | rdy-checks-net | interception probe only | webpki-roots license is CDLA-Permissive-2.0; allow it in deny.toml. |
| x509-parser | current | rdy-checks-net | issuer of an intercepting CA | On the cut list. |
| hickory-resolver | current | rdy-checks-net | DNS checks and the address policy resolver (ADR 0006, 0009) | Pre-1.0, API churn between minors. |
| kube, k8s-openapi | current | rdy-checks-k8s | Kubernetes client (ADR 0010) | Heavy; frequent MSRV bumps. Client feature only, behind the guard layer. |
| tower | 0.5 | rdy-checks-k8s | the read-only guard layer | Already a kube dependency. |
| clap | 4 | rdy | commands and flags | |
| indicatif | current | rdy | progress on a TTY stderr | |
| anstream | current | rdy | colour, `NO_COLOR`, `--color` | Comes with clap. |
| proptest, insta, assert_cmd, predicates, tempfile | current | dev only | property, golden and binary tests | |
| tar, zstd | 0.4, current | rdy-bundle (M2) | bundle archive | `zstd` builds C libzstd; fine for static musl with a C compiler. |
| regex, aho-corasick | 1 | rdy-engine (M1 redactor), rdy-bundle (M2) | redaction | |
| self_update | | rdy (M3) | named in the plan | **Risky.** Must verify a signature before replacing the binary. 06 decides between it and the cargo-dist updater. |
| aws-sdk-iam, -servicequotas, -ec2 | current | rdy-checks-cloud (M3) | AWS checks | **Risky:** defaults to aws-lc-rs, conflicts with ADR 0009. Spike in M2. |
| nvml-wrapper | | none | named in the plan | **Cannot work** in a static musl binary (needs `dlopen`). Dropped (ADR 0006). |
| mimalloc | | rdy, only if measured | allocator | Only if the M2 benchmark says so, after dependency review. |

Tooling, not crates: `cargo-dist` (release-engineer owns). Axo stopped development in 2025 and a
community maintainer resumed releases; treat it as a risk and keep a hand-written release workflow as
the fallback. `cargo-zigbuild` for local cross builds, `release-plz` and `cargo-semver-checks` from M2,
`cargo-deny`, `cargo-audit`, `cargo-auditable`, `cargo-cyclonedx`, `cargo-geiger` once for ADR 0001.

## Plan corrections found

These were merged into `13-plan-corrections.md` and applied or closed there in M1-009 (2026-10-28).
They are kept as the record of what was found.

- KICKOFF.md, "After the plan": starts M1 once the backlog is approved, but docs/plan/rdy-plan.md
  ("Risks, validation gates" and "Next 30 days") says no Rust until the gates are met, go or no-go on
  Nov 20, 2026. Fix: KICKOFF starts M1 only after a recorded "go"; the founder picks an option at the
  top of this file.
- KICKOFF.md constraints: "M1 is six weeks". M1 is 365 hours (306 core) against a 60 to 90 hour
  budget. Decision made (2026-10-28): M1 is extended to Jun 13, 2027 at 13 hours a week; see the M1
  calendar. Fix: KICKOFF points to 11-backlog.md for the M1 length.
- docs/plan/03-check-catalog.md: 24 tickets marked M1-late (72 hours). Decision made: they stay in M1,
  marked `core: no` in 11-backlog.md, after the 0.1.0 tag, except the macOS and Windows sources (M2)
  and `k8s.device_plugins` (M4), which the 11 review moved out.
- docs/plan/rdy-plan.md, Milestones table: every exit test is a business outcome CI cannot check. Fix:
  add the engineering done test column above.
- docs/plan/rdy-plan.md, Rust build plan: "Ship a usable CLI in about 12 weeks" while M1 is six weeks.
  Fix: state M1 at its real length from 11-backlog.md (29 weeks at 13 hours, to Jun 13, 2027).
- docs/plan/rdy-plan.md, "Build order inside M1": signing is last, but CLAUDE.md rule 3 says refuse
  unsigned specs. Fix: alpha builds run only with `--allow-unsigned`, are tagged alpha, and are not
  given to design partners.
- docs/plan/rdy-plan.md, Architecture: "One Cargo workspace. The CLI and the portal share the spec and
  result types". Fix: "Two workspaces; `rdy-cloud` consumes `rdy-spec` and `rdy-engine` from crates.io".
- docs/plan/rdy-plan.md, crate table: lists `rdy-server` (private repo) and `rdy-ffi`, `rdy-wasm` with no
  home. Fix: mark `rdy-server` as rdy-cloud; put the Embed SDK crates in the public repo at M5.
- docs/plan/rdy-plan.md, "How a POC flows" step 1: `rdy run acme-platform --token abc123` needs the
  portal (M2) and puts the token on argv, where `ps` and shell history see it. Fix: M1 runs a local file;
  from M2 the token comes from `RDY_TOKEN`, `--token-file` or a prompt.
- docs/plan/rdy-plan.md, Product definition example spec: contains `gpu.cuda` and `aws.iam`, which no
  M1 build can run. Fix: `examples/specs/acme-platform.yaml` for M1 uses only host, net and k8s checks,
  plus one unknown id to show SKIP.
- docs/plan/rdy-plan.md, Website plan, Install endpoint: says `get.<domain>`; CLAUDE.md and the names
  table say `getrdy.io/install`. Fix: use `getrdy.io/install` everywhere.
- CLAUDE.md, Repo layout: lists every crate from day one. Fix: crates enter the workspace when their
  milestone starts; crates.io placeholders hold the names.
- CLAUDE.md, Engineering standards: "Linux x86_64 and aarch64 (musl), macOS, Windows. CI runs all four."
  macOS ships two arches. Fix: five release targets; CI tests four natively (Linux x86_64, Linux
  aarch64, macOS aarch64, Windows x86_64); `x86_64-apple-darwin` is built and smoke-tested only.
- ADR-level corrections (serde_yaml, ed25519-dalek, Sigstore for specs, CLAUDE.md rule 3, nvml-wrapper,
  reqwest TLS default, `cargo run -p rdy-cli`, result model location, command list, launch families
  without a milestone) are listed in docs/adr/README.md.

## Tickets implied

The tickets this document implied are merged into `docs/plan/11-backlog.md`, which holds the ids, final
estimates, dependencies, milestones and order. The list that stood here went stale against 11 during the
review pass, so it is removed. Change tickets in 11.
