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
| M1 CLI alpha | Spec format, host, network and Kubernetes checks, HTML and JSON report, signed specs | One design partner catches a real install blocker with it | On Linux x86_64 and aarch64 (musl), macOS and Windows, `rdy run` on a signed fixture spec writes JSON and HTML into a new report directory and exits 0, 1 and 2 on the ready, warning and not-ready fixtures; an unsigned spec exits 64; a tampered spec exits 64 even with `--allow-unsigned`; every "0.1.0 gate" security ticket is closed. |
| M2 Portal MVP | Share links, results dashboard, redacted bundles, bundle viewer, Slack alerts | Design partners run it on 20 prospect environments | `rdy run <product>` with the token from `RDY_TOKEN`, `--token-file` or a prompt (never argv) fetches a signed spec from staging, the redaction golden suite passes, nothing uploads without the flag or a yes. |
| M3 Launch | AWS account checks, Stripe billing, docs, public open-source launch, Team tier on sale | First 10 paying vendors | AWS checks pass against recorded fixtures, the docs site builds its reference from the schema, `rdy-spec` and `rdy-engine` are 1.0, `custom.exec` runs only with hash-bound consent. |
| M4 Business tier | GPU and AI checks, CRM sync, analytics, custom-branded CLI, SSO | First Business-tier deal | GPU checks pass on fixtures and one real node, branded report renders from data, data store checks ship. |
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

### The honest count

| Slice | Source | Hours |
| --- | --- | --- |
| Architecture, engine, report, signing, CLI edge | tickets at the end of this file (excluding the SEC tickets) | 81 |
| Security, 11 standalone tickets | security-reviewer review, "M1 security budget" | 27 |
| Release, CI, signing of binaries, install.sh | 06-release-and-distribution.md, 8 M1 tickets | 24 |
| Check families, core (not marked M1-late) | 03-check-catalog.md, 19 tickets plus 2 reviews | 62 |
| **Total M1** | | **about 194** |

The budget in KICKOFF.md is six weeks at 10 to 15 hours: **60 to 90 hours**. M1 as scoped, with the
security work that a root binary on customer boxes needs, is about twice that. The check catalog's 25
"M1-late" tickets (about 75 hours) are **not** in the total: this plan moves them to M2. Two overlaps
should be merged in 11-backlog.md, saving about 4 hours: 03's "Command runner" with "Blocking helper and
subprocess kill on timeout", and 03's "Kube mock harness" with "Read-only guard layer and test".

A six-week M1 is not possible without dropping a whole family or the security gate. 90 hours covers the
release pipeline, the spec, engine, report and signing core, and the gate security tickets, with no check
families at all, which cannot meet the plan's exit test.

**Recommendation (founder decides):** extend M1 to **15 weeks at about 13 hours a week, Nov 23, 2026 to
Mar 7, 2027**, keeping the plan's build order and a usable binary every week. Two alternatives:

- **14 weeks (Feb 28, 2027)** by taking the cut list: parser property and fuzz tests (3h), SEC-22,
  SEC-24 and SEC-31 (marked "by 0.1.1", 6h), the second half of the SEC-26 corpus (1.5h), TLS issuer
  naming and print stylesheet polish (2h). About 12 hours. Those land in 0.1.1, two weeks after 0.1.0.
- **At 10 hours a week**, the same scope takes about 19 weeks (early April 2027).

Never on the cut list: the "0.1.0 gate" security tickets, the root-only system trust store, verify
before parse, the egress address policy and the kube guard layer.

### Week by week

Hours are founder hours including review of agent-written code. Ticket names from 03 and 06 are
abbreviated; full titles live in those files.

| Week | Dates | Build order step | Ships at the end of the week | Tickets | Hours |
| --- | --- | --- | --- | --- | --- |
| 1 | Nov 23 to 29 (Thanksgiving) | 1. Workspace, CI, release | `rdy version` as a CI artefact for five targets on every push | Create workspace skeleton; Reserve crates.io names; deny.toml; Package rdy; CLAUDE.md commands; confirm ADR reviews (2); SEC-04; 06 CI lint and deny job | 13 |
| 2 | Nov 30 to Dec 6 | 1 | First cosign-signed pre-release `rdy version` on GitHub Releases | 06 CI test matrix with static-pie proof; 06 rulesets; 06 dist init; 06 sign-release; SEC-05 | 14 |
| 3 | Dec 7 to 13 | 1 | `curl -sSf https://getrdy.io/install \| sh` installs a verified alpha | 06 first signed alpha; 06 install.sh core; 06 install.sh signature check; SEC-32; Define public spec types | 14 |
| 4 | Dec 14 to 20 | 2. Spec parser and result model | `rdy spec lint` with line and column; `rdy run --allow-unsigned --json` lists every check as SKIP "not built yet" and exits 2; published JSON schemas | Wire serde-saphyr; Result model and verdict; JSON schemas; Error types and exit codes; example spec | 13.5 |
| 5 | Dec 21 to 27 (Christmas) | 2 | Engine runs fixture checks with timeouts; unknown ids reported | Check trait, Need and Context; Scheduler; Unknown check ids | 9.5 |
| 6 | Dec 28 to Jan 3 (New Year) | 3. Host checks and HTML | Same binary with the fixture harness; first host check behind it | Blocking helper; 03 command runner; 03 fixture loader | 10 |
| 7 | Jan 4 to 10 | 3 | Real host checks: memory, disk, cpu; action log in the JSON | 03 units helpers; host.memory; host.disk; host.cpu; SEC-17 | 15 |
| 8 | Jan 11 to 17 | 3 | The demo: host checks plus the HTML report | host.ports; host.os; HTML report; Embed JSON safely; Golden tests | 13.5 |
| 9 | Jan 18 to 24 | 3 | Reports land in a fresh 0700 directory; evidence and errors redacted | SEC-19; SEC-25; SEC-26; 03 loopback network test support | 13 |
| 10 | Jan 25 to 31 | 4. Network checks | Egress direct and through the customer's proxy, with the address policy | HTTP client builder; SEC-21; net.egress core; net.egress via proxy | 13 |
| 11 | Feb 1 to 7 | 4 | Proxy discovery and TLS interception detection | net.proxy; net.tls_intercept; 03 TLS probe security review; musl resolver fixture; SEC-22 | 13 |
| 12 | Feb 8 to 14 | 5. Kubernetes checks | k8s access with context, server and user shown; guarded client | Kube client; Read-only guard layer; 03 kube mock harness; k8s.access | 13 |
| 13 | Feb 15 to 21 | 5 | k8s version, storage classes, RBAC, nodes | k8s.version; k8s.storageclass; k8s.rbac; k8s.nodes; 03 k8s review | 14 |
| 14 | Feb 22 to 28 | 6. Signing and `rdy verify` | Signed specs verified before parsing; keygen and sign | Verify minisign signatures; Trust store; spec keygen and sign; rdy verify and refuse-unsigned | 14.5 |
| 15 | Mar 1 to 7 | 6 | **0.1.0**, the build design partners get | trust add, list, remove; Security review of signing; SEC-24; SEC-31; parser property tests; tag and release | 11 |

Builds before week 14 are tagged `0.1.0-alpha.N`, run specs only with `--allow-unsigned` (so rule 3
holds before signing exists), and are not handed to design partners for real POCs.

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
    /// Creates <out_dir>/rdy-report-<product>-<ts>/ (0700) and both files (0600), no symlinks followed.
    pub fn write(report: &Report, out_dir: &Path) -> Result<PathBuf, ReportError>;
    pub fn to_json(report: &Report) -> Result<Vec<u8>, ReportError>;
    pub fn render_html(report: &Report) -> Result<String, ReportError>;
}
```

**rdy-checks-host (M1).** CPU, memory, disk, ports and OS in the core M1 set, then kernel, cgroups, time
sync, SELinux and AppArmor, security agents and the rest in M2 (03-check-catalog.md marks them M1-late).
Reads `/proc` and `/sys` only through `HostFs`, so fixtures are directories, and runs commands only
through `Exec`. Uses `sysinfo`, `nix` on Unix, `windows-sys` on Windows. Refuses to run setuid. No
stability promise.

```rust
pub struct HostFamily;
impl rdy_engine::Family for HostFamily { /* host.* */ }
```

**rdy-checks-net (M1).** Egress direct and through the customer's proxy, proxy discovery, TLS
interception detection. DNS, MTU and bandwidth are M1-late in 03 and move to M2. One policy client
(ADR 0009): no redirects, metadata and link-local addresses blocked, spec endpoints only, bodies
discarded. The recording TLS verifier is private to the interception probe. No stability promise.

```rust
pub struct NetFamily { /* policy client, endpoint allowlist from the spec, ActionLog */ }
impl NetFamily { pub fn new(proxy: ProxyConfig, endpoints: Vec<Endpoint>, actions: ActionLog) -> Result<Self, NetError>; }
pub struct ProxyConfig { pub https: Option<ProxyUrl>, pub http: Option<ProxyUrl>, pub no_proxy: Vec<String> }
impl ProxyConfig { pub fn from_env() -> Self; }
pub struct ProxyUrl(/* private */);                          // Debug and Display mask userinfo
```

**rdy-checks-k8s (M1).** Access and identity, server version, storage classes, RBAC through
`SelfSubjectAccessReview`, node resources. Admission, CRDs, CNI, DNS and device plugins are M1-late in
03 and move to M2. Read-only by a runtime guard layer that rejects writes, non-review POSTs and Secrets
(ADR 0010); the family accepts only the guarded client type.

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
`--kube-context`, `--kubeconfig`, `--timeout`, `--jobs`, `--dry-run`; `--allow-exec=<hash>` in M3. Pinning
happens only in `trust add`, with `--yes` for scripts. Builds the tokio runtime, installs the ring
provider, probes needs (euid, kube, proxy env), assembles the families, writes reports, maps errors to
exit codes and the `--json` error object with `anyhow` at the edge, and shows progress on stderr only
when it is a TTY. No library API.

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
| serde-saphyr | 1 | rdy-spec | YAML parser, pure Rust, budgets (ADR 0001) | Young, mostly one maintainer. Unsafe count to be checked with cargo geiger. Fallback `serde_yaml_ng`. |
| serde_yaml | | none | named in the plan | **Deprecated** (March 2024). Banned in deny.toml. |
| serde_yml | | none | common successor | **Archived**, RUSTSEC-2025-0068. Banned. |
| schemars | 1 | rdy-spec | JSON Schema from types (ADR 0012) | 1.x changed API from 0.8; start on 1.x. |
| minisign-verify | 0.2, exact pin | rdy-spec | ed25519 verification (ADR 0002) | Own ed25519 code; Wycheproof vectors in CI, every bump reviewed. |
| minisign | current | rdy | key generation and signing | |
| ed25519-dalek | | none | named in the plan | Not deprecated; replaced by minisign format (ADR 0002). |
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
| nix | current | rdy-checks-host, rdy-engine | Unix syscalls (euid, statvfs, process groups) | |
| windows-sys | current | rdy-checks-host, rdy-engine | Windows APIs, job objects | |
| reqwest | 0.13 | rdy-checks-net, later upload | HTTP egress (ADR 0009) | **Default TLS changed** to rustls on aws-lc-rs with the platform verifier. No default features, ring provider, redirects off. |
| rustls, tokio-rustls | 0.23, 0.26 | net, rdy | TLS and the interception probe | Provider: ring only. |
| rustls-platform-verifier | current | via reqwest | OS trust for egress and upload | |
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

- KICKOFF.md, "After the plan": starts M1 once the backlog is approved, but docs/plan/rdy-plan.md
  ("Risks, validation gates" and "Next 30 days") says no Rust until the gates are met, go or no-go on
  Nov 20, 2026. Fix: KICKOFF starts M1 only after a recorded "go"; the founder picks an option at the
  top of this file.
- KICKOFF.md constraints and CLAUDE.md founder context: "M1 is six weeks". M1 as scoped plus the
  security and release work is about 194 hours against a 60 to 90 hour budget. Fix: founder chooses
  15 weeks (recommended, to Mar 7, 2027), 14 weeks with the cut list, or a smaller M1 scope.
- docs/plan/03-check-catalog.md: 25 tickets marked M1-late (about 75 hours) cannot fit M1. Fix: move
  them to M2 in 11-backlog.md, and merge the two overlaps named in the calendar section.
- docs/plan/rdy-plan.md, Milestones table: every exit test is a business outcome CI cannot check. Fix:
  add the engineering done test column above.
- docs/plan/rdy-plan.md, Rust build plan: "Ship a usable CLI in about 12 weeks" while M1 is six weeks.
  Fix: state M1 at its real length once the founder decides.
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

- [M1] Create workspace skeleton | owner: rust-engineer | est: 2h | depends on: none | exit test: `cargo build`, `clippy -D warnings`, `fmt --check` and `cargo doc` with warnings as errors pass on edition 2024 crates with `forbid(unsafe_code)`, a pinned toolchain and shared lints.
- [M1] Reserve crates.io names with 0.0.1 placeholders | owner: release-engineer | est: 1h | depends on: none | exit test: every crate name in CLAUDE.md plus `rdy-cli` resolves on crates.io to a getrdy-io-owned 0.0.1, and `rdy-cli`'s description says "install rdy".
- [M1] Add deny.toml with crate bans and license allowlist | owner: release-engineer | est: 2h | depends on: Create workspace skeleton | exit test: adding serde_yaml, serde_yml, openssl-sys, native-tls or aws-lc-sys fails `cargo deny check` in CI.
- [M1] Package rdy in crates/rdy-cli with binary name rdy | owner: rust-engineer | est: 1h | depends on: Create workspace skeleton | exit test: `cargo run -p rdy -- version` and `-- --version` print the documented line and `cargo package -p rdy --list` contains no stray files.
- [M1] Update CLAUDE.md commands to cargo run -p rdy | owner: docs-writer | est: 1h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: every command in the CLAUDE.md Commands block runs green on a fresh clone.
- [M1] Confirm revised ADRs close security findings MF-01 to MF-07 | owner: security-reviewer | est: 1h | depends on: none | exit test: each must-fix is marked closed or reopened in docs/plan/reviews/ before the first M1 code ticket.
- [M1] Confirm revised ADRs close cli-ux findings M1 to M3 and the final command names | owner: cli-ux | est: 1h | depends on: none | exit test: 07-cli-ux.md uses the verdict words, status words and commands from ADRs 0002, 0003 and 0008.
- [M1] Define public spec types in rdy-spec | owner: rust-engineer | est: 3h | depends on: Create workspace skeleton | exit test: the plan's example spec deserializes through parse_unverified into typed values, round-trips through serde_json, and no public path builds a LoadedSpec without load().
- [M1] Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a 2 MiB file, an anchor or alias, a duplicate key and `cuda: 12.10` unquoted each give the documented SpecError with line and column, never a panic, and the geiger result is recorded in ADR 0001.
- [M1] Define result model and verdict mapping in rdy-spec | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: unit tests cover every row of the status and verdict tables, including a skipped block check giving not_ready with exit 2.
- [M1] Generate JSON schemas with schemars and check drift in CI | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: changing a doc comment without rerunning cargo xtask schema fails CI.
- [M1] Error types with fix hints and exit code mapping at the CLI edge | owner: rust-engineer | est: 3.5h | depends on: Define result model and verdict mapping in rdy-spec | exit test: every error variant has a non-empty hint, exit 64 and 70 cases print `fix:`, `--json` failures print the error object with a stable code, and control characters in a spec string are stripped.
- [M1] Write examples/specs/acme-platform.yaml with M1 checks only | owner: devrel | est: 1h | depends on: Define public spec types in rdy-spec | exit test: `rdy spec lint` passes on it and it contains one unknown id that reports SKIP.
- [M1] Check trait, Need and Context in rdy-engine | owner: rust-engineer | est: 3.5h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture family with one passing and one need-missing check produces PASS and SKIP through Engine::run, HostFs reads only under host_root, and a setuid launch is refused.
- [M1] Scheduler with concurrency limit, per-check timeout and panic isolation | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture check that sleeps forever reports Timeout, one that panics reports Error, `--jobs 500` is capped at 32, and the other checks still pass.
- [M1] Blocking helper and subprocess kill on timeout | owner: rust-engineer | est: 4h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: a check running a script that forks `sleep 600` times out, the whole process group is gone, `rdy` exits within 2 s, a fake binary earlier in a root user's PATH is not used, and `sudo` is refused.
- [M1] Unknown check ids report Skipped with a "needs a newer rdy" reason | owner: rust-engineer | est: 2h | depends on: Check trait, Need and Context in rdy-engine | exit test: the plan's example spec, which contains gpu.cuda and aws.iam, runs on M1 and reports both as SKIP with the reason and fix line, not as a parse error.
- [M1] askama HTML report with inline CSS, dark mode and print | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: the golden HTML shows the verdict and blocks first, makes no network requests in a headless browser test, and passes an HTML validator with lang and color-scheme set.
- [M1] Embed result JSON in the HTML report safely | owner: rust-engineer | est: 2.5h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a hostname of `</script><img onerror>` round-trips through the embedded JSON unchanged, renders as text, and the CSP and link attributes match ADR 0003.
- [M1] Golden tests for JSON and HTML reports | owner: qa-engineer | est: 2h | depends on: Embed result JSON in the HTML report safely | exit test: insta snapshots for ready, warning and not-ready fixtures pass on all four CI targets.
- [M1] Shared HTTP client builder with rustls ring and platform verifier | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: integration test with a local CONNECT proxy shows egress through the proxy, NO_PROXY honoured, `cargo tree -i aws-lc-sys` empty, and a proxy password never appears in Debug output.
- [M1] musl resolver behaviour fixture for net.dns | owner: qa-engineer | est: 2h | depends on: Shared HTTP client builder with rustls ring and platform verifier | exit test: a fixture resolv.conf and nsswitch.conf with `sss` produce the documented warning.
- [M1] Kube client from kubeconfig or in-cluster with rustls and timeouts | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: on a kind cluster in CI k8s.version passes and the context, server and user print before the first request; with no kubeconfig every k8s check is SKIP with the hint; exec plugin output never appears at RUST_LOG=trace.
- [M1] Read-only guard layer and test for rdy-checks-k8s | owner: k8s-expert | est: 3h | depends on: Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: the runtime layer rejects any write, any non-review POST and any secrets path, and the mock API server records only allowed requests across the full k8s fixture run.
- [M1] Verify minisign signatures in rdy-spec against a trust store with product binding | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: a tampered byte, a wrong product, a bad trusted-comment prefix and an unpinned key each fail with a distinct SignatureError, Wycheproof vectors pass, and a parser spy shows a tampered spec is never parsed.
- [M1] Trust store load and save in user and system locations | owner: rust-engineer | est: 3h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: as root with HOME and XDG_CONFIG_HOME pointing at a user store, only /etc/rdy/trust.yaml is read, and a symlinked, non-root or group-writable file is refused with the reason.
- [M1] rdy spec keygen and rdy spec sign | owner: rust-engineer | est: 4h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: a spec signed by rdy verifies with stock minisign and the reverse; keys are 0600 and encrypted unless --unencrypted; a world-readable key is refused.
- [M1] rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | owner: rust-engineer | est: 3.5h | depends on: rdy spec keygen and rdy spec sign | exit test: unsigned exits 64; with --allow-unsigned it runs and both reports say unsigned; an invalid signature exits 64 even with the flag and its hint never names the flag.
- [M1] rdy trust add, list and remove | owner: rust-engineer | est: 2h | depends on: Trust store load and save in user and system locations | exit test: `trust add` without a TTY and without --yes exits 64 with a fix line; with --yes it pins and `trust list` shows key id and fingerprint; `run --key` leaves the store unchanged.
- [M1] Security review of spec signing and trust store | owner: security-reviewer | est: 2h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: review notes filed and every blocker fixed before the 0.1.0 tag.
- [M1] Property and fuzz tests for rdy_spec::parse | owner: qa-engineer | est: 3h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: proptest over 10k random inputs in CI finds no panic. (On the cut list.)
- [M1] SEC-04 Harden GitHub org and repo settings | owner: security-reviewer | est: 2h | depends on: none | exit test: a checklist in the PR shows 2FA required, rulesets on main and v* tags, immutable releases, private vulnerability reporting and CODEOWNERS on security paths.
- [M1] SEC-05 Harden getrdy.io domain and hosting accounts | owner: release-engineer | est: 2h | depends on: none | exit test: registrar lock, DNSSEC, CAA and HSTS verified with public tools and hardware-key MFA confirmed on registrar and hosting accounts.
- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a product of `../x` fails validation, a pre-planted symlink is not followed, an existing dir is refused, modes are 0700 and 0600, and `--out-dir` and `--no-report` behave as written.
- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: canary secrets in env, proxy URL, kubeconfig and command output never appear in the JSON, HTML or stderr at RUST_LOG=trace.
- [M1] SEC-17 Action log in the result via mediated Context handles | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture run's JSON lists every command, file read, endpoint and kube request the checks used, plus identity and the redaction count.
- [M1] SEC-21 Egress address policy, no redirects, no bodies | owner: check-author | est: 3h | depends on: Shared HTTP client builder with rustls ring and platform verifier | exit test: a redirect to 169.254.169.254, a hostname resolving to link-local and an unlisted endpoint are all refused, and a body canary never reaches the report.
- [M1] SEC-26 M1 redaction corpus | owner: qa-engineer | est: 3h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: 60 synthetic cases including chunk-boundary and negative cases pass with zero misses in CI (30 required for 0.1.0).
- [M1] SEC-22 No-phone-home tests | owner: qa-engineer | est: 2h | depends on: SEC-21 Egress address policy, no redirects, no bodies | exit test: a no-net spec passes under `unshare -rn` on Linux CI and a contact-set test sees only spec endpoints.
- [M1] SEC-24 Read-only ClusterRole example and kube identity display | owner: k8s-expert | est: 2h | depends on: Read-only guard layer and test for rdy-checks-k8s | exit test: M1 k8s checks pass on kind with only `examples/rbac/rdy-readonly.yaml`, and the report shows context, server and user.
- [M1] SEC-31 Docs security page and verify-first install | owner: docs-writer | est: 2h | depends on: sign-release with cosign keyless, SHA256SUMS and self-verify (SEC-06, SEC-07) | exit test: the page lists what rdy reads and contacts, the report fields and link parameters, and CI runs its verify commands against the latest release.
- [M1] SEC-32 Enable vulnerability reporting channels | owner: security-reviewer | est: 1h | depends on: SEC-04 Harden GitHub org and repo settings | exit test: private vulnerability reporting is on, security@getrdy.io receives mail and security.txt is served on getrdy.io.
- [M2] Move the 03-check-catalog M1-late tickets into M2 | owner: rust-architect | est: 1h | depends on: none | exit test: 11-backlog.md lists all 25 under M2 with unchanged estimates.
- [M2] cargo-semver-checks in CI for rdy-spec and rdy-engine | owner: release-engineer | est: 2h | depends on: none | exit test: a PR that removes a public field without a version bump fails CI.
- [M2] release-plz config with trusted publishing for per-crate versions and changelogs | owner: release-engineer | est: 3h | depends on: none | exit test: a dry run opens a release PR bumping only the crates that changed, and the publish job holds no crates.io token secret.
- [M2] Keep golden result files per released version and parse them in CI | owner: qa-engineer | est: 1h | depends on: none | exit test: CI deserializes every file under tests/fixtures/results/ with the current rdy-engine.
- [M2] First crates.io release of rdy-spec and rdy-engine for rdy-cloud | owner: release-engineer | est: 2h | depends on: release-plz config with trusted publishing for per-crate versions and changelogs | exit test: a scratch crate outside the repo depends on both from crates.io and parses a golden result.
- [M2] Allocator benchmark musl vs glibc in CI | owner: release-engineer | est: 2h | depends on: none | exit test: CI prints both timings for the fixture spec and fails above the 20% threshold.
- [M2] Verify the AWS SDK runs on rustls with ring | owner: cloud-iam-expert | est: 3h | depends on: none | exit test: a spike branch builds aws-sdk-iam for both musl targets with no aws-lc-sys in cargo tree, or an ADR records why not.
- [M2] rdy-bundle: collectors, redactors, tar plus zstd, manifest | owner: rust-engineer | est: 24h | depends on: none | exit test: the redaction golden suite in 04-bundle-and-redaction.md passes on all four CI targets.
- [M2] Opt-in upload client and share-link spec fetch | owner: rust-engineer | est: 10h | depends on: First crates.io release of rdy-spec and rdy-engine for rdy-cloud | exit test: `rdy run acme-platform` with a synthetic token from RDY_TOKEN fetches a signed spec from staging, shows the key fingerprint before pinning, and uploads only after a yes.
- [M2] rdy report re-renders HTML from a result JSON | owner: rust-engineer | est: 2h | depends on: none | exit test: rendering a golden result file reproduces the golden HTML byte for byte.
- [M3] Threat model and design note for custom.exec | owner: security-reviewer | est: 4h | depends on: none | exit test: section added to 05-threat-model.md and reviewed by rust-architect.
- [M3] Implement custom.exec with argv, expectations, caps and hash-bound consent | owner: check-author | est: 14h | depends on: Threat model and design note for custom.exec | exit test: pass, fail, timeout, refused-without-consent, wrong-hash and unsigned-spec fixtures produce the documented statuses and exit codes on Linux, macOS and Windows.
- [M3] rdy-checks-cloud AWS family | owner: check-author | est: 30h | depends on: Verify the AWS SDK runs on rustls with ring | exit test: IAM simulate, quotas, regions and subnet capacity pass against recorded fixtures, reviewed by cloud-iam-expert.
- [M3] Signed self-update | owner: release-engineer | est: 6h | depends on: none | exit test: a tampered release asset is refused and the old binary keeps working.
- [M3] Release rdy-spec and rdy-engine 1.0 | owner: rust-architect | est: 4h | depends on: none | exit test: 1.0 published and the cargo-semver-checks baseline moved to 1.0.
- [M4] rdy-checks-gpu via nvidia-smi and procfs | owner: check-author | est: 20h | depends on: none | exit test: driver, CUDA and VRAM checks pass on recorded fixtures and on one real node, reviewed by gpu-expert.
- [M4] Data store reachability and version checks | owner: check-author | est: 12h | depends on: none | exit test: Postgres, Redis, Kafka and S3-compatible fixtures in CI containers pass and fail as expected.
- [M4] Custom-branded report from data | owner: rust-engineer | est: 6h | depends on: none | exit test: a branding block in the spec changes name, logo and accent colour in the golden HTML and nothing else.
- [M5] rdy-ffi and rdy-wasm builds of the engine | owner: rust-engineer | est: 30h | depends on: none | exit test: the C-ABI and WASM builds pass the same golden result tests as the CLI.
- [M5] Evaluate Sigstore keyless signing and vendor-domain keys for specs | owner: security-reviewer | est: 4h | depends on: none | exit test: an ADR accepts or rejects each with an offline-verification story.
