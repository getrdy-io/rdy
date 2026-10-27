# Rdy plan overview

Owner: rust-architect. Date: 2026-10-27. Sources: `docs/plan/rdy-plan.md` (the plan), `CLAUDE.md`,
`KICKOFF.md`. Decisions referenced as ADR NNNN live in `docs/adr/`.

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
  prototype the plan allows (two weekends, separate scratch repo, not this one), start M1 on Nov 23 only
  on a "go".
- **Option 2:** start M1 now and treat the gate as a later checkpoint. Faster, but spends the hours the
  plan reserves for interviews, and risks six weeks of Rust for a market that fails the kill rule.

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
| M1 CLI alpha | Spec format, host, network and Kubernetes checks, HTML and JSON report, signed specs | One design partner catches a real install blocker with it | On Linux x86_64 and aarch64 (musl), macOS and Windows, `rdy run` on a signed fixture spec writes JSON and HTML and exits 0, 1 and 2 on the ready, warning and blocked fixtures; an unsigned spec exits 64. |
| M2 Portal MVP | Share links, results dashboard, redacted bundles, bundle viewer, Slack alerts | Design partners run it on 20 prospect environments | `rdy run <product> --token` fetches a signed spec from staging, the redaction golden suite passes, nothing uploads without the flag or a yes. |
| M3 Launch | AWS account checks, Stripe billing, docs, public open-source launch, Team tier on sale | First 10 paying vendors | AWS checks pass against recorded fixtures, docs site builds its reference from the schema, `rdy-spec` and `rdy-engine` are 1.0, `custom.exec` behind `--allow-exec`. |
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

## M1 calendar: six weeks, a binary every week

Build order is the plan's. Hours are founder hours including review of agent-written code. "This doc"
counts the tickets at the end of this file; "other slices" is a rough figure for check, CI and release
tickets from 03-check-catalog.md and 06-release-and-distribution.md.

| Week | Dates | Build order step | Ships at the end of the week | Tickets from this doc | Hours (this doc + other slices) |
| --- | --- | --- | --- | --- | --- |
| 1 | Nov 23 to 29 (Thanksgiving Nov 26) | 1. Workspace, CI, release pipeline | `rdy version` on five targets via GitHub Releases and `install.sh`, cosign-signed, statically linked on Linux. Usable to prove the binary runs inside a design partner's locked-down box. | Create workspace skeleton; Package rdy in crates/rdy-cli with binary name rdy; Add deny.toml with crate bans and license allowlist; Reserve crates.io names with 0.0.1 placeholders; Prove static musl binaries on x86_64 and aarch64; Update CLAUDE.md commands to cargo run -p rdy | 9 + 4 = 13 |
| 2 | Nov 30 to Dec 6 | 2. Spec parser and result model, JSON schema | `rdy spec lint <file>` with line and column errors. `rdy run <file> --allow-unsigned --json` lists every check as Skipped "not built yet" with the right exit code. Published JSON schemas for editors. | Define public spec types in rdy-spec; Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits; Define result model and verdict mapping in rdy-spec; Generate JSON schemas with schemars and check drift in CI; Error types with fix hints and exit code mapping at the CLI edge | 14 + 0 = 14 |
| 3 | Dec 7 to 13 | 3. Host checks and HTML report | The demo: host checks run for real, HTML and JSON reports written. | Check trait, Need and Context in rdy-engine; Scheduler with concurrency limit, per-check timeout and panic isolation; Blocking helper and subprocess kill on timeout; askama HTML report with inline CSS, dark mode and print | 14 + 8 = 22 |
| 4 | Dec 14 to 20 | 4. Network checks | Egress through the customer's proxy, DNS, TLS interception detection. | Shared HTTP client builder with rustls ring, dual roots and proxy env; musl resolver behaviour fixture for net.dns; Embed result JSON in the HTML report safely; Golden tests for JSON and HTML reports; Unknown check ids report Skipped with a "needs a newer rdy" reason | 11 + 6 = 17 |
| 5 | Dec 21 to 27 (Christmas) | 5. Kubernetes checks | k8s version, storage classes, RBAC for the install identity, node resources. | Kube client from kubeconfig or in-cluster with rustls and timeouts; Read-only guard test for rdy-checks-k8s; cargo-semver-checks in CI for rdy-spec and rdy-engine; Keep golden result files per released version and parse them in CI | 7 + 8 = 15 |
| 6 | Dec 28 to Jan 3 (New Year) | 6. Spec signing and `rdy verify` | `0.1.0`: signed specs, `rdy verify`, unsigned specs refused unless `--allow-unsigned`. This is the build design partners get. | Verify minisign signatures in rdy-spec against a trust store with product binding; Trust store load and save in user and system locations; rdy spec keygen and rdy spec sign; rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner; Security review of spec signing and trust store | 13 + 2 = 15 |

Total: about 96 hours in the table, about 104 with the ADR reviews, the example spec and the parser
property tests, which are not tied to a week. The constraint gives 60 to 90 (six weeks at 10 to 15 hours), and two of the six
weeks are holiday weeks. Cut list, in order, if a week runs over: property and fuzz tests for the
parser (keep five hand-written malformed fixtures instead); TLS issuer naming in `net.tls_intercept`;
the system-wide trust store location; print stylesheet polish; then move week 6 into Jan 4 to 10, 2027.
Builds from weeks 2 to 5 are tagged `0.1.0-alpha.N`, run specs only with `--allow-unsigned` (so rule 3
holds before signing exists), and are not handed to design partners for real POCs.

## Crates and their public API

Rules for every crate: edition 2024, `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`, clippy
`unwrap_used` and `expect_used` denied outside tests, one public error enum. No third-party types in the
public API of `rdy-spec` except serde traits and `serde_json::Value`, so a dependency bump never breaks
the contract. A crate is created in the workspace when its milestone starts, not before; placeholders
on crates.io hold the names.

**rdy-spec (M1, contract crate).** Owns every `rdy/v1` wire type: the spec, the typed parameters of
every known check id, and the result report (ADR 0012). Parses YAML with limits (ADR 0001), runs
semantic validation, verifies minisign signatures against a trust store with per-product pinning
(ADR 0002), and exposes the generated JSON schemas. No async, no tokio, no filesystem access except
`TrustStore::load`. `rdy-cloud` uses it to validate specs and ingest results.

```rust
pub const API_VERSION: &str = "rdy/v1";

pub fn parse(bytes: &[u8]) -> Result<spec::Spec, SpecError>;
pub fn validate(spec: &spec::Spec) -> Result<(), SpecError>;
pub fn load(bytes: &[u8], sig: Option<&[u8]>, trust: &sig::TrustStore, policy: sig::Policy)
    -> Result<LoadedSpec, SpecError>;              // parse + validate + verify
pub fn spec_schema_json() -> String;
pub fn result_schema_json() -> String;

pub struct LoadedSpec { pub spec: spec::Spec, pub sha256: String, pub signature: result::SignatureState }

pub mod spec {
    pub struct Spec { pub api_version: String, pub kind: Kind, pub metadata: Metadata,
                      pub checks: Vec<CheckSpec>, pub bundle: Option<BundleSpec> }
    pub struct Metadata { pub product: String, pub version: Option<String> }
    pub struct CheckSpec { pub id: CheckId, pub name: Option<String>, pub severity: Severity,
                           pub fix: Option<String>, pub timeout: Option<Duration>, pub params: CheckParams }
    #[non_exhaustive]
    pub enum CheckParams { HostMemory(HostMemory), HostDisk(HostDisk), NetEgress(NetEgress),
                           K8sStorageClass(K8sStorageClass), /* one variant per known id */
                           Unknown { id: String, unknown_fields: Vec<String> } }
    pub enum Severity { Warn, Block }
    pub struct CheckId(String);                    // "family.name"
    pub struct Quantity(u64);                      // bytes; parses "32Gi"
}

pub mod result {
    pub struct Report { pub api_version: String, pub run_id: String, pub rdy_version: String,
                        pub spec: SpecRef, pub started_at: String, pub duration_ms: u64,
                        pub verdict: Verdict, pub summary: Summary, pub checks: Vec<CheckResult> }
    pub struct CheckResult { pub id: CheckId, pub name: Option<String>, pub severity: Severity,
                             pub status: Status, pub message: String, pub observed: Option<serde_json::Value>,
                             pub expected: Option<serde_json::Value>, pub fix: Option<String>, pub duration_ms: u64 }
    #[non_exhaustive]
    pub enum Status { Pass, Warn, Block, Skipped { reason: SkipReason }, Timeout { after_ms: u64 },
                      Error { message: String, hint: Option<String> } }
    #[non_exhaustive]
    pub enum SignatureState { Verified { key_id: String, signed_at: String }, Unsigned }
    pub enum Verdict { Ready, Warnings, Blocked }
    impl Verdict { pub fn exit_code(self) -> u8; }  // 0, 1, 2
    pub fn verdict(checks: &[CheckResult]) -> Verdict;
}

pub mod sig {
    pub struct TrustStore { /* product -> pinned keys */ }
    impl TrustStore {
        pub fn load(paths: &[PathBuf]) -> Result<Self, SignatureError>;
        pub fn pin(&mut self, product: &str, key: PublicKey, note: &str);
        pub fn save(&self, path: &Path) -> Result<(), SignatureError>;
    }
    pub struct PublicKey { /* minisign public key */ }
    impl PublicKey { pub fn from_base64(s: &str) -> Result<Self, SignatureError>; pub fn key_id(&self) -> String; }
    pub enum Policy { RequireSigned, AllowUnsigned }
}
```

**rdy-engine (M1, contract crate).** Runs checks and renders reports. Defines the `Check` and `Family`
traits (each has several implementations across the family crates), the needs model, the scheduler
(tokio, concurrency limit, per-check timeout, panic isolation, ADR 0004), the mapping from check outcomes
to `Status` (ADR 0008), and the JSON and HTML renderers (askama, ADR 0003). The scheduler sits behind the
default `runtime` feature so `rdy-cloud` can take only `html`. `Exec` is a trait because it has two
implementations from day one: real subprocesses and recorded fixtures.

```rust
pub use rdy_spec::result;

pub trait Check: Send + Sync + 'static {
    fn id(&self) -> &str;
    fn needs(&self) -> &[Need] { &[] }
    fn supported_on(&self, os: Os) -> bool { true }
    fn run(self: Arc<Self>, ctx: Arc<Context>) -> BoxFuture<'static, Result<Finding, CheckError>>;
}
pub trait Family: Send + Sync {
    fn prefix(&self) -> &'static str;              // "host", "net", "k8s"
    fn build(&self, spec: &rdy_spec::spec::CheckSpec) -> Option<Arc<dyn Check>>;
}
pub trait Exec: Send + Sync {
    fn run(&self, cmd: &Cmd) -> BoxFuture<'_, Result<Output, ExecError>>;
}

#[non_exhaustive]
pub enum Need { Root, KubeContext, Network, Command(&'static str) }
pub enum Finding { Pass { observed: serde_json::Value },
                   Fail { observed: serde_json::Value, expected: serde_json::Value, message: String } }
#[non_exhaustive]
pub enum CheckError { MissingNeed(Need), Unsupported(&'static str), Failed { message: String, hint: Option<String> } }

pub struct Context { pub os: Os, pub available: Vec<Need>, pub host_root: PathBuf, pub exec: Arc<dyn Exec> }
pub struct RunOptions { pub jobs: usize, pub default_timeout: Duration, pub deadline: Duration,
                        pub on_progress: Option<Box<dyn Fn(Progress) + Send + Sync>> }
pub struct Engine { /* families */ }
impl Engine {
    pub fn new(families: Vec<Box<dyn Family>>) -> Self;
    pub async fn run(&self, spec: &rdy_spec::LoadedSpec, ctx: Context, opts: RunOptions) -> result::Report;
}
pub fn blocking<T, F>(f: F) -> BoxFuture<'static, Result<T, CheckError>>
where F: FnOnce() -> Result<T, CheckError> + Send + 'static, T: Send + 'static;

pub mod report {
    pub fn write_json(report: &Report, out: &mut dyn std::io::Write) -> Result<(), ReportError>;
    pub fn render_html(report: &Report) -> Result<String, ReportError>;
}
```

**rdy-checks-host (M1).** CPU, memory, disk, kernel, cgroups, time sync, ports, SELinux and AppArmor,
known antivirus agents, in the M1 subset that 03-check-catalog.md picks. Reads `/proc` and `/sys` under
`Context::host_root` so fixtures are just directories, and runs commands only through `Exec`. Uses
`sysinfo` for portable numbers, `nix` on Unix and `windows-sys` on Windows. No stability promise.

```rust
pub struct HostFamily;
impl rdy_engine::Family for HostFamily { /* host.* */ }
```

**rdy-checks-net (M1).** Egress through the customer's proxy, DNS, TLS interception detection. MTU and
bandwidth sample move to M2 unless 03-check-catalog.md ranks them higher. One shared client builder
(ADR 0009), `hickory-resolver` for DNS with musl caveats reported (ADR 0006). No stability promise.

```rust
pub struct NetFamily { proxy: ProxyConfig }
impl NetFamily { pub fn new(proxy: ProxyConfig) -> Self; }
pub struct ProxyConfig { pub https: Option<String>, pub http: Option<String>, pub no_proxy: Vec<String> }
impl ProxyConfig { pub fn from_env() -> Self; }
pub fn client(proxy: &ProxyConfig, roots: Roots, timeout: Duration) -> Result<reqwest::Client, NetError>;
pub enum Roots { Mozilla, Os }
```

**rdy-checks-k8s (M1).** Server version, storage classes, RBAC through `SelfSubjectAccessReview`,
admission policies, node resources, device plugins. Read-only by construction and by test (ADR 0010).
The CLI probes for a cluster once and hands the client in; with no cluster, every k8s check is Skipped.

```rust
pub async fn connect(context: Option<&str>, timeout: Duration) -> Result<kube::Client, K8sError>;
pub struct K8sFamily { client: Option<kube::Client> }
impl K8sFamily { pub fn new(client: Option<kube::Client>) -> Self; }
```

**rdy (crate dir `rdy-cli`, M1).** The binary (ADR 0011). clap commands in M1: `run`, `verify`,
`spec lint`, `spec sign`, `spec keygen`, `trust add|list|remove`, `version` (names provisional until
07-cli-ux.md). Builds the tokio runtime, installs the ring crypto provider, probes needs (euid, kube,
proxy env), assembles the families, writes reports, maps errors to exit codes with `anyhow` at the edge,
and prints progress with `indicatif` on stderr. M2 adds `bundle`, `upload`, `report`; M3 adds
`self-update` and `spec init`. No library API.

**rdy-bundle (M2).** Collectors (journal, Kubernetes events, files by glob), redactors (AWS keys, bearer
tokens, emails, custom regex) applied before any byte is written, `tar` plus `zstd`, and a manifest that
lists every file and every redaction count. Designed in 04-bundle-and-redaction.md. `Collector` and
`Redactor` are traits because each has several implementations at launch.

```rust
pub fn build(spec: &rdy_spec::spec::BundleSpec, ctx: &BundleContext, out: &Path) -> Result<Manifest, BundleError>;
pub trait Redactor: Send + Sync { fn name(&self) -> &str; fn redact<'a>(&self, input: &'a str) -> Cow<'a, str>; }
```

**rdy-checks-cloud (M3).** AWS first: IAM policy simulation for the install identity, service quotas,
region availability, VPC and subnet capacity. GCP and Azure later through REST. Read-only APIs only,
which is also what Option B reuses. Blocked on the TLS provider question in ADR 0009.

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
| serde-saphyr | 1 | rdy-spec | YAML parser, pure Rust, budgets (ADR 0001) | Young, mostly one maintainer. Fallback `serde_yaml_ng`. |
| serde_yaml | | none | named in the plan | **Deprecated** (March 2024). Banned in deny.toml. |
| serde_yml | | none | common successor | **Archived**, RUSTSEC-2025-0068. Banned. |
| schemars | 1 | rdy-spec | JSON Schema from types (ADR 0012) | 1.x changed API from 0.8; use 1.x from the start. |
| minisign-verify | 0.2 | rdy-spec | ed25519 signature verification, no deps (ADR 0002) | |
| minisign | current | rdy-cli | key generation and signing | |
| ed25519-dalek | | none | named in the plan | Not deprecated; replaced by minisign format (ADR 0002). |
| sha2 | current | rdy-spec | spec digest in results | |
| thiserror | 2 | libraries | typed errors | |
| anyhow | 1 | rdy-cli | edge errors | |
| tokio | 1 | engine, net, k8s, cli | runtime (ADR 0004) | Only rdy-cli enables `rt-multi-thread`. |
| futures-util | 0.3 | rdy-engine | `BoxFuture` | |
| tracing, tracing-subscriber | 0.1, 0.3 | all, cli | logging, `RUST_LOG` | |
| askama | current (0.14 or later) | rdy-engine | compile-time HTML templates (ADR 0003) | Rinja merged back into askama in 2025; take the current line, not the old 0.12. |
| jiff | current | rdy-spec, rdy-engine | timestamps and durations (`10s`, `7d`) | Pre-1.0 at last check; fallback `time`. |
| uuid | 1 | rdy-engine | run ids | |
| semver | 1 | rdy-spec | `metadata.version` ranges | Kernel and CUDA versions are not semver; own lenient compare. |
| sysinfo | current | rdy-checks-host | CPU, memory, disk | Frequent breaking releases. Pin and update on purpose. |
| nix | current | rdy-checks-host | Unix syscalls (euid, statvfs) | |
| windows-sys | current | rdy-checks-host | Windows APIs | |
| reqwest | 0.13 | rdy-checks-net, later upload | HTTP egress (ADR 0009) | **Default TLS changed** to rustls on aws-lc-rs. Use no default features, ring provider. |
| rustls, tokio-rustls | 0.23, 0.26 | net, cli | TLS, interception detection | Provider: ring only. |
| webpki-roots, rustls-native-certs | current | rdy-checks-net | Mozilla roots vs OS roots | webpki-roots license is CDLA-Permissive-2.0; allow it in deny.toml. |
| x509-parser | current | rdy-checks-net | issuer of an intercepting CA | Cut-list candidate. |
| hickory-resolver | current | rdy-checks-net | DNS checks (ADR 0006) | Pre-1.0, API churn between minors. |
| kube, k8s-openapi | current | rdy-checks-k8s | Kubernetes client (ADR 0010) | Heavy; frequent MSRV bumps. Client feature only. |
| clap | 4 | rdy-cli | commands and flags | |
| indicatif | current | rdy-cli | progress on stderr | |
| anstream | current | rdy-cli | colour and `NO_COLOR` | Comes with clap. |
| proptest, insta, assert_cmd, predicates, tempfile | current | dev only | property, golden and binary tests | |
| tar, zstd | 0.4, current | rdy-bundle (M2) | bundle archive | `zstd` builds C libzstd; fine for static musl with a C compiler. |
| regex, aho-corasick | 1 | rdy-bundle (M2) | redaction | |
| self_update | | rdy-cli (M3) | named in the plan | **Risky.** Must verify a signature before replacing the binary. Decide in 06-release-and-distribution.md between it and cargo-dist's updater. |
| aws-sdk-iam, -servicequotas, -ec2 | current | rdy-checks-cloud (M3) | AWS checks | **Risky:** defaults to aws-lc-rs, conflicts with ADR 0009. Spike in M2. |
| nvml-wrapper | | none | named in the plan | **Cannot work** in a static musl binary (needs `dlopen`). Dropped (ADR 0006). |
| mimalloc | | rdy-cli, only if measured | allocator | Only if the M2 benchmark says so. |

Tooling, not crates: `cargo-dist` (release-engineer owns). Axo stopped development in 2025 and a
community maintainer resumed releases; treat it as a risk and keep a hand-written release workflow as
the fallback. `cargo-zigbuild` for local cross builds, `release-plz` from M2, `cargo-semver-checks`,
`cargo-deny`, `cargo-audit`, `cargo-auditable`, `cargo-cyclonedx`.

## Plan corrections found

- KICKOFF.md, "After the plan": starts M1 once the backlog is approved, but docs/plan/rdy-plan.md
  ("Risks, validation gates" and "Next 30 days") says no Rust until the gates are met, go or no-go on
  Nov 20, 2026. Fix: KICKOFF should start M1 only after a recorded "go"; founder decides between the
  two options at the top of this file.
- docs/plan/rdy-plan.md, Milestones table: every exit test is a business outcome CI cannot check. Fix:
  add the engineering done test column above.
- docs/plan/rdy-plan.md, Rust build plan: "Ship a usable CLI in about 12 weeks" while M1 is six weeks.
  Fix: say "M1 alpha in six weeks, a CLI ready for prospects at the end of M2".
- KICKOFF.md constraints and docs/plan/rdy-plan.md M1 scope: about 96 to 104 hours of work against a 60 to 90
  hour budget, with two holiday weeks. Fix: founder accepts the cut list in the calendar section, or
  M1 runs to Jan 10, 2027.
- docs/plan/rdy-plan.md, "Build order inside M1": signing is last, but CLAUDE.md rule 3 says refuse
  unsigned specs. Fix: weeks 2 to 5 run only with `--allow-unsigned` and are tagged alpha, not given to
  design partners.
- docs/plan/rdy-plan.md, Architecture: "One Cargo workspace. The CLI and the portal share the spec and
  result types". The repo split makes it two workspaces. Fix: "Two workspaces; `rdy-cloud` consumes
  `rdy-spec` and `rdy-engine` from crates.io".
- docs/plan/rdy-plan.md, crate table: lists `rdy-server` (private repo) and `rdy-ffi`, `rdy-wasm` with no
  home. Fix: mark `rdy-server` as rdy-cloud; put the Embed SDK crates in the public repo at M5.
- docs/plan/rdy-plan.md, "How a POC flows" step 1: `rdy run acme-platform --token abc123` needs the
  portal (M2). Fix: M1 runs a local file, `rdy run acme-platform.yaml`.
- docs/plan/rdy-plan.md, Product definition example spec: contains `gpu.cuda` and `aws.iam`, which no
  M1 build can run. Fix: `examples/specs/acme-platform.yaml` for M1 uses only host, net and k8s checks
  plus one unknown id to show Skipped.
- docs/plan/rdy-plan.md, Website plan, Install endpoint: says `get.<domain>`; CLAUDE.md and the names
  table say `getrdy.io/install`. Fix: use `getrdy.io/install` everywhere.
- CLAUDE.md, Repo layout: lists every crate from day one. Fix: crates enter the workspace when their
  milestone starts; crates.io placeholders hold the names.
- CLAUDE.md, Engineering standards: "Linux x86_64 and aarch64 (musl), macOS, Windows. CI runs all four."
  macOS ships two arches and GitHub no longer offers free Intel macOS runners for long. Fix: five
  release targets; CI tests four natively (Linux x86_64, Linux aarch64, macOS aarch64, Windows x86_64);
  `x86_64-apple-darwin` is built but smoke-tested only.
- CLAUDE.md, Repo layout, `rdy-cli` commands: no command creates a signing key or pins a vendor key.
  Fix: add `spec keygen` and `trust add|list|remove` (provisional, cli-ux to confirm).
- ADR-level corrections (serde_yaml, ed25519-dalek, Sigstore for specs, nvml-wrapper, reqwest TLS
  default, `cargo run -p rdy-cli`, result model location, launch families without a milestone) are
  listed in docs/adr/README.md.

## Tickets implied

- [M1] Create workspace skeleton | owner: rust-engineer | est: 2h | depends on: none | exit test: `cargo build`, `clippy -D warnings`, `fmt --check` and `cargo doc` with warnings as errors pass on a workspace of edition 2024 crates with `forbid(unsafe_code)`, a pinned toolchain and shared lints.
- [M1] Reserve crates.io names with 0.0.1 placeholders | owner: release-engineer | est: 1h | depends on: none | exit test: every crate name in CLAUDE.md resolves on crates.io to a getrdy-io-owned 0.0.1.
- [M1] Add deny.toml with crate bans and license allowlist | owner: release-engineer | est: 2h | depends on: Create workspace skeleton | exit test: adding serde_yaml, openssl-sys, native-tls or aws-lc-sys fails `cargo deny check` in CI.
- [M1] Package rdy in crates/rdy-cli with binary name rdy | owner: rust-engineer | est: 1h | depends on: Create workspace skeleton | exit test: `cargo run -p rdy -- version` prints the version and `cargo package -p rdy --list` contains no stray files.
- [M1] Update CLAUDE.md commands to cargo run -p rdy | owner: docs-writer | est: 1h | depends on: Package rdy in crates/rdy-cli with binary name rdy | exit test: every command in the CLAUDE.md Commands block runs green on a fresh clone.
- [M1] Prove static musl binaries on x86_64 and aarch64 | owner: release-engineer | est: 2h | depends on: Create workspace skeleton | exit test: CI fails unless `ldd` reports a static binary on both arches and the binary runs in a `scratch` container.
- [M1] Define public spec types in rdy-spec | owner: rust-engineer | est: 3h | depends on: Create workspace skeleton | exit test: the plan's example spec deserializes into typed values and round-trips through serde_json.
- [M1] Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a 2 MiB file, a billion-laughs file and a duplicate-key file each return a SpecError with line and column, never a panic.
- [M1] Define result model and verdict mapping in rdy-spec | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: unit tests cover every status to verdict and verdict to exit code combination.
- [M1] Generate JSON schemas with schemars and check drift in CI | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: changing a doc comment without rerunning cargo xtask schema fails CI.
- [M1] Error types with fix hints and exit code mapping at the CLI edge | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: integration tests assert exit 64 for a bad spec, 70 for an unwritable output dir, and a `fix:` line in both.
- [M1] Check trait, Need and Context in rdy-engine | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture family with one passing and one need-missing check produces Pass and Skipped through Engine::run.
- [M1] Scheduler with concurrency limit, per-check timeout and panic isolation | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture check that sleeps forever reports Timeout and a check that panics reports Error while the other checks still pass.
- [M1] Blocking helper and subprocess kill on timeout | owner: rust-engineer | est: 3h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: a check running `sleep 600` times out, the child process is gone, and `rdy` exits within 2 s of the deadline.
- [M1] askama HTML report with inline CSS, dark mode and print | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: the golden HTML renders with no network requests in a headless browser test and passes an HTML validator.
- [M1] Embed result JSON in the HTML report safely | owner: rust-engineer | est: 2h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: a fixture with `</script><img onerror>` in a hostname round-trips through the embedded JSON unchanged and renders as text.
- [M1] Golden tests for JSON and HTML reports | owner: qa-engineer | est: 2h | depends on: Embed result JSON in the HTML report safely | exit test: insta snapshots for ready, warning and blocked fixtures pass on all four CI targets.
- [M1] Unknown check ids report Skipped with a "needs a newer rdy" reason | owner: rust-engineer | est: 2h | depends on: Check trait, Need and Context in rdy-engine | exit test: the plan's example spec, which contains gpu.cuda and aws.iam, runs on M1 and reports both as Skipped, not as a parse error.
- [M1] Shared HTTP client builder with rustls ring, dual roots and proxy env | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: integration test with a local CONNECT proxy and a test CA shows egress passes through the proxy and NO_PROXY is honoured.
- [M1] musl resolver behaviour fixture for net.dns | owner: qa-engineer | est: 2h | depends on: Shared HTTP client builder with rustls ring, dual roots and proxy env | exit test: a fixture resolv.conf and nsswitch.conf with `sss` produce the documented warning.
- [M1] Kube client from kubeconfig or in-cluster with rustls and timeouts | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: against a kind cluster in CI, k8s.version passes; with no kubeconfig every k8s check reports Skipped with the hint.
- [M1] Read-only guard test for rdy-checks-k8s | owner: k8s-expert | est: 1h | depends on: Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a mock API server records only GET and the two self-review POSTs across the full k8s fixture run.
- [M1] cargo-semver-checks in CI for rdy-spec and rdy-engine | owner: release-engineer | est: 2h | depends on: Create workspace skeleton | exit test: a PR that removes a public field without a version bump fails CI.
- [M1] Keep golden result files per released version and parse them in CI | owner: qa-engineer | est: 1h | depends on: Golden tests for JSON and HTML reports | exit test: CI deserializes every file under tests/fixtures/results/ with the current rdy-engine.
- [M1] Verify minisign signatures in rdy-spec against a trust store with product binding | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a tampered byte, a wrong product and an unpinned key each fail with a distinct SignatureError.
- [M1] Trust store load and save in user and system locations | owner: rust-engineer | est: 2h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: running as root reads /etc/rdy/trust.yaml, as a user reads XDG config, in a temp-dir integration test.
- [M1] rdy spec keygen and rdy spec sign | owner: rust-engineer | est: 3h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: a spec signed by rdy verifies with the stock minisign CLI and the reverse.
- [M1] rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | owner: rust-engineer | est: 3h | depends on: rdy spec keygen and rdy spec sign | exit test: unsigned spec exits 64 with a hint; with --allow-unsigned it runs and the JSON says signature: unsigned.
- [M1] Security review of spec signing and trust store | owner: security-reviewer | est: 2h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: review notes filed and every blocker fixed before the M1 tag.
- [M1] Property and fuzz tests for rdy_spec::parse | owner: qa-engineer | est: 3h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: proptest over 10k random inputs in CI finds no panic. (First item on the cut list.)
- [M1] Write examples/specs/acme-platform.yaml with M1 checks only | owner: devrel | est: 1h | depends on: Define public spec types in rdy-spec | exit test: `rdy spec lint` passes on it and it contains one unknown id that reports Skipped.
- [M1] Review ADRs 0002, 0003, 0005 and 0008 for user-visible behaviour | owner: security-reviewer | est: 2h | depends on: none | exit test: each ADR has a review note and any requested change is merged before the first M1 code ticket that depends on it.
- [M1] Review ADRs 0002, 0003, 0008 and 0011 for command surface and output | owner: cli-ux | est: 2h | depends on: none | exit test: provisional command names in ADR 0002 are confirmed or replaced in 07-cli-ux.md.
- [M2] release-plz config for per-crate versions and changelogs | owner: release-engineer | est: 3h | depends on: Reserve crates.io names with 0.0.1 placeholders | exit test: a dry run opens a release PR bumping only the crates that changed.
- [M2] First crates.io release of rdy-spec and rdy-engine for rdy-cloud | owner: release-engineer | est: 2h | depends on: release-plz config for per-crate versions and changelogs | exit test: a scratch crate outside the repo depends on both from crates.io and parses a golden result.
- [M2] Allocator benchmark musl vs glibc in CI | owner: release-engineer | est: 2h | depends on: Prove static musl binaries on x86_64 and aarch64 | exit test: CI prints both timings for the fixture spec and fails above the 20% threshold.
- [M2] Verify the AWS SDK runs on rustls with ring | owner: cloud-iam-expert | est: 3h | depends on: none | exit test: a spike branch builds aws-sdk-iam for both musl targets with no aws-lc-sys in cargo tree, or an ADR records why not.
- [M2] rdy-bundle: collectors, redactors, tar plus zstd, manifest | owner: rust-engineer | est: 24h | depends on: none | exit test: redaction golden suite in 04-bundle-and-redaction.md passes on all four CI targets.
- [M2] Opt-in upload client and share-link spec fetch | owner: rust-engineer | est: 10h | depends on: First crates.io release of rdy-spec and rdy-engine for rdy-cloud | exit test: `rdy run acme-platform --token <synthetic>` fetches a signed spec from staging and uploads only after a yes.
- [M2] rdy report re-renders HTML from a result JSON | owner: rust-engineer | est: 2h | depends on: none | exit test: rendering a golden result file reproduces the golden HTML byte for byte.
- [M3] Threat model and design note for custom.exec | owner: security-reviewer | est: 4h | depends on: none | exit test: section added to 05-threat-model.md and reviewed by rust-architect.
- [M3] Implement custom.exec with argv, expectations, caps and --allow-exec | owner: check-author | est: 12h | depends on: Threat model and design note for custom.exec | exit test: fixtures for pass, fail, timeout and refused-without-flag all produce the expected statuses on Linux, macOS and Windows.
- [M3] rdy-checks-cloud AWS family | owner: check-author | est: 30h | depends on: Verify the AWS SDK runs on rustls with ring | exit test: IAM simulate, quotas, regions and subnet capacity pass against recorded fixtures, reviewed by cloud-iam-expert.
- [M3] Signed self-update | owner: release-engineer | est: 6h | depends on: none | exit test: a tampered release asset is refused and the old binary keeps working.
- [M3] Release rdy-spec and rdy-engine 1.0 | owner: rust-architect | est: 4h | depends on: none | exit test: 1.0 published and cargo-semver-checks baseline moved to 1.0.
- [M4] rdy-checks-gpu via nvidia-smi and procfs | owner: check-author | est: 20h | depends on: none | exit test: driver, CUDA and VRAM checks pass on recorded fixtures and on one real node, reviewed by gpu-expert.
- [M4] Data store reachability and version checks | owner: check-author | est: 12h | depends on: none | exit test: Postgres, Redis, Kafka and S3-compatible fixtures in CI containers pass and fail as expected.
- [M4] Custom-branded report from data | owner: rust-engineer | est: 6h | depends on: none | exit test: a branding block in the spec changes name, logo and accent colour in the golden HTML and nothing else.
- [M5] rdy-ffi and rdy-wasm builds of the engine | owner: rust-engineer | est: 30h | depends on: none | exit test: the C-ABI and WASM builds pass the same golden result tests as the CLI.
- [M5] Evaluate Sigstore keyless signing for specs as an option | owner: security-reviewer | est: 4h | depends on: none | exit test: an ADR accepts or rejects it with an offline-verification story.
