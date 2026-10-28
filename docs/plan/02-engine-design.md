# 02 Engine design

Owner: rust-architect. Status: draft, waiting for review by security-reviewer (probe facade, verdict rule,
output dir) and cli-ux (verdict wording, interrupt behaviour, output naming). Date: 2026-10-27.

This note designs `rdy-engine`: the `Check` trait, the registry, needs and privilege negotiation,
scheduling, the result flow, the action log, the probe facade, per-OS behaviour, the report renderers,
the custom check seam and the test seams. It builds on ADRs 0003, 0004, 0005, 0007, 0008, 0010 and 0012
and on the invariants in 05-threat-model.md (INV-nn). The wire types (`Report`, `CheckResult`, `Status`,
`SkipReason`, `Verdict`, `Summary`, `Action`, `Need`) live in `rdy_spec::result` per ADR 0012.
01-spec-format.md owns their names and JSON shape. Where this note lists fields, it lists what the engine
must fill; if 01 names them differently, 01 wins and this note follows.

## Decisions in one screen

1. Checks are async. One trait, `run(&self, &CheckContext) -> BoxFuture<CheckOutcome>`. Blocking work
   goes through the probe facade or `rdy_engine::blocking`, both on `spawn_blocking` (ADR 0004).
2. Every check carries a static `CheckInfo`: id, family, summary, needs, wants, default timeout, OS
   support, and a side-effect manifest (paths, commands, env vars, peers). The facade enforces the
   manifest. `--plan` (M2) prints it. The action log proves it.
3. Needs are probed once, before any check starts, and only for needs the run plan contains. A spec with
   no k8s checks never loads a kubeconfig.
4. A block-severity check that did not run (Skipped for any reason except "not applicable", Timeout, or
   Error) makes the verdict NOT READY, exit 2, counted as "required check not run". This adopts the
   proposed rule and extends it from Skipped to Timeout and Error. It supersedes ADR 0008 decision 3 and
   needs ADR 0013.
5. All side effects go through `Probe`. Its backend is a trait with two implementations: `Live` and
   `Replay` (fixtures). Policy and logging sit above the backend, so tests run the same policy code.
6. Net checks speak TLS and HTTP over sockets the facade opens. They do not use reqwest. This amends
   ADR 0009 decisions 1 and 2 and needs ADR 0014.
7. The engine redacts and size-caps every string in the `Report` before returning it (INV-14). The
   redactor is a module in `rdy-engine` that `rdy-bundle` reuses in M2 (ADR 0015 to write).
8. All output goes into one new directory through `cap-std` handles, 0700 and 0600 on Unix, temp file
   plus rename (INV-08, ADR 0016 to write). No other temp files in M1.
9. JSON keeps spec order. HTML groups blockers first. Both come from the same `Report` (ADR 0003).
10. In M1 the host family has data sources on Linux only. Net and k8s run on all four CI targets. Every
    check compiles everywhere; missing OS sources report Skipped "no data source for this OS yet".

## Crate shape

```text
crates/rdy-engine/src/
  lib.rs        pub use rdy_spec::result; re-exports below
  check.rs      Check, CheckInfo, Finding, Level, Partial, CheckError, CheckOutcome, OsSupport
  family.rs     Family trait, Registry
  plan.rs       RunPlan, PlannedCheck (pure, no I/O)
  needs.rs      Capabilities, Availability, core probes (root, commands, network)
  sched.rs      Engine::run: phases, semaphores, timeouts, cancellation, progress events
  probe/        Probe, Cmd, Output, ProbeStream, ProbeError, Backend trait, live.rs, log.rs, kube.rs
  redact.rs     minimal redactor (M1 corpus categories from 05)
  output.rs     OutputDir: create-new dir, atomic writes, modes
  report/       json.rs, html.rs; templates/ (askama)
  testing.rs    Replay backend, FakeCheck, run_fixture, normalize (feature "testing" only)
```

Features: `default = ["runtime", "html"]`. `runtime` holds the scheduler, needs, probe, output and
redact modules (tokio, tokio-util, cap-std, rustix, http, tower-layer, tower-service). `html` holds the
askama renderer. `testing` adds the Replay backend and helpers and is never enabled in the release
binary; CI asserts `cargo tree -p rdy -e features` does not contain `rdy-engine/testing`. `rdy-cloud`
takes `default-features = false, features = ["html"]` (ADR 0012).

## The Check trait and the registry

```rust
use futures_util::future::BoxFuture;
use rdy_spec::result::Need;
use std::time::Duration;

/// What a check is, known without running it. One `static` per check.
pub struct CheckInfo {
    pub id: &'static str,                  // "host.memory"
    pub family: &'static str,              // "host"
    pub summary: &'static str,             // one line, used by `rdy checks list` and the docs
    pub needs: &'static [Need],            // hard: missing means Skipped(MissingNeed)
    pub wants: &'static [Need],            // soft: missing means the result is partial
    pub default_timeout: Duration,         // from 03-check-catalog.md; engine cap is 60 s
    pub os: OsSupport,
    // Side-effect manifest. The facade refuses anything outside it.
    pub reads: &'static [&'static str],    // path prefixes, for example "/proc/meminfo", "/sys/fs/cgroup/"
    pub commands: &'static [&'static str], // program names, for example "getent"; resolved by the facade
    pub env: &'static [&'static str],      // env var names the check may read
    pub peers: Peers,                      // which network peers the check may contact
}

pub struct OsSupport { pub linux: Support, pub macos: Support, pub windows: Support }

pub enum Support {
    Full,
    Partial(&'static str),   // runs, some evidence missing on this OS; the note goes in the result
    NotYet,                  // Skipped(NotYetOnOs): counts as not run
    NotApplicable,           // the concept does not exist here (SELinux on Windows): no verdict effect
}

pub enum Peers { None, SpecEndpoints, Nameservers, KubeApi }

/// The raw result of a check, before the engine applies severity, timeout and redaction (ADR 0008).
pub type CheckOutcome = Result<Finding, CheckError>;

pub struct Finding {
    pub level: Level,                      // from the check's thresholds
    pub message: String,                   // one line with measured values: "31.3 GiB RAM, 32 GiB needed"
    pub observed: serde_json::Value,       // measured values, capped at 200 list items by the check
    pub expected: serde_json::Value,       // effective thresholds after defaults
    pub fix: Option<String>,               // built-in remediation with values filled in
    pub partial: Option<Partial>,
}

pub enum Level { Pass, Warn, Fail }

pub struct Partial { pub missing: Vec<Need>, pub note: String }

#[non_exhaustive]
pub enum CheckError {
    MissingNeed(Need),                     // found at run time, for example EACCES on a root-only file
    NotApplicable(&'static str),
    Unsupported(&'static str),             // no data source on this OS yet
    Probe(ProbeError),                     // the facade refused or failed; refusal is a bug in the check
    Failed { message: String, hint: Option<String> },
}

pub trait Check: Send + Sync + 'static {
    fn info(&self) -> &'static CheckInfo;
    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome>;
}

pub struct CheckContext { /* id, os, caps, probe bound to this check, deadline */ }
impl CheckContext {
    pub fn id(&self) -> &str;
    pub fn os(&self) -> Os;
    pub fn has(&self, need: &Need) -> bool;
    pub fn probe(&self) -> &Probe;
    pub fn remaining(&self) -> Duration;
}

pub enum Os { Linux, Macos, Windows }
impl Os { pub const fn current() -> Os; }
```

Sync or async: async, one trait. The engine spawns each check as
`tokio::spawn(async move { check.run(&ctx).await })`. The task owns the `Arc`s, so the borrowed signature
works and a panic stays inside the task (ADR 0004 point 6). Host checks are async too, but they do no
blocking work themselves: file reads, commands and native calls are facade calls that run on
`spawn_blocking` under the timeout. Pure CPU work over large input (parsing 5,000 `/proc/*/comm` entries)
uses `rdy_engine::blocking(f)`. Clippy `disallowed-methods` in every check crate bans `std::fs`,
`tokio::fs`, `std::process`, `tokio::process`, `std::net` and `tokio::net`, so a check cannot bypass the
facade by accident (INV-06).

Default thresholds live on the typed parameter structs in `rdy-spec` as serde defaults, plus methods for
derived defaults (`HostDisk::recommended_free()` is `min_free` plus 20%). That puts them in the generated
schema and the docs, and makes a default change a reviewed wire change. The check copies the effective
values into `Finding::expected`, so every report shows the thresholds it actually used.

```rust
pub trait Family: Send + Sync + 'static {
    fn name(&self) -> &'static str;                         // "host", "net", "k8s"
    fn checks(&self) -> &'static [&'static CheckInfo];      // every id this family knows
    fn max_concurrent(&self) -> usize { 4 }
    /// Probe needs only this family can probe. k8s owns KubeContext; cloud will own CloudCredentials.
    fn probe<'a>(&'a self, wanted: &'a [Need], probe: &'a Probe) -> BoxFuture<'a, Vec<Capability>> {
        Box::pin(async { Vec::new() })
    }
    fn build(&self, check: &rdy_spec::spec::CheckSpec, spec: &rdy_spec::spec::Spec)
        -> Result<Box<dyn Check>, BuildError>;
}

pub struct Registry { families: Vec<Box<dyn Family>> }
impl Registry {
    pub fn new(families: Vec<Box<dyn Family>>) -> Self;
    pub fn info(&self, id: &str) -> Option<&'static CheckInfo>;
    pub fn all(&self) -> impl Iterator<Item = &'static CheckInfo>;   // `rdy checks list`, docs generation
}
```

`build` receives the whole spec because some checks default from others (`net.tls_intercept` defaults
to the hosts in `net.egress`). `rdy-cli` assembles the built-ins:
`Registry::new(vec![Box::new(HostFamily), Box::new(NetFamily::new(proxy)), Box::new(K8sFamily::new(kube_opts))])`.
`K8sFamily` connects in its `probe` hook and keeps the client in a `OnceLock`, so `rdy-engine` never
depends on `kube`. A trait is justified: three families in M1.

## Needs and privilege negotiation

`Need` is a wire type (it appears in `SkipReason::MissingNeed` and in the capabilities section of the
report), so it lives in `rdy_spec::result` and is `#[non_exhaustive]`.

| Need | Met when | Probed by | Probe method | Never does |
| --- | --- | --- | --- | --- |
| `Root` | Unix: effective uid 0. Windows: elevated token. | engine | `rustix::process::geteuid()`. Windows: `%SystemRoot%\System32\whoami.exe /groups /fo csv` through the facade, looking for SID `S-1-16-12288` (high integrity), which avoids an `unsafe` token call. | ask for sudo, re-exec, prompt |
| `KubeContext` | the operator's kubeconfig (or in-cluster config) loads and `GET /version` answers | k8s family | `kube::Config::infer()` or `--kubeconfig`, `--context`; records context, server URL and user for SEC-24 | read a kubeconfig named by a spec or found in cwd (E5) |
| `Network` | the run allows sockets (no `--no-network` flag; cli-ux owns the name) | engine | none; it is a run option | contact anything to "test" connectivity (I5, INV-10) |
| `Command(name)` | the program exists in the fixed search path | engine | stat of `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin` (Unix) or `%SystemRoot%\System32` (Windows) | search the caller's `PATH` |
| `CloudCredentials(provider)` (M3) | provider credential chain resolves | cloud family | SDK chain, `sts:GetCallerIdentity` | assume a role unless the spec says so |

Rules:

1. **Plan, then probe, then run.** `Engine::plan` maps every spec check to a `CheckInfo` or a skip
   reason with no I/O. The union of `needs` and `wants` of runnable checks is the probe list. Nothing
   else is probed. All probes run concurrently before the first check starts, each under its own
   timeout (kube 10 s). Two phases cost at most one probe timeout and keep the code simple.
2. **Probe results are recorded.** `Report` gets a capabilities list: need, available yes or no, detail
   (for example "uid 1000", "context acme-staging at https://api.acme.example:6443 as user ci-reader"),
   and a hint when missing ("Rerun as root to complete 3 checks: host.ports, host.lsm,
   host.security_agents"). The CLI prints the hint once. It never escalates.
3. **Hard need missing:** the check does not run. Status `Skipped { reason: MissingNeed { need, hint } }`.
4. **Soft need missing:** the check runs. Whatever it could not read goes into `Finding::partial`.
   Rule from 03: a partial check never blocks on data it could not read. Added rule for check authors:
   if the unread data could have turned a pass into a block, the check must return `Level::Warn` with
   "not verified: <what>", not `Level::Pass`. Code review enforces it; fixtures prove it.
5. **Runtime discovery:** a check that hits a permission error on a source it cannot do without returns
   `CheckError::MissingNeed(Need::Root)`, which maps to the same Skipped status as rule 3.
6. **No inter-check dependencies in M1.** The catalog's "every k8s check depends on k8s.access" is
   expressed as a need: every k8s check except `k8s.access` needs `KubeContext`. `k8s.access` has no hard
   need and reports the probe outcome, so a missing kubeconfig shows up as one Block with a fix and the
   rest as Skipped.
7. **Setuid refusal** (INV-09): before planning, if real and effective uid differ, the engine returns
   `EngineError::Setuid` and the CLI exits 70 with a hint.

## The verdict rule for required checks that did not run

Adopted: a block-severity check that did not run makes the run NOT READY, exit 2, and is counted as
"required check not run". Amended in one way: Timeout and Error count as "did not run" too. A required
check that hung or crashed verified nothing, and reporting "warnings only" for it is the false
confidence ADR 0008 itself rules out. Only `Skipped(NotApplicable)` has no effect.

| Status of the check | `severity: block` | `severity: warn` |
| --- | --- | --- |
| Pass | none | none |
| Warn (level Warn, or level Fail under severity warn) | Warnings | Warnings |
| Block (level Fail under severity block) | Blocked | not possible |
| Skipped, reason NotApplicable | none | none |
| Skipped, any other reason (MissingNeed, NotYetOnOs, NeedsNewerRdy, RunDeadline, Cancelled) | Blocked, `required_not_run += 1` | Warnings, `not_run += 1` |
| Timeout | Blocked, `required_not_run += 1` | Warnings, `not_run += 1` |
| Error | Blocked, `required_not_run += 1` | Warnings, `not_run += 1` |

Verdict: Blocked if any cell says Blocked; else Warnings if any cell says Warnings; else Ready. One more
rule: if no check reached Pass, Warn or Block (empty spec, or everything not applicable), the verdict is
at least Warnings, because nothing was verified. `rdy_spec::result::verdict()` implements this and
`Verdict::exit_code()` maps 2, 1, 0. Proposed headline for cli-ux: `NOT READY: 1 blocker, 2 required
checks not run`. Consequence: an M1 binary on the canonical example spec (with `gpu.cuda` and `aws.iam`
at block) is NOT READY, which `examples/specs/acme-platform.yaml` already documents. ADR 0008's
`--strict` question becomes moot for block checks.

## Scheduling, timeouts and cancellation

```rust
pub struct Engine { registry: Registry, backend: Arc<dyn Backend> }

pub struct RunOptions {
    pub jobs: usize,                    // global cap, default 8 (ADR 0004), `--jobs`
    pub deadline: Duration,             // whole run, default 5 min
    pub network: bool,                  // false makes Need::Network unavailable
    pub cancel: tokio_util::sync::CancellationToken,
    pub on_progress: Option<Box<dyn Fn(&Progress) + Send + Sync>>,
    pub clock: Clock,                   // System, or Fixed(ts) for golden tests
    pub run_id: Option<String>,         // fixed in tests, uuid v4 otherwise
}

pub enum Progress { Probing(Need), Started { id: String }, Finished { id: String, status: StatusKind } }
pub enum Clock { System, Fixed(jiff::Timestamp) }

impl Engine {
    pub fn new(registry: Registry, backend: Arc<dyn Backend>) -> Self;
    pub fn plan(&self, spec: &rdy_spec::LoadedSpec, os: Os) -> RunPlan;
    pub async fn run(&self, spec: &rdy_spec::LoadedSpec, opts: RunOptions) -> Result<Report, EngineError>;
}

pub fn blocking<T, F>(f: F) -> BoxFuture<'static, Result<T, CheckError>>
where F: FnOnce() -> Result<T, CheckError> + Send + 'static, T: Send + 'static;
```

- **Concurrency.** A global semaphore of `jobs` permits, plus one per family: host 4, net 4, k8s 3.
  Inside the facade: at most 4 child processes and 16 open sockets at once, across all checks. `rdy-cli`
  sets `max_blocking_threads(32)` on the runtime so hung NFS `statvfs` calls cannot pile up hundreds of
  threads. Constants, not flags; only `--jobs` is user-facing.
- **Start order.** Spec order, through the semaphores. Deterministic, and the spec author controls it.
- **Per-check timeout.** `min(spec timeout, CheckInfo::default_timeout, 60 s, time left in the run)`.
  rdy-spec validation rejects a spec timeout above 60 s (01 to confirm). The check future runs inside
  `tokio::time::timeout`. On expiry the task is aborted, child processes die (kill on drop, process group
  on Unix), and the status is `Timeout { after_ms }`. The in-flight action is closed in the log with
  outcome Timeout, so the report says "timed out while running `getent ahostsv4 registry.acme.example`".
  A stuck `spawn_blocking` thread is abandoned (ADR 0004 point 5).
- **Facade call timeouts.** Each call has its own default (file read 5 s, command 10 s, connect 10 s),
  clipped to the check's remaining time.
- **Run deadline.** When it passes, running checks become Timeout and unstarted checks become
  `Skipped(RunDeadline)`. Both count as not run.
- **Cancellation.** The CLI cancels the token on the first Ctrl-C (and SIGTERM on Unix). The engine
  stops starting checks, aborts running ones, marks them `Skipped(Cancelled)`, sets
  `Report::interrupted = true` and returns. The CLI writes the report and exits by verdict (usually 2,
  since required checks did not run). A second Ctrl-C exits 70 at once with no report. cli-ux to
  confirm.
- **Panics.** Caught at the join handle and turned into `Error { message: "internal error in <id>, please
  report", hint }` (ADR 0008 point 6).
- **Report order.** `Report::checks` keeps spec order, so JSON diffs and portal ingestion are stable.
  The HTML groups by outcome (see renderers).

## Result model: how values flow

1. The vendor writes thresholds in the spec. `rdy-spec` parses them into the typed params with defaults.
2. `Family::build` hands the params to the check struct.
3. The check measures, compares, and returns `Finding { level, message, observed, expected, fix, partial }`.
4. The engine maps level and severity to `Status` (table above), times it, and fills the
   `CheckResult`: `id`, `name`, `family`, `severity`, `status`, `message`, `observed`, `expected`,
   `fix`, `fix_source`, `partial`, `duration_ms`.
5. `fix`: the spec's `fix` replaces the built-in text (03 convention), verbatim, no templating, so a
   spec cannot inject values. `fix_source` is `spec` or `rdy`. The HTML labels spec text "From
   <product>" so a reader knows the vendor wrote it, not Rdy.
6. Size caps before redaction: `observed` and `expected` 64 KiB serialized each, `message` 1 KiB, `fix`
   4 KiB. Over the cap the value is truncated and `truncated: true` is set.
7. Redaction pass over every string in the report, action log included (INV-14).
8. `verdict()` and `Summary` (pass, warn, block, required_not_run, not_run, not_applicable).

Fields the engine needs that the overview's sketch of `CheckResult` and `Report` lacks, for 01 to name:
`family`, `fix_source`, `partial { missing, note }`, `truncated`, `SkipReason` variants (MissingNeed,
NotYetOnOs, NotApplicable, NeedsNewerRdy, RunDeadline, Cancelled), `Summary::required_not_run` and
`not_run`, `Report::capabilities`, `Report::actions`, `Report::interrupted`, and run environment (os,
arch, rdy version, uid or "elevated", hostname after redaction).

## The action log

Threat 05 R1 and INV-06: every command run, file read, endpoint contacted and kube request is recorded
into the result. The facade writes it; checks cannot skip it.

```rust
// Wire type in rdy_spec::result; 01 owns the JSON. Shown here for what the engine records.
pub struct Action {
    pub seq: u32,
    pub check: Option<String>,          // None for startup probes
    pub at_ms: u64,                     // offset from run start
    pub duration_ms: u64,
    pub kind: ActionKind,
    pub outcome: ActionOutcome,         // Ok, Denied { rule }, Failed { error }, Timeout
}

#[non_exhaustive]
pub enum ActionKind {
    Exec { program: String, argv: Vec<String>, exit: Option<i32>, stdout_bytes: u64, truncated: bool },
    Read { path: String, bytes: u64, truncated: bool },
    ReadDir { path: String, entries: u32 },
    Stat { path: String },
    Env { name: String },               // the name only, never the value
    Lookup { host: String, answers: u32 },
    Connect { host: String, port: u16, addr: Option<String>, via_proxy: Option<String> },
    Tls { host: String, sni: String },
    Http { method: String, url: String, status: Option<u16> },   // url without query string
    Dns { server: String, name: String, rtype: String },
    Kube { method: String, path: String, status: Option<u16> },
    Native { api: String },             // for example "sysinfo::System::refresh_memory"
    Coalesced { kind: String, under: String, count: u32 },
}
```

- Exec, Connect, Tls, Http, Dns and Kube entries are never coalesced. They are few and they are what a
  security reviewer reads.
- Read, ReadDir and Stat entries beyond 200 per check are coalesced per parent directory ("4,812 reads
  under /proc"), so `host.security_agents` does not produce a 5 MB log.
- The log is in the JSON (`Report::actions`) and in the HTML as a collapsed `<details>` section per
  check (no JavaScript needed).
- Kube exec credential plugins run inside `kube`, outside the facade (ADR 0010 point 5). At connect time
  the k8s probe records an `Exec` entry with outcome `Ok` and a note that the kube client may run the
  named plugin, so the log does not hide it.
- `rdy run --plan` (M2, SEC-40) prints the union of the manifests in the run plan. A test asserts that
  every action in a fixture run is inside its check's manifest.

## The probe facade

One engine-owned interface for every side effect a check performs (TB2 in 05). Policy and logging live
in `Probe`. The backend does the raw I/O.

```rust
#[derive(Clone)]
pub struct Probe { /* Arc<Shared { backend, policy, log, semaphores }>, scope: this check's info and deadline */ }

impl Probe {
    // Files: read-only. Paths must start with a prefix in CheckInfo::reads and pass the deny list.
    pub async fn read(&self, path: &Path) -> Result<FileBytes, ProbeError>;          // first 1 MiB
    pub async fn read_tail(&self, path: &Path, max: usize) -> Result<FileBytes, ProbeError>; // last max, cap 1 MiB
    pub async fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, ProbeError>;  // cap 10,000 entries
    pub async fn read_link(&self, path: &Path) -> Result<PathBuf, ProbeError>;
    pub async fn stat(&self, path: &Path) -> Result<Option<FileMeta>, ProbeError>;
    pub fn env(&self, name: &str) -> Result<Option<String>, ProbeError>;              // name must be in CheckInfo::env

    // Commands: argv only, program must be in CheckInfo::commands.
    pub async fn exec(&self, cmd: Cmd) -> Result<Output, ProbeError>;

    // Network: targets must pass the peer policy.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, ProbeError>;        // system resolver
    pub async fn connect(&self, target: &Target, timeout: Duration) -> Result<ProbeStream, ProbeError>;
    pub fn permit_nameserver(&self, server: SocketAddr) -> Result<Permit, ProbeError>; // before a hickory query

    // Native OS calls (sysinfo, statvfs, Windows registry). Live runs `f`; Replay loads recorded JSON.
    pub async fn native<T, F>(&self, api: &'static str, f: F) -> Result<T, ProbeError>
    where T: Serialize + DeserializeOwned + Send + 'static,
          F: FnOnce() -> Result<T, String> + Send + 'static;

    // Protocol detail recorded by a check crate on top of a ProbeStream (TLS, HTTP, DNS answers).
    pub fn note(&self, kind: ActionKind, outcome: ActionOutcome);

    // Kubernetes: a tower layer installed once on the run's kube client by rdy-checks-k8s.
    pub fn kube_guard(&self) -> KubeGuardLayer;
}

pub struct Cmd { pub program: &'static str, pub args: Vec<String>, pub timeout: Option<Duration> }
pub struct Output { pub status: Option<i32>, pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub truncated: bool }
pub struct ProbeStream { /* AsyncRead + AsyncWrite; TcpStream live, DuplexStream in replay; byte counters */ }
pub enum Target { Host { host: String, port: u16 }, Proxy { proxy: Url, host: String, port: u16 } }

#[non_exhaustive]
pub enum ProbeError {
    Denied { rule: &'static str, what: String },   // policy refusal; logged; a bug in the check or a hostile spec
    NotFound,
    PermissionDenied,                              // checks map this to MissingNeed(Root) or partial
    Timeout,
    Io(String),
    NotRecorded(String),                           // Replay only: the fixture lacks this call
}

/// Raw I/O. Two implementations: Live (release) and Replay (feature "testing").
pub trait Backend: Send + Sync + 'static {
    fn read<'a>(&'a self, path: &'a Path, range: ReadRange) -> BoxFuture<'a, io::Result<FileBytes>>;
    fn read_dir<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Vec<DirEntry>>>;
    fn read_link<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<PathBuf>>;
    fn stat<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Option<FileMeta>>>;
    fn env(&self, name: &str) -> Option<String>;
    fn exec<'a>(&'a self, cmd: &'a ResolvedCmd) -> BoxFuture<'a, io::Result<Output>>;
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
    fn connect<'a>(&'a self, addr: SocketAddr, host: &'a str) -> BoxFuture<'a, io::Result<ProbeStream>>;
    fn native<'a>(&'a self, api: &'static str, live: NativeFn) -> BoxFuture<'a, Result<serde_json::Value, String>>;
}
```

`Probe` replaces the overview's `Exec` trait: same idea (two implementations from day one), wider scope.

Policies enforced in `Probe`, so Live and Replay share them:

| Area | Policy | Invariant |
| --- | --- | --- |
| Exec | Program resolved to an absolute path from the fixed search path, always, not only as root. Refused outright: `sh`, `bash`, `zsh`, `dash`, `cmd`, `powershell`, `pwsh`, `sudo`, `su`, `doas`, `pkexec`, `runas`. Environment cleared, then `LC_ALL=C`, `PATH=<fixed>` (Windows: `SystemRoot` only). No `LD_*`, `DYLD_*`. stdin null. cwd `/` (Windows: `%SystemRoot%`). Own process group on Unix, group killed on timeout. stdout cap 1 MiB, stderr cap 64 KiB, then the pipe is drained and dropped. | INV-07, S2, D1 |
| Files | Read-only opens. Path must match a `reads` prefix. Deny list checked on the path and on its canonical target: `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`, `*/.ssh/*`, `*.key`, `*.pem` with a private key header, `/root/.kube/*`, `~/.kube/*`, `/proc/*/environ`, `/proc/*/mem`. 1 MiB cap. Runs on `spawn_blocking` under the timeout (hung NFS). | INV-06, I1 |
| Env | Name must be in `env`. Logged by name. Values pass the redactor before any write. | I1 |
| Network | Allowed peers are built once from the verified spec: hosts in net check params, the proxy in effect, system nameservers read at startup, and the kube API server (through the guard). After lookup, every resolved address is checked again: link-local `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254` and other metadata addresses are refused even when listed (rebinding defense). Endpoint count capped at 64 per spec. Per-stream read cap 1 MiB, except `net.bandwidth`, which declares its own byte cap. Redirect targets are not in the allowlist unless the spec lists them. | INV-10, INV-11, I6, D1 |
| Kube | `KubeGuardLayer` is a tower layer over `http::Request` inside the kube client. Allowed: GET (no `watch=true`); POST to `selfsubjectaccessreviews`, `selfsubjectrulesreviews`, `selfsubjectreviews`; POST with `dryRun=All` only for checks whose spec turned on dry run. Refused: any path containing `/secrets`, `pods/exec`, `pods/attach`, `pods/portforward`, `/proxy`, `pods/log`. ConfigMaps: list as metadata only; GET by name only for names in the check's manifest (`kube-system/kubeadm-config`). Response body cap 32 MiB. Each request logged with method, path without query values, status. | INV-13, E1, I4 |

Kube attribution: kube wraps its service in a tower `Buffer`, so the guard's `call` runs on the buffer
worker. The guard enforces policy in `call` and writes the log entry from the response future, which is
polled on the calling check's task, where the engine's task-local check id is readable. A test asserts
attribution, so a kube or tower change cannot break it silently; the fallback is `check: None`.

TLS and HTTP: net checks run `tokio-rustls` over a `ProbeStream` (with the CONNECT written by
`rdy-checks-net` when a proxy is in effect) and HTTP/1.1 through `hyper::client::conn::http1` on top.
The net crate's HTTP helper returns status and selected headers and drains bodies without storing them
(INV-12). Direct nameserver queries use `hickory-resolver` after `permit_nameserver`; the contact-set
test (SEC-22) catches any socket opened outside the facade.

## How checks degrade on each OS

- Each check struct and its evaluation logic compile on every target. OS-specific gathering sits in
  `#[cfg(target_os = "linux")]`, `"macos"`, `"windows"` functions. Each family has one
  `#[cfg(not(any(...)))]` stub per gather function returning `Err(CheckError::Unsupported(..))`.
- `CheckInfo::os` is the source of truth. The engine reads it at plan time: `NotYet` gives
  `Skipped(NotYetOnOs)`, `NotApplicable` gives `Skipped(NotApplicable)`, and the check is never called.
  A unit test per family, run on each CI OS, asserts that every check marked `Full` or `Partial` on the
  current OS does not return `Unsupported` on its fixture.
- Evaluation is pure and takes plain fact structs (`MemoryFacts`), so macOS and Windows logic is tested
  on Linux CI from recorded facts before real sources exist.
- The spec's `os` filter (01 owns the field) gives `Skipped(NotApplicable)`. That is how a vendor says
  "this check is Linux only" without making a macOS run NOT READY.

M1 coverage:

| Family | Linux | macOS | Windows |
| --- | --- | --- | --- |
| host | Full for the M1 tier | `NotYet` for all (03 marks them M1-late) | `NotYet` for all; `host.lsm`, `host.cgroups` `NotApplicable` |
| net | Full | Full, except `net.proxy` `Partial` (env only until scutil parsing lands) | Full, except `net.proxy` `Partial` (env only until registry parsing lands) |
| k8s | Full | Full | Full |

So the host family is Linux-only in M1. A Linux spec run on a laptop reports the host checks as
"required checks not run", which is true.

## How the engine runs on each OS

- **Process model.** One foreground process. No daemon, no service, no scheduled task, no background
  thread outliving the run, no listener sockets. Children only through the facade, plus kube exec
  credential plugins. The tokio runtime is built by `rdy-cli` (ADR 0004) and dropped with
  `shutdown_timeout(1s)`.
- **Startup order.** Setuid refusal, ring provider install, spec load and verify (rdy-spec), plan,
  probes, checks, mapping and redaction, report write.
- **Output.** `rdy-cli` creates `./rdy-report-<product>-<UTC timestamp>/` (or `--out <dir>`) and
  fails if it exists (INV-08). Inside: `rdy-report-<product>-<UTC timestamp>.json` and `.html`
  (ADR 0003 names, so a file mailed alone keeps its context), and a copy of the verified spec and its
  `.minisig` (05, surface 2). `OutputDir` in `rdy-engine` uses `cap_std::fs::Dir`: create the directory
  with mode 0700, open it as a handle, create each file with `create_new` and mode 0600 under a
  `.name.tmp` name, write, fsync, rename inside the same handle. Handles never follow a symlink out of
  the directory. Windows: the directory inherits the parent's ACL; the docs say so and M2 can tighten it.
- **Human output** goes to stderr with progress from `Progress` events. Untrusted strings are stripped
  of control characters by the CLI (INV-16). With `--json`, the same JSON goes to stdout as well.
  `tracing` logs go to stderr only; M1 writes no log files.
- **Temp files.** None in M1 besides the `.tmp` files inside the output directory. Commands run with cwd
  `/`. `custom.exec` (M3) gets a fresh 0700 temp directory from `tempfile`, removed after the check.
- **Exit codes.** Engine returns `Report` or `EngineError`. The CLI maps: verdict 0, 1, 2; spec, flag or
  signature errors 64; setuid, unwritable output, runtime failure 70 (ADR 0008). If the report cannot be
  written but `--json` is set, the JSON still goes to stdout before exit 70.
- **Linux.** Full host sources through `/proc` and `/sys`. Static musl (ADR 0006). Process group kill on
  timeout.
- **macOS.** Same Unix code paths. System Integrity Protection and TCC can deny reads even as root;
  those surface as `PermissionDenied` and become partial results, not errors.
- **Windows.** Commands by absolute path under `%SystemRoot%\System32` only. Timeout kills the child
  with `kill_on_drop`; grandchildren are not killed in M1 (job objects are an M2 ticket). Ctrl-C through
  `tokio::signal::ctrl_c`.

## Report renderers

Both in `rdy-engine::report` (ADR 0003), both pure functions of `Report`, both deterministic.

```rust
pub mod report {
    pub fn write_json(report: &Report, out: &mut dyn std::io::Write) -> Result<(), ReportError>; // pretty, struct field order, BTreeMap only
    pub fn render_html(report: &Report) -> Result<String, ReportError>;                        // feature "html"
}
pub struct OutputDir { /* cap_std::fs::Dir */ }
impl OutputDir {
    pub fn create_new(parent: &Path, name: &str) -> Result<Self, ReportError>;
    pub fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), ReportError>;
}
```

- HTML sections in this order: verdict headline and summary; Blockers; Required checks not run (with the
  missing need and its hint); Warnings, including warn checks not run; Passed; Not applicable;
  Capabilities; Action log (collapsed per check). Inside each section, spec order. Every status carries a
  text label (ADR 0003 point 5). Spec-written fix text is labelled with the product name.
- The full JSON is embedded in `<script type="application/json" id="rdy-result">`. Escaping is JSON
  level: `<`, `>` and `&` become `<`, `>` and `&`, so `JSON.parse` of the element text
  returns the exact report and no `</script>` can appear. (ADR 0003 decision 3 lost these escapes in its
  text; see corrections.)
- The renderers do not redact; the `Report` is already redacted when the engine returns it. `rdy report`
  (M2) re-renders a JSON file and must run the redactor again on input it did not produce.

## Custom checks later (ADR 0005)

None in M1. `custom.exec` arrives in M3. What the engine keeps open now:

1. Unknown ids map to `Skipped(NeedsNewerRdy)`, so an M1 binary given a `custom.exec` check reports it
   as a required check not run, never a pass and never a parse error.
2. `Probe::exec` is the only command path. `custom.exec` will reuse it with a second policy: commands
   from the spec instead of `CheckInfo::commands`, allowed only when the run has `--allow-exec` or an
   interactive yes, cwd in a fresh temp directory, 64 KiB caps (ADR 0005). The `Cmd` origin becomes an
   enum then (`Builtin` or `Spec`); not before.
3. The run plan already lists every command a run will execute, so the M3 consent prompt is the plan,
   filtered to spec commands.
4. `Need::Root` on a custom check only makes it skip when not root. The engine has no escalation path to
   reuse.
5. No dynamic loading, no WASM, no scripting. `Check`, `Family` and `Probe` are public Rust API for the
   workspace crates with no stability promise until the 1.0 decision in M3 (ADR 0007).

## Testing seams

What qa-engineer builds on:

- **Replay backend** (feature `testing`). Reads the 03 fixture layout
  `tests/fixtures/<check-id>/<case>/`: `root/` maps absolute paths (`/proc/meminfo` is
  `root/proc/meminfo`); `commands/*.json` holds `{argv, stdout, stderr, exit, delay_ms}`; `net.json`
  scripts each `host:port` as `refused`, `blackhole` (never completes), `reset`, or `serve: <name>` to
  connect a duplex stream to an in-process test server (for example an `rcgen` TLS server); `native/`
  holds recorded JSON per api name; `env.json`; `caps.json` sets which needs are available. Anything not
  recorded fails with `NotRecorded`, so a fixture cannot silently fall through to the real machine.
- **Same policy in tests.** Replay sits under `Probe`, so every fixture run also tests the manifest,
  the deny lists and the caps.
- **Kubernetes** fixtures are a `tower` mock service handed to `kube::Client::new`, with
  `KubeGuardLayer` in front, so the guard is under test in every k8s fixture (ADR 0010 read-only test).
- **Time.** Tests use `#[tokio::test(start_paused = true)]`. A `delay_ms` beyond the timeout gives
  Timeout without waiting.
- **Helpers.**

```rust
// rdy_engine::testing, feature "testing"
pub fn replay(dir: &Path) -> Arc<dyn Backend>;
pub async fn run_fixture(check: Box<dyn Check>, dir: &Path) -> FixtureRun;   // result + action log
pub struct FixtureRun { pub result: CheckResult, pub actions: Vec<Action> }
impl FixtureRun { pub fn assert_within_manifest(&self); }                    // INV-06 per fixture
pub struct FakeCheck { pub info: &'static CheckInfo, pub behaviour: Fake }   // scheduler tests
pub enum Fake { Outcome(CheckOutcome), Sleep(Duration), Panic, Block }       // Block: spawn_blocking that never returns
pub fn normalize(report: &mut Report);                                       // zero durations and timestamps
```

- **Goldens.** `insta` snapshots of `CheckResult` per fixture case (`expect.json` in 03), and of the
  whole `Report` and HTML for the ready, warning and blocked runs, with `Clock::Fixed` and a fixed
  `run_id`.
- **Live integration.** Loopback servers (TLS with a test CA, CONNECT proxy, closed port, black hole)
  with the Live backend, run on all four CI targets. The kind cluster job for k8s (ADR 0010).
- **Record mode** for capturing fixtures from a real box is M2, dev-only, and its output is scrubbed to
  acme names before commit.

## Plan corrections found

- docs/adr/0008-errors-and-result-model.md, Decision 3: a skipped, timed-out or errored block-severity
  check yields Warnings, exit 1. Fix: Blocked, exit 2, counted as required check not run, as in the
  verdict table above; write ADR 0013 and mark 0008 decision 3 superseded. The `--strict` note in its
  Consequences becomes moot for block checks.
- docs/adr/0003-report-format-html-json.md, Decision 3: says `<`, `>` and `&` are "escaped as `<`, `>`,
  `&`", which is no escaping at all (the entities were lost). Fix: "escaped as the JSON escapes
  `<`, `>`, `&`". HTML entities would be wrong too: script element text is not
  entity-decoded.
- docs/adr/0009-http-client-and-tls.md, Decisions 1 and 2: `net.egress` uses reqwest and a shared
  `net::client` builder. reqwest opens its own sockets, which bypasses the probe facade (INV-06, INV-10)
  and cannot be replayed. 03 already moved to a tokio-rustls connector. Fix: ADR 0014, net checks use
  tokio-rustls and hyper's client conn API over `ProbeStream`; reqwest stays only for the M2 upload
  client, which is not a check.
- docs/adr/0010-kubernetes-client-kube-rs.md, Decisions 2 and 4: the client is "shared through the
  engine Context" and only two review kinds may be POSTed. Fix: the k8s family owns the client (the
  engine has no kube dependency); the allowlist is the one in the facade table above, which also admits
  `SelfSubjectRulesReview` and opt-in `dryRun=All`, matching 05 INV-13 and 03 `k8s.admission`.
- docs/plan/00-overview.md, rdy-engine API sketch: `Exec` trait, `Context { host_root, exec }`,
  `Check::{id, needs, supported_on}`, `run(self: Arc<Self>, Arc<Context>)`, `Need` in rdy-engine,
  `Finding { Pass, Fail }`. Fix: `Backend` behind `Probe`, `CheckContext`, `Check::info()` returning
  `CheckInfo`, `run(&self, &CheckContext)`, `Need` in `rdy_spec::result`, `Finding` with a Warn level
  and `partial`, as specified here.
- docs/plan/00-overview.md, rdy-checks-k8s sketch: public `connect()` and `K8sFamily::new(Option<Client>)`.
  Fix: `K8sFamily::new(KubeOptions)` connecting in its `probe` hook, so the cluster is touched only when
  the plan needs it.
- docs/plan/00-overview.md, Workspace dependencies: lists `nix`; 03 uses `rustix`, and `cap-std` already
  depends on `rustix`. Fix: `rustix` only; add `cap-std`, `tokio-util`, `http`, `tower-layer`,
  `tower-service` and `hyper` (direct, for net checks).
- docs/plan/00-overview.md, M1 calendar: does not count the engine's security tickets. 05's SEC-17, 18,
  19, 20, 23 and 25 add 20 h, and this note adds about 44 h of new tickets (below), so M1 lands near
  160 h against 60 to 90. Fix, in cut order: graceful Ctrl-C (keep plain abort), generic native calls
  (keep only `statvfs`), the HTML action log section (JSON keeps it), per-family limits (global
  semaphore only), Windows elevation probe (report Root as unknown on Windows). Even then M1 needs the
  founder's call to extend toward Jan 2027 or move k8s checks after `0.1.0`.
- docs/plan/05-threat-model.md, INV-05 and surface 2 E1: "unknown check ids ... are errors (exit 64)".
  ADRs 0005, 0007 and 0008 make them `Skipped(NeedsNewerRdy)`. With the verdict rule here an unknown
  block-severity id gives NOT READY, so there is no false pass. Fix: INV-05 keeps duplicate keys,
  anchors and multi-document input as errors and says unknown ids are Skipped and count as required
  checks not run. Unknown fields inside a check follow ADR 0007 point 6 unless 01 decides otherwise.
- docs/plan/05-threat-model.md, S2: fixed PATH "if euid is 0". Fix: always, because a user-writable
  PATH entry is just as wrong for a non-root run and one rule is simpler to test.
- docs/plan/05-threat-model.md, SEC-53 and the corrections list put custom exec at M4; ADR 0005 and
  00-overview say M3 and call it `custom.exec`; 03 says `custom.script` at M4. Fix: one name,
  `custom.exec`, and one milestone. M3 per ADR 0005, with SEC-53 moved to M3 ahead of the build ticket.
- docs/plan/03-check-catalog.md, `net.egress` and `net.registry`: follow redirects and probe the redirect
  host. That contacts hosts the spec did not list (INV-10, I6). Fix: record the `Location` host, do not
  connect unless the spec lists it, and say "redirects to cdn.acme.example; add it to endpoints to test
  it".
- docs/plan/03-check-catalog.md, Conventions, "Redaction in evidence": calls the `rdy-bundle` redactor
  the second line. In M1 the redactor is `rdy_engine::redact` (ADR 0015), applied to the whole report.
- docs/plan/03-check-catalog.md, Conventions: `severity: info`, `optional` and `partial` are assumed.
  The engine handles `partial` as specified here. `info` and `optional` need 01 to decide; if added, both
  sit in the "warn" column of the verdict table or below it, never in the block column.
- docs/plan/03-check-catalog.md, k8s intro: "every other check depends on k8s.access". Fix: expressed
  as the `KubeContext` need; there is no check dependency graph.
- docs/adr/0004-async-runtime-tokio.md, Decision 3: default timeout 10 s, spec override. Not wrong, but
  03 sets per-check defaults (5, 15, 30 s) and a 60 s cap. Fix: `CheckInfo::default_timeout` per check,
  10 s only as the fallback, 60 s hard cap validated by rdy-spec.

## Tickets implied

Tickets reused from 00-overview.md, the ADRs and 05 keep their exact titles so 11-backlog.md can dedupe.
Their scope is now as specified here.

- [M1] Write ADR 0013 required checks that did not run make the verdict Blocked | owner: rust-architect | est: 1h | depends on: none | exit test: ADR 0013 is Accepted, ADR 0008 shows "Decision 3 superseded by 0013", and the ADR index lists it.
- [M1] Write ADR 0014 the probe facade owns every check side effect | owner: rust-architect | est: 1h | depends on: none | exit test: the ADR records hyper over probe streams for net checks, amends ADR 0009 decisions 1 and 2, and carries a security-reviewer sign-off.
- [M1] Write ADR 0015 minimal redactor lives in rdy-engine | owner: rust-architect | est: 1h | depends on: none | exit test: the ADR is Accepted and 05's "redaction placement ADR" dependency of SEC-25 points to it.
- [M1] Write ADR 0016 output directory confinement with cap-std | owner: rust-architect | est: 1h | depends on: none | exit test: the ADR is Accepted with the Windows ACL limitation stated, and SEC-19 points to it.
- [M1] Check trait, Need and Context in rdy-engine | owner: rust-engineer | est: 3h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture family with one passing and one need-missing check produces Pass and Skipped through Engine::run.
- [M1] Family trait, registry and run plan | owner: rust-engineer | est: 3h | depends on: Unknown check ids report Skipped with a "needs a newer rdy" reason | exit test: the plan for examples/specs/acme-platform.yaml on Linux marks host, net and k8s checks runnable and gpu.cuda and aws.iam NeedsNewerRdy; on Windows host checks are NotYetOnOs; an `os: [linux]` check on macOS is NotApplicable; no I/O happens.
- [M1] Amend verdict mapping for required checks not run | owner: rust-engineer | est: 2h | depends on: Write ADR 0013 required checks that did not run make the verdict Blocked, Define result model and verdict mapping in rdy-spec | exit test: a table test covers every severity and status pair from 02, including NotApplicable and the empty-run rule, and asserts summary counts and exit codes.
- [M1] Capability probes for root, commands and network | owner: rust-engineer | est: 3h | depends on: Family trait, registry and run plan, SEC-17 Build the probe facade and action log | exit test: CI as non-root reports Root unavailable with a rerun hint, the sudo CI job reports it available, a recorded `whoami /groups` output maps high integrity to available, and needs absent from the plan are not probed.
- [M1] Family probe hook and lazy KubeContext probe | owner: rust-engineer | est: 2h | depends on: Capability probes for root, commands and network, Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a spec with no k8s checks makes zero kube requests and loads no kubeconfig; with no kubeconfig k8s.access blocks with the fix and every other k8s check is Skipped MissingNeed KubeContext.
- [M1] Scheduler with concurrency limit, per-check timeout and panic isolation | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture check that sleeps forever reports Timeout and a check that panics reports Error while the other checks still pass.
- [M1] Family limits, run deadline and Ctrl-C cancellation | owner: rust-engineer | est: 3h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: with paused time a deadline marks running checks Timeout and unstarted ones Skipped RunDeadline, a cancelled token yields a report with interrupted true, and k8s never has more than 3 checks in flight.
- [M1] Map outcomes to CheckResult with fix source, partial and size caps | owner: rust-engineer | est: 2h | depends on: Check trait, Need and Context in rdy-engine, Amend verdict mapping for required checks not run | exit test: a spec fix replaces the built-in text with fix_source spec, a 100 KiB observed value is truncated with truncated true, and a partial finding carries its missing needs.
- [M1] SEC-17 Build the probe facade and action log | owner: rust-engineer | est: 4h | depends on: Write ADR 0014 the probe facade owns every check side effect, Check trait, Need and Context in rdy-engine | exit test: a fixture run's JSON action log lists every command, file, endpoint and kube request the checks used, reads past 200 per check are coalesced, and a lint fails on `std::process::Command` outside the facade.
- [M1] SEC-18 Enforce command execution policy in the facade | owner: rust-engineer | est: 3h | depends on: SEC-17 Build the probe facade and action log | exit test: tests show no shell, fixed PATH always, scrubbed loader env, sudo-family refused, timeout and 1 MiB output cap enforced.
- [M1] Blocking helper and subprocess kill on timeout | owner: rust-engineer | est: 3h | depends on: SEC-18 Enforce command execution policy in the facade | exit test: a check running `sleep 600` times out, the child and its process group are gone on Unix, and `rdy` exits within 2 s of the deadline.
- [M1] File and env read policy in the facade | owner: rust-engineer | est: 3h | depends on: SEC-17 Build the probe facade and action log | exit test: /etc/shadow and a symlink pointing to it are Denied and logged, a path outside the check's prefixes is Denied, a 2 MiB file returns 1 MiB with truncated true, and an undeclared env name is Denied.
- [M1] Network permits in the facade for connect, lookup and nameservers | owner: rust-engineer | est: 3h | depends on: SEC-17 Build the probe facade and action log | exit test: an unlisted host, 169.254.169.254 and a listed name that resolves to a link-local address are Denied, a listed loopback endpoint connects and is logged, and more than 64 endpoints fail validation.
- [M1] Native call recording in the facade | owner: rust-engineer | est: 2h | depends on: SEC-17 Build the probe facade and action log | exit test: a statvfs native call is logged with its api name in Live and returns recorded JSON in Replay.
- [M1] SEC-23 Enforce Kubernetes request allowlist | owner: rust-engineer | est: 4h | depends on: SEC-17 Build the probe facade and action log | exit test: a mock API server behind KubeGuardLayer records every request from the k8s suite, the test asserts read verbs, access reviews and opt-in dry-run only with no secrets access, and every entry carries its check id.
- [M1] Replay backend and fixture loader | owner: rust-engineer | est: 4h | depends on: File and env read policy in the facade, Native call recording in the facade, Network permits in the facade for connect, lookup and nameservers | exit test: a host.memory fixture runs with no real file read, an unrecorded argv fails with NotRecorded, a scripted blackhole yields Timeout under paused time, and the release binary's feature tree excludes `testing`.
- [M1] Engine test helpers FakeCheck, run_fixture and normalize | owner: qa-engineer | est: 2h | depends on: Replay backend and fixture loader | exit test: the scheduler tests use FakeCheck for every status and `assert_within_manifest` fails on a fixture check that reads an undeclared path.
- [M1] Clippy disallowed-methods for check crates | owner: rust-engineer | est: 1h | depends on: SEC-17 Build the probe facade and action log | exit test: adding `std::fs::read` or `tokio::net::TcpStream::connect` to rdy-checks-host fails clippy in CI.
- [M1] SEC-19 Confine all writes to a new output directory | owner: rust-engineer | est: 4h | depends on: Write ADR 0016 output directory confinement with cap-std | exit test: a pre-planted symlink is not followed, an existing dir is refused, modes are 0700 and 0600, the verified spec copy is present, and a killed run leaves no partial file.
- [M1] SEC-20 Refuse setuid execution | owner: rust-engineer | est: 1h | depends on: none | exit test: unit test shows exit 70 with a fix hint when real and effective uid differ.
- [M1] SEC-25 Build minimal redactor for reports and evidence | owner: rust-engineer | est: 4h | depends on: Write ADR 0015 minimal redactor lives in rdy-engine | exit test: every evidence string passes through it before write and the M1 corpus passes with zero misses.
- [M1] Apply the redactor to every Report string before return | owner: rust-engineer | est: 2h | depends on: SEC-25 Build minimal redactor for reports and evidence, Map outcomes to CheckResult with fix source, partial and size caps | exit test: canary secrets placed in an observed value, a fix text, an env-derived message and an argv in the action log are redacted in both JSON and HTML.
- [M1] HTML report grouping with blockers first and a collapsed action log | owner: rust-engineer | est: 3h | depends on: askama HTML report with inline CSS, dark mode and print, SEC-17 Build the probe facade and action log | exit test: the golden blocked HTML shows Blockers, then Required checks not run, then Warnings, spec-written fix text is labelled with the product name, and the JSON keeps spec order.
- [M1] OS support table and compile stubs for rdy-checks-host | owner: check-author | est: 2h | depends on: Family trait, registry and run plan | exit test: all four CI targets build, on macOS and Windows every NotYet host check reports Skipped "no data source for this OS yet", and on Linux none do.
- [M1] Security review of 02-engine-design.md | owner: security-reviewer | est: 2h | depends on: none | exit test: a review file in docs/plan/reviews/ covers the facade policies, the verdict rule and output confinement, and every blocker is resolved in this note.
- [M1] cli-ux review of verdict wording, interrupt behaviour and output naming | owner: cli-ux | est: 1h | depends on: none | exit test: 07-cli-ux.md confirms or replaces the headline wording, the second Ctrl-C exit code, the `--no-network` and `--out` names.
- [M2] SEC-40 Add `rdy run --plan` preview | owner: rust-engineer | est: 6h | depends on: Family trait, registry and run plan | exit test: plan output matches the action log of a real run on the same fixtures.
- [M2] Windows job objects so a timeout kills the whole process tree | owner: rust-engineer | est: 3h | depends on: Blocking helper and subprocess kill on timeout | exit test: a Windows fixture command that spawns a grandchild leaves no process behind after its timeout.
- [M2] Dev-only fixture record mode with a scrub step | owner: qa-engineer | est: 4h | depends on: Replay backend and fixture loader | exit test: recording host.memory on a CI runner produces a fixture that replays to the same result, and the scrub step replaces the hostname with an acme name.
- [M2] rdy-bundle collectors read through the probe facade | owner: rust-engineer | est: 4h | depends on: File and env read policy in the facade | exit test: every collected file appears in the action log and deny-listed paths are refused.
- [M2] Restrict output directory ACL on Windows | owner: rust-engineer | est: 3h | depends on: SEC-19 Confine all writes to a new output directory | exit test: on Windows CI another local user cannot read the report files.
- [M3] Spec-origin exec policy, consent list and temp workdir for custom.exec | owner: rust-engineer | est: 4h | depends on: Threat model and design note for custom.exec | exit test: without `--allow-exec` no spec command runs and the refusal lists them; with it, commands run in a fresh temp dir with 64 KiB caps.
- [M3] CloudCredentials need and cloud family probe hook | owner: rust-engineer | est: 3h | depends on: Family probe hook and lazy KubeContext probe | exit test: with no AWS credentials every aws check is Skipped MissingNeed with a hint and no AWS endpoint is contacted.
- [M3] Decide the 1.0 stability scope of Check, Family and Probe | owner: rust-architect | est: 3h | depends on: none | exit test: an ADR states whether these modules are semver-covered at 1.0 or move under `rdy_engine::unstable`, before rdy-engine 1.0 ships.
