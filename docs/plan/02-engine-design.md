# 02 Engine design

Owner: rust-architect. Revision 2, 2026-10-28: applies the security review
(`docs/plan/reviews/02-engine-design-review-by-security-reviewer.md`, 10 must-fix) and aligns with
01-spec-format.md and the revised ADRs. Status: waiting for security-reviewer re-review and cli-ux review.

This note designs `rdy-engine`: checks and families, privilege and needs, scheduling, the result flow,
the action log, the probe facade, per-OS behaviour, output and reports, and the test seams. It builds on
ADRs 0003, 0004, 0005, 0008, 0010 and 0012, and on ADRs 0013 to 0016, written with this revision.
**01-spec-format.md owns every wire name** (`Report`, `CheckResult`, statuses, `skip_kind`, verdicts,
the action log shape). This note uses its names and says what the engine fills. Invariant numbers
(INV-nn) are those of 05-threat-model.md revision 2. Rust signatures are in Appendix A.

## Review items and where they are closed

| Item | Fix | Section |
| --- | --- | --- |
| MF-01 kube guard | Deny by default on parsed, normalised paths; no dry run; ADR 0010's two POSTs | Kubernetes, Appendix B |
| MF-02 native closures | Closed `NativeCall` enum (ADR 0014) | Native calls |
| MF-03 check-written CONNECT | The facade writes CONNECT, TLS and HTTP (ADR 0014) | Network |
| MF-04 lint wall | Full disallowed lists, lint-wall test crate, allow grep, deny wrappers; no bind fallback | Lint wall |
| MF-05 redaction order, logs | Redact, then cap; log layer; errors redacted (ADR 0015) | From finding to result |
| MF-06 not-applicable escape | Only the spec `os` list gives `not_applicable` (ADR 0013) | Verdict |
| MF-07 non-yielding check | Timer on the join handle, watchdog thread, `process::exit` | Scheduling |
| MF-08 log completeness | Kube entries open in `call`; plugin entry `delegated`; truncation drops only ok reads; strace test | Action log |
| MF-09 privilege-carrying binary | uid, gid and `CapEff` checked before the spec is read | Privilege |
| MF-10 lost escapes | Spelled out; the JSON writer applies them (01 section 5.5) | Output and reports |

Should-fix items SF-01 to SF-13 and nits N-01 to N-08 are applied in place; SF-12 renumbering and ticket
titles are in the ticket list.

## Decisions in one screen

1. Checks are async: `run(&self, &CheckContext) -> BoxFuture<CheckOutcome>`. Every check has a static
   `CheckInfo`: id, family, summary, needs, wants, default timeout, OS support, and a manifest of the
   paths, programs, env names and peer classes it may touch. The facade enforces the manifest, `--plan`
   (M2) prints it, the action log proves it.
2. One privilege snapshot at startup, before the spec is read. It feeds the trust store scope, the
   setuid refusal and the `root` need. Other needs are probed once, after planning, only if the plan
   contains them.
3. Verdict per 01 section 5.3 and ADR 0013: a required check that did not run gives `not_ready`; only
   the vendor's `os` list makes a check not count.
4. All side effects go through `Probe`, including TCP, proxy CONNECT, TLS and HTTP (ADR 0014). Native
   OS calls are a closed enum. The kube client sits behind a deny-by-default guard.
5. Redact every full string, then cap. Writers accept only `RedactedReport` (ADR 0015).
6. The output directory is created and opened right after verification and held (ADR 0016).
7. The scheduler owns the timers; a watchdog thread guarantees a report and an exit even if a check
   never yields.
8. M1 host checks have data sources on Linux only; net and k8s run on all four CI targets.

## Crate shape

```text
crates/rdy-engine/src/
  lib.rs       pub use rdy_spec::result
  check.rs     Check, CheckInfo, Finding, Level, Partial, CheckError, OsSupport
  family.rs    Family, Registry
  plan.rs      RunPlan (pure)
  privilege.rs Privilege snapshot, binary refusal
  needs.rs     Capabilities, core probes
  sched.rs     Engine::run, timers, deadline, watchdog snapshot
  probe/       Probe, policy, action log, Backend, live/, kube.rs (guard), net.rs (tcp, connect, tls, http)
  redact.rs    M1 rule set (no feature gate)
  units.rs     dotted version compare, quantities, nominal band, severity cap (03 asks for one home)
  output.rs    OutputDir
  report/      json.rs, html.rs, templates/
  testing.rs   Replay backend and helpers (feature "testing")
```

Features: `default = ["runtime", "html"]`. `runtime`: scheduler, privilege, needs, probe, output
(tokio, tokio-util, cap-std, rustix, http, tower-layer, tower-service, hyper, tokio-rustls, rustls with
ring only, webpki-roots). `html`: askama. `redact` and `units` need no feature, so `rdy-cloud`
(`default-features = false, features = ["html"]`) and `rdy report` can use them. `testing` is never in
the release binary; CI asserts `cargo tree -p rdy -e features` lacks it.

## Checks, families and the run plan

A check is a struct built from its typed spec params, with one `static CheckInfo`. Async, one trait: the
scheduler spawns `async move { check.run(&ctx).await }`, so the task owns its `Arc`s and a panic stays
inside it. Checks do no blocking work themselves: file reads, commands and native calls are facade
calls on `spawn_blocking`, and pure CPU work over big input uses `rdy_engine::blocking`.

`CheckInfo` fields that matter for policy:

| Field | Meaning |
| --- | --- |
| `needs` | Hard. Missing means `skipped`, `skip_kind: missing_need`. |
| `wants` | Soft. Missing means a `partial` result. A want marked `evidence_only` cannot change the level. |
| `default_timeout` | From 03. The engine falls back to 10 s and caps at 60 s. |
| `os` | `Full`, `Partial(note)` or `NotYet` per OS. There is no "not applicable" here (ADR 0013). |
| `reads`, `env` | Absolute path prefixes and env var names. |
| `commands` | `CommandSpec`: program name, extra search directories (absolute constants), stdout cap, extra env names. |
| `peers` | Peer classes: `SpecHosts`, `Proxy`, `SystemResolver`, `KubeApi`. |

Default thresholds live on the typed params in `rdy-spec` as serde defaults plus methods for derived
defaults, so they appear in the schema and the docs. The check copies effective thresholds into
`Finding::expected`.

`Family` (three in M1, so a trait): `name`, `checks()` (static infos), `probe()` for needs only it can
probe (k8s owns `kube_context`; cloud will own `cloud_credentials`), and `build(check, spec)`, which
returns the check plus its own host set computed from its params, derived defaults included
(`net.tls_intercept` defaults to the `net.egress` hosts). `Engine::plan` maps every spec entry to a
built check or a skip kind with no I/O:

| Situation | `skip_kind` (01) |
| --- | --- |
| Spec `os` list leaves this OS out | `not_applicable` (never counts) |
| Family reserved, not built into this rdy | `not_in_build` |
| Family built, id unknown | `unknown_check` |
| Known id, field or value this rdy cannot read | `unsupported_spec` |
| `CheckInfo::os` is `NotYet` here | `not_yet_on_os` |
| Hard need missing after probing | `missing_need` |
| Run deadline passed before start | `run_deadline` |
| Run interrupted (M2 graceful Ctrl-C) | `cancelled` |

There are no inter-check dependencies. Every k8s check except `k8s.access` needs `kube_context`;
`k8s.access` has no hard need and reports the probe outcome as a block with its fix.

## Privilege and needs

**Snapshot first.** Before the spec is read, `Privilege::snapshot()` records uid, euid, gid, egid and
(Linux) `CapEff` from `/proc/self/status`, all through the run-level facade (`check: null`). If uid and
euid differ, gid and egid differ, or `CapEff` is nonzero for a non-root uid, `rdy` exits 70 with a hint
naming `chmod u-s,g-s` and `setcap -r` (INV-10). On Windows the snapshot runs `whoami.exe /groups /fo csv`
through the facade: integrity SID `S-1-16-12288` (High) or `S-1-16-16384` (System) means elevated. If
`whoami` fails, the run counts as elevated for the trust store and `root` as unknown for checks. The CLI
maps the snapshot to the `rdy-spec` trust store scope (system store only when elevated, INV-04); the
loader never reads ids itself. One privilege answer per run.

| Need (01 name) | Met when | Probed by | Never does |
| --- | --- | --- | --- |
| `root` | snapshot says euid 0 or elevated | the snapshot | ask for sudo, re-exec, prompt; the hint never suggests `sudo -E` |
| `kube_context` | the operator's kubeconfig or in-cluster config loads and `GET /version` answers | k8s family `probe` | read a kubeconfig from a spec or the working directory |
| `network` | the run allows sockets (no `--no-network`) | run option | contact anything to test connectivity |
| `command` (with `name`) | the program exists in its search path | engine, by stat | search the caller's `PATH` |
| `cloud_credentials` (M3) | the provider chain resolves | cloud family | assume a role without consent |

Rules: plan, then probe, then run; all probes run concurrently before the first check, each under its
own timeout; probe results go into `capabilities` with a hint. With `--no-network`, `kube_context` is
unavailable and no kube client is built. The kube probe sends its first request (which may run an exec
credential plugin that waits for an SSO login) from a `spawn_blocking` thread through the runtime handle,
under a 10 s timer held by the scheduler, so a stuck plugin costs one abandoned blocking thread, never a
worker.

## Verdict

The rule is 01 section 5.3, recorded in ADR 0013 (refining ADR 0008 decision 3). What the engine adds:

- It never produces `not_applicable` except from the spec `os` list. A requirement met by absence is a
  `pass` with a note, reviewed per check.
- A level Pass with `partial` set on a required check becomes `warn`, "not verified: <missing>", unless
  every missing want is `evidence_only`.
- Unknown severity counts as block and unknown status as not run, in `rdy_spec::result::verdict()`.
- A run that verified nothing is `ready_with_warnings`, `verdict_reason: nothing_verified`.

Headline (cli-ux to confirm): `NOT READY: 1 blocker, 2 required checks not run`.

## Scheduling, timeouts and hangs

- **Concurrency.** One global semaphore, default 8, `--jobs` capped at 32 (ADR 0004). Facade-wide: at
  most 4 child processes and 16 sockets. `rdy` sets `max_blocking_threads(32)`. Per-family limits are M2.
- **Order.** Spec order through the semaphore.
- **Per-check timeout.** The spec's `timeout` replaces the check default; else `CheckInfo` default; else
  10 s. Capped at 60 s and at the time left in the run. The scheduler awaits each check's `JoinHandle`
  under `tokio::time::timeout`, so the timer lives in the scheduler task, not in the check. On expiry:
  abort, close the in-flight action as `timeout`, cancel the check's probe scope, status `timeout`.
- **Run deadline.** 5 minutes. Running checks become `timeout`, unstarted ones `skipped`,
  `run_deadline`.
- **Watchdog.** A plain OS thread, started before the runtime, fires at deadline plus 10 s. It builds a
  report from the shared snapshot of finished results (already redacted), marks running checks
  `timeout` and unstarted ones `run_deadline`, sets `complete: false`, writes through the held output
  directory and calls `std::process::exit(70)`. On the normal path the CLI writes, flushes and calls
  `std::process::exit(code)`; nothing waits on a runtime drop.
- **Ctrl-C in M1.** The first Ctrl-C cancels the run token: checks abort, child process groups die, the
  CLI exits 70 with "interrupted, no report written". Writing the partial report with
  `interrupted: true` is M2 (01 names). cli-ux to confirm.
- **Panics** become `error`, `error_kind: panic` (ADR 0008 decision 8).

## From finding to result: redact, then cap

1. `rdy-spec` parses thresholds into typed params with defaults; `Family::build` hands them to the check.
2. The check returns `Finding { level, message, observed, expected, fix, partial }`.
3. The engine maps level and severity to `status`, fills the 01 section 5.2 fields (`key`, `id`, `name`,
   `family`, `severity`, `status`, `message`, `fix`, `fix_source`, `builtin_fix`, `observed`,
   `expected`, `needs` with `met`, `partial`, `notes`, `started_ms`, `duration_ms`, and the
   status-specific fields). The vendor's `fix` replaces rdy's text verbatim on `warn` and `block` and is
   hidden when the check did not run (01 section 2.6).
4. Redaction over every full string in the report: results, actions, capabilities, identity, host, proxy.
5. Caps on char boundaries with a marker: message 1 KiB, fix 4 KiB, `observed` and `expected` 64 KiB,
   lists 200 items, then the 2 MiB report cap (Action log rule below).
6. The result is a `RedactedReport`. `write_json`, `render_html` and the watchdog accept nothing else.

`rdy` installs the redacting `tracing` layer first in `main`. With `RUST_LOG` unset, hyper, h2, rustls,
tower and kube are capped at `warn`. `EngineError`, `ReportError` and panic text are redacted before
printing (ADR 0015).

## The action log

Shape and kinds are 01 section 5.4. Rules the engine keeps:

- The facade writes every entry; checks cannot skip it. Run-level work (snapshot, machine id, hostname,
  os-release, command stats, kubeconfig read) is logged with `check: null`.
- `exec` entries record the resolved absolute path and `argv` as a JSON array of strings, redacted.
- Kube entries open in the guard's `call` (no check id yet) and are completed by the response future,
  which runs on the calling check's task and fills `check` from the engine's task-local. A dropped
  request is closed as `timeout`.
- The kube exec credential plugin gets an `exec` entry with the resolved plugin path and redacted args,
  outcome `delegated`, note "run by the kube client, output not captured, may run again on token
  refresh". The kubeconfig read gets a `read` entry. (`delegated` is a new outcome value for 01.)
- Coalescing (past 200 per check, per directory) and the 2 MiB truncation remove only `read`,
  `read_dir` and `stat` entries with outcome `ok`. `exec`, `connect`, `tls`, `http`, `dns`, `kube`,
  `native` entries and every `denied` or `failed` entry are always kept; they are bounded (64 hosts, a
  fixed command list).
- Completeness is tested, not only conformance: Linux CI runs the live fixture suite under
  `strace -f -e trace=execve,openat,connect,sendto` and asserts every target after spec load is in the
  log (folded into SEC-22).

## The probe facade

Policy and the log live in `Probe`, above the `Backend` trait (`Live`, `Replay`), so every fixture run
tests policy. Each check's `Probe` is bound to its `CheckInfo`, its host set and a cancellation token
cancelled when the check ends; a later call returns `denied`, rule `check finished`.

**Exec.**
- argv only; `Cmd.program` is `&'static str`; spec values pass 01's grammars (no leading `-`) and go
  after `--` where the program supports it.
- The program resolves to an absolute path from the fixed search path (`/usr/sbin:/usr/bin:/sbin:/bin`)
  always, then the check's declared extra directories (absolute constants, for operator-managed GPU
  tools). Windows: `%SystemRoot%\System32` only, and in M1 only `whoami.exe`, until job objects land.
- Refused outright: shells (`sh`, `bash`, `zsh`, `dash`, `cmd`, `powershell`, `pwsh`) and `sudo`,
  `su`, `doas`, `pkexec`, `runas`.
- Environment cleared, then `LC_ALL=C`, `PATH=<fixed>` and declared names only; no `LD_*`, `DYLD_*`.
- stdin null; cwd `/`.
- Each child gets its own process group, and the group is killed on timeout. If the child is not reaped
  within 1 s after SIGKILL (uninterruptible sleep), the call returns `Hung { pid }` and a detached task
  reaps it later.
- Output caps: stdout per `CommandSpec` (default 1 MiB, at most 4 MiB), stderr 64 KiB.

**Files.**
- Absolute paths only, and no `..` component; matched before any open.
- On Linux the facade opens with `O_PATH` (no side effect, no device open), reads the real path from
  `/proc/self/fd/<n>`, and `fstat`s it. Prefix and deny list are checked against that real path, then
  the file is reopened through the descriptor with `O_RDONLY | O_NONBLOCK`. Only regular files pass,
  except under `/proc` and `/sys`.
- macOS: `realpath`, open with `O_NOFOLLOW | O_NONBLOCK`, recheck with `F_GETPATH`.
- Windows: no M1 check reads files, so the facade refuses them.
- Deny list: `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`, `*/.ssh/*`, private key files, `~/.kube/*`
  and `/root/.kube/*` (kube reads the kubeconfig itself), `/proc/*/environ`, `/proc/*/cmdline`,
  `/proc/*/mem`, `/proc/*/fd/*`, `/proc/*/root/*`, `/proc/*/map_files/*`, `/proc/kcore`, `/dev/*`.
- 1 MiB cap. Reads run on `spawn_blocking`.
- Env names must be declared; values are redacted before any write.

**Network** (ADR 0014; ADR 0009 decisions 4, 6 and 7 stay).
- The calling check's host set is enforced, and the host must be in it. The spec may name at most 64
  distinct hosts (rdy-spec validation, exit 64).
- The facade resolves the name and refuses every address in ADR 0009's ranges (169.254.0.0/16,
  fe80::/10, fd00:ec2::254, IPv4-mapped forms), literal or resolved.
- `tcp` tries each address with a 250 ms stagger and a per-attempt timeout, and reports every attempt
  (dual stack, catalog hook 2). Checks cannot pick addresses.
- On the proxied path the facade writes CONNECT itself (8 KiB head cap, own timeout, Basic auth from
  `ProxyUrl`, `Proxy-Authorization` never logged). A literal blocked IP target is refused before any
  byte is sent; names resolve at the proxy (05 residual).
- `NO_PROXY` matching lives here.
- `tls_chain` runs the recording verifier, private to the facade, and returns the presented chain and
  whether it validates against the system roots and the bundled roots. It never sends application data.
- `http` sends HTTP/1.1 HEAD or GET over a verified stream. It returns status, a fixed header list,
  stage timings and the `Location` host. It reads at most 64 KiB of body and discards it, never follows
  a redirect, and returns typed failure classes (`dns`, `refused`, `blackhole`, `tls_unknown_issuer`,
  `tls_alert`, `reset_after_hello`, `proxy_403`, `proxy_407`, `http_status`, `blocked_address`).
- System roots: Linux PEM bundles (`SSL_CERT_FILE`, `SSL_CERT_DIR`, the standard paths) are read
  through the facade; macOS and Windows use `NativeCall::SystemRoots`. No revocation check, and the
  report says so.
- PAC is reported, never fetched, in M1 (SF-13).
- UDP (`udp_exchange`, with DNS messages built by `hickory-proto`) and unix sockets (`unix_get`, with a
  GET-only Docker API guard) are M2 facade methods. They must land before `host.time_sync`, direct
  `net.dns` queries and `host.container_runtime`. `permit_nameserver` is gone.

**Native calls.** A closed enum the Live backend executes; each variant is a reviewed change
(security-reviewer is CODEOWNER of the file).
- M1: `Statvfs { path }` (path passes the read rules; logged as `native`, `api: statvfs`, with
  `path`), `Uname`, `Rlimit(resource)`, `Hostname`, `MachineId` (macOS `kern.uuid`, Windows
  `MachineGuid`; Linux reads `/etc/machine-id` as a file), `SystemRoots`.
- No `sysinfo` in M1. In M2 its variants use refresh kinds without environ, cmdline, cwd and root.
- No `bind()` port probes: the `host.ports` bind fallback is dropped, and the result says "owner
  unknown, not verified".

**Kubernetes.** Appendix B has the guard rules: deny by default, on a parsed and normalised path, GET
only on a const resource list in `rdy-checks-k8s`, POST only to `selfsubjectaccessreviews` and
`selfsubjectrulesreviews` (ADR 0010 decision 2), no subresources, no dry run, no probe pod in M1.
`k8s.access` needs a POST to `selfsubjectreviews` for the authenticated user (ADR 0010 decision 4 and
the 01 example). That POST is allowed once the ADR 0010 amendment ticket lands; until then the identity
comes from the kubeconfig context. Construction:
- One constructor, `guarded_service(inner)`, is used by production and by the mock tests.
- A `ReadOnlyClient` newtype with a private constructor is the only client type checks get.
- The k8s family owns the client; the engine has no kube dependency.
- kube opens its own sockets. At probe time the facade resolves the API server host, applies the
  address rule and logs a `connect`. A kube connector built on the facade is an M2 ticket.

**Lint wall** (INV-07).
- `clippy.toml` `disallowed-methods` and `disallowed-types` in every check crate (list in Appendix A).
- A `tests/lint-wall` crate uses each entry, and CI expects each one to fail.
- `allow(clippy::disallowed_` is legal only in allowlisted files: the facade's `live/` module and the
  k8s client module.
- `deny.toml` `[bans]` wrappers keep `rustix`, `socket2`, `hyper`, `tokio-rustls`, `hickory-*`,
  `sysinfo` and `kube` direct dependencies of their owning crates only.

## Per-OS behaviour

- **Compile stubs.** Every check compiles everywhere. OS-specific gather functions sit behind
  `#[cfg(target_os = ..)]`, with a stub returning `CheckError::Unsupported`. `CheckInfo::os` is the
  source of truth at plan time. Evaluation is pure over fact structs, so macOS and Windows logic can be
  tested on Linux from recorded facts.
- **M1 coverage.**

| Family | Linux | macOS | Windows |
| --- | --- | --- | --- |
| host | `Full` for the M1 tier | `NotYet` | `NotYet` |
| net | `Full` | `Full`; `net.proxy` `Partial` (env only) | `Full`; `net.proxy` `Partial` (env only) |
| k8s | `Full` | `Full` | `Full` |

  03 asks for a `sysinfo` subset and code-level "not applicable" on macOS and Windows in M1. Declined:
  MF-02 keeps `sysinfo` out of M1 and ADR 0013 removes code-level not applicable. Vendors scope
  Linux-only checks with `os: [linux]`.
- **Process model.** One foreground process: no daemon, no service, no listener. Children only through
  the facade, plus kube exec plugins.
- **Startup order.** Redacting log layer; privilege snapshot and binary refusal; ring provider; spec
  load (verify, then parse); output directory created and held; plan; probes; checks; redact and cap;
  write; exit.
- **Linux:** `/proc`, `/sys`, `O_PATH` reads, process groups.
- **macOS:** same Unix paths; SIP and TCC denials become `partial`.
- **Windows:** M1 exec is `whoami.exe` only; Ctrl-C through `tokio::signal::ctrl_c`.
- **Temp files.** None in M1 besides `.tmp` files inside the output directory.
- **Exit codes.** Verdict 0, 1, 2; input errors 64; binary refusal, unwritable output, watchdog,
  interrupt and runtime failure 70 (ADR 0008). With `--json`, stdout carries the same bytes as the
  file, or the error object.

## Output and reports

- **Directory** (ADR 0016, ADR 0003).
  - `rdy-report-<product>-<YYYYMMDDTHHMMSSZ>/` goes under `--out-dir`. The slug is
    `^[a-z0-9][a-z0-9-]{0,62}$` (01 section 2.2) and is re-checked before use.
  - The directory is created right after verification, opened no-follow, and `fstat`-checked (owned by
    euid, 0700). The handle is held for the run.
  - Inside go `rdy-report-<product>-<ts>.json` and `.html`, plus the spec and its `.minisig` copied from
    the verified in-memory bytes (`VerifiedSpecBytes`). Each file is created `create_new`, 0600 with
    `fchmod`, written as `.tmp`, fsynced, then renamed; the directory is fsynced last.
  - `--no-report` writes nothing.
- **JSON.** `write_json(&RedactedReport)` follows 01 section 5.5. After serializing, every `<` becomes
  the six characters `\u003c` (backslash, `u`, `0`, `0`, `3`, `c`), every `>` becomes `\u003e`, every `&`
  becomes `\u0026`, and U+2028 and U+2029 become `\u2028` and `\u2029`. The writer applies this to every
  copy, so the `.json` file, `--json` stdout and the HTML embed are the same bytes. The renderer does
  not escape a second time.
- **HTML.**
  - `render_html(&RedactedReport)` follows 01 section 6: content in 01's order (blockers, required not
    run, warnings, passed, not applicable, capabilities, details, action log as one plain table).
  - No `<details>`; vendor fix text is labelled "From <product>".
  - The JSON is embedded with `data-sha256`.
  - The CSP is ADR 0003's.
- `rdy report` (M2) redacts input it did not produce before rendering.

## Catalog hooks (03, "Decisions needing an ADR")

| Hook | Answer |
| --- | --- |
| 1 UDP | Accepted for M2: `udp_exchange(server, payload, max_reply)` with peer classes `ntp_servers` (spec) and system nameservers, logged as `dns` or `connect`. Gates `host.time_sync` and direct `net.dns`. |
| 2 Connect targets | Dual stack accepted inside the facade's `tcp` (per-address attempts reported); `Target::Addr` from check code rejected, because address choice is policy. `unix_get` M2; named pipes M2. |
| 3 Nonblocking record read | Accepted for M2: `read_records(path, max_records, max_bytes)` with `O_NONBLOCK` until `EAGAIN`, `/dev/kmsg` as the only allowed device. No M1-tier check needs it. |
| 4 Exec | Accepted for M1: `Hung { pid }` without waiting, per-command stdout cap, declared extra search directories. |
| 5 Family-scoped shared state | Accepted for M2: `Family::facts()` with a family-scoped `Probe` (union of the fact's own manifest), a detached task with its own timeout, cached, attributed with an additive `fact` field (01). A check that times out waiting does not abort the fact. M1-tier k8s checks do not share fetches. |
| 6 Result fields | `partial.missing_grants: [string]` accepted (additive for 01; k8s 403 partials need it in M1). `caused_by` rejected: the missing need and its hint already name `k8s.access`. `evidence: Vec<ApiCall>` rejected: the action log is the evidence; an additive `request_id` on `http` and `kube` entries comes in M3. `identifier` evidence class deferred to 04 and M3. |
| 7 SDK clients | Accepted for M3: `http_exchange` returning a capped body to the caller, never logged or stored, for the AWS SDK adapter; `Need::Consent` for `--allow-assume-role` and `--allow-exec`; SDK credential provider exemption named in the M3 cloud ADR. `CheckContext` already has private fields and accessors; a typed extension slot is rejected (state goes through `Family::build`). |
| 8 Kube dry run | Rejected for M1 (05 INV-14, ADR 0010, 01 section 2.7). The catalog's constraints (core v1 Pod path only, `generateName: rdy-probe-`) go into the later ADR 0010 amendment. |
| 9 Shared helpers | Accepted: `rdy_engine::units`, covered by 03's "Shared helpers" ticket. |
| 10 ADR amendments | ADR 0009 by 0014; ADR 0010 by the amendment ticket below; ADR 0006 item 5 (`getent`) in M2 with `net.dns`. |

## Custom checks later (ADR 0005)

None in M1; unknown ids skip and count as not run. M3 `custom.exec` reuses `Probe::exec` with a second
policy: commands from the spec, consent bound to the plan by `--allow-exec=<sha256 of the exec plan>` or
an interactive yes (a bare flag is refused), cwd in a fresh 0700 temp directory, 64 KiB caps. Under
euid 0 a custom command runs as an unprivileged user unless it declares `needs: [root]`. `Cmd` gets an
origin enum then, not before. Preconditions that hold from M1: `&'static str` programs with `Box::leak`
and `String::leak` banned, argv logged as an array, the root-only trust store, Windows job objects
before Windows exec. The plan flag is `--dry-run` in ADR 0005 and `--plan` in 01 and 05; cli-ux picks
one.

## Testing seams

- **Replay backend** (feature `testing`) reads 03's fixture layout. `root/` maps absolute paths;
  `commands/*.json` holds argv, stdout, stderr, exit and `delay_ms`. `net.json` holds per host
  `lookup` addresses (including link-local cases, so the address rule runs in every net fixture) and
  per address `refused`, `blackhole`, `reset` or `serve: <name>`, which connects a duplex stream to an
  in-process server from 03's loopback test support. `native/` holds JSON per `NativeCall`;
  `env.json` and `caps.json` complete the case. Anything unrecorded fails with `NotRecorded`.
- **Kube** fixtures are a `tower` mock behind `guarded_service`, so the real layer order is under test.
  The kind job adds an API server audit policy and asserts rdy's user agent used only allowlisted verbs
  and resources.
- **Time.** `start_paused` tests. `FakeCheck` supports `Outcome`, `Sleep`, `Panic`, `Block` (a stuck
  `spawn_blocking`) and `Spin` (a future that never returns from poll). Spin and a fake exec plugin that
  sleeps 600 s must each end with a report within the deadline plus 12 s.
- **Goldens.** `insta` snapshots per fixture case and for whole reports, with `Clock::Fixed` and a
  fixed run id.
- **Live integration** against loopback servers on all four CI targets; strace completeness on Linux.

## Plan corrections found

- docs/plan/01-spec-format.md, section 5.2 `not_applicable` row and section 5.3 amendment 2: "the
  concept does not exist here" is a source of `not_applicable`. Fix: only the spec `os` list; concept
  absence is `pass` with a note or `not_yet_on_os` (ADR 0013, review MF-06).
- docs/plan/01-spec-format.md, section 2.3 `timeout`: `min(spec, check default, 60s, time left)` means a
  spec can never raise a timeout. Fix: the spec value replaces the default, capped at 60 s and time left.
- docs/plan/01-spec-format.md, section 5.4: add outcome `delegated`, state `argv` is an array of strings,
  add `partial.missing_grants`; section 5.5: truncation removes only `ok` read, read_dir and stat
  entries. Section 2.7 and the 7.2 example: validate `namespace` and `name` values as DNS-1123; the
  `selfsubjectreviews` POST waits for the ADR 0010 amendment.
- docs/adr/0010-kubernetes-client-kube-rs.md: decision 2 omits `selfsubjectreviews` that decision 4
  needs; decision 3 says the client is "shared through the engine Context" and uses `--kube-context`.
  Fix: amendment ticket below (POST list, family-owned client, flag name from cli-ux).
- docs/adr/0004-async-runtime-tokio.md, decision 5: fixed PATH "when euid is 0", job objects on Windows.
  Fix: fixed PATH always; M1 Windows exec only `whoami.exe` (ADR 0014; status line updated).
- docs/adr/0009-http-client-and-tls.md: reqwest, platform verifier and the `net::client` builder for net
  checks; 4 KiB body cap. Fix: ADR 0014 (facade TLS and HTTP, system roots with webpki, 64 KiB per
  INV-13). Its M1 ticket "Shared HTTP client builder with rustls ring and platform verifier" leaves M1,
  replaced by the facade network tickets; status line updated.
- docs/plan/03-check-catalog.md, host coverage correction and the `sysinfo` subset: declined (see
  Per-OS). `host.ports` bind fallback: dropped in M1. `net.proxy`: no PAC fetch in M1. `net.egress` and
  `net.registry`: redirects recorded, never followed. "net.egress core (... injectable connector)":
  TCP, CONNECT, TLS and HTTP now live in the facade; check-author re-estimates the ticket (likely 2 to
  3 h less). "Command table and argument allow-lists from Appendix A" depends on "SEC-18 Enforce command
  execution policy in the facade", which no longer exists; it depends on "Command policy: search path,
  declared directories, caps and Windows whoami only".
- docs/plan/08-testing.md, "Scheduler timeout, deadline and cancellation tests under paused time":
  depends on "Family limits, run deadline and Ctrl-C cancellation", now M2. Fix: depend on "Run
  deadline and watchdog with a report on hang".
- docs/plan/00-overview.md, rdy-engine and rdy-checks-k8s API sketches: `Exec` trait, `Context`,
  `host_root`, public `connect()`. Fix: as in Appendix A. M1 calendar: about 194 h becomes about 241 h
  (below).

## M1 hours and cut list

The engine M1 tickets below total **78 h**, counting tickets owned elsewhere that this design
re-scopes (SEC-17, SEC-19, SEC-25, SEC-21, Blocking helper, Check trait, Scheduler, the kube guard).
Against 00's 194 h the net addition is about 47 h: the review's 43 h, plus about 4 h for moving TCP,
CONNECT, TLS and HTTP into the facade, which the dropped ADR 0009 builder ticket (3 h) and a smaller
`net.egress core` ticket partly offset. **M1 is about 241 h**, roughly 18 to 19 weeks at 13 hours a
week. The founder decides in 00.

Cut list, invariant-neutral, first cut first:
1. Graceful Ctrl-C report and per-family limits (already M2).
2. Merge "Engine test helpers" into "Replay backend and fixture loader": 1 h.
3. Merge "Family probe hook and lazy KubeContext probe" into "Kube client from kubeconfig or
   in-cluster": 1 h.
4. One address per host in M1 instead of dual-stack attempts: 1 h.
5. HTML action log table limited to exec, connect and kube rows (the JSON has all): 0.5 h.

Never cut: the facade policies, the closed native enum, the lint wall, the kube guard, output
confinement, the privilege snapshot and binary refusal, redaction of reports and logs, timers on the
join handle with the deadline and watchdog, the verdict mapping, the lazy kube need.

## Tickets implied

Titles reuse 05 revision 2, 00, ADR and 03 titles where the work is the same. SEC-18, SEC-20 and SEC-23
are retired as duplicates (review SF-12).

- [M1] Check trait, Need and Context in rdy-engine | owner: rust-engineer | est: 3.5h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fixture family with one passing and one need-missing check produces pass and skipped missing_need through Engine::run, and no CheckError or Support variant can produce not_applicable.
- [M1] Privilege snapshot, binary refusal and capability probes | owner: rust-engineer | est: 3.5h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: injected uid, gid and CapEff mismatches each exit 70 with the hint before the spec is read; recorded whoami output maps High and System to elevated and a whoami failure to system trust scope; needs absent from the plan are not probed.
- [M1] Family trait, registry and run plan | owner: rust-engineer | est: 3h | depends on: Unknown check ids report Skipped with a "needs a newer rdy" reason | exit test: the plan for examples/specs/acme-platform.yaml gives not_in_build for gpu.cuda and aws.iam, unknown_check for a typo id, not_yet_on_os for host checks on Windows, not_applicable only for an `os: [linux]` entry on macOS, per-check host sets, and does no I/O.
- [M1] Family probe hook and lazy KubeContext probe | owner: rust-engineer | est: 2.5h | depends on: Privilege snapshot, binary refusal and capability probes, Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a spec with no k8s checks loads no kubeconfig and sends no request; `--no-network` builds no client; a fake exec plugin that sleeps 600 s makes kube_context unavailable after 10 s with no worker blocked.
- [M1] Scheduler with concurrency limit, per-check timeout and panic isolation | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: with the timer on the join handle, FakeCheck Sleep reports timeout, Panic reports error panic, and Spin on a 2-worker runtime still lets the other checks finish.
- [M1] Run deadline and watchdog with a report on hang | owner: rust-engineer | est: 2h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation, SEC-19 Confine writes to a new output dir with safe names | exit test: under paused time running checks become timeout and unstarted ones run_deadline; with two Spin checks the watchdog writes a complete false report and exits 70 within the deadline plus 12 s.
- [M1] Map outcomes to CheckResult with fix source, partial and needs | owner: rust-engineer | est: 2h | depends on: Check trait, Need and Context in rdy-engine, Define result model and verdict mapping in rdy-spec | exit test: a spec fix replaces the built-in text on block with fix_source spec and is hidden on skipped, a partial pass on a block check becomes warn unless evidence_only, and needs carry met flags.
- [M1] SEC-17 Mediated Context handles with action log and read denylist | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: the fixture run's action log lists every command, file, endpoint and kube request; a read of /proc/1/environ is refused; a Probe call after its check ends is denied and logged; truncation drops only ok read, read_dir and stat entries.
- [M1] Blocking helper and subprocess kill on timeout | owner: rust-engineer | est: 4h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: a check running `sleep 600` times out, its process group is gone, a child that ignores reaping returns Hung within 1 s of SIGKILL, and rdy exits within 2 s of the deadline.
- [M1] Command policy: search path, declared directories, caps and Windows whoami only | owner: rust-engineer | est: 2h | depends on: Blocking helper and subprocess kill on timeout | exit test: shells and the sudo family are refused, PATH is fixed for non-root runs too, LD_PRELOAD in the parent never reaches the child, a declared extra directory resolves, and any Windows program other than whoami.exe is refused.
- [M1] File and env read policy in the facade | owner: rust-engineer | est: 3.5h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: /etc/shadow, a symlink to it, a `..` path, a FIFO and /dev/zero under an allowed prefix are refused and logged; a 2 MiB file returns 1 MiB with truncated true; an undeclared env name is refused.
- [M1] Facade TCP attempts, proxy CONNECT and per-check host sets | owner: rust-engineer | est: 4h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: a host listed only by another check is denied, a CONNECT to a literal 169.254.169.254 is refused before any byte is sent, proxy 403 and 407 return typed errors, and Proxy-Authorization never appears in the log.
- [M1] Facade TLS with system roots and the recording chain probe | owner: rust-engineer | est: 3h | depends on: Facade TCP attempts, proxy CONNECT and per-check host sets | exit test: against loopback servers a test-CA chain validates only when the CA is in the fixture system bundle, tls_chain returns the chain without sending application data, and SNI always equals the permitted host.
- [M1] Facade HTTP/1.1 probe with 64 KiB discard and no redirects | owner: rust-engineer | est: 3h | depends on: Facade TLS with system roots and the recording chain probe | exit test: a 302 returns its Location host without a second request, a body canary never reaches the report, and each failure class is produced by its loopback case.
- [M1] SEC-21 Egress address policy, no redirects, no bodies | owner: rust-engineer | est: 3h | depends on: Facade HTTP/1.1 probe with 64 KiB discard and no redirects | exit test: link-local, metadata and IPv4-mapped targets are refused directly, by DNS and as CONNECT targets, and more than 64 distinct hosts fail spec validation with exit 64.
- [M1] Closed NativeCall enum in the facade | owner: rust-engineer | est: 2h | depends on: File and env read policy in the facade | exit test: Statvfs on a path outside the check's prefixes is refused, every variant is logged as native with its api name, Replay returns recorded JSON, and the facade has no closure-taking native API.
- [M1] Read-only guard layer and test for rdy-checks-k8s | owner: k8s-expert | est: 3h | depends on: Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a mock API server behind guarded_service records every request from the k8s suite and only allowlisted GETs and the two review POSTs appear.
- [M1] Kube guard path parser, resource allowlist and pending log entries | owner: rust-engineer | est: 2h | depends on: Read-only guard layer and test for rdy-checks-k8s | exit test: `%73ecrets`, `secrets` in every segment position, GET pods/exec with Upgrade, a dryRun POST and an unlisted resource are each refused and logged, and a dropped request leaves a timeout entry with its check id.
- [M1] Amend ADR 0010 for selfsubjectreviews, client ownership and the context flag | owner: rust-architect | est: 1h | depends on: none | exit test: ADR 0010 lists the three review POSTs, says the k8s family owns the ReadOnlyClient, uses cli-ux's flag name, and security-reviewer signs it.
- [M1] Replay backend and fixture loader | owner: rust-engineer | est: 3h | depends on: File and env read policy in the facade, Closed NativeCall enum in the facade | exit test: a host.memory fixture runs with no real file read, an unrecorded argv fails with NotRecorded, a recorded link-local lookup is refused by the address rule, and the release feature tree excludes `testing`.
- [M1] Engine test helpers FakeCheck, run_fixture and normalize | owner: qa-engineer | est: 2h | depends on: Replay backend and fixture loader | exit test: scheduler tests use every Fake variant including Spin, and assert_within_manifest fails on a fixture check that reads an undeclared path.
- [M1] Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers | owner: rust-engineer | est: 2h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: every Appendix A entry used in tests/lint-wall fails clippy, an allow attribute outside the allowlisted files fails CI, and a check crate depending on socket2 fails cargo deny.
- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: product `../x` fails validation, a pre-planted symlink is not followed, an existing directory is refused before the first check, modes are 0700 and 0600, the spec copy matches the verified bytes, and a killed run leaves no file under a final name.
- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: canaries in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace`.
- [M1] Redact then cap every Report string and return RedactedReport | owner: rust-engineer | est: 2h | depends on: SEC-25 Minimal redactor for evidence, errors and logs, Map outcomes to CheckResult with fix source, partial and needs | exit test: a PEM key placed across a 64 KiB cap boundary is fully redacted, and write_json and render_html do not compile with a plain Report.
- [M1] HTML fix source label and action log table | owner: rust-engineer | est: 1h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: the golden blocked HTML labels vendor fix text with the product name and shows the action log as one table with no details element.
- [M1] OS support table and compile stubs for rdy-checks-host | owner: check-author | est: 2h | depends on: Family trait, registry and run plan | exit test: all four CI targets build, every host check on macOS and Windows reports not_yet_on_os, and none does on Linux.
- [M1] Security re-review of 02 revision 2 and ADRs 0013 to 0016 | owner: security-reviewer | est: 2h | depends on: none | exit test: every MF item is marked closed in the review file and ADRs 0013 to 0016 move to Accepted or carry the requested change.
- [M1] cli-ux review of verdict wording, interrupt behaviour and output naming | owner: cli-ux | est: 1h | depends on: none | exit test: 07-cli-ux.md confirms the headline, the M1 Ctrl-C exit 70 message, `--no-network`, `--out-dir` and the plan flag name.
- [M2] Family limits and graceful Ctrl-C with a partial report | owner: rust-engineer | est: 3h | depends on: Run deadline and watchdog with a report on hang | exit test: Ctrl-C writes a report with interrupted true and unstarted checks skipped cancelled, and k8s never has more than 3 checks in flight.
- [M2] Facade methods for UDP exchanges and unix sockets with a GET-only Docker API guard | owner: rust-engineer | est: 4h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: an SNTP query to a server not in spec ntp_servers and a POST on the Docker socket are refused and logged, and host.time_sync and host.container_runtime depend on this ticket.
- [M2] Nonblocking record reads for /dev/kmsg | owner: rust-engineer | est: 2h | depends on: File and env read policy in the facade | exit test: a fixture kmsg with 10,000 records returns within its cap and timeout and no other device path is allowed.
- [M2] Family-scoped facts with detached fetch and fact attribution | owner: rust-engineer | est: 4h | depends on: Family trait, registry and run plan | exit test: two k8s checks share one nodes fetch, a check that times out does not abort it, and its log entries carry the fact name.
- [M2] sysinfo NativeCall variants without process environ or cmdline | owner: rust-engineer | est: 3h | depends on: Closed NativeCall enum in the facade | exit test: host.memory and host.cpu run on macOS and Windows CI and strace or the equivalent shows no environ or cmdline reads.
- [M2] Kube connector built on the facade | owner: rust-engineer | est: 4h | depends on: Facade TCP attempts, proxy CONNECT and per-check host sets | exit test: every kube socket appears as a facade connect entry and the address rule applies to the API server.
- [M2] Windows job objects so a timeout kills the whole process tree | owner: rust-engineer | est: 3h | depends on: Blocking helper and subprocess kill on timeout | exit test: a Windows fixture command that spawns a grandchild leaves no process after its timeout, and the Windows exec allowlist then opens to Appendix A's Windows rows.
- [M2] SEC-40 `rdy run --plan` preview | owner: rust-engineer | est: 6h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: plan output matches the action log of a real run on the same fixtures.
- [M2] Amend ADR 0006 item 5 for getent as the Linux system answer | owner: rust-architect | est: 1h | depends on: none | exit test: ADR 0006 names getent ahosts with hickory as fallback, and net.dns cites it.
- [M3] Spec-origin exec policy, hash-bound consent and temp workdir for custom.exec | owner: rust-engineer | est: 4h | depends on: SEC-53 Threat model for custom.exec | exit test: a bare --allow-exec is refused, the right hash runs commands as an unprivileged user under euid 0 in a fresh temp dir with 64 KiB caps, and a wrong hash runs nothing.
- [M3] http_exchange and Need::Consent for SDK adapters | owner: rust-engineer | est: 4h | depends on: Facade HTTP/1.1 probe with 64 KiB discard and no redirects | exit test: the AWS SDK adapter fixture runs through the facade with every call in the action log and no body in the report, and assume-role without consent is skipped missing_need.
- [M3] Decide the 1.0 stability scope of Check, Family and Probe | owner: rust-architect | est: 3h | depends on: none | exit test: an ADR says whether these modules are semver-covered at 1.0 or move under rdy_engine::unstable, before rdy-engine 1.0 ships.

## Appendix A. Rust signatures

```rust
// check.rs
pub struct CheckInfo {
    pub id: &'static str, pub family: &'static str, pub summary: &'static str,
    pub needs: &'static [Need], pub wants: &'static [Want],
    pub default_timeout: Option<Duration>, pub os: OsSupport,
    pub reads: &'static [&'static str], pub env: &'static [&'static str],
    pub commands: &'static [CommandSpec], pub peers: &'static [PeerClass],
}
pub struct Want { pub need: Need, pub evidence_only: bool }
pub struct CommandSpec { pub program: &'static str, pub extra_dirs: &'static [&'static str],
                         pub max_stdout: usize, pub env: &'static [&'static str] }
pub enum PeerClass { SpecHosts, Proxy, SystemResolver, KubeApi }
pub struct OsSupport { pub linux: Support, pub macos: Support, pub windows: Support }
pub enum Support { Full, Partial(&'static str), NotYet }

pub type CheckOutcome = Result<Finding, CheckError>;
pub struct Finding { pub level: Level, pub message: String, pub observed: serde_json::Value,
                     pub expected: serde_json::Value, pub fix: Option<String>,
                     pub partial: Option<Partial>, pub notes: Vec<String> }
pub enum Level { Pass, Warn, Fail }
pub struct Partial { pub missing: Vec<Need>, pub missing_grants: Vec<String>, pub note: String }
#[non_exhaustive]
pub enum CheckError { MissingNeed(Need), Unsupported(&'static str), Probe(ProbeError),
                      Failed { message: String, hint: String } }

pub trait Check: Send + Sync + 'static {
    fn info(&self) -> &'static CheckInfo;
    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome>;
}
pub struct CheckContext { /* private: key, os, caps, probe, deadline */ }
impl CheckContext {
    pub fn key(&self) -> &str; pub fn os(&self) -> Os; pub fn has(&self, need: &Need) -> bool;
    pub fn probe(&self) -> &Probe; pub fn remaining(&self) -> Duration;
}

// family.rs
pub trait Family: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn checks(&self) -> &'static [&'static CheckInfo];
    fn probe<'a>(&'a self, wanted: &'a [Need], probe: &'a Probe) -> BoxFuture<'a, Vec<Capability>>;
    fn build(&self, check: &CheckSpec, spec: &Spec) -> Result<Built, BuildError>;
}
pub struct Built { pub check: Box<dyn Check>, pub hosts: HostSet }

// privilege.rs, sched.rs
pub struct Privilege { pub uid: u32, pub euid: u32, pub gid: u32, pub egid: u32,
                       pub cap_eff: u64, pub elevation: Elevation }
pub enum Elevation { Root, High, System, NotElevated, Unknown }
impl Privilege { pub fn snapshot(probe: &Probe) -> Result<Self, EngineError>; // refuses setuid, setgid, file caps
                 pub fn trust_scope(&self) -> rdy_spec::sig::TrustScope; }
pub struct RunOptions { pub jobs: usize /* <= 32 */, pub deadline: Duration, pub network: bool,
                        pub cancel: CancellationToken, pub on_progress: Option<Box<dyn Fn(&Progress) + Send + Sync>>,
                        pub clock: Clock, pub run_id: Option<String> }
impl Engine {
    pub fn new(registry: Registry, backend: Arc<dyn Backend>) -> Self;
    pub fn plan(&self, spec: &LoadedSpec, os: Os) -> RunPlan;
    pub async fn run(&self, spec: &LoadedSpec, out: &OutputDir, opts: RunOptions)
        -> Result<RedactedReport, EngineError>;
}

// probe
impl Probe {
    pub async fn read(&self, path: &Path) -> Result<FileBytes, ProbeError>;
    pub async fn read_tail(&self, path: &Path, max: usize) -> Result<FileBytes, ProbeError>;
    pub async fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>, ProbeError>;
    pub async fn read_link(&self, path: &Path) -> Result<PathBuf, ProbeError>;
    pub async fn stat(&self, path: &Path) -> Result<Option<FileMeta>, ProbeError>;
    pub fn env(&self, name: &str) -> Result<Option<String>, ProbeError>;
    pub async fn exec(&self, cmd: Cmd) -> Result<Output, ProbeError>;
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, ProbeError>;
    pub async fn tcp(&self, target: &Target) -> Result<TcpReport, ProbeError>;     // attempts per address
    pub async fn tls_chain(&self, target: &Target) -> Result<TlsChain, ProbeError>;
    pub async fn http(&self, req: HttpProbe) -> Result<HttpOutcome, ProbeError>;
    pub async fn native(&self, call: NativeCall) -> Result<NativeValue, ProbeError>;
    pub fn kube_guard(&self) -> KubeGuardLayer;        // used only by guarded_service
}
pub struct Cmd { pub program: &'static str, pub args: Vec<String>, pub timeout: Option<Duration> }
pub enum Target { Direct { host: String, port: u16 }, ViaProxy { host: String, port: u16 } }
pub struct HttpProbe { pub url: String, pub method: Method /* Head | Get */, pub route: Route,
                       pub roots: Roots /* System | Bundled */ }
#[non_exhaustive]
pub enum NativeCall { Statvfs { path: PathBuf }, Uname, Rlimit(Resource), Hostname, MachineId, SystemRoots }
#[non_exhaustive]
pub enum ProbeError { Denied { rule: &'static str, what: String }, NotFound, PermissionDenied,
                      Timeout, Hung { pid: u32 }, Net(NetFailure), Io(String), NotRecorded(String) }
pub trait Backend: Send + Sync + 'static {   // Live and Replay; raw I/O only, no policy
    fn open_read<'a>(&'a self, path: &'a Path, range: ReadRange) -> BoxFuture<'a, io::Result<FileBytes>>;
    fn read_dir<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Vec<DirEntry>>>;
    fn read_link<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<PathBuf>>;
    fn stat<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Option<FileMeta>>>;
    fn env(&self, name: &str) -> Option<String>;
    fn spawn<'a>(&'a self, cmd: &'a ResolvedCmd) -> BoxFuture<'a, io::Result<Output>>;
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxedStream>>;
    fn native<'a>(&'a self, call: &'a NativeCall) -> BoxFuture<'a, io::Result<NativeValue>>;
}

// output, report, redact
impl OutputDir { pub fn create_new(parent: &Path, product: &str, ts: &str) -> Result<Self, ReportError>;
                 pub fn write_report(&self, r: &RedactedReport) -> Result<(), ReportError>;
                 pub fn write_spec(&self, s: &VerifiedSpecBytes) -> Result<(), ReportError>; }
pub fn write_json(r: &RedactedReport, out: &mut dyn std::io::Write) -> Result<(), ReportError>;
pub fn render_html(r: &RedactedReport) -> Result<String, ReportError>;
pub struct RedactedReport(/* private */ Report);
pub fn blocking<T, F>(f: F) -> BoxFuture<'static, Result<T, CheckError>>
where F: FnOnce() -> Result<T, CheckError> + Send + 'static, T: Send + 'static;
```

Lint wall entries for every check crate's `clippy.toml`:
- Process: `std::process::Command::new`, `tokio::process::Command::new`.
- Files: `std::fs::*` functions, `File::open`, `File::create`, `OpenOptions::new`, `tokio::fs::*`,
  `rustix::fs::*`.
- Sockets: `std::net::{TcpStream, UdpSocket, TcpListener}` constructors, `ToSocketAddrs`,
  `tokio::net::*` constructors and `lookup_host`, `std::os::unix::net::*`, `rustix::net::*`, type
  `socket2::Socket`.
- Threads and tasks: `std::thread::spawn`, `std::thread::Builder::spawn`, `tokio::spawn`,
  `tokio::task::spawn_blocking`.
- Env: `std::env::{var, var_os, vars, vars_os}`.
- Leaks: `Box::leak`, `String::leak`, `Vec::leak`.
- kube constructors outside the client module: `kube::Client::new`, `kube::Client::try_default`,
  `kube::Config::infer`.
- `rustix::process` functions other than the id getters.

## Appendix B. Kube guard rules

Global rules, because `call` runs on kube's buffer worker without a check id.

1. Before any rule, refuse a path containing `%`, `..`, `//`, `;`, an empty segment, a trailing `/` or
   a non-ASCII byte. Refuse `Upgrade` and `Connection: upgrade` headers. Allowed query keys: `limit`,
   `continue`, `labelSelector`, `fieldSelector`; anything else (including `watch`, `follow`, `dryRun`)
   is refused.
2. Parse into group, version, namespace, resource, name and subresource. Discovery GETs: `/version`,
   `/api`, `/apis`, `/api/v1`, `/apis/<group>`, `/apis/<group>/<version>`. A subresource is refused in
   M1.
3. GET only for (group, resource) pairs in `rdy_checks_k8s::ALLOWED`, a const list reviewed by
   security-reviewer. M1 list: core `namespaces`, `nodes`, `pods` (requests and node names only enter
   `observed`); `storage.k8s.io` `storageclasses`, `csidrivers`; `admissionregistration.k8s.io`
   `validatingadmissionpolicies`, `validatingadmissionpolicybindings`; `security.openshift.io`
   `securitycontextconstraints`; `config.openshift.io` `clusterversions`. A unit test asserts `secrets`
   never appears.
4. ConfigMaps: LIST only with an `Accept` header for `PartialObjectMetadataList`; GET by name only from
   a const list (`kube-system/kubeadm-config`, M1-late).
5. POST only to `/apis/authorization.k8s.io/v1/selfsubjectaccessreviews` and
   `/apis/authorization.k8s.io/v1/selfsubjectrulesreviews`, with no query string. After the ADR 0010
   amendment, also `/apis/authentication.k8s.io/v1/selfsubjectreviews`. Every other method is refused.
6. Response bodies are capped at 32 MiB. Spec `namespace` and `name` values are DNS-1123 (rdy-spec).
7. Every refusal is a `kube` entry with outcome `denied` and the rule name, and the request never
   leaves the process.
