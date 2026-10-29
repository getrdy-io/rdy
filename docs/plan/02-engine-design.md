# 02 Engine design

Owner: rust-architect. Revision 3, 2026-10-28. Applies both security reviews
(`docs/plan/reviews/02-engine-design-review-by-security-reviewer.md` and
`docs/plan/reviews/adr-0013-0016-review-by-security-reviewer.md`) and aligns with 01-spec-format.md and
the revised ADRs. Status: waiting for security-reviewer sign-off and cli-ux review.

This note designs `rdy-engine`: checks and families, privilege and needs, scheduling, the result flow,
the action log, the probe facade, per-OS behaviour, output and reports, and the test seams. It builds on
ADRs 0003, 0004, 0005, 0008, 0010 (as amended), 0011 (as amended) and 0012, and on ADRs 0013 to 0016.
**01-spec-format.md owns every wire name** (`Report`, `CheckResult`, statuses, `skip_kind`, verdicts,
the action log shape). This note uses its names and says what the engine fills. Invariant numbers
(INV-nn) are those of 05-threat-model.md revision 2. Rust signatures are in Appendix A.

## Review items and where they are closed

Revision 2 closed the ten must-fix items of the first review (kube guard, native closures,
check-written CONNECT, lint wall, redaction order and logs, the not-applicable escape, non-yielding
checks, log completeness, the privilege-carrying binary, lost escapes). Revision 3 closes the six
must-fix items of `docs/plan/reviews/adr-0013-0016-review-by-security-reviewer.md`:

| Item | Fix | Where |
| --- | --- | --- |
| MF-01 facade caps cut secrets | Truncation flags, line drop at cut edges, unterminated PEM rule, run-scoped known secrets, cap-offset corpus | From finding to result; ADR 0015 |
| MF-02 watchdog race and hang | One `AtomicU8` writer state, bounded helper-thread write, no std stdout lock, `try_lock` snapshot, own redaction pass, child groups killed | Scheduling; ADR 0016 |
| MF-03 kube allowlist gaps | Every GET the M1 k8s checks make, exactly, each cited by a check; late entries in `M1_LATE` | Appendix B |
| MF-04 unvetted crates | Direct dependency allowlist per check crate in CI, exact clippy items for every std file, link, permission, process, socket, thread and env API and every kube client and config constructor, wider deny wrappers | Lint wall; Appendix A; ADR 0014 |
| MF-05 Windows output dir | `%USERPROFILE%\rdy-reports` default, reparse point and final path check (05 I3) | Output and reports; ADR 0016 |
| MF-06 `selfsubjectreviews` | Allowed in M1 with a fixed body, `v1` only, `uid` and `extra` dropped (ADR 0010 amended) | Kubernetes; Appendix B |

Should-fix items applied: SF-01 forbidden ranges, SF-02 kube proxy CONNECT named, SF-03 sealed
`Backend` and private constructors, SF-04 native variant snapshot, SF-05 impersonation headers, SF-06
parser vectors and minimal structs, SF-07 per-result redaction, SF-08 in-process entry point (ADR 0011),
SF-09 `Partial` OS sets `partial`, SF-10 `pass_by_absence` registry, SF-11 all ids and `AT_SECURE`,
SF-12 child kill before exit, SF-13 cap-std platform details. Nits N-01 to N-09 applied.

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
(`net.tls_intercept` defaults to the `net.egress` hosts). `Registry::plan` (M1-035; `Engine::plan` will call it) maps every spec entry to a
built check or a skip kind with no I/O. The first row that fits wins, in this order:

| Situation | `skip_kind` (01) |
| --- | --- |
| Spec `os` list is empty (it would hide the check everywhere) | `unsupported_spec` |
| Spec `os` list leaves this OS out | `not_applicable` (never counts) |
| Id reserved, not built into this rdy | `not_in_build` |
| Id not reserved | `unknown_check` |
| Known id that no registered family builds (checked before its fields) | `not_in_build` |
| Known id, field or value this rdy cannot read | `unsupported_spec` |
| The family refuses to build the entry | `unsupported_spec` |
| `CheckInfo::os` is `NotYet` here | `not_yet_on_os` |
| Hard need missing after probing | `missing_need` |
| Run deadline passed before start | `run_deadline` |
| Run interrupted (M2 graceful Ctrl-C) | `cancelled` |

There are no inter-check dependencies. Every k8s check except `k8s.access` needs `kube_context`;
`k8s.access` has no hard need and reports the probe outcome as a block with its fix.

## Privilege and needs

**Snapshot first.** Before the spec is read, the async `Privilege::snapshot(&probe)` runs through the
run-level facade (`check: null`):
- Linux: all four values on the `Uid:` and `Gid:` lines of `/proc/self/status` (real, effective, saved,
  filesystem), `CapEff` and `CapAmb`, and `AT_SECURE` (type 23) from `/proc/self/auxv`.
- macOS: the four ids from `rustix`.
- `rdy` exits 70 if any uid or gid value differs from the real one, `CapEff` or `CapAmb` is nonzero for
  a non-root uid, or `AT_SECURE` is set (INV-10). The hint names `chmod u-s,g-s`, `setcap -r`, or
  ambient capabilities.
- Windows: `C:\Windows\System32\whoami.exe /groups /fo csv`, from a constant path, never from
  `%SystemRoot%`. Integrity SID `S-1-16-12288` (High) or `S-1-16-16384` (System) means elevated. If
  `whoami` fails, `root` is unknown for checks and `identity.elevated` is unset. In M1 `whoami` feeds only
  the `root` need and `identity.elevated`, never trust. M2-105 owns elevation detection for the trust path.

The CLI maps the snapshot to the `rdy-spec` trust store scope (system store only when elevated,
INV-04); the loader never reads ids itself. One privilege answer per run. In M1 the trust store does not
use the Windows answer: Windows has no user store and every existing system store is refused, so
elevation does not change what is read (ADR 0027). M2-105 revisits it.

| Need (01 name) | Met when | Probed by | Never does |
| --- | --- | --- | --- |
| `root` | snapshot says euid 0 or elevated | the snapshot | ask for sudo, re-exec, prompt; the hint never suggests `sudo -E` |
| `kube_context` | the operator's kubeconfig or in-cluster config loads and `GET /version` answers | k8s family `probe` | read a kubeconfig from a spec or the working directory |
| `network` | the run allows sockets (no `--no-network`) | run option | contact anything to test connectivity |
| `command` (with `name`) | the program exists in its search path | engine, by stat | search the caller's `PATH` |
| `cloud_credentials` (M3) | the provider chain resolves | cloud family | assume a role without consent |

Rules:
- Plan, then probe, then run. All probes run concurrently before the first check, each under its own
  timeout, and their results go into `capabilities` with a hint.
- With `--no-network`, `kube_context` is unavailable and no kube client is built.
- The kube probe sends its first request (which may run an exec credential plugin that waits for an SSO
  login) from a `spawn_blocking` thread through the runtime handle, under a 10 s timer held by the
  scheduler. A stuck plugin costs one abandoned blocking thread, never a worker.
- A token refresh later in the run runs the plugin inside kube and may block a worker. The per-check
  timer and the watchdog are the backstop. The kube client ticket verifies this and records it as a
  residual.

## Verdict

The rule is 01 section 5.3, recorded in ADR 0013 (refining ADR 0008 decision 3). What the engine adds:

- It never produces `not_applicable` except from the spec `os` list. A requirement met by absence is
  built only through `Finding::pass_by_absence(note)`.
- A level Pass with `partial` set on a required check becomes `warn`, "not verified: <missing>", unless
  every missing want is `evidence_only`.
- Every result from an OS that `CheckInfo` marks `Partial` gets `partial` set, with the OS note as what
  is missing, so `net.proxy` on macOS and Windows cannot report a full pass.
- A want the run did not meet is added to `partial.missing` by the engine, so a check cannot forget it.
  A `Partial` OS never gets the `evidence_only` exception, because its note is a reason of its own.
- A pass that the partial rule turns into `warn` shows rdy's text, with `fix_source: rdy`, never the
  vendor's `fix`. Nothing was measured as failing, so the vendor's advice would send the customer after
  a problem that was not found. `partial.missing_grants` goes to the result `notes` until 01 has the
  field.
- A golden snapshot lists every `evidence_only` want and every `pass_by_absence` call site.
- Unknown severity counts as block and unknown status as not run, in `rdy_spec::result::verdict()`.
- A run that verified nothing is `ready_with_warnings`, `verdict_reason: nothing_verified`. A spec with
  zero checks is refused by rdy-spec (exit 64).

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
- **Watchdog** (MF-02). A plain OS thread, started before the runtime, fires at deadline plus 10 s.
  - **One writer.** An `AtomicU8` write state (`Running`, `Writing`, `Done`, ADR 0016) decides who
    writes: whoever moves it from `Running` to `Writing`. If the watchdog loses, it waits at most 5 s
    for `Done`, then exits 70 without writing. If the CLI loses, it parks.
  - **Snapshot.** It takes the snapshot of finished results with a `try_lock` loop bounded at 1 s; a
    poisoned lock uses `into_inner`. With no snapshot it reports every check as `error`,
    `interrupted`.
  - **Its own pass.** It runs the same sync redact-then-cap pass as the engine and never assumes the
    snapshot is redacted. Results are already redacted as they complete (ADR 0015), so this pass is a
    second line. It marks running checks `timeout` and unstarted ones `run_deadline`, and sets
    `complete: false`.
  - **Bounded write.** The render and write run on a helper thread through the held output directory.
    The watchdog waits at most 10 s for it.
  - **Kill, then exit.** It sends SIGKILL to every live process group in the facade's lock-free list,
    then calls `std::process::exit(70)` whatever happened.
  - **Locks.** It never takes std's stdout or stderr locks; it writes one fixed stderr line with a
    non-blocking write, or nothing.
  - **Too early.** Before the output directory exists, it exits 70 with no report.
  - **Exit bound.** Worst case: deadline plus 22 s.
  - On the normal path the CLI moves the state to `Writing`, writes, flushes, sets `Done`, kills any
    leftover process groups and calls `std::process::exit(code)`; nothing waits on a runtime drop. The
    kube exec plugin is not ours to track (residual).
- **Ctrl-C in M1.** The first Ctrl-C cancels the run token: checks abort, child process groups are
  killed, and the CLI exits 70 with "interrupted, no report written". Writing the partial report with
  `interrupted: true` is M2 (01 names). cli-ux to confirm.
- **Panics** become `error`, `error_kind: panic` (ADR 0008 decision 8).

## From finding to result: redact, then cap

1. `rdy-spec` parses thresholds into typed params with defaults; `Family::build` hands them to the check.
2. The check returns `Finding { level, message, observed, expected, fix, partial }`. Facade buffers it
   parsed carry `truncated_head` and `truncated_tail` flags.
3. The engine maps level and severity to `status`, fills the 01 section 5.2 fields (`key`, `id`, `name`,
   `family`, `severity`, `status`, `message`, `fix`, `fix_source`, `builtin_fix`, `observed`,
   `expected`, `needs` with `met`, `partial`, `notes`, `started_ms`, `duration_ms`, and the
   status-specific fields). The vendor's `fix` replaces rdy's text verbatim on `warn` and `block` and is
   hidden when the check did not run (01 section 2.6).
4. **As each result or action entry completes**, it is redacted, then capped (ADR 0015):
   - Text from a facade-truncated buffer loses its partial edge line before matching (the last 4 KiB
     if it has no newline), replaced by the cap marker.
   - The PEM rule matches an unterminated private key block to the end of the buffer.
   - The run-scoped known-secret set (kubeconfig token and client key data, proxy password, values of
     declared env names that match the secret-name rule) is removed by exact match, and by any
     8-character or longer prefix or suffix at a truncated edge.
   - Then the caps, on char boundaries with a marker: message 1 KiB, fix 4 KiB, `observed` and
     `expected` 64 KiB, lists 200 items. The marker is ` [truncated]` and the cut never lands inside a
     placeholder. `Redactor::redact_check` and `redact_action` do this step for one entry,
     `Redactor::redact_report` and `redact_report_counted` for the whole report (M1-062).
5. A final pass over the assembled report (identity, host, proxy, capabilities included), then the
   2 MiB report cap, measured after JSON escaping (Action log rule below).
6. The result is a `RedactedReport`, with no `From<Report>`, no `Deserialize` and no `DerefMut`.
   `write_json`, `render_html`, the terminal renderer and the watchdog accept nothing else. `Progress`
   events carry id, status and duration only.

`rdy` installs the redacting `tracing` layer first in `main`. With `RUST_LOG` unset nothing is logged (07
D.6). With it set, hyper, h2, rustls, tower and kube stay capped at `warn` whatever the filter says. `EngineError`, `ReportError` and panic text are redacted before
printing.

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
tests policy.
- `Backend` is sealed with a private supertrait. `Probe` constructors are `pub(crate)`. `Live` is
  reachable only through `rdy_engine::live_backend()`, which is on the check crates' disallowed list.
- Each check's `Probe` is bound to its `CheckInfo`, its host set and a cancellation token cancelled when
  the check ends; a later call returns `denied`, rule `check finished`.

**Exec.**
- argv only. `Cmd.program` is `&'static str`. Spec values pass 01's grammars (no leading `-`) and go
  after `--` where the program supports it.
- The program resolves to an absolute path from the fixed search path (`/usr/sbin:/usr/bin:/sbin:/bin`)
  always, then the check's declared extra directories (absolute constants, for operator-managed GPU
  tools). Windows: in M1 only `C:\Windows\System32\whoami.exe`, until job objects land.
- Refused outright: shells (`sh`, `bash`, `zsh`, `dash`, `cmd`, `powershell`, `pwsh`, and the busybox shell applets `hush`, `msh`, `mksh`, `yash`, `rbash`, `posh`, `oksh`, `loksh`), the privilege
  family (`sudo`, `su`, `doas`, `pkexec`, `runas`, `run0`, `sudoedit`, `runuser`, `setpriv`, `sg`,
  `newgrp`, `ksu`, `machinectl`, `systemd-run`) and the programs that run another program from their
  arguments (`env`, `xargs`, `nice`, `nohup`, `timeout`, `setsid`, `chroot`, `nsenter`, `unshare`,
  `stdbuf`, `taskset`, `ionice`, `chrt`, `numactl`, `prlimit`, `flock`, `watch`, `capsh`, `script`,
  `strace`, `ltrace`, `gdb`, `cgexec`, `bwrap`, `firejail`, `systemd-nspawn`). A check that needs one
  of these effects runs the tool itself. The multi-call binaries `busybox` and `toybox` are refused by
  the name a check asks for, not by the file a name resolves to, because on a system built from one
  every tool is a link to it.
- Trust: the name resolves to a real path one component at a time. Every link on the way, the file and
  every directory above them must be owned by root or the running user (root only, when run as root)
  and not group- or world-writable. The directory that holds a link is judged like the one that holds
  the file, because whoever can write there can re-point the link. A writable directory with the
  sticky bit (like `/tmp`) is accepted above that directory, never as the one that holds the file or
  a link, and never the file. More than 40 links, or a path that cannot be resolved or
  read is refused. The program starts from the real path with `argv[0]` set to the name, so multi-call
  binaries (`busybox`, `kmod`) still pick the right applet.
- Environment cleared, then `LC_ALL=C`, `PATH=<fixed>` and declared names only (Windows: `SystemRoot`
  and a System32 `PATH`, no Unix path). Declared names may not be `LD_*`, `DYLD_*`, `MALLOC_*`,
  `PYTHON*`, `GIT_*`, `CORECLR_PROFILER*`, `GLIBC_TUNABLES`, `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`, `PERL5LIB`,
  `PERL5OPT`, `RUBYLIB`, `RUBYOPT`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `LESSOPEN`,
  `PAGER`, `EDITOR`, `VISUAL`, `SYSTEMD_PAGER`, `ZDOTDIR`, `PROMPT_COMMAND`, `LUA_INIT`, `LUA_PATH`,
  `LUA_CPATH`, `PERLLIB`, `PERL5DB`, `NODE_PATH`, `SSH_ASKPASS`, `SUDO_ASKPASS`, `BROWSER`, `TERMINFO`,
  `TERMINFO_DIRS`, `KUBECONFIG`, `DOTNET_STARTUP_HOOKS`, `COR_PROFILER`, `COMSPEC`, `PATHEXT` or
  `CUDA_INJECTION64_PATH`. The full list is in `policy.rs`.
- stdin null; cwd `/`; umask `0o077` (set process-wide before each start, since a child-only umask needs
  `pre_exec`, which is `unsafe`). The refusal list also holds `ash`, `ksh`, `csh`, `tcsh` and `fish`, and
  a program that resolves to a listed shell through a link is refused. The extra variable names that
  change loading or name resolution (`LOCPATH`, `NLSPATH`, `HOSTALIASES`, `BASH_ENV`, `IFS` and similar)
  are refused too. Code: `rdy_engine::exec::policy`.
- Descriptors above 2 that `rdy` inherited reach children in M1. `exec::inherited_fds()` lists them
  for the start-up warning (built, M1-168); closing them needs `unsafe` (M2-104, ADR 0023).
- `exec::run` and `ExecSpec::new` are public only under `cfg(any(test, feature = "testing"))`. Check
  crates reach the runner through `exec::table::run` only: it checks the command table (03 Appendix A),
  then the policy. `exec::policy::run` is crate-private, and a compile-fail test proves it. The table
  and `table::validate_for` need no `runtime` feature, so a probe gate without a runtime can refuse an
  unlisted command too.
- Each child gets its own process group, recorded in a lock-free list until reaped, and the group is
  killed on timeout. A child not reaped within 1 s of SIGKILL returns `Hung { pid }`; a detached task
  reaps it later.
- Output caps: stdout per `CommandSpec` (default 1 MiB, at most 4 MiB), stderr 64 KiB. Both carry
  truncation flags for the redactor.

**Files.**
- Absolute paths only, and no `..` component; matched before any open.
- Linux: open with `O_PATH` (no side effect, no device open), read the real path from
  `/proc/self/fd/<n>`, `fstat`, and check prefix and deny list against that real path. Then reopen
  through the descriptor with `O_RDONLY | O_NONBLOCK`. Only regular files pass, except under `/proc`
  and `/sys`.
- macOS: `realpath`, open with `O_NOFOLLOW | O_NONBLOCK`, and recheck with `F_GETPATH`.
- Windows: no M1 check reads files, so the facade refuses them.
- Deny list, matched on components at any depth (`/host/etc/shadow`, an overlay `diff/etc/shadow`, a
  macOS data volume): `etc/shadow*`, `etc/gshadow*`, `etc/sudoers*`, `etc/master.passwd`,
  `etc/security/opasswd`, `var/db/dslocal`; `.ssh`, `.kube` (the engine's own kubeconfig read needs a
  settled path: M1-102), `.aws`, `.azure`, `.config/gcloud`, `.gnupg`, `.docker/config.json`, `.netrc`,
  `.git-credentials`, `.pgpass`, `.vault-token`; private key files by name and extension (`*.key`,
  `*.p12`, `*.keytab`, `*.keychain`, `*.keychain-db`, `id_*`, `ssh_host_*_key`), `etc/ssl/private`,
  `etc/pki/tls/private`; cluster credentials (`etc/kubernetes/*.conf`, `etc/rancher/{k3s,rke2}/*.yaml`,
  `var/lib/kubelet/kubeconfig`, `var/lib/etcd`, `var/lib/rancher/*/server/{token,node-token,cred}`,
  `secrets/kubernetes.io/*`). `/proc/<pid>/` is an allowlist (`status`, `stat`, `statm`, `comm`,
  `cgroup`, `mountinfo`, `mounts`, `limits`, `net`, and the same under `task/<tid>/`, plus `auxv` for
  `self` only, which M1-042 reads for `AT_SECURE`), so `cwd`,
  `exe`, `root`, `fd`, `environ`, `cmdline`, `mem`, `maps` and `ns` are refused. At the root: `/proc/kcore`,
  `kmsg`, `vmcore`, `kallsyms`, `kpage*`, `/sys/kernel/debug`, `/sys/kernel/tracing`, and `/dev/*` for
  `stat` and `read_dir` as well as `read` (M4 adds a closed stat-only list: `/dev/nvidia*`, `/dev/dri/*`,
  `/dev/kfd`).
- 1 MiB cap; `read_tail` sets `truncated_head`. Reads run on `spawn_blocking`.
- Env names must be declared; values matching the secret-name rule join the known-secret set.

**Network** (ADR 0014; ADR 0009 decisions 4, 6 and 7 stay).
- The host must be in the calling check's own host set. The spec may name at most 64 distinct hosts
  (rdy-spec validation, exit 64).
- One `is_forbidden(IpAddr)` refuses, literal or resolved: 169.254.0.0/16, 100.100.100.200/32,
  fe80::/10, fd00:ec2::/64, and the IPv4-mapped, IPv4-compatible and `64:ff9b::/96` forms of each IPv4
  range. A table test backs it.
- `tcp` tries each address with a 250 ms stagger and a per-attempt timeout, and reports every attempt.
  Checks cannot pick addresses.
- Proxied path: the facade writes CONNECT (8 KiB head cap, own timeout, Basic auth from `ProxyUrl`,
  `Proxy-Authorization` never logged) and refuses a forbidden literal target before any byte is sent.
  Names resolve at the proxy (05 residual). `NO_PROXY` matching lives here.
- `tls_chain` runs the recording verifier, private to the facade, and returns the presented chain and
  whether it validates against the system roots and the bundled roots. It never sends application data.
- `http` sends HTTP/1.1 HEAD or GET over a verified stream. It returns status, a fixed header list,
  stage timings and the `Location` host. It reads at most 64 KiB of body and discards it, and never
  follows a redirect. Failures are typed: `dns`, `refused`, `blackhole`, `tls_unknown_issuer`,
  `tls_alert`, `reset_after_hello`, `proxy_403`, `proxy_407`, `http_status`, `blocked_address`.
- System roots: Linux PEM bundles (`SSL_CERT_FILE`, `SSL_CERT_DIR`, the standard paths) are read through
  the facade; macOS and Windows use `NativeCall::SystemRoots`. No revocation check, and the report says
  so.
- PAC is reported, never fetched, in M1.
- UDP (`udp_exchange`, DNS messages built by `hickory-proto`) and unix sockets (`unix_get`, GET-only
  Docker API guard) are M2 facade methods. They must land before `host.time_sync`, direct `net.dns`
  queries and `host.container_runtime`.

**Native calls.** A closed enum the Live backend executes.
- An exhaustive `match` maps each variant to its policy row. A snapshot test of the variant list fails
  CI until the snapshot and a 05 table row change in the same PR.
- M1 variants:
  - `Statvfs { path }`: the path passes the read rules; logged as `native`, `api: statvfs`, with
    `path`.
  - `Uname`, `Rlimit(resource)`, `Hostname`, `SystemRoots`.
  - `MachineId`: Windows `MachineGuid`; Linux reads `/etc/machine-id` as a file; macOS has none in M1,
    so its `host_id` is null. The raw value never enters the log or the report; only 01's salted
    `host_id` does.
- No `sysinfo` in M1. In M2 its variants use refresh kinds without environ, cmdline, cwd and root.
- No `bind()` port probes. `host.ports` reports "owner unknown, not verified".

**Kubernetes.** Appendix B has the guard rules: deny by default on a parsed and normalised path, GET only
on the exact list of resources the M1 checks read, no subresources, no dry run, no probe pod. POST only
to the three self reviews; `selfsubjectreviews` has a fixed body (ADR 0010 as amended).
- Construction:
  - One constructor, `guarded_service(inner)`, serves production and the mock tests.
  - A `ReadOnlyClient` newtype with a private constructor is the only client type checks get.
  - The k8s family owns the client; the engine has no kube dependency.
- kube's own sockets, its proxy CONNECT and TLS, and its exec plugins are the named exceptions of ADR
  0014. At probe time the facade resolves the API server host, applies `is_forbidden` and logs a
  `connect` with `via_proxy`. A kube connector built on the facade is an M2 ticket.

**Lint wall** (INV-07, ADR 0014 decision 7).
- `clippy.toml` `disallowed-methods` and `disallowed-types` list exact items, never wildcards
  (Appendix A).
- A `tests/lint-wall` crate uses each item, and CI expects each one to fail.
- `allow(clippy::disallowed_` is legal only in the facade's `live/` module and the k8s client module.
- **Direct dependency allowlist.** `ci/check-crate-deps.toml`:
  - every check crate: `rdy-engine`, `rdy-spec`, `serde`, `serde_json`, `thiserror`, `futures-util`;
  - `rdy-checks-k8s` adds `kube` and `k8s-openapi`, and is the only check crate that may depend on
    `kube`; inside it, only the client module may name a kube client or config type (Appendix A);
  - `rdy-checks-net` adds `x509-parser`.

  A CI script compares `cargo metadata` against the file. A change needs the `security-review` label.
- `deny.toml` wrappers keep `rustix`, `socket2`, `hyper`, `tokio-rustls`, `hickory-*`, `sysinfo`,
  `walkdir`, `tempfile`, `which`, `nix`, `ureq` and `reqwest` out of check crates.

## Per-OS behaviour

- **Compile stubs.** Every check compiles everywhere. OS-specific gather functions sit behind
  `#[cfg(target_os = ..)]`, with a stub returning `CheckError::Unsupported`. `CheckInfo::os` is the
  source of truth at plan time. Evaluation is pure over fact structs, so macOS and Windows logic can be
  tested on Linux from recorded facts.
- **M1 coverage.**

| Family | Linux | macOS | Windows |
| --- | --- | --- | --- |
| host | `Full` for the M1 tier | `NotYet` | `NotYet` |
| net | `Full` | `Full`; `net.proxy` `Partial` (env only; results marked partial) | `Full`; `net.proxy` `Partial` (env only; results marked partial) |
| k8s | `Full` | `Full` | `Full` |

  03 asks for a `sysinfo` subset and code-level "not applicable" on macOS and Windows in M1. Declined:
  MF-02 keeps `sysinfo` out of M1 and ADR 0013 removes code-level not applicable. Vendors scope
  Linux-only checks with `os: [linux]`.
- **Process model.** One foreground process: no daemon, no service, no listener. Children only through
  the facade, plus kube exec plugins.
- **Startup order.** `harden_umask()` and the inherited-descriptor list (a one-line `warning:` on stderr when
  not empty, M1-168); watchdog thread; redacting log layer; privilege snapshot and binary refusal; ring
  provider; spec load (verify, then parse); output directory created and held; plan; probes; checks
  (each result redacted as it completes); final pass; single-writer write; kill leftover process
  groups; exit.
- **Linux:** `/proc`, `/sys`, `O_PATH` reads, process groups.
- **macOS:** same Unix paths; SIP and TCC denials become `partial`.
- **Windows:** M1 exec is `whoami.exe` only; reports default to `%USERPROFILE%\rdy-reports`; Ctrl-C
  through `tokio::signal::ctrl_c`.
- **Temp files.** None in M1 besides `.tmp` files inside the output directory.
- **Exit codes.** Verdict 0, 1, 2; input errors 64; binary refusal, unwritable output, watchdog,
  interrupt and runtime failure 70 (ADR 0008). With `--json`, stdout carries the same bytes as the
  file, or the error object.

## Output and reports

- **Directory** (ADR 0016, ADR 0003).
  - `rdy-report-<product>-<YYYYMMDDTHHMMSSZ>/` goes under `--out-dir`. The default is `.` on Unix and
    `%USERPROFILE%\rdy-reports` on Windows (05 I3). The slug is `^[a-z0-9][a-z0-9-]{0,62}$` (01 section
    2.2) and is re-checked before use. A taken name retries `-2` to `-9`.
  - The directory is created right after verification and the handle is held. Unix: opened no-follow,
    owned by euid, `fchmod` to 0700. Windows: not a reparse point, final path equals the expected one.
  - Inside go `rdy-report-<product>-<ts>.json` and `.html`, plus `spec.yaml` and `spec.yaml.minisig`
    copied from the verified in-memory bytes (`VerifiedSpecBytes`). Each file is created `create_new`,
    0600 with `fchmod`, written as `.tmp`, fsynced, then renamed; the Windows rename retries 5 times at
    100 ms.
  - The ACL residuals (Windows inheritance, macOS inheritable ACEs) go into the report's notes until
    SEC-58. `--no-report` writes nothing.
- **JSON.** `write_json(&RedactedReport)` follows 01 section 5.5. After serializing, every `<` becomes
  the six characters `\u003c` (backslash, `u`, `0`, `0`, `3`, `c`), every `>` becomes `\u003e`, every `&`
  becomes `\u0026`, and U+2028 and U+2029 become `\u2028` and `\u2029`. The writer applies this to every
  copy, so the `.json` file, `--json` stdout and the HTML embed are the same bytes. The renderer does
  not escape a second time.
- **HTML.**
  - `render_html(&RedactedReport)` follows 01 section 6: content in 01's order (blockers, required not
    run, warnings, passed, not applicable, capabilities, details, action log as one plain table).
  - No `<details>`; vendor fix text is labelled "From <product>". An INCOMPLETE banner shows when
    `complete: false`.
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
| 8 Kube dry run | Rejected for M1 (05 INV-14, ADR 0010, 01 section 2.7). The catalog's constraints (core v1 Pod path only, `generateName: rdy-probe-`) go into any future ADR 0010 amendment that allows dry run. |
| 9 Shared helpers | Accepted: `rdy_engine::units`, covered by 03's "Shared helpers" ticket. |
| 10 ADR amendments | ADR 0009 by 0014; ADR 0010 amended in this revision (`selfsubjectreviews`, family-owned client); ADR 0006 item 5 (`getent`) in M2 with `net.dns`. |

## Custom checks later (ADR 0005)

None in M1; unknown ids skip and count as not run. M4 `custom.exec` reuses `Probe::exec` with a second
policy: commands from the spec, consent bound to the plan by `--allow-exec=<sha256 of the exec plan>` or
an interactive yes (a bare flag is refused), cwd in a fresh 0700 temp directory, 64 KiB caps. Under
euid 0 a custom command runs as an unprivileged user unless it declares `needs: [root]`. `Cmd` gets an
origin enum then, not before. Preconditions that hold from M1: `&'static str` programs with `Box::leak`
and `String::leak` banned, argv logged as an array, the root-only trust store, Windows job objects
before Windows exec. The plan flag is `--dry-run` in ADR 0005 and `--plan` in 01 and 05; cli-ux picks
one.

## Testing seams

- **Replay backend** (feature `testing`) reads 03's fixture layout:
  - `root/` maps absolute paths.
  - `commands/*.json` holds argv, stdout, stderr, exit and `delay_ms`.
  - `net.json` holds per host the `lookup` addresses (including forbidden ones, so `is_forbidden` runs
    in every net fixture), and per address `refused`, `blackhole`, `reset` or `serve: <name>`. `serve`
    connects a duplex stream to an in-process server from 03's loopback test support.
  - `native/` holds JSON per `NativeCall`; `env.json` and `caps.json` complete the case.
  - Anything unrecorded fails with `NotRecorded`.
- **CLI in process** (08 decision A, ADR 0011 decision 4 as amended). `#[doc(hidden)] rdy_cli::run(args,
  backend, hooks, out, err)`. Test hooks are `RunHooks` fields, never flags or env vars. CI checks that
  `Replay` is unnamed in `crates/rdy-cli/src` outside tests and that the `testing` feature and a
  Replay-only marker string are absent from every release binary. The log layer, panic hook, ring
  provider and `process::exit` stay in `main`. So the `RUST_LOG=trace` canary test and the watchdog
  exit-70 test use the real binary.
- **Kube.** Fixtures are a `tower` mock behind `guarded_service`, so the real layer order is under test.
  The kind job adds an API server audit policy and asserts rdy's user agent used only allowlisted verbs
  and resources.
- **Time and hangs.** `start_paused` tests. `FakeCheck` supports `Outcome`, `Sleep`, `Panic`, `Block`
  and `Spin`. Watchdog tests:
  - a finish at deadline plus 9.9 s keeps the complete report;
  - a blocked stdout pipe still gives exit 70 within deadline plus 22 s;
  - a held snapshot lock still gives a report;
  - a fake exec plugin that sleeps 600 s still ends with a report.
- **Redaction at caps.** For each facade cap, canaries at offsets cap minus 1 to cap minus 64 (M1
  corpus).
- **Goldens** use `Clock::Fixed` and a fixed run id. Live integration runs against loopback servers on
  all four CI targets, with strace completeness on Linux.

## Plan corrections found

- docs/plan/01-spec-format.md, section 5.2 `not_applicable` row and section 5.3 amendment 2: they list
  "the concept does not exist here" as a source of `not_applicable`. Fix: only the spec `os` list can
  produce it. Concept absence is either `pass` through `pass_by_absence` or `not_yet_on_os` (ADR 0013).
- docs/plan/01-spec-format.md, section 2.3 `timeout`: the formula `min(spec, check default, 60s, time
  left)` means a spec can never raise a timeout. Fix: the spec value replaces the default, capped at
  60 s and at the time left.
- docs/plan/01-spec-format.md, section 5.4:
  - add outcome `delegated`;
  - say `argv` is an array of strings;
  - add `partial.missing_grants`.
- docs/plan/01-spec-format.md, section 5.5: truncation removes only `ok` read, read_dir and stat
  entries, and the 2 MiB cap is measured after escaping.
- docs/plan/01-spec-format.md, section 5.1: macOS `host_id` is null in M1, and `identity.kube.user`
  comes from `SelfSubjectReview` (ADR 0010 as amended), marked "not verified" before 1.28.
- docs/plan/01-spec-format.md, section 2.7: validate `namespace` and `name` values as DNS-1123, and the
  `as:` value as in Appendix B rule 8.
- docs/adr/0009-http-client-and-tls.md: its M1 ticket "Shared HTTP client builder with rustls ring and
  platform verifier" leaves M1, replaced by the facade network tickets. Its status line now names
  ADR 0014.
- docs/plan/03-check-catalog.md:
  - host coverage and the M1 `sysinfo` subset: declined (Per-OS).
  - `host.ports`: no bind fallback in M1.
  - `net.proxy`: no PAC fetch in M1.
  - `net.egress` and `net.registry`: redirects are recorded, never followed.
  - "net.egress core": its connector work moves into the facade; check-author re-estimates it.
  - "Command table and argument allow-lists from Appendix A": depends on the retired SEC-18. Fix: it
    depends on "Command policy: search path, declared directories, caps and Windows whoami only".
  - Appendix A Windows rows (`NETSTAT.EXE`, `netsh`): wait for the M2 job object ticket.
- docs/plan/08-testing.md:
  - Rules item 3 and section 6 say "only the closure passed to `probe.native(..)`". Fix: "only the
    Live arm of each `NativeCall` variant".
  - The scheduler timeout and cancellation ticket expects `interrupted: true` and `cancelled` in M1
    and depends on an M2 ticket. Fix: depend on "Run deadline and watchdog with a report on hang"; the
    M1 test asserts exit 70 and no file under a final name, and the report assertions move to the M2
    graceful Ctrl-C ticket.
  - The in-process entry point gains a `RunHooks` parameter (ADR 0011 decision 4).
- docs/plan/05-threat-model.md (security-reviewer, revision 3):
  - INV-12: the `is_forbidden` ranges.
  - Appendix A I3: name ADR 0016 and `%USERPROFILE%\rdy-reports`.
  - Appendix F: cap-boundary redaction cases are M1.
  - INV-08: fixed PATH always.
- docs/plan/00-overview.md:
  - rdy-engine and rdy-checks-k8s API sketches: `Exec` trait, `Context`, `host_root`, public
    `connect()`. Fix: as in Appendix A.
  - M1 calendar: about 194 h becomes about 248 h.

## M1 hours and cut list

The engine M1 tickets below total **84.5 h**. That counts tickets owned elsewhere that this design
re-scopes: SEC-17, SEC-19, SEC-25, SEC-21, Blocking helper, Check trait, Scheduler and the kube guard.

Against 00's 194 h, the net addition is about 54 h:
- the first review's 43 h;
- about 4 h for moving TCP, CONNECT, TLS and HTTP into the facade, partly offset by the dropped
  ADR 0009 builder ticket;
- about 7 h from the second review (truncated-buffer redaction 3 h, dependency allowlist 1 h, Windows
  output directory 1 h, watchdog and kube guard folds 3 h, native snapshot 0.5 h, less the ADR 0010
  amendment done here, 1 h, and a shorter sign-off, 1 h, plus 0.5 h on 08's entry point).

**M1 is about 248 h**, roughly 19 weeks at 13 hours a week. The founder decides in 00.

Cut list, invariant-neutral, first cut first:
1. Graceful Ctrl-C report and per-family limits (already M2).
2. Merge "Engine test helpers" into "Replay backend and fixture loader": 1 h.
3. Merge "Family probe hook and lazy KubeContext probe" into "Kube client from kubeconfig or
   in-cluster": 1 h.
4. One address per host in M1 instead of dual-stack attempts: 1 h.
5. HTML action log table limited to exec, connect and kube rows (the JSON has all): 0.5 h.

Never cut:
- the facade policies, the closed native enum, the lint wall and the dependency allowlist;
- the kube guard and its exact list;
- output confinement, including the Windows default;
- the privilege snapshot and binary refusal;
- redaction of reports, truncated buffers and logs;
- timers on the join handle, with the deadline and the single-writer watchdog;
- the verdict mapping and the lazy kube need.

## Tickets implied

Titles reuse 05 revision 2, 00, ADR and 03 titles where the work is the same. SEC-18, SEC-20 and SEC-23
are retired as duplicates (review SF-12). The ADR 0010 amendment ticket of revision 2 is done in this
revision.

- [M1] Check trait, Need and Context in rdy-engine | owner: rust-engineer | est: 3.5h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a fake family with one passing and one need-missing check maps to pass and skipped missing_need through the outcome types, and no CheckError or Support variant can produce not_applicable.
- [M1] Privilege snapshot, binary refusal and capability probes | owner: rust-engineer | est: 3.5h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: injected mismatches of real, effective, saved and filesystem uid or gid, a nonzero CapEff or CapAmb, and AT_SECURE each exit 70 with the hint before the spec is read; recorded whoami output maps High and System to elevated and a whoami failure to an unknown `root` need; needs absent from the plan are not probed.
- [M1] Family trait, registry and run plan | owner: rust-engineer | est: 3h | depends on: Unknown check ids report Skipped with a "needs a newer rdy" reason | exit test: the plan for examples/specs/acme-platform.yaml gives not_in_build for gpu.cuda and aws.iam, unknown_check for a typo id, not_yet_on_os for host checks on Windows, not_applicable only for an `os: [linux]` entry on macOS, per-check host sets, and does no I/O.
- [M1] Family probe hook and lazy KubeContext probe | owner: rust-engineer | est: 2.5h | depends on: Privilege snapshot, binary refusal and capability probes, Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a spec with no k8s checks loads no kubeconfig and sends no request; `--no-network` builds no client; a fake exec plugin that sleeps 600 s makes kube_context unavailable after 10 s with no worker blocked.
- [M1] Scheduler with concurrency limit, per-check timeout and panic isolation | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: with the timer on the join handle, FakeCheck Sleep reports timeout, Panic reports error panic, and Spin on a 2-worker runtime still lets the other checks finish; a fake family's passing and need-missing checks come back through the scheduler as pass and skipped missing_need.
- [M1] Run deadline and watchdog with a report on hang | owner: rust-engineer | est: 3.5h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation, SEC-19 Confine writes to a new output dir with safe names | exit test: under paused time running checks become timeout and unstarted ones run_deadline; a finish at deadline plus 9.9 s keeps the complete report; two Spin checks with a blocked stdout pipe and a held snapshot lock still give a complete false report and exit 70 within deadline plus 22 s, with no child process group left.
- [M1] Map outcomes to CheckResult with fix source, partial and needs | owner: rust-engineer | est: 2h | depends on: Check trait, Need and Context in rdy-engine, Define result model and verdict mapping in rdy-spec | exit test: a spec fix replaces the built-in text on block with fix_source spec and is hidden on skipped, a partial pass on a block check becomes warn unless evidence_only, a result from a Partial OS is marked partial, and needs carry met flags.
- [M1] SEC-17 Mediated Context handles with action log and read denylist | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: the fixture run's action log lists every command, file, endpoint and kube request; a read of /proc/1/environ is refused; a Probe call after its check ends is denied and logged; truncation drops only ok read, read_dir and stat entries.
- [M1] Blocking helper and subprocess kill on timeout | owner: rust-engineer | est: 4h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: a check running `sleep 600` times out, its process group is gone, a child that ignores reaping returns Hung within 1 s of SIGKILL, and rdy exits within 2 s of the deadline.
- [M1] Command policy: search path, declared directories, caps and Windows whoami only | owner: rust-engineer | est: 2h | depends on: Blocking helper and subprocess kill on timeout | exit test: shells and the sudo family are refused, PATH is fixed for non-root runs too, LD_PRELOAD in the parent never reaches the child, a declared extra directory resolves, and on Windows only the constant whoami.exe path runs.
- [M1] File and env read policy in the facade | owner: rust-engineer | est: 3.5h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: /etc/shadow, a symlink to it, a `..` path, a FIFO and /dev/zero under an allowed prefix are refused and logged; a 2 MiB file returns 1 MiB with truncated true; an undeclared env name is refused; a file read outside the check's `reads` prefixes is refused and logged.
- [M1] Facade TCP attempts, proxy CONNECT and per-check host sets | owner: rust-engineer | est: 4h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: a host listed only by another check is denied, a CONNECT to a literal 169.254.169.254 is refused before any byte is sent, proxy 403 and 407 return typed errors, and Proxy-Authorization never appears in the log.
- [M1] Facade TLS with system roots and the recording chain probe | owner: rust-engineer | est: 3h | depends on: Facade TCP attempts, proxy CONNECT and per-check host sets | exit test: against loopback servers a test-CA chain validates only when the CA is in the fixture system bundle, tls_chain returns the chain without sending application data, and SNI always equals the permitted host.
- [M1] Facade HTTP/1.1 probe with 64 KiB discard and no redirects | owner: rust-engineer | est: 3h | depends on: Facade TLS with system roots and the recording chain probe | exit test: a 302 returns its Location host without a second request, a body canary never reaches the report, and each failure class is produced by its loopback case.
- [M1] SEC-21 Egress address policy, no redirects, no bodies | owner: rust-engineer | est: 3h | depends on: Facade HTTP/1.1 probe with 64 KiB discard and no redirects | exit test: link-local, metadata and IPv4-mapped targets are refused directly, by DNS and as CONNECT targets, and more than 64 distinct hosts fail spec validation with exit 64.
- [M1] Closed NativeCall enum in the facade | owner: rust-engineer | est: 2.5h | depends on: File and env read policy in the facade | exit test: Statvfs on a path outside the check's prefixes is refused, every variant is logged as native, the raw machine id appears nowhere in the report, the variant snapshot test fails on a new variant, Backend cannot be implemented outside rdy-engine, and check crates cannot call live_backend.
- [M1] Read-only guard layer and test for rdy-checks-k8s | owner: k8s-expert | est: 3h | depends on: Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a mock API server behind guarded_service records every request from the k8s suite and only allowlisted GETs and the three review POSTs appear, the SelfSubjectReview with its fixed body only.
- [M1] Kube guard path parser, resource allowlist and pending log entries | owner: rust-engineer | est: 3.5h | depends on: Read-only guard layer and test for rdy-checks-k8s | exit test: `%73ecrets`, `secrets` in every segment position, `/api/v1/namespaces/x/finalize`, GET pods/exec with Upgrade, a dryRun POST, a SelfSubjectReview with another body, Impersonate-User on a GET and an unlisted resource are each refused and logged; `/api/v1/namespaces/secrets` is allowed; every ALLOWED entry is cited by a CheckInfo; a dropped request leaves a timeout entry with its check id.
- [M1] Replay backend and fixture loader | owner: rust-engineer | est: 3h | depends on: File and env read policy in the facade, Closed NativeCall enum in the facade | exit test: a host.memory fixture runs with no real file read, an unrecorded argv fails with NotRecorded, a recorded link-local lookup is refused by the address rule, and the release feature tree excludes `testing`.
- [M1] Engine test helpers FakeCheck, run_fixture and normalize | owner: qa-engineer | est: 2h | depends on: Replay backend and fixture loader | exit test: scheduler tests use every Fake variant including Spin, and assert_within_manifest fails on a fixture check that reads an undeclared path.
- [M1] Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers | owner: rust-engineer | est: 2h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: every Appendix A entry except the kube ones (kube entries: clippy lists in M1-102, lint-wall proof in M1-107) used in tests/lint-wall fails clippy, an allow attribute outside the allowlisted files fails CI, and a check crate depending on socket2 fails cargo deny.
- [M1] Direct dependency allowlist for check crates | owner: rust-engineer | est: 1h | depends on: Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers | exit test: adding `walkdir` to rdy-checks-host fails CI, and the lint-wall crate has one exact entry per item with no wildcard.
- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: product `../x` fails validation, a pre-planted symlink is not followed, a taken name moves to `-2`, modes are 0700 and 0600 under a setgid parent, the spec copy matches the verified bytes under fixed names, and a killed run leaves no file under a final name.
- [M1] Windows output directory default and reparse-point checks | owner: rust-engineer | est: 1h | depends on: SEC-19 Confine writes to a new output dir with safe names | exit test: on the Windows CI leg the default lands under %USERPROFILE%\rdy-reports, and a pre-planted junction and a symlink with the target name are both refused before the first check.
- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: canaries in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace`.
- [M1] Redact facade-truncated buffers and a run-scoped known-secret set | owner: rust-engineer | est: 3h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: a PEM key, an AWS key id and a URL with userinfo placed across the stdout, stderr, file and tail caps at offsets cap minus 1 to cap minus 64 never appear in JSON, HTML or stderr, and the kubeconfig token is redacted wherever it appears.
- [M1] Redact then cap every Report string and return RedactedReport | owner: rust-engineer | est: 2h | depends on: SEC-25 Minimal redactor for evidence, errors and logs, Map outcomes to CheckResult with fix source, partial and needs | exit test: a PEM key placed across a 64 KiB cap boundary is fully redacted, results are redacted as they complete, and write_json, render_html and the terminal renderer do not compile with a plain Report.
- [M1] HTML fix source label and action log table | owner: rust-engineer | est: 1h | depends on: askama HTML report with inline CSS, dark mode and print | exit test: the golden blocked HTML labels vendor fix text with the product name and shows the action log as one table with no details element.
- [M1] OS support table and compile stubs for rdy-checks-host | owner: check-author | est: 2h | depends on: Family trait, registry and run plan | exit test: all four CI targets build, every host check on macOS and Windows reports not_yet_on_os, and none does on Linux.
- [M1] Security re-review sign-off of 02 revision 3 and ADRs 0014 to 0016 | owner: security-reviewer | est: 1h | depends on: Redact facade-truncated buffers and a run-scoped known-secret set | exit test: MF-01 to MF-06 of the ADR 0013 to 0016 review are marked closed in the reviewed files.
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
- [M4] Spec-origin exec policy, hash-bound consent and temp workdir for custom.exec | owner: rust-engineer | est: 4h | depends on: SEC-53 Threat model for custom.exec | exit test: a bare --allow-exec is refused, the right hash runs commands as an unprivileged user under euid 0 in a fresh temp dir with 64 KiB caps, and a wrong hash runs nothing.
- [M3] http_exchange and Need::Consent for SDK adapters | owner: rust-engineer | est: 4h | depends on: Facade HTTP/1.1 probe with 64 KiB discard and no redirects | exit test: the AWS SDK adapter fixture runs through the facade with every call in the action log and no body in the report, and assume-role without consent is skipped missing_need.
- [M3] Decide the 1.0 stability scope of Check, Family and Probe | owner: rust-architect | est: 3h | depends on: none | exit test: an ADR says whether these modules are semver-covered at 1.0 or move under rdy_engine::unstable, before rdy-engine 1.0 ships.

## Appendix A. Rust signatures

```rust
// check.rs
pub struct CheckInfo {
    pub id: &'static str, pub family: &'static str, pub summary: &'static str,
    pub meta: CheckMeta, // ADR 0026 (M1-089)
    pub needs: &'static [Need], pub wants: &'static [Want],
    pub default_timeout: Option<Duration>, pub os: OsSupport,
    pub reads: &'static [&'static str], pub env: &'static [&'static str],
    pub commands: &'static [CommandSpec], pub peers: &'static [PeerClass],
}
pub struct CheckMeta { pub title: &'static str, pub remediation: &'static str }
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
    fn build(&self, entry: &CheckSpec, params: CheckParams, spec: &Spec) -> Result<Built, BuildError>;
}
pub struct Built { pub check: Box<dyn Check>, pub hosts: HostSet }  // HostSet: deduplicated Vec<Target>
// plan.rs (M1-035): Registry::plan is pure and takes a &Spec (from LoadedSpec::spec()) and the binary's version.
// INV-01 (no parse before verification) is enforced where a LoadedSpec is required: Engine::run (M1-057).
impl Registry { pub fn plan(&self, spec: &Spec, os: Os, rdy_version: &str) -> RunPlan; }

// privilege.rs, sched.rs
pub struct Privilege { pub uid: [u32; 4], pub gid: [u32; 4], // real, effective, saved, filesystem
                       pub cap_eff: u64, pub cap_amb: u64, pub at_secure: bool, pub elevation: Elevation }
pub enum Elevation { Root, High, System, NotElevated, Unknown }
impl Privilege { pub async fn snapshot(probe: &Probe) -> Result<Self, EngineError>; // all ids, CapEff, CapAmb, AT_SECURE
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
// One Cmd type: rdy_engine::exec::policy::Cmd { program: &'static str, args, extra_dirs, env names, timeout, stdout_cap }.
// Build it with CommandEntry::cmd (the command table, ADR 0028). Probe::exec applies the check's
// CommandSpec (dirs, env names, cap), then table::validate_for(ctx.os, ..), so a command that is not in
// the table never reaches any backend, replay included (PC-44).

pub enum Target { Direct { host: String, port: u16 }, ViaProxy { host: String, port: u16 } }
pub struct HttpProbe { pub url: String, pub method: Method /* Head | Get */, pub route: Route,
                       pub roots: Roots /* System | Bundled */ }
#[non_exhaustive]
pub enum NativeCall { Statvfs { path: PathBuf }, Uname, Rlimit(Resource), Hostname,
                      MachineId /* raw value never logged or reported */, SystemRoots }
#[non_exhaustive]
pub enum ProbeError { Denied { rule: &'static str, what: String }, Policy(PolicyError), Table(TableError),
                      NotFound, PermissionDenied, Timeout, Hung { pid: u32 }, Net(NetFailure), Io(String),
                      NotRecorded(String) }   // Clone + PartialEq + Eq; every message ends with a Fix: hint
pub trait Backend: sealed::Sealed + Send + Sync + 'static {   // Live and Replay only; raw I/O, no policy
    fn open_read<'a>(&'a self, path: &'a Path, range: ReadRange) -> BoxFuture<'a, io::Result<FileBytes>>;
    fn read_dir<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Vec<DirEntry>>>;
    fn read_link<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<PathBuf>>;
    fn stat<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, io::Result<Option<FileMeta>>>;
    fn env(&self, name: &str) -> Option<String>;
    // Provided: the live path, exec::table::run (the only public runner). Replay overrides it. (PC-44)
    fn spawn<'a>(&'a self, cmd: Cmd) -> BoxFuture<'a, Result<Output, ProbeError>> { /* table::run */ }
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<BoxedStream>>;
    fn native<'a>(&'a self, call: &'a NativeCall) -> BoxFuture<'a, io::Result<NativeValue>>;
}

// output, report, redact
impl OutputDir { pub fn create_new(parent: &Path, product: &str, ts: &str) -> Result<Self, ReportError>;
                 pub fn write_atomic<T: AsRef<[u8]>>(&self, name: &str, c: &Redacted<T>) -> Result<PathBuf, ReportError>;  // M1-036
                 pub fn write_report(&self, r: &RedactedReport) -> Result<(), ReportError>;  // M1-062, calls write_atomic
                 pub fn write_spec(&self, s: &VerifiedSpecBytes) -> Result<Vec<PathBuf>, ReportError>; }  // M1-036
pub fn write_json(r: &RedactedReport, out: &mut dyn std::io::Write) -> Result<(), ReportError>;
pub fn render_html(r: &RedactedReport) -> Result<String, ReportError>;
pub struct RedactedReport(/* private */ Report);   // no From<Report>, no Deserialize, no DerefMut
pub fn live_backend() -> Arc<dyn Backend>;        // disallowed in check crates
pub struct FileBytes { pub bytes: Vec<u8>, pub truncated_head: bool, pub truncated_tail: bool }
pub fn blocking<T, F>(f: F) -> BoxFuture<'static, Result<T, CheckError>>
where F: FnOnce() -> Result<T, CheckError> + Send + 'static, T: Send + 'static;
```

Lint wall entries for every check crate's `clippy.toml`. Exact items only, because clippy matches exact
paths; each one is used once in `tests/lint-wall`, and CI expects each use to fail clippy. A type entry
catches every constructor and method reached by naming the type, so `std::fs::File` covers `File::open`
and `File::options`. Method entries that a type entry also covers stay, so the wall does not hinge on
one clippy rule.
- Process: type `std::process::Command`; `std::process::Command::new`, `std::process::exit`,
  `std::process::abort`, `tokio::process::Command::new`.
- Files and directories: types `std::fs::File`, `std::fs::OpenOptions`, `std::fs::DirBuilder`;
  `std::fs::read`, `std::fs::read_to_string`, `std::fs::read_dir`, `std::fs::read_link`,
  `std::fs::metadata`, `std::fs::symlink_metadata`, `std::fs::canonicalize`, `std::fs::exists`,
  `std::fs::write`, `std::fs::copy`, `std::fs::rename`, `std::fs::remove_file`, `std::fs::remove_dir`,
  `std::fs::remove_dir_all`, `std::fs::create_dir`, `std::fs::create_dir_all`,
  `std::fs::File::open`, `std::fs::File::create`, `std::fs::File::create_new`,
  `std::fs::OpenOptions::new`.
- Paths that touch the file system: `std::path::Path::metadata`, `std::path::Path::symlink_metadata`,
  `std::path::Path::canonicalize`, `std::path::Path::read_link`, `std::path::Path::read_dir`,
  `std::path::Path::exists`, `std::path::Path::try_exists`, `std::path::Path::is_file`,
  `std::path::Path::is_dir`, `std::path::Path::is_symlink` (`PathBuf` reaches these through `Deref`).
- Links and permissions: `std::fs::hard_link`, `std::fs::soft_link`, `std::fs::set_permissions`,
  `std::os::unix::fs::symlink`, `std::os::unix::fs::chown`, `std::os::unix::fs::fchown`,
  `std::os::unix::fs::lchown`, `std::os::unix::fs::chroot`, `std::os::windows::fs::symlink_file`,
  `std::os::windows::fs::symlink_dir`.
- Sockets: types `std::net::TcpStream`, `std::net::TcpListener`, `std::net::UdpSocket`,
  `std::os::unix::net::UnixStream`, `std::os::unix::net::UnixListener`,
  `std::os::unix::net::UnixDatagram`, `socket2::Socket`; `std::net::TcpStream::connect`,
  `std::net::TcpStream::connect_timeout`, `std::net::TcpListener::bind`, `std::net::UdpSocket::bind`,
  `std::net::ToSocketAddrs::to_socket_addrs`, `std::os::unix::net::UnixStream::connect`,
  `std::os::unix::net::UnixStream::connect_addr`, `std::os::unix::net::UnixStream::pair`,
  `std::os::unix::net::UnixListener::bind`, `std::os::unix::net::UnixListener::bind_addr`,
  `std::os::unix::net::UnixDatagram::bind`, `std::os::unix::net::UnixDatagram::bind_addr`,
  `std::os::unix::net::UnixDatagram::unbound`, `std::os::unix::net::UnixDatagram::pair`,
  `tokio::net::TcpStream::connect`, `tokio::net::UdpSocket::bind`, `tokio::net::TcpListener::bind`,
  `tokio::net::lookup_host`, `tokio::net::UnixStream::connect`.
- Threads and tasks: type `std::thread::Builder`; `std::thread::spawn`, `std::thread::scope`,
  `std::thread::Builder::spawn`, `std::thread::Builder::spawn_scoped`, `tokio::spawn`,
  `tokio::task::spawn_blocking`.
- Env, read and write: `std::env::var`, `std::env::var_os`, `std::env::vars`, `std::env::vars_os`,
  `std::env::set_var`, `std::env::remove_var`, `std::env::current_dir`, `std::env::set_current_dir`,
  `std::env::current_exe`, `std::env::home_dir`, `std::env::temp_dir`. (`set_var` and `remove_var`
  are `unsafe` in edition 2024, so `forbid(unsafe_code)` also stops them.)
- Leaks: `Box::leak`, `String::leak`, `Vec::leak`.
- Engine: `rdy_engine::live_backend`.
- Kube, outside the `rdy-checks-k8s` client module: types `kube::Client`, `kube::Config`,
  `kube::client::ClientBuilder`, `kube::config::Kubeconfig`; `kube::Client::new`,
  `kube::Client::try_default`, `kube::client::ClientBuilder::new`, `kube::Config::new`,
  `kube::Config::infer`, `kube::Config::incluster`, `kube::Config::incluster_env`,
  `kube::Config::incluster_dns`, `kube::Config::from_kubeconfig`,
  `kube::Config::from_custom_kubeconfig`, `kube::config::Kubeconfig::read`,
  `kube::config::Kubeconfig::read_from`, `kube::config::Kubeconfig::from_env`,
  `kube::config::Kubeconfig::from_yaml`. The paths `kube::client::Client` and `kube::config::Config`
  are re-exports of the same items, and clippy matches the item, so one entry covers both.
  - Trait routes: `TryFrom<Config>` and `TryFrom<Kubeconfig>` for `Client`, `TryFrom<Config>` for
    `ClientBuilder`, and `Default` and `Deserialize` for `Kubeconfig`. Each needs a named `Config` or
    `Kubeconfig` (type inference cannot pick one), so the type entries cover them. `tests/lint-wall`
    uses each route once.
  - `From<Api<K>>` for `Client` and `Api::into_client` return the client inside an `Api`. Checks only
    get `kube::Api<K>` values from `ReadOnlyClient`, so that client is the guarded one.
  - `ReadOnlyClient` hands out `kube::Api<K>` and never a `kube::Client`, so check code never names
    the type.
  - Verified on 2026-10-28 against kube 4.2.0 on docs.rs (`kube`, `kube::client` and `kube::config`
    index pages, and the `Client`, `Config`, `ClientBuilder`, `Kubeconfig` and `Api` pages). M1-102
    adds and pins kube, so the kube entries land there, re-checked against the pinned version (kube
    entries: clippy lists in M1-102, lint-wall proof in M1-107).
- Not listed: crates other than std, kube and the facade. `tokio`, `rustix`, `nix`, `socket2`,
  `walkdir`, `sysinfo` and the rest are not direct dependencies of any check crate, so their APIs are
  out of reach. The direct dependency allowlist enforces that, not clippy. The `tokio` and `socket2`
  entries above are a second line.

## Appendix B. Kube guard rules

Global rules, because `call` runs on kube's buffer worker without a check id.

1. **Path pre-filter.** Refuse a path containing `%`, `..`, `//`, `;`, an empty segment, a trailing `/`
   or a non-ASCII byte. The `%` rule applies to the path only. Query values are decoded once, then
   validated (kube-rs percent-encodes `fieldSelector`). Refuse `Upgrade` and `Connection: upgrade`.
   Allowed query keys: `limit`, `continue`, `labelSelector`, `fieldSelector`. Anything else, including
   `watch`, `follow` and `dryRun`, is refused.
2. **Parse** into group, version, namespace, resource, name and subresource, following the API server's
   request-info rules:
   - `/api/v1/namespaces/secrets` is a GET of a namespace named `secrets`, so it is allowed.
   - `/api/v1/namespaces/x/secrets/y` is refused.
   - `/api/v1/namespaces/x/finalize` is a subresource, so it is refused.
   - Any subresource is refused in M1.
3. **Discovery GETs:** `/version`, `/api`, `/apis`, `/api/v1`, `/apis/<group>` and
   `/apis/<group>/<version>`. The group must be a DNS-1123 subdomain and the version must match
   `^v[0-9]+((alpha|beta)[0-9]+)?$`. These serve `k8s.access`, `k8s.version` `apis`, the `k8s.admission`
   engine discovery (`security.openshift.io`, `kyverno.io`, `policies.kyverno.io`,
   `templates.gatekeeper.sh`, `constraints.gatekeeper.sh`) and Karpenter detection in `k8s.nodes`.
4. **`rdy_checks_k8s::ALLOWED`**, M1. Each entry names the check and field it serves, and a unit test
   asserts every entry is cited by at least one check's `CheckInfo` and that `secrets` appears nowhere.
   k8s-expert confirms the list against 03 before the guard ticket starts.

| Group, resource | Verbs and scope | Check: what it reads |
| --- | --- | --- |
| core `namespaces` | GET by name | `k8s.admission`: PSA labels; `k8s.storageclass`, `k8s.rbac`: namespace exists |
| core `nodes` | LIST | `k8s.nodes`: allocatable, conditions, taints, labels; `k8s.version`: `providerID`, `kubeletVersion` |
| core `pods` | LIST, cluster-wide or by `spec.nodeName`, with a `status.phase` field selector | `k8s.nodes`: requests, `nodeName`, phase only |
| core `persistentvolumeclaims` | LIST in the target namespace | `k8s.storageclass`: Pending claims older than 5 minutes |
| core `events` | LIST in the target namespace, `fieldSelector` must include `involvedObject.kind=PersistentVolumeClaim` | `k8s.storageclass`: `ProvisioningFailed`, `WaitForFirstConsumer` reasons |
| `storage.k8s.io` `storageclasses` | LIST, GET by name | `k8s.storageclass`: classes, default marker, provisioner |
| `storage.k8s.io` `csinodes` | LIST | `k8s.storageclass`: `spec.drivers[].name` |
| `storage.k8s.io` `csidrivers` | LIST | `k8s.storageclass`: driver objects |
| `apps` `deployments` | LIST in `kube-system` only | `k8s.nodes`: `cluster-autoscaler` presence by name |
| `security.openshift.io` `securitycontextconstraints` | LIST | `k8s.admission`: SCCs |
| `config.openshift.io` `clusterversions` | GET name `version` | `k8s.version`: OpenShift version |

5. **`M1_LATE`**, enabled only with the checks that need it: `admissionregistration.k8s.io` webhook
   configurations, `validatingadmissionpolicies` and bindings; core `services`; `discovery.k8s.io`
   `endpointslices`; Kyverno and Gatekeeper policy objects; ConfigMap GET of `kube-system/kubeadm-config`
   by name; the resources of `k8s.namespace`, `k8s.crds`, `k8s.ingress`, `k8s.cni`, `k8s.dns` and
   `k8s.device_plugins`. Each joins with the same citation rule.
6. **Projections.** `pods`, `events` and `deployments` deserialize into minimal structs (resources,
   `nodeName`, phase, reason, name), so env values and args are never even held as strings. ConfigMap
   lists must use an `Accept` header for `PartialObjectMetadataList`, and a response of any other
   `kind` is dropped.
7. **POST** with no query string, only to:
   - `/apis/authorization.k8s.io/v1/selfsubjectaccessreviews` and `.../selfsubjectrulesreviews`
     (`k8s.rbac`, `k8s.access` below 1.28);
   - `/apis/authentication.k8s.io/v1/selfsubjectreviews` (`k8s.access`, `k8s.rbac`, the identity line),
     with exactly the body `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`,
     compared byte for byte. Only `username` and `groups` are kept from the response. On 1.27 and
     older the report shows the kubeconfig user marked "not verified by the API server".

   Every other method is refused.
8. **Headers.** `Impersonate-*` headers are allowed only on the access and rules review POSTs. The value
   must equal the validated spec `as:` value: `system:serviceaccount:<dns1123>:<dns1123>`, or a user
   string with no control characters, at most 253 bytes. Otherwise only values the operator's kubeconfig
   sets are allowed. The header name is logged, never a token.
9. **Data.** Response bodies are capped at 32 MiB. Spec `namespace` and `name` values are DNS-1123
   (rdy-spec).
10. **Refusals.** Every refusal is a `kube` entry with outcome `denied` and the rule name. The request
    never leaves the process.
