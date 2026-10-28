# ADR 0004: tokio multi-thread runtime, blocking work on spawn_blocking, every check under a timeout

- Status: Accepted (revised 2026-10-28 after security-reviewer review)
- Date: 2026-10-27

## Context

Most checks are I/O: TCP and TLS to endpoints, DNS, the Kubernetes API, later cloud APIs. The crates we
need for those (`kube`, `reqwest`, the AWS SDK) are async and built on tokio. Host checks are blocking:
reading `/proc`, `sysinfo` calls, running `getenforce` or `nvidia-smi`. CLAUDE.md says no check may hang
and a timeout is a result, not a crash. A run is short and has tens of checks. Subprocesses run as root
in many runs, so how they are started matters as much as how they are stopped.

## Decision

1. `rdy` builds one tokio runtime: `Builder::new_multi_thread()` with `worker_threads = min(4,
   available_parallelism)`, `enable_all()`. No `#[tokio::main]`, so the CLI controls shutdown.
2. At most 8 checks run at a time (a `Semaphore`). `--jobs` overrides it, capped at 32.
3. Every check runs inside `tokio::time::timeout`. Default 10 s, spec override per check, global run
   deadline 5 minutes. On expiry the result is `Timeout { after }` and the run continues.
4. Blocking work goes through one helper, `rdy_engine::blocking(f)`, which wraps `spawn_blocking`.
5. Subprocesses go only through the engine's `Exec` handle:
   - argv only, no shell. The program is resolved to an absolute path before spawning. When euid is 0,
     PATH is fixed to `/usr/sbin:/usr/bin:/sbin:/bin`; the user's PATH is never used.
   - `sudo`, `su`, `doas` and `pkexec` are refused.
   - Cleared environment plus a named allowlist (`LANG`, `LC_ALL`, `TZ`, and per-command extras).
   - Each child starts in its own process group (a job object on Windows); on timeout the whole group is
     killed, so grandchildren do not outlive it. Stdout and stderr are capped.
   - `clippy::disallowed_methods` bans `std::process::Command`, `tokio::process::Command`,
     `std::thread::sleep` and `std::net::TcpStream::connect` in check crates. Only the `Exec`
     implementation may spawn.
6. A `spawn_blocking` task cannot be cancelled. If one is stuck past its timeout the engine reports
   `Timeout`, and at the end of the run the runtime is dropped with `shutdown_timeout(1s)`, so a stuck
   thread can delay exit by at most one second.
7. Each check runs in its own `tokio::spawn`; a panic becomes `Error` for that check (ADR 0008).

## Consequences

- One async stack shared by reqwest, kube and later the AWS SDK.
- Check authors cannot block inside async code or spawn processes on their own; review and clippy hold
  the line.
- Library crates take only the tokio features they use; only `rdy` enables `rt-multi-thread`.
- The one exception to rule 5's environment clearing is Kubernetes exec credential plugins (ADR 0010).

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| tokio current-thread | One accidental blocking call stalls every timer, so timeouts stop firing. |
| No async (threads plus `ureq`) | `kube` and the AWS SDK are async-only; we would run two HTTP stacks. |
| `smol` or `async-std` | `async-std` is discontinued; neither is what `kube` and `reqwest` are built on. |
| Inherit PATH | A fake `getenforce` in a user-writable PATH directory would run as root. |

## Tickets implied

- [M1] Scheduler with concurrency limit, per-check timeout and panic isolation | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture check that sleeps forever reports Timeout, one that panics reports Error, `--jobs 500` is capped at 32, and the other checks still pass.
- [M1] Blocking helper and subprocess kill on timeout | owner: rust-engineer | est: 4h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: a check running a script that forks `sleep 600` times out, the whole process group is gone, `rdy` exits within 2 s, a fake binary earlier in a root user's PATH is not used, and `sudo` is refused.
