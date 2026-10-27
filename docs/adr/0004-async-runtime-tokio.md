# ADR 0004: tokio multi-thread runtime, blocking work on spawn_blocking, every check under a timeout

- Status: Accepted
- Date: 2026-10-27

## Context

Most checks are I/O: TCP and TLS to endpoints, DNS, the Kubernetes API, later cloud APIs. The crates we
need for those (`kube`, `reqwest`, the AWS SDK) are async and built on tokio. Host checks are blocking:
reading `/proc`, `sysinfo` calls, running `getenforce` or `nvidia-smi`. CLAUDE.md says no check may hang
and a timeout is a result, not a crash. A run is short (seconds) and has tens of checks, not thousands.

## Decision

1. `rdy-cli` builds one tokio runtime: `Builder::new_multi_thread()` with `worker_threads = min(4,
   available_parallelism)`, `enable_all()`. No `#[tokio::main]` so the CLI controls shutdown.
2. Checks run concurrently, at most 8 at a time (a `Semaphore`, overridable with `--jobs`). Checks that
   share a resource (for example the same kube client) still run in parallel; the client handles it.
3. Every check runs inside `tokio::time::timeout`. Default 10 s, spec override per check, global run
   deadline 5 minutes. On expiry the result is `Timeout { after }` and the run continues.
4. Blocking work goes through one helper, `rdy_engine::blocking(f)`, which wraps `spawn_blocking`.
   Subprocesses use `tokio::process::Command` with `kill_on_drop(true)`, a cleared environment plus an
   allowlist, and a stdout cap, so a timeout kills the child.
5. A `spawn_blocking` task cannot be cancelled. If one is stuck past its timeout the engine reports
   `Timeout`, and at the end of the run the runtime is dropped with `shutdown_timeout(1s)`, so a stuck
   thread can delay exit by at most one second, never hang it.
6. Each check runs in its own `tokio::spawn`; a panic becomes `Error` for that check (ADR 0008).

## Consequences

- One async stack shared by reqwest, kube and later the AWS SDK.
- Check authors must not block inside async code. Enforced by review and by `clippy::disallowed_methods`
  in the check crates (`std::process::Command`, `std::thread::sleep`, `std::net::TcpStream::connect`),
  so blocking calls live only inside `blocking(..)`.
- Library crates depend on tokio with only the features they use; only `rdy-cli` enables `rt-multi-thread`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| tokio current-thread | One accidental blocking call stalls every timer, so timeouts stop firing. That is exactly the hang we must avoid. |
| No async (threads plus `ureq`) | `kube` and the AWS SDK are async-only, so we would embed a runtime anyway and run two HTTP stacks. |
| `smol` or `async-std` | `async-std` is discontinued; neither is what `kube` and `reqwest` are built on. |
| One thread per check with a watchdog | Works for host checks, fights the async client crates for the rest. |

## Tickets implied

- [M1] Scheduler with concurrency limit, per-check timeout and panic isolation | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture check that sleeps forever reports Timeout and a check that panics reports Error while the other checks still pass.
- [M1] Blocking helper and subprocess kill on timeout | owner: rust-engineer | est: 3h | depends on: Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: a check running `sleep 600` times out, the child process is gone, and `rdy` exits within 2 s of the deadline.
