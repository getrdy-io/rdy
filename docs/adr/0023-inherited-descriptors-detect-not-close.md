# ADR 0023: Descriptors inherited by `rdy` are listed and reported in M1, not closed

- Status: Accepted, security-reviewed (PR #53)
- Date: 2026-10-28

## Context

INV-08 and SEC-18 want every child command to start with a clean environment. Environment, search path,
working directory and umask are now set by the command policy (`rdy_engine::exec::policy`). Open file
descriptors are the gap. The standard library opens its own descriptors with close-on-exec, but a
descriptor above 2 that `rdy` inherited from its parent (a shell that left a log file, a socket or a
pipe open) passes to every child. M1-038 left this open and the PR #44 reviews asked for a fix.

Closing or marking a descriptor needs its raw number, and every API that takes a raw number is `unsafe`
(`OwnedFd::from_raw_fd`, `BorrowedFd::borrow_raw`) or unavailable. Facts checked on 2026-10-28:

- `std::process::Command` has no "close other descriptors" option. `pre_exec` is `unsafe`.
- Safe `rustix` has `fcntl_setfd`, `dup3` and `close_range` only over an owned or borrowed descriptor, and
  `close_range` is not implemented. `pidfd_getfd` returns a duplicate, which does not change the original.
- `nix::unistd::close` accepts a plain integer through `IntoRawFd`, so it compiles without `unsafe`. It
  would let a library close any descriptor, including the ones tokio and std own. That breaks I/O
  safety in spirit even though the compiler allows it, adds a dependency to a crate that avoids new ones,
  and is only correct if called first thing in `main`, which a library cannot enforce.
- INV-18 allows one named FFI module with a `deny` override and `// SAFETY:` comments. The workspace has
  none, and this ticket keeps `#![forbid(unsafe_code)]`.

## Decision

1. M1 does not close or mark inherited descriptors.
2. `rdy_engine::exec::inherited_fds()` lists the descriptors above 2 that are open, by reading
   `/proc/self/fd` (Linux) or `/dev/fd` (other Unix). It reads numbers only, never targets, so it leaks
   nothing. Windows returns an empty list.
3. The CLI start-up calls it before it opens anything of its own and, if the list is not empty, logs one
   warning with the count and numbers. The warning says that the descriptors reach child commands and how
   to start `rdy` without them (`rdy ... 3>&-` in a shell). That is M1-168, and it lands before the
   first public release. The CLI also calls `harden_umask()` there, first in `main`.
4. The residual is acceptable in M1 because the programs are a fixed set of system tools run with fixed
   argv, none of which reads a descriptor it was not told about, and the environment carries no hint of
   one. Shells, `sudo` and the programs that run other programs (`env`, `xargs`, `timeout` and
   similar) are refused, so nothing can walk the descriptor table on a spec's behalf. The security
   review accepted this for M1 on those grounds: children run with `rdy`'s own credentials, with
   fixed tools and fixed argv, and `sudo` closes descriptors above 2 itself.
5. Because the umask cannot be set for the child alone without `pre_exec`, the process-wide umask is set
   to `0o077` before each start (and the CLI may call `harden_umask()` earlier). This only makes files
   that `rdy` creates tighter, and the report writer sets modes explicitly (ADR 0016).
6. The M2 fix is M2-104: one small FFI module, allowed by INV-18, that calls `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`
   on Linux and sets `FD_CLOEXEC` on the listed descriptors elsewhere, run first thing in `main`. A test
   in `rdy-engine` already shows the leak (`only_descriptors_without_close_on_exec_reach_a_child`) and
   turns into the regression test for the fix.
7. This narrows the M1-039 exit test, which said a descriptor above 2 that `rdy` inherited does not reach
   the child. The backlog correction (correction-08) amends that exit test to "is listed by
   `inherited_fds()`", adds M1-168 and M2-104, and adds the rule that `exec::run` and `ExecSpec::new`
   are not available to check crates (they are public only under `cfg(any(test, feature = "testing"))`)
   to the M1-040 and M1-044 rows.

## Consequences

- A child can still see a descriptor that the operator's shell left open. The warning makes that visible.
- The detection is only exact when called before `rdy` opens its own files. Later in a run it can list
  descriptors that std opened with close-on-exec, which do not leak.
- No new dependency and no `unsafe`.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Close with `nix::unistd::close` at start-up | A raw close in a library, a new dependency, and correct only from `main`. |
| Refuse to start when any descriptor above 2 is open | Shells, IDEs, CI runners and test harnesses leak descriptors, so `rdy` would fail for reasons the customer cannot see. |
| An `unsafe` FFI module now | The ticket keeps `forbid(unsafe_code)`. INV-18 allows it later, with a SAFETY comment and an allowlist entry. |
| Re-exec through a helper that closes descriptors | Needs a second program to trust, and the only candidates are shells. |

## Tickets implied

- [M1] M1-168: CLI start-up warns on inherited descriptors, before the first public release | owner: rust-engineer | est: 0.5h | depends on: M1-039, the CLI `run` command | exit test: `rdy run` started with `3</dev/null` logs one warning that names descriptor 3 and no path.
- [M2] M2-104: FFI module that marks inherited descriptors close-on-exec | owner: rust-engineer | est: 2h | depends on: M1-039 | exit test: a child started after start-up with `3</dev/null` does not have descriptor 3.
