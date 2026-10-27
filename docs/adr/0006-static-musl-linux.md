# ADR 0006: Linux binaries are static musl for x86_64 and aarch64, built on native runners

- Status: Accepted
- Date: 2026-10-27

## Context

CLAUDE.md rule 5: one static binary, no runtime, musl on Linux, rustls everywhere. Customers run `rdy` on
whatever they have: RHEL 7 and 8 boxes in air-gapped sites, Ubuntu 24.04 cloud VMs, Alpine containers,
Graviton and Grace nodes. A glibc-linked binary fails on older glibc with a confusing loader error.
musl has real trade-offs that touch our checks directly, so they belong in writing.

## Decision

1. Release targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (both fully static),
   `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` with `+crt-static`.
   No glibc Linux build is published.
2. aarch64 Linux builds and tests run natively on GitHub's `ubuntu-24.04-arm` runners (free for public
   repos) with `musl-tools`. `cargo-zigbuild` is the fallback and the documented path for local
   cross builds. `cross` is not used.
3. Allocator: musl's default in M1. A release-build benchmark of `rdy run` on the fixture spec runs in CI;
   if it is more than 20% slower than a glibc build of the same commit, switch to `mimalloc` in `rdy-cli`
   only. A CLI that runs 30 checks for a few seconds is unlikely to notice.
4. DNS: `rdy` must report what the customer's software will see, which usually resolves through glibc.
   musl differs: no NSS (`/etc/nsswitch.conf` ignored, so no LDAP, sssd, mDNS or nss-resolve hosts), all
   nameservers queried in parallel, no `options rotate`, and TCP fallback for truncated answers only from
   musl 1.2.4. So `net.dns` resolves with `hickory-resolver` configured from `/etc/resolv.conf` and
   `/etc/hosts`, states that in its evidence, and warns when `nsswitch.conf` lists sources beyond
   `files` and `dns` that `rdy` cannot consult.
5. No `dlopen` in a static musl binary. Anything that loads a shared library at runtime is out:
   `nvml-wrapper` (plan, GPU row) cannot work. GPU checks on Linux use `nvidia-smi` and `/proc/driver/nvidia`.
6. User and group lookups (`getpwnam`) also skip NSS. Host checks that need a user read `/etc/passwd` and
   say "local users only" in their evidence.

## Consequences

- One Linux binary per arch that runs from RHEL 7 (kernel 3.10) to current, and inside scratch containers.
- `ring` and any crate with C or assembly need a musl C compiler in CI (`musl-gcc` or zig).
- Checks that compare with "what glibc would do" carry a caveat in their remediation text.
- Users who need NSS-aware resolution can run the macOS or Windows build elsewhere; there is no glibc
  escape hatch on Linux in v1. Revisit if a design partner hits it.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| glibc dynamic with an old baseline (manylinux-style, glibc 2.17) | Not static, breaks on Alpine and distroless, contradicts rule 5. Would give NSS. |
| Static glibc | Officially unsupported; NSS and `getaddrinfo` still try to `dlopen` at runtime. |
| Ship both musl and glibc | Doubles the matrix and support questions for a part-time founder. |
| `cross` (Docker plus QEMU) | Needs Docker in CI, slow emulated tests, worse than native arm runners. |
| jemalloc by default | C dependency and build time for a gain we have not measured. |

## Tickets implied

- [M1] Prove static musl binaries on x86_64 and aarch64 | owner: release-engineer | est: 2h | depends on: Create workspace skeleton | exit test: CI runs `file rdy` and `ldd rdy` on both arches and fails unless the binary is statically linked, then runs it in a `scratch` container.
- [M1] musl resolver behaviour fixture for net.dns | owner: qa-engineer | est: 2h | depends on: Shared HTTP client builder with rustls ring, dual roots and proxy env | exit test: a fixture resolv.conf and nsswitch.conf with `sss` produce the documented warning.
- [M2] Allocator benchmark musl vs glibc in CI | owner: release-engineer | est: 2h | depends on: Prove static musl binaries on x86_64 and aarch64 | exit test: CI prints both timings for the fixture spec and fails above the 20% threshold.
