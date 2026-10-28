# ADR 0006: Linux binaries are static musl for x86_64 and aarch64, built on native runners

- Status: Accepted (revised 2026-10-28 after security-reviewer review; decision 5 amended 2026-10-28 in M1-009: `getent ahosts` first, hickory as fallback)
- Date: 2026-10-27

## Context

CLAUDE.md rule 5: one static binary, no runtime, musl on Linux, rustls everywhere. Customers run `rdy` on
RHEL 7 and 8 boxes in air-gapped sites, Ubuntu cloud VMs, Alpine containers, Graviton and Grace nodes. A
glibc-linked binary fails on older glibc with a confusing loader error. musl has trade-offs that touch
our checks directly, so they belong in writing.

## Decision

1. Release targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (both fully static),
   `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` with `+crt-static`. No glibc
   Linux build is published.
2. Hardening is kept: Linux binaries are `static-pie` (ASLR), with full RELRO and a non-executable stack.
   The CI proof accepts `static-pie linked`, fails on a non-PIE binary, and checks RELRO and the stack
   flag with `readelf` on both arches (`scripts/check-static.sh`). A target that cannot be static-pie is
   recorded here. (Amended 2026-10-28 in M1-006: rustc 1.99.1 does not mark `aarch64-unknown-linux-musl`
   as able to build static-pie, so it links `-static -no-pie` with `crt1.o`, giving no ASLR and no
   RELRO flags. That target links through `scripts/musl-pie-linker.sh`, set in `.cargo/config.toml`. It
   swaps `crt1.o` for musl's `rcrt1.o` and passes `-static-pie` to `cc`. The CI check stays strict, so
   it fails if the wrapper stops working. Delete the wrapper when rustc supports the target itself.)
3. aarch64 Linux builds and tests run natively on GitHub's `ubuntu-24.04-arm` runners with `musl-tools`.
   `cargo-zigbuild` is the fallback and the documented local cross path. `cross` is not used.
4. Allocator: musl's default in M1. An M2 benchmark compares with a glibc build; above a 20% slowdown we
   switch to `mimalloc` in `rdy` only, after a dependency review, since it is new C code in a root binary.
5. DNS: `rdy` must report what the customer's software will see, which usually resolves through glibc.
   musl differs: no NSS (`/etc/nsswitch.conf` ignored, so no LDAP, sssd, mDNS or nss-resolve hosts), all
   nameservers queried in parallel, no `options rotate`, TCP fallback for truncated answers only from
   musl 1.2.4. So on Linux `net.dns` takes the system answer from `/usr/bin/getent ahosts <name>`
   through the facade's command runner when that binary exists: it is glibc's own path, with
   `nsswitch.conf`, mDNS and sssd. The name must match `^[A-Za-z0-9._-]+$`, must not start with `-`,
   and follows `--`. `hickory-resolver`, reading `/etc/resolv.conf` and `/etc/hosts`, queries each
   nameserver directly and is the fallback when `getent` is missing (scratch containers, Alpine). The
   evidence says which path answered. On the fallback it warns when `nsswitch.conf` lists sources beyond
   `files` and `dns`. (Amended 2026-10-28 in M1-009, from 03 `net.dns` and its rust-engineer review.)
6. No `dlopen` in a static musl binary: `nvml-wrapper` (plan, GPU row) cannot work. GPU checks on Linux
   use `nvidia-smi` and `/proc/driver/nvidia`.
7. User and group lookups skip NSS too. Host checks that need a user read `/etc/passwd` and say "local
   users only" in their evidence.

## Consequences

- One Linux binary per arch that runs from RHEL 7 (kernel 3.10) to current, and in scratch containers.
- `ring` and any crate with C or assembly need a musl C compiler in CI.
- Checks that compare with "what glibc would do" carry a caveat in their remediation text.
- No glibc escape hatch on Linux in v1. Revisit if a design partner hits it.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| glibc dynamic with an old baseline (glibc 2.17) | Not static, breaks on Alpine and distroless, contradicts rule 5. |
| Static glibc | Unsupported; NSS and `getaddrinfo` still try to `dlopen`. |
| Ship both musl and glibc | Doubles the matrix and support load for a part-time founder. |
| `cross` (Docker plus QEMU) | Docker in CI and slow emulated tests; native arm runners are better. |
| Non-PIE static binaries | Lose ASLR on a binary that often runs as root. |
| jemalloc by default | C dependency and build time for a gain we have not measured. |
| `net.dns` on `hickory-resolver` only (decision 5 before M1-009) | Misses NSS sources (sssd, LDAP, mDNS) that the customer's glibc-linked software uses. |

## Tickets implied

The static and hardening proof is part of 06-release-and-distribution.md's ticket "CI test matrix on five
native runners with ci-ok gate and static-musl proof (ADR 0006)"; its exit test must follow decision 2.

- [M1] musl resolver behaviour fixture for net.dns | owner: qa-engineer | est: 2h | depends on: Shared HTTP client builder with rustls ring and platform verifier | exit test: a fixture resolv.conf and nsswitch.conf with `sss` produce the documented warning.
- [M2] Allocator benchmark musl vs glibc in CI | owner: release-engineer | est: 2h | depends on: none | exit test: CI prints both timings for the fixture spec and fails above the 20% threshold.
