# ADR 0009: HTTP with reqwest on rustls, ring as the only crypto provider, two root stores

- Status: Accepted
- Date: 2026-10-27

## Context

Network checks are where most real POCs fail (plan, M1 build order step 4): egress through the customer's
proxy, and TLS interception by a corporate middlebox. Rule 5 says rustls everywhere, no OpenSSL. rustls
needs a crypto provider: `ring` or `aws-lc-rs`. reqwest 0.13 made rustls the default and picked
`aws-lc-rs`, which needs CMake and a C toolchain per target and has been painful for musl and cross builds.
`kube` also brings hyper and rustls. To detect interception we must see the certificate chain the
proxy presents, which a high-level HTTP client hides.

## Decision

1. **HTTP egress** (`net.egress`, later the upload client) uses `reqwest` without default features,
   rustls with no bundled provider (`rustls-no-provider` in 0.13), plus `http2`. `rdy-cli` installs
   `ring` as the process-wide rustls provider at startup, before any client is built.
2. **One shared client builder** in `rdy-checks-net` (`net::client(&ProxyConfig, Roots) -> Client`) so
   every network check uses the same proxy and timeout rules. Proxy from `HTTPS_PROXY`, `HTTP_PROXY`,
   `NO_PROXY` (both cases) or the spec's explicit `via_proxy`. PAC and WPAD are not supported in v1; the
   check says so in its hint.
3. **TLS interception** (`net.tls_intercept`) uses `tokio-rustls` directly over a TCP stream (through an
   HTTP CONNECT we write ourselves when a proxy is set) with a verifier that records the presented chain.
   It validates the chain twice: against Mozilla roots (`webpki-roots`) and against the OS store
   (`rustls-native-certs`). Valid only against the OS store means interception; the report names the
   issuer, parsed with `x509-parser`.
4. **DNS** uses `hickory-resolver` (ADR 0006).
5. `cargo deny` bans `openssl-sys`, `native-tls` and `aws-lc-sys` in M1 (ticket: Add deny.toml with crate
   bans and license allowlist), so CI fails if any of them appears in the dependency graph.

## Consequences

- One HTTP stack (hyper) shared by reqwest and kube. Smaller binary, one place for timeouts.
- `ring` builds cleanly on all five targets with a C compiler for its assembly.
- M3 risk: the AWS SDK defaults to `aws-lc-rs`. Before M3, verify the SDK can run on a hyper client
  using rustls with `ring`. If not, the ban on `aws-lc-sys` is lifted by a new ADR, not quietly.
- FIPS customers (Enterprise, M5) may require `aws-lc-rs` in FIPS mode. That is a separate build, later.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| reqwest with default rustls (`aws-lc-rs`) | Extra C and CMake toolchain per target for no benefit to us in M1. |
| `ureq` 3 (sync, ring by default) | Simple, but we would carry hyper anyway for kube, so two HTTP stacks. |
| `hyper-util` client directly | Proxy handling and redirects by hand. reqwest is the boring wrapper. |
| `rustls-platform-verifier` | Uses the OS verifier, which is right for "does this connect" but hides which root validated the chain, so interception detection needs our own two-store check. |
| native-tls or OpenSSL | Ruled out by rule 5. |

## Tickets implied

- [M1] Shared HTTP client builder with rustls ring, dual roots and proxy env | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: integration test with a local CONNECT proxy and a test CA shows egress passes through the proxy and NO_PROXY is honoured.
- [M2] Verify the AWS SDK runs on rustls with ring | owner: cloud-iam-expert | est: 3h | depends on: none | exit test: a spike branch builds aws-sdk-iam for both musl targets with no aws-lc-sys in cargo tree, or an ADR records why not.
