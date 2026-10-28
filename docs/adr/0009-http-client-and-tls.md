# ADR 0009: HTTP with reqwest on rustls and ring, a strict egress policy, dual roots only for the interception probe

- Status: Accepted (revised 2026-10-28 after security-reviewer review); decisions 1, 2, 3 and 5 superseded by ADR 0014 once it is accepted
- Date: 2026-10-27

## Context

Network checks are where most real POCs fail (plan, M1 build order step 4): egress through the customer's
proxy and TLS interception by a corporate middlebox. Rule 5 says rustls everywhere, no OpenSSL. rustls
needs a crypto provider, `ring` or `aws-lc-rs`; `aws-lc-rs` needs CMake and a C toolchain per target and
is painful for musl. reqwest 0.13 made rustls the default, uses `aws-lc-rs` unless told otherwise, dropped
the old root-certificate features and verifies with `rustls-platform-verifier` by default. `kube` also
brings hyper and rustls. `rdy` often runs as root on hosts that can reach cloud metadata endpoints, so a
spec endpoint must not be a path to them.

## Decision

1. **Client.** `reqwest` without default features, rustls with no bundled provider, plus `http2`. `rdy`
   installs `ring` as the process-wide rustls provider at startup. CI asserts `cargo tree -i aws-lc-sys`
   is empty with the chosen features.
2. **Verifier.** `net.egress` and the M2 upload client use the platform verifier (reqwest's default),
   because that is what the customer's software will see. Only `net.tls_intercept` uses its own roots.
3. **One builder, one policy** in `rdy-checks-net`: `net::client(&ProxyConfig, timeout)`. It enforces:
   - `redirect::Policy::none()`. A redirect is recorded as evidence (status and `Location`), not followed.
   - A custom `dns_resolver` that drops addresses in 169.254.0.0/16, fe80::/10 and `fd00:ec2::254`, and
     the same check on literal IPs. A blocked address is a `Block` with an explanation, not a silent skip.
   - Only endpoints listed in the verified spec are reachable, at most 64 per run.
   - At most 4 KiB of any body is read, then discarded. Bodies never enter evidence.
4. **Proxy.** From `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (both cases) or the spec's `via_proxy`.
   Held as a `ProxyUrl` newtype whose `Debug` and `Display` mask userinfo. PAC and WPAD are not supported
   in v1; the hint says so.
5. **Interception probe.** `net.tls_intercept` uses `tokio-rustls` over TCP, through an HTTP CONNECT we
   write ourselves (response header cap 8 KiB, its own timeout). A recording verifier accepts the chain
   so it can classify it against Mozilla roots (`webpki-roots`) and the OS store
   (`rustls-native-certs`): valid only against the OS store means interception, and the report names
   the issuer (`x509-parser`). That connection sends no HTTP request and no credentials. The recording
   verifier is private to the probe module and unreachable from `net::client()` or the upload client.
6. **DNS checks** use `hickory-resolver` (ADR 0006), with the same address policy on results they connect to.
7. `cargo deny` bans `openssl-sys`, `native-tls` and `aws-lc-sys` in M1.

## Consequences

- One HTTP stack (hyper) shared by reqwest and kube; one place for timeouts and policy.
- A spec cannot point `rdy` at a metadata service, directly, through DNS, or by redirect.
- M3 risk: the AWS SDK defaults to `aws-lc-rs`. A spike in M2 checks whether it runs on rustls with
  `ring`; if not, a new ADR lifts the ban, not a quiet change.
- FIPS customers (M5) may need `aws-lc-rs` in FIPS mode as a separate build.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| reqwest default TLS (`aws-lc-rs`) | Extra C and CMake toolchain per target for no gain in M1. |
| Our own dual-root verifier for egress | Shows what Mozilla trusts, not what the customer's software trusts. Kept only for the probe. |
| Follow redirects | Bypasses the endpoint list and the metadata block. |
| `ureq` 3 | We would carry hyper anyway for kube: two HTTP stacks. |
| native-tls or OpenSSL | Ruled out by rule 5. |

## Tickets implied

- [M1] Shared HTTP client builder with rustls ring and platform verifier | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: integration test with a local CONNECT proxy shows egress through the proxy, NO_PROXY honoured, `cargo tree -i aws-lc-sys` empty, and a proxy password never appears in Debug output.
- [M1] SEC-21 Egress address policy, no redirects, no bodies | owner: check-author | est: 3h | depends on: Shared HTTP client builder with rustls ring and platform verifier | exit test: a redirect to 169.254.169.254, a hostname resolving to link-local and an unlisted endpoint are all refused, and a body canary never reaches the report.
- [M2] Verify the AWS SDK runs on rustls with ring | owner: cloud-iam-expert | est: 3h | depends on: none | exit test: a spike branch builds aws-sdk-iam for both musl targets with no aws-lc-sys in cargo tree, or an ADR records why not.
