# ADR 0014: The probe facade owns every check side effect, including TCP, proxy CONNECT, TLS and HTTP

- Status: Accepted (2026-10-28, after the security-reviewer review of ADRs 0013 to 0016). Supersedes ADR 0009 decisions 1, 2, 3 and 5; tightens ADR 0004 decision 5. Decision 2 amended 2026-10-30 in M1-094. Decision 7 amended 2026-10-28 in M1-001 (PR #6, security MF-04): the lint wall lists std and kube items only, and the direct dependency allowlist keeps every other crate's I/O out of check crates.
- Date: 2026-10-28

## Context

Threat model TB2 and INV-07 require one engine-owned interface for every side effect a check performs,
with policy and an action log. ADR 0009 gives net checks reqwest, which opens its own sockets, follows
its own proxy logic and cannot be replayed from fixtures. Two security reviews of 02 found ways around
the facade: native closures, check-written CONNECT, an allow-by-default kube guard, a lint wall made of
wildcards clippy cannot match, and nothing stopping a check crate from adding a crate that does I/O.

## Decision

1. **One facade.** `rdy_engine::probe::Probe` is the only path for file reads, env reads, commands,
   name lookups, TCP, TLS, HTTP and native OS calls. Policy and the action log sit above a `Backend`
   trait, sealed with a private supertrait, with two implementations: `Live` (release, reachable only
   through `rdy_engine::live_backend()`, which check crates may not call) and `Replay` (feature
   `testing`, never in the release binary). `Probe` constructors are `pub(crate)`. Each check gets a
   `Probe` scoped to its `CheckInfo` manifest and host set, cancelled when the check ends.
2. **Network in the facade.** The facade resolves names and refuses, literal or resolved, every address
   for which one `is_forbidden(IpAddr)` holds: 169.254.0.0/16, 100.100.100.200/32, fe80::/10,
   fd00:ec2::/64, and the IPv4-mapped, IPv4-compatible and `64:ff9b::/96` forms of each IPv4 range. A
   table test backs it. The host must be in the calling check's own host set (at most 64 distinct hosts
   per spec). On the proxied path the facade writes the CONNECT itself (8 KiB response head cap, own
   timeout, Basic auth from the `ProxyUrl` newtype, `Proxy-Authorization` never logged). TLS SNI is
   always the permitted host.
   (Amendment, M1-094: the table also holds `fd20:ce::254/128`, the GCP IPv6 metadata address, and
   `168.63.129.16/32`, the Azure host-services address. The Azure address serves the VM agent's settings
   and certificates, so no spec host may be it. It is also the Azure VM's `resolv.conf` nameserver, so
   the `SystemResolver` peer class may reach it on port 53, UDP and TCP, and only when the address came
   from the OS nameserver list; ports 80 and 32526 stay refused. That class is not built yet (M1-155).
   Name lookups through the OS resolver are unaffected, because the OS makes that connection. The
   decision and its residual are in 05.)
3. **TLS verifier.** Net checks verify against the system root store loaded by the facade (PEM bundles
   on Linux read through the facade; OS roots on macOS and Windows through a native call) with webpki,
   or against `webpki-roots` when the spec says `trust: bundled`. No `rustls-platform-verifier` in M1:
   on macOS and Windows it can fetch revocation and AIA URLs outside the peer set. The report says "no
   revocation check". The recording verifier for `net.tls_intercept` is private to the facade and
   returns a chain, never a stream.
4. **HTTP.** The facade sends HTTP/1.1 HEAD or GET with hyper's client connection API. It returns
   status, a fixed header list and timings, reads at most 64 KiB of body and discards it (INV-13), and
   never follows a redirect (the `Location` host is returned). The M2 upload client cannot use this
   probe, which discards bodies. It uses the M3 `http_exchange` primitive with a run-level host instead.
   reqwest is banned in `deny.toml`.
5. **Native calls are a closed enum** (`NativeCall`), never a closure. M1 variants are `Statvfs`,
   `Uname`, `Rlimit`, `Hostname`, `MachineId` (Windows `MachineGuid`; Linux reads `/etc/machine-id` as
   a file; macOS has none in M1, so its `host_id` is null) and `SystemRoots`. Each variant has its own
   policy row, applied through an exhaustive `match`. A snapshot test of the variant list fails CI
   until the snapshot and a threat model table row change in the same PR. The raw machine id never
   enters the action log or the report; only 01's salted `host_id` does.
6. **Commands.** Fixed search path always, not only as root. Windows runs only `whoami.exe` in M1, from
   a constant path, until job objects land.
7. **Wall around the facade.**
   - `clippy.toml` lists exact items in `disallowed-methods` and `disallowed-types`, with no wildcards
     (02 Appendix A). They cover every std file, directory, link, permission, process, socket (TCP,
     UDP, unix stream and datagram), thread spawn and env API, every kube client and config
     constructor outside the `rdy-checks-k8s` client module, plus `Box::leak`, `String::leak` and
     `rdy_engine::live_backend`.
   - Other crates' I/O APIs are not listed. The direct dependency allowlist below keeps those crates
     out of check crates. The guarantee is the wall and the allowlist together: a check crate can
     reach the OS or a cluster only through the facade or the guarded kube client. (Amendment, MF-04:
     the first version promised a wall over every crate's I/O; clippy cannot match wildcards, so the
     promise is narrowed to std and kube, with the allowlist covering the rest.)
   - A `tests/lint-wall` crate uses each item, and CI expects each one to fail.
   - `allow(clippy::disallowed_` is legal only in allowlisted facade files and the k8s client module.
   - **Direct dependency allowlist.** `ci/check-crate-deps.toml` names the allowed direct
     dependencies of each check crate: `rdy-engine`, `rdy-spec`, `serde`, `serde_json`, `thiserror`
     and `futures-util`, plus `kube` and `k8s-openapi` for `rdy-checks-k8s` only, and `x509-parser` for
     `rdy-checks-net` only. No other `rdy-checks-*` crate may depend on `kube`, and inside
     `rdy-checks-k8s` only the client module may name a kube client or config type. A CI script
     compares `cargo metadata` against the file and fails on any difference. A change to the file needs the `security-review` label (CODEOWNERS).
   - `deny.toml` `[bans]` wrappers keep `rustix`, `socket2`, `hyper`, `tokio-rustls`, `hickory-*`,
     `sysinfo`, `walkdir`, `tempfile`, `which`, `nix`, `ureq` and `reqwest` from being direct or
     wrapped dependencies of check crates.
8. **Named exceptions**, each logged: the kube client's own sockets, its proxy CONNECT and TLS (the
   probe-time `connect` entry records `via_proxy`; the password comes from the same `ProxyUrl` and is
   never logged), and its exec credential plugins (ADR 0010). UDP, unix sockets and nonblocking record
   reads arrive in M2 as facade methods. (Amendment, M1-144: UDP and unix sockets moved to M1 as the
   facade methods `Probe::udp_exchange` and `Probe::unix_get`, because `host.time_sync` needs an SNTP
   query and `host.container_runtime` needs the Docker and Podman Engine API. The UDP peers are the
   check's own spec hosts and nothing else (INV-11). The unix socket call sends only `GET` of `/_ping`,
   `/version` and `/info` to a declared socket (INV-28). Nonblocking record reads stay in M2. The
   timing of this decision changed; its wall did not: both calls go through the facade, the policy and
   the action log.)

**Amendment (M1-093).** Decisions 3 and 4 as built. (a) The HTTP probe verifies with a strict client
configuration: a `WebPkiServerVerifier` on the system roots (`NativeCall::SystemRoots`) or, only for
`trust: bundled`, on `webpki-roots`. It has no custom verifier and never the recording one; ALPN is
`http/1.1` only. A chain the roots refuse fails the handshake before a request byte
(`NetFailure::TlsUntrusted`). (b) hyper is a direct dependency of `rdy-engine` (`client`, `http1`; `deny.toml`
lists `rdy-engine` as a wrapper), reached through a safe `Io` adapter, with no `hyper-util`. (c) A plain
`http://` target through the proxy is refused until M1-097 writes the absolute form. (d) A `testing`-gated
hub clock (`ProbeHub::pin_clock`) feeds the `time_provider` of both the recording and the strict
configuration. (e) `Probe::trust_store` gives a check the OS store's sources and the SHA-256 of each root.
It is a probe call like any other: it writes one `native` entry (`api: system_roots`) with the check's id,
and a call after the check ended is denied and logged. (f) A connection that ends after the reply head
does not lose the status: the head is data, and the body is cut (`body_cut`).

## Consequences

- One place enforces peers, the address rule, caps and the log, and Replay drives all of it.
- A check author who needs a new kind of I/O must change rdy-engine and a reviewed list, never just a
  check crate's `Cargo.toml`.
- We own CONNECT, absolute-form requests and `NO_PROXY` matching: security-relevant parsing with tests.
- HTTP/2 is not measured in M1; ALPN is recorded. Proxy auth stays Basic only; PAC is reported, not
  fetched.
- Linux trust matches PEM bundles and `SSL_CERT_FILE`; NSS-only or Java keystore CAs stay invisible.
- `rdy-engine`'s `runtime` feature carries hyper, tokio-rustls and rustls. `rdy-cloud` uses `html` only.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| reqwest with a resolver hook (ADR 0009) | Its sockets, proxy and redirect logic are a second policy surface we do not control and cannot replay. |
| Net crate writes CONNECT and HTTP over facade streams (02 revision 1) | Check code then chooses the real target and handles the proxy password. |
| `rustls-platform-verifier` | OS network fetches outside the peer set. |
| Native closures with an api name | Any code runs with no policy and no record. |
| Denylist of known crates only | A crate nobody listed gets the same power; an allowlist fails closed. |

## Tickets implied

- [M1] SEC-17 Mediated Context handles with action log and read denylist | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: the fixture run's action log lists every command, file, endpoint and kube request; a read of /proc/1/environ is refused; a Probe call after its check ends is denied and logged; truncation drops only ok read, read_dir and stat entries.
- [M1] Facade TCP attempts, proxy CONNECT and per-check host sets | owner: rust-engineer | est: 4h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: a host listed only by another check is denied, a CONNECT to a literal 169.254.169.254 is refused before any byte is sent, proxy 403 and 407 return typed errors, and Proxy-Authorization never appears in the log.
- [M1] Direct dependency allowlist for check crates | owner: rust-engineer | est: 1h | depends on: Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers | exit test: adding `walkdir` to rdy-checks-host fails CI, and the lint-wall crate has one exact entry per item with no wildcard.
