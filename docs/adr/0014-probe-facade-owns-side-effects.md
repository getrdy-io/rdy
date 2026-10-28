# ADR 0014: The probe facade owns every check side effect, including TCP, proxy CONNECT, TLS and HTTP

- Status: Proposed (2026-10-28, applies the security-reviewer review of 02; security-reviewer sign-off pending). When accepted it supersedes ADR 0009 decisions 1, 2, 3 and 5 and tightens ADR 0004 decision 5.
- Date: 2026-10-28

## Context

Threat model TB2 and INV-07 require one engine-owned interface for every side effect a check performs,
with policy and an action log. ADR 0009 gives net checks reqwest, which opens its own sockets, follows
its own proxy logic and cannot be replayed from fixtures. The 02 security review found four ways around
the facade in 02 revision 1: native closures, an incomplete lint wall, a CONNECT line written by check
code, and an allow-by-default kube guard.

## Decision

1. **One facade.** `rdy_engine::probe::Probe` is the only path for file reads, env reads, commands,
   name lookups, TCP, TLS, HTTP and native OS calls. Policy and the action log sit above a `Backend`
   trait with two implementations: `Live` (release) and `Replay` (feature `testing`, never in the
   release binary). Each check gets a `Probe` scoped to its `CheckInfo` manifest, which is cancelled
   when the check ends.
2. **Network in the facade.** The facade resolves names, applies the address rule of ADR 0009
   (169.254.0.0/16, fe80::/10, fd00:ec2::254 and IPv4-mapped forms, literal or resolved), checks the
   host against the calling check's own host set (at most 64 distinct hosts per spec), connects, and on
   the proxied path writes the CONNECT itself (8 KiB response head cap, own timeout, Basic auth from the
   `ProxyUrl` newtype, `Proxy-Authorization` never logged). TLS SNI is always the permitted host.
3. **TLS verifier.** Net checks verify against the system root store loaded by the facade
   (`rustls-native-certs` semantics: PEM bundles on Linux read through the facade, OS roots on macOS and
   Windows through a native call) with webpki, or against `webpki-roots` when the spec says
   `trust: bundled`. No `rustls-platform-verifier` in M1: on macOS and Windows it can fetch revocation
   and AIA URLs outside the peer set. The report says "no revocation check". The recording verifier for
   `net.tls_intercept` is private to the facade and returns a chain, never a stream.
4. **HTTP.** The facade sends HTTP/1.1 HEAD or GET with hyper's client connection API. It returns
   status, a fixed header list and timings, reads at most 64 KiB of body and discards it (INV-13), and
   never follows a redirect (the `Location` host is returned). The M2 upload client uses the same code.
   reqwest is banned in `deny.toml`.
5. **Native calls are a closed enum** (`NativeCall`), each variant reviewed, never a closure. M1:
   `Statvfs`, `Uname`, `Rlimit`, `Hostname`, `SystemRoots`, `MachineId`.
6. **Commands.** Fixed search path always, not only as root. Windows runs only `whoami.exe` in M1, until
   job objects land.
7. **Lint wall.** `clippy.toml` disallowed methods and types for every file, process, socket, thread and
   env API, plus `Box::leak` and `String::leak`; a `tests/lint-wall` crate proves each entry fires;
   `allow(clippy::disallowed_` is legal only in allowlisted facade files; `deny.toml` wrappers keep
   `rustix`, `socket2`, `hyper`, `tokio-rustls` and `kube` out of check crates.
8. **Named exceptions**, each logged: the kube client's own sockets and its exec credential plugins
   (ADR 0010). UDP, unix sockets and nonblocking record reads arrive in M2 as facade methods.

## Consequences

- One place enforces peers, the address rule, caps and the log, and Replay drives all of it.
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

## Tickets implied

- [M1] SEC-17 Mediated Context handles with action log and read denylist | owner: rust-engineer | est: 4h | depends on: Check trait, Need and Context in rdy-engine | exit test: the fixture run's action log lists every command, file, endpoint and kube request; a read of /proc/1/environ is refused; a Probe call after its check ends is denied and logged; truncation drops only ok read, read_dir and stat entries.
- [M1] Facade TCP attempts, proxy CONNECT and per-check host sets | owner: rust-engineer | est: 4h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: a host listed only by another check is Denied, a CONNECT to a literal 169.254.169.254 is refused before any byte is sent, proxy 403 and 407 return typed errors, and Proxy-Authorization never appears in the log.
