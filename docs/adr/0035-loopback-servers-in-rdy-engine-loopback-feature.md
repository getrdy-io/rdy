# ADR 0035: The loopback test servers live in `rdy-engine`, behind the `loopback` feature

- Status: Accepted. Moves the home that docs/plan/08-testing.md sections 1 and 8 gave them. Needs a `security-reviewer` look at the `deny.toml` wrapper change.
- Date: 2026-10-30

## Context

M1-090 builds the servers that net tests need on loopback: a TLS server with a generated CA, a CONNECT proxy
with four modes, a closed port, a listener that never accepts, a reset after the ClientHello, a 302 server
and a dual-stack case. 08 (sections 1 and 8) puts them behind a `test-support` feature of `rdy-checks-net`,
and 08 section "Review corrections" says no new crate.

That home cannot work, for two reasons.

1. **The wall.** A check crate may not depend on `tokio`, `socket2` or `tokio-rustls`. `deps_allowlist.rs`
   reads normal dependencies, optional ones included, and refuses those names in the allowlist file.
   `deny.toml` bans `socket2` and `tokio-rustls` for every `rdy-checks-*` crate. The servers need all three.
   A `test-support` feature would open the wall for the one crate whose job is the network.
2. **The consumers.** M1-091 (facade TCP and CONNECT) and M1-092 (facade TLS) test code inside `rdy-engine`.
   `rdy-engine` cannot depend on `rdy-checks-net`, not even as a dev-dependency: the dev-dependency would
   build a second copy of the engine and the types would not match. M1-095 and M1-098 test check code and
   reach the network through the Replay `net.json` `serve` entries, which name a factory.

Every consumer already depends on `rdy-engine` with the `testing` feature. A path dependency from a check
crate on any other new crate is refused by `deps_allowlist.rs` (only `rdy-engine` and `rdy-spec` may come
by path).

## Decision

1. The servers are the module `rdy_engine::testing::loopback`, behind a new feature `loopback` of
   `rdy-engine`. `loopback` implies `testing`. It also turns on `tokio` and the optional dependencies
   `rcgen` (features `crypto`, `pem`, `ring`), `tokio-rustls` (`ring`, `tls12`) and `socket2`. It does not
   turn on `runtime`, so the build without default features still compiles and lints it.
2. The feature is test-only like `testing`. The `rdy` binary never builds it. `cargo tree -p rdy -e
   normal,build,features` shows no `loopback`, `testing`, `rcgen` or `tokio-rustls`. `rdy-engine` itself turns
   it on for its own tests through its self dev-dependency. A check crate turns it on in its own
   `[dev-dependencies]` line for `rdy-engine`, which `deps_allowlist.rs` already permits.
3. `deny.toml` adds `rdy-engine` to the wrappers of `socket2` and `tokio-rustls`. No check crate becomes a
   wrapper. The ban on check crates depending on either is unchanged.
4. Every server binds `127.0.0.1` on port 0. The CONNECT proxy tunnels only to a loopback address or a route
   the test names, and answers `502` to anything else, so a test cannot reach a real network through it.
5. The Replay `serve` factory names of 08 Appendix A stay as they are. M1-091 maps a name to a started
   server when it connects the stream a Replay `dial` names (correction-18). This ADR only supplies the
   servers.
6. Certificates and keys are made in memory per test. The module writes no file.

## Alternatives considered

- **A `test-support` feature of `rdy-checks-net` (the plan as written).** Rejected: it needs the wall opened
  for `tokio`, `socket2` and `tokio-rustls` in a check crate, and `rdy-engine` tests could not use it.
- **A new unpublished crate under `tests/` that every consumer lists as a dev-dependency.** Rejected for
  M1. It works for `rdy-engine` and `rdy-cli`, but a check crate would need a path exception in
  `deps_allowlist.rs` (a change to the wall, with the `security-review` label). If a crate outside
  `rdy-engine` ever needs the servers without the engine, revisit this through a new ADR.
- **Put the servers in `rdy-checks-k8s`'s tests.** Rejected: nothing else can reach them.

## Consequences

- `rdy-engine` gains three optional dependencies. They are in no build that lacks the feature. The crate's
  published API gains nothing outside `testing`, which is already hidden and outside the semver promise.
- One more entry per wrapper in `deny.toml`, which `security-reviewer` reads once.
- 08 section 1, 08 Appendix A, the 08 plan correction for this ticket, and the fixture line in 03 net.egress, name `rdy_engine::testing::loopback`.
- Test authors get one set of servers on all five legs. The smoke tests in
  `crates/rdy-engine/src/testing/loopback/tests.rs` run in `cargo test -p rdy-engine`.

## Tickets implied

- M1-091: map each Replay `serve` name (08 Appendix A) to a started server and connect the stream.
- M1-092, M1-095, M1-098: use `TestCa`, `HttpServer`, `ConnectProxy` and `DualStack` from this module.
