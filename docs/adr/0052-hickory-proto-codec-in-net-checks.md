# ADR 0052: `hickory-proto` is a message codec inside `rdy-checks-net`, with no features

- Status: Accepted
- Date: 2026-11-18
- Relates to: ADR 0006 decision 5, ADR 0014 decision 7, ADR 0051, 02 "Lint wall", backlog M1-155

## Context

`net.dns` sends one DNS question to each nameserver and reads the reply. The wire format is easy to get wrong
and the reply comes from the network, so the parser must not trust lengths. The lint wall bans every
`hickory-*` crate from check crates, because the resolver crates open sockets and read `/etc/resolv.conf`
behind the facade's back. The M1-155 exit test asks for `hickory` with default features off.

## Decision

1. `hickory-proto` may be a normal dependency of `rdy-checks-net` and of no other check crate. `deny.toml`
   lists `rdy-checks-net` as its only wrapper. `hickory-resolver`, `hickory-client` and `hickory-net` stay
   banned everywhere.
2. It is built with no features at all (`default-features = false`, no `std`): a `[[bans.features]]` entry with
   `exact = true` and an empty `allow` fails the build on any feature a later change turns on. So there is no
   thread random number generator, no URL parsing, no DNSSEC, no mDNS and no serde.
3. The check uses `Message`, `Query` and `Name` to build and read bytes. The bytes travel through
   `Probe::nameserver_exchange` (ADR 0051). The check opens no socket and reads no file through the crate.
4. The reply is accepted only if it is a response with the query's ID and opcode and exactly the query's
   question. The query carries no OPT record.
5. `tests/lint-wall` holds the exception: `deny_wrappers.rs` names `("hickory-proto", "rdy-checks-net")`, and
   `deps_allowlist.rs` checks that only `rdy-checks-net` lists it and that the workspace entry has default
   features off.

## Residual

A later `hickory-proto` release may add a dependency that deny's licence or advisory rules reject, and the
feature pin does not stop a new default dependency. CI's `cargo deny check` is the guard.
