# ADR 0052: The `net.dns` codec is written by hand, and `hickory-proto` is only a test oracle

- Status: Accepted
- Date: 2026-11-18
- Relates to: ADR 0006 decision 5, ADR 0014 decision 7, ADR 0051, 02 "Lint wall", backlog M1-155

## Context

`net.dns` sends one DNS question to each nameserver and reads the reply. The reply is bytes from the network.
The M1-155 exit test first asked for `hickory` with default features off. The security review (SEC-155-5)
found that `hickory-proto` is not a small codec even then: `Message::from_vec` decodes every record type,
including ones that parse URLs from network bytes (CAA `iodef`), and the crate pulls in `idna`, `url`, the
`icu_*` and `zerovec` family (about 27 crates, with proc macros and unsafe code) for a reader that needs
three record types.

## Decision

1. The query and the reply reader are written by hand in `rdy-checks-net` (`dns/wire.rs`).
2. The reader checks every read against the buffer. It accepts a response with the expected ID, opcode 0
   and exactly one question that is ours. It reads at most 128 answer records and keeps A, AAAA and CNAME
   and skips the rest by RDLENGTH. It never reads the authority or additional sections. A compression
   pointer must point strictly backwards, at most 16 pointers are followed in a name, and a label type other
   than plain or pointer is refused.
3. An address counts only if its record is class IN and its owner is on the CNAME chain from the question
   name (8 links at most). A record for another name never becomes an address.
4. The message ID is the facade's: `Probe::nameserver_exchange` overwrites it with a random ID and returns it
   as `UdpReply::query_id`. The query is built with ID 0 and carries no OPT record.
5. `hickory-proto` (no features) is a dev-dependency of `rdy-checks-net` and the test oracle: tests encode
   replies and decode our queries with it, and the hand-written code must agree (a property test compares
   them). `cargo tree -e normal -p rdy` has no `hickory-proto`, `idna`, `url` or `icu_*`.
6. `deny.toml` still lists `rdy-checks-net` as the one wrapper of `hickory-proto`, because deny cannot tell a
   dev-dependency from a normal one (the same arrangement as `tempfile` for `rdy-checks-k8s`).
   `tests/lint-wall/tests/deps_allowlist.rs` fails if it is anything but a dev-dependency of
   `rdy-checks-net`, or if the workspace entry turns on a feature. `ci/check-crate-deps.toml` does not list it.

## Residual

The reader is about 150 lines of new parsing code on hostile input. It has unit tests for each rule, a
property test for arbitrary bytes, one for a valid start followed by random bytes, and the oracle comparison.
