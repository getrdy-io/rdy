# Wycheproof Ed25519 vectors

`ed25519_test.json` is `testvectors_v1/ed25519_test.json` from the C2SP/wycheproof project
(https://github.com/C2SP/wycheproof), unchanged, fetched on 2026-10-28. The project is licensed
Apache-2.0, the same as this repo.

`crates/rdy-spec/src/sig/tests.rs` runs every vector through the same strict ed25519 verifier that
`rdy_spec::load` uses (ADR 0018). A `valid` vector must verify, an `invalid` one must not, and an
`acceptable` one may do either.

To refresh the file, fetch the same path again, read the diff, and run the tests.
