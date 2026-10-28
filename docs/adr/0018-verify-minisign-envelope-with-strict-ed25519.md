# ADR 0018: rdy-spec checks the minisign envelope itself, over strict ed25519 and BLAKE2b

- Status: Accepted (2026-10-28, M1-120). Amends ADR 0002 decision 2 (the verifier crate).
- Date: 2026-10-28

## Context

ADR 0002 decision 2 says `rdy-spec` verifies with `minisign-verify`, pinned to an exact version, with
Wycheproof EdDSA vectors run against it in CI. The plan table (00-overview) names the 0.2 line. Reading the
current release (0.3.0) for M1-120 found three problems.

1. **The API hides what the design needs.** `Signature` and `PublicKey` expose no key id, no algorithm
   and no key bytes. The design looks keys up by key id, wants the fingerprint (SHA-256 of the 32 key
   bytes) and must refuse legacy `Ed` before any math. Getting those means decoding the envelope in
   `rdy-spec` anyway.
2. **Its ed25519 is not strict.** It rejects `S >= L` and the identity key. It accepts other small-order
   keys, and it does not check `R` for small order. The threat model (Surface 2, requirement 2) wants weak
   keys refused.
3. **Wycheproof cannot reach it.** The vectors sign raw messages. The crate hashes first and then checks a
   second signature over the comment. No public call runs a bare ed25519 verification, so the ADR's CI
   test would test the wrong thing.

## Decision

1. `rdy-spec` reads the minisign envelope itself (four lines, base64, 2+8+64 bytes and 64 bytes) in
   `crates/rdy-spec/src/sig.rs` and `sig/`. The code is small, with a strict base64 decoder (canonical,
   padded, no whitespace).
2. It verifies with `ed25519-dalek` `verify_strict` over the BLAKE2b-512 hash of the raw bytes, then over
   `signature || trusted comment`. Public keys with small order, off the curve or in a non-canonical encoding are refused when they are
   built (`PublicKey::from_base64`). Pinned exactly: `ed25519-dalek =2.2.0`, `blake2 =0.10.6`. Every bump
   is reviewed by hand. The 2.x line matches the `sha2` 0.10 and `digest` 0.10 the workspace already uses.
3. Only the prehashed form (`ED`) is accepted. `Ed` is refused as its own error before any math.
4. The Wycheproof `ed25519_test.json` file is vendored in `tests/fixtures/wycheproof/` and every vector
   runs through the production key parser and verifier. Valid must verify, invalid must not.
5. Tests sign with the `minisign` crate (dev-dependency only), so every good signature in the tests is one
   that stock minisign tooling writes. This is the interop proof for `minisign -V`.
6. Public keys must be the exact base64 with no surrounding whitespace, and the canonical encoding of the
   point. Each pin records a source (system, user or flag), and a verified result carries it, so the CLI
   can show KEY NOT PINNED for a one-run key. A bad file signature and a bad comment signature are two
   errors with one error code.
7. `rdy` still creates keys and signs with the `minisign` crate (ADR 0002), in M1-125. (Amended by ADR 0019: `rdy-cli` writes the secret key file and signs itself, because the crate's key cost is fixed and low.)

## Consequences

- We own the envelope parser. The tests cover each form error, and a proptest changes bytes of the signed
  fixture.
- Three crates enter the dependency tree of `rdy-spec`: `ed25519-dalek` (with `curve25519-dalek`, `subtle`),
  `blake2` and, for tests, `minisign`. All are MIT, Apache-2.0 or BSD-3-Clause. `cargo deny` stays clean.
- No third-party type appears in the public API of `rdy-spec`.
- If a verifier crate later exposes the key id and strict checks and takes the Wycheproof route, this can
  be replaced behind `rdy_spec::sig` without a format change.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| `minisign-verify` 0.3.0 (the ADR 0002 choice) | The three problems above. |
| The `minisign` crate for verification | It trims the trusted comment before signing and verifying, which differs from the bytes the design signs. It also pulls in password prompts. |
| `ring` ed25519 | No BLAKE2b, so a second crate would still be needed for the hash. |
| `ed25519-dalek` 3.0 | Newer major, brings `digest` 0.11 next to the 0.10 the workspace uses. Revisit with the next sha2 bump. |
