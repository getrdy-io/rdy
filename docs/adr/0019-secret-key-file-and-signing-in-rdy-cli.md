# ADR 0019: rdy writes minisign secret keys with scrypt at the stock cost, and signs in rdy-cli

- Status: Accepted (2026-10-28, M1-125). Amends ADR 0018 decision 7 and the last sentence of ADR 0002 decision 2 (the signing crate).
- Date: 2026-10-28

## Context

ADR 0002 decision 8 says `rdy spec keygen` writes the secret key password-encrypted by default and
`rdy spec sign` refuses a key that others can read. ADR 0018 decision 7 says `rdy` creates keys and
signs with the `minisign` crate. Neither says how strong the encryption is. Reading `minisign` 0.10 for
M1-125 found three problems.

1. **Its key cost is low.** `generate_encrypted_keypair` always uses scrypt with 32 MiB and N = 2^15. Stock
   minisign tooling uses 1 GiB and N = 2^20. The crate has no way to pick a cost, and its fields are
   private, so rdy cannot encrypt a key with a higher one through its API. The key file is the one secret a
   vendor has (threat model I1). If it leaks, the password is all that stands between the thief and a
   signed spec. A fast KDF makes the guess cheap.
2. **It reads and writes the terminal itself.** It prints `<empty>` and prompts to stdout, and it reads key
   files with `read_to_string` and no link or mode check. rdy needs its own prompt helper (M1-123), its own
   password sources (M1-112) and the checks of decision 3 below.
3. **Its signing is not the code rdy verifies.** It signs with a random nonce. rdy verifies with
   `verify_strict` (ADR 0018). Using one implementation for both ends is simpler to review.

## Decision

1. **rdy reads and writes the minisign secret key file itself.** It is the format stock minisign tooling
   reads: `Ed`, a KDF id (`Sc` for scrypt), `B2`, a 32-byte salt, two little-endian limits, then the key
   id, the 64-byte secret key and a BLAKE2b-256 checksum, XORed with 104 bytes of scrypt output. The code
   is `crates/rdy-cli/src/signing/key.rs` and is about 200 lines of logic.
2. **The cost of a new key is the stock cost, and it is also the most a key file may ask for.** Opslimit
   33,554,432 and memlimit 1,073,741,824, which libsodium's parameter rule turns into N = 2^20, r = 8, p = 1.
   It needs 1 GiB and about two to four seconds. A file that asks for more (a larger limit, or N above 2^20)
   is refused before any work starts, so a key file from someone else cannot exhaust memory or time. A file
   that asks for less (the `minisign` crate's own keys) opens. There is no flag to lower the cost.
3. **Key files are opened and created without trusting the path.** Read: one open with `O_NOFOLLOW` and
   `O_NONBLOCK`, then every check on the handle: regular file, owned by the effective user, no group or
   other bits, at most 1 KiB. Write: `create_new` (`O_EXCL`) with mode 0600 passed to `open`, so the file is
   never wider than 0600, not even for a moment. A key or signature is never replaced. Windows opens without
   following a reparse point and checks the type only. A new file there gets the folder's access list. That
   is a named residual and the success message says it.
4. **Signing is ed25519 over the BLAKE2b-512 hash of the spec, then over the signature and the trusted
   comment** (01 section 4.1). `ed25519-dalek` signs, with its `zeroize` feature, so the seed is wiped on
   drop. It is deterministic (RFC 8032), so a test can compare bytes. Passwords, seeds and decrypted bytes
   live in `Zeroizing` wrappers and are never printed or put in an error.
5. **`rdy spec sign` verifies its own signature with `rdy_spec::load` before it writes.** The same code a
   customer's rdy runs, with the key pinned for the product. A signature that does not check is a bug
   (exit 70) and nothing is written.
6. **The `minisign` crate stays as a dev-dependency.** It is the second implementation: tests open rdy's
   keys with it, rdy opens its keys, and it verifies rdy's signatures. That is the interop proof for stock
   `minisign -V`.
7. **New runtime dependencies of `rdy`:** `scrypt` 0.11 (and RustCrypto crates it uses), `ct-codecs` (constant
   time base64 for secret bytes), `getrandom` 0.4, and `blake2` and `ed25519-dalek`, which `rdy-spec` already
   pins. All were already in the tree through the dev-dependency. `scrypt` and its hash crates are built with
   `opt-level = 3` in the dev profile, because an unoptimized key derivation takes minutes.

## Consequences

- `rdy-spec` stays verify-only. The portal never gets signing code from the public crates.
- Key generation takes seconds and 1 GiB of memory. A small CI container may need more memory than
  that. A vendor who cannot spare it can run `keygen` on a laptop. Signing in CI then needs the same 1 GiB
  to open the key. The alternative, a lower cost, makes the stolen-key case worse, and the ticket's rule is
  the conservative option.
- Tests run the real cost once per command, one at a time (a mutex), and use a cheap cost elsewhere.
- We own about 200 lines of the container format. Round trips against the `minisign` crate in both
  directions, and a table of malformed files, keep them honest.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Use `minisign` 0.10 for keys and signing (ADR 0018 decision 7) | 32 MiB and N = 2^15, fixed, and its own terminal I/O. See the context. |
| Lower cost, such as N = 2^17 | Weaker than stock for no gain a vendor feels. |
| `age` or another file encryption instead of the minisign format | Stock minisign could no longer open the key, and the exit test needs that. |
| Raise the cost with a flag | A weak key made by habit is worse than an error. Add the flag if a real container needs it. |
| An OS keychain | Not portable to the five targets and not available in CI. A later ticket may add it behind the same container. |
