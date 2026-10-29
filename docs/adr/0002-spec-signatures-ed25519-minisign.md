# ADR 0002: Specs are signed with ed25519 in minisign format, verified before parsing, keys pinned per product

- Status: Accepted (revised 2026-10-28 after security-reviewer and cli-ux review; decision 5 amended 2026-10-28 in M1-009: a declined `trust add` exits 64; decision 2 amended 2026-10-28 in M1-120: see ADR 0018)
- Date: 2026-10-27

## Context

CLAUDE.md rule 3: specs are signed by the vendor's ed25519 key and the CLI refuses unsigned or tampered
specs unless `--allow-unsigned`. A spec decides what `rdy` reads on a customer box, and from M3
(ADR 0005) what it may execute. Verification must work offline. The plan's release section says
"binaries and specs signed with Sigstore", which conflicts with rule 3. Designing our own signature
envelope is a classic way to get crypto wrong. Untrusted bytes should not reach the YAML parser as root.

## Decision

1. **Format.** Detached minisign signature (ed25519 over a BLAKE2b-512 prehash of the exact file bytes,
   8-byte key id, signed trusted comment) in `<spec>.minisig`, or the file named by `--sig`. The trusted
   comment must be exactly `rdy-spec-v1 product=<slug> signed_at=<RFC 3339>`; anything else is refused.
   That prefix is our domain separation. Docs tell vendors to use a dedicated spec-signing key.
2. **Crates.** `rdy-spec` verifies with `minisign-verify`, pinned to an exact version and reviewed on
   every bump, called with legacy (non-prehashed) signatures off. (Amended by ADR 0018: `rdy-spec` reads
   the envelope itself and verifies with `ed25519-dalek` `verify_strict` and `blake2`.) Wycheproof EdDSA vectors and
   malleability cases run against it in CI. `rdy` creates keys and signs with the `minisign` crate (amended by ADR 0022: `rdy-cli` does this itself, and the crate is a test-only second implementation).
   Stock `minisign` interoperates.
3. **Verify, then parse.** `rdy_spec::load` reads the key id and the trusted comment from the signature,
   looks up keys pinned for that product, verifies the raw bytes, and only then parses. After parsing,
   `metadata.product` must equal the trusted-comment product. `load` is the only way to get a
   `LoadedSpec`. `parse_unverified` exists for `spec lint`, `--allow-unsigned` runs and portal authoring.
4. **Trust store.** Entries `{ product, key, added_at, note }`. A key is trusted only for named products.
   - Normal user: `$XDG_CONFIG_HOME/rdy/trust.yaml`.
   - euid 0: only `/etc/rdy/trust.yaml`, never a user path, whatever HOME or XDG say. Refused, with the
     reason, if it is a symlink, not owned by root, group or world writable, or in a directory writable
     by anyone but root. Written atomically, mode 0644. Not on any cut list.
5. **Pinning only in `rdy trust add <product> --key <file or base64>`.** It prints key id and
   fingerprint and asks `Trust this key for <product>? [y/N]`; `--yes` skips the question; with no TTY
   and no `--yes` it exits 64. A declined question (no, or an empty answer) also exits 64 and writes
   nothing, so a chain with `&&` stops. `rdy run <spec> --key <pubkey>` verifies for that run only and
   writes nothing. There is no `--trust-key`. `rdy trust list` and `rdy trust remove <product> [--key-id]`.
6. **Key distribution in M1** is out of band: the vendor's docs page and the SE's email. From M2, a key
   served with a share link is shown with its fingerprint and pinned only on an explicit yes. A changed
   key for an already pinned product is a hard failure, never a silent re-pin.
7. **Signature states:** `Verified`, `Unsigned`, `Invalid { reason }`. A missing signature exits 64
   unless `--allow-unsigned` (argv only: no env var, config or alias), which prints a red banner and
   stamps `unsigned` into both reports. A present but failing signature exits 64 always, even with the
   flag. Its fix hint says "get a fresh copy and its .minisig from the vendor"; it never suggests the flag.
8. **Secret keys.** `rdy spec keygen` writes with `create_new`, mode 0600, password-encrypted by
   default; `--unencrypted` is explicit for CI. `spec sign` refuses a group or world readable key. Secret
   bytes are never printed or logged.
9. **Sigstore signs binaries and checksums, not specs.** Different signer, key and verifier.

## Consequences

- Offline verification, no transparency log. Partner runs never parse unverified bytes.
- Rotation is pin-new, remove-old by hand. No revocation list in v1. Rollback of an old signed spec is
  visible through `signed_at` in the report; portal-served specs (M2) fix it.
- `ed25519-dalek` (plan) is not a direct dependency. Signing is still ed25519. (Amended by ADR 0022: `rdy` depends on `ed25519-dalek` directly to sign, with `zeroize`, because it writes the key file and signs itself.)
- Tightens CLAUDE.md rule 3: a tampered spec is refused even with `--allow-unsigned` (plan correction).

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Raw ed25519-dalek with our own envelope | We would design key ids, prehash and domain separation ourselves. |
| Signature embedded in the YAML | Needs YAML canonicalization, a known source of bypasses. |
| Sigstore keyless for specs | Needs online Fulcio and Rekor or a shipped trust root; breaks offline-first. Revisit in M5. |
| Key on the vendor's own domain (`/.well-known/rdy-keys.txt`) | A real second channel, but needs network and vendor setup. Candidate for M2 alongside the portal key. |
| SSH signatures or DSSE | Larger formats than a spec needs. |
| Trust on first use, or pinning from `run` | Silent or side-effect pinning of an attacker's key. Pinning is its own command. |

## Tickets implied

- [M1] Verify minisign signatures in rdy-spec against a trust store with product binding | owner: rust-engineer | est: 4h | depends on: Define public spec types in rdy-spec | exit test: a tampered byte, a wrong product, a bad trusted-comment prefix and an unpinned key each fail with a distinct SignatureError, Wycheproof vectors pass, and a parser spy shows a tampered spec is never parsed.
- [M1] Trust store load and save in user and system locations | owner: rust-engineer | est: 3h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: as root with HOME and XDG_CONFIG_HOME pointing at a user store, only /etc/rdy/trust.yaml is read, and a symlinked, non-root or group-writable file is refused with the reason.
- [M1] rdy spec keygen and rdy spec sign | owner: rust-engineer | est: 4h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: a spec signed by rdy verifies with stock minisign and the reverse; keys are 0600 and encrypted unless --unencrypted; a world-readable key is refused.
- [M1] rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | owner: rust-engineer | est: 3.5h | depends on: rdy spec keygen and rdy spec sign | exit test: unsigned exits 64; with --allow-unsigned it runs and both reports say unsigned; an invalid signature exits 64 even with the flag and its hint never names the flag.
- [M1] Security review of spec signing and trust store | owner: security-reviewer | est: 2h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: review notes filed and every blocker fixed before the 0.1.0 tag.
- [M1] rdy trust add, list and remove | owner: rust-engineer | est: 2h | depends on: Trust store load and save in user and system locations | exit test: `trust add` without a TTY and without --yes exits 64 with a fix line; with --yes it pins and `trust list` shows key id and fingerprint; `run --key` leaves the store unchanged.
