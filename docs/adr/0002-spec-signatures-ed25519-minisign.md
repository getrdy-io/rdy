# ADR 0002: Specs are signed with ed25519 in minisign format, keys pinned per product

- Status: Accepted
- Date: 2026-10-27

## Context

CLAUDE.md rule 3: specs are signed by the vendor's ed25519 key and the CLI refuses unsigned or tampered
specs unless `--allow-unsigned`. A spec decides what `rdy` reads on a customer box, and later (ADR 0005)
what it may execute, so the spec is the main supply-chain input. Verification must work fully offline.
The plan's release section says "binaries and specs signed with Sigstore", which conflicts with rule 3.
Designing our own signature envelope is a classic way to get crypto wrong.

## Decision

1. **Format.** Detached signature in minisign format: ed25519 over a BLAKE2b-512 prehash of the exact
   file bytes, with an 8-byte key id and a signed "trusted comment". The sidecar is `<spec>.minisig`
   next to the spec. The trusted comment carries `product=<metadata.product> signed_at=<RFC 3339>`.
2. **Crates.** `rdy-spec` verifies with `minisign-verify` (pure Rust, no dependencies), so `rdy-cloud`
   can verify with the same code. `rdy-cli` creates keys and signs with the `minisign` crate, which also
   gives password-encrypted secret keys. Vendors can use the stock `minisign` CLI instead; it interoperates.
3. **Key pinning.** The CLI trusts a key only for named products. Trust lives in
   `$XDG_CONFIG_HOME/rdy/trust.yaml` (user) and `/etc/rdy/trust.yaml` (system, used when running as root).
   Each entry is `{ product, key, added_at, note }`. A spec verifies only if its signer key is pinned for
   its `metadata.product`, and the trusted comment's product matches too.
4. **Key distribution in M1** is out of band. The vendor publishes its public key on its own docs page
   and in the SE's email. The customer passes it once with `--key <base64 or file>`; the CLI prints the
   key id and fingerprint and asks to pin it (non-interactive runs need `--trust-key` explicitly).
   From M2, a spec fetched through a portal share link arrives with the vendor key served by
   app.getrdy.io over TLS; that makes Rdy part of the trust chain and the docs say so.
5. **Unsigned or failing specs** exit with code 64 and a fix hint. `--allow-unsigned` runs them, prints a
   red banner on stderr, and stamps `signature: unsigned` into the JSON and HTML reports.
6. **Sigstore signs binaries and checksums, not specs.** The release pipeline signs with cosign keyless
   (GitHub OIDC). That proves "this binary came from getrdy-io/rdy CI". A spec signature proves "this
   vendor wrote these requirements". Different signers, different keys, different verifiers.

## Consequences

- Offline verification with no network and no transparency log.
- Rotation: a vendor pins a new key per product and signs with it; old keys are removed by hand
  (`rdy trust remove`). No revocation list in v1. Documented as a known limit.
- Rollback: an old, validly signed spec with looser thresholds can be replayed. The report shows
  `signed_at` so an SE can spot it; a portal-served spec (M2) fixes it by fetching the latest version.
- `ed25519-dalek`, named in the plan, is not a direct dependency. Signing is still ed25519.
- Command names (`trust add|list|remove`, `spec keygen`) are provisional until cli-ux signs off.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Raw ed25519-dalek with our own envelope | We would design key ids, prehash and domain separation ourselves. minisign already did, and reviewers know it. |
| Signature embedded in the YAML | Needs canonicalization of YAML, which is fragile and a known source of bypasses. |
| Sigstore keyless for specs | Needs Fulcio and Rekor online or a shipped trust root plus bundle; vendors would need OIDC identities. Breaks offline-first. Possible add-on in M5. |
| SSH signatures (`ssh-keygen -Y`) | Familiar keys, but a larger format to parse and RSA keys in the mix. |
| DSSE or in-toto envelope | Built for attestations of artifacts, heavier than a spec needs. |
| Trust on first use | Silent pinning of an attacker's key on first run. We pin only with an explicit user action. |

## Tickets implied

- [M1] Verify minisign signatures in rdy-spec against a trust store with product binding | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a tampered byte, a wrong product and an unpinned key each fail with a distinct SignatureError.
- [M1] Trust store load and save in user and system locations | owner: rust-engineer | est: 2h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: running as root reads /etc/rdy/trust.yaml, as a user reads XDG config, in a temp-dir integration test.
- [M1] rdy spec keygen and rdy spec sign | owner: rust-engineer | est: 3h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: a spec signed by rdy verifies with the stock minisign CLI and the reverse.
- [M1] rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | owner: rust-engineer | est: 3h | depends on: rdy spec keygen and rdy spec sign | exit test: unsigned spec exits 64 with a hint; with --allow-unsigned it runs and the JSON says signature: unsigned.
- [M1] Security review of spec signing and trust store | owner: security-reviewer | est: 2h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: review notes filed and every blocker fixed before the M1 tag.
