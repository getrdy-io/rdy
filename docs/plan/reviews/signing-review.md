# Security review of spec signing and the trust store (M1-132)

Reviewer: security-reviewer. Authors of the reviewed code: rust-engineer (M1-120, M1-121, M1-122, M1-125,
M1-126, M1-131). Date: 2026-11-17. No reviewed code was edited. This file is the exit test of M1-132.

## Scope

- The `rdy-spec` signature format and ed25519 verification: the minisign envelope reader, the strict
  base64 decoder, key ids, fingerprints, the trusted comment, weak, small-order and non-canonical keys,
  legacy `Ed` signatures, and interop with stock minisign.
- Spec loading policy: `Policy::RequireSigned`, `Policy::AllowUnsigned`, `--key` one-run trust, the
  `.minisig` sidecar and `--sig`, and the order verify, parse, product, expiry.
- Trust store read and write on Linux, macOS and Windows: paths per euid, owner and mode checks on open
  handles, root-only `/etc/rdy`, atomic writes, and ADR 0027 refusing every Windows store.
- `rdy spec keygen` and `rdy spec sign`: key files, scrypt encryption, password sources, the self-check
  and the sidecar write.
- `rdy trust add`, `list` and `remove`: the key argument, the fingerprint prompt, `--yes`, notes.
- The UNSIGNED SPEC and KEY NOT PINNED banners as they stand in code.

Read against: 01 sections 4.1 to 4.8, 05 Surface 2 (requirements 1 to 5, residual risks), Appendix B
(S1, S2, T1 to T4, R1, I1, D1), INV-01 to INV-05 and INV-17, ADRs 0002, 0018, 0021, 0022, 0027 and 0033,
and the 12-progress deferrals of M1-120 to M1-131.

Out of scope: the byte-for-byte banner text and the Tip forms (M1-130), the HTML banner (M1-181), and the
release signing of binaries (Sigstore, 06).

## Commit reviewed

`968df103220c4cbcd0b0b04d15478f03cd5578f4`, the head of `m1/126-rdy-verify` (PR #84, approved, not yet
merged). It holds main at `960ce15d` plus M1-126. This review branch, `m1/132-signing-review`, is stacked
on it. If PR #84 changes before it merges, the diff to this commit needs a second look.

## Method

- Read every file on the path line by line. In `crates/rdy-spec/src/`: `sig.rs`, `sig/base64.rs`,
  `sig/error.rs`, `sig/key.rs`, `sig/store.rs` and `loaded.rs`. In `crates/rdy-cli/src/`: `spec_load.rs`,
  `verify_cmd.rs`, `trust.rs`, `trust/unix.rs`, `trust/other.rs`, `trust_cmds.rs`, `spec_cmds.rs`,
  `password.rs`, `lint.rs`, `signing/files.rs`, `signing/key.rs`, `signing/pubkey.rs`,
  `signing/sidecar.rs`, the banner in `terminal.rs`, the spec error hints in `error/mod.rs` and the clap
  definitions in `cli.rs`.
- Walked each STRIDE row of 05 Appendix B and each Surface 2 requirement to the code that holds it and the
  test that proves it.
- Checked the crypto pins in `Cargo.toml` and `Cargo.lock` (`ed25519-dalek =2.2.0`, `curve25519-dalek
  4.1.3`, `blake2 =0.10.6`, `scrypt =0.11.0`, `ct-codecs =1.1.8`, `getrandom =0.4.3`) and the
  `verify_strict` path of `ed25519-dalek` 2.2.0.
- Checked test coverage by name: `sig/tests.rs` (Wycheproof, malleability, swaps, parser spy, proptest),
  the `sig/key.rs` tests, `sig/store/tests.rs`, and in `crates/rdy-cli/tests/`: `root_trust_strace.rs`,
  `verify_command.rs`, `verify_windows.rs`, `trust_commands.rs`, `trust_commands_windows.rs`,
  `spec_keygen_sign.rs`, `minisign_c_interop.rs` and `error_signature.rs`.
- Claims below are from code reading. No test was run for this review. The CI of PR #84 is the run record.

## Verdict

The signing path is sound for 0.1.0. Verify-then-parse is enforced by type privacy, a present signature
can never fall back to unsigned, keys are pinned per product and checked by full key, the verifier is
strict, root never builds a user path, and every Windows store is refused. No must-fix item. Four
should-fix items and one accepted residual follow.

## Findings

| ID | Severity | Where | Finding | Fix | Status | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| SR-01 | Low | `crates/rdy-cli/src/lint.rs:42` and `:49`; `crates/rdy-cli/src/spec_cmds.rs:420` and `:424` | The spec reader of `rdy run` and `rdy verify` stats the path, then opens it again with a blocking `File::open` and never checks the open handle. A path swapped to a FIFO in that gap hangs the command, and a swap to a device opens it, as root under `sudo`. The run watchdog is armed only after the output folder exists (`run_cmd.rs:169` loads, `:247` arms), so nothing bounds the hang. `spec sign` opens first and checks the type after, so a FIFO path hangs it outright. The sidecar and key readers already avoid this (`signing/files.rs:104`, `read_public`). Needs write access to the spec's folder and a race, so Low. | Read the spec with `signing::files::read_public(path, MAX_SPEC_BYTES + 1)` in both places (stat, then an `O_NONBLOCK`, `O_NOCTTY` open, then a device and inode compare), and map `FileError` to `spec_unreadable`. Add a test: a FIFO swapped in after the stat is refused within 1 s (INV-02). | should-fix, open | New follow-up ticket (rust-engineer), coordinator to number |
| SR-02 | Low | `crates/rdy-cli/src/spec_cmds.rs:347`, `:388` to `:389` | `rdy spec sign` lints with `Spec::lint_checks` only, not the whole `rdy spec lint` that 01 section 4.5 step 1 names. `lint_checks` has no expiry finding. An expired spec passes lint, gets signed, then the self-check `load` refuses it with `Expired`, and that error is mapped to `CliError::bug()`: exit 70 and "this is a bug" for a user error. Not a bypass (nothing is written), but it teaches vendors to ignore internal errors from the signing command. | Lint with `rdy_spec::lint::lint_bytes` (or add its expiry finding) so an expired spec refuses with exit 64 before the key is opened, and map a `SpecError::Expired` from the self-check to the `spec_expired` usage error. Add a test that signs a spec with a past `expires`. | should-fix, open | Same follow-up ticket as SR-01 |
| SR-03 | Low | `crates/rdy-spec/src/sig.rs:269` (form check only); no caller compares `signed_at` with the clock | 01 section 4.2 says a `signed_at` more than 24 hours in the future gives a warning. It is not built. M1-120 deferred it to M1-026, and M1-026 merged without it and without carrying it. A future stamp points at a wrong vendor clock, or at a spec made to look newer than it is. It is a heuristic, not an authentication gap: only the key holder chooses `signed_at`. | Fold it into M2-032 (signed_at and serial warnings), which already compares `signed_at`, and record that with a plan correction to 01 section 4.2 ("from M2-032"). If it stays in M1, build it in `spec_load` with the run clock and a `warning:` line, and record it in the result. | should-fix, open | M2-032; coordinator files the plan correction |
| SR-04 | Low | `crates/rdy-cli/src/terminal.rs:182`, `:232` | The KEY NOT PINNED banner shows a 12-digit short fingerprint (first 8 and last 4 hex digits, 48 bits). A key whose fingerprint matches those 48 bits can be ground for. The banner does not ask for a comparison ("rdy cannot tell whose key that is"), but 05's residual for `--key` named this banner as the mitigation, and people compare what they see. The full fingerprint is in the JSON report (`signature.key_fingerprint`) and in `rdy verify --key`. | Docs: the unsigned page (M1-133) and the sign and verify page (M1-134) say to compare the full fingerprint that `rdy verify --key` prints, never the short form in the banner. 05's residual text says this now (edited in this branch). Showing the full fingerprint in the banner needs a cli-ux change to 01 section 4.7; not required. | should-fix, open | M1-133 and M1-134 (docs-writer) |
| AR-01 | Low | `crates/rdy-cli/src/spec_load.rs:58` to `:61`, `signing/pubkey.rs:349`, `signing/files.rs:104` | 05 Surface 2 residual (PR #84 review, F7): a `--key` file has no owner or mode check, also in a root run, so a user who can write a shared folder can swap it. Reviewed: an attacker who can swap the key in that folder can swap the spec and the sidecar too, so an owner check on the key alone buys little. `--key` is the explicit unpinned path, the run prints KEY NOT PINNED, the report records `trust_source: flag` and the full fingerprint, and pinned runs are not affected. An owner rule would also break the normal `sudo rdy run spec.yaml --key ./vendor.pub` from the user's folder. | Accepted for M1. Next control: M2-034's TTY confirmation after the banner (SEC-56). Re-check this row when M2-034 lands. | accepted residual | M2-034 (re-check) |

## What holds, by area

**Signature format and verification (M1-120, ADR 0018).**
- The envelope is exactly four lines, one final newline, CR stripped per line, at most 4 KiB, UTF-8
  (`sig.rs:175` to `:242`). The untrusted comment is checked for its label and never read
  (`the_untrusted_comment_is_never_read`).
- Base64 is canonical: padding required, no whitespace, zero trailing bits (`sig/base64.rs`), so a
  signature has one accepted text.
- Only `ED` is accepted. `Ed` is its own error before any math (`a_legacy_signature_is_refused_by_its_form`).
- The trusted comment is exactly `rdy-spec-v1 product=<slug> signed_at=<YYYY-MM-DDTHH:MM:SSZ>`, single
  spaces, a real calendar date, and a slug that matches 01 section 4.2 (`spec.rs:149`). Domain separation
  holds.
- Both signatures use `verify_strict` (canonical `S`, small-order `R` and `A` refused), over BLAKE2b-512 of
  the raw bytes and over the signature followed by the comment. Wycheproof vectors and malleability cases
  run (`wycheproof_ed25519_vectors`, `malleable_signatures_are_refused`). A swapped or reused global
  signature fails (`swapping_the_two_signatures_or_reusing_another_files_signature_fails`).
- Public keys: 42 bytes, `Ed` prefix, a point on the curve, canonical encoding, not of small order
  (`sig/key.rs:158`). Every path that builds a `PublicKey` goes through this: trust file, `trust add`,
  `--key`.
- Key id preselects; the full key decides (`a_wrong_key_with_the_right_key_id_does_not_verify`). The
  fingerprint is SHA-256 of the 32 key bytes. A key pinned for product A does not verify product B.
- Interop: an rdy signature verifies with stock minisign and a C minisign 0.11 signature verifies in rdy
  (`minisign_c_interop.rs`, committed fixtures in `tests/fixtures/minisign-c/`).

**Spec loading policy (M1-126).**
- `LoadedSpec` has one private constructor, used only by `load`, which verifies before `parse_bytes`
  (`loaded.rs:154` to `:189`). Compile-fail tests pin it. A parser spy proves a tampered spec is never
  parsed (INV-01).
- A present sidecar is verified under either policy. A failing one never becomes unsigned. Only a default
  `.minisig` that does not exist at all (not even a dangling link) is "no signature". Any other read
  failure becomes an empty buffer that is refused as malformed (`spec_load.rs:110` to `:150`). A missing
  `--sig` file is a usage error.
- `--key`: read first, no trust store read, trusted only for the product the sidecar names, and that
  product must still equal `metadata.product`. A `--key` run with no sidecar is refused even with
  `--allow-unsigned`. The result carries `trust_source: flag`.
- `--allow-unsigned`, `--key` and `--yes` have no `env` binding in `cli.rs`. No hint or fix line names
  `--allow-unsigned` or `--key` (`no_error_message_or_hint_names_the_flags_that_weaken_the_check`).
- The verified buffers are the ones copied into the report folder (`VerifiedSpecBytes`).

**Trust store (M1-121, M1-122, ADR 0021, ADR 0027).**
- Euid 0 on Unix: the `Layout` has no user path, so no code can reach one. The real `rdy verify` as root
  under `strace -f` opens nothing under the user's home and does no account lookup
  (`root_verify_binary_opens_no_path_under_sudo_users_home`), and a `--key` run reads no store
  (`root_verify_with_key_reads_no_trust_store`).
- Unix reads open the folder with `O_NOFOLLOW` and `O_DIRECTORY`, check owner and mode on the handle, then
  `openat` the file with `O_NOFOLLOW`, `O_NONBLOCK` and `O_NOCTTY` and check type, owner and mode on that
  handle, with a bounded read (`trust/unix.rs`). System: root-owned folder and file, no group or other
  write. User: owned by the user or root, no group or other write, no symlink. A bad store stops the run,
  and no pin from the other store is used.
- Writes: an atomic temp file with `O_EXCL` and `O_NOFOLLOW`, the exact mode by `fchmod` (0644 system,
  0600 user), `fsync`, `renameat`. An existing store that a read would refuse is not replaced.
- Windows: any existing store is refused as unverifiable, a missing one is empty, saving is unsupported,
  and `%APPDATA%` is never read. A user who points `ProgramData` elsewhere gets an empty or a refused store,
  so this fails closed (ADR 0027).
- The trust file parser: 256 KiB, one document, no anchors, aliases, merge keys or tags, unknown keys
  refused, every key through the strict key parser, one key id per product.

**Keygen and sign (M1-125, ADR 0022).**
- Keys come from `getrandom`. The secret file is created with `O_EXCL` and `O_NOFOLLOW` at 0600 and is
  encrypted with scrypt at N = 2^20, r = 8, p = 1 unless `--unencrypted`, which warns. A key file that asks
  for more, or for p other than 1, is refused before any work.
- `spec sign` reads the secret key with `read_private` (no symlink, regular file, owner, no group or other
  access on Unix), signs one buffer, verifies the result with `load` before writing, and writes the sidecar
  with `O_EXCL`, or with `--force` through a new temp file and a rename. It refuses a sidecar path that is
  the spec or the key.
- Passwords never come from argv (`--password` is refused before clap). The variable source prints its
  note on a terminal. Secrets are in `Zeroizing` wrappers, and `SigningKey` zeroizes on drop.

**Trust commands (M1-131, ADR 0033).**
- `trust add` validates everything first, refuses before it prints the key when there is no terminal and
  no `--yes`, shows the key id, the full fingerprint in groups of four and the compare paragraph, asks
  `[y/N]` with default no, reads the store again after the yes, and exits 64 on a no. A secret key is
  refused by its form, from a file or from text, and is never echoed.
- Notes are at most 512 characters with no control characters, and are escaped (control, bidi and
  invisible code points) when printed.
- `trust remove` only takes trust away and never touches the other store.

**Banners.** `banner_title` shows a banner unless the spec is verified by a system or user pin, so a
`--key` run always shows KEY NOT PINNED and an unsigned run UNSIGNED SPEC. The spec path in the banner is
escaped. The text and placement are M1-130's to finish.

## Residuals already recorded elsewhere

| Residual | Where it is recorded | Owner |
| --- | --- | --- |
| Key distribution is manual. Pinning the wrong key trusts the wrong vendor. | 05 Surface 2 residual risks | accepted |
| No revocation in v1. A leaked key stays trusted until it is removed by hand. | 05 Surface 2, ADR 0002 | accepted; rotation in M2-032 |
| macOS extended ACLs are not seen by the mode checks. | 05 Surface 2, ADR 0021 | accepted, no FFI |
| Windows trust stores are refused. Real DACL checks, elevation detection and `FOLDERID_ProgramData` (not the variable) come later. | ADR 0027, 12-progress M1-122 | M2-105 |
| Windows key files get the folder's ACL, and `spec sign` checks no ACL. | 05 Appendix B I1, ADR 0022 | M2-085 (SEC-58) |
| Two `trust add` or `remove` runs can lose one change (no lock). | ADR 0033 consequences | M2-107 |
| The HTML report does not exist yet, so "both reports say unsigned" is proved on JSON and stderr. | 12-progress M1-126, correction-50 | M1-181 |
| Banner text byte for byte, both banners above the verdict, KEY NOT PINNED on every HTML page. | 11-backlog M1-130 | M1-130 |
| Portal-served keys, and a key change for a pinned product. | 05 Appendix B S3 | M2-033 (SEC-47) |
| Rollback to an older signed spec. | 05 Appendix B T4 | M2-032 (SEC-46) |
| TTY confirmation after either banner. | 05 Appendix B T2, 01 section 4.7 | M2-034 (SEC-56) |
| `RDY_KEY_PASSWORD` is readable by the same user and by root, and child processes inherit it. | `password.rs` module docs, `ENV_NOTE` | accepted, documented |
| Ctrl-C during the 2 to 4 second key derivation. | 12-progress M1-125 | the M1 Ctrl-C ticket |

Must-fix items open: 0. Should-fix items open: 4 (SR-01 to SR-04). Accepted residuals: 1 (AR-01).
