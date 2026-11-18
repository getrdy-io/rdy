# Security review of spec signing and the trust store (M1-132)

Reviewer: security-reviewer. Authors of the reviewed code: rust-engineer (M1-120, M1-121, M1-122, M1-125,
M1-126, M1-131). Date: 2026-11-17, revised the same day after the cold review of PR #96. No reviewed code
was edited. This file is the exit test of M1-132.

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
(S1, S2, T1 to T4, R1, I1, D1, E1), INV-01 to INV-06 and INV-17, ADRs 0002, 0018, 0021, 0022, 0027 and
0033, and the 12-progress deferrals of M1-120 to M1-131.

Out of scope: the byte-for-byte banner text and the Tip forms (M1-130), the HTML banner (M1-181), and the
release signing of binaries (Sigstore, 06).

## Commit reviewed

`968df103220c4cbcd0b0b04d15478f03cd5578f4`, the head of `m1/126-rdy-verify` (PR #84). PR #84 then merged
to main as `0fb5970f` with no crate diff from `968df103`, so the review holds for main. The branch
`m1/132-signing-review` has main merged. No file cited below changed between `968df103` and the head of
this branch.

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
  the `sig/key.rs` tests, `sig/store/tests.rs`, `trust/tests.rs`, and in `crates/rdy-cli/tests/`:
  `root_trust_strace.rs`, `verify_command.rs`, `verify_windows.rs`, `trust_commands.rs`,
  `trust_commands_windows.rs`, `spec_keygen_sign.rs`, `minisign_c_interop.rs` and `error_signature.rs`.
- Claims below are from code reading. No test was run for this review. The CI of PR #84 is the run record.

## Verdict

The signature checks are sound: verify-then-parse is enforced by type privacy, a present signature never
falls back to unsigned, keys are pinned per product and checked by full key, the verifier is strict, root
never builds a user path, and every Windows store is refused. The file reading around them is not: the
spec reader can hang or open a device (MF-01), which breaks INV-02. The review closes when M1-183 merges.

## Summary

| ID | Severity | Where | One line | Status | Owner |
| --- | --- | --- | --- | --- | --- |
| MF-01 | Must fix | `crates/rdy-cli/src/lint.rs:42`, `:49`; `crates/rdy-cli/src/spec_cmds.rs:420`, `:424`, `:347`, `:388` to `:389` | The spec reader blocks on a FIFO or tty and opens devices; `spec sign` of an expired spec exits 70 | open | M1-183 (correction 53, an M1-138 dependency) |
| SF-01 | Should fix | `crates/rdy-spec/src/sig.rs:269` | The `signed_at` future warning of 01 section 4.2 is not built | open | M2-032 (fold) |
| SF-02 | Should fix | `crates/rdy-cli/src/terminal.rs:182`, `:232` | The KEY NOT PINNED banner shows a 48-bit short fingerprint that people may compare | open | M1-134 and M1-133 (docs-writer) |
| N-01 | Nit | `crates/rdy-spec/src/sig/store.rs:410` to `:418` | Notes may hold bidi and invisible code points | open | M2-107 (fold) |
| AR-01 | Accepted residual | `crates/rdy-cli/src/spec_load.rs:58` to `:61`, `signing/pubkey.rs:349`, `signing/files.rs:104` | A `--key` file has no owner check in a root run | accepted for M1 | M2-034 (re-check) |
| AR-02 | Accepted residual | `crates/rdy-cli/src/signing/files.rs:97`, `:112` | `read_public` still opens a device swapped in between its `stat` and its `open` | accepted for M1 | M1-183 records it in 05 |

## Must fix

**MF-01. The spec reader of `run`, `verify` and `spec sign` can hang and can open devices. Breaks INV-02
and, for `spec sign`, 01 section 4.5 step 1 and the exit codes.**
- Problem:
  - INV-02 says a FIFO spec exits 64 within 1 s. `rdy spec sign <fifo>` opens the path before it checks
    the type (`spec_cmds.rs:420`, then `:424`), so it hangs with no race at all.
  - `rdy run` and `rdy verify` read the spec with `lint::read_spec`: a `stat` on the path
    (`lint.rs:42`), then a second, blocking `File::open` (`lint.rs:49`), and no check of the open handle.
    A FIFO or a tty swapped in between hangs rdy. The run watchdog is armed only after the output folder
    exists (`run_cmd.rs:169` loads, `:247` arms), so nothing bounds the hang. A device swapped in is
    opened, as root under `sudo`.
  - `spec sign` lints with `Spec::lint_checks` only (`spec_cmds.rs:347`), not the whole `rdy spec lint`
    that 01 section 4.5 step 1 names, so it has no expiry finding. An expired spec is signed, the
    self-check `load` refuses it with `Expired`, and that error becomes `CliError::bug()`
    (`spec_cmds.rs:388` to `:389`): exit 70 and "this is a bug" for a user error. Nothing is written, but
    it teaches vendors to ignore internal errors from the signing command.
  - The sidecar and key readers already do this right (`signing/files.rs:104`, `read_public`).
- Fix:
  - Read the spec in all three commands with `signing::files::read_public(path, MAX_SPEC_BYTES + 1)`:
    `stat`, then an open with `O_NONBLOCK` and `O_NOCTTY`, then a type, device and inode check on the
    handle. Map `FileError` to `spec_unreadable`. One reader, not two.
  - In `spec sign`, lint with `rdy_spec::lint::lint_bytes`, so an expired spec refuses with exit 64 and
    `spec_expired` before the key is opened. Map a `SpecError::Expired` from the self-check to the same
    usage error, never to `bug()`.
  - Tests: a direct FIFO, a FIFO swapped in between the `stat` and the open (through a test seam), and
    `/dev/zero` as the spec each exit 64 within 1 s for `rdy run`, `rdy verify` and `rdy spec sign`; and
    `rdy spec sign` of a spec with a past `expires` exits 64 with `spec_expired`.
  - Record AR-02 in 05 Surface 2 residual risks.
- Owner: M1-183 (rust-engineer), filed in correction 53 as a dependency of M1-138.

## Should fix

**SF-01. The `signed_at` future warning of 01 section 4.2 is not built.**
- Problem: 01 section 4.2 says a `signed_at` more than 24 hours in the future gives a warning.
  `parse_comment` checks the form only (`sig.rs:269`), and no caller compares it with the clock. M1-120
  deferred it to M1-026, and M1-026 merged without it and without carrying it. A future stamp points at a
  wrong vendor clock, or at a spec made to look newer than it is. It is a heuristic, not an
  authentication gap: only the key holder chooses `signed_at`.
- Fix: fold it into M2-032, which already compares `signed_at`, and correct 01 section 4.2 to say so (Plan
  corrections found).

**SF-02. The KEY NOT PINNED banner shows a short fingerprint.**
- Problem: the banner shows the first 8 and last 4 hex digits, 48 bits (`terminal.rs:182`, `:232`). A key
  whose fingerprint matches those 48 bits can be ground for. The banner does not ask for a comparison
  ("rdy cannot tell whose key that is"), but 05's residual for `--key` named this banner as the
  mitigation, and people compare what they see. The full fingerprint is in the JSON report
  (`signature.key_fingerprint`) and in `rdy verify --key`.
- Fix: the sign and verify page (M1-134) and the unsigned page (M1-133) say to compare the full
  fingerprint that `rdy verify --key` prints, never the short form in the banner. 05's residual says this
  now. A full fingerprint in the banner would need a cli-ux change to 01 section 4.7; not required.

## Nits

**N-01. Notes may hold bidi and invisible code points.** `check_note` refuses control characters only
(`sig/store.rs:410` to `:418`). The terminal escapes the rest, but a note also goes into every report the
customer sends. Fix: refuse what `rdy_engine::text::is_invisible` flags, in `check_note`, when M2-107 next
touches the store.

## Accepted residuals

**AR-01. A `--key` file has no owner or mode check, also in a root run** (05 Surface 2, PR #84 review F7).
An attacker who can swap the key in a shared folder can swap the spec and the sidecar too, so an owner
check on the key alone buys little. `--key` is the explicit unpinned path: the run prints KEY NOT PINNED,
the report records `trust_source: flag` and the full fingerprint, and pinned runs are not affected. An
owner rule would also break the normal `sudo rdy run spec.yaml --key ./vendor.pub` from the user's
folder. Accepted for M1. M2-034's TTY confirmation after the banner is the next control; re-check this
row when it lands.

**AR-02. `read_public` still opens a device swapped in during its gap** (`signing/files.rs:97`, `:112`).
The path is checked with `stat` and refused if it is not a regular file, and after the open the handle is
compared with what `stat` saw. A device swapped in between the two is refused, but it has seen its open.
The window needs write access to the folder and a race. Closing it needs a Linux-only `O_PATH` open
and a reopen of that handle, and macOS has no equivalent. Accepted for M1. M1-183
makes this the one reader of the spec, the sidecar and `--key` files, and records the residual in 05.

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
- CRLF: a file with Windows line endings fails as tampered, and the error says why and asks for the
  original (`sig/error.rs:54` to `:61`, `CliError::spec_in` in `error/mod.rs:403`;
  `windows_line_endings_are_tampered_and_the_error_says_so`, `error_signature.rs`).
- Interop: an rdy signature verifies with stock minisign and a C minisign 0.11 signature verifies in rdy
  (`minisign_c_interop.rs`, committed fixtures in `tests/fixtures/minisign-c/`).

**Spec loading policy (M1-126).**
- `LoadedSpec` has one private constructor, used only by `load`, which verifies before `parse_bytes`
  (`loaded.rs:154` to `:189`). Compile-fail tests pin it. A parser spy proves a tampered spec is never
  parsed (INV-01).
- The 1 MiB spec cap: the reader takes at most the limit plus one byte (`lint.rs:51`), and `load` refuses
  a larger buffer under every policy before it looks at the signature (`loaded.rs:161`;
  `an_oversized_spec_is_refused_under_every_policy_before_anything_else`,
  `a_spec_of_exactly_the_limit_can_verify`).
- A present sidecar is verified under either policy. A failing one never becomes unsigned. Only a default
  `.minisig` that does not exist at all (not even a dangling link) is "no signature". Any other read
  failure becomes an empty buffer that is refused as malformed (`spec_load.rs:110` to `:150`). A missing
  `--sig` file is a usage error.
- `--key`: read first, no trust store read, trusted only for the product the sidecar names, and that
  product must still equal `metadata.product`. A `--key` run with no sidecar is refused even with
  `--allow-unsigned`. The result carries `trust_source: flag`.
- `--allow-unsigned`, `--key` and `--yes` have no `env` binding in `cli.rs`. No hint or fix line names
  `--allow-unsigned` or `--key` (`no_error_message_or_hint_names_the_flags_that_weaken_the_check`,
  `an_env_variable_cannot_allow_an_unsigned_spec`).
- The 01 section 4.6 contract of `rdy verify`: it has no `--allow-unsigned` (`verify_cmd.rs:59` passes
  `false`, and `verify_takes_no_allow_unsigned_flag` gets exit 64 for the flag), it has no prompter and
  never asks, and it uses the same loader as `run`, so exit 0 means `rdy run` accepts the file with no
  override.
- The verified buffers are the ones copied into the report folder (`VerifiedSpecBytes`).
- Appendix B E1: unknown check ids and unknown fields become Skipped and run no code, a required one makes
  the verdict `not_ready`, unknown top-level keys exit 64, and M1 has no exec
  (`spec_refuses_unknown_top_level_keys_and_bad_kind`,
  `an_unknown_id_and_an_unknown_field_carry_the_did_you_mean_hint_of_skip_why`). All of it runs after
  verification, so an unsigned spec cannot reach it without `--allow-unsigned`.

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
- INV-02 for the store: a folder, a FIFO and a device are refused without a read, and a store over 256 KiB
  is refused while one of exactly the limit is not (`a_folder_or_a_pipe_is_not_a_store_and_is_not_read`,
  `a_device_is_not_a_store_and_is_not_read`,
  `a_store_over_256_kib_is_refused_and_one_at_the_limit_is_not_too_large`).
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
  the spec or the key. (Its spec reader is MF-01.)
- Passwords never come from argv (`--password` is refused before clap). The variable source prints its
  note on a terminal. Secrets are in `Zeroizing` wrappers, and `SigningKey` zeroizes on drop.

**Trust commands (M1-131, ADR 0033).**
- `trust add` validates everything first, refuses before it prints the key when there is no terminal and
  no `--yes`, shows the key id, the full fingerprint in groups of four and the compare paragraph, asks
  `[y/N]` with default no, reads the store again after the yes, and exits 64 on a no. A secret key is
  refused by its form, from a file or from text, and is never echoed.
- Notes are at most 512 characters with no control characters, and are escaped (control, bidi and
  invisible code points) when printed (N-01).
- `trust remove` only takes trust away and never touches the other store.

**Banners.** `banner_title` shows a banner unless the spec is verified by a system or user pin, so a
`--key` run always shows KEY NOT PINNED and an unsigned run UNSIGNED SPEC. The spec path in the banner is
escaped. The text and placement are M1-130's to finish.

## Plan corrections found

- docs/plan/01-spec-format.md section 4.2: "A `signed_at` more than 24 hours in the future gives a
  warning" is not built in M1. Fix: "From M2-032, a `signed_at` more than 24 hours in the future gives a
  warning, not a refusal." (SF-01)
- docs/plan/11-backlog.md, M1-134 row: add to the exit test "and the page says to compare the full
  fingerprint that `rdy verify --key` prints, never the short form in the KEY NOT PINNED banner". M1-133's
  unsigned page gets the same sentence. (SF-02)
- docs/plan/11-backlog.md: add M1-183 (below) and add it to the dependencies of M1-138. (MF-01)
- docs/plan/05-threat-model.md (mine), INV-02 test column: the FIFO and `/dev/zero` cases run for `rdy
  run`, `rdy verify` and `rdy spec sign`, plus a FIFO swapped in after the `stat` (M1-183). Surface 2
  residual risks gain AR-02. M1-183 lands both edits. The `--key` residual text of 05 Surface 2 already
  points at the full fingerprint and AR-01 (this branch).
- docs/plan/11-backlog.md, M2-032 row: add the SF-01 clause (Folds, below).

## Tickets implied

- [M1] M1-183 Read every spec through the checked non-blocking reader, and lint expiry in `spec sign` | rust-engineer | 2h | M1-126, M1-125 | a direct FIFO, a FIFO swapped in between the `stat` and the open (through a test seam), and `/dev/zero` as the spec each exit 64 within 1 s for `rdy run`, `rdy verify` and `rdy spec sign`; `rdy spec sign` of a spec with a past `expires` exits 64 with `spec_expired` before the key is opened, and no self-check error maps to exit 70; 05 INV-02 names the new cases and Surface 2 lists AR-02.

Folds (extra exit-test clauses on existing tickets):

| Existing ticket | Added clause | +h |
| --- | --- | --- |
| [M2] M2-032 SEC-46 Vendor key rotation, signed_at and serial rollback warnings | SF-01: a `signed_at` more than 24 hours after this machine's clock warns and is recorded in the result, and is never a refusal | 0.5 |
| [M1] M1-134 Sign and verify page | SF-02: the page says to compare the full fingerprint that `rdy verify --key` prints, never the short form in the banner (the same sentence on M1-133's unsigned page) | 0.25 |
| [M2] M2-107 Lock the trust store folder across load and save | N-01: `check_note` also refuses the code points `is_invisible` flags | 0.25 |

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

Must fix: 1 open (MF-01, owner M1-183). Should fix: 2 open (SF-01, SF-02). Nits: 1 (N-01). Accepted
residuals: 2 (AR-01, AR-02). This review closes when M1-183 merges; then it lists zero open must-fix
items and the M1-132 exit test is met before the 0.1.0 tag.
