# Security review of the TLS recording verifier and 03 Appendix A (M1-101)

Reviewer: security-reviewer. Authors of the reviewed code: rust-engineer (M1-092, M1-093) and check-author
(M1-099, M1-100). Date: 2026-11-17. No reviewed code was edited. This file is the exit test of M1-101.

## Scope

- The recording verifier of the probe facade (`crates/rdy-engine/src/probe/net/tls/record.rs`): the
  `ServerCertVerifier` that records both verdicts and accepts every chain, its `verify_tls12_signature`
  and `verify_tls13_signature`, the one `dangerous()` call, and the promise that no application byte is
  sent.
- `Probe::tls_chain` and its route and peer rules (`tls.rs`, `net.rs` `admit_tcp`), against ADR 0013,
  ADR 0014 decisions 2 and 3, and 05 INV-11 and INV-12.
- `net.tls_intercept` as M1-100 ships it: the pin rule (`leaf`, `ca_only`, `none`), `root_sha256` only for
  a self-issued last certificate, `expected_issuer`, and `x509-parser` on peer DER.
- The OS trust store: the live readers (`probe/live/roots.rs`), the `SSL_CERT_FILE` and `SSL_CERT_DIR`
  sources, `Probe::trust_store`, and how the report shows a path a variable named.
- 03 Appendix A against the command table in code.

Read against: 03 section 3 (`net.tls_intercept`, `net.egress`) and Appendix A, 05 "TLS" residuals, the
`system_roots` row, INV-02, INV-07, INV-11 and INV-12 and the `x509-parser` dependency entry, ADRs 0013,
0014 and 0028, and the 12-progress lines of M1-092, M1-093, M1-099 and M1-100.

Out of scope: the strict verifier of `Probe::http` beyond its separation from the recording one (reviewed
on PR #143), the proxy route (M1-097), and the Java and Node stores (M2-134).

## Commit reviewed

`ab9eeb745a194ff849489c48fbae8f8f5b7a23fd`, the head of `m1/100-tls-intercept-evidence` (PR #91, approved,
not merged). The branch `m1/101-tls-verifier-review` is stacked on that head. PR #91 does not change
`crates/rdy-engine/src/probe/net/`, `crates/rdy-engine/src/exec/` or 03 Appendix A, so the verifier and
the table are as M1-092 to M1-099 merged them to main. If PR #91 changes again before it merges, the
`net.tls_intercept` lines cited below must be checked again. The branch has main merged (8757283f); no
file cited below changed in that merge.

## Method

- Read every file on the path line by line. In `crates/rdy-engine/src/probe/`: `net/tls.rs`,
  `net/tls/record.rs`, `net/tls/strict.rs`, `admit_tcp` and `dial` in `net.rs`, `native.rs`,
  `live/roots.rs` and the open flags of `live/files.rs`. In `crates/rdy-checks-net/src/`:
  `tls_intercept.rs`, `tls_intercept/class.rs`, `tls_intercept/evidence.rs` and `family.rs`. In
  `crates/rdy-spec/src/check/net.rs`: `Sha256Hex`. The `dangerous` entries of every `clippy.toml`.
- Read the `x509-parser` 0.18.1 source for `basic_constraints`, `get_extension_unique`, the name
  `Display` and its `#![forbid(unsafe_code)]`.
- Checked the feature walls: `testing` and `loopback` stay out of the `rdy` binary (`ci.yml` tree guard,
  and `compile_error!` in `redact/mod.rs` for a release build with `testing`).
- Checked test coverage by name in `probe/net/tls/tests.rs`, `tls_intercept/tests.rs` and the
  `net.tls_intercept` env-harness fixtures, including the canary-user fixture.
- Ran `cargo test -p rdy-engine --test command_table` on this branch: 2 passed. Compared the Check column
  of Appendix A with `CommandEntry::checks` by hand, which that test does not do.
- Everything else is from code reading. The CI of PR #91 is the run record.

## Verdict

The recording verifier is sound. It records and accepts, but the server must still prove it holds the
leaf's key, and the stream never leaves the facade. Real verification lives in a separate strict
configuration that never sees the recording verifier. The pin rule, the root hash and the trust store
paths are built as ruled on PR #91. Appendix A matches the command table. No must-fix. Two should-fix
items: a promised "no revocation check" note that no report carries, and no test for the signature
check that the pin rule depends on.

## Summary

| ID | Severity | Where | One line | Status | Owner |
| --- | --- | --- | --- | --- | --- |
| SF-01 | Should fix | `crates/rdy-engine/src/probe/net/tls.rs:76`; `crates/rdy-checks-net/src/tls_intercept.rs:497` to `:504` | No report says "no revocation check", which ADR 0014, 02 and 05 promise | open | M1-096 (fold) |
| SF-02 | Should fix | `crates/rdy-engine/src/probe/net/tls/record.rs:275` to `:291`; `crates/rdy-engine/src/probe/net/tls/tests.rs:322` | No test proves the recording handshake checks the server's signature against the leaf | open | M1-184 (new, proposed; an M1-138 dependency, correction 55) |
| N-01 | Nit | `crates/rdy-checks-net/src/tls_intercept/evidence.rs:221` to `:229` | A doubled separator after the home prefix shows the user name | open | M2-134 (fold) |
| N-02 | Nit | `crates/rdy-checks-net/src/tls_intercept/evidence.rs:57`, `:71`, `:111` | "Self-signed" is a name equality, not a signature check | open | M2-136 (fold) |
| N-03 | Nit | `crates/rdy-checks-net/src/tls_intercept.rs:734` to `:737` | `root_in_os_store` is `false`, not `null`, when the store could not be read | open | M2-136 (fold) |
| N-04 | Nit | `crates/rdy-checks-net/src/tls_intercept/evidence.rs:69` | An issuer x509-parser cannot render is shown as its error text | open | M2-136 (fold) |
| N-05 | Nit | `crates/rdy-engine/tests/command_table.rs:214` to `:237` | The Appendix A test does not compare the Check column | open | M2-006 (fold) |
| AR-01 | Accepted residual | `crates/rdy-checks-net/src/tls_intercept.rs:641` to `:647`; `tls_intercept/evidence.rs:158` to `:174` | A middlebox this machine trusts can append a pinned public CA and hold a CA pin at a warning | accepted for M1 | M2-135 |
| AR-02 | Accepted residual | `crates/rdy-checks-net/src/tls_intercept/evidence.rs:69` | `expected_issuer` reads unescaped name text, so one value can look like several parts | accepted | 03 already says it is unauthenticated |

## Must fix

None.

## Should fix

**SF-01. No report says "no revocation check".**
- Problem: ADR 0014 decision 3 says "The report says 'no revocation check'". 02 ("System roots") and 05
  ("TLS") say the same. The facade defines the wording as `REVOCATION_NOTE` (`tls.rs:76`), but no check
  uses it. `net.tls_intercept` passes a `public` chain and `net.egress` passes a TLS stage with no note,
  so a reader can take a pass to mean the leaf is not revoked. This is a disclosure gap, not a hole: a
  revoked certificate with a valid chain is outside what M1 promises to detect.
- Fix: every `net.egress` result with at least one TLS stage, and every `net.tls_intercept` result with
  at least one chain, carries the note `REVOCATION_NOTE` once per result, not once per endpoint or host.
  A test asserts it on a public chain for each.
- Owner: fold into M1-096 (check-author), which already opens the `net.egress` result. Add M1-100 to its
  dependencies for the `net.tls_intercept` half.

**SF-02. No test proves the server must hold the leaf's key.**
- Problem: the recording verifier accepts every chain (`record.rs:251` to `:273`). The only thing that ties
  the chain to the server is the handshake signature, which `verify_tls12_signature` and
  `verify_tls13_signature` hand to `rustls::crypto` (`record.rs:275` to `:291`). The pin rule rests on it:
  `leaf` passes because the leaf is "the one certificate the server proves it holds the key of"
  (`evidence.rs:78`). The code is right today. But if either method returned
  `HandshakeSignatureValid::assertion()`, every test would still pass, and any server could replay a
  pinned vendor leaf and pass the pin. The facade asserts zero application bytes on a trusted chain
  (`tests.rs:322`) and on an unknown-CA chain
  (`the_live_backend_handshakes_on_loopback_and_reads_the_real_store`, `tests.rs:764` to `:813`), but
  `net.tls_intercept`'s unknown-CA case (`tls_intercept/tests.rs:351`) does not.
- Fix: a loopback server mode that presents a generated chain but signs with another key (a
  `ResolvesServerCert` that returns a `CertifiedKey` of leaf A and key B), on TLS 1.2 and on TLS 1.3.
  `Probe::tls_chain` returns `NetFailure::TlsFailed` and no chain, and `net.tls_intercept` with that
  leaf pinned gives `not_tested`, never `leaf`. Add the zero-application-bytes assertion to the
  unknown-CA case of `tls_intercept/tests.rs`.
- Owner: new M1-184 (rust-engineer, 1 h, proposed below), an M1-138 dependency (correction 55). It stays
  should-fix, because the code is right today, but the leaf pin is now the advice for blocking (AR-01)
  and the one property it rests on has no test, so 0.1.0 does not ship without it.

## Nits

**N-01. A doubled separator shows a user name.** `collapse_usual_home` takes the text up to the next
separator after the home prefix as the user name (`evidence.rs:221` to `:229`). With two slashes after
`home` in `SSL_CERT_FILE`, the next segment is empty, so the report shows `~` followed by the user name
and the rest of the path. The operator chose the odd path, and it is their own name. Fix: skip repeated
separators after the prefix. Fold into M2-134, which reuses this function for `NODE_EXTRA_CA_CERTS`.

**N-02. "Self-signed" is a name check.** `self_signed` is true when the subject bytes equal the issuer
bytes (`evidence.rs:71`); the signature is not checked. A server can send a last certificate that names
itself as issuer and is no root. `root_in_os_store` is a hash lookup, so it is still right, but the field
name (`evidence.rs:57`), the doc at `:111` and 03 say "self-signed". Fix: say "self-issued (subject
equals issuer; the signature is not checked)". Fold into M2-136, which replaces this logic.

**N-03. `root_in_os_store` is `false` for a store that did not read.** It is computed as
`store.missing.is_none() && store.contains(..)` (`tls_intercept.rs:734` to `:737`), so a store that is
`Unreadable` or `Overridden` gives `false`, which reads as "not in the store". Fix: `null` unless the store
was found. Fold into M2-136.

**N-04. An unrenderable issuer is shown as error text.** x509-parser's name `Display` writes
`<X509Error: Invalid X.509 name>` when a value does not render, and `names_of` keeps that as the issuer
(`evidence.rs:69`). It fails closed for `expected_issuer`, but the report shows a fake issuer and the
"issuer could not be read" wording does not apply. Fix: treat that case as `None`. Fold into M2-136.

**N-05. The Appendix A test does not compare the Check column.** `command_table.rs` compares program,
arguments, OS, timeout, exit codes, cap and path, not `CommandEntry::checks`. By hand all 14 rows match,
with two aliases: `gpu.*` covers `gpu.fabric` and `gpu.devices`, and the Check cell of row 14, "engine
Root probe (02)", is `engine.root` in the table (`table.rs:875`). Fix: compare them, with `gpu.*` as a
wildcard and "engine Root probe (02)" mapped to `engine.root`. Fold into M2-006, which next edits the
table.

## Accepted residuals

**AR-01. A CA pin can be held at a warning.** The pin rule is as ruled on PR #91 (SEC-100-1): `leaf`
passes; `ca_only` (a later certificate that x509-parser reads, at most 16 KiB, with exactly one
basicConstraints and `cA` true; `basic_constraints` uses `get_extension_unique`, so a duplicate is an
error and not a CA) is partial and a warning; everything else blocks. `Verdict::level` keeps a block
from the class (`tls_intercept.rs:641` to `:647`). The gap: a middlebox this machine trusts gives class
`machine_only`, a warning when `forbid_interception` is false. It can append the vendor's public pinned
CA certificate after its own leaf, and the pin becomes `ca_only` instead of `none`: a warning instead of
a block, exit 1 instead of 2. The report still names the class, the issuer and "rdy cannot yet prove it
is in the verified path", and the verdict is never READY. M2-135 records the verified path and closes it.
Until then a vendor who wants a block pins the leaf or sets `forbid_interception`. 05 "TLS" says so now
(this branch), and 03 and the network docs page should say it too (Plan corrections found).

**AR-02. `expected_issuer` reads unescaped name text.** x509-parser joins parts with `, ` and writes `=`
and `,` inside a value as they are, so one CN value can hold text like `x, CN=Acme Issuing CA` and match
`CN=Acme Issuing CA$`. A middlebox can copy the real name anyway, and 03 already says the rule is an
unauthenticated name match and only the pin proves anything. Accepted.

## What holds, by area

**Recording verifier (M1-092, M1-099).**
- `Recording` and `recording_client` are `pub(super)` in the facade. `recording_client` is the one
  place that calls `dangerous()` (`record.rs:233` to `:237`, with `#[expect]`). Every `clippy.toml`
  bans `ConfigBuilder::dangerous` and `ClientConfig::dangerous`, and no check crate may depend on
  `rustls` (05 dependency entry, `ci/check-crate-deps.toml`).
- Inside `verify_server_cert` it runs two real `WebPkiServerVerifier`s, OS and bundled, with the
  handshake's own `now` and server name, keeps both verdicts and the chain as sent, and returns
  `assertion()`. Both verdicts are what the strict verifier would decide on the same input.
- The handshake signature is checked with ring's algorithm set for TLS 1.2 and TLS 1.3 (SF-02 is about
  the missing test, not the code). A signature that fails ends the handshake, and the recorded chain is
  dropped with the recorder: `tls_chain` returns `TlsFailed`, never a chain.
- No application data: no client certificate, resumption off (so no early data), and after the
  handshake only `close_notify` and the write shutdown (`tls.rs:244`). The call returns a `TlsChain`
  of DER bytes and verdicts, never the stream.
- The strict configuration of `Probe::http` (`strict.rs`) uses `with_webpki_verifier` on the same
  `Trust` and never the recording verifier. A chain it refuses sends no request byte.
- The test clock and the extra public root exist only under `testing`. A release build with `testing`
  does not compile, and CI checks the `rdy` normal tree for `testing` and `loopback`.

**Routes and peers (ADR 0014 decision 2, INV-11, INV-12).**
- `tls_chain` runs `admit_tcp` before anything opens: no network refuses; `PeerClass::SpecHosts` must
  be declared, and `PeerClass::Proxy` too for `Route::ViaProxy`; host and port must be the check's own
  spec host; a forbidden literal is refused. `dial` refuses a forbidden resolved address.
- `net.tls_intercept` declares only `SpecHosts` and always uses `Route::Direct`. Its host set is its
  own `hosts`, or the TLS endpoints of the spec's `net.egress` entries, capped at 64, and the family
  gives the probe exactly that set (`family.rs:47` to `:53`).
- SNI is the spec host and nothing else; an address host sends none.
- ADR 0013: a host that gave no chain is `not_tested` and makes the result partial; no host tested, or
  none to test, is a warning and never a pass; `ca_only` is never a pass.

**Pin and root hash (M1-100).**
- `Sha256Hex` accepts only 64 lowercase hex digits, the form the check compares with. At most 16 pins.
- The leaf is `certs[0]`, the certificate the handshake signature is checked against. Only the first 32
  certificates are hashed; a later one beyond them never matches. A root the server did not send never
  matches.
- `root_sha256` and `root_hash` are set only when the last certificate names itself as issuer
  (`evidence.rs:126` to `:137`), else null, as the M1-100 row says (N-02 on the wording). `last_sha256`
  is always the last certificate sent.

**x509-parser on peer DER.**
- Version 0.18.1, default features off (no `verify`), `#![forbid(unsafe_code)]`, a direct dependency of
  `rdy-checks-net` only. It parses at most the leaf, the last certificate and the pinned later ones, and
  skips any over 16 KiB. A rustls handshake message caps the whole chain near 64 KiB.
- A proptest feeds arbitrary chains and text (`evidence_never_panics_on_arbitrary_chains`). A panic
  would still be isolated: the scheduler turns a panicking check into its own result (`sched.rs:476`).
- Names are cleaned (control, invisible and reordering code points, backticks) and cut at 160 characters
  before any report. `expected_issuer` sees at most 1024 characters and is compiled by the spec's
  linear-time pattern rules. No peer text reaches a `Fix:` line.

**Trust store reads and the variable sources.**
- Unix reads PEM through the facade's file rules: the denylist on the real path, `O_NONBLOCK` and
  `O_NOCTTY`, regular files only, at most 2048 files of a directory and 8 MiB in all, `CERTIFICATE`
  blocks only, at most 1024 roots of 16 KiB. The probe caps every backend's answer again.
- macOS and Windows with neither variable set use `rustls-native-certs` inside `catch_unwind`. With a
  variable set, macOS reads PEM through the same rules and Windows fails as `Overridden`, so that crate
  never reads a file without the rules.
- The action log holds the `system_roots` call, never a path or a certificate. The tracing warnings
  hold counts only.
- A source from `SSL_CERT_FILE` or `SSL_CERT_DIR` shows the variable and the path with control
  characters removed and the home folder as `~`. `HOME` is declared, read only when such a source
  exists, and never reported. The canary-user fixture shows no user name in the result. The residuals
  (a user name outside a home place, the invoking user's home under `sudo`, and a variable that names
  any readable file) are in the 05 `system_roots` row.

**03 Appendix A and the command table (ADR 0028).**
- The table is `crates/rdy-engine/src/exec/table.rs`, held equal to Appendix A by
  `crates/rdy-engine/tests/command_table.rs` (program, arguments, OS, timeout, exit meanings, stdout cap,
  path). It passed on this branch. `run` is the only public command runner and calls `validate`, so a
  command that is not in the table cannot start.
- The checks that run commands today (`host.time_sync`, `host.firewall`, `host.container_runtime`) build
  them from the table with `cmd_for`. `net.tls_intercept` runs no command; its fix text names
  `update-ca-certificates`, `update-ca-trust`, `keytool`, `apk` and `zypper`, all on the fix-text
  allow-list, and its `openssl s_client` hint is text only.

## Plan corrections found

- docs/plan/03-check-catalog.md, `net.tls_intercept` Source line: "one from `rustls-native-certs`"
  is not what M1 builds. Fix: "one on the OS roots of `NativeCall::SystemRoots` (PEM bundles through the
  facade on Linux, and on macOS when `SSL_CERT_FILE` or `SSL_CERT_DIR` is set; `rustls-native-certs` on
  macOS and Windows when neither is set)". The "Shared stack" paragraph of section 3 says the same and
  needs the same fix.
- docs/plan/03-check-catalog.md, `net.tls_intercept` Thresholds: add "Until M2-135, a CA pin is at best a
  warning, and a middlebox this machine trusts can append the pinned CA, so pin the leaf or set
  `forbid_interception` to block." (AR-01)
- docs/plan/11-backlog.md, M1-096 row: add the SF-01 clause (Folds, below) and M1-100 to its dependencies.
- docs/plan/11-backlog.md: add M1-184 (below), and add it to the dependencies of M1-138 (correction 55).
- docs/plan/11-backlog.md, M1-116 row: the network page says the AR-01 sentence (Folds, below).
- docs/plan/05-threat-model.md (mine), "TLS" bullet: AR-01 is recorded, and "the report says so" now says
  "from M1-096" (SF-01), on this branch.

## Tickets implied

- [M1] M1-184 The recording handshake refuses a server without the leaf's key, and an untrusted chain gets zero application bytes | rust-engineer | 1h | M1-100 | a loopback server that presents a generated chain but signs with another key fails `Probe::tls_chain` with `NetFailure::TlsFailed` and returns no chain, on TLS 1.2 and on TLS 1.3; `net.tls_intercept` with that leaf pinned gives `not_tested`, never `leaf`; and an unknown-CA chain costs the loopback server zero application bytes in `net.tls_intercept`'s unknown-CA case. An M1-138 dependency (correction 55). (M1-184 is the next free id on 2026-11-17; the coordinator assigns the final one.)

Folds (extra exit-test clauses on existing tickets):

| Existing ticket | Added clause | +h |
| --- | --- | --- |
| [M1] M1-096 net.egress HTTP stage and failure classes | SF-01: every `net.egress` result with a TLS stage and every `net.tls_intercept` result with a chain carries the note `no revocation check` (`REVOCATION_NOTE`) once per result, not once per endpoint or host, and a test asserts it for each on a public chain (adds M1-100 as a dependency) | 0.25 |
| [M1] M1-138 Tag and release 0.1.0 | SF-02: M1-184 joins the dependencies (correction 55). The leaf pin is now the advice for blocking, and the signature check it rests on has no test until M1-184 lands | 0 |
| [M1] M1-116 Check family renderer and the host, network and Kubernetes pages | AR-01: the network page says a CA pin is at best a warning until M2-135, so pin the leaf or set `forbid_interception` to block | 0.1 |
| [M2] M2-134 net.tls_intercept reports the Java and Node stores | N-01: a doubled separator after any usual home prefix does not show the user name | 0.1 |
| [M2] M2-136 net.tls_intercept finds the real trust anchor | N-02: "self-issued" wording; N-03: `root_in_os_store` is null unless the store was found; N-04: an issuer x509-parser cannot render is `None` | 0.25 |
| [M2] M2-006 Windows job objects | N-05: the Appendix A test also compares the Check column with `CommandEntry::checks`, with `gpu.*` as a wildcard and "engine Root probe (02)" as `engine.root` | 0.1 |

## Residuals already recorded elsewhere

| Residual | Where it is recorded | Owner |
| --- | --- | --- |
| No revocation check in M1 (the note is SF-01). | ADR 0014 decision 3, 05 "TLS" | accepted |
| A CA only in NSS or a Java keystore is invisible on Linux. | 05 "TLS", ADR 0014 consequences | M2-134 reports the Java and Node stores |
| webpki refuses no-SAN and SHA-1 certificates that old appliances issue; the class is `tls_untrusted`. | 05 "TLS" | accepted |
| `SSL_CERT_FILE` and `SSL_CERT_DIR` may name any file the denylist allows. | 05 `system_roots` row | accepted |
| A user name outside a home place, or the invoking user's home under `sudo`, still shows in a variable's path. | 05 `system_roots` row | accepted |
| `rustls-native-certs` unwraps in its Windows reader; caught, one `Unreadable` verdict. | 05 dependency entry (SEC-133-9) | accepted |
| `root_sha256` is null when the server does not send the root. | 03 M1-100 build note, correction 52 | M2-136 |
| A pin on a later certificate is partial until the verified path is kept. | 03 Thresholds, correction 52 | M2-135 |
| A host behind a proxy is not tried. | 03 M1-099 build note | M1-097 |
| The env harness `Timeout` class for `net.tls_intercept`. | 12-progress M1-100, correction 52 | M1-179 |

Must fix: 0 open. Should fix: 2 open (SF-01, SF-02; M1-184 for SF-02 is an M1-138 dependency). Nits: 5
(N-01 to N-05). Accepted residuals: 2 (AR-01,
AR-02). Appendix A matches the command table. The review is of the PR #91 head, so the M1-101 exit test
holds once PR #91 merges unchanged.
