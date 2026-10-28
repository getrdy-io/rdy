# Security review of 01-spec-format.md and the rdy/v1 schema files

Reviewer: security-reviewer. Author of the reviewed files: rust-architect. Date: 2026-10-28.
Reviewed: `docs/plan/01-spec-format.md`, `crates/rdy-spec/schema/spec.v1.schema.json`,
`crates/rdy-spec/schema/result.v1.schema.json`, `crates/rdy-spec/schema/README.md`.
Checked against 05-threat-model.md (INV-01 to INV-20, Surface 2), ADRs 0001, 0002, 0005, 0007, 0008,
0012, 04-bundle-and-redaction.md section 3.1, and my ADR review. No reviewed file was edited.

## Verdict

**Changes required.** Must fix: 5. Should fix: 14. Nits: 14.

The core is right. The order is verify, then parse, on the raw bytes, with `allow_legacy = false`, a
fixed `rdy-spec-v1` trusted-comment prefix and the 1 MiB, 4 KiB and 256 KiB caps. A root run reads only
`/etc/rdy/trust.yaml` (as far as the Unix rules go). `--allow-unsigned` covers only a missing signature.
A bad or unpinned signature exits 64 even with the flag. Unknown top-level, `metadata` and `bundle` keys
exit 64, and unknown check ids and fields skip and count as not run. The `bundle:` block is shape-only
in M1. The writer escapes `<`, `>` and `&` in the file itself, so the HTML copy is the same bytes. The
five must-fix items are gaps around those rules, not a redesign.

## How I checked the examples

`python3 -I` with `jsonschema` 4.26.0 (`Draft202012Validator`) and PyYAML 6.0.1:

- Both schema files pass `check_schema` for draft 2020-12.
- The 7.1 YAML block is byte-identical to `examples/specs/acme-platform.yaml`. SHA-256 `a56b97c8...e07c`
  and 1981 bytes both match. It validates.
- The 7.2 and 7.3 result blocks validate. The author's claim holds.
- `acme-quickstart.yaml` and `acme-inference-gpu.yaml` validate. `acme-airgap-host.yaml` fails on
  `via_proxy: never` and `acme-k8s-only.yaml` fails on `can_i`, as the doc's Plan corrections say.
- Hostile cases. Rejected: an unknown top-level `upload:`, `metadata.allow_unsigned`, `bundle.upload`,
  `mn` in `host.memory`, a missing `id`, a dotted product, `needs` together with `access_modes`.
  Accepted: `custom.exec` with `argv` (correct: skipped as `not_in_build` in M1), an unreserved family
  `upload.now`, a URL target with userinfo, `expires: tomorrow`, `timeout: 999d`, `file:../../etc/shadow`
  in `collect`, a `redact_patterns` regex that matches the empty string, `band: .nan`. On the result
  side, the schema accepts a 5 MiB `message`, `state: unsigned` with `allow_unsigned: false`, and
  `verdict: ready` with two block checks. Findings below cover the ones that matter.

## Must fix

**MF-01. 4.8, `spec_unsigned` fix line. The tool itself suggests `--allow-unsigned`.**
- Problem: the fix line is "ask the vendor for the .minisig file, or run with --allow-unsigned". 4.7 in
  the same doc says "no hint ever suggests the flag". 05 Appendix B T2 says the same. Signature stripping
  plus a nudge is the T2 attack: an attacker deletes the `.minisig`, and rdy then tells the customer how
  to run the attacker's spec.
- Fix: change it to `fix: ask the vendor for acme-platform.yaml.minisig and put it next to the spec.`
  Add a second line that names no flag: `If you wrote this spec yourself, see https://docs.getrdy.io/unsigned`.
  The flag is documented only on that page. Add to the `rdy verify` ticket's exit test: no
  `ErrorOutput.fix` and no stderr line for any 4.8 code contains `--allow-unsigned`.

**MF-02. 4.3, last sentence of the refusal paragraph. Root reads the invoking user's trust file to word a hint.**
- Problem: "When root finds no key but the invoking user's file has one, the hint says ...". To know
  that, a root process must open and parse a file the user controls (located through `SUDO_USER` or
  `HOME`). That breaks INV-04 ("with euid 0, only the system store is read"). It is also a root read
  through a user-planted symlink (`~/.config/rdy/trust.yaml -> /etc/shadow`), and its parse errors can
  echo file content.
- Fix: as euid 0, never stat, open or parse any user path. Print the root hint every time a root run
  finds no matching key: `as root, rdy reads only /etc/rdy/trust.yaml. If you pinned this key as a normal
  user, pin it for root too: sudo rdy trust add acme-platform --key <file>`. Add to the trust store
  ticket's exit test: under `strace -e trace=openat,stat,newfstatat`, a root run with `SUDO_USER` and
  `HOME` set touches no path under the user's home.

**MF-03. 4.3, Windows row. The system store's refusal rules are Unix-only.**
- Problem: the refusal rules are symlink, "not owned by root", and group or world writable. They mean
  nothing on Windows. By default, `BUILTIN\Users` can create folders and files under
  `C:\ProgramData`. A non-admin user can pre-create `C:\ProgramData\rdy\trust.yaml` with their own
  key, and an elevated run then trusts it. That is MF-02 of the ADR review again, on Windows. 05
  requirement 3 says "writable only by Administrators and SYSTEM". 01 does not carry it.
- Fix: in 4.3, for elevated Windows runs, refuse the store (`trust_store_insecure`) unless:
  - the file and `%ProgramData%\rdy` are owned by `Administrators` or `SYSTEM`;
  - their DACLs grant write, delete or `WRITE_DAC` to no other principal (CREATOR OWNER included);
  - neither one is a reparse point.

  `rdy trust add`, run elevated, creates the directory with a protected DACL (Administrators and SYSTEM
  full control, Users read). Add a Windows CI case: a directory pre-created by a non-admin user is
  refused.

**MF-04. 2.8 and the `Bundle.redact_patterns` schema description. A vendor pattern can switch off part of a built-in rule.**
- Problem: 2.8 promises "a spec can add redaction and never remove it". 04 section 3.1 resolves
  overlapping spans by priority ("keeps the highest priority ... where they overlap"), and custom
  patterns (priority 6) rank above emails (7) and the entropy rule (9). If a losing span is dropped,
  `redact_patterns: [{name: x, regex: "@"}]` turns `jdoe@corp.example` into
  `jdoe[REDACTED:custom.x:..]corp.example`, and the email rule never fires. A pattern that matches one
  character of a high-entropy token does the same to the entropy rule. Revision 0 freezes this field
  now, so the rule has to be part of the contract now.
- Fix: one sentence in 2.8 and the schema description, and the same rule in 04 section 3.1: "Overlapping
  spans merge. The replaced region is the union of every overlapping span, and priority picks only the
  placeholder's rule name. A custom pattern can never leave a byte unredacted that the built-in rules
  alone would redact." Also reject custom patterns that match the empty string (nit N-07). M2 corpus
  case: every built-in positive, run with a set of hostile custom patterns (`@`, `.`, the first byte of
  the secret, the key name), still has zero survivors.

**MF-05. 4.3 and 4.4 `--key`, 6 content item 2. A one-run key gives a clean `verified` report with no warning.**
- Problem: `rdy run --key attacker.pub` makes any attacker-signed spec `signature.state: verified`. The
  attacker controls the product, the `fix` texts and the endpoints. The banner only shows for
  `unsigned`. "Run it with `--key acme.pub`" is as easy to paste from an email as `--allow-unsigned`,
  and the result looks better than an honest unsigned run. Only `trust_source: flag`, buried in section
  10 of the HTML, gives it away.
- Fix:
  - When `trust_source` is `flag`, print a banner on stderr before any check runs, above the verdict
    line, and on every printed page of the HTML:
    `WARNING: KEY NOT PINNED` / `This spec was checked with a key given on the command line (fingerprint
    <sha256>). rdy cannot tell whose key that is.` The banner rule is "show it unless `state` is
    `verified` and `trust_source` is `system` or `user`".
  - `--key` is argv only, like `--allow-unsigned` (INV-05).
  - No hint suggests `--key`.
  - Add both banners to the `rdy verify` ticket's golden test.

## Should fix

**SF-01. 4.4 and 5.5. Say "one buffer" outright.** Step 1 reads the file. Nothing says that the
verified, parsed and SHA-256'd bytes, and the "copy of the verified spec" in the output dir, are the same
in-memory buffer. A root run on a spec in a user-writable directory is then open to a swap between
verify and parse, or between run and copy. Fix: "the spec and sidecar are each read once, into memory.
Verify, parse, hash and the copy into the output dir all use that buffer. rdy never reopens the path."
The same goes for `rdy spec sign`: lint and sign use one buffer. Test: a FUSE or `inotify` fixture swaps
the file after the first read, and the run still uses and records the first bytes.

**SF-02. 4.3 and 5 `signature`. The key id is not an identity.** A minisign key id is 8 random bytes
chosen at keygen and stored inside the key blob. It is not a hash of the public key, so anyone can mint a
key with the vendor's key id. Fix:
- The fingerprint shown by `trust add`, `verify` and the reports is SHA-256 over the 32-byte ed25519
  public key. Add `signature.key_fingerprint` to the result schema.
- Lookup matches on the full public key after the id preselects.
- `trust add` refuses a second key with the same id for the same product.
- 4.3 says `trust add` and `--key` refuse small-order and malformed keys (05 requirement 2).

**SF-03. 2, parser limits. YAML tags, directives and non-finite floats are not covered.** ADR 0001
lists duplicate keys, merge keys, anchors, aliases, depth and documents. The doc copies that list. It
does not cover explicit tags (`!!binary`, `!custom`), `%YAML` or `%TAG` directives, or `.inf` and
`.nan`. `band: .nan` validates against the schema, and in Rust a NaN comparison is false whichever
way it is written, so a band check can pass by accident. Fix: add to section 2 and to the "Wire
serde-saphyr" exit test: any tag or directive, and any non-finite float anywhere, exits 64 with line and
column.

**SF-04. result schema, all strings and arrays. The size caps of 5.2 and 5.5 are prose only.** The portal
validates customer-supplied JSON and HTML imports against this file. Without `maxLength` and
`maxItems` it accepts a 5 MiB `message`. Fix: put the caps in the schema: `message` 1 KiB, `fix` and
`builtin_fix` 4 KiB, `notes` 20 items of 1 KiB, `actions` 5000 items, every other string 4 KiB. State in
the description that the portal also enforces the 2 MiB document cap before it parses.

**SF-05. 5 `identity`, result schema `Identity.kube`. The fields that 05 SEC-24 and ADR review SF-11 need are missing.** The
report must show any kubeconfig exec plugin that ran and an `insecure-skip-tls-verify` context. Fix:
add `identity.kube.exec_plugin` (program base name, or null) and `identity.kube.insecure_tls`
(boolean), and show both in HTML section 10.

**SF-06. 5.1, exclusion list. The doc says no IP addresses, but the action log has them.**
`actions[].addr` (connect) and `actions[].server` (dns) carry IP addresses outside any check's
`observed`. The docs security page (SEC-31) will be built from this list, so the claim must be exact.
Fix: rewrite the sentence as "IP addresses appear only in check `observed` data, in `connect.addr` and in
`dns.server`". Keep the HTML notice in item 3, which already says "addresses".

**SF-07. 5.4, action log cap. A spec can push the network and kube entries out of the log.** The cap is
5000 entries, "later actions were dropped", and the size cap truncates the log first. A spec with 256
`host.*` checks that each coalesce 200 reads produces more than 5000 entries before the egress checks
run. The record of "what did it do" then loses exactly the entries a reviewer wants. Fix:
- `exec`, `connect`, `tls`, `http`, `dns`, `lookup` and `kube` entries are never dropped. They are
  bounded already, by 64 endpoints and the fixed command set.
- Truncation drops `read`, `read_dir` and `stat` first.
- Add `actions_dropped: {kind: count}` so the reader knows what is missing.

**SF-08. 6, embedded JSON, against 05 Appendix A T3. "No `safe`" and "exact bytes" conflict.** askama
autoescapes `"` inside `<script>` unless the value is marked safe, and that breaks both the JSON and the
hash. Fix: the 5.5 writer returns an `HtmlSafeJson` newtype, which is the only type the templates render
unescaped. It is built only by the writer, which guarantees there is no `<`, `>` or `&`. A CI grep keeps
`|safe` out of every template. I will change 05 T3 to "one audited exception". Exit test: the
`data-sha256` attribute equals the SHA-256 of the `.json` file in the golden pair.

**SF-09. 2.6 and 6, fix label. "From acme-platform" uses a name the spec chose.** Under
`--allow-unsigned` or `--key`, `metadata.product` is attacker-chosen, and the label lends vendor
authority to text such as "run curl ... | sudo sh". 05 Appendix B S1 says output never shows a vendor
name from the spec. Fix: label with the product only when `state` is `verified` and the key is pinned
(`trust_source` `system` or `user`), because the product is then bound to the pin. Otherwise label it
"From the spec file (not verified)". Do the same in the terminal.

**SF-10. 4.7, "a spec with no signature". Define "absent".** Fix: unsigned means no `--sig` was given
and opening `<spec>.minisig` returned not-found. Permission denied, a directory, a dangling symlink, an
empty file, or a `--sig` path that does not exist all exit 64 (`spec_signature_invalid`, or `usage` for
`--sig`), even with the flag.

**SF-11. 2.8, `bundle` from an unsigned or flag-key spec (M2).** In M2, the spec's `collect` list
decides what files root reads and packs. Fix: state now that `rdy bundle` ignores the spec's `collect`
and `redact_patterns` unless the spec is verified with a pinned key, the same rule ADR 0005 applies to
`custom.exec`. It then uses the built-in collector set and says so. Also say that `rdy run` never
collects, whatever the block says.

**SF-12. spec schema `Target`. A URL target can carry credentials.** `https://user:pass@host/` is
valid. rdy would send Basic auth to a host the spec names, and the target is echoed in `observed` and
`expected`. Fix: reject userinfo in `Target` (`^https?://[^/@\s]+(/[^\s]*)?$` for the URL form) and say
in 2.6 that specs never carry credentials. Strip fragments too, and keep the query out of the action log
as now.

**SF-13. 5.1, `host_id` on macOS. `kern.uuid` is the kernel build UUID, not a machine id.** It is
shared by every Mac on the same macOS build and changes on update. So `host_id` merges different hosts
and splits one host. Fix: use `IOPlatformUUID` through `ioreg -rd1 -c IOPlatformExpertDevice`, run by the
command runner with a fixed argv (no IOKit FFI, INV-18), or use `null` on macOS in M1. Also compute it as
HMAC-SHA256 with key `rdy-host-id-v1 || product`, as systemd's machine-id guidance asks of applications.

**SF-14. 2.5 open question: should `spec sign` refuse unknown fields in a known check?** Yes. The signer
is the vendor, and a typo signed once becomes a skipped check on every customer box, and a NOT READY
nobody can fix. Fix: `spec sign` errors on `unsupported_spec` and on `unknown_check` in a built-in family.
`not_in_build` stays a warning. `spec lint` keeps warnings.

## Sensitive fields in the result, and M1 redactor coverage

M1 rules (04): URL userinfo, auth headers and cookies, AWS keys, PEM private keys, kubeconfig credentials,
`rdy_st_` tokens, secrets by key name. Emails, JWTs, IPs and custom patterns are M2.

| Field | Why sensitive | M1 redactor |
| --- | --- | --- |
| `host.hostname` | internal naming | no, kept by design; M2 replace option |
| `host.host_id` | stable per host and product, a tracking id | n/a, derived, never redacted |
| `host.kernel`, `host.os.*` | patch level, recon | no, by design |
| `identity.user` | local login name | no |
| `identity.kube.context`, `.server`, `run.options.kube_context` | cluster names, internal API URL | userinfo only |
| `identity.kube.user` | can be an email (managed clusters) or a cloud ARN | **no** in M1 (emails are M2) |
| `proxy.https`, `proxy.http` | internal proxy host | yes, userinfo (also stripped at the source) |
| `proxy.no_proxy` | internal domains and CIDRs | no |
| `capabilities[].detail` | free text; the 7.3 example carries an AWS account id and instance id in an ARN | key-shaped secrets only; account ids no |
| `checks[].observed` | IPs (dns answers), CA subjects, mount points, port owners, security agent inventory, SELinux denial lines, node names | key-shaped secrets only |
| `checks[].message`, `notes`, `partial.note`, `actions[].error` | can embed OS and peer error text | key-shaped secrets only |
| `actions[].path` | paths can name users and products; home becomes `~` | no |
| `actions[].argv` | can hold spec values and tokens | yes, every M1 rule |
| `actions[].addr`, `actions[].server` | IP addresses | no (see SF-06) |
| `actions[].url` | paths can hold tokens; query dropped | userinfo yes; path tokens only if key-shaped |
| `signature.trust_note` | the customer's own note, sent to the vendor | no (N-11) |
| `redaction.by_rule` | counts reveal that a secret type exists on the box | n/a, counts only |
| `spec.file_name` | can name the customer | no |

Environment values: excluded, apart from the proxy settings. `env` actions record the variable name
only. No result field holds an environment value. That matches INV-15 as long as the 04 ticket "Apply the
redactor to every Report string before return" covers the list above. The bare-JWT gap in kube error
text is the one M1 risk I would close early. Recorded as a decision below, not a finding.

## Nits

- **N-01. 4.2.** Write the trusted comment as a full regex:
  `^rdy-spec-v1 product=[a-z0-9][a-z0-9-]{0,62} signed_at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`,
  with no trailing whitespace or CR. Warn when `signed_at` is more than 24 hours in the future.
- **N-02. 3.3.** In v2, the comment prefix must match `apiVersion` (`rdy-spec-v2` for `rdy/v2`), so a
  v1 signature can never vouch for a v2 body.
- **N-03. 3.2 reader table.** Add: an unknown `signature.state` or `trust_source` counts as unverified,
  and the banner shows.
- **N-04. spec schema `Metadata.expires`.** `format` is annotation-only in 2020-12, and `tomorrow`
  validates. Add a pattern ending in `Z`.
- **N-05. spec schema `Check`.** Add `"type": "object"`. Today, non-object entries are rejected only
  because every `if` passes vacuously.
- **N-06. spec schema `Bundle.collect`.** Use `if`/`then` per kind so that `file:` needs an absolute
  glob and `journal:` a `Duration`.
- **N-07. `redact_patterns`.** Reject a regex that matches the empty string, and compile every pattern
  in `spec lint` and `spec sign` in M1, so a bad pattern fails before it ships.
- **N-08. spec schema `timeout`.** The 1s to 60s range is prose only. Say whether out of range is
  `unsupported_spec` or exit 64. I suggest `unsupported_spec`.
- **N-09. 2.2 `annotations`.** Add: "rdy never changes behaviour because of an annotation. rdy-cloud
  treats annotations in a result as customer-reported and never routes or authorizes on them."
- **N-10. 3.2.** "Uses `verdict` as written, never recomputes it." Keep that for display, but have
  the portal recompute from known statuses and flag a mismatch as "inconsistent report". It costs
  nothing and catches naive edits.
- **N-11. 4.3.** Tell the customer at `trust add --note` that the note appears in every report.
- **N-12. result schema `Signature`.** Add `if state == unsigned then run.options.allow_unsigned ==
  true`, and `if state == verified then key_id, product, signed_at required`. Also add `fix_source: null`
  on `pass`.
- **N-13. 6 Data.** `rdy report` "re-renders to the same bytes, after running the redactor". If the
  redactor changes anything, the bytes differ. Say "same bytes when the input was written by rdy".
- **N-14. 2.3 `CheckId`.** An unreserved family (`upload.now`) gets `not_in_build` with "install a newer
  rdy". Give it `unknown_check` with "no rdy has this family", which is still forward compatible.

## Plan corrections found

- 01, 2.7: "threat model INV-13 reject the dry-run POST". The kube guard is INV-14. INV-13 is net bodies.
- 01, 5.4: "Threat model R1 and INV-06". The action log completeness test is INV-07 (SEC-17). INV-06 is
  the parser rules.
- 01, 5.1 `host.hostname` "after redaction" (schema too): no M1 rule matches a hostname. Say "kept
  as is. An M2 option replaces it."
- 05 (mine), INV-06: I accept 01's correction. Unknown ids and fields count as not run, and a
  block-severity one gives NOT READY. I will apply it.
- 05 (mine), Surface 2: I accept removing `--trust-key`. I will apply it, and add the `--key`
  banner from MF-05 to requirement 4.
- 05 (mine), Appendix A T3: "no `safe`" becomes "one audited `HtmlSafeJson` exception" (SF-08).
- CLAUDE.md rule 3 still says the flag runs tampered specs. That is open since the ADR review. 01 4.7
  and ADR 0002 decision 7 are right, and CLAUDE.md is stale.

## Decisions needing an ADR

- `rdy trust add --fingerprint <sha256>` (ADR 0002 amendment). In M1, the spec, the `.minisig` and the
  `.pub` usually travel in one email, which is the self-certifying pattern of 05 S3, already in M1. A
  fingerprint the vendor publishes on its docs page lets `trust add` fail on a swapped key without a
  human comparing hex. Conservative choice until decided: `spec sign` prints the fingerprint in the
  line it tells the vendor to send, and `trust add` asks the user to compare it.
- macOS `host_id` source: `ioreg` exec, IOKit FFI (unsafe, INV-18) or `null`. Conservative: `null` in
  M1.
- Move the `jwt` rule from M2 into M1 (04 owns it). A bare service account token in a kube error string
  is not caught by any M1 rule. Conservative: add it to the M1 rule ticket, about 1h.

## Tickets implied

- [M1] SEC-59 Unsigned and unpinned-key banners and hint wording for spec loading | owner: rust-engineer | est: 1.5h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: no 4.8 fix line or stderr line names `--allow-unsigned` or `--key`, a `--key` run prints the KEY NOT PINNED banner on stderr and every HTML page, and the fix label reads "From the spec file (not verified)" for unsigned and flag-key runs.
- [M1] SEC-60 Root trust lookup touches no user path, Windows store ACL rules | owner: rust-engineer | est: 3h | depends on: Trust store load and save in user and system locations | exit test: a root run under strace opens no path under SUDO_USER's home, and on Windows CI a ProgramData\rdy directory created by a non-admin user, or with a Users write ACE, exits 64 with trust_store_insecure.
- [M1] SEC-61 Single-buffer spec load and key fingerprints | owner: rust-engineer | est: 2h | depends on: Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: a file swapped after the first read does not change the parsed, hashed or copied bytes, a forged key with the vendor's key id fails, and the result carries signature.key_fingerprint.
- [M1] SEC-62 Parser rejects tags, directives and non-finite floats | owner: rust-engineer | est: 1h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: `!!binary`, `!custom`, `%YAML 1.1`, `.inf` and `.nan` fixtures each exit 64 with line and column.
- [M1] SEC-63 Result schema caps, identity.kube exec plugin and action log retention | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: a 5 MiB message fails the result schema, a fixture with an exec plugin shows exec_plugin in JSON and HTML, and a 300-check flood fixture keeps every connect and kube entry with actions_dropped counts.
- [M1] SEC-64 HtmlSafeJson as the only unescaped template value | owner: rust-engineer | est: 1h | depends on: HTML-safe deterministic JSON writer with size caps | exit test: CI fails on any `|safe` in templates, and the golden HTML's data-sha256 equals the SHA-256 of the golden .json.
- [M1] Apply 01 security review edits to 01-spec-format and the schema files | owner: rust-architect | est: 2h | depends on: none | exit test: every must-fix and should-fix item above is applied or answered in this file, and the schema hostile-case fixtures listed under "How I checked the examples" give the documented accept or reject.
- [M2] SEC-65 Redaction span union with hostile custom patterns | owner: rust-engineer | est: 3h | depends on: SEC-44 Full redaction corpus with chunk-boundary cases | exit test: every built-in positive in the corpus, run with custom patterns `@`, `.`, the first secret byte and the key name, has zero survivors.
- [M2] SEC-66 rdy bundle ignores spec collectors unless the spec is verified with a pinned key | owner: rust-engineer | est: 1h | depends on: SEC-43 Bundle collector path policy | exit test: an unsigned or --key spec with `collect: ["file:/etc/acme/*"]` builds a bundle from the built-in set only and says so.
