# Review of 04 Bundle and redaction (draft 2) by code-reviewer

Reviewer: code-reviewer, cold. Date: 2026-10-28. Inputs: CLAUDE.md, KICKOFF item 5, 05 revision 2
(invariants, Surface 4, Appendix F), 02 revision 2, ADRs 0009, 0012, 0015 and 0016, 01 draft 2 and
`crates/rdy-spec/schema/*.json`. I did not edit 04.

**Verdict: request changes.** 10 must fix, 20 should fix, 20 nits.

KICKOFF item 5 coverage is complete: collectors, redactor, test strategy, manifest, caps and a
byte-level upload flow are all here. The contract is mostly sound. The M1 redactor as written still
breaks on the real result schema, and three of its ten rules have no test. Several M2 parts contradict
01 and the schema. House rules: no em dashes, no competitor names, no old working name found.

## Must fix

1. **3.2, lines 179 to 182. The key-name walk breaks the typed round trip.** `redact_report` replaces
   "a member whose key matches a secret key stem" whole, then deserializes back into `Report`. The
   result schema has `summary.pass` (an integer, `result.v1.schema.json` line 833). Stem `pass` matches
   it, so every report would fail to deserialize. Every key in `redaction.by_rule` is a rule name with a
   stem in it (`secret_by_key`, `auth_header`, `aws_session_token`, `rdy_share_token`). Check-defined
   `observed` keys (`auth_method`, `passed`) would be hit as well. `redact_report` also returns
   `Redacted<Report>` with no error path, so "fail closed" has no defined result. Fix: run the
   whole-member rule only on string values inside free-form maps (`observed`, `expected`, env
   `{name, value}` pairs, action `argv`), never on schema-defined field names. Fill `redaction` after
   the walk. Change the signature to `-> Result<Redacted<Report>, RedactError>`. On error, write no
   report and exit 70. Add to the exit test of "Apply the redactor...": the 01 sample reports 7.2 to
   7.4 come back byte-identical apart from the planted canaries.

2. **3.2, lines 162, 171 and 177. Process-wide counts make `redaction.by_rule` nondeterministic.** The
   counts are shared per process by report, logs and bundle. The report's counts would then include
   redacted log lines and change with `RUST_LOG`. That breaks golden reports and the M1 exit test
   "`redaction.by_rule` matches the canaries". Fix: the `Redactor` shares only the key. `redact_report`
   counts per call and writes its own summary. Bundle entries count per entry. Test: one fixture run
   with `RUST_LOG` unset and with `RUST_LOG=trace` gives identical `by_rule`.

3. **1 (line 58) and 4.2 (lines 327 to 354). The M1 corpus does not test every M1 rule or form.** It
   claims "every M1 category in 05 Appendix F". These have no M1 case: `api_key_header` (`X-Api-Key`
   and Cookie are M2), `aws_session_token` (the `ASIA` plus `SessionToken` case is M2), JSON and INI
   key names (05 Appendix F lists both as M1; JSON is what most M1 evidence looks like), and the
   `--flag=` form that line 57 claims. A count floor did not catch this. Fix: move five cases into M1:
   `X-Api-Key`, JSON `SessionToken` with an `ASIA` id, JSON `"client_secret":`, an INI credentials
   file and `--password=x`. Add one negative with `passed: 12` and `author: alice` (stem false
   positives). M1 becomes 26 cases (21 positive, 5 negative). Make the harness fail when any rule in
   the M1 table has zero positive cases. SEC-26 goes from 2h to 3h.

4. **3.4 (lines 223 to 224) against section 1 (lines 55 to 56) and Appendix B line 701. Two PEM
   definitions.** M1 redacts from BEGIN to END, or to the end of the string. The M2 stream stops "at
   END or the first line that does not look like key material". The two disagree on unterminated
   blocks, so the property in 4.3 ("stream output equal to whole-input output") must fail. The
   streaming version also leaks legacy encrypted PEM: the `Proc-Type:` and `DEK-Info:` header lines
   end the state before the key body. Fix: use one definition in both modes. Redact from BEGIN to the
   matching END, header and blank lines included. With no END, redact to the end of the input in
   whole-string mode and to the end of the entry in stream mode (state carries across chunks). Add a
   `Proc-Type: 4,ENCRYPTED` case to M2 `pem`.

5. **2 (lines 74 to 77, 100, 105) and Appendix C line 755, against 01 2.8 and the schema. Collector ids
   contradict 01.** `spec.v1.schema.json` allows only `k8s:events` for `k8s:` (the `enum`), so a spec
   with `k8s:describe:acme` fails `spec lint` with exit 64. 01 2.8 says "other kinds are bad values
   until 04 adds them". 01's M2 ticket "Bundle block strict validation in rdy bundle" refuses unknown
   kinds, while 04 skips them. Inside 04, the id has a `:<ns>` argument, but the install-namespace rule
   picks namespaces anyway, and the manifest sample uses a bare `k8s:describe`. Line 9 says "01 wins",
   which would kill half of section 2. Fix: decide here. Unknown kinds are skipped with a manifest
   entry, because collecting less is safe and checks already work this way. The id is `k8s:describe`
   with no argument; namespaces come from the install-namespace rule. Then add Plan corrections for 01
   2.8 (list `host:*`, `container:runtime`, `k8s:describe`), for the schema (relax `k8s:` to
   `^k8s:[a-z_]{1,32}$` so older binaries skip rather than refuse) and for 01's strict-validation
   ticket (unknown kind: skip, unknown group: exit 64).

6. **Section 1 table (line 44) and Appendix B line 705. 01 asked 04 a question and got no answer.** 01
   "Decisions needing an ADR" (01 line 1717) asks 04 to decide whether `jwt` moves into M1, because no
   M1 rule catches a bare service-account token in a kube error string. 04 keeps `jwt` in M2 without
   saying why. Decision: move `jwt` to M1. It is one regex. It protects the M1 report under rule 2, and
   kube errors are M1 evidence. Fix: +0.5h on the M1 rules ticket and +1 M1 case (27 in all), and record
   the answer in Plan corrections against 01.

7. **6.2 step 0.3 (lines 494 to 496) against 3.6 (lines 258 to 262). A `--keep-emails` bundle can never
   be uploaded.** The Bundle set always redacts emails, so the residual scan finds the kept addresses
   and exits 64. Fix: the scan reads `groups_off_by_flags` from the manifest and honours only `emails`.
   Any other value exits 64, and the consent screen prints the "not redacted" line. Also say that spec
   `redact_patterns` cannot be re-checked at upload, because `rdy upload` has no verified spec.

8. **3.5, lines 239 to 240. The log redactor misses key names in colour output.** The writer redacts
   "each formatted event". With ANSI on, the `tracing-subscriber` fmt layer puts escape codes between
   the field name and `=` (italic name, dimmed `=`), so `secret_by_key` does not match
   `password=hunter2` on a terminal. That breaks INV-15 at `RUST_LOG=trace`. Fix: build the inner fmt
   layer with `.with_ansi(false)`, or strip CSI sequences before redaction. Move the ANSI-wrapped
   `hostile` case into M1 (28 cases). Add a canary-in-a-field test to "Redacting tracing writer, panic
   hook and CLI error text".

9. **6.2 step 0, lines 487 to 497. The bytes scanned may not be the bytes sent, and the decoder is
   unbounded.** The residual scan (3) and the hash (4) are separate passes over the file. Bytes changed
   between them get hashed, shown and sent without a scan. Decoding a 100 MiB `.tar.zst` also has no
   output or memory bound, and the zstd default allows a 128 MiB window. Fix: one streaming pass:
   handle, then sha256, then zstd decode, then tar, then a scan per entry. Use
   `window_log_max(23)` (the 5.3 setting), stop after 257 MiB decoded and 13,000 entries, and exit 64
   past either. Exit test: a zstd bomb and a 20,000-entry tar each exit 64 within 5 s.

10. **5.5, lines 455 and 467. The archive cap is not enforceable as written.** "Soft stop at 90 MiB
    written" checks compressed bytes after the fact. An entry being compressed when the stop hits can
    push the archive past 100 MiB, and then `rdy upload` refuses a bundle rdy just made. Fix: before
    each entry, require compressed bytes so far, plus the entry's `ZSTD_compressBound`, plus a 6 MiB
    manifest reserve, to stay at or under the cap. Otherwise truncate the entry with a marker to fit, or
    skip it with `archive_cap`. Bound the manifest at 13,000 entries. Exit test on the archive writer:
    incompressible fixtures never yield an archive over 100 MiB.

## Should fix

11. **Decision on the open disagreement: raw `bytes_in` (lines 424 to 426, 459 to 461, Appendix C).** A
    file with one redaction gives away that secret's exact length: `bytes_in - bytes_out` plus the
    known placeholder length. The truncation marker "of at least 9812345 bytes" leaks the same way.
    **Decision: do not store exact raw counts.** Rename the field to `raw_size_kib`, rounded up to a
    multiple of 4 KiB, and use the same rounding in markers. Exact counts stay in memory only. Reason:
    the field exists so support knows how big the source was, and 4 KiB granularity answers that.
    Rounding hides the length of any secret under 4 KiB, which is nearly all of them. It costs one
    line of code, and the debate ends.

12. **Decision on the open disagreement: corpus 60 vs 300 (4.2, Plan corrections line 880).**
    **Decision: 28 hand-blessed cases in M1 (after must-fix 3, 6 and 8) and 60 in M2. Reject 300.** Gate
    on coverage, not count. The harness reads Appendix B and fails unless every rule has at least one
    positive case for each syntax form it claims, and every key-name exclusion has a negative.
    Generated chunk-offset and property cases supply the volume, and every miss report adds a case.
    Reason: 300 hand-blessed goldens cost 15 to 25 founder hours of blessing and buy repetition, not
    coverage. Must-fix 3 shows a count floor can pass with three rules untested. 05 revision 3 must
    change SEC-26, SEC-44 and Appendix F to match.

13. **Drift from 02, ADR 0015 and ADR 0016 (lines 161, 163, 234, 942).** 04 puts the redactor behind
    feature `redact`, while 02 (line 72) and ADR 0015 decision 1 say no feature gate. 04 has
    `Redacted<Report>`; 02 and both ADRs have `RedactedReport`. 04 has `OutputDir::write_atomic`; 02
    has `write_report`. ADR 0015 already exists (Proposed). Fix: drop the feature and follow 02. Keep
    `Redacted<T>`, but list the rename in Plan corrections against 02 Appendix A and ADRs 0015 and
    0016. Retitle the first ticket "Amend ADR 0015 with span union, keyed tags, Redacted<T> and ring"
    (1h). Add ADRs 0014, 0015 and 0016 to the "builds on" list on line 7.

14. **Ticket titles do not dedupe (lines 937 to 947, 975).** Line 937 says reused titles are exact. They
    are not. "SEC-25 Build minimal redactor for reports and evidence" should be "SEC-25 Minimal redactor
    for evidence, errors and logs" (05, 02, ADR 0015). "Apply the redactor to every Report string
    before return" should be "Redact then cap every Report string and return RedactedReport". Two
    dependencies do not exist: "Map outcomes to CheckResult with fix source, partial and size caps"
    (02 has "... partial and needs") and "SEC-23 Enforce Kubernetes request allowlist" (not in 05
    revision 2). Fix: use the existing titles, and keep ADR 0015's exit clause "a PEM key placed
    across a 64 KiB cap boundary is fully redacted".

15. **Invariants (lines 481, 850 to 861).** 6.1 cites INV-25 to INV-27, which 05 revision 2 does not
    have. The correction says "INV-21 to INV-26" and then lists seven. Neither INV-09 (writes) nor
    INV-11 (peers) is amended, although M2 adds a bundle directory, a receipt written into an existing
    directory, and the upload origin. Fix: request INV-21 to INV-27 from 05 revision 3. Amend INV-09 to
    allow the new `rdy-bundle-*` directory and `upload-receipt-*.json` (`create_new`, 0600). Amend
    INV-11 to add "the upload origin, only in `rdy upload` and only after consent".

16. **Watchdog path (02 line 170 against 04 lines 58 to 59).** 02's watchdog writes "already redacted"
    results, but 04 redacts once, at the end. Fix: the watchdog calls `redact_report` on its snapshot.
    Add to the exit test: a hung check with a canary in a finished result writes a redacted report.

17. **Redactor construction (lines 166 and 177).** `new(set, extra, key)` takes the spec's patterns, but
    it is built "before the spec is read". Fix: `Redactor::new(key)` with the built-ins at start. In
    M2, `with_extra(&self, &Extra) -> Result<Redactor, RedactError>` after verification, sharing the
    key. M1 has no `Extra`.

18. **`--server` with `--yes` (lines 543 to 547).** A pasted `rdy upload x --server https://evil.example
    --yes` with `RDY_TOKEN` set sends the token to that host. The bold line is the only guard. Fix: a
    non-default server ignores `--yes` on a TTY and always asks. Without a TTY it is allowed, and the
    receipt records it.

19. **`--token-file` (lines 502 to 504).** It does not require a regular file, so a FIFO or `/dev/tty`
    blocks forever. Nothing says to trim the trailing newline, and Windows is "not checked". Fix: after
    open, `fstat` and require a regular file (exit 64), trim one trailing `\n` or `\r\n`, and on Windows
    refuse a reparse point.

20. **Offline text (lines 611 to 615).** It prints `metadata.contact` from the spec copy inside the
    bundle, which no one has re-verified. An edited bundle becomes a phishing line. Fix: print the
    contact only if the embedded spec and `.minisig` verify against the local trust store; otherwise
    leave the line out.

21. **Exec paths per OS (Appendix A line 680; 02 lines 228 to 232).** `crictl` usually lives in
    `/usr/local/bin`, which is not on the fixed PATH. On macOS, `docker` lives in Homebrew or
    `/usr/local/bin`, which can be user-writable, so running it as root is a privilege escalation. On
    Windows, `docker.exe` is outside System32, which 02 forbids. Fix: on Linux, declare `/usr/local/bin`
    as an extra directory, used as root only if the directory and the binary are root-owned and not
    group or world writable. Mark macOS and Windows `container:runtime` as `-` until an ADR 0014
    amendment.

22. **Deny list per OS (lines 110, 868 to 871, Appendix A line 674).** On macOS, `/etc` is a symlink to
    `/private/etc`. The list is checked on the canonical target, so `/etc/sudoers*` never matches. There
    are no Windows or macOS entries. Fix: add `/private/etc/...` and `/private/var/...` forms. Add
    Windows `C:\Windows\System32\config\*`, `*\.ssh\*`, `*\.aws\credentials`, `*\.docker\config.json`
    and macOS `*/Library/Keychains/*`. Test the canonical forms on the macOS leg.

23. **User names (line 765 against lines 392 and 424).** "Never in the manifest: user names", yet
    `source` and the archive `path` keep `/home/alice/...`. Fix: apply 01's home-to-`~` rule to `source`
    and to archive paths.

24. **Unsigned or unpinned specs (line 649 against 01 2.8 lines 253 to 256).** 01 says `rdy bundle` uses
    the "built-in collector set" unless the spec is verified with a pinned key. 04 never defines that
    set. Fix: define it as `rdy:result`, `host:processes`, `host:network` and `host:disk`, with a
    summary line. Also push back on 01 about ignoring `redact_patterns` for unpinned specs: they can
    only add redaction, `regex` is linear, and ignoring them lowers redaction.

25. **6.1 scope (lines 478 to 481).** "Before the answer no socket opens" is false for `--upload` on
    `run` and `bundle`, because checks and kube connect first. Section 7 also does not define `--upload`
    on `run`. Fix: "no connection to, and no DNS query for, the upload origin before the answer". Either
    add `rdy run --upload` to section 7 or drop it.

26. **Time caps hide truncation (lines 84 to 85, 454).** A time-capped entry is `partial` with no
    in-content marker. The 10-minute total cap is less than the sum of per-collector caps, and what
    happens when it runs out is not stated. Fix: add the marker
    `[rdy: stopped after 120 s (journal time cap), output is incomplete]`, set `truncated: true` and
    `truncation: "time"`, and when the total cap runs out, mark the remaining collectors
    `skipped: total_time`.

27. **`max_size` (lines 440, 468 to 469; 01 example `200Mi`).** It does not say whether `max_size`
    lowers the raw cap, the archive cap or both. The upload fix `--max-size 128MiB` cannot shrink an
    archive that is over 100 MiB. Fix: `max_size` lowers both caps to `min(value, default)`. Once
    must-fix 10 holds, an archive over the cap was not made by this rdy, and the message says so.

28. **Fake-server tests on macOS and Windows (line 546).** The platform verifier does not read
    `SSL_CERT_FILE` there, so the loopback TLS server cannot be trusted. Fix: a test-only extra root
    under feature `testing`, with the existing CI check that `testing` is not in the release binary.

29. **Public API and wire versioning (lines 160 to 175).** `RuleSet` and `RedactError` are public enums
    in `rdy-engine` and are not `#[non_exhaustive]` (ADR 0007 decision 6). The placeholder grammar now
    appears in every `rdy/v1` report, but 01 does not define it. Fix: mark both enums
    `#[non_exhaustive]`. Add `[REDACTED:<rule>:<tag>]` and its regex to 01 section 5. Say that a rule
    version bump is a CHANGELOG entry and a placeholder grammar change is a breaking change.

30. **Length: about 12,870 words. Cut to about 7,500, with a body that reads in 15 minutes.**
    - Delete: 3.6 (216 words; the email rule moves into 3.1, entropy into Appendix B, the residual scan
      into 6.2, dumpable into 3.5). Delete the ten "This note, draft 1" items from Plan corrections
      (about 400 words of history, not corrections), the stale 02 renumbering item (02 revision 2
      already uses 05 revision 2 numbers) and the "01 not written" item. Delete the "Moved from draft
      1" paragraph. Keep the no-raw-hash rule only in 3.1 (it is now stated five times: decision 5,
      3.1.6, 3.6, 5.4 and Appendix C).
    - Move to other docs: section 7, Appendix F and the 6.4 sample text go to 07-cli-ux.md, which cli-ux
      owns (about 450 words). 6.5 goes into the SEC-41 and fake-server exit tests, where it already
      mostly is. 6.6 goes into Decisions needing an ADR.
    - Move to appendices: 3.4 streaming becomes Appendix G (M2). The 4.2 table merges with Appendix D.
      The section 2 collector table merges with Appendix A (the two overlap). 5.1 to 5.3 go next to the
      manifest sample in Appendix C. 4.3 shrinks to the M2 ticket exit tests.
    - Keep in the body: decisions, the scope table, the collector contract bullets, 3.1, 3.2, 3.3, 3.5,
      the 3.7 limits, 4.1, the M1 half of 4.4, the 5.4 field list, 5.5, 6.1 to 6.3, and Appendix E (the
      byte-by-byte requirement). Shorten M2 ticket exit tests to one clause each. Target: body about
      3,500 words, appendices about 2,000, corrections and ADR list about 550, tickets about 1,500.

## Nits

31. Line 677: the command is `ss -tuln` with no `-p`, yet the degrade text talks about an owner column.
    Pick one.
32. Lines 121 and 655: `--plan` "reads nothing", yet it prints resolved globs. Say "lists directories,
    reads no file content, makes no request".
33. Line 703: the rule `rdy_st_[A-Za-z0-9]{20,64}` leaves the tail of a longer token. Redact
    `rdy_st_[A-Za-z0-9]{20,}` up to the 16 KiB limit, and keep the strict regex for validation only.
34. Line 669 cites ADR 0004 for the fixed search path. It is ADR 0014 and 02.
35. Line 9 calls 01 "revision 0" (it is draft 2). Line 440 calls `bundle.max_size` "proposed", but it is
    in the schema.
36. Line 528 counts by group and line 549 by rule. Pick one unit for the consent screen and the summary.
37. Line 582: say "read at most 64 KiB, then close". As written, it reads like it reads everything and
    discards the rest.
38. Line 977: the determinism exit test also needs a fixed bundle id, not just a fixed key and clock.
39. Line 153 says nothing hashes raw content, but `host_id` is derived from the machine id (01). Name
    it as the one exception.
40. Line 91: say what `rdy:<x>` in `collect:` does. Proposal: exit 64.
41. Line 675: the journal duration range of 1h to 30d is not in the schema pattern. Add it to 01, or
    say lint enforces it.
42. Line 453: a head-cut `rdy:result` is invalid JSON. Refuse a `--result` over 16 MiB at validation
    instead of truncating it.
43. Lines 120 to 121: "refused unless it passes ... the prefix check" is circular. Say "refused if it
    is outside the literal prefix or on the deny list".
44. Line 632: add the POST `Idempotency-Key` semantics to the open questions for `rdy-cloud`.
45. Line 572: a receipt printed to stdout collides with `--json`. With `--json`, the receipt is the
    JSON output.
46. Line 487: name the Windows equivalent of `O_NOFOLLOW` and the owner check, or list them as residuals.
47. Line 589: say the 15 s connect timeout includes DNS resolution.
48. Lines 505 to 507: in `bundle --upload`, a kube exec plugin (the INV-07 exception) inherits
    `RDY_TOKEN`. Document it as a residual.
49. Log lines: a PEM block split across several `tracing` events is not caught in M1 (no state, no
    entropy rule). Record it as a known gap.
50. M2 tickets of 8h to 12h (collector trait, host collectors, k8s collectors, SEC-41): split them to 4h
    or less before M2 planning, so each week still ships a binary.

## M1 sufficiency (CLAUDE.md rule 2)

With must-fix 1, 2, 3, 6 and 8 applied, the M1 minimum is enough. Every report string, the action
log, stdout, the logs, panics and errors go through one redactor before any write, and the `Redacted`
type makes skipping it a compile error. The one unredacted write is the verified spec copy. That is
correct, because signed bytes must stay exact, but the SEC-31 fold should state it on the security
page. Cost: 12.5h becomes about 14.5h (+1h corpus, +0.5h `jwt`, +0.5h the schema-aware walk and
per-call counts).

Speculative for M1: the `redact` feature (drop it, should-fix 13) and the `Extra` parameter
(should-fix 17). Keep the keyed tag in M1: the placeholder is part of the M1 report wire format, and
changing it later breaks goldens and `rdy-cloud`. `RuleSet::Bundle` can stay, because the result schema
already has `ruleset: bundle`.

## Checked and fine

- Spans merge by union; a custom pattern can only add (matches 01 2.8).
- `Redacted<T>` has no public constructor, `From`, `Default`, `Deserialize` or `DerefMut`.
- The HMAC key comes from `ring` `SystemRandom`, once per process, and is never stored. The 32-bit
  collision figure is right.
- An exact-placeholder skip only, with the `hunter2` test.
- A spec cannot remove a built-in rule, and an unknown group exits 64.
- Emails are on by default in bundles, with an argv-only `--keep-emails`.
- Collectors are read-only and go through the facade, with per-collector caps and degrade codes.
  Secrets, `pods/log`, `env[].value` and `last-applied-configuration` are excluded.
- Upload rules: the token is never on argv; one fixed origin; two requests; RFC 9530 `Content-Digest`;
  an idempotent `PUT` with `409` on a different digest; the client builds the URL itself; no redirects;
  https only; `--yes` is required without a TTY; the last chunk is held back for the changed-file abort.
- Timeouts and bounded retries on every request, and server error text is never printed raw.
- M1 tickets are each 1h to 3h, with exit tests. Every M2 and M3 ticket has an estimate.
- No em dashes, no competitor names, no old working name.
