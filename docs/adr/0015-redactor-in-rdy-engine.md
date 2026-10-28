# ADR 0015: The minimal redactor lives in rdy-engine and runs on whole strings before any cap or write

- Status: Accepted (security-reviewer sign-off in PR #13, 2026-10-28). First accepted 2026-10-28 after
  the security-reviewer review of ADRs 0013 to 0016; decision 10 added in M1-009 from 04 section 3.
- Date: 2026-10-28

## Context

CLAUDE.md rule 2 and threat model INV-15: every string written to a report or a log passes the
redactor first. The redactors are planned in `rdy-bundle` (M2), but M1 reports and logs need one now.
Reviews found two layers where values were cut before redaction: the report field caps (02 revision 1)
and the facade I/O caps (exec stdout and stderr, file reads, `read_tail`, the CONNECT head). A secret cut
at either layer leaves a fragment no pattern matches.

## Decision

1. `rdy_engine::redact` holds the M1 rule set (URL userinfo, bearer and basic auth, AWS keys, PEM
   private keys, kubeconfig credentials, `rdy_st_` tokens, generic secrets by key name). It is outside
   the `runtime` feature so `html`-only users and `rdy report` can call it. `rdy-bundle` reuses it in M2.
2. **Facade-truncated buffers.** `FileBytes` and `Output` carry `truncated_head` and `truncated_tail`.
   Before matching, the redactor drops the partial first line of a head-truncated buffer and the partial
   last line of a tail-truncated one (the last 4 KiB if it has no newline), and puts the cap marker in
   their place. The PEM rule matches an unterminated `-----BEGIN ... PRIVATE KEY-----` through to the
   end of the buffer.
3. **Run-scoped known secrets.** The facade registers secrets it handles: the kubeconfig token and
   client key data, the `ProxyUrl` password, and values of declared env names that match the
   secret-name rule. The redactor removes exact matches and any 8-character or longer prefix or suffix
   of one at a truncated edge.
4. **Report order.** Each `CheckResult` and action entry is redacted, then capped (char boundary, with a
   marker), as it completes, so the watchdog snapshot, progress events and the terminal see only redacted
   text. A final pass runs over the assembled report. The 2 MiB report cap is measured after JSON
   escaping. The engine returns a `RedactedReport` newtype with no `From<Report>`, no `Deserialize` and
   no `DerefMut`. `write_json`, `render_html` and the terminal renderer accept nothing else. `Progress`
   carries id, status and duration only.
5. **Logs:** `rdy` installs a redacting `tracing` layer first in `main`, before the spec is read. With
   `RUST_LOG` unset, hyper, h2, rustls, tower and kube are capped at `warn`. With it set, lines are
   still redacted.
6. **Errors:** the CLI redacts `EngineError`, `ReportError` and panic messages before printing.
7. The report carries counts per rule, never matched text (01 section 5).
8. Checks still record env var names, not values, and strip URL userinfo themselves. The redactor is
   the second line, not the first.
9. The M1 corpus includes, for each facade cap, a canary at offsets cap minus 1 to cap minus 64.
10. **Span union, keyed tags, `Redacted<T>` and `ring`** (04 sections 3.1 to 3.4). Every rule runs on
    the original text and reports `(start, end, rule, priority)`. Overlapping or touching spans merge
    into one span covering their union, named after the highest priority rule in it, and the output is
    written once, so no rule sees a placeholder and no partly overlapped span leaves bytes behind. The
    placeholder is `[REDACTED:<rule>:<tag>]`; the tag is the first 4 bytes of HMAC-SHA256 over the
    secret bytes, under a 32-byte key made once per process from `ring::rand::SystemRandom`, held in
    memory only and never written, logged or put in an error. HMAC, SHA-256 and the RNG come from
    `ring`; nothing hashes raw content (no raw digests). `Redacted<T>` has no public constructor,
    `From`, `Default`, `Deserialize` or `DerefMut`, and `RedactedReport` is `Redacted<Report>`.
    `redact_report` is a schema-aware walk over the report with its own per-call counts. Rules are
    compiled in: a spec can only add. Redaction fails closed: an error drops the string, never falls
    back to raw text, and if the RNG cannot make a key rdy exits 70.

## Consequences

- One rule set for reports, logs and later bundles, tested by one corpus (SEC-26).
- A truncated buffer loses up to one line at each cut edge. Accepted: evidence near a cap is already
  partial.
- `rdy-bundle` depends on `rdy-engine`, which it needs anyway for facade file reads.
- The redactor becomes public API of a contract crate, covered by ADR 0007.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Create `rdy-bundle` early with only the redactor | One more crate to publish for one module. |
| Redact at render time | Three renderers, three chances to forget; the JSON on stdout would bypass it. |
| Cap, then redact | Leaves unmatchable fragments; redaction can lengthen a value past its cap. |
| Raise facade caps until truncation is rare | Moves the boundary, does not remove it, and costs memory on big hosts. |
| Highest priority span wins where spans overlap | Leaves the bytes of the lower priority span that stick out (01 review, security MF-04). |
| Unkeyed hash as the tag | A hash of a short password is a lookup table. |

## Tickets implied

- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: canaries in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace`.
- [M1] Redact facade-truncated buffers and a run-scoped known-secret set | owner: rust-engineer | est: 3h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: a PEM key, an AWS key id and a URL with userinfo placed across the stdout, stderr, file and tail caps at offsets cap minus 1 to cap minus 64 never appear in JSON, HTML or stderr, and the kubeconfig token is redacted wherever it appears.
- [M1] Redact then cap every Report string and return RedactedReport | owner: rust-engineer | est: 2h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: a PEM key placed across a 64 KiB cap boundary is fully redacted, results are redacted as they complete, and write_json, render_html and the terminal renderer do not compile with a plain Report.
