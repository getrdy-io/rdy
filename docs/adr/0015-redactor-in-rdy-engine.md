# ADR 0015: The minimal redactor lives in rdy-engine and runs before caps and before any write

- Status: Proposed (2026-10-28, applies the security-reviewer review of 02; security-reviewer re-review pending)
- Date: 2026-10-28

## Context

CLAUDE.md rule 2 and threat model INV-15: every string written to a report or a log passes the
redactor first. The redactors are planned in `rdy-bundle` (M2), but M1 reports and logs need one now.
The 02 review (MF-05) found that 02 revision 1 truncated values before redacting them, which leaves
secret fragments no pattern matches, and said nothing about logs or printed errors.

## Decision

1. `rdy_engine::redact` holds the M1 rule set (URL userinfo, bearer and basic auth, AWS keys, PEM
   private keys, kubeconfig credentials, `rdy_st_` tokens, generic secrets by key name). It is outside
   the `runtime` feature so `html`-only users and `rdy report` can call it. `rdy-bundle` reuses it in M2.
2. **Order:** build every string in full, redact it, then cap it on a char boundary with a marker,
   then apply the 2 MiB report cap. The engine returns a `RedactedReport` newtype that only this pass
   can build; writers and renderers accept nothing else.
3. **Logs:** `rdy` installs a redacting `tracing` layer first in `main`, before the spec is read. With
   `RUST_LOG` unset, hyper, h2, rustls, tower and kube are capped at `warn`. With it set, lines are
   still redacted.
4. **Errors:** the CLI redacts `EngineError`, `ReportError` and panic messages before printing.
5. The report carries counts per rule, never matched text (01 section 5).
6. Checks still record env var names, not values, and strip URL userinfo themselves. The redactor is
   the second line, not the first.

## Consequences

- One rule set for reports, logs and later bundles, tested by one corpus (SEC-26).
- `rdy-bundle` depends on `rdy-engine`, which it needs anyway for facade file reads.
- The redactor becomes public API of a contract crate, covered by ADR 0007.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Create `rdy-bundle` early with only the redactor | One more crate to publish for one module. |
| Redact at render time | Two renderers, two chances to forget; the JSON on stdout would bypass it. |
| Cap, then redact | Leaves unmatchable fragments; redaction can lengthen a value past its cap. |

## Tickets implied

- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: canaries in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace`.
- [M1] Redact then cap every Report string and return RedactedReport | owner: rust-engineer | est: 2h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: a PEM key placed across a 64 KiB cap boundary is fully redacted, and write_json and render_html do not compile with a plain Report.
