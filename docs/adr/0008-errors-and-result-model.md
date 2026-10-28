# ADR 0008: Error handling and the result model; Timeout and Skipped are outcomes, never crashes

- Status: Accepted (revised 2026-10-28 after cli-ux and security-reviewer review); decision 3 refined by ADR 0013; decisions 4 and 7 amended 2026-10-28 in M1-009 (ADR 0016 timing, Ctrl-C, new codes, `report_write`)
- Date: 2026-10-27

## Context

`rdy` runs once, often as root, on a machine the vendor never sees. If it crashes, the SE gets nothing.
CLAUDE.md fixes the rules: `thiserror` in libraries, `anyhow` only at the binary edge, a fix hint on every
user-facing error, timeouts reported as results, exit codes 0 ready, 1 warnings only, 2 blockers, 64
usage, 70 internal. We must separate "the environment failed a check" from "rdy could not check" from
"rdy itself broke", and a CI gate written as "0 or 1 is fine" must never pass an unchecked environment.

## Decision

1. **Per-check status** (`rdy_spec::result`, re-exported by `rdy-engine`, `#[non_exhaustive]`, ADR 0012).
   JSON values and display words are one vocabulary:

   | Rust | JSON | Terminal and HTML | Meaning |
   | --- | --- | --- | --- |
   | `Pass` | `pass` | `PASS` | ran, met the requirement |
   | `Warn` | `warn` | `WARN` | ran, failed a `severity: warn` check |
   | `Block` | `block` | `BLOCK` | ran, failed a `severity: block` check |
   | `Skipped { reason }` | `skipped` | `SKIP` | need missing, OS unsupported, unknown id or field |
   | `Timeout { after }` | `timeout` | `TIMEOUT` | did not finish in time |
   | `Error { message, hint }` | `error` | `ERROR` | the check itself failed, including a caught panic |

2. **Check code returns `Result<Finding, CheckError>`.** The engine, not the check, applies severity and
   the timeout. `MissingNeed` and `Unsupported` map to `Skipped`; the rest to `Error`. A skip reason names
   the thing: `unknown field 'min_memory' for host.memory (needs a newer rdy, or a typo)`. `spec lint`
   reports the same as a warning with line, column and a did-you-mean.
3. **Run verdict**, one rule, no `--strict` flag:

   | Case | Verdict (Rust, JSON) | Exit | Last line |
   | --- | --- | --- | --- |
   | Any `Block` | `NotReady`, `not_ready` | 2 | `NOT READY` |
   | No `Block`, but a `severity: block` check was Skipped, Timeout or Error | `NotReady`, `not_ready`, `reason: "required_check_not_run"` | 2 | `NOT READY: 1 required check was not run` |
   | Only `Warn`, or a `severity: warn` check that did not run | `ReadyWithWarnings`, `ready_with_warnings` | 1 | `READY with warnings` |
   | All ran and passed | `Ready`, `ready` | 0 | `READY` |

   The summary counts them apart: `0 blocks, 1 warning, 3 passed, 1 required check not run`.
4. **Exit 64** when the input must change: bad flags, unreadable spec, parse or validation error,
   missing signature without `--allow-unsigned`, any invalid signature. **Exit 70** when `rdy` cannot
   deliver its result: the report directory cannot be created (before the first check, ADR 0016), the
   report files cannot be written at the end (the terminal result still prints in full, ADR 0003),
   Ctrl-C (M1: the run stops with no report; 07 section 5.1), runtime failed, a panic outside a check.
5. **Errors.** Each library crate has one public `thiserror` enum (`SpecError`, `SignatureError`,
   `EngineError`, `ReportError`), `#[non_exhaustive]`, with `fn hint(&self) -> &str`, never optional.
   Where the honest fix is "this is a bug", the hint says `this is a bug in rdy. Please report it at
   https://github.com/getrdy-io/rdy/issues and include the output of rdy version.` A unit test matches
   every variant and asserts a non-empty hint. `rdy` uses `anyhow` with `.context(..)` and downcasts to
   pick the exit code. Terminal output escapes control characters (as `\x1b`) in any untrusted string.
6. **First lines differ by kind.** Usage: `error: unknown flag --keey`. Signature: `error: the signature
   on acme-platform.yaml does not match the file. It may have been changed after signing.`
7. **`--json` on any non-verdict exit** prints one object on stdout, and the same text on stderr:
   `{"error": {"code": "spec_signature_invalid", "message": "...", "fix": "..."}, "verdict": null,
   "complete": false}`. Codes are stable and part of `rdy/v1` (ADR 0007): `usage`, `spec_unreadable`
   (exit 64), `spec_parse`, `spec_invalid`, `spec_unsigned`, `spec_signature_invalid`,
   `spec_key_unknown`, `spec_expired`, `trust_store_insecure` (01 section 4.8), `report_write`,
   `interrupted` (exit 70, Ctrl-C), `internal`. `report_write` is an error object only when no verdict
   exists: the report directory could not be created before the first check, or `rdy report` or
   `rdy bundle` could not write. When a verdict exists and the files cannot be written, stdout holds the
   Report with `"complete": false` and the error is on stderr (07 section 4.1).
8. **Panics.** Release profile keeps `panic = "unwind"` so a panicking check is caught by its join
   handle and becomes `Error` with "internal error in <id>" and the bug hint. The panic hook logs the
   message only, never environment or arguments.
9. **No secrets in strings.** Every message, `Error.message` and evidence string goes through the M1
   redactor before it is printed or written. reqwest errors use `without_url()`.

## Consequences

- The report lists every check with a status. A partial run is still useful, and an unchecked required
  check can never look like a pass or like "warnings only".
- The week 2 alpha, where every check is `SKIP` "not built yet", exits 2. That is correct.
- `panic = "unwind"` costs a little binary size. Accepted.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Skipped required checks give exit 1 | A "0 or 1 is fine" gate passes an environment nobody checked. |
| A `--strict` flag | Two meanings of ready; the unsafe one would be the default. |
| `hint() -> Option<&str>` | Makes "no fix" legal; new variants would ship without one. |
| `Skipped` counts as pass | Hides missing privileges. |
| `anyhow` everywhere | `rdy-cloud` needs typed errors. |
| `panic = "abort"` | One bad check would lose every other result. |

## Tickets implied

- [M1] Define result model and verdict mapping in rdy-spec | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: unit tests cover every row of the status and verdict tables, including a skipped block check giving not_ready with exit 2.
- [M1] Error types with fix hints and exit code mapping at the CLI edge | owner: rust-engineer | est: 3.5h | depends on: Define result model and verdict mapping in rdy-spec | exit test: every error variant has a non-empty hint, exit 64 and 70 cases print `fix:`, `--json` failures print the error object with a stable code, and control characters in a spec string are escaped.
