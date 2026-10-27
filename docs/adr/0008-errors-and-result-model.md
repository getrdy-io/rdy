# ADR 0008: Error handling and the result model; Timeout and Skipped are outcomes, never crashes

- Status: Accepted
- Date: 2026-10-27

## Context

`rdy` runs once, often as root, on a machine the vendor will never see. If it crashes, the SE gets
nothing. CLAUDE.md fixes the rules: `thiserror` in libraries, `anyhow` only at the binary edge, a fix
hint on every user-facing error, timeouts reported as results, and exit codes 0 ready, 1 warnings only,
2 blockers, 64 usage, 70 internal. We need one model that separates "the environment failed a check"
from "rdy could not check" from "rdy itself broke".

## Decision

1. **Per-check status** (in `rdy_spec::result`, re-exported by `rdy-engine`, `#[non_exhaustive]`; see ADR 0012):
   `Pass`, `Warn`, `Block` (the check ran and failed; which of the two comes from the spec `severity`),
   `Skipped { reason }` (a need was missing, the OS is unsupported, or the check id or a field is unknown),
   `Timeout { after }`, `Error { message, hint }` (the check itself failed, including a caught panic).
2. **Check code returns `Result<Finding, CheckError>`.** `Finding` is pass or fail plus observed and
   expected values. `CheckError::MissingNeed`, `Unsupported` map to `Skipped`; anything else maps to
   `Error`. The engine, not the check, applies severity and the timeout.
3. **Run verdict:** `Blocked` if any `Block`; else `Warnings` if any `Warn`, `Skipped`, `Timeout` or
   `Error`; else `Ready`. A check that could not run is never counted as passing. Exit codes 2, 1, 0.
4. **Exit 64** when the input is wrong and the user must change it: bad flags, unreadable spec, spec
   parse or validation error, signature failure without `--allow-unsigned`. **Exit 70** only when `rdy`
   cannot produce a report at all (cannot write the output file, runtime failed to start, a panic
   outside a check). Even then it prints the JSON it has to stdout if `--json` was given.
5. **Errors.** Each library crate has one public `thiserror` enum (`SpecError`, `SignatureError`,
   `EngineError`, `ReportError`), `#[non_exhaustive]`, each with `fn hint(&self) -> Option<&str>`.
   `rdy-cli` uses `anyhow` with `.context(..)`, downcasts to these types to pick the exit code and print
   `error: <what>` then `fix: <hint>`. No `unwrap` or `expect` outside tests (clippy `unwrap_used`,
   `expect_used` denied in library crates).
6. **Panics.** Release profile keeps `panic = "unwind"` so a panicking check is caught by its
   `tokio::spawn` join handle and becomes `Error` with "internal error in <id>, please report". A panic
   hook writes the message to the log, never the environment or arguments (they may hold tokens).

## Consequences

- The report always lists every check in the spec with a status. Partial runs are still useful.
- The portal can count "could not check" separately from failures, which is a sales signal on its own.
- `panic = "unwind"` costs a little binary size versus `abort`. Accepted.
- Skipped checks lower the verdict to at most `Warnings`, so a spec full of unknown ids can never be
  `Ready`. cli-ux decides whether `--strict` should turn non-runs into blockers.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Status `Fail` plus a separate severity field only | Every consumer would recompute warn vs block; the portal and the HTML would drift. Severity is still in the JSON. |
| `Skipped` counts as pass | Hides missing privileges; the customer reads READY when nothing was checked. |
| `anyhow` everywhere | Libraries consumed by `rdy-cloud` need typed errors to match on. |
| `miette` or `eyre` for rich diagnostics | Nicer output, more dependencies; line and column plus a hint is enough for v1. |
| `panic = "abort"` | One bad check would kill the whole run and lose every other result. |

## Tickets implied

- [M1] Define result model and verdict mapping in rdy-spec | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: unit tests cover every status to verdict and verdict to exit code combination.
- [M1] Error types with fix hints and exit code mapping at the CLI edge | owner: rust-engineer | est: 2h | depends on: Define result model and verdict mapping in rdy-spec | exit test: integration tests assert exit 64 for a bad spec, 70 for an unwritable output dir, and a `fix:` line in both.
