# Review of ADRs 0003, 0005, 0008, 0011 and the command surface in 00-overview.md, by cli-ux

Reviewer: cli-ux. Date: 2026-10-27. Reviewed cold. No reviewed file was edited.

Read: `docs/adr/0003`, `0005`, `0008`, `0011`, plus `0002` and `0012` where they touch the same surface, and `docs/plan/00-overview.md` (crate list, calendar, plan corrections, tickets).

Mechanical checks:

- Em dashes and en dashes: none in `docs/adr/` or `00-overview.md`.
- Competitor company or product names: none in those files (grepped for the names in the plan's market tables).
- Old working name: not seen on a full read. I cannot grep for a name I must not know.

## Verdicts

| ADR | Verdict |
| --- | --- |
| 0003 report format | Approve with nits (two should-fix items to settle before the report ticket starts) |
| 0005 plugin model | Approve with nits |
| 0008 errors and result model | Request changes (two must-fix items) |
| 0011 binary name and package | Approve (one nit) |
| 00-overview command surface | Approve with changes (names stand, one flag design changes) |

## Ranked findings

### Must fix

**M1. ADR 0008, decision 3 and Consequences: a skipped required check can give exit 1.**
Problem: the verdict is `Warnings` if any `Warn`, `Skipped`, `Timeout` or `Error` exists and no `Block` does. A `severity: block` check that could not run (no root, no kubeconfig, not in this build, timed out, crashed) then exits 1, "warnings only". A CI gate written as "0 or 1 is fine" passes an environment nobody checked. The ADR leaves the question open ("cli-ux decides whether `--strict` ..."). Week 2 of the calendar ships `rdy run --allow-unsigned --json` with every check Skipped, which would exit 1 today.
Fix: bake in one rule, no `--strict` flag.

| Case | Verdict | JSON `verdict` | Exit | Last line |
| --- | --- | --- | --- | --- |
| Any `Block` observed | not ready | `not_ready` | 2 | `NOT READY` |
| No `Block`, but a `severity: block` check was Skipped, Timeout or Error | not ready | `not_ready`, with `reason: "required_check_not_run"` | 2 | `NOT READY: 1 required check was not run` |
| Only `Warn`, or a `severity: warn` check that was Skipped, Timeout or Error | ready with warnings | `ready_with_warnings` | 1 | `READY with warnings` |
| All ran, all passed | ready | `ready` | 0 | `READY` |

The summary line counts them apart: `0 blocks, 1 warning, 3 passed, 1 required check not run`. The status word stays `SKIP` with a `(required)` marker and a fix line. Full samples are in my 10-devrel review. Rename the enum variant `Blocked` to `NotReady` so the code, the JSON and the last line use the same words (see S3).

**M2. ADR 0008, decision 5: `hint(&self) -> Option<&str>` lets an error ship without a fix.**
Problem: the house rule is that every failure has a fix. An `Option` makes "no fix" a legal value, and a `#[non_exhaustive]` enum will grow variants nobody tests.
Fix: `fn hint(&self) -> &str`, non-optional. Where the honest fix is "this is a bug", say so with the report address: `fix: this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues and include the output of rdy version.` Add a unit test that matches every variant of every error enum and asserts a non-empty hint. The panic message ("internal error in <id>, please report") also gets this fix line.

**M3. ADR 0003, decision 1: `<product>` in the file name comes from the spec.**
Problem: `metadata.product` is vendor-controlled text that becomes part of a path (`rdy-report-<product>-<timestamp>.json`). A value like `../../etc/x` or one with a slash, NUL or Windows reserved name writes outside the output directory or fails oddly. This is also a UX trap: spaces and unicode make files nobody can script.
Fix: `rdy-spec` validation restricts `metadata.product` to `[a-z0-9][a-z0-9._-]{0,63}` and `spec lint` reports it with line and column. The report code slugifies again defensively. Security-reviewer should confirm; I have flagged it to them through this file.

### Should fix

**S1. ADR 0003: define the file names and the output flags.**
Problem: "UTC timestamp" is not a format. A colon-separated timestamp is invalid on Windows. Scripts and humans both need to know the path. Nothing says how `--json` on stdout relates to the JSON file, or how to run without writing files (read-only directory, CI).
Fix: `rdy-report-<product>-20261027T143005Z.json` and `.html` (basic ISO 8601, no colons). The terminal prints both paths on a `Report written to` line, placed above the verdict so the verdict stays last. `--json` writes the same bytes to stdout as the file holds. Add `--out-dir <dir>` (default `.`) and `--no-report` (print only; with `--json` that is the whole output). If the output directory is not writable, do not lose the run: print the full terminal result, then `error: cannot write the report to ./` with `fix: use --out-dir <writable dir>`, and exit 70 only if the fallback also fails. Today ADR 0008 exits 70 and the customer sees no verdict.

**S2. ADR 0003: say what the HTML must show first.**
Problem: the ADR covers dark mode and print but not the order. My role rule is blockers first.
Fix: add to decision 5: the top of the page is the verdict (`READY`, `READY with warnings`, `NOT READY`, same words as the terminal), the counts, and a visible banner when the spec was unsigned (ADR 0002 stamps `signature: unsigned` in the JSON; the HTML must show it, not just carry it). Then blocks, then required checks not run, then warnings, then passes. Print expands everything but keeps this order. Add a one-line note near the top: "This file lists hostnames and addresses from this machine. Read it before you send it." The bug template already warns about this; the report should too.

**S3. One vocabulary across terminal, HTML, JSON and code.**
Problem: ADR 0003 labels the HTML `PASS, WARN, BLOCK, SKIPPED, TIMEOUT, ERROR`. ADR 0008 names the statuses `Skipped`, `Timeout`, `Blocked` (verdict). My terminal uses `SKIP`. Three vocabularies for the same thing confuse a customer reading both the terminal and the report.
Fix: display words, same in terminal and HTML: `PASS`, `WARN`, `BLOCK`, `SKIP`, `TIMEOUT`, `ERROR`. JSON values are lowercase snake case: `pass`, `warn`, `block`, `skipped`, `timeout`, `error`, and verdicts `ready`, `ready_with_warnings`, `not_ready`. The terminal status column is 7 wide. Put the mapping table in 01-spec-format.md and in the ADRs.

**S4. ADR 0008, decision 4: errors with `--json` are undefined for exit 64.**
Problem: exit 70 prints "the JSON it has to stdout", but a bad flag, a bad spec or a signature failure (64) with `--json` gives a script nothing parseable. Also, 64 covers both "you mistyped a flag" and "this spec is tampered". Scripts cannot tell them apart.
Fix: with `--json`, every non-verdict exit prints one object on stdout: `{"error": {"code": "spec_unsigned", "message": "...", "fix": "..."}, "verdict": null, "complete": false}`, and the same text on stderr. Stable `code` strings are part of the documented JSON contract: `usage`, `spec_parse`, `spec_unsigned`, `spec_signature_invalid`, `spec_key_unknown`, `internal`, and so on. A partial result from exit 70 sets `"complete": false` so nobody mistakes it for a finished run.

**S5. ADR 0008, decision 1: unknown field versus unknown id.**
Problem: "the check id or a field is unknown" both become `Skipped`. A typo (`min_memory` for `min`) in a known check would silently turn a required check into "needs a newer rdy". The reason text also gives no fix.
Fix: `run` still skips (so a newer spec runs on an older rdy), but the reason names the thing: `unknown field 'min_memory' for host.memory (needs a newer rdy, or a typo)`. `spec lint` reports the same as a warning with line and column and a did-you-mean from the known field list. Fix line for the not-in-build case: `Install a newer rdy, or ask the vendor to mark this check as warn.`

**S6. 00-overview and ADR 0002: `--key` plus `--trust-key` on `run` is confusing.**
Problem: ADR 0002 decision 4 has the customer pass `--key` on `rdy run`, the CLI prints a fingerprint and asks to pin it, and non-interactive runs need `--trust-key`. One flag supplies a key, another pins it, and `run` has a hidden side effect on the trust store. A command that checks an environment should not write trust state.
Fix: pinning only happens in `trust add`.
- `rdy trust add <product> --key <pubkey file or base64>` prints the key id and fingerprint, asks `Trust this key for acme-platform? [y/N]`, and with `--yes` does not ask. In a non-interactive session without `--yes` it exits 64 with a fix line.
- `rdy run <spec> --key <pubkey>` verifies for this run only and persists nothing. It is the one-shot path.
- Drop `--trust-key`. Edit ADR 0002 decision 4 and the ticket "rdy verify command and refuse-unsigned behaviour" to match.
- Signature location: the sidecar is `<spec>.minisig`. Add `--sig <file>` for when it lives elsewhere. Missing sidecar gives `error: no signature found at acme-platform.yaml.minisig` and `fix: ask the vendor for the .minisig file, or run with --allow-unsigned`.

**S7. ADR 0005, decision 3: the `--allow-exec` flow needs a defined shape.**
Problem: "lists every command a spec would execute and refuses without `--allow-exec` or an interactive yes" is good, but three cases are open: non-interactive, `--json`, and what the verdict is when the user refuses.
Fix: the listing is the same output as `rdy run --dry-run` (see C3), so build it once. Interactive: print the list and ask `Run these 2 commands? [y/N]`. Non-interactive or `--json` without `--allow-exec`: no prompt; the exec checks are Skipped and required ones follow the M1 rule above (NOT READY), with `fix: read the list above, then rerun with --allow-exec`. An unsigned spec that contains `custom.exec`: `error: this spec runs commands and is not signed. rdy will not run them.` with the fix `ask the vendor to sign the spec`, exit 64 (`--allow-unsigned` never implies `--allow-exec`, as the ADR says).

**S8. ADR 0008, decision 4: exit 64 for a tampered signature.**
Problem: the exit codes are fixed, so 64 stays, but the stderr line must make the difference between a typo and a failed signature obvious. A tampered spec is a security event, not a usage mistake.
Fix: different first line and code. Usage: `error: unknown flag --keey`. Signature: `error: the signature on acme-platform.yaml does not match the file. It may have been changed after signing.` with `fix: get a fresh copy and its .minisig from the vendor. Do not run this file.` Document the code in the S4 table.

**S9. Progress and non-TTY behaviour is not specified anywhere.**
Problem: 00-overview says `indicatif` on stderr. Progress bars in CI logs and pipes are noise.
Fix: in 07: progress only when stderr is a TTY. Otherwise one plain line per finished check, in the same format as the final list. `NO_COLOR` set (any value), `TERM=dumb`, or stderr not a TTY turns colour off; `--color auto|always|never` overrides. Not an ADR change; recorded here so rust-engineer does not invent it.

### Nits

- **N1. ADR 0003, decision 3.** The text says escaped as `<`, `>`, `&`, which shows the characters unchanged. The ADR means the `<`, `>`, `&` JSON escapes. Write them out so the ticket is unambiguous.
- **N2. ADR 0003, decision 3.** "Uploading the HTML alone gives the portal everything" is convenient but means the portal parses JSON out of an HTML file a customer may have edited. Security-reviewer should confirm the portal validates it as untrusted input, and the docs should say the JSON file is the supported upload.
- **N3. ADR 0003, decision 5.** Add `<html lang="en">`, a `color-scheme` meta so dark mode applies before first paint, and heading levels in order. Cheap accessibility wins; add to the report ticket exit test.
- **N4. ADR 0011, consequences.** "cargo-dist artefacts are `rdy-<target>.tar.xz`" conflicts with doc 06, which sets `.tar.gz` (busybox hosts may lack xz). Change the ADR text to `.tar.gz`.
- **N5. ADR 0011.** `rdy version` and `rdy --version` should both work. Specify `rdy 0.1.0-alpha.3 (abc1234 2026-12-01)` on stdout, and `rdy version --json` for bug reports. I will put this in 07.
- **N6. ADR 0008 consequences.** The line "so a spec full of unknown ids can never be `Ready`" stays true under the new rule and is stronger: it cannot be READY with warnings either if any are required.
- **N7. 00-overview, week 2.** "lists every check as Skipped 'not built yet'": the reason string in ADR 0005 is "needs a newer rdy". Pick one. In week 2 itself it is not a newer-rdy problem, so keep "not built yet" for that alpha only and note it.
- **N8. ADR 0005 context.** "acmectl preflight" and "port 7070" are fine and synthetic. No change.

## Command names: what stands and what changes

00-overview lists `run`, `verify`, `spec lint`, `spec sign`, `spec keygen`, `trust add|list|remove`, `version` for M1; `bundle`, `upload`, `report` for M2; `self-update` and `spec init` for M3. These are verbs or verb groups and match my rules. Nothing needs renaming. Two decisions:

- `rdy verify <spec>` stays top level (the plan names it in build step 6). `rdy spec --help` ends with a see-also line pointing to it, so nobody who just ran `spec sign` hits a dead end. No alias.
- `trust` is a noun group, like `git remote add`. It stands. It is the only noun group; do not add more.

## Final command names for 07-cli-ux.md

```text
rdy run <spec>              run the checks, write reports, print the verdict
rdy verify <spec>           check the spec's signature only; runs no checks
rdy spec lint <spec>        check the spec file; line and column errors
rdy spec sign <spec>        write <spec>.minisig with a secret key
rdy spec keygen             make a signing key pair (secret key is password protected)
rdy spec init               [M3] start a new spec from a template
rdy trust add <product>     pin a vendor key for one product (asks, or --yes)
rdy trust list              show pinned keys
rdy trust remove <product>  unpin (use --key-id when a product has two keys)
rdy version                 version, commit, date; --json for bug reports
rdy bundle <spec>           [M2] build a redacted diagnostics bundle
rdy upload <file>           [M2] send a report or bundle, after showing what leaves
rdy report <result.json>    [M2] re-render HTML from a result file
rdy self-update             [M3] today prints the install command only
```

Global flags: `--color auto|always|never`, `-h/--help`, `-V/--version`. `NO_COLOR` is honoured. `run` flags: `--allow-unsigned`, `--key <file>`, `--sig <file>`, `--json`, `--out-dir <dir>`, `--no-report`, `--kube-context <name>`, `--timeout <secs>` (per-check override), `--dry-run`, and in M3 `--allow-exec`. `--token` is M2 and later. Provisional until I land the full text in 07.

## Things a user would find confusing (collected)

1. A required check that did not run ends the run as `READY with warnings` (ADR 0008 as written). Fixed by M1.
2. Two flags (`--key`, `--trust-key`) that both touch keys, and a `run` that changes the trust store. Fixed by S6.
3. Two spellings for the same status across terminal and HTML. Fixed by S3.
4. Exit 64 for both a typo and a tampered spec. Fixed by S4 and S8.
5. A read-only working directory gives no verdict at all. Fixed by S1.
6. `--json` on a failure gives nothing parseable. Fixed by S4.

## Verdict

**Request changes**, driven by ADR 0008 (M1, M2) and the file-name rule in ADR 0003 (M3). Three must-fix items. Every item is a short edit. After they land: approve 0003, 0005, 0008, 0011 with the nits above.
