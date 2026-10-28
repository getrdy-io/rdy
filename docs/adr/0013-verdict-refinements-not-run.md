# ADR 0013: Verdict refinements: what counts as not run, and the one thing that never counts

- Status: Proposed (2026-10-28, applies the security-reviewer review of 02 and 01 section 5.3; security-reviewer re-review pending)
- Date: 2026-10-28

## Context

ADR 0008 decision 3 makes the verdict NOT READY, exit 2, when a `severity: block` check is Skipped,
Timeout or Error. 01-spec-format.md section 5.3 and 02-engine-design.md add cases ADR 0008 does not
cover: an OS on which a check makes no sense, a run where nothing was measured, a severity or status
value this rdy cannot read, and a check that passes on partial data. The security review of 02
(MF-06, SF-08) found that letting check code declare "not applicable" turns one bug into a false READY.
A false READY is the worst failure this tool has; a false NOT READY costs one rerun.

## Decision

1. **Not run** means status `skipped` (any `skip_kind` except `not_applicable`), `timeout`, `error`, or
   a status value this rdy does not know. A required check (decision 3) that did not run makes the
   verdict `not_ready` with `verdict_reason: required_check_not_run` when nothing blocked.
2. **Only the vendor can make a check not count.** `skip_kind: not_applicable` comes from one source:
   the spec's `os` list leaving this OS out. Engine and check code cannot produce it. A check with no
   data source on this OS is `not_yet_on_os` and counts. A requirement met by absence (a spec that
   allows `disabled` SELinux, run on Windows) is a `pass` with a note, reviewed per check.
3. **Required** means `severity` is not `warn`. An unreadable or unknown severity counts as `block`.
4. **Partial passes.** A check at level Pass with a `partial` result on a required check becomes `warn`
   with "not verified: <what is missing>", unless every missing want is marked `evidence_only` in the
   check's `CheckInfo` (it can only add detail, never change the level). The engine applies this, not
   code review.
5. **Nothing verified.** If no check reached `pass`, `warn` or `block`, the verdict is at least
   `ready_with_warnings` with `verdict_reason: nothing_verified` (01 section 5.3).
6. `rdy_spec::result::verdict()` is the one implementation. A table test covers every severity and
   status pair, unknown values, the partial rule and the empty run.

## Consequences

- A cross-platform spec reaches READY on each OS only through the vendor's `os` lists.
- macOS and Windows runs of Linux-only host checks are NOT READY until the vendor scopes them or the
  data sources land. That is true, and the fix text says so.
- Partial runs as non-root show more warnings. The capabilities section tells the operator which need
  would complete them.

## Alternatives considered

| Option | Why it lost |
| --- | --- |
| Check code may return not applicable (02 revision 1) | One wide condition or bug hides a required check. Only the spec author may relax a requirement. |
| Nothing verified is `not_ready` (security-reviewer's conservative choice) | 01 and the coordinator chose `ready_with_warnings`; with decision 2 an all-not-applicable run can only come from the vendor's own `os` lists, and exit 1 still fails a strict gate. Revisit if a design partner gates on exit 1. |
| Nothing verified is `ready` | Exit 0 for a run that measured nothing. |
| Partial passes stay `pass` and code review polices them | Review misses things; one engine rule does not. |

## Tickets implied

- [M1] Define result model and verdict mapping in rdy-spec | owner: rust-engineer | est: 3.5h | depends on: Define public spec types in rdy-spec | exit test: a table test covers every severity and status pair, unknown severity and status values, the partial rule, the not_applicable source rule and the empty run, and asserts verdict_reason and exit codes.
