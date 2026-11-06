# PR #154 (M1-057) security review, head f48617e

Verdict: approve with fixes. No critical or high. Static review only: I did not build or run cargo (brief rule).

Sound: declared secrets go into the set before the first log event, the gate, the spec read and any check, and the log, errors and report share one set. A sidecar is always verified, whatever the flag. A sidecar that cannot be read is exit 64, never "unsigned". The folder is made after verification, through `OutputDir` (0700, no-follow, 0600 files). `spec.yaml` is the verbatim spec by design (ADR 0016). `fail_after_verdict` redacts again and exits 70. No sudo. `identity` comes from `Privilege::identity()`. No socket, no new crates, no `unsafe`.

Exit test: proven (binary test plus the in-process schema and skip asserts).

SEC-154-1 | medium | run_cmd.rs:95-116
`--allow-unsigned` with no sidecar prints nothing on stderr until M1-126/M1-130 (alpha.23). About 12 signed alphas break rule 3 ("loudly").
Fix: when the state is Unsigned, print one fixed stderr line before the folder is made: `warning: this spec is not signed. rdy cannot tell who wrote it or if it was changed.` Do not name the flag. Add a binary test that asserts the line. If the coordinator calls this a widening, file a correction row and put the gap in the alpha release notes.

SEC-154-2 | low | run_cmd/tests.rs (secret-order test)
The test drops stderr and uses `--no-report`. `set_default` is thread-local, so it misses `spawn_blocking` events.
Fix: assert the canary is not on stderr. Add an `--out-dir` run and scan every file in the folder. Put the log assert in a `tests/` binary with a global subscriber.

SEC-154-3 | low | run_cmd.rs:210-237
No run-level test of the sidecar refusals. The bad-signature test skips for root and on Windows.
Fix: add in-process tests with `--allow-unsigned` for a directory sidecar, a garbage sidecar and (Unix, non-root) a mode 000 sidecar. Each exits 64 and makes no folder.

SEC-154-4 | low | deferral (1), current_thread runtime
With no watchdog, a check that blocks the executor, or a blocked stdout, hangs `rdy run`.
Fix: file the promised row before merge, and run M1-043's hang test against `rdy run`.

SEC-154-5 | nit | run_cmd.rs:122-127
A `uuid_v4` failure, a redaction failure or a panic after `open_report_dir` leaves an empty folder.
Fix: make the run id first, and reuse the M1-058 cleanup.

SEC-154-6 | nit | lib.rs:100-115; probe.rs `add_declared_env_secrets`
The env read now comes before the gate, and it leaves no action-log entry.
Fix: fix the INV-10 doc text, and record the declared names (not values) as one run-level action entry.

SEC-154-7 | nit | engine.rs `fill_spec_arg`; text.rs `shell_word`
The root fix can carry a home folder path into a report that can be uploaded. A word with a leading `-` counts as plain.
Fix: put `./` in front of a leading `-`. List the path in the docs "what stays" list.

## Confirm (fix round 1, cbb5d89, head c4d8bf7)

Diffed `f48617e..c4d8bf7` in a scratch clone. The main merge (c4d8bf7) does not touch the run wiring. Static review only, no build.

- SEC-154-1 closed. `UNSIGNED_WARNING` prints only for `SignatureState::Unsigned`. It comes after `load_spec`, before the run id and the folder, and it names no flag. Tests show: once and first on stderr in the binary, before a failed folder, none on a refused spec, none for a signed spec with or without the flag.
- SEC-154-2 closed. tests/run_secret_order.rs uses a global subscriber, so `spawn_blocking` threads are covered. Each of its two runs uses a new canary and checks that the log saw events. It asserts the canary is absent from stdout and stderr. The `--out-dir` run scans every file in the folder.
- SEC-154-3 closed. Tests with `--allow-unsigned` cover a directory sidecar (`spec_unreadable`), a garbage sidecar (`spec_signature_invalid`), a missing `--sig` and a mode 000 sidecar. Each exits 64, makes no folder, never reads as `spec_unsigned` and prints no warning.
- SEC-154-4 open, coordinator action. 12-progress points to "the watchdog row from correction-33". correction-33 is not on main, not on this branch and not in any open PR. Gate: correction-33 (open PR or merged) must exist before #154 merges.
- SEC-154-5 closed. The run id is made before the folder. `discard_if_empty` runs on the redaction-failure and write-failure paths. It drops the handle, then calls `remove_dir`, which removes only an empty folder and never follows a link. A panic after the folder is made still leaves it; that is M1-058.
  - Nit: the remove goes by path, not through the held parent. If someone swaps the folder in that short gap, the worst case is that rdy removes an empty folder of theirs. Accept.
- SEC-154-6 closed.
  - The INV-10 doc says the env reads are the one thing before the gate.
  - `begin_setup` writes one run-level `env` entry: sorted names only, capped at 4000 chars. Outcome Failed on a refusal.
  - `has_entries` counts `next_seq > setup`, so `set_proxy` still works. Tests show a later probe entry still blocks it.
  - `begin_setup` is `pub(crate)`, and its doc limits it to text the engine owns.
- SEC-154-7 closed. `shell_word` puts `./` in front of a leading `-` (tested). The 04 SEC-31 "what stays" line now lists the spec path as typed. `RunOptions::spec_arg` says so too.

`RunHooks::families`: it cannot be set in the shipped binary. The value is a `fn` pointer, so no argv, env or file can supply it. `entry::run_live`, the only caller in the binary, passes `RunHooks::default()`, so it is `None` and becomes `registry::registry`. The same function feeds the secret registration and the plan, so the two cannot disagree. The privilege gate does not use it. Only code that links `rdy_cli` as a library, and so builds its own binary, can set it. That is not a trust boundary.
- Nit: add a test that greps src/entry.rs for exactly one `RunHooks::default()` and no other `RunHooks` construction under `src/`, so a later hook cannot be wired from env by accident.

New in this round, reviewed: the macOS residual note (accurate, ADR 0016 line 45). Did-you-mean hints come from the fixed reserved-id and field lists. Engine entries are never dropped: an orphan becomes a "Not finished" error that keeps the verdict NOT READY (tested). run_logging.rs shows a spec-path canary at `RUST_LOG=trace` does not reach stderr, stdout or the folder.

Verdict: approve once correction-33 exists (SEC-154-4). No new findings above nit.
