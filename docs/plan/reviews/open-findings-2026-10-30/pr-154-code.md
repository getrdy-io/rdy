# PR #154 (M1-057) cold code review, head f48617e

Verdict: changes required (two CI legs are red; both fixes are small).

1. High. crates/rdy-engine/src/lib.rs:17. `[`engine::Engine`]` is an intra-doc link to a module behind
   `runtime`, so `cargo doc -p rdy-engine --no-default-features` fails. CI `lint` is red (job 124166156762).
   Fix: plain backticks (`` `engine::Engine` ``), the way the `sched` line does it.
2. High. crates/rdy-cli/src/run_cmd/tests.rs:235-253. The root-fix test plans with `current_os()`. On
   Windows the fix is the elevated-prompt text, so `test (windows-x64)` fails at line 251 (job
   124166156651). nextest stopped at the first failure, so other Windows failures may be hidden. Fix:
   `#[cfg(unix)]`, or assert the Windows text under `cfg!(windows)`.
3. High (needs a backlog row, not code here). Watchdog not wired. 02 principle 7 and MF-02 make it the
   backstop. The merged M1-043 line in 12-progress says "M1-057 must" wire it. `entry` builds a
   current-thread runtime, so a check that never yields hangs `rdy run` forever. The same happens with
   `--json` into a stdout pipe that nobody reads. M1-088's exit test assumes the watchdog path. Owner: a
   new rust-engineer row, "wire the watchdog into rdy run", filed before merge. Its exit test is the
   M1-043 carry list plus the real-binary blocked-stdout exit-70 test. M1-088 and M1-058 depend on it,
   and it must land before 0.1.0. Folding it into M1-088 (1.5 h) is too big.
4. Medium. plan.rs:32, outcome.rs:54. Deferral (5): the run's `unknown_check` and `unsupported_spec`
   fixes lack 01 section 5.2's "did you mean". The runbook carry list names it for M1-057. Fix: do it
   here, or have the coordinator file a row.
5. Medium. M1-062 carry ("M1-057 must"): the real-binary `by_rule` test at `RUST_LOG=trace` and the PC-43
   tracing-field canary on `rdy run` are missing, and the progress line does not list them as
   deferred. Fix: add them to run_command.rs, or list them as a deferral with an owner.
6. Low. engine.rs:177-182 and 239. An entry with no spec entry, or a missing item, is dropped with
   `continue` or `?`. A missing required check could turn the verdict to READY. Fix: push
   `unfinished_result`, never drop.
7. Low. run_cmd.rs:115 vs 125 and 162. The folder is made before `uuid_v4` and the report redaction, so
   those errors leave an empty folder. Fix: make the run id before `open_report_dir`.
8. Low. run_cmd.rs:172. No `stdout.flush()` after `write_json` (M1-055 carry). Fix: flush, and map the
   error through `writer_error`.
9. Low. run_cmd.rs:293. M1-036 asked for the macOS inheritable-ACE residual note too. Only the Windows one
   is printed. Fix: add it, or list it as a deferral.
10. Nit. run_command.rs:293. The test name says "runs no check" but nothing asserts that. Assert an empty
    action log for checks, or rename the test.
11. Nit. run_cmd.rs:139. `--kube-context` is recorded in `run.options` but not acted on until M1-107.

## Sound
- The swap to `verify` in exit_codes.rs:162/177 and error_json.rs:102 is sound: `verify` is still not
  built (M1-126 todo). Add a comment that M1-126 deletes these tests.
- `run_code` order is right (hub, secrets, first event, snapshot, gate, spec), and the layer test would
  catch a move. The writer errors map to `report_write` and exit 70. Signatures are enforced with
  `--allow-unsigned`. Stubs never run. Docs and the changelog are done. Deny and linux-arm64 are green.

## Exit test
Proven on Linux (in process, plus the real binary: new folder, schema-valid single Report, 8 checks,
exit matches the verdict, identity, xtask reads `rdy_cli::registry`). Not proven on Windows until
finding 2 is fixed.
