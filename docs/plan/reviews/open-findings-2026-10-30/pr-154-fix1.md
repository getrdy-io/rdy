# PR #154 M1-057 fix round 1. Branch m1/057-run-wiring, head f48617e.
Reviews: findings/154-code.md (code N, CHANGES: two red CI legs) and findings/154-sec.md (SEC-154-N, approve with fixes).
First `git merge origin/main`. Every commit, merges included, carries `Signed-off-by: Rdy <dev@getrdy.io>`.
1. Code 1 (high, lint red): crates/rdy-engine/src/lib.rs:17 plain backticks for `engine::Engine` (feature-gated module).
2. Code 2 (high, windows red): run_cmd/tests.rs root-fix test asserts the Windows elevated-prompt text under cfg(windows) and the sudo text under cfg(unix). Then look for other Windows-only failures nextest hid (read every test that asserts fix text, paths, modes or `sudo`).
3. SEC-154-1 (medium, product rule 3): when the spec is unsigned (no sidecar, `--allow-unsigned`), print one fixed stderr line before the folder is made: `warning: this spec is not signed. rdy cannot tell who wrote it or if it was changed.` Do not name the flag. Binary test for the line (and its absence for a signed spec).
4. Code 4 (medium): reconcile the plan's skip words with `SkipWhy` so the run's `unknown_check` and `unsupported_spec` fix lines carry the 01 section 5.2 did-you-mean hint, with a test.
5. Code 5 (medium): the M1-062 carry: a real-binary `by_rule` test at `RUST_LOG=trace` and the PC-43 tracing-field canary on `rdy run` (canary absent from stderr, the log and every file in the report folder).
6. SEC-154-2: the secret-order test asserts the canary is not on stderr, adds an `--out-dir` run scanning every file in the folder, and moves the log check into a `tests/` binary with a global subscriber (sees spawn_blocking threads). May share code with item 5.
7. SEC-154-3: in-process `rdy run --allow-unsigned` tests for a sidecar that is a directory, a garbage sidecar, and (unix, non-root) a mode 000 sidecar: each exits 64 and makes no folder.
8. Code 6: a runnable entry with no spec entry or a missing item pushes `unfinished_result`, never dropped; test that a missing required check cannot yield READY.
9. Code 7 + SEC-154-5: make the run id before `open_report_dir`; a failure after the folder is made (redaction, writer) leaves no empty folder (remove it if empty), test.
10. Code 8: `stdout.flush()` after `write_json`, error mapped like the writer's.
11. Code 9: print the macOS inheritable-ACE residual note too (M1-036 text).
12. SEC-154-6: INV-10 doc text says declared secret env reads come before the snapshot; record the declared variable names (never values) as one run-level action entry, if the action log allows it without breaking `set_proxy`; else say why in 12-progress.
13. SEC-154-7: `shell_word` prefixes `./` to a leading `-`; docs list "spec path as typed in the root fix" among what stays in a report.
14. Code 10: assert "runs no check" in that test. Code 11: comment that `--kube-context` is recorded only until M1-107. Comment in exit_codes.rs/error_json.rs that M1-126 replaces `verify` as the not-built command.
15. Do NOT wire the watchdog (code 3 / SEC-154-4): the coordinator files a backlog row. In 12-progress, point deferral 1 at "the watchdog row from correction-33".
Run the full gate (workspace tests, clippy -D warnings, both engine no-default-features clippy and `cargo doc -p rdy-engine --no-default-features` with -D warnings, fmt, deny, xtask docs --check, docs-lint, schema --check, goldens check).
16. README (if #155 merged first): update its Status and Build from source so they say `rdy run` works on main (with --allow-unsigned) and drop the 'exits 70 today' line.
17. README nits from #155 confirm: add host.firewall and k8s.access to 'Works on main today', rewrap README.md line 75; if NOTICE and TRADEMARKS.md exist on main, make them links.
