# PR #153 M1-169 fix round 1. Branch m1/169-read-link, head 89f9bb0.
Reviews: findings/153-code.md (code N) and findings/153-sec.md (SEC-153-N). Both approve with fixes.
First `git merge origin/main` (code 1, high: conflict in the probe.rs module doc against M1-093; keep main's paragraph, add `read_link` (M1-169) to its list, drop the "M1-169 adds both" bullet). Every commit, merges included, carries `Signed-off-by: Rdy <dev@getrdy.io>`.
1. SEC-153-1 (medium) + code 4: in `read_link_through_anchor` (a) lstat `real_parent` and compare dev and inode with `fstat(anchor)`, refuse with `RULE_CHANGED` on mismatch; (b) if `fstatfs(anchor)` is procfs (`PROC_SUPER_MAGIC`) and the real path does not start at `/proc`, refuse with `RULE_PROC`. A unit or live test for each (an rbind or a symlink through another mount if you can do it unprivileged in a test; otherwise a seam test of the decision function).
2. SEC-153-2 (medium, pre-existing): do NOT fix `locate` here; add it as a named residual in 05 I5 (`locate` trusts the `/proc/self/fd` real path; a directory in another mount namespace reads back under a non-`/proc` name; must be fixed before M2 `custom.file`). The coordinator adds an M2 ticket in a backlog correction.
3. SEC-153-3 (low): skip `FD_WALK` in both prefix loops (policy.rs and testing/fixture_run.rs); test that `read("/proc/<pid>/fd/x")` and a real `/proc/1234/fd/3` content read are refused with `RULE_OUTSIDE_READS`.
4. Code 6: the fixture audit ties path shape to call kind (3 components for `read_dir` of `/proc/<pid>/fd`, 4 for `read_link`), with a negative test.
5. Code 5: xtask checks `problems()` flags any check other than `host.ports` that lists `FD_WALK`, with a test.
6. SEC-153-4 (low): read `/proc/self` once when the live backend is built; refuse the own-process `ns/net` and `auxv` grants when it differs from `std::process::id()`; test the decision.
7. SEC-153-5 (nit): on Unix that is neither Linux nor macOS, `read_link_by_path` returns Unsupported (not a release target).
8. Code 3: a `#[cfg(target_os = "macos")]` live test: `read_link("/proc/self/ns/net") == Err(NotFound)`.
9. Code 2: keep Windows `Denied` (the M1 Windows file rule); the coordinator corrects the M1-169 exit test in the backlog. Make 12-progress say so plainly.
10. Code 7 / SEC-153-6: 12-progress line `[#153](https://github.com/getrdy-io/rdy/pull/153) | 2026-10-30`; ADR 0040 decision 5 says the target is read into memory then dropped; 03 process name from `comm`, not `cmdline` (ADR 0036).
11. Code 8: ADR 0040 status `Accepted, security-reviewed (PR #153)` (security-reviewer approved with fixes; the confirm round re-checks).
12. Code 9: rewrap doc comment lines over 100 columns (policy.rs:317, probe.rs:42, log.rs).
Run the full gate (workspace tests, clippy -D warnings, both engine no-default-features clippy runs, fmt, deny, cargo doc -D warnings, xtask docs --check, docs-lint, schema --check, goldens check).
