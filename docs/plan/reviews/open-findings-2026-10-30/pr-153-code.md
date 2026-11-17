# PR #153 (M1-169) cold code review, head 89f9bb0

Verdict: approve with fixes. The policy and code are sound. It cannot merge yet: it conflicts with main and no CI has run.

## Findings

1. High. `crates/rdy-engine/src/probe.rs:42`. The PR conflicts with main (`mergeable_state: dirty`). The conflict is in the module doc, against M1-093 (#143). Head 89f9bb0 has 0 check runs, so no leg has built it. On macOS, `read_link_by_path` has never run. Fix: merge main and keep main's paragraph, adding `read_link` (M1-169) to the list and dropping the "`read_link`: ... M1-169 adds both" bullet. Then get all five legs green. The macOS legs run the `read_link_*` live tests through `read_link_by_path`.
2. Medium. `policy.rs:336` and `replay/tests.rs:2339`. The exit test says `/proc/self/ns/net` "is NotFound elsewhere", but Windows returns `Denied` (`RULE_WINDOWS`), and the test asserts that. An ADR line cannot change an approved exit test. Fix: have the coordinator record a backlog correction ("NotFound on macOS; Denied by the M1 Windows file rule on Windows"), or return `NotFound`. The first fits "Windows has no file reads in M1".
3. Low. `live/tests.rs` (no macOS case). "NotFound off Linux" is only proven through Replay. Fix: add a `#[cfg(target_os = "macos")]` live test that asserts `read_link("/proc/self/ns/net") == Err(NotFound)`.
4. Low (for security-reviewer). `live/files.rs:224-243`. The fd and ns rules go by path names. They miss a procfs mounted at a path with no `proc` component (`/mnt/hostproc/1234/fd/4`) and a bind mount of an fd directory. There, a check whose `reads` cover the mount gets non-socket targets back. The same gap already exists for `environ`. Fix: `fstatfs(&anchor)`. If `f_type == PROC_SUPER_MAGIC` and the real path does not start at a root `/proc`, refuse with `RULE_PROC`.
5. Low. `crates/xtask/src/checks.rs:51`. The ticket says "allowed only by the rule host.ports declares", but nothing enforces it. Any check can list `FD_WALK`. Fix: in `problems()`, flag any check other than `host.ports` that lists `FD_WALK`, and add a test.
6. Low. `testing/fixture_run.rs:225`. This is looser than the guard: a `read_dir` of `/proc/1234/fd/7` and a `read_link` of `/proc/1234/fd` count as declared. Fix: tie the path shape to the kind (`read_dir` takes 3 names, `read_link` takes 4).
7. Low. `docs/plan/12-progress.md:353`. It says `PR #TBD` and has no date. Fix: `[#153](https://github.com/getrdy-io/rdy/pull/153) | 2026-10-30`.
8. Nit. `docs/adr/0040-...md:3`. "Accepted, pending security review" is not a valid status. Fix: use `Proposed` until security-reviewer signs off, then "Accepted, security-reviewed (PR #153)", the same in README.
9. Nit. Doc lines over 100 columns at `policy.rs:317`, `probe.rs:42` and in `log.rs`. rustfmt will not catch them. Rewrap.
10. Note for M1-072. Every non-socket fd becomes a `denied` entry, so a host.ports run on a busy host fills its 1000-entry quota with denials. The ADR already passes this to M1-072. Keep that.

## Cross-platform (read from cfg gates)
- Windows: `files` is unix-only, and `Live::read_link` uses `unsupported()`. Policy and replay do not depend on the OS.
- macOS: `NOFOLLOW_ANY`, `getpath` and the `dead_code` `cfg_attr` follow the existing code in `files.rs`.
- No compile risk found.

## Exit test
Proven for these parts, on live Linux and Replay:
- A link is resolved under `reads` and gets one `read_link` entry.
- `ns/net` resolves on Linux.
- A link outside the prefixes is refused and logged.
- `FD_WALK` gates the walk, and only `socket:[N]` comes back.
- Other targets are refused, with the target absent from both the error and the log.
- Replay serves `symlinks`.

Not proven or pending:
- Windows `NotFound` (finding 2).
- Live `NotFound` on macOS (finding 3).
- security-reviewer sign-off.

## Confirm (fix round 1, head 90f918b)

Verdict: approve with nits, once CI is green on all five legs. CI was running when I checked: deny, dco and cosign passed; the test legs were queued or in progress. The PR is now mergeable, and `git merge-tree` against main is clean.

### Code findings 1 to 9
1. Fixed. Merge 6e01010 resolves the `probe.rs` doc correctly: main's paragraph, with `read_link` (M1-169) added and the "M1-169 adds both" bullet gone. The remaining gate is CI. `test (macos-x64)` is the leg that runs `read_link_by_path` and the new macOS test; the macOS arm64 leg only compiles.
2. Resolved by decision. Windows stays `Denied`. ADR 0040 and 12-progress say so plainly. Still open: the coordinator's backlog correction to the M1-169 exit test.
3. Fixed. `live/tests.rs` adds `the_net_namespace_link_is_not_found_on_macos`. It returns `NotFound` because `canonicalize` fails before any policy runs.
4. Fixed. `confirm_real_parent` (`files.rs`, Linux only) does two things:
   - it `lstat`s the name `d_path` gave and compares dev and inode with the anchor;
   - on procfs it refuses with `RULE_PROC` unless the path is under `/proc`.

   The seam test covers same inode, other inode, missing, `/mnt/hostproc` and the real `/proc/self/ns`. The anchor pins the dentry, so procfs inode numbers stay stable between `fstat` and `lstat`.
5. Fixed. xtask `problems()` flags `FD_WALK` outside `host.ports`, with a test.
6. Fixed. The audit ties path shape to call kind (`is_fd_dir` for a listing, `is_fd_link` for a link read), skips `FD_WALK` as a prefix, and has negative tests.
7. Fixed: PR link and date. The line has stale text (N1).
8. Fixed. The status is now "Accepted, security-reviewed (PR #153)". Revert it if the security confirm round finds anything.
9. Fixed at the spots named. Long lines that remain elsewhere predate this PR.

### Cross-platform cfg gates
- `with_own_proc` is marked `expect(dead_code)` under `not(any(test, all(feature = "runtime", unix)))`, and that expectation holds in every build:
  - Linux and macOS with `runtime` use it;
  - Windows with `runtime`, and `--no-default-features` with or without `testing`, do not;
  - every test build uses it (policy tests).
- `is_fd_dir` is behind `any(test, feature = "testing")`. The engine's self dev-dependency turns on `testing` for every `--all-targets` run, so there is no dead-code warning.
- `Live::guard_for` has a `not(unix)` branch.
- `read_link_by_path` is now limited to Linux and Apple. Other Unix gets `Unsupported` (not a release target).
- `fstatfs` and `PROC_SUPER_MAGIC` are Linux only (rustix 1.1.6), and `fstatfs` is already used in `files.rs`.
- No compile risk on the five targets.

### New findings
- N1. Low. `docs/plan/12-progress.md:353` still says "other Unix `realpath` plus no-follow open" and "tested on Linux only and was not run on macOS". After this round, the portable path is macOS only, other Unix is `Unsupported`, a macOS live test exists, and CI covers macOS. Fix: reword both.
- N2. Nit. `proc_links::this_machines_proc_self_is_rdys_own_process` asserts a fact about the host. It fails if the suite runs in a container that mounts the host's `/proc`. That is fine on CI, but rename it or note the assumption.
- N3. Nit. `read_link_through_anchor` calls `fs::fstat(&anchor)` twice (the nlink check and `anchor_stat`). Reuse one result.
