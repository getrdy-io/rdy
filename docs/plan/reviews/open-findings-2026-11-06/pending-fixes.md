# Open PRs at the 2026-11-06 pause: what each still needs

Main is at 3c49a5a (#42). Every code PR below still needs main merged in, a clean `mergeable_state`, and
`ci-ok` green on the head before it merges. A docs-only PR merges without waiting for `ci-ok`, unless it
touches a doc that a test reads (see "Process lessons" in the runbook pause state). Review findings not
listed here were fixed in the PR or carried to a ticket named below.

## Merge order

The order of the 2026-10-31 list comes first, then the PRs opened in this session.

1. #26 M1-151 (host.cgroups). Approved. Main is merged in at 598af68, and the host family conflict is
   resolved: the stub list is `host.time_sync` and `host.kernel`. At the pause, CI was green on every leg
   except the two macOS legs, which were still running. Merge when `ci-ok` is green. If main moved, merge main
   again.
2. #27 M1-152 (host.kernel). Approved with nits at e3f9e00. Needs a main merge, and the host family files
   will conflict. Resolve the same way as #23, #25 and #26: take main's `family.rs`, `family/tests.rs`,
   `lib.rs` and the fixtures README, then apply this branch's changes: drop the `KERNEL` static, use
   `kernel::INFO`, build the check, drop `host.kernel` from the stub list, append the branch's family test,
   and add `host.kernel/` to the README list. Convert any lint-wall include prefix to the `&[&str]` list
   form. Then run the full `cargo test --workspace` before pushing. Its carries are already in M1-177's row
   (#24).
3. #28 M1-157 (net.mtu). Approved. The pre-merge round is done at b789185 (SEC-28-2 confirmed by
   security). Needs a main merge and `ci-ok`. Carry: a per-interface "not read" note on a hostile link,
   instead of ending the check on a denial (M2, no id yet).
4. #24 correction-34 (rust-architect). Approved. It needs a final main merge:
   - Recompute the totals and week sums from the rows. Corrections 35 to 41 landed after it. With #24, M1 is
     180 tickets.
   - Resolve the Done log and the calendar notes.
   - It is no longer docs-only: its 07 C.16 rewrite (host.lsm, host.firewall) breaks the test
     `the_c16_text_is_in_the_plan` in `crates/rdy-cli/src/terminal/tests.rs` and the C.16 terminal golden,
     which M1-086 (#42) pins. A cli-ux builder updates both in the same branch. Then wait for `ci-ok`.
   - Merge commit 2aa4b68 has no Signed-off-by line. The squash merge carries the signed message.
5. #35 M1-148 (host.time_sync). Approved by code and security at 35bb955. Needs a main merge (host family
   conflicts: time_sync becomes real, the lint wall uses the list form) and `ci-ok`. Its env harness
   PENDING row is owned by M1-179.
6. #39 M1-059 (`--no-network`, `--jobs`). Approved by code and security at 21e76ef. After #35 merges, do
   `fix-39b.md` in this folder: host.time_sync treats `RULE_NO_NETWORK` as soft and skips chronyc offline,
   `ProbeHub` fails closed, direct http and tls offline tests, the Denied entry wording, and an exhaustive
   match. Then merge main and wait for `ci-ok`.
7. #45 M1-095 (net.egress). Approved by code and security. Main was merged in at 42fdf1e, before #42 landed.
   Merge main again and wait for `ci-ok`. After #39 and #45 are both in, rerun the `root_*` `--no-network`
   strace test with net registered.
8. #47 M1-058 (Ctrl-C). Approved by code and security at 4d689ca. Needs a main merge and `ci-ok`. Nit:
   `let restored_again = restore(); let _ = restored_again;` in `interrupt.rs` becomes `let _ = restore();`.
9. #41 M1-083 (report goldens). Approved by security, and by code with nits, at 7450b88. In its main-merge
   round:
   - Match `src=` with a whitespace-normalised boundary.
   - The leak test checks the shown text too: cut cases assert the fragment is gone, and whole cases assert
     the secret is there before redaction.
   - Fix the comment that says "a clean page is the redactor's doing" for the aws and url cuts.
   - #42 added the same three fixture files under `tests/fixtures/results/plan-07/`. Keep one copy.
   - The static checks now also scan #22's action-log goldens.
10. #48 M1-160 (k8s.admission webhooks). Approved by code, k8s-expert and security at e84fa56. ADR 0042 is
    accepted. Do `fix-48b.md` in this folder: the doc wording in `rules.rs`, the 12-progress line, and
    refusing `(` in `LabelEquals`. The builder was stopped mid-edit and pushed nothing. Then merge main, wait
    for `ci-ok`, and check that the kind workflow is green.
11. #49 M1-180 (os-release). Code review says changes are required. Do `fix-49b.md`: merge main (never
    rebase), resolve `run_cmd.rs` against M1-086's `host_os_family()`, add the header tests (`rhel 9.4`, and
    `linux` when there is no file), and rewrap one doc line. Then re-review.
12. #30 README. Approved at b65ffbb, and main was merged in at 1144636. Its CI was cancelled. Before it
    merges, devrel rechecks the README against main:
    - M1-086 now prints per-check output, but the README still says it does not.
    - net.egress registration lands with #45, and #45's C7 edits the same README lines.
    Then merge main and wait for `ci-ok`. It also edits an example spec comment.
13. #1 and #2: Dependabot. Leave them for the founder.

## Not pushed: rerun from the brief

- M1-162 (k8s.dns): the builder was stopped and nothing was pushed. Rerun from the brief with the M1-161
  lessons (the `live_cluster.rs` GRANTED list and the derived count; the ConfigMap read kept minimal).
- M1-087 (exit-code golden suite): stopped, nothing pushed. Rerun. Correction-34 (#24) adds "a 65-host spec
  run with `rdy run` exits 64".

## Next tickets

Core first, in id order, when their dependencies are on main:

- M1-081 (ready now: M1-079 and M1-080 are merged).
- M1-082 after M1-081.
- M1-088 after M1-087.
- M1-096, M1-099 and M1-117 after #45.
- M1-126 after M1-087.
- M1-177 and M1-178 after #24.
- Then M1-097 and M1-098, M1-100 and M1-101, M1-107, M1-113, M1-115, M1-116, M1-118, M1-119,
  M1-127 to M1-130, M1-132 to M1-139, M1-141 and M1-175.

Non-core: M1-140, M1-142, M1-143, M1-153 to M1-156, M1-158, M1-159, M1-162 to M1-167, M1-173, M1-179.
