# Open PRs at the 2026-10-31 pause: what each still needs

Every PR below still needs main merged in, a clean `mergeable_state`, and `ci-ok` green on the head
before it merges. Docs-only PRs merge without waiting for `ci-ok` (founder rule, 2026-10-31). Findings
not listed here were fixed in the PR or carried to a ticket named below.

## Approved, merge in this order

1. #18 M1-174 (expect.json for the host cases). Approved by code, security and check-author. Main is merged
   in at a9e3293, and CI was queued at the pause. Carries to M1-177: `a_result_that_differs_from_the_golden_fails`
   breaks under `UPDATE_GOLDENS=1`.
2. #20 M1-149 (host.sysctl). Code approved with nits at 8687369. Carries to M1-177: run `fixtext::check` on the
   "Copy it to" and `/run` fix text; check that every case directory is in `cases()` (needs
   `rdy_engine::testing::fixture_cases`, now on main); the 12-progress line says 19 cases, but it is 23. The rdy-spec
   `SysctlName::canonical` fix is M1-178 (correction-34).
3. #19 M1-078 (embedded result JSON). Code and security approved at 97c86df. Carry to M1-141: count `json`
   tokens per whole template tag, so that `{{ json ~ json }}` and `{% let a = json %}{{ json }}` count as 2.
4. #21 M1-079 (print, legend). Code approved with nits at ca0fc4f. When main is merged in after #19,
   regenerate the goldens with `UPDATE_GOLDENS=1`. Do not hand-merge them.
5. #22 M1-080 (fix label, action log). Security approved. Code confirm says changes (high): `ActionKind::ReadLink`
   is missing from `kind_words` and `detail` in `report/html/view/actions.rs`. Add
   `ReadLink => ("Read where a link points", "link reads")` and the path arm in `detail`, and replace both `_`
   arms with the explicit open variant. Add a `read_link` row test. Nit: `connect` puts host and port in one
   `<bdi>`. Do this round when main is merged in after #19 and #21 (regenerate the goldens), then run a quick
   confirm. Also recheck that the "in the embedded JSON" line is true once #19 is in.
6. #23 M1-150 (host.container_runtime). Code and security approved at 86ddf0a. Carries to M1-177: a
   concurrency test with three slow sockets; the `from_io` ConnectionRefused hint wording for TCP, UDP and TLS;
   sock.rs docs ("at most", the Errors list); a changelog mention of `unix_get_within` and `ConnectionRefused`;
   "Run rdy as root" appears twice in containerd-no-access, so gate it on `!root`; rename the sock test; the
   `unix_get_within` long-timeout test needs a reply delay above `UNIX_TIMEOUT`.
7. #25 M1-072 (host.ports). Code and security approved at a25fe06. Nit: the comment at ports/tests.rs:129.
8. #26 M1-151 (host.cgroups). Code and security approved at 65f8e0b. Carries to M1-177: on a hybrid host whose
   v2 lists are unreadable, a hierarchy-0 controller should warn, not block; send the EL 10 fix text through
   `fixtext::check`; rename the "SEC-26-1" note id in 12-progress.
9. #27 M1-152 (host.kernel). Code approved with nits at e3f9e00. Carries to M1-177 (add them to its row in the
   #24 pre-merge round):
   - a `scan_dep_file` test with a generated modules.dep of 1.5 MiB and of 2.5 MiB;
   - read `modules.builtin` even when modules.dep is missing;
   - name both module directories in the message;
   - put the `ID_LIKE` hint in the blocking message;
   - give the unknown and the hostile release separate messages;
   - note that `-rc` meets `min`;
   - document that `distro_min` depends on the kernel flavour.
10. #28 M1-157 (net.mtu). Code and security approved at 083ce8f. Pre-merge round (the same builder, together
    with the main merge):
    - SEC-28-2: a hostile link `sys/class/net/evil -> ../../devices/virtual/dmi/id`, with an assert that
      reading `/sys/class/net/evil/board_asset_tag` is Denied end to end. Fix the misleading `..` comment.
    - Code nits: a `vpd`-through-`device`-link test; pass `mac` to `split` in `sys_class_device`; a changelog
      line for the read-policy rule.
11. #24 correction-34 (docs only, merge without CI). Approved with nits. Pre-merge round by rust-architect,
    together with the main merge (take this branch's totals, recompute from the rows with `totals.py`):
    - Move M1-175 to week 22, and M1-177 to week 24 if needed, so that no week is over 15 h.
    - M1-177: if M1-149 is not merged when it starts, its sysctl items move to M1-149's exit test.
    - Raise M1-177 to 3 h, or say that the code is already built.
    - Add to M1-177 the carries listed in items 1, 2, 6, 8 and 9 above, and that host.cpu declares
      `/sys/class/dmi/id/product_name` without its `/sys/devices/virtual/dmi/id` real path.
    - M1-157's row and 03 line 813: `min_mtu: 1400` becomes `1450` (1450 minus 50 is 1400, which fits). Log
      the 03 rule additions from #28.
    - Item 11 of `c34-list.md`: M1-094's progress-line wording, and 05 line ~126 ("a translator would have to
      sit inside that cloud network").
    - 07 lines 138, 2439 and 2444: the Tip example names host.ports as needing root. It no longer does
      (evidence-only want). Fix the example.
    - SEC-28-3, owner M2-110: deny `address` and `perm_addr` under `sys/class/net/*/` and `sys/devices/**/net/*/`.
    - The two tests that flaked once under parallel local load are owned by qa: the fixtext "`ip` must not be a
      fix command" test and `probe::tests::link_reads_fold_and_drop_like_file_reads`. Watch CI.

## Not finished: rerun from the brief

- M1-161 (k8s.namespace), branch `m1/161-k8s-namespace`, head 76eb627. The builder was stopped while
  running its final gate. No PR is open. On resume, run the full gate on that head (or rerun the builder
  with "finish M1-161 from the pushed head"), then open the PR and run the code review and the k8s-expert
  review.
- M1-148 (host.time_sync). Nothing was pushed. Rerun from the brief.
- README after M1-057 (founder ask). Nothing was pushed. Rerun devrel: say that `rdy run` works on main,
  link NOTICE and TRADEMARKS.md, and list only the checks a real main build runs (pr-154-fix1.md items 16
  and 17).
