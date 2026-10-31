# Correction-34 list (from this session's reviews; PR numbers are new-repo numbers)
1. M1-117 drops its base-move clause: M1-174 (PR #18) moved base-firewalld and base-ufw to envs/ and deleted LOADER_PENDING. 08 (~line 138) saying envs/ may hold bases stays with M1-117.
2. M1-155 (net.dns direct lookups) owns the Azure nameserver door: the SystemResolver peer class may reach 168.63.129.16 on port 53 (UDP and TCP) only when the address came from the OS nameserver list; the facade reads the list itself and the class takes no address argument from the check; spec hosts on any port and ports 80 and 32526 stay refused; IPv4-mapped and NAT64 forms stay outside the door; on GCE the nameserver 169.254.169.254 is Skipped too ("nameserver in a refused range"). Its exit test names the door and the Skipped text (PR #17 reviews, SEC-17-1, SEC-17-4).
3. M1-087 (exit-code golden suite) gains: a 65-host spec run with `rdy run` exits 64 (PR #17 review; `rdy spec lint` exits 2 by design, 07 C.8).
4. New M1 core ticket M1-177 (check-author, 2 h, week of the other host fixes, before M1-138; M1-138 depends on it): host check fixes from the M1-174 and M1-149 reviews (PR #18, PR #20):
   - host.memory: `partial` whenever a cgroup limit file is unreadable (unreadable > 0); regenerate `host.memory/cgroup-unreadable`.
   - host.security_agents: no `partial` on a positive forbid hit (`unreadable-comm`).
   - wording: host.lsm enforcing-other-denials count and "1 of the denials were"; firewalld "6443/tcp and 10250/tcp are accepted"; firewall `ports` evidence sorted numerically.
   - 03 edits: host.memory gives error on garbage or no /proc; `swap: forbid` not `off`; security_agents limited view rule as built; firewalld source-bound zone warns; missing os-release warns.
   - coverage cases: os amazon-linux-2 missing a `rhel` list; dotted-prefix note (Alpine 3.19 vs 3.19.1); a spec listing a derived id; cpu `recommended_cores` and an `arch` mismatch; lsm mode outside `allow` from the configured value, window truncation, `allow: []`.
   - expect.rs `a_result_that_differs_from_the_golden_fails` must not break under `UPDATE_GOLDENS=1` and must expect the golden-diff text.
   - host.sysctl: `fixtext::check` on the "Copy it to" and `/run` fix outputs; a check that every case directory is in `cases()` using `rdy_engine::testing::fixture_cases` (from PR #7).
5. M1-172 follow-up (owner: M1-177 or a new 0.5 h row, architect's call): rdy-spec `SysctlName::canonical` uses the first-separator rule (`a.b/c.d` style), and the duplicate check in `expect_once` uses it (PR #20 review).
6. M1-080 owns the 5 MiB page cap and the "N more entries are in the embedded JSON" line (07 D.4) once M1-078 (PR #19) is in; already noted as a deferral.
7. M1-081 owns the print banner's `position: fixed` (07 D.3) with its top padding, and the print page break before the action log (07 D.3) (PR #21, PR #22 reviews).
8. Owner for `required by <product>` on an unrun required check (07 D.7): it was assigned to M1-080 by M1-077's progress line but the row lacks it. Give it to M1-081 or M1-140, architect's call (PR #22 review).
9. 07 Appendix A gains the legend and the rule sentences for `rdy run --help` (07 D.7), and the M1-029 help snapshot updates; owner a cli-ux ticket (M1-143 or M1-130, architect's call) (PR #21 review).
10. M1-141 gains: `scripts/check-html-escapes.sh` counts `json` tokens per whole template tag so `{{ json ~ json }}` and `{% let a = json %}{{ json }}` count 2 (PR #19 review).
11. M1-094's 12-progress line: "a 65-host spec exits 64 at the `CliError` level" and "Carries: M1-087". 05 line ~126: replace "sits on a link-local address" with "a translator would have to sit inside that cloud network" (PR #17 review).
12. correction-33 nits: M1-115 says "three" OpenShift label-sync details; Done log says "the YAML and JSON env-list forms"; week 12 demo row adds "a hung check exits 70".
13. M1-115 gains the PR #7 (M1-114) nits: admission.rs module doc mentions the forbidden skip; engine-forbidden v1 fixture unread (drop or keep on purpose); `FoundGroup.version` doc; 12-progress "#151" wording.
