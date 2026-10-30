# PR #151 (M1-114, head 04cf3f3) cold code review

Verdict: approve with fixes. No code blockers. CI on 04cf3f3 is still running (the d5604fd run was cancelled). Merge only on green.

Exit test: proven. `a_restricted_namespace_blocks_a_privileged_need_and_the_fix_says_privileged`, `openshift_discovery_gives_the_scc_text` and `gatekeeper_and_kyverno_discovery_warn_with_names` (crates/rdy-checks-k8s/src/admission/tests.rs:191, 250, 289) run the real check over the mock with the guard and the INV-14 audit in front. They assert the exact paths, and the block maps to Status::Block.

## Findings

1. Medium. docs/plan/12-progress.md:243, deferrals (3) and (4). They point at M1-107 work that M1-107's row does not hold. The row builds only `VersionCheck` from params, and no row owns 03's read-review batch or `ClusterFacts`. M1-110 left the same gap. As it stands, nothing makes k8s.admission run in `rdy run`. Fix: add a backlog correction so M1-107 (or a new row) builds AdmissionCheck, StorageClassCheck and RbacCheck from `CheckParams` with the family namespace, and owns the read-review batch.
2. Medium. docs/plan/03-check-catalog.md:336-339. Some edits are corrections of fact: the key rename and dry-run removal already in 01, and OpenShift syncing only warn and audit. The rest are new thresholds:
   - warn and audit labels become notes on OpenShift and when enforce blocks;
   - a missing namespace is a note;
   - the SCC list read and its note;
   - no enforce label passes, and is "not verified" on RKE2.
   With an `scc` named, approved 03 warned on the synced warn label. Now it passes. The exit test, hours and deps are unchanged, so no backlog correction is needed. But the progress line calls all of this "corrected". Fix: list these changes as builder decisions in the progress line and get k8s-expert sign-off (or make them M1-115 items).
3. Low. scripts/gen-k8s-admission-fixtures.py:398 has a literal U+202E (a Trojan-source pattern). Fix: write `"A‮B"`.
4. Low. judge.rs:391 treats every warn and audit label on OpenShift as synced, even when the namespace sets `security.openshift.io/scc.podSecurityLabelSync: "false"`. Fix: keep the warn when sync is off.
5. Low. "The policies themselves" are deferred to M1-160. But M1-160's row and exit test name only webhooks and VAP, and ALLOWED has no clusterpolicies or constraints entries. Fix: add a backlog correction to M1-160, or move them to a later milestone in 03.
6. Low. 03 now says Rancher templates hide defaults, but only `+rke2` is detected (admission.rs:293). Fix: say "RKE2 only" in 03, or add a note.
7. Low. The facts dated 2026-10-30 (Kyverno 1.18/1.19, the RKE2 CIS exempt list `compliance-operator-system`) are past my cutoff. k8s-expert should confirm them in M1-115.
8. Nit. judge.rs:228: "Its policies" with two engines should be "Their".
9. Nit. engines.rs:67: hostile kinds sort ahead of real ones and push them out of the eight shown.
10. Nit. tests.rs:1026: the case list is hard-coded. Read the fixture directory so a new case cannot skip the audit.

## Checked and fine

- Naming: Kyverno and Gatekeeper are projects Rdy checks. Main's 03 and the M1-114 title already name them. The allow.toml entries are API group names.
- Partials and `missing_grants`: `get namespaces` and `get /apis` appear only on a 403. A forbidden SCC list or engine group is a note, never a block.
- Generator: `--check` fails on drift and on a stray file, and the CI lint step is added.
- Registry: INFOS goes to 5 and `NOT_BUILT_YET` drops admission. A fixture hits both ALLOWED pairs.
- Hostile server text is escaped and cut. The UID range is shape-checked. Every request is a GET, at most seven.
- `forbid(unsafe_code)` holds, the changelog fragment is present, and the code has no em dash.
