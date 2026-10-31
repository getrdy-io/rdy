# PR #151 (M1-114) fix round 1 confirm, cold code review, head 78bdd9e

Verdict: changes required. It is one small fix. All ten of my earlier findings are fixed, but the new legacy-command gate is wrong on real Kyverno clusters. CI on 78bdd9e is still running. Merge only on green.

## Earlier findings
1. Fixed. Deferrals now point at M1-175 and M1-160 (correction-32). Correction-32 is on branch `correction-32`, not on main yet, so merge it first or together.
2. Fixed. 12-progress:243 separates the corrections of fact from builder decisions (a) to (e).
3. Fixed. The generator writes U+202E as a Python escape. A scan of scripts, the crate, docs/plan, the fixtures and changelog.d found no bidi control and no em dash.
4. Fixed. `label_sync_off` (admission.rs:369, judge.rs:203) has fixture `openshift-sync-off` and a test.
5, 6. Fixed: correction-32 for M1-160, and 03 now says "Only RKE2 is detected".
7. The dates are corrected per k8s-expert. M1-115 re-checks them.
8, 9, 10. Fixed.

Checked: `gen-k8s-admission-fixtures.py --check` passes on the branch tree (27 cases). All 5 commits carry the Signed-off-by. The changelog fragment is still accurate.

## New findings
1. High. admission.rs:327-331, engines.rs:89, fix.rs:97. `legacy_policies` is read only from the kinds of the group's preferred version. The apiextensions server picks a group's preferred version as the highest kube-aware version over all CRDs in that group. Kyverno 1.13 and later serve `kyverno.io/v2` (PolicyException, CleanupPolicy, UpdateRequest), so the read is `/apis/kyverno.io/v2`. ClusterPolicy and Policy live in `v1` (and `v2beta1`). On every Kyverno from 1.13 to 1.19, the clusters that do have ClusterPolicy, the command is now dropped. The fixtures hide this. `group()` in the generator (line 90) makes the first listed version preferred, so `kyverno.io ["v1","v2"]` gets preferred `v1`, which no real API server sends. `kyverno-no-legacy` also puts PolicyException in `v1`, but it is `v2`. Fix:
   - For `kyverno.io`, keep the version list from `/apis` and read `/apis/kyverno.io/v1` when `v1` is listed. Set legacy from that read, and set it to false when `v1` is not served. This is still one GET per group, at most seven.
   - Make `group()` pick the kube-aware highest version.
   - Fixtures: `kyverno` gets preferred `v2` with the legacy kinds in `v1`. `kyverno-no-legacy` gets `kyverno.io` serving `v2` only, with PolicyException.
   - Have k8s-expert confirm the Kyverno CRD versions.
2. Low. admission.rs:331. When the kinds read is forbidden or runs out of time, legacy becomes `false`, so `engine-forbidden` loses the command it had in round 0. Fix: treat unknown as "show the command" (an `Option<bool>`, `None` gives the command), and assert the fix text in `an_engine_whose_groups_cannot_be_read_is_still_found`.
3. Nit. mock.rs:466. `fixture_cases` calls `std::fs::read_dir`, which crates/rdy-checks-k8s/clippy.toml:96 disallows. It passes only because `#![allow(clippy::disallowed_methods)]` in client/mod.rs:48 carries over to `mod mock`, and clippy.toml:5-6 says that allow is "for itself". This is test-only (`#[cfg(test)]`), so it is safe. Fix: move the helper to `rdy_engine::testing` next to `fixtures_dir`, or say in clippy.toml that `client::mock` inherits the allow.
4. Nit. engines.rs:84 and tests.rs:1048. `is_kind_shaped` accepts the 100-character `L...` name. The test comment says all four hostile names sort after the real ones, but that one sorts after `K8sCheck*` only by byte order. Fix: cap the length at 63 in `is_kind_shaped`, or fix the comment.

## Exit test
It is still proven: the restricted block with the "privileged" fix, the OpenShift SCC text, and the engines warning with names. Finding 1 changes only the policy-engine fix text, not the status.
