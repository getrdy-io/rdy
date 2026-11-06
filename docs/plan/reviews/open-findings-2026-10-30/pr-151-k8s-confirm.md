# PR 151 (M1-114 k8s.admission) fix round 1, k8s-expert confirmation
Head 78bdd9e (verified against origin/m1/114-k8s-admission). No build, no tests run; read the diff, the fixtures and the sources.

Verdict: APPROVE WITH ONE FIX (see "Kyverno versions" at the end: finding 2 is fixed for the fixture but wrong on real Kyverno 1.12 to 1.19 clusters). Everything else is fixed or correctly deferred.

## My findings
1 (Kyverno dates, medium): FIXED. engines.rs, 03 and 12-progress say: ClusterPolicy/Policy marked for deprecation 1.17, deprecated 1.19, removal planned 1.20; CEL types in policies.kyverno.io/v1 from 1.17, policy types page says stable since 1.18. Checked today:
  - 1.17 release post table: 1.17 "Marked for deprecation", 1.18 and 1.19 "Critical fixes only", 1.20 "Planned for removal" (Jan/Apr/Jul/Oct 2026 est.).
  - Policy types page: "Deprecated (v1.19), removed in v1.20"; ValidatingPolicy etc. "Stable (since v1.18)"; schedule 1.19 "officially deprecated", 1.20 "removed" (Nov 2026 est.).
  - Release post and CNCF blog call the v1 CEL types GA/stable in 1.17.
  So the two sources really do disagree on stable (1.17 vs 1.18), and the code text states both with attribution. Acceptable. It does not matter to behaviour, since both groups are looked for. The "deprecated in 1.19" wording matches the docs page; the release post calls 1.18/1.19 "critical fixes only". Both are consistent with what is written. Dates are "planned" and "estimated", and the text says planned. Good: the 1.20 removal is not claimed as done (today is 2026-10-30, 1.20 not confirmed shipped).
2 (legacy command, medium): FIXED. fix::engines takes legacy_policies; admission.rs computes it from the served kinds before the cut (has_legacy_policies, ClusterPolicy or Policy), judge.rs requires group == kyverno.io. Fixtures kyverno-no-legacy (kyverno.io serving only PolicyException; test asserts no "clusterpolicies" and the validatingpolicies command present) and kyverno-legacy-only (command present). Unreadable kinds give legacy=false, so no command; safe, and the text still says to ask the platform team.
3 (RKE2 text, low): FIXED. "RKE2 enforces restricted by default only with the CIS profile, and the profile is not readable". Only fires when need < restricted. Correct. 03 notes only RKE2 is detected, not Rancher templates.
4 (default config exemptions, low): FIXED. Note says the config also holds exemptions (namespaces, usernames, runtime classes) and an exempt namespace ignores its labels. Accurate.
5 (synced label hedge, low): FIXED. "...so pods are not rejected for it, if it was not edited by hand." Matches the OpenShift docs (a hand-edited label stops syncing for that label).
6 (uses gaps): deferred to an M2 ticket (correction-32), listed in 12-progress as deferral 4. Acceptable; I asked for no widening.
7 (invalid warn/audit note, nit): FIXED. Note says the API server reads it as privileged so it never warns; fixture invalid-warn. Correct (fail open, PolicyToEvaluate).
8 (restricted-v3, nit): no change needed.

## Domain facts asked about
- ClusterPolicy schedule (1.17 marked, 1.19 deprecated, 1.20 removal planned): correct as written.
- podSecurityLabelSync "false": judge.rs reads facts.label_sync_off; with the sync off the warn/audit labels are the namespace's own and judged normally (warn issue, or note when enforce already blocks). With sync on on OpenShift they stay notes. Matches Red Hat docs (sync is per namespace, derived from SCCs of service accounts, warn and audit only, never enforce). Fixture openshift-sync-off. Correct.
- RKE2: restricted default only with the CIS profile, exemptions kube-system, compliance-operator-system, tigera-operator, no profile means privileged. Correct; detector "+rke2" in git_version is right.
- PSA exemptions note: correct.
- Invalid warn/audit read as privileged, invalid enforce read as restricted: correct; unchanged level.rs.

## Nits, no action needed for merge
- OpenShift never syncs default, kube-*, openshift and most openshift-* namespaces, and user-created openshift-* start with sync off. The "synced" note could be slightly off for a product installed in an openshift-* namespace. Rare; M1-115 can hedge it.
- With sync off and no warn/audit label, the cluster-wide warn/audit default (restricted on OpenShift) still applies; the pass note covers the enforce side only. Not a block risk.

## Kyverno versions (added after the coordinator question, code-reviewer finding 1)
Answer: code-reviewer is right on both points. Verified from the Kyverno CRD manifests (raw `config/crds/kyverno/kyverno.io_*.yaml` on each `release-1.N` branch, parsed, served/storage per version) and the Kubernetes source.

Preferred-version rule (Kubernetes): for a CRD group the discovery controller merges the served versions of all CRDs in the group, sorts them with `version.CompareKubeAwareVersionStrings` (GA above beta above alpha, higher major first: v2 > v1 > v2beta1 > v1beta1 > v2alpha1 > v1alpha1), and sets `PreferredVersion` to the first. Only served versions are listed. A server never prefers "the first listed in a file". Source: kubernetes/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/customresource_discovery_controller.go (`sortGroupDiscoveryByKubeAwareVersion`, `PreferredVersion: apiVersionsForDiscovery[0]`).

Group `kyverno.io` (S = served, ST = also storage; checked on release-1.12 to 1.19 and main; there is no release-1.20 branch yet):
- ClusterPolicy and Policy: `v1` S ST, `v2beta1` S. Same in 1.12 to 1.18. In 1.19 and main both versions are flagged deprecated, still served. Never served in `v2`.
- PolicyException: 1.12 `v2` S, `v2beta1` S ST, `v2alpha1` not served. 1.13 to 1.18 `v2` S ST, `v2beta1` S deprecated. 1.19 and main: `v2` S ST also flagged deprecated (the policies.kyverno.io PolicyException replaces it).
- CleanupPolicy and ClusterCleanupPolicy: same pattern as PolicyException (1.12 `v2` S, `v2beta1` ST; 1.13 and later `v2` ST, `v2beta1` deprecated; 1.19 and main `v2` deprecated too).
- UpdateRequest: 1.12 `v1beta1` S ST, `v2` S. 1.13 to 1.15 `v1beta1` S deprecated, `v2` ST. 1.16 and later `v1beta1` not served, `v2` S ST.
- Result: from 1.12 through 1.19 the group serves v2, v1 and v2beta1, so the preferred version is `kyverno.io/v2`. `v2` has PolicyException, CleanupPolicy, ClusterCleanupPolicy and UpdateRequest, and never ClusterPolicy or Policy. They live only in `v1` and `v2beta1`. (Kyverno 1.10 and 1.11 are not shown here; v2beta1 was then preferred and the conclusion is the same.)
- Consequence: `legacy_policies` read from the preferred version is false on every real Kyverno 1.12 to 1.19 cluster, so the `kubectl get clusterpolicies.kyverno.io,policies.kyverno.io -A` command is never emitted, which is the opposite of the intent. My earlier confirmation of finding 2 trusted the fixture. The fixture `kyverno/discovery-apis.json` lists kyverno.io as v1 and v2 with v1 preferred, which a real server never returns (it would say v2). `group()` in `scripts/gen-k8s-admission-fixtures.py` sets `versions[0]` preferred.
- kubectl itself is fine: `kubectl get clusterpolicies.kyverno.io` resolves the resource in whichever served version has it (v1).

Group `policies.kyverno.io` (no problem): 1.16 `v1alpha1` ST, `v1beta1` S. 1.17 to main `v1` S, `v1beta1` ST, `v1alpha1` S deprecated. The kinds (ValidatingPolicy, MutatingPolicy, GeneratingPolicy, ImageValidatingPolicy, DeletingPolicy, PolicyException) are the same in every served version, so reading the preferred one is enough, except `NamespacedValidatingPolicy` which exists in `v1beta1` and `v1` only (the preferred one in both ranges). Storage is `v1beta1` in 1.17 and later although `v1` is preferred. Storage does not matter for the discovery read.
Gatekeeper (not verified from a manifest): constraint kinds are generated one per template and serve the same versions, so a preferred-version read is enough; I did not check the Gatekeeper CRD.

Recommended fix (small):
1. Carry every served version of the group from `GET /apis` (the group's `versions` list, which is already sorted newest first) and for the engine groups read each listed version, at most 4 per group (kyverno.io is 3 on 1.12 to 1.19), taking the union of kinds. Or cheaper: read the preferred version for the kind list, and for `kyverno.io` also read `v1` when it is listed and is not the preferred one, for the legacy flag only. Request budget: +1 or +2 requests, still all GET; update the "seven requests at most" text in 03 and 12-progress.
2. `legacy_policies` is true when any read version serves ClusterPolicy or Policy. If the extra read fails (forbidden, timeout), do not emit the command, as now.
3. Generator: `group()` must sort versions by Kubernetes version priority (v2, v1, v2beta1) and mark the first preferred. Make the `kyverno` fixtures realistic: `kyverno.io` served as v2, v1, v2beta1; `group-kyverno.io-v2.json` with PolicyException, CleanupPolicy, ClusterCleanupPolicy, UpdateRequest; `group-kyverno.io-v1.json` with ClusterPolicy and Policy. `kyverno-no-legacy` (1.20 shape): kyverno.io serving only v2 with PolicyException. `kyverno-legacy-only` keeps v1. Add a test that the legacy command appears when the preferred version is v2 and ClusterPolicy is only in v1.
4. After the CRD removal in 1.20 expect `kyverno.io` to go on serving v2 (PolicyException and the cleanup kinds); the kinds read covers it.

Sources: https://raw.githubusercontent.com/kyverno/kyverno/release-1.16/config/crds/kyverno/kyverno.io_clusterpolicies.yaml (and policies, policyexceptions, cleanuppolicies, clustercleanuppolicies, updaterequests, branches release-1.12 to release-1.19 and main); https://raw.githubusercontent.com/kyverno/kyverno/release-1.17/config/crds/policies.kyverno.io/policies.kyverno.io_validatingpolicies.yaml (and siblings); https://raw.githubusercontent.com/kubernetes/kubernetes/master/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/customresource_discovery_controller.go
