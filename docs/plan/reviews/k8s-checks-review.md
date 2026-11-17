# Review of the Kubernetes checks and fixtures (M1-115)

Reviewer: k8s-expert. Authors of the reviewed code: check-author and rust-engineer (M1-096, M1-097, M1-098,
M1-106, M1-107, M1-109 to M1-114, M1-175; PRs #62, #64, #65 and #78 for the four non-core checks). Date:
2026-11-17. This file is the exit test of M1-115.

## Scope

- `k8s.access`, `k8s.version`, `k8s.storageclass`, `k8s.rbac`, `k8s.nodes`, `k8s.namespace` and
  `k8s.admission`, with their fixtures under `tests/fixtures/checks/k8s.*` and the `_kube` fixtures.
- `k8s.dns`, `k8s.crds`, `k8s.ingress` and `k8s.cni`, read from their open PR branches without editing them.
- The `ALLOWED` table and the guard citation test, the registry, and the fixture harness audit (INV-14).
- Per question: check semantics, API groups and versions, RBAC degrade (what is reported when a read is
  forbidden), and the per-distro fixture sets.

Out of scope: the TLS and credential code (M1-101), webhooks and `ValidatingAdmissionPolicy` (M1-160), free
capacity (M1-159).

## Commits reviewed

- The stack `m1/175-k8s-family-params` at `2df79cb6` (M1-175, M1-113, M1-107, M1-098, M1-097, M1-096; PR
  #74). It is stacked and not merged. The branch `m1/115-k8s-checks-review` sits on it.
- `m1/162-k8s-dns` at `4e45384b` (PR #62), `m1/164-k8s-crds` at `ab5afbc5` (PR #64), `m1/163-k8s-ingress`
  at `2a8a0c09` (PR #65) and `m1/165-k8s-cni` at `77c87582` (PR #78). Each is based on main, not on the
  stack, so the review of their `ALLOWED` and registry edits is against main plus the stack.

## Method

- Read the module docs, `judge`, `fix` and the `ALLOWED` diff of every check. Walked each rule of 03 to the
  code and to a named fixture or test.
- Checked the removed-API table of `version/apis.rs` and the upgrade commands of `version/fix.rs` against
  the Kubernetes deprecation guide and the vendors upgrade guides (the open item of M1-106).
- Checked the OpenShift label sync rules against the OpenShift 4.20 pod security admission page.
- Ran the pair coverage: every `(ALLOWED entry, citing check)` pair, by the fixture tests of each check.
- Claims about the four open PRs are from reading their branches. No code of theirs was run.

## Verdict

The seven built checks are sound on semantics, API groups and RBAC degrade: a forbidden or capped read is
partial with the grant to ask for and never a block, and the guard and the audit prove it. The three OpenShift
label-sync details of M1-115 were wrong or missing in `k8s.admission` and are fixed here with tests. The
citation test is complete for the stack: `NOT_BUILT_YET` is empty and every cited check is registered. One
pair (`pods` with `k8s.nodes`) is read by no fixture because its check half is not built (SF-01). The four
open PRs cannot merge as they stand: they add duplicate `ALLOWED` entries (SF-02). This review lists zero
open must-fix items.

## Summary

| ID | Severity | Where | One line | Status | Owner |
| --- | --- | --- | --- | --- | --- |
| MF-01 | Must fix | `crates/rdy-checks-k8s/src/admission/judge.rs`, `admission.rs` | The OpenShift label-sync rules were by label only: no per-namespace rule, no cluster default note | closed in this branch | M1-115 |
| MF-02 | Must fix | `client/guard/tests/parser.rs` | Nothing stopped two `ALLOWED` entries for one resource; the audit uses the first | closed in this branch (test) | M1-115 |
| MF-03 | Must fix | `client/mock.rs`, six `tests.rs` | No test proved each `(entry, check)` pair is read by a fixture | closed in this branch | M1-115 |
| SF-01 | Should fix | `client/guard/rules.rs` (`pods`), `nodes/tests.rs` | `pods` with `k8s.nodes` is read by no fixture of the check | open, enforced by a test | M1-159 |
| SF-02 | Should fix | PRs #62, #64, #65, #78: `rules.rs`, `registry.rs`, `family.rs` | Duplicate `ALLOWED` entries, a doubled `GetIn` variant, no `build_check` arms | open | the PR authors, at merge |
| SF-03 | Should fix | `version/apis.rs` | Group-version rows for `networking.k8s.io`, `storage.k8s.io` and `admissionregistration.k8s.io` v1beta1 misreport newer betas | open | new M2 row |
| SF-04 | Should fix | `tests/fixtures/checks/k8s.storageclass/` | No AKS, RKE2, kind or vSphere class fixture | open | new M2 row |
| SF-05 | Should fix | PR #64 `rules.rs` | `GetInNamespace(Only::Any)` reads any Deployment in any namespace | open, tracked | M2-126 |
| SF-06 | Should fix | PR #62 `dns.rs` | RKE2 and OpenShift Corefile ConfigMaps are not read, so loop evidence is partial there | open, tracked | M2-125 |
| N-01 | Nit | `admission/engines.rs` | `FoundGroup.version` doc | closed in this branch | M1-115 |
| N-02 | Nit | `admission.rs` | Module doc did not say the `kyverno.io/v1` read is skipped when the preferred read was forbidden | closed in this branch | M1-115 |
| N-03 | Nit | `tests/fixtures/checks/k8s.admission/engine-forbidden/` | Unread `v1` answer file | closed in this branch (dropped) | M1-115 |
| N-04 | Nit | `docs/plan/12-progress.md` | M1-114 line cited the old PR number and "was #151" | closed in this branch | M1-115 |

## Must fix

**MF-01. OpenShift label sync was judged by the namespace label only. Closed.**
- Problem: OpenShift never syncs `default`, `kube-*` and `openshift`, and leaves out the system `openshift-*`
  namespaces. A namespace a user creates with an `openshift-` prefix starts with the sync off. The code said
  "synced from the SCCs, so pods are not rejected for it" for all of them, and so hid a real `warn` or
  `audit` label. With the sync off and no `warn` or `audit` label, the cluster default applies, and nothing
  said so.
- Fix, built: `NsFacts.sync_label` (`Unset`, `On`, `Off`) and `label_sync_applies(name, label)` in
  `admission/judge.rs`. `default`, `kube-*` and `openshift` never sync. `openshift-operators` syncs by
  default. Every other `openshift-*` namespace counts as unsynced unless its label says `true`. Any other
  namespace syncs unless its label says `false`. Where the sync does not run, `warn` and `audit` are
  judged like any label. With the sync not running, OpenShift, and neither label set, a note says the cluster
  default applies and rdy cannot read it (only when the need is below `restricted`).
- Tests: `unit_tests.rs` has a 15-row table over name and label, and the cluster default note test.
  `tests.rs` runs the new fixture `openshift-sync-off-no-labels`. 03 section 4 says the same.

**MF-02. Two `ALLOWED` entries for one resource are never reached past the first. Closed.**
- Problem: `target_of` and the audit take the first entry that matches. The open PRs add a second
  `services`, `configmaps` and `daemonsets` entry. A check cited only by the second would fail its audit with
  "its ALLOWED entry cites only ...". Nothing caught it before merge.
- Fix, built: `allowed_has_one_entry_per_group_version_and_resource` in `guard/tests/parser.rs`. SF-02 is
  the work that makes the four PRs pass it.

**MF-03. The exit test asks that every `(entry, check)` pair is hit by a fixture. Closed.**
- Fix, built: the audit records each pair into a thread local (`client/mock.rs`, `hits`). Each of the six
  checks that cite entries has `every_allowed_entry_that_cites_this_check_is_read_by_a_fixture_run`, which
  runs named fixture tests and compares `hits::unhit(check)` with the check own `NOT_READ_YET`. All pairs of
  the six checks are hit except `pods` with `k8s.nodes` (SF-01). `k8s.access` cites no entry. The test fails
  both ways: a pair that is not hit, and an exempt pair that is hit.
- The citation test has an empty `NOT_BUILT_YET` and every one of the seven checks is in `infos()`.

## Should fix

**SF-01. `pods` with `k8s.nodes` is read by no fixture of the check.** The `ALLOWED` entry belongs to the
free capacity half (`free`), which is M1-159. Today `free` is "not evaluated", and the only reads of the
entry are in `client/mock.rs` tests. The pair is the one entry of `NOT_READ_YET` in `nodes/tests.rs`. When
M1-159 lands, the list must be empty, and the test fails until it is. Owner: M1-159 (check-author).

**SF-02. The four open PRs conflict with each other and with the stack.**
- Duplicate `ALLOWED` entries once all merge: `services` (PR #62 `GetIn`, PR #65 `ListInNamespace`),
  `configmaps` (PR #62 `coredns`, PR #78 `kubeadm-config`) and `apps/v1 daemonsets` (PR #62 list, PR #78 by
  name). `deployments` is edited by PR #62 and PR #64 and `pods` by PR #62. `Access::GetIn` is added by both
  PR #62 and PR #78 with the same shape, so the second merge conflicts textually. MF-02 turns the duplicates
  into a failing test, not a silent audit failure.
- Registration: each PR adds its info to `registry::infos()` but none adds an arm to
  `family::build_check`. The family test (`family/tests.rs`) compares the registry with what the family
  builds, so the first merge fails it until the arm is added. Each PR adds its arm and, if needed, its
  id to `NOT_BUILT`, in the same change.
- Per the exit test, "every k8s check registered in `infos()`" is met for the seven built checks. For
  `k8s.dns`, `k8s.crds`, `k8s.ingress` and `k8s.cni` it depends on PRs #62, #64, #65 and #78 merging. This
  review records that and does not edit them.
- The pair test of MF-03 is needed in each of the four modules when they land, copied from the six above.
- Owner: the authors of the PRs (check-author), at merge, and the coordinator for the merge order.

**SF-03. The removed-API rows are too wide for three groups.** `version/apis.rs` has whole-group-version rows
for `networking.k8s.io/v1beta1`, `storage.k8s.io/v1beta1` and `admissionregistration.k8s.io/v1beta1`, all
"removed in 1.22". Those group versions came back later with new kinds (`ServiceCIDR` and `IPAddress` in
`networking` v1beta1 from 1.31, `VolumeAttributesClass` in `storage` v1beta1, `ValidatingAdmissionPolicy` in
`admissionregistration` v1beta1). `k8s.cni` reads `ServiceCIDR` at `v1beta1`. A spec that requires one on a
cluster that does not serve it would be told it was removed in 1.22. The rest of the table matches the
deprecation guide row by row (1.16, 1.22, 1.25, 1.26, 1.27, 1.29, 1.32). Fix: scope the three rows to the
kinds that were removed (`Ingress` and `IngressClass`; the four storage kinds; the two webhook configuration
kinds). Owner: check-author, a new M2 row. The upgrade commands of `version/fix.rs` match the vendors guides
(EKS one minor at a time, GKE `--master` with `--location`, AKS `az aks upgrade`, OpenShift `oc adm upgrade`,
the k3s and RKE2 install scripts) and the skew text is right (three minors from 1.25, two before, never newer).

**SF-04. The per-distro sets are uneven.** `k8s.version` has `eks`, `gke`, `aks`, `k3s`, `rke2`, `kind`,
`openshift` and `vanilla`. `k8s.nodes` has the autoscaler cases per distro (EKS Auto Mode, Autopilot, node
auto-provisioning, Karpenter, OpenShift) and `aks-no-zone`. `k8s.storageclass` has EKS (four), GKE, k3s and
ODF, but no AKS (`managed-csi` with `disk.csi.azure.com` is the common default and has its own fix text with
no fixture), no RKE2 or kind (`rancher.io/local-path` is covered by the k3s case) and no vSphere. Add
`aks-managed-csi` at least. Owner: qa-engineer, a new M2 row.

**SF-05. `k8s.crds` reads a Deployment by any name in any namespace** (PR #64: `GetInNamespace(Only::Any)`).
The parsed type drops env, args and annotations, so no secret value is held. The guard still allows more than
the check needs. M2-126 already pins the namespaced Role reads to the spec namespaces. security-reviewer to
confirm for PR #64. No new row.

**SF-06. `k8s.dns` cannot read the RKE2 or OpenShift Corefile.** The `rke2-loop` fixture says so. Loop
evidence is therefore restart evidence only there, and the result says it. M2-125 already adds the reads.

## Nits

- N-01: `FoundGroup.version` says it is the group preferred version, that `kinds` is read from it, that the
  `kyverno.io/v1` read adds kinds without changing it, and when it is `None`.
- N-02: the `admission.rs` module doc says the `kyverno.io/v1` read is skipped when the preferred read was
  forbidden, and that the legacy kinds are then unknown and the command stays.
- N-03: the `engine-forbidden` case had a `v1` answer that no request reads (the preferred read is forbidden,
  so `v1` is not asked, and a test asserts that). The generator no longer writes it and the file is gone. The
  case is read by `an_engine_whose_groups_cannot_be_read_is_still_found`.
- N-04: the M1-114 line in 12-progress cites PR #7 once, with no "PR #151 reviews, was #151".

## What holds, by area

- **API groups and versions.** `k8s.admission` reads `security.openshift.io/v1` SCCs and the Kyverno and
  Gatekeeper groups by discovery, and `kyverno.io/v1` only as the legacy fallback. `k8s.version` reads
  `config.openshift.io/v1` `ClusterVersion`. `k8s.rbac` and `k8s.access` use `authorization.k8s.io/v1`
  `SelfSubjectAccessReview` and `SelfSubjectRulesReview`, and `authentication.k8s.io/v1` `SelfSubjectReview`
  (GA 1.28). `ServiceCIDR` is read at `v1` then `v1beta1` (GA 1.33, beta from 1.31). `GatewayClass` is read at
  `v1` only. All match what the server serves.
- **RBAC degrade.** Each check maps a 403 to `partial` with `missing_grants` (`list nodes`, `get namespaces`,
  `get /apis`, `list storageclasses` and so on) and never to a block. A cut list is partial. Unreadable
  discovery leaves a result partial and does not turn into "not installed".
- **Admission.** PSA labels, the enforce, warn and audit levels, an invalid label read as the API server reads
  it, RKE2 default only with the CIS profile, OpenShift SCC text, Kyverno 1.17 to 1.20 kinds, Gatekeeper
  groups: all agree with the projects docs.
- **Storage.** Two defaults block below 1.26 and warn from 1.26, as the server picks the newest default from
  1.26. A class with no provisioner, an in-tree name with the CSI addon, EKS Auto Mode, a CSIDriver with no
  node registration, and PVCs pending with a `ProvisioningFailed` event all have fixtures.
- **Nodes.** Allocatable not capacity, the cordon, `NoSchedule` and `NoExecute` rules, the lifecycle taints
  that do not exclude, the pods-per-node limit, zone `0` on AKS, and the autoscaler signals per distro.
- **Fixture audit.** Every fixture run audits INV-14 when its rig drops. The all-clusters tests of
  `k8s.admission` and `k8s.namespace` read the fixture directory, so a new case cannot skip the audit.

## Plan corrections found

- 03 section 4 `k8s.admission`: the OpenShift sync text now says where the sync does not run, that a
  user-created `openshift-*` namespace starts off, and the cluster default note. Done in this branch.
- 11-backlog M1-115 row: its registration clause names `k8s.dns`, `k8s.crds`, `k8s.ingress` and `k8s.cni`
  only by implication. Proposed text: "the registration and `build_check` arm of `k8s.dns`, `k8s.crds`,
  `k8s.ingress` and `k8s.cni` are checked by the merge of PRs #62, #64, #65 and #78, which each add the pair
  test of MF-03".
- 12-progress M1-104 carried item (4), the pair coverage, is met by MF-03 except `pods` with `k8s.nodes`
  (SF-01, M1-159).

## Tickets implied

- [M2] Scope the three removed-API group version rows to their kinds | check-author | 1h | M1-106, M1-165 | a spec that requires `networking.k8s.io/v1beta1 ServiceCIDR`, `storage.k8s.io/v1beta1 VolumeAttributesClass` or `admissionregistration.k8s.io/v1beta1 ValidatingAdmissionPolicy` on a cluster that does not serve it gets the general text, and `Ingress` v1beta1 still says 1.22 (SF-03)
- [M2] AKS managed-csi class fixture and a vSphere or Longhorn class fixture for `k8s.storageclass` | qa-engineer | 1h | M1-110 | a default `managed-csi` class on AKS passes with the driver registered and gets the Azure fix text when the CSI node is missing (SF-04)

Folds (extra exit-test clauses on existing tickets):

| Existing ticket | Added clause | +h |
| --- | --- | --- |
| [M1] M1-159 k8s.nodes free capacity | SF-01: `NOT_READ_YET` in `nodes/tests.rs` is empty and the pair test passes | 0 |
| [M1] M1-162, M1-163, M1-164, M1-165 (PRs #62, #64, #65, #78) | SF-02: one `ALLOWED` entry per resource (the guard test passes), a `build_check` arm, and the pair test of MF-03 in the module | 0.5 each |
| [M2] M2-126 | SF-05: security-reviewer confirms `GetInNamespace` for PR #64 | 0 |
| [M2] M2-125 | SF-06: the `rke2-loop` fixture reads the Corefile and the loop is told | 0 |

Must fix: 0 open (MF-01, MF-02 and MF-03 closed in this branch). Should fix: 6 open (SF-01 to SF-06). Nits: 4,
all closed. This review lists zero open must-fix items and the M1-115 exit test is met for the stack. The
registration of `k8s.dns`, `k8s.crds`, `k8s.ingress` and `k8s.cni` waits for PRs #62, #64, #65 and #78.
