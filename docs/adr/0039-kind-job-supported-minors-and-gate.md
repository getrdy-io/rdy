# ADR 0039: The kind job tests the three minors Kubernetes patches at their ends, and does not gate merges

- Status: Proposed. The founder decides on the gate (decision 3). The security-reviewer has not seen it.
- Date: 2026-10-30

## Context

M1-108 adds a CI job that runs rdy's Kubernetes client and `k8s.version` against a real API server. Its
exit test says "the oldest and newest supported minors", and 03 and 08 say the same. Nothing in 01, 03, 06
or 08 names a supported range of Kubernetes minors. 06 "Version and support policy" covers rdy's own
versions, the toolchain and the OS platforms. The only numbers in the plan are the example `min: "1.28"`
(the release where `SelfSubjectReview` went GA), `k8s-openapi` with the `v1_36` feature (ADR 0010: the
newest the pinned crate has) and 08's matrix rows (kind on the newest upstream minor, kubeadm on the three
newest minors as fixtures).

06 also lists the jobs of `ci.yml` and says `ci-ok` "lists only gating jobs". It does not list a kind job.

## Decision

1. **The live range is the minors the Kubernetes project still patches.** On 2026-10-30 that is 1.35, 1.36
   and 1.37 (kubernetes.io/releases: 1.34 reached end of life on 2026-10-27). The job runs the oldest and
   the newest, 1.35 and 1.37. A cluster older than that is a customer's cluster and gets the fixture cases
   of `k8s.version` (`tests/fixtures/checks/k8s.version/`), not a live run. This is the range the job
   tests, not a promise to customers: no document says rdy refuses an older server, and `k8s.version` still
   judges any server against the spec's `min`. A support statement for customers is the docs-writer's.
2. **How the range moves.** When Kubernetes ships a minor and kind publishes images for it, replace the
   oldest and newest rows of the matrix in `.github/workflows/kind.yml` with the new oldest and newest, and
   bump `KIND_VERSION` and `KIND_SHA256` if the new images need a newer kind. Take the image digests from the
   release notes of the kind version, then confirm each with the registry (`docker buildx imagetools
   inspect kindest/node:<tag>` shows the same index digest). The matrix and its comments carry the dates.
3. **The job is a separate workflow and is not in `ci-ok`.** It runs on every PR and push to main (so a red
   result is visible on the PR), nightly, and by hand. It is not required. 06 does not name it a gate, and
   it depends on Docker Hub (the node image, subject to anonymous pull limits on shared runner addresses)
   and on a release download from GitHub. For a one-founder repo, an outside outage that blocks every merge
   costs more than a late red check on a change that touches the client. The mock-backed tests, which
   include the guard and the INV-14 audit, stay gating. To make it a gate later, move the job into `ci.yml` and add it to the `needs:` of `ci-ok`. That is one edit, and the
   founder makes it after a few weeks of green runs.
4. **Everything the job fetches is pinned.** The kind binary is a pinned release file with its sha256 checked
   before it runs (and equal to the release's own `.sha256sum`). Each node image is named by tag and by the
   index digest. `kubectl` is taken from the node image, so the client equals the server and needs no
   download. Actions are pinned by commit SHA as in `ci.yml`. The token is read-only and the job uploads
   nothing.
5. **The job proves what the exit test says, in two places.** The shell script `scripts/kind-live-test.sh`
   proves, with `kubectl`, that `restricted` is enforced on the test namespace (a server-side dry run
   refuses a privileged pod with `violates PodSecurity "restricted:latest"` and admits a pod that meets
   `restricted`) and that the `rdy-readonly` kubeconfig is read-only. The ignored tests of
   `crates/rdy-checks-k8s/tests/live_cluster.rs` prove the rest through rdy's own client: `k8s.version`
   passes on the minor the job started (`RDY_LIVE_EXPECT_MINOR` must match the server), the raw
   `SelfSubjectReview` names the caller, access reviews round trip, the namespace labels read back as
   `restricted`, and the read-only test of M1-103 (SEC-24) passes with the service account of
   `examples/rbac/rdy-readonly.yaml`. A test that cannot find its variable panics. It never skips.
6. **The script refuses a cluster it was not meant for.** It deletes the namespaces `rdy-live` and
   `rdy-system` and the read-only roles, so it runs only when the current context is named `kind-*` and
   the API server is on the loopback address (`127.0.0.1`, `localhost` or `[::1]`, where kind listens),
   unless `RDY_LIVE_ALLOW_ANY_CLUSTER=1`.

## Consequences

- The newest and oldest patched minors are exercised against a real server every night. The middle minor is
  not. Serialisation and review semantics have not changed between minors in the paths rdy uses, and the
  fixtures cover the middle one.
- The job is not a gate, so a regression of the client against a real server can reach main and show only as
  a red check. The mock-backed tests (the guard, the audit of INV-14) still gate. A release closes that
  gap: `RELEASING.md` asks for a green `kind` run on the release commit before the tag.
- A red nightly run notifies only the person who last edited the cron line of the workflow (GitHub's rule
  for scheduled runs). Nobody else hears of it. The founder watches the Actions tab, or edits the cron
  line (a new minute is enough) so the notice comes to them.
- The read-only role is checked on the live server in two ways: the server's access reviews deny writes,
  Secrets, token minting, exec, impersonation and bind, and the server's rules review for `default` and
  `kube-system` lists no grant outside the role file (plus the self reviews of `system:basic-user`).
- Three pins move by hand: the kind version, its hash and the image digests. Dependabot does not read them.
  The nightly run shows a pin that rotted (an image removed from Docker Hub).
- Not tested: the in-cluster path (a pod's service account), OpenShift, and managed distributions. Those are
  the M2 distro set (08).
