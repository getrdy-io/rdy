# PR #147 (M1-108) security confirm, fix round 2. Head d3922e1, diff f34462a..d3922e1

Scope: the PR's own commit 382cd99 (kind.yml, live_cluster.rs, kind-live-test.sh) and d3922e1 (12-progress). The merge 2e77bf5 is main's content, not reviewed.

## Verdict: APPROVE. No new findings above Info. SEC-147-8 closed.

## Checks
1. kind install: PASS. The download goes to `$RUNNER_TEMP/kind-download` and `sha256sum -c` checks it against the pinned `KIND_SHA256` before anything runs it. It is installed to `$RUNNER_TEMP/bin/kind` (0755, no sudo). The workflow no longer writes `$GITHUB_PATH`. Every call uses the full path: the version check, the version grep and `create cluster`. `scripts/kind-live-test.sh` never runs the kind binary. It uses `kind` only in context names and YAML.
2. `CC_*` write to `$GITHUB_ENV`: PASS. The line is `echo "CC_${TARGET//-/_}=musl-gcc"`. `TARGET` is a literal in the job `env` (`x86_64-unknown-linux-musl`). It does not come from a matrix value, an event field, a branch name or PR text. So the written line is always `CC_x86_64_unknown_linux_musl=musl-gcc`. Triggers are `pull_request`, `push`, `schedule` and `workflow_dispatch`, with no `pull_request_target` or `workflow_run`, so zizmor's `github-env` audit has no dangerous trigger to flag. ci.yml lines 309 and 425 use the same pattern. The zizmor job (`zizmor --format=github .`, which covers kind.yml) passed on 382cd99, the commit with this kind.yml (check run 124180872668). The lint wall does not ban `GITHUB_ENV`, and `CC_*` is not a `CARGO_` name.
3. `TARGET` / `RDY_LIVE_TARGET`: PASS. `--target "$TARGET"` is quoted in the build step and in `rustup target add`. `RDY_LIVE_TARGET: ${{ env.TARGET }}` sits in a step `env:` map, not inside `run:`, so it cannot inject a template. Its value is the same literal. The script uses `${RDY_LIVE_TARGET:+--target "$RDY_LIVE_TARGET"}`, which gives one quoted argument and nothing when unset. The script runs `set -eu`, and the `:+` form is safe for unset values under `-u`. A local user who sets the variable can only choose the value of `--target`. There is no option injection.
4. Permissions: PASS, unchanged. The workflow sets `permissions: {}` and the job sets `contents: read`. Checkout keeps `persist-credentials: false`. All `uses:` are still SHA-pinned. No step was added that uses a secret or a token.
5. SEC-147-8 comment claim: VERIFIED against upstream source (raw.githubusercontent.com, kubernetes/kubernetes tags v1.35.8 and v1.37.0):
   - `pkg/features/kube_features.go`: v1.35.8 has `ClusterTrustBundle` Alpha 1.27 default false and Beta 1.33 default false. v1.37.0 adds `{1.37, Default: true, GA} // LockToDefault in 1.38`.
   - `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go`, at both tags: when the gate is enabled, the ClusterRole `system:cluster-trust-bundle-discovery` gets Read (get, list, watch) on `certificates.k8s.io/clustertrustbundles`, and a ClusterRoleBinding of the same name binds it to `serviceaccount.AllServiceAccountsGroup` (`system:serviceaccounts`).
   - The test identity is a service account token (`create token rdy-readonly`), so "ours included" is correct. The comment's role, group, gate and per-version state all match the source. It is a fact, not an inference.

## Info (optional, no ticket needed)
- SEC-147-9 (Info). The doc comment on `SERVER_DEFAULTS` (live_cluster.rs, just above the const) says "Reads the Kubernetes project gives every signed-in user". The trust bundle grant goes to `system:serviceaccounts`, not to `system:authenticated`. Fix: say "every service account" (or "default bindings outside the role file"). That way a future entry is not justified with the wrong group.
- SEC-147-10 (Info). In the comment, "on in 1.37.0, off in 1.35.8" is the upstream default. kind does not override it here. Optional: add "by default (GA in 1.37, locked on from 1.38)", so a reader knows the entry stays once 1.35 leaves the matrix.

## CI note (not a security item)
On 382cd99: kind (1.35) and kind (1.37), zizmor, deny, dco, install-sh, cosign-roundtrip and release-workflow passed. The test legs, lint and root were cancelled when d3922e1 was pushed (cancel-in-progress), so ci-ok shows failure there. When I checked, the run on d3922e1 was still in progress. The lint-wall test and the five test legs have not yet been seen green on this head.
