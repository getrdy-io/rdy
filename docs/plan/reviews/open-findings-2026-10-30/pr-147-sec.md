# PR #147 (M1-108) security review, head 8084e7b

Verdict: approve with fixes. No critical or high findings.

Verified clean: `pull_request` only, `permissions: {}` plus job `contents: read`, `persist-credentials: false`, no secrets, no `${{ }}` in any `run:` (all via env), every `uses:` SHA-pinned and equal to ci.yml, rust-cache saves only on main. Pins checked upstream today: `KIND_SHA256` equals kind v0.33.0 `kind-linux-amd64.sha256sum`; both node digests equal the v0.33.0 release notes. kubectl comes from the digest-pinned image. Script: `umask 077`, trap cleanup deletes the SA (revoking the token), `can()` fails closed. `examples/rbac/rdy-readonly.yaml` unchanged; `tests/rbac_example.rs` still gates exact equality with `ALLOWED`. Positive side of SEC-24 covers every `ALLOWED` entry plus the three reviews and discovery. zizmor green; kind (1.37) green, kind (1.35) running at review time.

## Findings

SEC-147-1 | medium | crates/rdy-checks-k8s/tests/live_cluster.rs:435-448, 477-499
The test says "nothing else" but only samples 9 denials. The server's effective grant (other bindings, aggregation, a broad system:authenticated) is never compared. `serviceaccounts/token create`, `pods/exec`, `impersonate`, `bind`/`escalate`, `configmaps get`, `nodes watch` would all pass.
Fix: read the `SelfSubjectRulesReview` status already fetched at 441 for `default` and `kube-system`. Assert every `resourceRules` entry is in the expected set (the role, plus the system:basic-user review creates), and `incomplete == false`. Add `create serviceaccounts/token`, `create pods/exec`, `impersonate users`, `bind clusterroles` to the deny list.

SEC-147-2 | low | live_cluster.rs:368
`is_allowed` reads a missing status as "denied", so the deny asserts pass vacuously.
Fix: `.status.expect("the server fills the status")`, and assert `evaluation_error` is empty before trusting `allowed == false`.

SEC-147-3 | low | scripts/kind-live-test.sh:141
The SA token is on kubectl's argv, readable via `ps` and `/proc` by other local users on a hand run.
Fix: write `ro.kubeconfig` with a heredoc (or `printf`) from the shell variable.

SEC-147-4 | low | scripts/kind-live-test.sh:57
`mktemp -d` uses `/tmp`, not the runner temp. The brief asks for nothing outside it.
Fix: `work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rdy-live.XXXXXX")`.

SEC-147-5 | low | scripts/kind-live-test.sh:48-54
The guard against a non-kind cluster checks the context name only. A context named `kind-prod` passes.
Fix: also require the server host to be `127.0.0.1`, `localhost` or `[::1]` (kind's default) unless `RDY_LIVE_ALLOW_ANY_CLUSTER=1`.

SEC-147-6 | low | ADR 0039 decision 3
Because kind is not a gate, a role or guard regression seen only live can reach a tag. I accept non-gating for merges.
Fix: add a step to RELEASING.md: "the kind workflow is green on the release commit".

SEC-147-7 | nit | .github/workflows/kind.yml:73
`sudo install` into `/usr/local/bin`.
Fix: `install -m 0755` into `$RUNNER_TEMP/bin` and append that to `$GITHUB_PATH`.

## Exit test

M1-108 is proven when both legs are green: `k8s.version` on the expected minor, raw SelfSubjectReview, access reviews, `restricted` shown by labels and a server-side dry-run refusal. 1.37 is green and 1.35 was still running. SEC-24 "passes on kind with only that role" is proven for the allowed reads. "Nothing else" is proven statically by rbac_example.rs, but not yet on the live server (SEC-147-1).

## Fix round 1 (head f34462a)

Verdict: approve. SEC-147-1 to -7 fixed.

- 1: rules review read for `default` and `kube-system`. `incomplete` and `evaluation_error` are asserted. Every expanded `resourceRules` tuple must match exactly. A `*` stays a literal and fails. All surprises are collected. Four escalation denials added.
- 2: status expected, evaluation_error asserted.
- 3: heredoc under umask 077. No token on argv.
- 4, 5, 6, 7: done as asked.

SERVER_DEFAULTS: this is a real upstream default. Upstream `bootstrappolicy/policy.go` defines `system:cluster-trust-bundle-discovery` (get, list, watch on `certificates.k8s.io/clustertrustbundles`) behind the `ClusterTrustBundle` gate. The 1.37 grant matches that role exactly. The list is as narrow as it can be: three read verbs, one resource, no name wildcard.

SEC-147-8 | nit | live_cluster.rs SERVER_DEFAULTS comment
The comment says the grant goes to "every signed-in user" through "a default binding". Upstream binds it to `system:serviceaccounts`, not to `system:authenticated`.
Fix: name the ClusterRole, the group and the feature gate.

SEC-147-9 | low | live_cluster.rs `grants`
`nonResourceRules` is never checked, so a surprise grant on `/logs/*`, `/debug/*` or `*` would pass.
Fix: also check the nonResourceRules against the discovery and public-info-viewer defaults. Can be carried as a follow-up ticket.
