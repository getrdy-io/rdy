# PR #147, M1-108 (kind job), head 8084e7b: code review

**Verdict: approve with fixes.** Nothing is high or critical. Fix the two medium findings before merge.

**The exit test is proven.** Both kind legs passed on 8084e7b, 6 of 6 tests each: job 124113520814 (1.35.8) and job 124113520481 (1.37.0). The logs show `k8s.version` passing. The SelfSubjectReview names `kubernetes-admin`, and exactly `system:serviceaccount:rdy-system:rdy-readonly` for the service account. Access reviews round trip. A privileged pod is refused with `restricted:latest`, and the labels read back as restricted. The M1-103 read-only test passes.

I checked the pins myself: the kind sha256 and both image digests match upstream. shellcheck and zizmor are green, and no token appears in the logs. The `docker cp` kubectl step works. The exact-name asserts are sound: the admin name is not pinned (kubeadm changed it in 1.29), and the PodSecurity message is stable.

## Findings

1. **medium**, 06:94, 08:38/565, ADR 0039. Approved docs 06 and 08 are edited to say the job does not gate, while ADR 0039 is still Proposed. The ADR also defines "supported minors", which 03:291 leaves open. A workflow outside `ci-ok` was last done through a numbered correction (correction 05). 08:339 is stale: it still lists `kind` under ci.yml. The security-reviewer has not seen this change, which adds CI downloads. **Fix:** file correction-30 to define the range, record the gate as pending the founder and fix 08:339. Route ADR 0039 to the security-reviewer.
2. **medium**, kind.yml:77/93, script:159. The job builds the glibc target. 06:80 says Linux tests run against musl. **Fix:** install musl-tools, then set `CARGO_BUILD_TARGET=x86_64-unknown-linux-musl` and `CC_x86_64_unknown_linux_musl=musl-gcc` in the job env.
3. **low**, the script's kubectl calls and kind.yml:70 (curl). Only the 20-minute job timeout bounds them. **Fix:** wrap kubectl as `k() { "$KUBECTL" --request-timeout=30s "$@"; }`. Give curl `--retry 3 --max-time 120`.
4. **low**, script:119/149. Two races: the dry runs need the `default` service account, and the first `can-i` runs right after the RBAC apply. **Fix:** `kubectl wait --for=create -n "$NS" serviceaccount/default --timeout=30s`, then retry `can list nodes` for up to 30 seconds.
5. **low**, ADR 0039 Consequences. A red nightly notifies only whoever last edited the cron. **Fix:** say so in the ADR, or name the founder's notification setting.
6. **nit**, kind.yml:62. `EXPECT_MINOR` is never used. Remove it.
7. **nit**, script:41. Check cargo-nextest up front: `cargo nextest --version >/dev/null 2>&1 || usage ...`.
8. **nit**, the 12-progress M1-108 line. "Deferred (1) nothing ran" is stale. Record the two green job IDs.
