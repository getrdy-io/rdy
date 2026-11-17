# PR #152 (correction-32, head 5cf9e0a) cold review

Verdict: approve with fixes.

Fine: totals recounted from rows (M1 175 / 385.5 / 323, M2 113 / 429, All 388 / 1328 / 1265.5); 00 matches; week 23 is 14.5 h; every row has 8 columns; no em or en dashes; id map note; M1-138 and M2-017 deps; M1-160's 12-progress line. M1-107 builds `VersionCheck` from params and hands k8s.access a `Dialed`. It never says "builds `AccessCheck` from `CheckParams::K8sAccess`" (missing, low).

1. Medium. 11-backlog.md:1035 says "no ticket owns 03's read-review batch". False: M2-003 (line 375) owns it. M1-175 pulls half of M2-003 into M1 core, and 1 h cannot hold four builds plus the batch. Fix: drop the batch clause from M1-175 and point PR #151 deferral (4) at M2-003.
2. Low. M1-175's exit test is vague. Fix: "a family test on the M1-105 harness, with a spec holding all six k8s ids, gets six results, none `not_in_build`, and passes the INV-14 audit."
3. Low. M1-160's new clause has no assertion. Gatekeeper has no `constraints` resource, and Kyverno 1.20 drops ClusterPolicy. Fix: "a fixture with two constraint kinds and a ClusterPolicy names all three; a 403 is partial; kyverno.io serving only PolicyException lists no policy."
4. Low. M2-114 "as the standard says": name cases (NET_ADMIN, hostPort, hostIPC, Unconfined need privileged).
5. Low. M2-113 sits in open #144. Rebase totals at merge (M2 114, 432).
6. Nit. Move the Correction 32 bullet above 29; the log omits new totals.
