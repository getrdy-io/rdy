# PR #155 cold review (code-reviewer), readme-interim @ 8e398d4

Verdict: approve with fixes. Docs only. Findings 1 to 3 must land before merge; the rest are small.

Checked and clean: every link resolves on the branch (07, 05, SECURITY.md, CONTRIBUTING.md, LICENSE,
docs/intro/reference-spec.md, reference-result.md, examples/specs/ with five files, rust-toolchain.toml).
No em or en dashes, no non-ASCII, no install command, no docs.getrdy.io link, no competitor name (the
comparison section names a category only). Old working name not found by reading; CI docs-lint is the
authority. Verdict words and exit codes 0/1/2/64/70 match 07 section 2.4 and section 5. Header, status
words and "fix from <product>:" match 07 C.2. CLI facts check out: `--secret-key` (cli.rs:172),
`trust add <product> --key` (cli.rs:47), lint line "<file>: 0 errors, 0 warnings" (lint.rs:87),
"rdy run is not yet implemented in this build" exit 70 (error/mod.rs:343). Fragment slug is allowed by
ADR 0017 rule 1.

## Findings

1. HIGH. README.md:61-63, 68-71, 73-75. "every claim below is a rule the code is built and tested
   against" is false today. Not built: signature refusal and the loud banner inside a run (M1-126,
   M1-130 todo), the HTML renderer (M1-077 todo), the upload client (M2), the host allowlist (M1-094
   todo; permit_hosts wiring deferred in M1-144), the no-phone-home strace test (M1-128 todo). The
   README's own Status puts the first two under "Before 0.1.0". Fix line 61-63:
   "rdy runs inside your environment, sometimes on a production host. Do not take our word for what it
   does. The code is open (Apache-2.0). These are the rules it is built to. Items marked (before 0.1.0)
   or (M2) are not in the code yet."
   Then tag: the signature bullet "(verify and refuse: before 0.1.0; the verifier itself is built and
   tested)"; the renderer sentence "The HTML report renderer (before 0.1.0) and the upload client (M2)
   will be open source in this repo, so a security reviewer can read exactly what would leave the box."

2. HIGH. README.md:100, 101, 103, 165. Checks that are `core: no` in 11-backlog are called "Coming
   before 0.1.0". core: no = kernel M1-152, cgroups M1-151, time sync M1-148, sysctl M1-149, container
   runtime M1-150, net.dns M1-153/155, registry M1-156, MTU M1-157, bandwidth M1-158, k8s namespace
   M1-161, DNS M1-162, ingress M1-163, CRDs M1-164, CNI M1-165, admission webhooks M1-160, node free
   capacity M1-159. core: yes and todo = host.ports M1-072, net.egress M1-095..097, net.proxy M1-098,
   net.tls_intercept M1-099/100, k8s.nodes M1-113, k8s.admission PSA M1-114. Replace rows 99-103 with:
   ```
   | Host | CPU, memory, disk, OS, SELinux and AppArmor, firewall | Built (Linux), not reachable from `rdy run` yet |
   | Host | ports | Coming before 0.1.0 |
   | Host | kernel, cgroups, time sync, sysctl, container runtime | Planned after 0.1.0 |
   | Network | egress through a proxy, proxy settings, TLS interception | Coming before 0.1.0. The probe layer under them is built |
   | Network | DNS, registry, MTU, bandwidth | Planned after 0.1.0 |
   | Kubernetes | access, version, storage classes, RBAC for the install identity | Built, not reachable from `rdy run` yet |
   | Kubernetes | nodes, Pod Security admission | Coming before 0.1.0 |
   | Kubernetes | admission webhooks, namespace, DNS, ingress, CRDs, CNI | Planned after 0.1.0 |
   ```
   Line 165: "Host ports, the egress, proxy and TLS interception checks, and Kubernetes nodes and Pod
   Security admission." Add under "After 0.1.0" first: "0.1.x: the remaining host, network and
   Kubernetes checks in the table above."

3. MEDIUM. README.md:66-67 and 76-77 contradict 05 "The bounded sentence". "it never changes anything
   on the machine": a run writes a report folder, and `trust add` and `spec keygen` write files.
   "Checks only contact the hosts the spec lists": INV-11 peers also include the proxy, system resolvers
   and the Kubernetes API server. Replace with: "Checks only read. A run writes one new report folder
   and nothing else. In a cluster it reads, plus three self-review requests, and never reads Secrets."
   and "Checks connect only to the hosts the spec lists, your proxy, your DNS servers and the Kubernetes
   API server you chose. Redirects are recorded, never followed (enforced before 0.1.0)."

4. MEDIUM. README.md:28-51. The transcript runs acme-quickstart.yaml, but examples/specs/acme-quickstart.yaml
   has five checks including net.egress (block) and is unsigned, so a reader who compares sees a
   different run. Add to line 30: "It uses a signed copy of `examples/specs/acme-quickstart.yaml` with
   `net.egress` left out." Also replace "The banner and the report lines are left out." with "The report
   lines are left out." (a verified, pinned spec prints no banner, 07 section 2.1).

5. MEDIUM. README.md:180-182. macOS and Windows host and network data sources are M2 (M2-005, M2-007 to
   M2-010). A Windows customer gets required host checks not run, so NOT READY. Append: "In 0.1.0 the
   host checks read Linux data sources only. On macOS and Windows they report not run, which makes a
   required check NOT READY. Those data sources are planned for M2."

6. LOW. README.md:171. "A time-boxed quickstart" is M1-167, `core: no`. Replace with "A first-run page
   and the quickstart spec, run end to end on a clean checkout." (M1-129, M1-124).

7. LOW. docs/plan/12-progress.md:289. "PR #TBD" should be "[#155](https://github.com/getrdy-io/rdy/pull/155)".

8. LOW. README.md:161. "In progress" overstates: M1-057, M1-077 and M1-086 are all todo. Rename the
   heading "Next".

9. NIT. README.md:6. No signed release exists yet. "It is one signed binary" -> "It ships as one signed
   binary". README.md:180: rewrap the paragraph (the first line breaks after 66 characters).

## Confirm (fix round bb73452)

Verdict: approve. All nine findings are fixed as proposed.

1. Fixed. The intro now frames the claims as rules, with (before 0.1.0) and (M2) markers. The signature bullet uses "will" and tags verify and refuse. The renderer and upload sentence is tagged.
2. Fixed. The table splits by core flag and matches 11-backlog. The Next list and the "0.1.x" line under After 0.1.0 match.
3. Fixed. "Checks only read. A run writes one new report folder" and the INV-11 peer list now match the 05 bounded sentence.
4. Fixed. The transcript note names the signed copy with net.egress left out, and "banner" is dropped.
5. Fixed. The macOS and Windows paragraph is added, and the line wrap is fixed.
6. Fixed (M1-129, M1-124 wording).
7. Fixed (#155 link in 12-progress).
8. Fixed ("Next").
9. Fixed ("It ships as one signed binary"). Line 180 is rewrapped.

Rechecked with no regressions: no non-ASCII, no em dashes, no install command, no docs.getrdy.io link, no competitor name. Every link still resolves.

New, none blocking:
- LOW. README.md:209-210. NOTICE and TRADEMARKS.md do not exist on this branch. They are code spans, not links, so nothing is broken. Merge the NOTICE/TRADEMARKS PR first, or in the same release, so the README never names missing files. Turn them into links when they land.
- NIT. README.md:164. The "Works on main today" host list omits firewall, and the Kubernetes list omits access. The table has both. Add "firewall" and "access" there.
- NIT. README.md:75. The line is 105 characters ("...rdy will refuse a spec"). Rewrap it to match the rest.
