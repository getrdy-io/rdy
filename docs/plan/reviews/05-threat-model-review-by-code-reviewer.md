# Review: 05-threat-model.md and SECURITY.md

Reviewer: code-reviewer (cold review, did not write either file). Date: 2026-10-27.
Files reviewed: `docs/plan/05-threat-model.md` (TM), `SECURITY.md`. Cross-checked against CLAUDE.md,
KICKOFF.md, rdy-plan.md, 03-check-catalog.md, 06-release-and-distribution.md and ADRs 0001 to 0011.

## What passed

- STRIDE coverage matches KICKOFF item 6. All four surfaces are there (CLI as root, spec supply chain,
  install script and release, upload path), each with all six categories. Every mitigation has a
  milestone tag and a ticket. The one exception is Surface 4 I4, which says it is out of scope.
- No em dashes or en dashes. Neither file has a single non-ASCII character.
- The old working name does not appear.
- No competitor company or product names in either file. I checked every name in the plan's
  "where it stops", "what exists" and "why it lost" tables, plus troubleshoot.sh and kurl. Zero hits.
  `tj-actions/changed-files` (TM line 224) is a compromised GitHub Action cited as an incident, not a
  competitor. FYI, outside this review's scope: `docs/plan/rdy-plan.md` itself still names many
  competitors (lines 9 to 30, 128, 213, 221, 240, 283, 310, 321, 344 to 347, 432 to 436, 484, and the
  Sources list). The founder's rule covers the whole repo.
- The advisory ids are correct. I checked them on OSV: RUSTSEC-2025-0068 is serde_yml ("unsound and
  unmaintained"), RUSTSEC-2025-0067 is libyml. The `serde_yaml` ban is safe: kube-client 4.2.0 depends
  on serde-saphyr, not serde_yaml.
- Every M1 ticket is 1 to 4 hours and has an exit test.

## Findings

### Must fix

1. **The signing design contradicts accepted ADR 0002 and does not flag it.** TM lines 119 to 132,
   138 to 149 (S1, S2, E2), INV-03 (line 295), SEC-12, SEC-13 and SEC-16 specify raw Ed25519 through
   `ed25519-dalek` `verify_strict`, an `rdy-spec-v1\0` byte prefix, `--trusted-key` and `trusted-keys/`
   directories. ADR 0002 (Accepted) picks the minisign format (BLAKE2b prehash) verified with
   `minisign-verify`. It drops ed25519-dalek, keeps product-bound pinning in `trust.yaml`, and uses
   `--key`, `--trust-key` and `rdy trust`. A byte prefix would also break the stock minisign interop
   that ADR 0002 promises.
   Fix: rewrite the signing requirements against ADR 0002.
   - Verify with `allow_legacy = false`, so non-prehashed signatures are rejected.
   - Get domain separation from a required trusted-comment prefix, `rdy-spec-v1 product=<p>`. The
     global signature already covers the trusted comment.
   - Order: find the pinned key by key id, verify the raw bytes, then parse, then check that
     `metadata.product` equals both the pinned product and the trusted comment.
   - Replace E2 `verify_strict` with small-order key test vectors run against `minisign-verify`, and
     refuse weak keys at `rdy trust add`.
   - Rewrite the INV-03 test. minisign has no envelope that carries a key. Test that an unpinned key
     id gives "unknown key", and that a key pinned for product A fails on product B.

2. **Root can be made to trust a key that an ordinary user planted.** TM lines 119 to 121 read both
   `~/.config/rdy/trusted-keys/` and `/etc/rdy/trusted-keys/`. macOS `sudo` keeps `HOME`, and `sudo -E`
   or a kept `XDG_CONFIG_HOME` does the same on Linux. An unprivileged user can then drop a key that
   root trusts, and their spec runs as root.
   Fix: when euid is 0, read only the system store. Ignore `HOME` and `XDG_CONFIG_HOME`. Refuse trust
   files or directories that are not root-owned or that are group or world writable. Add this as an
   invariant with a test, and to the ADR 0002 trust-store ticket.

3. **Unknown check ids contradict ADR 0005, ADR 0007 and ADR 0008.** INV-05 (line 297), Surface 2 E1
   (line 148) and the SEC-15 exit test (line 558) make an unknown check id exit 64. The ADRs say it
   becomes `Skipped` with "needs a newer rdy", and the verdict is capped at Warnings. The plan's own
   example spec (`gpu.cuda`, `aws.iam`) must run on M1.
   Fix: unknown check ids and unknown per-check fields become `Skipped`. No code runs for them, so no
   capability is gained. These stay exit 64: duplicate keys, anchors and aliases, multi-document input,
   oversize input, and unknown top-level keys.

4. **The cosign identity pin is wrong in two ways.** TM lines 172 to 176 and line 210.
   - 06 puts signing in a called workflow, `sign-release.yml`. The Fulcio SAN is the `job_workflow_ref`,
     so pinning `release.yml` fails every verify.
   - `v[0-9]+\.[0-9]+\.[0-9]+$` rejects pre-release tags, and 06's M1 releases are tagged
     `v0.1.0-alpha.3`.

   Fix: pin
   `'^https://github\.com/getrdy-io/rdy/\.github/workflows/sign-release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'`
   and add `--certificate-github-workflow-repository getrdy-io/rdy`. Take the exact string from 06's
   sign-release ticket. Keep it in one place, `scripts/verify-release.sh`, and have install.sh and the
   docs reference that.

5. **install.sh behaviour contradicts 06 and does not flag it.** TM lines 189 to 213, T3 (line 223),
   INV-18, SEC-08 to SEC-10 and the ADR bullet at lines 521 to 525 disagree with 06 on five points:
   - Signature files: one `SHA256SUMS` plus one bundle (TM) vs a `.sigstore.json` and `.sha256` per
     asset (06).
   - Missing cosign: fail closed (TM) vs download a cosign whose hash is pinned in the script (06).
   - Root opt-in: `--allow-root` (TM) vs `RDY_ALLOW_ROOT=1`, which installs to `/usr/local/bin` (06).
   - Skipping signatures: `RDY_INSECURE_SKIP_SIGNATURE` (TM) vs `RDY_VERIFY=checksum` (06).
   - Immutable releases: required by TM T3, but 06 says they may be impossible if signing runs after
     announce.

   Also, `sha256sum --ignore-missing` (line 212) is GNU-only. busybox (Alpine) lacks it, and macOS
   needs `shasum -a 256`.
   Fix: 06 owns the behaviour. Delete the TM install.sh list and keep only the security requirements,
   written as INV-18 with 06's names. Make T3 conditional on 06's ordering decision, with "fail closed
   on a missing signature" as the fallback. 06's per-asset `.sha256` files remove the portability bug.

6. **INV-06, INV-07 and INV-10 are not true as written, so they cannot pass as tests.**
   - INV-10 and the bounded sentence (lines 18 to 21) leave out peers that do exist:
     - system DNS resolvers;
     - the configured proxy;
     - SNTP over UDP to the spec's `ntp_servers` (03 `host.time_sync`);
     - kube exec credential plugins (`aws eks get-token` calls STS) and OIDC refresh.

     Also, "cannot send data anywhere" is false: SNI, HTTP requests and DNS queries carry hostnames.
   - The INV-10 test is weak. A no-net run under `unshare -rn` also passes when a phone-home attempt
     fails silently. And `unshare -rn` fails on GitHub `ubuntu-24.04` runners, because Ubuntu 24.04
     restricts unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`).
   - INV-06 and INV-07 claim too much. kube-rs spawns exec plugins and hickory and reqwest open sockets
     outside the facade. ADR 0010 decision 5 exempts exec plugins on purpose. The fixed root PATH at
     line 68 would also hide `aws` and `kubelogin` in `/usr/local/bin`.
   - 03 line 223 runs `powershell.exe -Command` on Windows, which breaks "no shell is ever spawned".

   Fix:
   - Restate the peer set: spec endpoints and `ntp_servers`, the configured proxy, system resolvers
     (queries for spec hostnames only), and the selected API server. Kubeconfig credential plugins are
     a named exception that is logged in the action log.
   - Change the bounded sentence to "send result data anywhere".
   - Test with `sudo unshare -n` (or set that sysctl in the job) under
     `strace -f -e trace=connect,sendto,sendmsg`, and assert that every destination is a listed or
     loopback fixture address.
   - Enforce INV-06 with clippy `disallowed-methods` and `disallowed-types` in `clippy.toml`
     (`std::process::Command`, `tokio::process::Command`, `std::net::TcpStream`,
     `tokio::net::TcpStream`, `std::fs::write`, `std::fs::File::create`), with `#[allow]` only in the
     facade module. Drop the `sh -c` grep.
   - Reword INV-07: no shell receives spec-derived input. Windows PowerShell scripts are source
     constants, run by absolute path `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`.

7. **The Kubernetes allowlist conflicts with ADR 0010 and misses a call the checks need.** E1
   (line 82), INV-13 (line 305) and SEC-23 allow "any POST with `dryRun=All`". ADR 0010 decision 4
   allows no non-GET except the review kinds. The list also lacks `SelfSubjectReview`, which S1 and
   03 `k8s.access` use. A dry-run create still runs admission webhooks and lands in the audit log, so
   "any" is too broad. A full LIST of pods also returns literal env values.
   Fix:
   - Allow GET and LIST on a named set of resources, with metadata-only reads for anything not needed
     in full.
   - Allow POST only to `selfsubjectaccessreviews`, `selfsubjectrulesreviews` and
     `selfsubjectreviews`.
   - Allow a dry-run pod create only for 03's `probe_pod`, only when the spec sets it, and record it
     in the report.
   - Enforce all of this as a tower layer on the kube `Client`, so it is a runtime guard and not only
     a test. Flag the conflict with ADR 0010 under Plan corrections.

8. **The M1 security backlog is not proportionate.** 32 M1 tickets add up to 91 hours. At 10 to 15
   hours a week, M1 has 60 to 90 hours in total. About 18 of the tickets duplicate tickets already in
   06 or in ADRs 0001, 0002, 0003, 0009 and 0010.
   Fix: apply the merge and defer plan below. That leaves 12 standalone M1 security tickets of about
   38 hours, and most of that work is needed anyway.

### Should fix

9. **INV-17, E4 and SEC-30 contradict CLAUDE.md.** "Our crates contain no unsafe" is absolute.
   CLAUDE.md allows a documented FFI crate, and the plan's `rdy-checks-host` uses `windows-sys`, where
   every call is unsafe.
   Fix: set `[workspace.lints.rust] unsafe_code = "forbid"`, with a `deny` override only in one named
   FFI module. Each block gets a `// SAFETY:` comment, and CI keeps an allowlist of those files. The
   workspace lint replaces SEC-30.

10. **The TLS text contradicts ADR 0009 and misses real proxy behaviour.** Lines 269, 283, 510 to 512
    and 535 contradict ADR 0009. That ADR keeps two stores (webpki-roots and rustls-native-certs),
    rejects platform-verifier, and has already chosen `ring`. The technical gaps:
    - On Linux, rustls-native-certs reads only the PEM files `SSL_CERT_FILE`, `SSL_CERT_DIR` and the
      distro bundle. A proxy CA pushed only into NSS or a Java keystore is invisible to it.
    - webpki ignores CN and rejects certificates with no SAN, and SHA-1 signatures. Some older
      interception appliances still issue those, so rustls fails where curl works.

    Fix:
    - Cite ADR 0009.
    - Add `--ca-file`, or document `SSL_CERT_FILE`.
    - Have `net.tls_intercept` report "rejected by rustls policy (no SAN or SHA-1)" as its own result.
    - Drop the crypto-provider bullet from the ADR list.
    - Line 401 allows `aws-lc-sys` as an exception, but ADR 0009 bans it in M1. Add `aws-lc-sys` and
      `aws-lc-rs` to `[bans]`.

11. **The setuid check is too narrow.** E2 and INV-09 compare only real and effective uid. That misses
    setgid and Linux file capabilities (`setcap ...+ep rdy`).
    Fix: also compare gid and egid. On Linux, refuse when `CapEff` in `/proc/self/status` is nonzero
    for a non-root uid. State that the check does not apply on Windows.

12. **Windows gaps.** The S2 PATH row is Unix-only. On Windows, `Command::new("powershell")` searches
    the directory of `rdy.exe` first, for example a Downloads folder with a planted `powershell.exe`.
    INV-08 covers Unix only, so I3 (report readable by other users) is open on Windows, where a file in
    `C:\temp` inherits that folder's ACL.
    Fix: use absolute System32 paths for every Windows child process. List the Windows ACL
    inheritance as a residual risk and advise an output dir under the user profile.

13. **The facade has no file-read denylist.** Root can read `/proc/*/environ`, `/proc/*/cmdline` and
    `/etc/shadow`, and `host.security_agents` walks `/proc/*`.
    Fix: put a denylist in SEC-17 for `/proc/<pid>/environ` and `mem`, `/etc/shadow`, `~/.ssh/*`, and
    private key files. Use cmdline only for matching and never store it.

14. **The log caps conflict with CLAUDE.md.** I2 (line 75) caps dependency log levels, but CLAUDE.md
    says `RUST_LOG` is respected.
    Fix: apply the caps only when `RUST_LOG` is unset. When it is set, the redacting layer is the guard.
    The existing test stays.

15. **The CSP is incomplete.** T3 (line 71) gives only `default-src 'none'`, which renders the
    inline-CSS report unstyled.
    Fix: quote ADR 0003's exact policy, `default-src 'none'; style-src 'unsafe-inline'; img-src data:`.

16. **Other ADR conflicts that are not flagged:**
    - ADR 0010 uses `--kube-context`; TM and 03 use `--context`.
    - ADR 0005 puts `custom.exec` in M3; TM line 502 and SEC-53 say M4.
    - ADR 0011 says no `rdy-cli` package is published; SEC-11 reserves it.

    Fix: add these to Plan corrections. Proposed calls: `--context` (cli-ux decides), M3, and reserve
    `rdy-cli` with a placeholder that points to `rdy` (the conservative choice).

17. **Some ticket dependencies are not ticket titles.** Lines 555, 560, 568, 570, 579, 584 and 587
    depend on document sections or ADR names. Point each at a real title, for example "Verify minisign
    signatures in rdy-spec against a trust store with product binding" or "Check trait, Need and
    Context in rdy-engine".
    Two exit tests are not tests. SEC-04's "a checklist in the PR shows" becomes
    `scripts/check-org-settings.sh` using `gh api`. SEC-05's "verified with public tools" becomes a CI
    job running `dig +dnssec`, `dig CAA` and
    `curl -sI https://getrdy.io | grep -i strict-transport-security`.

18. **The document is too long.** It has about 7,650 real words (8,890 by `wc`, which counts table
    pipes as words). That is about 35 minutes of reading against the brief's 15. Proposed cuts:
    - Tickets (2,100 words): about 600 after consolidation.
    - Redaction corpus (449): move to 04.
    - deny.toml block and dependency policy (398): move into the real `deny.toml` under the CI lint
      ticket and keep five rule bullets.
    - install.sh behaviour and the verify command (about 350): move to 06.
    - SECURITY.md section (172): one line.
    - Security reviewer Q&A (449): Appendix A, or the docs security page (SEC-31).
    - Surface 4 STRIDE table: Appendix B, keeping six requirement bullets.
    - Plan corrections already settled by ADRs 0001, 0002 and 0011 and by 06: one-line references.

    Target: about 3,500 words, plus appendices.

19. **deny.toml details.**
    - The `atty` reason (line 413) calls RUSTSEC-2021-0145 "unmaintained". That advisory is the
      unaligned-read unsoundness; the unmaintained one is RUSTSEC-2024-0375.
    - `unmaintained = "all"` fails every PR whenever any transitive crate is flagged, which leaves the
      founder renewing 90-day ignores. Use `"workspace"` on the PR gate and `"all"` in the daily
      audit.yml, which opens an issue instead of blocking.
    - Add `allow-wildcard-paths = true`.
    - Aside: ADR 0001 line 15 calls 0068 "unsound libyml". 0068 is serde_yml; 0067 is libyml.

20. **SECURITY.md.**
    - Line 57 sends readers to docs.getrdy.io, which does not exist in M1. Inline the corrected cosign
      command or link `scripts/verify-release.sh`.
    - Add an out-of-scope list: issues that need root or the operator's own kubeconfig plugin, vendor
      spec content, social engineering, volumetric DoS, and dependency bugs with no rdy exploit path.
    - Line 41: say "a CVE where the issue qualifies".
    - Line 29: drop the PGP promise. GitHub private reporting is the encrypted channel, and it is one
      less key to manage.
    - Link the threat model.

### Nits

21. Line 314: change "Fortune 100 security reviewer" to "customer security reviewer", to match line 16.
22. Lines 221, 231, SEC-04 and SEC-05: say "hardware key or platform passkey". Passkeys are free and
    phishing-resistant.
23. Milestones that disagree with 06: line 329 has the repro job in M3 (06: M2); SEC-49 has
    self-update in M3 (06: M3 spike, M4 build); SEC-11 has trusted publishing in M1 (06: M2).
24. Ticket owners: SEC-24 and SEC-48 name domain reviewers. Use check-author, with k8s-expert or
    cloud-iam-expert reviewing. SEC-46 should be rust-engineer. SEC-55 [M2] is listed after the M3
    tickets.
25. T1 refuses an existing output dir. Use a timestamped default name so reruns do not fail
    (cli-ux owns this).
26. INV-02: read through a bounded `take(1 MiB + 1)` so `/dev/zero` or a FIFO cannot hang the run. Cap
    the `.minisig` and key files too.
27. INV-11: also test a hostname that resolves to 169.254.169.254 and the IPv4-mapped address
    `::ffff:169.254.169.254`. Note that CONNECT targets get only a hostname check. M3 needs an explicit
    IMDS check, because hop limit is a common EKS blocker.
28. INV-04: name the probes (`RDY_ALLOW_UNSIGNED=1` plus a config key). State exit 64 on signature
    failure, as ADR 0002 does.
29. SEC-26: chunk-boundary cases need streaming, which is M2. Move them out of the M1 exit test.
30. T2 and SEC-14: the TTY confirmation goes beyond ADR 0002. Defer it to cli-ux in M2.

## Proposed M1 security ticket plan

Keep 12 standalone M1 tickets, about 38 hours:

| Ticket | Est | Change |
|---|---|---|
| SEC-17 probe facade and action log | 4h | adds the read denylist and the clippy disallowed lists |
| SEC-18 command execution policy | 3h | adds absolute Windows paths and ADR 0004's cleared environment |
| SEC-19 output dir confinement | 4h | |
| SEC-21 network policy | 4h | |
| SEC-22 no-phone-home test | 3h | uses strace |
| SEC-23 kube allowlist | 3h | built as a tower layer |
| SEC-25 minimal redactor | 4h | |
| SEC-26 M1 corpus | 3h | drops chunk-boundary cases |
| SEC-29 log redaction | 3h | |
| SEC-31 docs security page | 3h | |
| Account and domain hardening | 2h | SEC-05 plus the mailbox and security.txt part of SEC-32 |
| M1 security review gate before the M1 tag | 2h | widens ADR 0002's signing review |

Merge into existing tickets as extra exit-test clauses:

| SEC ticket | Merge into |
|---|---|
| SEC-01 | 06 "CI lint job ... cargo-deny with baseline deny.toml". ADR 0009's deny ticket also duplicates this one. |
| SEC-02, SEC-03 | 06 "audit.yml: cargo-audit, deny advisories, zizmor". SHA pins and permissions go into each workflow ticket. |
| SEC-04, GitHub part of SEC-32 | 06 "Repo settings, rulesets and Dependabot" |
| SEC-06 | 06 "sign-release workflow" |
| SEC-07 | 06 "cargo-auditable, CycloneDX SBOM" |
| SEC-08, SEC-09 | 06 "install.sh core" and "install.sh signature verification" |
| SEC-10 | 06 "install.sh CI tests". Add wrong-identity and truncation cases. |
| SEC-11 | 06 "Reserve crate names" |
| SEC-12, SEC-13, SEC-14, SEC-16 | The four ADR 0002 tickets, plus the root-only trust store from finding 2 |
| SEC-15 | ADR 0001 "Wire serde-saphyr" |
| SEC-20 | The rdy-cli startup ticket |
| SEC-24 | 03 `k8s.access` |
| SEC-27 | ADR 0003 "Embed result JSON safely" |
| SEC-28 | The 07 human-output ticket |
| SEC-30 | The workspace skeleton (`[workspace.lints]`) |

Defer to M2:

- crates.io trusted publishing
- the `--allow-unsigned` TTY confirmation
- chunk-boundary redaction cases
- contact-set tests on macOS and Windows

## Verdict

Request changes. 8 must-fix findings. The threat model is good: the bounded-blast-radius sentence and
the probe facade are the right core. But it was written without reading the accepted ADRs and 06, so
the signing, install and kube sections specify things other documents have already decided
differently. Fix 1 to 8, consolidate the tickets, cut to about 3,500 words, then re-review.
