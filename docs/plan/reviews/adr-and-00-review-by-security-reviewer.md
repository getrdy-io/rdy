# Security review of ADRs 0001 to 0012 and 00-overview.md

Reviewer: security-reviewer. Author of the reviewed files: rust-architect. Date: 2026-10-27.
Checked against docs/plan/05-threat-model.md (surfaces, STRIDE rows, invariants INV-01 to INV-20).
No reviewed file was edited.

## Verdicts

| File | Verdict | Findings |
|---|---|---|
| ADR README | Accept | none |
| 0001 YAML parser | Accept with changes | SF-05, N-04 |
| 0002 minisign signing and pinning | Changes required | MF-01, MF-02, SF-01, SF-02, SF-03, SF-04 |
| 0003 report format | Changes required | MF-03, MF-04, SF-16 |
| 0004 async runtime | Accept with changes | SF-06, N-01 |
| 0005 plugin model | Accept with changes | SF-07 |
| 0006 static musl | Accept with changes | SF-08, N-03 |
| 0007 publishing and versioning | Accept with changes | SF-15, N-05 |
| 0008 errors and result model | Accept with changes | SF-02, SF-09 |
| 0009 HTTP and TLS, ring only | Changes required | MF-05, SF-10, N-02 |
| 0010 kube-rs | Changes required | MF-06, SF-11 |
| 0011 binary name | Accept with changes | SF-12 |
| 0012 wire types | Accept with changes | MF-01 (API shape), SF-09 |
| 00-overview.md | Changes required | MF-01, MF-02, MF-07, SF-13, SF-14, SF-17 |

Must fix: 7. Should fix: 17. Nits: 5.

House rules: no competitor company or product names, no em or en dashes, and no mention of the old
working name in any of the 13 files. I can only check for the phrase, not for a name I do not know.

The good news first. Ring only, no aws-lc-sys, no OpenSSL. Minisign instead of a home-made envelope.
Raw-byte signatures with no YAML canonicalization. No plugins, no dlopen, no WASM. Skipped and Timeout
can never count as a pass. Read-only Kubernetes access through SelfSubjectAccessReview. Those match the
threat model and make my job easier.

## Must fix

**MF-01. 0002, 0012, 00-overview (rdy-spec API). The spec is parsed before its signature is checked.**
- Problem: 0002 decision 3 binds the key to `metadata.product`, and you only get that field by parsing
  the YAML. The overview's `load()` says "parse + validate + verify" in that order, and `parse()` is a
  public function that returns a `Spec` with no verification at all. That breaks INV-01: untrusted bytes
  reach the YAML parser running as root, and any caller (CLI or rdy-cloud) can skip verification.
- Fix: verify first, parse second.
  1. Read the key id from the `.minisig` and the product from the signed trusted comment.
  2. Look up pinned keys for that product, then verify the raw bytes.
  3. Only then call the parser.
  4. After parsing, require `metadata.product` to equal the trusted-comment product, or fail.
  
  Make `load()` the only public way to get a `LoadedSpec`, and keep its constructor private. Rename
  `parse()` to `parse_unverified()`, used by `spec lint`, `--allow-unsigned` and rdy-cloud authoring.
  Add a test with a parser spy: a tampered spec is never parsed.

**MF-02. 0002 and 00-overview cut list. A root run can trust a key that a normal user pinned.**
- Problem: as root, `rdy` uses `/etc/rdy/trust.yaml`. But under `sudo` with HOME or XDG_CONFIG_HOME
  kept (sudo -E, some sudoers defaults, `su` without `-`), the user lookup points at a file the user
  can write. Worse, the overview's cut list drops "the system-wide trust store location". Then root
  reads the user's store, and a local user can pin a key for a product that root will then trust. Today
  that only steers read-only checks. Once `custom.exec` lands in M3, it is code execution as root.
- Fix: when euid is 0, read only `/etc/rdy/trust.yaml`, never a user path, whatever the environment
  says. Refuse that file, and say why, if:
  - it is a symlink,
  - it is not owned by root,
  - it is group or world writable,
  - its directory is writable by anyone but root.
  
  Write it atomically, mode 0644. Take the system location off the cut list. If it is ever cut, root
  runs need `--key` on every run and never read a user store.

**MF-03. 0003 decision 3. The escaping rule for the embedded JSON is wrong as written.**
- Problem: the ADR says `<`, `>` and `&` are escaped "as `<`, `>`, `&`", which changes nothing. If it
  is built that way, a hostname containing `</script><script>...` ends the data block. The CSP blocks
  inline script today, but the ADR already plans a hashed inline script later, and the portal may
  render this HTML.
- Fix: write the replacements as `<`, `>`, `&`, applied to the serialized JSON (valid,
  because those characters only occur inside JSON strings). Keep the existing ticket's
  `</script><img onerror>` round-trip test.

**MF-04. 0003 decision 1. The report file name comes from the spec, and the write location is unsafe.**
- Problem: `rdy-report-<product>-<UTC timestamp>.json` takes `<product>` from `metadata.product`. That
  value is vendor-controlled, and fully attacker-controlled under `--allow-unsigned`. `product:
  ../../etc/cron.d/x` is path traversal as root. The files are written "side by side" (in the cwd)
  with no rule on modes, existing files or symlinks. In a shared directory like `/tmp`, a pre-planted
  symlink makes root overwrite any file (05 surface 1, T1; INV-08).
- Fix:
  - Validate `metadata.product` in `rdy_spec::validate` as `^[a-z0-9][a-z0-9-]{0,62}$`, and apply the
    same rule to the trusted comment.
  - Write into one newly created output directory: `create_dir`, fail if it exists, mode 0700.
  - Create files with `create_new` and mode 0600, through a directory handle that does not follow
    symlinks (cap-std, or `openat` with `O_NOFOLLOW` via rustix), then temp file plus rename.
  - Exit 70 with a fix hint if any of this fails.

**MF-05. 0009. The egress client has no address policy and follows redirects.**
- Problem: reqwest follows up to 10 redirects by default. A spec endpoint that redirects to
  `169.254.169.254`, or a hostname that resolves to a link-local or metadata address (DNS rebinding),
  gets around the "spec-listed endpoints only, no metadata" rule (05 surface 1, I6; INV-10, INV-11).
  The ADR does not say that response bodies are never stored (INV-12). And the TLS interception check
  uses a verifier that accepts any chain so it can record it. Nothing confines that verifier.
- Fix:
  - Follow redirects by hand, at most 5 hops, and check each hop against the address policy. 03 needs the
    redirect host list, because registry blob redirects are a real install blocker. Record each `Location`.
  - Add a custom `dns_resolver` on the shared client that drops resolved addresses in 169.254.0.0/16,
    fe80::/10 and fd00:ec2::254, and checks literal IPs the same way.
  - Only endpoints listed in the verified spec are reachable, with a cap on how many.
  - Read at most a small fixed number of body bytes, then discard them. Never put a body in evidence.
  - The recording verifier lives only in `net.tls_intercept`. That connection sends no HTTP request
    and no credentials, and the verifier is never reachable from `net::client()` or the M2 upload
    client.

**MF-06. 0010 decision 4. The read-only guarantee for a cluster-admin client is only a test.**
- Problem: "a unit test asserts the check crate never builds a non-GET request". A fixture test only
  covers the code paths it runs. A future check, or a dependency upgrade, can send a write with
  cluster-admin rights and nothing stops it at runtime. The ADR also never says Secrets are off limits
  (INV-13, 05 surface 1, I4 and E1).
- Fix: put a tower layer on the kube client that rejects, at runtime and failing closed:
  - every method except GET,
  - every POST except to `selfsubjectaccessreviews` and `selfsubjectrulesreviews`,
  - any path under `/secrets`.
  
  `connect()` returns only the guarded client type, and `K8sFamily::new` accepts only that type. List
  ConfigMaps metadata-only. Keep the mock API server test as the second line of defence. The 1h "guard
  test" ticket becomes a 3h "guard layer and test" ticket.

**MF-07. 00-overview, M1 calendar. There is no room for the security work 0.1.0 needs.**
- Problem: the calendar is already 96 to 104 hours against a 60 to 90 hour budget, before any security
  ticket. The week 1 "other slices" figure of 4h does not match 06-release-and-distribution.md, which
  holds roughly 35h of M1 release, signing and install.sh tickets. The only security items in M1 are
  two review tickets and deny.toml. Week 6 hands `0.1.0` to design partners, to run as root on real
  customer boxes. Shipping it without output confinement, report redaction, the egress policy and the
  kube guard breaks CLAUDE.md rules 1 and 2.
- Fix: add the 11 standalone tickets and 9 folds listed in "M1 security budget" below (about 27h
  standalone plus 8h folded). Then pick one, and record the choice in 11-backlog.md:
  - (a) Extend M1 by two weeks, to Jan 17, 2027.
  - (b) Keep the date and move non-security work out: `cargo-semver-checks` and golden results per
    release go to M2, since ADR 0007 says nothing publishes before M2. Also move out TLS issuer naming
    and the print stylesheet.
  
  Either way, the security tickets marked "0.1.0 gate" are not on the cut list. Cutting the parser
  property and fuzz tests stays acceptable only if MF-01 lands, because partner builds then parse
  verified bytes only.

## Should fix

**SF-01. 0002. Domain separation and the verifier's edge cases.**
- Problem: minisign has no context string. A vendor who also signs release tarballs with the same key
  produces signatures that verify as spec signatures for any byte string that parses as a spec.
  `minisign-verify` has its own ed25519 implementation (no dalek), and the ADR does not say whether it
  accepts legacy non-prehashed signatures, non-canonical S values or small-order keys.
- Fix: require the trusted comment to start with `rdy-spec-v1 product=<slug> signed_at=<RFC 3339>` and
  reject anything else. Call verify with `allow_legacy = false`. Run Wycheproof EdDSA vectors and
  malleability cases against it in CI. Pin it to an exact version (`=0.2.x`) and review every bump.
  Docs tell vendors to use a dedicated spec-signing key. I will update 05 so this replaces my
  "context string prefix" requirement.

**SF-02. 0002 decision 5 and 0008. `--allow-unsigned` is too wide and too easy to suggest.**
- Problem: the result model has only `Verified` and `Unsigned`, so a spec whose signature is present
  but fails is either refused or reported as merely "unsigned". The ADR does not say the flag is
  argv-only (INV-04). Nothing stops the fix hint for a signature failure from saying "rerun with
  `--allow-unsigned`", which is the social-engineering path in 05 surface 2, T2.
- Fix:
  - Add `SignatureState::Invalid { reason }`.
  - A present but failing signature always exits 64, even with `--allow-unsigned`. The flag covers
    only a missing signature. This tightens CLAUDE.md rule 3; see Plan corrections.
  - The flag is read from argv only. No env var, config file or alias.
  - Signature-failure hints point to "get the vendor's current key or re-download the spec", never
    to the flag.

**SF-03. 0002 decision 4. The M2 portal-served key arrives on the same channel as the spec.**
- Problem: from M2, the share link delivers both the spec and the key that verifies it. That is the
  self-certifying pattern in 05 surface 2, S2. A second channel, a key published on the vendor's own
  domain (for example `/.well-known/rdy-keys.txt`), is not in the alternatives.
- Fix: a portal-served key is shown with its fingerprint and pinned only on an explicit yes. A changed
  key for an already pinned product is a hard failure, never a silent re-pin. Add the vendor-domain
  option to the alternatives table and carry it into the SEC-47 decision.

**SF-04. 0002 decision 2, keygen ticket. Secret key hygiene is not stated.**
- Fix: write keys with `create_new` and mode 0600. Encrypt by default; `--unencrypted` is explicit for
  CI use. `spec sign` refuses a group or world readable key file. Secret bytes are never printed or
  logged. Fold into "rdy spec keygen and rdy spec sign" (+1h).

**SF-05. 0001 decision 3. Aliases are capped, not rejected, and "no unsafe" is asserted, not checked.**
- Problem: a spec never needs anchors or aliases. 05 INV-05 rejects them. A budget only limits the
  damage. The ADR states as fact that serde-saphyr has no unsafe code. I could not confirm that from
  its docs, and its parser dependency counts too.
- Fix: set the alias limit to zero, so any anchor or alias is an error with line and column, and keep
  the budget as well. Before accepting, run `cargo geiger`, or grep the sources of serde-saphyr and its
  parser crate, and write down the result in the ADR.

**SF-06. 0004 decision 4. Gaps in the subprocess policy.**
- Problem:
  - "Cleared environment plus an allowlist" does not say whether PATH is inherited. If it is, a fake
    `getenforce` in a user-writable PATH directory runs as root (05 surface 1, S2).
  - `kill_on_drop` kills only the direct child, so grandchildren outlive the timeout.
  - `clippy::disallowed_methods` bans `std::process::Command` but not `tokio::process::Command`, so
    checks can go around `Exec`.
- Fix:
  - Fixed PATH `/usr/sbin:/usr/bin:/sbin:/bin` when euid is 0. Resolve to an absolute path before
    spawning.
  - Refuse `sudo`, `su`, `doas` and `pkexec`.
  - Start each child in its own process group and kill the group on timeout. On Windows, use a job
    object.
  - Add `tokio::process::Command` to the disallowed list outside the `Exec` implementation.
  - Fold into "Blocking helper and subprocess kill on timeout" (+1h).

**SF-07. 0005 decision 3 (M3, but it shapes the design now).**
- Problem:
  - "Runs as the invoking user" means a vendor command runs as root whenever `rdy` does.
  - `--allow-exec` is a blanket yes that a pasted share-link command can carry.
  - `shell: true` brings back the shell that 05 INV-07 bans.
- Fix:
  - When euid is 0, drop to an unprivileged user unless the check declares `needs: [root]`, and the
    consent prompt says "as root".
  - Bind consent to the exact command list: `--allow-exec=<sha256 of the exec plan>`, or an
    interactive yes.
  - Drop `shell: true`. A vendor who needs a shell writes `["/bin/sh", "-c", ...]` in argv, and the
    report shows it.

**SF-08. 0006 ticket and 00-overview ticket. The static-binary test can push someone to disable PIE.**
- Problem: current Rust musl targets are expected to produce `static-pie` binaries, which keeps ASLR. An
  exit test that greps for "statically linked" (also in 06) either fails, or tempts someone to turn
  PIE off.
- Fix: the test accepts `static-pie linked` and fails on a non-PIE binary. Add a readelf check for
  RELRO and a non-executable stack on both arches. Record any target that is not static-pie.

**SF-09. 0008, 0012, 00-overview (`Report`). The result carries no security provenance.**
- Problem: a reviewer's first two questions are "what did it do" and "what spec ran, signed by whom".
  The report has no action log and no run identity, and `SignatureState` has no product. `message`,
  `Error.message` and panic text may embed secrets. For example, reqwest error text includes the
  request URL, and proxy credentials can leak into context strings.
- Fix:
  - Add to `Report`: `SpecRef { sha256, product }`.
  - Add `SignatureState::Verified { key_id, product, signed_at }`.
  - Add `actions: Vec<Action>`: every command, file read, endpoint and kube request, with outcome.
  - Add `identity { euid, user, kube: { context, server, user } }`.
  - Add `redactions: u32`.
  - Every string field goes through the M1 redactor before it is written. Use `reqwest::Error::without_url()`.
  - This is SEC-17 and SEC-25 in 05.

**SF-10. 0009 decisions 1 to 3. The reqwest 0.13 facts are stale.**
- Problem: reqwest 0.13 removed the root-certificate features and uses `rustls-platform-verifier` by
  default; custom roots go through `tls_certs_only`. The ADR builds the reqwest client with
  `Roots { Mozilla, Os }` and rejects the platform verifier, which reqwest now uses anyway.
- Fix: state the choice explicitly. Use the platform verifier for `net.egress`, which shows what the
  customer's software will see, and for the M2 upload client. Keep the dual-store check on
  tokio-rustls only for `net.tls_intercept`. Confirm `cargo tree -i aws-lc-sys` is empty with these
  features.

**SF-11. 0010. Make the cluster identity visible and refuse surprises.**
- Fix:
  - Print the context, server URL and authenticated user before the first request and in the report
    (05 surface 1, S1).
  - Report `insecure-skip-tls-verify: true` as a warning.
  - Load kubeconfig only from the default path, `KUBECONFIG` or `--kubeconfig`.
  - Exec-plugin output is never logged, even at trace.
  - Fold into "Kube client from kubeconfig or in-cluster" (+1h).

**SF-12. 0011 decision 5. The squat risk was dismissed too fast.**
- Problem: "If someone squats it, nothing breaks" is wrong from the user's side. Anyone who reads the
  directory name and runs `cargo install rdy-cli` installs the squatter's code.
- Fix: publish a no-code `rdy-cli` 0.0.1 placeholder whose description says "install `rdy`". Add it
  to the reserve-names ticket (+0h).

**SF-13. 00-overview, `Context`. Only `Exec` is mediated.**
- Problem: checks get a raw `host_root: PathBuf`, a raw `reqwest::Client` and a raw `kube::Client`.
  File reads, connections and API calls skip the policies and the action log (05 TB2, INV-06).
- Fix: keep it small, not a framework. `Context` holds four handles: `exec`, `fs` (read-only, under
  `host_root`, size capped), `net` (the MF-05 policy client) and `kube` (the MF-06 guarded client).
  Each one appends to the action log. That is also what fixtures replay.

**SF-14. 00-overview, `ProxyConfig`. Proxy credentials are stored as plain `String`s.**
- Problem: `HTTPS_PROXY=http://svc:pa55@proxy:3128` lands in a `String`. A derived `Debug` or a tracing
  field prints it.
- Fix: use a `ProxyUrl` newtype whose `Debug` and `Display` mask the userinfo, plus a test.

**SF-15. 0007 decision 6. The unknown-field rule needs limits.**
- Problem: I accept "unknown check params make the check Skipped", because 0008 caps the verdict at
  Warnings. But the rule as written also covers top-level keys. An unknown `upload:` or `exec:` block
  then degrades quietly instead of failing.
- Fix: the Skipped rule applies only inside a check entry. Unknown top-level, `metadata` or `bundle`
  keys, and duplicate keys anywhere, exit 64. I will align 05 INV-05 with this.

**SF-16. 0003 decisions 2 and 6. Small CSP and link gaps.**
- Fix: add `base-uri 'none'; form-action 'none'` to the CSP. The footer link gets
  `rel="noopener noreferrer"`. The docs security page lists the query parameters the link carries.
  Fold into "Embed result JSON in the HTML report safely" (+0.5h).

**SF-17. 00-overview, M2 done test. The token is passed on argv.**
- Problem: `rdy run <product> --token` puts the token in `ps` output, shell history and CI logs
  (05 surface 4, I3).
- Fix: read the token from `RDY_TOKEN`, `--token-file` or a prompt.

## Nits

- **N-01. 0004.** Cap `--jobs` (for example at 32) so a typo cannot open hundreds of connections from a
  production host.
- **N-02. 0009.** The hand-written CONNECT reader needs a header size cap (8 KiB) and its own timeout.
- **N-03. 0006.** If the allocator benchmark picks mimalloc, it is new C code in the root binary and
  needs a dependency review like any other crate.
- **N-04. 0001 decision 4.** Add a test that `cuda: 12.10` reaches the field as `"12.10"` and not
  `"12.1"`. A plain scalar resolved as a float first would silently weaken a threshold.
- **N-05. 0007.** release-plz needs a write token. Use crates.io trusted publishing and a job with
  minimal `permissions`, like the release job in 06.

## M1 security budget (input to MF-07 and 11-backlog.md)

Cap respected: 11 standalone M1 security tickets. Everything else folds into existing engineering
tickets. "0.1.0 gate" means the ticket must be done before any design partner gets the build.

| # | Standalone ticket (05 id) | Owner | Est | Week | 0.1.0 gate |
|---|---|---|---|---|---|
| 1 | Org 2FA, private reporting, CODEOWNERS and a settings check script (SEC-04) | security-reviewer | 2h | 1 | yes |
| 2 | Harden getrdy.io domain and hosting accounts (SEC-05) | release-engineer | 2h | 1 | yes, before install.sh is served |
| 3 | Confine writes to a new output dir with safe names (SEC-19, MF-04) | rust-engineer | 3h | 3 | yes |
| 4 | Minimal redactor for evidence, errors and logs (SEC-25, SEC-29) | rust-engineer | 4h | 3 | yes |
| 5 | Mediated Context handles with action log and read denylist (SEC-17, SF-13) | rust-engineer | 3h | 3 | yes |
| 6 | Egress address policy, capped redirects, no bodies (SEC-21, MF-05) | check-author | 3h | 4 | yes |
| 7 | M1 redaction corpus, 60 cases (SEC-26) | qa-engineer | 3h | 4 | 30 cases yes, rest by 0.1.1 |
| 8 | No-phone-home strace test on Linux CI (SEC-22) | qa-engineer | 2h | 4 | no, by 0.1.1 |
| 9 | Read-only ClusterRole example and kube identity display (SEC-24) | k8s-expert | 2h | 5 | no, by 0.1.1 |
| 10 | Docs security page and verify-first install (SEC-31) | docs-writer | 2h | 6 | no, by 0.1.1 |
| 11 | Security mailbox and security.txt (SEC-32) | security-reviewer | 1h | 6 | yes |

Folds into existing tickets (about 8h in total):
- Verify minisign signatures: verify before parse, trusted-comment prefix, legacy off, Wycheproof (MF-01, SF-01), +1h.
- Trust store load and save: root-only system store, ownership and mode checks (MF-02), +1h.
- rdy verify and `--allow-unsigned`: argv only, `Invalid` state, safe hints (SF-02), +0.5h.
- rdy spec keygen and sign: key hygiene (SF-04), +1h.
- Blocking helper and subprocess kill: PATH, process group, sudo refusal (SF-06), +1h.
- Read-only guard test becomes guard layer and test (MF-06), +2h.
- Embed result JSON safely: correct escapes, CSP additions (MF-03, SF-16), +0.5h.
- Check trait, Need and Context: refuse setuid (SEC-20), +0.5h.
- Error types with fix hints: sanitize control characters in terminal output (SEC-28), +0.5h.

Already covered elsewhere, not counted here: deny.toml and bans, audit.yml with zizmor, cosign keyless
signing, SBOM and cargo-auditable, install.sh root refusal and verification (06 tickets), and
`forbid(unsafe_code)` (workspace skeleton ticket). Action SHA pins and job `permissions` fold into
06's "CI lint job" ticket.

## Plan corrections found

- CLAUDE.md, rule 3: "refuses unsigned or tampered specs unless `--allow-unsigned` is set" lets the
  flag run a spec whose signature fails. Proposed fix: "refuses unsigned specs unless
  `--allow-unsigned` is set, and always refuses a spec whose signature fails" (SF-02).
- docs/plan/00-overview.md, M1 calendar: week 1's "other slices" hours do not match the M1 tickets in
  docs/plan/06-release-and-distribution.md. Fix: recount from 06 when 11-backlog.md is assembled (MF-07).
- docs/plan/05-threat-model.md (mine), to update after this review: custom.exec is M3 not M4 (ADR 0005);
  the context-string requirement becomes the trusted-comment prefix (SF-01); INV-05 follows SF-15;
  INV-13 drops `dryRun=All` POSTs, which ADR 0010 does not need.

## Tickets implied

- [M1] SEC-04 Org 2FA, private reporting, CODEOWNERS and a settings check script | owner: security-reviewer | est: 2h | depends on: none | exit test: a checklist in the PR shows 2FA required, rulesets on main and v* tags, immutable releases, private vulnerability reporting and CODEOWNERS on security paths.
- [M1] SEC-05 Harden getrdy.io domain and hosting accounts | owner: release-engineer | est: 2h | depends on: none | exit test: registrar lock, DNSSEC, CAA and HSTS verified with public tools and hardware-key MFA confirmed on registrar and Cloudflare.
- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: a product of `../x` fails validation, a pre-planted symlink is not followed, an existing dir is refused, and modes are 0700 and 0600.
- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: canary secrets in env, proxy URL, kubeconfig and command output never appear in the JSON, HTML or stderr at RUST_LOG=trace.
- [M1] SEC-17 Mediated Context handles with action log and read denylist | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine | exit test: a fixture run's JSON lists every command, file read, endpoint and kube request the checks used.
- [M1] SEC-21 Egress address policy, capped redirects, no bodies | owner: check-author | est: 3h | depends on: Shared HTTP client builder with rustls ring, dual roots and proxy env | exit test: a redirect to 169.254.169.254, a hostname resolving to link-local and an unlisted endpoint are all refused, and a body canary never reaches the report.
- [M1] SEC-26 M1 redaction corpus | owner: qa-engineer | est: 3h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: 60 synthetic cases including chunk-boundary and negative cases pass with zero misses in CI.
- [M1] SEC-22 No-phone-home strace test on Linux CI | owner: qa-engineer | est: 2h | depends on: SEC-21 Egress address policy, capped redirects, no bodies | exit test: a no-net spec passes under `unshare -rn` on Linux CI and a contact-set test sees only spec endpoints.
- [M1] SEC-24 Read-only ClusterRole example and kube identity display | owner: k8s-expert | est: 2h | depends on: Read-only guard layer and test for rdy-checks-k8s | exit test: M1 k8s checks pass on kind with only `examples/rbac/rdy-readonly.yaml`, and the report shows context, server and user.
- [M1] SEC-31 Docs security page and verify-first install | owner: docs-writer | est: 2h | depends on: sign-release workflow with cosign keyless and ordering decision | exit test: the page lists what rdy reads and contacts, the report fields and link parameters, and CI runs its verify commands against the latest release.
- [M1] SEC-32 Security mailbox and security.txt | owner: security-reviewer | est: 1h | depends on: SEC-04 Org 2FA, private reporting, CODEOWNERS and a settings check script | exit test: private vulnerability reporting is on, security@getrdy.io receives mail and security.txt is served on getrdy.io.
- [M1] Read-only guard layer and test for rdy-checks-k8s (replaces the 1h guard test ticket) | owner: k8s-expert | est: 3h | depends on: Kube client from kubeconfig or in-cluster with rustls and timeouts | exit test: a runtime layer rejects any write, any non-review POST and any secrets path, and the mock API server records only allowed requests.

## Closure check (M1-001, 2026-10-28)

Reviewer: security-reviewer. Checked on `main` at `8f5705f` against ADRs 0002, 0003, 0009, 0010, 0014,
0015 and 0016 (all Accepted), `docs/plan/00-overview.md`, `docs/plan/02-engine-design.md` revision 3 and
`docs/plan/11-backlog.md`. Quotes are exact. Line numbers are at that commit. No ADR or plan file was
edited.

Result: all seven must-fix items are closed. Three follow-ups (CF-01 to CF-03) are listed below. None of
them reopens a must-fix.

| id | verdict | evidence | smallest fix |
| --- | --- | --- | --- |
| MF-01 verify before parse | closed | `docs/adr/0002-spec-signatures-ed25519-minisign.md:25` "looks up keys pinned for that product, verifies the raw bytes, and only then parses". Line 26: "`metadata.product` must equal the trusted-comment product". `docs/plan/00-overview.md:180` "Never yields a LoadedSpec." Line 186: "private fields, private constructor". Test: `docs/plan/11-backlog.md:256` (M1-120) "before the YAML is parsed (a parser spy proves it)". | none |
| MF-02 root reads only the system trust store | closed | `docs/adr/0002-spec-signatures-ed25519-minisign.md:30` "euid 0: only `/etc/rdy/trust.yaml`, never a user path, whatever HOME or XDG say." Line 32: "Written atomically, mode 0644. Not on any cut list." `docs/plan/00-overview.md:156` "the root-only system trust store" (in the never-cut list). Test: `docs/plan/11-backlog.md:257` (M1-121) "As root with HOME and XDG_CONFIG_HOME pointing at a user store only /etc/rdy/trust.yaml is read". Windows elevated runs: line 258 (M1-122, SEC-60). | none (see CF-01) |
| MF-03 escapes in the embedded JSON | closed | `docs/adr/0003-report-format-html-json.md:31` "every `<` becomes the six characters `<`, every `>` becomes `>`,". Tests: `docs/plan/11-backlog.md:191` (M1-055) "A hostname with `</script>` is written as `</script>`". Line 214 (M1-078): "round-trips through the embedded JSON unchanged and renders as text". | none |
| MF-04 report name and write location | closed | `docs/adr/0003-report-format-html-json.md:16` "`metadata.product` must match `^[a-z0-9][a-z0-9-]{0,62}$`". `docs/adr/0016-output-dir-confinement-cap-std.md:24` "It must be a directory owned by the effective user." Line 30: "Files are created inside the handle with `create_new`, mode 0600 and `fchmod`". `docs/adr/0003-report-format-html-json.md:26` "and the exit code is 70." Test: `docs/plan/11-backlog.md:172` (M1-036) "Product `../x` fails validation, a pre-planted symlink is not followed". | none |
| MF-05 egress address policy, redirects, bodies | closed | `docs/adr/0014-probe-facade-owns-side-effects.md:22` "The facade resolves names and refuses, literal or resolved, every address". Line 25: "The host must be in the calling check's own host set (at most 64 distinct hosts". Line 36: "reads at most 64 KiB of body and discards it (INV-13)". Line 37: "never follows a redirect (the `Location` host is returned)". Lines 33 to 34: "The recording verifier for `net.tls_intercept` is private to the facade and" / "returns a chain, never a stream." Test: `docs/plan/11-backlog.md:230` (M1-094). My fix asked for hand-followed redirects capped at 5 hops. Following none is stricter. Accepted. | none (see CF-03) |
| MF-06 runtime kube guard | closed | `docs/adr/0010-kubernetes-client-kube-rs.md:18` "A tower layer wraps the kube client and rejects, at runtime and failing closed,". Line 20: "any path naming `secrets`." Line 21: "POST only to `selfsubjectaccessreviews` and `selfsubjectrulesreviews`". Lines 26 to 27: "`connect()` returns only the guarded type" / "and `K8sFamily` accepts only that type. ConfigMaps are listed metadata-only." Ticket: `docs/plan/11-backlog.md:239` (M1-103, 3.5 h) "The runtime layer rejects any write, any POST other than the three reviews". A check crate can still build a second, unguarded kube client. That is a lint wall gap, tracked as MF-04 of the ADR 0013 to 0016 review and reopened there. | none here |
| MF-07 M1 room for security work | closed | `docs/plan/11-backlog.md:14` "The founder decided on 2026-10-28: M1 is extended, not cut." `docs/plan/00-overview.md:156` "Never on the cut list: the "0.1.0 gate" security tickets". `docs/plan/11-backlog.md:274` (M1-138) "every 0.1.0-gate security ticket (SEC-04, SEC-05, SEC-17, SEC-19, SEC-21, SEC-22, SEC-24, SEC-25, SEC-26 first 30, SEC-32) is closed". Ticket map: SEC-04 and SEC-32 in M1-011, SEC-05 M1-008, SEC-17 M1-040, SEC-19 M1-036, SEC-21 M1-094, SEC-22 M1-128, SEC-24 in M1-103, SEC-25 M1-048, SEC-26 M1-063. SEC-31 moved to M3-008 with the hosted docs site. My budget said "by 0.1.1", but it was never a 0.1.0 gate. Accepted. Parser property tests are core now, so the fuzz clause of MF-07 no longer applies. | none |

### Follow-ups found during the check

- **CF-01 (low). M1-121 does not test the directory rule.**
  - Problem: `docs/adr/0002-spec-signatures-ed25519-minisign.md:31` refuses a store "in a directory
    writable" by anyone but root. `docs/plan/11-backlog.md:257` (M1-121) tests the symlink, owner and
    group-writable cases only. A user-writable `/etc/rdy` lets a user swap the file by rename.
  - Fix: add "and a store in a user-writable directory exits 64 with trust_store_insecure" to the M1-121
    exit test. Owner: rust-architect, before M1-121 starts.
- **CF-02 (medium). 00-overview still describes the network stack before ADR 0014 and a writer that takes
  a plain `Report`.**
  - Problem: `docs/plan/00-overview.md:325` says "One policy client (ADR 0009)". Line 411 lists reqwest
    for "HTTP egress (ADR 0009)". Line 413 lists rustls-platform-verifier for "OS trust for egress and
    upload". Line 304 has "pub fn write(report: &Report, out_dir: &Path)". ADR 0014 lines 31 to 32 and
    39 reject the platform verifier and ban reqwest in M1. ADR 0015 decision 4 lets writers take only
    `RedactedReport`. Line 384 of 00 says M1-003 pins workspace versions from this table, so M1-003
    could add both crates. 02 lines 526 to 528 fix only the API sketches.
  - Fix: the M1-003 brief takes TLS and HTTP dependencies from ADR 0014 and 02 Appendix A, not from 00.
    M1-009 rewrites 00 lines 304, 325, 411 and 413 to match. Owner: coordinator (M1-003 brief) and
    rust-architect (M1-009).
- **CF-03 (low for M1, blocks M2-026). The upload client design conflicts.**
  - Problem: `docs/adr/0014-probe-facade-owns-side-effects.md:38` sends the M2 upload client to "the M3
    `http_exchange` primitive", and line 39 says "reqwest is banned in `deny.toml`". So an M2 client
    depends on an M3 primitive. `docs/plan/11-backlog.md:329` (M2-026) instead builds the upload client
    on reqwest with the platform verifier, which ADR 0014 lines 31 to 32 reject because it can fetch
    revocation and AIA URLs outside the peer set.
  - Fix: one ADR, before M2-026 starts, that picks the upload stack, its verifier and its `deny.toml`
    entry. Owner: rust-architect, reviewed by security-reviewer.
