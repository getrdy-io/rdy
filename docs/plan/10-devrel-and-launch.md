# DevRel and launch plan

Owner: devrel. Date: 2026-10-28. Status: revision 2, synced with the final 07-cli-ux, 01-spec-format and 06-release-and-distribution. Not yet reviewed.

This document covers everything the open-source community sees: the README, the example specs, the contribution flow, the public launch at the end of M3, the five-day content series, the first-week response playbook, and how we measure adoption without tracking anyone.

Three rules run through all of it.

1. Lead with the problem. Installs fail because the environment isn't ready, not because the product is broken.
2. Show the terminal. Every sample is pasted from a real run of the release candidate. Nothing is typed by hand.
3. Every public claim has a test behind it. If we cannot point at the test, we do not make the claim.

Terminal samples below follow the output format of `docs/plan/07-cli-ux.md` (final) line for line: the banner, the header, the check list sorted by bucket with the fix on the line below each problem, the summary line, the `Report written to` block, the last line and the exit code. Where this file and 07 differ, 07 wins. The samples in the README draft, the Show HN post and the Reddit posts are written from 07's grammar with 07's synthetic names, so they match its format but are not recorded output. The ticket "Golden transcripts for acme-quickstart" replaces them with golden files, and the ticket "Sync README and series samples with 07-cli-ux" checks them. Series posts trim the banner, header and report lines, say so under the block, and keep the check list, the summary line, the last line and the exit code exactly as rdy prints them.

Style: the product is Rdy and the command is `rdy`. Prose about the product says Rdy at the start of a sentence and `rdy` when it means the command. Titles say Rdy.

Skipped required checks: settled (01 section 5.3, ADR 0008 decision 3, 07 section 2.4). A skipped, timed-out or errored `severity: block` check is a required check not run. It gives NOT READY, exit 2. If no check blocked, the last line is `NOT READY: 1 required check was not run` (or `N required checks were not run`). If a check blocked, the last line is plain `NOT READY` and the summary line carries the count. A `severity: warn` check that did not run is an optional check not run and gives `READY with warnings`.

## 1. README plan

### Outline

| # | Section | Job | Length |
| --- | --- | --- | --- |
| 1 | Title, tagline, badges | Say what it is in one line | 5 lines |
| 2 | The problem | Name the pain in three sentences | 5 lines |
| 3 | What it looks like | The signing refusal, then NOT READY, then READY, then the skipped-required case | 110 lines |
| 4 | Quickstart | Zero to a real report in under five minutes | 80 lines |
| 5 | How it works | Spec, checks, report, exit codes | 20 lines |
| 6 | Security and trust | Each claim and how to verify it | 15 lines |
| 7 | Check families and status | What ships now, what is next | 12 lines |
| 8 | Write your own spec | Pointer to docs and to `examples/specs/` | 8 lines |
| 9 | Rdy and the Kubernetes-only preflight tool | Comparison | 10 lines |
| 10 | Project status | Alpha warning, roadmap, license | 8 lines |
| 11 | Contributing, security, license | Links | 5 lines |

Rules for the README:

- The first screen has the problem, the transcript and the install command. Nothing about pricing or the portal above the fold.
- The portal gets one sentence in section 10. It is not needed to use the tool.
- No badges beyond CI, release and license. Three is plenty.
- The five-minute path is timed on a clean VM by someone who has never seen rdy. The ticket does not close until that is done.
- Every command in the README is run in CI against the release build (a docs test). A README that lies is worse than none.
- Every transcript in the README is pasted from a golden file in 07's format, with its exit code. No transcript is edited by hand.
- The install block is the text of `06-release-and-distribution.md`. It is copied, not rewritten.
- The README demo uses `acme-quickstart.yaml`, which can reach READY today. `acme-platform.yaml` appears only in the skipped-required snippet.

### Draft copy

The block below is the README text. It is written for the M1 alpha. Lines marked `[M1-late]`, `[M2]`, `[M3]` or `[M4]` change when that milestone ships. The transcripts are in the output format of `docs/plan/07-cli-ux.md`, with the names of 07's samples (`acme-vm-03.corp.example`, `jdoe`, `proxy.corp.example`). They are placeholders until the golden transcripts exist (see the tickets).

````markdown
# rdy

**Install day should be boring.**

rdy checks a customer's environment against your requirements before install
day. One signed binary. No runtime. Works offline.

## The problem

Installs fail because the environment isn't ready, not because the product is
broken. Not enough RAM. A proxy that blocks the registry. A storage class that
can't do ReadWriteOnce. Somebody finds out on install day, on a call, with the
customer watching.

rdy runs those checks first. The vendor writes down what the product needs.
The customer runs one command and gets a list of what is wrong and how to fix
it.

## What it looks like

A vendor signs its spec. rdy refuses a spec with no signature:

```console
$ rdy run acme-quickstart.yaml
error: no signature found at acme-quickstart.yaml.minisig
fix: ask the vendor for acme-quickstart.yaml.minisig and put it next to the spec. If you wrote this spec yourself, see https://docs.getrdy.io/unsigned
$ echo $?
64
```

The example specs in this repo are not signed. `rdy run` has a flag for that,
`--allow-unsigned`. It runs a spec that has no signature at all, and nothing
else: a signature that does not match is still refused. Each run that uses it
prints a red banner first and again above the verdict, and marks the reports.
The rest of this page uses it.

The next two runs were recorded on a lab VM behind a test proxy. Your output
will differ.

```console
$ rdy run acme-quickstart.yaml --allow-unsigned
WARNING: UNSIGNED SPEC
acme-quickstart.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

rdy 0.1.0
spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)
proxy   http://proxy.corp.example:3128

  BLOCK    host.memory       4.0 GiB found, 8 GiB needed
                             fix from the spec file (not verified): Add RAM or choose a larger node
                             class.
  BLOCK    net.egress        1 of 2 endpoints unreachable: license.acme.example:443 (proxy refused
                             CONNECT, 403)
                             fix from the spec file (not verified): Ask your network team to allow
                             these endpoints through the proxy.
  WARN     host.disk/root    12.0 GiB free on /, 20 GiB needed
                             fix from the spec file (not verified): Free space on / or mount a
                             larger volume.
  PASS     host.cpu          4 vCPUs found, 4 needed
  SKIP     host.disk/system  Does not apply here. This check is for windows only.

2 blocks, 1 warning, 1 passed, 1 not applicable

Report written to ./rdy-report-acme-quickstart-20270309T101502Z/
  rdy-report-acme-quickstart-20270309T101502Z.html
  rdy-report-acme-quickstart-20270309T101502Z.json
  spec.yaml
WARNING: UNSIGNED SPEC
NOT READY
$ echo $?
2
```

Problems come first, each with its fix on the line below. Passing checks come
last. `host.disk/system` is for Windows, so on Linux it is skipped and does not
count: that is the `1 not applicable`. The fix lines say `from the spec file
(not verified)` because this spec has no signature and rdy cannot tell who
wrote it. With a signed spec and a key you trust, the same line says `fix from
acme-quickstart:`.

The team resizes the VM, opens the proxy rule and frees some disk. Then they
run it again.

```console
$ rdy run acme-quickstart.yaml --allow-unsigned
WARNING: UNSIGNED SPEC
acme-quickstart.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

rdy 0.1.0
spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)
proxy   http://proxy.corp.example:3128

  PASS     host.cpu          4 vCPUs found, 4 needed
  PASS     host.memory       15.4 GiB found, 8 GiB needed
  PASS     host.disk/root    48.0 GiB free on /, 20 GiB needed
  PASS     net.egress        2 of 2 endpoints reachable through the proxy
  SKIP     host.disk/system  Does not apply here. This check is for windows only.

0 blocks, 0 warnings, 4 passed, 1 not applicable

Report written to ./rdy-report-acme-quickstart-20270309T102140Z/
  rdy-report-acme-quickstart-20270309T102140Z.html
  rdy-report-acme-quickstart-20270309T102140Z.json
  spec.yaml
WARNING: UNSIGNED SPEC
READY
$ echo $?
0
```

The last line is one of three, and each has an exit code: `READY` (0),
`READY with warnings` (1), `NOT READY` (2). Two of them can carry a reason
after a colon, and the next section shows one. Exit 64 means the input must change,
for example a missing signature. Exit 70 means rdy could not deliver its
result. Both print `error:` and `fix:` lines and no verdict.

### A required check that cannot run is not a pass

A check the spec marks `severity: block` that rdy could not run (a missing
privilege, no kubeconfig, a check family this build does not have) is a
required check not run. It never produces READY. This run has no kubeconfig,
and `acme-platform.yaml` also asks for gpu and aws checks that this build does
not have:

```console
$ rdy run acme-platform.yaml --allow-unsigned
WARNING: UNSIGNED SPEC
acme-platform.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

rdy 0.1.0
spec    acme-platform >=4.2   (acme-platform.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    acme-node-01.corp.example   rhel 9.4   x86_64
user    jdoe (not root)
proxy   http://proxy.corp.example:3128
cluster no kubeconfig found

  SKIP     k8s.version       Not run. No Kubernetes cluster was reachable. (required)
                             fix from rdy: Set a kubeconfig, or pass --kube-context <name>, then run
                             again.
  SKIP     gpu.cuda          Not run. This version of rdy has no gpu checks yet. (required)
                             fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                             how to go on.
  SKIP     aws.iam           Not run. This version of rdy has no aws checks yet. (required)
                             fix from rdy: Install a newer rdy. If there is none yet, ask the vendor
                             how to go on.
  SKIP     k8s.storageclass  Not run. No Kubernetes cluster was reachable.
                             fix from rdy: Set a kubeconfig, or pass --kube-context <name>, then run
                             again.
  PASS     host.cpu          16 vCPUs found, 8 needed
  PASS     host.memory       62.8 GiB found, 32 GiB needed
  PASS     host.disk         180.0 GiB free for /var/lib (its own mount), 100 GiB needed
  PASS     net.egress        2 of 2 endpoints reachable through the proxy

0 blocks, 0 warnings, 4 passed, 3 required checks not run, 1 optional check not run

Report written to ./rdy-report-acme-platform-20270309T143005Z/
  rdy-report-acme-platform-20270309T143005Z.html
  rdy-report-acme-platform-20270309T143005Z.json
  spec.yaml
WARNING: UNSIGNED SPEC
NOT READY: 3 required checks were not run
$ echo $?
2
```

A skipped check marked `severity: warn` is an optional check not run. It only
gives `READY with warnings`. A gate written as `[ $? -le 1 ]` never passes an
environment nobody checked.

## Quickstart

You need a Linux or macOS machine and five minutes. No account. No sudo.

**1. Install.**

```sh
curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh
"$HOME/.local/bin/rdy" version
```

`[M1]` The install endpoint goes live in M2. Until then the script is an asset
of each release:

```sh
TAG=v0.1.0-alpha.3   # use the newest tag on the releases page
curl --proto '=https' --tlsv1.2 -sSfL "https://github.com/getrdy-io/rdy/releases/download/$TAG/install.sh" | sh
```

The script puts one binary in `~/.local/bin` (or `RDY_INSTALL_DIR`). It checks
the Sigstore signature on `SHA256SUMS` with cosign, then the SHA-256 of the
archive, and only then makes anything executable. It needs cosign 3 or newer.
Without cosign it stops and prints the manual steps. It never uses sudo, never
edits your shell profile, and prints a PATH hint. It refuses to run as root; if
you must, `curl ... | sh -s -- --allow-root` installs to `/usr/local/bin`.
`RDY_INSECURE_SKIP_SIGNATURE=1` skips the signature check only, prints a loud
warning, and the SHA-256 check still runs. Read the script first if you like:
`curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | less`.

Windows: download the zip from the
[releases page](https://github.com/getrdy-io/rdy/releases) and verify it as
below. A PowerShell installer comes later. `[M3]`

Rather not pipe to a shell? Download, verify and unpack by hand. The archive
holds `rdy-<triple>/rdy`. One signed file, `SHA256SUMS`, lists every asset:

```sh
TAG=v0.1.0-alpha.3   # use the newest tag on the releases page
BASE=https://github.com/getrdy-io/rdy/releases/download/$TAG
F=rdy-x86_64-unknown-linux-musl.tar.gz   # pick the file for your platform
curl -sSfL -O "$BASE/$F" -O "$BASE/SHA256SUMS" -O "$BASE/SHA256SUMS.sigstore.json"
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/getrdy-io/rdy/.github/workflows/sign-release.yml@refs/tags/$TAG" \
  --certificate-github-workflow-repository getrdy-io/rdy \
  --certificate-github-workflow-ref "refs/tags/$TAG" \
  --certificate-github-workflow-trigger push \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # macOS: shasum -a 256 -c on the matching line
tar xzf "$F" && ./rdy-x86_64-unknown-linux-musl/rdy version
```

**2. Get an example spec.**

```sh
TAG=v0.1.0-alpha.3   # the same tag
curl -sSfO "https://raw.githubusercontent.com/getrdy-io/rdy/$TAG/examples/specs/acme-quickstart.yaml"
rdy run acme-quickstart.yaml
```

If `rdy` is not found, put `~/.local/bin` on your `PATH`. The script printed
the line to add.

The last command fails on purpose, with the error shown above and exit 64. The
example describes a made-up product and has no signature. Real specs are
signed by the vendor, and rdy checks the signature.

**3. Run it.**

```sh
rdy run acme-quickstart.yaml --allow-unsigned
```

It takes a few seconds. rdy runs what it can, and tells you what it could not
run and why. It never asks for sudo.

Expect `net.egress` to BLOCK and the last line to be `NOT READY`, with exit 2.
The example talks to `registry.acme.example`, which does not exist, so the
message names the endpoints it could not reach. That is expected. The
`proxy refused CONNECT` message in the recording above only happens on a
network with a proxy that says no. On a small machine you may also see BLOCK
on `host.memory`, or WARN on `host.disk/root`, each with its fix.

**4. Read the report.**

rdy writes a new folder in the current directory and never overwrites one. The
run above printed its name:

```sh
open rdy-report-acme-quickstart-20270309T101502Z/rdy-report-acme-quickstart-20270309T101502Z.html      # macOS
xdg-open rdy-report-acme-quickstart-20270309T101502Z/rdy-report-acme-quickstart-20270309T101502Z.html  # Linux
```

Use the folder name rdy printed for your run. Each check shows what rdy
measured, what the spec asked for, and the fix. The page is one file with no
external requests. You can email it or print it. The `.json` file has the same
data for scripts. The folder also holds a copy of the spec. `--out-dir <dir>`
picks the parent folder and `--no-report` writes no files. If the folder cannot
be created, rdy says so before it runs any check and exits 70.

**5. Make it green.**

Copy the spec and point it at something you can reach.

```sh
cp acme-quickstart.yaml my-spec.yaml
$EDITOR my-spec.yaml   # set net.egress endpoints to ["github.com:443"]
rdy run my-spec.yaml --allow-unsigned
echo $?
```

On a machine with 4 cores, 8 GiB of RAM and 20 GiB free, that ends in `READY`
and exit 0. If the disk is short you get `READY with warnings` and exit 1,
because the disk check is optional. In a real install you fix the machine, not
the spec. Here we edit the spec so you can see a green run on whatever you are
holding.

## How it works

- A **spec** is a YAML file of requirements. `apiVersion: rdy/v1`, `kind:
  Readiness`, a list of checks with `severity: block` (required) or `warn`
  (optional), and an optional `fix` message. The check's message says what rdy
  measured. The `fix` line under it says what to do. A vendor's `fix` replaces
  rdy's own advice in the terminal, and the HTML report shows both. When a
  check could not run, rdy's own fix is shown, because the vendor's would tell
  you to fix something nobody measured.
- A **check** measures one thing: memory, an egress path, a storage class. Each
  check declares what it needs (root, a kube context, cloud credentials). rdy
  runs what it can and reports what it could not. When two or more checks need
  root, it prints a Tip and still never asks for sudo.
- A **report** is HTML and JSON in a new folder. The verdict is `READY`,
  `READY with warnings` or `NOT READY`.
- A **signature** from the vendor's key covers the spec. `rdy verify` checks it
  and `rdy trust add <product> --key <file>` pins the vendor's key, after you
  compare its fingerprint with what the vendor told you. rdy refuses unsigned
  or tampered specs unless you pass `--allow-unsigned` for an unsigned one, and
  then says so loudly, in the terminal and in every report.
- **Output.** The reading output goes to stderr. With `--json`, stdout carries
  only the JSON result, the same bytes as the `.json` file. `NO_COLOR` or a
  pipe turns colour off. The words PASS, WARN, BLOCK, SKIP, TIMEOUT and ERROR
  carry the meaning, so nothing depends on colour.
- **Proxy URLs** are printed without any `user:password@` part, in the terminal,
  the HTML report and the JSON.

Use it as a CI gate:

```sh
rdy run spec.yaml --json > result.json
echo $?   # 0 ready, 1 ready with warnings, 2 not ready, 64 usage, 70 internal
```

Scripts can rely on the exit code and on `verdict`, `summary` and
`checks[].status` in the JSON. Do not parse `message` or `fix`. The JSON only
grows within `rdy/v1`.

## Security and trust

rdy runs inside your environment, sometimes as root. You should not take our
word for what it does. Here is how to check.

| Claim | How to verify |
| --- | --- |
| Checks connect only to the endpoints in the spec | Run `rdy run spec.yaml --allow-unsigned --no-network` and `strace -f -e trace=socket` on it: rdy opens no socket, and network and Kubernetes checks are skipped. Or run it in a network-less namespace: `unshare -rn rdy run spec.yaml --allow-unsigned` (needs unprivileged user namespaces; Ubuntu 24.04 blocks them by default, so use `sudo unshare -n` there). Network checks BLOCK, nothing else changes. `rdy run --dry-run spec.yaml` lists what each check would read or contact, and runs nothing `[M2]`. |
| Nothing is uploaded by default | Upload is a separate command that needs your approval. Read `crates/rdy-cli/src/upload.rs`, the only code that sends results anywhere `[M2]`. |
| It never asks for sudo | It does not call sudo. Skipped checks say which privilege they needed. |
| An unsigned spec or a one-run key cannot pass quietly | Both print a red banner first and again above the verdict, and mark every report. `rdy verify spec.yaml` shows the signer, the fingerprint and where the trust came from. |
| Releases are signed | `cosign verify-blob` on `SHA256SUMS`, as above. SBOM attached to every release. |
| The install script fails closed | No cosign means stop. The only override skips the signature check, says so loudly, and still checks the SHA-256. The script is a short POSIX sh file you can read. |
| One static binary, no OpenSSL | `ldd rdy` says "not a dynamic executable" (wording varies by libc). rustls only. |
| Specs cannot run arbitrary commands | At this stage specs only select built-in checks. Custom script checks do not exist yet. `[M3]` From M3 a spec may ask for a command, and rdy runs it only if you approve that exact command list. |
| No telemetry | There is none. The only network traffic is what a check exists to make. |

Found a problem? See [SECURITY.md](SECURITY.md).

## Check families

| Family | Status |
| --- | --- |
| Host: CPU, memory, disk, ports, OS | Alpha |
| Host: kernel, cgroups, time sync, SELinux and AppArmor, security agents `[M1-late]` | Next |
| Network: egress through a proxy, proxy settings, TLS interception | Alpha |
| Network: DNS, registry, MTU, bandwidth `[M1-late]` | Next |
| Kubernetes: version, storage classes, RBAC for the install identity, admission, nodes | Alpha |
| Redacted diagnostics bundle `[M2]` | Next |
| AWS account: IAM dry run, quotas, regions `[M3]` | Planned |
| GPU: driver, CUDA, VRAM, device plugin `[M4]` | Planned |

A spec may name a check this build does not have yet. rdy says "Not run. This
version of rdy has no gpu checks yet.", counts it as not run, and never reports
it as a pass.

Missing a check that would have saved you an install? Open a
[check request](https://github.com/getrdy-io/rdy/issues/new/choose).

## Write your own spec

Start from a file in [`examples/specs/`](examples/specs/): a quickstart, a
full platform, Kubernetes only, an air-gapped host, and a GPU workload. Run
`rdy spec lint your-spec.yaml` to catch mistakes (exit 0 clean, 1 warnings, 2
errors). To sign it, make a key with `rdy spec keygen acme-signing`, then
`rdy spec sign your-spec.yaml --secret-key acme-signing.key`. Send customers
the `.pub` file by a second route. They pin it with `rdy trust add`. The
reference is at [docs.getrdy.io](https://docs.getrdy.io).

## Rdy and the Kubernetes-only preflight tool

The open-source Kubernetes preflight and support-bundle tool most vendors
already know is a good project. If you ship to Kubernetes through its vendor's
platform, use it. rdy aims at a wider job: one binary that checks a VM, a
Kubernetes cluster and (soon) a cloud account, with signed specs and a report
a non-engineer can read. Both tools run on the machine where you start them.
If your target is one cluster you may need only that tool. If it is a mix of
hosts, clusters and accounts, try rdy.

## Status

rdy is alpha software. The spec format (`rdy/v1`) can still change before 1.0,
and we will say so in the changelog. Linux x86_64 is the best tested platform.
Apache-2.0 licensed. A hosted portal for vendors is in development. The CLI
does not need it. Every command works offline.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Bugs and check requests are welcome.
````

Notes for the README ticket:

- The `unshare`, `strace` and `ldd` lines must be tested on the release build before they ship. Replace them if they do not hold.
- The install block, the manual path, the tag form (`v0.1.0-alpha.N`, every release is a prerelease through M1), the signer identity and the archive layout (`rdy-<triple>/rdy`) are copied from the contract table and the verification command in `docs/plan/06-release-and-distribution.md`. Re-copy them from there when 06 changes. The customer one-liner is that table's text; the pinned release URL is the M1 route until the Worker serves `getrdy.io/install` (M2).
- Install paragraph must match what `install.sh` does: `~/.local/bin` or `RDY_INSTALL_DIR`, refuses root without `--allow-root`, never edits the shell profile, fails closed without cosign, `RDY_INSECURE_SKIP_SIGNATURE=1` skips the signature only.
- The refusal block is 07 C.5 and the banner is 01 section 4.7. No error, fix or hint may name `--allow-unsigned` or `rdy run --key`; the README prose may, because it is documentation, as `--help` and docs.getrdy.io do.
- The three run transcripts follow 07 section 2 line for line: banner, header (`rdy`, `spec`, `sig`, `host`, `user`, `proxy`, `cluster` only when the spec has Kubernetes checks), checks sorted by bucket with a `fix from ...:` line under each problem, the summary line (07 section 2.4), the report block (three files when unsigned, four when signed), the banner's first line again, the verdict. Replace them with the golden files. Do not edit by hand.
- Commands in the README are provisional only where marked. Flags in this draft: `--allow-unsigned`, `--json`, `--out-dir`, `--no-report`, `--no-network`. `--dry-run` and `--timeout` are M2, `self-update` is M3. None of those appears in an M1 command line here.
- The proxy line in the first transcript only appears on a network with a proxy that refuses. Do not present it as what a reader will see.
- The "Both tools run on the machine where you start them" line is deliberate. See the corrections section: the plan's multi-node claim is not an rdy advantage in M1.

## 2. `examples/specs/` plan

All specs are synthetic. Every hostname ends in `.example` (RFC 2606). The product is a made-up company called Acme. No real customer or vendor appears anywhere.

| File | Product | Purpose | Families used | Runs fully in |
| --- | --- | --- | --- | --- |
| `acme-quickstart.yaml` | acme-quickstart | The README and quickstart spec. Four checks (`host.disk` twice, once per OS family, with a `name` each), no Kubernetes, nothing that needs root. A laptop reaches a real result in seconds and can reach READY after one edit. On Linux and macOS `host.disk/system` is `Does not apply here` and never counts. Also the golden-test spec. | host, net | M1 |
| `acme-platform.yaml` | acme-platform | The canonical spec from the plan. Used by the docs, the integration tests and `cargo run`. Mixed families. `rdy spec lint` exits 1 on it by design (two warnings: `gpu.cuda` and `aws.iam` are reserved ids this build does not have). It ends NOT READY until the cloud (M3) and gpu (M4) families ship, because those checks are required and cannot run. | host, net, k8s, gpu, aws | M1 (host, net, k8s), M3 (aws), M4 (gpu) |
| `acme-k8s-only.yaml` | acme-operator | A Helm chart plus operator vendor. Run from a laptop with a kubeconfig. Shows `k8s.version` with `over_max: block`, `k8s.nodes`, storage classes, RBAC for the install identity and admission. Good first spec for the kind-cluster demo. No `net.egress`: from a laptop it would test the laptop, not the pods. | k8s | M1 |
| `acme-airgap-host.yaml` | acme-edge | One VM, no internet, no Kubernetes. Only endpoint is an internal mirror (`via_proxy: direct`). Shows the offline flow: run, carry the report out by hand. Exercises most host checks. `host.kernel`, `host.cgroups`, `host.time_sync` and `host.lsm` are M1-late, so until they ship the run is NOT READY (`host.kernel` is required and not run). | host, net | M1-late (M1 for cpu, memory, disk, ports, egress) |
| `acme-inference-gpu.yaml` | acme-inference | GPU inference on Kubernetes. Parses now, runs fully in M4. Ends NOT READY until then. Proves the spec format already has room for the GPU family, and gives gpu-expert a target. | gpu, k8s, net | M4 |

Rules:

- Files are checked in unsigned. They are never real design-partner prerequisites. The README says plainly that running them needs `--allow-unsigned`.
- Every file starts with a comment saying it is synthetic and what it is for.
- A CI job runs `rdy spec lint` on every file in `examples/specs/`. Exit 0 and 1 pass (warnings are allowed, and `acme-platform.yaml` has two by design). Exit 2 and 64 fail, with the file name in the error. A schema change that breaks an example fails the build. The example gets fixed in the same PR.
- Every block and warn check in every file has a `fix`. Examples teach by imitation. A spec may omit `fix`, and the check then uses its built-in text. A vendor `fix` replaces rdy's advice in the terminal, labelled with the product when the signature is verified and the key is pinned, else "the spec file (not verified)". When a check could not run, rdy's own fix is shown.
- Each file has an integration test that runs it against a fixture environment and compares the output to a golden report (qa-engineer owns the fixtures).
- Check ids and parameters are final as of `01-spec-format.md` section 2.7 and `03-check-catalog.md`. Where they differ, the schema wins and the examples change. Names the examples use after the draft-2 renames: `access_modes` (not `needs`) on `k8s.storageclass`; `over_max` (not `max_severity`) on `k8s.version`; `can` on `k8s.rbac`, with entries written `verb resource.group`; `k8s.nodes` (not `k8s.node_resources`); `host.lsm` (not `host.selinux`); `version: v2` on `host.cgroups`; `free` on `host.ports`. Other renames in 01 that a future example may use: `tolerance_percent` and `tolerance_result` (not `band`) on `host.memory`, `swap: forbid` (not `off`), `forbid` on `host.security_agents`. `net.tls_intercept` and `net.dns` carry the TLS and DNS checks.
- `acme-inference-gpu.yaml` names `gpu.device_plugin`, which is not an id in the catalog. See "Plan corrections found".

All five files are in `/home/user/rdy/examples/specs/` and are the source of truth. The copy below shows the shape of the canonical one, as it is on disk.

```yaml
apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme-platform
  version: ">=4.2"
checks:
  - id: host.cpu
    min: 8
    severity: block
    fix: "Use a node with at least 8 vCPUs."
  - id: host.memory
    min: 32Gi
    severity: block
    fix: "Add RAM or choose a larger node class."
  - id: host.disk
    path: /var/lib
    min: 100Gi
    severity: warn
    fix: "Mount a larger volume at /var/lib before install."
  - id: net.egress
    endpoints: ["registry.acme.example:443", "license.acme.example:443"]
    via_proxy: auto
    severity: block
    fix: "Ask your network team to allow these endpoints through the proxy."
  - id: k8s.version
    min: "1.28"
    severity: block
    fix: "Upgrade the cluster to Kubernetes 1.28 or newer."
  - id: k8s.storageclass
    access_modes: ["ReadWriteOnce"]
    severity: warn
    fix: "Mark a storage class that supports ReadWriteOnce as the default."
  - id: gpu.cuda
    min: "12.4"
    severity: block
    fix: "Install CUDA 12.4 or newer on every GPU node."
  - id: aws.iam
    simulate: ["eks:DescribeCluster", "ec2:CreateSecurityGroup"]
    severity: block
    fix: "Add the missing actions to the install role. The report lists them."
bundle:
  collect: ["journal:7d", "k8s:events", "file:/etc/acme/*.yaml"]
  redact: ["aws_keys", "bearer_tokens", "emails"]
```

The file on disk also carries comments that mark `gpu.cuda` and `aws.iam` as "(later)".

**Behaviour the examples depend on.** The canonical spec holds checks that no M1 binary can run. The engine parses them and reports `SKIP` with the message `Not run. This version of rdy has no gpu checks yet.` and ` (required)` after it, and rdy's own fix. It never fails the parse and never reports a pass.

Required checks that cannot run make the verdict NOT READY, exit 2. With a block in the run the last line is `NOT READY` and the summary line carries the count. With no block it is `NOT READY: N required checks were not run` (`NOT READY: 1 required check was not run` for one). This is settled (01 section 5.3, ADR 0008 decision 3, 07 section 2.4), no longer a proposal. So `acme-platform.yaml` and `acme-inference-gpu.yaml` will not reach READY until their families ship. That is correct, and the docs say it out loud. The README demo uses `acme-quickstart.yaml`, which holds only checks every M1 build can run, and shows `acme-platform.yaml` only in the skipped-required transcript.

## 3. Public launch checklist (end of M3)

The launch is an announcement, not a first exposure. The repo and releases are public from M1 so design partners and their security reviewers can read the code and download signed binaries. We just do not promote it. Stars and attention arrive at launch.

### Gates: do not post until all are true

- [ ] M3 scope is done: AWS account checks, Stripe, docs, Team tier on sale. The portal is not needed to try the CLI.
- [ ] Three people who have never seen rdy ran the README quickstart on a clean VM. Median time under five minutes. Fix every stumble first.
- [ ] Every sentence in the posts is true of the release candidate. Walk the claims table at the end of section 7.
- [ ] Every personal claim (the founder's stories, numbers and history) was written by the founder from memory. Nothing in these drafts is a fact until then.
- [ ] The founder's HN account has a comment history. The founder's Reddit accounts have history on each of r/devops, r/rust and r/kubernetes. The current rules of each sub were read this week.
- [ ] Release is signed, `cosign verify-blob` on `SHA256SUMS` passes from a clean machine, the hashes in `SHA256SUMS` match the archives, SBOM is attached, `cargo deny check` and `cargo audit` are clean.
- [ ] `install.sh` tested on Ubuntu LTS, Debian, RHEL-family, Alpine, macOS arm64 and macOS x86_64. Windows zip tested by hand. `install.ps1` is M3 and is checked here too. The script refuses root without `--allow-root`, stops without cosign, and the signature-only override still checks the SHA-256.
- [ ] Repo hygiene: `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and PR templates, `CHANGELOG.md`, topics set, social preview image, Discussions on, private vulnerability reporting on.
- [ ] Ten issues labelled `good first issue` or `check request`, each with a clear exit test.
- [ ] docs.getrdy.io has install, first run, spec reference and one page per shipped check family, and the page at `/unsigned` that the signing refusal links to.
- [ ] Every terminal transcript in the posts equals a golden file in 07's format, exit code included, or says "output trimmed" and drops only the banner, header and report lines.
- [ ] Asciinema cast or short screen recording of the NOT READY then READY runs, recorded from the release candidate.
- [ ] getrdy.io and the install endpoint are static and cached (Cloudflare). They survive an HN front-page spike. Confirm GitHub release downloads are not rate limited for a spike (they are served from a CDN).
- [ ] Plausible goals set: docs first-run page, install page, waitlist form.
- [ ] Founder calendar cleared. The founder is at the keyboard for the first eight hours after each post. Book vacation days for launch week.
- [ ] lobste.rs account exists with an invite and some history (see timeline, week -3).
- [ ] Waitlist email drafted. Launch FAQ drafted (section 5).
- [ ] The threat model summary (`docs/plan/05-threat-model.md`) is published or linked from docs. HN readers will ask.

### Show HN

Rules we follow: submit the GitHub repo URL, no signup, nothing to buy, no asking anyone to upvote, post on a weekday morning US Eastern time, stay on the thread. Post from the founder's own HN account, not a new or throwaway one. Do not email the waitlist a link to the HN item and do not mention HN to them: it looks like a voting ring. If the post sinks unseen, email the HN moderators and ask about the second-chance pool. Do not repost. HN takes either a URL or text, not both. We submit the URL, so the text below goes in as the author's first comment, posted within a minute. The second comment, further down, is posted after it only if the thread asks for the background.

**Title** (63 characters):

```text
Show HN: Rdy, check a customer's environment before install day
```

**Body** (posted as the first comment; it leads with the problem). Bracketed lines are placeholders. The founder fills them from real experience or deletes them:

```text
I'm a sales engineer. [FOUNDER: one true sentence about the script you have
written before, and where. Use the real number of times and companies.]

[FOUNDER: one true story, with the real number of days a POC or install was
lost to the environment.]

Most failed installs have the same shape. The product works. The
environment was not ready: not enough RAM, a proxy that blocks the registry,
a storage class that cannot do ReadWriteOnce. Somebody finds out on install
day.

rdy is that checklist as a program. One static Rust binary. The vendor
writes a YAML spec of what the product needs and signs it. The customer runs
it. This example spec is unsigned, hence the flag and the banner. Output is
from the release candidate on a lab VM behind a test proxy:

    $ rdy run acme-quickstart.yaml --allow-unsigned
    WARNING: UNSIGNED SPEC
    acme-quickstart.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
    The spec decides which files rdy reads and which hosts it contacts.
    Run it only if you wrote it yourself or got it from the vendor in a way you trust.
    Every report from this run is marked UNSIGNED SPEC.

    rdy 0.1.0
    spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
    sig     UNSIGNED (allowed by --allow-unsigned)
    host    acme-vm-03.corp.example   rhel 9.4   x86_64
    user    jdoe (not root)
    proxy   http://proxy.corp.example:3128

      BLOCK    host.memory       4.0 GiB found, 8 GiB needed
                                 fix from the spec file (not verified): Add RAM or choose a larger node
                                 class.
      BLOCK    net.egress        1 of 2 endpoints unreachable: license.acme.example:443 (proxy refused
                                 CONNECT, 403)
                                 fix from the spec file (not verified): Ask your network team to allow
                                 these endpoints through the proxy.
      WARN     host.disk/root    12.0 GiB free on /, 20 GiB needed
                                 fix from the spec file (not verified): Free space on / or mount a
                                 larger volume.
      PASS     host.cpu          4 vCPUs found, 4 needed
      SKIP     host.disk/system  Does not apply here. This check is for windows only.

    2 blocks, 1 warning, 1 passed, 1 not applicable

    Report written to ./rdy-report-acme-quickstart-20270309T101502Z/
      rdy-report-acme-quickstart-20270309T101502Z.html
      rdy-report-acme-quickstart-20270309T101502Z.json
      spec.yaml
    WARNING: UNSIGNED SPEC
    NOT READY
    $ echo $?
    2

Each result has a fix. The run writes an HTML report and a JSON report. Exit
codes are 0 ready, 1 warnings, 2 blockers, so CI can gate on it. If a check
the spec requires cannot run (no root, no kubeconfig), the answer is NOT
READY, not a quiet pass.

What it does and does not do:

- Runs what it can without root and tells you what it could not check. It
  never asks for sudo.
- Checks connect only to the endpoints in the spec. Results leave the
  machine only if you run the separate upload command and approve it. The
  upload code and the report renderer are in the repo so you can read
  exactly what would leave.
- Specs are signed with ed25519 (minisign format). A spec with no signature
  is refused unless you pass --allow-unsigned, which prints a red banner and
  marks every report. A spec with a bad signature is always refused.
- Static musl binary, rustls, no OpenSSL, no runtime. It works offline.
- Specs select built-in checks. A spec can ask for a command only if you
  approve that exact command list. [FOUNDER: verify against the release
  candidate. If custom.exec did not ship, say "Specs cannot run commands."]
- rdy run --dry-run prints what each check will read or connect to, and the
  privilege it needs, without running anything. [ships in M2; verify it
  exists in the release candidate]

Where it is rough: it is alpha. [verify against the release candidate] Host, network, Kubernetes and AWS account
checks exist. GPU checks are not there yet. Linux x86_64 is best tested.
Windows has the fewest checks. The spec format can still change before 1.0.

If you know the Kubernetes-only preflight tool most vendors use: it is
good, and if you are a Kubernetes shop on its vendor's platform you may not
need this. I wanted one binary
for a VM, a cluster and a cloud account, with signed specs and a report the
customer's manager can read.

Business model, so nobody has to guess: the CLI is Apache-2.0 and free. I
plan to sell a hosted portal to vendors (share links, a dashboard of results
across prospects). The CLI never needs it.

I built it part time with an AI coding agent doing most of the typing. I
review everything, and the tests, clippy, cargo-deny and a threat model are
in the repo. A security audit comes before I sell anything to enterprises.

What I want from you: tell me which check would have saved your last bad
install, and read the redaction and upload code if you have a spare hour.

https://github.com/getrdy-io/rdy
```

Check before posting: the sample output in the body is the golden file from the release candidate, untrimmed, with the exit code. On HN a blank line ends a code block, so the transcript shows as several blocks. That is fine. Remove any sentence that is not true on that build.

**Second comment** (only if people ask why or how; otherwise hold it for replies):

```text
Author here. Some context that did not fit in the post.

Why a new tool: [FOUNDER: from your own experience, which failures were not
about Kubernetes alone? Name only ones you saw.] I wanted one thing that
covers a VM, a cluster and a cloud account.

How to verify what it does: releases are signed with cosign (command is in
the README), the SBOM is attached, and the threat model is in docs/. The
network-off test is in CI.

What I am least sure about: the spec format. If you have written
preflights for your own product, please look at examples/specs/ and tell
me what you cannot express.

I will be here all day.
```

### r/devops

Lead with the question. Disclose that you built the tool. Read the subreddit's current self-promotion and AI-assistance rules the week before and follow them. If promotion is limited to a weekly thread, post there. The same rule applies to r/rust and r/kubernetes below.

**Title:** `How do you check a customer's environment before an on-prem or BYOC install?`

```text
I do pre-sales engineering for a self-hosted product. [FOUNDER: one true
story of an install or POC that failed for a boring environment reason, from
your own history or from interview N.] The usual suspects are a proxy that
blocks the registry, a node with less RAM than asked for, and a storage class
that cannot do RWO. A PDF checklist rots, and so does a bash script.

How do you handle this? Docs, scripts, Kubernetes preflight tooling,
something else?

Disclosure: I got tired of rewriting the script and built an open-source
tool for it (rdy, Apache-2.0, one Rust binary, signed specs). Link below.
I am more interested in what failed installs you have seen than in whether
you use it.

https://github.com/getrdy-io/rdy
```

Stay in the thread. Answer with experience first, link second.

### r/rust

Technical angle. Flair: project or show-off, whichever the sub currently requires. Ask for code review on specific design points.

**Title:** `rdy: a single static binary that runs vendor-signed readiness checks (rustls, musl, ed25519)`

```text
I have been building rdy, a CLI that checks whether a machine, a Kubernetes
cluster or a cloud account is ready for a piece of software. Apache-2.0.

Some things that might interest this sub:

- Workspace of small crates: rdy-spec (serde + schemars, minisign-verify for
  ed25519 signed specs, so stock minisign can verify a spec), rdy-engine (check trait, scheduler, result model, askama
  for the HTML report), one crate per check family. The JSON schema for the
  spec is generated from the types, and so are the docs.
- Every check has a timeout and a declared privilege need. A check that
  cannot run reports why, instead of failing the run.
- musl static builds, rustls everywhere, no OpenSSL. cargo-dist for
  releases, cosign signatures, cargo-auditable and a CycloneDX SBOM.
- #![forbid(unsafe_code)] except where an FFI crate needs it.
- Golden-file tests for reports and redaction, proptest on the spec parser.

I would like review on: the Check trait (is it too clever or not enough), how
I model "could not run" next to pass/warn/block, and the Windows host checks.
Most of the typing is done by an AI coding agent, and I review all of it.

https://github.com/getrdy-io/rdy
```

Check each bullet against the repo on launch day. If a bullet is not true, cut it.

### r/kubernetes

**Title:** `Open-source preflight for installs into customer clusters: RBAC, storage classes, admission, node resources`

```text
Vendors who ship a chart or operator into customer clusters keep hitting the
same failures: the install identity cannot create ClusterRoles, there is no
default storage class that supports RWO, Pod Security Admission or another
admission policy rejects the workload, the nodes are smaller than the docs
assumed.

rdy is an Apache-2.0 CLI that runs these checks from a kubeconfig before
install day and prints a fix for each failure. It is read-only. RBAC is
checked with SelfSubjectAccessReview, so it asks the API server what you
can do instead of guessing. It prints the context and server it is about to
touch before the first request, and you pick them with --kubeconfig and
--kube-context.

Example (kind cluster, acme-k8s-only.yaml in the repo; banner, header and
report lines trimmed; this is the draft from series day 3, replace it with the
release candidate's output):

    $ rdy run acme-k8s-only.yaml --allow-unsigned
      BLOCK    k8s.nodes         1 node ready, 3 needed
                                 fix from the spec file (not verified): Add worker nodes or use a larger
                                 instance type.
      WARN     k8s.storageclass  Default class standard (rancher.io/local-path) supports ReadWriteOnce,
                                 ReadWriteMany needed
                                 fix from the spec file (not verified): Install a storage class that
                                 supports ReadWriteMany, or turn off shared volumes in the chart.
      PASS     k8s.version       Server v1.30.0, 1.27 to 1.31 needed
      PASS     k8s.rbac          3 of 3 actions allowed
      PASS     k8s.admission     Namespace default allows baseline

    1 block, 1 warning, 3 passed
    NOT READY
    $ echo $?
    2

Limits: it runs from one kube context at a time, it is alpha, and it
is not a replacement for the established Kubernetes-only preflight tool if
you already use it with its vendor's platform. I would like to know which admission and storage failures you see most, so I
can add checks for them.

https://github.com/getrdy-io/rdy
```

Verify before posting that RBAC really uses `SelfSubjectAccessReview` and that the checks are read-only. If check-author chose something else, say what they chose.

### lobste.rs

Lobsters expects authors to say plainly when they wrote the thing, and does not like launch hype. Submit the repo link once, with the tags `rust`, `devops` and `show` (use whichever tags the site currently offers). Tick "I am the author". Needs an account with an invite, so start in week -3. Comment on other people's posts for a while first. Submit on a different day from HN.

Submission text:

```text
I wrote this. rdy is a small Rust CLI that checks whether a machine, a
Kubernetes cluster or an AWS account meets a vendor's requirements for
installing their software, and prints a fix for each failure. Specs are
YAML, signed with ed25519. It is Apache-2.0, alpha, and builds a static
musl binary. I would value comments on the spec format and on the
Check trait in rdy-engine.
```

### PreSales Collective

Audience: sales engineers, not Rust developers. The post is about POC pain, not about Rust.

Ask the community managers before posting anything that links to a product. Read the channel rules. Post in the channel they point to, as yourself, a member who has been posting for months (the plan has a weekly LinkedIn story habit and Slack presence from M0).

**Post:**

```text
The POC that stalled on a proxy.

[FOUNDER: one true story of a POC that stalled on the customer's
environment. Use the real number of days. See interview N for a second
story if you want one that is not yours.]

[FOUNDER: one true sentence on the script you wrote for it.] I turned it
into a small open-source tool called rdy so I stop rewriting it. It checks
whether the machine is big enough, whether it can reach your endpoints
through their proxy, and whether the cluster is the right version.

Three questions for this group:

1. What is the dumbest thing that ever cost you a POC week?
2. Do you give customers a checklist, a script, or nothing?
3. How early do you know the environment is bad?

If you want to see it: github.com/getrdy-io/rdy. It is free and open source.
If you ship a self-hosted or BYOC product and want a draft readiness spec
for your product, send me your prerequisites page and I will write you a
first version.

I am running a roundtable on this on <date>. Details in the events channel.
```

The last offer is a founder decision, see "Decisions needing an ADR". Bracketed lines are placeholders for the founder's own words.

**Roundtable pitch** (to the community team):

```text
Title: Why POCs stall on the environment, and how to catch it before kickoff

Format: 45 minutes, cameras optional, not recorded unless the room agrees.
Max 25 people.

Plan:
  10 min  Three anonymous POC failure stories, mapped to the check that
          would have caught each. [FOUNDER: use real stories, e.g. from
          interviews N, N and N, with permission.]
  20 min  Open floor. Everyone brings one install failure. We write down the
          check as we go, in plain English: what to measure, what is good,
          what to tell the customer.
  10 min  Live: turn those checks into a readiness spec for a made-up
          product. Show the customer's view of a run.
   5 min  What to try on Monday. No pitch, no signup.

Leave with: a one-page list of your top ten environment checks, and a spec
file if you want one.

About me: sales engineer with a DevOps background. I built an open-source
tool for this and will say so once at the start.
```

Do not sponsor an event at launch. Plan allows $0 to $5k later; spend nothing until there are numbers.

### Partner announcements

The BYOC platforms are described by category here on purpose. This repo does not name competitors or incumbents. The list of target companies and contacts lives in a private note outside the repo and is never committed.

Rule: nobody is called a partner, and no logo is used, until they say yes in writing. First contact is a short note and a specific ask. Talk to each at least three weeks before launch (week -3). Do not claim integrations that do not exist.

| Partner | What they are (as the plan describes them) | What to ask | What to offer |
| --- | --- | --- | --- |
| BYOC deployment platforms (three to contact) | Platforms that help vendors deploy and run software in customer cloud accounts. Their checks run inside their own deployments. | A 20-minute call with someone on solutions or docs. Which environment problems their customers hit before a deployment or an egress-only access connector can come up. Whether a pre-flight step is useful. A line in their docs or community page if so. | An example spec for an AWS BYOC install. A spec that checks the egress path a connector needs. A sample CI step that runs `rdy` before the platform deploys. A joint post when it works. |
| Rancher (SUSE) | Kubernetes management. RKE2 has its own host prerequisites. | Someone to review the Kubernetes and host checks against RKE2 and Rancher-managed clusters. A mention in community docs or a slot at a community meetup. | A tested example spec for Rancher-managed clusters. Credit for the reviewers. |
| OpenShift (Red Hat) | Kubernetes distribution with security constraints and its own admission rules. | A review of the admission and SCC checks by someone who runs OpenShift. A place to publish a how-to. | A tested example spec. We say "tested on OpenShift" only after we run it on a real cluster (OpenShift Local or the developer sandbox). |

Rules for the announcements:

- One short email each. Subject names the specific ask. Body is five sentences: who I am, what rdy is, what I noticed about their product's install problems, the one ask, a link.
- Announce nothing on launch day unless they replied yes and approved the wording.
- Track replies in a plain table. After 14 days with no reply, stop. Do not chase.

### Launch week, day by day

Dates are relative. Launch day is a Tuesday.

| When | What |
| --- | --- |
| Week -3 | Book the roundtable. Request the lobste.rs invite and start commenting. Send partner emails. Ask the PreSales Collective team how they handle product posts. |
| Week -2 | Feature freeze. Cut release candidate. Run the three-stranger quickstart test. Fix what they hit. |
| Week -1 | Verify every claim in the posts against the release candidate. Record the cast. Write and schedule the five series posts. Draft the waitlist email. Pre-write the launch FAQ. Tag the stable release. |
| Mon (day -1) | Series post 1 (host checks) goes out. Final check of install script, docs links, Plausible goals. Sleep. |
| **Tue (launch)** | 08:30 US Eastern: post Show HN. Post the author comment. Stay on the thread, reply to every comment. 10:00: post series day 2 (network). After the HN post is live: send the waitlist email, linking to the repo and not to the HN item. Fix real bugs fast. No other community posts today. |
| Wed | 09:00: r/rust post. 12:00: PreSales Collective post (if the community team agreed). Series day 3 (Kubernetes). Triage overnight issues. Cut 0.x.1 if there are real bugs. |
| Thu | 09:00: r/kubernetes post. Afternoon: roundtable. Send partner announcements that were approved in writing. Series day 4 (cloud account). |
| Fri | 09:00: r/devops post (or the weekly thread). Submit to lobste.rs. Series day 5 (bundle and redaction). Write the week's notes. |
| Next Mon | Metrics snapshot (section 7). Publish 0.x.1 release notes. Short thank-you post with what we learned and what we will fix first. Close or label every issue opened in launch week. |

If HN does not take off, do nothing dramatic. Do not repost within a week. The Reddit and community posts still go out on schedule, because they reach different people.

## 4. "One check family a day" series

Five short posts, one per weekday of launch week. LinkedIn is the main home. Each also goes on the blog at getrdy.io as a short page with the same terminal output, and each links to its docs page. Each post is about 150 words and one terminal block. Never longer than a screen.

Format for each post:

1. One line that names the failure.
2. The terminal block.
3. Two sentences on why this fails installs.
4. One call to action.

Terminal rules for the series. Every block is pasted from the release candidate, in the format of `docs/plan/07-cli-ux.md`: checks sorted by bucket (blocks, required checks not run, warnings, passed, does not apply), the fix on the line below each problem, then the summary line, the last line and `$ echo $?`. A post that shows a partial run says "Output trimmed" under the block and leaves out only the banner, the header and the `Report written to` lines. It never drops a check, the summary line or the last line. The blocks below are drafts that follow that format. The runs are unsigned, so every fix line reads `from the spec file (not verified)`, and each post says in one line that the spec is an unsigned example. Replace each draft with real output. The snippets use `.example` names.

### Day 1 (Mon): Host

**Angle:** "Your 16 GiB node has 15.7 GiB. rdy knows that is fine." Hosts fail quietly: old kernel, wrong cgroups, a port already taken, SELinux enforcing, a clock off by a minute. The memory line shows the tolerance: a nominal size is not blocked on rounding.

**Demo:** `rdy run examples/specs/acme-airgap-host.yaml --allow-unsigned`. Needs a build that has the M1-late host checks (kernel, cgroups, time sync, SELinux). On an earlier build those four are `Not run` and the verdict is NOT READY by count.

```console
$ rdy run acme-airgap-host.yaml --allow-unsigned
  BLOCK    host.kernel     4.18.0 found, 5.10 needed
                           fix from the spec file (not verified): Upgrade to a distribution kernel
                           5.10 or newer.
  BLOCK    host.ports      8443 in use (process unknown without root)
                           fix from the spec file (not verified): Stop whatever is listening on
                           these ports, or ask the vendor for a different port.
  WARN     host.cgroups    cgroup v1 in use, v2 wanted
                           fix from the spec file (not verified): Boot with
                           systemd.unified_cgroup_hierarchy=1.
  WARN     host.time_sync  clock skew 94s, limit 5s
                           fix from the spec file (not verified): Point chrony or systemd-timesyncd
                           at an internal time source.
  WARN     host.lsm        SELinux is enforcing, permissive or disabled wanted
                           fix from the spec file (not verified): Install the acme-edge SELinux
                           policy module, or set permissive mode.
  PASS     host.cpu        4 vCPUs found, 4 needed
  PASS     host.memory     15.7 GiB found, 16 GiB needed, inside the 5% tolerance
  PASS     host.disk       180.0 GiB free for /opt/acme (its own mount), 50 GiB needed
  PASS     net.egress      1 of 1 endpoints reachable

2 blocks, 3 warnings, 4 passed
NOT READY
$ echo $?
2
```

Output trimmed: banner, header and report lines.

**CTA:** Run it on the oldest server you have. Tell us which host check we are missing: open a check request. If you want the process name behind a busy port, run it as root yourself. rdy never asks you to, and when two or more checks need root it prints a Tip instead.

### Day 2 (Tue): Network

**Angle:** "Works on my laptop. The proxy has other ideas." Proxy allowlists, TLS interception and DNS cause most failed POCs.

**Demo:** the egress, DNS and TLS interception checks behind a proxy. No example file holds `net.dns` or `net.tls_intercept`, so the post carries the whole spec (`net-demo.yaml`) and the reader can paste it. `net.tls_intercept` tests every `net.egress` host by default.

```yaml
apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme-net-demo
  version: ">=1.0"
checks:
  - id: net.egress
    endpoints: ["registry.acme.example:443", "license.acme.example:443"]
    via_proxy: auto
    severity: block
    fix: "Ask your network team to allow these endpoints through the proxy."
  - id: net.dns
    names: ["registry.acme.example"]
    severity: block
    fix: "Ask the DNS team to resolve registry.acme.example from this network."
  - id: net.tls_intercept
    forbid_interception: false
    severity: warn
    fix: "Ask the network team to bypass TLS inspection for registry.acme.example, or install the inspection CA."
```

```console
$ rdy run net-demo.yaml --allow-unsigned
  BLOCK    net.egress         1 of 2 endpoints unreachable: license.acme.example:443 (proxy refused
                              CONNECT, 403)
                              fix from the spec file (not verified): Ask your network team to allow
                              these endpoints through the proxy.
  WARN     net.tls_intercept  registry.acme.example: chain is trusted by this machine only, issuer
                              Acme Corp Inspection CA
                              fix from the spec file (not verified): Ask the network team to bypass
                              TLS inspection for registry.acme.example, or install the inspection
                              CA.
  PASS     net.dns            registry.acme.example resolves to 10.20.0.14

1 block, 1 warning, 1 passed
NOT READY
$ echo $?
2
```

Output trimmed: banner, header and report lines.

**CTA:** Run the network checks from a machine behind your own proxy. Send us the failure you saw that we did not catch.

### Day 3 (Wed): Kubernetes

**Angle:** "Three things stop `helm install`: RBAC, storage classes, admission."

**Demo:** reproducible by anyone with a kind cluster. rdy prints the context and server it is about to touch in the `cluster` header line, before the first request.

```console
$ kind create cluster
$ rdy run acme-k8s-only.yaml --allow-unsigned
  BLOCK    k8s.nodes         1 node ready, 3 needed
                             fix from the spec file (not verified): Add worker nodes or use a larger
                             instance type.
  WARN     k8s.storageclass  Default class standard (rancher.io/local-path) supports ReadWriteOnce,
                             ReadWriteMany needed
                             fix from the spec file (not verified): Install a storage class that
                             supports ReadWriteMany, or turn off shared volumes in the chart.
  PASS     k8s.version       Server v1.30.0, 1.27 to 1.31 needed
  PASS     k8s.rbac          3 of 3 actions allowed
  PASS     k8s.admission     Namespace default allows baseline

1 block, 1 warning, 3 passed
NOT READY
$ echo $?
2
```

Output trimmed: banner, header and report lines.

That is the whole run. A one-node kind cluster fails the node count on purpose, and its default storage class supports ReadWriteOnce only.

**CTA:** Run it on a cluster you can throw away. Tell us which admission policies bite you most.

### Day 4 (Thu): Cloud account

**Angle:** "Find out the IAM role is missing a permission before step 14 of the install."

**Demo:** the AWS IAM dry run with a read-only role. The check needs cloud credentials and `iam:SimulatePrincipalPolicy`, which is read-only. That shows the least-privilege point. Without credentials the check is not run, and because the spec requires it, the run is NOT READY. The spec (`aws-demo.yaml`):

```yaml
apiVersion: rdy/v1
kind: Readiness
metadata:
  product: acme-aws-demo
  version: ">=1.0"
checks:
  - id: aws.iam
    simulate: ["eks:DescribeCluster", "ec2:CreateSecurityGroup"]
    severity: block
    fix: "Add the missing actions to the install role. The report lists them."
```

```console
$ rdy run aws-demo.yaml --allow-unsigned
  BLOCK    aws.iam  1 of 2 actions denied for role acme-install: ec2:CreateSecurityGroup
                    fix from the spec file (not verified): Add the missing actions to the install
                    role. The report lists them.

1 block, 0 warnings, 0 passed
NOT READY
$ echo $?
2
```

Output trimmed: banner, header and report lines.

**CTA:** Run it in a sandbox account with a read-only role. Show us your most annoying quota or permission failure.

### Day 5 (Fri): Bundle and redaction

**Angle:** "What leaves the box? Nothing, and then only what you approve." Redaction runs before anything is written to disk.

**Demo:** build a bundle and show the manifest and the redaction summary. The bundle output format is not in 07 yet. The M2 ticket "Output for bundle, upload, report and redact" sets it, and this sample is replaced by that golden. The folder and file names follow `04-bundle-and-redaction.md`.

```console
$ rdy bundle examples/specs/acme-platform.yaml --allow-unsigned
  collected   journal:7d, k8s:events, 2 files
  redacted    3 aws_keys, 2 bearer_tokens, 14 emails
  wrote       ./rdy-bundle-acme-platform-20270309T101502Z/rdy-bundle-acme-platform-20270309T101502Z.tar.zst (1.2 MiB)
  not uploaded. To send it: rdy upload <file>
              (read the manifest first)
```

Output trimmed: the UNSIGNED SPEC banner.

**CTA:** Try to break the redactor. If a secret gets through, report it privately under SECURITY.md. We will credit you.

Command names in the day 5 sample (`rdy bundle`, `rdy upload`) are 07's M2 commands.

The GPU post is not in this series because the GPU family ships in M4. It becomes a stand-alone post when it does (backlog, M4).

## 5. First-week response playbook

### Rules

- Reply to every top-level comment on the HN thread, on the same day, with an answer in the first sentence. No defensiveness, no marketing words.
- If someone is right, say so and file the issue while they watch. Link it.
- Never argue about whether the product should exist. Answer the question asked.
- No sock-puppets, no asking friends to upvote. Friends may comment if they have real experience.
- Real bugs get a fix and a patch release inside 48 hours. Say so in the thread.
- Triage every issue within 24 hours. Label it. Reply even if the answer is "not now".
- Keep a `launch-fixes` project board: one column per day.
- If a security issue shows up in public, ask the reporter to move it to private reporting, thank them, fix it, publish an advisory.

### Likely objections

| Objection | Answer |
| --- | --- |
| "`curl \| sh` is a bad idea." | Agreed that it is a trust leap. The script is short, does one thing, and never needs root: it installs to `~/.local/bin` after checking the Sigstore signature on `SHA256SUMS` and then the archive's SHA-256, stops if cosign is missing, refuses to run as root unless you pass `--allow-root`, and never edits your shell profile. If you do not want to pipe it, the README shows the download, `cosign verify-blob` and unpack steps. Packages (Homebrew, winget, apt) come later. |
| "It runs as root in a customer's environment. Why would I trust that?" | It does not need root and does not ask for it. Each check declares the privilege it needs. Without it, the check is skipped and the report says which one and why. If the spec requires that check, the run says NOT READY instead of passing. The binary is open source, signed, has an SBOM, and we publish a threat model. Checks connect only to the endpoints in the spec. The only code that sends results anywhere is the upload client (from M2), it is a separate command that needs your approval, and it is in the repo. An independent audit comes before we sell to enterprises. |
| "Just use the existing Kubernetes preflight tool." | Maybe you should. If you are on Kubernetes and its vendor's platform, that tool is mature and has far more mileage than rdy. rdy is for a wider mix: one binary for a VM, a cluster and a cloud account, with signed specs and a report a non-engineer can read. Both tools run on the machine where you start them, so that is not a difference today. |
| "Why Rust?" | A static binary with no runtime installs in locked-down and air-gapped boxes. Memory safety matters for something that may run as root in someone else's environment. The check engine will later be built as a library other installers can embed. Go would have met the first goal too. Rust met all three. |
| "What about telemetry?" | None. The binary makes no network call unless a check exists to make it, or you run the separate upload command and approve it. We count downloads from GitHub and requests to the install script, nothing else. The network-off test is in CI. |
| "Another YAML DSL." | It is a list of built-in checks with thresholds. No logic, no templating. If you can read a Kubernetes manifest you can read a spec. Tell me what you cannot express and I will look. |
| "Can a malicious spec run commands?" | At this stage no. Specs only select built-in checks and set parameters. From M3 a spec may ask for a command, and rdy runs it only after the customer approves that exact command list with `--allow-exec`. An unsigned spec with a command check is refused. [Verify against the release candidate.] |
| "`--allow-unsigned` teaches people to skip signing." | It allows one thing: a spec with no signature at all. A signature that does not match is refused with or without it. It prints a red banner first and again above the verdict, and marks every report UNSIGNED SPEC. No error message suggests the flag. It is documented at docs.getrdy.io/unsigned, with when not to use it. |
| "Is this AI slop?" | I used an AI coding agent for most of the typing and I review all of it. Judge the repo: tests, golden files, clippy with warnings denied, cargo-deny, a threat model. If you find something sloppy, open an issue. |
| "What does the paid part do? Will the CLI get crippled?" | The paid part is a hosted portal: share links, a results dashboard, history. The CLI, the spec format and the checks stay Apache-2.0. Vendors pay for workflow, not for the right to run a check. |
| "Windows?" | A Windows build exists. It has the fewest checks. Which ones matter most to you? Open a check request. |
| "Who are you? What if you quit?" | One founder, part time, with a day job. That is the risk. It is Apache-2.0, the formats are documented, and anyone can fork it. |

Add every new objection to this table the same day and to the public FAQ the next.

## 6. Contribution guide and issue templates

### `CONTRIBUTING.md`

Written to `/home/user/rdy/CONTRIBUTING.md`, revised 2026-10-28 to match 07, 01 and 06. Contents: before you start (issue first), rules every check must follow (including the two-line `error:` and `fix:` form and the rule that no hint names `--allow-unsigned` or `run --key`), build and test commands, the five CI legs, pull request rules, DCO sign-off, AI-assisted change disclosure, spec and result format changes need a design note or ADR and the JSON only grows within `rdy/v1`, conduct, license. It must be re-verified on a fresh clone once the workspace exists (ticket below).

### Other community files

| File | Notes |
| --- | --- |
| `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1, unchanged. Contact is a project mailbox, not the founder's personal address. |
| `SECURITY.md` | Owned by security-reviewer. Must exist before launch. Points to GitHub private vulnerability reporting, gives a reply time, says what we consider in scope (redaction bypass, signature bypass, privilege issues, install script, upload path). devrel only links to it. |
| `.github/PULL_REQUEST_TEMPLATE.md` | Checklist taken from CLAUDE.md: tests, clippy, fmt, cargo deny, docs, CHANGELOG, DCO. Plus: "Does this touch privileges, network, redaction, signing or the install script? If yes, say how." |
| `.github/ISSUE_TEMPLATE/config.yml` | Blank issues off. Contact links: Discussions for questions, SECURITY.md for vulnerabilities. |

### Issue templates (GitHub issue forms, YAML)

**`bug_report.yml`**

| Field | Type | Notes |
| --- | --- | --- |
| What happened | textarea, required | |
| What did you expect | textarea, required | |
| Command you ran | input, required | Ask them to remove secrets. |
| `rdy version` output | input, required | |
| Exit code and last line | input, required | For example `2` and `NOT READY`. |
| OS and architecture | dropdown plus free text | Linux x86_64, Linux aarch64, macOS, Windows. Include distro. |
| Where it ran | dropdown | VM, Kubernetes, cloud account, container, other |
| The JSON report or relevant lines | textarea | Warn: check for hostnames and secrets first. rdy redacts bundles, not the terminal. |
| Checkboxes | required | I searched existing issues. This is not a security problem. |

**`check_request.yml`**

| Field | Type | Notes |
| --- | --- | --- |
| The install failure | textarea, required | What went wrong, in plain words. The story matters most. |
| What should rdy measure | textarea, required | |
| Where does the data come from | textarea | Command, file or API, per OS if known. |
| Privilege needed | dropdown | None, root, kube context, cloud credentials, unsure |
| Suggested thresholds | textarea | What is pass, warn, block |
| Suggested fix text | textarea | What would you tell the customer? |
| Family | dropdown | Host, network, Kubernetes, cloud, GPU, data stores, other |
| Would you write it | dropdown | Yes, with help; yes; no |

**`security_report`**: not a form. `config.yml` carries a contact link named "Report a security issue" that goes to the private advisory page and says "Read SECURITY.md first". The template chooser then shows security reports go private. There is deliberately no public template for it.

Labels created up front: `bug`, `check request`, `good first issue`, `help wanted`, `needs info`, `security-followup` (private use), `launch-fix`, plus one per family (`host`, `net`, `k8s`, `cloud`, `gpu`).

## 7. Metrics without tracking users

The plan's 12-month targets are 3,000 GitHub stars and 20,000 CLI installs. The 12 months start on launch day. The CLI has no telemetry, so every number comes from a third party that already counts it.

| Metric | Target | Source | How to read it |
| --- | --- | --- | --- |
| GitHub stars | 3,000 | GitHub API | `gh api repos/getrdy-io/rdy --jq .stargazers_count`, weekly, written to a CSV in the private repo. |
| Release binary downloads | part of 20,000 | GitHub releases | `gh api repos/getrdy-io/rdy/releases --jq '.[].assets[] \| {name, download_count}'`. Count binary archives only (`rdy-<triple>.tar.gz` and `.zip`). Leave out `.sha256`, `sha256.sum`, `SHA256SUMS`, `SHA256SUMS.sigstore.json`, `install.sh`, the SBOM and `source.tar.gz`. |
| `cargo install` downloads | part of 20,000 | crates.io | Download count on the `rdy` crate page. |
| Install script requests | funnel number, not added | Cloudflare analytics on `getrdy.io/install` | Count of `GET` requests with status 200, excluding known bots. We do not store IP addresses. The script itself does not call home. |
| Homebrew installs | not measurable | none | Public Homebrew analytics cover core formulae, not third-party taps. Do not report a number. |
| Forks, contributors, open and closed issues | track | GitHub API | Weekly. |
| Median time to first reply on an issue | under 24 hours | GitHub API | Computed monthly from issue timelines. |
| Docs first-run page views | funnel | Plausible | Page views on the quickstart page, no cookies. |
| Waitlist signups | 500 | Waitlist tool | Plan target, owned by the website. |
| Design-partner conversations from the PreSales Collective | 25 | CRM, entered by hand | Founder logs each one. |

**Definition of an install.** An install is one release binary archive downloaded from GitHub, plus one `cargo install rdy` download. That is an install event, not a user. CI jobs, mirrors, re-installs and bots inflate it, and we cannot remove them without tracking people, which we will not do. Install-script hits are reported beside it as a funnel number and never added, because each script run also downloads a release asset and would count the same install twice.

In public we say "downloads", not "users". In private we use the numbers as a trend line.

Add a script `scripts/metrics.sh` (M3) that pulls the GitHub and crates.io numbers into one CSV row. Cloudflare numbers are read from the dashboard by hand once a week.

The plan also wants a vendor-sourced conversion number ("10% of paying vendors sourced from a prospect-side run"). The report links to getrdy.io with the vendor's product name in the URL. The product name is already in the spec. The link must carry no run id, hostname or customer data. Clicks are counted by Plausible on the site, never by the CLI.

### Public claims and the test behind each

Used for the pre-launch walk. Ownership in brackets.

| Claim | Test or evidence |
| --- | --- |
| Works offline | CI runs the binary in a network-less namespace against fixtures. [qa-engineer] |
| Never asks for sudo | Grep and test: no `sudo` invocation in the tree; runs as an unprivileged user in CI. [qa-engineer] |
| Static binary, no OpenSSL | CI check on `ldd` or `file` output, and `cargo deny` bans `openssl-sys`. [release-engineer] |
| A spec with no signature is refused without the flag, a bad signature always | Integration tests on `rdy run` with no signature, a bad signature, and a bad signature with `--allow-unsigned` (exit 64 each). [security-reviewer] |
| An unsigned spec or a one-run key never passes quietly | Golden transcripts show the banner first and again above the verdict, and the reports are marked. [qa-engineer] |
| The install script fails closed | install.sh tamper tests: no cosign stops, a bad signature aborts, the override skips the signature only. [release-engineer] |
| Nothing uploaded by default | Test that no outbound connection is made without the upload flag. [qa-engineer] |
| Releases are signed with an SBOM | Release workflow, verified from a clean machine. [release-engineer] |
| Redaction runs before write | Golden-file redaction tests. [qa-engineer] |
| Specs cannot run commands without consent | Through the M3 launch the schema has no field that executes a command. From M4, `custom.exec` runs only with `--allow-exec` for the exact command list, and an unsigned spec with `custom.exec` exits 64. [rust-architect, security-reviewer] |
| Report has no external requests | Golden HTML test that fails on any `src=`, `href=` or `url(` pointing off the file. [qa-engineer] |
| Proxy credentials are never printed | Golden test with `HTTPS_PROXY=http://user:pass@proxy.acme.example:3128` that finds no `user` or `pass` in terminal, HTML or JSON output. [qa-engineer] |
| A required check that cannot run gives NOT READY | Golden transcript for a skipped `severity: block` check: exit 2, and `NOT READY: N required checks were not run` when nothing blocked. [qa-engineer] |

## Plan corrections found

Revision 2 of this file (2026-10-28) took in the final 07, 01 and 06. The first six items below are the changes it made to its own text, so reviewers can check them. The rest are corrections to other documents.

- This file, README draft, Show HN sample, r/kubernetes sample and series blocks, against `07-cli-ux.md` sections 2 and 4 and Appendix C. Fixed here: every transcript now has the banner (five lines, and its first line again above the verdict), the `rdy`, `spec`, `sig`, `host`, `user`, `proxy` header (and `cluster` only when the spec has Kubernetes checks), checks sorted by `bucket` with a `fix from ...:` line under each problem and no `Fixes:` block, `1 not applicable` in the summary, a report folder block (three files when unsigned, four when signed), the last line, and `$ echo $?`. Also fixed: the signing refusal is C.5, which no longer names `--allow-unsigned` or `rdy run --key`; the report folder is never overwritten, so quickstart step 4 no longer says "overwrite the last run"; `NOT READY: N required checks were not run` appears only when no block was seen.
- This file, README "How it works" and Security table, against 07 section 1. Fixed here: `rdy run --dry-run` is M2 (it was "M1 stretch"), `--timeout` is M2 and `self-update` is M3, so none is in an M1 command line. The "network off" claim now uses `--no-network` (M1) and `strace`, and keeps the `unshare` line. The ticket "rdy run --dry-run (stretch)" is deleted; its work is part of SEC-40 in 07's tickets.
- This file, README install block and manual path, against `06-release-and-distribution.md`. Fixed here: the customer command is `curl --proto '=https' --tlsv1.2 -sSf https://getrdy.io/install | sh`, live in M2; M1 users run the pinned release URL. The manual path verifies one signed file, `SHA256SUMS` (bundle `SHA256SUMS.sigstore.json`, identity `sign-release.yml@refs/tags/<TAG>`), then the archive hash, as 06 says archives are not signed one by one. The old draft fetched a `.sha256` and a bundle per archive and used the identity `release.yml`. The install paragraph now says `RDY_INSTALL_DIR`, `--allow-root`, cosign 3 or newer, fail closed, and the signature-only override.
- This file, examples section and series, against `01-spec-format.md` section 2.7. Fixed here: the field names `access_modes`, `over_max`, `can`, `version: v2` and the ids `k8s.nodes`, `host.lsm`, `net.tls_intercept`; the provisional-id warning is gone, because the ids are final. Lint tickets pass on exit 0 and 1 (07 corrections).
- This file, Show HN and r/rust: "Unsigned or tampered specs are refused unless you pass --allow-unsigned" was wrong, because a tampered spec is refused even with the flag. "ed25519-dalek" was wrong, because ADR 0002 uses `minisign-verify` and `minisign`. Both fixed.
- This file, claims "Specs cannot run commands" (README table, HN body, objections, claims table): `custom.exec` is an M4 check (03, section 9, ADR 0005) and the launch is at the end of M3, so the claim holds at launch; after M4 it must be worded as "only with the customer's approval of the exact command list (`--allow-exec`), and an unsigned spec with `custom.exec` is refused" (01 section 4.7). Reworded; the founder checks it against the release candidate.
- `examples/specs/acme-inference-gpu.yaml`: `gpu.device_plugin` is not an id in `03-check-catalog.md` (the catalog has `k8s.device_plugins`, M1-late, and `gpu.devices`). Lint would error with `unknown_check`, so `spec sign` refuses it and CI lint fails. Fix: replace it with `k8s.device_plugins` and `resources: [{name: nvidia.com/gpu, min_total: 2}]`, or reserve the id in 01. Owner: check-author with devrel.
- `CLAUDE.md`, "Names and places": the install line `curl -sSf https://getrdy.io/install | sh` lacks `--proto '=https' --tlsv1.2`, which 06's contract table has. Fix: use 06's text. Also `rdy-plan.md`, user flow step 1, and 06: the sales one-liner should call `"$HOME/.local/bin/rdy"`, because `~/.local/bin` may not be on `PATH` in that shell.
- `docs/plan/rdy-plan.md`, "How a POC flows" step 1: `rdy run acme-platform --token abc123` assumes (a) specs can be run by name, (b) a portal token exists, and (c) `rdy` is already on `PATH` after the install script. None is defined for M1. `--token` is M2 at the earliest. Fix: until M2, the documented command is `rdy run <file.yaml>`. Add name and token forms to the docs only when the portal ships.
- `docs/plan/rdy-plan.md`, "Website plan, Stack": "Install endpoint: `get.<domain>`". The naming section and `CLAUDE.md` say `getrdy.io/install`. Fix: use `https://getrdy.io/install` everywhere and drop `get.<domain>`.
- `docs/plan/rdy-plan.md`, "Check families at launch" lists GPU, data stores and custom script checks as launch families. The milestone table puts cloud in M3 and GPU in M4, and gives data stores and custom checks no milestone. Fix: add a column to the check list saying which milestone each family ships in, give data stores and custom checks a milestone or move them to "later". Launch copy only claims what ships by the end of M3: host, network, Kubernetes, AWS account, bundle and redaction.
- `docs/plan/rdy-plan.md`, example spec: `registry.acme.io` and `license.acme.io` may be real domains. Every machine that runs the example would query them. Fix: use `.example` names (RFC 2606), as `examples/specs/` does. Update the plan's sample.
- `docs/plan/rdy-plan.md`, "Positioning" says the incumbent preflight tool is "Kubernetes only". It also has host collectors and preflights. The evidence section's claim that its host collectors cannot run on remote nodes is also not an rdy advantage in M1, because rdy also runs on the machine where you start it. Fix: change to "Kubernetes-first" and keep any multi-node claim out of public copy until rdy can run against remote hosts.
- `docs/plan/rdy-plan.md`, "Metrics that matter" and "Conversion flow" step 4 ("see which prospects clicked through"): sits badly next to "nothing leaves the machine" and the no-telemetry promise. Fix: the report link carries only the public product name, and clicks are counted by Plausible on getrdy.io, never by the CLI. State this on the trust page. 07 section 8 and D.4 build the footer link that way.
- `docs/plan/rdy-plan.md`, "Milestones": M3 scope includes the public launch but the M3 exit test is "First 10 paying vendors", which can only be measured after launch. Fix: say the launch happens when M3 scope is done and the exit test is measured over the following eight weeks. Also state that the 12-month star and install targets start on launch day.
- `docs/plan/rdy-plan.md`, "Home page copy outline": "7x faster installs with preflight checks" is a 2022 study by the incumbent preflight vendor about its own preflight checks. Fix: in any rdy copy, give the source and the year in the same sentence, and do not use it in the HN post.
- `CLAUDE.md`, "Commands": `cargo run -p rdy-cli -- run examples/specs/acme-platform.yaml --json` is wrong in two ways. The package is named `rdy` (the directory is `crates/rdy-cli`), so it is `-p rdy`. And the example is unsigned, so it needs `--allow-unsigned`. Fix: `cargo run -p rdy -- run examples/specs/acme-platform.yaml --allow-unsigned --json`.
- `CLAUDE.md`, "Engineering standards" and "Repo layout": CI has five native legs, not four (Linux x86_64 and aarch64 musl, macOS arm64 and x86_64, Windows x86_64), and `rdy-cli` lists `spec (init|sign|lint)` while 07 adds `spec keygen` and the `trust` group in M1 and puts `spec init` and `self-update` in M3. CONTRIBUTING.md now says five legs. Fix CLAUDE.md to match.
- The "Skipped required checks" proposal in the first revision of this file is settled: `01-spec-format.md` section 5.3 and ADR 0008 decision 3 say a required check that did not run is NOT READY. No ADR change is pending from devrel.

## Decisions needing an ADR

- **How the example specs are signed.** Nothing in the plan says how a first-time user runs a spec. Options: (a) ship examples unsigned and show the refusal and then `--allow-unsigned` in the README (consistent with ADR 0002, which exits 64 on an unsigned spec); (b) sign the examples with a published demo key and ship its public key in the binary or docs; (c) a `rdy demo` command that bundles its own spec. Chosen for now: (a). It is the most conservative: it needs no demo key in the trust root, and it makes the first thing a new user sees the signing boundary. Cost: a first-run flag that teaches people to type `--allow-unsigned`. The cost is limited by 01 section 4.7: the flag allows only a spec with no signature, no error or hint names it, and every run prints the banner twice and marks the reports. Revisit with security-reviewer and cli-ux.
- **Skipped required checks.** Settled, not open. See the last item under "Plan corrections found".
- **Contributor terms.** Options: (a) DCO sign-off (chosen in CONTRIBUTING.md); (b) a CLA, which lets the company relicense; (c) nothing but Apache-2.0 inbound equals outbound. DCO is light and does not give the company extra rights. If the company ever needs to relicense, a CLA now would be easier than later. Chosen: (a), as the lowest friction for contributors.
- **Public from M1 or private until launch.** Options: (a) public repo and public signed releases from M1, no promotion; (b) private until launch. Design partners need to download the binary, and their security reviewers need to read the code, so (b) breaks the install flow. Chosen: (a). It means stars and early readers may arrive before launch. That is acceptable.
- **The free-spec offer in the PreSales Collective post.** The plan sells spec-authoring at $5k for the first ten customers. The post offers a free first draft to anyone who sends a prerequisites page. Options: (a) offer it, as lead generation; (b) leave it out until the paid offer is decided. Chosen: (b) is more conservative, so the draft copy marks the offer as optional and the founder decides before week -1.

## Tickets implied

Founder decision of 2026-10-28: M1 is extended, not cut, so every M1 ticket stays. `core: yes` marks the six-week minimum, and it covers devrel's own three deliverables only: the README, the `acme-quickstart` example and CONTRIBUTING. Everything else is `core: no` here. A core ticket still depends on tickets other slices own (the goldens, the renderer, signing and the install script). Those carry their owners' core marks in 02, 06, 07 and 08, and 11-backlog must treat the dependencies of a core ticket as core. If the founder trims, the cut order for this slice is: cast, claims audit table, issue forms, repo hygiene, then the other four example specs.

M1 total for this slice: 32h in 19 tickets. Core: 5h (`core: yes`). The ticket "rdy run --dry-run (stretch)" is gone (it is SEC-40, M2). The old example-lint ticket is split in two so the quickstart spec is core on its own. Dependency titles for tickets owned by other agents must be reconciled in `docs/plan/11-backlog.md`.

- [M1] Review and lint acme-quickstart.yaml | owner: devrel | est: 1h | depends on: Spec parser and JSON schema; rdy spec lint with errors, warnings and did-you-mean | exit test: `rdy spec lint examples/specs/acme-quickstart.yaml` exits 0, every block and warn check has a `fix`, and the file runs on Linux with only M1 checks. | core: yes
- [M1] Review and lint the other four example specs | owner: devrel | est: 1h | depends on: Review and lint acme-quickstart.yaml | exit test: `acme-platform.yaml` lints with exit 1 and exactly two `not_in_build` warnings, the other three exit 0 or 1 with warnings only, every block and warn check has a `fix`, and `acme-inference-gpu.yaml` no longer names `gpu.device_plugin`. | core: no
- [M1] CI job: lint every example spec | owner: qa-engineer | est: 1h | depends on: rdy spec lint with errors, warnings and did-you-mean; Review and lint the other four example specs | exit test: a PR that breaks an example spec fails CI with the file name in the error (lint exit 2 or 64 fails; exit 0 and 1 pass). | core: no
- [M1] Fixture lab for golden transcripts (test proxy, fake kube API) | owner: qa-engineer | est: 4h | depends on: Host checks and HTML report; Network checks; Kubernetes checks | exit test: a script starts a refusing proxy and a fake kube API, and `rdy run` against them gives stable output twice in a row. | core: no
- [M1] Golden transcripts for acme-quickstart (refusal, NOT READY, READY) | owner: qa-engineer | est: 2h | depends on: Fixture lab for golden transcripts (test proxy, fake kube API); Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict; rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner | exit test: the three README transcripts (the C.5 refusal with exit 64, the unsigned NOT READY run with exit 2, the unsigned READY run with exit 0) reproduce byte for byte from fixtures, banner, header, bucket order, summary line and report block included. | core: no
- [M1] Golden transcript for a skipped required check (acme-platform) | owner: qa-engineer | est: 1h | depends on: Fixture lab for golden transcripts (test proxy, fake kube API); Human renderer for run: header, bucket-sorted checks with fix lines, summary, report block and verdict | exit test: `rdy run acme-platform.yaml --allow-unsigned` on a fixture with no kubeconfig ends `NOT READY: 3 required checks were not run` with exit 2, and the summary line reads `3 required checks not run, 1 optional check not run`. | core: no
- [M1] Review CONTRIBUTING.md on a fresh clone | owner: devrel | est: 1h | depends on: Workspace and CI | exit test: every command in the "Build and test" block of CONTRIBUTING.md runs green on a clean checkout, and `cargo run -p rdy -- run examples/specs/acme-quickstart.yaml --allow-unsigned --out-dir /tmp` prints the banner and exits as the file says. | core: yes
- [M1] DCO sign-off check in CI | owner: release-engineer | est: 1h | depends on: Workspace and CI | exit test: a PR with an unsigned commit fails the check and one with `Signed-off-by` passes. | core: no
- [M1] Issue forms and config (bug report, check request, security contact link) | owner: devrel | est: 2h | depends on: none | exit test: the New Issue page on a test fork shows the two forms and the private security link, and blank issues are off. | core: no
- [M1] PR template and labels | owner: devrel | est: 1h | depends on: none | exit test: a test PR shows the checklist from CLAUDE.md and the labels from section 6 exist. | core: no
- [M1] CODE_OF_CONDUCT.md and link SECURITY.md | owner: devrel | est: 1h | depends on: SECURITY.md (security-reviewer) | exit test: both files exist and the repo Security tab shows the policy and private reporting. | core: no
- [M1] Repo hygiene: topics, social preview, Discussions, private vulnerability reporting | owner: devrel | est: 1h | depends on: none | exit test: all four settings are on in the repo and a screenshot of the repo page is in the PR. | core: no
- [M1] README docs-test harness | owner: qa-engineer | est: 3h | depends on: Fixture lab for golden transcripts (test proxy, fake kube API); install.sh CI tests | exit test: a CI job extracts every fenced command marked testable from README.md, runs it against the build and fails on a non-matching exit code or output. | core: no
- [M1] README draft from section 1 | owner: devrel | est: 3h | depends on: Review and lint acme-quickstart.yaml; Golden transcripts for acme-quickstart (refusal, NOT READY, READY); Golden transcript for a skipped required check (acme-platform); rdy verify command and refuse-unsigned behaviour with --allow-unsigned banner; install.sh signature check, fail closed, with tamper tests | exit test: README.md exists, its install block and manual path equal the text in `06-release-and-distribution.md`, all testable commands pass the docs-test harness, every transcript is pasted from a golden file, and no command line contains `--timeout`, `--dry-run`, `--plan` or `self-update`. | core: yes
- [M1] Sync README and series samples with 07-cli-ux | owner: devrel | est: 1h | depends on: README draft from section 1; 07-cli-ux.md | exit test: a diff of every transcript in README.md and in this document against the 07 samples and the goldens shows no difference in bucket order, fix lines, summary grammar, last line, exit code or banner text, without a note. | core: no
- [M1] Record the README terminal cast | owner: devrel | est: 2h | depends on: README draft from section 1 | exit test: an asciinema cast of the NOT READY then READY runs, from the release build, is linked from the README. | core: no
- [M1] Time the quickstart with two design-partner SEs | owner: devrel | est: 2h | depends on: README draft from section 1; Signing and rdy verify | exit test: both reach a report in under five minutes and every stumble is a filed issue. | core: no
- [M1] Alpha announcement to design partners | owner: devrel | est: 2h | depends on: Time the quickstart with two design-partner SEs | exit test: a short email with the install command, the quickstart spec, what is rough and how to report a blocker is sent to every design partner. | core: no
- [M1] Public claims audit table in docs | owner: devrel | est: 2h | depends on: README draft from section 1 | exit test: each claim in the README security table links to a test or a file, and any without one is removed or ticketed. | core: no
- [M2] README update for bundle, redaction and `--dry-run` | owner: devrel | est: 2h | depends on: Redacted bundle command; SEC-40 `rdy run --dry-run` preview | exit test: the README shows `rdy bundle` and `rdy run --dry-run` output pasted from real runs, the Security table has the redaction test, and the `[M2]` marks are gone.
- [M2] lobste.rs account and weekly comment habit | owner: devrel | est: 6h | depends on: none | exit test: an account exists with an invite and at least ten useful comments on other people's posts before week -3, spread over the weeks.
- [M2] First case study draft from a design-partner run | owner: devrel | est: 4h | depends on: Design partner POC runs | exit test: one written, approved, anonymised case study exists.
- [M3] Launch assets final (HN post, first comment, Reddit and lobste.rs posts, FAQ) | owner: devrel | est: 8h | depends on: Release candidate | exit test: every sentence is checked against the release candidate, every transcript equals a golden file, every founder placeholder is filled by the founder or deleted, and the claims table has no gaps.
- [M3] Series posts 1 to 5 written, recorded and scheduled | owner: devrel | est: 12h | depends on: Release candidate | exit test: five posts exist with terminal output pasted from the release candidate in 07's format and are scheduled.
- [M3] Partner outreach (five emails, reply tracker) | owner: devrel | est: 5h | depends on: none | exit test: emails sent in week -3 to each category, reply status tracked, nothing announced without written approval.
- [M3] PreSales Collective post and roundtable booked | owner: devrel | est: 5h | depends on: none | exit test: the community team approved the post and the roundtable has a date and a listing.
- [M3] Ten good-first-issue and check-request issues | owner: devrel | est: 3h | depends on: M2 check catalog | exit test: ten issues exist, each with an exit test and a pointer to the code.
- [M3] Metrics script and weekly routine | owner: devrel | est: 3h | depends on: none | exit test: `scripts/metrics.sh` writes one CSV row with stars, release downloads and crates.io downloads.
- [M3] Launch-week runbook and response board | owner: devrel | est: 3h | depends on: Launch assets final | exit test: the day-by-day table is on a calendar, and the `launch-fixes` board exists with the playbook linked.
- [M3] Three-stranger quickstart test | owner: devrel | est: 4h | depends on: Release candidate | exit test: median time to a report is under five minutes and all stumbles are fixed.
- [M4] GPU check family stand-alone post and example spec update | owner: devrel | est: 4h | depends on: GPU checks | exit test: `acme-inference-gpu.yaml` runs without skips on a GPU fixture and the post uses real output.
- [M5] Embed SDK developer guide and example | owner: devrel | est: 8h | depends on: Embed SDK | exit test: a stranger builds the example installer integration from the guide alone.
