# DevRel and launch plan

Owner: devrel. Date: 2026-10-27. Status: planning pass, not yet reviewed.

This document covers everything the open-source community sees: the README, the example specs, the contribution flow, the public launch at the end of M3, the five-day content series, the first-week response playbook, and how we measure adoption without tracking anyone.

Three rules run through all of it.

1. Lead with the problem. Installs fail because the environment isn't ready, not because the product is broken.
2. Show the terminal. Every sample is pasted from a real run of the release candidate. Nothing is typed by hand.
3. Every public claim has a test behind it. If we cannot point at the test, we do not make the claim.

Terminal samples below are drafts. The output format belongs to cli-ux (`docs/plan/07-cli-ux.md`). Re-sync every sample with that document when the README ticket starts.

## 1. README plan

### Outline

| # | Section | Job | Length |
| --- | --- | --- | --- |
| 1 | Title, tagline, badges | Say what it is in one line | 5 lines |
| 2 | The problem | Name the pain in three sentences | 5 lines |
| 3 | What it looks like | Terminal transcript: NOT READY, then READY | 50 lines |
| 4 | Quickstart | Zero to a real report in under five minutes | 40 lines |
| 5 | How it works | Spec, checks, report, exit codes | 20 lines |
| 6 | Security and trust | Each claim and how to verify it | 15 lines |
| 7 | Check families and status | What ships now, what is next | 12 lines |
| 8 | Write your own spec | Pointer to docs and to `examples/specs/` | 8 lines |
| 9 | Rdy and the Kubernetes-only preflight tool | Honest comparison | 10 lines |
| 10 | Project status | Alpha warning, roadmap, license | 8 lines |
| 11 | Contributing, security, license | Links | 5 lines |

Rules for the README:

- The first screen has the problem, the transcript and the install command. Nothing about pricing or the portal above the fold.
- The portal gets one sentence in section 10. It is not needed to use the tool.
- No badges beyond CI, release and license. Three is plenty.
- The five-minute path is timed on a clean VM by someone who has never seen rdy. The ticket does not close until that is done.
- Every command in the README is run in CI against the release build (a docs test). A README that lies is worse than none.

### Draft copy

The block below is the README text. It is written for the M1 alpha. Lines marked `[M2]`, `[M3]` or `[M4]` change when that milestone ships.

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

This run was recorded on a lab VM. Your output will differ.

```console
$ rdy run acme-platform.yaml --allow-unsigned
rdy 0.1.0
spec    acme-platform >=4.2   UNSIGNED (allowed by --allow-unsigned)
target  acme-vm-03   linux x86_64   8 cpu   16.0 GiB

  PASS   host.cpu            8 cores (need 8)
  BLOCK  host.memory         16.0 GiB found, 32 GiB needed
  PASS   host.disk           212 GiB free on /var/lib (need 100 GiB)
  BLOCK  net.egress          registry.acme.example:443 refused by proxy
                             http://proxy.acme.example:3128 (HTTP 403)
                             license.acme.example:443 ok via proxy
  PASS   k8s.version         v1.29.4 (need 1.28 or newer)
  WARN   k8s.storageclass    no default class supports ReadWriteOnce
  SKIP   gpu.cuda            not available in this build
  SKIP   aws.iam             not available in this build

2 blocks, 1 warning, 4 passed, 2 skipped

Fix these first:
  1. host.memory       Add RAM or choose a larger node class.
  2. net.egress        Ask your network team to allow these endpoints
                       through the proxy.
  3. k8s.storageclass  Mark a storage class that supports ReadWriteOnce
                       as the default.

Report written to ./rdy-report.html and ./rdy-report.json

NOT READY
$ echo $?
2
```

The team resizes the VM, opens the proxy rule and sets a default storage class.
Then they run it again.

```console
$ rdy run acme-platform.yaml --allow-unsigned
rdy 0.1.0
spec    acme-platform >=4.2   UNSIGNED (allowed by --allow-unsigned)
target  acme-vm-03   linux x86_64   16 cpu   64.0 GiB

  PASS   host.cpu            16 cores (need 8)
  PASS   host.memory         64.0 GiB found, 32 GiB needed
  PASS   host.disk           212 GiB free on /var/lib (need 100 GiB)
  PASS   net.egress          2 endpoints reachable via proxy
  PASS   k8s.version         v1.29.4 (need 1.28 or newer)
  PASS   k8s.storageclass    local-path (default) supports ReadWriteOnce
  SKIP   gpu.cuda            not available in this build
  SKIP   aws.iam             not available in this build

6 passed, 2 skipped

Report written to ./rdy-report.html and ./rdy-report.json

READY
$ echo $?
0
```

Exit codes: `0` ready, `1` warnings only, `2` blockers, `64` usage error,
`70` internal error. Skipped checks are listed, never counted as passed.

## Quickstart

You need a Linux or macOS machine and five minutes. No account. No sudo.

**1. Install.**

```sh
curl -sSf https://getrdy.io/install | sh
rdy version
```

The script puts one binary in `~/.local/bin`, checks its SHA-256 and its
Sigstore signature, and does nothing else. Read it first if you like:
`curl -sSf https://getrdy.io/install | less`. Windows: download the zip from
the [releases page](https://github.com/getrdy-io/rdy/releases). `[M3]`

Rather not pipe to a shell? Download, verify and unpack by hand:

```sh
# Pick the file for your platform from the latest release.
curl -sSfLO https://github.com/getrdy-io/rdy/releases/download/v0.1.0/rdy-x86_64-unknown-linux-musl.tar.gz
curl -sSfLO https://github.com/getrdy-io/rdy/releases/download/v0.1.0/rdy-x86_64-unknown-linux-musl.tar.gz.sigstore.json
cosign verify-blob \
  --bundle rdy-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/getrdy-io/rdy/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  rdy-x86_64-unknown-linux-musl.tar.gz
tar xzf rdy-x86_64-unknown-linux-musl.tar.gz && ./rdy version
```

**2. Get an example spec.**

```sh
curl -sSfO https://raw.githubusercontent.com/getrdy-io/rdy/v0.1.0/examples/specs/acme-platform.yaml
```

It describes a made-up product called Acme Platform. It is not signed, so rdy
will refuse it unless you pass `--allow-unsigned`. That refusal is the point.
Real specs are signed by the vendor, and rdy checks the signature.

**3. Run it.**

```sh
rdy run acme-platform.yaml --allow-unsigned
```

It takes a few seconds. rdy runs what it can, and tells you what it could not
run and why. For example, `k8s.*` checks are skipped if you have no kubeconfig.
It never asks for sudo.

You will probably see at least one BLOCK. The example talks to
`registry.acme.example`, which does not exist. That is expected.

**4. Read the report.**

```sh
open rdy-report.html        # macOS
xdg-open rdy-report.html    # Linux
```

Each check shows what rdy measured, what the spec asked for, and the fix. The
page is one file with no external requests. You can email it or print it.
`rdy-report.json` has the same data for scripts.

**5. Make it green.**

Copy the spec and change it to match your machine.

```sh
cp acme-platform.yaml my-spec.yaml
$EDITOR my-spec.yaml   # lower host.memory min, point net.egress at hosts you can reach
rdy run my-spec.yaml --allow-unsigned
```

In a real install you fix the machine, not the spec. Here we edit the spec so
you can see a green run on whatever you are holding.

## How it works

- A **spec** is a YAML file of requirements. `apiVersion: rdy/v1`, `kind:
  Readiness`, a list of checks with `severity: block` or `warn`, and a `fix`
  message for each.
- A **check** measures one thing: memory, an egress path, a storage class. Each
  check declares what it needs (root, a kube context, cloud credentials). rdy
  runs what it can and reports what it could not.
- A **report** is HTML and JSON. The result is `READY`, `READY with warnings`
  or `NOT READY`.
- A **signature** from the vendor's ed25519 key covers the spec. `rdy verify`
  checks it. rdy refuses unsigned or tampered specs unless you say
  `--allow-unsigned`, and then says so loudly.

## Security and trust

rdy runs inside your environment, often as root. You should not take our word
for what it does. Here is how to check.

| Claim | How to verify |
| --- | --- |
| Nothing leaves the machine by default | Run it with the network off: `unshare -rn rdy run spec.yaml` (Linux). Read `crates/rdy-cli/src/upload.rs`, the only code that sends anything. |
| It never asks for sudo | It does not call sudo. Skipped checks say which privilege they needed. |
| Releases are signed | `cosign verify-blob`, as above. SBOM attached to every release. |
| One static binary, no OpenSSL | `ldd rdy` says "not a dynamic executable". rustls only. |
| Specs cannot run arbitrary commands | At this stage specs only select built-in checks. Custom script checks do not exist yet. |
| No telemetry | There is none. The only network traffic is what a check exists to make, and `rdy self-update` when you run it. |

Found a problem? See [SECURITY.md](SECURITY.md).

## Check families

| Family | Status |
| --- | --- |
| Host: CPU, memory, disk, kernel, cgroups, time sync, ports, SELinux | Alpha |
| Network: egress through a proxy, DNS, TLS interception, MTU | Alpha |
| Kubernetes: version, storage classes, RBAC, admission, node resources | Alpha |
| Redacted diagnostics bundle `[M2]` | Next |
| AWS account: IAM dry run, quotas, regions `[M3]` | Planned |
| GPU: driver, CUDA, VRAM, device plugin `[M4]` | Planned |

Missing a check that would have saved you an install? Open a
[check request](https://github.com/getrdy-io/rdy/issues/new/choose).

## Write your own spec

Start from a file in [`examples/specs/`](examples/specs/): a full platform,
Kubernetes only, an air-gapped host, and a GPU workload. Run `rdy spec lint
your-spec.yaml` to catch mistakes. The reference is at
[docs.getrdy.io](https://docs.getrdy.io).

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
does not need it and never will.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Bugs and check requests are welcome.
````

Notes for the README ticket:

- The `unshare -rn` line and the `ldd` line must be tested on the release build before they ship. Replace them if they do not hold.
- The `cosign` identity regexp and artifact names must match `docs/plan/06-release-and-distribution.md` exactly.
- `rdy spec lint` is on the CLAUDE.md command list. If it is not in M1, delete that sentence.
- `~/.local/bin` and "does nothing else" must match what `install.sh` actually does.
- The "Both tools run on the machine where you start them" line is deliberate. See the corrections section: the plan's multi-node claim is not an rdy advantage in M1.

## 2. `examples/specs/` plan

All specs are synthetic. Every hostname ends in `.example` (RFC 2606). The product is a made-up company called Acme. No real customer or vendor appears anywhere.

| File | Product | Purpose | Families used | Runs fully in |
| --- | --- | --- | --- | --- |
| `acme-platform.yaml` | acme-platform | The canonical spec from the plan. Used by the README, the docs, the integration tests and `cargo run`. Mixed families, so it shows skip behaviour for families not built yet. | host, net, k8s, gpu, aws | M1 (host, net, k8s), M3 (aws), M4 (gpu) |
| `acme-k8s-only.yaml` | acme-operator | A Helm chart plus operator vendor. Run from a laptop with a kubeconfig. Shows RBAC for the install identity, storage classes, admission. Good first spec for the kind-cluster demo. | k8s, net | M1 |
| `acme-airgap-host.yaml` | acme-edge | One VM, no internet, no Kubernetes. Only endpoint is an internal mirror. Shows the offline flow: run, carry the report out by hand. Exercises most host checks. | host, net | M1 |
| `acme-inference-gpu.yaml` | acme-inference | GPU inference on Kubernetes. Parses now, runs fully in M4. Proves the spec format already has room for the GPU family, and gives gpu-expert a target. | gpu, k8s, net | M4 |

Rules:

- Files are checked in unsigned. They are never real design-partner prerequisites.
- Every file starts with a comment saying it is synthetic and what it is for.
- A CI job runs `rdy spec lint` on every file in `examples/specs/`. A schema change that breaks an example fails the build. The example gets fixed in the same PR.
- Each file has an integration test that runs it against a fixture environment and compares the output to a golden report (qa-engineer owns the fixtures).
- Check ids and parameter names in these files are provisional until `01-spec-format.md` and `03-check-catalog.md` land. Where they differ, the schema wins and the examples change. Provisional ids: `host.cpu`, `host.disk`, `host.kernel`, `host.cgroups`, `host.time_sync`, `host.ports`, `host.selinux`, `k8s.version`, `k8s.node_resources`, `k8s.rbac`, `k8s.admission`, `gpu.driver`, `gpu.vram`, `gpu.device_plugin`. Ids from the plan (`host.memory`, `net.egress`, `k8s.storageclass`, `gpu.cuda`, `aws.iam`) are kept as written.

`acme-platform.yaml` is written to `/home/user/rdy/examples/specs/acme-platform.yaml` with this planning pass. It keeps the plan's five checks and adds `host.cpu`, `host.disk` and `k8s.version` so the README demo has passes between the failures. The other three files are written there too.

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
  - id: k8s.storageclass
    needs: ["ReadWriteOnce"]
    severity: warn
    fix: "Mark a storage class that supports ReadWriteOnce as the default."
  - id: gpu.cuda
    min: "12.4"
    severity: block
  - id: aws.iam
    simulate: ["eks:DescribeCluster", "ec2:CreateSecurityGroup"]
    severity: block
bundle:
  collect: ["journal:7d", "k8s:events", "file:/etc/acme/*.yaml"]
  redact: ["aws_keys", "bearer_tokens", "emails"]
```

The file on disk also carries comments that mark `gpu.cuda` and `aws.iam` as "later".

**Behaviour the examples depend on.** The canonical spec holds checks that no M1 binary can run. The engine must parse them and report `SKIP` with the reason "not available in this build". It must never fail the parse and never report a pass. See "Decisions needing an ADR" for how skipped blockers affect the verdict.

## 3. Public launch checklist (end of M3)

The launch is an announcement, not a first exposure. The repo and releases are public from M1 so design partners and their security reviewers can read the code and download signed binaries. We just do not promote it. Stars and attention arrive at launch.

### Gates: do not post until all are true

- [ ] M3 scope is done: AWS account checks, Stripe, docs, Team tier on sale. The portal is not needed to try the CLI.
- [ ] Three people who have never seen rdy ran the README quickstart on a clean VM. Median time under five minutes. Fix every stumble first.
- [ ] Every sentence in the posts is true of the release candidate. Walk the claims table at the end of section 7.
- [ ] Release is signed, `cosign verify-blob` passes from a clean machine, SBOM is attached, `cargo deny check` and `cargo audit` are clean.
- [ ] `install.sh` tested on Ubuntu LTS, Debian, RHEL-family, Alpine, macOS arm64 and macOS x86_64. Windows zip tested by hand.
- [ ] Repo hygiene: `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and PR templates, `CHANGELOG.md`, topics set, social preview image, Discussions on, private vulnerability reporting on.
- [ ] Ten issues labelled `good first issue` or `check request`, each with a clear exit test.
- [ ] docs.getrdy.io has install, first run, spec reference and one page per shipped check family.
- [ ] Asciinema cast or short screen recording of the two-block run, recorded from the release candidate.
- [ ] getrdy.io and the install endpoint are static and cached (Cloudflare). They survive an HN front-page spike. Confirm GitHub release downloads are not rate limited for a spike (they are served from a CDN).
- [ ] Plausible goals set: docs first-run page, install page, waitlist form.
- [ ] Founder calendar cleared. The founder is at the keyboard for the first eight hours after each post. Book vacation days for launch week.
- [ ] lobste.rs account exists with an invite and some history (see timeline, week -3).
- [ ] Waitlist email drafted. Launch FAQ drafted (section 5).
- [ ] The threat model summary (`docs/plan/05-threat-model.md`) is published or linked from docs. HN readers will ask.

### Show HN

Rules we follow: submit the GitHub repo URL, no signup, nothing to buy, no asking anyone to upvote, post on a weekday morning US Eastern time, stay on the thread. HN takes either a URL or text, not both. We submit the URL, so the text below goes in as the author's first comment, posted within a minute. The second comment, further down, is posted after it only if the thread asks for the background.

**Title** (63 characters):

```text
Show HN: Rdy, check a customer's environment before install day
```

**Body** (posted as the first comment; it leads with the problem):

```text
I'm a sales engineer. At three companies I have written the same bash
script: the one a customer runs before a POC or an on-prem install, to find
out whether their machines can run the product. Enough RAM. DNS. Egress
through the corporate proxy. The right Kubernetes version. A storage class
that can do ReadWriteOnce.

Most failed installs I have seen were not product bugs. The environment was
not ready, and we found out on install day.

rdy is that script, done properly. One static Rust binary. The vendor writes
a YAML spec of what the product needs and signs it. The customer runs:

    $ rdy run acme-platform.yaml
      PASS   host.cpu            8 cores (need 8)
      BLOCK  host.memory         16.0 GiB found, 32 GiB needed
      BLOCK  net.egress          registry.acme.example:443 refused by proxy
                                 http://proxy.acme.example:3128 (HTTP 403)
      WARN   k8s.storageclass    no default class supports ReadWriteOnce
    2 blocks, 1 warning, 4 passed
    NOT READY

Each result has a fix. The run writes an HTML report and a JSON report. Exit
codes are 0 ready, 1 warnings, 2 blockers, so CI can gate on it.

What it does and does not do:

- Runs what it can without root and tells you what it could not check. It
  never asks for sudo.
- Nothing leaves the machine. There is an upload flag and it is off by
  default. The upload code and the report renderer are in the repo so you
  can read exactly what would leave.
- Specs are signed with ed25519. Unsigned or tampered specs are refused
  unless you pass --allow-unsigned.
- Static musl binary, rustls, no OpenSSL, no runtime. It works offline.
- Specs only select built-in checks. They cannot run commands.

Where it is rough: it is alpha. Host, network, Kubernetes and AWS account
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

Check before posting: the sample output in the body is pasted from the release candidate, trimmed. Remove any sentence that is not true on that build.

**Second comment** (only if people ask why or how; otherwise hold it for replies):

```text
Author here. Some context that did not fit in the post.

Why a new tool: the checks I kept rewriting were never about Kubernetes
alone. They were a VM with an old kernel, a proxy doing TLS interception,
a cluster with the wrong default storage class. I wanted one thing that
covers all of it.

How to verify what it does: releases are signed with cosign (command is in
the README), the SBOM is attached, and the threat model is in docs/. The
network-off test is in CI.

What I am least sure about: the spec format. If you have written
preflights for your own product, please look at examples/specs/ and tell
me what you cannot express.

I will be here all day.
```

### r/devops

Lead with the question. Disclose that you built the tool. Check the subreddit's current self-promotion rules the week before and follow them. If promotion is limited to a weekly thread, post there.

**Title:** `How do you check a customer's environment before an on-prem or BYOC install?`

```text
I do pre-sales engineering for a self-hosted product. Our worst installs
fail for boring reasons: a proxy that blocks the registry, a node with half
the RAM we asked for, a storage class that cannot do RWO. We used to send a
PDF checklist, then a bash script. Both rot.

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

- Workspace of small crates: rdy-spec (serde + schemars, ed25519-dalek for
  signed specs), rdy-engine (check trait, scheduler, result model, askama
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
default storage class that supports RWO, a pod security policy rejects the
workload, the nodes are smaller than the docs assumed.

rdy is an Apache-2.0 CLI that runs these checks from a kubeconfig before
install day and prints a fix for each failure. It is read-only. RBAC is
checked with SelfSubjectAccessReview, so it asks the API server what you
can do instead of guessing.

Example (kind cluster, acme-k8s-only.yaml in the repo):

    [paste real output here]

Honest limits: it runs from one kube context at a time, it is alpha, and it
is not a replacement for the established Kubernetes-only preflight tool if
you already use it with its vendor's platform. I would like to know which admission and storage failures you see most, so I
can add checks for them.

https://github.com/getrdy-io/rdy
```

Verify before posting that RBAC really uses `SelfSubjectAccessReview` and that the checks are read-only. If check-author chose something else, say what they chose.

### lobste.rs

Lobsters wants authors to be honest about self-promotion and does not like launch hype. Submit the repo link once, with the tags `rust`, `devops` and `show` (use whichever tags the site currently offers). Tick "I am the author". Needs an account with an invite, so start in week -3. Comment on other people's posts for a while first. Submit on a different day from HN.

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

Last year a POC of mine lost nine days. Product worked. The customer's
network did not let the cluster pull from our registry, and nobody knew
until kickoff day. It was the third time that quarter.

I ended up writing a script that the customer runs before kickoff. Is the
machine big enough, can it reach our endpoints through their proxy, is the
cluster the right version. Then I turned it into a small open-source tool
called rdy so I would stop rewriting it at each job.

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

The last offer is a founder decision, see "Decisions needing an ADR".

**Roundtable pitch** (to the community team):

```text
Title: Why POCs stall on the environment, and how to catch it before kickoff

Format: 45 minutes, cameras optional, not recorded unless the room agrees.
Max 25 people.

Plan:
  10 min  Three anonymous POC failure stories from the host, mapped to the
          check that would have caught each.
  20 min  Open floor. Everyone brings one install failure. We write down the
          check as we go, in plain English: what to measure, what is good,
          what to tell the customer.
  10 min  Live: turn those checks into a readiness spec for a made-up
          product. Show the customer's view of a run.
   5 min  What to try on Monday. No pitch, no signup.

Leave with: a one-page list of your top ten environment checks, and a spec
file if you want one.

About me: sales engineer, DevOps background, built an open-source tool for
this. I will say so once at the start.
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
| **Tue (launch)** | 08:30 US Eastern: post Show HN. Post the author comment. Stay on the thread, reply to every comment. 10:00: post series day 2 (network). After the HN post is live: send the waitlist email. Fix real bugs fast. Do not post anywhere else today. |
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

All terminal output below is a draft. Replace each with real output from the release candidate. The snippets use `.example` names.

### Day 1 (Mon): Host

**Angle:** "Your 32 GiB node has 31.4 GiB." Hosts fail quietly: old kernel, wrong cgroups, a port already taken, SELinux enforcing, a clock off by a minute.

**Demo:** `rdy run examples/specs/acme-airgap-host.yaml --allow-unsigned`

```console
  BLOCK  host.kernel      4.18.0 found, 5.10 needed
  WARN   host.cgroups     cgroup v1 in use, v2 wanted
  BLOCK  host.ports       8443 in use by pid 1214 (nginx)
  WARN   host.selinux     enforcing, spec allows permissive or disabled
  WARN   host.time_sync   clock skew 94s, limit 5s
```

**CTA:** Run it on the oldest server you have. Tell us which host check we are missing: open a check request.

### Day 2 (Tue): Network

**Angle:** "Works on my laptop. The proxy has other ideas." Proxy allowlists, TLS interception and DNS cause most failed POCs.

**Demo:** the egress and TLS checks behind a proxy.

```console
  BLOCK  net.egress       registry.acme.example:443 refused by proxy (HTTP 403)
  WARN   net.tls          certificate issuer is "Acme Corp Inspection CA",
                          not the public CA. TLS interception likely.
  PASS   net.dns          registry.acme.example resolves to 10.20.0.14
```

**CTA:** Run the network checks from a machine behind your own proxy. Send us the failure you saw that we did not catch.

### Day 3 (Wed): Kubernetes

**Angle:** "Three things stop `helm install`: RBAC, storage classes, admission."

**Demo:** reproducible by anyone with a kind cluster.

```console
$ kind create cluster
$ rdy run examples/specs/acme-k8s-only.yaml --allow-unsigned
  PASS   k8s.version        v1.30.0
  BLOCK  k8s.node_resources 1 node found, 3 needed
  WARN   k8s.storageclass   "standard" supports ReadWriteOnce only
  PASS   k8s.rbac           3 of 3 verbs allowed
  PASS   k8s.admission      namespace allows baseline
```

**CTA:** Run it on a cluster you can throw away. Tell us which admission policies bite you most.

### Day 4 (Thu): Cloud account

**Angle:** "Find out the IAM role is missing a permission before step 14 of the install."

**Demo:** the AWS IAM dry run. The policy needed to run the check itself is shown, to make the least-privilege point.

```console
  BLOCK  aws.iam   ec2:CreateSecurityGroup denied for role acme-install
                   eks:DescribeCluster allowed
                   needs: iam:SimulatePrincipalPolicy (read-only)
```

**CTA:** Run it in a sandbox account with a read-only role. Show us your most annoying quota or permission failure.

### Day 5 (Fri): Bundle and redaction

**Angle:** "What leaves the box? Nothing, and then only what you approve." Redaction runs before anything is written to disk.

**Demo:** build a bundle and show the manifest and the redaction summary.

```console
$ rdy bundle examples/specs/acme-platform.yaml --allow-unsigned
  collected   journal:7d, k8s:events, 2 files
  redacted    3 aws_keys, 2 bearer_tokens, 14 emails
  wrote       ./rdy-bundle.tar.zst (1.2 MiB)
  uploaded    nothing. Use --upload to send it, and read the manifest first.
```

**CTA:** Try to break the redactor. If a secret gets through, report it privately under SECURITY.md. We will credit you.

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

| Objection | Honest answer |
| --- | --- |
| "`curl \| sh` is a bad idea." | Agreed that it is a trust leap. The script is short, does one thing, and never needs root: it installs to `~/.local/bin` after checking SHA-256 and the Sigstore signature. If you do not want to pipe it, the README shows the download, `cosign verify-blob` and unpack steps. Packages (Homebrew, winget, apt) come later. |
| "It runs as root in a customer's environment. Why would I trust that?" | It does not need root and does not ask for it. Each check declares the privilege it needs. Without it, the check is skipped and the report says which one and why. The binary is open source, signed, has an SBOM, and we publish a threat model. The only code that can send anything off the machine is the upload client, it is off by default, and it is in the repo. An independent audit comes before we sell to enterprises. |
| "Just use the existing Kubernetes preflight tool." | Maybe you should. If you are on Kubernetes and its vendor's platform, that tool is mature and has far more mileage than rdy. rdy is for a wider mix: one binary for a VM, a cluster and a cloud account, with signed specs and a report a non-engineer can read. Both tools run on the machine where you start them, so that is not a difference today. |
| "Why Rust?" | A static binary with no runtime installs in locked-down and air-gapped boxes. Memory safety matters for something that may run as root in someone else's environment. The check engine will later be built as a library other installers can embed. Go would have met the first goal too. Rust met all three. |
| "What about telemetry?" | None. The binary makes no network call unless a check exists to make it, or you run `self-update`, or you pass the upload flag. We count downloads from GitHub and requests to the install script, nothing else. The network-off test is in CI. |
| "Another YAML DSL." | It is a list of built-in checks with thresholds. No logic, no templating. If you can read a Kubernetes manifest you can read a spec. Tell me what you cannot express and I will look. |
| "Can a malicious spec run commands?" | At this stage no. Specs only select built-in checks and set parameters. Custom script checks are planned later, with a sandbox, and they will need a signature. |
| "Is this AI slop?" | I used an AI coding agent for most of the typing and I review all of it. Judge the repo: tests, golden files, clippy with warnings denied, cargo-deny, a threat model. If you find something sloppy, open an issue. |
| "What does the paid part do? Will the CLI get crippled?" | The paid part is a hosted portal: share links, a results dashboard, history. The CLI, the spec format and the checks stay Apache-2.0. Vendors pay for workflow, not for the right to run a check. |
| "Windows?" | A Windows build exists. It has the fewest checks. Which ones matter most to you? Open a check request. |
| "Who are you? What if you quit?" | One founder, part time, with a day job. That is the risk. It is Apache-2.0, the formats are documented, and anyone can fork it. |

Add every new objection to this table the same day and to the public FAQ the next.

## 6. Contribution guide and issue templates

### `CONTRIBUTING.md`

Written to `/home/user/rdy/CONTRIBUTING.md` with this pass. Contents: before you start (issue first), rules every check must follow, build and test commands, pull request rules, DCO sign-off, AI-assisted change disclosure, spec and result format changes need a design note or ADR, conduct, license. It must be re-verified on a fresh clone once the workspace exists (ticket below).

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
| Release binary downloads | part of 20,000 | GitHub releases | `gh api repos/getrdy-io/rdy/releases --jq '.[].assets[] \| {name, download_count}'`. Count binary archives only. Leave out `.sha256`, `.sigstore.json`, SBOM files. |
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
| Unsigned or tampered specs refused | Integration tests on `rdy run` with a bad signature. [security-reviewer] |
| Nothing uploaded by default | Test that no outbound connection is made without the upload flag. [qa-engineer] |
| Releases are signed with an SBOM | Release workflow, verified from a clean machine. [release-engineer] |
| Redaction runs before write | Golden-file redaction tests. [qa-engineer] |
| Specs cannot run commands | Schema has no field that executes a command. [rust-architect] |

## Plan corrections found

- `docs/plan/rdy-plan.md`, "How a POC flows" step 1: `rdy run acme-platform --token abc123` assumes (a) specs can be run by name, (b) a portal token exists, and (c) `rdy` is already on `PATH` after the install script. None is defined for M1. `--token` is M2 at the earliest. Fix: until M2, the documented command is `rdy run <file.yaml>`. Add name and token forms to the docs only when the portal ships.
- `docs/plan/rdy-plan.md`, "Website plan, Stack": "Install endpoint: `get.<domain>`". The naming section and `CLAUDE.md` say `getrdy.io/install`. Fix: use `https://getrdy.io/install` everywhere and drop `get.<domain>`.
- `docs/plan/rdy-plan.md`, "Check families at launch" lists GPU, data stores and custom script checks as launch families. The milestone table puts cloud in M3 and GPU in M4, and gives data stores and custom checks no milestone. Fix: add a column to the check list saying which milestone each family ships in, give data stores and custom checks a milestone or move them to "later". Launch copy only claims what ships by the end of M3: host, network, Kubernetes, AWS account, bundle and redaction.
- `docs/plan/rdy-plan.md`, example spec: `registry.acme.io` and `license.acme.io` may be real domains. Every machine that runs the example would query them. Fix: use `.example` names (RFC 2606), as `examples/specs/` now does. Update the plan's sample.
- `docs/plan/rdy-plan.md`, "Positioning" says the incumbent preflight tool is "Kubernetes only". It also has host collectors and preflights. The evidence section's claim that its host collectors cannot run on remote nodes is also not an rdy advantage in M1, because rdy also runs on the machine where you start it. Fix: change to "Kubernetes-first" and keep any multi-node claim out of public copy until rdy can run against remote hosts.
- `docs/plan/rdy-plan.md`, "Metrics that matter" and "Conversion flow" step 4 ("see which prospects clicked through"): sits badly next to "nothing leaves the machine" and the no-telemetry promise. Fix: the report link carries only the public product name, and clicks are counted by Plausible on getrdy.io, never by the CLI. State this on the trust page.
- `docs/plan/rdy-plan.md`, "Milestones": M3 scope includes the public launch but the M3 exit test is "First 10 paying vendors", which can only be measured after launch. Fix: say the launch happens when M3 scope is done and the exit test is measured over the following eight weeks. Also state that the 12-month star and install targets start on launch day.
- `docs/plan/rdy-plan.md`, "Home page copy outline": "7x faster installs with preflight checks" is a 2022 study by the incumbent preflight vendor about its own preflight checks. Fix: in any rdy copy, give the source and the year in the same sentence, and do not use it in the HN post.
- `CLAUDE.md`, "Commands": `cargo run -p rdy-cli -- run examples/specs/acme-platform.yaml --json` is wrong in two ways. The package is named `rdy` (the directory is `crates/rdy-cli`), so it is `-p rdy`. And the example is unsigned, so it needs `--allow-unsigned`. Fix: `cargo run -p rdy -- run examples/specs/acme-platform.yaml --allow-unsigned --json`.
- Gap, not an error: security reviewers on HN will ask what rdy will do before they run it. Neither the plan nor `CLAUDE.md` has a way to list each check's commands and privilege needs without running anything. Proposed fix, owned by cli-ux: a dry-run mode (for example `rdy run --dry-run` or `rdy spec lint --show-needs`) that prints per check what it will read or run and what privilege it needs. It backs the "least privilege" claim better than prose does.

## Decisions needing an ADR

- **How the example specs are signed.** Nothing in the plan says how a first-time user runs a spec. Options: (a) ship examples unsigned and use `--allow-unsigned` in the README; (b) sign the examples with a published demo key and ship its public key in the binary or docs; (c) a `rdy demo` command that bundles its own spec. Chosen for now: (a). It is the most conservative: it needs no demo key in the trust root, and it makes the first thing a new user sees the signing boundary. Cost: a first-run flag that teaches people to type `--allow-unsigned`. Revisit with security-reviewer and cli-ux.
- **How skipped checks affect the verdict.** The canonical spec contains `gpu.cuda` and `aws.iam`, which no M1 binary can run. Options: (a) skipped checks are listed but do not change the verdict; (b) a skipped check with `severity: block` means the verdict cannot be plain `READY` (for example `READY with gaps`, exit 1); (c) the parse fails for unknown families. The README transcript uses (a), which is provisional. (b) is the more honest choice for a readiness tool, and the safer one: it never says READY about something it did not check. Under (b) the demo needs a variant spec with only built-in checks, or an extra line in the READY output. Owners: rust-architect and cli-ux decide. The README ticket waits on it.
- **Contributor terms.** Options: (a) DCO sign-off (chosen in CONTRIBUTING.md); (b) a CLA, which lets the company relicense; (c) nothing but Apache-2.0 inbound equals outbound. DCO is light and does not give the company extra rights. If the company ever needs to relicense, a CLA now would be easier than later. Chosen: (a), as the lowest friction for contributors.
- **Public from M1 or private until launch.** Options: (a) public repo and public signed releases from M1, no promotion; (b) private until launch. Design partners need to download the binary, and their security reviewers need to read the code, so (b) breaks the install flow. Chosen: (a). It means stars and early readers may arrive before launch. That is acceptable.
- **The free-spec offer in the PreSales Collective post.** The plan sells spec-authoring at $5k for the first ten customers. The post offers a free first draft to anyone who sends a prerequisites page. Options: (a) offer it, as lead generation; (b) leave it out until the paid offer is decided. Chosen: (b) is more conservative, so the draft copy marks the offer as optional and the founder decides before week -1.

## Tickets implied

M1 tickets cover the pre-launch work that has to exist while the alpha is in design partners' hands. Dependency titles for tickets owned by other agents are placeholders and must be reconciled in `docs/plan/11-backlog.md`.

- [M1] Write example specs (4 files) | owner: devrel | est: 3h | depends on: Spec parser and JSON schema | exit test: all four files in `examples/specs/` parse and pass `rdy spec lint`, and the acme-platform file matches the plan's example shape.
- [M1] CI job: lint every example spec | owner: qa-engineer | est: 1h | depends on: Write example specs (4 files) | exit test: a PR that breaks an example spec fails CI with the file name in the error.
- [M1] Golden report for acme-platform fixture | owner: qa-engineer | est: 3h | depends on: Write example specs (4 files) | exit test: `rdy run` against the synthetic lab fixture reproduces the NOT READY transcript and the READY rerun byte for byte.
- [M1] Review CONTRIBUTING.md on a fresh clone | owner: devrel | est: 1h | depends on: Workspace and CI | exit test: every command in CONTRIBUTING.md runs green on a clean checkout.
- [M1] Issue forms and config (bug report, check request, security contact link) | owner: devrel | est: 2h | depends on: none | exit test: the New Issue page on a test fork shows the two forms and the private security link, and blank issues are off.
- [M1] PR template and labels | owner: devrel | est: 1h | depends on: none | exit test: a test PR shows the checklist from CLAUDE.md and the labels from section 6 exist.
- [M1] CODE_OF_CONDUCT.md and SECURITY.md link check | owner: devrel | est: 1h | depends on: Threat model v1 (security-reviewer) | exit test: both files exist, and the repo Security tab shows the policy and private reporting.
- [M1] README first draft with verified commands | owner: devrel | est: 4h | depends on: Host checks and HTML report; Skipped-check verdict ADR | exit test: every command in the README runs in a docs test against the build, and the transcript is pasted from a real run.
- [M1] Time the quickstart with two design-partner SEs | owner: devrel | est: 2h | depends on: README first draft with verified commands; Signing and rdy verify | exit test: both reach a report in under five minutes and every stumble is a filed issue.
- [M1] Alpha announcement to design partners | owner: devrel | est: 2h | depends on: Time the quickstart with two design-partner SEs | exit test: a short email with the install command, the example spec, what is rough and how to report a blocker is sent to every design partner.
- [M1] Public claims audit table in docs | owner: devrel | est: 2h | depends on: README first draft with verified commands | exit test: each claim in the README security table links to a test or a file, and any without one is removed or ticketed.
- [M2] README update for bundle and redaction | owner: devrel | est: 2h | depends on: Redacted bundle command | exit test: the README shows `rdy bundle` output pasted from a real run and the claims table has the redaction test.
- [M2] lobste.rs invite and account history | owner: devrel | est: 1h | depends on: none | exit test: an account exists with at least ten helpful comments before week -3.
- [M2] First case study draft from a design-partner run | owner: devrel | est: 4h | depends on: Design partner POC runs | exit test: one written, approved, anonymised case study exists.
- [M3] Launch assets final (HN post, first comment, Reddit and lobste.rs posts, FAQ) | owner: devrel | est: 8h | depends on: Release candidate | exit test: every sentence is checked against the release candidate and the claims table has no gaps.
- [M3] Series posts 1 to 5 written, recorded and scheduled | owner: devrel | est: 12h | depends on: Release candidate | exit test: five posts exist with terminal output pasted from the release candidate and are scheduled.
- [M3] Partner outreach (five emails, reply tracker) | owner: devrel | est: 5h | depends on: none | exit test: five emails sent in week -3, reply status tracked, nothing announced without written approval.
- [M3] PreSales Collective post and roundtable booked | owner: devrel | est: 5h | depends on: none | exit test: the community team approved the post and the roundtable has a date and a listing.
- [M3] Ten good-first-issue and check-request issues | owner: devrel | est: 3h | depends on: M2 check catalog | exit test: ten issues exist, each with an exit test and a pointer to the code.
- [M3] Metrics script and weekly routine | owner: devrel | est: 3h | depends on: none | exit test: `scripts/metrics.sh` writes one CSV row with stars, release downloads and crates.io downloads.
- [M3] Launch-week runbook and response board | owner: devrel | est: 3h | depends on: Launch assets final | exit test: the day-by-day table is on a calendar, and the `launch-fixes` board exists with the playbook linked.
- [M3] Three-stranger quickstart test | owner: devrel | est: 4h | depends on: Release candidate | exit test: median time to a report is under five minutes and all stumbles are fixed.
- [M4] GPU check family stand-alone post and example spec update | owner: devrel | est: 4h | depends on: GPU checks | exit test: `acme-inference-gpu.yaml` runs without skips on a GPU fixture and the post uses real output.
- [M5] Embed SDK developer guide and example | owner: devrel | est: 8h | depends on: Embed SDK | exit test: a stranger builds the example installer integration from the guide alone.
