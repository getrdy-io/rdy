# rdy

**Install day should be boring.**

rdy checks a machine, a Kubernetes cluster or a cloud account against a software vendor's written
requirements, before the install. It tells you what is wrong and how to fix it. It ships as one signed
binary with no runtime, and it works offline.

> **Pre-release.** rdy is under active development. `rdy run`, the command that does the main job,
> works on `main` today, with thirteen host checks and two network checks. There is no tagged release
> yet, so the install command below is the shape it will have, and for now you build from source. See
> [Status](#status) for what works and what is coming.

## The problem

Installs fail because the environment isn't ready, not because the product is broken. Not enough RAM.
A proxy that blocks the registry. A storage class that cannot do ReadWriteMany. Somebody finds out on
install day, on a call, with the customer watching.

rdy moves that discovery earlier. The vendor writes down what the product needs, as a short YAML
file called a spec, and signs it. The customer's platform or IT engineer runs one command. They get a
list of what is wrong, with a fix under each problem, and a report to send back. Today the report is JSON,
and HTML is next.

You might be reading this because a vendor sent you a spec and asked you to run it. Or you are a
sales engineer who is tired of finding out about the proxy on install day. Both are the audience.

## Install and first run

Releases are signed. The M1 install path is the `install.sh` file attached to a pinned GitHub release.
It needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.1.3 or newer on your
PATH. Without it, the script stops and installs nothing. It checks the signature of the checksum file
and the sha256 of the archive before it installs anything. It never runs `sudo`. It writes one file,
`rdy`, to `$HOME/.local/bin`, or to the folder in `RDY_INSTALL_DIR`. As root, it refuses unless you
pass `--allow-root`, and then it writes `/usr/local/bin/rdy`, unless `RDY_INSTALL_DIR` is set. On
Windows, download the `.zip` from the release page and check its sha256 by hand.

There is no tagged release yet. When there is one, the command is this, with the version filled in:

```sh skip=placeholder
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -sSfL \
  https://github.com/getrdy-io/rdy/releases/download/v<VERSION>/install.sh | sh
"$HOME/.local/bin/rdy" run <spec-from-your-vendor>.yaml
```

Root shells need `sh -s -- --allow-root` after the pipe, and then run `/usr/local/bin/rdy`, not
`"$HOME/.local/bin/rdy"`. A shorter `getrdy.io/install` address comes later, in M2.

Until then, build from source ([below](#build-from-source)).

### Try it on an example spec

This run uses
[`examples/specs/acme-quickstart.yaml`](examples/specs/acme-quickstart.yaml). The example is unsigned,
so it needs `--allow-unsigned`. A spec from your vendor does not:

```console tested exit=2 shape=^NOT\sREADY transcript=tests/fixtures/readme/run-quickstart.txt
$ rdy run examples/specs/acme-quickstart.yaml --allow-unsigned --no-report
WARNING: UNSIGNED SPEC
examples/specs/acme-quickstart.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
(three more lines of warning left out here)

rdy 0.1.0-alpha.0
spec    acme-quickstart >=1.0   (examples/specs/acme-quickstart.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    vm   linux   x86_64
user    uid 0 (root)

  BLOCK    net.egress        2 of 2 endpoints unreachable: registry.acme.example:443 (dns),
                             license.acme.example:443 (dns)
                             fix from the spec file (not verified): Ask your network team to allow
                             these endpoints through the proxy.
  WARN     host.disk/root    `/` has 22.9 GiB free on `/` (ext4). 24 GiB is recommended and 20 GiB
                             is the least.
                             fix from the spec file (not verified): Free space on / or mount a
                             larger volume.
  PASS     host.cpu          4 vCPUs found, 4 needed
  PASS     host.memory       13.4 GiB found, 8 GiB needed
  SKIP     host.disk/system  Does not apply here. This check is for windows only.

1 block, 1 warning, 2 passed, 1 not applicable

WARNING: UNSIGNED SPEC
NOT READY
$ echo $?
2
```

This is a real run from a build of `main`, on a Linux VM. Two things were cut for width: the long
warning text, and a note on the memory line about the cgroup the shell runs in. Your numbers will differ.

Read it like this. Problems come first, each with its fix under it. The `registry.acme.example` name is
made up and does not resolve, so `net.egress` blocks, and the verdict is `NOT READY`. The example is
unsigned, so you get the warning. Real specs are signed, and then you drop `--allow-unsigned`. To see
what a run looks like with no network, add `--no-network`. Then `net.egress` is reported as not run, and
a required check that did not run is never a pass: the verdict stays `NOT READY`.

`READY` exits 0, `READY with warnings` exits 1, `NOT READY` exits 2. Exit 64 means the input must
change (a bad flag, a spec with no valid signature). Exit 70 means rdy itself failed. Without
`--no-report`, rdy also writes a new report folder with the JSON report and a copy of the spec. With
`--json`, stdout carries only the JSON result, the same bytes as the file.

On `main` today the terminal shows the per-check list, the summary and the verdict. The report folder
holds the JSON report and a copy of the spec. The HTML report is not written by `rdy run` yet.

## Why it is safe to run

rdy runs inside your environment, sometimes on a production host. Do not take our word for what it
does. The code is open (Apache-2.0). These are the rules it is built to. Items marked (M2) are
not in the code yet.

- **Least privilege.** Every check declares what it needs: root, a kube context, cloud credentials.
  rdy runs what it can and reports what it could not. It never asks for `sudo`. Checks only read. A
  run writes one new report folder and nothing else. In a cluster it reads, plus three self-review
  requests, and never reads Secrets.
- **Nothing leaves the machine by default.** Results are written to a local folder. Sending anything
  anywhere will be a separate, explicit step you choose (M2). The HTML report renderer is in this repo
  and the upload client (M2) will be too, so a security reviewer can read exactly
  what would leave the box. Secrets are redacted before anything is written to disk.
- **Specs are signed.** The vendor signs the spec with an ed25519 key (a standard minisign signature).
  You pin the vendor's key once, after you check its fingerprint by another route. rdy will refuse a spec
  whose signature does not verify, always. It refuses an unsigned spec unless you pass
  `--allow-unsigned`, and then it prints a warning line. `rdy run` does this on `main` today.
- **Offline first.** Every command works with no network. Checks connect only to the hosts the spec
  lists, your proxy, your DNS servers and the Kubernetes API server you chose. On `main` three
  checks can reach the network. `net.egress` and `net.tls_intercept` do, and `--no-network` skips them. `host.time_sync` sends
  an SNTP packet only to servers the spec lists, and with `--no-network` it skips that measurement and
  runs on local data. `net.mtu` reads local interface and route data and runs offline. `net.egress`
  makes no HTTP request yet, so there is no redirect to follow. The rule for the HTTP path, when it lands, is
  that redirects are recorded and never followed. A vendor portal is planned, and it is optional.
- **One static binary.** No runtime to install, no OpenSSL. musl on Linux, rustls everywhere.
- **No telemetry.**

The threat model is in [`docs/plan/05-threat-model.md`](docs/plan/05-threat-model.md). To report a
vulnerability, read [`SECURITY.md`](SECURITY.md).

## How it works

- A **spec** is a YAML file of requirements: a product name, then a list of checks. Each check has a
  severity, `block` (required) or `warn` (optional), and an optional `fix` message. See
  [`examples/specs/`](examples/specs/) for five made-up examples.
- A **check** measures one thing: memory, free disk, a storage class, an RBAC permission. The check
  says what it found next to what the spec asked for.
- A **report** is a new folder with a JSON file and a copy of the spec, plus a verdict. HTML is next.
  The JSON is the same data for scripts.
- Human output goes to stderr. With `--json`, stdout carries only the JSON result, so you can use rdy
  as a CI gate.

## Check families

| Family | Checks | Status |
| --- | --- | --- |
| Host | CPU, memory, disk, OS, kernel, cgroups, time sync, ports, SELinux and AppArmor, firewall, security agents, sysctl, container runtime | Runs in `rdy run` on Linux |
| Network | egress (lookup, connect, TLS) | Runs in `rdy run`. Direct only: no HTTP request and no proxy yet |
| Network | MTU | Runs in `rdy run` |
| Network | TLS interception | Runs in `rdy run`. Classes only: no issuer name or root hash yet |
| Network | egress through a proxy, proxy settings | Coming before 0.1.0. The probe layer under them is built |
| Network | DNS, registry, bandwidth | Planned after 0.1.0 |
| Kubernetes | access, version, storage classes, RBAC for the install identity, Pod Security admission | Built and tested on fixtures. Not registered in `rdy run` yet |
| Kubernetes | nodes | Coming before 0.1.0 |
| Kubernetes | admission webhooks, namespace, DNS, ingress, CRDs, CNI | Planned after 0.1.0 |
| Diagnostics bundle | redacted collection and upload | Planned (M2) |
| AWS account | IAM dry run, quotas, regions | Planned (M3) |
| GPU | driver, CUDA, VRAM, device plugin | Planned (M4) |

A spec may name a check this build does not have. rdy counts it as not run and never reports it as a
pass. On `main` that includes every `k8s.*` check, the `net.*` checks other than `net.egress`,
`net.mtu` and `net.tls_intercept`, and every `gpu.*` and `aws.*` check.

## Write your own spec

Copy a file from [`examples/specs/`](examples/specs/) and edit it. The field reference is generated from
the schema: [`docs/intro/reference-spec.md`](docs/intro/reference-spec.md) for specs and
[`docs/intro/reference-result.md`](docs/intro/reference-result.md) for results. Check it, make a key and
sign it:

```sh skip=placeholder
rdy spec lint my-spec.yaml
rdy spec keygen acme-signing
rdy spec sign my-spec.yaml --secret-key acme-signing.key
```

`spec lint`, `spec keygen`, `spec sign` and `trust add|list|remove` work on `main` today. Customers pin
your public key with `rdy trust add <product> --key acme-signing.pub`. `rdy run` then verifies the
signature before it runs anything. A separate `rdy verify` command is coming before 0.1.0.

## Build from source

For contributors and testers. You need the Rust toolchain that `rust-toolchain.toml` pins.

```sh skip=builds
git clone https://github.com/getrdy-io/rdy
cd rdy
cargo install --path crates/rdy-cli --locked
rdy spec lint examples/specs/acme-quickstart.yaml
```

That lint run is real. It prints `examples/specs/acme-quickstart.yaml: 0 errors, 0 warnings` and exits 0.
Now run a spec. `--no-network` opens no connections, and `--jobs N` sets how many checks run at once:

```sh tested exit=2 shape=^NOT\sREADY
rdy run examples/specs/acme-quickstart.yaml --allow-unsigned
```

```sh tested exit=2 shape=^NOT\sREADY
rdy run examples/specs/acme-quickstart.yaml --allow-unsigned --no-network --jobs 2
```

The example specs are unsigned, so rdy prints a warning. `rdy run examples/specs/acme-platform.yaml
--allow-unsigned` shows more of the output, because that spec names Kubernetes, GPU and AWS checks
this build does not have, and rdy reports them as not run.

## Status

rdy is pre-release and under active development. The first release is planned as 0.1.0. The spec
format (`rdy/v1`) can still change before 1.0, and the changelog will say so.

**Works on `main` today**

- `rdy run <spec>`: it verifies the spec, runs the checks that exist, prints each result with its fix,
  skips the rest as not run, writes the JSON report and exits 0, 1 or 2 by the verdict. `--json` puts
  the report on stdout. `--no-network` and `--jobs` are there too.
- Thirteen host checks, on Linux, registered in `rdy run`: `host.cpu`, `host.memory`, `host.disk`,
  `host.os`, `host.kernel`, `host.cgroups`, `host.time_sync`, `host.ports`, `host.lsm` (SELinux and
  AppArmor), `host.firewall`, `host.security_agents`, `host.sysctl` and `host.container_runtime`. On
  macOS and Windows they report not run.
- Two network checks, registered in `rdy run`: `net.egress` (name lookup, connect to every address, TLS
  and ALPN, and the HTTP status of a URL endpoint, direct) and `net.mtu`. `--no-network` skips `net.egress` and says so. `net.mtu` reads
  local data and runs offline.
- The `net.tls_intercept` check, registered in `rdy run`. It does one TLS handshake per host, sends no
  data, and says whether the chain is public, trusted by this machine only (warn), from an unknown CA
  (block), or a clock or expiry problem (block, never called interception). `--no-network` skips it and
  says so.
- The spec format, the schema and a spec linter (`rdy spec lint`).
- Signing: key generation, `rdy spec sign` and `rdy trust add|list|remove`. `rdy run` checks the
  signature and refuses a bad one.
- The check engine: scheduler, timeouts, privilege negotiation, the probe layer that all side effects go
  through, and redaction of secrets in reports.
- The JSON report, the verdict logic and the HTML report, which `rdy run` writes next to the JSON.
- Kubernetes version, storage class, access, RBAC and Pod Security checks. These are tested against
  recorded fixtures. They are not registered in `rdy run` yet.

**Next**

- Registering the Kubernetes checks in `rdy run`.
- The egress proxy path, the proxy check, and Kubernetes nodes.

**Before 0.1.0**

- `rdy verify`.
- Signed release binaries and an install script that checks them.
- A first-run page and the quickstart spec, run end to end on a clean checkout, and golden
  transcripts for this page.

**After 0.1.0**

- 0.1.x: the remaining host, network and Kubernetes checks in the table above.
- M2: the redacted diagnostics bundle, `rdy upload`, and the hosted portal for vendors. The portal is
  not needed to use the tool.
- M3: AWS account checks, `spec init`, `self-update`.
- M4: GPU checks and custom checks that run a command you approve.

The five release targets are Linux x86_64 and aarch64 (musl), macOS aarch64 and x86_64, and Windows
x86_64. In 0.1.0 the host checks read Linux data sources only. On macOS and Windows they report not
run, which makes a required check NOT READY. Those data sources are planned for M2.

## Rdy and the Kubernetes-only preflight tool

The open-source preflight and support-bundle tool for Kubernetes is a good project. If your target is
one cluster, it may be all you need. rdy aims at a wider job: one binary that checks a VM, a cluster
and, later, a cloud account, with signed specs and a report a non-engineer can read. Both run on the
machine where you start them.

## Contributing

Bugs and check requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. It has the build
steps, the rules every check follows and the PR checklist. For security problems, do not open a public
issue. Follow [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Apostolic Path LLC owns the code, the
copyright and the marks. The Rdy name and logo are trademarks and are not covered by the license. See
[`TRADEMARKS.md`](TRADEMARKS.md).
