# rdy

**Install day should be boring.**

rdy checks a machine, a Kubernetes cluster or (later) a cloud account against a software vendor's
written requirements, before the install. It tells you what is wrong and how to fix it. One signed
binary. No runtime. Works offline.

> **Pre-release.** No release is tagged yet. `rdy run` works on `main` today with 24 checks (host,
> network and Kubernetes). The install command below is the shape it will have. Until a tag exists you
> build from source. [Status](#status) says what works and what is planned.

## The problem

Installs fail because the environment isn't ready, not because the product is broken. Not enough RAM.
A proxy that blocks the registry. A storage class that cannot do ReadWriteMany. Somebody finds out on
install day, on a call, with the customer watching.

rdy runs those checks first. The vendor writes down what the product needs, as a short YAML file
called a spec, and signs it. The customer runs one command and gets a list of what is wrong, with a
fix under each problem, and a report to send back.

You might be reading this because a vendor sent you a spec and asked you to run it. Or you sell or
support software that ships into customer environments, and you are tired of finding out about the
proxy on install day. Both are the audience.

## What it looks like

A vendor signs its spec. rdy refuses a spec with no signature. This block runs against a spec in this
repo, from the repo root:

```console tested exit=64 shape=^fix:\s transcript=tests/fixtures/readme/refusal-unsigned.txt
$ rdy run examples/specs/acme-quickstart.yaml
error: no signature found at examples/specs/acme-quickstart.yaml.minisig
fix: ask the vendor for examples/specs/acme-quickstart.yaml.minisig and put it next to the spec. If you wrote this spec yourself, see https://docs.getrdy.io/unsigned
$ echo $?
64
```

The example specs in this repo are not signed. `--allow-unsigned` runs a spec that has no signature,
and nothing else: a signature that does not match is still refused. Each run that uses it prints a
banner first and again above the verdict, and marks the reports. The rest of this page uses it.

The next two runs come from synthetic test machines recorded in the test suite. They are not from a
live host, and the spec files `not-ready.yaml` and `ready.yaml` are test fixtures, not files in
`examples/`. Your output will differ. Problems come first, each with its fix under it. Passing checks
come last.

```console skip=placeholder transcript=tests/fixtures/readme/run-not-ready.txt
$ rdy run not-ready.yaml --allow-unsigned --no-report
WARNING: UNSIGNED SPEC
not-ready.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

rdy <version>
spec    acme-platform >=1.0   (not-ready.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    all-block.example   rhel 9.3   x86_64
user    uid 0 (root)

  BLOCK    host.memory             7.8 GiB found, 32 GiB needed; only 6.6 GiB available, 16 GiB
                                   wanted, the box is busy
                                   fix from the spec file (not verified): Add RAM or choose a larger
                                   VM size.
  BLOCK    host.disk               `/var/lib/acme` has 0 bytes free on `/var` (xfs), 20 GiB needed.
                                   fix from rdy: Run `df -h /var/lib/acme` to see the volume. If
                                   `/dev/mapper/rhel-var` is an LVM volume, grow it with `lvextend
                                   -r -L +24G /dev/mapper/rhel-var`. Otherwise grow the volume, or
                                   point the install at a larger disk.
  BLOCK    host.ports              Port 6443/tcp is held by `kube-apiserver` (pid 950).
                                   fix from rdy: Port 6443/tcp is held by `kube-apiserver` (pid
                                   950). Stop it, or change the product's port setting.
  BLOCK    net.egress              1 of 1 endpoints unreachable: web.acme.test:8080 (refused)
                                   fix from rdy: web.acme.test:8080 refused the connection: nothing
                                   listens there, or a firewall rejects it. Check the port in the
                                   spec, and ask the network team to allow tcp/8080 to web.acme.test
                                   from this machine.
  PASS     host.os                 Red Hat Enterprise Linux 9.3 (Plow) on x86_64 meets the spec.
  PASS     host.cpu                8 vCPUs found, 8 needed
  PASS     host.kernel             Kernel `5.14.0-362.el9.x86_64` meets the minimum of 5.4. All 3
                                   required modules are loaded or built in. BTF type information is
                                   present.
  PASS     host.cgroups            cgroup v2 in use, controllers `cpu`, `memory`, `io` and `pids`
                                   available
  PASS     host.sysctl             4 kernel parameters have the wanted value and are set at boot.
                                   Services get an open files limit of 1048576
                                   (`DefaultLimitNOFILE=1048576` in
                                   `/etc/systemd/system.conf.d/10-acme.conf`).
  PASS     host.lsm                SELinux is enforcing. AppArmor is off.
  PASS     host.time_sync          Clock is synchronized, under 1 ms away from chrony's reference
                                   `192.0.2.30`.
  PASS     host.security_agents    No known security software process was found among 7 processes.
  PASS     host.container_runtime  containerd 1.7.13 is running (cgroup driver systemd, storage
                                   driver overlayfs).
  PASS     host.firewall           firewalld zone public allows 6443/tcp and 10250/tcp inbound.
  PASS     net.mtu                 `eth0` has MTU 1500.

4 blocks, 0 warnings, 11 passed

WARNING: UNSIGNED SPEC
NOT READY
$ echo $?
2
```

The team resizes the disk, frees the port and opens the firewall rule. They run it again.

```console skip=placeholder transcript=tests/fixtures/readme/run-ready.txt
$ rdy run ready.yaml --allow-unsigned --no-report
WARNING: UNSIGNED SPEC
ready.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

rdy <version>
spec    acme-platform >=1.0   (ready.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    all-pass.example   rhel 9.3   x86_64
user    uid 0 (root)

  PASS     host.os                 Red Hat Enterprise Linux 9.3 (Plow) on x86_64 meets the spec.
  PASS     host.memory             31.3 GiB found, 32 GiB needed, inside the 5% tolerance
  PASS     host.cpu                8 vCPUs found, 8 needed
  PASS     host.disk               `/var/lib/acme` has 100 GiB free on `/var` (xfs). 20 GiB is
                                   needed.
  PASS     host.kernel             Kernel `5.14.0-362.el9.x86_64` meets the minimum of 5.4. All 3
                                   required modules are loaded or built in. BTF type information is
                                   present.
  PASS     host.cgroups            cgroup v2 in use, controllers `cpu`, `memory`, `io` and `pids`
                                   available
  PASS     host.sysctl             4 kernel parameters have the wanted value and are set at boot.
                                   Services get an open files limit of 1048576
                                   (`DefaultLimitNOFILE=1048576` in
                                   `/etc/systemd/system.conf.d/10-acme.conf`).
  PASS     host.lsm                SELinux is enforcing. AppArmor is off.
  PASS     host.time_sync          Clock is synchronized, under 1 ms away from chrony's reference
                                   `192.0.2.30`.
  PASS     host.ports              80/tcp, 443/tcp, 6443/tcp, 10250/tcp and 8472/udp are free.
  PASS     host.security_agents    No known security software process was found among 6 processes.
  PASS     host.container_runtime  containerd 1.7.13 is running (cgroup driver systemd, storage
                                   driver overlayfs).
  PASS     host.firewall           firewalld zone public allows 6443/tcp and 10250/tcp inbound.
  PASS     net.egress              1 of 1 endpoints reachable
  PASS     net.mtu                 `eth0` has MTU 1500.

0 blocks, 0 warnings, 15 passed

WARNING: UNSIGNED SPEC
READY
$ echo $?
0
```

The last line is one of three, and each has an exit code: `READY` (0), `READY with warnings` (1),
`NOT READY` (2). Exit 64 means the input must change, for example a missing signature. Exit 70 means
rdy itself failed. Both print `error:` and `fix:` lines and no verdict.

### A required check that cannot run is not a pass

A check the spec marks `severity: block` that rdy cannot run is a required check not run. It never
gives `READY`. The next run is a real run of an example spec on a recorded Linux machine with no
kubeconfig. The spec also asks for GPU and AWS checks, which this version does not have. The
`--no-report` flag keeps the transcript short by writing no report folder.

```console tested exit=2 shape=^NOT\sREADY transcript=tests/fixtures/readme/run-platform.txt
$ rdy run examples/specs/acme-platform.yaml --allow-unsigned --no-report
WARNING: UNSIGNED SPEC
examples/specs/acme-platform.yaml has no signature. rdy cannot tell who wrote it or whether it was changed.
The spec decides which files rdy reads and which hosts it contacts.
Run it only if you wrote it yourself or got it from the vendor in a way you trust.
Every report from this run is marked UNSIGNED SPEC.

rdy <version>
spec    acme-platform >=4.2   (examples/specs/acme-platform.yaml)
sig     UNSIGNED (allowed by --allow-unsigned)
host    acme-platform.example   rhel 9.3   x86_64
user    uid 0 (root)
cluster no kubeconfig found

  BLOCK    net.egress        2 of 2 endpoints unreachable: registry.acme.example:443
                             (reset_after_hello), license.acme.example:443 (reset_after_hello)
                             fix from the spec file (not verified): Ask your network team to allow
                             these endpoints through the proxy.
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
  PASS     host.cpu          8 vCPUs found, 8 needed
  PASS     host.memory       31.3 GiB found, 32 GiB needed, inside the 5% tolerance
  PASS     host.disk         `/var/lib` has 140 GiB free on `/var` (xfs). 100 GiB is needed.

1 block, 0 warnings, 3 passed, 3 required checks not run, 1 optional check not run

WARNING: UNSIGNED SPEC
NOT READY
$ echo $?
2
```

A check marked `severity: warn` that did not run is an optional check not run. It gives
`READY with warnings` at worst. A CI gate written as `[ $? -le 1 ]` therefore never passes an
environment nobody checked.

## Install and first run

Releases are signed. The M1 install path is the `install.sh` file attached to a pinned GitHub release.
It needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.1.3 or newer on your
PATH. Without it, the script stops and installs nothing. It checks the signature of the checksum file
and the sha256 of the archive before it makes anything executable. It never runs `sudo` and never edits
your shell profile. It writes one file, `rdy`, to `$HOME/.local/bin`, or to the folder in
`RDY_INSTALL_DIR`, and prints a PATH hint. As root, it refuses unless you pass `--allow-root`, and then
it writes `/usr/local/bin/rdy`, unless `RDY_INSTALL_DIR` is set.

There is no tagged release yet. When there is one, the tags look like `v0.1.0-alpha.N` and the
command is this:

```sh skip=placeholder
TAG=v0.1.0-alpha.N   # use the newest tag on the releases page
curl --proto '=https' --tlsv1.2 -sSfL "https://github.com/getrdy-io/rdy/releases/download/$TAG/install.sh" | sh
"$HOME/.local/bin/rdy" run <spec-from-your-vendor>.yaml
```

Root shells need `sh -s -- --allow-root` after the pipe, and then run `/usr/local/bin/rdy`, not
`"$HOME/.local/bin/rdy"`. A shorter `curl ... https://getrdy.io/install | sh` comes later, in M2, when
that address goes live.

On Windows, download the `.zip` from the [releases page](https://github.com/getrdy-io/rdy/releases)
and verify it by hand, as below. A PowerShell installer is planned for M3.

### Rather not pipe to a shell?

Download, verify and unpack by hand. The archive holds `rdy-<triple>/rdy`. One signed file,
`SHA256SUMS`, lists every asset:

```sh skip=placeholder
TAG=v0.1.0-alpha.N   # use the newest tag on the releases page
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

The last three `cosign` flags are required. Without them, a workflow in another repository could pass.

### Try it on an example spec

Until a release exists, build from source ([below](#build-from-source)). The example spec
[`examples/specs/acme-quickstart.yaml`](examples/specs/acme-quickstart.yaml) describes a made-up
product and is not signed. Check it, then run it from the repo root:

```sh tested shape=^examples/specs/acme-quickstart\.yaml:\s0\serrors,\s0\swarnings$
rdy spec lint examples/specs/acme-quickstart.yaml
```

```sh tested exit=2 shape=^NOT\sREADY
rdy run examples/specs/acme-quickstart.yaml --allow-unsigned
```

It takes a few seconds. rdy runs what it can, and says what it could not run and why. It never asks for
sudo. Expect `NOT READY` and exit 2. The example talks to `registry.acme.example`, which does not exist,
so `net.egress` blocks and names the endpoints it could not reach. On a small machine you may also see
`BLOCK` on `host.memory` or `WARN` on `host.disk`, each with its fix. `--no-network` opens no
connections. Then `net.egress` is reported as not run, and the verdict is still `NOT READY`.

rdy also writes a new folder in the current directory, and never overwrites one. It holds
`rdy-report-<spec>-<time>.html`, the same data as `.json`, and a copy of the spec. The HTML is one
self-contained page you can email or print. `--out-dir <dir>` picks the parent folder and `--no-report`
writes no files.

To see green, copy the spec and point `net.egress` at a host you can reach. In a real install you fix
the machine, not the spec. This is only so you can see a green run on whatever you are holding:

```sh skip=network
sed 's|\["registry.acme.example:443", "license.acme.example:443"\]|["github.com:443"]|' \
  examples/specs/acme-quickstart.yaml > my-spec.yaml
rdy run my-spec.yaml --allow-unsigned
```

On a machine with 4 cores, 8 GiB of RAM, 20 GiB free and a route to github.com, that ends in `READY`
and exit 0. If the disk is short, you get `READY with warnings` and exit 1.

## Why it is safe to run

rdy runs inside your environment, sometimes on a production host. Do not take our word for what it
does. The code is open (Apache-2.0). These are the rules it is built to. Items marked (M2) are not in
the code yet.

- **Least privilege.** Every check declares what it needs: root, a kube context, cloud credentials.
  rdy runs what it can and reports what it could not. It never asks for `sudo`. A run writes one new
  report folder and nothing else.
- **Nothing leaves the machine by default.** Results are written to a local folder. Sending anything
  anywhere will be a separate, explicit step you choose (M2). The HTML report renderer is in this repo
  and the upload client (M2) will be too, so a security reviewer can read exactly what would leave the
  box. Secrets are redacted before anything is written to disk.
- **Specs are signed.** The vendor signs the spec with an ed25519 key (a standard minisign signature).
  You pin the vendor's key once with `rdy trust add`, after you check its fingerprint by another route.
  rdy refuses a spec whose signature does not verify, always. It refuses an unsigned spec unless you
  pass `--allow-unsigned`, and then it prints a warning and marks every report. `rdy verify <spec>`
  checks a signature without running any check.
- **Offline first.** Every command works with no network. Checks connect only to the hosts the spec
  lists, your proxy, your DNS servers and the Kubernetes API server you chose. `--no-network` turns
  off every check that would open a connection, and says so in the result.
- **One static binary.** No runtime to install, no OpenSSL. The design is musl on Linux and rustls
  everywhere. Release binaries come with the first tagged release.
- **No telemetry.** There is none.

The threat model is in [`docs/plan/05-threat-model.md`](docs/plan/05-threat-model.md). To report a
vulnerability, read [`SECURITY.md`](SECURITY.md).

## How it works

- A **spec** is a YAML file of requirements: a product name, then a list of checks. Each check has a
  severity, `block` (required) or `warn` (optional), and an optional `fix` message.
- A **check** measures one thing: memory, free disk, a storage class, an RBAC permission. The result
  says what it found next to what the spec asked for.
- A **report** is a new folder with an HTML page, a JSON file and a copy of the spec, plus a verdict.
  The JSON is the same data for scripts.
- Human output goes to stderr. With `--json`, stdout carries only the JSON result, so you can use rdy
  as a CI gate:

```sh skip=placeholder
rdy run spec.yaml --json > result.json
echo $?   # 0 ready, 1 ready with warnings, 2 not ready, 64 usage, 70 internal
```

Scripts can rely on the exit code and on `verdict`, `summary` and `checks[].status` in the JSON. Do not
parse `message` or `fix`.

## Check families

| Family | Checks | Status |
| --- | --- | --- |
| Host | CPU, memory, disk, OS, kernel, cgroups, time sync, ports, SELinux and AppArmor, firewall, security agents, sysctl, container runtime | In `rdy run`, on Linux. On macOS and Windows they report not run |
| Network | egress, proxy, MTU, TLS interception | In `rdy run` |
| Network | DNS, registry, bandwidth | Planned after 0.1.0 |
| Kubernetes | access, version, storage classes, RBAC for the install identity, Pod Security admission, namespace, nodes | In `rdy run`. Tested on recorded fixtures, not yet on live clusters |
| Diagnostics bundle | redacted collection and upload | Planned (M2) |
| AWS account | IAM dry run, quotas, regions | Planned (M3) |
| GPU | driver, CUDA, VRAM, device plugin | Planned (M4) |

A spec may name a check this build does not have. rdy counts it as not run and never reports it as a
pass. To see what your build has, run `rdy run` on a spec and read the SKIP lines.

Missing a check that would have saved you an install? Open a check request. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Write your own spec

Copy a file from [`examples/specs/`](examples/specs/) (a quickstart, a full platform, Kubernetes only,
an air-gapped host and a GPU workload) and edit it. The field reference is generated from the schema:
[`docs/intro/reference-spec.md`](docs/intro/reference-spec.md) for specs and
[`docs/intro/reference-result.md`](docs/intro/reference-result.md) for results. Check it, make a key and
sign it:

```sh skip=placeholder
rdy spec lint my-spec.yaml
rdy spec keygen acme-signing
rdy spec sign my-spec.yaml --secret-key acme-signing.key
```

Customers pin your public key with `rdy trust add <product> --key acme-signing.pub`, after you give them
its fingerprint by a second route. `rdy run` then verifies the signature before it runs anything.

## Build from source

For contributors and testers. You need the Rust toolchain that `rust-toolchain.toml` pins.

```sh skip=builds
git clone https://github.com/getrdy-io/rdy
cd rdy
cargo install --path crates/rdy-cli --locked
rdy spec lint examples/specs/acme-quickstart.yaml
```

## Rdy and the Kubernetes-only preflight tool

The open-source preflight and support-bundle tool for Kubernetes is a good project. If your target is
one cluster, it may be all you need. rdy aims at a wider job: one binary that checks a VM, a cluster
and, later, a cloud account, with signed specs and a report a non-engineer can read. Both run on the
machine where you start them.

## Status

rdy is pre-release and under active development. The first release is planned as 0.1.0, and until
then tags look like `v0.1.0-alpha.N`. The spec format (`rdy/v1`) can still change before 1.0, and the
changelog will say so. Linux x86_64 is the best tested platform. The five release targets are Linux
x86_64 and aarch64 (musl), macOS aarch64 and x86_64, and Windows x86_64. In the first releases the host
checks read Linux data sources only. On macOS and Windows they report not run, which makes a required
check `NOT READY`. Those data sources are planned for M2.

Planned: the redacted diagnostics bundle, `rdy upload` and a hosted portal for vendors (M2, the CLI does
not need the portal), AWS account checks and `spec init` (M3), GPU checks and custom checks that run a
command you approve (M4).

## Contributing

Bugs and check requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. It has the build
steps, the rules every check follows and the PR checklist. For security problems, do not open a public
issue. Follow [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Apostolic Path LLC owns the code, the
copyright and the marks. The Rdy name and logo are trademarks and are not covered by the license. See
[`TRADEMARKS.md`](TRADEMARKS.md).
