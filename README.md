# rdy

**Install day should be boring.**

rdy checks a machine, a Kubernetes cluster or a cloud account against a software vendor's written
requirements, before the install. It tells you what is wrong and how to fix it. It is one signed binary
with no runtime, and it works offline.

> **Pre-release.** rdy is under active development. There is no release yet, so there is no install
> command on this page. `rdy run`, the command that does the main job, is not wired up on `main`
> yet. See [Status](#status) for what works today and what is coming.

## The problem

Installs fail because the environment isn't ready, not because the product is broken. Not enough RAM.
A proxy that blocks the registry. A storage class that cannot do ReadWriteMany. Somebody finds out on
install day, on a call, with the customer watching.

rdy moves that discovery earlier. The vendor writes down what the product needs, as a short YAML
file called a spec, and signs it. The customer's platform or IT engineer runs one command. They get a
list of what is wrong, with a fix under each problem, and an HTML and JSON report to send back.

You might be reading this because a vendor sent you a spec and asked you to run it. Or you are a
sales engineer who is tired of finding out about the proxy on install day. Both are the audience.

## What it looks like

This is what a run will look like. It is illustrative and written by hand from the output format in
[`docs/plan/07-cli-ux.md`](docs/plan/07-cli-ux.md), not recorded from a real run, because `rdy run` is
not wired up yet. The host names are made up. The banner and the report lines are left out.

```console
$ rdy run acme-quickstart.yaml
rdy 0.1.0
spec    acme-quickstart >=1.0   (acme-quickstart.yaml)
sig     verified, key 9F3A6C21D4E87B05, trusted by you, signed 2027-03-02
host    acme-vm-03.corp.example   rhel 9.4   x86_64
user    jdoe (not root)

  BLOCK    host.memory       4.0 GiB found, 8 GiB needed
                             fix from acme-quickstart: Add RAM or choose a larger node class.
  WARN     host.disk/root    12.0 GiB free on /, 20 GiB needed
                             fix from acme-quickstart: Free space on / or mount a larger volume.
  PASS     host.cpu          4 vCPUs found, 4 needed
  SKIP     host.disk/system  Does not apply here. This check is for windows only.

1 block, 1 warning, 1 passed, 1 not applicable
NOT READY
$ echo $?
2
```

Problems come first, each with its fix on the line below. The last line is the verdict, and the exit
code matches it: `READY` is 0, `READY with warnings` is 1, `NOT READY` is 2. A required check that
could not run, for example because it needed root or there is no kubeconfig, is never a pass. It makes
the verdict `NOT READY`. Exit 64 means the input must change (a bad flag, a spec with no valid
signature). Exit 70 means rdy itself failed.

## Why it is safe to run

rdy runs inside your environment, sometimes on a production host. You should not take our word for
what it does, so every claim below is a rule the code is built and tested against, and the code is
open (Apache-2.0).

- **Least privilege.** Every check declares what it needs: root, a kube context, cloud credentials.
  rdy runs what it can and reports what it could not. It never asks for `sudo`, and it never changes
  anything on the machine.
- **Nothing leaves the machine by default.** Results are written to a local folder. Sending anything
  anywhere is a separate, explicit step you choose. The upload client and the HTML report renderer are
  open source so a security reviewer can read exactly what would leave the box. Secrets are redacted
  before anything is written to disk.
- **Specs are signed.** The vendor signs the spec with an ed25519 key (a standard minisign signature).
  You pin the vendor's key once, after you check its fingerprint by another route. rdy refuses a spec
  whose signature does not verify, always. It refuses an unsigned spec unless you pass
  `--allow-unsigned`, and then it says so loudly.
- **Offline first.** Every command works with no network. Checks only contact the hosts the spec
  lists. A vendor portal is planned, and it is optional.
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
- A **report** is HTML and JSON in a new folder, plus a verdict. The JSON is the same data for scripts.
- Human output goes to stderr. With `--json`, stdout carries only the JSON result, so you can use rdy
  as a CI gate.

## Check families

| Family | Checks | Status |
| --- | --- | --- |
| Host | CPU, memory, disk, OS, SELinux and AppArmor | Built (Linux), not reachable from `rdy run` yet |
| Host | ports, kernel, cgroups, time sync, sysctl, container runtime | Coming before 0.1.0 |
| Network | egress through a proxy, DNS, registry, TLS interception, MTU, bandwidth | Coming before 0.1.0. The probe layer under them is built |
| Kubernetes | version, storage classes, RBAC for the install identity | Built, not reachable from `rdy run` yet |
| Kubernetes | nodes, admission, namespace, DNS, ingress, CRDs, CNI | Coming before 0.1.0 |
| Diagnostics bundle | redacted collection and upload | Planned (M2) |
| AWS account | IAM dry run, quotas, regions | Planned (M3) |
| GPU | driver, CUDA, VRAM, device plugin | Planned (M4) |

A spec may name a check this build does not have. rdy says "Not run. This version of rdy has no gpu
checks yet.", counts it as not run, and never reports it as a pass.

## Write your own spec

Copy a file from [`examples/specs/`](examples/specs/) and edit it. The field reference is generated from
the schema: [`docs/intro/reference-spec.md`](docs/intro/reference-spec.md) for specs and
[`docs/intro/reference-result.md`](docs/intro/reference-result.md) for results. Check it, make a key and
sign it:

```sh
rdy spec lint my-spec.yaml
rdy spec keygen acme-signing
rdy spec sign my-spec.yaml --secret-key acme-signing.key
```

`spec lint`, `spec keygen`, `spec sign` and `trust add|list|remove` work on `main` today. Customers pin
your public key with `rdy trust add <product> --key acme-signing.pub`. Verifying a signature while
running a spec (`rdy verify` and `rdy run`) is the next piece.

## Build from source

For contributors and testers. You need the Rust toolchain that `rust-toolchain.toml` pins.

```sh
git clone https://github.com/getrdy-io/rdy
cd rdy
cargo install --path crates/rdy-cli --locked
rdy spec lint examples/specs/acme-quickstart.yaml
```

That lint run is real and works today. It prints `examples/specs/acme-quickstart.yaml: 0 errors, 0
warnings` and exits 0. Running `rdy run examples/specs/acme-platform.yaml --allow-unsigned` is the
command the project is working toward. On `main` it currently prints `error: rdy run is not yet
implemented in this build` and exits 70. That is expected until `rdy run` is wired up.

## Status

rdy is pre-release and under active development. The first release is planned as 0.1.0. The spec
format (`rdy/v1`) can still change before 1.0, and the changelog will say so.

**Works on `main` today**

- The spec format, the schema and a spec linter (`rdy spec lint`).
- Signing: key generation, `rdy spec sign` and `rdy trust add|list|remove`. The signature verifier is
  built and tested.
- The check engine: scheduler, timeouts, privilege negotiation, the probe layer that all side effects go
  through, and redaction of secrets in reports.
- The JSON report and the verdict logic.
- Host checks on Linux (CPU, memory, disk, OS, SELinux and AppArmor), and Kubernetes version, storage
  class and RBAC checks. These are tested against recorded fixtures. They are not reachable from the
  command line yet.

**In progress**

- Wiring `rdy run` end to end: load the spec, run the checks, write the reports, set the exit code.
- The human terminal output and the HTML report.
- The network checks and the rest of the host and Kubernetes checks.

**Before 0.1.0**

- `rdy verify` and signature checking inside `rdy run`, with the `--allow-unsigned` banner.
- Signed release binaries and an install script that checks them.
- A time-boxed quickstart, tested on a clean machine, and golden transcripts for this page.

**After 0.1.0**

- M2: the redacted diagnostics bundle, `rdy upload`, and the hosted portal for vendors. The portal is
  not needed to use the tool.
- M3: AWS account checks, `spec init`, `self-update`.
- M4: GPU checks and custom checks that run a command you approve.

The five release targets are Linux x86_64 and aarch64 (musl),
macOS aarch64 and x86_64, and Windows x86_64. Where a data source is not built for an OS yet, the check
reports it as skipped. It does not pass.

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

Apache-2.0. See [`LICENSE`](LICENSE).
