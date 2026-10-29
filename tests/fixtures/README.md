# Fixtures

Fixtures let CI test environments it cannot have: a GPU node, an air-gapped site, a Windows host with a
given agent. A fixture is data. A Linux environment replays on a Windows runner.

The design is in `docs/plan/08-testing.md`, section 2 and Appendix A. This page is the format reference.
If the two differ, the plan wins until this page is fixed.

These files live at the repo root, outside every crate. `cargo package` never ships them, so tests that
need them do not run from a crates.io tarball. Tests find them from `CARGO_MANIFEST_DIR`.

## The rule: every fixture is synthetic

No byte came from a customer or a person. Never commit a secret, a real hostname, a real spec or anything
recorded at a design partner. If a partner hits a failure we cannot reproduce, write a `hand` fixture with
the same shape and `acme` names.

Each manifest names its `origin`:

| Origin | Meaning |
| --- | --- |
| `hand` | Written by us from a vendor doc or an RFC. Our guess at a system, not a recording |
| `generated` | Built at test time or by a script (`rcgen` chains, SNTP packets, kubeconfigs) |
| `ci-runner` | Recorded on a GitHub-hosted runner, then scrubbed |
| `throwaway` | Recorded on a rented machine made for the purpose and destroyed after, then scrubbed |

A developer laptop is not an origin. Only `ci-runner` and `throwaway` fixtures may be called "recorded from
a real system".

Allowed values:

- Addresses: documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`),
  RFC 1918, `100.64.0.0/10`, `fd00::/8` and loopback.
- Names: end in `.example`, `.test`, `.invalid`, `.local` or `cluster.local`. Use `acme` for the vendor.
  Vendors Rdy checks (OS vendors, `k8s.io`, `nvidia.com`) are on the lint allow-list. Anything else needs
  an entry in `allow.toml` with a one-line reason.
- Tokens: the string `REDACTED-TEST-TOKEN`, or built from parts at test time when a push-protection
  scanner would flag them.

## Layout

```text
tests/fixtures/
  README.md                      this page
  allow.toml                     lint exceptions, each with a one-line reason
  checks/<check-id>/<case>/      one check, one situation
  checks/_policy/<case>/         engine policy cases, for example symlink-to-shadow
  envs/<env>/                    one whole environment plus a spec to run against it
  redaction/<category>/<case>.{in,expected,toml}
  results/<rdy-version>/*.json   result files from released versions, append only
  specs/{valid,malformed}/       parser corpus
  signed/                        one signed spec, its .minisig and public key, never edited
  minisign-c/                    a key and a signature made by the C minisign tool, never edited
  wycheproof/                    ed25519 test vectors for the signature verifier
  canary/                        files that guard line endings on Windows
```

What exists today: `signed/`, `minisign-c/`, `specs/malformed/`, `wycheproof/` and `canary/`. The rest arrives with the
tickets that need it. The names above are fixed now so nobody invents another.

| Path | What it is | Who edits it |
| --- | --- | --- |
| `allow.toml` | Lint exceptions. `169.254.169.254` for the metadata tests is the first | By hand, with a reason per entry |
| `checks/<check-id>/<case>/` | A small environment for one check. Each registered check needs a passing case, a non-passing case, a no-privilege `partial` case where a root-optional need exists, and a `Timeout` case where it runs a command or opens a socket | By hand, with the check ticket |
| `checks/_policy/<case>/` | Engine policy cases. `symlink-to-shadow` is required and expects `Denied` | By hand |
| `envs/<env>/` | A whole environment and the spec the env test runs against it. Five in M1: `all-pass`, `warnings-only`, `all-block`, `no-privileges`, `timeouts` | By hand, goldens by `UPDATE_GOLDENS=1` |
| `redaction/<category>/<case>.in`, `.expected`, `.toml` | Input, expected output and the rule setup for a redaction case | By hand only. `UPDATE_GOLDENS` never touches it |
| `results/<rdy-version>/*.json` | Result files written by released versions. They must stay parseable | Append only. Never edited |
| `specs/valid/`, `specs/malformed/` | Parser corpus. Each malformed file is one way a spec can be wrong | By hand |
| `signed/` | One signed spec. See `signed/README.md` | Never. New cases get new files |
| `minisign-c/` | A key with a published test password and a signature, both made by C minisign 0.11. See `minisign-c/README.md` | Never |
| `wycheproof/` | Test vectors for ed25519. See `wycheproof/README.md` | Never |
| `canary/` | Files that must reach every OS byte for byte. See "Line endings" below | Never |

A check case and an environment use the same format. A case is a small environment. One loader reads both.

## An environment or case

```text
envs/all-pass/
  fixture.toml       the manifest
  spec.yaml          the spec the env test runs
  root/              fake file tree; root/etc/os-release stands for /etc/os-release
  root.manifest.json symlinks, unreadable files, modes, empty dirs (what git and Windows cannot store)
  commands/          recorded command output, one JSON file per argv
  native/            recorded results of native calls: statvfs, uname, registry keys
  api/               recorded Kubernetes and cloud API responses
  net.json           scripted DNS and TCP behaviour per host:port
  env.json           environment variables the process sees
  caps.json          which needs are available (see `[caps]` in the manifest)
  golden/            report.json, report.html, terminal.txt
  expect.json        (check cases) the reviewed expected result
```

Anything a check asks for that is not recorded fails the test. A fixture never falls through to the real
machine.

### `fixture.toml`

```toml
schema = 1
name = "net-corp-proxy"
summary = "Ubuntu VM behind an authenticating CONNECT proxy that re-signs TLS with a private CA"
origin = "hand"
os = "linux"                  # what Backend::os() reports: linux, macos, windows
arch = "x86_64"
base = "all-pass"             # optional, one level only
remove = ["root/etc/docker/daemon.json"]
crlf = []                     # files allowed to contain \r
answers = ["host.os", "net.egress", "net.proxy", "net.tls_intercept"]
spec = "spec.yaml"

[caps]                        # which needs are available
root = false
network = true
kube = false

[run]                         # honoured by the in-process harness
clock = "2026-11-02T09:00:00Z"
run_id = "00000000-0000-4000-8000-000000000001"
jobs = 1
deadline_ms = 20000

[expect]
verdict = "not_ready"
exit_code = 2

[matrix]                      # optional; only when the env is evidence for a matrix row
os_family = "ubuntu"
os_version = "22.04"
proxy = "connect-basic-tls-intercept"
```

- `base` is the only reuse feature. Child files replace base files by path. `remove` deletes some. One
  level, no other options.
- `answers` lists the check ids the env can answer. The loader says "this fixture does not answer
  host.memory" instead of a confusing `NotRecorded`.
- `crlf` lists the files that may contain `\r`. Every other fixture file must be LF only.
- Virtual paths are POSIX strings. `root/proc/meminfo` answers `/proc/meminfo` on every runner. A Windows
  env keeps drive files under `root/c/Windows/...`, mapped to the lowercase key `c:/windows/...`, only when
  `os = "windows"`. Programs resolve through the Backend by the fixture's `os`, never the runner's.

### `root/` and `root.manifest.json`

`root/` holds plain files. It holds no symlinks, no special modes and no name with `:`, `[` or `]`, because
git and Windows cannot store them. `root.manifest.json` adds them in memory:

```json
{
  "symlinks": { "proc/1234/fd/7": "socket:[8841]" },
  "unreadable": ["var/log/audit/audit.log"],
  "modes": { "etc/acme/license.key": "0640" },
  "dirs": ["var/lib/acme"]
}
```

`unreadable` simulates a no-privilege run. Replay follows the symlinks when it applies the deny list.

### `commands/*.json`

Any slug for the file name. One command per file:

```json
{ "argv": ["/usr/bin/chronyc", "-n", "-c", "tracking"], "stdout": "...", "stderr": "", "exit": 0, "delay_ms": 0 }
```

The key is the normalised resolved `argv`. Binary output uses `stdout_b64`. A duplicate key fails the
lint. A `delay_ms` is a timer, so a delay past the check limit gives a `Timeout` without real waiting.

### `api/*.json`

Any slug for the file name. One request per file:

```json
{ "request": { "method": "GET", "path": "/version", "query": "" }, "status": 200, "body": {}, "delay_ms": 0 }
```

Paged lists have one file per `continue` token. Access reviews are answered from `api/reviews.json`, a
table of attributes to `allowed` and `reason`. The mock records every request, and the k8s tests assert
that only the allowed ones arrived.

### `native/*.json`

One JSON file per native call that has no portable text form: `statvfs`, `uname`, `adjtimex`, sysinfo
results, Windows registry and service data. Keyed by the call's arguments, for example by path.

### `net.json`

```json
{
  "dns": { "registry.acme.example": ["192.0.2.10"], "gone.acme.example": "NXDOMAIN" },
  "tcp": {
    "192.0.2.10:443": { "serve": "tls-private-ca" },
    "192.0.2.11:443": "refused",
    "192.0.2.12:443": "blackhole",
    "192.0.2.13:443": "reset"
  }
}
```

`serve` names a server factory the test registers. `blackhole` is scripted: a future that never
completes. Under paused time the wait costs nothing.

### `env.json`

The environment variables the process under test sees, as one JSON object of strings.

### `golden/`

`report.json`, `report.html` and `terminal.txt` from the in-process run. HTML goldens exist for `all-pass`,
`warnings-only` and `all-block` only. A golden is the exact bytes the product writes. It changes only with
`UPDATE_GOLDENS=1`, and the diff is read before the code diff.

## Line endings

A default Windows checkout rewrites line endings. That breaks a signed spec, because the signature covers
the raw bytes. `.gitattributes` marks everything under `tests/fixtures/` as `-text`, so git never converts
a byte. A fixture that must carry CRLF keeps it on every OS, and any other fixture cannot gain it.

- New fixture files are LF. Put a file with CRLF in the manifest's `crlf` list.
- `canary/netstat-crlf.txt` is the one fixture that carries CRLF on purpose. It stands for recorded Windows
  console output.
- The `windows-x64` CI leg sets `core.autocrlf true` before checkout. The test
  `crates/rdy-spec/tests/fixture_canary.rs` then checks that `git check-attr text` says `unset` for the
  fixtures, and that `canary/netstat-crlf.txt` matches a digest committed in the test. The `signed/*` bytes
  are not pinned, because they are regenerated with a fresh key when the example spec changes.
- A red canary on Windows means `.gitattributes` or the checkout is wrong. Do not change the digests to
  make it green.
- The lint (M1-050) rejects a `\r` outside `crlf` in `tests/fixtures` and `examples/specs`. It must add an
  allow entry for `canary/netstat-crlf.txt` with a reason.

## Names and sizes

The lint (M1-050) fails on:

- a file name unique only by case, a Windows reserved name (`con`, `nul`, `aux`, `com1`), a trailing dot or
  space, one of `<>:"|?*[]`, a path over 150 characters, a symlink;
- a file over 256 KiB, an env over 1 MiB;
- a bad manifest, a missing `origin`, an `origin` outside the four;
- a URL host or FQDN outside the allowed names above, and any publicly routable IP address;
- a registered check without its cases, and a missing `checks/_policy/symlink-to-shadow`.

## Recording (M2)

Recording is a dev-only command in `xtask`, never in the `rdy` binary. It scrubs in memory, runs the lint
and deletes its output if the lint fails. Until it lands, write `hand` fixtures. See Appendix A of the
testing plan.
