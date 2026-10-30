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
  checks/_loader/<case>/         loader cases, for example manifest-entries
  checks/_kube/<case>/           clusters for the kube mock harness (api/ only), for example cluster and denied
  checks/_cgroup/<case>/         cgroup trees for the shared cgroup helper (v2, v1, hybrid)
  envs/<env>/                    one whole environment plus a spec to run against it
  redaction/<category>/<case>.{in,expected,toml}
  results/<rdy-version>/*.json   result files from released versions, append only
  reports/*.json                 sample reports that engine tests put their own action log into
  specs/{valid,malformed}/       parser corpus
  signed/                        one signed spec, its .minisig and public key, never edited
  minisign-c/                    a key and a signature made by the C minisign tool, never edited
  wycheproof/                    ed25519 test vectors for the signature verifier
  canary/                        files that guard line endings on Windows
```

What exists today: `allow.toml`, `signed/`, `minisign-c/`, `wycheproof/`, `canary/`, `reports/`, `specs/` (`invalid/`,
`malformed/`), and under `checks/` the cases `host.memory/pass`, `host.firewall/` (18 cases), the twelve machines of
`host.os/`, `host.security_agents/` (18 cases), `_policy/symlink-to-shadow`, `_loader/manifest-entries`, the `_cgroup`
cases and the `_kube` cases (`cluster`, `denied`). The rest
arrives with the tickets that need it. The names above are fixed now so nobody invents another.

| Path | What it is | Who edits it |
| --- | --- | --- |
| `allow.toml` | Lint exceptions: the CRLF canary, a reference link in the third-party vectors, the four-part WSL kernel version. The metadata address `169.254.169.254` gets its entry with the first test that uses it. The format is in the file header | By hand, with a reason per entry |
| `checks/<check-id>/<case>/` | A small environment for one check. Each registered check needs a passing case, a non-passing case, a no-privilege `partial` case where a root-optional need exists, and a `Timeout` case where it runs a command or opens a socket | By hand, with the check ticket |
| `checks/_policy/<case>/` | Engine policy cases. `symlink-to-shadow` is required and expects `Denied`. The expectation of a policy or loader case lives in its Rust test until the fixture lint has a format for it | By hand |
| `checks/_cgroup/<case>/` | Machines for the cgroup helper that `host.memory`, `host.cpu` and `host.cgroups` share: `/proc/self/cgroup`, `/proc/self/mountinfo` and a `/sys/fs/cgroup` tree. Cases: `v2-nested`, `v2-unlimited`, `v2-memory-off`, `v1-tree`, `v1-unlimited`, `hybrid`. A check's own cases carry their own trees | By hand |
| `checks/_kube/<case>/` | Synthetic clusters for the kube mock harness: `cluster` (paged nodes, a stale token, a pod selector, legacy discovery, an identity review, a review table) and `denied` (401 and 403). The k8s check tickets add their own cases under `checks/<check-id>/` and reuse the harness | By hand |
| `checks/_loader/<case>/` | Cases that exercise the loader and the replay, such as every kind of manifest entry. Their expectation is in the Rust test too | By hand |
| `envs/<env>/` | A whole environment and the spec the env test runs against it. Five in M1: `all-pass`, `warnings-only`, `all-block`, `no-privileges`, `timeouts` | By hand, goldens by `UPDATE_GOLDENS=1` |
| `redaction/<category>/<case>.in`, `.expected`, `.toml` | Input, expected output and the rule setup for a redaction case | By hand only. `UPDATE_GOLDENS` never touches it |
| `results/<rdy-version>/*.json` | Result files written by released versions. They must stay parseable | Append only. Never edited |
| `reports/*.json` | A valid sample report (`not-ready-7.2.json` is the 01 section 7.2 sample). A test replaces its `actions` and checks the result against the schema | By hand, when the sample in 01 changes |
| `specs/valid/`, `specs/malformed/` | Parser corpus. Each malformed file is one way a spec can be wrong | By hand |
| `signed/` | One signed spec. See `signed/README.md` | Never. New cases get new files |
| `minisign-c/` | A key with a published test password and a signature, both made by C minisign 0.11. See `minisign-c/README.md` | Never |
| `wycheproof/` | Test vectors for ed25519. See `wycheproof/README.md` | Never |
| `canary/` | Files that must reach every OS byte for byte. See "Line endings" below | Never |

A check case and an environment use the same format. A case is a small environment. One loader reads both:
`rdy_engine::testing::Fixture::load(fixtures_root, "checks/host.memory/pass")`. A test then builds a run with
`TestRun::for_fixture(&fixture)`. To run a whole check against a case, call
`rdy_engine::testing::run_fixture(&check, "checks/host.memory/pass").await`. It loads the case, calls
`ensure_answers` for the check (a case that does not list the check fails with the check named, before
the check runs), binds the probe to the check's `CheckInfo` and returns the outcome and the action log.
`FixtureRun::assert_within_manifest()` then fails if the check tried a read, command, variable or peer
that its `CheckInfo` does not declare, even when the check swallowed the refusal. That includes a
read that the deny list (`/etc/shadow`, `~/.ssh`, `/dev`), the relative path rule or the `..` rule refused
first: if no declared `reads` prefix covers the path, it counts. `run_fixture` has no timer, so a check
that hangs outside the probe hangs the test. The loader is behind the `testing` feature of `rdy-engine`, which a release
build never turns on.

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
  golden/            report.json, report.html, terminal.txt
  expect.json        (check cases) the reviewed expected result
```

The file tree is the machine: a path it does not hold is not found, as on a machine without that file, so a
check that expects a missing file can be tested. A command, a native call, an API request or an address
that is not recorded fails the test with `NotRecorded`. A fixture never falls through to the real machine.

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

- `base` is the only reuse feature. It names one environment under `envs/` (`base = "all-pass"` is
  `envs/all-pass`). Child files replace base files by path. `remove` deletes some: a file, or a directory
  and everything under it. A `remove` that names nothing in the base is an error. One level, no other
  options. The merged files are indexed after the merge, so a child command file with a new name but the
  same argv as a base file is a duplicate, not a replacement. Give it the base file's name to replace it.
  The base must have the same `os` and `arch`. A child `root.manifest.json` replaces the base's whole
  manifest (replace by path): the base's links, `dirs`, `unreadable` and `modes` are gone unless the child
  repeats them. Removing a file that the base manifest still names fails, because the manifest then names
  something that is not in the tree.
- `answers` lists the check ids the env can answer. `Fixture::ensure_answers` says "this fixture does not
  answer host.memory" instead of a confusing `NotRecorded`.
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

`unreadable` simulates a no-privilege run: a read fails with permission denied and `stat` of the path
still works. On a directory it hides everything below it: a read or `stat` of a path under it is denied,
as on a machine where the user may not search the directory.
Replay follows the symlinks when it applies the deny list, so a link to `/etc/shadow` is `Denied` (that is
`checks/_policy/symlink-to-shadow`). A relative target is read from the directory of the link. A target that
is not a path (`socket:[8841]`, what `/proc/<pid>/fd` shows) makes a special file that is neither a regular
file nor a directory. `modes` are kept for the check that needs them; no facade call reports a mode yet.
Every path in `unreadable` and `modes` must be in the tree. The paths of `symlinks` and `dirs` create
entries.

### `commands/*.json`

Any slug for the file name. One command per file:

```json
{ "argv": ["/usr/bin/chronyc", "-n", "-c", "tracking"], "stdout": "...", "stderr": "", "exit": 0, "delay_ms": 0 }
```

The key is the normalised resolved `argv`. `argv[0]` is the absolute path the program lives at, and it
stays in the key. Replay finds a recording as the live runner finds a program: it tries `/usr/sbin`,
`/usr/bin`, `/sbin` and `/bin`, then the directories the check declared, and uses the first one that
holds the program. A recording in any other directory (`/opt/x/chronyc`) answers nothing, and the
`NotRecorded` error names the recorded path and says the runner does not search that directory. On a Windows
fixture only `whoami.exe` in `C:\Windows\System32` runs, and names compare without case.

A machine that lacks a tool is recorded as `{ "argv": ["chronyc"], "missing": true }`: the bare program
name and nothing else in the file. A call to it fails with the error the live runner gives for a program
that is not on the search path. The same program cannot also be recorded as installed in one fixture.

`exit` may be `null` for a command a signal ended. Binary output uses `stdout_b64`
(standard base64 with padding); `stdout` and `stdout_b64` are exclusive. Stdout and stderr are cut at the
same caps as a live run, with the truncation flags set. A duplicate key fails the load and the lint.
A `delay_ms` is a timer on the tokio clock. A delay that reaches the command's time limit gives a
`Timeout` after the limit, without real waiting. An argv the fixture does not hold fails with
`NotRecorded`.

### `api/*.json`

Any slug for the file name. One request per file:

```json
{ "request": { "method": "GET", "path": "/version", "query": "" }, "status": 200, "body": {}, "delay_ms": 0 }
```

Paged lists have one file per `continue` token. The key is the upper-cased method, the path and the query
text; `query` may be left out. A duplicate key fails the load. Access reviews are answered from
`api/reviews.json`. The loader holds the responses (`Replay::api`, `Replay::api_records`); the mock that
serves them is `client/mock.rs` in `rdy-checks-k8s` (M1-105, test code only).

How the mock reads a fixture:

- **A request is found by its method, its path and its decoded query pairs, sorted.** Write the query in
  plain text and in any order: `limit=500&fieldSelector=status.phase!=Failed,status.phase!=Succeeded`
  matches the `%21%3D` form kube sends. Two files that are the same request after decoding fail the build
  of the mock. A list with another selector is another request, so it needs its own file.
- **Paging.** The first page has the query `limit=500`. Its body names the next token in
  `metadata.continue`, and the next file has the query `limit=500&continue=<token>`. A file that records
  status `410` answers it every time. A test that wants a token to expire only once calls
  `Mock::expire_once(token)`: the first request with that token gets `410 Gone`, the next finds the file.
- **Discovery** (`/version`, `/api`, `/apis`, `/apis/<group>/<version>`) is the legacy document, one file
  each. A group the cluster does not serve is a file with status `404`. A request whose `Accept` selects
  the aggregated discovery document gets `406`, because that document is not recorded.
- **Any other POST**, such as the `SelfSubjectReview`, is a plain recorded request (`"method": "POST"`, no
  query). The body of the request is not part of the key; the guard has already checked it.
- **A request the fixture does not hold** gets `501` and fails the run. A fixture never falls through to a
  default.

`api/reviews.json` answers `SelfSubjectAccessReview` and holds one list:

```json
{ "access": [
  { "spec": { "resourceAttributes": { "verb": "create", "resource": "namespaces" } },
    "status": { "allowed": true, "reason": "RBAC: allowed by ClusterRoleBinding \"acme-installer\"" } },
  { "spec": { "nonResourceAttributes": { "path": "/healthz", "verb": "get" } },
    "status": { "allowed": false, "denied": true, "reason": "denied by a webhook" } }
] }
```

A row matches when its `spec` equals the posted `spec`, ignoring empty strings and nulls (so a row may
leave out `name` and `subresource`). The row's `status` is the answer, and the mock echoes the posted
`spec`. `status` needs a boolean `allowed`; `reason`, `denied` and `evaluationError` are optional. Two rows
with the same `spec`, an unknown key or a missing `spec` fail the build of the mock. Attributes with no
row get `501` and fail the run.

**The audit (INV-14).** The harness records every request that reaches the mock and checks the run when it
is dropped. Each recorded request must pass the guard's own rules and name an `ALLOWED` entry (or be
`/version`, discovery or a review). Each sent action-log entry that names an `ALLOWED` entry must be
logged under a check id that the entry cites in `checks`. The log must hold one sent entry per recorded
request, and the fixture must have answered all of them. A failing audit panics the test and says which
request broke which rule. See the module docs of `client/mock.rs`.

### `native/*.json`

One JSON file per native call that has no portable text form: `statvfs`, `uname`, `adjtimex`, sysinfo
results, Windows registry and service data. Keyed by the call's arguments, for example by path. The calls
the facade has today are `statvfs`, `uname`, `rlimit`, `hostname`, `machine_id` and `system_roots`:

```json
{ "call": "statvfs", "path": "/var/lib/acme", "delay_ms": 0,
  "value": { "fragment_size": 4096, "blocks": 1000, "blocks_free": 500, "blocks_available": 400,
             "files": 0, "files_free": 0, "read_only": false, "no_exec": true, "no_suid": false } }
{ "call": "uname", "value": { "sysname": "Linux", "release": "5.14.0-362.el9.x86_64", "version": "#1 SMP", "machine": "x86_64" } }
{ "call": "rlimit", "resource": "nofile", "value": { "soft": 1024, "hard": null } }
{ "call": "hostname", "value": "host-01.acme.example" }
{ "call": "machine_id", "value": "0123456789abcdef0123456789abcdef" }
{ "call": "system_roots", "error": "unsupported" }
```

Every field of a `statvfs`, `uname` or `rlimit` value is required, so a missing one cannot pass as zero.
`no_exec` is `null` where the OS does not report it, and a `null` limit is unlimited. Use `error`
(`unsupported`, `permission_denied`, `not_found` or `io`) instead of `value` for a call that fails.
`system_roots` values are base64 DER certificates. `delay_ms` waits on the tokio clock, so a hung
`statvfs` is a large delay that the check's timeout ends. A call the fixture does not hold fails with
`NotRecorded`.

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

`serve` names a server factory the test registers. `blackhole` is scripted: `Replay::dial` returns a
future that never completes, with no timer and no thread. Under paused time the wait costs nothing. A
lookup may answer with a link-local or metadata address, as recorded. The address rule that refuses it is
the facade's (M1-094), and every net fixture can hold such an answer so the rule runs against it. Keys of
`tcp` are an IP address and a port, with IPv6 in brackets. A host name compares without case. An address
the file does not hold fails with `NotRecorded`.

The `dns` answers are the one table that `Backend::resolve` reads, so a facade lookup gets exactly what
the file holds. `NXDOMAIN` is "not found". A name the file does not hold fails with `NotRecorded`.

### `env.json`

The environment variables the process under test sees, as one JSON object of strings.

### The loader is strict

`Fixture::load` fails, naming the file, on an unknown file or directory at the top of a fixture, an unknown
key anywhere, a bad manifest, a symlink in the tree, a name in `root/` with `\`, `:`, `[` or `]`, a file over
4 MiB, and a duplicate command, native call or API request. `golden/`, `expect.json`, the spec file,
and `README.md` are left to the harness and the docs. The needs a fixture offers come from the `[caps]`
table of the manifest; a `caps.json` is refused with that hint. A key that repeats, in JSON or once
normalised (host names that differ in case, `[::1]` written two ways, two paths that are one on a Windows
fixture), fails the load and names both. A manifest link at `proc/self` is refused for now: the pid of the
test runner would decide what the read policy admits. A directory that is empty on disk is not read, because
the repository cannot store it: list it in `dirs`. The size and name rules of the lint (M1-050) are
stricter than the loader's on purpose.

### Golden files with placeholders

A value that changes between runs (a generated certificate serial or digest) is written `<serial>` or
`<sha256>` in the golden. `rdy_engine::testing::matches_placeholders(expected, actual)` compares them.
`<sha256>` is 64 lower case hex digits. `<serial>` is 2 to 64 hex digits and takes the longest run, so
the text after it must not start with a hex digit. Everything else must match byte for byte.

### `golden/`

`report.json`, `report.html` and `terminal.txt` from the in-process run. HTML goldens exist for `all-pass`,
`warnings-only` and `all-block` only. A golden is the exact bytes the product writes. It changes only with
`UPDATE_GOLDENS=1`, and the diff is read before the code diff.

### Comparing and updating goldens

A test compares output with a golden through one helper, `rdy_engine::testing::golden::assert_golden(path,
bytes)`. It compares bytes and does no scrubbing: hand it output that is already deterministic.

| Situation | What happens |
| --- | --- |
| Same bytes | Pass. A stale `<path>.actual` is deleted |
| Different bytes | Fail. The message has the first 40 lines of a unified diff and the accept command. The new bytes are in `<path>.actual`, which the repo ignores |
| No golden | Fail the same way. The golden is not created |
| `UPDATE_GOLDENS=1` | Write the golden (and its folders), print `golden written: <path>` for each file, pass |
| `UPDATE_GOLDENS=1` and `CI` set | Fail at once, even when the golden matches. An empty `CI` does not count |
| `UPDATE_GOLDENS` is anything but `1`, `0` or empty | Fail, so a typo never passes |
| A path under `tests/fixtures/redaction` or `tests/fixtures/results` | `UPDATE_GOLDENS` never writes there, even through a symlink. The compare still runs. Edit the file by hand |

The accept command is `UPDATE_GOLDENS=1 cargo nextest run -p <package>`. Read the diff of `tests/` and
`crates/` before you commit. The PR body has a `## Golden changes` section, one sentence per changed file.

Every path given to the helper is appended to `target/goldens-used/<pid>.txt` (below `CARGO_TARGET_DIR`
when it is set), as repo-relative text with `/` separators. `cargo xtask goldens check` lists the golden
files on disk and fails on each one that no record names. A golden file on disk is:

- `envs/<env>/golden/<file>`;
- `checks/<check-id>/<case>/expect.json`;
- `redaction/<category>/<case>.expected`.

Anything else is an input, or data that a check reads, such as a fake file tree. So the redaction corpus
must compare `.expected` through `assert_golden`. The helper never writes there, so the compare is all it
does.

Run `rm -rf target/goldens-used` before the test run, and `cargo xtask goldens check` after
`cargo nextest run --workspace`. A record left by an older run can hide an orphan. A run of one package
makes every other package's goldens look orphaned. CI does both on linux-x64.

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
- The lint rejects a `\r` outside `crlf` in `tests/fixtures` and `examples/specs`. `allow.toml` holds the one
  entry for `canary/netstat-crlf.txt`, with its reason.

## The lint

`crates/rdy-engine/tests/fixture_lint.rs` is a normal test, so every leg runs it with `cargo nextest run`.
Each finding names the file. It covers `tests/fixtures`, and `examples/specs` for line endings, host names
and addresses. It fails on:

- a file name unique only by case, a Windows reserved name (`con`, `nul`, `aux`, `prn`, `conin$`, `conout$`,
  `com0` to `com9`, `lpt0` to `lpt9`), a trailing dot or space, one of `<>:"|?*[]\`, a path over 150 characters, a symlink;
- a file over 256 KiB, a fixture directory over 1 MiB;
- a `\r` that the fixture's `crlf` list and `allow.toml` do not allow;
- a URL host or a dotted name that is not `.example`, `.test`, `.invalid`, `.local`, an RFC 2606 example
  domain or a vendor on the built-in list (OS vendors, `k8s.io`, `kubernetes.io`, `openshift.io`,
  `nvidia.com`, the clouds, `github.com`), unless `allow.toml` allows it. On the big cloud domains
  (`amazonaws.com`, `azure.com`, `googleapis.com`) only the bare name, `<service>.<domain>` and
  `<service>.<region>.<domain>` pass, so `acme-backups.s3.amazonaws.com` and
  `ec2-54-1-2-3.compute-1.amazonaws.com` fail. Outside URLs only names whose last label is a real top-level
  domain are checked. The list is every country code and the common generic labels, taken from the IANA root zone list and
  checked in at `crates/rdy-engine/tests/data/iana-tlds.txt`. Brand TLDs are left out on purpose, because they
  name companies and products. The list leaves out the labels that are also file extensions (`sh`, `py`,
  `rs`, `md`, `so`, `in`, `link` and a few more), so `cpu.max` and `install.sh` pass. A URL host is
  checked with any label. `README.md` files are not scanned, except inside `checks/` and `envs/`;
- an IP address that is publicly routable or link-local, unless `allow.toml` allows it. Allowed without an
  entry: the documentation ranges, RFC 1918, `100.64.0.0/10`, `fd00::/8`, loopback, unspecified, multicast
  and reserved (`240.0.0.0/4`, which holds netmasks). An IPv4-mapped address counts as its IPv4 address;
- a bad manifest, a missing `origin` or one outside the four, a duplicate argv, native call or API request,
  and every other refusal of `Fixture::load`. The lint calls the loader. It has no second parser. The
  `host.firewall` cases name a sibling `base` that the loader cannot find yet. The `LOADER_PENDING` row in
  the lint excuses that one error and nothing else; M1-117 moves the bases to `envs/` and removes the row;
- a case or environment directory without a `fixture.toml`. A `checks/_<name>/` helper directory (`_policy`,
  `_loader`, `_cgroup`) is checked like any other, so a new one needs no change to the lint;
- a missing required case. The list is `REQUIRED` in the lint: `checks/_policy/symlink-to-shadow` (its
  `root.manifest.json` must link to `/etc/shadow`) and `checks/host.memory/pass`. A ticket that adds a case
  the lint should guard, such as the `Timeout` case of `host.disk` in M1-068, adds a row. The rule "every registered check has its cases" is not in this lint,
  because `rdy-engine` cannot link the check families. M1-075 (the in-process env harness) owns it.

An entry in `allow.toml` that matches nothing is a finding too, so the list cannot go stale. The tests of
the lint plant one violation at a time in an in-memory copy of this tree and expect exactly that finding.

## Recording (M2)

Recording is a dev-only command in `xtask`, never in the `rdy` binary. It scrubs in memory, runs the lint
and deletes its output if the lint fails. Until it lands, write `hand` fixtures. See Appendix A of the
testing plan.
