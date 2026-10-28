# 08 Testing

Owner: qa-engineer. Status: draft, waiting for review by rust-architect (the fixture backend switch, the
`Probe` path type) and code-reviewer (golden review rule, definition of done). Date: 2026-10-28.

This note says how the suite catches regressions without a GPU node, an air-gapped site or a Windows host
with a particular agent. It builds on 02-engine-design.md (the `Backend` trait with `Live` and `Replay`,
and its testing seams), 03-check-catalog.md (one fixture list per check), 05-threat-model.md (the
invariants and the redaction corpus), 06-release-and-distribution.md (the five CI legs) and ADRs 0001,
0003, 0004, 0007, 0008 and 0012.

## Rules in one screen

1. Every side effect goes through `Probe`, so a fixture can answer every question a check asks. A check
   never learns whether it runs on a real machine.
2. Every fixture is synthetic. No real hostname, address, user, serial, account id or secret is ever
   committed. A lint enforces it.
3. Fixtures are data, not OS-specific code. A Linux environment replays on a Windows runner. Only the
   thin native closures (`statvfs`, the Windows registry) are behind `cfg`.
4. A golden is the exact bytes the product writes. Goldens are normalised, not hand-edited. They change
   only with `UPDATE_GOLDENS=1`, and a golden diff is read before the code diff.
5. Tests are deterministic. No sleeps for synchronisation, no wall-clock lower bounds, no real network
   except loopback on ephemeral ports.
6. A flaky test is a bug owned by qa-engineer. Quarantine is not allowed: fix it or delete it.
7. The PR that changes a check also changes its fixtures, its goldens and the compatibility matrix.

## 1. The test pyramid

| Layer | Where it lives | What it proves | Runs on |
| --- | --- | --- | --- |
| Unit | `#[cfg(test)]` in each crate | Pure functions: threshold helpers, quantity and version parsing, `/proc` and `os-release` parsers, verdict mapping, YAML limits | All five legs |
| Property | `proptest` in `rdy-spec`, `rdy-engine` | Parser never panics and keeps its limits, round trips hold, redactor and verdict invariants (section 4) | All five legs, 256 cases; 10,000 on linux-x64 |
| Check and engine | `rdy_engine::testing`: `run_fixture`, `FakeCheck`, the Replay backend | One check against one fixture case; scheduler, timeouts, panics, cancellation under paused time | All five legs |
| Loopback network | `crates/rdy-testkit` servers with the Live backend | Real sockets against a TLS server with a test CA, a CONNECT proxy, a closed port, a black hole | All five legs |
| Golden | plain files compared byte for byte | JSON and HTML reports, terminal text, plans per OS, redaction output | All five legs |
| Binary integration | `crates/rdy-cli/tests`, `assert_cmd` | The real `rdy` against fixture environments: exit codes 0, 1, 2, 64, 70, report files, signed spec flow | All five legs |
| Live CI jobs | `ci.yml` jobs | Kind cluster, `sudo` paths, no phone home under `unshare -n` and `strace` | linux-x64 only |
| Doc tests | `cargo test --doc` | Every public example in `rdy-spec` and `rdy-engine` compiles and runs; every `examples/specs/*.yaml` lints | linux-x64 |

Tooling: `cargo nextest` runs everything except doc tests, which it does not run. So CI also runs
`cargo test --doc --workspace --locked`. Nextest config lives in `.config/nextest.toml` with a `ci`
profile: `retries = 0`, `fail-fast = false`, `slow-timeout = { period = "30s", terminate-after = 4 }`, so a
hung test dies in two minutes and names itself. Tests find shared data through one helper,
`testing::fixtures_dir()`, which resolves `tests/fixtures` from `CARGO_MANIFEST_DIR`. The fixtures sit at
the repo root, outside every crate, so `cargo package` never ships them.

Not in the pyramid: mutation testing, browser matrices, load tests. `cargo-fuzz` is M2 (SEC-45).

## 2. Fixtures for environments CI cannot have

### The rule: every fixture is synthetic

"Synthetic" means no byte came from a customer or from a person. Each fixture manifest names its
`origin`, and only four are allowed:

| Origin | Meaning |
| --- | --- |
| `hand` | Written by us from a vendor doc or an RFC example |
| `generated` | Built at test time or by a script (`rcgen` certificate chains, SNTP packets, kubeconfigs) |
| `ci-runner` | Recorded on a GitHub-hosted runner, then scrubbed |
| `throwaway` | Recorded on a rented machine made for the purpose and destroyed after, then scrubbed |

A developer laptop is not an origin. A design partner's environment is never an origin: nothing recorded
there enters this public repo, scrubbed or not. If a partner hits a failure we cannot reproduce, we write a
`hand` fixture with the same shape and acme names.

### Layout

```text
tests/fixtures/
  README.md                      format, naming rules, how to record
  allow.toml                     lint exceptions, each with a one-line reason
  checks/<check-id>/<case>/      one check, one situation (03 lists the minimum cases)
  envs/<env>/                    one whole environment plus a spec to run against it
  redaction/<category>/<case>.{in,expected,toml}   (05, Appendix F)
  results/<rdy-version>/*.json   result files from released versions, append only (ADR 0007)
  specs/{valid,malformed}/       parser corpus
  signed/                        one signed spec, its .minisig and public key, never edited
```

A check case and an environment use the same format. A case is just a small environment. One loader reads
both.

```text
envs/net-corp-proxy/
  fixture.toml           the manifest
  spec.yaml              the spec the env-level tests run
  root/                  fake file tree; root/etc/os-release stands for /etc/os-release
  root.manifest.json     what a file system cannot hold: symlinks, unreadable files, modes, empty dirs
  commands/              recorded command output, one JSON file per argv
  native/                recorded results of native calls: statvfs, uname, registry keys
  api/                   recorded Kubernetes and cloud API responses, one JSON file per request
  net.json               scripted DNS and TCP behaviour per host:port
  env.json               environment variables the process sees
  golden/                report.json, report.html, terminal.txt
```

### The manifest

```toml
schema = 1
name = "net-corp-proxy"
summary = "Ubuntu VM behind an authenticating CONNECT proxy that re-signs TLS with a private CA"
origin = "hand"
os = "linux"                  # what Backend::os() reports: linux, macos, windows
arch = "x86_64"
base = "all-pass"             # optional, one level only
remove = ["root/etc/docker/daemon.json"]
answers = ["host.os", "net.egress", "net.proxy", "net.tls_intercept"]
spec = "spec.yaml"

[caps]                        # which needs are available (02, caps.json)
root = false
network = true
kube = false

[run]                         # honoured only by the fixture backend
clock = "2026-11-02T09:00:00Z"
run_id = "00000000-0000-4000-8000-000000000001"
jobs = 1
deadline_ms = 20000

[expect]
verdict = "not_ready"
exit_code = 2

[matrix]                      # feeds the compatibility matrix (section 7)
os_family = "ubuntu"
os_version = "22.04"
proxy = "connect-basic-tls-intercept"
```

- `base` is the only reuse feature. Files in the child replace files in the base path by path, and
  `remove` deletes some. It is one level deep and has no other options. Without it, ten environments would
  carry ten copies of `/proc/meminfo`.
- `answers` lists the check ids the environment can answer. The loader fails with "this fixture does not
  answer host.memory" instead of a confusing `NotRecorded` halfway through a run.
- Anything not recorded fails with `NotRecorded`, as in 02. A fixture never falls through to the real
  machine.

### File formats

- **Virtual paths are POSIX strings.** `root/proc/meminfo` answers a read of `/proc/meminfo` on every
  runner. Replay turns the requested `Path` into a POSIX string key before lookup. A
  Windows environment keys `C:\Windows\System32\NETSTAT.EXE` as `c:/windows/system32/netstat.exe`.
- **`root.manifest.json`** replaces what git and Windows cannot store:

```json
{
  "symlinks": { "proc/1234/fd/7": "socket:[8841]" },
  "unreadable": ["var/log/audit/audit.log"],
  "modes": { "etc/acme/license.key": "0640" },
  "dirs": ["var/lib/acme"]
}
```

  The loader builds these in memory. The fixture tree itself holds no symlinks, no special modes and no
  file name with `:`, `[` or `]`. `unreadable` is how a no-privilege run is simulated.
- **`commands/<slug>-<hash8>.json`**, where `hash8` is the first eight hex digits of SHA-256 over the argv
  joined by NUL bytes, and the slug is the argv in lowercase letters, digits and `-`, cut at 40 characters.

```json
{ "argv": ["/usr/bin/chronyc", "-n", "-c", "tracking"], "stdout": "...", "stderr": "", "exit": 0, "delay_ms": 0 }
```

  Binary output uses `stdout_b64`. A `delay_ms` beyond the check timeout gives `Timeout` without waiting.
- **`api/<slug>-<hash8>.json`**: `{ "request": {"method", "path", "query"}, "status", "body", "delay_ms" }`,
  hash over method, path and sorted query. Paged lists have one file per `continue` token. Access reviews
  are answered from `api/reviews.json`, a table of attributes to `allowed` and `reason`. The mock records
  every request, and the k8s tests assert that only the allowed ones arrived (ADR 0010, INV-14).
- **`net.json`**:

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

  `serve` connects a duplex stream to an in-process server from `rdy-testkit`. Certificate chains are
  built with `rcgen` at test time, so no key or certificate is committed. Their serials and digests are
  replaced by placeholders (`<serial>`, `<sha256>`) before comparison.
- Addresses are documentation ranges only: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  `2001:db8::/32`, plus loopback. Names end in `.example`. Tokens are the fixed string
  `REDACTED-TEST-TOKEN`, or built from parts at test time when a push-protection scanner would flag them.

### Windows checkouts and `.gitattributes`

Three things break on a default Windows checkout: `core.autocrlf` rewrites line endings, symlinks are not
created, and some names are illegal. The first one also breaks a signed spec, because the signature
covers the raw bytes.

```gitattributes
* text=auto eol=lf
/tests/fixtures/** -text
/examples/specs/** -text
*.minisig -text
/crates/*/templates/** text eol=lf
/crates/*/data/** text eol=lf
*.actual -diff
```

- `-text` under `tests/fixtures` means git never converts a byte. A fixture that must carry CRLF (recorded
  `NETSTAT.EXE` output) keeps it on every OS. A fixture that must not carry CRLF cannot gain it.
- Askama templates and shipped data files are `eol=lf`. Otherwise a Windows checkout compiles CRLF into the
  HTML and every golden fails on that leg only.
- `.editorconfig` sets `end_of_line = lf`. The lint (below) rejects a `\r` in any fixture file the
  manifest does not list under `crlf = [...]`, so an editor cannot add CRLF by accident.
- The windows-x64 leg runs `git config --global core.autocrlf true` before checkout. It is a permanent
  canary: a test hashes `tests/fixtures/signed/*` and one CRLF fixture against committed digests, and the
  signed spec must verify. The signed spec was signed once with a throwaway key. Only the public key and
  the `.minisig` are committed. The secret key was deleted. New cases get new files; nobody re-signs.
- Names: unique when lowercased, no Windows reserved names (`con`, `nul`, `aux`, `com1`), no trailing dot or
  space, none of `<>:"|?*[]`, and under 150 characters from the repo root.

### Recording a fixture from a real machine

Most M1 fixtures are written by hand. Recording exists so that macOS, Windows, k8s distro and GPU shapes
are real, not guessed. It is M2 and dev-only (02 agrees). It is a command in `xtask`, not in `rdy`: it
reads many files, and that code should not sit in a binary that runs as root on a customer box.

```text
cargo xtask fixture record --spec spec.yaml --origin ci-runner --out tests/fixtures/envs/macos-15-arm64
```

1. A `Recording` decorator (cargo feature `record` on `rdy-engine`, never in release) wraps the Live
   backend and runs the spec once. Raw responses stay in memory. Raw output is never written to disk, not
   even to a temp file.
2. **Scrub in memory**, before anything is written. First the `rdy_engine::redact` secret rules. Then an
   identity pass with one consistent mapping per recording: hostnames become `host-01.acme.example`, users
   `user-01`, addresses move into documentation ranges, MACs become `02:00:00:00:00:NN`, and UUIDs, serials,
   instance ids, account ids and ARNs become counters of the same shape. Public names not on
   `scrub-allow.toml` become acme names.
3. **Allow-lists for known formats.** Kubernetes JSON drops `managedFields`, `last-applied-configuration`
   and node `status.images`. NVIDIA XML keeps a tag allow-list and replaces UUID, serial, board id, bus id
   and process names. Process lists keep command names only. An unknown file type is refused unless
   `--include-unknown` is set.
4. The recorder writes to `<out>.tmp`, runs the fixture lint, and deletes the directory if the lint fails.
5. The real-to-fake mapping is never written anywhere. The recorder prints counts and the file list. The
   human reads `git diff` before commit, and code-reviewer reads it again.

For a remote host, build `xtask` as one static binary, copy it over, run it there, and carry back only the
scrubbed directory. For macOS and Windows, a manual workflow `record-fixtures.yml` runs the recorder on the
GitHub-hosted runners and uploads the scrubbed directory (M2). That gives real macOS and Windows output
without owning either machine. Kubernetes shapes can also come from `scripts/record-k8s-fixture.sh` (a
`kubectl get -o json` with a `jq` allow-list), then `cargo xtask fixture scrub`.

### The fixture lint

`cargo xtask fixture check` runs in `lint` and as a test on every leg. It fails on:

- a manifest that does not parse, a missing `origin`, an `origin` outside the four allowed;
- a file name that breaks the Windows rules, a symlink, a file over 256 KiB, an environment over 1 MiB,
  a `\r` not listed in the manifest, a missing `.gitattributes` line;
- any name not ending in `.example`, `.test`, `.invalid` or `localhost`, and any address outside the
  documentation and loopback ranges, unless `allow.toml` lists it with a reason (`169.254.169.254` for the
  metadata-address tests is the first entry);
- anything the M1 redactor would change. A fixture that contains a secret-shaped string must be under
  `tests/fixtures/redaction/`, where that is the point;
- for every check id in the registry: no `checks/<id>/` directory, or a directory without a passing case, a
  non-passing case and, where `CheckInfo` has a root-optional need, a no-privilege case with `partial`, and
  where the check runs a command or opens a socket, a `Timeout` case (03 lists the rest).

### M1 environments

Eleven environments. The first five are the ones the M1 exit test needs (exit codes 0, 1 and 2 on every
leg). The family ones cover one real-looking stack each. The last two prove the macOS and Windows stubs.

| Env | Origin | Story | Verdict, exit |
| --- | --- | --- | --- |
| `all-pass` | hand, generated | RHEL 9 VM, 32 GiB nominal showing 31.3 GiB, xfs, direct egress, vanilla three-node cluster | `ready`, 0 |
| `warnings-only` | based on `all-pass` | Swap on, port inside the ephemeral range, one proxy `NO_PROXY` gap, no default StorageClass | `ready_with_warnings`, 1 |
| `all-block` | based on `all-pass` | 8 GiB RAM, disk full, 6443 held, egress refused, TLS interception, cluster too old, RBAC denied, nodes NotReady | `not_ready`, 2 |
| `no-privileges` | based on `all-pass` | Not root, audit log and other users' fds unreadable, no kubeconfig: partial results and `MissingNeed` skips | `not_ready` (required checks not run), 2 |
| `timeouts` | based on `all-pass` | Commands with `delay_ms` past the limit, a black-hole endpoint, a slow `/version`, a hung `statvfs` | `not_ready`, 2, run ends inside `deadline_ms` |
| `host-ubuntu2204-container` | hand | Container with `memory.max` 8 GiB on a 64 GiB host, `cpu.max` quota, overlayfs, `noexec` tmpfs | per spec |
| `net-corp-proxy` | hand, generated | `HTTPS_PROXY` with a 407 Basic proxy, CONNECT ok, internal registry missing from `NO_PROXY`, no Docker drop-in, private-CA interception | `not_ready`, 2 |
| `net-airgapped` | hand | No default route, internal DNS only, public endpoints refused or black-holed, internal mirror reachable, runs `acme-airgap-host.yaml` | per spec |
| `k8s-openshift-restricted` | hand | `v1.xx.x+hash` version string, PSA `restricted` namespace, SCCs, no default StorageClass, CSI driver present | `ready_with_warnings`, 1 |
| `macos-15-arm64-stub` | hand (recorded in M2) | Host checks answer "no data source for this OS yet"; net and k8s run | per spec |
| `windows-2022-stub` | hand (recorded in M2) | Same, with CRLF command output and registry JSON for the proxy | per spec |

Cut order if hours run short: the two stubs (the per-OS plan golden in section 6 still covers them), then
`net-airgapped`, then `host-ubuntu2204-container`. The first five never move.

### How each hard case is covered

| Case CI cannot have | How it is covered | State shown in the matrix |
| --- | --- | --- |
| Air-gapped site | `net-airgapped`: `refused` and `blackhole` entries, DNS limited to internal names, the offline-first test (SEC-22) proving no connect leaves loopback | `ci` |
| GPU node (M4) | `nvidia-smi -q -x --dtd` captures from a rented T4 or L4, one A100 with MIG, and an HGX capture scrubbed by `xtask`. Every failure string and exit code is a command fixture. The runner asserts `nvidia-smi` is never called when the kernel module is absent (gpu-expert review) | `none` until a capture exists, then `ci` for the captured driver line, and `hand` for the first real node |
| Windows host with a specific agent | Registry and service JSON under `native/`, a `SecurityCenter2` result, a Defender preference dump. The catalog (`agents.toml`) has a unit test per entry | `ci`; `hand` only when we run on a real Windows box |
| Kubernetes distros | Per-distro directories under `checks/k8s.*/` and envs: `version.json`, `nodes.json`, `storageclasses.json`, `csidrivers.json`, `ingressclasses.json`, and a Namespace with the distro's PSA labels (k8s-expert S7). A live kind job covers the real API server | kind `ci` live, others `ci` by fixture |
| Proxy with TLS interception | `rcgen` chains served by `rdy-testkit` (public, private CA in a fake system store, unknown CA), a CONNECT proxy with modes `ok`, `403`, `407-basic`, `407-negotiate`. The probe test asserts zero application bytes are written | `ci` |

## 3. Golden tests

**What is golden.** Per environment: `report.json` (stdout of `rdy run --json`), `report.html`, and
`terminal.txt` (stderr with `NO_COLOR=1`, `TERM=dumb`, `COLUMNS=100`). Per check case: `expect.json`. Also
one plan golden per OS (section 6), and the redaction corpus. Goldens sit next to what they describe, so a
reviewer sees the input and the output in one diff. HTML goldens exist for `all-pass`, `warnings-only` and
`all-block` only, to keep review short.

**Compare.** One helper, `testing::golden::assert_golden(path, actual_bytes)`, about 60 lines. It compares
bytes. On a mismatch it writes `<path>.actual` (git-ignored), prints the first 40 lines of a unified diff
and the exact command to accept. No insta, no snapshot header: the file is the product's own output, and
`report.html` opens in a browser. Every path it touches is appended to `target/goldens-used/<pid>.txt`.

**Normalisation.** Determinism first, scrubbing second. The harness fixes the inputs, then `normalize`
handles what is left.

| Field | Treatment |
| --- | --- |
| `run.started_at`, `finished_at` | `Clock::Fixed` from the manifest, so no scrubbing |
| `run.id` | Fixed from the manifest |
| `run.duration_ms`, `started_ms`, `duration_ms`, action `at_ms` and `duration_ms` | Set to 0. `timeout_after_ms` stays: it is the configured limit |
| `producer.version`, `commit`, `target` | `<version>`, `<commit>`, `<target>`, so a release or a leg never changes a golden |
| `host.hostname`, `host_id` | Taken from the fixture. The lint proves they are synthetic. Not scrubbed |
| Action log order | Sorted by spec index of the check, then per-check order, then renumbered. Parallel arrival order is not part of the contract |
| Output directory in terminal text | `<out-dir>`, with `\` turned into `/` in the terminal golden only |
| Generated certificate serials and digests | `<serial>`, `<sha256>` |
| Environment | The harness sets `TZ=UTC`, `LC_ALL=C`, `NO_COLOR=1`, `HOME` to a temp dir, and clears the rest |

A second test runs each env at `jobs = 1` and `jobs = 8` and asserts equal normalised reports. That catches
order dependence the goldens would hide.

**Extra assertions on every JSON golden.** It validates against `result.v1.schema.json`. The HTML golden
gets the static checks from ADR 0003: the CSP meta is exactly as written, `lang` and `color-scheme` are
set, no `src` or `href` points off the file except the footer link with `rel="noopener noreferrer"`, no
`<link>`, no `@import`, no `url(`, and `|safe` appears in no template. A `</script><img onerror>` hostname
round-trips through the embedded JSON. A headless-browser no-network render is an M2 job, a change to the
ADR 0003 exit test (see corrections).

**Updating on purpose.**

```text
UPDATE_GOLDENS=1 cargo nextest run -p rdy --features fixture-backend   # rewrites goldens, lists each file
git diff tests/                                                        # read it
```

- `UPDATE_GOLDENS=1` is refused when `CI` is set, except in the `goldens-fresh` job below.
- It never touches `tests/fixtures/redaction/**` or `tests/fixtures/results/**`. A golden you can regenerate
  is not a security test. Redaction expectations are edited by hand, and result files from released
  versions are append only.
- Every update prints the changed files, so a typo in a path cannot bless a new file silently.

**Staleness checks in CI.**

1. The normal run on all five legs: a mismatch fails.
2. The `goldens-fresh` job (linux-x64): runs the suite with `UPDATE_GOLDENS=1`, then `git diff --exit-code
   tests/`. A diff means a golden was out of date or the output is not deterministic. Then `cargo xtask
   goldens check` compares `target/goldens-used` with the files on disk and fails on an orphan.
3. Goldens are OS independent by construction. There is no per-OS golden file, so no leg can hide a diff.
4. `cargo xtask fixture check` verifies every file under `tests/fixtures/results/<old version>/` is unchanged
   from `main`.

**Review rule.** A PR that changes a golden has a `## Golden changes` section in its body: one sentence
per changed file saying why, plus the output of `cargo xtask goldens summary` (changed files, counts of
changed JSON paths). A CI job fails the PR if goldens changed and the section is missing. It reads the body
through an environment variable, never through `${{ }}` inside `run:` (zizmor flags that). code-reviewer
reads the golden diff first, before the code. A golden-only PR, or a golden change the code change does not
explain, is rejected.

## 4. Property tests

`proptest`, with `PROPTEST_CASES` at 256 locally and on four legs, 10,000 on linux-x64 (the ADR 0001 exit
test), and 100,000 in the nightly job. Failures are saved to `proptest-regressions/` and committed, so a
shrunk case becomes a permanent unit test. PR runs use a fixed seed, so an unrelated PR never fails on a
fresh random draw. The nightly job uses a random seed, prints it, and files an issue instead of failing a
PR. (A fixed seed needs proptest 1.5 or newer; the ticket confirms the pinned version.)

**Spec parser** (`rdy_spec::parse_unverified` and `load`)

| Invariant | Generator |
| --- | --- |
| Never panics. Returns `Ok` or a `SpecError` with a non-empty `hint()`, and a line and column when the failure is in the YAML | Arbitrary bytes up to 4 KiB; YAML-shaped soup (`[`, `{`, `- `, `: `, `&a`, `*a`, `!!`, `<<`, NUL, BOM, CRLF, tabs, long unicode); mutations of every file in `examples/specs` (byte flip, truncate, duplicate a line) |
| Size limit: over 1 MiB is refused before parsing | Boundary cases (1 MiB, 1 MiB + 1), not random |
| Depth limit: depth 64 passes, 65 fails | Nested flow sequences and maps of generated depth |
| Anchors, aliases, merge keys, duplicate keys, a second document are each rejected with their own error | A valid generated spec with one poison step chosen by the strategy |
| Round trip: `Spec` to JSON (valid YAML 1.2) and back is equal; `parse(emit(parse(x))) == parse(x)` for the examples | Generated `Spec` values: slug `^[a-z0-9][a-z0-9-]{0,62}$`, known ids, quantities, severities |
| Version-like fields keep their text: `12.10` quoted stays `"12.10"`, unquoted is refused with a quote hint | Generated `\d{1,3}\.\d{1,3}(\.\d{1,3})?` |
| Verify before parse: any single-byte change to the signed spec fails with a `SignatureError` and the parser spy count stays 0 | The committed signed spec plus a random index and byte |
| The result type round trips: `Report` to JSON to `Report` is equal and validates against the schema | Generated reports from the result types |

**Redactor** (`rdy_engine::redact`)

| Invariant | Generator |
| --- | --- |
| Never panics on arbitrary UTF-8, nor on lossy-decoded bytes | Any string |
| Idempotent: `redact(redact(x)) == redact(x)` | Any string, and strings with planted secrets |
| A planted secret never survives, in its plain, JSON-escaped and URL-encoded forms, and the typed placeholder (`[REDACTED:aws_access_key_id]`) appears | Per-category secret generators (AWS key id, `rdy_st_` token, bearer, URL userinfo, PEM body, `password=`) embedded in random surrounding text, JSON strings, YAML and INI lines |
| Report level: after the engine's redaction pass, a canary planted in every free-text field is absent from the JSON and the HTML, and `redactions` equals the number planted | Walk the result schema and plant a canary in every string leaf that has no `enum` or `const`. A new field is covered the day it is added |

Not in M1: a property that random benign strings (git SHAs, UUIDs) pass unchanged. False positives are
counted, not gated, in M1 (05), and a known-failing asserted property would be a quarantined test by another
name. The curated negative cases in the corpus carry it until the rule set is stable in M2. Time is never
asserted in property tests: the `regex` crate has no backtracking, and a 1 MiB adversarial case runs under
the nextest slow-timeout.

**Verdict and exit code** (`rdy_spec::result::verdict`, the rule in 02)

First an exhaustive table test over severity (`warn`, `block`) times status (`pass`, `warn`, `block`,
`skipped` with each reason, `timeout`, `error`). Then properties over generated lists of results:

1. Order independent: any permutation gives the same verdict, counts and exit code.
2. Monotone: making one result worse, or adding a result, never improves the verdict.
3. A `severity: block` check that is skipped (other than not-applicable), timed out or errored gives
   `not_ready` and exit 2. This is the "a gate of 0 or 1 must never pass an unchecked environment" guard
   from ADR 0008.
4. Exit code is 0, 1 or 2, and 0 only when every result is `pass` or not-applicable and at least one passed.
5. Summary counts add up to `total`, and `required_not_run` equals the number of block-severity checks that
   did not run.
6. `verdict_reasons` match the statuses: `block_found` if and only if some check blocked.

The binary maps 64 and 70 as table tests, not properties (section 6, CLI exit codes).

## 5. Timeout and cancellation tests

| Level | How | Asserts |
| --- | --- | --- |
| Scheduler | `FakeCheck` with `Sleep(forever)`, `Block` (a `spawn_blocking` that never returns), `Panic`, under `#[tokio::test(start_paused = true)]` | `Timeout` with `timeout_after_ms` equal to the effective limit; the run returns without waiting for the stuck thread; `Panic` gives `Error` and the other checks still pass; no real time passes |
| Run deadline | `deadline` of 10 s, one check running, three unstarted | Running becomes `Timeout`, unstarted ones are not run, all counted as required or optional not run |
| Cancellation | Cancel the token while checks run | Report written with `run.complete = false`, unfinished checks are `error` with `error_kind = interrupted` (01, section 5.3), nothing left running (a drop guard counts live futures), verdict from the rule |
| Replay delays | `delay_ms` past the limit in a command or `net.json` `blackhole` | `Timeout` and an action log entry that says what was in flight |
| Process level, Unix | Live backend, a test check that runs the platform sleeper (`/usr/bin/sleep 600`), timeout 1 s | The run ends in under 4 s, the child and its process group are gone (checked by `kill -0` on a recorded pid), `rdy` exits within 2 s of the deadline |
| Binary, Unix | `rdy run` on the `timeouts` env, `SIGINT` after the first check starts | Exit within 3 s, report directory exists with `run.complete = false`, exit code by the verdict rule. A second `SIGINT` gives exit 70 and no report. `SIGTERM` behaves like the first `SIGINT` |

Rules that keep these stable:

- Engine tests use paused time, so they take microseconds and never flake on a slow runner. One case needs
  proof, not assumption: tokio must auto-advance the paused clock while a `spawn_blocking` thread is stuck.
  The harness test for `Fake::Block` proves it once. If it does not hold on the pinned tokio, that single
  test uses a real 50 ms timeout.
- The three real-time tests assert only upper bounds, with at least three times the expected time as margin.
  They never assert a lower bound or the order of unrelated events. Nextest's `slow-timeout` kills a test
  that hangs, so a regression fails in two minutes, not at the 25-minute job limit.
- Windows: the first-`SIGINT` binary test is `#[cfg(unix)]` because sending a console control event needs
  `unsafe`. On Windows the cancel path is covered at the engine level, and Ctrl-C on a real console is
  `hand` in the matrix. Grandchild kill on Windows waits for job objects (an M2 ticket in 02); until then
  the Windows process test asserts the direct child dies and the run ends.
- The Ctrl-C wording follows 02 (first Ctrl-C finishes with a partial report, second exits 70). cli-ux has
  not confirmed it. The test changes with 07, not the other way round.

## 6. Cross-platform

| Leg | Runner | Runs |
| --- | --- | --- |
| linux-x64 | `ubuntu-24.04`, musl | Everything, plus the Linux-only jobs: `root` (`sudo`, the `root_` tests), `nophonehome` (`sudo unshare -n` and `strace`, INV-11), `kind` (a live cluster), `goldens-fresh`, doc tests, 10,000-case properties. Nightly: coverage, flake hunt, 100,000-case properties |
| linux-arm64 | `ubuntu-24.04-arm`, musl | Unit, property (256), fixtures, goldens, binary integration |
| macos-arm64 | `macos-15` | Same, with the Unix process tests |
| macos-x64 | `macos-15-intel` | Same |
| windows-x64 | `windows-2022` | Same, with `core.autocrlf true`, minus Unix-only tests, plus Windows-only ones |

What is `cfg`-gated, and nothing else:

| Gate | Tests |
| --- | --- |
| `target_os = "linux"` | Live `statvfs` on a temp dir, live `/proc/self` smoke, `CapEff` parsing against the real file (the parsing itself is pure and ungated) |
| `unix` | Process-group kill, `SIGINT` and `SIGTERM` tests, output-dir modes 0700 and 0600, symlink-not-followed |
| `windows` | The `ping`-based sleeper, absolute `System32` resolution, live registry read compared in shape to the recorded JSON |
| none | Every parser and evaluator. Every Replay-driven fixture, for any recorded OS, on any runner |

The fourth row is the point. A `/proc/net/tcp` parser, a macOS `netstat` parser and a Windows `NETSTAT.EXE`
parser all run on all five legs, because their input comes through `Probe`. Only the closure passed to
`probe.native(..)` is `cfg`-gated. This tightens 02, which gates the whole gather function (see
corrections).

**How the macOS and Windows stubs are tested.**

1. **Plan goldens.** `Engine::plan(spec, os)` is pure. A test plans every example spec for each of
   `Linux`, `MacOs` and `Windows` on every runner and compares with `tests/fixtures/plans/<os>.txt`. The
   support table in `CheckInfo::os` is therefore checked on all legs, with no Mac or Windows machine
   needed. It shows `NotYet`, `NotApplicable`, `Partial` and `Full` per check.
2. **Stub environments.** `macos-15-arm64-stub` and `windows-2022-stub` run end to end on every leg. Host
   checks must be `skipped` with `skip_kind: unsupported_os` and the "no data source for this OS yet"
   text, counted as required checks not run when the spec says block, and net and k8s must run as normal.
   A spec that limits a check with `os:` gives `excluded`, which never counts.
3. **Per-family honesty test** (02): every check marked `Full` or `Partial` on an OS must not return
   `Unsupported` on that OS's fixture. It starts as an empty set and grows as data sources land.
4. **Real-OS smoke.** On each leg, the shipped build of `rdy` runs a tiny spec against the live runner and
   asserts only shape: the report validates against the schema, no check has `error_kind = panic`, host
   checks are non-skipped on Linux and skipped with the stub reason on macOS and Windows, and the exit code
   is 0, 1 or 2. This is the real-binary-on-every-OS test. It merges with release-engineer's M2
   `release-smoke` job.

**The fixture backend inside the real binary.** The integration tests run the real `rdy` (argument
parsing, exit codes, report writing) against an environment directory. That needs a Replay backend in the
binary. It is compiled only with cargo feature `fixture-backend` (which enables `rdy-engine/testing`) and
read only from `RDY_TEST_BACKEND_DIR`. Release builds never enable it. CI proves it three ways: `cargo
tree -p rdy -e features` on the release profile has no `testing`; `strings rdy | grep -c
RDY_TEST_BACKEND_DIR` is 0 on the release archive; the `fixture-backend` binary prints a banner on stderr.
The alternative, a separate test binary, cannot share the CLI code because `rdy` publishes no library
(ADR 0011). This needs an ADR because security-reviewer should see it.

**CLI exit codes.** Table tests through the real binary: 0, 1 and 2 on the three verdict envs; 64 for an
unknown flag, an unreadable spec, a parse error, an unsigned spec without `--allow-unsigned`, and a failing
signature even with the flag; 70 for an unwritable `--out-dir` (full terminal result still printed) and for
a setuid-like id mismatch injected through the fixture backend. `clap` exits 2 on a usage error by default,
which would read as "blockers". A test for `rdy --bogus` expecting 64 is the guard. `--json` failures print
the error object with the stable `code` from ADR 0008.

## 7. The compatibility matrix

`docs/compatibility.md` is the public page. It is generated, never edited. The source is
`tests/compat/matrix.toml`, rendered by `cargo xtask matrix` (the `docs-gen` job runs it with `--check`).

**Dimensions**, one table per group, not one giant cross product: OS family and version, architecture,
container runtime, Kubernetes distro and version, proxy type, network posture (direct, proxied,
air-gapped), GPU driver line.

**Three states.**

| State | Meaning | Evidence required |
| --- | --- | --- |
| `ci` | Verified in CI. By a fixture environment or case, or by a live runner leg (the evidence column says which) | The fixture env name, or the runner leg. The generator checks the env exists and its `[matrix]` values equal the row |
| `hand` | Verified by hand on a real environment | A record file `docs/compat/hand/<date>-<slug>.md`: rdy version, date, who, what the environment was, the command, redacted evidence. Shown as stale after 180 days |
| `none` | Unverified. We make no claim | Nothing. `none` is the default for every row |

A row looks like this:

```toml
[[row]]
group = "Kubernetes distro"
item = "OpenShift 4"
checks = ["k8s"]
state = "ci"
evidence = ["env:k8s-openshift-restricted"]

[[row]]
group = "Kubernetes distro"
item = "EKS"
version = "latest 3 minors"
checks = ["k8s"]
state = "hand"
rdy = "0.2.0"
verified_at = "2027-02-10"
record = "docs/compat/hand/2027-02-10-eks.md"
```

**Kept current.**

1. Every fixture env manifest has a `[matrix]` table. The generator fails if an env claims a dimension no row
   cites (an env nobody uses as evidence), or a row cites an env that does not exist or disagrees.
2. A PR that changes `crates/rdy-checks-*/src/**`, `tests/fixtures/**` or `CheckInfo::os` must also change
   `tests/compat/matrix.toml`, or its body must carry a line `Compat matrix: unchanged because <reason>`.
   A CI job checks the diff and the body (read through an environment variable). code-reviewer checks the
   reason is true.
3. Moving a row to `ci` needs the fixture. Moving it to `hand` needs the record file. Moving it down is
   always allowed and is the right call when a check changes and the evidence no longer applies.

**Day-one rows, the target for `0.1.0`.** Everything else is `none`.

| Group | Item | Checks | State | Evidence |
| --- | --- | --- | --- | --- |
| OS | Linux x86_64, Ubuntu 24.04 | host, net, k8s | `ci` | live runner linux-x64 |
| OS | Linux aarch64, Ubuntu 24.04 | host, net, k8s | `ci` | live runner linux-arm64 |
| OS | RHEL, Rocky, Alma 9 | host | `ci` | env `all-pass` |
| OS | Ubuntu 22.04 in a container | host | `ci` | env `host-ubuntu2204-container` |
| OS | RHEL, Rocky 8; Debian 12; Amazon Linux 2023; Alpine | host.os only | `ci` | `checks/host.os/*` cases |
| OS | macOS 15 arm64 and x86_64 | net, k8s (host is a stub) | `ci` | live runner legs, env `macos-15-arm64-stub` |
| OS | Windows Server 2022 x86_64 | net, k8s (host is a stub) | `ci` | live runner leg, env `windows-2022-stub` |
| OS | Windows 11, SLES 15, macOS 14 | all | `none` | |
| Container runtime | Docker, containerd, Podman, CRI-O | host.container_runtime (M1-late) | `none` | |
| Kubernetes | kind, newest upstream minor | k8s | `ci` | live `kind` job |
| Kubernetes | kubeadm vanilla, three newest minors | k8s | `ci` | env `all-pass` and per-version `version.json` cases |
| Kubernetes | OpenShift 4 | k8s | `ci` | env `k8s-openshift-restricted` |
| Kubernetes | EKS, GKE, AKS, RKE2, k3s | k8s | `none` | distro set is M2 |
| Proxy | Direct, none | net | `ci` | env `all-pass` |
| Proxy | CONNECT without auth; 407 Basic; 407 Negotiate (classified, not authenticated) | net | `ci` | loopback proxy modes, env `net-corp-proxy` |
| Proxy | TLS-intercepting with a private CA | net | `ci` | env `net-corp-proxy` |
| Proxy | PAC or WPAD | net | `none` | Not supported in v1. The check warns |
| Network | Air-gapped host | host, net | `ci` | env `net-airgapped` |
| GPU driver | 535, 550, 570 lines | gpu (M4) | `none` | Captures needed (see section 2) |

## 8. Coverage and flakes

**Coverage.** `cargo-llvm-cov` in a nightly job on linux-x64 (release-engineer owns the job, M2). It
uploads an lcov file and prints per-crate line coverage in the job summary. It is reported, not gated: no
threshold, no PR comment, no badge in M1. The founder looks at the per-crate table once a month and asks
for tests where a parser or a verdict path is uncovered. `xtask` and the `testing` modules are excluded.
The job runs on the glibc host target, so it measures our code, not the shipped musl binary. The number
that does gate is the fixture-completeness lint in section 2: every registered check has its cases.

**Flake policy.** A flake is a test that passes and fails on the same commit.

- The `ci` profile has `retries = 0`. A retry that turns red into green is how flakes hide.
- Every flake is a bug owned by qa-engineer, filed with label `flake` and the failing run link, fixed within
  five working days. If it is not fixed in five days, the test is deleted and a ticket is filed to rewrite
  it. **Quarantine is never allowed.** No `#[ignore]` as a parking place, no `continue-on-error`, no
  "known flaky" list.
- The one legal `#[ignore]` is `#[ignore = "runs in job: <name>"]` for a test another CI job runs with
  `--run-ignored only` (kind, root). A lint greps every `#[ignore` and fails unless the reason has that
  form and `<name>` is a job in `ci.yml`. Platform gating uses `cfg`, listed in section 6, never `ignore`.
- Root-only tests are named `root_*` and excluded from the normal profile by a nextest filter. In the `root`
  job they fail, not skip, if the process is not root.
- Test hygiene that prevents most flakes: bind loopback sockets on port 0 and read the port back; create
  every file under `tempfile`; no in-process environment changes (edition 2024 makes `set_var` unsafe, and
  `forbid(unsafe_code)` holds); set `TZ`, `LC_ALL`, `NO_COLOR` on child processes; no sleep to wait for a
  thing (wait on a channel, a port, or paused time); upper-bound timing only.
- A nightly flake hunt runs the suite repeatedly on all five legs (nextest stress mode, or a shell loop
  if the pinned nextest lacks it) and files issues itself.

## 9. Definition of done for a check ticket, test side

A check ticket is not done until the PR shows all of these. The PR template carries the list.

```text
[ ] CheckInfo complete: id, family, needs, os table, default timeout, manifest of reads/commands/env/peers.
    The registry test passes (ids unique, id matches its row in 03).
[ ] Evaluation is a pure function over plain fact structs. Unit tests hit each threshold boundary:
    exactly at min, one below, inside the nominal band, severity warn capping a block.
[ ] Parsers of external text have a "never panics on arbitrary bytes" property test (shared helper).
[ ] tests/fixtures/checks/<id>/ has the minimum cases: pass, each non-pass level, no-privilege (partial)
    if a root-optional need exists, Timeout if the source can hang, garbage input (empty, truncated,
    odd locale) giving Error or partial and never a panic. Each case has a reviewed expect.json.
[ ] assert_within_manifest passes for every case: the check read only what it declared.
[ ] Fix text: every placeholder is filled in expect.json (no stray braces), and the spec fix override case exists.
[ ] If the check records env, URLs or command output: a case with a planted canary shows it absent from JSON and HTML.
[ ] Every OS in CheckInfo::os is right. Plan goldens for all three OSes are updated. Stubs return the skip reason.
[ ] The check is used by at least one env spec. The env goldens are updated and the diff is explained in "## Golden changes".
[ ] Fixture lint passes (synthetic origin, addresses, names, sizes, Windows-safe names).
[ ] tests/compat/matrix.toml changed, or "Compat matrix: unchanged because ..." is in the PR body.
[ ] Green on all five legs, goldens-fresh green, no new #[ignore] outside the allowed form.
[ ] Ran once on a real machine if one is at hand. The command and redacted evidence are in the PR.
[ ] code-reviewer has read the golden diff first. security-reviewer has it if the check execs, opens sockets or reads sensitive paths.
```

## Plan corrections found

- docs/plan/03-check-catalog.md, Conventions, "Fixtures", and docs/plan/02-engine-design.md, "Testing seams":
  the layout `tests/fixtures/<check-id>/<case>/` leaves no room for whole environments, and the format has
  symlink trees, a mode-0600 file and `:[]` in names (the rust-engineer review, item 9). Fix:
  `tests/fixtures/checks/<check-id>/<case>/` beside `tests/fixtures/envs/<env>/`; add `fixture.toml`,
  `root.manifest.json`, `native/` and `net.json`; name command files by argv hash; keep Replay keys as POSIX
  strings (section 2).
- docs/plan/02-engine-design.md, "The probe facade": `Probe` takes `&Path`. On Windows that makes the
  fixture key depend on the runner. Fix: Replay normalises every requested path to a POSIX
  string before lookup, as the rust-engineer review asked.
- docs/plan/02-engine-design.md, "How checks degrade on each OS": the gather functions sit in
  `#[cfg(target_os)]` functions with stubs. Then a Linux fixture cannot exercise the Linux parser on a macOS
  leg. Fix: gate only the closures passed to `probe.native`; everything that reads through `Probe` is
  ungated and chooses its source from `Backend::os()` at run time (section 6).
- docs/plan/02-engine-design.md, "Testing seams", and docs/plan/00-overview.md, ticket "Golden tests for
  JSON and HTML reports": both say `insta`. This plan uses plain-file goldens and `UPDATE_GOLDENS=1`
  (section 3). Fix: drop `insta` from the dev-dependency table; rewrite that ticket's exit test (done in
  Tickets implied). See the ADR list.
- docs/plan/00-overview.md, same ticket, and CLAUDE.md "Cross-platform from day one": "all four CI targets".
  06 defines five legs (macOS has two). Fix: say "five CI legs".
- docs/plan/06-release-and-distribution.md, Appendix A `test` job: `cargo nextest run` does not run doc
  tests, and nothing sets `core.autocrlf` on the Windows leg. Fix: add `cargo test --doc --workspace
  --locked` (linux-x64), the `ci` nextest profile with `retries = 0`, and `git config --global
  core.autocrlf true` before checkout on windows-x64.
- docs/adr/0003-report-format-html-json.md, ticket "askama HTML report with inline CSS, dark mode and
  print" and 00-overview's same ticket: the exit test needs a headless browser in M1. Fix: M1 uses the static
  checks in section 3 (no off-file `src` or `href`, no `url(`, CSP exact). The browser render is an M2 job
  (ticket below).
- docs/adr/0007-crate-publishing-and-versioning.md, Tickets implied, "Keep golden result files per
  released version and parse them in CI" is `[M2]`; docs/plan/00-overview.md lists it as `[M1]`. Fix: M1.
  The week-2 to week-5 alphas already write result files, and the M2 portal must read what they wrote.
  Start the directory at `0.1.0-alpha.1`.
- docs/plan/rdy-plan.md "Example spec" and examples/specs/acme-airgap-host.yaml,
  examples/specs/acme-inference-gpu.yaml: they use `host.selinux` and `gpu.device_plugin`, but 03 names
  `host.lsm` and `k8s.device_plugins`. The examples lint test will report them as unknown ids. Fix: one
  name per check, decided in 01 and 03, then the examples follow.
- docs/plan/02-engine-design.md, "Scheduling, timeouts and cancellation": an interrupted run marks checks
  `Skipped(Cancelled)` and sets `Report::interrupted`. 01-spec-format.md, section 5.3, has no such flag:
  unfinished checks are `error` with `error_kind: interrupted` and `run.complete` is false. The `SkipReason`
  names in 02 also differ from the `skip_kind` codes in 01. Fix: 02 follows 01 (02 says 01 wins). The
  cancellation tests in section 5 are written to 01.
- docs/plan/08-testing.md depends on 01's ticket "Align example specs and check catalog with 01-spec-format
  names": `examples/specs/*.yaml` use `host.selinux` and `gpu.device_plugin`, but 03 names `host.lsm` and
  `k8s.device_plugins`. The examples lint test fails on them until that ticket lands.

## Decisions needing an ADR

Conservative choice first in each item.

- **A fixture backend inside the real binary.** Cargo feature `fixture-backend`, off in every release
  artifact, proven absent by a feature-tree check and a `strings` check, read only from `RDY_TEST_BACKEND_DIR`.
  Alternatives: no fixture-backed binary tests (only the live smoke, so no deterministic exit-code tests
  through the real CLI); a separate test binary (cannot share CLI code, since `rdy` has no library).
  security-reviewer should sign it.
- **Golden storage.** Plain files with a 60-line helper and `UPDATE_GOLDENS=1`. Alternative: `insta`, already
  in the dependency table, which gives `cargo insta review` but stores `.snap` files with a header and needs
  a separate path for redaction expectations that must never be regenerated. Switching later changes only
  the helper, about one hour.
- **`crates/rdy-testkit`.** A dev-only crate (`publish = false`, `dist = false`) holding the loopback
  servers (TLS with `rcgen`, CONNECT proxy, black hole), kept out of `rdy-engine` so its `testing` feature
  does not pull a server stack. Alternative: everything under `rdy_engine::testing`.
- **Where recording lives.** `cargo xtask fixture record`, not an `rdy` subcommand, so the shipped binary
  carries no bulk file-copy code. Alternative: a hidden `rdy fixture record`, simpler to run on a remote box
  (07 owns the command surface).

## Tickets implied

Tickets with a title that already appears in 00-overview.md, 02-engine-design.md or 05-threat-model.md keep
that title, so 11-backlog.md can dedupe. Where the scope here differs, the exit test is the new one. Total
qa-engineer load in M1 is about 58 hours: 15 reused and 43 new. That is a large share of an M1 that is
already over budget. Cut order, in this sequence: `Fixture envs macos-15-arm64-stub and windows-2022-stub`,
the net-airgapped half of `Fixture envs host-ubuntu2204-container and net-airgapped`,
`Property and fuzz tests for rdy_spec::parse` (keep five hand-written malformed specs), the matrix generator
(keep the hand-written table). Never cut the five exit-test environments, the fixture lint, or the Windows
canary.

- [M1] Fixture format README, fixture.toml schema and .gitattributes | owner: qa-engineer | est: 2h | depends on: Create workspace skeleton | exit test: `tests/fixtures/README.md` documents every file in section 2, `.gitattributes` has the lines above, and a doctest-style example manifest parses with the loader.
- [M1] Fixture lint: cargo xtask fixture check | owner: qa-engineer | est: 4h | depends on: Fixture format README, fixture.toml schema and .gitattributes; xtask skeleton with schema, docs, docs-lint and --check modes, dist and publish off | exit test: a planted `.com` hostname, a `\r` outside the manifest list, a file named `con.json`, a 2 MiB file, a public IP and an `origin = "laptop"` each fail with the file named, and a check id with no `checks/<id>/` directory fails.
- [M1] Windows checkout canary for CRLF and the signed spec | owner: qa-engineer | est: 2h | depends on: Fixture format README, fixture.toml schema and .gitattributes; CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: the windows-x64 leg checks out with `core.autocrlf true`, hashes `tests/fixtures/signed/*` and one CRLF fixture against committed digests, and verifies the signed spec with `minisign-verify`.
- [M1] Golden helper with UPDATE_GOLDENS and the goldens-fresh CI job | owner: qa-engineer | est: 3h | depends on: Engine test helpers FakeCheck, run_fixture and normalize; CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: a changed output fails with a diff and an `.actual` file, `UPDATE_GOLDENS=1` is refused when `CI` is set, an orphan golden fails `cargo xtask goldens check`, and `goldens-fresh` fails on a non-deterministic field.
- [M1] Engine test helpers FakeCheck, run_fixture and normalize | owner: qa-engineer | est: 2h | depends on: Replay backend and fixture loader | exit test: the scheduler tests use FakeCheck for every status, `assert_within_manifest` fails on a fixture check that reads an undeclared path, and `normalize` re-sorts the action log so two runs at `jobs = 1` and `jobs = 8` give equal reports.
- [M1] Golden tests for JSON and HTML reports | owner: qa-engineer | est: 2h | depends on: Embed result JSON in the HTML report safely; Golden helper with UPDATE_GOLDENS and the goldens-fresh CI job | exit test: `report.json` for ready, warning and not-ready envs validates against the result schema, `report.html` passes the static checks (CSP, no off-file src or href, `</script>` hostname round trip), and all pass on five legs.
- [M1] Test-only fixture backend switch in the rdy binary behind a cargo feature | owner: rust-engineer | est: 2h | depends on: Package rdy in crates/rdy-cli with binary name rdy; Replay backend and fixture loader | exit test: `cargo tree -p rdy -e features` on the release profile has no `testing`, `strings` on the release binary finds no `RDY_TEST_BACKEND_DIR`, and the feature build reads an env dir and prints a banner.
- [M1] Env-level harness: run the real rdy against a fixture env and compare goldens | owner: qa-engineer | est: 4h | depends on: Test-only fixture backend switch in the rdy binary behind a cargo feature; Golden helper with UPDATE_GOLDENS and the goldens-fresh CI job | exit test: one test per env checks exit code, `report.json`, `terminal.txt` and, where present, `report.html`, with `TZ`, `LC_ALL`, `NO_COLOR` and `HOME` pinned, and the `jobs = 1` and `jobs = 8` reports are equal.
- [M1] Fixture env all-pass | owner: qa-engineer | est: 3h | depends on: Env-level harness: run the real rdy against a fixture env and compare goldens; host.memory (meminfo, swap, cgroup limit, nominal band); net.egress core (DNS, TCP, TLS, HTTP, failure classes, injectable connector); k8s.version (gitVersion parse, distro, discovery API availability) | exit test: `rdy run` on the env exits 0 on all five legs with a golden JSON, HTML and terminal text, and 31.3 GiB against `min: 32Gi` passes with its note.
- [M1] Fixture envs warnings-only, all-block and no-privileges | owner: qa-engineer | est: 3h | depends on: Fixture env all-pass | exit test: exit codes 1, 2 and 2 with goldens, `no-privileges` shows `partial` results and `MissingNeed` skips, and the verdict reason is `required_check_not_run`.
- [M1] Fixture env timeouts | owner: qa-engineer | est: 2h | depends on: Fixture env all-pass; Scheduler with concurrency limit, per-check timeout and panic isolation | exit test: each hung source gives `Timeout` with the configured limit, the run ends inside `deadline_ms` under paused time, and the verdict is not_ready with required checks not run.
- [M1] Fixture envs host-ubuntu2204-container and net-airgapped | owner: qa-engineer | est: 3h | depends on: Fixture env all-pass; host.cpu (cores with cgroup quota, arch, flags, hypervisor); net.egress core (DNS, TCP, TLS, HTTP, failure classes, injectable connector) | exit test: the container env reports the 8 GiB cgroup limit against a 64 GiB host, and the air-gapped env runs `acme-airgap-host.yaml` with every public endpoint refused or black-holed and the mirror reachable.
- [M1] Fixture envs net-corp-proxy and k8s-openshift-restricted | owner: qa-engineer | est: 4h | depends on: Fixture env all-pass; net.proxy (Linux env and config files, daemon drop-ins, NO_PROXY coverage, reachability); net.tls_intercept (probe verifier, chain classification, trust store report); k8s.storageclass (default class, CSI driver, binding mode, provisioner table) | exit test: the proxy env shows the 407 Basic classification, the `NO_PROXY` gap and private-CA interception with no userinfo in any output, and the OpenShift env gives exit 1 with the missing default StorageClass.
- [M1] Fixture envs macos-15-arm64-stub and windows-2022-stub | owner: qa-engineer | est: 2h | depends on: Fixture env all-pass; OS support table and compile stubs for rdy-checks-host | exit test: on all five legs host checks are skipped with the "no data source for this OS yet" reason and net and k8s run, with CRLF command output intact on the Windows env.
- [M1] Scheduler timeout, deadline and cancellation tests under paused time | owner: qa-engineer | est: 3h | depends on: Family limits, run deadline and Ctrl-C cancellation | exit test: the table in section 5 (engine rows) passes, including the proof that a stuck `spawn_blocking` does not stop the paused clock, and no test uses a real sleep above 50 ms.
- [M1] Property and fuzz tests for rdy_spec::parse | owner: qa-engineer | est: 3h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: the invariants in section 4 hold over 10,000 cases on linux-x64 with a fixed seed on PRs, regressions are committed, and no input panics.
- [M1] SEC-26 M1 redaction corpus | owner: qa-engineer | est: 3h | depends on: SEC-25 Build minimal redactor for reports and evidence | exit test: 60 synthetic cases across the M1 categories pass with zero misses, secrets built from parts, and `UPDATE_GOLDENS=1` leaves `tests/fixtures/redaction/**` untouched.
- [M1] SEC-22 No-phone-home strace test on Linux CI | owner: qa-engineer | est: 2h | depends on: SEC-21 Egress address policy, no redirects, no bodies; Fixture env all-pass | exit test: under `sudo unshare -n` and `strace -f -e trace=connect,sendto,sendmsg`, every destination while running `all-pass` and `net-airgapped` is a loopback fixture address.
- [M1] musl resolver behaviour fixture for net.dns | owner: qa-engineer | est: 2h | depends on: Shared HTTP client builder with rustls ring and platform verifier | exit test: a fixture resolv.conf and nsswitch.conf with `sss` produce the documented warning.
- [M1] CLI exit-code tests through the real binary | owner: qa-engineer | est: 3h | depends on: Env-level harness: run the real rdy against a fixture env and compare goldens; Error types with fix hints and exit code mapping at the CLI edge | exit test: 0, 1, 2 from the verdict envs, 64 for an unknown flag (not clap's 2), an unreadable spec, an unsigned spec and a bad signature with `--allow-unsigned`, and 70 for an unwritable `--out-dir` with the full terminal result printed.
- [M1] Keep golden result files per released version and parse them in CI | owner: qa-engineer | est: 1h | depends on: Golden tests for JSON and HTML reports | exit test: `tests/fixtures/results/0.1.0-alpha.1/` parses with the current rdy-engine on every leg, and a modified file under an older version directory fails `cargo xtask fixture check`.
- [M1] Compatibility matrix source, generator and day-one rows | owner: qa-engineer | est: 3h | depends on: Fixture env all-pass; xtask skeleton with schema, docs, docs-lint and --check modes, dist and publish off | exit test: `cargo xtask matrix --check` fails on a row citing a missing env or a mismatched `[matrix]` value, and the generated `docs/compatibility.md` lists the day-one rows from section 7.
- [M1] Nextest ci profile, ignore lint and PR template with the check definition of done | owner: qa-engineer | est: 2h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: a test that fails once in three runs is not retried, a bare `#[ignore]` fails the lint, `cargo test --doc` runs on linux-x64, and the PR template lists the section 9 items.
- [M2] Compat-touched and golden-section PR checks | owner: qa-engineer | est: 2h | depends on: Compatibility matrix source, generator and day-one rows; Golden helper with UPDATE_GOLDENS and the goldens-fresh CI job | exit test: a PR that changes a check crate without touching `matrix.toml` or the body line fails, a golden change without `## Golden changes` fails, and both read the body through an environment variable.
- [M2] Per-OS plan goldens and stub honesty test | owner: qa-engineer | est: 2h | depends on: Family trait, registry and run plan | exit test: `plans/linux.txt`, `macos.txt` and `windows.txt` match on all five legs and the Full-or-Partial-must-not-be-Unsupported test runs for each OS.
- [M2] Verdict and exit-code property tests | owner: qa-engineer | est: 2h | depends on: Amend verdict mapping for required checks not run | exit test: the six properties in section 4 hold over 10,000 generated result lists.
- [M2] Redactor property tests and the schema-walk canary test | owner: qa-engineer | est: 3h | depends on: Apply the redactor to every Report string before return | exit test: idempotence and the planted-secret properties hold, and a new string field added to the result schema is covered with no test change.
- [M2] Process-level timeout and Ctrl-C tests on Unix | owner: qa-engineer | est: 3h | depends on: Blocking helper and subprocess kill on timeout; Env-level harness: run the real rdy against a fixture env and compare goldens | exit test: the two process rows of section 5 pass on linux and macos legs, with upper-bound timing only.
- [M2] Dev-only fixture record mode with a scrub step | owner: qa-engineer | est: 4h | depends on: Replay backend and fixture loader; Fixture lint: cargo xtask fixture check | exit test: recording `host.memory` on a CI runner writes nothing raw to disk, replays to the same result, and a planted hostname, address, MAC and serial are replaced consistently.
- [M2] record-fixtures workflow for macOS and Windows runners | owner: qa-engineer | est: 3h | depends on: Dev-only fixture record mode with a scrub step | exit test: a manual run uploads scrubbed directories for macos-15 and windows-2022, and the stub envs are replaced by recordings that replay without `Error`.
- [M2] Nightly flake hunt and 100,000-case property job | owner: qa-engineer | est: 3h | depends on: Nextest ci profile, ignore lint and PR template with the check definition of done | exit test: a planted test that fails one run in ten is caught by the nightly and files an issue with the seed.
- [M2] Headless browser render of the golden HTML with no network | owner: qa-engineer | est: 3h | depends on: Golden tests for JSON and HTML reports | exit test: the headless render of each HTML golden makes zero network requests and logs no console errors.
- [M2] Repo-wide forbidden-name scan using a hashed word list | owner: qa-engineer | est: 2h | depends on: Fixture lint: cargo xtask fixture check | exit test: a file containing a listed word fails CI, and the repo holds only hashes, never the words.
- [M2] Fixture drift job: record on today's runner image and replay | owner: qa-engineer | est: 3h | depends on: record-fixtures workflow for macOS and Windows runners | exit test: a nightly run records on each runner, replays the host and net checks, and fails if any check returns `Error` or a panic.
- [M2] Kubernetes distro fixture set | owner: qa-engineer | est: 6h | depends on: Fixture envs net-corp-proxy and k8s-openshift-restricted | exit test: `eks`, `gke`, `aks`, `rke2`, `k3s` and `kind` directories hold the files named in the k8s-expert review, and the matrix rows move to `ci`.
- [M4] GPU capture set from rented machines with the NVIDIA XML scrub | owner: qa-engineer | est: 8h | depends on: Dev-only fixture record mode with a scrub step | exit test: captures with `-q -x --dtd` for a T4 or L4, an A100 with MIG and an HGX scrub clean, every tag the code reads exists in each DTD, and the matrix rows for those driver lines move to `ci`.
