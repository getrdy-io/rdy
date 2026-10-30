# 08 Testing

Owner: qa-engineer. Status: revised 2026-10-28 after the code-reviewer review (8 must-fix items applied).
Waiting for a second pass, and for security-reviewer on the in-process entry point (decision A).

This note says how the suite catches regressions without a GPU node, an air-gapped site or a Windows host
with a particular agent. It builds on 02-engine-design.md (the `Backend` trait with `Live` and `Replay`,
the testing seams), 01-spec-format.md (result names), 03-check-catalog.md (fixture lists), 05-threat-model.md
(invariants, redaction corpus), 06-release-and-distribution.md (the five CI legs) and ADRs 0001, 0003, 0004,
0007, 0008 and 0012. Long material is in the appendices.

## Rules in one screen

1. Every side effect goes through `Probe`, so a fixture can answer every question a check asks.
2. Every fixture is synthetic. A lint enforces it.
3. Fixtures are data. A Linux environment replays on a Windows runner. Only the thin native closures
   (`statvfs`, the Windows registry) are behind `cfg`.
4. The CLI is tested in process. Tests call `rdy_cli::run(args, backend, out, err)` with the Replay backend.
   No shipped binary contains a way to read a fixture directory.
5. A golden is the exact bytes the product writes. It changes only with `UPDATE_GOLDENS=1`, and a golden
   diff is read before the code diff.
6. Tests are deterministic. Engine and env tests run on paused time. No sleep for synchronisation, no
   wall-clock lower bounds, no real network except loopback on ephemeral ports.
7. A flaky test is a bug owned by qa-engineer. Quarantine is not allowed: fix it or delete it.
8. The PR that changes a check also changes its fixtures, its goldens and the compatibility page.

## 1. The test pyramid

| Layer | Where it lives | What it proves | Runs on |
| --- | --- | --- | --- |
| Unit | `#[cfg(test)]` in each crate | Pure functions: thresholds, quantity and version parsing, `/proc` and `os-release` parsers, verdict mapping, YAML limits | All five legs |
| Property | `proptest` in `rdy-spec` and `rdy-engine` | Parser never panics and keeps its limits, round trips, forward compatibility (section 4) | All five legs |
| Check and engine | `rdy_engine::testing`: `run_fixture`, `FakeCheck`, Replay | One check against one fixture case; scheduler, timeouts, panics, cancellation | All five legs |
| Loopback network | `rdy_engine::testing::loopback`, behind the `loopback` feature of `rdy-engine` (ADR 0035) | Real sockets against a TLS server with a test CA, a CONNECT proxy, a closed port, a reset after ClientHello | All five legs |
| Golden | Plain files compared byte for byte | JSON and HTML reports, terminal text, redaction output | All five legs |
| CLI, in process | `crates/rdy-cli/tests`, calling `rdy_cli::run` | Exit codes, report files and terminal text for each fixture environment | All five legs |
| CLI, real binary | `assert_cmd`, Live backend only | `rdy --bogus` gives 64, an unwritable `--out-dir` gives 70, the signed spec flow, the real-OS smoke | All five legs |
| Live CI jobs | `ci.yml` | Kind cluster, `sudo` paths, no phone home under `unshare -n` | linux-x64 |
| Doc tests | `cargo test --doc` on the host target | Public examples in `rdy-spec` and `rdy-engine` run | linux-x64 |

Tooling. `cargo nextest` does not run doc tests, so CI also runs `cargo test --doc --workspace --locked`.
The nextest `ci` profile has `retries = 0`, `fail-fast = false` and `slow-timeout = { period = "30s",
terminate-after = 4 }`, so a hung test dies in two minutes and names itself. The one exception is
trybuild: its compile-fail tests run a nested `cargo build`, which took 90 seconds on the Intel macOS
runner. A test binary named `*_guarantee` is one test group with one thread and a ten-minute limit
(`.config/nextest.toml`). Name every trybuild test binary that way. Shared data comes from
`testing::fixtures_dir()`, which resolves `tests/fixtures` from `CARGO_MANIFEST_DIR`. The fixtures sit at
the repo root, outside every crate, so `cargo package` never ships them and the tests do not run from a
crates.io tarball (the fixtures README says so). `rdy_engine::testing` is `#[doc(hidden)]`, unstable and
outside the semver promise (see corrections). `cargo-fuzz` is M2 (SEC-45).

## 2. Fixtures for environments CI cannot have

### The rule: every fixture is synthetic

"Synthetic" means no byte came from a customer or a person. Each manifest names its `origin`, one of four:

| Origin | Meaning |
| --- | --- |
| `hand` | Written by us from a vendor doc or an RFC. It is our guess at a system, not a recording |
| `generated` | Built at test time or by a script (`rcgen` chains, SNTP packets, kubeconfigs) |
| `ci-runner` | Recorded on a GitHub-hosted runner, then scrubbed |
| `throwaway` | Recorded on a rented machine made for the purpose and destroyed after, then scrubbed |

A developer laptop is not an origin. A design partner's environment is never an origin: nothing recorded
there enters this public repo, scrubbed or not. If a partner hits a failure we cannot reproduce, we write
a `hand` fixture with the same shape and acme names. Only `ci-runner` and `throwaway` fixtures may be
described anywhere as "recorded from a real system".

### Layout

```text
tests/fixtures/
  README.md                      format, naming rules, how to record
  allow.toml                     lint exceptions, each with a one-line reason
  checks/<check-id>/<case>/      one check, one situation (03 lists the minimum cases)
  checks/_policy/<case>/         engine policy cases, for example symlink-to-shadow
  envs/<env>/                    one whole environment plus a spec to run against it
  redaction/<category>/<case>.{in,expected,toml}   (05, Appendix F)
  reports/golden/*.json          goldens of the JSON writer (M1-055), compared on every leg
  results/<rdy-version>/*.json   result files from released versions, append only (ADR 0007)
  specs/{valid,malformed}/       parser corpus
  signed/                        one signed spec, its .minisig and public key, never edited
```

A check case and an environment use the same format. A case is a small environment. One loader reads both.

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
crlf = []                     # files allowed to contain \r
answers = ["host.os", "net.egress", "net.proxy", "net.tls_intercept"]
spec = "spec.yaml"

[caps]                        # which needs are available (02, caps.json)
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

- `base` is the only reuse feature: child files replace base files by path, `remove` deletes some. One
  level, no other options. Without it, every env would carry its own `/proc/meminfo`.
- `answers` lists the check ids the env can answer. The loader fails with "this fixture does not answer
  host.memory" instead of a confusing `NotRecorded`. Anything unrecorded fails, as in 02: a fixture never
  falls through to the real machine.
- Virtual paths are POSIX strings. `root/proc/meminfo` answers `/proc/meminfo` on every runner. A Windows
  env keeps drive files under `root/c/Windows/...`, mapped to the key `c:/windows/...` (lowercased) only
  when `os = "windows"`. Case is kept on Linux and macOS. Programs resolve through the Backend by the
  fixture's `os`, never the runner's.
- Replay follows `root.manifest.json` symlinks when it applies the deny list, so the symlink-to-`/etc/shadow`
  case is exercised. The lint requires `checks/_policy/symlink-to-shadow` and expects `Denied`.
- `commands/` and `api/` files are indexed by the `argv` or `request` field inside them. File names are
  free slugs. The loader and lint fail on a duplicate key. Appendix A has samples.
- Replay never uses a blocking thread. A `delay_ms` is a tokio timer, and `blackhole` is a future that
  never completes. Under paused time the wait costs nothing.
- Addresses are documentation ranges, RFC 1918, `100.64.0.0/10`, `fd00::/8` and loopback. Names end in
  `.example` unless a public name is in the lint allow-list (section below). Tokens are the string
  `REDACTED-TEST-TOKEN`, or built from parts at test time when a push-protection scanner would flag them.

### Windows checkouts and `.gitattributes`

A default Windows checkout rewrites line endings, skips symlinks and rejects some names. The first one also
breaks a signed spec, because the signature covers the raw bytes.

```gitattributes
* text=auto eol=lf
/tests/fixtures/** -text
/examples/specs/** -text
*.minisig -text
/crates/*/templates/** text eol=lf
/crates/*/data/** text eol=lf
```

- `-text` means git never converts a byte, so a fixture that must carry CRLF (recorded `NETSTAT.EXE`
  output) keeps it everywhere, and one that must not carry CRLF cannot gain it.
- Askama templates and shipped data files are `eol=lf`. Otherwise a Windows checkout compiles CRLF into
  the HTML and every golden fails on that leg.
- `.editorconfig` sets `end_of_line = lf`. The lint rejects a `\r` in any fixture or example file not
  listed in the manifest's `crlf`.
- The windows-x64 leg sets `core.autocrlf true` before checkout. A test hashes `tests/fixtures/signed/*`
  and one CRLF fixture against committed digests, and `git check-attr text` must say `unset` for them on
  every leg. The signed spec was signed once with a throwaway key. Only the public key and the `.minisig`
  are committed. New cases get new files; nobody re-signs.

### The fixture lint

It is a nextest test in `rdy-engine` (`tests/fixture_lint.rs`), so it runs on every leg with no extra
command. It fails on:

- a bad manifest, a missing `origin`, an `origin` outside the four;
- a file name unique only by case, a Windows reserved name (`con`, `nul`, `aux`, `com0`, `com1`, `conin$`), a trailing dot or
  space, one of `<>:"|?*[]`, a path over 150 characters, a symlink, a file over 256 KiB, an env over 1 MiB;
- a `\r` not listed in `crlf`, in `tests/fixtures` or `examples/specs`;
- a URL host, or a dotted name that ends in an IANA top-level domain (see the note below), that is not `.example`, `.test`, `.invalid`, `.local`,
  `cluster.local` or on the built-in allow-list of vendors Rdy checks (OS vendors, `k8s.io`,
  `nvidia.com`); any publicly routable IP address. Other entries need `allow.toml` with a reason
  (`169.254.169.254` for the metadata tests is the first);
- (M1-075, in `crates/rdy-cli/tests/env_harness/completeness.rs`, not in the lint file) a registered, implemented check
  (registered by a family and not on its stub list) with no `checks/<id>/` directory, or without a passing
  case, a non-passing case, a no-privilege `partial` case where a root-optional need exists, and a `Timeout`
  case where it declares a command, a peer or a `statfs` prefix. A case counts through its `expect.json`
  (`result.level`, `result.partial`, `result.timed_out_ms`). A `PENDING` list in the test names what is still
  owed and by which ticket, and a row that is no longer true is a failure; a missing
  `checks/_policy/symlink-to-shadow` stays in the lint file.

Two deviations, decided in the M1-050 review. The host rule uses a short list of country codes and common
generic labels, not brand TLDs (`crates/rdy-engine/tests/data/iana-tlds.txt`, taken from the IANA root zone
list and checked in so the test needs no network), not the public suffix list. Brand TLDs are left out on
purpose because they name companies and products. It leaves out the labels that are also file extensions in the fixtures (`sh`, `py`, `rs`, `md`,
`so`, `in`, `link` and a few more) for dotted names outside URLs. A URL host is checked with any
label. On `amazonaws.com`, `azure.com` and `googleapis.com` only the bare name, `<service>.<domain>` and
`<service>.<region>.<domain>` pass, because anyone can get a name there. The registry rule in the last
bullet needs the check families, which `rdy-engine` cannot link, so M1-075 (the env harness links the CLI
and the families) owns it, and the lint file keeps a hand-kept `REQUIRED` list until then.

M2 adds the rule that nothing in a fixture changes under the redactor (it needs SEC-25), and the recorder.

### Environments

Five in M1, because the M1 exit test needs exit codes 0, 1 and 2 on every leg, and `all-pass` already has
host, net and k8s facts in it. The rest are M2.

| Env | Milestone | Story | Verdict, exit |
| --- | --- | --- | --- |
| `all-pass` | M1 | RHEL 9 VM, 32 GiB nominal showing 31.3 GiB, xfs, direct egress, vanilla three-node cluster | `ready`, 0 |
| `warnings-only` | M1 | Swap on, port inside the ephemeral range, one `NO_PROXY` gap, no default StorageClass | `ready_with_warnings`, 1 |
| `all-block` | M1 | 8 GiB RAM, disk full, 6443 held, egress refused, TLS interception, cluster too old, RBAC denied | `not_ready`, 2 |
| `no-privileges` | M1 | Not root, audit log unreadable, no kubeconfig: partial results and `missing_need` skips | `not_ready`, 2 |
| `timeouts` | M1 | Commands with `delay_ms` past the limit, a black-hole endpoint, a slow `/version`, a hung `statvfs` | `not_ready`, 2 |
| `net-airgapped` | M2, first to add back | No default route, internal DNS only, public endpoints refused, mirror reachable; runs `acme-airgap-host.yaml` | per spec |
| `host-ubuntu2204-container` | M2 | `memory.max` 8 GiB on a 64 GiB host, `cpu.max` quota, overlayfs, `noexec` tmpfs | per spec |
| `net-corp-proxy` | M2 | 407 Basic proxy, CONNECT ok, `NO_PROXY` gap, private-CA interception | `not_ready`, 2 |
| `k8s-openshift-restricted` | M2 | `+hash` version string, PSA `restricted`, SCCs, no default StorageClass | `ready_with_warnings`, 1 |
| `macos-15-arm64-stub`, `windows-2022-stub` | M2 | Host checks skipped, net runs; real recordings replace them | per spec |

The check-level cases for each of these shapes ship with the 03 check tickets in M1. The macOS and Windows
stub behaviour in M1 is covered by the exit test of "Family trait, registry and run plan" (02): the plan for
Windows marks host checks `not_yet_on_os`, a pure unit test with no I/O.

### How each hard case is covered

| Case CI cannot have | How it is covered | Matrix state |
| --- | --- | --- |
| Air-gapped site | `net-airgapped` (`refused` and `blackhole` entries, DNS limited to internal names) and SEC-22 (no connect leaves loopback). Both are M2 add-backs | `none` until they land, then `fixture` |
| GPU node (M4) | `nvidia-smi -q -x --dtd` captures from a rented T4 or L4, one A100 with MIG, and an HGX capture, all scrubbed. Every failure string and exit code is a command fixture. A case asserts `nvidia-smi` is never called when the kernel module is absent | `none` until a capture exists, then `fixture` (origin `throwaway`); `field` for the first real node |
| Windows host with a specific agent | Registry and service JSON under `native/`, a `SecurityCenter2` result, a Defender preference dump. `agents.toml` has a unit test per entry | `fixture`; `field` only when we run on a real Windows box |
| Kubernetes distros | Per-distro sets as 03 describes, plus a live kind job for the real API server | kind `live`, others `fixture` |
| Proxy with TLS interception | `rcgen` chains served by the loopback test server, a CONNECT proxy with modes `ok`, `403`, `407-basic`, `407-negotiate`. The probe test asserts zero application bytes are written | `fixture`: a simulated middlebox, not a real one |

## 3. Golden tests

**What is golden.** Per environment: `report.json` (the `--json` stdout), `report.html` and `terminal.txt`
(stderr with colour off and width 100), captured from the in-process run. Per check case: `expect.json`.
Redaction expectations are goldens too. HTML goldens exist for `all-pass`, `warnings-only` and `all-block`
only. Goldens sit next to what they describe, so a reviewer sees input and output in one diff.

**Compare.** One helper, `testing::golden::assert_golden(path, actual_bytes)`, about 60 lines. It compares
bytes. A mismatch writes `<path>.actual` (git-ignored), prints the first 40 lines of a unified diff and the
exact accept command. A missing golden fails, unless `UPDATE_GOLDENS=1`. Every path it touches is appended
to `target/goldens-used/<pid>.txt`. No insta: the file is the product's own output, and `report.html` opens
in a browser.

**Normalisation.** Determinism first (fixed clock, run id, jobs, environment), scrubbing second. The field
list is in Appendix C. The env test runs each env at `jobs = 1` and `jobs = 8` on paused time and asserts
equal normalised reports.

**Checks on every golden.** JSON validates against `result.v1.schema.json`. Tests use the typed enums from
`rdy-spec` for `skip_kind`, `error_kind` and `verdict_reason`, never string literals, so a renamed value
fails to compile. The HTML golden gets the static checks from ADR 0003: exact CSP meta, `lang` and
`color-scheme`, no `src` or `href` off the file except the footer link with `rel="noopener noreferrer"`,
no `<link>`, `@import` or `url(`, no `|safe` in a template, and a `</script><img onerror>` hostname round
trip through the embedded JSON. A headless browser render is M2.

**Updating on purpose.**

```text
UPDATE_GOLDENS=1 cargo nextest run --workspace    # rewrites goldens and lists each file
git diff tests/ crates/                           # read it
```

- `UPDATE_GOLDENS=1` is refused when `CI` is set.
- It never touches `tests/fixtures/redaction/**` or `tests/fixtures/results/**`. A golden you can
  regenerate is not a security test. Redaction expectations are edited by hand, and result files from
  released versions are append only (the lint compares them with `main`).
- Staleness. The normal run fails on a mismatch and on a missing golden. After nextest on linux-x64,
  `cargo xtask goldens check` compares `target/goldens-used` with the files on disk and fails on an orphan.
  Goldens are OS independent by construction: there is no per-OS golden file.

**Review rule.** A PR that changes a golden has a `## Golden changes` section in its body: one sentence per
changed file saying why. code-reviewer reads the golden diff first, before the code. A golden-only PR, or a
change the code does not explain, is rejected. The CI check for the section is M2; until then
code-reviewer enforces it by hand.

## 4. Property tests

`proptest`. The case count is set per test with `ProptestConfig`, not with the global `PROPTEST_CASES`:
10,000 for the parser "never panics" and limits properties, 256 for everything else. Strings are capped at
4 KiB and collections at 64 items. `max_shrink_time` is 30,000 ms, so a failure finishes shrinking before
nextest's kill. The whole property suite stays under 60 s on linux-x64. Failures are saved to
`proptest-regressions/` and committed. PR runs use a fixed seed, so an unrelated PR never fails on a fresh
draw; a nightly job (M2) uses a random seed, prints it and files an issue. (A fixed seed needs proptest 1.5
or newer; the ticket confirms the pinned version.)

**Spec parser** (`rdy_spec::parse_unverified` and `load`), M1:

| Invariant | Generator |
| --- | --- |
| Never panics. Returns `Ok` or a `SpecError` with a non-empty `hint()` and, for YAML failures, a line and column | Arbitrary bytes; YAML-shaped soup (`[`, `{`, `- `, `&a`, `*a`, `!!`, `<<`, NUL, BOM, CRLF, tabs); mutations of every file in `examples/specs` |
| Over 1 MiB is refused before parsing; depth 64 passes, 65 fails | Boundary cases and nested flow collections of generated depth |
| Anchors, aliases, merge keys, duplicate keys and a second document are each rejected with their own error | A valid generated spec with one poison step |
| Round trip: `Spec` to JSON (valid YAML 1.2) and back is equal; `parse(emit(parse(x))) == parse(x)` for the examples | Generated `Spec` values: slug `^[a-z0-9][a-z0-9-]{0,62}$`, known ids, quantities, severities |
| **Forward compatibility:** a valid spec plus an unknown id, an unknown field or an unknown severity still parses, and the check is `skipped` with `not_in_build`, `unknown_check` or `unsupported_spec` (an unknown severity counts as block), never `pass` | A valid spec with one such insertion |
| Version-like fields keep their text: `12.10` quoted stays `"12.10"`, unquoted is refused with a quote hint | `\d{1,3}\.\d{1,3}(\.\d{1,3})?` |
| Verify before parse: changing any byte of the signed spec gives a `SignatureError` and the parser spy count stays 0 | The signed spec plus a random index and byte |

The redactor properties (idempotence, planted secrets never survive, a schema-driven canary walk over the
whole `Report`) and the verdict properties are M2. Appendix D has both tables.

## 5. Timeout and cancellation tests

| Level | How | Asserts |
| --- | --- | --- |
| Scheduler | `FakeCheck` with `Sleep(forever)` and `Panic`, `#[tokio::test(start_paused = true)]` | `Timeout` with `timeout_after_ms` equal to the effective limit; `Panic` gives `Error` and the others still pass; no real time passes |
| Stuck blocking thread | `Fake::Block` waits on a `std::sync::mpsc::Receiver` that the test releases after its asserts. The test builds its own runtime and ends it with `shutdown_timeout(100 ms)`. **Real time**: 50 ms check timeout, upper bound 1 s | `Timeout`, and the run returns without waiting for the thread. It never uses paused time, because tokio can stop auto-advancing while a blocking task runs |
| Run deadline | Deadline 10 s, one check running, three unstarted | Running becomes `Timeout`, unstarted ones are not run (`skipped`), all counted as required or optional not run |
| Cancellation | Cancel the token while checks run | Report written with `interrupted: true`; unfinished checks `skipped` with `skip_kind: cancelled`; nothing left running (a drop guard counts live futures); verdict from the 01 rule. `complete` is not asserted until 01 says what it is after Ctrl-C (see corrections) |
| Replay delays | `delay_ms` past the limit, or a `blackhole` entry | `Timeout`, and an action log entry that says what was in flight |
| `timeouts` env | In process, paused time, at `jobs = 1` and `jobs = 8` | Every hung source gives `Timeout`; the run ends inside `deadline_ms` in virtual time; verdict `not_ready` with `required_check_not_run` |
| Process level, Unix (M2) | Live backend, a test check running `/bin/sleep 600`, timeout 1 s | The run ends in under 4 s, and the process group is gone (checked with `rustix` on the group id right after the run), so no reused pid can fool it |
| Real binary, Unix (M2) | `rdy run` with a spec that sets `timeout: 1s`, `SIGINT` after the first check starts | Exit within 3 s, report directory with `interrupted: true`, exit by the verdict rule; a second `SIGINT` exits 70 with no report; `SIGTERM` acts like the first `SIGINT` |

Rules that keep these stable:

- Only the `Block` test and the two M2 rows use real time. They assert upper bounds with at least three
  times the expected duration, never a lower bound, and never the order of unrelated events.
- Windows: the `SIGINT` row is `#[cfg(unix)]`, since sending a console event needs `unsafe`. On Windows the
  cancel path is covered at the engine level, and Ctrl-C on a real console is `field` in the matrix.
  Grandchild kill waits for job objects (an M2 ticket in 02).
- The Ctrl-C wording follows 02: first Ctrl-C finishes with a partial report, second exits 70. cli-ux has
  not confirmed it. The test changes with 07.

## 6. Cross-platform

| Leg | Runner | Runs |
| --- | --- | --- |
| linux-x64 | `ubuntu-24.04`, musl | Everything, plus the Linux-only jobs: `root` (the `root_*` tests as a prebuilt nextest archive run under `sudo`, so `target/` stays user-owned), `kind`, doc tests, 10,000-case parser properties, `cargo xtask goldens check` |
| linux-arm64 | `ubuntu-24.04-arm`, musl | Unit, property, fixtures, goldens, in-process CLI, real-binary tests |
| macos-arm64, macos-x64 | `macos-15`, `macos-15-intel` | Same, with the Unix process tests |
| windows-x64 | `windows-2022` | Same, with `core.autocrlf true`, minus Unix-only tests, plus Windows-only ones |

**The `root_*` convention.** A test that needs uid 0 has a name whose last path segment starts with `root_`
(`root_whoami_is_zero`, `trust::root_ignores_sudo_user_home`). Rules:

- `.config/nextest.toml` skips those tests in the `default` and `ci` profiles. The `root` profile runs only
  them. The filter is `test(/(^|::)root_[^:]*$/)`. A name that does not follow the convention runs in the
  normal job and fails there.
- The `root` job in `ci.yml` (linux-x64 only) installs `strace`, builds a nextest archive as the runner user,
  then runs the archive under `sudo` with `--profile root --no-tests=fail`. `target/` stays user-owned and
  root never runs cargo or rustup. It sets `RDY_REQUIRE_ROOT=1`.
- Plain `cargo test` has no name filter. Each `root_*` test returns early when it is not root and
  `RDY_REQUIRE_ROOT` is unset, so `cargo test --workspace` stays green for a normal user. With the variable
  set, not being root is a failure. `crates/rdy-cli/tests/root_smoke.rs` (`root_whoami_is_zero`) is the
  canary. It proves the job really runs as root, and `--no-tests=fail` proves the filter still matches.
- The `test` job on linux-x64 lists the `ci` profile and fails if a `root_*` test appears.
- The setuid-gate test (`crates/rdy-cli/tests/setuid_gate.rs`, M1-074) is not a root test: it runs as the CI
  user and uses passwordless `sudo` only to `chown`, `chmod u+s` and `setcap` a copy of the binary. The
  linux-x64 leg installs `libcap2-bin` and sets `RDY_REQUIRE_SETUID=1`. Without the variable the test
  skips, so `cargo test --workspace` stays green for a normal user; with it, a missing `sudo` or `setcap` is
  a failure. The spec path is a FIFO with no writer, so an exit 70 within 5 s shows the spec was never opened.
- Root tests never run on macOS or Windows. The Windows store refusal tests (M1-122, ADR 0027) are `windows-only` tests; the ACL checks themselves are M2-105.

What is `cfg`-gated, and nothing else:

| Gate | Tests |
| --- | --- |
| `target_os = "linux"` | Live `statvfs` on a temp dir, a live `/proc/self` smoke |
| `unix` | Process-group kill, `SIGINT` and `SIGTERM`, output-dir modes 0700 and 0600, symlink-not-followed |
| `windows` | The `ping`-based sleeper, absolute `System32` resolution, a live registry read compared in shape to the recorded JSON |
| none | Every parser and evaluator, and every Replay-driven fixture, for any recorded OS, on any runner |

The last row is the point. A `/proc/net/tcp` parser, a macOS `netstat` parser and a Windows `NETSTAT.EXE`
parser run on all five legs, because their input comes through `Probe`. Only the closure passed to
`probe.native(..)` is gated. The setuid-like id mismatch (INV-10) is a unit test on the pure refusal
function with injected ids, not a backend feature.

**The CLI in process (decision A).** `rdy_cli` is a library target (09 already needs it for the CLI
reference). It exposes `#[doc(hidden)] pub fn run(args, backend: Arc<dyn Backend>, stdout, stderr) ->
ExitCode`. `main.rs` calls it with the Live backend and nothing else. Env tests call it with Replay and
capture buffers, so they get exit codes, `terminal.txt` and the report files with paused time. No release
artifact has a switch, a feature or an environment variable that reads a fixture, so there is nothing to
prove absent. ADR 0011 decision 4 ("no library") is amended in the same change. The real-binary tests stay
small and Live-only. `rdy --bogus` must exit 64, not clap's default 2, which would read as "blockers"; that
case lives in ADR 0008's "Error types with fix hints" ticket.

**Real-OS smoke.** On each leg the shipped `rdy` runs a tiny spec against the live runner and asserts
shape only: the report validates against the schema, no check has `error_kind: panic`, host checks are not
skipped on Linux and are `not_yet_on_os` on macOS and Windows, and the exit code is 0, 1 or 2. It merges
with release-engineer's M2 `release-smoke` job.

## 7. The compatibility matrix

`docs/compatibility.md` is the public page, linked from the docs site. In M1 it is a hand-written table
owned by docs-writer, with one row per claim below. From M2 it is generated from `tests/compat/matrix.toml`
by `cargo xtask matrix`, and `docs-gen` runs it with `--check`. Appendix B has the rules and the day-one
rows.

**Dimensions**, one small table per group, not a cross product: OS family and version, architecture,
container runtime, Kubernetes distro and version, proxy type, network posture, GPU driver line.

**States.** The page makes a claim, so the words are exact.

| State | Meaning |
| --- | --- |
| `live` | A CI runner leg or the kind job exercised real code on a real system of that kind. The evidence column names the leg |
| `fixture` | CI replays a fixture. The page shows its origin. A `hand` fixture is our model of the system, not a recording |
| `field` | Verified by hand on a real environment. Needs a record file with rdy version, date, who, and redacted evidence |
| `none` | Unverified. We make no claim. The default for every row |

**Kept current.** Every fixture env's optional `[matrix]` table must be cited by a row, and a row that cites
an env must match it. A PR that changes `crates/rdy-checks-*/src/**`, `tests/fixtures/**` or
`CheckInfo::os` also changes the page, or its body says `Compat matrix: unchanged because <reason>`
(the CI check is M2; code-reviewer enforces it by hand in M1). Moving a row down is always allowed and is
right when a check changes and the evidence no longer applies. Staleness of `field` rows (over 180 days) is
reported by a nightly job that opens an issue. It is never computed inside `--check`, so it cannot fail an
unrelated PR.

## 8. Coverage and flakes

**Coverage.** `cargo-llvm-cov` in the nightly job on linux-x64, which is release-engineer's 06 ticket
"Nightly coverage job, not gating". It uploads lcov and prints per-crate lines in the job summary. It is
reported, not gated: no threshold, no PR comment. The job runs on the glibc host target, so it measures our
code, not the shipped musl binary. The founder reads the per-crate table monthly. The number that does gate
is the fixture-completeness rule in the lint.

**Flake policy.** A flake is a test that passes and fails on the same commit.

- The `ci` profile has `retries = 0`. A retry that turns red into green is how flakes hide.
- Every flake is a bug owned by qa-engineer, filed with label `flake` and the run link, fixed within five
  working days. If not fixed, the test is deleted and a ticket is filed to rewrite it. **Quarantine is
  never allowed.** No `#[ignore]` as a parking place, no `continue-on-error`, no "known flaky" list.
- The one legal `#[ignore]` is `#[ignore = "runs in job: <name>"]` for a test another job runs with
  `--run-ignored only` (kind). Root tests use the `root_*` name filter instead (section 6). An ignore lint is M2.
- Hygiene: loopback sockets bind port 0 and read the port back; files live under `tempfile`; no in-process
  environment changes (edition 2024 makes `set_var` unsafe and `forbid(unsafe_code)` holds); `TZ`, `LC_ALL`
  and `NO_COLOR` are set on child processes; nothing sleeps to wait for something; timing is upper bound only.
- A nightly flake hunt (M2) runs the suite repeatedly on all five legs and files issues itself.

## 9. Definition of done for a check ticket, test side

The checklist is Appendix E and is copied into `.github/pull_request_template.md`. In one line: a check is
done when it has a complete `CheckInfo`, boundary unit tests, the minimum fixture cases with reviewed
`expect.json`, an in-manifest proof, a Timeout case where it can hang, a canary case where it records
sensitive input, the right OS table, a use in at least one env spec, a matrix decision, green on five legs,
and a golden diff that code-reviewer has read first.

## Appendix A. Fixture file formats and recording

**`root.manifest.json`**

```json
{
  "symlinks": { "proc/1234/fd/7": "socket:[8841]" },
  "unreadable": ["var/log/audit/audit.log"],
  "modes": { "etc/acme/license.key": "0640" },
  "dirs": ["var/lib/acme"]
}
```

Built in memory. The tree holds no symlinks, no special modes and no name with `:`, `[` or `]`.
`unreadable` simulates a no-privilege run.

**`commands/*.json`** (any slug): `{ "argv": ["/usr/bin/chronyc", "-n", "-c", "tracking"], "stdout": "...",
"stderr": "", "exit": 0, "delay_ms": 0 }`. The key is the normalised resolved argv. Binary output uses
`stdout_b64`. Replay finds a recording as the live runner finds a program: `argv[0]` must be in a
fixed search directory or one the check declared (Windows: only `whoami.exe` in its constant directory),
and the arguments match by value. `exit` may be `null` for a signal. `{ "argv": ["chronyc"], "missing":
true }` records a program the machine does not have; a call fails with the live runner's not-found error. **`native/*.json`** (any slug): `{ "call": "statvfs", "path": "...", "value": {...} }` or
`"error": "unsupported"`, one file per `NativeCall`, every field of a value required. The shapes are in
`tests/fixtures/README.md`, which the loader tests keep true (M1-049).

**`api/*.json`** (any slug): `{ "request": {"method", "path", "query"}, "status", "body", "delay_ms" }`.
Paged lists have one file per `continue` token. Access reviews are answered from `api/reviews.json`, a
table of attributes to `allowed` and `reason`. The mock records every request, and the k8s tests assert
only the allowed ones arrived (ADR 0010, INV-14). Cloud APIs (M3) replay at the facade (03).

**`net.json`**

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

`serve` names a server factory the test registers with the Replay builder. The servers behind the
factories are `rdy_engine::testing::loopback` (feature `loopback` of `rdy-engine`, ADR 0035), which any
crate that already uses the engine `testing` feature can turn on, so `rdy-engine` does not depend on a
check crate and no check crate needs `tokio`, `socket2` or `tokio-rustls`. M1-091 maps a name to a started
server: `Replay::serve` takes a factory, `serve_tcp` connects a loopback server such as `ConnectProxy`, and
`serve_duplex` runs an in-process task on one end of a pipe; the backend runs the factory when the facade
connects to the address `net.json` scripts as `serve`. Certificate chains are built with `rcgen` at test time.
Their serials and digests become placeholders (`<serial>`, `<sha256>`) before comparison. `blackhole` is
scripted only: a real black hole cannot exist on loopback (03).

**Recording (M2, dev-only).** It is a command in `xtask`, not in `rdy`, so the shipped binary carries no
bulk file-reading code.

```text
cargo xtask fixture record --spec spec.yaml --origin ci-runner --out tests/fixtures/envs/macos-15-arm64
```

1. A `Recording` decorator (feature `record` on `rdy-engine`, never in release) wraps the Live backend and
   runs the spec once. Raw responses stay in memory and are never written to disk.
2. Scrub in memory: first the redactor rules, then one consistent identity mapping per recording.
   Hostnames become `host-01.acme.example`, users `user-01`, addresses move into documentation ranges,
   MACs become `02:00:00:00:00:NN`, and UUIDs, serials, instance ids, account ids and ARNs become counters
   of the same shape.
3. Allow-lists for known formats. Kubernetes JSON drops `managedFields`, `last-applied-configuration` and
   node `status.images`. NVIDIA XML keeps a tag allow-list and replaces UUID, serial, board id, bus id and
   process names. Process lists keep command names only. An unknown file type is refused.
4. The recorder writes to `<out>.tmp`, runs the fixture lint, and deletes the directory if the lint fails.
5. The real-to-fake mapping is never written. The recorder prints counts and the file list. A human reads
   `git diff`, and code-reviewer reads it again.

For a remote host, build `xtask` as one static binary, run it there, and carry back only the scrubbed
directory. For macOS and Windows, a manual workflow `record-fixtures.yml` runs the recorder on the
GitHub-hosted runners and uploads the scrubbed directory. That gives real macOS and Windows output without
owning either machine. Kubernetes shapes can come from `scripts/record-k8s-fixture.sh`, then the scrub step.

## Appendix B. Matrix rules and day-one rows

`tests/compat/matrix.toml` (M2 onward):

```toml
[[row]]
group = "Kubernetes distro"
item = "OpenShift 4"
checks = ["k8s"]
state = "fixture"
evidence = ["env:k8s-openshift-restricted"]

[[row]]
group = "Kubernetes distro"
item = "EKS"
version = "three newest minors"
checks = ["k8s"]
state = "field"
rdy = "0.2.0"
verified_at = "2027-02-10"
record = "docs/compat/field/2027-02-10-eks.md"
```

A `field` row needs its record file. A `fixture` row needs its env to exist, and the generator shows the
env's `origin`. A `live` row names the runner leg or job.

Day-one rows, the target for `0.1.0`. Everything else is `none`.

| Group | Item | Checks | State | Evidence |
| --- | --- | --- | --- | --- |
| OS | Linux x86_64, Ubuntu 24.04 | host, net, k8s | `live` | linux-x64 leg, kind job |
| OS | Linux aarch64, Ubuntu 24.04 | host, net | `live` | linux-arm64 leg |
| OS | RHEL, Rocky, Alma 9 | host | `fixture` | env `all-pass` (origin `hand`) |
| OS | RHEL, Rocky 8; Debian 12; Amazon Linux 2023; Alpine | host.os only | `fixture` | `checks/host.os/*` cases (`hand`) |
| OS | macOS 15 arm64 and x86_64 | net | `live` | macos-15 and macos-15-intel legs. Host checks are `not_yet_on_os` |
| OS | Windows Server 2022 x86_64 | net | `live` | windows-2022 leg. Host checks are `not_yet_on_os` |
| Container runtime | Docker, containerd, Podman, CRI-O | host.container_runtime (M1-late) | `none` | |
| Kubernetes | kind, newest upstream minor | k8s | `live` | kind job |
| Kubernetes | kubeadm vanilla, three newest minors | k8s | `fixture` | env `all-pass`, `version.json` cases (`hand`) |
| Kubernetes | OpenShift 4, EKS, GKE, AKS, RKE2, k3s | k8s | `none` | Distro set is M2 |
| Proxy | Direct | net | `fixture` | env `all-pass` |
| Proxy | CONNECT; 407 Basic; 407 Negotiate (classified, not authenticated) | net | `fixture` | loopback proxy modes, a simulated proxy |
| Proxy | TLS-intercepting with a private CA | net | `fixture` | generated chains, a simulated middlebox |
| Proxy | PAC or WPAD | net | `none` | Not supported in v1. The check warns |
| Network | Air-gapped host | host, net | `none` | `net-airgapped` is the first M2 add-back |
| GPU driver | 535, 550, 570 lines | gpu (M4) | `none` | Captures needed |

## Appendix C. Normalisation

| Field | Treatment |
| --- | --- |
| `run.started_at`, `finished_at`, `run.id` | Fixed from the manifest `[run]` table. No scrubbing |
| `duration_ms`, `started_ms`, action `at_ms` and `duration_ms` | Set to 0. `timeout_after_ms` stays: it is the configured limit |
| `producer.version`, `commit`, `target` | `<version>`, `<commit>`, `<target>`, so a release or a leg never changes a golden |
| `host.hostname`, `host_id` | Taken from the fixture. The lint proves they are synthetic |
| Action log order | Sorted by spec index of the check, then per-check order, then renumbered |
| Output directory in terminal text | `<out-dir>`, with `\` turned into `/` in the terminal golden only |
| Generated certificate serials and digests | `<serial>`, `<sha256>` |
| Process environment | The harness passes `TZ=UTC`, `LC_ALL=C`, `NO_COLOR=1`, `HOME` as a temp dir, and nothing else |

## Appendix D. Property tables for M2

**Redactor** (`rdy_engine::redact`)

| Invariant | Generator |
| --- | --- |
| Never panics on arbitrary UTF-8 or lossy-decoded bytes | Any string up to 4 KiB |
| Idempotent: `redact(redact(x)) == redact(x)` | Any string, and strings with planted secrets |
| A planted secret never survives, in plain, JSON-escaped and URL-encoded form, and the typed placeholder appears | Per-category generators (AWS key id, `rdy_st_` token, bearer, URL userinfo, PEM body, `password=`) in random text, JSON, YAML and INI |
| After the engine's redaction pass, a canary planted in every free-text field is absent from the JSON and the HTML, and `redactions` equals the number planted | Walk the result schema and plant a canary in every string leaf with no `enum` or `const`. A new field is covered the day it is added |

Random benign strings (git SHAs, UUIDs) are not asserted unchanged until the rule set is stable: false
positives are counted, not gated, in M1 (05), and a known-failing property would be a quarantined test.

**Verdict and exit code** (`rdy_spec::result`, the rule in 01 section 5.3). First an exhaustive table test
over severity (`warn`, `block`, unknown) times status (`pass`, `warn`, `block`, `skipped` with each
`skip_kind`, `timeout`, `error`, unknown). Then, over generated lists:

1. Order independent: any permutation gives the same verdict, counts and exit code.
2. Monotone: making one result worse, or adding a non-pass result, never improves the verdict. Adding a
   `pass` to a list where nothing was verified is the one allowed improvement, and has its own case: it
   moves `ready_with_warnings` with `verdict_reason: nothing_verified` (exit 1) to `ready` (exit 0).
3. A required check (severity `block` or unknown) that is skipped (other than `not_applicable`), timed out,
   errored or has an unknown status gives `not_ready` and exit 2.
4. Exit code is 0 only when every required check passed or is `not_applicable`, nothing warned, no
   optional check failed to run, and at least one check passed.
5. Summary buckets add up to `total`, and `required_not_run` equals the count in property 3.
6. `verdict_reason` is `required_check_not_run`, `nothing_verified` or null, and matches the statuses.

## Appendix E. Check ticket checklist (the PR template)

```text
[ ] CheckInfo complete: id, family, needs, os table, default timeout, manifest of reads/commands/env/peers.
    The registry test passes (ids unique, id matches its row in 03).
[ ] Evaluation is a pure function over plain fact structs. Unit tests hit each threshold boundary:
    exactly at min, one below, inside the nominal band, severity warn capping a block.
[ ] Parsers of external text have a "never panics on arbitrary bytes" property (shared helper).
[ ] tests/fixtures/checks/<id>/ has the minimum cases: pass, each non-pass level, no-privilege (partial)
    if a root-optional need exists, Timeout if the source can hang, garbage input (empty, truncated,
    odd locale) giving Error or partial and never a panic. Each case has a reviewed expect.json.
[ ] assert_within_manifest passes for every case.
[ ] Fix text: every placeholder is filled in expect.json, and the spec fix override case exists.
[ ] If the check records env, URLs or command output: a canary case shows it absent from JSON and HTML.
[ ] Every OS in CheckInfo::os is right; the plan unit test for Windows and macOS passes.
[ ] The check is used by at least one env spec; env goldens updated and explained in "## Golden changes".
[ ] Fixture lint passes.
[ ] Compatibility page changed, or "Compat matrix: unchanged because ..." is in the PR body.
[ ] Green on all five legs; no new #[ignore] outside the allowed form.
[ ] Ran once on a real machine if one is at hand; command and redacted evidence in the PR.
[ ] code-reviewer read the golden diff first. security-reviewer has it if the check execs, opens sockets
    or reads sensitive paths.
```

## Plan corrections found

- docs/plan/03-check-catalog.md, Conventions "Fixtures", and docs/plan/02-engine-design.md, "Testing
  seams": the path `tests/fixtures/<check-id>/<case>/` leaves no room for whole environments. Fix:
  `tests/fixtures/checks/<check-id>/<case>/` beside `tests/fixtures/envs/<env>/`, and 03's
  `tests/fixtures/k8s/distros/` becomes `checks/k8s.*/` cases. Add `fixture.toml`, `native/` and `net.json`.
  Command and api files are indexed by the content inside them with free slug names, not argv hashes
  (code-review item 12); 03's "slug plus hash of argv" convention and its ticket "Fixture manifest
  (symlinks, unreadable, dirs), placeholders and Windows-safe command names" follow this note.
- docs/plan/02-engine-design.md, "The probe facade": `Probe` takes `&Path`. On Windows the fixture key then
  depends on the runner. Fix: Replay normalises to POSIX strings, maps `root/c/...` to `c:/...` only for
  `os = "windows"`, and resolves programs by the fixture's `os`.
- docs/plan/02-engine-design.md, "How checks degrade on each OS": whole gather functions sit under
  `#[cfg(target_os)]`, so a Linux fixture cannot exercise the Linux parser on a macOS leg. Fix: gate only
  the closures passed to `probe.native`.
- docs/plan/02-engine-design.md, "Testing seams", and docs/plan/00-overview.md, ticket "Golden tests for
  JSON and HTML reports": both say `insta`. Plain-file goldens and `UPDATE_GOLDENS=1` replace it. Fix: drop
  `insta` from the dev-dependency table; the ticket's exit test is rewritten below.
- docs/plan/00-overview.md ticket "Property and fuzz tests for rdy_spec::parse" and docs/adr/0001: the title
  says fuzz, but fuzzing is M2 (SEC-45). Fix: the ticket is "Property tests for rdy_spec::parse".
- docs/plan/00-overview.md, same golden ticket, and CLAUDE.md "Cross-platform from day one": "all four CI
  targets". 06 defines five legs. Fix: say "five CI legs".
- docs/plan/06-release-and-distribution.md, Appendix A `test` job: `cargo nextest run` skips doc tests, and
  nothing sets `core.autocrlf` on the Windows leg. Fix: add `cargo test --doc --workspace --locked`
  (linux-x64), the nextest `ci` profile with `retries = 0`, and the autocrlf step before checkout.
- docs/adr/0011-binary-name-and-cli-package.md, decision 4 ("publishes no library API"): 09 already adds a
  `rdy_cli` library target. Fix: amend decision 4 to say the library holds the command tree and the
  `#[doc(hidden)]` `run` entry point, with no stability promise. security-reviewer signs.
- docs/adr/0007-crate-publishing-and-versioning.md: `rdy_engine::testing` and its feature are public
  surface of a published crate. Fix: state that `testing` and `record` are `#[doc(hidden)]`, unstable,
  outside the semver promise and excluded from `cargo-semver-checks`.
- docs/adr/0003 ticket "askama HTML report with inline CSS, dark mode and print" and the same ticket in 00:
  the exit test needs a headless browser in M1. Fix: M1 uses the static checks in section 3; the browser
  render is M2.
- docs/adr/0007, Tickets implied: "Keep golden result files per released version and parse them in CI" is
  `[M2]`, while 00 lists `[M1]`. Fix: M1. The alphas already write result files and the M2 portal must read
  them. Start the directory at `0.1.0-alpha.1`.
- docs/plan/03-check-catalog.md, ticket "Loopback network test support": no home is named. First fix: the
  servers live behind a non-default `test-support` feature of `rdy-checks-net`. That cannot work: the lint
  wall bars `tokio`, `socket2` and `tokio-rustls` from check crates, and the facade tests (M1-091, M1-092)
  sit in `rdy-engine`, which cannot depend on a check crate. Final fix (M1-090, ADR 0035): the servers are
  `rdy_engine::testing::loopback`, behind the `loopback` feature of `rdy-engine`. No new crate. The live
  loopback list drops "black hole" (scripted only, per 03).
- docs/plan/01-spec-format.md, section 5.3: `complete: false` is tied only to exit 70, so after a Ctrl-C
  that still writes a report its value is not stated. Fix: 01 says it. The cancellation test asserts
  `interrupted: true` and `skip_kind: cancelled` only, until then.
- docs/plan/00-overview.md, ADR 0008 ticket "Error types with fix hints and exit code mapping at the CLI
  edge": add to its exit test that `rdy --bogus` exits 64, not clap's 2, and an unwritable `--out-dir`
  exits 70 with the full terminal result printed (this replaces a separate qa ticket).
- docs/plan/03-check-catalog.md, ticket "net.dns": the musl resolver fixture (`sss` in `nsswitch.conf` gives
  the warning) moves into it from the qa-engineer ticket of the same name in 00.
- examples/specs/*.yaml use `host.selinux` and `gpu.device_plugin`, but 03 names `host.lsm` and
  `k8s.device_plugins`. The examples lint test fails on them until 01's ticket "Align example specs and
  check catalog with 01-spec-format names" lands.

## Decisions needing an ADR

Conservative choice first in each item.

- **A. How the CLI is tested.** Add `rdy_cli::run(args, backend, out, err)` as a `#[doc(hidden)]` library
  entry point, and amend ADR 0011 decision 4. No shipped binary has a fixture switch. Alternatives: a cargo
  feature `fixture-backend` plus `RDY_TEST_BACKEND_DIR` in the binary (needs a `compile_error!` in release,
  a `cargo tree -i` check, a `grep -q` on each extracted dist archive inside `sign-release.yml` before
  signing, and still cannot use paused time); only Live smoke tests (no deterministic exit-code tests).
  security-reviewer signs before the ADR is written.
- **B. Golden storage.** Plain files, a 60-line helper, `UPDATE_GOLDENS=1`. Alternative: `insta`, already in
  the dependency table, with `cargo insta review`, but `.snap` headers, and a separate path for redaction
  expectations that must never be regenerated. Switching later changes only the helper, about one hour.
- **C. Where recording lives.** `cargo xtask fixture record`, not an `rdy` subcommand. Alternative: a hidden
  `rdy fixture record`, simpler on a remote box (07 owns the command surface).

## Tickets implied

Titles that already appear in 00, 02, 03 or 05 are reused so 11-backlog.md can dedupe. M1 qa-engineer load
is 32 hours (down from 58). The review's cut list was applied. Add-back order if hours free up:
`net-airgapped` (2h, the KICKOFF air-gap case), SEC-22 (2h), `windows-2022-stub` (1h). The M2 to M4 tickets
below are coarse and move to 11-backlog.md when it is merged.

- [M1] Fixture format README, .gitattributes and Windows canary | owner: qa-engineer | est: 2h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006); Verify minisign signatures in rdy-spec against a trust store with product binding | exit test: `tests/fixtures/README.md` documents every file in section 2 and Appendix A, `.gitattributes` has the lines above, and the windows-x64 leg checks out with `core.autocrlf true`, shows `git check-attr text` as `unset` for the fixtures, matches committed digests for `tests/fixtures/signed/*` and one CRLF fixture, and verifies the signed spec.
- [M1] Replay loader reads the 08 fixture format | owner: rust-engineer | est: 3h | depends on: Replay backend and fixture loader; Fixture manifest (symlinks, unreadable, dirs), placeholders and Windows-safe command names | exit test: a `fixture.toml` with `base`, `remove` and `answers` loads; command and api files are found by the argv or request inside them; `root/c/Windows/...` answers `c:/windows/...` only when `os = "windows"`; a manifest symlink to `/etc/shadow` is Denied through the canonical check; a `delay_ms` waits on the tokio clock and `blackhole` never completes, with no blocking thread.
- [M1] In-process CLI entry point rdy_cli::run taking a Backend | owner: rust-engineer | est: 2h | depends on: Package rdy in crates/rdy-cli with binary name rdy; clap command tree in rdy-cli exposed as library rdy_cli | exit test: a test calls `run` with the Replay backend and capture buffers and gets the exit code, stdout and stderr; `main.rs` calls it with the Live backend only; ADR 0011 decision 4 is amended and signed by security-reviewer.
- [M1] Fixture lint as a nextest test | owner: qa-engineer | est: 3h | depends on: Fixture format README, .gitattributes and Windows canary; Replay loader reads the 08 fixture format | exit test: a planted public hostname, a `\r` outside `crlf`, a file named `con.json`, a 2 MiB file, a public IP, an `origin = "laptop"` and a duplicate argv key each fail with the file named, and a missing `checks/_policy/symlink-to-shadow` fails.
- [M1] Engine test helpers FakeCheck, run_fixture and normalize | owner: qa-engineer | est: 2h | depends on: Replay loader reads the 08 fixture format | exit test: the scheduler tests use FakeCheck for every status, `Fake::Block` waits on an mpsc receiver the test releases, `assert_within_manifest` fails on a fixture check that reads an undeclared path, and `normalize` gives equal reports for `jobs = 1` and `jobs = 8`.
- [M1] Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check | owner: qa-engineer | est: 2h | depends on: Engine test helpers FakeCheck, run_fixture and normalize | exit test: a changed output fails with a diff and an `.actual` file, a missing golden fails, `UPDATE_GOLDENS=1` is refused when `CI` is set and never touches `tests/fixtures/redaction/**`, and `cargo xtask goldens check` fails on an orphan.
- [M1] Golden tests for JSON and HTML reports | owner: qa-engineer | est: 2h | depends on: Embed result JSON in the HTML report safely; Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check | exit test: `report.json` for the ready, warning and not-ready runs validates against the result schema, `report.html` passes the static checks (CSP, no off-file src or href, `</script>` hostname round trip), and all pass on five legs.
- [M1] Env-level harness, in process | owner: qa-engineer | est: 3h | depends on: In-process CLI entry point rdy_cli::run taking a Backend; Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check | exit test: one test per env checks exit code, `report.json`, `terminal.txt` and, where present, `report.html`, with the clock, run id and environment pinned, and the `jobs = 1` and `jobs = 8` reports are equal.
- [M1] Fixture env all-pass | owner: qa-engineer | est: 3h | depends on: Env-level harness, in process; host.memory (meminfo, swap, cgroup limit, nominal band); net.egress staged connector (lookup, dual-stack connect, TLS, ALPN); k8s.version (gitVersion parse, distro, discovery API availability) | exit test: the env exits 0 on all five legs with golden JSON, HTML and terminal text, and 31.3 GiB against `min: 32Gi` passes with its note.
- [M1] Fixture envs warnings-only, all-block and no-privileges | owner: qa-engineer | est: 3h | depends on: Fixture env all-pass | exit test: exit codes 1, 2 and 2 with goldens, `no-privileges` shows `partial` results and `missing_need` skips, and its verdict reason is `required_check_not_run`.
- [M1] Timeouts env and scheduler timeout, deadline and cancellation tests under paused time | owner: qa-engineer | est: 4h | depends on: Fixture env all-pass; Family limits, run deadline and Ctrl-C cancellation | exit test: the `timeouts` env runs in process under paused time at `jobs = 1` and `jobs = 8`, every hung source gives `Timeout`, the run ends inside `deadline_ms` in virtual time, cancellation gives `interrupted: true` with `skip_kind: cancelled`, and only the `Fake::Block` test uses real time with a 1 s upper bound.
- [M1] Property tests for rdy_spec::parse | owner: qa-engineer | est: 3h | depends on: Wire serde-saphyr behind rdy_spec::parse with size, depth, alias and duplicate-key limits | exit test: the section 4 table holds, 10,000 cases for never-panics and limits and 256 for the rest, with a fixed seed on PRs, committed regressions, `max_shrink_time` 30 s and the suite under 60 s on linux-x64.
- [M1] SEC-26 M1 redaction corpus | owner: qa-engineer | est: 3h | depends on: SEC-25 Build minimal redactor for reports and evidence; Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check | exit test: 28 synthetic cases (04 Appendix D; the rest of SEC-26 moves to SEC-44, M2-061) pass with zero misses, secrets built from parts, and `UPDATE_GOLDENS=1` leaves `tests/fixtures/redaction/**` untouched.
- [M1] Keep golden result files per released version and parse them in CI | owner: qa-engineer | est: 1h | depends on: Golden tests for JSON and HTML reports | exit test: `tests/fixtures/results/0.1.0-alpha.1/` parses with the current rdy-engine on every leg, and a modified file under an older version directory fails the lint.
- [M1] Nextest ci profile, cargo test --doc in CI and PR template | owner: qa-engineer | est: 1h | depends on: CI test matrix on five native runners with ci-ok gate and static-musl proof (ADR 0006) | exit test: a test that fails once in three runs is not retried, `cargo test --doc` runs on linux-x64, and `.github/pull_request_template.md` carries Appendix E.
- [M1] Hand-written compatibility page with the day-one rows | owner: docs-writer | est: 1h | depends on: Fixture env all-pass | exit test: `docs/compatibility.md` lists the Appendix B rows with the four state words and each fixture row shows its origin.
- [M2] Compatibility matrix source and generator, and the compat-touched PR check | owner: qa-engineer | est: 4h | depends on: Hand-written compatibility page with the day-one rows | exit test: `cargo xtask matrix --check` fails on a row citing a missing env or a mismatched `[matrix]` value, and a PR that changes a check crate without touching the page or the body line fails.
- [M2] Fixture envs net-airgapped, host-ubuntu2204-container, net-corp-proxy and k8s-openshift-restricted | owner: qa-engineer | est: 8h | depends on: Fixture env all-pass | exit test: each env runs in process with goldens, the air-gapped env runs `acme-airgap-host.yaml` with every public endpoint refused or black-holed, and the proxy env shows the 407 Basic classification and private-CA interception with no userinfo in any output.
- [M2] SEC-22 No-phone-home strace test on Linux CI | owner: qa-engineer | est: 2h | depends on: SEC-21 Egress address policy, no redirects, no bodies; Fixture env all-pass | exit test: under `sudo unshare -n` and `strace -f -e trace=connect,sendto,sendmsg`, every destination while running `all-pass` and `net-airgapped` is a loopback fixture address.
- [M2] Fixture envs macos-15-arm64-stub and windows-2022-stub | owner: qa-engineer | est: 3h | depends on: Fixture env all-pass; OS support table and compile stubs for rdy-checks-host | exit test: host checks are `not_yet_on_os` on all five legs, net runs, and CRLF command output stays intact on the Windows env.
- [M2] Verdict and exit-code property tests, and redactor property tests with the schema-walk canary | owner: qa-engineer | est: 5h | depends on: Amend verdict mapping for required checks not run; Apply the redactor to every Report string before return | exit test: the Appendix D properties hold, including the nothing-verified improvement case, and a new string field added to the result schema is covered with no test change.
- [M2] Process-level timeout and Ctrl-C tests on Unix | owner: qa-engineer | est: 3h | depends on: Blocking helper and subprocess kill on timeout; Timeouts env and scheduler timeout, deadline and cancellation tests under paused time | exit test: the two M2 rows of section 5 pass on linux and macos legs with upper-bound timing only.
- [M2] Dev-only fixture record mode with a scrub step, and the record-fixtures workflow | owner: qa-engineer | est: 7h | depends on: Replay loader reads the 08 fixture format; Fixture lint as a nextest test | exit test: recording `host.memory` on a CI runner writes nothing raw to disk and replays to the same result, a planted hostname, address, MAC and serial are replaced consistently, and a manual run uploads scrubbed macOS and Windows directories.
- [M2] Fixture lint redactor rule, golden-section PR check, ignore lint, nightly flake hunt and fixture drift job | owner: qa-engineer | est: 6h | depends on: Fixture lint as a nextest test; Golden tests for JSON and HTML reports | exit test: a secret-shaped string in a fixture fails the lint, a golden change without `## Golden changes` fails, a bare `#[ignore]` fails, and a planted test failing one run in ten is caught nightly with its seed.
- [M2] Headless browser render of the golden HTML with no network | owner: qa-engineer | est: 3h | depends on: Golden tests for JSON and HTML reports | exit test: each HTML golden renders with zero network requests and no console errors.
- [M2] Kubernetes distro fixture set | owner: qa-engineer | est: 6h | depends on: Fixture envs net-airgapped, host-ubuntu2204-container, net-corp-proxy and k8s-openshift-restricted | exit test: `eks`, `gke`, `aks`, `rke2`, `k3s` and `kind` cases hold the files named in the k8s-expert review and the matrix rows move to `fixture`.
- [M4] GPU capture set from rented machines with the NVIDIA XML scrub | owner: qa-engineer | est: 8h | depends on: Dev-only fixture record mode with a scrub step, and the record-fixtures workflow | exit test: captures with `-q -x --dtd` for a T4 or L4, an A100 with MIG and an HGX scrub clean, every tag the code reads exists in each DTD, and the matrix rows for those driver lines move to `fixture`.
