# Security review of 02-engine-design.md

Reviewer: security-reviewer. Author of the reviewed file: rust-architect. Date: 2026-10-28.
Checked against 05-threat-model.md revision 2 (INV-01 to INV-20), ADRs 0001 to 0012 as they stand on
2026-10-28, 01-spec-format.md (draft of 2026-10-28, which appeared during this review) and 03. 02 was not
edited.

## Verdict

**Changes required.** The shape is right and I want to keep it: one probe facade with the policy above
a swappable backend, Replay under the same policy, `Cmd.program: &'static str`, plan then probe then run,
lazy kube context, no temp files, cap-std for output, and Timeout and Error counting as "required check
not run". But the facade has four ways around it (native closures, the lint wall, check-written CONNECT,
the kube guard's allow-by-default GET). Redaction runs after truncation. The verdict table has a
"not applicable" escape that 01 already closed. A non-yielding check can hang the run with no report.

Must fix: 10. Should fix: 13. Nits: 8. The must-fix items gate ADR 0014 and the start of SEC-17.

## What is right

- Policy and the action log sit in `Probe`, above the `Backend`, so every fixture run tests policy.
- Program names are `&'static str`: INV-08 "every program is a source constant" is enforced by type.
- Fixed PATH always, not only as root. I accept this and will change 05 (see Plan corrections).
- Needs are probed only when the plan contains them, so a host-only spec never runs a kube exec plugin.
- Redirects are recorded, not followed. Stricter than 05 INV-11. I accept it.
- The `testing` feature is checked out of the release feature tree in CI.
- Vendor `fix` text is verbatim, untemplated and labelled with the product.

## Must fix

**MF-01. The probe facade, Kube row. The kube guard is allow-by-default and bypassable.**
- Section: "Policies enforced in Probe", Kube row; corrections bullet on ADR 0010.
- Problem:
  - Every GET is allowed except a substring denylist. 05 INV-14 asks for a deny-by-default list of
    resources named in rdy-checks-k8s. A new check or a dependency bump can read any resource,
    including custom resources that hold credentials.
  - Substring matching on the raw path can be bypassed. The API server percent-decodes the path, so
    `/api/v1/namespaces/x/%73ecrets` reaches Secrets and contains no `/secrets`. Spec values become path
    segments (`namespace`, `name` in `k8s.rbac` and `k8s.admission`), so a signed spec can try it.
  - POST with `dryRun=All` "for checks whose spec turned on dry run" is allowed. 05 INV-14 and ADR 0010
    reject it in M1. And `call` runs on the Buffer worker with no check id, as 02 itself says, so a
    per-check condition cannot be enforced there. 01 section 2.7 also lists `probe_pod`, a pod create.
  - "ConfigMaps metadata only" and "GET by name only for manifest names" have no stated mechanism.
- Fix:
  - Before any rule, refuse a path containing `%`, `..`, `//`, `;`, a trailing `/` or non-ASCII bytes.
    Refuse `Upgrade` headers and the query keys `watch` and `follow`.
  - Parse the path into group, version, namespace, resource, name and subresource. Allow GET only on a
    const `ALLOWED` list of (group, resource) pairs in rdy-checks-k8s, plus `/version`, `/api`, `/apis`
    and discovery documents. No subresources in M1. POST only to `selfsubjectaccessreviews`,
    `selfsubjectrulesreviews` and `selfsubjectreviews`.
  - ConfigMaps: LIST only with an `Accept` header for `PartialObjectMetadataList`. GET by name only from
    a const list (`kube-system/kubeadm-config`). Global rules, because `call` has no check id.
  - No dry run and no probe pod in M1. 01 makes `dry_run` and `probe_pod` `unsupported_spec` in M1 with
    "needs an ADR 0010 amendment".
  - rdy-spec validates spec namespaces and names as DNS-1123 labels or subdomains.
  - Tests: `%73ecrets`, `secrets` in every segment position, GET `pods/exec` with `Upgrade`, a dry-run
    POST and an unlisted resource are each refused and logged.

**MF-02. The probe facade, `Probe::native`. Native calls bypass every policy.**
- Problem: `native(api, f)` runs any closure on `spawn_blocking`. Only the api name is logged. No
  reads prefix, deny list, size cap or peer rule applies inside `f`. `sysinfo` process refresh can read
  `/proc/<pid>/environ` and `cmdline` (05 I5). `statvfs` on a spec path skips the reads prefix and the
  path log. Replay returns recorded JSON, so no test sees what `f` touched. This is the widest hole.
- Fix: replace the closure with a closed `NativeCall` enum that the Live backend executes. M1 variants:
  `Statvfs { path }` (path passes the reads prefix and deny list, logged as `stat`), `Uname`,
  `Rlimit(resource)`. Each new variant is a reviewed change (security-reviewer is CODEOWNER of the file).
  `sysinfo` stays out of M1, since macOS and Windows host sources are NotYet. When it lands, its variant
  uses a refresh kind without environ, cmdline, cwd and root. This matches 02's own cut ("keep only
  statvfs").

**MF-03. The probe facade, TLS and HTTP paragraph. Check code writes the proxy CONNECT.**
- Problem: `connect(Target::Proxy { proxy, host, port })` checks `host`, opens a socket to the proxy,
  and then `rdy-checks-net` writes the CONNECT line itself. The facade never sees the host actually
  requested. On the proxied path, which is the normal enterprise path, INV-11 (peers) and INV-12
  (literal metadata addresses in the CONNECT target) become advisory. Check code also handles the proxy
  password.
- Fix: the facade writes CONNECT from the `Target` (8 KiB response head cap, its own timeout, Basic auth
  from the `ProxyUrl` newtype, `Proxy-Authorization` never logged), parses the status, and returns a
  tunnelled `ProbeStream` or a typed error (`proxy_403`, `proxy_407 { scheme }`). TLS helpers take the
  `ServerName` from the `Target`, so SNI equals the permitted host. Log a `connect` to the proxy plus
  `http CONNECT host:port via proxy`, the shape in 01's example. Replay scripts proxies at this layer.

**MF-04. The Check trait paragraph and Decisions 5. The lint wall has holes, and some side effects have
no facade path.**
- Problem:
  - 02 says clippy bans `std::fs`, `tokio::fs`, `std::process`, `tokio::process`, `std::net` and
    `tokio::net`. clippy matches exact item paths, with no module wildcard, so only the real list
    counts. The exit test covers two items.
  - Not covered: `rustix::fs`, `rustix::net` and `rustix::process` functions (except the id getters),
    `socket2`, `std::os::unix::net`, `std::net::UdpSocket` and `TcpListener`, `std::fs::OpenOptions`,
    `std::thread::spawn`, `tokio::spawn` (see SF-09), `Box::leak` and `String::leak` (they defeat the
    `&'static str` program rule), and crates that open their own files or sockets (`hickory-resolver`,
    `sysinfo`, `walkdir`, `reqwest`, `kube::Client` constructors).
  - One `#[allow(clippy::disallowed_methods)]` in check code switches it off without a trace.
  - No facade path for `bind` (03 `host.ports`, M1, "bind fallback"), UDP (03 `host.time_sync` SNTP and
    `net.dns` direct queries, M1-late) or unix sockets and named pipes (03 `host.container_runtime`,
    M1-late, a root-equivalent API).
- Fix:
  - `clippy.toml` lists every item above in `disallowed-methods` and `disallowed-types`. A
    `tests/lint-wall` crate uses each one, and CI expects each to fail.
  - CI grep: `allow(clippy::disallowed_` may appear only in an allowlisted file (the live backend), the
    same mechanism as INV-18.
  - `deny.toml` `[bans]` with `wrappers`, so `rustix`, `socket2`, `hickory-*`, `sysinfo`, `kube`,
    `hyper` and `tokio-rustls` may be direct dependencies only of the crates that own them.
  - M1: drop the `host.ports` bind fallback and report "owner unknown, not verified". A bind on a
    production host can take a port that a restarting service needs.
  - M2 gate: `udp_exchange` and `unix_connect` facade methods (the second with a GET-only Docker API
    guard) land before `host.time_sync`, direct `net.dns` queries and `host.container_runtime`. Remove
    `permit_nameserver` from the M1 API.

**MF-05. Result model steps 6 and 7, and "Human output". Redaction runs after truncation, and logs are
not covered.**
- Problem:
  - Caps are applied "before redaction". A cap that cuts through a secret leaves a fragment no pattern
    matches: a PEM block without its END line, a key cut at 12 characters, a URL cut inside its
    userinfo. Redaction can also lengthen a value (`[REDACTED:aws_access_key_id]`), so a cap applied
    first is not a cap.
  - 02 says nothing about the redacting `tracing` layer. Its SEC-25 exit test drops 05's "stderr at
    `RUST_LOG=trace`" clause. kube, hyper and h2 at trace can print request headers, including the
    kubeconfig bearer token (INV-15, 05 I2).
  - `EngineError` text and panic messages are printed but not said to be redacted.
- Fix:
  - Order: redact every full string, then cap. A cap cuts on a char boundary and appends a marker.
  - Install the redacting log layer first in `main`, before the spec is read. When `RUST_LOG` is unset,
    cap hyper, h2, rustls, tower and kube at warn. When it is set, lines are still redacted.
  - The CLI redacts `EngineError` and `ReportError` text. The panic hook prints only the redacted
    message (ADR 0008 point 8).
  - Restore 05's SEC-25 exit test word for word.

**MF-06. Verdict rule and "How checks degrade". A "not applicable" escape bypasses the verdict rule.**
- Problem: 02 has three ways for a check to have no verdict effect: the spec's `os` filter,
  `Support::NotApplicable`, and a runtime `CheckError::NotApplicable(&str)` from check code. The last two
  are our code, not the vendor's statement. One bug or one wide condition turns a required check into
  nothing, which is a false READY. 01 sections 5.2 and 5.3 already decided otherwise: only `excluded`
  (the spec's `os` list) does not count; a requirement met by absence returns `pass` with a note; every
  other case is `unsupported_os` and counts as not run. 02 says 01 wins on names, but this is meaning.
- Fix: delete `CheckError::NotApplicable` and `Support::NotApplicable`. `Support::NotYet` and
  `CheckError::Unsupported` map to `skipped`, `unsupported_os`. Pass by absence (`host.lsm` with
  `allow: [disabled]` on Windows) is a `Finding` with level Pass and a note, reviewed per check. A table
  test asserts that only the spec `os` filter produces `excluded`.

**MF-07. Scheduling and "How the engine runs". A check that never yields hangs the run with no report.**
- Problem: the per-check timeout is `tokio::time::timeout` inside the spawned task. If the check
  blocks its worker thread (a sync call on an async thread, a CPU loop on a big input, or the kube exec
  credential plugin, which kube runs itself; verify whether it blocks a worker), the timeout future is
  never polled. ADR 0004 sets `worker_threads = min(4, cores)`. On a 2-vCPU host two stuck checks stall
  the scheduler too. A plugin waiting for an SSO browser login is a common real case. The customer
  kills `rdy` and gets nothing.
- Fix:
  - The scheduler awaits each `JoinHandle` under the timeout, so the timer lives in the scheduler task,
    not in the check. On expiry: abort, record Timeout, move on.
  - A plain OS watchdog thread, started before the runtime, fires at run deadline plus 10 s. It writes
    the report from a shared snapshot of finished results, with `run.complete: false` and unfinished
    checks as `error`, `interrupted` (01 section 5.3 already defines this), redacted, through the
    already-open output dir (SF-03). Then it calls `std::process::exit(70)`.
  - On the normal path the CLI writes the report, flushes, and calls `std::process::exit(code)`.
    `shutdown_timeout(1s)` stays, but nothing waits on a drop.
  - The KubeContext probe builds the client and sends its first request on a dedicated thread under
    the 10 s probe timeout, so a blocked plugin costs one abandoned thread, not a worker.
  - Tests: `Fake::Spin` (a future that never returns from poll) and a fake exec plugin that sleeps
    600 s each end with a report within the deadline plus 12 s.

**MF-08. The action log. Completeness has four gaps.**
- Problem:
  - Kube entries are written from the response future. A request whose future is dropped (check
    timeout, cancel) reached the API server but leaves no entry.
  - The exec plugin entry is logged with outcome `Ok` before anything ran, and a token refresh during
    the run runs it again with no entry.
  - 01 caps the log at 5000 entries and truncates the action log first when the report passes 2 MiB,
    with no rule on which entries go. That can drop exec, connect and refused entries, the ones a
    reviewer reads first.
  - `assert_within_manifest` proves conformance, not completeness. It cannot see a side effect that
    skipped the facade.
- Fix:
  - The guard creates the kube entry in `call` (outcome pending, check id from a request extension
    when present, else null) and the response future completes it. A drop guard marks it `cancelled`.
  - Plugin entry: kind `exec`, target the resolved absolute plugin path and its args (redacted),
    outcome `delegated`, detail "run by the kube client, output not captured, may run again on token
    refresh".
  - Coalescing and truncation only ever remove `file_read`, `dir_list` and `stat` entries with outcome
    `ok`. Exec, connect, tls, http, dns and kube entries, and every refused or denied entry, are always
    kept. They are bounded (64 hosts, a fixed command list).
  - Linux CI runs the live fixture suite under `strace -f -e trace=execve,openat,connect,sendto` and
    asserts that every target after spec load is in the action log, with an allowlist for the
    runtime's own startup reads. Fold into SEC-22.

**MF-09. Needs, rule 7, and SEC-20. The privilege-carrying binary check is incomplete (INV-10).**
- Problem: only real against effective uid is checked. INV-10 also requires gid against egid and, on
  Linux, `CapEff` nonzero for a non-root uid (file capabilities). A `setcap cap_dac_read_search+ep` or
  setgid install passes.
- Fix: check uid, euid, gid, egid and Linux `CapEff` from `/proc/self/status`, before the spec is read.
  Exit 70 with a hint naming `chmod u-s,g-s` and `setcap -r`. Fold into "Check trait, Need and Context"
  as 05 does, and extend the exit test to all three cases.

**MF-10. Report renderers, embedded JSON bullet, and the ADR 0003 correction bullet. 02 repeats the bug
it found.**
- Problem: 02 writes "`<`, `>` and `&` become `<`, `>` and `&`". The escapes were lost in 02's own text,
  exactly as in the old ADR 0003. An implementer reading 02 builds no escaping.
- Fix: spell the bytes out, as ADR 0003 decision 4 now does: each `<` becomes the six characters
  `\u003c` (backslash, `u`, `0`, `0`, `3`, `c`), `>` becomes `\u003e`, `&` becomes `\u0026`. Point to 01
  section 5.5: the JSON writer applies them, plus U+2028 and U+2029, to every copy, so the `.json` file,
  `--json` stdout and the HTML embed are the same bytes. The renderer does not escape a second time.

## Should fix

**SF-01. Check trait (`peers`) and Network row. The declared touch list for the network is per class,
not per check.**
- Problem: `peers: Peers` is one class, and the allowlist is built once from all net params. Any net
  check can reach any host another check lists, and a check that needs two classes cannot say so. 02
  caps 64 endpoints per spec. 01 allows 64 per entry and 256 overall.
- Fix: `peers: &'static [PeerClass]`, plus a per-check host set computed in `Family::build` from that
  check's own params. Derived defaults (`net.tls_intercept` from `net.egress` hosts) are resolved at build
  time and appear in the plan. The facade checks against the calling check's set. One cap: 64 distinct
  hosts per spec, validated in rdy-spec (exit 64).

**SF-02. Files row. Path handling as root.**
- Problem: canonicalize-then-open leaves a window when root reads under a user-writable directory. A
  component-wise prefix test accepts `/sys/fs/cgroup/../../etc/shadow`. A FIFO or device under an
  allowed prefix blocks a thread or returns device data. The deny list lacks `/proc/*/cmdline` (05 I5),
  `/proc/*/fd/*`, `/proc/*/root/*`, `/proc/*/map_files/*`, `/proc/kcore` and `/dev/*`.
- Fix: refuse relative paths and any `..` component before matching. Open first (`O_NOFOLLOW`,
  `O_NONBLOCK`), then check prefix and deny list against the real path of the open descriptor (Linux
  `/proc/self/fd/<n>`, macOS `F_GETPATH`). `fstat`: regular files only, except under `/proc` and `/sys`.
  Add the missing deny entries.

**SF-03. "How the engine runs", Output, and SEC-19. Output confinement details.**
- Problem:
  - The directory is created at the end of the run. That costs a whole run before exit 70, and the
    parent can change between start and write.
  - After `create_dir`, the handle is opened by name. In a shared writable parent the name can be
    swapped for a symlink to another directory in that parent.
  - The source of the spec copy is unstated. Re-reading it from disk writes bytes nobody verified.
  - `--out <dir>` (the directory itself) conflicts with ADR 0003 `--out-dir` (the parent).
  - `write_atomic(name, &[u8])` takes any bytes, so nothing forces redaction before write.
- Fix: create and open the directory right after spec verification, before the first check, and hold
  the handle. Open with `open_dir_nofollow`, then `fstat`: owned by euid and mode 0700, or exit 70.
  Copy the spec and `.minisig` from the verified in-memory buffers. Re-check the slug with ADR 0003's
  pattern. Use ADR 0003's `--out-dir`. Writers take `&RedactedReport` (a newtype only the engine's
  redaction pass builds) and `&VerifiedSpecBytes`. `fchmod` after create (umask), `fsync` the
  directory after rename.

**SF-04. TLS and HTTP paragraph. What replaces reqwest must be stated.**
- Problem: with reqwest gone, the platform verifier is gone too, and 02 names no verifier. ADR 0009's
  rule that the recording verifier is "unreachable from `net::client()`" has no equivalent. Body caps
  disagree: ADR 0009 4 KiB, 05 INV-13 64 KiB, 02 a 1 MiB stream cap.
- Fix: in ADR 0014, verify net checks with `rustls-native-certs` roots and webpki (see the ADR 0009
  section below). The HTTP helper accepts only a `VerifiedTls` stream type that the recording verifier
  cannot produce. Turn default features off on rustls, tokio-rustls and kube so only ring is linked.
  One body cap: 64 KiB read then discarded (INV-13), with the `net.bandwidth` byte cap declared in its
  `CheckInfo`. The M2 upload client uses the same helper, and `deny.toml` bans reqwest.

**SF-05. Crate shape and the k8s corrections. Kube client construction.**
- Fix:
  - One constructor, `guarded_service(inner)`, used by production and by the mock tests, so tests
    exercise the real layer order.
  - `ReadOnlyClient` newtype with a private constructor. clippy bans `kube::Client::new`,
    `Client::try_default` and `Config::infer` outside one module.
  - kube opens its own sockets. Supply kube's HTTP connector built on `Probe::connect`, or at least log a
    `connect` to the API server address and apply the INV-12 address rule to it.
  - With `--no-network`, KubeContext is unavailable and no kube client is built.

**SF-06. Needs table, Root row. One privilege answer per run, taken before the spec is read.**
- Problem: the Root probe runs after planning. The trust store choice (05 surface 2 requirement 3, and
  01 section 4.3, where an elevated Windows run reads only `%ProgramData%`) happens at spec load,
  earlier. Two privilege answers in one run is how a planted pin gets trusted. The Windows test looks
  only for `S-1-16-12288`. A SYSTEM run (`S-1-16-16384`, common under deployment tools) reads as not
  elevated and would read a user store.
- Fix: a `Privilege` snapshot at startup, before spec load. Unix: uid, euid, gid, egid, `CapEff` (also
  feeds MF-09). Windows: integrity level from `whoami.exe /groups` through the facade (check null).
  High or System means elevated. If `whoami` fails, treat the run as elevated for the trust store
  (system store only) and Root as unknown for checks. The rdy-spec trust store loader takes the snapshot
  as a parameter and never reads ids itself. The Windows probe stays in M1.

**SF-07. "How the engine runs", Windows. Exec without job objects contradicts ADR 0004 decision 5.**
- Fix: in M1 the facade allows exec on Windows only for `whoami.exe`. Windows sources that run
  commands (03 `NETSTAT.EXE`, `netsh`) and `custom.exec` depend on the job object ticket. ADR 0004
  records the M1 restriction.

**SF-08. Verdict rule and Needs rule 4. Three more false-READY paths.**
- Fix:
  - Partial results: the engine, not code review, maps level Pass with `partial` set on a
    block-severity check to `warn`, "not verified: <missing>". A want marked `evidence_only` in
    `CheckInfo` (it cannot change the level; reviewed) is the exception.
  - Nothing verified: 02 maps it to warnings and 01 maps an all-`excluded` run to `ready`. Both let a
    `[ $? -le 1 ]` gate pass a host where nothing was measured. Make it `not_ready` with reason
    `nothing_verified`, in ADR 0013.
  - Names: use 01's verdict and skip-kind names. `RunDeadline` and `Cancelled` either become 01's
    `timeout` and `error`, `interrupted`, or 01 adds `skip_kind: run_deadline`. `Report::interrupted`
    becomes `run.complete`.

**SF-09. The probe facade. A `Probe` clone can outlive its check.**
- Problem: `Probe` is `Clone`. A check can move a clone into `tokio::spawn` or `blocking` and keep
  acting after its timeout or abort, outside its deadline and with a wrong attribution.
- Fix: each check scope carries a cancellation token, cancelled when the check ends. Every `Probe`
  call checks it first and returns `Denied { rule: "check finished" }`, logged. clippy bans
  `tokio::spawn` and `std::thread::spawn` in check crates (MF-04).

**SF-10. Custom checks later. Two statements conflict with ADR 0005.**
- Problem: point 2 allows a bare `--allow-exec` or an interactive yes. ADR 0005 requires
  `--allow-exec=<sha256 of the exec plan>` and refuses the bare flag. Point 4 says `Need::Root` only
  makes a check skip, and misses ADR 0005's rule that under euid 0 a custom command runs as an
  unprivileged user unless it declares `needs: [root]`. 02 says `--plan`; ADR 0005 says `--dry-run`.
- Fix: restate ADR 0005 in point 2 and point 4. Pick one flag name with cli-ux. The rest is in "The
  custom.exec seam" below.

**SF-11. Testing seams. Small additions that make the invariants testable.**
- Fix:
  - Replay `lookup` returns recorded addresses, including link-local cases, so the address rule runs in
    every net fixture.
  - Add `Fake::Spin` to the scheduler tests (MF-07).
  - The kind job enables an API server audit policy and asserts that requests with rdy's user agent use
    only allowlisted verbs and resources. A third line behind the guard and the mock.
  - One guarded kube constructor for tests and production (SF-05).

**SF-12. Throughout. Traceability to 05 and the backlog.**
- Problem:
  - 02 cites 05 revision 1 numbers. Every INV reference is one low: 02's INV-05 is now INV-06, INV-06
    is INV-07, INV-07 is INV-08, INV-08 is INV-09, INV-09 is INV-10, INV-10 is INV-11, INV-11 is INV-12,
    INV-12 is INV-13, INV-13 is INV-14, INV-14 is INV-15, INV-16 is INV-17.
  - SEC-17, SEC-19 and SEC-25 carry titles that differ from 05 and from 00 (three titles for SEC-17).
    SEC-18, SEC-20 and SEC-23 do not exist in 05 revision 2. They duplicate ADR 0004 "Blocking helper and
    subprocess kill on timeout", 03 "Command runner", ADR 0010 "Read-only guard layer and test" and the
    05 fold on "Check trait".
  - Stale corrections: ADR 0008 decision 3 already has the not-run rule; 05 INV-06 already makes unknown
    ids Skipped; 05 SEC-53 is already M3.
  - "M1 lands near 160 h" uses an old 00 total. 00 says 194 h.
- Fix: renumber, reuse the 05 titles exactly, drop the duplicate SEC ids, delete the stale bullets, and
  use the hour figures below.

**SF-13. Alignment with 03.**
- Problem: 03 `net.proxy` (M1) fetches PAC files. That contacts a host from local configuration, not
  the spec. The facade refuses it, so a block-severity `net.proxy` errors and the run is NOT READY.
  03 `net.egress` and `net.registry` still follow redirects (02 records this already).
- Fix: in M1, `net.proxy` reports the PAC URL and says rdy does not fetch or evaluate PAC. No fetch.

## Nits

- **N-01. Per-check timeout.** `min(spec timeout, default, 60 s, ...)` means a spec can never raise a
  timeout above the check default, and 01 allows 1 s to 120 s. Pick one cap with 01; a spec value
  replaces the default.
- **N-02. Features.** Move `redact` out of the `runtime` feature, so `html`-only users and the M2
  `rdy report` can call it without tokio.
- **N-03. Run-level side effects.** Machine id for `host_id` (01 section 5.1), hostname, os-release, the
  `Command` need stats and the kubeconfig read go through the facade with `check: null`.
- **N-04. Spec values in argv.** Rely on 01's Target and Path grammars (no leading `-`) and add `--`
  before operands where the program supports it.
- **N-05. `--jobs`.** Restate ADR 0004's cap of 32 in `RunOptions`.
- **N-06. Root hint.** The "rerun as root" hint never suggests `sudo -E`.
- **N-07. SEC-19 exit test.** "A killed run leaves no partial file" should read "no file under a final
  name"; `.tmp` files stay inside the new directory.
- **N-08. HTML action log.** 02 says collapsed `<details>` per check; 01 section 6 says no `<details>`
  and one table. Follow 01.

## Invariant coverage

| Invariant | In 02 | Finding |
| --- | --- | --- |
| INV-01 verify before parse | `Engine::run` takes `LoadedSpec`; verify comes before plan | covered |
| INV-02, 03, 05 | rdy-spec and CLI scope | not 02 |
| INV-04 root-only trust store | not mentioned; privilege known only after plan | SF-06 |
| INV-06 unknown ids | Skipped, counts as not run | covered (05 wording to fix) |
| INV-07 facade only | native, lint wall, CONNECT, kube sockets, `Probe` clones | MF-02, MF-03, MF-04, SF-05, SF-09 |
| INV-08 no shell, fixed PATH | stronger than 05 | covered, SF-07 |
| INV-09 output dir | cap-std, 0700 and 0600, temp plus rename | SF-03 |
| INV-10 privilege-carrying binary | uid only | MF-09 |
| INV-11 peers | global, per class; CONNECT unchecked | MF-03, SF-01 |
| INV-12 metadata addresses | direct path covered; proxied path not | MF-03 |
| INV-13 bodies | not stored; three caps | SF-04 |
| INV-14 kube | allow-by-default GET, dry run | MF-01 |
| INV-15 redaction | after caps; logs missing | MF-05 |
| INV-16 HTML | ADR 0003 and 01 correct; 02 text wrong | MF-10 |
| INV-17 control characters | CLI strips | covered |
| INV-18 unsafe | Windows elevation via `whoami.exe`, no FFI | covered |
| INV-19, INV-20 | install and upload scope | not 02 (SF-04 for upload transport) |

## ADR 0009 amendment: sound, with costs

Net checks speaking TLS and HTTP over facade-opened sockets is sound, and better than ADR 0009. One
place enforces peers, the address rule and the log, and Replay can drive it. reqwest's resolver hook
only covered direct connections. Its proxy and redirect logic would have been a second policy surface
that we do not control. ADR 0009 already writes its own CONNECT and runs tokio-rustls for
`net.tls_intercept`, so most of the code exists. What it costs:

- **Code we now own.** The CONNECT client (MF-03), absolute-form requests for `http://` through a
  proxy, and `NO_PROXY` matching (suffix, leading dot, `*`, CIDR, port, upper and lower case). That is
  security-relevant parsing with test cases from 03's loopback servers. About 1 to 2 h more than the
  3 h "Shared HTTP client builder" ticket it replaces.
- **Trust store.** The platform verifier goes with reqwest. Use `rustls-native-certs` roots with webpki.
  On Linux it reads PEM bundles and honours `SSL_CERT_FILE`, which is 05's stated residual (NSS-only or
  Java-keystore CAs are invisible). On macOS and Windows it loads the OS roots but not OS policy
  (distrust lists, constraints, revocation). Do not use `rustls-platform-verifier` in M1: on macOS and
  Windows it hands the chain to the OS, which can fetch AIA, CRL and OCSP URLs over the network,
  outside the facade and the INV-11 peer set, where Replay cannot reproduce it. The report says
  "verified against the system root store, no revocation check". This reverses ADR 0009 decision 2's
  reason ("what the customer's software sees") for macOS and Windows hosts, which are rare targets.
- **Through a proxy** the address rule can check only the CONNECT target string. Literal IPs are
  refused, names resolve at the proxy. Already a 05 residual; the report says so.
- **HTTP/2** is gone unless hyper's http2 and ALPN are added. M1 egress measures HTTP/1.1 only.
  Acceptable; record `alpn` in evidence.
- **Proxy auth** stays Basic only. SOCKS and PAC stay unsupported. Same as ADR 0009.
- **Two TLS stacks remain.** kube keeps its own hyper and rustls. Both must link ring only (SF-04).
- **M2 upload.** Keep it on the same helper (SF-04). Otherwise reqwest returns as a named exception in
  INV-07 and INV-11, with its own sockets.

ADR 0014 should carry all of this, supersede ADR 0009 decisions 1 to 3 and 5, and keep 4 and 7. Decision 6
(hickory opens its own sockets) waits for the M2 UDP facade method (MF-04).

## The custom.exec seam

What 02 leaves open is the right size: a second exec policy on the same `Probe::exec`, a `Cmd` origin
enum added in M3 and not before, the consent list taken from the plan, and a fresh temp directory.
Unknown ids skip and count as not run, so an M1 binary given `custom.exec` never runs it and never passes
it. Nothing in M1 makes M3 unsafe if these hold:

1. `Cmd.program: &'static str` stays the only M1 constructor, with `Box::leak` and `String::leak` banned
   in check crates (MF-04).
2. The root-only trust store rule ships in M1 with one privilege snapshot (SF-06). With `custom.exec`, a
   planted pin becomes code execution as root.
3. The `exec` action entry stores the resolved absolute path and argv as an array. 01 section 5.4 joins
   argv with spaces, which is ambiguous. The M3 consent hash and the log must describe the same thing.
4. Windows job objects come before `custom.exec` on Windows (SF-07).
5. 02 follows ADR 0005 on hash-bound consent and the run-as rule (SF-10).

## ADR 0003 escaping bug

Confirmed, and confirmed fixed in ADR 0003 decision 4 as it now reads: each `<`, `>` and `&` in the
serialized JSON becomes the six-character JSON escape (backslash, `u`, four hex digits: `\u003c`,
`\u003e`, `\u0026`). That is correct. serde_json emits those characters only inside strings, any JSON
parser decodes the escapes back to the exact report, and with no literal `<` left, neither `</script`
nor `<!--` can occur inside the script element. 01 section 5.5 adds U+2028 and U+2029, applies the
escapes in the writer for every copy, and adds `data-sha256`. Both are fine. The same loss of escapes is
in 02's own text (MF-10) and in the fix line of my ADR review MF-03 (Plan corrections). Whatever tool
wrote those lines decoded the escapes, so spell them out in prose wherever they matter.

## M1 hours

02 adds about 44 h of new tickets plus 20 h of SEC tickets. Against 00's 194 h, the real addition is
about 51 h, because SEC-17, 19 and 25 are already in 00 and SEC-18, 20 and 23 duplicate existing tickets.
That takes M1 to about 245 h.

| 02 ticket | 02 h | Call | M1 h |
| --- | --- | --- | --- |
| Write ADR 0013 | 1 | Essential. One ADR shared with 01, carrying 01's amendments and SF-08 | 1 |
| Write ADR 0014 | 1 | Essential. Also records the 0015 and 0016 decisions and the verifier | 1.5 |
| Write ADR 0015, Write ADR 0016 | 2 | Merge into 0014 | 0 |
| Family trait, registry and run plan | 3 | Keep. Needed for lazy needs and `--plan` | 3 |
| Amend verdict mapping | 2 | Fold into "Define result model and verdict mapping in rdy-spec" | 0.5 |
| Capability probes | 3 | Essential (INV-04, SF-06). Moves to startup | 3 |
| Family probe hook and lazy KubeContext | 2 | Essential (E5: no plugin runs without k8s checks) | 2 |
| Family limits, run deadline and Ctrl-C | 3 | Run deadline is essential, folds into the scheduler. Per-family limits and graceful Ctrl-C go to M2 | 1 |
| Map outcomes, fix source, partial, caps | 2 | Keep. Caps after redaction (MF-05) | 2 |
| File and env read policy | 3 | Essential (I5), plus SF-02 | 3.5 |
| Network permits | 3 | Essential, same exit test as SEC-21: merge. Plus MF-03 and SF-01 | 1.5 |
| Native call recording | 2 | Essential as a closed enum (MF-02) | 2 |
| Replay backend and fixture loader | 4 | Merge with 03 "Fixture loader and golden compare" and the command runner replay | 2.5 |
| Engine test helpers | 2 | Keep | 2 |
| Clippy disallowed-methods | 1 | Essential (INV-07), widened (MF-04) | 2 |
| Apply the redactor to every Report string | 2 | Essential (INV-15) | 2 |
| HTML grouping and action log | 3 | Keep 01's action log table and the product label. Grouping is in the askama ticket | 1 |
| OS support table and stubs | 2 | Keep (four-target CI) | 2 |
| Security review, cli-ux review | 3 | Keep | 3 |
| **New block** | **44** | | **35.5** |

The SEC block shrinks to its real deltas: SEC-17 +1, SEC-18 merged into "Blocking helper" (+0.5),
SEC-19 +1, SEC-20 folded (+0.5), SEC-23 replaces ADR 0010's 3 h guard ticket (+1.5), SEC-25 0. That is
4.5 h. The must-fix work adds 3 h inside existing tickets (watchdog, strace completeness, kind audit).
Net addition over 00: about 43 h, so M1 is about 237 h, roughly 18 weeks at 13 hours a week.

Security-essential in M1, not deferrable without breaking an invariant: the facade and action log,
exec, file and network policy, the closed native enum, the lint wall, the kube guard, output
confinement, the privilege snapshot and binary refusal, redaction of the report and the logs, per-check
timeouts with the run deadline and the watchdog, the verdict mapping, and the lazy kube need.

Deferrable with no invariant weakened: per-family concurrency limits, graceful Ctrl-C (a plain abort
leaves only `.tmp` files inside the new directory), HTML regrouping beyond 01's contract, and ADRs 0015
and 0016 as separate files. Optional merges worth about 3 h more: engine test helpers into the fixture
loader, the family probe hook into the kube client ticket. The rest of the gap is scope, which is the
founder's call in 00, not something security can cut.

## Inconsistencies with 01-spec-format.md

1. Product slug. 01 2.2 allows `^[a-z0-9][a-z0-9._-]{0,63}$`. ADR 0003 decision 1 and the ADR README
   review notes chose `^[a-z0-9][a-z0-9-]{0,62}$` and rejected dots on purpose. 01 must take ADR 0003's
   pattern. This feeds the output directory name.
2. Timeout range. 01 2.3: 1 s to 120 s. 02: 60 s cap. ADR 0004: 10 s default (N-01).
3. Skip kinds. 02: MissingNeed, NotYetOnOs, NotApplicable, NeedsNewerRdy, RunDeadline, Cancelled. 01:
   `missing_need`, `not_in_build`, `unknown_check`, `unsupported_spec`, `unsupported_os`, `excluded`
   (SF-08).
4. "Not applicable". 02 lets check code skip with no verdict effect; 01 allows that only for `excluded`
   (MF-06).
5. Verdict and summary names. 02: Blocked, Warnings, `not_run`, `not_applicable`. 01: `not_ready`,
   `ready_with_warnings`, `optional_not_run`, `excluded`, with separate counts per status.
6. Interrupted runs. 02: `Report::interrupted` and `Skipped(Cancelled)`. 01: `run.complete: false` and
   `error`, `interrupted`.
7. Fix source. 02: `spec` or `rdy`. 01: `spec`, `builtin`, `rdy` plus `builtin_fix`, and the vendor fix
   is hidden on non-run statuses. 01 is better; 02 follows it.
8. Partial. 02: `partial { missing, note }`. 01: `partial: true` plus `needs[].met`.
9. Action log. Kinds: 02 has `stat`, `env`, `native` and coalesced entries that 01 lacks. Outcomes:
   02's `Denied { rule }` is 01's `refused`, and 01's `denied` means something else. 01 joins argv with
   spaces. 01's 5000-entry cap and "truncate the action log first" (MF-08).
10. HTML. 02: collapsed `<details>` per check. 01: no `<details>`, one table (N-08).
11. Endpoint cap. 02: 64 per spec. 01: 64 per entry, 256 overall (SF-01).
12. `k8s.admission` `dry_run` and `probe_pod` in 01 2.7 against 05 INV-14 and ADR 0010 (MF-01).
13. 01 section 6 CSP lacks `base-uri 'none'; form-action 'none'` from ADR 0003 decision 3.
14. 01 4.3 trust store refusal covers group and world writable files and the owner, but not a symlinked
    file or a writable parent directory (05 INV-04).
15. Embedded JSON. 02 escapes at embed time; 01 escapes in the writer for every copy. 02 follows 01.

## ADRs that look mid-edit

- ADR 0003 decision 4: one long unwrapped line inside a wrapped paragraph. The content is correct.
- ADR 0010: decision 2 does not allow POST to `selfsubjectreviews`, but decision 4 needs
  SelfSubjectReview and 01's example run sends it. Decision 3 still says the client is "shared through
  the engine Context", which the ADR README review notes reversed. It still uses `--kube-context`.
- ADR 0009 still describes reqwest and the platform verifier, and 00 still carries its ticket title.
- ADR 0004 decision 5: fixed PATH only as root, job objects on Windows. 02 differs on both.
- ADR 0008 decision 3 already carries the not-run rule, while 01 and 02 both say it must be
  superseded. The README index has no 0013, though 01 says 0013 was written with it.
- ADR 0005 uses `rdy run --dry-run`; 02 and 05 use `--plan`.

## Plan corrections found

- docs/plan/05-threat-model.md (mine), INV-06: "cap the verdict at Warnings" is wrong after ADR 0008
  and 01 section 5.3. Fix in revision 3: unknown ids and fields skip and count as not run, so a
  block-severity one gives `not_ready`.
- docs/plan/05-threat-model.md, INV-08 and Appendix A S2: fixed PATH "as root". Fix: always (02).
- docs/plan/05-threat-model.md, INV-11, INV-12 and SEC-21: "redirect hops (max 5)". Fix: redirects are
  recorded, not followed (ADR 0009, 02). My ADR review MF-05 asked for followed hops; that is withdrawn.
- docs/plan/05-threat-model.md, INV-07: add `TcpListener`, `UdpSocket`, `UnixStream`, `OpenOptions`,
  `rustix` fs and net, `socket2` and thread spawning to the list (MF-04).
- docs/plan/05-threat-model.md, INV-14: state the deny-by-default resource list, the path rules and "no
  dry run in M1" (MF-01).
- docs/plan/05-threat-model.md, surface 2 requirement 3: add 01's rule that an elevated Windows run
  reads only the system store, with the SYSTEM integrity level counted as elevated (SF-06).
- docs/plan/reviews/adr-and-00-review-by-security-reviewer.md (mine), MF-03 fix line: the escapes
  printed as plain `<`, `>`, `&`. ADR 0003 got it right anyway. Do not copy from that line.
- docs/plan/03-check-catalog.md, `host.ports`: drop the bind fallback in M1 (MF-04). `net.proxy`: no
  PAC fetch in M1 (SF-13).
- docs/plan/00-overview.md, M1 calendar: with 02 after this review, M1 is about 237 h, not 194 h.

## Decisions needing an ADR

- **ADR 0014, TLS verifier for net checks.** Options: `rustls-native-certs` with webpki, or
  `rustls-platform-verifier`. Conservative choice: native certs with webpki, no OS revocation fetches.
- **ADR 0013, nothing verified.** Options: `ready` (01), `ready_with_warnings` (02), `not_ready`.
  Conservative choice: `not_ready` with reason `nothing_verified`.
- **ADR 0010 amendment, kube allowlist.** Deny-by-default resource list, `selfsubjectreviews` added, no
  dry run or probe pod in M1. Conservative choice: as stated in MF-01.
- **M2 upload transport.** Options: the facade HTTP helper, or reqwest as a named exception.
  Conservative choice: the helper.

## Tickets implied

- [M1] Revise 02-engine-design.md for security review must-fix items MF-01 to MF-10 | owner: rust-architect | est: 2h | depends on: none | exit test: every MF in docs/plan/reviews/02-engine-design-review-by-security-reviewer.md is marked closed in 02 or answered in this file, and security-reviewer signs off.
- [M1] Update 05-threat-model.md to revision 3 for 01 and 02 | owner: security-reviewer | est: 1h | depends on: Revise 02-engine-design.md for security review must-fix items MF-01 to MF-10 | exit test: INV-06, INV-07, INV-08, INV-11, INV-12, INV-14 and SEC-21 match 01, 02 and ADR 0009, and the invariant ids are unchanged.
- [M2] Facade methods for UDP exchanges and unix sockets with a GET-only Docker API guard | owner: rust-engineer | est: 4h | depends on: SEC-17 Mediated Context handles with action log and read denylist | exit test: an SNTP query to a server not in spec `ntp_servers` and a POST on the Docker socket are refused and logged, and host.time_sync and host.container_runtime depend on this ticket.

Folds (extra exit-test clauses on existing tickets, 7.5 h in total, counted in "M1 hours" above):

| Existing ticket | Added clause | +h |
| --- | --- | --- |
| SEC-23 Enforce Kubernetes request allowlist (replaces ADR 0010 "Read-only guard layer and test") | MF-01 path rules and allowlist, MF-08 entry written in `call` | 1.5 |
| Check trait, Need and Context in rdy-engine | MF-09 gid and CapEff | 0.5 |
| SEC-19 Confine writes to a new output dir with safe names | SF-03 early open, nofollow and fstat, spec bytes from memory, `RedactedReport` | 1 |
| SEC-17 Mediated Context handles with action log and read denylist | MF-08 truncation rules, SF-09 scope token | 1 |
| Blocking helper and subprocess kill on timeout (absorbs SEC-18) | Fixed PATH always, loader variables refused | 0.5 |
| Scheduler with concurrency limit, per-check timeout and panic isolation | MF-07 JoinHandle timeout, watchdog, `process::exit`, `Fake::Spin` | 1 |
| SEC-22 No-phone-home strace test on Linux CI | MF-08 strace comparison against the action log | 1 |
| SEC-24 Read-only ClusterRole example and kube identity display | SF-11 kind audit-log assertion | 1 |
