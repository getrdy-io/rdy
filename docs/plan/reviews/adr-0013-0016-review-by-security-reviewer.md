# Security review of ADRs 0013 to 0016, 02 revision 2 and the 08 in-process entry point

Reviewer: security-reviewer. Author of the reviewed files: rust-architect (ADRs, 02), qa-engineer (08).
Date: 2026-10-28. Checked against 05-threat-model.md revision 2 (INV-01 to INV-20), my review of 02
(`02-engine-design-review-by-security-reviewer.md`, MF-01 to MF-10), ADRs 0004 and 0008 to 0012, 01 and
03 as they stand today. No reviewed file was edited.

## Verdicts

| Item | Verdict | Blocking items |
| --- | --- | --- |
| ADR 0013 verdict refinements | **Accept.** Move to Accepted. SF-09 and SF-10 land as edits, not gates. | none |
| ADR 0014 probe facade | **Changes required.** The enum is closed; the wall around it is not. | MF-04 |
| ADR 0015 redactor before caps | **Changes required.** Correct for report caps, wrong for facade caps. | MF-01 |
| ADR 0016 output dir via cap-std | **Changes required.** Sound on Linux, under-specified on Windows and macOS. | MF-02, MF-05 |
| 02 revision 2 | **Changes required.** Eight of my ten must-fix items are closed. | MF-02, MF-03, MF-06 |
| 08 in-process `rdy_cli::run` (amends ADR 0011 decision 4) | **Accept with conditions** (SF-08). Better than any fixture switch. | none |

Must fix: 6. Should fix: 13. Nits: 9.

## Status of the earlier must-fix list

| Earlier item | Status | Where |
| --- | --- | --- |
| MF-01 kube guard | Mostly closed: deny by default, path pre-filter, parsed path, no dry run, no subresources, global rules. Still open: the M1 list misses resources the M1 checks read, and `selfsubjectreviews` is deferred. | MF-03, MF-06, SF-05, SF-06 |
| MF-02 native closures | Closed in type (closed `NativeCall`, Live executes it). Not closed in effect: a new crate gives the same power. 08 still describes closures. | MF-04, SF-03, SF-04 |
| MF-03 check-written CONNECT | Closed. kube's own proxy CONNECT must be named in the exception. | SF-02 |
| MF-04 lint wall | Partly closed: bind fallback dropped, UDP and unix sockets gated to M2, allow grep, deny wrappers. Open: wildcard entries and no direct-dependency allowlist. | MF-04 |
| MF-05 redaction order and logs | Closed for report caps, the log layer and printed errors. Reopened one layer down, at the facade I/O caps. | MF-01, SF-07 |
| MF-06 not-applicable escape | Closed. Only the spec `os` list produces `not_applicable`. | SF-09, SF-10 |
| MF-07 non-yielding check | Closed in design: timer on the join handle, watchdog, `process::exit`, kube probe off the workers. The watchdog itself is unsafe as written. | MF-02, SF-12 |
| MF-08 action log completeness | Closed. | none |
| MF-09 privilege-carrying binary | Closed for uid, gid and `CapEff`. Saved ids and `AT_SECURE` are cheap additions. | SF-11 |
| MF-10 lost escapes | Closed. 02 line 348 spells out `\u003c`, `\u003e`, `\u0026`. | none |

Earlier should-fix items SF-01 to SF-13 are closed, except SF-03 on Windows (MF-05). SF-08 "nothing
verified" was decided against my conservative choice. I accept that decision (see ADR 0013 below).

## Must fix

**MF-01. ADR 0015 decision 2 and 02 "From finding to result". Facade caps cut secrets before the
redactor sees them.**
- Problem:
  - Redact-then-cap is right for the report field caps (message 1 KiB, `observed` 64 KiB, the 2 MiB
    report). But most strings are already truncated before they get there. The facade caps exec stdout
    at 1 to 4 MiB and stderr at 64 KiB, file reads at 1 MiB, and `read_tail` cuts from the front. The
    CONNECT head is capped at 8 KiB. Those cuts happen at I/O time, before redaction.
  - A PEM private key that runs past a stdout or file cap has a BEGIN line and no END line. An AWS key
    id cut by `read_tail` loses its `AKIA` prefix. A URL cut inside its userinfo has no `@`. A pattern
    that needs the whole token misses all three. This is the MF-05 failure mode, one layer lower.
  - The ADR's exit test (a PEM key across the 64 KiB report cap) does not reach this path.
- Fix:
  - `FileBytes` and `Output` carry `truncated_head` and `truncated_tail`. Before matching, the
    redactor drops the partial first line of a head-truncated buffer and the partial last line of a
    tail-truncated one. If there is no newline in the last 4 KiB, it drops the last 4 KiB. It puts the
    cap marker in their place.
  - The PEM rule matches an unterminated `-----BEGIN ... PRIVATE KEY-----` through to the end of the
    buffer.
  - Add a run-scoped known-secret set: the kubeconfig token and client key data, the `ProxyUrl`
    password, and the values of declared env names that match the secret-name rule. Redact exact
    matches, and any 8-character or longer prefix or suffix of one at a truncated edge.
  - Corpus: for each facade cap, a canary at offsets cap minus 1 to cap minus 64. These are M1 cases,
    not M2 (see Plan corrections).
  - Extend the ADR 0015 exit test to cover stdout, file and tail caps.

**MF-02. 02 "Scheduling", Watchdog, and ADR 0016 decision 6. The watchdog can overwrite a complete
report, and it can hang.**
- Problem:
  - Race. The run finishes near the deadline plus 10 s, and the CLI starts writing. The watchdog
    fires, writes its `complete: false` report through the same handle and renames it over the final
    name. A rename replaces the target on all three OSes. Or it calls `exit(70)` halfway through the
    CLI's write. Either way the customer gets a wrong or truncated file, or a good file with exit 70.
  - Hang. The watchdog does blocking work with no bound of its own: it takes the snapshot mutex,
    renders, writes, fsyncs, and with `--json` prints to stdout. A stuck thread can hold std's stdout
    lock (stdout piped to a reader that stopped), and the output dir can sit on a hung NFS mount. Then
    the watchdog blocks and the process never exits, which is the exact failure MF-07 was meant to
    remove.
  - "Already redacted" is assumed, not built. 02 redacts the whole report once at step 4, so a
    mid-run snapshot holds unredacted results and action entries.
- Fix:
  - One `AtomicU8` write state: `Running`, `Writing`, `Done`. Whoever moves it from `Running` to
    `Writing` writes. If the watchdog loses, it waits up to 5 s for `Done` and then exits 70 without
    writing. If the CLI loses, it parks.
  - The watchdog runs its write on a helper thread and waits at most 10 s. Then it calls
    `std::process::exit(70)` whatever happened. It never takes std's stdout or stderr locks. It writes
    one fixed stderr line with a non-blocking write, or nothing.
  - The snapshot lock is a `try_lock` loop with a 1 s bound. A poisoned lock uses `into_inner`. If no
    snapshot is taken, the watchdog writes a report with every check `error`, `interrupted`.
  - The watchdog builds its report with the same sync redact-then-cap pass (SF-07). It never trusts
    "already redacted".
  - Before the output dir exists, the watchdog exits 70 with no report.
  - Tests: a finish at deadline plus 9.9 s keeps the complete report. A blocked stdout pipe still gives
    exit 70 within deadline plus 22 s. A held snapshot lock still gives a report.

**MF-03. 02 Appendix B rule 3. The M1 allowlist does not cover what the M1 checks in 03 read.**
- Problem: deny by default is correct. But the const list misses reads that M1 checks make:
  - `k8s.storageclass` (M1): `storage.k8s.io` `csinodes` (its strongest driver evidence), core
    `persistentvolumeclaims` and `events` in the target namespace.
  - `k8s.nodes` (M1): `apps` `deployments` for `cluster-autoscaler` detection.

  Each of these is denied, the check reports `error`, and the run is NOT READY on a healthy cluster.
  The guard ticket's exit test ("only allowlisted GETs appear across the k8s suite") then fails, and
  the first fix under deadline pressure is a wide entry. Meanwhile `validatingadmissionpolicies` and
  their bindings are M1-late (03 section 4) but sit in the M1 list.
- Fix:
  - Add (core `persistentvolumeclaims`, namespaced LIST only), (core `events`, namespaced LIST only,
    with a `fieldSelector` on `involvedObject.kind=PersistentVolumeClaim`), (`storage.k8s.io`
    `csinodes`) and (`apps` `deployments`, GET by name from a const list of autoscaler names and
    namespaces, or namespaced LIST).
  - Move the two VAP entries to an `M1_LATE` block that is enabled with the webhook half of
    `k8s.admission`.
  - Each entry carries a comment naming the check and the field it reads. A unit test asserts every
    `ALLOWED` entry is cited by at least one check's `CheckInfo`, and that `secrets` appears nowhere.
  - k8s-expert confirms the list against 03 before the guard ticket starts.

**MF-04. ADR 0014 decisions 5 and 7, 02 "Lint wall" and Appendix A. The native enum is closed, but a
check author can get the same power without touching it.**
- Problem:
  - `NativeCall` lives in rdy-engine, so a check crate cannot add a variant. That part holds.
  - But the wall is a denylist of known paths. A check crate that adds `nix`, `walkdir`, `tempfile`,
    `which`, `ureq` or `sysinfo` under another name gets syscalls, file walks, writes or sockets that
    no clippy entry names. `deny.toml` wrappers cover only the crates listed. 05's "a new direct
    dependency needs security-reviewer approval" is a process rule, and with one maintainer and an AI
    agent typing, process rules are skipped.
  - Appendix A writes `std::fs::*`, `tokio::fs::*`, `rustix::fs::*`, `tokio::net::*`,
    `std::os::unix::net::*` and `rustix::net::*`. clippy's `disallowed-methods` matches exact paths. My
    earlier MF-04 said so, and I found no documented glob support. A wildcard entry is either rejected
    or matches nothing.
- Fix:
  - `ci/check-crate-deps.toml` lists the allowed direct dependencies of each check crate. Proposed
    list: `rdy-engine`, `rdy-spec`, `serde`, `serde_json`, `thiserror`, `futures-util`, plus `kube`
    and `k8s-openapi` for rdy-checks-k8s only, plus `x509-parser` for rdy-checks-net only. A 30-line
    CI script compares `cargo metadata` against it and fails on any difference. A change to the file
    needs a `security-review` label (SEC-04 CODEOWNERS).
  - Expand every wildcard into exact items. `tests/lint-wall` uses each item, and CI expects each one
    to fail.

**MF-05. ADR 0016 decisions 1 and 5. The Windows rules are missing, and the default directory
contradicts 05 I3.**
- Problem:
  - Decision 1 checks "owned by the effective user with mode 0700". Windows has no euid or mode bits,
    and cap-std metadata exposes no owner. As written the check either does nothing or fails every
    Windows run.
  - The default `--out-dir` is `.`. 05 Appendix A I3 (M1) says "Windows: default dir under the user
    profile". An elevated Command Prompt starts in `C:\Windows\System32`, so a default elevated run
    writes the report there, and it inherits that folder's ACL (Users can read). `C:\temp` style
    working directories are common on jump hosts.
  - Windows reparse points: junctions need no privilege to create. Decision 1's "no-follow directory
    open" must be proven to refuse a junction as well as a symlink.
- Fix:
  - On Windows the default parent is `%USERPROFILE%\rdy-reports`, created if missing. The profile ACL
    is owner, SYSTEM and Administrators by default. `.` is used only when given explicitly. Unix keeps
    `.`.
  - The Windows post-open check: a directory, not a reparse point (`FILE_ATTRIBUTE_REPARSE_POINT`
    clear), and the opened handle's final path equals the expected path. Otherwise exit 70.
  - The Windows CI leg tests a pre-planted junction and a symlink with the target name. Both are
    refused before the first check.
  - Name the ACL residual in the ADR and in the report's notes until SEC-58.

**MF-06. 02 "Kubernetes" and Appendix B rule 5, ADR 0010. The `selfsubjectreviews` POST must be
allowed in M1.**
- Plain answer: **yes, an ADR 0010 amendment should allow it, in M1, before the guard ticket closes.**
- Why:
  - SelfSubjectReview creates nothing, stores nothing and returns only the caller's own user info. It
    is GA in 1.28, and every authenticated user may call it through the default `system:basic-user`
    role. It is the only way to show the authenticated principal behind an exec plugin, OIDC or IAM
    mapping.
  - 05 S1 ("wrong cluster or identity", M1, SEC-24) and 05 INV-14 already depend on it. Without it the
    report shows the kubeconfig's user entry name, which is often `admin` or a cluster ARN and is not
    the identity the API server sees.
  - 02's fallback is safe, but it weakens an M1 mitigation and leaves 02, 05 and the guard ticket out
    of step: that ticket's exit test says "the two review POSTs", 05 says three.
- Conditions for the amendment:
  - Exactly `POST /apis/authentication.k8s.io/v1/selfsubjectreviews`, no query string, and the body is
    the fixed constant `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`. The
    guard compares bytes.
  - No `v1beta1` or `v1alpha1`. On 1.27 and older, the report shows the kubeconfig user marked "not
    verified by the API server".
  - Keep only `username` and `groups` from the response. Drop `uid` and `extra`. EKS can put
    `accessKeyId`, `arn` and `sessionName` in `extra`.
  - The 02 guard ticket's exit test and 01 section 5.1 (`identity.kube.user`) change in the same PR.

## Should fix

**SF-01. ADR 0014 decision 2 and 02 "Network". The address rule misses current credential endpoints.**
EKS Pod Identity serves on `fd00:ec2::23` (and `169.254.170.23`, already covered). Alibaba Cloud
metadata is `100.100.100.200`. IPv6-only clusters reach IPv4 metadata through NAT64 (`64:ff9b::/96`).
Fix: one `is_forbidden(IpAddr)` covering 169.254.0.0/16, fe80::/10, `fd00:ec2::/64`, 100.100.100.200/32,
and the IPv4-mapped, IPv4-compatible and `64:ff9b::/96` forms of each IPv4 range. Back it with a table
test. Update 05 INV-12 to match.

**SF-02. ADR 0014 decision 8. Name kube's proxy CONNECT.** 03 has `k8s.access` set `HTTPS_PROXY` on
the kube client, so kube writes its own CONNECT and sends the proxy password. Fix: name "kube's proxy
CONNECT and TLS" in the exception. The probe-time `connect` entry records `via_proxy`. The password
comes from the same `ProxyUrl` and is never logged.

**SF-03. 02 Appendix A, `Probe`, `Backend`, `Live`. Per-check scoping can be bypassed if constructors
are public.** `Engine::new` takes `Arc<dyn Backend>`, so the CLI must be able to build `Live`. If
`Probe::new` is public too, a check can build its own `Probe` over `Live` with a wider `CheckInfo`. That
skips its manifest, host set and cancellation scope. Fix:
- Make `Probe` constructors `pub(crate)`.
- Seal `Backend` with a private supertrait.
- Expose `Live` only through `rdy_engine::live_backend()`, and put that function in the clippy
  disallowed list for check crates.

**SF-04. ADR 0014 decision 5. "Each variant reviewed" needs a mechanical gate.** CODEOWNERS with one
human is not a second pair of eyes. Fix: an exhaustive `match` in rdy-engine maps each variant to its
policy row (path rule, logged fields) and feeds a snapshot test of the variant list. A new variant
fails CI until the snapshot and a 05 table row change in the same PR. Two variant rules:
- `MachineId`'s raw value never enters the action log or the report. Only 01's HMAC `host_id` does.
- Drop the macOS `kern.uuid` source in M1. 01 says macOS `host_id` is null, and `sysctlbyname` needs
  FFI.

**SF-05. 02 Appendix B. Header rules.** `k8s.rbac` sends `Impersonate-User` from the spec's `as:`.
The guard says nothing about impersonation headers, so either rbac breaks or every GET can impersonate.
Fix: allow `Impersonate-*` headers only on the SSAR and SSRR POSTs. The value must equal the validated
spec `as:` value (`system:serviceaccount:<dns1123>:<dns1123>`, or a user string without control
characters, at most 253 bytes). Otherwise allow only the values the operator's kubeconfig sets. Log
the header name, never the token.

**SF-06. 02 Appendix B rules 1 to 4. Parser and data handling details.**
- Apply the `%` rule to the path only. Decode query values once, then validate them; kube-rs
  percent-encodes `fieldSelector`.
- Validate spec-derived discovery segments (`k8s.version` `apis`): the group is a DNS-1123 subdomain
  and the version matches `^v[0-9]+((alpha|beta)[0-9]+)?$`.
- Add parser vectors that follow the API server's request-info rules:
  - `/api/v1/namespaces/secrets` is a GET of a namespace named `secrets`, so it is allowed.
  - `/api/v1/namespaces/x/secrets/y` is refused.
  - `/api/v1/namespaces/x/finalize` is a subresource, so it is refused.
- Deserialize `pods` and `events` into minimal structs (resources, `nodeName`, phase, reason). Env
  values and args are then never even held as strings.
- For ConfigMaps, check that the response `kind` is `PartialObjectMetadataList` and drop it otherwise.

**SF-07. ADR 0015 decision 2 and 02 steps 4 to 6. Redact each result as it completes.** The watchdog
snapshot (MF-02), `on_progress` and the terminal renderer all see results before the whole-report pass.
Fix:
- Run the sync redact-then-cap pass on each `CheckResult` and action entry when it completes. Run the
  final pass over the assembled report.
- `Progress` carries id, status and duration only.
- The terminal renderer, like `write_json` and `render_html`, accepts only `&RedactedReport`.
- `RedactedReport` has no `From<Report>`, no `Deserialize` and no `DerefMut`.

**SF-08. 08 decision A and ADR 0011 decision 4. Conditions for the in-process entry point.** I accept
`#[doc(hidden)] rdy_cli::run(args, backend, out, err)`. A function that only tests call is not a switch
in the binary, and it beats a feature plus an env var. But "there is nothing to prove absent" is too
strong. The ADR 0011 amendment must state, and CI must check:
- Test hooks (clock, run id, deadline, watchdog action, privilege ids) are fields of a `RunHooks`
  parameter. They are never argv flags or env vars, so the shipped binary cannot be steered into
  them.
- `crates/rdy-cli/src` outside `#[cfg(test)]` never names `Replay` or `testing` (CI grep). The release
  build is `-p rdy` without `--all-targets`. `cargo tree -p rdy -e normal,features --target <t>` lacks
  `testing` on every leg. A marker string compiled only into the Replay module is absent from each
  dist binary before signing.
- Process-global effects stay in `main`: the log layer, the panic hook, the ring provider and
  `process::exit`. In process, the watchdog fires a hook, not `exit`. So SEC-25's "stderr at
  `RUST_LOG=trace`" canary test and the watchdog exit-70 test run against the real binary
  (`assert_cmd`), not in process.
- `Backend` is sealed (SF-03), so the public `run` cannot take a third-party backend.

**SF-09. ADR 0013 decision 2 and 02 `OsSupport`. `Support::Partial(note)` has no verdict meaning.**
`net.proxy` is `Partial` on macOS and Windows, but nothing marks its result partial. A Pass there is a
full pass. Fix: the engine sets `partial` (with the OS note as `missing`) on every result from a
`Partial` OS, so decision 4 applies.

**SF-10. ADR 0013 decisions 2 and 4. Downgrade paths need a registry.** `evidence_only` wants and
"pass by absence" are check-authored ways to keep a level. Fix: one constructor,
`Finding::pass_by_absence(note)`, plus a golden snapshot listing every `evidence_only` want and every
`pass_by_absence` call site across the registry. Changes show up in review.

**SF-11. 02 "Privilege and needs", INV-10. Compare all ids.** Fix:
- On Linux, compare all four values on the `Uid:` and `Gid:` lines (real, effective, saved, fs). A
  saved uid of 0 lets a process regain root.
- Also read `AT_SECURE` (type 23) from `/proc/self/auxv` through the facade. The kernel sets it for
  setuid, setgid and file-capability execs.
- On macOS, compare the four ids from rustix.
- The hint names `CapAmb` when ambient capabilities caused the refusal.

**SF-12. 02 "Watchdog". Kill children before exit.** `process::exit` leaves child process groups
running, including a `Hung` child. Fix: the facade keeps a lock-free list of live process group ids.
The watchdog and the Ctrl-C path send SIGKILL to each before exit. The kube exec plugin is not ours to
track; record that as a residual. The HTML shows an INCOMPLETE banner when `complete: false`.

**SF-13. ADR 0016 decisions 3 and 5. Platform details.**
- macOS: ACLs are checked before mode bits, so a parent with inheritable ACEs grants access despite
  0700 and 0600. Name it as a residual next to Windows, and extend SEC-58 to macOS.
- Windows: retry the final rename up to 5 times at 100 ms, because Defender briefly holds new files.
  A directory fsync is a no-op there and never an exit 70.
- Pin `cap-std` and `cap-primitives` to 3.4.1 or later (RUSTSEC-2024-0445, Windows device names; our
  names are fixed, but `cargo deny` will flag older versions anyway).
- Record the cap-std dependency approval (05 dependency policy).

## Nits

- **N-01.** ADR 0016 decision 1: a setgid parent gives the new directory mode 02700. Check
  `mode & 0o777` and `fchmod` the directory to 0700. NFS `root_squash` makes the owner check fail
  correctly; the hint names it.
- **N-02.** ADR 0016: when the name already exists, retry with `-2` to `-9` before exit 70. Otherwise a
  local user can pre-create predictable names and block runs.
- **N-03.** ADR 0016 decision 4: copy the spec under fixed names (`spec.yaml`, `spec.yaml.minisig`),
  never the operator's file name.
- **N-04.** 02 Appendix A: `Privilege::snapshot` is sync, but `Probe` calls are async, and the Windows
  snapshot runs `whoami.exe`. Pick one. Resolve `whoami.exe` from `GetSystemDirectoryW` or a constant,
  not from `%SystemRoot%`.
- **N-05.** 02 "Privilege and needs": a kube token refresh during a check runs the exec plugin inside
  kube, which may block a worker. The watchdog is the backstop. Verify, and record it.
- **N-06.** ADR 0013 decision 5: rdy-spec should reject a spec with zero checks (exit 64), so
  `nothing_verified` comes only from the vendor's `os` lists.
- **N-07.** 02 step 5: measure the 2 MiB cap after JSON escaping, which lengthens `<`, `>` and `&` to
  six bytes each.
- **N-08.** ADR 0014 decision 4: the M2 upload client cannot "use the same code", because the HTTP probe
  discards bodies. It uses hook 7's `http_exchange` with a run-level host. Say so.
- **N-09.** 02 ticket "Read-only guard layer and test for rdy-checks-k8s": "the two review POSTs"
  becomes three after MF-06.

## On ADR 0013 "nothing verified"

My conservative choice was `not_ready`. ADR 0013 takes `ready_with_warnings`. I accept that. After
decision 2, a run that verified nothing has two possible causes. Either every check was excluded by
the vendor's own signed `os` lists, or every check that did not run was `severity: warn`, which ADR 0008
already maps to exit 1. Neither is our code hiding a required check. Exit 1 still fails a strict gate,
and the headline says "nothing was checked". N-06 closes the empty-spec case.

## Plan corrections found

- docs/plan/05-threat-model.md (mine), Appendix F: "chunk-boundary cases at every offset are M2". Facade
  caps cut buffers in M1, so cap-boundary cases are M1 (MF-01). Fix in revision 3.
- docs/plan/05-threat-model.md, INV-12: add the SF-01 ranges.
- docs/plan/05-threat-model.md, Appendix A I3: name ADR 0016 and the Windows default directory once
  MF-05 lands.
- docs/plan/08-testing.md, rules item 3 and section 6 ("Only the closure passed to `probe.native(..)`
  is gated"): native calls are a closed `NativeCall` enum (ADR 0014). Fix: "only the Live arm of each
  `NativeCall` variant is gated".
- docs/plan/08-testing.md, ticket "Timeouts env and scheduler timeout, deadline and cancellation
  tests": it expects `interrupted: true` and `skip_kind: cancelled` in M1, but 02 says M1 Ctrl-C exits
  70 with no report, and it depends on an M2 ticket. Fix: the M1 test asserts exit 70 and no file
  under a final name. The report assertions move to the M2 graceful Ctrl-C ticket.
- docs/plan/01-spec-format.md, sections 5.1 and 7 (`identity.kube.user` "waits for the ADR 0010
  amendment"): update when MF-06 lands.
- docs/adr/0011-binary-name-and-cli-package.md, decision 4: amend as 08 proposes, with the SF-08
  conditions written into the decision.

## Decisions needing an ADR

- **ADR 0010 amendment (MF-06).** Allow `selfsubjectreviews` in M1 under the stated conditions, or keep
  the kubeconfig name. Conservative choice: allow it with the conditions, because the alternative
  weakens an M1 mitigation and adds no safety.
- **Windows default output directory (MF-05).** Options: `%USERPROFILE%\rdy-reports`, `.` with a
  warning, or `%LOCALAPPDATA%\rdy\reports`. Conservative choice: `%USERPROFILE%\rdy-reports`, because
  it is easy to find and its ACL is owner-only. cli-ux confirms the name.

## Tickets implied

- [M1] Redact facade-truncated buffers and a run-scoped known-secret set | owner: rust-engineer | est: 3h | depends on: SEC-25 Minimal redactor for evidence, errors and logs | exit test: a PEM key, an AWS key id and a URL with userinfo placed across the stdout, stderr, file and tail caps at offsets cap minus 1 to cap minus 64 never appear in JSON, HTML or stderr, and the kubeconfig token is redacted wherever it appears.
- [M1] Direct dependency allowlist for check crates | owner: rust-engineer | est: 1h | depends on: Lint wall: clippy lists, lint-wall test crate, allow grep and deny wrappers | exit test: adding `walkdir` to rdy-checks-host fails CI, and the lint-wall crate has one exact entry per Appendix A item with no wildcard.
- [M1] Security re-review sign-off of 02 revision 3 and ADRs 0014 to 0016 | owner: security-reviewer | est: 1h | depends on: Redact facade-truncated buffers and a run-scoped known-secret set | exit test: MF-01 to MF-06 of this file are marked closed in the reviewed files and the ADRs move to Accepted.

Folds (extra exit-test clauses on existing tickets, 5.5 h in total):

| Existing ticket | Added clause | +h |
| --- | --- | --- |
| Run deadline and watchdog with a report on hang | MF-02 single writer, bounded exit, no stdout lock, try_lock snapshot; SF-12 child kill | 1.5 |
| Kube guard path parser, resource allowlist and pending log entries | MF-03 entries and citation test; SF-05 headers; SF-06 vectors and projections | 1.5 |
| Amend ADR 0010 for selfsubjectreviews, client ownership and the context flag | MF-06 fixed body, v1 only, `extra` and `uid` dropped | 0.5 |
| SEC-19 Confine writes to a new output dir with safe names | MF-05 Windows default and reparse-point check; SF-13; N-01 | 1 |
| Closed NativeCall enum in the facade | SF-03 sealed Backend and private constructors; SF-04 snapshot | 0.5 |
| In-process CLI entry point rdy_cli::run taking a Backend | SF-08 RunHooks, grep, feature tree and marker checks | 0.5 |

## Closure check (M1-001, 2026-10-28)

Reviewer: security-reviewer. Checked on `main` at `8f5705f` against ADR 0010 (as amended), ADRs 0014,
0015 and 0016 (all Accepted), `docs/plan/02-engine-design.md` revision 3 and `docs/plan/11-backlog.md`.
Quotes are exact. Line numbers are at that commit, except the MF-04 row, which was re-checked at
`74e162a` and cites that commit. This check itself edited no ADR or plan file. The M1-001 PR (#6) did,
in separate commits: `74e162a` (ADRs 0010 and 0014, 02, 11) and `f896576` (05 revision 3).

Result: all six must-fix items are closed. MF-04 was reopened in the first pass and closed after
rust-architect completed the lint wall in `74e162a`. With that, 02 revision 3 has security-reviewer
sign-off. Its status line (02 line 6) can drop "waiting for security-reviewer sign-off"; that edit is
rust-architect's.

| id | verdict | evidence | smallest fix |
| --- | --- | --- | --- |
| MF-01 facade caps cut secrets | closed | `docs/adr/0015-redactor-in-rdy-engine.md:19` "`FileBytes` and `Output` carry `truncated_head` and `truncated_tail`." Line 22: "The PEM rule matches an unterminated `-----BEGIN ... PRIVATE KEY-----` through to the". Line 26: "The redactor removes exact matches and any 8-character or longer prefix or suffix". Line 41: "a canary at offsets cap minus 1 to cap minus 64." Line 63 extends the exit test to "the stdout, stderr, file and tail caps". `docs/plan/02-engine-design.md:225` "**As each result or action entry completes**, it is redacted, then capped (ADR 0015):". | none (see CF-04) |
| MF-02 watchdog race and hang | closed | `docs/adr/0016-output-dir-confinement-cap-std.md:40` "whoever moves it from `Running` to `Writing` writes. The loser never writes." `docs/plan/02-engine-design.md:192` "`try_lock` loop bounded at 1 s". Line 195: "It runs the same sync redact-then-cap pass as the engine and never assumes the". Line 199: "The render and write run on a helper thread through the held output directory." Line 201: "It sends SIGKILL to every live process group in the facade's lock-free list,". Line 203: "It never takes std's stdout or stderr locks". Line 205: "Before the output directory exists, it exits 70 with no report." Tests: lines 474 to 476. | none (see CF-05) |
| MF-03 kube allowlist gaps | closed | `docs/plan/02-engine-design.md:781` "`k8s.storageclass`: Pending claims older than 5 minutes". Line 782: "`fieldSelector` must include `involvedObject.kind=PersistentVolumeClaim`". Line 784: "`k8s.storageclass`: `spec.drivers[].name`". Line 786: "`k8s.nodes`: `cluster-autoscaler` presence by name". Lines 790 to 791 move the webhook and `validatingadmissionpolicies` entries into "**`M1_LATE`**". Line 773: "asserts every entry is cited by at least one check's `CheckInfo` and that `secrets` appears nowhere." Deployments are a LIST in `kube-system` only, narrower than my either-or, and projected to minimal structs (line 795). Accepted. | none (see CF-06) |
| MF-04 unvetted crates and the lint wall | closed (re-checked at `74e162a`) | The first pass of this check, at `8f5705f`, reopened it: 02 Appendix A lacked std write and socket items and let a check crate build an unguarded kube client. `74e162a` closes it. `docs/plan/02-engine-design.md:739` lists "`std::fs::remove_dir_all`", and lines 735 to 767 now hold every std item I named (links, permissions, `chown`, `chroot`, `UnixDatagram`, `connect_addr`, `bind_addr`, `std::thread::scope`, type `std::fs::DirBuilder`) and more (`std::path::Path` metadata calls, `std::env::current_dir`, `std::process::exit`). Line 771: "`kube::client::ClientBuilder`, `kube::config::Kubeconfig`; `kube::Client::new`," as disallowed types and methods outside the client module. Line 779: "Trait routes: `TryFrom<Config>` and `TryFrom<Kubeconfig>` for `Client`". Line 787: "Verified on 2026-10-28 against kube 4.2.0 on docs.rs". Line 791: "Not listed: crates other than std, kube and the facade." `docs/adr/0014-probe-facade-owns-side-effects.md:55` "The guarantee is the wall and the allowlist together", and line 63: "`rdy-checks-k8s` only the client module may name a kube client or config type." Tests: `docs/plan/11-backlog.md:180` (M1-044) "each entry, used once in tests/lint-wall, fails clippy"; line 238 (M1-102) "each 02 Appendix A kube entry, re-checked against the pinned kube version and used once in tests/lint-wall, fails clippy". | none |
| MF-05 Windows output dir | closed | `docs/adr/0016-output-dir-confinement-cap-std.md:18` "`%USERPROFILE%\rdy-reports` (created if missing; owner, SYSTEM and Administrators by default)." Line 27: "`FILE_ATTRIBUTE_REPARSE_POINT` is clear, and its final". Line 28: "Junctions and symlinks with the target name are both refused." Line 42 names the ACL residuals "in the report's notes until SEC-58". `docs/plan/02-engine-design.md:403` "`%USERPROFILE%\rdy-reports` on Windows (05 I3)". Test: `docs/plan/11-backlog.md:173` (M1-037) "a pre-planted junction and a symlink with the target name are both refused before the first check". | none |
| MF-06 `selfsubjectreviews` in M1 | closed | `docs/adr/0010-kubernetes-client-kube-rs.md:22` "and to `selfsubjectreviews` (`authentication.k8s.io/v1`) with no query string and exactly the body". Line 24: "From its response only `username` and `groups` are kept". Line 26: "kubeconfig user marked "not verified by the API server"". `docs/plan/02-engine-design.md:803` "compared byte for byte". Test: `docs/plan/11-backlog.md:239` (M1-103) "a SelfSubjectReview with a different body or a query string". | none (see CF-07) |

### Follow-ups found during the check

Numbering continues from the closure check in `adr-and-00-review-by-security-reviewer.md` (CF-01 to
CF-03).

- **CF-04 (medium). M1-061 lost the PEM case.** Done: backlog correction 02 (PR #5) restored it.
  - Problem: `docs/plan/11-backlog.md:197` (M1-061) tests "An AWS key id and a URL with userinfo". ADR
    0015 line 63 and 02 line 594 also test "a PEM key" across the facade caps. M1-062 covers only the
    64 KiB report cap. So the unterminated PEM rule at a facade cap is untested in M1.
  - Fix: M1-061 exit test starts "A PEM key, an AWS key id and a URL with userinfo". Owner:
    rust-architect, before M1-061 starts.
- **CF-05 (medium). M1-043 lost the held-lock case.** Done: backlog correction 02 (PR #5) restored it.
  - Problem: `docs/plan/11-backlog.md:179` (M1-043) has no "held snapshot lock" case. 02 lines 476 and
    574 have it. It is the test for the `try_lock` bound.
  - Fix: add "and a held snapshot lock" to the M1-043 Spin clause. Owner: rust-architect, before
    M1-043 starts.
- **CF-06 (medium). M1-104 lost the citation test.** Done: backlog correction 02 (PR #5) restored the
  three clauses and re-estimated M1-104 at 3.5 h.
  - Problem: `docs/plan/11-backlog.md:240` (M1-104) drops three clauses that 02 line 586 has: "an
    unlisted resource" is refused, "every ALLOWED entry is cited by a CheckInfo", and "a dropped request
    leaves a timeout entry with its check id". The citation test is the MF-03 control against a wide
    entry added under deadline pressure. The estimate also fell from 3.5 h to 1 h.
  - Fix: restore the three clauses and re-estimate. Owner: rust-architect, before M1-104 starts.
- **CF-07 (low). 01 still takes the kube user from the kubeconfig.**
  - Problem: `docs/plan/01-spec-format.md:506` says the authenticated user "waits for the ADR 0010
    amendment that allows that POST", and line 876 says the same. The amendment has landed. 02 line 497
    lists the fix, but 13 does not carry it, so M1-009 does not own it.
  - Fix: both lines say `identity.kube.user` comes from `SelfSubjectReview`, and on 1.27 and older it is
    the kubeconfig user marked "not verified by the API server". Owner: rust-architect, before M1-020
    starts.
- **CF-08 (low). 05 revision 3 has no ticket.** Done: 05 revision 3 is part of M1-001 and landed with it.
  - Problem: the threat model edits that this review and 02 lines 521 to 525 ask for (INV-12 ranges,
    Appendix A I3, Appendix F cap-boundary cases in M1, INV-08 fixed PATH) are not in 11-backlog.md.
  - Fix: a 1 h M1 ticket for security-reviewer, before M1-040 starts. Exit test: 05 revision 3 carries
    those four edits and names ADRs 0014 to 0016.
