# Review of 08-testing.md by code-reviewer

Reviewer: code-reviewer, cold. I did not write 08. Date: 2026-10-28. Read against CLAUDE.md, KICKOFF item 9,
02 (testing seams, `Backend`), 01 (sections 5.2 and 5.3), 03 (fixture conventions, loopback ticket), 05,
06 (CI matrix, Appendix A), 09 (xtask, `rdy_cli` library target), ADRs 0006, 0008 and 0011.
Line numbers refer to 08-testing.md as of this date.

## Summary

The doc covers every part of KICKOFF item 9: air-gapped, GPU and Windows fixture strategy, goldens, property
tests and the matrix. The fixture format is mostly sound and Windows-aware. The `-text` rule, the
`root.manifest.json` idea, POSIX keys and the autocrlf canary are the right calls. Plain-file goldens
over insta is defensible. Coverage tracked and not gated matches CLAUDE.md. Nextest plus a separate
`cargo test --doc` is correct.

It is not ready. The CI proof for the in-binary fixture backend does not prove what it claims. Several
tests are written against a misreading of 01. Two engine tests will hang or fail by construction. The
timeouts env cannot run as specified. M1 load is 58 hours against an M1 that 00 already puts at twice its
budget. Doc length is about 10,000 words by `wc -w` (746 lines), not 7,000. That is well past the
15-minute rule.

## Must fix

1. **Section 6 "The fixture backend inside the real binary" (lines 491 to 498), ticket line 716, ADR list
   lines 683 to 687. The CI proof is not real.**
   Problem: (a) `cargo tree` has no profile option, and features do not depend on the profile. The
   default edge set includes dev-dependencies, and the harness will dev-depend on `rdy-engine/testing`.
   So `cargo tree -p rdy -e features` shows `testing` on every run, and the check is wrong either way.
   (b) `strings rdy | grep -c X` exits 1 when the count is 0, so a `set -e` step fails on the good case.
   (c) Both checks run on a `cargo build` in `ci.yml`. They do not run on the artifacts dist builds with
   `--profile dist` and its own feature config, which are what gets signed. (d) Nothing stops a release
   profile build with the feature on. (e) The rejected alternative rests on ADR 0011 point 4 ("no
   library"). But 09-docs-site.md section "CLI reference" already adds a `rdy_cli` library target, so
   that argument no longer holds.
   Fix: preferred, drive the CLI in process. Add a `#[doc(hidden)] pub fn run(args, backend: Arc<dyn
   Backend>, stdout, stderr) -> ExitCode` to the `rdy_cli` lib that 09 already needs. Env tests call it
   with Replay. No binary ever contains a switch, and paused time works (see item 5). Amend ADR 0011
   point 4 in the same change. Keep `assert_cmd` for a few live-backend tests (`rdy --bogus` gives 64,
   unwritable `--out-dir` gives 70, the real-OS smoke). If the founder keeps the env-var switch:
   `#[cfg(all(feature = "fixture-backend", not(debug_assertions)))] compile_error!(..)`. The feature
   build refuses to start without `RDY_TEST_BACKEND_DIR`. Use `cargo tree -p rdy --target <triple>
   -e normal,build,features -i rdy-engine` and assert no `testing`. Use `! grep -q RDY_TEST_BACKEND_DIR`
   on all five extracted dist archives inside `sign-release.yml`, before signing, so a failure blocks
   publication. Either way, security-reviewer signs the ADR.

2. **Sections 5 and 6, plus the correction at lines 670 to 674. The tests contradict 01.**
   Problem: the correction says 01 has no interrupted flag and that unfinished checks become `error` with
   `error_kind = interrupted`. 01 section 5 says the opposite. Line 406 has `interrupted: true` after
   Ctrl-C. Line 476 has `skip_kind: cancelled`. Line 437 limits `error_kind` to `check_failed` and
   `panic`. So 02 and 01 already agree, and the cancellation rows (lines 428 and 431) assert values that
   cannot exist. Other names also drift from 01. `skip_kind: unsupported_os` (line 480) is
   `not_yet_on_os` in 01. `excluded` (line 482) is `not_applicable`. `verdict_reasons` and `block_found`
   (line 418) are `verdict_reason`, which takes `required_check_not_run`, `nothing_verified` or null.
   Fix: delete that correction bullet. Rewrite the cancellation rows: unfinished checks are `skipped`
   with `skip_kind: cancelled`, and `interrupted: true`. Ask the 01 owner whether `complete` is true or
   false after a Ctrl-C that still wrote a report. Today, line 406 only ties `complete: false` to exit 70.
   Replace each drifted name with 01's word, and add a test that greps 08's test names against the
   schema enums.

3. **Section 5, scheduler row (line 426) and rules (lines 435 to 438). `Fake::Block` will hang the
   suite.**
   Problem: `Block` is "a `spawn_blocking` that never returns". Dropping the runtime that `#[tokio::test]`
   builds waits for blocking tasks with no limit, so the test never ends. Also, tokio's `test-util`
   stops auto-advancing the paused clock while a blocking task runs (recent 1.x releases). The "proof
   once" will most likely fail, not pass.
   Fix: `Block` waits on a `std::sync::mpsc::Receiver` that the test releases after its asserts. Build
   the runtime by hand and end it with `shutdown_timeout(Duration::from_millis(100))`. Plan this one test
   on real time from the start, with a 50 ms check timeout and an upper bound of 1 s. Leave the other
   scheduler rows on paused time.

4. **Section 4, verdict properties 2 and 4 (lines 411 and 415). The properties contradict each other
   and 01.**
   Problem: under 01 rule 5.3 amendment 3 (`nothing_verified`), an empty or all-`not_applicable` list is
   `ready_with_warnings`. Adding one `pass` makes it `ready`. That breaks "adding a result never improves
   the verdict", so the property fails by construction.
   Fix: change property 2 to "making one result worse, or adding a non-pass result, never improves the
   verdict". Add an explicit case: adding a pass to a list with nothing verified moves it from 1 to 0.
   Add unknown severity and unknown status to the generators (01 amendment 4).

5. **Section 2 `timeouts` env (line 280), Replay delays (lines 166, 429), ticket line 720. The env cannot
   run as specified.**
   Problem: env tests run the real binary in a subprocess, so paused time is not available.
   `Backend::exec` and `Backend::connect` (02) get no timeout argument. So Replay cannot "give
   `Timeout` without waiting". It has to stay pending until `Probe`'s timer fires in real time, up to the
   20 s `deadline_ms`, twice (once at `jobs = 1`, once at `jobs = 8`), on five legs. That is slow, and it
   is the kind of real-time test rule 5 says causes flakes.
   Fix: Replay waits with `tokio::time::sleep(delay_ms)` and `std::future::pending()` for `blackhole`, so
   paused time skips the wait. Run the `timeouts` env in process (item 1) under `start_paused = true`.
   If one binary-level timeout test is wanted, its spec sets `timeout: 1s`, and the test asserts only an
   upper bound. Fix the ticket's exit test to match.

6. **`crates/rdy-testkit` (lines 34, 185, 692 to 694) and `serve` in env-level tests. This is a design
   hole and an extra crate.**
   Problem: CLAUDE.md fixes the crate list, and `rdy-testkit` is not on it. 03 already has "Loopback
   network test support" (rust-engineer, 4h, "shared test support module"), but 08 neither links to that
   ticket nor gives its own. `serve` connects a duplex stream to an in-process server. If env tests run
   the real binary, that server stack (rcgen, TLS server, CONNECT proxy) must be compiled into the
   fixture binary. That is the very thing the ADR item was trying to avoid. Line 34 also lists "a black
   hole" for live loopback. 03 (line 209) explains that this cannot exist on loopback.
   Fix: no new crate in M1. Put the servers behind a non-default `test-support` feature of
   `rdy-checks-net`, under 03's existing ticket. `rdy` tests use it as a dev-dependency through the
   in-process path from item 1. Drop "black hole" from the live loopback row, since it is scripted only.
   Revisit a shared crate only when a third crate needs the servers, through an ADR.

7. **Tickets implied, line 703. M1 qa-engineer load is about 58 hours.**
   Problem: 00 counts M1 at about 194 hours against a 60 to 90 hour budget. This adds about 43 new hours.
   Fix: cut to about 32 hours (29 if SEC-26 stays in 00's security budget). Keep:

   | Keep in M1 | h |
   | --- | --- |
   | Fixture format README, `.gitattributes` and Windows canary (merge the two tickets) | 2 |
   | Fixture lint as a nextest test, not an xtask command (redactor rule moves to M2) | 3 |
   | Engine test helpers FakeCheck, run_fixture and normalize (02) | 2 |
   | Golden helper with UPDATE_GOLDENS, missing-golden failure and orphan check (no `goldens-fresh` job) | 2 |
   | Golden tests for JSON and HTML reports (00) | 2 |
   | Env-level harness, in process | 3 |
   | Fixture env all-pass | 3 |
   | Fixture envs warnings-only, all-block and no-privileges | 3 |
   | Timeouts env plus scheduler timeout, deadline and cancel tests under paused time (merged) | 4 |
   | Property tests for rdy_spec::parse | 3 |
   | SEC-26 M1 redaction corpus (05) | 3 |
   | Golden result files per released version | 1 |
   | Nextest ci profile, `cargo test --doc` in CI, PR template | 1 |
   | **Total** | **32** |

   Move to M2: `goldens-fresh`, the matrix generator (M1 ships a hand table owned by docs-writer), both
   stub envs (an `Engine::plan(spec, Os::Windows)` unit test in the registry ticket covers the skip), the
   container, airgapped, corp-proxy and OpenShift envs (their check-level cases ship with the 03 check
   tickets), the ignore lint, and SEC-22. Fold the `rdy --bogus` gives 64 case into ADR 0008's "Error types
   with fix hints" ticket and drop the separate CLI exit-code ticket. The musl resolver fixture belongs to
   03's `net.dns` ticket (check-author). Add-back order if hours free up: `net-airgapped` (2h, the
   KICKOFF air-gap case), SEC-22 (2h), `windows-2022-stub` (1h).

8. **Section 7, day-one rows (lines 556 to 578) and states (lines 516 to 522). The public matrix
   overclaims.**
   Problem: `ci` means "Verified in CI". But "RHEL, Rocky, Alma 9", "OpenShift 4" and "kubeadm, three
   newest minors" rest on `origin = "hand"` fixtures: our own guess at what those systems look like.
   "macOS 15: net, k8s `ci`, live runner" claims k8s on a runner that has no cluster. Security reviewers
   at vendors will read this page as a claim. The state name `hand` ("verified on a real box") also
   clashes with the fixture origin `hand` ("written by us, not real"). And "stale after 180 days",
   computed inside `--check`, makes `docs-gen` fail on day 181 for an unrelated PR.
   Fix: split `ci` into `live` (a runner leg or the kind job) and `fixture`. The page shows the fixture's
   origin, and only `ci-runner` or `throwaway` recordings may say "recorded from a real system". Rename
   the matrix state `hand` to `field`. Drop k8s from the macOS and Windows live rows. Compute staleness in
   a nightly job that opens an issue, not in `--check`.

## Should fix

9. **Section 3, staleness (lines 352 to 360).** `git diff --exit-code tests/` ignores untracked files. So
   a test that writes a brand-new golden under `UPDATE_GOLDENS=1` passes the job. Apart from that, the
   job repeats what the normal run already catches, at the cost of another full suite run. How the
   helper knows it is "the goldens-fresh job" (line 346) is not defined. Fix: a missing golden fails the
   normal run unless `UPDATE_GOLDENS=1`. Run `cargo xtask goldens check` (orphans) after nextest on the
   linux-x64 leg. Drop `goldens-fresh`, or, if it stays, use `git status --porcelain tests/` and an
   explicit `RDY_GOLDENS_FRESH=1`.
10. **Section 3, update command (line 342).** `-p rdy` does not regenerate check-case `expect.json` files
    owned by the `rdy-checks-*` test suites. Fix: `UPDATE_GOLDENS=1 cargo nextest run --workspace`, plus
    the feature if item 1 keeps it.
11. **Section 2, POSIX keys (lines 143 to 145) and names (lines 218 to 219).** `c:/windows/...` cannot sit
    on disk, because `:` is banned. Lowercasing is not scoped to Windows. Command hashes cover argv, but
    the resolved `argv[0]` for a Windows fixture depends on how `Probe` resolves programs, and the runner
    must not affect that. Fix: on disk, use `root/c/Windows/...`, mapped to key `c:/windows/...` only when
    `os = "windows"`, with case kept on Linux and macOS. Resolve programs through the Backend by the
    fixture's `os`, never the runner's. Hash the normalised resolved argv.
12. **Section 2, command and api file names (lines 159 to 170).** Hand fixtures are most of M1, and
    asking authors to compute a SHA-256 for each file name is friction. Fix: the loader indexes by the
    `argv` or `request` field inside each file, and file names are free slugs. The lint fails on
    duplicate keys and on Windows-illegal names. This also keeps 03's readable names.
13. **Section 2, `root.manifest.json` (lines 146 to 158).** The doc never says the deny list's
    canonical-target check (02, Files row) resolves through manifest symlinks in Replay. Without that,
    the symlink-to-`/etc/shadow` case is never exercised. Fix: Replay canonicalises through
    `symlinks`, and add a lint-required case `checks/_policy/symlink-to-shadow` that must give
    `Denied`.
14. **Section 2, lint (lines 255 to 267).** (a) "Any name not ending in `.example`" will flag
    `os-release` `HOME_URL` values, `cluster.local`, `registry.k8s.io` and vendor driver URLs. (b)
    Banning RFC 1918 addresses breaks realistic pod and service CIDRs and the `NO_PROXY` and CIDR-overlap
    checks. (c) The redactor rule needs SEC-25, which the lint ticket does not depend on. (d) The
    completeness rule fails for registered checks that are not built yet. Fix: (a) check only URL and
    FQDN tokens with a public suffix, with a built-in allow-list of the vendors Rdy checks (OS vendors,
    `k8s.io`, `nvidia.com`). (b) Allow RFC 1918, `100.64.0.0/10` and `fd00::/8`, and ban public routable
    addresses only. (c) Move the redactor rule to M2. (d) Apply completeness only to checks whose
    `CheckInfo` is marked implemented.
15. **Section 4, bounds (lines 371 to 375, 394).** `PROPTEST_CASES=10000` applies to every property in
    the process, so round-trip and schema-validated report properties run 10,000 times too. Proptest
    shrinks with no time limit by default, so a failure can reach nextest's two-minute kill and lose the
    shrunk case. "Any string" has no stated size. Fix: set cases per test with `ProptestConfig`: 10,000
    only for parser never-panics and limits, 256 for the rest. Set `max_shrink_time = 30_000`. Cap
    strings at 4 KiB and collections at 64. Budget: the whole property suite under 60 s on linux-x64.
16. **Section 4, parser invariants (lines 379 to 388).** The most important forward-compatibility rule
    is missing. Fix: add "a valid spec plus an unknown id, unknown field or unknown severity parses, and
    the check is `skipped` with the 01 `skip_kind` (`not_in_build`, `unknown_check`,
    `unsupported_spec`), never `pass`" (01 section 5.2, ADR 0008 decision 2).
17. **Section 2, cut order (line 288).** It says the per-OS plan goldens still cover the stubs if they
    are cut. But the plan goldens are an M2 ticket (line 734). Fix: point at the `Engine::plan` unit test
    from item 7, or move a minimal plan golden into M1.
18. **Tickets implied.** (a) 02's "Replay backend and fixture loader" (rust-engineer) must take 08's
    format (`fixture.toml`, `base`, `remove`, `answers`, `root.manifest.json`, POSIX keys, drive mapping),
    yet 08 lists no amended exit test for it. (b) The README ticket (line 710) tests "parses with the
    loader" but depends only on the skeleton. (c) SEC-26 (line 726) asserts `UPDATE_GOLDENS` behaviour
    without depending on the golden helper. (d) The M2 forbidden-name scan (line 742) duplicates 09's
    `docs-lint` banned-token-hash rule. Fix: add (a) with a full exit test. Add the missing dependencies
    for (b) and (c). Delete (d).
19. **Public API versioning.** `rdy_engine::testing` and the `testing` feature become part of a published
    crate's surface (ADR 0007). Fix: state in ADR 0007 that `testing` is `#[doc(hidden)]`, unstable and
    outside the semver promise, and exclude it from any semver-checks run.
20. **Coverage (lines 582 to 587).** No ticket exists in 08 or 06, so "tracked" has no owner. Fix: add
    `[M2] Nightly cargo-llvm-cov job with per-crate summary | owner: release-engineer | est: 2h`.
21. **Section 5, process row (line 430).** `/usr/bin/sleep` does not exist on macOS. A `kill -0` on a
    recorded pid can hit a reused pid. Fix: use `/bin/sleep`, which exists on both. Probe the process
    group (`kill -0 -<pgid>` through `rustix`) right after the run ends.
22. **Doc length.** About 10,000 words by `wc -w`. Fix: target 4,500 for the body. Move to appendices:
    A, recording and scrubbing (lines 221 to 251, all M2). B, the full matrix rules and day-one table
    (lines 545 to 578). C, the normalisation table (lines 317 to 327). D, the redactor and verdict
    property tables (M2). E, the definition of done (lines 608 to 631), which belongs in
    `.github/pull_request_template.md` and is linked from here. Also move the M2 to M4 tickets into
    11-backlog.md.

## Nits

23. Line 205: `*.actual -diff` does nothing, because `.actual` files are git-ignored. Drop it.
24. Line 213: the `crlf = [...]` manifest key is missing from the manifest example (lines 100 to 131).
25. Line 212: extend the `\r` lint to `examples/specs/**`, which is also `-text`.
26. Line 214: the Windows runner image already defaults `core.autocrlf` to true. Keep the explicit step,
    and add `git check-attr text -- tests/fixtures/signed/*` asserting `unset` on every leg as a cheap
    second proof.
27. Line 547: make `[matrix]` optional. `timeouts` and `no-privileges` have nothing to claim.
28. Lines 596 to 600: root tests use two mechanisms (the `#[ignore]` form and a `root_*` name filter).
    Pick the name filter and drop `root` from the ignore form. Also run the root tests as a prebuilt
    nextest archive under `sudo`, not `sudo cargo`, so `target/` does not become root-owned.
29. Line 725: the title says "fuzz", but fuzzing is M2 (SEC-45). Rename the ticket to "Property tests for
    rdy_spec::parse".
30. Line 38: "every `examples/specs/*.yaml` lints" is an integration test, not a doc test. Also say that
    doc tests run on the host target, not musl.
31. Line 503: inject the setuid-like mismatch into the pure refusal function in a unit test, not through
    the fixture backend. That keeps the backend's surface smaller.
32. Line 44: `fixtures_dir()` reaches outside the crate, so tests fail from a crates.io tarball. Fine, but
    say so in the README.

## Checks I ran

- No em dashes or en dashes in 08. No competitor names or old working name seen.
- Every M1 ticket is 1 to 4 hours and has an exit test. The M1 tickets sum to 58 hours for qa-engineer,
  plus 2 for rust-engineer, matching line 703.
- KICKOFF item 9 coverage: air-gapped (`net-airgapped`, SEC-22), GPU (M4 capture plan), Windows (CRLF,
  registry JSON, stub env), goldens, property tests, and the compatibility matrix are all present.

## Verdict

Request changes. 8 must-fix items. The format, the gitattributes rules, the golden choice and the coverage
stance can stay. Fix items 1 to 8 and the M1 cut list, shorten the body, then send it back for a second
pass. security-reviewer must see the revised item 1 before the ADR is written.
